//! Failure-atomic PQ attestation aggregation.

use consensus_signature::{
    AggregationService, V1_MAX_AGGREGATION_CONTRIBUTIONS, V1_MAX_AGGREGATION_INPUT_BYTES,
    V1_MAX_AGGREGATION_SIGNERS, is_individual_same_message_evidence,
};
use parking_lot::Mutex;
use ssz::Encode;
use state_processing::{
    PqAttestationError, PqAttestationInvalid, PqAttestationLocalError, PqValidatorKeyCache,
    PreparedPqAttestation, VerifiedPqAttestation, prepare_pq_attestation_aggregate,
};
#[cfg(feature = "pq-block-selection")]
use state_processing::{
    PqBlockAttestationSelectionError, PqLocalBlockError, VerifiedPqLocalBlock, VerifiedPqRandao,
    prepare_pq_local_block, validate_pq_attestation_for_block_selection,
};
use std::{collections::HashMap, future::Future, sync::Arc};
#[cfg(feature = "pq-block-selection")]
use types::BeaconBlock;
use types::{Attestation, AttestationData, BeaconState, ChainSpec, EthSpec, Slot};

/// Coordinator-wide cap on distinct retained V1 attestation buckets.
///
/// This is four times the Minimal preset's honest two-epoch, sixteen-slot window.
pub const V1_MAX_ATTESTATION_BUCKETS: usize = 64;
/// Coordinator-wide cap on actual retained same-message evidence bytes.
pub const V1_MAX_RETAINED_EVIDENCE_BYTES: usize = V1_MAX_AGGREGATION_INPUT_BYTES;
/// Maximum number of sealed candidates cloned into one non-consuming block-selection snapshot.
pub const V1_MAX_RETAINED_ATTESTATION_CANDIDATES: usize =
    V1_MAX_ATTESTATION_BUCKETS * V1_MAX_AGGREGATION_CONTRIBUTIONS;
#[cfg(feature = "pq-block-selection")]
const PQ_MAX_ATTESTATIONS_PER_BLOCK: usize = 8;

/// The exact attestation-data and single Electra committee aggregation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PqAttestationBucket {
    pub data: AttestationData,
    pub committee_index: u64,
}

/// Result of inserting one already-authenticated candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted { id: u64, removed_subsets: usize },
    Dominated,
    CapacityExceeded,
    BucketCapacityExceeded { actual: usize, max: usize },
    EvidenceCapacityExceeded { actual: usize, max: usize },
    UnsupportedCandidate,
    GenerationExhausted,
}

/// A synchronous snapshot-preparation failure. No aggregation work has started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrepareAggregateError {
    UnknownBucket,
    AlreadyInFlight,
    GenerationExhausted,
    InvalidLocalRequest(PqAttestationError),
}

/// A failure produced after a locally constructed, previously verified snapshot starts execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateFailure {
    InvariantInvalid(PqAttestationInvalid),
    Local(PqAttestationLocalError),
    RetainedEvidenceCapacity { actual: usize, max: usize },
}

/// Result of removing all buckets older than a caller-supplied slot cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PruneOutcome {
    pub buckets_removed: usize,
    pub candidates_removed: usize,
    pub evidence_bytes_released: usize,
}

/// Terminal result of executing a prepared aggregation snapshot.
pub enum AggregateOutcome<E: EthSpec> {
    /// The deterministic selection contained one candidate, so no prover job was run.
    Singleton(Arc<VerifiedPqAttestation<E>>),
    /// A new verified aggregate was installed atomically.
    Aggregated(Arc<VerifiedPqAttestation<E>>),
    /// A selected candidate was removed or replaced while proof work was in progress.
    StaleSnapshot,
    /// Proof execution failed locally. Every source candidate remains available for retry.
    Failed(AggregateFailure),
}

/// Non-cloneable authoritative block selection retaining every sealed authentication token.
#[cfg(feature = "pq-block-selection")]
pub struct PqBlockAttestationSelection<E: EthSpec> {
    candidates: Vec<Arc<VerifiedPqAttestation<E>>>,
}

#[cfg(feature = "pq-block-selection")]
#[derive(Debug)]
pub enum PqRetainedAttestationAssemblyError {
    WrongFork,
    Capacity,
    LocalBlock(PqLocalBlockError),
}

#[cfg(feature = "pq-block-selection")]
impl std::fmt::Display for PqRetainedAttestationAssemblyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ retained-attestation assembly failed: {self:?}"
        )
    }
}

#[cfg(feature = "pq-block-selection")]
impl std::error::Error for PqRetainedAttestationAssemblyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LocalBlock(error) => Some(error),
            Self::WrongFork | Self::Capacity => None,
        }
    }
}

#[cfg(feature = "pq-block-selection")]
impl<E: EthSpec> PqBlockAttestationSelection<E> {
    /// Consumes the only selection authority, installs exact attestation bytes, and seals the
    /// local block with the identical retained tokens.
    pub fn into_verified_local_block(
        self,
        state: &BeaconState<E>,
        mut block: BeaconBlock<E>,
        randao: VerifiedPqRandao<E>,
    ) -> Result<VerifiedPqLocalBlock<E>, PqRetainedAttestationAssemblyError> {
        let attestations = self
            .candidates
            .iter()
            .map(|candidate| match candidate.attestation() {
                Attestation::Electra(attestation) => Ok(attestation.clone()),
                Attestation::Base(_) => Err(PqRetainedAttestationAssemblyError::WrongFork),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let BeaconBlock::Electra(inner) = &mut block else {
            return Err(PqRetainedAttestationAssemblyError::WrongFork);
        };
        inner.body.attestations = attestations
            .try_into()
            .map_err(|_| PqRetainedAttestationAssemblyError::Capacity)?;
        prepare_pq_local_block(state, block, randao, self.candidates)
            .map_err(PqRetainedAttestationAssemblyError::LocalBlock)
    }
}

struct Candidate<T> {
    id: u64,
    signer_indices: Vec<u64>,
    value: Arc<T>,
    evidence_bytes: usize,
}

struct BucketState<T> {
    candidates: Vec<Candidate<T>>,
    in_flight: Option<u64>,
}

struct PqCandidateOrderingMetadata<'a> {
    data: &'a AttestationData,
    committee_index: u64,
    signer_indices: &'a [u64],
}

fn compare_pq_candidate_ordering_metadata(
    left: PqCandidateOrderingMetadata<'_>,
    right: PqCandidateOrderingMetadata<'_>,
) -> std::cmp::Ordering {
    left.data
        .slot
        .cmp(&right.data.slot)
        .then_with(|| left.data.as_ssz_bytes().cmp(&right.data.as_ssz_bytes()))
        .then_with(|| left.committee_index.cmp(&right.committee_index))
        .then_with(|| right.signer_indices.len().cmp(&left.signer_indices.len()))
        .then_with(|| left.signer_indices.cmp(right.signer_indices))
}

fn try_filter_take_pq_candidates<Candidate, Error>(
    candidates: impl IntoIterator<Item = Candidate>,
    maximum: usize,
    mut retain: impl FnMut(&Candidate) -> Result<bool, Error>,
) -> Result<Vec<Candidate>, Error> {
    let mut retained = Vec::with_capacity(maximum);
    if maximum == 0 {
        return Ok(retained);
    }
    for candidate in candidates {
        if retain(&candidate)? {
            retained.push(candidate);
            if retained.len() == maximum {
                break;
            }
        }
    }
    Ok(retained)
}

impl<T> Default for BucketState<T> {
    fn default() -> Self {
        Self {
            candidates: Vec::new(),
            in_flight: None,
        }
    }
}

struct CoordinatorState<T> {
    buckets: HashMap<PqAttestationBucket, BucketState<T>>,
    next_id: u64,
    retained_evidence_bytes: usize,
}

impl<T> Default for CoordinatorState<T> {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
            next_id: 0,
            retained_evidence_bytes: 0,
        }
    }
}

impl<T> CoordinatorState<T> {
    fn reserve_id(&mut self) -> Option<u64> {
        let next = self.next_id.checked_add(1)?;
        let id = self.next_id;
        self.next_id = next;
        Some(id)
    }

    #[cfg(test)]
    fn insert(
        &mut self,
        bucket: PqAttestationBucket,
        signer_indices: Vec<u64>,
        value: T,
    ) -> InsertOutcome {
        self.insert_sized(bucket, signer_indices, value, 0)
    }

    fn check_insert(
        &self,
        bucket: Option<&BucketState<T>>,
        signer_indices: &[u64],
        evidence_bytes: usize,
    ) -> Result<(), InsertOutcome> {
        if signer_indices.is_empty()
            || signer_indices.len() > V1_MAX_AGGREGATION_SIGNERS
            || !strictly_increasing(signer_indices)
        {
            return Err(InsertOutcome::CapacityExceeded);
        }
        if bucket.is_none() && self.buckets.len() >= V1_MAX_ATTESTATION_BUCKETS {
            return Err(InsertOutcome::BucketCapacityExceeded {
                actual: self.buckets.len().saturating_add(1),
                max: V1_MAX_ATTESTATION_BUCKETS,
            });
        }
        let mut removed_evidence_bytes = 0usize;
        if let Some(existing) = bucket {
            if existing
                .candidates
                .iter()
                .any(|stored| is_subset(signer_indices, &stored.signer_indices))
            {
                return Err(InsertOutcome::Dominated);
            }
            let removed_subsets = existing
                .candidates
                .iter()
                .filter(|stored| is_subset(&stored.signer_indices, signer_indices))
                .count();
            let resulting_count = existing
                .candidates
                .len()
                .saturating_sub(removed_subsets)
                .saturating_add(1);
            if resulting_count > V1_MAX_AGGREGATION_CONTRIBUTIONS {
                return Err(InsertOutcome::CapacityExceeded);
            }
            let mut union = signer_indices.to_vec();
            for stored in existing
                .candidates
                .iter()
                .filter(|stored| !is_subset(&stored.signer_indices, signer_indices))
            {
                for signer in &stored.signer_indices {
                    if !union.contains(signer) {
                        if union.len() == V1_MAX_AGGREGATION_SIGNERS {
                            return Err(InsertOutcome::CapacityExceeded);
                        }
                        union.push(*signer);
                    }
                }
            }
            removed_evidence_bytes = existing
                .candidates
                .iter()
                .filter(|stored| is_subset(&stored.signer_indices, signer_indices))
                .try_fold(0usize, |total, stored| {
                    total.checked_add(stored.evidence_bytes)
                })
                .unwrap_or(usize::MAX);
        }
        let retained_after_removal = self
            .retained_evidence_bytes
            .checked_sub(removed_evidence_bytes)
            .unwrap_or(usize::MAX);
        let actual = match retained_after_removal.checked_add(evidence_bytes) {
            Some(actual) => actual,
            None => usize::MAX,
        };
        if actual > V1_MAX_RETAINED_EVIDENCE_BYTES {
            return Err(InsertOutcome::EvidenceCapacityExceeded {
                actual,
                max: V1_MAX_RETAINED_EVIDENCE_BYTES,
            });
        }
        Ok(())
    }

    fn insert_sized(
        &mut self,
        bucket: PqAttestationBucket,
        signer_indices: Vec<u64>,
        value: T,
        evidence_bytes: usize,
    ) -> InsertOutcome {
        if let Err(outcome) =
            self.check_insert(self.buckets.get(&bucket), &signer_indices, evidence_bytes)
        {
            return outcome;
        }
        let Some(id) = self.reserve_id() else {
            return InsertOutcome::GenerationExhausted;
        };
        let bucket_state = self.buckets.entry(bucket).or_default();
        let before = bucket_state.candidates.len();
        let removed_evidence_bytes = bucket_state
            .candidates
            .iter()
            .filter(|stored| is_subset(&stored.signer_indices, &signer_indices))
            .fold(0usize, |total, stored| {
                total.saturating_add(stored.evidence_bytes)
            });
        bucket_state
            .candidates
            .retain(|stored| !is_subset(&stored.signer_indices, &signer_indices));
        let removed_subsets = before.saturating_sub(bucket_state.candidates.len());
        bucket_state.candidates.push(Candidate {
            id,
            signer_indices,
            value: Arc::new(value),
            evidence_bytes,
        });
        self.retained_evidence_bytes = self
            .retained_evidence_bytes
            .saturating_sub(removed_evidence_bytes)
            .saturating_add(evidence_bytes);
        InsertOutcome::Inserted {
            id,
            removed_subsets,
        }
    }

    fn prune_before_slot(&mut self, cutoff: Slot) -> PruneOutcome {
        let mut outcome = PruneOutcome {
            buckets_removed: 0,
            candidates_removed: 0,
            evidence_bytes_released: 0,
        };
        self.buckets.retain(|bucket, bucket_state| {
            let retain = bucket.data.slot >= cutoff;
            if !retain {
                outcome.buckets_removed = outcome.buckets_removed.saturating_add(1);
                outcome.candidates_removed = outcome
                    .candidates_removed
                    .saturating_add(bucket_state.candidates.len());
                outcome.evidence_bytes_released = bucket_state
                    .candidates
                    .iter()
                    .fold(outcome.evidence_bytes_released, |total, candidate| {
                        total.saturating_add(candidate.evidence_bytes)
                    });
            }
            retain
        });
        self.retained_evidence_bytes = self
            .retained_evidence_bytes
            .saturating_sub(outcome.evidence_bytes_released);
        outcome
    }

    fn snapshot(
        &mut self,
        bucket: &PqAttestationBucket,
    ) -> Result<MachineSnapshot<T>, PrepareAggregateError> {
        let bucket_state = self
            .buckets
            .get(bucket)
            .ok_or(PrepareAggregateError::UnknownBucket)?;
        if bucket_state.in_flight.is_some() {
            return Err(PrepareAggregateError::AlreadyInFlight);
        }
        let selected = select_disjoint(&bucket_state.candidates);
        let token = if selected.len() <= 1 {
            None
        } else {
            Some(
                self.reserve_id()
                    .ok_or(PrepareAggregateError::GenerationExhausted)?,
            )
        };
        if let Some(token) = token {
            let bucket_state = self
                .buckets
                .get_mut(bucket)
                .ok_or(PrepareAggregateError::UnknownBucket)?;
            bucket_state.in_flight = Some(token);
        }
        Ok(MachineSnapshot { token, selected })
    }

    fn clear_snapshot(&mut self, bucket: &PqAttestationBucket, token: u64) {
        if let Some(bucket_state) = self.buckets.get_mut(bucket)
            && bucket_state.in_flight == Some(token)
        {
            bucket_state.in_flight = None;
        }
    }

    fn commit(
        &mut self,
        bucket: &PqAttestationBucket,
        snapshot: &MachineSnapshot<T>,
        signer_indices: Vec<u64>,
        aggregate: T,
        evidence_bytes: usize,
    ) -> MachineCommit {
        let Some(token) = snapshot.token else {
            return MachineCommit::Stale;
        };
        let Some(bucket_state) = self.buckets.get_mut(bucket) else {
            return MachineCommit::Stale;
        };
        if bucket_state.in_flight != Some(token) {
            return MachineCommit::Stale;
        }
        let unchanged = snapshot.selected.iter().all(|selected| {
            bucket_state.candidates.iter().any(|candidate| {
                candidate.id == selected.id && Arc::ptr_eq(&candidate.value, &selected.value)
            })
        });
        if !unchanged {
            bucket_state.in_flight = None;
            return MachineCommit::Stale;
        }
        let removed_evidence_bytes = bucket_state
            .candidates
            .iter()
            .filter(|candidate| is_subset(&candidate.signer_indices, &signer_indices))
            .fold(0usize, |total, candidate| {
                total.saturating_add(candidate.evidence_bytes)
            });
        let actual = self
            .retained_evidence_bytes
            .checked_sub(removed_evidence_bytes)
            .and_then(|retained| retained.checked_add(evidence_bytes))
            .unwrap_or(usize::MAX);
        if actual > V1_MAX_RETAINED_EVIDENCE_BYTES {
            bucket_state.in_flight = None;
            return MachineCommit::EvidenceCapacityExceeded {
                actual,
                max: V1_MAX_RETAINED_EVIDENCE_BYTES,
            };
        }
        bucket_state
            .candidates
            .retain(|candidate| !is_subset(&candidate.signer_indices, &signer_indices));
        bucket_state.candidates.push(Candidate {
            id: token,
            signer_indices,
            value: Arc::new(aggregate),
            evidence_bytes,
        });
        bucket_state.in_flight = None;
        self.retained_evidence_bytes = actual;
        MachineCommit::Committed
    }
}

#[cfg(feature = "pq-block-selection")]
fn prune_for_block_selection<E: EthSpec, V>(
    state: &BeaconState<E>,
    coordinator_state: &mut CoordinatorState<V>,
) -> PruneOutcome {
    let cutoff = state.previous_epoch().start_slot(E::slots_per_epoch());
    coordinator_state.prune_before_slot(cutoff)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MachineCommit {
    Committed,
    Stale,
    EvidenceCapacityExceeded { actual: usize, max: usize },
}

struct MachineSnapshot<T> {
    token: Option<u64>,
    selected: Vec<SnapshotCandidate<T>>,
}

fn next_ready_pq_background_aggregation_bucket<T>(
    state: &CoordinatorState<T>,
    mut is_supported_raw_singleton: impl FnMut(&PqAttestationBucket, &T) -> bool,
) -> Option<PqAttestationBucket> {
    let mut ready = state
        .buckets
        .iter()
        .filter_map(|(bucket, bucket_state)| {
            if bucket_state.in_flight.is_some() {
                return None;
            }
            let selected = select_disjoint(&bucket_state.candidates);
            (selected.len() == 2
                && selected.iter().all(|candidate| {
                    candidate.signer_indices.len() == 1
                        && is_supported_raw_singleton(bucket, &candidate.value)
                }))
            .then(|| bucket.clone())
        })
        .collect::<Vec<_>>();
    ready.sort_unstable_by(|left, right| {
        left.data
            .slot
            .cmp(&right.data.slot)
            .then_with(|| left.data.as_ssz_bytes().cmp(&right.data.as_ssz_bytes()))
            .then_with(|| left.committee_index.cmp(&right.committee_index))
    });
    ready.into_iter().next()
}

enum MachineExecution<T, E> {
    Committed(Arc<T>),
    Stale,
    Failed(E),
    EvidenceCapacityExceeded { actual: usize, max: usize },
}

/// Owns an in-flight snapshot across one unlocked asynchronous operation.
///
/// Both the real aggregation path and unit fake executors share this cleanup and commit seam.
struct PreparedExecution<T> {
    state: Arc<Mutex<CoordinatorState<T>>>,
    bucket: PqAttestationBucket,
    snapshot: Option<MachineSnapshot<T>>,
}

impl<T> PreparedExecution<T> {
    fn new(
        state: Arc<Mutex<CoordinatorState<T>>>,
        bucket: PqAttestationBucket,
        snapshot: MachineSnapshot<T>,
    ) -> Self {
        Self {
            state,
            bucket,
            snapshot: Some(snapshot),
        }
    }

    fn selected(&self) -> &[SnapshotCandidate<T>] {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.selected.as_slice())
            .unwrap_or_default()
    }

    async fn execute_with<F, E>(mut self, future: F) -> MachineExecution<T, E>
    where
        F: Future<Output = Result<(Vec<u64>, T, usize), E>>,
    {
        // Deliberately retain only the owned snapshot, never the mutex guard, across this await.
        let result = future.await;
        let Some(snapshot) = self.snapshot.take() else {
            return MachineExecution::Stale;
        };
        let Some(token) = snapshot.token else {
            return MachineExecution::Stale;
        };
        match result {
            Ok((signer_indices, aggregate, evidence_bytes)) => {
                let mut state = self.state.lock();
                match state.commit(
                    &self.bucket,
                    &snapshot,
                    signer_indices,
                    aggregate,
                    evidence_bytes,
                ) {
                    MachineCommit::Committed => state
                        .buckets
                        .get(&self.bucket)
                        .and_then(|bucket_state| {
                            bucket_state
                                .candidates
                                .iter()
                                .find(|candidate| candidate.id == token)
                                .map(|candidate| Arc::clone(&candidate.value))
                        })
                        .map(MachineExecution::Committed)
                        .unwrap_or(MachineExecution::Stale),
                    MachineCommit::Stale => MachineExecution::Stale,
                    MachineCommit::EvidenceCapacityExceeded { actual, max } => {
                        MachineExecution::EvidenceCapacityExceeded { actual, max }
                    }
                }
            }
            Err(error) => {
                let mut state = self.state.lock();
                let Some(bucket_state) = state.buckets.get_mut(&self.bucket) else {
                    return MachineExecution::Stale;
                };
                if bucket_state.in_flight != Some(token) {
                    return MachineExecution::Stale;
                }
                bucket_state.in_flight = None;
                MachineExecution::Failed(error)
            }
        }
    }
}

impl<T> Drop for PreparedExecution<T> {
    fn drop(&mut self) {
        if let Some(snapshot) = &self.snapshot
            && let Some(token) = snapshot.token
        {
            self.state.lock().clear_snapshot(&self.bucket, token);
        }
    }
}

struct CoordinatorInner<E: EthSpec> {
    service: Arc<AggregationService>,
    state: Arc<Mutex<CoordinatorState<VerifiedPqAttestation<E>>>>,
}

/// Owns bounded candidate state and the shared aggregation service for one beacon node.
///
/// A storage caller cannot forge the sealed input to [`Self::insert_verified`]:
///
/// ```compile_fail
/// use state_processing::VerifiedPqAttestation;
/// use types::{Attestation, EthSpec};
///
/// fn forge<E: EthSpec>(attestation: Attestation<E>) -> VerifiedPqAttestation<E> {
///     VerifiedPqAttestation {
///         attestation,
///         signer_indices: vec![0],
///         claim: unreachable!(),
///     }
/// }
/// ```
pub struct PqAttestationAggregationCoordinator<E: EthSpec> {
    inner: Arc<CoordinatorInner<E>>,
}

impl<E: EthSpec> Clone for PqAttestationAggregationCoordinator<E> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<E: EthSpec> PqAttestationAggregationCoordinator<E> {
    pub fn new(service: Arc<AggregationService>) -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                service,
                state: Arc::new(Mutex::new(CoordinatorState::default())),
            }),
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_uses_aggregation_service(&self, service: &Arc<AggregationService>) -> bool {
        Arc::ptr_eq(&self.inner.service, service)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_candidate_signer_sets(&self) -> Vec<Vec<u64>> {
        let mut signer_sets = self
            .inner
            .state
            .lock()
            .buckets
            .values()
            .flat_map(|bucket| bucket.candidates.iter())
            .map(|candidate| candidate.signer_indices.clone())
            .collect::<Vec<_>>();
        signer_sets.sort_unstable();
        signer_sets
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_next_generation(&self, next_generation: u64) {
        self.inner.state.lock().next_id = next_generation;
    }

    /// Inserts one sealed candidate, applying deterministic set dominance within its exact bucket.
    pub fn insert_verified(&self, candidate: VerifiedPqAttestation<E>) -> InsertOutcome {
        let Some((data, committee_index)) = bucket_parts(candidate.attestation()) else {
            return InsertOutcome::UnsupportedCandidate;
        };
        let signer_indices = candidate.signer_indices();
        if signer_indices.is_empty()
            || signer_indices.len() > V1_MAX_AGGREGATION_SIGNERS
            || !strictly_increasing(signer_indices)
        {
            return InsertOutcome::UnsupportedCandidate;
        }
        let evidence_bytes = candidate.attestation().signature().as_bytes().len();
        let mut state = self.inner.state.lock();
        let existing_key = state
            .buckets
            .keys()
            .find(|bucket| bucket.committee_index == committee_index && bucket.data == *data);
        let existing_bucket = existing_key.and_then(|bucket| state.buckets.get(bucket));
        if let Err(outcome) = state.check_insert(existing_bucket, signer_indices, evidence_bytes) {
            return outcome;
        }
        let bucket = existing_key
            .cloned()
            .unwrap_or_else(|| PqAttestationBucket {
                data: data.clone(),
                committee_index,
            });
        let signer_indices = signer_indices.to_vec();
        state.insert_sized(bucket, signer_indices, candidate, evidence_bytes)
    }

    /// Selects one policy-complete, non-consuming candidate set for block production.
    ///
    /// Pruning and the bounded metadata snapshot are atomic. Validation and canonical ordering run
    /// without the coordinator lock, and stop immediately after eight valid candidates.
    #[cfg(feature = "pq-block-selection")]
    pub fn select_for_block(
        &self,
        state: &BeaconState<E>,
        key_cache: &PqValidatorKeyCache,
        spec: &ChainSpec,
    ) -> Result<PqBlockAttestationSelection<E>, PqBlockAttestationSelectionError> {
        let mut coordinator_state = self.inner.state.lock();
        prune_for_block_selection(state, &mut coordinator_state);
        let mut candidates = coordinator_state
            .buckets
            .iter()
            .flat_map(|(bucket, bucket_state)| {
                bucket_state.candidates.iter().map(|candidate| {
                    (
                        Arc::clone(&candidate.value),
                        bucket.committee_index,
                        candidate.signer_indices.clone(),
                    )
                })
            })
            .take(V1_MAX_RETAINED_ATTESTATION_CANDIDATES)
            .collect::<Vec<_>>();
        drop(coordinator_state);
        candidates.sort_unstable_by(|left, right| {
            compare_pq_candidate_ordering_metadata(
                PqCandidateOrderingMetadata {
                    data: left.0.attestation().data(),
                    committee_index: left.1,
                    signer_indices: &left.2,
                },
                PqCandidateOrderingMetadata {
                    data: right.0.attestation().data(),
                    committee_index: right.1,
                    signer_indices: &right.2,
                },
            )
        });
        let candidates = try_filter_take_pq_candidates(
            candidates,
            PQ_MAX_ATTESTATIONS_PER_BLOCK,
            |candidate| {
                validate_pq_attestation_for_block_selection(state, key_cache, &candidate.0, spec)
            },
        )?
        .into_iter()
        .map(|(candidate, _, _)| candidate)
        .collect();
        Ok(PqBlockAttestationSelection { candidates })
    }

    /// Removes every bucket older than `cutoff`, releasing its retained-evidence accounting.
    ///
    /// If a removed bucket has work in flight, that owned execution becomes stale and cannot
    /// resurrect the bucket when it finishes or is dropped.
    pub fn prune_before_slot(&self, cutoff: Slot) -> PruneOutcome {
        self.inner.state.lock().prune_before_slot(cutoff)
    }

    /// Selects and marks one deterministic bounded snapshot, then constructs its owned job after
    /// releasing the coordinator lock and before any asynchronous work begins.
    pub fn prepare_aggregate(
        &self,
        bucket: &PqAttestationBucket,
        state: &BeaconState<E>,
        key_cache: &PqValidatorKeyCache,
        spec: &ChainSpec,
    ) -> Result<PreparedAggregate<E>, PrepareAggregateError> {
        let snapshot = self.inner.state.lock().snapshot(bucket)?;

        self.prepare_aggregate_snapshot(bucket.clone(), snapshot, state, key_cache, spec)
    }

    /// Selects the first canonical bucket containing exactly two disjoint raw singletons.
    ///
    /// Selection and the generation-bound in-flight mark are atomic under the coordinator lock.
    /// Request construction remains off-lock and preserves the same failure-atomic RAII as an
    /// explicitly addressed preparation.
    pub fn prepare_next_aggregate(
        &self,
        state: &BeaconState<E>,
        key_cache: &PqValidatorKeyCache,
        spec: &ChainSpec,
    ) -> Result<Option<PreparedAggregate<E>>, PrepareAggregateError> {
        let next = {
            let mut coordinator_state = self.inner.state.lock();
            let Some(bucket) = next_ready_pq_background_aggregation_bucket(
                &coordinator_state,
                |_bucket, candidate: &VerifiedPqAttestation<E>| {
                    let Attestation::Electra(attestation) = candidate.attestation() else {
                        return false;
                    };
                    attestation.aggregation_bits.len() == 2
                        && is_individual_same_message_evidence(&attestation.signature)
                },
            ) else {
                return Ok(None);
            };
            let snapshot = coordinator_state.snapshot(&bucket)?;
            (bucket, snapshot)
        };
        self.prepare_aggregate_snapshot(next.0, next.1, state, key_cache, spec)
            .map(Some)
    }

    fn prepare_aggregate_snapshot(
        &self,
        bucket: PqAttestationBucket,
        snapshot: MachineSnapshot<VerifiedPqAttestation<E>>,
        state: &BeaconState<E>,
        key_cache: &PqValidatorKeyCache,
        spec: &ChainSpec,
    ) -> Result<PreparedAggregate<E>, PrepareAggregateError> {
        let Some(_token) = snapshot.token else {
            let candidate = snapshot
                .selected
                .first()
                .ok_or(PrepareAggregateError::UnknownBucket)?;
            return Ok(PreparedAggregate::singleton(
                Arc::clone(&self.inner),
                Arc::clone(&candidate.value),
            ));
        };
        let execution = PreparedExecution::new(Arc::clone(&self.inner.state), bucket, snapshot);
        let contributions = execution
            .selected()
            .iter()
            .map(|candidate| {
                (
                    candidate.value.attestation().clone(),
                    candidate.signer_indices.clone(),
                )
            })
            .collect::<Vec<_>>();
        let request = match prepare_pq_attestation_aggregate(state, key_cache, contributions, spec)
        {
            Ok(request) => request,
            Err(error) => {
                return Err(PrepareAggregateError::InvalidLocalRequest(error));
            }
        };
        Ok(PreparedAggregate {
            inner: Arc::clone(&self.inner),
            execution: Some(execution),
            request: Some(request),
            singleton: None,
        })
    }
}

struct SnapshotCandidate<T> {
    id: u64,
    signer_indices: Vec<u64>,
    value: Arc<T>,
}

fn select_disjoint<T>(candidates: &[Candidate<T>]) -> Vec<SnapshotCandidate<T>> {
    let mut ordered = candidates.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| {
        right
            .signer_indices
            .len()
            .cmp(&left.signer_indices.len())
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut selected = Vec::with_capacity(ordered.len().min(V1_MAX_AGGREGATION_CONTRIBUTIONS));
    let mut signer_union = Vec::new();
    for candidate in ordered {
        if candidate
            .signer_indices
            .len()
            .saturating_add(signer_union.len())
            > V1_MAX_AGGREGATION_SIGNERS
            || intersects(&signer_union, &candidate.signer_indices)
        {
            continue;
        }
        signer_union.extend_from_slice(&candidate.signer_indices);
        signer_union.sort_unstable();
        selected.push(SnapshotCandidate {
            id: candidate.id,
            signer_indices: candidate.signer_indices.clone(),
            value: Arc::clone(&candidate.value),
        });
    }
    selected
}

/// An owned snapshot whose asynchronous proof work and final commit hold no state/cache locks.
pub struct PreparedAggregate<E: EthSpec> {
    inner: Arc<CoordinatorInner<E>>,
    execution: Option<PreparedExecution<VerifiedPqAttestation<E>>>,
    request: Option<PreparedPqAttestation<E>>,
    singleton: Option<Arc<VerifiedPqAttestation<E>>>,
}

impl<E: EthSpec> PreparedAggregate<E> {
    fn singleton(
        inner: Arc<CoordinatorInner<E>>,
        candidate: Arc<VerifiedPqAttestation<E>>,
    ) -> Self {
        Self {
            inner,
            execution: None,
            request: None,
            singleton: Some(candidate),
        }
    }

    pub async fn execute(mut self) -> AggregateOutcome<E> {
        if let Some(candidate) = self.singleton.take() {
            return AggregateOutcome::Singleton(candidate);
        }
        let Some(request) = self.request.take() else {
            return AggregateOutcome::StaleSnapshot;
        };
        let Some(execution) = self.execution.take() else {
            return AggregateOutcome::StaleSnapshot;
        };
        let service = Arc::clone(&self.inner.service);
        let future = async move {
            request.aggregate(&service).await.map(|aggregate| {
                let signer_indices = aggregate.signer_indices().to_vec();
                let evidence_bytes = aggregate.attestation().signature().as_bytes().len();
                (signer_indices, aggregate, evidence_bytes)
            })
        };
        match execution.execute_with(future).await {
            MachineExecution::Committed(aggregate) => AggregateOutcome::Aggregated(aggregate),
            MachineExecution::Stale => AggregateOutcome::StaleSnapshot,
            MachineExecution::Failed(PqAttestationError::Invalid(error)) => {
                AggregateOutcome::Failed(AggregateFailure::InvariantInvalid(error))
            }
            MachineExecution::Failed(PqAttestationError::Local(error)) => {
                AggregateOutcome::Failed(AggregateFailure::Local(error))
            }
            MachineExecution::EvidenceCapacityExceeded { actual, max } => {
                AggregateOutcome::Failed(AggregateFailure::RetainedEvidenceCapacity { actual, max })
            }
        }
    }
}

fn bucket_parts<E: EthSpec>(attestation: &Attestation<E>) -> Option<(&AttestationData, u64)> {
    let Attestation::Electra(electra) = attestation else {
        return None;
    };
    let mut selected = electra
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, present)| present.then_some(index));
    let committee_index = u64::try_from(selected.next()?).ok()?;
    if selected.next().is_some() {
        return None;
    }
    Some((&electra.data, committee_index))
}

fn strictly_increasing(values: &[u64]) -> bool {
    values.windows(2).all(|pair| {
        let [left, right] = pair else {
            return false;
        };
        left < right
    })
}

fn is_subset(left: &[u64], right: &[u64]) -> bool {
    let mut right_position = 0;
    for value in left {
        while right.get(right_position).is_some_and(|right| right < value) {
            right_position = right_position.saturating_add(1);
        }
        if right.get(right_position) != Some(value) {
            return false;
        }
    }
    true
}

fn intersects(left: &[u64], right: &[u64]) -> bool {
    let mut left_position = 0;
    let mut right_position = 0;
    while let (Some(left_value), Some(right_value)) =
        (left.get(left_position), right.get(right_position))
    {
        match left_value.cmp(right_value) {
            std::cmp::Ordering::Less => left_position = left_position.saturating_add(1),
            std::cmp::Ordering::Greater => right_position = right_position.saturating_add(1),
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;
    #[cfg(feature = "pq-block-selection")]
    use types::{Eth1Data, ForkName, MinimalEthSpec};

    #[derive(Clone)]
    struct OrderingCandidate {
        candidate_id: u64,
        data: AttestationData,
        committee_index: u64,
        signer_indices: Vec<u64>,
    }

    fn canonically_ordered_candidate_ids(mut candidates: Vec<OrderingCandidate>) -> Vec<u64> {
        candidates.sort_unstable_by(|left, right| {
            compare_pq_candidate_ordering_metadata(
                PqCandidateOrderingMetadata {
                    data: &left.data,
                    committee_index: left.committee_index,
                    signer_indices: &left.signer_indices,
                },
                PqCandidateOrderingMetadata {
                    data: &right.data,
                    committee_index: right.committee_index,
                    signer_indices: &right.signer_indices,
                },
            )
        });
        candidates
            .into_iter()
            .map(|candidate| candidate.candidate_id)
            .collect()
    }

    fn bucket(byte: u8, committee_index: u64) -> PqAttestationBucket {
        bucket_at(byte, committee_index, 0)
    }

    fn bucket_at(byte: u8, committee_index: u64, slot: u64) -> PqAttestationBucket {
        PqAttestationBucket {
            data: AttestationData {
                slot: types::Slot::new(slot),
                beacon_block_root: Hash256::repeat_byte(byte),
                ..AttestationData::default()
            },
            committee_index,
        }
    }

    #[cfg(feature = "pq-block-selection")]
    fn block_selection_state_at(slot: u64) -> BeaconState<MinimalEthSpec> {
        let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
        let mut state = BeaconState::new(0, Eth1Data::default(), &spec);
        *state.slot_mut() = Slot::new(slot);
        state
    }

    #[cfg(feature = "pq-block-selection")]
    #[test]
    fn block_selection_prunes_exactly_before_previous_epoch_start() {
        let slot_seven = bucket_at(80, 0, 7);
        let slot_eight = bucket_at(81, 0, 8);
        let slot_fifteen = bucket_at(82, 0, 15);
        let mut coordinator_state = CoordinatorState::<u8>::default();
        assert!(matches!(
            coordinator_state.insert_sized(slot_seven.clone(), vec![1], 1, 10),
            InsertOutcome::Inserted { .. }
        ));
        assert!(matches!(
            coordinator_state.insert_sized(slot_seven.clone(), vec![2], 2, 20),
            InsertOutcome::Inserted { .. }
        ));
        assert!(matches!(
            coordinator_state.insert_sized(slot_eight.clone(), vec![3], 3, 30),
            InsertOutcome::Inserted { .. }
        ));
        assert!(matches!(
            coordinator_state.insert_sized(slot_fifteen.clone(), vec![4], 4, 40),
            InsertOutcome::Inserted { .. }
        ));

        let outcome =
            prune_for_block_selection(&block_selection_state_at(16), &mut coordinator_state);

        assert_eq!(
            outcome,
            PruneOutcome {
                buckets_removed: 1,
                candidates_removed: 2,
                evidence_bytes_released: 30,
            }
        );
        assert!(!coordinator_state.buckets.contains_key(&slot_seven));
        assert!(coordinator_state.buckets.contains_key(&slot_eight));
        assert!(coordinator_state.buckets.contains_key(&slot_fifteen));
        assert_eq!(coordinator_state.buckets.len(), 2);
        assert_eq!(
            coordinator_state
                .buckets
                .values()
                .map(|bucket| bucket.candidates.len())
                .sum::<usize>(),
            2
        );
        assert_eq!(coordinator_state.retained_evidence_bytes, 70);
    }

    #[cfg(feature = "pq-block-selection")]
    #[test]
    fn block_selection_at_epoch_one_retains_genesis_slot() {
        let genesis_slot = bucket_at(83, 0, 0);
        let mut coordinator_state = CoordinatorState::<u8>::default();
        assert!(matches!(
            coordinator_state.insert_sized(genesis_slot.clone(), vec![1], 1, 11),
            InsertOutcome::Inserted { .. }
        ));
        assert!(matches!(
            coordinator_state.insert_sized(genesis_slot.clone(), vec![2], 2, 13),
            InsertOutcome::Inserted { .. }
        ));

        let outcome =
            prune_for_block_selection(&block_selection_state_at(8), &mut coordinator_state);

        assert_eq!(
            outcome,
            PruneOutcome {
                buckets_removed: 0,
                candidates_removed: 0,
                evidence_bytes_released: 0,
            }
        );
        assert!(coordinator_state.buckets.contains_key(&genesis_slot));
        assert_eq!(coordinator_state.buckets.len(), 1);
        assert_eq!(coordinator_state.buckets[&genesis_slot].candidates.len(), 2);
        assert_eq!(coordinator_state.retained_evidence_bytes, 24);
    }

    #[test]
    fn block_candidate_order_is_canonical_content_not_arrival_generation() {
        let same_committee_data = AttestationData {
            slot: Slot::new(2),
            ..AttestationData::default()
        };
        let same_signer_bucket_data = AttestationData {
            slot: Slot::new(3),
            ..AttestationData::default()
        };
        let lexicographic_signer_data = AttestationData {
            slot: Slot::new(4),
            ..AttestationData::default()
        };
        let candidates = vec![
            OrderingCandidate {
                candidate_id: 900,
                data: AttestationData {
                    slot: Slot::new(0),
                    ..AttestationData::default()
                },
                committee_index: 99,
                signer_indices: vec![99],
            },
            // SSZ encodes uint64 little-endian, so index 256 (`00 01 ...`) sorts before index 1
            // (`01 00 ...`) even though its numeric value is larger.
            OrderingCandidate {
                candidate_id: 800,
                data: AttestationData {
                    slot: Slot::new(1),
                    index: 256,
                    ..AttestationData::default()
                },
                committee_index: 9,
                signer_indices: vec![8],
            },
            OrderingCandidate {
                candidate_id: 1,
                data: AttestationData {
                    slot: Slot::new(1),
                    index: 1,
                    ..AttestationData::default()
                },
                committee_index: 0,
                signer_indices: vec![1],
            },
            OrderingCandidate {
                candidate_id: 700,
                data: same_committee_data.clone(),
                committee_index: 0,
                signer_indices: vec![9],
            },
            OrderingCandidate {
                candidate_id: 0,
                data: same_committee_data,
                committee_index: 1,
                signer_indices: vec![1],
            },
            OrderingCandidate {
                candidate_id: 2,
                data: same_signer_bucket_data.clone(),
                committee_index: 0,
                signer_indices: vec![7, 8],
            },
            OrderingCandidate {
                candidate_id: 999,
                data: same_signer_bucket_data,
                committee_index: 0,
                signer_indices: vec![1],
            },
            OrderingCandidate {
                candidate_id: 600,
                data: lexicographic_signer_data.clone(),
                committee_index: 0,
                signer_indices: vec![2, 9],
            },
            OrderingCandidate {
                candidate_id: 3,
                data: lexicographic_signer_data,
                committee_index: 0,
                signer_indices: vec![3, 4],
            },
        ];
        let expected = vec![900, 800, 1, 700, 0, 2, 999, 600, 3];

        assert_eq!(
            canonically_ordered_candidate_ids(candidates.clone()),
            expected,
        );
        let mut reversed = candidates.clone();
        reversed.reverse();
        assert_eq!(canonically_ordered_candidate_ids(reversed), expected);
        let mut permuted = candidates;
        permuted.rotate_left(4);
        assert_eq!(canonically_ordered_candidate_ids(permuted), expected);
    }

    #[test]
    fn block_candidate_cap_applies_after_validation_and_stops_after_eight_valid() {
        let input = vec![0_u64, 1, 10, 11, 12, 13, 14, 15, 16, 17, 99];
        let mut visited = Vec::new();
        let selected = try_filter_take_pq_candidates(input.clone(), 8, |candidate| {
            visited.push(*candidate);
            match *candidate {
                0 | 1 => Ok(false),
                99 => Err("tail candidate must not be visited"),
                _ => Ok(true),
            }
        })
        .expect("the invalid prefix is skipped before the eight-valid cap");

        assert_eq!(selected, vec![10, 11, 12, 13, 14, 15, 16, 17]);
        assert_eq!(visited, vec![0, 1, 10, 11, 12, 13, 14, 15, 16, 17]);

        let mut zero_cap_visits = 0;
        let selected = try_filter_take_pq_candidates(input, 0, |_| {
            zero_cap_visits += 1;
            Ok::<_, &'static str>(true)
        })
        .expect("zero capacity is an empty successful selection");
        assert!(selected.is_empty());
        assert_eq!(zero_cap_visits, 0);
    }

    #[test]
    fn duplicate_subset_superset_and_overlap_are_deterministic() {
        let key = bucket(1, 0);
        let mut state = CoordinatorState::<u8>::default();
        assert!(matches!(
            state.insert(key.clone(), vec![1, 2], 10),
            InsertOutcome::Inserted { .. }
        ));
        assert_eq!(
            state.insert(key.clone(), vec![1, 2], 11),
            InsertOutcome::Dominated
        );
        assert_eq!(
            state.insert(key.clone(), vec![1], 12),
            InsertOutcome::Dominated
        );
        assert!(matches!(
            state.insert(key.clone(), vec![1, 2, 3], 13),
            InsertOutcome::Inserted {
                removed_subsets: 1,
                ..
            }
        ));
        assert!(matches!(
            state.insert(key.clone(), vec![3, 4], 14),
            InsertOutcome::Inserted {
                removed_subsets: 0,
                ..
            }
        ));
        assert_eq!(state.buckets[&key].candidates.len(), 2);

        let accounting_key = bucket(11, 0);
        let _ = state.insert_sized(accounting_key.clone(), vec![8], 20, 10);
        let _ = state.insert_sized(accounting_key.clone(), vec![8, 9], 21, 25);
        assert_eq!(state.buckets[&accounting_key].candidates.len(), 1);
        assert_eq!(state.retained_evidence_bytes, 25);
    }

    #[test]
    fn selection_is_largest_first_disjoint_and_stably_tied_by_id() {
        let key = bucket(2, 0);
        let mut state = CoordinatorState::<u8>::default();
        let _ = state.insert(key.clone(), vec![1, 2], 10);
        let _ = state.insert(key.clone(), vec![2, 3], 11);
        let _ = state.insert(key.clone(), vec![4], 12);

        let snapshot = state.snapshot(&key).expect("bounded snapshot");
        assert_eq!(
            snapshot
                .selected
                .iter()
                .map(|candidate| candidate.id)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn contribution_and_signer_caps_apply_before_mutation() {
        let key = bucket(3, 0);
        let mut state = CoordinatorState::<u8>::default();
        for signer in 0..V1_MAX_AGGREGATION_SIGNERS {
            assert!(matches!(
                state.insert(key.clone(), vec![signer as u64], signer as u8),
                InsertOutcome::Inserted { .. }
            ));
        }
        assert_eq!(
            state.insert(key.clone(), vec![16], 16),
            InsertOutcome::CapacityExceeded
        );
        assert_eq!(state.buckets[&key].candidates.len(), 16);
    }

    #[test]
    fn committees_are_independent_and_only_one_snapshot_is_in_flight() {
        let first = bucket(4, 0);
        let second = bucket(4, 1);
        let mut state = CoordinatorState::<u8>::default();
        let _ = state.insert(first.clone(), vec![1], 1);
        let _ = state.insert(first.clone(), vec![2], 2);
        let _ = state.insert(second.clone(), vec![3], 3);
        assert!(state.snapshot(&first).is_ok());
        assert_eq!(
            state.snapshot(&first).map(|_| ()),
            Err(PrepareAggregateError::AlreadyInFlight)
        );
        let singleton = state.snapshot(&second).expect("other committee");
        assert!(singleton.token.is_none());
        assert_eq!(singleton.selected.len(), 1);
    }

    #[test]
    fn next_background_bucket_is_canonical_and_requires_exactly_two_raw_singletons() {
        let canonical = bucket_at(40, 0, 1);
        let later = bucket_at(41, 0, 2);
        let wrong_committee_size = bucket_at(38, 0, 0);
        let singleton = bucket_at(39, 0, 0);
        let contains_child = bucket_at(42, 0, 3);
        let mut state = CoordinatorState::<u8>::default();

        let _ = state.insert(wrong_committee_size.clone(), vec![8], 1);
        let _ = state.insert(wrong_committee_size.clone(), vec![9], 2);
        let _ = state.insert(later.clone(), vec![3], 3);
        let _ = state.insert(later.clone(), vec![4], 4);
        let _ = state.insert(canonical.clone(), vec![1], 1);
        let _ = state.insert(canonical.clone(), vec![2], 2);
        let _ = state.insert(singleton, vec![0], 0);
        let _ = state.insert(contains_child, vec![5, 6], 5);
        let _ = state.insert(bucket_at(42, 0, 3), vec![7], 7);

        assert_eq!(
            next_ready_pq_background_aggregation_bucket(&state, |bucket, candidate| {
                bucket != &wrong_committee_size && *candidate < 5
            }),
            Some(canonical.clone()),
        );

        let held = state
            .snapshot(&canonical)
            .expect("canonical bucket in flight");
        assert_eq!(
            next_ready_pq_background_aggregation_bucket(&state, |bucket, candidate| {
                bucket != &wrong_committee_size && *candidate < 5
            }),
            Some(later),
        );
        drop(held);
    }

    #[test]
    fn arrivals_survive_commit_but_selected_pruning_makes_it_stale() {
        let key = bucket(5, 0);
        let mut state = CoordinatorState::<u8>::default();
        let _ = state.insert(key.clone(), vec![1], 1);
        let _ = state.insert(key.clone(), vec![2], 2);
        let snapshot = state.snapshot(&key).expect("snapshot");
        let _ = state.insert(key.clone(), vec![3], 3);
        assert_eq!(
            state.commit(&key, &snapshot, vec![1, 2], 9, 0),
            MachineCommit::Committed
        );
        assert!(
            state.buckets[&key]
                .candidates
                .iter()
                .any(|candidate| candidate.signer_indices == [3])
        );

        let stale_snapshot = state.snapshot(&key).expect("second snapshot");
        let _ = state.insert(key.clone(), vec![1, 2, 3], 10);
        assert_eq!(
            state.commit(&key, &stale_snapshot, vec![1, 2, 3], 11, 0),
            MachineCommit::Stale
        );
        assert!(state.buckets[&key].in_flight.is_none());
    }

    #[test]
    fn commit_prunes_concurrent_arrivals_dominated_by_the_finished_union() {
        let key = bucket(9, 0);
        let mut state = CoordinatorState::<u8>::default();
        let _ = state.insert_sized(key.clone(), vec![1, 2], 1, 10);
        let _ = state.insert_sized(key.clone(), vec![3, 4], 2, 20);
        let snapshot = state.snapshot(&key).expect("snapshot");
        let _ = state.insert_sized(key.clone(), vec![1, 3], 3, 30);
        let _ = state.insert_sized(key.clone(), vec![1, 5], 4, 40);

        assert_eq!(
            state.commit(&key, &snapshot, vec![1, 2, 3, 4], 9, 50),
            MachineCommit::Committed
        );
        let candidates = &state.buckets[&key].candidates;
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.signer_indices == [1, 2, 3, 4])
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.signer_indices == [1, 5])
        );
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.signer_indices != [1, 3])
        );
        assert_eq!(state.retained_evidence_bytes, 90);
    }

    #[test]
    fn generation_overflow_fails_closed() {
        let key = bucket(7, 0);
        let mut state = CoordinatorState::<u8> {
            next_id: u64::MAX,
            ..CoordinatorState::default()
        };
        assert_eq!(
            state.insert(key.clone(), vec![1], 1),
            InsertOutcome::GenerationExhausted
        );
        assert!(!state.buckets.contains_key(&key));
    }

    #[test]
    fn distinct_bucket_and_total_evidence_caps_are_checked_before_mutation() {
        let mut buckets = CoordinatorState::<u8>::default();
        for index in 0..V1_MAX_ATTESTATION_BUCKETS {
            let key = bucket(index as u8, 0);
            assert!(matches!(
                buckets.insert_sized(key, vec![1], index as u8, 0),
                InsertOutcome::Inserted { .. }
            ));
        }
        let cap_plus_one = bucket(V1_MAX_ATTESTATION_BUCKETS as u8, 0);
        assert_eq!(
            buckets.insert_sized(cap_plus_one.clone(), vec![1], 99, 0),
            InsertOutcome::BucketCapacityExceeded {
                actual: V1_MAX_ATTESTATION_BUCKETS + 1,
                max: V1_MAX_ATTESTATION_BUCKETS,
            }
        );
        assert!(!buckets.buckets.contains_key(&cap_plus_one));
        let released = buckets.prune_before_slot(types::Slot::new(1));
        assert_eq!(released.buckets_removed, V1_MAX_ATTESTATION_BUCKETS);
        let replacement_bucket = bucket_at(65, 0, 1);
        assert!(matches!(
            buckets.insert_sized(replacement_bucket, vec![1], 100, 0),
            InsertOutcome::Inserted { .. }
        ));

        let exact_key = bucket(70, 0);
        let mut exact = CoordinatorState::<u8>::default();
        assert!(matches!(
            exact.insert_sized(
                exact_key,
                vec![1],
                1,
                consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES,
            ),
            InsertOutcome::Inserted { .. }
        ));
        assert_eq!(
            exact.retained_evidence_bytes,
            consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES
        );
        assert_eq!(
            exact.insert_sized(bucket(70, 0), vec![2], 2, 1),
            InsertOutcome::EvidenceCapacityExceeded {
                actual: consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES.saturating_add(1),
                max: consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES,
            }
        );
        assert_eq!(exact.buckets[&bucket(70, 0)].candidates.len(), 1);

        let too_large_key = bucket(71, 0);
        let mut too_large = CoordinatorState::<u8>::default();
        assert_eq!(
            too_large.insert_sized(
                too_large_key.clone(),
                vec![1],
                1,
                consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES.saturating_add(1),
            ),
            InsertOutcome::EvidenceCapacityExceeded {
                actual: consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES.saturating_add(1),
                max: consensus_signature::V1_MAX_AGGREGATION_INPUT_BYTES,
            }
        );
        assert!(!too_large.buckets.contains_key(&too_large_key));
    }

    #[test]
    fn pruning_releases_bucket_and_evidence_capacity_without_touching_current_slots() {
        let old = bucket_at(72, 0, 0);
        let current = bucket_at(73, 0, 1);
        let replacement = bucket_at(74, 0, 2);
        let mut state = CoordinatorState::<u8>::default();
        let old_bytes = V1_MAX_RETAINED_EVIDENCE_BYTES.saturating_sub(60);
        let _ = state.insert_sized(old.clone(), vec![1], 1, old_bytes);
        let _ = state.insert_sized(current.clone(), vec![2], 2, 60);

        let pruned = state.prune_before_slot(types::Slot::new(1));
        assert_eq!(pruned.buckets_removed, 1);
        assert_eq!(pruned.candidates_removed, 1);
        assert_eq!(pruned.evidence_bytes_released, old_bytes);
        assert!(!state.buckets.contains_key(&old));
        assert!(state.buckets.contains_key(&current));
        assert_eq!(state.retained_evidence_bytes, 60);
        assert!(matches!(
            state.insert_sized(replacement, vec![3], 3, old_bytes),
            InsertOutcome::Inserted { .. }
        ));
        assert_eq!(
            state.retained_evidence_bytes,
            V1_MAX_RETAINED_EVIDENCE_BYTES
        );
    }

    #[test]
    fn pruning_an_in_flight_bucket_makes_shared_execution_stale_without_resurrection() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };

        let key = bucket_at(75, 0, 0);
        let state = Arc::new(Mutex::new(CoordinatorState::<u8>::default()));
        let execution = {
            let mut guard = state.lock();
            let _ = guard.insert_sized(key.clone(), vec![1], 1, 10);
            let _ = guard.insert_sized(key.clone(), vec![2], 2, 20);
            let snapshot = guard.snapshot(&key).expect("in-flight snapshot");
            PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot)
        };
        let pruned = state.lock().prune_before_slot(types::Slot::new(1));
        assert_eq!(pruned.evidence_bytes_released, 30);
        let mut future =
            Box::pin(execution.execute_with(async { Ok::<_, &'static str>((vec![1, 2], 9, 50)) }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(MachineExecution::Stale)
        ));
        assert!(!state.lock().buckets.contains_key(&key));
    }

    #[test]
    fn pruning_during_await_makes_backend_failure_stale_without_resurrection() {
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll, Waker},
        };

        struct YieldOnce(bool);

        impl Future for YieldOnce {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let key = bucket_at(78, 0, 0);
        let state = Arc::new(Mutex::new(CoordinatorState::<u8>::default()));
        let execution = {
            let mut guard = state.lock();
            let _ = guard.insert_sized(key.clone(), vec![1], 1, 10);
            let _ = guard.insert_sized(key.clone(), vec![2], 2, 20);
            let snapshot = guard.snapshot(&key).expect("in-flight snapshot");
            PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot)
        };
        let mut future = Box::pin(execution.execute_with(async {
            YieldOnce(false).await;
            Err::<(Vec<u64>, u8, usize), _>("worker stopped")
        }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));

        let pruned = state.lock().prune_before_slot(types::Slot::new(1));
        assert_eq!(pruned.buckets_removed, 1);
        assert_eq!(pruned.candidates_removed, 2);
        assert_eq!(pruned.evidence_bytes_released, 30);
        assert_eq!(state.lock().retained_evidence_bytes, 0);

        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(MachineExecution::Stale)
        ));
        let state = state.lock();
        assert!(!state.buckets.contains_key(&key));
        assert_eq!(state.retained_evidence_bytes, 0);
    }

    #[test]
    fn old_failure_cannot_clear_a_recreated_buckets_replacement_snapshot() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };

        let key = bucket_at(79, 0, 0);
        let state = Arc::new(Mutex::new(CoordinatorState::<u8>::default()));
        let (old_execution, old_token) = {
            let mut guard = state.lock();
            let _ = guard.insert_sized(key.clone(), vec![1], 1, 10);
            let _ = guard.insert_sized(key.clone(), vec![2], 2, 20);
            let snapshot = guard.snapshot(&key).expect("old in-flight snapshot");
            let token = snapshot.token.expect("old snapshot token");
            (
                PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot),
                token,
            )
        };

        let (replacement_execution, replacement_token, candidates_before) = {
            let mut guard = state.lock();
            let pruned = guard.prune_before_slot(types::Slot::new(1));
            assert_eq!(pruned.evidence_bytes_released, 30);
            let _ = guard.insert_sized(key.clone(), vec![3], 3, 40);
            let _ = guard.insert_sized(key.clone(), vec![4], 4, 50);
            let snapshot = guard.snapshot(&key).expect("replacement snapshot");
            let token = snapshot.token.expect("replacement snapshot token");
            assert_ne!(token, old_token, "the regression requires a token mismatch");
            let candidates = guard.buckets[&key]
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.id,
                        candidate.signer_indices.clone(),
                        *candidate.value,
                        candidate.evidence_bytes,
                    )
                })
                .collect::<Vec<_>>();
            (
                PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot),
                token,
                candidates,
            )
        };

        let mut old_future = Box::pin(
            old_execution
                .execute_with(async { Err::<(Vec<u64>, u8, usize), _>("old worker stopped") }),
        );
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            old_future.as_mut().poll(&mut context),
            Poll::Ready(MachineExecution::Stale)
        ));

        let guard = state.lock();
        let replacement = &guard.buckets[&key];
        assert_eq!(replacement.in_flight, Some(replacement_token));
        assert_eq!(guard.retained_evidence_bytes, 90);
        assert_eq!(
            replacement
                .candidates
                .iter()
                .map(|candidate| {
                    (
                        candidate.id,
                        candidate.signer_indices.clone(),
                        *candidate.value,
                        candidate.evidence_bytes,
                    )
                })
                .collect::<Vec<_>>(),
            candidates_before
        );
        drop(guard);
        drop(replacement_execution);
    }

    #[test]
    fn aggregate_commit_accepts_exact_evidence_cap_and_rejects_max_plus_one_atomically() {
        let exact_key = bucket(76, 0);
        let mut exact = CoordinatorState::<u8>::default();
        let _ = exact.insert_sized(exact_key.clone(), vec![1], 1, 0);
        let _ = exact.insert_sized(exact_key.clone(), vec![2], 2, 0);
        let exact_snapshot = exact.snapshot(&exact_key).expect("exact snapshot");
        assert_eq!(
            exact.commit(
                &exact_key,
                &exact_snapshot,
                vec![1, 2],
                9,
                V1_MAX_RETAINED_EVIDENCE_BYTES,
            ),
            MachineCommit::Committed
        );
        assert_eq!(
            exact.retained_evidence_bytes,
            V1_MAX_RETAINED_EVIDENCE_BYTES
        );

        let overflow_key = bucket(77, 0);
        let mut overflow = CoordinatorState::<u8>::default();
        let _ = overflow.insert_sized(overflow_key.clone(), vec![1], 1, 0);
        let _ = overflow.insert_sized(overflow_key.clone(), vec![2], 2, 0);
        let overflow_snapshot = overflow.snapshot(&overflow_key).expect("overflow snapshot");
        assert_eq!(
            overflow.commit(
                &overflow_key,
                &overflow_snapshot,
                vec![1, 2],
                9,
                V1_MAX_RETAINED_EVIDENCE_BYTES.saturating_add(1),
            ),
            MachineCommit::EvidenceCapacityExceeded {
                actual: V1_MAX_RETAINED_EVIDENCE_BYTES.saturating_add(1),
                max: V1_MAX_RETAINED_EVIDENCE_BYTES,
            }
        );
        assert_eq!(overflow.buckets[&overflow_key].candidates.len(), 2);
        assert!(overflow.buckets[&overflow_key].in_flight.is_none());
        assert_eq!(overflow.retained_evidence_bytes, 0);
    }

    #[test]
    fn fake_executor_reenters_after_await_without_crossing_the_state_lock() {
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll, Waker},
        };

        struct YieldOnce(bool);

        impl Future for YieldOnce {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        struct FakeExecutor {
            state: Arc<Mutex<CoordinatorState<u8>>>,
            bucket: PqAttestationBucket,
        }

        impl FakeExecutor {
            async fn execute(&self) -> Result<(Vec<u64>, u8, usize), &'static str> {
                YieldOnce(false).await;
                let mut state = self.state.try_lock().expect("coordinator lock released");
                let outcome = state.insert(self.bucket.clone(), vec![3], 3);
                assert!(matches!(outcome, InsertOutcome::Inserted { .. }));
                Ok((vec![1, 2], 9, 0))
            }
        }

        let key = bucket(8, 0);
        let state = Arc::new(Mutex::new(CoordinatorState::<u8>::default()));
        let execution = {
            let mut guard = state.lock();
            let _ = guard.insert(key.clone(), vec![1], 1);
            let _ = guard.insert(key.clone(), vec![2], 2);
            let snapshot = guard.snapshot(&key).expect("in-flight snapshot");
            PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot)
        };
        let executor = FakeExecutor {
            state: Arc::clone(&state),
            bucket: key.clone(),
        };
        let mut future = Box::pin(execution.execute_with(executor.execute()));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert!(state.try_lock().is_some());
        let Poll::Ready(MachineExecution::Committed(aggregate)) =
            future.as_mut().poll(&mut context)
        else {
            panic!("fake execution should commit");
        };
        assert_eq!(*aggregate, 9);
        let state = state.lock();
        assert_eq!(state.buckets[&key].candidates.len(), 2);
        assert!(
            state.buckets[&key]
                .candidates
                .iter()
                .any(|candidate| candidate.signer_indices == [3])
        );
    }

    #[test]
    fn shared_execution_failure_and_drop_clear_in_flight_without_losing_sources() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };

        let key = bucket(10, 0);
        let state = Arc::new(Mutex::new(CoordinatorState::<u8>::default()));
        let execution = {
            let mut guard = state.lock();
            let _ = guard.insert(key.clone(), vec![1], 1);
            let _ = guard.insert(key.clone(), vec![2], 2);
            let snapshot = guard.snapshot(&key).expect("in-flight snapshot");
            PreparedExecution::new(Arc::clone(&state), key.clone(), snapshot)
        };
        let mut future = Box::pin(
            execution.execute_with(async { Err::<(Vec<u64>, u8, usize), _>("queue saturated") }),
        );
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(MachineExecution::Failed("queue saturated"))
        ));
        drop(future);
        assert_eq!(state.lock().buckets[&key].candidates.len(), 2);

        let dropped = {
            let mut guard = state.lock();
            let retry = guard.snapshot(&key).expect("failure permits retry");
            PreparedExecution::new(Arc::clone(&state), key.clone(), retry)
        };
        drop(dropped);
        assert!(state.lock().snapshot(&key).is_ok());
    }
}
