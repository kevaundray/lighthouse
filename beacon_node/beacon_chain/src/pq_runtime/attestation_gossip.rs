use crate::{BeaconChain, BeaconChainTypes, BeaconSnapshot};
use parking_lot::Mutex;
use slot_clock::SlotClock;
use state_processing::{
    PqAttestationError, PqAttestationInvalid, PqAttestationLocalError, PqConsensusError,
    PqConsensusInvalid, PqConsensusLocalError, PreparedPqAggregateAndProof,
    PreparedPqSingleAttestation, VerifiedPqAggregateAndProof, VerifiedPqSingleAttestation,
    prepare_pq_aggregate_and_proof, prepare_pq_single_attestation,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use tree_hash::TreeHash;
use types::{
    AttestationRef, BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedAggregateAndProof,
    SignedBeaconBlock, SingleAttestation, Slot, SubnetId,
};

/// At most two large PQ gossip candidates may retain preparation/proof state concurrently.
pub const PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY: usize = 2;
// The V1 profile has exactly 16 validators and gossip retains at most the current and previous
// epoch, so each per-validator observation index is bounded by 16 * 2 entries.
const PQ_ATTESTATION_OBSERVATION_CAPACITY: usize = 16 * 2;

#[derive(Debug)]
pub enum PqAttestationGossipPeerInvalid {
    InvalidTargetEpoch,
    TargetRootMismatch {
        expected: Hash256,
        actual: Hash256,
    },
    InvalidSubnet {
        expected: SubnetId,
        actual: SubnetId,
    },
    ReferencedBlockAfterAttestation {
        block: Slot,
        attestation: Slot,
    },
    InvalidAttestation(PqAttestationInvalid),
    InvalidAggregate(PqConsensusInvalid),
}

#[derive(Debug)]
pub enum PqAttestationGossipLocalError {
    ShuttingDown,
    IngressCapacity,
    ClockUnavailable,
    ReceiptBeforeWindow {
        attestation: Slot,
        latest_permissible: Slot,
    },
    ReceiptAfterWindow {
        attestation: Slot,
        earliest_permissible: Slot,
    },
    BlockingTask(&'static str),
    AsyncTask(&'static str),
    BoundHeadNoLongerCanonical {
        bound: Hash256,
        current: Hash256,
    },
    ProofOutlivedPropagationWindow {
        attestation: Slot,
    },
    ReferencedBlockUnavailable(Hash256),
    ReferencedStateUnavailable(Hash256),
    StateAdvanceTooLarge {
        referenced_block: Slot,
        attestation: Slot,
        maximum: u64,
    },
    StateUnavailable,
    ObservationCapacity,
    ObservationGenerationExhausted,
    ObservationLost,
    Attestation(PqAttestationLocalError),
    Aggregate(PqConsensusLocalError),
    Store(store::Error),
}

#[derive(Debug)]
pub enum PqAttestationGossipError {
    PeerInvalid(PqAttestationGossipPeerInvalid),
    Local(PqAttestationGossipLocalError),
    Duplicate(PqAttestationGossipObservation),
}

impl PqAttestationGossipError {
    pub const fn should_penalize_peer(&self) -> bool {
        matches!(self, Self::PeerInvalid(_))
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Local(error) if !matches!(
            error,
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow { .. }
                | PqAttestationGossipLocalError::BoundHeadNoLongerCanonical { .. }
                | PqAttestationGossipLocalError::StateAdvanceTooLarge { .. }
                | PqAttestationGossipLocalError::ObservationGenerationExhausted
                | PqAttestationGossipLocalError::ShuttingDown
                | PqAttestationGossipLocalError::ReceiptAfterWindow { .. }
        ))
    }
}

impl std::fmt::Display for PqAttestationGossipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ attestation gossip failed: {self:?}")
    }
}

impl std::error::Error for PqAttestationGossipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(PqAttestationGossipLocalError::Attestation(
                PqAttestationLocalError::SigningId(error),
            )) => Some(error),
            Self::Local(PqAttestationGossipLocalError::Attestation(
                PqAttestationLocalError::Aggregation(error),
            )) => Some(error),
            Self::Local(PqAttestationGossipLocalError::Aggregate(
                PqConsensusLocalError::SigningId(error),
            )) => Some(error),
            Self::Local(PqAttestationGossipLocalError::Aggregate(
                PqConsensusLocalError::Aggregation(error),
            )) => Some(error),
            Self::Local(PqAttestationGossipLocalError::Aggregate(
                PqConsensusLocalError::Attestation(PqAttestationLocalError::SigningId(error)),
            )) => Some(error),
            Self::Local(PqAttestationGossipLocalError::Aggregate(
                PqConsensusLocalError::Attestation(PqAttestationLocalError::Aggregation(error)),
            )) => Some(error),
            Self::PeerInvalid(_)
            | Self::Duplicate(_)
            | Self::Local(
                PqAttestationGossipLocalError::ShuttingDown
                | PqAttestationGossipLocalError::IngressCapacity
                | PqAttestationGossipLocalError::ClockUnavailable
                | PqAttestationGossipLocalError::ReceiptBeforeWindow { .. }
                | PqAttestationGossipLocalError::ReceiptAfterWindow { .. }
                | PqAttestationGossipLocalError::BlockingTask(_)
                | PqAttestationGossipLocalError::AsyncTask(_)
                | PqAttestationGossipLocalError::BoundHeadNoLongerCanonical { .. }
                | PqAttestationGossipLocalError::ProofOutlivedPropagationWindow { .. }
                | PqAttestationGossipLocalError::ReferencedBlockUnavailable(_)
                | PqAttestationGossipLocalError::ReferencedStateUnavailable(_)
                | PqAttestationGossipLocalError::StateAdvanceTooLarge { .. }
                | PqAttestationGossipLocalError::StateUnavailable
                | PqAttestationGossipLocalError::ObservationCapacity
                | PqAttestationGossipLocalError::ObservationGenerationExhausted
                | PqAttestationGossipLocalError::ObservationLost
                | PqAttestationGossipLocalError::Store(_)
                | PqAttestationGossipLocalError::Attestation(
                    PqAttestationLocalError::UnsupportedProfile
                    | PqAttestationLocalError::CommitteeCacheUnavailable
                    | PqAttestationLocalError::CacheInvariant,
                )
                | PqAttestationGossipLocalError::Aggregate(
                    PqConsensusLocalError::UnsupportedProfile
                    | PqConsensusLocalError::StateUnavailable
                    | PqConsensusLocalError::CacheInvariant
                    | PqConsensusLocalError::Attestation(
                        PqAttestationLocalError::UnsupportedProfile
                        | PqAttestationLocalError::CommitteeCacheUnavailable
                        | PqAttestationLocalError::CacheInvariant,
                    ),
                ),
            ) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObservationState {
    Pending {
        identity: Hash256,
        generation: u64,
    },
    ConsumptionPending {
        identity: Hash256,
        generation: u64,
    },
    Observed {
        identity: Hash256,
    },
    Consumed {
        identity: Hash256,
        result: PqSingleConsumptionResult,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqSingleConsumptionResult {
    Applied,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationGossipObservation {
    Unseen,
    Pending,
    Observed,
    Conflict,
    Capacity,
    GenerationExhausted,
}

pub(crate) struct PqAttestationGossipObservationCache<E: EthSpec> {
    singles: HashMap<(Epoch, u64), ObservationState>,
    aggregators: HashMap<(Epoch, u64), ObservationState>,
    aggregate_candidates: HashMap<(Slot, Hash256, u64), Vec<AggregateObservation<E>>>,
    next_generation: u64,
}

struct AggregateObservation<E: EthSpec> {
    identity: Hash256,
    generation: u64,
    pending: bool,
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

impl<E: EthSpec> Default for PqAttestationGossipObservationCache<E> {
    fn default() -> Self {
        Self {
            singles: HashMap::new(),
            aggregators: HashMap::new(),
            aggregate_candidates: HashMap::new(),
            next_generation: 0,
        }
    }
}

impl<E: EthSpec> PqAttestationGossipObservationCache<E> {
    fn allocate_generation(&mut self) -> Result<u64, PqAttestationGossipObservation> {
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(PqAttestationGossipObservation::GenerationExhausted)?;
        self.next_generation = generation;
        Ok(generation)
    }

    fn prune(&mut self, earliest_slot: Slot) {
        let earliest_epoch = earliest_slot.epoch(E::slots_per_epoch());
        self.singles.retain(|(epoch, _), state| {
            *epoch >= earliest_epoch || matches!(state, ObservationState::ConsumptionPending { .. })
        });
        self.aggregators
            .retain(|(epoch, _), _| *epoch >= earliest_epoch);
        self.aggregate_candidates
            .retain(|(slot, _, _), _| *slot >= earliest_slot);
    }

    fn single_status(
        &self,
        key: (Epoch, u64),
        _identity: Hash256,
    ) -> PqAttestationGossipObservation {
        match self.singles.get(&key) {
            Some(ObservationState::Pending { .. }) => PqAttestationGossipObservation::Pending,
            Some(ObservationState::ConsumptionPending { .. }) => {
                PqAttestationGossipObservation::Observed
            }
            Some(ObservationState::Observed { .. }) => PqAttestationGossipObservation::Observed,
            Some(ObservationState::Consumed { .. }) => PqAttestationGossipObservation::Observed,
            None if self.singles.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY => {
                PqAttestationGossipObservation::Capacity
            }
            None => PqAttestationGossipObservation::Unseen,
        }
    }

    fn precheck_single(
        &mut self,
        key: (Epoch, u64),
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.prune(earliest_slot);
        self.single_status(key, Hash256::default())
    }

    fn claim_single(
        &mut self,
        key: (Epoch, u64),
        identity: Hash256,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.prune(earliest_slot);
        match self.single_status(key, identity) {
            PqAttestationGossipObservation::Unseen => {
                let generation = self.allocate_generation()?;
                self.singles.insert(
                    key,
                    ObservationState::Pending {
                        identity,
                        generation,
                    },
                );
                Ok(generation)
            }
            other => Err(other),
        }
    }

    fn finalize_single(
        &mut self,
        key: (Epoch, u64),
        identity: Hash256,
        generation: u64,
        result: PqSingleConsumptionResult,
    ) -> bool {
        let authorized = matches!(
            self.singles.get(&key),
            Some(
                ObservationState::Pending {
                    identity: known,
                    generation: known_generation,
                } | ObservationState::ConsumptionPending {
                    identity: known,
                    generation: known_generation,
                }
            ) if *known == identity && *known_generation == generation
        );
        if authorized {
            self.singles
                .insert(key, ObservationState::Consumed { identity, result });
        }
        authorized
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn single_consumption_result(
        &self,
        key: (Epoch, u64),
    ) -> Option<PqSingleConsumptionResult> {
        match self.singles.get(&key) {
            Some(ObservationState::Consumed { result, .. }) => Some(*result),
            _ => None,
        }
    }

    fn retains_single(&self, key: (Epoch, u64), identity: Hash256, generation: u64) -> bool {
        matches!(
            self.singles.get(&key),
            Some(ObservationState::Pending {
                identity: known,
                generation: known_generation,
            }) if *known == identity && *known_generation == generation
        )
    }

    fn mark_single_propagated(
        &mut self,
        key: (Epoch, u64),
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let authorized = self.retains_single(key, identity, generation);
        if authorized {
            self.singles.insert(
                key,
                ObservationState::ConsumptionPending {
                    identity,
                    generation,
                },
            );
        }
        authorized
    }

    fn rollback_single(&mut self, key: (Epoch, u64), identity: Hash256, generation: u64) {
        if matches!(
            self.singles.get(&key),
            Some(ObservationState::Pending {
                identity: known,
                generation: known_generation,
            }) if *known == identity && *known_generation == generation
        ) {
            self.singles.remove(&key);
        }
    }

    fn aggregate_status(
        &self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        identity: Hash256,
        bits: &ssz_types::BitList<E::MaxValidatorsPerSlot>,
    ) -> PqAttestationGossipObservation {
        if let Some(state) = self.aggregators.get(&aggregator_key) {
            return match state {
                ObservationState::Pending {
                    identity: known, ..
                } if *known == identity => PqAttestationGossipObservation::Pending,
                ObservationState::Observed { identity: known } if *known == identity => {
                    PqAttestationGossipObservation::Observed
                }
                _ => PqAttestationGossipObservation::Observed,
            };
        }
        if let Some(known) = self.aggregate_candidates.get(&data_key) {
            for candidate in known {
                if bits.is_subset(&candidate.bits) {
                    return if candidate.pending {
                        PqAttestationGossipObservation::Pending
                    } else {
                        PqAttestationGossipObservation::Observed
                    };
                }
                if candidate.pending && candidate.bits.is_subset(bits) {
                    return PqAttestationGossipObservation::Pending;
                }
            }
        }
        let candidate_count = self
            .aggregate_candidates
            .values()
            .fold(0usize, |count, candidates| {
                count.saturating_add(candidates.len())
            });
        if self.aggregators.len() >= PQ_ATTESTATION_OBSERVATION_CAPACITY
            || candidate_count >= PQ_ATTESTATION_OBSERVATION_CAPACITY
        {
            PqAttestationGossipObservation::Capacity
        } else {
            PqAttestationGossipObservation::Unseen
        }
    }

    fn precheck_aggregate(
        &mut self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        bits: &ssz_types::BitList<E::MaxValidatorsPerSlot>,
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.prune(earliest_slot);
        self.aggregate_status(aggregator_key, data_key, Hash256::default(), bits)
    }

    fn claim_aggregate(
        &mut self,
        aggregator_key: (Epoch, u64),
        data_key: (Slot, Hash256, u64),
        identity: Hash256,
        bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.prune(earliest_slot);
        match self.aggregate_status(aggregator_key, data_key, identity, &bits) {
            PqAttestationGossipObservation::Unseen => {
                let generation = self.allocate_generation()?;
                self.aggregators.insert(
                    aggregator_key,
                    ObservationState::Pending {
                        identity,
                        generation,
                    },
                );
                self.aggregate_candidates
                    .entry(data_key)
                    .or_default()
                    .push(AggregateObservation {
                        identity,
                        generation,
                        pending: true,
                        bits,
                    });
                Ok(generation)
            }
            other => Err(other),
        }
    }

    fn finalize_aggregate(&mut self, binding: &AggregateObservationBinding<E>) -> bool {
        let aggregator_authorized = matches!(
            self.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending { identity, generation })
                if *identity == binding.identity && *generation == binding.generation
        );
        let candidate_authorized = self
            .aggregate_candidates
            .get(&binding.data_key)
            .is_some_and(|candidates| {
                candidates.iter().any(|candidate| {
                    candidate.pending
                        && candidate.identity == binding.identity
                        && candidate.generation == binding.generation
                })
            });
        if !aggregator_authorized || !candidate_authorized {
            return false;
        }
        self.aggregators.insert(
            binding.aggregator_key,
            ObservationState::Observed {
                identity: binding.identity,
            },
        );
        if let Some(candidates) = self.aggregate_candidates.get_mut(&binding.data_key) {
            candidates.retain(|candidate| {
                candidate.generation == binding.generation
                    || candidate.pending
                    || !candidate.bits.is_subset(&binding.bits)
            });
            if let Some(candidate) = candidates
                .iter_mut()
                .find(|candidate| candidate.generation == binding.generation)
            {
                candidate.pending = false;
            }
        }
        true
    }

    fn rollback_aggregate(&mut self, binding: &AggregateObservationBinding<E>) {
        if matches!(
            self.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending { identity, generation })
                if *identity == binding.identity && *generation == binding.generation
        ) {
            self.aggregators.remove(&binding.aggregator_key);
        }
        if let Some(candidates) = self.aggregate_candidates.get_mut(&binding.data_key) {
            candidates.retain(|candidate| {
                !(candidate.pending
                    && candidate.identity == binding.identity
                    && candidate.generation == binding.generation)
            });
            if candidates.is_empty() {
                self.aggregate_candidates.remove(&binding.data_key);
            }
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
#[derive(Default)]
pub struct TestingPqAttestationObservationCache {
    inner: PqAttestationGossipObservationCache<types::MinimalEthSpec>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqAttestationObservationCache {
    fn participant_bits(
        participant_indices: &[usize],
    ) -> ssz_types::BitList<<types::MinimalEthSpec as EthSpec>::MaxValidatorsPerSlot> {
        let mut bits = ssz_types::BitList::with_capacity(16)
            .expect("16 participants fit the minimal test profile");
        for index in participant_indices {
            bits.set(*index, true)
                .expect("test participant index is within the 16-validator profile");
        }
        bits
    }

    pub const fn capacity(&self) -> usize {
        PQ_ATTESTATION_OBSERVATION_CAPACITY
    }

    pub fn len_singles(&self) -> usize {
        self.inner.singles.len()
    }

    pub fn set_next_generation(&mut self, generation: u64) {
        self.inner.next_generation = generation;
    }

    pub fn observe_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        earliest_slot: Slot,
    ) -> Result<(), PqAttestationGossipObservation> {
        let key = (epoch, validator_index);
        let generation = self.inner.claim_single(key, identity, earliest_slot)?;
        if self.inner.finalize_single(
            key,
            identity,
            generation,
            PqSingleConsumptionResult::Applied,
        ) {
            Ok(())
        } else {
            Err(PqAttestationGossipObservation::Conflict)
        }
    }

    pub fn claim_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner
            .claim_single((epoch, validator_index), identity, earliest_slot)
    }

    pub fn status_single(
        &self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
    ) -> PqAttestationGossipObservation {
        self.inner.single_status((epoch, validator_index), identity)
    }

    pub fn finalize_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        self.inner.finalize_single(
            (epoch, validator_index),
            identity,
            generation,
            PqSingleConsumptionResult::Applied,
        )
    }

    pub fn mark_single_propagated(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        self.inner
            .mark_single_propagated((epoch, validator_index), identity, generation)
    }

    pub fn finalize_single_terminal(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        self.inner.finalize_single(
            (epoch, validator_index),
            identity,
            generation,
            PqSingleConsumptionResult::Terminal,
        )
    }

    pub fn single_consumption_result(
        &self,
        epoch: Epoch,
        validator_index: u64,
    ) -> Option<PqSingleConsumptionResult> {
        self.inner
            .single_consumption_result((epoch, validator_index))
    }

    pub fn rollback_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        identity: Hash256,
        generation: u64,
    ) -> bool {
        let key = (epoch, validator_index);
        let authorized = matches!(
            self.inner.singles.get(&key),
            Some(ObservationState::Pending {
                identity: known,
                generation: known_generation,
            }) if *known == identity && *known_generation == generation
        );
        self.inner.rollback_single(key, identity, generation);
        authorized
    }

    pub fn precheck_single(
        &mut self,
        epoch: Epoch,
        validator_index: u64,
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.inner
            .precheck_single((epoch, validator_index), earliest_slot)
    }

    pub fn len_aggregators(&self) -> usize {
        self.inner.aggregators.len()
    }

    pub fn len_aggregate_candidates(&self) -> usize {
        self.inner.aggregate_candidates.values().map(Vec::len).sum()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        participant_indices: &[usize],
        earliest_slot: Slot,
    ) -> Result<u64, PqAttestationGossipObservation> {
        self.inner.claim_aggregate(
            (epoch, aggregator_index),
            (slot, data_root, committee_index),
            identity,
            Self::participant_bits(participant_indices),
            earliest_slot,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        generation: u64,
        participant_indices: &[usize],
    ) -> bool {
        self.inner.finalize_aggregate(&AggregateObservationBinding {
            aggregator_key: (epoch, aggregator_index),
            data_key: (slot, data_root, committee_index),
            identity,
            generation,
            bits: Self::participant_bits(participant_indices),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rollback_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        identity: Hash256,
        generation: u64,
        participant_indices: &[usize],
    ) -> bool {
        let binding = AggregateObservationBinding {
            aggregator_key: (epoch, aggregator_index),
            data_key: (slot, data_root, committee_index),
            identity,
            generation,
            bits: Self::participant_bits(participant_indices),
        };
        let authorized = matches!(
            self.inner.aggregators.get(&binding.aggregator_key),
            Some(ObservationState::Pending {
                identity: known,
                generation: known_generation,
            }) if *known == identity && *known_generation == generation
        );
        self.inner.rollback_aggregate(&binding);
        authorized
    }

    #[allow(clippy::too_many_arguments)]
    pub fn precheck_aggregate(
        &mut self,
        epoch: Epoch,
        aggregator_index: u64,
        slot: Slot,
        data_root: Hash256,
        committee_index: u64,
        participant_indices: &[usize],
        earliest_slot: Slot,
    ) -> PqAttestationGossipObservation {
        self.inner.precheck_aggregate(
            (epoch, aggregator_index),
            (slot, data_root, committee_index),
            &Self::participant_bits(participant_indices),
            earliest_slot,
        )
    }
}

struct SingleObservationBinding {
    key: (Epoch, u64),
    identity: Hash256,
    generation: u64,
}

/// BeaconChain-contextual sealed provenance for a propagated single attestation.
pub struct PqVerifiedGossipSingle<E: EthSpec> {
    verified: Option<VerifiedPqSingleAttestation<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    admission: Option<OwnedSemaphorePermit>,
    activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
    subnet: SubnetId,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqVerifiedGossipSingle<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqSingleAttestation<E>> {
        self.verified.as_ref()
    }

    pub const fn subnet(&self) -> SubnetId {
        self.subnet
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub(crate) fn into_consumption_parts(
        mut self,
    ) -> Result<
        (
            VerifiedPqSingleAttestation<E>,
            SubnetId,
            Hash256,
            PqSingleGossipConsumption<E>,
        ),
        PqAttestationGossipError,
    > {
        if self.verified.is_none()
            || self.binding.is_none()
            || self.admission.is_none()
            || self.activity.is_none()
        {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let admission = self
            .admission
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        let activity = self.activity.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        Ok((
            verified,
            self.subnet,
            self.bound_head_root,
            PqSingleGossipConsumption {
                observations: Arc::clone(&self.observations),
                binding: Some(binding),
                _admission: admission,
                _activity: activity,
            },
        ))
    }
}

impl<E: EthSpec> Drop for PqVerifiedGossipSingle<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().finalize_single(
                binding.key,
                binding.identity,
                binding.generation,
                PqSingleConsumptionResult::Terminal,
            );
        }
    }
}

pub(crate) struct PqSingleGossipConsumption<E: EthSpec> {
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> PqSingleGossipConsumption<E> {
    pub(crate) fn finalize_applied(mut self) -> Result<(), PqAttestationGossipError> {
        self.finalize(PqSingleConsumptionResult::Applied)
    }

    pub(crate) fn finalize_terminal(mut self) -> Result<(), PqAttestationGossipError> {
        self.finalize(PqSingleConsumptionResult::Terminal)
    }

    fn finalize(
        &mut self,
        result: PqSingleConsumptionResult,
    ) -> Result<(), PqAttestationGossipError> {
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        if self.observations.lock().finalize_single(
            binding.key,
            binding.identity,
            binding.generation,
            result,
        ) {
            Ok(())
        } else {
            Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))
        }
    }
}

impl<E: EthSpec> Drop for PqSingleGossipConsumption<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().finalize_single(
                binding.key,
                binding.identity,
                binding.generation,
                PqSingleConsumptionResult::Terminal,
            );
        }
    }
}

/// Unique post-proof capability which must be consumed only after gossipsub accepts propagation.
pub struct PqSingleGossipPropagationToken<E: EthSpec> {
    verified: Option<VerifiedPqSingleAttestation<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<SingleObservationBinding>,
    _admission: Option<OwnedSemaphorePermit>,
    _activity: Option<Arc<crate::beacon_chain::PqImportActivity>>,
    subnet: SubnetId,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqSingleGossipPropagationToken<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqSingleAttestation<E>> {
        self.verified.as_ref()
    }

    /// Marks actual gossipsub propagation and returns the sealed provenance for Task 5.2b.
    pub fn mark_propagated(
        mut self,
    ) -> Result<PqVerifiedGossipSingle<E>, PqAttestationGossipError> {
        if self.verified.is_none()
            || self.binding.is_none()
            || self._admission.is_none()
            || self._activity.is_none()
        {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        let admission = self
            ._admission
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        let activity = self
            ._activity
            .take()
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ))?;
        if !self.observations.lock().mark_single_propagated(
            binding.key,
            binding.identity,
            binding.generation,
        ) {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        Ok(PqVerifiedGossipSingle {
            verified: Some(verified),
            observations: Arc::clone(&self.observations),
            binding: Some(binding),
            admission: Some(admission),
            activity: Some(activity),
            subnet: self.subnet,
            bound_head_root: self.bound_head_root,
        })
    }
}

impl<E: EthSpec> Drop for PqSingleGossipPropagationToken<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().rollback_single(
                binding.key,
                binding.identity,
                binding.generation,
            );
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_single_prepropagation_retry() -> bool {
    let observations = Arc::new(Mutex::new(PqAttestationGossipObservationCache::<
        types::MinimalEthSpec,
    >::default()));
    let key = (Epoch::new(0), 1);
    let identity = Hash256::repeat_byte(2);
    let Ok(generation) = observations
        .lock()
        .claim_single(key, identity, Slot::new(0))
    else {
        return false;
    };
    drop(PqSingleGossipPropagationToken {
        verified: None,
        observations: Arc::clone(&observations),
        binding: Some(SingleObservationBinding {
            key,
            identity,
            generation,
        }),
        _admission: None,
        _activity: None,
        subnet: SubnetId::new(0),
        bound_head_root: Hash256::ZERO,
    });
    if observations.lock().single_status(key, identity) != PqAttestationGossipObservation::Unseen {
        return false;
    }
    matches!(
        observations
            .lock()
            .claim_single(key, identity, Slot::new(0)),
        Ok(retry_generation) if retry_generation != generation
    )
}

struct AggregateObservationBinding<E: EthSpec> {
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    identity: Hash256,
    generation: u64,
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

/// BeaconChain-contextual sealed provenance for a propagated aggregate-and-proof.
pub struct PqVerifiedGossipAggregate<E: EthSpec> {
    verified: VerifiedPqAggregateAndProof<E>,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqVerifiedGossipAggregate<E> {
    pub const fn verified(&self) -> &VerifiedPqAggregateAndProof<E> {
        &self.verified
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub fn into_parts(self) -> (VerifiedPqAggregateAndProof<E>, Hash256) {
        (self.verified, self.bound_head_root)
    }
}

/// Unique aggregate propagation capability holding both exact outer and verified inner provenance.
pub struct PqAggregateGossipPropagationToken<E: EthSpec> {
    verified: Option<VerifiedPqAggregateAndProof<E>>,
    observations: Arc<Mutex<PqAttestationGossipObservationCache<E>>>,
    binding: Option<AggregateObservationBinding<E>>,
    _admission: Option<OwnedSemaphorePermit>,
    bound_head_root: Hash256,
}

impl<E: EthSpec> PqAggregateGossipPropagationToken<E> {
    pub const fn verified(&self) -> Option<&VerifiedPqAggregateAndProof<E>> {
        self.verified.as_ref()
    }

    pub fn mark_propagated(
        mut self,
    ) -> Result<PqVerifiedGossipAggregate<E>, PqAttestationGossipError> {
        let binding = self.binding.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        if !self.observations.lock().finalize_aggregate(&binding) {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationLost,
            ));
        }
        let verified = self.verified.take().ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationLost,
        ))?;
        Ok(PqVerifiedGossipAggregate {
            verified,
            bound_head_root: self.bound_head_root,
        })
    }
}

impl<E: EthSpec> Drop for PqAggregateGossipPropagationToken<E> {
    fn drop(&mut self) {
        if let Some(binding) = self.binding.take() {
            self.observations.lock().rollback_aggregate(&binding);
        }
    }
}

struct PreparedSingle<E: EthSpec> {
    prepared: PreparedPqSingleAttestation<E>,
    identity: Hash256,
    key: (Epoch, u64),
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
    activity: Arc<crate::beacon_chain::PqImportActivity>,
}

struct PreparedAggregate<E: EthSpec> {
    prepared: PreparedPqAggregateAndProof<E>,
    identity: Hash256,
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
    bound_head_root: Hash256,
    admission: OwnedSemaphorePermit,
}

struct CanonicalReference<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    state: BeaconState<E>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_try_reserve_pq_attestation_gossip_admission(
        &self,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.pq_attestation_gossip_admission).try_acquire_owned()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_attestation_gossip_available_permits(&self) -> usize {
        self.pq_attestation_gossip_admission.available_permits()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub async fn testing_only_pq_attestation_bound_is_canonical(
        &self,
        bound_root: Hash256,
    ) -> Result<bool, PqAttestationGossipError> {
        let admission = Arc::clone(&self.pq_attestation_gossip_admission)
            .try_acquire_owned()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        self.pq_attestation_bound_is_canonical(bound_root, admission)
            .await
            .map(|(is_canonical, _admission)| is_canonical)
    }

    async fn pq_attestation_bound_is_canonical(
        &self,
        bound_root: Hash256,
        admission: OwnedSemaphorePermit,
    ) -> Result<(bool, OwnedSemaphorePermit), PqAttestationGossipError> {
        let snapshot = self.head_snapshot();
        let store = Arc::clone(&self.store);
        #[cfg(feature = "pq-startup-testing")]
        let blocking_test_hook = self.pq_blocking_test_hook.clone();
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = blocking_test_hook {
                        hook.run();
                    }
                    canonical_lineage_contains::<T>(&store, &snapshot, bound_root)
                        .map(|is_canonical| (is_canonical, admission))
                },
                "pq-attestation-gossip-late-lineage",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-attestation-gossip-late-lineage"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-attestation-gossip-late-lineage",
                ))
            })?
    }

    pub async fn verify_pq_single_attestation_for_gossip(
        &self,
        attestation: SingleAttestation,
        subnet: SubnetId,
    ) -> Result<PqSingleGossipPropagationToken<T::EthSpec>, PqAttestationGossipError> {
        let activity =
            self.pq_import_coordinator
                .try_start()
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ShuttingDown,
                ))?;
        let admission = Arc::clone(&self.pq_attestation_gossip_admission)
            .try_acquire_owned()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        let (latest_slot, earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let key = (attestation.data.target.epoch, attestation.attester_index);
        let early_status = self
            .pq_attestation_gossip_observations
            .lock()
            .precheck_single(key, earliest_slot);
        classify_observation(early_status)?;
        let snapshot = self.head_snapshot();
        let store = Arc::clone(&self.store);
        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        let preparation = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    prepare_single_context::<T>(
                        store,
                        snapshot,
                        spec,
                        key_cache,
                        attestation,
                        subnet,
                        latest_slot,
                        earliest_slot,
                        admission,
                        activity,
                    )
                },
                "pq-attestation-gossip-prepare",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-attestation-gossip-prepare"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-attestation-gossip-prepare",
                ))
            })??;

        let service = Arc::clone(&self.pq_aggregation_service);
        let proof_task = self
            .task_executor
            .spawn_handle(
                async move {
                    let PreparedSingle {
                        prepared,
                        identity,
                        key,
                        bound_head_root,
                        admission,
                        activity,
                    } = preparation;
                    (
                        prepared.verify(&service).await,
                        identity,
                        key,
                        bound_head_root,
                        admission,
                        activity,
                    )
                },
                "pq-attestation-gossip-proof",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-attestation-gossip-proof"),
            ))?;
        let Some((verified, identity, key, bound_head_root, admission, activity)) =
            proof_task.await.map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::AsyncTask(
                    "pq-attestation-gossip-proof",
                ))
            })?
        else {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-attestation-gossip-proof"),
            ));
        };
        let verified = verified.map_err(map_attestation_error)?;

        let (late_latest_slot, late_earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec).map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::ClockUnavailable)
            })?;
        let verified_slot = verified.single_attestation().data.slot;
        validate_late_propagation_window(verified_slot, late_earliest_slot, late_latest_slot)?;
        let actual_head = self.head_snapshot().beacon_block_root;
        let (bound_is_canonical, admission) = self
            .pq_attestation_bound_is_canonical(bound_head_root, admission)
            .await?;
        if !bound_is_canonical {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
                    bound: bound_head_root,
                    current: actual_head,
                },
            ));
        }
        let generation = self
            .pq_attestation_gossip_observations
            .lock()
            .claim_single(key, identity, late_earliest_slot)
            .map_err(observation_error)?;
        Ok(PqSingleGossipPropagationToken {
            verified: Some(verified),
            observations: Arc::clone(&self.pq_attestation_gossip_observations),
            binding: Some(SingleObservationBinding {
                key,
                identity,
                generation,
            }),
            _admission: Some(admission),
            _activity: Some(activity),
            subnet,
            bound_head_root,
        })
    }

    pub async fn verify_pq_aggregate_for_gossip(
        &self,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) -> Result<PqAggregateGossipPropagationToken<T::EthSpec>, PqAttestationGossipError> {
        let admission = Arc::clone(&self.pq_attestation_gossip_admission)
            .try_acquire_owned()
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::IngressCapacity)
            })?;
        let (latest_slot, earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let AggregateObservationInput {
            aggregator_key: early_aggregator_key,
            data_key: early_data_key,
            bits: early_bits,
        } = aggregate_observation_input::<T::EthSpec>(&aggregate)?;
        let early_status = self
            .pq_attestation_gossip_observations
            .lock()
            .precheck_aggregate(
                early_aggregator_key,
                early_data_key,
                &early_bits,
                earliest_slot,
            );
        classify_observation(early_status)?;
        let snapshot = self.head_snapshot();
        let store = Arc::clone(&self.store);
        let spec = Arc::clone(&self.spec);
        let key_cache = Arc::clone(&self.pq_validator_key_cache);
        let preparation = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    prepare_aggregate_context::<T>(
                        store,
                        snapshot,
                        spec,
                        key_cache,
                        aggregate,
                        latest_slot,
                        earliest_slot,
                        admission,
                    )
                },
                "pq-aggregate-gossip-prepare",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BlockingTask("pq-aggregate-gossip-prepare"),
            ))?
            .await
            .map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::BlockingTask(
                    "pq-aggregate-gossip-prepare",
                ))
            })??;

        let service = Arc::clone(&self.pq_aggregation_service);
        let proof_task = self
            .task_executor
            .spawn_handle(
                async move {
                    let PreparedAggregate {
                        prepared,
                        identity,
                        aggregator_key,
                        data_key,
                        bits,
                        bound_head_root,
                        admission,
                    } = preparation;
                    (
                        prepared.verify(&service).await,
                        identity,
                        aggregator_key,
                        data_key,
                        bits,
                        bound_head_root,
                        admission,
                    )
                },
                "pq-aggregate-gossip-proof",
            )
            .ok_or(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-aggregate-gossip-proof"),
            ))?;
        let Some((verified, identity, aggregator_key, data_key, bits, bound_head_root, admission)) =
            proof_task.await.map_err(|_| {
                PqAttestationGossipError::Local(PqAttestationGossipLocalError::AsyncTask(
                    "pq-aggregate-gossip-proof",
                ))
            })?
        else {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::AsyncTask("pq-aggregate-gossip-proof"),
            ));
        };
        let verified = verified.map_err(map_consensus_error)?;
        let (late_latest_slot, late_earliest_slot) =
            propagation_bounds::<T::EthSpec, _>(&self.slot_clock, &self.spec)?;
        let verified_slot = verified.aggregate().message().aggregate().data().slot;
        validate_late_propagation_window(verified_slot, late_earliest_slot, late_latest_slot)?;
        let actual_head = self.head_snapshot().beacon_block_root;
        let (bound_is_canonical, admission) = self
            .pq_attestation_bound_is_canonical(bound_head_root, admission)
            .await?;
        if !bound_is_canonical {
            return Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::BoundHeadNoLongerCanonical {
                    bound: bound_head_root,
                    current: actual_head,
                },
            ));
        }
        let generation = self
            .pq_attestation_gossip_observations
            .lock()
            .claim_aggregate(
                aggregator_key,
                data_key,
                identity,
                bits.clone(),
                late_earliest_slot,
            )
            .map_err(observation_error)?;
        Ok(PqAggregateGossipPropagationToken {
            verified: Some(verified),
            observations: Arc::clone(&self.pq_attestation_gossip_observations),
            binding: Some(AggregateObservationBinding {
                aggregator_key,
                data_key,
                identity,
                generation,
                bits,
            }),
            _admission: Some(admission),
            bound_head_root,
        })
    }
}

struct AggregateObservationInput<E: EthSpec> {
    aggregator_key: (Epoch, u64),
    data_key: (Slot, Hash256, u64),
    bits: ssz_types::BitList<E::MaxValidatorsPerSlot>,
}

fn aggregate_observation_input<E: EthSpec>(
    aggregate: &SignedAggregateAndProof<E>,
) -> Result<AggregateObservationInput<E>, PqAttestationGossipError> {
    let aggregate_ref = aggregate.message();
    let aggregator_index = aggregate_ref.aggregator_index();
    let AttestationRef::Electra(inner) = aggregate_ref.aggregate() else {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    };
    let mut selected_committees = inner
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index));
    let committee_index = selected_committees
        .next()
        .and_then(|index| u64::try_from(index).ok())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ))?;
    if selected_committees.next().is_some() {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    }
    Ok(AggregateObservationInput {
        aggregator_key: (inner.data.target.epoch, aggregator_index),
        data_key: (
            inner.data.slot,
            inner.data.tree_hash_root(),
            committee_index,
        ),
        bits: inner.aggregation_bits.clone(),
    })
}

fn propagation_bounds<E: EthSpec, S: SlotClock>(
    clock: &S,
    spec: &ChainSpec,
) -> Result<(Slot, Slot), PqAttestationGossipError> {
    let latest = clock
        .now_with_future_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ClockUnavailable,
        ))?;
    let now_past = clock
        .now_with_past_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ClockUnavailable,
        ))?;
    let one_epoch_prior = now_past - E::slots_per_epoch();
    let now = clock.now().ok_or(PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::ClockUnavailable,
    ))?;
    let earliest = if spec.fork_name_at_slot::<E>(now).deneb_enabled() {
        one_epoch_prior
            .epoch(E::slots_per_epoch())
            .start_slot(E::slots_per_epoch())
    } else {
        one_epoch_prior
    };
    Ok((latest, earliest))
}

fn validate_late_propagation_window(
    attestation_slot: Slot,
    earliest_slot: Slot,
    latest_slot: Slot,
) -> Result<(), PqAttestationGossipError> {
    if attestation_slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: attestation_slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if attestation_slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ProofOutlivedPropagationWindow {
                attestation: attestation_slot,
            },
        ));
    }
    Ok(())
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_late_window(
    attestation_slot: Slot,
    earliest_slot: Slot,
    latest_slot: Slot,
) -> Result<(), PqAttestationGossipError> {
    validate_late_propagation_window(attestation_slot, earliest_slot, latest_slot)
}

#[allow(clippy::too_many_arguments)]
fn prepare_single_context<T: BeaconChainTypes>(
    store: crate::BeaconStore<T>,
    snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    spec: Arc<ChainSpec>,
    key_cache: Arc<state_processing::PqValidatorKeyCache>,
    attestation: SingleAttestation,
    subnet: SubnetId,
    latest_slot: Slot,
    earliest_slot: Slot,
    admission: OwnedSemaphorePermit,
    activity: Arc<crate::beacon_chain::PqImportActivity>,
) -> Result<PreparedSingle<T::EthSpec>, PqAttestationGossipError> {
    if attestation.data.slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: attestation.data.slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if attestation.data.slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptAfterWindow {
                attestation: attestation.data.slot,
                earliest_permissible: earliest_slot,
            },
        ));
    }
    if attestation.data.target.epoch != attestation.data.slot.epoch(T::EthSpec::slots_per_epoch()) {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidTargetEpoch,
        ));
    }
    let bound_head_root = snapshot.beacon_block_root;
    let CanonicalReference {
        block: reference_block,
        mut state,
    } = canonical_reference::<T>(&store, &snapshot, attestation.data.beacon_block_root)?;
    if reference_block.slot() > attestation.data.slot {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: reference_block.slot(),
                attestation: attestation.data.slot,
            },
        ));
    }
    let advance_distance = pq_attestation_advance_distance::<T::EthSpec>(
        reference_block.slot(),
        attestation.data.slot,
    )?;
    for _ in 0..advance_distance {
        state_processing::per_slot_processing_pq(&mut state, &spec).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    }
    let target_slot = attestation
        .data
        .target
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    let reference_is_target = reference_block.slot().epoch(T::EthSpec::slots_per_epoch())
        < attestation.data.slot.epoch(T::EthSpec::slots_per_epoch())
        || reference_block.slot() == target_slot;
    let expected_target = if reference_is_target {
        attestation.data.beacon_block_root
    } else {
        let historical_target = *state.get_block_root(target_slot).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
        pq_attestation_target_root::<T::EthSpec>(
            reference_block.slot(),
            attestation.data.beacon_block_root,
            attestation.data.slot,
            historical_target,
        )
    };
    if attestation.data.target.root != expected_target {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::TargetRootMismatch {
                expected: expected_target,
                actual: attestation.data.target.root,
            },
        ));
    }
    state.build_all_committee_caches(&spec).map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    let committee_count = state
        .get_committee_count_at_slot(attestation.data.slot)
        .map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    let expected_subnet = SubnetId::compute_subnet_for_single_attestation::<T::EthSpec>(
        &attestation,
        committee_count,
        &spec,
    )
    .map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    if subnet != expected_subnet {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidSubnet {
                expected: expected_subnet,
                actual: subnet,
            },
        ));
    }
    let identity = attestation.tree_hash_root();
    let key = (attestation.data.target.epoch, attestation.attester_index);
    let prepared = prepare_pq_single_attestation(&state, &key_cache, attestation, &spec)
        .map_err(map_attestation_error)?;
    Ok(PreparedSingle {
        prepared,
        identity,
        key,
        bound_head_root,
        admission,
        activity,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_aggregate_context<T: BeaconChainTypes>(
    store: crate::BeaconStore<T>,
    snapshot: Arc<BeaconSnapshot<T::EthSpec>>,
    spec: Arc<ChainSpec>,
    key_cache: Arc<state_processing::PqValidatorKeyCache>,
    aggregate: SignedAggregateAndProof<T::EthSpec>,
    latest_slot: Slot,
    earliest_slot: Slot,
    admission: OwnedSemaphorePermit,
) -> Result<PreparedAggregate<T::EthSpec>, PqAttestationGossipError> {
    let aggregate_ref = aggregate.message();
    let aggregator_index = aggregate_ref.aggregator_index();
    let inner = aggregate_ref.aggregate();
    let AttestationRef::Electra(inner) = inner else {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    };
    let data = inner.data.clone();
    let bits = inner.aggregation_bits.clone();
    let mut selected_committees = inner
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index));
    let committee_index = selected_committees
        .next()
        .and_then(|index| u64::try_from(index).ok())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ))?;
    if selected_committees.next().is_some() {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(
                PqConsensusInvalid::BaseAggregateAndProof,
            ),
        ));
    }
    if data.slot > latest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptBeforeWindow {
                attestation: data.slot,
                latest_permissible: latest_slot,
            },
        ));
    }
    if data.slot < earliest_slot {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ReceiptAfterWindow {
                attestation: data.slot,
                earliest_permissible: earliest_slot,
            },
        ));
    }
    if data.target.epoch != data.slot.epoch(T::EthSpec::slots_per_epoch()) {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidTargetEpoch,
        ));
    }
    let bound_head_root = snapshot.beacon_block_root;
    let CanonicalReference {
        block: reference_block,
        mut state,
    } = canonical_reference::<T>(&store, &snapshot, data.beacon_block_root)?;
    if reference_block.slot() > data.slot {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: reference_block.slot(),
                attestation: data.slot,
            },
        ));
    }
    let advance_distance =
        pq_attestation_advance_distance::<T::EthSpec>(reference_block.slot(), data.slot)?;
    for _ in 0..advance_distance {
        state_processing::per_slot_processing_pq(&mut state, &spec).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
    }
    let target_slot = data.target.epoch.start_slot(T::EthSpec::slots_per_epoch());
    let reference_is_target = reference_block.slot().epoch(T::EthSpec::slots_per_epoch())
        < data.slot.epoch(T::EthSpec::slots_per_epoch())
        || reference_block.slot() == target_slot;
    let expected_target = if reference_is_target {
        data.beacon_block_root
    } else {
        let historical_target = *state.get_block_root(target_slot).map_err(|_| {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
        })?;
        pq_attestation_target_root::<T::EthSpec>(
            reference_block.slot(),
            data.beacon_block_root,
            data.slot,
            historical_target,
        )
    };
    if data.target.root != expected_target {
        return Err(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::TargetRootMismatch {
                expected: expected_target,
                actual: data.target.root,
            },
        ));
    }
    state.build_all_committee_caches(&spec).map_err(|_| {
        PqAttestationGossipError::Local(PqAttestationGossipLocalError::StateUnavailable)
    })?;
    let identity = aggregate.tree_hash_root();
    let data_key = (data.slot, data.tree_hash_root(), committee_index);
    let aggregator_key = (data.target.epoch, aggregator_index);
    let prepared = prepare_pq_aggregate_and_proof(&state, &key_cache, aggregate, &spec)
        .map_err(map_consensus_error)?;
    Ok(PreparedAggregate {
        prepared,
        identity,
        aggregator_key,
        data_key,
        bits,
        bound_head_root,
        admission,
    })
}

fn pq_attestation_target_root<E: EthSpec>(
    referenced_block_slot: Slot,
    referenced_block_root: Hash256,
    attestation_slot: Slot,
    same_epoch_target_root: Hash256,
) -> Hash256 {
    if referenced_block_slot.epoch(E::slots_per_epoch())
        < attestation_slot.epoch(E::slots_per_epoch())
        || referenced_block_slot
            == attestation_slot
                .epoch(E::slots_per_epoch())
                .start_slot(E::slots_per_epoch())
    {
        referenced_block_root
    } else {
        same_epoch_target_root
    }
}

fn pq_attestation_advance_distance<E: EthSpec>(
    referenced_block_slot: Slot,
    attestation_slot: Slot,
) -> Result<u64, PqAttestationGossipError> {
    let distance = attestation_slot
        .as_u64()
        .checked_sub(referenced_block_slot.as_u64())
        .ok_or(PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::ReferencedBlockAfterAttestation {
                block: referenced_block_slot,
                attestation: attestation_slot,
            },
        ))?;
    let maximum = E::slots_per_epoch()
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(2))
        .ok_or(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::StateUnavailable,
        ))?;
    if distance > maximum {
        return Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::StateAdvanceTooLarge {
                referenced_block: referenced_block_slot,
                attestation: attestation_slot,
                maximum,
            },
        ));
    }
    Ok(distance)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_advance_distance<E: EthSpec>(
    referenced_block_slot: Slot,
    attestation_slot: Slot,
) -> Result<u64, PqAttestationGossipError> {
    pq_attestation_advance_distance::<E>(referenced_block_slot, attestation_slot)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_attestation_target_root<E: EthSpec>(
    referenced_block_slot: Slot,
    referenced_block_root: Hash256,
    attestation_slot: Slot,
    same_epoch_target_root: Hash256,
) -> Hash256 {
    pq_attestation_target_root::<E>(
        referenced_block_slot,
        referenced_block_root,
        attestation_slot,
        same_epoch_target_root,
    )
}

fn canonical_reference<T: BeaconChainTypes>(
    store: &crate::BeaconStore<T>,
    snapshot: &BeaconSnapshot<T::EthSpec>,
    requested_root: Hash256,
) -> Result<CanonicalReference<T::EthSpec>, PqAttestationGossipError> {
    let mut block = Arc::clone(&snapshot.beacon_block);
    let mut root = snapshot.beacon_block_root;
    let max_steps = T::EthSpec::slots_per_epoch()
        .saturating_mul(2)
        .saturating_add(2);
    for _ in 0..max_steps {
        if root == requested_root {
            if root == snapshot.beacon_block_root {
                return Ok(CanonicalReference {
                    block,
                    state: snapshot.beacon_state.clone(),
                });
            }
            let state_root = block.message().state_root();
            let state = store
                .get_state(&state_root, Some(block.slot()), true)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedStateUnavailable(state_root),
                ))?;
            return Ok(CanonicalReference { block, state });
        }
        if block.slot() == Slot::new(0) {
            break;
        }
        root = block.parent_root();
        block = Arc::new(
            store
                .get_full_block(&root)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedBlockUnavailable(root),
                ))?,
        );
    }
    Err(PqAttestationGossipError::Local(
        PqAttestationGossipLocalError::ReferencedBlockUnavailable(requested_root),
    ))
}

fn canonical_lineage_contains<T: BeaconChainTypes>(
    store: &crate::BeaconStore<T>,
    snapshot: &BeaconSnapshot<T::EthSpec>,
    requested_root: Hash256,
) -> Result<bool, PqAttestationGossipError> {
    let mut block = Arc::clone(&snapshot.beacon_block);
    let mut root = snapshot.beacon_block_root;
    let max_steps = T::EthSpec::slots_per_epoch()
        .saturating_mul(2)
        .saturating_add(2);
    for _ in 0..max_steps {
        if root == requested_root {
            return Ok(true);
        }
        if block.slot() == Slot::new(0) {
            return Ok(false);
        }
        root = block.parent_root();
        block = Arc::new(
            store
                .get_full_block(&root)
                .map_err(|error| {
                    PqAttestationGossipError::Local(PqAttestationGossipLocalError::Store(error))
                })?
                .ok_or(PqAttestationGossipError::Local(
                    PqAttestationGossipLocalError::ReferencedBlockUnavailable(root),
                ))?,
        );
    }
    Ok(false)
}

fn map_attestation_error(error: PqAttestationError) -> PqAttestationGossipError {
    match error {
        PqAttestationError::Invalid(error) => PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAttestation(error),
        ),
        PqAttestationError::Local(error) => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::Attestation(error))
        }
    }
}

fn map_consensus_error(error: PqConsensusError) -> PqAttestationGossipError {
    match error {
        PqConsensusError::Invalid(error) => PqAttestationGossipError::PeerInvalid(
            PqAttestationGossipPeerInvalid::InvalidAggregate(error),
        ),
        PqConsensusError::Local(error) => {
            PqAttestationGossipError::Local(PqAttestationGossipLocalError::Aggregate(error))
        }
    }
}

fn classify_observation(
    observation: PqAttestationGossipObservation,
) -> Result<(), PqAttestationGossipError> {
    match observation {
        PqAttestationGossipObservation::Unseen => Ok(()),
        PqAttestationGossipObservation::Pending
        | PqAttestationGossipObservation::Observed
        | PqAttestationGossipObservation::Conflict => {
            Err(PqAttestationGossipError::Duplicate(observation))
        }
        PqAttestationGossipObservation::Capacity => Err(PqAttestationGossipError::Local(
            PqAttestationGossipLocalError::ObservationCapacity,
        )),
        PqAttestationGossipObservation::GenerationExhausted => {
            Err(PqAttestationGossipError::Local(
                PqAttestationGossipLocalError::ObservationGenerationExhausted,
            ))
        }
    }
}

fn observation_error(observation: PqAttestationGossipObservation) -> PqAttestationGossipError {
    match classify_observation(observation) {
        Err(error) => error,
        Ok(()) => PqAttestationGossipError::Local(PqAttestationGossipLocalError::ObservationLost),
    }
}
