use crate::{BeaconChain, BeaconChainTypes};
use consensus_signature::{ValidatorPublicKeyBytes, is_individual_same_message_evidence};
use sha2::{Digest, Sha256};
use slot_clock::SlotClock;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use types::{
    Attestation, ChainSpec, Domain, EthSpec, ForkName, Hash256, MinimalEthSpec, RelativeEpoch,
    SignedRoot, SingleAttestation, Slot, SubnetId,
};

pub const PQ_LOCAL_ATTESTER_IDENTITY_CAPACITY: usize = 16;
pub const PQ_LOCAL_ATTESTATION_CONTEXT_ADMISSION_CAPACITY: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqLocalAttesterIdentity {
    pubkey: ValidatorPublicKeyBytes,
    validator_index: u64,
}

impl PqLocalAttesterIdentity {
    pub const fn new(pubkey: ValidatorPublicKeyBytes, validator_index: u64) -> Self {
        Self {
            pubkey,
            validator_index,
        }
    }

    pub const fn pubkey(&self) -> ValidatorPublicKeyBytes {
        self.pubkey
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }
}

#[derive(Debug)]
pub struct PqLocalAttestationCandidate<E: EthSpec> {
    pubkey: ValidatorPublicKeyBytes,
    validator_index: u64,
    committee_index: u64,
    committee_position: usize,
    committee_length: usize,
    committee_count_at_slot: u64,
    subnet: SubnetId,
    bound_head_root: Hash256,
    dependent_root: Hash256,
    signing_root: Hash256,
    attestation: Attestation<E>,
}

impl<E: EthSpec> PqLocalAttestationCandidate<E> {
    pub const fn pubkey(&self) -> ValidatorPublicKeyBytes {
        self.pubkey
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    pub const fn committee_index(&self) -> u64 {
        self.committee_index
    }

    pub const fn committee_position(&self) -> usize {
        self.committee_position
    }

    pub const fn committee_length(&self) -> usize {
        self.committee_length
    }

    pub const fn committee_count_at_slot(&self) -> u64 {
        self.committee_count_at_slot
    }

    pub const fn subnet(&self) -> SubnetId {
        self.subnet
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    pub const fn signing_root(&self) -> Hash256 {
        self.signing_root
    }

    pub const fn attestation(&self) -> &Attestation<E> {
        &self.attestation
    }

    /// Consumes one immutable duty candidate and seals the exact output returned by the signer.
    ///
    /// `signed_ssz_digest` is SHA-256 over the complete SSZ encoding of the resulting
    /// [`SingleAttestation`], including its signature evidence.
    pub fn into_local_single(
        self,
        returned_validator_index: u64,
        signed_attestation: Attestation<E>,
        spec: &ChainSpec,
    ) -> Result<PqLocallyConstructedSingle<E>, PqLocalSingleConstructionError> {
        if returned_validator_index != self.validator_index {
            return Err(PqLocalSingleConstructionError::ValidatorIndexMismatch {
                expected: self.validator_index,
                actual: returned_validator_index,
            });
        }
        if signed_attestation.data() != self.attestation.data() {
            return Err(PqLocalSingleConstructionError::AttestationDataMismatch);
        }
        let Attestation::Electra(electra) = &signed_attestation else {
            return Err(PqLocalSingleConstructionError::WrongFork);
        };
        if electra.aggregation_bits.len() != self.committee_length
            || electra.aggregation_bits.num_set_bits() != 1
            || !electra
                .aggregation_bits
                .get(self.committee_position)
                .map_err(|_| PqLocalSingleConstructionError::InvalidAggregationBits)?
        {
            return Err(PqLocalSingleConstructionError::InvalidAggregationBits);
        }
        let committee_position = usize::try_from(self.committee_index)
            .map_err(|_| PqLocalSingleConstructionError::InvalidCommitteeBits)?;
        if electra.committee_bits.num_set_bits() != 1
            || !electra
                .committee_bits
                .get(committee_position)
                .map_err(|_| PqLocalSingleConstructionError::InvalidCommitteeBits)?
        {
            return Err(PqLocalSingleConstructionError::InvalidCommitteeBits);
        }
        if !is_individual_same_message_evidence(signed_attestation.signature()) {
            return Err(PqLocalSingleConstructionError::InvalidSignature);
        }
        let single = signed_attestation
            .to_single_attestation_with_attester_index(self.validator_index)
            .map_err(PqLocalSingleConstructionError::Attestation)?;
        if single.committee_index != self.committee_index
            || single.attester_index != self.validator_index
        {
            return Err(PqLocalSingleConstructionError::CandidateAssociationMismatch);
        }
        let expected_subnet = SubnetId::compute_subnet_for_single_attestation::<E>(
            &single,
            self.committee_count_at_slot,
            spec,
        )
        .map_err(|_| PqLocalSingleConstructionError::InvalidSubnet {
            expected: self.subnet,
            actual: self.subnet,
        })?;
        if expected_subnet != self.subnet {
            return Err(PqLocalSingleConstructionError::InvalidSubnet {
                expected: expected_subnet,
                actual: self.subnet,
            });
        }
        let encoded = ssz::Encode::as_ssz_bytes(&single);
        let signed_ssz_digest = Sha256::digest(encoded).into();
        Ok(PqLocallyConstructedSingle {
            single,
            signed_attestation,
            pubkey: self.pubkey,
            validator_index: self.validator_index,
            committee_index: self.committee_index,
            committee_position: self.committee_position,
            committee_length: self.committee_length,
            committee_count_at_slot: self.committee_count_at_slot,
            subnet: self.subnet,
            slot: self.attestation.data().slot,
            bound_head_root: self.bound_head_root,
            dependent_root: self.dependent_root,
            signing_root: self.signing_root,
            signed_ssz_digest,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[derive(Debug)]
pub enum PqLocalSingleConstructionError {
    ValidatorIndexMismatch {
        expected: u64,
        actual: u64,
    },
    AttestationDataMismatch,
    WrongFork,
    InvalidAggregationBits,
    InvalidCommitteeBits,
    InvalidSignature,
    CandidateAssociationMismatch,
    InvalidSubnet {
        expected: SubnetId,
        actual: SubnetId,
    },
    Attestation(types::AttestationError),
}

impl std::fmt::Display for PqLocalSingleConstructionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ local single construction failed: {self:?}")
    }
}

impl Error for PqLocalSingleConstructionError {}

/// Exact, locally constructed single-attestation provenance awaiting contextual verification.
///
/// Private fields and the lack of `Clone` prevent callers from replacing its signer, committee,
/// subnet, head, signing root, signature, or complete signed SSZ identity.
pub struct PqLocallyConstructedSingle<E: EthSpec> {
    pub(crate) single: SingleAttestation,
    pub(crate) signed_attestation: Attestation<E>,
    pub(crate) pubkey: ValidatorPublicKeyBytes,
    pub(crate) validator_index: u64,
    pub(crate) committee_index: u64,
    pub(crate) committee_position: usize,
    pub(crate) committee_length: usize,
    pub(crate) committee_count_at_slot: u64,
    pub(crate) subnet: SubnetId,
    pub(crate) slot: Slot,
    pub(crate) bound_head_root: Hash256,
    pub(crate) dependent_root: Hash256,
    pub(crate) signing_root: Hash256,
    pub(crate) signed_ssz_digest: [u8; 32],
    pub(crate) _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> PqLocallyConstructedSingle<E> {
    pub const fn single(&self) -> &SingleAttestation {
        &self.single
    }

    pub const fn signed_attestation(&self) -> &Attestation<E> {
        &self.signed_attestation
    }

    pub const fn pubkey(&self) -> ValidatorPublicKeyBytes {
        self.pubkey
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    pub const fn committee_index(&self) -> u64 {
        self.committee_index
    }

    pub const fn committee_position(&self) -> usize {
        self.committee_position
    }

    pub const fn committee_length(&self) -> usize {
        self.committee_length
    }

    pub const fn committee_count_at_slot(&self) -> u64 {
        self.committee_count_at_slot
    }

    pub const fn subnet(&self) -> SubnetId {
        self.subnet
    }

    pub const fn slot(&self) -> Slot {
        self.slot
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    pub const fn signing_root(&self) -> Hash256 {
        self.signing_root
    }

    pub const fn signed_ssz_digest(&self) -> [u8; 32] {
        self.signed_ssz_digest
    }
}

pub struct PqLocalAttestationContext<E: EthSpec> {
    slot: Slot,
    bound_head_root: Hash256,
    dependent_root: Hash256,
    candidates: Vec<PqLocalAttestationCandidate<E>>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> std::fmt::Debug for PqLocalAttestationContext<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqLocalAttestationContext")
            .field("slot", &self.slot)
            .field("bound_head_root", &self.bound_head_root)
            .field("dependent_root", &self.dependent_root)
            .field("candidates", &self.candidates)
            .finish_non_exhaustive()
    }
}

impl<E: EthSpec> PqLocalAttestationContext<E> {
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }
}

/// A derivation snapshot revalidated coherently against the canonical import gate.
///
/// This is not signing authorization: the short-lived import-gate claim is released before this
/// value is returned, and later signing/publication must enforce its own timing and head checks.
pub struct PqCoherentLocalAttestationSnapshot<E: EthSpec> {
    slot: Slot,
    bound_head_root: Hash256,
    dependent_root: Hash256,
    candidates: Vec<PqLocalAttestationCandidate<E>>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

/// An owned local-attestation candidate batch which retains its original bounded chain guards.
///
/// Candidates are available only by shared reference. The batch must be consumed atomically when
/// associating validator-store output, so no production candidate can outlive its admission or
/// shutdown activity.
pub struct PqOwnedLocalAttestationCandidateBatch<E: EthSpec> {
    candidates: Vec<PqLocalAttestationCandidate<E>>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> PqOwnedLocalAttestationCandidateBatch<E> {
    pub fn candidates(&self) -> &[PqLocalAttestationCandidate<E>] {
        &self.candidates
    }

    pub fn seal_exact_ordered(
        self,
        returned: Vec<(u64, Attestation<E>)>,
        spec: &ChainSpec,
    ) -> Result<PqSealedLocalAttestationBatch<E>, PqLocalAttestationBatchSealError> {
        if returned.len() != self.candidates.len() {
            return Err(PqLocalAttestationBatchSealError::CountMismatch {
                expected: self.candidates.len(),
                actual: returned.len(),
            });
        }
        let mut provenances = Vec::with_capacity(self.candidates.len());
        for (candidate, (validator_index, signed_attestation)) in
            self.candidates.into_iter().zip(returned)
        {
            provenances.push(
                candidate
                    .into_local_single(validator_index, signed_attestation, spec)
                    .map_err(PqLocalAttestationBatchSealError::Candidate)?,
            );
        }
        Ok(PqSealedLocalAttestationBatch {
            provenances,
            _admission: self._admission,
            _activity: self._activity,
        })
    }
}

/// Atomically sealed store output which continues to retain the candidate batch guards.
pub struct PqSealedLocalAttestationBatch<E: EthSpec> {
    provenances: Vec<PqLocallyConstructedSingle<E>>,
    _admission: OwnedSemaphorePermit,
    _activity: Arc<crate::beacon_chain::PqImportActivity>,
}

impl<E: EthSpec> PqSealedLocalAttestationBatch<E> {
    pub fn len(&self) -> usize {
        self.provenances.len()
    }

    pub fn is_empty(&self) -> bool {
        self.provenances.is_empty()
    }
}

#[derive(Debug)]
pub enum PqLocalAttestationBatchSealError {
    CountMismatch { expected: usize, actual: usize },
    Candidate(PqLocalSingleConstructionError),
}

impl std::fmt::Display for PqLocalAttestationBatchSealError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ local attestation batch sealing failed: {self:?}"
        )
    }
}

impl Error for PqLocalAttestationBatchSealError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Candidate(error) => Some(error),
            Self::CountMismatch { .. } => None,
        }
    }
}

impl<E: EthSpec> std::fmt::Debug for PqCoherentLocalAttestationSnapshot<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqCoherentLocalAttestationSnapshot")
            .field("slot", &self.slot)
            .field("bound_head_root", &self.bound_head_root)
            .field("dependent_root", &self.dependent_root)
            .field("candidates", &self.candidates)
            .finish_non_exhaustive()
    }
}

impl<E: EthSpec> PqCoherentLocalAttestationSnapshot<E> {
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    pub fn candidates(&self) -> &[PqLocalAttestationCandidate<E>] {
        &self.candidates
    }

    /// Transfers the coherent candidates and their original guards into an owned signing batch.
    pub fn into_owned_candidate_batch(self) -> PqOwnedLocalAttestationCandidateBatch<E> {
        PqOwnedLocalAttestationCandidateBatch {
            candidates: self.candidates,
            _admission: self._admission,
            _activity: self._activity,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_into_candidates(self) -> Vec<PqLocalAttestationCandidate<E>> {
        self.candidates
    }
}

#[derive(Debug)]
pub enum PqLocalAttestationContextError {
    IdentityCapacity {
        count: usize,
        maximum: usize,
    },
    IngressCapacity,
    HeadTransitionBusy,
    WrongEthSpec,
    WrongFork(ForkName),
    InvalidSlotDuration(Duration),
    ShuttingDown,
    IdentityOrder {
        previous: u64,
        current: u64,
    },
    DuplicateValidatorIndex(u64),
    DuplicatePubkey,
    ValidatorPubkeyMismatch {
        validator_index: u64,
    },
    ValidatorIndexOutOfBounds(u64),
    HeadNotReady {
        head: Slot,
        current: Slot,
    },
    HeadAhead {
        head: Slot,
        current: Slot,
    },
    HeadInconsistent {
        state: Slot,
        block: Slot,
    },
    HeadChanged {
        expected: Hash256,
        actual: Hash256,
    },
    ClockChanged {
        before: Slot,
        after: Slot,
    },
    HeadReconciliationPending {
        block_root: Hash256,
    },
    HeadReconciliationFailed {
        block_root: Hash256,
    },
    HeadReconciliationInconsistent {
        head: Hash256,
        reconciliation: Hash256,
    },
    ClockUnavailable,
    State(types::BeaconStateError),
    Attestation(types::AttestationError),
    InvalidCommitteeBounds,
    InvalidSubnet,
    BlockingTask,
}

impl std::fmt::Display for PqLocalAttestationContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ local attestation context unavailable: {self:?}"
        )
    }
}

impl PqLocalAttestationContextError {
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::IngressCapacity
                | Self::HeadTransitionBusy
                | Self::ClockUnavailable
                | Self::ClockChanged { .. }
                | Self::HeadChanged { .. }
                | Self::HeadNotReady { .. }
                | Self::HeadReconciliationPending { .. }
        )
    }
}

impl Error for PqLocalAttestationContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

fn validate_pq_local_attester_profile<E: EthSpec>(
    spec: &types::ChainSpec,
    slot: Slot,
) -> Result<(), PqLocalAttestationContextError> {
    if std::any::TypeId::of::<E>() != std::any::TypeId::of::<MinimalEthSpec>() {
        return Err(PqLocalAttestationContextError::WrongEthSpec);
    }
    let slot_duration = spec.get_slot_duration();
    if slot_duration != Duration::from_secs(300) {
        return Err(PqLocalAttestationContextError::InvalidSlotDuration(
            slot_duration,
        ));
    }
    let fork = spec.fork_name_at_slot::<E>(slot);
    if fork != ForkName::Electra {
        return Err(PqLocalAttestationContextError::WrongFork(fork));
    }
    Ok(())
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_validate_pq_local_attester_profile<E: EthSpec>(
    spec: &types::ChainSpec,
    slot: Slot,
) -> Result<(), PqLocalAttestationContextError> {
    validate_pq_local_attester_profile::<E>(spec, slot)
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    fn require_pq_local_attester_reconciled_head(
        &self,
        bound_head_root: Hash256,
    ) -> Result<(), PqLocalAttestationContextError> {
        match self.pq_execution_reconciliation.current() {
            crate::beacon_chain::PqExecutionReconciliationState::Reconciled { block_root }
                if block_root == bound_head_root =>
            {
                Ok(())
            }
            crate::beacon_chain::PqExecutionReconciliationState::Pending { block_root }
                if block_root == bound_head_root =>
            {
                Err(PqLocalAttestationContextError::HeadReconciliationPending { block_root })
            }
            crate::beacon_chain::PqExecutionReconciliationState::Failed { block_root }
                if block_root == bound_head_root =>
            {
                Err(PqLocalAttestationContextError::HeadReconciliationFailed { block_root })
            }
            state => {
                let reconciliation = match state {
                    crate::beacon_chain::PqExecutionReconciliationState::Pending { block_root }
                    | crate::beacon_chain::PqExecutionReconciliationState::Reconciled {
                        block_root,
                    }
                    | crate::beacon_chain::PqExecutionReconciliationState::Failed { block_root } => {
                        block_root
                    }
                };
                Err(
                    PqLocalAttestationContextError::HeadReconciliationInconsistent {
                        head: bound_head_root,
                        reconciliation,
                    },
                )
            }
        }
    }

    pub async fn pq_local_attestation_context(
        &self,
        identities: Arc<[PqLocalAttesterIdentity]>,
    ) -> Result<PqLocalAttestationContext<T::EthSpec>, PqLocalAttestationContextError> {
        if identities.len() > PQ_LOCAL_ATTESTER_IDENTITY_CAPACITY {
            return Err(PqLocalAttestationContextError::IdentityCapacity {
                count: identities.len(),
                maximum: PQ_LOCAL_ATTESTER_IDENTITY_CAPACITY,
            });
        }
        let activity = self
            .pq_import_coordinator
            .try_start()
            .ok_or(PqLocalAttestationContextError::ShuttingDown)?;
        let admission = Arc::clone(&self.pq_local_attester_context_admission)
            .try_acquire_owned()
            .map_err(|_| PqLocalAttestationContextError::IngressCapacity)?;
        let slot = self
            .slot_clock
            .now()
            .ok_or(PqLocalAttestationContextError::ClockUnavailable)?;
        validate_pq_local_attester_profile::<T::EthSpec>(&self.spec, slot)?;
        let initial_head_gate = Arc::clone(&self.pq_import_gate)
            .try_acquire_owned()
            .map_err(|_| PqLocalAttestationContextError::HeadTransitionBusy)?;
        let snapshot = self.head_snapshot();
        let head_slot = snapshot.beacon_state.slot();
        let block_slot = snapshot.beacon_block.slot();
        if block_slot != head_slot {
            return Err(PqLocalAttestationContextError::HeadInconsistent {
                state: head_slot,
                block: block_slot,
            });
        }
        if head_slot < slot {
            return Err(PqLocalAttestationContextError::HeadNotReady {
                head: head_slot,
                current: slot,
            });
        }
        if head_slot > slot {
            return Err(PqLocalAttestationContextError::HeadAhead {
                head: head_slot,
                current: slot,
            });
        }
        let mut previous_index = None;
        let mut seen_pubkeys = Vec::with_capacity(identities.len());
        for identity in identities.iter() {
            if let Some(previous) = previous_index {
                if identity.validator_index == previous {
                    return Err(PqLocalAttestationContextError::DuplicateValidatorIndex(
                        identity.validator_index,
                    ));
                }
                if identity.validator_index < previous {
                    return Err(PqLocalAttestationContextError::IdentityOrder {
                        previous,
                        current: identity.validator_index,
                    });
                }
            }
            if seen_pubkeys.contains(&identity.pubkey) {
                return Err(PqLocalAttestationContextError::DuplicatePubkey);
            }
            let validator_index = usize::try_from(identity.validator_index).map_err(|_| {
                PqLocalAttestationContextError::ValidatorIndexOutOfBounds(identity.validator_index)
            })?;
            let validator = snapshot
                .beacon_state
                .validators()
                .get(validator_index)
                .ok_or(PqLocalAttestationContextError::ValidatorIndexOutOfBounds(
                    identity.validator_index,
                ))?;
            if validator.pubkey != identity.pubkey {
                return Err(PqLocalAttestationContextError::ValidatorPubkeyMismatch {
                    validator_index: identity.validator_index,
                });
            }
            previous_index = Some(identity.validator_index);
            seen_pubkeys.push(identity.pubkey);
        }
        let bound_head_root = snapshot.beacon_block_root;
        self.require_pq_local_attester_reconciled_head(bound_head_root)?;
        drop(initial_head_gate);
        let spec = Arc::clone(&self.spec);
        #[cfg(feature = "pq-startup-testing")]
        let test_hook = self.pq_local_attester_context_test_hook.clone();
        let derived = self
            .task_executor
            .spawn_blocking_handle_without_exit(
                move || {
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = test_hook {
                        hook.run();
                    }
                    let mut state = snapshot.beacon_state.clone();
                    let relative_epoch = RelativeEpoch::Current;
                    state
                        .build_committee_cache(relative_epoch, &spec)
                        .map_err(PqLocalAttestationContextError::State)?;
                    let state = &state;
                    let dependent_root = state
                        .attester_shuffling_decision_root(bound_head_root, relative_epoch)
                        .map_err(PqLocalAttestationContextError::State)?;
                    let target_slot = slot
                        .epoch(T::EthSpec::slots_per_epoch())
                        .start_slot(T::EthSpec::slots_per_epoch());
                    let target_root = if state.slot() <= target_slot {
                        bound_head_root
                    } else {
                        *state
                            .get_block_root(target_slot)
                            .map_err(PqLocalAttestationContextError::State)?
                    };
                    let target = types::Checkpoint {
                        epoch: slot.epoch(T::EthSpec::slots_per_epoch()),
                        root: target_root,
                    };
                    let source = state.current_justified_checkpoint();
                    let mut candidates = Vec::new();
                    for identity in identities.iter() {
                        let validator_index =
                            usize::try_from(identity.validator_index).map_err(|_| {
                                PqLocalAttestationContextError::ValidatorIndexOutOfBounds(
                                    identity.validator_index,
                                )
                            })?;
                        let Some(duty) = state
                            .get_attestation_duties(validator_index, relative_epoch)
                            .map_err(PqLocalAttestationContextError::State)?
                        else {
                            continue;
                        };
                        if duty.slot != slot {
                            continue;
                        }
                        if duty.index >= duty.committees_at_slot
                            || duty.committee_position >= duty.committee_len
                        {
                            return Err(PqLocalAttestationContextError::InvalidCommitteeBounds);
                        }
                        let subnet = SubnetId::compute_subnet::<T::EthSpec>(
                            slot,
                            duty.index,
                            duty.committees_at_slot,
                            &spec,
                        )
                        .map_err(|_| PqLocalAttestationContextError::InvalidSubnet)?;
                        let attestation = Attestation::empty_for_signing(
                            duty.index,
                            duty.committee_len,
                            slot,
                            bound_head_root,
                            source,
                            target,
                            false,
                            &spec,
                        )
                        .map_err(PqLocalAttestationContextError::Attestation)?;
                        let domain = spec.get_domain(
                            target.epoch,
                            Domain::BeaconAttester,
                            &state.fork(),
                            state.genesis_validators_root(),
                        );
                        let signing_root = attestation.data().signing_root(domain);
                        candidates.push(PqLocalAttestationCandidate {
                            pubkey: identity.pubkey,
                            validator_index: identity.validator_index,
                            committee_index: duty.index,
                            committee_position: duty.committee_position,
                            committee_length: duty.committee_len,
                            committee_count_at_slot: duty.committees_at_slot,
                            subnet,
                            bound_head_root,
                            dependent_root,
                            signing_root,
                            attestation,
                        });
                    }
                    Ok(PqLocalAttestationContext {
                        slot,
                        bound_head_root,
                        dependent_root,
                        candidates,
                        _admission: admission,
                        _activity: activity,
                    })
                },
                "pq-local-attestation-context",
            )
            .ok_or(PqLocalAttestationContextError::BlockingTask)?
            .await
            .map_err(|_| PqLocalAttestationContextError::BlockingTask)?
            .map_err(|_| PqLocalAttestationContextError::BlockingTask)??;
        let late_head_gate = Arc::clone(&self.pq_import_gate)
            .try_acquire_owned()
            .map_err(|_| PqLocalAttestationContextError::HeadTransitionBusy)?;
        let late_slot = self
            .slot_clock
            .now()
            .ok_or(PqLocalAttestationContextError::ClockUnavailable)?;
        if late_slot != slot {
            return Err(PqLocalAttestationContextError::ClockChanged {
                before: slot,
                after: late_slot,
            });
        }
        let late_snapshot = self.head_snapshot();
        if late_snapshot.beacon_block_root != bound_head_root {
            return Err(PqLocalAttestationContextError::HeadChanged {
                expected: bound_head_root,
                actual: late_snapshot.beacon_block_root,
            });
        }
        let late_state_slot = late_snapshot.beacon_state.slot();
        let late_block_slot = late_snapshot.beacon_block.slot();
        if late_state_slot != slot || late_block_slot != slot {
            return Err(PqLocalAttestationContextError::HeadInconsistent {
                state: late_state_slot,
                block: late_block_slot,
            });
        }
        self.require_pq_local_attester_reconciled_head(bound_head_root)?;
        drop(late_head_gate);
        Ok(derived)
    }

    /// Consumes a derivation context and validates one coherent clock/head/reconciliation view.
    /// The canonical import gate is held only for these checks and is released before return.
    pub fn consume_pq_local_attestation_context(
        &self,
        context: PqLocalAttestationContext<T::EthSpec>,
    ) -> Result<PqCoherentLocalAttestationSnapshot<T::EthSpec>, PqLocalAttestationContextError>
    {
        let head_gate = Arc::clone(&self.pq_import_gate)
            .try_acquire_owned()
            .map_err(|_| PqLocalAttestationContextError::HeadTransitionBusy)?;
        let current_slot = self
            .slot_clock
            .now()
            .ok_or(PqLocalAttestationContextError::ClockUnavailable)?;
        if current_slot != context.slot {
            return Err(PqLocalAttestationContextError::ClockChanged {
                before: context.slot,
                after: current_slot,
            });
        }
        let head = self.head_snapshot();
        if head.beacon_block_root != context.bound_head_root {
            return Err(PqLocalAttestationContextError::HeadChanged {
                expected: context.bound_head_root,
                actual: head.beacon_block_root,
            });
        }
        let state_slot = head.beacon_state.slot();
        let block_slot = head.beacon_block.slot();
        if state_slot != context.slot || block_slot != context.slot {
            return Err(PqLocalAttestationContextError::HeadInconsistent {
                state: state_slot,
                block: block_slot,
            });
        }
        self.require_pq_local_attester_reconciled_head(context.bound_head_root)?;
        let PqLocalAttestationContext {
            slot,
            bound_head_root,
            dependent_root,
            candidates,
            _admission,
            _activity,
        } = context;
        drop(head_gate);
        Ok(PqCoherentLocalAttestationSnapshot {
            slot,
            bound_head_root,
            dependent_root,
            candidates,
            _admission,
            _activity,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_local_attestation_context_available_permits(&self) -> usize {
        self.pq_local_attester_context_admission.available_permits()
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_candidate_fixture(
    subnet_override: Option<SubnetId>,
) -> (
    PqLocalAttestationCandidate<MinimalEthSpec>,
    Attestation<MinimalEthSpec>,
    ChainSpec,
) {
    use consensus_signature::{PqPublicKey, PqRawSignature};

    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let slot = Slot::new(0);
    let bound_head_root = Hash256::repeat_byte(0x41);
    let dependent_root = Hash256::repeat_byte(0x42);
    let committee_index = 0;
    let committee_position = 2;
    let committee_length = 4;
    let committee_count_at_slot = 1;
    let attestation = Attestation::empty_for_signing(
        committee_index,
        committee_length,
        slot,
        bound_head_root,
        types::Checkpoint::default(),
        types::Checkpoint {
            epoch: types::Epoch::new(0),
            root: bound_head_root,
        },
        false,
        &spec,
    )
    .expect("fixed testing-only attestation candidate");
    let single = SingleAttestation {
        committee_index,
        attester_index: 3,
        data: attestation.data().clone(),
        signature: consensus_signature::SameMessageEvidence::from(&PqRawSignature::empty()),
    };
    let expected_subnet = SubnetId::compute_subnet_for_single_attestation::<MinimalEthSpec>(
        &single,
        committee_count_at_slot,
        &spec,
    )
    .expect("fixed testing-only subnet");
    let candidate = PqLocalAttestationCandidate {
        pubkey: PqPublicKey::deserialize(&[3; 32]).expect("fixed testing-only public key"),
        validator_index: 3,
        committee_index,
        committee_position,
        committee_length,
        committee_count_at_slot,
        subnet: subnet_override.unwrap_or(expected_subnet),
        bound_head_root,
        dependent_root,
        signing_root: Hash256::repeat_byte(0x43),
        attestation: attestation.clone(),
    };
    let mut signed = attestation;
    signed
        .attach_individual_signature(&PqRawSignature::empty(), committee_position)
        .expect("fixed testing-only signature attachment");
    (candidate, signed, spec)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_candidate_batch_fixture(
    count: usize,
) -> (
    PqOwnedLocalAttestationCandidateBatch<MinimalEthSpec>,
    Vec<Attestation<MinimalEthSpec>>,
    ChainSpec,
) {
    let (batch, signed, spec, _guards) =
        testing_only_pq_local_candidate_batch_fixture_with_guards(count);
    (batch, signed, spec)
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub struct TestingPqLocalCandidateBatchGuards {
    coordinator: Arc<crate::beacon_chain::PqImportCoordinator>,
    admission: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "pq-startup-testing")]
impl TestingPqLocalCandidateBatchGuards {
    pub fn available_permits(&self) -> usize {
        self.admission.available_permits()
    }

    pub async fn close_and_drain(&self) {
        self.coordinator.close_and_drain().await;
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_local_candidate_batch_fixture_with_guards(
    count: usize,
) -> (
    PqOwnedLocalAttestationCandidateBatch<MinimalEthSpec>,
    Vec<Attestation<MinimalEthSpec>>,
    ChainSpec,
    TestingPqLocalCandidateBatchGuards,
) {
    use consensus_signature::{PqPublicKey, PqRawSignature};

    assert!(
        count <= 17,
        "testing candidate batch is intentionally bounded"
    );
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let slot = Slot::new(0);
    let dependent_root = Hash256::repeat_byte(0x52);
    let committee_length = count.max(1);
    let committee_count_at_slot = 1;
    let mut candidates = Vec::with_capacity(count);
    let mut signed = Vec::with_capacity(count);
    for index in 0..count {
        let validator_index = u64::try_from(index).expect("bounded testing validator index");
        let key_byte = u8::try_from(index + 1).expect("bounded testing public key byte");
        let root_byte = 0x51_u8
            .checked_add(u8::try_from(index).expect("bounded testing root byte"))
            .expect("bounded testing root byte addition");
        let bound_head_root = Hash256::repeat_byte(root_byte);
        let attestation = Attestation::empty_for_signing(
            0,
            committee_length,
            slot,
            bound_head_root,
            types::Checkpoint::default(),
            types::Checkpoint {
                epoch: types::Epoch::new(0),
                root: bound_head_root,
            },
            false,
            &spec,
        )
        .expect("fixed testing-only attestation candidate batch");
        let single = SingleAttestation {
            committee_index: 0,
            attester_index: validator_index,
            data: attestation.data().clone(),
            signature: consensus_signature::SameMessageEvidence::from(&PqRawSignature::empty()),
        };
        let subnet = SubnetId::compute_subnet_for_single_attestation::<MinimalEthSpec>(
            &single,
            committee_count_at_slot,
            &spec,
        )
        .expect("fixed testing-only batch subnet");
        candidates.push(PqLocalAttestationCandidate {
            pubkey: PqPublicKey::deserialize(&[key_byte; 32])
                .expect("fixed testing-only public key"),
            validator_index,
            committee_index: 0,
            committee_position: index,
            committee_length,
            committee_count_at_slot,
            subnet,
            bound_head_root,
            dependent_root,
            signing_root: Hash256::repeat_byte(0x53),
            attestation: attestation.clone(),
        });
        let mut signed_attestation = attestation;
        signed_attestation
            .attach_individual_signature(&PqRawSignature::empty(), index)
            .expect("fixed testing-only batch signature attachment");
        signed.push(signed_attestation);
    }
    let coordinator = Arc::new(crate::beacon_chain::PqImportCoordinator::default());
    let activity = coordinator
        .try_start()
        .expect("testing candidate batch activity");
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let admission_permit = Arc::clone(&admission)
        .try_acquire_owned()
        .expect("testing candidate batch admission");
    (
        PqOwnedLocalAttestationCandidateBatch {
            candidates,
            _admission: admission_permit,
            _activity: activity,
        },
        signed,
        spec,
        TestingPqLocalCandidateBatchGuards {
            coordinator,
            admission,
        },
    )
}
