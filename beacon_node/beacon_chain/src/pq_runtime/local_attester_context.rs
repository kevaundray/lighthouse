use crate::{BeaconChain, BeaconChainTypes};
use consensus_signature::ValidatorPublicKeyBytes;
use slot_clock::SlotClock;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use types::{
    Attestation, EthSpec, ForkName, Hash256, MinimalEthSpec, RelativeEpoch, Slot, SubnetId,
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

    pub const fn attestation(&self) -> &Attestation<E> {
        &self.attestation
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
                        candidates.push(PqLocalAttestationCandidate {
                            pubkey: identity.pubkey,
                            validator_index: identity.validator_index,
                            committee_index: duty.index,
                            committee_position: duty.committee_position,
                            committee_length: duty.committee_len,
                            committee_count_at_slot: duty.committees_at_slot,
                            subnet,
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
}
