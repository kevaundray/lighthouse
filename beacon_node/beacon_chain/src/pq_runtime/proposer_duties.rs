use crate::{BeaconChain, BeaconChainTypes};
use consensus_signature::ValidatorPublicKeyBytes;
use slot_clock::SlotClock;
use state_processing::per_slot_processing_pq;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use types::{Epoch, EthSpec, ForkName, Hash256, Slot};

/// At most two small duty responses may be derived or retained by slow HTTP clients at once.
pub const PQ_PROPOSER_DUTY_ADMISSION_CAPACITY: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqProposerDuty {
    pubkey: ValidatorPublicKeyBytes,
    validator_index: u64,
    slot: Slot,
}

impl PqProposerDuty {
    pub const fn pubkey(&self) -> ValidatorPublicKeyBytes {
        self.pubkey
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    pub const fn slot(&self) -> Slot {
        self.slot
    }
}

#[derive(Debug)]
pub struct PqProposerDuties {
    entries: Vec<PqProposerDuty>,
    dependent_root: Hash256,
    bound_head_root: Hash256,
    _admission: OwnedSemaphorePermit,
    #[cfg(feature = "pq-startup-testing")]
    advanced_slots: u64,
}

impl PqProposerDuties {
    pub fn entries(&self) -> &[PqProposerDuty] {
        &self.entries
    }

    pub const fn dependent_root(&self) -> Hash256 {
        self.dependent_root
    }

    pub const fn bound_head_root(&self) -> Hash256 {
        self.bound_head_root
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub const fn testing_only_advanced_slots(&self) -> u64 {
        self.advanced_slots
    }
}

#[derive(Debug)]
pub enum PqProposerDutiesError {
    Capacity,
    ClockUnavailable,
    EpochOutsideWindow { current: Epoch, requested: Epoch },
    HeadOutsideWindow { head: Epoch, current: Epoch },
    WrongFork(ForkName),
    State(types::BeaconStateError),
    Transition(state_processing::PqTransitionError),
    ValidatorIndexOverflow(usize),
    SlotOverflow,
    BlockingTask,
    StaleHead { expected: Hash256, actual: Hash256 },
}

impl std::fmt::Display for PqProposerDutiesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ proposer duties unavailable: {self:?}")
    }
}

impl Error for PqProposerDutiesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transition(error) => Some(error),
            Self::Capacity
            | Self::ClockUnavailable
            | Self::EpochOutsideWindow { .. }
            | Self::HeadOutsideWindow { .. }
            | Self::WrongFork(_)
            | Self::ValidatorIndexOverflow(_)
            | Self::SlotOverflow
            | Self::BlockingTask
            | Self::State(_)
            | Self::StaleHead { .. } => None,
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_proposer_duty_available_permits(&self) -> usize {
        self.pq_proposer_duty_admission.available_permits()
    }

    pub async fn pq_proposer_duties(
        self: &Arc<Self>,
        requested: Epoch,
    ) -> Result<PqProposerDuties, PqProposerDutiesError> {
        let admission = self
            .pq_proposer_duty_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| PqProposerDutiesError::Capacity)?;
        let current = self
            .slot_clock
            .now()
            .ok_or(PqProposerDutiesError::ClockUnavailable)?
            .epoch(T::EthSpec::slots_per_epoch());
        let next = Epoch::new(
            current
                .as_u64()
                .checked_add(1)
                .ok_or(PqProposerDutiesError::SlotOverflow)?,
        );
        if requested != current && requested != next {
            return Err(PqProposerDutiesError::EpochOutsideWindow { current, requested });
        }

        let snapshot = self.head_snapshot();
        let bound_head_root = snapshot.beacon_block_root;
        let head_epoch = snapshot
            .beacon_state
            .slot()
            .epoch(T::EthSpec::slots_per_epoch());
        let head_next = Epoch::new(
            head_epoch
                .as_u64()
                .checked_add(1)
                .ok_or(PqProposerDutiesError::SlotOverflow)?,
        );
        if current < head_epoch || current > head_next {
            return Err(PqProposerDutiesError::HeadOutsideWindow {
                head: head_epoch,
                current,
            });
        }
        if requested != head_epoch && requested != head_next {
            return Err(PqProposerDutiesError::HeadOutsideWindow {
                head: head_epoch,
                current,
            });
        }

        let spec = Arc::clone(&self.spec);
        #[cfg(feature = "pq-startup-testing")]
        let blocking_test_hook = self.pq_proposer_duties_test_hook.clone();
        let derived = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = blocking_test_hook {
                        hook.run();
                    }
                    let mut state = snapshot.beacon_state.clone();
                    let fork = spec.fork_name_at_epoch(requested);
                    if fork != ForkName::Electra {
                        return Err(PqProposerDutiesError::WrongFork(fork));
                    }
                    let requested_start = requested.start_slot(T::EthSpec::slots_per_epoch());
                    #[cfg(feature = "pq-startup-testing")]
                    let initial_slot = state.slot();
                    while state.slot() < requested_start {
                        per_slot_processing_pq(&mut state, &spec)
                            .map_err(PqProposerDutiesError::Transition)?;
                    }
                    let proposer_indices = state
                        .get_beacon_proposer_indices(requested, &spec)
                        .map_err(PqProposerDutiesError::State)?;
                    let start = requested.start_slot(T::EthSpec::slots_per_epoch());
                    let mut entries = Vec::with_capacity(proposer_indices.len());
                    for (offset, proposer_index) in proposer_indices.into_iter().enumerate() {
                        let offset = u64::try_from(offset)
                            .map_err(|_| PqProposerDutiesError::SlotOverflow)?;
                        let slot = start
                            .as_u64()
                            .checked_add(offset)
                            .map(Slot::new)
                            .ok_or(PqProposerDutiesError::SlotOverflow)?;
                        let validator = state
                            .get_validator(proposer_index)
                            .map_err(PqProposerDutiesError::State)?;
                        entries.push(PqProposerDuty {
                            pubkey: validator.pubkey,
                            validator_index: u64::try_from(proposer_index).map_err(|_| {
                                PqProposerDutiesError::ValidatorIndexOverflow(proposer_index)
                            })?,
                            slot,
                        });
                    }
                    let dependent_root = state
                        .legacy_proposer_shuffling_decision_root_at_epoch(
                            requested,
                            bound_head_root,
                        )
                        .map_err(PqProposerDutiesError::State)?;
                    Ok(PqProposerDuties {
                        entries,
                        dependent_root,
                        bound_head_root,
                        _admission: admission,
                        #[cfg(feature = "pq-startup-testing")]
                        advanced_slots: state
                            .slot()
                            .as_u64()
                            .checked_sub(initial_slot.as_u64())
                            .ok_or(PqProposerDutiesError::SlotOverflow)?,
                    })
                },
                "pq-proposer-duties",
            )
            .ok_or(PqProposerDutiesError::BlockingTask)?
            .await
            .map_err(|_| PqProposerDutiesError::BlockingTask)??;

        let actual = self.head_snapshot().beacon_block_root;
        if actual != derived.bound_head_root {
            return Err(PqProposerDutiesError::StaleHead {
                expected: derived.bound_head_root,
                actual,
            });
        }
        let late_current = self
            .slot_clock
            .now()
            .ok_or(PqProposerDutiesError::ClockUnavailable)?
            .epoch(T::EthSpec::slots_per_epoch());
        let late_next = Epoch::new(
            late_current
                .as_u64()
                .checked_add(1)
                .ok_or(PqProposerDutiesError::SlotOverflow)?,
        );
        if requested != late_current && requested != late_next {
            return Err(PqProposerDutiesError::EpochOutsideWindow {
                current: late_current,
                requested,
            });
        }
        Ok(derived)
    }
}
