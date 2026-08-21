//! Private direct local attester service for the bounded PQ devnet profile.

#![cfg_attr(not(feature = "pq-devnet"), allow(dead_code))]

#[cfg(feature = "pq-devnet")]
use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqLocalAttestationBatchSealError,
    PqLocalAttestationContextError, PqLocalAttesterIdentity, PqOwnedLocalAttestationCandidateBatch,
    PqSealedLocalAttestationBatch, PqVerifiedLocalAttestationBatch, PqVerifiedLocalSingle,
};
#[cfg(feature = "pq-devnet")]
use futures::{FutureExt, StreamExt};
#[cfg(feature = "pq-devnet")]
use lighthouse_validator_store::LighthouseValidatorStore;
#[cfg(feature = "pq-devnet")]
use slot_clock::SlotClock;
#[cfg(feature = "pq-devnet")]
use slot_clock::SystemTimeSlotClock;
#[cfg(feature = "pq-devnet")]
use std::collections::HashSet;
#[cfg(feature = "pq-devnet")]
use std::future::Future;
#[cfg(feature = "pq-devnet")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "pq-devnet")]
use task_executor::TaskExecutor;
#[cfg(feature = "pq-devnet")]
use types::{Attestation, AttestationData, ChainSpec, Epoch, EthSpec, MinimalEthSpec, Slot};
#[cfg(feature = "pq-devnet")]
use validator_store::{AttestationToSign, ValidatorStore};

#[cfg(feature = "pq-devnet")]
pub const PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY: usize = 16;

/// Maximum number of local Minimal attestations proven concurrently by the direct service.
#[cfg(feature = "pq-devnet")]
pub const PQ_LOCAL_ATTESTATION_PROOF_CAPACITY: usize = 2;

/// A bounded local-attestation signing decision which retains the Slice-A candidate guards.
#[cfg(feature = "pq-devnet")]
pub enum PqLocalAttestationSigningPlan<E: EthSpec> {
    NoDuty,
    Sign(PqLocalAttestationSigningBatch<E>),
}

/// An exact candidate batch awaiting validator-store output.
#[cfg(feature = "pq-devnet")]
pub struct PqLocalAttestationSigningBatch<E: EthSpec> {
    candidates: PqOwnedLocalAttestationCandidateBatch<E>,
}

#[cfg(feature = "pq-devnet")]
impl<E: EthSpec> PqLocalAttestationSigningBatch<E> {
    fn requests(&self) -> Vec<AttestationToSign<E>> {
        self.candidates
            .candidates()
            .iter()
            .map(|candidate| AttestationToSign {
                validator_index: candidate.validator_index(),
                pubkey: candidate.pubkey(),
                validator_committee_index: candidate.committee_position(),
                attestation: candidate.attestation().clone(),
            })
            .collect()
    }

    fn attempt_descriptors(&self) -> Arc<[PqAttestationAttemptDescriptor]> {
        self.candidates
            .candidates()
            .iter()
            .map(|candidate| PqAttestationAttemptDescriptor {
                pubkey: candidate.pubkey(),
                validator_index: candidate.validator_index(),
                target_epoch: candidate.attestation().data().target.epoch,
                data: candidate.attestation().data().clone(),
                signing_root: candidate.signing_root(),
            })
            .collect()
    }

    /// Starts exactly one validator-store signing attempt while retaining the Slice-A guards.
    ///
    /// The returned receipt is only an observer: dropping it cannot cancel the process-owned
    /// signing operation or release its candidate admission/activity guards.
    pub fn sign_once<T: SlotClock + 'static>(
        self,
        store: Arc<LighthouseValidatorStore<T, E>>,
        task_executor: TaskExecutor,
        spec: Arc<ChainSpec>,
    ) -> Result<PqLocalAttestationSigningReceipt<E>, PqLocalAttestationSigningError> {
        self.spawn_sign_once(task_executor, spec, move |requests| async move {
            let signed_stream = store.sign_attestations(requests);
            futures::pin_mut!(signed_stream);
            let signed = signed_stream
                .next()
                .await
                .ok_or(PqLocalAttestationSigningError::StoreStreamClosed)?
                .map_err(PqLocalAttestationSigningError::Store)?;
            if signed_stream.next().await.is_some() {
                return Err(PqLocalAttestationSigningError::MultipleStoreBatches);
            }
            Ok(signed)
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_sign_once_with<F, Fut>(
        self,
        task_executor: TaskExecutor,
        spec: Arc<ChainSpec>,
        signer: F,
    ) -> Result<PqLocalAttestationSigningReceipt<E>, PqLocalAttestationSigningError>
    where
        F: FnOnce(Vec<AttestationToSign<E>>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<(u64, Attestation<E>)>, PqLocalAttestationSigningError>>
            + Send
            + 'static,
    {
        self.spawn_sign_once(task_executor, spec, signer)
    }

    fn spawn_sign_once<F, Fut>(
        self,
        task_executor: TaskExecutor,
        spec: Arc<ChainSpec>,
        signer: F,
    ) -> Result<PqLocalAttestationSigningReceipt<E>, PqLocalAttestationSigningError>
    where
        F: FnOnce(Vec<AttestationToSign<E>>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Vec<(u64, Attestation<E>)>, PqLocalAttestationSigningError>>
            + Send
            + 'static,
    {
        let receipt = task_executor
            .spawn_handle_without_exit(
                async move {
                    let requests = self.requests();
                    let returned = signer(requests).await?;
                    self.validate_signed(returned, &spec)
                        .map_err(PqLocalAttestationSigningError::Validation)
                },
                "pq_local_attestation_sign_once",
            )
            .ok_or(PqLocalAttestationSigningError::TaskUnavailable)?;
        Ok(PqLocalAttestationSigningReceipt { receipt })
    }

    fn validate_signed(
        self,
        returned: Vec<(u64, Attestation<E>)>,
        spec: &ChainSpec,
    ) -> Result<PqValidatedLocalAttestationBatch<E>, PqLocalAttestationBatchValidationError> {
        if returned.is_empty() {
            return Err(PqLocalAttestationBatchValidationError::Empty);
        }
        if returned.len() > PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY {
            return Err(PqLocalAttestationBatchValidationError::ReturnedCapacity {
                returned: returned.len(),
                maximum: PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY,
            });
        }
        let mut returned_indices = HashSet::with_capacity(returned.len());
        for (validator_index, _) in &returned {
            if !returned_indices.insert(*validator_index) {
                return Err(
                    PqLocalAttestationBatchValidationError::DuplicateReturnedIndex {
                        validator_index: *validator_index,
                    },
                );
            }
        }
        if let Some((validator_index, _)) = returned.iter().find(|(validator_index, _)| {
            !self
                .candidates
                .candidates()
                .iter()
                .any(|candidate| candidate.validator_index() == *validator_index)
        }) {
            return Err(PqLocalAttestationBatchValidationError::ExtraMember {
                validator_index: *validator_index,
            });
        }
        if returned.len() < self.candidates.candidates().len()
            && let Some(missing) = self.candidates.candidates().iter().find(|candidate| {
                !returned
                    .iter()
                    .any(|(validator_index, _)| *validator_index == candidate.validator_index())
            })
        {
            return Err(PqLocalAttestationBatchValidationError::MissingMember {
                validator_index: missing.validator_index(),
            });
        }
        if let Some((position, (candidate, (actual, _)))) = self
            .candidates
            .candidates()
            .iter()
            .zip(returned.iter())
            .enumerate()
            .find(|(_, (candidate, (actual, _)))| candidate.validator_index() != *actual)
        {
            return Err(PqLocalAttestationBatchValidationError::OrderMismatch {
                position,
                expected: candidate.validator_index(),
                actual: *actual,
            });
        }
        let sealed = self
            .candidates
            .seal_exact_ordered(returned, spec)
            .map_err(PqLocalAttestationBatchValidationError::Seal)?;
        Ok(PqValidatedLocalAttestationBatch { sealed })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_validate_signed(
        self,
        returned: Vec<(u64, Attestation<E>)>,
        spec: &ChainSpec,
    ) -> Result<PqValidatedLocalAttestationBatch<E>, PqLocalAttestationBatchValidationError> {
        self.validate_signed(returned, spec)
    }
}

/// Result-bearing observer for one process-owned local-attestation signing attempt.
#[cfg(feature = "pq-devnet")]
pub struct PqLocalAttestationSigningReceipt<E: EthSpec> {
    receipt: tokio::sync::oneshot::Receiver<
        Result<
            Result<PqValidatedLocalAttestationBatch<E>, PqLocalAttestationSigningError>,
            tokio::task::JoinError,
        >,
    >,
}

#[cfg(feature = "pq-devnet")]
impl<E: EthSpec> PqLocalAttestationSigningReceipt<E> {
    pub async fn wait(
        self,
    ) -> Result<PqValidatedLocalAttestationBatch<E>, PqLocalAttestationSigningError> {
        self.receipt
            .await
            .map_err(|_| PqLocalAttestationSigningError::CompletionClosed)?
            .map_err(|_| PqLocalAttestationSigningError::TaskFailed)?
    }
}

#[cfg(feature = "pq-devnet")]
#[derive(Debug)]
pub enum PqLocalAttestationSigningError {
    TaskUnavailable,
    TaskFailed,
    CompletionClosed,
    StoreStreamClosed,
    MultipleStoreBatches,
    Store(lighthouse_validator_store::Error),
    Validation(PqLocalAttestationBatchValidationError),
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqLocalAttestationSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ local attestation signing failed: {self:?}")
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqLocalAttestationSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::TaskUnavailable
            | Self::TaskFailed
            | Self::CompletionClosed
            | Self::StoreStreamClosed
            | Self::MultipleStoreBatches
            | Self::Store(_) => None,
        }
    }
}

/// Exact signed output retained atomically with its Slice-A admission and shutdown activity.
#[cfg(feature = "pq-devnet")]
pub struct PqValidatedLocalAttestationBatch<E: EthSpec> {
    sealed: PqSealedLocalAttestationBatch<E>,
}

#[cfg(feature = "pq-devnet")]
impl<E: EthSpec> PqValidatedLocalAttestationBatch<E> {
    pub fn len(&self) -> usize {
        self.sealed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sealed.is_empty()
    }

    fn into_sealed(self) -> PqSealedLocalAttestationBatch<E> {
        self.sealed
    }
}

#[cfg(feature = "pq-devnet")]
#[derive(Debug)]
pub enum PqLocalAttestationBatchValidationError {
    Capacity {
        requested: usize,
        maximum: usize,
    },
    ReturnedCapacity {
        returned: usize,
        maximum: usize,
    },
    DuplicateReturnedIndex {
        validator_index: u64,
    },
    Empty,
    ExtraMember {
        validator_index: u64,
    },
    MissingMember {
        validator_index: u64,
    },
    OrderMismatch {
        position: usize,
        expected: u64,
        actual: u64,
    },
    Seal(PqLocalAttestationBatchSealError),
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqLocalAttestationBatchValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ local attestation batch failed: {self:?}")
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqLocalAttestationBatchValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Seal(error) => Some(error),
            Self::Capacity { .. }
            | Self::ReturnedCapacity { .. }
            | Self::DuplicateReturnedIndex { .. }
            | Self::Empty
            | Self::ExtraMember { .. }
            | Self::MissingMember { .. }
            | Self::OrderMismatch { .. } => None,
        }
    }
}

#[cfg(feature = "pq-devnet")]
pub fn plan_pq_local_attestations<E: EthSpec>(
    candidates: PqOwnedLocalAttestationCandidateBatch<E>,
) -> Result<PqLocalAttestationSigningPlan<E>, PqLocalAttestationBatchValidationError> {
    let requested = candidates.candidates().len();
    if requested == 0 {
        return Ok(PqLocalAttestationSigningPlan::NoDuty);
    }
    if requested > PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY {
        return Err(PqLocalAttestationBatchValidationError::Capacity {
            requested,
            maximum: PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY,
        });
    }
    Ok(PqLocalAttestationSigningPlan::Sign(
        PqLocalAttestationSigningBatch { candidates },
    ))
}

/// Cloneable, bounded public result of one direct local-attestation attempt.
#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqAttestationCompletion {
    NoDuty { slot: Slot },
    Verified(PqVerifiedAttestationBatchMetadata),
}

/// Exact non-secret bindings for a completed local attestation batch.
#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqVerifiedAttestationBatchMetadata {
    pub slot: Slot,
    pub members: Arc<[PqVerifiedAttestationMetadata]>,
}

/// Exact non-secret bindings for one locally verified attestation.
#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqVerifiedAttestationMetadata {
    pub validator_index: u64,
    pub pubkey: consensus_signature::ValidatorPublicKeyBytes,
    pub committee_index: u64,
    pub committee_position: usize,
    pub committee_length: usize,
    pub committee_count_at_slot: u64,
    pub subnet: types::SubnetId,
    pub slot: Slot,
    pub bound_head_root: types::Hash256,
    pub dependent_root: types::Hash256,
    pub signing_root: types::Hash256,
    pub signed_ssz_digest: [u8; 32],
}

#[cfg(feature = "pq-devnet")]
impl PqVerifiedAttestationMetadata {
    fn from_verified(verified: &PqVerifiedLocalSingle<MinimalEthSpec>) -> Self {
        Self {
            validator_index: verified.validator_index(),
            pubkey: verified.pubkey(),
            committee_index: verified.committee_index(),
            committee_position: verified.committee_position(),
            committee_length: verified.committee_length(),
            committee_count_at_slot: verified.committee_count_at_slot(),
            subnet: verified.subnet(),
            slot: verified.slot(),
            bound_head_root: verified.bound_head_root(),
            dependent_root: verified.dependent_root(),
            signing_root: verified.signing_root(),
            signed_ssz_digest: verified.signed_ssz_digest(),
        }
    }
}

/// Cloneable result observer. Dropping it never owns or cancels the attestation operation.
#[cfg(feature = "pq-devnet")]
pub struct PqAttestationReceipt {
    completion: tokio::sync::watch::Receiver<
        Option<Result<PqAttestationCompletion, PqAttesterServiceError>>,
    >,
}

#[cfg(feature = "pq-devnet")]
impl PqAttestationReceipt {
    pub async fn wait(mut self) -> Result<PqAttestationCompletion, PqAttesterServiceError> {
        loop {
            if let Some(completion) = self.completion.borrow_and_update().clone() {
                return completion;
            }
            self.completion
                .changed()
                .await
                .map_err(|_| PqAttesterServiceError::CompletionClosed)?;
        }
    }
}

#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum PqAttestationPhase {
    PreSign,
    Stateful(Arc<[PqAttestationAttemptDescriptor]>),
}

#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PqAttestationAttemptDescriptor {
    pubkey: consensus_signature::ValidatorPublicKeyBytes,
    validator_index: u64,
    target_epoch: Epoch,
    data: AttestationData,
    signing_root: types::Hash256,
}

#[cfg(feature = "pq-devnet")]
struct PqAttesterOperationSuccess {
    completion: PqAttestationCompletion,
    owned: Option<PqVerifiedLocalAttestationBatch<MinimalEthSpec>>,
}

#[cfg(feature = "pq-devnet")]
impl PqAttesterOperationSuccess {
    fn no_duty(slot: Slot) -> Self {
        Self {
            completion: PqAttestationCompletion::NoDuty { slot },
            owned: None,
        }
    }
}

#[cfg(feature = "pq-devnet")]
enum PqAttesterState {
    Idle,
    InFlight {
        slot: Slot,
        phase: PqAttestationPhase,
        completion: tokio::sync::watch::Sender<
            Option<Result<PqAttestationCompletion, PqAttesterServiceError>>,
        >,
    },
    CompletedNoDuty {
        slot: Slot,
    },
    CompletedVerified {
        slot: Slot,
        attempts: Arc<[PqAttestationAttemptDescriptor]>,
        metadata: PqVerifiedAttestationBatchMetadata,
        owned: Option<PqVerifiedLocalAttestationBatch<MinimalEthSpec>>,
    },
    CompletedTerminal {
        slot: Slot,
        attempts: Option<Arc<[PqAttestationAttemptDescriptor]>>,
        error: PqAttesterServiceError,
    },
}

#[cfg(feature = "pq-devnet")]
struct PqAttesterControl {
    closed: bool,
    active: usize,
    no_duty_watermark: Option<Slot>,
    state: PqAttesterState,
}

#[cfg(feature = "pq-devnet")]
struct PqAttesterShared {
    control: Mutex<PqAttesterControl>,
    active: tokio::sync::watch::Sender<usize>,
}

#[cfg(feature = "pq-devnet")]
impl PqAttesterShared {
    fn new() -> Self {
        let (active, _) = tokio::sync::watch::channel(0);
        Self {
            control: Mutex::new(PqAttesterControl {
                closed: false,
                active: 0,
                no_duty_watermark: None,
                state: PqAttesterState::Idle,
            }),
            active,
        }
    }

    fn finish_activity(&self, control: &mut PqAttesterControl) {
        control.active = control.active.saturating_sub(1);
        self.active.send_replace(control.active);
    }

    fn try_admit(
        &self,
        slot: Slot,
    ) -> Result<(PqAttestationReceipt, bool), PqAttesterServiceError> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| PqAttesterServiceError::StatePoisoned)?;
        if control.closed {
            return Err(PqAttesterServiceError::Closed);
        }
        if matches!(control.state, PqAttesterState::Idle)
            && let Some(completed) = control.no_duty_watermark
        {
            if slot == completed {
                return Ok((
                    immediate_receipt(Ok(PqAttestationCompletion::NoDuty { slot })),
                    false,
                ));
            }
            if slot < completed {
                return Err(PqAttesterServiceError::SlotRollback {
                    completed,
                    requested: slot,
                });
            }
        }
        match &control.state {
            PqAttesterState::Idle => {}
            PqAttesterState::InFlight {
                slot: active_slot,
                completion,
                ..
            } if *active_slot == slot => {
                return Ok((
                    PqAttestationReceipt {
                        completion: completion.subscribe(),
                    },
                    false,
                ));
            }
            PqAttesterState::InFlight {
                slot: active_slot, ..
            } => {
                return Err(PqAttesterServiceError::Busy {
                    active: *active_slot,
                    requested: slot,
                });
            }
            PqAttesterState::CompletedNoDuty {
                slot: completed_slot,
            } if slot > *completed_slot => {}
            PqAttesterState::CompletedNoDuty {
                slot: completed_slot,
            } if slot < *completed_slot => {
                return Err(PqAttesterServiceError::SlotRollback {
                    completed: *completed_slot,
                    requested: slot,
                });
            }
            PqAttesterState::CompletedVerified {
                slot: completed_slot,
                ..
            }
            | PqAttesterState::CompletedTerminal {
                slot: completed_slot,
                ..
            } if *completed_slot != slot => {
                return Err(PqAttesterServiceError::PreviousUnconsumed {
                    previous: *completed_slot,
                    requested: slot,
                });
            }
            PqAttesterState::CompletedNoDuty { .. } => {
                return Ok((
                    immediate_receipt(Ok(PqAttestationCompletion::NoDuty { slot })),
                    false,
                ));
            }
            PqAttesterState::CompletedVerified { metadata, .. } => {
                return Ok((
                    immediate_receipt(Ok(PqAttestationCompletion::Verified(metadata.clone()))),
                    false,
                ));
            }
            PqAttesterState::CompletedTerminal { error, .. } => return Err(error.clone()),
        }
        let (completion, receipt) = tokio::sync::watch::channel(None);
        control.active = control
            .active
            .checked_add(1)
            .ok_or(PqAttesterServiceError::ActivityOverflow)?;
        self.active.send_replace(control.active);
        control.state = PqAttesterState::InFlight {
            slot,
            phase: PqAttestationPhase::PreSign,
            completion,
        };
        Ok((
            PqAttestationReceipt {
                completion: receipt,
            },
            true,
        ))
    }

    fn finish(
        &self,
        slot: Slot,
        result: Result<PqAttesterOperationSuccess, PqAttesterServiceError>,
    ) {
        let Ok(mut control) = self.control.lock() else {
            return;
        };
        let (completion, phase) = match &control.state {
            PqAttesterState::InFlight {
                slot: active_slot,
                phase,
                completion,
                ..
            } if *active_slot == slot => (completion.clone(), phase.clone()),
            _ => return,
        };
        let public_result = match result {
            Ok(PqAttesterOperationSuccess {
                completion:
                    PqAttestationCompletion::NoDuty {
                        slot: completed_slot,
                    },
                owned: None,
            }) => {
                control.no_duty_watermark = Some(
                    control
                        .no_duty_watermark
                        .map_or(completed_slot, |watermark| watermark.max(completed_slot)),
                );
                control.state = PqAttesterState::CompletedNoDuty { slot };
                Ok(PqAttestationCompletion::NoDuty {
                    slot: completed_slot,
                })
            }
            Ok(PqAttesterOperationSuccess {
                completion: PqAttestationCompletion::Verified(metadata),
                owned: Some(owned),
            }) => {
                let attempts = match &phase {
                    PqAttestationPhase::Stateful(attempts) => Arc::clone(attempts),
                    PqAttestationPhase::PreSign => Arc::from([]),
                };
                control.state = PqAttesterState::CompletedVerified {
                    slot,
                    attempts,
                    metadata: metadata.clone(),
                    owned: Some(owned),
                };
                Ok(PqAttestationCompletion::Verified(metadata))
            }
            Ok(_) => {
                let error = PqAttesterServiceError::AtomicBatchMissing;
                control.state = PqAttesterState::CompletedTerminal {
                    slot,
                    attempts: match &phase {
                        PqAttestationPhase::PreSign => None,
                        PqAttestationPhase::Stateful(attempts) => Some(Arc::clone(attempts)),
                    },
                    error: error.clone(),
                };
                Err(error)
            }
            Err(error) if phase == PqAttestationPhase::PreSign && error.is_pre_sign_retryable() => {
                control.state = PqAttesterState::Idle;
                Err(error)
            }
            Err(error) => {
                control.state = PqAttesterState::CompletedTerminal {
                    slot,
                    attempts: match &phase {
                        PqAttestationPhase::PreSign => None,
                        PqAttestationPhase::Stateful(attempts) => Some(Arc::clone(attempts)),
                    },
                    error: error.clone(),
                };
                Err(error)
            }
        };
        self.finish_activity(&mut control);
        completion.send_replace(Some(public_result));
    }

    fn mark_stateful(
        &self,
        slot: Slot,
        attempts: Arc<[PqAttestationAttemptDescriptor]>,
    ) -> Result<(), PqAttesterServiceError> {
        let mut control = self
            .control
            .lock()
            .map_err(|_| PqAttesterServiceError::StatePoisoned)?;
        match &mut control.state {
            PqAttesterState::InFlight {
                slot: active_slot,
                phase,
                ..
            } if *active_slot == slot => {
                *phase = PqAttestationPhase::Stateful(attempts);
                Ok(())
            }
            _ => Err(PqAttesterServiceError::StatePoisoned),
        }
    }

    fn is_stateful(&self, slot: Slot) -> bool {
        self.control.lock().is_ok_and(|control| {
            matches!(
                &control.state,
                PqAttesterState::InFlight {
                    slot: active_slot,
                    phase: PqAttestationPhase::Stateful(_),
                    ..
                } if *active_slot == slot
            )
        })
    }
}

#[cfg(feature = "pq-devnet")]
fn immediate_receipt(
    completion: Result<PqAttestationCompletion, PqAttesterServiceError>,
) -> PqAttestationReceipt {
    let (_, receipt) = tokio::sync::watch::channel(Some(completion));
    PqAttestationReceipt {
        completion: receipt,
    }
}

#[cfg(feature = "pq-devnet")]
fn prepare_pq_stateful_signing(
    shared: &PqAttesterShared,
    slot: Slot,
    batch: PqLocalAttestationSigningBatch<MinimalEthSpec>,
) -> Result<PqLocalAttestationSigningBatch<MinimalEthSpec>, PqAttesterServiceError> {
    let count = batch.candidates.candidates().len();
    if count > PQ_LOCAL_ATTESTATION_PROOF_CAPACITY {
        return Err(PqAttesterServiceError::ProofCapacity {
            count,
            maximum: PQ_LOCAL_ATTESTATION_PROOF_CAPACITY,
        });
    }
    shared.mark_stateful(slot, batch.attempt_descriptors())?;
    Ok(batch)
}

#[cfg(feature = "pq-devnet")]
fn spawn_pq_attester_supervisor<Fut>(
    shared: Arc<PqAttesterShared>,
    task_executor: &TaskExecutor,
    slot: Slot,
    operation: Fut,
) -> Result<(), PqAttesterServiceError>
where
    Fut: Future<Output = Result<PqAttesterOperationSuccess, PqAttesterServiceError>>
        + Send
        + 'static,
{
    let completion_shared = Arc::clone(&shared);
    let mut shutdown = task_executor.shutdown_sender();
    let mut unavailable_shutdown = task_executor.shutdown_sender();
    let task = task_executor.spawn_handle_without_exit(
        async move {
            match std::panic::AssertUnwindSafe(operation).catch_unwind().await {
                Ok(result) => {
                    let signal_failure = result.is_err()
                        && (completion_shared.is_stateful(slot)
                            || result
                                .as_ref()
                                .is_err_and(PqAttesterServiceError::requires_global_failure));
                    completion_shared.finish(slot, result);
                    if signal_failure {
                        let _ = shutdown.try_send(task_executor::ShutdownReason::Failure(
                            "PQ attester operation failed",
                        ));
                    }
                }
                Err(_) => {
                    completion_shared.finish(slot, Err(PqAttesterServiceError::TaskPanic));
                    let _ = shutdown.try_send(task_executor::ShutdownReason::Failure(
                        "PQ attester task panicked",
                    ));
                }
            }
        },
        "pq-attester-current-slot",
    );
    if task.is_none() {
        shared.finish(slot, Err(PqAttesterServiceError::TaskUnavailable));
        let _ = unavailable_shutdown.try_send(task_executor::ShutdownReason::Failure(
            "PQ attester task unavailable",
        ));
        return Err(PqAttesterServiceError::TaskUnavailable);
    }
    drop(task);
    Ok(())
}

#[cfg(feature = "pq-devnet")]
async fn close_and_drain_pq_attester(
    shared: &PqAttesterShared,
) -> Result<(), PqAttesterServiceError> {
    let mut active = shared.active.subscribe();
    let retained =
        {
            let mut control = shared
                .control
                .lock()
                .map_err(|_| PqAttesterServiceError::StatePoisoned)?;
            control.closed = true;
            match &mut control.state {
                PqAttesterState::CompletedVerified {
                    attempts, owned, ..
                } => {
                    debug_assert!(attempts.len() <= PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY);
                    debug_assert!(owned.as_ref().is_none_or(|batch| {
                        batch.len() <= PQ_LOCAL_ATTESTATION_PROOF_CAPACITY
                    }));
                    owned.take()
                }
                PqAttesterState::CompletedTerminal { attempts, .. } => {
                    debug_assert!(attempts.as_ref().is_none_or(|attempts| {
                        attempts.len() <= PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY
                    }));
                    None
                }
                _ => None,
            }
        };
    drop(retained);
    while *active.borrow_and_update() != 0 {
        active
            .changed()
            .await
            .map_err(|_| PqAttesterServiceError::CompletionClosed)?;
    }
    let completed_during_drain = {
        let mut control = shared
            .control
            .lock()
            .map_err(|_| PqAttesterServiceError::StatePoisoned)?;
        match &mut control.state {
            PqAttesterState::CompletedVerified { owned, .. } => owned.take(),
            _ => None,
        }
    };
    drop(completed_during_drain);
    Ok(())
}

/// Concrete process-owned direct attester for the frozen Minimal PQ profile.
#[cfg(feature = "pq-devnet")]
pub struct PqAttesterService<T>
where
    T: BeaconChainTypes<EthSpec = MinimalEthSpec, SlotClock = SystemTimeSlotClock>,
{
    chain: Arc<BeaconChain<T>>,
    validator_store: Arc<LighthouseValidatorStore<SystemTimeSlotClock, MinimalEthSpec>>,
    task_executor: TaskExecutor,
    identities: Arc<[PqLocalAttesterIdentity]>,
    shared: Arc<PqAttesterShared>,
}

#[cfg(feature = "pq-devnet")]
impl<T> PqAttesterService<T>
where
    T: BeaconChainTypes<EthSpec = MinimalEthSpec, SlotClock = SystemTimeSlotClock>,
{
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        validator_store: Arc<LighthouseValidatorStore<SystemTimeSlotClock, MinimalEthSpec>>,
        task_executor: TaskExecutor,
    ) -> Result<Self, PqAttesterServiceError> {
        let identities = validate_pq_attester_identity_snapshot(
            validator_store.pq_validator_identity_snapshot(),
        )?;
        Ok(Self {
            chain,
            validator_store,
            task_executor,
            identities,
            shared: Arc::new(PqAttesterShared::new()),
        })
    }

    pub fn try_attest_current_slot(
        self: &Arc<Self>,
    ) -> Result<PqAttestationReceipt, PqAttesterServiceError> {
        let slot = self
            .chain
            .slot_clock
            .now()
            .ok_or(PqAttesterServiceError::ClockUnavailable)?;
        let (receipt, started) = self.shared.try_admit(slot)?;
        if !started {
            return Ok(receipt);
        }

        let service = Arc::clone(self);
        spawn_pq_attester_supervisor(
            Arc::clone(&self.shared),
            &self.task_executor,
            slot,
            async move { service.run_initial_operation(slot).await },
        )?;
        Ok(receipt)
    }

    async fn run_initial_operation(
        &self,
        slot: Slot,
    ) -> Result<PqAttesterOperationSuccess, PqAttesterServiceError> {
        let context = self
            .chain
            .pq_local_attestation_context(Arc::clone(&self.identities))
            .await
            .map_err(map_context_error)?;
        let snapshot = self
            .chain
            .consume_pq_local_attestation_context(context)
            .map_err(map_context_error)?;
        match plan_pq_local_attestations(snapshot.into_owned_candidate_batch())
            .map_err(|error| PqAttesterServiceError::Planning(Arc::new(error)))?
        {
            PqLocalAttestationSigningPlan::NoDuty => Ok(PqAttesterOperationSuccess::no_duty(slot)),
            PqLocalAttestationSigningPlan::Sign(batch) => {
                let batch = prepare_pq_stateful_signing(&self.shared, slot, batch)?;
                let signed = batch
                    .sign_once(
                        Arc::clone(&self.validator_store),
                        self.task_executor.clone(),
                        Arc::clone(&self.chain.spec),
                    )
                    .map_err(|error| PqAttesterServiceError::Signing(Arc::new(error)))?
                    .wait()
                    .await
                    .map_err(|error| PqAttesterServiceError::Signing(Arc::new(error)))?;
                self.verify_local_batch(slot, signed).await
            }
        }
    }

    async fn verify_local_batch(
        &self,
        slot: Slot,
        signed: PqValidatedLocalAttestationBatch<MinimalEthSpec>,
    ) -> Result<PqAttesterOperationSuccess, PqAttesterServiceError> {
        let verified = self
            .chain
            .verify_pq_local_attestation_batch(signed.into_sealed())
            .await
            .map_err(|error| PqAttesterServiceError::LocalProof(Arc::new(error)))?;
        let metadata = PqVerifiedAttestationBatchMetadata {
            slot,
            members: verified
                .verified()
                .iter()
                .map(PqVerifiedAttestationMetadata::from_verified)
                .collect(),
        };
        Ok(PqAttesterOperationSuccess {
            completion: PqAttestationCompletion::Verified(metadata),
            owned: Some(verified),
        })
    }

    /// Closes direct admission, drops retained verified capabilities, and awaits the sole owner.
    pub async fn close_and_drain(&self) -> Result<(), PqAttesterServiceError> {
        close_and_drain_pq_attester(&self.shared).await
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_completed_verified_metadata(
        &self,
    ) -> Option<PqVerifiedAttestationBatchMetadata> {
        let control = self.shared.control.lock().ok()?;
        match &control.state {
            PqAttesterState::CompletedVerified { metadata, .. } => Some(metadata.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_owned_verified_count(&self) -> Option<usize> {
        let control = self.shared.control.lock().ok()?;
        match &control.state {
            PqAttesterState::CompletedVerified {
                owned: Some(owned), ..
            } => Some(owned.len()),
            _ => None,
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_take_owned_verified_batch(
        &self,
    ) -> Option<PqVerifiedLocalAttestationBatch<MinimalEthSpec>> {
        let mut control = self.shared.control.lock().ok()?;
        match &mut control.state {
            PqAttesterState::CompletedVerified { owned, .. } => owned.take(),
            _ => None,
        }
    }
}

#[cfg(feature = "pq-devnet")]
fn validate_pq_attester_identity_snapshot(
    identities: Option<Vec<(consensus_signature::ValidatorPublicKeyBytes, u64)>>,
) -> Result<Arc<[PqLocalAttesterIdentity]>, PqAttesterServiceError> {
    let identities = identities.ok_or(PqAttesterServiceError::IdentitySnapshotUnavailable)?;
    if identities.is_empty() {
        return Err(PqAttesterServiceError::EmptyIdentitySet);
    }
    if identities.len() > PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY {
        return Err(PqAttesterServiceError::IdentityCapacity {
            count: identities.len(),
            maximum: PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY,
        });
    }
    let mut sealed = Vec::with_capacity(identities.len());
    let mut previous = None;
    let mut pubkeys = HashSet::with_capacity(identities.len());
    for (pubkey, validator_index) in identities {
        if !pubkeys.insert(pubkey) {
            return Err(PqAttesterServiceError::DuplicatePubkey);
        }
        if let Some(previous_index) = previous {
            if validator_index == previous_index {
                return Err(PqAttesterServiceError::DuplicateValidatorIndex(
                    validator_index,
                ));
            }
            if validator_index < previous_index {
                return Err(PqAttesterServiceError::IdentityOrder {
                    previous: previous_index,
                    current: validator_index,
                });
            }
        }
        previous = Some(validator_index);
        sealed.push(PqLocalAttesterIdentity::new(pubkey, validator_index));
    }
    Ok(sealed.into())
}

#[cfg(feature = "pq-devnet")]
fn map_context_error(error: PqLocalAttestationContextError) -> PqAttesterServiceError {
    PqAttesterServiceError::Context(Arc::new(error))
}

#[cfg(feature = "pq-devnet")]
#[derive(Clone, Debug)]
pub enum PqAttesterServiceError {
    IdentitySnapshotUnavailable,
    EmptyIdentitySet,
    IdentityCapacity { count: usize, maximum: usize },
    IdentityOrder { previous: u64, current: u64 },
    DuplicateValidatorIndex(u64),
    DuplicatePubkey,
    ClockUnavailable,
    Closed,
    Busy { active: Slot, requested: Slot },
    PreviousUnconsumed { previous: Slot, requested: Slot },
    SlotRollback { completed: Slot, requested: Slot },
    StatePoisoned,
    ActivityOverflow,
    CompletionClosed,
    TaskUnavailable,
    TaskPanic,
    Context(Arc<PqLocalAttestationContextError>),
    Planning(Arc<PqLocalAttestationBatchValidationError>),
    Signing(Arc<PqLocalAttestationSigningError>),
    ProofCapacity { count: usize, maximum: usize },
    LocalProof(Arc<beacon_chain::PqLocalAttestationBatchVerificationError>),
    AtomicBatchMissing,
}

#[cfg(feature = "pq-devnet")]
impl PqAttesterServiceError {
    pub fn is_pre_sign_retryable(&self) -> bool {
        matches!(self, Self::Context(error) if error.is_retryable())
    }

    fn requires_global_failure(&self) -> bool {
        match self {
            Self::Context(error) => !error.is_retryable(),
            Self::TaskUnavailable
            | Self::TaskPanic
            | Self::Planning(_)
            | Self::LocalProof(_)
            | Self::AtomicBatchMissing => true,
            _ => false,
        }
    }
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqAttesterServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ direct attester failed: {self:?}")
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqAttesterServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Context(error) => Some(error.as_ref()),
            Self::Planning(error) => Some(error.as_ref()),
            Self::Signing(error) => Some(error.as_ref()),
            Self::LocalProof(error) => Some(error.as_ref()),
            Self::IdentitySnapshotUnavailable
            | Self::EmptyIdentitySet
            | Self::IdentityCapacity { .. }
            | Self::IdentityOrder { .. }
            | Self::DuplicateValidatorIndex(_)
            | Self::DuplicatePubkey
            | Self::ClockUnavailable
            | Self::Closed
            | Self::Busy { .. }
            | Self::PreviousUnconsumed { .. }
            | Self::SlotRollback { .. }
            | Self::StatePoisoned
            | Self::ActivityOverflow
            | Self::CompletionClosed
            | Self::TaskUnavailable
            | Self::TaskPanic
            | Self::ProofCapacity { .. }
            | Self::AtomicBatchMissing => None,
        }
    }
}

#[cfg(all(test, feature = "pq-startup-testing"))]
mod service_state_tests {
    use super::*;
    use beacon_chain::testing_only_pq_local_candidate_batch_fixture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn two_exact_keys() -> [consensus_signature::ValidatorPublicKeyBytes; 2] {
        let (batch, _, _) = testing_only_pq_local_candidate_batch_fixture(2);
        [
            batch.candidates()[0].pubkey(),
            batch.candidates()[1].pubkey(),
        ]
    }

    #[test]
    fn identity_snapshot_is_exact_sorted_unique_and_bounded() {
        assert!(matches!(
            validate_pq_attester_identity_snapshot(None),
            Err(PqAttesterServiceError::IdentitySnapshotUnavailable)
        ));
        assert!(matches!(
            validate_pq_attester_identity_snapshot(Some(vec![])),
            Err(PqAttesterServiceError::EmptyIdentitySet)
        ));
        let [first, second] = two_exact_keys();
        assert!(matches!(
            validate_pq_attester_identity_snapshot(Some(vec![(first, 0); 17])),
            Err(PqAttesterServiceError::IdentityCapacity {
                count: 17,
                maximum: 16,
            })
        ));
        assert!(matches!(
            validate_pq_attester_identity_snapshot(Some(vec![(first, 0), (first, 1)])),
            Err(PqAttesterServiceError::DuplicatePubkey)
        ));
        assert!(matches!(
            validate_pq_attester_identity_snapshot(Some(vec![(first, 0), (second, 0)])),
            Err(PqAttesterServiceError::DuplicateValidatorIndex(0))
        ));
        assert!(matches!(
            validate_pq_attester_identity_snapshot(Some(vec![(first, 1), (second, 0)])),
            Err(PqAttesterServiceError::IdentityOrder {
                previous: 1,
                current: 0,
            })
        ));
        let sealed = validate_pq_attester_identity_snapshot(Some(vec![(first, 0), (second, 1)]))
            .expect("exact sorted identity snapshot");
        assert_eq!(sealed.len(), 2);
        assert_eq!(sealed[0].pubkey(), first);
        assert_eq!(sealed[0].validator_index(), 0);
        assert_eq!(sealed[1].pubkey(), second);
        assert_eq!(sealed[1].validator_index(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cap_one_coalesces_same_slot_and_refuses_other_or_closed_admission() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(7);
        let (first, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        let (second, started) = shared.try_admit(slot).expect("same-slot coalescing");
        assert!(!started);
        assert!(matches!(
            shared.try_admit(slot + 1),
            Err(PqAttesterServiceError::Busy {
                active,
                requested,
            }) if active == slot && requested == slot + 1
        ));

        shared.finish(slot, Ok(PqAttesterOperationSuccess::no_duty(slot)));
        assert_eq!(
            first.wait().await.expect("first shared completion"),
            PqAttestationCompletion::NoDuty { slot }
        );
        assert_eq!(
            second.wait().await.expect("second shared completion"),
            PqAttestationCompletion::NoDuty { slot }
        );
        let (cached, started) = shared.try_admit(slot).expect("cached no-duty receipt");
        assert!(!started);
        assert_eq!(
            cached.wait().await.expect("cached completion"),
            PqAttestationCompletion::NoDuty { slot }
        );

        shared.control.lock().expect("state lock").closed = true;
        assert!(matches!(
            shared.try_admit(slot),
            Err(PqAttesterServiceError::Closed)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_no_duty_admits_the_next_monotonic_slot() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(20);
        let (receipt, started) = shared.try_admit(slot).expect("first slot");
        assert!(started);
        shared.finish(slot, Ok(PqAttesterOperationSuccess::no_duty(slot)));
        assert_eq!(
            receipt.wait().await.expect("no-duty completion"),
            PqAttestationCompletion::NoDuty { slot }
        );
        assert!(matches!(
            shared.try_admit(slot - 1),
            Err(PqAttesterServiceError::SlotRollback {
                completed,
                requested,
            }) if completed == slot && requested == slot - 1
        ));
        let (_next, started) = shared
            .try_admit(slot + 1)
            .expect("the next monotonic slot must be admitted");
        assert!(started);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retryable_next_slot_preserves_the_no_duty_watermark() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(30);
        let (_first, started) = shared.try_admit(slot).expect("first slot");
        assert!(started);
        shared.finish(slot, Ok(PqAttesterOperationSuccess::no_duty(slot)));

        let (_next, started) = shared.try_admit(slot + 1).expect("next slot");
        assert!(started);
        shared.finish(
            slot + 1,
            Err(PqAttesterServiceError::Context(Arc::new(
                PqLocalAttestationContextError::IngressCapacity,
            ))),
        );

        let (cached, started) = shared
            .try_admit(slot)
            .expect("prior no-duty slot remains cached");
        assert!(!started, "cached no-duty must not start another operation");
        assert_eq!(
            cached.wait().await.expect("cached no-duty completion"),
            PqAttestationCompletion::NoDuty { slot }
        );
        assert!(matches!(
            shared.try_admit(slot - 1),
            Err(PqAttesterServiceError::SlotRollback {
                completed,
                requested,
            }) if completed == slot && requested == slot - 1
        ));
        let (_retry, started) = shared
            .try_admit(slot + 1)
            .expect("retry the transient next slot");
        assert!(started);
    }

    #[test]
    fn three_candidates_fail_before_stateful_signing_or_store_use() {
        let (candidates, _signed, _spec) = testing_only_pq_local_candidate_batch_fixture(3);
        let PqLocalAttestationSigningPlan::Sign(batch) =
            plan_pq_local_attestations(candidates).expect("three candidates fit signing cap")
        else {
            panic!("three candidates produce a signing plan")
        };
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(21);
        let (_receipt, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        let signer_calls = AtomicUsize::new(0);
        let result = prepare_pq_stateful_signing(&shared, slot, batch).map(|_| {
            signer_calls.fetch_add(1, Ordering::SeqCst);
        });
        assert!(matches!(
            result,
            Err(PqAttesterServiceError::ProofCapacity {
                count: 3,
                maximum: 2,
            })
        ));
        assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
        let control = shared.control.lock().expect("state lock");
        assert!(matches!(
            control.state,
            PqAttesterState::InFlight {
                phase: PqAttestationPhase::PreSign,
                ..
            }
        ));
        drop(control);
        shared.finish(
            slot,
            Err(PqAttesterServiceError::ProofCapacity {
                count: 3,
                maximum: 2,
            }),
        );
        let control = shared.control.lock().expect("state lock");
        assert!(matches!(
            control.state,
            PqAttesterState::CompletedTerminal { attempts: None, .. }
        ));
    }

    fn exact_attempts() -> Arc<[PqAttestationAttemptDescriptor]> {
        let (batch, _, _) = testing_only_pq_local_candidate_batch_fixture(2);
        let PqLocalAttestationSigningPlan::Sign(batch) =
            plan_pq_local_attestations(batch).expect("two-candidate signing plan")
        else {
            panic!("two candidates must be stateful")
        };
        batch.attempt_descriptors()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn only_pre_stateful_retryable_failure_restores_idle() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(8);
        let (first, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        shared.finish(
            slot,
            Err(PqAttesterServiceError::Context(Arc::new(
                PqLocalAttestationContextError::IngressCapacity,
            ))),
        );
        assert!(matches!(
            first.wait().await,
            Err(PqAttesterServiceError::Context(error))
                if matches!(*error, PqLocalAttestationContextError::IngressCapacity)
        ));
        let (retry, started) = shared.try_admit(slot).expect("pre-sign retry is admitted");
        assert!(started);

        let attempts = exact_attempts();
        shared
            .mark_stateful(slot, Arc::clone(&attempts))
            .expect("stateful boundary");
        shared.finish(
            slot,
            Err(PqAttesterServiceError::Context(Arc::new(
                PqLocalAttestationContextError::IngressCapacity,
            ))),
        );
        assert!(matches!(
            retry.wait().await,
            Err(PqAttesterServiceError::Context(error))
                if matches!(*error, PqLocalAttestationContextError::IngressCapacity)
        ));
        assert!(matches!(
            shared.try_admit(slot),
            Err(PqAttesterServiceError::Context(error))
                if matches!(*error, PqLocalAttestationContextError::IngressCapacity)
        ));
        let control = shared.control.lock().expect("state lock");
        let PqAttesterState::CompletedTerminal {
            attempts: Some(retained),
            ..
        } = &control.state
        else {
            panic!("post-stateful failure must retain a terminal attempt")
        };
        assert_eq!(retained.as_ref(), attempts.as_ref());
    }

    #[test]
    fn stateful_attempts_retain_every_validator_target_and_signing_binding() {
        let exact = exact_attempts();
        assert_ne!(exact[0].pubkey, exact[1].pubkey);
        assert_ne!(exact[0].validator_index, exact[1].validator_index);
        assert_eq!(exact[0].target_epoch, exact[0].data.target.epoch);
        assert_eq!(exact[1].target_epoch, exact[1].data.target.epoch);
    }

    #[test]
    fn service_errors_retain_cloneable_typed_causes_and_sources() {
        let context = Arc::new(PqLocalAttestationContextError::IngressCapacity);
        let context_error = PqAttesterServiceError::Context(Arc::clone(&context));
        assert!(context_error.is_pre_sign_retryable());
        assert!(std::error::Error::source(&context_error).is_some());
        let PqAttesterServiceError::Context(cloned_context) = context_error.clone() else {
            panic!("context cause remains typed")
        };
        assert!(Arc::ptr_eq(&context, &cloned_context));

        let planning = PqAttesterServiceError::Planning(Arc::new(
            PqLocalAttestationBatchValidationError::Empty,
        ));
        assert!(std::error::Error::source(&planning).is_some());
        let signing = PqAttesterServiceError::Signing(Arc::new(
            PqLocalAttestationSigningError::TaskUnavailable,
        ));
        assert!(std::error::Error::source(&signing).is_some());
        let proof = PqAttesterServiceError::LocalProof(Arc::new(
            beacon_chain::PqLocalAttestationBatchVerificationError::Capacity {
                count: 3,
                maximum: 2,
            },
        ));
        assert!(std::error::Error::source(&proof).is_some());
    }

    fn controlled_executor() -> (
        TaskExecutor,
        async_channel::Sender<()>,
        futures::channel::mpsc::Receiver<task_executor::ShutdownReason>,
    ) {
        let (exit_sender, exit) = async_channel::bounded(1);
        let (shutdown, shutdown_receiver) = futures::channel::mpsc::channel(4);
        (
            TaskExecutor::new(tokio::runtime::Handle::current(), exit, shutdown),
            exit_sender,
            shutdown_receiver,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn caller_drop_executor_exit_and_close_do_not_cancel_owned_operation() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(9);
        let (receipt, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        let (executor, exit_sender, _shutdown) = controlled_executor();
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        spawn_pq_attester_supervisor(Arc::clone(&shared), &executor, slot, async move {
            let _ = entered_sender.send(());
            let _ = release_receiver.await;
            Ok(PqAttesterOperationSuccess::no_duty(slot))
        })
        .expect("supervisor starts");
        entered_receiver.await.expect("operation entered");
        drop(receipt);
        exit_sender.send(()).await.expect("executor exit");
        let drain_shared = Arc::clone(&shared);
        let drain = tokio::spawn(async move { close_and_drain_pq_attester(&drain_shared).await });
        tokio::task::yield_now().await;
        assert!(
            !drain.is_finished(),
            "close must retain the owned operation"
        );
        release_sender.send(()).expect("release operation");
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("bounded drain")
            .expect("drain task")
            .expect("service drain");
        assert!(matches!(
            shared.try_admit(slot),
            Err(PqAttesterServiceError::Closed)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_stateful_panic_is_terminal_and_signals_process_failure() {
        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(10);
        let (receipt, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        let attempts = exact_attempts();
        shared
            .mark_stateful(slot, Arc::clone(&attempts))
            .expect("stateful boundary");
        let (executor, _exit_sender, mut shutdown) = controlled_executor();
        spawn_pq_attester_supervisor(Arc::clone(&shared), &executor, slot, async move {
            let _ = slot;
            panic!("injected post-stateful panic");
            #[allow(unreachable_code)]
            Ok(PqAttesterOperationSuccess::no_duty(slot))
        })
        .expect("supervisor starts");
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), receipt.wait())
                .await
                .expect("panic receipt resolves"),
            Err(PqAttesterServiceError::TaskPanic)
        ));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), shutdown.next())
                .await
                .expect("failure signal arrives"),
            Some(task_executor::ShutdownReason::Failure(
                "PQ attester task panicked"
            ))
        ));
        assert!(matches!(
            shared.try_admit(slot),
            Err(PqAttesterServiceError::TaskPanic)
        ));
        let control = shared.control.lock().expect("state lock");
        let PqAttesterState::CompletedTerminal {
            attempts: Some(retained),
            ..
        } = &control.state
        else {
            panic!("panic must retain the exact attempted data")
        };
        assert_eq!(retained.as_ref(), attempts.as_ref());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sealed_batch_guards_cannot_be_separated_from_atomic_verified_owner() {
        let (candidates, mut signed, spec, guards) =
            beacon_chain::testing_only_pq_local_candidate_batch_fixture_with_guards(2);
        let PqLocalAttestationSigningPlan::Sign(batch) =
            plan_pq_local_attestations(candidates).expect("two-candidate plan")
        else {
            panic!("two candidates require signing")
        };
        let returned = signed
            .drain(..)
            .enumerate()
            .map(|(index, attestation)| {
                (
                    u64::try_from(index).expect("bounded validator index"),
                    attestation,
                )
            })
            .collect();
        let verified_batch = batch
            .validate_signed(returned, &spec)
            .expect("exact signed batch")
            .into_sealed()
            .testing_only_into_empty_verified_batch();
        assert_eq!(verified_batch.len(), 0);
        let drain = tokio::spawn(async move { guards.close_and_drain().await });
        tokio::task::yield_now().await;
        assert!(
            !drain.is_finished(),
            "the atomic verified batch must retain candidate guards"
        );
        drop(verified_batch);
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("bounded guard drain")
            .expect("guard drain task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chain_atomic_batch_cap_precedes_proof_and_failure_drops_siblings() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_verifier = Arc::clone(&calls);
        assert!(matches!(
            beacon_chain::testing_only_collect_pq_local_batch_atomically(
                vec![0, 1, 2],
                move |_| {
                    calls_in_verifier.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok::<(), ()>(()))
                },
            )
            .await,
            Err(beacon_chain::TestingPqAtomicLocalBatchError::Capacity {
                count: 3,
                maximum: 2,
            })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        struct FakeVerified(Arc<AtomicUsize>);
        impl Drop for FakeVerified {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let dropped_in_verifier = Arc::clone(&dropped);
        let result = beacon_chain::testing_only_collect_pq_local_batch_atomically(
            vec![0, 1],
            move |index| {
                let dropped = Arc::clone(&dropped_in_verifier);
                async move {
                    tokio::task::yield_now().await;
                    if index == 0 {
                        Ok(FakeVerified(dropped))
                    } else {
                        Err("injected sibling failure")
                    }
                }
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(beacon_chain::TestingPqAtomicLocalBatchError::Proof(
                "injected sibling failure"
            ))
        ));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_drops_service_owned_verified_guard_before_waiting_chain_drain() {
        let (candidates, mut signed, spec, guards) =
            beacon_chain::testing_only_pq_local_candidate_batch_fixture_with_guards(1);
        let PqLocalAttestationSigningPlan::Sign(batch) =
            plan_pq_local_attestations(candidates).expect("one-candidate plan")
        else {
            panic!("one candidate requires signing")
        };
        let sealed = batch
            .validate_signed(
                vec![(0, signed.pop().expect("one signed attestation"))],
                &spec,
            )
            .expect("exact signed batch")
            .into_sealed()
            .testing_only_into_empty_verified_batch();

        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(11);
        let (receipt, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        shared
            .mark_stateful(slot, exact_attempts())
            .expect("stateful boundary");
        let metadata = PqVerifiedAttestationBatchMetadata {
            slot,
            members: Arc::from([]),
        };
        shared.finish(
            slot,
            Ok(PqAttesterOperationSuccess {
                completion: PqAttestationCompletion::Verified(metadata.clone()),
                owned: Some(sealed),
            }),
        );
        assert_eq!(
            receipt.wait().await.expect("verified metadata receipt"),
            PqAttestationCompletion::Verified(metadata)
        );

        let chain_drain = tokio::spawn(async move { guards.close_and_drain().await });
        tokio::task::yield_now().await;
        assert!(
            !chain_drain.is_finished(),
            "service-owned batch must retain the original chain guards"
        );
        close_and_drain_pq_attester(&shared)
            .await
            .expect("service close");
        tokio::time::timeout(std::time::Duration::from_secs(1), chain_drain)
            .await
            .expect("chain drain after owned batch drop")
            .expect("chain drain task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_rechecks_verified_owner_published_after_close_begins() {
        let (candidates, mut signed, spec, guards) =
            beacon_chain::testing_only_pq_local_candidate_batch_fixture_with_guards(1);
        let PqLocalAttestationSigningPlan::Sign(batch) =
            plan_pq_local_attestations(candidates).expect("one-candidate plan")
        else {
            panic!("one candidate requires signing")
        };
        let sealed = batch
            .validate_signed(
                vec![(0, signed.pop().expect("one signed attestation"))],
                &spec,
            )
            .expect("exact signed batch")
            .into_sealed()
            .testing_only_into_empty_verified_batch();

        let shared = Arc::new(PqAttesterShared::new());
        let slot = Slot::new(12);
        let (_receipt, started) = shared.try_admit(slot).expect("first admission");
        assert!(started);
        shared
            .mark_stateful(slot, exact_attempts())
            .expect("stateful boundary");
        let close_shared = Arc::clone(&shared);
        let close = tokio::spawn(async move { close_and_drain_pq_attester(&close_shared).await });
        tokio::task::yield_now().await;
        assert!(!close.is_finished(), "close waits for the parked operation");

        let metadata = PqVerifiedAttestationBatchMetadata {
            slot,
            members: Arc::from([]),
        };
        shared.finish(
            slot,
            Ok(PqAttesterOperationSuccess {
                completion: PqAttestationCompletion::Verified(metadata),
                owned: Some(sealed),
            }),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), close)
            .await
            .expect("service close completes")
            .expect("service close task")
            .expect("service close result");

        let chain_drain = tokio::spawn(async move { guards.close_and_drain().await });
        tokio::time::timeout(std::time::Duration::from_millis(100), chain_drain)
            .await
            .expect("close must drop a verified owner published during its wait")
            .expect("chain drain task");
        assert!(matches!(
            shared.try_admit(slot),
            Err(PqAttesterServiceError::Closed)
        ));
    }
}
