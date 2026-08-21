//! Private direct local attester service for the bounded PQ devnet profile.

#![cfg_attr(not(feature = "pq-devnet"), allow(dead_code))]

#[cfg(feature = "pq-devnet")]
use beacon_chain::{
    PqLocalAttestationBatchSealError, PqOwnedLocalAttestationCandidateBatch,
    PqSealedLocalAttestationBatch,
};
#[cfg(feature = "pq-devnet")]
use futures::StreamExt;
#[cfg(feature = "pq-devnet")]
use lighthouse_validator_store::LighthouseValidatorStore;
#[cfg(feature = "pq-devnet")]
use slot_clock::SlotClock;
#[cfg(feature = "pq-devnet")]
use std::collections::HashSet;
#[cfg(feature = "pq-devnet")]
use std::future::Future;
#[cfg(feature = "pq-devnet")]
use std::sync::Arc;
#[cfg(feature = "pq-devnet")]
use task_executor::TaskExecutor;
#[cfg(feature = "pq-devnet")]
use types::{Attestation, ChainSpec, EthSpec};
#[cfg(feature = "pq-devnet")]
use validator_store::{AttestationToSign, ValidatorStore};

#[cfg(feature = "pq-devnet")]
pub const PQ_LOCAL_ATTESTATION_SIGNING_BATCH_CAPACITY: usize = 16;

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
