use super::{PqBlockBroadcastError, PqBlockBroadcastSender};
use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqBlockImportOutcome, PqBlockImportRequest, PqImportError,
    PqImportLocalError, PqKnownPublishObservation, PqPublishCommitOutcome, PqPublishObservation,
    PqPublishPromotion,
};
use consensus_signature::{PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_RAW_SIGNATURE_LEN};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use types::{ChainSpec, EthSpec, Hash256, SignedBeaconBlock};

pub const PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY: usize = 2;
pub const PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES: usize = 1024 * 1024;
/// A publication body may be split into at most this many transport chunks before it is rejected
/// as a local resource failure. The limit bounds retained chunk objects independently of bytes.
pub const PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY: usize = 4096;
/// The HTTP collector rejects chunk object types larger than this accounting bound.
pub const PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES: usize = 128;
/// Per-admission allowance for the chunk vector and other fixed collection bookkeeping.
pub const PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqPublicationBodyLimits {
    max_ssz_bytes: usize,
    max_json_bytes: usize,
    max_retained_body_bytes: usize,
}

impl PqPublicationBodyLimits {
    pub fn try_from_spec<E: EthSpec>(
        spec: &ChainSpec,
    ) -> Result<Self, PqBlockPublicationConfigurationError> {
        Self::checked::<E>(spec).ok_or(PqBlockPublicationConfigurationError::BodyLimitsOverflow)
    }

    pub fn checked<E: EthSpec>(spec: &ChainSpec) -> Option<Self> {
        let payload_bytes = usize::try_from(spec.max_payload_size).ok()?;
        let attestation_evidence_bytes =
            E::max_attestations_electra().checked_mul(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)?;
        let individual_signature_bytes = 2usize.checked_mul(PQ_RAW_SIGNATURE_LEN)?;
        let max_ssz_bytes = payload_bytes
            .checked_add(attestation_evidence_bytes)?
            .checked_add(individual_signature_bytes)?
            .checked_add(PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES)?;
        let max_json_bytes = max_ssz_bytes
            .checked_mul(2)?
            .checked_add(PQ_PUBLICATION_FIXED_BODY_ALLOWANCE_BYTES)?;
        let raw_chunks_and_decode_copy = max_json_bytes.checked_mul(2)?;
        let chunk_metadata = PQ_BLOCK_PUBLICATION_BODY_CHUNK_CAPACITY
            .checked_mul(PQ_BLOCK_PUBLICATION_BODY_CHUNK_METADATA_BYTES)?;
        let retained_per_admission = raw_chunks_and_decode_copy
            .checked_add(chunk_metadata)?
            .checked_add(PQ_BLOCK_PUBLICATION_RETAINED_BODY_FIXED_BYTES)?;
        let max_retained_body_bytes =
            retained_per_admission.checked_mul(PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY)?;
        Some(Self {
            max_ssz_bytes,
            max_json_bytes,
            max_retained_body_bytes,
        })
    }

    pub const fn max_ssz_bytes(self) -> usize {
        self.max_ssz_bytes
    }

    pub const fn max_json_bytes(self) -> usize {
        self.max_json_bytes
    }

    pub const fn max_retained_body_bytes(self) -> usize {
        self.max_retained_body_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBlockPublicationConfigurationError {
    BodyLimitsOverflow,
}

impl PqBlockPublicationConfigurationError {
    pub const fn is_retryable(self) -> bool {
        false
    }
}

impl std::fmt::Display for PqBlockPublicationConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyLimitsOverflow => {
                formatter.write_str("PQ publication body-limit arithmetic overflowed")
            }
        }
    }
}

impl std::error::Error for PqBlockPublicationConfigurationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPublicationCapacity {
    Admission,
    Observation,
    Broadcast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBlockPublicationTerminal {
    Rejected,
    Stale,
}

#[derive(Debug)]
pub enum PqBlockPublicationLocalError {
    Import(PqImportError),
    Broadcast(PqBlockBroadcastError),
    TaskUnavailable,
}

impl std::fmt::Display for PqBlockPublicationLocalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Import(error) => error.fmt(formatter),
            Self::Broadcast(error) => error.fmt(formatter),
            Self::TaskUnavailable => {
                formatter.write_str("PQ block publication task is unavailable")
            }
        }
    }
}

impl std::error::Error for PqBlockPublicationLocalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Import(error) => Some(error),
            Self::Broadcast(error) => Some(error),
            Self::TaskUnavailable => None,
        }
    }
}

#[derive(Debug)]
pub enum PqBlockPublicationDisposition {
    Published(PqBlockImportOutcome),
    Committed,
    Pending,
    Terminal(PqBlockPublicationTerminal),
    Equivocation { previous: Hash256 },
    Capacity(PqPublicationCapacity),
    Invalid(PqImportError),
    Local(PqBlockPublicationLocalError),
}

/// Process-owned local publication boundary. The broadcaster and executor are fixed at startup,
/// never selected by an individual request.
pub struct PqBlockPublicationService<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    task_executor: TaskExecutor,
    broadcaster: PqBlockBroadcastSender<T::EthSpec>,
    admission: Arc<Semaphore>,
    body_limits: PqPublicationBodyLimits,
}

impl<T: BeaconChainTypes> PqBlockPublicationService<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        task_executor: TaskExecutor,
        broadcaster: PqBlockBroadcastSender<T::EthSpec>,
    ) -> Result<Self, PqBlockPublicationConfigurationError> {
        let body_limits = PqPublicationBodyLimits::try_from_spec::<T::EthSpec>(&chain.spec)?;
        Ok(Self {
            chain,
            task_executor,
            broadcaster,
            admission: Arc::new(Semaphore::new(PQ_BLOCK_PUBLICATION_ADMISSION_CAPACITY)),
            body_limits,
        })
    }

    pub const fn body_limits(&self) -> PqPublicationBodyLimits {
        self.body_limits
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_available_admission_permits(&self) -> usize {
        self.admission.available_permits()
    }

    pub fn try_admit(
        self: &Arc<Self>,
    ) -> Result<PqBlockPublicationAdmission<T>, PqPublicationCapacity> {
        let permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| PqPublicationCapacity::Admission)?;
        Ok(PqBlockPublicationAdmission {
            service: Arc::clone(self),
            permit,
        })
    }

    async fn publish_owned(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> PqBlockPublicationDisposition {
        match self.chain.known_pq_publish_observation(&block) {
            Some(PqKnownPublishObservation::Pending) => {
                return PqBlockPublicationDisposition::Pending;
            }
            Some(PqKnownPublishObservation::Committed) => {
                return PqBlockPublicationDisposition::Committed;
            }
            Some(PqKnownPublishObservation::Terminal) => {
                return PqBlockPublicationDisposition::Terminal(
                    PqBlockPublicationTerminal::Rejected,
                );
            }
            None => {}
        }
        let verified = match self
            .chain
            .verify_pq_block(PqBlockImportRequest::publish(block))
            .await
        {
            Ok(verified) => verified,
            Err(error) => return classify_import_error(error),
        };
        match self.chain.observe_verified_pq_publish_block(verified) {
            PqPublishObservation::New(token) => {
                let block = match token.block() {
                    Ok(block) => Arc::clone(block),
                    Err(error) => return classify_import_error(error),
                };
                let acknowledgement = match self.broadcaster.try_send(block) {
                    Ok(acknowledgement) => acknowledgement,
                    Err(error) => return classify_broadcast_error(error),
                };
                if let Err(error) = acknowledgement.wait().await {
                    return classify_broadcast_error(error);
                }
                let promotion = match token.after_propagation() {
                    Ok(promotion) => promotion,
                    Err(error) => return classify_import_error(error),
                };
                match promotion {
                    PqPublishPromotion::Commit(commit) => match commit.commit().await {
                        Ok(PqPublishCommitOutcome::Imported(outcome)) => {
                            PqBlockPublicationDisposition::Published(outcome)
                        }
                        Ok(PqPublishCommitOutcome::Committed) => {
                            PqBlockPublicationDisposition::Committed
                        }
                        Err(error) => classify_import_error(error),
                    },
                    PqPublishPromotion::Committed => PqBlockPublicationDisposition::Committed,
                    PqPublishPromotion::Pending => PqBlockPublicationDisposition::Pending,
                    PqPublishPromotion::Terminal => PqBlockPublicationDisposition::Terminal(
                        PqBlockPublicationTerminal::Rejected,
                    ),
                    PqPublishPromotion::Equivocation { previous } => {
                        PqBlockPublicationDisposition::Equivocation { previous }
                    }
                    PqPublishPromotion::Stale => {
                        PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Stale)
                    }
                }
            }
            PqPublishObservation::Retry(commit) => match commit.commit().await {
                Ok(PqPublishCommitOutcome::Imported(outcome)) => {
                    PqBlockPublicationDisposition::Published(outcome)
                }
                Ok(PqPublishCommitOutcome::Committed) => PqBlockPublicationDisposition::Committed,
                Err(error) => classify_import_error(error),
            },
            PqPublishObservation::Pending => PqBlockPublicationDisposition::Pending,
            PqPublishObservation::Committed => PqBlockPublicationDisposition::Committed,
            PqPublishObservation::Terminal => {
                PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Rejected)
            }
            PqPublishObservation::Equivocation { previous } => {
                PqBlockPublicationDisposition::Equivocation { previous }
            }
            PqPublishObservation::Capacity => {
                PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Observation)
            }
            PqPublishObservation::NotPublish => {
                PqBlockPublicationDisposition::Local(PqBlockPublicationLocalError::Import(
                    PqImportError::Local(PqImportLocalError::Invariant(
                        "PQ publication verifier returned a non-publication capability",
                    )),
                ))
            }
        }
    }
}

/// Non-forgeable pre-buffer admission. Dropping it before publication immediately releases the
/// retained-body slot; once `publish` starts, the detached process task owns it to completion.
pub struct PqBlockPublicationAdmission<T: BeaconChainTypes> {
    service: Arc<PqBlockPublicationService<T>>,
    permit: OwnedSemaphorePermit,
}

impl<T: BeaconChainTypes> PqBlockPublicationAdmission<T> {
    pub async fn publish(
        self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> PqBlockPublicationDisposition {
        let executor = self.service.task_executor.clone();
        let service = Arc::clone(&self.service);
        let task = executor.spawn_handle(
            async move {
                let _permit = self.permit;
                service.publish_owned(block).await
            },
            "pq-block-publication",
        );
        let Some(task) = task else {
            return PqBlockPublicationDisposition::Local(
                PqBlockPublicationLocalError::TaskUnavailable,
            );
        };
        match task.await {
            Ok(Some(disposition)) => disposition,
            Ok(None) | Err(_) => {
                PqBlockPublicationDisposition::Local(PqBlockPublicationLocalError::TaskUnavailable)
            }
        }
    }
}

fn classify_broadcast_error(error: PqBlockBroadcastError) -> PqBlockPublicationDisposition {
    match error {
        PqBlockBroadcastError::Capacity => {
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Broadcast)
        }
        PqBlockBroadcastError::WorkerUnavailable | PqBlockBroadcastError::Rejected => {
            PqBlockPublicationDisposition::Local(PqBlockPublicationLocalError::Broadcast(error))
        }
    }
}

fn classify_import_error(error: PqImportError) -> PqBlockPublicationDisposition {
    match error {
        PqImportError::PeerInvalid(_) => PqBlockPublicationDisposition::Invalid(error),
        PqImportError::ExecutionRejected(_)
        | PqImportError::ExecutionReconciliation(_)
        | PqImportError::DurableStateUnknown { .. }
        | PqImportError::TerminalObservation { .. } => {
            PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Rejected)
        }
        PqImportError::StaleHeadAfterVerification { .. } => {
            PqBlockPublicationDisposition::Terminal(PqBlockPublicationTerminal::Stale)
        }
        PqImportError::Local(PqImportLocalError::ObservationCapacity) => {
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Observation)
        }
        PqImportError::Local(PqImportLocalError::IngressCapacity) => {
            PqBlockPublicationDisposition::Capacity(PqPublicationCapacity::Admission)
        }
        PqImportError::Local(_) => {
            PqBlockPublicationDisposition::Local(PqBlockPublicationLocalError::Import(error))
        }
    }
}
