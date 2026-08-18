//! Owned, operation-level aggregation jobs shared by consensus signature backends.
//!
//! Consensus callers retain participant bits. This module validates and aggregates only the
//! cryptographic evidence; callers must commit the returned evidence and their bits atomically.
//!
//! Cancellation caused by dropping an aggregation future is intentionally silent: there is no
//! receiver left to observe a result.
//!
//! ```compile_fail
//! use consensus_signature::AggregationError;
//!
//! let _ = AggregationError::Cancelled;
//! ```

use crate::{OneTimeUseId, SameMessageEvidence, ValidatorPublicKeyBytes};

/// Runtime signer cap for the experimental V1 aggregation service.
pub const V1_MAX_AGGREGATION_SIGNERS: usize = 16;
/// Runtime contribution cap for the experimental V1 aggregation service.
pub const V1_MAX_AGGREGATION_CONTRIBUTIONS: usize = 16;
/// Maximum total encoded input accepted by one V1 aggregation job.
pub const V1_MAX_AGGREGATION_INPUT_BYTES: usize = 8 * 1024 * 1024;

#[cfg(not(feature = "pq-wire"))]
pub const V1_MAX_AGGREGATION_OUTPUT_BYTES: usize = 96;
#[cfg(feature = "pq-wire")]
pub const V1_MAX_AGGREGATION_OUTPUT_BYTES: usize = crate::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN;

/// The common statement authenticated by every contribution in an aggregation job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SameMessageClaim {
    pub signing_root: [u8; 32],
    pub one_time_use_id: OneTimeUseId,
}

impl SameMessageClaim {
    pub const fn new(signing_root: [u8; 32], one_time_use_id: OneTimeUseId) -> Self {
        Self {
            signing_root,
            one_time_use_id,
        }
    }
}

/// One validator participating in an aggregation job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregationSigner {
    pub validator_index: u64,
    pub public_key: ValidatorPublicKeyBytes,
}

/// One already-produced raw or aggregate signature and its exact signer set.
#[derive(Clone, PartialEq)]
pub struct AggregationContribution {
    pub signers: Vec<AggregationSigner>,
    pub evidence: SameMessageEvidence,
}

/// A complete, owned request to aggregate signatures over one claim.
pub struct AggregationJob {
    pub claim: SameMessageClaim,
    pub expected_signers: Vec<AggregationSigner>,
    pub contributions: Vec<AggregationContribution>,
}

/// A structural caller error. These errors are never peer-attributable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidAggregationJob {
    EmptySignerSet,
    EmptyContributions,
    EmptyContributionSignerSet,
    NonCanonicalValidatorOrder,
    DuplicateValidatorIndex,
    DuplicatePublicKey,
    ContributionOverlap,
    SignerUnionMismatch,
    InvalidPublicKey,
    VerificationRequiresSingleContribution { actual: usize },
}

/// Semantic admission class for contextual signature verification.
///
/// Local recursive proving has no public class: callers must use [`AggregationService::aggregate`]
/// and therefore cannot promote proving work into a verification queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationClass {
    /// Signature evidence required while verifying or importing a block.
    Block,
    /// Signature evidence received through attestation gossip.
    Gossip,
}

/// The local resource limit exceeded by an aggregation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationResource {
    TooManySigners { actual: usize, max: usize },
    TooManyContributions { actual: usize, max: usize },
    TooManyContributionSigners { actual: usize, max: usize },
    InputTooLarge { actual: usize, max: usize },
    QueueSaturated { max_queued: usize },
}

/// Failure classes exposed by the operation-level aggregation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregationError {
    /// Supplied evidence does not authenticate its declared claim and exact signer set.
    InvalidEvidence,
    /// The locally constructed job is structurally invalid.
    InvalidJob(InvalidAggregationJob),
    /// A configured admission limit rejected the job before backend work.
    ResourceExhausted(AggregationResource),
    /// The selected backend is not available in this process or build.
    Unavailable,
    /// The owned backend worker stopped before returning a result.
    WorkerStopped,
    /// The backend panicked and permanently poisoned its process-wide worker state.
    WorkerPanicked,
    /// Locally produced evidence exceeded the configured output cap.
    OutputTooLarge { actual: usize, max: usize },
    /// An unexpected local backend failure.
    Internal,
}

impl std::fmt::Display for AggregationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence => formatter.write_str("invalid aggregation evidence"),
            Self::InvalidJob(error) => write!(formatter, "invalid aggregation job: {error:?}"),
            Self::ResourceExhausted(error) => {
                write!(formatter, "aggregation resources exhausted: {error:?}")
            }
            Self::Unavailable => formatter.write_str("aggregation service unavailable"),
            Self::WorkerStopped => formatter.write_str("aggregation worker stopped"),
            Self::WorkerPanicked => formatter.write_str("aggregation worker panicked"),
            Self::OutputTooLarge { actual, max } => {
                write!(
                    formatter,
                    "aggregation output length {actual} exceeds maximum {max}"
                )
            }
            Self::Internal => formatter.write_str("internal aggregation failure"),
        }
    }
}

impl std::error::Error for AggregationError {}

/// Returns whether evidence uses the active backend's cheap individual/promotable representation.
///
/// This is a framing check only. Submit a one-contribution [`AggregationJob`] to authenticate the
/// evidence against its exact claim and signer.
pub fn is_individual_same_message_evidence(evidence: &SameMessageEvidence) -> bool {
    #[cfg(not(feature = "pq-wire"))]
    {
        !evidence.is_empty()
    }
    #[cfg(feature = "pq-devnet")]
    {
        crate::PqRawSignature::from_bytes(evidence.as_bytes()).is_ok()
    }
}

/// Backend-selected owner for operation-level aggregation.
#[cfg(not(feature = "pq-devnet"))]
pub struct AggregationService;

/// Backend-selected owner for operation-level aggregation.
#[cfg(feature = "pq-devnet")]
pub struct AggregationService {
    prover: crate::pq::PqProver,
}

impl AggregationService {
    /// Initializes the selected aggregation backend.
    pub fn new() -> Result<Self, AggregationError> {
        #[cfg(not(feature = "pq-devnet"))]
        {
            Ok(Self)
        }
        #[cfg(feature = "pq-devnet")]
        {
            crate::pq::PqProver::new()
                .map(|prover| Self { prover })
                .map_err(|_| AggregationError::Unavailable)
        }
    }

    /// Validates and executes one owned job without blocking an async caller on PQ proof work.
    pub async fn aggregate(
        &self,
        job: AggregationJob,
    ) -> Result<SameMessageEvidence, AggregationError> {
        let job = ValidatedAggregationJob::new(job)?;
        #[cfg(not(feature = "pq-devnet"))]
        {
            crate::bls::aggregate_job(job)
        }
        #[cfg(feature = "pq-devnet")]
        {
            self.prover.aggregate_job(job).await
        }
    }

    /// Contextually verifies exactly one raw or already-aggregated contribution.
    ///
    /// PQ builds use the semantic class for reserved admission. BLS builds execute immediately;
    /// both backends enforce the same verification-only job shape.
    pub async fn verify(
        &self,
        class: VerificationClass,
        job: AggregationJob,
    ) -> Result<SameMessageEvidence, AggregationError> {
        let job = ValidatedAggregationJob::new_verification(job)?;
        #[cfg(not(feature = "pq-devnet"))]
        {
            let _ = class;
            crate::bls::aggregate_job(job)
        }
        #[cfg(feature = "pq-devnet")]
        {
            self.prover.verify_job(class, job).await
        }
    }
}

pub(crate) struct ValidatedAggregationJob {
    pub(crate) claim: SameMessageClaim,
    pub(crate) expected_signers: Vec<AggregationSigner>,
    pub(crate) contributions: Vec<AggregationContribution>,
    pub(crate) queued_evidence_bytes: usize,
}

impl ValidatedAggregationJob {
    fn new(job: AggregationJob) -> Result<Self, AggregationError> {
        let queued_evidence_bytes = validate_limits(&job)?;
        validate_signer_list(&job.expected_signers, false)?;

        let mut seen_expected = vec![false; job.expected_signers.len()];
        for contribution in &job.contributions {
            if contribution.signers.is_empty() {
                return Err(AggregationError::InvalidJob(
                    InvalidAggregationJob::EmptyContributionSignerSet,
                ));
            }
            validate_signer_list(&contribution.signers, true)?;
            for signer in &contribution.signers {
                let expected_position = job
                    .expected_signers
                    .iter()
                    .position(|expected| expected.validator_index == signer.validator_index)
                    .ok_or(AggregationError::InvalidJob(
                        InvalidAggregationJob::SignerUnionMismatch,
                    ))?;
                let expected_signer = job.expected_signers.get(expected_position).ok_or(
                    AggregationError::InvalidJob(InvalidAggregationJob::SignerUnionMismatch),
                )?;
                if expected_signer.public_key != signer.public_key {
                    return Err(AggregationError::InvalidJob(
                        InvalidAggregationJob::SignerUnionMismatch,
                    ));
                }
                let seen = seen_expected.get_mut(expected_position).ok_or(
                    AggregationError::InvalidJob(InvalidAggregationJob::SignerUnionMismatch),
                )?;
                if *seen {
                    return Err(AggregationError::InvalidJob(
                        InvalidAggregationJob::ContributionOverlap,
                    ));
                }
                *seen = true;
            }
        }
        if seen_expected.iter().any(|seen| !seen) {
            return Err(AggregationError::InvalidJob(
                InvalidAggregationJob::SignerUnionMismatch,
            ));
        }

        Ok(Self {
            claim: job.claim,
            expected_signers: job.expected_signers,
            contributions: job.contributions,
            queued_evidence_bytes,
        })
    }

    fn new_verification(job: AggregationJob) -> Result<Self, AggregationError> {
        let actual = job.contributions.len();
        if actual != 1 {
            return Err(AggregationError::InvalidJob(
                InvalidAggregationJob::VerificationRequiresSingleContribution { actual },
            ));
        }
        Self::new(job)
    }
}

fn validate_limits(job: &AggregationJob) -> Result<usize, AggregationError> {
    if job.expected_signers.len() > V1_MAX_AGGREGATION_SIGNERS {
        return Err(AggregationError::ResourceExhausted(
            AggregationResource::TooManySigners {
                actual: job.expected_signers.len(),
                max: V1_MAX_AGGREGATION_SIGNERS,
            },
        ));
    }
    if job.contributions.len() > V1_MAX_AGGREGATION_CONTRIBUTIONS {
        return Err(AggregationError::ResourceExhausted(
            AggregationResource::TooManyContributions {
                actual: job.contributions.len(),
                max: V1_MAX_AGGREGATION_CONTRIBUTIONS,
            },
        ));
    }
    let contribution_signers = job
        .contributions
        .iter()
        .map(|contribution| contribution.signers.len())
        .try_fold(0usize, usize::checked_add)
        .ok_or(AggregationError::ResourceExhausted(
            AggregationResource::TooManyContributionSigners {
                actual: usize::MAX,
                max: V1_MAX_AGGREGATION_SIGNERS,
            },
        ))?;
    if contribution_signers > V1_MAX_AGGREGATION_SIGNERS {
        return Err(AggregationError::ResourceExhausted(
            AggregationResource::TooManyContributionSigners {
                actual: contribution_signers,
                max: V1_MAX_AGGREGATION_SIGNERS,
            },
        ));
    }
    let queued_evidence_bytes = validate_total_input_bytes(
        job.contributions
            .iter()
            .map(|contribution| evidence_len(&contribution.evidence)),
    )?;
    if job.expected_signers.is_empty() {
        return Err(AggregationError::InvalidJob(
            InvalidAggregationJob::EmptySignerSet,
        ));
    }
    if job.contributions.is_empty() {
        return Err(AggregationError::InvalidJob(
            InvalidAggregationJob::EmptyContributions,
        ));
    }
    Ok(queued_evidence_bytes)
}

fn validate_total_input_bytes(
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, AggregationError> {
    let total_input_bytes = lengths
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(AggregationError::ResourceExhausted(
            AggregationResource::InputTooLarge {
                actual: usize::MAX,
                max: V1_MAX_AGGREGATION_INPUT_BYTES,
            },
        ))?;
    if total_input_bytes > V1_MAX_AGGREGATION_INPUT_BYTES {
        return Err(AggregationError::ResourceExhausted(
            AggregationResource::InputTooLarge {
                actual: total_input_bytes,
                max: V1_MAX_AGGREGATION_INPUT_BYTES,
            },
        ));
    }
    Ok(total_input_bytes)
}

fn validate_signer_list(
    signers: &[AggregationSigner],
    contribution: bool,
) -> Result<(), AggregationError> {
    for pair in signers.windows(2) {
        let [first, second] = pair else {
            continue;
        };
        if first.validator_index == second.validator_index {
            return Err(AggregationError::InvalidJob(
                InvalidAggregationJob::DuplicateValidatorIndex,
            ));
        }
        if first.validator_index > second.validator_index {
            return Err(AggregationError::InvalidJob(
                InvalidAggregationJob::NonCanonicalValidatorOrder,
            ));
        }
    }
    for (position, signer) in signers.iter().enumerate() {
        if signers
            .iter()
            .skip(position.saturating_add(1))
            .any(|other| signer.public_key == other.public_key)
        {
            return Err(AggregationError::InvalidJob(if contribution {
                InvalidAggregationJob::ContributionOverlap
            } else {
                InvalidAggregationJob::DuplicatePublicKey
            }));
        }
    }
    Ok(())
}

#[cfg(not(feature = "pq-wire"))]
fn evidence_len(_evidence: &SameMessageEvidence) -> usize {
    96
}

#[cfg(feature = "pq-wire")]
fn evidence_len(evidence: &SameMessageEvidence) -> usize {
    evidence.as_bytes().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_input_cap_is_checked_without_allocating_payloads() {
        assert_eq!(
            validate_total_input_bytes([V1_MAX_AGGREGATION_INPUT_BYTES]),
            Ok(V1_MAX_AGGREGATION_INPUT_BYTES)
        );
        assert_eq!(
            validate_total_input_bytes([V1_MAX_AGGREGATION_INPUT_BYTES, 1]),
            Err(AggregationError::ResourceExhausted(
                AggregationResource::InputTooLarge {
                    actual: V1_MAX_AGGREGATION_INPUT_BYTES + 1,
                    max: V1_MAX_AGGREGATION_INPUT_BYTES,
                }
            ))
        );
    }

    #[cfg(feature = "pq-devnet")]
    #[test]
    fn pq_uses_the_same_index_mapping_overlap_and_union_contract() {
        use crate::pq::{PqSigningClaim, PqUnreservedSigningKey};
        use crate::{PqSameMessageEvidence, SigningDuty};

        let one_time_use_id = OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation)
            .expect("slot zero is supported");
        let claim = SameMessageClaim::new([0x42; 32], one_time_use_id);
        let pq_claim = PqSigningClaim::new(claim.signing_root, one_time_use_id);
        let first_key =
            PqUnreservedSigningKey::from_seed([0x61; 32], one_time_use_id..=one_time_use_id)
                .expect("first key");
        let second_key =
            PqUnreservedSigningKey::from_seed([0x62; 32], one_time_use_id..=one_time_use_id)
                .expect("second key");
        let first = AggregationSigner {
            validator_index: 4,
            public_key: first_key.public_key(),
        };
        let second = AggregationSigner {
            validator_index: 9,
            public_key: second_key.public_key(),
        };
        let first_evidence =
            PqSameMessageEvidence::from(&first_key.sign(&pq_claim).expect("first signature"));
        let second_evidence =
            PqSameMessageEvidence::from(&second_key.sign(&pq_claim).expect("second signature"));

        ValidatedAggregationJob::new(AggregationJob {
            claim,
            expected_signers: vec![first.clone(), second.clone()],
            contributions: vec![
                AggregationContribution {
                    signers: vec![first.clone()],
                    evidence: first_evidence.clone(),
                },
                AggregationContribution {
                    signers: vec![second.clone()],
                    evidence: second_evidence.clone(),
                },
            ],
        })
        .expect("validator-index order need not match key-byte order");

        let invalid_jobs = [
            AggregationJob {
                claim,
                expected_signers: vec![second.clone(), first.clone()],
                contributions: vec![AggregationContribution {
                    signers: vec![second.clone(), first.clone()],
                    evidence: first_evidence.clone(),
                }],
            },
            AggregationJob {
                claim,
                expected_signers: vec![first.clone(), first.clone()],
                contributions: vec![AggregationContribution {
                    signers: vec![first.clone()],
                    evidence: first_evidence.clone(),
                }],
            },
            AggregationJob {
                claim,
                expected_signers: vec![first.clone(), second.clone()],
                contributions: vec![
                    AggregationContribution {
                        signers: vec![first.clone()],
                        evidence: first_evidence.clone(),
                    },
                    AggregationContribution {
                        signers: vec![first.clone()],
                        evidence: first_evidence.clone(),
                    },
                ],
            },
            AggregationJob {
                claim,
                expected_signers: vec![first.clone(), second],
                contributions: vec![AggregationContribution {
                    signers: vec![first],
                    evidence: second_evidence,
                }],
            },
        ];
        for job in invalid_jobs {
            assert!(matches!(
                ValidatedAggregationJob::new(job),
                Err(AggregationError::InvalidJob(_))
            ));
        }
    }
}
