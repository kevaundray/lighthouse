//! Narrow import and execution boundary for the experimental leanMultisig backend.
//!
//! The pinned prover requires an AVX2-only x86-64 build. Host capability must be checked by the
//! launcher before starting that binary: a globally AVX2-compiled binary cannot safely discover
//! an incompatible CPU after process startup. Scalar builds retain this module for workspace
//! compatibility, but [`PqProver::new`] refuses to create a working prover.
//!
//! Stateful signing is deliberately not a public primitive:
//!
//! ```compile_fail
//! use consensus_signature::pq::PqUnreservedSigningKey;
//! ```
//!
//! Recursive prover ownership is also crate-private so downstream code cannot reserve the
//! process singleton outside [`crate::AggregationService`]:
//!
//! ```compile_fail
//! use consensus_signature::pq::PqProver;
//! let _prover = PqProver::new();
//! ```
//!
//! The operation-level service also hides the superseded backend-specific aggregate wrapper:
//!
//! ```compile_fail
//! use consensus_signature::pq::PqAggregateSignature;
//! ```
//!
//! Backend-specific aggregation errors are likewise not part of the downstream contract:
//!
//! ```compile_fail
//! use consensus_signature::pq::AggregateError;
//! ```
//!
//! Worker lifecycle details stay behind [`crate::AggregationService`]:
//!
//! ```compile_fail
//! use consensus_signature::pq::ProverUnavailable;
//! ```

mod backend;
pub use crate::{
    PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_PUBLIC_KEY_LEN, PQ_RAW_SIGNATURE_LEN, PqPublicKey,
    PqRawSignature, PqSameMessageEvidence, PqWireError,
};

use crate::OneTimeUseId;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use crate::aggregation::AggregationResource;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use crate::aggregation::InvalidAggregationJob;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use crate::aggregation::V1_MAX_AGGREGATION_OUTPUT_BYTES;
use crate::aggregation::{AggregationError, ValidatedAggregationJob, VerificationClass};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use crate::pq_wire::PQ_EVIDENCE_HEADER_LEN;
#[cfg(test)]
use backend::BackendSigningKey;
#[cfg(test)]
use std::ops::RangeInclusive;

/// Frozen signer/contribution cap for the Lean PQ devnet V1 profile.
pub const PQ_MAX_SIGNERS: usize = 32_768;

/// A PQ signing statement bound to a semantic one-time-use identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqSigningClaim {
    signing_root: [u8; 32],
    one_time_use_id: OneTimeUseId,
}

impl PqSigningClaim {
    pub const fn new(signing_root: [u8; 32], one_time_use_id: OneTimeUseId) -> Self {
        Self {
            signing_root,
            one_time_use_id,
        }
    }

    pub const fn signing_root(&self) -> &[u8; 32] {
        &self.signing_root
    }

    pub const fn one_time_use_id(&self) -> OneTimeUseId {
        self.one_time_use_id
    }
}

/// A low-level live-key handle that does not reserve one-time-use identifiers.
///
/// This primitive exists for provisioning, tests, and the journal-owning signing authority that
/// will be added in Task 3.3. Production validator code must not expose it directly: callers must
/// durably reserve `(public_key, one_time_use_id, signing_root)` before calling [`Self::sign`].
#[derive(Debug)]
#[cfg(test)]
pub(crate) struct PqUnreservedSigningKey {
    backend: BackendSigningKey,
    one_time_use_range: RangeInclusive<u32>,
}

#[cfg(test)]
impl PqUnreservedSigningKey {
    pub(crate) fn from_seed(
        seed: [u8; 32],
        one_time_use_range: RangeInclusive<OneTimeUseId>,
    ) -> Result<Self, PqKeyError> {
        let start = one_time_use_range.start().as_u32();
        let end = one_time_use_range.end().as_u32();
        backend::signing_key_from_seed(seed, start..=end)
            .map(|backend| Self {
                backend,
                one_time_use_range: start..=end,
            })
            .map_err(PqKeyError::from_backend)
    }

    pub(crate) fn public_key(&self) -> PqPublicKey {
        PqPublicKey::from_backend_bytes(backend::public_key(&self.backend))
    }

    pub(crate) fn sign(&self, claim: &PqSigningClaim) -> Result<PqRawSignature, PqSignError> {
        if !self
            .one_time_use_range
            .contains(&claim.one_time_use_id().as_u32())
        {
            return Err(PqSignError::InvalidSigningRequest);
        }
        let payload = backend::sign_raw(&self.backend, claim).map_err(PqSignError::from_backend)?;
        Ok(PqRawSignature::from_backend_payload(payload))
    }
}

/// Failure to construct a PQ signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum PqKeyError {
    InvalidRange,
    Internal,
}

#[cfg(test)]
impl std::fmt::Display for PqKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRange => formatter.write_str("invalid PQ one-time-use range"),
            Self::Internal => formatter.write_str("internal PQ key construction failure"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for PqKeyError {}

#[cfg(test)]
impl PqKeyError {
    fn from_backend(error: lean_multisig::Error) -> Self {
        match error {
            lean_multisig::Error::KeyGen(_) => Self::InvalidRange,
            _ => Self::Internal,
        }
    }
}

/// Failure to produce one raw signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum PqSignError {
    InvalidSigningRequest,
    Internal,
}

#[cfg(test)]
impl std::fmt::Display for PqSignError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSigningRequest => formatter.write_str("invalid PQ signing request"),
            Self::Internal => formatter.write_str("internal PQ signing failure"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for PqSignError {}

#[cfg(test)]
impl PqSignError {
    fn from_backend(_error: lean_multisig::Error) -> Self {
        Self::Internal
    }
}

/// Failure to verify peer-supplied raw PQ evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqVerifyError {
    InvalidEvidence,
    InvalidRequest(PqVerifyRequestError),
    Internal,
}

/// A backend-independent invalid aggregate-verification request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqVerifyRequestError {
    EmptySignerSet,
    TooManySigners { actual: usize, max: usize },
    DuplicateSigner,
    NonCanonicalSignerOrder,
}

impl std::fmt::Display for PqVerifyRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySignerSet => formatter.write_str("no PQ signers supplied"),
            Self::TooManySigners { actual, max } => {
                write!(formatter, "too many PQ signers: {actual}, maximum {max}")
            }
            Self::DuplicateSigner => formatter.write_str("duplicate PQ signer"),
            Self::NonCanonicalSignerOrder => {
                formatter.write_str("PQ signers are not in canonical public-key order")
            }
        }
    }
}

impl std::error::Error for PqVerifyRequestError {}

impl PqVerifyError {
    fn from_backend(error: lean_multisig::Error) -> Self {
        match error {
            lean_multisig::Error::InvalidSignature { .. }
            | lean_multisig::Error::MalformedSignature
            | lean_multisig::Error::MessageMismatch
            | lean_multisig::Error::SignerSetMismatch => Self::InvalidEvidence,
            _ => Self::Internal,
        }
    }

    fn from_aggregate_backend(error: lean_multisig::Error) -> Self {
        match error {
            lean_multisig::Error::InvalidSignature { .. }
            | lean_multisig::Error::Proof(_)
            | lean_multisig::Error::MalformedSignature
            | lean_multisig::Error::MessageMismatch
            | lean_multisig::Error::SignerSetMismatch => Self::InvalidEvidence,
            // Public keys and the request structure are locally resolved. Unknown variants from
            // the non-exhaustive upstream error remain local rather than becoming peer blame.
            _ => Self::Internal,
        }
    }
}

impl std::fmt::Display for PqVerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence => formatter.write_str("invalid PQ signing evidence"),
            Self::InvalidRequest(error) => write!(formatter, "invalid PQ verify request: {error}"),
            Self::Internal => formatter.write_str("internal PQ verification failure"),
        }
    }
}

impl std::error::Error for PqVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::InvalidEvidence | Self::Internal => None,
        }
    }
}

/// Verifies one strict raw signature without initializing recursive-proof resources.
pub fn verify_raw(
    signature: &PqRawSignature,
    public_key: &PqPublicKey,
    claim: &PqSigningClaim,
) -> Result<(), PqVerifyError> {
    backend::verify_raw(
        signature.backend_payload(),
        public_key.backend_bytes(),
        claim,
    )
    .map_err(PqVerifyError::from_backend)
}

/// Contextually decodes and verifies bounded aggregate evidence.
///
/// `public_keys` must be the exact expected signer set in strictly ascending canonical byte
/// order. The outer size and signer-count bounds are checked before collecting backend keys or
/// invoking backend parsing/setup.
pub fn verify_aggregate_evidence(
    evidence: &PqSameMessageEvidence,
    public_keys: &[PqPublicKey],
    claim: &PqSigningClaim,
) -> Result<(), PqVerifyError> {
    if evidence.as_bytes().len() > PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN {
        return Err(PqVerifyError::InvalidEvidence);
    }
    validate_aggregate_signer_count(public_keys.len())?;
    validate_canonical_signer_order(public_keys)?;
    let envelope = evidence
        .backend_aggregate_envelope()
        .map_err(|_| PqVerifyError::InvalidEvidence)?;
    let backend_public_keys = public_keys
        .iter()
        .map(PqPublicKey::backend_bytes)
        .collect::<Vec<_>>();
    let signature = backend::decode_aggregate_signature(envelope, &backend_public_keys, claim)
        .map_err(PqVerifyError::from_aggregate_backend)?;
    backend::verify_signature(&signature, &backend_public_keys, claim)
        .map_err(PqVerifyError::from_aggregate_backend)
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn execute_aggregation_job(
    job: ValidatedAggregationJob,
) -> Result<PqSameMessageEvidence, AggregationError> {
    #[cfg(test)]
    if job.contributions.len() > 1 {
        PQ_AGGREGATE_EXECUTIONS_STARTED.fetch_add(1, Ordering::SeqCst);
    }
    let claim = PqSigningClaim::new(job.claim.signing_root, job.claim.one_time_use_id);
    let mut decoded = Vec::with_capacity(job.contributions.len());
    for contribution in &job.contributions {
        let mut public_keys = contribution
            .signers
            .iter()
            .map(|signer| signer.public_key.backend_bytes())
            .collect::<Vec<_>>();
        // Domain lists remain validator-index ordered. The backend receives its own strictly
        // key-sorted projection because upstream canonicalizes signer sets by key bytes.
        public_keys.sort_unstable();
        let signature = match PqRawSignature::from_bytes(contribution.evidence.as_bytes()) {
            Ok(raw) if public_keys.len() == 1 => {
                let public_key = public_keys
                    .first()
                    .copied()
                    .ok_or(AggregationError::Internal)?;
                backend::decode_raw_signature(raw.backend_payload(), public_key, &claim)
                    .map_err(classify_peer_evidence_error)?
            }
            Ok(_) => return Err(AggregationError::InvalidEvidence),
            Err(_) => {
                let envelope = contribution
                    .evidence
                    .backend_aggregate_envelope()
                    .map_err(|_| AggregationError::InvalidEvidence)?;
                backend::decode_aggregate_signature(envelope, &public_keys, &claim)
                    .map_err(classify_peer_evidence_error)?
            }
        };
        backend::verify_signature(&signature, &public_keys, &claim)
            .map_err(classify_peer_evidence_error)?;
        decoded.push(signature);
    }

    if job.contributions.len() == 1 {
        return job
            .contributions
            .into_iter()
            .next()
            .map(|contribution| contribution.evidence)
            .ok_or(AggregationError::Internal);
    }

    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
    {
        let _ = decoded;
        let _ = job.expected_signers;
        Err(AggregationError::Unavailable)
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        let aggregate =
            backend::aggregate(decoded, &claim).map_err(classify_local_backend_error)?;
        let mut expected_public_keys = job
            .expected_signers
            .iter()
            .map(|signer| signer.public_key.backend_bytes())
            .collect::<Vec<_>>();
        expected_public_keys.sort_unstable();
        backend::verify_signature(&aggregate, &expected_public_keys, &claim)
            .map_err(classify_local_backend_error)?;
        let envelope = backend::encode_aggregate_signature(&aggregate)
            .map_err(classify_local_backend_error)?;
        let output_len = PQ_EVIDENCE_HEADER_LEN.saturating_add(envelope.len());
        validate_job_output_len(output_len, V1_MAX_AGGREGATION_OUTPUT_BYTES)?;
        Ok(PqSameMessageEvidence::from_backend_aggregate_envelope(
            envelope,
        ))
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn validate_job_output_len(length: usize, max: usize) -> Result<(), AggregationError> {
    if length > max {
        Err(AggregationError::OutputTooLarge {
            actual: length,
            max,
        })
    } else {
        Ok(())
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn classify_peer_evidence_error(error: lean_multisig::Error) -> AggregationError {
    match error {
        lean_multisig::Error::InvalidSignature { .. }
        | lean_multisig::Error::Proof(_)
        | lean_multisig::Error::MalformedSignature
        | lean_multisig::Error::MessageMismatch
        | lean_multisig::Error::SignerSetMismatch => AggregationError::InvalidEvidence,
        lean_multisig::Error::MalformedPublicKey => {
            AggregationError::InvalidJob(InvalidAggregationJob::InvalidPublicKey)
        }
        _ => AggregationError::Internal,
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn classify_local_backend_error<T>(_error: T) -> AggregationError {
    AggregationError::Internal
}

fn validate_aggregate_signer_count(count: usize) -> Result<(), PqVerifyError> {
    if count == 0 {
        return Err(PqVerifyError::InvalidRequest(
            PqVerifyRequestError::EmptySignerSet,
        ));
    }
    if count > PQ_MAX_SIGNERS {
        return Err(PqVerifyError::InvalidRequest(
            PqVerifyRequestError::TooManySigners {
                actual: count,
                max: PQ_MAX_SIGNERS,
            },
        ));
    }
    Ok(())
}

fn validate_canonical_signer_order(public_keys: &[PqPublicKey]) -> Result<(), PqVerifyError> {
    for pair in public_keys.windows(2) {
        let [first, second] = pair else {
            continue;
        };
        match first.cmp(second) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(PqVerifyError::InvalidRequest(
                    PqVerifyRequestError::DuplicateSigner,
                ));
            }
            std::cmp::Ordering::Greater => {
                return Err(PqVerifyError::InvalidRequest(
                    PqVerifyRequestError::NonCanonicalSignerOrder,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use futures::channel::oneshot;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use parking_lot::{Condvar, Mutex};
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::sync::mpsc::{SyncSender, sync_channel};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::thread::Builder;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::thread::JoinHandle;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::{collections::VecDeque, sync::Arc};

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
const PQ_WORKER_STACK_SIZE: usize = 512 * 1024 * 1024;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
static PQ_PROVER_LIFECYCLE: ProverLifecycle = ProverLifecycle::idle();
#[cfg(test)]
static PQ_AGGREGATE_EXECUTIONS_STARTED: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
fn testing_only_aggregate_executions_started() -> usize {
    PQ_AGGREGATE_EXECUTIONS_STARTED.load(Ordering::SeqCst)
}

/// A local build or process state that cannot provide the experimental prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProverUnavailable {
    /// The pinned prover is currently supported only on x86-64.
    #[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
    UnsupportedTarget,
    /// The binary was not compiled in the required AVX2-only mode.
    #[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
    Avx2NotEnabledAtCompileTime,
    /// A prover worker already owns the process-wide upstream proving state.
    #[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
    AlreadyActive,
    /// A caught backend panic may have poisoned process-wide upstream proving state.
    ProcessPoisoned,
}

impl std::fmt::Display for ProverUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            #[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
            Self::UnsupportedTarget => "the PQ prover is supported only on x86-64",
            #[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
            Self::Avx2NotEnabledAtCompileTime => {
                "the PQ prover requires an AVX2-only binary and launcher preflight"
            }
            #[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
            Self::AlreadyActive => "a PQ prover worker is already active in this process",
            Self::ProcessPoisoned => {
                "the PQ prover process is poisoned after a caught backend panic"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProverUnavailable {}

/// A failure to create and initialize the owned prover worker.
#[derive(Debug)]
pub(crate) enum ProverError {
    /// The build or process state cannot host the prover.
    Unavailable(ProverUnavailable),
    /// The operating system refused to create the dedicated worker.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    WorkerSpawn(std::io::Error),
    /// Upstream setup panicked on the dedicated worker.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    InitializationPanicked,
    /// The worker stopped before reporting its initialization result.
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    InitializationWorkerStopped,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "PQ prover unavailable: {error}"),
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            Self::WorkerSpawn(error) => {
                write!(formatter, "failed to spawn PQ prover worker: {error}")
            }
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            Self::InitializationPanicked => formatter.write_str("PQ prover setup panicked"),
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            Self::InitializationWorkerStopped => {
                formatter.write_str("PQ prover worker stopped during setup")
            }
        }
    }
}

impl std::error::Error for ProverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(error) => Some(error),
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            Self::WorkerSpawn(error) => Some(error),
            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            Self::InitializationPanicked | Self::InitializationWorkerStopped => None,
        }
    }
}

/// The process-wide owner of recursive-proof setup and aggregation.
///
/// Construction starts one named OS thread with a 512 MiB stack and initializes upstream proving
/// state there. Every aggregate job owns its signatures and claim and is executed serially on the
/// same worker. This type is intentionally not cloneable, and a second live instance is rejected.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) struct PqProver {
    worker: WorkerControl<ValidatedAggregationJob, PqSameMessageEvidence>,
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
pub(crate) struct PqProver {
    _unavailable: (),
}

impl PqProver {
    /// Starts and initializes the singleton prover worker.
    pub(crate) fn new() -> Result<Self, ProverError> {
        start_prover()
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl PqProver {
    pub(crate) async fn aggregate_job(
        &self,
        job: ValidatedAggregationJob,
    ) -> Result<PqSameMessageEvidence, AggregationError> {
        self.submit(WorkClass::Aggregate, job).await
    }

    pub(crate) async fn verify_job(
        &self,
        class: VerificationClass,
        job: ValidatedAggregationJob,
    ) -> Result<PqSameMessageEvidence, AggregationError> {
        self.submit(class.into(), job).await
    }

    async fn submit(
        &self,
        class: WorkClass,
        job: ValidatedAggregationJob,
    ) -> Result<PqSameMessageEvidence, AggregationError> {
        let scheduler = self.worker.scheduler()?;
        let (response, result) = oneshot::channel();
        let queued_evidence_bytes = job.queued_evidence_bytes;
        scheduler
            .try_admit(
                class,
                Command {
                    job,
                    queued_evidence_bytes,
                    response,
                },
            )
            .map_err(|error| error.into_aggregation_error(class, &scheduler.limits))?;
        result.await.map_err(|_| AggregationError::WorkerStopped)?
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
impl PqProver {
    pub(crate) async fn aggregate_job(
        &self,
        job: ValidatedAggregationJob,
    ) -> Result<PqSameMessageEvidence, AggregationError> {
        let ValidatedAggregationJob {
            claim,
            expected_signers,
            contributions,
            queued_evidence_bytes,
        } = job;
        drop((
            claim,
            expected_signers,
            contributions,
            queued_evidence_bytes,
        ));
        Err(AggregationError::Unavailable)
    }

    pub(crate) async fn verify_job(
        &self,
        class: VerificationClass,
        job: ValidatedAggregationJob,
    ) -> Result<PqSameMessageEvidence, AggregationError> {
        let _ = class;
        let ValidatedAggregationJob {
            claim,
            expected_signers,
            contributions,
            queued_evidence_bytes,
        } = job;
        drop((
            claim,
            expected_signers,
            contributions,
            queued_evidence_bytes,
        ));
        Err(AggregationError::Unavailable)
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
type Command = WorkerCommand<ValidatedAggregationJob, PqSameMessageEvidence>;

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct WorkerCommand<Job, Output> {
    job: Job,
    queued_evidence_bytes: usize,
    response: oneshot::Sender<Result<Output, AggregationError>>,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct WorkerControl<Job, Output> {
    scheduler: Option<Arc<PriorityScheduler<Job, Output>>>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl<Job, Output> WorkerControl<Job, Output> {
    fn scheduler(&self) -> Result<&Arc<PriorityScheduler<Job, Output>>, AggregationError> {
        self.scheduler
            .as_ref()
            .ok_or(AggregationError::WorkerStopped)
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl<Job, Output> Drop for WorkerControl<Job, Output> {
    fn drop(&mut self) {
        // Closing admissions drains already-admitted work by priority. Dropping the join handle
        // detaches instead of blocking an async caller. The worker owns ActiveProver, so a
        // replacement cannot start until every admitted request has completed safely.
        if let Some(scheduler) = self.scheduler.take() {
            scheduler.close();
        }
        self.worker.take();
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkClass {
    Block,
    Gossip,
    Aggregate,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl From<VerificationClass> for WorkClass {
    fn from(class: VerificationClass) -> Self {
        match class {
            VerificationClass::Block => Self::Block,
            VerificationClass::Gossip => Self::Gossip,
        }
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy)]
struct SchedulerLimits {
    block_count: usize,
    gossip_count: usize,
    aggregation_count: usize,
    block_bytes: usize,
    gossip_bytes: usize,
    aggregation_bytes: usize,
    total_bytes: usize,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_BLOCK_QUEUE_CAPACITY: usize = 2;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_GOSSIP_QUEUE_CAPACITY: usize = 4;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_AGGREGATION_QUEUE_CAPACITY: usize = 1;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_BLOCK_QUEUE_BYTES: usize =
    PQ_BLOCK_QUEUE_CAPACITY * crate::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_GOSSIP_QUEUE_BYTES: usize =
    PQ_GOSSIP_QUEUE_CAPACITY * crate::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_AGGREGATION_QUEUE_BYTES: usize = crate::aggregation::V1_MAX_AGGREGATION_INPUT_BYTES;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_TOTAL_QUEUED_EVIDENCE_BYTES: usize =
    PQ_BLOCK_QUEUE_BYTES + PQ_GOSSIP_QUEUE_BYTES + PQ_AGGREGATION_QUEUE_BYTES;
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
const PQ_SCHEDULER_LIMITS: SchedulerLimits = SchedulerLimits {
    // Each verification slot can retain one maximum-size PQ evidence envelope. The independent
    // class budgets are reservations: gossip and local proving cannot consume block capacity.
    block_count: PQ_BLOCK_QUEUE_CAPACITY,
    gossip_count: PQ_GOSSIP_QUEUE_CAPACITY,
    aggregation_count: PQ_AGGREGATION_QUEUE_CAPACITY,
    block_bytes: PQ_BLOCK_QUEUE_BYTES,
    gossip_bytes: PQ_GOSSIP_QUEUE_BYTES,
    aggregation_bytes: PQ_AGGREGATION_QUEUE_BYTES,
    total_bytes: PQ_TOTAL_QUEUED_EVIDENCE_BYTES,
};
#[cfg(test)]
const PQ_MAX_RETAINED_EVIDENCE_BYTES: usize =
    PQ_TOTAL_QUEUED_EVIDENCE_BYTES + crate::aggregation::V1_MAX_AGGREGATION_INPUT_BYTES;

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulerAdmissionError {
    CountFull { max: usize },
    ClassBytesFull { actual: usize, max: usize },
    TotalBytesFull { actual: usize, max: usize },
    Stopped,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl SchedulerAdmissionError {
    fn into_aggregation_error(
        self,
        class: WorkClass,
        limits: &SchedulerLimits,
    ) -> AggregationError {
        match self {
            Self::Stopped => AggregationError::WorkerStopped,
            Self::CountFull { .. } | Self::ClassBytesFull { .. } | Self::TotalBytesFull { .. } => {
                AggregationError::ResourceExhausted(AggregationResource::QueueSaturated {
                    max_queued: limits.count(class),
                })
            }
        }
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl SchedulerLimits {
    fn count(&self, class: WorkClass) -> usize {
        match class {
            WorkClass::Block => self.block_count,
            WorkClass::Gossip => self.gossip_count,
            WorkClass::Aggregate => self.aggregation_count,
        }
    }

    fn bytes(&self, class: WorkClass) -> usize {
        match class {
            WorkClass::Block => self.block_bytes,
            WorkClass::Gossip => self.gossip_bytes,
            WorkClass::Aggregate => self.aggregation_bytes,
        }
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct PriorityScheduler<Job, Output> {
    limits: SchedulerLimits,
    state: Mutex<SchedulerState<Job, Output>>,
    ready: Condvar,
    #[cfg(test)]
    wait_hook: Mutex<Option<Arc<std::sync::Barrier>>>,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct SchedulerState<Job, Output> {
    accepting: bool,
    health: SchedulerHealth,
    block: VecDeque<WorkerCommand<Job, Output>>,
    gossip: VecDeque<WorkerCommand<Job, Output>>,
    aggregate: VecDeque<WorkerCommand<Job, Output>>,
    block_bytes: usize,
    gossip_bytes: usize,
    aggregate_bytes: usize,
    total_bytes: usize,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulerHealth {
    Healthy,
    AccountingPoisoned,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountingInvariantError;

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct AccountingPartitionError<Job, Output> {
    removed: Vec<WorkerCommand<Job, Output>>,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct AccountingPartition<Job, Output> {
    removed_bytes: usize,
    removed: Vec<WorkerCommand<Job, Output>>,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl<Job, Output> std::fmt::Debug for AccountingPartitionError<Job, Output> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountingPartitionError")
            .field("removed_count", &self.removed.len())
            .finish()
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl<Job, Output> PriorityScheduler<Job, Output> {
    fn new(limits: SchedulerLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(SchedulerState {
                accepting: true,
                health: SchedulerHealth::Healthy,
                block: VecDeque::new(),
                gossip: VecDeque::new(),
                aggregate: VecDeque::new(),
                block_bytes: 0,
                gossip_bytes: 0,
                aggregate_bytes: 0,
                total_bytes: 0,
            }),
            ready: Condvar::new(),
            #[cfg(test)]
            wait_hook: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn new_with_wait_hook(limits: SchedulerLimits, wait_hook: Arc<std::sync::Barrier>) -> Self {
        let scheduler = Self::new(limits);
        *scheduler.wait_hook.lock() = Some(wait_hook);
        scheduler
    }

    fn try_admit(
        &self,
        class: WorkClass,
        command: WorkerCommand<Job, Output>,
    ) -> Result<(), SchedulerAdmissionError> {
        let mut state = self.state.lock();
        let removed = match state.purge_cancelled() {
            Ok(removed) => removed,
            Err(error) => {
                let stopped = state.poison_accounting_and_drain();
                drop(state);
                drop(error.removed);
                drop(command);
                Self::resolve_stopped(stopped);
                self.ready.notify_all();
                return Err(SchedulerAdmissionError::Stopped);
            }
        };
        let admission = state.try_push(&self.limits, class, command);
        drop(state);
        drop(removed);
        let result = match admission {
            Ok(()) => Ok(()),
            Err((error, rejected)) => {
                drop(rejected);
                Err(error)
            }
        };
        if result.is_ok() {
            self.ready.notify_one();
        }
        result
    }

    fn pop(&self) -> Option<WorkerCommand<Job, Output>> {
        let mut state = self.state.lock();
        loop {
            if let Some((class, command)) = state.pop_highest_priority() {
                if state
                    .release_bytes(class, command.queued_evidence_bytes)
                    .is_ok()
                {
                    return Some(command);
                }
                let mut stopped = vec![command];
                stopped.extend(state.poison_accounting_and_drain());
                drop(state);
                Self::resolve_stopped(stopped);
                self.ready.notify_all();
                return None;
            }
            if !state.accepting {
                return None;
            }
            #[cfg(test)]
            if let Some(wait_hook) = self.wait_hook.lock().take() {
                wait_hook.wait();
            }
            self.ready.wait(&mut state);
        }
    }

    fn close(&self) {
        self.state.lock().accepting = false;
        self.ready.notify_all();
    }

    fn stop_and_resolve_queued(&self) {
        let mut state = self.state.lock();
        state.accepting = false;
        let stopped = state
            .drain_by_priority_exact()
            .unwrap_or_else(|_| state.poison_accounting_and_drain());
        drop(state);
        Self::resolve_stopped(stopped);
        self.ready.notify_all();
    }

    fn resolve_stopped(commands: Vec<WorkerCommand<Job, Output>>) {
        for command in commands {
            let _ = command.response.send(Err(AggregationError::WorkerStopped));
        }
    }

    #[cfg(test)]
    fn queued_evidence_bytes(&self) -> usize {
        self.state.lock().total_bytes
    }

    #[cfg(test)]
    fn accounting_poisoned(&self) -> bool {
        self.state.lock().health == SchedulerHealth::AccountingPoisoned
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl<Job, Output> SchedulerState<Job, Output> {
    fn queue(&self, class: WorkClass) -> &VecDeque<WorkerCommand<Job, Output>> {
        match class {
            WorkClass::Block => &self.block,
            WorkClass::Gossip => &self.gossip,
            WorkClass::Aggregate => &self.aggregate,
        }
    }

    fn queue_mut(&mut self, class: WorkClass) -> &mut VecDeque<WorkerCommand<Job, Output>> {
        match class {
            WorkClass::Block => &mut self.block,
            WorkClass::Gossip => &mut self.gossip,
            WorkClass::Aggregate => &mut self.aggregate,
        }
    }

    fn class_bytes(&self, class: WorkClass) -> usize {
        match class {
            WorkClass::Block => self.block_bytes,
            WorkClass::Gossip => self.gossip_bytes,
            WorkClass::Aggregate => self.aggregate_bytes,
        }
    }

    fn set_class_bytes(&mut self, class: WorkClass, bytes: usize) {
        match class {
            WorkClass::Block => self.block_bytes = bytes,
            WorkClass::Gossip => self.gossip_bytes = bytes,
            WorkClass::Aggregate => self.aggregate_bytes = bytes,
        }
    }

    fn try_push(
        &mut self,
        limits: &SchedulerLimits,
        class: WorkClass,
        command: WorkerCommand<Job, Output>,
    ) -> Result<(), (SchedulerAdmissionError, WorkerCommand<Job, Output>)> {
        if !self.accepting || self.health != SchedulerHealth::Healthy {
            return Err((SchedulerAdmissionError::Stopped, command));
        }
        let count_max = limits.count(class);
        if self.queue(class).len() >= count_max {
            return Err((
                SchedulerAdmissionError::CountFull { max: count_max },
                command,
            ));
        }
        let class_max = limits.bytes(class);
        let Some(class_actual) = self
            .class_bytes(class)
            .checked_add(command.queued_evidence_bytes)
        else {
            return Err((
                SchedulerAdmissionError::ClassBytesFull {
                    actual: usize::MAX,
                    max: class_max,
                },
                command,
            ));
        };
        if class_actual > class_max {
            return Err((
                SchedulerAdmissionError::ClassBytesFull {
                    actual: class_actual,
                    max: class_max,
                },
                command,
            ));
        }
        let Some(total_actual) = self.total_bytes.checked_add(command.queued_evidence_bytes) else {
            return Err((
                SchedulerAdmissionError::TotalBytesFull {
                    actual: usize::MAX,
                    max: limits.total_bytes,
                },
                command,
            ));
        };
        if total_actual > limits.total_bytes {
            return Err((
                SchedulerAdmissionError::TotalBytesFull {
                    actual: total_actual,
                    max: limits.total_bytes,
                },
                command,
            ));
        }
        self.set_class_bytes(class, class_actual);
        self.total_bytes = total_actual;
        self.queue_mut(class).push_back(command);
        Ok(())
    }

    fn pop_highest_priority(&mut self) -> Option<(WorkClass, WorkerCommand<Job, Output>)> {
        self.block
            .pop_front()
            .map(|command| (WorkClass::Block, command))
            .or_else(|| {
                self.gossip
                    .pop_front()
                    .map(|command| (WorkClass::Gossip, command))
            })
            .or_else(|| {
                self.aggregate
                    .pop_front()
                    .map(|command| (WorkClass::Aggregate, command))
            })
    }

    fn release_bytes(
        &mut self,
        class: WorkClass,
        bytes: usize,
    ) -> Result<(), AccountingInvariantError> {
        if self.health != SchedulerHealth::Healthy {
            return Err(AccountingInvariantError);
        }
        let class_bytes = self
            .class_bytes(class)
            .checked_sub(bytes)
            .ok_or(AccountingInvariantError)?;
        let total_bytes = self
            .total_bytes
            .checked_sub(bytes)
            .ok_or(AccountingInvariantError)?;
        self.set_class_bytes(class, class_bytes);
        self.total_bytes = total_bytes;
        Ok(())
    }

    fn purge_cancelled(
        &mut self,
    ) -> Result<Vec<WorkerCommand<Job, Output>>, AccountingPartitionError<Job, Output>> {
        if self.health != SchedulerHealth::Healthy {
            return Err(AccountingPartitionError {
                removed: Vec::new(),
            });
        }
        let mut removed = Vec::new();
        for class in [WorkClass::Block, WorkClass::Gossip, WorkClass::Aggregate] {
            let AccountingPartition {
                removed_bytes,
                removed: mut class_removed,
            } = match Self::partition_matching_once(self.queue_mut(class), |command| {
                command.response.is_canceled()
            }) {
                Ok(partition) => partition,
                Err(mut error) => {
                    removed.append(&mut error.removed);
                    return Err(AccountingPartitionError { removed });
                }
            };
            if self.release_bytes(class, removed_bytes).is_err() {
                removed.append(&mut class_removed);
                return Err(AccountingPartitionError { removed });
            }
            removed.append(&mut class_removed);
        }
        Ok(removed)
    }

    fn partition_matching_once(
        queue: &mut VecDeque<WorkerCommand<Job, Output>>,
        mut remove: impl FnMut(&WorkerCommand<Job, Output>) -> bool,
    ) -> Result<AccountingPartition<Job, Output>, AccountingPartitionError<Job, Output>> {
        let original_len = queue.len();
        let mut removed_bytes = 0usize;
        let mut removed = Vec::new();
        for _ in 0..original_len {
            let Some(command) = queue.pop_front() else {
                return Err(AccountingPartitionError { removed });
            };
            if remove(&command) {
                let next_removed_bytes = removed_bytes.checked_add(command.queued_evidence_bytes);
                removed.push(command);
                let Some(next_removed_bytes) = next_removed_bytes else {
                    return Err(AccountingPartitionError { removed });
                };
                removed_bytes = next_removed_bytes;
            } else {
                queue.push_back(command);
            }
        }
        Ok(AccountingPartition {
            removed_bytes,
            removed,
        })
    }

    fn drain_by_priority_exact(
        &mut self,
    ) -> Result<Vec<WorkerCommand<Job, Output>>, AccountingInvariantError> {
        if self.health != SchedulerHealth::Healthy {
            return Err(AccountingInvariantError);
        }
        let block_bytes = Self::queue_evidence_bytes(&self.block)?;
        let gossip_bytes = Self::queue_evidence_bytes(&self.gossip)?;
        let aggregate_bytes = Self::queue_evidence_bytes(&self.aggregate)?;
        let total_bytes = block_bytes
            .checked_add(gossip_bytes)
            .and_then(|total| total.checked_add(aggregate_bytes))
            .ok_or(AccountingInvariantError)?;
        if block_bytes != self.block_bytes
            || gossip_bytes != self.gossip_bytes
            || aggregate_bytes != self.aggregate_bytes
            || total_bytes != self.total_bytes
        {
            return Err(AccountingInvariantError);
        }
        let queued_count = self
            .block
            .len()
            .checked_add(self.gossip.len())
            .and_then(|count| count.checked_add(self.aggregate.len()))
            .ok_or(AccountingInvariantError)?;
        let mut drained = Vec::with_capacity(queued_count);
        drained.extend(self.block.drain(..));
        drained.extend(self.gossip.drain(..));
        drained.extend(self.aggregate.drain(..));
        self.block_bytes = 0;
        self.gossip_bytes = 0;
        self.aggregate_bytes = 0;
        self.total_bytes = 0;
        Ok(drained)
    }

    fn queue_evidence_bytes(
        queue: &VecDeque<WorkerCommand<Job, Output>>,
    ) -> Result<usize, AccountingInvariantError> {
        queue
            .iter()
            .try_fold(0usize, |total, command| {
                total.checked_add(command.queued_evidence_bytes)
            })
            .ok_or(AccountingInvariantError)
    }

    fn poison_accounting_and_drain(&mut self) -> Vec<WorkerCommand<Job, Output>> {
        self.health = SchedulerHealth::AccountingPoisoned;
        self.accepting = false;
        let mut drained = Vec::new();
        drained.extend(self.block.drain(..));
        drained.extend(self.gossip.drain(..));
        drained.extend(self.aggregate.drain(..));
        // The queue is now empty. Resetting the counters is explicit recovery after permanently
        // poisoning admissions, rather than silently hiding an arithmetic mismatch.
        self.block_bytes = 0;
        self.gossip_bytes = 0;
        self.aggregate_bytes = 0;
        self.total_bytes = 0;
        drained
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct ActiveProver {
    lifecycle: &'static ProverLifecycle,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl ActiveProver {
    const fn new(lifecycle: &'static ProverLifecycle) -> Self {
        Self { lifecycle }
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl Drop for ActiveProver {
    fn drop(&mut self) {
        self.lifecycle.release();
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct ProverLifecycle {
    state: AtomicU8,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl ProverLifecycle {
    const IDLE: u8 = 0;
    const ACTIVE: u8 = 1;
    const POISONED: u8 = 2;

    const fn idle() -> Self {
        Self {
            state: AtomicU8::new(Self::IDLE),
        }
    }

    fn try_activate(&self) -> Result<(), ProverUnavailable> {
        match self.state.compare_exchange(
            Self::IDLE,
            Self::ACTIVE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(Self::ACTIVE) => Err(ProverUnavailable::AlreadyActive),
            Err(Self::POISONED) => Err(ProverUnavailable::ProcessPoisoned),
            // All writes are private to this state machine. Treat an impossible state as poisoned
            // rather than risk re-entering process-global upstream state.
            Err(_) => Err(ProverUnavailable::ProcessPoisoned),
        }
    }

    fn poison(&self) {
        self.state.store(Self::POISONED, Ordering::Release);
    }

    fn release(&self) {
        // A caught backend panic changes ACTIVE to POISONED. Never overwrite that terminal state.
        let _ = self.state.compare_exchange(
            Self::ACTIVE,
            Self::IDLE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn catch_backend_panic<T>(
    lifecycle: &ProverLifecycle,
    operation: impl FnOnce() -> T,
) -> std::thread::Result<T> {
    let result = catch_unwind(AssertUnwindSafe(operation));
    if result.is_err() {
        lifecycle.poison();
    }
    result
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
fn start_prover() -> Result<PqProver, ProverError> {
    Err(ProverError::Unavailable(build_mode_unavailable()))
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn start_prover() -> Result<PqProver, ProverError> {
    PQ_PROVER_LIFECYCLE
        .try_activate()
        .map_err(ProverError::Unavailable)?;
    let active = ActiveProver::new(&PQ_PROVER_LIFECYCLE);
    let scheduler = Arc::new(PriorityScheduler::new(PQ_SCHEDULER_LIMITS));
    let (initialization_sender, initialization_receiver) = sync_channel(1);
    let worker_scheduler = Arc::clone(&scheduler);
    let worker = Builder::new()
        .name("pq-prover".into())
        .stack_size(PQ_WORKER_STACK_SIZE)
        .spawn(move || worker_main(worker_scheduler, initialization_sender, active))
        .map_err(ProverError::WorkerSpawn)?;

    match initialization_receiver.recv() {
        Ok(InitializationResult::Ready) => Ok(PqProver {
            worker: WorkerControl {
                scheduler: Some(scheduler),
                worker: Some(worker),
            },
        }),
        Ok(InitializationResult::Panicked) => {
            let _ = worker.join();
            Err(ProverError::InitializationPanicked)
        }
        Err(_) => {
            let initialization_panicked = worker.join().is_err();
            if initialization_panicked {
                Err(ProverError::InitializationPanicked)
            } else {
                Err(ProverError::InitializationWorkerStopped)
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
enum InitializationResult {
    Ready,
    Panicked,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn worker_main(
    scheduler: Arc<PriorityScheduler<ValidatedAggregationJob, PqSameMessageEvidence>>,
    initialized: SyncSender<InitializationResult>,
    _active: ActiveProver,
) {
    let setup_result = catch_backend_panic(&PQ_PROVER_LIFECYCLE, backend::setup);
    if setup_result.is_err() {
        let _ = initialized.send(InitializationResult::Panicked);
        return;
    }
    if initialized.send(InitializationResult::Ready).is_err() {
        return;
    }

    run_worker_loop(scheduler, &PQ_PROVER_LIFECYCLE, execute_aggregation_job);
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn run_worker_loop<Job, Output>(
    scheduler: Arc<PriorityScheduler<Job, Output>>,
    lifecycle: &ProverLifecycle,
    mut execute: impl FnMut(Job) -> Result<Output, AggregationError>,
) {
    while let Some(command) = scheduler.pop() {
        if command.response.is_canceled() {
            // Dropping the async result receiver is cancellation. The check is deliberately at
            // the last safe point: once recursive proving begins it must run to completion. No
            // result is sent because the dropped receiver cannot observe one.
            continue;
        }
        let result = catch_backend_panic(lifecycle, || execute(command.job));
        match result {
            Ok(result) => {
                let _ = command.response.send(result);
            }
            Err(_) => {
                let _ = command.response.send(Err(AggregationError::WorkerPanicked));
                scheduler.stop_and_resolve_queued();
                break;
            }
        }
    }
}

#[cfg(any(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
const fn build_mode_unavailable_for(
    is_x86_64: bool,
    avx2_enabled: bool,
) -> Option<ProverUnavailable> {
    if !is_x86_64 {
        Some(ProverUnavailable::UnsupportedTarget)
    } else if !avx2_enabled {
        Some(ProverUnavailable::Avx2NotEnabledAtCompileTime)
    } else {
        None
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
const fn build_mode_unavailable() -> ProverUnavailable {
    match build_mode_unavailable_for(cfg!(target_arch = "x86_64"), cfg!(target_feature = "avx2")) {
        Some(error) => error,
        // This function is compiled only for unavailable build modes. Fail closed if its cfg and
        // the explicit target mapping ever diverge.
        None => ProverUnavailable::ProcessPoisoned,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PQ_MAX_SIGNERS, PqPublicKey, PqRawSignature, PqSameMessageEvidence, PqSignError,
        PqSigningClaim, PqUnreservedSigningKey, PqVerifyError, PqVerifyRequestError,
        ProverLifecycle, ProverUnavailable, catch_backend_panic, validate_aggregate_signer_count,
        validate_canonical_signer_order, verify_aggregate_evidence, verify_raw,
    };
    use crate::aggregation::{
        AggregationContribution, AggregationError, AggregationSigner, SameMessageClaim,
        ValidatedAggregationJob,
    };
    use crate::{OneTimeUseId, SigningDuty};
    use std::error::Error as _;

    fn id(duty: SigningDuty) -> OneTimeUseId {
        OneTimeUseId::for_lean_pq_devnet_v1(0, duty).expect("slot zero is in range")
    }

    fn randao_id() -> OneTimeUseId {
        id(SigningDuty::RandaoReveal)
    }

    fn block_id() -> OneTimeUseId {
        id(SigningDuty::BeaconBlockProposal)
    }

    fn signing_key(seed: u8) -> PqUnreservedSigningKey {
        PqUnreservedSigningKey::from_seed([seed; 32], randao_id()..=randao_id())
            .expect("one-leaf deterministic key")
    }

    #[test]
    fn one_raw_aggregation_job_is_verified_and_returned_without_proving() {
        let key = signing_key(0x41);
        let pq_claim = PqSigningClaim::new([0x42; 32], randao_id());
        let claim = SameMessageClaim::new([0x42; 32], randao_id());
        let raw = key.sign(&pq_claim).expect("raw signature");
        let evidence = PqSameMessageEvidence::from(&raw);
        let expected = evidence.as_bytes().to_vec();
        assert!(crate::is_individual_same_message_evidence(&evidence));
        assert!(!crate::is_individual_same_message_evidence(
            &PqSameMessageEvidence::empty()
        ));
        let signer = AggregationSigner {
            validator_index: 7,
            public_key: key.public_key(),
        };
        let job = ValidatedAggregationJob {
            claim,
            expected_signers: vec![signer.clone()],
            contributions: vec![AggregationContribution {
                signers: vec![signer],
                evidence,
            }],
            queued_evidence_bytes: expected.len(),
        };

        let result = super::execute_aggregation_job(job)
            .expect("a valid raw contribution is returned without recursive proving");
        assert_eq!(result.as_bytes(), expected);

        let wrong_claim_job = ValidatedAggregationJob {
            claim: SameMessageClaim::new([0x43; 32], randao_id()),
            expected_signers: vec![AggregationSigner {
                validator_index: 7,
                public_key: key.public_key(),
            }],
            contributions: vec![AggregationContribution {
                signers: vec![AggregationSigner {
                    validator_index: 7,
                    public_key: key.public_key(),
                }],
                evidence: PqSameMessageEvidence::from(&raw),
            }],
            queued_evidence_bytes: raw.as_bytes().len(),
        };
        assert_eq!(
            super::execute_aggregation_job(wrong_claim_job),
            Err(AggregationError::InvalidEvidence)
        );

        let wrong_key = signing_key(0x42);
        let wrong_key_signer = AggregationSigner {
            validator_index: 7,
            public_key: wrong_key.public_key(),
        };
        let wrong_key_job = ValidatedAggregationJob {
            claim,
            expected_signers: vec![wrong_key_signer.clone()],
            contributions: vec![AggregationContribution {
                signers: vec![wrong_key_signer],
                evidence: PqSameMessageEvidence::from(&raw),
            }],
            queued_evidence_bytes: raw.as_bytes().len(),
        };
        assert_eq!(
            super::execute_aggregation_job(wrong_key_job),
            Err(AggregationError::InvalidEvidence)
        );
    }

    fn scheduler_limits() -> super::SchedulerLimits {
        super::SchedulerLimits {
            block_count: 2,
            gossip_count: 2,
            aggregation_count: 2,
            block_bytes: 10,
            gossip_bytes: 10,
            aggregation_bytes: 10,
            total_bytes: 30,
        }
    }

    fn command(
        job: u8,
        queued_evidence_bytes: usize,
    ) -> (
        super::WorkerCommand<u8, u8>,
        futures::channel::oneshot::Receiver<Result<u8, AggregationError>>,
    ) {
        let (response, result) = futures::channel::oneshot::channel();
        (
            super::WorkerCommand {
                job,
                queued_evidence_bytes,
                response,
            },
            result,
        )
    }

    #[test]
    fn full_lower_priority_byte_budgets_leave_block_admission_reserved() {
        let scheduler = super::PriorityScheduler::new(scheduler_limits());
        let (gossip, _gossip_result) = command(1, 10);
        scheduler
            .try_admit(super::WorkClass::Gossip, gossip)
            .expect("full gossip byte budget is admitted");
        let (aggregation, _aggregation_result) = command(2, 10);
        scheduler
            .try_admit(super::WorkClass::Aggregate, aggregation)
            .expect("full aggregation byte budget is admitted");
        let (block, _block_result) = command(3, 10);
        scheduler
            .try_admit(super::WorkClass::Block, block)
            .expect("maximum block remains reserved");
        assert_eq!(scheduler.queued_evidence_bytes(), 30);
    }

    #[test]
    fn production_scheduler_limits_pin_reserved_and_total_evidence_bounds() {
        let limits = super::PQ_SCHEDULER_LIMITS;
        assert_eq!(limits.block_count, 2);
        assert_eq!(limits.gossip_count, 4);
        assert_eq!(limits.aggregation_count, 1);
        assert_eq!(
            limits.block_bytes,
            limits
                .block_count
                .checked_mul(crate::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)
                .expect("production block byte bound fits usize")
        );
        assert_eq!(
            limits.gossip_bytes,
            limits
                .gossip_count
                .checked_mul(crate::PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN)
                .expect("production gossip byte bound fits usize")
        );
        assert_eq!(
            limits.aggregation_bytes,
            crate::aggregation::V1_MAX_AGGREGATION_INPUT_BYTES
        );
        assert_eq!(
            limits.total_bytes,
            limits
                .block_bytes
                .checked_add(limits.gossip_bytes)
                .and_then(|total| total.checked_add(limits.aggregation_bytes))
                .expect("production queued byte bound fits usize")
        );
        assert_eq!(
            super::PQ_MAX_RETAINED_EVIDENCE_BYTES,
            limits
                .total_bytes
                .checked_add(crate::aggregation::V1_MAX_AGGREGATION_INPUT_BYTES)
                .expect("production retained byte bound fits usize")
        );
    }

    #[test]
    fn scheduler_pops_block_then_gossip_then_aggregate_fifo() {
        let scheduler = super::PriorityScheduler::new(scheduler_limits());
        let mut results = Vec::new();
        for (class, job) in [
            (super::WorkClass::Aggregate, 50),
            (super::WorkClass::Aggregate, 51),
            (super::WorkClass::Gossip, 30),
            (super::WorkClass::Gossip, 31),
            (super::WorkClass::Block, 10),
            (super::WorkClass::Block, 11),
        ] {
            let (command, result) = command(job, 1);
            scheduler.try_admit(class, command).expect("job admitted");
            results.push(result);
        }
        scheduler.close();

        let mut jobs = Vec::new();
        while let Some(command) = scheduler.pop() {
            jobs.push(command.job);
        }
        assert_eq!(jobs, [10, 11, 30, 31, 50, 51]);
        assert_eq!(scheduler.queued_evidence_bytes(), 0);
        drop(results);
    }

    #[test]
    fn scheduler_checks_each_count_and_byte_cap_before_retaining_a_job() {
        for class in [
            super::WorkClass::Block,
            super::WorkClass::Gossip,
            super::WorkClass::Aggregate,
        ] {
            let scheduler = super::PriorityScheduler::new(scheduler_limits());
            let mut results = Vec::new();
            for job in [1, 2] {
                let (command, result) = command(job, 1);
                scheduler.try_admit(class, command).expect("at count cap");
                results.push(result);
            }
            let (overflow, _result) = command(3, 1);
            assert_eq!(
                scheduler.try_admit(class, overflow),
                Err(super::SchedulerAdmissionError::CountFull { max: 2 })
            );
            assert_eq!(scheduler.queued_evidence_bytes(), 2);
            drop(results);
        }

        let scheduler = super::PriorityScheduler::new(scheduler_limits());
        let (at_max, _result) = command(1, 10);
        scheduler
            .try_admit(super::WorkClass::Gossip, at_max)
            .expect("exact class byte cap");
        let (class_overflow, _result) = command(2, 1);
        assert_eq!(
            scheduler.try_admit(super::WorkClass::Gossip, class_overflow),
            Err(super::SchedulerAdmissionError::ClassBytesFull {
                actual: 11,
                max: 10,
            })
        );
        assert_eq!(scheduler.queued_evidence_bytes(), 10);

        let total_scheduler = super::PriorityScheduler::new(super::SchedulerLimits {
            block_bytes: usize::MAX,
            gossip_bytes: usize::MAX,
            aggregation_bytes: usize::MAX,
            total_bytes: 10,
            ..scheduler_limits()
        });
        let (at_total, _result) = command(1, 10);
        total_scheduler
            .try_admit(super::WorkClass::Block, at_total)
            .expect("exact total byte cap");
        let (total_overflow, _result) = command(2, 1);
        assert_eq!(
            total_scheduler.try_admit(super::WorkClass::Gossip, total_overflow),
            Err(super::SchedulerAdmissionError::TotalBytesFull {
                actual: 11,
                max: 10,
            })
        );
        assert_eq!(total_scheduler.queued_evidence_bytes(), 10);
    }

    #[test]
    fn dropped_queued_responses_are_skipped_and_release_bytes() {
        use std::sync::{Arc, Mutex};

        let scheduler = Arc::new(super::PriorityScheduler::new(scheduler_limits()));
        let (cancelled, cancelled_result) = command(1, 7);
        scheduler
            .try_admit(super::WorkClass::Block, cancelled)
            .expect("cancelled job admitted");
        let (live, live_result) = command(2, 3);
        scheduler
            .try_admit(super::WorkClass::Block, live)
            .expect("live job admitted");
        // Cancel only after the final admission so this command remains queued until the worker's
        // last-safe cancellation check.
        drop(cancelled_result);
        scheduler.close();

        let lifecycle = ProverLifecycle::idle();
        lifecycle.try_activate().expect("worker activates");
        let executions = Arc::new(Mutex::new(Vec::new()));
        super::run_worker_loop(Arc::clone(&scheduler), &lifecycle, {
            let executions = Arc::clone(&executions);
            move |job| {
                executions.lock().expect("test mutex").push(job);
                Ok(job)
            }
        });

        assert_eq!(futures::executor::block_on(live_result), Ok(Ok(2)));
        assert_eq!(*executions.lock().expect("test mutex"), [2]);
        assert_eq!(scheduler.queued_evidence_bytes(), 0);
        lifecycle.release();
    }

    #[test]
    fn admission_purges_cancelled_work_before_applying_count_and_byte_caps() {
        let scheduler = super::PriorityScheduler::new(super::SchedulerLimits {
            block_count: 1,
            ..scheduler_limits()
        });
        let (cancelled, cancelled_result) = command(1, 10);
        scheduler
            .try_admit(super::WorkClass::Block, cancelled)
            .expect("first maximum block admitted");
        drop(cancelled_result);

        let (replacement, _replacement_result) = command(2, 10);
        scheduler
            .try_admit(super::WorkClass::Block, replacement)
            .expect("cancelled block is purged before admission caps");
        assert_eq!(scheduler.queued_evidence_bytes(), 10);
    }

    #[test]
    fn cancellation_partition_decides_each_identity_once_and_sums_that_exact_set() {
        use std::collections::VecDeque;

        let mut results = Vec::new();
        let mut queue = VecDeque::new();
        for (job, bytes) in [(1, 1), (2, 7), (3, 2)] {
            let (command, result) = command(job, bytes);
            queue.push_back(command);
            results.push(result);
        }
        let mut calls = [0u8; 4];

        let super::AccountingPartition {
            removed_bytes,
            removed,
        } = super::SchedulerState::partition_matching_once(&mut queue, |queued_command| {
            let position = usize::from(queued_command.job);
            calls[position] = calls[position].saturating_add(1);
            // A second observation deliberately changes its answer, modeling cancellation
            // changing between scans. The helper must never make that second observation.
            queued_command.job == 2 && calls[position] == 1
        })
        .expect("the exact removed-byte sum fits");

        assert_eq!(removed_bytes, 7);
        assert_eq!(calls, [0, 1, 1, 1]);
        assert_eq!(
            queue.iter().map(|command| command.job).collect::<Vec<_>>(),
            [1, 3]
        );
        assert_eq!(
            removed
                .iter()
                .map(|command| command.job)
                .collect::<Vec<_>>(),
            [2]
        );
        drop(removed);
        drop(results);
    }

    #[test]
    fn admission_destroys_cancelled_jobs_only_after_releasing_scheduler_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Weak};

        struct ReentrantDropJob {
            scheduler: Weak<super::PriorityScheduler<ReentrantDropJob, u8>>,
            lock_was_free: Arc<AtomicBool>,
        }

        impl Drop for ReentrantDropJob {
            fn drop(&mut self) {
                let lock_was_free = self
                    .scheduler
                    .upgrade()
                    .is_some_and(|scheduler| scheduler.state.try_lock().is_some());
                self.lock_was_free.store(lock_was_free, Ordering::SeqCst);
            }
        }

        let scheduler = Arc::new(super::PriorityScheduler::new(scheduler_limits()));
        let first_lock_was_free = Arc::new(AtomicBool::new(false));
        let (first_response, first_result) = futures::channel::oneshot::channel();
        scheduler
            .try_admit(
                super::WorkClass::Block,
                super::WorkerCommand {
                    job: ReentrantDropJob {
                        scheduler: Arc::downgrade(&scheduler),
                        lock_was_free: Arc::clone(&first_lock_was_free),
                    },
                    queued_evidence_bytes: 1,
                    response: first_response,
                },
            )
            .expect("first job admitted");
        drop(first_result);

        let second_lock_was_free = Arc::new(AtomicBool::new(false));
        let (second_response, second_result) = futures::channel::oneshot::channel();
        scheduler
            .try_admit(
                super::WorkClass::Block,
                super::WorkerCommand {
                    job: ReentrantDropJob {
                        scheduler: Arc::downgrade(&scheduler),
                        lock_was_free: Arc::clone(&second_lock_was_free),
                    },
                    queued_evidence_bytes: 1,
                    response: second_response,
                },
            )
            .expect("replacement job admitted after purge");

        assert!(first_lock_was_free.load(Ordering::SeqCst));
        drop(second_result);
        scheduler.close();
        let command = scheduler.pop().expect("replacement remains queued");
        drop(command);
        assert!(second_lock_was_free.load(Ordering::SeqCst));
    }

    #[test]
    fn owner_drop_drains_admitted_work_and_does_not_wait_for_active_work() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let scheduler = Arc::new(super::PriorityScheduler::new(scheduler_limits()));
        let (active, active_result) = command(1, 1);
        scheduler
            .try_admit(super::WorkClass::Block, active)
            .expect("active job admitted");
        let (queued, queued_result) = command(2, 1);
        scheduler
            .try_admit(super::WorkClass::Gossip, queued)
            .expect("queued job admitted");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let lifecycle = Box::leak(Box::new(ProverLifecycle::idle()));
        lifecycle.try_activate().expect("worker activates");
        let (exited_sender, exited_receiver) = mpsc::channel();
        let worker = {
            let scheduler = Arc::clone(&scheduler);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                super::run_worker_loop(scheduler, lifecycle, |job| {
                    if job == 1 {
                        entered.wait();
                        release.wait();
                    }
                    Ok(job)
                });
                let _ = exited_sender.send(());
            })
        };
        entered.wait();

        let owner = super::WorkerControl {
            scheduler: Some(Arc::clone(&scheduler)),
            worker: Some(worker),
        };
        let (dropped_sender, dropped_receiver) = mpsc::channel();
        std::thread::spawn(move || {
            drop(owner);
            let _ = dropped_sender.send(());
        });
        dropped_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("owner Drop is nonblocking while backend is active");
        release.wait();

        assert_eq!(futures::executor::block_on(active_result), Ok(Ok(1)));
        assert_eq!(futures::executor::block_on(queued_result), Ok(Ok(2)));
        exited_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("closed scheduler drains and exits");
    }

    #[test]
    fn admission_notifies_a_worker_already_waiting_on_the_condition_variable() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let waiting = Arc::new(Barrier::new(2));
        let scheduler = Arc::new(super::PriorityScheduler::new_with_wait_hook(
            scheduler_limits(),
            Arc::clone(&waiting),
        ));
        let (popped_sender, popped_receiver) = mpsc::channel();
        let worker = {
            let scheduler = Arc::clone(&scheduler);
            std::thread::spawn(move || {
                let popped = scheduler.pop().map(|command| command.job);
                let _ = popped_sender.send(popped);
            })
        };
        waiting.wait();

        let (admitted, admitted_result) = command(7, 1);
        scheduler
            .try_admit(super::WorkClass::Block, admitted)
            .expect("admission wakes waiting worker");

        assert_eq!(
            popped_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("notify_one wakes worker"),
            Some(7)
        );
        assert!(futures::executor::block_on(admitted_result).is_err());
        worker
            .join()
            .expect("waiting worker exits after one command");
    }

    #[test]
    fn close_notifies_a_waiting_worker_and_releases_its_lifecycle() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let waiting = Arc::new(Barrier::new(2));
        let scheduler = Arc::new(super::PriorityScheduler::<u8, u8>::new_with_wait_hook(
            scheduler_limits(),
            Arc::clone(&waiting),
        ));
        let lifecycle = Box::leak(Box::new(ProverLifecycle::idle()));
        lifecycle.try_activate().expect("worker activates");
        let active = super::ActiveProver::new(lifecycle);
        let (exited_sender, exited_receiver) = mpsc::channel();
        let worker = {
            let scheduler = Arc::clone(&scheduler);
            std::thread::spawn(move || {
                let _active = active;
                assert!(scheduler.pop().is_none());
                let _ = exited_sender.send(());
            })
        };
        waiting.wait();

        scheduler.close();

        exited_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("notify_all wakes closed worker");
        worker.join().expect("closed worker exits");
        assert_eq!(lifecycle.try_activate(), Ok(()));
        lifecycle.release();
    }

    #[test]
    fn worker_panic_resolves_active_and_queued_and_poison_lifecycle() {
        let scheduler = std::sync::Arc::new(super::PriorityScheduler::new(scheduler_limits()));
        let (active, active_result) = command(1, 1);
        scheduler
            .try_admit(super::WorkClass::Block, active)
            .expect("active job admitted");
        let (queued_block, queued_block_result) = command(2, 1);
        scheduler
            .try_admit(super::WorkClass::Block, queued_block)
            .expect("queued block admitted");
        let (queued_gossip, queued_gossip_result) = command(3, 1);
        scheduler
            .try_admit(super::WorkClass::Gossip, queued_gossip)
            .expect("queued gossip admitted");
        let (queued_aggregate, queued_aggregate_result) = command(4, 1);
        scheduler
            .try_admit(super::WorkClass::Aggregate, queued_aggregate)
            .expect("queued aggregate admitted");
        scheduler.close();
        let lifecycle = ProverLifecycle::idle();
        lifecycle.try_activate().expect("worker activates");

        super::run_worker_loop(scheduler, &lifecycle, |_job| -> Result<u8, _> {
            panic!("injected worker panic")
        });

        assert_eq!(
            futures::executor::block_on(active_result),
            Ok(Err(AggregationError::WorkerPanicked))
        );
        for queued in [
            queued_block_result,
            queued_gossip_result,
            queued_aggregate_result,
        ] {
            assert_eq!(
                futures::executor::block_on(queued),
                Ok(Err(AggregationError::WorkerStopped))
            );
        }
        assert_eq!(
            lifecycle.try_activate(),
            Err(ProverUnavailable::ProcessPoisoned)
        );
    }

    #[test]
    fn stopping_resolves_wakers_without_holding_the_scheduler_lock() {
        use futures::task::{ArcWake, waker_ref};
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};

        struct LockProbe {
            scheduler: Arc<super::PriorityScheduler<u8, u8>>,
            woken: AtomicBool,
            lock_was_free: AtomicBool,
        }

        impl ArcWake for LockProbe {
            fn wake_by_ref(probe: &Arc<Self>) {
                probe.woken.store(true, Ordering::SeqCst);
                probe
                    .lock_was_free
                    .store(probe.scheduler.state.try_lock().is_some(), Ordering::SeqCst);
            }
        }

        let scheduler = Arc::new(super::PriorityScheduler::new(scheduler_limits()));
        let (queued, mut result) = command(1, 1);
        scheduler
            .try_admit(super::WorkClass::Gossip, queued)
            .expect("queued job admitted");
        let probe = Arc::new(LockProbe {
            scheduler: Arc::clone(&scheduler),
            woken: AtomicBool::new(false),
            lock_was_free: AtomicBool::new(false),
        });
        let waker = waker_ref(&probe);
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut result).poll(&mut context),
            Poll::Pending
        ));

        scheduler.stop_and_resolve_queued();

        assert!(probe.woken.load(Ordering::SeqCst));
        assert!(probe.lock_was_free.load(Ordering::SeqCst));
        assert_eq!(
            futures::executor::block_on(result),
            Ok(Err(AggregationError::WorkerStopped))
        );
    }

    #[test]
    fn accounting_underflow_poison_stops_and_resolves_the_scheduler() {
        let scheduler = super::PriorityScheduler::new(scheduler_limits());
        let (queued, result) = command(1, 1);
        scheduler
            .try_admit(super::WorkClass::Block, queued)
            .expect("queued job admitted");
        scheduler.state.lock().block_bytes = 0;

        assert!(scheduler.pop().is_none());
        assert_eq!(
            futures::executor::block_on(result),
            Ok(Err(AggregationError::WorkerStopped))
        );
        assert!(scheduler.accounting_poisoned());
        let (replacement, _replacement_result) = command(2, 1);
        assert_eq!(
            scheduler.try_admit(super::WorkClass::Block, replacement),
            Err(super::SchedulerAdmissionError::Stopped)
        );
    }

    #[test]
    fn accounting_overflow_during_cancel_purge_poison_stops_admission() {
        let scheduler = super::PriorityScheduler::new(super::SchedulerLimits {
            block_count: 2,
            block_bytes: usize::MAX,
            total_bytes: usize::MAX,
            ..scheduler_limits()
        });
        let (first, first_result) = command(1, usize::MAX);
        let (second, second_result) = command(2, 1);
        drop((first_result, second_result));
        {
            let mut state = scheduler.state.lock();
            state.block.push_back(first);
            state.block.push_back(second);
            state.block_bytes = usize::MAX;
            state.total_bytes = usize::MAX;
        }

        let (replacement, _replacement_result) = command(3, 1);
        assert_eq!(
            scheduler.try_admit(super::WorkClass::Block, replacement),
            Err(super::SchedulerAdmissionError::Stopped)
        );
        assert!(scheduler.accounting_poisoned());
        assert_eq!(scheduler.queued_evidence_bytes(), 0);
        let (later, _later_result) = command(4, 1);
        assert_eq!(
            scheduler.try_admit(super::WorkClass::Block, later),
            Err(super::SchedulerAdmissionError::Stopped)
        );
    }

    #[test]
    fn scheduler_admission_failures_map_only_to_local_queue_saturation() {
        for error in [
            super::SchedulerAdmissionError::CountFull { max: 2 },
            super::SchedulerAdmissionError::ClassBytesFull {
                actual: 11,
                max: 10,
            },
            super::SchedulerAdmissionError::TotalBytesFull {
                actual: 31,
                max: 30,
            },
        ] {
            assert_eq!(
                error.into_aggregation_error(super::WorkClass::Block, &scheduler_limits()),
                AggregationError::ResourceExhausted(
                    crate::aggregation::AggregationResource::QueueSaturated { max_queued: 2 }
                )
            );
        }
    }

    #[test]
    fn aggregation_output_cap_reports_the_exact_local_overflow() {
        assert_eq!(super::validate_job_output_len(512, 512), Ok(()));
        assert_eq!(
            super::validate_job_output_len(513, 512),
            Err(AggregationError::OutputTooLarge {
                actual: 513,
                max: 512,
            })
        );
    }

    #[test]
    fn detached_worker_retains_lifecycle_ownership_until_it_exits() {
        use std::sync::{Arc, Barrier};

        let lifecycle = Box::leak(Box::new(ProverLifecycle::idle()));
        lifecycle.try_activate().expect("worker activates");
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let release = Arc::clone(&release);
            let active = super::ActiveProver::new(lifecycle);
            std::thread::spawn(move || {
                let _active = active;
                release.wait();
            })
        };

        assert_eq!(
            lifecycle.try_activate(),
            Err(ProverUnavailable::AlreadyActive)
        );
        release.wait();
        worker.join().expect("worker exits");
        assert_eq!(lifecycle.try_activate(), Ok(()));
        lifecycle.release();
    }

    #[test]
    fn aggregate_verification_bounds_signers_before_collecting_keys() {
        let empty = PqVerifyError::InvalidRequest(PqVerifyRequestError::EmptySignerSet);
        assert!(empty.source().is_some());
        assert!(PqVerifyError::InvalidEvidence.source().is_none());
        assert!(PqVerifyError::Internal.source().is_none());
        assert_eq!(
            validate_aggregate_signer_count(0),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::EmptySignerSet
            ))
        );
        assert_eq!(validate_aggregate_signer_count(PQ_MAX_SIGNERS), Ok(()));
        assert_eq!(
            validate_aggregate_signer_count(PQ_MAX_SIGNERS + 1),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::TooManySigners {
                    actual: PQ_MAX_SIGNERS + 1,
                    max: PQ_MAX_SIGNERS,
                }
            ))
        );
    }

    #[test]
    fn aggregate_verification_rejects_noncanonical_signer_context_before_backend_setup() {
        let evidence = PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\x01LMSI\x01\x01\x00")
            .expect("structurally bounded aggregate evidence");
        let first = PqPublicKey::deserialize(&[1; 32]).expect("fixed-size public key");
        let second = PqPublicKey::deserialize(&[2; 32]).expect("fixed-size public key");
        let claim = PqSigningClaim::new([0x42; 32], randao_id());

        assert_eq!(
            validate_canonical_signer_order(&[first, first]),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::DuplicateSigner
            ))
        );
        assert_eq!(
            verify_aggregate_evidence(&evidence, &[second, first], &claim),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::NonCanonicalSignerOrder
            ))
        );
        assert_eq!(
            verify_aggregate_evidence(&evidence, &[], &claim),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::EmptySignerSet
            ))
        );
        let oversized = vec![first; PQ_MAX_SIGNERS + 1];
        assert_eq!(
            verify_aggregate_evidence(&evidence, &oversized, &claim),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::TooManySigners {
                    actual: PQ_MAX_SIGNERS + 1,
                    max: PQ_MAX_SIGNERS,
                }
            ))
        );
    }

    #[test]
    fn aggregate_verification_rejects_non_aggregate_outer_kinds() {
        let key = signing_key(7);
        let claim = PqSigningClaim::new([0x42; 32], randao_id());
        let raw = key.sign(&claim).expect("raw signature");
        let raw_evidence = PqSameMessageEvidence::from(&raw);
        let absent = PqSameMessageEvidence::empty();

        assert_eq!(
            verify_aggregate_evidence(&raw_evidence, &[key.public_key()], &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
        assert_eq!(
            verify_aggregate_evidence(&absent, &[key.public_key()], &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
        let mismatched_inner_kind =
            PqSameMessageEvidence::from_bytes(b"LHPQ\x01\x01\x01LMSI\x01\x00\x00")
                .expect("generic wire decoding keeps the aggregate payload opaque");
        assert_eq!(
            verify_aggregate_evidence(&mismatched_inner_kind, &[key.public_key()], &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
    }

    #[test]
    fn raw_signature_retry_is_deterministic_and_verifies_without_a_prover() {
        let key = signing_key(1);
        let claim = PqSigningClaim::new([0x42; 32], randao_id());

        let first = key.sign(&claim).expect("first raw signature");
        let retry = key.sign(&claim).expect("same claim retry");

        assert_eq!(first, retry);
        assert_eq!(first.as_bytes().len(), 1_215);
        assert_eq!(&first.as_bytes()[..7], b"LHPQ\x01\x01\x00");
        verify_raw(&first, &key.public_key(), &claim)
            .expect("raw signature verifies without setup");
    }

    #[test]
    fn raw_verification_is_bound_to_root_key_and_one_time_use_id() {
        let key = signing_key(2);
        let wrong_key = signing_key(3);
        let claim = PqSigningClaim::new([0x42; 32], randao_id());
        let signature = key.sign(&claim).expect("raw signature");

        for result in [
            verify_raw(
                &signature,
                &key.public_key(),
                &PqSigningClaim::new([0x43; 32], randao_id()),
            ),
            verify_raw(&signature, &wrong_key.public_key(), &claim),
            verify_raw(
                &signature,
                &key.public_key(),
                &PqSigningClaim::new([0x42; 32], block_id()),
            ),
        ] {
            assert_eq!(result, Err(PqVerifyError::InvalidEvidence));
        }
    }

    #[test]
    fn raw_verification_rejects_noncanonical_backend_payload() {
        let key = signing_key(4);
        let claim = PqSigningClaim::new([0x42; 32], randao_id());
        let mut bytes = key.sign(&claim).expect("raw signature").as_bytes().to_vec();
        bytes[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
        let malformed = PqRawSignature::from_bytes(&bytes).expect("wire framing remains opaque");

        assert_eq!(
            verify_raw(&malformed, &key.public_key(), &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
    }

    #[test]
    fn signing_outside_the_key_range_is_an_invalid_request() {
        let key = signing_key(5);
        let outside_range = PqSigningClaim::new([0x42; 32], block_id());

        assert_eq!(
            key.sign(&outside_range),
            Err(PqSignError::InvalidSigningRequest)
        );
    }

    #[test]
    fn canonical_empty_raw_placeholder_never_verifies() {
        let key = signing_key(6);
        let claim = PqSigningClaim::new([0x42; 32], randao_id());
        let empty = PqRawSignature::empty();

        assert_eq!(empty.as_bytes().len(), 1_215);
        assert_eq!(
            verify_raw(&empty, &key.public_key(), &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
    }

    #[test]
    fn unavailable_build_mode_distinguishes_target_from_avx2_support() {
        assert_eq!(
            super::build_mode_unavailable_for(false, false),
            Some(ProverUnavailable::UnsupportedTarget)
        );
        assert_eq!(
            super::build_mode_unavailable_for(false, true),
            Some(ProverUnavailable::UnsupportedTarget)
        );
        assert_eq!(
            super::build_mode_unavailable_for(true, false),
            Some(ProverUnavailable::Avx2NotEnabledAtCompileTime)
        );
        assert_eq!(super::build_mode_unavailable_for(true, true), None);
    }

    #[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
    #[test]
    fn crate_owned_prover_refuses_a_build_without_avx2() {
        assert!(matches!(
            super::PqProver::new(),
            Err(super::ProverError::Unavailable(
                ProverUnavailable::Avx2NotEnabledAtCompileTime
            ))
        ));
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn crate_owned_prover_refuses_an_unsupported_target() {
        assert!(matches!(
            super::PqProver::new(),
            Err(super::ProverError::Unavailable(
                ProverUnavailable::UnsupportedTarget
            ))
        ));
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn pq_dependency_smoke() {
        use super::{PqProver, ProverError};
        use crate::aggregation::{
            AggregationContribution, AggregationJob, AggregationService, AggregationSigner,
            SameMessageClaim, VerificationClass,
        };
        use std::{sync::Arc, time::Instant};

        let service =
            Arc::new(AggregationService::new().expect("PQ prover worker starts and initializes"));
        assert!(matches!(
            PqProver::new(),
            Err(ProverError::Unavailable(ProverUnavailable::AlreadyActive))
        ));

        let one_time_use_id = randao_id();
        let claim = PqSigningClaim::new([0x42; 32], one_time_use_id);
        let first_signing_key = signing_key(0x11);
        let same_first_key = signing_key(0x11);
        let second_signing_key = signing_key(0x22);
        let wrong_key = signing_key(0x33);
        assert_eq!(first_signing_key.public_key(), same_first_key.public_key());

        let first_public_key = first_signing_key.public_key();
        let second_public_key = second_signing_key.public_key();
        let first_raw = first_signing_key
            .sign(&claim)
            .expect("first raw PQ signature");
        let second_raw = second_signing_key
            .sign(&claim)
            .expect("second raw PQ signature");
        verify_raw(&first_raw, &first_public_key, &claim).expect("raw signature verifies");

        let common_claim = SameMessageClaim::new([0x42; 32], one_time_use_id);
        let (first_index, second_index) = if first_public_key < second_public_key {
            (1, 0)
        } else {
            (0, 1)
        };
        let first_signer = AggregationSigner {
            validator_index: first_index,
            public_key: first_public_key,
        };
        let second_signer = AggregationSigner {
            validator_index: second_index,
            public_key: second_public_key,
        };
        let mut pair_signers = vec![first_signer.clone(), second_signer.clone()];
        pair_signers.sort_by_key(|signer| signer.validator_index);
        assert!(pair_signers[0].public_key > pair_signers[1].public_key);
        let started = Instant::now();
        let evidence = futures::executor::block_on(service.aggregate(AggregationJob {
            claim: common_claim,
            expected_signers: pair_signers.clone(),
            contributions: vec![
                AggregationContribution {
                    signers: vec![first_signer.clone()],
                    evidence: PqSameMessageEvidence::from(&first_raw),
                },
                AggregationContribution {
                    signers: vec![second_signer.clone()],
                    evidence: PqSameMessageEvidence::from(&second_raw),
                },
            ],
        }))
        .expect("two-signer PQ aggregate");
        eprintln!(
            "PQ two-raw aggregation: elapsed={:?}, evidence_bytes={}",
            started.elapsed(),
            evidence.as_bytes().len()
        );
        assert_eq!(&evidence.as_bytes()[..7], b"LHPQ\x01\x01\x01");
        assert_eq!(&evidence.as_bytes()[7..13], b"LMSI\x01\x01");

        let verification_started = Instant::now();
        let verified_evidence = futures::executor::block_on(service.verify(
            VerificationClass::Block,
            AggregationJob {
                claim: common_claim,
                expected_signers: pair_signers.clone(),
                contributions: vec![AggregationContribution {
                    signers: pair_signers.clone(),
                    evidence: evidence.clone(),
                }],
            },
        ))
        .expect("authentic two-signer aggregate verifies");
        let verification_elapsed = verification_started.elapsed();
        eprintln!(
            "PQ two-signer aggregate verification: elapsed={verification_elapsed:?}, evidence_bytes={}",
            verified_evidence.as_bytes().len(),
        );
        assert_eq!(verified_evidence, evidence);
        assert!(
            verification_elapsed <= std::time::Duration::from_secs(60),
            "authentic aggregate verification exceeds the frozen devnet budget",
        );

        let aggregate_executions_before = super::testing_only_aggregate_executions_started();
        let concurrent_service = Arc::clone(&service);
        let concurrent_signers = pair_signers.clone();
        let concurrent_first_signer = first_signer.clone();
        let concurrent_second_signer = second_signer.clone();
        let concurrent_first_evidence = PqSameMessageEvidence::from(&first_raw);
        let concurrent_second_evidence = PqSameMessageEvidence::from(&second_raw);
        let concurrent_started = Instant::now();
        let concurrent_aggregate = std::thread::spawn(move || {
            futures::executor::block_on(concurrent_service.aggregate(AggregationJob {
                claim: common_claim,
                expected_signers: concurrent_signers,
                contributions: vec![
                    AggregationContribution {
                        signers: vec![concurrent_first_signer],
                        evidence: concurrent_first_evidence,
                    },
                    AggregationContribution {
                        signers: vec![concurrent_second_signer],
                        evidence: concurrent_second_evidence,
                    },
                ],
            }))
        });
        while super::testing_only_aggregate_executions_started() == aggregate_executions_before {
            assert!(
                concurrent_started.elapsed() < std::time::Duration::from_secs(60),
                "the admitted real aggregate must begin inside its safe window",
            );
            std::thread::yield_now();
        }
        let critical_started = Instant::now();
        let critical = futures::executor::block_on(service.verify(
            VerificationClass::Block,
            AggregationJob {
                claim: common_claim,
                expected_signers: vec![first_signer.clone()],
                contributions: vec![AggregationContribution {
                    signers: vec![first_signer.clone()],
                    evidence: PqSameMessageEvidence::from(&first_raw),
                }],
            },
        ))
        .expect("Block-class verification admitted behind the real raw-plus-raw aggregate");
        assert_eq!(
            critical.as_bytes(),
            PqSameMessageEvidence::from(&first_raw).as_bytes()
        );
        assert!(
            critical_started.elapsed() <= std::time::Duration::from_secs(60),
            "the non-preemptive aggregate plus Block-class verification must fit the gate budget",
        );
        concurrent_aggregate
            .join()
            .expect("real aggregate caller thread")
            .expect("real aggregate completes before the critical request budget");
        assert!(
            concurrent_started.elapsed() <= std::time::Duration::from_secs(60),
            "the admitted real raw-plus-raw aggregate must fit the gate budget",
        );

        let third_signing_key = signing_key(0x44);
        let fourth_signing_key = signing_key(0x55);
        let third_signer = AggregationSigner {
            validator_index: 2,
            public_key: third_signing_key.public_key(),
        };
        let fourth_signer = AggregationSigner {
            validator_index: 3,
            public_key: fourth_signing_key.public_key(),
        };
        let third_raw = third_signing_key.sign(&claim).expect("third raw signature");
        let fourth_raw = fourth_signing_key
            .sign(&claim)
            .expect("fourth raw signature");

        let child_started = Instant::now();
        let second_child = futures::executor::block_on(service.aggregate(AggregationJob {
            claim: common_claim,
            expected_signers: vec![third_signer.clone(), fourth_signer.clone()],
            contributions: vec![
                AggregationContribution {
                    signers: vec![third_signer.clone()],
                    evidence: PqSameMessageEvidence::from(&third_raw),
                },
                AggregationContribution {
                    signers: vec![fourth_signer.clone()],
                    evidence: PqSameMessageEvidence::from(&fourth_raw),
                },
            ],
        }))
        .expect("second raw child aggregate");
        eprintln!(
            "PQ second two-raw aggregation: elapsed={:?}, evidence_bytes={}",
            child_started.elapsed(),
            second_child.as_bytes().len()
        );

        let raw_child_started = Instant::now();
        let raw_plus_child = futures::executor::block_on(
            service.aggregate(AggregationJob {
                claim: common_claim,
                expected_signers: pair_signers
                    .iter()
                    .cloned()
                    .chain([third_signer.clone()])
                    .collect(),
                contributions: vec![
                    AggregationContribution {
                        signers: pair_signers.clone(),
                        evidence: evidence.clone(),
                    },
                    AggregationContribution {
                        signers: vec![third_signer.clone()],
                        evidence: PqSameMessageEvidence::from(&third_raw),
                    },
                ],
            }),
        )
        .expect("raw plus child aggregate recurses");
        eprintln!(
            "PQ raw-plus-child aggregation: elapsed={:?}, evidence_bytes={}",
            raw_child_started.elapsed(),
            raw_plus_child.as_bytes().len()
        );

        let children_started = Instant::now();
        let children = futures::executor::block_on(
            service.aggregate(AggregationJob {
                claim: common_claim,
                expected_signers: pair_signers
                    .iter()
                    .cloned()
                    .chain([third_signer.clone(), fourth_signer.clone()])
                    .collect(),
                contributions: vec![
                    AggregationContribution {
                        signers: pair_signers.clone(),
                        evidence: evidence.clone(),
                    },
                    AggregationContribution {
                        signers: vec![third_signer, fourth_signer],
                        evidence: second_child,
                    },
                ],
            }),
        )
        .expect("aggregate plus aggregate recurses");
        eprintln!(
            "PQ child-plus-child aggregation: elapsed={:?}, evidence_bytes={}",
            children_started.elapsed(),
            children.as_bytes().len()
        );

        assert_eq!(
            futures::executor::block_on(service.aggregate(AggregationJob {
                claim: SameMessageClaim::new([0x43; 32], one_time_use_id),
                expected_signers: pair_signers.clone(),
                contributions: vec![AggregationContribution {
                    signers: pair_signers.clone(),
                    evidence: evidence.clone(),
                }],
            })),
            Err(AggregationError::InvalidEvidence)
        );

        let mut expected_signers = [first_public_key, second_public_key];
        expected_signers.sort();
        verify_aggregate_evidence(&evidence, &expected_signers, &claim)
            .expect("encoded aggregate verifies");

        let wrong_claim = PqSigningClaim::new([0x43; 32], one_time_use_id);
        let wrong_id_claim = PqSigningClaim::new([0x42; 32], block_id());
        let missing_signer = [expected_signers[0]];
        let mut extra_signer = [first_public_key, second_public_key, wrong_key.public_key()];
        extra_signer.sort();
        let mut wrong_signer = [first_public_key, wrong_key.public_key()];
        wrong_signer.sort();
        for result in [
            verify_aggregate_evidence(&evidence, &missing_signer, &claim),
            verify_aggregate_evidence(&evidence, &extra_signer, &claim),
            verify_aggregate_evidence(&evidence, &wrong_signer, &claim),
            verify_aggregate_evidence(&evidence, &expected_signers, &wrong_claim),
            verify_aggregate_evidence(&evidence, &expected_signers, &wrong_id_claim),
        ] {
            assert_eq!(result, Err(PqVerifyError::InvalidEvidence));
        }

        assert_eq!(
            verify_aggregate_evidence(
                &evidence,
                &[expected_signers[0], expected_signers[0]],
                &claim,
            ),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::DuplicateSigner
            ))
        );
        assert_eq!(
            verify_aggregate_evidence(
                &evidence,
                &[expected_signers[1], expected_signers[0]],
                &claim,
            ),
            Err(PqVerifyError::InvalidRequest(
                PqVerifyRequestError::NonCanonicalSignerOrder
            ))
        );

        for malformed_bytes in [
            &evidence.as_bytes()[..evidence.as_bytes().len() - 1],
            b"LHPQ\x01\x01\x01LMSI\x01\x01".as_slice(),
        ] {
            let malformed = PqSameMessageEvidence::from_bytes(malformed_bytes)
                .expect("generic wire decoding intentionally keeps payload opaque");
            assert_eq!(
                verify_aggregate_evidence(&malformed, &expected_signers, &claim),
                Err(PqVerifyError::InvalidEvidence)
            );
        }

        let mut trailing_bytes = evidence.as_bytes().to_vec();
        trailing_bytes.push(0);
        let trailing = PqSameMessageEvidence::from_bytes(&trailing_bytes)
            .expect("generic wire decoding intentionally keeps payload opaque");
        assert_eq!(
            verify_aggregate_evidence(&trailing, &expected_signers, &claim),
            Err(PqVerifyError::InvalidEvidence)
        );

        let mut corrupted_bytes = evidence.as_bytes().to_vec();
        let last_byte = corrupted_bytes
            .last_mut()
            .expect("aggregate evidence is nonempty");
        *last_byte ^= 1;
        let corrupted = PqSameMessageEvidence::from_bytes(&corrupted_bytes)
            .expect("generic wire decoding intentionally keeps payload opaque");
        assert_eq!(
            verify_aggregate_evidence(&corrupted, &expected_signers, &claim),
            Err(PqVerifyError::InvalidEvidence)
        );
        let backend_public_keys = expected_signers
            .iter()
            .map(PqPublicKey::backend_bytes)
            .collect::<Vec<_>>();
        let corrupted_signature = super::backend::decode_aggregate_signature(
            corrupted
                .backend_aggregate_envelope()
                .expect("aggregate outer kind"),
            &backend_public_keys,
            &claim,
        )
        .expect("the mutation preserves the upstream aggregate encoding");
        let proof_error =
            super::backend::verify_signature(&corrupted_signature, &backend_public_keys, &claim)
                .expect_err("the mutated proof is invalid");
        assert!(matches!(proof_error, lean_multisig::Error::Proof(_)));
        assert_eq!(
            PqVerifyError::from_aggregate_backend(proof_error),
            PqVerifyError::InvalidEvidence
        );
    }

    #[test]
    fn post_verification_backend_failures_are_local_internal_errors() {
        assert_eq!(
            super::classify_local_backend_error(lean_multisig::Error::MalformedSignature),
            AggregationError::Internal
        );
        assert_eq!(
            super::classify_local_backend_error(lean_multisig::Error::NotInitialized),
            AggregationError::Internal
        );
    }

    #[test]
    fn backend_errors_default_to_local_unless_explicitly_classified() {
        assert_eq!(
            PqVerifyError::from_backend(lean_multisig::Error::MalformedSignature),
            PqVerifyError::InvalidEvidence
        );
        assert_eq!(
            PqVerifyError::from_backend(lean_multisig::Error::MalformedPublicKey),
            PqVerifyError::Internal
        );
        assert_eq!(
            PqVerifyError::from_backend(lean_multisig::Error::NotInitialized),
            PqVerifyError::Internal
        );
    }

    #[test]
    fn caught_backend_panic_permanently_poisons_the_process_lifecycle() {
        let lifecycle = ProverLifecycle::idle();
        assert_eq!(lifecycle.try_activate(), Ok(()));
        assert_eq!(
            lifecycle.try_activate(),
            Err(ProverUnavailable::AlreadyActive)
        );
        lifecycle.release();
        assert_eq!(lifecycle.try_activate(), Ok(()));

        assert!(catch_backend_panic(&lifecycle, || panic!("injected backend panic")).is_err());
        lifecycle.release();

        assert_eq!(
            lifecycle.try_activate(),
            Err(ProverUnavailable::ProcessPoisoned)
        );
    }
}
