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
use crate::aggregation::InvalidAggregationJob;
use crate::aggregation::{AggregationError, ValidatedAggregationJob};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use crate::aggregation::{AggregationResource, V1_MAX_AGGREGATION_OUTPUT_BYTES};
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
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::sync::mpsc::Receiver;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::thread::{Builder, JoinHandle};

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
const PQ_WORKER_STACK_SIZE: usize = 512 * 1024 * 1024;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
static PQ_PROVER_LIFECYCLE: ProverLifecycle = ProverLifecycle::idle();

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
    commands: Option<SyncSender<Command>>,
    worker: Option<JoinHandle<()>>,
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
        let commands = self
            .commands
            .as_ref()
            .ok_or(AggregationError::WorkerStopped)?;
        let (response, result) = oneshot::channel();
        commands
            .try_send(Command { job, response })
            .map_err(|error| match error {
                TrySendError::Full(_) => {
                    AggregationError::ResourceExhausted(AggregationResource::QueueSaturated {
                        max_queued: 1,
                    })
                }
                TrySendError::Disconnected(_) => AggregationError::WorkerStopped,
            })?;
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
        } = job;
        drop((claim, expected_signers, contributions));
        Err(AggregationError::Unavailable)
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl Drop for PqProver {
    fn drop(&mut self) {
        // Disconnecting drains the one admitted queued job and then stops the worker. Dropping the
        // join handle detaches instead of blocking an async caller. The worker owns ActiveProver,
        // so a replacement cannot start until every admitted proof has completed safely.
        self.commands.take();
        self.worker.take();
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
type Command = WorkerCommand<ValidatedAggregationJob, PqSameMessageEvidence>;

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
struct WorkerCommand<Job, Output> {
    job: Job,
    response: oneshot::Sender<Result<Output, AggregationError>>,
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
    let (command_sender, command_receiver) = sync_channel(1);
    let (initialization_sender, initialization_receiver) = sync_channel(1);
    let worker = Builder::new()
        .name("pq-prover".into())
        .stack_size(PQ_WORKER_STACK_SIZE)
        .spawn(move || worker_main(command_receiver, initialization_sender, active))
        .map_err(ProverError::WorkerSpawn)?;

    match initialization_receiver.recv() {
        Ok(InitializationResult::Ready) => Ok(PqProver {
            commands: Some(command_sender),
            worker: Some(worker),
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
    commands: Receiver<Command>,
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

    run_worker_loop(commands, &PQ_PROVER_LIFECYCLE, execute_aggregation_job);
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn run_worker_loop<Job, Output>(
    commands: Receiver<WorkerCommand<Job, Output>>,
    lifecycle: &ProverLifecycle,
    mut execute: impl FnMut(Job) -> Result<Output, AggregationError>,
) {
    while let Ok(command) = commands.recv() {
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
        };
        assert_eq!(
            super::execute_aggregation_job(wrong_key_job),
            Err(AggregationError::InvalidEvidence)
        );
    }

    #[test]
    fn bounded_worker_saturates_at_one_queued_job_and_skips_cancelled_work() {
        use futures::channel::oneshot;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc::{TrySendError, sync_channel};
        use std::sync::{Arc, Barrier};

        let lifecycle = Arc::new(ProverLifecycle::idle());
        lifecycle.try_activate().expect("test worker activates");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let executions = Arc::new(AtomicUsize::new(0));
        let (commands, receiver) = sync_channel(1);
        let worker = {
            let lifecycle = Arc::clone(&lifecycle);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let executions = Arc::clone(&executions);
            std::thread::Builder::new()
                .name("pq-prover-test".into())
                .spawn(move || {
                    super::run_worker_loop(receiver, &lifecycle, |job| {
                        assert_eq!(std::thread::current().name(), Some("pq-prover-test"));
                        executions.fetch_add(1, Ordering::SeqCst);
                        if job == 1 {
                            entered.wait();
                            release.wait();
                        }
                        Ok(job)
                    });
                })
                .expect("test worker starts")
        };

        let (first_response, first_result) = oneshot::channel();
        commands
            .try_send(super::WorkerCommand {
                job: 1,
                response: first_response,
            })
            .expect("active job admitted");
        entered.wait();

        let (cancelled_response, cancelled_result) = oneshot::channel();
        commands
            .try_send(super::WorkerCommand {
                job: 2,
                response: cancelled_response,
            })
            .expect("one queued job admitted");
        drop(cancelled_result);

        let (overflow_response, _overflow_result) = oneshot::channel();
        assert!(matches!(
            commands.try_send(super::WorkerCommand {
                job: 3,
                response: overflow_response,
            }),
            Err(TrySendError::Full(_))
        ));

        release.wait();
        assert_eq!(
            futures::executor::block_on(first_result).expect("worker responds"),
            Ok(1)
        );
        drop(commands);
        worker.join().expect("worker exits after disconnect");
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_panic_poisoning_stop_and_output_error_are_classified() {
        use futures::channel::oneshot;
        use std::sync::Arc;
        use std::sync::mpsc::sync_channel;

        let output_lifecycle = Arc::new(ProverLifecycle::idle());
        output_lifecycle
            .try_activate()
            .expect("output worker activates");
        let (output_commands, output_receiver) = sync_channel(1);
        let output_worker = {
            let lifecycle = Arc::clone(&output_lifecycle);
            std::thread::spawn(move || {
                super::run_worker_loop(output_receiver, &lifecycle, |_job: u8| -> Result<u8, _> {
                    Err(AggregationError::OutputTooLarge {
                        actual: 513,
                        max: 512,
                    })
                });
            })
        };
        let (output_response, output_result) = oneshot::channel();
        output_commands
            .try_send(super::WorkerCommand {
                job: 1,
                response: output_response,
            })
            .expect("output job admitted");
        assert_eq!(
            futures::executor::block_on(output_result).expect("worker responds"),
            Err(AggregationError::OutputTooLarge {
                actual: 513,
                max: 512,
            })
        );
        drop(output_commands);
        output_worker.join().expect("output worker stops");
        output_lifecycle.release();

        let panic_lifecycle = Arc::new(ProverLifecycle::idle());
        panic_lifecycle
            .try_activate()
            .expect("panic worker activates");
        let (panic_commands, panic_receiver) = sync_channel(1);
        let panic_worker = {
            let lifecycle = Arc::clone(&panic_lifecycle);
            std::thread::spawn(move || {
                super::run_worker_loop(panic_receiver, &lifecycle, |_job: u8| -> Result<u8, _> {
                    panic!("injected worker panic")
                });
            })
        };
        let (panic_response, panic_result) = oneshot::channel();
        panic_commands
            .try_send(super::WorkerCommand {
                job: 1,
                response: panic_response,
            })
            .expect("panic job admitted");
        assert_eq!(
            futures::executor::block_on(panic_result).expect("panic is contained"),
            Err(AggregationError::WorkerPanicked)
        );
        panic_worker.join().expect("panic is caught inside worker");
        assert_eq!(
            panic_lifecycle.try_activate(),
            Err(ProverUnavailable::ProcessPoisoned)
        );
        let (stopped_response, _stopped_result) = oneshot::channel();
        assert!(
            panic_commands
                .try_send(super::WorkerCommand {
                    job: 2,
                    response: stopped_response,
                })
                .is_err()
        );
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
            SameMessageClaim,
        };
        use std::time::Instant;

        let service = AggregationService::new().expect("PQ prover worker starts and initializes");
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
                    signers: vec![first_signer],
                    evidence: PqSameMessageEvidence::from(&first_raw),
                },
                AggregationContribution {
                    signers: vec![second_signer],
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
