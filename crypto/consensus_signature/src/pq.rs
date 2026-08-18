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

mod backend;
pub use crate::{
    PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_PUBLIC_KEY_LEN, PQ_RAW_SIGNATURE_LEN, PqPublicKey,
    PqRawSignature, PqSameMessageEvidence, PqWireError,
};

use crate::OneTimeUseId;
use crate::pq_wire::PQ_EVIDENCE_HEADER_LEN;
use backend::BackendSignature;
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

/// One strict raw signature paired with the public key needed to reconstruct backend context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqRawContribution {
    signature: PqRawSignature,
    public_key: PqPublicKey,
}

impl PqRawContribution {
    pub const fn new(signature: PqRawSignature, public_key: PqPublicKey) -> Self {
        Self {
            signature,
            public_key,
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    fn decode(&self, claim: &PqSigningClaim) -> Result<BackendSignature, AggregateError> {
        backend::decode_aggregate_input(
            self.signature.backend_payload(),
            self.public_key.backend_bytes(),
            claim,
        )
        .map_err(AggregateError::from_backend_failure)
    }
}

/// An in-memory aggregate proof produced by the owned prover.
///
/// Its network encoding is available only through [`Self::into_same_message_evidence`], which
/// validates the frozen output bound before constructing same-message evidence.
#[derive(Clone, Debug)]
pub struct PqAggregateSignature(BackendSignature);

impl PqAggregateSignature {
    /// Converts a locally proved aggregate into bounded Lighthouse same-message evidence.
    ///
    /// The complete pinned upstream `LMSI` envelope is retained inside the Lighthouse aggregate
    /// payload. No public API can construct this type from arbitrary bytes.
    pub fn into_same_message_evidence(self) -> Result<PqSameMessageEvidence, AggregateError> {
        let envelope = backend::encode_aggregate_signature(&self.0)
            .map_err(|error| AggregateError::Internal(PqBackendError(error)))?;
        let evidence_len = PQ_EVIDENCE_HEADER_LEN.saturating_add(envelope.len());
        validate_aggregate_evidence_len(evidence_len)?;
        Ok(PqSameMessageEvidence::from_backend_aggregate_envelope(
            envelope,
        ))
    }
}

/// Verifies one in-memory aggregate against its exact claim and signer set.
pub fn verify_aggregate(
    signature: &PqAggregateSignature,
    public_keys: &[PqPublicKey],
    claim: &PqSigningClaim,
) -> Result<(), PqVerifyError> {
    validate_aggregate_signer_count(public_keys.len())?;
    validate_canonical_signer_order(public_keys)?;
    let public_keys = public_keys
        .iter()
        .map(PqPublicKey::backend_bytes)
        .collect::<Vec<_>>();
    backend::verify_signature(&signature.0, &public_keys, claim)
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
        match pair[0].cmp(&pair[1]) {
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
use std::panic::{AssertUnwindSafe, catch_unwind};
#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use std::thread::{Builder, JoinHandle};

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
const PQ_WORKER_STACK_SIZE: usize = 512 * 1024 * 1024;
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
static PQ_PROVER_LIFECYCLE: ProverLifecycle = ProverLifecycle::idle();

/// A local build or process state that cannot provide the experimental prover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverUnavailable {
    /// The pinned prover is currently supported only on x86-64.
    UnsupportedTarget,
    /// The binary was not compiled in the required AVX2-only mode.
    Avx2NotEnabledAtCompileTime,
    /// A prover worker already owns the process-wide upstream proving state.
    AlreadyActive,
    /// A caught backend panic may have poisoned process-wide upstream proving state.
    ProcessPoisoned,
}

impl std::fmt::Display for ProverUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnsupportedTarget => "the PQ prover is supported only on x86-64",
            Self::Avx2NotEnabledAtCompileTime => {
                "the PQ prover requires an AVX2-only binary and launcher preflight"
            }
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
pub enum ProverError {
    /// The build or process state cannot host the prover.
    Unavailable(ProverUnavailable),
    /// The operating system refused to create the dedicated worker.
    WorkerSpawn(std::io::Error),
    /// Upstream setup panicked on the dedicated worker.
    InitializationPanicked,
    /// The worker stopped before reporting its initialization result.
    InitializationWorkerStopped,
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "PQ prover unavailable: {error}"),
            Self::WorkerSpawn(error) => {
                write!(formatter, "failed to spawn PQ prover worker: {error}")
            }
            Self::InitializationPanicked => formatter.write_str("PQ prover setup panicked"),
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
            Self::WorkerSpawn(error) => Some(error),
            Self::InitializationPanicked | Self::InitializationWorkerStopped => None,
        }
    }
}

/// A failure to aggregate PQ evidence.
#[derive(Debug)]
pub enum AggregateError {
    /// Peer-supplied evidence is malformed or does not prove the requested claim/signers.
    InvalidEvidence(PqBackendError),
    /// The owned job is empty or exceeds an upstream protocol limit.
    InvalidRequest(PqAggregateRequestError),
    /// A locally produced proof exceeds the frozen devnet resource limit.
    Resource(PqAggregateResourceError),
    /// The local prover is unavailable before a worker exists.
    Unavailable(ProverUnavailable),
    /// The worker stopped before accepting or answering this job.
    WorkerStopped,
    /// Upstream aggregation panicked. The worker stops after reporting this error.
    WorkerPanicked,
    /// An upstream failure that must not be attributed to peer evidence.
    Internal(PqBackendError),
}

/// A backend-independent invalid aggregate-proving request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAggregateRequestError {
    Empty,
    TooManyContributions { actual: usize, max: usize },
}

/// A bounded local aggregate-output failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAggregateResourceError {
    ProofTooLarge { actual: usize, max: usize },
}

impl std::fmt::Display for PqAggregateResourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofTooLarge { actual, max } => {
                write!(formatter, "PQ proof length {actual} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for PqAggregateResourceError {}

impl std::fmt::Display for PqAggregateRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("no PQ contributions supplied"),
            Self::TooManyContributions { actual, max } => write!(
                formatter,
                "too many PQ contributions: {actual}, maximum {max}"
            ),
        }
    }
}

impl std::error::Error for PqAggregateRequestError {}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
fn validate_aggregate_contribution_count(count: usize) -> Result<(), AggregateError> {
    if count == 0 {
        return Err(AggregateError::InvalidRequest(
            PqAggregateRequestError::Empty,
        ));
    }
    if count > PQ_MAX_SIGNERS {
        return Err(AggregateError::InvalidRequest(
            PqAggregateRequestError::TooManyContributions {
                actual: count,
                max: PQ_MAX_SIGNERS,
            },
        ));
    }
    Ok(())
}

fn validate_aggregate_evidence_len(length: usize) -> Result<(), AggregateError> {
    if length > PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN {
        return Err(AggregateError::Resource(
            PqAggregateResourceError::ProofTooLarge {
                actual: length,
                max: PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN,
            },
        ));
    }
    Ok(())
}

impl AggregateError {
    #[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
    fn from_backend_failure(failure: backend::AggregateFailure) -> Self {
        let category = failure.category();
        let error = PqBackendError(failure.into_error());
        match category {
            backend::AggregateFailureCategory::PeerInvalidEvidence => Self::InvalidEvidence(error),
            backend::AggregateFailureCategory::LocallyGeneratedProof
            | backend::AggregateFailureCategory::Internal => Self::Internal(error),
        }
    }
}

/// Opaque diagnostic detail from the exact pinned backend.
#[derive(Debug)]
pub struct PqBackendError(backend::BackendError);

impl std::fmt::Display for PqBackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for PqBackendError {}

impl std::fmt::Display for AggregateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence(error) => write!(formatter, "invalid PQ evidence: {error}"),
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid PQ aggregation request: {error}")
            }
            Self::Resource(error) => write!(formatter, "PQ aggregation resource limit: {error}"),
            Self::Unavailable(error) => write!(formatter, "PQ prover unavailable: {error}"),
            Self::WorkerStopped => formatter.write_str("PQ prover worker stopped"),
            Self::WorkerPanicked => formatter.write_str("PQ prover worker panicked"),
            Self::Internal(error) => write!(formatter, "internal PQ prover failure: {error}"),
        }
    }
}

impl std::error::Error for AggregateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEvidence(error) | Self::Internal(error) => Some(error),
            Self::InvalidRequest(error) => Some(error),
            Self::Resource(error) => Some(error),
            Self::Unavailable(error) => Some(error),
            Self::WorkerStopped | Self::WorkerPanicked => None,
        }
    }
}

/// The process-wide owner of recursive-proof setup and aggregation.
///
/// Construction starts one named OS thread with a 512 MiB stack and initializes upstream proving
/// state there. Every aggregate job owns its signatures and claim and is executed serially on the
/// same worker. This type is intentionally not cloneable, and a second live instance is rejected.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub struct PqProver {
    commands: SyncSender<Command>,
    worker: Option<JoinHandle<()>>,
    _active: ActiveProver,
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
pub struct PqProver {
    _unavailable: (),
}

impl PqProver {
    /// Starts and initializes the singleton prover worker.
    pub fn new() -> Result<Self, ProverError> {
        start_prover()
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl PqProver {
    /// Runs one owned aggregate job on the serialized prover worker.
    pub fn aggregate(
        &self,
        contributions: Vec<PqRawContribution>,
        claim: PqSigningClaim,
    ) -> Result<PqAggregateSignature, AggregateError> {
        validate_aggregate_contribution_count(contributions.len())?;
        let signatures = contributions
            .iter()
            .map(|contribution| contribution.decode(&claim))
            .collect::<Result<Vec<_>, _>>()?;
        let (response_sender, response_receiver) = sync_channel(1);
        self.commands
            .send(Command::Aggregate {
                signatures,
                claim,
                response: response_sender,
            })
            .map_err(|_| AggregateError::WorkerStopped)?;
        response_receiver
            .recv()
            .map_err(|_| AggregateError::WorkerStopped)?
            .map(PqAggregateSignature)
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
impl PqProver {
    /// Refuses proving in a build that cannot create this type through [`Self::new`].
    pub fn aggregate(
        &self,
        _contributions: Vec<PqRawContribution>,
        _claim: PqSigningClaim,
    ) -> Result<PqAggregateSignature, AggregateError> {
        Err(AggregateError::Unavailable(build_mode_unavailable()))
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl Drop for PqProver {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
enum Command {
    Aggregate {
        signatures: Vec<BackendSignature>,
        claim: PqSigningClaim,
        response: SyncSender<Result<BackendSignature, AggregateError>>,
    },
    Shutdown,
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
struct ActiveProver;

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl Drop for ActiveProver {
    fn drop(&mut self) {
        PQ_PROVER_LIFECYCLE.release();
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

#[cfg(not(target_arch = "x86_64"))]
fn start_prover() -> Result<PqProver, ProverError> {
    Err(ProverError::Unavailable(build_mode_unavailable()))
}

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
fn start_prover() -> Result<PqProver, ProverError> {
    Err(ProverError::Unavailable(build_mode_unavailable()))
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn start_prover() -> Result<PqProver, ProverError> {
    PQ_PROVER_LIFECYCLE
        .try_activate()
        .map_err(ProverError::Unavailable)?;
    let active = ActiveProver;
    let (command_sender, command_receiver) = sync_channel(1);
    let (initialization_sender, initialization_receiver) = sync_channel(1);
    let worker = Builder::new()
        .name("pq-prover".into())
        .stack_size(PQ_WORKER_STACK_SIZE)
        .spawn(move || worker_main(command_receiver, initialization_sender))
        .map_err(ProverError::WorkerSpawn)?;

    match initialization_receiver.recv() {
        Ok(InitializationResult::Ready) => Ok(PqProver {
            commands: command_sender,
            worker: Some(worker),
            _active: active,
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
fn worker_main(commands: Receiver<Command>, initialized: SyncSender<InitializationResult>) {
    let setup_result = catch_backend_panic(&PQ_PROVER_LIFECYCLE, backend::setup);
    if setup_result.is_err() {
        let _ = initialized.send(InitializationResult::Panicked);
        return;
    }
    if initialized.send(InitializationResult::Ready).is_err() {
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            Command::Aggregate {
                signatures,
                claim,
                response,
            } => {
                let aggregate_result = catch_backend_panic(&PQ_PROVER_LIFECYCLE, || {
                    backend::aggregate(signatures, &claim)
                });
                match aggregate_result {
                    Ok(result) => {
                        let _ = response.send(result.map_err(AggregateError::from_backend_failure));
                    }
                    Err(_) => {
                        let _ = response.send(Err(AggregateError::WorkerPanicked));
                        break;
                    }
                }
            }
            Command::Shutdown => break,
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
const fn build_mode_unavailable() -> ProverUnavailable {
    ProverUnavailable::UnsupportedTarget
}

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
const fn build_mode_unavailable() -> ProverUnavailable {
    ProverUnavailable::Avx2NotEnabledAtCompileTime
}

#[cfg(test)]
mod tests {
    use super::{
        AggregateError, PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_MAX_SIGNERS, PqAggregateRequestError,
        PqAggregateResourceError, PqBackendError, PqPublicKey, PqRawSignature,
        PqSameMessageEvidence, PqSignError, PqSigningClaim, PqUnreservedSigningKey, PqVerifyError,
        PqVerifyRequestError, ProverLifecycle, ProverUnavailable, catch_backend_panic,
        validate_aggregate_contribution_count, validate_aggregate_evidence_len,
        validate_aggregate_signer_count, validate_canonical_signer_order,
        verify_aggregate_evidence, verify_raw,
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
    fn contribution_limit_is_checked_before_backend_decoding() {
        assert!(validate_aggregate_contribution_count(PQ_MAX_SIGNERS).is_ok());
        assert!(matches!(
            validate_aggregate_contribution_count(0),
            Err(AggregateError::InvalidRequest(
                PqAggregateRequestError::Empty
            ))
        ));
        assert!(matches!(
            validate_aggregate_contribution_count(PQ_MAX_SIGNERS + 1),
            Err(AggregateError::InvalidRequest(
                PqAggregateRequestError::TooManyContributions { actual, max }
            )) if actual == PQ_MAX_SIGNERS + 1 && max == PQ_MAX_SIGNERS
        ));
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
    fn aggregate_evidence_size_is_checked_without_allocating_the_payload() {
        assert!(validate_aggregate_evidence_len(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN).is_ok());
        assert!(matches!(
            validate_aggregate_evidence_len(PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1),
            Err(AggregateError::Resource(
                PqAggregateResourceError::ProofTooLarge { actual, max }
            )) if actual == PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN + 1
                && max == PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN
        ));
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
    fn opaque_backend_error_terminates_the_public_source_chain() {
        let range_start = 1;
        let range_end = 0;
        let upstream = super::backend::signing_key_from_seed([0; 32], range_start..=range_end)
            .expect_err("reversed key range is invalid");
        let error = PqBackendError(super::backend::BackendError::from_upstream(upstream));

        assert!(error.source().is_none());
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

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn pq_dependency_smoke() {
        use super::{PqProver, PqRawContribution, ProverError};

        let prover = PqProver::new().expect("PQ prover worker starts and initializes");
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

        assert!(matches!(
            prover.aggregate(Vec::new(), claim),
            Err(AggregateError::InvalidRequest(_))
        ));
        let aggregate = prover
            .aggregate(
                vec![
                    PqRawContribution::new(first_raw, first_public_key),
                    PqRawContribution::new(second_raw, second_public_key),
                ],
                claim,
            )
            .expect("two-signer PQ aggregate");
        let evidence = aggregate
            .into_same_message_evidence()
            .expect("bounded Lighthouse aggregate evidence");
        assert_eq!(&evidence.as_bytes()[..7], b"LHPQ\x01\x01\x01");
        assert_eq!(&evidence.as_bytes()[7..13], b"LMSI\x01\x01");

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
    fn semantic_local_proof_failure_maps_to_internal() {
        let failure = super::backend::injected_aggregate_failure(
            super::backend::AggregateFailureCategory::LocallyGeneratedProof,
        );

        assert!(matches!(
            AggregateError::from_backend_failure(failure),
            AggregateError::Internal(_)
        ));

        let failure = super::backend::injected_aggregate_failure(
            super::backend::AggregateFailureCategory::PeerInvalidEvidence,
        );
        assert!(matches!(
            AggregateError::from_backend_failure(failure),
            AggregateError::InvalidEvidence(_)
        ));

        let failure = super::backend::injected_aggregate_failure(
            super::backend::AggregateFailureCategory::Internal,
        );
        assert!(matches!(
            AggregateError::from_backend_failure(failure),
            AggregateError::Internal(_)
        ));
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
