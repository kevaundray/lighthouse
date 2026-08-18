//! Narrow import and execution boundary for the experimental leanMultisig backend.
//!
//! The pinned prover requires an AVX2-only x86-64 build. Host capability must be checked by the
//! launcher before starting that binary: a globally AVX2-compiled binary cannot safely discover
//! an incompatible CPU after process startup. Scalar builds retain this module for workspace
//! compatibility, but [`PqProver::new`] refuses to create a working prover.

pub use lean_multisig::{Claim, Error, PublicKey, SecretKey, Signature, verify};

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
    InvalidEvidence(Error),
    /// The owned job is empty or exceeds an upstream protocol limit.
    InvalidRequest(Error),
    /// The local prover is unavailable before a worker exists.
    Unavailable(ProverUnavailable),
    /// The worker stopped before accepting or answering this job.
    WorkerStopped,
    /// Upstream aggregation panicked. The worker stops after reporting this error.
    WorkerPanicked,
    /// An upstream failure that must not be attributed to peer evidence.
    Internal(Error),
}

impl From<Error> for AggregateError {
    fn from(error: Error) -> Self {
        match &error {
            Error::InvalidSignature { .. }
            | Error::Proof(_)
            | Error::MalformedSignature
            | Error::MalformedMultiClaimProof
            | Error::MalformedPublicKey
            | Error::MessageMismatch
            | Error::SignerSetMismatch
            | Error::ClaimSetMismatch => Self::InvalidEvidence(error),
            Error::TooManySigners { .. } | Error::TooManyClaims { .. } | Error::Empty => {
                Self::InvalidRequest(error)
            }
            // `Error` is non-exhaustive. Unknown future variants are local/internal by default so
            // callers never penalize a peer for an error this adapter has not classified.
            _ => Self::Internal(error),
        }
    }
}

impl std::fmt::Display for AggregateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence(error) => write!(formatter, "invalid PQ evidence: {error}"),
            Self::InvalidRequest(error) => {
                write!(formatter, "invalid PQ aggregation request: {error}")
            }
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
            Self::InvalidEvidence(error) | Self::InvalidRequest(error) | Self::Internal(error) => {
                Some(error)
            }
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
        signatures: Vec<Signature>,
        claim: Claim,
    ) -> Result<Signature, AggregateError> {
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
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
impl PqProver {
    /// Refuses proving in a build that cannot create this type through [`Self::new`].
    pub fn aggregate(
        &self,
        _signatures: Vec<Signature>,
        _claim: Claim,
    ) -> Result<Signature, AggregateError> {
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
        signatures: Vec<Signature>,
        claim: Claim,
        response: SyncSender<Result<Signature, AggregateError>>,
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
    let setup_result = catch_backend_panic(&PQ_PROVER_LIFECYCLE, lean_multisig::setup);
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
                    lean_multisig::aggregate(signatures, &claim)
                });
                match aggregate_result {
                    Ok(result) => {
                        let _ = response.send(result.map_err(AggregateError::from));
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
    use super::{ProverLifecycle, ProverUnavailable, catch_backend_panic};

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
