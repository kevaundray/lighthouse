use crate::Client;
use crate::config::{ClientGenesis, Config as ClientConfig, PqDevnetConfigError};
use beacon_chain::builder::{BeaconChainBuilder, Witness};
use beacon_chain::slot_clock::SystemTimeSlotClock;
use beacon_chain::{
    BeaconChain, PqOperationalEvent, PqOperationalEventError, PqOperationalEventRole,
    PqOperationalEventSink, PqRuntimeStartup, PqStoreStartup, classify_pq_store_startup,
    migrate_pq_schema,
};
use consensus_signature::AggregationService;
#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
use consensus_signature::PqValidatorRegistryEntry;
use environment::RuntimeContext;
use futures::FutureExt;
use lighthouse_network::{Context, NetworkGlobals, load_private_key};
#[cfg(feature = "pq-proposer")]
use lighthouse_validator_store::{Config as ValidatorStoreConfig, LighthouseValidatorStore};
use network::{
    PqBlockBroadcastSender, PqNetworkService, PqNetworkServiceError, PqNetworkServiceShutdown,
    pq_block_broadcast_channel,
};
use pq_http_api::PqHttpApi;
#[cfg(feature = "pq-proposer")]
use pq_proposer_service::{
    PqBeaconFailure, PqProposalCompletion, PqProposerService, PqProposerServiceError,
};
#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags};
#[cfg(feature = "pq-proposer")]
use slot_clock::SlotClock;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use store::HotColdDB;
use store::database::interface::BeaconNodeBackend;
use types::{
    BeaconState, ChainSpec, Config as Eth2Config, EthSpec, ForkContext, ForkName, Hash256,
    MinimalEthSpec,
};

const PQ_HTTP_LOOPBACK_CONNECTION_CAPACITY: usize = 2;
const PQ_HTTP_REMOTE_CONNECTION_CAPACITY: usize = 16;
#[cfg(feature = "pq-proposer")]
const PQ_PROPOSER_RETRY_DELAY: Duration = Duration::from_secs(1);

const PQ_TESTNET_CONFIG_FILE: &str = "config.yaml";
const PQ_TESTNET_DEPOSIT_BLOCK_FILE: &str = "deposit_contract_block.txt";
const PQ_TESTNET_BOOTSTRAP_FILE: &str = "bootstrap_nodes.yaml";
const PQ_TESTNET_GENESIS_FILE: &str = "genesis.ssz";
const PQ_TESTNET_FILE_COUNT: usize = 4;
const MAX_PQ_TESTNET_CONFIG_BYTES: usize = 64 * 1024;
const MAX_PQ_TESTNET_DEPOSIT_BLOCK_BYTES: usize = 1024;
const MAX_PQ_TESTNET_BOOTSTRAP_BYTES: usize = 64 * 1024;
const MAX_PQ_TESTNET_GENESIS_BYTES: usize = 128 * 1024 * 1024;

type PqDiskWitness =
    Witness<SystemTimeSlotClock, MinimalEthSpec, BeaconNodeBackend, BeaconNodeBackend>;
type PqDiskChain = BeaconChain<PqDiskWitness>;
#[cfg(feature = "pq-proposer")]
type PqValidatorStore = LighthouseValidatorStore<SystemTimeSlotClock, MinimalEthSpec>;

#[cfg(feature = "pq-proposer")]
fn register_pq_validator_identities(
    database: &slashing_protection::SlashingDatabase,
    identities: &[(consensus_signature::ValidatorPublicKeyBytes, u64)],
) -> Result<(), PqRuntimeError> {
    if identities.is_empty()
        || !identities
            .iter()
            .zip(0_u64..)
            .all(|((_, actual), expected)| *actual == expected)
    {
        return Err(PqRuntimeError::ProposerPreflightInvariant);
    }
    database
        .register_validators(identities.iter().map(|(public_key, _)| public_key))
        .map_err(PqRuntimeError::Slashing)
}

pub type PqClient = Client<PqDiskWitness>;

struct PqPublicTestnet {
    genesis_bytes: Box<[u8]>,
    genesis_validators_root: Hash256,
    genesis_time: u64,
    #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
    validator_registry: Box<[PqValidatorRegistryEntry]>,
}

impl PqPublicTestnet {
    fn into_genesis_state(
        self,
        spec: &ChainSpec,
    ) -> Result<BeaconState<MinimalEthSpec>, PqPublicTestnetError> {
        let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&self.genesis_bytes, spec)
            .map_err(|error| PqPublicTestnetError::GenesisDecode(format!("{error:?}")))?;
        if state.genesis_validators_root() != self.genesis_validators_root
            || state.genesis_time() != self.genesis_time
        {
            return Err(PqPublicTestnetError::UnsafeLayout(
                "sealed genesis identity changed before consumption",
            ));
        }
        Ok(state)
    }
}

#[cfg(feature = "pq-startup-testing")]
pub struct PqPublicTestnetSummary {
    genesis_bytes_len: usize,
    genesis_validators_root: Hash256,
    genesis_time: u64,
    validator_registry: Box<[PqValidatorRegistryEntry]>,
}

#[cfg(feature = "pq-startup-testing")]
impl PqPublicTestnetSummary {
    pub fn genesis_bytes_len(&self) -> usize {
        self.genesis_bytes_len
    }

    pub fn genesis_validators_root(&self) -> Hash256 {
        self.genesis_validators_root
    }

    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    pub fn validator_registry(&self) -> &[PqValidatorRegistryEntry] {
        &self.validator_registry
    }
}

#[derive(Debug)]
pub enum PqPublicTestnetError {
    UnsupportedPlatform,
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    UnsafeLayout(&'static str),
    FileTooLarge(&'static str),
    InvalidConfig,
    InvalidDepositBlock,
    NonEmptyBootstrapList,
    GenesisDecode(String),
    GenesisProfile(state_processing::PqDevnetStateError),
}

impl std::fmt::Display for PqPublicTestnetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("PQ public testnet loading requires Linux")
            }
            Self::Io { path, error } => {
                write!(formatter, "could not read {}: {error}", path.display())
            }
            Self::UnsafeLayout(reason) => write!(formatter, "unsafe PQ testnet layout: {reason}"),
            Self::FileTooLarge(file) => write!(formatter, "PQ testnet file {file} is too large"),
            Self::InvalidConfig => formatter.write_str("invalid frozen PQ testnet config"),
            Self::InvalidDepositBlock => {
                formatter.write_str("invalid frozen PQ deposit contract block")
            }
            Self::NonEmptyBootstrapList => {
                formatter.write_str("PQ testnet bootstrap list must be empty")
            }
            Self::GenesisDecode(error) => write!(formatter, "invalid PQ genesis SSZ: {error}"),
            Self::GenesisProfile(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PqPublicTestnetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::GenesisProfile(error) => Some(error),
            Self::UnsupportedPlatform
            | Self::UnsafeLayout(_)
            | Self::FileTooLarge(_)
            | Self::InvalidConfig
            | Self::InvalidDepositBlock
            | Self::NonEmptyBootstrapList
            | Self::GenesisDecode(_) => None,
        }
    }
}

fn exact_pq_testnet_spec() -> ChainSpec {
    ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000)
}

#[cfg(target_os = "linux")]
fn read_pq_testnet_file(
    directory: &File,
    directory_path: &std::path::Path,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, PqPublicTestnetError> {
    let path = directory_path.join(name);
    let fd = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| PqPublicTestnetError::Io {
        path: path.clone(),
        error: error.into(),
    })?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|error| PqPublicTestnetError::Io {
        path: path.clone(),
        error,
    })?;
    let length =
        usize::try_from(metadata.len()).map_err(|_| PqPublicTestnetError::FileTooLarge(name))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o644 {
        return Err(PqPublicTestnetError::UnsafeLayout(
            "public files must be regular 0644 entries",
        ));
    }
    if length > maximum {
        return Err(PqPublicTestnetError::FileTooLarge(name));
    }
    let limit = u64::try_from(maximum)
        .map_err(|_| PqPublicTestnetError::FileTooLarge(name))?
        .checked_add(1)
        .ok_or(PqPublicTestnetError::FileTooLarge(name))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| PqPublicTestnetError::FileTooLarge(name))?;
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| PqPublicTestnetError::Io { path, error })?;
    if bytes.len() > maximum {
        return Err(PqPublicTestnetError::FileTooLarge(name));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn load_pq_public_testnet(
    testnet_dir: &std::path::Path,
) -> Result<PqPublicTestnet, PqPublicTestnetError> {
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        testnet_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| PqPublicTestnetError::Io {
        path: testnet_dir.to_path_buf(),
        error: error.into(),
    })?;
    let directory = File::from(fd);
    let metadata = directory
        .metadata()
        .map_err(|error| PqPublicTestnetError::Io {
            path: testnet_dir.to_path_buf(),
            error,
        })?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o755 {
        return Err(PqPublicTestnetError::UnsafeLayout(
            "public testnet must be a 0755 directory",
        ));
    }

    let anchored_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut entries = std::fs::read_dir(&anchored_path)
        .map_err(|error| PqPublicTestnetError::Io {
            path: testnet_dir.to_path_buf(),
            error,
        })?
        .take(PQ_TESTNET_FILE_COUNT + 1)
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| PqPublicTestnetError::Io {
                    path: testnet_dir.to_path_buf(),
                    error,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if entries.len() != PQ_TESTNET_FILE_COUNT {
        return Err(PqPublicTestnetError::UnsafeLayout(
            "public testnet has missing or unexpected entries",
        ));
    }
    entries.sort();
    let mut expected = [
        PQ_TESTNET_BOOTSTRAP_FILE,
        PQ_TESTNET_CONFIG_FILE,
        PQ_TESTNET_DEPOSIT_BLOCK_FILE,
        PQ_TESTNET_GENESIS_FILE,
    ];
    expected.sort();
    if !entries
        .iter()
        .zip(expected)
        .all(|(actual, expected)| actual == std::ffi::OsStr::new(expected))
    {
        return Err(PqPublicTestnetError::UnsafeLayout(
            "public testnet has missing or unexpected entries",
        ));
    }

    let config_bytes = read_pq_testnet_file(
        &directory,
        testnet_dir,
        PQ_TESTNET_CONFIG_FILE,
        MAX_PQ_TESTNET_CONFIG_BYTES,
    )?;
    let config: Eth2Config = yaml_serde::from_reader(config_bytes.as_slice())
        .map_err(|_| PqPublicTestnetError::InvalidConfig)?;
    let spec = exact_pq_testnet_spec();
    if config != Eth2Config::from_chain_spec::<MinimalEthSpec>(&spec) {
        return Err(PqPublicTestnetError::InvalidConfig);
    }
    let deposit_bytes = read_pq_testnet_file(
        &directory,
        testnet_dir,
        PQ_TESTNET_DEPOSIT_BLOCK_FILE,
        MAX_PQ_TESTNET_DEPOSIT_BLOCK_BYTES,
    )?;
    let deposit_block: u64 = yaml_serde::from_reader(deposit_bytes.as_slice())
        .map_err(|_| PqPublicTestnetError::InvalidDepositBlock)?;
    if deposit_block != 0 {
        return Err(PqPublicTestnetError::InvalidDepositBlock);
    }
    let bootstrap_bytes = read_pq_testnet_file(
        &directory,
        testnet_dir,
        PQ_TESTNET_BOOTSTRAP_FILE,
        MAX_PQ_TESTNET_BOOTSTRAP_BYTES,
    )?;
    let bootstrap_nodes: Vec<String> = yaml_serde::from_reader(bootstrap_bytes.as_slice())
        .map_err(|_| PqPublicTestnetError::NonEmptyBootstrapList)?;
    if !bootstrap_nodes.is_empty() {
        return Err(PqPublicTestnetError::NonEmptyBootstrapList);
    }
    let genesis_bytes = read_pq_testnet_file(
        &directory,
        testnet_dir,
        PQ_TESTNET_GENESIS_FILE,
        MAX_PQ_TESTNET_GENESIS_BYTES,
    )?;
    let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&genesis_bytes, &spec)
        .map_err(|error| PqPublicTestnetError::GenesisDecode(format!("{error:?}")))?;
    state_processing::validate_lean_pq_devnet_v1(&state, &spec, state.slot())
        .map_err(PqPublicTestnetError::GenesisProfile)?;
    #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
    let validator_registry = state
        .validators()
        .iter()
        .enumerate()
        .map(|(position, validator)| {
            let validator_index = u64::try_from(position).map_err(|_| {
                PqPublicTestnetError::UnsafeLayout("genesis validator index does not fit u64")
            })?;
            Ok(PqValidatorRegistryEntry::new(
                validator_index,
                validator.pubkey,
                validator.withdrawal_credentials.0,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    Ok(PqPublicTestnet {
        genesis_validators_root: state.genesis_validators_root(),
        genesis_time: state.genesis_time(),
        genesis_bytes: genesis_bytes.into_boxed_slice(),
        #[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
        validator_registry,
    })
}

#[cfg(not(target_os = "linux"))]
fn load_pq_public_testnet(
    _testnet_dir: &std::path::Path,
) -> Result<PqPublicTestnet, PqPublicTestnetError> {
    Err(PqPublicTestnetError::UnsupportedPlatform)
}

struct PqBlockingRuntime {
    chain: Arc<PqDiskChain>,
    startup: PqStoreStartup,
    #[cfg(feature = "pq-proposer")]
    validator_store: Option<Arc<PqValidatorStore>>,
    network_config: Arc<network::NetworkConfig>,
    http_api_config: crate::config::PqHttpApiConfig,
    #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
    fail_proposer_construction: bool,
    #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
    fail_proposer_loop_start: bool,
    #[cfg(feature = "pq-startup-testing")]
    fail_runtime_ready_event: bool,
}

struct PqHttpServerShutdown {
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
    connection_shutdown: tokio_util::sync::CancellationToken,
    stopping: Arc<AtomicBool>,
    #[cfg(feature = "pq-startup-testing")]
    outcome: tokio::sync::watch::Receiver<Option<PqHttpTaskOutcome>>,
    task: tokio::sync::oneshot::Receiver<Result<PqHttpTaskOutcome, tokio::task::JoinError>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PqHttpTaskOutcome {
    Graceful,
    Unexpected,
}

impl PqHttpServerShutdown {
    async fn wait(mut self) -> Result<(), PqRuntimeError> {
        self.stopping.store(true, Ordering::SeqCst);
        self.connection_shutdown.cancel();
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        match self.task.await {
            Ok(Ok(PqHttpTaskOutcome::Graceful)) => Ok(()),
            Ok(Ok(PqHttpTaskOutcome::Unexpected)) => Err(PqRuntimeError::HttpUnexpectedExit),
            Ok(Err(error)) => Err(PqRuntimeError::TaskJoin(error.to_string())),
            Err(_) => Err(PqRuntimeError::TaskUnavailable),
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    async fn testing_only_stop_unexpectedly(&self) -> Result<(), PqRuntimeError> {
        let mut outcome = self.outcome.clone();
        self.connection_shutdown.cancel();
        loop {
            if let Some(outcome) = *outcome.borrow() {
                return match outcome {
                    PqHttpTaskOutcome::Unexpected => Ok(()),
                    PqHttpTaskOutcome::Graceful => Err(PqRuntimeError::TaskUnavailable),
                };
            }
            outcome
                .changed()
                .await
                .map_err(|_| PqRuntimeError::TaskUnavailable)?;
        }
    }
}

async fn cleanup_pq_post_bind_owners(
    http_shutdown: Option<PqHttpServerShutdown>,
    broadcaster: PqBlockBroadcastSender<MinimalEthSpec>,
    network_shutdown: PqNetworkServiceShutdown,
    chain: Arc<PqDiskChain>,
    operational_events: Arc<PqOperationalEventSink>,
    operational_event_completion: tokio::sync::oneshot::Receiver<
        Result<Result<(), PqOperationalEventError>, tokio::task::JoinError>,
    >,
) {
    if let Some(http_shutdown) = http_shutdown {
        let _ = http_shutdown.wait().await;
    }
    drop(broadcaster);
    let _ = network_shutdown.wait().await;
    chain.close_and_drain_pq_imports().await;
    drop(operational_events);
    let _ = operational_event_completion.await;
}

struct PqHttpConnection {
    stream: tokio::net::TcpStream,
    shutdown: futures::future::Fuse<futures::future::BoxFuture<'static, ()>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl tokio::io::AsyncRead for PqHttpConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.shutdown.poll_unpin(context).is_ready() {
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for PqHttpConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.shutdown.poll_unpin(context).is_ready() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        std::pin::Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.shutdown.poll_unpin(context).is_ready() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        std::pin::Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[cfg(feature = "pq-proposer")]
struct PqProposerLoopShutdown {
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::sync::oneshot::Receiver<
        Result<Result<(), PqProposerServiceError>, tokio::task::JoinError>,
    >,
    #[cfg(feature = "pq-startup-testing")]
    observer: Arc<PqProposerLoopObserver>,
}

#[cfg(feature = "pq-proposer")]
struct PqParkedProposerLoop {
    release_sender: Option<tokio::sync::oneshot::Sender<()>>,
    shutdown: PqProposerLoopShutdown,
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
struct PqProposerLoopObserver {
    attempts: std::sync::atomic::AtomicUsize,
    max_retained_receipts: std::sync::atomic::AtomicUsize,
    attempt: tokio::sync::Notify,
}

#[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
impl PqProposerLoopObserver {
    fn new() -> Self {
        Self {
            attempts: std::sync::atomic::AtomicUsize::new(0),
            max_retained_receipts: std::sync::atomic::AtomicUsize::new(0),
            attempt: tokio::sync::Notify::new(),
        }
    }
}

#[cfg(feature = "pq-proposer")]
impl PqProposerLoopShutdown {
    async fn wait(mut self) -> Result<(), PqRuntimeError> {
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        match self.task.await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(PqRuntimeError::Proposer(error)),
            Ok(Err(error)) => Err(PqRuntimeError::TaskJoin(error.to_string())),
            Err(_) => Err(PqRuntimeError::TaskUnavailable),
        }
    }

    #[cfg(all(feature = "pq-startup-testing", test))]
    async fn testing_only_wait_for_exit(mut self) -> Result<(), PqRuntimeError> {
        // Retain the sender across the task completion so this observes executor/loop exit rather
        // than causing an explicit stop by dropping or sending it.
        let shutdown_sender = self.shutdown_sender.take();
        let result = match self.task.await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(PqRuntimeError::Proposer(error)),
            Ok(Err(error)) => Err(PqRuntimeError::TaskJoin(error.to_string())),
            Err(_) => Err(PqRuntimeError::TaskUnavailable),
        };
        drop(shutdown_sender);
        result
    }
}

#[cfg(feature = "pq-proposer")]
impl PqParkedProposerLoop {
    async fn release(mut self) -> Result<PqProposerLoopShutdown, PqRuntimeError> {
        if self
            .release_sender
            .take()
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .send(())
            .is_err()
        {
            let _ = self.shutdown.wait().await;
            return Err(PqRuntimeError::TaskUnavailable);
        }
        Ok(self.shutdown)
    }

    async fn wait(self) -> Result<(), PqRuntimeError> {
        drop(self.release_sender);
        self.shutdown.wait().await
    }
}

#[cfg(feature = "pq-proposer")]
fn pq_beacon_failure_is_fatal(error: &PqBeaconFailure, conflict_is_slot_local: bool) -> bool {
    match error {
        PqBeaconFailure::Connect
        | PqBeaconFailure::Timeout
        | PqBeaconFailure::Status(408 | 429 | 503) => false,
        PqBeaconFailure::Status(409) if conflict_is_slot_local => false,
        PqBeaconFailure::Status(_)
        | PqBeaconFailure::ResponseTooLarge
        | PqBeaconFailure::FragmentLimit
        | PqBeaconFailure::Stream
        | PqBeaconFailure::Resource
        | PqBeaconFailure::InvalidHeaders
        | PqBeaconFailure::InvalidJson
        | PqBeaconFailure::InvalidSsz
        | PqBeaconFailure::Protocol => true,
    }
}

#[cfg(feature = "pq-proposer")]
fn pq_proposer_error_is_fatal(error: &PqProposerServiceError) -> bool {
    match error {
        PqProposerServiceError::DutyRequest(error) => pq_beacon_failure_is_fatal(error, false),
        PqProposerServiceError::BlockProduction(error)
        | PqProposerServiceError::Publication(error) => pq_beacon_failure_is_fatal(error, true),
        PqProposerServiceError::PublicationRejected { status } => *status != 409,
        PqProposerServiceError::ClockUnavailable
        | PqProposerServiceError::OptimisticDuties
        | PqProposerServiceError::DoppelgangerNotReady { .. }
        | PqProposerServiceError::BlockSigningExpired { .. }
        | PqProposerServiceError::PublicationExpired { .. }
        | PqProposerServiceError::PreparationExpired { .. }
        | PqProposerServiceError::StaleAfterDuty { .. }
        | PqProposerServiceError::StaleSlot { .. }
        | PqProposerServiceError::Capacity => false,
        PqProposerServiceError::Randao(error) | PqProposerServiceError::BlockSigning(error) => {
            !error.is_transient()
        }
        PqProposerServiceError::InvalidIdentitySet
        | PqProposerServiceError::WrongSlotDuration { .. }
        | PqProposerServiceError::Configuration(_)
        | PqProposerServiceError::MissingValidatorIndex { .. }
        | PqProposerServiceError::DutyIdentityMismatch { .. }
        | PqProposerServiceError::InvalidCurrentSlotDutyCount { .. }
        | PqProposerServiceError::InvalidProducedBlock(_)
        | PqProposerServiceError::PublicationEncoding(_)
        | PqProposerServiceError::PublicationProtocol { .. }
        | PqProposerServiceError::TimingOverflow
        | PqProposerServiceError::TaskUnavailable => true,
    }
}

#[cfg(feature = "pq-proposer")]
trait PqProposerLoopReceipt: Send {
    fn slot(&self) -> types::Slot;

    fn completion(
        &self,
    ) -> futures::future::BoxFuture<'_, Result<PqProposalCompletion, PqProposerServiceError>>;
}

#[cfg(feature = "pq-proposer")]
impl PqProposerLoopReceipt for pq_proposer_service::PqProposalReceipt {
    fn slot(&self) -> types::Slot {
        self.slot()
    }

    fn completion(
        &self,
    ) -> futures::future::BoxFuture<'_, Result<PqProposalCompletion, PqProposerServiceError>> {
        self.completion().boxed()
    }
}

#[cfg(feature = "pq-proposer")]
trait PqProposerLoopSource: Send + Sync + 'static {
    type Receipt: PqProposerLoopReceipt;

    fn now(&self) -> Option<types::Slot>;
    fn genesis_slot(&self) -> types::Slot;
    fn duration_to_next_slot(&self) -> Option<Duration>;
    fn try_propose_current_slot(&self) -> Result<Self::Receipt, PqProposerServiceError>;
}

#[cfg(feature = "pq-proposer")]
struct ProductionPqProposerLoopSource {
    service: Arc<PqProposerService<SystemTimeSlotClock>>,
    clock: SystemTimeSlotClock,
}

#[cfg(feature = "pq-proposer")]
impl PqProposerLoopSource for ProductionPqProposerLoopSource {
    type Receipt = pq_proposer_service::PqProposalReceipt;

    fn now(&self) -> Option<types::Slot> {
        self.clock.now()
    }

    fn genesis_slot(&self) -> types::Slot {
        self.clock.genesis_slot()
    }

    fn duration_to_next_slot(&self) -> Option<Duration> {
        self.clock.duration_to_next_slot()
    }

    fn try_propose_current_slot(&self) -> Result<Self::Receipt, PqProposerServiceError> {
        self.service.try_propose_current_slot()
    }
}

#[cfg(feature = "pq-proposer")]
async fn run_pq_proposer_loop<S: PqProposerLoopSource>(
    source: S,
    shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
    exit: impl std::future::Future<Output = ()> + Send + 'static,
    startup: PqRuntimeStartup,
    #[cfg(feature = "pq-startup-testing")] observer: Arc<PqProposerLoopObserver>,
) -> Result<(), PqProposerServiceError> {
    let mut shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(async move {
            tokio::select! {
                _ = exit => {}
                _ = shutdown_receiver => {}
            }
        });
    let mut completed_slot = None;

    if startup == PqRuntimeStartup::Resume {
        // A resumed proposer may finish its expensive authenticated startup part-way through a
        // slot.  Observe the clock only after RuntimeReady has been acknowledged and the parked
        // loop released, then deliberately skip that first observed slot.
        let observed_slot = loop {
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => return Ok(()),
                _ = std::future::ready(()) => {}
            }
            if let Some(slot) = source.now() {
                break slot;
            }
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => return Ok(()),
                _ = tokio::time::sleep(PQ_PROPOSER_RETRY_DELAY) => {}
            }
        };
        let first_admissible_slot = types::Slot::new(
            observed_slot
                .as_u64()
                .checked_add(1)
                .ok_or(PqProposerServiceError::TimingOverflow)?,
        );
        completed_slot = Some(observed_slot);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => return Ok(()),
                _ = std::future::ready(()) => {}
            }
            if source
                .now()
                .is_some_and(|slot| slot >= first_admissible_slot)
            {
                // A stop becoming ready during the boundary observation wins over admission.
                tokio::select! {
                    biased;
                    _ = shutdown.as_mut() => return Ok(()),
                    _ = std::future::ready(()) => {}
                }
                break;
            }
            let delay = source
                .duration_to_next_slot()
                .unwrap_or(PQ_PROPOSER_RETRY_DELAY);
            tokio::select! {
                biased;
                _ = shutdown.as_mut() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    loop {
        let Some(now) = source.now() else {
            tokio::select! {
                _ = shutdown.as_mut() => return Ok(()),
                _ = tokio::time::sleep(PQ_PROPOSER_RETRY_DELAY) => continue,
            }
        };
        if now == source.genesis_slot() || completed_slot.is_some_and(|slot| now <= slot) {
            let delay = source
                .duration_to_next_slot()
                .unwrap_or(PQ_PROPOSER_RETRY_DELAY);
            tokio::select! {
                _ = shutdown.as_mut() => return Ok(()),
                _ = tokio::time::sleep(delay) => continue,
            }
        }

        // Give an already-ready (or concurrently-ready) process stop priority immediately before
        // admission.  The ready branch makes this a non-waiting gate while `biased` ensures that a
        // stop observed in the same poll cannot start another non-cancellable proposal.
        tokio::select! {
            biased;
            _ = shutdown.as_mut() => return Ok(()),
            _ = std::future::ready(()) => {}
        }

        let receipt = match source.try_propose_current_slot() {
            Ok(receipt) => receipt,
            Err(error) if pq_proposer_error_is_fatal(&error) => return Err(error),
            Err(_) => {
                tokio::select! {
                    biased;
                    _ = shutdown.as_mut() => return Ok(()),
                    _ = tokio::time::sleep(PQ_PROPOSER_RETRY_DELAY) => continue,
                }
            }
        };
        #[cfg(feature = "pq-startup-testing")]
        {
            observer.attempts.fetch_add(1, Ordering::SeqCst);
            observer
                .max_retained_receipts
                .fetch_max(1, Ordering::SeqCst);
            observer.attempt.notify_waiters();
        }
        let slot = receipt.slot();
        let completion = tokio::select! {
            _ = shutdown.as_mut() => {
                return match receipt.completion().await {
                    Err(error) if pq_proposer_error_is_fatal(&error) => Err(error),
                    _ => Ok(()),
                };
            }
            completion = receipt.completion() => completion,
        };
        completed_slot = Some(slot);
        match completion {
            Ok(PqProposalCompletion::NoLocalDuty { .. })
            | Ok(PqProposalCompletion::Published { .. }) => {}
            Err(error) if pq_proposer_error_is_fatal(&error) => return Err(error),
            Err(_) => {}
        }
    }
}

#[cfg(feature = "pq-proposer")]
async fn start_pq_proposer_loop_parked(
    service: Arc<PqProposerService<SystemTimeSlotClock>>,
    clock: SystemTimeSlotClock,
    task_executor: task_executor::TaskExecutor,
    startup: PqRuntimeStartup,
) -> Result<PqParkedProposerLoop, PqRuntimeError> {
    start_pq_proposer_loop_source_parked(
        ProductionPqProposerLoopSource { service, clock },
        task_executor,
        startup,
    )
    .await
}

#[cfg(all(feature = "pq-proposer", test))]
async fn start_pq_proposer_loop_source<S: PqProposerLoopSource>(
    source: S,
    task_executor: task_executor::TaskExecutor,
) -> Result<PqProposerLoopShutdown, PqRuntimeError> {
    start_pq_proposer_loop_source_parked(source, task_executor, PqRuntimeStartup::Fresh)
        .await?
        .release()
        .await
}

#[cfg(feature = "pq-proposer")]
async fn start_pq_proposer_loop_source_parked<S: PqProposerLoopSource>(
    source: S,
    task_executor: task_executor::TaskExecutor,
    startup: PqRuntimeStartup,
) -> Result<PqParkedProposerLoop, PqRuntimeError> {
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let (live_sender, live_receiver) = tokio::sync::oneshot::channel();
    #[cfg(feature = "pq-startup-testing")]
    let observer = Arc::new(PqProposerLoopObserver::new());
    #[cfg(feature = "pq-startup-testing")]
    let task_observer = Arc::clone(&observer);
    let exit = task_executor.exit();
    let mut process_shutdown = task_executor.shutdown_sender();
    let mut task = task_executor
        .spawn_handle_without_exit(
            async move {
                let _ = live_sender.send(());
                let mut exit = Box::pin(exit);
                let mut shutdown_receiver = shutdown_receiver;
                tokio::select! {
                    biased;
                    _ = exit.as_mut() => return Ok(()),
                    _ = &mut shutdown_receiver => return Ok(()),
                    release = release_receiver => {
                        if release.is_err() {
                            return Ok(());
                        }
                    }
                }
                let result = run_pq_proposer_loop(
                    source,
                    shutdown_receiver,
                    exit,
                    startup,
                    #[cfg(feature = "pq-startup-testing")]
                    task_observer,
                )
                .await;
                if result.as_ref().is_err_and(pq_proposer_error_is_fatal) {
                    let _ = process_shutdown.try_send(task_executor::ShutdownReason::Failure(
                        "PQ proposer loop failed",
                    ));
                }
                result
            },
            "pq_proposer_loop",
        )
        .ok_or(PqRuntimeError::TaskUnavailable)?;
    tokio::select! {
        biased;
        result = &mut task => match result {
            Ok(Ok(Err(error))) => Err(PqRuntimeError::Proposer(error)),
            Ok(Ok(Ok(()))) | Ok(Err(_)) | Err(_) => Err(PqRuntimeError::TaskUnavailable),
        },
        live = live_receiver => {
            live.map_err(|_| PqRuntimeError::TaskUnavailable)?;
            Ok(PqParkedProposerLoop {
                release_sender: Some(release_sender),
                shutdown: PqProposerLoopShutdown {
                    shutdown_sender: Some(shutdown_sender),
                    task,
                    #[cfg(feature = "pq-startup-testing")]
                    observer,
                },
            })
        }
    }
}

#[cfg(feature = "pq-proposer")]
async fn acknowledge_runtime_ready_and_release_proposer(
    operational_events: &Arc<PqOperationalEventSink>,
    runtime_ready_event: PqOperationalEvent,
    parked_proposer_loop: Option<PqParkedProposerLoop>,
) -> Result<Option<PqProposerLoopShutdown>, PqRuntimeError> {
    if let Err(error) = operational_events.emit_and_wait(runtime_ready_event).await {
        if let Some(proposer_loop) = parked_proposer_loop {
            let _ = proposer_loop.wait().await;
        }
        return Err(PqRuntimeError::OperationalEvent(error));
    }
    match parked_proposer_loop {
        Some(proposer_loop) => proposer_loop.release().await.map(Some),
        None => Ok(None),
    }
}

fn pq_local_http_address(bound: std::net::SocketAddr) -> std::net::SocketAddr {
    let ip = match bound.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
        ip => ip,
    };
    std::net::SocketAddr::new(ip, bound.port())
}

async fn start_pq_http_server(
    chain: Arc<PqDiskChain>,
    task_executor: task_executor::TaskExecutor,
    broadcaster: PqBlockBroadcastSender<MinimalEthSpec>,
    config: &crate::config::PqHttpApiConfig,
) -> Result<
    (
        std::net::SocketAddr,
        sensitive_url::SensitiveUrl,
        PqHttpServerShutdown,
    ),
    PqRuntimeError,
> {
    let routes = PqHttpApi::new(chain, task_executor.clone(), broadcaster)
        .map_err(PqRuntimeError::HttpConfiguration)?
        .routes();
    let configured = std::net::SocketAddr::new(config.listen_addr, config.listen_port);
    let listener = std::net::TcpListener::bind(configured).map_err(PqRuntimeError::HttpBind)?;
    listener
        .set_nonblocking(true)
        .map_err(PqRuntimeError::HttpBind)?;
    let bound = listener.local_addr().map_err(PqRuntimeError::HttpBind)?;
    let listener = tokio::net::TcpListener::from_std(listener).map_err(PqRuntimeError::HttpBind)?;
    let listener = Arc::new(listener);
    let loopback_admission = Arc::new(tokio::sync::Semaphore::new(
        PQ_HTTP_LOOPBACK_CONNECTION_CAPACITY,
    ));
    let remote_admission = Arc::new(tokio::sync::Semaphore::new(
        PQ_HTTP_REMOTE_CONNECTION_CAPACITY,
    ));
    let connection_shutdown = tokio_util::sync::CancellationToken::new();
    let incoming_shutdown = connection_shutdown.clone();
    let incoming = futures::stream::unfold(
        (
            listener,
            loopback_admission,
            remote_admission,
            incoming_shutdown,
        ),
        |(listener, loopback_admission, remote_admission, shutdown)| async move {
            loop {
                let accepted = tokio::select! {
                    _ = shutdown.cancelled() => return None,
                    accepted = listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, peer)) => {
                        let admission = if peer.ip().is_loopback() {
                            Arc::clone(&loopback_admission).try_acquire_owned()
                        } else {
                            Arc::clone(&remote_admission).try_acquire_owned()
                        };
                        match admission {
                            Ok(permit) => {
                                let connection = PqHttpConnection {
                                    stream,
                                    shutdown: shutdown.clone().cancelled_owned().boxed().fuse(),
                                    _permit: permit,
                                };
                                return Some((
                                    Ok::<_, std::io::Error>(connection),
                                    (listener, loopback_admission, remote_admission, shutdown),
                                ));
                            }
                            Err(_) => {
                                drop(stream);
                                tokio::task::yield_now().await;
                            }
                        }
                    }
                    Err(error) => {
                        return Some((
                            Err(error),
                            (listener, loopback_admission, remote_admission, shutdown),
                        ));
                    }
                }
            }
        },
    );
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = warp::serve(routes).serve_incoming_with_graceful_shutdown(incoming, async move {
        let _ = shutdown_receiver.await;
    });
    let local = pq_local_http_address(bound);
    let local_url = sensitive_url::SensitiveUrl::parse(&format!("http://{local}/"))
        .map_err(|error| PqRuntimeError::HttpUrl(error.to_string()))?;
    let (live_sender, live_receiver) = tokio::sync::oneshot::channel();
    #[cfg(feature = "pq-startup-testing")]
    let (outcome_sender, outcome_receiver) = tokio::sync::watch::channel(None);
    let stopping = Arc::new(AtomicBool::new(false));
    let task_stopping = Arc::clone(&stopping);
    let mut process_shutdown = task_executor.shutdown_sender();
    let mut task = task_executor
        .spawn_handle_without_exit(
            async move {
                let _ = live_sender.send(());
                server.await;
                let outcome = if task_stopping.load(Ordering::SeqCst) {
                    PqHttpTaskOutcome::Graceful
                } else {
                    let _ = process_shutdown.try_send(task_executor::ShutdownReason::Failure(
                        "PQ HTTP API exited unexpectedly",
                    ));
                    PqHttpTaskOutcome::Unexpected
                };
                #[cfg(feature = "pq-startup-testing")]
                outcome_sender.send_replace(Some(outcome));
                outcome
            },
            "pq_http_api",
        )
        .ok_or(PqRuntimeError::TaskUnavailable)?;
    tokio::select! {
        biased;
        result = &mut task => match result {
            Ok(Ok(PqHttpTaskOutcome::Unexpected)) => Err(PqRuntimeError::HttpUnexpectedExit),
            Ok(Ok(PqHttpTaskOutcome::Graceful)) => Err(PqRuntimeError::TaskUnavailable),
            Ok(Err(error)) => Err(PqRuntimeError::TaskJoin(error.to_string())),
            Err(_) => Err(PqRuntimeError::TaskUnavailable),
        },
        live = live_receiver => {
            live.map_err(|_| PqRuntimeError::TaskUnavailable)?;
            Ok((bound, local_url, PqHttpServerShutdown {
                shutdown_sender: Some(shutdown_sender),
                connection_shutdown,
                stopping,
                #[cfg(feature = "pq-startup-testing")]
                outcome: outcome_receiver,
                task,
            }))
        }
    }
}

struct PqPreparedDiskRuntime {
    builder: BeaconChainBuilder<PqDiskWitness>,
    startup: PqStoreStartup,
    plan: PqRuntimePlan,
    #[cfg(feature = "pq-proposer")]
    network_identity: (Hash256, u64),
    #[cfg(feature = "pq-proposer")]
    validator_registry: Vec<PqValidatorRegistryEntry>,
}

/// Unvalidated inputs for the isolated minimal PQ runtime.
#[derive(Clone)]
pub struct PqRuntimeConfig {
    client: ClientConfig,
    testnet_dir: PathBuf,
    validator_bundle: Option<PathBuf>,
    #[cfg(feature = "pq-startup-testing")]
    blocking_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    genesis_read_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    execution_notifier: Option<Arc<dyn beacon_chain::PqNewPayloadTransport<MinimalEthSpec>>>,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    bundle_auth_test_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    fail_proposer_construction: bool,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    fail_proposer_loop_start: bool,
    #[cfg(feature = "pq-startup-testing")]
    fail_runtime_ready_event: bool,
}

impl std::fmt::Debug for PqRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqRuntimeConfig")
            .field("client", &self.client)
            .field("testnet_dir", &self.testnet_dir)
            .field("validator_bundle", &self.validator_bundle)
            .finish_non_exhaustive()
    }
}

impl PqRuntimeConfig {
    pub fn new(client: ClientConfig, testnet_dir: PathBuf) -> Self {
        Self {
            client,
            testnet_dir,
            validator_bundle: None,
            #[cfg(feature = "pq-startup-testing")]
            blocking_test_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            genesis_read_test_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            execution_notifier: None,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            bundle_auth_test_barriers: None,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            fail_proposer_construction: false,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            fail_proposer_loop_start: false,
            #[cfg(feature = "pq-startup-testing")]
            fail_runtime_ready_event: false,
        }
    }

    pub fn with_validator_bundle(mut self, bundle_dir: PathBuf) -> Self {
        self.validator_bundle = Some(bundle_dir);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_blocking_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.blocking_test_hook = Some(hook);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_genesis_read_hook(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.genesis_read_test_hook = Some(hook);
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_execution_notifier(
        mut self,
        notifier: Arc<dyn beacon_chain::PqNewPayloadTransport<MinimalEthSpec>>,
    ) -> Self {
        self.execution_notifier = Some(notifier);
        self
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_bundle_auth_barriers(
        mut self,
        entered: Arc<tokio::sync::Barrier>,
        completed: Arc<tokio::sync::Barrier>,
    ) -> Self {
        self.bundle_auth_test_barriers = Some((entered, completed));
        self
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_fail_proposer_construction(mut self) -> Self {
        self.fail_proposer_construction = true;
        self
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_fail_proposer_loop_start(mut self) -> Self {
        self.fail_proposer_loop_start = true;
        self
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_fail_runtime_ready_event(mut self) -> Self {
        self.fail_runtime_ready_event = true;
        self
    }

    /// Validate and seal startup inputs without consulting or mutating the filesystem.
    fn validate(self, spec: &ChainSpec) -> Result<PqRuntimePlan, PqRuntimeConfigError> {
        if spec.get_slot_duration() != Duration::from_secs(300) {
            return Err(PqRuntimeConfigError::InvalidSlotDuration);
        }
        let execution = self
            .client
            .execution_layer
            .as_ref()
            .ok_or(PqRuntimeConfigError::MissingExecutionLayer)?;
        if execution.execution_endpoint.is_none() {
            return Err(PqRuntimeConfigError::MissingExecutionEndpoint);
        }
        if execution.secret_file.is_none() {
            return Err(PqRuntimeConfigError::MissingJwtSecret);
        }
        if self.client.http_api.tls_config.is_some() {
            return Err(PqRuntimeConfigError::UnsupportedOption("HTTP TLS"));
        }
        if self.client.http_api.allow_origin.is_some() {
            return Err(PqRuntimeConfigError::UnsupportedOption("HTTP CORS"));
        }
        if self.client.http_metrics.enabled {
            return Err(PqRuntimeConfigError::UnsupportedOption("metrics"));
        }
        if self.client.monitoring_api.is_some() {
            return Err(PqRuntimeConfigError::UnsupportedOption("monitoring"));
        }
        #[cfg(not(feature = "pq-proposer"))]
        if self.validator_bundle.is_some() {
            return Err(PqRuntimeConfigError::ProposerFeatureDisabled);
        }
        if self.validator_bundle.is_some() && !self.client.http_api.enabled {
            return Err(PqRuntimeConfigError::ProposerRequiresHttp);
        }
        self.client
            .validate_pq_devnet::<MinimalEthSpec>(spec)
            .map_err(PqRuntimeConfigError::Client)?;
        self.client
            .store
            .verify::<MinimalEthSpec>()
            .map_err(|_| PqRuntimeConfigError::InvalidStoreConfiguration)?;
        let (hot_db_path, cold_db_path, blobs_db_path) = self.client.pq_lexical_store_paths();
        let network_dir = self.client.network.network_dir.clone();
        let jwt_secret_path = execution
            .secret_file
            .clone()
            .ok_or(PqRuntimeConfigError::MissingJwtSecret)?;
        #[cfg(feature = "pq-proposer")]
        let proposer = self
            .validator_bundle
            .map(|bundle_dir| PqProposerRuntimePaths {
                bundle_dir,
                slashing_db: self
                    .client
                    .data_dir()
                    .join("pq-proposer")
                    .join(slashing_protection::SLASHING_PROTECTION_FILENAME),
            });
        #[cfg(not(feature = "pq-proposer"))]
        let proposer = None;
        Ok(PqRuntimePlan {
            client: self.client,
            genesis_state_path: self.testnet_dir.join("genesis.ssz"),
            proposer,
            hot_db_path,
            cold_db_path,
            blobs_db_path,
            network_dir,
            jwt_secret_path,
            #[cfg(feature = "pq-startup-testing")]
            blocking_test_hook: self.blocking_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            genesis_read_test_hook: self.genesis_read_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            execution_notifier: self.execution_notifier,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            bundle_auth_test_barriers: self.bundle_auth_test_barriers,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            fail_proposer_construction: self.fail_proposer_construction,
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            fail_proposer_loop_start: self.fail_proposer_loop_start,
            #[cfg(feature = "pq-startup-testing")]
            fail_runtime_ready_event: self.fail_runtime_ready_event,
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_validate(
        self,
        spec: &ChainSpec,
    ) -> Result<PqRuntimePlan, PqRuntimeConfigError> {
        self.validate(spec)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_load_public_testnet(
        testnet_dir: &std::path::Path,
    ) -> Result<PqPublicTestnetSummary, PqPublicTestnetError> {
        let sealed = load_pq_public_testnet(testnet_dir)?;
        Ok(PqPublicTestnetSummary {
            genesis_bytes_len: sealed.genesis_bytes.len(),
            genesis_validators_root: sealed.genesis_validators_root,
            genesis_time: sealed.genesis_time,
            validator_registry: sealed.validator_registry,
        })
    }
}

/// Paths retained for the later proposer assembly slice. E4c never opens them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqProposerRuntimePaths {
    bundle_dir: PathBuf,
    slashing_db: PathBuf,
}

impl PqProposerRuntimePaths {
    pub fn bundle_dir(&self) -> &std::path::Path {
        &self.bundle_dir
    }

    pub fn slashing_db(&self) -> &std::path::Path {
        &self.slashing_db
    }
}

/// Side-effect-free, profile-checked startup inputs.
pub struct PqRuntimePlan {
    client: ClientConfig,
    genesis_state_path: PathBuf,
    proposer: Option<PqProposerRuntimePaths>,
    hot_db_path: PathBuf,
    cold_db_path: PathBuf,
    blobs_db_path: PathBuf,
    network_dir: PathBuf,
    jwt_secret_path: PathBuf,
    #[cfg(feature = "pq-startup-testing")]
    blocking_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    genesis_read_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    execution_notifier: Option<Arc<dyn beacon_chain::PqNewPayloadTransport<MinimalEthSpec>>>,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    bundle_auth_test_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    fail_proposer_construction: bool,
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    fail_proposer_loop_start: bool,
    #[cfg(feature = "pq-startup-testing")]
    fail_runtime_ready_event: bool,
}

impl std::fmt::Debug for PqRuntimePlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqRuntimePlan")
            .field("client", &self.client)
            .field("genesis_state_path", &self.genesis_state_path)
            .field("proposer", &self.proposer)
            .field("hot_db_path", &self.hot_db_path)
            .field("cold_db_path", &self.cold_db_path)
            .field("blobs_db_path", &self.blobs_db_path)
            .field("network_dir", &self.network_dir)
            .field("jwt_secret_path", &self.jwt_secret_path)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "pq-startup-testing")]
impl PqRuntimePlan {
    pub fn client_config(&self) -> &ClientConfig {
        &self.client
    }

    pub fn genesis_state_path(&self) -> &std::path::Path {
        &self.genesis_state_path
    }

    pub fn proposer(&self) -> Option<&PqProposerRuntimePaths> {
        self.proposer.as_ref()
    }

    pub fn hot_db_path(&self) -> &std::path::Path {
        &self.hot_db_path
    }

    pub fn cold_db_path(&self) -> &std::path::Path {
        &self.cold_db_path
    }

    pub fn blobs_db_path(&self) -> &std::path::Path {
        &self.blobs_db_path
    }

    pub fn network_dir(&self) -> &std::path::Path {
        &self.network_dir
    }

    pub fn jwt_secret_path(&self) -> &std::path::Path {
        &self.jwt_secret_path
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqRuntimeConfigError {
    InvalidSlotDuration,
    MissingExecutionLayer,
    MissingExecutionEndpoint,
    MissingJwtSecret,
    ProposerRequiresHttp,
    ProposerFeatureDisabled,
    UnsupportedOption(&'static str),
    InvalidStoreConfiguration,
    Client(PqDevnetConfigError),
}

impl std::fmt::Display for PqRuntimeConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSlotDuration => {
                formatter.write_str("lean PQ runtime requires an exact 300-second slot")
            }
            Self::MissingExecutionLayer => {
                formatter.write_str("lean PQ runtime requires an execution layer")
            }
            Self::MissingExecutionEndpoint => {
                formatter.write_str("lean PQ runtime requires a real execution endpoint")
            }
            Self::MissingJwtSecret => {
                formatter.write_str("lean PQ runtime requires an explicit JWT secret path")
            }
            Self::ProposerRequiresHttp => {
                formatter.write_str("lean PQ proposer requires the narrow HTTP API")
            }
            Self::ProposerFeatureDisabled => {
                formatter.write_str("PQ validator bundle requires the pq-proposer feature")
            }
            Self::UnsupportedOption(option) => {
                write!(formatter, "lean PQ runtime does not support {option}")
            }
            Self::InvalidStoreConfiguration => {
                formatter.write_str("lean PQ runtime store configuration is invalid")
            }
            Self::Client(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PqRuntimeConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(error) => Some(error),
            Self::InvalidSlotDuration
            | Self::MissingExecutionLayer
            | Self::MissingExecutionEndpoint
            | Self::MissingJwtSecret
            | Self::ProposerRequiresHttp
            | Self::ProposerFeatureDisabled
            | Self::UnsupportedOption(_)
            | Self::InvalidStoreConfiguration => None,
        }
    }
}

pub(crate) struct PqRuntimeOwner {
    chain: Arc<PqDiskChain>,
    network_globals: Arc<NetworkGlobals<MinimalEthSpec>>,
    broadcaster: PqBlockBroadcastSender<MinimalEthSpec>,
    http_api_listen_addr: Option<std::net::SocketAddr>,
    _local_http_url: Option<sensitive_url::SensitiveUrl>,
    http_shutdown: Option<PqHttpServerShutdown>,
    #[cfg(feature = "pq-proposer")]
    _proposer_service: Option<Arc<PqProposerService<SystemTimeSlotClock>>>,
    #[cfg(feature = "pq-proposer")]
    proposer_loop: Option<PqProposerLoopShutdown>,
    #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
    validator_identities: Option<Vec<(consensus_signature::ValidatorPublicKeyBytes, u64)>>,
    network_shutdown: PqNetworkServiceShutdown,
    operational_events: Arc<PqOperationalEventSink>,
    operational_event_completion: tokio::sync::oneshot::Receiver<
        Result<Result<(), PqOperationalEventError>, tokio::task::JoinError>,
    >,
}

impl PqRuntimeOwner {
    async fn start(
        context: RuntimeContext<MinimalEthSpec>,
        config: PqRuntimeConfig,
    ) -> Result<Self, PqRuntimeError> {
        let spec = Arc::clone(&context.eth2_config.spec);
        let blocking_spec = Arc::clone(&spec);
        let plan = config.validate(&spec)?;
        let executor = context.executor.clone();
        let blocking_executor = context.executor.clone();
        #[cfg(feature = "pq-proposer")]
        let operational_event_role = if plan.proposer.is_some() {
            PqOperationalEventRole::Proposer
        } else {
            PqOperationalEventRole::Verifier
        };
        #[cfg(not(feature = "pq-proposer"))]
        let operational_event_role = PqOperationalEventRole::Verifier;
        let (operational_events, operational_event_writer) =
            PqOperationalEventSink::channel(operational_event_role);
        let mut operational_event_failure = executor.shutdown_sender();
        let (operational_event_live_sender, operational_event_live_receiver) =
            tokio::sync::oneshot::channel();
        let operational_event_completion = executor
            .spawn_blocking_handle_without_exit(
                move || {
                    let result = operational_event_writer
                        .run_with_live_signal(operational_event_live_sender);
                    if result.is_err() {
                        let _ = operational_event_failure.try_send(
                            task_executor::ShutdownReason::Failure(
                                "PQ operational event writer failed",
                            ),
                        );
                    }
                    result
                },
                "pq-operational-event-writer",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?;
        operational_event_live_receiver
            .await
            .map_err(|_| PqRuntimeError::TaskUnavailable)?;
        let operational_events = Arc::new(operational_events);
        operational_events
            .try_emit(PqOperationalEvent::EventWriterReady)
            .map_err(PqRuntimeError::OperationalEvent)?;
        let testnet_dir = plan
            .genesis_state_path
            .parent()
            .ok_or(PqRuntimeError::PublicTestnet(
                PqPublicTestnetError::UnsafeLayout("genesis path has no public testnet directory"),
            ))?
            .to_path_buf();
        let jwt_secret_path = plan.jwt_secret_path.clone();
        #[cfg(feature = "pq-startup-testing")]
        let genesis_read_test_hook = plan.genesis_read_test_hook.clone();
        let public_testnet = context
            .executor
            .spawn_blocking_handle(
                move || {
                    execution_layer::validate_jwt_secret_file(&jwt_secret_path)
                        .map_err(PqRuntimeError::JwtInvalid)?;
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = genesis_read_test_hook.as_ref() {
                        hook();
                    }
                    load_pq_public_testnet(&testnet_dir).map_err(PqRuntimeError::PublicTestnet)
                },
                "pq-runtime-read-only-network-preflight",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .await
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))??;
        let preparation_spec = Arc::clone(&blocking_spec);
        let chain_operational_events = Arc::downgrade(&operational_events);
        let prepared_runtime = context
            .executor
            .spawn_blocking_handle(
                move || {
                    let expected_network_identity = (
                        public_testnet.genesis_validators_root,
                        public_testnet.genesis_time,
                    );
                    #[cfg(feature = "pq-proposer")]
                    let validator_registry = public_testnet.validator_registry.to_vec();
                    let has_existing_store_path =
                        [&plan.hot_db_path, &plan.cold_db_path, &plan.blobs_db_path]
                            .into_iter()
                            .any(|path| path.exists());
                    let genesis_state_configured = match &plan.client.genesis {
                        ClientGenesis::GenesisState => true,
                        ClientGenesis::FromStore => false,
                        _ => return Err(PqRuntimeError::UnsupportedGenesis),
                    };
                    let mut public_testnet = Some(public_testnet);
                    let mut consume_genesis_state = || {
                        let state = public_testnet
                            .take()
                            .ok_or(PqRuntimeError::PublicTestnet(
                                PqPublicTestnetError::UnsafeLayout(
                                    "sealed genesis was consumed more than once",
                                ),
                            ))?
                            .into_genesis_state(&preparation_spec)
                            .map_err(PqRuntimeError::PublicTestnet)?;
                        state_processing::validate_lean_pq_devnet_v1(
                            &state,
                            &preparation_spec,
                            state.slot(),
                        )
                        .map_err(PqRuntimeError::GenesisProfile)?;
                        Ok::<BeaconState<MinimalEthSpec>, PqRuntimeError>(state)
                    };
                    let prevalidated_genesis =
                        if genesis_state_configured && !has_existing_store_path {
                            Some(consume_genesis_state()?)
                        } else {
                            None
                        };

                    for path in [&plan.hot_db_path, &plan.cold_db_path, &plan.blobs_db_path] {
                        std::fs::create_dir_all(path).map_err(|error| {
                            PqRuntimeError::Directory {
                                path: path.clone(),
                                error,
                            }
                        })?;
                    }
                    let store = HotColdDB::open(
                        &plan.hot_db_path,
                        &plan.cold_db_path,
                        &plan.blobs_db_path,
                        migrate_pq_schema::<PqDiskWitness>,
                        plan.client.store.clone(),
                        Arc::clone(&preparation_spec),
                    )
                    .map_err(PqRuntimeError::Store)?;
                    let startup =
                        classify_pq_store_startup(&store).map_err(PqRuntimeError::StoreStartup)?;
                    let builder = BeaconChainBuilder::<PqDiskWitness>::pq_new(MinimalEthSpec)
                        .store(store)
                        .custom_spec(Arc::clone(&preparation_spec))
                        .pq_operational_events(chain_operational_events);
                    let builder = match startup {
                        PqStoreStartup::Empty if genesis_state_configured => {
                            let state = match prevalidated_genesis {
                                Some(state) => state,
                                None => consume_genesis_state()?,
                            };
                            builder
                                .genesis_state(state)
                                .map_err(PqRuntimeError::Chain)?
                        }
                        PqStoreStartup::Empty => {
                            return Err(PqRuntimeError::EmptyStoreRequiresGenesis);
                        }
                        PqStoreStartup::Resume => {
                            builder.resume_from_db().map_err(PqRuntimeError::Chain)?
                        }
                    };
                    if builder
                        .pq_snapshot_network_identity()
                        .map_err(PqRuntimeError::Chain)?
                        != expected_network_identity
                    {
                        return Err(PqRuntimeError::PersistedNetworkIdentityMismatch);
                    }
                    Ok::<_, PqRuntimeError>(PqPreparedDiskRuntime {
                        builder,
                        startup,
                        plan,
                        #[cfg(feature = "pq-proposer")]
                        network_identity: expected_network_identity,
                        #[cfg(feature = "pq-proposer")]
                        validator_registry,
                    })
                },
                "pq-runtime-open-and-bind-disk",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .await
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))??;
        let prepared_runtime = Box::new(prepared_runtime);
        #[cfg(feature = "pq-proposer")]
        let (prepared_runtime, initialized_validators) =
            if let Some(proposer) = prepared_runtime.plan.proposer.as_ref() {
                let bundle_dir = proposer.bundle_dir.clone();
                let network_identity = prepared_runtime.network_identity;
                let validator_registry = prepared_runtime.validator_registry.clone();
                #[cfg(feature = "pq-startup-testing")]
                let test_barriers = prepared_runtime.plan.bundle_auth_test_barriers.clone();
                let authentication_executor = context.executor.clone();
                let (sender, receiver) = tokio::sync::oneshot::channel();
                context.executor.spawn(
                    async move {
                        #[cfg(feature = "pq-startup-testing")]
                        if let Some((entered, _)) = test_barriers.as_ref() {
                            entered.wait().await;
                        }
                        let result = initialized_validators::InitializedValidators::from_pq_bundle(
                            bundle_dir,
                            network_identity.0.0,
                            network_identity.1,
                            validator_registry,
                            authentication_executor,
                        )
                        .await;
                        #[cfg(feature = "pq-startup-testing")]
                        if let Some((_, completed)) = test_barriers.as_ref() {
                            completed.wait().await;
                        }
                        let _ = sender.send((prepared_runtime, result));
                    },
                    "pq-runtime-authenticate-validator-bundle",
                );
                let (prepared_runtime, initialized) = receiver
                    .await
                    .map_err(|_| PqRuntimeError::TaskUnavailable)?;
                (
                    prepared_runtime,
                    Some(initialized.map_err(PqRuntimeError::ValidatorInitialization)?),
                )
            } else {
                (prepared_runtime, None)
            };
        let blocking_runtime = context
            .executor
            .spawn_blocking_handle(
                move || {
                    let PqPreparedDiskRuntime {
                        builder,
                        startup,
                        plan,
                        #[cfg(feature = "pq-proposer")]
                            network_identity: _,
                        #[cfg(feature = "pq-proposer")]
                            validator_registry: _,
                    } = *prepared_runtime;
                    let aggregation =
                        Arc::new(AggregationService::new().map_err(PqRuntimeError::Aggregation)?);
                    let execution_config = plan
                        .client
                        .execution_layer
                        .clone()
                        .ok_or(PqRuntimeError::MissingExecutionLayer)?;
                    let execution = Arc::new(
                        execution_layer::ExecutionLayer::from_config(
                            execution_config,
                            blocking_executor.clone(),
                        )
                        .map_err(PqRuntimeError::Execution)?,
                    );
                    let chain_builder = builder
                        .pq_aggregation_service(aggregation)
                        .pq_execution_layer(execution)
                        .task_executor(blocking_executor.clone());
                    #[cfg(feature = "pq-startup-testing")]
                    let chain_builder = match plan.execution_notifier.as_ref() {
                        Some(notifier) => {
                            chain_builder.testing_only_pq_execution_notifier(notifier.clone())
                        }
                        None => chain_builder,
                    };
                    let chain = chain_builder.build().map_err(PqRuntimeError::Chain)?;
                    let chain = Arc::new(chain);
                    #[cfg(feature = "pq-proposer")]
                    let validator_store = match (initialized_validators, plan.proposer.as_ref()) {
                        (Some(initialized), Some(proposer)) => {
                            let proposer_dir = proposer.slashing_db.parent().ok_or_else(|| {
                                PqRuntimeError::Directory {
                                    path: proposer.slashing_db.clone(),
                                    error: std::io::Error::other(
                                        "PQ slashing path has no parent directory",
                                    ),
                                }
                            })?;
                            std::fs::create_dir_all(proposer_dir).map_err(|error| {
                                PqRuntimeError::Directory {
                                    path: proposer_dir.to_path_buf(),
                                    error,
                                }
                            })?;
                            #[cfg(unix)]
                            std::fs::set_permissions(
                                proposer_dir,
                                std::os::unix::fs::PermissionsExt::from_mode(0o700),
                            )
                            .map_err(|error| {
                                PqRuntimeError::Directory {
                                    path: proposer_dir.to_path_buf(),
                                    error,
                                }
                            })?;
                            let slashing = slashing_protection::SlashingDatabase::open_or_create(
                                &proposer.slashing_db,
                            )
                            .map_err(PqRuntimeError::Slashing)?;
                            let identities = initialized
                                .pq_validator_identity_snapshot()
                                .ok_or(PqRuntimeError::ProposerPreflightInvariant)?;
                            register_pq_validator_identities(&slashing, &identities)?;
                            Some(Arc::new(LighthouseValidatorStore::new(
                                initialized,
                                slashing,
                                chain.head_snapshot().beacon_state.genesis_validators_root(),
                                Arc::clone(&blocking_spec),
                                None,
                                chain.slot_clock.clone(),
                                &ValidatorStoreConfig::default(),
                                blocking_executor.clone(),
                            )))
                        }
                        (None, None) => None,
                        _ => return Err(PqRuntimeError::ProposerPreflightInvariant),
                    };
                    #[cfg(feature = "pq-startup-testing")]
                    if let Some(hook) = plan.blocking_test_hook.as_ref() {
                        hook();
                    }
                    let network_config = Arc::new(plan.client.network.clone());
                    let http_api_config = plan.client.http_api.clone();
                    Ok::<_, PqRuntimeError>(PqBlockingRuntime {
                        chain,
                        startup,
                        #[cfg(feature = "pq-proposer")]
                        validator_store,
                        network_config,
                        http_api_config,
                        #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
                        fail_proposer_construction: plan.fail_proposer_construction,
                        #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
                        fail_proposer_loop_start: plan.fail_proposer_loop_start,
                        #[cfg(feature = "pq-startup-testing")]
                        fail_runtime_ready_event: plan.fail_runtime_ready_event,
                    })
                },
                "pq-runtime-build-disk-owner",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .await
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))??;
        let PqBlockingRuntime {
            chain,
            startup,
            #[cfg(feature = "pq-proposer")]
            validator_store,
            network_config,
            http_api_config,
            #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
            fail_proposer_construction,
            #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
            fail_proposer_loop_start,
            #[cfg(feature = "pq-startup-testing")]
            fail_runtime_ready_event,
        } = blocking_runtime;
        chain
            .reconcile_persisted_pq_head()
            .await
            .map_err(PqRuntimeError::ExecutionReconciliation)?;
        let ready_identity = chain
            .pq_operational_head_identity()
            .await
            .map_err(PqRuntimeError::ExecutionReconciliation)?;
        let runtime_startup = match startup {
            PqStoreStartup::Empty => PqRuntimeStartup::Fresh,
            PqStoreStartup::Resume => PqRuntimeStartup::Resume,
        };
        let runtime_ready_event = PqOperationalEvent::RuntimeReady {
            startup: runtime_startup,
            slot: ready_identity.slot,
            block_root: ready_identity.block_root,
            execution_hash: ready_identity.execution_hash,
            finalized_epoch: ready_identity.finalized_epoch,
            finalized_root: ready_identity.finalized_root,
            signed_ssz_digest: ready_identity.signed_ssz_digest,
        };
        let network_dir = network_config.network_dir.clone();
        let key_network_config = Arc::clone(&network_config);
        let local_keypair = context
            .executor
            .spawn_blocking_handle(
                move || {
                    std::fs::create_dir_all(&network_dir).map_err(|error| {
                        PqRuntimeError::Directory {
                            path: network_dir,
                            error,
                        }
                    })?;
                    Ok::<_, PqRuntimeError>(load_private_key(&key_network_config))
                },
                "pq-runtime-create-network-owner",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .await
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))??;
        let head = chain.head_snapshot();
        let genesis_validators_root = head.beacon_state.genesis_validators_root();
        let fork_context = Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        ));
        let enr_fork_id =
            spec.enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root);
        drop(head);
        let network_context = Context {
            config: network_config,
            enr_fork_id,
            fork_context,
            chain_spec: Arc::clone(&spec),
            libp2p_registry: None,
        };
        let (broadcaster, broadcast_receiver) = pq_block_broadcast_channel();
        let service = PqNetworkService::new(
            executor.clone(),
            network_context,
            spec.custody_requirement,
            local_keypair,
            Arc::clone(&chain),
            broadcast_receiver,
            Arc::clone(&operational_events),
        )
        .await
        .map_err(PqRuntimeError::Network)?;
        let network_globals = service.network_globals();
        let network_shutdown = service
            .start_with_shutdown_receipt()
            .await
            .map_err(PqRuntimeError::Network)?;
        let (http_api_listen_addr, local_http_url, http_shutdown) = if http_api_config.enabled {
            match start_pq_http_server(
                Arc::clone(&chain),
                executor.clone(),
                broadcaster.clone(),
                &http_api_config,
            )
            .await
            {
                Ok((address, local_url, shutdown)) => {
                    (Some(address), Some(local_url), Some(shutdown))
                }
                Err(error) => {
                    Box::pin(cleanup_pq_post_bind_owners(
                        None,
                        broadcaster,
                        network_shutdown,
                        Arc::clone(&chain),
                        operational_events,
                        operational_event_completion,
                    ))
                    .await;
                    return Err(error);
                }
            }
        } else {
            (None, None, None)
        };
        #[cfg(feature = "pq-proposer")]
        let mut http_shutdown = http_shutdown;
        #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
        let validator_identities = validator_store
            .as_ref()
            .and_then(|store| store.pq_validator_identity_snapshot());
        #[cfg(feature = "pq-proposer")]
        let proposer_service_result = (|| {
            Ok(match validator_store {
                Some(validator_store) => {
                    #[cfg(feature = "pq-startup-testing")]
                    if fail_proposer_construction {
                        return Err(PqRuntimeError::ProposerPreflightInvariant);
                    }
                    let local_url = local_http_url
                        .clone()
                        .ok_or(PqRuntimeError::ProposerPreflightInvariant)?;
                    let beacon_node = eth2::StrictBeaconNodeHttpClient::from_builder(
                        local_url,
                        eth2::Timeouts::set_all(Duration::from_secs(285)),
                        reqwest::Client::builder().no_proxy().http1_only(),
                    )
                    .map_err(PqRuntimeError::HttpClient)?;
                    Some(Arc::new(
                        PqProposerService::new(
                            chain.slot_clock.clone(),
                            executor.clone(),
                            validator_store,
                            beacon_node,
                        )
                        .map_err(PqRuntimeError::Proposer)?,
                    ))
                }
                None => None,
            })
        })();
        #[cfg(feature = "pq-proposer")]
        let proposer_service = match proposer_service_result {
            Ok(service) => service,
            Err(error) => {
                Box::pin(cleanup_pq_post_bind_owners(
                    http_shutdown.take(),
                    broadcaster,
                    network_shutdown,
                    Arc::clone(&chain),
                    operational_events,
                    operational_event_completion,
                ))
                .await;
                return Err(error);
            }
        };
        #[cfg(feature = "pq-proposer")]
        let parked_proposer_loop = match proposer_service.as_ref() {
            Some(service) => {
                #[cfg(feature = "pq-startup-testing")]
                let start = if fail_proposer_loop_start {
                    Err(PqRuntimeError::TaskUnavailable)
                } else {
                    start_pq_proposer_loop_parked(
                        Arc::clone(service),
                        chain.slot_clock.clone(),
                        executor,
                        runtime_startup,
                    )
                    .await
                };
                #[cfg(not(feature = "pq-startup-testing"))]
                let start = start_pq_proposer_loop_parked(
                    Arc::clone(service),
                    chain.slot_clock.clone(),
                    executor,
                    runtime_startup,
                )
                .await;
                match start {
                    Ok(proposer_loop) => Some(proposer_loop),
                    Err(error) => {
                        Box::pin(cleanup_pq_post_bind_owners(
                            http_shutdown.take(),
                            broadcaster,
                            network_shutdown,
                            Arc::clone(&chain),
                            operational_events,
                            operational_event_completion,
                        ))
                        .await;
                        return Err(error);
                    }
                }
            }
            None => None,
        };
        #[cfg(feature = "pq-startup-testing")]
        if fail_runtime_ready_event {
            operational_events.testing_only_fail_closed();
        }
        #[cfg(feature = "pq-proposer")]
        let proposer_loop = match acknowledge_runtime_ready_and_release_proposer(
            &operational_events,
            runtime_ready_event,
            parked_proposer_loop,
        )
        .await
        {
            Ok(proposer_loop) => proposer_loop,
            Err(error) => {
                Box::pin(cleanup_pq_post_bind_owners(
                    http_shutdown.take(),
                    broadcaster,
                    network_shutdown,
                    Arc::clone(&chain),
                    operational_events,
                    operational_event_completion,
                ))
                .await;
                return Err(error);
            }
        };
        #[cfg(not(feature = "pq-proposer"))]
        if let Err(error) = operational_events.emit_and_wait(runtime_ready_event).await {
            Box::pin(cleanup_pq_post_bind_owners(
                http_shutdown,
                broadcaster,
                network_shutdown,
                Arc::clone(&chain),
                operational_events,
                operational_event_completion,
            ))
            .await;
            return Err(PqRuntimeError::OperationalEvent(error));
        }
        Ok(Self {
            chain,
            network_globals,
            broadcaster,
            http_api_listen_addr,
            _local_http_url: local_http_url,
            http_shutdown,
            #[cfg(feature = "pq-proposer")]
            _proposer_service: proposer_service,
            #[cfg(feature = "pq-proposer")]
            proposer_loop,
            #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
            validator_identities,
            network_shutdown,
            operational_events,
            operational_event_completion,
        })
    }

    fn beacon_chain(&self) -> Arc<PqDiskChain> {
        Arc::clone(&self.chain)
    }

    fn network_globals(&self) -> Arc<NetworkGlobals<MinimalEthSpec>> {
        Arc::clone(&self.network_globals)
    }

    async fn shutdown(self) -> Result<(), PqRuntimeError> {
        let Self {
            chain,
            network_globals: _,
            broadcaster,
            http_api_listen_addr: _,
            _local_http_url: _,
            http_shutdown,
            #[cfg(feature = "pq-proposer")]
                _proposer_service: proposer_service,
            #[cfg(feature = "pq-proposer")]
            proposer_loop,
            #[cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]
                validator_identities: _,
            network_shutdown,
            operational_events,
            operational_event_completion,
        } = self;
        #[cfg(feature = "pq-proposer")]
        let proposer_result = match proposer_loop {
            Some(proposer_loop) => proposer_loop.wait().await,
            None => Ok(()),
        };
        let http_result = match http_shutdown {
            Some(http_shutdown) => http_shutdown.wait().await,
            None => Ok(()),
        };
        drop(broadcaster);
        let network_result = network_shutdown
            .wait()
            .await
            .map_err(PqRuntimeError::Network);
        chain.close_and_drain_pq_imports().await;
        drop(operational_events);
        let operational_event_result = operational_event_completion
            .await
            .map_err(|_| PqRuntimeError::TaskUnavailable)?
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))?
            .map_err(PqRuntimeError::OperationalEvent);
        #[cfg(feature = "pq-proposer")]
        drop(proposer_service);
        #[cfg(feature = "pq-proposer")]
        if let Err(error) = proposer_result {
            return Err(error);
        }
        operational_event_result?;
        match (http_result, network_result) {
            (Err(http_error), _) => Err(http_error),
            (Ok(()), Err(network_error)) => Err(network_error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Client<PqDiskWitness> {
    pub async fn start_pq_runtime(
        context: RuntimeContext<MinimalEthSpec>,
        config: PqRuntimeConfig,
    ) -> Result<Self, PqRuntimeError> {
        let owner = Box::pin(PqRuntimeOwner::start(context, config)).await?;
        Ok(Self {
            beacon_chain: Some(owner.beacon_chain()),
            network_globals: Some(owner.network_globals()),
            http_api_listen_addr: owner.http_api_listen_addr,
            http_metrics_listen_addr: None,
            pq_runtime_owner: Some(owner),
        })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_broadcaster(&self) -> Option<PqBlockBroadcastSender<MinimalEthSpec>> {
        self.pq_runtime_owner
            .as_ref()
            .map(|owner| owner.broadcaster.clone())
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_local_http_url(&self) -> Option<sensitive_url::SensitiveUrl> {
        self.pq_runtime_owner.as_ref()?._local_http_url.clone()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub async fn testing_only_stop_pq_http_unexpectedly(&self) -> Result<(), PqRuntimeError> {
        self.pq_runtime_owner
            .as_ref()
            .and_then(|owner| owner.http_shutdown.as_ref())
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .testing_only_stop_unexpectedly()
            .await
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_pq_validator_identities(
        &self,
    ) -> Option<Vec<(consensus_signature::ValidatorPublicKeyBytes, u64)>> {
        self.pq_runtime_owner.as_ref()?.validator_identities.clone()
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_pq_proposer_is_running(&self) -> bool {
        self.pq_runtime_owner
            .as_ref()
            .is_some_and(|owner| owner._proposer_service.is_some())
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub async fn testing_only_wait_for_pq_proposer_attempt(&self) -> Result<(), PqRuntimeError> {
        let observer = &self
            .pq_runtime_owner
            .as_ref()
            .and_then(|owner| owner.proposer_loop.as_ref())
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .observer;
        loop {
            if observer.attempts.load(Ordering::SeqCst) > 0 {
                return Ok(());
            }
            observer.attempt.notified().await;
        }
    }

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_pq_proposer_max_retained_receipts(&self) -> Option<usize> {
        let observer = &self
            .pq_runtime_owner
            .as_ref()?
            .proposer_loop
            .as_ref()?
            .observer;
        Some(observer.max_retained_receipts.load(Ordering::SeqCst))
    }

    pub async fn shutdown(mut self) -> Result<(), PqRuntimeError> {
        match self.pq_runtime_owner.take() {
            Some(owner) => owner.shutdown().await,
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum PqRuntimeError {
    Config(PqRuntimeConfigError),
    JwtInvalid(execution_layer::Error),
    GenesisRead(String),
    GenesisDecode(String),
    GenesisProfile(state_processing::PqDevnetStateError),
    PublicTestnet(PqPublicTestnetError),
    #[cfg(feature = "pq-proposer")]
    ValidatorInitialization(initialized_validators::Error),
    #[cfg(feature = "pq-proposer")]
    Slashing(slashing_protection::NotSafe),
    ProposerPreflightInvariant,
    PersistedNetworkIdentityMismatch,
    UnsupportedGenesis,
    Directory {
        path: PathBuf,
        error: std::io::Error,
    },
    Store(store::Error),
    StoreStartup(beacon_chain::PqStoreStartupError),
    EmptyStoreRequiresGenesis,
    MissingExecutionLayer,
    Aggregation(consensus_signature::AggregationError),
    Execution(execution_layer::Error),
    Chain(beacon_chain::PqRuntimeError),
    ExecutionReconciliation(beacon_chain::PqImportError),
    OperationalEvent(PqOperationalEventError),
    Network(PqNetworkServiceError),
    HttpConfiguration(network::PqBlockPublicationConfigurationError),
    HttpBind(std::io::Error),
    HttpUrl(String),
    HttpUnexpectedExit,
    #[cfg(feature = "pq-proposer")]
    HttpClient(eth2::Error),
    #[cfg(feature = "pq-proposer")]
    Proposer(pq_proposer_service::PqProposerServiceError),
    TaskUnavailable,
    TaskJoin(String),
}

impl From<PqRuntimeConfigError> for PqRuntimeError {
    fn from(error: PqRuntimeConfigError) -> Self {
        Self::Config(error)
    }
}

impl std::fmt::Display for PqRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => error.fmt(formatter),
            Self::JwtInvalid(error) => write!(formatter, "invalid PQ JWT secret: {error:?}"),
            Self::GenesisRead(error) => write!(formatter, "could not read PQ genesis: {error}"),
            Self::GenesisDecode(error) => write!(formatter, "invalid PQ genesis SSZ: {error}"),
            Self::GenesisProfile(error) => error.fmt(formatter),
            Self::PublicTestnet(error) => error.fmt(formatter),
            #[cfg(feature = "pq-proposer")]
            Self::ValidatorInitialization(error) => error.fmt(formatter),
            #[cfg(feature = "pq-proposer")]
            Self::Slashing(error) => error.fmt(formatter),
            Self::ProposerPreflightInvariant => {
                formatter.write_str("PQ proposer preflight ownership invariant failed")
            }
            Self::PersistedNetworkIdentityMismatch => {
                formatter.write_str("persisted PQ head does not match the sealed testnet identity")
            }
            Self::UnsupportedGenesis => formatter.write_str("unsupported PQ genesis mode"),
            Self::Directory { path, error } => {
                write!(formatter, "could not create {}: {error}", path.display())
            }
            Self::Store(error) => write!(formatter, "could not open PQ store: {error:?}"),
            Self::StoreStartup(error) => error.fmt(formatter),
            Self::EmptyStoreRequiresGenesis => {
                formatter.write_str("empty PQ store requires an explicit genesis state")
            }
            Self::MissingExecutionLayer => {
                formatter.write_str("validated PQ plan lost its execution layer")
            }
            Self::Aggregation(error) => error.fmt(formatter),
            Self::Execution(error) => {
                write!(
                    formatter,
                    "could not construct PQ execution layer: {error:?}"
                )
            }
            Self::Chain(error) => error.fmt(formatter),
            Self::ExecutionReconciliation(error) => error.fmt(formatter),
            Self::OperationalEvent(error) => error.fmt(formatter),
            Self::Network(error) => error.fmt(formatter),
            Self::HttpConfiguration(error) => error.fmt(formatter),
            Self::HttpBind(error) => write!(formatter, "could not bind PQ HTTP API: {error}"),
            Self::HttpUrl(error) => write!(formatter, "invalid PQ local HTTP URL: {error}"),
            Self::HttpUnexpectedExit => formatter.write_str("PQ HTTP API exited unexpectedly"),
            #[cfg(feature = "pq-proposer")]
            Self::HttpClient(error) => write!(
                formatter,
                "could not construct strict PQ HTTP client: {error}"
            ),
            #[cfg(feature = "pq-proposer")]
            Self::Proposer(error) => error.fmt(formatter),
            Self::TaskUnavailable => formatter.write_str("PQ runtime executor is unavailable"),
            Self::TaskJoin(error) => write!(formatter, "PQ runtime blocking task failed: {error}"),
        }
    }
}

impl std::error::Error for PqRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::GenesisProfile(error) => Some(error),
            Self::PublicTestnet(error) => Some(error),
            #[cfg(feature = "pq-proposer")]
            Self::ValidatorInitialization(error) => Some(error),
            Self::Directory { error, .. } => Some(error),
            Self::StoreStartup(error) => Some(error),
            Self::Aggregation(error) => Some(error),
            Self::Chain(error) => Some(error),
            Self::ExecutionReconciliation(error) => Some(error),
            Self::OperationalEvent(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::HttpConfiguration(error) => Some(error),
            Self::HttpBind(error) => Some(error),
            #[cfg(feature = "pq-proposer")]
            Self::Proposer(error) => Some(error),
            #[cfg(feature = "pq-proposer")]
            Self::Slashing(_) => None,
            #[cfg(feature = "pq-proposer")]
            Self::HttpClient(_) => None,
            Self::JwtInvalid(_)
            | Self::GenesisRead(_)
            | Self::GenesisDecode(_)
            | Self::PersistedNetworkIdentityMismatch
            | Self::ProposerPreflightInvariant
            | Self::UnsupportedGenesis
            | Self::EmptyStoreRequiresGenesis
            | Self::Store(_)
            | Self::MissingExecutionLayer
            | Self::Execution(_)
            | Self::HttpUrl(_)
            | Self::HttpUnexpectedExit
            | Self::TaskUnavailable
            | Self::TaskJoin(_) => None,
        }
    }
}

#[cfg(all(test, feature = "pq-proposer"))]
mod tests {
    use super::*;
    use consensus_signature::{PqPublicKey, ValidatorPublicKeyBytes};

    #[test]
    fn canonical_multi_identity_registration_is_atomic_on_late_conflict() {
        let directory = tempfile::tempdir().expect("slashing fixture");
        let database_path = directory.path().join("slashing_protection.sqlite");
        let database = slashing_protection::SlashingDatabase::create(&database_path)
            .expect("initialize slashing database schema");
        let identities = (1_u8..=3)
            .zip(0_u64..)
            .map(|(byte, index)| {
                (
                    PqPublicKey::deserialize(&[byte; 32]).expect("synthetic PQ public key"),
                    index,
                )
            })
            .collect::<Vec<(ValidatorPublicKeyBytes, u64)>>();
        let rejected_public_key = identities.last().expect("third identity").0.as_hex_string();
        drop(database);
        let connection = rusqlite::Connection::open(&database_path).expect("trigger connection");
        connection
            .execute_batch(&format!(
                "CREATE TRIGGER reject_third_validator BEFORE INSERT ON validators \
                 WHEN NEW.public_key = '{rejected_public_key}' \
                 BEGIN SELECT RAISE(ABORT, 'injected registration conflict'); END;"
            ))
            .expect("registration conflict trigger");
        drop(connection);
        let database = slashing_protection::SlashingDatabase::open(&database_path)
            .expect("reopen slashing database with conflict trigger");

        assert!(matches!(
            register_pq_validator_identities(&database, &identities),
            Err(PqRuntimeError::Slashing(_)),
        ));
        assert_eq!(
            database.num_validator_rows().expect("row count"),
            0,
            "a late registration conflict must roll back the whole identity set",
        );

        drop(database);
        let connection = rusqlite::Connection::open(&database_path).expect("trigger connection");
        connection
            .execute_batch("DROP TRIGGER reject_third_validator")
            .expect("remove registration conflict");
        drop(connection);
        let database = slashing_protection::SlashingDatabase::open(&database_path)
            .expect("reopen slashing database after conflict");
        register_pq_validator_identities(&database, &identities)
            .expect("canonical identity registration");
        assert_eq!(database.num_validator_rows().expect("row count"), 3);
        for (public_key, canonical_index) in identities {
            assert_eq!(
                database
                    .get_validator_id(&public_key)
                    .expect("registered validator ID"),
                i64::try_from(canonical_index).expect("small canonical index") + 1,
            );
        }
    }
}

#[cfg(all(test, feature = "pq-proposer", feature = "pq-startup-testing"))]
mod proposer_loop_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct TestingReceipt {
        slot: types::Slot,
        completion: tokio::sync::watch::Receiver<
            Option<Result<PqProposalCompletion, PqProposerServiceError>>,
        >,
    }

    impl PqProposerLoopReceipt for TestingReceipt {
        fn slot(&self) -> types::Slot {
            self.slot
        }

        fn completion(
            &self,
        ) -> futures::future::BoxFuture<'_, Result<PqProposalCompletion, PqProposerServiceError>>
        {
            async move {
                let mut completion = self.completion.clone();
                loop {
                    if let Some(result) = completion.borrow().clone() {
                        return result;
                    }
                    completion
                        .changed()
                        .await
                        .map_err(|_| PqProposerServiceError::TaskUnavailable)?;
                }
            }
            .boxed()
        }
    }

    struct TestingSource {
        now: std::sync::atomic::AtomicU64,
        now_calls: std::sync::atomic::AtomicUsize,
        genesis: types::Slot,
        starts: std::sync::atomic::AtomicUsize,
        boundary_checks: std::sync::atomic::AtomicUsize,
        now_script: Mutex<VecDeque<Option<types::Slot>>>,
        script: Mutex<VecDeque<Result<TestingReceipt, PqProposerServiceError>>>,
        stop_on_now_call: Mutex<Option<(usize, tokio::sync::oneshot::Sender<()>)>>,
    }

    impl TestingSource {
        fn new(
            now: Option<types::Slot>,
            genesis: types::Slot,
            script: Vec<Result<TestingReceipt, PqProposerServiceError>>,
        ) -> Self {
            Self {
                now: std::sync::atomic::AtomicU64::new(now.map_or(u64::MAX, |slot| slot.as_u64())),
                now_calls: std::sync::atomic::AtomicUsize::new(0),
                genesis,
                starts: std::sync::atomic::AtomicUsize::new(0),
                boundary_checks: std::sync::atomic::AtomicUsize::new(0),
                now_script: Mutex::new(VecDeque::new()),
                script: Mutex::new(script.into()),
                stop_on_now_call: Mutex::new(None),
            }
        }

        fn set_now(&self, now: Option<types::Slot>) {
            self.now
                .store(now.map_or(u64::MAX, |slot| slot.as_u64()), Ordering::SeqCst);
        }

        fn stop_on_now_call(&self, call: usize, sender: tokio::sync::oneshot::Sender<()>) {
            *self.stop_on_now_call.lock().expect("stop-on-now lock") = Some((call, sender));
        }

        fn script_now(&self, observations: impl IntoIterator<Item = Option<types::Slot>>) {
            self.now_script
                .lock()
                .expect("now script lock")
                .extend(observations);
        }
    }

    impl PqProposerLoopSource for Arc<TestingSource> {
        type Receipt = TestingReceipt;

        fn now(&self) -> Option<types::Slot> {
            let call = self.now_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let mut stop = self.stop_on_now_call.lock().expect("stop-on-now lock");
            if stop.as_ref().is_some_and(|(expected, _)| *expected == call)
                && let Some((_, sender)) = stop.take()
            {
                let _ = sender.send(());
            }
            if let Some(now) = self.now_script.lock().expect("now script lock").pop_front() {
                return now;
            }
            let now = self.now.load(Ordering::SeqCst);
            (now != u64::MAX).then(|| types::Slot::new(now))
        }

        fn genesis_slot(&self) -> types::Slot {
            self.genesis
        }

        fn duration_to_next_slot(&self) -> Option<Duration> {
            self.boundary_checks.fetch_add(1, Ordering::SeqCst);
            Some(Duration::from_secs(1))
        }

        fn try_propose_current_slot(&self) -> Result<Self::Receipt, PqProposerServiceError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            self.script
                .lock()
                .expect("testing script lock")
                .pop_front()
                .unwrap_or(Err(PqProposerServiceError::TaskUnavailable))
        }
    }

    fn receipt(
        slot: u64,
    ) -> (
        TestingReceipt,
        tokio::sync::watch::Sender<Option<Result<PqProposalCompletion, PqProposerServiceError>>>,
    ) {
        let (sender, completion) = tokio::sync::watch::channel(None);
        (
            TestingReceipt {
                slot: types::Slot::new(slot),
                completion,
            },
            sender,
        )
    }

    fn observer() -> Arc<PqProposerLoopObserver> {
        Arc::new(PqProposerLoopObserver::new())
    }

    async fn run_for_startup<S: PqProposerLoopSource>(
        source: S,
        shutdown_receiver: tokio::sync::oneshot::Receiver<()>,
        exit: impl std::future::Future<Output = ()> + Send + 'static,
        startup: PqRuntimeStartup,
        observer: Arc<PqProposerLoopObserver>,
    ) -> Result<(), PqProposerServiceError> {
        run_pq_proposer_loop(source, shutdown_receiver, exit, startup, observer).await
    }

    #[tokio::test(start_paused = true)]
    async fn resume_waits_for_the_first_post_release_slot_boundary() {
        let (next, completion) = receipt(5);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(5),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(4)),
            types::Slot::new(0),
            vec![Ok(next)],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_for_startup(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Resume,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            0,
            "Resume must mark the first observed slot skipped, not admit it",
        );
        source.set_now(Some(types::Slot::new(5)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        shutdown_sender.send(()).expect("stop resumed loop");
        assert!(task.await.expect("resumed loop task").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn resume_waits_for_clock_then_skips_first_successful_observation() {
        let (next, completion) = receipt(5);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(5),
        })));
        let source = Arc::new(TestingSource::new(
            None,
            types::Slot::new(0),
            vec![Ok(next)],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_for_startup(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Resume,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        assert_eq!(tokio::spawn(async { 53 }).await.expect("heartbeat"), 53);
        tokio::time::advance(PQ_PROPOSER_RETRY_DELAY - Duration::from_millis(1)).await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        source.set_now(Some(types::Slot::new(4)));
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            0,
            "the first successful clock observation is the skipped slot",
        );
        source.set_now(Some(types::Slot::new(5)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        shutdown_sender.send(()).expect("stop resumed loop");
        assert!(task.await.expect("resumed loop task").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn resume_ignores_rollback_and_admits_only_current_slot_after_jump() {
        let (jumped, completion) = receipt(7);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(7),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(4)),
            types::Slot::new(0),
            vec![Ok(jumped)],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_for_startup(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Resume,
            observer(),
        ));

        tokio::task::yield_now().await;
        source.set_now(Some(types::Slot::new(3)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        source.set_now(Some(types::Slot::new(4)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        source.set_now(Some(types::Slot::new(7)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            1,
            "a multi-slot jump admits the current slot once without catch-up",
        );
        shutdown_sender.send(()).expect("stop resumed loop");
        assert!(task.await.expect("resumed loop task").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn resume_marks_observed_slot_completed_across_a_boundary_rollback() {
        let (next, completion) = receipt(5);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(5),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(5)),
            types::Slot::new(0),
            vec![Ok(next)],
        ));
        source.script_now([
            Some(types::Slot::new(4)),
            Some(types::Slot::new(5)),
            Some(types::Slot::new(4)),
        ]);
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_for_startup(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Resume,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            0,
            "the observed slot remains completed if the clock rolls back after the boundary",
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        shutdown_sender.send(()).expect("stop resumed loop");
        assert!(task.await.expect("resumed loop task").is_ok());
    }

    #[tokio::test]
    async fn resume_stop_at_observed_boundary_prevents_admission() {
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(5)),
            types::Slot::new(0),
            vec![Err(PqProposerServiceError::TaskUnavailable)],
        ));
        source.script_now([Some(types::Slot::new(4)), Some(types::Slot::new(5))]);
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        source.stop_on_now_call(2, shutdown_sender);
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        assert!(
            run_for_startup(
                Arc::clone(&source),
                shutdown_receiver,
                async move {
                    let _ = exit_receiver.await;
                },
                PqRuntimeStartup::Resume,
                observer(),
            )
            .await
            .is_ok(),
        );
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resume_slot_overflow_is_fatal_and_signals_process_shutdown() {
        use futures::StreamExt;

        let source = Arc::new(TestingSource::new(None, types::Slot::new(0), vec![]));
        source.script_now([Some(types::Slot::new(u64::MAX))]);
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, mut process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );
        let parked =
            start_pq_proposer_loop_source_parked(source, executor, PqRuntimeStartup::Resume)
                .await
                .expect("live parked resumed loop");
        let result = tokio::time::timeout(Duration::from_secs(5), async move {
            match parked.release().await {
                Ok(shutdown) => shutdown.testing_only_wait_for_exit().await,
                Err(error) => Err(error),
            }
        })
        .await
        .expect("resumed overflow loop must terminate");
        assert!(matches!(
            result,
            Err(PqRuntimeError::Proposer(
                PqProposerServiceError::TimingOverflow
            )),
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), process_shutdown_receiver.next())
                .await
                .expect("fatal overflow must signal process shutdown"),
            Some(task_executor::ShutdownReason::Failure(
                "PQ proposer loop failed"
            )),
        ));
        drop(exit_sender);
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_and_clock_retries_are_bounded_but_executor_loss_is_fatal() {
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![
                Err(PqProposerServiceError::Capacity),
                Err(PqProposerServiceError::ClockUnavailable),
                Err(PqProposerServiceError::TaskUnavailable),
            ],
        ));
        let (_shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task_source = Arc::clone(&source);
        let task = tokio::spawn(run_pq_proposer_loop(
            task_source,
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Fresh,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        assert_eq!(tokio::spawn(async { 17 }).await.expect("heartbeat"), 17);
        tokio::time::advance(Duration::from_millis(999)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            task.await.expect("loop task"),
            Err(PqProposerServiceError::TaskUnavailable),
        ));
        assert_eq!(source.starts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn synchronous_stale_slot_waits_and_next_slot_can_succeed() {
        let (next, completion) = receipt(2);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(2),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![
                Err(PqProposerServiceError::StaleSlot {
                    slot: types::Slot::new(1),
                    highest_started: Some(types::Slot::new(1)),
                }),
                Ok(next),
            ],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_pq_proposer_loop(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Fresh,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        assert!(
            !task.is_finished(),
            "StaleSlot is slot-local, not loop-fatal"
        );
        source.set_now(Some(types::Slot::new(2)));
        tokio::time::advance(PQ_PROPOSER_RETRY_DELAY).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 2);
        shutdown_sender.send(()).expect("stop live loop");
        assert!(task.await.expect("loop task").is_ok());
    }

    #[tokio::test]
    async fn already_ready_stop_prevents_non_genesis_admission() {
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Err(PqProposerServiceError::TaskUnavailable)],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        shutdown_sender.send(()).expect("arm stop before loop");
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        assert!(
            run_pq_proposer_loop(
                Arc::clone(&source),
                shutdown_receiver,
                async move {
                    let _ = exit_receiver.await;
                },
                PqRuntimeStartup::Fresh,
                observer(),
            )
            .await
            .is_ok(),
        );
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stop_racing_completed_receipt_at_advanced_slot_prevents_next_admission() {
        let (first, completion) = receipt(1);
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Ok(first), Err(PqProposerServiceError::TaskUnavailable)],
        ));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        source.stop_on_now_call(2, shutdown_sender);
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_pq_proposer_loop(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Fresh,
            observer(),
        ));
        while source.starts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        source.set_now(Some(types::Slot::new(2)));
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(1),
        })));

        assert!(task.await.expect("loop task").is_ok());
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            1,
            "the stop made ready by the advanced-slot observation must win before admission",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn genesis_and_completed_same_slot_wait_for_recomputed_next_boundary() {
        let (first, first_completion) = receipt(1);
        first_completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(1),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(0)),
            types::Slot::new(0),
            vec![Ok(first), Err(PqProposerServiceError::TaskUnavailable)],
        ));
        let (_shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (_exit_sender, exit_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_pq_proposer_loop(
            Arc::clone(&source),
            shutdown_receiver,
            async move {
                let _ = exit_receiver.await;
            },
            PqRuntimeStartup::Fresh,
            observer(),
        ));

        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        source.set_now(Some(types::Slot::new(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        source.set_now(Some(types::Slot::new(2)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            task.await.expect("loop task"),
            Err(PqProposerServiceError::TaskUnavailable),
        ));
        assert_eq!(source.starts.load(Ordering::SeqCst), 2);
        assert!(source.boundary_checks.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn stop_retains_one_receipt_until_noncancellable_completion() {
        let (held, completion) = receipt(1);
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Ok(held)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, _process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );
        let loop_shutdown = start_pq_proposer_loop_source(source, executor)
            .await
            .expect("result-bearing loop owner");
        let observer = Arc::clone(&loop_shutdown.observer);
        while observer.attempts.load(Ordering::SeqCst) == 0 {
            observer.attempt.notified().await;
        }
        let task = tokio::spawn(loop_shutdown.wait());
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "stop must retain the admitted receipt");
        assert_eq!(observer.max_retained_receipts.load(Ordering::SeqCst), 1,);
        assert_eq!(tokio::spawn(async { 23 }).await.expect("heartbeat"), 23);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(1),
        })));
        assert!(task.await.expect("loop task").is_ok());
        drop(exit_sender);
    }

    #[tokio::test]
    async fn proposer_loop_is_live_but_parked_until_runtime_ready_is_written() {
        let (receipt, completion) = receipt(1);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(1),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Ok(receipt)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, _process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );

        let parked = start_pq_proposer_loop_source_parked(
            Arc::clone(&source),
            executor,
            PqRuntimeStartup::Fresh,
        )
        .await
        .expect("live parked proposer loop");
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            0,
            "first-poll liveness must not admit a proposal before RuntimeReady is written",
        );
        assert_eq!(tokio::spawn(async { 43 }).await.expect("heartbeat"), 43);

        let loop_shutdown = parked
            .release()
            .await
            .expect("release loop after RuntimeReady acknowledgement");
        let observer = Arc::clone(&loop_shutdown.observer);
        while observer.attempts.load(Ordering::SeqCst) == 0 {
            observer.attempt.notified().await;
        }
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        loop_shutdown.wait().await.expect("stop released loop");
        drop(exit_sender);
    }

    #[tokio::test(start_paused = true)]
    async fn resumed_parked_loop_samples_clock_only_after_runtime_ready_release() {
        let (receipt, completion) = receipt(6);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(6),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(4)),
            types::Slot::new(0),
            vec![Ok(receipt)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, _process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );

        let parked = start_pq_proposer_loop_source_parked(
            Arc::clone(&source),
            executor,
            PqRuntimeStartup::Resume,
        )
        .await
        .expect("live parked resumed loop");
        assert_eq!(
            source.now_calls.load(Ordering::SeqCst),
            0,
            "parked startup must not capture a pre-RuntimeReady slot",
        );
        source.set_now(Some(types::Slot::new(5)));
        let loop_shutdown = parked
            .release()
            .await
            .expect("release resumed loop after RuntimeReady acknowledgement");
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 0);
        source.set_now(Some(types::Slot::new(6)));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        loop_shutdown.wait().await.expect("stop resumed loop");
        drop(exit_sender);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_runtime_ready_output_keeps_the_live_proposer_loop_parked() {
        struct BlockedOutput {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }

        impl std::io::Write for BlockedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.entered
                    .send(())
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                self.release
                    .recv()
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (receipt, completion) = receipt(1);
        completion.send_replace(Some(Ok(PqProposalCompletion::NoLocalDuty {
            slot: types::Slot::new(1),
        })));
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Ok(receipt)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, _process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );
        let parked = start_pq_proposer_loop_source_parked(
            Arc::clone(&source),
            executor,
            PqRuntimeStartup::Fresh,
        )
        .await
        .expect("live parked proposer loop");
        let (sink, writer) = PqOperationalEventSink::channel(PqOperationalEventRole::Proposer);
        let sink = Arc::new(sink);
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let writer_thread = std::thread::spawn(move || {
            let mut output = BlockedOutput {
                entered: entered_sender,
                release: release_receiver,
            };
            writer.testing_only_run_with_output(&mut output)
        });
        let task_sink = Arc::clone(&sink);
        let readiness = tokio::spawn(async move {
            acknowledge_runtime_ready_and_release_proposer(
                &task_sink,
                PqOperationalEvent::RuntimeReady {
                    startup: PqRuntimeStartup::Fresh,
                    slot: types::Slot::new(0),
                    block_root: types::Hash256::ZERO,
                    execution_hash: types::ExecutionBlockHash::zero(),
                    finalized_epoch: types::Epoch::new(0),
                    finalized_root: types::Hash256::ZERO,
                    signed_ssz_digest: [0; 32],
                },
                Some(parked),
            )
            .await
        });

        entered_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("RuntimeReady writer entered");
        assert!(
            !readiness.is_finished(),
            "writer acknowledgement is pending"
        );
        assert_eq!(
            source.starts.load(Ordering::SeqCst),
            0,
            "proposal admission must remain parked while RuntimeReady output is blocked",
        );
        assert_eq!(tokio::spawn(async { 47 }).await.expect("heartbeat"), 47);
        release_sender.send(()).expect("release RuntimeReady write");
        let loop_shutdown = readiness
            .await
            .expect("readiness task")
            .expect("RuntimeReady acknowledgement")
            .expect("proposer loop owner");
        let observer = Arc::clone(&loop_shutdown.observer);
        while observer.attempts.load(Ordering::SeqCst) == 0 {
            observer.attempt.notified().await;
        }
        assert_eq!(source.starts.load(Ordering::SeqCst), 1);
        loop_shutdown.wait().await.expect("stop released loop");
        drop(sink);
        assert_eq!(writer_thread.join().expect("writer thread"), Ok(()));
        drop(exit_sender);
    }

    #[tokio::test]
    async fn stop_retains_fatal_receipt_and_propagates_failure_after_completion() {
        use futures::StreamExt;

        let (held, completion) = receipt(1);
        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Ok(held)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, mut process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );
        let loop_shutdown = start_pq_proposer_loop_source(source, executor)
            .await
            .expect("result-bearing loop owner");
        let observer = Arc::clone(&loop_shutdown.observer);
        while observer.attempts.load(Ordering::SeqCst) == 0 {
            observer.attempt.notified().await;
        }
        let task = tokio::spawn(loop_shutdown.wait());
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "stop must retain the fatal receipt");

        completion.send_replace(Some(Err(PqProposerServiceError::TaskUnavailable)));
        assert!(matches!(
            task.await.expect("loop task"),
            Err(PqRuntimeError::Proposer(
                PqProposerServiceError::TaskUnavailable
            )),
        ));
        assert!(matches!(
            process_shutdown_receiver.next().await,
            Some(task_executor::ShutdownReason::Failure(
                "PQ proposer loop failed"
            )),
        ));
        drop(exit_sender);
    }

    #[tokio::test]
    async fn fatal_executor_loss_signals_process_shutdown() {
        use futures::StreamExt;

        let source = Arc::new(TestingSource::new(
            Some(types::Slot::new(1)),
            types::Slot::new(0),
            vec![Err(PqProposerServiceError::TaskUnavailable)],
        ));
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (process_shutdown, mut process_shutdown_receiver) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            process_shutdown,
        );
        let error = match start_pq_proposer_loop_source(source, executor).await {
            Err(error) => error,
            Ok(shutdown) => shutdown
                .testing_only_wait_for_exit()
                .await
                .expect_err("executor loss must terminate the loop"),
        };
        assert!(matches!(
            error,
            PqRuntimeError::Proposer(PqProposerServiceError::TaskUnavailable),
        ));
        assert!(matches!(
            process_shutdown_receiver.next().await,
            Some(task_executor::ShutdownReason::Failure(
                "PQ proposer loop failed"
            )),
        ));
        drop(exit_sender);
    }

    #[test]
    fn nested_beacon_failures_have_an_exhaustive_operation_sensitive_fatal_policy() {
        let cases = [
            (PqBeaconFailure::Connect, false, false, false),
            (PqBeaconFailure::Timeout, false, false, false),
            (PqBeaconFailure::Status(408), false, false, false),
            (PqBeaconFailure::Status(429), false, false, false),
            (PqBeaconFailure::Status(503), false, false, false),
            (PqBeaconFailure::Status(409), true, false, false),
            (PqBeaconFailure::Status(400), true, true, true),
            (PqBeaconFailure::ResponseTooLarge, true, true, true),
            (PqBeaconFailure::FragmentLimit, true, true, true),
            (PqBeaconFailure::Stream, true, true, true),
            (PqBeaconFailure::Resource, true, true, true),
            (PqBeaconFailure::InvalidHeaders, true, true, true),
            (PqBeaconFailure::InvalidJson, true, true, true),
            (PqBeaconFailure::InvalidSsz, true, true, true),
            (PqBeaconFailure::Protocol, true, true, true),
        ];
        for (failure, duty_fatal, production_fatal, publication_fatal) in cases {
            assert_eq!(
                pq_proposer_error_is_fatal(&PqProposerServiceError::DutyRequest(failure)),
                duty_fatal,
                "duty policy for {failure:?}",
            );
            assert_eq!(
                pq_proposer_error_is_fatal(&PqProposerServiceError::BlockProduction(failure)),
                production_fatal,
                "block-production policy for {failure:?}",
            );
            assert_eq!(
                pq_proposer_error_is_fatal(&PqProposerServiceError::Publication(failure)),
                publication_fatal,
                "publication policy for {failure:?}",
            );
        }
        assert!(!pq_proposer_error_is_fatal(
            &PqProposerServiceError::PublicationRejected { status: 409 }
        ));
        for status in [400, 413, 415] {
            assert!(pq_proposer_error_is_fatal(
                &PqProposerServiceError::PublicationRejected { status }
            ));
        }
        assert!(pq_proposer_error_is_fatal(
            &PqProposerServiceError::PublicationProtocol { status: 204 }
        ));
    }
}
