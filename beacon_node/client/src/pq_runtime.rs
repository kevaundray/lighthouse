use crate::Client;
use crate::config::{ClientGenesis, Config as ClientConfig, PqDevnetConfigError};
use beacon_chain::builder::{BeaconChainBuilder, Witness};
use beacon_chain::slot_clock::SystemTimeSlotClock;
use beacon_chain::{BeaconChain, PqStoreStartup, classify_pq_store_startup, migrate_pq_schema};
use consensus_signature::AggregationService;
#[cfg(any(feature = "pq-proposer", feature = "pq-startup-testing"))]
use consensus_signature::PqValidatorRegistryEntry;
use environment::RuntimeContext;
use lighthouse_network::{Context, NetworkGlobals, identity::Keypair, load_private_key};
#[cfg(feature = "pq-proposer")]
use lighthouse_validator_store::{Config as ValidatorStoreConfig, LighthouseValidatorStore};
use network::{
    PqBlockBroadcastSender, PqNetworkService, PqNetworkServiceError, PqNetworkServiceShutdown,
    pq_block_broadcast_channel,
};
#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags};
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::HotColdDB;
use store::database::interface::BeaconNodeBackend;
use types::{
    BeaconState, ChainSpec, Config as Eth2Config, EthSpec, ForkContext, ForkName, Hash256,
    MinimalEthSpec,
};

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
    #[cfg(feature = "pq-proposer")]
    validator_store: Option<Arc<PqValidatorStore>>,
    network_config: Arc<network::NetworkConfig>,
    local_keypair: Keypair,
}

struct PqPreparedDiskRuntime {
    builder: BeaconChainBuilder<PqDiskWitness>,
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
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    bundle_auth_test_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
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
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            bundle_auth_test_barriers: None,
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
            #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
            bundle_auth_test_barriers: self.bundle_auth_test_barriers,
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
    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    bundle_auth_test_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
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
    #[cfg(feature = "pq-proposer")]
    _validator_store: Option<Arc<PqValidatorStore>>,
    network_shutdown: PqNetworkServiceShutdown,
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
                        .custom_spec(Arc::clone(&preparation_spec));
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
                    let chain = builder
                        .pq_aggregation_service(aggregation)
                        .pq_execution_layer(execution)
                        .task_executor(blocking_executor.clone())
                        .build()
                        .map_err(PqRuntimeError::Chain)?;
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
                    std::fs::create_dir_all(&plan.network_dir).map_err(|error| {
                        PqRuntimeError::Directory {
                            path: plan.network_dir.clone(),
                            error,
                        }
                    })?;
                    let network_config = Arc::new(plan.client.network.clone());
                    let local_keypair = load_private_key(&network_config);
                    Ok::<_, PqRuntimeError>(PqBlockingRuntime {
                        chain,
                        #[cfg(feature = "pq-proposer")]
                        validator_store,
                        network_config,
                        local_keypair,
                    })
                },
                "pq-runtime-build-disk-owner",
            )
            .ok_or(PqRuntimeError::TaskUnavailable)?
            .await
            .map_err(|error| PqRuntimeError::TaskJoin(error.to_string()))??;
        let PqBlockingRuntime {
            chain,
            #[cfg(feature = "pq-proposer")]
            validator_store,
            network_config,
            local_keypair,
        } = blocking_runtime;
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
            executor,
            network_context,
            spec.custody_requirement,
            local_keypair,
            Arc::clone(&chain),
            broadcast_receiver,
        )
        .await
        .map_err(PqRuntimeError::Network)?;
        let network_globals = service.network_globals();
        let network_shutdown = service
            .start_with_shutdown_receipt()
            .await
            .map_err(PqRuntimeError::Network)?;
        Ok(Self {
            chain,
            network_globals,
            broadcaster,
            #[cfg(feature = "pq-proposer")]
            _validator_store: validator_store,
            network_shutdown,
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
            chain: _,
            network_globals: _,
            broadcaster,
            #[cfg(feature = "pq-proposer")]
                _validator_store: _,
            network_shutdown,
        } = self;
        drop(broadcaster);
        network_shutdown
            .wait()
            .await
            .map_err(PqRuntimeError::Network)
    }
}

impl Client<PqDiskWitness> {
    pub async fn start_pq_runtime(
        context: RuntimeContext<MinimalEthSpec>,
        config: PqRuntimeConfig,
    ) -> Result<Self, PqRuntimeError> {
        let owner = PqRuntimeOwner::start(context, config).await?;
        Ok(Self {
            beacon_chain: Some(owner.beacon_chain()),
            network_globals: Some(owner.network_globals()),
            http_api_listen_addr: None,
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

    #[cfg(all(feature = "pq-startup-testing", feature = "pq-proposer"))]
    #[doc(hidden)]
    pub fn testing_only_pq_validator_identities(
        &self,
    ) -> Option<Vec<(consensus_signature::ValidatorPublicKeyBytes, u64)>> {
        self.pq_runtime_owner
            .as_ref()?
            ._validator_store
            .as_ref()?
            .pq_validator_identity_snapshot()
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
    Network(PqNetworkServiceError),
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
            Self::Network(error) => error.fmt(formatter),
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
            Self::Network(error) => Some(error),
            #[cfg(feature = "pq-proposer")]
            Self::Slashing(_) => None,
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
