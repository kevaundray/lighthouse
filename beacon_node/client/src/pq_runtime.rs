use crate::Client;
use crate::config::{ClientGenesis, Config as ClientConfig, PqDevnetConfigError};
use beacon_chain::builder::{BeaconChainBuilder, Witness};
use beacon_chain::slot_clock::SystemTimeSlotClock;
use beacon_chain::{BeaconChain, PqStoreStartup, classify_pq_store_startup, migrate_pq_schema};
use consensus_signature::AggregationService;
use environment::RuntimeContext;
use lighthouse_network::{Context, NetworkGlobals, identity::Keypair, load_private_key};
use network::{
    PqBlockBroadcastSender, PqNetworkService, PqNetworkServiceError, PqNetworkServiceShutdown,
    pq_block_broadcast_channel,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::HotColdDB;
use store::database::interface::BeaconNodeBackend;
use types::{BeaconState, ChainSpec, ForkContext, MinimalEthSpec};

type PqDiskWitness =
    Witness<SystemTimeSlotClock, MinimalEthSpec, BeaconNodeBackend, BeaconNodeBackend>;
type PqDiskChain = BeaconChain<PqDiskWitness>;

pub type PqClient = Client<PqDiskWitness>;

struct PqBlockingRuntime {
    chain: Arc<PqDiskChain>,
    network_config: Arc<network::NetworkConfig>,
    local_keypair: Keypair,
}

/// Unvalidated inputs for the isolated minimal PQ runtime.
#[derive(Clone)]
pub struct PqRuntimeConfig {
    client: ClientConfig,
    testnet_dir: PathBuf,
    proposer: Option<PqProposerRuntimePaths>,
    #[cfg(feature = "pq-startup-testing")]
    blocking_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(feature = "pq-startup-testing")]
    genesis_read_test_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for PqRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PqRuntimeConfig")
            .field("client", &self.client)
            .field("testnet_dir", &self.testnet_dir)
            .field("proposer", &self.proposer)
            .finish_non_exhaustive()
    }
}

impl PqRuntimeConfig {
    pub fn new(client: ClientConfig, testnet_dir: PathBuf) -> Self {
        Self {
            client,
            testnet_dir,
            proposer: None,
            #[cfg(feature = "pq-startup-testing")]
            blocking_test_hook: None,
            #[cfg(feature = "pq-startup-testing")]
            genesis_read_test_hook: None,
        }
    }

    pub fn with_proposer(mut self, proposer: PqProposerRuntimePaths) -> Self {
        self.proposer = Some(proposer);
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
        if self.proposer.is_some() && !self.client.http_api.enabled {
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
        Ok(PqRuntimePlan {
            client: self.client,
            genesis_state_path: self.testnet_dir.join("genesis.ssz"),
            proposer: self.proposer,
            hot_db_path,
            cold_db_path,
            blobs_db_path,
            network_dir,
            jwt_secret_path,
            #[cfg(feature = "pq-startup-testing")]
            blocking_test_hook: self.blocking_test_hook,
            #[cfg(feature = "pq-startup-testing")]
            genesis_read_test_hook: self.genesis_read_test_hook,
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
}

/// Paths retained for the later proposer assembly slice. E4c never opens them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqProposerRuntimePaths {
    bundle_dir: PathBuf,
    slashing_db: PathBuf,
}

impl PqProposerRuntimePaths {
    pub fn new(bundle_dir: PathBuf, slashing_db: PathBuf) -> Self {
        Self {
            bundle_dir,
            slashing_db,
        }
    }

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
            | Self::UnsupportedOption(_)
            | Self::InvalidStoreConfiguration => None,
        }
    }
}

pub(crate) struct PqRuntimeOwner {
    chain: Arc<PqDiskChain>,
    network_globals: Arc<NetworkGlobals<MinimalEthSpec>>,
    broadcaster: PqBlockBroadcastSender<MinimalEthSpec>,
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
        let blocking_runtime = context
            .executor
            .spawn_blocking_handle(
                move || {
                    execution_layer::validate_jwt_secret_file(&plan.jwt_secret_path)
                        .map_err(PqRuntimeError::JwtInvalid)?;
                    let has_existing_store_path =
                        [&plan.hot_db_path, &plan.cold_db_path, &plan.blobs_db_path]
                            .into_iter()
                            .any(|path| path.exists());
                    let genesis_state_configured = match &plan.client.genesis {
                        ClientGenesis::GenesisState => true,
                        ClientGenesis::FromStore => false,
                        _ => return Err(PqRuntimeError::UnsupportedGenesis),
                    };
                    let read_genesis_state = || {
                        #[cfg(feature = "pq-startup-testing")]
                        if let Some(hook) = plan.genesis_read_test_hook.as_ref() {
                            hook();
                        }
                        std::fs::read(&plan.genesis_state_path)
                            .map_err(|error| PqRuntimeError::GenesisRead(error.to_string()))
                            .and_then(|genesis_bytes| {
                                BeaconState::<MinimalEthSpec>::from_ssz_bytes(
                                    &genesis_bytes,
                                    &blocking_spec,
                                )
                                .map_err(|error| {
                                    PqRuntimeError::GenesisDecode(format!("{error:?}"))
                                })
                            })
                            .and_then(|state| {
                                state_processing::validate_lean_pq_devnet_v1(
                                    &state,
                                    &blocking_spec,
                                    state.slot(),
                                )
                                .map_err(PqRuntimeError::GenesisProfile)?;
                                Ok(state)
                            })
                    };
                    let prevalidated_genesis =
                        if genesis_state_configured && !has_existing_store_path {
                            Some(read_genesis_state()?)
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
                        Arc::clone(&blocking_spec),
                    )
                    .map_err(PqRuntimeError::Store)?;
                    let startup =
                        classify_pq_store_startup(&store).map_err(PqRuntimeError::StoreStartup)?;
                    let builder = BeaconChainBuilder::<PqDiskWitness>::pq_new(MinimalEthSpec)
                        .store(store)
                        .custom_spec(Arc::clone(&blocking_spec));
                    let builder = match startup {
                        PqStoreStartup::Empty if genesis_state_configured => {
                            let state = match prevalidated_genesis {
                                Some(state) => state,
                                None => read_genesis_state()?,
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
                        .task_executor(blocking_executor)
                        .build()
                        .map_err(PqRuntimeError::Chain)?;
                    let chain = Arc::new(chain);
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
            Self::Directory { error, .. } => Some(error),
            Self::StoreStartup(error) => Some(error),
            Self::Aggregation(error) => Some(error),
            Self::Chain(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::JwtInvalid(_)
            | Self::GenesisRead(_)
            | Self::GenesisDecode(_)
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
