mod cli;
mod config;

#[cfg(not(any(feature = "full-runtime", feature = "pq-devnet")))]
compile_error!(
    "beacon_node requires exactly one runtime profile: enable full-runtime or pq-devnet"
);
#[cfg(all(feature = "full-runtime", feature = "pq-devnet"))]
compile_error!("beacon_node runtime profiles full-runtime and pq-devnet are mutually exclusive");

pub use beacon_chain;
#[cfg(not(feature = "pq-devnet"))]
use beacon_chain::{builder::Witness, slot_clock::SystemTimeSlotClock};
use clap::ArgMatches;
pub use cli::cli_app;
#[cfg(not(feature = "pq-devnet"))]
pub use client::ClientBuilder;
#[cfg(feature = "pq-devnet")]
pub use client::PqRuntimeConfig;
#[cfg(feature = "pq-devnet")]
pub use client::config::PqDevnetConfigError as PqClientConfigError;
pub use client::{Client, ClientConfig, ClientGenesis};
#[cfg(feature = "pq-devnet")]
pub use config::PqDevnetConfigError as PqCliConfigError;
#[cfg(feature = "pq-devnet")]
pub use config::PqDevnetConfigError as PqLaunchCliError;
pub use config::{get_config, get_data_dir, set_network_config};
use environment::RuntimeContext;
pub use eth2_config::Eth2Config;
#[cfg(not(feature = "pq-devnet"))]
use lighthouse_network::load_private_key;
#[cfg(not(feature = "pq-devnet"))]
use network_utils::enr_ext::peer_id_to_node_id;
#[cfg(feature = "pq-devnet")]
use sensitive_url::SensitiveUrl;
#[cfg(feature = "slasher")]
use slasher::{DatabaseBackendOverride, Slasher};
#[cfg(not(feature = "pq-devnet"))]
use std::ops::{Deref, DerefMut};
#[cfg(feature = "pq-devnet")]
use std::path::PathBuf;
#[cfg(not(feature = "pq-devnet"))]
use std::sync::Arc;
#[cfg(not(feature = "pq-devnet"))]
use store::database::interface::BeaconNodeBackend;
#[cfg(not(feature = "pq-devnet"))]
use tracing::{info, warn};
#[cfg(not(feature = "pq-devnet"))]
use types::EthSpec;
#[cfg(not(feature = "pq-devnet"))]
use types::{ChainSpec, Epoch, ForkName};

/// A type-alias to the tighten the definition of a production-intended `Client`.
#[cfg(not(feature = "pq-devnet"))]
pub type ProductionClient<E> =
    Client<Witness<SystemTimeSlotClock, E, BeaconNodeBackend, BeaconNodeBackend>>;

/// Side-effect-free launch paths selected by the narrow PQ CLI.
#[cfg(feature = "pq-devnet")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqLaunchCliPlan {
    testnet_dir: PathBuf,
    validator_bundle: Option<PathBuf>,
}

#[cfg(feature = "pq-devnet")]
impl PqLaunchCliPlan {
    pub fn testnet_dir(&self) -> &std::path::Path {
        &self.testnet_dir
    }

    pub fn validator_bundle(&self) -> Option<&std::path::Path> {
        self.validator_bundle.as_deref()
    }
}

/// Parses only path values. It never resolves, probes, creates, or removes them.
#[cfg(feature = "pq-devnet")]
pub fn parse_pq_launch_cli(matches: &ArgMatches) -> Result<PqLaunchCliPlan, PqLaunchCliError> {
    config::validate_pq_devnet_cli_profile(matches)?;
    let testnet_dir = matches
        .try_get_raw("testnet-dir")
        .ok()
        .flatten()
        .and_then(|mut values| values.next_back())
        .map(PathBuf::from)
        .ok_or(PqLaunchCliError::MissingTestnetDir)?;
    let validator_bundle = matches
        .try_get_raw("pq-validator-bundle")
        .ok()
        .flatten()
        .and_then(|mut values| values.next_back())
        .map(PathBuf::from);
    #[cfg(not(feature = "pq-proposer"))]
    if validator_bundle.is_some() {
        return Err(PqLaunchCliError::ProposerFeatureDisabled);
    }
    if validator_bundle.is_some() && !matches.get_flag("http") {
        return Err(PqLaunchCliError::ProposerRequiresHttp);
    }
    Ok(PqLaunchCliPlan {
        testnet_dir,
        validator_bundle,
    })
}

/// Builds the opaque PQ runtime configuration from the positive CLI profile without filesystem,
/// DNS, socket, or worker side effects.
#[cfg(feature = "pq-devnet")]
pub fn build_pq_runtime_config(
    matches: &ArgMatches,
) -> Result<client::PqRuntimeConfig, PqLaunchConfigError> {
    let launch = parse_pq_launch_cli(matches).map_err(PqLaunchConfigError::Cli)?;
    let mut client_config = ClientConfig::default();
    client_config.set_data_dir(get_data_dir(matches));
    client_config.genesis = ClientGenesis::GenesisState;
    client_config.store.hierarchy_config.exponents = vec![0];
    client_config.chain.enable_light_client_server = false;
    client_config.network.enable_light_client_server = false;
    client_config.chain.optimistic_finalized_sync = false;

    let data_dir = client_config.data_dir().clone();
    set_network_config(&mut client_config.network, matches, &data_dir)
        .map_err(PqLaunchConfigError::Network)?;
    client_config.network.enable_light_client_server = false;

    client_config.http_api.enabled = matches.get_flag("http");
    if let Some(address) = matches.get_one::<String>("http-address") {
        client_config.http_api.listen_addr = address
            .parse()
            .map_err(|_| PqLaunchConfigError::InvalidHttpAddress)?;
    }
    if let Some(port) = matches.get_one::<String>("http-port") {
        client_config.http_api.listen_port = port
            .parse()
            .map_err(|_| PqLaunchConfigError::InvalidHttpPort)?;
    }
    if matches.get_flag("zero-ports") {
        client_config.http_api.listen_port = 0;
    }

    let endpoint = matches
        .get_one::<String>("execution-endpoint")
        .ok_or(PqLaunchConfigError::MissingExecutionEndpoint)?;
    let jwt = matches
        .get_one::<String>("execution-jwt")
        .ok_or(PqLaunchConfigError::MissingJwt)?;
    let mut execution = execution_layer::Config::default();
    execution.execution_endpoint = Some(
        SensitiveUrl::parse(endpoint).map_err(|_| PqLaunchConfigError::InvalidExecutionEndpoint)?,
    );
    execution.secret_file = Some(PathBuf::from(jwt));
    execution.jwt_id = matches.get_one::<String>("execution-jwt-id").cloned();
    execution.jwt_version = matches.get_one::<String>("execution-jwt-version").cloned();
    execution.default_datadir = client_config.data_dir().clone();
    client_config.execution_layer = Some(execution);

    let mut runtime = client::PqRuntimeConfig::new(client_config, launch.testnet_dir);
    if let Some(bundle) = launch.validator_bundle {
        runtime = runtime.with_validator_bundle(bundle);
    }
    Ok(runtime)
}

#[cfg(feature = "pq-devnet")]
#[derive(Debug)]
pub enum PqLaunchConfigError {
    Cli(PqLaunchCliError),
    MissingExecutionEndpoint,
    MissingJwt,
    InvalidExecutionEndpoint,
    InvalidHttpAddress,
    InvalidHttpPort,
    Network(String),
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqLaunchConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli(error) => error.fmt(formatter),
            Self::MissingExecutionEndpoint => {
                formatter.write_str("lean PQ runtime requires --execution-endpoint")
            }
            Self::MissingJwt => formatter.write_str("lean PQ runtime requires --execution-jwt"),
            Self::InvalidExecutionEndpoint => {
                formatter.write_str("--execution-endpoint is not a valid URL")
            }
            Self::InvalidHttpAddress => formatter.write_str("--http-address is not a valid IP"),
            Self::InvalidHttpPort => formatter.write_str("--http-port is not a valid u16"),
            Self::Network(error) => write!(formatter, "invalid PQ network configuration: {error}"),
        }
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqLaunchConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cli(error) => Some(error),
            Self::MissingExecutionEndpoint
            | Self::MissingJwt
            | Self::InvalidExecutionEndpoint
            | Self::InvalidHttpAddress
            | Self::InvalidHttpPort
            | Self::Network(_) => None,
        }
    }
}

/// A typed, side-effect-free rejection from the frozen PQ production boundary.
#[cfg(feature = "pq-devnet")]
#[derive(Debug)]
pub enum PqStartupError {
    CliConfig(PqCliConfigError),
    LaunchConfig(PqLaunchConfigError),
    ClientConfig(PqClientConfigError),
    Runtime(client::PqRuntimeError),
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CliConfig(error) => error.fmt(formatter),
            Self::LaunchConfig(error) => error.fmt(formatter),
            Self::ClientConfig(error) => error.fmt(formatter),
            Self::Runtime(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqStartupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CliConfig(error) => Some(error),
            Self::LaunchConfig(error) => Some(error),
            Self::ClientConfig(error) => Some(error),
            Self::Runtime(error) => Some(error),
        }
    }
}

#[cfg(feature = "pq-devnet")]
impl From<PqCliConfigError> for PqStartupError {
    fn from(error: PqCliConfigError) -> Self {
        Self::CliConfig(error)
    }
}

#[cfg(feature = "pq-devnet")]
impl From<PqClientConfigError> for PqStartupError {
    fn from(error: PqClientConfigError) -> Self {
        Self::ClientConfig(error)
    }
}

#[cfg(feature = "pq-devnet")]
impl From<PqLaunchConfigError> for PqStartupError {
    fn from(error: PqLaunchConfigError) -> Self {
        Self::LaunchConfig(error)
    }
}

#[cfg(feature = "pq-devnet")]
impl From<client::PqRuntimeError> for PqStartupError {
    fn from(error: client::PqRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

/// The beacon node `Client` that is used in production.
///
/// Generic over some `EthSpec`.
#[cfg(not(feature = "pq-devnet"))]
pub struct ProductionBeaconNode<E: EthSpec>(ProductionClient<E>);

#[cfg(feature = "pq-devnet")]
pub struct ProductionBeaconNode(client::PqClient);

#[cfg(not(feature = "pq-devnet"))]
impl<E: EthSpec> ProductionBeaconNode<E> {
    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Identical to `start_from_client_config`, however the `client_config` is generated from the
    /// given `matches` and potentially configuration files on the local filesystem or other
    /// configurations hosted remotely.
    pub async fn new_from_cli(
        context: RuntimeContext<E>,
        matches: ArgMatches,
    ) -> Result<Self, String> {
        let client_config = get_config::<E>(&matches, &context)?;
        Self::new(context, client_config).await
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub async fn new(
        context: RuntimeContext<E>,
        mut client_config: ClientConfig,
    ) -> Result<Self, String> {
        let spec = context.eth2_config().spec.clone();
        let client_genesis = client_config.genesis.clone();
        let store_config = client_config.store.clone();
        let _datadir = client_config.create_data_dir()?;
        let db_path = client_config.create_db_path()?;
        let freezer_db_path = client_config.create_freezer_db_path()?;
        let blobs_db_path = client_config.create_blobs_db_path()?;
        let executor = context.executor.clone();

        if let Some(legacy_dir) = client_config.get_existing_legacy_data_dir() {
            warn!(
                msg = "this occurs when using relative paths for a datadir location",
                location = ?legacy_dir,
                "Legacy datadir location"
            )
        }

        if let Err(misaligned_forks) = validator_fork_epochs(&spec) {
            warn!(
                info = "This may cause issues as fork boundaries do not align with the \
                start of sync committee period.",
                ?misaligned_forks,
                "Fork boundaries are not well aligned / multiples of 256"
            );
        }

        let builder = ClientBuilder::new(context.eth_spec_instance.clone())
            .runtime_context(context)
            .chain_spec(spec.clone())
            .beacon_processor(client_config.beacon_processor.clone())
            .http_api_config(client_config.http_api.clone())
            .disk_store(&db_path, &freezer_db_path, &blobs_db_path, store_config)?;

        #[cfg(feature = "slasher")]
        let builder = if let Some(mut slasher_config) = client_config.slasher.clone() {
            match slasher_config.override_backend() {
                DatabaseBackendOverride::Success(old_backend) => {
                    info!(
                        reason = "database exists",
                        configured_backend = %old_backend,
                        override_backend = %slasher_config.backend,
                        "Slasher backend overridden"
                    );
                }
                DatabaseBackendOverride::Failure(path) => {
                    warn!(
                        advice = "delete old MDBX database or enable MDBX backend",
                        path = %path.display(),
                        "Slasher backend override failed"
                    );
                }
                _ => {}
            }
            let slasher = Arc::new(
                Slasher::open(slasher_config, spec)
                    .map_err(|e| format!("Slasher open error: {:?}", e))?,
            );
            builder.slasher(slasher)
        } else {
            builder
        };

        let builder = if let Some(monitoring_config) = &mut client_config.monitoring_api {
            monitoring_config.db_path = Some(db_path);
            monitoring_config.freezer_db_path = Some(freezer_db_path);
            builder.monitoring_client(monitoring_config)?
        } else {
            builder
        };

        // Generate or load the node id.
        let local_keypair = load_private_key(&client_config.network);
        let node_id = peer_id_to_node_id(&local_keypair.public().to_peer_id())?.raw();

        let builder = builder
            .beacon_chain_builder(client_genesis, client_config.clone(), node_id)
            .await?;
        info!("Block production enabled");

        let builder = builder.system_time_slot_clock()?;

        #[cfg(feature = "pq-devnet")]
        let builder = builder.prepare_pq_runtime().await?;

        // Inject the executor into the discv5 network config.
        let discv5_executor = Discv5Executor(executor);
        client_config.network.discv5_config.executor = Some(Box::new(discv5_executor));

        builder
            .build_beacon_chain()?
            .network(Arc::new(client_config.network), local_keypair)
            .await?
            .notifier()?
            .http_metrics_config(client_config.http_metrics.clone())
            .build()
            .map(Self)
    }

    pub fn into_inner(self) -> ProductionClient<E> {
        self.0
    }
}

#[cfg(feature = "pq-devnet")]
impl ProductionBeaconNode {
    pub async fn new_from_cli(
        context: RuntimeContext<types::MinimalEthSpec>,
        matches: ArgMatches,
    ) -> Result<Self, PqStartupError> {
        let config = build_pq_runtime_config(&matches)?;
        Self::new(context, config).await
    }

    pub async fn new(
        context: RuntimeContext<types::MinimalEthSpec>,
        config: client::PqRuntimeConfig,
    ) -> Result<Self, PqStartupError> {
        client::PqClient::start_pq_runtime(context, config)
            .await
            .map(Self)
            .map_err(Into::into)
    }

    pub async fn shutdown(self) -> Result<(), PqStartupError> {
        self.0.shutdown().await.map_err(Into::into)
    }

    pub fn into_inner(self) -> client::PqClient {
        self.0
    }
}

#[cfg(not(feature = "pq-devnet"))]
fn validator_fork_epochs(spec: &ChainSpec) -> Result<(), Vec<(ForkName, Epoch)>> {
    // @dapplion: "We try to schedule forks such that the fork epoch is a multiple of 256, to keep
    // historical vectors in the same fork. Indirectly that makes light client periods align with
    // fork boundaries."
    let sync_committee_period = spec.epochs_per_sync_committee_period; // 256
    let is_fork_boundary_misaligned = |epoch: Epoch| epoch % sync_committee_period != 0;

    let forks_with_misaligned_epochs = ForkName::list_all_fork_epochs(spec)
        .iter()
        .filter_map(|(fork, fork_epoch_opt)| {
            fork_epoch_opt
                .and_then(|epoch| is_fork_boundary_misaligned(epoch).then_some((*fork, epoch)))
        })
        .collect::<Vec<_>>();

    if forks_with_misaligned_epochs.is_empty() {
        Ok(())
    } else {
        Err(forks_with_misaligned_epochs)
    }
}

#[cfg(not(feature = "pq-devnet"))]
impl<E: EthSpec> Deref for ProductionBeaconNode<E> {
    type Target = ProductionClient<E>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "pq-devnet"))]
impl<E: EthSpec> DerefMut for ProductionBeaconNode<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Implements the Discv5 Executor trait over our global executor
#[derive(Clone)]
#[cfg(not(feature = "pq-devnet"))]
struct Discv5Executor(task_executor::TaskExecutor);

#[cfg(not(feature = "pq-devnet"))]
impl lighthouse_network::discv5::Executor for Discv5Executor {
    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        self.0.spawn(future, "discv5")
    }
}

#[cfg(all(test, not(feature = "pq-devnet")))]
mod test {
    use super::*;
    use types::MainnetEthSpec;

    #[test]
    fn test_validator_fork_epoch_alignments() {
        let mut spec = MainnetEthSpec::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(256));
        spec.deneb_fork_epoch = Some(Epoch::new(257));
        spec.electra_fork_epoch = None;
        spec.fulu_fork_epoch = None;
        spec.gloas_fork_epoch = None;
        let result = validator_fork_epochs(&spec);
        assert_eq!(
            result,
            Err(vec![(ForkName::Deneb, spec.deneb_fork_epoch.unwrap())])
        );
    }
}

#[cfg(all(test, feature = "pq-devnet"))]
mod pq_test {
    use super::*;

    #[test]
    fn cli_stops_at_the_deferred_boundary_before_config_io() {
        let matches = cli_app()
            .try_get_matches_from([
                "beacon_node",
                "--execution-endpoint",
                "http://127.0.0.1:8551",
            ])
            .expect("plain beacon-node arguments");
        assert_eq!(
            parse_pq_launch_cli(&matches).map(|_| ()),
            Err(PqCliConfigError::MissingTestnetDir),
        );
    }
}
