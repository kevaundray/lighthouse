use beacon_chain::graffiti_calculator::GraffitiOrigin;
use beacon_chain::validator_monitor::ValidatorMonitorConfig;
use beacon_processor::BeaconProcessorConfig;
use directory::DEFAULT_ROOT_DIR;
use environment::LoggerConfig;
use kzg::trusted_setup::get_trusted_setup;
use network::NetworkConfig;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
#[cfg(feature = "pq-devnet")]
use types::{ChainSpec, EthSpec};

#[cfg(feature = "pq-devnet")]
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct PqHttpTlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[cfg(feature = "pq-devnet")]
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct PqHttpApiConfig {
    pub enabled: bool,
    pub listen_addr: std::net::IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub tls_config: Option<PqHttpTlsConfig>,
    pub data_dir: PathBuf,
    pub sse_capacity_multiplier: usize,
    pub enable_beacon_processor: bool,
    #[serde(with = "eth2::types::serde_status_code")]
    pub duplicate_block_status_code: hyper::StatusCode,
    pub target_peers: usize,
    pub historical_committee_cache_size: usize,
}

#[cfg(feature = "pq-devnet")]
impl Default for PqHttpApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            listen_port: 5052,
            allow_origin: None,
            tls_config: None,
            data_dir: PathBuf::from(DEFAULT_ROOT_DIR),
            sse_capacity_multiplier: 1,
            enable_beacon_processor: false,
            duplicate_block_status_code: hyper::StatusCode::ACCEPTED,
            target_peers: 100,
            historical_committee_cache_size: 64,
        }
    }
}

#[cfg(feature = "pq-devnet")]
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct PqHttpMetricsConfig {
    pub enabled: bool,
    pub listen_addr: std::net::IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub allocator_metrics_enabled: bool,
}

#[cfg(feature = "pq-devnet")]
impl Default for PqHttpMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            listen_port: 5054,
            allow_origin: None,
            allocator_metrics_enabled: true,
        }
    }
}

/// Default directory name for the freezer database under the top-level data dir.
const DEFAULT_FREEZER_DB_DIR: &str = "freezer_db";
/// Default directory name for the blobs database under the top-level data dir.
const DEFAULT_BLOBS_DB_DIR: &str = "blobs_db";

/// Defines how the client should initialize the `BeaconChain` and other components.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ClientGenesis {
    /// Creates a genesis state as per the 2019 Canada interop specifications.
    Interop {
        validator_count: usize,
        genesis_time: u64,
    },
    // Creates a genesis state similar to the 2019 Canada specs, but starting post-Merge.
    InteropMerge {
        validator_count: usize,
        genesis_time: u64,
    },
    /// Reads the genesis state and other persisted data from the `Store`.
    FromStore,
    /// Connects to an eth1 node and waits until it can create the genesis state from the deposit
    /// contract.
    #[default]
    DepositContract,
    /// Loads the genesis state from the genesis state in the `Eth2NetworkConfig`.
    GenesisState,
    WeakSubjSszBytes {
        anchor_state_bytes: Vec<u8>,
        anchor_block_bytes: Vec<u8>,
        anchor_blobs_bytes: Option<Vec<u8>>,
    },
    CheckpointSyncUrl {
        url: SensitiveUrl,
    },
}

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    data_dir: PathBuf,
    /// Name of the directory inside the data directory where the main "hot" DB is located.
    pub db_name: String,
    /// Path where the freezer database will be located.
    pub freezer_db_path: Option<PathBuf>,
    /// Path where the blobs database will be located if blobs should be in a separate database.
    pub blobs_db_path: Option<PathBuf>,
    pub log_file: PathBuf,
    /// Graffiti to be inserted everytime we create a block if the validator doesn't specify.
    pub beacon_graffiti: GraffitiOrigin,
    pub validator_monitor: ValidatorMonitorConfig,
    #[serde(skip)]
    /// The `genesis` field is not serialized or deserialized by `serde` to ensure it is defined
    /// via the CLI at runtime, instead of from a configuration file saved to disk.
    pub genesis: ClientGenesis,
    pub store: store::StoreConfig,
    pub network: network::NetworkConfig,
    pub chain: beacon_chain::ChainConfig,
    pub execution_layer: Option<execution_layer::Config>,
    pub trusted_setup: Vec<u8>,
    #[cfg(feature = "full-runtime")]
    pub http_api: http_api::Config,
    #[cfg(feature = "pq-devnet")]
    pub http_api: PqHttpApiConfig,
    #[cfg(feature = "full-runtime")]
    pub http_metrics: http_metrics::Config,
    #[cfg(feature = "pq-devnet")]
    pub http_metrics: PqHttpMetricsConfig,
    pub monitoring_api: Option<monitoring_api::Config>,
    #[cfg(feature = "slasher")]
    pub slasher: Option<slasher::Config>,
    pub logger_config: LoggerConfig,
    pub beacon_processor: BeaconProcessorConfig,
    pub genesis_state_url: Option<String>,
    pub genesis_state_url_timeout: Duration,
    pub allow_insecure_genesis_sync: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(DEFAULT_ROOT_DIR),
            db_name: "chain_db".to_string(),
            freezer_db_path: None,
            blobs_db_path: None,
            log_file: PathBuf::from(""),
            genesis: <_>::default(),
            store: <_>::default(),
            network: NetworkConfig::default(),
            chain: <_>::default(),
            execution_layer: None,
            trusted_setup: get_trusted_setup(),
            beacon_graffiti: GraffitiOrigin::default(),
            http_api: <_>::default(),
            http_metrics: <_>::default(),
            monitoring_api: None,
            #[cfg(feature = "slasher")]
            slasher: None,
            validator_monitor: <_>::default(),
            logger_config: LoggerConfig::default(),
            beacon_processor: <_>::default(),
            genesis_state_url: <_>::default(),
            // This default value should always be overwritten by the CLI default value.
            genesis_state_url_timeout: Duration::from_secs(60),
            allow_insecure_genesis_sync: false,
        }
    }
}

impl Config {
    /// Validates the frozen lean PQ devnet V1 startup profile without performing any I/O.
    ///
    /// This is deliberately a programmatic guard rather than a CLI-only check.  Callers must run
    /// it before creating data directories, opening databases, connecting to execution clients or
    /// starting worker threads.
    #[cfg(feature = "pq-devnet")]
    pub fn validate_pq_devnet<E: EthSpec>(
        &self,
        spec: &ChainSpec,
    ) -> Result<(), PqDevnetConfigError> {
        if !matches!(
            self.genesis,
            ClientGenesis::GenesisState | ClientGenesis::FromStore
        ) {
            return Err(PqDevnetConfigError::UnsupportedGenesis);
        }

        #[cfg(feature = "slasher")]
        if self.slasher.is_some() {
            return Err(PqDevnetConfigError::UnsupportedOption("slasher"));
        }

        if self
            .execution_layer
            .as_ref()
            .is_some_and(|config| config.builder_url.is_some())
        {
            return Err(PqDevnetConfigError::UnsupportedOption("builder URL"));
        }
        if self.chain.weak_subjectivity_checkpoint.is_some() {
            return Err(PqDevnetConfigError::UnsupportedOption(
                "weak-subjectivity checkpoint",
            ));
        }
        if self.chain.archive {
            return Err(PqDevnetConfigError::UnsupportedOption("archive mode"));
        }
        if self.chain.genesis_backfill {
            return Err(PqDevnetConfigError::UnsupportedOption("genesis backfill"));
        }
        if self.chain.complete_blob_backfill {
            return Err(PqDevnetConfigError::UnsupportedOption(
                "complete blob backfill",
            ));
        }
        if self.chain.enable_light_client_server || self.network.enable_light_client_server {
            return Err(PqDevnetConfigError::UnsupportedOption(
                "light-client server",
            ));
        }
        if self.chain.optimistic_finalized_sync {
            return Err(PqDevnetConfigError::UnsupportedOption(
                "optimistic finalized sync",
            ));
        }
        if self.validator_monitor.auto_register || !self.validator_monitor.validators.is_empty() {
            return Err(PqDevnetConfigError::UnsupportedOption(
                "validator monitoring",
            ));
        }
        if self.store.hierarchy_config.exponents.as_slice() != [0] {
            return Err(PqDevnetConfigError::InvalidStoreHierarchy);
        }

        let genesis_epoch = E::genesis_epoch();
        let is_frozen_electra = spec.altair_fork_epoch == Some(genesis_epoch)
            && spec.bellatrix_fork_epoch == Some(genesis_epoch)
            && spec.capella_fork_epoch == Some(genesis_epoch)
            && spec.deneb_fork_epoch == Some(genesis_epoch)
            && spec.electra_fork_epoch == Some(genesis_epoch)
            && !spec.is_fulu_scheduled()
            && !spec.is_gloas_scheduled();
        if !is_frozen_electra {
            return Err(PqDevnetConfigError::InvalidForkSchedule);
        }

        Ok(())
    }

    /// Updates the data directory for the Client.
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir.clone_from(&data_dir);
        self.http_api.data_dir = data_dir;
    }

    /// Gets the config's data_dir.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Get the database path without initialising it.
    pub fn get_db_path(&self) -> PathBuf {
        self.get_data_dir().join(&self.db_name)
    }

    /// Get the database path, creating it if necessary.
    pub fn create_db_path(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_db_path())
    }

    /// Fetch default path to use for the freezer database.
    fn default_freezer_db_path(&self) -> PathBuf {
        self.get_data_dir().join(DEFAULT_FREEZER_DB_DIR)
    }

    /// Returns the path to which the client may initialize the on-disk freezer database.
    ///
    /// Will attempt to use the user-supplied path from e.g. the CLI, or will default
    /// to a directory in the data_dir if no path is provided.
    pub fn get_freezer_db_path(&self) -> PathBuf {
        self.freezer_db_path
            .clone()
            .unwrap_or_else(|| self.default_freezer_db_path())
    }

    /// Fetch default path to use for the blobs database.
    fn default_blobs_db_path(&self) -> PathBuf {
        self.get_data_dir().join(DEFAULT_BLOBS_DB_DIR)
    }

    /// Returns the path to which the client may initialize the on-disk blobs database.
    ///
    /// Will attempt to use the user-supplied path from e.g. the CLI, or will default
    /// to None.
    pub fn get_blobs_db_path(&self) -> PathBuf {
        self.blobs_db_path
            .clone()
            .unwrap_or_else(|| self.default_blobs_db_path())
    }

    /// Get the freezer DB path, creating it if necessary.
    pub fn create_freezer_db_path(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_freezer_db_path())
    }

    /// Get the blobs DB path, creating it if necessary.
    pub fn create_blobs_db_path(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_blobs_db_path())
    }

    /// Returns the "modern" path to the data_dir.
    ///
    /// See `Self::get_data_dir` documentation for more info.
    fn get_modern_data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// Returns the "legacy" path to the data_dir.
    ///
    /// See `Self::get_data_dir` documentation for more info.
    pub fn get_existing_legacy_data_dir(&self) -> Option<PathBuf> {
        dirs::home_dir()
            .map(|home_dir| home_dir.join(&self.data_dir))
            // Return `None` if the legacy directory does not exist or if it is identical to the modern.
            .filter(|dir| dir.exists() && *dir != self.get_modern_data_dir())
    }

    /// Returns the core path for the client.
    ///
    /// Will not create any directories.
    ///
    /// ## Legacy Info
    ///
    /// Legacy versions of Lighthouse did not properly handle relative paths for `--datadir`.
    ///
    /// For backwards compatibility, we still compute the legacy path and check if it exists.  If
    /// it does exist, we use that directory rather than the modern path.
    ///
    /// For more information, see:
    ///
    /// https://github.com/sigp/lighthouse/pull/2843
    pub fn get_data_dir(&self) -> PathBuf {
        let existing_legacy_dir = self.get_existing_legacy_data_dir();

        if let Some(legacy_dir) = existing_legacy_dir {
            legacy_dir
        } else {
            self.get_modern_data_dir()
        }
    }

    /// Returns the core path for the client.
    ///
    /// Creates the directory if it does not exist.
    pub fn create_data_dir(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_data_dir())
    }
}

/// A typed, side-effect-free rejection from the frozen lean PQ devnet V1 startup preflight.
#[cfg(feature = "pq-devnet")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqDevnetConfigError {
    UnsupportedGenesis,
    UnsupportedOption(&'static str),
    InvalidForkSchedule,
    InvalidStoreHierarchy,
}

#[cfg(feature = "pq-devnet")]
impl std::fmt::Display for PqDevnetConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedGenesis => formatter
                .write_str("lean PQ devnet V1 supports only GenesisState or FromStore startup"),
            Self::UnsupportedOption(option) => {
                write!(formatter, "lean PQ devnet V1 does not support {option}")
            }
            Self::InvalidForkSchedule => formatter.write_str(
                "lean PQ devnet V1 requires Electra from genesis with Fulu and Gloas unscheduled",
            ),
            Self::InvalidStoreHierarchy => formatter.write_str(
                "lean PQ devnet V1 requires state hierarchy exponents [0] (snapshot every slot)",
            ),
        }
    }
}

#[cfg(feature = "pq-devnet")]
impl std::error::Error for PqDevnetConfigError {}

/// Ensure that the directory at `path` exists, by creating it and all parents if necessary.
fn ensure_dir_exists(path: PathBuf) -> Result<PathBuf, String> {
    fs::create_dir_all(&path).map_err(|e| format!("Unable to create {}: {}", path.display(), e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let config = Config::default();
        let serialized =
            yaml_serde::to_string(&config).expect("should serde encode default config");
        yaml_serde::from_str::<Config>(&serialized).expect("should serde decode default config");
    }

    #[cfg(feature = "pq-devnet")]
    fn valid_pq_config() -> Config {
        let mut config = Config::default();
        config.genesis = ClientGenesis::GenesisState;
        config.store.hierarchy_config.exponents = vec![0];
        config.chain.enable_light_client_server = false;
        config.network.enable_light_client_server = false;
        config.chain.optimistic_finalized_sync = false;
        config
    }

    #[cfg(feature = "pq-devnet")]
    fn pq_spec() -> ChainSpec {
        types::ForkName::Electra.make_genesis_spec(types::MinimalEthSpec::default_spec())
    }

    #[cfg(feature = "pq-devnet")]
    fn assert_pq_rejected(config: Config, expected: PqDevnetConfigError) {
        assert_eq!(
            config.validate_pq_devnet::<types::MinimalEthSpec>(&pq_spec()),
            Err(expected)
        );
    }

    #[cfg(feature = "pq-devnet")]
    #[test]
    fn pq_programmatic_preflight_accepts_only_the_frozen_profile_without_io() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut valid = valid_pq_config();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        let absent_dir = std::env::temp_dir().join(format!(
            "lighthouse-pq-config-preflight-{}-{unique}",
            std::process::id()
        ));
        assert!(!absent_dir.exists());
        valid.set_data_dir(absent_dir.clone());
        assert_eq!(
            valid.validate_pq_devnet::<types::MinimalEthSpec>(&pq_spec()),
            Ok(())
        );
        assert!(
            !absent_dir.exists(),
            "preflight must not create the data dir"
        );

        for genesis in [
            ClientGenesis::DepositContract,
            ClientGenesis::Interop {
                validator_count: 16,
                genesis_time: 0,
            },
            ClientGenesis::InteropMerge {
                validator_count: 16,
                genesis_time: 0,
            },
            ClientGenesis::WeakSubjSszBytes {
                anchor_state_bytes: vec![],
                anchor_block_bytes: vec![],
                anchor_blobs_bytes: None,
            },
            ClientGenesis::CheckpointSyncUrl {
                url: SensitiveUrl::parse("http://localhost:5052").expect("test URL"),
            },
        ] {
            let mut config = valid_pq_config();
            config.genesis = genesis;
            assert_pq_rejected(config, PqDevnetConfigError::UnsupportedGenesis);
        }

        let mut config = valid_pq_config();
        let mut execution_layer = execution_layer::Config::default();
        execution_layer.builder_url =
            Some(SensitiveUrl::parse("http://localhost:18550").expect("test builder URL"));
        config.execution_layer = Some(execution_layer);
        assert_pq_rejected(
            config,
            PqDevnetConfigError::UnsupportedOption("builder URL"),
        );

        let mut config = valid_pq_config();
        config.chain.weak_subjectivity_checkpoint = Some(types::Checkpoint::default());
        assert_pq_rejected(
            config,
            PqDevnetConfigError::UnsupportedOption("weak-subjectivity checkpoint"),
        );

        let rejected_bools: &[(fn(&mut Config), &'static str)] = &[
            (|c| c.chain.archive = true, "archive mode"),
            (|c| c.chain.genesis_backfill = true, "genesis backfill"),
            (
                |c| c.chain.complete_blob_backfill = true,
                "complete blob backfill",
            ),
            (
                |c| c.chain.enable_light_client_server = true,
                "light-client server",
            ),
            (
                |c| c.network.enable_light_client_server = true,
                "light-client server",
            ),
            (
                |c| c.chain.optimistic_finalized_sync = true,
                "optimistic finalized sync",
            ),
            (
                |c| c.validator_monitor.auto_register = true,
                "validator monitoring",
            ),
        ];
        for (mutate, option) in rejected_bools {
            let mut config = valid_pq_config();
            mutate(&mut config);
            assert_pq_rejected(config, PqDevnetConfigError::UnsupportedOption(option));
        }

        let mut config = valid_pq_config();
        config.store.hierarchy_config.exponents = vec![5, 0];
        assert_pq_rejected(config, PqDevnetConfigError::InvalidStoreHierarchy);

        for mutate_spec in [
            (|spec: &mut ChainSpec| spec.electra_fork_epoch = None) as fn(&mut ChainSpec),
            |spec| spec.fulu_fork_epoch = Some(types::Epoch::new(1)),
            |spec| spec.gloas_fork_epoch = Some(types::Epoch::new(1)),
        ] {
            let mut spec = pq_spec();
            mutate_spec(&mut spec);
            assert_eq!(
                valid_pq_config().validate_pq_devnet::<types::MinimalEthSpec>(&spec),
                Err(PqDevnetConfigError::InvalidForkSchedule)
            );
        }
    }
}
