#![cfg(all(feature = "pq-devnet", feature = "pq-startup-testing"))]

use beacon_chain::{PqStoreStartup, PqStoreStartupError, classify_pq_store_startup};
use client::config::{ClientGenesis, Config as ClientConfig, PqHttpTlsConfig};
use client::{
    PqClient, PqPublicTestnetError, PqRuntimeConfig, PqRuntimeConfigError, PqRuntimeError,
};
use consensus_signature::PqPublicKey;
#[cfg(feature = "pq-proposer")]
#[cfg(target_feature = "avx2")]
use consensus_signature::PqValidatorRegistryEntry;
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use std::sync::Arc;
#[cfg(target_feature = "avx2")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{DBColumn, KeyValueStore};
use types::{EthSpec, ForkName, MinimalEthSpec};

struct AlwaysValidStartupExecution;

impl beacon_chain::PqNewPayloadTransport<MinimalEthSpec> for AlwaysValidStartupExecution {
    fn notify_new_payload<'a>(
        &'a self,
        _request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
    }

    fn notify_forkchoice_updated<'a>(
        &'a self,
        _head_block_hash: types::ExecutionBlockHash,
        _current_slot: types::Slot,
        _head_block_root: types::Hash256,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
    }
}

fn testing_runtime_config(client: ClientConfig, testnet: std::path::PathBuf) -> PqRuntimeConfig {
    PqRuntimeConfig::new(client, testnet)
        .testing_only_execution_notifier(Arc::new(AlwaysValidStartupExecution))
}

fn valid_client_config(absent_data_dir: std::path::PathBuf) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.set_data_dir(absent_data_dir);
    config.genesis = ClientGenesis::GenesisState;
    config.store.hierarchy_config.exponents = vec![0];
    config.chain.enable_light_client_server = false;
    config.network.enable_light_client_server = false;
    config
        .network
        .set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    config.network.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    config.network.disable_discovery = true;
    config.chain.optimistic_finalized_sync = false;
    let mut execution = execution_layer::Config::default();
    execution.execution_endpoint =
        Some(SensitiveUrl::parse("http://127.0.0.1:8551").expect("valid execution endpoint"));
    execution.secret_file = Some(std::path::PathBuf::from("jwt.hex"));
    config.execution_layer = Some(execution);
    config
}

#[test]
fn pure_plan_rejects_non_300_second_profile_before_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let absent_data_dir = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-preflight-{}-{unique}",
        std::process::id()
    ));
    assert!(!absent_data_dir.exists());
    let config = testing_runtime_config(
        valid_client_config(absent_data_dir.clone()),
        std::path::PathBuf::from("testnet"),
    );
    let invalid_spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());

    assert_eq!(
        config
            .testing_only_validate(&invalid_spec)
            .expect_err("non-300-second profile must fail"),
        PqRuntimeConfigError::InvalidSlotDuration,
    );
    assert!(
        !absent_data_dir.exists(),
        "pure validation must not create or inspect the data directory",
    );
}

#[test]
fn pure_plan_requires_a_real_execution_endpoint_and_explicit_jwt() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-no-io-el-matrix-{}-{unique}",
        std::process::id()
    ));
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let mut missing_layer = valid_client_config(data_dir.clone());
    missing_layer.execution_layer = None;
    assert_eq!(
        testing_runtime_config(missing_layer, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("execution layer is mandatory"),
        PqRuntimeConfigError::MissingExecutionLayer,
    );

    let mut missing_endpoint = valid_client_config(data_dir.clone());
    missing_endpoint
        .execution_layer
        .as_mut()
        .expect("execution config")
        .execution_endpoint = None;
    assert_eq!(
        testing_runtime_config(missing_endpoint, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("execution endpoint is mandatory"),
        PqRuntimeConfigError::MissingExecutionEndpoint,
    );

    let mut missing_jwt = valid_client_config(data_dir.clone());
    missing_jwt
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = None;
    assert_eq!(
        testing_runtime_config(missing_jwt, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("explicit JWT path is mandatory"),
        PqRuntimeConfigError::MissingJwtSecret,
    );
    assert!(!data_dir.exists());
}

#[cfg(not(feature = "pq-proposer"))]
#[test]
fn pure_plan_rejects_validator_bundle_without_proposer_feature() {
    let data_dir = std::path::PathBuf::from("absent-node");
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    assert_eq!(
        testing_runtime_config(valid_client_config(data_dir), "testnet".into())
            .with_validator_bundle("bundle".into())
            .testing_only_validate(&spec)
            .expect_err("validator bundle requires the additive feature"),
        PqRuntimeConfigError::ProposerFeatureDisabled,
    );
}

#[cfg(feature = "pq-proposer")]
#[test]
fn pure_plan_seals_optional_proposer_paths_without_opening_them() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-proposer-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let bundle_dir = root.join("bundle");
    let slashing_db = data_dir
        .join("pq-proposer")
        .join(slashing_protection::SLASHING_PROTECTION_FILENAME);
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let disabled_http = valid_client_config(data_dir.clone());
    assert_eq!(
        testing_runtime_config(disabled_http, root.join("testnet"))
            .with_validator_bundle(bundle_dir.clone())
            .testing_only_validate(&spec)
            .expect_err("proposer requires the narrow HTTP surface"),
        PqRuntimeConfigError::ProposerRequiresHttp,
    );

    let mut enabled_http = valid_client_config(data_dir);
    enabled_http.http_api.enabled = true;
    let plan = testing_runtime_config(enabled_http, root.join("testnet"))
        .with_validator_bundle(bundle_dir.clone())
        .testing_only_validate(&spec)
        .expect("sealed proposer plan");
    let proposer = plan.proposer().expect("proposer paths retained");
    assert_eq!(proposer.bundle_dir(), bundle_dir);
    assert_eq!(proposer.slashing_db(), slashing_db);
    assert!(!root.exists(), "pure planning must not open proposer paths");
}

#[test]
fn pure_plan_rejects_unsupported_http_metrics_and_monitoring() {
    let root = std::env::temp_dir().join("lighthouse-pq-runtime-unsupported-services");
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let mut tls = valid_client_config(root.join("tls"));
    tls.http_api.tls_config = Some(PqHttpTlsConfig {
        cert: "cert.pem".into(),
        key: "key.pem".into(),
    });
    assert_eq!(
        testing_runtime_config(tls, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("HTTP TLS is outside the PQ facade"),
        PqRuntimeConfigError::UnsupportedOption("HTTP TLS"),
    );

    let mut cors = valid_client_config(root.join("cors"));
    cors.http_api.allow_origin = Some("*".into());
    assert_eq!(
        testing_runtime_config(cors, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("CORS is outside the PQ facade"),
        PqRuntimeConfigError::UnsupportedOption("HTTP CORS"),
    );

    let mut metrics = valid_client_config(root.join("metrics"));
    metrics.http_metrics.enabled = true;
    assert_eq!(
        testing_runtime_config(metrics, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("metrics are outside the PQ runtime"),
        PqRuntimeConfigError::UnsupportedOption("metrics"),
    );

    let mut monitoring = valid_client_config(root.join("monitoring"));
    monitoring.monitoring_api = Some(monitoring_api::Config::default());
    assert_eq!(
        testing_runtime_config(monitoring, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("monitoring is outside the PQ runtime"),
        PqRuntimeConfigError::UnsupportedOption("monitoring"),
    );
    assert!(!root.exists());
}

#[test]
fn pure_plan_seals_exact_disk_network_genesis_and_jwt_paths_without_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-paths-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet_dir = root.join("testnet");
    let jwt = root.join("engine.jwt");
    let network = root.join("network");
    let mut config = valid_client_config(data_dir.clone());
    config.network.network_dir.clone_from(&network);
    config
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt.clone());
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let plan = testing_runtime_config(config, testnet_dir.clone())
        .testing_only_validate(&spec)
        .expect("valid pure plan");
    assert_eq!(plan.hot_db_path(), data_dir.join("chain_db"));
    assert_eq!(plan.cold_db_path(), data_dir.join("freezer_db"));
    assert_eq!(plan.blobs_db_path(), data_dir.join("blobs_db"));
    assert_eq!(plan.network_dir(), network);
    assert_eq!(plan.genesis_state_path(), testnet_dir.join("genesis.ssz"));
    assert_eq!(plan.jwt_secret_path(), jwt);
    assert!(!root.exists());
}

#[test]
fn pure_plan_uses_configured_data_dir_lexically_even_if_a_legacy_directory_exists() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let relative_data_dir = std::path::PathBuf::from(format!(
        ".lighthouse-pq-runtime-legacy-{}-{unique}",
        std::process::id()
    ));
    let legacy_data_dir = dirs::home_dir()
        .expect("home directory")
        .join(&relative_data_dir);
    std::fs::create_dir_all(&legacy_data_dir).expect("legacy fixture");
    let mut client = valid_client_config(relative_data_dir.clone());
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(relative_data_dir.join("jwt.hex"));
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let plan = testing_runtime_config(client, relative_data_dir.join("testnet"))
        .testing_only_validate(&spec)
        .expect("pure lexical plan");
    assert_eq!(plan.hot_db_path(), relative_data_dir.join("chain_db"),);
    assert_ne!(plan.hot_db_path(), legacy_data_dir.join("chain_db"));
    std::fs::remove_dir_all(legacy_data_dir).expect("remove legacy fixture");
}

#[test]
fn pure_plan_rejects_invalid_store_compression_and_pruning_before_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-invalid-store-{}-{unique}",
        std::process::id()
    ));
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let mut invalid_compression = valid_client_config(root.join("compression"));
    invalid_compression.store.compression_level = i32::MAX;
    assert_eq!(
        testing_runtime_config(invalid_compression, root.join("testnet"))
            .testing_only_validate(&spec)
            .expect_err("invalid store compression"),
        PqRuntimeConfigError::InvalidStoreConfiguration,
    );
    assert!(!root.exists());

    let mut invalid_pruning = valid_client_config(root.join("pruning"));
    invalid_pruning.store.epochs_per_blob_prune = 0;
    assert_eq!(
        testing_runtime_config(invalid_pruning, root.join("testnet"))
            .testing_only_validate(&spec)
            .expect_err("invalid blob prune period"),
        PqRuntimeConfigError::InvalidStoreConfiguration,
    );
    assert!(!root.exists());
}

#[test]
fn pq_store_classifier_accepts_only_missing_head_plus_uninitialized_anchor_as_empty() {
    let mut store_config = store::StoreConfig::default();
    store_config.hierarchy_config.exponents = vec![0];
    let store = Arc::new(
        store::HotColdDB::<MinimalEthSpec, store::MemoryStore, store::MemoryStore>::open_ephemeral(
            store_config,
            Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())),
        )
        .expect("memory store"),
    );
    assert!(matches!(
        classify_pq_store_startup(&store),
        Ok(PqStoreStartup::Empty),
    ));
}

fn pq_memory_store() -> Arc<store::HotColdDB<MinimalEthSpec, store::MemoryStore, store::MemoryStore>>
{
    let mut store_config = store::StoreConfig::default();
    store_config.hierarchy_config.exponents = vec![0];
    Arc::new(
        store::HotColdDB::open_ephemeral(
            store_config,
            Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())),
        )
        .expect("memory store"),
    )
}

fn pq_ready_store() -> Arc<store::HotColdDB<MinimalEthSpec, store::MemoryStore, store::MemoryStore>>
{
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let state = pq_genesis_state(&spec);
    let database = pq_memory_store();
    beacon_chain::builder::BeaconChainBuilder::<
        beacon_chain::builder::Witness<
            beacon_chain::slot_clock::SystemTimeSlotClock,
            MinimalEthSpec,
            store::MemoryStore,
            store::MemoryStore,
        >,
    >::pq_new(MinimalEthSpec)
    .store(Arc::clone(&database))
    .custom_spec(spec)
    .genesis_state(state)
    .expect("persist exact PQ genesis markers");
    database
}

fn pq_genesis_state(spec: &types::ChainSpec) -> types::BeaconState<MinimalEthSpec> {
    state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        types::Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32]).expect("synthetic PQ key"),
                withdrawal_credentials: types::Hash256::ZERO,
            })
            .collect(),
        None,
        spec,
    )
    .expect("direct PQ genesis")
}

fn write_exact_public_testnet(
    testnet_dir: &std::path::Path,
    spec: &types::ChainSpec,
) -> types::BeaconState<MinimalEthSpec> {
    let state = pq_genesis_state(spec);
    write_public_testnet_state(testnet_dir, spec, &state);
    state
}

fn write_public_testnet_state(
    testnet_dir: &std::path::Path,
    spec: &types::ChainSpec,
    state: &types::BeaconState<MinimalEthSpec>,
) {
    std::fs::create_dir_all(testnet_dir).expect("public testnet directory fixture");
    #[cfg(unix)]
    std::fs::set_permissions(
        testnet_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("public testnet directory permissions");
    let config = types::Config::from_chain_spec::<MinimalEthSpec>(spec);
    let config_yaml = yaml_serde::to_string(&config).expect("config YAML fixture");
    let deposit_yaml = yaml_serde::to_string(&0_u64).expect("deposit block YAML fixture");
    let bootstrap_yaml =
        yaml_serde::to_string(&Vec::<String>::new()).expect("bootstrap YAML fixture");
    std::fs::write(
        testnet_dir.join("config.yaml"),
        config_yaml.strip_prefix("---\n").unwrap_or(&config_yaml),
    )
    .expect("config fixture");
    std::fs::write(
        testnet_dir.join("deposit_contract_block.txt"),
        deposit_yaml.strip_prefix("---\n").unwrap_or(&deposit_yaml),
    )
    .expect("deposit block fixture");
    std::fs::write(
        testnet_dir.join("bootstrap_nodes.yaml"),
        bootstrap_yaml
            .strip_prefix("---\n")
            .unwrap_or(&bootstrap_yaml),
    )
    .expect("bootstrap fixture");
    std::fs::write(testnet_dir.join("genesis.ssz"), state.as_ssz_bytes()).expect("genesis fixture");
    #[cfg(unix)]
    for name in [
        "config.yaml",
        "deposit_contract_block.txt",
        "bootstrap_nodes.yaml",
        "genesis.ssz",
    ] {
        std::fs::set_permissions(
            testnet_dir.join(name),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .expect("public testnet file permissions");
    }
}

#[test]
fn bounded_public_testnet_loader_seals_exact_genesis_identity() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-public-testnet-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let state = write_exact_public_testnet(&testnet, &spec);

    let sealed =
        PqRuntimeConfig::testing_only_load_public_testnet(&testnet).expect("exact public testnet");

    assert_eq!(sealed.genesis_bytes_len(), state.as_ssz_bytes().len());
    assert_eq!(
        sealed.genesis_validators_root(),
        state.genesis_validators_root()
    );
    assert_eq!(sealed.genesis_time(), state.genesis_time());
    let registry = sealed.validator_registry();
    assert_eq!(registry.len(), state.validators().len());
    for (position, (sealed, validator)) in registry.iter().zip(state.validators()).enumerate() {
        assert_eq!(
            sealed.validator_index(),
            u64::try_from(position).expect("small registry index")
        );
        assert_eq!(sealed.public_key(), validator.pubkey);
        assert_eq!(
            sealed.withdrawal_credentials(),
            validator.withdrawal_credentials.0
        );
    }
    std::fs::remove_dir_all(root).expect("remove public testnet fixture");
}

#[cfg(unix)]
#[test]
fn bounded_public_testnet_loader_rejects_unsafe_entries_and_oversize_genesis() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-public-testnet-policy-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    write_exact_public_testnet(&testnet, &spec);

    let unexpected = testnet.join("unexpected.yaml");
    std::fs::write(&unexpected, b"[]\n").expect("unexpected public entry");
    assert!(matches!(
        PqRuntimeConfig::testing_only_load_public_testnet(&testnet),
        Err(PqPublicTestnetError::UnsafeLayout(_)),
    ));
    std::fs::remove_file(unexpected).expect("remove unexpected entry");

    let config = testnet.join("config.yaml");
    let external_config = root.join("external-config.yaml");
    std::fs::rename(&config, &external_config).expect("move config outside public directory");
    std::os::unix::fs::symlink(&external_config, &config).expect("config symlink fixture");
    assert!(matches!(
        PqRuntimeConfig::testing_only_load_public_testnet(&testnet),
        Err(PqPublicTestnetError::Io { .. }),
    ));
    std::fs::remove_file(&config).expect("remove config symlink");
    std::fs::rename(external_config, &config).expect("restore regular config");

    std::fs::OpenOptions::new()
        .write(true)
        .open(testnet.join("genesis.ssz"))
        .expect("open sparse genesis fixture")
        .set_len(128 * 1024 * 1024 + 1)
        .expect("oversized sparse genesis fixture");
    assert!(matches!(
        PqRuntimeConfig::testing_only_load_public_testnet(&testnet),
        Err(PqPublicTestnetError::FileTooLarge("genesis.ssz")),
    ));
    std::fs::remove_dir_all(root).expect("remove public testnet policy fixture");
}

#[cfg(target_feature = "avx2")]
fn persist_pq_disk_genesis(client: &ClientConfig, spec: Arc<types::ChainSpec>) {
    type DiskWitness = beacon_chain::builder::Witness<
        beacon_chain::slot_clock::SystemTimeSlotClock,
        MinimalEthSpec,
        store::database::interface::BeaconNodeBackend,
        store::database::interface::BeaconNodeBackend,
    >;
    let hot = client.get_db_path();
    let cold = client.get_freezer_db_path();
    let blobs = client.get_blobs_db_path();
    for path in [&hot, &cold, &blobs] {
        std::fs::create_dir_all(path).expect("disk store directory fixture");
    }
    let database = store::HotColdDB::open(
        &hot,
        &cold,
        &blobs,
        beacon_chain::migrate_pq_schema::<DiskWitness>,
        client.store.clone(),
        Arc::clone(&spec),
    )
    .expect("disk store fixture");
    beacon_chain::builder::BeaconChainBuilder::<DiskWitness>::pq_new(MinimalEthSpec)
        .store(database)
        .custom_spec(Arc::clone(&spec))
        .genesis_state(pq_genesis_state(&spec))
        .expect("persist disk genesis fixture");
}

#[test]
fn pq_store_classifier_rejects_partial_ordinary_and_corrupt_markers_exactly() {
    let anchor_only = pq_memory_store();
    let anchor_op = anchor_only
        .init_anchor_info(
            types::Hash256::ZERO,
            types::Slot::new(0),
            types::Slot::new(0),
            false,
        )
        .expect("anchor marker");
    anchor_only
        .hot_db
        .do_atomically(vec![anchor_op])
        .expect("persist anchor marker");
    assert!(matches!(
        classify_pq_store_startup(&anchor_only),
        Err(PqStoreStartupError::MissingPqHeadForInitializedAnchor),
    ));

    let ordinary = pq_memory_store();
    ordinary
        .hot_db
        .put_bytes(DBColumn::BeaconChain, types::Hash256::ZERO.as_slice(), &[1])
        .expect("ordinary sentinel");
    assert!(matches!(
        classify_pq_store_startup(&ordinary),
        Err(PqStoreStartupError::OrdinaryBeaconChain),
    ));

    let corrupt = pq_memory_store();
    corrupt
        .hot_db
        .put_bytes(
            DBColumn::BeaconChain,
            types::Hash256::repeat_byte(0x51).as_slice(),
            &[1],
        )
        .expect("corrupt PQ marker");
    assert!(matches!(
        classify_pq_store_startup(&corrupt),
        Err(PqStoreStartupError::Store(_)),
    ));
}

#[test]
fn pq_store_classifier_requires_the_exact_frozen_genesis_anchor() {
    let ready = pq_ready_store();
    assert!(matches!(
        classify_pq_store_startup(&ready),
        Ok(PqStoreStartup::Resume),
    ));
    let exact = ready.get_anchor_info();
    let mutations = [
        store::AnchorInfo {
            anchor_slot: types::Slot::new(1),
            ..exact.clone()
        },
        store::AnchorInfo {
            oldest_block_slot: types::Slot::new(1),
            ..exact.clone()
        },
        store::AnchorInfo {
            oldest_block_parent: types::Hash256::repeat_byte(1),
            ..exact.clone()
        },
        store::AnchorInfo {
            state_upper_limit: types::Slot::new(0),
            ..exact.clone()
        },
        store::AnchorInfo {
            state_lower_limit: types::Slot::new(1),
            ..exact
        },
    ];
    for mutated in mutations {
        let database = pq_ready_store();
        database
            .compare_and_set_anchor_info_with_write(database.get_anchor_info(), mutated)
            .expect("mutate anchor fixture");
        assert!(matches!(
            classify_pq_store_startup(&database),
            Err(PqStoreStartupError::IncompatibleAnchor),
        ));
    }

    let head_only = pq_ready_store();
    head_only
        .compare_and_set_anchor_info_with_write(
            head_only.get_anchor_info(),
            store::metadata::ANCHOR_UNINITIALIZED,
        )
        .expect("remove anchor fixture");
    assert!(matches!(
        classify_pq_store_startup(&head_only),
        Err(PqStoreStartupError::MissingAnchorForPqHead),
    ));

    let coexist = pq_ready_store();
    coexist
        .hot_db
        .put_bytes(DBColumn::BeaconChain, types::Hash256::ZERO.as_slice(), &[1])
        .expect("ordinary sentinel alongside PQ metadata");
    assert!(matches!(
        classify_pq_store_startup(&coexist),
        Err(PqStoreStartupError::OrdinaryBeaconChain),
    ));
}

#[test]
fn pq_schema_dispatcher_accepts_current_only_and_rejects_ordinary_migration() {
    type DiskWitness = beacon_chain::builder::Witness<
        beacon_chain::slot_clock::SystemTimeSlotClock,
        MinimalEthSpec,
        store::MemoryStore,
        store::MemoryStore,
    >;
    let database = pq_memory_store();
    let current = store::metadata::CURRENT_SCHEMA_VERSION;
    assert!(
        beacon_chain::migrate_pq_schema::<DiskWitness>(Arc::clone(&database), current, current,)
            .is_ok(),
    );
    assert!(matches!(
        beacon_chain::migrate_pq_schema::<DiskWitness>(
            database,
            store::metadata::SchemaVersion(current.as_u64() - 1),
            current,
        ),
        Err(store::Error::HotColdDBError(
            store::hot_cold_store::HotColdDBError::UnsupportedSchemaVersion { .. }
        )),
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_genesis_is_rejected_on_owned_blocking_worker_before_runtime_writes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-invalid-genesis-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let network_dir = root.join("network");
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");

    let mut client = valid_client_config(data_dir.clone());
    client.network.network_dir.clone_from(&network_dir);
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    std::fs::write(testnet.join("genesis.ssz"), [1, 2, 3]).expect("invalid genesis fixture");
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    assert!(matches!(
        PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet)).await,
        Err(PqRuntimeError::PublicTestnet(
            PqPublicTestnetError::GenesisDecode(_)
        )),
    ));
    assert!(!data_dir.exists());
    assert!(!network_dir.exists());
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[tokio::test(flavor = "current_thread")]
async fn jwt_is_parsed_with_the_exact_execution_layer_format_before_genesis() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-invalid-jwt-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let network_dir = root.join("network");
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    std::fs::write(testnet.join("genesis.ssz"), [1, 2, 3]).expect("invalid genesis fixture");
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, format!("0x0x{}", "11".repeat(32))).expect("JWT fixture");

    let mut client = valid_client_config(data_dir.clone());
    client.network.network_dir.clone_from(&network_dir);
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    assert!(matches!(
        PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet)).await,
        Err(PqRuntimeError::JwtInvalid(_)),
    ));
    assert!(!data_dir.exists());
    assert!(!network_dir.exists());
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_reconciliation_precedes_all_network_resources_and_cleans_failure() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-reconciliation-order-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let network_dir = root.join("network");
    let jwt = root.join("jwt.hex");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    std::fs::write(
        &jwt,
        hex::encode(execution_layer::test_utils::DEFAULT_JWT_SECRET),
    )
    .expect("JWT fixture");
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve network port");
    let network_port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);

    let engine_runtime = task_executor::test_utils::TestRuntime::default();
    let engine = execution_layer::test_utils::MockExecutionLayer::<MinimalEthSpec>::new(
        engine_runtime.task_executor.clone(),
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        Some(
            execution_layer::auth::JwtKey::from_slice(
                &execution_layer::test_utils::DEFAULT_JWT_SECRET,
            )
            .expect("MockEngine JWT"),
        ),
        Arc::clone(&spec),
        None,
    );
    engine.server.all_payloads_syncing_on_forkchoice_updated();
    let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release_hook = Arc::clone(&release);
    let blocked_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let blocked_once_hook = Arc::clone(&blocked_once);
    engine
        .server
        .ctx
        .hook
        .lock()
        .set_forkchoice_updated_hook(Box::new(move |_, attributes| {
            assert!(attributes.is_none(), "startup FCU must have no attributes");
            if !blocked_once_hook.swap(true, std::sync::atomic::Ordering::SeqCst) {
                entered_sender.send(()).expect("startup observer alive");
                let (lock, condition) = &*release_hook;
                let mut released = lock.lock().expect("startup release lock");
                while !*released {
                    released = condition.wait(released).expect("startup release wait");
                }
            }
            None
        }));

    let mut client = valid_client_config(data_dir.clone());
    client.network.network_dir.clone_from(&network_dir);
    client
        .network
        .set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, network_port, 0, 0);
    let execution = client.execution_layer.as_mut().expect("execution config");
    execution.execution_endpoint =
        Some(SensitiveUrl::parse(&engine.server.url()).expect("MockEngine execution endpoint"));
    execution.secret_file = Some(jwt);
    let context = |executor| environment::RuntimeContext {
        executor,
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let failed_runtime = task_executor::test_utils::TestRuntime::default();
    let start = tokio::spawn(PqClient::start_pq_runtime(
        context(failed_runtime.task_executor.clone()),
        PqRuntimeConfig::new(client.clone(), testnet.clone()),
    ));
    tokio::task::spawn_blocking(move || {
        entered_receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("startup reaches persisted-head FCU")
    })
    .await
    .expect("startup observer task");
    assert!(!network_dir.exists());
    let held_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, network_port))
        .expect("network listener must not exist before reconciliation");
    drop(held_port);
    let (lock, condition) = &*release;
    *lock.lock().expect("startup release lock") = true;
    condition.notify_all();
    assert!(matches!(
        start.await.expect("startup task"),
        Err(PqRuntimeError::ExecutionReconciliation(
            beacon_chain::PqImportError::ExecutionReconciliation(
                beacon_chain::PqExecutionReconciliationError::Unavailable { attempts: 3 }
            )
        ))
    ));
    assert!(!network_dir.exists());
    let rebound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, network_port))
        .expect("failed startup leaves network port restartable");
    drop(rebound);

    engine.server.all_payloads_valid_on_forkchoice_updated();
    let recovery_runtime = task_executor::test_utils::TestRuntime::default();
    let recovered = PqClient::start_pq_runtime(
        context(recovery_runtime.task_executor.clone()),
        PqRuntimeConfig::new(client, testnet),
    )
    .await
    .expect("valid startup reconciliation exposes the runtime");
    assert!(network_dir.exists());
    recovered
        .shutdown()
        .await
        .expect("recovered runtime shutdown");
    let rebound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, network_port))
        .expect("clean shutdown releases the network port");
    drop(rebound);
    std::fs::remove_dir_all(root).expect("remove reconciliation fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_genesis_disk_configuration_constructs_an_owned_runtime() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-valid-genesis-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");

    let mut client = valid_client_config(data_dir);
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let handle = PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet))
        .await
        .expect("valid PQ disk runtime");
    handle.shutdown().await.expect("clean PQ runtime shutdown");
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_ready_event_failure_drains_bound_network_before_returning() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-ready-failure-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve network port");
    let network_port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);

    let mut client = valid_client_config(root.join("node"));
    client.network.network_dir = root.join("network");
    client
        .network
        .set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, network_port, 0, 0);
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = || environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let error = match PqClient::start_pq_runtime(
        context(),
        testing_runtime_config(client.clone(), testnet.clone())
            .testing_only_fail_runtime_ready_event(),
    )
    .await
    {
        Err(error) => error,
        Ok(runtime) => {
            runtime
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("injected RuntimeReady event failure unexpectedly started")
        }
    };
    assert!(matches!(
        error,
        PqRuntimeError::OperationalEvent(beacon_chain::PqOperationalEventError::Closed)
    ));
    let rebound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, network_port))
        .expect("RuntimeReady failure awaits bound network shutdown");
    drop(rebound);

    let recovered = PqClient::start_pq_runtime(context(), testing_runtime_config(client, testnet))
        .await
        .expect("RuntimeReady cleanup releases all owners");
    recovered.shutdown().await.expect("recovered shutdown");
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_http_binds_after_network_and_normalizes_wildcard_port_zero() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-http-port-zero-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");

    let mut client = valid_client_config(data_dir);
    client.network.network_dir = root.join("network");
    client.http_api.enabled = true;
    client.http_api.listen_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    client.http_api.listen_port = 0;
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let handle = PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet))
        .await
        .expect("verifier HTTP runtime");
    let listen = handle
        .http_api_listen_addr()
        .expect("enabled PQ HTTP listener");
    assert_eq!(
        listen.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    );
    assert_ne!(
        listen.port(),
        0,
        "Warp must report the actual assigned port"
    );
    assert_eq!(
        handle
            .testing_only_pq_local_http_url()
            .expect("normalized local HTTP URL"),
        SensitiveUrl::parse(&format!("http://127.0.0.1:{}/", listen.port()))
            .expect("expected normalized URL"),
    );
    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, listen.port()))
        .await
        .expect("bound PQ Warp listener is live");

    handle.shutdown().await.expect("clean PQ runtime shutdown");
    let rebound = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, listen.port()))
        .expect("graceful HTTP shutdown releases the actual port");
    drop(rebound);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_bind_failure_drains_network_and_allows_immediate_runtime_restart() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-http-bind-failure-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let occupied =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("reserve HTTP port");
    let occupied_port = occupied.local_addr().expect("reserved address").port();

    let mut client = valid_client_config(data_dir);
    client.network.network_dir = root.join("network");
    client.http_api.enabled = true;
    client.http_api.listen_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    client.http_api.listen_port = occupied_port;
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = || environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let error = match PqClient::start_pq_runtime(
        context(),
        testing_runtime_config(client.clone(), testnet.clone()),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("occupied HTTP port unexpectedly started")
        }
    };
    assert!(matches!(error, PqRuntimeError::HttpBind(_)), "{error:?}");

    drop(occupied);
    let restarted = PqClient::start_pq_runtime(context(), testing_runtime_config(client, testnet))
        .await
        .expect("bind failure released network, aggregation, and store owners");
    assert_eq!(
        restarted
            .http_api_listen_addr()
            .expect("restarted HTTP listener")
            .port(),
        occupied_port,
    );
    restarted.shutdown().await.expect("restarted shutdown");
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connection_admission_bounds_idle_partial_headers_and_shutdown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-http-connection-cap-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(root.join("node"));
    client.network.network_dir = root.join("network");
    client.http_api.enabled = true;
    client.http_api.listen_port = 0;
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let handle = PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet))
        .await
        .expect("bounded HTTP runtime");
    let port = handle.http_api_listen_addr().expect("HTTP listener").port();

    let mut admitted = Vec::new();
    for _ in 0..2 {
        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("admitted loopback connection");
        stream
            .write_all(b"GET /")
            .await
            .expect("partial request retained");
        admitted.push(stream);
    }
    let mut overflow = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .expect("kernel accepts overflow before application admission");
    overflow
        .write_all(b"GET /")
        .await
        .expect("overflow write races safely with close");
    let mut byte = [0_u8; 1];
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(2), overflow.read(&mut byte))
                .await
                .expect("overflow connection must be closed promptly"),
            Ok(0) | Err(_)
        ),
        "overflow must be closed or reset without reaching Hyper",
    );

    tokio::time::timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("shutdown must close bounded partial-header connections")
        .expect("bounded runtime shutdown");
    for mut stream in admitted {
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                    .await
                    .expect("shutdown closes admitted partial request"),
                Ok(0) | Err(_)
            ),
            "admitted connection must be closed or reset during shutdown",
        );
    }
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unexpected_http_exit_signals_process_and_shutdown_still_drains_network() {
    use futures::StreamExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-http-unexpected-exit-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(root.join("node"));
    client.network.network_dir = root.join("network");
    client.http_api.enabled = true;
    client.http_api.listen_port = 0;
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);

    let (exit_sender, exit_receiver) = async_channel::bounded(1);
    let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
    let executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        exit_receiver,
        shutdown_sender,
    );
    let context = || environment::RuntimeContext {
        executor: executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let handle = PqClient::start_pq_runtime(
        context(),
        testing_runtime_config(client.clone(), testnet.clone()),
    )
    .await
    .expect("HTTP runtime");

    handle
        .testing_only_stop_pq_http_unexpectedly()
        .await
        .expect("unexpected HTTP completion observed");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), shutdown_receiver.next())
            .await
            .expect("unexpected HTTP exit must signal process shutdown"),
        Some(task_executor::ShutdownReason::Failure(
            "PQ HTTP API exited unexpectedly"
        )),
    ));
    assert!(matches!(
        handle.shutdown().await,
        Err(PqRuntimeError::HttpUnexpectedExit),
    ));

    let restarted = PqClient::start_pq_runtime(context(), testing_runtime_config(client, testnet))
        .await
        .expect("HTTP failure shutdown still drained network and store owners");
    restarted.shutdown().await.expect("restarted shutdown");
    drop(exit_sender);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_store_requires_one_exact_public_testnet_load() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-from-store-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet = root.join("selected-testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let jwt = root.join("jwt.hex");
    std::fs::create_dir_all(&root).expect("fixture root");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.genesis = ClientGenesis::FromStore;
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    persist_pq_disk_genesis(&client, Arc::clone(&spec));
    assert!(!testnet.join("genesis.ssz").exists());
    let runtime = task_executor::test_utils::TestRuntime::default();
    let absent_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    assert!(matches!(
        PqClient::start_pq_runtime(
            absent_context,
            testing_runtime_config(client.clone(), testnet.clone()),
        )
        .await,
        Err(PqRuntimeError::PublicTestnet(
            PqPublicTestnetError::Io { .. }
        )),
    ));

    write_exact_public_testnet(&testnet, &spec);
    std::fs::write(testnet.join("genesis.ssz"), b"corrupt selected genesis")
        .expect("corrupt selected public genesis");
    let corrupt_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    assert!(matches!(
        PqClient::start_pq_runtime(corrupt_context, testing_runtime_config(client, testnet),).await,
        Err(PqRuntimeError::PublicTestnet(
            PqPublicTestnetError::GenesisDecode(_)
        )),
    ));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(all(target_feature = "avx2", feature = "pq-startup-testing"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_resume_checks_the_selected_public_identity_before_runtime_owners() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-verifier-identity-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet = root.join("selected-testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let jwt = root.join("jwt.hex");
    std::fs::create_dir_all(&root).expect("fixture root");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.genesis = ClientGenesis::FromStore;
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    persist_pq_disk_genesis(&client, Arc::clone(&spec));
    let selected_state =
        state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
            types::Hash256::ZERO,
            1,
            (1..=16)
                .map(|byte| state_processing::DirectGenesisValidator {
                    public_key: PqPublicKey::deserialize(&[byte; 32]).expect("synthetic PQ key"),
                    withdrawal_credentials: types::Hash256::ZERO,
                })
                .collect(),
            None,
            &spec,
        )
        .expect("different selected network identity");
    write_public_testnet_state(&testnet, &spec, &selected_state);
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let read_hook: Arc<dyn Fn() + Send + Sync> = {
        let reads = Arc::clone(&reads);
        Arc::new(move || {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let aggregation_owner = consensus_signature::AggregationService::new()
        .expect("hold the sole aggregation service across verifier identity preflight");
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let error = match PqClient::start_pq_runtime(
        context,
        testing_runtime_config(client, testnet).testing_only_genesis_read_hook(read_hook),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("selected network identity unexpectedly accepted the persisted chain")
        }
    };
    assert!(
        matches!(error, PqRuntimeError::PersistedNetworkIdentityMismatch),
        "identity mismatch must win before aggregation construction: {error:?}",
    );
    assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(aggregation_owner);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[tokio::test(flavor = "current_thread")]
async fn from_store_rejects_an_empty_disk_without_starting_runtime_workers() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-empty-from-store-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet = root.join("absent-testnet");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let jwt = root.join("jwt.hex");
    std::fs::create_dir_all(&root).expect("fixture root");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.genesis = ClientGenesis::FromStore;
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    assert!(matches!(
        PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet)).await,
        Err(PqRuntimeError::EmptyStoreRequiresGenesis),
    ));
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(all(target_feature = "avx2", feature = "pq-startup-testing"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caller_cancellation_retains_the_owned_blocking_runtime_until_completion() {
    use std::sync::{Condvar, Mutex};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-cancelled-start-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let entered_sender = Arc::new(Mutex::new(Some(entered_sender)));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let hook_release = Arc::clone(&release);
    let hook = Arc::new(move || {
        if let Some(sender) = entered_sender.lock().expect("entered lock").take() {
            let _ = sender.send(());
        }
        let (lock, condition) = &*hook_release;
        let mut released = lock.lock().expect("release lock");
        while !*released {
            released = condition.wait(released).expect("release wait");
        }
    });
    let config = testing_runtime_config(client, testnet).testing_only_blocking_hook(hook);

    let start = tokio::spawn(PqClient::start_pq_runtime(context, config));
    tokio::time::timeout(std::time::Duration::from_secs(60), entered_receiver)
        .await
        .expect("blocking construction entered")
        .expect("blocking construction sender");
    start.abort();
    let _ = start.await;
    assert!(matches!(
        consensus_signature::AggregationService::new(),
        Err(consensus_signature::AggregationError::AlreadyActive),
    ));
    {
        let (lock, condition) = &*release;
        *lock.lock().expect("release lock") = true;
        condition.notify_all();
    }
    let recovered_service = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match consensus_signature::AggregationService::new() {
                Ok(service) => break service,
                Err(consensus_signature::AggregationError::AlreadyActive) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected aggregation recovery error: {error:?}"),
            }
        }
    })
    .await
    .expect("blocking runtime ownership released");
    drop(recovered_service);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genesis_state_mode_resumes_from_one_sealed_public_network_load() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-disk-restart-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let genesis_path = testnet.join("genesis.ssz");
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let reserved = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserved restart port");
    let restart_port = reserved.local_addr().expect("reserved address").port();
    drop(reserved);
    let mut client = valid_client_config(data_dir);
    client
        .network
        .set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, restart_port, 0, 0);
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();

    let first_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let first = PqClient::start_pq_runtime(
        first_context,
        testing_runtime_config(client.clone(), testnet.clone()),
    )
    .await
    .expect("initial disk runtime");
    let first_head = first
        .beacon_chain()
        .expect("PQ beacon chain")
        .head_snapshot();
    let first_root = first_head.beacon_block_root;
    let first_block = Arc::clone(&first_head.beacon_block);
    let retained_broadcaster = first
        .testing_only_pq_broadcaster()
        .expect("private PQ broadcaster");
    first.shutdown().await.expect("initial clean shutdown");
    assert!(matches!(
        retained_broadcaster.try_send(Arc::clone(&first_block)),
        Err(network::PqBlockBroadcastError::WorkerUnavailable),
    ));

    let genesis_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let genesis_read_hook: Arc<dyn Fn() + Send + Sync> = {
        let genesis_reads = Arc::clone(&genesis_reads);
        Arc::new(move || {
            genesis_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let second_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let second = PqClient::start_pq_runtime(
        second_context,
        testing_runtime_config(client.clone(), testnet.clone())
            .testing_only_genesis_read_hook(Arc::clone(&genesis_read_hook)),
    )
    .await
    .expect("resume disk runtime from the selected public network");
    let second_head = second
        .beacon_chain()
        .expect("PQ beacon chain")
        .head_snapshot();
    assert_eq!(second_head.beacon_block_root, first_root);
    assert_eq!(second_head.beacon_block.as_ref(), first_block.as_ref());
    assert_eq!(
        genesis_reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Resume must bounded-load the selected public network exactly once",
    );
    second.shutdown().await.expect("resumed clean shutdown");

    std::fs::write(&genesis_path, b"corrupt genesis candidate").expect("corrupt genesis fixture");
    let third_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let third_error = match PqClient::start_pq_runtime(
        third_context,
        testing_runtime_config(client, testnet).testing_only_genesis_read_hook(genesis_read_hook),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("corrupt selected public genesis unexpectedly resumed")
        }
    };
    assert!(matches!(
        third_error,
        PqRuntimeError::PublicTestnet(PqPublicTestnetError::GenesisDecode(_))
    ));
    assert_eq!(genesis_reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_network_construction_failure_releases_all_provisional_runtime_owners() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-network-failure-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    write_exact_public_testnet(&testnet, &spec);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let occupied = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("occupied TCP fixture");
    let occupied_port = occupied.local_addr().expect("occupied address").port();
    let mut client = valid_client_config(data_dir);
    client
        .network
        .set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, occupied_port, 0, 0);
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    assert!(matches!(
        PqClient::start_pq_runtime(context, testing_runtime_config(client, testnet)).await,
        Err(PqRuntimeError::Network(
            network::PqNetworkServiceError::Construction(_)
        )),
    ));
    let recovered = consensus_signature::AggregationService::new()
        .expect("late startup failure must release the sole aggregation owner");
    drop(recovered);
    drop(occupied);
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(all(target_feature = "avx2", feature = "pq-proposer"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposer_manifest_identity_mismatch_releases_the_prepared_store_without_late_resources() {
    let root = tempfile::tempdir().expect("root");
    let testnet = root.path().join("testnet");
    let bundle = root.path().join("bundle");
    let validators = bundle.join("validators");
    let secrets = bundle.join("secrets");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let genesis = write_exact_public_testnet(&testnet, &spec);
    std::fs::create_dir(&bundle).expect("bundle directory");
    std::fs::create_dir(&validators).expect("validator directory");
    std::fs::create_dir(&secrets).expect("secret directory");
    #[cfg(unix)]
    for path in [&bundle, &validators, &secrets] {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private directory mode");
    }
    let manifest_path = bundle
        .join(pq_signing::XMSS_USAGE_FILENAME)
        .with_file_name(validator_dir::PQ_DEVNET_MANIFEST_FILE);
    let manifest = serde_json::json!({
        "format": "lighthouse-pq-devnet",
        "version": 1,
        "preset": "minimal",
        "fork": "electra",
        "validator_count": 1,
        "one_time_use_start": 0,
        "one_time_use_end": 7,
        "eth1_timestamp": 1,
        "genesis_validators_root": hex::encode(genesis.genesis_validators_root().0),
        "validators": [{
            "derivation_index": 0,
            "public_key": "01".repeat(32),
            "withdrawal_credentials": "00".repeat(32),
        }],
    });
    let journal = bundle.join(pq_signing::XMSS_USAGE_FILENAME);
    let journal_lock = bundle.join(format!("{}.lock", pq_signing::XMSS_USAGE_FILENAME));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");
    std::fs::write(&journal, b"not consulted before identity mismatch").expect("journal");
    std::fs::write(&journal_lock, b"").expect("journal lock");
    #[cfg(unix)]
    for path in [&manifest_path, &journal, &journal_lock] {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("private file mode");
    }

    let data_dir = root.path().join("node");
    let network_dir = root.path().join("network");
    let jwt = root.path().join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir.clone());
    client.http_api.enabled = true;
    client.network.network_dir.clone_from(&network_dir);
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    let aggregation_owner = consensus_signature::AggregationService::new()
        .expect("hold the sole aggregation service across identity preflight");
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    let error = match PqClient::start_pq_runtime(
        context,
        testing_runtime_config(client.clone(), testnet.clone())
            .with_validator_bundle(bundle.clone()),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("mismatched manifest unexpectedly started the runtime");
        }
    };
    assert!(
        matches!(
            error,
            PqRuntimeError::ValidatorInitialization(initialized_validators::Error::PqBundle(
                validator_dir::PqDevnetBundleError::Manifest(
                    validator_dir::PqDevnetManifestError::WrongGenesisTime { .. }
                )
            ))
        ),
        "unexpected preflight error: {error:?}",
    );

    let mut wrong_root_manifest = manifest;
    wrong_root_manifest["eth1_timestamp"] = serde_json::json!(0);
    wrong_root_manifest["genesis_validators_root"] = serde_json::json!("ff".repeat(32));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&wrong_root_manifest).expect("wrong-root manifest JSON"),
    )
    .expect("wrong-root manifest");
    let root_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let error = match PqClient::start_pq_runtime(
        root_context,
        testing_runtime_config(client.clone(), testnet.clone())
            .with_validator_bundle(bundle.clone()),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("wrong-root manifest unexpectedly started the runtime");
        }
    };
    assert!(
        matches!(
            error,
            PqRuntimeError::ValidatorInitialization(initialized_validators::Error::PqBundle(
                validator_dir::PqDevnetBundleError::Manifest(
                    validator_dir::PqDevnetManifestError::WrongNetworkRoot { .. }
                )
            ))
        ),
        "unexpected preflight error: {error:?}",
    );
    assert!(
        data_dir.exists(),
        "the selected-network disk phase precedes bundle auth"
    );
    assert!(!data_dir.join("pq-proposer").exists());
    assert!(!network_dir.exists());
    drop(aggregation_owner);

    let recovery_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let recovered =
        PqClient::start_pq_runtime(recovery_context, testing_runtime_config(client, testnet))
            .await
            .expect("invalid bundle authentication must release the prepared store");
    recovered
        .shutdown()
        .await
        .expect("recovered verifier shutdown");
}

#[cfg(all(target_feature = "avx2", feature = "pq-proposer"))]
#[derive(Clone, Copy)]
enum PostBindProposerFailure {
    Construction,
    LoopStart,
}

#[cfg(all(target_feature = "avx2", feature = "pq-proposer"))]
async fn assert_post_bind_proposer_failure_cleans_all_owners(
    executor: task_executor::TaskExecutor,
    spec: Arc<types::ChainSpec>,
    client: &ClientConfig,
    testnet: &std::path::Path,
    bundle_dir: &std::path::Path,
    root: &std::path::Path,
    failure: PostBindProposerFailure,
) {
    let failure_name = match failure {
        PostBindProposerFailure::Construction => "constructor",
        PostBindProposerFailure::LoopStart => "loop-start",
    };
    let failure_data_dir = root.join(format!("{failure_name}-failure-node"));
    let failure_network_dir = root.join(format!("{failure_name}-failure-network"));
    let failure_slashing_db = failure_data_dir
        .join("pq-proposer")
        .join(slashing_protection::SLASHING_PROTECTION_FILENAME);
    let reserved_http = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve constructor-failure HTTP port");
    let failure_http_port = reserved_http
        .local_addr()
        .expect("reserved HTTP address")
        .port();
    drop(reserved_http);
    let mut failure_client = client.clone();
    failure_client.set_data_dir(failure_data_dir);
    failure_client
        .network
        .network_dir
        .clone_from(&failure_network_dir);
    failure_client.http_api.listen_port = failure_http_port;
    let context = || environment::RuntimeContext {
        executor: executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let config = testing_runtime_config(failure_client.clone(), testnet.to_path_buf())
        .with_validator_bundle(bundle_dir.to_path_buf());
    let config = match failure {
        PostBindProposerFailure::Construction => config.testing_only_fail_proposer_construction(),
        PostBindProposerFailure::LoopStart => config.testing_only_fail_proposer_loop_start(),
    };
    let observed_failure = match PqClient::start_pq_runtime(context(), config).await {
        Err(error) => error,
        Ok(handle) => {
            handle.shutdown().await.expect("unexpected shutdown");
            panic!("injected proposer construction unexpectedly succeeded")
        }
    };
    assert!(
        matches!(
            (&failure, &observed_failure),
            (
                PostBindProposerFailure::Construction,
                PqRuntimeError::ProposerPreflightInvariant
            ) | (
                PostBindProposerFailure::LoopStart,
                PqRuntimeError::TaskUnavailable
            )
        ),
        "the original {failure_name} error must survive staged cleanup: {observed_failure:?}",
    );
    let rebound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, failure_http_port))
        .unwrap_or_else(|error| panic!("{failure_name} failure must stop and await HTTP: {error}"));
    drop(rebound);
    let failure_slashing = slashing_protection::SlashingDatabase::open(&failure_slashing_db)
        .unwrap_or_else(|error| panic!("{failure_name} failure leaves resumable SQLite: {error}"));
    assert_eq!(
        failure_slashing
            .num_validator_rows()
            .expect("registered identity rows"),
        1,
    );
    drop(failure_slashing);
    let recovered = PqClient::start_pq_runtime(
        context(),
        testing_runtime_config(failure_client, testnet.to_path_buf()),
    )
    .await
    .unwrap_or_else(|error| panic!("{failure_name} cleanup restart: {error:?}"));
    assert_eq!(
        recovered
            .http_api_listen_addr()
            .expect("recovered HTTP listener")
            .port(),
        failure_http_port,
    );
    recovered.shutdown().await.expect("recovered shutdown");
}

#[cfg(all(target_feature = "avx2", feature = "pq-proposer"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposer_configuration_constructs_a_sealed_validator_store_owner() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-sealed-proposer-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("fixture root");
    const PASSWORD: &[u8] = b"deterministic test password";
    let container = root.join("container");
    let testnet = container.join("testnet");
    let bundle_dir = container.join("bundle");
    let validators = bundle_dir.join("validators");
    let secrets = bundle_dir.join("secrets");
    std::fs::create_dir_all(&validators).expect("validator directory");
    std::fs::create_dir_all(&secrets).expect("secret directory");
    #[cfg(unix)]
    for path in [&bundle_dir, &validators, &secrets] {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("private directory mode");
    }
    let keystore =
        pq_signing::PqKeystore::from_seed([44; 32], 0..=7, PASSWORD).expect("local PQ keystore");
    let metadata = keystore
        .authenticate(PASSWORD)
        .expect("authenticated metadata");
    let public_key = *metadata.public_key();
    validator_dir::PqValidatorDirBuilder::new(validators)
        .password_dir(&secrets)
        .voting_keystore(keystore, PASSWORD)
        .build()
        .expect("validator directory");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut direct_validators = vec![state_processing::DirectGenesisValidator {
        public_key,
        withdrawal_credentials: types::Hash256::ZERO,
    }];
    direct_validators.extend(
        (2..=16).map(|byte| state_processing::DirectGenesisValidator {
            public_key: PqPublicKey::deserialize(&[byte; 32]).expect("synthetic registry key"),
            withdrawal_credentials: types::Hash256::ZERO,
        }),
    );
    let genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        types::Hash256::ZERO,
        42,
        direct_validators,
        None,
        &spec,
    )
    .expect("16-validator PQ genesis");
    write_public_testnet_state(&testnet, &spec, &genesis);
    let genesis_root = genesis.genesis_validators_root().0;
    pq_signing::provision_usage_journal(
        &bundle_dir.join(pq_signing::XMSS_USAGE_FILENAME),
        genesis_root,
        std::slice::from_ref(&metadata),
    )
    .expect("network-bound usage journal");
    let manifest = validator_dir::PqDevnetManifest::new(
        1,
        0,
        7,
        42,
        genesis_root,
        vec![validator_dir::PqManifestValidator::new(
            0, public_key, [0; 32],
        )],
    );
    let manifest_path = bundle_dir.join(validator_dir::PQ_DEVNET_MANIFEST_FILE);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");
    #[cfg(unix)]
    std::fs::set_permissions(
        &manifest_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("manifest mode");
    let data_dir = root.join("node");
    let slashing_db = data_dir
        .join("pq-proposer")
        .join(slashing_protection::SLASHING_PROTECTION_FILENAME);
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.http_api.enabled = true;
    client.http_api.listen_port = 0;
    client.network.network_dir = root.join("network");
    client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(jwt);
    let runtime = task_executor::test_utils::TestRuntime::default();
    for failure in [
        PostBindProposerFailure::Construction,
        PostBindProposerFailure::LoopStart,
    ] {
        Box::pin(assert_post_bind_proposer_failure_cleans_all_owners(
            runtime.task_executor.clone(),
            Arc::clone(&spec),
            &client,
            &testnet,
            &bundle_dir,
            &root,
            failure,
        ))
        .await;
    }
    let context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let config = testing_runtime_config(client.clone(), testnet.clone())
        .with_validator_bundle(bundle_dir.clone());

    let handle = PqClient::start_pq_runtime(context, config)
        .await
        .expect("sealed PQ validator-store owner");
    assert_eq!(
        handle
            .testing_only_pq_validator_identities()
            .expect("private PQ validator store"),
        vec![(public_key, 0)],
    );
    assert!(
        handle.testing_only_pq_proposer_is_running(),
        "the sealed store must be consumed only after actual HTTP bind",
    );
    handle
        .testing_only_wait_for_pq_proposer_attempt()
        .await
        .expect("slot loop calls the concrete proposer service");
    assert_eq!(
        handle.testing_only_pq_proposer_max_retained_receipts(),
        Some(1),
        "the process-owned loop retains at most one cloneable receipt",
    );
    assert!(bundle_dir.exists());
    assert!(slashing_db.is_file());
    handle.shutdown().await.expect("clean PQ runtime shutdown");
    assert!(bundle_dir.exists());
    assert!(slashing_db.is_file());

    let signing_root = types::Hash256::repeat_byte(0x5a);
    let slashing = slashing_protection::SlashingDatabase::open(&slashing_db)
        .expect("open the first runtime's slashing database");
    assert_eq!(slashing.num_validator_rows().expect("registered rows"), 1);
    assert_eq!(
        slashing.check_and_insert_block_signing_root(
            &public_key,
            types::Slot::new(1),
            signing_root.into(),
        ),
        Ok(slashing_protection::Safe::Valid),
    );
    drop(slashing);

    let restart_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let restarted = PqClient::start_pq_runtime(
        restart_context,
        testing_runtime_config(client.clone(), testnet.clone())
            .with_validator_bundle(bundle_dir.clone()),
    )
    .await
    .expect("restart with the existing slashing database");
    assert_eq!(
        restarted
            .testing_only_pq_validator_identities()
            .expect("restarted private PQ validator store"),
        vec![(public_key, 0)],
    );
    restarted
        .shutdown()
        .await
        .expect("clean restarted PQ runtime shutdown");
    let slashing = slashing_protection::SlashingDatabase::open(&slashing_db)
        .expect("reopen the restarted slashing database");
    assert_eq!(slashing.num_validator_rows().expect("registered rows"), 1);
    assert_eq!(
        slashing.check_and_insert_block_signing_root(
            &public_key,
            types::Slot::new(1),
            signing_root.into(),
        ),
        Ok(slashing_protection::Safe::SameData),
        "restart must retain exact proposal history",
    );
    drop(slashing);

    let cancelled_data_dir = root.join("cancelled-node");
    let cancelled_network_dir = root.join("cancelled-network");
    let cancelled_slashing_db = cancelled_data_dir
        .join("pq-proposer")
        .join(slashing_protection::SLASHING_PROTECTION_FILENAME);
    let mut cancelled_client = valid_client_config(cancelled_data_dir);
    cancelled_client.http_api.enabled = true;
    cancelled_client
        .network
        .network_dir
        .clone_from(&cancelled_network_dir);
    cancelled_client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(root.join("jwt.hex"));
    let auth_entered = Arc::new(tokio::sync::Barrier::new(2));
    let auth_completed = Arc::new(tokio::sync::Barrier::new(2));
    let cancelled_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let cancelled_start = tokio::spawn(PqClient::start_pq_runtime(
        cancelled_context,
        testing_runtime_config(cancelled_client.clone(), testnet.clone())
            .with_validator_bundle(bundle_dir.clone())
            .testing_only_bundle_auth_barriers(
                Arc::clone(&auth_entered),
                Arc::clone(&auth_completed),
            ),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(60), auth_entered.wait())
        .await
        .expect("bundle authentication owner entered");
    cancelled_start.abort();
    let _ = cancelled_start.await;

    let contender_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    match PqClient::start_pq_runtime(
        contender_context,
        testing_runtime_config(cancelled_client.clone(), testnet.clone()),
    )
    .await
    {
        Err(PqRuntimeError::Store(_)) => {}
        Err(error) => panic!("unexpected retained-store contender result: {error:?}"),
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected contender shutdown");
            panic!("caller cancellation released the prepared store during bundle auth")
        }
    }

    let (heartbeat_sender, heartbeat_receiver) = tokio::sync::oneshot::channel();
    runtime.task_executor.spawn(
        async move {
            tokio::task::yield_now().await;
            let _ = heartbeat_sender.send(());
        },
        "pq-runtime-bundle-auth-heartbeat",
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), heartbeat_receiver)
        .await
        .expect("TaskExecutor heartbeat while the boxed prepared owner authenticates")
        .expect("heartbeat sender");

    tokio::time::timeout(std::time::Duration::from_secs(120), auth_completed.wait())
        .await
        .expect("bundle authentication completed while retaining the prepared store");
    assert!(
        !cancelled_slashing_db.exists(),
        "canceled startup must not reach slashing protection"
    );
    assert!(
        !cancelled_network_dir.exists(),
        "canceled startup must not reach network construction"
    );
    let recovered_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec: Arc::clone(&spec),
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let recovered = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        PqClient::start_pq_runtime(
            recovered_context,
            testing_runtime_config(cancelled_client, testnet.clone()),
        ),
    )
    .await
    .expect("prepared store released after detached authentication completion")
    .expect("verifier restart after canceled proposer authentication");
    recovered
        .shutdown()
        .await
        .expect("recovered verifier shutdown");

    let mismatched_data_dir = root.join("mismatched-node");
    let mismatched_network_dir = root.join("mismatched-network");
    let mismatched_slashing_db = mismatched_data_dir
        .join("pq-proposer")
        .join(slashing_protection::SLASHING_PROTECTION_FILENAME);
    let mut mismatched_client = valid_client_config(mismatched_data_dir);
    mismatched_client.http_api.enabled = true;
    mismatched_client
        .network
        .network_dir
        .clone_from(&mismatched_network_dir);
    mismatched_client
        .execution_layer
        .as_mut()
        .expect("execution config")
        .secret_file = Some(root.join("jwt.hex"));
    persist_pq_disk_genesis(&mismatched_client, Arc::clone(&spec));
    let genesis_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let genesis_read_hook: Arc<dyn Fn() + Send + Sync> = {
        let genesis_reads = Arc::clone(&genesis_reads);
        Arc::new(move || {
            genesis_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
    };
    let held_initialized = initialized_validators::InitializedValidators::from_pq_bundle(
        bundle_dir.clone(),
        genesis_root,
        genesis.genesis_time(),
        genesis
            .validators()
            .iter()
            .enumerate()
            .map(|(position, validator)| {
                PqValidatorRegistryEntry::new(
                    u64::try_from(position).expect("small registry index"),
                    validator.pubkey,
                    validator.withdrawal_credentials.0,
                )
            })
            .collect(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("hold the journal-backed signing authority across mismatched resume");
    let aggregation_owner = consensus_signature::AggregationService::new()
        .expect("hold the sole aggregation service before mismatched resume");
    let mismatch_context = environment::RuntimeContext {
        executor: runtime.task_executor.clone(),
        eth_spec_instance: MinimalEthSpec,
        eth2_config: eth2_config::Eth2Config {
            eth_spec_id: types::EthSpecId::Minimal,
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };
    let mismatch_error = match PqClient::start_pq_runtime(
        mismatch_context,
        testing_runtime_config(mismatched_client, testnet)
            .with_validator_bundle(bundle_dir.clone())
            .testing_only_genesis_read_hook(genesis_read_hook),
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle
                .shutdown()
                .await
                .expect("unexpected runtime shutdown");
            panic!("mismatched persisted network unexpectedly started")
        }
    };
    assert!(
        matches!(
            mismatch_error,
            PqRuntimeError::PersistedNetworkIdentityMismatch
        ),
        "persisted identity must fail before aggregation construction: {mismatch_error:?}",
    );
    assert_eq!(
        genesis_reads.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Resume must bounded-load the selected network once without an inner reread",
    );
    assert!(!mismatched_network_dir.exists());
    assert!(!mismatched_slashing_db.exists());
    drop(aggregation_owner);
    drop(held_initialized);
    std::fs::remove_dir_all(root).expect("remove fixture");
}
