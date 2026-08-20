#![cfg(all(feature = "pq-devnet", feature = "pq-startup-testing"))]

use beacon_chain::{PqStoreStartup, PqStoreStartupError, classify_pq_store_startup};
use client::config::{ClientGenesis, Config as ClientConfig, PqHttpTlsConfig};
use client::{
    PqClient, PqProposerRuntimePaths, PqRuntimeConfig, PqRuntimeConfigError, PqRuntimeError,
};
use consensus_signature::PqPublicKey;
use sensitive_url::SensitiveUrl;
#[cfg(target_feature = "avx2")]
use ssz::Encode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{DBColumn, KeyValueStore};
use types::{EthSpec, ForkName, MinimalEthSpec};

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
    let config = PqRuntimeConfig::new(
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
        PqRuntimeConfig::new(missing_layer, "testnet".into())
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
        PqRuntimeConfig::new(missing_endpoint, "testnet".into())
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
        PqRuntimeConfig::new(missing_jwt, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("explicit JWT path is mandatory"),
        PqRuntimeConfigError::MissingJwtSecret,
    );
    assert!(!data_dir.exists());
}

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
    let slashing_db = root.join("slashing.sqlite");
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);

    let disabled_http = valid_client_config(data_dir.clone());
    assert_eq!(
        PqRuntimeConfig::new(disabled_http, root.join("testnet"))
            .with_proposer(PqProposerRuntimePaths::new(
                bundle_dir.clone(),
                slashing_db.clone(),
            ))
            .testing_only_validate(&spec)
            .expect_err("proposer requires the narrow HTTP surface"),
        PqRuntimeConfigError::ProposerRequiresHttp,
    );

    let mut enabled_http = valid_client_config(data_dir);
    enabled_http.http_api.enabled = true;
    let plan = PqRuntimeConfig::new(enabled_http, root.join("testnet"))
        .with_proposer(PqProposerRuntimePaths::new(
            bundle_dir.clone(),
            slashing_db.clone(),
        ))
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
        PqRuntimeConfig::new(tls, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("HTTP TLS is outside the PQ facade"),
        PqRuntimeConfigError::UnsupportedOption("HTTP TLS"),
    );

    let mut cors = valid_client_config(root.join("cors"));
    cors.http_api.allow_origin = Some("*".into());
    assert_eq!(
        PqRuntimeConfig::new(cors, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("CORS is outside the PQ facade"),
        PqRuntimeConfigError::UnsupportedOption("HTTP CORS"),
    );

    let mut metrics = valid_client_config(root.join("metrics"));
    metrics.http_metrics.enabled = true;
    assert_eq!(
        PqRuntimeConfig::new(metrics, "testnet".into())
            .testing_only_validate(&spec)
            .expect_err("metrics are outside the PQ runtime"),
        PqRuntimeConfigError::UnsupportedOption("metrics"),
    );

    let mut monitoring = valid_client_config(root.join("monitoring"));
    monitoring.monitoring_api = Some(monitoring_api::Config::default());
    assert_eq!(
        PqRuntimeConfig::new(monitoring, "testnet".into())
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

    let plan = PqRuntimeConfig::new(config, testnet_dir.clone())
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

    let plan = PqRuntimeConfig::new(client, relative_data_dir.join("testnet"))
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
        PqRuntimeConfig::new(invalid_compression, root.join("testnet"))
            .testing_only_validate(&spec)
            .expect_err("invalid store compression"),
        PqRuntimeConfigError::InvalidStoreConfiguration,
    );
    assert!(!root.exists());

    let mut invalid_pruning = valid_client_config(root.join("pruning"));
    invalid_pruning.store.epochs_per_blob_prune = 0;
    assert_eq!(
        PqRuntimeConfig::new(invalid_pruning, root.join("testnet"))
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
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    std::fs::write(testnet.join("genesis.ssz"), [1, 2, 3]).expect("invalid genesis fixture");
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
        PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet)).await,
        Err(PqRuntimeError::GenesisDecode(_)),
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
            spec,
        },
        eth2_network_config: None,
        sse_logging_components: None,
    };

    assert!(matches!(
        PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet)).await,
        Err(PqRuntimeError::JwtInvalid(_)),
    ));
    assert!(!data_dir.exists());
    assert!(!network_dir.exists());
    std::fs::remove_dir_all(root).expect("remove fixture");
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
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    std::fs::write(
        testnet.join("genesis.ssz"),
        pq_genesis_state(&spec).as_ssz_bytes(),
    )
    .expect("genesis fixture");
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

    let handle = PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet))
        .await
        .expect("valid PQ disk runtime");
    handle.shutdown().await.expect("clean PQ runtime shutdown");
    std::fs::remove_dir_all(root).expect("remove fixture");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_store_resumes_a_valid_disk_without_a_genesis_file() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-from-store-{}-{unique}",
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
    persist_pq_disk_genesis(&client, Arc::clone(&spec));
    assert!(!testnet.join("genesis.ssz").exists());
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

    let handle = PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet))
        .await
        .expect("resume valid PQ disk without genesis file");
    handle.shutdown().await.expect("clean PQ runtime shutdown");
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
        PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet)).await,
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
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    std::fs::write(
        testnet.join("genesis.ssz"),
        pq_genesis_state(&spec).as_ssz_bytes(),
    )
    .expect("genesis fixture");
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
    let config = PqRuntimeConfig::new(client, testnet).testing_only_blocking_hook(hook);

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
async fn genesis_state_mode_resumes_the_exact_signed_head_when_genesis_is_absent_or_corrupt() {
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
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let genesis_path = testnet.join("genesis.ssz");
    std::fs::write(&genesis_path, pq_genesis_state(&spec).as_ssz_bytes()).expect("genesis fixture");
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
        PqRuntimeConfig::new(client.clone(), testnet.clone()),
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

    std::fs::remove_file(&genesis_path).expect("remove genesis before resume");
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
        PqRuntimeConfig::new(client.clone(), testnet.clone())
            .testing_only_genesis_read_hook(Arc::clone(&genesis_read_hook)),
    )
    .await
    .expect("resume disk runtime without genesis");
    let second_head = second
        .beacon_chain()
        .expect("PQ beacon chain")
        .head_snapshot();
    assert_eq!(second_head.beacon_block_root, first_root);
    assert_eq!(second_head.beacon_block.as_ref(), first_block.as_ref());
    assert_eq!(genesis_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
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
    let third = PqClient::start_pq_runtime(
        third_context,
        PqRuntimeConfig::new(client, testnet).testing_only_genesis_read_hook(genesis_read_hook),
    )
    .await
    .expect("resume disk runtime with corrupt genesis candidate");
    let third_head = third
        .beacon_chain()
        .expect("PQ beacon chain")
        .head_snapshot();
    assert_eq!(third_head.beacon_block_root, first_root);
    assert_eq!(third_head.beacon_block.as_ref(), first_block.as_ref());
    assert_eq!(genesis_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    third
        .shutdown()
        .await
        .expect("second resumed clean shutdown");
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
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    std::fs::write(
        testnet.join("genesis.ssz"),
        pq_genesis_state(&spec).as_ssz_bytes(),
    )
    .expect("genesis fixture");
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
        PqClient::start_pq_runtime(context, PqRuntimeConfig::new(client, testnet)).await,
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

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposer_configuration_remains_sealed_without_opening_signer_or_slashing_resources() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-runtime-sealed-proposer-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("testnet");
    let data_dir = root.join("node");
    let bundle_dir = root.join("private-bundle");
    let slashing_db = root.join("slashing.sqlite");
    std::fs::create_dir_all(&testnet).expect("testnet fixture");
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    std::fs::write(
        testnet.join("genesis.ssz"),
        pq_genesis_state(&spec).as_ssz_bytes(),
    )
    .expect("genesis fixture");
    let jwt = root.join("jwt.hex");
    std::fs::write(&jwt, "11".repeat(32)).expect("JWT fixture");
    let mut client = valid_client_config(data_dir);
    client.http_api.enabled = true;
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
    let config = PqRuntimeConfig::new(client, testnet).with_proposer(PqProposerRuntimePaths::new(
        bundle_dir.clone(),
        slashing_db.clone(),
    ));

    let handle = PqClient::start_pq_runtime(context, config)
        .await
        .expect("e4c retains but does not open proposer resources");
    assert!(!bundle_dir.exists());
    assert!(!slashing_db.exists());
    handle.shutdown().await.expect("clean PQ runtime shutdown");
    assert!(!bundle_dir.exists());
    assert!(!slashing_db.exists());
    std::fs::remove_dir_all(root).expect("remove fixture");
}
