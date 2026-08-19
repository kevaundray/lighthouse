use beacon_chain::{
    PqRuntimeError,
    builder::{BeaconChainBuilder, Witness},
};
use beacon_node::{
    ClientConfig, PqCliConfigError, PqClientConfigError, PqStartupError, ProductionBeaconNode,
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{AggregationError, AggregationService};
use consensus_signature::{IndividualSignature, PqPublicKey};
use slot_clock::TestingSlotClock;
#[cfg(target_feature = "avx2")]
use state_processing::per_slot_processing_pq;
use state_processing::{
    DirectGenesisValidator, PqDevnetStateError, initialize_beacon_state_from_validators,
};
use std::sync::Arc;
use store::{DBColumn, HotColdDB, KeyValueStore, MemoryStore, StoreConfig};
use types::{
    BeaconBlock, BeaconState, ChainSpec, EthSpec, ForkName, Hash256, MinimalEthSpec,
    SignedBeaconBlock,
};

type TestWitness = Witness<TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[test]
fn caller_can_match_typed_cli_and_deferred_startup_errors() {
    let plain_matches = beacon_node::cli_app()
        .try_get_matches_from([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
        ])
        .expect("plain beacon-node arguments");
    assert!(matches!(
        ProductionBeaconNode::<MinimalEthSpec>::new_from_cli(plain_matches),
        Err(PqStartupError::Runtime(
            PqRuntimeError::DeferredRuntimeIntegration
        ))
    ));

    let unsupported_matches = beacon_node::cli_app()
        .try_get_matches_from([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--archive",
        ])
        .expect("archive is parsed before PQ profile validation");
    assert!(matches!(
        ProductionBeaconNode::<MinimalEthSpec>::new_from_cli(unsupported_matches),
        Err(PqStartupError::CliConfig(
            PqCliConfigError::UnsupportedOption("--archive")
        ))
    ));
}

#[test]
fn caller_can_match_typed_programmatic_config_error() {
    let environment = environment::EnvironmentBuilder::minimal()
        .multi_threaded_tokio_runtime()
        .expect("test runtime")
        .build()
        .expect("test environment");
    let context = environment.core_context();
    assert!(matches!(
        environment
            .runtime()
            .block_on(ProductionBeaconNode::<MinimalEthSpec>::new(
                context,
                ClientConfig::default(),
            )),
        Err(PqStartupError::ClientConfig(
            PqClientConfigError::UnsupportedGenesis
        ))
    ));
}

#[test]
fn pq_runtime_error_preserves_nested_error_sources() {
    let runtime = PqRuntimeError::InvalidState(PqDevnetStateError::InvalidForkSchedule);
    let source = std::error::Error::source(&runtime).expect("invalid state source");
    assert_eq!(
        source.to_string(),
        PqDevnetStateError::InvalidForkSchedule.to_string()
    );
}

#[test]
fn canonical_snapshot_persistence_is_one_atomic_hot_db_batch() {
    let spec = Arc::new(electra_spec());
    let store = exact_snapshot_store(spec.clone());
    let (state, block) = signed_head(valid_state(&spec), &spec);
    let state_root = block.message().state_root();
    let block_root = block.canonical_root();
    store
        .hot_db
        .fail_atomic_batch_containing(DBColumn::BeaconBlock);

    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store.clone())
            .custom_spec(spec)
            .testing_only_persist_unverified_canonical_snapshot(state, block),
        Err(PqRuntimeError::Store(_))
    ));
    assert_eq!(
        store.get_anchor_info(),
        store::metadata::ANCHOR_UNINITIALIZED
    );
    assert!(
        store
            .hot_db
            .get_bytes(DBColumn::BeaconStateHotSnapshot, state_root.as_slice())
            .expect("read state snapshot")
            .is_none()
    );
    assert!(
        store
            .hot_db
            .get_bytes(DBColumn::BeaconBlock, block_root.as_slice())
            .expect("read block")
            .is_none()
    );
    assert!(
        store
            .hot_db
            .get_bytes(DBColumn::BeaconChain, &[0x51; 32])
            .expect("read PQ head")
            .is_none()
    );
}

fn electra_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

fn synthetic_validator(byte: u8) -> DirectGenesisValidator {
    DirectGenesisValidator {
        public_key: PqPublicKey::deserialize(&[byte; 32]).expect("canonical test public key"),
        withdrawal_credentials: Hash256::ZERO,
    }
}

fn valid_state(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    state_with_validators(spec, (1..=16).collect())
}

fn state_with_validators(spec: &ChainSpec, key_bytes: Vec<u8>) -> BeaconState<MinimalEthSpec> {
    initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        key_bytes.into_iter().map(synthetic_validator).collect(),
        None,
        spec,
    )
    .expect("direct PQ genesis")
}

fn exact_snapshot_store(
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

fn overwrite_persisted_head(
    store: &HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>,
    block_root: Hash256,
    state_root: Hash256,
    slot: u64,
) {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(block_root.as_slice());
    bytes.extend_from_slice(state_root.as_slice());
    bytes.extend_from_slice(&slot.to_le_bytes());
    store
        .hot_db
        .put_bytes(
            DBColumn::BeaconChain,
            Hash256::repeat_byte(0x51).as_slice(),
            &bytes,
        )
        .expect("overwrite PQ head metadata");
}

fn persisted_head(
    store: Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>>,
    spec: Arc<ChainSpec>,
    state: BeaconState<MinimalEthSpec>,
    block: SignedBeaconBlock<MinimalEthSpec>,
) -> (Hash256, Hash256) {
    let block_root = block.canonical_root();
    let state_root = block.message().state_root();
    BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(store)
        .custom_spec(spec)
        .testing_only_persist_unverified_canonical_snapshot(state, block)
        .expect("persist valid PQ head");
    (block_root, state_root)
}

fn signed_head(
    mut state: BeaconState<MinimalEthSpec>,
    spec: &ChainSpec,
) -> (
    BeaconState<MinimalEthSpec>,
    SignedBeaconBlock<MinimalEthSpec>,
) {
    let state_root = state.update_tree_hash_cache().expect("state root");
    let mut block = BeaconBlock::empty(spec);
    let BeaconBlock::Electra(inner) = &mut block else {
        panic!("Electra profile")
    };
    inner.slot = state.slot();
    inner.state_root = state_root;
    (
        state,
        SignedBeaconBlock::from_block(block, IndividualSignature::empty()),
    )
}

#[test]
#[cfg(target_feature = "avx2")]
fn startup_owns_one_cache_and_service_and_restart_ignores_bls_records() {
    let test_runtime = task_executor::test_utils::TestRuntime::default();
    let spec = Arc::new(electra_spec());
    let store = exact_snapshot_store(spec.clone());
    let mut state = valid_state(&spec);
    for _ in 0..7 {
        per_slot_processing_pq(&mut state, &spec).expect("advance exact snapshot state");
    }
    assert_eq!(
        state.slot().as_u64(),
        7,
        "restart must not hide at epoch 32"
    );
    let (state, block) = signed_head(state, &spec);

    let builder = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(store.clone())
        .custom_spec(spec.clone())
        .testing_only_persist_unverified_canonical_snapshot(state, block)
        .expect("strict state preflight before worker startup");
    assert_eq!(
        store
            .hot_db
            .iter_column_keys::<Vec<u8>>(DBColumn::PubkeyCache)
            .count(),
        0,
        "PQ startup must not create pkc"
    );

    let service = Arc::new(AggregationService::new().expect("sole PQ aggregation service"));
    match AggregationService::new() {
        Err(error) => assert_eq!(error, AggregationError::AlreadyActive),
        Ok(_) => panic!("second singleton must fail explicitly"),
    }
    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store.clone())
            .custom_spec(spec.clone())
            .resume_from_db()
            .expect("load persisted head for missing-executor check")
            .pq_aggregation_service(service.clone())
            .build(),
        Err(PqRuntimeError::MissingTaskExecutor)
    ));
    let chain = builder
        .pq_aggregation_service(service.clone())
        .task_executor(test_runtime.task_executor.clone())
        .build()
        .expect("valid PQ ownership core");
    assert!(Arc::ptr_eq(&chain.pq_aggregation_service, &service));
    assert_eq!(chain.pq_validator_key_cache.len(), 16);

    let cache_before = chain.pq_validator_key_cache.clone();
    let legacy_pkc_key = [0x31; 32];
    let legacy_pkc_bytes = b"legacy-pkc-must-remain-byte-identical";
    let legacy_opo_key = [0; 32];
    let legacy_opo_bytes = b"legacy-opo-must-remain-byte-identical";
    store
        .hot_db
        .put_bytes(DBColumn::PubkeyCache, &legacy_pkc_key, legacy_pkc_bytes)
        .expect("seed legacy pkc");
    store
        .hot_db
        .put_bytes(DBColumn::OpPool, &legacy_opo_key, legacy_opo_bytes)
        .expect("seed legacy opo");

    let restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(store.clone())
        .custom_spec(spec)
        .resume_from_db()
        .expect("exact non-epoch snapshot restart")
        .pq_aggregation_service(service.clone())
        .task_executor(test_runtime.task_executor.clone())
        .build()
        .expect("restart reuses the sole service");
    assert_eq!(*restarted.pq_validator_key_cache, *cache_before);
    assert!(!Arc::ptr_eq(
        &restarted.pq_validator_key_cache,
        &cache_before
    ));
    assert!(Arc::ptr_eq(&restarted.pq_aggregation_service, &service));
    assert_eq!(restarted.head_snapshot().beacon_state.slot().as_u64(), 7);
    assert_eq!(
        store
            .hot_db
            .get_bytes(DBColumn::PubkeyCache, &legacy_pkc_key)
            .expect("read legacy pkc")
            .as_deref(),
        Some(legacy_pkc_bytes.as_slice())
    );
    assert_eq!(
        store
            .hot_db
            .get_bytes(DBColumn::OpPool, &legacy_opo_key)
            .expect("read legacy opo")
            .as_deref(),
        Some(legacy_opo_bytes.as_slice())
    );
}

#[test]
fn restart_rejects_tampered_persisted_slot_binding() {
    let spec = Arc::new(electra_spec());
    let store = exact_snapshot_store(spec.clone());
    let (state, block) = signed_head(valid_state(&spec), &spec);
    let (block_root, state_root) = persisted_head(store.clone(), spec.clone(), state, block);
    overwrite_persisted_head(&store, block_root, state_root, 1);

    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store)
            .custom_spec(spec)
            .resume_from_db(),
        Err(PqRuntimeError::PersistedHeadBinding(_))
    ));
}

#[test]
fn restart_rejects_block_stored_under_the_wrong_root() {
    let spec = Arc::new(electra_spec());
    let store = exact_snapshot_store(spec.clone());
    let (state, block) = signed_head(valid_state(&spec), &spec);
    let (block_root, _) = persisted_head(store.clone(), spec.clone(), state, block.clone());
    let mut wrong_block = block;
    *wrong_block.message_mut().parent_root_mut() = Hash256::repeat_byte(0x42);
    assert_ne!(wrong_block.canonical_root(), block_root);
    store
        .put_block(&block_root, wrong_block)
        .expect("tamper block contents under persisted root");

    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store)
            .custom_spec(spec)
            .resume_from_db(),
        Err(PqRuntimeError::PersistedHeadBinding(_))
    ));
}

#[test]
fn restart_rejects_unrelated_valid_state() {
    let spec = Arc::new(electra_spec());
    let store = exact_snapshot_store(spec.clone());
    let (state, block) = signed_head(valid_state(&spec), &spec);
    let (block_root, _) = persisted_head(store.clone(), spec.clone(), state, block);

    let mut unrelated_state = valid_state(&spec);
    unrelated_state.genesis_time_mut().clone_from(&1);
    let unrelated_root = unrelated_state
        .update_tree_hash_cache()
        .expect("unrelated state root");
    store
        .put_state(&unrelated_root, &unrelated_state)
        .expect("persist unrelated valid state");
    overwrite_persisted_head(&store, block_root, unrelated_root, 0);

    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(store)
            .custom_spec(spec)
            .resume_from_db(),
        Err(PqRuntimeError::PersistedHeadBinding(_))
    ));
}

#[test]
fn canonical_head_rejects_invalid_profile_and_never_rewrites_a_signed_head() {
    let spec = Arc::new(electra_spec());

    for validator_keys in [(1..=15).collect(), (1..=17).collect()] {
        let state = state_with_validators(&spec, validator_keys);
        let (state, block) = signed_head(state, &spec);
        assert!(matches!(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(spec.clone()))
                .custom_spec(spec.clone())
                .testing_only_persist_unverified_canonical_snapshot(state, block),
            Err(PqRuntimeError::InvalidState(_))
        ));
    }

    let duplicate_keys = vec![1; 16];
    let state = state_with_validators(&spec, duplicate_keys);
    let (state, block) = signed_head(state, &spec);
    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(spec.clone()))
            .custom_spec(spec.clone())
            .testing_only_persist_unverified_canonical_snapshot(state, block),
        Err(PqRuntimeError::InvalidKeyCache(_))
    ));

    let mut pending_state = valid_state(&spec);
    *pending_state
        .balances_mut()
        .get_mut(0)
        .expect("first balance") += 1;
    pending_state
        .queue_excess_active_balance(0, &spec)
        .expect("queue unsupported pending deposit");
    let (pending_state, pending_block) = signed_head(pending_state, &spec);
    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(spec.clone()))
            .custom_spec(spec.clone())
            .testing_only_persist_unverified_canonical_snapshot(pending_state, pending_block),
        Err(PqRuntimeError::InvalidState(
            PqDevnetStateError::UnsupportedPendingDeposits
        ))
    ));

    let (state, mut signed_block) = signed_head(valid_state(&spec), &spec);
    let signed_root_before = signed_block.canonical_root();
    *signed_block.message_mut().state_root_mut() = Hash256::repeat_byte(0x99);
    let mismatched_root = signed_block.canonical_root();
    assert_ne!(mismatched_root, signed_root_before);
    assert!(matches!(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(spec.clone()))
            .custom_spec(spec)
            .testing_only_persist_unverified_canonical_snapshot(state, signed_block),
        Err(PqRuntimeError::HeadStateRootMismatch { .. })
    ));
}
