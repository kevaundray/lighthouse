use beacon_chain::{
    PqNewPayloadTransport, TestingPqAttestationPoolSnapshot,
    builder::{BeaconChainBuilder, Witness},
};
use consensus_signature::{AggregationError, AggregationService, PqPublicKey};
use operation_pool::{
    PqAttestationPoolInsertDisposition, PqAttestationPoolInsertInvariant,
    PqAttestationPoolResourceLimit, testing_only_classify_pq_attestation_pool_insert,
};
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use store::{HotColdDB, MemoryStore, StoreConfig};
use types::{ChainSpec, EthSpec, ForkName, Hash256, MinimalEthSpec, Slot};

type PoolWitness = Witness<TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

struct ValidExecution;

impl PqNewPayloadTransport<MinimalEthSpec> for ValidExecution {
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
        _current_slot: Slot,
        _head_block_root: Hash256,
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

fn exact_snapshot_store(
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

#[test]
fn pq_operation_pool_owns_exactly_one_chain_aggregation_coordinator() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        (1..=16)
            .map(|byte| state_processing::DirectGenesisValidator {
                public_key: PqPublicKey::deserialize(&[byte; 32])
                    .expect("canonical synthetic public key"),
                withdrawal_credentials: Hash256::ZERO,
            })
            .collect(),
        None,
        &spec,
    )
    .expect("direct PQ genesis");
    let aggregation_service =
        Arc::new(AggregationService::new().expect("one process aggregation service"));
    let chain = Arc::new(
        BeaconChainBuilder::<PoolWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(spec)
            .genesis_state(genesis)
            .expect("persist genesis")
            .pq_aggregation_service(Arc::clone(&aggregation_service))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(ValidExecution))
            .build()
            .expect("actual PQ BeaconChain"),
    );

    assert!(chain.testing_only_pq_attestation_pool_uses_aggregation_service(&aggregation_service));
    assert_eq!(
        chain.testing_only_pq_attestation_pool_snapshot(),
        TestingPqAttestationPoolSnapshot::default(),
    );
    assert!(matches!(
        AggregationService::new(),
        Err(AggregationError::AlreadyActive)
    ));
}

#[test]
fn ordinary_operation_pool_does_not_activate_attestation_aggregation() {
    let manifest = include_str!("../../../beacon_node/operation_pool/Cargo.toml");
    assert!(manifest.contains("default = [\"leveldb\"]"));
    assert!(manifest.contains("pq-devnet = ["));
    assert!(manifest.contains("\"dep:attestation_aggregation\""));
    assert!(manifest.contains(
        "attestation_aggregation = { workspace = true, optional = true, default-features = false }",
    ));

    let default_features = manifest
        .split("default = [")
        .nth(1)
        .and_then(|suffix| suffix.split(']').next())
        .expect("operation_pool default feature list");
    assert!(
        !default_features.contains("attestation_aggregation"),
        "ordinary operation_pool must not activate the PQ aggregation coordinator",
    );
}

#[test]
fn pq_attestation_pool_insert_classification_is_central_and_fail_closed() {
    use attestation_aggregation::InsertOutcome;

    for inserted in [
        InsertOutcome::Inserted {
            id: 7,
            removed_subsets: 0,
        },
        InsertOutcome::Inserted {
            id: 8,
            removed_subsets: 1,
        },
    ] {
        assert_eq!(
            testing_only_classify_pq_attestation_pool_insert(inserted),
            Ok(PqAttestationPoolInsertDisposition::Inserted {
                removed_subsets: match inserted {
                    InsertOutcome::Inserted {
                        removed_subsets, ..
                    } => removed_subsets,
                    _ => unreachable!("loop contains only inserted outcomes"),
                },
            }),
        );
    }
    assert_eq!(
        testing_only_classify_pq_attestation_pool_insert(InsertOutcome::Dominated),
        Ok(PqAttestationPoolInsertDisposition::Dominated),
    );
    for resource_limited in [
        InsertOutcome::CapacityExceeded,
        InsertOutcome::BucketCapacityExceeded {
            actual: 65,
            max: 64,
        },
        InsertOutcome::EvidenceCapacityExceeded {
            actual: 1_048_577,
            max: 1_048_576,
        },
    ] {
        assert_eq!(
            testing_only_classify_pq_attestation_pool_insert(resource_limited),
            Ok(PqAttestationPoolInsertDisposition::ResourceLimited(
                match resource_limited {
                    InsertOutcome::CapacityExceeded => {
                        PqAttestationPoolResourceLimit::Candidates
                    }
                    InsertOutcome::BucketCapacityExceeded { .. } => {
                        PqAttestationPoolResourceLimit::Buckets
                    }
                    InsertOutcome::EvidenceCapacityExceeded { .. } => {
                        PqAttestationPoolResourceLimit::Evidence
                    }
                    _ => unreachable!("loop contains only bounded resource outcomes"),
                },
            )),
        );
    }
    assert_eq!(
        testing_only_classify_pq_attestation_pool_insert(InsertOutcome::UnsupportedCandidate),
        Err(PqAttestationPoolInsertInvariant::UnsupportedCandidate),
    );
    assert_eq!(
        testing_only_classify_pq_attestation_pool_insert(InsertOutcome::GenerationExhausted),
        Err(PqAttestationPoolInsertInvariant::GenerationExhausted),
    );
}
