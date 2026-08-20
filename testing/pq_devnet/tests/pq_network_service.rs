use consensus_signature::IndividualSignature;
use network::{
    PQ_NETWORK_BLOCK_COMMIT_CAPACITY, PQ_NETWORK_BLOCK_ENCODING_CAPACITY,
    PQ_NETWORK_BLOCK_PROOF_CAPACITY, PqBlockBroadcastError, PqCommitCompletionQueueTestTrace,
    PqCommitResolutionTestCase, PqCompletionQueueTestScenario, PqCompletionQueueTestTrace,
    PqCompletionTestDisposition, PqCompletionTestEvent, PqEncodingShutdownTestTrace,
    PqNetworkServiceError, PqProofAdmissionTestTrace, PqStatusTestEvent, PqStatusTestScenario,
    PqStatusTestTrace, pq_block_broadcast_channel, testing_only_pq_commit_completion_queue,
    testing_only_pq_commit_resolution, testing_only_pq_completion_lifecycle,
    testing_only_pq_completion_queue, testing_only_pq_encoding_shutdown,
    testing_only_pq_proof_admission, testing_only_pq_status_lifecycle,
};
use std::sync::Arc;
use types::{
    BeaconBlock, EthSpec, ForkContext, ForkName, Hash256, MinimalEthSpec, SignedBeaconBlock,
};

#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PqNewPayloadTransport,
    builder::{BeaconChainBuilder, Witness},
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{AggregationService, PqPublicKey};
#[cfg(target_feature = "avx2")]
use lighthouse_network::{Context, NetworkConfig, identity::secp256k1};
#[cfg(target_feature = "avx2")]
use network::PqNetworkService;
#[cfg(target_feature = "avx2")]
use network_utils::enr_ext::EnrExt;
#[cfg(target_feature = "avx2")]
use ssz::Encode;
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
#[cfg(target_feature = "avx2")]
use types::ChainSpec;

#[test]
fn pq_network_service_has_the_frozen_bounded_proof_contract() {
    assert_eq!(PQ_NETWORK_BLOCK_PROOF_CAPACITY, 2);
    assert_eq!(PQ_NETWORK_BLOCK_ENCODING_CAPACITY, 2);
    assert_eq!(PQ_NETWORK_BLOCK_COMMIT_CAPACITY, 2);
}

#[test]
fn detached_commit_resolution_releases_only_exact_retryable_commit_failures() {
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::Success,
    ));
    assert!(testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::BlockingTask,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::ParentUnavailable,
    ));
    assert!(!testing_only_pq_commit_resolution(
        PqCommitResolutionTestCase::TerminalObservation,
    ));
}

#[test]
fn detached_commit_completion_queue_is_exactly_bounded_and_raii_on_shutdown() {
    assert_eq!(
        testing_only_pq_commit_completion_queue(),
        PqCommitCompletionQueueTestTrace {
            admitted: vec![true, true, false],
            dropped_after_overflow: 1,
            dropped_after_shutdown: 3,
        },
    );
}

#[test]
fn pq_network_construction_error_preserves_lower_detail() {
    assert_eq!(
        PqNetworkServiceError::Construction("lower network detail".into()).to_string(),
        "could not construct the PQ libp2p service: lower network detail",
    );
}

#[test]
fn accept_is_reported_before_propagation_promotion_and_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Accept {
            report_succeeded: true,
        }),
        vec![
            PqCompletionTestEvent::ReportedAccept,
            PqCompletionTestEvent::PromotedAfterPropagation,
            PqCompletionTestEvent::CommitSpawned,
        ]
    );
}

#[test]
fn failed_accept_report_drops_propagation_capability_without_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Accept {
            report_succeeded: false,
        }),
        vec![
            PqCompletionTestEvent::ReportedAccept,
            PqCompletionTestEvent::PropagationCapabilityDropped,
        ]
    );
}

#[test]
fn retry_is_ignored_for_gossip_then_committed_without_repropagation() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Retry),
        vec![
            PqCompletionTestEvent::ReportedCommitWithoutPropagation,
            PqCompletionTestEvent::CommitSpawned,
        ]
    );
}

#[test]
fn reject_reports_reject_and_penalizes_without_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Reject),
        vec![
            PqCompletionTestEvent::ReportedReject,
            PqCompletionTestEvent::PeerPenalized,
        ]
    );
}

#[test]
fn ignore_reports_ignore_without_penalty_or_commit() {
    assert_eq!(
        testing_only_pq_completion_lifecycle(PqCompletionTestDisposition::Ignore),
        vec![PqCompletionTestEvent::ReportedRetryableIgnore]
    );
}

#[test]
fn proof_admission_is_nonwaiting_and_recovers_after_raii_drop() {
    assert_eq!(
        testing_only_pq_proof_admission(),
        PqProofAdmissionTestTrace {
            admitted: vec![true, true, false],
            proofs_started: 2,
            admitted_after_drop: true,
        }
    );
}

#[test]
fn full_completion_queue_drops_token_and_releases_permit() {
    assert_eq!(
        testing_only_pq_completion_queue(PqCompletionQueueTestScenario::Full),
        PqCompletionQueueTestTrace {
            dropped_after_send: 1,
            available_after_send: 1,
            dropped_after_receiver_drop: 2,
            available_after_receiver_drop: 2,
        }
    );
}

#[test]
fn closed_completion_queue_drops_token_and_releases_permit() {
    assert_eq!(
        testing_only_pq_completion_queue(PqCompletionQueueTestScenario::Closed),
        PqCompletionQueueTestTrace {
            dropped_after_send: 1,
            available_after_send: 2,
            dropped_after_receiver_drop: 1,
            available_after_receiver_drop: 2,
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn pending_broadcast_ack_reports_worker_unavailable_when_owner_drops() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    ));
    let (sender, receiver) = pq_block_broadcast_channel();
    let acknowledgement = sender.try_send(block).expect("bounded broadcast ingress");
    drop(receiver);
    assert_eq!(
        acknowledgement.wait().await,
        Err(PqBlockBroadcastError::WorkerUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn encoded_completion_after_owner_shutdown_releases_ack_and_permit() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    ));
    assert_eq!(
        testing_only_pq_encoding_shutdown(block, [8; 4]).await,
        PqEncodingShutdownTestTrace {
            acknowledgement: Err(PqBlockBroadcastError::WorkerUnavailable),
            available_permits: PQ_NETWORK_BLOCK_ENCODING_CAPACITY,
        }
    );
}

#[test]
fn pq_rpc_profile_advertises_only_status_and_control_protocols() {
    let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
    let fork_context = Arc::new(ForkContext::new::<MinimalEthSpec>(
        spec.genesis_slot,
        Hash256::ZERO,
        &spec,
    ));
    let pq = lighthouse_network::rpc::testing_only_pq_rpc_protocols(Arc::clone(&fork_context));
    assert_eq!(
        pq,
        vec![
            "/eth2/beacon_chain/req/status/2/ssz_snappy",
            "/eth2/beacon_chain/req/status/1/ssz_snappy",
            "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            "/eth2/beacon_chain/req/metadata/2/ssz_snappy",
            "/eth2/beacon_chain/req/metadata/1/ssz_snappy",
        ]
    );

    let full = lighthouse_network::rpc::testing_only_full_rpc_protocols(fork_context);
    assert!(
        full.iter()
            .any(|protocol| protocol.contains("beacon_blocks_by_range")),
        "ordinary construction must retain the full RPC profile",
    );
    assert!(full.len() > pq.len());
}

#[test]
fn mismatched_status_fork_disconnects_without_starting_block_verification() {
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::ForkDigestMismatch),
        PqStatusTestTrace {
            events: vec![PqStatusTestEvent::DisconnectedIrrelevantNetwork],
            block_verifications_started: 0,
        }
    );
}

#[test]
fn mismatched_status_finalized_fields_disconnect_without_starting_block_verification() {
    for scenario in [
        PqStatusTestScenario::FinalizedEpochMismatch,
        PqStatusTestScenario::FinalizedRootMismatch,
    ] {
        assert_eq!(
            testing_only_pq_status_lifecycle(scenario),
            PqStatusTestTrace {
                events: vec![PqStatusTestEvent::DisconnectedIrrelevantNetwork],
                block_verifications_started: 0,
            }
        );
    }
}

#[test]
fn compatible_status_marks_peer_and_seventeenth_disconnects_without_verification() {
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::Compatible),
        PqStatusTestTrace {
            events: vec![PqStatusTestEvent::MarkedCompatible],
            block_verifications_started: 0,
        }
    );
    assert_eq!(
        testing_only_pq_status_lifecycle(PqStatusTestScenario::CompatibleCapacityFull),
        PqStatusTestTrace {
            events: vec![PqStatusTestEvent::DisconnectedTooManyPeers],
            block_verifications_started: 0,
        }
    );
}

#[cfg(target_feature = "avx2")]
type TestWitness = Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[cfg(target_feature = "avx2")]
struct UnusedValidTransport;

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for UnusedValidTransport {
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
}

#[cfg(target_feature = "avx2")]
fn exact_snapshot_store(
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

#[cfg(target_feature = "avx2")]
fn build_chain(
    runtime: &task_executor::test_utils::TestRuntime,
) -> (Arc<beacon_chain::BeaconChain<TestWitness>>, Arc<ChainSpec>) {
    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
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
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis)
            .expect("persist genesis")
            .pq_aggregation_service(Arc::new(
                AggregationService::new().expect("PQ aggregation service"),
            ))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(UnusedValidTransport))
            .build()
            .expect("PQ chain"),
    );
    (chain, spec)
}

#[cfg(target_feature = "avx2")]
async fn start_network_service(
    runtime: &task_executor::test_utils::TestRuntime,
    chain: Arc<beacon_chain::BeaconChain<TestWitness>>,
    spec: Arc<ChainSpec>,
    boot_nodes: Vec<lighthouse_network::Enr>,
    disable_discovery: bool,
    encoding_hook: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (
    network::PqBlockBroadcastSender<MinimalEthSpec>,
    Arc<lighthouse_network::NetworkGlobals<MinimalEthSpec>>,
    tokio::sync::mpsc::Sender<lighthouse_network::Multiaddr>,
    Arc<lighthouse_network::PqGossipValidationAdmission>,
) {
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.boot_nodes_enr = boot_nodes;
    network_config.disable_discovery = disable_discovery;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let network_config = Arc::new(network_config);
    let context = Context {
        config: network_config,
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let mut service = PqNetworkService::new(
        runtime.task_executor.clone(),
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
    )
    .await
    .expect("PQ network service");
    if let Some(hook) = encoding_hook {
        service.testing_only_set_block_encoding_hook(hook);
    }
    let globals = service.network_globals();
    let dial_sender = service.testing_only_dial_sender();
    let gossip_admission = service.testing_only_gossip_admission();
    service.start().expect("start PQ network service");
    (broadcast_sender, globals, dial_sender, gossip_admission)
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_confirms_owner_shutdown() {
    use std::sync::{Condvar, Mutex};

    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let (lock, condition) = &*self.0;
            *lock.lock().expect("release lock") = true;
            condition.notify_all();
        }
    }

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let block = Arc::clone(&head.beacon_block);
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: spec,
        libp2p_registry: None,
    };
    let (broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let (network_runtime_owner, network_exit) = async_channel::bounded(1);
    let (network_shutdown_sender, _) = futures::channel::mpsc::channel(1);
    let network_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        network_exit,
        network_shutdown_sender,
    );
    let mut service = PqNetworkService::new(
        network_executor,
        context,
        MinimalEthSpec::default_spec().custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
    )
    .await
    .expect("PQ network service");
    assert!(
        service
            .testing_only_gossip_admission()
            .try_add_compatible(lighthouse_network::PeerId::random())
    );
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let _release_on_drop = ReleaseOnDrop(Arc::clone(&release));
    let (entered_sender, mut entered_receiver) = tokio::sync::mpsc::unbounded_channel();
    let hook = {
        let release = Arc::clone(&release);
        Arc::new(move || {
            entered_sender.send(()).expect("shutdown test alive");
            let (lock, condition) = &*release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    service.testing_only_set_block_encoding_hook(hook);

    let shutdown = service
        .start_with_shutdown_receipt()
        .await
        .expect("result-bearing network start");
    let retained_sender = broadcast_sender.clone();
    let pending = broadcast_sender
        .try_send(Arc::clone(&block))
        .expect("bounded pending broadcast");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("encoding hook entered")
        .expect("encoding hook signal");
    let mut shutdown_task = tokio::spawn(shutdown.testing_only_wait_for_exit());
    drop(network_runtime_owner);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut shutdown_task)
            .await
            .is_err(),
        "shutdown must retain the in-flight encoder owner",
    );
    assert!(matches!(
        AggregationService::new(),
        Err(consensus_signature::AggregationError::AlreadyActive),
    ));
    {
        let (lock, condition) = &*release;
        *lock.lock().expect("release lock") = true;
        condition.notify_all();
    }
    assert_eq!(
        pending.wait().await,
        Err(PqBlockBroadcastError::WorkerUnavailable),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_task)
        .await
        .expect("network owner shutdown")
        .expect("shutdown task")
        .expect("network worker result");
    assert!(matches!(
        retained_sender.try_send(block),
        Err(PqBlockBroadcastError::WorkerUnavailable),
    ));
    drop(AggregationService::new().expect("aggregation owner released after drain"));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_rejects_executor_shutdown_before_first_poll() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (runtime_owner, exit) = async_channel::bounded(1);
    let (shutdown_sender, _) = futures::channel::mpsc::channel(1);
    let shutting_down_executor =
        task_executor::TaskExecutor::new(tokio::runtime::Handle::current(), exit, shutdown_sender);
    let (_broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let service = PqNetworkService::new(
        shutting_down_executor,
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
    )
    .await
    .expect("PQ network service");
    drop(runtime_owner);

    assert!(matches!(
        service.start_with_shutdown_receipt().await,
        Err(PqNetworkServiceError::TaskUnavailable),
    ));
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn result_bearing_network_start_reports_worker_panic_through_task_executor() {
    use futures::StreamExt;

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let head = chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(std::net::Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(std::net::Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = tempfile::TempDir::new().expect("network directory").keep();
    let context = Context {
        config: Arc::new(network_config),
        enr_fork_id: spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &spec,
        )),
        chain_spec: Arc::clone(&spec),
        libp2p_registry: None,
    };
    let (_runtime_owner, exit) = async_channel::bounded(1);
    let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
    let monitored_executor =
        task_executor::TaskExecutor::new(tokio::runtime::Handle::current(), exit, shutdown_sender);
    let (_broadcast_sender, broadcast_receiver) = pq_block_broadcast_channel();
    let mut service = PqNetworkService::new(
        monitored_executor,
        context,
        spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        chain,
        broadcast_receiver,
    )
    .await
    .expect("PQ network service");
    service.testing_only_set_run_hook(Arc::new(|| panic!("PQ network worker panic")));

    assert!(matches!(
        service.start_with_shutdown_receipt().await,
        Err(PqNetworkServiceError::TaskUnavailable),
    ));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), shutdown_receiver.next())
            .await
            .expect("panic monitor notification"),
        Some(task_executor::ShutdownReason::Failure(
            "Panic (fatal error)"
        )),
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn live_worker_negatively_acknowledges_exact_block_without_peers() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let genesis_root = chain.head_snapshot().beacon_block_root;
    let (sender, _globals, _dial_sender, gossip_admission) = start_network_service(
        &runtime,
        Arc::clone(&chain),
        Arc::clone(&spec),
        vec![],
        true,
        None,
    )
    .await;
    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&spec),
        IndividualSignature::empty(),
    ));
    let acknowledgement = sender.try_send(block).expect("bounded broadcast ingress");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), acknowledgement.wait())
            .await
            .expect("worker acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
    );
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(gossip_admission.testing_only_active_total(), 0);
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn live_workers_status_and_acknowledge_publish_and_exact_duplicate() {
    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let (_receiver_sender, receiver_globals, _receiver_dial, _receiver_admission) =
        start_network_service(
            &runtime,
            Arc::clone(&chain),
            Arc::clone(&spec),
            vec![],
            false,
            None,
        )
        .await;
    let receiver_address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");
    let (sender, sender_globals, sender_dial, sender_admission) =
        start_network_service(&runtime, chain, Arc::clone(&spec), vec![], true, None).await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0 || receiver_globals.connected_peers() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ status-compatible peers connect");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !sender_admission.has_compatible_peers() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outbound Status response marks the receiver compatible");

    let block = Arc::new(SignedBeaconBlock::from_block(
        BeaconBlock::empty(&spec),
        IndividualSignature::empty(),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let acknowledgement = sender
                .try_send(Arc::clone(&block))
                .expect("bounded broadcast ingress");
            if acknowledgement.wait().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("initial publication must become publishable after topic subscription");

    let acknowledgement = sender
        .try_send(Arc::clone(&block))
        .expect("bounded broadcast ingress");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), acknowledgement.wait())
            .await
            .expect("exact duplicate acknowledgement"),
        Ok(()),
        "exact duplicate must be positively acknowledged",
    );
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn block_encoding_is_cap_two_offloop_and_poll_loop_remains_responsive() {
    use std::sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    let runtime = task_executor::test_utils::TestRuntime::default();
    let (chain, spec) = build_chain(&runtime);
    let (_receiver_sender, receiver_globals, _receiver_dial, _receiver_admission) =
        start_network_service(
            &runtime,
            Arc::clone(&chain),
            Arc::clone(&spec),
            vec![],
            false,
            None,
        )
        .await;
    let receiver_address = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let enr = receiver_globals.local_enr();
            if let Some(address) = enr.multiaddr_p2p_tcp().into_iter().next() {
                break address;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receiver listening ENR");

    let armed = Arc::new(AtomicBool::new(false));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_sender, mut entered_receiver) = tokio::sync::mpsc::unbounded_channel();
    let hook = {
        let armed = Arc::clone(&armed);
        let release = Arc::clone(&release);
        Arc::new(move || {
            if !armed.load(Ordering::SeqCst) {
                return;
            }
            entered_sender.send(()).expect("test observer alive");
            let (lock, condition) = &*release;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = condition.wait(released).expect("release wait");
            }
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let (sender, sender_globals, sender_dial, sender_admission) =
        start_network_service(&runtime, chain, Arc::clone(&spec), vec![], true, Some(hook)).await;
    sender_dial
        .try_send(receiver_address)
        .expect("bounded testing dial command");
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while sender_globals.connected_peers() == 0 || receiver_globals.connected_peers() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("PQ workers connect");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !sender_admission.has_compatible_peers() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outbound Status response marks the receiver compatible");

    let mut unsigned = BeaconBlock::<MinimalEthSpec>::empty(&spec);
    match unsigned.body_mut() {
        types::BeaconBlockBodyRefMut::Electra(body) => body
            .execution_payload
            .execution_payload
            .transactions
            .push(
                vec![0x5a; 2_000_000]
                    .try_into()
                    .expect("bounded transaction"),
            )
            .expect("transaction capacity"),
        _ => panic!("expected Electra body"),
    }
    let block = Arc::new(SignedBeaconBlock::from_block(
        unsigned,
        IndividualSignature::empty(),
    ));
    assert!(
        block.as_ssz_bytes().len() > 1_000_000,
        "fixture must exercise a large PQ evidence body",
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let acknowledgement = sender
                .try_send(Arc::clone(&block))
                .expect("bounded broadcast ingress");
            if acknowledgement.wait().await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("status and subscription become publishable");

    armed.store(true, Ordering::SeqCst);
    let first = sender
        .try_send(Arc::clone(&block))
        .expect("first encoding admission");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("first encoder enters")
        .expect("first encoder observer");
    let second = sender
        .try_send(Arc::clone(&block))
        .expect("second encoding admission");
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_receiver.recv())
        .await
        .expect("second encoder enters while the first is blocked")
        .expect("second encoder observer");
    let third = sender
        .try_send(Arc::clone(&block))
        .expect("broadcast queue remains responsive");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), third.wait())
            .await
            .expect("cap+1 acknowledgement while encoders are blocked"),
        Err(PqBlockBroadcastError::Capacity),
    );

    sender_admission.remove_compatible(&receiver_globals.local_enr().peer_id());
    let (lock, condition) = &*release;
    *lock.lock().expect("release lock") = true;
    condition.notify_all();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), first.wait())
            .await
            .expect("first acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
        "a peer lost after encoding started must prevent lower publication",
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), second.wait())
            .await
            .expect("second acknowledgement"),
        Err(PqBlockBroadcastError::Rejected),
    );
}
