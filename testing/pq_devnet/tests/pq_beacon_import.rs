use beacon_chain::{
    PQ_BLOCK_IMPORT_ADMISSION_CAPACITY, PQ_FORWARD_RANGE_BLOCK_CAPACITY, PqBlockImportSource,
    PqEnginePayloadDisposition, PqEnginePayloadStatus, PqImportError, PqImportLocalError,
    PqImportPeerInvalid, TestingPqExternalReservation, TestingPqGossipClaim, TestingPqGossipFinish,
    TestingPqGossipObservationCache, classify_pq_engine_payload_status,
};
#[cfg(target_feature = "avx2")]
use beacon_chain::{
    PqNewPayloadTransport, TestingPqBlockingHook,
    builder::{BeaconChainBuilder, Witness},
};
#[cfg(target_feature = "avx2")]
use consensus_signature::{AggregationService, OneTimeUseId, PqPublicKey, SigningDuty};
#[cfg(target_feature = "avx2")]
use network::{PqGossipBlockDisposition, PqNetworkBlockProcessor};
#[cfg(target_feature = "avx2")]
use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
#[cfg(target_feature = "avx2")]
use std::sync::Arc;
#[cfg(target_feature = "avx2")]
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
#[cfg(target_feature = "avx2")]
use store::{HotColdDB, MemoryStore, StoreConfig};
#[cfg(target_feature = "avx2")]
use types::EthSpec;
#[cfg(target_feature = "avx2")]
use types::SignedBeaconBlock;
#[cfg(target_feature = "avx2")]
use types::{
    BeaconBlock, ChainSpec, Domain, ExecutionPayloadRef, ForkName, MinimalEthSpec, SignedRoot,
};
use types::{Hash256, Slot};

#[test]
fn every_external_block_source_uses_the_same_import_boundary() {
    assert_eq!(
        PqBlockImportSource::ALL,
        [
            PqBlockImportSource::Gossip,
            PqBlockImportSource::Rpc,
            PqBlockImportSource::Lookup,
            PqBlockImportSource::ForwardRange,
        ]
    );
}

#[test]
fn peer_invalid_and_local_failures_have_stable_scoring_and_retry_policy() {
    let peer_error = PqImportError::PeerInvalid(PqImportPeerInvalid::NonLinearRange {
        expected: Hash256::repeat_byte(1),
        actual: Hash256::repeat_byte(2),
    });
    assert!(peer_error.should_penalize_peer());
    assert!(!peer_error.is_retryable());

    let unavailable_parent = PqImportError::Local(PqImportLocalError::ParentUnavailable {
        parent_root: Hash256::repeat_byte(3),
    });
    assert!(!unavailable_parent.should_penalize_peer());
    assert!(unavailable_parent.is_retryable());

    let saturated = PqImportError::Local(PqImportLocalError::IngressCapacity);
    assert!(!saturated.should_penalize_peer());
    assert!(saturated.is_retryable());

    let stale = PqImportError::StaleHeadAfterVerification {
        expected_parent: Hash256::repeat_byte(4),
        actual_head: Hash256::repeat_byte(5),
    };
    assert!(!stale.should_penalize_peer());
    assert!(!stale.is_retryable());
    assert_eq!(PQ_BLOCK_IMPORT_ADMISSION_CAPACITY, 2);
    assert_eq!(PQ_FORWARD_RANGE_BLOCK_CAPACITY, 8);
}

#[test]
fn engine_payload_status_retains_valid_and_syncing_outcomes() {
    assert!(!PqEnginePayloadStatus::Valid.would_require_optimistic_import());
    assert!(PqEnginePayloadStatus::Syncing.would_require_optimistic_import());
}

#[test]
fn real_engine_responses_have_typed_commit_retry_and_reject_mapping() {
    use execution_layer::PayloadStatus;

    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Valid),
        PqEnginePayloadDisposition::CommitValid
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Syncing),
        PqEnginePayloadDisposition::Retry(PqEnginePayloadStatus::Syncing)
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Accepted),
        PqEnginePayloadDisposition::Retry(PqEnginePayloadStatus::Syncing)
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::Invalid {
            latest_valid_hash: None,
            validation_error: Some("invalid payload".to_owned()),
        }),
        PqEnginePayloadDisposition::Reject
    );
    assert_eq!(
        classify_pq_engine_payload_status(&PayloadStatus::InvalidBlockHash {
            validation_error: Some("bad hash".to_owned()),
        }),
        PqEnginePayloadDisposition::Reject
    );

    let rejected = PqImportError::ExecutionRejected(PayloadStatus::InvalidBlockHash {
        validation_error: None,
    });
    assert!(!rejected.should_penalize_peer());
    assert!(!rejected.is_retryable());
    let transport = PqImportError::Local(PqImportLocalError::Transport(
        execution_layer::Error::NoEngine,
    ));
    assert!(!transport.should_penalize_peer());
    assert!(transport.is_retryable());
}

#[test]
fn slot_ordering_is_a_peer_invalid_error() {
    let error = PqImportError::PeerInvalid(PqImportPeerInvalid::NonAdvancingSlot {
        parent: Slot::new(7),
        block: Slot::new(7),
    });
    assert!(error.should_penalize_peer());
}

#[test]
fn gossip_claim_lifecycle_blocks_pending_duplicates_and_terminal_retries() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(1);
    let root = Hash256::repeat_byte(1);
    let first = cache.claim(slot, 3, root, Slot::new(0));
    let TestingPqGossipClaim::Propagate(first_generation) = first else {
        panic!("first fully verified gossip block must own propagation")
    };
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Pending
    );
    assert!(cache.mark_propagated(slot, 3, first_generation));
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Pending
    );
    assert!(cache.cancel(slot, 3, first_generation));
    let TestingPqGossipClaim::Retry(retry_generation) = cache.claim(slot, 3, root, Slot::new(0))
    else {
        panic!("a dropped claim must become retryable")
    };
    assert_ne!(first_generation, retry_generation);
    assert!(cache.finish(slot, 3, retry_generation, TestingPqGossipFinish::Terminal));
    assert_eq!(
        cache.claim(slot, 3, root, Slot::new(0)),
        TestingPqGossipClaim::Terminal
    );
    assert_eq!(
        cache.claim(slot, 3, Hash256::repeat_byte(2), Slot::new(0)),
        TestingPqGossipClaim::Equivocation(root)
    );
}

#[test]
fn gossip_claim_lifecycle_retries_only_after_retryable_completion() {
    let mut cache = TestingPqGossipObservationCache::default();
    let dropped_slot = Slot::new(3);
    let dropped_root = Hash256::repeat_byte(3);
    let TestingPqGossipClaim::Propagate(dropped_generation) =
        cache.claim(dropped_slot, 1, dropped_root, Slot::new(2))
    else {
        panic!("initial propagation claim")
    };
    assert!(cache.cancel(dropped_slot, 1, dropped_generation));
    assert!(matches!(
        cache.claim(dropped_slot, 1, dropped_root, Slot::new(2)),
        TestingPqGossipClaim::Propagate(_)
    ));

    let slot = Slot::new(4);
    let root = Hash256::repeat_byte(4);
    let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, 2, root, Slot::new(3))
    else {
        panic!("propagation claim")
    };
    assert!(cache.mark_propagated(slot, 2, generation));
    assert!(cache.finish(slot, 2, generation, TestingPqGossipFinish::Retryable));
    let TestingPqGossipClaim::Retry(retry_generation) = cache.claim(slot, 2, root, Slot::new(3))
    else {
        panic!("retry claim")
    };
    assert!(cache.finish(slot, 2, retry_generation, TestingPqGossipFinish::Committed));
    cache.prune_after_commit(slot);
    assert_eq!(
        cache.claim(slot, 2, root, slot),
        TestingPqGossipClaim::Terminal
    );
    assert_eq!(cache.len(), 1, "the current committed record is retained");
}

#[test]
fn gossip_claim_cache_prunes_long_chains_and_bounds_failed_entries() {
    let mut cache = TestingPqGossipObservationCache::default();
    let capacity_u64 =
        u64::try_from(TestingPqGossipObservationCache::CAPACITY).expect("capacity fits u64");
    let long_chain_end = capacity_u64.checked_mul(3).expect("small test bound");
    for slot_u64 in 1..=long_chain_end {
        let slot = Slot::new(slot_u64);
        let proposer = slot_u64 % 16;
        let root = Hash256::with_last_byte(
            u8::try_from(slot_u64 % 251).expect("remainder fits in one byte"),
        );
        let TestingPqGossipClaim::Propagate(generation) =
            cache.claim(slot, proposer, root, Slot::new(slot_u64 - 1))
        else {
            panic!("linear propagation claim")
        };
        assert!(cache.mark_propagated(slot, proposer, generation));
        assert!(cache.finish(slot, proposer, generation, TestingPqGossipFinish::Committed));
        cache.prune_after_commit(slot);
        assert_eq!(cache.len(), 1);
    }

    let head = Slot::new(long_chain_end);
    for offset in 1..TestingPqGossipObservationCache::CAPACITY {
        let offset_u64 = u64::try_from(offset).expect("offset fits u64");
        let slot = Slot::new(
            long_chain_end
                .checked_add(offset_u64)
                .expect("small test slot"),
        );
        let proposer = offset_u64 % 16;
        let root = Hash256::with_last_byte(
            u8::try_from(offset_u64 % 251).expect("remainder fits in one byte"),
        );
        let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, proposer, root, head)
        else {
            panic!("failed-entry propagation claim")
        };
        assert!(cache.mark_propagated(slot, proposer, generation));
        assert!(cache.finish(
            slot,
            proposer,
            generation,
            if offset % 2 == 0 {
                TestingPqGossipFinish::Retryable
            } else {
                TestingPqGossipFinish::Terminal
            }
        ));
    }
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    assert_eq!(
        cache.claim(
            Slot::new(long_chain_end.checked_add(10_000).expect("small test slot")),
            0,
            Hash256::repeat_byte(252),
            head,
        ),
        TestingPqGossipClaim::Capacity
    );
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    let retained_root = Hash256::with_last_byte(
        u8::try_from(long_chain_end % 251).expect("remainder fits in one byte"),
    );
    assert_eq!(
        cache.reserve_external(
            Slot::new(long_chain_end.checked_add(20_000).expect("small test slot")),
            0,
            Hash256::repeat_byte(253),
            head,
        ),
        TestingPqExternalReservation::Capacity,
    );
    assert_eq!(cache.len(), TestingPqGossipObservationCache::CAPACITY);
    assert_eq!(
        cache.claim(head, long_chain_end % 16, retained_root, head),
        TestingPqGossipClaim::Terminal,
        "capacity eviction must preserve the retained current-head record"
    );
}

#[test]
fn cross_source_equivocation_leaves_the_first_pending_root_authorized() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(8);
    let first_gossip_root = Hash256::repeat_byte(8);
    let external_equivocation = Hash256::repeat_byte(9);

    let TestingPqGossipClaim::Propagate(first_generation) =
        cache.claim(slot, 4, first_gossip_root, Slot::new(7))
    else {
        panic!("first gossip propagation claim")
    };
    assert!(cache.mark_propagated(slot, 4, first_generation));
    assert_eq!(
        cache.reserve_external(slot, 4, external_equivocation, Slot::new(7)),
        TestingPqExternalReservation::Equivocation(first_gossip_root)
    );
    assert!(cache.authorize_commit(slot, 4, first_gossip_root, first_generation));

    let mut same_root = TestingPqGossipObservationCache::default();
    let TestingPqGossipClaim::Propagate(generation) =
        same_root.claim(slot, 4, first_gossip_root, Slot::new(7))
    else {
        panic!("same-root propagation claim")
    };
    same_root.record_commit(slot, 4, first_gossip_root);
    assert!(!same_root.mark_propagated(slot, 4, generation));
    assert_eq!(
        same_root.claim(slot, 4, first_gossip_root, slot),
        TestingPqGossipClaim::Terminal
    );
}

#[test]
fn cross_source_engine_rejection_invalidates_a_queued_exact_generation() {
    let mut cache = TestingPqGossipObservationCache::default();
    let slot = Slot::new(9);
    let root = Hash256::repeat_byte(9);
    let TestingPqGossipClaim::Propagate(generation) = cache.claim(slot, 5, root, Slot::new(8))
    else {
        panic!("propagation claim")
    };
    assert!(cache.mark_propagated(slot, 5, generation));
    assert!(cache.authorize_commit(slot, 5, root, generation));

    cache.record_terminal(slot, 5, root);
    assert!(!cache.authorize_commit(slot, 5, root, generation));
    assert_eq!(
        cache.claim(slot, 5, root, Slot::new(8)),
        TestingPqGossipClaim::Terminal
    );
}

#[cfg(target_feature = "avx2")]
const PASSWORD: &[u8] = b"correct horse battery staple";

#[cfg(target_feature = "avx2")]
type TestWitness = Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

#[cfg(target_feature = "avx2")]
struct RecordingTransport {
    calls: Mutex<Vec<Hash256>>,
    responses: Mutex<VecDeque<Result<execution_layer::PayloadStatus, execution_layer::Error>>>,
}

#[cfg(target_feature = "avx2")]
impl RecordingTransport {
    fn always_valid() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([Ok(execution_layer::PayloadStatus::Valid)])),
        }
    }

    fn syncing_then_valid() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([
                Ok(execution_layer::PayloadStatus::Syncing),
                Ok(execution_layer::PayloadStatus::Valid),
                Ok(execution_layer::PayloadStatus::Valid),
            ])),
        }
    }

    fn invalid_block_hash() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from([Ok(
                execution_layer::PayloadStatus::InvalidBlockHash {
                    validation_error: Some("fixture rejection".to_owned()),
                },
            )])),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for RecordingTransport {
    fn notify_new_payload<'a>(
        &'a self,
        request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                > + Send
                + 'a,
        >,
    > {
        self.calls
            .lock()
            .expect("recording transport calls lock")
            .push(request.block_hash().into_root());
        let response = self
            .responses
            .lock()
            .expect("recording transport responses lock")
            .pop_front()
            .unwrap_or(Err(execution_layer::Error::Unexpected(
                "missing fixture response".to_owned(),
            )));
        Box::pin(async move { response })
    }
}

#[cfg(target_feature = "avx2")]
struct StallingTransport {
    calls: AtomicUsize,
    release: tokio::sync::Semaphore,
}

#[cfg(target_feature = "avx2")]
impl StallingTransport {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[cfg(target_feature = "avx2")]
impl PqNewPayloadTransport<MinimalEthSpec> for StallingTransport {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let permit = self.release.acquire().await.map_err(|_| {
                execution_layer::Error::Unexpected("stalling test transport closed".to_owned())
            })?;
            permit.forget();
            Ok(execution_layer::PayloadStatus::Valid)
        })
    }
}

#[cfg(target_feature = "avx2")]
fn electra_spec() -> ChainSpec {
    ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(17_000)
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
async fn wait_for_test_condition(mut condition: impl FnMut() -> bool, description: &str) {
    for _ in 0..100_000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting for {description}");
}

#[cfg(target_feature = "avx2")]
#[tokio::test(flavor = "current_thread")]
async fn full_gossip_verification_precedes_observation_engine_commit_and_restart() {
    let test_runtime = task_executor::test_utils::TestRuntime::default();
    let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let spec = Arc::new(electra_spec());
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
    let proposer_index = genesis
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let maximum_leaf = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
        .expect("slot-one proposal leaf")
        .as_u32();
    let keystore =
        PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD).expect("fixture keystore");
    let authenticated = keystore.authenticate(PASSWORD).expect("authenticated key");
    genesis
        .validators_mut()
        .get_mut(proposer_index)
        .expect("proposer validator")
        .pubkey = *authenticated.public_key();
    let genesis_validators_root = genesis.genesis_validators_root().0;
    provision_usage_journal(&journal_path, genesis_validators_root, &[authenticated])
        .expect("usage journal");
    let authority = PqSigningAuthority::open(
        &journal_path,
        genesis_validators_root,
        vec![PqKeyUnlock::new(keystore, PASSWORD).expect("unlock")],
    )
    .expect("signing authority");
    let store = exact_snapshot_store(Arc::clone(&spec));
    let service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
    let transport = Arc::new(RecordingTransport::syncing_then_valid());
    let chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(transport.clone())
            .build()
            .expect("PQ chain"),
    );
    let processor = PqNetworkBlockProcessor::new(Arc::clone(&chain));
    let genesis_root = chain.head_snapshot().beacon_block_root;

    let mut pre_state = genesis.clone();
    state_processing::per_slot_processing_pq(&mut pre_state, &spec)
        .expect("advance exact parent state");
    let sign = |duty: SigningDuty, signing_root: [u8; 32]| {
        let public_key = pre_state
            .validators()
            .get(proposer_index)
            .expect("proposer validator")
            .pubkey;
        authority
            .signer(&public_key)
            .expect("bound signer")
            .sign(consensus_signature::pq::PqSigningClaim::new(
                signing_root,
                OneTimeUseId::for_lean_pq_devnet_v1(1, duty).expect("V1 leaf"),
            ))
            .expect("journal-backed signature")
    };
    let randao_domain = spec.get_domain(
        pre_state.current_epoch(),
        Domain::Randao,
        &pre_state.fork(),
        pre_state.genesis_validators_root(),
    );
    let randao_signature = sign(
        SigningDuty::RandaoReveal,
        pre_state.current_epoch().signing_root(randao_domain).0,
    );
    let verified_randao = state_processing::prepare_pq_randao(
        &pre_state,
        Arc::clone(&chain.pq_validator_key_cache),
        Slot::new(1),
        randao_signature.clone(),
        Arc::clone(&spec),
    )
    .expect("prepared RANDAO")
    .verify(&service)
    .await
    .expect("verified RANDAO");

    let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(inner) = &mut block else {
        panic!("Electra fixture")
    };
    inner.slot = Slot::new(1);
    inner.proposer_index = proposer_index as u64;
    inner.parent_root = genesis_root;
    inner.body.randao_reveal = randao_signature;
    inner.body.execution_payload.execution_payload.timestamp = pre_state
        .genesis_time()
        .checked_add(spec.get_slot_duration().as_secs())
        .expect("slot-one timestamp");
    inner.body.execution_payload.execution_payload.prev_randao = *pre_state
        .get_randao_mix(pre_state.current_epoch())
        .expect("current RANDAO mix");
    let execution_block_hash = execution_layer::calculate_execution_block_hash(
        ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
        Some(inner.parent_root),
        Some(&inner.body.execution_requests),
    )
    .0;
    inner.body.execution_payload.execution_payload.block_hash = execution_block_hash;

    let local =
        state_processing::prepare_pq_local_block(&pre_state, block, verified_randao, vec![])
            .expect("sealed local block");
    let mut local_state = pre_state.clone();
    let local_output = state_processing::per_block_processing_pq_local(&mut local_state, local)
        .expect("local transition");
    let (mut block, _) = local_output.into_parts();
    let state_root = local_state.canonical_root().expect("post-state root");
    *block.state_root_mut() = state_root;
    let proposal_domain = spec.get_domain(
        pre_state.current_epoch(),
        Domain::BeaconProposer,
        &pre_state.fork(),
        pre_state.genesis_validators_root(),
    );
    let proposal_signature = sign(
        SigningDuty::BeaconBlockProposal,
        block.signing_root(proposal_domain).0,
    );
    let signed = Arc::new(SignedBeaconBlock::from_block(block, proposal_signature));

    let wrong_root_journal_path = temporary_directory.path().join("xmss_wrong_root.sqlite");
    let wrong_root_keystore = PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD)
        .expect("wrong-root fixture keystore");
    let wrong_root_authenticated = wrong_root_keystore
        .authenticate(PASSWORD)
        .expect("wrong-root authenticated key");
    provision_usage_journal(
        &wrong_root_journal_path,
        genesis_validators_root,
        &[wrong_root_authenticated],
    )
    .expect("wrong-root usage journal");
    let wrong_root_authority = PqSigningAuthority::open(
        &wrong_root_journal_path,
        genesis_validators_root,
        vec![PqKeyUnlock::new(wrong_root_keystore, PASSWORD).expect("wrong-root unlock")],
    )
    .expect("wrong-root signing authority");
    let (mut wrong_root_block, _) = signed.as_ref().clone().deconstruct();
    *wrong_root_block.state_root_mut() = Hash256::repeat_byte(0x9a);
    let wrong_root_public_key = pre_state
        .validators()
        .get(proposer_index)
        .expect("wrong-root proposer")
        .pubkey;
    let wrong_root_signature = wrong_root_authority
        .signer(&wrong_root_public_key)
        .expect("wrong-root bound signer")
        .sign(consensus_signature::pq::PqSigningClaim::new(
            wrong_root_block.signing_root(proposal_domain).0,
            OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::BeaconBlockProposal)
                .expect("wrong-root proposal leaf"),
        ))
        .expect("separately proposal-signed wrong-root block");
    let wrong_root_signed = Arc::new(SignedBeaconBlock::from_block(
        wrong_root_block,
        wrong_root_signature,
    ));

    assert!(matches!(
        processor.verify_gossip_block(Arc::clone(&signed)).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::FutureSlot { current, block }
        )) if current == Slot::new(0) && block == Slot::new(1)
    ));
    assert!(transport.calls.lock().expect("calls lock").is_empty());
    chain.slot_clock.set_slot(2);

    assert!(matches!(
        processor.verify_gossip_block(wrong_root_signed).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::Transition(
                state_processing::PqTransitionError::PostStateRootMismatch { .. }
            )
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let (mut malformed_block, malformed_signature) = signed.as_ref().clone().deconstruct();
    let BeaconBlock::Electra(malformed_inner) = &mut malformed_block else {
        panic!("Electra fixture")
    };
    malformed_inner
        .body
        .execution_payload
        .execution_payload
        .block_hash = types::ExecutionBlockHash::repeat_byte(0x44);
    let malformed = Arc::new(SignedBeaconBlock::from_block(
        malformed_block,
        malformed_signature,
    ));
    assert!(matches!(
        processor.verify_gossip_block(malformed).await,
        PqGossipBlockDisposition::Reject(PqImportError::PeerInvalid(
            PqImportPeerInvalid::ExecutionPayload(_)
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let (mut unknown_parent_block, unknown_parent_signature) =
        signed.as_ref().clone().deconstruct();
    *unknown_parent_block.parent_root_mut() = Hash256::repeat_byte(0x55);
    let unknown_parent = Arc::new(SignedBeaconBlock::from_block(
        unknown_parent_block,
        unknown_parent_signature,
    ));
    let unknown_parent_error = match processor.import_lookup_block(unknown_parent).await {
        Ok(_) => panic!("unknown lookup parent must not verify"),
        Err(error) => error,
    };
    assert!(!unknown_parent_error.should_penalize_peer());
    assert!(unknown_parent_error.is_retryable());
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let non_linear = processor
        .import_forward_range(vec![Arc::clone(&signed), Arc::clone(&signed)])
        .await
        .expect_err("non-linear range fails whole-batch preflight");
    assert!(non_linear.imported.is_empty());
    assert!(non_linear.error.should_penalize_peer());
    assert!(transport.calls.lock().expect("calls lock").is_empty());

    let verified = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Accept(token) => token,
        _ => panic!("full sealed gossip verification must accept"),
    };
    assert!(matches!(
        processor.verify_gossip_block(Arc::clone(&signed)).await,
        PqGossipBlockDisposition::IgnorePending
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert!(transport.calls.lock().expect("calls lock").is_empty());
    drop(verified);

    let propagation_retry = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Accept(token) => token,
        _ => panic!("drop before propagation requires a new propagation claim"),
    };
    let commit = propagation_retry
        .after_propagation()
        .expect("exact propagation claim promotes to commit-ready");
    assert!(matches!(
        processor.commit_gossip_block(commit).await,
        Err(PqImportError::Local(
            PqImportLocalError::ExecutionUnavailable(PqEnginePayloadStatus::Syncing)
        ))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 1);

    let retry = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Retry(token) => token,
        _ => panic!("local Engine failure creates one commit retry claim"),
    };
    store
        .hot_db
        .fail_atomic_batch_containing(store::DBColumn::BeaconBlock);
    assert!(matches!(
        processor.commit_gossip_block(retry).await,
        Err(PqImportError::Local(PqImportLocalError::Persistence(
            beacon_chain::PqRuntimeError::Store(_)
        )))
    ));
    assert_eq!(chain.head_snapshot().beacon_block_root, genesis_root);
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 2);

    let queued_before_range = match processor.verify_gossip_block(Arc::clone(&signed)).await {
        PqGossipBlockDisposition::Retry(token) => token,
        _ => panic!("persistence failure exposes one commit retry"),
    };

    let (mut invalid_child_block, invalid_child_signature) = signed.as_ref().clone().deconstruct();
    *invalid_child_block.slot_mut() = Slot::new(2);
    *invalid_child_block.parent_root_mut() = signed.canonical_root();
    let invalid_child = Arc::new(SignedBeaconBlock::from_block(
        invalid_child_block,
        invalid_child_signature,
    ));
    let range_error = processor
        .import_forward_range(vec![Arc::clone(&signed), invalid_child])
        .await
        .expect_err("second range block is deterministically invalid");
    assert_eq!(range_error.imported.len(), 1);
    assert!(range_error.error.should_penalize_peer());
    let outcome = range_error.imported.first().expect("exact imported prefix");
    assert_eq!(outcome.block_root, signed.canonical_root());
    assert_eq!(chain.head_snapshot().beacon_block_root, outcome.block_root);
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 3);
    assert!(matches!(
        processor.commit_gossip_block(queued_before_range).await,
        Err(PqImportError::TerminalObservation { block_root })
            if block_root == outcome.block_root
    ));
    assert_eq!(transport.calls.lock().expect("calls lock").len(), 3);

    let restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("resume imported snapshot")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(transport)
        .build()
        .expect("restarted chain");
    assert_eq!(
        restarted.head_snapshot().beacon_block_root,
        outcome.block_root
    );

    let rejection_store = exact_snapshot_store(Arc::clone(&spec));
    let rejection_transport = Arc::new(RecordingTransport::invalid_block_hash());
    let rejection_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(rejection_store)
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist rejection-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(rejection_transport.clone())
            .build()
            .expect("rejection-test PQ chain"),
    );
    let rejection_processor = PqNetworkBlockProcessor::new(Arc::clone(&rejection_chain));
    rejection_chain.slot_clock.set_slot(2);
    let queued_gossip = match rejection_processor
        .verify_gossip_block(Arc::clone(&signed))
        .await
    {
        PqGossipBlockDisposition::Accept(token) => token
            .after_propagation()
            .expect("propagated queued gossip claim"),
        _ => panic!("queued gossip owns the initial claim"),
    };
    assert!(matches!(
        rejection_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::ExecutionRejected(
            execution_layer::PayloadStatus::InvalidBlockHash { .. }
        ))
    ));
    assert_eq!(
        rejection_transport.calls.lock().expect("calls lock").len(),
        1
    );
    assert!(matches!(
        rejection_processor.commit_gossip_block(queued_gossip).await,
        Err(PqImportError::TerminalObservation { .. })
    ));
    assert_eq!(
        rejection_transport.calls.lock().expect("calls lock").len(),
        1
    );

    let admission_transport = Arc::new(StallingTransport::new());
    let blocking_hook = TestingPqBlockingHook::blocking();
    let admission_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist admission-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_blocking_hook(Arc::clone(&blocking_hook))
            .testing_only_pq_execution_notifier(admission_transport.clone())
            .build()
            .expect("admission-test PQ chain"),
    );
    admission_chain.slot_clock.set_slot(2);
    let admission_processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&admission_chain)));
    let heartbeat_count = Arc::new(AtomicUsize::new(0));
    let heartbeat_stop = Arc::new(AtomicBool::new(false));
    let heartbeat = {
        let heartbeat_count = Arc::clone(&heartbeat_count);
        let heartbeat_stop = Arc::clone(&heartbeat_stop);
        tokio::spawn(async move {
            while !heartbeat_stop.load(Ordering::SeqCst) {
                heartbeat_count.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        })
    };
    let blocked_import = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || blocking_hook.entered() == 1,
        "blocking preparation hook entry",
    )
    .await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        heartbeat_count.load(Ordering::SeqCst) > 0,
        "blocking PQ preparation must not stall the async worker"
    );
    blocked_import.abort();
    assert_eq!(
        admission_chain.testing_only_pq_import_available_permits(),
        1,
        "an orphaned blocking phase must retain its admission until owned work exits"
    );
    blocking_hook.release();
    wait_for_test_condition(
        || {
            admission_chain.testing_only_pq_import_available_permits()
                == PQ_BLOCK_IMPORT_ADMISSION_CAPACITY
        },
        "admission release after canceled blocking phase",
    )
    .await;
    heartbeat_stop.store(true, Ordering::SeqCst);
    heartbeat.await.expect("heartbeat task");

    let first_engine = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    let queued_commit = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || {
            blocking_hook.entered() == 3
                && admission_chain.testing_only_pq_import_available_permits() == 0
                && admission_transport.calls.load(Ordering::SeqCst) == 1
        },
        "two admitted imports and one stalled Engine call",
    )
    .await;
    let preparation_calls_at_capacity = blocking_hook.entered();
    assert!(matches!(
        admission_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(PqImportLocalError::IngressCapacity))
    ));
    assert_eq!(blocking_hook.entered(), preparation_calls_at_capacity);
    assert_eq!(admission_transport.calls.load(Ordering::SeqCst), 1);

    let oversized = admission_processor
        .import_forward_range(vec![
            Arc::clone(&signed);
            PQ_FORWARD_RANGE_BLOCK_CAPACITY + 1
        ])
        .await
        .expect_err("oversized raw range fails before hashing or proof preparation");
    assert!(matches!(
        oversized.error,
        PqImportError::Local(PqImportLocalError::ForwardRangeCapacity {
            supplied,
            maximum,
        }) if supplied == PQ_FORWARD_RANGE_BLOCK_CAPACITY + 1
            && maximum == PQ_FORWARD_RANGE_BLOCK_CAPACITY
    ));
    assert_eq!(blocking_hook.entered(), preparation_calls_at_capacity);
    assert_eq!(admission_transport.calls.load(Ordering::SeqCst), 1);

    queued_commit.abort();
    wait_for_test_condition(
        || admission_chain.testing_only_pq_import_available_permits() == 1,
        "queued import cancellation",
    )
    .await;
    first_engine.abort();
    wait_for_test_condition(
        || admission_chain.testing_only_pq_import_available_permits() == 2,
        "pending Engine cancellation",
    )
    .await;
    let retry_after_engine_cancellation = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    let stale_after_verification = {
        let processor = Arc::clone(&admission_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || {
            admission_transport.calls.load(Ordering::SeqCst) == 2
                && admission_chain.testing_only_pq_import_available_permits() == 0
        },
        "Engine retry and queued verified import after canceled notification",
    )
    .await;
    admission_transport.release.add_permits(1);
    let rpc_result = retry_after_engine_cancellation.await.expect("retry task");
    let lookup_result = stale_after_verification.await.expect("stale import task");
    let (admission_outcome, stale_error) = match (rpc_result, lookup_result) {
        (Ok(outcome), Err(stale)) | (Err(stale), Ok(outcome)) => (outcome, stale),
        (rpc, lookup) => panic!(
            "one queued import must commit and one must become stale: rpc={rpc:?}, lookup={lookup:?}"
        ),
    };
    assert_eq!(admission_outcome.block_root, signed.canonical_root());
    assert!(matches!(
        stale_error,
        PqImportError::StaleHeadAfterVerification {
            expected_parent,
            actual_head,
        } if expected_parent == genesis_root && actual_head == admission_outcome.block_root
    ));
    assert_eq!(
        admission_transport.calls.load(Ordering::SeqCst),
        2,
        "a stale post-verification import must not call Engine"
    );

    for expected_source in [PqBlockImportSource::Rpc, PqBlockImportSource::Lookup] {
        let source_transport = Arc::new(RecordingTransport::always_valid());
        let source_chain = Arc::new(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(Arc::clone(&spec)))
                .custom_spec(Arc::clone(&spec))
                .genesis_state(genesis.clone())
                .expect("persist exact-source genesis")
                .pq_aggregation_service(Arc::clone(&service))
                .task_executor(test_runtime.task_executor.clone())
                .testing_only_pq_execution_notifier(source_transport.clone())
                .build()
                .expect("exact-source PQ chain"),
        );
        source_chain.slot_clock.set_slot(2);
        let source_processor = PqNetworkBlockProcessor::new(source_chain);
        let outcome = match expected_source {
            PqBlockImportSource::Rpc => {
                source_processor.import_rpc_block(Arc::clone(&signed)).await
            }
            PqBlockImportSource::Lookup => {
                source_processor
                    .import_lookup_block(Arc::clone(&signed))
                    .await
            }
            _ => unreachable!("exact-source test covers RPC and lookup"),
        }
        .expect("exact source imports through its awaited network route");
        assert_eq!(outcome.source, expected_source);
        assert_eq!(outcome.block_root, signed.canonical_root());
        assert_eq!(source_transport.calls.lock().expect("calls lock").len(), 1);
    }

    let persistence_store = exact_snapshot_store(Arc::clone(&spec));
    let persistence_transport = Arc::new(RecordingTransport::always_valid());
    let persistence_hook = TestingPqBlockingHook::blocking();
    let persistence_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&persistence_store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist cancellation-test genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_persistence_hook(Arc::clone(&persistence_hook))
            .testing_only_pq_execution_notifier(persistence_transport.clone())
            .build()
            .expect("persistence-cancellation PQ chain"),
    );
    persistence_chain.slot_clock.set_slot(2);
    let persistence_processor =
        Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&persistence_chain)));
    let canceled_after_valid = {
        let processor = Arc::clone(&persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || persistence_hook.entered() == 1,
        "post-VALID persistence barrier",
    )
    .await;
    assert_eq!(
        persistence_transport
            .calls
            .lock()
            .expect("calls lock")
            .len(),
        1
    );
    assert_eq!(
        persistence_chain.head_snapshot().beacon_block_root,
        genesis_root
    );
    canceled_after_valid.abort();
    assert_eq!(
        persistence_chain.testing_only_pq_import_available_permits(),
        1,
        "canceled post-VALID publication retains its admission"
    );
    let blocked_behind_publication = {
        let processor = Arc::clone(&persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_lookup_block(block).await })
    };
    wait_for_test_condition(
        || persistence_chain.testing_only_pq_import_available_permits() == 0,
        "second verified import blocked behind owned publication",
    )
    .await;
    assert!(matches!(
        persistence_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(PqImportLocalError::IngressCapacity))
    ));
    assert_eq!(
        persistence_transport
            .calls
            .lock()
            .expect("calls lock")
            .len(),
        1,
        "the queued commit cannot reach Engine while publication owns the gate"
    );
    persistence_hook.release();
    wait_for_test_condition(
        || persistence_chain.head_snapshot().beacon_block_root == signed.canonical_root(),
        "cancellation-independent canonical publication",
    )
    .await;
    assert!(matches!(
        blocked_behind_publication
            .await
            .expect("blocked publication task"),
        Err(PqImportError::StaleHeadAfterVerification { .. })
    ));
    assert!(persistence_chain.testing_only_pq_observation_is_committed(
        signed.slot(),
        signed.message().proposer_index(),
        signed.canonical_root(),
    ));
    let persistence_restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(persistence_store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("resume cancellation-independent publication")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(persistence_transport)
        .build()
        .expect("restarted cancellation-independent chain");
    assert_eq!(
        persistence_restarted.head_snapshot().beacon_block_root,
        signed.canonical_root()
    );

    let failed_persistence_store = exact_snapshot_store(Arc::clone(&spec));
    let failed_persistence_transport = Arc::new(RecordingTransport::always_valid());
    let failed_persistence_hook = TestingPqBlockingHook::blocking();
    let failed_persistence_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&failed_persistence_store))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist failed-publication genesis")
            .pq_aggregation_service(Arc::clone(&service))
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_persistence_hook(Arc::clone(&failed_persistence_hook))
            .testing_only_pq_execution_notifier(failed_persistence_transport.clone())
            .build()
            .expect("failed-publication PQ chain"),
    );
    failed_persistence_chain.slot_clock.set_slot(2);
    failed_persistence_store
        .hot_db
        .fail_atomic_batch_containing(store::DBColumn::BeaconBlock);
    let failed_persistence_processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(
        &failed_persistence_chain,
    )));
    let canceled_failed_publication = {
        let processor = Arc::clone(&failed_persistence_processor);
        let block = Arc::clone(&signed);
        tokio::spawn(async move { processor.import_rpc_block(block).await })
    };
    wait_for_test_condition(
        || failed_persistence_hook.entered() == 1,
        "failed post-VALID persistence barrier",
    )
    .await;
    canceled_failed_publication.abort();
    failed_persistence_hook.release();
    wait_for_test_condition(
        || {
            failed_persistence_chain.testing_only_pq_import_available_permits()
                == PQ_BLOCK_IMPORT_ADMISSION_CAPACITY
                && failed_persistence_chain.testing_only_pq_observation_is_absent(
                    signed.slot(),
                    signed.message().proposer_index(),
                )
        },
        "failed publication owned cleanup",
    )
    .await;
    assert_eq!(
        failed_persistence_chain.head_snapshot().beacon_block_root,
        genesis_root,
        "database failure cannot publish memory after caller cancellation"
    );
    let failed_persistence_restarted = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
        .store(failed_persistence_store)
        .custom_spec(Arc::clone(&spec))
        .resume_from_db()
        .expect("failed publication retains restartable genesis")
        .pq_aggregation_service(Arc::clone(&service))
        .task_executor(test_runtime.task_executor.clone())
        .testing_only_pq_execution_notifier(failed_persistence_transport)
        .build()
        .expect("restart after canceled database failure");
    assert_eq!(
        failed_persistence_restarted
            .head_snapshot()
            .beacon_block_root,
        genesis_root
    );

    let capacity_transport = Arc::new(RecordingTransport::invalid_block_hash());
    let capacity_chain = Arc::new(
        BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(exact_snapshot_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist capacity-test genesis")
            .pq_aggregation_service(service)
            .task_executor(test_runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(capacity_transport.clone())
            .build()
            .expect("capacity-test PQ chain"),
    );
    let capacity_processor = PqNetworkBlockProcessor::new(Arc::clone(&capacity_chain));
    capacity_chain.slot_clock.set_slot(2);
    assert!(capacity_chain.testing_only_fill_pq_observation_capacity());
    assert!(matches!(
        capacity_processor
            .import_rpc_block(Arc::clone(&signed))
            .await,
        Err(PqImportError::Local(
            PqImportLocalError::ObservationCapacity
        ))
    ));
    assert!(
        capacity_transport
            .calls
            .lock()
            .expect("calls lock")
            .is_empty(),
        "a full observation cache must fail before Engine notification"
    );
}
