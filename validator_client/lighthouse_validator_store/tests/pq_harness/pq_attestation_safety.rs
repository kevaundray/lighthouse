use eth2::{StrictBeaconNodeHttpClient, Timeouts};
use context_deserialize::ContextDeserialize;
use futures::StreamExt;
use initialized_validators::InitializedValidators;
use lighthouse_validator_store::{Config, LighthouseValidatorStore};
use pq_devnet::{ProvisionConfig, provision_devnet};
use pq_proposer_service::{PqProposerService, PqProposerServiceError};
use pq_signing::PqSigningError;
use sensitive_url::SensitiveUrl;
use signing_method::Error as SigningMethodError;
use slashing_protection::{Safe, SlashingDatabase};
use slot_clock::{SlotClock, TestingSlotClock};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use task_executor::test_utils::TestRuntime;
use tempfile::tempdir;
use types::{
    Attestation, AttestationData, BeaconBlock, BlindedPayload, ChainSpec, Checkpoint, Domain,
    EthSpec, ForkName, Hash256, MinimalEthSpec, Slot,
};
use validator_store::{AttestationToSign, UnsignedBlock, ValidatorStore};
use warp::{Filter, Reply};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_pq_attestation_call_retains_precheck_and_reports_panic() {
    let root = tempdir().expect("root");
    let seed_path = root.path().join("seed");
    let password_path = root.path().join("password");
    fs::write(&seed_path, [44; 32]).expect("seed");
    fs::write(&password_path, b"deterministic test password").expect("password");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600))
        .expect("password mode");
    let destination = root.path().join("devnet");
    let provisioned = provision_devnet(
        ProvisionConfig::for_test(destination.clone(), 1, 0..=125, 44),
        &seed_path,
        &password_path,
    )
    .expect("devnet");
    let public_key = provisioned.public_keys()[0];
    let (exit_sender, exit_receiver) = async_channel::bounded(1);
    let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(2);
    let executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        exit_receiver,
        shutdown_sender,
    );
    let initialized = InitializedValidators::from_pq_bundle(
        provisioned.bundle_dir().to_path_buf(),
        provisioned.genesis_validators_root(),
        provisioned.genesis_time(),
        provisioned.validator_registry().to_vec(),
        executor.clone(),
    )
    .await
    .expect("initialized validators");
    let slashing = SlashingDatabase::create(&destination.join("slashing_protection.sqlite"))
        .expect("fresh slashing DB");
    slashing
        .register_validator(public_key)
        .expect("register validator");
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
    let store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(provisioned.genesis_validators_root()),
        Arc::clone(&spec),
        None,
        clock,
        &Config::default(),
        executor,
    ));
    let make_request = || AttestationToSign {
        validator_index: 0,
        pubkey: public_key,
        validator_committee_index: 0,
        attestation: attestation(&spec, Slot::new(0), Hash256::repeat_byte(0x71)),
    };

    let invocations = Arc::new(AtomicUsize::new(0));
    let invocations_for_hook = Arc::clone(&invocations);
    let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
    let release_receiver = Arc::new(std::sync::Mutex::new(release_receiver));
    store.testing_only_set_pq_attestation_precheck_hook(Some(Arc::new(move || {
        invocations_for_hook.fetch_add(1, Ordering::SeqCst);
        entered_sender.send(()).expect("report blocked precheck");
        release_receiver
            .lock()
            .expect("release receiver lock")
            .recv()
            .expect("release blocked precheck");
        panic!("actual PQ precheck panic after caller abort")
    })));
    let aborted_store = Arc::clone(&store);
    let aborted_request = make_request();
    let caller = tokio::spawn(async move {
        let stream = aborted_store.sign_attestations(vec![aborted_request]);
        futures::pin_mut!(stream);
        stream.next().await
    });
    tokio::task::spawn_blocking(move || {
        entered_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("real precheck entered")
    })
    .await
    .expect("entered waiter");
    caller.abort();
    assert!(caller.await.expect_err("caller aborted").is_cancelled());
    drop(exit_sender);
    release_sender.send(()).expect("release retained precheck");
    let first_reason = tokio::time::timeout(Duration::from_secs(2), shutdown_receiver.next())
        .await
        .expect("retained panic reported")
        .expect("failure reason");
    assert_eq!(
        first_reason,
        task_executor::ShutdownReason::Failure("Panic (fatal error)")
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let invocations_for_hook = Arc::clone(&invocations);
    store.testing_only_set_pq_attestation_precheck_hook(Some(Arc::new(move || {
        invocations_for_hook.fetch_add(1, Ordering::SeqCst);
        panic!("awaited actual PQ precheck panic")
    })));
    let stream = store.sign_attestations(vec![make_request()]);
    futures::pin_mut!(stream);
    let error = stream
        .next()
        .await
        .expect("one real store batch")
        .expect_err("actual precheck panic is typed");
    assert!(matches!(error, validator_store::Error::ExecutorError));
    let second_reason = tokio::time::timeout(Duration::from_secs(2), shutdown_receiver.next())
        .await
        .expect("awaited panic reported")
        .expect("failure reason");
    assert_eq!(
        second_reason,
        task_executor::ShutdownReason::Failure("Panic (fatal error)")
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn real_pq_block_signing_offloads_the_locked_sqlite_transaction() {
    let root = tempdir().expect("root");
    let seed_path = root.path().join("seed");
    let password_path = root.path().join("password");
    fs::write(&seed_path, [43; 32]).expect("seed");
    fs::write(&password_path, b"deterministic test password").expect("password");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600))
        .expect("password mode");
    let destination = root.path().join("devnet");
    let provisioned = provision_devnet(
        ProvisionConfig::for_test(destination.clone(), 1, 0..=125, 43),
        &seed_path,
        &password_path,
    )
    .expect("devnet");
    let public_key = provisioned.public_keys()[0];
    let runtime = TestRuntime::default();
    let initialized = InitializedValidators::from_pq_bundle(
        provisioned.bundle_dir().to_path_buf(),
        provisioned.genesis_validators_root(),
        provisioned.genesis_time(),
        provisioned.validator_registry().to_vec(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("initialized validators");
    let slashing = SlashingDatabase::create(&destination.join("slashing_protection.sqlite"))
        .expect("fresh slashing DB");
    slashing
        .register_validator(public_key)
        .expect("register validator");
    let locked_slashing = slashing.clone();
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(300));
    let store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(provisioned.genesis_validators_root()),
        Arc::clone(&spec),
        None,
        clock.clone(),
        &Config::default(),
        runtime.task_executor.clone(),
    ));
    let duties = warp::path!("eth" / "v1" / "validator" / "duties" / "proposer" / u64)
        .map(move |_| {
            warp::reply::json(&eth2::types::DutiesResponse {
                dependent_root: Hash256::repeat_byte(0x31),
                execution_optimistic: Some(false),
                data: vec![
                    eth2::types::ProposerData {
                        pubkey: public_key,
                        validator_index: 0,
                        slot: Slot::new(4),
                    },
                    eth2::types::ProposerData {
                        pubkey: public_key,
                        validator_index: 0,
                        slot: Slot::new(5),
                    },
                ],
            })
            .into_response()
    });
    let production_spec = Arc::clone(&spec);
    let production_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let production_attempts_for_route = Arc::clone(&production_attempts);
    let produce = warp::path!("eth" / "v3" / "validator" / "blocks" / u64)
        .and(warp::query::<eth2::types::ValidatorBlocksQuery>())
        .and(warp::header::optional::<String>("accept"))
        .map(move |slot, query: eth2::types::ValidatorBlocksQuery, accept: Option<String>| {
            production_attempts_for_route.fetch_add(1, Ordering::SeqCst);
            let mut block = BeaconBlock::<MinimalEthSpec>::empty(&production_spec);
            *block.slot_mut() = Slot::new(slot);
            *block.proposer_index_mut() = 0;
            *block.state_root_mut() = Hash256::repeat_byte(0x55);
            *block.body_mut().randao_reveal_mut() = query
                .decode_randao_reveal()
                .expect("service sends canonical exact RANDAO");
            *block.body_mut().graffiti_mut() = query.graffiti.unwrap_or_default();
            let contents = eth2::types::FullBlockContents::new(
                block,
                Some((
                    types::KzgProofs::<MinimalEthSpec>::default(),
                    types::BlobsList::<MinimalEthSpec>::default(),
                )),
            );
            let ssz_requested = accept
                .as_deref()
                .is_some_and(|accept| accept.contains("application/octet-stream"));
            let (content_type, body) = if ssz_requested {
                (
                    "application/octet-stream",
                    vec![0_u8],
                )
            } else {
                (
                    "application/json",
                    serde_json::to_vec(&eth2::types::ForkVersionedResponse {
                        version: ForkName::Electra,
                        metadata: eth2::types::ProduceBlockV3Metadata {
                            consensus_version: ForkName::Electra,
                            execution_payload_blinded: false,
                            execution_payload_value: types::Uint256::from(17_u64),
                            consensus_block_value: types::Uint256::ZERO,
                        },
                        data: eth2::types::ProduceBlockV3Response::Full(contents),
                    })
                    .expect("V3 JSON response"),
                )
            };
            warp::http::Response::builder()
                .status(warp::http::StatusCode::OK)
                .header("content-type", content_type)
                .header("eth-consensus-version", "electra")
                .header("eth-execution-payload-blinded", "false")
                .header("eth-execution-payload-value", "17")
                .header("eth-consensus-block-value", "0")
                .header("connection", "close")
                .body(warp::hyper::Body::from(body))
                .expect("V3 response")
        });
    let (published_tx, mut published_rx) = tokio::sync::mpsc::unbounded_channel();
    let publish_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let publish_attempts_for_route = Arc::clone(&publish_attempts);
    let publish = warp::path!("eth" / "v2" / "beacon" / "blocks")
        .and(warp::post())
        .and(warp::header::exact("eth-consensus-version", "electra"))
        .and(warp::header::optional::<String>("content-type"))
        .and(warp::body::bytes())
        .map(move |content_type: Option<String>, body: warp::hyper::body::Bytes| {
            let _ = published_tx.send((content_type, body.to_vec()));
            let attempt = publish_attempts_for_route.fetch_add(1, Ordering::SeqCst);
            let status = if attempt == 0 {
                warp::http::StatusCode::ACCEPTED
            } else {
                warp::http::StatusCode::OK
            };
            warp::reply::with_status("", status).into_response()
        });
    let routes = duties.or(produce).unify().or(publish).unify();
    let restart_routes = routes.clone();
    let (address, server) = warp::serve(routes).bind_ephemeral(([127, 0, 0, 1], 0));
    let initial_server = Arc::new(std::sync::Mutex::new(Some(tokio::spawn(server))));
    let beacon_node = StrictBeaconNodeHttpClient::from_builder(
        SensitiveUrl::parse(&format!("http://{address}/")).expect("test beacon node URL"),
        Timeouts::set_all(Duration::from_secs(10)),
        reqwest::Client::builder(),
    )
    .expect("strict configured beacon node client");
    store.set_validator_index(&public_key, 99);
    assert_eq!(
        store.validator_index(&public_key),
        Some(0),
        "ordinary duty discovery cannot replace a manifest-sealed PQ identity index",
    );
    let initial_server_for_hook = Arc::clone(&initial_server);
    let post_production_hook = move || {
        let server = initial_server_for_hook
            .lock()
            .expect("initial server lock")
            .take();
        async move {
            if let Some(server) = server {
                server.abort();
                let _ = server.await;
            }
        }
    };
    let restarted_server = Arc::new(std::sync::Mutex::new(None));
    let restarted_server_for_hook = Arc::clone(&restarted_server);
    let fallback_hook = Arc::new(move || {
        let server = tokio::spawn(warp::serve(restart_routes.clone()).run(address));
        *restarted_server_for_hook
            .lock()
            .expect("restarted server lock") = Some(server);
    });
    let (encode_entered_tx, encode_entered_rx) = std::sync::mpsc::sync_channel(0);
    let (encode_release_tx, encode_release_rx) = std::sync::mpsc::sync_channel(0);
    let encode_release_rx = std::sync::Mutex::new(encode_release_rx);
    let encode_watchdog_fired = Arc::new(AtomicBool::new(false));
    let encode_watchdog_fired_for_hook = Arc::clone(&encode_watchdog_fired);
    let encode_calls = Arc::new(AtomicUsize::new(0));
    let encode_calls_for_hook = Arc::clone(&encode_calls);
    let encode_hook = Arc::new(move || {
        if encode_calls_for_hook.fetch_add(1, Ordering::SeqCst) == 1 {
            encode_entered_tx.send(()).expect("announce encoder entry");
            if encode_release_rx
                .lock()
                .expect("encoder release lock")
                .recv_timeout(Duration::from_secs(5))
                .is_err()
            {
                encode_watchdog_fired_for_hook.store(true, Ordering::SeqCst);
            }
        }
    });
    let service = Arc::new(
        PqProposerService::new(
            clock.clone(),
            runtime.task_executor.clone(),
            Arc::clone(&store),
            beacon_node,
        )
        .expect("concrete proposer facade derives the exact provisioned identity from its store")
        .testing_only_publication_encode_hook(encode_hook)
        .testing_only_publication_json_fallback_hook(fallback_hook)
        .testing_only_post_production_hook(post_production_hook),
    );
    clock.set_slot(4);
    let first_receipt = service
        .try_propose_current_slot()
        .expect("first current-slot proposal starts");
    let coalesced_receipt = service
        .try_propose_current_slot()
        .expect("same-slot call coalesces");
    assert_eq!(first_receipt.slot(), Slot::new(4));
    assert_eq!(coalesced_receipt.slot(), Slot::new(4));
    let first_completion = first_receipt.completion().await;
    let coalesced_completion = coalesced_receipt.completion().await;
    let published = first_completion
        .clone()
        .expect("exact PQ proposal published");
    let pq_proposer_service::PqProposalCompletion::Published { slot, block_root } = published else {
        panic!("final receipt must not expose an intermediate duty")
    };
    assert_eq!(slot, Slot::new(4));
    assert_eq!(coalesced_completion, first_completion);
    let (first_content_type, first_published_bytes) =
        tokio::time::timeout(Duration::from_secs(5), published_rx.recv())
        .await
        .expect("publication deadline")
        .expect("exact signed publication bytes");
    let (retried_content_type, published_bytes) =
        tokio::time::timeout(Duration::from_secs(5), published_rx.recv())
        .await
        .expect("publication retry deadline")
        .expect("exact signed publication retry bytes");
    assert_eq!(first_content_type.as_deref(), Some("application/json"));
    assert_eq!(retried_content_type.as_deref(), Some("application/json"));
    assert_eq!(published_bytes, first_published_bytes);
    assert_eq!(publish_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(production_attempts.load(Ordering::SeqCst), 2);
    let mut deserializer = serde_json::Deserializer::from_slice(&published_bytes);
    let published = eth2::types::PublishBlockRequest::<MinimalEthSpec>::context_deserialize(
        &mut deserializer,
        ForkName::Electra,
    )
    .expect("published Electra signed JSON block contents");
    deserializer.end().expect("complete signed JSON body");
    assert_eq!(published.signed_block().slot(), Slot::new(4));
    assert_eq!(published.signed_block().message().proposer_index(), 0);
    assert_eq!(published.signed_block().canonical_root(), block_root);

    clock.set_slot(5);
    let expiring_receipt = service
        .try_propose_current_slot()
        .expect("next-slot proposal starts");
    let (encode_forward_tx, encode_forward_rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = encode_entered_rx.recv();
        let _ = encode_forward_tx.send(());
    });
    encode_forward_rx.await.expect("blocking encoder entered");
    let heartbeat = tokio::spawn(async { 31usize });
    assert_eq!(heartbeat.await.expect("encoder heartbeat"), 31);
    let coalesced_expiring = service
        .try_propose_current_slot()
        .expect("same-slot encoder call coalesces");
    assert_eq!(coalesced_expiring.slot(), Slot::new(5));
    clock.set_slot(6);
    assert!(matches!(
        service.try_propose_current_slot(),
        Err(PqProposerServiceError::Capacity)
    ));
    clock.set_current_time(Duration::from_secs(5 * 300 + 46));
    encode_release_tx.send(()).expect("release blocking encoder");
    let expired = expiring_receipt.completion().await;
    assert!(matches!(
        &expired,
        Err(PqProposerServiceError::PublicationExpired { .. })
    ));
    assert_eq!(coalesced_expiring.completion().await, expired);
    assert!(!encode_watchdog_fired.load(Ordering::SeqCst));
    assert_eq!(publish_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(production_attempts.load(Ordering::SeqCst), 4);
    if let Some(server) = restarted_server
        .lock()
        .expect("restarted server lock")
        .take()
    {
        server.abort();
    }

    let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let lock_thread = std::thread::spawn(move || {
        locked_slashing
            .with_transaction::<(), slashing_protection::NotSafe, _>(|_| {
                locked_tx.send(()).expect("announce locked transaction");
                release_rx.recv().expect("release locked transaction");
                Ok(())
            })
            .expect("locked transaction");
    });
    locked_rx.recv().expect("SQLite transaction lock acquired");
    let (cancel_watchdog_tx, cancel_watchdog_rx) = std::sync::mpsc::sync_channel(0);
    let normal_release_tx = release_tx.clone();
    let watchdog_fired = Arc::new(AtomicBool::new(false));
    let watchdog_fired_for_thread = Arc::clone(&watchdog_fired);
    let watchdog = std::thread::spawn(move || {
        if cancel_watchdog_rx
            .recv_timeout(Duration::from_secs(2))
            .is_err()
        {
            watchdog_fired_for_thread.store(true, Ordering::SeqCst);
            let _ = release_tx.send(());
        }
    });

    let mut block = BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
    *block.slot_mut() = Slot::new(6);
    let retry_block = block.clone();
    let sign_store = Arc::clone(&store);
    let (signing_entered_tx, signing_entered_rx) = tokio::sync::oneshot::channel();
    let signing = tokio::spawn(async move {
        let _ = signing_entered_tx.send(());
        sign_store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(block),
                Slot::new(6),
            )
            .await
    });
    signing_entered_rx
        .await
        .expect("real sign_block call entered");
    let heartbeat = tokio::spawn(async { 29usize });
    assert_eq!(heartbeat.await.expect("async heartbeat"), 29);
    assert!(
        !watchdog_fired.load(Ordering::SeqCst),
        "the real sign_block SQLite transaction blocked the current-thread async worker",
    );
    normal_release_tx
        .send(())
        .expect("release SQLite transaction");
    cancel_watchdog_tx.send(()).expect("cancel watchdog");
    watchdog.join().expect("watchdog");
    lock_thread.join().expect("lock thread");
    let first = signing
        .await
        .expect("signing task")
        .expect("real PQ block signature after SQLite lock release");
    let retry = store
        .sign_block(
            public_key,
            UnsignedBlock::Blinded(retry_block),
            Slot::new(6),
        )
        .await
        .expect("exact Safe::SameData block retry");
    match (first, retry) {
        (validator_store::SignedBlock::Blinded(first), validator_store::SignedBlock::Blinded(retry)) => {
            assert_eq!(
                first.signature().as_bytes(),
                retry.signature().as_bytes(),
                "the journal-backed exact retry must return the identical PQ signature",
            );
        }
        _ => panic!("the proposer-only PQ path signs full or blinded blocks without changing shape"),
    }

    let mut out_of_range_block =
        BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
    *out_of_range_block.slot_mut() = Slot::new(16);
    assert!(matches!(
        store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(out_of_range_block),
                Slot::new(16),
            )
            .await,
        Err(validator_store::Error::SpecificError(
            SigningMethodError::PqSigning(PqSigningError::InvalidSigningRequest)
        ))
    ));
}

fn signed_attestation_count(status: &str) -> u64 {
    validator_metrics::get_int_counter(
        &validator_metrics::SIGNED_ATTESTATIONS_TOTAL,
        &[status],
    )
    .expect("signed attestation metric")
    .get()
}

fn signed_block_count(status: &str) -> u64 {
    validator_metrics::get_int_counter(&validator_metrics::SIGNED_BLOCKS_TOTAL, &[status])
        .expect("signed block metric")
        .get()
}

fn attestation(spec: &ChainSpec, slot: Slot, block_root: Hash256) -> Attestation<MinimalEthSpec> {
    let target_epoch = slot.epoch(MinimalEthSpec::slots_per_epoch());
    Attestation::empty_for_signing(
        0,
        1,
        slot,
        block_root,
        Checkpoint {
            epoch: target_epoch.saturating_sub(1_u64),
            root: Hash256::ZERO,
        },
        Checkpoint {
            epoch: target_epoch,
            root: Hash256::ZERO,
        },
        false,
        spec,
    )
    .expect("attestation")
}

#[tokio::test(flavor = "multi_thread")]
async fn slashing_commit_precedes_pq_reservation_and_same_data_is_recoverable() {
    let root = tempdir().expect("root");
    let seed_path = root.path().join("seed");
    let password_path = root.path().join("password");
    fs::write(&seed_path, [42; 32]).expect("seed");
    fs::write(&password_path, b"deterministic test password").expect("password");
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).expect("seed mode");
    fs::set_permissions(&password_path, fs::Permissions::from_mode(0o600)).expect("password mode");
    let destination = root.path().join("devnet");
    let provisioned = provision_devnet(
        ProvisionConfig::for_test(destination.clone(), 1, 0..=125, 42),
        &seed_path,
        &password_path,
    )
    .expect("devnet");
    let public_key = provisioned.public_keys()[0];
    let runtime = TestRuntime::default();
    let initialized = InitializedValidators::from_pq_bundle(
        provisioned.bundle_dir().to_path_buf(),
        provisioned.genesis_validators_root(),
        provisioned.genesis_time(),
        provisioned.validator_registry().to_vec(),
        runtime.task_executor.clone(),
    )
    .await
    .expect("initialized validators");
    let slashing_path = destination.join("slashing_protection.sqlite");
    let slashing = SlashingDatabase::create(&slashing_path).expect("fresh slashing DB");
    slashing
        .register_validator(public_key)
        .expect("register validator");
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let slot_zero_data = AttestationData {
        slot: Slot::new(0),
        beacon_block_root: Hash256::repeat_byte(0x11),
        target: Checkpoint::default(),
        ..AttestationData::default()
    };
    let domain = spec.get_domain(
        slot_zero_data.target.epoch,
        Domain::BeaconAttester,
        &spec.fork_at_epoch(slot_zero_data.target.epoch),
        Hash256::from(provisioned.genesis_validators_root()),
    );
    assert_eq!(
        slashing.with_transaction(|txn| {
            slashing.check_and_insert_attestation(&public_key, &slot_zero_data, domain, txn)
        }),
        Ok(Safe::Valid)
    );
    let clock = TestingSlotClock::new(Slot::new(0), Duration::ZERO, Duration::from_secs(12));
    let store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(provisioned.genesis_validators_root()),
        spec.clone(),
        None,
        clock,
        &Config::default(),
        runtime.task_executor.clone(),
    ));

    // Simulates cancellation after the ordinary slashing DB commit: Safe::SameData must still
    // reach the deterministic PQ authority.
    let successes_before_recovery = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_recovery = signed_attestation_count(validator_metrics::SAME_DATA);
    let recovered = {
        let recovered_stream = store.sign_attestations(vec![AttestationToSign {
            validator_index: 0,
            pubkey: public_key,
            validator_committee_index: 0,
            attestation: attestation(&spec, Slot::new(0), Hash256::repeat_byte(0x11)),
        }]);
        futures::pin_mut!(recovered_stream);
        recovered_stream
            .next()
            .await
            .expect("batch")
            .expect("recovered signature")
    };
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_recovery,
        "a successful same-data retry must not be classified as a fresh success"
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_recovery + 1,
        "same-data is recorded only after signature attachment"
    );

    let successes_before_mixed = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_mixed = signed_attestation_count(validator_metrics::SAME_DATA);
    let mixed = {
        let mixed_stream = store.sign_attestations(vec![
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(16), Hash256::repeat_byte(0x44)),
            },
        ]);
        futures::pin_mut!(mixed_stream);
        mixed_stream
            .next()
            .await
            .expect("batch")
            .expect("successful sibling must survive signer failure")
    };
    assert_eq!(mixed.len(), 1);
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_mixed + 1
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_mixed
    );

    let successes_before_concurrent = signed_attestation_count(validator_metrics::SUCCESS);
    let same_data_before_concurrent = signed_attestation_count(validator_metrics::SAME_DATA);
    let concurrent = {
        let concurrent_stream = store.sign_attestations(vec![
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x22)),
            },
            AttestationToSign {
                validator_index: 0,
                pubkey: public_key,
                validator_committee_index: 0,
                attestation: attestation(&spec, Slot::new(8), Hash256::repeat_byte(0x33)),
            },
        ]);
        futures::pin_mut!(concurrent_stream);
        concurrent_stream
            .next()
            .await
            .expect("batch")
            .expect("safe signatures")
    };
    assert_eq!(concurrent.len(), 2);
    assert_eq!(
        concurrent[0].1.signature().as_bytes(),
        concurrent[1].1.signature().as_bytes()
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_concurrent,
        "same-data siblings are not fresh successful signatures"
    );
    assert_eq!(
        signed_attestation_count(validator_metrics::SAME_DATA),
        same_data_before_concurrent + 2,
        "both attached retries are classified as same-data"
    );

    // Slot 16 maps to leaf 226, beyond the provisioned 0..=125 range. Slashing protection
    // accepts and commits this new data, but the stateful signer cannot produce a signature.
    // Therefore it must not be reported as a successful attestation signature.
    let successes_before_failure = signed_attestation_count(validator_metrics::SUCCESS);
    let out_of_range = {
        let out_of_range_stream = store.sign_attestations(vec![AttestationToSign {
            validator_index: 0,
            pubkey: public_key,
            validator_committee_index: 0,
            attestation: attestation(&spec, Slot::new(16), Hash256::repeat_byte(0x44)),
        }]);
        futures::pin_mut!(out_of_range_stream);
        out_of_range_stream
            .next()
            .await
            .expect("batch")
            .expect("failed member is dropped")
    };
    assert!(out_of_range.is_empty(), "out-of-range member must be dropped");
    assert_eq!(
        signed_attestation_count(validator_metrics::SUCCESS),
        successes_before_failure,
        "slashing precheck alone must not increment signing success"
    );

    let mut block =
        BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
    *block.slot_mut() = Slot::new(16);
    let retry_block = block.clone();
    let block_success_before = signed_block_count(validator_metrics::SUCCESS);
    let block_same_data_before = signed_block_count(validator_metrics::SAME_DATA);
    assert!(
        store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(block),
                Slot::new(16)
            )
            .await
            .is_err(),
        "out-of-range Safe::Valid block signing must fail"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SUCCESS),
        block_success_before,
        "Safe::Valid is successful only after block construction"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SAME_DATA),
        block_same_data_before
    );
    assert!(
        store
            .sign_block(
                public_key,
                UnsignedBlock::Blinded(retry_block),
                Slot::new(16)
            )
            .await
            .is_err(),
        "out-of-range Safe::SameData block signing must fail"
    );
    assert_eq!(
        signed_block_count(validator_metrics::SUCCESS),
        block_success_before
    );
    assert_eq!(
        signed_block_count(validator_metrics::SAME_DATA),
        block_same_data_before,
        "Safe::SameData is recorded only after block construction"
    );

    drop(store);
    let connection =
        rusqlite::Connection::open(destination.join("xmss_usage.sqlite")).expect("journal query");
    let reservations: i64 = connection
        .query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))
        .expect("reservation count");
    assert_eq!(
        reservations, 2,
        "unsafe conflicting data must not burn a leaf"
    );
}
