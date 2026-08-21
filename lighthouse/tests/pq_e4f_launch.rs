#![cfg(all(feature = "pq-proposer", target_os = "linux"))]

use beacon_node::beacon_chain::{
    BeaconChain, PqLocalAttesterIdentity, PqNewPayloadTransport, PqOperationalEvent,
    PqOperationalEventRole, PqOperationalEventSink,
    builder::{BeaconChainBuilder, Witness},
    testing_only_running_pq_operational_event_sink,
};
use consensus_signature::{AggregationService, PqValidatorRegistryEntry};
use execution_layer::auth::JwtKey;
use execution_layer::test_utils::{DEFAULT_JWT_SECRET, MockEngineAuditEvent, MockServer};
use fs2::FileExt;
use initialized_validators::InitializedValidators;
use lighthouse_network::{
    Context, GossipTopic, MessageId, NetworkConfig, identity::secp256k1,
    libp2p::gossipsub::IdentTopic, types::GossipEncoding, types::GossipKind,
};
use lighthouse_validator_store::{Config as ValidatorStoreConfig, LighthouseValidatorStore};
use network::{
    PqLocalAttestationMemberPublishProgress, PqNetworkBlockProcessor, PqNetworkService,
    pq_block_broadcast_channel,
};
use network_utils::enr_ext::EnrExt;
use pq_attester_service::{PqAttestationCompletion, PqAttesterService};
use pq_devnet::{production_config, provision_devnet};
use rusqlite::{Connection, MAIN_DB, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use slashing_protection::SlashingDatabase;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use ssz::Encode;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use store::{HotColdDB, MemoryStore, StoreConfig};
use tempfile::TempDir;
use types::{
    BeaconBlock, BeaconState, ChainSpec, EthSpec, ExecutionBlockHash, ExecutionPayloadRef,
    ForkContext, ForkName, Hash256, MinimalEthSpec, SignedBeaconBlock, Slot, SubnetId, Uint256,
};
use validator_dir::{PqDevnetBundle, PqDevnetManifest};
use validator_store::{SignedBlock, UnsignedBlock, ValidatorStore};

const PQ_EVENT_PREFIX: &str = "PQ_EVENT_V1";
const MAX_LOG_FRAME_BYTES: usize = 64 * 1024;
const MAX_RETAINED_LOG_FRAMES: usize = 512;
const MAX_RETAINED_PQ_EVENTS: usize = 64;
const MAX_ENR_BYTES: u64 = 4096;
const MAX_TEMPLATE_ENTRIES: usize = 128;
const MAX_TEMPLATE_BYTES: u64 = 256 * 1024 * 1024;
const TEMPLATE_VERSION: &str = "pq-e4f-template-v1";
const PINNED_TEMPLATE_SEMANTIC_SHA256: &str =
    "0ce1ebc8555a9a65e11d470bda2f697f652b444acc4d1e214bf737288d76addb";
const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(900);
const STATUS_EVENT_TIMEOUT: Duration = Duration::from_secs(240);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const PQ_SLOT_SECONDS: u64 = 300;
const THREE_SLOT_TARGET: u64 = 3;
const PROPOSAL_COMPLETION_SECONDS: u64 = 285;
const RESTART_STOP_MARGIN_SECONDS: u64 = 5;

fn unix_time_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))
}

type DirectAttesterWitness = Witness<SystemTimeSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

struct DirectAttesterExecution;

impl PqNewPayloadTransport<MinimalEthSpec> for DirectAttesterExecution {
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
        _head_block_hash: ExecutionBlockHash,
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

fn direct_attester_store(
    spec: Arc<ChainSpec>,
) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
    let mut config = StoreConfig::default();
    config.hierarchy_config.exponents = vec![0];
    config.block_cache_size = 0;
    Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
}

fn clone_validated_attester_template() -> (TempDir, PqNetworkIdentity) {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target");
    let target = open_directory_nofollow(&target, None).expect("open target directory once");
    let lock = open_fixture_lock(&target).expect("anchored fixture lock");
    lock.lock_exclusive()
        .expect("exclusive fixture-generation lock");
    let template = anchored_path(&target).join(TEMPLATE_VERSION);
    validate_template_structure(&template).expect("validated immutable template structure");
    let template_root =
        open_directory_nofollow(&template, Some(0o700)).expect("held immutable template");
    let expected_inventory = TemplateInventory::decode(
        &read_named_bounded(&template_root, "inventory", 0o600, 1024)
            .expect("bounded template inventory"),
    )
    .expect("exact template inventory");
    let source_container = template.join("container");
    assert_eq!(
        inventory_tree(&source_container).expect("source raw inventory"),
        expected_inventory,
        "the retained cache instance must match its published raw inventory",
    );
    let identity =
        validate_network_identity(&source_container).expect("source semantic network identity");
    validate_frozen_template_identity(&identity).expect("frozen template identity");
    validate_semantic_anchor(&identity, PINNED_TEMPLATE_SEMANTIC_SHA256)
        .expect("pinned deterministic semantic identity");

    let root = tempfile::tempdir().expect("private direct-attester clone root");
    let destination = root.path().join("container");
    copy_tree_exact(&source_container, &destination).expect("descriptor-bound private clone");
    assert_eq!(
        inventory_tree(&destination).expect("copied raw inventory"),
        expected_inventory,
        "the node must never authenticate or mutate the immutable source cache",
    );
    FileExt::unlock(&lock).expect("unlock fixture cache");
    (root, identity)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedDirectAttestation {
    validator_index: u64,
    pubkey: consensus_signature::ValidatorPublicKeyBytes,
    committee_index: u64,
    committee_position: usize,
    committee_length: usize,
    committee_count_at_slot: u64,
    subnet: SubnetId,
    bound_head_root: Hash256,
    dependent_root: Hash256,
    signing_root: Hash256,
}

struct RootLastOwner<T> {
    owner: T,
    _root: TempDir,
}

impl<T> Deref for RootLastOwner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.owner
    }
}

struct AuthenticDirectAttesterOwners {
    _executor_exit_sender: async_channel::Sender<()>,
    chain: Arc<BeaconChain<DirectAttesterWitness>>,
    service: Arc<PqAttesterService<DirectAttesterWitness>>,
    prechecks: Arc<std::sync::atomic::AtomicUsize>,
    expected: Vec<ExpectedDirectAttestation>,
}

type AuthenticDirectAttesterFixture = RootLastOwner<AuthenticDirectAttesterOwners>;

struct RootPresenceOnOwnerDrop {
    root: PathBuf,
    observed: Arc<Mutex<Option<bool>>>,
}

impl Drop for RootPresenceOnOwnerDrop {
    fn drop(&mut self) {
        *self.observed.lock().expect("drop-order observation lock") = Some(self.root.exists());
    }
}

#[test]
fn direct_attester_fixture_drops_owners_before_root_normally_and_on_unwind() {
    for unwind in [false, true] {
        let root = tempfile::tempdir().expect("drop-order root");
        let root_path = root.path().to_path_buf();
        let observed = Arc::new(Mutex::new(None));
        let observed_by_owner = Arc::clone(&observed);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let fixture = RootLastOwner {
                _root: root,
                owner: RootPresenceOnOwnerDrop {
                    root: root_path.clone(),
                    observed: observed_by_owner,
                },
            };
            if unwind {
                panic!("exercise fixture unwind cleanup");
            }
            drop(fixture);
        }));
        assert_eq!(outcome.is_err(), unwind);
        assert_eq!(
            *observed.lock().expect("drop-order result"),
            Some(true),
            "every runtime owner must observe the fixture root until its own Drop completes",
        );
        assert!(
            !root_path.exists(),
            "the TempDir must still clean up after every runtime owner",
        );
    }
}

async fn wait_for_direct_attester_slot_one(clock: &SystemTimeSlotClock) {
    tokio::time::timeout(Duration::from_secs(360), async {
        loop {
            match clock.now() {
                Some(slot) if slot == Slot::new(1) => return,
                Some(slot) if slot > Slot::new(1) => {
                    panic!("direct-attester fixture missed slot one: {slot}")
                }
                Some(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                None => panic!("system clock unavailable"),
            }
        }
    })
    .await
    .expect("bounded wait for direct-attester slot one");
}

async fn authentic_system_slot_one_attester_fixture() -> AuthenticDirectAttesterFixture {
    let started = Instant::now();
    let (root, cached_identity) = clone_validated_attester_template();
    eprintln!(
        "PQ direct attester: validated private cache clone after {:?}",
        started.elapsed()
    );
    let (executor_exit_sender, executor_exit) = async_channel::bounded(1);
    let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(2);
    let task_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        executor_exit,
        shutdown_sender,
    );
    let container = root.path().join("container");
    let initialized = InitializedValidators::from_pq_bundle(
        container.join("bundle"),
        cached_identity.genesis_validators_root,
        cached_identity.genesis_time,
        cached_identity.registry.clone(),
        task_executor.clone(),
    )
    .await
    .expect("authenticate copied exact 16-key bundle once");
    eprintln!(
        "PQ direct attester: copied authority open after {:?}",
        started.elapsed()
    );

    let now = unix_time_now().expect("fixture clock");
    let slot_one_start = now.checked_add(180).expect("slot-one start");
    let genesis_time = slot_one_start.checked_sub(300).expect("genesis time");
    rebase_network_identity(&container, genesis_time).expect("late exact clone rebase");
    let identity = validate_network_identity(&container).expect("rebased identity");
    assert_eq!(
        identity.genesis_validators_root,
        cached_identity.genesis_validators_root
    );
    assert_eq!(identity.registry, cached_identity.registry);
    assert_eq!(identity.genesis_time, genesis_time);

    let spec = Arc::new(
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000),
    );
    let mut genesis = BeaconState::<MinimalEthSpec>::from_ssz_bytes(
        &fs::read(container.join("testnet/genesis.ssz")).expect("rebased genesis bytes"),
        &spec,
    )
    .expect("rebased genesis state");
    genesis
        .build_all_committee_caches(&spec)
        .expect("genesis committee caches");
    let slashing_path = root.path().join("slashing_protection.sqlite");
    let slashing = SlashingDatabase::create(&slashing_path).expect("fresh slashing DB");
    for entry in &identity.registry {
        slashing
            .register_validator(entry.public_key())
            .expect("register exact manifest validator");
    }
    let clock = SystemTimeSlotClock::new(
        Slot::new(0),
        Duration::from_secs(genesis_time),
        Duration::from_secs(PQ_SLOT_SECONDS),
    );
    let validator_store = Arc::new(LighthouseValidatorStore::new(
        initialized,
        slashing,
        Hash256::from(identity.genesis_validators_root),
        Arc::clone(&spec),
        None,
        clock.clone(),
        &ValidatorStoreConfig::default(),
        task_executor.clone(),
    ));
    let prechecks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prechecks_for_hook = Arc::clone(&prechecks);
    validator_store.testing_only_set_pq_attestation_precheck_hook(Some(Arc::new(move || {
        prechecks_for_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })));
    let aggregation_service =
        Arc::new(AggregationService::new().expect("sole PQ aggregation service"));
    let chain = Arc::new(
        BeaconChainBuilder::<DirectAttesterWitness>::pq_new(MinimalEthSpec)
            .store(direct_attester_store(Arc::clone(&spec)))
            .custom_spec(Arc::clone(&spec))
            .genesis_state(genesis.clone())
            .expect("persist exact 16-validator genesis")
            .pq_aggregation_service(aggregation_service)
            .task_executor(task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(DirectAttesterExecution))
            .build()
            .expect("SystemTime direct-attester chain"),
    );

    let genesis_root = chain.head_snapshot().beacon_block_root;
    let mut pre_state = genesis;
    state_processing::per_slot_processing_pq(&mut pre_state, &spec)
        .expect("advance exact slot-one parent state");
    let proposer_index = pre_state
        .get_beacon_proposer_index(Slot::new(1), &spec)
        .expect("slot-one proposer");
    let proposer_pubkey = pre_state
        .validators()
        .get(proposer_index)
        .expect("slot-one proposer validator")
        .pubkey;
    let randao = validator_store
        .randao_reveal(proposer_pubkey, Slot::new(1))
        .await
        .expect("real journal-backed RANDAO");
    let verified_randao = state_processing::prepare_pq_randao(
        &pre_state,
        Arc::clone(&chain.pq_validator_key_cache),
        Slot::new(1),
        randao.clone(),
        Arc::clone(&spec),
    )
    .expect("prepared RANDAO")
    .verify(&chain.pq_aggregation_service)
    .await
    .expect("authentic RANDAO proof");
    eprintln!(
        "PQ direct attester: RANDAO verified after {:?}",
        started.elapsed()
    );
    let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
    let BeaconBlock::Electra(inner) = &mut block else {
        panic!("frozen Electra block")
    };
    inner.slot = Slot::new(1);
    inner.proposer_index = proposer_index as u64;
    inner.parent_root = genesis_root;
    inner.body.randao_reveal = randao;
    inner.body.execution_payload.execution_payload.timestamp = pre_state
        .genesis_time()
        .checked_add(spec.get_slot_duration().as_secs())
        .expect("slot-one timestamp");
    inner.body.execution_payload.execution_payload.prev_randao = *pre_state
        .get_randao_mix(pre_state.current_epoch())
        .expect("current RANDAO mix");
    inner.body.execution_payload.execution_payload.block_hash =
        execution_layer::calculate_execution_block_hash(
            ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
            Some(inner.parent_root),
            Some(&inner.body.execution_requests),
        )
        .0;
    let local =
        state_processing::prepare_pq_local_block(&pre_state, block, verified_randao, vec![])
            .expect("sealed slot-one block");
    let mut post_state = pre_state.clone();
    let local_output = state_processing::per_block_processing_pq_local(&mut post_state, local)
        .expect("slot-one local transition");
    let (mut block, _) = local_output.into_parts();
    *block.state_root_mut() = post_state.canonical_root().expect("post-state root");
    let contents = eth2::types::FullBlockContents::new(
        block,
        Some((
            types::KzgProofs::<MinimalEthSpec>::default(),
            types::BlobsList::<MinimalEthSpec>::default(),
        )),
    );
    let SignedBlock::Full(signed) = validator_store
        .sign_block(proposer_pubkey, UnsignedBlock::Full(contents), Slot::new(1))
        .await
        .expect("real journal-backed proposal")
    else {
        panic!("full block signing preserves shape")
    };
    let signed: Arc<SignedBeaconBlock<MinimalEthSpec>> = Arc::clone(signed.signed_block());
    let block_root = signed.canonical_root();
    wait_for_direct_attester_slot_one(&clock).await;
    PqNetworkBlockProcessor::new(Arc::clone(&chain))
        .import_rpc_block(signed)
        .await
        .expect("execution-VALID slot-one import");
    assert!(chain.testing_only_pq_execution_reconciled(block_root));
    eprintln!(
        "PQ direct attester: slot one imported after {:?}",
        started.elapsed()
    );

    let identities: Arc<[PqLocalAttesterIdentity]> = identity
        .registry
        .iter()
        .map(|entry| PqLocalAttesterIdentity::new(entry.public_key(), entry.validator_index()))
        .collect::<Vec<_>>()
        .into();
    let context = chain
        .pq_local_attestation_context(identities)
        .await
        .expect("independent exact local context");
    let context = chain
        .consume_pq_local_attestation_context(context)
        .expect("independent coherent local context");
    let expected = context
        .candidates()
        .iter()
        .map(|candidate| ExpectedDirectAttestation {
            validator_index: candidate.validator_index(),
            pubkey: candidate.pubkey(),
            committee_index: candidate.committee_index(),
            committee_position: candidate.committee_position(),
            committee_length: candidate.committee_length(),
            committee_count_at_slot: candidate.committee_count_at_slot(),
            subnet: candidate.subnet(),
            bound_head_root: candidate.bound_head_root(),
            dependent_root: context.dependent_root(),
            signing_root: candidate.signing_root(),
        })
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 2, "frozen full-16 slot-one duty count");
    drop(context);
    let service = Arc::new(
        PqAttesterService::new(Arc::clone(&chain), validator_store, task_executor)
            .expect("internally sourced exact 16-key identity snapshot"),
    );
    RootLastOwner {
        _root: root,
        owner: AuthenticDirectAttesterOwners {
            _executor_exit_sender: executor_exit_sender,
            chain,
            service,
            prechecks,
            expected,
        },
    }
}

#[tokio::test(flavor = "current_thread")]
async fn direct_pq_attester_service_authentically_signs_and_proves_slot_once() {
    let started = Instant::now();
    let fixture = authentic_system_slot_one_attester_fixture().await;
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_attestation_gossip_observation_count(),
        0,
    );
    let first = fixture
        .service
        .try_attest_current_slot()
        .expect("current slot admitted")
        .wait()
        .await
        .expect("real direct service completion");
    let PqAttestationCompletion::Verified(first_metadata) = first else {
        panic!("two exact current-slot duties must verify")
    };
    eprintln!(
        "PQ direct attester: service verified after {:?}",
        started.elapsed()
    );
    assert_eq!(first_metadata.slot, Slot::new(1));
    assert_eq!(first_metadata.members.len(), fixture.expected.len());
    for (actual, expected) in first_metadata.members.iter().zip(&fixture.expected) {
        assert_eq!(actual.validator_index, expected.validator_index);
        assert_eq!(actual.pubkey, expected.pubkey);
        assert_eq!(actual.committee_index, expected.committee_index);
        assert_eq!(actual.committee_position, expected.committee_position);
        assert_eq!(actual.committee_length, expected.committee_length);
        assert_eq!(
            actual.committee_count_at_slot,
            expected.committee_count_at_slot,
        );
        assert_eq!(actual.subnet, expected.subnet);
        assert_eq!(actual.bound_head_root, expected.bound_head_root);
        assert_eq!(actual.dependent_root, expected.dependent_root);
        assert_eq!(actual.signing_root, expected.signing_root);
        assert_ne!(actual.signed_ssz_digest, [0; 32]);
    }
    assert_eq!(
        fixture.service.testing_only_owned_verified_count(),
        Some(fixture.expected.len()),
    );
    assert_eq!(
        fixture.service.testing_only_completed_verified_metadata(),
        Some(first_metadata.clone()),
    );
    let cached = fixture
        .service
        .try_attest_current_slot()
        .expect("same-slot result cached")
        .wait()
        .await
        .expect("cached direct completion");
    assert_eq!(cached, PqAttestationCompletion::Verified(first_metadata));
    assert_eq!(
        fixture.prechecks.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "same-slot cache must not invoke SQLite/signing twice",
    );
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_local_attestation_batch_verification_count(),
        1,
        "same-slot cache must not invoke the real local proof batch twice",
    );
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_attestation_gossip_observation_count(),
        0,
        "local proof must not enter remote gossip observations",
    );

    let verified_batch = fixture
        .service
        .testing_only_take_owned_verified_batch()
        .expect("take the exact authentic batch once for the network tracer");
    assert_eq!(verified_batch.len(), fixture.expected.len());
    assert_eq!(fixture.service.testing_only_owned_verified_count(), None);
    let expected_encoded = verified_batch
        .verified()
        .iter()
        .map(|verified| {
            let signed_ssz = verified.single().as_ssz_bytes();
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(&signed_ssz)),
                verified.signed_ssz_digest(),
                "the independently encoded signed single binds the verified token digest",
            );
            let fork_digest = fixture
                .chain
                .spec
                .enr_fork_id::<MinimalEthSpec>(
                    verified.slot(),
                    fixture
                        .chain
                        .head_snapshot()
                        .beacon_state
                        .genesis_validators_root(),
                )
                .fork_digest;
            let topic = IdentTopic::from(GossipTopic::new(
                GossipKind::Attestation(verified.subnet()),
                GossipEncoding::default(),
                fork_digest,
            ));
            let topic_hash = topic.hash();
            let topic_bytes = topic_hash.as_str().as_bytes();
            let mut message_id_preimage = Vec::with_capacity(
                fixture.chain.spec.message_domain_valid_snappy.len()
                    + std::mem::size_of::<usize>()
                    + topic_bytes.len()
                    + signed_ssz.len(),
            );
            message_id_preimage.extend_from_slice(&fixture.chain.spec.message_domain_valid_snappy);
            message_id_preimage.extend_from_slice(&topic_bytes.len().to_le_bytes());
            message_id_preimage.extend_from_slice(topic_bytes);
            message_id_preimage.extend_from_slice(&signed_ssz);
            let message_id_digest = Sha256::digest(message_id_preimage);
            (
                topic_hash.to_string(),
                MessageId::from(&message_id_digest[..20]),
            )
        })
        .collect::<Vec<_>>();
    let network_dir = tempfile::tempdir().expect("private no-peer network directory");
    let head = fixture.chain.head_snapshot();
    let genesis_validators_root = head.beacon_state.genesis_validators_root();
    let mut network_config = NetworkConfig::default();
    network_config.set_ipv4_listening_address(Ipv4Addr::LOCALHOST, 0, 0, 0);
    network_config.enr_address = (Some(Ipv4Addr::LOCALHOST), None);
    network_config.disable_discovery = true;
    network_config.network_dir = network_dir.path().to_path_buf();
    let network_context = Context {
        config: Arc::new(network_config),
        enr_fork_id: fixture
            .chain
            .spec
            .enr_fork_id::<MinimalEthSpec>(head.beacon_block.slot(), genesis_validators_root),
        fork_context: Arc::new(ForkContext::new::<MinimalEthSpec>(
            head.beacon_block.slot(),
            genesis_validators_root,
            &fixture.chain.spec,
        )),
        chain_spec: Arc::clone(&fixture.chain.spec),
        libp2p_registry: None,
    };
    let (network_exit_owner, network_exit) = async_channel::bounded(1);
    let (network_failure_sender, _network_failure_receiver) = futures::channel::mpsc::channel(2);
    let network_executor = task_executor::TaskExecutor::new(
        tokio::runtime::Handle::current(),
        network_exit,
        network_failure_sender,
    );
    let (_block_broadcast_sender, block_broadcast_receiver) = pq_block_broadcast_channel();
    let operational_events = testing_only_running_pq_operational_event_sink(&network_executor);
    let network_service = PqNetworkService::new(
        network_executor,
        network_context,
        fixture.chain.spec.custody_requirement,
        secp256k1::Keypair::generate().into(),
        Arc::clone(&fixture.chain),
        block_broadcast_receiver,
        Arc::clone(&operational_events),
    )
    .await
    .expect("actual no-peer PQ network service");
    let publisher = network_service.local_attestation_batch_publish_sender();
    let network_shutdown = network_service
        .start_with_shutdown_receipt()
        .await
        .expect("actual network worker live");
    let publish_receipt = publisher
        .try_publish(verified_batch)
        .expect("whole authentic verified batch admitted");
    let progress = tokio::time::timeout(Duration::from_secs(10), publish_receipt.wait())
        .await
        .expect("bounded actual no-peer publication")
        .expect("network returns the exact authentic batch owner");
    assert_eq!(progress.verified_count(), fixture.expected.len());
    let encoding_trace = progress.testing_only_encoding_trace();
    assert_eq!(encoding_trace.encoded_member_count, expected_encoded.len());
    assert_eq!(
        encoding_trace.attempted_member0_topic.as_deref(),
        Some(expected_encoded[0].0.as_str()),
    );
    assert_eq!(
        encoding_trace.attempted_member0_message_id.as_ref(),
        Some(&expected_encoded[0].1),
    );
    assert!(progress.is_retryable());
    assert!(matches!(
        progress.member_progress(),
        [PqLocalAttestationMemberPublishProgress::Retryable { message_id },
         PqLocalAttestationMemberPublishProgress::Verified]
            if !message_id.0.is_empty(),
    ));
    assert_eq!(
        fixture
            .chain
            .testing_only_pq_attestation_gossip_observation_count(),
        0,
        "local network publication must not enter remote gossip observations",
    );
    drop(progress);
    network_shutdown
        .wait()
        .await
        .expect("no-peer network service drains cleanly");
    drop(operational_events);
    drop(network_exit_owner);
    fixture
        .service
        .close_and_drain()
        .await
        .expect("drop service-owned real token batch");
    fixture.chain.close_and_drain_pq_imports().await;
    assert!(matches!(
        fixture.service.try_attest_current_slot(),
        Err(pq_attester_service::PqAttesterServiceError::Closed)
    ));
    eprintln!("PQ direct attester: drained after {:?}", started.elapsed());
}

fn unix_time_now_precise() -> Result<Duration, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))
}

fn three_slot_wait_remaining(genesis_time: u64, now: u64) -> Result<Duration, String> {
    let slot_three_boundary = THREE_SLOT_TARGET
        .checked_mul(PQ_SLOT_SECONDS)
        .and_then(|offset| genesis_time.checked_add(offset))
        .ok_or("three-slot absolute deadline overflow")?;
    let deadline = slot_three_boundary
        .checked_add(PROPOSAL_COMPLETION_SECONDS)
        .ok_or("three-slot completion deadline overflow")?;
    let remaining = deadline
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or("three-slot absolute deadline expired")?;
    Ok(Duration::from_secs(remaining))
}

fn restart_ready_remaining(genesis_time: u64, now: u64) -> Result<Duration, String> {
    restart_ready_remaining_precise(genesis_time, Duration::from_secs(now))
}

fn restart_ready_remaining_precise(genesis_time: u64, now: Duration) -> Result<Duration, String> {
    let slot_five_boundary = 5_u64
        .checked_mul(PQ_SLOT_SECONDS)
        .and_then(|offset| genesis_time.checked_add(offset))
        .ok_or("restart slot-5 boundary overflow")?;
    let ready_deadline = slot_five_boundary
        .checked_sub(RESTART_STOP_MARGIN_SECONDS)
        .ok_or("restart stop margin underflow")?;
    let remaining = Duration::from_secs(ready_deadline)
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or("restart can no longer stop safely before slot 5")?;
    Ok(remaining)
}

#[derive(Default)]
struct BoundedProcessLog {
    state: Mutex<BoundedProcessLogState>,
    changed: Condvar,
}

struct BoundedProcessLogState {
    frames: VecDeque<String>,
    events: VecDeque<PqProcessEvent>,
    event_failure: Option<PqProcessEventFailure>,
    next_event_sequence: u64,
}

impl Default for BoundedProcessLogState {
    fn default() -> Self {
        Self {
            frames: VecDeque::new(),
            events: VecDeque::new(),
            event_failure: None,
            next_event_sequence: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessRole {
    Proposer,
    Verifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessStatusDirection {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessStatusRejection {
    ForkDigest,
    FinalizedEpoch,
    FinalizedRoot,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessStartup {
    Fresh,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessBlockSource {
    Publish,
    Gossip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessEventKind {
    EventWriterReady,
    RuntimeReady {
        startup: PqProcessStartup,
        slot: u64,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        finalized_epoch: u64,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ProposalStarted {
        slot: u64,
        parent_root: Hash256,
    },
    BlockPersisted {
        source: PqProcessBlockSource,
        slot: u64,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        finalized_epoch: u64,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ExecutionReconciled {
        source: PqProcessBlockSource,
        slot: u64,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        finalized_epoch: u64,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ProposalPublished {
        slot: u64,
        block_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    GossipImported {
        slot: u64,
        block_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    PeerConnected {
        peer_digest: [u8; 16],
        direction: PqProcessConnectionDirection,
    },
    StatusSent {
        peer_digest: [u8; 16],
        direction: PqProcessStatusDirection,
    },
    StatusRejected {
        peer_digest: [u8; 16],
        code: PqProcessStatusRejection,
    },
    PeerCompatible {
        peer_digest: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PqProcessEvent {
    sequence: u64,
    role: PqProcessRole,
    kind: PqProcessEventKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessEventFailure {
    Malformed,
    Sequence,
    Capacity,
}

fn exact_field<'a>(field: &'a str, name: &str) -> Result<&'a str, PqProcessEventFailure> {
    field
        .strip_prefix(name)
        .filter(|value| !value.is_empty())
        .ok_or(PqProcessEventFailure::Malformed)
}

fn parse_peer_digest(field: &str) -> Result<[u8; 16], PqProcessEventFailure> {
    let encoded = exact_field(field, "peer_digest=")?;
    if encoded.len() != 32 || encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let mut digest = [0; 16];
    hex::decode_to_slice(encoded, &mut digest).map_err(|_| PqProcessEventFailure::Malformed)?;
    Ok(digest)
}

fn parse_canonical_u64(field: &str, name: &str) -> Result<u64, PqProcessEventFailure> {
    let text = exact_field(field, name)?;
    let value = text
        .parse::<u64>()
        .map_err(|_| PqProcessEventFailure::Malformed)?;
    if value.to_string() != text {
        return Err(PqProcessEventFailure::Malformed);
    }
    Ok(value)
}

fn parse_hash256(field: &str, name: &str) -> Result<Hash256, PqProcessEventFailure> {
    let encoded = exact_field(field, name)?;
    let Some(hex) = encoded.strip_prefix("0x") else {
        return Err(PqProcessEventFailure::Malformed);
    };
    if hex.len() != 64 || hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(hex, &mut bytes).map_err(|_| PqProcessEventFailure::Malformed)?;
    Ok(Hash256::from(bytes))
}

fn parse_signed_ssz_digest(field: &str) -> Result<[u8; 32], PqProcessEventFailure> {
    let encoded = exact_field(field, "signed_ssz_digest=")?;
    if encoded.len() != 64 || encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(encoded, &mut digest).map_err(|_| PqProcessEventFailure::Malformed)?;
    Ok(digest)
}

fn parse_block_source(field: &str) -> Result<PqProcessBlockSource, PqProcessEventFailure> {
    match exact_field(field, "source=")? {
        "publish" => Ok(PqProcessBlockSource::Publish),
        "gossip" => Ok(PqProcessBlockSource::Gossip),
        _ => Err(PqProcessEventFailure::Malformed),
    }
}

fn parse_pq_process_event(line: &str) -> Result<PqProcessEvent, PqProcessEventFailure> {
    let fields = line.split(' ').collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) || fields.first() != Some(&PQ_EVENT_PREFIX) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let event = exact_field(
        fields
            .get(1)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "event=",
    )?;
    let sequence_text = exact_field(
        fields
            .get(2)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "sequence=",
    )?;
    let sequence = sequence_text
        .parse::<u64>()
        .map_err(|_| PqProcessEventFailure::Malformed)?;
    if sequence.to_string() != sequence_text || sequence == 0 {
        return Err(PqProcessEventFailure::Malformed);
    }
    let role = match exact_field(
        fields
            .get(3)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "role=",
    )? {
        "proposer" => PqProcessRole::Proposer,
        "verifier" => PqProcessRole::Verifier,
        _ => return Err(PqProcessEventFailure::Malformed),
    };
    let kind = match event {
        "EventWriterReady" if fields.len() == 4 => PqProcessEventKind::EventWriterReady,
        "RuntimeReady" if fields.len() == 11 => PqProcessEventKind::RuntimeReady {
            startup: match exact_field(fields[4], "startup=")? {
                "fresh" => PqProcessStartup::Fresh,
                "resume" => PqProcessStartup::Resume,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
            slot: parse_canonical_u64(fields[5], "slot=")?,
            block_root: parse_hash256(fields[6], "block_root=")?,
            execution_hash: ExecutionBlockHash::from_root(parse_hash256(
                fields[7],
                "execution_hash=",
            )?),
            finalized_epoch: parse_canonical_u64(fields[8], "finalized_epoch=")?,
            finalized_root: parse_hash256(fields[9], "finalized_root=")?,
            signed_ssz_digest: parse_signed_ssz_digest(fields[10])?,
        },
        "ProposalStarted" if fields.len() == 6 => PqProcessEventKind::ProposalStarted {
            slot: parse_canonical_u64(fields[4], "slot=")?,
            parent_root: parse_hash256(fields[5], "parent_root=")?,
        },
        "BlockPersisted" if fields.len() == 11 => PqProcessEventKind::BlockPersisted {
            source: parse_block_source(fields[4])?,
            slot: parse_canonical_u64(fields[5], "slot=")?,
            block_root: parse_hash256(fields[6], "block_root=")?,
            execution_hash: ExecutionBlockHash::from_root(parse_hash256(
                fields[7],
                "execution_hash=",
            )?),
            finalized_epoch: parse_canonical_u64(fields[8], "finalized_epoch=")?,
            finalized_root: parse_hash256(fields[9], "finalized_root=")?,
            signed_ssz_digest: parse_signed_ssz_digest(fields[10])?,
        },
        "ExecutionReconciled" if fields.len() == 11 => PqProcessEventKind::ExecutionReconciled {
            source: parse_block_source(fields[4])?,
            slot: parse_canonical_u64(fields[5], "slot=")?,
            block_root: parse_hash256(fields[6], "block_root=")?,
            execution_hash: ExecutionBlockHash::from_root(parse_hash256(
                fields[7],
                "execution_hash=",
            )?),
            finalized_epoch: parse_canonical_u64(fields[8], "finalized_epoch=")?,
            finalized_root: parse_hash256(fields[9], "finalized_root=")?,
            signed_ssz_digest: parse_signed_ssz_digest(fields[10])?,
        },
        "ProposalPublished" if fields.len() == 7 => PqProcessEventKind::ProposalPublished {
            slot: parse_canonical_u64(fields[4], "slot=")?,
            block_root: parse_hash256(fields[5], "block_root=")?,
            signed_ssz_digest: parse_signed_ssz_digest(fields[6])?,
        },
        "GossipImported" if fields.len() == 7 => PqProcessEventKind::GossipImported {
            slot: parse_canonical_u64(fields[4], "slot=")?,
            block_root: parse_hash256(fields[5], "block_root=")?,
            signed_ssz_digest: parse_signed_ssz_digest(fields[6])?,
        },
        "PeerConnected" if fields.len() == 6 => PqProcessEventKind::PeerConnected {
            peer_digest: parse_peer_digest(fields[4])?,
            direction: match exact_field(fields[5], "direction=")? {
                "incoming" => PqProcessConnectionDirection::Incoming,
                "outgoing" => PqProcessConnectionDirection::Outgoing,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "StatusSent" if fields.len() == 6 => PqProcessEventKind::StatusSent {
            peer_digest: parse_peer_digest(fields[4])?,
            direction: match exact_field(fields[5], "direction=")? {
                "request" => PqProcessStatusDirection::Request,
                "response" => PqProcessStatusDirection::Response,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "StatusRejected" if fields.len() == 6 => PqProcessEventKind::StatusRejected {
            peer_digest: parse_peer_digest(fields[4])?,
            code: match exact_field(fields[5], "code=")? {
                "fork_digest" => PqProcessStatusRejection::ForkDigest,
                "finalized_epoch" => PqProcessStatusRejection::FinalizedEpoch,
                "finalized_root" => PqProcessStatusRejection::FinalizedRoot,
                "capacity" => PqProcessStatusRejection::Capacity,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "PeerCompatible" if fields.len() == 5 => PqProcessEventKind::PeerCompatible {
            peer_digest: parse_peer_digest(fields[4])?,
        },
        _ => return Err(PqProcessEventFailure::Malformed),
    };
    Ok(PqProcessEvent {
        sequence,
        role,
        kind,
    })
}

fn peer_digest_from_enr(enr: &discv5::enr::Enr<discv5::enr::CombinedKey>) -> [u8; 16] {
    let digest = Sha256::digest(enr.peer_id().to_bytes());
    let mut peer_digest = [0; 16];
    peer_digest.copy_from_slice(&digest[..16]);
    peer_digest
}

fn validate_compatible_event_trace(
    events: &[PqProcessEvent],
    role: PqProcessRole,
    connection_direction: PqProcessConnectionDirection,
    peer_digest: [u8; 16],
) -> Result<(), String> {
    if events.len() != 6
        || events[0]
            != (PqProcessEvent {
                sequence: 1,
                role,
                kind: PqProcessEventKind::EventWriterReady,
            })
        || events.iter().enumerate().any(|(offset, event)| {
            event.role != role || event.sequence != u64::try_from(offset + 1).unwrap_or(u64::MAX)
        })
    {
        return Err(format!("invalid PQ compatible event frame: {events:?}"));
    }
    let positions = |predicate: fn(&PqProcessEventKind) -> bool| {
        events
            .iter()
            .enumerate()
            .filter_map(|(position, event)| predicate(&event.kind).then_some(position))
            .collect::<Vec<_>>()
    };
    let ready = positions(|event| {
        matches!(
            event,
            PqProcessEventKind::RuntimeReady {
                startup: PqProcessStartup::Fresh,
                slot: 0,
                block_root,
                execution_hash,
                finalized_epoch: 0,
                finalized_root,
                signed_ssz_digest,
            } if *block_root != Hash256::ZERO
                && *execution_hash == ExecutionBlockHash::zero()
                && *finalized_root == Hash256::ZERO
                && *signed_ssz_digest != [0; 32]
        )
    });
    let connected = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| {
            (event.kind
                == PqProcessEventKind::PeerConnected {
                    peer_digest,
                    direction: connection_direction,
                })
            .then_some(position)
        })
        .collect::<Vec<_>>();
    let request = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| {
            (event.kind
                == PqProcessEventKind::StatusSent {
                    peer_digest,
                    direction: PqProcessStatusDirection::Request,
                })
            .then_some(position)
        })
        .collect::<Vec<_>>();
    let response = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| {
            (event.kind
                == PqProcessEventKind::StatusSent {
                    peer_digest,
                    direction: PqProcessStatusDirection::Response,
                })
            .then_some(position)
        })
        .collect::<Vec<_>>();
    let compatible = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| {
            (event.kind == PqProcessEventKind::PeerCompatible { peer_digest }).then_some(position)
        })
        .collect::<Vec<_>>();
    if ready.len() != 1
        || connected.len() != 1
        || request.len() != 1
        || response.len() != 1
        || compatible.len() != 1
        || !(connected[0] < request[0] && request[0] < response[0] && request[0] < compatible[0])
    {
        return Err(format!("invalid PQ compatible event topology: {events:?}"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PqProcessBlockIdentity {
    slot: u64,
    block_root: Hash256,
    execution_hash: ExecutionBlockHash,
    finalized_epoch: u64,
    finalized_root: Hash256,
    signed_ssz_digest: [u8; 32],
}

fn persisted_identity(
    event: &PqProcessEvent,
    expected_role: PqProcessRole,
    expected_source: PqProcessBlockSource,
) -> Option<PqProcessBlockIdentity> {
    match event {
        PqProcessEvent {
            role,
            kind:
                PqProcessEventKind::BlockPersisted {
                    source,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch,
                    finalized_root,
                    signed_ssz_digest,
                },
            ..
        } if *role == expected_role && *source == expected_source => Some(PqProcessBlockIdentity {
            slot: *slot,
            block_root: *block_root,
            execution_hash: *execution_hash,
            finalized_epoch: *finalized_epoch,
            finalized_root: *finalized_root,
            signed_ssz_digest: *signed_ssz_digest,
        }),
        _ => None,
    }
}

fn reconciled_identity(
    event: &PqProcessEvent,
    expected_role: PqProcessRole,
    expected_source: PqProcessBlockSource,
) -> Option<PqProcessBlockIdentity> {
    match event {
        PqProcessEvent {
            role,
            kind:
                PqProcessEventKind::ExecutionReconciled {
                    source,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch,
                    finalized_root,
                    signed_ssz_digest,
                },
            ..
        } if *role == expected_role && *source == expected_source => Some(PqProcessBlockIdentity {
            slot: *slot,
            block_root: *block_root,
            execution_hash: *execution_hash,
            finalized_epoch: *finalized_epoch,
            finalized_root: *finalized_root,
            signed_ssz_digest: *signed_ssz_digest,
        }),
        _ => None,
    }
}

fn validate_engine_history(
    history: &[MockEngineAuditEvent],
    identities: &[PqProcessBlockIdentity],
    expect_get_payload: bool,
) -> Result<(), String> {
    let mut expected = vec![MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash: ExecutionBlockHash::zero(),
        safe_block_hash: ExecutionBlockHash::zero(),
        finalized_block_hash: ExecutionBlockHash::zero(),
        has_payload_attributes: false,
    }];
    let mut parent_execution_hash = ExecutionBlockHash::zero();
    for identity in identities {
        if expect_get_payload {
            expected.extend([
                MockEngineAuditEvent::ForkchoiceUpdated {
                    head_block_hash: parent_execution_hash,
                    safe_block_hash: ExecutionBlockHash::zero(),
                    finalized_block_hash: ExecutionBlockHash::zero(),
                    has_payload_attributes: true,
                },
                MockEngineAuditEvent::GetPayload {
                    block_hash: identity.execution_hash,
                    blob_count: 0,
                },
            ]);
        }
        expected.extend([
            MockEngineAuditEvent::NewPayload {
                block_hash: identity.execution_hash,
                blob_count: 0,
            },
            MockEngineAuditEvent::ForkchoiceUpdated {
                head_block_hash: identity.execution_hash,
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
                has_payload_attributes: false,
            },
        ]);
        parent_execution_hash = identity.execution_hash;
    }
    if history != expected {
        return Err(format!(
            "unexpected complete Engine audit:\nexpected={expected:?}\nactual={history:?}"
        ));
    }
    Ok(())
}

fn validate_restart_idempotence(
    proposer_events: &[PqProcessEvent],
    verifier_events: &[PqProcessEvent],
    expected: PqProcessBlockIdentity,
    proposer_engine_before: &[MockEngineAuditEvent],
    proposer_engine_after: &[MockEngineAuditEvent],
    verifier_engine_before: &[MockEngineAuditEvent],
    verifier_engine_after: &[MockEngineAuditEvent],
) -> Result<(), String> {
    let validate_events = |events: &[PqProcessEvent], role: PqProcessRole| {
        if events.first()
            != Some(&PqProcessEvent {
                sequence: 1,
                role,
                kind: PqProcessEventKind::EventWriterReady,
            })
            || events.iter().enumerate().any(|(offset, event)| {
                event.role != role
                    || event.sequence != u64::try_from(offset + 1).unwrap_or(u64::MAX)
            })
        {
            return Err(format!("invalid resumed event frame: {events:?}"));
        }
        let runtime_ready = events
            .iter()
            .filter_map(|event| match event.kind {
                PqProcessEventKind::RuntimeReady {
                    startup,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch,
                    finalized_root,
                    signed_ssz_digest,
                } => Some((
                    startup,
                    PqProcessBlockIdentity {
                        slot,
                        block_root,
                        execution_hash,
                        finalized_epoch,
                        finalized_root,
                        signed_ssz_digest,
                    },
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        if runtime_ready != [(PqProcessStartup::Resume, expected)] {
            return Err(format!(
                "resume RuntimeReady does not match the persisted slot-3 identity: {runtime_ready:?}"
            ));
        }
        if events.iter().any(|event| {
            matches!(
                event.kind,
                PqProcessEventKind::ProposalStarted { .. }
                    | PqProcessEventKind::BlockPersisted { .. }
                    | PqProcessEventKind::ExecutionReconciled { .. }
                    | PqProcessEventKind::ProposalPublished { .. }
                    | PqProcessEventKind::GossipImported { .. }
            )
        }) {
            return Err("block lifecycle began during the idempotent restart window".into());
        }
        Ok(())
    };
    validate_events(proposer_events, PqProcessRole::Proposer)?;
    validate_events(verifier_events, PqProcessRole::Verifier)?;

    let validate_engine = |before: &[MockEngineAuditEvent], after: &[MockEngineAuditEvent]| {
        let expected_replay = MockEngineAuditEvent::ForkchoiceUpdated {
            head_block_hash: expected.execution_hash,
            safe_block_hash: ExecutionBlockHash::zero(),
            finalized_block_hash: ExecutionBlockHash::zero(),
            has_payload_attributes: false,
        };
        if after.len()
            != before
                .len()
                .checked_add(1)
                .ok_or("Engine history overflow")?
            || !after.starts_with(before)
            || after.last() != Some(&expected_replay)
        {
            return Err(format!(
                "restart Engine history is not one exact no-attributes replay:\nbefore={before:?}\nafter={after:?}"
            ));
        }
        Ok(())
    };
    validate_engine(proposer_engine_before, proposer_engine_after)?;
    validate_engine(verifier_engine_before, verifier_engine_after)?;
    Ok(())
}

fn validate_three_slot_process_convergence(
    proposer: &[PqProcessEvent],
    verifier: &[PqProcessEvent],
    proposer_engine: &[MockEngineAuditEvent],
    verifier_engine: &[MockEngineAuditEvent],
) -> Result<(), String> {
    let proposer_runtime_events = proposer
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event.kind, PqProcessEventKind::RuntimeReady { .. }))
        .collect::<Vec<_>>();
    if proposer_runtime_events.len() != 1 {
        return Err("proposer lacks exactly one genesis RuntimeReady identity".into());
    }
    let (proposer_ready_position, proposer_runtime_event) = proposer_runtime_events[0];
    let runtime_root = match proposer_runtime_event.kind {
        PqProcessEventKind::RuntimeReady {
            slot: 0,
            block_root,
            finalized_epoch: 0,
            finalized_root,
            ..
        } if finalized_root == Hash256::ZERO => block_root,
        _ => return Err("proposer RuntimeReady is not the genesis identity".into()),
    };
    let verifier_runtime_events = verifier
        .iter()
        .enumerate()
        .filter(|(_, event)| matches!(event.kind, PqProcessEventKind::RuntimeReady { .. }))
        .collect::<Vec<_>>();
    if verifier_runtime_events.len() != 1 {
        return Err("verifier RuntimeReady does not match proposer genesis".into());
    }
    let (verifier_ready_position, verifier_runtime_event) = verifier_runtime_events[0];
    if !matches!(
        verifier_runtime_event.kind,
        PqProcessEventKind::RuntimeReady {
            slot: 0,
            block_root,
            finalized_epoch: 0,
            finalized_root,
            ..
        } if block_root == runtime_root && finalized_root == Hash256::ZERO
    ) {
        return Err("verifier RuntimeReady does not match proposer genesis".into());
    }
    let proposer_compatible = proposer
        .iter()
        .position(|event| matches!(event.kind, PqProcessEventKind::PeerCompatible { .. }))
        .ok_or("proposer lacks compatible peer")?;
    let verifier_compatible = verifier
        .iter()
        .position(|event| matches!(event.kind, PqProcessEventKind::PeerCompatible { .. }))
        .ok_or("verifier lacks compatible peer")?;
    let starts = proposer
        .iter()
        .enumerate()
        .filter_map(|(position, event)| match event.kind {
            PqProcessEventKind::ProposalStarted { slot, parent_root } => {
                Some((position, slot, parent_root))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if starts.len() != 3
        || starts[0].0 <= proposer_compatible
        || starts[0].0 <= proposer_ready_position
    {
        return Err(format!(
            "expected three post-compatibility proposals: {starts:?}"
        ));
    }
    if starts[1].1 != starts[0].1.checked_add(1).ok_or("slot overflow")?
        || starts[2].1 != starts[1].1.checked_add(1).ok_or("slot overflow")?
    {
        return Err(format!("proposal slots are not consecutive: {starts:?}"));
    }
    let proposer_persisted = proposer
        .iter()
        .filter_map(|event| {
            persisted_identity(
                event,
                PqProcessRole::Proposer,
                PqProcessBlockSource::Publish,
            )
        })
        .collect::<Vec<_>>();
    let proposer_reconciled = proposer
        .iter()
        .filter_map(|event| {
            reconciled_identity(
                event,
                PqProcessRole::Proposer,
                PqProcessBlockSource::Publish,
            )
        })
        .collect::<Vec<_>>();
    let verifier_persisted = verifier
        .iter()
        .filter_map(|event| {
            persisted_identity(event, PqProcessRole::Verifier, PqProcessBlockSource::Gossip)
        })
        .collect::<Vec<_>>();
    let verifier_reconciled = verifier
        .iter()
        .filter_map(|event| {
            reconciled_identity(event, PqProcessRole::Verifier, PqProcessBlockSource::Gossip)
        })
        .collect::<Vec<_>>();
    if proposer_persisted.len() != 3
        || proposer_persisted != proposer_reconciled
        || proposer_persisted != verifier_persisted
        || proposer_persisted != verifier_reconciled
    {
        return Err("persisted/reconciled identities do not converge exactly".into());
    }
    let published = proposer
        .iter()
        .filter_map(|event| match event.kind {
            PqProcessEventKind::ProposalPublished {
                slot,
                block_root,
                signed_ssz_digest,
            } => Some((slot, block_root, signed_ssz_digest)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let imported = verifier
        .iter()
        .filter_map(|event| match event.kind {
            PqProcessEventKind::GossipImported {
                slot,
                block_root,
                signed_ssz_digest,
            } => Some((slot, block_root, signed_ssz_digest)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected_publications = proposer_persisted
        .iter()
        .map(|identity| {
            (
                identity.slot,
                identity.block_root,
                identity.signed_ssz_digest,
            )
        })
        .collect::<Vec<_>>();
    if published != expected_publications || imported != expected_publications {
        return Err("published/gossip signed SSZ identities do not converge".into());
    }
    for (index, ((_, slot, parent_root), identity)) in
        starts.iter().zip(&proposer_persisted).enumerate()
    {
        let expected_parent = if index == 0 {
            runtime_root
        } else {
            proposer_persisted[index - 1].block_root
        };
        if *slot != identity.slot
            || *parent_root != expected_parent
            || identity.finalized_epoch != 0
            || identity.finalized_root != Hash256::ZERO
        {
            return Err("proposal parent/finalized identity mismatch".into());
        }
        let proposer_positions = (
            starts[index].0,
            proposer
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::BlockPersisted {
                            source: PqProcessBlockSource::Publish,
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing proposer persistence")?,
            proposer
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::ExecutionReconciled {
                            source: PqProcessBlockSource::Publish,
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing proposer reconciliation")?,
            proposer
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::ProposalPublished {
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing proposer publication")?,
        );
        if !(proposer_positions.0 < proposer_positions.1
            && proposer_positions.1 < proposer_positions.2
            && proposer_positions.2 < proposer_positions.3)
        {
            return Err("proposer event order is not start/persist/reconcile/publish".into());
        }
        let verifier_positions = (
            verifier
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::BlockPersisted {
                            source: PqProcessBlockSource::Gossip,
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing verifier persistence")?,
            verifier
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::ExecutionReconciled {
                            source: PqProcessBlockSource::Gossip,
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing verifier reconciliation")?,
            verifier
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::GossipImported {
                            slot: event_slot,
                            ..
                        } if event_slot == identity.slot
                    )
                })
                .ok_or("missing verifier gossip import")?,
        );
        if verifier_positions.0 <= verifier_compatible
            || verifier_positions.0 <= verifier_ready_position
            || !(verifier_positions.0 < verifier_positions.1
                && verifier_positions.1 < verifier_positions.2)
        {
            return Err("verifier event order is not compatible/persist/reconcile/import".into());
        }
        if index > 0 {
            let previous_slot = proposer_persisted[index - 1].slot;
            let previous_publication = proposer
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        PqProcessEventKind::ProposalPublished {
                            slot: event_slot,
                            ..
                        } if event_slot == previous_slot
                    )
                })
                .ok_or("missing previous proposer publication")?;
            if starts[index].0 <= previous_publication {
                return Err("next proposal started before previous publication completed".into());
            }
        }
    }
    validate_engine_history(proposer_engine, &proposer_persisted, true)?;
    validate_engine_history(verifier_engine, &proposer_persisted, false)?;
    Ok(())
}

impl BoundedProcessLog {
    fn push(&self, stream: &'static str, frame: &[u8]) {
        let mut state = self.state.lock().expect("process log lock");
        if stream == "stdout" && frame.starts_with(PQ_EVENT_PREFIX.as_bytes()) {
            if state.event_failure.is_some() {
                return;
            }
            let event = std::str::from_utf8(frame)
                .map_err(|_| PqProcessEventFailure::Malformed)
                .and_then(parse_pq_process_event);
            match event {
                Ok(event) if event.sequence != state.next_event_sequence => {
                    state.event_failure = Some(PqProcessEventFailure::Sequence);
                }
                Ok(_) if state.events.len() == MAX_RETAINED_PQ_EVENTS => {
                    state.event_failure = Some(PqProcessEventFailure::Capacity);
                }
                Ok(event) => {
                    state.next_event_sequence = match state.next_event_sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => {
                            state.event_failure = Some(PqProcessEventFailure::Sequence);
                            return;
                        }
                    };
                    state.events.push_back(event);
                }
                Err(error) => state.event_failure = Some(error),
            }
            self.changed.notify_all();
            return;
        }
        if state.frames.len() == MAX_RETAINED_LOG_FRAMES {
            state.frames.pop_front();
        }
        let rendered = format!("{stream}:{}", String::from_utf8_lossy(frame).trim_end());
        state.frames.push_back(rendered);
        self.changed.notify_all();
    }

    fn contains_frame(&self, needle: &str) -> bool {
        let state = self.state.lock().expect("process log lock");
        state.frames.iter().any(|frame| frame.contains(needle))
    }

    fn events(&self) -> Result<Vec<PqProcessEvent>, PqProcessEventFailure> {
        let state = self.state.lock().expect("process log lock");
        match state.event_failure {
            Some(error) => Err(error),
            None => Ok(state.events.iter().copied().collect()),
        }
    }

    fn event_failure(&self) -> Option<PqProcessEventFailure> {
        self.state.lock().expect("process log lock").event_failure
    }

    fn snapshot(&self) -> String {
        let state = self.state.lock().expect("process log lock");
        let mut snapshot = state
            .events
            .iter()
            .map(|event| format!("event:{event:?}"))
            .collect::<Vec<_>>();
        if let Some(error) = state.event_failure {
            snapshot.push(format!("event_failure:{error:?}"));
        }
        snapshot.extend(state.frames.iter().cloned());
        snapshot.join("\n")
    }
}

struct ChildNode {
    name: &'static str,
    child: Child,
    log: Arc<BoundedProcessLog>,
    readers: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
enum ChildStartupError {
    EarlyExit {
        status: std::process::ExitStatus,
        diagnostics: String,
    },
    EnrTimeout {
        diagnostics: String,
    },
    EnrInspection(String),
}

impl std::fmt::Display for ChildStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EarlyExit {
                status,
                diagnostics,
            } => write!(
                formatter,
                "child exited during startup: {status}\n{diagnostics}"
            ),
            Self::EnrTimeout { diagnostics } => {
                write!(
                    formatter,
                    "timed out waiting for bounded ENR\n{diagnostics}"
                )
            }
            Self::EnrInspection(error) => write!(formatter, "inspect bounded ENR: {error}"),
        }
    }
}

impl ChildNode {
    fn spawn(name: &'static str, args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("start {name} Lighthouse process: {error}"));
        let log = Arc::new(BoundedProcessLog::default());
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let readers = vec![
            spawn_bounded_reader("stdout", stdout, Arc::clone(&log)),
            spawn_bounded_reader("stderr", stderr, Arc::clone(&log)),
        ];
        Self {
            name,
            child,
            log,
            readers,
        }
    }

    async fn wait_for_event_count(
        &mut self,
        event_count: usize,
        timeout: Duration,
    ) -> Vec<PqProcessEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.log.events() {
                Ok(events) if events.len() >= event_count => return events,
                Ok(_) => {}
                Err(error) => panic!(
                    "{} emitted an invalid PQ event stream: {error:?}\n{}",
                    self.name,
                    self.log.snapshot()
                ),
            }
            if let Some(status) = self.child.try_wait().expect("poll Lighthouse child") {
                panic!(
                    "{} exited before {event_count} PQ events: {status}\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "{} did not emit {event_count} PQ events before timeout\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_event_kind_count(
        &mut self,
        event_count: usize,
        timeout: Duration,
        predicate: impl Fn(&PqProcessEventKind) -> bool,
    ) -> Vec<PqProcessEvent> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("bounded process event deadline");
        self.wait_for_event_kind_count_until(event_count, deadline, predicate)
            .await
    }

    async fn wait_for_event_kind_count_until(
        &mut self,
        event_count: usize,
        deadline: Instant,
        predicate: impl Fn(&PqProcessEventKind) -> bool,
    ) -> Vec<PqProcessEvent> {
        loop {
            match self.log.events() {
                Ok(events)
                    if events.iter().filter(|event| predicate(&event.kind)).count()
                        >= event_count =>
                {
                    return events;
                }
                Ok(_) => {}
                Err(error) => panic!(
                    "{} emitted an invalid PQ event stream: {error:?}\n{}",
                    self.name,
                    self.log.snapshot()
                ),
            }
            if let Some(status) = self.child.try_wait().expect("poll Lighthouse child") {
                panic!(
                    "{} exited before {event_count} target PQ events: {status}\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "{} did not emit {event_count} target PQ events before timeout\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_enr(
        &mut self,
        network_dir: &Path,
        timeout: Duration,
    ) -> Result<String, ChildStartupError> {
        let path = network_dir.join("enr.dat");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|error| {
                ChildStartupError::EnrInspection(format!("poll Lighthouse child: {error}"))
            })? {
                self.join_readers();
                return Err(ChildStartupError::EarlyExit {
                    status,
                    diagnostics: self.log.snapshot(),
                });
            }
            match open_bounded_regular_nofollow(&path, MAX_ENR_BYTES) {
                Ok(bytes) => {
                    let enr = String::from_utf8(bytes)
                        .map_err(|_| ChildStartupError::EnrInspection("ENR is not UTF-8".into()))?;
                    let enr = enr.trim();
                    if enr
                        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
                        .is_ok()
                    {
                        return Ok(enr.to_owned());
                    }
                }
                Err(error)
                    if error.contains("No such file") || error.contains("changed while read") => {}
                Err(error) => return Err(ChildStartupError::EnrInspection(error)),
            }
            if Instant::now() >= deadline {
                return Err(ChildStartupError::EnrTimeout {
                    diagnostics: self.log.snapshot(),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            reader.join().expect("bounded pipe reader");
        }
    }

    fn signal_interrupt(&mut self) {
        assert!(
            self.child
                .try_wait()
                .expect("poll child before SIGINT")
                .is_none(),
            "{} exited before SIGINT",
            self.name
        );
        let pid = libc::pid_t::try_from(self.child.id()).expect("child PID fits pid_t");
        // SAFETY: the PID belongs to the live child owned by this guard.
        let result = unsafe { libc::kill(pid, libc::SIGINT) };
        assert_eq!(result, 0, "send SIGINT to {}", self.name);
    }

    async fn stop(mut self) {
        self.signal_interrupt();
        self.finish_stop_after_signal().await;
    }

    async fn finish_stop_after_signal(mut self) {
        let deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll stopped child") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let status = self.child.wait().expect("reap killed Lighthouse child");
                panic!(
                    "{} did not stop after SIGINT: {status}\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        self.join_readers();
        assert!(
            status.success(),
            "{} failed during graceful shutdown: {status}\n{}",
            self.name,
            self.log.snapshot()
        );
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    stream: &'static str,
    mut reader: R,
    log: Arc<BoundedProcessLog>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        let mut frame = Vec::with_capacity(8192);
        loop {
            let count = match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            for byte in &chunk[..count] {
                if *byte == b'\n' {
                    log.push(stream, &frame);
                    frame.clear();
                } else if frame.len() < MAX_LOG_FRAME_BYTES {
                    frame.push(*byte);
                } else {
                    log.push(stream, b"<oversized child log frame discarded>");
                    frame.clear();
                }
            }
        }
        if !frame.is_empty() {
            log.push(stream, &frame);
        }
    })
}

struct LaunchFixture {
    _root: TempDir,
    testnet_dir: PathBuf,
    bundle_dir: PathBuf,
    jwt_proposer: PathBuf,
    jwt_verifier: PathBuf,
    proposer_data: PathBuf,
    proposer_network: PathBuf,
    verifier_data: PathBuf,
    verifier_network: PathBuf,
    genesis_time: u64,
}

impl LaunchFixture {
    fn materialize(
        template: &Path,
        authenticated: &AuthenticatedTemplate,
        preparation: &mut TemplatePreparationAudit,
    ) -> Self {
        let root = tempfile::tempdir().expect("e4f test root");
        let staging = root.path().join("container.staging");
        copy_tree_exact(&template.join("container"), &staging).expect("private template clone");
        let copied = inventory_tree(&staging).expect("inventory private template clone");
        assert_eq!(
            copied, authenticated.inventory,
            "the exact copied source must still match the authenticated cache instance"
        );
        preparation
            .record_copy()
            .expect("record exact template copy");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture genesis clock")
            .as_secs();
        let genesis_time = preparation
            .select_genesis_time(now)
            .expect("select genesis only after expensive authentication and copy");
        rebase_network_identity(&staging, genesis_time).expect("atomic network identity rebase");
        let rebased =
            validate_network_identity(&staging).expect("bounded post-rebase network identity");
        assert_eq!(
            authenticated.identity.genesis_validators_root,
            rebased.genesis_validators_root
        );
        assert_eq!(authenticated.identity.registry, rebased.registry);
        assert_eq!(rebased.genesis_time, genesis_time);
        let container = root.path().join("container");
        fs::rename(&staging, &container).expect("publish private run container");
        File::open(root.path())
            .expect("run root")
            .sync_all()
            .expect("sync private run container");
        let testnet_dir = container.join("testnet");
        let bundle_dir = container.join("bundle");
        let published =
            validate_network_identity(&container).expect("bounded published network identity");
        assert_eq!(
            published.genesis_validators_root,
            authenticated.identity.genesis_validators_root
        );
        assert_eq!(published.registry, authenticated.identity.registry);
        assert_eq!(published.genesis_time, genesis_time);

        let jwt_proposer = root.path().join("proposer.jwt");
        let jwt_verifier = root.path().join("verifier.jwt");
        write_private(&jwt_proposer, hex::encode(DEFAULT_JWT_SECRET).as_bytes());
        write_private(&jwt_verifier, hex::encode(DEFAULT_JWT_SECRET).as_bytes());
        assert_ne!(jwt_proposer, jwt_verifier);

        Self {
            proposer_data: root.path().join("proposer-data"),
            proposer_network: root.path().join("proposer-network"),
            verifier_data: root.path().join("verifier-data"),
            verifier_network: root.path().join("verifier-network"),
            _root: root,
            testnet_dir,
            bundle_dir,
            jwt_proposer,
            jwt_verifier,
            genesis_time,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TemplateInventory {
    entries: usize,
    bytes: u64,
    digest: String,
}

impl TemplateInventory {
    fn encode(&self) -> String {
        format!(
            "version={TEMPLATE_VERSION}\nentries={}\nbytes={}\nsha256={}\n",
            self.entries, self.bytes, self.digest
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1024 {
            return Err("template inventory is oversized".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "template inventory is not UTF-8")?;
        let mut lines = text.lines();
        if lines.next() != Some(&format!("version={TEMPLATE_VERSION}")) {
            return Err("template inventory version mismatch".into());
        }
        let entries = parse_inventory_number(lines.next(), "entries")?;
        let bytes = parse_inventory_number(lines.next(), "bytes")?;
        let digest = lines
            .next()
            .and_then(|line| line.strip_prefix("sha256="))
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or("invalid template inventory digest")?
            .to_owned();
        if lines.next().is_some() {
            return Err("unexpected template inventory fields".into());
        }
        Ok(Self {
            entries: usize::try_from(entries).map_err(|_| "entry count does not fit usize")?,
            bytes,
            digest,
        })
    }
}

fn parse_inventory_number(line: Option<&str>, field: &str) -> Result<u64, String> {
    line.and_then(|line| line.strip_prefix(&format!("{field}=")))
        .ok_or_else(|| format!("missing template inventory {field}"))?
        .parse()
        .map_err(|_| format!("invalid template inventory {field}"))
}

fn prepare_launch_fixture() -> LaunchFixture {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target");
    let target = open_directory_nofollow(&target, None).expect("open target directory once");
    let lock = open_fixture_lock(&target).expect("anchored fixture lock");
    lock.lock_exclusive()
        .expect("exclusive fixture-generation lock");
    let template = anchored_path(&target).join(TEMPLATE_VERSION);
    let mut preparation = TemplatePreparationAudit::default();
    let authenticated = ensure_template(&template, &mut preparation);
    let fixture = LaunchFixture::materialize(&template, &authenticated, &mut preparation);
    preparation
        .finish()
        .expect("one authentication, one copy, one late genesis selection");
    FileExt::unlock(&lock).expect("unlock fixture generation");
    fixture
}

fn open_fixture_lock(target: &File) -> Result<File, String> {
    let lock_path = anchored_path(target).join("pq-e4f-template.lock");
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lock = lock_options
        .open(&lock_path)
        .map_err(|error| format!("open anchored fixture lock: {error}"))?;
    let lock_metadata = lock
        .metadata()
        .map_err(|error| format!("fstat anchored fixture lock: {error}"))?;
    if !lock_metadata.file_type().is_file()
        || lock_metadata.nlink() != 1
        || lock_metadata.mode() & 0o7777 != 0o600
    {
        return Err("fixture lock must be one private regular inode".into());
    }
    Ok(lock)
}

fn ensure_template(
    template: &Path,
    preparation: &mut TemplatePreparationAudit,
) -> AuthenticatedTemplate {
    if open_directory_nofollow(template, Some(0o700)).is_ok() {
        let authenticated =
            validate_template(template).expect("validate immutable PQ template before reuse");
        preparation
            .record_authentication()
            .expect("authenticate immutable template exactly once");
        return authenticated;
    }
    let parent = template.parent().expect("template parent");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("template staging clock")
        .as_nanos();
    let staging = parent.join(format!(
        ".{TEMPLATE_VERSION}.owned-staging-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&staging).expect("template staging directory");
    let mut cleanup = OwnedStaging::new(staging.clone());
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .expect("template staging mode");

    let generation = tempfile::tempdir().expect("template generation root");
    let seed = generation.path().join("seed");
    let password = generation.path().join("password");
    write_private(&seed, &[42; 32]);
    write_private(&password, b"e4f deterministic private fixture password");
    let provisioned = provision_devnet(
        production_config(generation.path().join("container"), 0),
        &seed,
        &password,
    )
    .expect("provision deterministic 16-validator immutable template");
    copy_tree_exact(provisioned.output_dir(), &staging.join("container"))
        .expect("copy provisioned immutable template");
    let inventory = inventory_tree(&staging.join("container")).expect("template inventory");
    atomic_replace(
        &staging.join("inventory"),
        inventory.encode().as_bytes(),
        0o600,
    )
    .expect("write template inventory");
    validate_template_structure(&staging).expect("validate template structure before auth");
    let identity = validate_authenticated_container(&staging.join("container"))
        .expect("authenticate deterministic template exactly once");
    preparation
        .record_authentication()
        .expect("authenticate generated template exactly once");
    validate_frozen_template_identity(&identity).expect("generated template has exact frozen time");
    let semantic = identity
        .semantic_digest()
        .expect("bounded semantic template identity");
    if validate_semantic_anchor(&identity, PINNED_TEMPLATE_SEMANTIC_SHA256).is_err() {
        panic!("deterministic PQ semantic anchor required: sha256={semantic}");
    }
    fs::rename(&staging, template).expect("atomically publish immutable template");
    cleanup.disarm();
    File::open(parent)
        .expect("template parent")
        .sync_all()
        .expect("sync immutable template publication");
    AuthenticatedTemplate {
        inventory,
        identity,
    }
}

struct OwnedStaging {
    path: Option<PathBuf>,
}

impl OwnedStaging {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for OwnedStaging {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_template(template: &Path) -> Result<AuthenticatedTemplate, String> {
    let inventory = validate_template_structure(template)?;
    let identity = validate_authenticated_container(&template.join("container"))?;
    validate_frozen_template_identity(&identity)?;
    validate_semantic_anchor(&identity, PINNED_TEMPLATE_SEMANTIC_SHA256)?;
    Ok(AuthenticatedTemplate {
        inventory,
        identity,
    })
}

fn validate_template_structure(template: &Path) -> Result<TemplateInventory, String> {
    let root = open_directory_nofollow(template, Some(0o700))?;
    let mut root_entries = read_anchored_names(&root)?;
    root_entries.sort();
    if root_entries != ["container", "inventory"] {
        return Err("template contains unexpected mutable state".into());
    }
    let expected =
        TemplateInventory::decode(&read_named_bounded(&root, "inventory", 0o600, 1024)?)?;
    let container = open_anchored_directory(&root, "container", Some(0o755))?;
    let actual = inventory_tree_from_fd(&container)?;
    if actual != expected {
        return Err("template inventory mismatch".into());
    }
    validate_template_layout(&container)?;
    validate_pristine_journal(&anchored_path(&container).join("bundle/xmss_usage.sqlite"))?;
    Ok(actual)
}

struct AuthenticatedTemplate {
    inventory: TemplateInventory,
    identity: PqNetworkIdentity,
}

#[derive(Default)]
struct TemplatePreparationAudit {
    authentications: u8,
    copied: bool,
    genesis_selected: bool,
}

impl TemplatePreparationAudit {
    fn record_authentication(&mut self) -> Result<(), String> {
        if self.authentications != 0 || self.copied || self.genesis_selected {
            return Err("template authentication is not exactly once and before copy".into());
        }
        self.authentications = 1;
        Ok(())
    }

    fn record_copy(&mut self) -> Result<(), String> {
        if self.authentications != 1 || self.copied || self.genesis_selected {
            return Err("template copy must follow its sole authentication".into());
        }
        self.copied = true;
        Ok(())
    }

    fn select_genesis_time(&mut self, now: u64) -> Result<u64, String> {
        if self.authentications != 1 || !self.copied || self.genesis_selected {
            return Err("genesis time must be selected once after authentication and copy".into());
        }
        self.genesis_selected = true;
        now.checked_add(900)
            .ok_or_else(|| "fixture genesis time overflow".into())
    }

    fn finish(&self) -> Result<(), String> {
        if self.authentications == 1 && self.copied && self.genesis_selected {
            Ok(())
        } else {
            Err("incomplete template preparation lifecycle".into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PqNetworkIdentity {
    genesis_validators_root: [u8; 32],
    genesis_time: u64,
    eth1_timestamp: u64,
    registry: Vec<PqValidatorRegistryEntry>,
    one_time_use_start: u32,
    one_time_use_end: u32,
}

impl PqNetworkIdentity {
    fn semantic_digest(&self) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"lighthouse/pq-e4f/semantic-template/v1");
        hasher.update(b"minimal/electra/300");
        hasher.update(self.genesis_validators_root);
        hasher.update(self.genesis_time.to_le_bytes());
        hasher.update(self.one_time_use_start.to_le_bytes());
        hasher.update(self.one_time_use_end.to_le_bytes());
        let registry_len = u32::try_from(self.registry.len())
            .map_err(|_| "semantic registry length does not fit u32")?;
        hasher.update(registry_len.to_le_bytes());
        for entry in &self.registry {
            hasher.update(entry.validator_index().to_le_bytes());
            hasher.update(entry.public_key().serialize());
            hasher.update(entry.withdrawal_credentials());
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

fn validate_frozen_template_identity(identity: &PqNetworkIdentity) -> Result<(), String> {
    if identity.genesis_time != 300 || identity.eth1_timestamp != 0 {
        return Err("immutable template timing must be genesis=300 and eth1=0".into());
    }
    Ok(())
}

fn validate_semantic_anchor(
    identity: &PqNetworkIdentity,
    trusted_digest: &str,
) -> Result<(), String> {
    let actual = identity.semantic_digest()?;
    if actual == trusted_digest {
        Ok(())
    } else {
        Err(format!(
            "template does not match the trusted semantic anchor: {actual}"
        ))
    }
}

fn validate_authenticated_container(container: &Path) -> Result<PqNetworkIdentity, String> {
    let identity = validate_network_identity(container)?;
    let container = open_directory_nofollow(container, Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let bundle_path = bundle_loader_path(&bundle);
    let loaded = PqDevnetBundle::load_for_network_registry(
        &bundle_path,
        identity.genesis_validators_root,
        identity.genesis_time,
        &identity.registry,
    )
    .map_err(|error| format!("authenticated template bundle: {error}"))?;
    if loaded.registry() != identity.registry || loaded.unlock_count() != identity.registry.len() {
        return Err("authenticated bundle registry mismatch".into());
    }
    let authority = loaded
        .open_authority(identity.genesis_validators_root)
        .map_err(|error| format!("fresh exact template journal: {error}"))?;
    if authority.public_keys()
        != identity
            .registry
            .iter()
            .map(PqValidatorRegistryEntry::public_key)
            .collect::<Vec<_>>()
    {
        return Err("journal authority key set mismatch".into());
    }
    drop(authority);
    Ok(identity)
}

fn validate_network_identity(container: &Path) -> Result<PqNetworkIdentity, String> {
    let container = open_directory_nofollow(container, Some(0o755))?;
    let testnet = open_anchored_directory(&container, "testnet", Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let mut public_names = read_anchored_names(&testnet)?;
    public_names.sort();
    if public_names
        != [
            "bootstrap_nodes.yaml",
            "config.yaml",
            "deposit_contract_block.txt",
            "genesis.ssz",
        ]
    {
        return Err("bounded public testnet layout mismatch".into());
    }
    let config_bytes = read_named_bounded(&testnet, "config.yaml", 0o644, 64 * 1024)?;
    let config: types::Config = yaml_serde::from_reader(config_bytes.as_slice())
        .map_err(|error| format!("public config YAML: {error}"))?;
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    if config != types::Config::from_chain_spec::<MinimalEthSpec>(&spec) {
        return Err("public config is not frozen Minimal Electra/300".into());
    }
    let deposit_bytes = read_named_bounded(&testnet, "deposit_contract_block.txt", 0o644, 1024)?;
    let deposit: u64 = yaml_serde::from_reader(deposit_bytes.as_slice())
        .map_err(|_| "invalid public deposit block")?;
    if deposit != 0 {
        return Err("public deposit block must be zero".into());
    }
    let bootstrap_bytes = read_named_bounded(&testnet, "bootstrap_nodes.yaml", 0o644, 64 * 1024)?;
    let bootstrap: Vec<String> = yaml_serde::from_reader(bootstrap_bytes.as_slice())
        .map_err(|_| "invalid public bootstrap list")?;
    if !bootstrap.is_empty() {
        return Err("public bootstrap list must be empty".into());
    }
    let genesis_bytes = read_named_bounded(&testnet, "genesis.ssz", 0o644, 128 * 1024 * 1024)?;
    let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&genesis_bytes, &spec)
        .map_err(|error| format!("public genesis decode: {error:?}"))?;
    state_processing::validate_lean_pq_devnet_v1(&state, &spec, state.slot())
        .map_err(|error| format!("public genesis profile: {error:?}"))?;
    let genesis_validators_root = state
        .genesis_validators_root()
        .as_slice()
        .try_into()
        .map_err(|_| "genesis validators root length")?;
    let registry = state
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            Ok(PqValidatorRegistryEntry::new(
                u64::try_from(index).map_err(|_| "validator index overflow")?,
                validator.pubkey,
                validator.withdrawal_credentials.0,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if registry.len() != 16 {
        return Err("public registry must contain exactly 16 validators".into());
    }
    let manifest = PqDevnetManifest::from_json_slice(&read_named_bounded(
        &bundle,
        "pq-devnet.json",
        0o600,
        1024 * 1024,
    )?)
    .map_err(|error| format!("template manifest: {error}"))?;
    let validated = manifest
        .validate_for_network_registry(genesis_validators_root, state.genesis_time(), &registry)
        .map_err(|error| format!("template manifest network binding: {error}"))?;
    Ok(PqNetworkIdentity {
        genesis_validators_root,
        genesis_time: state.genesis_time(),
        eth1_timestamp: validated.eth1_timestamp(),
        registry,
        one_time_use_start: validated.one_time_use_start(),
        one_time_use_end: validated.one_time_use_end(),
    })
}

fn read_named_bounded(
    directory: &File,
    name: &str,
    mode: u32,
    max: u64,
) -> Result<Vec<u8>, String> {
    let mut file = open_anchored_file(directory, name, Some(mode))?;
    read_held_bounded(&mut file, max)
}

fn validate_template_layout(container: &File) -> Result<(), String> {
    validate_held_directory(container, Some(0o755))?;
    let mut container_entries = read_anchored_names(container)?;
    container_entries.sort();
    if container_entries != ["bundle", "testnet"] {
        return Err("template container layout mismatch".into());
    }
    let testnet = open_anchored_directory(container, "testnet", Some(0o755))?;
    let mut public = read_anchored_names(&testnet)?;
    public.sort();
    if public
        != [
            "bootstrap_nodes.yaml",
            "config.yaml",
            "deposit_contract_block.txt",
            "genesis.ssz",
        ]
    {
        return Err("template public layout mismatch".into());
    }
    for file in public {
        open_anchored_file(&testnet, &file, Some(0o644))?;
    }
    let bundle = open_anchored_directory(container, "bundle", Some(0o700))?;
    let mut private = read_anchored_names(&bundle)?;
    private.sort();
    if private
        != [
            "pq-devnet.json",
            "secrets",
            "validators",
            "xmss_usage.sqlite",
            "xmss_usage.sqlite.lock",
        ]
    {
        return Err("template private layout mismatch".into());
    }
    for file in [
        "pq-devnet.json",
        "xmss_usage.sqlite",
        "xmss_usage.sqlite.lock",
    ] {
        open_anchored_file(&bundle, file, Some(0o600))?;
    }
    for directory_name in ["validators", "secrets"] {
        let directory = open_anchored_directory(&bundle, directory_name, Some(0o700))?;
        let names = read_anchored_names(&directory)?;
        if names.len() != 16 {
            return Err(format!("template {directory_name} count mismatch"));
        }
        for name in names {
            if directory_name == "validators" {
                open_anchored_directory(&directory, &name, Some(0o700))?;
            } else {
                open_anchored_file(&directory, &name, Some(0o600))?;
            }
        }
    }
    Ok(())
}

fn validate_pristine_journal(path: &Path) -> Result<(), String> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("open pristine journal: {error}"))?;
    let keys: i64 = connection
        .query_row("SELECT count(*) FROM xmss_keys", [], |row| row.get(0))
        .map_err(|error| format!("count journal keys: {error}"))?;
    let reservations: i64 = connection
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .map_err(|error| format!("count journal reservations: {error}"))?;
    if keys != 16 || reservations != 0 {
        return Err(format!(
            "template journal is not pristine: keys={keys}, reservations={reservations}"
        ));
    }
    Ok(())
}

fn inventory_tree(root: &Path) -> Result<TemplateInventory, String> {
    let root = open_directory_nofollow(root, None)?;
    inventory_tree_from_fd(&root)
}

fn inventory_tree_from_fd(root: &File) -> Result<TemplateInventory, String> {
    let mut hasher = Sha256::new();
    let mut accounting = TemplateAccounting::default();
    inventory_directory(root, "", &mut hasher, &mut accounting)?;
    Ok(TemplateInventory {
        entries: accounting.entries,
        bytes: accounting.bytes,
        digest: hex::encode(hasher.finalize()),
    })
}

#[derive(Default)]
struct TemplateAccounting {
    entries: usize,
    bytes: u64,
}

fn inventory_directory(
    directory: &File,
    prefix: &str,
    hasher: &mut Sha256,
    accounting: &mut TemplateAccounting,
) -> Result<(), String> {
    for name in read_anchored_names(directory)? {
        accounting.entries = accounting
            .entries
            .checked_add(1)
            .ok_or("template entry count overflow")?;
        if accounting.entries > MAX_TEMPLATE_ENTRIES {
            return Err("template entry cap exceeded".into());
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        hasher.update(relative.len().to_le_bytes());
        hasher.update(relative.as_bytes());
        if let Ok(child) = open_anchored_directory(directory, &name, None) {
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat inventory directory: {error}"))?;
            hasher.update((metadata.mode() & 0o7777).to_le_bytes());
            hasher.update(b"d");
            inventory_directory(&child, &relative, hasher, accounting)?;
        } else {
            let mut child = open_anchored_file(directory, &name, None)?;
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat inventory file: {error}"))?;
            hasher.update((metadata.mode() & 0o7777).to_le_bytes());
            hasher.update(b"f");
            let remaining = MAX_TEMPLATE_BYTES
                .checked_sub(accounting.bytes)
                .ok_or("template byte accounting underflow")?;
            let bytes = read_held_bounded(&mut child, remaining)?;
            accounting.bytes = accounting
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "file length overflow")?)
                .ok_or("template byte count overflow")?;
            hasher.update(bytes.len().to_le_bytes());
            hasher.update(bytes);
        }
    }
    Ok(())
}

fn copy_tree_exact(source: &Path, destination: &Path) -> Result<(), String> {
    copy_tree_exact_with_hooks(source, destination, || {}, || {})
}

fn copy_tree_exact_with_hooks(
    source: &Path,
    destination: &Path,
    after_source_enumerated: impl FnOnce(),
    after_destination_opened: impl FnOnce(),
) -> Result<(), String> {
    let source = open_directory_nofollow(source, None)?;
    let source_names = read_anchored_names(&source)?;
    after_source_enumerated();
    let destination_parent = destination
        .parent()
        .ok_or("copy destination has no parent")?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("copy destination name is not UTF-8")?;
    let destination_parent = open_directory_nofollow(destination_parent, None)?;
    let destination =
        create_anchored_destination_directory(&destination_parent, destination_name, &source)?;
    after_destination_opened();
    let mut accounting = TemplateAccounting::default();
    copy_directory_entries(&source, &destination, source_names, &mut accounting)?;
    verify_anchored_directory_binding(&destination_parent, destination_name, &destination)
}

fn copy_directory_entries(
    source: &File,
    destination: &File,
    names: Vec<String>,
    accounting: &mut TemplateAccounting,
) -> Result<(), String> {
    for name in names {
        accounting.entries = accounting
            .entries
            .checked_add(1)
            .ok_or("copy entry count overflow")?;
        if accounting.entries > MAX_TEMPLATE_ENTRIES {
            return Err("copy source entry cap exceeded".into());
        }
        if let Ok(child) = open_anchored_directory(source, &name, None) {
            let child_names = read_anchored_names(&child)?;
            let destination_child =
                create_anchored_destination_directory(destination, &name, &child)?;
            copy_directory_entries(&child, &destination_child, child_names, accounting)?;
            verify_anchored_directory_binding(destination, &name, &destination_child)?;
        } else {
            let mut child = open_anchored_file(source, &name, None)?;
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat copy source file: {error}"))?;
            let remaining = MAX_TEMPLATE_BYTES
                .checked_sub(accounting.bytes)
                .ok_or("copy byte accounting underflow")?;
            let bytes = read_held_bounded(&mut child, remaining)?;
            accounting.bytes = accounting
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "copy length overflow")?)
                .ok_or("copy byte count overflow")?;
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(metadata.mode() & 0o7777)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut destination_file = options
                .open(anchored_path(destination).join(&name))
                .map_err(|error| format!("create copied file: {error}"))?;
            destination_file
                .write_all(&bytes)
                .map_err(|error| format!("write copied file: {error}"))?;
            destination_file
                .set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))
                .map_err(|error| format!("set copied file mode: {error}"))?;
            let copied = destination_file
                .metadata()
                .map_err(|error| format!("fstat copied file: {error}"))?;
            if metadata.mode() & 0o7000 != 0
                || copied.nlink() != 1
                || copied.mode() & 0o7777 != metadata.mode() & 0o7777
                || (copied.dev() == metadata.dev() && copied.ino() == metadata.ino())
            {
                return Err("copied file identity or mode mismatch".into());
            }
            destination_file
                .sync_all()
                .map_err(|error| format!("sync copied file: {error}"))?;
            verify_anchored_file_binding(destination, &name, &destination_file)?;
        }
    }
    destination
        .sync_all()
        .map_err(|error| format!("sync copied directory: {error}"))?;
    Ok(())
}

fn create_anchored_destination_directory(
    parent: &File,
    name: &str,
    source: &File,
) -> Result<File, String> {
    let source_metadata = source
        .metadata()
        .map_err(|error| format!("fstat copy source directory: {error}"))?;
    let mode = source_metadata.mode() & 0o7777;
    if mode & 0o7000 != 0 {
        return Err("copy source directory has special permission bits".into());
    }
    let destination_path = anchored_path(parent).join(name);
    fs::create_dir(&destination_path)
        .map_err(|error| format!("create anchored clone directory: {error}"))?;
    let destination = open_anchored_directory(parent, name, None)?;
    destination
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set held clone directory mode: {error}"))?;
    let destination_metadata = destination
        .metadata()
        .map_err(|error| format!("fstat held clone directory: {error}"))?;
    if destination_metadata.mode() & 0o7777 != mode
        || (destination_metadata.dev() == source_metadata.dev()
            && destination_metadata.ino() == source_metadata.ino())
    {
        return Err("copied directory identity or mode mismatch".into());
    }
    destination
        .sync_all()
        .map_err(|error| format!("sync created clone directory: {error}"))?;
    Ok(destination)
}

fn verify_anchored_directory_binding(parent: &File, name: &str, held: &File) -> Result<(), String> {
    let current = open_anchored_directory(parent, name, None)?;
    let current = current
        .metadata()
        .map_err(|error| format!("fstat current destination binding: {error}"))?;
    let held = held
        .metadata()
        .map_err(|error| format!("fstat held destination binding: {error}"))?;
    if current.dev() != held.dev() || current.ino() != held.ino() {
        return Err("destination binding changed during copy".into());
    }
    Ok(())
}

fn verify_anchored_file_binding(parent: &File, name: &str, held: &File) -> Result<(), String> {
    let current = open_anchored_file(parent, name, None)?;
    let current = current
        .metadata()
        .map_err(|error| format!("fstat current destination file: {error}"))?;
    let held = held
        .metadata()
        .map_err(|error| format!("fstat held destination file: {error}"))?;
    if current.dev() != held.dev() || current.ino() != held.ino() {
        return Err("destination file binding changed during copy".into());
    }
    Ok(())
}

fn open_directory_nofollow(path: &Path, mode: Option<u32>) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    let file = options
        .open(path)
        .map_err(|error| format!("open directory {}: {error}", path.display()))?;
    validate_held_directory(&file, mode)?;
    Ok(file)
}

fn open_anchored_directory(parent: &File, name: &str, mode: Option<u32>) -> Result<File, String> {
    open_directory_nofollow(&anchored_path(parent).join(name), mode)
}

fn open_anchored_file(parent: &File, name: &str, mode: Option<u32>) -> Result<File, String> {
    let path = anchored_path(parent).join(name);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(&path)
        .map_err(|error| format!("open anchored file {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat anchored file: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
    {
        return Err(format!("unsafe anchored file {}", path.display()));
    }
    Ok(file)
}

fn validate_held_directory(directory: &File, mode: Option<u32>) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("fstat held directory: {error}"))?;
    if !metadata.file_type().is_dir() || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode) {
        return Err("unsafe held directory".into());
    }
    Ok(())
}

fn anchored_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn bundle_loader_path(directory: &File) -> PathBuf {
    anchored_path(directory).join(".")
}

fn read_anchored_names(directory: &File) -> Result<Vec<String>, String> {
    let mut entries = fs::read_dir(anchored_path(directory))
        .map_err(|error| format!("read anchored directory: {error}"))?
        .take(MAX_TEMPLATE_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read anchored entry: {error}"))?;
    if entries.len() > MAX_TEMPLATE_ENTRIES {
        return Err("anchored directory entry cap exceeded".into());
    }
    entries.sort_by_key(|entry| entry.file_name());
    entries
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| "anchored entry name is not UTF-8".into())
        })
        .collect()
}

fn read_held_bounded(file: &mut File, max: u64) -> Result<Vec<u8>, String> {
    let before = file
        .metadata()
        .map_err(|error| format!("fstat bounded file: {error}"))?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > max {
        return Err("unsafe or oversized held file".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(max.checked_add(1).ok_or("bounded held read overflow")?)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read held file: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("post-read fstat held file: {error}"))?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("held file changed while read".into());
    }
    Ok(bytes)
}

fn rebase_network_identity(container: &Path, genesis_time: u64) -> Result<(), String> {
    let eth1_timestamp = genesis_time
        .checked_sub(300)
        .ok_or("genesis time is below frozen genesis delay")?;
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let container = open_directory_nofollow(container, Some(0o755))?;
    let testnet = open_anchored_directory(&container, "testnet", Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let genesis_path = anchored_path(&testnet).join("genesis.ssz");
    let genesis = read_named_bounded(&testnet, "genesis.ssz", 0o644, 128 * 1024 * 1024)?;
    let mut state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&genesis, &spec)
        .map_err(|error| format!("decode genesis: {error:?}"))?;
    *state.genesis_time_mut() = genesis_time;
    atomic_replace(&genesis_path, &state.as_ssz_bytes(), 0o644)?;

    let manifest_path = anchored_path(&bundle).join("pq-devnet.json");
    let bytes = read_named_bounded(&bundle, "pq-devnet.json", 0o600, 1024 * 1024)?;
    let mut manifest: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("decode manifest JSON: {error}"))?;
    *manifest
        .get_mut("eth1_timestamp")
        .ok_or("manifest timestamp missing")? = Value::from(eth1_timestamp);
    let rebased = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("encode rebased manifest: {error}"))?;
    atomic_replace(&manifest_path, &rebased, 0o600)?;
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("replacement path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.rebase-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("replacement filename is not UTF-8")?,
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create replacement: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write replacement: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set replacement mode: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat replacement: {error}"))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o7777 != mode
    {
        return Err("replacement inode or mode mismatch".into());
    }
    file.sync_all()
        .map_err(|error| format!("sync replacement: {error}"))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| format!("publish replacement: {error}"))?;
    let published = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open published replacement: {error}"))?;
    let published_metadata = published
        .metadata()
        .map_err(|error| format!("fstat published replacement: {error}"))?;
    if !published_metadata.file_type().is_file()
        || published_metadata.nlink() != 1
        || published_metadata.mode() & 0o7777 != mode
    {
        return Err("published replacement inode or mode mismatch".into());
    }
    File::open(parent)
        .map_err(|error| format!("open replacement parent: {error}"))?
        .sync_all()
        .map_err(|error| format!("sync replacement parent: {error}"))?;
    Ok(())
}

fn validate_manifest_network_identity(
    manifest: &PqDevnetManifest,
    root: [u8; 32],
    genesis_time: u64,
) -> Result<(), String> {
    manifest
        .validate_for_network_identity(root, genesis_time)
        .map(|_| ())
        .map_err(|error| format!("manifest network binding: {error}"))
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).expect("create private fixture input");
    file.write_all(bytes).expect("write private fixture input");
    file.sync_all().expect("sync private fixture input");
}

fn reserve_tcp_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve TCP port")
        .local_addr()
        .expect("TCP address")
        .port()
}

fn reserve_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve UDP port")
        .local_addr()
        .expect("UDP address")
        .port()
}

fn probe_network_ports_released(tcp_ports: &[u16], udp_ports: &[u16]) -> Result<(), String> {
    let mut tcp = Vec::with_capacity(tcp_ports.len());
    for port in tcp_ports {
        tcp.push(
            TcpListener::bind((Ipv4Addr::LOCALHOST, *port))
                .map_err(|error| format!("TCP port {port} remains owned: {error}"))?,
        );
    }
    let mut udp = Vec::with_capacity(udp_ports.len());
    for port in udp_ports {
        udp.push(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, *port))
                .map_err(|error| format!("UDP port {port} remains owned: {error}"))?,
        );
    }
    Ok(())
}

const PQ_LEVELDB_LOCK_PATH_ENV: &str = "LIGHTHOUSE_PQ_E4F_LEVELDB_LOCK_PATH";
const PQ_LEVELDB_LOCK_READY_ENV: &str = "LIGHTHOUSE_PQ_E4F_LEVELDB_LOCK_READY";
const PQ_SQLITE_LOCK_PATH_ENV: &str = "LIGHTHOUSE_PQ_E4F_SQLITE_LOCK_PATH";
const PQ_SQLITE_LOCK_READY_ENV: &str = "LIGHTHOUSE_PQ_E4F_SQLITE_LOCK_READY";

struct HeldLevelDbProcess {
    child: Child,
}

impl HeldLevelDbProcess {
    fn spawn(path: &Path, ready: &Path) -> Result<Self, String> {
        let child = Command::new(
            std::env::current_exe().map_err(|error| format!("resolve test binary: {error}"))?,
        )
        .arg("pq_leveldb_lock_holder_process")
        .arg("--exact")
        .arg("--nocapture")
        .env(PQ_LEVELDB_LOCK_PATH_ENV, path)
        .env(PQ_LEVELDB_LOCK_READY_ENV, ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn LevelDB lock holder: {error}"))?;
        let mut held = Self { child };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or("LevelDB lock-holder deadline overflow")?;
        while !ready.exists() {
            if let Some(status) = held
                .child
                .try_wait()
                .map_err(|error| format!("poll LevelDB lock holder: {error}"))?
            {
                return Err(format!("LevelDB lock holder exited before ready: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("LevelDB lock holder did not become ready".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(held)
    }

    fn stop(mut self) -> Result<(), String> {
        let mut stdin = self
            .child
            .stdin
            .take()
            .ok_or("LevelDB lock holder has no stdin")?;
        stdin
            .write_all(&[0])
            .map_err(|error| format!("stop LevelDB lock holder: {error}"))?;
        drop(stdin);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or("LevelDB lock-holder stop deadline overflow")?;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("poll stopped LevelDB lock holder: {error}"))?
            {
                if status.success() {
                    return Ok(());
                }
                return Err(format!("LevelDB lock holder failed: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("LevelDB lock holder did not stop".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for HeldLevelDbProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct HeldSqliteProcess {
    child: Child,
}

impl HeldSqliteProcess {
    fn spawn(path: &Path, ready: &Path) -> Result<Self, String> {
        let child = Command::new(
            std::env::current_exe().map_err(|error| format!("resolve test binary: {error}"))?,
        )
        .arg("pq_sqlite_lock_holder_process")
        .arg("--exact")
        .arg("--nocapture")
        .env(PQ_SQLITE_LOCK_PATH_ENV, path)
        .env(PQ_SQLITE_LOCK_READY_ENV, ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn SQLite lock holder: {error}"))?;
        let mut held = Self { child };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or("SQLite lock-holder deadline overflow")?;
        while !ready.exists() {
            if let Some(status) = held
                .child
                .try_wait()
                .map_err(|error| format!("poll SQLite lock holder: {error}"))?
            {
                return Err(format!("SQLite lock holder exited before ready: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("SQLite lock holder did not become ready".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(held)
    }

    fn stop(mut self) -> Result<(), String> {
        let mut stdin = self
            .child
            .stdin
            .take()
            .ok_or("SQLite lock holder has no stdin")?;
        stdin
            .write_all(&[0])
            .map_err(|error| format!("stop SQLite lock holder: {error}"))?;
        drop(stdin);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or("SQLite lock-holder stop deadline overflow")?;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("poll stopped SQLite lock holder: {error}"))?
            {
                if status.success() {
                    return Ok(());
                }
                return Err(format!("SQLite lock holder failed: {status}"));
            }
            if Instant::now() >= deadline {
                return Err("SQLite lock holder did not stop".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for HeldSqliteProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn pq_node_data_dir(cli_data_dir: &Path) -> PathBuf {
    cli_data_dir.join(directory::DEFAULT_BEACON_NODE_DIR)
}

fn pq_store_paths(cli_data_dir: &Path) -> [PathBuf; 3] {
    let data_dir = pq_node_data_dir(cli_data_dir);
    [
        data_dir.join("chain_db"),
        data_dir.join("freezer_db"),
        data_dir.join("blobs_db"),
    ]
}

fn validate_safe_database_directory(directory: &File, label: &str) -> Result<(u64, u64), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("inspect held {label} directory: {error}"))?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || !matches!(mode, 0o700 | 0o705 | 0o750 | 0o755 | 0o770 | 0o775)
    {
        return Err(format!("{label} directory has unsafe mode/type {mode:o}"));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn validate_safe_leveldb_file(file: &File, label: &str, max_len: u64) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect held LevelDB {label}: {error}"))?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || !matches!(mode, 0o600 | 0o604 | 0o640 | 0o644)
        || metadata.len() > max_len
    {
        return Err(format!("unsafe LevelDB {label} mode/type/length"));
    }
    Ok(())
}

fn validate_existing_leveldb(directory: &File) -> Result<(), String> {
    const CURRENT_MAX_BYTES: u64 = 64;
    const MANIFEST_MAX_BYTES: u64 = 64 * 1024 * 1024;

    let mut current = open_anchored_file(directory, "CURRENT", None)?;
    validate_safe_leveldb_file(&current, "CURRENT", CURRENT_MAX_BYTES)?;
    let current_bytes = read_held_bounded(&mut current, CURRENT_MAX_BYTES)?;
    let current_name = std::str::from_utf8(&current_bytes)
        .map_err(|_| "LevelDB CURRENT is not UTF-8")?
        .strip_suffix('\n')
        .ok_or("LevelDB CURRENT lacks its exact newline")?;
    let manifest_digits = current_name
        .strip_prefix("MANIFEST-")
        .ok_or("LevelDB CURRENT does not name a manifest")?;
    if !(6..=20).contains(&manifest_digits.len())
        || !manifest_digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("LevelDB CURRENT contains an unsafe manifest name".into());
    }

    let manifest = open_anchored_file(directory, current_name, None)?;
    validate_safe_leveldb_file(&manifest, "manifest", MANIFEST_MAX_BYTES)?;
    if manifest
        .metadata()
        .map_err(|error| format!("inspect held LevelDB manifest: {error}"))?
        .len()
        == 0
    {
        return Err("LevelDB manifest is empty".into());
    }

    let lock = open_anchored_file(directory, "LOCK", None)?;
    validate_safe_leveldb_file(&lock, "LOCK", 0)?;
    Ok(())
}

fn probe_chain_store_released(data_dir: &Path) -> Result<(), String> {
    probe_chain_store_released_with_hooks(data_dir, || {}, || {})
}

fn probe_chain_store_released_with_hooks<BeforeFirstOpen, AfterFirstOpen>(
    data_dir: &Path,
    before_first_open: BeforeFirstOpen,
    after_first_open: AfterFirstOpen,
) -> Result<(), String>
where
    BeforeFirstOpen: FnOnce(),
    AfterFirstOpen: FnOnce(),
{
    struct HeldStoreDirectory {
        path: PathBuf,
        directory: File,
        dev: u64,
        ino: u64,
    }

    let beacon_path = pq_node_data_dir(data_dir);
    let beacon_directory = open_directory_nofollow(&beacon_path, None)?;
    let (beacon_dev, beacon_ino) =
        validate_safe_database_directory(&beacon_directory, "beacon data")?;
    let current_beacon = std::fs::symlink_metadata(&beacon_path)
        .map_err(|error| format!("inspect beacon data binding: {error}"))?;
    if !current_beacon.file_type().is_dir()
        || current_beacon.dev() != beacon_dev
        || current_beacon.ino() != beacon_ino
    {
        return Err("beacon data directory binding changed".into());
    }

    let mut held_directories = Vec::with_capacity(3);
    for (name, path) in ["chain_db", "freezer_db", "blobs_db"]
        .into_iter()
        .zip(pq_store_paths(data_dir))
    {
        let directory = open_anchored_directory(&beacon_directory, name, None)?;
        let (dev, ino) = validate_safe_database_directory(&directory, "store")?;
        validate_existing_leveldb(&directory)?;
        let current = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect store binding {}: {error}", path.display()))?;
        if !current.file_type().is_dir() || current.dev() != dev || current.ino() != ino {
            return Err(format!(
                "store directory binding changed: {}",
                path.display()
            ));
        }
        held_directories.push(HeldStoreDirectory {
            path,
            directory,
            dev,
            ino,
        });
    }

    let config = store::StoreConfig::default();
    let mut databases = Vec::with_capacity(3);
    let mut before_first_open = Some(before_first_open);
    let mut after_first_open = Some(after_first_open);
    for (index, held) in held_directories.iter().enumerate() {
        let verify_binding = || {
            let current = std::fs::symlink_metadata(&held.path).map_err(|error| {
                format!("reinspect store binding {}: {error}", held.path.display())
            })?;
            let held_metadata = held.directory.metadata().map_err(|error| {
                format!("reinspect held store {}: {error}", held.path.display())
            })?;
            if !current.file_type().is_dir()
                || current.dev() != held.dev
                || current.ino() != held.ino
                || held_metadata.dev() != held.dev
                || held_metadata.ino() != held.ino
            {
                return Err(format!(
                    "store directory binding changed: {}",
                    held.path.display()
                ));
            }
            Ok::<(), String>(())
        };
        verify_binding()?;
        if index == 0 {
            before_first_open
                .take()
                .ok_or("first store pre-open hook already consumed")?();
        }
        let held_path = bundle_loader_path(&held.directory);
        databases.push(
            store::database::interface::BeaconNodeBackend::open(&config, &held_path).map_err(
                |error| {
                    format!(
                        "store path {} remains owned: {error:?}",
                        held.path.display()
                    )
                },
            )?,
        );
        if index == 0 {
            after_first_open
                .take()
                .ok_or("first store post-open hook already consumed")?();
        }
        verify_binding()?;
    }
    Ok(())
}

fn probe_slashing_db_released(cli_data_dir: &Path) -> Result<(), String> {
    probe_slashing_db_released_with_hooks(cli_data_dir, || {}, || {})
}

fn probe_slashing_db_released_with_hooks<BeforeSqliteOpen, AfterSqliteOpen>(
    cli_data_dir: &Path,
    before_sqlite_open: BeforeSqliteOpen,
    after_sqlite_open: AfterSqliteOpen,
) -> Result<(), String>
where
    BeforeSqliteOpen: FnOnce(),
    AfterSqliteOpen: FnOnce(),
{
    probe_slashing_db_released_with_all_hooks(
        cli_data_dir,
        || {},
        before_sqlite_open,
        after_sqlite_open,
    )
}

fn probe_slashing_db_released_with_parent_hooks<BeforeRawOpen, AfterSqliteOpen>(
    cli_data_dir: &Path,
    before_raw_open: BeforeRawOpen,
    after_sqlite_open: AfterSqliteOpen,
) -> Result<(), String>
where
    BeforeRawOpen: FnOnce(),
    AfterSqliteOpen: FnOnce(),
{
    probe_slashing_db_released_with_all_hooks(
        cli_data_dir,
        before_raw_open,
        || {},
        after_sqlite_open,
    )
}

fn probe_slashing_db_released_with_all_hooks<BeforeRawOpen, BeforeSqliteOpen, AfterSqliteOpen>(
    cli_data_dir: &Path,
    before_raw_open: BeforeRawOpen,
    before_sqlite_open: BeforeSqliteOpen,
    after_sqlite_open: AfterSqliteOpen,
) -> Result<(), String>
where
    BeforeRawOpen: FnOnce(),
    BeforeSqliteOpen: FnOnce(),
    AfterSqliteOpen: FnOnce(),
{
    // This test-harness probe runs inside its ephemeral 0700 run root. The standard SQLite VFS
    // cannot eliminate its internal fullpath-to-open window against a hostile same-UID mutator,
    // which is outside this harness's trust boundary. Held directory/file descriptors and the raw
    // O_NOFOLLOW open prevent accidental pathname redirection in the tested lifecycle.
    let beacon_path = pq_node_data_dir(cli_data_dir);
    let beacon_directory = open_directory_nofollow(&beacon_path, None)?;
    let (beacon_dev, beacon_ino) =
        validate_safe_database_directory(&beacon_directory, "beacon data")?;
    let current_beacon = std::fs::symlink_metadata(&beacon_path)
        .map_err(|error| format!("inspect beacon data binding: {error}"))?;
    if !current_beacon.file_type().is_dir()
        || current_beacon.dev() != beacon_dev
        || current_beacon.ino() != beacon_ino
    {
        return Err("beacon data directory binding changed".into());
    }
    let proposer_path = beacon_path.join("pq-proposer");
    let proposer_directory = open_anchored_directory(&beacon_directory, "pq-proposer", None)?;
    let (proposer_dev, proposer_ino) =
        validate_safe_database_directory(&proposer_directory, "proposer")?;
    let current_proposer = std::fs::symlink_metadata(&proposer_path)
        .map_err(|error| format!("inspect proposer directory binding: {error}"))?;
    if !current_proposer.file_type().is_dir()
        || current_proposer.dev() != proposer_dev
        || current_proposer.ino() != proposer_ino
    {
        return Err("proposer directory binding changed".into());
    }
    before_raw_open();
    let anchored_path = bundle_loader_path(&proposer_directory).join("slashing_protection.sqlite");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&anchored_path)
        .map_err(|error| {
            format!(
                "open existing proposer DB {}: {error}",
                anchored_path.display()
            )
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect proposer DB {}: {error}", anchored_path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() == 0
    {
        return Err("proposer DB must be one nonempty private regular inode".into());
    }

    before_sqlite_open();
    let sqlite_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let canonical_sqlite_path = std::fs::canonicalize(&sqlite_path)
        .map_err(|error| format!("canonicalize held proposer DB: {error}"))?;
    let connection = Connection::open_with_flags(
        &sqlite_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open proposer DB read-write: {error}"))?;
    connection
        .busy_timeout(Duration::from_millis(100))
        .map_err(|error| format!("set bounded proposer DB timeout: {error}"))?;
    after_sqlite_open();
    let current = std::fs::metadata(&sqlite_path)
        .map_err(|error| format!("reinspect proposer DB binding: {error}"))?;
    if !current.file_type().is_file()
        || current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
    {
        return Err("proposer DB binding changed during inspection".into());
    }
    if connection
        .is_readonly(MAIN_DB)
        .map_err(|error| format!("inspect proposer DB write mode: {error}"))?
    {
        return Err("proposer DB unexpectedly opened read-only".into());
    }
    let database_list = {
        let mut statement = connection
            .prepare("PRAGMA database_list")
            .map_err(|error| format!("prepare proposer database_list: {error}"))?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| format!("query proposer database_list: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode proposer database_list: {error}"))?
    };
    if database_list
        != [(
            0,
            "main".into(),
            canonical_sqlite_path.to_string_lossy().into_owned(),
        )]
    {
        return Err(format!(
            "unexpected proposer database_list: {database_list:?}"
        ));
    }
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| format!("inspect proposer journal mode: {error}"))?;
    if journal_mode != "delete" {
        return Err(format!("unexpected proposer journal mode: {journal_mode}"));
    }
    let sidecars = ["-journal", "-wal", "-shm"].map(|suffix| {
        let mut path = canonical_sqlite_path.as_os_str().to_owned();
        path.push(suffix);
        PathBuf::from(path)
    });
    if sidecars.iter().any(|path| path.exists()) {
        return Err("unexpected proposer DB sidecar before inspection".into());
    }
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .map_err(|error| format!("set exclusive proposer DB inspection: {error}"))?;
    connection
        .execute_batch("BEGIN EXCLUSIVE;")
        .map_err(|error| format!("proposer DB remains owned: {error}"))?;

    let validation = (|| {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .map_err(|error| format!("query proposer DB schema: {error}"))?;
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| format!("read proposer DB schema: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("decode proposer DB schema: {error}"))?;
        if tables != ["signed_attestations", "signed_blocks", "validators"] {
            return Err(format!("unexpected proposer DB tables: {tables:?}"));
        }

        type Column = (i64, String, String, i64, Option<String>, i64);
        let columns = |table: &str| -> Result<Vec<Column>, String> {
            let sql = match table {
                "validators" => "PRAGMA table_info('validators')",
                "signed_blocks" => "PRAGMA table_info('signed_blocks')",
                "signed_attestations" => "PRAGMA table_info('signed_attestations')",
                _ => return Err("unrecognized proposer DB table".into()),
            };
            let mut statement = connection
                .prepare(sql)
                .map_err(|error| format!("inspect {table} schema: {error}"))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })
                .map_err(|error| format!("query {table} columns: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("decode {table} columns: {error}"))
        };
        if columns("validators")?
            != [
                (0, "id".into(), "INTEGER".into(), 0, None, 1),
                (1, "public_key".into(), "BLOB".into(), 1, None, 0),
                (
                    2,
                    "enabled".into(),
                    "BOOL".into(),
                    1,
                    Some("TRUE".into()),
                    0,
                ),
            ]
            || columns("signed_blocks")?
                != [
                    (0, "validator_id".into(), "INTEGER".into(), 1, None, 0),
                    (1, "slot".into(), "INTEGER".into(), 1, None, 0),
                    (2, "signing_root".into(), "BLOB".into(), 1, None, 0),
                ]
            || columns("signed_attestations")?
                != [
                    (0, "validator_id".into(), "INTEGER".into(), 0, None, 0),
                    (1, "source_epoch".into(), "INTEGER".into(), 1, None, 0),
                    (2, "target_epoch".into(), "INTEGER".into(), 1, None, 0),
                    (3, "signing_root".into(), "BLOB".into(), 1, None, 0),
                ]
        {
            return Err("unexpected proposer DB column schema".into());
        }

        type Index = (i64, String, i64, String, i64);
        let indexes = |table: &str| -> Result<Vec<Index>, String> {
            let sql = match table {
                "validators" => "PRAGMA index_list('validators')",
                "signed_blocks" => "PRAGMA index_list('signed_blocks')",
                "signed_attestations" => "PRAGMA index_list('signed_attestations')",
                _ => return Err("unrecognized proposer DB index table".into()),
            };
            let mut statement = connection
                .prepare(sql)
                .map_err(|error| format!("inspect {table} indexes: {error}"))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .map_err(|error| format!("query {table} indexes: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("decode {table} indexes: {error}"))
        };
        if indexes("validators")? != [(0, "sqlite_autoindex_validators_1".into(), 1, "u".into(), 0)]
            || indexes("signed_blocks")?
                != [(
                    0,
                    "sqlite_autoindex_signed_blocks_1".into(),
                    1,
                    "u".into(),
                    0,
                )]
            || indexes("signed_attestations")?
                != [(
                    0,
                    "sqlite_autoindex_signed_attestations_1".into(),
                    1,
                    "u".into(),
                    0,
                )]
        {
            return Err("unexpected proposer DB unique indexes".into());
        }

        type IndexedColumn = (i64, i64, String);
        let indexed_columns = |index: &str| -> Result<Vec<IndexedColumn>, String> {
            let sql = match index {
                "validators" => "PRAGMA index_info('sqlite_autoindex_validators_1')",
                "signed_blocks" => "PRAGMA index_info('sqlite_autoindex_signed_blocks_1')",
                "signed_attestations" => {
                    "PRAGMA index_info('sqlite_autoindex_signed_attestations_1')"
                }
                _ => return Err("unrecognized proposer DB index".into()),
            };
            let mut statement = connection
                .prepare(sql)
                .map_err(|error| format!("inspect {index} indexed columns: {error}"))?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(|error| format!("query {index} indexed columns: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("decode {index} indexed columns: {error}"))
        };
        if indexed_columns("validators")? != [(0, 1, "public_key".into())]
            || indexed_columns("signed_blocks")?
                != [(0, 0, "validator_id".into()), (1, 1, "slot".into())]
            || indexed_columns("signed_attestations")?
                != [(0, 0, "validator_id".into()), (1, 2, "target_epoch".into())]
        {
            return Err("unexpected proposer DB unique index columns".into());
        }

        type ForeignKey = (i64, i64, String, String, String, String, String, String);
        let foreign_keys = |table: &str| -> Result<Vec<ForeignKey>, String> {
            let sql = match table {
                "validators" => "PRAGMA foreign_key_list('validators')",
                "signed_blocks" => "PRAGMA foreign_key_list('signed_blocks')",
                "signed_attestations" => "PRAGMA foreign_key_list('signed_attestations')",
                _ => return Err("unrecognized proposer DB foreign-key table".into()),
            };
            let mut statement = connection
                .prepare(sql)
                .map_err(|error| format!("inspect {table} foreign keys: {error}"))?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                })
                .map_err(|error| format!("query {table} foreign keys: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("decode {table} foreign keys: {error}"))
        };
        let expected_foreign_key = [(
            0,
            0,
            "validators".into(),
            "validator_id".into(),
            "id".into(),
            "NO ACTION".into(),
            "NO ACTION".into(),
            "NONE".into(),
        )];
        if !foreign_keys("validators")?.is_empty()
            || foreign_keys("signed_blocks")? != expected_foreign_key.clone()
            || foreign_keys("signed_attestations")? != expected_foreign_key
        {
            return Err("unexpected proposer DB foreign keys".into());
        }

        let validator_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM validators", [], |row| row.get(0))
            .map_err(|error| format!("count proposer validators: {error}"))?;
        if validator_rows != 16 {
            return Err(format!(
                "expected 16 proposer validators, found {validator_rows}"
            ));
        }
        Ok(())
    })();
    let rollback = connection
        .execute_batch("ROLLBACK;")
        .map_err(|error| format!("release proposer DB inspection: {error}"));
    validation?;
    rollback?;
    if sidecars.iter().any(|path| path.exists()) {
        return Err("proposer DB inspection left a sidecar".into());
    }
    drop(connection);
    drop(file);
    Ok(())
}

fn require_pq_avx2_launch_profile() {
    #[cfg(target_arch = "x86_64")]
    {
        assert!(
            std::is_x86_feature_detected!("avx2"),
            "pq_e4f_launch requires an AVX2-capable host"
        );
        assert!(
            cfg!(target_feature = "avx2"),
            "pq_e4f_launch requires test and CARGO_BIN_EXE_lighthouse compiled with AVX2"
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    panic!("pq_e4f_launch requires an x86_64 AVX2 host");
}

fn open_bounded_regular_nofollow(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    open_bounded_regular_nofollow_with_hook(path, max, || {})
}

fn open_bounded_regular_nofollow_with_hook(
    path: &Path,
    max: u64,
    after_initial_fstat: impl FnOnce(),
) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let before = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    let mode = before.mode() & 0o7777;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || !matches!(mode, 0o600 | 0o604 | 0o640 | 0o644)
        || before.len() > max
    {
        return Err(format!("unsafe bounded file {}", path.display()));
    }
    after_initial_fstat();
    let limit = max.checked_add(1).ok_or("bounded read limit overflow")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("bounded read {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("post-read fstat {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).map_err(|_| "bounded read length overflow")? > max
        || bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(format!(
            "bounded file changed while read: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn node_args(
    data_dir: &Path,
    network_dir: &Path,
    testnet_dir: &Path,
    execution_url: &str,
    jwt: &Path,
    tcp_port: u16,
    udp_port: u16,
    boot_node: Option<&str>,
    bundle: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "--datadir".into(),
        path_text(data_dir),
        "--testnet-dir".into(),
        path_text(testnet_dir),
        "beacon_node".into(),
        "--network-dir".into(),
        path_text(network_dir),
        "--execution-endpoint".into(),
        execution_url.into(),
        "--execution-jwt".into(),
        path_text(jwt),
        "--listen-address".into(),
        "127.0.0.1".into(),
        "--port".into(),
        tcp_port.to_string(),
        "--discovery-port".into(),
        udp_port.to_string(),
        "--disable-quic".into(),
        "--disable-upnp".into(),
        "--enr-address".into(),
        "127.0.0.1".into(),
        "--enr-tcp-port".into(),
        tcp_port.to_string(),
        "--enr-udp-port".into(),
        udp_port.to_string(),
        "--target-peers".into(),
        "1".into(),
    ];
    if let Some(enr) = boot_node {
        args.extend(["--boot-nodes".into(), enr.into()]);
    }
    if let Some(bundle) = bundle {
        args.extend([
            "--http".into(),
            "--http-address".into(),
            "127.0.0.1".into(),
            "--http-port".into(),
            "0".into(),
            "--pq-validator-bundle".into(),
            path_text(bundle),
        ]);
    }
    args
}

fn path_text(path: &Path) -> String {
    path.to_str().expect("UTF-8 test path").to_owned()
}

fn synthetic_template() -> TempDir {
    let root = tempfile::tempdir().expect("synthetic template root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("synthetic root mode");
    let container = root.path().join("container");
    fs::create_dir(&container).expect("synthetic container");
    fs::set_permissions(&container, fs::Permissions::from_mode(0o755))
        .expect("synthetic container mode");
    let testnet = container.join("testnet");
    fs::create_dir(&testnet).expect("synthetic public directory");
    fs::set_permissions(&testnet, fs::Permissions::from_mode(0o755))
        .expect("synthetic public mode");
    for file in [
        "bootstrap_nodes.yaml",
        "config.yaml",
        "deposit_contract_block.txt",
        "genesis.ssz",
    ] {
        fs::write(testnet.join(file), file.as_bytes()).expect("synthetic public file");
        fs::set_permissions(testnet.join(file), fs::Permissions::from_mode(0o644))
            .expect("synthetic public file mode");
    }
    let bundle = container.join("bundle");
    fs::create_dir(&bundle).expect("synthetic bundle");
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700)).expect("synthetic bundle mode");
    for directory in ["validators", "secrets"] {
        let directory = bundle.join(directory);
        fs::create_dir(&directory).expect("synthetic private directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("synthetic private directory mode");
        for index in 0..16 {
            let entry = directory.join(format!("{index:02}"));
            if directory.ends_with("validators") {
                fs::create_dir(&entry).expect("synthetic validator directory");
                fs::set_permissions(entry, fs::Permissions::from_mode(0o700))
                    .expect("synthetic validator directory mode");
            } else {
                fs::write(&entry, [u8::try_from(index).expect("small index")])
                    .expect("synthetic secret entry");
                fs::set_permissions(entry, fs::Permissions::from_mode(0o600))
                    .expect("synthetic secret entry mode");
            }
        }
    }
    for file in ["pq-devnet.json", "xmss_usage.sqlite.lock"] {
        fs::write(bundle.join(file), b"synthetic").expect("synthetic bundle file");
        fs::set_permissions(bundle.join(file), fs::Permissions::from_mode(0o600))
            .expect("synthetic bundle file mode");
    }
    let journal_path = bundle.join("xmss_usage.sqlite");
    let connection = Connection::open(&journal_path).expect("synthetic journal");
    connection
        .execute_batch(
            "CREATE TABLE xmss_keys (stable_key_id BLOB PRIMARY KEY NOT NULL);
             CREATE TABLE reservations (
                stable_key_id BLOB NOT NULL,
                one_time_use_id INTEGER NOT NULL,
                signing_root BLOB NOT NULL
             );",
        )
        .expect("synthetic journal schema");
    for index in 0..16_u8 {
        connection
            .execute(
                "INSERT INTO xmss_keys (stable_key_id) VALUES (?1)",
                params![vec![index; 32]],
            )
            .expect("synthetic journal key");
    }
    drop(connection);
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600))
        .expect("synthetic journal mode");
    let inventory = inventory_tree(&container).expect("synthetic inventory");
    atomic_replace(
        &root.path().join("inventory"),
        inventory.encode().as_bytes(),
        0o600,
    )
    .expect("synthetic inventory file");
    root
}

#[test]
fn immutable_template_validation_rejects_rewritten_inventory_and_private_mutations() {
    let root = synthetic_template();
    validate_template_structure(root.path()).expect("synthetic template baseline");

    let journal_path = root.path().join("container/bundle/xmss_usage.sqlite");
    let connection = Connection::open(&journal_path).expect("mutation journal");
    let stable_key_id: Vec<u8> = connection
        .query_row("SELECT stable_key_id FROM xmss_keys LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("mutation key");
    connection
        .execute(
            "INSERT INTO reservations (stable_key_id, one_time_use_id, signing_root) VALUES (?1, ?2, ?3)",
            params![stable_key_id, 0_i64, vec![7_u8; 32]],
        )
        .expect("reservation mutation");
    drop(connection);
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("attacker-rewritten inventory");
    assert!(
        validate_template_structure(root.path())
            .expect_err("a reserved journal is never an immutable template")
            .contains("not pristine")
    );

    let root = synthetic_template();
    fs::set_permissions(
        root.path().join("container/testnet/genesis.ssz"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("mode mutation");
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("attacker-rewritten inventory");
    assert!(validate_template_structure(root.path()).is_err());

    let root = synthetic_template();
    fs::set_permissions(
        root.path().join("container/testnet/config.yaml"),
        fs::Permissions::from_mode(0o4644),
    )
    .expect("setuid mode mutation");
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("setuid inventory rewrite");
    assert!(
        validate_template_structure(root.path()).is_err(),
        "special mode bits must remain visible to exact validation"
    );
}

#[test]
fn semantic_anchor_accepts_randomized_encryption_and_rejects_substituted_registry() {
    use consensus_signature::PqPublicKey;

    let registry = vec![PqValidatorRegistryEntry::new(
        0,
        PqPublicKey::deserialize(&[0x11; 32]).expect("canonical semantic key"),
        [0x22; 32],
    )];
    let identity = PqNetworkIdentity {
        genesis_validators_root: [0x33; 32],
        genesis_time: 300,
        eth1_timestamp: 0,
        registry,
        one_time_use_start: 0,
        one_time_use_end: 1119,
    };
    let first_encrypted_inventory = TemplateInventory {
        entries: 1,
        bytes: 10,
        digest: "11".repeat(32),
    };
    let second_encrypted_inventory = TemplateInventory {
        entries: 1,
        bytes: 10,
        digest: "22".repeat(32),
    };
    let trusted_semantic_digest = identity.semantic_digest().expect("semantic test identity");
    assert_eq!(
        trusted_semantic_digest, "e880f744fe2e0a3963e81fd79c72f86828dd3b52b6290fbc9c1cf0e8bc0e9f5f",
        "semantic identity uses fixed-width genesis time and u32 registry cardinality"
    );
    let first = AuthenticatedTemplate {
        inventory: first_encrypted_inventory,
        identity: identity.clone(),
    };
    let second = AuthenticatedTemplate {
        inventory: second_encrypted_inventory,
        identity: identity.clone(),
    };
    assert_ne!(first.inventory, second.inventory);
    validate_semantic_anchor(&first.identity, &trusted_semantic_digest)
        .expect("randomized encrypted bytes are outside semantic identity");
    validate_semantic_anchor(&second.identity, &trusted_semantic_digest)
        .expect("a second randomized encryption retains semantic identity");

    let mut substituted = identity.clone();
    substituted.registry[0] = PqValidatorRegistryEntry::new(
        0,
        PqPublicKey::deserialize(&[0x44; 32]).expect("canonical substituted key"),
        [0x22; 32],
    );
    assert!(validate_semantic_anchor(&substituted, &trusted_semantic_digest).is_err());

    let mut wrong_time = identity;
    wrong_time.genesis_time = 301;
    assert!(validate_frozen_template_identity(&wrong_time).is_err());
    assert_ne!(
        wrong_time.semantic_digest().expect("wrong-time digest"),
        trusted_semantic_digest
    );
}

#[test]
fn compiled_semantic_anchor_matches_the_authenticated_cold_capture() {
    assert_eq!(
        PINNED_TEMPLATE_SEMANTIC_SHA256,
        "0ce1ebc8555a9a65e11d470bda2f697f652b444acc4d1e214bf737288d76addb"
    );
}

#[test]
fn pq_launch_profile_preflights_host_and_compile_time_avx2() {
    require_pq_avx2_launch_profile();
}

#[test]
fn bounded_process_log_retains_events_without_lock_order_deadlock() {
    let log = Arc::new(BoundedProcessLog::default());
    let (completed, completion) = std::sync::mpsc::channel();
    let producer_log = Arc::clone(&log);
    let producer_completed = completed.clone();
    let producer = std::thread::spawn(move || {
        for sequence in 1..=32 {
            producer_log.push(
                "stdout",
                format!(
                    "{PQ_EVENT_PREFIX} event=PeerConnected sequence={sequence} role=verifier \
peer_digest=01010101010101010101010101010101 direction=incoming"
                )
                .as_bytes(),
            );
            for _ in 0..32 {
                producer_log.push("stderr", b"ordinary bounded diagnostic");
            }
        }
        producer_completed.send(()).unwrap();
    });
    let consumer_log = Arc::clone(&log);
    let consumer = std::thread::spawn(move || {
        for _ in 0..10_000 {
            let _ = consumer_log.events();
            let _ = consumer_log.contains_frame("ordinary bounded diagnostic");
        }
        completed.send(()).unwrap();
    });
    completion
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded log producer completed");
    completion
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded log consumer completed");
    producer.join().unwrap();
    consumer.join().unwrap();
    let events = log.events().unwrap();
    assert_eq!(events.len(), 32);
    assert_eq!(events.first().unwrap().sequence, 1);
    assert_eq!(events.last().unwrap().sequence, 32);
}

#[test]
fn structured_event_parser_rejects_malformed_topology_and_bounds_overflow() {
    let valid = "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01010101010101010101010101010101 direction=incoming";
    assert!(parse_pq_process_event(valid).is_ok());
    for invalid in [
        "PQ_EVENT_V1 event=Unknown sequence=1 role=proposer",
        "PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer extra=value",
        "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01 direction=incoming",
        "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01010101010101010101010101010101 direction=sideways",
    ] {
        assert!(
            parse_pq_process_event(invalid).is_err(),
            "accepted {invalid}"
        );
    }

    let log = BoundedProcessLog::default();
    log.push("stderr", valid.as_bytes());
    assert_eq!(log.events().unwrap(), vec![]);
    log.push("stdout", valid.as_bytes());
    log.push(
        "stdout",
        b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer",
    );
    assert_eq!(log.event_failure(), Some(PqProcessEventFailure::Sequence));

    let gap = BoundedProcessLog::default();
    gap.push(
        "stdout",
        b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=verifier",
    );
    gap.push(
        "stdout",
        b"PQ_EVENT_V1 event=PeerCompatible sequence=3 role=verifier \
peer_digest=02020202020202020202020202020202",
    );
    assert_eq!(gap.event_failure(), Some(PqProcessEventFailure::Sequence));

    let peer_digest = [3; 16];
    let valid_trace = vec![
        PqProcessEvent {
            sequence: 1,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::EventWriterReady,
        },
        PqProcessEvent {
            sequence: 2,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::RuntimeReady {
                startup: PqProcessStartup::Fresh,
                slot: 0,
                block_root: Hash256::repeat_byte(1),
                execution_hash: ExecutionBlockHash::zero(),
                finalized_epoch: 0,
                finalized_root: Hash256::ZERO,
                signed_ssz_digest: [2; 32],
            },
        },
        PqProcessEvent {
            sequence: 3,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::PeerConnected {
                peer_digest,
                direction: PqProcessConnectionDirection::Incoming,
            },
        },
        PqProcessEvent {
            sequence: 4,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::StatusSent {
                peer_digest,
                direction: PqProcessStatusDirection::Request,
            },
        },
        PqProcessEvent {
            sequence: 5,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::StatusSent {
                peer_digest,
                direction: PqProcessStatusDirection::Response,
            },
        },
        PqProcessEvent {
            sequence: 6,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::PeerCompatible { peer_digest },
        },
    ];
    validate_compatible_event_trace(
        &valid_trace,
        PqProcessRole::Proposer,
        PqProcessConnectionDirection::Incoming,
        peer_digest,
    )
    .unwrap();
    let mut network_first = valid_trace.clone();
    let runtime_ready = network_first[1].kind;
    network_first[1].kind = network_first[2].kind;
    network_first[2].kind = network_first[3].kind;
    network_first[3].kind = runtime_ready;
    validate_compatible_event_trace(
        &network_first,
        PqProcessRole::Proposer,
        PqProcessConnectionDirection::Incoming,
        peer_digest,
    )
    .expect("network Status may race ahead of RuntimeReady acknowledgement");
    let mut wrong_role = valid_trace.clone();
    wrong_role[5].role = PqProcessRole::Verifier;
    assert!(
        validate_compatible_event_trace(
            &wrong_role,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            peer_digest,
        )
        .is_err()
    );
    let mut wrong_order = valid_trace.clone();
    wrong_order.swap(2, 3);
    assert!(
        validate_compatible_event_trace(
            &wrong_order,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            peer_digest,
        )
        .is_err()
    );
    assert!(
        validate_compatible_event_trace(
            &valid_trace,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Outgoing,
            peer_digest,
        )
        .is_err()
    );
    assert!(
        validate_compatible_event_trace(
            &valid_trace,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            [4; 16],
        )
        .is_err()
    );

    let overflow = BoundedProcessLog::default();
    for sequence in 1..=65 {
        overflow.push(
            "stdout",
            format!(
                "PQ_EVENT_V1 event=PeerCompatible sequence={sequence} role=verifier \
peer_digest=02020202020202020202020202020202"
            )
            .as_bytes(),
        );
    }
    overflow.push("stderr", b"ordinary-after-overflow");
    assert_eq!(
        overflow.event_failure(),
        Some(PqProcessEventFailure::Capacity)
    );
    assert_eq!(
        overflow.events().unwrap_err(),
        PqProcessEventFailure::Capacity
    );
    assert!(overflow.contains_frame("ordinary-after-overflow"));
}

#[test]
fn extended_structured_event_parser_is_exact_and_mutation_sensitive() {
    let runtime = parse_pq_process_event(
        "PQ_EVENT_V1 event=RuntimeReady sequence=6 role=proposer startup=resume slot=3 \
block_root=0x0101010101010101010101010101010101010101010101010101010101010101 \
execution_hash=0x0202020202020202020202020202020202020202020202020202020202020202 \
finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 \
signed_ssz_digest=0404040404040404040404040404040404040404040404040404040404040404",
    )
    .expect("exact runtime-ready event");
    assert!(matches!(
        runtime.kind,
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Resume,
            slot: 3,
            block_root,
            execution_hash,
            finalized_epoch: 0,
            finalized_root,
            signed_ssz_digest,
        } if block_root == types::Hash256::repeat_byte(1)
            && execution_hash == ExecutionBlockHash::repeat_byte(2)
            && finalized_root == types::Hash256::repeat_byte(3)
            && signed_ssz_digest == [4; 32]
    ));
    let block = parse_pq_process_event(
        "PQ_EVENT_V1 event=BlockPersisted sequence=7 role=verifier source=gossip slot=4 \
block_root=0x0505050505050505050505050505050505050505050505050505050505050505 \
execution_hash=0x0606060606060606060606060606060606060606060606060606060606060606 \
finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 \
signed_ssz_digest=0707070707070707070707070707070707070707070707070707070707070707",
    )
    .expect("exact persisted event");
    assert!(matches!(
        block.kind,
        PqProcessEventKind::BlockPersisted {
            source: PqProcessBlockSource::Gossip,
            slot: 4,
            signed_ssz_digest,
            ..
        } if signed_ssz_digest == [7; 32]
    ));
    for invalid in [
        "PQ_EVENT_V1 event=RuntimeReady sequence=1 role=proposer startup=future slot=1 block_root=0x0101010101010101010101010101010101010101010101010101010101010101 execution_hash=0x0202020202020202020202020202020202020202020202020202020202020202 finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 signed_ssz_digest=0404040404040404040404040404040404040404040404040404040404040404",
        "PQ_EVENT_V1 event=BlockPersisted sequence=1 role=verifier source=rpc slot=1 block_root=0x0505050505050505050505050505050505050505050505050505050505050505 execution_hash=0x0606060606060606060606060606060606060606060606060606060606060606 finalized_epoch=0 finalized_root=0x0303030303030303030303030303030303030303030303030303030303030303 signed_ssz_digest=0707070707070707070707070707070707070707070707070707070707070707",
        "PQ_EVENT_V1 event=ProposalStarted sequence=1 role=proposer slot=01 parent_root=0x0505050505050505050505050505050505050505050505050505050505050505",
        "PQ_EVENT_V1 event=ProposalPublished sequence=1 role=proposer slot=2 block_root=0x0505050505050505050505050505050505050505050505050505050505050505 signed_ssz_digest=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(
            parse_pq_process_event(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn three_slot_convergence_contract_is_exact_and_mutation_sensitive() {
    fn status_prefix(role: PqProcessRole) -> Vec<PqProcessEvent> {
        let peer_digest = [9; 16];
        vec![
            PqProcessEvent {
                sequence: 1,
                role,
                kind: PqProcessEventKind::EventWriterReady,
            },
            PqProcessEvent {
                sequence: 2,
                role,
                kind: PqProcessEventKind::RuntimeReady {
                    startup: PqProcessStartup::Fresh,
                    slot: 0,
                    block_root: Hash256::repeat_byte(1),
                    execution_hash: ExecutionBlockHash::zero(),
                    finalized_epoch: 0,
                    finalized_root: Hash256::ZERO,
                    signed_ssz_digest: [2; 32],
                },
            },
            PqProcessEvent {
                sequence: 3,
                role,
                kind: PqProcessEventKind::PeerConnected {
                    peer_digest,
                    direction: PqProcessConnectionDirection::Incoming,
                },
            },
            PqProcessEvent {
                sequence: 4,
                role,
                kind: PqProcessEventKind::StatusSent {
                    peer_digest,
                    direction: PqProcessStatusDirection::Request,
                },
            },
            PqProcessEvent {
                sequence: 5,
                role,
                kind: PqProcessEventKind::StatusSent {
                    peer_digest,
                    direction: PqProcessStatusDirection::Response,
                },
            },
            PqProcessEvent {
                sequence: 6,
                role,
                kind: PqProcessEventKind::PeerCompatible { peer_digest },
            },
        ]
    }

    let mut proposer = status_prefix(PqProcessRole::Proposer);
    let mut verifier = status_prefix(PqProcessRole::Verifier);
    let mut proposer_engine = vec![];
    let mut verifier_engine = vec![];
    proposer_engine.push(MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash: ExecutionBlockHash::zero(),
        safe_block_hash: ExecutionBlockHash::zero(),
        finalized_block_hash: ExecutionBlockHash::zero(),
        has_payload_attributes: false,
    });
    verifier_engine.push(MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash: ExecutionBlockHash::zero(),
        safe_block_hash: ExecutionBlockHash::zero(),
        finalized_block_hash: ExecutionBlockHash::zero(),
        has_payload_attributes: false,
    });
    let mut parent_root = Hash256::repeat_byte(1);
    let mut parent_execution_hash = ExecutionBlockHash::zero();
    for slot in 1_u64..=3 {
        let marker = u8::try_from(slot + 10).unwrap();
        let block_root = Hash256::repeat_byte(marker);
        let execution_hash = ExecutionBlockHash::repeat_byte(marker + 10);
        let digest = [marker + 20; 32];
        let proposer_sequence = u64::try_from(proposer.len() + 1).unwrap();
        proposer.extend([
            PqProcessEvent {
                sequence: proposer_sequence,
                role: PqProcessRole::Proposer,
                kind: PqProcessEventKind::ProposalStarted { slot, parent_root },
            },
            PqProcessEvent {
                sequence: proposer_sequence + 1,
                role: PqProcessRole::Proposer,
                kind: PqProcessEventKind::BlockPersisted {
                    source: PqProcessBlockSource::Publish,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch: 0,
                    finalized_root: Hash256::ZERO,
                    signed_ssz_digest: digest,
                },
            },
            PqProcessEvent {
                sequence: proposer_sequence + 2,
                role: PqProcessRole::Proposer,
                kind: PqProcessEventKind::ExecutionReconciled {
                    source: PqProcessBlockSource::Publish,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch: 0,
                    finalized_root: Hash256::ZERO,
                    signed_ssz_digest: digest,
                },
            },
            PqProcessEvent {
                sequence: proposer_sequence + 3,
                role: PqProcessRole::Proposer,
                kind: PqProcessEventKind::ProposalPublished {
                    slot,
                    block_root,
                    signed_ssz_digest: digest,
                },
            },
        ]);
        let verifier_sequence = u64::try_from(verifier.len() + 1).unwrap();
        verifier.extend([
            PqProcessEvent {
                sequence: verifier_sequence,
                role: PqProcessRole::Verifier,
                kind: PqProcessEventKind::BlockPersisted {
                    source: PqProcessBlockSource::Gossip,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch: 0,
                    finalized_root: Hash256::ZERO,
                    signed_ssz_digest: digest,
                },
            },
            PqProcessEvent {
                sequence: verifier_sequence + 1,
                role: PqProcessRole::Verifier,
                kind: PqProcessEventKind::ExecutionReconciled {
                    source: PqProcessBlockSource::Gossip,
                    slot,
                    block_root,
                    execution_hash,
                    finalized_epoch: 0,
                    finalized_root: Hash256::ZERO,
                    signed_ssz_digest: digest,
                },
            },
            PqProcessEvent {
                sequence: verifier_sequence + 2,
                role: PqProcessRole::Verifier,
                kind: PqProcessEventKind::GossipImported {
                    slot,
                    block_root,
                    signed_ssz_digest: digest,
                },
            },
        ]);
        proposer_engine.extend([
            MockEngineAuditEvent::ForkchoiceUpdated {
                head_block_hash: parent_execution_hash,
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
                has_payload_attributes: true,
            },
            MockEngineAuditEvent::GetPayload {
                block_hash: execution_hash,
                blob_count: 0,
            },
            MockEngineAuditEvent::NewPayload {
                block_hash: execution_hash,
                blob_count: 0,
            },
            MockEngineAuditEvent::ForkchoiceUpdated {
                head_block_hash: execution_hash,
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
                has_payload_attributes: false,
            },
        ]);
        verifier_engine.extend([
            MockEngineAuditEvent::NewPayload {
                block_hash: execution_hash,
                blob_count: 0,
            },
            MockEngineAuditEvent::ForkchoiceUpdated {
                head_block_hash: execution_hash,
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
                has_payload_attributes: false,
            },
        ]);
        parent_root = block_root;
        parent_execution_hash = execution_hash;
    }
    validate_three_slot_process_convergence(
        &proposer,
        &verifier,
        &proposer_engine,
        &verifier_engine,
    )
    .expect("exact synthetic three-slot convergence");

    let mut wrong_digest = verifier.clone();
    if let PqProcessEventKind::GossipImported {
        signed_ssz_digest, ..
    } = &mut wrong_digest.last_mut().unwrap().kind
    {
        *signed_ssz_digest = [0xff; 32];
    }
    assert!(
        validate_three_slot_process_convergence(
            &proposer,
            &wrong_digest,
            &proposer_engine,
            &verifier_engine,
        )
        .is_err()
    );
    let mut wrong_order = proposer.clone();
    wrong_order.swap(7, 8);
    assert!(
        validate_three_slot_process_convergence(
            &wrong_order,
            &verifier,
            &proposer_engine,
            &verifier_engine,
        )
        .is_err()
    );
    let mut overlapping_slots = proposer.clone();
    let first_publication = overlapping_slots[9].kind;
    overlapping_slots[9].kind = overlapping_slots[10].kind;
    overlapping_slots[10].kind = first_publication;
    assert!(
        validate_three_slot_process_convergence(
            &overlapping_slots,
            &verifier,
            &proposer_engine,
            &verifier_engine,
        )
        .is_err()
    );
    let mut skipped_slot = proposer.clone();
    if let PqProcessEventKind::ProposalStarted { slot, .. } = &mut skipped_slot[10].kind {
        *slot += 1;
    }
    assert!(
        validate_three_slot_process_convergence(
            &skipped_slot,
            &verifier,
            &proposer_engine,
            &verifier_engine,
        )
        .is_err()
    );
    let mut blobbed = proposer_engine.clone();
    if let MockEngineAuditEvent::GetPayload { blob_count, .. } = &mut blobbed[2] {
        *blob_count = 1;
    } else {
        panic!("expected first proposer getPayload audit at index 2");
    }
    assert!(
        validate_three_slot_process_convergence(&proposer, &verifier, &blobbed, &verifier_engine,)
            .is_err()
    );
    let mut missing_attributes = proposer_engine.clone();
    missing_attributes.remove(1);
    assert!(
        validate_three_slot_process_convergence(
            &proposer,
            &verifier,
            &missing_attributes,
            &verifier_engine,
        )
        .is_err()
    );
    let mut extra_attributes = proposer_engine.clone();
    extra_attributes.insert(1, extra_attributes[1]);
    assert!(
        validate_three_slot_process_convergence(
            &proposer,
            &verifier,
            &extra_attributes,
            &verifier_engine,
        )
        .is_err()
    );
    let mut wrong_attributes = proposer_engine.clone();
    if let MockEngineAuditEvent::ForkchoiceUpdated {
        has_payload_attributes,
        ..
    } = &mut wrong_attributes[1]
    {
        *has_payload_attributes = false;
    }
    assert!(
        validate_three_slot_process_convergence(
            &proposer,
            &verifier,
            &wrong_attributes,
            &verifier_engine,
        )
        .is_err()
    );
}

#[test]
fn three_slot_wait_uses_a_checked_absolute_genesis_deadline() {
    assert_eq!(
        three_slot_wait_remaining(900, 0).unwrap(),
        Duration::from_secs(2_085),
        "genesis lead plus slot-3 boundary plus 285-second completion budget",
    );
    assert_eq!(
        three_slot_wait_remaining(900, 2_084).unwrap(),
        Duration::from_secs(1),
    );
    assert!(three_slot_wait_remaining(900, 2_085).is_err());
    assert!(three_slot_wait_remaining(u64::MAX, 0).is_err());
}

#[test]
fn restart_ready_deadline_is_checked_and_precedes_slot_five() {
    assert_eq!(
        restart_ready_remaining(0, 1_494).unwrap(),
        Duration::from_secs(1),
    );
    assert!(restart_ready_remaining(0, 1_495).is_err());
    assert!(restart_ready_remaining(0, 1_500).is_err());
    assert!(restart_ready_remaining(u64::MAX, 0).is_err());
}

#[test]
fn restart_idempotence_contract_is_exact_and_mutation_sensitive() {
    let identity = PqProcessBlockIdentity {
        slot: 3,
        block_root: Hash256::repeat_byte(0x33),
        execution_hash: ExecutionBlockHash::from_root(Hash256::repeat_byte(0x44)),
        finalized_epoch: 0,
        finalized_root: Hash256::ZERO,
        signed_ssz_digest: [0x55; 32],
    };
    let events = |role| {
        vec![
            PqProcessEvent {
                sequence: 1,
                role,
                kind: PqProcessEventKind::EventWriterReady,
            },
            PqProcessEvent {
                sequence: 2,
                role,
                kind: PqProcessEventKind::RuntimeReady {
                    startup: PqProcessStartup::Resume,
                    slot: identity.slot,
                    block_root: identity.block_root,
                    execution_hash: identity.execution_hash,
                    finalized_epoch: identity.finalized_epoch,
                    finalized_root: identity.finalized_root,
                    signed_ssz_digest: identity.signed_ssz_digest,
                },
            },
        ]
    };
    let proposer = events(PqProcessRole::Proposer);
    let verifier = events(PqProcessRole::Verifier);
    let proposer_before = vec![MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash: identity.execution_hash,
        safe_block_hash: ExecutionBlockHash::zero(),
        finalized_block_hash: ExecutionBlockHash::zero(),
        has_payload_attributes: false,
    }];
    let verifier_before = proposer_before.clone();
    let mut proposer_after = proposer_before.clone();
    proposer_after.push(MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash: identity.execution_hash,
        safe_block_hash: ExecutionBlockHash::zero(),
        finalized_block_hash: ExecutionBlockHash::zero(),
        has_payload_attributes: false,
    });
    let verifier_after = proposer_after.clone();
    validate_restart_idempotence(
        &proposer,
        &verifier,
        identity,
        &proposer_before,
        &proposer_after,
        &verifier_before,
        &verifier_after,
    )
    .expect("exact resume is idempotent");

    let mut wrong_digest = proposer.clone();
    if let PqProcessEventKind::RuntimeReady {
        signed_ssz_digest, ..
    } = &mut wrong_digest[1].kind
    {
        *signed_ssz_digest = [0xff; 32];
    }
    assert!(
        validate_restart_idempotence(
            &wrong_digest,
            &verifier,
            identity,
            &proposer_before,
            &proposer_after,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );
    let mut proposal_after_ready = proposer.clone();
    proposal_after_ready.push(PqProcessEvent {
        sequence: 3,
        role: PqProcessRole::Proposer,
        kind: PqProcessEventKind::ProposalStarted {
            slot: 4,
            parent_root: identity.block_root,
        },
    });
    assert!(
        validate_restart_idempotence(
            &proposal_after_ready,
            &verifier,
            identity,
            &proposer_before,
            &proposer_after,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );

    for mutation in [
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Fresh,
            slot: identity.slot,
            block_root: identity.block_root,
            execution_hash: identity.execution_hash,
            finalized_epoch: identity.finalized_epoch,
            finalized_root: identity.finalized_root,
            signed_ssz_digest: identity.signed_ssz_digest,
        },
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Resume,
            slot: identity.slot + 1,
            block_root: identity.block_root,
            execution_hash: identity.execution_hash,
            finalized_epoch: identity.finalized_epoch,
            finalized_root: identity.finalized_root,
            signed_ssz_digest: identity.signed_ssz_digest,
        },
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Resume,
            slot: identity.slot,
            block_root: Hash256::repeat_byte(0xee),
            execution_hash: identity.execution_hash,
            finalized_epoch: identity.finalized_epoch,
            finalized_root: identity.finalized_root,
            signed_ssz_digest: identity.signed_ssz_digest,
        },
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Resume,
            slot: identity.slot,
            block_root: identity.block_root,
            execution_hash: ExecutionBlockHash::from_root(Hash256::repeat_byte(0xee)),
            finalized_epoch: identity.finalized_epoch,
            finalized_root: identity.finalized_root,
            signed_ssz_digest: identity.signed_ssz_digest,
        },
        PqProcessEventKind::RuntimeReady {
            startup: PqProcessStartup::Resume,
            slot: identity.slot,
            block_root: identity.block_root,
            execution_hash: identity.execution_hash,
            finalized_epoch: 1,
            finalized_root: Hash256::repeat_byte(0xee),
            signed_ssz_digest: identity.signed_ssz_digest,
        },
    ] {
        let mut mutated = proposer.clone();
        mutated[1].kind = mutation;
        assert!(
            validate_restart_idempotence(
                &mutated,
                &verifier,
                identity,
                &proposer_before,
                &proposer_after,
                &verifier_before,
                &verifier_after,
            )
            .is_err()
        );
    }

    let mut proposal_race = proposer.clone();
    proposal_race.insert(
        1,
        PqProcessEvent {
            sequence: 2,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::ProposalStarted {
                slot: 4,
                parent_root: identity.block_root,
            },
        },
    );
    proposal_race[2].sequence = 3;
    assert!(
        validate_restart_idempotence(
            &proposal_race,
            &verifier,
            identity,
            &proposer_before,
            &proposer_after,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );

    let mut extra_engine_call = proposer_after.clone();
    extra_engine_call.push(MockEngineAuditEvent::NewPayload {
        block_hash: identity.execution_hash,
        blob_count: 0,
    });
    assert!(
        validate_restart_idempotence(
            &proposer,
            &verifier,
            identity,
            &proposer_before,
            &extra_engine_call,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );

    let mut wrong_replay = proposer_after.clone();
    if let MockEngineAuditEvent::ForkchoiceUpdated {
        head_block_hash, ..
    } = wrong_replay.last_mut().expect("restart replay")
    {
        *head_block_hash = ExecutionBlockHash::zero();
    }
    assert!(
        validate_restart_idempotence(
            &proposer,
            &verifier,
            identity,
            &proposer_before,
            &wrong_replay,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );
    assert!(
        validate_restart_idempotence(
            &proposer,
            &verifier,
            identity,
            &proposer_before,
            &proposer_before,
            &verifier_before,
            &verifier_after,
        )
        .is_err()
    );
}

#[test]
fn pq_leveldb_lock_holder_process() {
    let Some(path) = std::env::var_os(PQ_LEVELDB_LOCK_PATH_ENV) else {
        return;
    };
    let ready =
        std::env::var_os(PQ_LEVELDB_LOCK_READY_ENV).expect("LevelDB lock-holder ready path");
    let database = store::database::interface::BeaconNodeBackend::open(
        &store::StoreConfig::default(),
        Path::new(&path),
    )
    .expect("hold LevelDB in helper process");
    File::create(ready).expect("publish LevelDB lock-holder readiness");
    let mut stop = [0];
    std::io::stdin()
        .read_exact(&mut stop)
        .expect("wait for parent stop");
    drop(database);
}

#[test]
fn pq_sqlite_lock_holder_process() {
    let Some(path) = std::env::var_os(PQ_SQLITE_LOCK_PATH_ENV) else {
        return;
    };
    let ready = std::env::var_os(PQ_SQLITE_LOCK_READY_ENV).expect("SQLite lock-holder ready path");
    let connection = Connection::open_with_flags(
        Path::new(&path),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .expect("open SQLite in helper process");
    connection
        .busy_timeout(Duration::from_millis(100))
        .expect("bounded SQLite lock-holder timeout");
    connection
        .pragma_update(None, "locking_mode", "EXCLUSIVE")
        .expect("exclusive SQLite lock-holder mode");
    connection
        .execute_batch("BEGIN EXCLUSIVE;")
        .expect("hold SQLite transaction in helper process");
    File::create(ready).expect("publish SQLite lock-holder readiness");
    let mut stop = [0];
    std::io::stdin()
        .read_exact(&mut stop)
        .expect("wait for parent stop");
    connection
        .execute_batch("ROLLBACK;")
        .expect("release SQLite helper transaction");
}

#[test]
fn restart_resource_probe_is_mutation_sensitive() {
    let held_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("held TCP listener");
    let held_tcp_port = held_tcp.local_addr().expect("held TCP address").port();
    let held_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("held UDP socket");
    let held_udp_port = held_udp.local_addr().expect("held UDP address").port();
    assert!(probe_network_ports_released(&[held_tcp_port], &[held_udp_port]).is_err());
    drop(held_tcp);
    drop(held_udp);
    probe_network_ports_released(&[held_tcp_port], &[held_udp_port])
        .expect("stopped runtime releases its network listeners");

    let data_dir = tempfile::tempdir().expect("store resource probe");
    let config = store::StoreConfig::default();
    for name in ["chain_db", "freezer_db", "blobs_db"] {
        drop(
            store::database::interface::BeaconNodeBackend::open(
                &config,
                &data_dir.path().join(name),
            )
            .expect("closed direct-root decoy store"),
        );
    }
    let actual_data_dir = data_dir.path().join(directory::DEFAULT_BEACON_NODE_DIR);
    fs::create_dir(&actual_data_dir).expect("actual beacon-node data directory");
    let actual_paths = pq_store_paths(data_dir.path());
    for path in &actual_paths {
        drop(
            store::database::interface::BeaconNodeBackend::open(&config, path)
                .expect("closed real chain store"),
        );
    }
    for (index, path) in actual_paths.iter().enumerate() {
        let ready = data_dir.path().join(format!("leveldb-lock-ready-{index}"));
        let held_store = HeldLevelDbProcess::spawn(path, &ready)
            .expect("held real chain store in an independent process");
        assert!(
            probe_chain_store_released(data_dir.path()).is_err(),
            "a held {} store must be detected",
            path.file_name().expect("store basename").to_string_lossy(),
        );
        held_store.stop().expect("stop LevelDB lock holder");
        probe_chain_store_released(data_dir.path())
            .expect("released individual store permits exact inspection");
    }
    probe_chain_store_released(data_dir.path())
        .expect("stopped runtime releases all three chain databases");
}

#[test]
fn chain_store_probe_rejects_wrong_or_missing_effective_paths_without_creating() {
    let cli_data_dir = tempfile::tempdir().expect("missing store resource probe");
    let config = store::StoreConfig::default();
    for name in ["chain_db", "freezer_db", "blobs_db"] {
        drop(
            store::database::interface::BeaconNodeBackend::open(
                &config,
                &cli_data_dir.path().join(name),
            )
            .expect("closed wrong-root decoy store"),
        );
    }
    fs::create_dir(pq_node_data_dir(cli_data_dir.path()))
        .expect("existing effective beacon data directory");
    let effective_paths = pq_store_paths(cli_data_dir.path());
    assert!(probe_chain_store_released(cli_data_dir.path()).is_err());
    assert!(
        effective_paths.iter().all(|path| !path.exists()),
        "a release probe must never create missing effective store directories",
    );
}

#[test]
fn chain_store_probe_rejects_empty_decoys_without_creating_leveldb_identity() {
    let cli_data_dir = tempfile::tempdir().expect("empty store resource probe");
    fs::create_dir(pq_node_data_dir(cli_data_dir.path()))
        .expect("existing effective beacon data directory");
    let effective_paths = pq_store_paths(cli_data_dir.path());
    for path in &effective_paths {
        fs::create_dir(path).expect("empty decoy store directory");
    }

    assert!(probe_chain_store_released(cli_data_dir.path()).is_err());
    for path in &effective_paths {
        assert!(
            fs::read_dir(path)
                .expect("read unchanged empty store")
                .next()
                .is_none(),
            "release inspection must not initialize an empty store directory",
        );
    }
}

#[test]
fn chain_store_probe_rejects_effective_beacon_directory_symlink() {
    let cli_data_dir = tempfile::tempdir().expect("beacon symlink store probe");
    let actual_beacon = cli_data_dir.path().join("actual-beacon");
    fs::create_dir(&actual_beacon).expect("actual beacon store parent");
    let config = store::StoreConfig::default();
    for name in ["chain_db", "freezer_db", "blobs_db"] {
        drop(
            store::database::interface::BeaconNodeBackend::open(&config, &actual_beacon.join(name))
                .expect("closed substituted chain store"),
        );
    }
    std::os::unix::fs::symlink(&actual_beacon, pq_node_data_dir(cli_data_dir.path()))
        .expect("substitute effective beacon directory symlink");

    assert!(probe_chain_store_released(cli_data_dir.path()).is_err());
}

#[test]
fn chain_store_probe_opens_validated_directory_after_path_replacement() {
    let cli_data_dir = tempfile::tempdir().expect("interposed store resource probe");
    fs::create_dir(pq_node_data_dir(cli_data_dir.path())).expect("effective beacon data directory");
    let config = store::StoreConfig::default();
    let paths = pq_store_paths(cli_data_dir.path());
    for path in &paths {
        drop(
            store::database::interface::BeaconNodeBackend::open(&config, path)
                .expect("closed validated store"),
        );
    }
    let replacement = pq_node_data_dir(cli_data_dir.path()).join("replacement-chain");
    drop(
        store::database::interface::BeaconNodeBackend::open(&config, &replacement)
            .expect("closed replacement store"),
    );
    fs::write(replacement.join("CURRENT"), b"MALFORMED\n")
        .expect("corrupt replacement store identity");
    let original = paths[0].with_extension("original");
    let displaced_replacement = replacement.with_extension("displaced");
    let before_path = paths[0].clone();
    let before_original = original.clone();
    let before_replacement = replacement.clone();
    let after_path = paths[0].clone();
    let after_original = original.clone();
    let after_displaced = displaced_replacement.clone();

    probe_chain_store_released_with_hooks(
        cli_data_dir.path(),
        move || {
            fs::rename(&before_path, &before_original).expect("retain validated store inode");
            fs::rename(&before_replacement, &before_path)
                .expect("interpose held replacement store");
        },
        move || {
            fs::rename(&after_path, &after_displaced).expect("displace replacement store");
            fs::rename(&after_original, &after_path).expect("restore validated store binding");
        },
    )
    .expect("backend opens the held validated directory rather than its replaced pathname");
}

#[test]
fn chain_store_probe_rejects_malformed_leveldb_identity() {
    let create = || {
        let root = tempfile::tempdir().expect("malformed LevelDB identity root");
        fs::create_dir(pq_node_data_dir(root.path())).expect("effective beacon data directory");
        let paths = pq_store_paths(root.path());
        let config = store::StoreConfig::default();
        for path in &paths {
            drop(
                store::database::interface::BeaconNodeBackend::open(&config, path)
                    .expect("closed real chain store"),
            );
        }
        (root, paths)
    };

    let (root, paths) = create();
    File::create(paths[0].join("CURRENT")).expect("truncate CURRENT");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    fs::write(paths[1].join("CURRENT"), b"../MANIFEST-000001\n").expect("write unsafe CURRENT");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    let manifest = fs::read_to_string(paths[2].join("CURRENT"))
        .expect("read current manifest")
        .trim_end_matches('\n')
        .to_owned();
    File::create(paths[2].join(manifest)).expect("truncate manifest");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    fs::hard_link(paths[0].join("LOCK"), paths[0].join("LOCK.extra"))
        .expect("add LevelDB LOCK hard link");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    fs::set_permissions(paths[1].join("LOCK"), fs::Permissions::from_mode(0o666))
        .expect("weaken LevelDB LOCK mode");
    assert!(probe_chain_store_released(root.path()).is_err());
}

#[test]
fn chain_store_probe_rejects_unsafe_type_mode_and_symlink() {
    let create = || {
        let root = tempfile::tempdir().expect("mutated store resource probe");
        fs::create_dir(pq_node_data_dir(root.path())).expect("effective beacon data directory");
        let paths = pq_store_paths(root.path());
        let config = store::StoreConfig::default();
        for path in &paths {
            drop(
                store::database::interface::BeaconNodeBackend::open(&config, path)
                    .expect("closed real chain store"),
            );
        }
        (root, paths)
    };

    let (root, paths) = create();
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o777))
        .expect("weaken chain store mode");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    let original = paths[1].with_extension("original");
    fs::rename(&paths[1], &original).expect("retain freezer store");
    std::os::unix::fs::symlink(&original, &paths[1]).expect("substitute freezer symlink");
    assert!(probe_chain_store_released(root.path()).is_err());

    let (root, paths) = create();
    fs::remove_dir_all(&paths[2]).expect("remove blobs store directory");
    File::create(&paths[2]).expect("substitute blobs store file");
    assert!(probe_chain_store_released(root.path()).is_err());
    assert!(
        paths[2].is_file(),
        "release inspection must never replace an invalid store path",
    );
}

const PROBE_SLASHING_SCHEMA: &str = "CREATE TABLE validators (
        id INTEGER PRIMARY KEY,
        public_key BLOB NOT NULL UNIQUE,
        enabled BOOL NOT NULL DEFAULT TRUE
    );
    CREATE TABLE signed_blocks (
        validator_id INTEGER NOT NULL,
        slot INTEGER NOT NULL,
        signing_root BLOB NOT NULL,
        FOREIGN KEY(validator_id) REFERENCES validators(id),
        UNIQUE (validator_id, slot)
    );
    CREATE TABLE signed_attestations (
        validator_id INTEGER,
        source_epoch INTEGER NOT NULL,
        target_epoch INTEGER NOT NULL,
        signing_root BLOB NOT NULL,
        FOREIGN KEY(validator_id) REFERENCES validators(id),
        UNIQUE (validator_id, target_epoch)
    );";

fn create_probe_slashing_database_with_schema(path: &Path, schema: &str) -> Connection {
    fs::create_dir_all(path.parent().expect("slashing DB parent"))
        .expect("create slashing DB parent");
    let connection = Connection::open(path).expect("create probe slashing DB");
    connection
        .execute_batch(schema)
        .expect("create exact slashing schema");
    for index in 0_u8..16 {
        connection
            .execute(
                "INSERT INTO validators (public_key, enabled) VALUES (?1, TRUE)",
                params![vec![index; 32]],
            )
            .expect("register probe validator");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private slashing DB mode");
    connection
}

fn create_probe_slashing_database(path: &Path) -> Connection {
    create_probe_slashing_database_with_schema(path, PROBE_SLASHING_SCHEMA)
}

#[test]
fn proposer_slashing_probe_uses_real_cli_path_and_never_creates() {
    let cli_data_dir = tempfile::tempdir().expect("slashing resource probe");
    let direct_decoy = cli_data_dir
        .path()
        .join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&direct_decoy));
    let decoy_inventory = || {
        let mut entries = fs::read_dir(direct_decoy.parent().expect("direct decoy parent"))
            .expect("read direct decoy directory")
            .map(|entry| {
                let entry = entry.expect("read direct decoy entry");
                (
                    entry.file_name(),
                    entry.metadata().expect("inspect direct decoy entry").len(),
                )
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    };
    let decoy_before = decoy_inventory();
    let real_path =
        pq_node_data_dir(cli_data_dir.path()).join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&real_path));
    let ready = cli_data_dir.path().join("sqlite-lock-ready");
    let held = HeldSqliteProcess::spawn(&real_path, &ready)
        .expect("hold real proposer DB in an independent process");

    let blocked_probe_started = Instant::now();
    assert!(probe_slashing_db_released(cli_data_dir.path()).is_err());
    assert!(
        blocked_probe_started.elapsed() < Duration::from_secs(2),
        "cross-process SQLite lock detection must honor its bounded busy timeout",
    );
    held.stop().expect("stop SQLite lock holder");
    probe_slashing_db_released(cli_data_dir.path())
        .expect("stopped runtime releases exact proposer SQLite ownership");
    assert_eq!(
        decoy_inventory(),
        decoy_before,
        "release inspection must not create or mutate direct-root decoy files",
    );

    let absent = tempfile::tempdir().expect("absent slashing DB root");
    assert!(probe_slashing_db_released(absent.path()).is_err());
    assert!(
        !pq_node_data_dir(absent.path())
            .join("pq-proposer/slashing_protection.sqlite")
            .exists(),
        "release inspection must never create an absent database",
    );
}

#[test]
fn proposer_slashing_probe_rejects_inode_schema_and_registration_mutations() {
    let create = || {
        let root = tempfile::tempdir().expect("mutated proposer DB root");
        let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
        let connection = create_probe_slashing_database(&path);
        (root, path, connection)
    };

    let (_root, _path, connection) = create();
    connection
        .execute("DELETE FROM validators WHERE id = 16", [])
        .expect("remove one validator registration");
    drop(connection);
    assert!(probe_slashing_db_released(_root.path()).is_err());

    let (_root, _path, connection) = create();
    connection
        .execute("CREATE TABLE unexpected_state (id INTEGER)", [])
        .expect("add unexpected schema");
    drop(connection);
    assert!(probe_slashing_db_released(_root.path()).is_err());

    let (_root, _path, connection) = create();
    connection
        .execute("ALTER TABLE validators ADD COLUMN unexpected INTEGER", [])
        .expect("mutate validator schema");
    drop(connection);
    assert!(probe_slashing_db_released(_root.path()).is_err());

    let (_root, path, connection) = create();
    drop(connection);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("weaken proposer DB mode");
    assert!(probe_slashing_db_released(_root.path()).is_err());

    let (_root, path, connection) = create();
    drop(connection);
    fs::hard_link(&path, path.with_extension("hardlink")).expect("add proposer DB hard link");
    assert!(probe_slashing_db_released(_root.path()).is_err());

    let root = tempfile::tempdir().expect("empty proposer DB root");
    let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
    fs::create_dir_all(path.parent().expect("empty proposer DB parent"))
        .expect("create empty proposer DB parent");
    File::create(&path).expect("create empty proposer DB");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("empty proposer DB mode");
    assert!(probe_slashing_db_released(root.path()).is_err());

    let root = tempfile::tempdir().expect("symlink proposer DB root");
    let proposer_dir = pq_node_data_dir(root.path()).join("pq-proposer");
    fs::create_dir_all(&proposer_dir).expect("symlink proposer DB parent");
    let target = proposer_dir.join("target.sqlite");
    drop(create_probe_slashing_database(&target));
    std::os::unix::fs::symlink(&target, proposer_dir.join("slashing_protection.sqlite"))
        .expect("symlink proposer DB");
    assert!(probe_slashing_db_released(root.path()).is_err());
}

#[test]
fn proposer_slashing_probe_rejects_parent_directory_symlink_substitution() {
    let root = tempfile::tempdir().expect("symlink beacon directory root");
    let actual_beacon = root.path().join("actual-beacon");
    let actual_db = actual_beacon.join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&actual_db));
    std::os::unix::fs::symlink(&actual_beacon, pq_node_data_dir(root.path()))
        .expect("substitute beacon directory symlink");
    assert!(probe_slashing_db_released(root.path()).is_err());

    let root = tempfile::tempdir().expect("symlink proposer directory root");
    let beacon = pq_node_data_dir(root.path());
    fs::create_dir(&beacon).expect("real beacon directory");
    let actual_proposer = root.path().join("actual-proposer");
    let actual_db = actual_proposer.join("slashing_protection.sqlite");
    drop(create_probe_slashing_database(&actual_db));
    std::os::unix::fs::symlink(&actual_proposer, beacon.join("pq-proposer"))
        .expect("substitute proposer directory symlink");
    assert!(probe_slashing_db_released(root.path()).is_err());

    let root = tempfile::tempdir().expect("unsafe beacon directory root");
    let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&path));
    fs::set_permissions(
        pq_node_data_dir(root.path()),
        fs::Permissions::from_mode(0o777),
    )
    .expect("weaken beacon directory mode");
    assert!(probe_slashing_db_released(root.path()).is_err());

    let root = tempfile::tempdir().expect("unsafe proposer directory root");
    let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&path));
    fs::set_permissions(
        path.parent().expect("proposer directory"),
        fs::Permissions::from_mode(0o777),
    )
    .expect("weaken proposer directory mode");
    assert!(probe_slashing_db_released(root.path()).is_err());
}

#[test]
fn proposer_slashing_probe_opens_validated_parent_after_path_replacement() {
    let root = tempfile::tempdir().expect("interposed proposer parent root");
    let proposer = pq_node_data_dir(root.path()).join("pq-proposer");
    let path = proposer.join("slashing_protection.sqlite");
    drop(create_probe_slashing_database(&path));
    let original = proposer.with_extension("original");
    let replacement = proposer.with_extension("replacement");
    fs::create_dir(&replacement).expect("replacement proposer directory");
    let replacement_db = replacement.join("slashing_protection.sqlite");
    File::create(&replacement_db).expect("empty replacement proposer DB");
    fs::set_permissions(&replacement_db, fs::Permissions::from_mode(0o600))
        .expect("private replacement proposer DB");
    let displaced_replacement = replacement.with_extension("displaced");
    let proposer_before = proposer.clone();
    let original_before = original.clone();
    let replacement_before = replacement.clone();
    let proposer_after = proposer.clone();
    let original_after = original.clone();
    let displaced_after = displaced_replacement.clone();

    probe_slashing_db_released_with_parent_hooks(
        root.path(),
        move || {
            fs::rename(&proposer_before, &original_before)
                .expect("retain validated proposer directory");
            fs::rename(&replacement_before, &proposer_before)
                .expect("interpose replacement proposer directory");
        },
        move || {
            fs::rename(&proposer_after, &displaced_after)
                .expect("displace replacement proposer directory");
            fs::rename(&original_after, &proposer_after)
                .expect("restore validated proposer directory");
        },
    )
    .expect("SQLite inspection remains anchored to the held proposer directory");
}

#[test]
fn proposer_slashing_probe_retains_validated_inode_after_interposed_symlink() {
    let root = tempfile::tempdir().expect("SQLite symlink-swap root");
    let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
    drop(create_probe_slashing_database(&path));
    let backup = path.with_extension("original");
    let replacement = path.with_extension("replacement");
    File::create(&replacement).expect("empty replacement proposer DB");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
        .expect("private replacement proposer DB");

    let path_before_open = path.clone();
    let backup_before_open = backup.clone();
    let replacement_before_open = replacement.clone();
    let path_after_open = path.clone();
    let backup_after_open = backup.clone();
    probe_slashing_db_released_with_hooks(
        root.path(),
        move || {
            fs::rename(&path_before_open, &backup_before_open)
                .expect("retain validated original proposer DB");
            std::os::unix::fs::symlink(&replacement_before_open, &path_before_open)
                .expect("interpose proposer DB symlink");
        },
        move || {
            fs::remove_file(&path_after_open).expect("remove interposed proposer DB symlink");
            fs::rename(&backup_after_open, &path_after_open)
                .expect("restore validated original proposer DB");
        },
    )
    .expect("SQLite must retain the validated file inode across final-name replacement");
}

#[test]
fn proposer_slashing_probe_rejects_missing_unique_and_foreign_key_constraints() {
    let mutations = [
        PROBE_SLASHING_SCHEMA.replace(
            "public_key BLOB NOT NULL UNIQUE",
            "public_key BLOB NOT NULL",
        ),
        PROBE_SLASHING_SCHEMA.replace("UNIQUE (validator_id, slot)", "CHECK (validator_id >= 0)"),
        PROBE_SLASHING_SCHEMA.replace(
            "UNIQUE (validator_id, target_epoch)",
            "CHECK (validator_id >= 0)",
        ),
        PROBE_SLASHING_SCHEMA.replacen(
            "FOREIGN KEY(validator_id) REFERENCES validators(id),",
            "",
            1,
        ),
        PROBE_SLASHING_SCHEMA
            .rsplit_once("FOREIGN KEY(validator_id) REFERENCES validators(id),")
            .map(|(prefix, suffix)| format!("{prefix}{suffix}"))
            .expect("attestation foreign-key schema mutation"),
    ];
    for schema in mutations {
        let root = tempfile::tempdir().expect("constraint mutation root");
        let path = pq_node_data_dir(root.path()).join("pq-proposer/slashing_protection.sqlite");
        drop(create_probe_slashing_database_with_schema(&path, &schema));
        probe_slashing_db_released(root.path())
            .expect_err("slashing-critical schema constraint mutation must be rejected");
    }
}

#[tokio::test]
async fn pq_operational_event_writer_reaches_process_stdout() {
    let (sink, writer) = PqOperationalEventSink::channel(PqOperationalEventRole::Proposer);
    sink.try_emit(PqOperationalEvent::PeerCompatible {
        peer_digest: [0x5a; 16],
    })
    .expect("bounded operational event");
    drop(sink);
    tokio::task::spawn_blocking(move || writer.run())
        .await
        .expect("operational event writer task")
        .expect("operational event writer");
}

#[test]
fn template_authentication_is_once_and_genesis_selection_follows_copy() {
    let mut early = TemplatePreparationAudit::default();
    assert!(early.select_genesis_time(100).is_err());

    let mut preparation = TemplatePreparationAudit::default();
    preparation
        .record_authentication()
        .expect("first authentication");
    assert!(preparation.record_authentication().is_err());
    assert!(preparation.select_genesis_time(100).is_err());
    preparation
        .record_copy()
        .expect("copy after authentication");
    assert_eq!(
        preparation
            .select_genesis_time(100)
            .expect("late genesis selection"),
        1000
    );
    assert!(preparation.select_genesis_time(100).is_err());
    preparation
        .finish()
        .expect("complete preparation lifecycle");
}

#[test]
fn descriptor_anchoring_rejects_lock_and_special_file_mutations() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::tempdir().expect("descriptor mutation root");
    let target = open_directory_nofollow(root.path(), None).expect("held target directory");
    std::os::unix::fs::symlink("elsewhere", root.path().join("pq-e4f-template.lock"))
        .expect("lock symlink mutation");
    assert!(open_fixture_lock(&target).is_err());

    let oversized = root.path().join("oversized");
    fs::write(&oversized, [0_u8; 5]).expect("oversized fixture");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
        .expect("oversized fixture mode");
    let mut oversized =
        open_anchored_file(&target, "oversized", Some(0o600)).expect("open held oversized fixture");
    assert!(read_held_bounded(&mut oversized, 4).is_err());

    let fifo = root.path().join("fifo");
    let fifo_path =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path has no NUL");
    // SAFETY: the NUL-terminated path is owned for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    let socket = UnixListener::bind(root.path().join("socket")).expect("Unix socket mutation");
    assert!(inventory_tree(root.path()).is_err());
    drop(socket);

    let dev = open_directory_nofollow(Path::new("/dev"), None).expect("held /dev directory");
    assert!(open_anchored_file(&dev, "null", None).is_err());

    for mutation in ["symlink", "hardlink", "fifo", "socket"] {
        let template = synthetic_template();
        let secrets = template.path().join("container/bundle/secrets");
        let first = secrets.join("00");
        fs::remove_file(&first).expect("remove nested secret");
        let mut socket_guard = None;
        match mutation {
            "symlink" => {
                std::os::unix::fs::symlink("01", &first).expect("nested secret symlink mutation")
            }
            "hardlink" => {
                fs::hard_link(secrets.join("01"), &first).expect("nested secret hardlink mutation")
            }
            "fifo" => {
                let path = std::ffi::CString::new(first.as_os_str().as_encoded_bytes())
                    .expect("nested FIFO path has no NUL");
                // SAFETY: the NUL-terminated path is owned for the duration of the call.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "socket" => {
                socket_guard = Some(UnixListener::bind(&first).expect("nested socket mutation"));
            }
            _ => unreachable!(),
        }
        assert!(
            inventory_tree(&template.path().join("container")).is_err(),
            "nested {mutation} must be rejected"
        );
        drop(socket_guard);
    }

    let template = synthetic_template();
    let secrets = template.path().join("container/bundle/secrets");
    for index in 16..=MAX_TEMPLATE_ENTRIES {
        fs::write(secrets.join(format!("extra-{index}")), []).expect("nested overcap entry");
    }
    assert!(inventory_tree(&template.path().join("container")).is_err());
}

#[test]
fn anchored_copy_detects_concurrent_source_replacement_and_entry_overflow() {
    let root = tempfile::tempdir().expect("copy mutation root");
    let source = root.path().join("source");
    fs::create_dir(&source).expect("source directory");
    fs::write(source.join("value"), b"trusted").expect("trusted source");
    let destination = root.path().join("destination");
    let displaced_source = root.path().join("displaced-source");
    copy_tree_exact_with_hooks(
        &source,
        &destination,
        || {
            fs::rename(&source, &displaced_source).expect("displace held source");
            fs::create_dir(&source).expect("replacement source directory");
            fs::write(source.join("value"), b"replacement").expect("replacement source bytes");
        },
        || {},
    )
    .expect("the held source must copy the enumerated inode");
    assert_eq!(
        fs::read(destination.join("value")).expect("copied held bytes"),
        b"trusted"
    );

    let source = root.path().join("second-source");
    fs::create_dir(&source).expect("second source directory");
    fs::write(source.join("value"), b"trusted").expect("second trusted source");
    let destination = root.path().join("second-destination");
    let displaced_destination = root.path().join("displaced-destination");
    let error = copy_tree_exact_with_hooks(
        &source,
        &destination,
        || {},
        || {
            fs::rename(&destination, &displaced_destination).expect("displace held destination");
            fs::create_dir(&destination).expect("replacement destination directory");
        },
    )
    .expect_err("destination pathname replacement must not redirect publication");
    assert!(error.contains("destination binding changed"));

    let overcap = root.path().join("overcap");
    fs::create_dir(&overcap).expect("overcap directory");
    for index in 0..=MAX_TEMPLATE_ENTRIES {
        fs::write(overcap.join(index.to_string()), []).expect("overcap entry");
    }
    assert!(inventory_tree(&overcap).is_err());
}

#[test]
fn rebased_manifest_time_is_exactly_eth1_plus_frozen_delay() {
    use consensus_signature::PqPublicKey;
    use validator_dir::PqManifestValidator;

    let root = [3; 32];
    let manifest = PqDevnetManifest::new(
        1,
        0,
        1119,
        42,
        root,
        vec![PqManifestValidator::new(
            0,
            PqPublicKey::deserialize(&[0x11; 32]).expect("canonical test key"),
            [4; 32],
        )],
    );
    validate_manifest_network_identity(&manifest, root, 342).expect("42 + frozen 300-second delay");
    assert!(validate_manifest_network_identity(&manifest, root, 341).is_err());
    assert!(validate_manifest_network_identity(&manifest, root, 343).is_err());
}

#[test]
fn bounded_enr_read_rejects_symlink_oversize_and_concurrent_rewrite() {
    let root = tempfile::tempdir().expect("ENR mutation root");
    let path = root.path().join("enr.dat");
    fs::write(&path, b"old!").expect("initial ENR bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("initial ENR mode");

    let error = open_bounded_regular_nofollow_with_hook(&path, 8, || {
        fs::write(&path, b"replacement").expect("concurrent ENR rewrite");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("replacement ENR mode");
    })
    .expect_err("a changed held ENR must be rejected");
    assert!(error.contains("changed while read"));

    assert!(open_bounded_regular_nofollow(&path, 4).is_err());
    fs::rename(&path, root.path().join("target")).expect("move ENR target");
    std::os::unix::fs::symlink("target", &path).expect("ENR symlink mutation");
    assert!(open_bounded_regular_nofollow(&path, 16).is_err());

    let modes = root.path().join("mode-enr.dat");
    fs::write(&modes, b"enr").expect("mode ENR bytes");
    for mode in [0o600, 0o604, 0o640, 0o644] {
        fs::set_permissions(&modes, fs::Permissions::from_mode(mode)).expect("safe ENR mode");
        open_bounded_regular_nofollow(&modes, 16).expect("safe restrictive-umask ENR mode");
    }
    for mode in [0o666, 0o620, 0o744, 0o4644] {
        fs::set_permissions(&modes, fs::Permissions::from_mode(mode)).expect("unsafe ENR mode");
        assert!(open_bounded_regular_nofollow(&modes, 16).is_err());
    }

    let fifo = root.path().join("fifo-enr.dat");
    let fifo_path =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path has no NUL");
    // SAFETY: the NUL-terminated path is owned for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o644) }, 0);
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = open_bounded_regular_nofollow(&fifo, 16);
        let _ = finished_tx.send(result);
    });
    assert!(
        finished_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("FIFO inspection must not block")
            .is_err()
    );
}

#[test]
fn authenticated_bundle_loader_accepts_a_held_directory_path() {
    let root = tempfile::tempdir().expect("held bundle root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("held bundle mode");
    let held = open_directory_nofollow(root.path(), Some(0o700)).expect("held bundle directory");
    let error = match PqDevnetBundle::load_for_network_registry(
        bundle_loader_path(&held),
        [0; 32],
        300,
        &[],
    ) {
        Ok(_) => panic!("an empty held bundle remains invalid"),
        Err(error) => error,
    };
    assert!(
        !error
            .to_string()
            .contains("Too many levels of symbolic links"),
        "the real loader must open the held directory before rejecting its contents: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_aware_enr_wait_reports_early_exit_with_bounded_diagnostics() {
    let network = tempfile::tempdir().expect("startup wait network directory");
    let mut child = ChildNode::spawn("invalid-startup", &["--pq-e4f-invalid-option".into()]);
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        child.wait_for_enr(network.path(), PROCESS_START_TIMEOUT),
    )
    .await
    .expect("early child exit must beat the long ENR deadline")
    .expect_err("invalid Lighthouse startup must be typed");
    match error {
        ChildStartupError::EarlyExit {
            status,
            diagnostics,
        } => {
            assert!(!status.success());
            assert!(diagnostics.contains("stderr:"));
            assert!(diagnostics.contains("pq-e4f-invalid-option"));
            assert!(diagnostics.len() <= MAX_LOG_FRAME_BYTES * MAX_RETAINED_LOG_FRAMES);
        }
        other => panic!("expected typed early exit, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_real_processes_emit_compatible_status_before_any_proposal() {
    require_pq_avx2_launch_profile();
    let fixture = tokio::task::spawn_blocking(prepare_launch_fixture)
        .await
        .expect("fixture provisioning task");

    let jwt = JwtKey::from_slice(&DEFAULT_JWT_SECRET).expect("JWT key");
    let proposer_engine = MockServer::<MinimalEthSpec>::new(
        &tokio::runtime::Handle::current(),
        jwt.clone(),
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        None,
    );
    let verifier_engine = MockServer::<MinimalEthSpec>::new(
        &tokio::runtime::Handle::current(),
        jwt,
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        None,
    );
    assert_ne!(proposer_engine.url(), verifier_engine.url());
    for engine in [&proposer_engine, &verifier_engine] {
        engine.enable_engine_audit();
        engine.full_payload_verification();
        engine
            .execution_block_generator()
            .set_blob_count_range(0, 0);
        engine.insert_pow_block(
            0,
            ExecutionBlockHash::zero(),
            ExecutionBlockHash::zero(),
            Uint256::ZERO,
        );
        assert!(engine.get_block(ExecutionBlockHash::zero()).is_some());
    }

    let proposer_tcp = reserve_tcp_port();
    let proposer_udp = reserve_udp_port();
    let verifier_tcp = reserve_tcp_port();
    let verifier_udp = reserve_udp_port();
    let verifier_only_diagnostic = std::env::var_os("PQ_E4F_VERIFIER_ONLY_DIAGNOSTIC").is_some();
    let proposer_args = node_args(
        &fixture.proposer_data,
        &fixture.proposer_network,
        &fixture.testnet_dir,
        &proposer_engine.url(),
        &fixture.jwt_proposer,
        proposer_tcp,
        proposer_udp,
        None,
        (!verifier_only_diagnostic).then_some(fixture.bundle_dir.as_path()),
    );
    let mut proposer = ChildNode::spawn("proposer", &proposer_args);
    let proposer_enr = proposer
        .wait_for_enr(&fixture.proposer_network, PROCESS_START_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("proposer startup before ENR: {error}"));
    let parsed_proposer_enr = proposer_enr
        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
        .expect("bounded proposer ENR");
    assert_eq!(parsed_proposer_enr.ip4(), Some(Ipv4Addr::LOCALHOST));
    assert_eq!(parsed_proposer_enr.tcp4(), Some(proposer_tcp));
    assert_eq!(parsed_proposer_enr.udp4(), Some(proposer_udp));
    let proposer_role = if verifier_only_diagnostic {
        PqProcessRole::Verifier
    } else {
        PqProcessRole::Proposer
    };
    let proposer_ready = proposer
        .wait_for_event_kind_count(1, PROCESS_START_TIMEOUT, |event| {
            matches!(event, PqProcessEventKind::RuntimeReady { .. })
        })
        .await;
    assert!(matches!(
        proposer_ready.first(),
        Some(PqProcessEvent {
            sequence: 1,
            role,
            kind: PqProcessEventKind::EventWriterReady,
        }) if *role == proposer_role
    ));
    let ready = proposer_ready
        .iter()
        .filter(|event| matches!(event.kind, PqProcessEventKind::RuntimeReady { .. }))
        .collect::<Vec<_>>();
    assert!(matches!(
        ready.as_slice(),
        [PqProcessEvent {
            role,
            kind: PqProcessEventKind::RuntimeReady {
                startup: PqProcessStartup::Fresh,
                slot: 0,
                execution_hash,
                finalized_epoch: 0,
                finalized_root,
                ..
            },
            ..
        }] if *role == proposer_role
            && *execution_hash == ExecutionBlockHash::zero()
            && *finalized_root == Hash256::ZERO
    ));

    let verifier_args = node_args(
        &fixture.verifier_data,
        &fixture.verifier_network,
        &fixture.testnet_dir,
        &verifier_engine.url(),
        &fixture.jwt_verifier,
        verifier_tcp,
        verifier_udp,
        Some(&proposer_enr),
        None,
    );
    let mut verifier = ChildNode::spawn("verifier", &verifier_args);
    let verifier_enr = verifier
        .wait_for_enr(&fixture.verifier_network, PROCESS_START_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("verifier startup before ENR: {error}"));
    let parsed_verifier_enr = verifier_enr
        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
        .expect("bounded verifier ENR");
    assert_eq!(parsed_verifier_enr.ip4(), Some(Ipv4Addr::LOCALHOST));
    assert_eq!(parsed_verifier_enr.tcp4(), Some(verifier_tcp));
    assert_eq!(parsed_verifier_enr.udp4(), Some(verifier_udp));

    let proposer_events = proposer.wait_for_event_count(6, STATUS_EVENT_TIMEOUT).await;
    let verifier_events = verifier.wait_for_event_count(6, STATUS_EVENT_TIMEOUT).await;
    validate_compatible_event_trace(
        &proposer_events,
        proposer_role,
        PqProcessConnectionDirection::Incoming,
        peer_digest_from_enr(&parsed_verifier_enr),
    )
    .expect("exact proposer-compatible event topology");
    validate_compatible_event_trace(
        &verifier_events,
        PqProcessRole::Verifier,
        PqProcessConnectionDirection::Outgoing,
        peer_digest_from_enr(&parsed_proposer_enr),
    )
    .expect("exact verifier-compatible event topology");

    if !verifier_only_diagnostic {
        let proposer_timeout = three_slot_wait_remaining(
            fixture.genesis_time,
            unix_time_now().expect("three-slot proposer wait clock"),
        )
        .expect("third proposal remains inside its absolute completion deadline");
        let proposer_events = proposer
            .wait_for_event_kind_count(3, proposer_timeout, |event| {
                matches!(event, PqProcessEventKind::ProposalPublished { .. })
            })
            .await;
        let verifier_timeout = three_slot_wait_remaining(
            fixture.genesis_time,
            unix_time_now().expect("three-slot verifier wait clock"),
        )
        .expect("third gossip import remains inside the shared absolute completion deadline");
        let verifier_events = verifier
            .wait_for_event_kind_count(3, verifier_timeout, |event| {
                matches!(event, PqProcessEventKind::GossipImported { .. })
            })
            .await;
        let proposer_engine_history = proposer_engine
            .engine_audit_history()
            .expect("bounded proposer Engine audit");
        let verifier_engine_history = verifier_engine
            .engine_audit_history()
            .expect("bounded verifier Engine audit");
        validate_three_slot_process_convergence(
            &proposer_events,
            &verifier_events,
            &proposer_engine_history,
            &verifier_engine_history,
        )
        .expect("exact three-slot process convergence and Engine histories");
        let persisted = proposer_events
            .iter()
            .filter_map(|event| {
                persisted_identity(
                    event,
                    PqProcessRole::Proposer,
                    PqProcessBlockSource::Publish,
                )
            })
            .last()
            .expect("slot-3 persisted identity");
        assert_eq!(persisted.slot, THREE_SLOT_TARGET);

        let (_, _) = tokio::join!(verifier.stop(), proposer.stop());
        probe_network_ports_released(&[proposer_tcp, verifier_tcp], &[proposer_udp, verifier_udp])
            .expect("first shutdown releases exact network listeners before restart");

        let mut proposer = ChildNode::spawn("restarted-proposer", &proposer_args);
        let mut verifier = ChildNode::spawn("restarted-verifier", &verifier_args);
        let restart_timeout = restart_ready_remaining_precise(
            fixture.genesis_time,
            unix_time_now_precise().expect("restart-ready deadline clock"),
        )
        .expect("restart retains a checked pre-slot-5 stop margin");
        let restart_deadline = Instant::now()
            .checked_add(restart_timeout)
            .expect("bounded monotonic restart-ready deadline");
        let (proposer_ready_snapshot, verifier_ready_snapshot) = tokio::join!(
            proposer.wait_for_event_kind_count_until(1, restart_deadline, |event| {
                matches!(event, PqProcessEventKind::RuntimeReady { .. })
            }),
            verifier.wait_for_event_kind_count_until(1, restart_deadline, |event| {
                matches!(event, PqProcessEventKind::RuntimeReady { .. })
            }),
        );
        proposer.signal_interrupt();
        verifier.signal_interrupt();
        let proposer_restart_log = Arc::clone(&proposer.log);
        let verifier_restart_log = Arc::clone(&verifier.log);
        let (_, _) = tokio::join!(
            verifier.finish_stop_after_signal(),
            proposer.finish_stop_after_signal()
        );
        let restarted_proposer_enr = String::from_utf8(
            open_bounded_regular_nofollow(&fixture.proposer_network.join("enr.dat"), MAX_ENR_BYTES)
                .expect("bounded restarted proposer ENR"),
        )
        .expect("UTF-8 restarted proposer ENR");
        let restarted_verifier_enr = String::from_utf8(
            open_bounded_regular_nofollow(&fixture.verifier_network.join("enr.dat"), MAX_ENR_BYTES)
                .expect("bounded restarted verifier ENR"),
        )
        .expect("UTF-8 restarted verifier ENR");
        assert_eq!(restarted_proposer_enr.trim(), proposer_enr);
        assert_eq!(restarted_verifier_enr.trim(), verifier_enr);

        let proposer_restart_events = proposer_restart_log
            .events()
            .expect("exact restarted proposer event stream");
        let verifier_restart_events = verifier_restart_log
            .events()
            .expect("exact restarted verifier event stream");
        assert!(proposer_restart_events.starts_with(&proposer_ready_snapshot));
        assert!(verifier_restart_events.starts_with(&verifier_ready_snapshot));
        let proposer_engine_after_restart = proposer_engine
            .engine_audit_history()
            .expect("bounded proposer Engine audit after restart");
        let verifier_engine_after_restart = verifier_engine
            .engine_audit_history()
            .expect("bounded verifier Engine audit after restart");
        validate_restart_idempotence(
            &proposer_restart_events,
            &verifier_restart_events,
            persisted,
            &proposer_engine_history,
            &proposer_engine_after_restart,
            &verifier_engine_history,
            &verifier_engine_after_restart,
        )
        .expect("restart replays exactly the persisted slot-3 execution view");
        probe_network_ports_released(&[proposer_tcp, verifier_tcp], &[proposer_udp, verifier_udp])
            .expect("second shutdown releases exact network listeners");
        probe_slashing_db_released(&fixture.proposer_data)
            .expect("second shutdown releases exact proposer SQLite ownership");
        probe_chain_store_released(&fixture.proposer_data)
            .expect("second shutdown releases proposer chain databases");
        probe_chain_store_released(&fixture.verifier_data)
            .expect("second shutdown releases verifier chain databases");
    } else {
        let (_, _) = tokio::join!(verifier.stop(), proposer.stop());
    }
}
