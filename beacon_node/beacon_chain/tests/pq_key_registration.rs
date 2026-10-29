//! EIP-8450 (post-quantum consensus key registry): blocks carrying `SignedPqKeyRegistration`s on
//! the gossip-verify → import path, across the fork upgrade, and block production of builder
//! registrations that the block's parent execution requests invalidate.

use beacon_chain::pq_key_registration_verification::PqKeyRegistrationOutcome;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    builder_withdrawal_credentials,
};
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, InvalidSignature, NotifyExecutionLayer,
};
use bls::Keypair;
use lean_pq::xmss;
use ssz_types::ProgressiveVariableList;
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
    per_block_processing,
    per_block_processing::{
        errors::{BlockOperationError, PqKeyRegistrationInvalid},
        get_pq_possession_signing_root, verify_pq_key_registration,
    },
    state_advance::complete_state_advance,
};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use types::test_utils::{generate_deterministic_keypair, generate_deterministic_keypairs};
use types::{
    BeaconState, BlockImportSource, BuilderDepositRequest, BuilderExitRequest, ChainSpec,
    DepositMessage, Domain, Epoch, EthSpec, ExecutionRequests, ExecutionRequestsGloas, ForkName,
    Hash256, MinimalEthSpec, PQ_POSSESSION_XMSS_INDEX, PqKeyRegistration, PqPublicKeys,
    PqRegistryIndex, SignedBeaconBlock, SignedExecutionPayloadEnvelope, SignedPqKeyRegistration,
    SignedRoot, Slot, XmssPublicKey, XmssSignature,
};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

const VALIDATOR_COUNT: usize = 32;
const EIP8450_FORK_EPOCH: u64 = 1;
/// The validator that registers keys in these tests.
const REGISTRANT: u64 = 5;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(VALIDATOR_COUNT));

/// A leanXMSS key from a fixed seed.
static XMSS_KEY: LazyLock<xmss::SecretKey> = LazyLock::new(|| {
    let start = Instant::now();
    let secret_key = xmss::SecretKey::from_seed([0x51; xmss::SEED_LEN]);
    eprintln!("leanXMSS key generated in {:?}", start.elapsed());
    secret_key
});

fn xmss_public_key() -> XmssPublicKey {
    XmssPublicKey::new(XMSS_KEY.public_key().to_bytes().to_vec()).unwrap()
}

fn public_keys() -> PqPublicKeys {
    PqPublicKeys {
        xmss_public_key: xmss_public_key(),
        vrf_root: Hash256::repeat_byte(0xaa),
    }
}

/// A first registration of `XMSS_KEY` for `REGISTRANT`, with a valid proof of possession and a
/// valid BLS authorization.
fn registration(state: &BeaconState<E>, spec: &ChainSpec) -> SignedPqKeyRegistration {
    let validator_pubkey = state.get_validator(REGISTRANT as usize).unwrap().pubkey;
    let signing_root =
        get_pq_possession_signing_root(state, &validator_pubkey, &xmss_public_key(), spec);
    let start = Instant::now();
    let possession = XMSS_KEY
        .sign(&signing_root.0, PQ_POSSESSION_XMSS_INDEX)
        .expect("leanXMSS signing succeeds");
    eprintln!("leanXMSS possession proof signed in {:?}", start.elapsed());
    PqKeyRegistration {
        index: REGISTRANT,
        public_keys: public_keys(),
        // A first registration names the stored entry, `FAR_FUTURE_EPOCH` until it registers.
        previous_change_epoch: *state
            .pq_key_change_epochs()
            .unwrap()
            .get(REGISTRANT as usize)
            .unwrap(),
    }
    .sign(
        XmssSignature::new(possession.to_bytes().to_vec()).unwrap(),
        &KEYPAIRS[REGISTRANT as usize].sk,
        state.genesis_validators_root(),
        spec,
    )
}

/// A chain with every fork up to Heze at genesis and Eip8450 at `EIP8450_FORK_EPOCH`, extended
/// into the first Eip8450 epoch.
async fn harness_past_eip8450_fork() -> Harness {
    let mut spec = ForkName::Heze.make_genesis_spec(E::default_spec());
    spec.eip8450_fork_epoch = Some(Epoch::new(EIP8450_FORK_EPOCH));
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(Arc::new(spec))
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    assert_eq!(
        harness.get_current_state().fork_name_unchecked(),
        ForkName::Heze
    );

    harness.advance_slot();
    harness
        .extend_chain(
            (EIP8450_FORK_EPOCH * E::slots_per_epoch()) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // The fork upgrade initialized one unset entry per validator.
    let head_state = harness.get_current_state();
    assert_eq!(head_state.fork_name_unchecked(), ForkName::Eip8450);
    assert_eq!(head_state.validators().len(), VALIDATOR_COUNT);
    assert!(
        head_state
            .pq_public_keys()
            .unwrap()
            .iter()
            .all(|keys| *keys == PqPublicKeys::default())
    );
    assert_eq!(
        head_state.pq_key_change_epochs().unwrap().len(),
        VALIDATOR_COUNT
    );
    assert!(
        head_state
            .pq_key_change_epochs()
            .unwrap()
            .iter()
            .all(|epoch| *epoch == harness.spec.far_future_epoch)
    );
    harness
}

/// A block for the next slot carrying `registrations`, with a correct state root and proposer
/// signature, together with its re-targeted payload envelope, post-state and state root.
async fn block_with_registrations(
    harness: &Harness,
    registrations: Vec<SignedPqKeyRegistration>,
) -> (
    Arc<SignedBeaconBlock<E>>,
    SignedExecutionPayloadEnvelope<E>,
    BeaconState<E>,
    Hash256,
) {
    let spec = &harness.spec;
    harness.advance_slot();
    let slot = harness.get_current_slot();
    let state = harness.get_current_state();

    let mut pre_state = state.clone();
    complete_state_advance(&mut pre_state, None, slot, None, spec).unwrap();
    pre_state.build_caches(spec).unwrap();

    let ((block, _), envelope, _) = harness.make_block_with_envelope(state, slot).await;
    let mut envelope = envelope.expect("Eip8450 blocks have an envelope");
    let (mut block, _) = Arc::unwrap_or_clone(block).deconstruct();
    *block.body_mut().pq_key_registrations_mut().unwrap() =
        ProgressiveVariableList::new(registrations).unwrap();

    // Signatures are irrelevant to the post-state, so process without them to find its root.
    let mut post_state = pre_state.clone();
    let unsigned = harness.sign_beacon_block(block.clone(), &pre_state);
    per_block_processing(
        &mut post_state,
        &unsigned,
        BlockSignatureStrategy::NoVerification,
        VerifyBlockRoot::True,
        &mut ConsensusContext::new(slot),
        spec,
    )
    .unwrap();
    let state_root = post_state.update_tree_hash_cache().unwrap();
    *block.state_root_mut() = state_root;
    let block = Arc::new(harness.sign_beacon_block(block, &pre_state));

    // The self-built payload now belongs to the modified block.
    let proposer = block.message().proposer_index() as usize;
    envelope.message.beacon_block_root = block.canonical_root();
    let domain = spec.get_domain(
        slot.epoch(E::slots_per_epoch()),
        Domain::BeaconBuilder,
        &post_state.fork(),
        post_state.genesis_validators_root(),
    );
    envelope.signature = KEYPAIRS[proposer]
        .sk
        .sign(envelope.message.signing_root(domain));

    (block, envelope, post_state, state_root)
}

/// Gossip-verifies `block`, then imports it.
async fn gossip_verify_and_import(
    harness: &Harness,
    block: Arc<SignedBeaconBlock<E>>,
) -> Result<AvailabilityProcessingStatus, BlockError> {
    let gossip_verified = harness
        .chain
        .verify_block_for_gossip(block)
        .await
        .map_err(|e| e.into_block_error())?;
    let block_root = gossip_verified.block_root;
    harness
        .chain
        .process_block(
            block_root,
            gossip_verified,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Gossip,
            || Ok(()),
        )
        .await
}

#[tokio::test]
async fn block_with_valid_registration_imports() {
    let harness = harness_past_eip8450_fork().await;
    let spec = harness.spec.clone();
    let signed = registration(&harness.get_current_state(), &spec);

    let (block, envelope, post_state, state_root) =
        block_with_registrations(&harness, vec![signed]).await;
    let block_root = block.canonical_root();
    let status = gossip_verify_and_import(&harness, block.clone()).await;
    assert!(
        matches!(
            status,
            Ok(AvailabilityProcessingStatus::Imported(slot, root))
                if slot == block.slot() && root == block_root
        ),
        "{status:?}"
    );
    harness
        .process_envelope(block_root, envelope, &post_state, state_root)
        .await;

    let head = harness.chain.head_snapshot();
    assert_eq!(head.beacon_block_root, block_root);
    let registration_epoch = block.slot().epoch(E::slots_per_epoch());
    let head_state = &head.beacon_state;
    assert_eq!(
        head_state
            .pq_public_keys()
            .unwrap()
            .get(REGISTRANT as usize),
        Some(&public_keys())
    );
    assert_eq!(
        head_state
            .pq_key_change_epochs()
            .unwrap()
            .get(REGISTRANT as usize),
        Some(&registration_epoch)
    );

    // The chain builds on the block, and the registration persists.
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    let head = harness.chain.head_snapshot();
    assert!(head.beacon_block.slot() > block.slot());
    assert_eq!(
        head.beacon_state
            .pq_public_keys()
            .unwrap()
            .get(REGISTRANT as usize),
        Some(&public_keys())
    );
}

#[tokio::test]
async fn block_with_invalid_possession_proof_is_rejected() {
    let harness = harness_past_eip8450_fork().await;
    let spec = harness.spec.clone();
    // Valid BLS authorization, corrupted proof of possession.
    let mut signed = registration(&harness.get_current_state(), &spec);
    signed.possession[100] ^= 0x01;

    let head_before = harness.chain.head_snapshot().beacon_block_root;
    let (block, _, _, _) = block_with_registrations(&harness, vec![signed]).await;
    let block_root = block.canonical_root();

    // Gossip verification checks the proposal only; import verifies every signature in the body.
    assert!(matches!(
        gossip_verify_and_import(&harness, block).await,
        Err(BlockError::InvalidSignature(
            InvalidSignature::BlockBodySignatures
        ))
    ));
    assert!(!harness.chain.block_is_known_to_fork_choice(&block_root));
    assert_eq!(harness.chain.head_snapshot().beacon_block_root, head_before);

    // The chain still advances, without the registration.
    harness.advance_slot();
    harness
        .extend_chain(
            E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    let head = harness.chain.head_snapshot();
    assert_ne!(head.beacon_block_root, head_before);
    assert!(
        head.beacon_block.slot()
            >= Epoch::new(EIP8450_FORK_EPOCH + 1).start_slot(E::slots_per_epoch())
    );
    assert_eq!(
        head.beacon_state
            .pq_public_keys()
            .unwrap()
            .get(REGISTRANT as usize),
        Some(&PqPublicKeys::default())
    );
}

/// Validators whose keys the genesis builders use, by builder index.
const BUILDER_VALIDATORS: [usize; 2] = [10, 11];
const BUILDER_BALANCE: u64 = 32_000_000_000;

/// A second leanXMSS key from a fixed seed.
static XMSS_KEY_2: LazyLock<xmss::SecretKey> =
    LazyLock::new(|| xmss::SecretKey::from_seed([0x52; xmss::SEED_LEN]));

/// The registry index of the builder at `builder_index`, with `BUILDER_INDEX_FLAG` set.
fn builder(builder_index: u64) -> u64 {
    PqRegistryIndex::Builder(builder_index).as_u64()
}

/// A first registration of `xmss_key` for the genesis builder at `builder_index`, with a valid
/// proof of possession and BLS authorization.
fn builder_registration(
    state: &BeaconState<E>,
    builder_index: u64,
    xmss_key: &xmss::SecretKey,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    let xmss_public_key = XmssPublicKey::new(xmss_key.public_key().to_bytes().to_vec()).unwrap();
    let builder_state = state.get_builder(builder_index).unwrap();
    let signing_root =
        get_pq_possession_signing_root(state, &builder_state.pubkey, &xmss_public_key, spec);
    let possession = xmss_key
        .sign(&signing_root.0, PQ_POSSESSION_XMSS_INDEX)
        .expect("leanXMSS signing succeeds");
    PqKeyRegistration {
        index: builder(builder_index),
        public_keys: PqPublicKeys {
            xmss_public_key,
            vrf_root: Hash256::ZERO,
        },
        previous_change_epoch: builder_state.deposit_epoch,
    }
    .sign(
        XmssSignature::new(possession.to_bytes().to_vec()).unwrap(),
        &KEYPAIRS[BUILDER_VALIDATORS[builder_index as usize]].sk,
        state.genesis_validators_root(),
        spec,
    )
}

/// An Eip8450-genesis chain with the builders of `BUILDER_VALIDATORS`, extended until their
/// deposit epoch is finalized, so that they are active.
async fn harness_with_active_builders() -> Harness {
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(Arc::new(
            ForkName::Eip8450.make_genesis_spec(E::default_spec()),
        ))
        .keypairs(KEYPAIRS.clone())
        .genesis_builders(BUILDER_VALIDATORS.to_vec(), BUILDER_BALANCE)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness.advance_slot();
    harness
        .extend_chain(
            5 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    let state = harness.get_current_state();
    for builder_index in 0..BUILDER_VALIDATORS.len() as u64 {
        assert!(
            state
                .is_active_builder(builder_index, &harness.spec)
                .unwrap()
        );
    }
    harness
}

/// Verifies `registration` as the HTTP API does and adds it to the op pool.
fn submit(harness: &Harness, registration: SignedPqKeyRegistration) {
    let PqKeyRegistrationOutcome::New(verified) = harness
        .chain
        .verify_pq_key_registration_for_http_api(registration)
        .unwrap()
    else {
        panic!("registration should be new");
    };
    harness.chain.import_pq_key_registration(*verified);
}

/// Makes the next payload carry `requests`, and imports the block and envelope carrying it. The
/// next block applies the requests as its parent execution requests.
async fn import_parent_with_requests(harness: &Harness, requests: &ExecutionRequestsGloas<E>) {
    harness
        .execution_block_generator()
        .set_next_execution_requests(ExecutionRequests::Gloas(requests.clone()));
    harness
        .extend_to_slot(harness.get_current_slot() + Slot::new(1))
        .await;
}

/// Produces and imports the next block on the head, returning the registrations it packed. It
/// must apply `parent_requests`.
async fn produce_and_import_child(
    harness: &Harness,
    parent_requests: &ExecutionRequestsGloas<E>,
) -> Vec<SignedPqKeyRegistration> {
    let parent_state = harness.get_current_state();
    harness.advance_slot();
    let slot = harness.get_current_slot();
    let (block_contents, _, _) = harness.make_block_with_envelope(parent_state, slot).await;
    let body = block_contents.0.message().body();
    assert_eq!(body.parent_execution_requests().unwrap(), parent_requests);
    let packed = body.pq_key_registrations().unwrap().to_vec();

    // Import runs block processing with every signature: the packed registrations are valid
    // after the parent's requests.
    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(slot, block_root, block_contents)
        .await
        .expect("the produced block should import");
    assert_eq!(
        harness.chain.head_beacon_block().canonical_root(),
        block_root
    );
    packed
}

/// A builder whose exit request is among the block's parent execution requests is exited before
/// the block's registrations, so its registration is not packed, while another builder's is.
#[tokio::test]
async fn registration_of_builder_exiting_in_the_same_block_is_not_packed() {
    let harness = harness_with_active_builders().await;
    let spec = harness.spec.clone();

    let exiting_builder = harness.get_current_state().get_builder(0).unwrap().clone();
    let mut requests = ExecutionRequestsGloas::<E>::default();
    requests
        .builder_exits
        .push(BuilderExitRequest {
            source_address: exiting_builder.execution_address,
            pubkey: exiting_builder.pubkey,
        })
        .unwrap();
    import_parent_with_requests(&harness, &requests).await;

    // Both registrations are valid against the head, where builder 0 is still active.
    let state = harness.get_current_state();
    let exiting = builder_registration(&state, 0, &XMSS_KEY, &spec);
    let staying = builder_registration(&state, 1, &XMSS_KEY_2, &spec);
    submit(&harness, exiting);
    submit(&harness, staying.clone());

    let packed = produce_and_import_child(&harness, &requests).await;
    assert_eq!(packed, vec![staying]);

    let state = harness.get_current_state();
    assert_ne!(
        state.get_builder(0).unwrap().withdrawable_epoch,
        spec.far_future_epoch
    );
    assert!(!state.is_pq_registered(builder(0)).unwrap());
    assert!(state.is_pq_registered(builder(1)).unwrap());
}

/// A builder deposit among the block's parent execution requests reuses the index of a builder
/// that exited and was swept. A registration of the earlier builder is not packed.
#[tokio::test]
async fn registration_of_builder_whose_index_is_reused_in_the_same_block_is_not_packed() {
    let harness = harness_with_active_builders().await;
    let spec = harness.spec.clone();
    let state = harness.get_current_state();
    // Signed while builder 0 is active.
    let stale = builder_registration(&state, 0, &XMSS_KEY, &spec);

    // Builder 0 exits, becomes withdrawable and is swept.
    let exiting_builder = state.get_builder(0).unwrap().clone();
    let mut exit_requests = ExecutionRequestsGloas::<E>::default();
    exit_requests
        .builder_exits
        .push(BuilderExitRequest {
            source_address: exiting_builder.execution_address,
            pubkey: exiting_builder.pubkey,
        })
        .unwrap();
    import_parent_with_requests(&harness, &exit_requests).await;
    harness
        .extend_to_slot(harness.get_current_slot() + Slot::new(1))
        .await;
    let withdrawable_epoch = harness
        .get_current_state()
        .get_builder(0)
        .unwrap()
        .withdrawable_epoch;
    assert_ne!(withdrawable_epoch, spec.far_future_epoch);
    harness
        .extend_to_slot((withdrawable_epoch + 1).start_slot(E::slots_per_epoch()))
        .await;
    let state = harness.get_current_state();
    assert_eq!(state.get_builder(0).unwrap().balance, 0);
    assert_eq!(state.get_index_for_new_builder(), Ok(0));

    // A new builder's deposit.
    let new_keypair = generate_deterministic_keypair(VALIDATOR_COUNT);
    let mut deposit = BuilderDepositRequest {
        pubkey: new_keypair.pk.compress(),
        withdrawal_credentials: builder_withdrawal_credentials(&new_keypair.pk, &spec),
        amount: BUILDER_BALANCE,
        signature: bls::SignatureBytes::empty(),
    };
    let domain = spec.compute_domain(
        Domain::BuilderDeposit,
        spec.genesis_fork_version,
        Hash256::ZERO,
    );
    let deposit_message = DepositMessage {
        pubkey: deposit.pubkey,
        withdrawal_credentials: deposit.withdrawal_credentials,
        amount: deposit.amount,
    };
    deposit.signature = new_keypair
        .sk
        .sign(deposit_message.signing_root(domain))
        .into();
    assert!(deposit.is_valid_builder_deposit_signature(&spec));
    let mut deposit_requests = ExecutionRequestsGloas::<E>::default();
    deposit_requests.builder_deposits.push(deposit).unwrap();
    import_parent_with_requests(&harness, &deposit_requests).await;

    // The pool still offers the earlier builder's registration. It is invalid against the
    // block's pre-state already: a reusable index belongs to a builder that is not active.
    assert_eq!(
        harness
            .chain
            .op_pool
            .insert_pq_key_registration(stale.clone()),
        operation_pool::PqKeyRegistrationInsertOutcome::Inserted
    );
    let mut pre_state = harness.get_current_state();
    complete_state_advance(
        &mut pre_state,
        None,
        harness.get_current_slot() + Slot::new(1),
        None,
        &spec,
    )
    .unwrap();
    assert_eq!(
        verify_pq_key_registration(&pre_state, &stale, VerifySignatures::False, &spec),
        Err(BlockOperationError::Invalid(
            PqKeyRegistrationInvalid::BuilderNotActive(0)
        ))
    );

    let packed = produce_and_import_child(&harness, &deposit_requests).await;
    assert!(packed.is_empty());

    // The new builder took index 0, with a fresh entry starting at its deposit epoch.
    let state = harness.get_current_state();
    let new_builder = state.get_builder(0).unwrap();
    assert_eq!(new_builder.pubkey, new_keypair.pk.compress());
    assert_eq!(new_builder.deposit_epoch, state.current_epoch());
    assert_eq!(
        state.get_pq_key_change_epoch(builder(0)),
        Ok(state.current_epoch())
    );
    assert!(!state.is_pq_registered(builder(0)).unwrap());
}
