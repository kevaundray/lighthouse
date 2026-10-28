//! EIP-8450 (post-quantum validator key registry): blocks carrying `SignedPqKeyRegistration`s on
//! the gossip-verify → import path, across the fork upgrade.

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, InvalidSignature, NotifyExecutionLayer,
};
use bls::Keypair;
use lean_pq::xmss;
use ssz_types::ProgressiveVariableList;
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, per_block_processing,
    per_block_processing::get_pq_possession_signing_root, state_advance::complete_state_advance,
};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use types::test_utils::generate_deterministic_keypairs;
use types::{
    BeaconState, BlockImportSource, ChainSpec, Domain, Epoch, EthSpec, ForkName, Hash256,
    MinimalEthSpec, PQ_POSSESSION_XMSS_INDEX, PqKeyRegistration, PqPublicKeys, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, SignedPqKeyRegistration, SignedRoot, XmssPublicKey,
    XmssSignature,
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
        validator_index: REGISTRANT,
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
