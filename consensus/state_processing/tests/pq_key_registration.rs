//! EIP-8450 (post-quantum consensus key registry): behavioural tests of the state transition.
//!
//! Covers the Test Cases of EIP-8450: registrations and changes of keys, every rejection of
//! `process_pq_key_registration`, block-level limits, the fork upgrade, the registry length
//! invariant and the `PqPubkeyCache`.
//!
//! leanXMSS keys come from fixed seeds. Each `(key, message, leaf index)` is signed once per process
//! and the signature is reused, as a signer reuses its stored proof of possession: signing is not
//! assumed to be deterministic.
#![cfg(not(feature = "fake_crypto"))]

use beacon_chain::test_utils::{
    BeaconChainHarness, EphemeralHarnessType, builder_withdrawal_credentials,
};
use bls::{Keypair, PublicKeyBytes};
use lean_pq::xmss;
use ssz::Encode;
use ssz_types::ProgressiveVariableList;
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
    common::initiate_validator_exit,
    per_block_processing,
    per_block_processing::{
        BlockSignatureVerifier,
        block_signature_verifier::Error as BlockSignatureVerifierError,
        errors::{BlockOperationError, BlockProcessingError, PqKeyRegistrationInvalid},
        get_pq_possession_signing_root, is_valid_pq_possession_proof, pq_public_key_owner,
        process_operations::{apply_deposit, process_pq_key_registrations},
        signature_sets::get_pubkey_from_state,
        verify_pq_key_registration,
    },
    state_advance::complete_state_advance,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;
use types::test_utils::{generate_deterministic_keypair, generate_deterministic_keypairs};
use types::{
    BeaconBlock, BeaconState, ChainSpec, DepositData, Domain, Epoch, EthSpec, ForkName, Hash256,
    MinimalEthSpec, PQ_POSSESSION_XMSS_INDEX, PqKeyRegistration, PqPublicKeys, PqRegistryIndex,
    SignedBeaconBlock, SignedPqKeyRegistration, SignedRoot, Slot, VrfRoot, XmssPublicKey,
    XmssSignature, consts::gloas::PAYLOAD_BUILDER_VERSION,
    light_client::consts::FINALIZED_CHECKPOINT_FIELD_INDEX,
};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<EphemeralHarnessType<E>>;

const VALIDATOR_COUNT: usize = 32;
/// The `pq_key_change_epochs` entry of a validator that has never registered: `FAR_FUTURE_EPOCH`.
const NEVER_REGISTERED: Epoch = Epoch::new(u64::MAX);
/// `MAX_PQ_KEY_REGISTRATIONS + 1` leanXMSS keys, so a block can carry one registration too many.
static XMSS_KEYS: [LazyLock<xmss::SecretKey>; 9] = [
    LazyLock::new(|| generate_xmss_key(0)),
    LazyLock::new(|| generate_xmss_key(1)),
    LazyLock::new(|| generate_xmss_key(2)),
    LazyLock::new(|| generate_xmss_key(3)),
    LazyLock::new(|| generate_xmss_key(4)),
    LazyLock::new(|| generate_xmss_key(5)),
    LazyLock::new(|| generate_xmss_key(6)),
    LazyLock::new(|| generate_xmss_key(7)),
    LazyLock::new(|| generate_xmss_key(8)),
];

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(VALIDATOR_COUNT));

/// Number of builders `add_builders` adds.
const BUILDER_COUNT: usize = 4;

/// BLS key pairs of the builders, distinct from every validator's.
static BUILDER_KEYPAIRS: LazyLock<Vec<Keypair>> = LazyLock::new(|| {
    (VALIDATOR_COUNT..VALIDATOR_COUNT + BUILDER_COUNT)
        .map(generate_deterministic_keypair)
        .collect()
});

/// leanXMSS signatures by `(key, message, leaf index)`.
type XmssSignatureCache = HashMap<(usize, Hash256, u32), XmssSignature>;

static XMSS_SIGNATURES: LazyLock<Mutex<XmssSignatureCache>> = LazyLock::new(Default::default);

/// The leanXMSS key with fixed seed number `key`.
fn generate_xmss_key(key: u8) -> xmss::SecretKey {
    let mut seed = [0x84; xmss::SEED_LEN];
    seed[0] = key;
    let start = Instant::now();
    let secret_key = xmss::SecretKey::from_seed(seed);
    eprintln!("leanXMSS key {key} generated in {:?}", start.elapsed());
    secret_key
}

fn xmss_key(key: usize) -> &'static xmss::SecretKey {
    &XMSS_KEYS[key]
}

fn xmss_public_key(key: usize) -> XmssPublicKey {
    XmssPublicKey::new(xmss_key(key).public_key().to_bytes().to_vec()).unwrap()
}

fn xmss_sign(key: usize, message: Hash256, leaf_index: u32) -> XmssSignature {
    XMSS_SIGNATURES
        .lock()
        .unwrap()
        .entry((key, message, leaf_index))
        .or_insert_with(|| {
            let start = Instant::now();
            let signature = xmss_key(key)
                .sign(&message.0, leaf_index)
                .expect("leanXMSS signing succeeds");
            eprintln!(
                "leanXMSS signature by key {key} at leaf {leaf_index} in {:?}",
                start.elapsed()
            );
            XmssSignature::new(signature.to_bytes().to_vec()).unwrap()
        })
        .clone()
}

/// The BLS public key of the validator at `validator_index` in `state`.
fn validator_pubkey(state: &BeaconState<E>, validator_index: u64) -> PublicKeyBytes {
    state
        .get_validator(validator_index as usize)
        .unwrap()
        .pubkey
}

/// The BLS public key of the validator or flagged builder index in `state`.
fn registrant_pubkey(state: &BeaconState<E>, index: u64) -> PublicKeyBytes {
    match PqRegistryIndex::new(index) {
        PqRegistryIndex::Validator(validator_index) => validator_pubkey(state, validator_index),
        PqRegistryIndex::Builder(builder_index) => state.get_builder(builder_index).unwrap().pubkey,
    }
}

/// The BLS key pair of the validator or builder that `index` names, assuming the builders were
/// added by `add_builders`.
fn signer(index: u64) -> &'static Keypair {
    match PqRegistryIndex::new(index) {
        PqRegistryIndex::Validator(validator_index) => {
            &KEYPAIRS[validator_index as usize % VALIDATOR_COUNT]
        }
        PqRegistryIndex::Builder(builder_index) => &BUILDER_KEYPAIRS[builder_index as usize],
    }
}

/// The proof of possession of leanXMSS key `key` for the validator holding `validator_pubkey`,
/// at `leaf_index`.
fn possession_proof(
    state: &BeaconState<E>,
    validator_pubkey: &PublicKeyBytes,
    key: usize,
    leaf_index: u32,
    spec: &ChainSpec,
) -> XmssSignature {
    let signing_root =
        get_pq_possession_signing_root(state, validator_pubkey, &xmss_public_key(key), spec);
    xmss_sign(key, signing_root, leaf_index)
}

fn vrf_root(byte: u8) -> VrfRoot {
    VrfRoot::repeat_byte(byte)
}

fn public_keys(key: usize, vrf_byte: u8) -> PqPublicKeys {
    PqPublicKeys {
        xmss_public_key: xmss_public_key(key),
        vrf_root: vrf_root(vrf_byte),
    }
}

/// A registration of `public_keys` for a validator or flagged builder `index` with a valid proof
/// of possession (by leanXMSS key `key`) and a valid BLS authorization.
fn registration_with_keys(
    state: &BeaconState<E>,
    index: u64,
    key: usize,
    public_keys: PqPublicKeys,
    previous_change_epoch: Epoch,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    let possession = possession_proof(
        state,
        &registrant_pubkey(state, index),
        key,
        PQ_POSSESSION_XMSS_INDEX,
        spec,
    );
    PqKeyRegistration {
        index,
        public_keys,
        previous_change_epoch,
    }
    .sign(
        possession,
        &signer(index).sk,
        state.genesis_validators_root(),
        spec,
    )
}

/// A fully valid registration of leanXMSS key `key` (and a VRF root of `vrf_byte`s).
fn registration(
    state: &BeaconState<E>,
    validator_index: u64,
    key: usize,
    vrf_byte: u8,
    previous_change_epoch: Epoch,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    registration_with_keys(
        state,
        validator_index,
        key,
        public_keys(key, vrf_byte),
        previous_change_epoch,
        spec,
    )
}

/// Re-signs the registration message with the registrant's BLS key, keeping the possession proof.
fn resign(
    mut signed: SignedPqKeyRegistration,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    let resigned = signed.message.clone().sign(
        signed.possession.clone(),
        &signer(signed.message.index).sk,
        state.genesis_validators_root(),
        spec,
    );
    signed.signature = resigned.signature;
    signed
}

fn harness(spec: ChainSpec) -> Harness {
    BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(Arc::new(spec))
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
}

fn eip8450_harness() -> Harness {
    harness(ForkName::Eip8450.make_genesis_spec(E::default_spec()))
}

/// The genesis state of an Eip8450-genesis chain, with its slot moved to the start of `epoch`.
///
/// Registration processing reads only the current epoch, so this is enough to exercise the
/// change delay without processing empty epochs.
fn state_at_epoch(harness: &Harness, epoch: u64) -> BeaconState<E> {
    let mut state = harness.get_current_state();
    *state.slot_mut() = Epoch::new(epoch).start_slot(E::slots_per_epoch());
    state
}

fn invalid(reason: PqKeyRegistrationInvalid) -> BlockProcessingError {
    BlockProcessingError::PqKeyRegistrationInvalid { index: 0, reason }
}

fn assert_rejected(
    state: &BeaconState<E>,
    signed: &SignedPqKeyRegistration,
    expected: PqKeyRegistrationInvalid,
    spec: &ChainSpec,
) {
    assert_eq!(
        verify_pq_key_registration(state, signed, VerifySignatures::True, spec),
        Err(BlockOperationError::Invalid(expected.clone()))
    );
    // Processing fails with the same reason and leaves the registry untouched.
    let mut post_state = state.clone();
    assert_eq!(
        process_pq_key_registrations(
            &mut post_state,
            std::slice::from_ref(signed),
            VerifySignatures::True,
            spec
        ),
        Err(invalid(expected))
    );
    assert_eq!(
        post_state.pq_public_keys().unwrap(),
        state.pq_public_keys().unwrap()
    );
    assert_eq!(
        post_state.pq_key_change_epochs().unwrap(),
        state.pq_key_change_epochs().unwrap()
    );
    assert_eq!(
        post_state.builder_pq_public_keys().unwrap(),
        state.builder_pq_public_keys().unwrap()
    );
    assert_eq!(
        post_state.builder_pq_key_change_epochs().unwrap(),
        state.builder_pq_key_change_epochs().unwrap()
    );
}

fn process(state: &mut BeaconState<E>, signed: &SignedPqKeyRegistration, spec: &ChainSpec) {
    process_pq_key_registrations(
        state,
        std::slice::from_ref(signed),
        VerifySignatures::True,
        spec,
    )
    .expect("registration is valid");
}

/// Builds a valid registration (see `registration`) and processes it.
fn register(
    state: &mut BeaconState<E>,
    validator_index: u64,
    key: usize,
    vrf_byte: u8,
    previous_change_epoch: Epoch,
    spec: &ChainSpec,
) {
    let signed = registration(
        state,
        validator_index,
        key,
        vrf_byte,
        previous_change_epoch,
        spec,
    );
    process(state, &signed, spec);
}

/// The keys and the change epoch of a validator or flagged builder index.
fn entry(state: &BeaconState<E>, index: u64) -> (PqPublicKeys, Epoch) {
    (
        state.get_pq_public_keys(index).unwrap().clone(),
        state.get_pq_key_change_epoch(index).unwrap(),
    )
}

fn assert_registry_invariant(state: &BeaconState<E>) {
    let validators = state.validators().len();
    assert_eq!(state.pq_public_keys().unwrap().len(), validators);
    assert_eq!(state.pq_key_change_epochs().unwrap().len(), validators);
    let builders = state.builders().unwrap().len();
    assert_eq!(state.builder_pq_public_keys().unwrap().len(), builders);
    assert_eq!(
        state.builder_pq_key_change_epochs().unwrap().len(),
        builders
    );
}

/// The registry index of the builder at `builder_index`, with `BUILDER_INDEX_FLAG` set.
fn builder(builder_index: u64) -> u64 {
    PqRegistryIndex::Builder(builder_index).as_u64()
}

/// Builder keys: leanXMSS key `key` and the zero VRF root.
fn builder_keys(key: usize) -> PqPublicKeys {
    PqPublicKeys {
        xmss_public_key: xmss_public_key(key),
        vrf_root: VrfRoot::ZERO,
    }
}

/// A fully valid registration of leanXMSS key `key` for the builder at `builder_index`.
fn builder_registration(
    state: &BeaconState<E>,
    builder_index: u64,
    key: usize,
    previous_change_epoch: Epoch,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    registration_with_keys(
        state,
        builder(builder_index),
        key,
        builder_keys(key),
        previous_change_epoch,
        spec,
    )
}

/// Adds the builder of `keypair`, deposited at `deposit_epoch`, returning its index.
fn add_builder(
    state: &mut BeaconState<E>,
    keypair: &Keypair,
    deposit_epoch: Epoch,
    spec: &ChainSpec,
) -> u64 {
    let pubkey = &keypair.pk;
    state
        .add_builder_to_registry(
            pubkey.compress(),
            PAYLOAD_BUILDER_VERSION,
            builder_withdrawal_credentials(pubkey, spec),
            spec.min_deposit_amount,
            deposit_epoch.start_slot(E::slots_per_epoch()),
            spec,
        )
        .unwrap()
}

/// Adds the `BUILDER_COUNT` builders of `BUILDER_KEYPAIRS`, deposited at `deposit_epoch`.
fn add_builders(state: &mut BeaconState<E>, deposit_epoch: Epoch, spec: &ChainSpec) {
    for keypair in 0..BUILDER_COUNT {
        assert_eq!(
            add_builder(state, &BUILDER_KEYPAIRS[keypair], deposit_epoch, spec),
            keypair as u64
        );
    }
}

/// The epoch at which `state_with_active_builders` deposits its builders.
const BUILDER_DEPOSIT_EPOCH: Epoch = Epoch::new(1);

/// The genesis state at `epoch` (see `state_at_epoch`), with the `BUILDER_COUNT` builders
/// deposited at `BUILDER_DEPOSIT_EPOCH` and the finalized checkpoint at `finalized_epoch`.
///
/// Builders are active once `finalized_epoch` is after their deposit epoch.
fn state_with_builders(harness: &Harness, epoch: u64, finalized_epoch: u64) -> BeaconState<E> {
    let mut state = state_at_epoch(harness, epoch);
    add_builders(&mut state, BUILDER_DEPOSIT_EPOCH, &harness.spec);
    state.finalized_checkpoint_mut().epoch = Epoch::new(finalized_epoch);
    state
}

#[tokio::test]
async fn first_registration_writes_keys_and_change_epoch() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = state_at_epoch(&harness, 3);

    assert!(!state.is_pq_registered(1).unwrap());
    assert_eq!(
        entry(&state, 1),
        (PqPublicKeys::default(), NEVER_REGISTERED)
    );

    let signed = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    assert_eq!(
        verify_pq_key_registration(&state, &signed, VerifySignatures::True, spec),
        Ok(())
    );
    process(&mut state, &signed, spec);

    assert!(state.is_pq_registered(1).unwrap());
    assert_eq!(entry(&state, 1), (public_keys(0, 0xaa), Epoch::new(3)));
    assert_eq!(
        pq_public_key_owner(&state, &xmss_public_key(0)),
        Ok(Some(1))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), Some(1));
    // No other entry changed.
    for (index, keys) in state.pq_public_keys().unwrap().iter().enumerate() {
        if index != 1 {
            assert_eq!(*keys, PqPublicKeys::default());
            assert_eq!(
                state.pq_key_change_epochs().unwrap().get(index),
                Some(&NEVER_REGISTERED)
            );
        }
    }
    assert_registry_invariant(&state);
}

#[tokio::test]
async fn key_change_respects_min_delay_and_replays_are_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let first_epoch = 3;
    let mut state = state_at_epoch(&harness, first_epoch);

    let first = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    process(&mut state, &first, spec);

    // One epoch before the delay has passed, the change is rejected.
    let change = registration(&state, 1, 1, 0xbb, Epoch::new(first_epoch), spec);
    let mut too_soon = state.clone();
    *too_soon.slot_mut() = Epoch::new(first_epoch + delay - 1).start_slot(E::slots_per_epoch());
    assert_rejected(
        &too_soon,
        &change,
        PqKeyRegistrationInvalid::ChangeTooSoon {
            current_epoch: Epoch::new(first_epoch + delay - 1),
            earliest_epoch: Epoch::new(first_epoch + delay),
        },
        spec,
    );

    // Once it has passed, the same change is accepted.
    let change_epoch = first_epoch + delay;
    *state.slot_mut() = Epoch::new(change_epoch).start_slot(E::slots_per_epoch());
    process(&mut state, &change, spec);
    assert_eq!(
        entry(&state, 1),
        (public_keys(1, 0xbb), Epoch::new(change_epoch))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(1)), Some(1));
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), None);

    // Replaying either registration fails: the change epoch they name is stale, even once the
    // delay has passed again.
    *state.slot_mut() = Epoch::new(change_epoch + delay).start_slot(E::slots_per_epoch());
    for (stale, previous_change_epoch) in [
        (&first, NEVER_REGISTERED),
        (&change, Epoch::new(first_epoch)),
    ] {
        assert_rejected(
            &state,
            stale,
            PqKeyRegistrationInvalid::PreviousChangeEpochMismatch {
                expected: Epoch::new(change_epoch),
                found: previous_change_epoch,
            },
            spec,
        );
    }
}

/// Every registration carries a leanXMSS key that no validator holds, including the registering
/// validator: a change that keeps the current key is rejected, whether it changes only the VRF root
/// or nothing at all.
#[tokio::test]
async fn change_keeping_the_key_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 2);

    register(&mut state, 4, 0, 0xaa, NEVER_REGISTERED, spec);

    // Same leanXMSS key (and therefore the same proof of possession), once the delay has passed:
    // with a new VRF root, and with the current keys unchanged.
    *state.slot_mut() = Epoch::new(2 + delay).start_slot(E::slots_per_epoch());
    let vrf_change = registration(&state, 4, 0, 0xcc, Epoch::new(2), spec);
    let same_keys = registration(&state, 4, 0, 0xaa, Epoch::new(2), spec);
    assert_eq!(same_keys.message.public_keys, entry(&state, 4).0);
    let expected = PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 4 };
    for keeps_key in [&vrf_change, &same_keys] {
        assert_eq!(
            keeps_key.message.public_keys.xmss_public_key,
            xmss_public_key(0)
        );
        assert_rejected(&state, keeps_key, expected.clone(), spec);
    }

    // The registry scan finds the validator itself too.
    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    assert_eq!(
        verify_pq_key_registration(&uncached, &vrf_change, VerifySignatures::True, spec),
        Err(BlockOperationError::Invalid(expected))
    );
    assert_eq!(
        pq_public_key_owner(&uncached, &xmss_public_key(0)),
        Ok(Some(4))
    );
    assert_eq!(entry(&state, 4), (public_keys(0, 0xaa), Epoch::new(2)));
}

#[tokio::test]
async fn key_change_keeping_the_vrf_root_is_accepted() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 2);

    register(&mut state, 4, 0, 0xaa, NEVER_REGISTERED, spec);

    // New leanXMSS key, same VRF root.
    *state.slot_mut() = Epoch::new(2 + delay).start_slot(E::slots_per_epoch());
    let key_change = registration(&state, 4, 1, 0xaa, Epoch::new(2), spec);
    assert_eq!(
        key_change.message.public_keys.vrf_root,
        entry(&state, 4).0.vrf_root
    );
    process(&mut state, &key_change, spec);

    assert_eq!(
        entry(&state, 4),
        (public_keys(1, 0xaa), Epoch::new(2 + delay))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), None);
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(1)), Some(4));
    assert_eq!(
        pq_public_key_owner(&state, &xmss_public_key(1)),
        Ok(Some(4))
    );
}

/// A key is held only by the validator whose current entry holds it, so once a validator changes
/// away from a key, no one holds it and the validator itself may register it again.
#[tokio::test]
async fn own_key_freed_by_a_change_is_registerable_again() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 2);

    register(&mut state, 4, 0, 0xaa, NEVER_REGISTERED, spec);
    *state.slot_mut() = Epoch::new(2 + delay).start_slot(E::slots_per_epoch());
    register(&mut state, 4, 1, 0xbb, Epoch::new(2), spec);
    assert_eq!(pq_public_key_owner(&state, &xmss_public_key(0)), Ok(None));

    // Key 0 again, with the stored proof of possession.
    *state.slot_mut() = Epoch::new(2 + 2 * delay).start_slot(E::slots_per_epoch());
    register(&mut state, 4, 0, 0xcc, Epoch::new(2 + delay), spec);
    assert_eq!(
        entry(&state, 4),
        (public_keys(0, 0xcc), Epoch::new(2 + 2 * delay))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), Some(4));
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(1)), None);
}

#[tokio::test]
async fn exiting_validator_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = harness.get_current_state();
    state.build_caches(spec).unwrap();

    initiate_validator_exit(&mut state, 5, spec).unwrap();
    let exit_epoch = state.validators().get(5).unwrap().exit_epoch;
    assert_ne!(exit_epoch, spec.far_future_epoch);

    let signed = registration(&state, 5, 0, 0xaa, NEVER_REGISTERED, spec);
    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::ValidatorExiting { exit_epoch },
        spec,
    );
}

#[tokio::test]
async fn unknown_validator_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();
    let index = state.validators().len() as u64;

    let mut signed = registration(&state, 0, 0, 0xaa, NEVER_REGISTERED, spec);
    signed.message.index = index;
    let signed = resign(signed, &state, spec);
    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::ValidatorUnknown(index),
        spec,
    );
}

/// The all-zero leanXMSS key, held by every unregistered entry, is never registered: an entry is
/// registered exactly when its key is not all-zero, and the cache never indexes the zero key.
#[tokio::test]
async fn unregistered_entries_never_own_the_all_zero_key() {
    let harness = eip8450_harness();
    let state = state_with_builders(&harness, 3, 2);
    let zero_key = XmssPublicKey::default();

    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    let mut rebuilt = uncached.clone();
    rebuilt.update_pq_pubkey_cache().unwrap();
    for state in [&state, &uncached, &rebuilt] {
        assert!(!state.is_pq_registered(1).unwrap());
        assert!(!state.is_pq_registered(builder(0)).unwrap());
        assert_eq!(state.registered_pq_public_keys().unwrap().count(), 0);
        assert_eq!(pq_public_key_owner(state, &zero_key), Ok(None));
    }
    assert!(!uncached.pq_pubkey_cache().is_initialized());
    assert_eq!(rebuilt.pq_pubkey_cache().get(&zero_key), None);
}

/// A registration of the all-zero key is rejected after the change delay and the BLS signature,
/// and before the key-in-use check (which every unregistered all-zero entry would fail), for a
/// validator and for a builder.
#[tokio::test]
async fn all_zero_key_is_rejected_after_the_signature_and_before_the_key_check() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = state_with_builders(&harness, 3, 2);
    let zero_keys = PqPublicKeys::default();
    let validator_zero =
        registration_with_keys(&state, 1, 0, zero_keys.clone(), NEVER_REGISTERED, spec);
    let builder_zero = registration_with_keys(
        &state,
        builder(0),
        0,
        zero_keys.clone(),
        BUILDER_DEPOSIT_EPOCH,
        spec,
    );

    for signed in [&validator_zero, &builder_zero] {
        assert_eq!(
            verify_pq_key_registration(&state, signed, VerifySignatures::False, spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::ZeroXmssPublicKey
            ))
        );
        assert_rejected(
            &state,
            signed,
            PqKeyRegistrationInvalid::ZeroXmssPublicKey,
            spec,
        );

        // The signature is checked first.
        let mut other_signer = signed.clone();
        other_signer.signature = signed
            .message
            .clone()
            .sign(
                signed.possession.clone(),
                &KEYPAIRS[7].sk,
                state.genesis_validators_root(),
                spec,
            )
            .signature;
        assert_rejected(
            &state,
            &other_signer,
            PqKeyRegistrationInvalid::BadSignature,
            spec,
        );
    }

    // The change delay is checked before it too.
    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let change_to_zero = registration_with_keys(&state, 1, 1, zero_keys, Epoch::new(3), spec);
    assert_rejected(
        &state,
        &change_to_zero,
        PqKeyRegistrationInvalid::ChangeTooSoon {
            current_epoch: Epoch::new(3),
            earliest_epoch: Epoch::new(3) + spec.min_pq_key_change_delay,
        },
        spec,
    );
}

#[tokio::test]
async fn key_registered_by_another_validator_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = harness.get_current_state();

    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);

    // Validator 2 holds a valid proof of possession of the same key for its own BLS public key.
    let copy = registration(&state, 2, 0, 0xbb, NEVER_REGISTERED, spec);
    assert!(is_valid_pq_possession_proof(
        &state,
        &validator_pubkey(&state, 2),
        &xmss_public_key(0),
        &copy.possession,
        spec
    ));
    let expected = PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 1 };
    assert_rejected(&state, &copy, expected.clone(), spec);

    // The check does not depend on the cache: the registry scan finds the owner too.
    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    assert!(!uncached.pq_pubkey_cache().is_initialized());
    assert_eq!(
        verify_pq_key_registration(&uncached, &copy, VerifySignatures::True, spec),
        Err(BlockOperationError::Invalid(expected))
    );
}

#[tokio::test]
async fn key_freed_by_a_change_is_registerable_by_another_validator() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 1);

    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let takeover = registration(&state, 2, 0, 0xbb, NEVER_REGISTERED, spec);
    assert_rejected(
        &state,
        &takeover,
        PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 1 },
        spec,
    );

    // Validator 1 changes away from key 0, which frees it.
    *state.slot_mut() = Epoch::new(1 + delay).start_slot(E::slots_per_epoch());
    register(&mut state, 1, 1, 0xaa, Epoch::new(1), spec);
    assert_eq!(pq_public_key_owner(&state, &xmss_public_key(0)), Ok(None));

    process(&mut state, &takeover, spec);
    assert_eq!(
        entry(&state, 2),
        (public_keys(0, 0xbb), Epoch::new(1 + delay))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), Some(2));
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(1)), Some(1));
}

#[tokio::test]
async fn invalid_possession_proofs_are_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();
    let valid = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);

    // One corrupted byte (past the leaf index).
    let mut corrupted = valid.clone();
    let last = corrupted.possession.len() - 1;
    corrupted.possession[last] ^= 0x01;
    // A valid proof of the same key for another validator's BLS public key.
    let other_pubkey = validator_pubkey(&state, 7);
    let mut other_validator = valid.clone();
    other_validator.possession =
        possession_proof(&state, &other_pubkey, 0, PQ_POSSESSION_XMSS_INDEX, spec);
    assert!(is_valid_pq_possession_proof(
        &state,
        &other_pubkey,
        &xmss_public_key(0),
        &other_validator.possession,
        spec
    ));

    for signed in [&corrupted, &other_validator] {
        assert!(!is_valid_pq_possession_proof(
            &state,
            &validator_pubkey(&state, 1),
            &xmss_public_key(0),
            &signed.possession,
            spec
        ));
        assert_rejected(
            &state,
            signed,
            PqKeyRegistrationInvalid::BadPossessionProof,
            spec,
        );
        // Without signature verification, the proof is left to the caller (bulk verification).
        assert_eq!(
            verify_pq_key_registration(&state, signed, VerifySignatures::False, spec),
            Ok(())
        );
    }
}

#[tokio::test]
async fn possession_proof_at_leaf_index_one_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();

    let mut signed = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let pubkey = validator_pubkey(&state, 1);
    signed.possession = possession_proof(&state, &pubkey, 0, 1, spec);

    // The real key signed the right message, at the wrong leaf index.
    let signature = xmss::Signature::from_bytes(&signed.possession).unwrap();
    assert_eq!(signature.leaf_index(), 1);
    let signing_root = get_pq_possession_signing_root(&state, &pubkey, &xmss_public_key(0), spec);
    assert_eq!(
        xmss_key(0).public_key().verify(&signing_root.0, &signature),
        Ok(())
    );

    assert!(!is_valid_pq_possession_proof(
        &state,
        &pubkey,
        &xmss_public_key(0),
        &signed.possession,
        spec
    ));
    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::BadPossessionProof,
        spec,
    );
}

#[tokio::test]
async fn bls_signature_under_current_fork_version_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();
    assert_ne!(state.fork().current_version, spec.genesis_fork_version);

    let mut signed = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let domain = spec.get_domain(
        state.current_epoch(),
        Domain::PqKeyRegistration,
        &state.fork(),
        state.genesis_validators_root(),
    );
    signed.signature = KEYPAIRS[1].sk.sign(signed.message.signing_root(domain));

    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::BadSignature,
        spec,
    );
}

/// Builds the next block on the harness head, applies `edit` to it, signs it by its proposer,
/// and returns it with its pre-state.
async fn block_with(
    harness: &Harness,
    edit: impl FnOnce(&mut BeaconBlock<E>),
) -> (SignedBeaconBlock<E>, BeaconState<E>) {
    let state = harness.get_current_state();
    let slot = state.slot() + Slot::new(1);
    let ((block, _), pre_state) = harness.make_block_return_pre_state(state, slot).await;
    let (mut block, _) = Arc::unwrap_or_clone(block).deconstruct();
    edit(&mut block);
    (harness.sign_beacon_block(block, &pre_state), pre_state)
}

/// Builds the next block on the harness head carrying `registrations`, signed by its proposer,
/// and returns it with its pre-state.
async fn block_with_registrations(
    harness: &Harness,
    registrations: Vec<SignedPqKeyRegistration>,
) -> (SignedBeaconBlock<E>, BeaconState<E>) {
    block_with(harness, |block| {
        *block.body_mut().pq_key_registrations_mut().unwrap() =
            ProgressiveVariableList::new(registrations).unwrap();
    })
    .await
}

fn process_block(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    strategy: BlockSignatureStrategy,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    per_block_processing(
        state,
        block,
        strategy,
        VerifyBlockRoot::True,
        &mut ConsensusContext::new(block.slot()),
        spec,
    )
}

/// One registration per validator `0..count`, validator `i` registering leanXMSS key `i`.
fn distinct_registrations(
    state: &BeaconState<E>,
    count: usize,
    spec: &ChainSpec,
) -> Vec<SignedPqKeyRegistration> {
    (0..count)
        .map(|i| registration(state, i as u64, i, i as u8, NEVER_REGISTERED, spec))
        .collect()
}

#[tokio::test]
async fn block_with_max_registrations_is_valid() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let max = E::max_pq_key_registrations();
    let registrations = distinct_registrations(&harness.get_current_state(), max, spec);
    let (block, pre_state) = block_with_registrations(&harness, registrations.clone()).await;

    for strategy in [
        BlockSignatureStrategy::VerifyIndividual,
        BlockSignatureStrategy::VerifyBulk,
    ] {
        let mut state = pre_state.clone();
        assert_eq!(process_block(&mut state, &block, strategy, spec), Ok(()));
        for signed in &registrations {
            let index = signed.message.index;
            assert_eq!(
                entry(&state, index),
                (signed.message.public_keys.clone(), state.current_epoch())
            );
            assert_eq!(
                state
                    .pq_pubkey_cache()
                    .get(&signed.message.public_keys.xmss_public_key),
                Some(index)
            );
        }
        assert_registry_invariant(&state);
    }
}

/// `MAX_PQ_KEY_REGISTRATIONS + 1` registrations, each valid on its own, never make a valid block:
/// the body type cannot hold them, a block encoding carrying them does not decode, and
/// `process_pq_key_registrations` rejects them.
#[tokio::test]
async fn block_with_too_many_registrations_is_invalid() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let max = E::max_pq_key_registrations();
    let registrations = distinct_registrations(&harness.get_current_state(), max + 1, spec);

    assert!(
        ProgressiveVariableList::<_, <E as EthSpec>::MaxPqKeyRegistrations>::new(
            registrations.clone()
        )
        .is_err()
    );

    // `pq_key_registrations` is the last field of the body, which is the last field of the
    // block, and its items have a fixed size: appending an item's encoding to a block's encoding
    // appends it to the list.
    let append = |block: &SignedBeaconBlock<E>, signed: &SignedPqKeyRegistration| {
        let mut bytes = block.as_ssz_bytes();
        bytes.extend(signed.as_ssz_bytes());
        SignedBeaconBlock::<E>::from_ssz_bytes(&bytes, spec)
    };
    let (block, pre_state) =
        block_with_registrations(&harness, registrations[..max - 1].to_vec()).await;
    let full_block = append(&block, &registrations[max - 1]).expect("MAX registrations decode");
    assert_eq!(
        full_block
            .message()
            .body()
            .pq_key_registrations()
            .unwrap()
            .as_slice(),
        &registrations[..max]
    );
    assert!(append(&full_block, &registrations[max]).is_err());

    let mut state = pre_state.clone();
    assert_eq!(
        process_pq_key_registrations(&mut state, &registrations, VerifySignatures::True, spec),
        Err(BlockProcessingError::OperationListTooLong {
            kind: "pq_key_registrations",
            length: max + 1,
            max,
        })
    );
    assert_eq!(
        state.pq_public_keys().unwrap(),
        pre_state.pq_public_keys().unwrap()
    );
}

#[tokio::test]
async fn block_registering_one_key_for_two_validators_is_invalid() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();
    // Each registration alone is valid.
    let first = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let second = registration(&state, 2, 0, 0xbb, NEVER_REGISTERED, spec);
    for signed in [&first, &second] {
        assert_eq!(
            verify_pq_key_registration(&state, signed, VerifySignatures::True, spec),
            Ok(())
        );
    }

    let (block, pre_state) = block_with_registrations(&harness, vec![first, second]).await;
    for strategy in [
        BlockSignatureStrategy::VerifyIndividual,
        BlockSignatureStrategy::VerifyBulk,
    ] {
        let mut state = pre_state.clone();
        assert_eq!(
            process_block(&mut state, &block, strategy, spec),
            Err(BlockProcessingError::PqKeyRegistrationInvalid {
                index: 1,
                reason: PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 1 },
            })
        );
    }
}

/// Registrations are processed after the other operations of the block, so a slashing or a
/// voluntary exit earlier in the same block exits the validator before its registration.
#[tokio::test]
async fn block_exiting_a_validator_before_its_registration_is_invalid() {
    let mut spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
    // Genesis validators can exit voluntarily at once.
    spec.shard_committee_period = 0;
    let harness = harness(spec);
    let spec = &harness.spec;
    let (slashed, exited) = (3, 4);

    for (index, proposer_slashings, voluntary_exits) in [
        (
            slashed,
            vec![harness.make_proposer_slashing(slashed)],
            vec![],
        ),
        (
            exited,
            vec![],
            vec![harness.make_voluntary_exit(exited, Epoch::new(0))],
        ),
    ] {
        // The registration alone is valid.
        let state = harness.get_current_state();
        let signed = registration(&state, index, 0, 0xaa, NEVER_REGISTERED, spec);
        assert_eq!(
            verify_pq_key_registration(&state, &signed, VerifySignatures::True, spec),
            Ok(())
        );

        let (block, pre_state) = block_with(&harness, |block| {
            *block
                .body_mut()
                .proposer_slashings_progressive_mut()
                .unwrap() = ProgressiveVariableList::new(proposer_slashings).unwrap();
            *block.body_mut().voluntary_exits_progressive_mut().unwrap() =
                ProgressiveVariableList::new(voluntary_exits).unwrap();
            *block.body_mut().pq_key_registrations_mut().unwrap() =
                ProgressiveVariableList::new(vec![signed]).unwrap();
        })
        .await;
        assert_ne!(block.message().proposer_index(), index);

        // The exit epoch that the slashing or the voluntary exit sets.
        let mut exiting_state = pre_state.clone();
        exiting_state.build_caches(spec).unwrap();
        initiate_validator_exit(&mut exiting_state, index as usize, spec).unwrap();
        let exit_epoch = exiting_state
            .validators()
            .get(index as usize)
            .unwrap()
            .exit_epoch;
        assert_ne!(exit_epoch, spec.far_future_epoch);

        for strategy in [
            BlockSignatureStrategy::VerifyIndividual,
            BlockSignatureStrategy::VerifyBulk,
        ] {
            let mut state = pre_state.clone();
            assert_eq!(
                process_block(&mut state, &block, strategy, spec),
                Err(invalid(PqKeyRegistrationInvalid::ValidatorExiting {
                    exit_epoch
                }))
            );
        }
    }
}

#[tokio::test]
async fn block_with_invalid_possession_proof_is_invalid() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();
    let valid = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let mut corrupted = valid.clone();
    corrupted.possession[100] ^= 0x80;
    // A valid proof of the key for another validator's BLS public key.
    let mut other_validator = valid;
    other_validator.possession = possession_proof(
        &state,
        &validator_pubkey(&state, 7),
        0,
        PQ_POSSESSION_XMSS_INDEX,
        spec,
    );

    for invalid_registration in [corrupted, other_validator] {
        let (block, pre_state) =
            block_with_registrations(&harness, vec![invalid_registration]).await;

        // Individual verification attributes the failure to the registration.
        let mut state = pre_state.clone();
        assert_eq!(
            process_block(
                &mut state,
                &block,
                BlockSignatureStrategy::VerifyIndividual,
                spec
            ),
            Err(invalid(PqKeyRegistrationInvalid::BadPossessionProof))
        );

        // Bulk verification checks the proof, against the validator's BLS public key in the
        // state, alongside the (valid) BLS signatures.
        let mut state = pre_state.clone();
        assert_eq!(
            process_block(&mut state, &block, BlockSignatureStrategy::VerifyBulk, spec),
            Err(BlockProcessingError::BulkSignatureVerificationFailed)
        );
        assert_eq!(
            BlockSignatureVerifier::verify_entire_block(
                &pre_state,
                |i| get_pubkey_from_state(&pre_state, i),
                |pk_bytes: &PublicKeyBytes| pk_bytes.decompress().ok().map(Cow::Owned),
                &block,
                &mut ConsensusContext::new(block.slot()),
                spec,
            ),
            Err(BlockSignatureVerifierError::PqPossessionProofInvalid)
        );
    }
}

#[tokio::test]
async fn fork_upgrade_initializes_unset_entries() {
    let mut spec = ForkName::Heze.make_genesis_spec(E::default_spec());
    spec.eip8450_fork_epoch = Some(Epoch::new(1));
    let harness = harness(spec);
    let spec = &harness.spec;

    let mut state = harness.get_current_state();
    assert_eq!(state.fork_name_unchecked(), ForkName::Heze);
    assert!(state.pq_public_keys().is_err());

    let fork_slot = Epoch::new(1).start_slot(E::slots_per_epoch());
    complete_state_advance(&mut state, None, fork_slot, None, spec).unwrap();

    assert_eq!(state.fork_name_unchecked(), ForkName::Eip8450);
    assert_eq!(state.fork().current_version, spec.eip8450_fork_version);
    assert_eq!(state.validators().len(), VALIDATOR_COUNT);
    assert_registry_invariant(&state);
    assert!(
        state
            .pq_public_keys()
            .unwrap()
            .iter()
            .all(|keys| *keys == PqPublicKeys::default())
    );
    assert!(
        state
            .pq_key_change_epochs()
            .unwrap()
            .iter()
            .all(|epoch| *epoch == NEVER_REGISTERED)
    );
    assert!(state.pq_pubkey_cache().is_initialized());

    // Keys can be registered right after the upgrade.
    let signed = registration(&state, 3, 0, 0xaa, NEVER_REGISTERED, spec);
    process(&mut state, &signed, spec);
    assert_eq!(entry(&state, 3), (public_keys(0, 0xaa), Epoch::new(1)));
}

#[tokio::test]
async fn deposit_after_fork_keeps_registry_lengths() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = harness.get_current_state();
    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    let cache_before = state.pq_pubkey_cache().clone();

    let new_keypair = generate_deterministic_keypair(VALIDATOR_COUNT);
    let mut deposit_data = DepositData {
        pubkey: new_keypair.pk.compress(),
        withdrawal_credentials: Hash256::repeat_byte(0x01),
        amount: spec.min_activation_balance,
        signature: bls::SignatureBytes::empty(),
    };
    deposit_data.signature = deposit_data.create_signature(&new_keypair.sk, spec);
    apply_deposit(&mut state, deposit_data, None, false, spec).unwrap();

    assert_eq!(state.validators().len(), VALIDATOR_COUNT + 1);
    assert_registry_invariant(&state);
    assert_eq!(
        entry(&state, VALIDATOR_COUNT as u64),
        (PqPublicKeys::default(), NEVER_REGISTERED)
    );
    assert_eq!(*state.pq_pubkey_cache(), cache_before);
    assert_eq!(entry(&state, 1), (public_keys(0, 0xaa), Epoch::new(0)));
}

#[tokio::test]
async fn pq_pubkey_cache_rebuilt_from_uncached_state_matches() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 1);

    // Registrations, a key change (freeing key 0) and a key change keeping the VRF root (freeing
    // key 1).
    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    register(&mut state, 2, 1, 0xbb, NEVER_REGISTERED, spec);
    *state.slot_mut() = Epoch::new(1 + delay).start_slot(E::slots_per_epoch());
    register(&mut state, 1, 2, 0xaa, Epoch::new(1), spec);
    register(&mut state, 2, 3, 0xbb, Epoch::new(1), spec);
    assert!(state.pq_pubkey_cache().is_initialized());

    // A state decoded from SSZ (as when loaded from disk) carries no cache.
    let mut decoded = BeaconState::<E>::from_ssz_bytes(&state.as_ssz_bytes(), spec).unwrap();
    assert!(!decoded.pq_pubkey_cache().is_initialized());

    // The registry scan agrees with the cache before the rebuild...
    for key in 0..4 {
        assert_eq!(
            pq_public_key_owner(&decoded, &xmss_public_key(key)),
            pq_public_key_owner(&state, &xmss_public_key(key))
        );
    }
    for (key, owner) in [(0, None), (1, None), (2, Some(1)), (3, Some(2))] {
        assert_eq!(
            pq_public_key_owner(&state, &xmss_public_key(key)),
            Ok(owner)
        );
    }

    // ...and the rebuilt cache is identical.
    decoded.update_pq_pubkey_cache().unwrap();
    assert_eq!(decoded.pq_pubkey_cache(), state.pq_pubkey_cache());
    let mut cloned = state.clone();
    cloned.drop_pq_pubkey_cache();
    cloned.update_pq_pubkey_cache().unwrap();
    assert_eq!(cloned.pq_pubkey_cache(), state.pq_pubkey_cache());

    // Further processing gives identical results on the original and the rebuilt state.
    let copy = registration(&state, 3, 3, 0xdd, NEVER_REGISTERED, spec);
    let freed = registration(&state, 3, 0, 0xdd, NEVER_REGISTERED, spec);
    for state in [&mut state, &mut decoded] {
        assert_eq!(
            verify_pq_key_registration(state, &copy, VerifySignatures::True, spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 2 }
            ))
        );
        process(state, &freed, spec);
    }
    assert_eq!(decoded.as_ssz_bytes(), state.as_ssz_bytes());
    assert_eq!(decoded.pq_pubkey_cache(), state.pq_pubkey_cache());
}

/// A registration applied in the genesis epoch moves the validator's entry from
/// `FAR_FUTURE_EPOCH` to `GENESIS_EPOCH`, so it cannot be included again once the change delay has
/// passed. (With `GENESIS_EPOCH` as the marker, it stored the value it named and could be.)
#[tokio::test]
async fn registration_applied_in_genesis_epoch_cannot_be_replayed() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = harness.get_current_state();
    assert_eq!(state.current_epoch(), E::genesis_epoch());

    let first = registration(&state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    process(&mut state, &first, spec);
    assert_eq!(entry(&state, 1), (public_keys(0, 0xaa), E::genesis_epoch()));

    *state.slot_mut() = Epoch::new(delay).start_slot(E::slots_per_epoch());
    assert_rejected(
        &state,
        &first,
        PqKeyRegistrationInvalid::PreviousChangeEpochMismatch {
            expected: E::genesis_epoch(),
            found: NEVER_REGISTERED,
        },
        spec,
    );

    // A change naming the genesis epoch, the stored change epoch, is the one that applies.
    let change = registration(&state, 1, 1, 0xbb, E::genesis_epoch(), spec);
    process(&mut state, &change, spec);
    assert_eq!(entry(&state, 1), (public_keys(1, 0xbb), Epoch::new(delay)));
}

/// An unregistered validator's entry is `FAR_FUTURE_EPOCH`, so a first registration naming
/// `GENESIS_EPOCH` names the wrong entry.
#[tokio::test]
async fn first_registration_naming_genesis_epoch_is_rejected() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = harness.get_current_state();

    let signed = registration(&state, 1, 0, 0xaa, E::genesis_epoch(), spec);
    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::PreviousChangeEpochMismatch {
            expected: NEVER_REGISTERED,
            found: E::genesis_epoch(),
        },
        spec,
    );
}

/// A builder's never-registered marker is its deposit epoch. A first registration names it and
/// stores the current epoch, after which the builder is registered and holds the key.
#[tokio::test]
async fn builder_first_registration_stores_the_current_epoch() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = state_with_builders(&harness, 3, 2);
    assert_registry_invariant(&state);

    assert_eq!(
        state.get_builder(0).unwrap().deposit_epoch,
        BUILDER_DEPOSIT_EPOCH
    );
    assert_eq!(
        entry(&state, builder(0)),
        (PqPublicKeys::default(), BUILDER_DEPOSIT_EPOCH)
    );
    assert!(!state.is_pq_registered(builder(0)).unwrap());

    let signed = builder_registration(&state, 0, 0, BUILDER_DEPOSIT_EPOCH, spec);
    process(&mut state, &signed, spec);

    assert!(state.is_pq_registered(builder(0)).unwrap());
    assert_eq!(entry(&state, builder(0)), (builder_keys(0), Epoch::new(3)));
    assert_eq!(
        pq_public_key_owner(&state, &xmss_public_key(0)),
        Ok(Some(builder(0)))
    );
    // The other builders and the validators are untouched.
    assert!(!state.is_pq_registered(builder(1)).unwrap());
    assert_eq!(state.registered_pq_public_keys().unwrap().count(), 1);
    assert_registry_invariant(&state);

    // The rebuilt cache indexes the builder's key under its flagged index.
    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    assert_eq!(
        pq_public_key_owner(&uncached, &xmss_public_key(0)),
        Ok(Some(builder(0)))
    );
    uncached.update_pq_pubkey_cache().unwrap();
    assert_eq!(uncached.pq_pubkey_cache(), state.pq_pubkey_cache());
}

/// A builder's change is rate-limited like a validator's, and its first registration cannot be
/// replayed once the delay has passed: the stored epoch moved from the deposit epoch.
#[tokio::test]
async fn builder_replay_is_rejected_after_the_delay() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_with_builders(&harness, 3, 2);
    let first = builder_registration(&state, 0, 0, BUILDER_DEPOSIT_EPOCH, spec);
    process(&mut state, &first, spec);

    let change = builder_registration(&state, 0, 1, Epoch::new(3), spec);
    assert_rejected(
        &state,
        &change,
        PqKeyRegistrationInvalid::ChangeTooSoon {
            current_epoch: Epoch::new(3),
            earliest_epoch: Epoch::new(3 + delay),
        },
        spec,
    );

    *state.slot_mut() = Epoch::new(3 + delay).start_slot(E::slots_per_epoch());
    assert_rejected(
        &state,
        &first,
        PqKeyRegistrationInvalid::PreviousChangeEpochMismatch {
            expected: Epoch::new(3),
            found: BUILDER_DEPOSIT_EPOCH,
        },
        spec,
    );
    process(&mut state, &change, spec);
    assert_eq!(
        entry(&state, builder(0)),
        (builder_keys(1), Epoch::new(3 + delay))
    );
}

#[tokio::test]
async fn builder_registration_rejections() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let state = state_with_builders(&harness, 3, 2);
    let valid = builder_registration(&state, 0, 0, BUILDER_DEPOSIT_EPOCH, spec);
    assert_eq!(
        verify_pq_key_registration(&state, &valid, VerifySignatures::True, spec),
        Ok(())
    );

    // Not yet active: the deposit epoch is not before the finalized epoch.
    let mut not_finalized = state.clone();
    not_finalized.finalized_checkpoint_mut().epoch = BUILDER_DEPOSIT_EPOCH;
    assert_rejected(
        &not_finalized,
        &valid,
        PqKeyRegistrationInvalid::BuilderNotActive(0),
        spec,
    );

    // Initiated an exit.
    let mut exiting = state.clone();
    exiting
        .builders_mut()
        .unwrap()
        .get_mut(0)
        .unwrap()
        .withdrawable_epoch = Epoch::new(3) + spec.min_builder_withdrawability_delay;
    assert_rejected(
        &exiting,
        &valid,
        PqKeyRegistrationInvalid::BuilderNotActive(0),
        spec,
    );

    // Outside the builder registry.
    let mut unknown = valid.clone();
    unknown.message.index = builder(BUILDER_COUNT as u64);
    assert_rejected(
        &state,
        &unknown,
        PqKeyRegistrationInvalid::BuilderUnknown(BUILDER_COUNT as u64),
        spec,
    );

    // A non-zero VRF root.
    let with_vrf_root = registration_with_keys(
        &state,
        builder(0),
        0,
        public_keys(0, 0xaa),
        BUILDER_DEPOSIT_EPOCH,
        spec,
    );
    assert_rejected(
        &state,
        &with_vrf_root,
        PqKeyRegistrationInvalid::BuilderNonZeroVrfRoot(0),
        spec,
    );

    // Signed by a validator's key rather than the builder's.
    let mut validator_signed = valid.clone();
    validator_signed.signature = valid
        .message
        .clone()
        .sign(
            valid.possession.clone(),
            &KEYPAIRS[0].sk,
            state.genesis_validators_root(),
            spec,
        )
        .signature;
    assert_rejected(
        &state,
        &validator_signed,
        PqKeyRegistrationInvalid::BadSignature,
        spec,
    );

    // A proof of possession of the key for another BLS public key (validator 0's).
    let mut other_pubkey = valid.clone();
    other_pubkey.possession = possession_proof(
        &state,
        &validator_pubkey(&state, 0),
        0,
        PQ_POSSESSION_XMSS_INDEX,
        spec,
    );
    assert_rejected(
        &state,
        &other_pubkey,
        PqKeyRegistrationInvalid::BadPossessionProof,
        spec,
    );

    // Key uniqueness spans validators and builders, both ways.
    let mut state = state;
    register(&mut state, 1, 2, 0xaa, NEVER_REGISTERED, spec);
    let builder_copy = builder_registration(&state, 0, 2, BUILDER_DEPOSIT_EPOCH, spec);
    assert_rejected(
        &state,
        &builder_copy,
        PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 1 },
        spec,
    );
    let first = builder_registration(&state, 1, 3, BUILDER_DEPOSIT_EPOCH, spec);
    process(&mut state, &first, spec);
    let validator_copy = registration(&state, 2, 3, 0xbb, NEVER_REGISTERED, spec);
    assert_rejected(
        &state,
        &validator_copy,
        PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: builder(1) },
        spec,
    );
}

/// Exits builder 0 of `state` and sweeps it, then moves `state` to the epoch at which its index is
/// reusable, `withdrawable_epoch`, which it returns.
fn sweep_builder_0(state: &mut BeaconState<E>, spec: &ChainSpec) -> Epoch {
    let withdrawable_epoch = state.current_epoch() + spec.min_builder_withdrawability_delay;
    let exited = state.builders_mut().unwrap().get_mut(0).unwrap();
    exited.withdrawable_epoch = withdrawable_epoch;
    exited.balance = 0;
    *state.slot_mut() = withdrawable_epoch.start_slot(E::slots_per_epoch());
    assert_eq!(state.get_index_for_new_builder(), Ok(0));
    withdrawable_epoch
}

/// Reusing a builder index resets its entry, starting the change epoch at the new builder's
/// deposit epoch and releasing the earlier builder's key, with and without a built cache.
/// Registrations signed for an earlier builder then never apply, even once the same BLS key
/// re-enters at the index. A deposit for a key still in the registry is a top-up, so it re-enters
/// only after another builder has held the index in between.
#[tokio::test]
async fn builder_index_reuse_resets_the_entry_and_frees_the_key() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = state_with_builders(&harness, 3, 2);
    let first = builder_registration(&state, 0, 0, BUILDER_DEPOSIT_EPOCH, spec);
    process(&mut state, &first, spec);
    // A change the earlier builder signed but never got included.
    let stale_change = builder_registration(&state, 0, 1, Epoch::new(3), spec);

    // Another builder takes index 0 once builder 0 has exited and been swept.
    let reuse_epoch = sweep_builder_0(&mut state, spec);
    let other_keypair = generate_deterministic_keypair(VALIDATOR_COUNT + BUILDER_COUNT);
    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    for state in [&mut state, &mut uncached] {
        assert_eq!(add_builder(state, &other_keypair, reuse_epoch, spec), 0);
        assert_eq!(state.builders().unwrap().len(), BUILDER_COUNT);
        assert_eq!(
            entry(state, builder(0)),
            (PqPublicKeys::default(), reuse_epoch)
        );
        assert!(!state.is_pq_registered(builder(0)).unwrap());
        assert_eq!(pq_public_key_owner(state, &xmss_public_key(0)), Ok(None));
        assert_registry_invariant(state);
    }
    assert!(state.pq_pubkey_cache().is_initialized());
    assert!(!uncached.pq_pubkey_cache().is_initialized());
    uncached.update_pq_pubkey_cache().unwrap();
    assert_eq!(uncached.pq_pubkey_cache(), state.pq_pubkey_cache());

    // The released key is registrable again.
    let freed = registration(&state, 5, 0, 0xaa, NEVER_REGISTERED, spec);
    assert_eq!(
        verify_pq_key_registration(&state, &freed, VerifySignatures::False, spec),
        Ok(())
    );

    // The other builder exits too, and the earlier builder's BLS key re-enters at index 0.
    let reentry_epoch = sweep_builder_0(&mut state, spec);
    assert_eq!(
        add_builder(&mut state, &BUILDER_KEYPAIRS[0], reentry_epoch, spec),
        0
    );
    assert_eq!(
        entry(&state, builder(0)),
        (PqPublicKeys::default(), reentry_epoch)
    );

    // Once it is active, the registrations signed before name epochs before its deposit epoch.
    state.finalized_checkpoint_mut().epoch = reentry_epoch + 1;
    *state.slot_mut() = (reentry_epoch + 1).start_slot(E::slots_per_epoch());
    for stale in [&first, &stale_change] {
        assert_rejected(
            &state,
            stale,
            PqKeyRegistrationInvalid::PreviousChangeEpochMismatch {
                expected: reentry_epoch,
                found: stale.message.previous_change_epoch,
            },
            spec,
        );
    }
    let fresh = builder_registration(&state, 0, 1, reentry_epoch, spec);
    process(&mut state, &fresh, spec);
    assert_eq!(
        entry(&state, builder(0)),
        (builder_keys(1), reentry_epoch + 1)
    );
}

/// The upgrade gives every builder an unset entry whose change epoch is its deposit epoch.
#[tokio::test]
async fn fork_upgrade_initializes_builder_entries_with_their_deposit_epoch() {
    let mut spec = ForkName::Heze.make_genesis_spec(E::default_spec());
    spec.eip8450_fork_epoch = Some(Epoch::new(2));
    let harness = harness(spec);
    let spec = &harness.spec;

    let mut state = harness.get_current_state();
    assert_eq!(state.fork_name_unchecked(), ForkName::Heze);
    add_builder(&mut state, &BUILDER_KEYPAIRS[0], Epoch::new(0), spec);
    add_builder(&mut state, &BUILDER_KEYPAIRS[1], Epoch::new(1), spec);

    complete_state_advance(
        &mut state,
        None,
        Epoch::new(2).start_slot(E::slots_per_epoch()),
        None,
        spec,
    )
    .unwrap();

    assert_eq!(state.fork_name_unchecked(), ForkName::Eip8450);
    assert_registry_invariant(&state);
    assert_eq!(state.builders().unwrap().len(), 2);
    for (builder_index, deposit_epoch) in [(0, 0), (1, 1)] {
        assert_eq!(
            entry(&state, builder(builder_index)),
            (PqPublicKeys::default(), Epoch::new(deposit_epoch))
        );
        assert!(!state.is_pq_registered(builder(builder_index)).unwrap());
    }
    assert_eq!(state.registered_pq_public_keys().unwrap().count(), 0);

    // A builder added after the upgrade gets an entry too.
    add_builder(&mut state, &BUILDER_KEYPAIRS[2], Epoch::new(2), spec);
    assert_registry_invariant(&state);
    assert_eq!(
        entry(&state, builder(2)),
        (PqPublicKeys::default(), Epoch::new(2))
    );

    // The state is a 50-field progressive container: proofs of the first and the last field
    // verify against its root.
    let root = state.update_tree_hash_cache().unwrap();
    let leaves = state.get_beacon_state_leaves();
    assert_eq!(leaves.len(), 50);
    for field_index in [FINALIZED_CHECKPOINT_FIELD_INDEX, 49] {
        let proof = state.generate_proof(field_index, &leaves).unwrap();
        let gindex = merkle_proof::progressive_container_gindex(field_index).unwrap();
        let depth = gindex.ilog2() as usize;
        assert_eq!(proof.len(), depth);
        assert!(merkle_proof::verify_merkle_proof(
            leaves[field_index],
            &proof,
            depth,
            gindex - (1 << depth),
            root
        ));
    }
}

/// Block signature verification reads the builder's BLS public key for a flagged index, both for
/// the authorization and the proof of possession.
#[tokio::test]
async fn block_signatures_of_builder_registrations_use_the_builder_key() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    // Move into epoch 1, so that a builder deposited at genesis can be active with a finalized
    // epoch no later than the current epoch.
    harness
        .extend_to_slot(Slot::new(E::slots_per_epoch()))
        .await;
    // Builders and finality do not enter the block, so they are added to its pre-state after it
    // is built.
    let with_builders = |state: &mut BeaconState<E>| {
        add_builders(state, Epoch::new(0), spec);
        state.finalized_checkpoint_mut().epoch = Epoch::new(1);
    };
    let mut builders_state = harness.get_current_state();
    with_builders(&mut builders_state);

    let valid = builder_registration(&builders_state, 0, 0, Epoch::new(0), spec);
    let mut other_pubkey = builder_registration(&builders_state, 1, 1, Epoch::new(0), spec);
    other_pubkey.possession = possession_proof(
        &builders_state,
        &validator_pubkey(&builders_state, 0),
        1,
        PQ_POSSESSION_XMSS_INDEX,
        spec,
    );

    let (block, mut pre_state) = block_with_registrations(&harness, vec![valid.clone()]).await;
    with_builders(&mut pre_state);
    for strategy in [
        BlockSignatureStrategy::VerifyIndividual,
        BlockSignatureStrategy::VerifyBulk,
    ] {
        let mut state = pre_state.clone();
        assert_eq!(process_block(&mut state, &block, strategy, spec), Ok(()));
        assert_eq!(
            entry(&state, builder(0)),
            (builder_keys(0), state.current_epoch())
        );
    }

    let (block, mut pre_state) = block_with_registrations(&harness, vec![other_pubkey]).await;
    with_builders(&mut pre_state);
    assert_eq!(
        BlockSignatureVerifier::verify_entire_block(
            &pre_state,
            |i| get_pubkey_from_state(&pre_state, i),
            |pk_bytes: &PublicKeyBytes| pk_bytes.decompress().ok().map(Cow::Owned),
            &block,
            &mut ConsensusContext::new(block.slot()),
            spec,
        ),
        Err(BlockSignatureVerifierError::PqPossessionProofInvalid)
    );
}
