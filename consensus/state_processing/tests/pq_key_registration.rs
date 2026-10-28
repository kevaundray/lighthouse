//! EIP-8450 (post-quantum validator key registry): behavioural tests of the state transition.
//!
//! Covers the Test Cases of EIP-8450: registrations and changes of keys, every rejection of
//! `process_pq_key_registration`, block-level limits, the fork upgrade, the registry length
//! invariant and the `PqPubkeyCache`.
//!
//! leanXMSS keys come from fixed seeds. Each `(key, message, leaf index)` is signed once per process
//! and the signature is reused, as a signer reuses its stored proof of possession: signing is not
//! assumed to be deterministic.
#![cfg(not(feature = "fake_crypto"))]

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
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
        get_pq_possession_signing_root, is_pq_registered, is_valid_pq_possession_proof,
        pq_public_key_owner,
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
    MinimalEthSpec, PQ_POSSESSION_XMSS_INDEX, PqKeyRegistration, PqPublicKeys, SignedBeaconBlock,
    SignedPqKeyRegistration, SignedRoot, Slot, VrfRoot, XmssPublicKey, XmssSignature,
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

/// A registration of `public_keys` for `validator_index` with a valid proof of possession (by
/// leanXMSS key `key`) and a valid BLS authorization.
fn registration_with_keys(
    state: &BeaconState<E>,
    validator_index: u64,
    key: usize,
    public_keys: PqPublicKeys,
    previous_change_epoch: Epoch,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    let possession = possession_proof(
        state,
        &validator_pubkey(state, validator_index),
        key,
        PQ_POSSESSION_XMSS_INDEX,
        spec,
    );
    PqKeyRegistration {
        validator_index,
        public_keys,
        previous_change_epoch,
    }
    .sign(
        possession,
        &KEYPAIRS[validator_index as usize].sk,
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

/// Re-signs the registration message with the validator's BLS key, keeping the possession proof.
fn resign(
    mut signed: SignedPqKeyRegistration,
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> SignedPqKeyRegistration {
    let signer = &KEYPAIRS[signed.message.validator_index as usize % VALIDATOR_COUNT].sk;
    let resigned = signed.message.clone().sign(
        signed.possession.clone(),
        signer,
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

fn entry(state: &BeaconState<E>, index: u64) -> (PqPublicKeys, Epoch) {
    (
        state
            .pq_public_keys()
            .unwrap()
            .get(index as usize)
            .unwrap()
            .clone(),
        *state
            .pq_key_change_epochs()
            .unwrap()
            .get(index as usize)
            .unwrap(),
    )
}

fn assert_registry_invariant(state: &BeaconState<E>) {
    let validators = state.validators().len();
    assert_eq!(state.pq_public_keys().unwrap().len(), validators);
    assert_eq!(state.pq_key_change_epochs().unwrap().len(), validators);
}

#[tokio::test]
async fn first_registration_writes_keys_and_change_epoch() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = state_at_epoch(&harness, 3);

    assert!(!is_pq_registered(&state, 1).unwrap());
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

    assert!(is_pq_registered(&state, 1).unwrap());
    assert_eq!(entry(&state, 1), (public_keys(0, 0xaa), Epoch::new(3)));
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(0, 0xaa), u64::MAX),
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

#[tokio::test]
async fn vrf_root_only_change_keeps_the_key() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let delay = spec.min_pq_key_change_delay.as_u64();
    let mut state = state_at_epoch(&harness, 2);

    register(&mut state, 4, 0, 0xaa, NEVER_REGISTERED, spec);

    // Same leanXMSS key (and therefore the same proof of possession), new VRF root.
    *state.slot_mut() = Epoch::new(2 + delay).start_slot(E::slots_per_epoch());
    let vrf_change = registration(&state, 4, 0, 0xcc, Epoch::new(2), spec);
    assert_eq!(
        vrf_change.message.public_keys.xmss_public_key,
        xmss_public_key(0)
    );
    process(&mut state, &vrf_change, spec);

    assert_eq!(
        entry(&state, 4),
        (public_keys(0, 0xcc), Epoch::new(2 + delay))
    );
    assert_eq!(state.pq_pubkey_cache().get(&xmss_public_key(0)), Some(4));
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(0, 0xcc), u64::MAX),
        Ok(Some(4))
    );
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
    signed.message.validator_index = index;
    let signed = resign(signed, &state, spec);
    assert_rejected(
        &state,
        &signed,
        PqKeyRegistrationInvalid::ValidatorUnknown(index),
        spec,
    );
}

/// Registration is decided by `pq_key_change_epochs` alone: the all-zero `pq_public_keys` entry of
/// an unregistered validator never owns the all-zero key, whether the `PqPubkeyCache` is built or
/// not, while a registered validator holding that key does.
#[tokio::test]
async fn unregistered_entries_never_own_the_all_zero_key() {
    let harness = eip8450_harness();
    let spec = &harness.spec;
    let mut state = harness.get_current_state();
    let zero_keys = PqPublicKeys::default();
    let zero_key = XmssPublicKey::default();

    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    let mut rebuilt = uncached.clone();
    rebuilt.update_pq_pubkey_cache().unwrap();
    for state in [&state, &uncached, &rebuilt] {
        assert!(
            state
                .pq_public_keys()
                .unwrap()
                .iter()
                .all(|keys| *keys == zero_keys)
        );
        assert_eq!(state.registered_pq_public_keys().unwrap().count(), 0);
        for excluded_index in [0, 1, u64::MAX] {
            assert_eq!(
                pq_public_key_owner(state, &zero_keys, excluded_index),
                Ok(None)
            );
        }
        // A registration of the all-zero key passes the uniqueness check and fails only on its
        // proof of possession.
        let signed = registration_with_keys(state, 1, 0, zero_keys.clone(), NEVER_REGISTERED, spec);
        assert_eq!(
            verify_pq_key_registration(state, &signed, VerifySignatures::False, spec),
            Ok(())
        );
        assert_rejected(
            state,
            &signed,
            PqKeyRegistrationInvalid::BadPossessionProof,
            spec,
        );
    }
    assert!(!uncached.pq_pubkey_cache().is_initialized());
    assert_eq!(rebuilt.pq_pubkey_cache().get(&zero_key), None);

    // A registered validator holding the all-zero key (written directly: no proof of possession
    // of it exists) owns it, and the unregistered all-zero entries still do not.
    state
        .set_pq_public_keys(5, zero_keys.clone(), Epoch::new(0))
        .unwrap();
    assert!(is_pq_registered(&state, 5).unwrap());
    assert!(!is_pq_registered(&state, 4).unwrap());
    let mut uncached = state.clone();
    uncached.drop_pq_pubkey_cache();
    let mut rebuilt = uncached.clone();
    rebuilt.update_pq_pubkey_cache().unwrap();
    assert_eq!(rebuilt.pq_pubkey_cache(), state.pq_pubkey_cache());
    assert_eq!(state.pq_pubkey_cache().get(&zero_key), Some(5));
    for state in [&state, &uncached, &rebuilt] {
        assert_eq!(pq_public_key_owner(state, &zero_keys, 1), Ok(Some(5)));
        assert_eq!(pq_public_key_owner(state, &zero_keys, 5), Ok(None));
        assert_eq!(
            state
                .registered_pq_public_keys()
                .unwrap()
                .collect::<Vec<_>>(),
            vec![(5, &zero_keys)]
        );
    }
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
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(0, 0xbb), 2),
        Ok(None)
    );

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
            let index = signed.message.validator_index;
            assert_eq!(
                entry(&state, index),
                (signed.message.public_keys.clone(), state.current_epoch())
            );
            assert_eq!(
                state
                    .pq_pubkey_cache()
                    .get(&signed.message.public_keys.xmss_public_key),
                Some(index as usize)
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

    // Registrations, a key change (freeing key 0) and a VRF-only change.
    register(&mut state, 1, 0, 0xaa, NEVER_REGISTERED, spec);
    register(&mut state, 2, 1, 0xbb, NEVER_REGISTERED, spec);
    *state.slot_mut() = Epoch::new(1 + delay).start_slot(E::slots_per_epoch());
    register(&mut state, 1, 2, 0xaa, Epoch::new(1), spec);
    register(&mut state, 2, 1, 0xcc, Epoch::new(1), spec);
    assert!(state.pq_pubkey_cache().is_initialized());

    // A state decoded from SSZ (as when loaded from disk) carries no cache.
    let mut decoded = BeaconState::<E>::from_ssz_bytes(&state.as_ssz_bytes(), spec).unwrap();
    assert!(!decoded.pq_pubkey_cache().is_initialized());

    // The registry scan agrees with the cache before the rebuild...
    for key in 0..3 {
        let keys = public_keys(key, 0);
        assert_eq!(
            pq_public_key_owner(&decoded, &keys, u64::MAX),
            pq_public_key_owner(&state, &keys, u64::MAX)
        );
    }
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(0, 0), u64::MAX),
        Ok(None)
    );
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(1, 0), u64::MAX),
        Ok(Some(2))
    );
    assert_eq!(
        pq_public_key_owner(&state, &public_keys(2, 0), u64::MAX),
        Ok(Some(1))
    );

    // ...and the rebuilt cache is identical.
    decoded.update_pq_pubkey_cache().unwrap();
    assert_eq!(decoded.pq_pubkey_cache(), state.pq_pubkey_cache());
    let mut cloned = state.clone();
    cloned.drop_pq_pubkey_cache();
    cloned.update_pq_pubkey_cache().unwrap();
    assert_eq!(cloned.pq_pubkey_cache(), state.pq_pubkey_cache());

    // Further processing gives identical results on the original and the rebuilt state.
    let copy = registration(&state, 3, 1, 0xdd, NEVER_REGISTERED, spec);
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
