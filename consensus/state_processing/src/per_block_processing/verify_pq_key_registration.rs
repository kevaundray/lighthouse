//! Post-quantum consensus key registry (EIP-8450): validation of `SignedPqKeyRegistration`s.

use super::errors::{BlockOperationError, PqKeyRegistrationInvalid as Invalid};
use crate::VerifySignatures;
use crate::per_block_processing::signature_sets::{
    get_builder_pubkey_from_state, get_pubkey_from_state, pq_key_registration_signature_set,
};
use bls::PublicKeyBytes;
use lean_pq::xmss;
use safe_arith::SafeArith;
use std::cmp::Ordering;
use types::{
    BeaconState, BeaconStateError, ChainSpec, Domain, Epoch, EthSpec, Hash256,
    PQ_POSSESSION_XMSS_INDEX, PQ_UNREGISTERED_CHANGE_EPOCH, PqKeyMaterial, PqKeyPossession,
    PqRegistryIndex, SignedPqKeyRegistration, SignedRoot, VrfRoot, XmssPublicKey, XmssSignature,
};

type Result<T, E = BlockOperationError<Invalid>> = std::result::Result<T, E>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Returns the validator or builder, including the one registering, that holds the non-zero
/// leanXMSS key `xmss_public_key` (`is_pq_public_key_in_use`), with builder indices flagged.
///
/// Every registration therefore carries a new leanXMSS key: a validator or builder cannot
/// re-register its own current key, even to change only its VRF root.
///
/// The all-zero key is held by every unregistered entry but owned by none here: callers reject it
/// first (`ZeroXmssPublicKey`), as `process_pq_key_registration` does. Uses the state's
/// `PqPubkeyCache` when it is built, and scans the registries otherwise.
pub fn pq_public_key_owner<E: EthSpec>(
    state: &BeaconState<E>,
    xmss_public_key: &XmssPublicKey,
) -> Result<Option<u64>, BeaconStateError> {
    if state.pq_pubkey_cache().is_initialized() {
        return Ok(state.pq_pubkey_cache().get(xmss_public_key));
    }
    Ok(state
        .registered_pq_key_material()?
        .find(|(_, entry)| entry.xmss_public_key == *xmss_public_key)
        .map(|(index, _)| index))
}

/// Compares two values of the stored change epoch of a validator or builder index by the order in
/// which a chain takes them.
///
/// A validator's entry starts at `FAR_FUTURE_EPOCH` (never registered), and every change stores
/// the current epoch, which is later than the previous change. So `FAR_FUTURE_EPOCH` comes before
/// every epoch, and epochs compare numerically.
///
/// A builder index's entry only takes real epochs, and they increase numerically along a chain,
/// even across reuse of the index:
///
/// - it starts at the builder's deposit epoch `D`. A registration requires an active builder,
///   whose `D` is before the finalized epoch, so it stores a current epoch after `D`, and later
///   changes store later epochs;
/// - the last value `L` of a builder is stored while it is active, i.e. before its exit is
///   initiated at some epoch `X >= L` (a registration in the block of the exit request comes after
///   it, and fails). Its index is reused only once `withdrawable_epoch = X +
///   MIN_BUILDER_WITHDRAWABILITY_DELAY <= current epoch`, so the next builder's deposit epoch is
///   at least `L + MIN_BUILDER_WITHDRAWABILITY_DELAY > L`. An exited builder never becomes active
///   again: a deposit to it only moves its `withdrawable_epoch`, which never returns to
///   `FAR_FUTURE_EPOCH`.
///
/// So the order is numeric for builders too, and `FAR_FUTURE_EPOCH`, which a builder entry never
/// holds, sorts first.
pub fn cmp_pq_change_epochs(a: Epoch, b: Epoch) -> Ordering {
    match (
        a == PQ_UNREGISTERED_CHANGE_EPOCH,
        b == PQ_UNREGISTERED_CHANGE_EPOCH,
    ) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(&b),
    }
}

/// Returns whether no state descending from a finalized state can apply a registration of a
/// validator or builder index naming `previous_change_epoch`, where `stored` is the index's stored
/// change epoch in the finalized state and `finalized_epoch` its current epoch.
///
/// A descendant's entry is either `stored`, or the epoch of a block applied on top of the
/// finalized state, which is at least `finalized_epoch`: a change, or for a builder index the
/// deposit epoch of a builder that reuses it. So the registration is dead if it names another
/// value that is:
///
/// - behind `stored` in the order of [`cmp_pq_change_epochs`]: the entry only moves forward along
///   a chain;
/// - or a real epoch before `finalized_epoch`: a change or builder deposit at such an epoch on the
///   finalized chain would be in the finalized state, so it was made on a fork that is not
///   canonical. A builder's first registration names its deposit epoch, which is before the
///   finalized epoch of the including state by `is_active_builder`; if that deposit is canonical,
///   it is `stored` until the builder registers.
///
/// A registration naming `finalized_epoch` itself is not dead: a block of that epoch after the
/// finalized checkpoint can still make a change at it.
pub fn is_pq_registration_dead(
    stored: Epoch,
    previous_change_epoch: Epoch,
    finalized_epoch: Epoch,
) -> bool {
    previous_change_epoch != stored
        && (cmp_pq_change_epochs(stored, previous_change_epoch) == Ordering::Greater
            || (previous_change_epoch != PQ_UNREGISTERED_CHANGE_EPOCH
                && previous_change_epoch < finalized_epoch))
}

/// Returns the signing root of the `PqKeyPossession` of `xmss_public_key` for the validator or
/// builder holding `pubkey` (`get_pq_possession_signing_root`).
///
/// The proof binds the leanXMSS key to the registrant's BLS public key, which never changes and is
/// known before the registrant has an index. The domain uses the genesis fork version, so a proof
/// stays valid across forks.
pub fn get_pq_possession_signing_root<E: EthSpec>(
    state: &BeaconState<E>,
    pubkey: &PublicKeyBytes,
    xmss_public_key: &XmssPublicKey,
    spec: &ChainSpec,
) -> Hash256 {
    let domain = spec.compute_domain(
        Domain::PqKeyPossession,
        spec.genesis_fork_version,
        state.genesis_validators_root(),
    );
    PqKeyPossession {
        pubkey: *pubkey,
        xmss_public_key: xmss_public_key.clone(),
    }
    .signing_root(domain)
}

/// Checks if `proof` is a signature, by `xmss_public_key`, of the key itself for the validator or
/// builder holding `pubkey` (`is_valid_pq_possession_proof`).
///
/// The proof must be at leaf index `PQ_POSSESSION_XMSS_INDEX`, which is reserved for it.
pub fn is_valid_pq_possession_proof<E: EthSpec>(
    state: &BeaconState<E>,
    pubkey: &PublicKeyBytes,
    xmss_public_key: &XmssPublicKey,
    proof: &XmssSignature,
    spec: &ChainSpec,
) -> bool {
    let Ok(signature) = xmss::Signature::from_bytes(proof) else {
        return false;
    };
    if signature.leaf_index() != PQ_POSSESSION_XMSS_INDEX {
        return false;
    }
    let Ok(public_key) = xmss::PublicKey::from_bytes(xmss_public_key) else {
        return false;
    };
    let signing_root = get_pq_possession_signing_root(state, pubkey, xmss_public_key, spec);
    public_key.verify(&signing_root.0, &signature).is_ok()
}

/// Returns the BLS public key of the validator or builder that `index` names, after the checks of
/// `process_pq_key_registration` on the index itself: a known validator that has not initiated an
/// exit, or a known, active builder registering a zero VRF root.
pub fn verify_pq_registrant<E: EthSpec>(
    state: &BeaconState<E>,
    index: u64,
    key_material: &PqKeyMaterial,
    spec: &ChainSpec,
) -> Result<PublicKeyBytes> {
    match PqRegistryIndex::new(index) {
        PqRegistryIndex::Builder(builder_index) => {
            let builder = state
                .builders()?
                .get(builder_index as usize)
                .ok_or_else(|| error(Invalid::BuilderUnknown(builder_index)))?;
            // Keys are registered only for active builders, whose deposit epoch is finalized.
            verify!(
                state.is_active_builder(builder_index, spec)?,
                Invalid::BuilderNotActive(builder_index)
            );
            // Builders make no selection proofs, so they register no VRF root.
            verify!(
                key_material.vrf_root == VrfRoot::ZERO,
                Invalid::BuilderNonZeroVrfRoot(builder_index)
            );
            Ok(builder.pubkey)
        }
        PqRegistryIndex::Validator(validator_index) => {
            let validator = state
                .validators()
                .get(validator_index as usize)
                .ok_or_else(|| error(Invalid::ValidatorUnknown(validator_index)))?;
            // Keys are registered only for validators that have not initiated an exit.
            verify!(
                validator.exit_epoch == spec.far_future_epoch,
                Invalid::ValidatorExiting {
                    exit_epoch: validator.exit_epoch
                }
            );
            Ok(validator.pubkey)
        }
    }
}

/// Indicates if a `SignedPqKeyRegistration` is valid to be included in a block, where the block is
/// being applied to the given `state` at its current epoch.
///
/// Evaluates every assertion of `process_pq_key_registration`, in order, for a validator index or
/// a flagged builder index. With `VerifySignatures::True` it also checks the BLS authorization and
/// the leanXMSS proof of possession; with `VerifySignatures::False` both are expected to be checked
/// by the caller (see `BlockSignatureVerifier`).
pub fn verify_pq_key_registration<E: EthSpec>(
    state: &BeaconState<E>,
    signed_registration: &SignedPqKeyRegistration,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let registration = &signed_registration.message;
    let index = registration.index;
    let key_material = &registration.key_material;

    if state.pq_key_change_epochs().is_err() {
        return Err(error(Invalid::RegistryUnavailable));
    }

    let pubkey = verify_pq_registrant(state, index, key_material, spec)?;

    // The registration applies to the current entry only. Every change moves the stored epoch, so
    // a replayed registration fails here.
    let last_change_epoch = state.get_pq_key_change_epoch(index)?;
    verify!(
        registration.previous_change_epoch == last_change_epoch,
        Invalid::PreviousChangeEpochMismatch {
            expected: last_change_epoch,
            found: registration.previous_change_epoch,
        }
    );

    // Changes of registered keys are rate-limited. An entry holding the all-zero key has never
    // registered: its change epoch is its never-registered marker, which is never added to.
    if state.is_pq_registered(index)? {
        let current_epoch = state.current_epoch();
        let earliest_epoch = last_change_epoch.safe_add(spec.min_pq_key_change_delay)?;
        verify!(
            current_epoch >= earliest_epoch,
            Invalid::ChangeTooSoon {
                current_epoch,
                earliest_epoch,
            }
        );
    }

    // The BLS signing key of the validator or builder authorizes the registration.
    if verify_signatures.is_true() {
        verify!(
            pq_key_registration_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                |i| get_builder_pubkey_from_state(state, i),
                signed_registration,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    // The key must be a new, non-zero key: no validator or builder, including this one, may hold
    // it. The registrant must also prove possession of it for its BLS public key.
    verify!(
        key_material.xmss_public_key != XmssPublicKey::default(),
        Invalid::ZeroXmssPublicKey
    );
    if let Some(owner) = pq_public_key_owner(state, &key_material.xmss_public_key)? {
        return Err(error(Invalid::XmssPublicKeyInUse { owner }));
    }
    if verify_signatures.is_true() {
        verify!(
            is_valid_pq_possession_proof(
                state,
                &pubkey,
                &key_material.xmss_public_key,
                &signed_registration.possession,
                spec
            ),
            Invalid::BadPossessionProof
        );
    }

    Ok(())
}
