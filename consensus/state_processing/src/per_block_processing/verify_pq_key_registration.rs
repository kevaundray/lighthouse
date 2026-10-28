//! Post-quantum validator key registry (EIP-8450): validation of `SignedPqKeyRegistration`s.

use super::errors::{BlockOperationError, PqKeyRegistrationInvalid as Invalid};
use crate::VerifySignatures;
use crate::per_block_processing::signature_sets::{
    get_pubkey_from_state, pq_key_registration_signature_set,
};
use lean_pq::xmss;
use safe_arith::SafeArith;
use types::{
    BeaconState, BeaconStateError, ChainSpec, Domain, EthSpec, Hash256, PQ_KEYS_VERSION_1,
    PQ_POSSESSION_XMSS_INDEX, PqKeyPossession, PqPublicKeys, SignedPqKeyRegistration, SignedRoot,
    XmssPublicKey, XmssSignature,
};

type Result<T, E = BlockOperationError<Invalid>> = std::result::Result<T, E>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Returns whether the validator at `index` has registered post-quantum keys (`is_pq_registered`).
pub fn is_pq_registered<E: EthSpec>(
    state: &BeaconState<E>,
    index: u64,
) -> Result<bool, BeaconStateError> {
    state
        .pq_public_keys()?
        .get(index as usize)
        .map(PqPublicKeys::is_registered)
        .ok_or(BeaconStateError::UnknownValidator(index as usize))
}

/// Returns whether a validator other than `excluded_index` registered the leanXMSS key of
/// `public_keys` (`is_pq_public_key_in_use`), returning that validator's index.
///
/// Uses the state's `PqPubkeyCache` when it is built, and scans the registry otherwise.
pub fn pq_public_key_owner<E: EthSpec>(
    state: &BeaconState<E>,
    public_keys: &PqPublicKeys,
    excluded_index: u64,
) -> Result<Option<u64>, BeaconStateError> {
    let owner = if state.pq_pubkey_cache().is_initialized() {
        state.pq_pubkey_cache().get(&public_keys.xmss_public_key)
    } else {
        state.pq_public_keys()?.iter().position(|entry| {
            entry.is_registered() && entry.xmss_public_key == public_keys.xmss_public_key
        })
    };
    Ok(owner
        .map(|owner| owner as u64)
        .filter(|owner| *owner != excluded_index))
}

/// Returns the message that the proof of possession of `xmss_public_key` for `index` signs.
///
/// The domain uses the genesis fork version, so a proof stays valid across forks.
pub fn get_pq_possession_signing_root<E: EthSpec>(
    state: &BeaconState<E>,
    index: u64,
    xmss_public_key: &XmssPublicKey,
    spec: &ChainSpec,
) -> Hash256 {
    let domain = spec.compute_domain(
        Domain::PqKeyPossession,
        spec.genesis_fork_version,
        state.genesis_validators_root(),
    );
    PqKeyPossession {
        validator_index: index,
        xmss_public_key: xmss_public_key.clone(),
    }
    .signing_root(domain)
}

/// Checks that the holder of `xmss_public_key` signed it for the validator at `index`, at leaf
/// index `PQ_POSSESSION_XMSS_INDEX`.
pub fn is_valid_pq_possession_proof<E: EthSpec>(
    state: &BeaconState<E>,
    index: u64,
    xmss_public_key: &XmssPublicKey,
    proof: &XmssSignature,
    spec: &ChainSpec,
) -> bool {
    let Ok(signature) = xmss::Signature::from_bytes(proof) else {
        return false;
    };
    // Leaf index 0 is reserved for the proof of possession.
    if signature.leaf_index() != PQ_POSSESSION_XMSS_INDEX {
        return false;
    }
    let Ok(public_key) = xmss::PublicKey::from_bytes(xmss_public_key) else {
        return false;
    };
    let signing_root = get_pq_possession_signing_root(state, index, xmss_public_key, spec);
    public_key.verify(&signing_root.0, &signature).is_ok()
}

/// Indicates if a `SignedPqKeyRegistration` is valid to be included in a block, where the block is
/// being applied to the given `state` at its current epoch.
///
/// Evaluates every assertion of `process_pq_key_registration`, in order. With
/// `VerifySignatures::True` it also checks the BLS authorization and the leanXMSS proof of
/// possession; with `VerifySignatures::False` both are expected to be checked by the caller (see
/// `BlockSignatureVerifier`).
pub fn verify_pq_key_registration<E: EthSpec>(
    state: &BeaconState<E>,
    signed_registration: &SignedPqKeyRegistration,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<()> {
    let registration = &signed_registration.message;
    let index = registration.validator_index;
    let public_keys = &registration.public_keys;

    let pq_key_change_epochs = state
        .pq_key_change_epochs()
        .map_err(|_| error(Invalid::RegistryUnavailable))?;

    let validator = state
        .validators()
        .get(index as usize)
        .ok_or_else(|| error(Invalid::ValidatorUnknown(index)))?;

    // Keys are registered only for validators that have not initiated an exit.
    verify!(
        validator.exit_epoch == spec.far_future_epoch,
        Invalid::ValidatorExiting {
            exit_epoch: validator.exit_epoch
        }
    );
    verify!(
        public_keys.version == PQ_KEYS_VERSION_1,
        Invalid::UnsupportedVersion(public_keys.version)
    );

    // The registration applies to the validator's current entry only.
    let last_change_epoch = *pq_key_change_epochs
        .get(index as usize)
        .ok_or(BeaconStateError::UnknownValidator(index as usize))?;
    verify!(
        registration.previous_change_epoch == last_change_epoch,
        Invalid::PreviousChangeEpochMismatch {
            expected: last_change_epoch,
            found: registration.previous_change_epoch,
        }
    );

    // Changes of registered keys are rate-limited.
    if is_pq_registered(state, index)? {
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

    // The validator's signing key authorizes the registration.
    if verify_signatures.is_true() {
        verify!(
            pq_key_registration_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_registration,
                spec
            )?
            .verify(),
            Invalid::BadSignature
        );
    }

    // The key must be unique, and the registrant must prove possession of it.
    if let Some(owner) = pq_public_key_owner(state, public_keys, index)? {
        return Err(error(Invalid::XmssPublicKeyInUse { owner }));
    }
    if verify_signatures.is_true() {
        verify!(
            is_valid_pq_possession_proof(
                state,
                index,
                &public_keys.xmss_public_key,
                &signed_registration.possession,
                spec
            ),
            Invalid::BadPossessionProof
        );
    }

    Ok(())
}
