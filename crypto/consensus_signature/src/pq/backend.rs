//! Exact-pin bridge to leanMultisig's private envelope conventions.

use super::PqSigningClaim;
use crate::pq_wire::RAW_PAYLOAD_LEN;
#[cfg(test)]
use std::ops::RangeInclusive;

const UPSTREAM_MAGIC: &[u8; 4] = b"LMSI";
const UPSTREAM_VERSION: u8 = 1;
const UPSTREAM_RAW_KIND: u8 = 0;
const UPSTREAM_AGGREGATE_KIND: u8 = 1;
const UPSTREAM_HEADER_LEN: usize = UPSTREAM_MAGIC.len() + 2;

pub(crate) type BackendSignature = lean_multisig::Signature;
#[cfg(test)]
pub(crate) type BackendSigningKey = lean_multisig::SecretKey;

#[derive(Debug)]
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) struct BackendError(lean_multisig::Error);

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
impl std::fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
pub(crate) fn signing_key_from_seed(
    seed: [u8; 32],
    range: RangeInclusive<u32>,
) -> Result<BackendSigningKey, lean_multisig::Error> {
    BackendSigningKey::from_seed(seed, range)
}

#[cfg(test)]
pub(crate) fn public_key(key: &BackendSigningKey) -> [u8; 32] {
    key.public_key()
}

fn backend_claim(claim: &PqSigningClaim) -> lean_multisig::Claim {
    lean_multisig::Claim::new(*claim.signing_root(), claim.one_time_use_id().as_u32())
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) fn setup() {
    lean_multisig::setup();
}

#[cfg(test)]
pub(crate) fn sign_raw(
    key: &BackendSigningKey,
    claim: &PqSigningClaim,
) -> Result<[u8; RAW_PAYLOAD_LEN], lean_multisig::Error> {
    let signature = key.sign(&backend_claim(claim))?;
    raw_payload(&signature).ok_or(lean_multisig::Error::MalformedSignature)
}

pub(crate) fn verify_raw(
    payload: [u8; RAW_PAYLOAD_LEN],
    public_key: [u8; 32],
    claim: &PqSigningClaim,
) -> Result<(), lean_multisig::Error> {
    let signature = decode_raw_signature(payload, public_key, claim)?;
    verify_signature(&signature, &[public_key], claim)
}

pub(crate) fn decode_raw_signature(
    payload: [u8; RAW_PAYLOAD_LEN],
    public_key: [u8; 32],
    claim: &PqSigningClaim,
) -> Result<BackendSignature, lean_multisig::Error> {
    let mut upstream = Vec::with_capacity(UPSTREAM_HEADER_LEN + RAW_PAYLOAD_LEN);
    upstream.extend_from_slice(UPSTREAM_MAGIC);
    upstream.push(UPSTREAM_VERSION);
    upstream.push(UPSTREAM_RAW_KIND);
    upstream.extend_from_slice(&payload);
    BackendSignature::from_bytes(&upstream, &backend_claim(claim), &[public_key])
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) fn encode_aggregate_signature(
    signature: &BackendSignature,
) -> Result<Vec<u8>, BackendError> {
    let bytes = signature.to_bytes();
    if !has_upstream_envelope(&bytes, UPSTREAM_AGGREGATE_KIND) {
        return Err(BackendError(lean_multisig::Error::MalformedSignature));
    }
    Ok(bytes)
}

pub(crate) fn decode_aggregate_signature(
    bytes: &[u8],
    public_keys: &[[u8; 32]],
    claim: &PqSigningClaim,
) -> Result<BackendSignature, lean_multisig::Error> {
    if !has_upstream_envelope(bytes, UPSTREAM_AGGREGATE_KIND) {
        return Err(lean_multisig::Error::MalformedSignature);
    }
    BackendSignature::from_bytes(bytes, &backend_claim(claim), public_keys)
}

fn has_upstream_envelope(bytes: &[u8], kind: u8) -> bool {
    bytes.len() > UPSTREAM_HEADER_LEN
        && bytes.get(..UPSTREAM_MAGIC.len()) == Some(UPSTREAM_MAGIC)
        && bytes.get(UPSTREAM_MAGIC.len()).copied() == Some(UPSTREAM_VERSION)
        && bytes.get(UPSTREAM_MAGIC.len() + 1).copied() == Some(kind)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) fn aggregate(
    signatures: Vec<BackendSignature>,
    claim: &PqSigningClaim,
) -> Result<BackendSignature, BackendError> {
    lean_multisig::aggregate(signatures, &backend_claim(claim)).map_err(BackendError)
}

pub(crate) fn verify_signature(
    signature: &BackendSignature,
    public_keys: &[[u8; 32]],
    claim: &PqSigningClaim,
) -> Result<(), lean_multisig::Error> {
    lean_multisig::verify(signature, public_keys, &backend_claim(claim))
}

#[cfg(test)]
pub(crate) fn raw_payload(signature: &BackendSignature) -> Option<[u8; RAW_PAYLOAD_LEN]> {
    let bytes = signature.to_bytes();
    if bytes.len() != UPSTREAM_HEADER_LEN + RAW_PAYLOAD_LEN
        || bytes.get(..UPSTREAM_MAGIC.len()) != Some(UPSTREAM_MAGIC)
        || bytes.get(UPSTREAM_MAGIC.len()).copied() != Some(UPSTREAM_VERSION)
        || bytes.get(UPSTREAM_MAGIC.len() + 1).copied() != Some(UPSTREAM_RAW_KIND)
    {
        return None;
    }
    bytes.get(UPSTREAM_HEADER_LEN..)?.try_into().ok()
}
