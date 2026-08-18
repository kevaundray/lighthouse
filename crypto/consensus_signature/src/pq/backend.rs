//! Exact-pin bridge to leanMultisig's private envelope conventions.

use super::PqSigningClaim;
use super::wire::RAW_PAYLOAD_LEN;
#[cfg(test)]
use std::ops::RangeInclusive;

const UPSTREAM_MAGIC: &[u8; 4] = b"LMSI";
const UPSTREAM_VERSION: u8 = 1;
const UPSTREAM_RAW_KIND: u8 = 0;
const UPSTREAM_HEADER_LEN: usize = UPSTREAM_MAGIC.len() + 2;

pub(crate) type BackendSignature = lean_multisig::Signature;
#[cfg(test)]
pub(crate) type BackendSigningKey = lean_multisig::SecretKey;

#[derive(Debug)]
pub(crate) struct BackendError(lean_multisig::Error);

impl BackendError {
    #[cfg(test)]
    pub(crate) fn from_upstream(error: lean_multisig::Error) -> Self {
        Self(error)
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AggregateFailureCategory {
    PeerInvalidEvidence,
    LocallyGeneratedProof,
    Internal,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
#[derive(Debug)]
pub(crate) struct AggregateFailure {
    category: AggregateFailureCategory,
    error: BackendError,
}

#[cfg(any(test, all(target_arch = "x86_64", target_feature = "avx2")))]
impl AggregateFailure {
    pub(crate) const fn category(&self) -> AggregateFailureCategory {
        self.category
    }

    pub(crate) fn into_error(self) -> BackendError {
        self.error
    }

    fn new(category: AggregateFailureCategory, error: lean_multisig::Error) -> Self {
        Self {
            category,
            error: BackendError(error),
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn classify_aggregate_input(error: lean_multisig::Error) -> AggregateFailure {
    let category = match &error {
        lean_multisig::Error::MalformedSignature => AggregateFailureCategory::PeerInvalidEvidence,
        // The public key comes from locally resolved validator state. All other variants are
        // impossible for the exact one-key raw decoder or are conservatively local.
        _ => AggregateFailureCategory::Internal,
    };
    AggregateFailure::new(category, error)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn classify_raw_only_aggregate(error: lean_multisig::Error) -> AggregateFailure {
    let category = match &error {
        // Raw contribution bytes can be structurally canonical but cryptographically invalid.
        lean_multisig::Error::InvalidSignature { .. } => {
            AggregateFailureCategory::PeerInvalidEvidence
        }
        // Every recursive proof on this path was generated inside the owned worker.
        lean_multisig::Error::Proof(_) => AggregateFailureCategory::LocallyGeneratedProof,
        // Requests were bounded before entering the backend. Unknown and impossible variants are
        // local so a future upstream error can never become peer blame by default.
        _ => AggregateFailureCategory::Internal,
    };
    AggregateFailure::new(category, error)
}

#[cfg(test)]
pub(crate) fn injected_aggregate_failure(category: AggregateFailureCategory) -> AggregateFailure {
    AggregateFailure::new(category, lean_multisig::Error::NotInitialized)
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
pub(crate) fn decode_aggregate_input(
    payload: [u8; RAW_PAYLOAD_LEN],
    public_key: [u8; 32],
    claim: &PqSigningClaim,
) -> Result<BackendSignature, AggregateFailure> {
    decode_raw_signature(payload, public_key, claim).map_err(classify_aggregate_input)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub(crate) fn aggregate(
    signatures: Vec<BackendSignature>,
    claim: &PqSigningClaim,
) -> Result<BackendSignature, AggregateFailure> {
    lean_multisig::aggregate(signatures, &backend_claim(claim)).map_err(classify_raw_only_aggregate)
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
