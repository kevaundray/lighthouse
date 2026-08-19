use std::borrow::Cow;

use crate::aggregation::{
    AggregationError, InvalidAggregationJob, V1_MAX_AGGREGATION_OUTPUT_BYTES,
    ValidatedAggregationJob,
};

pub use bls::Hash256;

/// The serialized validator public key used by the active signature backend.
pub type ValidatorPublicKeyBytes = bls::PublicKeyBytes;

/// A decoded validator public key used during verification.
pub type VerificationKey = bls::PublicKey;

/// Evidence produced by one validator for one signing claim.
pub type IndividualSignature = bls::Signature;

/// Serialized form used to carry an individual signature across HTTP.
pub type SerializedIndividualSignature = bls::SignatureBytes;

/// Serializes an individual signature without changing the BLS wire representation.
pub fn serialize_individual_signature(
    signature: &IndividualSignature,
) -> SerializedIndividualSignature {
    signature.clone().into()
}

/// Decodes the HTTP transport form into an individual signature.
pub fn decode_individual_signature(
    signature: &SerializedIndividualSignature,
) -> Result<IndividualSignature, crate::IndividualSignatureTransportError> {
    signature
        .decompress()
        .map_err(|_| crate::IndividualSignatureTransportError::InvalidEncoding)
}

/// Returns whether this is the legacy BLS infinity value accepted when RANDAO verification is
/// explicitly skipped.
pub fn is_verification_skip_placeholder(signature: &IndividualSignature) -> bool {
    signature.is_infinity()
}

/// Evidence authorizing one signing claim for one or more validators.
///
/// In the BLS profile this is an aggregate signature, including the one-signer aggregate used by
/// `SingleAttestation`. The PQ profile may instead use a cheaply promotable tagged raw signature
/// or aggregate proof.
pub type SameMessageEvidence = bls::AggregateSignature;

/// Backwards-compatible name used while verification callers migrate to semantic terminology.
pub type RawSignature = IndividualSignature;

/// Backwards-compatible name used while aggregation callers migrate to semantic terminology.
pub type AggregateSignature = SameMessageEvidence;

/// A backend-owned request used while state-processing callers migrate to semantic requests.
///
/// This keeps the BLS `SignatureSet` construction API stable while ensuring that backend batch
/// selection and invocation occur inside this crate.
pub type BatchVerificationRequest<'a> = bls::SignatureSet<'a>;

/// A consensus-signature verification failure.
///
/// Only [`Self::InvalidEvidence`] indicates peer-provided evidence is invalid. The other variants
/// represent local failures and must not be attributed to the peer.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The supplied signature does not authenticate the expected claim and signer set.
    InvalidEvidence,
    /// The local verification backend is not currently available.
    LocalUnavailable,
    /// Local verification limits prevent processing the request.
    ResourceExhausted,
    /// The local verification backend failed unexpectedly.
    Internal,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidEvidence => "invalid consensus signature evidence",
            Self::LocalUnavailable => "consensus signature verifier unavailable",
            Self::ResourceExhausted => "consensus signature verification resources exhausted",
            Self::Internal => "internal consensus signature verification failure",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for VerifyError {}

/// The consensus information cryptographically authenticated by a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningClaim {
    signing_root: Hash256,
}

impl SigningClaim {
    /// Creates a claim for `signing_root`.
    pub const fn new(signing_root: Hash256) -> Self {
        Self { signing_root }
    }

    /// Returns the root authenticated by the signature.
    pub const fn signing_root(self) -> Hash256 {
        self.signing_root
    }
}

/// A raw-signature verification request.
#[derive(Clone, Copy)]
pub struct RawVerificationRequest<'a> {
    claim: SigningClaim,
    public_key: &'a VerificationKey,
    signature: &'a RawSignature,
}

impl<'a> RawVerificationRequest<'a> {
    /// Creates a request to verify one validator signature.
    pub const fn new(
        claim: SigningClaim,
        public_key: &'a VerificationKey,
        signature: &'a RawSignature,
    ) -> Self {
        Self {
            claim,
            public_key,
            signature,
        }
    }
}

/// An aggregate-signature verification request for a single signing claim.
#[derive(Clone, Copy)]
pub struct AggregateVerificationRequest<'a> {
    claim: SigningClaim,
    public_keys: &'a [&'a VerificationKey],
    signature: &'a AggregateSignature,
}

impl<'a> AggregateVerificationRequest<'a> {
    /// Creates a request to verify an aggregate over `public_keys`.
    pub const fn new(
        claim: SigningClaim,
        public_keys: &'a [&'a VerificationKey],
        signature: &'a AggregateSignature,
    ) -> Self {
        Self {
            claim,
            public_keys,
            signature,
        }
    }
}

/// A validator-signature verification request accepted by the active backend.
#[derive(Clone, Copy)]
pub enum VerificationRequest<'a> {
    /// Evidence from one validator.
    Raw(RawVerificationRequest<'a>),
    /// Evidence aggregated from validators that signed the same claim.
    Aggregate(AggregateVerificationRequest<'a>),
}

impl<'a> From<RawVerificationRequest<'a>> for VerificationRequest<'a> {
    fn from(request: RawVerificationRequest<'a>) -> Self {
        Self::Raw(request)
    }
}

impl<'a> From<AggregateVerificationRequest<'a>> for VerificationRequest<'a> {
    fn from(request: AggregateVerificationRequest<'a>) -> Self {
        Self::Aggregate(request)
    }
}

/// Verifies one raw or aggregate request.
pub fn verify(request: VerificationRequest<'_>) -> Result<(), VerifyError> {
    let is_valid = match request {
        VerificationRequest::Raw(request) => request
            .signature
            .verify(request.public_key, request.claim.signing_root()),
        VerificationRequest::Aggregate(request) => request
            .signature
            .fast_aggregate_verify(request.claim.signing_root(), request.public_keys),
    };

    if is_valid {
        Ok(())
    } else {
        Err(VerifyError::InvalidEvidence)
    }
}

/// Batch-verifies raw and aggregate requests using the active backend.
pub fn verify_all<'a>(
    requests: impl IntoIterator<Item = VerificationRequest<'a>>,
) -> Result<(), VerifyError> {
    let signature_sets = requests.into_iter().map(signature_set).collect::<Vec<_>>();
    if bls::verify_signature_sets(signature_sets.iter()) {
        Ok(())
    } else {
        Err(VerifyError::InvalidEvidence)
    }
}

/// Batch-verifies backend-owned requests using the active consensus-signature backend.
pub fn verify_batch<'a>(
    requests: impl ExactSizeIterator<Item = &'a BatchVerificationRequest<'a>>,
) -> Result<(), VerifyError> {
    if bls::verify_signature_sets(requests) {
        Ok(())
    } else {
        Err(VerifyError::InvalidEvidence)
    }
}

fn signature_set(request: VerificationRequest<'_>) -> bls::SignatureSet<'_> {
    match request {
        VerificationRequest::Raw(request) => bls::SignatureSet::single_pubkey(
            request.signature,
            Cow::Borrowed(request.public_key),
            request.claim.signing_root(),
        ),
        VerificationRequest::Aggregate(request) => bls::SignatureSet::multiple_pubkeys(
            request.signature,
            request
                .public_keys
                .iter()
                .copied()
                .map(Cow::Borrowed)
                .collect(),
            request.claim.signing_root(),
        ),
    }
}

pub(crate) fn aggregate_job(
    job: ValidatedAggregationJob,
) -> Result<SameMessageEvidence, AggregationError> {
    // BLS executes synchronously, but consumes the same validated accounting metadata so backend
    // selection does not change the operation-level job shape.
    let _queued_evidence_bytes = job.queued_evidence_bytes;
    for contribution in &job.contributions {
        let public_keys = contribution
            .signers
            .iter()
            .map(|signer| signer.public_key.decompress())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AggregationError::InvalidJob(InvalidAggregationJob::InvalidPublicKey))?;
        let public_key_refs = public_keys.iter().collect::<Vec<_>>();
        if !contribution
            .evidence
            .fast_aggregate_verify(Hash256::from(job.claim.signing_root), &public_key_refs)
        {
            return Err(AggregationError::InvalidEvidence);
        }
    }

    let mut contributions = job.contributions.into_iter();
    let mut aggregate = contributions
        .next()
        .ok_or(AggregationError::Internal)?
        .evidence;
    for contribution in contributions {
        // Point mutation remains private to the BLS backend. Consensus callers only submit an
        // owned, fully validated operation-level job.
        aggregate.add_assign_aggregate(&contribution.evidence);
    }
    let expected_public_keys = job
        .expected_signers
        .iter()
        .map(|signer| signer.public_key.decompress())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AggregationError::InvalidJob(InvalidAggregationJob::InvalidPublicKey))?;
    let expected_public_key_refs = expected_public_keys.iter().collect::<Vec<_>>();
    if !aggregate.fast_aggregate_verify(
        Hash256::from(job.claim.signing_root),
        &expected_public_key_refs,
    ) {
        return Err(AggregationError::Internal);
    }
    let output_len = aggregate.serialize().len();
    if output_len > V1_MAX_AGGREGATION_OUTPUT_BYTES {
        return Err(AggregationError::OutputTooLarge {
            actual: output_len,
            max: V1_MAX_AGGREGATION_OUTPUT_BYTES,
        });
    }
    Ok(aggregate)
}
