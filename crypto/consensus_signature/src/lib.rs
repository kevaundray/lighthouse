//! Consensus-signature operations shared by consensus callers.
//!
//! This crate names validator-signature concepts without exposing backend selection to callers.
//! Its default implementation preserves Lighthouse's BLS wire types and verification behaviour.

#[cfg(any(not(feature = "pq-wire"), feature = "pq-devnet"))]
mod aggregation;
#[cfg(not(feature = "pq-wire"))]
mod bls;
mod signing_id;

#[cfg(feature = "pq-wire")]
mod pq_wire;

#[cfg(feature = "pq-devnet")]
pub mod pq;

#[cfg(not(feature = "pq-wire"))]
pub use bls::{
    AggregateSignature, AggregateVerificationRequest, BatchVerificationRequest, Hash256,
    IndividualSignature, RawSignature, RawVerificationRequest, SameMessageEvidence,
    SerializedIndividualSignature, SigningClaim, ValidatorPublicKeyBytes, VerificationKey,
    VerificationRequest, VerifyError, decode_individual_signature,
    is_verification_skip_placeholder, serialize_individual_signature, verify, verify_all,
    verify_batch,
};
#[cfg(feature = "pq-wire")]
pub use pq_wire::{
    PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_PUBLIC_KEY_LEN, PQ_RAW_SIGNATURE_LEN, PqPublicKey,
    PqRawSignature, PqSameMessageEvidence, PqWireError, SerializedIndividualSignature,
    decode_individual_signature, is_verification_skip_placeholder, serialize_individual_signature,
};
#[cfg(feature = "pq-wire")]
pub type ValidatorPublicKeyBytes = PqPublicKey;
#[cfg(feature = "pq-wire")]
pub type VerificationKey = PqPublicKey;
#[cfg(feature = "pq-devnet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqValidatorRegistryEntry {
    validator_index: u64,
    public_key: PqPublicKey,
    withdrawal_credentials: [u8; 32],
}

#[cfg(feature = "pq-devnet")]
impl PqValidatorRegistryEntry {
    pub const fn new(
        validator_index: u64,
        public_key: PqPublicKey,
        withdrawal_credentials: [u8; 32],
    ) -> Self {
        Self {
            validator_index,
            public_key,
            withdrawal_credentials,
        }
    }

    pub const fn validator_index(&self) -> u64 {
        self.validator_index
    }

    pub const fn public_key(&self) -> PqPublicKey {
        self.public_key
    }

    pub const fn withdrawal_credentials(&self) -> [u8; 32] {
        self.withdrawal_credentials
    }
}
#[cfg(feature = "pq-wire")]
pub type IndividualSignature = PqRawSignature;
#[cfg(feature = "pq-wire")]
pub type RawSignature = PqRawSignature;
#[cfg(feature = "pq-wire")]
pub type SameMessageEvidence = PqSameMessageEvidence;
#[cfg(feature = "pq-wire")]
pub type AggregateSignature = PqSameMessageEvidence;
#[cfg(any(not(feature = "pq-wire"), feature = "pq-devnet"))]
pub use aggregation::{
    AggregationContribution, AggregationError, AggregationJob, AggregationResource,
    AggregationService, AggregationSigner, InvalidAggregationJob, SameMessageClaim,
    V1_MAX_AGGREGATION_CONTRIBUTIONS, V1_MAX_AGGREGATION_INPUT_BYTES,
    V1_MAX_AGGREGATION_OUTPUT_BYTES, V1_MAX_AGGREGATION_SIGNERS, VerificationClass,
    is_individual_same_message_evidence,
};
pub use signing_id::{
    LEAN_PQ_DEVNET_V1_LEAVES_PER_SLOT, LEAN_PQ_DEVNET_V1_MAX_SLOT, OneTimeUseId, SigningDuty,
    SigningIdError, SyncSubcommittee,
};

/// Failure to decode the HTTP transport form of an individual consensus signature.
///
/// This error deliberately does not expose backend-library error details so API behavior remains
/// stable when the compile-time consensus-signature backend changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndividualSignatureTransportError {
    /// The serialized value is not a valid individual signature for the active backend.
    InvalidEncoding,
}

impl std::fmt::Display for IndividualSignatureTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid individual signature encoding")
    }
}

impl std::error::Error for IndividualSignatureTransportError {}
