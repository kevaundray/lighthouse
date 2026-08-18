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
    IndividualSignature, RawSignature, RawVerificationRequest, SameMessageEvidence, SigningClaim,
    ValidatorPublicKeyBytes, VerificationKey, VerificationRequest, VerifyError, verify, verify_all,
    verify_batch,
};
#[cfg(feature = "pq-wire")]
pub use pq_wire::{
    PQ_MAX_SAME_MESSAGE_EVIDENCE_LEN, PQ_PUBLIC_KEY_LEN, PQ_RAW_SIGNATURE_LEN, PqPublicKey,
    PqRawSignature, PqSameMessageEvidence, PqWireError,
};
#[cfg(feature = "pq-wire")]
pub type ValidatorPublicKeyBytes = PqPublicKey;
#[cfg(feature = "pq-wire")]
pub type VerificationKey = PqPublicKey;
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
