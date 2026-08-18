//! Consensus-signature operations shared by consensus callers.
//!
//! This crate names validator-signature concepts without exposing backend selection to callers.
//! Its default implementation preserves Lighthouse's BLS wire types and verification behaviour.

mod bls;
mod signing_id;

#[cfg(feature = "pq-devnet")]
pub mod pq;

pub use bls::{
    AggregateSignature, AggregateVerificationRequest, BatchVerificationRequest, Hash256,
    IndividualSignature, RawSignature, RawVerificationRequest, SameMessageEvidence, SigningClaim,
    ValidatorPublicKeyBytes, VerificationKey, VerificationRequest, VerifyError, verify, verify_all,
    verify_batch,
};
pub use signing_id::{
    LEAN_PQ_DEVNET_V1_LEAVES_PER_SLOT, LEAN_PQ_DEVNET_V1_MAX_SLOT, OneTimeUseId, SigningDuty,
    SigningIdError, SyncSubcommittee,
};
