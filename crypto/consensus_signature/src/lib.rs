//! Consensus-signature operations shared by consensus callers.
//!
//! This crate names validator-signature concepts without exposing backend selection to callers.
//! Its default implementation preserves Lighthouse's BLS wire types and verification behaviour.

mod bls;

#[cfg(feature = "pq-devnet")]
pub mod pq;

pub use bls::{
    AggregateSignature, AggregateVerificationRequest, BatchVerificationRequest, Hash256,
    IndividualSignature, RawSignature, RawVerificationRequest, SameMessageEvidence, SigningClaim,
    ValidatorPublicKeyBytes, VerificationKey, VerificationRequest, VerifyError, verify, verify_all,
    verify_batch,
};
