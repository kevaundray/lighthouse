//! Consensus-signature operations shared by consensus callers.
//!
//! This crate names validator-signature concepts without exposing backend selection to callers.
//! Its default implementation preserves Lighthouse's BLS wire types and verification behaviour.

mod bls;

pub use bls::{
    AggregateSignature, AggregateVerificationRequest, BatchVerificationRequest, Hash256,
    RawSignature, RawVerificationRequest, SigningClaim, ValidatorPublicKeyBytes, VerificationKey,
    VerificationRequest, VerifyError, verify, verify_all, verify_batch,
};
