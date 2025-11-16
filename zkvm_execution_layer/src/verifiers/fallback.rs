//! Fallback proof verifier
//!
//! This module implements a pass-through verifier for fallback proofs.
//! Fallback proofs are created when the Ethproofs API fails or times out,
//! and they are used to allow blocks to progress without cryptographic verification.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;

/// Fallback verifier that accepts all proofs without cryptographic verification.
///
/// This verifier is used for fallback proofs created when:
/// - The Ethproofs API times out
/// - The Ethproofs API returns an error
/// - Other proof generation systems are unavailable
///
/// Since fallback proofs are created locally and represent a "best effort" state,
/// they bypass the full cryptographic verification pipeline.
pub struct FallbackVerifier;

impl ProofVerifier for FallbackVerifier {
    fn verify(_proof_data: &[u8], _vk_data: &[u8]) -> VerificationResult {
        debug!("Fallback verifier: accepting proof without cryptographic verification");
        Ok(true)
    }

    fn name() -> &'static str {
        "fallback"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_verifier_name() {
        assert_eq!(FallbackVerifier::name(), "fallback");
    }

    #[test]
    fn test_fallback_verifier_always_accepts() {
        // Fallback verifier should accept any input without verification
        let result = FallbackVerifier::verify(&[], &[]);
        assert_eq!(result, Ok(true));

        // Test with non-empty data
        let proof_data = vec![1, 2, 3, 4, 5];
        let vk_data = vec![6, 7, 8, 9, 10];
        let result = FallbackVerifier::verify(&proof_data, &vk_data);
        assert_eq!(result, Ok(true));
    }
}
