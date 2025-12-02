//! Airbender STARK proof verifier
//!
//! This module implements proof verification for Airbender zkVM.
//! Currently a placeholder implementation - full verification logic will be implemented separately.

use super::{panic_safe, ProofVerifier, VerificationResult};
use tracing::debug;

/// Airbender verifier
///
/// Placeholder implementation for Airbender STARK proof verification.
/// Returns true for any valid proof data.
pub struct AirbenderVerifier;

impl ProofVerifier for AirbenderVerifier {
    fn verify(proof_data: &[u8], _vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                "Starting Airbender verification (placeholder)"
            );

            // Validate proof data is not empty
            if proof_data.is_empty() {
                debug!("Invalid input: proof data is empty");
                return Ok(false);
            }

            // Placeholder: always return true for valid proof data
            // TODO(ethproofs): Implement full verification logic with execution_utils
            debug!("Airbender verification placeholder - returning true");
            Ok(true)
        })
    }

    fn name() -> &'static str {
        "airbender"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airbender_verifier_name() {
        assert_eq!(AirbenderVerifier::name(), "airbender");
    }

    #[test]
    fn test_airbender_empty_proof() {
        // Empty proof data should return false
        let result = AirbenderVerifier::verify(&[], &[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_airbender_valid_proof() {
        // Valid proof data should return true
        let result = AirbenderVerifier::verify(&[1u8; 32], &[]);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
