//! ZisK zkVM STARK proof verifier
//!
//! This module implements proof verification for ZisK zkVM using the proofman-verifier.

use super::{panic_safe, ProofVerifier, VerificationResult};
use tracing::debug;

/// ZisK verifier
pub struct ZiskVerifier;

impl ProofVerifier for ZiskVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting ZisK verification"
            );

            let result =
                proofman_verifier::verify_vadcop_final_compressed_bytes(proof_data, vk_data);

            debug!(verification_result = result, "Completed ZisK verification");

            Ok(result)
        })
    }

    fn name() -> &'static str {
        "zisk"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zisk_verifier_name() {
        assert_eq!(ZiskVerifier::name(), "zisk");
    }

    #[test]
    fn test_zisk_invalid_proof() {
        // Test that verification returns false for invalid proof data
        // This tests error handling without requiring valid proof/VK pairs
        let invalid_proof = vec![0u8; 100];
        let invalid_vk = vec![0u8; 100];

        let result = ZiskVerifier::verify(&invalid_proof, &invalid_vk);

        // Should return Ok(false) for invalid data, not panic
        assert!(
            result.is_ok(),
            "Verification should not error on invalid data"
        );
        assert!(
            !result.unwrap(),
            "Verification should return false for invalid data"
        );
    }
}
