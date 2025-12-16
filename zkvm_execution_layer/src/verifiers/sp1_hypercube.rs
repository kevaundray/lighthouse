//! SP1-Hypercube proof verifier
//!
//! This module implements proof verification for SP1-Hypercube zkVM using the sp1-verifier.

use super::{panic_safe, ProofVerifier, VerificationResult};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;
use tracing::debug;

/// SP1-Hypercube verifier
pub struct Sp1HypercubeVerifier;

impl ProofVerifier for Sp1HypercubeVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting SP1-Hypercube verification"
            );

            // Call the sp1-verifier verify function via SP1CompressedVerifierRaw
            // vk_data should be the serialized vkey hash (bincode serialized [SP1Field; 8])
            // Returns Result<(), CompressedError> where Ok(()) means verification succeeded
            match SP1CompressedVerifierRaw::verify(proof_data, vk_data) {
                Ok(()) => {
                    debug!("SP1-Hypercube verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = ?e, "SP1-Hypercube verification failed");
                    Ok(false)
                }
            }
        })
    }

    fn name() -> &'static str {
        "sp1-hypercube"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_hypercube_verifier_name() {
        assert_eq!(Sp1HypercubeVerifier::name(), "sp1-hypercube");
    }

    #[test]
    fn test_sp1_hypercube_invalid_proof() {
        // Test that verification returns false for invalid proof data
        // This tests error handling without requiring valid proof/VK pairs
        let invalid_proof = vec![0u8; 100];
        let invalid_vk = vec![0u8; 100];

        let result = Sp1HypercubeVerifier::verify(&invalid_proof, &invalid_vk);

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
