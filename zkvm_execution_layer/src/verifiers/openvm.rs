//! OpenVM STARK proof verifier
//!
//! This module implements proof verification for OpenVM using the OpenVM verify-stark library.

use super::{panic_safe, ProofVerifier, VerificationResult};
use tracing::debug;
use verify_stark::{verify_vm_stark_proof, vk::VmStarkVerifyingKey};

/// OpenVM verifier
pub struct OpenVmVerifier;

impl ProofVerifier for OpenVmVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting OpenVM verification"
            );

            // Deserialize the verification key from bitcode bytes
            let vk: VmStarkVerifyingKey = match bitcode::deserialize(vk_data) {
                Ok(vk) => vk,
                Err(e) => {
                    debug!(error = ?e, "Failed to deserialize OpenVM verification key");
                    return Ok(false);
                }
            };

            // Verify the proof using the OpenVM verify-stark library
            match verify_vm_stark_proof(&vk, proof_data) {
                Ok(()) => {
                    debug!("OpenVM verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = ?e, "OpenVM verification failed");
                    Ok(false)
                }
            }
        })
    }

    fn name() -> &'static str {
        "openvm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openvm_verifier_name() {
        assert_eq!(OpenVmVerifier::name(), "openvm");
    }

    #[test]
    fn test_openvm_invalid_proof() {
        // Test that verification returns false for invalid proof data
        // This tests error handling without requiring valid proof/VK pairs
        let invalid_proof = vec![0u8; 100];
        let invalid_vk = vec![0u8; 100];

        let result = OpenVmVerifier::verify(&invalid_proof, &invalid_vk);

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
