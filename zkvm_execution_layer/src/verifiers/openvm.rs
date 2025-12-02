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
    use std::path::PathBuf;

    #[test]
    fn test_openvm_verifier_name() {
        assert_eq!(OpenVmVerifier::name(), "openvm");
    }

    #[test]
    fn test_openvm_verification() {
        // Load test proof and verification key
        let test_proof_path =
            PathBuf::from("src/test_proofs/openvm_9b6768c0-831d-488c-ba72-05f93975a3be.bin");
        let vk_path =
            PathBuf::from("src/verification_keys/openvm_9b6768c0-831d-488c-ba72-05f93975a3be.bin");

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = OpenVmVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(result.is_ok(), "OpenVM verification failed: {:?}", result);
        assert!(result.unwrap(), "OpenVM proof verification returned false");
    }
}
