//! OpenVM STARK proof verifier
//!
//! This module implements proof verification for OpenVM using the OpenVM verify-stark library.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;
use verify_stark::{verify_vm_stark_proof, vk::VmStarkVerifyingKey};

/// OpenVM verifier
pub struct OpenvmVerifier;

impl ProofVerifier for OpenvmVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
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
        assert_eq!(OpenvmVerifier::name(), "openvm");
    }

    #[test]
    fn test_openvm_verification() {
        // Load test proof and verification key
        let test_proof_path =
            PathBuf::from("src/test_proofs/openvm_65ddb827-6770-421d-934b-75e8e555faca.bin");
        let vk_path =
            PathBuf::from("src/verification_keys/openvm_425971e7-78eb-4d61-95d9-e9eea62f41da.bin");

        // Skip test if files don't exist
        if !test_proof_path.exists() || !vk_path.exists() {
            eprintln!(
                "Skipping OpenVM test: proof or VK file not found. \
                 Expected: {:?} and {:?}",
                test_proof_path, vk_path
            );
            return;
        }

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = OpenvmVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(result.is_ok(), "OpenVM verification failed: {:?}", result);
        assert!(result.unwrap(), "OpenVM proof verification returned false");
    }
}
