//! SP1-Hypercube proof verifier
//!
//! This module implements proof verification for SP1-Hypercube zkVM using the sp1-verifier.

use super::{ProofVerifier, VerificationResult};
use sp1_verifier::compressed::SP1CompressedVerifierRaw;
use tracing::debug;

/// SP1-Hypercube verifier
pub struct Sp1HypercubeVerifier;

impl ProofVerifier for Sp1HypercubeVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
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
    }

    fn name() -> &'static str {
        "sp1-hypercube"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_sp1_hypercube_verifier_name() {
        assert_eq!(Sp1HypercubeVerifier::name(), "sp1-hypercube");
    }

    #[test]
    fn test_sp1_hypercube_verification() {
        // Load test proof and verification key
        let test_proof_path =
            PathBuf::from("src/test_proofs/succinct_9d0bd54d-69f9-4404-8f30-020516a8155d.bin");
        let vk_path = PathBuf::from(
            "src/verification_keys/succinct_9d0bd54d-69f9-4404-8f30-020516a8155d.bin",
        );

        // Skip test if files don't exist
        if !test_proof_path.exists() || !vk_path.exists() {
            eprintln!(
                "Skipping SP1-Hypercube test: proof or VK file not found. \
                 Expected: {:?} and {:?}",
                test_proof_path, vk_path
            );
            return;
        }

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = Sp1HypercubeVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(
            result.is_ok(),
            "SP1-Hypercube verification failed: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "SP1-Hypercube proof verification returned false"
        );
    }
}
