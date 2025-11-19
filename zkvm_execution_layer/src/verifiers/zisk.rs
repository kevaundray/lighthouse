//! ZisK zkVM STARK proof verifier
//!
//! This module implements proof verification for ZisK zkVM using the proofman-verifier.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;

/// ZisK verifier
pub struct ZiskVerifier;

impl ProofVerifier for ZiskVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        debug!(
            proof_size = proof_data.len(),
            vk_size = vk_data.len(),
            "Starting ZisK verification"
        );

        // Call the proofman-verifier verify function
        let result = proofman_verifier::verify(proof_data, vk_data);

        debug!(verification_result = result, "Completed ZisK verification");

        Ok(result)
    }

    fn name() -> &'static str {
        "zisk"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_zisk_verifier_name() {
        assert_eq!(ZiskVerifier::name(), "zisk");
    }

    #[test]
    fn test_zisk_1_girona_verification() {
        // Load test proof and verification key for ZisK 1 (Girona)
        let test_proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/test_proofs/zisk_817bbf03-07b4-466d-879b-e476322bd080.bin");
        let vk_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/verification_keys/zisk_817bbf03-07b4-466d-879b-e476322bd080.bin");

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = ZiskVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(
            result.is_ok(),
            "ZisK 1 (Girona) verification failed: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "ZisK 1 (Girona) proof verification returned false"
        );
    }

    #[test]
    fn test_zisk_2_sevilla_verification() {
        // Load test proof and verification key for ZisK 2 (Sevilla)
        let test_proof_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/test_proofs/zisk_534e6cf4-3dfe-47de-bba2-a0b11d544557.bin");
        let vk_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/verification_keys/zisk_534e6cf4-3dfe-47de-bba2-a0b11d544557.bin");

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = ZiskVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(
            result.is_ok(),
            "ZisK 2 (Sevilla) verification failed: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "ZisK 2 (Sevilla) proof verification returned false"
        );
    }
}
