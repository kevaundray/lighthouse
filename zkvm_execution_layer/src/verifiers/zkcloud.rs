//! ZisK-ZkCloud proof verifier
//!
//! This module implements proof verification for ZisK-ZkCloud using ZisK.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;

/// ZisK-ZkCloud verifier (uses ZisK)
pub struct ZkCloudVerifier;

impl ProofVerifier for ZkCloudVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        debug!(
            proof_size = proof_data.len(),
            vk_size = vk_data.len(),
            "Starting ZisK-ZkCloud verification"
        );

        // Delegate to ZisK verifier implementation
        let result = super::zisk::ZiskVerifier::verify(proof_data, vk_data)?;

        debug!(
            verification_result = result,
            "Completed ZisK-ZkCloud verification"
        );

        Ok(result)
    }

    fn name() -> &'static str {
        "zisk-zkcloud"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_zisk_zkcloud_verifier_name() {
        assert_eq!(ZkCloudVerifier::name(), "zisk-zkcloud");
    }

    #[test]
    fn test_zisk_zkcloud_verification() {
        // Load test proof and verification key
        let test_proof_path =
            PathBuf::from("src/test_proofs/zisk_zkcloud_884fcc21-d522-4b4a-b535-7cfde199485c.bin");
        let vk_path = PathBuf::from(
            "src/verification_keys/zisk_zkcloud_884fcc21-d522-4b4a-b535-7cfde199485c.bin",
        );

        let proof_data = std::fs::read(&test_proof_path).expect("Failed to read test proof file");
        let vk_data = std::fs::read(&vk_path).expect("Failed to read verification key file");

        // Verify the proof
        let result = ZkCloudVerifier::verify(&proof_data, &vk_data);

        // The test should succeed
        assert!(
            result.is_ok(),
            "ZisK-ZkCloud verification failed: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "ZisK-ZkCloud proof verification returned false"
        );
    }
}
