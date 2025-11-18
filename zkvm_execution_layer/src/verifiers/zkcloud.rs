//! ZisK-ZkCloud proof verifier
//!
//! This module implements proof verification for ZisK-ZkCloud using ZisK.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;

/// ZisK-ZkCloud verifier (uses ZisK)
pub struct ZkcloudVerifier;

impl ProofVerifier for ZkcloudVerifier {
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

    #[test]
    fn test_zisk_zkcloud_verifier_name() {
        assert_eq!(ZkcloudVerifier::name(), "zisk-zkcloud");
    }
}
