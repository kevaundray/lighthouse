//! ZkCloud proof verifier
//!
//! This module implements proof verification for ZkCloud using ZisK.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;

/// ZkCloud verifier (uses ZisK)
pub struct ZkcloudVerifier;

impl ProofVerifier for ZkcloudVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        debug!(
            proof_size = proof_data.len(),
            vk_size = vk_data.len(),
            "Starting ZkCloud verification"
        );

        // Delegate to ZisK verifier implementation
        let result = super::zisk::ZiskVerifier::verify(proof_data, vk_data)?;

        debug!(
            verification_result = result,
            "Completed ZkCloud verification"
        );

        Ok(result)
    }

    fn name() -> &'static str {
        "zkcloud"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkcloud_verifier_name() {
        assert_eq!(ZkcloudVerifier::name(), "zkcloud");
    }
}
