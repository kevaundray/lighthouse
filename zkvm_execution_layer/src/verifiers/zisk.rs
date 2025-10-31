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

    #[test]
    fn test_zisk_verifier_name() {
        assert_eq!(ZiskVerifier::name(), "zisk");
    }
}
