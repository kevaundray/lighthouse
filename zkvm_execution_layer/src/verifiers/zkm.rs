//! ZKM (Ziren) zkVM STARK proof verifier
//!
//! This module implements proof verification for ZKM zkVM using the zkm-verifier.

use super::{ProofVerifier, VerificationResult};
use tracing::debug;
use zkm_verifier::StarkVerifier;

/// ZKM verifier
pub struct ZkmVerifier;

impl ProofVerifier for ZkmVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        debug!(
            proof_size = proof_data.len(),
            vk_size = vk_data.len(),
            "Starting ZKM verification"
        );

        // Call the zkm_verifier StarkVerifier::verify_proof function
        let result = StarkVerifier::verify_proof(proof_data, vk_data).is_ok();

        debug!(verification_result = result, "Completed ZKM verification");

        Ok(result)
    }

    fn name() -> &'static str {
        "zkm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkm_verifier_name() {
        assert_eq!(ZkmVerifier::name(), "zkm");
    }
}
