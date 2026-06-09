//! ZisK zkVM STARK proof verifier
//!
//! This module implements proof verification for ZisK zkVM using the proofman-verifier.
//!
//! Input format from zisk_common::Proof::get_proof_u64():
//!   [minimal(1)][n_publics(1)][program_vk(4)][publics(64)][proof(...)][zisk_vk(4)]
//!
//! The vk_data parameter is ignored since zisk_vk is embedded in the proof.

use super::{panic_safe, ProofVerifier, VerificationResult};
use proofman_verifier::{verify_vadcop_final_compressed_u64, verify_vadcop_final_u64};
use tracing::debug;

const PROGRAM_VK_LEN: usize = 4;

/// ZisK verifier
pub struct ZiskVerifier;

impl ProofVerifier for ZiskVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting ZisK verification"
            );

            if proof_data.len() % 8 != 0 {
                return Err("proof_data length must be a multiple of 8".into());
            }

            let words: Vec<u64> = proof_data
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
                .collect();

            if words.len() < 2 + PROGRAM_VK_LEN {
                return Err("proof too short".into());
            }

            let minimal = words[0] != 0;
            let zisk_vk_start = words.len() - PROGRAM_VK_LEN;
            let zisk_vk = &words[zisk_vk_start..];
            let blob = &words[1..zisk_vk_start];

            let result = if minimal {
                verify_vadcop_final_compressed_u64(blob, zisk_vk)
            } else {
                verify_vadcop_final_u64(blob, zisk_vk)
            };

            debug!(verification_result = result, "Completed ZisK verification");

            Ok(result)
        })
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

    #[test]
    fn test_zisk_invalid_proof() {
        // Test that verification returns false for invalid proof data
        // This tests error handling without requiring valid proof/VK pairs
        let invalid_proof = vec![0u8; 104];
        let invalid_vk = vec![0u8; 100];

        let result = ZiskVerifier::verify(&invalid_proof, &invalid_vk);

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
