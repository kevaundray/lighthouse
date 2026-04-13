//! OpenVM v2 STARK proof verifier
//!
//! This module implements proof verification for OpenVM v2 using the openvm-verify-stark-host library.

use super::{panic_safe, ProofVerifier, VerificationResult};
use tracing::debug;
use openvm_verify_stark_host::{verify_vm_stark_proof, vk::VmStarkVerifyingKey};

/// OpenVM v2 verifier
pub struct OpenVm2Verifier;

impl ProofVerifier for OpenVm2Verifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting OpenVM v2 verification"
            );

            // Deserialize the verification key from bitcode bytes
            let vk: VmStarkVerifyingKey = match bitcode::deserialize(vk_data) {
                Ok(vk) => vk,
                Err(e) => {
                    debug!(error = ?e, "Failed to deserialize OpenVM v2 verification key");
                    return Ok(false);
                }
            };

            // Verify the proof using the OpenVM v2 verify-stark-host library
            match verify_vm_stark_proof(&vk, proof_data) {
                Ok(()) => {
                    debug!("OpenVM v2 verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = ?e, "OpenVM v2 verification failed");
                    Ok(false)
                }
            }
        })
    }

    fn name() -> &'static str {
        "openvm2"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openvm2_verifier_name() {
        assert_eq!(OpenVm2Verifier::name(), "openvm2");
    }

    #[test]
    fn test_openvm2_invalid_proof() {
        let invalid_proof = vec![0u8; 100];
        let invalid_vk = vec![0u8; 100];

        let result = OpenVm2Verifier::verify(&invalid_proof, &invalid_vk);

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
