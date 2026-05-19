//! OpenVM v2 STARK proof verifier
//!
//! This module implements proof verification for OpenVM v2 using the openvm-verify-stark-host library.

use super::{panic_safe, ProofVerifier, VerificationResult};
use openvm_circuit::system::memory::{merkle::public_values::UserPublicValuesProof, CHUNK};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::{BabyBearPoseidon2Config as SC, F},
    openvm_stark_backend::proof::Proof,
};
use openvm_verify_stark_host::{
    verify_vm_stark_proof_decoded, vk::VmStarkVerifyingKey, VmStarkProof,
};
use tracing::debug;

const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Persisted final-proof wrapper produced by openvm-eth/reth-verify.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StarkProofWithPublicValue<Field> {
    proof: Proof<SC>,
    user_public_values: Option<UserPublicValuesProof<CHUNK, Field>>,
}

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

            let vk: VmStarkVerifyingKey = match bitcode::deserialize(vk_data) {
                Ok(vk) => vk,
                Err(e) => {
                    debug!(error = ?e, "Failed to deserialize OpenVM v2 verification key");
                    return Ok(false);
                }
            };

            let proof = match decode_final_proof(proof_data) {
                Ok(proof) => proof,
                Err(e) => {
                    debug!(error = %e, "Failed to decode OpenVM v2 proof");
                    return Ok(false);
                }
            };

            match verify_vm_stark_proof_decoded(&vk, &proof) {
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

fn decode_final_proof(proof_bytes: &[u8]) -> Result<VmStarkProof, String> {
    let decoded = if proof_bytes.starts_with(&ZSTD_FRAME_MAGIC) {
        zstd::decode_all(proof_bytes)
            .map_err(|e| format!("Failed to zstd-decompress proof: {}", e))?
    } else {
        proof_bytes.to_vec()
    };

    let proof: StarkProofWithPublicValue<F> = bincode::deserialize(&decoded)
        .map_err(|e| format!("Failed to deserialize STARK proof: {}", e))?;

    let user_pvs_proof = proof
        .user_public_values
        .ok_or_else(|| "Proof does not include user public values; not a final STARK proof".to_string())?;

    Ok(VmStarkProof {
        inner: proof.proof,
        user_pvs_proof,
        deferral_merkle_proofs: None,
    })
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
