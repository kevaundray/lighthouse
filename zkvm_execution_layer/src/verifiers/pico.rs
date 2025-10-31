//! Pico zkVM STARK proof verifier
//!
//! This module implements proof verification for Pico zkVM using KoalaBear field arithmetic.

use super::{ProofVerifier, VerificationResult};
use pico_vm::{
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{keys::BaseVerifyingKey, machine::MachineBehavior, proof::MetaProof},
    primitives::consts::RECURSION_NUM_PVS,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Serializable wrapper for KoalaBear MetaProof
/// Required because MetaProof contains Rc which isn't directly serializable
#[derive(Serialize, Deserialize)]
struct SerializableKoalaBearMetaProof {
    proofs: Vec<pico_vm::machine::proof::BaseProof<KoalaBearPoseidon2>>,
    vks: Vec<BaseVerifyingKey<KoalaBearPoseidon2>>,
    pv_stream: Option<Vec<u8>>,
}

impl SerializableKoalaBearMetaProof {
    fn to_meta_proof(self) -> MetaProof<KoalaBearPoseidon2> {
        MetaProof::new(self.proofs.into(), self.vks.into(), self.pv_stream)
    }
}

/// Pico verifier using KoalaBear field
pub struct PicoVerifier;

impl ProofVerifier for PicoVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        debug!(
            proof_size = proof_data.len(),
            vk_size = vk_data.len(),
            "Starting Pico verification"
        );

        // Deserialize the KoalaBear proof
        let serializable_proof: SerializableKoalaBearMetaProof =
            bincode::deserialize(proof_data)
                .map_err(|e| format!("Failed to deserialize proof: {}", e))?;
        let proof = serializable_proof.to_meta_proof();

        // Deserialize the KoalaBear verification key
        let riscv_vk: BaseVerifyingKey<KoalaBearPoseidon2> = bincode::deserialize(vk_data)
            .map_err(|e| format!("Failed to deserialize verification key: {}", e))?;

        // Create the machine and run verification
        let machine = CombineMachine::new(
            KoalaBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        let result = machine.verify(&proof, &riscv_vk).is_ok();

        debug!(verification_result = result, "Completed Pico verification");

        Ok(result)
    }

    fn name() -> &'static str {
        "pico"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pico_verifier_name() {
        assert_eq!(PicoVerifier::name(), "pico");
    }

    #[test]
    fn test_pico_verifier_invalid_proof() {
        let invalid_proof = vec![1, 2, 3, 4];
        let invalid_vk = vec![5, 6, 7, 8];

        // Should fail to deserialize
        let result = PicoVerifier::verify(&invalid_proof, &invalid_vk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to deserialize proof"));
    }
}
