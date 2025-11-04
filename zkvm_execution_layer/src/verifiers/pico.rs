//! Pico Prism zkVM STARK proof verifier
//!
//! This module implements proof verification for Pico Prism zkVM using KoalaBear field arithmetic.

use super::{ProofVerifier, VerificationResult};
use pico_prism_vm::{
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::KoalaBearPoseidon2,
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::{BaseProof, MetaProof},
    },
    primitives::consts::RECURSION_NUM_PVS,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

// Serializable wrappers for MetaProof
#[derive(Serialize, Deserialize)]
struct SerializableKoalaBearMetaProof {
    proofs: Vec<BaseProof<KoalaBearPoseidon2>>,
    vks: Vec<BaseVerifyingKey<KoalaBearPoseidon2>>,
    pv_stream: Option<Vec<u8>>,
}

impl SerializableKoalaBearMetaProof {
    fn to_meta_proof(self) -> MetaProof<KoalaBearPoseidon2> {
        MetaProof::new(self.proofs.into(), self.vks.into(), self.pv_stream)
    }
}

struct KoalaBearCombineVerifier {
    machine: CombineMachine<KoalaBearPoseidon2, RecursionChipType<Val<KoalaBearPoseidon2>>>,
}

impl KoalaBearCombineVerifier {
    fn new() -> Self {
        let machine = CombineMachine::new(
            KoalaBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        Self { machine }
    }

    fn verify(
        &self,
        proof: &MetaProof<KoalaBearPoseidon2>,
        riscv_vk: &BaseVerifyingKey<KoalaBearPoseidon2>,
    ) -> bool {
        self.machine.verify(proof, riscv_vk).is_ok()
    }
}

/// Pico Prism verifier using KoalaBear field
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

        // Deserialize KoalaBear verification key
        let riscv_vk: BaseVerifyingKey<KoalaBearPoseidon2> = bincode::deserialize(vk_data)
            .map_err(|e| format!("Failed to deserialize verification key: {}", e))?;

        // Create and run verifier
        let verifier = KoalaBearCombineVerifier::new();
        let result = verifier.verify(&proof, &riscv_vk);

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
}
