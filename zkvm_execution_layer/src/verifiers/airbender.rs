//! Airbender STARK proof verifier
//!
//! This module implements proof verification for Airbender zkVM using the
//! zksync-airbender unified circuit verifier. Ported from the WASM reference
//! implementation in ethereum-prover/proof_verifier_js/wasm.
//!
//! The circuit setup and layout artifacts are embedded at compile time
//! (matching the WASM verifier approach), so no external VK data is required.

use std::collections::BTreeMap;
use std::io::Read;

use super::{ProofVerifier, VerificationResult, panic_safe};
use airbender_prover::common_constants;
use airbender_prover::common_constants::TimestampScalar;
use airbender_prover::cs::utils::split_timestamp;
use airbender_prover::prover_stages::Proof;
use airbender_prover::prover_stages::unrolled_prover::UnrolledModeProof;
use full_statement_verifier::definitions::{
    OP_VERIFY_UNIFIED_RECURSION_LAYER_IN_UNIFIED_CIRCUIT,
    OP_VERIFY_UNROLLED_RECURSION_LAYER_IN_UNIFIED_CIRCUIT,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::debug;
use verifier_common::cs::one_row_compiler::CompiledCircuitArtifact;
use verifier_common::field::Mersenne31Field;
use verifier_common::proof_flattener;
use verifier_common::prover::definitions::MerkleTreeCap;

const CAP_SIZE: usize = 64;
const NUM_COSETS: usize = 2;

/// Stack size for the verification thread (128 MB).
/// The airbender verifier requires a large stack for recursive proof verification.
const VERIFICATION_THREAD_STACK_SIZE: usize = 1 << 27;

// ---------------------------------------------------------------------------
// Embedded circuit artifacts (from ethereum-prover/artifacts/)
// ---------------------------------------------------------------------------

const DEFAULT_SETUP_BIN: &[u8] =
    include_bytes!("airbender_artifacts/recursion_unified_setup.bin");
const DEFAULT_LAYOUT_BIN: &[u8] =
    include_bytes!("airbender_artifacts/recursion_unified_layouts.bin");

/// Parsed setup and layout, initialized once on first use.
static VERIFIER_CONTEXT: Lazy<Result<VerifierContext, String>> =
    Lazy::new(|| VerifierContext::parse(DEFAULT_SETUP_BIN, DEFAULT_LAYOUT_BIN));

struct VerifierContext {
    setup: UnrolledProgramSetup,
    layout: CompiledCircuitsSet,
}

impl VerifierContext {
    fn parse(setup_bin: &[u8], layout_bin: &[u8]) -> Result<Self, String> {
        let (setup, _): (UnrolledProgramSetup, usize) =
            bincode2::serde::decode_from_slice(setup_bin, bincode2::config::standard())
                .map_err(|e| format!("Failed to parse setup: {}", e))?;

        let (layout, _): (CompiledCircuitsSet, usize) =
            bincode2::serde::decode_from_slice(layout_bin, bincode2::config::standard())
                .map_err(|e| format!("Failed to parse layout: {}", e))?;

        Ok(Self { setup, layout })
    }
}

// ---------------------------------------------------------------------------
// Types mirrored from ethereum-prover/proof_verifier_js/wasm/src/unified_verifier.rs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
struct CompiledCircuitsSet {
    compiled_circuit_families: BTreeMap<u8, CompiledCircuitArtifact<Mersenne31Field>>,
    compiled_inits_and_teardowns: Option<CompiledCircuitArtifact<Mersenne31Field>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct FinalRegisterValue {
    value: u32,
    last_access_timestamp: TimestampScalar,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
struct UnrolledProgramSetup {
    expected_final_pc: u32,
    binary_hash: [u8; 32],
    circuit_families_setups: BTreeMap<u8, [MerkleTreeCap<CAP_SIZE>; NUM_COSETS]>,
    inits_and_teardowns_setup: [MerkleTreeCap<CAP_SIZE>; NUM_COSETS],
    end_params: [u32; 8],
}

impl UnrolledProgramSetup {
    fn flatten_for_recursion(&self) -> Vec<u32> {
        let mut result = vec![];
        for (_, caps) in self.circuit_families_setups.iter() {
            result.extend_from_slice(MerkleTreeCap::flatten(caps));
        }
        result.extend_from_slice(MerkleTreeCap::flatten(&self.inits_and_teardowns_setup));
        result
    }

    fn flatten_unified_for_recursion(&self) -> Vec<u32> {
        assert_eq!(self.circuit_families_setups.len(), 1);
        let mut result = vec![];
        for (_, caps) in self.circuit_families_setups.iter() {
            result.extend_from_slice(MerkleTreeCap::flatten(caps));
        }
        result
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
struct UnrolledProgramProof {
    final_pc: u32,
    final_timestamp: TimestampScalar,
    circuit_families_proofs: BTreeMap<u8, Vec<UnrolledModeProof>>,
    inits_and_teardowns_proofs: Vec<UnrolledModeProof>,
    delegation_proofs: BTreeMap<u32, Vec<Proof>>,
    register_final_values: [FinalRegisterValue; 32],
    recursion_chain_preimage: Option<[u32; 16]>,
    recursion_chain_hash: Option<[u32; 8]>,
}

impl UnrolledProgramProof {
    fn flatten_into_responses(
        &self,
        allowed_delegation_circuits: &[u32],
        compiled_layouts: &CompiledCircuitsSet,
    ) -> Vec<u32> {
        let mut responses = Vec::with_capacity(32 + 32 * 2);

        assert_eq!(self.register_final_values.len(), 32);
        for final_values in self.register_final_values.iter() {
            responses.push(final_values.value);
            let (low, high) = split_timestamp(final_values.last_access_timestamp);
            responses.push(low);
            responses.push(high);
        }

        responses.push(self.final_pc);
        let (low, high) = split_timestamp(self.final_timestamp);
        responses.push(low);
        responses.push(high);

        for (family, proofs) in self.circuit_families_proofs.iter() {
            responses.push(proofs.len() as u32);
            for proof in proofs.iter() {
                let artifact = compiled_layouts
                    .compiled_circuit_families
                    .get(family)
                    .expect("Proof references unknown circuit family");
                let flattened = proof_flattener::flatten_full_unrolled_proof(proof, artifact);
                responses.extend(flattened);
            }
        }

        if let Some(compiled_inits_and_teardowns) =
            compiled_layouts.compiled_inits_and_teardowns.as_ref()
        {
            responses.push(self.inits_and_teardowns_proofs.len() as u32);
            for proof in self.inits_and_teardowns_proofs.iter() {
                let flattened = proof_flattener::flatten_full_unrolled_proof(
                    proof,
                    compiled_inits_and_teardowns,
                );
                responses.extend(flattened);
            }
        } else {
            responses.push(0u32);
        }

        for delegation_type in allowed_delegation_circuits.iter() {
            if *delegation_type == common_constants::NON_DETERMINISM_CSR {
                continue;
            }
            if let Some(proofs) = self.delegation_proofs.get(delegation_type) {
                responses.push(proofs.len() as u32);
                for proof in proofs.iter() {
                    let flattened = proof_flattener::flatten_full_proof(proof, 0);
                    responses.extend(flattened);
                }
            } else {
                responses.push(0);
            }
        }

        if let Some(preimage) = self.recursion_chain_preimage {
            responses.extend(preimage);
        }

        responses
    }
}

// ---------------------------------------------------------------------------
// Proof flattening and verification
// ---------------------------------------------------------------------------

fn flatten_proof_into_responses(
    proof: &UnrolledProgramProof,
    setup: &UnrolledProgramSetup,
    compiled_layouts: &CompiledCircuitsSet,
    input_is_unrolled: bool,
) -> Vec<u32> {
    let mut responses = vec![];

    let op = if input_is_unrolled {
        assert!(setup.circuit_families_setups.len() > 1);
        assert!(!proof.inits_and_teardowns_proofs.is_empty());
        OP_VERIFY_UNROLLED_RECURSION_LAYER_IN_UNIFIED_CIRCUIT
    } else {
        assert_eq!(setup.circuit_families_setups.len(), 1);
        assert!(
            setup
                .circuit_families_setups
                .contains_key(&common_constants::REDUCED_MACHINE_CIRCUIT_FAMILY_IDX)
        );
        assert_eq!(proof.circuit_families_proofs.len(), 1);
        assert!(proof.inits_and_teardowns_proofs.is_empty());
        assert!(
            !proof.circuit_families_proofs[&common_constants::REDUCED_MACHINE_CIRCUIT_FAMILY_IDX]
                .is_empty()
        );
        OP_VERIFY_UNIFIED_RECURSION_LAYER_IN_UNIFIED_CIRCUIT
    };

    responses.push(op);

    if input_is_unrolled {
        responses.extend(setup.flatten_for_recursion());
    } else {
        responses.extend(setup.flatten_unified_for_recursion());
    }

    responses.extend(proof.flatten_into_responses(
        &[common_constants::delegation_types::blake2s_with_control::BLAKE2S_DELEGATION_CSR_REGISTER],
        compiled_layouts,
    ));

    responses
}

fn verify_in_unified_layer(
    proof: &UnrolledProgramProof,
    setup: &UnrolledProgramSetup,
    compiled_layouts: &CompiledCircuitsSet,
    input_is_unrolled: bool,
) -> Result<[u32; 16], String> {
    let responses = flatten_proof_into_responses(proof, setup, compiled_layouts, input_is_unrolled);

    std::thread::Builder::new()
        .name("airbender-verifier".to_string())
        .stack_size(VERIFICATION_THREAD_STACK_SIZE)
        .spawn(move || {
            let it = responses.into_iter();
            airbender_prover::nd_source_std::set_iterator(it);

            full_statement_verifier::unified_circuit_statement::
                verify_unrolled_or_unified_circuit_recursion_layer()
        })
        .map_err(|e| format!("Failed to spawn verifier thread: {}", e))?
        .join()
        .map_err(|_| "Verifier thread panicked".to_string())
}

// ---------------------------------------------------------------------------
// ProofVerifier implementation
// ---------------------------------------------------------------------------

/// Airbender STARK verifier
///
/// Verifies proofs produced by the Airbender zkVM using the zksync-airbender
/// unified circuit verifier. Proof data is expected to be gzip-compressed,
/// bincode v2 serialized `UnrolledProgramProof`.
///
/// The circuit setup and layout are embedded at compile time, so `vk_data` is
/// ignored (pass `&[]`).
pub struct AirbenderVerifier;

impl ProofVerifier for AirbenderVerifier {
    fn verify(proof_data: &[u8], _vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(proof_size = proof_data.len(), "Starting Airbender verification");

            // Get the embedded verifier context (parsed once on first call)
            let ctx = VERIFIER_CONTEXT
                .as_ref()
                .map_err(|e| format!("Failed to initialize verifier context: {}", e))?;

            // Decompress proof data (gzip)
            let mut decoder = flate2::read::GzDecoder::new(proof_data);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("Failed to decompress proof: {}", e))?;

            // Deserialize proof (bincode v2)
            let (proof, _): (UnrolledProgramProof, usize) =
                bincode2::serde::decode_from_slice(&decompressed, bincode2::config::standard())
                    .map_err(|e| format!("Failed to deserialize proof: {}", e))?;

            // Determine if proof is unrolled based on setup structure
            let input_is_unrolled = ctx.setup.circuit_families_setups.len() > 1;

            // Run verification in a dedicated thread with large stack
            match verify_in_unified_layer(&proof, &ctx.setup, &ctx.layout, input_is_unrolled) {
                Ok(_result) => {
                    debug!("Airbender verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = %e, "Airbender verification failed");
                    Ok(false)
                }
            }
        })
    }

    fn name() -> &'static str {
        "airbender"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airbender_verifier_name() {
        assert_eq!(AirbenderVerifier::name(), "airbender");
    }

    #[test]
    fn test_airbender_empty_proof() {
        let result = AirbenderVerifier::verify(&[], &[]);
        // Empty proof will fail at decompression - either Err or Ok(false) is acceptable
        match result {
            Ok(verified) => assert!(!verified, "Empty proof should not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_airbender_invalid_proof() {
        let invalid_proof = vec![0u8; 100];

        let result = AirbenderVerifier::verify(&invalid_proof, &[]);

        // Should not panic - can return either Err or Ok(false) for invalid data
        match result {
            Ok(verified) => assert!(!verified, "Invalid data should not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_embedded_artifacts_parse() {
        // Verify the embedded setup and layout can be parsed successfully
        assert!(
            VERIFIER_CONTEXT.is_ok(),
            "Embedded artifacts should parse: {:?}",
            VERIFIER_CONTEXT.as_ref().err()
        );
    }
}
