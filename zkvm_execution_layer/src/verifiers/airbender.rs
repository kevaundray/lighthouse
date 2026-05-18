//! Airbender STARK proof verifier (100-bit security)
//!
//! This module implements 100-bit proof verification for the Airbender zkVM,
//! using the zksync-airbender unified circuit verifier. Ported from the
//! reference implementation in ethereum-prover/proof_verifier_js/wasm.
//!
//! The verification key is a single-file envelope (magic `EVKEY001`) that
//! carries its security level explicitly. The proof is a gzip-compressed,
//! bincode-encoded envelope (magic `EPROOF01`) that also carries its
//! security level. Both `proof_data` and `vk_data` are required — no
//! embedded defaults are used.
//!
//! Shared types (`UnrolledProgramSetup`, `UnrolledProgramProof`,
//! `CompiledCircuitsSet`) and the underlying verification routine are
//! defined here and reused by the 80-bit verifier in `airbender_80.rs`.

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
use serde::{Deserialize, Serialize};
use tracing::debug;
use verifier_common::SecurityModel;
use verifier_common::cs::one_row_compiler::CompiledCircuitArtifact;
use verifier_common::field::Mersenne31Field;
use verifier_common::proof_flattener;
use verifier_common::prover::definitions::MerkleTreeCap;

pub(super) const CAP_SIZE: usize = 64;
pub(super) const NUM_COSETS: usize = 2;

/// Stack size for the verification thread (128 MB).
/// The airbender verifier requires a large stack for recursive proof verification.
pub(super) const VERIFICATION_THREAD_STACK_SIZE: usize = 1 << 27;

// ---------------------------------------------------------------------------
// Shared types mirrored from ethereum-prover/proof_verifier_js/wasm
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub(super) struct CompiledCircuitsSet {
    pub(super) compiled_circuit_families: BTreeMap<u8, CompiledCircuitArtifact<Mersenne31Field>>,
    pub(super) compiled_inits_and_teardowns: Option<CompiledCircuitArtifact<Mersenne31Field>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(super) struct FinalRegisterValue {
    pub(super) value: u32,
    pub(super) last_access_timestamp: TimestampScalar,
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub(super) struct UnrolledProgramSetup {
    pub(super) expected_final_pc: u32,
    pub(super) binary_hash: [u8; 32],
    pub(super) circuit_families_setups: BTreeMap<u8, [MerkleTreeCap<CAP_SIZE>; NUM_COSETS]>,
    pub(super) inits_and_teardowns_setup: [MerkleTreeCap<CAP_SIZE>; NUM_COSETS],
    pub(super) end_params: [u32; 8],
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
pub(super) struct UnrolledProgramProof {
    pub(super) final_pc: u32,
    pub(super) final_timestamp: TimestampScalar,
    pub(super) circuit_families_proofs: BTreeMap<u8, Vec<UnrolledModeProof>>,
    pub(super) inits_and_teardowns_proofs: Vec<UnrolledModeProof>,
    pub(super) delegation_proofs: BTreeMap<u32, Vec<Proof>>,
    pub(super) register_final_values: [FinalRegisterValue; 32],
    pub(super) recursion_chain_preimage: Option<[u32; 16]>,
    pub(super) recursion_chain_hash: Option<[u32; 8]>,
    pub(super) pow_challenge: u64,
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

        let pow_challenge_low = self.pow_challenge as u32;
        let pow_challenge_high = (self.pow_challenge >> 32) as u32;
        responses.push(pow_challenge_low);
        responses.push(pow_challenge_high);

        if let Some(preimage) = self.recursion_chain_preimage {
            responses.extend(preimage);
        }

        responses
    }
}

// ---------------------------------------------------------------------------
// Shared verifier context and verification driver
// ---------------------------------------------------------------------------

pub(super) struct VerifierContext {
    pub(super) setup: UnrolledProgramSetup,
    pub(super) layout: CompiledCircuitsSet,
}

impl VerifierContext {
    pub(super) fn parse(setup_bin: &[u8], layout_bin: &[u8]) -> Result<Self, String> {
        let (setup, _): (UnrolledProgramSetup, usize) =
            bincode2::serde::decode_from_slice(setup_bin, bincode2::config::standard())
                .map_err(|e| format!("Failed to parse setup: {}", e))?;

        let (layout, _): (CompiledCircuitsSet, usize) =
            bincode2::serde::decode_from_slice(layout_bin, bincode2::config::standard())
                .map_err(|e| format!("Failed to parse layout: {}", e))?;

        Ok(Self { setup, layout })
    }
}

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

pub(super) fn verify_in_unified_layer(
    proof: &UnrolledProgramProof,
    setup: &UnrolledProgramSetup,
    compiled_layouts: &CompiledCircuitsSet,
    security: SecurityModel,
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
                verify_unrolled_or_unified_circuit_recursion_layer(security)
        })
        .map_err(|e| format!("Failed to spawn verifier thread: {}", e))?
        .join()
        .map_err(|_| "Verifier thread panicked".to_string())
}

// ---------------------------------------------------------------------------
// 100-bit envelope formats (single-file VK and tagged proof)
// ---------------------------------------------------------------------------

const VERIFICATION_KEY_MAGIC: [u8; 8] = *b"EVKEY001";
const VERIFICATION_KEY_FORMAT_VERSION: u8 = 1;
const PROOF_MAGIC: [u8; 8] = *b"EPROOF01";
const PROOF_FORMAT_VERSION: u8 = 1;
const SECURITY_LEVEL_WIRE_100: u8 = 100;

#[derive(Debug, Serialize, Deserialize)]
struct EncodedVerificationKey {
    magic: [u8; 8],
    version: u8,
    security: u8,
    setup: UnrolledProgramSetup,
    layouts: CompiledCircuitsSet,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncodedProof {
    magic: [u8; 8],
    version: u8,
    security: u8,
    proof: UnrolledProgramProof,
}

fn decode_exact<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, String> {
    let (value, bytes_read): (T, usize) =
        bincode2::serde::decode_from_slice(bytes, bincode2::config::standard())
            .map_err(|e| format!("failed to parse {what}: {e}"))?;

    if bytes_read != bytes.len() {
        return Err(format!(
            "failed to parse {what}: trailing {} byte(s) indicate an incompatible format",
            bytes.len() - bytes_read
        ));
    }

    Ok(value)
}

fn decode_verification_key(bytes: &[u8]) -> Result<VerifierContext, String> {
    if !bytes.starts_with(&VERIFICATION_KEY_MAGIC) {
        return Err("verification key magic does not match expected value".to_string());
    }

    let encoded = decode_exact::<EncodedVerificationKey>(bytes, "verification key")?;
    if encoded.version != VERIFICATION_KEY_FORMAT_VERSION {
        return Err(format!(
            "unsupported verification key version {}",
            encoded.version
        ));
    }
    if encoded.security != SECURITY_LEVEL_WIRE_100 {
        return Err(format!(
            "airbender verifier requires 100-bit verification key, got {}-bit",
            encoded.security
        ));
    }

    Ok(VerifierContext {
        setup: encoded.setup,
        layout: encoded.layouts,
    })
}

fn decode_proof_envelope(bytes: &[u8]) -> Result<UnrolledProgramProof, String> {
    if !bytes.starts_with(&PROOF_MAGIC) {
        return Err("proof envelope magic does not match expected value".to_string());
    }

    let encoded = decode_exact::<EncodedProof>(bytes, "proof envelope")?;
    if encoded.version != PROOF_FORMAT_VERSION {
        return Err(format!(
            "unsupported proof envelope version {}",
            encoded.version
        ));
    }
    if encoded.security != SECURITY_LEVEL_WIRE_100 {
        return Err(format!(
            "airbender verifier requires 100-bit proof, got {}-bit",
            encoded.security
        ));
    }

    Ok(encoded.proof)
}

// ---------------------------------------------------------------------------
// ProofVerifier implementation (100-bit)
// ---------------------------------------------------------------------------

/// Airbender STARK verifier (100-bit security)
///
/// Verifies proofs produced by the Airbender zkVM at 100-bit security using
/// the zksync-airbender unified circuit verifier.
///
/// - `proof_data` must be gzip-compressed bytes of an `EPROOF01` envelope.
/// - `vk_data` must be the raw bytes of an `EVKEY001` envelope.
///
/// Both inputs are required; there are no embedded defaults.
pub struct AirbenderVerifier;

impl ProofVerifier for AirbenderVerifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting Airbender (100-bit) verification"
            );

            if vk_data.is_empty() {
                return Err("airbender verifier requires non-empty vk_data".to_string());
            }

            let ctx = decode_verification_key(vk_data)?;

            let mut decoder = flate2::read::GzDecoder::new(proof_data);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("Failed to decompress proof: {}", e))?;

            let proof = decode_proof_envelope(&decompressed)?;

            let input_is_unrolled = ctx.setup.circuit_families_setups.len() > 1;

            match verify_in_unified_layer(
                &proof,
                &ctx.setup,
                &ctx.layout,
                SecurityModel::Security100,
                input_is_unrolled,
            ) {
                Ok(_result) => {
                    debug!("Airbender (100-bit) verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = %e, "Airbender (100-bit) verification failed");
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
    fn test_airbender_requires_vk() {
        // Empty vk_data must be rejected — no embedded defaults for 100-bit.
        let result = AirbenderVerifier::verify(&[], &[]);
        assert!(
            result.is_err(),
            "100-bit verifier must reject empty vk_data, got {:?}",
            result
        );
    }

    #[test]
    fn test_airbender_rejects_invalid_vk_magic() {
        // Random bytes without EVKEY001 magic should be rejected.
        let vk = vec![0u8; 64];
        let result = AirbenderVerifier::verify(&[], &vk);
        assert!(
            result.is_err(),
            "verifier must reject vk with invalid magic, got {:?}",
            result
        );
    }

    #[test]
    fn test_airbender_invalid_proof_with_valid_vk_magic() {
        // VK starts with magic but is otherwise garbage — should error on parse.
        let mut vk = VERIFICATION_KEY_MAGIC.to_vec();
        vk.extend_from_slice(&[0u8; 32]);
        let result = AirbenderVerifier::verify(&[0u8; 100], &vk);
        match result {
            Ok(verified) => assert!(!verified, "Invalid data should not verify"),
            Err(_) => {}
        }
    }
}
