//! Airbender STARK proof verifier (legacy 80-bit security)
//!
//! Verifies proofs produced by older Airbender zkVM deployments at 80-bit
//! security. The verification key uses the legacy split-format with a 4-byte
//! big-endian length prefix separating setup and layout sections:
//!   `[setup_len (4 BE bytes)][setup bytes][layout bytes]`
//!
//! When `vk_data` is empty, compile-time-embedded artifacts under
//! `airbender_artifacts/` are used.
//!
//! Shared serialization types and the verification driver live in
//! `super::airbender`. New integrations should use the 100-bit
//! `AirbenderVerifier` instead.

use std::io::Read;

use super::airbender::{VerifierContext, verify_in_unified_layer};
use super::{ProofVerifier, VerificationResult, panic_safe};
use once_cell::sync::Lazy;
use tracing::debug;
use verifier_common::SecurityModel;

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

/// Parse VK bytes with a 4-byte big-endian length prefix into setup and layout slices.
fn parse_vk_data(vk_data: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if vk_data.len() < 4 {
        return Err("vk_data too short to contain length prefix".to_string());
    }
    let setup_len = u32::from_be_bytes(
        vk_data[..4]
            .try_into()
            .map_err(|_| "Failed to read setup length prefix".to_string())?,
    ) as usize;
    if vk_data.len() < 4 + setup_len {
        return Err(format!(
            "vk_data setup length ({}) exceeds remaining buffer ({})",
            setup_len,
            vk_data.len() - 4
        ));
    }
    let setup = &vk_data[4..4 + setup_len];
    let layout = &vk_data[4 + setup_len..];
    Ok((setup, layout))
}

/// Airbender STARK verifier (legacy 80-bit security)
///
/// If `vk_data` is non-empty, it is expected to contain a 4-byte big-endian
/// length prefix followed by setup and layout bytes:
/// `[setup_len (4 BE bytes)][setup bytes][layout bytes]`.
/// If `vk_data` is empty, the embedded compile-time artifacts are used.
pub struct Airbender80Verifier;

impl ProofVerifier for Airbender80Verifier {
    fn verify(proof_data: &[u8], vk_data: &[u8]) -> VerificationResult {
        panic_safe::safe_verify(|| {
            debug!(
                proof_size = proof_data.len(),
                vk_size = vk_data.len(),
                "Starting Airbender (80-bit) verification"
            );

            // Parse or use embedded verifier context
            let custom_ctx;
            let ctx = if vk_data.is_empty() {
                VERIFIER_CONTEXT
                    .as_ref()
                    .map_err(|e| format!("Failed to initialize verifier context: {}", e))?
            } else {
                let (setup_bytes, layout_bytes) = parse_vk_data(vk_data)?;
                custom_ctx = VerifierContext::parse(setup_bytes, layout_bytes)?;
                &custom_ctx
            };

            // Decompress proof data (gzip)
            let mut decoder = flate2::read::GzDecoder::new(proof_data);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| format!("Failed to decompress proof: {}", e))?;

            // Deserialize proof (legacy: bare bincode, no envelope)
            let (proof, _): (super::airbender::UnrolledProgramProof, usize) =
                bincode2::serde::decode_from_slice(&decompressed, bincode2::config::standard())
                    .map_err(|e| format!("Failed to deserialize proof: {}", e))?;

            let input_is_unrolled = ctx.setup.circuit_families_setups.len() > 1;

            match verify_in_unified_layer(
                &proof,
                &ctx.setup,
                &ctx.layout,
                SecurityModel::Security80,
                input_is_unrolled,
            ) {
                Ok(_result) => {
                    debug!("Airbender (80-bit) verification succeeded");
                    Ok(true)
                }
                Err(e) => {
                    debug!(error = %e, "Airbender (80-bit) verification failed");
                    Ok(false)
                }
            }
        })
    }

    fn name() -> &'static str {
        "airbender-80"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_airbender_80_verifier_name() {
        assert_eq!(Airbender80Verifier::name(), "airbender-80");
    }

    #[test]
    fn test_airbender_80_empty_proof() {
        let result = Airbender80Verifier::verify(&[], &[]);
        match result {
            Ok(verified) => assert!(!verified, "Empty proof should not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_airbender_80_invalid_proof() {
        let invalid_proof = vec![0u8; 100];
        let result = Airbender80Verifier::verify(&invalid_proof, &[]);
        match result {
            Ok(verified) => assert!(!verified, "Invalid data should not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_embedded_artifacts_parse() {
        assert!(
            VERIFIER_CONTEXT.is_ok(),
            "Embedded artifacts should parse: {:?}",
            VERIFIER_CONTEXT.as_ref().err()
        );
    }

    #[test]
    fn test_parse_vk_data_valid() {
        // 3-byte setup, 2-byte layout
        let mut vk = vec![0, 0, 0, 3];
        vk.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        vk.extend_from_slice(&[0xDD, 0xEE]);

        let (setup, layout) = parse_vk_data(&vk).unwrap();
        assert_eq!(setup, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(layout, &[0xDD, 0xEE]);
    }

    #[test]
    fn test_parse_vk_data_too_short() {
        assert!(parse_vk_data(&[0, 0]).is_err());
    }

    #[test]
    fn test_parse_vk_data_setup_len_exceeds_buffer() {
        let vk = vec![0, 0, 0, 10, 0xAA, 0xBB];
        assert!(parse_vk_data(&vk).is_err());
    }

    #[test]
    fn test_parse_vk_data_empty_layout() {
        let mut vk = vec![0, 0, 0, 2];
        vk.extend_from_slice(&[0xAA, 0xBB]);

        let (setup, layout) = parse_vk_data(&vk).unwrap();
        assert_eq!(setup, &[0xAA, 0xBB]);
        assert!(layout.is_empty());
    }

    #[test]
    fn test_verify_with_empty_vk_uses_defaults() {
        let result = Airbender80Verifier::verify(&[], &[]);
        match result {
            Ok(verified) => assert!(!verified, "Empty proof should not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_verify_with_invalid_vk_prefix() {
        let result = Airbender80Verifier::verify(&[], &[0, 0]);
        assert!(result.is_err() || result == Ok(false));
    }
}
