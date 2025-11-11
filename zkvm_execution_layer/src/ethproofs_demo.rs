use crate::verification_keys::VerificationKeyStore;
use crate::verifiers::VerifierStore;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use types::ExecutionProof;

/// Trait for validating proofs
pub trait ProofValidator: Send + Sync {
    /// Validate a proof using the verifier store
    fn validate(&self, proof: &ExecutionProof) -> bool;
}

/// Default implementation using the Ethproofs verifier store
pub struct EthproofsValidator;

impl ProofValidator for EthproofsValidator {
    fn validate(&self, proof: &ExecutionProof) -> bool {
        validate_proof(proof)
    }
}

/// Global verification key store, loaded once on first access
pub static VERIFICATION_KEY_STORE: Lazy<Option<VerificationKeyStore>> =
    Lazy::new(|| match VerificationKeyStore::load_embedded() {
        Ok(store) => Some(store),
        Err(e) => {
            warn!(error = %e, "[Ethproofs] Failed to load verification keys");
            None
        }
    });

/// Global verifier store, initialized with default verifiers
pub static VERIFIER_STORE: Lazy<VerifierStore> = Lazy::new(VerifierStore::with_defaults);

/// Represents a proof from the Ethproofs proofs list endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ethproof {
    /// The proof ID from Ethproofs
    pub proof_id: u64,
    /// The cluster ID that generated this proof (matches against available prover_ids)
    pub cluster_id: String,
}

/// Represents the response from the Ethproofs proofs list endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofsListResponse {
    pub proofs: Vec<Ethproof>,
}

/// Fetch a proof for a block from Ethproofs API.
///
/// Polls the endpoint for a single cluster until a proof is found or a timeout is reached,
/// using exponential backoff. This accepts the block hash and a single cluster ID to query.
///
/// Returns the proof for the requested cluster, or an error if not found within the timeout window.
pub async fn fetch_proof_from_ethproofs(
    block_hash: types::ExecutionBlockHash,
    cluster: String,
) -> Result<Vec<Ethproof>, String> {
    const MAX_WAIT_TIME_SECS: u64 = 30;
    const INITIAL_DELAY_MS: u64 = 100;
    const MAX_DELAY_MS: u64 = 5000;

    let client = reqwest::Client::new();
    let url = format!(
        "https://ethproofs.org/api/v0/proofs?block={}&clusters={}",
        block_hash, cluster
    );

    let start = Instant::now();
    let mut delay_ms = INITIAL_DELAY_MS;

    loop {
        // Check if we've exceeded max wait time
        if start.elapsed() > Duration::from_secs(MAX_WAIT_TIME_SECS) {
            debug!(
                block_hash = %block_hash,
                cluster = %cluster,
                "[Ethproofs] Timeout waiting for proof"
            );
            return Err(format!(
                "No proof found for block {} in cluster {} within {} seconds",
                block_hash, cluster, MAX_WAIT_TIME_SECS
            ));
        }

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        match response.status() {
            StatusCode::OK => {
                let response_data: ProofsListResponse = response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

                // Return the first proof found for this cluster
                if !response_data.proofs.is_empty() {
                    return Ok(response_data.proofs);
                }
            }
            StatusCode::NOT_FOUND => {
                // Proof not ready yet, will retry with exponential backoff
            }
            status => {
                return Err(format!(
                    "Request failed with status: {} for block {}",
                    status, block_hash
                ));
            }
        }

        // Wait before retrying
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        // Exponential backoff: double the delay, up to MAX_DELAY_MS
        delay_ms = (delay_ms * 2).min(MAX_DELAY_MS);
    }
}

/// Download a proof binary directly from Ethproofs using the proof_id.
///
/// Returns the binary proof data.
pub async fn download_proof_binary(proof_id: u64) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::new();
    let url = format!("https://ethproofs.org/api/v0/proofs/download/{}", proof_id);

    debug!(proof_id, "[Ethproofs] Downloading proof binary");

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    match response.status() {
        StatusCode::OK => {
            let proof_data = response
                .bytes()
                .await
                .map_err(|e| format!("Failed to read response: {}", e))?;
            Ok(proof_data.to_vec())
        }
        StatusCode::NOT_FOUND => Err(format!("Proof {} not found", proof_id)),
        status => Err(format!(
            "Request failed with status: {} for proof {}",
            status, proof_id
        )),
    }
}

/// Validate a proof using the verifier store
///
/// This function performs cryptographic verification of a proof by:
/// 1. Looking up the verifier for the proof's proof_id
/// 2. Running the cryptographic verification function
/// 3. Returning whether the proof is valid
pub fn validate_proof(proof: &ExecutionProof) -> bool {
    // Check if this is a fallback proof (created when Ethproofs API failed/timed out)
    if proof.proof_id.is_fallback() {
        debug!(
            proof_id = %proof.proof_id,
            "[Ethproofs] Fallback proof detected, skipping verification"
        );
        return true;
    }

    // Get the prover UUID for this proof_id from the hardcoded mapping
    let prover_uuid = match VERIFIER_STORE.get_prover_uuid_for_proof_id(proof.proof_id) {
        Some(uuid) => uuid,
        None => {
            warn!(
                proof_id = %proof.proof_id,
                "[Ethproofs] No prover UUID mapping found for this proof_id"
            );
            return false;
        }
    };

    match &*VERIFICATION_KEY_STORE {
        Some(store) => {
            match store.get(&prover_uuid) {
                Some(vk) => {
                    debug!(
                        prover_id = %prover_uuid,
                        vk_size = vk.size(),
                        proof_size = proof.proof_data.len(),
                        "[Ethproofs] Found vk for prover"
                    );

                    // Look up the verifier for this prover
                    match VERIFIER_STORE.get(&prover_uuid) {
                        Some(verifier_entry) => {
                            debug!(
                                prover_id = %prover_uuid,
                                verifier = verifier_entry.name,
                                "[Ethproofs] Found verifier, starting verification"
                            );

                            // Run the actual cryptographic verification
                            match (verifier_entry.verify_fn)(&proof.proof_data, &vk.vk) {
                                Ok(result) => {
                                    debug!(
                                        prover_id = %prover_uuid,
                                        verification_result = result,
                                        "[Ethproofs] Verification completed"
                                    );
                                    result
                                }
                                Err(e) => {
                                    warn!(
                                        prover_id = %prover_uuid,
                                        error = %e,
                                        "[Ethproofs] Verification failed with error"
                                    );
                                    false
                                }
                            }
                        }
                        None => {
                            warn!(
                                prover_id = %prover_uuid,
                                "[Ethproofs] No verifier registered for this prover, cannot verify proof"
                            );
                            false
                        }
                    }
                }
                None => {
                    warn!(
                        prover_id = %prover_uuid,
                        "[Ethproofs] No verification key found for this prover"
                    );
                    false
                }
            }
        }
        None => {
            warn!("[Ethproofs] Verification key store not initialized");
            false
        }
    }
}
