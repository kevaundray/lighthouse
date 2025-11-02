use crate::verification_keys::VerificationKeyStore;
use crate::verifiers::VerifierStore;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use types::ExecutionProof;

/// Global verification key store, loaded once on first access
pub static VERIFICATION_KEY_STORE: Lazy<Option<VerificationKeyStore>> =
    Lazy::new(|| match VerificationKeyStore::load_embedded() {
        Ok(store) => {
            debug!(
                key_count = store.len(),
                prover_ids = ?store.prover_ids(),
                "[Ethproofs] Loaded verification keys"
            );
            Some(store)
        }
        Err(e) => {
            warn!(error = %e, "[Ethproofs] Failed to load verification keys");
            None
        }
    });

/// Global verifier store, initialized with default verifiers
pub static VERIFIER_STORE: Lazy<VerifierStore> = Lazy::new(|| {
    let store = VerifierStore::with_defaults();
    debug!(
        verifier_count = store.len(),
        "[Ethproofs] Initialized verifier store"
    );
    store
});

/// Select a random prover_id from available registered verifiers
pub fn select_random_prover_id() -> [u8; 16] {
    use rand::Rng;

    let available_provers = VERIFIER_STORE.prover_ids();

    if available_provers.is_empty() {
        warn!("[Ethproofs] No verifiers registered, cannot select prover_id");
        return [0u8; 16];
    }

    let mut rng = rand::rng();
    let random_index = rng.random_range(0..available_provers.len());
    let selected_uuid = available_provers[random_index];

    debug!(
        prover_id = %selected_uuid,
        available_count = available_provers.len(),
        "[Ethproofs] Randomly selected prover_id"
    );

    *selected_uuid.as_bytes()
}

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
    const MAX_WAIT_TIME_SECS: u64 = 15;
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

        debug!(
            block_hash = %block_hash,
            cluster = %cluster,
            delay_ms,
            "[Ethproofs] Polling Ethproofs for proof"
        );

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
                    debug!(
                        block_hash = %block_hash,
                        cluster = %cluster,
                        proof_count = response_data.proofs.len(),
                        "[Ethproofs] Found proof"
                    );
                    return Ok(response_data.proofs);
                }
            }
            StatusCode::NOT_FOUND => {
                debug!(
                    block_hash = %block_hash,
                    cluster = %cluster,
                    "[Ethproofs] Block not found, retrying..."
                );
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

            debug!(
                proof_id,
                size_bytes = proof_data.len(),
                "[Ethproofs] Successfully downloaded proof binary"
            );

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
                        "[Ethproofs] Found verification key for prover"
                    );

                    // Look up the verifier for this prover
                    match VERIFIER_STORE.get(&prover_uuid) {
                        Some(verifier_entry) => {
                            debug!(
                                prover_id = %prover_uuid,
                                verifier = verifier_entry.name,
                                "[Ethproofs] Found verifier, running cryptographic verification"
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
