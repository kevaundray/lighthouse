use crate::active_provers_loader;
use crate::ethproofs_prover_registry::EthproofsProverRegistry;
use crate::verification_keys::ExecutionProofVerificationKey;
use crate::verifiers::VerifierStore;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
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

/// Global prover registry for dynamic proof type mapping
pub static PROVER_REGISTRY: Lazy<Arc<RwLock<EthproofsProverRegistry>>> =
    Lazy::new(|| Arc::new(RwLock::new(EthproofsProverRegistry::new())));

/// Global dynamic verification keys, keyed by proof_id
pub static DYNAMIC_VK_STORE: Lazy<Arc<RwLock<HashMap<u8, ExecutionProofVerificationKey>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Global verifier store, initialized with verifiers registered by zkvm_slug
pub static VERIFIER_STORE: Lazy<VerifierStore> = Lazy::new(|| {
    let mut store = VerifierStore::new();
    // Register verifiers by zkvm_slug for dynamic prover loading
    store.register_all_by_slug();
    store
});

/// Load active provers from the Ethproofs API during initialization.
///
/// This should be called during beacon node startup to populate the prover registry.
///
/// Returns Ok(()) if successful, or logs a warning if loading fails.
pub async fn initialize_ethproofs_provers() -> Result<(), String> {
    info!("[Ethproofs] Initializing active provers from API");

    // Load active provers from API (verification keys endpoint is public)
    match active_provers_loader::load_active_provers().await {
        Ok((registry, vk_store)) => {
            // Update the global registry and VK store
            {
                let mut reg = PROVER_REGISTRY.write().await;
                *reg = registry;
            }

            {
                let mut vks = DYNAMIC_VK_STORE.write().await;
                *vks = vk_store;
            }

            info!("[Ethproofs] Successfully initialized active provers from API");
            Ok(())
        }
        Err(e) => {
            warn!("[Ethproofs] Failed to load active provers: {}", e);
            // Return error so caller can decide how to handle it
            Err(e)
        }
    }
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
    const MAX_WAIT_TIME_SECS: u64 = 60;
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
            info!(
                block_hash = %block_hash,
                cluster = %cluster,
                "[Ethproofs] Timeout waiting for proof"
            );
            return Err(format!(
                "No proof found for block {} in cluster {} within {} seconds",
                block_hash, cluster, MAX_WAIT_TIME_SECS
            ));
        }

        let mut request = client.get(&url);

        // Add API key header if environment variable is set
        if let Ok(api_key) = std::env::var("ETHPROOFS_API_KEY") {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
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

    info!(proof_id, "[Ethproofs] Downloading proof binary");

    let mut request = client.get(&url);

    // Add API key header if environment variable is set
    if let Ok(api_key) = std::env::var("ETHPROOFS_API_KEY") {
        request = request.header("Authorization", format!("Bearer {}", api_key));
    }

    let response = request
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

/// Validate a proof using the dynamic verifier system
///
/// This function performs cryptographic verification of a proof by:
/// 1. Fallback proofs (proof_id = 0) are accepted without verification
/// 2. Looks up proof_id in EthproofsProverRegistry to get zkvm_slug
/// 3. Looks up proof_id in dynamic VK store to get verification key
/// 4. Looks up zkvm_slug in verifier store to run verification
///
/// The dynamic system must be initialized by calling `load_active_provers()` during
/// beacon node startup. If not initialized, verification will fail.
///
/// Returns true if the proof is valid, false otherwise.
pub fn validate_proof(proof: &ExecutionProof) -> bool {
    let proof_id = proof.proof_id.as_u8();

    // Fallback proofs (proof_id 0) are accepted without verification
    if proof_id == 0 {
        debug!(
            slot = %proof.slot,
            block_hash = %proof.block_hash,
            "[Ethproofs] Fallback proof accepted"
        );
        return true;
    }

    // Use dynamic system (must be initialized via load_active_provers())
    let registry = match PROVER_REGISTRY.try_read() {
        Ok(r) => r,
        Err(e) => {
            warn!(
                proof_id = proof_id,
                error = %e,
                "[Ethproofs] Failed to read prover registry"
            );
            return false;
        }
    };

    if registry.is_empty() {
        warn!(
            proof_id = proof_id,
            "[Ethproofs] Prover registry not initialized. Call load_active_provers() during startup."
        );
        return false;
    }

    let prover_info = match registry.get_by_proof_id(proof_id) {
        Some(info) => info,
        None => {
            debug!(
                proof_id = proof_id,
                "[Ethproofs] Proof ID not found in registry"
            );
            return false;
        }
    };

    // Get VK from dynamic store
    let vk_store = match DYNAMIC_VK_STORE.try_read() {
        Ok(store) => store,
        Err(e) => {
            warn!(
                proof_id = proof_id,
                error = %e,
                "[Ethproofs] Failed to read VK store"
            );
            return false;
        }
    };

    let vk = match vk_store.get(&proof_id) {
        Some(vk) => vk,
        None => {
            warn!(
                proof_id = proof_id,
                "[Ethproofs] Verification key not found for proof_id"
            );
            return false;
        }
    };

    // Get verifier by zkvm_slug
    let verifier_entry = match VERIFIER_STORE.get_by_slug(&prover_info.zkvm_slug) {
        Some(entry) => entry,
        None => {
            warn!(
                proof_id = proof_id,
                zkvm_slug = %prover_info.zkvm_slug,
                "[Ethproofs] Verifier not found for zkvm_slug"
            );
            return false;
        }
    };

    debug!(
        slot = %proof.slot,
        block_hash = %proof.block_hash,
        proof_id = proof_id,
        zkvm_slug = %prover_info.zkvm_slug,
        vk_size = vk.size(),
        proof_size = proof.proof_data.len(),
        "[Ethproofs] Found proof, VK, and verifier"
    );

    info!(
        "[Ethproofs] Verification started: verifier={} slot={}",
        verifier_entry.name, proof.slot
    );

    // Run the actual cryptographic verification
    match (verifier_entry.verify_fn)(&proof.proof_data, &vk.vk) {
        Ok(result) => {
            info!(
                "[Ethproofs] Verification completed: verifier={} slot={} result={}",
                verifier_entry.name, proof.slot, result
            );
            result
        }
        Err(e) => {
            debug!(
                slot = %proof.slot,
                block_hash = %proof.block_hash,
                verifier = verifier_entry.name,
                error = %e,
                "[Ethproofs] Verification failed"
            );
            false
        }
    }
}
