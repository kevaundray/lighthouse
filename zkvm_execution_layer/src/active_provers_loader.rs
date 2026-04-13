//! Dynamic loader for active provers from Ethproofs API
//!
//! This module fetches active verification keys and prover metadata from the Ethproofs API
//! and builds the runtime configuration for proof verification.

use crate::ethproofs_demo::VERIFIER_STORE;
use crate::ethproofs_prover_registry::EthproofsProverRegistry;
use crate::verification_keys::ExecutionProofVerificationKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};
use uuid::Uuid;

/// Response from the /api/v0/verification-keys/active endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProverResponse {
    /// The cluster ID (UUID as string)
    pub cluster_id: String,
    /// The version index of this cluster version
    pub cluster_version_index: u32,
    /// The team slug
    pub team: String,
    /// The zkVM slug (e.g., "sp1-hypercube", "zisk")
    pub zkvm: String,
    /// The VK file path in storage
    pub vk_path: String,
    /// The VK binary data as base64 string
    pub vk_binary: String,
}

/// Loaded prover with decoded VK
#[derive(Debug, Clone)]
pub struct LoadedProver {
    pub proof_id: u8,
    pub cluster_id: Uuid,
    pub zkvm_slug: String,
    pub team: String,
    pub vk_data: Vec<u8>,
}

/// Fetch and load active provers from the Ethproofs API
///
/// The verification keys endpoint is public and does not require authentication.
pub async fn load_active_provers() -> Result<
    (
        EthproofsProverRegistry,
        HashMap<u8, ExecutionProofVerificationKey>,
    ),
    String,
> {
    const ETHPROOFS_API_URL: &str = "https://ethproofs.org";
    let url = format!("{}/api/v0/verification-keys/active", ETHPROOFS_API_URL);

    debug!(url = %url, "[Ethproofs] Fetching active provers from API");

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch active provers: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("API returned error status: {}", response.status()));
    }

    let provers: Vec<ActiveProverResponse> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {}", e))?;

    debug!(
        count = provers.len(),
        "[Ethproofs] Fetched active provers from API"
    );

    // Sort by cluster_id to ensure consistent proof_id assignment
    let mut sorted_provers = provers;
    sorted_provers.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));

    // Build registry and VK store
    let mut registry = EthproofsProverRegistry::new();
    let mut vk_store = HashMap::new();

    for (index, prover) in sorted_provers.iter().enumerate() {
        // Start at 1 to reserve proof_id 0 for fallback proofs
        let proof_id = (index + 1) as u8;

        // Check if verifier exists for this zkvm_slug
        if !VERIFIER_STORE.contains_slug(&prover.zkvm) {
            debug!(
                zkvm_slug = %prover.zkvm,
                cluster_id = %prover.cluster_id,
                "[Ethproofs] Skipping prover: no verifier available"
            );
            continue;
        }

        // Parse cluster_id as UUID
        let cluster_id = Uuid::parse_str(&prover.cluster_id)
            .map_err(|e| format!("Invalid cluster_id UUID '{}': {}", prover.cluster_id, e))?;

        // Decode base64 VK
        let vk_binary = base64_to_vec(&prover.vk_binary)?;

        // Create verification key (using cluster_id as prover_id)
        let vk = ExecutionProofVerificationKey::new(cluster_id, vk_binary.clone());

        // Register in prover registry
        registry.register(
            proof_id,
            cluster_id,
            prover.zkvm.clone(),
            prover.team.clone(),
        );

        // Store VK by proof_id
        vk_store.insert(proof_id, vk);

        debug!(
            proof_id = proof_id,
            cluster_id = %cluster_id,
            zkvm_slug = %prover.zkvm,
            vk_size = vk_binary.len(),
            "[Ethproofs] Loaded prover"
        );
    }

    if registry.is_empty() {
        warn!("[Ethproofs] No active provers loaded from API");
    }

    Ok((registry, vk_store))
}

/// Decode base64 string to bytes
fn base64_to_vec(b64: &str) -> Result<Vec<u8>, String> {
    // Use the base64 crate's decode functionality
    base64_decode(b64).map_err(|_| "Failed to decode base64 VK".to_string())
}

/// Helper function to decode base64 - we'll use a simple implementation
/// If base64 crate is available, this can be replaced
fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    general_purpose::STANDARD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        // "hello" encoded in base64
        let b64 = "aGVsbG8=";
        let decoded = base64_to_vec(b64).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_base64_decode_invalid() {
        let b64 = "!!!invalid!!!";
        assert!(base64_to_vec(b64).is_err());
    }

}
