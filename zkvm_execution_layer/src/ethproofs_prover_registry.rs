//! Ethproofs prover registry mapping proof_id to cluster_id and zkvm_slug
//!
//! This module manages the relationship between proof types loaded from the Ethproofs API:
//! - proof_id (0-7): Specific proof type instance
//! - cluster_id (UUID): The Ethproofs cluster that generates this proof
//! - zkvm_slug (string): The underlying proof system (e.g., "sp1-hypercube", "zisk")

use std::collections::HashMap;
use uuid::Uuid;

/// Represents the mapping for a single proof type
#[derive(Clone, Debug)]
pub struct ProverInfo {
    /// The proof type ID (0-7)
    pub proof_id: u8,
    /// The cluster ID from the Ethproofs prover (UUID)
    pub cluster_id: Uuid,
    /// The zkVM proof system slug (e.g., "sp1-hypercube", "zisk")
    pub zkvm_slug: String,
    /// Team that owns this prover
    pub team: String,
}

/// Registry mapping proof_id → cluster_id → zkvm_slug for Ethproofs provers
///
/// This registry stores the dynamic mapping of proof types to Ethproofs clusters
/// and their corresponding proof systems, loaded from the Ethproofs API.
#[derive(Clone, Debug)]
pub struct EthproofsProverRegistry {
    /// Mapping: proof_id → ProverInfo
    by_proof_id: HashMap<u8, ProverInfo>,
    /// Mapping: cluster_id (UUID string) → zkvm_slug
    by_cluster_id: HashMap<String, String>,
}

impl EthproofsProverRegistry {
    /// Create a new empty prover registry
    pub fn new() -> Self {
        Self {
            by_proof_id: HashMap::new(),
            by_cluster_id: HashMap::new(),
        }
    }

    /// Register a prover for a given proof_id
    pub fn register(
        &mut self,
        proof_id: u8,
        cluster_id: Uuid,
        zkvm_slug: String,
        team: String,
    ) {
        let cluster_id_str = cluster_id.to_string();

        let info = ProverInfo {
            proof_id,
            cluster_id,
            zkvm_slug: zkvm_slug.clone(),
            team,
        };

        self.by_proof_id.insert(proof_id, info);
        self.by_cluster_id.insert(cluster_id_str, zkvm_slug);
    }

    /// Get prover info by proof_id
    pub fn get_by_proof_id(&self, proof_id: u8) -> Option<&ProverInfo> {
        self.by_proof_id.get(&proof_id)
    }

    /// Get zkvm_slug by cluster_id
    pub fn get_zkvm_slug(&self, cluster_id: &Uuid) -> Option<&str> {
        self.by_cluster_id.get(&cluster_id.to_string()).map(|s| s.as_str())
    }

    /// Get cluster_id by proof_id
    pub fn get_cluster_id(&self, proof_id: u8) -> Option<Uuid> {
        self.by_proof_id.get(&proof_id).map(|info| info.cluster_id)
    }

    /// Get all registered proof_ids
    pub fn proof_ids(&self) -> Vec<u8> {
        self.by_proof_id.keys().copied().collect()
    }

    /// Get all registered prover infos
    pub fn all_provers(&self) -> Vec<ProverInfo> {
        self.by_proof_id.values().cloned().collect()
    }

    /// Check if a proof_id is registered
    pub fn has_proof_id(&self, proof_id: u8) -> bool {
        self.by_proof_id.contains_key(&proof_id)
    }

    /// Get the number of registered proof types
    pub fn len(&self) -> usize {
        self.by_proof_id.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.by_proof_id.is_empty()
    }
}

impl Default for EthproofsProverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_retrieve() {
        let mut registry = EthproofsProverRegistry::new();
        let cluster_id = Uuid::parse_str("fbef2553-8cd0-4f45-b328-570b5c8688b2").unwrap();

        registry.register(4, cluster_id, "sp1-hypercube".to_string(), "ethproofs".to_string());

        assert!(registry.has_proof_id(4));
        assert_eq!(registry.get_cluster_id(4), Some(cluster_id));
        assert_eq!(registry.get_zkvm_slug(&cluster_id), Some("sp1-hypercube"));
    }

    #[test]
    fn test_multiple_registrations() {
        let mut registry = EthproofsProverRegistry::new();
        let cluster_id_1 = Uuid::parse_str("fbef2553-8cd0-4f45-b328-570b5c8688b2").unwrap();
        let cluster_id_2 = Uuid::parse_str("884fcc21-d522-4b4a-b535-7cfde199485c").unwrap();

        registry.register(4, cluster_id_1, "sp1-hypercube".to_string(), "ethproofs".to_string());
        registry.register(7, cluster_id_2, "zisk".to_string(), "ethproofs".to_string());

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.get_zkvm_slug(&cluster_id_1), Some("sp1-hypercube"));
        assert_eq!(registry.get_zkvm_slug(&cluster_id_2), Some("zisk"));
    }
}
