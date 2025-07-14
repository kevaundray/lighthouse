//! Storage proof types for internal representation

use super::{ExecutionBlockHash, ProofId};
use serde::{Deserialize, Serialize};

/// Represents a proof for an execution payload in storage
/// This is the internal representation with full metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPayloadProof {
    /// The execution block hash this proof attests to
    pub block_hash: ExecutionBlockHash,
    /// The ID of the proof type (maps to gossip subnet)
    pub proof_id: ProofId,
    /// Version of the proof format
    pub version: u32,
    /// Opaque proof data - structure depends on proof_id and version
    pub proof_data: Vec<u8>,
    /// Timestamp when this proof was received/stored
    pub timestamp: u64,
}

impl ExecutionPayloadProof {
    /// Create a new execution payload proof
    pub fn new(
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
        version: u32,
        proof_data: Vec<u8>,
    ) -> Self {
        Self {
            block_hash,
            proof_id,
            version,
            proof_data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create a new execution payload proof with default version (1)
    pub fn new_v1(block_hash: ExecutionBlockHash, proof_id: ProofId, proof_data: Vec<u8>) -> Self {
        Self::new(block_hash, proof_id, 1, proof_data)
    }

    /// Check if this proof version is supported
    pub fn is_version_supported(&self) -> bool {
        matches!(self.version, 1)
    }

    /// Get a description of the proof including type and version
    pub fn description(&self) -> String {
        format!("{} v{}", self.proof_id.description(), self.version)
    }

    /// Get the identifier string for this proof (useful for metrics/logging)
    pub fn identifier(&self) -> String {
        format!("{}_v{}", self.proof_id.identifier(), self.version)
    }

    /// Convert to network representation
    pub fn to_network_proof(&self) -> super::ExecutionProof {
        super::ExecutionProof::new(
            self.block_hash,
            self.proof_id.subnet_id(),
            self.version,
            self.proof_data.clone(),
            self.timestamp,
        )
    }

    /// Create from network representation
    pub fn from_network_proof(network_proof: &super::ExecutionProof) -> Self {
        Self {
            block_hash: network_proof.block_hash,
            proof_id: network_proof.subnet_id.as_proof_id(),
            version: network_proof.version,
            proof_data: network_proof.proof_data.clone(),
            timestamp: network_proof.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    #[test]
    fn test_execution_payload_proof_creation() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(2);
        let proof_data = vec![1, 2, 3, 4, 5];
        
        let proof = ExecutionPayloadProof::new_v1(block_hash, proof_id, proof_data.clone());
        
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.proof_id, proof_id);
        assert_eq!(proof.version, 1);
        assert_eq!(proof.proof_data, proof_data);
        assert!(proof.timestamp > 0);
    }

    #[test]
    fn test_description_and_identifier() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        
        let witness_proof = ExecutionPayloadProof::new_v1(
            block_hash,
            ProofId::EXECUTION_WITNESS,
            vec![1],
        );
        assert_eq!(witness_proof.description(), "Execution witness proof v1");
        assert_eq!(witness_proof.identifier(), "execution_witness_v1");
        
        let custom_proof = ExecutionPayloadProof::new(
            block_hash,
            ProofId::custom(42),
            2,
            vec![1],
        );
        assert_eq!(custom_proof.description(), "Custom proof type 42 v2");
        assert_eq!(custom_proof.identifier(), "custom_v2");
    }

    #[test]
    fn test_network_conversion() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(3);
        let proof_data = vec![1, 2, 3];
        
        let storage_proof = ExecutionPayloadProof::new_v1(block_hash, proof_id, proof_data);
        let network_proof = storage_proof.to_network_proof();
        let roundtrip_proof = ExecutionPayloadProof::from_network_proof(&network_proof);
        
        assert_eq!(storage_proof.block_hash, roundtrip_proof.block_hash);
        assert_eq!(storage_proof.proof_id, roundtrip_proof.proof_id);
        assert_eq!(storage_proof.version, roundtrip_proof.version);
        assert_eq!(storage_proof.proof_data, roundtrip_proof.proof_data);
        assert_eq!(storage_proof.timestamp, roundtrip_proof.timestamp);
    }
}