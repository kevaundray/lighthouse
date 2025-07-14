//! Network proof types for gossip transmission

use super::{ExecutionBlockHash, SubnetId};
use serde::{Deserialize, Serialize};

/// Execution proof as transmitted over the gossip network
/// This is a lightweight version optimized for network transmission
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProof {
    /// The execution block hash this proof attests to
    pub block_hash: ExecutionBlockHash,
    /// The subnet ID this proof belongs to
    pub subnet_id: SubnetId,
    /// Version of the proof format
    pub version: u32,
    /// Opaque proof data - structure depends on subnet_id and version
    pub proof_data: Vec<u8>,
    /// Timestamp when this proof was created (Unix timestamp in seconds)
    pub timestamp: u64,
}

impl ExecutionProof {
    /// Create a new execution proof
    pub fn new(
        block_hash: ExecutionBlockHash,
        subnet_id: SubnetId,
        version: u32,
        proof_data: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            block_hash,
            subnet_id,
            version,
            proof_data,
            timestamp,
        }
    }

    /// Create a new execution proof with the current timestamp
    pub fn new_with_current_timestamp(
        block_hash: ExecutionBlockHash,
        subnet_id: SubnetId,
        version: u32,
        proof_data: Vec<u8>,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self::new(block_hash, subnet_id, version, proof_data, timestamp)
    }

    /// Check if the proof is structurally valid
    pub fn is_structurally_valid(&self) -> bool {
        // Basic validation
        !self.proof_data.is_empty() && self.version > 0
    }

    /// Get a description of the proof
    pub fn description(&self) -> String {
        format!(
            "ExecutionProof(block: {:?}, subnet: {}, version: {})",
            self.block_hash, self.subnet_id, self.version
        )
    }

    /// Check if this proof version is supported
    pub fn is_version_supported(&self) -> bool {
        matches!(self.version, 1)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    #[test]
    fn test_execution_proof_creation() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let subnet_id = SubnetId::new(1).unwrap();
        let proof_data = vec![1, 2, 3, 4];
        
        let proof = ExecutionProof::new_with_current_timestamp(
            block_hash,
            subnet_id,
            1,
            proof_data.clone(),
        );
        
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.subnet_id, subnet_id);
        assert_eq!(proof.version, 1);
        assert_eq!(proof.proof_data, proof_data);
        assert!(proof.timestamp > 0);
    }

    #[test]
    fn test_structural_validation() {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let subnet_id = SubnetId::new(0).unwrap();
        
        // Valid proof
        let valid_proof = ExecutionProof::new(block_hash, subnet_id, 1, vec![1], 100);
        assert!(valid_proof.is_structurally_valid());
        
        // Invalid: empty proof data
        let invalid_proof1 = ExecutionProof::new(block_hash, subnet_id, 1, vec![], 100);
        assert!(!invalid_proof1.is_structurally_valid());
        
        // Invalid: version 0
        let invalid_proof2 = ExecutionProof::new(block_hash, subnet_id, 0, vec![1], 100);
        assert!(!invalid_proof2.is_structurally_valid());
    }
}