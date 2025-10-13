//! Execution payload proof message for gossip.

use crate::{ExecutionBlockHash, Hash256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// Execution proof identifiers for different proof systems/zkVMs.
pub const EXECUTION_PROOF_0: u64 = 0;
pub const EXECUTION_PROOF_1: u64 = 1;
pub const EXECUTION_PROOF_2: u64 = 2;

/// Represents a proof for an execution payload.
/// If this proof verifies as true, it is equivalent to the ExecutionLayer
/// specifying that the payload is valid.
///
/// Multiple proof systems can exist for a single execution payload
/// All proofs are sent on a single subnet. Different proof systems/zkVMs and their versions
/// are distinguished by the execution_proof_id and version fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionProof {
    /// The beacon block root this proof is for
    pub block_root: Hash256,
    /// The execution block hash this proof attests to
    pub block_hash: ExecutionBlockHash,
    /// Identifies which proof system/zkVM generated this proof
    /// See EXECUTION_PROOF_* constants for known values.
    pub execution_proof_id: u64,
    /// Version of the proof format within the specific proof system
    /// Each proof system can independently upgrade their version number.
    pub version: u64,
    /// Opaque proof data - structure depends on execution_proof_id and version
    /// This will contain cryptographic proofs received via gossip
    pub proof_data: Vec<u8>,
}

impl ExecutionProof {
    /// Create a new execution proof for gossip
    pub fn new(
        block_root: Hash256,
        block_hash: ExecutionBlockHash,
        execution_proof_id: u64,
        version: u64,
        proof_data: Vec<u8>,
    ) -> Self {
        Self {
            block_root,
            block_hash,
            execution_proof_id,
            version,
            proof_data,
        }
    }

    /// Get a description of the proof type based on execution_proof_id
    pub fn description(&self) -> String {
        let system_name = match self.execution_proof_id {
            EXECUTION_PROOF_0 => "zkVM_0",
            EXECUTION_PROOF_1 => "zkVM_1",
            EXECUTION_PROOF_2 => "zkVM_2",
            _ => "Unknown", // TODO(zkproofs): should this be a panic!
        };
        format!("{} v{}", system_name, self.version)
    }

    /// Check if this proof system is known
    pub fn is_proof_system_known(&self) -> bool {
        matches!(
            self.execution_proof_id,
            EXECUTION_PROOF_0 | EXECUTION_PROOF_1 | EXECUTION_PROOF_2
        )
    }

    /// Check if this proof version is supported for the given proof system
    pub fn is_version_supported(&self) -> bool {
        // TODO(zkproofs): Currently all known proof systems only support version 1.
        // Each proof system/zkVM will have its own supported version set as they evolve.
        // This could be expanded to a match on (execution_proof_id, version) tuple.
        self.is_proof_system_known() && matches!(self.version, 1)
    }

    /// Validate basic structure of the proof
    pub fn is_structurally_valid(&self) -> bool {
        // Basic validation: non-empty proof data and supported version
        !self.proof_data.is_empty() && self.is_version_supported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash256;
    use ssz::{Decode, Encode};

    #[test]
    fn test_execution_proof_creation() {
        let block_root = Hash256::random();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let execution_proof_id = EXECUTION_PROOF_0;
        let proof_data = vec![1, 2, 3, 4];

        let proof = ExecutionProof::new(block_root, block_hash, execution_proof_id, 1, proof_data.clone());

        assert_eq!(proof.block_root, block_root);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.execution_proof_id, execution_proof_id);
        assert_eq!(proof.version, 1);
        assert_eq!(proof.proof_data, proof_data);
    }

    #[test]
    fn test_execution_proof_validation() {
        let block_root = Hash256::random();
        let block_hash = ExecutionBlockHash::from(Hash256::random());

        // Valid proof for proof system 0
        let valid_proof = ExecutionProof::new(block_root, block_hash, EXECUTION_PROOF_0, 1, vec![1, 2, 3]);
        assert!(valid_proof.is_proof_system_known());
        assert!(valid_proof.is_version_supported());
        assert!(valid_proof.is_structurally_valid());

        // Valid proof for proof system 1
        let proof_1 = ExecutionProof::new(block_root, block_hash, EXECUTION_PROOF_1, 1, vec![1, 2, 3]);
        assert!(proof_1.is_proof_system_known());
        assert!(proof_1.is_version_supported());

        // Unknown proof system
        let unknown_system = ExecutionProof::new(block_root, block_hash, 999, 1, vec![1, 2, 3]);
        assert!(!unknown_system.is_proof_system_known());
        assert!(!unknown_system.is_version_supported());
        assert!(!unknown_system.is_structurally_valid());

        // Invalid version for known system
        let invalid_version =
            ExecutionProof::new(block_root, block_hash, EXECUTION_PROOF_0, 99, vec![1, 2, 3]);
        assert!(invalid_version.is_proof_system_known());
        assert!(!invalid_version.is_version_supported());
        assert!(!invalid_version.is_structurally_valid());

        // Empty proof data
        let empty_proof = ExecutionProof::new(block_root, block_hash, EXECUTION_PROOF_0, 1, vec![]);
        assert!(empty_proof.is_version_supported());
        assert!(!empty_proof.is_structurally_valid());
    }

    #[test]
    fn test_execution_proof_description() {
        let block_root = Hash256::random();
        let block_hash = ExecutionBlockHash::from(Hash256::random());

        let proof_0 = ExecutionProof::new(
            block_root,
            block_hash,
            EXECUTION_PROOF_0,
            1,
            vec![1, 2, 3],
        );
        assert_eq!(proof_0.description(), "zkVM_0 v1");

        let proof_1 = ExecutionProof::new(
            block_root,
            block_hash,
            EXECUTION_PROOF_1,
            2,
            vec![1, 2, 3],
        );
        assert_eq!(proof_1.description(), "zkVM_1 v2");

        let proof_2 = ExecutionProof::new(
            block_root,
            block_hash,
            EXECUTION_PROOF_2,
            1,
            vec![1, 2, 3],
        );
        assert_eq!(proof_2.description(), "zkVM_2 v1");

        let unknown_proof = ExecutionProof::new(
            block_root,
            block_hash,
            999,
            1,
            vec![1, 2, 3],
        );
        assert_eq!(unknown_proof.description(), "Unknown v1");
    }

    #[test]
    fn test_execution_proof_ssz_encoding() {
        let block_root = Hash256::random();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let execution_proof_id = EXECUTION_PROOF_2;
        let proof_data = vec![10, 20, 30, 40, 50];

        let original = ExecutionProof::new(block_root, block_hash, execution_proof_id, 1, proof_data);

        // Test SSZ encoding and decoding
        let encoded = original.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).expect("should decode successfully");

        assert_eq!(original, decoded);
    }
}
