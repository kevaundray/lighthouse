use crate::{ExecutionBlockHash, Hash256, VariableList};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;
use std::fmt::{self, Debug};
use tree_hash_derive::TreeHash;

use super::ExecutionProofSubnetId;

/// Maximum size of proof data in bytes (1 MB for zkVM proofs)
pub const MAX_PROOF_DATA_BYTES: usize = 1_048_576;

/// Type alias for proof data with maximum size limit
type ProofData = VariableList<u8, typenum::U1048576>;

/// ExecutionProof represents a cryptographic proof (e.g., zkVM proof) that
/// an execution payload is valid.
///
/// Each proof is associated with a specific subnet_id, which identifies the
/// proof system (zkVM) used to generate it. Multiple proofs from different
/// subnets can exist for the same execution payload, providing M-of-N security.
#[derive(Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Which subnet/proof system this proof belongs to (0-7)
    pub subnet_id: ExecutionProofSubnetId,

    /// The block hash of the execution payload this proof validates
    pub block_hash: ExecutionBlockHash,

    /// The beacon block root this proof is associated with
    pub block_root: Hash256,

    /// The actual proof data (format depends on zkVM system)
    /// For RISC Zero: serialized RISC Zero receipt
    /// For SP1: serialized SP1 proof
    /// Limited to MAX_PROOF_DATA_BYTES (1 MB)
    pub proof_data: ProofData,
}

impl ExecutionProof {
    /// Create a new ExecutionProof
    pub fn new(
        subnet_id: ExecutionProofSubnetId,
        block_hash: ExecutionBlockHash,
        block_root: Hash256,
        proof_data: Vec<u8>,
    ) -> Result<Self, String> {
        let proof_data = ProofData::new(proof_data)
            .map_err(|e| format!("Failed to create proof data: {:?}", e))?;

        Ok(Self {
            subnet_id,
            block_hash,
            block_root,
            proof_data,
        })
    }

    /// Returns the size of the proof data in bytes
    pub fn proof_data_size(&self) -> usize {
        self.proof_data.len()
    }

    /// Get a reference to the proof data as a slice
    pub fn proof_data_slice(&self) -> &[u8] {
        &self.proof_data
    }

    /// Check if this proof is for a specific execution block hash
    pub fn is_for_block(&self, block_hash: &ExecutionBlockHash) -> bool {
        &self.block_hash == block_hash
    }

    /// Check if this proof is from a specific subnet
    pub fn is_from_subnet(&self, subnet_id: ExecutionProofSubnetId) -> bool {
        self.subnet_id == subnet_id
    }
}

impl Debug for ExecutionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionProof")
            .field("subnet_id", &self.subnet_id)
            .field("block_hash", &self.block_hash)
            .field("block_root", &self.block_root)
            .field("proof_data_size", &self.proof_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_proof_creation() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![1, 2, 3, 4];

        let proof = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data.clone());
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.subnet_id, subnet_id);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.block_root, block_root);
        assert_eq!(proof.proof_data, proof_data);
        assert_eq!(proof.proof_data_size(), 4);
    }

    #[test]
    fn test_execution_proof_too_large() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES + 1];

        let result = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Proof data too large"));
    }

    #[test]
    fn test_execution_proof_max_size() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES];

        let result = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_for_block() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::from_low_u64_be(42);
        let block_root = Hash256::zero();
        let proof_data = vec![1, 2, 3];

        let proof = ExecutionProof::new(subnet_id, block_hash, block_root, proof_data).unwrap();

        assert!(proof.is_for_block(&block_hash));
        assert!(!proof.is_for_block(&ExecutionBlockHash::zero()));
    }

    #[test]
    fn test_is_from_subnet() {
        let subnet_id_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_id_1 = ExecutionProofSubnetId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let block_root = Hash256::zero();
        let proof_data = vec![1, 2, 3];

        let proof = ExecutionProof::new(subnet_id_0, block_hash, block_root, proof_data).unwrap();

        assert!(proof.is_from_subnet(subnet_id_0));
        assert!(!proof.is_from_subnet(subnet_id_1));
    }
}
