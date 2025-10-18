use crate::{
    ExecutionBlockHash, FixedBytesExtended, Hash256, SignedBeaconBlockHeader, Slot, VariableList,
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;
use std::fmt::{self, Debug};
use tree_hash::TreeHash;
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
///
/// Following the BlobSidecar pattern, this includes the signed beacon block header
/// which provides slot, proposer_index, and all header fields. The block_root
/// can be computed via tree hashing the header.
#[derive(Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq, Eq)]
pub struct ExecutionProof {
    /// Which subnet/proof system this proof belongs to (0-7)
    pub subnet_id: ExecutionProofSubnetId,

    /// The block hash of the execution payload this proof validates
    pub block_hash: ExecutionBlockHash,

    /// The signed beacon block header this proof is associated with.
    /// Contains slot, proposer_index, parent_root, state_root, body_root, and signature.
    /// The block_root can be computed via tree_hash_root() on the message.
    pub signed_block_header: SignedBeaconBlockHeader,

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
        signed_block_header: SignedBeaconBlockHeader,
        proof_data: Vec<u8>,
    ) -> Result<Self, String> {
        let proof_data = ProofData::new(proof_data)
            .map_err(|e| format!("Failed to create proof data: {:?}", e))?;

        Ok(Self {
            subnet_id,
            block_hash,
            signed_block_header,
            proof_data,
        })
    }

    /// Create a new ExecutionProof with a minimal header for testing
    ///
    /// This is a convenience method for tests and dummy implementations.
    /// Real implementations should use `new()` with proper SignedBeaconBlockHeader.
    ///
    /// The created header will have slot=0 and use block_root as the body_root.
    pub fn new_for_testing(
        subnet_id: ExecutionProofSubnetId,
        block_hash: ExecutionBlockHash,
        block_root: Hash256,
        proof_data: Vec<u8>,
    ) -> Result<Self, String> {
        use crate::BeaconBlockHeader;

        let header = BeaconBlockHeader {
            slot: Slot::new(0),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: block_root,
        };
        let signed_header = SignedBeaconBlockHeader {
            message: header,
            signature: bls::Signature::empty().into(),
        };

        Self::new(subnet_id, block_hash, signed_header, proof_data)
    }

    /// Returns the slot of the beacon block this proof is associated with
    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    /// Returns the beacon block root by computing the tree hash of the header
    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }

    /// Returns the proposer index of the beacon block
    pub fn proposer_index(&self) -> u64 {
        self.signed_block_header.message.proposer_index
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
            .field("slot", &self.slot())
            .field("block_root", &self.block_root())
            .field("proposer_index", &self.proposer_index())
            .field("proof_data_size", &self.proof_data.len())
            .finish()
    }
}

/// Identifier for requesting a specific execution proof via RPC
///
/// Similar to BlobIdentifier, this identifies a proof by its beacon block root
/// and subnet ID (which proof system generated it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Encode, Decode, Serialize, Deserialize)]
pub struct ExecutionProofIdentifier {
    /// The beacon block root this proof is associated with
    pub block_root: Hash256,
    /// The subnet/proof system ID (0-7)
    pub subnet_id: ExecutionProofSubnetId,
}

impl ExecutionProofIdentifier {
    pub fn new(block_root: Hash256, subnet_id: ExecutionProofSubnetId) -> Self {
        Self {
            block_root,
            subnet_id,
        }
    }
}

impl PartialOrd for ExecutionProofIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExecutionProofIdentifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block_root
            .cmp(&other.block_root)
            .then_with(|| self.subnet_id.cmp(&other.subnet_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BeaconBlockHeader;

    fn create_test_header(slot: u64) -> SignedBeaconBlockHeader {
        let header = BeaconBlockHeader {
            slot: Slot::new(slot),
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body_root: Hash256::zero(),
        };
        SignedBeaconBlockHeader {
            message: header,
            signature: bls::Signature::empty().into(),
        }
    }

    #[test]
    fn test_execution_proof_creation() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let signed_header = create_test_header(42);
        let proof_data = vec![1, 2, 3, 4];

        let proof = ExecutionProof::new(
            subnet_id,
            block_hash,
            signed_header.clone(),
            proof_data.clone(),
        );
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.subnet_id, subnet_id);
        assert_eq!(proof.block_hash, block_hash);
        assert_eq!(proof.slot(), Slot::new(42));
        assert_eq!(proof.block_root(), signed_header.message.tree_hash_root());
        assert_eq!(proof.proof_data_size(), 4);
    }

    #[test]
    fn test_execution_proof_too_large() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let signed_header = create_test_header(0);
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES + 1];

        let result = ExecutionProof::new(subnet_id, block_hash, signed_header, proof_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to create proof data"));
    }

    #[test]
    fn test_execution_proof_max_size() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let signed_header = create_test_header(0);
        let proof_data = vec![0u8; MAX_PROOF_DATA_BYTES];

        let result = ExecutionProof::new(subnet_id, block_hash, signed_header, proof_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_for_block() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(42));
        let signed_header = create_test_header(0);
        let proof_data = vec![1, 2, 3];

        let proof = ExecutionProof::new(subnet_id, block_hash, signed_header, proof_data).unwrap();

        assert!(proof.is_for_block(&block_hash));
        assert!(!proof.is_for_block(&ExecutionBlockHash::zero()));
    }

    #[test]
    fn test_is_from_subnet() {
        let subnet_id_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_id_1 = ExecutionProofSubnetId::new(1).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let signed_header = create_test_header(0);
        let proof_data = vec![1, 2, 3];

        let proof =
            ExecutionProof::new(subnet_id_0, block_hash, signed_header, proof_data).unwrap();

        assert!(proof.is_from_subnet(subnet_id_0));
        assert!(!proof.is_from_subnet(subnet_id_1));
    }

    #[test]
    fn test_slot_and_block_root_methods() {
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let block_hash = ExecutionBlockHash::zero();
        let signed_header = create_test_header(123);
        let proof_data = vec![1, 2, 3];

        let proof = ExecutionProof::new(subnet_id, block_hash, signed_header.clone(), proof_data)
            .unwrap();

        assert_eq!(proof.slot(), Slot::new(123));
        assert_eq!(proof.block_root(), signed_header.message.tree_hash_root());
        assert_eq!(proof.proposer_index(), 0);
    }
}
