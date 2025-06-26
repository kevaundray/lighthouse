//! Execution proof types for zkVM proofs and stateless execution witnesses.

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

/// An execution proof containing opaque proof or witness data.
/// The format is determined by the proof type and version.
#[derive(arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ExecutionProof {
    /// Version of the proof format - allows for backwards-incompatible updates
    /// TODO: change to u64?
    pub version: u8,
    /// Opaque proof or witness data - format determined by proof type and version
    pub data: Vec<u8>,
}

/// Types of execution proofs supported by different subnets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofType {
    /// SP1 zkVM proofs for state transitions
    SP1Proof = 0,
    /// Risc0 zkVM proofs for state transitions  
    Risc0Proof = 1,
    /// Execution witnesses for stateless block execution (MPT proofs + block data)
    ExecutionWitness = 2,
    // Future zkVM proof types can be added: Jolt = 3, Nexus = 4, etc.
}

impl ExecutionProof {
    /// Create a new execution proof
    pub fn new(version: u8, data: Vec<u8>) -> Self {
        Self { version, data }
    }

    /// Get the proof data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the proof version
    pub fn version(&self) -> u8 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn test_execution_proof_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let proof = ExecutionProof::new(1, data.clone());
        
        assert_eq!(proof.version(), 1);
        assert_eq!(proof.data(), &data);
    }

    #[test]
    fn test_execution_proof_ssz_encoding() {
        let proof = ExecutionProof::new(42, vec![0xde, 0xad, 0xbe, 0xef]);
        
        // Test encoding and decoding
        let encoded = proof.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).unwrap();
        
        assert_eq!(proof, decoded);
        assert_eq!(decoded.version(), 42);
        assert_eq!(decoded.data(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_execution_proof_empty_data() {
        let proof = ExecutionProof::new(0, vec![]);
        assert_eq!(proof.data().len(), 0);
        
        // Should still encode/decode correctly
        let encoded = proof.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_execution_proof_large_data() {
        let large_data = vec![42u8; 1000000]; // 1MB of data
        let proof = ExecutionProof::new(255, large_data.clone());
        
        assert_eq!(proof.data().len(), 1000000);
        assert_eq!(proof.version(), 255);
        
        // Test SSZ with large data
        let encoded = proof.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_proof_type_values() {
        assert_eq!(ProofType::SP1Proof as u8, 0);
        assert_eq!(ProofType::Risc0Proof as u8, 1);
        assert_eq!(ProofType::ExecutionWitness as u8, 2);
    }
}