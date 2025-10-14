//! Execution payload proof message for gossip.

use crate::{ExecutionBlockHash, Hash256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strum::{EnumCount, EnumIter, IntoEnumIterator};

/// Execution proof system identifiers for different zkVMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumCount, EnumIter)]
#[repr(u64)]
pub enum ProofSystemId {
    ZKVM0 = 0,
    ZKVM1 = 1,
    ZKVM2 = 2,
}

impl ProofSystemId {
    /// Convert to u64 for wire format
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Try to parse from u64
    pub const fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::ZKVM0),
            1 => Some(Self::ZKVM1),
            2 => Some(Self::ZKVM2),
            _ => None,
        }
    }

    /// Get human-readable name for this proof system
    pub const fn name(self) -> &'static str {
        match self {
            Self::ZKVM0 => "zkVM_0",
            Self::ZKVM1 => "zkVM_1",
            Self::ZKVM2 => "zkVM_2",
        }
    }

    /// Get all known proof systems
    pub fn all() -> impl Iterator<Item = Self> {
        Self::iter()
    }
}

/// Maximum number of different proof systems that can generate proofs.
/// This represents the diversity of proof systems, not the number of subnets.
///
/// This value is automatically derived from the number of variants in ProofSystemId.
/// To add a new proof system, simply add a new variant to ProofSystemId.
pub const MAX_PROOF_SYSTEMS: usize = ProofSystemId::COUNT;

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
        let system_name = ProofSystemId::from_u64(self.execution_proof_id)
            .map(|id| id.name())
            .unwrap_or("Unknown");
        format!("{} v{}", system_name, self.version)
    }

    /// Check if this proof system is known
    pub fn is_proof_system_known(&self) -> bool {
        ProofSystemId::from_u64(self.execution_proof_id).is_some()
    }

    /// Get the ProofSystemId if this proof system is known
    pub fn proof_system_id(&self) -> Option<ProofSystemId> {
        ProofSystemId::from_u64(self.execution_proof_id)
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
        let execution_proof_id = ProofSystemId::ZKVM0.as_u64();
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
        let valid_proof = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM0.as_u64(),
            1,
            vec![1, 2, 3]
        );
        assert!(valid_proof.is_proof_system_known());
        assert!(valid_proof.is_version_supported());
        assert!(valid_proof.is_structurally_valid());

        // Valid proof for proof system 1
        let proof_1 = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM1.as_u64(),
            1,
            vec![1, 2, 3]
        );
        assert!(proof_1.is_proof_system_known());
        assert!(proof_1.is_version_supported());

        // Unknown proof system
        let unknown_system = ExecutionProof::new(block_root, block_hash, 999, 1, vec![1, 2, 3]);
        assert!(!unknown_system.is_proof_system_known());
        assert!(!unknown_system.is_version_supported());
        assert!(!unknown_system.is_structurally_valid());

        // Invalid version for known system
        let invalid_version = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM0.as_u64(),
            99,
            vec![1, 2, 3]
        );
        assert!(invalid_version.is_proof_system_known());
        assert!(!invalid_version.is_version_supported());
        assert!(!invalid_version.is_structurally_valid());

        // Empty proof data
        let empty_proof = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM0.as_u64(),
            1,
            vec![]
        );
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
            ProofSystemId::ZKVM0.as_u64(),
            1,
            vec![1, 2, 3],
        );
        assert_eq!(proof_0.description(), "zkVM_0 v1");

        let proof_1 = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM1.as_u64(),
            2,
            vec![1, 2, 3],
        );
        assert_eq!(proof_1.description(), "zkVM_1 v2");

        let proof_2 = ExecutionProof::new(
            block_root,
            block_hash,
            ProofSystemId::ZKVM2.as_u64(),
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
        let execution_proof_id = ProofSystemId::ZKVM2.as_u64();
        let proof_data = vec![10, 20, 30, 40, 50];

        let original = ExecutionProof::new(block_root, block_hash, execution_proof_id, 1, proof_data);

        // Test SSZ encoding and decoding
        let encoded = original.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).expect("should decode successfully");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_max_proof_systems_matches_enum_count() {
        // This test ensures MAX_PROOF_SYSTEMS stays in sync with ProofSystemId enum.
        // Thanks to strum's EnumCount, this is automatically derived!

        // MAX_PROOF_SYSTEMS should equal the number of enum variants
        assert_eq!(MAX_PROOF_SYSTEMS, ProofSystemId::COUNT);

        // Collect all proof system IDs
        let all_systems: Vec<_> = ProofSystemId::all().collect();
        assert_eq!(all_systems.len(), MAX_PROOF_SYSTEMS);

        // Verify all proof system IDs are sequential starting from 0
        for (i, proof_system) in all_systems.iter().enumerate() {
            assert_eq!(proof_system.as_u64(), i as u64,
                "Proof system IDs should be sequential starting from 0. Found ID {} at index {}",
                proof_system.as_u64(), i);
        }

        // Verify all proof systems are recognized by is_proof_system_known()
        let block_root = Hash256::random();
        let block_hash = ExecutionBlockHash::from(Hash256::random());

        for proof_system in &all_systems {
            let proof = ExecutionProof::new(
                block_root,
                block_hash,
                proof_system.as_u64(),
                1,
                vec![1, 2, 3]
            );
            assert!(proof.is_proof_system_known(),
                "Proof system {:?} should be known", proof_system);
            assert_eq!(proof.proof_system_id(), Some(*proof_system));
        }

        // Verify all proof systems have names in description()
        for proof_system in &all_systems {
            let proof = ExecutionProof::new(
                block_root,
                block_hash,
                proof_system.as_u64(),
                1,
                vec![1, 2, 3]
            );
            let desc = proof.description();
            assert!(!desc.starts_with("Unknown"),
                "Proof system {:?} should have a proper name, got: {}", proof_system, desc);
            assert_eq!(proof_system.name(), desc.split_whitespace().next().unwrap());
        }

        // Verify proof system ID beyond MAX_PROOF_SYSTEMS is not known
        let unknown_id = MAX_PROOF_SYSTEMS as u64;
        let unknown_proof = ExecutionProof::new(block_root, block_hash, unknown_id, 1, vec![1, 2, 3]);
        assert!(!unknown_proof.is_proof_system_known(),
            "Proof system {} (>= MAX_PROOF_SYSTEMS) should not be known", unknown_id);
        assert_eq!(unknown_proof.proof_system_id(), None);
    }

    #[test]
    fn test_all_proof_systems_are_unique() {
        // Ensure no duplicate proof system IDs
        let all_systems: Vec<_> = ProofSystemId::all().collect();
        let mut seen = std::collections::HashSet::new();

        for proof_system in &all_systems {
            let id = proof_system.as_u64();
            assert!(seen.insert(id),
                "Duplicate proof system ID found: {} ({:?})", id, proof_system);
        }
    }

    #[test]
    fn test_proof_system_id_round_trip() {
        // Test that all ProofSystemIds can round-trip through u64
        for proof_system in ProofSystemId::all() {
            let as_u64 = proof_system.as_u64();
            let parsed = ProofSystemId::from_u64(as_u64);
            assert_eq!(Some(proof_system), parsed,
                "Round-trip failed for {:?}", proof_system);
        }

        // Test that invalid IDs return None
        assert_eq!(ProofSystemId::from_u64(999), None);
        assert_eq!(ProofSystemId::from_u64(u64::MAX), None);
    }
}
