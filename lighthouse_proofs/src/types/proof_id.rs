//! Proof identifier types and subnet mapping

use serde::{Deserialize, Serialize};
use std::fmt;

/// Default maximum number of execution proof subnets
pub const MAX_EXECUTION_PROOF_SUBNETS: u64 = 8;

/// Identifier for different types of proofs that can be received for execution payloads
/// Each proof ID maps directly to a subnet number for gossip distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId(pub u64);

impl ProofId {
    /// Execution witness proof (subnet 0)
    /// This is the standard execution payload witness proof
    pub const EXECUTION_WITNESS: ProofId = ProofId(0);

    /// Create a custom proof ID for specific zkVMs
    /// Each zkVM will have its own subnet and proof ID
    pub const fn custom(id: u64) -> Self {
        ProofId(id)
    }

    /// Get the numeric ID
    pub fn id(&self) -> u64 {
        self.0
    }

    /// Get the gossip subnet ID for this proof type
    /// Direct one-to-one mapping: ProofId IS the subnet ID
    pub fn subnet_id(&self) -> SubnetId {
        SubnetId::new(self.0).expect("ProofId should always be valid subnet")
    }

    /// Get the gossip topic name for this proof type
    pub fn subnet_topic(&self) -> String {
        format!("execution_proof_{}", self.0)
    }

    /// Get a string identifier for this proof type
    pub fn identifier(&self) -> &'static str {
        match self.0 {
            0 => "execution_witness",
            _ => "custom",
        }
    }

    /// Get a human-readable description of the proof type
    pub fn description(&self) -> String {
        match self.0 {
            0 => "Execution witness proof".to_string(),
            _ => format!("Custom proof type {}", self.0),
        }
    }
}

impl fmt::Display for ProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProofId({})", self.0)
    }
}

/// Type-safe subnet identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetId(u64);

impl SubnetId {
    /// Create a new subnet ID with validation
    pub fn new(id: u64) -> Result<Self, crate::Error> {
        if id < MAX_EXECUTION_PROOF_SUBNETS {
            Ok(Self(id))
        } else {
            Err(crate::Error::InvalidSubnetId(id))
        }
    }

    /// Create a subnet ID without validation (unsafe)
    /// Only use when you're certain the ID is valid
    pub const fn new_unchecked(id: u64) -> Self {
        Self(id)
    }

    /// Get the subnet ID as u64
    pub fn id(&self) -> u64 {
        self.0
    }

    /// Convert to ProofId
    pub fn as_proof_id(&self) -> ProofId {
        ProofId(self.0)
    }
}

impl fmt::Display for SubnetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<SubnetId> for u64 {
    fn from(subnet: SubnetId) -> Self {
        subnet.0
    }
}

impl TryFrom<u64> for SubnetId {
    type Error = crate::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        SubnetId::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_id_basics() {
        assert_eq!(ProofId::EXECUTION_WITNESS.id(), 0);
        assert_eq!(ProofId::custom(42).id(), 42);
    }

    #[test]
    fn test_proof_id_descriptions() {
        assert_eq!(ProofId::EXECUTION_WITNESS.identifier(), "execution_witness");
        assert_eq!(ProofId::custom(1).identifier(), "custom");
        assert_eq!(ProofId::EXECUTION_WITNESS.description(), "Execution witness proof");
        assert_eq!(ProofId::custom(42).description(), "Custom proof type 42");
    }

    #[test]
    fn test_subnet_id_validation() {
        assert!(SubnetId::new(0).is_ok());
        assert!(SubnetId::new(7).is_ok());
        assert!(SubnetId::new(8).is_err());
        assert!(SubnetId::new(100).is_err());
    }

    #[test]
    fn test_proof_id_subnet_mapping() {
        let proof_id = ProofId::custom(3);
        let subnet_id = proof_id.subnet_id();
        assert_eq!(subnet_id.id(), 3);
        assert_eq!(proof_id.subnet_topic(), "execution_proof_3");
    }
}