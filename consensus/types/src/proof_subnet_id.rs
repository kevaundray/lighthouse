//! Identifies each proof subnet by an integer identifier.
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

// Define the number of proof subnets - adjustable based on requirements
pub const PROOF_SUBNET_COUNT: u64 = 8;

lazy_static! {
    static ref PROOF_SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(PROOF_SUBNET_COUNT as usize);

        for i in 0..PROOF_SUBNET_COUNT {
            v.push(i.to_string());
        }
        v
    };
}

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProofSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

pub fn proof_subnet_id_to_string(i: u64) -> &'static str {
    if i < PROOF_SUBNET_COUNT {
        PROOF_SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below PROOF_SUBNET_COUNT")
    } else {
        "proof subnet id out of range"
    }
}

impl ProofSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    /// Get the subnet ID for a specific proof type.
    /// Each proof type maps to a dedicated subnet.
    pub fn for_proof_type(proof_type: crate::execution_proof::ProofType) -> Self {
        Self::new(proof_type as u64)
    }
    
    /// Get the subnet ID for SP1 zkVM proofs (subnet 0)
    pub fn sp1() -> Self {
        Self::new(0)
    }
    
    /// Get the subnet ID for Risc0 zkVM proofs (subnet 1) 
    pub fn risc0() -> Self {
        Self::new(1)
    }
    
    /// Get the subnet ID for execution witnesses (subnet 2)
    pub fn execution_witness() -> Self {
        Self::new(2)
    }
}

impl Display for ProofSubnetId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Deref for ProofSubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProofSubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for ProofSubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<u64> for ProofSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &ProofSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for ProofSubnetId {
    fn as_ref(&self) -> &str {
        proof_subnet_id_to_string(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_proof::ProofType;

    #[test]
    fn test_proof_subnet_id_creation() {
        let subnet_id = ProofSubnetId::new(5);
        assert_eq!(*subnet_id, 5);
        assert_eq!(subnet_id.to_string(), "5");
    }

    #[test]
    fn test_proof_type_mapping() {
        assert_eq!(ProofSubnetId::sp1(), ProofSubnetId::new(0));
        assert_eq!(ProofSubnetId::risc0(), ProofSubnetId::new(1));
        assert_eq!(ProofSubnetId::execution_witness(), ProofSubnetId::new(2));
        
        assert_eq!(ProofSubnetId::for_proof_type(ProofType::SP1Proof), ProofSubnetId::sp1());
        assert_eq!(ProofSubnetId::for_proof_type(ProofType::Risc0Proof), ProofSubnetId::risc0());
        assert_eq!(ProofSubnetId::for_proof_type(ProofType::ExecutionWitness), ProofSubnetId::execution_witness());
    }

    #[test]
    fn test_proof_subnet_conversions() {
        let subnet_id = ProofSubnetId::new(3);
        
        // Test From/Into
        let from_u64: ProofSubnetId = 3u64.into();
        assert_eq!(subnet_id, from_u64);
        
        let into_u64: u64 = subnet_id.into();
        assert_eq!(into_u64, 3);
        
        let ref_into_u64: u64 = (&subnet_id).into();
        assert_eq!(ref_into_u64, 3);
    }

    #[test]
    fn test_proof_subnet_string_conversion() {
        for i in 0..PROOF_SUBNET_COUNT {
            let subnet_id = ProofSubnetId::new(i);
            assert_eq!(subnet_id.as_ref(), i.to_string());
            assert_eq!(subnet_id.to_string(), i.to_string());
        }
        
        // Test out of range
        let out_of_range = proof_subnet_id_to_string(PROOF_SUBNET_COUNT + 1);
        assert_eq!(out_of_range, "proof subnet id out of range");
    }

    #[test]
    fn test_proof_subnet_bounds() {
        // Test edge cases
        let min = ProofSubnetId::new(0);
        let max = ProofSubnetId::new(PROOF_SUBNET_COUNT - 1);
        
        assert_eq!(*min, 0);
        assert_eq!(*max, PROOF_SUBNET_COUNT - 1);
        
        // Test that we can create subnets up to the limit
        let _valid = ProofSubnetId::new(PROOF_SUBNET_COUNT - 1);
    }

    #[test]
    fn test_proof_subnet_serialization() {
        let subnet_id = ProofSubnetId::new(42);
        
        // Test JSON serialization/deserialization
        let json = serde_json::to_string(&subnet_id).unwrap();
        let deserialized: ProofSubnetId = serde_json::from_str(&json).unwrap();
        
        assert_eq!(subnet_id, deserialized);
    }
}