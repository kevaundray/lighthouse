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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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