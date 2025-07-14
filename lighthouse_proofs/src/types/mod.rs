//! Core proof types

mod proof_id;
mod network;
mod storage;
mod payload;

pub use proof_id::{ProofId, SubnetId, MAX_EXECUTION_PROOF_SUBNETS};
pub use network::ExecutionProof;
pub use storage::ExecutionPayloadProof;
pub use payload::ErasedExecutionPayload;

// Re-export types from the types crate that we use
pub use types::{ExecutionBlockHash, Hash256, Slot, EthSpec, ExecutionPayload};