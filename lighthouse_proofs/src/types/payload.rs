//! Type-erased execution payload for trait object safety

use types::{EthSpec, ExecutionPayload, ExecutionBlockHash};
use serde::{Deserialize, Serialize};

/// Type-erased execution payload that can be used with trait objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasedExecutionPayload {
    pub block_hash: ExecutionBlockHash,
    pub block_number: u64,
    pub parent_hash: ExecutionBlockHash,
    pub timestamp: u64,
    /// Serialized payload data
    pub payload_bytes: Vec<u8>,
}

impl ErasedExecutionPayload {
    /// Create from a concrete ExecutionPayload
    pub fn from_payload<E: EthSpec>(payload: &ExecutionPayload<E>) -> Self {
        Self {
            block_hash: payload.block_hash(),
            block_number: payload.block_number(),
            parent_hash: payload.parent_hash(),
            timestamp: payload.timestamp(),
            // In a real implementation, this would serialize the full payload
            payload_bytes: vec![],
        }
    }
}