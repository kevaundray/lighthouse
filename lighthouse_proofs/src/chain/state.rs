//! Proven chain state types

use crate::types::{ExecutionBlockHash, Hash256, Slot};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Information about a block that has been proven with execution proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenBlockInfo {
    /// The beacon block root
    pub beacon_block_root: Hash256,
    /// The execution block hash
    pub execution_block_hash: ExecutionBlockHash,
    /// The slot of the block
    pub slot: Slot,
    /// The parent beacon block root
    pub parent_root: Hash256,
    /// Number of proofs available for this block
    pub proof_count: usize,
    /// When this block was marked as proven (timestamp in seconds)
    pub proven_at_timestamp: u64,
}

impl ProvenBlockInfo {
    /// Create a new proven block info
    pub fn new(
        beacon_block_root: Hash256,
        execution_block_hash: ExecutionBlockHash,
        slot: Slot,
        parent_root: Hash256,
        proof_count: usize,
    ) -> Self {
        Self {
            beacon_block_root,
            execution_block_hash,
            slot,
            parent_root,
            proof_count,
            proven_at_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// State of the proven chain
#[derive(Debug, Clone, Default)]
pub struct ProvenChainState {
    /// The current proven head (beacon block root, slot)
    pub proven_head: Option<(Hash256, Slot)>,
    /// The proven finalized checkpoint (beacon block root, slot)
    pub proven_finalized: Option<(Hash256, Slot)>,
    /// Number of blocks in the proven chain
    pub chain_length: usize,
    /// Last update timestamp
    pub last_update: Option<Instant>,
}