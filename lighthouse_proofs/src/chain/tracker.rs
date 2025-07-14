//! Proven chain tracker implementation

use super::{ProvenBlockInfo, ProvenChainState};
use crate::types::{ExecutionBlockHash, Hash256, Slot};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

/// Tracks the proven canonical chain
pub struct ProvenChainTracker {
    /// Maps beacon block root to proven block information
    proven_blocks: Arc<RwLock<HashMap<Hash256, ProvenBlockInfo>>>,
    /// Current state of the proven chain
    state: Arc<RwLock<ProvenChainState>>,
    /// Reverse mapping: execution block hash -> beacon block roots
    execution_to_beacon: Arc<RwLock<HashMap<ExecutionBlockHash, Vec<Hash256>>>>,
}

impl ProvenChainTracker {
    /// Create a new proven chain tracker
    pub fn new() -> Self {
        Self {
            proven_blocks: Arc::new(RwLock::new(HashMap::new())),
            state: Arc::new(RwLock::new(ProvenChainState::default())),
            execution_to_beacon: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a block as proven
    pub fn mark_block_proven(&self, block_info: ProvenBlockInfo) {
        let beacon_root = block_info.beacon_block_root;
        let exec_hash = block_info.execution_block_hash;
        
        // Update proven blocks
        self.proven_blocks.write().insert(beacon_root, block_info.clone());
        
        // Update reverse mapping
        self.execution_to_beacon
            .write()
            .entry(exec_hash)
            .or_insert_with(Vec::new)
            .push(beacon_root);
        
        debug!(
            "Marked block as proven - beacon: {:?}, exec: {:?}, slot: {}",
            beacon_root, exec_hash, block_info.slot
        );
    }

    /// Check if a beacon block is proven
    pub fn is_block_proven(&self, beacon_block_root: &Hash256) -> bool {
        self.proven_blocks.read().contains_key(beacon_block_root)
    }

    /// Get proven block info
    pub fn get_proven_block(&self, beacon_block_root: &Hash256) -> Option<ProvenBlockInfo> {
        self.proven_blocks.read().get(beacon_block_root).cloned()
    }

    /// Get beacon blocks for an execution hash
    pub fn get_beacon_blocks_for_execution(
        &self,
        exec_hash: &ExecutionBlockHash,
    ) -> Vec<Hash256> {
        self.execution_to_beacon
            .read()
            .get(exec_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Update the proven chain state
    pub fn update_state(
        &self,
        proven_head: Option<(Hash256, Slot)>,
        proven_finalized: Option<(Hash256, Slot)>,
    ) {
        let mut state = self.state.write();
        state.proven_head = proven_head;
        state.proven_finalized = proven_finalized;
        state.chain_length = self.proven_blocks.read().len();
        state.last_update = Some(Instant::now());
        
        if let Some((head_root, head_slot)) = proven_head {
            info!(
                "Updated proven chain - head: {:?} at slot {}, length: {}",
                head_root, head_slot, state.chain_length
            );
        }
    }

    /// Get the current proven chain state
    pub fn get_state(&self) -> ProvenChainState {
        self.state.read().clone()
    }

    /// Get all proven blocks ordered by slot
    pub fn get_proven_chain(&self) -> Vec<ProvenBlockInfo> {
        let mut blocks: Vec<_> = self.proven_blocks.read().values().cloned().collect();
        blocks.sort_by_key(|b| b.slot);
        blocks
    }

    /// Clear all proven blocks
    pub fn clear(&self) {
        self.proven_blocks.write().clear();
        self.execution_to_beacon.write().clear();
        *self.state.write() = ProvenChainState::default();
    }

    /// Remove blocks older than a given slot
    pub fn prune_old_blocks(&self, min_slot: Slot) -> usize {
        let mut proven_blocks = self.proven_blocks.write();
        let mut execution_mapping = self.execution_to_beacon.write();
        
        let initial_len = proven_blocks.len();
        
        // Find blocks to remove
        let blocks_to_remove: Vec<_> = proven_blocks
            .iter()
            .filter(|(_, info)| info.slot < min_slot)
            .map(|(root, info)| (*root, info.execution_block_hash))
            .collect();
        
        // Remove from proven blocks
        for (root, exec_hash) in blocks_to_remove {
            proven_blocks.remove(&root);
            
            // Update execution mapping
            if let Some(beacon_roots) = execution_mapping.get_mut(&exec_hash) {
                beacon_roots.retain(|&r| r != root);
                if beacon_roots.is_empty() {
                    execution_mapping.remove(&exec_hash);
                }
            }
        }
        
        initial_len - proven_blocks.len()
    }
}

impl Default for ProvenChainTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proven_chain_tracker() {
        let tracker = ProvenChainTracker::new();
        
        // Create test block info
        let beacon_root = Hash256::random();
        let exec_hash = ExecutionBlockHash::from(Hash256::random());
        let block_info = ProvenBlockInfo::new(
            beacon_root,
            exec_hash,
            Slot::new(100),
            Hash256::random(),
            3,
        );
        
        // Mark block as proven
        tracker.mark_block_proven(block_info.clone());
        
        // Verify block is tracked
        assert!(tracker.is_block_proven(&beacon_root));
        assert_eq!(tracker.get_proven_block(&beacon_root).unwrap().slot, Slot::new(100));
        
        // Check reverse mapping
        let beacon_blocks = tracker.get_beacon_blocks_for_execution(&exec_hash);
        assert_eq!(beacon_blocks.len(), 1);
        assert_eq!(beacon_blocks[0], beacon_root);
        
        // Update state
        tracker.update_state(Some((beacon_root, Slot::new(100))), None);
        let state = tracker.get_state();
        assert_eq!(state.proven_head, Some((beacon_root, Slot::new(100))));
        assert_eq!(state.chain_length, 1);
    }

    #[test]
    fn test_prune_old_blocks() {
        let tracker = ProvenChainTracker::new();
        
        // Add blocks at different slots
        for i in 0..5 {
            let block_info = ProvenBlockInfo::new(
                Hash256::random(),
                ExecutionBlockHash::from(Hash256::random()),
                Slot::new(i * 10),
                Hash256::random(),
                1,
            );
            tracker.mark_block_proven(block_info);
        }
        
        assert_eq!(tracker.get_proven_chain().len(), 5);
        
        // Prune blocks older than slot 25
        let pruned = tracker.prune_old_blocks(Slot::new(25));
        assert_eq!(pruned, 3); // Blocks at slots 0, 10, 20 removed
        assert_eq!(tracker.get_proven_chain().len(), 2); // Blocks at slots 30, 40 remain
    }
}