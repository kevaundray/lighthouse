//! Proof broadcast manager

use super::{BroadcastStatus, ProofBroadcastState};
use crate::types::{ExecutionBlockHash, ProofId};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Manages broadcast state for execution proofs
#[derive(Debug)]
pub struct ProofBroadcastManager {
    /// Map from (execution block hash, proof ID) to broadcast state
    broadcast_states: Arc<RwLock<HashMap<(ExecutionBlockHash, ProofId), ProofBroadcastState>>>,
}

impl ProofBroadcastManager {
    /// Create a new broadcast manager
    pub fn new() -> Self {
        Self {
            broadcast_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get broadcast state for a proof, creating a new one if it doesn't exist
    pub fn get_or_create_state(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
    ) -> ProofBroadcastState {
        let mut states = self.broadcast_states.write();
        states
            .entry((block_hash, proof_id))
            .or_insert_with(ProofBroadcastState::new)
            .clone()
    }

    /// Update broadcast state for a proof
    pub fn update_state(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
        state: ProofBroadcastState,
    ) {
        let mut states = self.broadcast_states.write();
        states.insert((block_hash, proof_id), state);
    }

    /// Mark a proof as being broadcast
    pub fn mark_broadcasting(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcasting();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Mark a proof as successfully broadcast
    pub fn mark_broadcast_success(
        &self,
        block_hash: ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcast_success();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Mark a proof broadcast as failed
    pub fn mark_broadcast_failed(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> bool {
        let mut state = self.get_or_create_state(block_hash, proof_id);
        state.mark_broadcast_failed();
        self.update_state(block_hash, proof_id, state);
        true
    }

    /// Get all proofs ready for broadcast
    pub fn get_proofs_ready_for_broadcast(
        &self,
        available_proofs: &[(ExecutionBlockHash, ProofId)],
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        available_proofs
            .iter()
            .filter(|(block_hash, proof_id)| {
                let state = self.get_or_create_state(*block_hash, *proof_id);
                state.is_ready_to_broadcast()
            })
            .copied()
            .collect()
    }

    /// Get proofs that should be retried
    pub fn get_proofs_for_retry(
        &self,
        available_proofs: &[(ExecutionBlockHash, ProofId)],
        max_attempts: u32,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        available_proofs
            .iter()
            .filter(|(block_hash, proof_id)| {
                let state = self.get_or_create_state(*block_hash, *proof_id);
                state.should_retry_broadcast(max_attempts)
            })
            .copied()
            .collect()
    }

    /// Clean up old broadcast states
    pub fn cleanup_old_states(&self, current_proofs: &[(ExecutionBlockHash, ProofId)]) {
        let current_set: std::collections::HashSet<_> = current_proofs.iter().copied().collect();
        let mut states = self.broadcast_states.write();
        states.retain(|key, _| current_set.contains(key));
    }

    /// Get broadcast statistics
    pub fn get_statistics(&self) -> BroadcastStatistics {
        let states = self.broadcast_states.read();
        
        let mut stats = BroadcastStatistics::default();
        
        for (_, state) in states.iter() {
            match state.status {
                BroadcastStatus::NotBroadcast => stats.not_broadcast += 1,
                BroadcastStatus::Broadcasting => stats.broadcasting += 1,
                BroadcastStatus::Broadcast => stats.broadcast += 1,
                BroadcastStatus::Failed => stats.failed += 1,
            }
            stats.total_attempts += state.attempts as u64;
        }
        
        stats.total = states.len();
        stats
    }
}

impl Default for ProofBroadcastManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about broadcast states
#[derive(Debug, Default, Clone)]
pub struct BroadcastStatistics {
    pub total: usize,
    pub not_broadcast: usize,
    pub broadcasting: usize,
    pub broadcast: usize,
    pub failed: usize,
    pub total_attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash256;

    #[test]
    fn test_broadcast_manager_states() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Initial state
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::NotBroadcast);
        assert!(state.is_ready_to_broadcast());
        
        // Mark as broadcasting
        assert!(manager.mark_broadcasting(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcasting);
        assert!(!state.is_ready_to_broadcast());
        
        // Mark as successful
        assert!(manager.mark_broadcast_success(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcast);
        assert!(!state.is_ready_to_broadcast());
    }

    #[test]
    fn test_get_ready_proofs() {
        let manager = ProofBroadcastManager::new();
        
        let proof1 = (ExecutionBlockHash::from(Hash256::random()), ProofId::custom(1));
        let proof2 = (ExecutionBlockHash::from(Hash256::random()), ProofId::custom(2));
        let proof3 = (ExecutionBlockHash::from(Hash256::random()), ProofId::custom(3));
        
        // Mark proof2 as already broadcast
        manager.mark_broadcast_success(proof2.0, proof2.1);
        
        let available = vec![proof1, proof2, proof3];
        let ready = manager.get_proofs_ready_for_broadcast(&available);
        
        assert_eq!(ready.len(), 2); // proof1 and proof3 are ready
        assert!(ready.contains(&proof1));
        assert!(ready.contains(&proof3));
        assert!(!ready.contains(&proof2));
    }
}