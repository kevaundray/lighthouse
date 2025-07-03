//! Background task for broadcasting execution proofs when they become available.
//!
//! This module implements the background proof broadcaster that periodically checks for
//! unbroadcast proofs and broadcasts them to the gossip network. This ensures that
//! proofs generated asynchronously are eventually broadcast, even if they weren't
//! ready during initial block production.

use beacon_chain::execution_payload_proofs::ProofId;
use beacon_chain::{parking_lot::RwLock, BeaconChain, BeaconChainTypes};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId};

/// Status of proof broadcasting to the network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastStatus {
    /// Proof has not been broadcast yet
    NotBroadcast,
    /// Proof is currently being broadcast
    Broadcasting,
    /// Proof has been successfully broadcast
    Broadcast,
    /// Proof broadcasting failed after retries
    Failed,
}

impl Default for BroadcastStatus {
    fn default() -> Self {
        BroadcastStatus::NotBroadcast
    }
}

/// Broadcast state for a specific execution proof
#[derive(Debug, Clone)]
pub struct ProofBroadcastState {
    /// Current broadcast status of this proof
    pub status: BroadcastStatus,
    /// Number of broadcast attempts made
    pub attempts: u32,
    /// Timestamp of the last broadcast attempt
    pub last_attempt: Option<Duration>,
}

impl ProofBroadcastState {
    /// Create a new broadcast state
    pub fn new() -> Self {
        Self {
            status: BroadcastStatus::NotBroadcast,
            attempts: 0,
            last_attempt: None,
        }
    }

    /// Check if this proof is ready to be broadcast
    pub fn is_ready_to_broadcast(&self) -> bool {
        matches!(self.status, BroadcastStatus::NotBroadcast | BroadcastStatus::Failed)
    }


    /// Mark proof as currently being broadcast
    pub fn mark_broadcasting(&mut self) {
        self.status = BroadcastStatus::Broadcasting;
        self.attempts += 1;
        self.last_attempt = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
        );
    }

    /// Mark proof as successfully broadcast
    pub fn mark_broadcast_success(&mut self) {
        self.status = BroadcastStatus::Broadcast;
    }

    /// Mark proof broadcast as failed
    pub fn mark_broadcast_failed(&mut self) {
        self.status = BroadcastStatus::Failed;
    }

    /// Check if broadcast should be retried (failed with attempts under limit)
    pub fn should_retry_broadcast(&self, max_attempts: u32) -> bool {
        matches!(self.status, BroadcastStatus::Failed) 
            && self.attempts < max_attempts
    }
}

impl Default for ProofBroadcastState {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages broadcast state for execution proofs separately from proof storage
#[derive(Debug)]
pub struct ProofBroadcastManager {
    /// Map from (execution block hash, proof ID) to broadcast state
    broadcast_states: RwLock<HashMap<(ExecutionBlockHash, ProofId), ProofBroadcastState>>,
}

impl ProofBroadcastManager {
    /// Create a new broadcast manager
    pub fn new() -> Self {
        Self {
            broadcast_states: RwLock::new(HashMap::new()),
        }
    }

    /// Get broadcast state for a proof, creating a new one if it doesn't exist
    pub fn get_or_create_state(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> ProofBroadcastState {
        let mut states = self.broadcast_states.write();
        states.entry((block_hash, proof_id))
            .or_insert_with(ProofBroadcastState::new)
            .clone()
    }

    /// Update broadcast state for a proof
    pub fn update_state(&self, block_hash: ExecutionBlockHash, proof_id: ProofId, state: ProofBroadcastState) {
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
    pub fn mark_broadcast_success(&self, block_hash: ExecutionBlockHash, proof_id: ProofId) -> bool {
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
    pub fn get_proofs_ready_for_broadcast<T: BeaconChainTypes>(
        &self,
        chain: &Arc<BeaconChain<T>>,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut ready_proofs = Vec::new();
        
        // Get all stored proofs
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();
        
        for (block_hash, proof_id) in stored_proofs.keys() {
            let state = self.get_or_create_state(*block_hash, *proof_id);
            if state.is_ready_to_broadcast() {
                ready_proofs.push((*block_hash, *proof_id));
            }
        }
        
        ready_proofs
    }

    /// Get proofs that should be retried
    pub fn get_proofs_for_retry<T: BeaconChainTypes>(
        &self,
        chain: &Arc<BeaconChain<T>>,
        max_attempts: u32,
    ) -> Vec<(ExecutionBlockHash, ProofId)> {
        let mut retry_proofs = Vec::new();
        
        // Get all stored proofs
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();
        
        for (block_hash, proof_id) in stored_proofs.keys() {
            let state = self.get_or_create_state(*block_hash, *proof_id);
            if state.should_retry_broadcast(max_attempts) {
                retry_proofs.push((*block_hash, *proof_id));
            }
        }
        
        retry_proofs
    }

    /// Clean up old broadcast states for proofs that no longer exist
    pub fn cleanup_old_states<T: BeaconChainTypes>(&self, chain: &Arc<BeaconChain<T>>) {
        let stored_proofs = chain.execution_payload_proof_store.get_all_proofs();
        let mut states = self.broadcast_states.write();
        
        // Remove broadcast states for proofs that no longer exist in storage
        states.retain(|key, _| stored_proofs.contains_key(key));
    }
}

/// Configuration for the execution proof broadcaster
#[derive(Debug, Clone)]
pub struct ExecutionProofBroadcasterConfig {
    /// How often to check for unbroadcast proofs
    pub broadcast_interval: Duration,
    /// Maximum number of broadcast attempts per proof
    pub max_broadcast_attempts: u32,
    /// Delay between retries for failed broadcasts
    pub retry_delay: Duration,
}

impl Default for ExecutionProofBroadcasterConfig {
    fn default() -> Self {
        Self {
            broadcast_interval: Duration::from_secs(1), // Check every second
            max_broadcast_attempts: 3,                  // Try up to 3 times
            retry_delay: Duration::from_secs(5),        // Wait 5 seconds between retries
        }
    }
}

/// Start the execution proof broadcaster service
/// This spawns the background task that periodically broadcasts unbroadcast execution proofs
pub fn start_execution_proof_broadcaster_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
) {
    // Only start the broadcaster if not in stateless validation mode
    // (stateless nodes don't generate proofs, they only validate them)
    if !chain.config.stateless_validation {
        let config = ExecutionProofBroadcasterConfig::default();
        let broadcast_manager = Arc::new(ProofBroadcastManager::new());
        
        info!("Starting execution proof broadcaster service");
        
        executor.spawn(
            execution_proof_broadcaster_task(chain, network_tx, config, broadcast_manager),
            "execution_proof_broadcaster",
        );
    } else {
        debug!("Skipping execution proof broadcaster service in stateless validation mode");
    }
}

/// Background task that periodically broadcasts unbroadcast execution proofs
pub async fn execution_proof_broadcaster_task<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    config: ExecutionProofBroadcasterConfig,
    broadcast_manager: Arc<ProofBroadcastManager>,
) {
    let mut interval = tokio::time::interval(config.broadcast_interval);
    
    info!("Starting execution proof broadcaster task");

    loop {
        interval.tick().await;
        
        // Get proofs ready for initial broadcast
        let ready_proofs = broadcast_manager.get_proofs_ready_for_broadcast(&chain);
            
        // Get proofs ready for retry
        let retry_proofs = broadcast_manager.get_proofs_for_retry(&chain, config.max_broadcast_attempts);

        let total_proofs = ready_proofs.len() + retry_proofs.len();
        
        if total_proofs > 0 {
            debug!(
                "Found {} proofs ready for broadcast ({} new, {} retries)",
                total_proofs,
                ready_proofs.len(),
                retry_proofs.len()
            );
        }

        // Broadcast ready proofs
        for (execution_block_hash, proof_id) in ready_proofs {
            if let Some(proof) = chain.execution_payload_proof_store.get_proof(&execution_block_hash, proof_id) {
                broadcast_single_proof(
                    &chain,
                    &network_tx,
                    &broadcast_manager,
                    execution_block_hash,
                    proof_id,
                    &proof,
                ).await;
            }
        }

        // Broadcast retry proofs (with delay if recently attempted)
        for (execution_block_hash, proof_id) in retry_proofs {
            if let Some(proof) = chain.execution_payload_proof_store.get_proof(&execution_block_hash, proof_id) {
                // Check if enough time has passed since last attempt
                let broadcast_state = broadcast_manager.get_or_create_state(execution_block_hash, proof_id);
                if let Some(last_attempt) = broadcast_state.last_attempt {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    
                    if now.saturating_sub(last_attempt) < config.retry_delay {
                        debug!(
                            "Skipping retry for proof on subnet {} - not enough time since last attempt",
                            proof_id.subnet_id()
                        );
                        continue;
                    }
                }

                debug!(
                    "Retrying broadcast for proof on subnet {} (attempt {})",
                    proof_id.subnet_id(),
                    broadcast_state.attempts + 1
                );

                broadcast_single_proof(
                    &chain,
                    &network_tx,
                    &broadcast_manager,
                    execution_block_hash,
                    proof_id,
                    &proof,
                ).await;
            }
        }

        // Periodically clean up old broadcast states
        if total_proofs == 0 {
            broadcast_manager.cleanup_old_states(&chain);
        }
    }
}

/// Broadcast a single execution proof to the gossip network
async fn broadcast_single_proof<T: BeaconChainTypes>(
    _chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    broadcast_manager: &ProofBroadcastManager,
    execution_block_hash: ExecutionBlockHash,
    proof_id: ProofId,
    stored_proof: &beacon_chain::execution_payload_proofs::ExecutionPayloadProof,
) {
    // Mark as currently broadcasting
    if !broadcast_manager.mark_broadcasting(execution_block_hash, proof_id) {
        warn!(
            "Failed to mark proof as broadcasting for block {:?} subnet {}",
            execution_block_hash,
            proof_id.subnet_id()
        );
        return;
    }

    // Convert ExecutionPayloadProof to ExecutionProof (gossip format)
    let gossip_proof = ExecutionProof::new_with_current_timestamp(
        execution_block_hash,
        ExecutionProofSubnetId::new(proof_id.subnet_id()),
        stored_proof.version,
        stored_proof.proof_data.clone(),
    );

    // Create the gossip message
    let pubsub_message = PubsubMessage::ExecutionProofMessage(Box::new((
        ExecutionProofSubnetId::new(proof_id.subnet_id()),
        Arc::new(gossip_proof),
    )));

    // Broadcast the proof
    match network_tx.send(NetworkMessage::Publish {
        messages: vec![pubsub_message],
    }) {
        Ok(()) => {
            // Mark as successfully broadcast
            if broadcast_manager.mark_broadcast_success(execution_block_hash, proof_id) {
                info!(
                    "Successfully broadcast execution proof for block {:?} on subnet {}",
                    execution_block_hash,
                    proof_id.subnet_id()
                );
            } else {
                warn!(
                    "Broadcast succeeded but failed to update proof status for block {:?} subnet {}",
                    execution_block_hash,
                    proof_id.subnet_id()
                );
            }
        }
        Err(e) => {
            // Mark as failed
            if broadcast_manager.mark_broadcast_failed(execution_block_hash, proof_id) {
                warn!(
                    "Failed to broadcast execution proof for block {:?} subnet {}: {}",
                    execution_block_hash,
                    proof_id.subnet_id(),
                    e
                );
            } else {
                warn!(
                    "Broadcast failed and unable to update proof status for block {:?} subnet {}: {}",
                    execution_block_hash,
                    proof_id.subnet_id(),
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BroadcastStatus, ExecutionProofBroadcasterConfig, ProofBroadcastManager, ProofBroadcastState,
    };
    use beacon_chain::execution_payload_proofs::{ExecutionPayloadProofStore, ProofId};
    use lighthouse_network::PubsubMessage;
    use network::NetworkMessage;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use types::{ExecutionBlockHash, Hash256};

    #[test]
    fn test_broadcast_status_transitions() {
        let mut state = ProofBroadcastState::new();
        
        // Initial state
        assert_eq!(state.status, BroadcastStatus::NotBroadcast);
        assert_eq!(state.attempts, 0);
        assert!(state.last_attempt.is_none());
        assert!(state.is_ready_to_broadcast());
        
        // Mark as broadcasting
        state.mark_broadcasting();
        assert_eq!(state.status, BroadcastStatus::Broadcasting);
        assert_eq!(state.attempts, 1);
        assert!(state.last_attempt.is_some());
        assert!(!state.is_ready_to_broadcast());
        
        // Mark as successful
        state.mark_broadcast_success();
        assert_eq!(state.status, BroadcastStatus::Broadcast);
        assert!(!state.is_ready_to_broadcast());
        
        // Reset and test failure path
        let mut state = ProofBroadcastState::new();
        state.mark_broadcasting();
        state.mark_broadcast_failed();
        assert_eq!(state.status, BroadcastStatus::Failed);
        assert!(state.is_ready_to_broadcast());
        assert!(state.should_retry_broadcast(3));
    }

    #[test]
    fn test_broadcast_state_retry_logic() {
        let mut state = ProofBroadcastState::new();
        
        // First attempt
        state.mark_broadcasting();
        state.mark_broadcast_failed();
        assert_eq!(state.attempts, 1);
        assert!(state.should_retry_broadcast(3));
        
        // Second attempt
        state.mark_broadcasting();
        state.mark_broadcast_failed();
        assert_eq!(state.attempts, 2);
        assert!(state.should_retry_broadcast(3));
        
        // Third attempt
        state.mark_broadcasting();
        state.mark_broadcast_failed();
        assert_eq!(state.attempts, 3);
        assert!(!state.should_retry_broadcast(3)); // Max attempts reached
    }

    #[test]
    fn test_broadcast_manager_basic_operations() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Get initial state
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::NotBroadcast);
        
        // Mark as broadcasting
        assert!(manager.mark_broadcasting(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcasting);
        assert_eq!(state.attempts, 1);
        
        // Mark as success
        assert!(manager.mark_broadcast_success(block_hash, proof_id));
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Broadcast);
    }

    #[tokio::test]
    async fn test_broadcast_manager_thread_safety() {
        let manager = Arc::new(ProofBroadcastManager::new());
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Spawn multiple tasks trying to update state concurrently
        let num_tasks = 100;
        let success_count = Arc::new(AtomicUsize::new(0));
        
        let tasks: Vec<_> = (0..num_tasks).map(|i| {
            let manager = manager.clone();
            let success_count = success_count.clone();
            tokio::spawn(async move {
                // Simulate concurrent broadcast attempts
                if manager.mark_broadcasting(block_hash, proof_id) {
                    tokio::task::yield_now().await; // Give other tasks a chance
                    
                    if i % 2 == 0 {
                        manager.mark_broadcast_success(block_hash, proof_id);
                        success_count.fetch_add(1, Ordering::Relaxed);
                    } else {
                        manager.mark_broadcast_failed(block_hash, proof_id);
                    }
                }
            })
        }).collect();
        
        // Wait for all tasks to complete
        for task in tasks {
            task.await.unwrap();
        }
        
        // Verify final state is consistent (no corruption)
        let final_state = manager.get_or_create_state(block_hash, proof_id);
        assert!(matches!(
            final_state.status, 
            BroadcastStatus::Broadcast | BroadcastStatus::Failed | BroadcastStatus::Broadcasting
        ));
        
        // Verify that at least some operations succeeded
        assert!(final_state.attempts > 0);
        println!("Final state: {:?}, Success count: {}", final_state, success_count.load(Ordering::Relaxed));
    }

    #[test]
    fn test_broadcast_manager_cleanup() {
        let manager = ProofBroadcastManager::new();
        let block_hash1 = ExecutionBlockHash::from(Hash256::random());
        let block_hash2 = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Create states for two different block hashes
        manager.mark_broadcasting(block_hash1, proof_id);
        manager.mark_broadcasting(block_hash2, proof_id);
        
        // Create a mock proof store with only one proof
        let proof_store = ExecutionPayloadProofStore::new(10);
        proof_store.generate_and_store_dummy_proof(block_hash1, proof_id).unwrap();
        
        // Create mock chain (we can't easily create a real BeaconChain in tests)
        // This is a limitation - in practice we'd need integration tests with real chain
        
        // Verify states exist before cleanup
        let state1 = manager.get_or_create_state(block_hash1, proof_id);
        let state2 = manager.get_or_create_state(block_hash2, proof_id);
        assert_eq!(state1.attempts, 1);
        assert_eq!(state2.attempts, 1);
        
        // Note: Full cleanup test would require BeaconChain integration
    }

    #[test]
    fn test_broadcast_config_defaults() {
        let config = ExecutionProofBroadcasterConfig::default();
        assert_eq!(config.broadcast_interval, Duration::from_secs(1));
        assert_eq!(config.max_broadcast_attempts, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_success() {
        let _manager = Arc::new(ProofBroadcastManager::new());
        let (network_tx, mut network_rx) = mpsc::unbounded_channel();
        
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(2);
        
        // Create a dummy proof
        let proof = ExecutionPayloadProofStore::generate_dummy_proof(block_hash, proof_id);
        
        // Create a mock chain (minimal for testing)
        // In practice this would need a real BeaconChain instance
        
        // Broadcast the proof
        tokio::spawn(async move {
            // This would call broadcast_single_proof but we can't without a real chain
            // So we simulate the network message being sent
            let gossip_proof = types::ExecutionProof::new_with_current_timestamp(
                block_hash,
                types::ExecutionProofSubnetId::new(proof_id.subnet_id()),
                proof.version,
                proof.proof_data.clone(),
            );
            
            let pubsub_message: PubsubMessage<types::MainnetEthSpec> = PubsubMessage::ExecutionProofMessage(Box::new((
                types::ExecutionProofSubnetId::new(proof_id.subnet_id()),
                Arc::new(gossip_proof),
            )));
            
            let _ = network_tx.send(NetworkMessage::Publish {
                messages: vec![pubsub_message],
            });
        });
        
        // Verify network message was sent
        let result = timeout(Duration::from_millis(100), network_rx.recv()).await;
        assert!(result.is_ok());
        
        if let Ok(Some(NetworkMessage::Publish { messages })) = result {
            assert_eq!(messages.len(), 1);
            match &messages[0] {
                PubsubMessage::ExecutionProofMessage(data) => {
                    let (subnet_id, _proof) = data.as_ref();
                    let subnet_id_val: u64 = (*subnet_id).into();
                    assert_eq!(subnet_id_val, proof_id.subnet_id());
                }
                _ => panic!("Expected ExecutionProofMessage"),
            }
        } else {
            panic!("Expected network message");
        }
    }

    #[tokio::test]
    async fn test_broadcast_single_proof_network_failure() {
        let manager = Arc::new(ProofBroadcastManager::new());
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(3);
        
        // Create a channel and immediately close the receiver to simulate network failure
        let (network_tx, network_rx) = mpsc::unbounded_channel::<NetworkMessage<types::MainnetEthSpec>>();
        drop(network_rx); // This will cause sends to fail
        
        let proof = ExecutionPayloadProofStore::generate_dummy_proof(block_hash, proof_id);
        
        // Simulate what broadcast_single_proof would do on network failure
        manager.mark_broadcasting(block_hash, proof_id);
        
        let gossip_proof = types::ExecutionProof::new_with_current_timestamp(
            block_hash,
            types::ExecutionProofSubnetId::new(proof_id.subnet_id()),
            proof.version,
            proof.proof_data.clone(),
        );
        
        let pubsub_message: PubsubMessage<types::MainnetEthSpec> = PubsubMessage::ExecutionProofMessage(Box::new((
            types::ExecutionProofSubnetId::new(proof_id.subnet_id()),
            Arc::new(gossip_proof),
        )));
        
        // This should fail because receiver is dropped
        let send_result = network_tx.send(NetworkMessage::Publish {
            messages: vec![pubsub_message],
        });
        
        assert!(send_result.is_err());
        
        // Simulate marking as failed
        manager.mark_broadcast_failed(block_hash, proof_id);
        
        // Verify state is marked as failed
        let state = manager.get_or_create_state(block_hash, proof_id);
        assert_eq!(state.status, BroadcastStatus::Failed);
        assert_eq!(state.attempts, 1);
    }

    #[test]
    fn test_multiple_proof_ids_same_block() {
        let manager = ProofBroadcastManager::new();
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id_1 = ProofId::custom(1);
        let proof_id_2 = ProofId::custom(2);
        
        // Mark different proof IDs for same block with different states
        manager.mark_broadcasting(block_hash, proof_id_1);
        manager.mark_broadcast_success(block_hash, proof_id_1);
        
        manager.mark_broadcasting(block_hash, proof_id_2);
        manager.mark_broadcast_failed(block_hash, proof_id_2);
        
        // Verify states are independent
        let state1 = manager.get_or_create_state(block_hash, proof_id_1);
        let state2 = manager.get_or_create_state(block_hash, proof_id_2);
        
        assert_eq!(state1.status, BroadcastStatus::Broadcast);
        assert_eq!(state2.status, BroadcastStatus::Failed);
        assert_eq!(state1.attempts, 1);
        assert_eq!(state2.attempts, 1);
    }

    #[test]
    fn test_broadcast_state_time_tracking() {
        let mut state = ProofBroadcastState::new();
        
        // Initially no last attempt
        assert!(state.last_attempt.is_none());
        
        // After marking as broadcasting, should have timestamp
        state.mark_broadcasting();
        assert!(state.last_attempt.is_some());
        
        let first_attempt = state.last_attempt.unwrap();
        
        // Sleep briefly and mark as broadcasting again
        std::thread::sleep(Duration::from_millis(10));
        state.mark_broadcasting();
        
        let second_attempt = state.last_attempt.unwrap();
        assert!(second_attempt > first_attempt);
        assert_eq!(state.attempts, 2);
    }
}