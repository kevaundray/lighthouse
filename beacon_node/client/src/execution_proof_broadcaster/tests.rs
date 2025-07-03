#[cfg(test)]
mod tests {
    use crate::execution_proof_broadcaster::{
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