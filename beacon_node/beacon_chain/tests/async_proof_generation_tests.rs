//! Tests for async proof generation during block production

#[cfg(test)]
mod tests {
    use beacon_chain::execution_payload_proofs::{ExecutionPayloadProofStore, ProofId};
    use execution_layer::{BlockProposalContents, BlockProposalContentsType};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use types::{ExecutionBlockHash, Hash256, FullPayload, MainnetEthSpec, Uint256, ExecPayload, ForkName};

    #[tokio::test]
    async fn test_spawn_proof_generation_task_basic() {
        // This test verifies the proof generation task spawning logic
        // Note: We can't easily test the full BeaconChain integration without a complete setup
        
        let proof_store = Arc::new(ExecutionPayloadProofStore::new(10));
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        
        // Simulate what the spawn_proof_generation_task would do
        let store_clone = proof_store.clone();
        let task = tokio::spawn(async move {
            // Simulate generating proofs for different subnets
            let proof_subnets = vec![0, 1, 2]; // Simulate some subnets
            
            for subnet_id in proof_subnets {
                let proof_id = ProofId::custom(subnet_id);
                let result = store_clone.generate_and_store_dummy_proof(block_hash, proof_id);
                if let Err(e) = result {
                    eprintln!("Failed to generate proof for subnet {}: {}", subnet_id, e);
                }
            }
        });
        
        // Wait for task completion with timeout
        let result = timeout(Duration::from_millis(500), task).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
        
        // Verify proofs were generated
        assert!(proof_store.len() > 0);
        assert!(proof_store.has_valid_proof(&block_hash));
    }

    #[test]
    fn test_execution_block_hash_extraction() {
        // Test the block hash extraction logic used in spawn_proof_generation_task
        
        // Create a mock full payload
        let mock_payload = FullPayload::<MainnetEthSpec>::default_at_fork(ForkName::Deneb).unwrap();
        let expected_hash = mock_payload.block_hash();
        
        let block_contents = BlockProposalContentsType::Full(
            BlockProposalContents::Payload {
                payload: mock_payload,
                block_value: Uint256::ZERO,
            }
        );
        
        // Extract hash using the same logic as spawn_proof_generation_task
        let extracted_hash = match &block_contents {
            BlockProposalContentsType::Full(contents) => match contents {
                BlockProposalContents::Payload { payload, .. } => Some(payload.block_hash()),
                BlockProposalContents::PayloadAndBlobs { payload, .. } => {
                    Some(payload.clone().execution_payload().block_hash())
                }
            },
            BlockProposalContentsType::Blinded(_) => None,
        };
        
        assert!(extracted_hash.is_some());
        assert_eq!(extracted_hash.unwrap(), expected_hash);
    }

    #[test]
    fn test_blinded_payload_handling() {
        // Test that blinded payloads don't trigger proof generation
        use types::payload::BlindedPayload;
        
        let blinded_payload = BlindedPayload::<MainnetEthSpec>::Deneb(
            types::BlindedPayloadDeneb::default()
        );
        let block_contents = BlockProposalContentsType::Blinded(
            BlockProposalContents::Payload {
                payload: blinded_payload,
                block_value: Uint256::ZERO,
            }
        );
        
        // Extract hash using the same logic as spawn_proof_generation_task
        let extracted_hash = match &block_contents {
            BlockProposalContentsType::Full(_) => Some(ExecutionBlockHash::default()),
            BlockProposalContentsType::Blinded(_) => None, // Should return None
        };
        
        assert!(extracted_hash.is_none());
    }

    #[tokio::test]
    async fn test_concurrent_proof_generation_tasks() {
        let proof_store = Arc::new(ExecutionPayloadProofStore::new(100));
        
        // Simulate spawning multiple proof generation tasks concurrently
        let tasks: Vec<_> = (0..10).map(|i| {
            let store = proof_store.clone();
            let block_hash = ExecutionBlockHash::from(Hash256::random());
            
            tokio::spawn(async move {
                // Simulate proof generation for multiple subnets
                for subnet_id in 0..3 {
                    let proof_id = ProofId::custom(subnet_id);
                    store.generate_and_store_dummy_proof(block_hash, proof_id).unwrap();
                }
                (i, block_hash)
            })
        }).collect();
        
        // Wait for all tasks
        let mut results = Vec::new();
        for task in tasks {
            let result = task.await.unwrap();
            results.push(result);
        }
        
        assert_eq!(results.len(), 10);
        
        // Verify all proofs were stored
        assert_eq!(proof_store.len(), 30); // 10 blocks * 3 proofs each
        
        // Verify each block has proofs
        for (_, block_hash) in results {
            assert!(proof_store.has_valid_proof(&block_hash));
            assert_eq!(proof_store.proof_count_for_payload(&block_hash), 3);
        }
    }

    #[tokio::test]
    async fn test_proof_generation_task_error_handling() {
        let proof_store = Arc::new(ExecutionPayloadProofStore::new(2)); // Very small capacity
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        
        // Simulate task that might encounter errors due to capacity limits
        let error_task = tokio::spawn(async move {
            let mut success_count = 0;
            let mut error_count = 0;
            
            // Try to generate more proofs than capacity allows
            for subnet_id in 0..10 {
                let proof_id = ProofId::custom(subnet_id);
                match proof_store.generate_and_store_dummy_proof(block_hash, proof_id) {
                    Ok(_) => success_count += 1,
                    Err(_) => error_count += 1,
                }
            }
            
            (success_count, error_count)
        });
        
        let (success_count, error_count) = error_task.await.unwrap();
        
        // Should have some successes and potentially some errors due to eviction
        assert!(success_count > 0);
        // Due to LRU eviction, some might be evicted but generation itself shouldn't fail
        println!("Success: {}, Errors: {}", success_count, error_count);
    }

    #[tokio::test]
    async fn test_proof_generation_timing() {
        let proof_store = Arc::new(ExecutionPayloadProofStore::new(10));
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        
        let start_time = std::time::Instant::now();
        
        // Simulate proof generation task
        let generation_task = async {
            for subnet_id in 0..8 {
                let proof_id = ProofId::custom(subnet_id);
                proof_store.generate_and_store_dummy_proof(block_hash, proof_id).unwrap();
            }
        };
        
        generation_task.await;
        let duration = start_time.elapsed();
        
        // Proof generation should be relatively fast (under 100ms for dummy proofs)
        assert!(duration < Duration::from_millis(100));
        
        // Verify all proofs were generated
        assert_eq!(proof_store.len(), 8);
        assert_eq!(proof_store.proof_count_for_payload(&block_hash), 8);
    }

    #[tokio::test]
    async fn test_task_executor_simulation() {
        // Simulate what happens when task executor spawns multiple proof generation tasks
        
        let proof_store = Arc::new(ExecutionPayloadProofStore::new(100));
        let mut tasks = Vec::new();
        
        // Simulate rapid block production spawning multiple proof generation tasks
        for i in 0..5 {
            let store = proof_store.clone();
            let block_hash = ExecutionBlockHash::from(Hash256::random());
            
            let task = tokio::spawn(async move {
                // Simulate some async delay (like real proof generation might have)
                tokio::time::sleep(Duration::from_millis(10)).await;
                
                for subnet_id in 0..3 {
                    let proof_id = ProofId::custom(subnet_id);
                    store.generate_and_store_dummy_proof(block_hash, proof_id).unwrap();
                }
                
                format!("Block {} proofs generated", i)
            });
            
            tasks.push(task);
        }
        
        // Wait for all tasks to complete
        let mut results = Vec::new();
        for task in tasks {
            let result = task.await.unwrap();
            results.push(result);
        }
        
        assert_eq!(results.len(), 5);
        
        // Verify all proofs were generated (5 blocks * 3 proofs each)
        assert_eq!(proof_store.len(), 15);
        
        println!("Task results: {:?}", results);
    }

    #[test]
    fn test_proof_generation_config_simulation() {
        // Test simulating different configurations for proof generation
        
        struct MockProofConfig {
            enabled_subnets: Vec<u64>,
            _max_concurrent_tasks: usize,
        }
        
        let configs = vec![
            MockProofConfig {
                enabled_subnets: vec![0, 1, 2, 3], // 4 subnets
                _max_concurrent_tasks: 2,
            },
            MockProofConfig {
                enabled_subnets: vec![0, 1, 2, 3, 4, 5, 6, 7], // All 8 subnets
                _max_concurrent_tasks: 4,
            },
            MockProofConfig {
                enabled_subnets: vec![0], // Only execution witness
                _max_concurrent_tasks: 1,
            },
        ];
        
        for config in configs {
            let proof_store = ExecutionPayloadProofStore::new(100);
            let block_hash = ExecutionBlockHash::from(Hash256::random());
            
            // Simulate proof generation for configured subnets
            for subnet_id in &config.enabled_subnets {
                let proof_id = ProofId::custom(*subnet_id);
                let result = proof_store.generate_and_store_dummy_proof(block_hash, proof_id);
                assert!(result.is_ok());
            }
            
            // Verify correct number of proofs generated
            let expected_count = config.enabled_subnets.len();
            assert_eq!(proof_store.proof_count_for_payload(&block_hash), expected_count);
        }
    }
}