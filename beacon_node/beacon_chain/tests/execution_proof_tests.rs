//! Tests for execution proof generation and async task management

use beacon_chain::execution_payload_proofs::{ExecutionPayloadProofStore, ProofId};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use types::{ExecutionBlockHash, Hash256};

#[tokio::test]
async fn test_execution_proof_store_concurrent_operations() {
    let store = Arc::new(ExecutionPayloadProofStore::new(100));
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    // Spawn multiple tasks generating proofs concurrently
    let tasks: Vec<_> = (0..10).map(|i| {
        let store = store.clone();
        let proof_id = ProofId::custom(i % 8); // Use different proof IDs
        tokio::spawn(async move {
            store.generate_and_store_dummy_proof(block_hash, proof_id)
        })
    }).collect();
    
    // Wait for all tasks and collect results
    let mut results = Vec::new();
    for task in tasks {
        let result = task.await.unwrap();
        results.push(result);
    }
    
    // Verify all succeeded
    assert_eq!(results.len(), 10);
    for result in results {
        assert!(result.is_ok());
    }
    
    // Verify proofs are stored
    let all_proofs = store.get_all_proofs();
    assert!(all_proofs.len() <= 8); // Max 8 unique proof IDs (0-7)
    
    // Verify all stored proofs are for the correct block hash
    for ((stored_hash, _), _) in &all_proofs {
        assert_eq!(*stored_hash, block_hash);
    }
}

#[tokio::test]
async fn test_proof_store_memory_management() {
    let store = ExecutionPayloadProofStore::new(5); // Small capacity
    
    // Generate more proofs than capacity
    let mut block_hashes = Vec::new();
    for _i in 0..10 {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        block_hashes.push(block_hash);
        
        // Add timestamp delay to ensure ordering
        tokio::time::sleep(Duration::from_millis(1)).await;
        
        let result = store.generate_and_store_dummy_proof(block_hash, ProofId::EXECUTION_WITNESS);
        assert!(result.is_ok());
    }
    
    // Should only have 5 proofs (capacity limit)
    assert_eq!(store.len(), 5);
    
    // Count how many of our generated proofs are still present
    let mut present_count = 0;
    for i in 0..10 {
        if store.has_valid_proof(&block_hashes[i]) {
            present_count += 1;
        }
    }
    assert_eq!(present_count, 5, "Exactly 5 proofs should be present in the store");
}

#[tokio::test]
async fn test_proof_validation_edge_cases() {
    let _store = ExecutionPayloadProofStore::new(10);
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    // Test with different proof versions
    let mut proof_v1 = ExecutionPayloadProofStore::generate_dummy_proof(
        block_hash, 
        ProofId::custom(1)
    );
    proof_v1.version = 1;
    assert!(ExecutionPayloadProofStore::validate_proof(&proof_v1));
    
    // Test with unsupported version
    let mut proof_v999 = ExecutionPayloadProofStore::generate_dummy_proof(
        block_hash, 
        ProofId::custom(1)
    );
    proof_v999.version = 999;
    assert!(!ExecutionPayloadProofStore::validate_proof(&proof_v999));
    
    // Test with empty proof data
    let mut proof_empty = ExecutionPayloadProofStore::generate_dummy_proof(
        block_hash, 
        ProofId::custom(1)
    );
    proof_empty.proof_data = Vec::new();
    assert!(!ExecutionPayloadProofStore::validate_proof(&proof_empty));
}

#[tokio::test]
async fn test_proof_store_cleanup_and_pruning() {
    let store = ExecutionPayloadProofStore::new(10);
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    // Generate proof with custom timestamp
    let mut proof = ExecutionPayloadProofStore::generate_dummy_proof(
        block_hash, 
        ProofId::EXECUTION_WITNESS
    );
    proof.timestamp = 1000; // Old timestamp
    
    store.store_validated_proof(proof);
    assert_eq!(store.len(), 1);
    
    // Prune old proofs
    let cutoff = 2000; // Newer than our proof
    store.prune_old_proofs(cutoff);
    
    // Proof should be removed
    assert_eq!(store.len(), 0);
    assert!(!store.has_valid_proof(&block_hash));
}

#[tokio::test]
async fn test_multiple_proof_types_per_payload() {
    let store = ExecutionPayloadProofStore::new(10);
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    // Store different proof types for the same payload
    let proof_types = vec![
        ProofId::EXECUTION_WITNESS,
        ProofId::custom(1),
        ProofId::custom(2),
        ProofId::custom(3),
    ];
    
    for proof_id in &proof_types {
        let result = store.generate_and_store_dummy_proof(block_hash, *proof_id);
        assert!(result.is_ok());
    }
    
    // Should have all proof types
    assert_eq!(store.len(), proof_types.len());
    assert_eq!(store.proof_count_for_payload(&block_hash), proof_types.len());
    
    // Verify each proof type exists
    for proof_id in &proof_types {
        assert!(store.has_valid_proof_for_id(&block_hash, *proof_id));
        let proof = store.get_proof(&block_hash, *proof_id);
        assert!(proof.is_some());
        assert_eq!(proof.unwrap().proof_id, *proof_id);
    }
    
    // Get all proofs for this payload
    let all_proofs = store.get_proofs(&block_hash);
    assert_eq!(all_proofs.len(), proof_types.len());
}

#[tokio::test]
async fn test_proof_store_error_handling() {
    let store = ExecutionPayloadProofStore::new(10);
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    // Test storing invalid proof
    let mut invalid_proof = ExecutionPayloadProofStore::generate_dummy_proof(
        block_hash, 
        ProofId::EXECUTION_WITNESS
    );
    invalid_proof.proof_data = Vec::new(); // Make it invalid
    
    let result = store.store_proof(invalid_proof);
    assert!(result.is_err());
    assert_eq!(store.len(), 0);
    
    // Test storing valid proof after invalid one
    let valid_result = store.generate_and_store_dummy_proof(block_hash, ProofId::EXECUTION_WITNESS);
    assert!(valid_result.is_ok());
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn test_concurrent_proof_access() {
    let store = Arc::new(ExecutionPayloadProofStore::new(100));
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    let proof_id = ProofId::EXECUTION_WITNESS;
    
    // Store initial proof
    store.generate_and_store_dummy_proof(block_hash, proof_id).unwrap();
    
    // Spawn multiple readers
    let read_tasks: Vec<_> = (0..20).map(|_| {
        let store = store.clone();
        tokio::spawn(async move {
            // Repeatedly read the proof
            for _ in 0..100 {
                let proof = store.get_proof(&block_hash, proof_id);
                assert!(proof.is_some());
                tokio::task::yield_now().await;
            }
        })
    }).collect();
    
    // Spawn a few writers
    let write_tasks: Vec<_> = (0..5).map(|i| {
        let store = store.clone();
        let new_block_hash = ExecutionBlockHash::from(Hash256::random());
        tokio::spawn(async move {
            let new_proof_id = ProofId::custom(i + 1);
            for _ in 0..10 {
                let result = store.generate_and_store_dummy_proof(new_block_hash, new_proof_id);
                assert!(result.is_ok());
                tokio::task::yield_now().await;
            }
        })
    }).collect();
    
    // Wait for all tasks
    for task in read_tasks {
        task.await.unwrap();
    }
    for task in write_tasks {
        task.await.unwrap();
    }
    
    // Verify original proof still exists
    assert!(store.has_valid_proof(&block_hash));
    assert!(store.get_proof(&block_hash, proof_id).is_some());
}

#[test]
fn test_proof_id_subnet_mapping() {
    // Test that ProofId correctly maps to subnet IDs
    for subnet_id in 0..16 {
        let proof_id = ProofId::custom(subnet_id);
        assert_eq!(proof_id.subnet_id(), subnet_id);
        assert_eq!(proof_id.id(), subnet_id);
        assert_eq!(proof_id.subnet_topic(), format!("execution_proof_{}", subnet_id));
    }
    
    // Test special execution witness proof
    let witness_proof = ProofId::EXECUTION_WITNESS;
    assert_eq!(witness_proof.subnet_id(), 0);
    assert_eq!(witness_proof.identifier(), "execution_witness");
}

#[tokio::test]
async fn test_proof_store_with_timeout() {
    let store = Arc::new(ExecutionPayloadProofStore::new(1000));
    
    // Test that operations complete within reasonable time
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    
    let generation_task = async {
        // Generate many proofs
        for i in 0..100 {
            let proof_id = ProofId::custom(i % 8);
            store.generate_and_store_dummy_proof(block_hash, proof_id).unwrap();
        }
    };
    
    // Should complete within 1 second
    let result = timeout(Duration::from_secs(1), generation_task).await;
    assert!(result.is_ok());
    
    // Verify proofs were stored
    assert!(store.len() > 0);
    assert!(store.has_valid_proof(&block_hash));
}

#[tokio::test]
async fn test_proof_store_unique_payload_count() {
    let store = ExecutionPayloadProofStore::new(100);
    
    // Create proofs for different block hashes
    let mut block_hashes = Vec::new();
    for _i in 0..10 {
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        block_hashes.push(block_hash);
        
        // Store multiple proof types for each block
        store.generate_and_store_dummy_proof(block_hash, ProofId::EXECUTION_WITNESS).unwrap();
        store.generate_and_store_dummy_proof(block_hash, ProofId::custom(1)).unwrap();
    }
    
    // Should have 20 total proofs (10 blocks * 2 proof types each)
    assert_eq!(store.len(), 20);
    
    // But only 10 unique payloads
    assert_eq!(store.unique_payload_count(), 10);
    
    // Verify proof count per payload
    for block_hash in &block_hashes {
        assert_eq!(store.proof_count_for_payload(block_hash), 2);
    }
}