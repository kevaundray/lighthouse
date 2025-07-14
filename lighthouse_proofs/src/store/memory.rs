//! In-memory proof storage with LRU eviction

use super::{ProofStore, ProofStoreMetrics};
use crate::types::{ExecutionBlockHash, ExecutionPayloadProof, ProofId};
use crate::{Error, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// In-memory proof store with LRU eviction
pub struct MemoryProofStore {
    /// Map from (execution block hash, proof ID) to proof
    proofs: Arc<RwLock<HashMap<(ExecutionBlockHash, ProofId), ExecutionPayloadProof>>>,
    /// Maximum number of proofs to store
    max_proofs: usize,
    /// Metrics
    evictions: AtomicU64,
    successful_stores: AtomicU64,
    failed_stores: AtomicU64,
}

impl MemoryProofStore {
    /// Create a new memory proof store with given capacity
    pub fn new(max_proofs: usize) -> Self {
        Self {
            proofs: Arc::new(RwLock::new(HashMap::new())),
            max_proofs,
            evictions: AtomicU64::new(0),
            successful_stores: AtomicU64::new(0),
            failed_stores: AtomicU64::new(0),
        }
    }

    /// Validate a proof before storage
    fn validate_proof(proof: &ExecutionPayloadProof) -> Result<()> {
        // Basic validation
        if proof.proof_data.is_empty() {
            return Err(Error::InvalidProof {
                block_hash: proof.block_hash,
                subnet_id: proof.proof_id.id(),
                reason: "Empty proof data".to_string(),
            });
        }

        if !proof.is_version_supported() {
            return Err(Error::InvalidProof {
                block_hash: proof.block_hash,
                subnet_id: proof.proof_id.id(),
                reason: format!("Unsupported version: {}", proof.version),
            });
        }

        Ok(())
    }

    /// Evict the oldest proof if at capacity
    fn evict_if_needed(&self, proofs: &mut HashMap<(ExecutionBlockHash, ProofId), ExecutionPayloadProof>) {
        if proofs.len() >= self.max_proofs {
            // Find and remove the oldest proof
            if let Some(oldest_key) = proofs
                .iter()
                .min_by_key(|(_, proof)| proof.timestamp)
                .map(|(key, _)| *key)
            {
                proofs.remove(&oldest_key);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[async_trait]
impl ProofStore for MemoryProofStore {
    async fn store_proof(&self, proof: ExecutionPayloadProof) -> Result<()> {
        // Validate before storing
        Self::validate_proof(&proof)?;
        self.store_validated_proof(proof).await
    }

    async fn store_validated_proof(&self, proof: ExecutionPayloadProof) -> Result<()> {
        let mut proofs = self.proofs.write();
        
        // Check capacity and evict if needed
        self.evict_if_needed(&mut proofs);
        
        let key = (proof.block_hash, proof.proof_id);
        proofs.insert(key, proof);
        
        self.successful_stores.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn get_proof(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> Option<ExecutionPayloadProof> {
        let proofs = self.proofs.read();
        proofs.get(&(*block_hash, proof_id)).cloned()
    }

    async fn get_proofs(&self, block_hash: &ExecutionBlockHash) -> Vec<ExecutionPayloadProof> {
        let proofs = self.proofs.read();
        proofs
            .iter()
            .filter_map(|((hash, _), proof)| {
                if hash == block_hash {
                    Some(proof.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    async fn has_valid_proof(&self, block_hash: &ExecutionBlockHash) -> bool {
        let proofs = self.proofs.read();
        proofs.keys().any(|(hash, _)| hash == block_hash)
    }

    async fn has_valid_proof_for_id(
        &self,
        block_hash: &ExecutionBlockHash,
        proof_id: ProofId,
    ) -> bool {
        let proofs = self.proofs.read();
        proofs.contains_key(&(*block_hash, proof_id))
    }

    async fn proof_count_for_payload(&self, block_hash: &ExecutionBlockHash) -> usize {
        let proofs = self.proofs.read();
        proofs
            .keys()
            .filter(|(hash, _)| hash == block_hash)
            .count()
    }

    async fn len(&self) -> usize {
        self.proofs.read().len()
    }

    async fn unique_payload_count(&self) -> usize {
        let proofs = self.proofs.read();
        let unique_hashes: std::collections::HashSet<ExecutionBlockHash> =
            proofs.keys().map(|(hash, _)| *hash).collect();
        unique_hashes.len()
    }

    async fn clear(&self) -> Result<()> {
        self.proofs.write().clear();
        Ok(())
    }

    async fn prune_old_proofs(&self, cutoff_timestamp: u64) -> Result<usize> {
        let mut proofs = self.proofs.write();
        let initial_len = proofs.len();
        proofs.retain(|_, proof| proof.timestamp >= cutoff_timestamp);
        let pruned = initial_len - proofs.len();
        Ok(pruned)
    }

    async fn metrics(&self) -> ProofStoreMetrics {
        // Get metrics data without holding lock across await
        let (total_proofs, proofs_by_type, capacity_percent) = {
            let proofs = self.proofs.read();
            
            // Count proofs by type
            let mut proof_counts: HashMap<String, usize> = HashMap::new();
            for (_, proof) in proofs.iter() {
                *proof_counts.entry(proof.identifier()).or_insert(0) += 1;
            }
            
            let proofs_by_type: Vec<(String, usize)> = proof_counts.into_iter().collect();
            let total = proofs.len();
            let capacity_percent = (total as f64 / self.max_proofs as f64) * 100.0;
            
            (total, proofs_by_type, capacity_percent)
        };
        
        // Now we can safely await without holding the lock
        let unique_payloads = self.unique_payload_count().await;
        
        ProofStoreMetrics {
            total_proofs,
            unique_payloads,
            proofs_by_type,
            capacity_used_percent: capacity_percent,
            evictions: self.evictions.load(Ordering::Relaxed),
            successful_stores: self.successful_stores.load(Ordering::Relaxed),
            failed_stores: self.failed_stores.load(Ordering::Relaxed),
        }
    }
    
    async fn cleanup_finalized_blocks(&self, _finalized_roots: Vec<types::Hash256>) -> usize {
        // TODO: In a real implementation, we would need to track the mapping
        // between beacon block roots and execution block hashes to properly clean up.
        // For now, return 0 as we don't have this mapping in the simple memory store.
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash256;

    #[tokio::test]
    async fn test_memory_store_basic_operations() {
        let store = MemoryProofStore::new(10);
        let block_hash = ExecutionBlockHash::from(Hash256::random());
        let proof_id = ProofId::custom(1);
        
        // Store a proof
        let proof = ExecutionPayloadProof::new_v1(block_hash, proof_id, vec![1, 2, 3]);
        assert!(store.store_proof(proof.clone()).await.is_ok());
        
        // Verify storage
        assert!(store.has_valid_proof(&block_hash).await);
        assert!(store.has_valid_proof_for_id(&block_hash, proof_id).await);
        assert_eq!(store.len().await, 1);
        
        // Retrieve proof
        let retrieved = store.get_proof(&block_hash, proof_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().proof_data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_memory_store_lru_eviction() {
        let store = MemoryProofStore::new(2);
        
        // Store 3 proofs with controlled timestamps
        let mut proof1 = ExecutionPayloadProof::new_v1(
            ExecutionBlockHash::from(Hash256::random()),
            ProofId::EXECUTION_WITNESS,
            vec![1],
        );
        proof1.timestamp = 100;
        
        let mut proof2 = ExecutionPayloadProof::new_v1(
            ExecutionBlockHash::from(Hash256::random()),
            ProofId::custom(1),
            vec![2],
        );
        proof2.timestamp = 200;
        
        let proof3 = ExecutionPayloadProof::new_v1(
            ExecutionBlockHash::from(Hash256::random()),
            ProofId::custom(2),
            vec![3],
        );
        
        // Store all proofs
        assert!(store.store_validated_proof(proof1.clone()).await.is_ok());
        assert!(store.store_validated_proof(proof2.clone()).await.is_ok());
        assert!(store.store_validated_proof(proof3.clone()).await.is_ok());
        
        // Should have evicted the oldest (proof1)
        assert_eq!(store.len().await, 2);
        assert!(!store.has_valid_proof(&proof1.block_hash).await);
        assert!(store.has_valid_proof(&proof2.block_hash).await);
        assert!(store.has_valid_proof(&proof3.block_hash).await);
        
        // Check metrics
        let metrics = store.metrics().await;
        assert_eq!(metrics.evictions, 1);
    }
}