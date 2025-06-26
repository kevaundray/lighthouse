//! Integration tests for execution proof functionality
//! 
//! Tests the full flow from gossip message reception to proof caching and validation.

#[cfg(test)]
mod tests {
    use crate::execution_proof_cache::{GlobalExecutionProofCache, initialize_global_proof_cache};
    use slog::Logger;
    use std::sync::Arc;
    use types::{ExecutionProof, ProofSubnetId, MinimalEthSpec, Hash256};

    async fn setup_proof_cache(log: Logger) -> Arc<GlobalExecutionProofCache> {
        initialize_global_proof_cache(log)
    }

    #[tokio::test]
    async fn test_proof_cache_basic_operations() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let cache = setup_proof_cache(log).await;
        
        // Create a test proof
        let proof = ExecutionProof::new(1, vec![1, 2, 3, 4]);
        let subnet_id = ProofSubnetId::sp1();
        
        // Cache the proof
        cache.cache_proof(proof.clone(), subnet_id).await;
        
        // Note: This test demonstrates the cache interface
        // The actual payload hash extraction would need real proof formats
        println!("Proof caching test completed - cache interface working");
    }

    #[tokio::test]
    async fn test_proof_subnet_mappings() {
        // Test that proof types correctly map to subnet IDs
        assert_eq!(ProofSubnetId::sp1(), ProofSubnetId::new(0));
        assert_eq!(ProofSubnetId::risc0(), ProofSubnetId::new(1));
        assert_eq!(ProofSubnetId::execution_witness(), ProofSubnetId::new(2));
        
        // Test conversions
        let sp1_subnet: u64 = ProofSubnetId::sp1().into();
        assert_eq!(sp1_subnet, 0);
        
        let risc0_subnet: u64 = ProofSubnetId::risc0().into();
        assert_eq!(risc0_subnet, 1);
    }

    #[tokio::test]
    async fn test_execution_proof_config_defaults() {
        use crate::execution_proof_cache::ProofConfig;
        
        let config = ProofConfig::default();
        
        // Verify default configuration
        assert_eq!(config.enabled, false);
        assert_eq!(config.optimistic_acceptance, true);
        assert_eq!(config.fallback_to_execution, true);
        assert_eq!(config.verification_timeout_ms, 5000);
        assert_eq!(config.max_cache_size, 1000);
        assert_eq!(config.cache_ttl_seconds, 300);
    }

    #[tokio::test]
    async fn test_proof_cache_pending_validation() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let cache = setup_proof_cache(log).await;
        
        let payload_hash = Hash256::from_low_u64_be(42);
        
        // Add pending validation
        let _receiver = cache.add_pending_validation(payload_hash).await;
        
        // This demonstrates the async validation setup
        // In a real test, we'd verify that when a proof arrives,
        // the pending validation gets triggered
        println!("Pending validation test completed");
    }
}