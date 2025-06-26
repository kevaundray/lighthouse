use serde::{Deserialize, Serialize};

/// Configuration for execution proof verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofConfig {
    /// Whether proof verification is enabled
    pub enabled: bool,
    /// Whether to accept payloads optimistically if no proof is available
    pub optimistic_acceptance: bool,
    /// Whether to fallback to execution layer verification if proof is unavailable
    pub fallback_to_execution: bool,
    /// Timeout for proof verification in milliseconds
    pub verification_timeout_ms: u64,
    /// Maximum size of proof cache entries
    pub max_cache_size: usize,
    /// TTL for cached proofs in seconds
    pub cache_ttl_seconds: u64,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            optimistic_acceptance: true,
            fallback_to_execution: true,
            verification_timeout_ms: 5000,
            max_cache_size: 1000,
            cache_ttl_seconds: 300, // 5 minutes
        }
    }
}