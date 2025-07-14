//! Metrics for proof storage

use serde::{Deserialize, Serialize};

/// Metrics about proof storage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofStoreMetrics {
    /// Total number of proofs stored
    pub total_proofs: usize,
    
    /// Number of unique execution payloads with proofs
    pub unique_payloads: usize,
    
    /// Number of proofs by type
    pub proofs_by_type: Vec<(String, usize)>,
    
    /// Storage capacity used (percentage)
    pub capacity_used_percent: f64,
    
    /// Number of evictions performed
    pub evictions: u64,
    
    /// Number of successful stores
    pub successful_stores: u64,
    
    /// Number of failed stores
    pub failed_stores: u64,
}