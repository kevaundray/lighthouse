//! Configuration for the proof system

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the entire proof system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSystemConfig {
    /// Whether stateless validation is enabled
    pub stateless_validation: bool,
    
    /// Whether this node generates execution proofs
    pub generate_execution_proofs: bool,
    
    /// Maximum number of execution payload proofs to store
    pub max_execution_payload_proofs: usize,
    
    /// Maximum number of execution proof subnets to participate in
    pub max_execution_proof_subnets: u64,
    
    /// Minimum number of proofs required to consider a block valid
    pub stateless_min_proofs_required: usize,
    
    /// Proof generation configuration
    pub generation: ProofGenerationConfig,
    
    /// Proof broadcasting configuration
    pub broadcast: ProofBroadcastConfig,
    
    /// Proof storage configuration
    pub storage: ProofStorageConfig,
}

impl Default for ProofSystemConfig {
    fn default() -> Self {
        Self {
            stateless_validation: false,
            generate_execution_proofs: false,
            max_execution_payload_proofs: 10_000,
            max_execution_proof_subnets: 8,
            stateless_min_proofs_required: 1,
            generation: ProofGenerationConfig::default(),
            broadcast: ProofBroadcastConfig::default(),
            storage: ProofStorageConfig::default(),
        }
    }
}

impl ProofSystemConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.stateless_min_proofs_required == 0 {
            return Err("stateless_min_proofs_required must be at least 1".to_string());
        }
        
        if self.stateless_min_proofs_required as u64 > self.max_execution_proof_subnets {
            return Err(format!(
                "stateless_min_proofs_required ({}) cannot exceed max_execution_proof_subnets ({})",
                self.stateless_min_proofs_required, self.max_execution_proof_subnets
            ));
        }
        
        if self.max_execution_payload_proofs == 0 {
            return Err("max_execution_payload_proofs must be greater than 0".to_string());
        }
        
        Ok(())
    }

    /// Get the maximum number of proofs to store
    pub fn max_proofs(&self) -> usize {
        self.max_execution_payload_proofs
    }
}

/// Configuration for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGenerationConfig {
    /// Maximum concurrent proof generation tasks
    pub max_concurrent_tasks: usize,
    
    /// Timeout for proof generation
    pub generation_timeout: Duration,
    
    /// Delay ranges for simulated proof generation (milliseconds)
    pub simulation_delay_range: (u64, u64),
    
    /// Staggered delays for multiple proofs (milliseconds)
    pub staggered_delays: Vec<u64>,
}

impl Default for ProofGenerationConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 4,
            generation_timeout: Duration::from_secs(60),
            simulation_delay_range: (1000, 3000),
            staggered_delays: vec![0, 5000, 10000, 15000, 20000],
        }
    }
}

/// Configuration for proof broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBroadcastConfig {
    /// How often to check for unbroadcast proofs
    pub broadcast_interval: Duration,
    
    /// Maximum number of broadcast attempts per proof
    pub max_broadcast_attempts: u32,
    
    /// Delay between retries for failed broadcasts
    pub retry_delay: Duration,
    
    /// Number of batches to split broadcasts into
    pub broadcast_batches: usize,
    
    /// Delay between broadcast batches
    pub batch_interval: Duration,
}

impl Default for ProofBroadcastConfig {
    fn default() -> Self {
        Self {
            broadcast_interval: Duration::from_secs(1),
            max_broadcast_attempts: 3,
            retry_delay: Duration::from_secs(5),
            broadcast_batches: 1,
            batch_interval: Duration::from_millis(100),
        }
    }
}

/// Configuration for proof storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStorageConfig {
    /// Whether to enable persistent storage (future feature)
    pub persistent_storage: bool,
    
    /// TTL for orphaned proofs (proofs without blocks)
    pub orphaned_proof_ttl: Duration,
    
    /// How often to run cleanup tasks
    pub cleanup_interval: Duration,
    
    /// Maximum age for proofs before pruning
    pub max_proof_age: Duration,
}

impl Default for ProofStorageConfig {
    fn default() -> Self {
        Self {
            persistent_storage: false,
            orphaned_proof_ttl: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(60),     // 1 minute
            max_proof_age: Duration::from_secs(3600),      // 1 hour
        }
    }
}