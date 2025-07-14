//! # Lighthouse Proofs
//! 
//! This crate provides execution proof management for Lighthouse, including:
//! - Proof generation and validation
//! - Proof storage and retrieval
//! - Proven chain tracking
//! - Network broadcasting
//!
//! ## Architecture
//! 
//! The crate is organized into modules:
//! - `types`: Core proof data structures
//! - `store`: Proof storage implementations
//! - `generation`: Proof generation logic
//! - `validation`: Proof validation logic
//! - `chain`: Proven chain tracking
//! - `broadcast`: Proof broadcasting management
//!
//! ## Example Usage
//! 
//! ```rust,ignore
//! use lighthouse_proofs::{ProofSystem, ProofSystemConfig};
//! 
//! let config = ProofSystemConfig::default();
//! let proof_system = ProofSystem::builder()
//!     .with_config(config)
//!     .build()?;
//! ```

pub mod types;
pub mod store;
pub mod generation;
pub mod validation;
pub mod chain;
pub mod broadcast;
pub mod config;
pub mod error;

// Re-export commonly used types
pub use types::{ProofId, ExecutionProof, ExecutionPayloadProof};
pub use store::{ProofStore, MemoryProofStore};
pub use generation::{ProofGenerator, DummyProofGenerator};
pub use validation::{ProofValidator, BasicProofValidator};
pub use chain::{ProvenChainTracker, ProvenBlockInfo};
pub use broadcast::{ProofBroadcastManager, BroadcastStatus};
pub use config::ProofSystemConfig;
pub use error::{Error, Result};

use std::sync::Arc;

/// Main proof system coordinator
pub struct ProofSystem {
    pub store: Arc<dyn ProofStore>,
    pub generator: Arc<dyn ProofGenerator>,
    pub validator: Arc<dyn ProofValidator>,
    pub chain_tracker: Arc<ProvenChainTracker>,
    pub broadcast_manager: Arc<ProofBroadcastManager>,
    pub config: ProofSystemConfig,
}

impl ProofSystem {
    /// Create a new proof system builder
    pub fn builder() -> ProofSystemBuilder {
        ProofSystemBuilder::new()
    }

    /// Get the proof store
    pub fn store(&self) -> &Arc<dyn ProofStore> {
        &self.store
    }

    /// Get the proof generator
    pub fn generator(&self) -> &Arc<dyn ProofGenerator> {
        &self.generator
    }

    /// Get the proof validator
    pub fn validator(&self) -> &Arc<dyn ProofValidator> {
        &self.validator
    }

    /// Get the proven chain tracker
    pub fn chain_tracker(&self) -> &Arc<ProvenChainTracker> {
        &self.chain_tracker
    }

    /// Get the broadcast manager
    pub fn broadcast_manager(&self) -> &Arc<ProofBroadcastManager> {
        &self.broadcast_manager
    }
}

/// Builder for constructing a ProofSystem
pub struct ProofSystemBuilder {
    store: Option<Arc<dyn ProofStore>>,
    generator: Option<Arc<dyn ProofGenerator>>,
    validator: Option<Arc<dyn ProofValidator>>,
    config: Option<ProofSystemConfig>,
}

impl ProofSystemBuilder {
    fn new() -> Self {
        Self {
            store: None,
            generator: None,
            validator: None,
            config: None,
        }
    }

    pub fn with_store(mut self, store: impl ProofStore + 'static) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    pub fn with_generator(mut self, generator: impl ProofGenerator + 'static) -> Self {
        self.generator = Some(Arc::new(generator));
        self
    }

    pub fn with_validator(mut self, validator: impl ProofValidator + 'static) -> Self {
        self.validator = Some(Arc::new(validator));
        self
    }

    pub fn with_config(mut self, config: ProofSystemConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn build(self) -> Result<ProofSystem> {
        let config = self.config.unwrap_or_default();
        
        // Validate configuration
        config.validate().map_err(Error::ConfigError)?;
        
        let store = self.store
            .unwrap_or_else(|| Arc::new(MemoryProofStore::new(config.max_proofs())));
            
        let generator = self.generator
            .unwrap_or_else(|| Arc::new(DummyProofGenerator::new()));
            
        let validator = self.validator
            .unwrap_or_else(|| Arc::new(BasicProofValidator::new()));

        let chain_tracker = Arc::new(ProvenChainTracker::new());
        let broadcast_manager = Arc::new(ProofBroadcastManager::new());

        Ok(ProofSystem {
            store,
            generator,
            validator,
            chain_tracker,
            broadcast_manager,
            config,
        })
    }
}