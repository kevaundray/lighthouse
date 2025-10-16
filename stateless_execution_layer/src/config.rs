use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use types::ExecutionProofSubnetId;

/// Configuration for the Stateless Execution Layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatelessExecutionLayerConfig {
    /// Which subnets to subscribe to for verification
    pub subscribed_subnets: HashSet<ExecutionProofSubnetId>,

    /// Minimum proofs required from DIFFERENT subnets for validation
    pub min_proofs_required: usize,

    /// Which subnets to generate proofs for (empty if not generating)
    pub generation_subnets: HashSet<ExecutionProofSubnetId>,

    /// Proof cache size (number of execution block hashes to cache proofs for)
    pub proof_cache_size: usize,

    /// Timeout for proof requests via RPC
    pub proof_request_timeout: Duration,

    /// Delay before falling back to RPC (gossip grace period)
    /// During this time, we wait for proofs to arrive via gossip
    pub gossip_grace_period: Duration,
}

impl Default for StatelessExecutionLayerConfig {
    fn default() -> Self {
        Self {
            subscribed_subnets: HashSet::new(),
            min_proofs_required: 1,
            generation_subnets: HashSet::new(),
            proof_cache_size: 1024,
            proof_request_timeout: Duration::from_secs(5),
            gossip_grace_period: Duration::from_millis(200),
        }
    }
}

impl StatelessExecutionLayerConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Ensure min_proofs_required is reasonable
        if self.min_proofs_required == 0 {
            return Err("min_proofs_required must be at least 1".to_string());
        }

        // Ensure we subscribe to enough subnets to meet min_proofs_required
        if self.subscribed_subnets.len() < self.min_proofs_required {
            return Err(format!(
                "subscribed_subnets ({}) must be >= min_proofs_required ({})",
                self.subscribed_subnets.len(),
                self.min_proofs_required
            ));
        }

        // Ensure generation subnets are a subset of subscribed subnets
        for subnet in &self.generation_subnets {
            if !self.subscribed_subnets.contains(subnet) {
                return Err(format!(
                    "generation_subnets must be a subset of subscribed_subnets (subnet {} not subscribed)",
                    subnet
                ));
            }
        }

        // Ensure cache size is reasonable
        if self.proof_cache_size == 0 {
            return Err("proof_cache_size must be at least 1".to_string());
        }

        Ok(())
    }

    /// Create a builder for the config
    pub fn builder() -> StatelessExecutionLayerConfigBuilder {
        StatelessExecutionLayerConfigBuilder::default()
    }
}

/// Builder for StatelessExecutionLayerConfig
#[derive(Default)]
pub struct StatelessExecutionLayerConfigBuilder {
    subscribed_subnets: HashSet<ExecutionProofSubnetId>,
    min_proofs_required: Option<usize>,
    generation_subnets: HashSet<ExecutionProofSubnetId>,
    proof_cache_size: Option<usize>,
    proof_request_timeout: Option<Duration>,
    gossip_grace_period: Option<Duration>,
}

impl StatelessExecutionLayerConfigBuilder {
    /// Set the subnets to subscribe to
    pub fn subscribed_subnets(mut self, subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        self.subscribed_subnets = subnets;
        self
    }

    /// Add a subnet to subscribe to
    pub fn add_subscribed_subnet(mut self, subnet: ExecutionProofSubnetId) -> Self {
        self.subscribed_subnets.insert(subnet);
        self
    }

    /// Set minimum proofs required
    pub fn min_proofs_required(mut self, min: usize) -> Self {
        self.min_proofs_required = Some(min);
        self
    }

    /// Set the subnets to generate proofs for
    pub fn generation_subnets(mut self, subnets: HashSet<ExecutionProofSubnetId>) -> Self {
        self.generation_subnets = subnets;
        self
    }

    /// Add a subnet to generate proofs for
    pub fn add_generation_subnet(mut self, subnet: ExecutionProofSubnetId) -> Self {
        self.generation_subnets.insert(subnet);
        self
    }

    /// Set proof cache size
    pub fn proof_cache_size(mut self, size: usize) -> Self {
        self.proof_cache_size = Some(size);
        self
    }

    /// Set proof request timeout
    pub fn proof_request_timeout(mut self, timeout: Duration) -> Self {
        self.proof_request_timeout = Some(timeout);
        self
    }

    /// Set gossip grace period
    pub fn gossip_grace_period(mut self, period: Duration) -> Self {
        self.gossip_grace_period = Some(period);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<StatelessExecutionLayerConfig, String> {
        let config = StatelessExecutionLayerConfig {
            subscribed_subnets: self.subscribed_subnets,
            min_proofs_required: self.min_proofs_required.unwrap_or(1),
            generation_subnets: self.generation_subnets,
            proof_cache_size: self.proof_cache_size.unwrap_or(1024),
            proof_request_timeout: self
                .proof_request_timeout
                .unwrap_or_else(|| Duration::from_secs(5)),
            gossip_grace_period: self
                .gossip_grace_period
                .unwrap_or_else(|| Duration::from_millis(200)),
        };

        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = StatelessExecutionLayerConfig::default();
        // Default config should fail validation (no subnets subscribed)
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_config() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .min_proofs_required(2)
            .build();

        assert!(config.is_ok());
    }

    #[test]
    fn test_min_proofs_too_high() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(2) // Requires 2 but only subscribed to 1
            .build();

        assert!(config.is_err());
        assert!(config.unwrap_err().contains("subscribed_subnets"));
    }

    #[test]
    fn test_generation_subnet_not_subscribed() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_generation_subnet(subnet_1) // Generate for subnet 1 but not subscribed
            .build();

        assert!(config.is_err());
        assert!(config
            .unwrap_err()
            .contains("generation_subnets must be a subset"));
    }

    #[test]
    fn test_valid_config_with_generation() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_1 = ExecutionProofSubnetId::new(1).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .add_subscribed_subnet(subnet_1)
            .add_generation_subnet(subnet_0)
            .min_proofs_required(1)
            .proof_cache_size(512)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.subscribed_subnets.len(), 2);
        assert_eq!(config.generation_subnets.len(), 1);
        assert_eq!(config.min_proofs_required, 1);
        assert_eq!(config.proof_cache_size, 512);
    }

    #[test]
    fn test_min_proofs_required_zero() {
        let subnet_0 = ExecutionProofSubnetId::new(0).unwrap();

        let config = StatelessExecutionLayerConfig::builder()
            .add_subscribed_subnet(subnet_0)
            .min_proofs_required(0) // Invalid: must be > 0
            .build();

        assert!(config.is_err());
        assert!(config
            .unwrap_err()
            .contains("min_proofs_required must be at least 1"));
    }
}
