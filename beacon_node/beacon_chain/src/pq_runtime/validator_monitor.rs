use consensus_signature::ValidatorPublicKeyBytes;
use serde::{Deserialize, Serialize};

/// Configuration-only validator monitor surface. Monitoring workers are omitted in PQ V1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidatorMonitorConfig {
    pub auto_register: bool,
    pub validators: Vec<ValidatorPublicKeyBytes>,
    pub individual_tracking_threshold: usize,
}

impl Default for ValidatorMonitorConfig {
    fn default() -> Self {
        Self {
            auto_register: false,
            validators: vec![],
            individual_tracking_threshold: 64,
        }
    }
}
