//! Broadcast status types

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Status of proof broadcasting to the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastStatus {
    /// Proof has not been broadcast yet
    NotBroadcast,
    /// Proof is currently being broadcast
    Broadcasting,
    /// Proof has been successfully broadcast
    Broadcast,
    /// Proof broadcasting failed after retries
    Failed,
}

impl Default for BroadcastStatus {
    fn default() -> Self {
        BroadcastStatus::NotBroadcast
    }
}

/// Broadcast state for a specific execution proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBroadcastState {
    /// Current broadcast status of this proof
    pub status: BroadcastStatus,
    /// Number of broadcast attempts made
    pub attempts: u32,
    /// Timestamp of the last broadcast attempt
    pub last_attempt: Option<Duration>,
}

impl ProofBroadcastState {
    /// Create a new broadcast state
    pub fn new() -> Self {
        Self {
            status: BroadcastStatus::NotBroadcast,
            attempts: 0,
            last_attempt: None,
        }
    }

    /// Check if this proof is ready to be broadcast
    pub fn is_ready_to_broadcast(&self) -> bool {
        matches!(
            self.status,
            BroadcastStatus::NotBroadcast | BroadcastStatus::Failed
        )
    }

    /// Mark proof as currently being broadcast
    pub fn mark_broadcasting(&mut self) {
        self.status = BroadcastStatus::Broadcasting;
        self.attempts += 1;
        self.last_attempt = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        );
    }

    /// Mark proof as successfully broadcast
    pub fn mark_broadcast_success(&mut self) {
        self.status = BroadcastStatus::Broadcast;
    }

    /// Mark proof broadcast as failed
    pub fn mark_broadcast_failed(&mut self) {
        self.status = BroadcastStatus::Failed;
    }

    /// Check if broadcast should be retried
    pub fn should_retry_broadcast(&self, max_attempts: u32) -> bool {
        matches!(self.status, BroadcastStatus::Failed) && self.attempts < max_attempts
    }
}

impl Default for ProofBroadcastState {
    fn default() -> Self {
        Self::new()
    }
}