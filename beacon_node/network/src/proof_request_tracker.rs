//! Tracks outgoing proof requests for RPC fallback mechanism.
//!
//! This module manages the lifecycle of proof requests sent to peers,
//! including timeouts, retries, and tracking which peers have been asked.

use lighthouse_network::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use types::{ExecutionProofSubnetId, Hash256};

/// How long to wait for a peer to respond before considering the request failed
const PROOF_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of times to retry requesting a proof from different peers
const MAX_PROOF_REQUEST_RETRIES: usize = 3;

/// Maximum number of concurrent requests to different peers for the same proof
const MAX_CONCURRENT_PEER_REQUESTS: usize = 2;

/// Tracks a single proof request for a specific block and subnet
#[derive(Debug, Clone)]
struct ProofRequest {
    /// When the first request was made
    first_requested: Instant,
    /// Peers we've asked and when we asked them
    requested_peers: HashMap<PeerId, Instant>,
    /// Total number of retry attempts
    retry_count: usize,
}

impl ProofRequest {
    fn new() -> Self {
        Self {
            first_requested: Instant::now(),
            requested_peers: HashMap::new(),
            retry_count: 0,
        }
    }

    /// Check if we should retry this request
    fn should_retry(&self) -> bool {
        self.retry_count < MAX_PROOF_REQUEST_RETRIES
    }

    /// Check if we can request from another peer concurrently
    fn can_request_from_another_peer(&self) -> bool {
        self.active_requests() < MAX_CONCURRENT_PEER_REQUESTS
    }

    /// Count how many active (non-timed-out) requests are pending
    fn active_requests(&self) -> usize {
        let now = Instant::now();
        self.requested_peers
            .values()
            .filter(|&&requested_at| now.duration_since(requested_at) < PROOF_REQUEST_TIMEOUT)
            .count()
    }

    /// Get peers that have timed out
    fn timed_out_peers(&self) -> Vec<PeerId> {
        let now = Instant::now();
        self.requested_peers
            .iter()
            .filter(|&(_, &requested_at)| now.duration_since(requested_at) >= PROOF_REQUEST_TIMEOUT)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }

    /// Record that we requested from a peer
    fn add_request(&mut self, peer_id: PeerId) {
        self.requested_peers.insert(peer_id, Instant::now());
    }

    /// Check if we've already asked this peer
    fn has_asked_peer(&self, peer_id: &PeerId) -> bool {
        self.requested_peers.contains_key(peer_id)
    }
}

/// Identifier for a specific proof we need
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct ProofIdentifier {
    block_root: Hash256,
    subnet_id: ExecutionProofSubnetId,
}

/// Tracks all pending proof requests
pub struct ProofRequestTracker {
    /// Map of proof identifier to request state
    requests: HashMap<ProofIdentifier, ProofRequest>,
}

impl ProofRequestTracker {
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Record that we're requesting specific proofs from a peer
    pub fn insert_request(
        &mut self,
        block_root: Hash256,
        subnet_ids: &[ExecutionProofSubnetId],
        peer_id: PeerId,
    ) {
        for &subnet_id in subnet_ids {
            let id = ProofIdentifier {
                block_root,
                subnet_id,
            };
            let request = self.requests.entry(id).or_insert_with(ProofRequest::new);
            request.add_request(peer_id);
        }
    }

    /// Check if we're currently tracking a proof request
    pub fn is_tracking(&self, block_root: &Hash256, subnet_id: ExecutionProofSubnetId) -> bool {
        let id = ProofIdentifier {
            block_root: *block_root,
            subnet_id,
        };
        self.requests.contains_key(&id)
    }

    /// Remove a proof from tracking (called when proof is received or request expires)
    pub fn remove_request(&mut self, block_root: &Hash256, subnet_id: ExecutionProofSubnetId) {
        let id = ProofIdentifier {
            block_root: *block_root,
            subnet_id,
        };
        self.requests.remove(&id);
    }

    /// Get all subnet IDs that need retry for a specific block
    ///
    /// Returns subnet IDs where:
    /// - We haven't exceeded max retries
    /// - All current requests have timed out
    pub fn get_retry_subnets(&mut self, block_root: &Hash256) -> Vec<ExecutionProofSubnetId> {
        let mut retry_subnets = Vec::new();

        // Collect subnet IDs that match this block_root
        let matching_ids: Vec<ProofIdentifier> = self
            .requests
            .keys()
            .filter(|id| id.block_root == *block_root)
            .copied()
            .collect();

        for id in matching_ids {
            if let Some(request) = self.requests.get_mut(&id) {
                // Check if all requests for this proof have timed out
                if request.active_requests() == 0 && request.should_retry() {
                    request.retry_count += 1;
                    retry_subnets.push(id.subnet_id);
                } else if !request.should_retry() && request.active_requests() == 0 {
                    // Exceeded max retries and no active requests, give up
                    self.requests.remove(&id);
                }
            }
        }

        retry_subnets
    }

    /// Get peers we've already asked for a specific proof
    pub fn get_asked_peers(
        &self,
        block_root: &Hash256,
        subnet_id: ExecutionProofSubnetId,
    ) -> HashSet<PeerId> {
        let id = ProofIdentifier {
            block_root: *block_root,
            subnet_id,
        };
        self.requests
            .get(&id)
            .map(|req| req.requested_peers.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Check if we can make another concurrent request for a proof
    pub fn can_request_another_peer(
        &self,
        block_root: &Hash256,
        subnet_id: ExecutionProofSubnetId,
    ) -> bool {
        let id = ProofIdentifier {
            block_root: *block_root,
            subnet_id,
        };
        self.requests
            .get(&id)
            .map(|req| req.can_request_from_another_peer())
            .unwrap_or(true)
    }

    /// Clean up expired requests (called periodically)
    pub fn prune_old_requests(&mut self) {
        let now = Instant::now();
        const MAX_REQUEST_AGE: Duration = Duration::from_secs(300); // 5 minutes

        self.requests.retain(|_, request| {
            now.duration_since(request.first_requested) < MAX_REQUEST_AGE
        });
    }
}

impl Default for ProofRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id(_n: u8) -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_insert_and_tracking() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let peer_id = test_peer_id(1);

        assert!(!tracker.is_tracking(&block_root, subnet_id));

        tracker.insert_request(block_root, &[subnet_id], peer_id);

        assert!(tracker.is_tracking(&block_root, subnet_id));
    }

    #[test]
    fn test_remove_request() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let peer_id = test_peer_id(1);

        tracker.insert_request(block_root, &[subnet_id], peer_id);
        assert!(tracker.is_tracking(&block_root, subnet_id));

        tracker.remove_request(&block_root, subnet_id);
        assert!(!tracker.is_tracking(&block_root, subnet_id));
    }

    #[test]
    fn test_get_asked_peers() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let peer1 = test_peer_id(1);
        let peer2 = test_peer_id(2);

        tracker.insert_request(block_root, &[subnet_id], peer1);
        tracker.insert_request(block_root, &[subnet_id], peer2);

        let asked_peers = tracker.get_asked_peers(&block_root, subnet_id);
        assert_eq!(asked_peers.len(), 2);
        assert!(asked_peers.contains(&peer1));
        assert!(asked_peers.contains(&peer2));
    }

    #[test]
    fn test_concurrent_peer_limit() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();

        // First request should be allowed
        assert!(tracker.can_request_another_peer(&block_root, subnet_id));

        tracker.insert_request(block_root, &[subnet_id], test_peer_id(1));
        assert!(tracker.can_request_another_peer(&block_root, subnet_id));

        tracker.insert_request(block_root, &[subnet_id], test_peer_id(2));
        // Should hit the concurrent limit (MAX_CONCURRENT_PEER_REQUESTS = 2)
        assert!(!tracker.can_request_another_peer(&block_root, subnet_id));
    }

    #[test]
    fn test_retry_logic_not_exceeded() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();

        // Insert initial request
        tracker.insert_request(block_root, &[subnet_id], test_peer_id(1));

        // Immediately check for retries (should be empty since request is active)
        let retry_subnets = tracker.get_retry_subnets(&block_root);
        assert!(retry_subnets.is_empty(), "Should not retry while request is active");

        // Wait for timeout (in real scenario, would wait PROOF_REQUEST_TIMEOUT)
        // For testing, we rely on the fact that active_requests() will be 0 after timeout
        // This test verifies the logic, actual timeout testing would need time mocking
        std::thread::sleep(Duration::from_millis(50));
    }

    #[test]
    fn test_multiple_subnets_tracking() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id_0 = ExecutionProofSubnetId::new(0).unwrap();
        let subnet_id_1 = ExecutionProofSubnetId::new(1).unwrap();
        let peer_id = test_peer_id(1);

        // Insert request for multiple subnets
        tracker.insert_request(block_root, &[subnet_id_0, subnet_id_1], peer_id);

        // Both subnets should be tracked
        assert!(tracker.is_tracking(&block_root, subnet_id_0));
        assert!(tracker.is_tracking(&block_root, subnet_id_1));

        // Remove one subnet
        tracker.remove_request(&block_root, subnet_id_0);

        // Only subnet_id_1 should still be tracked
        assert!(!tracker.is_tracking(&block_root, subnet_id_0));
        assert!(tracker.is_tracking(&block_root, subnet_id_1));
    }

    #[test]
    fn test_prune_old_requests() {
        let mut tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();

        // Insert a request
        tracker.insert_request(block_root, &[subnet_id], test_peer_id(1));
        assert!(tracker.is_tracking(&block_root, subnet_id));

        // Prune immediately (should not remove since it's fresh)
        tracker.prune_old_requests();
        assert!(tracker.is_tracking(&block_root, subnet_id));

        // In a real scenario, we'd wait > 5 minutes and then prune
        // For this unit test, we just verify the method doesn't panic
        // and maintains recent requests
    }

    #[test]
    fn test_different_blocks_isolated() {
        let mut tracker = ProofRequestTracker::new();
        let block_root_1 = Hash256::repeat_byte(1);
        let block_root_2 = Hash256::repeat_byte(2);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
        let peer_id = test_peer_id(1);

        // Track requests for two different blocks
        tracker.insert_request(block_root_1, &[subnet_id], peer_id);
        tracker.insert_request(block_root_2, &[subnet_id], peer_id);

        // Both should be tracked independently
        assert!(tracker.is_tracking(&block_root_1, subnet_id));
        assert!(tracker.is_tracking(&block_root_2, subnet_id));

        // Remove one block's request
        tracker.remove_request(&block_root_1, subnet_id);

        // Only block_root_2 should remain
        assert!(!tracker.is_tracking(&block_root_1, subnet_id));
        assert!(tracker.is_tracking(&block_root_2, subnet_id));
    }

    #[test]
    fn test_asked_peers_empty_for_untracked() {
        let tracker = ProofRequestTracker::new();
        let block_root = Hash256::repeat_byte(1);
        let subnet_id = ExecutionProofSubnetId::new(0).unwrap();

        // Get asked peers for non-existent request
        let asked_peers = tracker.get_asked_peers(&block_root, subnet_id);
        assert!(asked_peers.is_empty());
    }
}
