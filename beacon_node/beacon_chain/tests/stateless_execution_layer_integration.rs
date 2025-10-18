// Integration tests for Stateless Execution Layer proof availability
//
// These tests validate the proof availability mechanism integrated with
// the beacon chain's execution layer.
//
// Test scenarios:
// 1. Callback triggers when proofs arrive via gossip
// 2. Payload status transitions from SYNCING to VALID as proofs arrive
// 3. M-of-N security model enforced (need M proofs from different subnets)

use stateless_execution_layer::{StatelessExecutionLayer, StatelessExecutionLayerConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofSubnetId, Hash256};

/// Create a test logger (discards output)
fn test_logger() -> slog::Logger {
    use slog::o;
    slog::Logger::root(slog::Discard, o!())
}

/// Creates a stateless execution layer for testing.
fn build_stateless_el(min_proofs_required: usize) -> Arc<StatelessExecutionLayer> {
    let mut builder =
        StatelessExecutionLayerConfig::builder().min_proofs_required(min_proofs_required);

    // Add subnets to meet minimum requirement
    for subnet_id in 0..min_proofs_required.max(2) {
        let subnet = ExecutionProofSubnetId::new(subnet_id as u8).unwrap();
        builder = builder.add_subscribed_subnet(subnet);
    }

    let config = builder.build().expect("config should be valid");

    Arc::new(
        StatelessExecutionLayer::new(config, test_logger())
            .expect("should create stateless execution layer"),
    )
}

/// Helper to create a dummy execution proof for testing
fn create_dummy_proof(
    payload_hash: ExecutionBlockHash,
    block_root: Hash256,
    subnet_id: u8,
) -> (ExecutionProofSubnetId, Arc<ExecutionProof>) {
    let subnet = ExecutionProofSubnetId::new(subnet_id).unwrap();
    let proof = ExecutionProof::new_for_testing(subnet, payload_hash, block_root, vec![0u8; 100])
        .expect("should create proof");
    (subnet, Arc::new(proof))
}

#[tokio::test]
async fn test_callback_triggers_when_proofs_arrive() {
    // Test that the proof-ready callback is triggered when
    // sufficient proofs arrive for a block

    let min_proofs = 2;
    let stateless_el = build_stateless_el(min_proofs);

    // Set up a callback to track when it's triggered
    let callback_triggered = Arc::new(AtomicBool::new(false));
    let callback_flag = callback_triggered.clone();

    stateless_el
        .register_proof_ready_callback(Arc::new(move |_payload_hash| {
            callback_flag.store(true, Ordering::SeqCst);
        }))
        .await;

    // Create a dummy payload hash to test with
    let payload_hash = ExecutionBlockHash::repeat_byte(0x42);
    let block_root = Hash256::repeat_byte(0x01);

    // Initially, callback should not have been triggered
    assert!(!callback_triggered.load(Ordering::SeqCst));

    // Send first proof (not enough yet)
    let (subnet1, proof1) = create_dummy_proof(payload_hash, block_root, 0);
    stateless_el
        .on_gossip_proof_received(subnet1, proof1)
        .await
        .expect("should accept proof");

    // Callback should not trigger yet (need 2 proofs)
    assert!(!callback_triggered.load(Ordering::SeqCst));

    // Send second proof from different subnet
    let (subnet2, proof2) = create_dummy_proof(payload_hash, block_root, 1);
    stateless_el
        .on_gossip_proof_received(subnet2, proof2)
        .await
        .expect("should accept proof");

    // Give callback time to execute
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Now callback should have been triggered
    assert!(
        callback_triggered.load(Ordering::SeqCst),
        "callback should trigger when threshold reached"
    );

    println!("✅ Phase 3.4 Test 1: Callback triggered when sufficient proofs arrived");
}

#[tokio::test]
async fn test_proof_availability_status_transitions() {
    // Test that payload status transitions from SYNCING to VALID
    // as proofs become available

    let min_proofs = 2;
    let stateless_el = build_stateless_el(min_proofs);

    let payload_hash = ExecutionBlockHash::repeat_byte(0x42);
    let block_root = Hash256::repeat_byte(0x01);

    // Initially, no proofs available - should return SYNCING
    let status = stateless_el
        .new_payload(payload_hash, block_root)
        .await
        .expect("new_payload should not error");

    assert!(
        matches!(status, stateless_execution_layer::PayloadStatus::Syncing),
        "should return SYNCING when no proofs available"
    );

    // Add first proof
    let (subnet1, proof1) = create_dummy_proof(payload_hash, block_root, 0);
    stateless_el
        .on_gossip_proof_received(subnet1, proof1)
        .await
        .expect("should accept proof");

    // Still not enough proofs - should still return SYNCING
    let status = stateless_el
        .new_payload(payload_hash, block_root)
        .await
        .expect("new_payload should not error");

    assert!(
        matches!(status, stateless_execution_layer::PayloadStatus::Syncing),
        "should still return SYNCING with only 1 proof (need 2)"
    );

    // Add second proof from different subnet
    let (subnet2, proof2) = create_dummy_proof(payload_hash, block_root, 1);
    stateless_el
        .on_gossip_proof_received(subnet2, proof2)
        .await
        .expect("should accept proof");

    // Now we have enough proofs - should return VALID
    let status = stateless_el
        .new_payload(payload_hash, block_root)
        .await
        .expect("new_payload should not error");

    assert!(
        matches!(status, stateless_execution_layer::PayloadStatus::Valid),
        "should return VALID when sufficient proofs available"
    );

    println!("✅ Phase 3.4 Test 2: Payload status correctly transitions SYNCING → SYNCING → VALID");
}

#[tokio::test]
async fn test_multiple_proofs_same_subnet_only_counts_once() {
    // Test that multiple proofs from the same subnet only count as one proof
    // towards the M-of-N threshold

    let min_proofs = 2;
    let stateless_el = build_stateless_el(min_proofs);

    let payload_hash = ExecutionBlockHash::repeat_byte(0x42);
    let block_root = Hash256::repeat_byte(0x01);

    // Add first proof from subnet 0
    let (subnet1, proof1) = create_dummy_proof(payload_hash, block_root, 0);
    stateless_el
        .on_gossip_proof_received(subnet1, proof1)
        .await
        .expect("should accept proof");

    // Add another proof from subnet 0 (duplicate subnet)
    let (subnet2, proof2) = create_dummy_proof(payload_hash, block_root, 0);
    stateless_el
        .on_gossip_proof_received(subnet2, proof2)
        .await
        .expect("should accept proof");

    // Should still return SYNCING (both proofs from same subnet)
    let status = stateless_el
        .new_payload(payload_hash, block_root)
        .await
        .expect("new_payload should not error");

    assert!(
        matches!(status, stateless_execution_layer::PayloadStatus::Syncing),
        "should return SYNCING when both proofs are from same subnet"
    );

    // Add proof from different subnet (subnet 1)
    let (subnet3, proof3) = create_dummy_proof(payload_hash, block_root, 1);
    stateless_el
        .on_gossip_proof_received(subnet3, proof3)
        .await
        .expect("should accept proof");

    // Now should return VALID (2 different subnets)
    let status = stateless_el
        .new_payload(payload_hash, block_root)
        .await
        .expect("new_payload should not error");

    assert!(
        matches!(status, stateless_execution_layer::PayloadStatus::Valid),
        "should return VALID when proofs from 2 different subnets"
    );

    println!("✅ Phase 3.4 Test 3: M-of-N correctly requires M different subnets");
}
