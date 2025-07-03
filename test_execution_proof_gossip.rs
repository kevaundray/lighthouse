#!/usr/bin/env cargo +stable -Zscript
//! Quick integration test for ExecutionProof gossip functionality

use lighthouse_network::types::{GossipKind, GossipTopic, PubsubMessage};
use lighthouse_network::GossipEncoding;
use std::sync::Arc;
use types::{ExecutionProof, ExecutionProofSubnetId, ExecutionBlockHash, Hash256, ForkContext, ChainSpec, MainnetEthSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Testing ExecutionProof gossip integration...");

    // Create a test ExecutionProof
    let block_hash = ExecutionBlockHash::from(Hash256::random());
    let subnet_id = ExecutionProofSubnetId::new(0);
    let proof_data = b"test_dummy_proof_data".to_vec();
    
    let execution_proof = ExecutionProof::new_with_current_timestamp(
        block_hash,
        subnet_id,
        1, // version
        proof_data,
    );
    
    println!("✅ Created ExecutionProof: {:?}", execution_proof.description());
    
    // Test GossipKind creation
    let gossip_kind = GossipKind::ExecutionProof(subnet_id);
    println!("✅ Created GossipKind::ExecutionProof for subnet {}", *subnet_id);
    
    // Test topic generation
    let fork_digest = [0u8; 4]; // Dummy fork digest
    let gossip_topic = GossipTopic {
        encoding: GossipEncoding::SSZSnappy,
        fork_digest,
        kind: gossip_kind,
    };
    
    let topic_string = format!("{}", gossip_topic);
    println!("✅ Generated topic string: {}", topic_string);
    
    // Verify topic can be parsed back
    let parsed_topic = GossipTopic::decode(&topic_string)?;
    if let GossipKind::ExecutionProof(parsed_subnet_id) = parsed_topic.kind() {
        assert_eq!(*parsed_subnet_id, *subnet_id);
        println!("✅ Topic parsing works correctly");
    } else {
        return Err("Topic parsing failed".into());
    }
    
    // Test PubsubMessage creation
    let pubsub_message: PubsubMessage<MainnetEthSpec> = PubsubMessage::ExecutionProofMessage(
        Box::new((subnet_id, Arc::new(execution_proof)))
    );
    
    println!("✅ Created PubsubMessage::ExecutionProofMessage");
    
    // Test message kind extraction
    if let GossipKind::ExecutionProof(msg_subnet_id) = pubsub_message.kind() {
        assert_eq!(msg_subnet_id, subnet_id);
        println!("✅ Message kind extraction works correctly");
    } else {
        return Err("Message kind extraction failed".into());
    }
    
    // Test SSZ encoding/decoding
    let encoded = pubsub_message.as_ssz_bytes();
    println!("✅ SSZ encoded message ({} bytes)", encoded.len());
    
    // Create dummy fork context for decoding
    let spec = ChainSpec::mainnet();
    let fork_context = ForkContext::new::<MainnetEthSpec>(
        types::Slot::new(0),
        Hash256::zero(),
        &spec,
    );
    
    let decoded = PubsubMessage::decode(&gossip_topic.into(), &encoded, &fork_context)?;
    if let PubsubMessage::ExecutionProofMessage(decoded_data) = decoded {
        assert_eq!(decoded_data.0, subnet_id);
        assert_eq!(decoded_data.1.block_hash, block_hash);
        println!("✅ SSZ decoding works correctly");
    } else {
        return Err("SSZ decoding failed".into());
    }
    
    println!("\n🎉 All ExecutionProof gossip integration tests passed!");
    println!("   - ExecutionProof creation ✅");
    println!("   - GossipKind creation ✅");
    println!("   - Topic generation and parsing ✅");
    println!("   - PubsubMessage creation ✅");
    println!("   - SSZ encoding/decoding ✅");
    
    Ok(())
}