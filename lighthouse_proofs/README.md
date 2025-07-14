# Lighthouse Proofs

A modular crate for managing execution proofs in Lighthouse, supporting the stateless validation architecture.

## Overview

This crate provides a clean, trait-based architecture for:
- **Proof Generation**: Create execution proofs (currently dummy, extensible for zkVM)
- **Proof Storage**: Manage proofs with configurable storage backends
- **Proof Validation**: Validate proof structure and cryptography
- **Chain Tracking**: Track the proven canonical chain separately from fork choice
- **Broadcast Management**: Handle proof distribution across gossip subnets

## Architecture

The crate follows a modular design with clear separation of concerns:

```
ProofSystem
├── Store (trait: ProofStore)
│   └── MemoryProofStore (LRU cache)
├── Generator (trait: ProofGenerator)
│   └── DummyProofGenerator (for testing)
├── Validator (trait: ProofValidator)
│   └── BasicProofValidator
├── ChainTracker
│   └── Tracks proven blocks and chain state
└── BroadcastManager
    └── Manages proof broadcast states
```

## Usage

```rust
use lighthouse_proofs::{ProofSystem, ProofSystemConfig};

// Configure the proof system
let config = ProofSystemConfig {
    stateless_validation: true,
    generate_execution_proofs: true,
    max_execution_payload_proofs: 10_000,
    max_execution_proof_subnets: 8,
    stateless_min_proofs_required: 2,
    ..Default::default()
};

// Build the proof system
let proof_system = ProofSystem::builder()
    .with_config(config)
    .build()?;

// Generate a proof
let proof = proof_system.generator()
    .generate_proof(&payload, &witness, proof_id)
    .await?;

// Store the proof
proof_system.store()
    .store_proof(proof)
    .await?;

// Check if we have sufficient proofs
let has_enough = proof_system.store()
    .has_sufficient_proofs(&block_hash, min_required)
    .await;
```

## Key Types

- **ProofId**: Identifies proof types (maps to subnet IDs)
- **ExecutionProof**: Network representation for gossip
- **ExecutionPayloadProof**: Internal storage representation
- **ProvenBlockInfo**: Information about proven blocks
- **BroadcastStatus**: Tracks proof broadcast state

## Extensibility

The trait-based design allows easy extension:

1. **Custom Storage**: Implement `ProofStore` for persistent storage
2. **Real Proof Generation**: Implement `ProofGenerator` for zkVM integration
3. **Cryptographic Validation**: Extend `ProofValidator` with real crypto
4. **Alternative Broadcasting**: Customize proof distribution strategies

## Configuration

The `ProofSystemConfig` provides comprehensive control over:
- Proof generation parameters
- Storage limits and cleanup
- Broadcasting behavior
- Resource constraints

## Future Work

- Integration with real zkVM systems (SP1, RISC0, etc.)
- Persistent storage backend
- Proof aggregation mechanisms
- Advanced subnet allocation strategies
- Comprehensive metrics and monitoring