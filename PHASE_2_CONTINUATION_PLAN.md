# Phase 2 Continuation: Message Flow Implementation Plan

## Status Summary

✅ **Completed:**
- Phase 2 Gossip Foundation (topics, subnets, subscriptions)
- All non-exhaustive pattern matches fixed
- Basic infrastructure with TODOs marking next work

⏸️ **Next Steps (This Document):**
1. PubsubMessage variant and SSZ decoding (Step 1)
2. Router integration for message forwarding (Step 2)
3. Beacon node initialization with channel wiring (Step 3)

---

## Goal
Complete the execution proof message flow from gossip → stateless-EL by implementing:
1. PubsubMessage variant and SSZ decoding
2. Router integration for message forwarding
3. Beacon node initialization with channel wiring

---

## Step 1: PubsubMessage Variant and SSZ Decoding

**Status:** ⏸️ NOT STARTED (TODO marker added at pubsub.rs:390-393)
**Estimated Time:** 30 minutes
**File:** `beacon_node/lighthouse_network/src/types/pubsub.rs`

**Current TODO Location:**
```rust
// Line 390-393:
// TODO: Add PubsubMessage::ExecutionProof variant and decoding logic
GossipKind::ExecutionProof(_) => {
    Err("ExecutionProof messages not yet supported in pubsub".to_string())
}
```

### 1.1: Add Import for ExecutionProof Types

**Location:** Top of file (around line 1-20)

**Add:**
```rust
use types::{ExecutionProof, ExecutionProofSubnetId};
```

**Check if already imported. If not, add to the existing `use types::` block.**

---

### 1.2: Add ExecutionProofMessage Variant to Enum

**Location:** `pub enum PubsubMessage<E: EthSpec>` (around line 58)

**Find:**
```rust
pub enum PubsubMessage<E: EthSpec> {
    // ... existing variants
    LightClientOptimisticUpdate(Box<Arc<LightClientOptimisticUpdate<E>>>),
}
```

**Add after LightClientOptimisticUpdate:**
```rust
    /// ExecutionProof message with subnet_id and proof data
    ExecutionProofMessage(Box<(ExecutionProofSubnetId, Arc<ExecutionProof>)>),
```

**Why this structure:**
- Boxed to reduce enum size (large types should be boxed)
- Tuple of (subnet_id, proof) for easy routing
- Arc<ExecutionProof> for cheap cloning when forwarding

---

### 1.3: Implement Decoding Logic

**Location:** `impl<E: EthSpec> PubsubMessage<E>` → `decode()` method (around line 390)

**Find:**
```rust
// TODO: Add PubsubMessage::ExecutionProof variant and decoding logic
GossipKind::ExecutionProof(_) => {
    Err("ExecutionProof messages not yet supported in pubsub".to_string())
}
```

**Replace with:**
```rust
GossipKind::ExecutionProof(subnet_id) => {
    // Decode ExecutionProof from SSZ bytes
    let execution_proof = ExecutionProof::from_ssz_bytes(data)
        .map_err(|e| {
            format!(
                "Failed to decode ExecutionProof from SSZ: {:?}",
                e
            )
        })?;

    // Verify subnet_id in proof matches gossip topic subnet_id
    if execution_proof.subnet_id != *subnet_id {
        return Err(format!(
            "ExecutionProof subnet_id mismatch: gossip_topic={:?}, proof.subnet_id={:?}",
            subnet_id,
            execution_proof.subnet_id
        ));
    }

    // Verify proof has content
    if execution_proof.proof_data_size() == 0 {
        return Err("ExecutionProof has empty proof_data".to_string());
    }

    Ok(PubsubMessage::ExecutionProofMessage(Box::new((
        *subnet_id,
        Arc::new(execution_proof),
    ))))
}
```

**Why these validations:**
- Subnet mismatch could indicate malicious behavior
- Empty proof data is invalid and should be rejected early

---

### 1.4: Implement Encoding Logic

**Location:** `impl<E: EthSpec> PubsubMessage<E>` → `encode()` method (around line 420)

**Find the match statement:**
```rust
pub fn encode(&self, encoding: GossipEncoding) -> Vec<u8> {
    match self {
        // ... existing variants
        PubsubMessage::LightClientOptimisticUpdate(data) => {
            // ...
        }
    }
}
```

**Add after LightClientOptimisticUpdate case:**
```rust
        PubsubMessage::ExecutionProofMessage(data) => {
            let (_, execution_proof) = &**data;
            // Use the encode_ssz helper
            encode_ssz(execution_proof, encoding)
        }
```

---

### 1.5: Implement kind() Method

**Location:** `impl<E: EthSpec> PubsubMessage<E>` → `kind()` method (around line 520)

**Find:**
```rust
pub fn kind(&self) -> GossipKind {
    match self {
        // ... existing variants
        PubsubMessage::LightClientOptimisticUpdate(_) => {
            GossipKind::LightClientOptimisticUpdate
        }
    }
}
```

**Add:**
```rust
        PubsubMessage::ExecutionProofMessage(data) => {
            let (subnet_id, _) = &**data;
            GossipKind::ExecutionProof(*subnet_id)
        }
```

---

### 1.6: Implement id() Method

**Location:** `impl<E: EthSpec> PubsubMessage<E>` → `id()` method (around line 550)

**Find:**
```rust
pub fn id(&self) -> String {
    match self {
        // ... existing variants
        PubsubMessage::LightClientOptimisticUpdate(_) => {
            "lc_optimistic_update".to_string()
        }
    }
}
```

**Add:**
```rust
        PubsubMessage::ExecutionProofMessage(data) => {
            let (subnet_id, proof) = &**data;
            format!(
                "exec_proof_{}:{}:{}",
                subnet_id.as_u8(),
                proof.block_hash,
                proof.block_root
            )
        }
```

**Why this format:**
- Unique per proof (block_hash + block_root + subnet)
- Used for deduplication in gossip cache
- Helps with debugging/logging

---

### 1.7: Verification

**Run:**
```bash
cargo check --package lighthouse_network
```

**Expected:** Should compile without errors

**If you see errors about missing methods**, you may also need to add cases to:
- `as_voluntary_exit()` (return None)
- `as_proposer_slashing()` (return None)
- `as_attester_slashing()` (return None)
- etc.

These are accessor methods that return `None` for non-matching types.

---

---

## Step 2: Router Integration

**Status:** ⏸️ NOT STARTED (No explicit TODO yet, but follows Step 1)
**Estimated Time:** 1 hour
**File:** `beacon_node/network/src/router/mod.rs`

**Prerequisites:** Step 1 must be complete first

### 2.1: Add Import

**Location:** Top of file

**Add:**
```rust
use types::{ExecutionProof, ExecutionProofSubnetId};
use tokio::sync::mpsc;
```

---

### 2.2: Add Field to Router Struct

**Location:** `pub struct Router<T: EthSpec>` (around line 60)

**Find:**
```rust
pub struct Router<T: EthSpec> {
    /// Access to the peer database
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// Sends messages to the beacon processor
    beacon_processor_send: BeaconProcessorSend<T>,
    // ... other fields
}
```

**Add field:**
```rust
    /// Channel to send execution proofs to stateless-EL (if configured)
    stateless_el_proof_tx: Option<mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>,
```

---

### 2.3: Update Router Constructor

**Location:** `impl<T: EthSpec> Router<T>` → `new()` method

**Find:**
```rust
pub fn new(
    beacon_processor_send: BeaconProcessorSend<T>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    // ... other params
) -> Self {
    Self {
        beacon_processor_send,
        network_globals,
        // ... other fields
    }
}
```

**Add parameter:**
```rust
pub fn new(
    beacon_processor_send: BeaconProcessorSend<T>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    stateless_el_proof_tx: Option<mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>,
    // ... other params
) -> Self {
    Self {
        beacon_processor_send,
        network_globals,
        stateless_el_proof_tx,
        // ... other fields
    }
}
```

---

### 2.4: Handle ExecutionProofMessage in Routing Logic

**Location:** `handle_gossip_message()` method (or wherever gossip messages are routed)

**Find where messages are matched and routed. It might look like:**
```rust
fn handle_gossip_message(
    &mut self,
    id: PeerId,
    peer_client: Client,
    message: PubsubMessage<T::EthSpec>,
    // ...
) {
    match message {
        PubsubMessage::BeaconBlock(block) => {
            // Route to beacon processor
        }
        // ... other cases
    }
}
```

**Add case for ExecutionProofMessage:**
```rust
        PubsubMessage::ExecutionProofMessage(data) => {
            if let Some(tx) = &self.stateless_el_proof_tx {
                let (subnet_id, proof) = *data;

                debug!(
                    self.log,
                    "Forwarding execution proof to stateless-EL";
                    "subnet_id" => subnet_id.as_u8(),
                    "block_hash" => ?proof.block_hash,
                    "block_root" => ?proof.block_root,
                    "peer_id" => %id,
                );

                if let Err(e) = tx.send((subnet_id, proof)) {
                    warn!(
                        self.log,
                        "Failed to send execution proof to stateless-EL";
                        "error" => ?e,
                        "subnet_id" => subnet_id.as_u8(),
                    );
                }
            } else {
                // Stateless-EL not configured, log and ignore
                debug!(
                    self.log,
                    "Received execution proof but stateless-EL not configured";
                    "subnet_id" => data.0.as_u8(),
                    "peer_id" => %id,
                );
            }

            // No need to send to beacon processor - stateless-EL handles this
        }
```

**Important notes:**
- Only route to stateless-EL, **not** to beacon processor
- This is different from blocks/attestations which go to beacon processor
- Similar to how data columns might be routed directly to DA checker

---

### 2.5: Add Setter Method (Optional but Recommended)

**Location:** `impl<T: EthSpec> Router<T>`

**Add method to allow setting the channel after construction:**
```rust
    /// Set the stateless-EL proof sender channel
    pub fn set_stateless_el_proof_tx(
        &mut self,
        tx: mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>,
    ) {
        self.stateless_el_proof_tx = Some(tx);
    }
```

**Why:** Allows beacon node to configure router after creation if needed.

---

### 2.6: Update Call Sites

**Location:** Find where `Router::new()` is called (likely in `beacon_node/network/src/service/mod.rs` or similar)

**Find:**
```rust
let router = Router::new(
    beacon_processor_send,
    network_globals.clone(),
    // ... other params
);
```

**Update to:**
```rust
let router = Router::new(
    beacon_processor_send,
    network_globals.clone(),
    None, // stateless_el_proof_tx - will be set later
    // ... other params
);
```

---

### 2.7: Verification

**Run:**
```bash
cargo check --package network
```

**Expected:** Should compile without errors

---

---

## Step 3: Beacon Node Initialization and Wiring

**Status:** ⏸️ NOT STARTED (No explicit TODO yet, but follows Steps 1-2)
**Estimated Time:** 1-2 hours
**File:** `beacon_node/src/lib.rs`

**Prerequisites:** Steps 1-2 must be complete first

This is the most complex step as it involves understanding the beacon node initialization flow.

### 3.1: Add Imports

**Location:** Top of file

**Add:**
```rust
use stateless_execution_layer::StatelessExecutionLayer;
use tokio::sync::mpsc;
use types::{ExecutionProof, ExecutionProofSubnetId};
```

---

### 3.2: Parse CLI Configuration

**Location:** Where `ClientConfig` is processed (search for `client_config.chain`)

**Find where chain config is used to initialize components.**

**You need to add fields to `ChainConfig`** (in `beacon_node/beacon_chain/src/chain_config.rs`):

```rust
pub struct ChainConfig {
    // ... existing fields

    /// Enable stateless execution layer instead of full EL
    pub stateless_execution_layer: bool,

    /// Execution proof subnets to subscribe to (for verification)
    pub verify_execution_proof_subnets: HashSet<ExecutionProofSubnetId>,

    /// Minimum proofs required from different subnets
    pub min_proofs_required: usize,

    /// Execution proof subnets to generate proofs for
    pub generate_execution_proof_subnets: HashSet<ExecutionProofSubnetId>,
}
```

---

### 3.3: Create Stateless-EL Proof Channels

**Location:** In beacon node initialization, before creating network service

**Add:**
```rust
// Create channels for execution proof flow:
// - Network receives proofs from gossip
// - Sends to stateless-EL via proof_rx
// - Stateless-EL sends proofs to publish via proof_tx
let (proof_to_sel_tx, proof_from_net_rx) = mpsc::unbounded_channel();
let (proof_from_sel_tx, proof_to_net_rx) = mpsc::unbounded_channel();
```

**Channel flow:**
```
Gossip → Router → proof_to_sel_tx → proof_from_net_rx → Stateless-EL
                                                              ↓
Network ← proof_to_net_rx ← proof_from_sel_tx ← Stateless-EL
```

---

### 3.4: Create Stateless-EL Instance

**Location:** After creating ExecutionLayer config, before creating BeaconChain

**Add:**
```rust
// Create stateless-EL if configured
let stateless_el = if client_config.chain.stateless_execution_layer {
    info!(
        context.log(),
        "Initializing stateless execution layer";
        "verify_subnets" => ?client_config.chain.verify_execution_proof_subnets,
        "generate_subnets" => ?client_config.chain.generate_execution_proof_subnets,
        "min_proofs_required" => client_config.chain.min_proofs_required,
    );

    // Create configuration
    let config = StatelessExecutionLayerConfig::builder()
        .subscribed_subnets(client_config.chain.verify_execution_proof_subnets.clone())
        .min_proofs_required(client_config.chain.min_proofs_required)
        .generation_subnets(client_config.chain.generate_execution_proof_subnets.clone())
        .proof_cache_size(1024) // TODO: Make configurable
        .build();

    // Create instance
    let sel = StatelessExecutionLayer::new(
        config,
        proof_from_net_rx,      // Receives proofs from network
        proof_from_sel_tx,      // Sends proofs to network
        context.log().clone(),
    )?;

    Some(Arc::new(sel))
} else {
    None
};
```

---

### 3.5: Update ExecutionLayer Creation

**Location:** Where ExecutionLayer is created

**Find:**
```rust
let execution_layer = ExecutionLayer::new(
    // ... params
)?;
```

**Modify to use stateless-EL if configured:**
```rust
let execution_layer = if let Some(sel) = stateless_el.clone() {
    // Use stateless-EL as execution backend
    info!(context.log(), "Using stateless execution layer as execution backend");

    ExecutionLayer::new_stateless(
        sel,
        context.log().clone(),
    )?
} else {
    // Use full execution engine
    ExecutionLayer::new(
        client_config.execution_endpoint.clone(),
        // ... other params
    )?
};
```

**Note:** `ExecutionLayer::new_stateless()` needs to be implemented (see Step 3.7)

---

### 3.6: Wire Router to Stateless-EL

**Location:** After creating network service and router

**Find where router is created or configured:**
```rust
let mut router = Router::new(/* ... */);
```

**Add:**
```rust
// Configure router to forward execution proofs to stateless-EL
if stateless_el.is_some() {
    router.set_stateless_el_proof_tx(proof_to_sel_tx);
    info!(context.log(), "Router configured to forward execution proofs to stateless-EL");
}
```

---

### 3.7: Update ExecutionLayer to Support Stateless Backend

**File:** `beacon_node/execution_layer/src/lib.rs`

**Add enum for execution backend:**
```rust
pub enum ExecutionBackend {
    /// Full execution engine (geth, nethermind, etc.)
    Full {
        engines: Engines<EngineApi>,
        // ... other fields
    },

    /// Stateless execution layer
    Stateless(Arc<StatelessExecutionLayer>),
}
```

**Update ExecutionLayer struct:**
```rust
pub struct ExecutionLayer<T: EthSpec> {
    backend: ExecutionBackend,
    // ... other fields
}
```

**Add constructor:**
```rust
impl<T: EthSpec> ExecutionLayer<T> {
    pub fn new_stateless(
        stateless_el: Arc<StatelessExecutionLayer>,
        log: Logger,
    ) -> Result<Self, Error> {
        Ok(Self {
            backend: ExecutionBackend::Stateless(stateless_el),
            log,
            // ... initialize other fields appropriately
        })
    }
}
```

**Update new_payload() method:**
```rust
pub async fn new_payload(
    &self,
    payload: ExecutionPayload<T>,
) -> Result<PayloadStatus, Error> {
    match &self.backend {
        ExecutionBackend::Full { engines, .. } => {
            // Existing full EL logic
            engines.request(|engine| engine.new_payload(payload)).await
        }
        ExecutionBackend::Stateless(sel) => {
            // Call stateless-EL
            sel.new_payload(payload).await
                .map_err(|e| Error::StatelessExecution(e))
        }
    }
}
```

**Similar updates needed for:**
- `forkchoice_updated()`
- `get_payload()` (might not be supported - return error for stateless)
- Other Engine API methods

---

### 3.8: Handle Proof Publishing from Stateless-EL

**Location:** Spawn a task to handle proofs that stateless-EL wants to publish

**Add after creating stateless-EL:**
```rust
// Spawn task to handle proof publishing from stateless-EL
if stateless_el.is_some() {
    let network_send = network_send.clone(); // Get network sender
    let log = context.log().clone();

    context.executor.spawn(
        async move {
            while let Some((subnet_id, proof)) = proof_to_net_rx.recv().await {
                debug!(
                    log,
                    "Publishing execution proof to network";
                    "subnet_id" => subnet_id.as_u8(),
                    "block_hash" => ?proof.block_hash,
                );

                // Create gossip message
                let message = PubsubMessage::ExecutionProofMessage(Box::new((
                    subnet_id,
                    proof,
                )));

                // Send to network for gossip
                if let Err(e) = network_send.send(NetworkMessage::Publish { message }) {
                    warn!(log, "Failed to publish execution proof"; "error" => ?e);
                }
            }
        },
        "stateless_el_proof_publisher",
    );
}
```

**Note:** The exact API for `network_send` will depend on how Lighthouse's network service accepts messages for publishing. You may need to adjust this based on the actual network API.

---

### 3.9: Update NetworkConfig

**File:** `beacon_node/lighthouse_network/src/config.rs`

**Add field:**
```rust
pub struct Config {
    // ... existing fields

    /// Execution proof subnets to subscribe to
    pub execution_proof_subnets: HashSet<ExecutionProofSubnetId>,
}
```

**Set from ChainConfig:**
```rust
network_config.execution_proof_subnets = client_config.chain.verify_execution_proof_subnets.clone();
```

---

### 3.10: Verification

**Run full build:**
```bash
cargo check --package beacon_node
```

**Then try running:**
```bash
cargo build --package beacon_node
```

**Expected:** Should compile without errors

**Test with:**
```bash
# Just check stateless-EL can be instantiated
lighthouse bn --stateless-execution-layer --help
```

---

## Testing the Complete Flow

### Integration Test Approach

**File:** Create `beacon_node/network/tests/execution_proof_flow.rs`

```rust
#[tokio::test]
async fn test_execution_proof_gossip_flow() {
    // 1. Create test execution proof
    let subnet_id = ExecutionProofSubnetId::new(0).unwrap();
    let proof = ExecutionProof::new(/* ... */);

    // 2. Create gossip message
    let message = PubsubMessage::ExecutionProofMessage(Box::new((
        subnet_id,
        Arc::new(proof),
    )));

    // 3. Encode to SSZ
    let encoded = message.encode(GossipEncoding::SSZSnappy);

    // 4. Decode back
    let decoded = PubsubMessage::decode(
        GossipKind::ExecutionProof(subnet_id),
        &encoded,
        GossipEncoding::SSZSnappy,
    ).unwrap();

    // 5. Verify round-trip
    match decoded {
        PubsubMessage::ExecutionProofMessage(data) => {
            assert_eq!(data.0, subnet_id);
            // Additional assertions
        }
        _ => panic!("Wrong message type"),
    }
}
```

---

## Troubleshooting Guide

### Issue: Compiler error "ExecutionProof not found"

**Solution:** Add import:
```rust
use types::ExecutionProof;
```

---

### Issue: "stateless_execution_layer crate not found"

**Solution:** Add to `beacon_node/Cargo.toml`:
```toml
[dependencies]
stateless_execution_layer = { path = "../stateless_execution_layer" }
```

---

### Issue: "Channel disconnected" warnings at runtime

**Cause:** Stateless-EL dropped or never created, but router trying to send

**Solution:** Check that:
1. Stateless-EL is actually created when flag is set
2. Channel is properly connected
3. Receiver (stateless-EL) is running

---

### Issue: Proofs not appearing in stateless-EL

**Debug steps:**
1. Add logging in `Router::handle_gossip_message()` for ExecutionProofMessage case
2. Check if `stateless_el_proof_tx.is_some()`
3. Verify gossip subscription is working (`core_topics_to_subscribe` returns ExecutionProof)
4. Check ENR has execution_proof_subnets (future - OK to skip for now)

---

## Success Criteria

### Step 1 Complete When:
- ✅ `cargo check --package lighthouse_network` succeeds
- ✅ PubsubMessage has ExecutionProofMessage variant
- ✅ Decoding/encoding implemented
- ✅ kind() and id() methods implemented

### Step 2 Complete When:
- ✅ `cargo check --package network` succeeds
- ✅ Router has stateless_el_proof_tx field
- ✅ ExecutionProofMessage routed to stateless-EL, not beacon processor

### Step 3 Complete When:
- ✅ `cargo build --package beacon_node` succeeds
- ✅ Beacon node can start with `--stateless-execution-layer` flag
- ✅ Channels created and wired correctly
- ✅ ExecutionLayer supports stateless backend
- ✅ Proof publishing task spawned

### Integration Complete When:
- ✅ Gossip proof → Router → Stateless-EL (can add logging to verify)
- ✅ Stateless-EL → Network for publishing (can add logging to verify)
- ✅ No panics or channel disconnection errors

---

## Estimated Timeline

| Step | Task | Time | Complexity |
|------|------|------|------------|
| 1.1-1.3 | PubsubMessage variant + decode | 15 min | Low |
| 1.4-1.6 | Encode, kind, id methods | 10 min | Low |
| 1.7 | Verification + fixes | 5 min | Low |
| 2.1-2.4 | Router field + routing | 20 min | Low |
| 2.5-2.6 | Call site updates | 10 min | Low |
| 2.7 | Verification + fixes | 10 min | Low |
| 3.1-3.2 | Config setup | 15 min | Medium |
| 3.3-3.4 | Channel creation + stateless-EL init | 20 min | Medium |
| 3.5-3.6 | ExecutionLayer wiring | 15 min | Medium |
| 3.7 | ExecutionBackend enum | 30 min | High |
| 3.8 | Proof publishing task | 15 min | Medium |
| 3.9 | NetworkConfig update | 10 min | Low |
| 3.10 | Verification + debugging | 30 min | Medium |
| **Total** | | **3-4 hours** | |

**Note:** Times are estimates. Debugging and understanding existing code patterns may take additional time.

---

## Related TODOs in Codebase

Based on Phase 2 foundation work, these TODOs were added that relate to future phases:

### ENR & Peer Discovery (Phase 2.4)
- `subnet_predicate.rs:45-46`: "TODO: Add ENR metadata support for execution proof subnets"
- `discovery/mod.rs:563-564`: "TODO: Add ENR metadata support for execution proof subnets"

### Peer Metadata & Tracking (Phase 2.5)
- `peer_info.rs:108-109`: "TODO: Add metadata support for execution proof subnets"
- `peer_manager/mod.rs:1084-1085`: "TODO: Track execution proof subnets in peer_info"

### Configuration & State (Step 3 dependencies)
- `globals.rs:226`: "TODO: Add execution proof subnet tracking" (needs field in NetworkGlobals)

These TODOs should be addressed in **later phases** after Steps 1-3 are complete.

---

## Next Steps After Completion

Once Steps 1-3 are complete:

1. **Test end-to-end:** Use local testnet to verify proof flow
2. **Phase 3:** DA checker integration
3. **Phase 4:** RPC proof fetching (ExecutionProofsByRoot)
4. **Phase 2.4:** ENR advertisement
5. **Phase 2.5:** Metadata protocol

---

**Document Version:** 1.0
**Created:** 2025-10-15
**For:** Stateless Execution Layer Implementation
**Prerequisites:** Phase 1 complete, Phase 2 foundation complete
