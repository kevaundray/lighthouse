# Phase 2 - Step 3: Beacon Node Wiring - Detailed Implementation Plan

**Date:** 2025-10-15
**Status:** PLANNING - Steps 1 & 2 Complete, Ready for Step 3
**Prerequisite:** Stateless-EL crate exists and compiles ✅

---

## Overview

Step 3 connects the execution proof gossip infrastructure (Steps 1-2) with the `StatelessExecutionLayer` component in the beacon node initialization flow. This creates the complete message flow:

```
Gossip Network → Router → StatelessEL → Proof Verification
                     ↑
                     └── Proof Generation (if configured)
```

### Key Integration Points

1. **Beacon node initialization** (`beacon_node/client/src/builder.rs`)
2. **Network service startup** (`beacon_node/network/src/service.rs`)
3. **Router channel wiring** (`beacon_node/network/src/router.rs`)
4. **CLI configuration** (`lighthouse/src/cli.rs`, `beacon_node/src/config.rs`)
5. **Execution layer integration** (`beacon_node/execution_layer/src/lib.rs`)

---

## Architecture Decision: Where to Initialize StatelessEL?

###  **Option A: Parallel to ExecutionLayer** (RECOMMENDED)

Initialize StatelessEL alongside ExecutionLayer in `beacon_chain_builder()` method.

**Pros:**
- Clean separation of concerns
- Stateless-EL is independent from full-EL
- Easy to enable/disable via flag
- Mirrors existing ExecutionLayer pattern

**Cons:**
- Slightly more complex initialization
- Two separate components to manage

### Option B: Inside ExecutionLayer

Make ExecutionLayer wrap StatelessEL internally.

**Pros:**
- Single execution component
- Simpler from beacon chain perspective

**Cons:**
- Tight coupling between full-EL and stateless-EL
- Harder to test independently
- Complicates ExecutionLayer logic

**DECISION:** Use Option A - parallel initialization with independent lifecycle.

---

## Step 3.1: Add CLI Flags

**File:** `lighthouse/src/cli.rs`
**Location:** In the `beacon_node_subcommand()` function, add new flags

### Flags to Add:

```rust
.arg(
    Arg::new("stateless-execution-layer")
        .long("stateless-execution-layer")
        .help("Enable stateless execution layer for proof-based payload verification. \
               Requires subscription to execution proof subnets.")
        .action(ArgAction::SetTrue)
)
.arg(
    Arg::new("verify-execution-proof-subnets")
        .long("verify-execution-proof-subnets")
        .value_name("SUBNETS")
        .help("Comma-separated list of execution proof subnet IDs to subscribe to for \
               verification (0-7). Example: --verify-execution-proof-subnets 0,1,2")
        .value_delimiter(',')
        .requires("stateless-execution-layer")
)
.arg(
    Arg::new("generate-execution-proof-subnets")
        .long("generate-execution-proof-subnets")
        .value_name("SUBNETS")
        .help("Comma-separated list of execution proof subnet IDs to generate proofs for \
               (0-7). Example: --generate-execution-proof-subnets 3,4")
        .value_delimiter(',')
        .requires("stateless-execution-layer")
)
.arg(
    Arg::new("stateless-el-min-proofs")
        .long("stateless-el-min-proofs")
        .value_name("COUNT")
        .help("Minimum number of valid proofs from different subnets required to accept \
               a payload (default: 1)")
        .default_value("1")
        .requires("stateless-execution-layer")
)
```

### Usage Examples:

```bash
# Verify-only node (subscribe to subnets 0 and 1)
lighthouse bn --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1

# Generator node (generate for subnet 2, verify subnets 0,1,2)
lighthouse bn --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1,2 \
  --generate-execution-proof-subnets 2

# Require 2 proofs from different subnets
lighthouse bn --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1,2,3 \
  --stateless-el-min-proofs 2
```

---

## Step 3.2: Parse Configuration

**File:** `beacon_node/src/config.rs`
**Location:** In `get_config()` function, after execution_layer config parsing

### Add to ClientConfig

First, check if `ClientConfig` needs a new field:

**File:** `beacon_node/client/src/config.rs`

```rust
pub struct ClientConfig {
    // ... existing fields

    /// Stateless execution layer configuration (if enabled)
    pub stateless_execution_layer: Option<StatelessExecutionLayerConfig>,
}
```

### Parse CLI Arguments

**In `beacon_node/src/config.rs`**, add after execution layer config (around line 325):

```rust
/*
 * Stateless Execution Layer
 */
if cli_args.get_flag("stateless-execution-layer") {
    use stateless_execution_layer::StatelessExecutionLayerConfigBuilder;
    use types::ExecutionProofSubnetId;

    let mut config_builder = StatelessExecutionLayerConfigBuilder::default();

    // Parse subscription subnets (required)
    let verify_subnets_str: Vec<&str> = cli_args
        .get_many::<String>("verify-execution-proof-subnets")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    if verify_subnets_str.is_empty() {
        return Err(
            "--stateless-execution-layer requires --verify-execution-proof-subnets".to_string()
        );
    }

    for subnet_str in verify_subnets_str {
        let subnet_id = subnet_str
            .parse::<u8>()
            .map_err(|_| format!("Invalid subnet ID: {}", subnet_str))
            .and_then(|id| {
                ExecutionProofSubnetId::new(id)
                    .map_err(|e| format!("Invalid subnet ID {}: {:?}", id, e))
            })?;
        config_builder = config_builder.add_subscribed_subnet(subnet_id);
    }

    // Parse generation subnets (optional)
    if let Some(generate_subnets) = cli_args.get_many::<String>("generate-execution-proof-subnets") {
        for subnet_str in generate_subnets {
            let subnet_id = subnet_str
                .parse::<u8>()
                .map_err(|_| format!("Invalid subnet ID: {}", subnet_str))
                .and_then(|id| {
                    ExecutionProofSubnetId::new(id)
                        .map_err(|e| format!("Invalid subnet ID {}: {:?}", id, e))
                })?;
            config_builder = config_builder.add_generation_subnet(subnet_id);
        }
    }

    // Parse min proofs required
    if let Some(min_proofs_str) = cli_args.get_one::<String>("stateless-el-min-proofs") {
        let min_proofs = min_proofs_str
            .parse::<usize>()
            .map_err(|_| "Invalid value for --stateless-el-min-proofs")?;

        if min_proofs == 0 {
            return Err("--stateless-el-min-proofs must be at least 1".to_string());
        }

        config_builder = config_builder.min_proofs_required(min_proofs);
    }

    let stateless_el_config = config_builder
        .build()
        .map_err(|e| format!("Invalid stateless-EL configuration: {}", e))?;

    client_config.stateless_execution_layer = Some(stateless_el_config);

    info!(
        "Stateless execution layer enabled";
        "verify_subnets" => ?stateless_el_config.subscribed_subnets,
        "generate_subnets" => ?stateless_el_config.generation_subnets,
        "min_proofs" => stateless_el_config.min_proofs_required,
    );
}
```

---

## Step 3.3: Initialize StatelessExecutionLayer

**File:** `beacon_node/client/src/builder.rs`
**Location:** In `beacon_chain_builder()` method, after ExecutionLayer initialization

### Context

The `beacon_chain_builder()` method (around line 178) already initializes `ExecutionLayer`:

```rust
let execution_layer = if let Some(config) = config.execution_layer.clone() {
    let context = runtime_context.service_context("exec".into());
    let execution_layer = ExecutionLayer::from_config(config, context.executor.clone())
        .map_err(|e| format!("unable to start execution layer endpoints: {:?}", e))?;
    Some(execution_layer)
} else {
    None
};
```

### Add After ExecutionLayer Init:

```rust
// Initialize StatelessExecutionLayer if configured
let stateless_execution_layer = if let Some(sel_config) = config.stateless_execution_layer.clone() {
    use stateless_execution_layer::StatelessExecutionLayer;

    let context = runtime_context.service_context("stateless_exec".into());
    let log = context.log().clone();

    let stateless_el = StatelessExecutionLayer::new(sel_config, log)
        .map_err(|e| format!("Failed to initialize stateless execution layer: {:?}", e))?;

    Some(Arc::new(stateless_el))
} else {
    None
};
```

### Store in BeaconChainBuilder

The `BeaconChainBuilder` needs to receive the stateless_el instance. We need to check if `BeaconChainBuilder` has a method for this or if we need to add one.

**TODO:** Check `beacon_chain/src/builder.rs` for the builder pattern. Likely need to add:

```rust
// In BeaconChainBuilder
pub fn stateless_execution_layer(
    mut self,
    stateless_el: Option<Arc<StatelessExecutionLayer>>,
) -> Self {
    self.stateless_execution_layer = stateless_el;
    self
}
```

Then use it:

```rust
let builder = BeaconChainBuilder::new(eth_spec_instance, Arc::new(kzg))
    .store(store)
    // ... existing methods
    .execution_layer(execution_layer)
    .stateless_execution_layer(stateless_execution_layer) // NEW
    // ... rest
```

---

## Step 3.4: Configure Network Gossip Subscriptions

**File:** `beacon_node/src/config.rs`
**Location:** In `set_network_config()` function

### Add Execution Proof Subnet Subscriptions:

After the line that sets network config (around line 1431):

```rust
// Configure execution proof subnet subscriptions for stateless-EL
if let Some(ref stateless_el_config) = client_config.stateless_execution_layer {
    config.execution_proof_subnets = stateless_el_config.subscribed_subnets.clone();

    info!(
        "Configured execution proof gossip subscriptions";
        "subnets" => ?config.execution_proof_subnets,
    );
}
```

**Note:** This requires adding `execution_proof_subnets` field to `NetworkConfig`.

**File:** `beacon_node/lighthouse_network/src/config.rs` (or wherever NetworkConfig is defined)

```rust
pub struct NetworkConfig {
    // ... existing fields

    /// Execution proof subnets to subscribe to (for stateless-EL)
    pub execution_proof_subnets: HashSet<ExecutionProofSubnetId>,
}
```

And in `Default` impl:

```rust
impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            // ... existing fields
            execution_proof_subnets: HashSet::new(),
        }
    }
}
```

---

## Step 3.5: Create Proof Channels

**File:** `beacon_node/client/src/builder.rs`
**Location:** In `network()` method, before `NetworkService::start()`

### Create Bidirectional Channels:

The `network()` method (around line 456) starts the network service. We need to create channels for proof communication:

```rust
pub async fn network(mut self, config: Arc<NetworkConfig>) -> Result<Self, String> {
    let beacon_chain = self
        .beacon_chain
        .clone()
        .ok_or("network requires a beacon chain")?;
    let context = self
        .runtime_context
        .as_ref()
        .ok_or("network requires a runtime_context")?
        .clone();
    let beacon_processor_channels = self
        .beacon_processor_channels
        .as_ref()
        .ok_or("network requires beacon_processor_channels")?;

    // NEW: Create proof channels if stateless-EL is configured
    let proof_channels = if beacon_chain.stateless_execution_layer.is_some() {
        use tokio::sync::mpsc;
        use types::{ExecutionProof, ExecutionProofSubnetId};

        // Gossip → StatelessEL: Router sends received proofs here
        let (gossip_to_sel_tx, gossip_to_sel_rx) = mpsc::unbounded_channel::<(
            ExecutionProofSubnetId,
            Arc<ExecutionProof>,
        )>();

        // StatelessEL → Gossip: StatelessEL publishes generated proofs here
        let (sel_to_gossip_tx, sel_to_gossip_rx) = mpsc::unbounded_channel::<(
            ExecutionProofSubnetId,
            Arc<ExecutionProof>,
        )>();

        Some((
            gossip_to_sel_tx,
            gossip_to_sel_rx,
            sel_to_gossip_tx,
            sel_to_gossip_rx,
        ))
    } else {
        None
    };

    // ... existing code continues
```

---

## Step 3.6: Wire Router with Proof Channel

**File:** `beacon_node/network/src/service.rs`
**Location:** In `build()` method where Router is spawned

### Pass Proof TX to Router:

Currently the `Router::spawn()` method doesn't accept a proof channel. We need to modify it.

**File:** `beacon_node/network/src/router.rs`

Update `Router::spawn()` signature:

```rust
pub fn spawn(
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    executor: task_executor::TaskExecutor,
    invalid_block_storage: InvalidBlockStorage,
    beacon_processor_send: BeaconProcessorSend<T::EthSpec>,
    fork_context: Arc<ForkContext>,
    stateless_el_proof_tx: Option<mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>, // NEW
) -> Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>, String> {
```

And update Router initialization:

```rust
let mut handler = Router {
    network_globals,
    chain: beacon_chain,
    sync_send,
    network: HandlerNetworkContext::new(network_send),
    network_beacon_processor,
    logger_debounce: TimeLatch::default(),
    stateless_el_proof_tx, // Use the provided channel instead of None
};
```

### Update Router Call Site:

**File:** `beacon_node/network/src/service.rs`

In the `build()` method (around line 300), pass the channel:

```rust
let router_send = Router::spawn(
    beacon_chain.clone(),
    network_globals.clone(),
    network_send.clone(),
    executor.clone(),
    config.invalid_block_storage.clone(),
    beacon_processor_send.clone(),
    fork_context.clone(),
    stateless_el_proof_tx, // NEW - from proof_channels
)?;
```

### Update Router Handle Method:

**File:** `beacon_node/network/src/router.rs`

In `handle_gossip()`, uncomment the forwarding logic:

```rust
PubsubMessage::ExecutionProofMessage(data) => {
    let (subnet_id, proof) = *data;

    // Forward to stateless-EL if channel available
    if let Some(tx) = &self.stateless_el_proof_tx {
        if let Err(e) = tx.send((subnet_id, proof.clone())) {
            warn!(
                self.chain.log,
                "Failed to send execution proof to stateless-EL";
                "error" => ?e,
                "subnet_id" => subnet_id.as_u8(),
            );
        } else {
            debug!(
                self.chain.log,
                "Forwarded execution proof to stateless-EL";
                "subnet_id" => subnet_id.as_u8(),
                "block_hash" => ?proof.block_hash,
            );
        }
    } else {
        // Stateless-EL not configured, just log
        debug!(
            self.chain.log,
            "Received execution proof (stateless-EL not configured)";
            "subnet_id" => subnet_id.as_u8(),
            "block_hash" => ?proof.block_hash,
        );
    }
}
```

---

## Step 3.7: Spawn Proof Receiver Task

**File:** `beacon_node/client/src/builder.rs`
**Location:** In `network()` method, after `NetworkService::start()`

### Spawn Task to Process Incoming Proofs:

```rust
// Spawn task to forward gossip proofs to stateless-EL
if let Some((gossip_to_sel_tx, mut gossip_to_sel_rx, sel_to_gossip_tx, sel_to_gossip_rx)) = proof_channels {
    // Get stateless-EL reference
    if let Some(stateless_el) = beacon_chain.stateless_execution_layer.as_ref() {
        // Configure stateless-EL with network TX for publishing
        {
            let mut sel = stateless_el.clone();
            sel.set_network_tx(sel_to_gossip_tx);
        }

        // Spawn task: Gossip → StatelessEL
        let sel_clone = stateless_el.clone();
        let log = context.log().clone();
        context.executor.spawn(
            async move {
                while let Some((subnet_id, proof)) = gossip_to_sel_rx.recv().await {
                    debug!(
                        log,
                        "Forwarding gossip proof to stateless-EL";
                        "subnet_id" => subnet_id.as_u8(),
                        "block_hash" => ?proof.block_hash,
                    );

                    if let Err(e) = sel_clone.on_gossip_proof_received(subnet_id, proof).await {
                        warn!(
                            log,
                            "Stateless-EL rejected proof";
                            "error" => ?e,
                            "subnet_id" => subnet_id.as_u8(),
                        );
                    }
                }
            },
            "stateless_el_proof_receiver",
        );

        // Spawn task: StatelessEL → Gossip
        let network_send = self.network_senders
            .as_ref()
            .ok_or("network_senders required for stateless-EL")?
            .clone();
        let log = context.log().clone();
        context.executor.spawn(
            async move {
                while let Some((subnet_id, proof)) = sel_to_gossip_rx.recv().await {
                    debug!(
                        log,
                        "Publishing stateless-EL proof to gossip";
                        "subnet_id" => subnet_id.as_u8(),
                        "block_hash" => ?proof.block_hash,
                    );

                    // TODO: Actually publish to gossip network
                    // This requires adding a method to NetworkSenders to publish proofs
                    // For now, just log
                    warn!(log, "Proof publishing not yet implemented");
                }
            },
            "stateless_el_proof_publisher",
        );
    }
}
```

---

## Step 3.8: Integrate with ExecutionLayer (Optional)

**Goal:** Make `ExecutionLayer` query `StatelessExecutionLayer` for payload validation when available.

**File:** `beacon_node/execution_layer/src/lib.rs`

### Approach 1: BeaconChain Manages Logic (SIMPLER)

Don't modify ExecutionLayer. Instead, beacon chain's `process_new_payload()` checks stateless-EL first:

```rust
// In BeaconChain
pub async fn process_new_payload(&self, payload: ExecutionPayload) -> Result<PayloadStatus> {
    // Try stateless-EL first if available
    if let Some(stateless_el) = &self.stateless_execution_layer {
        match stateless_el.new_payload(payload.block_hash(), block_root).await {
            Ok(PayloadStatus::Valid) => return Ok(PayloadStatus::Valid),
            Ok(PayloadStatus::Invalid { error }) => return Ok(PayloadStatus::Invalid { error }),
            Ok(PayloadStatus::Syncing) => {
                // Fall through to full EL if we don't have proofs yet
                debug!(self.log, "Stateless-EL syncing, falling back to full EL");
            }
            Err(e) => {
                warn!(self.log, "Stateless-EL error, falling back to full EL"; "error" => ?e);
            }
        }
    }

    // Fall back to full execution layer
    self.execution_layer.new_payload(payload).await
}
```

### Approach 2: ExecutionLayer Wraps Stateless-EL (MORE COMPLEX)

Add stateless-EL as field in ExecutionLayer and check it in `new_payload()`.

**RECOMMENDATION:** Start with Approach 1 for Step 3. Move to Approach 2 in later phase if needed.

---

## Step 3.9: Update Gossip Topic Subscriptions

**File:** `beacon_node/lighthouse_network/src/types/topics.rs`

The `core_topics_to_subscribe()` function (line 99) already has execution proof subscription logic from Step 2:

```rust
// Subscribe to execution proof subnets if configured
for subnet in &opts.execution_proof_subnets {
    topics.push(GossipKind::ExecutionProof(*subnet));
}
```

This will automatically subscribe when `NetworkConfig.execution_proof_subnets` is populated (Step 3.4).

**No changes needed - already complete from Step 2.**

---

## Compilation Checklist

After implementing Step 3, verify:

```bash
# 1. Check stateless_execution_layer compiles
cargo check -p stateless_execution_layer

# 2. Check beacon_node/client compiles
cargo check -p client

# 3. Check network compiles
cargo check -p network

# 4. Check beacon_node compiles
cargo check -p beacon_node

# 5. Check lighthouse binary compiles
cargo check -p lighthouse
```

---

## Testing Plan

### Unit Tests

1. **Config parsing tests** (`beacon_node/src/config.rs`)
   - Test valid subnet ID parsing
   - Test invalid subnet IDs rejected
   - Test min_proofs validation
   - Test missing required flags

2. **Channel wiring tests** (`beacon_node/client/src/builder.rs`)
   - Mock proof flow through channels
   - Verify proofs reach stateless-EL
   - Verify generated proofs reach network

### Integration Tests

1. **Local testnet with stateless-EL**
   - Start node with `--stateless-execution-layer --verify-execution-proof-subnets 0`
   - Verify gossip subscriptions active
   - Send test proof via network
   - Verify proof reaches stateless-EL

2. **Two-node setup**
   - Node 1: Generates proofs (subnet 0)
   - Node 2: Verifies proofs (subnet 0)
   - Verify proof propagation

### Manual Testing

```bash
# 1. Start stateless-EL enabled node
lighthouse bn \
  --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1 \
  --stateless-el-min-proofs 1 \
  --execution-endpoint http://localhost:8551

# 2. Check logs for:
grep "Stateless execution layer enabled" beacon.log
grep "Configured execution proof gossip subscriptions" beacon.log
grep "Forwarding gossip proof to stateless-EL" beacon.log

# 3. Monitor metrics (if added):
curl http://localhost:5054/metrics | grep execution_proof
```

---

## Files Modified Summary

### New Files:
- None (all existing)

### Modified Files:

1. **`lighthouse/src/cli.rs`**
   - Add 4 new CLI flags
   - ~40 lines

2. **`beacon_node/src/config.rs`**
   - Add stateless-EL config parsing
   - Add network config execution_proof_subnets
   - ~80 lines

3. **`beacon_node/client/src/config.rs`**
   - Add `stateless_execution_layer` field to `ClientConfig`
   - ~3 lines

4. **`beacon_node/client/src/builder.rs`**
   - Initialize StatelessExecutionLayer
   - Create proof channels
   - Spawn proof receiver/publisher tasks
   - Wire router with channel
   - ~100 lines

5. **`beacon_node/network/src/service.rs`**
   - Pass proof channel to Router::spawn()
   - ~5 lines

6. **`beacon_node/network/src/router.rs`**
   - Update spawn() signature
   - Uncomment forwarding logic in handle_gossip()
   - ~10 lines

7. **`beacon_node/lighthouse_network/src/config.rs`**
   - Add `execution_proof_subnets` field to NetworkConfig
   - ~5 lines

8. **`beacon_chain/src/builder.rs`** (TODO: verify this file exists)
   - Add `stateless_execution_layer()` builder method
   - ~10 lines

**Total: ~250 lines across 8 files**

---

## Potential Issues and Solutions

### Issue 1: StatelessEL Not Mutable

**Problem:** `set_network_tx()` requires `&mut self`, but we have `Arc<StatelessExecutionLayer>`.

**Solution:** Make `network_tx` field use interior mutability:

```rust
// In stateless_execution_layer/src/lib.rs
pub struct StatelessExecutionLayer {
    // ... other fields
    network_tx: Arc<Mutex<Option<mpsc::UnboundedSender<...>>>>,
}

pub fn set_network_tx(&self, tx: mpsc::UnboundedSender<...>) {
    *self.network_tx.lock().unwrap() = Some(tx);
}
```

### Issue 2: BeaconChain Doesn't Have stateless_execution_layer Field

**Problem:** BeaconChain struct doesn't have the field yet.

**Solution:** Add it to BeaconChain and BeaconChainBuilder:

```rust
// In beacon_chain/src/beacon_chain.rs
pub struct BeaconChain<T: BeaconChainTypes> {
    // ... existing fields
    pub stateless_execution_layer: Option<Arc<StatelessExecutionLayer>>,
}
```

### Issue 3: Circular Dependencies

**Problem:** `stateless_execution_layer` crate might depend on `beacon_chain`, which depends on it.

**Solution:** StatelessEL should NOT depend on beacon_chain. Only depends on:
- `types` (for ExecutionProof, etc.)
- `execution_layer` (for ExecutionBlockHash, etc.)
- Standard crates (tokio, slog, etc.)

### Issue 4: Proof Publishing to Gossip

**Problem:** How does StatelessEL publish proofs to gossip network?

**Solution:** Add method to `NetworkSenders`:

```rust
// In beacon_node/network/src/service.rs
impl<E: EthSpec> NetworkSenders<E> {
    pub fn publish_execution_proof(
        &self,
        subnet_id: ExecutionProofSubnetId,
        proof: Arc<ExecutionProof>,
    ) -> Result<(), String> {
        // Convert to PubsubMessage
        let message = PubsubMessage::ExecutionProofMessage(Box::new((subnet_id, proof)));

        // Send via network_send channel
        self.network_send
            .send(NetworkMessage::Publish { message })
            .map_err(|e| format!("Failed to publish proof: {:?}", e))
    }
}
```

---

## Success Criteria

Step 3 is complete when:

- ✅ `cargo check` passes for all modified packages
- ✅ CLI flags parse correctly
- ✅ StatelessEL initializes when flag is present
- ✅ Gossip subscriptions include execution proof topics
- ✅ Proofs received via gossip reach StatelessEL
- ✅ Proof channels connect all components
- ✅ Beacon node starts successfully with stateless-EL enabled
- ✅ Logs show proof forwarding activity
- ✅ No panics or crashes during startup

---

## Next Steps After Step 3

### Phase 2.4: ENR Advertisement
- Advertise execution proof subnet participation in ENR
- Update peer discovery to find peers on specific subnets

### Phase 2.5: Peer Metadata Protocol
- Add execution proof subnets to METADATA requests
- Track which peers subscribe to which subnets

### Phase 3: Full Stateless-EL Implementation
- Replace DummyVerifier with real zkVM verifiers
- Replace DummyGenerator with real proof generation
- RPC proof fetching (ExecutionProofsByRoot)

### Phase 4: Production Readiness
- Performance optimization
- Metrics and monitoring
- Error recovery and edge cases
- Documentation

---

## Estimated Effort

- **Implementation Time:** 4-6 hours
- **Testing Time:** 2-3 hours
- **Debugging:** 2-4 hours
- **Total:** 8-13 hours (1-2 days)

**Complexity:** High
- Touches multiple critical systems
- Requires understanding beacon node initialization flow
- Async channel wiring can be tricky
- Integration with existing ExecutionLayer needs careful design

---

## Implementation Order Recommendation

1. ✅ Start with CLI flags (easiest, validates concept)
2. ✅ Add config parsing (validates flag handling)
3. ✅ Add NetworkConfig field (enables gossip)
4. ⚠️  Add BeaconChain field (may require changes to builder)
5. ✅ Initialize StatelessEL in builder
6. ⚠️  Create channels (most complex async logic)
7. ⚠️  Wire router
8. ⚠️  Spawn tasks
9. ✅ Test compilation
10. ⚠️  Manual testing with local testnet

**Legend:**
- ✅ Low risk, straightforward
- ⚠️  Medium risk, needs careful implementation
- ❌ High risk, requires significant changes

---

**Document Version:** 1.0
**Created:** 2025-10-15
**Status:** Ready for Implementation
