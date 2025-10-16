# Phase 2 - Step 3 Implementation Progress

**Date:** 2025-10-16
**Status:** IN PROGRESS - CLI flags added, config parsing next
**Estimated Remaining:** 6-10 hours

---

## Summary

Step 3 involves wiring the gossip infrastructure (Steps 1-2) with the StatelessExecutionLayer in the beacon node. This requires changes across 8+ files and ~250 lines of code.

**Current Status:** 1 of 10 substeps complete (10%)

---

## Completed Work ✅

### Step 3.1: CLI Flags Added
**File:** `beacon_node/src/cli.rs` (Lines 935-980)

Added 4 new flags:

```rust
--stateless-execution-layer
    Enable stateless execution layer for proof-based payload verification

--verify-execution-proof-subnets <SUBNETS>
    Comma-separated list of subnet IDs to subscribe to (0-7)
    Example: --verify-execution-proof-subnets 0,1,2

--generate-execution-proof-subnets <SUBNETS>
    Comma-separated list of subnet IDs to generate proofs for (0-7)
    Example: --generate-execution-proof-subnets 3,4

--stateless-el-min-proofs <COUNT>
    Minimum number of valid proofs required (default: 1)
```

**Usage Example:**
```bash
lighthouse bn --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1 \
  --stateless-el-min-proofs 1
```

---

## Remaining Work (Steps 3.2-3.10)

### Step 3.2: Parse Configuration ⏸️
**File:** `beacon_node/src/config.rs`
**Estimated Time:** 30-45 minutes

**What to do:**
1. Add parsing logic after execution layer config (around line 325)
2. Parse `--verify-execution-proof-subnets` into `ExecutionProofSubnetId` set
3. Parse `--generate-execution-proof-subnets` (optional)
4. Parse `--stateless-el-min-proofs`
5. Build `StatelessExecutionLayerConfig` from builder
6. Set `client_config.stateless_execution_layer = Some(config)`

**Code template:**
```rust
/*
 * Stateless Execution Layer
 */
if cli_args.get_flag("stateless-execution-layer") {
    use stateless_execution_layer::StatelessExecutionLayerConfigBuilder;
    use types::ExecutionProofSubnetId;

    let mut config_builder = StatelessExecutionLayerConfigBuilder::default();

    // Parse subscription subnets (required)
    let verify_subnets: Vec<&str> = cli_args
        .get_many::<String>("verify-execution-proof-subnets")
        .map(|vals| vals.map(|s| s.as_str()).collect())
        .unwrap_or_default();

    if verify_subnets.is_empty() {
        return Err(
            "--stateless-execution-layer requires --verify-execution-proof-subnets".to_string()
        );
    }

    for subnet_str in verify_subnets {
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

    // Parse min proofs
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

### Step 3.3: Add stateless_execution_layer to ClientConfig ⏸️
**File:** `beacon_node/client/src/config.rs`
**Estimated Time:** 5 minutes

**What to do:**
```rust
pub struct ClientConfig {
    // ... existing fields

    /// Stateless execution layer configuration (if enabled)
    pub stateless_execution_layer: Option<StatelessExecutionLayerConfig>,
}
```

And in `Default` impl:
```rust
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            // ... existing fields
            stateless_execution_layer: None,
        }
    }
}
```

---

### Step 3.4: Add execution_proof_subnets to NetworkConfig ⏸️
**File:** `beacon_node/lighthouse_network/src/config.rs`
**Estimated Time:** 10 minutes

**What to do:**
```rust
pub struct NetworkConfig {
    // ... existing fields

    /// Execution proof subnets to subscribe to
    pub execution_proof_subnets: HashSet<ExecutionProofSubnetId>,
}
```

In `Default` impl:
```rust
execution_proof_subnets: HashSet::new(),
```

In `beacon_node/src/config.rs` (set_network_config):
```rust
// Configure execution proof subnet subscriptions
if let Some(ref stateless_el_config) = client_config.stateless_execution_layer {
    config.execution_proof_subnets = stateless_el_config.subscribed_subnets.clone();

    info!(
        "Configured execution proof gossip subscriptions";
        "subnets" => ?config.execution_proof_subnets,
    );
}
```

---

### Step 3.5: Add stateless_execution_layer to BeaconChain ⏸️
**File:** `beacon_node/beacon_chain/src/beacon_chain.rs`
**Estimated Time:** 15 minutes

**Challenge:** This requires finding BeaconChain struct and BeaconChainBuilder.

**What to do:**
1. Add field to `BeaconChain<T>`:
```rust
pub stateless_execution_layer: Option<Arc<StatelessExecutionLayer>>,
```

2. Add builder method to `BeaconChainBuilder<T>`:
```rust
pub fn stateless_execution_layer(
    mut self,
    stateless_el: Option<Arc<StatelessExecutionLayer>>,
) -> Self {
    self.stateless_execution_layer = stateless_el;
    self
}
```

3. Initialize field in `build()` method.

---

### Step 3.6: Initialize StatelessExecutionLayer in Builder ⏸️
**File:** `beacon_node/client/src/builder.rs`
**Estimated Time:** 20 minutes

**What to do:**
In `beacon_chain_builder()` method, after ExecutionLayer init:

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

// Add to builder chain
let builder = builder
    // ... existing methods
    .stateless_execution_layer(stateless_execution_layer)
    // ... rest
```

---

### Step 3.7: Create Proof Channels ⏸️
**File:** `beacon_node/client/src/builder.rs` (in `network()` method)
**Estimated Time:** 20 minutes

**What to do:**
```rust
// Create proof channels if stateless-EL is configured
let proof_channels = if beacon_chain.stateless_execution_layer.is_some() {
    use tokio::sync::mpsc;
    use types::{ExecutionProof, ExecutionProofSubnetId};

    // Gossip → StatelessEL
    let (gossip_to_sel_tx, gossip_to_sel_rx) = mpsc::unbounded_channel::<(
        ExecutionProofSubnetId,
        Arc<ExecutionProof>,
    )>();

    // StatelessEL → Gossip
    let (sel_to_gossip_tx, sel_to_gossip_rx) = mpsc::unbounded_channel::<(
        ExecutionProofSubnetId,
        Arc<ExecutionProof>,
    )>();

    Some((gossip_to_sel_tx, gossip_to_sel_rx, sel_to_gossip_tx, sel_to_gossip_rx))
} else {
    None
};
```

---

### Step 3.8: Wire Router with Proof Channel ⏸️
**Files:**
- `beacon_node/network/src/router.rs` (update spawn signature)
- `beacon_node/network/src/service.rs` (pass channel to Router::spawn)

**Estimated Time:** 15 minutes

**What to do:**

1. Update `Router::spawn()` signature:
```rust
pub fn spawn(
    // ... existing params
    stateless_el_proof_tx: Option<mpsc::UnboundedSender<(ExecutionProofSubnetId, Arc<ExecutionProof>)>>,
) -> Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>, String>
```

2. Update Router init:
```rust
let mut handler = Router {
    // ... existing fields
    stateless_el_proof_tx, // Use the provided channel
};
```

3. Update call site in `service.rs`:
```rust
let router_send = Router::spawn(
    // ... existing args
    stateless_el_proof_tx, // Pass from proof_channels
)?;
```

4. Uncomment forwarding logic in `handle_gossip()` (already done in Step 2).

---

### Step 3.9: Spawn Proof Receiver/Publisher Tasks ⏸️
**File:** `beacon_node/client/src/builder.rs` (in `network()` method)
**Estimated Time:** 30 minutes

**What to do:**
```rust
// Spawn tasks if proof channels exist
if let Some((gossip_to_sel_tx, mut gossip_to_sel_rx, sel_to_gossip_tx, mut sel_to_gossip_rx)) = proof_channels {
    if let Some(stateless_el) = beacon_chain.stateless_execution_layer.as_ref() {
        // Configure stateless-EL with network TX
        stateless_el.set_network_tx(sel_to_gossip_tx);

        // Task: Gossip → StatelessEL
        let sel_clone = stateless_el.clone();
        let log = context.log().clone();
        context.executor.spawn(
            async move {
                while let Some((subnet_id, proof)) = gossip_to_sel_rx.recv().await {
                    debug!(log, "Forwarding proof to stateless-EL"; "subnet_id" => subnet_id.as_u8());
                    if let Err(e) = sel_clone.on_gossip_proof_received(subnet_id, proof).await {
                        warn!(log, "Stateless-EL rejected proof"; "error" => ?e);
                    }
                }
            },
            "stateless_el_proof_receiver",
        );

        // Task: StatelessEL → Gossip
        let network_send = self.network_senders.as_ref().unwrap().clone();
        let log = context.log().clone();
        context.executor.spawn(
            async move {
                while let Some((subnet_id, proof)) = sel_to_gossip_rx.recv().await {
                    debug!(log, "Publishing proof to gossip"; "subnet_id" => subnet_id.as_u8());
                    // TODO: Actually publish via network_send
                }
            },
            "stateless_el_proof_publisher",
        );
    }
}
```

---

### Step 3.10: Verify Compilation ⏸️
**Estimated Time:** 1-2 hours (including fixing issues)

**What to do:**
```bash
# Check each package
cargo check -p stateless_execution_layer
cargo check -p client
cargo check -p network
cargo check -p beacon_node

# Check full build
cargo check
```

---

## Potential Issues & Solutions

### Issue 1: StatelessEL.set_network_tx() requires &mut
**Solution:** Use interior mutability (Mutex/RwLock) for network_tx field

### Issue 2: BeaconChain field addition breaks existing code
**Solution:** Update all BeaconChain initialization sites

### Issue 3: Circular dependencies
**Solution:** Ensure stateless_execution_layer doesn't depend on beacon_chain

---

## Testing After Completion

### Manual Test:
```bash
lighthouse bn \
  --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1 \
  --execution-endpoint http://localhost:8551

# Check logs for:
# - "Stateless execution layer enabled"
# - "Configured execution proof gossip subscriptions"
# - No startup errors
```

### Verification:
```bash
# Check CLI help
lighthouse bn --help | grep -A5 "stateless-execution-layer"

# Check config parsing
lighthouse bn --stateless-execution-layer \
  --verify-execution-proof-subnets 0,1 \
  --execution-endpoint http://localhost:8551 \
  2>&1 | grep "Stateless"
```

---

## Time Estimates

| Step | Task | Time | Status |
|------|------|------|--------|
| 3.1 | CLI flags | 15 min | ✅ DONE |
| 3.2 | Config parsing | 45 min | ⏸️ TODO |
| 3.3 | ClientConfig field | 5 min | ⏸️ TODO |
| 3.4 | NetworkConfig field | 10 min | ⏸️ TODO |
| 3.5 | BeaconChain field | 15 min | ⏸️ TODO |
| 3.6 | Initialize StatelessEL | 20 min | ⏸️ TODO |
| 3.7 | Create channels | 20 min | ⏸️ TODO |
| 3.8 | Wire Router | 15 min | ⏸️ TODO |
| 3.9 | Spawn tasks | 30 min | ⏸️ TODO |
| 3.10 | Verify compilation | 2 hours | ⏸️ TODO |

**Total Remaining:** ~6-8 hours

---

## Next Steps

**Option A: Continue Implementation**
- Proceed with Step 3.2 (config parsing)
- Work through Steps 3.3-3.10
- Test and debug

**Option B: Pause for Review**
- Review completed work (Steps 1-2 + CLI flags)
- Plan testing strategy
- Resume Step 3 in next session

**Recommendation:** Given complexity, proceed incrementally:
1. Complete Steps 3.2-3.4 (config)
2. Test compilation
3. Complete Steps 3.5-3.9 (wiring)
4. Full integration test

---

## Files Modified So Far

1. `beacon_node/src/cli.rs` - Added 4 CLI flags (✅ Complete)
2. `beacon_node/lighthouse_network/src/types/pubsub.rs` - ExecutionProofMessage (✅ Step 1)
3. `beacon_node/network/src/router.rs` - Router integration (✅ Step 2)

**Total:** 3 files, ~150 lines added

---

## Document Version

**Version:** 1.0
**Created:** 2025-10-16
**Last Updated:** 2025-10-16
**Status:** Step 3.1 complete, Steps 3.2-3.10 pending
