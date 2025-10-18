# Phase 3.3 Callback Wiring - Implementation Plan

**Status:** Deferred - Requires architectural decision
**Date:** 2025-10-17
**Complexity:** Medium-High

---

## Summary

Phase 3.3 aims to implement proactive re-verification of blocks when execution proofs arrive via gossip. Currently, blocks without proofs are marked as optimistic and eventually verified when fork choice runs. The callback would reduce latency by triggering immediate re-verification.

## Current State

### What's Implemented ✅

1. **Callback Infrastructure (Phase 2.7)**
   - `StatelessExecutionLayer` has `proof_ready_callback` field
   - `register_proof_ready_callback()` method implemented
   - Callback triggered in `on_gossip_proof_received()` when threshold reached

2. **ExecutionLayer Passthrough (Phase 3.3 Partial)**
   - `ExecutionLayer::register_proof_ready_callback()` implemented
   - Routes callback to underlying stateless backend
   - Location: `beacon_node/execution_layer/src/lib.rs:631-640`

3. **BeaconChain Fields**
   - `execution_layer: Option<ExecutionLayer<T::EthSpec>>`
   - `stateless_execution_layer: Option<Arc<StatelessExecutionLayer>>`
   - Location: `beacon_node/beacon_chain/src/beacon_chain.rs`

### What's Missing ❌

1. **Stateless-EL initialization in BeaconChain**
   - Currently set to `None` in builder
   - TODO comment at `beacon_node/beacon_chain/src/builder.rs:983`
   - Need to pass stateless-EL reference from client builder

2. **Callback Registration Logic**
   - Need to wire callback after beacon chain is built
   - Callback should call beacon chain method to handle proof-ready event

3. **BeaconChain Handler Method**
   - Method to re-verify blocks when proofs arrive
   - Needs to interact with fork choice safely

---

## Architecture Analysis

### Key Finding: Natural Re-verification

After researching the codebase, I discovered that **explicit callback-based re-verification may not be necessary**:

1. **Fork Choice Already Handles This:**
   - Optimistic blocks are periodically re-verified
   - `get_head()` and fork choice updates check execution status
   - ExecutionLayer calls are idempotent

2. **Safety is Guaranteed:**
   - Blocks without proofs return `PayloadStatus::Syncing`
   - Marked as optimistic (not fully trusted)
   - Cannot be finalized until fully verified
   - Fork choice naturally re-verifies when proofs become available

3. **Callback is UX Optimization:**
   - Reduces latency from seconds to milliseconds
   - Not a security requirement
   - Adds complexity to fork choice interaction

### Recommendation

**Option A: Minimal Logging Implementation** (Recommended)
- Implement callback that logs when proofs arrive
- Provides observability without risking fork choice
- Easy to upgrade later if proactive re-verification is desired

**Option B: Full Re-verification** (Complex)
- Callback triggers immediate payload re-verification
- Requires careful fork choice locking
- Risk of deadlocks (see CLAUDE.md warnings)
- Needs extensive testing

**Option C: Defer Indefinitely** (Current)
- Rely on natural fork choice re-verification
- Simplest and safest approach
- Acceptable latency for initial implementation

---

## Implementation Plan: Option A (Minimal Logging)

This approach provides the wiring without complex re-verification logic.

### Step 1: Pass Stateless-EL to BeaconChain

**File:** `beacon_node/client/src/builder.rs`

**Changes:**

```rust
// Around line 180, after creating stateless execution layer:
let execution_layer = if let Some(stateless_config) = config.stateless_execution_layer.clone() {
    // ... existing code ...

    let stateless_el = Arc::new(stateless_el); // Store Arc for later use

    let execution_layer = ExecutionLayer::from_stateless(
        stateless_el.clone(), // Clone Arc
        None,
        context.executor.clone(),
    )?;

    Some((execution_layer, Some(stateless_el))) // Return both
} else if let Some(config) = config.execution_layer.clone() {
    // ... existing code ...
    Some((execution_layer, None)) // No stateless-EL
} else {
    None
};

// Extract tuple
let (execution_layer, stateless_el) = execution_layer.unzip();

// Later when building BeaconChainBuilder (around line 228):
let builder = BeaconChainBuilder::new(eth_spec_instance, Arc::new(kzg))
    .store(store)
    // ... other methods ...
    .execution_layer(execution_layer)
    .stateless_execution_layer(stateless_el) // NEW METHOD NEEDED
```

### Step 2: Add BeaconChainBuilder Method

**File:** `beacon_node/beacon_chain/src/builder.rs`

**Add method:**

```rust
impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    // ... existing methods ...

    /// Sets the stateless execution layer.
    pub fn stateless_execution_layer(
        mut self,
        stateless_el: Option<Arc<stateless_execution_layer::StatelessExecutionLayer>>,
    ) -> Self {
        self.stateless_execution_layer = stateless_el;
        self
    }
}
```

**Update BeaconChainBuilder struct to store it:**

```rust
pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    // ... existing fields ...
    execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    stateless_execution_layer: Option<Arc<stateless_execution_layer::StatelessExecutionLayer>>,
    // ... other fields ...
}
```

**Pass it to BeaconChain in build() method:**

```rust
// Around line 983, replace:
stateless_execution_layer: None, // TODO: Initialize in task 6

// With:
stateless_execution_layer: self.stateless_execution_layer.clone(),
```

### Step 3: Add Logging Handler to BeaconChain

**File:** `beacon_node/beacon_chain/src/beacon_chain.rs`

**Add method:**

```rust
impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Called when execution proofs become available for a payload.
    /// Currently just logs the event.
    ///
    /// Future enhancement: Could trigger re-verification of optimistic blocks.
    pub fn on_execution_proofs_ready(&self, payload_hash: ExecutionBlockHash) {
        info!(
            payload_hash = ?payload_hash,
            "Execution proofs became available"
        );

        // TODO (Phase 3.3 enhancement): Re-verify optimistic blocks
        // This would involve:
        // 1. Query fork choice for blocks with this payload_hash in optimistic state
        // 2. Re-call notify_new_payload() with the same payload
        // 3. Update fork choice with new verification status
        //
        // For now, fork choice will naturally re-verify on next update.
    }
}
```

### Step 4: Register Callback in Client Builder

**File:** `beacon_node/client/src/builder.rs`

**In `build_beacon_chain()` method, after beacon chain is built:**

```rust
// After line 680: self.beacon_chain = Some(Arc::new(chain));

// Register proof-ready callback if using stateless-EL
if let Some(execution_layer) = self.beacon_chain
    .as_ref()
    .and_then(|chain| chain.execution_layer.as_ref())
{
    if execution_layer.is_stateless() {
        let chain = self.beacon_chain.clone().unwrap();
        let callback = Arc::new(move |payload_hash: ExecutionBlockHash| {
            chain.on_execution_proofs_ready(payload_hash);
        });

        // Spawn async task to register callback
        let el = execution_layer.clone();
        context.executor.spawn(
            async move {
                el.register_proof_ready_callback(callback).await;
            },
            "register_proof_callback",
        );
    }
}
```

### Step 5: Testing

**Unit Test:**

```rust
#[tokio::test]
async fn test_proof_ready_callback_logging() {
    // Create beacon chain harness with stateless-EL
    // Trigger proof arrival
    // Verify log message appears
}
```

---

## Implementation Plan: Option B (Full Re-verification)

If proactive re-verification is desired:

### Additional Steps Beyond Option A

#### Step 6: Implement Re-verification Logic

**File:** `beacon_node/beacon_chain/src/beacon_chain.rs`

```rust
impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn on_execution_proofs_ready(&self, payload_hash: ExecutionBlockHash) {
        info!(payload_hash = ?payload_hash, "Execution proofs available, re-verifying");

        // Get execution layer
        let execution_layer = match &self.execution_layer {
            Some(el) => el,
            None => {
                warn!("No execution layer available");
                return;
            }
        };

        // TODO: Query fork choice for optimistic blocks with this payload
        // This requires fork choice API additions

        // For now, just trigger a fork choice update which will
        // naturally re-verify optimistic blocks
        let chain = self.clone();
        self.task_executor.spawn(
            async move {
                if let Err(e) = chain.recompute_head_at_current_slot().await {
                    warn!(
                        error = ?e,
                        payload_hash = ?payload_hash,
                        "Failed to recompute head after proofs arrived"
                    );
                }
            },
            "proof_ready_recompute_head",
        );
    }
}
```

#### Step 7: Fork Choice Integration (Complex)

Would need to:
1. Add method to query optimistic blocks by payload hash
2. Re-call `notify_new_payload()` for those blocks
3. Update fork choice with new status
4. Handle locking carefully (see `canonical_head.rs:9` warnings)

**Estimated effort:** 8-16 hours
**Risk:** Medium-High (fork choice deadlocks)

---

## Decision Matrix

| Aspect | Option A (Logging) | Option B (Re-verify) | Option C (Defer) |
|--------|-------------------|---------------------|------------------|
| **Complexity** | Low | High | None |
| **Risk** | Low | Medium-High | None |
| **Latency** | Seconds* | Milliseconds | Seconds* |
| **Effort** | 2-4 hours | 8-16 hours | 0 hours |
| **Safety** | Guaranteed | Guaranteed | Guaranteed |
| **Observability** | Good (logs) | Good | Poor |
| **Future-proof** | Easy to upgrade | Complete | Would need later work |

*Latency until block transitions from optimistic to verified. Fork choice runs periodically.

---

## Recommendation

**Implement Option A (Minimal Logging)** for the following reasons:

1. **Low Risk:** No fork choice interaction, can't cause deadlocks
2. **Observable:** Logs show when proofs arrive
3. **Future-proof:** Easy to add re-verification later if needed
4. **Functional:** Core safety guarantees work without callback
5. **Quick:** Can be implemented in 2-4 hours

**Defer Option B** until:
- Real zkVM proofs are integrated (Phase 5)
- Production deployment shows latency is problematic
- Fork choice API for querying optimistic blocks is designed
- Comprehensive testing infrastructure is ready

---

## Files to Modify

### Option A (Minimal)

1. `beacon_node/client/src/builder.rs`
   - Extract stateless-EL Arc when creating execution layer
   - Pass to BeaconChainBuilder
   - Register callback after beacon chain built

2. `beacon_node/beacon_chain/src/builder.rs`
   - Add `stateless_execution_layer()` method
   - Add field to BeaconChainBuilder struct
   - Pass to BeaconChain in build()
   - Remove TODO comment at line 983

3. `beacon_node/beacon_chain/src/beacon_chain.rs`
   - Add `on_execution_proofs_ready()` method
   - Log when proofs arrive
   - Add TODO for future enhancement

### Option B (Full)

All of Option A, plus:

4. `consensus/fork_choice/src/fork_choice.rs`
   - Add method to query optimistic blocks by payload hash

5. `beacon_node/beacon_chain/src/beacon_chain.rs`
   - Implement full re-verification logic
   - Handle fork choice locking
   - Error handling and retry logic

6. `beacon_node/beacon_chain/src/test_utils.rs`
   - Add BeaconChainHarness support for stateless-EL
   - Integration test helpers

---

## Testing Strategy

### Option A

**Unit Tests:**
- Callback registration succeeds
- Callback triggers on proof arrival
- Log message appears with correct payload hash

**Integration Tests (Deferred):**
- Local testnet with stateless nodes
- Verify logs appear when proofs propagate

### Option B

All of Option A, plus:

**Integration Tests:**
- Block imports as optimistic without proofs
- Proofs arrive via gossip
- Callback triggers
- Block re-verified within milliseconds
- Block transitions to fully verified
- Fork choice selects verified block as head

**Performance Tests:**
- Measure latency reduction vs natural re-verification
- Verify no fork choice deadlocks under load
- Concurrent proof arrivals don't cause issues

---

## Next Steps

1. **Decision:** Choose Option A, B, or C
2. **Review:** Get team feedback on approach
3. **Implement:** Follow chosen option's plan
4. **Test:** Unit tests for chosen approach
5. **Document:** Update PHASE_3_REVIEW.md with completion status

---

## References

- Phase 3.3 requirements: `STATELESS_EL_IMPLEMENTATION_CHECKLIST.md:234-253`
- Fork choice locking warnings: `beacon_node/beacon_chain/src/canonical_head.rs:9`
- DA checker pattern (for reference): `beacon_node/beacon_chain/src/data_availability_checker/`
- CLAUDE.md development guidelines: Search for "fork choice", "locks", "deadlock"

---

**Document Version:** 1.0
**Last Updated:** 2025-10-17
**Author:** Claude Code (Anthropic)
**Status:** Implementation plan ready for review
