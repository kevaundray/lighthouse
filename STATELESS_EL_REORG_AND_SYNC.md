# Stateless Execution Layer: Reorgs and Sync Behavior

This document explains how the Stateless Execution Layer architecture handles chain reorganizations and syncing scenarios.

## Table of Contents

1. [Key Architectural Principles](#key-architectural-principles)
2. [Reorg Scenarios](#reorg-scenarios)
3. [Sync Behavior](#sync-behavior)
4. [Proof Cache Management](#proof-cache-management)
5. [Edge Cases and Mitigations](#edge-cases-and-mitigations)

---

## Key Architectural Principles

### 1. Stateless-EL is Content-Addressed

The proof cache is keyed by `ExecutionBlockHash`:

```rust
// Proof cache structure
LruCache<ExecutionBlockHash, Vec<ExecutionProof>>

// Example:
cache[hash_A] = [proof_risc_zero_A, proof_sp1_A]
cache[hash_B] = [proof_risc_zero_B]
cache[hash_C] = [proof_risc_zero_C, proof_sp1_C]
```

**Implication:** Multiple chains' proofs can coexist without conflict. A reorg doesn't require cache invalidation.

### 2. Stateless-EL is Chain-State Agnostic

The stateless-EL:
- ✅ Verifies execution payloads when asked
- ✅ Caches proofs by execution block hash
- ✅ Returns Valid/Syncing/Invalid status
- ❌ Does NOT track which block is head
- ❌ Does NOT know about fork choice
- ❌ Does NOT care about canonical vs non-canonical chains

**Implication:** Fork choice and chain selection remain entirely in the consensus layer.

### 3. SYNCING Status is the Coordination Mechanism

```rust
pub async fn new_payload(&self, payload: ExecutionPayload) -> PayloadStatus {
    if has_required_proofs(payload) {
        verify_proofs(payload)?;
        return PayloadStatus::Valid;
    }

    // Missing proofs
    request_proofs_async(payload);
    return PayloadStatus::Syncing;  // ← CL will retry later
}
```

**Implication:** The CL handles retries and timing, just like with a full EL that's syncing.

### 4. LRU Cache Handles Cleanup

```rust
pub struct StatelessExecutionLayerConfig {
    pub proof_cache_size: usize,  // e.g., 1024 blocks
}
```

**Implication:** No manual proof pruning needed. Old proofs (including orphaned blocks) are automatically evicted.

---

## Reorg Scenarios

### Scenario 1: Simple Reorg to Alternative Chain

```
Initial chain:
Block N-1 → Block N (payload A) → Block N+1 (payload B)

After reorg:
Block N-1 → Block N' (payload C) → Block N+1' (payload D)
         ↓
    (Block N, N+1 orphaned)
```

#### What Happens:

1. **Initial state:**
   - Stateless-EL cache contains: `{hash_A: [proof_A], hash_B: [proof_B]}`
   - Blocks N and N+1 are in fork choice

2. **Reorg occurs:**
   - New blocks N' and N+1' arrive with payloads C and D
   - CL calls `new_payload(payload_C)`

3. **Stateless-EL response:**
   ```rust
   // Check cache for hash_C
   let proofs = cache.get(hash_C);  // None - not in cache yet

   // Trigger proof request
   request_missing_proofs(hash_C);

   // Return SYNCING
   return PayloadStatus::Syncing;
   ```

4. **Proofs arrive via gossip:**
   - Proof for payload C arrives from the block producer
   - Stored: `cache.insert(hash_C, proof_C)`
   - DA checker callback triggered

5. **CL retries:**
   ```rust
   // CL calls new_payload again
   let status = execution_layer.new_payload(payload_C).await;
   // Now returns Valid
   ```

6. **Cache state after reorg:**
   ```
   cache = {
       hash_A: [proof_A],     // Old chain (orphaned)
       hash_B: [proof_B],     // Old chain (orphaned)
       hash_C: [proof_C],     // New chain
       hash_D: [proof_D],     // New chain
   }
   ```

#### Key Points:

- ✅ Both chains' proofs coexist in cache
- ✅ No conflicts (different execution hashes)
- ✅ Old proofs eventually evicted by LRU
- ✅ No manual cleanup needed

---

### Scenario 2: Fork Choice Switches Head

```
                    ┌→ Block N (payload A) ← was head
Block N-1 (payload X)
                    └→ Block N' (payload C) ← becomes new head (heavier)
```

#### What Happens:

1. **Both blocks import optimistically:**
   - Block N arrives → `new_payload(A)` → SYNCING (no proofs yet)
   - Block N' arrives → `new_payload(C)` → SYNCING (no proofs yet)
   - Fork choice has both as candidates

2. **Proofs for payload A arrive first:**
   - `new_payload(A)` → Valid
   - Fork choice makes Block N the head

3. **Later, proofs for payload C arrive:**
   - `new_payload(C)` → Valid
   - Fork choice re-evaluates
   - Block N' is heavier → becomes new head

4. **Stateless-EL perspective:**
   ```rust
   // No EL calls needed for head switch
   // Both payloads already verified
   cache = {
       hash_A: [proof_A],  // Verified
       hash_C: [proof_C],  // Verified
   }
   ```

#### Key Points:

- ✅ Stateless-EL doesn't care which is head
- ✅ Both payloads remain verified
- ✅ Fork choice handles head selection
- ✅ No re-verification needed

---

### Scenario 3: Deep Reorg During Sync

```
Initial sync:
Block 100 → 101 → ... → 150 (old chain)

Canonical chain discovered:
Block 100 → 101' → ... → 155 (heavier chain)
```

#### What Happens:

1. **Syncing blocks 101'-155:**
   ```rust
   for block in blocks_101_to_155 {
       let status = execution_layer.new_payload(block.payload()).await;

       match status {
           PayloadStatus::Valid => import_block(block),
           PayloadStatus::Syncing => {
               // Missing proofs, wait and retry
               sleep(500ms);
               retry();
           }
           PayloadStatus::Invalid => reject_block(block),
       }
   }
   ```

2. **Proof fetching for each block:**
   ```rust
   // In stateless-EL
   async fn new_payload(&self, payload: ExecutionPayload) -> PayloadStatus {
       if !has_proofs(payload.block_hash()) {
           // Trigger RPC request for proofs (Phase 4)
           self.fetch_proofs_via_rpc(payload.block_hash());
           return PayloadStatus::Syncing;
       }

       verify_proofs(payload)?;
       PayloadStatus::Valid
   }
   ```

3. **Cache fills with new chain:**
   ```
   cache = {
       hash_101': [proof],
       hash_102': [proof],
       ...
       hash_155': [proof],
   }

   // Old chain blocks 101-150 eventually evicted by LRU
   ```

#### Key Points:

- ✅ Same retry pattern as full EL syncing
- ✅ RPC fetching provides proofs during sync
- ✅ LRU evicts old chain proofs automatically
- ✅ No special reorg handling needed

---

## Sync Behavior

### Normal Forward Sync (Full EL Pattern)

**How full ELs work:**

```rust
// CL imports blocks during sync
loop {
    let block = get_next_block();

    match execution_layer.new_payload(payload).await {
        PayloadStatus::Valid => {
            // EL executed successfully
            import_block(block);
        }
        PayloadStatus::Syncing => {
            // EL doesn't have parent, is syncing
            // Wait and retry
            sleep(500ms);
            continue;
        }
        PayloadStatus::Invalid => {
            reject_block(block);
        }
    }
}
```

### Stateless-EL During Sync

**Identical pattern:**

```rust
// Stateless-EL's new_payload
pub async fn new_payload(&self, payload: ExecutionPayload) -> PayloadStatus {
    let block_hash = payload.block_hash();

    // Check cache
    let proofs = self.proof_cache.read().await.get(&block_hash);

    if proofs.len() >= self.config.min_proofs_required {
        // Have enough proofs, verify
        self.verify_proofs(&payload, proofs).await?;
        return PayloadStatus::Valid;
    }

    // Don't have proofs yet
    // Trigger fetching (Phase 4 - RPC)
    self.request_missing_proofs(block_hash, block_root);

    // CL will retry later
    PayloadStatus::Syncing
}
```

**For the CL:** Waiting for proofs is identical to waiting for full EL to sync parent block.

### DA Checker Role During Sync

**Important:** DA checker is only for **gossip blocks**, not historical sync.

```
┌─────────────────────────────────────────────────┐
│ Gossip Block Path (recent blocks)              │
├─────────────────────────────────────────────────┤
│ Block arrives via gossip                       │
│   ↓                                            │
│ DA checker: check_availability(block)          │
│   ↓                                            │
│ Has blobs? Has proofs? (queries stateless-EL)  │
│   ↓                                            │
│ If Available → Import                          │
│ If MissingComponents → Wait                    │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ Historical Sync Path (old blocks)              │
├─────────────────────────────────────────────────┤
│ Block arrives via RPC sync                     │
│   ↓                                            │
│ SKIP DA checker (not gossip)                   │
│   ↓                                            │
│ Directly call new_payload                      │
│   ↓                                            │
│ If Syncing → Retry later                       │
│ If Valid → Import                              │
└─────────────────────────────────────────────────┘
```

**Rationale:** DA checker tracks recent data availability windows. Historical blocks use RPC sync patterns.

---

## Proof Cache Management

### Cache Structure

```rust
pub struct ProofCache {
    cache: LruCache<ExecutionBlockHash, Vec<ExecutionProof>>,
    capacity: usize,
}

impl ProofCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(capacity),
            capacity,
        }
    }

    pub fn insert(&mut self, block_hash: ExecutionBlockHash, proof: ExecutionProof) {
        self.cache
            .entry(block_hash)
            .or_insert_with(Vec::new)
            .push(proof);
    }
}
```

### Cache Behavior During Reorgs

**Example:**

```
Cache size: 100 blocks
Current chain: blocks 1-100 (all proofs cached)

Deep reorg at block 50:
  - Old chain: blocks 50-100 (50 proofs in cache)
  - New chain: blocks 50-150 (100 new proofs arrive)
  - Total: ~150 proofs in cache temporarily
  - LRU eviction: Old chain blocks 50-100 gradually evicted
```

**Cache state over time:**

```
T0 (before reorg):
  cache = [blocks 1-100 old chain]  // 100 entries

T1 (reorg starts):
  cache = [blocks 1-49 old, 50-100 old, 50-60 new]  // 111 entries
  LRU evicts: blocks 1-11 (oldest)

T2 (reorg progresses):
  cache = [blocks 40-100 old, 50-120 new]  // 100 entries
  LRU evicts: more old chain blocks

T3 (reorg complete):
  cache = [blocks 100-150 new chain only]  // 100 entries
  All old chain blocks evicted
```

### Configuration

```rust
pub struct StatelessExecutionLayerConfig {
    /// Proof cache size (number of blocks)
    pub proof_cache_size: usize,  // Default: 1024
}
```

**Sizing considerations:**

- **Minimum:** Finalization depth (~64-128 blocks)
- **Recommended:** 1024 blocks (~3.4 hours at 12s slots)
- **Maximum:** Limited by memory (~1MB per block = 1GB for 1024 blocks)

### No Manual Cleanup Needed

```rust
// ❌ NOT needed:
fn cleanup_orphaned_proofs(&mut self, canonical_chain: Vec<Hash256>) {
    // Don't do this!
}

// ✅ Automatic:
// LRU eviction handles everything
cache.insert(new_hash, new_proof);  // Old entries auto-evicted
```

---

## Edge Cases and Mitigations

### Edge Case 1: Proofs Don't Arrive After Reorg

**Scenario:**

```
Reorg to Block N' with payload C
  ↓
CL calls new_payload(payload C)
  ↓
Stateless-EL: No proofs for C
  ↓
Returns SYNCING
  ↓
Wait for proofs...
  ↓
Proofs NEVER arrive (gossip failure, peer withholding, etc.)
```

**Mitigation (Phase 4 - RPC Fetching):**

```rust
async fn request_missing_proofs(
    &self,
    block_hash: ExecutionBlockHash,
    block_root: Hash256,
) {
    // 1. Wait for gossip grace period
    tokio::time::sleep(self.config.gossip_grace_period).await;

    // 2. Check if proofs arrived via gossip
    if self.has_required_proofs(block_hash) {
        return;  // Got them via gossip
    }

    // 3. Gossip failed, request via RPC
    warn!(
        self.log,
        "Proofs not received via gossip, requesting via RPC";
        "block_hash" => ?block_hash
    );

    let _ = self.rpc_request_tx.send(RpcRequest::ExecutionProofsByRoot {
        block_hash,
        block_root,
        subnet_ids: self.config.subscribed_subnets.clone(),
    }).await;
}
```

**If RPC also fails:**

```rust
// CL keeps retrying with exponential backoff
let mut retry_delay = Duration::from_millis(500);
for attempt in 0..MAX_RETRIES {
    match execution_layer.new_payload(payload).await {
        PayloadStatus::Syncing => {
            warn!("Payload still syncing, retry {}/{}", attempt, MAX_RETRIES);
            tokio::time::sleep(retry_delay).await;
            retry_delay *= 2;  // Exponential backoff
        }
        status => return status,
    }
}

// Eventually timeout and reject block
Err(BlockError::ExecutionPayloadTimeout)
```

**This is the same failure mode as a full EL that can't sync the parent block.**

---

### Edge Case 2: Orphaned Proof Generation

**Scenario:**

```
Node builds Block N with payload A
  ↓
Generates proof for payload A (expensive operation)
  ↓
Publishes proof to gossip
  ↓
Block N gets reorged out
  ↓
Proof for payload A now "orphaned"
```

**What happens:**

1. **Proof stays in local cache** (no harm)
2. **Proof stays in other nodes' caches** (also no harm)
3. **Proof eventually evicted by LRU** when cache fills
4. **Proof bandwidth already spent** (can't recover)

**Why this is acceptable:**

- Proofs prove execution validity, not consensus validity
- A proof for payload A is valid regardless of which block contains it
- If another block with payload A appears, the proof is reusable
- Cost: Wasted computation and bandwidth (same as orphaned blocks)

**Potential optimization (future):**

```rust
// Before generating proof, check if block is likely to be canonical
if fork_choice.head() == block.parent() &&
   block.slot() == current_slot &&
   !detected_competing_block {
    // Probably canonical, generate proof
    generate_proof(payload);
} else {
    // Might be orphaned, skip proof generation
    warn!("Skipping proof generation for potentially orphaned block");
}
```

---

### Edge Case 3: Proof Arrives for Unknown Block

**Scenario:**

```
Proof for payload X arrives via gossip
  ↓
Node has never seen block with payload X
  ↓
What to do with the proof?
```

**Current behavior:**

```rust
pub async fn on_gossip_proof_received(
    &self,
    subnet_id: ExecutionProofSubnetId,
    proof: Arc<ExecutionProof>,
) -> Result<()> {
    // Validate subnet ID
    if proof.subnet_id != subnet_id {
        return Err(SubnetMismatch);
    }

    // Check subscription
    if !self.config.subscribed_subnets.contains(&subnet_id) {
        return Err(UnsubscribedSubnet);
    }

    // Store in cache (even if block unknown)
    let block_hash = proof.block_hash;
    self.proof_cache.write().await
        .entry(block_hash)
        .or_insert_with(Vec::new)
        .push((*proof).clone());

    // ✅ Proof cached, ready when block arrives
    Ok(())
}
```

**Why this works:**

- Proof might arrive before block (gossip timing)
- When block arrives later, proofs already cached
- If block never arrives, proof evicted by LRU
- No harm in caching "orphaned" proofs

---

### Edge Case 4: Multiple Proofs for Same Payload

**Scenario:**

```
Block N with payload A
  ↓
Two proof generators produce proofs:
  - Generator 1: RISC Zero proof (subnet 0)
  - Generator 2: SP1 proof (subnet 1)
  ↓
Both proofs arrive
```

**Behavior:**

```rust
// Cache stores Vec<ExecutionProof> per block hash
cache[hash_A] = [
    ExecutionProof { subnet_id: 0, proof_data: [...] },  // RISC Zero
    ExecutionProof { subnet_id: 1, proof_data: [...] },  // SP1
]

// Verification checks M-of-N
async fn verify_proofs(&self, payload: &ExecutionPayload, proofs: &[ExecutionProof]) {
    let mut verified_subnets = HashSet::new();

    for proof in proofs {
        let verifier = self.verifiers.get_verifier(proof.subnet_id)?;
        if verifier.verify(payload, proof).await? {
            verified_subnets.insert(proof.subnet_id);
        }

        // Early exit if we have enough
        if verified_subnets.len() >= self.config.min_proofs_required {
            return Ok(());
        }
    }

    // Not enough verified subnets
    Err(InsufficientProofs)
}
```

**This is the intended behavior for M-of-N security.**

---

## Summary: Why Reorgs Work Seamlessly

1. **Content-addressed cache** (by execution block hash)
   - No conflicts between chains
   - Multiple chains' proofs coexist naturally

2. **Stateless about chain state**
   - Doesn't track head or canonical chain
   - Just verifies payloads when asked
   - Fork choice handles chain selection

3. **SYNCING status pattern**
   - Missing proofs → return SYNCING
   - CL retries later (standard pattern)
   - Works for reorgs, sync, any scenario

4. **LRU cache automatic cleanup**
   - Old proofs naturally evicted
   - No manual pruning needed
   - Configurable cache size

5. **RPC fallback resilience**
   - Gossip misses handled by RPC requests
   - Same reliability as blob sync
   - Timeouts prevent infinite waiting

6. **Same patterns as full EL**
   - CL doesn't distinguish stateless-EL from full EL
   - Reorg handling is identical
   - No new failure modes introduced

The architecture naturally handles reorgs because it follows the **principle of separation of concerns**: stateless-EL handles execution verification, consensus layer handles chain selection.

---

**Document Version:** 1.0
**Last Updated:** 2025-10-15
**Related Documents:**
- `STATELESS_EXECUTION_LAYER_DESIGN.md` - Architecture design
- `STATELESS_EL_IMPLEMENTATION_CHECKLIST.md` - Implementation plan
