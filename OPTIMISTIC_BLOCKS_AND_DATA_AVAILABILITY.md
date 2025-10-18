# Optimistic Blocks and Data Availability in Lighthouse

A comprehensive guide to how Lighthouse handles optimistic sync, data availability checking, and fork choice integration.

---

## Table of Contents

1. [Overview](#overview)
2. [Execution Payload Validation Propagation](#execution-payload-validation-propagation)
3. [When Blocks Enter Fork Choice](#when-blocks-enter-fork-choice)
4. [Optimistic Blocks in Fork Choice](#optimistic-blocks-in-fork-choice)
5. [Validator Attestation Rules](#validator-attestation-rules)
6. [Data Availability Requirements](#data-availability-requirements)
7. [Missing Components Handling](#missing-components-handling)
8. [Active vs Passive Blob Fetching](#active-vs-passive-blob-fetching)
9. [Complete Flow Diagrams](#complete-flow-diagrams)

---

## Overview

Lighthouse implements Ethereum's optimistic sync protocol, which allows the beacon node to continue processing blocks even when the execution layer (EL) hasn't verified execution payloads yet. This document explains the intricate relationship between:

- **Execution payload verification** (Verified, Optimistic, or Irrelevant)
- **Data availability** (blobs/data columns present or missing)
- **Fork choice** (which blocks can be the head)
- **Validator behavior** (when validators can/cannot attest)

### Key Invariants

1. **Blocks must be available before fork choice import** - All required blobs/columns must be present
2. **Optimistic blocks CAN be in fork choice** - But validators cannot attest to them
3. **Validators ONLY attest to verified blocks** - Never to optimistic or invalid blocks
4. **Attestations trigger active blob fetching** - Network interest drives resource allocation

---

## Execution Payload Validation Propagation

### The Function: `propagate_execution_payload_validation_by_index`

**Location**: `consensus/proto_array/src/proto_array.rs:393-411`

**Purpose**: When a block's execution payload is verified as valid, this function walks up the ancestor chain and converts any `Optimistic` ancestors to `Valid`.

**Algorithm**:
```rust
fn propagate_execution_payload_validation_by_index(
    &mut self,
    block_index: usize,
) -> Result<(), Error> {
    let mut index = block_index;
    loop {
        match self.nodes[index].execution_status {
            ExecutionStatus::Optimistic(hash) => {
                // Convert Optimistic → Valid
                self.nodes[index].execution_status = ExecutionStatus::Valid(hash);
            }
            ExecutionStatus::Valid(_) | ExecutionStatus::Irrelevant(_) => {
                // Stop - already valid or pre-merge
                break;
            }
            ExecutionStatus::Invalid(_) => {
                // ERROR - invalid ancestor found!
                return Err(Error::InvalidAncestorOfValidPayload { block_index: index });
            }
        }

        // Walk up to parent
        if let Some(parent_index) = self.nodes[index].parent {
            index = parent_index;
        } else {
            break;
        }
    }
    Ok(())
}
```

### When It's Called

**Automatically during block import** - when a block with `ExecutionStatus::Valid` is added:

**From `proto_array.rs:362-364`**:
```rust
if matches!(block.execution_status, ExecutionStatus::Valid(_)) {
    self.propagate_execution_payload_validation_by_index(parent_index)?;
}
```

### Call Chain

```
BeaconChain::import_block (beacon_chain.rs:3807)
    ↓
ForkChoice::on_block (fork_choice.rs:659)
    ↓
ProtoArrayForkChoice::process_block (proto_array_fork_choice.rs:498)
    ↓
ProtoArray::on_block (proto_array.rs:309)
    ↓
    IF block.execution_status == Valid:
        propagate_execution_payload_validation_by_index(parent_index) ✅
```

### Why This Matters

This enables **retroactive validation**: When an execution client finally verifies a payload, all ancestor blocks that were optimistically imported are automatically upgraded to valid status without requiring individual verification calls.

---

## When Blocks Enter Fork Choice

### The Two-Stage Gating Process

```
Block Received
    ↓
┌─────────────────────────────────────────────┐
│ STAGE 1: Execution Payload Verification    │
│ - Consensus validation ✅                   │
│ - State transition ✅                       │
│ - Execution payload check                  │
│   → Verified ✅                             │
│   → Optimistic ⏳                           │
│   → Irrelevant (pre-merge) ➖              │
└─────────────────────────────────────────────┘
    ↓
AvailabilityPendingExecutedBlock
    ↓
┌─────────────────────────────────────────────┐
│ STAGE 2: Data Availability Check           │
│ - Check for required blobs/columns         │
│ - Pre-Deneb: No data needed ✅             │
│ - Post-Deneb: Need all blobs ⏳            │
│ - Post-PeerDAS: Need custody columns ⏳    │
└─────────────────────────────────────────────┘
    ↓
    ├─► Availability::Available
    │   → AvailableExecutedBlock ✅
    │   → Import to fork choice
    │
    └─► Availability::MissingComponents
        → Cache in DataAvailabilityChecker ⏳
        → NOT in fork choice yet ❌
```

**Key Code References**:

**From `beacon_chain.rs:3734-3744`**:
```rust
match availability {
    Availability::Available(block) => {
        // Block is fully available, import into fork choice
        self.import_available_block(block).await
    }
    Availability::MissingComponents(block_root) => {
        // Components missing - just return status, block stays cached
        Ok(AvailabilityProcessingStatus::MissingComponents(slot, block_root))
    },
}
```

### Possible Block States

| Execution Status | Data Availability | In Fork Choice? | Can Be Head? | Validators Can Attest? |
|-----------------|-------------------|-----------------|--------------|------------------------|
| Optimistic      | Missing          | ❌ No           | ❌ No        | ❌ No                  |
| Optimistic      | Available        | ✅ Yes          | ✅ Yes       | ❌ No                  |
| Verified        | Missing          | ❌ No           | ❌ No        | ❌ No                  |
| Verified        | Available        | ✅ Yes          | ✅ Yes       | ✅ Yes                 |
| Invalid         | Any              | ❌ No*          | ❌ No        | ❌ No                  |

*Invalid blocks may be in fork choice but get zero weight and are not viable for head.

---

## Optimistic Blocks in Fork Choice

### Yes, Fork Choice Accepts Optimistic Blocks!

**From `fork_choice.rs:854-881`**:
```rust
let execution_status = if let Ok(execution_payload) = block.body().execution_payload() {
    let block_hash = execution_payload.block_hash();

    if block_hash == ExecutionBlockHash::zero() {
        ExecutionStatus::irrelevant()
    } else {
        match payload_verification_status {
            PayloadVerificationStatus::Verified =>
                ExecutionStatus::Valid(block_hash),      // ✅ Verified

            PayloadVerificationStatus::Optimistic =>
                ExecutionStatus::Optimistic(block_hash), // ⏳ Optimistic - ACCEPTED!

            PayloadVerificationStatus::Irrelevant => {
                return Err(...)  // ❌ Error
            }
        }
    }
} else {
    ExecutionStatus::irrelevant()
};
```

### Optimistic Blocks ARE Viable for Head

**From `proto_array.rs:882-885`**:
```rust
fn node_is_viable_for_head<E: EthSpec>(&self, node: &ProtoNode, current_slot: Slot) -> bool {
    if node.execution_status.is_invalid() {
        return false;  // ❌ Only INVALID blocks are excluded
    }
    // ✅ Optimistic blocks pass this check!

    // ... rest of viable checks (justified/finalized)
}
```

### Optimistic Blocks Receive Normal Treatment

1. **Normal attestation weight** - Same as verified blocks (proto_array.rs:196-208)
2. **Can receive proposer boost** - If proposed recently (proto_array.rs:226-237)
3. **Can become head** - Network can follow optimistic chain
4. **Eventually validated or invalidated** - EL responds asynchronously

### Why This Design?

**Enables optimistic sync** - A critical Ethereum feature:

```
Benefits:
✅ No sync delays - Don't wait for EL verification
✅ Liveness - Keep producing/attesting even if EL is slow
✅ Graceful degradation - If EL goes offline, consensus continues
✅ Trust but verify - Accept blocks tentatively, validate later

Safety Net:
If optimistic block later found invalid:
  → propagate_execution_payload_invalidation()
  → Mark as Invalid + descendants
  → Zero weight assigned
  → Not viable for head
  → Fork choice automatically switches to different head
```

---

## Validator Attestation Rules

### Validators CANNOT Vote on Optimistic Blocks

This is a **critical safety rule** in Ethereum's optimistic sync protocol.

**From `beacon_chain.rs:2003-2017`**:
```rust
// Only attest to a block if it is fully verified (i.e. not optimistic or invalid).
match self
    .canonical_head
    .fork_choice_read_lock()
    .get_block_execution_status(&beacon_block_root)
{
    Some(execution_status) if execution_status.is_valid_or_irrelevant() => (),
    Some(execution_status) => {
        return Err(Error::HeadBlockNotFullyVerified {
            beacon_block_root,
            execution_status,  // ❌ Includes Optimistic!
        });
    }
    None => return Err(Error::HeadMissingFromForkChoice(beacon_block_root)),
};
```

### Test Confirmation

**From `payload_invalidation.rs:1167-1266`**:
```rust
async fn attesting_to_optimistic_head() {
    // ... setup optimistic head ...

    assert!(
        rig.execution_status(root).is_strictly_optimistic(),
        "the head should be optimistic"
    );

    // Ensure attestation production fails with an optimistic head.
    assert_head_block_not_fully_verified!(produce_unaggregated());
    assert_head_block_not_fully_verified!(get_aggregated());

    // ✅ Ensure attestation production succeeds once the head is verified.
    rig.validate_manually(root);
    assert!(rig.execution_status(root).is_valid_and_post_bellatrix());

    produce_unaggregated().unwrap();  // Now it works!
}
```

### Fork Choice vs Validators - Different Rules

| Component | Can Use Optimistic Blocks? | Why? |
|-----------|---------------------------|------|
| **Fork Choice** | ✅ Yes | Needs to track all blocks to maintain liveness and compute head |
| **Validators** | ❌ No | Cannot attest to unverified execution payloads (safety critical) |

### What Happens If Head Is Optimistic?

**Scenario**: Block 1 is Valid, Block 2 is Optimistic (current head)

```
Slot 1: Block 1 (Valid) ✅
Slot 2: Block 2 (Optimistic) ⏳ ← Current Head
```

**When validator tries to attest in Slot 2**:

```rust
if request_slot >= head_state.slot() {
    // Use the head of the chain
    beacon_block_root = head.beacon_block_root;  // ← Block 2 (Optimistic)
}

// Then verification check:
match execution_status {
    Valid | Irrelevant => ✅ OK,
    Optimistic | Invalid => ❌ Error!  // FAILS HERE
}
```

**Result**:
- ❌ Validator **cannot** attest to either Block 1 or Block 2
- ⏳ Validator **waits** for Block 2 to be verified
- **No fallback** to last valid block
- Validators **sacrifice liveness for safety**

### The Safety Model

```
Block 2 arrives (Optimistic)
         ↓
Fork Choice: "Block 2 is now head" ✅
         ↓
Validator: "Can I attest to Slot 2?"
         ↓
Beacon Node: "NO - head is optimistic" ❌
         ↓
Validator: "Can I attest to Slot 3?"
         ↓
Beacon Node: "NO - head still optimistic" ❌
         ↓
[EL verifies Block 2...]
         ↓
propagate_execution_payload_validation() → Block 2 now Valid ✅
         ↓
Validator: "Can I attest to Slot 4?"
         ↓
Beacon Node: "YES!" ✅
```

**Why No Fallback?**

1. **Consensus Safety** - Validators' attestations finalize the chain
2. **Slashing Risk** - Attesting to later-invalidated blocks is dangerous
3. **Spec Requirement** - Ethereum specification explicitly forbids it
4. **Trust Model** - Must verify before voting, not vote and hope

---

## Data Availability Requirements

### Blocks Must Be Available Before Fork Choice

**From `data_availability_checker.rs:58-61`**:
```rust
/// Cache to hold fully valid data that can't be imported to fork-choice yet.
/// After Dencun hard-fork blocks have a sidecar of data that is received
/// separately from the network.
```

**From `beacon_chain.rs:3054`**:
```rust
// If this block has already been imported to forkchoice it must have been available
```

### Data Availability Status Types

**Pre-Deneb** (before EIP-4844):
- No blobs required
- Block immediately available

**Post-Deneb, Pre-PeerDAS**:
- Requires all blobs (up to 6 per block)
- Each blob is 128 KB
- Received via gossip or RPC

**Post-PeerDAS** (Data Availability Sampling):
- Requires custody columns (sampled subset)
- Each column is 256 KB
- Can reconstruct missing columns if >50% received
- More efficient for validators

### Checking Availability

**From `overflow_lru_cache.rs:216-295`**:
```rust
pub fn make_available(&self, ...) -> Result<Option<AvailableExecutedBlock<E>>, ...> {
    let Some(CachedBlock::Executed(block)) = &self.block else {
        return Ok(None);  // ❌ Block not cached yet
    };

    let num_expected_blobs = block.num_blobs_expected();

    // Pre-Deneb: no data needed
    if num_expected_blobs == 0 {
        return Some(AvailableBlockData::NoData);
    }

    // Post-Deneb: check blobs
    let num_received_blobs = self.verified_blobs.iter().flatten().count();
    match num_received_blobs.cmp(&num_expected_blobs) {
        Ordering::Equal => {
            // ✅ All blobs present!
            Some(AvailableBlockData::Blobs(blobs))
        }
        Ordering::Less => {
            // ❌ Still missing blobs
            None
        }
        // ...
    }

    // Post-PeerDAS: check columns
    let num_received_columns = self.verified_data_columns.len();
    match num_received_columns.cmp(&num_expected_columns) {
        Ordering::Equal => {
            // ✅ All custody columns present!
            Some(AvailableBlockData::DataColumns(columns))
        }
        Ordering::Less => {
            // ❌ Still missing columns
            None
        }
        // ...
    }
}
```

### The PendingComponents Cache

**From `overflow_lru_cache.rs:72-79`**:
```rust
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub verified_blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,  // Partial list
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,     // Partial list
    pub block: Option<CachedBlock<E>>,                                   // The block itself
    pub reconstruction_started: bool,                                    // For PeerDAS recovery
    span: Span,
}
```

**Cache Properties**:
- LRU eviction (capacity: 32 blocks)
- Holds fully validated blocks waiting for data
- Incrementally filled as blobs/columns arrive
- Pruned after cutoff epoch if never completed

---

## Missing Components Handling

### What Happens When Components Are Missing?

**From `beacon_chain.rs:3734-3744`**:
```rust
match availability {
    Availability::Available(block) => {
        // ✅ All components present - import to fork choice
        self.import_available_block(block).await
    }
    Availability::MissingComponents(block_root) => {
        // ❌ Components missing - just return status, block stays cached
        Ok(AvailabilityProcessingStatus::MissingComponents(slot, block_root))
    },
}
```

**From `gossip_methods.rs:1547-1552`**:
```rust
Ok(AvailabilityProcessingStatus::MissingComponents(slot, block_root)) => {
    trace!(
        %slot,
        %block_root,
        "Processed block, waiting for other components"
    );
    // That's it - just log and wait! ⏳
}
```

### The Waiting Process

```
Time T: Block arrives (needs 3 blobs)
    ↓
Cache: [Block ✅] [Blob 0: ❌] [Blob 1: ❌] [Blob 2: ❌]
    ↓
Status: MissingComponents(block_root) ⏳
    ↓
**Block NOT added to fork choice** ❌

Time T+1: Blob 0 arrives via gossip
    ↓
Cache: [Block ✅] [Blob 0: ✅] [Blob 1: ❌] [Blob 2: ❌]
    ↓
check_availability() → Still missing
    ↓
Status: MissingComponents(block_root) ⏳
    ↓
**Still NOT in fork choice** ❌

Time T+2: Blob 1 arrives via gossip
    ↓
Cache: [Block ✅] [Blob 0: ✅] [Blob 1: ✅] [Blob 2: ❌]
    ↓
check_availability() → Still missing
    ↓
Status: MissingComponents(block_root) ⏳
    ↓
**Still NOT in fork choice** ❌

Time T+3: Blob 2 arrives via gossip
    ↓
Cache: [Block ✅] [Blob 0: ✅] [Blob 1: ✅] [Blob 2: ✅]
    ↓
check_availability() → Complete! ✅
    ↓
make_available() returns Some(AvailableExecutedBlock)
    ↓
Status: Available ✅
    ↓
import_available_block() called
    ↓
**Block added to fork choice!** ✅
    ↓
Can become head (if optimistic, validators still can't attest)
```

### Each Blob Arrival Triggers Re-Check

**From `overflow_lru_cache.rs:494-532`**:
```rust
pub fn put_kzg_verified_blobs(...) -> Result<Availability<T::EthSpec>, ...> {
    // Get or create pending components for this block
    let pending_components =
        self.update_or_insert_pending_components(block_root, epoch, |pending_components| {
            pending_components.merge_blobs(fixed_blobs);  // ← Add new blobs
            Ok(())
        })?;

    // Check again: do we have everything now?
    self.check_availability_and_cache_components(block_root, pending_components, None)
    // ← Returns Availability::Available if complete!
    // ← Returns Availability::MissingComponents if still missing some
}
```

### PeerDAS Reconstruction

For PeerDAS, there's an additional recovery mechanism:

**From `gossip_methods.rs:1049-1075`**:
```rust
AvailabilityProcessingStatus::MissingComponents(slot, block_root) => {
    if self
        .chain
        .data_availability_checker
        .custody_context()
        .should_attempt_reconstruction(slot.epoch(...), &self.chain.spec)
    {
        // Schedule reconstruction task! 🔨
        // If >50% of columns received, can recover missing ones
        self.beacon_processor_send.try_send(WorkEvent {
            // ... reconstruction work event
        })
    }
}
```

**Reconstruction enables**:
- Recovery of missing columns using erasure coding
- Only needs >50% of total columns
- Reduces bandwidth and storage requirements
- More fault-tolerant than requiring all pieces

---

## Active vs Passive Blob Fetching

### Two Modes of Operation

#### 1. Passive Waiting (Primary for Gossip Blocks)

When a block arrives via gossip and returns `MissingComponents`, the system **passively waits** for blobs to arrive via gossip.

**No proactive action taken** - just caching and logging.

#### 2. Active Fetching (Triggered by Attestations)

When attestations reference a block (even one cached in DA checker), the system becomes **active**.

### The Attestation Trigger

**From `gossip_methods.rs:2411-2427`**:
```rust
AttnError::UnknownHeadBlock { beacon_block_root } => {
    trace!(
        %peer_id,
        block = ?beacon_block_root,
        "Attestation for unknown block"
    );

    // Trigger a lookup!
    self.sync_tx
        .send(SyncMessage::UnknownBlockHashFromAttestation(
            peer_id,
            *beacon_block_root,
        ))
    // ...
}
```

**From `sync/manager.rs:812-817`**:
```rust
SyncMessage::UnknownBlockHashFromAttestation(peer_id, block_root) => {
    if !self.notified_unknown_roots.contains(&(peer_id, block_root)) {
        self.notified_unknown_roots.insert((peer_id, block_root));
        debug!(?block_root, ?peer_id, "Received unknown block hash message");
        self.handle_unknown_block_root(peer_id, block_root);  // ← Triggers lookup!
    }
}
```

**Debouncing**: `notified_unknown_roots` cache (30 second expiry) prevents duplicate lookups.

### Why "Unknown" for Cached Blocks?

**Key insight**: Attestation verification **only checks fork choice**, not the DA checker cache.

**From `attestation_verification.rs:1140-1181`**:
```rust
let block_opt = chain
    .canonical_head
    .fork_choice_read_lock()
    .get_block(&attestation_data.beacon_block_root)  // ← NOT in fork choice yet!
    .or_else(|| {
        chain
            .early_attester_cache
            .get_proto_block(attestation_data.beacon_block_root)
    });

if let Some(block) = block_opt {
    Ok(block)  // Found in fork choice
} else {
    // Block NOT in fork choice → returns UnknownHeadBlock
    // (Even if cached in DA checker!)
    Err(Error::UnknownHeadBlock {
        beacon_block_root: attestation_data.beacon_block_root,
    })
}
```

Since blocks aren't added to fork choice until fully available, a block waiting for blobs returns `UnknownHeadBlock` - triggering a lookup!

### The Smart Lookup Optimization

When a lookup is created, it checks if the block is already cached:

**From `single_block_lookup.rs:216-241`**:
```rust
// Check if block is already cached in DA checker
if let Some(block) = downloaded_block.or_else(|| {
    match cx.chain.get_block_process_status(&self.block_root) {
        BlockProcessStatus::Unknown => None,
        BlockProcessStatus::NotValidated(block, _) => Some(block.clone()),
        BlockProcessStatus::ExecutionValidated(block) => Some(block.clone()),  // ✅ Found!
    }
}) {
    // Block is cached! Determine how many blobs it needs
    let expected_blobs = block.num_expected_blobs();

    if expected_blobs == 0 {
        self.component_requests = ComponentRequests::NotNeeded("no data");
    } else if cx.chain.should_fetch_blobs(block_epoch) {
        // Skip block download, go straight to blob request! 🚀
        self.component_requests = ComponentRequests::ActiveBlobRequest(
            BlobRequestState::new(self.block_root),
            expected_blobs,
        );
    }
}
```

**From `beacon_chain.rs:1315-1321`**:
```rust
pub fn get_block_process_status(&self, block_root: &Hash256) -> BlockProcessStatus<T::EthSpec> {
    if let Some(cached_block) = self.data_availability_checker.get_cached_block(block_root) {
        return cached_block;  // ✅ Found in DA checker!
    }

    BlockProcessStatus::Unknown
}
```

### Optimizations

1. **No duplicate block fetching** - Detects block is cached, skips re-download
2. **Direct blob requests** - Goes straight to requesting missing blobs
3. **Smart deduplication** - Cache prevents multiple attestations triggering duplicate lookups
4. **Works at any validation stage** - Pre-execution or post-execution

### Complete Attestation-Triggered Flow

```
Block with missing blobs cached in DA checker
         ↓
NOT in fork choice (availability required)
         ↓
Attestation arrives referencing this block
         ↓
Attestation verification checks fork choice
         ↓
Block NOT found → UnknownHeadBlock ❌
         ↓
Trigger: UnknownBlockHashFromAttestation
         ↓
SyncManager.handle_unknown_block_root()
         ↓
BlockLookups.search_unknown_block() 🔍
         ↓
SingleBlockLookup created
         ↓
Lookup calls: get_block_process_status()
         ↓
Check DA checker cache
         ↓
Found! BlockProcessStatus::ExecutionValidated(block) ✅
         ↓
Extract: expected_blobs = 3
         ↓
Skip block download! Go straight to blobs: 🚀
    ComponentRequests::ActiveBlobRequest(state, 3)
         ↓
Request missing blobs via RPC ➡️
    (BlobsByRoot request for 3 blobs)
         ↓
Blobs arrive from peer ✅
         ↓
Add blobs to DA checker cache
         ↓
DA checker: check_availability()
         ↓
All components present! ✅
         ↓
Import to fork choice! 🎉
```

---

## Complete Flow Diagrams

### Normal Block Import (All Components Available)

```
Block + Blobs arrive via gossip
    ↓
┌──────────────────────────────────┐
│ Consensus Validation             │
│ - Signature checks ✅            │
│ - State transition ✅            │
│ - Proposer index valid ✅        │
└──────────────────────────────────┘
    ↓
┌──────────────────────────────────┐
│ Execution Payload Check          │
│ - Query EL for verification      │
│ - Returns: Verified/Optimistic   │
└──────────────────────────────────┘
    ↓
AvailabilityPendingExecutedBlock
    ↓
┌──────────────────────────────────┐
│ Data Availability Check          │
│ - All blobs present? ✅          │
│ - KZG proofs valid? ✅           │
└──────────────────────────────────┘
    ↓
Availability::Available ✅
    ↓
AvailableExecutedBlock
    ↓
┌──────────────────────────────────┐
│ Import to Fork Choice            │
│ - Add to proto_array             │
│ - ExecutionStatus set            │
│ - Can become head                │
└──────────────────────────────────┘
    ↓
IF ExecutionStatus::Valid:
    propagate_execution_payload_validation_by_index()
    (Validate optimistic ancestors)
    ↓
Block fully imported! 🎉
```

### Block Import with Missing Components

```
Block arrives via gossip (blobs not yet received)
    ↓
Consensus Validation ✅
    ↓
Execution Payload Check
    → Optimistic or Verified
    ↓
AvailabilityPendingExecutedBlock
    ↓
Data Availability Check
    → Missing blobs! ❌
    ↓
Availability::MissingComponents(block_root)
    ↓
┌──────────────────────────────────┐
│ Cache in DataAvailabilityChecker │
│ - Store validated block          │
│ - Store any blobs received       │
│ - Wait for remaining blobs       │
│ - NOT in fork choice yet ❌      │
└──────────────────────────────────┘
    ↓
Return: MissingComponents status
    ↓
Log: "Processed block, waiting for other components"
    ↓
┌──────────────────────────────────┐
│ PASSIVE WAITING MODE ⏳          │
│ Wait for blobs via gossip        │
└──────────────────────────────────┘
    ↓
    ├─► Blob 1 arrives → check_availability() → Still missing
    ├─► Blob 2 arrives → check_availability() → Still missing
    └─► Blob 3 arrives → check_availability() → Complete! ✅
            ↓
    Availability::Available
            ↓
    Import to fork choice! 🎉
```

### Attestation-Triggered Blob Fetching

```
Block cached with missing blobs (NOT in fork choice)
    ↓
Network continues, validators process next slots
    ↓
Attestation arrives from peer referencing this block
    ↓
Attestation Verification:
    Check if beacon_block_root is in fork choice
    ↓
    NOT found! (block not in fork choice yet)
    ↓
    Error: UnknownHeadBlock
    ↓
Trigger: UnknownBlockHashFromAttestation(peer, block_root)
    ↓
SyncManager receives message
    ↓
Check debounce cache (prevent spam)
    Not recently processed ✅
    ↓
Insert to debounce cache (30s expiry)
    ↓
handle_unknown_block_root()
    ↓
BlockLookups.search_unknown_block()
    ↓
┌──────────────────────────────────┐
│ Create SingleBlockLookup         │
│ - target: block_root             │
│ - peer: attestation sender       │
└──────────────────────────────────┘
    ↓
Lookup initialization:
    Call get_block_process_status(block_root)
    ↓
    Check DA checker cache
    ↓
    Found! BlockProcessStatus::ExecutionValidated(block) ✅
    ↓
┌──────────────────────────────────┐
│ OPTIMIZATION: Block Already Has! │
│ Skip block download              │
│ Extract: expected_blobs = 3      │
└──────────────────────────────────┘
    ↓
Transition to: ActiveBlobRequest
    ↓
┌──────────────────────────────────┐
│ REQUEST MISSING BLOBS VIA RPC    │
│ BlobsByRoot(block_root, [0,1,2]) │
│ Send to peer ➡️                  │
└──────────────────────────────────┘
    ↓
Peer responds with blobs
    ↓
Verify KZG proofs ✅
    ↓
Add to DA checker cache
    ↓
check_availability()
    ↓
All components now present! ✅
    ↓
Availability::Available
    ↓
Import to fork choice! 🎉
    ↓
Block can now be head
(If Verified: validators can attest)
(If Optimistic: validators wait)
```

### Validator Attestation Decision

```
Validator duty: Attest to current head
    ↓
produce_unaggregated_attestation()
    ↓
Get canonical head from fork choice
    ↓
head = fork_choice.get_head()
    ↓
beacon_block_root = head.beacon_block_root
    ↓
┌──────────────────────────────────┐
│ CRITICAL CHECK                   │
│ Verify execution status          │
└──────────────────────────────────┘
    ↓
get_block_execution_status(beacon_block_root)
    ↓
    ├─► Valid or Irrelevant
    │   → ✅ Proceed with attestation
    │   → Create attestation data
    │   → Sign and broadcast
    │   → Validators perform duty
    │
    └─► Optimistic or Invalid
        → ❌ Error: HeadBlockNotFullyVerified
        → Cannot attest!
        → Validator skips this duty
        → Wait for verification
        → Miss attestation for this slot
```

### Optimistic to Valid Transition

```
Block imported as Optimistic
    ↓
Added to fork choice with ExecutionStatus::Optimistic
    ↓
Can be head, but validators cannot attest ⏳
    ↓
┌──────────────────────────────────┐
│ Background: EL Verification      │
│ Execution client processes       │
│ - Executes transactions          │
│ - Validates state root           │
│ - Checks against EL rules        │
└──────────────────────────────────┘
    ↓
    Time passes (could be seconds or minutes)
    ↓
EL responds: "Payload is valid!" ✅
    ↓
BeaconChain receives verification result
    ↓
┌──────────────────────────────────┐
│ New Block Created                │
│ (or verification notification)   │
│ ExecutionStatus: Valid           │
└──────────────────────────────────┘
    ↓
Import this new info to fork choice
    ↓
on_block() with ExecutionStatus::Valid
    ↓
propagate_execution_payload_validation_by_index()
    ↓
┌──────────────────────────────────┐
│ Walk up ancestor chain           │
│ For each ancestor:               │
│   - If Optimistic → Valid ✅     │
│   - If Valid → Stop (done)       │
│   - If Invalid → Error! ❌       │
└──────────────────────────────────┘
    ↓
All ancestors now Valid! ✅
    ↓
Validators can now attest to this chain! 🎉
```

---

## Key Takeaways

1. **Two-stage gating**: Blocks must pass both execution verification (can be optimistic) AND data availability (must be complete) before entering fork choice

2. **Optimistic blocks in fork choice**: Allowed and can be head, but validators cannot attest to them

3. **Attestations drive blob fetching**: Network interest (via attestations) triggers active fetching of missing components

4. **Smart caching**: DA checker holds validated blocks waiting for blobs, lookup mechanism detects cached blocks and skips re-downloading

5. **Safety over liveness**: Validators sacrifice attestation duties rather than vote on unverified blocks

6. **Retroactive validation**: When a payload is verified, all optimistic ancestors are automatically upgraded

7. **PeerDAS reconstruction**: Can recover missing columns if >50% received, reducing bandwidth requirements

8. **Debouncing prevents spam**: 30-second cache prevents duplicate lookups from multiple attestations

---

## Code References

### Key Files

- **Proto Array**: `consensus/proto_array/src/proto_array.rs`
- **Fork Choice**: `consensus/fork_choice/src/fork_choice.rs`
- **Beacon Chain**: `beacon_node/beacon_chain/src/beacon_chain.rs`
- **Data Availability**: `beacon_node/beacon_chain/src/data_availability_checker.rs`
- **Attestation Verification**: `beacon_node/beacon_chain/src/attestation_verification.rs`
- **Sync Manager**: `beacon_node/network/src/sync/manager.rs`
- **Block Lookups**: `beacon_node/network/src/sync/block_lookups/`

### Critical Functions

- `propagate_execution_payload_validation_by_index()` - proto_array.rs:393
- `on_block()` - proto_array.rs:309, fork_choice.rs:659
- `import_block()` - beacon_chain.rs:3807
- `check_availability_and_cache_components()` - overflow_lru_cache.rs:578
- `get_block_process_status()` - beacon_chain.rs:1315
- `produce_unaggregated_attestation()` - beacon_chain.rs:1872
- `handle_unknown_block_root()` - sync/manager.rs:902

---

## Testing

Unit tests were added for `propagate_execution_payload_validation_by_index` in proto_array.rs covering:

- Propagating validation through optimistic chain
- Stopping at already-valid blocks
- Stopping at irrelevant (pre-merge) blocks
- Erroring on invalid ancestors
- Preserving execution payload hashes
- Testing both private and public API

Run tests with:
```bash
cargo test -p proto_array --lib propagate_validation
```

---

*Document created: 2025-10-18*
*Lighthouse version: Based on analysis of current codebase*
