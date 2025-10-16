# Network Integration Status for Execution Proofs

## What Has Been Completed ✅

### 1. Basic Type Additions
- ✅ Added `ExecutionProofSubnetId` import to `topics.rs`
- ✅ Added `EXECUTION_PROOF_PREFIX` constant
- ✅ Added `execution_proof_subnets` field to `TopicConfig`
- ✅ Added `GossipKind::ExecutionProof(ExecutionProofSubnetId)` variant
- ✅ Added `Subnet::ExecutionProof(ExecutionProofSubnetId)` variant

## What's Missing ❌

Based on the list you provided and comparing with how other subnet types (attestation, sync committee, data columns) work:

### 1. Display Implementation for GossipKind ❌

**Location:** `topics.rs:189-205` (impl Display for GossipKind)

**Current code:**
```rust
impl std::fmt::Display for GossipKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipKind::Attestation(subnet_id) => write!(f, "beacon_attestation_{}", **subnet_id),
            GossipKind::SyncCommitteeMessage(subnet_id) => {
                write!(f, "sync_committee_{}", **subnet_id)
            }
            GossipKind::BlobSidecar(blob_index) => {
                write!(f, "{}{}", BLOB_SIDECAR_PREFIX, blob_index)
            }
            GossipKind::DataColumnSidecar(column_subnet_id) => {
                write!(f, "{}{}", DATA_COLUMN_SIDECAR_PREFIX, **column_subnet_id)
            }
            x => f.write_str(x.as_ref()),  // ← ExecutionProof falls through here
        }
    }
}
```

**Needs to add:**
```rust
GossipKind::ExecutionProof(subnet_id) => {
    write!(f, "{}{}", EXECUTION_PROOF_PREFIX, **subnet_id)
}
```

**Before the `x => ...` catch-all.**

---

###2. core_topics_to_subscribe() - Subscription Logic ❌

**Location:** `topics.rs:42-100`

**Currently missing:** No execution proof subscription logic

**Needs to add:**
```rust
// After the Fulu data column subscription logic (around line 97)

// Subscribe to execution proof subnets if configured
for subnet in &opts.execution_proof_subnets {
    topics.push(GossipKind::ExecutionProof(*subnet));
}
```

**Note:** Unlike blobs/columns which are fork-gated, execution proofs should probably always be subscribed if configured (not fork-specific). But consider if this should be gated behind a fork check.

---

### 3. is_fork_non_core_topic() - Non-Core Topic Handling ❌

**Location:** `topics.rs:107-125`

**Current code:**
```rust
pub fn is_fork_non_core_topic(topic: &GossipTopic, _fork_name: ForkName) -> bool {
    match topic.kind() {
        // Node may be aggregator of attestation and sync_committee_message topics
        GossipKind::Attestation(_) | GossipKind::SyncCommitteeMessage(_) => true,
        // All these topics are core-only
        GossipKind::BeaconBlock
        | GossipKind::BeaconAggregateAndProof
        | GossipKind::BlobSidecar(_)
        | GossipKind::DataColumnSidecar(_)
        | GossipKind::VoluntaryExit
        | GossipKind::ProposerSlashing
        | GossipKind::AttesterSlashing
        | GossipKind::SignedContributionAndProof
        | GossipKind::BlsToExecutionChange
        | GossipKind::LightClientFinalityUpdate
        | GossipKind::LightClientOptimisticUpdate => false,
    }
}
```

**Missing:** `ExecutionProof` case - causes non-exhaustive match warning

**Needs to add:**
```rust
GossipKind::ExecutionProof(_) => false,  // Core-only topic
```

**Or:** Could make it non-core if nodes might dynamically subscribe/unsubscribe. But probably should be core-only.

---

### 4. subnet_topic_index() - Topic Parsing ❌

**Location:** `topics.rs:185-202`

**Current code:**
```rust
fn subnet_topic_index(topic: &str) -> Option<GossipKind> {
    if let Some(index) = topic.strip_prefix(BEACON_ATTESTATION_PREFIX) {
        return Some(GossipKind::Attestation(SubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    } else if let Some(index) = topic.strip_prefix(SYNC_COMMITTEE_PREFIX_TOPIC) {
        return Some(GossipKind::SyncCommitteeMessage(SyncSubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    } else if let Some(index) = topic.strip_prefix(BLOB_SIDECAR_PREFIX) {
        return Some(GossipKind::BlobSidecar(index.parse::<u64>().ok()?));
    } else if let Some(index) = topic.strip_prefix(DATA_COLUMN_SIDECAR_PREFIX) {
        return Some(GossipKind::DataColumnSidecar(DataColumnSubnetId::new(
            index.parse::<u64>().ok()?,
        )));
    }
    None
}
```

**Needs to add:**
```rust
} else if let Some(index) = topic.strip_prefix(EXECUTION_PROOF_PREFIX) {
    return Some(GossipKind::ExecutionProof(ExecutionProofSubnetId::new(
        index.parse::<u8>().ok()?,  // Note: u8, not u64!
    ).ok()?));  // ExecutionProofSubnetId::new() returns Result
```

**Note:** ExecutionProofSubnetId uses `u8` (0-7), not `u64` like other subnets.

---

### 5. GossipTopic::decode() - Topic Decoding ❌

**Location:** topics.rs:239-283

**Current code is fine** - `decode()` delegates to `subnet_topic_index()`, so fixing #4 above will fix this automatically.

**No additional changes needed here.**

---

### 6. GossipTopic::subnet_id() - Subnet Extraction ❌

**Location:** `topics.rs:106-113`

**Current code:**
```rust
pub fn subnet_id(&self) -> Option<Subnet> {
    match self.kind() {
        GossipKind::Attestation(subnet_id) => Some(Subnet::Attestation(*subnet_id)),
        GossipKind::SyncCommitteeMessage(subnet_id) => Some(Subnet::SyncCommittee(*subnet_id)),
        GossipKind::DataColumnSidecar(subnet_id) => Some(Subnet::DataColumn(*subnet_id)),
        _ => None,
    }
}
```

**Needs to add:**
```rust
GossipKind::ExecutionProof(subnet_id) => Some(Subnet::ExecutionProof(*subnet_id)),
```

---

### 7. From<Subnet> for GossipKind - Conversion ❌

**Location:** `topics.rs:167-175`

**Current code:**
```rust
impl From<Subnet> for GossipKind {
    fn from(subnet_id: Subnet) -> Self {
        match subnet_id {
            Subnet::Attestation(s) => GossipKind::Attestation(s),
            Subnet::SyncCommittee(s) => GossipKind::SyncCommitteeMessage(s),
            Subnet::DataColumn(s) => GossipKind::DataColumnSidecar(s),
        }
    }
}
```

**Needs to add:**
```rust
Subnet::ExecutionProof(s) => GossipKind::ExecutionProof(s),
```

**This will cause a compiler error until added (non-exhaustive match).**

---

### 8. GossipTopic Display - Topic String Formatting ❌

**Location:** `topics.rs:309-330` (impl Display for GossipTopic)

**Current code:**
```rust
let kind = match self.kind {
    GossipKind::BeaconBlock => BEACON_BLOCK_TOPIC.into(),
    GossipKind::BeaconAggregateAndProof => BEACON_AGGREGATE_AND_PROOF_TOPIC.into(),
    GossipKind::VoluntaryExit => VOLUNTARY_EXIT_TOPIC.into(),
    GossipKind::ProposerSlashing => PROPOSER_SLASHING_TOPIC.into(),
    GossipKind::AttesterSlashing => ATTESTER_SLASHING_TOPIC.into(),
    GossipKind::Attestation(index) => format!("{}{}", BEACON_ATTESTATION_PREFIX, *index,),
    GossipKind::SignedContributionAndProof => SIGNED_CONTRIBUTION_AND_PROOF_TOPIC.into(),
    GossipKind::SyncCommitteeMessage(index) => {
        format!("{}{}", SYNC_COMMITTEE_PREFIX_TOPIC, *index)
    }
    GossipKind::BlobSidecar(blob_index) => {
        format!("{}{}", BLOB_SIDECAR_PREFIX, blob_index)
    }
    GossipKind::DataColumnSidecar(column_subnet_id) => {
        format!("{}{}", DATA_COLUMN_SIDECAR_PREFIX, *column_subnet_id)
    }
    GossipKind::BlsToExecutionChange => BLS_TO_EXECUTION_CHANGE_TOPIC.into(),
    GossipKind::LightClientFinalityUpdate => LIGHT_CLIENT_FINALITY_UPDATE.into(),
    GossipKind::LightClientOptimisticUpdate => LIGHT_CLIENT_OPTIMISTIC_UPDATE.into(),
};
```

**Needs to add:**
```rust
GossipKind::ExecutionProof(subnet_id) => {
    format!("{}{}", EXECUTION_PROOF_PREFIX, *subnet_id)
}
```

**After DataColumnSidecar, before BlsToExecutionChange.**

---

### 9. Test Updates ❌

**Location:** `topics.rs:135-425` (tests module)

Several test functions need updates:

#### A. `get_topic_config()` needs execution_proof_subnets field ❌

**Location:** `topics.rs:348-355`

**Current:**
```rust
fn get_topic_config(sampling_subnets: &HashSet<DataColumnSubnetId>) -> TopicConfig {
    TopicConfig {
        enable_light_client_server: false,
        subscribe_all_subnets: false,
        subscribe_all_data_column_subnets: false,
        sampling_subnets: sampling_subnets.clone(),
    }
}
```

**Needs:**
```rust
fn get_topic_config(sampling_subnets: &HashSet<DataColumnSubnetId>) -> TopicConfig {
    TopicConfig {
        enable_light_client_server: false,
        subscribe_all_subnets: false,
        subscribe_all_data_column_subnets: false,
        sampling_subnets: sampling_subnets.clone(),
        execution_proof_subnets: HashSet::new(),  // NEW
    }
}
```

#### B. `topics()` test helper should include ExecutionProof ❌

**Location:** `topics.rs:216-236`

**Current:**
```rust
fn topics() -> Vec<String> {
    let mut topics = Vec::new();
    let fork_digest: [u8; 4] = [1, 2, 3, 4];
    for encoding in [GossipEncoding::SSZSnappy].iter() {
        for kind in [
            BeaconBlock,
            BeaconAggregateAndProof,
            SignedContributionAndProof,
            Attestation(SubnetId::new(42)),
            SyncCommitteeMessage(SyncSubnetId::new(42)),
            VoluntaryExit,
            ProposerSlashing,
            AttesterSlashing,
        ]
        .iter()
        {
            topics.push(GossipTopic::new(kind.clone(), encoding.clone(), fork_digest).into());
        }
    }
    topics
}
```

**Needs to add:**
```rust
ExecutionProof(ExecutionProofSubnetId::new(0).unwrap()),
```

**To the list of test kinds.**

#### C. `test_as_str_ref()` should test ExecutionProof ❌

**Location:** `topics.rs:312-331`

**Needs to add:**
```rust
assert_eq!(
    "execution_proof",
    ExecutionProof(ExecutionProofSubnetId::new(0).unwrap()).as_ref()
);
```

#### D. `all_topics_at_fork()` needs execution_proof_subnets ❌

**Location:** `topics.rs:127-137`

**Current:**
```rust
pub fn all_topics_at_fork<E: EthSpec>(fork: ForkName, spec: &ChainSpec) -> Vec<GossipKind> {
    let sampling_subnets = HashSet::from_iter(spec.all_data_column_sidecar_subnets());
    let opts = TopicConfig {
        enable_light_client_server: true,
        subscribe_all_subnets: true,
        subscribe_all_data_column_subnets: true,
        sampling_subnets,
    };
    core_topics_to_subscribe::<E>(fork, &opts, spec)
}
```

**Needs:**
```rust
pub fn all_topics_at_fork<E: EthSpec>(fork: ForkName, spec: &ChainSpec) -> Vec<GossipKind> {
    let sampling_subnets = HashSet::from_iter(spec.all_data_column_sidecar_subnets());
    let opts = TopicConfig {
        enable_light_client_server: true,
        subscribe_all_subnets: true,
        subscribe_all_data_column_subnets: true,
        sampling_subnets,
        execution_proof_subnets: HashSet::new(),  // NEW - or all subnets if testing
    };
    core_topics_to_subscribe::<E>(fork, &opts, spec)
}
```

---

## Summary of Missing Pieces

| # | Item | Location | Impact |
|---|------|----------|--------|
| 1 | Display for GossipKind | topics.rs:189-205 | ExecutionProof won't format correctly |
| 2 | core_topics_to_subscribe() | topics.rs:42-100 | Won't subscribe to exec proof topics |
| 3 | is_fork_non_core_topic() | topics.rs:107-125 | Non-exhaustive match warning |
| 4 | subnet_topic_index() | topics.rs:185-202 | Can't parse exec proof topics |
| 5 | GossipTopic::decode() | topics.rs:239-283 | Auto-fixed by #4 |
| 6 | GossipTopic::subnet_id() | topics.rs:106-113 | Can't extract subnet from topic |
| 7 | From<Subnet> for GossipKind | topics.rs:167-175 | Compiler error (non-exhaustive) |
| 8 | GossipTopic Display | topics.rs:309-330 | Topics won't serialize correctly |
| 9 | Test updates | topics.rs:135-425 | Tests will fail |

---

## Comparison with Design Doc

The design doc (`STATELESS_EXECUTION_LAYER_DESIGN.md`) expected these changes, and they're mostly correct. The missing pieces above align with what I outlined in the design.

### One Consideration: Fork Gating

**Question:** Should execution proof topics be gated behind a fork?

**Current approach in code:**
- Blobs: Only in Deneb (fork-gated)
- Data columns: Only in Fulu (fork-gated)
- Execution proofs: **Not fork-gated** (would subscribe in all forks if configured)

**My recommendation:** Probably should be fork-gated to a future fork (e.g., Gloas or later), unless this is intended to work on current forks via a config flag only.

If fork-gating is needed:
```rust
// In core_topics_to_subscribe()
if fork_name.gloas_enabled() {  // Or whatever fork
    for subnet in &opts.execution_proof_subnets {
        topics.push(GossipKind::ExecutionProof(*subnet));
    }
}
```

---

## Next Steps

Tell the other AI to complete the 8 missing pieces above. They're all straightforward pattern-matching additions following the existing code for DataColumnSidecar or Attestation.

**Priority order:**
1. #7 (From<Subnet>) - Causes compiler error
2. #3 (is_fork_non_core_topic) - Causes compiler warning
3. #1 (Display for GossipKind) - Core functionality
4. #4 (subnet_topic_index) - Core functionality
5. #6 (subnet_id extraction) - Core functionality
6. #8 (GossipTopic Display) - Core functionality
7. #2 (core_topics_to_subscribe) - Core functionality
8. #9 (Tests) - Polish

All of these are small, localized changes following existing patterns.
