//! Synchronous fork-choice replay, not a deterministic BeaconChain runtime.
//!
//! Fixture preparation uses real production block/state processing and signed, verified votes.
//! It runs outside the replay boundary. Replay owns fresh production stores and controls only
//! message delivery and fork-choice time. Blocks are fixed artifacts, not adaptive proposals.
//! Base/Mainnet avoids execution-layer mocks. This short corpus cannot demonstrate finality progress.

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType, HARNESS_GENESIS_TIME};
use beacon_chain::{BeaconForkChoiceStore, BeaconSnapshot};
use fork_choice::{
    AttestationFromBlock, Error, ForkChoice, ForkChoiceStore, InvalidBlock,
    PayloadVerificationStatus,
};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;
use state_processing::VerifySignatures;
use state_processing::common::attesting_indices_base;
use state_processing::per_block_processing::is_valid_indexed_attestation;
use state_processing::state_advance::complete_state_advance;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use store::{HotColdDB, MemoryStore};
use types::{
    Attestation, BeaconState, ChainSpec, Checkpoint, EthSpec, ForkName, Hash256,
    IndexedAttestation, MainnetEthSpec, SignedBeaconBlock, Slot,
};

type E = MainnetEthSpec;
type Database = HotColdDB<E, MemoryStore, MemoryStore>;
type Choice = ForkChoice<BeaconForkChoiceStore<E, MemoryStore, MemoryStore>, E>;
type Result<T, Error = String> = std::result::Result<T, Error>;
const VALIDATORS: usize = 64;
const MAX_EVENTS: usize = 128;

fn checked<T, D: Debug>(value: std::result::Result<T, D>) -> Result<T> {
    value.map_err(|error| format!("{error:?}"))
}

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

struct Block {
    signed: Arc<SignedBeaconBlock<E>>,
    state: BeaconState<E>,
    root: Hash256,
}

impl Block {
    fn new(signed: Arc<SignedBeaconBlock<E>>, state: BeaconState<E>) -> Self {
        let root = signed.canonical_root();
        Self {
            signed,
            state,
            root,
        }
    }
}

/// Immutable input corpus shared between independent replay executions.
pub struct Corpus {
    spec: Arc<ChainSpec>,
    anchor: BeaconSnapshot<E>,
    // A1 -> A3 competes with B2, which skips A1. No proposer signs twice in one slot.
    blocks: [Block; 3],
    votes: Vec<IndexedAttestation<E>>,
    preferred: usize,
    vote_weight: u64,
}

impl Corpus {
    pub async fn build(seed: u64) -> Result<Self> {
        // Capture fixture-helper panics as contextual failures. Tokio/Rayon used here are explicitly
        // outside the deterministic replay boundary, and are never used by `replay`.
        checked(tokio::spawn(Self::generate()).await)
            .and_then(|result| result)
            .map_err(|error| format!("seed={seed} fixture preparation: {error}"))
    }

    async fn generate() -> Result<Self> {
        let spec = Arc::new(ForkName::Base.make_genesis_spec(E::default_spec()));
        let harness: BeaconChainHarness<EphemeralHarnessType<E>> =
            BeaconChainHarness::builder(MainnetEthSpec)
                .spec(spec.clone())
                .deterministic_keypairs(VALIDATORS)
                .fresh_ephemeral_store()
                .build();
        let anchor = harness.chain.head_snapshot();
        require(
            anchor.beacon_state.genesis_time() == HARNESS_GENESIS_TIME,
            "fixture genesis must be fixed",
        )?;
        let ((a1, _), a1_state) = harness
            .make_block(anchor.beacon_state.clone(), Slot::new(1))
            .await;
        let ((b2, _), b2_state) = harness
            .make_block(anchor.beacon_state.clone(), Slot::new(2))
            .await;
        let ((a3, _), a3_state) = harness.make_block(a1_state.clone(), Slot::new(3)).await;
        let blocks = [
            Block::new(a1, a1_state),
            Block::new(b2, b2_state),
            Block::new(a3, a3_state),
        ];
        // A nonzero honest vote must overturn the lexicographic root tie-break. Choose the losing
        // branch, rather than assuming any particular graffiti/hash happens to order first.
        let preferred = if blocks[0].root < blocks[1].root {
            2
        } else {
            1
        };
        let block = &blocks[preferred];
        let mut state = block.state.clone();
        checked(complete_state_advance(
            &mut state,
            None,
            Slot::new(4),
            None,
            &spec,
        ))?;
        checked(state.build_caches(&spec))?;
        let state_root = checked(state.update_tree_hash_cache())?;
        let validators = (0..VALIDATORS).collect::<Vec<_>>();
        let attestations = harness.make_unaggregated_attestations(
            &validators,
            &state,
            state_root,
            block.root.into(),
            Slot::new(4),
        );
        let mut votes = Vec::new();
        let mut vote_weight = 0u64;
        for (attestation, _) in attestations.into_iter().flatten() {
            let Attestation::Base(attestation) = attestation else {
                return Err("expected a Base attestation".into());
            };
            let committee =
                checked(state.get_beacon_committee(attestation.data.slot, attestation.data.index))?;
            let indexed = checked(attesting_indices_base::get_indexed_attestation(
                committee.committee,
                &attestation,
            ))?;
            checked(is_valid_indexed_attestation(
                &state,
                indexed.to_ref(),
                VerifySignatures::True,
                &spec,
            ))?;
            for index in indexed.to_ref().attesting_indices_iter() {
                let validator = anchor
                    .beacon_state
                    .validators()
                    .get(*index as usize)
                    .ok_or_else(|| format!("missing fixture validator {index}"))?;
                vote_weight = vote_weight
                    .checked_add(validator.effective_balance)
                    .ok_or_else(|| "fixture weight overflow".to_string())?;
            }
            votes.push(indexed);
        }
        require(
            vote_weight > 0,
            "fixture requires a nonempty slot-4 committee",
        )?;
        Ok(Self {
            spec,
            anchor: (*anchor).clone(),
            blocks,
            votes,
            preferred,
            vote_weight,
        })
    }

    fn node(&self) -> Result<Node> {
        let db = Arc::new(checked(Database::open_ephemeral(
            Default::default(),
            self.spec.clone(),
        ))?);
        // Like genesis initialization, establish the anchor before writing hot states.
        // Replays do not reopen the database, so only the live anchor metadata is needed.
        let _ = checked(db.init_anchor_info(
            self.anchor.beacon_block.parent_root(),
            self.anchor.beacon_block.slot(),
            self.anchor.beacon_state.slot(),
            false,
        ))?;
        checked(db.put_block(
            &self.anchor.beacon_block_root,
            (*self.anchor.beacon_block).clone(),
        ))?;
        checked(db.put_state(&self.anchor.beacon_state_root(), &self.anchor.beacon_state))?;
        let store = checked(BeaconForkChoiceStore::get_forkchoice_store(
            db.clone(),
            self.anchor.clone(),
        ))?;
        let choice = checked(ForkChoice::from_anchor(
            store,
            self.anchor.beacon_block_root,
            &self.anchor.beacon_block,
            &self.anchor.beacon_state,
            Some(Slot::new(0)),
            &self.spec,
        ))?;
        let finalized = choice.finalized_checkpoint();
        Ok(Node {
            choice,
            db,
            finalized,
        })
    }

    fn time(&self, slot: u64) -> u64 {
        slot.saturating_mul(self.spec.get_slot_duration().as_millis() as u64)
    }

    fn slot(&self, time: u64) -> Slot {
        Slot::new(time / self.spec.get_slot_duration().as_millis() as u64)
    }

    fn preferred_root(&self) -> Hash256 {
        self.blocks[self.preferred].root
    }

    fn unvoted_root(&self) -> Hash256 {
        self.blocks[if self.preferred == 2 { 1 } else { 2 }].root
    }

    fn header(&self, seed: u64, scenario: &str) -> String {
        let votes = self
            .votes
            .iter()
            .map(|vote| {
                (
                    vote.to_ref().data().clone(),
                    vote.to_ref().attesting_indices_to_vec(),
                )
            })
            .collect::<Vec<_>>();
        format!(
            "seed={seed} scenario={scenario} rng=ChaCha8Rng fork=Base preset=Mainnet validators={VALIDATORS} genesis={} slot_ms={} due_ms={} boost={:?} anchor={:?} A1={:?} B2={:?} A3={:?} preferred={:?} vote_weight={} votes={votes:?}",
            self.anchor.beacon_state.genesis_time(),
            self.time(1),
            self.spec.get_attestation_due::<E>(Slot::new(1)).as_millis(),
            self.spec.proposer_score_boost,
            self.anchor.beacon_block_root,
            self.blocks[0].root,
            self.blocks[1].root,
            self.blocks[2].root,
            self.preferred_root(),
            self.vote_weight,
        )
    }
}

struct Node {
    choice: Choice,
    db: Arc<Database>,
    finalized: Checkpoint,
}

impl Node {
    fn block(
        &mut self,
        corpus: &Corpus,
        time: u64,
        index: usize,
        expected: Expected,
    ) -> Result<()> {
        let block = &corpus.blocks[index];
        let delay =
            Duration::from_millis(time.saturating_sub(corpus.time(block.signed.slot().as_u64())));
        let result = self.choice.on_block(
            corpus.slot(time),
            block.signed.message(),
            block.root,
            delay,
            &block.state,
            PayloadVerificationStatus::Irrelevant,
            &corpus.spec,
        );
        match (expected, result) {
            (Expected::Accepted, Ok(())) => {
                checked(self.db.put_block(&block.root, (*block.signed).clone()))?;
                checked(self.db.put_state(&block.signed.state_root(), &block.state))?;
                Ok(())
            }
            (
                Expected::UnknownParent,
                Err(Error::InvalidBlock(InvalidBlock::UnknownParent(root))),
            ) if root == block.signed.parent_root() => Ok(()),
            (
                Expected::Future,
                Err(Error::InvalidBlock(InvalidBlock::FutureSlot {
                    current_slot,
                    block_slot,
                })),
            ) if current_slot == corpus.slot(time) && block_slot == block.signed.slot() => Ok(()),
            (_, result) => Err(format!(
                "block={index} expected={expected:?}, got={result:?}"
            )),
        }
    }

    fn vote(&mut self, corpus: &Corpus, time: u64, index: usize) -> Result<()> {
        checked(self.choice.on_attestation(
            corpus.slot(time),
            corpus.votes[index].to_ref(),
            AttestationFromBlock::False,
            &corpus.spec,
        ))
    }

    fn observe(&mut self, corpus: &Corpus, time: u64) -> Result<String> {
        let head = checked(self.choice.get_head(corpus.slot(time), &corpus.spec))?;
        let finalized = self.choice.finalized_checkpoint();
        require(
            finalized.epoch >= self.finalized.epoch,
            "finalized epoch regressed",
        )?;
        require(
            self.choice
                .is_descendant(self.finalized.root, finalized.root),
            "conflicting finalization",
        )?;
        require(
            self.choice
                .is_finalized_checkpoint_or_descendant(head.root()),
            "head violates finalized ancestry",
        )?;
        require(
            finalized
                == Checkpoint {
                    epoch: 0u64.into(),
                    root: corpus.anchor.beacon_block_root,
                },
            format!("short no-inclusion corpus unexpectedly changed finality: {finalized:?}"),
        )?;
        self.finalized = finalized;
        let queued: usize = self
            .choice
            .queued_attestations()
            .values()
            .map(Vec::len)
            .sum();
        let weights = corpus
            .blocks
            .iter()
            .map(|block| self.choice.get_block_weight(&block.root))
            .collect::<Vec<_>>();
        Ok(format!(
            "head={head:?} justified={:?} finalized={finalized:?} boost={:?} queued={queued} weights={weights:?}",
            self.choice.justified_checkpoint(),
            self.choice.fc_store().proposer_boost_root()
        ))
    }

    fn expect_head(&mut self, corpus: &Corpus, time: u64, root: Hash256) -> Result<()> {
        let actual = checked(self.choice.get_head(corpus.slot(time), &corpus.spec))?.root();
        require(
            actual == root,
            format!("head expected={root:?} actual={actual:?}"),
        )
    }

    fn expect_weight(&self, corpus: &Corpus, expected: u64) -> Result<()> {
        let actual = self.choice.get_block_weight(&corpus.preferred_root());
        require(
            actual == Some(expected),
            format!("vote weight expected={expected} actual={actual:?}"),
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Accepted,
    UnknownParent,
    Future,
}

#[derive(Clone, Debug)]
enum Message {
    Block(usize, Expected),
    Vote(usize),
}

#[derive(Clone, Debug)]
enum Action {
    Partition(bool),
    // Connectivity is checked at arrival, not send time. Partitions drop, never buffer.
    Deliver {
        from: usize,
        to: usize,
        sent: u64,
        message: Message,
        dropped: bool,
    },
    Diverged,
    Unvoted,
    Converged,
}

#[derive(Debug)]
struct Event {
    time: u64,
    sequence: usize,
    action: Action,
}

fn push(events: &mut Vec<Event>, time: u64, action: Action) {
    events.push(Event {
        time,
        sequence: events.len(),
        action,
    });
}

fn delivery(
    events: &mut Vec<Event>,
    time: u64,
    from: usize,
    to: usize,
    sent: u64,
    message: Message,
    dropped: bool,
) {
    push(
        events,
        time,
        Action::Deliver {
            from,
            to,
            sent,
            message,
            dropped,
        },
    );
}

/// Finite partition, an in-flight drop, a reordered child, and explicit parent-first recovery.
/// Plausible bugs: leaking partitioned traffic, accepting unknown parents, duplicate vote inflation,
/// or failing to apply delayed votes. Exact heads and weights make each observable.
pub fn replay(corpus: &Corpus, seed: u64) -> Result<Vec<String>> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut events = Vec::new();
    let block = |i| Message::Block(i, Expected::Accepted);
    delivery(
        &mut events,
        corpus.time(1),
        0,
        0,
        corpus.time(1),
        block(0),
        false,
    );
    push(
        &mut events,
        corpus.time(1).saturating_add(1),
        Action::Partition(true),
    );
    delivery(
        &mut events,
        corpus.time(2),
        1,
        1,
        corpus.time(2),
        block(1),
        false,
    );
    // Sent before the partition; delivery-time connectivity must still drop it.
    delivery(
        &mut events,
        corpus.time(2).saturating_add(rng.random_range(1..100)),
        0,
        1,
        corpus.time(1),
        block(0),
        true,
    );
    delivery(
        &mut events,
        corpus.time(3),
        0,
        0,
        corpus.time(3),
        block(2),
        false,
    );
    delivery(
        &mut events,
        corpus.time(3).saturating_add(1),
        1,
        0,
        corpus.time(2),
        block(1),
        true,
    );
    push(
        &mut events,
        corpus.time(3).saturating_add(100),
        Action::Diverged,
    );
    push(&mut events, corpus.time(4), Action::Partition(false));
    delivery(
        &mut events,
        corpus.time(4).saturating_add(1),
        0,
        1,
        corpus.time(3),
        Message::Block(2, Expected::UnknownParent),
        false,
    );
    // Recovery is simulator policy: ForkChoice itself has no sync/retry network.
    delivery(
        &mut events,
        corpus.time(4).saturating_add(10),
        0,
        1,
        corpus.time(4),
        block(0),
        false,
    );
    delivery(
        &mut events,
        corpus.time(4).saturating_add(20),
        0,
        1,
        corpus.time(4),
        block(2),
        false,
    );
    delivery(
        &mut events,
        corpus.time(4).saturating_add(10),
        1,
        0,
        corpus.time(4),
        block(1),
        false,
    );
    push(
        &mut events,
        corpus.time(4).saturating_add(30),
        Action::Unvoted,
    );
    let vote_origin = if corpus.preferred == 2 { 0 } else { 1 };
    for node in 0..2 {
        let mut order = (0..corpus.votes.len()).collect::<Vec<_>>();
        order.shuffle(&mut rng);
        for index in order {
            let arrival = corpus.time(4).saturating_add(rng.random_range(100..500));
            delivery(
                &mut events,
                arrival,
                vote_origin,
                node,
                corpus.time(4),
                Message::Vote(index),
                false,
            );
            delivery(
                &mut events,
                corpus.time(5).saturating_add(rng.random_range(1..100)),
                vote_origin,
                node,
                corpus.time(4),
                Message::Vote(index),
                false,
            );
        }
        delivery(
            &mut events,
            corpus.time(5).saturating_add(101),
            0,
            node,
            corpus.time(4),
            block(2),
            false,
        );
    }
    push(&mut events, corpus.time(5), Action::Converged);
    push(&mut events, corpus.time(6), Action::Converged);
    events.sort_by_key(|event| (event.time, event.sequence));
    require(
        events.len() <= MAX_EVENTS,
        format!("seed={seed} event budget exceeded"),
    )?;
    let mut nodes = [corpus.node(), corpus.node()]
        .into_iter()
        .collect::<Result<Vec<_>>>()
        .map_err(|error| format!("seed={seed} initialization: {error}"))?;
    let mut partitioned = false;
    let mut trace = vec![corpus.header(seed, "partition-recovery")];
    for event in events {
        let context = format!(
            "seed={seed} t={} event={} {:?}",
            event.time, event.sequence, event.action
        );
        let result = (|| -> Result<()> {
            match &event.action {
                Action::Partition(value) => partitioned = *value,
                Action::Deliver {
                    from,
                    to,
                    sent,
                    message,
                    dropped,
                } => {
                    require(*sent <= event.time, "delivery precedes send")?;
                    let actual_drop = partitioned && from != to;
                    require(actual_drop == *dropped, "unexpected connectivity outcome")?;
                    if !actual_drop {
                        match message {
                            Message::Block(index, expected) => {
                                nodes[*to].block(corpus, event.time, *index, *expected)?
                            }
                            Message::Vote(index) => nodes[*to].vote(corpus, event.time, *index)?,
                        }
                    }
                }
                Action::Diverged => {
                    nodes[0].expect_head(corpus, event.time, corpus.blocks[2].root)?;
                    nodes[1].expect_head(corpus, event.time, corpus.blocks[1].root)?;
                }
                Action::Unvoted => {
                    for node in &mut nodes {
                        node.expect_head(corpus, event.time, corpus.unvoted_root())?;
                        node.expect_weight(corpus, 0)?;
                    }
                }
                Action::Converged => {
                    for node in &mut nodes {
                        node.expect_head(corpus, event.time, corpus.preferred_root())?;
                        node.expect_weight(corpus, corpus.vote_weight)?;
                        require(
                            node.choice.queued_attestations().is_empty(),
                            "recovery left queued votes",
                        )?;
                        require(
                            node.choice.fc_store().proposer_boost_root() == Hash256::ZERO,
                            "recovery retained boost",
                        )?;
                    }
                }
            }
            for (index, node) in nodes.iter_mut().enumerate() {
                trace.push(format!(
                    "{context} node={index} {}",
                    node.observe(corpus, event.time)?
                ));
            }
            Ok(())
        })();
        result.map_err(|error| format!("{context}: {error}\ntrace:\n{}", trace.join("\n")))?;
    }
    Ok(trace)
}

/// Same-slot votes must remain queued; duplicates must not create weight, even across queue drain.
pub fn vote_boundaries(corpus: &Corpus, seed: u64) -> Result<Vec<String>> {
    let mut trace = vec![corpus.header(seed, "vote-boundaries")];
    (|| -> Result<()> {
        let mut node = corpus.node()?;
        let time = corpus.time(4);
        for index in [0, 1, 2] {
            node.block(corpus, time, index, Expected::Accepted)?;
        }
        node.expect_head(corpus, time, corpus.unvoted_root())?;
        for index in 0..corpus.votes.len() {
            node.vote(corpus, time, index)?;
            node.vote(corpus, time, index)?;
        }
        trace.push(format!(
            "t={time} same-slot {}",
            node.observe(corpus, time)?
        ));
        node.expect_head(corpus, time, corpus.unvoted_root())?;
        node.expect_weight(corpus, 0)?;
        let time = corpus.time(5);
        trace.push(format!("t={time} drain {}", node.observe(corpus, time)?));
        node.expect_head(corpus, time, corpus.preferred_root())?;
        node.expect_weight(corpus, corpus.vote_weight)?;
        require(
            node.choice.queued_attestations().is_empty(),
            "slot tick did not drain votes",
        )?;
        for index in (0..corpus.votes.len()).rev() {
            node.vote(corpus, time, index)?;
        }
        trace.push(format!(
            "t={time} redelivery {}",
            node.observe(corpus, time)?
        ));
        node.expect_head(corpus, time, corpus.preferred_root())?;
        node.expect_weight(corpus, corpus.vote_weight)?;
        Ok(())
    })()
    .map_err(|error| format!("seed={seed} vote-boundaries: {error}\n{}", trace.join("\n")))?;
    Ok(trace)
}

/// Strict timeliness cutoff, duplicate import, boost reset, and rejection without implicit retries.
pub fn block_boundaries(corpus: &Corpus, seed: u64) -> Result<Vec<String>> {
    let mut trace = vec![corpus.header(seed, "block-boundaries")];
    (|| -> Result<()> {
        let due = corpus
            .spec
            .get_attestation_due::<E>(Slot::new(1))
            .as_millis() as u64;
        require(due > 0, "attestation cutoff must be positive")?;
        for (delay, boosted) in [(due.saturating_sub(1), true), (due, false)] {
            let mut node = corpus.node()?;
            let time = corpus.time(1).saturating_add(delay);
            node.block(corpus, time, 0, Expected::Accepted)?;
            let boost = if boosted {
                corpus.blocks[0].root
            } else {
                Hash256::ZERO
            };
            require(
                node.choice.fc_store().proposer_boost_root() == boost,
                format!("wrong boost at delay={delay}"),
            )?;
            trace.push(format!(
                "t={time} delay={delay} {}",
                node.observe(corpus, time)?
            ));
            node.block(corpus, time, 0, Expected::Accepted)?;
            require(
                node.choice.fc_store().proposer_boost_root() == boost,
                "duplicate changed boost",
            )?;
            trace.push(format!(
                "t={} expiry {}",
                corpus.time(2),
                node.observe(corpus, corpus.time(2))?
            ));
            require(
                node.choice.fc_store().proposer_boost_root() == Hash256::ZERO,
                "slot tick retained boost",
            )?;
            node.block(corpus, corpus.time(2), 0, Expected::Accepted)?;
            require(
                node.choice.fc_store().proposer_boost_root() == Hash256::ZERO,
                "duplicate resurrected expired boost",
            )?;
        }
        let mut node = corpus.node()?;
        node.block(corpus, 0, 0, Expected::Future)?;
        require(
            node.choice.get_block(&corpus.blocks[0].root).is_none(),
            "future block entered DAG",
        )?;
        node.block(corpus, corpus.time(3), 2, Expected::UnknownParent)?;
        require(
            node.choice.get_block(&corpus.blocks[2].root).is_none(),
            "unknown-parent block entered DAG",
        )?;
        trace.push(format!(
            "t={} rejected {}",
            corpus.time(3),
            node.observe(corpus, corpus.time(3))?
        ));
        node.block(corpus, corpus.time(4), 0, Expected::Accepted)?;
        require(
            node.choice.get_block(&corpus.blocks[2].root).is_none(),
            "fork choice implicitly retried child",
        )?;
        node.block(corpus, corpus.time(4), 2, Expected::Accepted)?;
        node.expect_head(corpus, corpus.time(4), corpus.blocks[2].root)?;
        trace.push(format!(
            "t={} explicit-recovery {}",
            corpus.time(4),
            node.observe(corpus, corpus.time(4))?
        ));
        Ok(())
    })()
    .map_err(|error| {
        format!(
            "seed={seed} block-boundaries: {error}\n{}",
            trace.join("\n")
        )
    })?;
    Ok(trace)
}
