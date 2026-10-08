#[path = "support/deterministic_simulation.rs"]
mod deterministic_simulation;

use deterministic_simulation::{Corpus, block_boundaries, replay, vote_boundaries};

#[tokio::test(flavor = "current_thread")]
async fn partition_recovery_replays_independently() {
    let corpus = Corpus::build(0).await.expect("seed=0 fixture preparation");
    for seed in [0, 1, 7, 42, 0x5eed, u64::MAX] {
        let first = replay(&corpus, seed).unwrap_or_else(|error| panic!("{error}"));
        let second = replay(&corpus, seed).unwrap_or_else(|error| panic!("{error}"));
        // Each replay creates new ForkChoice, MemoryStore, votes and checkpoints. Semantic
        // divergence/convergence and exact vote weights are asserted inside replay as well.
        assert_eq!(
            first, second,
            "seed={seed} independent replay traces differ"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn same_slot_votes_wait_and_duplicates_do_not_inflate_weight() {
    let seed = 7;
    let corpus = Corpus::build(seed)
        .await
        .expect("seed=7 fixture preparation");
    vote_boundaries(&corpus, seed).unwrap_or_else(|error| panic!("{error}"));
}

#[tokio::test(flavor = "current_thread")]
async fn boost_cutoff_expiry_and_explicit_parent_recovery() {
    let seed = 42;
    let corpus = Corpus::build(seed)
        .await
        .expect("seed=42 fixture preparation");
    block_boundaries(&corpus, seed).unwrap_or_else(|error| panic!("{error}"));
}
