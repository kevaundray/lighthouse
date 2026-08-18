#![cfg(feature = "pq-devnet")]

use consensus_signature::pq::{AggregateError, ProverUnavailable};

#[test]
fn unavailable_prover_is_a_local_aggregate_failure() {
    let error = AggregateError::Unavailable(ProverUnavailable::AlreadyActive);

    assert!(matches!(error, AggregateError::Unavailable(_)));
}
