#![cfg(feature = "pq-devnet")]

use consensus_signature::pq::{AggregateError, Error};

#[test]
fn pq_aggregate_errors_distinguish_peer_evidence_from_local_failures() {
    assert!(matches!(
        AggregateError::from(Error::MessageMismatch),
        AggregateError::InvalidEvidence(Error::MessageMismatch)
    ));
    assert!(matches!(
        AggregateError::from(Error::MalformedSignature),
        AggregateError::InvalidEvidence(Error::MalformedSignature)
    ));
    assert!(matches!(
        AggregateError::from(Error::Empty),
        AggregateError::InvalidRequest(Error::Empty)
    ));
    assert!(matches!(
        AggregateError::from(Error::TooManySigners { got: 2, max: 1 }),
        AggregateError::InvalidRequest(Error::TooManySigners { got: 2, max: 1 })
    ));
    assert!(matches!(
        AggregateError::from(Error::NotInitialized),
        AggregateError::Internal(Error::NotInitialized)
    ));
}
