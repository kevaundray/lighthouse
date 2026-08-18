#![cfg(feature = "pq-devnet")]

use consensus_signature::pq::{
    AggregateError, Claim, Error, PqProver, ProverError, ProverUnavailable, SecretKey, Signature,
    verify,
};

#[test]
fn pq_dependency_smoke() {
    let prover = PqProver::new().expect("PQ prover worker starts and initializes");
    assert!(matches!(
        PqProver::new(),
        Err(ProverError::Unavailable(ProverUnavailable::AlreadyActive))
    ));

    let claim = Claim::new([0x42; 32], 7);
    let first_signing_key = SecretKey::from_seed([0x11; 32], 0..=15).expect("deterministic PQ key");
    let same_first_key =
        SecretKey::from_seed([0x11; 32], 0..=15).expect("same deterministic PQ key");
    let second_signing_key =
        SecretKey::from_seed([0x22; 32], 0..=15).expect("second deterministic PQ key");
    let wrong_key =
        SecretKey::from_seed([0x33; 32], 0..=15).expect("different deterministic PQ key");
    assert_eq!(first_signing_key.public_key(), same_first_key.public_key());

    let first_public_key = first_signing_key.public_key();
    let second_public_key = second_signing_key.public_key();
    let first_raw = first_signing_key
        .sign(&claim)
        .expect("first raw PQ signature");
    let second_raw = second_signing_key
        .sign(&claim)
        .expect("second raw PQ signature");
    let raw_bytes = first_raw.to_bytes();
    let decoded_raw = Signature::from_bytes(&raw_bytes, &claim, &[first_public_key])
        .expect("contextual raw-signature decode");
    verify(&decoded_raw, &[first_public_key], &claim).expect("raw signature verifies");

    assert!(matches!(
        prover.aggregate(Vec::new(), claim),
        Err(AggregateError::InvalidRequest(Error::Empty))
    ));
    let aggregate = prover
        .aggregate(vec![first_raw, second_raw], claim)
        .expect("two-signer PQ aggregate");
    let aggregate_bytes = aggregate.to_bytes();
    let expected_signers = [first_public_key, second_public_key];
    let decoded_aggregate = Signature::from_bytes(&aggregate_bytes, &claim, &expected_signers)
        .expect("contextual aggregate decode");
    verify(&decoded_aggregate, &expected_signers, &claim).expect("aggregate verifies");

    let wrong_claim = Claim::new([0x43; 32], 7);
    let missing_signer = [first_public_key];
    let extra_signer = [first_public_key, second_public_key, wrong_key.public_key()];
    let wrong_signer = [first_public_key, wrong_key.public_key()];
    assert!(verify(&decoded_aggregate, &missing_signer, &claim).is_err());
    assert!(verify(&decoded_aggregate, &extra_signer, &claim).is_err());
    assert!(verify(&decoded_aggregate, &wrong_signer, &claim).is_err());
    assert!(verify(&decoded_aggregate, &expected_signers, &wrong_claim).is_err());
    assert!(
        Signature::from_bytes(&aggregate_bytes, &claim, &missing_signer)
            .and_then(|signature| verify(&signature, &missing_signer, &claim))
            .is_err()
    );
    assert!(
        Signature::from_bytes(&aggregate_bytes, &claim, &extra_signer)
            .and_then(|signature| verify(&signature, &extra_signer, &claim))
            .is_err()
    );
    assert!(
        Signature::from_bytes(&aggregate_bytes, &claim, &wrong_signer)
            .and_then(|signature| verify(&signature, &wrong_signer, &claim))
            .is_err()
    );
    assert!(
        Signature::from_bytes(&aggregate_bytes, &wrong_claim, &expected_signers)
            .and_then(|signature| verify(&signature, &expected_signers, &wrong_claim))
            .is_err()
    );
}
