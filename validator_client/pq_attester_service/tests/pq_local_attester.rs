use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqAttestationGossipLocalError, PqLocalAttestationInvariant,
    PqLocalAttestationVerificationError, PqLocalSingleConstructionError, PqVerifiedLocalSingle,
    testing_only_pq_local_candidate_fixture,
};
use consensus_signature::{AggregationError, SameMessageEvidence, SigningIdError};
use state_processing::PqAttestationLocalError;
use std::sync::Arc;
use types::{Attestation, Hash256, SubnetId};

#[allow(dead_code)]
async fn wished_local_verifier_returns_unforgeable_prepropagation_capability<
    T: BeaconChainTypes,
>(
    chain: Arc<BeaconChain<T>>,
    provenance: beacon_chain::PqLocallyConstructedSingle<T::EthSpec>,
) -> PqVerifiedLocalSingle<T::EthSpec> {
    chain
        .verify_pq_single_attestation_for_local(provenance)
        .await
        .expect("the exact local single should verify without claiming gossip propagation")
}

#[test]
fn wished_direct_service_owns_exact_context() {
    let (candidate, signed, spec) = testing_only_pq_local_candidate_fixture(None);
    let expected_index = candidate.validator_index();
    let expected_pubkey = candidate.pubkey();
    let expected_position = candidate.committee_position();
    let expected_subnet = candidate.subnet();
    let expected_head = signed.data().beacon_block_root;
    let sealed = candidate
        .into_local_single(expected_index, signed, &spec)
        .expect("exact local signer output seals");
    assert_eq!(sealed.validator_index(), expected_index);
    assert_eq!(sealed.pubkey(), expected_pubkey);
    assert_eq!(sealed.committee_position(), expected_position);
    assert_eq!(sealed.subnet(), expected_subnet);
    assert_eq!(sealed.bound_head_root(), expected_head);
}

#[test]
fn local_candidate_provenance_rejects_every_mutable_output_field() {
    let (candidate, signed, spec) = testing_only_pq_local_candidate_fixture(None);
    assert!(matches!(
        candidate.into_local_single(99, signed, &spec),
        Err(PqLocalSingleConstructionError::ValidatorIndexMismatch { .. })
    ));

    let (candidate, mut signed, spec) = testing_only_pq_local_candidate_fixture(None);
    let validator_index = candidate.validator_index();
    signed.data_mut().beacon_block_root = Hash256::repeat_byte(0xa1);
    assert!(matches!(
        candidate.into_local_single(validator_index, signed, &spec),
        Err(PqLocalSingleConstructionError::AttestationDataMismatch)
    ));

    let (candidate, mut signed, spec) = testing_only_pq_local_candidate_fixture(None);
    let validator_index = candidate.validator_index();
    let Attestation::Electra(electra) = &mut signed else {
        panic!("fixture must be Electra")
    };
    electra
        .aggregation_bits
        .set(candidate.committee_position(), false)
        .expect("fixture aggregation position");
    assert!(matches!(
        candidate.into_local_single(validator_index, signed, &spec),
        Err(PqLocalSingleConstructionError::InvalidAggregationBits)
    ));

    let (candidate, mut signed, spec) = testing_only_pq_local_candidate_fixture(None);
    let validator_index = candidate.validator_index();
    let Attestation::Electra(electra) = &mut signed else {
        panic!("fixture must be Electra")
    };
    electra
        .committee_bits
        .set(candidate.committee_index() as usize, false)
        .expect("fixture committee position");
    assert!(matches!(
        candidate.into_local_single(validator_index, signed, &spec),
        Err(PqLocalSingleConstructionError::InvalidCommitteeBits)
    ));

    let (candidate, mut signed, spec) = testing_only_pq_local_candidate_fixture(None);
    let validator_index = candidate.validator_index();
    let Attestation::Electra(electra) = &mut signed else {
        panic!("fixture must be Electra")
    };
    electra.signature = SameMessageEvidence::empty();
    assert!(matches!(
        candidate.into_local_single(validator_index, signed, &spec),
        Err(PqLocalSingleConstructionError::InvalidSignature)
    ));

    let (candidate, signed, spec) = testing_only_pq_local_candidate_fixture(Some(SubnetId::new(7)));
    let validator_index = candidate.validator_index();
    assert!(matches!(
        candidate.into_local_single(validator_index, signed, &spec),
        Err(PqLocalSingleConstructionError::InvalidSubnet { .. })
    ));
}

#[test]
fn local_verification_preserves_nested_signing_and_aggregation_sources() {
    let signing =
        PqLocalAttestationVerificationError::Local(PqAttestationGossipLocalError::Attestation(
            PqAttestationLocalError::SigningId(SigningIdError::SlotOutOfRange(u64::MAX)),
        ));
    assert!(std::error::Error::source(&signing).is_some());

    let aggregation =
        PqLocalAttestationVerificationError::Local(PqAttestationGossipLocalError::Attestation(
            PqAttestationLocalError::Aggregation(AggregationError::InvalidEvidence),
        ));
    assert!(std::error::Error::source(&aggregation).is_some());

    let invariant = PqLocalAttestationVerificationError::Invariant(
        PqLocalAttestationInvariant::ProvenanceMismatch("test"),
    );
    assert!(std::error::Error::source(&invariant).is_none());
}
