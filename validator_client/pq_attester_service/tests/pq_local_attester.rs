use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqAttestationGossipLocalError, PqLocalAttestationInvariant,
    PqLocalAttestationVerificationError, PqLocalSingleConstructionError, PqVerifiedLocalSingle,
    testing_only_pq_local_candidate_batch_fixture,
    testing_only_pq_local_candidate_batch_fixture_with_guards,
    testing_only_pq_local_candidate_fixture,
};
use consensus_signature::{AggregationError, SameMessageEvidence, SigningIdError};
use state_processing::PqAttestationLocalError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use types::{Attestation, Hash256, SubnetId};

use pq_attester_service::PqLocalAttestationBatchValidationError;
use pq_attester_service::{PqLocalAttestationSigningPlan, plan_pq_local_attestations};

#[tokio::test(flavor = "current_thread")]
async fn guarded_sign_once_cannot_escape_requests_or_cancel_with_its_receipt() {
    let (owned_candidates, signed, spec, guards) =
        testing_only_pq_local_candidate_batch_fixture_with_guards(2);
    let expected = owned_candidates
        .candidates()
        .iter()
        .map(|candidate| {
            (
                candidate.validator_index(),
                candidate.pubkey(),
                candidate.committee_position(),
                candidate.attestation().clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_ne!(expected[0].0, expected[1].0);
    assert_ne!(expected[0].1, expected[1].1);
    assert_ne!(expected[0].3.data(), expected[1].3.data());
    assert_eq!(expected[0].2, 0);
    assert_eq!(expected[1].2, 1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    let runtime = task_executor::test_utils::TestRuntime::default();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_signer = Arc::clone(&calls);
    let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
    let receipt = batch
        .testing_only_sign_once_with(
            runtime.task_executor.clone(),
            Arc::new(spec),
            move |requests| async move {
                assert_eq!(calls_in_signer.fetch_add(1, Ordering::SeqCst), 0);
                assert_eq!(requests.len(), 2);
                for (request, expected) in requests.iter().zip(&expected) {
                    assert_eq!(request.validator_index, expected.0);
                    assert_eq!(request.pubkey, expected.1);
                    assert_eq!(request.validator_committee_index, expected.2);
                    assert_eq!(request.attestation, expected.3);
                }
                let _ = entered_sender.send(());
                let _ = release_receiver.await;
                Ok(signed
                    .into_iter()
                    .enumerate()
                    .map(|(index, attestation)| {
                        (
                            u64::try_from(index).expect("two bounded validator indices"),
                            attestation,
                        )
                    })
                    .collect())
            },
        )
        .expect("owned signing task starts");
    entered_receiver.await.expect("signing task entered");
    drop(receipt);
    let drain = tokio::spawn(async move {
        guards.close_and_drain().await;
        guards.available_permits()
    });
    tokio::task::yield_now().await;
    assert!(
        !drain.is_finished(),
        "dropped caller receipt must not release guarded signing work",
    );
    release_sender.send(()).expect("release fake signer");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("guard drain completes")
            .expect("guard drain task"),
        1,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

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
fn exact_complete_store_batch_seals_owned_candidates() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(1);
    let plan = plan_pq_local_attestations(owned_candidates).expect("bounded signing plan");
    let PqLocalAttestationSigningPlan::Sign(batch) = plan else {
        panic!("one exact candidate must require signing")
    };
    let returned = vec![(0, signed.pop().expect("one exact signed attestation"))];
    let sealed = batch
        .testing_only_validate_signed(returned, &spec)
        .expect("exact complete ordered store batch");
    assert_eq!(sealed.len(), 1);
}

#[test]
fn empty_candidate_batch_is_no_duty_before_store_use() {
    let (owned_candidates, signed, _spec) = testing_only_pq_local_candidate_batch_fixture(0);
    assert!(signed.is_empty());
    let plan = plan_pq_local_attestations(owned_candidates).expect("empty batch plan");
    assert!(matches!(plan, PqLocalAttestationSigningPlan::NoDuty));
}

#[test]
fn requested_batch_rejects_empty_store_output() {
    let (owned_candidates, _signed, spec) = testing_only_pq_local_candidate_batch_fixture(1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    assert!(matches!(
        batch.testing_only_validate_signed(vec![], &spec),
        Err(PqLocalAttestationBatchValidationError::Empty)
    ));
}

#[test]
fn requested_batch_rejects_missing_store_member() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(2);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("two-candidate plan")
    else {
        panic!("two candidates require store signing")
    };
    let first = signed.remove(0);
    assert!(matches!(
        batch.testing_only_validate_signed(vec![(0, first)], &spec),
        Err(PqLocalAttestationBatchValidationError::MissingMember { validator_index: 1 })
    ));
}

#[test]
fn requested_batch_rejects_extra_store_member() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    let first = signed.pop().expect("one signed attestation");
    assert!(matches!(
        batch.testing_only_validate_signed(vec![(0, first.clone()), (99, first)], &spec),
        Err(PqLocalAttestationBatchValidationError::ExtraMember {
            validator_index: 99
        })
    ));
}

#[test]
fn requested_batch_rejects_duplicate_returned_index() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(2);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("two-candidate plan")
    else {
        panic!("two candidates require store signing")
    };
    let first = signed.remove(0);
    let second = signed.remove(0);
    assert!(matches!(
        batch.testing_only_validate_signed(vec![(0, first), (0, second)], &spec),
        Err(PqLocalAttestationBatchValidationError::DuplicateReturnedIndex { validator_index: 0 })
    ));
}

#[test]
fn requested_batch_rejects_store_order_mismatch() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(2);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("two-candidate plan")
    else {
        panic!("two candidates require store signing")
    };
    let first = signed.remove(0);
    let second = signed.remove(0);
    assert!(matches!(
        batch.testing_only_validate_signed(vec![(1, second), (0, first)], &spec),
        Err(PqLocalAttestationBatchValidationError::OrderMismatch {
            position: 0,
            expected: 0,
            actual: 1,
        })
    ));
}

#[test]
fn requested_batch_rejects_store_attestation_data_mismatch() {
    let (owned_candidates, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    let mut wrong = signed.pop().expect("one signed attestation");
    wrong.data_mut().beacon_block_root = Hash256::repeat_byte(0x91);
    assert!(matches!(
        batch.testing_only_validate_signed(vec![(0, wrong)], &spec),
        Err(PqLocalAttestationBatchValidationError::Seal(
            beacon_chain::PqLocalAttestationBatchSealError::Candidate(
                PqLocalSingleConstructionError::AttestationDataMismatch
            )
        ))
    ));
}

#[test]
fn signing_plan_and_store_output_are_capped_at_sixteen() {
    let (too_many, _signed, _spec) = testing_only_pq_local_candidate_batch_fixture(17);
    assert!(matches!(
        plan_pq_local_attestations(too_many),
        Err(PqLocalAttestationBatchValidationError::Capacity {
            requested: 17,
            maximum: 16,
        })
    ));

    let (maximum, mut signed, spec) = testing_only_pq_local_candidate_batch_fixture(16);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(maximum).expect("maximum candidate plan")
    else {
        panic!("maximum nonempty batch requires store signing")
    };
    let extra = signed.first().expect("maximum batch nonempty").clone();
    let mut returned = signed
        .drain(..)
        .enumerate()
        .map(|(index, attestation)| {
            (
                u64::try_from(index).expect("bounded returned validator index"),
                attestation,
            )
        })
        .collect::<Vec<_>>();
    returned.push((99, extra));
    assert!(matches!(
        batch.testing_only_validate_signed(returned, &spec),
        Err(PqLocalAttestationBatchValidationError::ReturnedCapacity {
            returned: 17,
            maximum: 16,
        })
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn signing_plan_and_sealed_output_retain_then_release_batch_guards() {
    let (owned_candidates, mut signed, spec, guards) =
        testing_only_pq_local_candidate_batch_fixture_with_guards(1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    assert_eq!(guards.available_permits(), 0);
    let sealed = batch
        .testing_only_validate_signed(
            vec![(0, signed.pop().expect("one signed attestation"))],
            &spec,
        )
        .expect("exact sealed output");
    let drain = tokio::spawn(async move {
        guards.close_and_drain().await;
        guards.available_permits()
    });
    tokio::task::yield_now().await;
    assert!(!drain.is_finished(), "sealed output must retain activity");
    drop(sealed);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("guard drain completes")
            .expect("guard drain task"),
        1,
    );

    let (owned_candidates, _signed, spec, guards) =
        testing_only_pq_local_candidate_batch_fixture_with_guards(1);
    let PqLocalAttestationSigningPlan::Sign(batch) =
        plan_pq_local_attestations(owned_candidates).expect("one-candidate plan")
    else {
        panic!("one candidate requires store signing")
    };
    assert!(matches!(
        batch.testing_only_validate_signed(vec![], &spec),
        Err(PqLocalAttestationBatchValidationError::Empty)
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), guards.close_and_drain())
        .await
        .expect("validation error drops every batch guard");
    assert_eq!(guards.available_permits(), 1);
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
