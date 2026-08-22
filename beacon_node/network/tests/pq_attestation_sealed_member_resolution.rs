#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use beacon_chain::{
    PqPublishedLocalMemberResolution, PqSingleConsumptionResult, PqSingleObservationCompletion,
    PqSingleObservationStatus, testing_only_pq_published_local_member_resolver,
};
use lighthouse_network::{MessageId, pq_anonymous_message_id};

fn exact_member_message_id(
    resolver: &beacon_chain::TestingPqPublishedLocalMemberResolver,
) -> MessageId {
    let wire = resolver.borrowed_sealed_member_wire();
    pq_anonymous_message_id(
        wire.topic_hash(),
        wire.signed_ssz(),
        wire.message_domain_valid_snappy(),
        wire.altair_enabled(),
    )
}

#[tokio::test]
async fn sealed_member_and_exact_message_id_resolve_the_chain_observation() {
    for result in [
        PqSingleConsumptionResult::Applied,
        PqSingleConsumptionResult::Queued,
    ] {
        let mut resolver = testing_only_pq_published_local_member_resolver();
        let message_id = exact_member_message_id(&resolver);
        resolver.finalize_exact_observation_before_resolution(result);
        assert!(matches!(
            resolver.resolve(&message_id),
            Ok(PqPublishedLocalMemberResolution::Immediate(actual)) if actual == result
        ));
    }

    for (mark_propagated, completion) in [
        (
            false,
            PqSingleObservationCompletion::Consumed(PqSingleConsumptionResult::Applied),
        ),
        (
            true,
            PqSingleObservationCompletion::Consumed(PqSingleConsumptionResult::Queued),
        ),
    ] {
        let mut resolver = testing_only_pq_published_local_member_resolver();
        let message_id = exact_member_message_id(&resolver);
        resolver.claim_exact_observation();
        if mark_propagated {
            resolver.mark_exact_observation_propagated();
        }
        let PqPublishedLocalMemberResolution::Wait(mut receipt) = resolver
            .resolve(&message_id)
            .expect("an exact pending state yields a real watch")
        else {
            panic!("pending and consumption-pending must not be reported as immediate");
        };
        let PqSingleObservationCompletion::Consumed(result) = completion else {
            unreachable!()
        };
        resolver.finalize_exact_observation(result);
        assert_eq!(receipt.wait().await, Ok(completion));
    }

    let mut released = testing_only_pq_published_local_member_resolver();
    let released_id = exact_member_message_id(&released);
    released.claim_exact_observation();
    let PqPublishedLocalMemberResolution::Wait(mut receipt) = released
        .resolve(&released_id)
        .expect("a pending exact observation yields a real watch")
    else {
        panic!("a pending exact observation must wait");
    };
    released.rollback_exact_observation();
    assert_eq!(
        receipt.wait().await,
        Ok(PqSingleObservationCompletion::Released),
    );

    for expected_status in [
        PqSingleObservationStatus::Conflict,
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
        PqSingleObservationStatus::Unseen,
    ] {
        let mut resolver = testing_only_pq_published_local_member_resolver();
        let message_id = exact_member_message_id(&resolver);
        resolver.arrange_exact_status(expected_status);
        assert!(matches!(
            resolver.resolve(&message_id),
            Err(actual) if actual == expected_status
        ));
    }

    let mut wrong_id = testing_only_pq_published_local_member_resolver();
    wrong_id.claim_exact_observation();
    let subscriptions_before = wrong_id.subscription_count();
    let mut message_id = exact_member_message_id(&wrong_id);
    message_id.0[0] ^= 1;
    assert!(wrong_id.resolve(&message_id).is_err());
    assert_eq!(wrong_id.subscription_count(), subscriptions_before);

    let mut wrong_digest = testing_only_pq_published_local_member_resolver();
    let exact_id = exact_member_message_id(&wrong_digest);
    wrong_digest.claim_exact_observation();
    wrong_digest.testing_only_corrupt_sealed_member_signed_ssz_digest();
    let subscriptions_before = wrong_digest.subscription_count();
    assert!(wrong_digest.resolve(&exact_id).is_err());
    assert_eq!(wrong_digest.subscription_count(), subscriptions_before);
}
