use beacon_chain::{
    TestingPqBackgroundAggregationCandidateShape, TestingPqBackgroundAggregationDecision,
    TestingPqBackgroundAggregationGate, testing_only_pq_background_aggregation_submission_is_open,
    testing_only_pq_background_aggregation_window_is_coherent,
};
use std::time::Duration;
use types::Slot;

const SLOT_DURATION: Duration = Duration::from_secs(300);
const MINIMUM_REMAINING: Duration = Duration::from_secs(60);

#[test]
fn background_aggregation_requires_the_exact_safe_window_and_current_head() {
    let mut gate = TestingPqBackgroundAggregationGate::new(SLOT_DURATION);
    let exact_candidates = TestingPqBackgroundAggregationCandidateShape::TwoRawSingletons;

    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(1),
            Slot::new(1),
            MINIMUM_REMAINING - Duration::from_millis(1),
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::InsufficientRemaining,
    );
    assert_eq!(gate.last_started_slot(), None);

    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(0),
            Slot::new(0),
            MINIMUM_REMAINING,
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::HeadNotCurrent,
    );
    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(1),
            Slot::new(0),
            MINIMUM_REMAINING,
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::HeadNotReconciled,
    );

    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(1),
            Slot::new(1),
            MINIMUM_REMAINING,
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::Admitted,
    );
    assert_eq!(gate.last_started_slot(), Some(Slot::new(1)));
    assert_eq!(
        gate.try_admit(
            Slot::new(0),
            Slot::new(0),
            Slot::new(0),
            SLOT_DURATION,
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::AlreadyStartedThisSlot,
        "clock rollback must not reset the one-launch-per-slot watermark",
    );
    assert_eq!(gate.last_started_slot(), Some(Slot::new(1)));
    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(1),
            Slot::new(1),
            SLOT_DURATION,
            exact_candidates,
        ),
        TestingPqBackgroundAggregationDecision::AlreadyStartedThisSlot,
    );
}

#[test]
fn background_aggregation_rejects_unsupported_shapes_and_disables_after_an_overrun() {
    let mut gate = TestingPqBackgroundAggregationGate::new(SLOT_DURATION);

    for shape in [
        TestingPqBackgroundAggregationCandidateShape::ContainsAggregate,
        TestingPqBackgroundAggregationCandidateShape::WrongContributionCount,
    ] {
        assert_eq!(
            gate.try_admit(
                Slot::new(1),
                Slot::new(1),
                Slot::new(1),
                MINIMUM_REMAINING,
                shape,
            ),
            TestingPqBackgroundAggregationDecision::UnsupportedCandidateShape,
        );
    }

    assert_eq!(
        gate.try_admit(
            Slot::new(1),
            Slot::new(1),
            Slot::new(1),
            MINIMUM_REMAINING,
            TestingPqBackgroundAggregationCandidateShape::TwoRawSingletons,
        ),
        TestingPqBackgroundAggregationDecision::Admitted,
    );
    gate.record_completion(Duration::from_secs(60) + Duration::from_millis(1));
    assert!(gate.is_disabled());
    assert_eq!(
        gate.try_admit(
            Slot::new(2),
            Slot::new(2),
            Slot::new(2),
            SLOT_DURATION,
            TestingPqBackgroundAggregationCandidateShape::TwoRawSingletons,
        ),
        TestingPqBackgroundAggregationDecision::DisabledAfterOverrun,
    );
}

#[test]
fn background_aggregation_clock_window_must_be_one_coherent_slot() {
    assert!(!testing_only_pq_background_aggregation_window_is_coherent(
        Slot::new(1),
        SLOT_DURATION,
        Slot::new(2),
    ));
    assert!(testing_only_pq_background_aggregation_window_is_coherent(
        Slot::new(2),
        SLOT_DURATION - Duration::from_millis(1),
        Slot::new(2),
    ));
}

#[test]
fn background_aggregation_never_submits_after_shutdown_or_executor_exit() {
    assert!(testing_only_pq_background_aggregation_submission_is_open(
        false, false,
    ));
    assert!(!testing_only_pq_background_aggregation_submission_is_open(
        true, false,
    ));
    assert!(!testing_only_pq_background_aggregation_submission_is_open(
        false, true,
    ));
}
