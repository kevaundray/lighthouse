#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use beacon_chain::{PqSingleConsumptionResult, PqSingleObservationStatus};
use network::{
    PqAttestationFailureOnceScenario, PqAttestationFailureOnceTerminal,
    testing_only_pq_attestation_failure_once_driver,
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_post_propagation_failure_has_exactly_one_process_signal_and_terminal_owner() {
    for (scenario, expected_terminal, panic_monitor_is_owner) in [
        (
            PqAttestationFailureOnceScenario::ForkChoiceSemantic,
            PqAttestationFailureOnceTerminal::ForkChoiceSemantic,
            false,
        ),
        (
            PqAttestationFailureOnceScenario::NestedSpawnUnavailable,
            PqAttestationFailureOnceTerminal::TaskUnavailable,
            false,
        ),
        (
            PqAttestationFailureOnceScenario::NestedJoinFailure,
            PqAttestationFailureOnceTerminal::TaskJoin,
            false,
        ),
        (
            PqAttestationFailureOnceScenario::Panic,
            PqAttestationFailureOnceTerminal::Panic,
            true,
        ),
    ] {
        let mut driver = testing_only_pq_attestation_failure_once_driver(scenario).await;
        driver
            .start_actual_remote_consumption_with_h3_waiter()
            .await
            .expect("real propagated remote token, lower commit, and H3 exact watch are active");
        assert!(driver.h3_receipt_is_pending());
        assert_eq!(driver.guard_available_permits(), 0);

        driver
            .release_actual_failure_barrier()
            .expect("the real chain consume continuation reaches its injected failure");
        let reason = tokio::time::timeout(Duration::from_secs(2), driver.next_shutdown_reason())
            .await
            .expect("one bounded process failure signal")
            .expect("shutdown channel remains owned");
        assert!(matches!(reason, task_executor::ShutdownReason::Failure(_)));
        assert!(
            driver
                .second_shutdown_reason_is_pending(Duration::from_millis(25))
                .await,
            "the same semantic failure must never be signalled by two owners",
        );

        let trace = driver
            .finish_actual_network_and_h3_lifecycle()
            .await
            .expect("network completion terminalizes lower, chain observation, and H3 receipt");
        assert_eq!(trace.local_terminal, Some(expected_terminal));
        assert_eq!(trace.shutdown_failure_count, 1);
        assert_eq!(trace.lower_terminal_resolution_count, 1);
        assert_eq!(
            trace.chain_observation_status,
            PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Terminal),
        );
        assert_eq!(trace.chain_ingress_close_count, 1);
        assert_eq!(trace.fail_closed_authority_count, 1);
        assert!(trace.guards_retained_until_failure_authority);
        assert_eq!(trace.guard_available_permits_after_owner_drop, 1);
        assert_eq!(
            trace.panic_monitor_signal_count,
            usize::from(panic_monitor_is_owner)
        );
        assert_eq!(
            trace.explicit_owner_signal_count,
            usize::from(!panic_monitor_is_owner),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_remote_consumption_emits_no_failure_signal() {
    let mut driver =
        testing_only_pq_attestation_failure_once_driver(PqAttestationFailureOnceScenario::Success)
            .await;
    driver
        .start_actual_remote_consumption_with_h3_waiter()
        .await
        .expect("real propagated remote token, lower commit, and H3 exact watch are active");
    driver
        .release_actual_failure_barrier()
        .expect("success control continuation is released");
    assert!(
        driver
            .second_shutdown_reason_is_pending(Duration::from_millis(25))
            .await,
        "success must not emit any process failure signal",
    );
    let trace = driver
        .finish_actual_network_and_h3_lifecycle()
        .await
        .expect("success control applies and resolves H3");
    assert_eq!(trace.local_terminal, None);
    assert_eq!(trace.shutdown_failure_count, 0);
    assert_eq!(trace.lower_terminal_resolution_count, 0);
    assert_eq!(
        trace.chain_observation_status,
        PqSingleObservationStatus::Consumed(PqSingleConsumptionResult::Applied),
    );
    assert_eq!(trace.chain_ingress_close_count, 0);
    assert_eq!(trace.fail_closed_authority_count, 0);
}
