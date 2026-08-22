#![cfg(all(feature = "pq-proposer", feature = "pq-startup-testing"))]

use network::{
    PqNetworkServiceReadyEvent, PqNetworkServiceReadyEventTestCase,
    testing_only_pq_network_service_select_ready_event,
};

#[tokio::test]
async fn local_published_prefix_event_outranks_network_but_not_shutdown_or_executor_exit() {
    assert_eq!(
        testing_only_pq_network_service_select_ready_event(
            PqNetworkServiceReadyEventTestCase::ExecutorShutdownLocalAndNetwork,
        )
        .await,
        PqNetworkServiceReadyEvent::ExecutorExit,
        "executor exit remains the highest-priority ready event",
    );
    assert_eq!(
        testing_only_pq_network_service_select_ready_event(
            PqNetworkServiceReadyEventTestCase::ShutdownLocalAndNetwork,
        )
        .await,
        PqNetworkServiceReadyEvent::Shutdown,
        "explicit shutdown remains ahead of local retry/finalization",
    );
    assert_eq!(
        testing_only_pq_network_service_select_ready_event(
            PqNetworkServiceReadyEventTestCase::LocalAndNetwork,
        )
        .await,
        PqNetworkServiceReadyEvent::LocalAttestationPublish,
        "a ready published-prefix retry/finalization event must beat a ready network event",
    );
    assert_eq!(
        testing_only_pq_network_service_select_ready_event(
            PqNetworkServiceReadyEventTestCase::NetworkOnly,
        )
        .await,
        PqNetworkServiceReadyEvent::Network,
        "the shared selector still services the network when no higher-priority event is ready",
    );
}
