#![cfg(feature = "pq-proposer")]

use beacon_chain::{
    BeaconChain, PqPublishedLocalAttestationBatchConsumer, PqVerifiedLocalAttestationBatch,
};
#[cfg(feature = "pq-startup-testing")]
use beacon_chain::{
    TestingPqLocalCandidateBatchGuards, testing_only_pq_local_candidate_batch_fixture,
    testing_only_pq_local_candidate_batch_fixture_with_guards,
};
#[cfg(feature = "pq-startup-testing")]
use network::{
    PqLocalAttestationBatchEncodingFailure, PqLocalAttestationPublishTestOutcome,
    testing_only_pq_local_attestation_batch_publish_channel,
    testing_only_pq_local_attestation_encode_batch,
    testing_only_pq_local_attestation_encode_exact_signed_ssz,
    testing_only_pq_local_attestation_publish_progress,
};
use network::{
    PqLocalAttestationBatchPublishReceipt, PqLocalAttestationBatchPublishRetryError,
    PqLocalAttestationBatchPublishSendError, PqLocalAttestationBatchPublishSender,
};
#[cfg(feature = "pq-startup-testing")]
use sha2::{Digest, Sha256};
use types::MinimalEthSpec;

#[allow(dead_code)]
fn network_service_owns_the_whole_batch_command_receiver<T: beacon_chain::BeaconChainTypes>(
    service: &network::PqNetworkService<T>,
) {
    let _: PqLocalAttestationBatchPublishSender<T::EthSpec> =
        service.local_attestation_batch_publish_sender();
}

#[test]
fn whole_verified_batch_command_is_unique_and_result_bearing() {
    let _: fn(
        &PqLocalAttestationBatchPublishSender<MinimalEthSpec>,
        PqVerifiedLocalAttestationBatch<MinimalEthSpec>,
    ) -> Result<
        PqLocalAttestationBatchPublishReceipt<MinimalEthSpec>,
        PqLocalAttestationBatchPublishSendError<MinimalEthSpec>,
    > = PqLocalAttestationBatchPublishSender::<MinimalEthSpec>::try_publish;
}

#[allow(dead_code)]
fn post_publish_consumption_is_an_opaque_chain_bound_capability<
    T: beacon_chain::BeaconChainTypes,
>(
    chain: &std::sync::Arc<BeaconChain<T>>,
) {
    let _: PqPublishedLocalAttestationBatchConsumer<T> =
        BeaconChain::<T>::pq_published_local_attestation_batch_consumer(chain);
}

#[test]
fn plain_post_publish_chain_consume_endpoint_is_not_public() {
    let source = include_str!("../../beacon_chain/src/pq_runtime/beacon_chain.rs");
    assert!(
        !source.contains("pub async fn consume_pq_published_local_attestation_batch("),
        "network must own an opaque chain-bound consumer instead of exposing raw batch consumption",
    );
}

#[allow(dead_code)]
fn retry_consumes_only_the_opaque_progress_owner(
    sender: &PqLocalAttestationBatchPublishSender<MinimalEthSpec>,
    progress: network::PqLocalAttestationBatchPublishProgress<MinimalEthSpec>,
) {
    let _: Result<
        PqLocalAttestationBatchPublishReceipt<MinimalEthSpec>,
        PqLocalAttestationBatchPublishRetryError<MinimalEthSpec>,
    > = sender.try_retry(progress);
}

#[cfg(feature = "pq-startup-testing")]
mod behavior {
    use super::*;
    use beacon_chain::PqSingleConsumptionResult;
    use network::{
        PqLocalAttestationEvidenceMutation, PqLocalAttestationPreConsumerEvidenceFailure,
        testing_only_pq_local_attestation_post_publish_service_channel,
    };
    use types::EthSpec;

    #[test]
    fn exact_signed_ssz_buffer_is_hashed_and_moved_without_reconstruction() {
        let signed_ssz = vec![3, 1, 4, 1, 5, 9];
        let digest: [u8; 32] = Sha256::digest(&signed_ssz).into();
        let trace = testing_only_pq_local_attestation_encode_exact_signed_ssz(
            signed_ssz.clone(),
            digest,
            types::SubnetId::new(3),
            [7; 4],
        )
        .expect("the exact signed SSZ buffer matches its digest");
        assert_eq!(trace.data, signed_ssz);
        assert!(trace.reused_allocation);

        let mut corrupted_digest = digest;
        corrupted_digest[0] ^= 1;
        assert!(
            testing_only_pq_local_attestation_encode_exact_signed_ssz(
                signed_ssz,
                corrupted_digest,
                types::SubnetId::new(3),
                [7; 4],
            )
            .is_err(),
            "a one-byte digest mutation must reject the actual buffer",
        );
    }

    #[test]
    fn production_batch_encoder_keeps_every_member_and_exact_slot_subnet_topic() {
        let members = [
            (vec![1, 2, 3], types::SubnetId::new(2), types::Slot::new(1)),
            (vec![4, 5, 6], types::SubnetId::new(7), types::Slot::new(2)),
        ];
        let inputs = members
            .iter()
            .map(|(signed_ssz, subnet, slot)| {
                (
                    signed_ssz.clone(),
                    <[u8; 32]>::from(Sha256::digest(signed_ssz)),
                    *subnet,
                    *slot,
                )
            })
            .collect();
        let trace = testing_only_pq_local_attestation_encode_batch(inputs)
            .expect("the exact two-member batch encodes");
        let spec = types::ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000);
        let expected_topics = members
            .iter()
            .map(|(_, subnet, slot)| {
                let fork_digest = spec
                    .enr_fork_id::<MinimalEthSpec>(*slot, types::Hash256::ZERO)
                    .fork_digest;
                lighthouse_network::libp2p::gossipsub::IdentTopic::from(
                    lighthouse_network::GossipTopic::new(
                        lighthouse_network::types::GossipKind::Attestation(*subnet),
                        lighthouse_network::types::GossipEncoding::default(),
                        fork_digest,
                    ),
                )
                .hash()
                .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(trace.encoded_member_count, 2);
        assert_eq!(trace.topics, expected_topics);
        assert_eq!(trace.data, members.map(|member| member.0));
    }

    fn empty_verified_batch() -> PqVerifiedLocalAttestationBatch<MinimalEthSpec> {
        let (candidates, signed, spec) = testing_only_pq_local_candidate_batch_fixture(0);
        let returned = candidates
            .candidates()
            .iter()
            .map(|candidate| candidate.validator_index())
            .zip(signed)
            .collect();
        candidates
            .seal_exact_ordered(returned, &spec)
            .expect("empty batch seals exactly")
            .testing_only_into_empty_verified_batch()
    }

    fn empty_verified_batch_with_guards() -> (
        PqVerifiedLocalAttestationBatch<MinimalEthSpec>,
        TestingPqLocalCandidateBatchGuards,
    ) {
        let (candidates, signed, spec, guards) =
            testing_only_pq_local_candidate_batch_fixture_with_guards(0);
        let returned = candidates
            .candidates()
            .iter()
            .map(|candidate| candidate.validator_index())
            .zip(signed)
            .collect();
        let verified = candidates
            .seal_exact_ordered(returned, &spec)
            .expect("empty guarded batch seals exactly")
            .testing_only_into_empty_verified_batch();
        (verified, guards)
    }

    #[tokio::test]
    async fn whole_batch_command_is_cap_one_and_recovers_ownership_when_closed() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let first = sender
            .try_publish(empty_verified_batch())
            .expect("first whole batch is admitted");

        let second = sender
            .try_publish(empty_verified_batch())
            .expect_err("cap plus one is rejected without losing its batch");
        assert_eq!(second.returned_verified_count(), 0);

        receiver.close_and_return_pending();
        let progress = first
            .wait()
            .await
            .expect("closed worker returns the still-owned first batch");
        assert_eq!(progress.verified_count(), 0);
        drop(progress);

        let closed = sender
            .try_publish(empty_verified_batch())
            .expect_err("closed worker rejects new ownership");
        assert!(closed.is_closed());
        assert_eq!(closed.returned_verified_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn off_loop_encoding_survives_caller_and_executor_exit_and_drains() {
        let (exit_sender, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let executor_exit_owner = task_executor.clone();
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        assert_eq!(guards.available_permits(), 0);
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let entered_sender = std::sync::Mutex::new(Some(entered_sender));
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let release_receiver = std::sync::Mutex::new(release_receiver);
        let hook = std::sync::Arc::new(move || {
            if let Some(sender) = entered_sender.lock().expect("test hook lock").take() {
                let _ = sender.send(());
            }
            let _ = release_receiver.lock().expect("test release lock").recv();
        });
        assert!(receiver.start_next_encoding(task_executor, hook));
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_receiver)
            .await
            .expect("blocking encoder entered")
            .expect("blocking encoder reports entry");

        tokio::time::timeout(std::time::Duration::from_secs(1), tokio::task::yield_now())
            .await
            .expect("mutable network-loop heartbeat remains live");
        drop(receipt);
        exit_sender.try_send(()).expect("executor exit signal");
        drop(executor_exit_owner);
        let drain = tokio::spawn(async move { receiver.close_and_drain().await });
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(25),
                &mut Box::pin(async {
                    while !drain.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
            )
            .await
            .is_err(),
            "drain must remain pending while encoding is blocked",
        );
        assert_eq!(guards.available_permits(), 0);

        release_sender.send(()).expect("release blocking encoder");
        tokio::time::timeout(std::time::Duration::from_secs(2), drain)
            .await
            .expect("drain completes after encoding")
            .expect("drain task joins");
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encoding_panic_is_terminal_signals_failure_and_retains_the_batch() {
        let (_exit_sender, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        assert!(receiver.start_next_encoding(
            task_executor,
            std::sync::Arc::new(|| panic!("injected encoder panic")),
        ));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                receiver.finish_next_encoding(),
            )
            .await
            .expect("service-owned completion poll is bounded")
        );

        let progress = tokio::time::timeout(std::time::Duration::from_secs(2), receipt.wait())
            .await
            .expect("panic completion is bounded")
            .expect("the exact batch owner is returned after panic");
        assert_eq!(
            progress.encoding_failure(),
            Some(PqLocalAttestationBatchEncodingFailure::TaskPanicked),
        );
        assert!(progress.is_terminal());
        assert_eq!(guards.available_permits(), 0);
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut shutdown_receiver),
            )
            .await
            .expect("failure signal is bounded"),
            Some(task_executor::ShutdownReason::Failure(_)),
        ));

        drop(progress);
        assert_eq!(guards.available_permits(), 1);
        receiver.close_and_drain().await;
    }

    #[tokio::test]
    async fn unavailable_encoding_worker_is_explicit_terminal_and_never_runs_the_hook() {
        let (_exit_sender, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            std::sync::Weak::<tokio::runtime::Runtime>::new(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        drop(receipt);
        let hook_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_ran_for_worker = std::sync::Arc::clone(&hook_ran);
        assert!(!receiver.start_next_encoding(
            task_executor,
            std::sync::Arc::new(move || {
                hook_ran_for_worker.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
        ));

        assert_eq!(receiver.completed_owner_count(), 1);
        let progress = receiver
            .take_completed_for_test()
            .expect("service retains the exact unavailable-worker batch owner");
        assert_eq!(
            progress.encoding_failure(),
            Some(PqLocalAttestationBatchEncodingFailure::TaskUnavailable),
        );
        assert!(!hook_ran.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(guards.available_permits(), 0);
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut shutdown_receiver),
            )
            .await
            .expect("failure signal is bounded"),
            Some(task_executor::ShutdownReason::Failure(_)),
        ));

        drop(progress);
        assert_eq!(guards.available_permits(), 1);
        receiver.close_and_drain().await;
    }

    #[test]
    fn two_member_retry_skips_the_published_prefix_and_reuses_member_two() {
        let trace = testing_only_pq_local_attestation_publish_progress(
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::NoPeers,
                PqLocalAttestationPublishTestOutcome::Published,
            ],
        );
        assert_eq!(trace.attempted_members, vec![0, 1, 1]);
        assert_eq!(trace.encoded_member_instances, vec![0, 1, 1]);
        assert_eq!(trace.published_members, vec![0, 1]);
        assert!(trace.retryable_members.is_empty());
        assert_eq!(trace.encoding_passes, 1);
    }

    #[test]
    fn pending_and_retained_remote_duplicates_remain_distinct_unresolved_progress() {
        let pending = testing_only_pq_local_attestation_publish_progress(
            1,
            &[PqLocalAttestationPublishTestOutcome::PendingRemote],
        );
        assert_eq!(pending.waiting_remote_members, vec![(0, false)]);
        assert!(pending.published_members.is_empty());

        let retained = testing_only_pq_local_attestation_publish_progress(
            1,
            &[PqLocalAttestationPublishTestOutcome::DuplicateRemote],
        );
        assert_eq!(retained.waiting_remote_members, vec![(0, true)]);
        assert!(retained.published_members.is_empty());
    }

    #[test]
    fn local_duplicate_advances_but_unknown_duplicate_and_transform_are_terminal() {
        let duplicate_local = testing_only_pq_local_attestation_publish_progress(
            2,
            &[
                PqLocalAttestationPublishTestOutcome::DuplicateLocal,
                PqLocalAttestationPublishTestOutcome::Published,
            ],
        );
        assert_eq!(duplicate_local.attempted_members, vec![0, 1]);
        assert_eq!(duplicate_local.published_members, vec![0, 1]);
        assert_eq!(duplicate_local.duplicate_local_members, vec![0]);

        let duplicate_unknown = testing_only_pq_local_attestation_publish_progress(
            2,
            &[PqLocalAttestationPublishTestOutcome::DuplicateUnknown],
        );
        assert_eq!(duplicate_unknown.attempted_members, vec![0]);
        assert_eq!(duplicate_unknown.terminal_members, vec![0]);
        assert!(duplicate_unknown.published_members.is_empty());

        let transform = testing_only_pq_local_attestation_publish_progress(
            2,
            &[PqLocalAttestationPublishTestOutcome::Transform],
        );
        assert_eq!(transform.attempted_members, vec![0]);
        assert_eq!(transform.terminal_members, vec![0]);
        assert!(transform.published_members.is_empty());
    }

    #[tokio::test]
    async fn terminal_progress_retains_the_whole_batch_and_cap_until_drop() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        assert!(receiver.complete_next_terminal());
        let terminal = receipt.wait().await.expect("terminal owner is returned");
        assert!(terminal.is_terminal());
        assert_eq!(
            terminal.member_progress(),
            &[],
            "the opaque owner exposes only bounded member status, never its tokens or encoded request",
        );
        assert_eq!(guards.available_permits(), 0);
        let not_retryable = sender
            .try_retry(terminal)
            .expect_err("terminal progress cannot bypass publication resolution");
        assert!(not_retryable.is_not_retryable());
        let terminal = not_retryable.into_progress();
        assert!(matches!(
            sender.try_publish(empty_verified_batch()),
            Err(PqLocalAttestationBatchPublishSendError::Capacity(_))
        ));

        drop(terminal);
        assert_eq!(guards.available_permits(), 1);
        let admitted = sender
            .try_publish(empty_verified_batch())
            .expect("capacity releases only after terminal owner drop");
        receiver.close_and_return_pending();
        drop(admitted.wait().await);
    }

    #[tokio::test]
    async fn close_returns_the_exact_queued_retry_owner_without_bypassing_cap_one() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        assert!(receiver.complete_next_retryable_for_ownership_test());
        let retryable = receipt.wait().await.expect("retry owner is returned");
        assert!(retryable.is_retryable());
        assert_eq!(guards.available_permits(), 0);

        let retry_receipt = sender
            .try_retry(retryable)
            .expect("the exact retry owner is queued once");
        assert!(matches!(
            sender.try_publish(empty_verified_batch()),
            Err(PqLocalAttestationBatchPublishSendError::Capacity(_))
        ));
        receiver.close_and_return_pending();
        let returned = retry_receipt
            .wait()
            .await
            .expect("close returns the queued retry owner");
        assert!(returned.is_retryable());
        assert_eq!(guards.available_permits(), 0);

        drop(returned);
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test]
    async fn production_close_returns_a_queued_batch_to_its_live_receipt() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");

        receiver.close_and_drain_in_place().await;

        let returned = receipt
            .wait()
            .await
            .expect("a live receipt retains the exact queued batch across close");
        assert_eq!(returned.verified_count(), 0);
        assert_eq!(guards.available_permits(), 0);
        drop(returned);
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn production_close_returns_a_blocked_encoding_batch_to_its_live_receipt() {
        let (_exit_sender, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let entered_sender = std::sync::Mutex::new(Some(entered_sender));
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let release_receiver = std::sync::Mutex::new(release_receiver);
        assert!(receiver.start_next_encoding(
            task_executor,
            std::sync::Arc::new(move || {
                if let Some(sender) = entered_sender.lock().expect("test hook lock").take() {
                    let _ = sender.send(());
                }
                let _ = release_receiver.lock().expect("test release lock").recv();
            }),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_receiver)
            .await
            .expect("blocking encoder entered")
            .expect("blocking encoder reports entry");

        let close = tokio::spawn(async move { receiver.close_and_drain().await });
        assert_eq!(guards.available_permits(), 0);
        release_sender.send(()).expect("release blocking encoder");
        tokio::time::timeout(std::time::Duration::from_secs(2), close)
            .await
            .expect("close completes after encoder release")
            .expect("close task joins");

        let returned = receipt
            .wait()
            .await
            .expect("a live receipt retains the encoded batch across close");
        assert_eq!(returned.encoding_failure(), None);
        assert_eq!(guards.available_permits(), 0);
        drop(returned);
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test]
    async fn production_close_preserves_already_completed_progress_for_its_live_receipt() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        assert!(receiver.complete_next_published_for_ownership_test());

        receiver.close_and_drain_in_place().await;

        let completed = receipt
            .wait()
            .await
            .expect("close drops only the service owner while a live receipt retains progress");
        assert!(matches!(
            completed.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Published {
                    duplicate: false,
                    ..
                }
            ],
        ));
        assert_eq!(guards.available_permits(), 0);
        drop(completed);
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test]
    async fn dropped_receipt_cannot_drop_completed_published_progress_owned_by_service() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        drop(receipt);

        assert!(receiver.complete_next_published_for_ownership_test());
        assert_eq!(receiver.completed_owner_count(), 1);
        assert_eq!(guards.available_permits(), 0);
        assert!(matches!(
            sender.try_publish(empty_verified_batch()),
            Err(PqLocalAttestationBatchPublishSendError::Capacity(_)),
        ));
        let mut chain_drain = Box::pin(guards.close_and_drain());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut chain_drain)
                .await
                .is_err(),
            "chain drain remains pending while the service owns completed progress",
        );

        let completed = receiver
            .take_completed_for_test()
            .expect("service retains the exact completed owner after receipt drop");
        assert!(matches!(
            completed.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Published {
                    duplicate: false,
                    ..
                }
            ],
        ));
        assert_eq!(guards.available_permits(), 0);
        drop(completed);
        tokio::time::timeout(std::time::Duration::from_secs(2), chain_drain)
            .await
            .expect("chain drain completes after explicit completed-owner drop");
        assert_eq!(guards.available_permits(), 1);
        receiver.close_and_drain().await;
    }

    #[tokio::test]
    async fn shutdown_deliberately_drops_service_owned_retry_progress_and_drains() {
        let (sender, mut receiver) = testing_only_pq_local_attestation_batch_publish_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("batch is admitted");
        drop(receipt);
        assert!(receiver.complete_next_retryable_for_ownership_test());
        assert_eq!(receiver.completed_owner_count(), 1);
        assert_eq!(guards.available_permits(), 0);

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.close_and_drain_in_place(),
        )
        .await
        .expect("shutdown drops retained retry progress and drains");
        assert_eq!(guards.available_permits(), 1);
        drop(receiver);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lower_retry_and_terminal_outcomes_never_start_post_publish_consumption() {
        let (_exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );

        for lower_outcome in [
            PqLocalAttestationPublishTestOutcome::NoPeers,
            PqLocalAttestationPublishTestOutcome::ValidationAdmissionFull,
            PqLocalAttestationPublishTestOutcome::AllQueuesFull,
        ] {
            let (sender, mut service) =
                testing_only_pq_local_attestation_post_publish_service_channel();
            let (batch, guards) = empty_verified_batch_with_guards();
            let receipt = sender.try_publish(batch).expect("whole batch is admitted");
            assert!(service.start_next_from_actual_publish_cursor(
                task_executor.clone(),
                2,
                &[lower_outcome],
                &[],
                std::sync::Arc::new(|| {}),
            ));
            assert!(service.finish_next_post_publish().await);

            let retry = receipt
                .wait()
                .await
                .expect("retryable progress returns to the live receipt");
            assert!(retry.is_retryable());
            assert_eq!(service.consumer_call_count(), 0);
            assert_eq!(service.fail_closed_call_count(), 0);
            assert_eq!(guards.available_permits(), 0);
            drop(retry);
            assert_eq!(guards.available_permits(), 1);
            service.close_and_drain().await;
        }

        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor,
            2,
            &[PqLocalAttestationPublishTestOutcome::DuplicateUnknown],
            &[],
            std::sync::Arc::new(|| {}),
        ));
        assert!(service.finish_next_post_publish().await);
        let terminal = receipt
            .wait()
            .await
            .expect("typed terminal progress returns to the live receipt");
        assert!(terminal.is_terminal());
        assert_eq!(service.consumer_call_count(), 0);
        assert_eq!(service.fail_closed_call_count(), 0);
        assert_eq!(guards.available_permits(), 0);
        drop(terminal);
        assert_eq!(guards.available_permits(), 1);
        service.close_and_drain().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_local_wire_success_waits_for_exact_chain_consumption_before_receipt() {
        let (exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let executor_exit_owner = task_executor.clone();
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let entered_sender = std::sync::Mutex::new(Some(entered_sender));
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let release_receiver = std::sync::Mutex::new(release_receiver);
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor,
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::DuplicateLocal,
            ],
            &[
                PqSingleConsumptionResult::Applied,
                PqSingleConsumptionResult::Queued,
            ],
            std::sync::Arc::new(move || {
                if let Some(sender) = entered_sender.lock().expect("entered lock").take() {
                    let _ = sender.send(());
                }
                let _ = release_receiver.lock().expect("release lock").recv();
            }),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_receiver)
            .await
            .expect("post-publish consumer entered")
            .expect("consumer reports entry");
        assert_eq!(service.consumer_call_count(), 1);
        assert_eq!(guards.available_permits(), 0);

        let mut receipt = Box::pin(receipt.wait());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut receipt)
                .await
                .is_err(),
            "wire publication alone must not complete the batch receipt",
        );
        exit_owner
            .try_send(())
            .expect("executor exit must not cancel the no-exit consumer");
        drop(executor_exit_owner);
        let close = tokio::spawn(async move { service.close_and_drain().await });
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(25),
                &mut Box::pin(async {
                    while !close.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
            )
            .await
            .is_err(),
            "service close must drain the blocked chain consumer",
        );

        release_sender.send(()).expect("release chain consumer");
        tokio::time::timeout(std::time::Duration::from_secs(2), close)
            .await
            .expect("service close completes after consumer")
            .expect("close task joins");
        let completed = tokio::time::timeout(std::time::Duration::from_secs(2), receipt)
            .await
            .expect("live receipt completes after chain consumption")
            .expect("whole progress owner remains available");
        assert!(matches!(
            completed.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Consumed {
                    message_id,
                    result: PqSingleConsumptionResult::Applied,
                    ..
                },
                network::PqLocalAttestationMemberPublishProgress::Consumed {
                    message_id: queued_message_id,
                    result: PqSingleConsumptionResult::Queued,
                    ..
                },
            ] if *message_id == lighthouse_network::MessageId(vec![0])
                && *queued_message_id == lighthouse_network::MessageId(vec![1])
        ));
        assert_eq!(
            guards.available_permits(),
            1,
            "successful chain consumption drops the sealed proof guards before metadata receipt",
        );
        drop(completed);
        assert_eq!(guards.available_permits(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_receipt_and_executor_exit_do_not_cancel_post_publish_consumption() {
        let (exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let executor_exit_owner = task_executor.clone();
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        drop(receipt);
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let entered_sender = std::sync::Mutex::new(Some(entered_sender));
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let release_receiver = std::sync::Mutex::new(release_receiver);
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor,
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::DuplicateLocal,
            ],
            &[
                PqSingleConsumptionResult::Applied,
                PqSingleConsumptionResult::Queued,
            ],
            std::sync::Arc::new(move || {
                if let Some(sender) = entered_sender.lock().expect("entered lock").take() {
                    let _ = sender.send(());
                }
                let _ = release_receiver.lock().expect("release lock").recv();
            }),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_receiver)
            .await
            .expect("post-publish consumer entered")
            .expect("consumer reports entry");
        assert_eq!(guards.available_permits(), 0);
        exit_owner.try_send(()).expect("executor exit signal");
        drop(executor_exit_owner);
        release_sender.send(()).expect("release chain consumer");
        assert!(service.finish_next_post_publish().await);
        assert_eq!(service.consumer_call_count(), 1);
        assert_eq!(service.completed_owner_count(), 1);
        assert_eq!(guards.available_permits(), 1);
        let completed = service
            .take_completed_for_test()
            .expect("service retains consumed metadata after receipt abandonment");
        assert!(matches!(
            completed.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Consumed {
                    result: PqSingleConsumptionResult::Applied,
                    ..
                },
                network::PqLocalAttestationMemberPublishProgress::Consumed {
                    result: PqSingleConsumptionResult::Queued,
                    ..
                },
            ]
        ));
        drop(completed);
        service.close_and_drain().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_publish_task_panic_is_typed_and_fails_closed_exactly_once() {
        let (_exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, mut shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor,
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::DuplicateLocal,
            ],
            &[
                PqSingleConsumptionResult::Applied,
                PqSingleConsumptionResult::Queued,
            ],
            std::sync::Arc::new(|| panic!("injected post-publish consumer panic")),
        ));
        assert!(service.finish_next_post_publish().await);
        let terminal = receipt
            .wait()
            .await
            .expect("panic returns typed terminal metadata to the receipt");
        assert_eq!(
            terminal.post_publish_failure(),
            Some(network::PqLocalAttestationPostPublishFailure::TaskPanicked),
        );
        assert!(terminal.is_terminal());
        assert_eq!(service.consumer_call_count(), 1);
        assert_eq!(service.fail_closed_call_count(), 1);
        assert_eq!(guards.available_permits(), 1);
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                futures::StreamExt::next(&mut shutdown_receiver),
            )
            .await
            .expect("panic failure signal is bounded"),
            Some(task_executor::ShutdownReason::Failure(_)),
        ));
        drop(terminal);
        service.close_and_drain().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_prefix_stays_service_owned_across_retry_remote_wait_and_terminal_close() {
        let (_exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );

        // A retry after one irreversible wire publication remains internal to the service.  The
        // same encoded member and MessageId are retried, while member zero's non-clone
        // publication token remains owned by the command.
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor.clone(),
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::NoPeers,
                PqLocalAttestationPublishTestOutcome::Published,
            ],
            &[
                PqSingleConsumptionResult::Applied,
                PqSingleConsumptionResult::Queued,
            ],
            std::sync::Arc::new(|| {}),
        ));
        let mut receipt = Box::pin(receipt.wait());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut receipt)
                .await
                .is_err(),
            "a published prefix plus retryable suffix must not complete the public receipt",
        );
        assert_eq!(guards.available_permits(), 0);
        assert_eq!(service.published_prefix_owner_count(), 1);
        let before_retry = service
            .published_prefix_trace()
            .expect("service retains the published prefix and exact retry request");
        assert_eq!(before_retry.attempted_members, vec![0, 1]);
        assert_eq!(
            before_retry.attempted_message_ids,
            vec![
                lighthouse_network::MessageId(vec![0]),
                lighthouse_network::MessageId(vec![1]),
            ],
        );
        assert_eq!(
            before_retry.attempted_signed_ssz_digests,
            vec![
                <[u8; 32]>::from(Sha256::digest([0])),
                <[u8; 32]>::from(Sha256::digest([1])),
            ],
        );
        assert_eq!(
            before_retry.published_token_message_ids,
            vec![(0, lighthouse_network::MessageId(vec![0]))],
        );
        assert!(
            service.finish_next_post_publish().await,
            "the production event path automatically retries the retained suffix after backoff",
        );
        let after_retry = service
            .published_prefix_trace()
            .expect("service retains exact cumulative publication evidence until consumption");
        assert_eq!(after_retry.attempted_members, vec![0, 1, 1]);
        assert_eq!(
            after_retry.attempted_message_ids[1], after_retry.attempted_message_ids[2],
            "retry must reuse the exact MessageId",
        );
        assert_eq!(
            after_retry.attempted_signed_ssz_digests[1],
            after_retry.attempted_signed_ssz_digests[2],
            "retry must reuse the exact encoded bytes",
        );
        assert_eq!(
            after_retry.published_token_message_ids,
            vec![
                (0, lighthouse_network::MessageId(vec![0])),
                (1, lighthouse_network::MessageId(vec![1])),
            ],
        );
        let completed = tokio::time::timeout(std::time::Duration::from_secs(2), receipt)
            .await
            .expect("receipt completes only after exact post-wire consumption")
            .expect("service returns typed consumed metadata");
        assert!(matches!(
            completed.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Consumed { .. },
                network::PqLocalAttestationMemberPublishProgress::Consumed { .. },
            ],
        ));
        assert_eq!(guards.available_permits(), 1);
        drop(completed);
        service.close_and_drain().await;

        // A remote-pending suffix is also unresolved service-owned work.  Abandoning the receipt
        // and closing the service must fail-close the irreversible prefix exactly once before
        // dropping the guards.
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        assert!(service.start_next_from_actual_publish_cursor(
            task_executor.clone(),
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::PendingRemote,
            ],
            &[],
            std::sync::Arc::new(|| {}),
        ));
        let mut receipt = Box::pin(receipt.wait());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut receipt)
                .await
                .is_err(),
            "a published prefix plus remote-pending suffix remains unresolved",
        );
        assert_eq!(service.published_prefix_owner_count(), 1);
        let waiting = service
            .published_prefix_trace()
            .expect("service owns both the token and remote wait state");
        assert_eq!(waiting.waiting_remote_members, vec![1]);
        assert_eq!(
            waiting.published_token_message_ids,
            vec![(0, lighthouse_network::MessageId(vec![0]))],
        );
        assert_eq!(guards.available_permits(), 0);
        drop(receipt);
        service.close_and_drain_in_place().await;
        assert_eq!(service.fail_closed_call_count(), 1);
        assert_eq!(guards.available_permits(), 1);
        drop(service);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_prefix_terminal_fails_closed_synchronously_before_receipt() {
        let (_exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");

        assert!(service.start_next_from_actual_publish_cursor(
            task_executor,
            2,
            &[
                PqLocalAttestationPublishTestOutcome::Published,
                PqLocalAttestationPublishTestOutcome::DuplicateUnknown,
            ],
            &[],
            std::sync::Arc::new(|| {}),
        ));
        assert_eq!(
            service.fail_closed_call_count(),
            1,
            "the post-publish handler must fail-close before returning to the outer select",
        );
        let terminal = receipt
            .wait()
            .await
            .expect("receipt completes only after synchronous terminal finalization");
        assert!(terminal.is_terminal());
        assert!(matches!(
            terminal.member_progress(),
            [
                network::PqLocalAttestationMemberPublishProgress::Published { .. },
                network::PqLocalAttestationMemberPublishProgress::Terminal { .. },
            ],
        ));
        assert_eq!(guards.available_permits(), 0);
        drop(terminal);
        assert_eq!(guards.available_permits(), 1);
        service.close_and_drain_in_place().await;
        assert_eq!(service.fail_closed_call_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_prefix_close_invokes_fail_closed_before_releasing_live_or_abandoned_owner() {
        for abandon_receipt in [false, true] {
            let (_exit_owner, exit_receiver) = async_channel::bounded(1);
            let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
            let task_executor = task_executor::TaskExecutor::new(
                tokio::runtime::Handle::current(),
                exit_receiver,
                shutdown_sender,
            );
            let (sender, mut service) =
                testing_only_pq_local_attestation_post_publish_service_channel();
            let (batch, guards) = empty_verified_batch_with_guards();
            let receipt = sender.try_publish(batch).expect("whole batch is admitted");
            assert!(service.start_next_from_actual_publish_cursor(
                task_executor,
                2,
                &[
                    PqLocalAttestationPublishTestOutcome::Published,
                    PqLocalAttestationPublishTestOutcome::PendingRemote,
                ],
                &[],
                std::sync::Arc::new(|| {}),
            ));
            assert_eq!(guards.available_permits(), 0);

            let callback_calls = std::sync::atomic::AtomicUsize::new(0);
            if abandon_receipt {
                drop(receipt);
                service
                    .close_and_drain_in_place_with_fail_closed(|| {
                        assert_eq!(
                            guards.available_permits(),
                            0,
                            "fail-close authority runs before abandoned ownership is dropped",
                        );
                        callback_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    })
                    .await;
                assert_eq!(callback_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
                assert_eq!(guards.available_permits(), 1);
            } else {
                service
                    .close_and_drain_in_place_with_fail_closed(|| {
                        assert_eq!(
                            guards.available_permits(),
                            0,
                            "fail-close authority runs before the live receipt is completed",
                        );
                        callback_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    })
                    .await;
                assert_eq!(callback_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
                let terminal = receipt
                    .wait()
                    .await
                    .expect("live receipt receives typed terminal ownership after fail-close");
                assert_eq!(guards.available_permits(), 0);
                assert!(terminal.is_terminal());
                drop(terminal);
                assert_eq!(guards.available_permits(), 1);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_wire_evidence_is_validated_atomically_before_any_consumer_or_owner_release() {
        for mutation in [
            PqLocalAttestationEvidenceMutation::RemoveToken { member: 1 },
            PqLocalAttestationEvidenceMutation::CorruptToken { member: 1 },
        ] {
            let (_exit_owner, exit_receiver) = async_channel::bounded(1);
            let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
            let task_executor = task_executor::TaskExecutor::new(
                tokio::runtime::Handle::current(),
                exit_receiver,
                shutdown_sender,
            );
            let (sender, mut service) =
                testing_only_pq_local_attestation_post_publish_service_channel();
            let (batch, guards) = empty_verified_batch_with_guards();
            let guards = std::sync::Arc::new(guards);
            let receipt = sender.try_publish(batch).expect("whole batch is admitted");
            let fail_closed_observed_with_guard =
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let fail_closed_observed = std::sync::Arc::clone(&fail_closed_observed_with_guard);
            let guards_during_fail = std::sync::Arc::clone(&guards);

            assert!(service.start_next_from_actual_publish_cursor_with_evidence_mutation(
                task_executor,
                2,
                &[
                    PqLocalAttestationPublishTestOutcome::Published,
                    PqLocalAttestationPublishTestOutcome::DuplicateLocal,
                ],
                mutation,
                move || {
                    assert_eq!(
                        guards_during_fail.available_permits(),
                        0,
                        "fail-close must run while both tokens and the whole guard remain owned",
                    );
                    fail_closed_observed.store(true, std::sync::atomic::Ordering::SeqCst);
                },
            ));
            assert!(service.finish_next_post_publish().await);
            assert_eq!(service.consumer_call_count(), 0);
            assert_eq!(service.fail_closed_call_count(), 1);
            assert!(fail_closed_observed_with_guard.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(guards.available_permits(), 0);

            let terminal = receipt
                .wait()
                .await
                .expect("receipt completes only after synchronous fail-close");
            assert_eq!(
                terminal.post_publish_failure(),
                Some(
                    network::PqLocalAttestationPostPublishFailure::PreConsumerEvidence(
                        PqLocalAttestationPreConsumerEvidenceFailure::MemberToken { member: 1 },
                    )
                ),
                "evidence preparation failure is typed before the consumer boundary",
            );
            assert!(terminal.is_terminal());
            assert_eq!(guards.available_permits(), 0);
            drop(terminal);
            assert_eq!(guards.available_permits(), 1);
            service.close_and_drain().await;
        }

        let (_exit_owner, exit_receiver) = async_channel::bounded(1);
        let (shutdown_sender, _shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_receiver,
            shutdown_sender,
        );
        let (sender, mut service) =
            testing_only_pq_local_attestation_post_publish_service_channel();
        let (batch, guards) = empty_verified_batch_with_guards();
        let guards = std::sync::Arc::new(guards);
        let receipt = sender.try_publish(batch).expect("whole batch is admitted");
        assert!(
            service.start_next_from_actual_publish_cursor_with_evidence_mutation(
                task_executor,
                2,
                &[
                    PqLocalAttestationPublishTestOutcome::Published,
                    PqLocalAttestationPublishTestOutcome::DuplicateLocal,
                ],
                PqLocalAttestationEvidenceMutation::RemoveToken { member: 1 },
                || {},
            )
        );
        drop(receipt);
        let callback_calls = std::sync::atomic::AtomicUsize::new(0);
        let guards_during_fail = std::sync::Arc::clone(&guards);
        service
            .close_and_drain_in_place_with_fail_closed(|| {
                assert_eq!(guards_during_fail.available_permits(), 0);
                callback_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .await;
        assert_eq!(callback_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(service.consumer_call_count(), 0);
        assert_eq!(guards.available_permits(), 1);
    }
}
