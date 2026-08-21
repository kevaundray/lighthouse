#![cfg(feature = "pq-proposer")]

use beacon_chain::PqVerifiedLocalAttestationBatch;
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
}
