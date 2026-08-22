use crate::beacon_chain::{
    BeaconSnapshot, PqBackgroundAggregationCandidateShape, PqBackgroundAggregationDecision,
    PqBackgroundAggregationGate, PqExecutionReconciliation, PqExecutionReconciliationState,
};
use futures::FutureExt;
use operation_pool::{OperationPool, PqAttestationPoolPrepareError};
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use state_processing::{PqValidatorKeyCache, validate_lean_pq_devnet_v1};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use task_executor::{ShutdownReason, TaskExecutor};
use types::{ChainSpec, EthSpec};

const PQ_BACKGROUND_AGGREGATION_TASK: &str = "pq-background-attestation-aggregation";

fn sample_pq_background_aggregation_window(
    mut sample_slot: impl FnMut() -> Option<types::Slot>,
    mut sample_remaining: impl FnMut() -> Option<Duration>,
) -> Option<(types::Slot, Duration)> {
    let slot_before = sample_slot()?;
    let remaining = sample_remaining()?;
    let slot_after = sample_slot()?;
    (slot_before == slot_after).then_some((slot_after, remaining))
}

fn pq_background_aggregation_submission_is_open(closed: bool, executor_exiting: bool) -> bool {
    !closed && !executor_exiting
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_background_aggregation_window_is_coherent(
    slot_before: types::Slot,
    remaining: Duration,
    slot_after: types::Slot,
) -> bool {
    let mut slots = [Some(slot_before), Some(slot_after)].into_iter();
    sample_pq_background_aggregation_window(|| slots.next().flatten(), || Some(remaining)).is_some()
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_background_aggregation_submission_is_open(
    closed: bool,
    executor_exiting: bool,
) -> bool {
    pq_background_aggregation_submission_is_open(closed, executor_exiting)
}

/// Process-owned admission and drain boundary for one persistent background aggregation worker.
pub(crate) struct PqBackgroundAttestationAggregator<E: EthSpec, S: SlotClock> {
    kick: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
    completion: tokio::sync::Mutex<
        Option<tokio::sync::oneshot::Receiver<Result<(), tokio::task::JoinError>>>,
    >,
    closed: Arc<AtomicBool>,
    #[cfg(feature = "pq-startup-testing")]
    close_hook: Mutex<Option<Arc<crate::TestingPqBlockingHook>>>,
    #[cfg(feature = "pq-startup-testing")]
    task_executor: TaskExecutor,
    marker: std::marker::PhantomData<(E, S)>,
}

impl<E: EthSpec, S: SlotClock + 'static> PqBackgroundAttestationAggregator<E, S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        pool: Arc<OperationPool<E>>,
        canonical_head: Arc<RwLock<Arc<BeaconSnapshot<E>>>>,
        reconciliation: Arc<PqExecutionReconciliation>,
        key_cache: Arc<PqValidatorKeyCache>,
        spec: Arc<ChainSpec>,
        slot_clock: S,
        task_executor: TaskExecutor,
    ) -> Option<Self> {
        let (kick, receiver) = tokio::sync::mpsc::channel(1);
        let closed = Arc::new(AtomicBool::new(false));
        let worker_closed = Arc::clone(&closed);
        let worker_executor = task_executor.clone();
        let completion = task_executor.spawn_handle_without_exit(
            async move {
                run_background_aggregation_worker(
                    pool,
                    canonical_head,
                    reconciliation,
                    key_cache,
                    spec,
                    slot_clock,
                    worker_executor,
                    receiver,
                    worker_closed,
                )
                .await;
            },
            PQ_BACKGROUND_AGGREGATION_TASK,
        )?;
        Some(Self {
            kick: Mutex::new(Some(kick)),
            completion: tokio::sync::Mutex::new(Some(completion)),
            closed,
            #[cfg(feature = "pq-startup-testing")]
            close_hook: Mutex::new(None),
            #[cfg(feature = "pq-startup-testing")]
            task_executor,
            marker: std::marker::PhantomData,
        })
    }

    pub(crate) fn kick(&self) {
        let kick = self.kick.lock();
        if let Some(kick) = kick.as_ref() {
            let _ = kick.try_send(());
        }
    }

    pub(crate) async fn close_and_drain(&self) {
        self.closed.store(true, Ordering::Release);
        self.kick.lock().take();
        #[cfg(feature = "pq-startup-testing")]
        let close_hook = { self.close_hook.lock().clone() };
        #[cfg(feature = "pq-startup-testing")]
        if let Some(hook) = close_hook
            && let Some(completion) = self.task_executor.spawn_blocking_handle_without_exit(
                move || hook.run(),
                "pq-background-attestation-close-hook",
            )
        {
            let _ = completion.await;
        }
        if let Some(completion) = self.completion.lock().await.take() {
            let _ = completion.await;
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    pub(crate) fn testing_only_set_close_hook(
        &self,
        hook: Option<Arc<crate::TestingPqBlockingHook>>,
    ) {
        *self.close_hook.lock() = hook;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_background_aggregation_worker<E: EthSpec, S: SlotClock + 'static>(
    pool: Arc<OperationPool<E>>,
    canonical_head: Arc<RwLock<Arc<BeaconSnapshot<E>>>>,
    reconciliation: Arc<PqExecutionReconciliation>,
    key_cache: Arc<PqValidatorKeyCache>,
    spec: Arc<ChainSpec>,
    slot_clock: S,
    task_executor: TaskExecutor,
    mut receiver: tokio::sync::mpsc::Receiver<()>,
    closed: Arc<AtomicBool>,
) {
    let mut gate = PqBackgroundAggregationGate::new(slot_clock.slot_duration());
    let exit_executor = task_executor.clone();
    let mut exit = Box::pin(exit_executor.exit());
    loop {
        tokio::select! {
            biased;
            _ = exit.as_mut() => break,
            kick = receiver.recv() => {
                if kick.is_none() || closed.load(Ordering::Acquire) {
                    break;
                }
            }
        }
        let Some((clock_slot, remaining)) = sample_pq_background_aggregation_window(
            || slot_clock.now(),
            || slot_clock.duration_to_next_slot(),
        ) else {
            continue;
        };
        if remaining < Duration::from_secs(60) || E::slots_per_epoch() != 8 {
            continue;
        }
        let sampled_head = canonical_head.read().clone();
        if sampled_head.beacon_state.slot() != clock_slot
            || !matches!(
                reconciliation.current(),
                PqExecutionReconciliationState::Reconciled { block_root }
                    if block_root == sampled_head.beacon_block_root
            )
        {
            continue;
        }

        let preparation = {
            let pool = Arc::clone(&pool);
            let key_cache = Arc::clone(&key_cache);
            let spec = Arc::clone(&spec);
            let mut state = sampled_head.beacon_state.clone();
            task_executor.spawn_blocking_handle_without_exit(
                move || {
                    if validate_lean_pq_devnet_v1(&state, &spec, clock_slot).is_err()
                        || state.build_all_committee_caches(&spec).is_err()
                    {
                        return Ok(None);
                    }
                    pool.prepare_next_pq_attestation_aggregate(&state, &key_cache, &spec)
                },
                "pq-background-attestation-prepare",
            )
        };
        let Some(preparation) = preparation else {
            signal_background_aggregation_failure(&task_executor);
            break;
        };
        let prepared = match preparation.await {
            Ok(Ok(Ok(Some(prepared)))) => prepared,
            Ok(Ok(Ok(None))) => continue,
            Ok(Ok(Err(PqAttestationPoolPrepareError::GenerationExhausted))) => {
                signal_background_aggregation_failure(&task_executor);
                break;
            }
            Ok(Ok(Err(_))) => continue,
            Ok(Err(_)) | Err(_) => {
                signal_background_aggregation_failure(&task_executor);
                break;
            }
        };

        let final_head = canonical_head.read().clone();
        let Some((final_slot, final_remaining)) = sample_pq_background_aggregation_window(
            || slot_clock.now(),
            || slot_clock.duration_to_next_slot(),
        ) else {
            continue;
        };
        if final_head.beacon_block_root != sampled_head.beacon_block_root {
            continue;
        }
        let reconciled_slot = match reconciliation.current() {
            PqExecutionReconciliationState::Reconciled { block_root }
                if block_root == final_head.beacon_block_root =>
            {
                final_head.beacon_state.slot()
            }
            _ => types::Slot::new(u64::MAX),
        };
        let decision = gate.try_admit(
            final_slot,
            final_head.beacon_state.slot(),
            reconciled_slot,
            final_remaining,
            PqBackgroundAggregationCandidateShape::TwoRawSingletons,
        );
        if decision != PqBackgroundAggregationDecision::Admitted {
            continue;
        }

        let executor_exiting = exit.as_mut().now_or_never().is_some();
        if !pq_background_aggregation_submission_is_open(
            closed.load(Ordering::Acquire),
            executor_exiting,
        ) {
            break;
        }

        let started = Instant::now();
        let disposition = prepared.execute().await;
        gate.record_completion(started.elapsed());
        if disposition.is_fatal() {
            signal_background_aggregation_failure(&task_executor);
            break;
        }
    }
}

fn signal_background_aggregation_failure(task_executor: &TaskExecutor) {
    let mut shutdown = task_executor.shutdown_sender();
    let _ = shutdown.try_send(ShutdownReason::Failure(
        "PQ background attestation aggregation failed",
    ));
}
