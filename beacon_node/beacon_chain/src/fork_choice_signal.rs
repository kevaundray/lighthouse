//! Concurrency helpers for synchronising block proposal with fork choice.
//!
//! The transmitter provides a way for a thread runnning fork choice on a schedule to signal
//! to the receiver that fork choice has been updated for a given slot.
use crate::BeaconChainError;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use types::Slot;

/// Sender, for use by the per-slot task timer.
pub struct ForkChoiceSignalTx {
    pair: Arc<(Mutex<Slot>, Notify)>,
}

/// Receiver, for use by the beacon chain waiting on fork choice to complete.
pub struct ForkChoiceSignalRx {
    pair: Arc<(Mutex<Slot>, Notify)>,
}

pub enum ForkChoiceWaitResult {
    /// Successfully reached a slot greater than or equal to the awaited slot.
    Success(Slot),
    /// Fork choice was updated to a lower slot, indicative of lag or processing delays.
    Behind(Slot),
    /// Timed out waiting for the fork choice update from the sender.
    TimeOut,
}

impl ForkChoiceSignalTx {
    pub fn new() -> Self {
        let pair = Arc::new((Mutex::new(Slot::new(0)), Notify::new()));
        Self { pair }
    }

    pub fn get_receiver(&self) -> ForkChoiceSignalRx {
        ForkChoiceSignalRx {
            pair: self.pair.clone(),
        }
    }

    /// Signal to the receiver that fork choice has been updated to `slot`.
    ///
    /// Return an error if the provided `slot` is strictly less than any previously provided slot.
    pub fn notify_fork_choice_complete(&self, slot: Slot) -> Result<(), BeaconChainError> {
        let (lock, notify) = &*self.pair;

        let mut current_slot = lock.lock();

        if slot < *current_slot {
            return Err(BeaconChainError::ForkChoiceSignalOutOfOrder {
                current: *current_slot,
                latest: slot,
            });
        } else {
            *current_slot = slot;
        }

        // All concurrent proposals need to observe this update.
        notify.notify_waiters();

        Ok(())
    }
}

impl Default for ForkChoiceSignalTx {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkChoiceSignalRx {
    pub async fn wait_for_fork_choice(
        &self,
        slot: Slot,
        timeout: Duration,
    ) -> ForkChoiceWaitResult {
        let (lock, notify) = &*self.pair;
        let notified = notify.notified();
        tokio::pin!(notified);
        // Register before checking the slot so an update cannot be lost between
        // the check and the first poll. No mutex guard crosses the await.
        notified.as_mut().enable();
        let current_slot = *lock.lock();
        if current_slot >= slot {
            return ForkChoiceWaitResult::Success(current_slot);
        }
        // As with the blocking signal, a single behind-slot notification is
        // returned immediately rather than waiting for another update.
        if tokio::time::timeout(timeout, notified).await.is_err() {
            return ForkChoiceWaitResult::TimeOut;
        }
        let current_slot = *lock.lock();
        if current_slot >= slot {
            ForkChoiceWaitResult::Success(current_slot)
        } else {
            ForkChoiceWaitResult::Behind(current_slot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Poll;

    #[tokio::test]
    async fn wakes_all_proposals_and_reports_behind() {
        let tx = ForkChoiceSignalTx::new();
        let rx = tx.get_receiver();
        let first = rx.wait_for_fork_choice(Slot::new(2), Duration::from_secs(1));
        let second = rx.wait_for_fork_choice(Slot::new(3), Duration::from_secs(1));
        tokio::pin!(first, second);
        assert!(matches!(futures::poll!(&mut first), Poll::Pending));
        assert!(matches!(futures::poll!(&mut second), Poll::Pending));

        tx.notify_fork_choice_complete(Slot::new(2)).unwrap();
        assert!(matches!(
            first.await,
            ForkChoiceWaitResult::Success(slot) if slot == Slot::new(2)
        ));
        assert!(matches!(
            second.await,
            ForkChoiceWaitResult::Behind(slot) if slot == Slot::new(2)
        ));
    }

    #[tokio::test]
    async fn completed_slot_needs_no_notification_and_cannot_regress() {
        let tx = ForkChoiceSignalTx::new();
        tx.notify_fork_choice_complete(Slot::new(3)).unwrap();
        assert!(matches!(
            tx.notify_fork_choice_complete(Slot::new(2)),
            Err(BeaconChainError::ForkChoiceSignalOutOfOrder { .. })
        ));
        assert!(matches!(
            tx.get_receiver()
                .wait_for_fork_choice(Slot::new(2), Duration::ZERO)
                .await,
            ForkChoiceWaitResult::Success(slot) if slot == Slot::new(3)
        ));
    }

    #[tokio::test]
    async fn missing_slot_times_out() {
        assert!(matches!(
            ForkChoiceSignalTx::new()
                .get_receiver()
                .wait_for_fork_choice(Slot::new(1), Duration::ZERO)
                .await,
            ForkChoiceWaitResult::TimeOut
        ));
    }
}
