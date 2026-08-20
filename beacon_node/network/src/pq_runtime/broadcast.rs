use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use types::{EthSpec, SignedBeaconBlock};

/// Maximum number of verified blocks retained while the process-owned network worker is busy.
pub const PQ_BLOCK_BROADCAST_QUEUE_CAPACITY: usize = 2;

/// Retryable local failure at the acknowledged PQ block-broadcast boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBlockBroadcastError {
    Capacity,
    WorkerUnavailable,
    Rejected,
}

impl std::fmt::Display for PqBlockBroadcastError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => formatter.write_str("PQ block broadcaster queue is full"),
            Self::WorkerUnavailable => formatter.write_str("PQ block broadcaster is unavailable"),
            Self::Rejected => formatter.write_str("PQ block broadcaster rejected the block"),
        }
    }
}

impl std::error::Error for PqBlockBroadcastError {}

/// Immutable process-owned ingress to the bounded broadcaster queue.
#[derive(Clone)]
pub struct PqBlockBroadcastSender<E: EthSpec> {
    sender: mpsc::Sender<PqBlockBroadcastCommand<E>>,
}

impl<E: EthSpec> PqBlockBroadcastSender<E> {
    /// Non-waiting submission. The returned capability resolves only when the network worker
    /// acknowledges accepting this exact immutable block for publication.
    pub fn try_send(
        &self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> Result<PqBlockBroadcastAcknowledgement, PqBlockBroadcastError> {
        let (acknowledgement_sender, acknowledgement_receiver) = oneshot::channel();
        let command = PqBlockBroadcastCommand {
            block,
            acknowledgement: Some(acknowledgement_sender),
        };
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => PqBlockBroadcastError::Capacity,
            mpsc::error::TrySendError::Closed(_) => PqBlockBroadcastError::WorkerUnavailable,
        })?;
        Ok(PqBlockBroadcastAcknowledgement {
            receiver: acknowledgement_receiver,
        })
    }
}

/// Sole process-owned receiver, retained by the network worker assembled in e-e4.
pub struct PqBlockBroadcastReceiver<E: EthSpec> {
    receiver: mpsc::Receiver<PqBlockBroadcastCommand<E>>,
}

impl<E: EthSpec> PqBlockBroadcastReceiver<E> {
    pub async fn recv(&mut self) -> Option<PqBlockBroadcastCommand<E>> {
        self.receiver.recv().await
    }

    pub(super) fn close_and_reject_pending(&mut self) {
        self.receiver.close();
        while let Ok(command) = self.receiver.try_recv() {
            command.acknowledge(Err(PqBlockBroadcastError::WorkerUnavailable));
        }
    }
}

/// One exact fully verified block awaiting a network-worker acknowledgment.
pub struct PqBlockBroadcastCommand<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    acknowledgement: Option<oneshot::Sender<Result<(), PqBlockBroadcastError>>>,
}

impl<E: EthSpec> PqBlockBroadcastCommand<E> {
    pub fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub fn acknowledge(mut self, result: Result<(), PqBlockBroadcastError>) {
        if let Some(sender) = self.acknowledgement.take() {
            let _ = sender.send(result);
        }
    }
}

/// Awaitable acknowledgment for one already-enqueued command.
pub struct PqBlockBroadcastAcknowledgement {
    receiver: oneshot::Receiver<Result<(), PqBlockBroadcastError>>,
}

impl PqBlockBroadcastAcknowledgement {
    pub async fn wait(self) -> Result<(), PqBlockBroadcastError> {
        self.receiver
            .await
            .unwrap_or(Err(PqBlockBroadcastError::WorkerUnavailable))
    }
}

pub fn pq_block_broadcast_channel<E: EthSpec>()
-> (PqBlockBroadcastSender<E>, PqBlockBroadcastReceiver<E>) {
    let (sender, receiver) = mpsc::channel(PQ_BLOCK_BROADCAST_QUEUE_CAPACITY);
    (
        PqBlockBroadcastSender { sender },
        PqBlockBroadcastReceiver { receiver },
    )
}
