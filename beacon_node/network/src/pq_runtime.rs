use beacon_chain::{
    BeaconChain, BeaconChainTypes, PqBlockImportOutcome, PqBlockImportRequest, PqForwardRangeError,
    PqGossipCommitToken, PqGossipObservation, PqGossipPropagationToken, PqImportError,
};
use std::sync::Arc;
use types::SignedBeaconBlock;

/// Result of the complete sealed verification which precedes a gossipsub decision.
pub enum PqGossipBlockDisposition<T: BeaconChainTypes> {
    /// Propagate this fully authenticated block, then consume it in `commit_gossip_block`.
    Accept(PqGossipPropagationToken<T>),
    /// Do not propagate again. This is the unique retry claim made available only after an earlier
    /// local Engine/transport/store failure or a dropped propagation/commit capability.
    Retry(PqGossipCommitToken<T>),
    /// Another exact capability is still pending propagation or commit.
    IgnorePending,
    /// The same root was rejected by Engine, committed, or otherwise completed terminally.
    IgnoreTerminal,
    /// A fully verified equivocation is not propagated in V1, which has no slashing pipeline.
    IgnoreEquivocation,
    /// Hostile deterministic input. Reject and apply the caller's peer-invalid policy.
    Reject(PqImportError),
    /// Missing parent or local proof/resource failure. Ignore without penalizing the peer.
    Ignore(PqImportError),
}

/// PQ-only network boundary. The ordinary BLS router/sync processor remains cfg-omitted.
pub struct PqNetworkBlockProcessor<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
}

impl<T: BeaconChainTypes> PqNetworkBlockProcessor<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self { chain }
    }

    pub async fn verify_gossip_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> PqGossipBlockDisposition<T> {
        match self
            .chain
            .verify_pq_block(PqBlockImportRequest::gossip(block))
            .await
        {
            Ok(verified) => match self.chain.observe_verified_pq_gossip_block(verified) {
                PqGossipObservation::New(token) => PqGossipBlockDisposition::Accept(token),
                PqGossipObservation::Retry(token) => PqGossipBlockDisposition::Retry(token),
                PqGossipObservation::Pending => PqGossipBlockDisposition::IgnorePending,
                PqGossipObservation::Terminal => PqGossipBlockDisposition::IgnoreTerminal,
                PqGossipObservation::Equivocation { .. } => {
                    PqGossipBlockDisposition::IgnoreEquivocation
                }
                PqGossipObservation::NotGossip => {
                    PqGossipBlockDisposition::Ignore(verified_source_invariant())
                }
                PqGossipObservation::Capacity => PqGossipBlockDisposition::Ignore(
                    PqImportError::Local(beacon_chain::PqImportLocalError::ObservationCapacity),
                ),
            },
            Err(error) if error.should_penalize_peer() => PqGossipBlockDisposition::Reject(error),
            Err(error) => PqGossipBlockDisposition::Ignore(error),
        }
    }

    /// Call only after gossipsub propagation for `Accept`, or immediately for a duplicate retry.
    pub async fn commit_gossip_block(
        &self,
        verified: PqGossipCommitToken<T>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        verified.commit().await
    }

    pub async fn import_rpc_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        self.chain
            .import_pq_block(PqBlockImportRequest::rpc(block))
            .await
    }

    pub async fn import_lookup_block(
        &self,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<PqBlockImportOutcome, PqImportError> {
        self.chain
            .import_pq_block(PqBlockImportRequest::lookup(block))
            .await
    }

    pub async fn import_forward_range(
        &self,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<Vec<PqBlockImportOutcome>, PqForwardRangeError> {
        self.chain
            .import_pq_forward_range(
                blocks
                    .into_iter()
                    .map(PqBlockImportRequest::forward_range)
                    .collect(),
            )
            .await
    }
}

fn verified_source_invariant() -> PqImportError {
    PqImportError::Local(beacon_chain::PqImportLocalError::Invariant(
        "gossip verifier returned a non-gossip capability",
    ))
}
