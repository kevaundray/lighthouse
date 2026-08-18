use crate::{
    BlockProcessingError, ConsensusContext, PqConsensusError, VerifiedPqBlock,
    per_block_processing::process_verified_pq_block,
    per_slot_processing::{Error as SlotProcessingError, per_slot_processing},
    pq_profile::pq_pre_state_root,
    pq_verification::preflight_pq_transition_block,
};
use types::{BeaconState, ChainSpec, EthSpec, Hash256};

#[derive(Debug, PartialEq)]
pub enum PqTransitionError {
    PreStateMismatch { expected: Hash256, actual: Hash256 },
    Invalidated(PqConsensusError),
    BlockProcessing(BlockProcessingError),
    SlotProcessing(SlotProcessingError),
}

pub fn per_slot_processing_pq<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<Option<crate::per_epoch_processing::EpochProcessingSummary<E>>, PqTransitionError> {
    if !crate::pq_profile::is_lean_pq_devnet_v1(state, spec, state.slot()) {
        return Err(PqTransitionError::Invalidated(PqConsensusError::Local(
            crate::PqConsensusLocalError::UnsupportedProfile,
        )));
    }
    per_slot_processing(state, None, spec).map_err(PqTransitionError::SlotProcessing)
}

impl std::fmt::Display for PqTransitionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ block transition failed: {self:?}")
    }
}

impl std::error::Error for PqTransitionError {}

pub fn per_block_processing_pq<E: EthSpec>(
    state: &mut BeaconState<E>,
    verified_block: VerifiedPqBlock<E>,
) -> Result<ConsensusContext<E>, PqTransitionError> {
    let (block, expected_pre_state_root, spec) = verified_block.into_transition_parts();
    let actual_pre_state_root = pq_pre_state_root(state).map_err(|error| {
        PqTransitionError::BlockProcessing(BlockProcessingError::BeaconStateError(error))
    })?;
    if actual_pre_state_root != expected_pre_state_root {
        return Err(PqTransitionError::PreStateMismatch {
            expected: expected_pre_state_root,
            actual: actual_pre_state_root,
        });
    }
    preflight_pq_transition_block(state, &block, &spec).map_err(PqTransitionError::Invalidated)?;

    let mut context = ConsensusContext::new(block.slot());
    process_verified_pq_block(state, &block, &mut context, &spec)
        .map_err(PqTransitionError::BlockProcessing)?;
    Ok(context)
}
