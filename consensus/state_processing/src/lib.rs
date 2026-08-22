// Clippy lint set-up (disabled in tests)
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::disallowed_methods,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::let_underscore_must_use
    )
)]
#[cfg(any(
    not(any(feature = "pq-genesis", feature = "pq-attestation")),
    feature = "pq-transition"
))]
#[macro_use]
mod macros;
#[cfg(any(
    not(any(feature = "pq-genesis", feature = "pq-attestation")),
    feature = "pq-transition"
))]
mod metrics;

#[cfg(any(
    not(any(feature = "pq-genesis", feature = "pq-attestation")),
    feature = "pq-transition"
))]
pub mod all_caches;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod block_replayer;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod common;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
mod common;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod consensus_context;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
mod consensus_context;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod envelope_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod epoch_cache;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
mod epoch_cache;
#[cfg(any(feature = "pq-genesis", not(feature = "pq-attestation")))]
pub mod genesis;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_block_processing;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
mod per_block_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_epoch_processing;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
pub mod per_epoch_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_slot_processing;
#[cfg(all(feature = "pq-transition", feature = "pq-attestation"))]
mod per_slot_processing;
#[cfg(feature = "pq-attestation")]
mod pq_attestation;
#[cfg(feature = "pq-attestation")]
mod pq_profile;
#[cfg(feature = "pq-transition")]
mod pq_transition;
#[cfg(feature = "pq-verification")]
mod pq_verification;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod state_advance;
#[cfg(any(feature = "pq-genesis", not(feature = "pq-attestation")))]
pub mod upgrade;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod verify_operation;

#[cfg(any(
    not(any(feature = "pq-genesis", feature = "pq-attestation")),
    feature = "pq-transition"
))]
pub use all_caches::AllCaches;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use block_replayer::{BlockReplayError, BlockReplayer};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use consensus_context::{ConsensusContext, ContextError};
#[cfg(feature = "pq-transition")]
pub use consensus_context::{ConsensusContext, ContextError};
#[cfg(feature = "pq-genesis")]
pub use genesis::{DirectGenesisValidator, initialize_beacon_state_from_validators};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use genesis::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    process_activations,
};
#[cfg(feature = "pq-transition")]
pub use per_block_processing::deneb::kzg_commitment_to_versioned_hash;
#[cfg(feature = "pq-transition")]
pub use per_block_processing::errors::{
    AttesterSlashingValidationError, BlockProcessingError, HeaderInvalid, SignatureSetError,
};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_block_processing::{
    BlockSignatureStrategy, BlockSignatureVerifier, VerifyBlockRoot, VerifySignatures,
    block_signature_verifier, errors::BlockProcessingError, per_block_processing, signature_sets,
};
#[cfg(feature = "pq-transition")]
pub use per_block_processing::{compute_timestamp_at_slot, get_expected_withdrawals};
#[cfg(feature = "pq-transition")]
pub use per_epoch_processing::{EpochProcessingSummary, errors::EpochProcessingError};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_epoch_processing::{
    errors::EpochProcessingError, process_epoch as per_epoch_processing,
};
#[cfg(feature = "pq-transition")]
pub use per_slot_processing::Error as SlotProcessingError;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_slot_processing::{Error as SlotProcessingError, per_slot_processing};
#[cfg(feature = "pq-attestation")]
pub use pq_attestation::{
    PqAttestationCacheError, PqAttestationContribution, PqAttestationError, PqAttestationInvalid,
    PqAttestationLocalError, PqValidatorKeyCache, PreparedPqAttestation,
    PreparedPqSingleAttestation, VerifiedPqAttestation, VerifiedPqSingleAttestation,
    aggregate_pq_attestation_job, build_pq_attestation_job, build_pq_single_attestation_job,
    prepare_pq_attestation, prepare_pq_attestation_aggregate, prepare_pq_single_attestation,
    verify_pq_attestation_job,
};
#[cfg(feature = "pq-attestation")]
pub use pq_profile::{
    LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT, PqDevnetStateError, validate_lean_pq_devnet_v1,
};
#[cfg(feature = "pq-transition")]
pub use pq_transition::{
    PqImportedTransitionOutput, PqLocalTransitionOutput, PqTransitionError,
    per_block_processing_pq, per_block_processing_pq_local, per_slot_processing_pq,
    transition_pq_imported_block,
};
#[cfg(feature = "pq-transition")]
pub use pq_verification::{
    PqBlockAttestationSelectionError, PqBlockAttestationSelectionLocalError,
    validate_pq_attestation_for_block_selection,
};
#[cfg(feature = "pq-verification")]
pub use pq_verification::{
    PqConsensusComponent, PqConsensusError, PqConsensusInvalid, PqConsensusLocalError,
    PqLocalBlockError, PqLocalBlockInvalid, PqUnsupportedBlock, PreparedPqAggregateAndProof,
    PreparedPqBlock, PreparedPqBlockProposal, PreparedPqRandao, VerifiedPqAggregateAndProof,
    VerifiedPqBlock, VerifiedPqBlockProposal, VerifiedPqLocalBlock, VerifiedPqRandao,
    prepare_pq_aggregate_and_proof, prepare_pq_block, prepare_pq_block_proposal,
    prepare_pq_local_block, prepare_pq_randao,
};
#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub use pq_verification::{
    classify_pq_consensus_aggregation_error, preflight_pq_local_block_with_sealing_work_count,
    prepare_pq_aggregate_and_proof_with_evidence_work_count,
    prepare_pq_block_with_evidence_work_count, prepare_pq_randao_with_evidence_work_count,
};
#[cfg(feature = "pq-transition")]
pub use types::{EpochCache, EpochCacheError, EpochCacheKey};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use types::{EpochCache, EpochCacheError, EpochCacheKey};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use verify_operation::{SigVerifiedOp, TransformPersist, VerifyOperation, VerifyOperationAt};
