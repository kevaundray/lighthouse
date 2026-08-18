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

#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
#[macro_use]
mod macros;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
mod metrics;

#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod all_caches;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod block_replayer;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod common;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod consensus_context;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod envelope_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod epoch_cache;
#[cfg(any(feature = "pq-genesis", not(feature = "pq-attestation")))]
pub mod genesis;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_block_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_epoch_processing;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod per_slot_processing;
#[cfg(feature = "pq-attestation")]
mod pq_attestation;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod state_advance;
#[cfg(any(feature = "pq-genesis", not(feature = "pq-attestation")))]
pub mod upgrade;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub mod verify_operation;

#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use all_caches::AllCaches;
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use block_replayer::{BlockReplayError, BlockReplayer};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use consensus_context::{ConsensusContext, ContextError};
#[cfg(feature = "pq-genesis")]
pub use genesis::{DirectGenesisValidator, initialize_beacon_state_from_validators};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use genesis::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    process_activations,
};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_block_processing::{
    BlockSignatureStrategy, BlockSignatureVerifier, VerifyBlockRoot, VerifySignatures,
    block_signature_verifier, errors::BlockProcessingError, per_block_processing, signature_sets,
};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_epoch_processing::{
    errors::EpochProcessingError, process_epoch as per_epoch_processing,
};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use per_slot_processing::{Error as SlotProcessingError, per_slot_processing};
#[cfg(feature = "pq-attestation")]
pub use pq_attestation::{
    PqAttestationCacheError, PqAttestationContribution, PqAttestationError, PqAttestationInvalid,
    PqAttestationLocalError, PqValidatorKeyCache, build_pq_attestation_job,
    build_pq_single_attestation_job, verify_pq_attestation_job,
};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use types::{EpochCache, EpochCacheError, EpochCacheKey};
#[cfg(not(any(feature = "pq-genesis", feature = "pq-attestation")))]
pub use verify_operation::{SigVerifiedOp, TransformPersist, VerifyOperation, VerifyOperationAt};
