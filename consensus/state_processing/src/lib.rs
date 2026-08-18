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

#[cfg(not(feature = "pq-genesis"))]
#[macro_use]
mod macros;
#[cfg(not(feature = "pq-genesis"))]
mod metrics;

#[cfg(not(feature = "pq-genesis"))]
pub mod all_caches;
#[cfg(not(feature = "pq-genesis"))]
pub mod block_replayer;
#[cfg(not(feature = "pq-genesis"))]
pub mod common;
#[cfg(not(feature = "pq-genesis"))]
pub mod consensus_context;
#[cfg(not(feature = "pq-genesis"))]
pub mod envelope_processing;
#[cfg(not(feature = "pq-genesis"))]
pub mod epoch_cache;
pub mod genesis;
#[cfg(not(feature = "pq-genesis"))]
pub mod per_block_processing;
#[cfg(not(feature = "pq-genesis"))]
pub mod per_epoch_processing;
#[cfg(not(feature = "pq-genesis"))]
pub mod per_slot_processing;
#[cfg(not(feature = "pq-genesis"))]
pub mod state_advance;
pub mod upgrade;
#[cfg(not(feature = "pq-genesis"))]
pub mod verify_operation;

#[cfg(not(feature = "pq-genesis"))]
pub use all_caches::AllCaches;
#[cfg(not(feature = "pq-genesis"))]
pub use block_replayer::{BlockReplayError, BlockReplayer};
#[cfg(not(feature = "pq-genesis"))]
pub use consensus_context::{ConsensusContext, ContextError};
#[cfg(feature = "pq-genesis")]
pub use genesis::{DirectGenesisValidator, initialize_beacon_state_from_validators};
#[cfg(not(feature = "pq-genesis"))]
pub use genesis::{
    eth2_genesis_time, initialize_beacon_state_from_eth1, is_valid_genesis_state,
    process_activations,
};
#[cfg(not(feature = "pq-genesis"))]
pub use per_block_processing::{
    BlockSignatureStrategy, BlockSignatureVerifier, VerifyBlockRoot, VerifySignatures,
    block_signature_verifier, errors::BlockProcessingError, per_block_processing, signature_sets,
};
#[cfg(not(feature = "pq-genesis"))]
pub use per_epoch_processing::{
    errors::EpochProcessingError, process_epoch as per_epoch_processing,
};
#[cfg(not(feature = "pq-genesis"))]
pub use per_slot_processing::{Error as SlotProcessingError, per_slot_processing};
#[cfg(not(feature = "pq-genesis"))]
pub use types::{EpochCache, EpochCacheError, EpochCacheKey};
#[cfg(not(feature = "pq-genesis"))]
pub use verify_operation::{SigVerifiedOp, TransformPersist, VerifyOperation, VerifyOperationAt};
