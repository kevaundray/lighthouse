//! Compile-time-selected operation pool runtime.
//!
//! The frozen PQ V1 profile owns an ephemeral, bounded verified-attestation coordinator. Its
//! candidates are inserted only after successful fork-choice disposition; unsupported BLS
//! operations and persisted `opo` bytes are never interpreted in this profile.

#[cfg(not(feature = "pq-devnet"))]
#[path = "bls_runtime.rs"]
mod runtime;
#[cfg(feature = "pq-devnet")]
#[path = "pq_runtime.rs"]
mod runtime;

#[cfg(not(feature = "pq-devnet"))]
mod attestation;
#[cfg(not(feature = "pq-devnet"))]
pub mod attestation_storage;
#[cfg(not(feature = "pq-devnet"))]
mod attester_slashing;
#[cfg(not(feature = "pq-devnet"))]
mod bls_to_execution_changes;
#[cfg(not(feature = "pq-devnet"))]
mod max_cover;
#[cfg(not(feature = "pq-devnet"))]
mod metrics;
#[cfg(not(feature = "pq-devnet"))]
mod persistence;
#[cfg(not(feature = "pq-devnet"))]
mod reward_cache;
#[cfg(not(feature = "pq-devnet"))]
mod sync_aggregate_id;

pub use runtime::*;
