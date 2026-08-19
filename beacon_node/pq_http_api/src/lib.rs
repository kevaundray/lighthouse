//! Isolated HTTP surface for the bounded PQ devnet profile.

#[cfg(feature = "pq-devnet")]
mod api;

#[cfg(feature = "pq-devnet")]
pub use api::*;
