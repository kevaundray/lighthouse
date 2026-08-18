#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

#[cfg(feature = "pq-attestation")]
mod pq;

#[cfg(feature = "pq-attestation")]
pub use pq::*;
