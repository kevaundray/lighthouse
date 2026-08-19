#[cfg(not(feature = "pq-devnet"))]
mod common;
#[cfg(not(feature = "pq-devnet"))]
mod interop;

#[cfg(not(feature = "pq-devnet"))]
pub use interop::{
    DEFAULT_ETH1_BLOCK_HASH, InteropGenesisBuilder, bls_withdrawal_credentials,
    interop_genesis_state, interop_genesis_state_with_eth1,
};
#[cfg(not(feature = "pq-devnet"))]
pub use types::test_utils::generate_deterministic_keypairs;
