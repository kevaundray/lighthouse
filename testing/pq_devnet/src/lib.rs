#![cfg_attr(not(feature = "pq-devnet"), allow(dead_code))]

#[cfg(feature = "pq-devnet")]
mod provision;

#[cfg(feature = "pq-devnet")]
pub use provision::{
    PQ_DEVNET_GENESIS_FILE, PQ_DEVNET_JOURNAL_FILE, PQ_DEVNET_MANIFEST_FILE, ProvisionConfig,
    ProvisionError, ProvisionedDevnet, production_config, provision_devnet, staging_path,
};
