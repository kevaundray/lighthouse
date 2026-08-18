//! Provides:
//!
//! - `ValidatorDir`: manages a directory containing validator keypairs, deposit info and other
//!   things.
//!
//! This crate is intended to be used by the account manager to create validators and the validator
//! client to load those validators.

mod builder;
pub mod insecure_keys;
#[cfg(feature = "pq-devnet")]
mod pq_devnet_bundle;
#[cfg(feature = "pq-devnet")]
mod pq_validator_dir;
mod validator_dir;

pub use crate::validator_dir::{
    ETH1_DEPOSIT_TX_HASH_FILE, Error, Eth1DepositData, ValidatorDir,
    unlock_keypair_from_password_path,
};
pub use builder::{
    Builder, ETH1_DEPOSIT_DATA_FILE, Error as BuilderError, VOTING_KEYSTORE_FILE,
    WITHDRAWAL_KEYSTORE_FILE, keystore_password_path,
};
#[cfg(feature = "pq-devnet")]
pub use pq_devnet_bundle::{
    MAX_PQ_DEVNET_MANIFEST_BYTES, MAX_PQ_DEVNET_VALIDATORS, PQ_DEVNET_GENESIS_FILE,
    PQ_DEVNET_JOURNAL_FILE, PQ_DEVNET_MANIFEST_FILE, PqDevnetBundle, PqDevnetBundleError,
    PqDevnetManifest, PqDevnetManifestError, PqManifestValidator, ValidatedPqDevnetManifest,
};
#[cfg(feature = "pq-devnet")]
pub use pq_validator_dir::{
    PQ_VOTING_KEYSTORE_FILE, PqValidatorDir, PqValidatorDirBuilder, PqValidatorDirError,
};
