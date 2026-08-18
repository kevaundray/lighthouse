//! Isolated integration harness for the experimental lean PQ devnet profile.
//!
//! Consensus verification tokens cannot be forged outside `state_processing`:
//!
//! ```compile_fail
//! use state_processing::PreparedPqBlockProposal;
//! use std::sync::Arc;
//! use types::{MinimalEthSpec, SignedBeaconBlock};
//!
//! fn forge(block: Arc<SignedBeaconBlock<MinimalEthSpec>>) -> PreparedPqBlockProposal<MinimalEthSpec> {
//!     PreparedPqBlockProposal { block, job: todo!() }
//! }
//! ```
//!
//! Sealed inner aggregate evidence cannot be replaced downstream:
//!
//! ```compile_fail
//! use state_processing::VerifiedPqAggregateAndProof;
//! use types::MinimalEthSpec;
//!
//! fn replace_inner(token: &mut VerifiedPqAggregateAndProof<MinimalEthSpec>) {
//!     token.inner_attestation = todo!();
//! }
//! ```

#![cfg_attr(not(feature = "pq-devnet"), allow(dead_code))]

#[cfg(feature = "pq-devnet")]
mod provision;

#[cfg(feature = "pq-devnet")]
pub use provision::{
    ProvisionConfig, ProvisionError, ProvisionedDevnet, production_config, provision_devnet,
    staging_path,
};
#[cfg(feature = "pq-devnet")]
pub use validator_dir::{PQ_DEVNET_GENESIS_FILE, PQ_DEVNET_JOURNAL_FILE, PQ_DEVNET_MANIFEST_FILE};
