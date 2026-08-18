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
//!
//! The PQ state transition accepts only the sealed token, never an unverified block handle:
//!
//! ```compile_fail
//! use state_processing::per_block_processing_pq;
//! use std::sync::Arc;
//! use types::{BeaconState, MinimalEthSpec, SignedBeaconBlock};
//!
//! fn bypass(
//!     state: &mut BeaconState<MinimalEthSpec>,
//!     block: Arc<SignedBeaconBlock<MinimalEthSpec>>,
//! ) {
//!     per_block_processing_pq(state, block).unwrap();
//! }
//! ```
//!
//! The BLS signature-skipping strategy is not exposed in a PQ build:
//!
//! ```compile_fail
//! use state_processing::{BlockSignatureStrategy, per_block_processing};
//! let _ = BlockSignatureStrategy::NoVerification;
//! let _ = per_block_processing;
//! ```
//!
//! A sealed transition does not accept substitutable spec, block-root, or context inputs:
//!
//! ```compile_fail
//! use state_processing::{ConsensusContext, VerifiedPqBlock, per_block_processing_pq};
//! use types::{BeaconState, ChainSpec, MinimalEthSpec};
//!
//! fn substitute_transition_inputs(
//!     state: &mut BeaconState<MinimalEthSpec>,
//!     token: VerifiedPqBlock<MinimalEthSpec>,
//!     spec: &ChainSpec,
//!     context: &mut ConsensusContext<MinimalEthSpec>,
//! ) {
//!     per_block_processing_pq(state, token, spec, false, context).unwrap();
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
