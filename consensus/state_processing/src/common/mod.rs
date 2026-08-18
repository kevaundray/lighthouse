#[cfg(not(feature = "pq-transition"))]
mod deposit_data_tree;
mod get_attestation_participation;
mod get_attesting_indices;
#[cfg(not(feature = "pq-transition"))]
mod get_payload_attesting_indices;
mod initiate_validator_exit;
#[cfg(not(feature = "pq-transition"))]
mod slash_validator;

pub mod altair;
pub mod base;
pub mod update_progressive_balances_cache;

#[cfg(not(feature = "pq-transition"))]
pub use deposit_data_tree::DepositDataTree;
pub use get_attestation_participation::get_attestation_participation_flag_indices;
#[cfg(not(feature = "pq-transition"))]
pub use get_attesting_indices::get_attesting_indices_from_state;
pub use get_attesting_indices::{attesting_indices_base, attesting_indices_electra};
#[cfg(not(feature = "pq-transition"))]
pub use get_payload_attesting_indices::{
    get_indexed_payload_attestation, get_payload_attesting_indices,
};
pub use initiate_validator_exit::initiate_validator_exit;
#[cfg(not(feature = "pq-transition"))]
pub use slash_validator::slash_validator;

use safe_arith::SafeArith;
use types::{BeaconState, BeaconStateError, EthSpec};

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    increase_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance<E: EthSpec>(
    state: &mut BeaconState<E>,
    index: usize,
    delta: u64,
) -> Result<(), BeaconStateError> {
    decrease_balance_directly(state.get_balance_mut(index)?, delta)
}

/// Increase the balance of a validator, erroring upon overflow, as per the spec.
pub fn increase_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    balance.safe_add_assign(delta)?;
    Ok(())
}

/// Decrease the balance of a validator, saturating upon overflow, as per the spec.
pub fn decrease_balance_directly(balance: &mut u64, delta: u64) -> Result<(), BeaconStateError> {
    *balance = balance.saturating_sub(delta);
    Ok(())
}
