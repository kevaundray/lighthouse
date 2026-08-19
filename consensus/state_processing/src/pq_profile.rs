use types::{BeaconState, ChainSpec, EthSpec, ForkName, Hash256, Slot};

pub const LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT: usize = 16;

/// A deterministic startup-profile rejection for lean PQ devnet V1 state ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqDevnetStateError {
    InvalidForkSchedule,
    InvalidStateFork,
    InvalidValidatorCount { actual: usize, expected: usize },
    UnsupportedDepositState,
    UnsupportedPendingDeposits,
    UnsupportedPendingPartialWithdrawals,
    UnsupportedPendingConsolidations,
}

impl std::fmt::Display for PqDevnetStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "lean PQ devnet V1 state rejected: {self:?}")
    }
}

impl std::error::Error for PqDevnetStateError {}

#[cfg(feature = "pq-verification")]
pub(crate) fn pq_pre_state_root<E: EthSpec>(
    state: &BeaconState<E>,
) -> Result<Hash256, types::BeaconStateError> {
    let mut snapshot = state.clone();
    snapshot.canonical_root()
}

/// Returns whether state, schedule, and duty slot match the frozen lean PQ devnet V1 profile.
pub(crate) fn is_lean_pq_devnet_v1<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
    duty_slot: Slot,
) -> bool {
    validate_lean_pq_devnet_v1(state, spec, duty_slot).is_ok()
}

/// Strictly validates the frozen V1 state/profile before any PQ worker is started.
pub fn validate_lean_pq_devnet_v1<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
    duty_slot: Slot,
) -> Result<(), PqDevnetStateError> {
    let genesis_epoch = E::genesis_epoch();
    if spec.fork_name_at_slot::<E>(duty_slot) != ForkName::Electra
        || spec.altair_fork_epoch != Some(genesis_epoch)
        || spec.bellatrix_fork_epoch != Some(genesis_epoch)
        || spec.capella_fork_epoch != Some(genesis_epoch)
        || spec.deneb_fork_epoch != Some(genesis_epoch)
        || spec.electra_fork_epoch != Some(genesis_epoch)
        || spec.is_fulu_scheduled()
        || spec.is_gloas_scheduled()
    {
        return Err(PqDevnetStateError::InvalidForkSchedule);
    }
    if state.fork_name(spec) != Ok(ForkName::Electra)
        || state.fork_name_unchecked() != ForkName::Electra
    {
        return Err(PqDevnetStateError::InvalidStateFork);
    }
    if state.validators().len() != LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT {
        return Err(PqDevnetStateError::InvalidValidatorCount {
            actual: state.validators().len(),
            expected: LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT,
        });
    }
    if state.eth1_data().deposit_root != Hash256::ZERO
        || state.eth1_data().deposit_count != 0
        || state.eth1_deposit_index() != 0
    {
        return Err(PqDevnetStateError::UnsupportedDepositState);
    }
    if !state
        .pending_deposits()
        .is_ok_and(|deposits| deposits.is_empty())
    {
        return Err(PqDevnetStateError::UnsupportedPendingDeposits);
    }
    if !state
        .pending_partial_withdrawals()
        .is_ok_and(|withdrawals| withdrawals.is_empty())
    {
        return Err(PqDevnetStateError::UnsupportedPendingPartialWithdrawals);
    }
    if !state
        .pending_consolidations()
        .is_ok_and(|consolidations| consolidations.is_empty())
    {
        return Err(PqDevnetStateError::UnsupportedPendingConsolidations);
    }
    Ok(())
}
