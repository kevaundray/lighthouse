use types::{BeaconState, ChainSpec, EthSpec, ForkName, Hash256, Slot};

pub(crate) const LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT: usize = 16;

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
    let genesis_epoch = E::genesis_epoch();
    state.fork_name(spec) == Ok(ForkName::Electra)
        && state.fork_name_unchecked() == ForkName::Electra
        && spec.fork_name_at_slot::<E>(duty_slot) == ForkName::Electra
        && spec.altair_fork_epoch == Some(genesis_epoch)
        && spec.bellatrix_fork_epoch == Some(genesis_epoch)
        && spec.capella_fork_epoch == Some(genesis_epoch)
        && spec.deneb_fork_epoch == Some(genesis_epoch)
        && spec.electra_fork_epoch == Some(genesis_epoch)
        && !spec.is_fulu_scheduled()
        && !spec.is_gloas_scheduled()
        && state.validators().len() == LEAN_PQ_DEVNET_V1_VALIDATOR_COUNT
        && state.eth1_data().deposit_root == Hash256::ZERO
        && state.eth1_data().deposit_count == 0
        && state.eth1_deposit_index() == 0
        && state
            .pending_deposits()
            .is_ok_and(|deposits| deposits.is_empty())
        && state
            .pending_partial_withdrawals()
            .is_ok_and(|withdrawals| withdrawals.is_empty())
        && state
            .pending_consolidations()
            .is_ok_and(|consolidations| consolidations.is_empty())
}
