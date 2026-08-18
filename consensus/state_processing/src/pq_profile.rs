use types::{BeaconState, ChainSpec, EthSpec, ForkName, Slot};

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
        && state.eth1_data().deposit_count == 0
        && state.eth1_deposit_index() == 0
        && state
            .pending_deposits()
            .is_ok_and(|deposits| deposits.is_empty())
}
