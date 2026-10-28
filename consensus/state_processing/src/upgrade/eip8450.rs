use milhouse::ProgressiveList;
use std::mem;
use types::{
    BeaconState, BeaconStateEip8450, BeaconStateError as Error, ChainSpec, EthSpec, Fork,
    PqPubkeyCache, PqPublicKeys,
};

/// Transform a `Heze` state into an `Eip8450` state.
pub fn upgrade_to_eip8450<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let post = upgrade_state_to_eip8450(pre_state, spec)?;

    *pre_state = post;

    Ok(())
}

pub fn upgrade_state_to_eip8450<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_heze_mut()?;
    let num_validators = pre.validators.len();

    // [New in EIP-8450] one unset registry entry per validator. `FAR_FUTURE_EPOCH` marks a
    // validator that has never registered.
    let pq_public_keys = ProgressiveList::try_from_iter(std::iter::repeat_n(
        PqPublicKeys::default(),
        num_validators,
    ))?;
    let pq_key_change_epochs =
        ProgressiveList::try_from_iter(std::iter::repeat_n(spec.far_future_epoch, num_validators))?;

    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Eip8450(BeaconStateEip8450 {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.eip8450_fork_version,
            epoch,
        },
        // History
        latest_block_header: pre.latest_block_header.clone(),
        block_roots: pre.block_roots.clone(),
        state_roots: pre.state_roots.clone(),
        historical_roots: mem::take(&mut pre.historical_roots),
        // Eth1
        eth1_data: pre.eth1_data.clone(),
        eth1_data_votes: mem::take(&mut pre.eth1_data_votes),
        eth1_deposit_index: pre.eth1_deposit_index,
        // Registry
        validators: mem::take(&mut pre.validators),
        balances: mem::take(&mut pre.balances),
        // Randomness
        randao_mixes: pre.randao_mixes.clone(),
        // Slashings
        slashings: pre.slashings.clone(),
        // Participation
        previous_epoch_participation: mem::take(&mut pre.previous_epoch_participation),
        current_epoch_participation: mem::take(&mut pre.current_epoch_participation),
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores: mem::take(&mut pre.inactivity_scores),
        // Sync committees
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        // Execution Bid
        latest_execution_payload_bid: pre.latest_execution_payload_bid.clone(),
        // Capella
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // Electra
        deposit_requests_start_index: pre.deposit_requests_start_index,
        deposit_balance_to_consume: pre.deposit_balance_to_consume,
        exit_balance_to_consume: pre.exit_balance_to_consume,
        earliest_exit_epoch: pre.earliest_exit_epoch,
        consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
        pending_deposits: pre.pending_deposits.clone(),
        pending_partial_withdrawals: pre.pending_partial_withdrawals.clone(),
        pending_consolidations: pre.pending_consolidations.clone(),
        proposer_lookahead: mem::take(&mut pre.proposer_lookahead),
        // Gloas
        builders: mem::take(&mut pre.builders),
        next_withdrawal_builder_index: pre.next_withdrawal_builder_index,
        execution_payload_availability: pre.execution_payload_availability.clone(),
        builder_pending_payments: pre.builder_pending_payments.clone(),
        builder_pending_withdrawals: mem::take(&mut pre.builder_pending_withdrawals),
        latest_block_hash: pre.latest_block_hash,
        payload_expected_withdrawals: mem::take(&mut pre.payload_expected_withdrawals),
        ptc_window: pre.ptc_window.clone(),
        // Eip8450
        pq_public_keys,
        pq_key_change_epochs,
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        // Every registry entry is unset, so no key is registered yet.
        pq_pubkey_cache: PqPubkeyCache::new_initialized(),
        exit_cache: mem::take(&mut pre.exit_cache),
        slashings_cache: mem::take(&mut pre.slashings_cache),
        epoch_cache: mem::take(&mut pre.epoch_cache),
    });

    Ok(post)
}
