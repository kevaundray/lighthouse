use crate::ConsensusContext;
use crate::common::{
    get_attestation_participation_flag_indices, increase_balance,
    update_progressive_balances_cache::update_progressive_balances_on_attestation,
};
use crate::per_block_processing::{
    VerifySignatures,
    errors::{BlockProcessingError, IntoWithIndex},
    verify_attestation_for_block_inclusion,
};
use safe_arith::SafeArith;
use types::consts::altair::{PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR};
use types::{AttestationRef, BeaconState, BeaconStateError, ChainSpec, EthSpec};

pub fn process_attestations<'a, E: EthSpec, I>(
    state: &mut BeaconState<E>,
    attestations: I,
    verify_signatures: VerifySignatures,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError>
where
    I: Iterator<Item = AttestationRef<'a, E>>,
{
    attestations.enumerate().try_for_each(|(i, attestation)| {
        process_attestation(state, attestation, i, ctxt, verify_signatures, spec)
    })
}

pub fn process_attestation<E: EthSpec>(
    state: &mut BeaconState<E>,
    attestation: AttestationRef<E>,
    att_index: usize,
    ctxt: &mut ConsensusContext<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let proposer_index = ctxt.get_proposer_index(state, spec)?;
    let previous_epoch = ctxt.previous_epoch;
    let current_epoch = ctxt.current_epoch;

    let indexed_att =
        verify_attestation_for_block_inclusion(state, attestation, ctxt, verify_signatures, spec)
            .map_err(|error| error.into_with_index(att_index))?;

    let data = attestation.data();
    let inclusion_delay = state.slot().safe_sub(data.slot)?.as_u64();
    let participation_flag_indices =
        get_attestation_participation_flag_indices(state, data, inclusion_delay, spec)?;

    let mut proposer_reward_numerator = 0u64;
    for index in indexed_att.attesting_indices_iter() {
        let index = *index as usize;
        let validator_effective_balance = state.epoch_cache().get_effective_balance(index)?;
        let validator_slashed = state.slashings_cache().is_slashed(index);

        for (flag_index, &weight) in PARTICIPATION_FLAG_WEIGHTS.iter().enumerate() {
            let epoch_participation = state.get_epoch_participation_mut(
                data.target.epoch,
                previous_epoch,
                current_epoch,
            )?;

            if participation_flag_indices.contains(&flag_index) {
                let validator_participation = epoch_participation
                    .get_mut(index)
                    .ok_or(BeaconStateError::ParticipationOutOfBounds(index))?;

                if !validator_participation.has_flag(flag_index)? {
                    validator_participation.add_flag(flag_index)?;
                    proposer_reward_numerator
                        .safe_add_assign(state.get_base_reward(index)?.safe_mul(weight)?)?;
                    update_progressive_balances_on_attestation(
                        state,
                        data.target.epoch,
                        flag_index,
                        validator_effective_balance,
                        validator_slashed,
                    )?;
                }
            }
        }
    }

    let proposer_reward_denominator = WEIGHT_DENOMINATOR
        .safe_sub(PROPOSER_WEIGHT)?
        .safe_mul(WEIGHT_DENOMINATOR)?
        .safe_div(PROPOSER_WEIGHT)?;
    let proposer_reward = proposer_reward_numerator.safe_div(proposer_reward_denominator)?;
    increase_balance(state, proposer_index as usize, proposer_reward)?;
    Ok(())
}
