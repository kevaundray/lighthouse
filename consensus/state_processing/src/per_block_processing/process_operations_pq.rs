use crate::ConsensusContext;
use crate::per_block_processing::{VerifySignatures, errors::BlockProcessingError};
use types::{AbstractExecPayload, BeaconBlockBodyRef, BeaconState, ChainSpec, EthSpec};

#[path = "process_operations/altair_deneb.rs"]
mod altair_deneb;

pub fn process_operations<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    block_body: BeaconBlockBodyRef<E, Payload>,
    verify_signatures: VerifySignatures,
    context: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    altair_deneb::process_attestations(
        state,
        block_body.attestations(),
        verify_signatures,
        context,
        spec,
    )
}
