//! Owned contextual verification transitions for the frozen PQ consensus profile.
//!
//! Prepared and verified tokens cannot be forged because their fields are private:
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
//! The verified aggregate's sealed inner evidence cannot be replaced downstream:
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
//! Local-production capabilities are sealed and cannot be forged or converted from an imported
//! block capability:
//!
//! ```compile_fail
//! use state_processing::{VerifiedPqBlock, VerifiedPqLocalBlock};
//! use types::MinimalEthSpec;
//!
//! fn reuse_imported(token: VerifiedPqBlock<MinimalEthSpec>) -> VerifiedPqLocalBlock<MinimalEthSpec> {
//!     token.into()
//! }
//! ```
//!
//! Local sealing accepts neither a caller-controlled outer signature nor a caller-controlled
//! cache or spec. The active empty outer proposal placeholder is installed only inside the
//! consuming transition:
//!
//! ```compile_fail
//! use state_processing::{VerifiedPqAttestation, VerifiedPqRandao, prepare_pq_local_block};
//! use std::sync::Arc;
//! use types::{BeaconState, ChainSpec, MinimalEthSpec, SignedBeaconBlock};
//!
//! fn bypass(
//!     state: &BeaconState<MinimalEthSpec>,
//!     signed_block: SignedBeaconBlock<MinimalEthSpec>,
//!     randao: VerifiedPqRandao<MinimalEthSpec>,
//!     attestations: Vec<Arc<VerifiedPqAttestation<MinimalEthSpec>>>,
//!     spec: &ChainSpec,
//! ) {
//!     prepare_pq_local_block(state, signed_block, randao, attestations, spec).unwrap();
//! }
//! ```

#[cfg(feature = "pq-transition")]
use crate::{
    ConsensusContext, ContextError, SignatureSetError,
    common::get_attestation_participation_flag_indices,
};
use crate::{
    PqAttestationError, PqAttestationInvalid, PqAttestationLocalError, PqValidatorKeyCache,
    PreparedPqAttestation, VerifiedPqAttestation,
    pq_attestation::{
        materialize_pq_attestation_verification_job, materialize_prepared_pq_attestation,
        preflight_pq_attestation_from_bits, preflight_pq_attestation_verification_job,
    },
    pq_profile::{is_lean_pq_devnet_v1, pq_pre_state_root},
};
use consensus_signature::{
    AggregationContribution, AggregationError, AggregationJob, AggregationService,
    AggregationSigner, OneTimeUseId, SameMessageClaim, SameMessageEvidence, SigningDuty,
    SigningIdError, VerificationClass,
};
#[cfg(feature = "pq-transition")]
use safe_arith::SafeArith;
use std::sync::Arc;
#[cfg(feature = "pq-transition")]
use types::{Attestation, AttestationRef, ParticipationFlags};
use types::{
    BeaconBlock, BeaconBlockRef, BeaconState, BeaconStateError, ChainSpec, Domain, EthSpec,
    ForkName, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
};

#[cfg(feature = "pq-transition")]
#[derive(Clone, Debug, PartialEq)]
pub enum PqBlockAttestationSelectionLocalError {
    State(BeaconStateError),
    SignatureSet(SignatureSetError),
    SszTypes(ssz_types::Error),
    Bitfield(ssz::BitfieldError),
    ConsensusContext(ContextError),
    Arithmetic(safe_arith::ArithError),
    Attestation(PqAttestationLocalError),
    SignerIndexOverflow(u64),
}

#[cfg(feature = "pq-transition")]
impl std::fmt::Display for PqBlockAttestationSelectionLocalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PQ block-attestation selection local error: {self:?}"
        )
    }
}

#[cfg(feature = "pq-transition")]
impl std::error::Error for PqBlockAttestationSelectionLocalError {}

#[cfg(feature = "pq-transition")]
#[derive(Clone, Debug, PartialEq)]
pub enum PqBlockAttestationSelectionError {
    Local(PqBlockAttestationSelectionLocalError),
}

#[cfg(feature = "pq-transition")]
impl std::fmt::Display for PqBlockAttestationSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ block-attestation selection failed: {self:?}")
    }
}

#[cfg(feature = "pq-transition")]
impl std::error::Error for PqBlockAttestationSelectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => Some(error),
        }
    }
}

/// Returns true when the authenticated signer set would gain at least one awarded participation
/// flag in the selected epoch's participation vector.
#[cfg(feature = "pq-transition")]
pub fn pq_signers_add_marginal_participation(
    signer_participation: &[ParticipationFlags],
    awarded_flags: &[usize],
) -> Result<bool, PqBlockAttestationSelectionLocalError> {
    for participation in signer_participation {
        for flag_index in awarded_flags {
            if !participation
                .has_flag(*flag_index)
                .map_err(PqBlockAttestationSelectionLocalError::Arithmetic)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqConsensusComponent {
    BlockProposal,
    RandaoReveal,
    BlockAttestation(usize),
    SelectionProof,
    AggregateAttestation,
    AggregateAndProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqConsensusInvalid {
    InconsistentBlockFork,
    BaseAggregateAndProof,
    ProposalSlotOutOfCurrentEpoch {
        proposal: u64,
        current: u64,
    },
    IncorrectBlockProposer {
        block: u64,
        expected: u64,
    },
    InvalidValidatorIndex(u64),
    AggregatorNotInCommittee(u64),
    AggregatorNotSelected(u64),
    InvalidAttestation {
        component: PqConsensusComponent,
        error: PqAttestationInvalid,
    },
    InvalidEvidence(PqConsensusComponent),
    UnsupportedBlock(PqUnsupportedBlock),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqUnsupportedBlock {
    StateSlotMismatch { state: Slot, block: Slot },
    Deposits,
    DepositRequests,
    ProposerSlashings,
    AttesterSlashings,
    VoluntaryExits,
    BlsToExecutionChanges,
    WithdrawalRequests,
    ConsolidationRequests,
    BlobKzgCommitments,
    Eth1DataChanged,
    SyncCommitteeParticipants,
    SyncCommitteeEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqConsensusLocalError {
    UnsupportedProfile,
    StateUnavailable,
    CacheInvariant,
    SigningId(SigningIdError),
    Attestation(PqAttestationLocalError),
    Aggregation(AggregationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqConsensusError {
    Invalid(PqConsensusInvalid),
    Local(PqConsensusLocalError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqLocalBlockInvalid {
    NonZeroStateRoot,
    SlotMismatch { block: Slot, randao: Slot },
    ProposerMismatch { block: u64, randao: u64 },
    RandaoMismatch,
    AttestationCountMismatch { block: usize, tokens: usize },
    AttestationBytesMismatch(usize),
    AttestationSignerMismatch(usize),
    AttestationClaimMismatch(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqLocalBlockError {
    PreStateMismatch {
        expected: types::Hash256,
        actual: types::Hash256,
    },
    Invalid(PqLocalBlockInvalid),
    Consensus(PqConsensusError),
}

impl std::fmt::Display for PqLocalBlockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ local block sealing failed: {self:?}")
    }
}

impl std::error::Error for PqLocalBlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Consensus(error) => Some(error),
            Self::PreStateMismatch { .. } | Self::Invalid(_) => None,
        }
    }
}

impl std::fmt::Display for PqConsensusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ consensus verification failed: {self:?}")
    }
}

impl std::error::Error for PqConsensusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(PqConsensusLocalError::SigningId(error)) => Some(error),
            Self::Local(PqConsensusLocalError::Aggregation(error)) => Some(error),
            Self::Local(PqConsensusLocalError::Attestation(
                PqAttestationLocalError::SigningId(error),
            )) => Some(error),
            Self::Local(PqConsensusLocalError::Attestation(
                PqAttestationLocalError::Aggregation(error),
            )) => Some(error),
            Self::Invalid(_)
            | Self::Local(
                PqConsensusLocalError::UnsupportedProfile
                | PqConsensusLocalError::StateUnavailable
                | PqConsensusLocalError::CacheInvariant
                | PqConsensusLocalError::Attestation(
                    PqAttestationLocalError::UnsupportedProfile
                    | PqAttestationLocalError::CommitteeCacheUnavailable
                    | PqAttestationLocalError::CacheInvariant,
                ),
            ) => None,
        }
    }
}

pub struct PreparedPqBlockProposal<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    job: AggregationJob,
}

pub struct VerifiedPqBlockProposal<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
}

pub struct PreparedPqBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    pre_state_root: types::Hash256,
    spec: Arc<ChainSpec>,
    proposal_job: AggregationJob,
    randao_job: AggregationJob,
    attestation_jobs: Vec<AggregationJob>,
}

pub struct VerifiedPqBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    pre_state_root: types::Hash256,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    spec: Arc<ChainSpec>,
}

pub struct PreparedPqRandao<E: EthSpec> {
    pre_state_root: types::Hash256,
    spec: Arc<ChainSpec>,
    key_cache: Arc<PqValidatorKeyCache>,
    slot: Slot,
    proposer_index: u64,
    signature: consensus_signature::IndividualSignature,
    job: AggregationJob,
    _eth_spec: std::marker::PhantomData<E>,
}

pub struct VerifiedPqRandao<E: EthSpec> {
    pre_state_root: types::Hash256,
    spec: Arc<ChainSpec>,
    key_cache: Arc<PqValidatorKeyCache>,
    slot: Slot,
    proposer_index: u64,
    signature: consensus_signature::IndividualSignature,
    _eth_spec: std::marker::PhantomData<E>,
}

pub struct VerifiedPqLocalBlock<E: EthSpec> {
    block: BeaconBlock<E>,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    pre_state_root: types::Hash256,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    spec: Arc<ChainSpec>,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    randao: VerifiedPqRandao<E>,
    #[cfg_attr(not(feature = "pq-transition"), allow(dead_code))]
    attestations: Vec<Arc<VerifiedPqAttestation<E>>>,
}

pub struct PreparedPqAggregateAndProof<E: EthSpec> {
    aggregate: Arc<SignedAggregateAndProof<E>>,
    selection_job: AggregationJob,
    inner_attestation: PreparedPqAttestation<E>,
    outer_job: AggregationJob,
}

pub struct VerifiedPqAggregateAndProof<E: EthSpec> {
    aggregate: Arc<SignedAggregateAndProof<E>>,
    inner_attestation: VerifiedPqAttestation<E>,
}

impl<E: EthSpec> PreparedPqBlockProposal<E> {
    pub const fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub async fn verify(
        self,
        service: &AggregationService,
    ) -> Result<VerifiedPqBlockProposal<E>, PqConsensusError> {
        verify_component_job(
            service,
            VerificationClass::Gossip,
            self.job,
            PqConsensusComponent::BlockProposal,
        )
        .await?;
        Ok(VerifiedPqBlockProposal { block: self.block })
    }
}

impl<E: EthSpec> VerifiedPqBlockProposal<E> {
    pub const fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub fn into_block(self) -> Arc<SignedBeaconBlock<E>> {
        self.block
    }
}

impl<E: EthSpec> PreparedPqBlock<E> {
    pub const fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub async fn verify(
        self,
        service: &AggregationService,
    ) -> Result<VerifiedPqBlock<E>, PqConsensusError> {
        verify_component_job(
            service,
            VerificationClass::Block,
            self.proposal_job,
            PqConsensusComponent::BlockProposal,
        )
        .await?;
        verify_component_job(
            service,
            VerificationClass::Block,
            self.randao_job,
            PqConsensusComponent::RandaoReveal,
        )
        .await?;
        for (position, job) in self.attestation_jobs.into_iter().enumerate() {
            verify_component_job(
                service,
                VerificationClass::Block,
                job,
                PqConsensusComponent::BlockAttestation(position),
            )
            .await?;
        }
        Ok(VerifiedPqBlock {
            block: self.block,
            pre_state_root: self.pre_state_root,
            spec: self.spec,
        })
    }
}

impl<E: EthSpec> VerifiedPqBlock<E> {
    pub const fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub fn into_block(self) -> Arc<SignedBeaconBlock<E>> {
        self.block
    }

    #[cfg(feature = "pq-transition")]
    pub(crate) fn into_transition_parts(
        self,
    ) -> (Arc<SignedBeaconBlock<E>>, types::Hash256, Arc<ChainSpec>) {
        (self.block, self.pre_state_root, self.spec)
    }
}

impl<E: EthSpec> PreparedPqRandao<E> {
    pub async fn verify(
        self,
        service: &AggregationService,
    ) -> Result<VerifiedPqRandao<E>, PqConsensusError> {
        verify_component_job(
            service,
            VerificationClass::Block,
            self.job,
            PqConsensusComponent::RandaoReveal,
        )
        .await?;
        Ok(VerifiedPqRandao {
            pre_state_root: self.pre_state_root,
            spec: self.spec,
            key_cache: self.key_cache,
            slot: self.slot,
            proposer_index: self.proposer_index,
            signature: self.signature,
            _eth_spec: std::marker::PhantomData,
        })
    }
}

impl<E: EthSpec> VerifiedPqLocalBlock<E> {
    pub const fn block(&self) -> &BeaconBlock<E> {
        &self.block
    }

    #[cfg(feature = "pq-transition")]
    pub(crate) fn into_transition_parts(self) -> (BeaconBlock<E>, types::Hash256, Arc<ChainSpec>) {
        let Self {
            block,
            pre_state_root,
            spec,
            randao: _verified_randao,
            attestations: _verified_attestations,
        } = self;
        (block, pre_state_root, spec)
    }
}

pub fn prepare_pq_randao<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: Arc<PqValidatorKeyCache>,
    slot: Slot,
    signature: consensus_signature::IndividualSignature,
    spec: Arc<ChainSpec>,
) -> Result<PreparedPqRandao<E>, PqConsensusError> {
    let mut evidence_work = 0;
    prepare_pq_randao_inner(state, key_cache, slot, signature, spec, &mut evidence_work)
}

#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub fn prepare_pq_randao_with_evidence_work_count<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: Arc<PqValidatorKeyCache>,
    slot: Slot,
    signature: consensus_signature::IndividualSignature,
    spec: Arc<ChainSpec>,
    evidence_work: &mut usize,
) -> Result<PreparedPqRandao<E>, PqConsensusError> {
    prepare_pq_randao_inner(state, key_cache, slot, signature, spec, evidence_work)
}

fn prepare_pq_randao_inner<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: Arc<PqValidatorKeyCache>,
    slot: Slot,
    signature: consensus_signature::IndividualSignature,
    spec: Arc<ChainSpec>,
    evidence_work: &mut usize,
) -> Result<PreparedPqRandao<E>, PqConsensusError> {
    validate_v1_profile(state, &spec, slot)?;
    if state.slot() != slot {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::UnsupportedBlock(PqUnsupportedBlock::StateSlotMismatch {
                state: state.slot(),
                block: slot,
            }),
        ));
    }
    let proposer_index = state
        .get_beacon_proposer_index(slot, &spec)
        .map_err(classify_state_error)
        .and_then(|index| {
            u64::try_from(index)
                .map_err(|_| PqConsensusError::Local(PqConsensusLocalError::StateUnavailable))
        })?;
    let randao_domain = spec.get_domain(
        slot.epoch(E::slots_per_epoch()),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let randao_id =
        OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), SigningDuty::RandaoReveal)
            .map_err(|error| PqConsensusError::Local(PqConsensusLocalError::SigningId(error)))?;
    let preflight = preflight_individual(
        state,
        &key_cache,
        proposer_index,
        slot.epoch(E::slots_per_epoch())
            .signing_root(randao_domain)
            .0,
        randao_id,
    )?;
    let pre_state_root = pq_pre_state_root(state)
        .map_err(|_| PqConsensusError::Local(PqConsensusLocalError::StateUnavailable))?;
    let job = materialize_individual_job(preflight, &signature, evidence_work);
    Ok(PreparedPqRandao {
        pre_state_root,
        spec,
        key_cache,
        slot,
        proposer_index,
        signature,
        job,
        _eth_spec: std::marker::PhantomData,
    })
}

/// Revalidates one sealed, previously authenticated candidate against the exact block pre-state.
///
/// Consensus-invalid candidates and candidates sealed against a different state context are
/// reported as `Ok(false)` so a proposer can skip them. Local state/cache failures abort
/// selection.
#[cfg(feature = "pq-transition")]
pub fn validate_pq_attestation_for_block_selection<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    candidate: &VerifiedPqAttestation<E>,
    spec: &ChainSpec,
) -> Result<bool, PqBlockAttestationSelectionError> {
    use crate::per_block_processing::{
        VerifySignatures, errors::BlockOperationError, verify_attestation_for_block_inclusion,
    };

    let attestation = match candidate.attestation() {
        Attestation::Base(attestation) => AttestationRef::Base(attestation),
        Attestation::Electra(attestation) => AttestationRef::Electra(attestation),
    };
    let preflight =
        match preflight_pq_attestation_verification_job(state, key_cache, attestation, spec) {
            Ok(preflight) => preflight,
            Err(PqAttestationError::Invalid(_)) => return Ok(false),
            Err(PqAttestationError::Local(error)) => {
                return Err(PqBlockAttestationSelectionError::Local(
                    PqBlockAttestationSelectionLocalError::Attestation(error),
                ));
            }
        };
    if preflight.signer_indices() != candidate.signer_indices()
        || preflight.signers() != candidate.signers()
        || preflight.claim() != candidate.claim()
    {
        return Ok(false);
    }
    let mut context = ConsensusContext::new(state.slot());
    match verify_attestation_for_block_inclusion(
        state,
        attestation,
        &mut context,
        VerifySignatures::False,
        spec,
    ) {
        Ok(_) => {}
        Err(BlockOperationError::Invalid(_)) => return Ok(false),
        Err(BlockOperationError::BeaconStateError(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::State(error),
            ));
        }
        Err(BlockOperationError::SignatureSetError(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::SignatureSet(error),
            ));
        }
        Err(BlockOperationError::SszTypesError(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::SszTypes(error),
            ));
        }
        Err(BlockOperationError::BitfieldError(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::Bitfield(error),
            ));
        }
        Err(BlockOperationError::ConsensusContext(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::ConsensusContext(error),
            ));
        }
        Err(BlockOperationError::ArithError(error)) => {
            return Err(PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::Arithmetic(error),
            ));
        }
    }
    let data = attestation.data();
    let inclusion_delay = state
        .slot()
        .safe_sub(data.slot)
        .map_err(|error| {
            PqBlockAttestationSelectionError::Local(
                PqBlockAttestationSelectionLocalError::Arithmetic(error),
            )
        })?
        .as_u64();
    let awarded_flags =
        get_attestation_participation_flag_indices(state, data, inclusion_delay, spec).map_err(
            |error| {
                PqBlockAttestationSelectionError::Local(
                    PqBlockAttestationSelectionLocalError::State(error),
                )
            },
        )?;
    let epoch_participation = if data.target.epoch == state.current_epoch() {
        state.current_epoch_participation()
    } else if data.target.epoch == state.previous_epoch() {
        state.previous_epoch_participation()
    } else {
        return Ok(false);
    }
    .map_err(|error| {
        PqBlockAttestationSelectionError::Local(PqBlockAttestationSelectionLocalError::State(error))
    })?;
    let signer_participation = candidate
        .signer_indices()
        .iter()
        .map(|signer_index| {
            let signer_position = usize::try_from(*signer_index).map_err(|_| {
                PqBlockAttestationSelectionLocalError::SignerIndexOverflow(*signer_index)
            })?;
            epoch_participation.get(signer_position).copied().ok_or(
                PqBlockAttestationSelectionLocalError::State(
                    BeaconStateError::ParticipationOutOfBounds(signer_position),
                ),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(PqBlockAttestationSelectionError::Local)?;
    pq_signers_add_marginal_participation(&signer_participation, &awarded_flags)
        .map_err(PqBlockAttestationSelectionError::Local)
}

pub fn prepare_pq_local_block<E: EthSpec>(
    state: &BeaconState<E>,
    block: BeaconBlock<E>,
    randao: VerifiedPqRandao<E>,
    attestations: Vec<Arc<VerifiedPqAttestation<E>>>,
) -> Result<VerifiedPqLocalBlock<E>, PqLocalBlockError> {
    preflight_pq_local_block(state, &block, &randao, &attestations)?;
    Ok(VerifiedPqLocalBlock {
        block,
        pre_state_root: randao.pre_state_root,
        spec: Arc::clone(&randao.spec),
        randao,
        attestations,
    })
}

#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub fn preflight_pq_local_block_with_sealing_work_count<E: EthSpec>(
    state: &BeaconState<E>,
    block: &BeaconBlock<E>,
    randao: &VerifiedPqRandao<E>,
    attestations: &[Arc<VerifiedPqAttestation<E>>],
    sealing_work: &mut usize,
) -> Result<(), PqLocalBlockError> {
    preflight_pq_local_block(state, block, randao, attestations)?;
    *sealing_work = sealing_work.saturating_add(1);
    Ok(())
}

fn preflight_pq_local_block<E: EthSpec>(
    state: &BeaconState<E>,
    block: &BeaconBlock<E>,
    randao: &VerifiedPqRandao<E>,
    attestations: &[Arc<VerifiedPqAttestation<E>>],
) -> Result<(), PqLocalBlockError> {
    let actual_pre_state_root = pq_pre_state_root(state).map_err(|_| {
        PqLocalBlockError::Consensus(PqConsensusError::Local(
            PqConsensusLocalError::StateUnavailable,
        ))
    })?;
    if actual_pre_state_root != randao.pre_state_root {
        return Err(PqLocalBlockError::PreStateMismatch {
            expected: randao.pre_state_root,
            actual: actual_pre_state_root,
        });
    }
    if block.state_root() != types::Hash256::ZERO {
        return Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::NonZeroStateRoot,
        ));
    }
    if block.slot() != randao.slot {
        return Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::SlotMismatch {
                block: block.slot(),
                randao: randao.slot,
            },
        ));
    }
    if block.proposer_index() != randao.proposer_index {
        return Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::ProposerMismatch {
                block: block.proposer_index(),
                randao: randao.proposer_index,
            },
        ));
    }
    if block.body().randao_reveal() != &randao.signature {
        return Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::RandaoMismatch,
        ));
    }
    preflight_pq_transition_block_message(state, block.to_ref(), &randao.spec)
        .map_err(PqLocalBlockError::Consensus)?;

    let block_attestation_count = block.body().attestations_len();
    if block_attestation_count != attestations.len() {
        return Err(PqLocalBlockError::Invalid(
            PqLocalBlockInvalid::AttestationCountMismatch {
                block: block_attestation_count,
                tokens: attestations.len(),
            },
        ));
    }
    for (position, (block_attestation, token)) in block
        .body()
        .attestations()
        .zip(attestations.iter())
        .enumerate()
    {
        let bytes_match = match (block_attestation, token.attestation()) {
            (types::AttestationRef::Base(left), types::Attestation::Base(right)) => left == right,
            (types::AttestationRef::Electra(left), types::Attestation::Electra(right)) => {
                left == right
            }
            _ => false,
        };
        if !bytes_match {
            return Err(PqLocalBlockError::Invalid(
                PqLocalBlockInvalid::AttestationBytesMismatch(position),
            ));
        }
        let preflight = preflight_pq_attestation_verification_job(
            state,
            &randao.key_cache,
            block_attestation,
            &randao.spec,
        )
        .map_err(|error| {
            PqLocalBlockError::Consensus(map_attestation_error(
                PqConsensusComponent::BlockAttestation(position),
                error,
            ))
        })?;
        if preflight.signer_indices() != token.signer_indices()
            || preflight.signers() != token.signers()
        {
            return Err(PqLocalBlockError::Invalid(
                PqLocalBlockInvalid::AttestationSignerMismatch(position),
            ));
        }
        if preflight.claim() != token.claim() {
            return Err(PqLocalBlockError::Invalid(
                PqLocalBlockInvalid::AttestationClaimMismatch(position),
            ));
        }
    }
    Ok(())
}

impl<E: EthSpec> PreparedPqAggregateAndProof<E> {
    pub const fn aggregate(&self) -> &Arc<SignedAggregateAndProof<E>> {
        &self.aggregate
    }

    pub async fn verify(
        self,
        service: &AggregationService,
    ) -> Result<VerifiedPqAggregateAndProof<E>, PqConsensusError> {
        verify_component_job(
            service,
            VerificationClass::Gossip,
            self.selection_job,
            PqConsensusComponent::SelectionProof,
        )
        .await?;
        let inner_attestation = self
            .inner_attestation
            .verify(service, VerificationClass::Gossip)
            .await
            .map_err(|error| {
                map_attestation_error(PqConsensusComponent::AggregateAttestation, error)
            })?;
        verify_component_job(
            service,
            VerificationClass::Gossip,
            self.outer_job,
            PqConsensusComponent::AggregateAndProof,
        )
        .await?;
        Ok(VerifiedPqAggregateAndProof {
            aggregate: self.aggregate,
            inner_attestation,
        })
    }
}

impl<E: EthSpec> VerifiedPqAggregateAndProof<E> {
    pub const fn aggregate(&self) -> &Arc<SignedAggregateAndProof<E>> {
        &self.aggregate
    }

    pub const fn inner_attestation(&self) -> &VerifiedPqAttestation<E> {
        &self.inner_attestation
    }

    pub fn into_aggregate(self) -> Arc<SignedAggregateAndProof<E>> {
        self.aggregate
    }

    /// Consumes the sealed aggregate while preserving both its exact outer wire object and the
    /// authenticated inner attestation for the downstream coordinator.
    pub fn into_parts(self) -> (Arc<SignedAggregateAndProof<E>>, VerifiedPqAttestation<E>) {
        (self.aggregate, self.inner_attestation)
    }
}

pub fn prepare_pq_block_proposal<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    block: Arc<SignedBeaconBlock<E>>,
    spec: &ChainSpec,
) -> Result<PreparedPqBlockProposal<E>, PqConsensusError> {
    let structural = preflight_proposal_structure(state, key_cache, &block, spec)?;
    let mut evidence_work = 0usize;
    evidence_work = evidence_work.saturating_add(1);
    let preflight = finish_proposal_preflight(structural, &block);
    let job = materialize_individual_job(preflight, block.signature(), &mut evidence_work);
    Ok(PreparedPqBlockProposal { block, job })
}

pub fn prepare_pq_block<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    block: Arc<SignedBeaconBlock<E>>,
    spec: &ChainSpec,
) -> Result<PreparedPqBlock<E>, PqConsensusError> {
    let mut evidence_work = 0;
    prepare_pq_block_inner(state, key_cache, block, spec, &mut evidence_work)
}

#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub fn prepare_pq_block_with_evidence_work_count<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    block: Arc<SignedBeaconBlock<E>>,
    spec: &ChainSpec,
    evidence_work: &mut usize,
) -> Result<PreparedPqBlock<E>, PqConsensusError> {
    prepare_pq_block_inner(state, key_cache, block, spec, evidence_work)
}

fn prepare_pq_block_inner<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    block: Arc<SignedBeaconBlock<E>>,
    spec: &ChainSpec,
    evidence_work: &mut usize,
) -> Result<PreparedPqBlock<E>, PqConsensusError> {
    preflight_pq_transition_block(state, &block, spec)?;
    let proposal_structure = preflight_proposal_structure(state, key_cache, &block, spec)?;
    let proposer_index = block.message().proposer_index();
    let randao_domain = spec.get_domain(
        block.epoch(),
        Domain::Randao,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let randao_id =
        OneTimeUseId::for_lean_pq_devnet_v1(block.slot().as_u64(), SigningDuty::RandaoReveal)
            .map_err(|error| PqConsensusError::Local(PqConsensusLocalError::SigningId(error)))?;
    let randao_preflight = preflight_individual(
        state,
        key_cache,
        proposer_index,
        block.epoch().signing_root(randao_domain).0,
        randao_id,
    )?;
    let mut attestation_preflights = Vec::with_capacity(block.message().body().attestations_len());
    for (position, attestation) in block.message().body().attestations().enumerate() {
        let preflight =
            preflight_pq_attestation_verification_job(state, key_cache, attestation, spec)
                .map_err(|error| {
                    map_attestation_error(PqConsensusComponent::BlockAttestation(position), error)
                })?;
        attestation_preflights.push(preflight);
    }

    // Bind the capability to the exact claim-producing state only after all hostile block
    // structure has passed preflight, but before any evidence is copied or backend work exists.
    let pre_state_root = pq_pre_state_root(state)
        .map_err(|_| PqConsensusError::Local(PqConsensusLocalError::StateUnavailable))?;

    // The proposal claim tree-hashes the complete block, including every attestation, only after
    // every attacker-controlled included attestation has passed structural preflight.
    *evidence_work = evidence_work.saturating_add(1);
    let proposal_preflight = finish_proposal_preflight(proposal_structure, &block);
    let proposal_job =
        materialize_individual_job(proposal_preflight, block.signature(), evidence_work);
    let randao_job = materialize_individual_job(
        randao_preflight,
        block.message().body().randao_reveal(),
        evidence_work,
    );
    let mut attestation_jobs = Vec::with_capacity(attestation_preflights.len());
    for (position, (attestation, preflight)) in block
        .message()
        .body()
        .attestations()
        .zip(attestation_preflights)
        .enumerate()
    {
        let job =
            materialize_pq_attestation_verification_job(attestation, &preflight, evidence_work)
                .map_err(|error| {
                    map_attestation_error(PqConsensusComponent::BlockAttestation(position), error)
                })?;
        attestation_jobs.push(job);
    }
    Ok(PreparedPqBlock {
        block,
        pre_state_root,
        spec: Arc::new(spec.clone()),
        proposal_job,
        randao_job,
        attestation_jobs,
    })
}

pub(crate) fn preflight_pq_transition_block<E: EthSpec>(
    state: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    spec: &ChainSpec,
) -> Result<(), PqConsensusError> {
    preflight_pq_transition_block_message(state, block.message(), spec)
}

fn preflight_pq_transition_block_message<E: EthSpec>(
    state: &BeaconState<E>,
    block: BeaconBlockRef<'_, E>,
    spec: &ChainSpec,
) -> Result<(), PqConsensusError> {
    validate_v1_profile(state, spec, block.slot())?;
    if state.slot() != block.slot() {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::UnsupportedBlock(PqUnsupportedBlock::StateSlotMismatch {
                state: state.slot(),
                block: block.slot(),
            }),
        ));
    }

    let types::BeaconBlockRef::Electra(electra) = block else {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InconsistentBlockFork,
        ));
    };
    let body = &electra.body;
    let unsupported = if !body.deposits.is_empty() {
        Some(PqUnsupportedBlock::Deposits)
    } else if !body.execution_requests.deposits.is_empty() {
        Some(PqUnsupportedBlock::DepositRequests)
    } else if !body.proposer_slashings.is_empty() {
        Some(PqUnsupportedBlock::ProposerSlashings)
    } else if !body.attester_slashings.is_empty() {
        Some(PqUnsupportedBlock::AttesterSlashings)
    } else if !body.voluntary_exits.is_empty() {
        Some(PqUnsupportedBlock::VoluntaryExits)
    } else if !body.bls_to_execution_changes.is_empty() {
        Some(PqUnsupportedBlock::BlsToExecutionChanges)
    } else if !body.execution_requests.withdrawals.is_empty() {
        Some(PqUnsupportedBlock::WithdrawalRequests)
    } else if !body.execution_requests.consolidations.is_empty() {
        Some(PqUnsupportedBlock::ConsolidationRequests)
    } else if !body.blob_kzg_commitments.is_empty() {
        Some(PqUnsupportedBlock::BlobKzgCommitments)
    } else if body.eth1_data != *state.eth1_data() || body.eth1_data.deposit_count != 0 {
        Some(PqUnsupportedBlock::Eth1DataChanged)
    } else if body.sync_aggregate.sync_committee_bits.num_set_bits() != 0 {
        Some(PqUnsupportedBlock::SyncCommitteeParticipants)
    } else if !body.sync_aggregate.sync_committee_signature.is_empty() {
        Some(PqUnsupportedBlock::SyncCommitteeEvidence)
    } else {
        None
    };

    if let Some(unsupported) = unsupported {
        Err(PqConsensusError::Invalid(
            PqConsensusInvalid::UnsupportedBlock(unsupported),
        ))
    } else {
        Ok(())
    }
}

pub fn prepare_pq_aggregate_and_proof<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    aggregate: SignedAggregateAndProof<E>,
    spec: &ChainSpec,
) -> Result<PreparedPqAggregateAndProof<E>, PqConsensusError> {
    let mut evidence_work = 0;
    prepare_pq_aggregate_and_proof_inner(state, key_cache, aggregate, spec, &mut evidence_work)
}

#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub fn prepare_pq_aggregate_and_proof_with_evidence_work_count<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    aggregate: SignedAggregateAndProof<E>,
    spec: &ChainSpec,
    evidence_work: &mut usize,
) -> Result<PreparedPqAggregateAndProof<E>, PqConsensusError> {
    prepare_pq_aggregate_and_proof_inner(state, key_cache, aggregate, spec, evidence_work)
}

fn prepare_pq_aggregate_and_proof_inner<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    aggregate: SignedAggregateAndProof<E>,
    spec: &ChainSpec,
    evidence_work: &mut usize,
) -> Result<PreparedPqAggregateAndProof<E>, PqConsensusError> {
    if !matches!(&aggregate, SignedAggregateAndProof::Electra(_)) {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::BaseAggregateAndProof,
        ));
    }
    let aggregate_ref = aggregate.message();
    let inner_ref = aggregate_ref.aggregate();
    let slot = inner_ref.data().slot;
    validate_v1_profile(state, spec, slot)?;
    let aggregator_index = aggregate_ref.aggregator_index();
    let committee_index = inner_ref
        .committee_index()
        .ok_or(PqConsensusError::Invalid(
            PqConsensusInvalid::BaseAggregateAndProof,
        ))?;
    let committee = state
        .get_beacon_committee(slot, committee_index)
        .map_err(classify_aggregate_committee_error)?;
    let aggregator_position = usize::try_from(aggregator_index).map_err(|_| {
        PqConsensusError::Invalid(PqConsensusInvalid::InvalidValidatorIndex(aggregator_index))
    })?;
    if !committee.committee.contains(&aggregator_position) {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::AggregatorNotInCommittee(aggregator_index),
        ));
    }
    let selection_domain = spec.get_domain(
        slot.epoch(E::slots_per_epoch()),
        Domain::SelectionProof,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let selection_id =
        OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), SigningDuty::AttestationSelectionProof)
            .map_err(|error| PqConsensusError::Local(PqConsensusLocalError::SigningId(error)))?;
    let selection_preflight = preflight_individual(
        state,
        key_cache,
        aggregator_index,
        slot.signing_root(selection_domain).0,
        selection_id,
    )?;

    let inner_preflight = preflight_pq_attestation_from_bits(state, key_cache, inner_ref, spec)
        .map_err(|error| {
            map_attestation_error(PqConsensusComponent::AggregateAttestation, error)
        })?;

    let outer_domain = spec.get_domain(
        slot.epoch(E::slots_per_epoch()),
        Domain::AggregateAndProof,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let outer_id =
        OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), SigningDuty::AggregateAndProof)
            .map_err(|error| PqConsensusError::Local(PqConsensusLocalError::SigningId(error)))?;
    let outer_signer = preflight_individual_signer(state, key_cache, aggregator_index)?;

    // `BeaconState::is_aggregator` hashes an owned SSZ serialization of the borrowed selection
    // proof, so the test seam counts that transient evidence copy as evidence work too.
    *evidence_work = evidence_work.saturating_add(1);
    let selected = state
        .is_aggregator(slot, committee_index, aggregate_ref.selection_proof(), spec)
        .map_err(|_| PqConsensusError::Local(PqConsensusLocalError::StateUnavailable))?;
    if !selected {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::AggregatorNotSelected(aggregator_index),
        ));
    }

    // The outer claim tree-hashes the complete aggregate-and-proof message only after selection
    // eligibility has succeeded.
    *evidence_work = evidence_work.saturating_add(1);
    let outer_preflight = finish_individual_preflight(
        outer_signer,
        aggregate_ref.signing_root(outer_domain).0,
        outer_id,
    );
    let selection_job = materialize_individual_job(
        selection_preflight,
        aggregate_ref.selection_proof(),
        evidence_work,
    );
    let inner_attestation =
        materialize_prepared_pq_attestation(inner_ref, inner_preflight, evidence_work).map_err(
            |error| map_attestation_error(PqConsensusComponent::AggregateAttestation, error),
        )?;
    let outer_job =
        materialize_individual_job(outer_preflight, aggregate.signature(), evidence_work);
    let aggregate = Arc::new(aggregate);
    Ok(PreparedPqAggregateAndProof {
        aggregate,
        selection_job,
        inner_attestation,
        outer_job,
    })
}

struct IndividualPreflight {
    claim: SameMessageClaim,
    signer: AggregationSigner,
}

struct IndividualSignerPreflight {
    signer: AggregationSigner,
}

struct ProposalPreflight {
    signer: IndividualSignerPreflight,
    domain: types::Hash256,
    one_time_use_id: OneTimeUseId,
}

fn preflight_proposal_structure<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    block: &SignedBeaconBlock<E>,
    spec: &ChainSpec,
) -> Result<ProposalPreflight, PqConsensusError> {
    validate_v1_profile(state, spec, block.slot())?;
    if block.fork_name(spec) != Ok(ForkName::Electra) {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::InconsistentBlockFork,
        ));
    }
    let proposal_epoch = block.epoch();
    let current_epoch = state.current_epoch();
    if proposal_epoch != current_epoch {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::ProposalSlotOutOfCurrentEpoch {
                proposal: proposal_epoch.as_u64(),
                current: current_epoch.as_u64(),
            },
        ));
    }
    let expected = state
        .get_beacon_proposer_index(block.slot(), spec)
        .map_err(classify_state_error)
        .and_then(|index| {
            u64::try_from(index)
                .map_err(|_| PqConsensusError::Local(PqConsensusLocalError::StateUnavailable))
        })?;
    let actual = block.message().proposer_index();
    if actual != expected {
        return Err(PqConsensusError::Invalid(
            PqConsensusInvalid::IncorrectBlockProposer {
                block: actual,
                expected,
            },
        ));
    }
    let domain = spec.get_domain(
        block.epoch(),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let one_time_use_id = OneTimeUseId::for_lean_pq_devnet_v1(
        block.slot().as_u64(),
        SigningDuty::BeaconBlockProposal,
    )
    .map_err(|error| PqConsensusError::Local(PqConsensusLocalError::SigningId(error)))?;
    let signer = preflight_individual_signer(state, key_cache, actual)?;
    Ok(ProposalPreflight {
        signer,
        domain,
        one_time_use_id,
    })
}

fn finish_proposal_preflight<E: EthSpec>(
    preflight: ProposalPreflight,
    block: &SignedBeaconBlock<E>,
) -> IndividualPreflight {
    IndividualPreflight {
        claim: SameMessageClaim::new(
            block.message().signing_root(preflight.domain).0,
            preflight.one_time_use_id,
        ),
        signer: preflight.signer.signer,
    }
}

fn preflight_individual<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    validator_index: u64,
    signing_root: [u8; 32],
    one_time_use_id: OneTimeUseId,
) -> Result<IndividualPreflight, PqConsensusError> {
    let preflight = preflight_individual_signer(state, key_cache, validator_index)?;
    Ok(finish_individual_preflight(
        preflight,
        signing_root,
        one_time_use_id,
    ))
}

fn finish_individual_preflight(
    preflight: IndividualSignerPreflight,
    signing_root: [u8; 32],
    one_time_use_id: OneTimeUseId,
) -> IndividualPreflight {
    IndividualPreflight {
        claim: SameMessageClaim::new(signing_root, one_time_use_id),
        signer: preflight.signer,
    }
}

fn preflight_individual_signer<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    validator_index: u64,
) -> Result<IndividualSignerPreflight, PqConsensusError> {
    let validator_position = usize::try_from(validator_index).map_err(|_| {
        PqConsensusError::Invalid(PqConsensusInvalid::InvalidValidatorIndex(validator_index))
    })?;
    let validator = state
        .validators()
        .get(validator_position)
        .ok_or(PqConsensusError::Invalid(
            PqConsensusInvalid::InvalidValidatorIndex(validator_index),
        ))?;
    let public_key = key_cache
        .get(validator_index)
        .ok_or(PqConsensusError::Local(
            PqConsensusLocalError::CacheInvariant,
        ))?;
    if key_cache.len() != state.validators().len() || public_key != &validator.pubkey {
        return Err(PqConsensusError::Local(
            PqConsensusLocalError::CacheInvariant,
        ));
    }
    Ok(IndividualSignerPreflight {
        signer: AggregationSigner {
            validator_index,
            public_key: *public_key,
        },
    })
}

fn materialize_individual_job(
    preflight: IndividualPreflight,
    signature: &consensus_signature::IndividualSignature,
    materializations: &mut usize,
) -> AggregationJob {
    *materializations = materializations.saturating_add(1);
    AggregationJob {
        claim: preflight.claim,
        expected_signers: vec![preflight.signer.clone()],
        contributions: vec![AggregationContribution {
            signers: vec![preflight.signer],
            evidence: SameMessageEvidence::from(signature),
        }],
    }
}

async fn verify_component_job(
    service: &AggregationService,
    class: VerificationClass,
    job: AggregationJob,
    component: PqConsensusComponent,
) -> Result<SameMessageEvidence, PqConsensusError> {
    service
        .verify(class, job)
        .await
        .map_err(|error| map_aggregation_error(error, component))
}

fn map_aggregation_error(
    error: AggregationError,
    component: PqConsensusComponent,
) -> PqConsensusError {
    match error {
        AggregationError::InvalidEvidence => {
            PqConsensusError::Invalid(PqConsensusInvalid::InvalidEvidence(component))
        }
        local => PqConsensusError::Local(PqConsensusLocalError::Aggregation(local)),
    }
}

#[cfg(feature = "pq-verification-testing")]
#[doc(hidden)]
pub fn classify_pq_consensus_aggregation_error(
    error: AggregationError,
    component: PqConsensusComponent,
) -> PqConsensusError {
    map_aggregation_error(error, component)
}

fn map_attestation_error(
    component: PqConsensusComponent,
    error: PqAttestationError,
) -> PqConsensusError {
    match error {
        PqAttestationError::Invalid(error) => {
            PqConsensusError::Invalid(PqConsensusInvalid::InvalidAttestation { component, error })
        }
        PqAttestationError::Local(error) => {
            PqConsensusError::Local(PqConsensusLocalError::Attestation(error))
        }
    }
}

fn validate_v1_profile<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
    slot: types::Slot,
) -> Result<(), PqConsensusError> {
    if is_lean_pq_devnet_v1(state, spec, slot) {
        Ok(())
    } else {
        Err(PqConsensusError::Local(
            PqConsensusLocalError::UnsupportedProfile,
        ))
    }
}

fn classify_state_error(_error: BeaconStateError) -> PqConsensusError {
    PqConsensusError::Local(PqConsensusLocalError::StateUnavailable)
}

fn classify_aggregate_committee_error(error: BeaconStateError) -> PqConsensusError {
    match error {
        BeaconStateError::CommitteeCacheUninitialized(_)
        | BeaconStateError::PreviousCommitteeCacheUninitialized
        | BeaconStateError::CurrentCommitteeCacheUninitialized => {
            PqConsensusError::Local(PqConsensusLocalError::StateUnavailable)
        }
        _ => PqConsensusError::Invalid(PqConsensusInvalid::InvalidAttestation {
            component: PqConsensusComponent::AggregateAttestation,
            error: PqAttestationInvalid::InvalidCommittee,
        }),
    }
}
