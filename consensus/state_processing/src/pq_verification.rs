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

use crate::{
    PqAttestationError, PqAttestationInvalid, PqAttestationLocalError, PqValidatorKeyCache,
    PreparedPqAttestation, VerifiedPqAttestation,
    pq_attestation::{
        materialize_pq_attestation_verification_job, materialize_prepared_pq_attestation,
        preflight_pq_attestation_from_bits, preflight_pq_attestation_verification_job,
    },
    pq_profile::is_lean_pq_devnet_v1,
};
use consensus_signature::{
    AggregationContribution, AggregationError, AggregationJob, AggregationService,
    AggregationSigner, OneTimeUseId, SameMessageClaim, SameMessageEvidence, SigningDuty,
    SigningIdError, VerificationClass,
};
use std::sync::Arc;
use types::{
    BeaconState, BeaconStateError, ChainSpec, Domain, EthSpec, ForkName, SignedAggregateAndProof,
    SignedBeaconBlock, SignedRoot,
};

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
    proposal_job: AggregationJob,
    randao_job: AggregationJob,
    attestation_jobs: Vec<AggregationJob>,
}

pub struct VerifiedPqBlock<E: EthSpec> {
    block: Arc<SignedBeaconBlock<E>>,
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
        Ok(VerifiedPqBlock { block: self.block })
    }
}

impl<E: EthSpec> VerifiedPqBlock<E> {
    pub const fn block(&self) -> &Arc<SignedBeaconBlock<E>> {
        &self.block
    }

    pub fn into_block(self) -> Arc<SignedBeaconBlock<E>> {
        self.block
    }
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
        proposal_job,
        randao_job,
        attestation_jobs,
    })
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
