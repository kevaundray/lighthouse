use consensus_signature::{
    AggregationContribution, AggregationError, AggregationJob, AggregationService,
    AggregationSigner, OneTimeUseId, PqPublicKey, SameMessageClaim, SameMessageEvidence,
    SigningDuty, SigningIdError, V1_MAX_AGGREGATION_CONTRIBUTIONS, V1_MAX_AGGREGATION_SIGNERS,
    is_individual_same_message_evidence,
};
use std::collections::BTreeMap;
use types::{
    Attestation, BeaconState, BeaconStateError, ChainSpec, Domain, EthSpec, ForkName, SignedRoot,
    SingleAttestation,
};

/// Startup failure while rebuilding the ephemeral PQ registry cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationCacheError {
    EmptyRegistry,
    TooManyValidators { actual: usize, max: usize },
    ValidatorIndexOutOfRange(usize),
    NonCanonicalPublicKey(u64),
    DuplicatePublicKey { first: u64, duplicate: u64 },
}

impl std::fmt::Display for PqAttestationCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "invalid PQ validator registry: {self:?}")
    }
}

impl std::error::Error for PqAttestationCacheError {}

/// Peer-attributable malformed attestation data or invalid evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationInvalid {
    BaseAttestation,
    EmptySignerSet,
    TooManyContributions { actual: usize, max: usize },
    TooManySigners { actual: usize, max: usize },
    DuplicateSignerIndex(u64),
    NonCanonicalSignerOrder,
    MismatchedAttestationData,
    InvalidCommittee,
    InvalidBitfield,
    InvalidAttesterIndex(u64),
    AttesterNotInCommittee(u64),
    NonIndividualSingleEvidence,
    InvalidEvidence,
}

/// Locally attributable profile, cache, resource, or backend failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationLocalError {
    UnsupportedProfile,
    CommitteeCacheUnavailable,
    CacheInvariant,
    SigningId(SigningIdError),
    Aggregation(AggregationError),
}

/// Contextually verifies a previously built owned job.
///
/// A one-contribution request still enters `AggregationService`: the service verifies the raw or
/// recursive evidence against the exact claim and signer set, then returns it byte-identically
/// without invoking aggregate proving.
pub async fn verify_pq_attestation_job(
    service: &AggregationService,
    job: AggregationJob,
) -> Result<SameMessageEvidence, PqAttestationError> {
    service.aggregate(job).await.map_err(|error| match error {
        AggregationError::InvalidEvidence => {
            PqAttestationError::Invalid(PqAttestationInvalid::InvalidEvidence)
        }
        local => PqAttestationError::Local(PqAttestationLocalError::Aggregation(local)),
    })
}

/// Stable peer-versus-local failure classification for PQ attestation requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationError {
    Invalid(PqAttestationInvalid),
    Local(PqAttestationLocalError),
}

impl std::fmt::Display for PqAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ attestation request failed: {self:?}")
    }
}

impl std::error::Error for PqAttestationError {}

/// Ephemeral registry-order cache for the compile-time PQ profile.
///
/// This is rebuilt from the state registry on each startup. It is deliberately unrelated to the
/// persisted BLS `pkc` cache and must never be encoded into that database record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqValidatorKeyCache {
    registry_order: Vec<PqPublicKey>,
    validator_indices: BTreeMap<PqPublicKey, u64>,
}

/// A borrowed Electra evidence contribution and its caller-reconstructed signer indices.
///
/// The builder independently derives the indices from committee and aggregation bits and requires
/// exact equality. Keeping evidence borrowed lets all index, bitfield, and cache checks finish
/// before the potentially large evidence value is cloned into the owned job.
#[derive(Clone, Copy)]
pub struct PqAttestationContribution<'a, E: EthSpec> {
    attestation: &'a Attestation<E>,
    signer_indices: &'a [u64],
}

/// An owned contextual-verification request that holds no state or cache references.
///
/// Construct this value with [`prepare_pq_attestation`], release all state, cache, and shuffling
/// locks, then consume it with [`PreparedPqAttestation::verify`].
pub struct PreparedPqAttestation<E: EthSpec> {
    attestation: Attestation<E>,
    signer_indices: Vec<u64>,
    claim: SameMessageClaim,
    job: AggregationJob,
}

/// An Electra attestation authenticated against its exact claim, signer set, registry keys, and
/// participant bits.
///
/// Its fields are intentionally private so storage callers cannot create an unauthenticated
/// candidate or replace its evidence after verification.
pub struct VerifiedPqAttestation<E: EthSpec> {
    attestation: Attestation<E>,
    signer_indices: Vec<u64>,
    claim: SameMessageClaim,
}

impl<E: EthSpec> PreparedPqAttestation<E> {
    /// Performs contextual evidence verification and seals the owned candidate on success.
    pub async fn verify(
        self,
        service: &AggregationService,
    ) -> Result<VerifiedPqAttestation<E>, PqAttestationError> {
        let evidence = verify_pq_attestation_job(service, self.job).await?;
        let mut attestation = self.attestation;
        match &mut attestation {
            Attestation::Electra(electra) => electra.signature = evidence,
            Attestation::Base(_) => {
                return Err(PqAttestationError::Local(
                    PqAttestationLocalError::CacheInvariant,
                ));
            }
        }
        Ok(VerifiedPqAttestation {
            attestation,
            signer_indices: self.signer_indices,
            claim: self.claim,
        })
    }
}

impl<E: EthSpec> VerifiedPqAttestation<E> {
    pub const fn attestation(&self) -> &Attestation<E> {
        &self.attestation
    }

    pub fn signer_indices(&self) -> &[u64] {
        &self.signer_indices
    }

    pub const fn claim(&self) -> SameMessageClaim {
        self.claim
    }
}

/// Prepares an owned verification transition for one Electra candidate.
pub fn prepare_pq_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    attestation: Attestation<E>,
    signer_indices: Vec<u64>,
    spec: &ChainSpec,
) -> Result<PreparedPqAttestation<E>, PqAttestationError> {
    single_electra_committee_index(&attestation)?;
    let contribution = PqAttestationContribution::new(&attestation, &signer_indices);
    let job = build_pq_attestation_job(state, key_cache, &[contribution], spec)?;
    let claim = job.claim;
    Ok(PreparedPqAttestation {
        attestation,
        signer_indices,
        claim,
        job,
    })
}

/// Prepares one owned multi-contribution aggregate request without retaining borrowed state.
pub fn prepare_pq_attestation_aggregate<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    contributions: Vec<(Attestation<E>, Vec<u64>)>,
    spec: &ChainSpec,
) -> Result<PreparedPqAttestation<E>, PqAttestationError> {
    if contributions.len() > V1_MAX_AGGREGATION_CONTRIBUTIONS {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManyContributions {
                actual: contributions.len(),
                max: V1_MAX_AGGREGATION_CONTRIBUTIONS,
            },
        ));
    }
    let first_committee = contributions
        .first()
        .ok_or(PqAttestationError::Invalid(
            PqAttestationInvalid::EmptySignerSet,
        ))
        .and_then(|(attestation, _)| single_electra_committee_index(attestation))?;
    for (attestation, _) in &contributions {
        if single_electra_committee_index(attestation)? != first_committee {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidCommittee,
            ));
        }
    }
    let borrowed = contributions
        .iter()
        .map(|(attestation, signers)| PqAttestationContribution::new(attestation, signers))
        .collect::<Vec<_>>();
    let job = build_pq_attestation_job(state, key_cache, &borrowed, spec)?;
    let claim = job.claim;
    let signer_indices = job
        .expected_signers
        .iter()
        .map(|signer| signer.validator_index)
        .collect::<Vec<_>>();
    let mut contribution_iter = contributions.into_iter();
    let (mut attestation, _) = contribution_iter.next().ok_or(PqAttestationError::Invalid(
        PqAttestationInvalid::EmptySignerSet,
    ))?;
    let Attestation::Electra(combined) = &mut attestation else {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::BaseAttestation,
        ));
    };
    for (other, _) in contribution_iter {
        let Attestation::Electra(other) = other else {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::BaseAttestation,
            ));
        };
        for (position, present) in other.aggregation_bits.iter().enumerate() {
            if present {
                combined.aggregation_bits.set(position, true).map_err(|_| {
                    PqAttestationError::Invalid(PqAttestationInvalid::InvalidBitfield)
                })?;
            }
        }
    }
    Ok(PreparedPqAttestation {
        attestation,
        signer_indices,
        claim,
        job,
    })
}

fn single_electra_committee_index<E: EthSpec>(
    attestation: &Attestation<E>,
) -> Result<u64, PqAttestationError> {
    let Attestation::Electra(electra) = attestation else {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::BaseAttestation,
        ));
    };
    let mut selected = electra
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, present)| present.then_some(index));
    let committee_index = selected.next().ok_or(PqAttestationError::Invalid(
        PqAttestationInvalid::InvalidCommittee,
    ))?;
    if selected.next().is_some() {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidCommittee,
        ));
    }
    u64::try_from(committee_index)
        .map_err(|_| PqAttestationError::Invalid(PqAttestationInvalid::InvalidCommittee))
}

impl<'a, E: EthSpec> PqAttestationContribution<'a, E> {
    pub const fn new(attestation: &'a Attestation<E>, signer_indices: &'a [u64]) -> Self {
        Self {
            attestation,
            signer_indices,
        }
    }
}

impl PqValidatorKeyCache {
    pub fn from_state<E: EthSpec>(state: &BeaconState<E>) -> Result<Self, PqAttestationCacheError> {
        let validators = state.validators();
        if validators.is_empty() {
            return Err(PqAttestationCacheError::EmptyRegistry);
        }
        if validators.len() > V1_MAX_AGGREGATION_SIGNERS {
            return Err(PqAttestationCacheError::TooManyValidators {
                actual: validators.len(),
                max: V1_MAX_AGGREGATION_SIGNERS,
            });
        }
        let mut registry_order = Vec::with_capacity(validators.len());
        let mut validator_indices = BTreeMap::new();
        for (position, validator) in validators.iter().enumerate() {
            let validator_index = u64::try_from(position)
                .map_err(|_| PqAttestationCacheError::ValidatorIndexOutOfRange(position))?;
            let public_key = PqPublicKey::deserialize(validator.pubkey.as_serialized())
                .map_err(|_| PqAttestationCacheError::NonCanonicalPublicKey(validator_index))?;
            if let Some(first) = validator_indices.insert(public_key, validator_index) {
                return Err(PqAttestationCacheError::DuplicatePublicKey {
                    first,
                    duplicate: validator_index,
                });
            }
            registry_order.push(public_key);
        }
        Ok(Self {
            registry_order,
            validator_indices,
        })
    }

    pub fn len(&self) -> usize {
        self.registry_order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registry_order.is_empty()
    }

    pub fn get(&self, validator_index: u64) -> Option<&PqPublicKey> {
        usize::try_from(validator_index)
            .ok()
            .and_then(|index| self.registry_order.get(index))
    }

    pub fn validator_index(&self, public_key: &PqPublicKey) -> Option<u64> {
        self.validator_indices.get(public_key).copied()
    }
}

/// Builds an owned verification request for an Electra V1 `SingleAttestation`.
///
/// No evidence bytes are cloned until the profile, index, committee membership, and exact cache
/// key have been checked. The returned job owns everything needed by the asynchronous aggregation
/// service, so callers can release state, cache, and shuffling locks before awaiting it.
pub fn build_pq_single_attestation_job<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    attestation: &SingleAttestation,
    spec: &ChainSpec,
) -> Result<AggregationJob, PqAttestationError> {
    validate_v1_profile(state, spec, attestation.data.slot)?;
    if attestation.data.index != 0 {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidCommittee,
        ));
    }
    let validator_position = usize::try_from(attestation.attester_index).map_err(|_| {
        PqAttestationError::Invalid(PqAttestationInvalid::InvalidAttesterIndex(
            attestation.attester_index,
        ))
    })?;
    let validator =
        state
            .validators()
            .get(validator_position)
            .ok_or(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidAttesterIndex(attestation.attester_index),
            ))?;
    let cached_public_key =
        key_cache
            .get(attestation.attester_index)
            .ok_or(PqAttestationError::Local(
                PqAttestationLocalError::CacheInvariant,
            ))?;
    if cached_public_key != &validator.pubkey || key_cache.len() != state.validators().len() {
        return Err(PqAttestationError::Local(
            PqAttestationLocalError::CacheInvariant,
        ));
    }

    let committee = state
        .get_beacon_committee(attestation.data.slot, attestation.committee_index)
        .map_err(classify_committee_error)?;
    if !committee.committee.contains(&validator_position) {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::AttesterNotInCommittee(attestation.attester_index),
        ));
    }
    if !is_individual_same_message_evidence(&attestation.signature) {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::NonIndividualSingleEvidence,
        ));
    }

    let one_time_use_id = OneTimeUseId::for_lean_pq_devnet_v1(
        attestation.data.slot.as_u64(),
        SigningDuty::Attestation,
    )
    .map_err(|error| PqAttestationError::Local(PqAttestationLocalError::SigningId(error)))?;
    let domain = spec.get_domain(
        attestation.data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let signer = AggregationSigner {
        validator_index: attestation.attester_index,
        public_key: *cached_public_key,
    };
    Ok(AggregationJob {
        claim: SameMessageClaim::new(attestation.data.signing_root(domain).0, one_time_use_id),
        expected_signers: vec![signer.clone()],
        contributions: vec![AggregationContribution {
            signers: vec![signer],
            evidence: attestation.signature.clone(),
        }],
    })
}

/// Builds one owned same-message job from Electra aggregate-attestation contributions.
///
/// Every supplied signer slice must be strictly increasing. Contribution order is independent;
/// the builder canonicalizes the expected signer union by validator index after rejecting overlap.
pub fn build_pq_attestation_job<E: EthSpec>(
    state: &BeaconState<E>,
    key_cache: &PqValidatorKeyCache,
    contributions: &[PqAttestationContribution<'_, E>],
    spec: &ChainSpec,
) -> Result<AggregationJob, PqAttestationError> {
    if contributions.len() > V1_MAX_AGGREGATION_CONTRIBUTIONS {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManyContributions {
                actual: contributions.len(),
                max: V1_MAX_AGGREGATION_CONTRIBUTIONS,
            },
        ));
    }
    let first = contributions.first().ok_or(PqAttestationError::Invalid(
        PqAttestationInvalid::EmptySignerSet,
    ))?;
    let first_data = match first.attestation {
        Attestation::Electra(attestation) => &attestation.data,
        Attestation::Base(_) => {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::BaseAttestation,
            ));
        }
    };
    validate_v1_profile(state, spec, first_data.slot)?;
    if first_data.index != 0 {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidCommittee,
        ));
    }
    if key_cache.len() != state.validators().len() {
        return Err(PqAttestationError::Local(
            PqAttestationLocalError::CacheInvariant,
        ));
    }
    let signer_count = contributions
        .iter()
        .map(|contribution| contribution.signer_indices.len())
        .try_fold(0usize, usize::checked_add)
        .ok_or(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManySigners {
                actual: usize::MAX,
                max: V1_MAX_AGGREGATION_SIGNERS,
            },
        ))?;
    if signer_count > V1_MAX_AGGREGATION_SIGNERS {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::TooManySigners {
                actual: signer_count,
                max: V1_MAX_AGGREGATION_SIGNERS,
            },
        ));
    }

    let mut contribution_signers = Vec::with_capacity(contributions.len());
    let mut expected_signers = Vec::new();
    for contribution in contributions {
        if contribution.signer_indices.is_empty() {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::EmptySignerSet,
            ));
        }
        for pair in contribution.signer_indices.windows(2) {
            let [first, second] = pair else {
                continue;
            };
            if first == second {
                return Err(PqAttestationError::Invalid(
                    PqAttestationInvalid::DuplicateSignerIndex(*first),
                ));
            }
            if first > second {
                return Err(PqAttestationError::Invalid(
                    PqAttestationInvalid::NonCanonicalSignerOrder,
                ));
            }
        }
        let electra = match contribution.attestation {
            Attestation::Electra(electra) => electra,
            Attestation::Base(_) => {
                return Err(PqAttestationError::Invalid(
                    PqAttestationInvalid::BaseAttestation,
                ));
            }
        };
        if electra.data != *first_data {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::MismatchedAttestationData,
            ));
        }
        let mut signers = Vec::with_capacity(contribution.signer_indices.len());
        for &validator_index in contribution.signer_indices {
            let validator_position = usize::try_from(validator_index).map_err(|_| {
                PqAttestationError::Invalid(PqAttestationInvalid::InvalidAttesterIndex(
                    validator_index,
                ))
            })?;
            let validator =
                state
                    .validators()
                    .get(validator_position)
                    .ok_or(PqAttestationError::Invalid(
                        PqAttestationInvalid::InvalidAttesterIndex(validator_index),
                    ))?;
            let public_key = key_cache
                .get(validator_index)
                .ok_or(PqAttestationError::Local(
                    PqAttestationLocalError::CacheInvariant,
                ))?;
            if public_key != &validator.pubkey {
                return Err(PqAttestationError::Local(
                    PqAttestationLocalError::CacheInvariant,
                ));
            }
            let signer = AggregationSigner {
                validator_index,
                public_key: *public_key,
            };
            signers.push(signer.clone());
            expected_signers.push(signer);
        }
        if electra_attesting_indices(state, electra)? != contribution.signer_indices {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidBitfield,
            ));
        }
        contribution_signers.push(signers);
    }
    if expected_signers.is_empty() {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::EmptySignerSet,
        ));
    }

    let one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(first_data.slot.as_u64(), SigningDuty::Attestation)
            .map_err(|error| {
                PqAttestationError::Local(PqAttestationLocalError::SigningId(error))
            })?;
    let domain = spec.get_domain(
        first_data.target.epoch,
        Domain::BeaconAttester,
        &state.fork(),
        state.genesis_validators_root(),
    );
    expected_signers.sort_unstable_by_key(|signer| signer.validator_index);
    for pair in expected_signers.windows(2) {
        let [first, second] = pair else {
            continue;
        };
        if first.validator_index == second.validator_index {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::DuplicateSignerIndex(first.validator_index),
            ));
        }
    }

    let contributions = contributions
        .iter()
        .zip(contribution_signers)
        .map(|(contribution, signers)| {
            let Attestation::Electra(electra) = contribution.attestation else {
                return Err(PqAttestationError::Invalid(
                    PqAttestationInvalid::BaseAttestation,
                ));
            };
            Ok(AggregationContribution {
                signers,
                evidence: electra.signature.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AggregationJob {
        claim: SameMessageClaim::new(first_data.signing_root(domain).0, one_time_use_id),
        expected_signers,
        contributions,
    })
}

fn electra_attesting_indices<E: EthSpec>(
    state: &BeaconState<E>,
    attestation: &types::AttestationElectra<E>,
) -> Result<Vec<u64>, PqAttestationError> {
    let committees = state
        .get_beacon_committees_at_slot(attestation.data.slot)
        .map_err(classify_committee_error)?;
    let selected_committees = attestation
        .committee_bits
        .iter()
        .enumerate()
        .filter_map(|(index, selected)| selected.then_some(index))
        .collect::<Vec<_>>();
    if selected_committees.is_empty() {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidCommittee,
        ));
    }

    let mut committee_offset = 0usize;
    let mut validator_indices = Vec::new();
    for committee_index in selected_committees {
        let committee = committees
            .get(committee_index)
            .ok_or(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidCommittee,
            ))?;
        let next_offset = committee_offset
            .checked_add(committee.committee.len())
            .ok_or(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidBitfield,
            ))?;
        let mut committee_has_attester = false;
        for (position, validator_index) in committee.committee.iter().enumerate() {
            let bit_position =
                committee_offset
                    .checked_add(position)
                    .ok_or(PqAttestationError::Invalid(
                        PqAttestationInvalid::InvalidBitfield,
                    ))?;
            if attestation
                .aggregation_bits
                .get(bit_position)
                .map_err(|_| PqAttestationError::Invalid(PqAttestationInvalid::InvalidBitfield))?
            {
                committee_has_attester = true;
                validator_indices.push(u64::try_from(*validator_index).map_err(|_| {
                    PqAttestationError::Invalid(PqAttestationInvalid::InvalidAttesterIndex(
                        u64::MAX,
                    ))
                })?);
            }
        }
        if !committee_has_attester {
            return Err(PqAttestationError::Invalid(
                PqAttestationInvalid::InvalidBitfield,
            ));
        }
        committee_offset = next_offset;
    }
    if committee_offset != attestation.aggregation_bits.len() {
        return Err(PqAttestationError::Invalid(
            PqAttestationInvalid::InvalidBitfield,
        ));
    }
    validator_indices.sort_unstable();
    Ok(validator_indices)
}

fn validate_v1_profile<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
    attestation_slot: types::Slot,
) -> Result<(), PqAttestationError> {
    let genesis_epoch = E::genesis_epoch();
    let is_electra_v1 = state.fork_name(spec) == Ok(ForkName::Electra)
        && state.fork_name_unchecked() == ForkName::Electra
        && spec.fork_name_at_slot::<E>(attestation_slot) == ForkName::Electra
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
            .is_ok_and(|deposits| deposits.is_empty());
    if is_electra_v1 {
        Ok(())
    } else {
        Err(PqAttestationError::Local(
            PqAttestationLocalError::UnsupportedProfile,
        ))
    }
}

fn classify_committee_error(error: BeaconStateError) -> PqAttestationError {
    match error {
        BeaconStateError::CommitteeCacheUninitialized(_)
        | BeaconStateError::PreviousCommitteeCacheUninitialized
        | BeaconStateError::CurrentCommitteeCacheUninitialized => {
            PqAttestationError::Local(PqAttestationLocalError::CommitteeCacheUnavailable)
        }
        _ => PqAttestationError::Invalid(PqAttestationInvalid::InvalidCommittee),
    }
}
