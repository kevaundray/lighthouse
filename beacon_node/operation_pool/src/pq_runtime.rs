pub use attestation_aggregation::PqRetainedAttestationAssemblyError;
use attestation_aggregation::{
    InsertOutcome, PqAttestationAggregationCoordinator,
    PqBlockAttestationSelection as AggregationPqBlockAttestationSelection,
};
use consensus_signature::AggregationService;
use state_processing::{
    PqBlockAttestationSelectionError, PqValidatorKeyCache, VerifiedPqAttestation,
    VerifiedPqLocalBlock, VerifiedPqRandao,
};
use std::sync::Arc;
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationPoolResourceLimit {
    Candidates,
    Buckets,
    Evidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationPoolInsertDisposition {
    Inserted { removed_subsets: usize },
    Dominated,
    ResourceLimited(PqAttestationPoolResourceLimit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAttestationPoolInsertInvariant {
    UnsupportedCandidate,
    GenerationExhausted,
}

impl std::fmt::Display for PqAttestationPoolInsertInvariant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PQ attestation pool invariant failed: {self:?}")
    }
}

impl std::error::Error for PqAttestationPoolInsertInvariant {}

fn classify_pq_attestation_pool_insert(
    outcome: InsertOutcome,
) -> Result<PqAttestationPoolInsertDisposition, PqAttestationPoolInsertInvariant> {
    match outcome {
        InsertOutcome::Inserted {
            removed_subsets, ..
        } => Ok(PqAttestationPoolInsertDisposition::Inserted { removed_subsets }),
        InsertOutcome::Dominated => Ok(PqAttestationPoolInsertDisposition::Dominated),
        InsertOutcome::CapacityExceeded => Ok(PqAttestationPoolInsertDisposition::ResourceLimited(
            PqAttestationPoolResourceLimit::Candidates,
        )),
        InsertOutcome::BucketCapacityExceeded { .. } => {
            Ok(PqAttestationPoolInsertDisposition::ResourceLimited(
                PqAttestationPoolResourceLimit::Buckets,
            ))
        }
        InsertOutcome::EvidenceCapacityExceeded { .. } => {
            Ok(PqAttestationPoolInsertDisposition::ResourceLimited(
                PqAttestationPoolResourceLimit::Evidence,
            ))
        }
        InsertOutcome::UnsupportedCandidate => {
            Err(PqAttestationPoolInsertInvariant::UnsupportedCandidate)
        }
        InsertOutcome::GenerationExhausted => {
            Err(PqAttestationPoolInsertInvariant::GenerationExhausted)
        }
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_classify_pq_attestation_pool_insert(
    outcome: InsertOutcome,
) -> Result<PqAttestationPoolInsertDisposition, PqAttestationPoolInsertInvariant> {
    classify_pq_attestation_pool_insert(outcome)
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TestingPqAttestationPoolSnapshot {
    pub candidate_validator_indices: Vec<u64>,
    pub candidate_count: usize,
    pub candidate_signer_sets: Vec<Vec<u64>>,
    pub gossip_inserted: usize,
    pub gossip_dominated: usize,
    pub gossip_removed_subsets: usize,
    pub local_inserted: usize,
    pub local_dominated: usize,
    pub local_removed_subsets: usize,
}

/// Single failure-atomic ownership root for verified PQ attestation candidates.
pub struct OperationPool<E: EthSpec> {
    _coordinator: PqAttestationAggregationCoordinator<E>,
}

/// Non-cloneable authoritative block selection retaining every sealed authentication token.
pub struct PqBlockAttestationSelection<E: EthSpec> {
    selected: AggregationPqBlockAttestationSelection<E>,
}

impl<E: EthSpec> PqBlockAttestationSelection<E> {
    /// Consumes the only selection authority, installs exact attestation bytes, and seals the
    /// local block with the identical retained tokens.
    pub fn into_verified_local_block(
        self,
        state: &BeaconState<E>,
        block: BeaconBlock<E>,
        randao: VerifiedPqRandao<E>,
    ) -> Result<VerifiedPqLocalBlock<E>, PqRetainedAttestationAssemblyError> {
        self.selected
            .into_verified_local_block(state, block, randao)
    }
}

impl<E: EthSpec> OperationPool<E> {
    pub fn new(aggregation_service: Arc<AggregationService>) -> Self {
        Self {
            _coordinator: PqAttestationAggregationCoordinator::new(aggregation_service),
        }
    }

    pub fn insert_verified(
        &self,
        candidate: VerifiedPqAttestation<E>,
    ) -> Result<PqAttestationPoolInsertDisposition, PqAttestationPoolInsertInvariant> {
        classify_pq_attestation_pool_insert(self._coordinator.insert_verified(candidate))
    }

    pub fn select_pq_attestations_for_block(
        &self,
        state: &BeaconState<E>,
        key_cache: &PqValidatorKeyCache,
        spec: &ChainSpec,
    ) -> Result<PqBlockAttestationSelection<E>, PqBlockAttestationSelectionError> {
        let selected = self._coordinator.select_for_block(state, key_cache, spec)?;
        Ok(PqBlockAttestationSelection { selected })
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_uses_aggregation_service(
        &self,
        service: &Arc<AggregationService>,
    ) -> bool {
        self._coordinator
            .testing_only_uses_aggregation_service(service)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_pq_snapshot(&self) -> TestingPqAttestationPoolSnapshot {
        let candidate_signer_sets = self._coordinator.testing_only_candidate_signer_sets();
        let mut candidate_validator_indices = candidate_signer_sets
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        candidate_validator_indices.sort_unstable();
        candidate_validator_indices.dedup();
        TestingPqAttestationPoolSnapshot {
            candidate_validator_indices,
            candidate_count: candidate_signer_sets.len(),
            candidate_signer_sets,
            ..TestingPqAttestationPoolSnapshot::default()
        }
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_set_pq_next_generation(&self, next_generation: u64) {
        self._coordinator
            .testing_only_set_next_generation(next_generation);
    }
}
