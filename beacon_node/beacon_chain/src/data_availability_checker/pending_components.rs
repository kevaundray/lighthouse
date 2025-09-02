use super::AvailableBlockData;
use super::state_lru_cache::DietAvailabilityPendingExecutedBlock;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableBlock, AvailableExecutedBlock,
};
use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use lighthouse_tracing::SPAN_PENDING_COMPONENTS;
use std::cmp::Ordering;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, Epoch, EthSpec, Hash256, RuntimeFixedVector,
    RuntimeVariableList,
};

/// This represents the components of a partially available block
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub verified_blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    pub executed_block: Option<DietAvailabilityPendingExecutedBlock<E>>,
    pub reconstruction_started: bool,
    pub(super) span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns an immutable reference to the cached block.
    pub fn get_cached_block(&self) -> &Option<DietAvailabilityPendingExecutedBlock<E>> {
        &self.executed_block
    }

    /// Returns an immutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs(&self) -> &RuntimeFixedVector<Option<KzgVerifiedBlob<E>>> {
        &self.verified_blobs
    }

    /// Returns an immutable reference to the cached data column.
    pub fn get_cached_data_column(
        &self,
        data_column_index: u64,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        self.verified_data_columns
            .iter()
            .find(|d| d.index() == data_column_index)
            .map(|d| d.clone_arc())
    }

    /// Returns a mutable reference to the cached block.
    pub fn get_cached_block_mut(&mut self) -> &mut Option<DietAvailabilityPendingExecutedBlock<E>> {
        &mut self.executed_block
    }

    /// Returns a mutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs_mut(&mut self) -> &mut RuntimeFixedVector<Option<KzgVerifiedBlob<E>>> {
        &mut self.verified_blobs
    }

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    pub fn blob_exists(&self, blob_index: usize) -> bool {
        self.get_cached_blobs()
            .get(blob_index)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Returns the indices of cached custody columns
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        self.verified_data_columns
            .iter()
            .map(|d| d.index())
            .collect()
    }

    /// Inserts a block into the cache.
    pub fn insert_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        *self.get_cached_block_mut() = Some(block)
    }

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    pub fn insert_blob_at_index(&mut self, blob_index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(b) = self.get_cached_blobs_mut().get_mut(blob_index) {
            *b = Some(blob);
        }
    }

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_blobs(&mut self, blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>) {
        for (index, blob) in blobs.iter().cloned().enumerate() {
            let Some(blob) = blob else { continue };
            self.merge_single_blob(index, blob);
        }
    }

    /// Merges a single blob into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists, or
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_single_blob(&mut self, index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(cached_block) = self.get_cached_block() {
            let block_commitment_opt = cached_block.get_commitments().get(index).copied();
            if let Some(block_commitment) = block_commitment_opt
                && block_commitment == *blob.get_commitment()
            {
                self.insert_blob_at_index(index, blob)
            }
        } else if !self.blob_exists(index) {
            self.insert_blob_at_index(index, blob)
        }
    }

    /// Merges a given set of data columns into the cache.
    pub(super) fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
        &mut self,
        kzg_verified_data_columns: I,
    ) -> Result<(), AvailabilityCheckError> {
        for data_column in kzg_verified_data_columns {
            if self.get_cached_data_column(data_column.index()).is_none() {
                self.verified_data_columns.push(data_column);
            }
        }

        Ok(())
    }

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
    pub fn merge_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.insert_block(block);
        let reinsert = self.get_cached_blobs_mut().take();
        self.merge_blobs(reinsert);
    }

    /// Returns Some if the block has received all its required data for import. The return value
    /// must be persisted in the DB along with the block.
    ///
    /// WARNING: This function can potentially take a lot of time if the state needs to be
    /// reconstructed from disk. Ensure you are not holding any write locks while calling this.
    pub fn make_available<R>(
        &self,
        spec: &Arc<ChainSpec>,
        num_expected_columns_opt: Option<usize>,
        recover: R,
    ) -> Result<Option<AvailableExecutedBlock<E>>, AvailabilityCheckError>
    where
        R: FnOnce(
            DietAvailabilityPendingExecutedBlock<E>,
            &Span,
        ) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        let Some(block) = &self.executed_block else {
            // Block not available yet
            return Ok(None);
        };

        let num_expected_blobs = block.num_blobs_expected();
        let blob_data = if num_expected_blobs == 0 {
            Some(AvailableBlockData::NoData)
        } else if let Some(num_expected_columns) = num_expected_columns_opt {
            let num_received_columns = self.verified_data_columns.len();
            match num_received_columns.cmp(&num_expected_columns) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns got {num_received_columns} expected {num_expected_columns}"
                    )));
                }
                Ordering::Equal => {
                    // Block is post-peerdas, and we got enough columns
                    let data_columns = self
                        .verified_data_columns
                        .iter()
                        .map(|d| d.clone().into_inner())
                        .collect::<Vec<_>>();
                    Some(AvailableBlockData::DataColumns(data_columns))
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    None
                }
            }
        } else {
            // Before PeerDAS, blobs
            let num_received_blobs = self.verified_blobs.iter().flatten().count();
            match num_received_blobs.cmp(&num_expected_blobs) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many blobs got {num_received_blobs} expected {num_expected_blobs}"
                    )));
                }
                Ordering::Equal => {
                    let max_blobs = spec.max_blobs_per_block(block.epoch()) as usize;
                    let blobs_vec = self
                        .verified_blobs
                        .iter()
                        .flatten()
                        .map(|blob| blob.clone().to_blob())
                        .collect::<Vec<_>>();
                    let blobs_len = blobs_vec.len();
                    let blobs = RuntimeVariableList::new(blobs_vec, max_blobs).map_err(|_| {
                        AvailabilityCheckError::Unexpected(format!(
                            "over max_blobs len {blobs_len} max {max_blobs}"
                        ))
                    })?;
                    Some(AvailableBlockData::Blobs(blobs))
                }
                Ordering::Less => {
                    // Not enough blobs received yet
                    None
                }
            }
        };

        // Block's data not available yet
        let Some(blob_data) = blob_data else {
            return Ok(None);
        };

        // Block is available, construct `AvailableExecutedBlock`

        let blobs_available_timestamp = match blob_data {
            AvailableBlockData::NoData => None,
            AvailableBlockData::Blobs(_) => self
                .verified_blobs
                .iter()
                .flatten()
                .map(|blob| blob.seen_timestamp())
                .max(),
            // TODO(das): To be fixed with https://github.com/sigp/lighthouse/pull/6850
            AvailableBlockData::DataColumns(_) => None,
        };

        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = recover(block.clone(), &self.span)?;

        let available_block = AvailableBlock {
            block_root: self.block_root,
            block,
            blob_data,
            blobs_available_timestamp,
            spec: spec.clone(),
        };

        self.span.in_scope(|| {
            debug!("Block and all data components are available");
        });
        Ok(Some(AvailableExecutedBlock::new(
            available_block,
            import_data,
            payload_verification_outcome,
        )))
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256, max_len: usize) -> Self {
        let span = debug_span!(parent: None, SPAN_PENDING_COMPONENTS, %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            verified_blobs: RuntimeFixedVector::new(vec![None; max_len]),
            verified_data_columns: vec![],
            executed_block: None,
            reconstruction_started: false,
            span,
        }
    }

    /// Returns the epoch of:
    /// - The block if it is cached
    /// - The first available blob
    /// - The first data column
    ///   Otherwise, returns None
    pub fn epoch(&self) -> Option<Epoch> {
        // Get epoch from cached executed block
        if let Some(executed_block) = &self.executed_block {
            return Some(executed_block.as_block().epoch());
        }

        // Or, get epoch from first available blob
        if let Some(blob) = self.verified_blobs.iter().flatten().next() {
            return Some(blob.as_blob().slot().epoch(E::slots_per_epoch()));
        }

        // Or, get epoch from first data column
        if let Some(data_column) = self.verified_data_columns.first() {
            return Some(data_column.as_data_column().epoch());
        }

        None
    }

    pub fn status_str(&self, num_expected_columns_opt: Option<usize>) -> String {
        let block_count = if self.executed_block.is_some() { 1 } else { 0 };
        if let Some(num_expected_columns) = num_expected_columns_opt {
            format!(
                "block {} data_columns {}/{}",
                block_count,
                self.verified_data_columns.len(),
                num_expected_columns
            )
        } else {
            let num_expected_blobs = if let Some(block) = self.get_cached_block() {
                &block.num_blobs_expected().to_string()
            } else {
                "?"
            };
            format!(
                "block {} blobs {}/{}",
                block_count,
                self.verified_blobs.iter().flatten().count(),
                num_expected_blobs
            )
        }
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::PayloadVerificationOutcome;
    use crate::block_verification_types::BlockImportData;
    use crate::data_availability_checker::state_lru_cache::DietAvailabilityPendingExecutedBlock;
    use crate::test_utils::{NumBlobs, generate_rand_block_and_blobs, test_spec};
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{
        BeaconState, BlobSidecar, FixedBytesExtended, ForkName, MainnetEthSpec, SignedBeaconBlock,
        Slot,
    };

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        usize,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let spec = test_spec::<E>();
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng, &spec);
        let max_len = spec.max_blobs_per_block(block.epoch()) as usize;
        let mut blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs, max_len)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    );

    pub fn setup_pending_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        invalid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
    ) -> PendingComponentsSetup<E> {
        let blobs = RuntimeFixedVector::new(
            valid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = RuntimeFixedVector::new(
            invalid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let dummy_parent = block.clone_as_blinded();
        let block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Default::default(),
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (block.into(), blobs, invalid_blobs)
    }

    pub fn assert_cache_consistent(cache: PendingComponents<E>, max_len: usize) {
        if let Some(cached_block) = cache.get_cached_block() {
            let cached_block_commitments = cached_block.get_commitments();
            for index in 0..max_len {
                let block_commitment = cached_block_commitments.get(index).copied();
                let blob_commitment_opt = cache.get_cached_blobs().get(index).unwrap();
                let blob_commitment = blob_commitment_opt.as_ref().map(|b| *b.get_commitment());
                assert_eq!(block_commitment, blob_commitment);
            }
        } else {
            panic!("No cached block")
        }
    }

    pub fn assert_empty_blob_cache(cache: PendingComponents<E>) {
        for blob in cache.get_cached_blobs().iter() {
            assert!(blob.is_none());
        }
    }

    #[test]
    fn valid_block_invalid_blobs_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(cache, max_len);
    }
}
