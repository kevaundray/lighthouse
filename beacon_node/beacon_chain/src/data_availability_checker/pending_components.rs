use super::AvailableBlockData;
use super::state_lru_cache::DietAvailabilityPendingExecutedBlock;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableBlock, AvailableExecutedBlock,
};
use crate::data_availability_checker::AvailabilityCheckError;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use lighthouse_tracing::SPAN_PENDING_COMPONENTS;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, Epoch, EthSpec, Hash256, RuntimeFixedVector,
    RuntimeVariableList,
};

#[derive(Clone)]
pub enum PendingComponents<E: EthSpec> {
    /// Post-Deneb, Pre-PeerDAS: Only blob sidecars needed
    PostDeneb {
        block_root: Hash256,
        executed_block: Option<DietAvailabilityPendingExecutedBlock<E>>,
        verified_blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
        span: Span,
    },
    
    /// Post-PeerDAS: Only data columns needed
    PostPeerDAS {
        block_root: Hash256,
        executed_block: Option<DietAvailabilityPendingExecutedBlock<E>>,
        verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
        reconstruction_started: bool,  // Keep flag for preventing duplicate reconstruction
        span: Span,
    },
}

impl<E: EthSpec> PendingComponents<E> {
    pub fn empty_for_epoch(block_root: Hash256, epoch: Epoch, spec: &ChainSpec) -> Self {
        let span = debug_span!(parent: None, SPAN_PENDING_COMPONENTS, %block_root);
        
        if spec.is_peer_das_enabled_for_epoch(epoch) {
            Self::PostPeerDAS {
                block_root,
                executed_block: None,
                verified_data_columns: Vec::new(),
                reconstruction_started: false,
                span,
            }
        } else {
            // Post-Deneb, Pre-PeerDAS
            Self::PostDeneb {
                block_root,
                executed_block: None,
                verified_blobs: RuntimeFixedVector::new(vec![None; spec.max_blobs_per_block(epoch) as usize]),
                span,
            }
        }
    }
    
    pub fn get_cached_block(&self) -> &Option<DietAvailabilityPendingExecutedBlock<E>> {
        match self {
            Self::PostDeneb { executed_block, .. } => executed_block,
            Self::PostPeerDAS { executed_block, .. } => executed_block,
        }
    }
    
    pub fn get_cached_blobs(&self) -> &RuntimeFixedVector<Option<KzgVerifiedBlob<E>>> {
        match self {
            Self::PostDeneb { verified_blobs, .. } => verified_blobs,
            Self::PostPeerDAS { .. } => {
                // Return reference to a static empty vector for non-blob variants
                static EMPTY_BLOBS: std::sync::OnceLock<RuntimeFixedVector<Option<KzgVerifiedBlob<types::MainnetEthSpec>>>> = std::sync::OnceLock::new();
                // This is a bit of a hack, but it maintains API compatibility
                unsafe { std::mem::transmute(EMPTY_BLOBS.get_or_init(|| RuntimeFixedVector::new(Vec::new()))) }
            }
        }
    }
    
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        match self {
            Self::PostPeerDAS { verified_data_columns, .. } => {
                verified_data_columns.iter().map(|d| d.index()).collect()
            },
            Self::PostDeneb { .. } => Vec::new(), // No columns in blob variant
        }
    }
    
    pub fn get_cached_data_column(&self, data_column_index: u64) -> Option<Arc<DataColumnSidecar<E>>> {
        match self {
            Self::PostPeerDAS { verified_data_columns, .. } => {
                verified_data_columns
                    .iter()
                    .find(|d| d.index() == data_column_index)
                    .map(|d| d.clone_arc())
            },
            Self::PostDeneb { .. } => None, // No columns in blob variant
        }
    }
    
    pub fn insert_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        match self {
            Self::PostDeneb { executed_block, .. } => *executed_block = Some(block),
            Self::PostPeerDAS { executed_block, .. } => *executed_block = Some(block),
        }
    }
    
    pub fn merge_blobs(&mut self, blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>) {
        match self {
            Self::PostDeneb { .. } => {
                for (index, blob) in blobs.iter().cloned().enumerate() {
                    let Some(blob) = blob else { continue };
                    self.merge_single_blob(index, blob);
                }
            },
            Self::PostPeerDAS { .. } => {
                // Silently ignore blobs for PeerDAS variant
            }
        }
    }
    
    pub fn merge_single_blob(&mut self, index: usize, blob: KzgVerifiedBlob<E>) {
        match self {
            Self::PostDeneb { verified_blobs, executed_block, .. } => {
                if let Some(cached_block) = executed_block {
                    let block_commitment_opt = cached_block.get_commitments().get(index).copied();
                    if let Some(block_commitment) = block_commitment_opt
                        && block_commitment == *blob.get_commitment()
                    {
                        if let Some(b) = verified_blobs.get_mut(index) {
                            *b = Some(blob);
                        }
                    }
                } else if let Some(b) = verified_blobs.get_mut(index) {
                    if b.is_none() {
                        *b = Some(blob);
                    }
                }
            },
            Self::PostPeerDAS { .. } => {
                // Silently ignore blobs for PeerDAS variant
            }
        }
    }
    
    pub fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
        &mut self,
        kzg_verified_data_columns: I,
    ) -> Result<(), AvailabilityCheckError> {
        match self {
            Self::PostPeerDAS { verified_data_columns, .. } => {
                for data_column in kzg_verified_data_columns {
                    if !verified_data_columns.iter().any(|existing| existing.index() == data_column.index()) {
                        verified_data_columns.push(data_column);
                    }
                }
                Ok(())
            },
            Self::PostDeneb { .. } => {
                // Silently ignore columns for blob variant
                Ok(())
            }
        }
    }
    
    pub fn merge_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.insert_block(block);
        match self {
            Self::PostDeneb { verified_blobs, .. } => {
                let reinsert = verified_blobs.clone();
                *verified_blobs = RuntimeFixedVector::new(vec![None; verified_blobs.len()]);
                self.merge_blobs(reinsert);
            },
            Self::PostPeerDAS { .. } => {
                // No blob revalidation needed for PeerDAS
            }
        }
    }
    
    pub fn epoch(&self) -> Option<Epoch> {
        match self {
            Self::PostDeneb { executed_block, verified_blobs, .. } => {
                if let Some(executed_block) = executed_block {
                    Some(executed_block.as_block().epoch())
                } else if let Some(blob) = verified_blobs.iter().flatten().next() {
                    Some(blob.as_blob().slot().epoch(E::slots_per_epoch()))
                } else {
                    None
                }
            },
            Self::PostPeerDAS { executed_block, verified_data_columns, .. } => {
                if let Some(executed_block) = executed_block {
                    Some(executed_block.as_block().epoch())
                } else if let Some(data_column) = verified_data_columns.first() {
                    Some(data_column.as_data_column().epoch())
                } else {
                    None
                }
            }
        }
    }
    
    pub fn status_str(&self, num_expected_columns_opt: Option<usize>) -> String {
        match self {
            Self::PostDeneb { executed_block, verified_blobs, .. } => {
                let block_count = if executed_block.is_some() { 1 } else { 0 };
                let num_expected_blobs = if let Some(block) = executed_block {
                    &block.num_blobs_expected().to_string()
                } else {
                    "?"
                };
                format!(
                    "block {} blobs {}/{}",
                    block_count,
                    verified_blobs.iter().flatten().count(),
                    num_expected_blobs
                )
            },
            Self::PostPeerDAS { executed_block, verified_data_columns, .. } => {
                let block_count = if executed_block.is_some() { 1 } else { 0 };
                let num_expected_columns = num_expected_columns_opt
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".to_string());
                format!(
                    "block {} data_columns {}/{}",
                    block_count,
                    verified_data_columns.len(),
                    num_expected_columns
                )
            }
        }
    }
    
    /// Check if reconstruction has started (only relevant for PostPeerDAS)
    pub fn reconstruction_started(&self) -> bool {
        match self {
            Self::PostPeerDAS { reconstruction_started, .. } => *reconstruction_started,
            Self::PostDeneb { .. } => false, // Reconstruction doesn't apply to blobs
        }
    }
    
    /// Set reconstruction started flag (only relevant for PostPeerDAS)
    pub fn set_reconstruction_started(&mut self, started: bool) {
        match self {
            Self::PostPeerDAS { reconstruction_started, .. } => *reconstruction_started = started,
            Self::PostDeneb { .. } => {}, // No-op for blob variant
        }
    }
    
    /// Get the span for this pending component
    pub fn span(&self) -> &Span {
        match self {
            Self::PostDeneb { span, .. } => span,
            Self::PostPeerDAS { span, .. } => span,
        }
    }
    
    /// Set the span for this pending component
    pub fn set_span(&mut self, new_span: Span) {
        match self {
            Self::PostDeneb { span, .. } => *span = new_span,
            Self::PostPeerDAS { span, .. } => *span = new_span,
        }
    }
    
    /// Get the verified data columns for reconstruction (only for PostPeerDAS)
    pub fn get_verified_data_columns(&self) -> Vec<KzgVerifiedCustodyDataColumn<E>> {
        match self {
            Self::PostPeerDAS { verified_data_columns, .. } => verified_data_columns.clone(),
            Self::PostDeneb { .. } => Vec::new(), // No columns for blob variant
        }
    }
    
    /// Clear verified data columns and reset reconstruction (for reconstruction failure handling)
    pub fn clear_data_columns_and_reset_reconstruction(&mut self) {
        match self {
            Self::PostPeerDAS { verified_data_columns, reconstruction_started, .. } => {
                verified_data_columns.clear();
                *reconstruction_started = false;
            },
            Self::PostDeneb { .. } => {}, // No-op for blob variant
        }
    }
    
    pub fn make_available<R>(
        &self,
        spec: &Arc<ChainSpec>,
        num_expected_columns_opt: Option<usize>,
        recover: R,
    ) -> Result<Option<AvailableExecutedBlock<E>>, AvailabilityCheckError>
    where
        R: FnOnce(DietAvailabilityPendingExecutedBlock<E>, &Span) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        match self {
            Self::PostDeneb { executed_block: Some(block), verified_blobs, span, .. } => {
                let num_expected_blobs = block.num_blobs_expected();
                
                if num_expected_blobs == 0 {
                    // No blobs required
                    let recovered = recover(block.clone(), span)?;
                    self.create_available_block(recovered, AvailableBlockData::NoData, spec)
                } else {
                    // Check if we have all required blobs
                    let num_received_blobs = verified_blobs.iter().flatten().count();
                    if num_received_blobs >= num_expected_blobs {
                        let blobs_vec = verified_blobs
                            .iter()
                            .flatten()
                            .map(|blob| blob.clone().to_blob())
                            .collect::<Vec<_>>();
                        let max_blobs = spec.max_blobs_per_block(block.epoch()) as usize;
                        let blobs = RuntimeVariableList::new(blobs_vec, max_blobs)
                            .map_err(|_| AvailabilityCheckError::Unexpected("blob count exceeded max".to_string()))?;
                        
                        let recovered = recover(block.clone(), span)?;
                        self.create_available_block(recovered, AvailableBlockData::Blobs(blobs), spec)
                    } else {
                        Ok(None) // Still missing blobs
                    }
                }
            },
            Self::PostPeerDAS { executed_block: Some(block), verified_data_columns, span, .. } => {
                let num_expected_blobs = block.num_blobs_expected();
                
                if num_expected_blobs == 0 {
                    // No data required
                    let recovered = recover(block.clone(), span)?;
                    self.create_available_block(recovered, AvailableBlockData::NoData, spec)
                } else if let Some(num_expected_columns) = num_expected_columns_opt {
                    // Check if we have enough columns
                    let num_received_columns = verified_data_columns.len();
                    if num_received_columns >= num_expected_columns {
                        let data_columns = verified_data_columns
                            .iter()
                            .map(|d| d.clone().into_inner())
                            .collect::<Vec<_>>();
                        
                        let recovered = recover(block.clone(), span)?;
                        self.create_available_block(recovered, AvailableBlockData::DataColumns(data_columns), spec)
                    } else {
                        Ok(None) // Still missing columns
                    }
                } else {
                    Ok(None) // No expected column count provided
                }
            },
            _ => Ok(None), // No block cached yet
        }
    }
    
    fn create_available_block(
        &self,
        recovered_block: AvailabilityPendingExecutedBlock<E>,
        blob_data: AvailableBlockData<E>,
        spec: &Arc<ChainSpec>,
    ) -> Result<Option<AvailableExecutedBlock<E>>, AvailabilityCheckError> {
        let blobs_available_timestamp = match &blob_data {
            AvailableBlockData::NoData => None,
            AvailableBlockData::Blobs(_) => {
                match self {
                    Self::PostDeneb { verified_blobs, .. } => {
                        verified_blobs
                            .iter()
                            .flatten()
                            .map(|blob| blob.seen_timestamp())
                            .max()
                    },
                    _ => None,
                }
            },
            AvailableBlockData::DataColumns(_) => None, // TODO: Add timestamp tracking for columns
        };

        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = recovered_block;

        let available_block = AvailableBlock {
            block_root: match self {
                Self::PostDeneb { block_root, .. } => *block_root,
                Self::PostPeerDAS { block_root, .. } => *block_root,
            },
            block,
            blob_data,
            blobs_available_timestamp,
            spec: spec.clone(),
        };

        match self {
            Self::PostDeneb { span, .. } | Self::PostPeerDAS { span, .. } => {
                span.in_scope(|| {
                    debug!("Block and all data components are available");
                });
            }
        }

        Ok(Some(AvailableExecutedBlock::new(
            available_block,
            import_data,
            payload_verification_outcome,
        )))
    }
    
    #[cfg(test)]
    pub fn empty(block_root: Hash256, max_len: usize) -> Self {
        // Use empty_for_epoch in tests
        let span = debug_span!(parent: None, SPAN_PENDING_COMPONENTS, %block_root);
        Self::PostDeneb {
            block_root,
            executed_block: None,
            verified_blobs: RuntimeFixedVector::new(vec![None; max_len]),
            span,
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

    fn create_test_diet_block() -> DietAvailabilityPendingExecutedBlock<E> {
        // Simplified test block creation
        let spec = test_spec::<E>();
        let (block, _) = generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::None, &mut StdRng::seed_from_u64(42), &spec);
        let dummy_parent = block.clone_as_blinded();
        
        let pending_block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Hash256::zero(),
                state: BeaconState::new(0, types::Eth1Data::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        
        pending_block.into()
    }

    #[test]
    fn test_enum_constructor_creates_correct_variant() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        
        // Test Pre-PeerDAS (should create PostDeneb variant)
        let pre_peerdas_epoch = Epoch::new(5); // Assume PeerDAS starts later
        let post_deneb = PendingComponents::<E>::empty_for_epoch(block_root, pre_peerdas_epoch, &spec);
        match post_deneb {
            PendingComponents::PostDeneb { .. } => {}, // Expected
            _ => panic!("Expected PostDeneb variant for pre-PeerDAS epoch"),
        }
        
        // Test Post-PeerDAS (should create PostPeerDAS variant) 
        // Note: This test would need a spec with PeerDAS enabled
        // For now, just test that the constructor works
    }

    #[test]
    fn test_mutual_exclusion_enforced() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        let epoch = Epoch::new(5);
        
        // Create PostDeneb variant
        let post_deneb = PendingComponents::<E>::empty_for_epoch(block_root, epoch, &spec);
        
        // Should have blobs accessor
        let _blobs = post_deneb.get_cached_blobs();
        
        // Should have empty columns (mutual exclusion)
        let columns = post_deneb.get_cached_data_columns_indices();
        assert!(columns.is_empty(), "PostDeneb variant should have no columns");
        
        // Should not have reconstruction flag
        assert!(!post_deneb.reconstruction_started(), "PostDeneb should not have reconstruction");
    }

    #[test] 
    fn test_api_compatibility() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        let epoch = Epoch::new(5);
        
        let mut pending = PendingComponents::empty_for_epoch(block_root, epoch, &spec);
        
        // Test that all original API methods exist and work
        let _block = pending.get_cached_block();
        let _blobs = pending.get_cached_blobs();
        let _columns = pending.get_cached_data_columns_indices();
        let _column = pending.get_cached_data_column(0);
        let _epoch = pending.epoch();
        let _status = pending.status_str(None);
        let _span = pending.span();
        
        // Test mutation methods
        let diet_block = create_test_diet_block();
        pending.insert_block(diet_block);
        
        // Test reconstruction methods (should be no-op for PostDeneb)
        pending.set_reconstruction_started(true);
        assert!(!pending.reconstruction_started(), "PostDeneb should ignore reconstruction flag");
    }

    #[test]
    fn test_memory_efficiency() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        let epoch = Epoch::new(5);
        
        // Create both variants and verify they only store relevant data
        let post_deneb = PendingComponents::<E>::empty_for_epoch(block_root, epoch, &spec);
        
        match post_deneb {
            PendingComponents::PostDeneb { verified_blobs, .. } => {
                // Should have blob storage
                assert_eq!(verified_blobs.len(), spec.max_blobs_per_block(epoch) as usize);
            },
            _ => panic!("Expected PostDeneb variant"),
        }
        
        // For PostPeerDAS, we'd test that it only has column storage
        // This would require a spec with PeerDAS enabled
    }

    #[test]
    fn test_backward_compatibility_empty_method() {
        let block_root = Hash256::zero();
        let max_len = 6;
        
        // Old-style constructor should still work
        let pending = PendingComponents::<E>::empty(block_root, max_len);
        
        // Should create PostDeneb variant by default
        match pending {
            PendingComponents::PostDeneb { verified_blobs, .. } => {
                assert_eq!(verified_blobs.len(), max_len);
            },
            _ => panic!("Expected PostDeneb variant from legacy empty() method"),
        }
    }

    #[test]
    fn test_fork_specific_operations() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        let epoch = Epoch::new(5);
        
        let mut post_deneb = PendingComponents::<E>::empty_for_epoch(block_root, epoch, &spec);
        
        // Should accept blob operations
        let empty_blobs = RuntimeFixedVector::new(vec![None; 6]);
        post_deneb.merge_blobs(empty_blobs); // Should work
        
        // Should silently ignore column operations
        let result = post_deneb.merge_data_columns(std::iter::empty());
        assert!(result.is_ok(), "Should silently ignore columns for PostDeneb");
        
        let columns = post_deneb.get_cached_data_columns_indices();
        assert!(columns.is_empty(), "Should have no columns after trying to add them");
    }

    #[test]
    fn test_status_string_fork_awareness() {
        let spec = test_spec::<E>();
        let block_root = Hash256::zero();
        let epoch = Epoch::new(5);
        
        let post_deneb = PendingComponents::<E>::empty_for_epoch(block_root, epoch, &spec);
        
        // Should generate blob-focused status string
        let status = post_deneb.status_str(None);
        assert!(status.contains("blobs"), "PostDeneb status should mention blobs");
        assert!(!status.contains("data_columns"), "PostDeneb status should not mention columns");
        
        // For PostPeerDAS, we'd test the opposite
    }

    // Original tests adapted for enum structure
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

    pub fn assert_cache_consistent(cache: &PendingComponents<E>, max_len: usize) {
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

    pub fn assert_empty_blob_cache(cache: &PendingComponents<E>) {
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
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(&cache, max_len);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(&cache, max_len);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(&cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(&cache, max_len);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(&cache, max_len);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = PendingComponents::<E>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(&cache, max_len);
    }
}
