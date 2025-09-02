use super::state_machine::{AvailabilityState, StateTransition, AvailabilityError};
use crate::data_availability_checker::{StateLRUCache, DietAvailabilityPendingExecutedBlock}; 
use super::error::{Error as AvailabilityCheckError};
use super::{Availability};
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::AvailabilityPendingExecutedBlock;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::BeaconChainTypes;
use crate::BeaconStore;
use crate::CustodyContext;
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::debug;
use types::blob_sidecar::BlobIdentifier;
use types::{
    BlobSidecar, ChainSpec, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    SignedBeaconBlock,
};

/// New state machine-based implementation of the availability checker
pub struct DataAvailabilityCheckerInner<T: BeaconChainTypes> {
    /// State machine storage - simple HashMap for core data
    states: RwLock<HashMap<Hash256, AvailabilityState<T::EthSpec>>>,
    /// LRU ordering for eviction (separate from data for better cache locality)
    lru_order: RwLock<LruCache<Hash256, ()>>,
    /// State cache for BeaconState memory management (restored optimization)
    state_cache: StateLRUCache<T>,
    custody_context: Arc<CustodyContext>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> DataAvailabilityCheckerInner<T> {
    pub fn new(
        capacity: NonZeroUsize,
        beacon_store: BeaconStore<T>,
        custody_context: Arc<CustodyContext>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            states: RwLock::new(HashMap::new()),
            lru_order: RwLock::new(LruCache::new(capacity)),
            state_cache: StateLRUCache::new(beacon_store, spec.clone()),
            custody_context,
            spec,
        })
    }

    /// Get execution valid block if it exists
    pub fn get_execution_valid_block(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedBeaconBlock<T::EthSpec>>> {
        let states = self.states.read();
        
        if let Some(state) = states.get(block_root) {
            match state {
                AvailabilityState::PreDeneb { block } => Some(block.block.clone()),
                AvailabilityState::PostDeneb { block, .. } => {
                    block.as_ref().map(|b| b.block.clone())
                },
                AvailabilityState::PostPeerDAS { block, .. } => {
                    block.as_ref().map(|b| b.block.clone())
                },
                AvailabilityState::Reconstructing { block, .. } => Some(block.block.clone()),
                AvailabilityState::Available { available_block, .. } => {
                    Some(available_block.block.block_cloned())
                },
                AvailabilityState::Failed { .. } => None,
            }
        } else {
            None
        }
    }

    /// Peek at pending components with a closure (for compatibility with existing API)
    pub fn peek_pending_components<R, F: FnOnce(Option<&CompatibilityWrapper<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        let states = self.states.read();
        
        if let Some(state) = states.get(block_root) {
            let wrapper = CompatibilityWrapper { state };
            f(Some(&wrapper))
        } else {
            f(None)
        }
    }

    /// Fetch a blob from the cache without affecting the LRU ordering
    pub fn peek_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        let states = self.states.read();
        
        if let Some(state) = states.get(&blob_id.block_root) {
            match state {
                AvailabilityState::PostDeneb { blobs, .. } => {
                    Ok(blobs.get_blob(blob_id.index)
                        .map(|kzg_blob| kzg_blob.clone_blob()))
                },
                _ => Ok(None), // Other states don't have blobs
            }
        } else {
            Ok(None)
        }
    }

    /// Fetch data columns of a given `block_root` from the cache
    pub fn peek_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        let states = self.states.read();
        
        if let Some(state) = states.get(&block_root) {
            match state {
                AvailabilityState::PostPeerDAS { columns, .. } => {
                    Some(columns.clone().into_column_list())
                },
                AvailabilityState::Reconstructing { partial_columns, .. } => {
                    Some(partial_columns.clone().into_column_list())
                },
                _ => None, // Other states don't have columns
            }
        } else {
            None
        }
    }

    /// Put pending executed block into the state machine
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let block_root = executed_block.import_data.block_root;
        let epoch = executed_block.as_block().epoch();
        
        // Convert to diet block for memory efficiency (same as old code)
        let diet_block = self.state_cache.register_pending_executed_block(executed_block);
        
        // Update LRU ordering
        self.lru_order.write().put(block_root, ());
        
        // Get or create state and add the diet block
        let current_state = {
            let mut states = self.states.write();
            states.remove(&block_root).unwrap_or_else(|| {
                let expected_column_count = self.custody_context
                    .num_of_data_columns_to_sample(Some(epoch), &self.spec);
                
                AvailabilityState::create_initial_state(
                    block_root,
                    None, // Will be added via add_diet_block
                    epoch,
                    &self.spec,
                    expected_column_count,
                )
            })
        };
        
        // Add diet block to state and check availability (like old make_available pattern)
        let state_with_block = current_state.add_diet_block(diet_block.clone());
        
        // Check if block is now available using make_available pattern
        let recovery_fn = |diet: DietAvailabilityPendingExecutedBlock<T::EthSpec>| {
            self.state_cache.recover_pending_executed_block(diet)
                .map_err(|e| AvailabilityCheckError::Unexpected(format!("Recovery failed: {:?}", e)))
        };
        
        match state_with_block.make_available(&self.spec, 
            self.custody_context.num_of_data_columns_to_sample(Some(epoch), &self.spec),
            recovery_fn) {
            Ok(Some(available_block)) => {
                debug!(
                    component = "block",
                    ?block_root,
                    status = "completed",
                    "Block became available"
                );
                
                // Store state for cleanup but don't need to track Available state
                self.states.write().insert(block_root, state_with_block);
                self.maybe_evict();
                
                Ok(Availability::Available(Box::new(available_block)))
            },
            Ok(None) => {
                let status = self.get_status_string(&state_with_block, epoch);
                debug!(
                    component = "block",
                    ?block_root,
                    status = status,
                    "Block added to availability checker"
                );
                
                self.states.write().insert(block_root, state_with_block);
                
                // Check capacity and evict if needed
                self.maybe_evict();
                
                Ok(Availability::MissingComponents(block_root))
            },
            Err(error) => {
                self.states.write().insert(
                    block_root,
                    AvailabilityState::Failed {
                        block_root,
                        error: AvailabilityError::InternalError(format!("make_available failed: {:?}", error)),
                        failed_at: std::time::Instant::now(),
                    }
                );
                
                // Check capacity and evict if needed
                self.maybe_evict();
                
                Err(AvailabilityCheckError::Unexpected(format!("make_available failed: {:?}", error)))
            }
        }
    }

    /// Put KZG verified blobs into the state machine
    pub fn put_kzg_verified_blobs<I: IntoIterator<Item = KzgVerifiedBlob<T::EthSpec>>>(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let blobs: Vec<_> = kzg_verified_blobs.into_iter().collect();
        if blobs.is_empty() {
            return Err(AvailabilityCheckError::Unexpected("empty blobs".to_owned()));
        }

        let epoch = blobs[0].as_blob().epoch();
        
        // Update LRU ordering
        self.lru_order.write().put(block_root, ());
        
        // Get or create state and apply blob addition
        let current_state = {
            let mut states = self.states.write();
            states.remove(&block_root).unwrap_or_else(|| {
                let expected_blob_count = blobs.len() as u64; // Estimate from incoming blobs
                
                AvailabilityState::PostDeneb {
                    block: None,
                    blobs: super::collections::BlobCollection::new(
                        self.spec.max_blobs_per_block(epoch) as usize
                    ),
                    expected_blob_count,
                }
            })
        };

        // Apply state transition
        match current_state.add_blobs(blobs, &self.spec) {
            StateTransition::Completed(available_block) => {
                // Should not occur; creation is deferred to outer layer
                Ok(Availability::Available(Box::new(available_block)))
            },
            StateTransition::Changed(new_state) => {
                let status = self.get_status_string(&new_state, epoch);
                debug!(
                    component = "blobs",
                    ?block_root,
                    status = status,
                    "Blobs added to availability checker"
                );
                
                // Store and then attempt to recover to available using make_available
                self.states.write().insert(block_root, new_state);
                let state = self.states.write().remove(&block_root).expect("inserted above");
                let recovery_fn = |diet: DietAvailabilityPendingExecutedBlock<T::EthSpec>| {
                    self.state_cache.recover_pending_executed_block(diet)
                        .map_err(|e| AvailabilityCheckError::Unexpected(format!("Recovery failed: {:?}", e)))
                };
                let epoch_for_state = state.epoch().unwrap_or(epoch);
                match state.make_available(&self.spec,
                    self.custody_context.num_of_data_columns_to_sample(Some(epoch_for_state), &self.spec),
                    recovery_fn
                ) {
                    Ok(Some(available_block)) => {
                        debug!(component = "blobs", ?block_root, status = "completed", "Block became available with blobs");
                        self.maybe_evict();
                        Ok(Availability::Available(Box::new(available_block)))
                    },
                    Ok(None) => {
                        // Put state back and continue waiting
                        self.states.write().insert(block_root, state);
                        self.maybe_evict();
                        Ok(Availability::MissingComponents(block_root))
                    },
                    Err(error) => {
                        self.states.write().insert(
                            block_root,
                            AvailabilityState::Failed {
                                block_root,
                                error: AvailabilityError::InternalError(format!("make_available failed: {:?}", error)),
                                failed_at: std::time::Instant::now(),
                            }
                        );
                        self.maybe_evict();
                        Err(AvailabilityCheckError::Unexpected(format!("make_available failed: {:?}", error)))
                    }
                }
            },
            StateTransition::Failed(error) => {
                self.states.write().insert(
                    block_root,
                    AvailabilityState::Failed {
                        block_root,
                        error: error.clone(),
                        failed_at: std::time::Instant::now(),
                    }
                );
                
                // Check capacity and evict if needed
                self.maybe_evict();
                
                Err(error.into())
            },
            StateTransition::NoChange => {
                // Don't try to reuse moved current_state, just return missing components
                Ok(Availability::MissingComponents(block_root))
            }
        }
    }

    /// Put KZG verified data columns into the state machine  
    pub fn put_kzg_verified_data_columns<
        I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    >(
        &self,
        block_root: Hash256,
        kzg_verified_data_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let columns: Vec<_> = kzg_verified_data_columns.into_iter().collect();
        if columns.is_empty() {
            return Err(AvailabilityCheckError::Unexpected("empty columns".to_owned()));
        }

        let epoch = columns[0].as_data_column().epoch();
        
        // Update LRU ordering
        self.lru_order.write().put(block_root, ());
        
        // Get or create state and apply column addition
        let current_state = {
            let mut states = self.states.write();
            states.remove(&block_root).unwrap_or_else(|| {
                let expected_column_count = self.custody_context
                    .num_of_data_columns_to_sample(Some(epoch), &self.spec);
                
                AvailabilityState::PostPeerDAS {
                    block: None,
                    columns: super::collections::ColumnCollection::new(),
                    expected_column_count,
                }
            })
        };

        // Apply state transition
        match current_state.add_columns(columns, &self.spec) {
            StateTransition::Completed(available_block) => {
                // Should not occur; creation is deferred to outer layer
                Ok(Availability::Available(Box::new(available_block)))
            },
            StateTransition::Changed(new_state) => {
                let status = self.get_status_string(&new_state, epoch);
                debug!(
                    component = "data_columns",
                    ?block_root,
                    status = status,
                    "Data columns added to availability checker"
                );
                
                // Store and then attempt to recover to available using make_available
                self.states.write().insert(block_root, new_state);
                let state = self.states.write().remove(&block_root).expect("inserted above");
                let recovery_fn = |diet: DietAvailabilityPendingExecutedBlock<T::EthSpec>| {
                    self.state_cache.recover_pending_executed_block(diet)
                        .map_err(|e| AvailabilityCheckError::Unexpected(format!("Recovery failed: {:?}", e)))
                };
                let epoch_for_state = state.epoch().unwrap_or(epoch);
                match state.make_available(&self.spec,
                    self.custody_context.num_of_data_columns_to_sample(Some(epoch_for_state), &self.spec),
                    recovery_fn
                ) {
                    Ok(Some(available_block)) => {
                        debug!(component = "data_columns", ?block_root, status = "completed", "Block became available with columns");
                        self.maybe_evict();
                        Ok(Availability::Available(Box::new(available_block)))
                    },
                    Ok(None) => {
                        self.states.write().insert(block_root, state);
                        self.maybe_evict();
                        Ok(Availability::MissingComponents(block_root))
                    },
                    Err(error) => {
                        self.states.write().insert(
                            block_root,
                            AvailabilityState::Failed {
                                block_root,
                                error: AvailabilityError::InternalError(format!("make_available failed: {:?}", error)),
                                failed_at: std::time::Instant::now(),
                            }
                        );
                        self.maybe_evict();
                        Err(AvailabilityCheckError::Unexpected(format!("make_available failed: {:?}", error)))
                    }
                }
            },
            StateTransition::Failed(error) => {
                self.states.write().insert(
                    block_root,
                    AvailabilityState::Failed {
                        block_root,
                        error: error.clone(),
                        failed_at: std::time::Instant::now(),
                    }
                );
                
                // Check capacity and evict if needed
                self.maybe_evict();
                
                Err(error.into())
            },
            StateTransition::NoChange => {
                // Don't try to reuse moved current_state, just return missing components
                Ok(Availability::MissingComponents(block_root))
            }
        }
    }

    /// Check if reconstruction should be started and get columns for reconstruction
    pub fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut states = self.states.write();
        
        if let Some(state) = states.remove(block_root) {
            if state.can_start_reconstruction() {
                // Extract the data we need before moving the state
                let columns = match &state {
                    AvailabilityState::PostPeerDAS { columns, .. } => {
                        columns.columns().to_vec()
                    },
                    _ => {
                        states.insert(*block_root, state);
                        return ReconstructColumnsDecision::No("not in PostPeerDAS state");
                    }
                };
                
                // Now try the state transition
                match state.start_reconstruction() {
                    StateTransition::Changed(new_state) => {
                        states.insert(*block_root, new_state);
                    drop(states); // Release lock before eviction
                    self.maybe_evict();
                    ReconstructColumnsDecision::Yes(columns)
                    },
                    StateTransition::Failed(_) => {
                        ReconstructColumnsDecision::No("failed to start reconstruction")
                    },
                    _ => {
                        ReconstructColumnsDecision::No("unexpected state transition")
                    }
                }
            } else {
                states.insert(*block_root, state);
                ReconstructColumnsDecision::No("not ready for reconstruction")
            }
        } else {
            ReconstructColumnsDecision::No("block not found")
        }
    }

    /// Handle reconstruction failure
    pub fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        let mut states = self.states.write();
        
        if let Some(state) = states.remove(block_root) {
            match state.handle_reconstruction_failure("reconstruction failed".to_string()) {
                StateTransition::Changed(new_state) => {
                    states.insert(*block_root, new_state);
                },
                StateTransition::Completed(_) => {
                    // Reconstruction failure somehow completed the block - this shouldn't happen
                    // but handle it gracefully
                    states.insert(*block_root, AvailabilityState::Failed {
                        block_root: *block_root,
                        error: AvailabilityError::ReconstructionFailed("unexpected completion during failure".to_string()),
                        failed_at: std::time::Instant::now(),
                    });
                },
                StateTransition::Failed(_) => {
                    states.insert(*block_root, AvailabilityState::Failed {
                        block_root: *block_root,
                        error: AvailabilityError::ReconstructionFailed("reconstruction failed".to_string()),
                        failed_at: std::time::Instant::now(),
                    });
                },
                StateTransition::NoChange => {
                    // Create a new failed state since we can't reuse the moved state
                    states.insert(*block_root, AvailabilityState::Failed {
                        block_root: *block_root,
                        error: AvailabilityError::ReconstructionFailed("reconstruction failed".to_string()),
                        failed_at: std::time::Instant::now(),
                    });
                }
            }
        }
        
        // Check capacity and evict if needed after reconstruction failure handling
        self.maybe_evict();
    }

    /// Remove pending components (cleanup)
    pub fn remove_pending_components(&self, block_root: Hash256) {
        self.states.write().remove(&block_root);
        self.lru_order.write().pop_entry(&block_root);
    }

    /// Maintenance cleanup
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // TODO: Add state cache cleanup when implementing full state management

        // Collect keys of blocks to remove (before cutoff_epoch)
        let keys_to_remove: Vec<Hash256> = {
            let states = self.states.read();
            states
                .iter()
                .filter_map(|(key, state)| {
                    if let Some(epoch) = state.epoch() {
                        if epoch < cutoff_epoch {
                            Some(*key)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        };

        // Remove old entries
        if !keys_to_remove.is_empty() {
            let mut states = self.states.write();
            let mut lru = self.lru_order.write();
            
            for key in keys_to_remove {
                states.remove(&key);
                lru.pop_entry(&key);
            }
        }

        Ok(())
    }

    /// Check capacity and evict oldest entries if needed
    fn maybe_evict(&self) {
        let capacity = crate::data_availability_checker_new::OVERFLOW_LRU_CAPACITY.get();
        let mut states = self.states.write();
        let mut lru = self.lru_order.write();
        
        // If over capacity, evict oldest entries
        while states.len() > capacity {
            if let Some((oldest_key, _)) = lru.pop_lru() {
                states.remove(&oldest_key);
                debug!("Evicted block {} from availability cache due to capacity", oldest_key);
            } else {
                break; // No more entries to evict
            }
        }
    }

    /// Enhanced eviction with smart policies (future enhancement)
    fn should_evict_state(&self, state: &AvailabilityState<T::EthSpec>, current_epoch: Epoch) -> bool {
        match state {
            AvailabilityState::Failed { failed_at, .. } => {
                // Evict failed states after 1 minute
                failed_at.elapsed() > std::time::Duration::from_secs(60)
            },
            AvailabilityState::Reconstructing { reconstruction_started_at, .. } => {
                // Evict stuck reconstructions after 5 minutes
                reconstruction_started_at.elapsed() > std::time::Duration::from_secs(300)
            },
            AvailabilityState::Available { completed_at, .. } => {
                // Evict completed blocks after 10 minutes (should have been imported by then)
                completed_at.elapsed() > std::time::Duration::from_secs(600)
            },
            _ => false, // Let standard LRU handle active states
        }
    }

    /// Get cache sizes for metrics
    pub fn state_cache_size(&self) -> usize {
        self.state_cache.lru_cache().read().len()
    }

    pub fn block_cache_size(&self) -> usize {
        self.states.read().len()
    }

    /// Helper to get status string for debugging
    fn get_status_string(&self, state: &AvailabilityState<T::EthSpec>, epoch: Epoch) -> String {
        let block_count = match state {
            AvailabilityState::PreDeneb { .. } |
            AvailabilityState::Reconstructing { .. } |
            AvailabilityState::Available { .. } => 1,
            AvailabilityState::PostDeneb { block, .. } |
            AvailabilityState::PostPeerDAS { block, .. } => {
                if block.is_some() { 1 } else { 0 }
            },
            AvailabilityState::Failed { .. } => 0,
        };

        if self.spec.is_peer_das_enabled_for_epoch(epoch) {
            match state {
                AvailabilityState::PostPeerDAS { columns, expected_column_count, .. } => {
                    format!(
                        "block {} data_columns {}/{}",
                        block_count,
                        columns.column_count(),
                        expected_column_count
                    )
                },
                AvailabilityState::Reconstructing { partial_columns: columns, .. } => {
                    format!(
                        "block {} data_columns {}/? (reconstructing)",
                        block_count,
                        columns.column_count()
                    )
                },
                _ => format!("block {} (PeerDAS epoch)", block_count),
            }
        } else {
            match state {
                AvailabilityState::PostDeneb { blobs, expected_blob_count, .. } => {
                    format!(
                        "block {} blobs {}/{}",
                        block_count,
                        blobs.blob_count(),
                        expected_blob_count
                    )
                },
                _ => format!("block {} (pre-PeerDAS epoch)", block_count),
            }
        }
    }
}

/// Compatibility wrapper to provide the old PendingComponents-like interface
pub struct CompatibilityWrapper<'a, E: EthSpec> {
    state: &'a AvailabilityState<E>,
}

impl<'a, E: EthSpec> CompatibilityWrapper<'a, E> {
    pub fn get_cached_blobs(&self) -> Vec<Option<&crate::blob_verification::KzgVerifiedBlob<E>>> {
        match self.state {
            AvailabilityState::PostDeneb { blobs, .. } => {
                (0..6) // Max blobs per block
                    .map(|i| blobs.get_blob(i))
                    .collect()
            },
            _ => vec![None; 6], // Empty blob list for non-blob states
        }
    }

    pub fn get_cached_data_columns_indices(&self) -> Vec<u64> {
        match self.state {
            AvailabilityState::PostPeerDAS { columns, .. } |
            AvailabilityState::Reconstructing { partial_columns: columns, .. } => {
                columns.cached_indices()
            },
            _ => Vec::new(),
        }
    }

    pub fn get_cached_data_column(&self, index: u64) -> Option<Arc<DataColumnSidecar<E>>> {
        match self.state {
            AvailabilityState::PostPeerDAS { columns, .. } |
            AvailabilityState::Reconstructing { partial_columns: columns, .. } => {
                columns.get_column(index).map(|col| col.clone_arc())
            },
            _ => None,
        }
    }
}

/// Decision for reconstruction (compatibility with existing API)
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<KzgVerifiedCustodyDataColumn<E>>),
    No(&'static str),
}
