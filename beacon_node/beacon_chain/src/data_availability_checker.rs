use crate::blob_verification::{verify_kzg_for_blob_list, GossipVerifiedBlob, KzgVerifiedBlob};
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableExecutedBlock, RpcBlock,
};
use crate::{BeaconChain, BeaconChainTypes, BeaconStore, CustodyContext};
use kzg::Kzg;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tracing::{debug, error, info_span, Instrument};
use types::blob_sidecar::{BlobIdentifier, BlobSidecar, FixedBlobSidecarList};
use types::{
    BlobSidecarList, ChainSpec, DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Hash256,
    RuntimeVariableList, SignedBeaconBlock,
};

mod error;
mod state_machine;
mod components;
#[cfg(test)]
mod state_machine_tests;

use crate::data_column_verification::{
    verify_kzg_for_data_column_list_with_scoring, CustodyDataColumn, GossipVerifiedDataColumn,
    KzgVerifiedCustodyDataColumn, KzgVerifiedDataColumn,
};
use crate::observed_data_sidecars::ObservationStrategy;
pub use error::{Error as AvailabilityCheckError, ErrorCategory as AvailabilityCheckErrorCategory};

use components::{ComponentError, VerifiedComponents};
use state_machine::{AvailabilityState, StateTransition};

/// Maximum number of availability states to track concurrently
const MAX_AVAILABILITY_STATES: usize = 1024;

/// Data availability checker using explicit state machine.
/// 
/// Manages the availability checking process for post-Deneb blocks that require
/// blob sidecars or data columns. Uses a clean state machine to track each block's
/// progress from receiving initial components to becoming fully available.
pub struct DataAvailabilityChecker<T: BeaconChainTypes> {
    /// State machines for each block being tracked
    states: RwLock<HashMap<Hash256, AvailabilityState<T::EthSpec>>>,
    
    /// Slot clock for time-based operations
    slot_clock: T::SlotClock,
    
    /// KZG cryptographic operations
    kzg: Arc<Kzg>,
    
    /// Custody context for data sampling
    custody_context: Arc<CustodyContext>,
    
    /// Chain specification  
    spec: Arc<ChainSpec>,
}

pub type AvailabilityAndReconstructedColumns<E> = (Availability<E>, DataColumnSidecarList<E>);

#[derive(Debug)]
pub enum DataColumnReconstructionResult<E: EthSpec> {
    Success(AvailabilityAndReconstructedColumns<E>),
    NotStarted(&'static str),
    RecoveredColumnsNotImported(&'static str),
}

/// This type is returned after adding a block / blob to the `DataAvailabilityChecker`.
///
/// Indicates if the block is fully `Available` or if we need blobs or blocks
///  to "complete" the requirements for an `AvailableBlock`.
pub enum Availability<E: EthSpec> {
    MissingComponents(Hash256),
    Available(Box<AvailableExecutedBlock<E>>),
}

impl<E: EthSpec> Debug for Availability<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingComponents(block_root) => {
                write!(f, "MissingComponents({})", block_root)
            }
            Self::Available(block) => write!(f, "Available({:?})", block.import_data.block_root),
        }
    }
}

impl<T: BeaconChainTypes> DataAvailabilityChecker<T> {
    pub fn new(
        slot_clock: T::SlotClock,
        kzg: Arc<Kzg>,
        _store: BeaconStore<T>,
        custody_context: Arc<CustodyContext>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            states: RwLock::new(HashMap::new()),
            slot_clock,
            kzg,
            custody_context,
            spec,
        })
    }

    pub fn custody_context(&self) -> Arc<CustodyContext> {
        self.custody_context.clone()
    }

    /// Checks if the block root is currently in the availability cache awaiting import because
    /// of missing components.
    pub fn get_execution_valid_block(
        &self,
        block_root: &Hash256,
    ) -> Option<Arc<SignedBeaconBlock<T::EthSpec>>> {
        let states = self.states.read();
        let Some(state) = states.get(block_root) else {
            return None;
        };
        
        match state {
            AvailabilityState::Available { complete, .. } => {
                Some(complete.block.block_cloned())
            },
            _ => None, // For now, only return blocks that are fully available
        }
    }

    /// Return the set of cached blob indexes for `block_root`. Returns None if there is no block
    /// component for `block_root`.
    pub fn cached_blob_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        let states = self.states.read();
        if let Some(state) = states.get(block_root) {
            match state {
                AvailabilityState::WaitingForBlock { components, .. } |
                AvailabilityState::WaitingForComponents { components, .. } => {
                    Some(components.blob_indices())
                },
                _ => None,
            }
        } else {
            None
        }
    }

    /// Return the set of cached custody column indexes for `block_root`. Returns None if there is
    /// no block component for `block_root`.
    pub fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        let states = self.states.read();
        if let Some(state) = states.get(block_root) {
            match state {
                AvailabilityState::WaitingForBlock { components, .. } |
                AvailabilityState::WaitingForComponents { components, .. } => {
                    Some(components.column_indices())
                },
                _ => None,
            }
        } else {
            None
        }
    }

    /// Check if the exact data column is in the availability cache.
    pub fn is_data_column_cached(
        &self,
        block_root: &Hash256,
        data_column: &DataColumnSidecar<T::EthSpec>,
    ) -> bool {
        let states = self.states.read();
        if let Some(state) = states.get(block_root) {
            match state {
                AvailabilityState::WaitingForBlock { components, .. } |
                AvailabilityState::WaitingForComponents { components, .. } => {
                    components.has_column(data_column.index) &&
                    components.get_column(data_column.index)
                        .map_or(false, |cached| cached.as_data_column() == data_column)
                },
                _ => false,
            }
        } else {
            false
        }
    }

    /// Get a blob from the availability cache.
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        let states = self.states.read();
        if let Some(state) = states.get(&blob_id.block_root) {
            match state {
                AvailabilityState::WaitingForBlock { components, .. } |
                AvailabilityState::WaitingForComponents { components, .. } => {
                    Ok(components.get_blob(blob_id.index).map(|blob| blob.clone_blob()))
                },
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Get data columns for a block from the availability cache.
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        let states = self.states.read();
        if let Some(state) = states.get(&block_root) {
            match state {
                AvailabilityState::WaitingForBlock { components, .. } |
                AvailabilityState::WaitingForComponents { components, .. } => {
                    Some(components.columns.values().map(|col| col.clone_arc()).collect())
                },
                _ => None,
            }
        } else {
            None
        }
    }

    /// Check if we have all the blobs for a block. Returns `Availability` which has information
    /// about whether all components have been received or more are required.
    pub fn put_pending_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Convert pending block to executed block  
        let available_executed = self.convert_pending_to_executed(executed_block)?;
        let block_root = available_executed.import_data.block_root;
        
        let mut states = self.states.write();
        let current_state = states
            .remove(&block_root)
            .unwrap_or_else(|| AvailabilityState::from_components(block_root));
        
        match current_state.add_block(available_executed) {
            StateTransition::Completed(AvailabilityState::Available { complete, .. }) => {
                // Don't store completed states - return immediately
                Ok(Availability::Available(Box::new(complete)))
            },
            StateTransition::Changed(new_state) | StateTransition::Unchanged(new_state) => {
                states.insert(block_root, new_state);
                self.maybe_evict_old_states(&mut states);
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Failed(failed_state) => {
                states.insert(block_root, failed_state);
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
            StateTransition::Ignored => {
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Rejected(_reason) => {
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
        }
    }

    /// Check if we've cached other blobs for this block. If it completes a set and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    /// Otherwise cache the blob sidecar.
    pub fn put_gossip_verified_blobs<
        I: IntoIterator<Item = GossipVerifiedBlob<T, O>>,
        O: ObservationStrategy,
    >(
        &self,
        block_root: Hash256,
        blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let kzg_verified_blobs: Vec<_> = blobs.into_iter().map(|b| b.into_inner()).collect();
        self.put_kzg_verified_blobs(block_root, kzg_verified_blobs)
    }

    /// Check if we've cached other data columns for this block. If it satisfies the custody requirement and we also
    /// have a block cached, return the `Availability` variant triggering block import.
    pub fn put_gossip_verified_data_columns<
        O: ObservationStrategy,
        I: IntoIterator<Item = GossipVerifiedDataColumn<T, O>>,
    >(
        &self,
        block_root: Hash256,
        data_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let custody_columns = data_columns
            .into_iter()
            .map(|c| KzgVerifiedCustodyDataColumn::from_asserted_custody(c.into_inner()))
            .collect::<Vec<_>>();

        self.put_kzg_verified_data_columns(block_root, custody_columns)
    }

    pub fn put_kzg_verified_custody_data_columns<
        I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    >(
        &self,
        block_root: Hash256,
        custody_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        self.put_kzg_verified_data_columns(block_root, custody_columns.into_iter().collect())
    }

    /// Put a list of blobs received via RPC into the availability cache. This performs KZG
    /// verification on the blobs in the list.
    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let seen_timestamp = self
            .slot_clock
            .now_duration()
            .ok_or(AvailabilityCheckError::SlotClockError)?;

        // Verify KZG for all blobs
        let mut verified_blobs = Vec::new();
        for blob_opt in blobs.iter() {
            if let Some(blob) = blob_opt {
                let kzg_verified = KzgVerifiedBlob::new(blob.clone(), &self.kzg, seen_timestamp)
                    .map_err(AvailabilityCheckError::InvalidBlobs)?;
                verified_blobs.push(kzg_verified);
            }
        }

        self.put_kzg_verified_blobs(block_root, verified_blobs)
    }

    /// Put a list of custody columns received via RPC into the availability cache.
    #[allow(clippy::type_complexity)]
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        // Verify KZG for all data columns
        let kzg_verified_columns =
            KzgVerifiedDataColumn::from_batch_with_scoring(custody_columns, &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;

        let verified_custody_columns = kzg_verified_columns
            .into_iter()
            .map(KzgVerifiedCustodyDataColumn::from_asserted_custody)
            .collect::<Vec<_>>();

        self.put_kzg_verified_data_columns(block_root, verified_custody_columns)
    }

    pub fn remove_pending_components(&self, block_root: Hash256) {
        self.states.write().remove(&block_root);
    }

    /// Verifies kzg commitments for an RpcBlock, returns a `MaybeAvailableBlock` that may
    /// include the fully available block.
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_block(
        &self,
        block: RpcBlock<T::EthSpec>,
    ) -> Result<MaybeAvailableBlock<T::EthSpec>, AvailabilityCheckError> {
        let (block_root, block, blobs, data_columns) = block.deconstruct();
        if self.blobs_required_for_block(&block) {
            return if let Some(blob_list) = blobs {
                verify_kzg_for_blob_list(blob_list.iter(), &self.kzg)
                    .map_err(AvailabilityCheckError::InvalidBlobs)?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blob_data: AvailableBlockData::Blobs(blob_list),
                    blobs_available_timestamp: None,
                    spec: self.spec.clone(),
                }))
            } else {
                Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
            };
        }
        if self.data_columns_required_for_block(&block) {
            return if let Some(data_column_list) = data_columns.as_ref() {
                verify_kzg_for_data_column_list_with_scoring(
                    data_column_list
                        .iter()
                        .map(|custody_column| custody_column.as_data_column()),
                    &self.kzg,
                )
                .map_err(AvailabilityCheckError::InvalidColumn)?;
                Ok(MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blob_data: AvailableBlockData::DataColumns(
                        data_column_list
                            .into_iter()
                            .map(|d| d.clone_arc())
                            .collect(),
                    ),
                    blobs_available_timestamp: None,
                    spec: self.spec.clone(),
                }))
            } else {
                Ok(MaybeAvailableBlock::AvailabilityPending { block_root, block })
            };
        }

        Ok(MaybeAvailableBlock::Available(AvailableBlock {
            block_root,
            block,
            blob_data: AvailableBlockData::NoData,
            blobs_available_timestamp: None,
            spec: self.spec.clone(),
        }))
    }

    /// Checks if a vector of blocks are available. Returns a vector of `MaybeAvailableBlock`
    /// This is more efficient than calling `verify_kzg_for_rpc_block` in a loop as it does
    /// all kzg verification at once
    ///
    /// WARNING: This function assumes all required blobs are already present, it does NOT
    ///          check if there are any missing blobs.
    pub fn verify_kzg_for_rpc_blocks(
        &self,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<Vec<MaybeAvailableBlock<T::EthSpec>>, AvailabilityCheckError> {
        let mut results = Vec::with_capacity(blocks.len());
        let all_blobs = blocks
            .iter()
            .filter(|block| self.blobs_required_for_block(block.as_block()))
            .filter_map(|block| block.blobs().cloned())
            .flatten()
            .collect::<Vec<_>>();

        // verify kzg for all blobs at once
        if !all_blobs.is_empty() {
            verify_kzg_for_blob_list(all_blobs.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidBlobs)?;
        }

        let all_data_columns = blocks
            .iter()
            .filter(|block| self.data_columns_required_for_block(block.as_block()))
            .filter_map(|block| block.custody_columns().cloned())
            .flatten()
            .map(CustodyDataColumn::into_inner)
            .collect::<Vec<_>>();
        let all_data_columns =
            RuntimeVariableList::from_vec(all_data_columns, self.spec.number_of_columns as usize);

        // verify kzg for all data columns at once
        if !all_data_columns.is_empty() {
            verify_kzg_for_data_column_list_with_scoring(all_data_columns.iter(), &self.kzg)
                .map_err(AvailabilityCheckError::InvalidColumn)?;
        }

        for block in blocks {
            let (block_root, block, blobs, data_columns) = block.deconstruct();

            let maybe_available_block = if self.blobs_required_for_block(&block) {
                if let Some(blobs) = blobs {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blob_data: AvailableBlockData::Blobs(blobs),
                        blobs_available_timestamp: None,
                        spec: self.spec.clone(),
                    })
                } else {
                    MaybeAvailableBlock::AvailabilityPending { block_root, block }
                }
            } else if self.data_columns_required_for_block(&block) {
                if let Some(data_columns) = data_columns {
                    MaybeAvailableBlock::Available(AvailableBlock {
                        block_root,
                        block,
                        blob_data: AvailableBlockData::DataColumns(
                            data_columns.into_iter().map(|d| d.into_inner()).collect(),
                        ),
                        blobs_available_timestamp: None,
                        spec: self.spec.clone(),
                    })
                } else {
                    MaybeAvailableBlock::AvailabilityPending { block_root, block }
                }
            } else {
                MaybeAvailableBlock::Available(AvailableBlock {
                    block_root,
                    block,
                    blob_data: AvailableBlockData::NoData,
                    blobs_available_timestamp: None,
                    spec: self.spec.clone(),
                })
            };

            results.push(maybe_available_block);
        }

        Ok(results)
    }

    /// Determines the blob requirements for a block. If the block is pre-deneb, no blobs are required.
    /// If the epoch is from prior to the data availability boundary, no blobs are required.
    pub fn blobs_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.da_check_required_for_epoch(epoch) && !self.spec.is_peer_das_enabled_for_epoch(epoch)
    }

    /// Determines the data column requirements for an epoch.
    /// - If the epoch is pre-peerdas, no data columns are required.
    /// - If the epoch is from prior to the data availability boundary, no data columns are required.
    pub fn data_columns_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.da_check_required_for_epoch(epoch) && self.spec.is_peer_das_enabled_for_epoch(epoch)
    }

    /// See `Self::blobs_required_for_epoch`
    fn blobs_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.blobs_required_for_epoch(block.epoch())
    }

    /// See `Self::data_columns_required_for_epoch`
    fn data_columns_required_for_block(&self, block: &SignedBeaconBlock<T::EthSpec>) -> bool {
        block.num_expected_blobs() > 0 && self.data_columns_required_for_epoch(block.epoch())
    }

    /// The epoch at which we require a data availability check in block processing.
    /// `None` if the `Deneb` fork is disabled.
    pub fn data_availability_boundary(&self) -> Option<Epoch> {
        let current_epoch = self.slot_clock.now()?.epoch(T::EthSpec::slots_per_epoch());
        self.spec
            .min_epoch_data_availability_boundary(current_epoch)
    }

    /// Returns true if the given epoch lies within the da boundary and false otherwise.
    pub fn da_check_required_for_epoch(&self, block_epoch: Epoch) -> bool {
        self.data_availability_boundary()
            .is_some_and(|da_epoch| block_epoch >= da_epoch)
    }

    /// Returns `true` if the current epoch is greater than or equal to the `Deneb` epoch.
    pub fn is_deneb(&self) -> bool {
        self.slot_clock.now().is_some_and(|slot| {
            self.spec.deneb_fork_epoch.is_some_and(|deneb_epoch| {
                let now_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
                now_epoch >= deneb_epoch
            })
        })
    }

    /// Collects metrics from the data availability checker.
    pub fn metrics(&self) -> DataAvailabilityCheckerMetrics {
        let states = self.states.read();
        DataAvailabilityCheckerMetrics {
            state_cache_size: 0, // No separate state cache 
            block_cache_size: states.len(),
        }
    }

    pub fn reconstruct_data_columns(
        &self,
        _block_root: &Hash256,
    ) -> Result<DataColumnReconstructionResult<T::EthSpec>, AvailabilityCheckError> {
        // Simplified reconstruction - for now just return not started
        // This would need full implementation for production use
        Ok(DataColumnReconstructionResult::NotStarted("Reconstruction not implemented yet"))
    }

    /// Helper methods from helpers.rs integrated here

    /// Internal helper to process KZG verified blobs using state machine
    fn put_kzg_verified_blobs(
        &self,
        block_root: Hash256,
        blobs: Vec<KzgVerifiedBlob<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if blobs.is_empty() {
            return Ok(Availability::MissingComponents(block_root));
        }

        let mut states = self.states.write();
        let current_state = states
            .remove(&block_root)
            .unwrap_or_else(|| AvailabilityState::from_components(block_root));
        
        match current_state.add_blobs(blobs) {
            StateTransition::Completed(AvailabilityState::Available { complete, .. }) => {
                Ok(Availability::Available(Box::new(complete)))
            },
            StateTransition::Changed(new_state) | StateTransition::Unchanged(new_state) => {
                states.insert(block_root, new_state);
                self.maybe_evict_old_states(&mut states);
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Failed(failed_state) => {
                states.insert(block_root, failed_state);
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
            StateTransition::Ignored => {
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Rejected(_reason) => {
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
        }
    }

    /// Internal helper to process KZG verified data columns using state machine
    fn put_kzg_verified_data_columns(
        &self,
        block_root: Hash256,
        columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if columns.is_empty() {
            return Ok(Availability::MissingComponents(block_root));
        }

        let mut states = self.states.write();
        let current_state = states
            .remove(&block_root)
            .unwrap_or_else(|| AvailabilityState::from_components(block_root));
        
        match current_state.add_columns(columns) {
            StateTransition::Completed(AvailabilityState::Available { complete, .. }) => {
                Ok(Availability::Available(Box::new(complete)))
            },
            StateTransition::Changed(new_state) | StateTransition::Unchanged(new_state) => {
                states.insert(block_root, new_state);
                self.maybe_evict_old_states(&mut states);
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Failed(failed_state) => {
                states.insert(block_root, failed_state);
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
            StateTransition::Ignored => {
                Ok(Availability::MissingComponents(block_root))
            },
            StateTransition::Rejected(_reason) => {
                Err(AvailabilityCheckError::UnknownBlock(block_root))
            },
        }
    }

    /// Convert pending executed block to available executed block
    fn convert_pending_to_executed(
        &self,
        pending: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<AvailableExecutedBlock<T::EthSpec>, AvailabilityCheckError> {
        // For now, we can directly convert since the types are similar
        // In a more complete implementation, this might need state reconstruction
        
        // Create a basic AvailableBlock from the pending block
        let available_block = AvailableBlock {
            block_root: pending.import_data.block_root,
            block: pending.block.clone(),
            blob_data: AvailableBlockData::NoData, // Will be updated when components arrive
            blobs_available_timestamp: None,
            spec: self.spec.clone(),
        };
        
        Ok(AvailableExecutedBlock {
            block: available_block,
            import_data: pending.import_data,
            payload_verification_outcome: pending.payload_verification_outcome,
        })
    }

    /// Evict old states if we're over capacity
    fn maybe_evict_old_states(
        &self,
        states: &mut HashMap<Hash256, AvailabilityState<T::EthSpec>>
    ) {
        if states.len() > MAX_AVAILABILITY_STATES {
            // Simple eviction strategy: remove failed states first, then oldest
            let mut to_remove = Vec::new();
            
            // First remove failed states
            for (root, state) in states.iter() {
                if matches!(state, AvailabilityState::Failed { .. }) {
                    to_remove.push(*root);
                    if states.len() - to_remove.len() <= MAX_AVAILABILITY_STATES {
                        break;
                    }
                }
            }
            
            for root in to_remove {
                states.remove(&root);
            }
            
            // If still over capacity, remove some more
            if states.len() > MAX_AVAILABILITY_STATES {
                let excess = states.len() - MAX_AVAILABILITY_STATES;
                let keys_to_remove: Vec<_> = states.keys().take(excess).copied().collect();
                for key in keys_to_remove {
                    states.remove(&key);
                }
            }
        }
    }
}

/// Helper struct to group data availability checker metrics.
pub struct DataAvailabilityCheckerMetrics {
    pub state_cache_size: usize,
    pub block_cache_size: usize,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // Simplified maintenance service for our new state machine implementation
    if chain.spec.deneb_fork_epoch.is_some() {
        executor.spawn(
            async move {
                availability_cache_maintenance_service(chain)
                    .instrument(info_span!(
                        "DataAvailabilityChecker",
                        service = "data_availability_checker"
                    ))
                    .await
            },
            "availability_cache_service",
        );
    } else {
        debug!("Deneb fork not configured, not starting availability cache maintenance service");
    }
}

async fn availability_cache_maintenance_service<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) {
    let epoch_duration = chain.slot_clock.slot_duration() * T::EthSpec::slots_per_epoch() as u32;
    loop {
        match chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
        {
            Some(duration) => {
                // this service should run 3/4 of the way through the epoch
                let additional_delay = (epoch_duration * 3) / 4;
                tokio::time::sleep(duration + additional_delay).await;

                let Some(deneb_fork_epoch) = chain.spec.deneb_fork_epoch else {
                    break;
                };

                debug!("Availability cache maintenance service firing");
                let Some(current_epoch) = chain
                    .slot_clock
                    .now()
                    .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
                else {
                    continue;
                };

                if current_epoch < deneb_fork_epoch {
                    continue;
                }

                // Simple cleanup for our new implementation - remove failed states
                let mut states_to_remove = Vec::new();
                {
                    let states = chain.data_availability_checker.states.read();
                    for (block_root, state) in states.iter() {
                        if matches!(state, AvailabilityState::Failed { .. }) {
                            states_to_remove.push(*block_root);
                        }
                    }
                }

                if !states_to_remove.is_empty() {
                    let mut states = chain.data_availability_checker.states.write();
                    for block_root in states_to_remove {
                        states.remove(&block_root);
                    }
                }
            }
            None => {
                error!("Failed to read slot clock");
                tokio::time::sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
}

#[derive(Debug)]
pub enum AvailableBlockData<E: EthSpec> {
    /// Block is pre-Deneb or has zero blobs
    NoData,
    /// Block is post-Deneb, pre-PeerDAS and has more than zero blobs
    Blobs(BlobSidecarList<E>),
    /// Block is post-PeerDAS and has more than zero blobs
    DataColumns(DataColumnSidecarList<E>),
}

/// A fully available block that is ready to be imported into fork choice.
#[derive(Debug)]
pub struct AvailableBlock<E: EthSpec> {
    block_root: Hash256,
    block: Arc<SignedBeaconBlock<E>>,
    blob_data: AvailableBlockData<E>,
    /// Timestamp at which this block first became available (UNIX timestamp, time since 1970).
    blobs_available_timestamp: Option<Duration>,
    pub spec: Arc<ChainSpec>,
}

impl<E: EthSpec> AvailableBlock<E> {
    pub fn __new_for_testing(
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
        data: AvailableBlockData<E>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            block_root,
            block,
            blob_data: data,
            blobs_available_timestamp: None,
            spec,
        }
    }

    pub fn block(&self) -> &SignedBeaconBlock<E> {
        &self.block
    }
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        self.block.clone()
    }

    pub fn blobs_available_timestamp(&self) -> Option<Duration> {
        self.blobs_available_timestamp
    }

    pub fn data(&self) -> &AvailableBlockData<E> {
        &self.blob_data
    }

    pub fn has_blobs(&self) -> bool {
        match self.blob_data {
            AvailableBlockData::NoData => false,
            AvailableBlockData::Blobs(..) => true,
            AvailableBlockData::DataColumns(_) => false,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn deconstruct(self) -> (Hash256, Arc<SignedBeaconBlock<E>>, AvailableBlockData<E>) {
        let AvailableBlock {
            block_root,
            block,
            blob_data,
            ..
        } = self;
        (block_root, block, blob_data)
    }

    /// Only used for testing
    pub fn __clone_without_recv(&self) -> Result<Self, String> {
        Ok(Self {
            block_root: self.block_root,
            block: self.block.clone(),
            blob_data: match &self.blob_data {
                AvailableBlockData::NoData => AvailableBlockData::NoData,
                AvailableBlockData::Blobs(blobs) => AvailableBlockData::Blobs(blobs.clone()),
                AvailableBlockData::DataColumns(data_columns) => {
                    AvailableBlockData::DataColumns(data_columns.clone())
                }
            },
            blobs_available_timestamp: self.blobs_available_timestamp,
            spec: self.spec.clone(),
        })
    }
}

#[derive(Debug)]
pub enum MaybeAvailableBlock<E: EthSpec> {
    /// This variant is fully available.
    /// i.e. for pre-deneb blocks, it contains a (`SignedBeaconBlock`, `Blobs::None`) and for
    /// post-4844 blocks, it contains a `SignedBeaconBlock` and a Blobs variant other than `Blobs::None`.
    Available(AvailableBlock<E>),
    /// This variant is not fully available and requires blobs to become fully available.
    AvailabilityPending {
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<E>>,
    },
}

impl<E: EthSpec> MaybeAvailableBlock<E> {
    pub fn block_cloned(&self) -> Arc<SignedBeaconBlock<E>> {
        match self {
            Self::Available(block) => block.block_cloned(),
            Self::AvailabilityPending { block, .. } => block.clone(),
        }
    }
}