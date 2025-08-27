use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{AvailableBlock, AvailableExecutedBlock};
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::BeaconChainTypes;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::{ColumnIndex, Epoch, EthSpec, Hash256};

use super::components::{
    ComponentError, ComponentRequirements, PartialComponents, RequirementCheck, VerifiedComponents,
};

/// Represents all possible states during block availability checking
#[derive(Debug)]
pub enum AvailabilityState<E: EthSpec> {
    /// Have some blobs/columns but waiting for the block
    WaitingForBlock { 
        block_root: Hash256,
        components: VerifiedComponents<E>,
    },
    
    /// Have block but missing required data components
    WaitingForComponents { 
        block_root: Hash256,
        components: VerifiedComponents<E>,
        missing: ComponentRequirements,
    },
    
    /// Currently reconstructing missing data from partial components
    Reconstructing { 
        block_root: Hash256,
        partial_data: PartialComponents<E>,
        started_at: Duration,
    },
    
    /// All required components available and ready for import
    Available { 
        complete: AvailableExecutedBlock<E>,
        completion_time: Duration,
    },
    
    /// Failed to become available (timeout, invalid data, etc.)
    Failed {
        block_root: Hash256,
        reason: FailureReason,
        failed_at: Duration,
    },
}

/// Possible reasons for availability failure
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// Block root mismatch between components
    BlockRootMismatch,
    /// Invalid blob index or commitment mismatch
    InvalidBlob(String),
    /// Invalid data column
    InvalidColumn(String),
    /// Reconstruction failed
    ReconstructionFailed(String),
    /// Timed out waiting for components
    Timeout,
    /// Invalid state transition
    InvalidTransition(String),
}

/// Result of attempting a state transition
#[derive(Debug)]
pub enum StateTransition<E: EthSpec> {
    /// State changed, but not complete
    Changed(AvailabilityState<E>),
    
    /// Block became available
    Completed(AvailabilityState<E>),
    
    /// State unchanged
    Unchanged(AvailabilityState<E>),
    
    /// Input was ignored (already complete, wrong block root, etc.)
    Ignored,
    
    /// Transition rejected due to error
    Rejected(FailureReason),
    
    /// State failed permanently
    Failed(AvailabilityState<E>),
}

impl<E: EthSpec> StateTransition<E> {
    pub fn into_state(self) -> Option<AvailabilityState<E>> {
        match self {
            Self::Changed(s) | Self::Completed(s) | Self::Unchanged(s) | Self::Failed(s) => Some(s),
            Self::Ignored | Self::Rejected(_) => None,
        }
    }
    
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Completed(_))
    }
    
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl<E: EthSpec> AvailabilityState<E> {
    /// Create new state from initial components  
    pub fn from_components(block_root: Hash256) -> Self {
        Self::WaitingForBlock {
            block_root,
            components: VerifiedComponents::new(),
        }
    }
    
    /// Get the block root if known
    pub fn block_root(&self) -> Hash256 {
        match self {
            Self::WaitingForBlock { block_root, .. } => *block_root,
            Self::WaitingForComponents { block_root, .. } => *block_root,
            Self::Reconstructing { block_root, .. } => *block_root,
            Self::Available { complete, .. } => complete.import_data.block_root,
            Self::Failed { block_root, .. } => *block_root,
        }
    }
    
    /// Check if state is terminal (available or failed)
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Available { .. } | Self::Failed { .. })
    }
    
    /// Add a block to the state
    pub fn add_block(self, block: AvailableExecutedBlock<E>) -> StateTransition<E> {
        let block_root = block.import_data.block_root;
        
        match self {
            Self::WaitingForBlock { block_root: waiting_root, components } => {
                if block_root == waiting_root {
                    let requirements = Self::requirements_for_block(&block);
                    match requirements.is_satisfied_by(&components) {
                        RequirementCheck::Complete => {
                            match AvailableExecutedBlock::from_executed_block_and_components(block, components) {
                                Ok(available_executed_block) => StateTransition::Completed(Self::Available {
                                    complete: available_executed_block,
                                    completion_time: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default(),
                                }),
                                Err(e) => StateTransition::Failed(Self::Failed {
                                    block_root,
                                    reason: FailureReason::InvalidTransition(e.to_string()),
                                    failed_at: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default(),
                                }),
                            }
                        },
                        RequirementCheck::CanReconstruct => {
                            StateTransition::Changed(Self::Reconstructing {
                                block_root,
                                partial_data: PartialComponents::from_components(
                                    components,
                                    requirements.column_indices.len() as u64
                                ),
                                started_at: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default(),
                            })
                        },
                        RequirementCheck::Missing { blobs, columns } => {
                            StateTransition::Changed(Self::WaitingForComponents {
                                block_root,
                                components,
                                missing: ComponentRequirements::new(blobs, columns, true),
                            })
                        },
                    }
                } else {
                    StateTransition::Rejected(FailureReason::BlockRootMismatch)
                }
            },
            
            Self::Available { .. } | Self::Failed { .. } => {
                StateTransition::Ignored // Already terminal
            },
            
            _ => StateTransition::Rejected(FailureReason::InvalidTransition(
                "Block already present".to_string()
            )),
        }
    }
    
    /// Add blobs to the state
    pub fn add_blobs(self, blobs: Vec<KzgVerifiedBlob<E>>) -> StateTransition<E> {
        if blobs.is_empty() {
            return StateTransition::Unchanged(self);
        }
        
        let blob_block_root = blobs[0].block_root();
        
        match self {
            Self::WaitingForBlock { block_root, mut components } => {
                if blob_block_root == block_root {
                    // Add blobs to components
                    for blob in blobs {
                        match components.add_blob(blob) {
                            Ok(_) => {},
                            Err(e) => return StateTransition::Rejected(FailureReason::InvalidBlob(e.to_string())),
                        }
                    }
                    StateTransition::Changed(Self::WaitingForBlock { block_root, components })
                } else {
                    StateTransition::Rejected(FailureReason::BlockRootMismatch)
                }
            },
            
            Self::WaitingForComponents { block, mut components, missing } => {
                if blob_block_root == block.import_data.block_root {
                    // Add blobs to components
                    for blob in blobs {
                        match components.add_blob(blob) {
                            Ok(_) => {},
                            Err(e) => return StateTransition::Rejected(FailureReason::InvalidBlob(e.to_string())),
                        }
                    }
                    
                    // Check if we now have all required components
                    match missing.is_satisfied_by(&components) {
                        RequirementCheck::Complete => {
                            match AvailableBlock::from_executed_block_and_components(block, components) {
                                Ok(available_block) => StateTransition::Completed(Self::Available {
                                    complete: available_block,
                                    completion_time: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default(),
                                }),
                                Err(e) => StateTransition::Failed(Self::Failed {
                                    block_root: block.import_data.block_root,
                                    reason: FailureReason::InvalidTransition(e.to_string()),
                                    failed_at: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default(),
                                }),
                            }
                        },
                        RequirementCheck::CanReconstruct => {
                            StateTransition::Changed(Self::Reconstructing {
                                block,
                                partial_data: PartialComponents::from_components(
                                    components,
                                    missing.column_indices.len() as u64
                                ),
                                started_at: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default(),
                            })
                        },
                        RequirementCheck::Missing { blobs: missing_blobs, columns: missing_columns } => {
                            StateTransition::Changed(Self::WaitingForComponents {
                                block,
                                components,
                                missing: ComponentRequirements::new(missing_blobs, missing_columns, true),
                            })
                        },
                    }
                } else {
                    StateTransition::Rejected(FailureReason::BlockRootMismatch)
                }
            },
            
            // Create new WaitingForBlock state if we don't have this block yet
            Self::WaitingForComponents { .. } | Self::Reconstructing { .. } => {
                let mut components = VerifiedComponents::new();
                for blob in blobs {
                    match components.add_blob(blob) {
                        Ok(_) => {},
                        Err(e) => return StateTransition::Rejected(FailureReason::InvalidBlob(e.to_string())),
                    }
                }
                StateTransition::Changed(Self::WaitingForBlock { 
                    block_root: blob_block_root, 
                    components 
                })
            },
            
            _ => StateTransition::Ignored,
        }
    }
    
    /// Helper method to determine requirements for a block
    fn requirements_for_block(block: &AvailableExecutedBlock<E>) -> ComponentRequirements {
        let num_blobs = block.block().message().body().blob_kzg_commitments().len();
        let blob_indices = (0..num_blobs as u64).collect();
        
        // For now, simplified column requirements (this would be more complex in real implementation)
        let column_indices = if block.epoch() >= Epoch::new(0) { // PeerDAS epoch check
            (0..8).collect() // Example: need 8 columns
        } else {
            vec![]
        };
        
        ComponentRequirements::new(blob_indices, column_indices, true)
    }
    
    /// Add data columns to the state  
    pub fn add_columns(self, columns: Vec<KzgVerifiedCustodyDataColumn<E>>) -> StateTransition<E> {
        if columns.is_empty() {
            return StateTransition::Unchanged(self);
        }
        
        let column_block_root = columns[0].block_root();
        
        // Similar logic to add_blobs but for columns
        match self {
            Self::WaitingForBlock { block_root, mut components } => {
                if column_block_root == block_root {
                    for column in columns {
                        match components.add_column(column) {
                            Ok(_) => {},
                            Err(e) => return StateTransition::Rejected(FailureReason::InvalidColumn(e.to_string())),
                        }
                    }
                    StateTransition::Changed(Self::WaitingForBlock { block_root, components })
                } else {
                    StateTransition::Rejected(FailureReason::BlockRootMismatch)
                }
            },
            
            Self::WaitingForComponents { block, mut components, missing } => {
                if column_block_root == block.import_data.block_root {
                    for column in columns {
                        match components.add_column(column) {
                            Ok(_) => {},
                            Err(e) => return StateTransition::Rejected(FailureReason::InvalidColumn(e.to_string())),
                        }
                    }
                    
                    // Check completion status after adding columns
                    self.check_completion_after_update(block, components, missing)
                } else {
                    StateTransition::Rejected(FailureReason::BlockRootMismatch)
                }
            },
            
            _ => StateTransition::Ignored,
        }
    }
    
    /// Helper to check completion status after updating components
    fn check_completion_after_update(
        self,
        block: AvailableExecutedBlock<E>,
        components: VerifiedComponents<E>,
        missing: ComponentRequirements,
    ) -> StateTransition<E> {
        match missing.is_satisfied_by(&components) {
            RequirementCheck::Complete => {
                match AvailableBlock::from_executed_block_and_components(block, components) {
                    Ok(available_block) => StateTransition::Completed(Self::Available {
                        complete: available_block,
                        completion_time: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default(),
                    }),
                    Err(e) => StateTransition::Failed(Self::Failed {
                        block_root: block.import_data.block_root,
                        reason: FailureReason::InvalidTransition(e.to_string()),
                        failed_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default(),
                    }),
                }
            },
            RequirementCheck::CanReconstruct => {
                StateTransition::Changed(Self::Reconstructing {
                    block,
                    partial_data: PartialComponents::from_components(
                        components,
                        missing.column_indices.len() as u64
                    ),
                    started_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default(),
                })
            },
            RequirementCheck::Missing { blobs: missing_blobs, columns: missing_columns } => {
                StateTransition::Changed(Self::WaitingForComponents {
                    block,
                    components,
                    missing: ComponentRequirements::new(missing_blobs, missing_columns, true),
                })
            },
        }
    }
    
    /// Complete reconstruction with the reconstructed columns
    pub fn complete_reconstruction(
        self, 
        reconstructed_columns: Vec<KzgVerifiedCustodyDataColumn<E>>
    ) -> StateTransition<E> {
        match self {
            Self::Reconstructing { block, mut partial_data, started_at: _ } => {
                // Add reconstructed columns to partial data
                for column in reconstructed_columns {
                    match partial_data.add_column(column) {
                        Ok(_) => {},
                        Err(e) => return StateTransition::Failed(Self::Failed {
                            block_root: block.import_data.block_root,
                            reason: FailureReason::ReconstructionFailed(e.to_string()),
                            failed_at: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default(),
                        }),
                    }
                }
                
                // Check if reconstruction is complete
                if partial_data.is_complete() {
                    // Convert to components and create available block
                    let mut components = VerifiedComponents::new();
                    for (_, column) in partial_data.columns {
                        components.add_column(column).ok(); // We know these are valid
                    }
                    
                    match AvailableBlock::from_executed_block_and_components(&block, components) {
                        Ok(available_block) => StateTransition::Completed(Self::Available {
                            complete: available_block,
                            completion_time: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default(),
                        }),
                        Err(e) => StateTransition::Failed(Self::Failed {
                            block_root: block.import_data.block_root,
                            reason: FailureReason::ReconstructionFailed(e.to_string()),
                            failed_at: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default(),
                        }),
                    }
                } else {
                    StateTransition::Failed(Self::Failed {
                        block_root: block.import_data.block_root,
                        reason: FailureReason::ReconstructionFailed(
                            "Reconstruction did not complete successfully".to_string()
                        ),
                        failed_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default(),
                    })
                }
            },
            other => StateTransition::Unchanged(other),
        }
    }
    
    /// Mark state as failed
    pub fn mark_failed(self, reason: FailureReason) -> StateTransition<E> {
        let block_root = self.block_root();
        StateTransition::Failed(Self::Failed {
            block_root,
            reason,
            failed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        })
    }
}

impl<E: EthSpec> Default for AvailabilityState<E> {
    fn default() -> Self {
        Self::new()
    }
}