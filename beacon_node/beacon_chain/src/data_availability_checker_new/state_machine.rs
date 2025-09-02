use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::AvailabilityPendingExecutedBlock;
use crate::data_availability_checker::DietAvailabilityPendingExecutedBlock;
use crate::data_availability_checker_new::error::{Error as AvailabilityCheckError};
use crate::data_availability_checker_new::collections::{BlobCollection, ColumnCollection};
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use std::time::Instant;
use std::sync::Arc;
use types::{EthSpec, Hash256, ChainSpec, Epoch};
use crate::block_verification_types::AvailableExecutedBlock;

/// Epoch-aware availability states that reflect the fork-based mutual exclusion
pub enum AvailabilityState<E: EthSpec> {
    /// Pre-Deneb blocks require no additional data  
    PreDeneb {
        block: DietAvailabilityPendingExecutedBlock<E>,
    },
    
    /// Post-Deneb, Pre-PeerDAS: requires blob sidecars
    PostDeneb {
        block: Option<DietAvailabilityPendingExecutedBlock<E>>,
        blobs: BlobCollection<E>,
        expected_blob_count: u64,
    },
    
    /// Post-PeerDAS: requires data columns
    PostPeerDAS {
        block: Option<DietAvailabilityPendingExecutedBlock<E>>,
        columns: ColumnCollection<E>, 
        expected_column_count: u64,
    },
    
    /// PeerDAS reconstruction in progress
    Reconstructing {
        block: DietAvailabilityPendingExecutedBlock<E>,
        partial_columns: ColumnCollection<E>,
        reconstruction_started_at: Instant,
    },
    
    /// Block is fully available and ready for import
    Available {
        available_block: AvailableExecutedBlock<E>,
        completed_at: Instant,
    },
    
    /// Terminal failure state
    Failed {
        block_root: Hash256,
        error: AvailabilityError,
        failed_at: Instant,
    },
}

/// Custom error type for availability operations
#[derive(Debug, Clone)]
pub enum AvailabilityError {
    InvalidStateTransition(String),
    MissingComponents(String),
    ReconstructionFailed(String),
    InternalError(String),
}

impl From<AvailabilityError> for AvailabilityCheckError {
    fn from(error: AvailabilityError) -> Self {
        match error {
            AvailabilityError::InvalidStateTransition(msg) => {
                AvailabilityCheckError::Unexpected(format!("Invalid state transition: {}", msg))
            },
            AvailabilityError::MissingComponents(msg) => {
                AvailabilityCheckError::Unexpected(format!("Missing components: {}", msg))
            },
            AvailabilityError::ReconstructionFailed(msg) => {
                AvailabilityCheckError::Unexpected(format!("Reconstruction failed: {}", msg))
            },
            AvailabilityError::InternalError(msg) => {
                AvailabilityCheckError::Unexpected(format!("Internal error: {}", msg))
            },
        }
    }
}

/// Result of a state transition
pub enum StateTransition<E: EthSpec> {
    /// State changed, block not yet available
    Changed(AvailabilityState<E>),
    /// Block became available for import
    Completed(AvailableExecutedBlock<E>),
    /// Terminal failure occurred
    Failed(AvailabilityError),
    /// No change needed
    NoChange,
}

impl<E: EthSpec> AvailabilityState<E> {
    /// Create initial state for a block based on its epoch
    pub fn create_initial_state(
        _block_root: Hash256,
        block: Option<DietAvailabilityPendingExecutedBlock<E>>,
        epoch: Epoch,
        spec: &ChainSpec,
        expected_column_count: u64,
    ) -> Self {
        if !Self::is_deneb_enabled_for_epoch(epoch, spec) {
            // Pre-Deneb: blocks are immediately available
            if let Some(block) = block {
                Self::PreDeneb { block }
            } else {
                panic!("Pre-Deneb blocks should always have the block available immediately")
            }
        } else if spec.is_peer_das_enabled_for_epoch(epoch) {
            // Post-PeerDAS: requires data columns
            Self::PostPeerDAS {
                block,
                columns: ColumnCollection::new(),
                expected_column_count,
            }
        } else {
            // Post-Deneb, Pre-PeerDAS: requires blob sidecars
            let expected_blob_count = block.as_ref()
                .map(|b| b.as_block().num_expected_blobs() as u64)
                .unwrap_or(0u64);
            
            Self::PostDeneb {
                block,
                blobs: BlobCollection::new(spec.max_blobs_per_block(epoch) as usize),
                expected_blob_count,
            }
        }
    }
    
    /// Check if Deneb fork is enabled for the given epoch
    fn is_deneb_enabled_for_epoch(epoch: Epoch, spec: &ChainSpec) -> bool {
        spec.deneb_fork_epoch.is_some_and(|deneb_epoch| epoch >= deneb_epoch)
    }
    
    /// Check if the state can be made available with a recovery function (essential for diet/recovery pattern)
    pub fn make_available<R>(
        &self,
        spec: &ChainSpec,
        expected_column_count: u64,
        recover: R,
    ) -> Result<Option<AvailableExecutedBlock<E>>, AvailabilityError>
    where
        R: FnOnce(DietAvailabilityPendingExecutedBlock<E>) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        // Check if we have all required components based on state
        match self {
            AvailabilityState::PreDeneb { block } => {
                // Pre-Deneb is always available
                let recovered_block = recover(block.clone())
                    .map_err(|e| AvailabilityError::InternalError(format!("Recovery failed: {:?}", e)))?;
                use crate::data_availability_checker::AvailableBlock;
                let available_block = AvailableBlock::__new_for_testing(
                    recovered_block.import_data.block_root,
                    recovered_block.block.clone(),
                    crate::data_availability_checker::AvailableBlockData::NoData,
                    Arc::new(spec.clone()),
                );
                Ok(Some(AvailableExecutedBlock::new(
                    available_block,
                    recovered_block.import_data,
                    recovered_block.payload_verification_outcome,
                )))
            },
            AvailabilityState::PostDeneb { block: Some(diet_block), blobs, expected_blob_count } => {
                if blobs.is_complete(*expected_blob_count) {
                    let recovered_block = recover(diet_block.clone())
                        .map_err(|e| AvailabilityError::InternalError(format!("Recovery failed: {:?}", e)))?;
                    use crate::data_availability_checker::AvailableBlock;
                    let available_block = AvailableBlock::__new_for_testing(
                        recovered_block.import_data.block_root,
                        recovered_block.block.clone(),
                        crate::data_availability_checker::AvailableBlockData::Blobs(
                            blobs.clone().into_blob_list()
                        ),
                        Arc::new(spec.clone()),
                    );
                    Ok(Some(AvailableExecutedBlock::new(
                        available_block,
                        recovered_block.import_data,
                        recovered_block.payload_verification_outcome,
                    )))
                } else {
                    Ok(None) // Still missing blobs
                }
            },
            AvailabilityState::PostPeerDAS { block: Some(diet_block), columns, expected_column_count } => {
                if columns.is_complete(*expected_column_count) {
                    let recovered_block = recover(diet_block.clone())
                        .map_err(|e| AvailabilityError::InternalError(format!("Recovery failed: {:?}", e)))?;
                    use crate::data_availability_checker::AvailableBlock;
                    let available_block = AvailableBlock::__new_for_testing(
                        recovered_block.import_data.block_root,
                        recovered_block.block.clone(),
                        crate::data_availability_checker::AvailableBlockData::DataColumns(
                            columns.clone().into_column_list()
                        ),
                        Arc::new(spec.clone()),
                    );
                    Ok(Some(AvailableExecutedBlock::new(
                        available_block,
                        recovered_block.import_data,
                        recovered_block.payload_verification_outcome,
                    )))
                } else {
                    Ok(None) // Still missing columns
                }
            },
            _ => Ok(None), // Other states not ready
        }
    }

    /// Add a diet block to the state (internal method - just storage)
    pub fn add_diet_block(
        self, 
        diet_block: DietAvailabilityPendingExecutedBlock<E>
    ) -> Self {
        match self {
            AvailabilityState::PreDeneb { .. } => {
                AvailabilityState::PreDeneb { block: diet_block }
            },
            AvailabilityState::PostDeneb { blobs, expected_blob_count, .. } => {
                AvailabilityState::PostDeneb {
                    block: Some(diet_block),
                    blobs,
                    expected_blob_count,
                }
            },
            AvailabilityState::PostPeerDAS { columns, expected_column_count, .. } => {
                AvailabilityState::PostPeerDAS {
                    block: Some(diet_block),
                    columns,
                    expected_column_count,
                }
            },
            AvailabilityState::Reconstructing { partial_columns, reconstruction_started_at, .. } => {
                AvailabilityState::Reconstructing {
                    block: diet_block,
                    partial_columns,
                    reconstruction_started_at,
                }
            },
            // Keep other states unchanged, just update with diet block where applicable
            other => other,
        }
    }
    
    /// Add blob sidecars to the state (Pre-PeerDAS only)
    pub fn add_blobs(
        self, 
        new_blobs: Vec<KzgVerifiedBlob<E>>,
        spec: &ChainSpec,
    ) -> StateTransition<E> {
        match self {
            AvailabilityState::PostDeneb { block, mut blobs, expected_blob_count } => {
                // Merge new blobs into collection
                blobs.merge_blobs(new_blobs);
                
                if let Some(block) = block {
                    if blobs.is_complete(expected_blob_count) {
                        // All blobs received; mark state as complete and let outer layer recover
                        StateTransition::Changed(AvailabilityState::PostDeneb {
                            block: Some(block),
                            blobs,
                            expected_blob_count,
                        })
                    } else {
                        // Still need more blobs
                        StateTransition::Changed(AvailabilityState::PostDeneb {
                            block: Some(block),
                            blobs,
                            expected_blob_count,
                        })
                    }
                } else {
                    // Block not yet received
                    StateTransition::Changed(AvailabilityState::PostDeneb {
                        block: None,
                        blobs,
                        expected_blob_count,
                    })
                }
            },
            // Invalid for other states
            _ => StateTransition::Failed(AvailabilityError::InvalidStateTransition(
                "Cannot add blobs to non-PostDeneb state".to_string()
            ))
        }
    }
    
    /// Add data columns to the state (Post-PeerDAS only)
    pub fn add_columns(
        self, 
        new_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
        spec: &ChainSpec,
    ) -> StateTransition<E> {
        match self {
            AvailabilityState::PostPeerDAS { block, mut columns, expected_column_count } => {
                // Merge new columns into collection
                columns.merge_columns(new_columns);
                
                if let Some(block) = block {
                    if columns.is_complete(expected_column_count) {
                        // All columns received; mark state as complete and let outer layer recover
                        StateTransition::Changed(AvailabilityState::PostPeerDAS {
                            block: Some(block),
                            columns,
                            expected_column_count,
                        })
                    } else {
                        // Check if we can start reconstruction
                        if columns.can_start_reconstruction(expected_column_count) && block.as_block().num_expected_blobs() > 0 {
                            StateTransition::Changed(AvailabilityState::Reconstructing {
                                block,
                                partial_columns: columns,
                                reconstruction_started_at: Instant::now(),
                            })
                        } else {
                            // Still need more columns
                            StateTransition::Changed(AvailabilityState::PostPeerDAS {
                                block: Some(block),
                                columns,
                                expected_column_count,
                            })
                        }
                    }
                } else {
                    // Block not yet received
                    StateTransition::Changed(AvailabilityState::PostPeerDAS {
                        block: None,
                        columns,
                        expected_column_count,
                    })
                }
            },
            AvailabilityState::Reconstructing { block, mut partial_columns, reconstruction_started_at } => {
                // Add columns to reconstruction
                partial_columns.merge_columns(new_columns);
                
                if partial_columns.is_complete_for_reconstruction() {
                    // Reconstruction completed; mark state as complete and let outer layer recover
                    StateTransition::Changed(AvailabilityState::PostPeerDAS {
                        block: Some(block),
                        columns: partial_columns,
                        expected_column_count: 0, // treated as complete
                    })
                } else {
                    // Continue reconstruction
                    StateTransition::Changed(AvailabilityState::Reconstructing {
                        block,
                        partial_columns,
                        reconstruction_started_at,
                    })
                }
            },
            // Invalid for other states
            _ => StateTransition::Failed(AvailabilityError::InvalidStateTransition(
                "Cannot add columns to non-PeerDAS state".to_string()
            ))
        }
    }
    
    /// Helper method to create an available block (simple version)
    // creation of AvailableExecutedBlock is deferred to outer layer where full state recovery exists
    
    // /// Get the block root for this state
    // pub fn block_root(&self) -> Option<Hash256> {
    //     match self {
    //         AvailabilityState::PreDeneb { block } => Some(block.import_data.block_root),
    //         AvailabilityState::PostDeneb { block, .. } => {
    //             block.as_ref().map(|b| b.import_data.block_root)
    //         },
    //         AvailabilityState::PostPeerDAS { block, .. } => {
    //             block.as_ref().map(|b| b.import_data.block_root)
    //         },
    //         AvailabilityState::Reconstructing { block, .. } => Some(block.import_data.block_root),
    //         AvailabilityState::Available { available_block, .. } => Some(available_block.import_data.block_root),
    //         AvailabilityState::Failed { block_root, .. } => Some(*block_root),
    //     }
    // }
    
    /// Get the epoch for this state
    pub fn epoch(&self) -> Option<Epoch> {
        match self {
            AvailabilityState::PreDeneb { block } => Some(block.as_block().epoch()),
            AvailabilityState::PostDeneb { block, .. } => {
                block.as_ref().map(|b| b.as_block().epoch())
            },
            AvailabilityState::PostPeerDAS { block, .. } => {
                block.as_ref().map(|b| b.as_block().epoch())
            },
            AvailabilityState::Reconstructing { block, .. } => Some(block.as_block().epoch()),
            AvailabilityState::Available { .. } => {
                // For Available state, we don't need to track epoch since it's completed
                None
            },
            AvailabilityState::Failed { .. } => None,
        }
    }
    
    /// Check if this state can start reconstruction
    pub fn can_start_reconstruction(&self) -> bool {
        match self {
            AvailabilityState::PostPeerDAS { block, columns, expected_column_count } => {
                block.is_some() && 
                columns.can_start_reconstruction(*expected_column_count) &&
                !columns.reconstruction_started()
            },
            _ => false,
        }
    }
    
    /// Mark reconstruction as started
    pub fn start_reconstruction(self) -> StateTransition<E> {
        match self {
            AvailabilityState::PostPeerDAS { block, columns, .. } if self.can_start_reconstruction() => {
                if let Some(block) = block {
                    StateTransition::Changed(AvailabilityState::Reconstructing {
                        block,
                        partial_columns: columns,
                        reconstruction_started_at: Instant::now(),
                    })
                } else {
                    StateTransition::Failed(AvailabilityError::InvalidStateTransition(
                        "Cannot start reconstruction without block".to_string()
                    ))
                }
            },
            _ => StateTransition::Failed(AvailabilityError::InvalidStateTransition(
                "Cannot start reconstruction from this state".to_string()
            ))
        }
    }
    
    /// Get reconstruction columns if in reconstruction state
    pub fn get_reconstruction_columns(&self) -> Option<&ColumnCollection<E>> {
        match self {
            AvailabilityState::Reconstructing { partial_columns, .. } => Some(partial_columns),
            _ => None,
        }
    }
    
    /// Handle reconstruction failure
    pub fn handle_reconstruction_failure(self, error: String) -> StateTransition<E> {
        match self {
            AvailabilityState::Reconstructing { block, partial_columns, .. } => {
                // Reset to PostPeerDAS state with cleared columns for retry
                StateTransition::Changed(AvailabilityState::PostPeerDAS {
                    block: Some(block),
                    columns: ColumnCollection::new(), // Clear columns for retry
                    expected_column_count: partial_columns.expected_count(),
                })
            },
            _ => StateTransition::Failed(AvailabilityError::ReconstructionFailed(error))
        }
    }
}
