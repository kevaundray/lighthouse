use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::AvailableExecutedBlock;
use crate::data_availability_checker::{AvailableBlock, AvailableBlockData};
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{ColumnIndex, EthSpec, Hash256};

pub type BlobIndex = u64;

/// Holds verified components (blobs and columns) for a block
#[derive(Debug, Clone)]
pub struct VerifiedComponents<E: EthSpec> {
    pub blobs: HashMap<BlobIndex, KzgVerifiedBlob<E>>,
    pub columns: HashMap<ColumnIndex, KzgVerifiedCustodyDataColumn<E>>,
}

impl<E: EthSpec> VerifiedComponents<E> {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            columns: HashMap::new(),
        }
    }
    
    pub fn add_blob(&mut self, blob: KzgVerifiedBlob<E>) -> Result<(), ComponentError> {
        let index = blob.blob_index();
        if self.blobs.contains_key(&index) {
            // Allow replacing with identical blob, reject different ones
            let existing = &self.blobs[&index];
            if existing.kzg_commitment() != blob.kzg_commitment() {
                return Err(ComponentError::ConflictingBlob(index));
            }
        }
        self.blobs.insert(index, blob);
        Ok(())
    }
    
    pub fn add_column(&mut self, column: KzgVerifiedCustodyDataColumn<E>) -> Result<(), ComponentError> {
        let index = column.index();
        if self.columns.contains_key(&index) {
            // Allow replacing with identical column, reject different ones
            let existing = &self.columns[&index];
            if existing.kzg_commitment() != column.kzg_commitment() {
                return Err(ComponentError::ConflictingColumn(index));
            }
        }
        self.columns.insert(index, column);
        Ok(())
    }
    
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }
    
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }
    
    pub fn has_blob(&self, index: BlobIndex) -> bool {
        self.blobs.contains_key(&index)
    }
    
    pub fn has_column(&self, index: ColumnIndex) -> bool {
        self.columns.contains_key(&index)
    }
    
    pub fn get_blob(&self, index: BlobIndex) -> Option<&KzgVerifiedBlob<E>> {
        self.blobs.get(&index)
    }
    
    pub fn get_column(&self, index: ColumnIndex) -> Option<&KzgVerifiedCustodyDataColumn<E>> {
        self.columns.get(&index)
    }
    
    /// Get all blob indices we have
    pub fn blob_indices(&self) -> Vec<BlobIndex> {
        self.blobs.keys().copied().collect()
    }
    
    /// Get all column indices we have
    pub fn column_indices(&self) -> Vec<ColumnIndex> {
        self.columns.keys().copied().collect()
    }
    
    /// Check if we have enough columns to attempt reconstruction
    pub fn can_reconstruct(&self, total_columns: u64) -> bool {
        // Reed-Solomon can reconstruct with 50%+ of data
        self.column_count() >= ((total_columns + 1) / 2) as usize
    }
}

impl<E: EthSpec> Default for VerifiedComponents<E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds partial components during reconstruction
#[derive(Debug, Clone)]
pub struct PartialComponents<E: EthSpec> {
    pub columns: HashMap<ColumnIndex, KzgVerifiedCustodyDataColumn<E>>,
    pub total_expected: u64,
}

impl<E: EthSpec> PartialComponents<E> {
    pub fn new(total_expected: u64) -> Self {
        Self {
            columns: HashMap::new(),
            total_expected,
        }
    }
    
    pub fn from_components(components: VerifiedComponents<E>, total_expected: u64) -> Self {
        Self {
            columns: components.columns,
            total_expected,
        }
    }
    
    pub fn add_column(&mut self, column: KzgVerifiedCustodyDataColumn<E>) -> Result<(), ComponentError> {
        let index = column.index();
        if index >= self.total_expected {
            return Err(ComponentError::IndexOutOfRange(index));
        }
        self.columns.insert(index, column);
        Ok(())
    }
    
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }
    
    pub fn is_complete(&self) -> bool {
        self.column_count() == self.total_expected as usize
    }
    
    pub fn can_reconstruct(&self) -> bool {
        self.column_count() >= ((self.total_expected + 1) / 2) as usize
    }
    
    pub fn missing_indices(&self) -> Vec<ColumnIndex> {
        (0..self.total_expected)
            .filter(|&i| !self.columns.contains_key(&i))
            .collect()
    }
}

/// Requirements for what components a block needs
#[derive(Debug, Clone)]
pub struct ComponentRequirements {
    pub blob_indices: Vec<BlobIndex>,
    pub column_indices: Vec<ColumnIndex>,
    pub can_use_reconstruction: bool,
}

impl ComponentRequirements {
    pub fn new(
        blob_indices: Vec<BlobIndex>, 
        column_indices: Vec<ColumnIndex>,
        can_use_reconstruction: bool,
    ) -> Self {
        Self {
            blob_indices,
            column_indices,
            can_use_reconstruction,
        }
    }
    
    /// Check if components satisfy the requirements
    pub fn is_satisfied_by<E: EthSpec>(&self, components: &VerifiedComponents<E>) -> RequirementCheck {
        let missing_blobs: Vec<_> = self.blob_indices
            .iter()
            .filter(|&&idx| !components.has_blob(idx))
            .copied()
            .collect();
            
        let missing_columns: Vec<_> = self.column_indices
            .iter()
            .filter(|&&idx| !components.has_column(idx))
            .copied()
            .collect();
        
        if missing_blobs.is_empty() && missing_columns.is_empty() {
            RequirementCheck::Complete
        } else if missing_columns.is_empty() || !self.can_use_reconstruction {
            RequirementCheck::Missing { 
                blobs: missing_blobs, 
                columns: missing_columns 
            }
        } else {
            // Check if we can reconstruct the missing columns
            if components.can_reconstruct(self.column_indices.len() as u64) {
                RequirementCheck::CanReconstruct
            } else {
                RequirementCheck::Missing { 
                    blobs: missing_blobs, 
                    columns: missing_columns 
                }
            }
        }
    }
}

/// Result of checking if requirements are met
#[derive(Debug)]
pub enum RequirementCheck {
    /// All requirements satisfied
    Complete,
    /// Missing some components
    Missing {
        blobs: Vec<BlobIndex>,
        columns: Vec<ColumnIndex>,
    },
    /// Can reconstruct missing components
    CanReconstruct,
}

/// Errors that can occur when working with components
/// Convert verified components and block into AvailableExecutedBlock for existing API  
impl<E: EthSpec> AvailableExecutedBlock<E> {
    pub fn from_executed_block_and_components(
        executed_block: AvailableExecutedBlock<E>,
        components: VerifiedComponents<E>,
    ) -> Result<Self, ComponentError> {
        // Create the new AvailableBlock with the components
        let blob_data = if !components.blobs.is_empty() {
            // We have blobs - convert to BlobSidecarList
            let blob_list = components.blobs
                .into_values()
                .map(|blob| blob.clone_blob())
                .collect();
            AvailableBlockData::Blobs(blob_list)
        } else if !components.columns.is_empty() {
            // We have data columns - convert to DataColumnSidecarList  
            let column_list = components.columns
                .into_values()
                .map(|col| col.clone_arc())
                .collect();
            AvailableBlockData::DataColumns(column_list)
        } else {
            // No blob data
            AvailableBlockData::NoData
        };
        
        // Create updated AvailableBlock
        let updated_available_block = AvailableBlock {
            block_root: executed_block.import_data.block_root,
            block: executed_block.block.block_cloned(),
            blob_data,
            blobs_available_timestamp: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
            ),
            spec: executed_block.block.spec.clone(),
        };
        
        // Return AvailableExecutedBlock with updated AvailableBlock
        Ok(AvailableExecutedBlock {
            block: updated_available_block,
            import_data: executed_block.import_data,
            payload_verification_outcome: executed_block.payload_verification_outcome,
        })
    }
}

#[derive(Debug)]
pub enum ComponentError {
    ConflictingBlob(BlobIndex),
    ConflictingColumn(ColumnIndex),
    IndexOutOfRange(ColumnIndex),
    Invalid(String),
}

impl std::fmt::Display for ComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ComponentError::ConflictingBlob(index) => write!(f, "Conflicting blob at index {}", index),
            ComponentError::ConflictingColumn(index) => write!(f, "Conflicting column at index {}", index),
            ComponentError::IndexOutOfRange(index) => write!(f, "Index {} is out of range", index),
            ComponentError::Invalid(msg) => write!(f, "Invalid component: {}", msg),
        }
    }
}

impl std::error::Error for ComponentError {}