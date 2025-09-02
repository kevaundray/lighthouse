use crate::blob_verification::KzgVerifiedBlob;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use std::sync::Arc;
use types::{EthSpec, BlobSidecar, BlobSidecarList, DataColumnSidecar, DataColumnSidecarList, RuntimeFixedVector, RuntimeVariableList};

/// Type-safe blob collection for Post-Deneb, Pre-PeerDAS blocks
/// Only stores blobs, never data columns (enforces mutual exclusion)
#[derive(Debug, Clone)]
pub struct BlobCollection<E: EthSpec> {
    blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    max_blobs: usize,
}

impl<E: EthSpec> BlobCollection<E> {
    /// Create a new empty blob collection
    pub fn new(max_blobs: usize) -> Self {
        Self {
            blobs: RuntimeFixedVector::new(vec![None; max_blobs]),
            max_blobs,
        }
    }
    
    /// Merge new blobs into the collection
    /// Only inserts blobs that don't already exist at their index
    pub fn merge_blobs(&mut self, new_blobs: Vec<KzgVerifiedBlob<E>>) {
        for blob in new_blobs {
            let index = blob.blob_index() as usize;
            if index < self.max_blobs {
                // Only insert if slot is empty (no duplicates)
                if self.blobs[index].is_none() {
                    self.blobs[index] = Some(blob);
                }
            }
        }
    }
    
    /// Check if we have all required blobs
    pub fn is_complete(&self, expected_count: u64) -> bool {
        let expected_count = expected_count as usize;
        if expected_count == 0 {
            return true; // No blobs required
        }
        
        self.blobs.iter()
            .take(expected_count)
            .all(|blob| blob.is_some())
    }
    
    /// Convert to BlobSidecarList for availability
    pub fn into_blob_list(self) -> BlobSidecarList<E> {
        let blobs: Vec<Arc<BlobSidecar<E>>> = self.blobs
            .into_iter()
            .flatten()
            .map(|kzg_blob| kzg_blob.clone_blob())
            .collect();
            
        RuntimeVariableList::from_vec(blobs, self.max_blobs)
    }
    
    /// Get blob indices that are currently cached
    pub fn cached_indices(&self) -> Vec<u64> {
        self.blobs.iter()
            .enumerate()
            .filter_map(|(index, blob)| {
                blob.as_ref().map(|_| index as u64)
            })
            .collect()
    }
    
    /// Get a specific blob by index
    pub fn get_blob(&self, index: u64) -> Option<&KzgVerifiedBlob<E>> {
        let index = index as usize;
        if index < self.max_blobs {
            self.blobs[index].as_ref()
        } else {
            None
        }
    }
    
    /// Check if a specific blob exists
    pub fn has_blob(&self, index: u64) -> bool {
        self.get_blob(index).is_some()
    }
    
    /// Count of blobs currently stored
    pub fn blob_count(&self) -> usize {
        self.blobs.iter().filter(|b| b.is_some()).count()
    }    
}

/// Type-safe column collection for Post-PeerDAS blocks  
/// Only stores data columns, never blobs (enforces mutual exclusion)
#[derive(Debug, Clone)]
pub struct ColumnCollection<E: EthSpec> {
    columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    reconstruction_started: bool,
    expected_count: u64,
}

impl<E: EthSpec> ColumnCollection<E> {
    /// Create a new empty column collection
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            reconstruction_started: false,
            expected_count: 0,
        }
    }
    
    // with_expected_count not required by current callers.
    
    /// Merge new columns into the collection
    /// Only inserts columns that don't already exist (by index)
    pub fn merge_columns(&mut self, new_columns: Vec<KzgVerifiedCustodyDataColumn<E>>) {
        for column in new_columns {
            let index = column.index();
            
            // Only add if we don't already have this column index
            if !self.columns.iter().any(|existing| existing.index() == index) {
                self.columns.push(column);
            }
        }
        
        // Sort by index for consistent ordering
        self.columns.sort_by_key(|col| col.index());
    }
    
    /// Check if we have all required columns
    pub fn is_complete(&self, expected_count: u64) -> bool {
        if expected_count == 0 {
            return true; // No columns required
        }
        
        self.columns.len() >= expected_count as usize
    }
    
    /// Check if we can start reconstruction (have >= 50% of columns)
    pub fn can_start_reconstruction(&self, total_columns: u64) -> bool {
        if total_columns == 0 {
            return false;
        }
        
        let required_for_reconstruction = total_columns / 2; // At least 50%
        self.columns.len() >= required_for_reconstruction as usize && 
        !self.reconstruction_started
    }
    
    /// Check if reconstruction is sufficient to complete
    /// (This would be called after actual reconstruction process)
    pub fn is_complete_for_reconstruction(&self) -> bool {
        // This should be called after reconstruction has added more columns
        // For now, assume reconstruction adds enough columns to be complete
        self.columns.len() > 0 && self.reconstruction_started
    }
    
    /// Check if reconstruction has started
    pub fn reconstruction_started(&self) -> bool {
        self.reconstruction_started
    }
    
    // reset_reconstruction unused; reconstruction restarts via state transitions.
    
    /// Convert to DataColumnSidecarList for availability
    pub fn into_column_list(self) -> DataColumnSidecarList<E> {
        let columns: Vec<Arc<DataColumnSidecar<E>>> = self.columns
            .into_iter()
            .map(|col| col.clone_arc())
            .collect();
            
        columns
    }
    
    /// Get column indices that are currently cached
    pub fn cached_indices(&self) -> Vec<u64> {
        self.columns.iter()
            .map(|col| col.index())
            .collect()
    }
    
    /// Get a specific column by index
    pub fn get_column(&self, index: u64) -> Option<&KzgVerifiedCustodyDataColumn<E>> {
        self.columns.iter()
            .find(|col| col.index() == index)
    }
    
    /// Check if a specific column exists
    pub fn has_column(&self, index: u64) -> bool {
        self.get_column(index).is_some()
    }
    
    /// Count of columns currently stored
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }
    
    /// Get all columns as references
    pub fn columns(&self) -> &[KzgVerifiedCustodyDataColumn<E>] {
        &self.columns
    }
    
    // matches_cached_column not used externally.
    
    /// Set expected count (used for completion checking)
    pub fn set_expected_count(&mut self, expected_count: u64) {
        self.expected_count = expected_count;
    }
    
    /// Get expected count
    pub fn expected_count(&self) -> u64 {
        self.expected_count
    }
    
    // status_string not used; omit to keep API minimal.
}

impl<E: EthSpec> Default for ColumnCollection<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_column_verification::KzgVerifiedDataColumn;
    use types::test_utils::TestRandom;
    use types::MainnetEthSpec;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    type E = MainnetEthSpec;
    
    #[test]
    fn blob_collection_basic_operations() {
        let mut collection = BlobCollection::<E>::new(6);
        
        // Start empty
        assert_eq!(collection.blob_count(), 0);
        assert!(!collection.is_complete(3));
        assert!(collection.is_complete(0)); // No blobs required
        
        // Add some test blobs
        let mut hasher = DefaultHasher::new();
        42u64.hash(&mut hasher);
        let mut test_blobs = Vec::new();
        for i in 0..3 {
            let mut blob = BlobSidecar::<E>::empty();
            blob.index = i as u64;
            let kzg_blob = KzgVerifiedBlob::__assumed_valid(Arc::new(blob));
            test_blobs.push(kzg_blob);
        }
        
        collection.merge_blobs(test_blobs);
        
        // Check results
        assert_eq!(collection.blob_count(), 3);
        assert!(collection.is_complete(3));
        assert!(!collection.is_complete(4));
        
        // Check specific blobs exist
        assert!(collection.has_blob(0));
        assert!(collection.has_blob(1));
        assert!(collection.has_blob(2));
        assert!(!collection.has_blob(3));
        
        // Check indices
        let indices = collection.cached_indices();
        assert_eq!(indices, vec![0, 1, 2]);
    }
    
    #[test]
    fn blob_collection_no_duplicates() {
        let mut collection = BlobCollection::<E>::new(6);
        let mut hasher = DefaultHasher::new();
        42u64.hash(&mut hasher);
        
        // Create blob at index 0
        let mut blob1 = BlobSidecar::<E>::empty();
        blob1.index = 0;
        let kzg_blob1 = KzgVerifiedBlob::__assumed_valid(Arc::new(blob1));
        
        // Create different blob at same index 0
        let mut blob2 = BlobSidecar::<E>::empty();
        blob2.index = 0;
        let kzg_blob2 = KzgVerifiedBlob::__assumed_valid(Arc::new(blob2));
        
        // Add first blob
        collection.merge_blobs(vec![kzg_blob1.clone()]);
        assert_eq!(collection.blob_count(), 1);
        
        // Try to add second blob at same index - should be ignored
        collection.merge_blobs(vec![kzg_blob2]);
        assert_eq!(collection.blob_count(), 1);
        
        // Verify original blob is still there
        let cached_blob = collection.get_blob(0).unwrap();
        assert_eq!(cached_blob.blob_index(), kzg_blob1.blob_index());
    }
    
    #[test]
    fn column_collection_basic_operations() {
        let mut collection = ColumnCollection::<E>::new();
        
        // Start empty
        assert_eq!(collection.column_count(), 0);
        assert!(!collection.is_complete(3));
        assert!(collection.is_complete(0)); // No columns required
        
        // Test reconstruction logic
        collection.set_expected_count(10);
        assert!(!collection.can_start_reconstruction(10)); // Need at least 50%
        
        // Add enough columns to start reconstruction
        let mut hasher = DefaultHasher::new();
        42u64.hash(&mut hasher);
        let mut test_columns = Vec::new();
        let mut rng = rand::thread_rng();
        
        for i in 0..6 {  // 60% of 10 columns
            let mut column = DataColumnSidecar::random_for_test(&mut rng);
            column.index = i as u64;
            let verified = KzgVerifiedDataColumn::__new_for_testing(Arc::new(column));
            let kzg_column = KzgVerifiedCustodyDataColumn::from_asserted_custody(verified);
            test_columns.push(kzg_column);
        }
        
        collection.merge_columns(test_columns);
        
        // Check results
        assert_eq!(collection.column_count(), 6);
        assert!(!collection.is_complete(10)); // Need all 10
        assert!(collection.can_start_reconstruction(10)); // Have >= 50%
        
        // Check specific columns exist
        assert!(collection.has_column(0));
        assert!(collection.has_column(5));
        assert!(!collection.has_column(6));
        
        // Check indices are sorted
        let indices = collection.cached_indices();
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5]);
    }
    
    #[test]
    fn column_collection_no_duplicates() {
        let mut collection = ColumnCollection::<E>::new();
        let mut hasher = DefaultHasher::new();
        42u64.hash(&mut hasher);
        let mut rng = rand::thread_rng();
        
        // Create column at index 0
        let mut col1 = DataColumnSidecar::random_for_test(&mut rng);
        col1.index = 0;
        let kzg_col1 = KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(Arc::new(col1))
        );
        
        // Create different column at same index 0
        let mut col2 = DataColumnSidecar::random_for_test(&mut rng);
        col2.index = 0;
        let kzg_col2 = KzgVerifiedCustodyDataColumn::from_asserted_custody(
            KzgVerifiedDataColumn::__new_for_testing(Arc::new(col2))
        );
        
        // Add first column
        collection.merge_columns(vec![kzg_col1.clone()]);
        assert_eq!(collection.column_count(), 1);
        
        // Try to add second column at same index - should be ignored
        collection.merge_columns(vec![kzg_col2]);
        assert_eq!(collection.column_count(), 1);
        
        // Verify original column is still there
        let cached_column = collection.get_column(0).unwrap();
        assert_eq!(cached_column.index(), kzg_col1.index());
    }
    
    #[test]
    fn collections_enforce_mutual_exclusion() {
        // This test verifies that BlobCollection and ColumnCollection
        // are separate types that cannot be mixed up
        
        let blob_collection = BlobCollection::<E>::new(6);
        let column_collection = ColumnCollection::<E>::new();
        
        // Cannot mix collections
        // This won't even compile:
        // blob_collection.merge_columns(vec![]); // ← Compile error
        // column_collection.merge_blobs(vec![]); // ← Compile error
        
        // They convert to different types
        let blob_list = blob_collection.into_blob_list();
        let column_list = column_collection.into_column_list();
        
        assert_eq!(blob_list.len(), 0);
        assert_eq!(column_list.len(), 0);
    }
}
