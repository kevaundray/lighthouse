//! Execution proof verification key management
//!
//! This module handles loading and managing verification keys for execution proofs.
//! Verification keys are stored as .bin files in the verification_keys directory,
//! with each file named by its prover UUID.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};
use uuid::Uuid;

/// Represents a verification key for validating execution proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProofVerificationKey {
    /// Unique identifier for the prover that generated this key
    pub prover_id: Uuid,
    /// The binary verification key data
    pub vk: Vec<u8>,
}

impl ExecutionProofVerificationKey {
    /// Create a new verification key
    pub fn new(prover_id: Uuid, vk: Vec<u8>) -> Self {
        Self { prover_id, vk }
    }

    /// Get the size of the verification key in bytes
    pub fn size(&self) -> usize {
        self.vk.len()
    }
}

/// Manager for loading and accessing verification keys
#[derive(Debug, Default)]
pub struct VerificationKeyStore {
    /// Map of prover_id to verification key
    keys: HashMap<Uuid, ExecutionProofVerificationKey>,
}

impl VerificationKeyStore {
    /// Create a new empty verification key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Load all verification keys from a directory
    ///
    /// Expected file format: `{prover}_{uuid}.bin`
    /// where prover_id is a valid UUID string
    ///
    /// # Example
    /// ```ignore
    /// let store = VerificationKeyStore::load_from_directory("./verification_keys")?;
    /// ```
    pub fn load_from_directory<P: AsRef<Path>>(dir: P) -> Result<Self, String> {
        let dir_path = dir.as_ref();

        if !dir_path.exists() {
            return Err(format!("Directory does not exist: {:?}", dir_path));
        }

        if !dir_path.is_dir() {
            return Err(format!("Path is not a directory: {:?}", dir_path));
        }

        let mut store = Self::new();
        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| format!("Failed to read directory {:?}: {}", dir_path, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();

            // Only process .bin files
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }

            // Extract prover_id from filename
            // Expected format: {prover}_{uuid}.bin
            // We split on '_' and take index [1] for the UUID
            let file_stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(stem) => stem,
                None => {
                    warn!("Skipping file with invalid name: {:?}", path);
                    continue;
                }
            };

            // Split filename on '_' and extract UUID from second part
            let parts: Vec<&str> = file_stem.split('_').collect();
            let uuid_str = if parts.len() >= 2 {
                parts[1]
            } else {
                warn!(
                    "Skipping file {:?}: filename does not match pattern {{name}}_{{uuid}}",
                    path
                );
                continue;
            };

            let prover_id = match Uuid::parse_str(uuid_str) {
                Ok(uuid) => uuid,
                Err(e) => {
                    warn!(
                        "Skipping file {:?}: '{}' is not a valid UUID: {}",
                        path, uuid_str, e
                    );
                    continue;
                }
            };

            // Read the verification key binary data
            let vk_data = std::fs::read(&path)
                .map_err(|e| format!("Failed to read file {:?}: {}", path, e))?;

            debug!(
                prover_id = %prover_id,
                size_bytes = vk_data.len(),
                path = ?path,
                "Loaded verification key"
            );

            let vk = ExecutionProofVerificationKey::new(prover_id, vk_data);
            store.add_key(vk);
        }

        debug!(
            key_count = store.keys.len(),
            "Loaded verification keys from directory"
        );

        Ok(store)
    }

    /// Add a verification key to the store
    pub fn add_key(&mut self, key: ExecutionProofVerificationKey) {
        self.keys.insert(key.prover_id, key);
    }

    /// Get a verification key by prover ID
    pub fn get(&self, prover_id: &Uuid) -> Option<&ExecutionProofVerificationKey> {
        self.keys.get(prover_id)
    }

    /// Check if a verification key exists for a prover
    pub fn contains(&self, prover_id: &Uuid) -> bool {
        self.keys.contains_key(prover_id)
    }

    /// Get the number of verification keys in the store
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get all prover IDs
    pub fn prover_ids(&self) -> Vec<Uuid> {
        self.keys.keys().copied().collect()
    }

    /// Load verification keys from the embedded directory
    ///
    /// This looks for .bin files in the beacon_chain/src/verification_keys directory
    pub fn load_embedded() -> Result<Self, String> {
        let vk_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("verification_keys");

        Self::load_from_directory(vk_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_verification_key_creation() {
        let prover_id = Uuid::new_v4();
        let vk_data = vec![1, 2, 3, 4, 5];
        let vk = ExecutionProofVerificationKey::new(prover_id, vk_data.clone());

        assert_eq!(vk.prover_id, prover_id);
        assert_eq!(vk.vk, vk_data);
        assert_eq!(vk.size(), 5);
    }

    #[test]
    fn test_verification_key_store() {
        let mut store = VerificationKeyStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let prover_id = Uuid::new_v4();
        let vk = ExecutionProofVerificationKey::new(prover_id, vec![1, 2, 3]);

        store.add_key(vk.clone());
        assert_eq!(store.len(), 1);
        assert!(store.contains(&prover_id));

        let retrieved = store.get(&prover_id).unwrap();
        assert_eq!(retrieved.prover_id, prover_id);
        assert_eq!(retrieved.vk, vec![1, 2, 3]);
    }

    #[test]
    fn test_load_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let vk_dir = temp_dir.path();

        // Create test verification key files with format: {prover}_{uuid}.bin
        let prover_id1 = Uuid::new_v4();
        let prover_id2 = Uuid::new_v4();

        let vk1_path = vk_dir.join(format!("brevis_{}.bin", prover_id1));
        let vk2_path = vk_dir.join(format!("zkm_{}.bin", prover_id2));

        fs::write(&vk1_path, vec![1, 2, 3, 4]).unwrap();
        fs::write(&vk2_path, vec![5, 6, 7, 8, 9]).unwrap();

        // Also create a non-.bin file that should be ignored
        fs::write(vk_dir.join("ignored.txt"), "ignore me").unwrap();

        // Load the verification keys
        let store = VerificationKeyStore::load_from_directory(vk_dir).unwrap();

        assert_eq!(store.len(), 2);
        assert!(store.contains(&prover_id1));
        assert!(store.contains(&prover_id2));

        let vk1 = store.get(&prover_id1).unwrap();
        assert_eq!(vk1.vk, vec![1, 2, 3, 4]);

        let vk2 = store.get(&prover_id2).unwrap();
        assert_eq!(vk2.vk, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_invalid_filename_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let vk_dir = temp_dir.path();

        // Create file with invalid format (no underscore)
        fs::write(vk_dir.join("not-valid-format.bin"), vec![1, 2, 3]).unwrap();

        // Create file with invalid UUID after underscore
        fs::write(vk_dir.join("prover_not-a-uuid.bin"), vec![1, 2, 3]).unwrap();

        let store = VerificationKeyStore::load_from_directory(vk_dir).unwrap();
        assert_eq!(store.len(), 0); // Should be empty since filenames are invalid
    }
}
