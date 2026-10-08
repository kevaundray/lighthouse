//! Deterministic storage boundary model, not a filesystem or database-engine crash model.
//!
//! Each database has visible bytes and a durable checkpoint. Successful sync commits all prior
//! writes to that database. A process crash preserves visible bytes; power loss discards writes
//! since the last successful sync. Crashes fence every old handle before chain destructors run.
use crate::{
    ColumnIter, ColumnKeyIter, DBColumn, Error, ItemStore, Key, KeyValueStore, KeyValueStoreOp,
    get_key_for_col, hot_cold_store::BytesKey,
};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

type DBMap = BTreeMap<BytesKey, Vec<u8>>;

#[derive(Clone, Copy, Debug)]
pub enum SimulationCrash {
    Process,
    PowerLoss,
}

#[derive(Default)]
struct Disk {
    visible: DBMap,
    durable: DBMap,
    dirty: BTreeSet<BytesKey>,
    fault: bool,
    block_fault: bool,
    next_write_fault: bool,
    next_sync_fault: bool,
    observed_faults: u64,
}

impl Disk {
    fn check_fault(&mut self) -> Result<(), Error> {
        if self.fault {
            self.observed_faults += 1;
            Err(storage_error("Injected storage fault: too many open files"))
        } else {
            Ok(())
        }
    }

    fn check_write(&mut self, writes_block: bool) -> Result<(), Error> {
        self.check_fault()?;
        if writes_block && std::mem::take(&mut self.block_fault) {
            self.fault = true;
            return self.check_fault();
        }
        if std::mem::take(&mut self.next_write_fault) {
            self.observed_faults += 1;
            return Err(storage_error("Injected storage write failure"));
        }
        Ok(())
    }

    fn check_sync(&mut self) -> Result<(), Error> {
        self.check_fault()?;
        if std::mem::take(&mut self.next_sync_fault) {
            self.observed_faults += 1;
            return Err(storage_error("Injected storage sync failure"));
        }
        Ok(())
    }

    fn commit(&mut self) {
        for key in std::mem::take(&mut self.dirty) {
            if let Some(value) = self.visible.get(&key) {
                self.durable.insert(key, value.clone());
            } else {
                self.durable.remove(&key);
            }
        }
    }

    fn put(&mut self, key: BytesKey, value: Vec<u8>) {
        self.dirty.insert(key.clone());
        self.visible.insert(key, value);
    }

    fn delete(&mut self, key: BytesKey) {
        self.visible.remove(&key);
        self.dirty.insert(key);
    }

    fn clear_faults(&mut self) {
        self.fault = false;
        self.block_fault = false;
        self.next_write_fault = false;
        self.next_sync_fault = false;
    }
}

#[derive(Default)]
struct Storage {
    generation: u64,
    // All databases share one lock so fencing is atomic with respect to every operation.
    disks: [Disk; 3],
}

/// Retain this handle, not a live HotColdDB or BeaconChain, across node restart.
#[derive(Clone, Default)]
pub struct SimulationStorage(Arc<Mutex<Storage>>);

impl SimulationStorage {
    /// Fence all old handles BEFORE killing tasks or dropping the old client. Never syncs.
    /// Armed faults are cleared, while observed error counts survive the crash.
    pub fn crash(&self, mode: SimulationCrash) {
        let mut storage = self.0.lock();
        storage.generation += 1;
        for disk in &mut storage.disks {
            if matches!(mode, SimulationCrash::PowerLoss) {
                disk.visible.clone_from(&disk.durable);
                disk.dirty.clear();
            }
            disk.clear_faults();
        }
    }

    /// Open fresh hot, cold, and blobs handles, fencing any previous generation.
    /// Does not copy chain caches or make unsynced data durable.
    pub fn reopen(&self) -> (SimulationStore, SimulationStore, SimulationStore) {
        let mut storage = self.0.lock();
        storage.generation += 1;
        let handle = |index| SimulationStore {
            storage: self.clone(),
            generation: storage.generation,
            index,
        };
        (handle(0), handle(1), handle(2))
    }

    /// Fail the next hot-store block batch before applying ANY of its operations. Like
    /// MemoryStore's fault control, the fault remains active until explicitly cleared.
    pub fn arm_failed_next_block_batch(&self) {
        self.0.lock().disks[0].block_fault = true;
    }

    /// Fail the next hot-store mutation, leaving its bytes unchanged.
    pub fn fail_next_write(&self) {
        self.0.lock().disks[0].next_write_fault = true;
    }

    /// Fail the next hot-store sync (including put_bytes_sync), without advancing durability.
    pub fn fail_next_sync(&self) {
        self.0.lock().disks[0].next_sync_fault = true;
    }

    pub fn observed_fault_count(&self) -> u64 {
        self.0
            .lock()
            .disks
            .iter()
            .map(|disk| disk.observed_faults)
            .sum()
    }

    pub fn clear_faults(&self) {
        for disk in &mut self.0.lock().disks {
            disk.clear_faults();
        }
    }

    /// Explicit model checkpoint. Crash and reopen never invoke this operation.
    /// Normal node durability must instead come from production storage sync calls.
    pub fn sync_all(&self) -> Result<(), Error> {
        let mut storage = self.0.lock();
        for disk in &mut storage.disks {
            disk.check_sync()?;
            disk.commit();
        }
        Ok(())
    }
}

pub struct SimulationStore {
    storage: SimulationStorage,
    generation: u64,
    index: usize,
}

fn storage_error(message: &str) -> Error {
    Error::DBError {
        message: message.into(),
    }
}

impl SimulationStore {
    fn with_disk<T>(&self, f: impl FnOnce(&mut Disk) -> Result<T, Error>) -> Result<T, Error> {
        let mut storage = self.storage.0.lock();
        if self.generation != storage.generation {
            return Err(storage_error(
                "Storage handle belongs to a crashed node generation",
            ));
        }
        f(&mut storage.disks[self.index])
    }

    pub fn inject_faults(&self, enabled: bool) {
        let _ = self.with_disk(|disk| {
            if enabled {
                disk.fault = true;
            } else {
                disk.clear_faults();
            }
            Ok(())
        });
    }

    pub fn inject_faults_on_next_block_write(&self) {
        let _ = self.with_disk(|disk| {
            disk.block_fault = true;
            Ok(())
        });
    }

    pub fn observed_fault_count(&self) -> u64 {
        self.storage.0.lock().disks[self.index].observed_faults
    }
}

impl KeyValueStore for SimulationStore {
    fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.with_disk(|disk| {
            disk.check_fault()?;
            Ok(disk
                .visible
                .get(&BytesKey::from_vec(get_key_for_col(column, key)))
                .cloned())
        })
    }

    fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(false)?;
            disk.put(
                BytesKey::from_vec(get_key_for_col(column, key)),
                value.to_vec(),
            );
            Ok(())
        })
    }

    fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(false)?;
            // Fail before mutation: the failed operation is neither visible nor durable.
            disk.check_sync()?;
            disk.put(
                BytesKey::from_vec(get_key_for_col(column, key)),
                value.to_vec(),
            );
            disk.commit();
            Ok(())
        })
    }

    fn sync(&self) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_sync()?;
            disk.commit();
            Ok(())
        })
    }

    fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        self.with_disk(|disk| {
            disk.check_fault()?;
            Ok(disk
                .visible
                .contains_key(&BytesKey::from_vec(get_key_for_col(column, key))))
        })
    }

    fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(false)?;
            disk.delete(BytesKey::from_vec(get_key_for_col(column, key)));
            Ok(())
        })
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(batch.iter().any(|op| {
                matches!(
                    op,
                    KeyValueStoreOp::PutKeyValue(DBColumn::BeaconBlock, _, _)
                )
            }))?;
            for op in batch {
                match op {
                    KeyValueStoreOp::PutKeyValue(column, key, value) => {
                        disk.put(BytesKey::from_vec(get_key_for_col(column, &key)), value);
                    }
                    KeyValueStoreOp::DeleteKey(column, key) => {
                        disk.delete(BytesKey::from_vec(get_key_for_col(column, &key)));
                    }
                }
            }
            Ok(())
        })
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        self.with_disk(|disk| disk.check_fault())
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
        let entries = self.with_disk(|disk| {
            disk.check_fault()?;
            disk.visible
                .range(BytesKey::from_vec(get_key_for_col(column, from))..)
                .take_while(|(key, _)| key.remove_column_variable(column).is_some())
                .map(|(key, value)| {
                    let key = key
                        .remove_column_variable(column)
                        .ok_or_else(|| storage_error("Invalid column prefix"))?;
                    Ok((K::from_bytes(key)?, value.clone()))
                })
                .collect::<Result<Vec<_>, Error>>()
        });
        match entries {
            Ok(entries) => Box::new(entries.into_iter().map(move |entry| {
                self.with_disk(|disk| disk.check_fault())?;
                Ok(entry)
            })),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        self.iter_column_keys_from(column, &[])
    }

    fn iter_column_keys_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnKeyIter<'_, K> {
        let keys = self.with_disk(|disk| {
            disk.check_fault()?;
            disk.visible
                .range(BytesKey::from_vec(get_key_for_col(column, from))..)
                .take_while(|(key, _)| key.remove_column_variable(column).is_some())
                .map(|(key, _)| {
                    let key = key
                        .remove_column_variable(column)
                        .ok_or_else(|| storage_error("Invalid column prefix"))?;
                    K::from_bytes(key)
                })
                .collect::<Result<Vec<_>, Error>>()
        });
        match keys {
            Ok(keys) => Box::new(keys.into_iter().map(move |key| {
                self.with_disk(|disk| disk.check_fault())?;
                Ok(key)
            })),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }

    fn delete_batch(&self, column: DBColumn, keys: HashSet<&[u8]>) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(false)?;
            for key in keys {
                disk.delete(BytesKey::from_vec(get_key_for_col(column, key)));
            }
            Ok(())
        })
    }

    fn delete_if(
        &self,
        column: DBColumn,
        mut f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.with_disk(|disk| {
            disk.check_write(false)?;
            let mut deletes = Vec::new();
            for (key, value) in &disk.visible {
                if key.remove_column_variable(column).is_some() && f(value)? {
                    deletes.push(key.clone());
                }
            }
            for key in deletes {
                disk.delete(key);
            }
            Ok(())
        })
    }
}

impl ItemStore for SimulationStore {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_block_batch_changes_no_keys_and_counts_returned_faults() {
        let storage = SimulationStorage::default();
        let (hot, _, _) = storage.reopen();
        hot.put_bytes(DBColumn::BeaconBlock, b"old", b"original")
            .unwrap();
        storage.arm_failed_next_block_batch();
        assert_eq!(storage.observed_fault_count(), 0);
        assert!(
            hot.do_atomically(vec![
                KeyValueStoreOp::DeleteKey(DBColumn::BeaconBlock, b"old".to_vec()),
                KeyValueStoreOp::PutKeyValue(
                    DBColumn::BeaconBlock,
                    b"new".to_vec(),
                    b"block".to_vec()
                ),
            ])
            .is_err()
        );
        assert_eq!(storage.observed_fault_count(), 1);
        storage.clear_faults();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"old").unwrap(),
            Some(b"original".to_vec())
        );
        assert_eq!(hot.get_bytes(DBColumn::BeaconBlock, b"new").unwrap(), None);
    }

    #[test]
    fn process_crash_retains_unsynced_writes_but_power_loss_discards_them() {
        let storage = SimulationStorage::default();
        let (hot, cold, _) = storage.reopen();
        hot.put_bytes_sync(DBColumn::BeaconBlock, b"key", b"durable")
            .unwrap();
        hot.put_bytes(DBColumn::BeaconBlock, b"key", b"unsynced")
            .unwrap();
        cold.put_bytes(DBColumn::BeaconBlock, b"cold", b"unsynced")
            .unwrap();
        storage.crash(SimulationCrash::Process);
        let (hot, cold, _) = storage.reopen();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"unsynced".to_vec())
        );
        assert_eq!(
            cold.get_bytes(DBColumn::BeaconBlock, b"cold").unwrap(),
            Some(b"unsynced".to_vec())
        );
        storage.crash(SimulationCrash::PowerLoss);
        let (hot, cold, _) = storage.reopen();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"durable".to_vec())
        );
        assert_eq!(
            cold.get_bytes(DBColumn::BeaconBlock, b"cold").unwrap(),
            None
        );
    }

    #[test]
    fn sync_commits_prior_writes_and_deletes_only_in_its_database() {
        let storage = SimulationStorage::default();
        let (hot, cold, _) = storage.reopen();
        hot.put_bytes_sync(DBColumn::BeaconBlock, b"deleted", b"old")
            .unwrap();
        hot.key_delete(DBColumn::BeaconBlock, b"deleted").unwrap();
        hot.put_bytes(DBColumn::BeaconBlock, b"prior", b"first")
            .unwrap();
        cold.put_bytes(DBColumn::BeaconBlock, b"cold", b"not-synced")
            .unwrap();
        hot.put_bytes_sync(DBColumn::BeaconBlock, b"last", b"second")
            .unwrap();
        storage.crash(SimulationCrash::PowerLoss);
        let (hot, cold, _) = storage.reopen();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"deleted").unwrap(),
            None
        );
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"prior").unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"last").unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            cold.get_bytes(DBColumn::BeaconBlock, b"cold").unwrap(),
            None
        );
    }

    #[test]
    fn failed_sync_never_advances_durability_or_applies_sync_write() {
        let storage = SimulationStorage::default();
        let (hot, _, _) = storage.reopen();
        hot.put_bytes_sync(DBColumn::BeaconBlock, b"key", b"durable")
            .unwrap();
        hot.put_bytes(DBColumn::BeaconBlock, b"key", b"pending")
            .unwrap();
        storage.fail_next_sync();
        assert!(hot.sync().is_err());
        storage.fail_next_sync();
        assert!(
            hot.put_bytes_sync(DBColumn::BeaconBlock, b"new", b"failed")
                .is_err()
        );
        assert_eq!(hot.get_bytes(DBColumn::BeaconBlock, b"new").unwrap(), None);
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"pending".to_vec())
        );
        assert_eq!(storage.observed_fault_count(), 2);
        storage.crash(SimulationCrash::PowerLoss);
        let (hot, _, _) = storage.reopen();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"durable".to_vec())
        );
        assert_eq!(hot.get_bytes(DBColumn::BeaconBlock, b"new").unwrap(), None);
    }

    #[test]
    fn crash_fences_old_handles_and_iterators_before_and_after_reopen() {
        let storage = SimulationStorage::default();
        let (old_hot, old_cold, old_blobs) = storage.reopen();
        let key = &[1; 32];
        old_hot
            .put_bytes_sync(DBColumn::BeaconBlock, key, b"durable")
            .unwrap();
        let mut entries = old_hot.iter_column_from::<Vec<u8>>(DBColumn::BeaconBlock, b"");
        let mut keys = old_hot.iter_column_keys_from::<Vec<u8>>(DBColumn::BeaconBlock, b"");
        storage.crash(SimulationCrash::Process);
        assert!(
            old_hot
                .put_bytes_sync(DBColumn::BeaconBlock, key, b"stale-drop")
                .is_err()
        );
        assert!(entries.next().unwrap().is_err());
        assert!(keys.next().unwrap().is_err());
        let (new_hot, _, _) = storage.reopen();
        assert!(old_hot.sync().is_err());
        assert!(
            old_cold
                .put_bytes(DBColumn::BeaconBlock, key, b"stale")
                .is_err()
        );
        assert!(old_blobs.key_delete(DBColumn::BeaconBlock, key).is_err());
        old_hot.inject_faults(true);
        assert_eq!(
            new_hot.get_bytes(DBColumn::BeaconBlock, key).unwrap(),
            Some(b"durable".to_vec())
        );
        new_hot
            .put_bytes_sync(DBColumn::BeaconBlock, key, b"new")
            .unwrap();
        assert!(
            old_hot
                .put_bytes(DBColumn::BeaconBlock, key, b"stale")
                .is_err()
        );
        assert_eq!(
            new_hot.get_bytes(DBColumn::BeaconBlock, key).unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn failed_single_write_can_be_retried_without_partial_mutation() {
        let storage = SimulationStorage::default();
        let (hot, _, _) = storage.reopen();
        hot.put_bytes(DBColumn::BeaconBlock, b"key", b"old")
            .unwrap();
        storage.fail_next_write();
        assert!(
            hot.put_bytes(DBColumn::BeaconBlock, b"key", b"new")
                .is_err()
        );
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"old".to_vec())
        );
        hot.put_bytes(DBColumn::BeaconBlock, b"key", b"new")
            .unwrap();
        assert_eq!(
            hot.get_bytes(DBColumn::BeaconBlock, b"key").unwrap(),
            Some(b"new".to_vec())
        );
        assert_eq!(storage.observed_fault_count(), 1);
    }
}
