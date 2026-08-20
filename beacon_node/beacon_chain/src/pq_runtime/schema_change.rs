use crate::BeaconChainTypes;
use std::sync::Arc;
use store::Error as StoreError;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{CURRENT_SCHEMA_VERSION, SchemaVersion};

/// PQ startup accepts only the current schema. Ordinary migrations may read or rewrite
/// fork-choice state that the deliberately minimal PQ store does not contain.
pub fn migrate_pq_schema<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    from: SchemaVersion,
    to: SchemaVersion,
) -> Result<(), StoreError> {
    if from == to && to == CURRENT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into())
    }
}
