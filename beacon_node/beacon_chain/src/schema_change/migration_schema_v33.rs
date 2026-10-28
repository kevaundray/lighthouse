use crate::beacon_chain::{BeaconChainTypes, OP_POOL_DB_KEY};
use operation_pool::{PersistedOperationPool, PersistedOperationPoolV20};
use store::hot_cold_store::HotColdDB;
use store::{Error as StoreError, ItemStore, KeyValueStoreOp, StoreItem};
use tracing::info;

/// Upgrade from schema v32 to v33.
///
/// Schema v33 persists the operation pool as `PersistedOperationPoolV33`, which adds EIP-8450
/// post-quantum key registrations. A v33 node still decodes a `PersistedOperationPoolV20` and
/// rewrites it as `V33` the next time it persists the pool, so nothing changes on disk.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn upgrade_to_v33<T: BeaconChainTypes>(
    _db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    Ok(vec![])
}

/// Downgrade from schema v33 to v32.
///
/// Rewrites a `PersistedOperationPoolV33` as `PersistedOperationPoolV20`, which is the only
/// layout v32 decodes, dropping its post-quantum key registrations.
///
/// Returns a list of store ops to be applied atomically with the schema version write.
pub fn downgrade_from_v33<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<Vec<KeyValueStoreOp>, StoreError> {
    let Some(PersistedOperationPool::V33(op_pool)) = db
        .hot_db
        .get::<PersistedOperationPool<T::EthSpec>>(&OP_POOL_DB_KEY)?
    else {
        return Ok(vec![]);
    };

    info!(
        dropped_pq_key_registrations = op_pool.pq_key_registrations.len(),
        "Rewriting the persisted op pool for schema v32"
    );

    let op_pool_v20 = PersistedOperationPoolV20 {
        attestations: op_pool.attestations,
        sync_contributions: op_pool.sync_contributions,
        attester_slashings: op_pool.attester_slashings,
        proposer_slashings: op_pool.proposer_slashings,
        voluntary_exits: op_pool.voluntary_exits,
        bls_to_execution_changes: op_pool.bls_to_execution_changes,
        capella_bls_change_broadcast_indices: op_pool.capella_bls_change_broadcast_indices,
    };

    Ok(vec![op_pool_v20.as_kv_store_op(OP_POOL_DB_KEY)])
}
