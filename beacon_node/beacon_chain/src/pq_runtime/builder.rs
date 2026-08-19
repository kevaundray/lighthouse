use crate::{BeaconChain, BeaconChainTypes, BeaconSnapshot, PqRuntimeError};
use consensus_signature::{AggregationService, IndividualSignature};
use kzg::Kzg;
use slot_clock::SlotClock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{PqValidatorKeyCache, validate_lean_pq_devnet_v1};
use std::marker::PhantomData;
use std::sync::Arc;
use store::metadata::ANCHOR_UNINITIALIZED;
use store::{DBColumn, HotColdDB, ItemStore, StoreItem, StoreOp};
use types::{BeaconState, ChainSpec, EthSpec, Hash256, SignedBeaconBlock, Slot};

const PQ_HEAD_DB_KEY: Hash256 = Hash256::repeat_byte(0x51);

#[derive(Clone, Encode, Decode)]
struct PersistedPqHead {
    block_root: Hash256,
    state_root: Hash256,
    slot: Slot,
}

impl StoreItem for PersistedPqHead {
    fn db_column() -> DBColumn {
        DBColumn::BeaconChain
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, store::Error> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

/// Type witness retained across the default and PQ-selected builder APIs.
pub struct Witness<TSlotClock, E, THotStore, TColdStore>(
    PhantomData<(TSlotClock, E, THotStore, TColdStore)>,
);

impl<TSlotClock, E, THotStore, TColdStore> BeaconChainTypes
    for Witness<TSlotClock, E, THotStore, TColdStore>
where
    TSlotClock: SlotClock + 'static,
    E: EthSpec + 'static,
    THotStore: ItemStore + 'static,
    TColdStore: ItemStore + 'static,
{
    type EthSpec = E;
    type HotStore = THotStore;
    type ColdStore = TColdStore;
    type SlotClock = TSlotClock;
}

/// Builder for the real, deliberately narrow Task 5.3e-b PQ ownership core.
///
/// Production callers cannot persist an arbitrary raw state and signed block as the canonical
/// head. Non-genesis persistence will consume a sealed transition output when import wiring is
/// added in Task 5.3e-c.
pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    store: Option<Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>>,
    spec: Arc<ChainSpec>,
    snapshot: Option<BeaconSnapshot<T::EthSpec>>,
    key_cache: Option<Arc<PqValidatorKeyCache>>,
    aggregation_service: Option<Arc<AggregationService>>,
    marker: PhantomData<T>,
}

impl<TSlotClock, E, THotStore, TColdStore>
    BeaconChainBuilder<Witness<TSlotClock, E, THotStore, TColdStore>>
where
    TSlotClock: SlotClock + 'static,
    E: EthSpec + 'static,
    THotStore: ItemStore + 'static,
    TColdStore: ItemStore + 'static,
{
    pub fn pq_new(_eth_spec_instance: E) -> Self {
        Self {
            store: None,
            spec: Arc::new(E::default_spec()),
            snapshot: None,
            key_cache: None,
            aggregation_service: None,
            marker: PhantomData,
        }
    }

    pub fn new(_eth_spec_instance: E, _kzg: Arc<Kzg>) -> Self {
        Self::pq_new(_eth_spec_instance)
    }

    pub fn store(mut self, store: Arc<HotColdDB<E, THotStore, TColdStore>>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn custom_spec(mut self, spec: Arc<ChainSpec>) -> Self {
        self.spec = spec;
        self
    }

    fn persist_unverified_canonical_snapshot(
        mut self,
        mut state: BeaconState<E>,
        block: SignedBeaconBlock<E>,
    ) -> Result<Self, PqRuntimeError> {
        validate_lean_pq_devnet_v1(&state, &self.spec, state.slot())
            .map_err(PqRuntimeError::InvalidState)?;
        if block.slot() != state.slot() {
            return Err(PqRuntimeError::MissingHeadBlock);
        }
        let key_cache = Arc::new(
            PqValidatorKeyCache::from_state(&state).map_err(PqRuntimeError::InvalidKeyCache)?,
        );
        let state_root = state.update_tree_hash_cache().map_err(store::Error::from)?;
        if block.message().state_root() != state_root {
            return Err(PqRuntimeError::HeadStateRootMismatch {
                block: block.message().state_root(),
                state: state_root,
            });
        }
        let block_root = block.canonical_root();
        let snapshot = BeaconSnapshot {
            beacon_block: Arc::new(block.clone()),
            beacon_block_root: block_root,
            beacon_state: state,
        };
        let store = self
            .store
            .as_ref()
            .ok_or(PqRuntimeError::MissingHeadState)?;
        let previous_anchor = store.get_anchor_info();
        let mut store_ops = Vec::with_capacity(if previous_anchor == ANCHOR_UNINITIALIZED {
            4
        } else {
            3
        });
        let initialized_anchor = if previous_anchor == ANCHOR_UNINITIALIZED {
            let anchor_op = store.init_anchor_info(
                block.message().parent_root(),
                block.slot(),
                block.slot(),
                false,
            )?;
            store_ops.push(StoreOp::KeyValueOp(anchor_op));
            Some(store.get_anchor_info())
        } else {
            None
        };
        store_ops.push(StoreOp::PutState(state_root, &snapshot.beacon_state));
        store_ops.push(StoreOp::PutBlock(block_root, snapshot.beacon_block.clone()));
        store_ops.push(StoreOp::KeyValueOp(
            PersistedPqHead {
                block_root,
                state_root,
                slot: snapshot.beacon_state.slot(),
            }
            .as_kv_store_op(PQ_HEAD_DB_KEY),
        ));
        if let Err(error) = store.do_atomically_with_block_and_blobs_cache(store_ops) {
            if let Some(initialized_anchor) = initialized_anchor {
                store
                    .compare_and_set_anchor_info(initialized_anchor, previous_anchor)
                    .map(|_| ())?;
            }
            return Err(error.into());
        }
        self.snapshot = Some(snapshot);
        self.key_cache = Some(key_cache);
        Ok(self)
    }

    /// Test-only escape hatch for restart/tamper fixtures.
    ///
    /// This accepts an unsealed raw state/block pair and must never be enabled in a production
    /// feature graph. Task 5.3e-c will persist non-genesis heads from sealed transition output.
    #[cfg(feature = "pq-startup-testing")]
    pub fn testing_only_persist_unverified_canonical_snapshot(
        self,
        state: BeaconState<E>,
        block: SignedBeaconBlock<E>,
    ) -> Result<Self, PqRuntimeError> {
        self.persist_unverified_canonical_snapshot(state, block)
    }

    /// Constructs and persists the slot-zero PQ genesis snapshot.
    pub fn genesis_state(self, mut state: BeaconState<E>) -> Result<Self, PqRuntimeError> {
        let mut block = state_processing::genesis::genesis_block(&state, &self.spec)
            .map_err(store::Error::from)?;
        *block.state_root_mut() = state.update_tree_hash_cache().map_err(store::Error::from)?;
        let signed = SignedBeaconBlock::from_block(block, IndividualSignature::empty());
        self.persist_unverified_canonical_snapshot(state, signed)
    }

    /// Loads an exact snapshot and rebuilds the ephemeral cache without reading `pkc` or `opo`.
    pub fn resume_from_db(mut self) -> Result<Self, PqRuntimeError> {
        let store = self
            .store
            .as_ref()
            .ok_or(PqRuntimeError::MissingHeadState)?;
        let persisted = store
            .get_item::<PersistedPqHead>(&PQ_HEAD_DB_KEY)?
            .ok_or(PqRuntimeError::MissingPersistedHead)?;
        let block = store
            .get_full_block(&persisted.block_root)?
            .ok_or(PqRuntimeError::MissingHeadBlock)?;
        let mut state = store
            .get_state(&persisted.state_root, Some(persisted.slot), true)?
            .ok_or(PqRuntimeError::MissingHeadState)?;
        if persisted.slot != state.slot() || persisted.slot != block.slot() {
            return Err(PqRuntimeError::PersistedHeadBinding(
                "metadata, state and block slots differ",
            ));
        }
        let computed_state_root = state.update_tree_hash_cache().map_err(store::Error::from)?;
        if computed_state_root != persisted.state_root {
            return Err(PqRuntimeError::PersistedHeadBinding(
                "state contents do not match the persisted state root",
            ));
        }
        if block.canonical_root() != persisted.block_root {
            return Err(PqRuntimeError::PersistedHeadBinding(
                "block contents do not match the persisted block root",
            ));
        }
        if block.message().state_root() != computed_state_root {
            return Err(PqRuntimeError::PersistedHeadBinding(
                "block state root does not match the persisted state",
            ));
        }
        validate_lean_pq_devnet_v1(&state, &self.spec, state.slot())
            .map_err(PqRuntimeError::InvalidState)?;
        let key_cache = Arc::new(
            PqValidatorKeyCache::from_state(&state).map_err(PqRuntimeError::InvalidKeyCache)?,
        );
        self.snapshot = Some(BeaconSnapshot {
            beacon_block: Arc::new(block),
            beacon_block_root: persisted.block_root,
            beacon_state: state,
        });
        self.key_cache = Some(key_cache);
        Ok(self)
    }

    pub fn pq_aggregation_service(mut self, service: Arc<AggregationService>) -> Self {
        self.aggregation_service = Some(service);
        self
    }

    pub fn build(
        self,
    ) -> Result<BeaconChain<Witness<TSlotClock, E, THotStore, TColdStore>>, PqRuntimeError> {
        Ok(BeaconChain::new(
            self.spec,
            self.store.ok_or(PqRuntimeError::MissingHeadState)?,
            self.snapshot.ok_or(PqRuntimeError::MissingHeadState)?,
            self.key_cache.ok_or(PqRuntimeError::MissingHeadState)?,
            self.aggregation_service.ok_or(PqRuntimeError::Aggregation(
                consensus_signature::AggregationError::Unavailable,
            ))?,
        ))
    }
}
