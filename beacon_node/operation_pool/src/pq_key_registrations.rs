use state_processing::per_block_processing::{
    VerifySignatures, cmp_pq_change_epochs, is_pq_registration_dead, verify_pq_key_registration,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use types::{
    BeaconState, ChainSpec, Epoch, EthSpec, PqRegistryIndex, SignedPqKeyRegistration, XmssPublicKey,
};

/// Number of epochs of full blocks worth of registrations the pool holds at most.
///
/// See `max_pool_len`.
pub const PQ_KEY_REGISTRATION_POOL_EPOCHS: usize = 64;

/// Maximum number of registrations in the pool: `MAX_PQ_KEY_REGISTRATIONS * SLOTS_PER_EPOCH *
/// PQ_KEY_REGISTRATION_POOL_EPOCHS`, i.e. 16,384 on mainnet and 4,096 on minimal.
///
/// Blocks include at most `MAX_PQ_KEY_REGISTRATIONS` registrations, so this is 64 epochs (about 7
/// hours on mainnet) of full blocks: more than the network can include before entries are pruned
/// at the next finalization, while bounding the pool at about 45 MB (registrations are 2580 bytes
/// of SSZ). Registrations that do not fit are ignored and can be submitted again once the pool
/// drains.
pub fn max_pool_len<E: EthSpec>() -> usize {
    E::max_pq_key_registrations()
        .saturating_mul(E::slots_per_epoch() as usize)
        .saturating_mul(PQ_KEY_REGISTRATION_POOL_EPOCHS)
}

/// Result of inserting a registration into the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqKeyRegistrationInsertOutcome {
    /// The registration was added, possibly replacing the older one of its index.
    Inserted,
    /// The pool holds a registration for the index with the same or a later
    /// `previous_change_epoch`.
    NotNewer,
    /// The pool is full and holds no registration for the index to replace.
    PoolFull,
}

/// A registration in the pool, with the order in which it was inserted.
#[derive(Debug, Clone)]
struct PooledRegistration {
    /// Position of the registration in insertion order, the key of `PqKeyRegistrations::fifo`.
    sequence: u64,
    registration: SignedPqKeyRegistration,
}

/// Pool of post-quantum key registrations (EIP-8450), holding at most one registration per
/// validator or builder index (flagged for builders), and at most `max_len` registrations in
/// total.
///
/// Every registration in the pool has passed full verification, including its BLS signature and
/// leanXMSS proof of possession. Neither signature depends on the fork, so they are not checked
/// again when packing a block.
#[derive(Debug, Default)]
pub struct PqKeyRegistrations {
    /// Map from validator or flagged builder index to its registration.
    by_index: HashMap<u64, PooledRegistration>,
    /// Indices of the registrations in insertion order, keyed by sequence number.
    fifo: BTreeMap<u64, u64>,
    /// Sequence number of the next insertion.
    next_sequence: u64,
}

impl PqKeyRegistrations {
    /// Returns `true` if inserting `registration` would not exceed `max_len`: the pool has room,
    /// or `registration` would replace the existing registration of its index.
    pub fn has_room_for(&self, registration: &SignedPqKeyRegistration, max_len: usize) -> bool {
        self.len() < max_len || self.by_index.contains_key(&registration.message.index)
    }

    /// Insert a verified registration, keeping at most `max_len` registrations.
    ///
    /// A registration replaces the existing one of its index only if it names a later
    /// `previous_change_epoch` in chain order (see `cmp_pq_change_epochs`), i.e. it applies to a
    /// later change of the index's keys. For a builder index this holds across reuse of the
    /// index, whose stored epoch only increases.
    pub fn insert(
        &mut self,
        registration: SignedPqKeyRegistration,
        max_len: usize,
    ) -> PqKeyRegistrationInsertOutcome {
        let index = registration.message.index;
        let sequence = self.next_sequence;
        let pooled = PooledRegistration {
            sequence,
            registration,
        };
        let pool_len = self.by_index.len();
        match self.by_index.entry(index) {
            Entry::Vacant(entry) => {
                if pool_len >= max_len {
                    return PqKeyRegistrationInsertOutcome::PoolFull;
                }
                entry.insert(pooled);
            }
            Entry::Occupied(mut entry) => {
                if cmp_pq_change_epochs(
                    pooled.registration.message.previous_change_epoch,
                    entry.get().registration.message.previous_change_epoch,
                ) != Ordering::Greater
                {
                    return PqKeyRegistrationInsertOutcome::NotNewer;
                }
                let replaced = entry.insert(pooled);
                self.fifo.remove(&replaced.sequence);
            }
        }
        self.fifo.insert(sequence, index);
        self.next_sequence = self.next_sequence.saturating_add(1);
        PqKeyRegistrationInsertOutcome::Inserted
    }

    /// Number of registrations in the pool.
    fn len(&self) -> usize {
        self.by_index.len()
    }

    /// Registrations in insertion order (oldest first), used for persistence and block packing.
    pub fn iter_fifo(&self) -> impl Iterator<Item = &SignedPqKeyRegistration> {
        self.fifo
            .values()
            .filter_map(|index| self.by_index.get(index).map(|pooled| &pooled.registration))
    }

    /// Select up to `limit` registrations that are valid when applied in order to `state`, the
    /// pre-state of the block being packed.
    ///
    /// Registrations are taken oldest first. A registration is skipped if:
    ///
    /// - it is invalid against `state` (unknown or exiting validator, unknown or inactive builder,
    ///   non-zero builder VRF root, stale `previous_change_epoch`, change delay not elapsed,
    ///   all-zero key, key held by any validator or builder, including its own), or
    /// - `exits_in_block` returns `true` for its index (flagged for a builder), because an
    ///   operation processed before registrations in the same block (slashing, voluntary exit,
    ///   parent execution request) may initiate its exit, or
    /// - its leanXMSS key is registered by a registration selected earlier.
    ///
    /// Registrations apply to distinct indices, so a selected registration only changes the entry
    /// of its own index, and the key uniqueness check above accounts for keys taken by earlier
    /// registrations in the block. Keys released by earlier registrations, or by a builder deposit
    /// reusing an index, are treated as still in use, which is conservative.
    ///
    /// The pool is walked in FIFO order without sorting and the walk stops once `limit`
    /// registrations are selected. Skipped registrations cost a cheap check each (signatures are
    /// not verified), and the pool holds at most `max_pool_len` of them.
    pub fn select_for_block<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        exits_in_block: impl Fn(u64) -> bool,
        limit: usize,
        spec: &ChainSpec,
    ) -> Vec<SignedPqKeyRegistration> {
        if state.pq_public_keys().is_err() {
            return vec![];
        }

        let mut selected = Vec::with_capacity(limit.min(self.len()));
        let mut selected_keys = HashSet::with_capacity(limit.min(self.len()));
        for registration in self.iter_fifo() {
            if selected.len() >= limit {
                break;
            }
            let message = &registration.message;
            if exits_in_block(message.index)
                || verify_pq_key_registration(state, registration, VerifySignatures::False, spec)
                    .is_err()
                || !selected_keys.insert(&message.public_keys.xmss_public_key)
            {
                continue;
            }
            selected.push(registration.clone());
        }
        selected
    }

    /// The pool's registration for a validator or flagged builder index, if any.
    pub fn get(&self, index: u64) -> Option<&SignedPqKeyRegistration> {
        self.by_index.get(&index).map(|pooled| &pooled.registration)
    }

    /// Remove `registration` from the pool, if the pool holds exactly it. Returns `true` if it
    /// was removed.
    pub fn remove(&mut self, registration: &SignedPqKeyRegistration) -> bool {
        let Entry::Occupied(entry) = self.by_index.entry(registration.message.index) else {
            return false;
        };
        if entry.get().registration != *registration {
            return false;
        }
        let removed = entry.remove();
        self.fifo.remove(&removed.sequence);
        true
    }

    /// Prune registrations that are dead or invalid against `finalized_state`, returning the
    /// `(index, previous_change_epoch)` pairs of the pruned registrations.
    ///
    /// A registration is pruned if, in `finalized_state`:
    ///
    /// - its `previous_change_epoch` is dead (`is_pq_registration_dead`): its index's stored change
    ///   epoch is past it, so it was applied or a later change superseded it, or it names a change
    ///   (or builder deposit) before the finalized epoch that the finalized chain does not hold,
    ///   made on a fork that is not canonical. No descendant can include it;
    /// - any validator or builder holds its leanXMSS key: another one won a race for the key, its
    ///   own index applied it, or it re-registers a key its index holds. It is invalid against the
    ///   finalized state. It could become valid again on a descendant if the holder later changes
    ///   away from the key (or a builder's index is reused), but it is pruned anyway, as EIP-8450
    ///   allows for a first-seen registration that is no longer valid against the finalized state:
    ///   keeping it would hold its pool slot and its gossip pair indefinitely, and a resubmission
    ///   is accepted once the pair is forgotten;
    /// - its validator initiated an exit, or its builder initiated an exit
    ///   (`withdrawable_epoch != FAR_FUTURE_EPOCH`) and it names the builder's stored epoch. Neither
    ///   becomes registrable again. A builder's index can be reused by a later builder, but every
    ///   registration of the later builder names a later epoch (see `cmp_pq_change_epochs`), and is
    ///   kept.
    ///
    /// The caller must forget the returned pairs in its gossip duplicate filter: a pair whose
    /// registration lost a key race is otherwise never accepted again, since the stored change
    /// epoch does not move.
    ///
    /// Pruning against the finalized state rather than the head keeps registrations applied in
    /// non-finalized blocks, so they can be included again if those blocks are re-orged out.
    /// Block packing skips them while they are applied in the head chain.
    pub fn prune<E: EthSpec>(
        &mut self,
        finalized_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Vec<(u64, Epoch)> {
        if finalized_state.pq_key_change_epochs().is_err() {
            return vec![];
        }
        let finalized_epoch = finalized_state.current_epoch();
        let held_keys = self.finalized_held_keys(finalized_state);

        let mut pruned = vec![];
        self.by_index.retain(
            |&index,
             PooledRegistration {
                 sequence,
                 registration,
             }| {
                let message = &registration.message;
                let stored = finalized_state.get_pq_key_change_epoch(index).ok();
                let dead = stored.is_some_and(|stored| {
                    is_pq_registration_dead(stored, message.previous_change_epoch, finalized_epoch)
                });
                let exited = match PqRegistryIndex::new(index) {
                    PqRegistryIndex::Validator(validator_index) => finalized_state
                        .validators()
                        .get(validator_index as usize)
                        .is_some_and(|validator| validator.exit_epoch != spec.far_future_epoch),
                    PqRegistryIndex::Builder(builder_index) => {
                        stored == Some(message.previous_change_epoch)
                            && finalized_state
                                .get_builder(builder_index)
                                .is_ok_and(|builder| {
                                    builder.withdrawable_epoch != spec.far_future_epoch
                                })
                    }
                };
                let key_taken = held_keys.contains(&message.public_keys.xmss_public_key);
                let keep = !exited && !dead && !key_taken;
                if !keep {
                    pruned.push((*sequence, index, message.previous_change_epoch));
                }
                keep
            },
        );
        pruned
            .into_iter()
            .map(|(sequence, index, previous_change_epoch)| {
                self.fifo.remove(&sequence);
                (index, previous_change_epoch)
            })
            .collect()
    }

    /// The leanXMSS keys of the pooled registrations that a validator or builder holds in `state`.
    ///
    /// Uses the state's `PqPubkeyCache` when it is built, and otherwise scans the registry once.
    fn finalized_held_keys<E: EthSpec>(&self, state: &BeaconState<E>) -> HashSet<XmssPublicKey> {
        let pooled_keys = self
            .by_index
            .values()
            .map(|pooled| &pooled.registration.message.public_keys.xmss_public_key)
            .collect::<HashSet<_>>();
        if pooled_keys.is_empty() {
            return HashSet::new();
        }
        let cache = state.pq_pubkey_cache();
        if cache.is_initialized() {
            return pooled_keys
                .into_iter()
                .filter(|key| cache.get(key).is_some())
                .cloned()
                .collect();
        }
        let Ok(registered) = state.registered_pq_public_keys() else {
            return HashSet::new();
        };
        registered
            .map(|(_, keys)| &keys.xmss_public_key)
            .filter(|key| pooled_keys.contains(key))
            .cloned()
            .collect()
    }
}

/// Pools are equal if they hold the same registrations in the same order.
impl PartialEq for PqKeyRegistrations {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter_fifo().eq(other.iter_fifo())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationPool;
    use crate::persistence::{PersistedOperationPool, PersistedOperationPoolV20};
    use beacon_chain::test_utils::InteropGenesisBuilder;
    use beacon_chain::test_utils::builder_withdrawal_credentials;
    use bls::Signature;
    use ssz::Encode;
    use store::StoreItem;
    use types::consts::gloas::PAYLOAD_BUILDER_VERSION;
    use types::test_utils::generate_deterministic_keypairs;
    use types::{
        Epoch, ForkName, Hash256, MainnetEthSpec, MinimalEthSpec, PqKeyRegistration, PqPublicKeys,
        PqRegistryIndex, Slot,
    };

    type E = MinimalEthSpec;

    const VALIDATOR_COUNT: usize = 16;
    /// The `previous_change_epoch` of a first registration: `FAR_FUTURE_EPOCH`.
    const NEVER: u64 = u64::MAX;

    fn spec() -> ChainSpec {
        ForkName::Eip8450.make_genesis_spec(E::default_spec())
    }

    fn genesis_state(spec: &ChainSpec) -> BeaconState<E> {
        let keypairs = generate_deterministic_keypairs(VALIDATOR_COUNT);
        InteropGenesisBuilder::<E>::new()
            .build_genesis_state(&keypairs, 0, Hash256::ZERO, spec)
            .unwrap()
    }

    fn keys(key_byte: u8) -> PqPublicKeys {
        PqPublicKeys {
            xmss_public_key: vec![key_byte; 32].try_into().unwrap(),
            vrf_root: Hash256::repeat_byte(key_byte),
        }
    }

    /// A registration with dummy signatures: the pool trusts that registrations were verified on
    /// insertion and does not check signatures when packing.
    fn registration(
        index: u64,
        key_byte: u8,
        previous_change_epoch: u64,
    ) -> SignedPqKeyRegistration {
        SignedPqKeyRegistration {
            message: PqKeyRegistration {
                index,
                public_keys: keys(key_byte),
                previous_change_epoch: Epoch::new(previous_change_epoch),
            },
            possession: vec![0; 2404].try_into().unwrap(),
            signature: Signature::empty(),
        }
    }

    fn pool_with(registrations: &[SignedPqKeyRegistration]) -> PqKeyRegistrations {
        let mut pool = PqKeyRegistrations::default();
        for registration in registrations {
            assert_eq!(
                pool.insert(registration.clone(), usize::MAX),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }
        pool
    }

    fn validator_indices(registrations: &[SignedPqKeyRegistration]) -> Vec<u64> {
        registrations
            .iter()
            .map(|registration| registration.message.index)
            .collect()
    }

    #[test]
    fn duplicate_key_across_validators_selects_one() {
        let spec = spec();
        let state = genesis_state(&spec);
        let pool = pool_with(&[
            registration(0, 1, NEVER),
            registration(1, 1, NEVER),
            registration(2, 2, NEVER),
        ]);

        let selected = pool.select_for_block(&state, |_| false, 8, &spec);
        assert_eq!(validator_indices(&selected), vec![0, 2]);
    }

    #[test]
    fn invalid_registrations_are_skipped() {
        let spec = spec();
        let mut state = genesis_state(&spec);

        // Validator 1 initiated an exit.
        state.validators_mut().get_mut(1).unwrap().exit_epoch = Epoch::new(10);
        // Validator 5 holds key 5, validators 6 and 7 registered at epoch 0.
        state.set_pq_public_keys(5, keys(5), Epoch::new(0)).unwrap();
        state.set_pq_public_keys(6, keys(6), Epoch::new(0)).unwrap();
        state.set_pq_public_keys(7, keys(7), Epoch::new(0)).unwrap();

        // Validator 7 re-registers the leanXMSS key it holds, with a new VRF root.
        let mut own_key = registration(7, 7, 0);
        own_key.message.public_keys.vrf_root = Hash256::repeat_byte(0xee);

        let pool = pool_with(&[
            // Stale: validator 0 never registered, so its change epoch is `FAR_FUTURE_EPOCH`.
            registration(0, 10, 3),
            // Exited validator.
            registration(1, 11, NEVER),
            // Exited by an operation of the same block.
            registration(2, 12, NEVER),
            // Valid.
            registration(3, 13, NEVER),
            // Key owned by validator 5.
            registration(4, 5, NEVER),
            // Change of validator 6 before `MIN_PQ_KEY_CHANGE_DELAY` epochs.
            registration(6, 16, 0),
            // Validator 7's own current key: no validator may hold a registered key, including
            // the registering one, even once the delay has passed.
            own_key,
        ]);

        let selected = pool.select_for_block(&state, |index| index == 2, 8, &spec);
        assert_eq!(validator_indices(&selected), vec![3]);

        // Once the delay has passed, validator 6 can change its keys, but validator 7 cannot keep
        // its key.
        *state.slot_mut() = spec
            .min_pq_key_change_delay
            .start_slot(E::slots_per_epoch());
        let selected = pool.select_for_block(&state, |index| index == 2, 8, &spec);
        assert_eq!(validator_indices(&selected), vec![3, 6]);
    }

    #[test]
    fn selection_is_capped_at_max_pq_key_registrations() {
        let spec = spec();
        let state = genesis_state(&spec);
        let op_pool = OperationPool::<E>::new();
        for index in 0..10 {
            assert_eq!(
                op_pool.insert_pq_key_registration(registration(index, index as u8 + 1, NEVER)),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }

        let selected = op_pool.get_pq_key_registrations(&state, |_| false, &spec);
        assert_eq!(E::max_pq_key_registrations(), 8);
        assert_eq!(validator_indices(&selected), (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn nothing_selected_before_eip8450() {
        let spec = ForkName::Heze.make_genesis_spec(E::default_spec());
        let state = genesis_state(&spec);
        let pool = pool_with(&[registration(0, 1, NEVER)]);

        assert!(
            pool.select_for_block(&state, |_| false, 8, &spec)
                .is_empty()
        );
    }

    #[test]
    fn insert_replaces_only_later_previous_change_epoch() {
        let mut pool = pool_with(&[registration(0, 1, 4), registration(1, 1, NEVER)]);

        // Not later in chain order: the same change epoch, an earlier one, or a first
        // registration, which comes before every change.
        for previous_change_epoch in [4, 3, NEVER] {
            assert_eq!(
                pool.insert(registration(0, 2, previous_change_epoch), usize::MAX),
                PqKeyRegistrationInsertOutcome::NotNewer
            );
        }
        assert_eq!(pool.get(0), Some(&registration(0, 1, 4)));
        assert_eq!(pool.get(2), None);

        // Only the exact pooled registration is removed.
        assert!(!pool.remove(&registration(1, 2, NEVER)));
        assert!(pool.remove(&registration(1, 1, NEVER)));
        assert_eq!(pool.get(1), None);
        assert_eq!(
            pool.insert(registration(1, 1, NEVER), usize::MAX),
            PqKeyRegistrationInsertOutcome::Inserted
        );

        // A change replaces a pooled first registration, and a replacement moves to the back of
        // the FIFO order.
        for replacement in [registration(1, 2, 0), registration(0, 2, 5)] {
            assert_eq!(
                pool.insert(replacement, usize::MAX),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }
        assert_eq!(
            pool.iter_fifo().cloned().collect::<Vec<_>>(),
            vec![registration(1, 2, 0), registration(0, 2, 5)]
        );
    }

    #[test]
    fn pool_is_capped() {
        assert_eq!(max_pool_len::<MainnetEthSpec>(), 16_384);
        assert_eq!(max_pool_len::<MinimalEthSpec>(), 4_096);

        let max_len = 3;
        let mut pool = PqKeyRegistrations::default();
        for index in 0..3 {
            assert!(pool.has_room_for(&registration(index, 1, NEVER), max_len));
            assert_eq!(
                pool.insert(registration(index, 1, NEVER), max_len),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }

        // A new validator does not fit.
        assert!(!pool.has_room_for(&registration(3, 1, NEVER), max_len));
        assert_eq!(
            pool.insert(registration(3, 1, NEVER), max_len),
            PqKeyRegistrationInsertOutcome::PoolFull
        );
        // A later registration of a pooled validator replaces its entry.
        assert!(pool.has_room_for(&registration(1, 2, 7), max_len));
        assert_eq!(
            pool.insert(registration(1, 2, 7), max_len),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        assert_eq!(pool.len(), 3);
        assert_eq!(
            validator_indices(&pool.iter_fifo().cloned().collect::<Vec<_>>()),
            vec![0, 2, 1]
        );

        // Room frees up once entries are pruned.
        let spec = spec();
        let mut finalized_state = genesis_state(&spec);
        finalized_state
            .set_pq_public_keys(0, keys(9), Epoch::new(2))
            .unwrap();
        pool.prune(&finalized_state, &spec);
        assert_eq!(
            pool.insert(registration(3, 1, NEVER), max_len),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        assert_eq!(
            validator_indices(&pool.iter_fifo().cloned().collect::<Vec<_>>()),
            vec![2, 1, 3]
        );
    }

    #[test]
    fn prune_removes_only_registrations_dead_in_finalized_state() {
        let spec = spec();
        let mut finalized_state = genesis_state(&spec);
        // Validator 0 registered keys 1 at epoch 3 in the finalized chain.
        finalized_state
            .set_pq_public_keys(0, keys(1), Epoch::new(3))
            .unwrap();
        // Validator 5 registered keys 6 at epoch 0.
        finalized_state
            .set_pq_public_keys(5, keys(6), Epoch::new(0))
            .unwrap();
        // Validator 7 last changed its keys at epoch 4, and validator 8 at epoch 1.
        finalized_state
            .set_pq_public_keys(7, keys(8), Epoch::new(4))
            .unwrap();
        finalized_state
            .set_pq_public_keys(8, keys(10), Epoch::new(1))
            .unwrap();
        // Validator 3 exited in the finalized state.
        finalized_state
            .validators_mut()
            .get_mut(3)
            .unwrap()
            .exit_epoch = Epoch::new(1);

        // Validator 8 re-registers the leanXMSS key it holds, with a new VRF root.
        let mut own_key = registration(8, 10, 1);
        own_key.message.public_keys.vrf_root = Hash256::repeat_byte(0xee);

        let registrations = [
            // A first registration of other keys, superseded by validator 0's registration.
            registration(0, 7, NEVER),
            // Applicable to the finalized state, or applied in a block that is not finalized:
            // kept, so a re-org can include it again.
            registration(1, 2, NEVER),
            // Names a change made in a non-finalized block, while the finalized state has none.
            registration(2, 3, 5),
            // Exited.
            registration(3, 4, NEVER),
            // Lost the race for key 1 to validator 0.
            registration(4, 1, NEVER),
            // Applied: validator 5 holds exactly these keys.
            registration(5, 6, NEVER),
            // Validator 5's keys, for validator 6: lost the race too.
            registration(6, 6, NEVER),
            // Names a change before validator 7's finalized change at epoch 4.
            registration(7, 9, 2),
            // Names validator 8's finalized change, but re-registers the key it holds.
            own_key,
        ];

        // With the finalized state's PQ pubkey cache built, and without it.
        let mut uncached_state = finalized_state.clone();
        uncached_state.drop_pq_pubkey_cache();
        for state in [&finalized_state, &uncached_state] {
            let mut pool = pool_with(&registrations);
            let mut pruned = pool.prune(state, &spec);
            pruned.sort();

            assert_eq!(
                pool.iter_fifo().cloned().collect::<Vec<_>>(),
                vec![registration(1, 2, NEVER), registration(2, 3, 5)]
            );
            let mut expected = [0, 3, 4, 5, 6]
                .map(|index| (index, Epoch::new(NEVER)))
                .to_vec();
            expected.push((7, Epoch::new(2)));
            expected.push((8, Epoch::new(1)));
            assert_eq!(pruned, expected);
        }
    }

    /// A registration naming a change before the finalized epoch that the finalized state does
    /// not hold was made on an orphaned fork, and is pruned. One naming the finalized epoch or a
    /// later one may still be made by a canonical block, and is kept.
    #[test]
    fn prune_removes_registrations_naming_orphaned_changes() {
        let spec = spec();
        let mut finalized_state = genesis_state(&spec);
        let finalized_epoch = Epoch::new(5);
        *finalized_state.slot_mut() = finalized_epoch.start_slot(E::slots_per_epoch());
        // Validators 4 and 5 last changed their keys at epoch 2 in the finalized chain.
        for index in [4, 5] {
            finalized_state
                .set_pq_public_keys(index, keys(40 + index as u8), Epoch::new(2))
                .unwrap();
        }

        let registrations = [
            // Validators 0, 1 and 2 never registered in the finalized chain: changes at epochs 4,
            // 5 and 6 on other forks.
            registration(0, 1, 4),
            registration(1, 2, 5),
            registration(2, 3, 6),
            // A first registration.
            registration(3, 4, NEVER),
            // A change after validator 4's finalized change, but before the finalized epoch.
            registration(4, 5, 3),
            // The finalized change of validator 5.
            registration(5, 6, 2),
        ];
        let mut pool = pool_with(&registrations);
        let mut pruned = pool.prune(&finalized_state, &spec);
        pruned.sort();

        assert_eq!(pruned, vec![(0, Epoch::new(4)), (4, Epoch::new(3))]);
        assert_eq!(
            pool.iter_fifo().cloned().collect::<Vec<_>>(),
            vec![
                registration(1, 2, 5),
                registration(2, 3, 6),
                registration(3, 4, NEVER),
                registration(5, 6, 2),
            ]
        );

        // The first registration of validator 0 is accepted once the orphaned one is pruned.
        assert_eq!(
            pool.insert(registration(0, 1, NEVER), usize::MAX),
            PqKeyRegistrationInsertOutcome::Inserted
        );
    }

    #[test]
    fn persistence_round_trip() {
        let op_pool = OperationPool::<E>::new();
        for index in [3, 1, 2] {
            assert_eq!(
                op_pool.insert_pq_key_registration(registration(index, index as u8, NEVER)),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }

        let persisted = PersistedOperationPool::from_operation_pool(&op_pool);
        let decoded =
            PersistedOperationPool::<E>::from_store_bytes(&persisted.as_store_bytes()).unwrap();
        assert!(matches!(decoded, PersistedOperationPool::V33(_)));
        let restored = decoded.into_operation_pool().unwrap();

        assert_eq!(restored, op_pool);
        assert_eq!(
            validator_indices(&restored.get_all_pq_key_registrations()),
            vec![3, 1, 2]
        );
    }

    #[test]
    fn v20_op_pool_still_decodes() {
        let v20 = PersistedOperationPoolV20::<E> {
            attestations: vec![],
            sync_contributions: vec![],
            attester_slashings: vec![],
            proposer_slashings: vec![],
            voluntary_exits: vec![],
            bls_to_execution_changes: vec![],
            capella_bls_change_broadcast_indices: vec![7],
        };

        let decoded = PersistedOperationPool::<E>::from_store_bytes(&v20.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, PersistedOperationPool::V20(v20));
        let restored = decoded.into_operation_pool().unwrap();
        assert!(restored.get_all_pq_key_registrations().is_empty());
    }

    /// The registry index of the builder at `builder_index`, with `BUILDER_INDEX_FLAG` set.
    fn builder(builder_index: u64) -> u64 {
        PqRegistryIndex::Builder(builder_index).as_u64()
    }

    /// A builder registration of key `key_byte`, with the zero VRF root.
    fn builder_registration(
        builder_index: u64,
        key_byte: u8,
        previous_change_epoch: u64,
    ) -> SignedPqKeyRegistration {
        let mut registration =
            registration(builder(builder_index), key_byte, previous_change_epoch);
        registration.message.public_keys.vrf_root = Hash256::ZERO;
        registration
    }

    /// The genesis state at `epoch`, with `count` builders deposited at genesis (validator keys
    /// `0..count`) and the finalized checkpoint at `epoch - 1`, so that the builders are active.
    fn state_with_builders(spec: &ChainSpec, count: u64, epoch: u64) -> BeaconState<E> {
        let mut state = genesis_state(spec);
        let keypairs = generate_deterministic_keypairs(count as usize);
        for keypair in &keypairs {
            state
                .add_builder_to_registry(
                    keypair.pk.compress(),
                    PAYLOAD_BUILDER_VERSION,
                    builder_withdrawal_credentials(&keypair.pk, spec),
                    spec.min_deposit_amount,
                    Slot::new(0),
                    spec,
                )
                .unwrap();
        }
        *state.slot_mut() = Epoch::new(epoch).start_slot(E::slots_per_epoch());
        state.finalized_checkpoint_mut().epoch = Epoch::new(epoch - 1);
        state
    }

    fn initiate_builder_exit(state: &mut BeaconState<E>, builder_index: u64) {
        let withdrawable_epoch = state.current_epoch() + 2;
        state
            .builders_mut()
            .unwrap()
            .get_mut(builder_index as usize)
            .unwrap()
            .withdrawable_epoch = withdrawable_epoch;
    }

    #[test]
    fn builder_registrations_are_selected_unless_invalidated_in_block() {
        let spec = spec();
        let mut state = state_with_builders(&spec, 4, 2);
        // Builder 2 initiated an exit.
        initiate_builder_exit(&mut state, 2);

        let mut with_vrf_root = builder_registration(3, 4, 0);
        with_vrf_root.message.public_keys.vrf_root = Hash256::repeat_byte(4);
        let pool = pool_with(&[
            builder_registration(0, 1, 0),
            // Exited by an operation of the same block.
            builder_registration(1, 2, 0),
            // Exited.
            builder_registration(2, 3, 0),
            // Builders register no VRF root.
            with_vrf_root,
            // Outside the builder registry.
            builder_registration(4, 5, 0),
            // A validator registration is selected alongside.
            registration(0, 6, NEVER),
        ]);

        let selected = pool.select_for_block(&state, |index| index == builder(1), 8, &spec);
        assert_eq!(validator_indices(&selected), vec![builder(0), 0]);

        // A builder's stored epoch only moves forward numerically, also from its deposit epoch.
        let mut pool = pool;
        assert_eq!(
            pool.insert(builder_registration(0, 7, NEVER), usize::MAX),
            PqKeyRegistrationInsertOutcome::NotNewer
        );
        assert_eq!(
            pool.insert(builder_registration(0, 7, 3), usize::MAX),
            PqKeyRegistrationInsertOutcome::Inserted
        );
    }

    /// Builder registrations are pruned when dead by the builder's stored epoch (which starts at
    /// its deposit epoch), when the builder initiated an exit and the registration names its
    /// stored epoch, and when their key is held. A registration naming a later epoch for an exited
    /// builder's index is kept: a builder reusing the index names its own, later, deposit epoch.
    #[test]
    fn prune_handles_builder_entries() {
        let spec = spec();
        let mut finalized_state = state_with_builders(&spec, 6, 5);
        finalized_state
            .set_pq_public_keys(builder(0), keys(30), Epoch::new(3))
            .unwrap();
        finalized_state
            .set_pq_public_keys(5, keys(31), Epoch::new(4))
            .unwrap();
        initiate_builder_exit(&mut finalized_state, 2);
        initiate_builder_exit(&mut finalized_state, 3);

        let registrations = [
            // Superseded by builder 0's registration at epoch 3.
            builder_registration(0, 1, 0),
            // A first registration of an active builder.
            builder_registration(1, 2, 0),
            // A first registration of a builder that initiated an exit.
            builder_registration(2, 3, 0),
            // Names a later deposit epoch at the exited builder 3's index.
            builder_registration(3, 4, 7),
            // Validator 5 holds the key.
            builder_registration(4, 31, 0),
            // Names a change before the finalized epoch that the finalized state does not hold.
            builder_registration(5, 6, 2),
        ];

        let mut uncached_state = finalized_state.clone();
        uncached_state.drop_pq_pubkey_cache();
        for state in [&finalized_state, &uncached_state] {
            let mut pool = pool_with(&registrations);
            let mut pruned = pool.prune(state, &spec);
            pruned.sort();
            assert_eq!(
                pool.iter_fifo().cloned().collect::<Vec<_>>(),
                vec![builder_registration(1, 2, 0), builder_registration(3, 4, 7)]
            );
            assert_eq!(
                pruned,
                vec![
                    (builder(0), Epoch::new(0)),
                    (builder(2), Epoch::new(0)),
                    (builder(4), Epoch::new(0)),
                    (builder(5), Epoch::new(2)),
                ]
            );
        }
    }
}
