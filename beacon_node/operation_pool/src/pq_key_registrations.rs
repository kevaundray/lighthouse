use state_processing::per_block_processing::{
    VerifySignatures, cmp_pq_change_epochs, is_pq_registration_dead, verify_pq_key_registration,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, SignedPqKeyRegistration, XmssPublicKey};

/// Number of epochs of full blocks worth of registrations the pool holds at most.
///
/// See `max_pool_len`.
pub const PQ_KEY_REGISTRATION_POOL_EPOCHS: usize = 64;

/// Maximum number of registrations in the pool: `MAX_PQ_KEY_REGISTRATIONS * SLOTS_PER_EPOCH *
/// PQ_KEY_REGISTRATION_POOL_EPOCHS`, i.e. 16,384 on mainnet and 4,096 on minimal.
///
/// Blocks include at most `MAX_PQ_KEY_REGISTRATIONS` registrations, so this is 64 epochs (about 7
/// hours on mainnet) of full blocks: more than the network can include before entries are pruned
/// at the next finalization, while bounding the pool at about 45 MB (registrations are 2581 bytes
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
    /// The registration was added, possibly replacing the validator's older one.
    Inserted,
    /// The pool holds a registration for the validator with the same or a later
    /// `previous_change_epoch`.
    NotNewer,
    /// The pool is full and holds no registration for the validator to replace.
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
/// validator, and at most `max_len` registrations in total.
///
/// Every registration in the pool has passed full verification, including its BLS signature and
/// leanXMSS proof of possession. Neither signature depends on the fork, so they are not checked
/// again when packing a block.
#[derive(Debug, Default)]
pub struct PqKeyRegistrations {
    /// Map from validator index to its registration.
    by_validator_index: HashMap<u64, PooledRegistration>,
    /// Validator indices of the registrations in insertion order, keyed by sequence number.
    fifo: BTreeMap<u64, u64>,
    /// Sequence number of the next insertion.
    next_sequence: u64,
}

impl PqKeyRegistrations {
    /// Returns `true` if inserting `registration` would not exceed `max_len`: the pool has room,
    /// or `registration` would replace the validator's existing registration.
    pub fn has_room_for(&self, registration: &SignedPqKeyRegistration, max_len: usize) -> bool {
        self.len() < max_len
            || self
                .by_validator_index
                .contains_key(&registration.message.validator_index)
    }

    /// Insert a verified registration, keeping at most `max_len` registrations.
    ///
    /// A registration replaces the validator's existing one only if it names a later
    /// `previous_change_epoch` in chain order (see `cmp_pq_change_epochs`), i.e. it applies to a
    /// later change of the validator's keys.
    pub fn insert(
        &mut self,
        registration: SignedPqKeyRegistration,
        max_len: usize,
    ) -> PqKeyRegistrationInsertOutcome {
        let validator_index = registration.message.validator_index;
        let sequence = self.next_sequence;
        let pooled = PooledRegistration {
            sequence,
            registration,
        };
        let pool_len = self.by_validator_index.len();
        match self.by_validator_index.entry(validator_index) {
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
        self.fifo.insert(sequence, validator_index);
        self.next_sequence = self.next_sequence.saturating_add(1);
        PqKeyRegistrationInsertOutcome::Inserted
    }

    /// Number of registrations in the pool.
    fn len(&self) -> usize {
        self.by_validator_index.len()
    }

    /// Registrations in insertion order (oldest first), used for persistence and block packing.
    pub fn iter_fifo(&self) -> impl Iterator<Item = &SignedPqKeyRegistration> {
        self.fifo.values().filter_map(|validator_index| {
            self.by_validator_index
                .get(validator_index)
                .map(|pooled| &pooled.registration)
        })
    }

    /// Select up to `limit` registrations that are valid when applied in order to `state`, the
    /// pre-state of the block being packed.
    ///
    /// Registrations are taken oldest first. A registration is skipped if:
    ///
    /// - it is invalid against `state` (unknown or exiting validator, stale
    ///   `previous_change_epoch`, change delay not elapsed, key owned by another validator), or
    /// - `exits_in_block` returns `true` for its validator, because an operation processed before
    ///   registrations in the same block (slashing, voluntary exit, parent execution request) may
    ///   initiate its exit, or
    /// - its leanXMSS key is registered by a registration selected earlier.
    ///
    /// Registrations apply to distinct validators, so a selected registration only changes the
    /// entry of its own validator, and the key uniqueness check above accounts for keys taken by
    /// earlier registrations in the block. Keys released by earlier registrations are treated as
    /// still in use, which is conservative.
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
            if exits_in_block(message.validator_index)
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

    /// The pool's registration for `validator_index`, if any.
    pub fn get(&self, validator_index: u64) -> Option<&SignedPqKeyRegistration> {
        self.by_validator_index
            .get(&validator_index)
            .map(|pooled| &pooled.registration)
    }

    /// Remove `registration` from the pool, if the pool holds exactly it. Returns `true` if it
    /// was removed.
    pub fn remove(&mut self, registration: &SignedPqKeyRegistration) -> bool {
        let validator_index = registration.message.validator_index;
        let Entry::Occupied(entry) = self.by_validator_index.entry(validator_index) else {
            return false;
        };
        if entry.get().registration != *registration {
            return false;
        }
        let removed = entry.remove();
        self.fifo.remove(&removed.sequence);
        true
    }

    /// Prune registrations that can no longer be included in any block descending from
    /// `finalized_state`, returning the `(validator_index, previous_change_epoch)` pairs of the
    /// pruned registrations.
    ///
    /// A registration is pruned if, in `finalized_state`:
    ///
    /// - its `previous_change_epoch` is dead (`is_pq_registration_dead`): its validator's
    ///   `pq_key_change_epochs` entry is past it, so it was applied or a later change superseded
    ///   it, or it names a change before the finalized epoch that the finalized chain does not
    ///   hold, made on a fork that is not canonical;
    /// - its validator already holds exactly its keys: it was applied, and applying it again
    ///   would change nothing;
    /// - another validator owns its leanXMSS key: it lost a race for the key (a validator only
    ///   releases a key by changing its own keys, which is not expected for a key it just won);
    /// - its validator initiated an exit.
    ///
    /// The caller should forget the returned pairs in its gossip duplicate filter: a pair whose
    /// registration lost a key race is otherwise never accepted again, since the validator's
    /// change epoch does not move.
    ///
    /// Pruning against the finalized state rather than the head keeps registrations applied in
    /// non-finalized blocks, so they can be included again if those blocks are re-orged out.
    /// Block packing skips them while they are applied in the head chain.
    pub fn prune<E: EthSpec>(
        &mut self,
        finalized_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Vec<(u64, Epoch)> {
        let (Ok(change_epochs), Ok(public_keys)) = (
            finalized_state.pq_key_change_epochs(),
            finalized_state.pq_public_keys(),
        ) else {
            return vec![];
        };
        let validators = finalized_state.validators();
        let finalized_epoch = finalized_state.current_epoch();
        let key_owners = self.finalized_key_owners(finalized_state);

        let mut pruned = vec![];
        self.by_validator_index.retain(
            |&validator_index,
             PooledRegistration {
                 sequence,
                 registration,
             }| {
                let message = &registration.message;
                let index = validator_index as usize;
                let exited = validators
                    .get(index)
                    .is_some_and(|validator| validator.exit_epoch != spec.far_future_epoch);
                let dead = change_epochs.get(index).is_some_and(|epoch| {
                    is_pq_registration_dead(*epoch, message.previous_change_epoch, finalized_epoch)
                });
                let applied = public_keys
                    .get(index)
                    .is_some_and(|keys| *keys == message.public_keys);
                let key_taken = key_owners
                    .get(&message.public_keys.xmss_public_key)
                    .is_some_and(|owner| *owner != validator_index);
                let keep = !exited && !dead && !applied && !key_taken;
                if !keep {
                    pruned.push((*sequence, validator_index, message.previous_change_epoch));
                }
                keep
            },
        );
        pruned
            .into_iter()
            .map(|(sequence, validator_index, previous_change_epoch)| {
                self.fifo.remove(&sequence);
                (validator_index, previous_change_epoch)
            })
            .collect()
    }

    /// The owners in `state` of the leanXMSS keys of the pooled registrations.
    ///
    /// Uses the state's `PqPubkeyCache` when it is built, and otherwise scans the registry once.
    fn finalized_key_owners<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> HashMap<XmssPublicKey, u64> {
        let pooled_keys = self
            .by_validator_index
            .values()
            .map(|pooled| &pooled.registration.message.public_keys.xmss_public_key)
            .collect::<HashSet<_>>();
        if pooled_keys.is_empty() {
            return HashMap::new();
        }
        let cache = state.pq_pubkey_cache();
        if cache.is_initialized() {
            return pooled_keys
                .into_iter()
                .filter_map(|key| cache.get(key).map(|owner| (key.clone(), owner as u64)))
                .collect();
        }
        let Ok(public_keys) = state.pq_public_keys() else {
            return HashMap::new();
        };
        public_keys
            .iter()
            .enumerate()
            .filter(|(_, keys)| keys.is_registered() && pooled_keys.contains(&keys.xmss_public_key))
            .map(|(owner, keys)| (keys.xmss_public_key.clone(), owner as u64))
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
    use bls::Signature;
    use ssz::Encode;
    use store::StoreItem;
    use types::test_utils::generate_deterministic_keypairs;
    use types::{
        Epoch, ForkName, Hash256, MainnetEthSpec, MinimalEthSpec, PQ_KEYS_VERSION_1,
        PqKeyRegistration, PqPublicKeys,
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
            version: PQ_KEYS_VERSION_1,
            xmss_public_key: vec![key_byte; 32].try_into().unwrap(),
            vrf_root: vec![key_byte; 32].try_into().unwrap(),
        }
    }

    /// A registration with dummy signatures: the pool trusts that registrations were verified on
    /// insertion and does not check signatures when packing.
    fn registration(
        validator_index: u64,
        key_byte: u8,
        previous_change_epoch: u64,
    ) -> SignedPqKeyRegistration {
        SignedPqKeyRegistration {
            message: PqKeyRegistration {
                validator_index,
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
            .map(|registration| registration.message.validator_index)
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
        // Validator 5 holds key 5, validator 6 registered at epoch 0.
        state.set_pq_public_keys(5, keys(5), Epoch::new(0)).unwrap();
        state.set_pq_public_keys(6, keys(6), Epoch::new(0)).unwrap();

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
        ]);

        let selected = pool.select_for_block(&state, |index| index == 2, 8, &spec);
        assert_eq!(validator_indices(&selected), vec![3]);

        // Once the delay has passed, validator 6 can change its keys.
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
        // Validator 7 last changed its keys at epoch 4.
        finalized_state
            .set_pq_public_keys(7, keys(8), Epoch::new(4))
            .unwrap();
        // Validator 3 exited in the finalized state.
        finalized_state
            .validators_mut()
            .get_mut(3)
            .unwrap()
            .exit_epoch = Epoch::new(1);

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
}
