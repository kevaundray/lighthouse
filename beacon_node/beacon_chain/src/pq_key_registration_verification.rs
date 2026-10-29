//! Verification of EIP-8450 post-quantum key registrations received on gossip or via the HTTP API.
//!
//! Gossip verification implements the `pq_key_registration` topic rules of EIP-8450, in their
//! stated order. HTTP API verification runs every check of block processing against the head
//! state.

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::EventKind;
use operation_pool::PqKeyRegistrationInsertOutcome;
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::{
    BlockOperationError, PqKeyRegistrationInvalid,
};
use state_processing::per_block_processing::signature_sets::{
    Error as SignatureSetError, get_builder_pubkey_from_state, get_pubkey_from_state,
    pq_key_registration_signature_set,
};
use state_processing::per_block_processing::{
    VerifySignatures, is_pq_registration_dead, is_valid_pq_possession_proof, pq_public_key_owner,
    verify_pq_key_registration,
};
use std::collections::HashSet;
use types::{
    BeaconState, BeaconStateError, BuilderIndex, Epoch, EthSpec, PqRegistryIndex,
    SignedPqKeyRegistration, Slot, VrfRoot, XmssPublicKey,
};

/// Reasons a `SignedPqKeyRegistration` failed verification.
///
/// The doc comment of each gossip variant states the action the gossip rules prescribe.
#[derive(Debug)]
pub enum Error {
    /// The current slot, allowing for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`, is prior to the EIP-8450
    /// fork.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: the message is not valid on the current fork yet.
    PriorToEip8450 { current_slot: Slot },
    /// The head state is prior to the EIP-8450 fork, so it has no key registry to verify against.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: our head lags the fork boundary.
    HeadPriorToEip8450,
    /// The validator is not in the head state.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    UnknownValidator(u64),
    /// The validator has initiated an exit in the head state.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    ValidatorExiting {
        validator_index: u64,
        exit_epoch: Epoch,
    },
    /// The builder (index without `BUILDER_INDEX_FLAG`) is not in the head state.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    UnknownBuilder(BuilderIndex),
    /// The builder has initiated an exit in the head state.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    BuilderExiting {
        builder_index: BuilderIndex,
        withdrawable_epoch: Epoch,
    },
    /// The builder's deposit epoch is not before the head state's finalized epoch, so the builder
    /// is not active yet.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: finality can differ between nodes, so a peer that has seen finality advance
    /// forwards it honestly.
    BuilderDepositNotFinalized {
        builder_index: BuilderIndex,
        deposit_epoch: Epoch,
        finalized_epoch: Epoch,
    },
    /// The builder registers a non-zero VRF root.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    BuilderNonZeroVrfRoot(BuilderIndex),
    /// A valid registration for the same index and previous change epoch was already seen.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE.
    PriorRegistrationKnown {
        index: u64,
        previous_change_epoch: Epoch,
    },
    /// The registration does not name the stored change epoch of its index in the head state.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    PreviousChangeEpochMismatch { expected: Epoch, found: Epoch },
    /// The index has registered keys, and `MIN_PQ_KEY_CHANGE_DELAY` epochs have not passed
    /// since its last change at the current (wall-clock) epoch, allowing for
    /// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: the registration becomes valid later.
    ChangeTooSoon {
        current_epoch: Epoch,
        earliest_epoch: Epoch,
    },
    /// The BLS signature of the registrant's signing key is invalid.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    InvalidSignature,
    /// The registration carries the all-zero leanXMSS key.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    ZeroXmssPublicKey,
    /// A validator or builder, possibly the one registering, registered the leanXMSS key in the
    /// head state. `owner` is flagged for a builder.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    XmssPublicKeyInUse { owner: u64 },
    /// The leanXMSS proof of possession is invalid.
    ///
    /// ## Peer scoring
    ///
    /// REJECT.
    InvalidPossessionProof,
    /// HTTP API only: the registration fails a check of block processing against the head state.
    Invalid(PqKeyRegistrationInvalid),
    /// HTTP API only: the pool holds a different registration for the same index and previous
    /// change epoch.
    ConflictsWithPool,
    /// The registration is valid but the op pool is full (see
    /// `operation_pool::max_pq_key_registrations_in_pool`). Its pair is not marked as observed,
    /// so it can be submitted again once the pool drains.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: a local resource limit, not a fault of the peer.
    PoolFull,
    /// There was an error whilst processing the registration. It is not known if it is valid.
    ///
    /// ## Peer scoring
    ///
    /// IGNORE: we cannot tell if the message is valid.
    BeaconChainError(Box<BeaconChainError>),
    /// See `Self::BeaconChainError`.
    BeaconStateError(BeaconStateError),
    /// See `Self::BeaconChainError`.
    SignatureSetError(SignatureSetError),
    /// HTTP API only: a check of block processing failed with an error rather than a verdict.
    VerificationError(BlockOperationError<PqKeyRegistrationInvalid>),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

impl From<SignatureSetError> for Error {
    fn from(e: SignatureSetError) -> Self {
        Error::SignatureSetError(e)
    }
}

impl From<BlockOperationError<PqKeyRegistrationInvalid>> for Error {
    fn from(e: BlockOperationError<PqKeyRegistrationInvalid>) -> Self {
        match e {
            BlockOperationError::Invalid(reason) => Error::Invalid(reason),
            e => Error::VerificationError(e),
        }
    }
}

/// A registration that passed full verification, including its BLS signature and leanXMSS proof
/// of possession.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPqKeyRegistration(SignedPqKeyRegistration);

impl VerifiedPqKeyRegistration {
    pub fn as_inner(&self) -> &SignedPqKeyRegistration {
        &self.0
    }

    pub fn into_inner(self) -> SignedPqKeyRegistration {
        self.0
    }
}

/// Outcome of verifying a registration submitted via the HTTP API.
#[derive(Debug, Clone, PartialEq)]
pub enum PqKeyRegistrationOutcome {
    /// The registration is valid and new: import and publish it.
    New(Box<VerifiedPqKeyRegistration>),
    /// The registration is already known.
    AlreadyKnown,
}

/// Tracks the `(index, previous_change_epoch)` pairs of the valid registrations seen, implementing
/// the gossip rule that only the first valid registration for a pair is forwarded. Builder indices
/// are flagged.
///
/// Registrations are signed with the genesis fork version, so the set is not reset at fork
/// boundaries. A pair is pruned once it is dead in the finalized state (see
/// `is_pq_registration_dead`), since no registration for that pair can become valid again.
#[derive(Debug, Default)]
pub struct ObservedPqKeyRegistrations {
    observed: HashSet<(u64, Epoch)>,
}

impl ObservedPqKeyRegistrations {
    /// Returns `true` if a valid registration for the pair was observed.
    pub fn is_known(&self, index: u64, previous_change_epoch: Epoch) -> bool {
        self.observed.contains(&(index, previous_change_epoch))
    }

    /// Record a valid registration for the pair. Returns `true` if the pair was not known.
    pub fn observe(&mut self, index: u64, previous_change_epoch: Epoch) -> bool {
        self.observed.insert((index, previous_change_epoch))
    }

    /// Forget the pair, e.g. because its registration could not be stored after all.
    pub fn forget(&mut self, index: u64, previous_change_epoch: Epoch) {
        self.observed.remove(&(index, previous_change_epoch));
    }

    /// Drop the pairs that no registration can match on top of `finalized_state`. The stored
    /// change epoch of a builder index is read from the builder registry lists.
    pub fn prune<E: EthSpec>(&mut self, finalized_state: &BeaconState<E>) {
        if finalized_state.pq_key_change_epochs().is_err() {
            return;
        }
        let finalized_epoch = finalized_state.current_epoch();
        self.observed.retain(|(index, previous_change_epoch)| {
            finalized_state
                .get_pq_key_change_epoch(*index)
                .ok()
                .is_none_or(|stored| {
                    !is_pq_registration_dead(stored, *previous_change_epoch, finalized_epoch)
                })
        });
    }

    /// Number of observed pairs.
    pub fn len(&self) -> usize {
        self.observed.len()
    }

    /// Returns `true` if no pair is observed.
    pub fn is_empty(&self) -> bool {
        self.observed.is_empty()
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Verify a post-quantum key registration received on gossip, following the
    /// `pq_key_registration` gossip rules of EIP-8450 in their stated order. On success the
    /// registration's pair is recorded as observed.
    ///
    /// The current epoch of the fork gate and the change delay allows for
    /// `MAXIMUM_GOSSIP_CLOCK_DISPARITY`, as the spec's `is_future_epoch` does.
    pub fn verify_pq_key_registration_for_gossip(
        &self,
        signed_registration: SignedPqKeyRegistration,
    ) -> Result<VerifiedPqKeyRegistration, Error> {
        let current_slot = self
            .slot_clock
            .now_with_future_tolerance(self.spec.maximum_gossip_clock_disparity())
            .ok_or(BeaconChainError::UnableToReadSlot)?;
        if !self
            .spec
            .fork_name_at_slot::<T::EthSpec>(current_slot)
            .eip8450_enabled()
        {
            return Err(Error::PriorToEip8450 { current_slot });
        }
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

        let head = self.head_snapshot();
        let state = &head.beacon_state;

        let registration = &signed_registration.message;
        let index = registration.index;
        let public_keys = &registration.public_keys;

        // [IGNORE] The head state is at or after the fork, so that it has the registry. A head
        // state prior to the fork (e.g. right after the fork boundary) has nothing to check
        // against.
        if state.pq_key_change_epochs().is_err() {
            return Err(Error::HeadPriorToEip8450);
        }

        // [REJECT] The index is a validator in the head state that has not initiated an exit, or
        // a flagged builder index of a builder that has not initiated an exit.
        // [IGNORE] A builder's deposit epoch is finalized in the head state, so it is active.
        // [REJECT] A builder registers a zero VRF root.
        let pubkey = match PqRegistryIndex::new(index) {
            PqRegistryIndex::Validator(validator_index) => {
                let validator = state
                    .validators()
                    .get(validator_index as usize)
                    .ok_or(Error::UnknownValidator(validator_index))?;
                if validator.exit_epoch != self.spec.far_future_epoch {
                    return Err(Error::ValidatorExiting {
                        validator_index,
                        exit_epoch: validator.exit_epoch,
                    });
                }
                validator.pubkey
            }
            PqRegistryIndex::Builder(builder_index) => {
                let builder = state
                    .builders()?
                    .get(builder_index as usize)
                    .ok_or(Error::UnknownBuilder(builder_index))?;
                if builder.withdrawable_epoch != self.spec.far_future_epoch {
                    return Err(Error::BuilderExiting {
                        builder_index,
                        withdrawable_epoch: builder.withdrawable_epoch,
                    });
                }
                let finalized_epoch = state.finalized_checkpoint().epoch;
                if builder.deposit_epoch >= finalized_epoch {
                    return Err(Error::BuilderDepositNotFinalized {
                        builder_index,
                        deposit_epoch: builder.deposit_epoch,
                        finalized_epoch,
                    });
                }
                if public_keys.vrf_root != VrfRoot::ZERO {
                    return Err(Error::BuilderNonZeroVrfRoot(builder_index));
                }
                builder.pubkey
            }
        };

        // Hold the lock until the registration is observed, so that only the first valid
        // registration for a pair passes.
        let mut observed = self.observed_pq_key_registrations.lock();

        // [IGNORE] The registration is the first valid one for its pair.
        if observed.is_known(index, registration.previous_change_epoch) {
            return Err(Error::PriorRegistrationKnown {
                index,
                previous_change_epoch: registration.previous_change_epoch,
            });
        }

        // [REJECT] The registration names the stored change epoch of the index in the head state.
        let last_change_epoch = state.get_pq_key_change_epoch(index)?;
        if registration.previous_change_epoch != last_change_epoch {
            return Err(Error::PreviousChangeEpochMismatch {
                expected: last_change_epoch,
                found: registration.previous_change_epoch,
            });
        }

        // [IGNORE] If the index's stored leanXMSS key is not all-zero, its change delay has passed
        // at the current epoch, allowing for clock disparity. An entry holding the all-zero key
        // stores its never-registered marker, not a change epoch, which is never added to.
        if state.is_pq_registered(index)? {
            let earliest_epoch = registration
                .previous_change_epoch
                .saturating_add(self.spec.min_pq_key_change_delay);
            if current_epoch < earliest_epoch {
                return Err(Error::ChangeTooSoon {
                    current_epoch,
                    earliest_epoch,
                });
            }
        }

        // [REJECT] The leanXMSS key is not all-zero and is not registered for any index in the head
        // state, including this one. Checked before the signature, as it is cheaper.
        if public_keys.xmss_public_key == XmssPublicKey::default() {
            return Err(Error::ZeroXmssPublicKey);
        }
        if let Some(owner) = pq_public_key_owner(state, &public_keys.xmss_public_key)? {
            return Err(Error::XmssPublicKeyInUse { owner });
        }

        // [REJECT] The signing key of the validator or builder signed the registration.
        let signature_set = pq_key_registration_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            |i| get_builder_pubkey_from_state(state, i),
            &signed_registration,
            &self.spec,
        )?;
        if !signature_set.verify() {
            return Err(Error::InvalidSignature);
        }

        // [REJECT] The proof of possession of the leanXMSS key for the BLS public key of the
        // validator or builder is valid.
        if !is_valid_pq_possession_proof(
            state,
            &pubkey,
            &public_keys.xmss_public_key,
            &signed_registration.possession,
            &self.spec,
        ) {
            return Err(Error::InvalidPossessionProof);
        }

        // The pool must have room before the pair is marked as observed, otherwise the
        // registration could not be propagated again once the pool drains.
        if !self
            .op_pool
            .pq_key_registration_has_room(&signed_registration)
        {
            return Err(Error::PoolFull);
        }

        observed.observe(index, registration.previous_change_epoch);
        drop(observed);

        Ok(VerifiedPqKeyRegistration(signed_registration))
    }

    /// Verify a post-quantum key registration submitted via the HTTP API.
    ///
    /// Runs every check of block processing, including both signatures, against the head state
    /// first, so a registration already applied on the head is refused even while the pool still
    /// holds it (until finalization prunes it). A valid registration already in the pool is then
    /// `AlreadyKnown`.
    ///
    /// If the pool holds a different registration for the index, it is replaced when it no
    /// longer verifies against the head (e.g. another validator took its key), and conflicts
    /// otherwise.
    ///
    /// A valid registration whose pair was already observed, but which the pool does not hold
    /// (e.g. it was dropped because the pool was full, or a re-org made it valid again), is `New`:
    /// the submitter gets it imported and published rather than being told it is known.
    pub fn verify_pq_key_registration_for_http_api(
        &self,
        signed_registration: SignedPqKeyRegistration,
    ) -> Result<PqKeyRegistrationOutcome, Error> {
        let registration = &signed_registration.message;
        let index = registration.index;
        let previous_change_epoch = registration.previous_change_epoch;

        let head = self.head_snapshot();
        let state = &head.beacon_state;
        verify_pq_key_registration(
            state,
            &signed_registration,
            VerifySignatures::True,
            &self.spec,
        )?;

        if let Some(pooled) = self.op_pool.get_pq_key_registration(index) {
            if pooled == signed_registration {
                return Ok(PqKeyRegistrationOutcome::AlreadyKnown);
            }
            // Both registrations verifying against the head means they name the same change.
            if verify_pq_key_registration(state, &pooled, VerifySignatures::False, &self.spec)
                .is_ok()
            {
                return Err(Error::ConflictsWithPool);
            }
            self.op_pool.remove_pq_key_registration(&pooled);
        }

        if !self
            .op_pool
            .pq_key_registration_has_room(&signed_registration)
        {
            return Err(Error::PoolFull);
        }

        self.observed_pq_key_registrations
            .lock()
            .observe(index, previous_change_epoch);

        Ok(PqKeyRegistrationOutcome::New(Box::new(
            VerifiedPqKeyRegistration(signed_registration),
        )))
    }

    /// Import a verified post-quantum key registration to the op pool, notifying SSE subscribers
    /// if it was added.
    ///
    /// If the pool filled up since verification, the registration's pair is forgotten so it can
    /// be submitted again.
    pub fn import_pq_key_registration(
        &self,
        registration: VerifiedPqKeyRegistration,
    ) -> PqKeyRegistrationInsertOutcome {
        let index = registration.as_inner().message.index;
        let previous_change_epoch = registration.as_inner().message.previous_change_epoch;
        let event = self
            .event_handler
            .as_ref()
            .filter(|event_handler| event_handler.has_pq_key_registration_subscribers())
            .map(|_| registration.as_inner().clone());

        let outcome = self
            .op_pool
            .insert_pq_key_registration(registration.into_inner());

        match outcome {
            PqKeyRegistrationInsertOutcome::Inserted => {
                if let (Some(event_handler), Some(registration)) =
                    (self.event_handler.as_ref(), event)
                {
                    event_handler.register(EventKind::PqKeyRegistration(Box::new(registration)));
                }
            }
            PqKeyRegistrationInsertOutcome::PoolFull => {
                self.observed_pq_key_registrations
                    .lock()
                    .forget(index, previous_change_epoch);
            }
            PqKeyRegistrationInsertOutcome::NotNewer => {}
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use state_processing::per_block_processing::get_pq_possession_signing_root;
    use std::sync::{Arc, LazyLock};
    use std::time::Duration;
    use types::{
        ForkName, Hash256, MinimalEthSpec, PQ_POSSESSION_XMSS_INDEX, PqKeyRegistration,
        PqPublicKeys, PqRegistryIndex, XmssPublicKey,
    };

    type E = MinimalEthSpec;
    /// The `previous_change_epoch` of a first registration: `FAR_FUTURE_EPOCH`.
    const NEVER: u64 = u64::MAX;

    const VALIDATOR_COUNT: usize = 8;

    /// leanXMSS keys from fixed seeds, generated once.
    static XMSS_KEYS: LazyLock<Vec<lean_pq::xmss::SecretKey>> = LazyLock::new(|| {
        (1..=2_u8)
            .map(|seed| lean_pq::xmss::SecretKey::from_seed([seed; 32]))
            .collect()
    });

    fn get_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(Arc::new(spec))
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();
        harness
    }

    fn registration(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        validator_index: u64,
        xmss_key: &lean_pq::xmss::SecretKey,
        previous_change_epoch: u64,
    ) -> SignedPqKeyRegistration {
        let state = harness.get_current_state();
        let xmss_public_key =
            XmssPublicKey::try_from(xmss_key.public_key().to_bytes().to_vec()).unwrap();
        let validator_pubkey = state
            .get_validator(validator_index as usize)
            .unwrap()
            .pubkey;
        let possession_root = get_pq_possession_signing_root(
            &state,
            &validator_pubkey,
            &xmss_public_key,
            &harness.spec,
        );
        let possession = xmss_key
            .sign(&possession_root.0, PQ_POSSESSION_XMSS_INDEX)
            .unwrap();

        PqKeyRegistration {
            index: validator_index,
            public_keys: PqPublicKeys {
                xmss_public_key,
                vrf_root: Hash256::repeat_byte(validator_index as u8),
            },
            previous_change_epoch: Epoch::new(previous_change_epoch),
        }
        .sign(
            possession.to_bytes().to_vec().try_into().unwrap(),
            &harness.validator_keypairs[validator_index as usize].sk,
            state.genesis_validators_root(),
            &harness.spec,
        )
    }

    #[tokio::test]
    async fn gossip_rules_apply_in_order() {
        let harness = get_harness();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];

        let valid = registration(&harness, 0, key_a, NEVER);
        assert_eq!(
            chain
                .verify_pq_key_registration_for_gossip(valid.clone())
                .unwrap()
                .into_inner(),
            valid
        );

        // [IGNORE] Only the first valid registration for a pair passes.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(valid.clone()),
            Err(Error::PriorRegistrationKnown { .. })
        ));
        let other_key = registration(&harness, 0, key_b, NEVER);
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(other_key),
            Err(Error::PriorRegistrationKnown { .. })
        ));

        // [REJECT] Unknown validator.
        let mut unknown_validator = registration(&harness, 1, key_b, NEVER);
        unknown_validator.message.index = VALIDATOR_COUNT as u64;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(unknown_validator),
            Err(Error::UnknownValidator(_))
        ));

        // [REJECT] Stale previous change epoch: a first registration naming `GENESIS_EPOCH`.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(registration(&harness, 1, key_b, 0)),
            Err(Error::PreviousChangeEpochMismatch { expected, found })
                if expected == Epoch::new(NEVER) && found == Epoch::new(0)
        ));

        // [REJECT] The all-zero key, checked before the signature.
        let mut zero_key = registration(&harness, 1, key_b, NEVER);
        zero_key.message.public_keys.xmss_public_key = XmssPublicKey::default();
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(zero_key),
            Err(Error::ZeroXmssPublicKey)
        ));

        // [REJECT] BLS signature of another validator.
        let mut bad_signature = registration(&harness, 1, key_b, NEVER);
        bad_signature.signature = registration(&harness, 2, key_b, NEVER).signature;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(bad_signature),
            Err(Error::InvalidSignature)
        ));

        // [REJECT] Proof of possession of another key and validator.
        let mut bad_possession = registration(&harness, 1, key_b, NEVER);
        bad_possession.possession = valid.possession.clone();
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(bad_possession),
            Err(Error::InvalidPossessionProof)
        ));

        // Rejected registrations do not mark their pair as observed.
        assert!(
            chain
                .verify_pq_key_registration_for_gossip(registration(&harness, 1, key_b, NEVER))
                .is_ok()
        );
    }

    /// The fork gate uses the current slot allowing for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`: a
    /// registration received within the disparity before the fork boundary passes it.
    #[tokio::test]
    async fn fork_gate_allows_gossip_clock_disparity() {
        let mut spec = ForkName::Heze.make_genesis_spec(E::default_spec());
        spec.eip8450_fork_epoch = Some(Epoch::new(1));
        let harness = BeaconChainHarness::builder(E::default())
            .spec(Arc::new(spec))
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        let chain = &harness.chain;
        let fork_slot = Epoch::new(1).start_slot(E::slots_per_epoch());
        let fork_start = chain.slot_clock.start_of(fork_slot).unwrap();
        let disparity = chain.spec.maximum_gossip_clock_disparity();
        let valid = registration(&harness, 0, &XMSS_KEYS[0], NEVER);

        // Just outside the disparity: still before the fork.
        chain
            .slot_clock
            .set_current_time(fork_start - disparity - Duration::from_millis(1));
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(valid.clone()),
            Err(Error::PriorToEip8450 { current_slot }) if current_slot == fork_slot - 1
        ));

        // Within the disparity: the fork gate passes, and the pre-fork head is what ignores it.
        chain.slot_clock.set_current_time(fork_start - disparity);
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(valid.clone()),
            Err(Error::HeadPriorToEip8450)
        ));

        // The head state is checked before the validator.
        let mut unknown_validator = valid;
        unknown_validator.message.index = VALIDATOR_COUNT as u64;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(unknown_validator),
            Err(Error::HeadPriorToEip8450)
        ));
    }

    #[tokio::test]
    async fn http_api_checks_pool_and_block_processing_rules() {
        let harness = get_harness();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];

        let valid = registration(&harness, 2, key_a, NEVER);
        let PqKeyRegistrationOutcome::New(verified) = chain
            .verify_pq_key_registration_for_http_api(valid.clone())
            .unwrap()
        else {
            panic!("registration should be new");
        };
        assert_eq!(
            chain.import_pq_key_registration(*verified),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        assert_eq!(
            chain.op_pool.get_all_pq_key_registrations(),
            vec![valid.clone()]
        );

        assert_eq!(
            chain
                .verify_pq_key_registration_for_http_api(valid)
                .unwrap(),
            PqKeyRegistrationOutcome::AlreadyKnown
        );
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(registration(&harness, 2, key_b, NEVER)),
            Err(Error::ConflictsWithPool)
        ));

        let mut bad_possession = registration(&harness, 3, key_b, NEVER);
        bad_possession.possession = registration(&harness, 4, key_b, NEVER).possession;
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(bad_possession),
            Err(Error::Invalid(PqKeyRegistrationInvalid::BadPossessionProof))
        ));
    }

    #[tokio::test]
    async fn http_api_imports_observed_registration_missing_from_pool() {
        let harness = get_harness();
        let chain = &harness.chain;

        // Observed on gossip, but never stored (e.g. dropped by a re-org or a full pool).
        let valid = registration(&harness, 0, &XMSS_KEYS[0], NEVER);
        chain
            .verify_pq_key_registration_for_gossip(valid.clone())
            .unwrap();
        assert!(chain.op_pool.get_all_pq_key_registrations().is_empty());

        let PqKeyRegistrationOutcome::New(verified) = chain
            .verify_pq_key_registration_for_http_api(valid.clone())
            .unwrap()
        else {
            panic!("registration missing from the pool should be imported");
        };
        assert_eq!(
            chain.import_pq_key_registration(*verified),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        assert_eq!(chain.op_pool.get_all_pq_key_registrations(), vec![valid]);
    }

    #[tokio::test]
    async fn full_pool_ignores_without_observing() {
        let harness = get_harness();
        let chain = &harness.chain;
        let first = registration(&harness, 0, &XMSS_KEYS[0], NEVER);
        let second = registration(&harness, 1, &XMSS_KEYS[1], NEVER);

        // Verified while the pool has room.
        let verified = chain
            .verify_pq_key_registration_for_gossip(first.clone())
            .unwrap();

        // Fill the pool with registrations of other validators.
        let max_len = operation_pool::max_pq_key_registrations_in_pool::<E>();
        for validator_index in 0..max_len as u64 {
            let mut filler = second.clone();
            filler.message.index = validator_index + VALIDATOR_COUNT as u64;
            assert_eq!(
                chain.op_pool.insert_pq_key_registration(filler),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }

        // The pool filled up after verification: the pair is forgotten so it can be resubmitted.
        assert_eq!(
            chain.import_pq_key_registration(verified),
            PqKeyRegistrationInsertOutcome::PoolFull
        );
        assert!(
            !chain
                .observed_pq_key_registrations
                .lock()
                .is_known(0, Epoch::new(NEVER))
        );

        // Gossip ignores a valid registration without observing its pair, and HTTP refuses it.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(second.clone()),
            Err(Error::PoolFull)
        ));
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(first),
            Err(Error::PoolFull)
        ));
        let observed = chain.observed_pq_key_registrations.lock();
        assert!(!observed.is_known(0, Epoch::new(NEVER)));
        assert!(!observed.is_known(1, Epoch::new(NEVER)));
    }

    /// A head state loaded from disk (e.g. after a restart) gets its PQ pubkey cache built with
    /// the other caches, so gossip checks do not scan the registry.
    #[tokio::test]
    async fn build_caches_builds_pq_pubkey_cache() {
        let harness = get_harness();
        let mut state = harness.get_current_state();
        state.drop_pq_pubkey_cache();
        assert!(!state.pq_pubkey_cache().is_initialized());
        state.build_caches(&harness.spec).unwrap();
        assert!(state.pq_pubkey_cache().is_initialized());

        // Before the fork it leaves the cache untouched.
        let heze_spec = ForkName::Heze.make_genesis_spec(E::default_spec());
        let mut heze_state = genesis::InteropGenesisBuilder::<E>::new()
            .build_genesis_state(
                &harness.validator_keypairs,
                0,
                types::Hash256::ZERO,
                &heze_spec,
            )
            .unwrap();
        heze_state.drop_pq_pubkey_cache();
        heze_state.build_caches(&heze_spec).unwrap();
        assert!(!heze_state.pq_pubkey_cache().is_initialized());
    }

    /// Gossip-verify and import `registrations`, then produce the next block and return its
    /// registrations.
    async fn import_and_pack(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        registrations: &[SignedPqKeyRegistration],
    ) -> Vec<SignedPqKeyRegistration> {
        for registration in registrations {
            let verified = harness
                .chain
                .verify_pq_key_registration_for_gossip(registration.clone())
                .unwrap();
            assert_eq!(
                harness.chain.import_pq_key_registration(verified),
                PqKeyRegistrationInsertOutcome::Inserted
            );
        }
        let block_root = harness.extend_slots(1).await;
        let block = harness.chain.get_block(&block_root).await.unwrap().unwrap();
        block
            .message()
            .body()
            .pq_key_registrations()
            .unwrap()
            .to_vec()
    }

    /// A validator that loses a race for a key can register another key once finality prunes the
    /// losing registration, and an applied registration is refused over HTTP while still pooled.
    #[tokio::test]
    async fn key_race_loser_registers_again_after_finality() {
        let harness = get_harness();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];

        // Validators 1 and 0 race for key A; validator 1 is first in the pool and wins.
        let winner = registration(&harness, 1, key_a, NEVER);
        let loser = registration(&harness, 0, key_a, NEVER);
        let included = import_and_pack(&harness, &[winner.clone(), loser.clone()]).await;
        assert_eq!(included, vec![winner.clone()]);

        // Applied on the head: HTTP refuses it although the pool still holds it.
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(winner.clone()),
            Err(Error::Invalid(_))
        ));

        // The loser's pair is observed, so a registration of another key is ignored on gossip.
        let retry = registration(&harness, 0, key_b, NEVER);
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(retry.clone()),
            Err(Error::PriorRegistrationKnown { .. })
        ));

        // Finality prunes both registrations and forgets the loser's pair.
        harness
            .extend_slots(5 * E::slots_per_epoch() as usize)
            .await;
        assert!(harness.finalized_checkpoint().epoch >= 1);
        assert!(chain.op_pool.get_all_pq_key_registrations().is_empty());
        assert!(
            !chain
                .observed_pq_key_registrations
                .lock()
                .is_known(0, Epoch::new(NEVER))
        );

        // The validator registers another key.
        let verified = chain
            .verify_pq_key_registration_for_gossip(retry.clone())
            .unwrap();
        assert_eq!(
            chain.import_pq_key_registration(verified),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        assert_eq!(chain.op_pool.get_all_pq_key_registrations(), vec![retry]);
    }

    /// Gossip and HTTP reject a change that re-registers the key its own validator holds: every
    /// registration carries a key that no validator holds, including the registering one.
    #[tokio::test]
    async fn own_current_key_is_rejected() {
        let mut spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        // Changes are allowed at once, so the key check is reached.
        spec.min_pq_key_change_delay = Epoch::new(0);
        let harness = BeaconChainHarness::builder(E::default())
            .spec(Arc::new(spec))
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];

        let first = registration(&harness, 0, key_a, NEVER);
        assert_eq!(
            import_and_pack(&harness, std::slice::from_ref(&first)).await,
            vec![first]
        );
        let change_epoch = *harness
            .get_current_state()
            .pq_key_change_epochs()
            .unwrap()
            .get(0)
            .unwrap();

        let same_key = registration(&harness, 0, key_a, change_epoch.as_u64());
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(same_key.clone()),
            Err(Error::XmssPublicKeyInUse { owner: 0 })
        ));
        // On gossip the key rule comes before the signature: a key in use with a signature of
        // another validator is rejected for its key.
        let mut bad_signature = same_key.clone();
        bad_signature.signature = registration(&harness, 1, key_b, NEVER).signature;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(bad_signature.clone()),
            Err(Error::XmssPublicKeyInUse { owner: 0 })
        ));
        // Block processing checks the signature first.
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(bad_signature),
            Err(Error::Invalid(PqKeyRegistrationInvalid::BadSignature))
        ));
        assert!(matches!(
            chain.verify_pq_key_registration_for_http_api(same_key),
            Err(Error::Invalid(
                PqKeyRegistrationInvalid::XmssPublicKeyInUse { owner: 0 }
            ))
        ));

        // A change to a new key is accepted: the rejection did not observe the pair.
        assert!(
            chain
                .verify_pq_key_registration_for_gossip(registration(
                    &harness,
                    0,
                    key_b,
                    change_epoch.as_u64()
                ))
                .is_ok()
        );
    }

    /// Over HTTP, a pooled registration that lost its key is replaced right away.
    #[tokio::test]
    async fn http_api_replaces_pooled_registration_that_lost_its_key() {
        let harness = get_harness();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];

        let winner = registration(&harness, 1, key_a, NEVER);
        let loser = registration(&harness, 0, key_a, NEVER);
        let included = import_and_pack(&harness, &[winner.clone(), loser.clone()]).await;
        assert_eq!(included, vec![winner.clone()]);

        let retry = registration(&harness, 0, key_b, NEVER);
        let PqKeyRegistrationOutcome::New(verified) = chain
            .verify_pq_key_registration_for_http_api(retry.clone())
            .unwrap()
        else {
            panic!("the pooled registration no longer verifies and should be replaced");
        };
        assert_eq!(
            chain.import_pq_key_registration(*verified),
            PqKeyRegistrationInsertOutcome::Inserted
        );
        let pooled = chain.op_pool.get_all_pq_key_registrations();
        assert!(pooled.contains(&retry));
        assert!(!pooled.contains(&loser));

        let block_root = harness.extend_slots(1).await;
        let block = chain.get_block(&block_root).await.unwrap().unwrap();
        assert_eq!(
            block
                .message()
                .body()
                .pq_key_registrations()
                .unwrap()
                .as_slice(),
            std::slice::from_ref(&retry)
        );
    }

    #[tokio::test]
    async fn observed_pairs_are_pruned_by_finalized_state() {
        let harness = get_harness();
        let mut finalized_state = harness.get_current_state();
        *finalized_state.slot_mut() = Epoch::new(5).start_slot(E::slots_per_epoch());
        let keys = registration(&harness, 0, &XMSS_KEYS[0], NEVER)
            .message
            .public_keys;
        // Validator 0 last changed its keys at epoch 3; validator 1 never registered.
        finalized_state
            .set_pq_public_keys(0, keys, Epoch::new(3))
            .unwrap();

        let mut observed = ObservedPqKeyRegistrations::default();
        let pairs = [
            (0, NEVER),
            (0, 2),
            (0, 3),
            (0, 4),
            (0, 5),
            (0, 6),
            (1, NEVER),
            (1, 4),
            (1, 5),
            (1, 6),
        ];
        for (validator_index, previous_change_epoch) in pairs {
            assert!(observed.observe(validator_index, Epoch::new(previous_change_epoch)));
        }
        assert!(!observed.observe(1, Epoch::new(NEVER)));

        observed.prune(&finalized_state);
        // Behind validator 0's finalized change: its first registration and a change naming
        // epoch 2. Changes at epoch 4, before the finalized epoch 5, that the finalized state
        // does not hold were made on orphaned forks. Changes at the finalized epoch or later may
        // still be made by canonical blocks, so they are kept.
        let kept = [(0, 3), (0, 5), (0, 6), (1, NEVER), (1, 5), (1, 6)];
        assert_eq!(observed.len(), kept.len());
        for (validator_index, previous_change_epoch) in kept {
            assert!(observed.is_known(validator_index, Epoch::new(previous_change_epoch)));
        }
    }

    /// Validators whose keys the genesis builders of `builder_harness` use, by builder index.
    const BUILDER_VALIDATORS: [usize; 2] = [6, 7];

    /// The registry index of the builder at `builder_index`, with `BUILDER_INDEX_FLAG` set.
    fn builder(builder_index: u64) -> u64 {
        PqRegistryIndex::Builder(builder_index).as_u64()
    }

    /// An Eip8450-genesis harness with the builders of `BUILDER_VALIDATORS`, deposited at genesis
    /// and so not active until epoch 0 is finalized.
    fn builder_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let harness = BeaconChainHarness::builder(E::default())
            .spec(Arc::new(spec))
            .deterministic_keypairs(VALIDATOR_COUNT)
            .genesis_builders(BUILDER_VALIDATORS.to_vec(), 32_000_000_000)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        harness.advance_slot();
        harness
    }

    /// A registration of `xmss_key`, with the zero VRF root, for the builder at `builder_index`,
    /// with a valid proof of possession and BLS authorization.
    fn builder_registration(
        harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
        builder_index: u64,
        xmss_key: &lean_pq::xmss::SecretKey,
        previous_change_epoch: u64,
    ) -> SignedPqKeyRegistration {
        let state = harness.get_current_state();
        let xmss_public_key =
            XmssPublicKey::try_from(xmss_key.public_key().to_bytes().to_vec()).unwrap();
        let pubkey = state.get_builder(builder_index).unwrap().pubkey;
        let possession_root =
            get_pq_possession_signing_root(&state, &pubkey, &xmss_public_key, &harness.spec);
        let possession = xmss_key
            .sign(&possession_root.0, PQ_POSSESSION_XMSS_INDEX)
            .unwrap();

        PqKeyRegistration {
            index: builder(builder_index),
            public_keys: PqPublicKeys {
                xmss_public_key,
                vrf_root: Hash256::ZERO,
            },
            previous_change_epoch: Epoch::new(previous_change_epoch),
        }
        .sign(
            possession.to_bytes().to_vec().try_into().unwrap(),
            &harness.validator_keypairs[BUILDER_VALIDATORS[builder_index as usize]].sk,
            state.genesis_validators_root(),
            &harness.spec,
        )
    }

    #[tokio::test]
    async fn gossip_builder_rules_apply_in_order() {
        let harness = builder_harness();
        let chain = &harness.chain;
        let [key_a, key_b] = [&XMSS_KEYS[0], &XMSS_KEYS[1]];
        let deposit_epoch = 0;
        let with_vrf_root = |mut registration: SignedPqKeyRegistration| {
            registration.message.public_keys.vrf_root = Hash256::repeat_byte(1);
            registration
        };

        // [IGNORE] Not active: the deposit epoch is not finalized. The finality rule comes before
        // the VRF root rule.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(with_vrf_root(builder_registration(
                &harness,
                0,
                key_a,
                deposit_epoch
            ))),
            Err(Error::BuilderDepositNotFinalized {
                builder_index: 0,
                ..
            })
        ));
        // [REJECT] Outside the builder registry.
        let mut unknown = builder_registration(&harness, 0, key_a, deposit_epoch);
        unknown.message.index = builder(BUILDER_VALIDATORS.len() as u64);
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(unknown),
            Err(Error::UnknownBuilder(2))
        ));

        // Finalize the deposit epoch.
        harness
            .extend_slots(5 * E::slots_per_epoch() as usize)
            .await;
        assert!(harness.finalized_checkpoint().epoch > deposit_epoch);

        // [REJECT] A non-zero VRF root, checked before the stored change epoch.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(with_vrf_root(builder_registration(
                &harness, 0, key_a, NEVER
            ))),
            Err(Error::BuilderNonZeroVrfRoot(0))
        ));
        // [REJECT] A builder's never-registered marker is its deposit epoch, not
        // `FAR_FUTURE_EPOCH`.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(builder_registration(
                &harness, 0, key_a, NEVER
            )),
            Err(Error::PreviousChangeEpochMismatch { expected, found })
                if expected == Epoch::new(deposit_epoch) && found == Epoch::new(NEVER)
        ));
        // [REJECT] The all-zero key, checked before the signature.
        let mut zero_key = builder_registration(&harness, 0, key_a, deposit_epoch);
        zero_key.message.public_keys.xmss_public_key = XmssPublicKey::default();
        zero_key.signature = registration(&harness, 0, key_a, NEVER).signature;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(zero_key),
            Err(Error::ZeroXmssPublicKey)
        ));
        // [REJECT] Signed by a validator's key rather than the builder's.
        let mut validator_signed = builder_registration(&harness, 0, key_a, deposit_epoch);
        validator_signed.signature = validator_signed
            .message
            .clone()
            .sign(
                validator_signed.possession.clone(),
                &harness.validator_keypairs[0].sk,
                harness.get_current_state().genesis_validators_root(),
                &harness.spec,
            )
            .signature;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(validator_signed),
            Err(Error::InvalidSignature)
        ));
        // [REJECT] A proof of possession for a validator's BLS public key.
        let mut other_pubkey = builder_registration(&harness, 0, key_a, deposit_epoch);
        other_pubkey.possession = registration(&harness, 0, key_a, NEVER).possession;
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(other_pubkey),
            Err(Error::InvalidPossessionProof)
        ));

        let valid = builder_registration(&harness, 0, key_a, deposit_epoch);
        assert!(chain.verify_pq_key_registration_for_gossip(valid).is_ok());
        assert!(
            chain
                .observed_pq_key_registrations
                .lock()
                .is_known(builder(0), Epoch::new(deposit_epoch))
        );
        // [IGNORE] Only the first valid registration for the pair passes, but the VRF root rule
        // comes first.
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(builder_registration(
                &harness,
                0,
                key_b,
                deposit_epoch
            )),
            Err(Error::PriorRegistrationKnown { index, .. }) if index == builder(0)
        ));
        assert!(matches!(
            chain.verify_pq_key_registration_for_gossip(with_vrf_root(builder_registration(
                &harness,
                0,
                key_b,
                deposit_epoch
            ))),
            Err(Error::BuilderNonZeroVrfRoot(0))
        ));
    }

    /// Builder pairs are pruned against the builder lists, whose never-registered marker is the
    /// deposit epoch.
    #[tokio::test]
    async fn observed_builder_pairs_are_pruned_by_builder_lists() {
        let harness = builder_harness();
        let mut finalized_state = harness.get_current_state();
        *finalized_state.slot_mut() = Epoch::new(5).start_slot(E::slots_per_epoch());
        let keys = builder_registration(&harness, 0, &XMSS_KEYS[0], 0)
            .message
            .public_keys;
        // Builder 0 last changed its keys at epoch 3; builder 1 never registered (deposit
        // epoch 0).
        finalized_state
            .set_pq_public_keys(builder(0), keys, Epoch::new(3))
            .unwrap();

        let mut observed = ObservedPqKeyRegistrations::default();
        let pairs = [
            (builder(0), 0),
            (builder(0), 3),
            (builder(1), 0),
            (builder(1), 2),
            (builder(1), 6),
            (builder(1), NEVER),
        ];
        for (index, previous_change_epoch) in pairs {
            assert!(observed.observe(index, Epoch::new(previous_change_epoch)));
        }
        observed.prune(&finalized_state);
        let kept = [(builder(0), 3), (builder(1), 0), (builder(1), 6)];
        assert_eq!(observed.len(), kept.len());
        for (index, previous_change_epoch) in kept {
            assert!(observed.is_known(index, Epoch::new(previous_change_epoch)));
        }
    }
}
