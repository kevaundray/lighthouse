#[cfg(target_feature = "avx2")]
mod avx2 {
    use beacon_chain::{
        BeaconChain, PqLocalAttesterIdentity, PqNewPayloadTransport, TestingPqBlockingHook,
        builder::{BeaconChainBuilder, Witness},
    };
    use consensus_signature::{AggregationService, IndividualSignature, PqPublicKey};
    use std::sync::Arc;
    use store::{HotColdDB, MemoryStore, StoreConfig};
    use types::{
        Attestation, BeaconBlock, ChainSpec, Checkpoint, EthSpec, ForkName, Hash256,
        MainnetEthSpec, MinimalEthSpec, RelativeEpoch, SignedBeaconBlock, Slot,
    };

    type TestWitness =
        Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

    struct ValidExecution;

    impl PqNewPayloadTransport<MinimalEthSpec> for ValidExecution {
        fn notify_new_payload<'a>(
            &'a self,
            _request: execution_layer::NewPayloadRequest<'a, MinimalEthSpec>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
        }

        fn notify_forkchoice_updated<'a>(
            &'a self,
            _head_block_hash: types::ExecutionBlockHash,
            _current_slot: Slot,
            _head_block_root: Hash256,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<execution_layer::PayloadStatus, execution_layer::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(execution_layer::PayloadStatus::Valid) })
        }
    }

    struct Fixture {
        chain: Arc<BeaconChain<TestWitness>>,
        _runtime: task_executor::test_utils::TestRuntime,
    }

    fn electra_spec() -> ChainSpec {
        ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000)
    }

    fn exact_snapshot_store(
        spec: Arc<ChainSpec>,
    ) -> Arc<HotColdDB<MinimalEthSpec, MemoryStore, MemoryStore>> {
        let mut config = StoreConfig::default();
        config.hierarchy_config.exponents = vec![0];
        config.block_cache_size = 0;
        Arc::new(HotColdDB::open_ephemeral(config, spec).expect("snapshot-every-slot store"))
    }

    async fn fresh_fixture_with_spec_and_reconciliation(
        spec: ChainSpec,
        reconcile: bool,
    ) -> Fixture {
        fresh_fixture_with_options(spec, reconcile, None).await
    }

    async fn fresh_fixture_with_options(
        spec: ChainSpec,
        reconcile: bool,
        context_hook: Option<Arc<TestingPqBlockingHook>>,
    ) -> Fixture {
        fresh_fixture_with_cache_options(spec, reconcile, context_hook, false).await
    }

    async fn fresh_fixture_with_cache_options(
        spec: ChainSpec,
        reconcile: bool,
        context_hook: Option<Arc<TestingPqBlockingHook>>,
        drop_current_committee_cache: bool,
    ) -> Fixture {
        let runtime = task_executor::test_utils::TestRuntime::default();
        let spec = Arc::new(spec);
        let mut genesis =
            state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
                Hash256::ZERO,
                0,
                (1..=16)
                    .map(|byte| state_processing::DirectGenesisValidator {
                        public_key: PqPublicKey::deserialize(&[byte; 32])
                            .expect("canonical synthetic public key"),
                        withdrawal_credentials: Hash256::ZERO,
                    })
                    .collect(),
                None,
                &spec,
            )
            .expect("direct PQ genesis");
        genesis
            .build_all_committee_caches(&spec)
            .expect("genesis committee caches");
        if drop_current_committee_cache {
            genesis
                .drop_committee_cache(RelativeEpoch::Current)
                .expect("resume-style absent current committee cache");
        }
        let store = exact_snapshot_store(Arc::clone(&spec));
        let builder = BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
            .store(Arc::clone(&store))
            .custom_spec(Arc::clone(&spec));
        let builder = if drop_current_committee_cache {
            let persisted = builder.genesis_state(genesis).expect("persist genesis");
            drop(persisted);
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(store)
                .custom_spec(spec)
                .resume_from_db()
                .expect("load resume snapshot with ephemeral caches absent")
        } else {
            builder.genesis_state(genesis).expect("persist genesis")
        };
        let mut builder = builder
            .pq_aggregation_service(Arc::new(
                AggregationService::new().expect("PQ aggregation service"),
            ))
            .task_executor(runtime.task_executor.clone())
            .testing_only_pq_execution_notifier(Arc::new(ValidExecution));
        if let Some(hook) = context_hook {
            builder = builder.testing_only_pq_local_attester_context_hook(hook);
        }
        let chain = Arc::new(builder.build().expect("PQ chain"));
        if reconcile {
            chain
                .reconcile_persisted_pq_head()
                .await
                .expect("reconcile genesis execution head");
        }
        Fixture {
            chain,
            _runtime: runtime,
        }
    }

    async fn fresh_fixture_with_reconciliation(reconcile: bool) -> Fixture {
        fresh_fixture_with_spec_and_reconciliation(electra_spec(), reconcile).await
    }

    async fn fresh_fixture() -> Fixture {
        fresh_fixture_with_reconciliation(true).await
    }

    async fn synthetic_slot_seventeen_fixture() -> Fixture {
        let runtime = task_executor::test_utils::TestRuntime::default();
        let spec = Arc::new(electra_spec());
        let mut state =
            state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
                Hash256::ZERO,
                0,
                (1..=16)
                    .map(|byte| state_processing::DirectGenesisValidator {
                        public_key: PqPublicKey::deserialize(&[byte; 32])
                            .expect("canonical synthetic public key"),
                        withdrawal_credentials: Hash256::ZERO,
                    })
                    .collect(),
                None,
                &spec,
            )
            .expect("direct PQ genesis");
        *state.slot_mut() = Slot::new(17);
        *state.block_roots_mut().get_mut(0).expect("slot-zero root") = Hash256::repeat_byte(0x10);
        *state
            .block_roots_mut()
            .get_mut(7)
            .expect("current shuffling decision root") = Hash256::repeat_byte(0x17);
        *state
            .block_roots_mut()
            .get_mut(16)
            .expect("epoch-two target root") = Hash256::repeat_byte(0x26);
        *state.current_justified_checkpoint_mut() = Checkpoint {
            epoch: types::Epoch::new(1),
            root: Hash256::repeat_byte(0x33),
        };
        state
            .build_committee_cache(RelativeEpoch::Current, &spec)
            .expect("slot-seventeen current committee cache");
        let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
        *block.slot_mut() = Slot::new(17);
        *block.state_root_mut() = state
            .update_tree_hash_cache()
            .expect("synthetic slot-seventeen state root");
        let signed = SignedBeaconBlock::from_block(block, IndividualSignature::empty());
        let chain = Arc::new(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(Arc::clone(&spec)))
                .custom_spec(spec)
                .testing_only_persist_unverified_canonical_snapshot(state, signed)
                .expect("persist synthetic slot-seventeen snapshot")
                .pq_aggregation_service(Arc::new(
                    AggregationService::new().expect("PQ aggregation service"),
                ))
                .task_executor(runtime.task_executor.clone())
                .testing_only_pq_execution_notifier(Arc::new(ValidExecution))
                .build()
                .expect("synthetic slot-seventeen chain"),
        );
        chain.slot_clock.set_slot(17);
        chain
            .reconcile_persisted_pq_head()
            .await
            .expect("reconcile synthetic slot-seventeen execution head");
        Fixture {
            chain,
            _runtime: runtime,
        }
    }

    async fn wait_for_blocking_hook(
        hook: &TestingPqBlockingHook,
        task: &tokio::task::JoinHandle<
            Result<
                beacon_chain::PqLocalAttestationContext<MinimalEthSpec>,
                beacon_chain::PqLocalAttestationContextError,
            >,
        >,
    ) {
        let entered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while hook.entered() == 0 && !task.is_finished() {
                tokio::task::yield_now().await;
            }
            hook.entered()
        })
        .await;
        if entered != Ok(1) {
            hook.release();
        }
        assert_eq!(entered, Ok(1), "context must enter the blocking boundary");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_registry_yields_exact_two_current_slot_candidates() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                PqLocalAttesterIdentity::new(
                    validator.pubkey,
                    u64::try_from(index).expect("bounded validator index"),
                )
            })
            .collect::<Vec<_>>()
            .into();
        let expected = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| {
                head.beacon_state
                    .get_attestation_duties(index, RelativeEpoch::Current)
                    .expect("cached attester duty")
                    .filter(|duty| duty.slot == Slot::new(0))
                    .map(|duty| (index, validator.pubkey, duty))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            expected.len(),
            2,
            "the frozen full-16 profile has two duties per slot"
        );

        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("exact current-slot local context");
        let context = fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent exact current-slot context");

        assert_eq!(context.slot(), Slot::new(0));
        assert_eq!(context.bound_head_root(), head.beacon_block_root);
        assert_eq!(context.candidates().len(), expected.len());
        assert_eq!(
            context
                .candidates()
                .iter()
                .map(|candidate| (
                    candidate.validator_index(),
                    candidate.committee_index(),
                    candidate.committee_position(),
                    candidate.committee_length(),
                    candidate.committee_count_at_slot(),
                    u64::from(candidate.subnet()),
                ))
                .collect::<Vec<_>>(),
            vec![(6, 0, 0, 2, 1, 0), (15, 0, 1, 2, 1, 0)],
            "frozen full-16 profile has an independently pinned slot-zero committee vector",
        );
        for (candidate, (index, pubkey, duty)) in context.candidates().iter().zip(expected) {
            assert_eq!(candidate.validator_index(), index as u64);
            assert_eq!(candidate.pubkey(), pubkey);
            assert_eq!(candidate.committee_index(), duty.index);
            assert_eq!(candidate.committee_position(), duty.committee_position);
            assert_eq!(candidate.committee_length(), duty.committee_len);
            assert_eq!(candidate.committee_count_at_slot(), duty.committees_at_slot);
            let Attestation::Electra(attestation) = candidate.attestation() else {
                panic!("frozen PQ profile must produce Electra candidates")
            };
            assert_eq!(attestation.data.slot, Slot::new(0));
            assert_eq!(attestation.data.index, 0);
            assert_eq!(attestation.data.beacon_block_root, head.beacon_block_root);
            assert_eq!(
                attestation.data.source,
                head.beacon_state.current_justified_checkpoint(),
            );
            assert_eq!(attestation.data.target.epoch.as_u64(), 0);
            assert_eq!(attestation.data.target.root, head.beacon_block_root);
            assert_eq!(attestation.aggregation_bits.num_set_bits(), 0);
            assert_eq!(attestation.committee_bits.num_set_bits(), 1);
            assert!(
                attestation
                    .committee_bits
                    .get(duty.index as usize)
                    .expect("committee bit in bounds")
            );
        }
        let expected_dependent_root = head
            .beacon_state
            .attester_shuffling_decision_root(head.beacon_block_root, RelativeEpoch::Current)
            .expect("current attester dependent root");
        assert_eq!(context.dependent_root(), expected_dependent_root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resume_style_missing_committee_cache_is_rebuilt_off_loop() {
        let fixture = fresh_fixture_with_cache_options(electra_spec(), true, None, true).await;
        let head = fixture.chain.head_snapshot();
        assert!(
            !head
                .beacon_state
                .committee_cache_is_initialized(RelativeEpoch::Current),
            "fixture must model a decoded persisted state with ephemeral caches absent",
        );
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("context derivation must rebuild the cloned Current committee cache");
        let context = fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent rebuilt-cache context");
        assert_eq!(context.slot(), Slot::new(0));
        assert_eq!(context.bound_head_root(), head.beacon_block_root);
        assert_eq!(context.candidates().len(), 2);
        assert!(
            !fixture
                .chain
                .head_snapshot()
                .beacon_state
                .committee_cache_is_initialized(RelativeEpoch::Current),
            "ephemeral rebuild must not mutate the canonical persisted snapshot",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_epoch_zero_context_pins_dependent_source_and_target_roots() {
        let fixture = synthetic_slot_seventeen_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("slot-seventeen context");
        let context = fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent slot-seventeen context");
        assert_eq!(context.slot(), Slot::new(17));
        assert_eq!(context.dependent_root(), Hash256::repeat_byte(0x17));
        assert_ne!(
            context.dependent_root(),
            head.beacon_state
                .attester_shuffling_decision_root(head.beacon_block_root, RelativeEpoch::Previous,)
                .expect("previous-epoch decision root"),
            "Current and Previous shuffling roots must be mutation-distinct",
        );
        assert_eq!(context.candidates().len(), 2);
        for candidate in context.candidates() {
            let Attestation::Electra(attestation) = candidate.attestation() else {
                panic!("frozen PQ profile must produce Electra candidates")
            };
            assert_eq!(
                attestation.data.source,
                Checkpoint {
                    epoch: types::Epoch::new(1),
                    root: Hash256::repeat_byte(0x33),
                }
            );
            assert_eq!(
                attestation.data.target,
                Checkpoint {
                    epoch: types::Epoch::new(2),
                    root: Hash256::repeat_byte(0x26),
                }
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identity_count_above_frozen_sixteen_is_rejected() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let mut identities = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                PqLocalAttesterIdentity::new(
                    validator.pubkey,
                    u64::try_from(index).expect("bounded validator index"),
                )
            })
            .collect::<Vec<_>>();
        identities.push(identities[0]);

        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(identities.into())
                .await,
            Err(
                beacon_chain::PqLocalAttestationContextError::IdentityCapacity {
                    count: 17,
                    maximum: 16,
                }
            )
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identities_must_be_sorted_unique_and_bound_to_the_registry() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| {
                PqLocalAttesterIdentity::new(
                    validator.pubkey,
                    u64::try_from(index).expect("bounded validator index"),
                )
            })
            .collect::<Vec<_>>();

        let mut out_of_order = identities.clone();
        out_of_order.swap(0, 1);
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(out_of_order.into())
                .await,
            Err(
                beacon_chain::PqLocalAttestationContextError::IdentityOrder {
                    previous: 1,
                    current: 0,
                }
            )
        ));

        let mut duplicate_index = identities.clone();
        duplicate_index[1] = PqLocalAttesterIdentity::new(identities[1].pubkey(), 0);
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(duplicate_index.into())
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::DuplicateValidatorIndex(0))
        ));

        let mut duplicate_pubkey = identities.clone();
        duplicate_pubkey[1] =
            PqLocalAttesterIdentity::new(identities[0].pubkey(), identities[1].validator_index());
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(duplicate_pubkey.into())
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::DuplicatePubkey)
        ));

        let mut wrong_pubkey = identities.clone();
        wrong_pubkey[0] = PqLocalAttesterIdentity::new(
            PqPublicKey::deserialize(&[0x55; 32]).expect("canonical wrong public key"),
            0,
        );
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(wrong_pubkey.into())
                .await,
            Err(
                beacon_chain::PqLocalAttestationContextError::ValidatorPubkeyMismatch {
                    validator_index: 0,
                }
            )
        ));

        let out_of_bounds: Arc<[PqLocalAttesterIdentity]> =
            Arc::from([PqLocalAttesterIdentity::new(identities[0].pubkey(), 16)]);
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(out_of_bounds)
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::ValidatorIndexOutOfBounds(16))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selected_head_must_be_exactly_execution_reconciled() {
        let fixture = fresh_fixture_with_reconciliation(false).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        let pending = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect_err("pending execution reconciliation must reject local duties");
        assert!(matches!(
            pending,
            beacon_chain::PqLocalAttestationContextError::HeadReconciliationPending {
                block_root,
            } if block_root == head.beacon_block_root
        ));
        assert!(pending.is_retryable());

        fixture
            .chain
            .reconcile_persisted_pq_head()
            .await
            .expect("reconcile selected genesis head");
        fixture
            .chain
            .testing_only_set_pq_execution_reconciliation_failed(head.beacon_block_root);
        let failed = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect_err("failed execution reconciliation is terminal");
        assert!(matches!(
            failed,
            beacon_chain::PqLocalAttestationContextError::HeadReconciliationFailed {
                block_root,
            } if block_root == head.beacon_block_root
        ));
        assert!(!failed.is_retryable());

        let replacement = Hash256::repeat_byte(0x42);
        fixture
            .chain
            .testing_only_replace_pq_canonical_head_root(replacement);
        let inconsistent = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect_err("head/reconciliation disagreement is a terminal local invariant");
        assert!(matches!(
            inconsistent,
            beacon_chain::PqLocalAttestationContextError::HeadReconciliationInconsistent {
                head: inconsistent_head,
                reconciliation,
            } if inconsistent_head == replacement && reconciliation == head.beacon_block_root
        ));
        assert!(!inconsistent.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canonical_head_behind_current_slot_is_retryable() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        fixture.chain.slot_clock.set_slot(1);

        let error = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect_err("an older head is not a current-slot signing context");
        assert!(matches!(
            error,
            beacon_chain::PqLocalAttestationContextError::HeadNotReady {
                head,
                current,
            } if head == Slot::new(0) && current == Slot::new(1)
        ));
        assert!(error.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_context_requires_the_exact_three_hundred_second_electra_profile() {
        let fixture = fresh_fixture_with_spec_and_reconciliation(
            ForkName::Electra
                .make_genesis_spec(MinimalEthSpec::default_spec())
                .set_slot_duration_ms::<MinimalEthSpec>(299_000),
            true,
        )
        .await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(identities)
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::InvalidSlotDuration(
                duration,
            )) if duration == std::time::Duration::from_secs(299)
        ));
    }

    #[test]
    fn profile_gate_pins_minimal_electra_and_exact_slot_duration() {
        assert!(
            beacon_chain::testing_only_validate_pq_local_attester_profile::<MinimalEthSpec>(
                &electra_spec(),
                Slot::new(0),
            )
            .is_ok()
        );
        for seconds in [299, 301] {
            let spec = ForkName::Electra
                .make_genesis_spec(MinimalEthSpec::default_spec())
                .set_slot_duration_ms::<MinimalEthSpec>(seconds * 1_000);
            assert!(matches!(
                beacon_chain::testing_only_validate_pq_local_attester_profile::<MinimalEthSpec>(
                    &spec,
                    Slot::new(0),
                ),
                Err(beacon_chain::PqLocalAttestationContextError::InvalidSlotDuration(duration))
                    if duration == std::time::Duration::from_secs(seconds)
            ));
        }
        let deneb = ForkName::Deneb
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000);
        assert!(matches!(
            beacon_chain::testing_only_validate_pq_local_attester_profile::<MinimalEthSpec>(
                &deneb,
                Slot::new(0),
            ),
            Err(beacon_chain::PqLocalAttestationContextError::WrongFork(
                ForkName::Deneb
            ))
        ));
        let mainnet = ForkName::Electra
            .make_genesis_spec(MainnetEthSpec::default_spec())
            .set_slot_duration_ms::<MainnetEthSpec>(300_000);
        assert!(matches!(
            beacon_chain::testing_only_validate_pq_local_attester_profile::<MainnetEthSpec>(
                &mainnet,
                Slot::new(0),
            ),
            Err(beacon_chain::PqLocalAttestationContextError::WrongEthSpec)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clock_advance_during_derivation_discards_the_stale_context() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let derivation = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.pq_local_attestation_context(identities).await })
        };
        wait_for_blocking_hook(&hook, &derivation).await;
        fixture.chain.slot_clock.set_slot(1);
        hook.release();

        let error = derivation
            .await
            .expect("derivation task")
            .expect_err("a late clock change must discard stale candidates");
        assert!(matches!(
            error,
            beacon_chain::PqLocalAttestationContextError::ClockChanged {
                before,
                after,
            } if before == Slot::new(0) && after == Slot::new(1)
        ));
        assert!(error.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reconciliation_change_during_derivation_discards_the_stale_context() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let derivation = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.pq_local_attestation_context(identities).await })
        };
        wait_for_blocking_hook(&hook, &derivation).await;
        fixture
            .chain
            .testing_only_set_pq_execution_reconciliation_failed(head.beacon_block_root);
        hook.release();

        let error = derivation
            .await
            .expect("derivation task")
            .expect_err("a late reconciliation change must discard stale candidates");
        assert!(matches!(
            error,
            beacon_chain::PqLocalAttestationContextError::HeadReconciliationFailed {
                block_root,
            } if block_root == head.beacon_block_root
        ));
        assert!(!error.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canonical_head_change_during_derivation_discards_the_stale_context() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let derivation = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.pq_local_attestation_context(identities).await })
        };
        wait_for_blocking_hook(&hook, &derivation).await;
        let replacement = Hash256::repeat_byte(0x5a);
        fixture
            .chain
            .testing_only_replace_pq_canonical_head_root(replacement);
        hook.release();

        let error = derivation
            .await
            .expect("derivation task")
            .expect_err("a late canonical-head change must discard stale candidates");
        assert!(matches!(
            error,
            beacon_chain::PqLocalAttestationContextError::HeadChanged {
                expected,
                actual,
            } if expected == head.beacon_block_root && actual == replacement
        ));
        assert!(error.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_validation_is_retryably_busy_during_a_canonical_transition() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let derivation = {
            let chain = Arc::clone(&fixture.chain);
            let identities = Arc::clone(&identities);
            tokio::spawn(async move { chain.pq_local_attestation_context(identities).await })
        };
        wait_for_blocking_hook(&hook, &derivation).await;
        let transition = fixture.chain.testing_only_hold_pq_import_gate().await;
        hook.release();

        let error = tokio::time::timeout(std::time::Duration::from_secs(5), derivation)
            .await
            .expect("late validation remains bounded")
            .expect("derivation task")
            .expect_err("late validation must not sample through a canonical transition");
        assert!(matches!(
            error,
            beacon_chain::PqLocalAttestationContextError::HeadTransitionBusy
        ));
        assert!(error.is_retryable());

        drop(transition);
        fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("transition contention releases activity and admission for retry");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn initial_and_consume_boundaries_are_retryably_busy_without_starting_derivation() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        let transition = fixture.chain.testing_only_hold_pq_import_gate().await;
        let initial_error = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect_err("initial transition contention must be nonwaiting");
        assert!(matches!(
            initial_error,
            beacon_chain::PqLocalAttestationContextError::HeadTransitionBusy
        ));
        assert!(initial_error.is_retryable());
        assert_eq!(
            hook.entered(),
            0,
            "busy ingress must not start blocking work"
        );
        drop(transition);
        hook.release();

        let context = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("initial contention releases activity and admission");
        let transition = fixture.chain.testing_only_hold_pq_import_gate().await;
        let consume_error = fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect_err("consume transition contention must be nonwaiting");
        assert!(matches!(
            consume_error,
            beacon_chain::PqLocalAttestationContextError::HeadTransitionBusy
        ));
        assert!(consume_error.is_retryable());
        drop(transition);

        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("consume contention releases activity and admission");
        fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect("consume retry after canonical transition");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn candidates_seal_the_canonical_committee_bounds_and_subnet() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("current-slot candidates");
        let context = fixture
            .chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent committee context");

        for candidate in context.candidates() {
            assert!(candidate.committee_index() < candidate.committee_count_at_slot());
            assert!(candidate.committee_position() < candidate.committee_length());
            let expected = types::SubnetId::compute_subnet::<MinimalEthSpec>(
                context.slot(),
                candidate.committee_index(),
                candidate.committee_count_at_slot(),
                &fixture.chain.spec,
            )
            .expect("bounded canonical subnet");
            assert_eq!(candidate.subnet(), expected);
            assert!(u64::from(candidate.subnet()) < fixture.chain.spec.attestation_subnet_count);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_contexts_are_bounded_at_two_and_release_for_retry() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        let first = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("first retained context");
        let second = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("second retained context");
        let capacity = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect_err("cap+1 retained context");
        assert!(matches!(
            capacity,
            beacon_chain::PqLocalAttestationContextError::IngressCapacity
        ));
        assert!(capacity.is_retryable());

        drop(first);
        let retry = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("released permit admits exact retry");
        let second = fixture
            .chain
            .consume_pq_local_attestation_context(second)
            .expect("coherent second context");
        let retry = fixture
            .chain
            .consume_pq_local_attestation_context(retry)
            .expect("coherent retry context");
        assert_eq!(retry.candidates().len(), second.candidates().len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn returned_context_retains_shutdown_activity_until_drop() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let context = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("retained local context");
        let drain = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        let drain_was_pending = !drain.is_finished();
        drop(context);
        tokio::time::timeout(std::time::Duration::from_secs(5), drain)
            .await
            .expect("context drop releases shutdown drain")
            .expect("drain task");
        assert!(
            drain_was_pending,
            "returned context must retain its admitted shutdown activity",
        );
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(Arc::from([]))
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::ShuttingDown)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn consume_boundary_revalidates_clock_head_and_reconciliation() {
        let fixture = fresh_fixture().await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();

        let unchanged = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("unchanged context");
        let ready = fixture
            .chain
            .consume_pq_local_attestation_context(unchanged)
            .expect("coherent consume-time snapshot");
        assert_eq!(ready.slot(), Slot::new(0));
        assert_eq!(ready.bound_head_root(), head.beacon_block_root);
        assert_eq!(ready.candidates().len(), 2);
        assert_eq!(
            fixture
                .chain
                .testing_only_pq_import_gate_available_permits(),
            1,
            "consume-time canonical gate must be released before candidates are exposed",
        );
        drop(ready);

        let stale_clock = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("context before clock mutation");
        fixture.chain.slot_clock.set_slot(1);
        assert!(matches!(
            fixture
                .chain
                .consume_pq_local_attestation_context(stale_clock),
            Err(beacon_chain::PqLocalAttestationContextError::ClockChanged {
                before,
                after,
            }) if before == Slot::new(0) && after == Slot::new(1)
        ));
        fixture.chain.slot_clock.set_slot(0);

        let stale_head = fixture
            .chain
            .pq_local_attestation_context(Arc::clone(&identities))
            .await
            .expect("context before head mutation");
        let replacement = Hash256::repeat_byte(0xa5);
        fixture
            .chain
            .testing_only_replace_pq_canonical_head_root(replacement);
        assert!(matches!(
            fixture
                .chain
                .consume_pq_local_attestation_context(stale_head),
            Err(beacon_chain::PqLocalAttestationContextError::HeadChanged {
                expected,
                actual,
            }) if expected == head.beacon_block_root && actual == replacement
        ));
        fixture
            .chain
            .testing_only_replace_pq_canonical_head_root(head.beacon_block_root);

        let stale_reconciliation = fixture
            .chain
            .pq_local_attestation_context(identities)
            .await
            .expect("context before reconciliation mutation");
        fixture
            .chain
            .testing_only_set_pq_execution_reconciliation_failed(head.beacon_block_root);
        assert!(matches!(
            fixture
                .chain
                .consume_pq_local_attestation_context(stale_reconciliation),
            Err(beacon_chain::PqLocalAttestationContextError::HeadReconciliationFailed {
                block_root,
            }) if block_root == head.beacon_block_root
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn caller_cancellation_keeps_derivation_owned_until_chain_drain() {
        let hook = TestingPqBlockingHook::blocking();
        let fixture =
            fresh_fixture_with_options(electra_spec(), true, Some(Arc::clone(&hook))).await;
        let head = fixture.chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let derivation = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.pq_local_attestation_context(identities).await })
        };
        wait_for_blocking_hook(&hook, &derivation).await;
        let heartbeat = tokio::spawn(async {
            for _ in 0..64 {
                tokio::task::yield_now().await;
            }
        });
        heartbeat
            .await
            .expect("async heartbeat while context is blocked");

        derivation.abort();
        let drain = {
            let chain = Arc::clone(&fixture.chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        let drain_was_pending = !drain.is_finished();
        hook.release();
        tokio::time::timeout(std::time::Duration::from_secs(5), drain)
            .await
            .expect("drain after derivation release")
            .expect("drain task");
        assert!(
            drain_was_pending,
            "chain shutdown must retain a canceled caller's blocking derivation",
        );

        let closed_identities: Arc<[PqLocalAttesterIdentity]> = Arc::from([]);
        assert!(matches!(
            fixture
                .chain
                .pq_local_attestation_context(closed_identities)
                .await,
            Err(beacon_chain::PqLocalAttestationContextError::ShuttingDown)
        ));
    }
}

#[cfg(not(target_feature = "avx2"))]
#[test]
fn local_attester_context_requires_avx2_backend() {
    assert_eq!(
        <types::MinimalEthSpec as types::EthSpec>::slots_per_epoch(),
        8,
    );
}
