#[cfg(target_feature = "avx2")]
mod avx2 {
    use beacon_chain::{
        BeaconChain, PqLocalAttesterIdentity, PqNewPayloadTransport,
        builder::{BeaconChainBuilder, Witness},
    };
    use consensus_signature::{
        AggregationService, OneTimeUseId, PqPublicKey, PqRawSignature, SameMessageEvidence,
        SigningDuty,
    };
    use futures::StreamExt;
    use network::{PqGossipAttestationDisposition, PqNetworkBlockProcessor};
    use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
    use slot_clock::SlotClock;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use store::{HotColdDB, MemoryStore, StoreConfig};
    use types::{
        Attestation, AttestationData, BeaconBlock, ChainSpec, Checkpoint, Domain, EthSpec,
        ExecutionPayloadRef, ForkName, Hash256, MinimalEthSpec, RelativeEpoch, SignedBeaconBlock,
        SignedRoot, SingleAttestation, Slot, SubnetId,
    };

    const PASSWORD: &[u8] = b"correct horse battery staple";
    type TestWitness =
        Witness<slot_clock::TestingSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>;

    struct BlockingForkchoiceTransport {
        new_payload_calls: AtomicUsize,
        forkchoice_calls: AtomicUsize,
        forkchoice_release: tokio::sync::Semaphore,
    }

    impl BlockingForkchoiceTransport {
        fn new() -> Self {
            Self {
                new_payload_calls: AtomicUsize::new(0),
                forkchoice_calls: AtomicUsize::new(0),
                forkchoice_release: tokio::sync::Semaphore::new(0),
            }
        }
    }

    impl PqNewPayloadTransport<MinimalEthSpec> for BlockingForkchoiceTransport {
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
            self.new_payload_calls.fetch_add(1, Ordering::SeqCst);
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
            self.forkchoice_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let permit = self.forkchoice_release.acquire().await.map_err(|_| {
                    execution_layer::Error::Unexpected("fixture FCU release closed".to_owned())
                })?;
                permit.forget();
                Ok(execution_layer::PayloadStatus::Valid)
            })
        }
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

    async fn wait_for_test_condition(mut condition: impl FnMut() -> bool, description: &str) {
        for _ in 0..100_000 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for {description}");
    }

    struct FreshSlotOneFixture {
        executor_exit_sender: async_channel::Sender<()>,
        shutdown_receiver: futures::channel::mpsc::Receiver<task_executor::ShutdownReason>,
        _temporary_directory: tempfile::TempDir,
        chain: Arc<BeaconChain<TestWitness>>,
        processor: Arc<PqNetworkBlockProcessor<TestWitness>>,
        signed: Arc<SignedBeaconBlock<MinimalEthSpec>>,
        block_root: Hash256,
        genesis_root: Hash256,
        post_state: types::BeaconState<MinimalEthSpec>,
        attester_index: u64,
        authority: PqSigningAuthority,
        spec: Arc<ChainSpec>,
        transport: Arc<BlockingForkchoiceTransport>,
    }

    async fn fresh_slot_one_fixture() -> FreshSlotOneFixture {
        let (executor_exit_sender, executor_exit) = async_channel::bounded(1);
        let (shutdown_sender, shutdown_receiver) = futures::channel::mpsc::channel(1);
        let task_executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            executor_exit,
            shutdown_sender,
        );
        let temporary_directory = tempfile::TempDir::new().expect("temporary directory");
        let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
        let spec = Arc::new(electra_spec());
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
        let proposer_index = genesis
            .get_beacon_proposer_index(Slot::new(1), &spec)
            .expect("slot-one proposer");
        let attester_index = *genesis
            .get_beacon_committee(Slot::new(1), 0)
            .expect("slot-one committee")
            .committee
            .iter()
            .find(|validator_index| **validator_index != proposer_index)
            .expect("slot-one attester distinct from proposer");
        let maximum_leaf = [SigningDuty::BeaconBlockProposal, SigningDuty::Attestation]
            .into_iter()
            .map(|duty| {
                OneTimeUseId::for_lean_pq_devnet_v1(1, duty)
                    .expect("slot-one V1 leaf")
                    .as_u32()
            })
            .max()
            .expect("nonempty duty set");
        let proposer_keystore = PqKeystore::from_seed([0xa5; 32], 0..=maximum_leaf, PASSWORD)
            .expect("fixture keystore");
        let proposer_authenticated = proposer_keystore
            .authenticate(PASSWORD)
            .expect("authenticated proposer key");
        let attester_keystore = PqKeystore::from_seed([0xb5; 32], 0..=maximum_leaf, PASSWORD)
            .expect("attester fixture keystore");
        let attester_authenticated = attester_keystore
            .authenticate(PASSWORD)
            .expect("authenticated attester key");
        genesis
            .validators_mut()
            .get_mut(proposer_index)
            .expect("proposer validator")
            .pubkey = *proposer_authenticated.public_key();
        genesis
            .validators_mut()
            .get_mut(attester_index)
            .expect("attester validator")
            .pubkey = *attester_authenticated.public_key();
        let genesis_validators_root = genesis.genesis_validators_root().0;
        provision_usage_journal(
            &journal_path,
            genesis_validators_root,
            &[proposer_authenticated, attester_authenticated],
        )
        .expect("usage journal");
        let authority = PqSigningAuthority::open(
            &journal_path,
            genesis_validators_root,
            vec![
                PqKeyUnlock::new(proposer_keystore, PASSWORD).expect("proposer unlock"),
                PqKeyUnlock::new(attester_keystore, PASSWORD).expect("attester unlock"),
            ],
        )
        .expect("signing authority");
        let service = Arc::new(AggregationService::new().expect("PQ aggregation service"));
        let transport = Arc::new(BlockingForkchoiceTransport::new());
        let chain = Arc::new(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(Arc::clone(&spec)))
                .custom_spec(Arc::clone(&spec))
                .genesis_state(genesis.clone())
                .expect("persist genesis")
                .pq_aggregation_service(Arc::clone(&service))
                .task_executor(task_executor)
                .testing_only_pq_execution_notifier(transport.clone())
                .build()
                .expect("PQ chain"),
        );
        let genesis_root = chain.head_snapshot().beacon_block_root;
        let mut pre_state = genesis;
        state_processing::per_slot_processing_pq(&mut pre_state, &spec)
            .expect("advance exact parent state");
        let sign = |duty: SigningDuty, signing_root: [u8; 32]| {
            let public_key = pre_state
                .validators()
                .get(proposer_index)
                .expect("proposer validator")
                .pubkey;
            authority
                .signer(&public_key)
                .expect("bound signer")
                .sign(consensus_signature::pq::PqSigningClaim::new(
                    signing_root,
                    OneTimeUseId::for_lean_pq_devnet_v1(1, duty).expect("V1 leaf"),
                ))
                .expect("journal-backed signature")
        };
        let randao_domain = spec.get_domain(
            pre_state.current_epoch(),
            Domain::Randao,
            &pre_state.fork(),
            pre_state.genesis_validators_root(),
        );
        let randao_signature = sign(
            SigningDuty::RandaoReveal,
            pre_state.current_epoch().signing_root(randao_domain).0,
        );
        let verified_randao = state_processing::prepare_pq_randao(
            &pre_state,
            Arc::clone(&chain.pq_validator_key_cache),
            Slot::new(1),
            randao_signature.clone(),
            Arc::clone(&spec),
        )
        .expect("prepared RANDAO")
        .verify(&service)
        .await
        .expect("verified RANDAO");

        let mut block: BeaconBlock<MinimalEthSpec> = BeaconBlock::empty(&spec);
        let BeaconBlock::Electra(inner) = &mut block else {
            panic!("Electra fixture")
        };
        inner.slot = Slot::new(1);
        inner.proposer_index = proposer_index as u64;
        inner.parent_root = genesis_root;
        inner.body.randao_reveal = randao_signature;
        inner.body.execution_payload.execution_payload.timestamp = pre_state
            .genesis_time()
            .checked_add(spec.get_slot_duration().as_secs())
            .expect("slot-one timestamp");
        inner.body.execution_payload.execution_payload.prev_randao = *pre_state
            .get_randao_mix(pre_state.current_epoch())
            .expect("current RANDAO mix");
        let execution_block_hash = execution_layer::calculate_execution_block_hash(
            ExecutionPayloadRef::Electra(&inner.body.execution_payload.execution_payload),
            Some(inner.parent_root),
            Some(&inner.body.execution_requests),
        )
        .0;
        inner.body.execution_payload.execution_payload.block_hash = execution_block_hash;
        let local =
            state_processing::prepare_pq_local_block(&pre_state, block, verified_randao, vec![])
                .expect("sealed local block");
        let mut post_state = pre_state.clone();
        let local_output = state_processing::per_block_processing_pq_local(&mut post_state, local)
            .expect("local transition");
        let (mut block, _) = local_output.into_parts();
        *block.state_root_mut() = post_state.canonical_root().expect("post-state root");
        let proposal_domain = spec.get_domain(
            pre_state.current_epoch(),
            Domain::BeaconProposer,
            &pre_state.fork(),
            pre_state.genesis_validators_root(),
        );
        let proposal_signature = sign(
            SigningDuty::BeaconBlockProposal,
            block.signing_root(proposal_domain).0,
        );
        let signed = Arc::new(SignedBeaconBlock::from_block(block, proposal_signature));
        let block_root = signed.canonical_root();
        let processor = Arc::new(PqNetworkBlockProcessor::new(Arc::clone(&chain)));
        FreshSlotOneFixture {
            executor_exit_sender,
            shutdown_receiver,
            _temporary_directory: temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            genesis_root,
            post_state,
            attester_index: attester_index as u64,
            authority,
            spec,
            transport,
        }
    }

    fn slot_one_single_attestation(fixture: &FreshSlotOneFixture) -> (SingleAttestation, SubnetId) {
        let data = AttestationData {
            slot: Slot::new(1),
            index: 0,
            beacon_block_root: fixture.block_root,
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: types::Epoch::new(0),
                root: fixture.genesis_root,
            },
        };
        let domain = fixture.spec.get_domain(
            types::Epoch::new(0),
            Domain::BeaconAttester,
            &fixture.post_state.fork(),
            fixture.post_state.genesis_validators_root(),
        );
        let attester_public_key = fixture
            .post_state
            .validators()
            .get(fixture.attester_index as usize)
            .expect("attester validator")
            .pubkey;
        let signature = fixture
            .authority
            .signer(&attester_public_key)
            .expect("bound attester signer")
            .sign(consensus_signature::pq::PqSigningClaim::new(
                data.signing_root(domain).0,
                OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::Attestation)
                    .expect("slot-one attestation leaf"),
            ))
            .expect("attestation signature");
        let single = SingleAttestation {
            committee_index: 0,
            attester_index: fixture.attester_index,
            data,
            signature: (&signature).into(),
        };
        let subnet = SubnetId::compute_subnet_for_single_attestation::<MinimalEthSpec>(
            &single,
            fixture
                .post_state
                .get_committee_count_at_slot(Slot::new(1))
                .expect("slot-one committee count"),
            &fixture.spec,
        )
        .expect("slot-one subnet");
        (single, subnet)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_prepare_uses_the_same_snapshot_as_its_bound_head() {
        let fixture = fresh_slot_one_fixture().await;
        let (mut remote_single, subnet) = slot_one_single_attestation(&fixture);
        remote_single.signature = SameMessageEvidence::empty();
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            transport,
            ..
        } = fixture;
        let _executor_exit_sender = executor_exit_sender;
        chain.slot_clock.set_slot(1);
        let snapshot_hook = beacon_chain::TestingPqBlockingHook::blocking();
        chain
            .testing_only_set_pq_remote_attestation_snapshot_hook(Some(Arc::clone(&snapshot_hook)));
        let remote = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move {
                chain
                    .verify_pq_single_attestation_for_gossip(remote_single, subnet)
                    .await
            })
        };
        wait_for_test_condition(
            || snapshot_hook.entered() == 1,
            "remote bound-head snapshot captured",
        )
        .await;
        transport.forkchoice_release.add_permits(1);
        processor
            .import_rpc_block(Arc::clone(&signed))
            .await
            .expect("advance canonical head while remote prepare is parked");
        snapshot_hook.release();
        let error = match remote.await.expect("remote verifier task") {
            Ok(_) => panic!("snapshot-A remote verification prepared against snapshot B"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            beacon_chain::PqAttestationGossipError::Local(
                beacon_chain::PqAttestationGossipLocalError::ReferencedBlockUnavailable(root)
            ) if root == block_root
        ));
        chain.testing_only_set_pq_remote_attestation_snapshot_hook(None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aborted_local_waiter_retains_activity_through_blocked_lineage() {
        let fixture = fresh_slot_one_fixture().await;
        let (signed_single, _) = slot_one_single_attestation(&fixture);
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            attester_index,
            spec,
            transport,
            ..
        } = fixture;
        let _executor_exit_sender = executor_exit_sender;
        chain.slot_clock.set_slot(1);
        transport.forkchoice_release.add_permits(1);
        processor
            .import_rpc_block(signed)
            .await
            .expect("execution-VALID slot-one import");
        let head = chain.head_snapshot();
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
            .collect::<Vec<_>>()
            .into();
        let context = chain
            .pq_local_attestation_context(identities)
            .await
            .expect("slot-one local context");
        let context = chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent slot-one local context");
        let candidate = context
            .into_candidates()
            .into_iter()
            .find(|candidate| candidate.validator_index() == attester_index)
            .expect("signed validator exact candidate");
        let mut signed_attestation = candidate.attestation().clone();
        let raw_signature = PqRawSignature::from_bytes(signed_single.signature.as_bytes())
            .expect("authentic individual signature envelope");
        signed_attestation
            .attach_individual_signature(&raw_signature, candidate.committee_position())
            .expect("attach authentic signature");
        let provenance = candidate
            .into_local_single(attester_index, signed_attestation, &spec)
            .expect("exact local provenance");
        let lineage_hook = beacon_chain::TestingPqBlockingHook::blocking();
        chain.testing_only_set_pq_attestation_lineage_hook(Some(Arc::clone(&lineage_hook)));
        let verification = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move {
                chain
                    .verify_pq_single_attestation_for_local(provenance)
                    .await
            })
        };
        wait_for_test_condition(
            || lineage_hook.entered() == 1,
            "blocked local late-lineage check",
        )
        .await;
        verification.abort();
        let join_error = match verification.await {
            Ok(_) => panic!("aborted caller-facing lineage waiter completed"),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled());
        let drain = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        let retained_activity = !drain.is_finished();
        lineage_hook.release();
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("drain completes after lineage release")
            .expect("drain task");
        assert!(
            retained_activity,
            "caller abort must not release activity while lineage DB work is still blocked",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_imported_current_slot_seals_exact_local_attester_context() {
        let fixture = fresh_slot_one_fixture().await;
        let (signed_single, signed_subnet) = slot_one_single_attestation(&fixture);
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            genesis_root,
            post_state,
            attester_index,
            spec,
            transport,
            ..
        } = fixture;
        let _executor_exit_sender = executor_exit_sender;
        chain.slot_clock.set_slot(1);
        transport.forkchoice_release.add_permits(1);
        let import = processor
            .import_rpc_block(Arc::clone(&signed))
            .await
            .expect("real slot-one execution-VALID import");
        assert_eq!(import.block_root, block_root);
        assert_ne!(
            block_root, genesis_root,
            "slot-one root must not substitute genesis"
        );
        assert!(chain.testing_only_pq_execution_reconciled(block_root));

        let head = chain.head_snapshot();
        assert_eq!(head.beacon_block_root, block_root);
        assert_eq!(head.beacon_state, post_state);
        let identities: Arc<[PqLocalAttesterIdentity]> = head
            .beacon_state
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| PqLocalAttesterIdentity::new(validator.pubkey, index as u64))
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
                    .expect("cached imported-head attester duty")
                    .filter(|duty| duty.slot == Slot::new(1))
                    .map(|duty| (index, validator.pubkey, duty))
            })
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), 2, "full-16 profile has two slot-one duties");

        let context = chain
            .pq_local_attestation_context(identities)
            .await
            .expect("imported current-slot local context");
        let context = chain
            .consume_pq_local_attestation_context(context)
            .expect("coherent imported current-slot context");
        assert_eq!(context.slot(), Slot::new(1));
        assert_eq!(context.bound_head_root(), block_root);
        assert_ne!(context.bound_head_root(), genesis_root);
        assert_eq!(
            context.dependent_root(),
            head.beacon_state
                .attester_shuffling_decision_root(block_root, RelativeEpoch::Current)
                .expect("imported-head dependent root")
        );
        assert_eq!(context.candidates().len(), expected.len());
        for (candidate, (index, pubkey, duty)) in context.candidates().iter().zip(expected) {
            assert_eq!(candidate.validator_index(), index as u64);
            assert_eq!(candidate.pubkey(), pubkey);
            assert_eq!(candidate.committee_index(), duty.index);
            assert_eq!(candidate.committee_position(), duty.committee_position);
            assert_eq!(candidate.committee_length(), duty.committee_len);
            assert_eq!(candidate.committee_count_at_slot(), duty.committees_at_slot);
            let expected_subnet = SubnetId::compute_subnet::<MinimalEthSpec>(
                Slot::new(1),
                duty.index,
                duty.committees_at_slot,
                &spec,
            )
            .expect("slot-one subnet");
            assert_eq!(candidate.subnet(), expected_subnet);
            let Attestation::Electra(attestation) = candidate.attestation() else {
                panic!("frozen imported PQ context must be Electra")
            };
            assert_eq!(attestation.data.slot, Slot::new(1));
            assert_eq!(attestation.data.index, 0);
            assert_eq!(attestation.data.beacon_block_root, block_root);
            assert_eq!(
                attestation.data.source,
                head.beacon_state.current_justified_checkpoint()
            );
            assert_eq!(
                attestation.data.target,
                Checkpoint {
                    epoch: types::Epoch::new(0),
                    root: genesis_root,
                }
            );
        }

        let mut candidates = context.into_candidates();
        let candidate_position = candidates
            .iter()
            .position(|candidate| candidate.validator_index() == attester_index)
            .expect("signed validator has an exact local candidate");
        let candidate = candidates.remove(candidate_position);
        let mut signed_attestation = candidate.attestation().clone();
        let raw_signature = PqRawSignature::from_bytes(signed_single.signature.as_bytes())
            .expect("authentic individual signature envelope");
        signed_attestation
            .attach_individual_signature(&raw_signature, candidate.committee_position())
            .expect("attach authentic local signature to exact candidate");
        let provenance = candidate
            .into_local_single(attester_index, signed_attestation, &spec)
            .expect("seal exact locally constructed single");
        assert_eq!(provenance.single(), &signed_single);
        assert_eq!(provenance.subnet(), signed_subnet);
        let observations_before = chain.testing_only_pq_attestation_gossip_observation_count();
        assert_eq!(
            observations_before, 0,
            "local verification starts with no remote observation state",
        );
        let verified = chain
            .verify_pq_single_attestation_for_local(provenance)
            .await
            .expect("authentic local single proof");
        assert_eq!(verified.single(), &signed_single);
        assert_eq!(verified.validator_index(), attester_index);
        assert_eq!(verified.subnet(), signed_subnet);
        assert_eq!(verified.bound_head_root(), block_root);
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_observation_count(),
            observations_before,
            "local verification must not claim or finalize remote gossip observations",
        );

        let invalid_candidate = candidates
            .pop()
            .expect("full-16 profile retains another exact local candidate");
        let invalid_index = invalid_candidate.validator_index();
        let mut invalid_attestation = invalid_candidate.attestation().clone();
        invalid_attestation
            .attach_individual_signature(
                &PqRawSignature::empty(),
                invalid_candidate.committee_position(),
            )
            .expect("empty evidence has the exact individual structural shape");
        let invalid_provenance = invalid_candidate
            .into_local_single(invalid_index, invalid_attestation, &spec)
            .expect("structurally sealed invalid local evidence");
        let invalid_error = match chain
            .verify_pq_single_attestation_for_local(invalid_provenance)
            .await
        {
            Ok(_) => panic!("cryptographically invalid local evidence verified"),
            Err(error) => error,
        };
        assert!(matches!(
            invalid_error,
            beacon_chain::PqLocalAttestationVerificationError::Invariant(
                beacon_chain::PqLocalAttestationInvariant::Contextual(
                    beacon_chain::PqAttestationGossipPeerInvalid::InvalidAttestation(
                        state_processing::PqAttestationInvalid::InvalidEvidence
                    )
                )
            )
        ));
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_observation_count(),
            0,
            "invalid local evidence must not enter the remote observation path",
        );
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_available_permits(),
            beacon_chain::PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY - 1,
            "a retained local pre-propagation token must retain proof admission",
        );
        let drain = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !drain.is_finished(),
            "a retained local pre-propagation token must retain chain activity",
        );
        drop(verified);
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("drain completes after local token drop")
            .expect("drain task");
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_available_permits(),
            beacon_chain::PQ_ATTESTATION_GOSSIP_ADMISSION_CAPACITY,
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_fcu_clock_loss_is_terminal_before_import_gate_release() {
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            transport,
            mut shutdown_receiver,
            ..
        } = fresh_slot_one_fixture().await;
        let _executor_exit_sender = executor_exit_sender;
        chain.slot_clock.set_slot(2);
        let import = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };
        wait_for_test_condition(
            || transport.forkchoice_calls.load(Ordering::SeqCst) == 1,
            "blocked execution reconciliation",
        )
        .await;
        assert_eq!(transport.new_payload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.head_snapshot().beacon_block_root, block_root);
        assert!(
            !chain.testing_only_pq_fork_choice_contains_block(block_root),
            "durable publication alone must not insert an unreconciled block"
        );
        assert!(matches!(
            chain.known_pq_publish_observation(&signed),
            Some(beacon_chain::PqKnownPublishObservation::Pending)
        ));
        let duplicate = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !duplicate.is_finished(),
            "exact duplicate must coalesce through post-DB reconciliation"
        );
        chain.testing_only_force_pq_fork_choice_clock_unavailable();
        transport.forkchoice_release.add_permits(1);
        let error = import
            .await
            .expect("import task")
            .expect_err("post-VALID clock loss must fail terminally");
        assert!(matches!(
            error,
            beacon_chain::PqImportError::DurableStateUnknown {
                phase: "pq-fork-choice-on-reconciled-block"
            }
        ));
        assert!(!error.is_retryable());
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), shutdown_receiver.next())
                .await
                .expect("fatal shutdown delivery"),
            Some(task_executor::ShutdownReason::Failure(_))
        ));
        assert!(
            !chain.testing_only_pq_fork_choice_contains_block(block_root),
            "panicked post-VALID insertion must not publish a false fork-choice block"
        );
        assert!(matches!(
            duplicate.await.expect("duplicate task"),
            Err(beacon_chain::PqImportError::TerminalObservation {
                block_root: failed,
            }) if failed == block_root
        ));
        assert!(matches!(
            chain.known_pq_publish_observation(&signed),
            Some(beacon_chain::PqKnownPublishObservation::Terminal)
        ));
        assert!(matches!(
            processor.import_rpc_block(Arc::clone(&signed)).await,
            Err(beacon_chain::PqImportError::Local(
                beacon_chain::PqImportLocalError::Transport(execution_layer::Error::ShuttingDown)
            ))
        ));
        assert_eq!(transport.new_payload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.forkchoice_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_current_slot_single_is_queued_until_checked_next_tick() {
        let fixture = fresh_slot_one_fixture().await;
        let (single, subnet) = slot_one_single_attestation(&fixture);
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            attester_index,
            transport,
            ..
        } = fixture;
        chain.slot_clock.set_slot(1);
        let import = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };
        wait_for_test_condition(
            || transport.forkchoice_calls.load(Ordering::SeqCst) == 1,
            "blocked slot-one execution reconciliation",
        )
        .await;
        assert_eq!(chain.head_snapshot().beacon_block_root, block_root);
        assert!(!chain.testing_only_pq_fork_choice_contains_block(block_root));
        let duplicate_block = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };

        let duplicate_single = single.clone();
        let token = match processor.verify_gossip_attestation(single, subnet).await {
            PqGossipAttestationDisposition::Accept(token) => token,
            PqGossipAttestationDisposition::Reject(error) => {
                panic!("valid single was rejected: {error:?}")
            }
            PqGossipAttestationDisposition::Ignore(error) => {
                panic!("valid single was ignored: {error:?}")
            }
        };
        let verified = (*token)
            .mark_propagated()
            .expect("finalize actual propagation");
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_available_permits(),
            1,
            "propagation must transfer, not release, the original verification admission"
        );
        assert!(matches!(
            processor
                .verify_gossip_attestation(duplicate_single, subnet)
                .await,
            PqGossipAttestationDisposition::Ignore(_)
        ));
        let drain = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !drain.is_finished(),
            "propagated vote must retain shutdown activity"
        );
        let consumption = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.consume_pq_verified_gossip_single(verified).await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !consumption.is_finished(),
            "vote bound to a Pending execution head must coalesce until reconciliation"
        );
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 0);
        chain.slot_clock.set_slot(2);
        consumption.abort();
        assert!(
            consumption
                .await
                .expect_err("caller cancellation")
                .is_cancelled(),
            "only the caller-facing waiter should be cancelled"
        );
        drop(executor_exit_sender);
        let fork_choice_hook = beacon_chain::TestingPqBlockingHook::blocking();
        chain.testing_only_set_pq_fork_choice_block_hook(Arc::clone(&fork_choice_hook));
        transport.forkchoice_release.add_permits(1);
        wait_for_test_condition(
            || fork_choice_hook.entered() == 1,
            "blocked post-VALID fork-choice insertion",
        )
        .await;
        assert!(matches!(
            chain.known_pq_publish_observation(&signed),
            Some(beacon_chain::PqKnownPublishObservation::Pending)
        ));
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 0);
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !duplicate_block.is_finished(),
            "exact duplicate must remain pending until fork-choice insertion"
        );
        fork_choice_hook.release();
        import.await.expect("import task").expect("slot-one import");
        duplicate_block
            .await
            .expect("duplicate task")
            .expect("duplicate after fork-choice insertion");
        assert_eq!(transport.new_payload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.forkchoice_calls.load(Ordering::SeqCst), 1);
        wait_for_test_condition(
            || chain.testing_only_pq_fork_choice_attestation_calls() == 1,
            "cancel-safe chain-owned attestation continuation",
        )
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("drain completes after vote consumption")
            .expect("drain task");
        assert_eq!(
            chain.testing_only_pq_fork_choice_queued_attestation_count(),
            0
        );
        assert_eq!(
            chain.testing_only_pq_fork_choice_latest_message(attester_index),
            Some((Slot::new(1), block_root))
        );
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 1);
        assert_eq!(
            chain.testing_only_pq_single_consumption_result(types::Epoch::new(0), attester_index,),
            Some(beacon_chain::PqSingleConsumptionResult::Applied)
        );
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 1);
        assert_eq!(
            chain.testing_only_pq_fork_choice_latest_message(attester_index),
            Some((Slot::new(1), block_root))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_bound_head_reconciliation_finalizes_vote_terminally() {
        let fixture = fresh_slot_one_fixture().await;
        let (single, subnet) = slot_one_single_attestation(&fixture);
        let duplicate = single.clone();
        let FreshSlotOneFixture {
            executor_exit_sender,
            _temporary_directory,
            chain,
            processor,
            signed,
            block_root,
            attester_index,
            transport,
            mut shutdown_receiver,
            ..
        } = fixture;
        let _executor_exit_sender = executor_exit_sender;
        chain.slot_clock.set_slot(1);
        let import = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };
        wait_for_test_condition(
            || transport.forkchoice_calls.load(Ordering::SeqCst) == 1,
            "blocked slot-one reconciliation for terminal vote",
        )
        .await;
        let token = match processor.verify_gossip_attestation(single, subnet).await {
            PqGossipAttestationDisposition::Accept(token) => token,
            PqGossipAttestationDisposition::Reject(error) => {
                panic!("valid single was rejected: {error:?}")
            }
            PqGossipAttestationDisposition::Ignore(error) => {
                panic!("valid single was ignored: {error:?}")
            }
        };
        let verified = (*token).mark_propagated().expect("propagated single");
        let consumption = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.consume_pq_verified_gossip_single(verified).await })
        };
        let fork_choice_hook = beacon_chain::TestingPqBlockingHook::blocking_panicking();
        chain.testing_only_set_pq_fork_choice_block_hook(Arc::clone(&fork_choice_hook));
        transport.forkchoice_release.add_permits(1);
        wait_for_test_condition(
            || fork_choice_hook.entered() == 1,
            "blocked panicking post-VALID fork-choice insertion",
        )
        .await;
        assert!(matches!(
            chain.known_pq_publish_observation(&signed),
            Some(beacon_chain::PqKnownPublishObservation::Pending)
        ));
        assert!(!consumption.is_finished());
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 0);
        let duplicate_block = {
            let processor = Arc::clone(&processor);
            let signed = Arc::clone(&signed);
            tokio::spawn(async move { processor.import_rpc_block(signed).await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(!duplicate_block.is_finished());
        fork_choice_hook.release();
        let import_error = import
            .await
            .expect("import task")
            .expect_err("post-VALID fork-choice panic");
        assert!(matches!(
            import_error,
            beacon_chain::PqImportError::DurableStateUnknown {
                phase: "pq-fork-choice-on-reconciled-block"
            }
        ));
        assert!(matches!(
            consumption.await.expect("consumption task"),
            Err(beacon_chain::PqForkChoiceAttestationError::ReconciliationFailed {
                block_root: failed,
            }) if failed == block_root
        ));
        assert!(matches!(
            duplicate_block.await.expect("duplicate task"),
            Err(beacon_chain::PqImportError::TerminalObservation {
                block_root: failed,
            }) if failed == block_root
        ));
        assert!(matches!(
            chain.known_pq_publish_observation(&signed),
            Some(beacon_chain::PqKnownPublishObservation::Terminal)
        ));
        assert_eq!(transport.new_payload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.forkchoice_calls.load(Ordering::SeqCst), 1);
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 0);
        assert_eq!(
            chain.testing_only_pq_single_consumption_result(types::Epoch::new(0), attester_index,),
            Some(beacon_chain::PqSingleConsumptionResult::Terminal)
        );
        assert!(matches!(
            processor.verify_gossip_attestation(duplicate, subnet).await,
            PqGossipAttestationDisposition::Ignore(_)
        ));
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), shutdown_receiver.next())
                .await
                .expect("fatal shutdown delivery"),
            Some(task_executor::ShutdownReason::Failure(_))
        ));
        assert_eq!(chain.testing_only_pq_fork_choice_attestation_calls(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fork_choice_ingress_is_nonwaiting_bounded_and_close_drained() {
        let test_runtime = task_executor::test_utils::TestRuntime::default();
        let spec = Arc::new(electra_spec());
        let genesis = state_processing::initialize_beacon_state_from_validators::<MinimalEthSpec>(
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
        let chain = Arc::new(
            BeaconChainBuilder::<TestWitness>::pq_new(MinimalEthSpec)
                .store(exact_snapshot_store(Arc::clone(&spec)))
                .custom_spec(Arc::clone(&spec))
                .genesis_state(genesis)
                .expect("persist genesis")
                .pq_aggregation_service(Arc::new(
                    AggregationService::new().expect("PQ aggregation service"),
                ))
                .task_executor(test_runtime.task_executor.clone())
                .testing_only_pq_execution_notifier(Arc::new(BlockingForkchoiceTransport::new()))
                .build()
                .expect("fresh PQ chain"),
        );
        assert_eq!(chain.slot_clock.now(), Some(Slot::new(0)));
        chain
            .on_pq_fork_choice_tick(Slot::new(0))
            .await
            .expect("equal tick is an explicit no-op");
        chain.slot_clock.set_slot(9);
        assert!(matches!(
            chain.on_pq_fork_choice_tick(Slot::new(9)).await,
            Err(beacon_chain::PqForkChoiceAttestationError::TickAdvanceTooLarge {
                current,
                requested,
                maximum: 8,
            }) if current == Slot::new(0) && requested == Slot::new(9)
        ));
        chain.slot_clock.set_slot(8);
        chain
            .on_pq_fork_choice_tick(Slot::new(8))
            .await
            .expect("maximum checked V1 tick advance");
        chain.slot_clock.set_slot(7);
        assert!(matches!(
            chain.on_pq_fork_choice_tick(Slot::new(7)).await,
            Err(beacon_chain::PqForkChoiceAttestationError::TickRollback {
                current,
                requested,
            }) if current == Slot::new(8) && requested == Slot::new(7)
        ));
        chain.slot_clock.set_slot(8);
        assert!(matches!(
            chain.on_pq_fork_choice_tick(Slot::new(7)).await,
            Err(beacon_chain::PqForkChoiceAttestationError::TickMismatch {
                clock,
                requested,
            }) if clock == Slot::new(8) && requested == Slot::new(7)
        ));
        let first = chain
            .testing_try_reserve_pq_attestation_gossip_admission()
            .expect("first admission");
        let second = chain
            .testing_try_reserve_pq_attestation_gossip_admission()
            .expect("second admission");
        assert!(matches!(
            chain.testing_only_try_start_pq_fork_choice_ingress(),
            Err(beacon_chain::PqForkChoiceAttestationError::IngressCapacity)
        ));
        assert!(matches!(
            chain.on_pq_fork_choice_tick(Slot::new(8)).await,
            Err(beacon_chain::PqForkChoiceAttestationError::IngressCapacity)
        ));

        drop(first);
        drop(second);
        chain.slot_clock.set_slot(9);
        let tick_hook = beacon_chain::TestingPqBlockingHook::blocking();
        chain.testing_only_set_pq_fork_choice_tick_hook(Arc::clone(&tick_hook));
        let tick = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.on_pq_fork_choice_tick(Slot::new(9)).await })
        };
        wait_for_test_condition(
            || tick_hook.entered() == 1,
            "chain-owned blocking fork-choice tick",
        )
        .await;
        let drain = {
            let chain = Arc::clone(&chain);
            tokio::spawn(async move { chain.close_and_drain_pq_imports().await })
        };
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !drain.is_finished(),
            "close/drain must retain the admitted blocking tick"
        );
        tick.abort();
        assert!(
            tick.await
                .expect_err("tick caller cancellation")
                .is_cancelled()
        );
        tick_hook.release();
        wait_for_test_condition(
            || chain.testing_only_pq_fork_choice_current_slot() == Some(Slot::new(9)),
            "cancel-safe one-slot tick completion",
        )
        .await;
        assert!(matches!(
            chain.testing_only_try_start_pq_fork_choice_ingress(),
            Err(beacon_chain::PqForkChoiceAttestationError::ShuttingDown)
        ));
        chain.slot_clock.set_slot(10);
        assert!(matches!(
            chain.on_pq_fork_choice_tick(Slot::new(10)).await,
            Err(beacon_chain::PqForkChoiceAttestationError::ShuttingDown)
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .expect("drain completes after final activity release")
            .expect("drain task");
        assert_eq!(
            chain.testing_only_pq_attestation_gossip_available_permits(),
            2
        );
    }
}

#[cfg(not(target_feature = "avx2"))]
#[test]
fn requires_avx2_for_real_pq_fork_choice_fixture() {
    eprintln!("skipped: real PQ fork-choice fixture requires AVX2");
}
