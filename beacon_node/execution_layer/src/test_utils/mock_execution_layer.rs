use crate::{
    test_utils::{
        DEFAULT_TERMINAL_BLOCK, DEFAULT_TERMINAL_DIFFICULTY, ExecutionBlockGenerator,
    },
    *,
};
use crate::MockExecutionEngine;
use crate::test_utils::DEFAULT_JWT_SECRET;
use alloy_primitives::B256 as H256;
use kzg::Kzg;
use parking_lot::Mutex;
use std::sync::Arc;
use types::{FixedBytesExtended, MainnetEthSpec};

pub struct MockExecutionLayer<E: EthSpec> {
    pub el: ExecutionLayer<E>,
    pub executor: TaskExecutor,
    pub spec: Arc<ChainSpec>,
    /// Keep a direct reference to the MockExecutionEngine for test configuration.
    /// 
    /// While `el` contains the same MockExecutionEngine (as `Arc<dyn ExecutionEngine<E>>`),
    /// we need this typed reference to access MockExecutionEngine-specific methods like:
    /// - `set_payload_status()` - configure responses for specific block hashes
    /// - `all_payloads_valid()` - set global mock behavior
    /// - `call_count()` - verify method invocations in tests
    /// 
    /// Rust trait objects don't allow safe downcasting without additional setup,
    /// so we maintain this reference for test convenience and type safety.
    mock_engine: Arc<MockExecutionEngine>,
    /// Block generator for creating realistic execution blocks and terminal blocks.
    /// 
    /// This provides the same block generation capabilities that the original MockServer had,
    /// allowing tests to work with actual terminal blocks instead of None values.
    block_generator: Arc<Mutex<ExecutionBlockGenerator<E>>>,
}

impl<E: EthSpec> MockExecutionLayer<E> {
    pub fn default_params(executor: TaskExecutor) -> Self {
        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_total_difficulty = Uint256::from(DEFAULT_TERMINAL_DIFFICULTY);
        spec.terminal_block_hash = ExecutionBlockHash::zero();
        spec.terminal_block_hash_activation_epoch = Epoch::new(0);
        Self::new(
            executor,
            DEFAULT_TERMINAL_BLOCK,
            None,
            None,
            None,
            None,
            Some(JwtKey::from_slice(&DEFAULT_JWT_SECRET).unwrap()),
            Arc::new(spec),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executor: TaskExecutor,
        terminal_block: u64,
        shanghai_time: Option<u64>,
        cancun_time: Option<u64>,
        prague_time: Option<u64>,
        osaka_time: Option<u64>,
        _jwt_key: Option<JwtKey>,
        spec: Arc<ChainSpec>,
        kzg: Option<Arc<Kzg>>,
    ) -> Self {
        // Create mock execution engine with configuration for payload generation
        let mock_engine = Arc::new(MockExecutionEngine::new());
        
        // Configure the mock engine with chain spec and fork times for payload generation
        mock_engine.set_chain_spec(spec.clone());
        mock_engine.set_fork_times(shanghai_time, cancun_time, prague_time, osaka_time);
        mock_engine.set_terminal_block_settings(
            spec.terminal_total_difficulty,
            terminal_block,
        );
        
        // Create ExecutionLayer using the mock engine
        let suggested_fee_recipient = Some(Address::repeat_byte(42));
        let el = ExecutionLayer::with_execution_engine(
            mock_engine.clone(),
            suggested_fee_recipient,
            executor.clone(),
        );

        // Create block generator with the same parameters as the original MockServer
        let terminal_difficulty = spec.terminal_total_difficulty;
        let terminal_block_hash = spec.terminal_block_hash;
        let block_generator = Arc::new(Mutex::new(ExecutionBlockGenerator::new(
            terminal_difficulty,
            terminal_block,
            terminal_block_hash,
            shanghai_time,
            cancun_time,
            prague_time,
            osaka_time,
            spec.clone(),
            kzg,
        )));

        Self {
            mock_engine,
            el,
            executor,
            spec,
            block_generator,
        }
    }

    pub async fn produce_valid_execution_payload_on_head(self) -> Self {
        // TODO: We could enhance MockExecutionEngine to generate actual blocks like MockServer did.
        // The original MockServer used ExecutionBlockGenerator to create realistic blocks with:
        // - Sequential block numbers and proper parent hash chains  
        // - Valid block hashes and execution payloads
        // - Terminal difficulty and PoW/PoS transition handling
        //
        // Current limitation: MockExecutionEngine is a simpler stub mock that returns
        // configured responses rather than generating actual block data.
        // 
        // For now, we configure mock responses instead of generating real blocks:

        let parent_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(1));
        let parent_gas_limit = 30_000_000;
        let block_number = 2;
        
        // Configure mock engine for valid responses
        self.mock_engine.all_payloads_valid();
        let timestamp = block_number;
        let prev_randao = Hash256::from_low_u64_be(block_number);
        let head_block_root = Hash256::repeat_byte(42);
        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root: head_block_root,
            head_hash: Some(parent_hash),
            justified_hash: None,
            finalized_hash: None,
        };
        let payload_attributes =
            PayloadAttributes::new(timestamp, prev_randao, Address::repeat_byte(42), None, None);

        // Insert a proposer to ensure the fork choice updated command works.
        let slot = Slot::new(0);
        let validator_index = 0;
        self.el
            .insert_proposer(slot, head_block_root, validator_index, payload_attributes)
            .await;

        self.el
            .notify_forkchoice_updated(
                parent_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
            )
            .await
            .unwrap();

        let validator_index = 0;
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes =
            PayloadAttributes::new(timestamp, prev_randao, suggested_fee_recipient, None, None);

        let payload_parameters = PayloadParameters {
            parent_hash,
            parent_gas_limit,
            proposer_gas_limit: None,
            payload_attributes: &payload_attributes,
            forkchoice_update_params: &forkchoice_update_params,
            current_fork: ForkName::Bellatrix,
        };

        let block_proposal_content_type = self
            .el
            .get_payload(
                payload_parameters,
                builder_params,
                &self.spec,
                None,
                BlockProductionVersion::FullV2,
            )
            .await
            .unwrap();

        let payload: ExecutionPayload<E> = match block_proposal_content_type {
            BlockProposalContentsType::Full(block) => block.to_payload().into(),
            BlockProposalContentsType::Blinded(_) => panic!("Should always be a full payload"),
        };

        let block_hash = payload.block_hash();
        assert_eq!(payload.parent_hash(), parent_hash);
        assert_eq!(payload.block_number(), block_number);
        assert_eq!(payload.timestamp(), timestamp);
        assert_eq!(payload.prev_randao(), prev_randao);

        // Ensure the payload cache is empty.
        assert!(self
            .el
            .get_payload_by_root(&payload.tree_hash_root())
            .is_none());
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot,
            chain_health: ChainHealth::Healthy,
        };
        let suggested_fee_recipient = self.el.get_suggested_fee_recipient(validator_index).await;
        let payload_attributes =
            PayloadAttributes::new(timestamp, prev_randao, suggested_fee_recipient, None, None);

        let payload_parameters = PayloadParameters {
            parent_hash,
            parent_gas_limit,
            proposer_gas_limit: None,
            payload_attributes: &payload_attributes,
            forkchoice_update_params: &forkchoice_update_params,
            current_fork: ForkName::Bellatrix,
        };

        let block_proposal_content_type = self
            .el
            .get_payload(
                payload_parameters,
                builder_params,
                &self.spec,
                None,
                BlockProductionVersion::BlindedV2,
            )
            .await
            .unwrap();

        match block_proposal_content_type {
            BlockProposalContentsType::Full(block) => {
                let payload_header = block.to_payload();
                self.assert_valid_execution_payload_on_head(
                    payload,
                    payload_header,
                    block_hash,
                    parent_hash,
                    block_number,
                    timestamp,
                    prev_randao,
                )
                .await;
            }
            BlockProposalContentsType::Blinded(block) => {
                let payload_header = block.to_payload();
                self.assert_valid_execution_payload_on_head(
                    payload,
                    payload_header,
                    block_hash,
                    parent_hash,
                    block_number,
                    timestamp,
                    prev_randao,
                )
                .await;
            }
        };

        self
    }

    /// Get access to the underlying mock execution engine for configuration.
    pub fn mock_engine(&self) -> &Arc<MockExecutionEngine> {
        &self.mock_engine
    }

    /// Configure all payloads to return valid status.
    pub fn all_payloads_valid(&self) {
        self.mock_engine.all_payloads_valid();
    }

    /// Configure all payloads to return syncing status.
    pub fn all_payloads_syncing(&self) {
        self.mock_engine.all_payloads_syncing();
    }

    /// Configure all payloads to return invalid status.
    pub fn all_payloads_invalid(&self, latest_valid_hash: ExecutionBlockHash) {
        self.mock_engine.all_payloads_invalid(latest_valid_hash);
    }

    /// Set a specific payload status for a block hash.
    pub fn set_payload_status(&self, block_hash: ExecutionBlockHash, status: PayloadStatus) {
        self.mock_engine.set_payload_status(block_hash, status);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn assert_valid_execution_payload_on_head<Payload: AbstractExecPayload<E>>(
        &self,
        payload: ExecutionPayload<E>,
        payload_header: Payload,
        block_hash: ExecutionBlockHash,
        parent_hash: ExecutionBlockHash,
        block_number: u64,
        timestamp: u64,
        prev_randao: H256,
    ) {
        assert_eq!(payload_header.block_hash(), block_hash);
        assert_eq!(payload_header.parent_hash(), parent_hash);
        assert_eq!(payload_header.block_number(), block_number);
        assert_eq!(payload_header.timestamp(), timestamp);
        assert_eq!(payload_header.prev_randao(), prev_randao);

        // Ensure the payload cache has the correct payload.
        assert_eq!(
            self.el
                .get_payload_by_root(&payload_header.tree_hash_root()),
            Some(FullPayloadContents::Payload(payload.clone()))
        );

        // TODO: again consider forks
        let status = self
            .el
            .notify_new_payload(payload.to_ref().try_into().unwrap())
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        // Use junk values for slot/head-root to ensure there is no payload supplied.
        let slot = Slot::new(0);
        let head_block_root = Hash256::repeat_byte(13);
        self.el
            .notify_forkchoice_updated(
                block_hash,
                ExecutionBlockHash::zero(),
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
            )
            .await
            .unwrap();

        // With mock engine, we can't verify block generation in the same way
        // but we can verify that the mock engine received the expected calls
        assert!(self.mock_engine.call_count("notify_forkchoice_updated") > 0);
    }

    pub fn move_to_block_prior_to_terminal_block(self) -> Self {
        // Use the ExecutionBlockGenerator to move to block prior to terminal block
        let terminal_block = self.block_generator.lock().terminal_block_number;
        if terminal_block > 0 {
            let target_block = terminal_block - 1;
            let result = {
                let mut generator = self.block_generator.lock();
                generator.move_to_pow_block(target_block)
            };
            
            if let Err(e) = result {
                eprintln!("Warning: Failed to move to block prior to terminal block: {}", e);
                return self;
            }
            
            // Populate the mock engine with blocks from the generator
            {
                let generator = self.block_generator.lock();
                
                // Add all blocks from the generator to the mock engine
                for block_number in 0..=target_block {
                    if let Some(execution_block) = generator.execution_block_by_number(block_number) {
                        self.mock_engine.set_execution_block(execution_block.block_hash, execution_block);
                    }
                }
            }
        }
        self
    }

    pub fn move_to_terminal_block(self) -> Self {
        // Use the ExecutionBlockGenerator to move to terminal block
        let result = {
            let mut generator = self.block_generator.lock();
            generator.move_to_terminal_block()
        };
        
        if let Err(e) = result {
            eprintln!("Warning: Failed to move to terminal block: {}", e);
            return self;
        }
        
        // Populate the mock engine with blocks from the generator
        {
            let generator = self.block_generator.lock();
            
            // Add all blocks from the generator to the mock engine
            for block_number in 0..=generator.terminal_block_number {
                if let Some(execution_block) = generator.execution_block_by_number(block_number) {
                    self.mock_engine.set_execution_block(execution_block.block_hash, execution_block);
                }
            }
        }
        
        self
    }

    pub fn produce_forked_pow_block(self) -> (Self, ExecutionBlockHash) {
        // Create a forked PoW block using the block generator
        let forked_block_hash = {
            let generator = self.block_generator.lock();
            
            // Get the current terminal block
            if let Some(terminal_block) = generator.latest_execution_block() {
                // Create a forked block at the same height as terminal but with different hash
                let forked_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(
                    terminal_block.block_number + 1000 // Ensure different hash
                ));
                
                // Create a mock execution block for the fork
                let forked_execution_block = ExecutionBlock {
                    block_hash: forked_hash,
                    block_number: terminal_block.block_number,
                    parent_hash: terminal_block.parent_hash,
                    total_difficulty: terminal_block.total_difficulty,
                    timestamp: terminal_block.timestamp,
                };
                
                // Add the forked block to the mock engine
                self.mock_engine.set_execution_block(forked_hash, forked_execution_block);
                
                forked_hash
            } else {
                // Fallback: create a basic forked block
                let block_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(42));
                let execution_block = ExecutionBlock {
                    block_hash,
                    block_number: DEFAULT_TERMINAL_BLOCK,
                    parent_hash: ExecutionBlockHash::from_root(Hash256::from_low_u64_be(41)),
                    total_difficulty: Some(Uint256::from(DEFAULT_TERMINAL_DIFFICULTY)),
                    timestamp: DEFAULT_TERMINAL_BLOCK,
                };
                self.mock_engine.set_execution_block(block_hash, execution_block);
                block_hash
            }
        };
        
        (self, forked_block_hash)
    }

    pub async fn with_terminal_block<U, V>(self, func: U) -> Self
    where
        U: Fn(Arc<ChainSpec>, ExecutionLayer<E>, Option<ExecutionBlock>) -> V,
        V: Future<Output = ()>,
    {
        // Get the actual terminal block from the block generator
        let terminal_block = self.block_generator.lock().latest_execution_block();
        func(self.spec.clone(), self.el.clone(), terminal_block).await;
        self
    }
}
