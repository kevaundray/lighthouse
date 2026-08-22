#![cfg(feature = "pq-beacon-startup-testing")]

use consensus_signature::IndividualSignature;
use ssz::Encode;
use ssz_types::VariableList;
use std::{
    cell::Cell,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use store::{Error, HotColdDB, MemoryStore, StoreConfig, TestingPqStoredBlockValidationHook};
use types::{
    BeaconBlock, BeaconBlockElectra, EmptyBlock, EthSpec, ForkName, FullPayload, Hash256,
    MinimalEthSpec, PqSignedBlockSizeLimits, SignedBeaconBlock,
};

#[test]
fn pq_stored_block_bounds_records_and_recomposed_signed_block() {
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let mut store_config = StoreConfig::default();
    store_config.hierarchy_config.exponents = vec![0];
    store_config.block_cache_size = 0;
    let store = HotColdDB::<MinimalEthSpec, MemoryStore, MemoryStore>::open_ephemeral(
        store_config,
        Arc::clone(&spec),
    )
    .expect("ephemeral PQ store");
    let limits =
        PqSignedBlockSizeLimits::checked::<MinimalEthSpec>(&spec).expect("checked PQ block limits");
    let block = SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    );

    let exact_root = Hash256::repeat_byte(1);
    store
        .testing_only_put_raw_pq_block_bytes(exact_root, vec![0; limits.max_ssz_bytes()])
        .expect("inject exact-cap stored bytes");
    let exact_decoder_called = Cell::new(false);
    let exact = store
        .get_block_with(&exact_root, |_| {
            exact_decoder_called.set(true);
            Ok(block.clone())
        })
        .expect("exact-cap bytes reach the bounded decoder");
    assert!(exact_decoder_called.get());
    assert_eq!(exact, Some(block.clone()));

    let oversized_root = Hash256::repeat_byte(2);
    let oversized = limits.max_ssz_bytes().checked_add(1).expect("cap plus one");
    store
        .testing_only_put_raw_pq_block_bytes(oversized_root, vec![0; oversized])
        .expect("inject oversized stored bytes");
    let oversized_decoder_called = Cell::new(false);
    let error = store
        .get_block_with::<FullPayload<MinimalEthSpec>>(&oversized_root, |_| {
            oversized_decoder_called.set(true);
            panic!("oversized PQ block reached decoder")
        })
        .expect_err("cap-plus-one stored bytes are rejected");
    assert!(!oversized_decoder_called.get());
    assert!(matches!(
        error,
        Error::PqBlockSizeExceeded { actual, max }
            if actual == oversized && max == limits.max_ssz_bytes()
    ));

    let oversized_payload_root = Hash256::repeat_byte(3);
    let (empty_blinded, _) = block.clone().into();
    store
        .testing_only_put_raw_pq_block_bytes(oversized_payload_root, empty_blinded.as_ssz_bytes())
        .expect("inject valid blinded block");
    store
        .testing_only_put_raw_pq_execution_payload_bytes(oversized_payload_root, vec![0; oversized])
        .expect("inject oversized execution payload bytes");
    let error = store
        .get_full_block(&oversized_payload_root)
        .expect_err("cap-plus-one payload bytes are rejected before decoding");
    assert!(matches!(
        error,
        Error::PqBlockSizeExceeded { actual, max }
            if actual == oversized && max == limits.max_ssz_bytes()
    ));
    assert!(matches!(
        store
            .get_execution_payload_dangerous_fork_agnostic(&oversized_payload_root)
            .expect_err("the fork-agnostic payload getter is bounded before decoding"),
        Error::PqBlockSizeExceeded { actual, max }
            if actual == oversized && max == limits.max_ssz_bytes()
    ));
    assert!(
        store
            .execution_payload_exists(&oversized_payload_root)
            .expect("payload existence does not decode corrupt bytes")
    );

    let transaction = VariableList::try_from(vec![0; 1024]).expect("bounded transaction");
    let empty_len = block.ssz_bytes_len();
    let transaction_ssz_bytes = 4usize
        .checked_add(transaction.len())
        .expect("transaction offset and bytes");
    let transaction_count = limits
        .max_ssz_bytes()
        .saturating_sub(empty_len)
        .checked_div(transaction_ssz_bytes)
        .and_then(|count| count.checked_add(1))
        .expect("recomposed cap crossing count");
    let mut oversized_block = BeaconBlockElectra::<MinimalEthSpec>::empty(&spec);
    oversized_block
        .body
        .execution_payload
        .execution_payload
        .transactions = VariableList::try_from(
        std::iter::repeat_n(transaction, transaction_count).collect::<Vec<_>>(),
    )
    .expect("bounded transaction list");
    let oversized_block = SignedBeaconBlock::from_block(
        BeaconBlock::Electra(oversized_block),
        IndividualSignature::empty(),
    );
    let recomposed_actual = oversized_block.ssz_bytes_len();
    assert!(recomposed_actual > limits.max_ssz_bytes());
    let (blinded, payload) = oversized_block.into();
    let payload = payload.expect("Electra block has an execution payload");
    let blinded_bytes = blinded.as_ssz_bytes();
    let payload_bytes = payload.as_ssz_bytes();
    assert!(blinded_bytes.len() <= limits.max_ssz_bytes());
    assert!(payload_bytes.len() <= limits.max_ssz_bytes());

    let recomposed_root = Hash256::repeat_byte(4);
    store
        .testing_only_put_raw_pq_block_bytes(recomposed_root, blinded_bytes)
        .expect("inject individually bounded blinded block");
    store
        .testing_only_put_raw_pq_execution_payload_bytes(recomposed_root, payload_bytes)
        .expect("inject individually bounded execution payload");
    let error = store
        .get_full_block(&recomposed_root)
        .expect_err("oversized recomposed signed block is rejected");
    assert!(matches!(
        error,
        Error::PqBlockSizeExceeded { actual, max }
            if actual == recomposed_actual && max == limits.max_ssz_bytes()
    ));
}

#[test]
fn pq_cache_lock_is_released_before_full_block_validation() {
    let spec = Arc::new(ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec()));
    let mut store_config = StoreConfig::default();
    store_config.hierarchy_config.exponents = vec![0];
    store_config.block_cache_size = 1;
    let store = Arc::new(
        HotColdDB::<MinimalEthSpec, MemoryStore, MemoryStore>::open_ephemeral(
            store_config,
            Arc::clone(&spec),
        )
        .expect("ephemeral PQ store with block cache"),
    );
    let block = SignedBeaconBlock::from_block(
        BeaconBlock::<MinimalEthSpec>::empty(&spec),
        IndividualSignature::empty(),
    );
    let block_root = Hash256::repeat_byte(5);
    store
        .put_block(&block_root, block.clone())
        .expect("cache one validated full block");

    let hook = TestingPqStoredBlockValidationHook::blocking();
    store.testing_only_set_pq_stored_block_validation_hook(Arc::clone(&hook));
    let release_guard = HookReleaseGuard(Arc::clone(&hook));
    let worker_store = Arc::clone(&store);
    let worker = thread::spawn(move || worker_store.get_full_block(&block_root));

    let deadline = Instant::now() + Duration::from_secs(5);
    while hook.entered() == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        hook.entered(),
        1,
        "cache-hit validation hook was not reached"
    );
    assert!(
        store.testing_only_pq_block_cache_lock_available(),
        "PQ block-size validation retained the block-cache mutex"
    );
    drop(release_guard);
    assert_eq!(
        worker
            .join()
            .expect("cache-hit worker did not panic")
            .expect("cache-hit validation succeeds"),
        Some(block)
    );
}

struct HookReleaseGuard(Arc<TestingPqStoredBlockValidationHook>);

impl Drop for HookReleaseGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}
