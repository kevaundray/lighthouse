use std::marker::PhantomData;
use types::EthSpec;

/// Ephemeral ownership root until verified PQ attestation pools are connected in Task 5.2b.
#[derive(Debug)]
pub struct OperationPool<E: EthSpec> {
    marker: PhantomData<E>,
}

impl<E: EthSpec> Default for OperationPool<E> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<E: EthSpec> OperationPool<E> {
    pub fn new() -> Self {
        Self::default()
    }
}
