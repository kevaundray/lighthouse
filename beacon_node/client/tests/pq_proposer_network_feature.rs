#![cfg(feature = "pq-proposer")]

#[test]
fn proposer_client_enables_the_network_local_attestation_publisher() {
    fn assert_sender<E: types::EthSpec>(
        _: Option<network::PqLocalAttestationBatchPublishSender<E>>,
    ) {
    }

    assert_sender::<types::MinimalEthSpec>(None);
}
