#![cfg(feature = "pq-devnet")]

use consensus_signature::{IndividualSignature, PQ_RAW_SIGNATURE_LEN, SameMessageEvidence};
use types::{Attestation, ChainSpec, Checkpoint, Hash256, MinimalEthSpec, Slot};

fn raw_signature(fill: u8) -> IndividualSignature {
    let mut bytes = vec![fill; PQ_RAW_SIGNATURE_LEN];
    bytes[..7].copy_from_slice(b"LHPQ\x01\x01\x00");
    IndividualSignature::from_bytes(&bytes).expect("raw signature")
}

#[test]
fn attaches_one_participant_without_proving_or_combining() {
    let mut spec = ChainSpec::minimal();
    spec.electra_fork_epoch = Some(0u64.into());
    let mut attestation = Attestation::<MinimalEthSpec>::empty_for_signing(
        0,
        4,
        Slot::new(0),
        Hash256::ZERO,
        Checkpoint::default(),
        Checkpoint::default(),
        false,
        &spec,
    )
    .expect("attestation");
    let signature = raw_signature(0x42);

    attestation
        .attach_individual_signature(&signature, 2)
        .expect("attachment");
    assert!(attestation.get_aggregation_bit(2).expect("bit"));
    assert_eq!(attestation.signature().as_bytes(), signature.as_bytes());
    assert_eq!(
        attestation.signature(),
        &SameMessageEvidence::from(&signature)
    );
    assert!(
        attestation
            .attach_individual_signature(&raw_signature(0x43), 2)
            .is_err()
    );
}
