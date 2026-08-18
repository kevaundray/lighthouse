use consensus_signature::PqPublicKey;
use ssz::Encode;
use state_processing::{DirectGenesisValidator, initialize_beacon_state_from_validators};
use types::{
    BeaconState, ChainSpec, Epoch, EthSpec, ExecutionPayloadHeader, ForkName, Hash256,
    MinimalEthSpec,
};

fn electra_spec() -> ChainSpec {
    ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec())
}

fn synthetic_validator(byte: u8) -> DirectGenesisValidator {
    let mut withdrawal_credentials = [0; 32];
    withdrawal_credentials[0] = 1;
    withdrawal_credentials[31] = byte;
    DirectGenesisValidator {
        public_key: PqPublicKey::deserialize(&[byte; 32]).expect("fixed-size public key"),
        withdrawal_credentials: Hash256::from(withdrawal_credentials),
    }
}

#[test]
fn direct_registry_genesis_is_electra_active_and_deposit_free() {
    let spec = electra_spec();
    let validators = vec![synthetic_validator(1), synthetic_validator(2)];
    let state = initialize_beacon_state_from_validators::<MinimalEthSpec>(
        Hash256::ZERO,
        0,
        validators.clone(),
        None::<ExecutionPayloadHeader<MinimalEthSpec>>,
        &spec,
    )
    .expect("direct registry genesis");

    assert!(matches!(state, BeaconState::Electra(_)));
    assert_eq!(state.validators().len(), validators.len());
    assert_eq!(state.balances().len(), validators.len());
    assert_eq!(state.eth1_data().deposit_root, Hash256::ZERO);
    assert_eq!(state.eth1_data().deposit_count, 0);
    assert_eq!(state.eth1_deposit_index(), 0);
    assert!(state.pending_deposits().expect("Electra state").is_empty());

    for (validator, expected) in state.validators().iter().zip(validators) {
        assert_eq!(validator.pubkey, expected.public_key);
        assert_eq!(
            validator.withdrawal_credentials,
            expected.withdrawal_credentials
        );
        assert_eq!(validator.activation_epoch, Epoch::new(0));
        assert_eq!(validator.activation_eligibility_epoch, Epoch::new(0));
        assert!(!validator.slashed);
    }

    let sync_committee = state.current_sync_committee().expect("Electra committee");
    assert_eq!(sync_committee.aggregate_pubkey, PqPublicKey::empty());
}

#[test]
fn direct_registry_genesis_is_deterministic() {
    let spec = electra_spec();
    let validators = vec![synthetic_validator(7), synthetic_validator(3)];
    let build = || {
        initialize_beacon_state_from_validators::<MinimalEthSpec>(
            Hash256::ZERO,
            42,
            validators.clone(),
            None,
            &spec,
        )
        .expect("direct registry genesis")
    };

    let first = build();
    let second = build();
    assert_eq!(first.as_ssz_bytes(), second.as_ssz_bytes());
    assert_eq!(
        first
            .validators()
            .iter()
            .map(|validator| validator.pubkey)
            .collect::<Vec<_>>(),
        validators
            .iter()
            .map(|validator| validator.public_key)
            .collect::<Vec<_>>()
    );
}

#[test]
fn direct_registry_genesis_rejects_non_electra_genesis_specs() {
    let validators = vec![synthetic_validator(1)];
    for fork in [ForkName::Base, ForkName::Fulu, ForkName::Gloas] {
        let spec = fork.make_genesis_spec(MinimalEthSpec::default_spec());
        assert!(
            initialize_beacon_state_from_validators::<MinimalEthSpec>(
                Hash256::ZERO,
                0,
                validators.clone(),
                None,
                &spec,
            )
            .is_err(),
            "{fork:?} must not silently produce a PQ genesis"
        );
    }
}
