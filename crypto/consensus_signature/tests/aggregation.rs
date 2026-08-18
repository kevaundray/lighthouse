#![cfg(not(feature = "pq-wire"))]

use bls::SecretKey;
use consensus_signature::{
    AggregationContribution, AggregationError, AggregationJob, AggregationService,
    AggregationSigner, Hash256, OneTimeUseId, SameMessageClaim, SameMessageEvidence, SigningDuty,
    V1_MAX_AGGREGATION_CONTRIBUTIONS, V1_MAX_AGGREGATION_SIGNERS,
    is_individual_same_message_evidence,
};
use futures::executor::block_on;

fn secret_key(value: u64) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::deserialize(&bytes).expect("non-zero deterministic secret key")
}

fn claim(root: u8) -> SameMessageClaim {
    SameMessageClaim::new(
        [root; 32],
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation)
            .expect("slot zero is supported"),
    )
}

fn signer(index: u64, key: &SecretKey) -> AggregationSigner {
    AggregationSigner {
        validator_index: index,
        public_key: key.public_key().compress(),
    }
}

fn evidence(key: &SecretKey, claim: SameMessageClaim) -> SameMessageEvidence {
    let signature = key.sign(Hash256::from(claim.signing_root));
    SameMessageEvidence::from(&signature)
}

fn contribution(
    signers: Vec<AggregationSigner>,
    evidence: SameMessageEvidence,
) -> AggregationContribution {
    AggregationContribution { signers, evidence }
}

fn aggregate(job: AggregationJob) -> Result<SameMessageEvidence, AggregationError> {
    let service = AggregationService::new().expect("BLS aggregation service is available");
    block_on(service.aggregate(job))
}

#[test]
fn one_contribution_is_verified_and_returned_without_reencoding() {
    let key = secret_key(1);
    let claim = claim(0x42);
    let signer = signer(7, &key);
    let evidence = evidence(&key, claim);
    let expected_bytes = evidence.serialize();

    let result = aggregate(AggregationJob {
        claim,
        expected_signers: vec![signer.clone()],
        contributions: vec![contribution(vec![signer], evidence)],
    })
    .expect("one valid contribution is promoted without proving");

    assert_eq!(result.serialize(), expected_bytes);
}

#[test]
fn bls_individual_same_message_evidence_rejects_only_the_empty_placeholder() {
    let key = secret_key(1);
    let claim = claim(0x42);

    assert!(is_individual_same_message_evidence(&evidence(&key, claim)));
    assert!(!is_individual_same_message_evidence(
        &SameMessageEvidence::empty()
    ));
}

#[test]
fn multiple_contributions_are_aggregated_behind_the_owned_job() {
    let first_key = secret_key(1);
    let second_key = secret_key(2);
    let claim = claim(0x42);
    let first_signer = signer(3, &first_key);
    let second_signer = signer(9, &second_key);

    let result = aggregate(AggregationJob {
        claim,
        expected_signers: vec![first_signer.clone(), second_signer.clone()],
        contributions: vec![
            contribution(vec![first_signer], evidence(&first_key, claim)),
            contribution(vec![second_signer], evidence(&second_key, claim)),
        ],
    })
    .expect("valid contributions aggregate");

    let public_keys = [first_key.public_key(), second_key.public_key()];
    let public_key_refs = public_keys.iter().collect::<Vec<_>>();
    assert!(result.fast_aggregate_verify(Hash256::from(claim.signing_root), &public_key_refs));
}

#[test]
fn raw_and_aggregate_contributions_compose() {
    let keys = [secret_key(1), secret_key(2), secret_key(3)];
    let claim = claim(0x42);
    let signers = keys
        .iter()
        .enumerate()
        .map(|(index, key)| signer(index as u64, key))
        .collect::<Vec<_>>();
    let mut child = evidence(&keys[1], claim);
    child.add_assign_aggregate(&evidence(&keys[2], claim));

    let result = aggregate(AggregationJob {
        claim,
        expected_signers: signers.clone(),
        contributions: vec![
            contribution(vec![signers[0].clone()], evidence(&keys[0], claim)),
            contribution(signers[1..].to_vec(), child),
        ],
    })
    .expect("raw plus aggregate composes");

    let public_keys = keys.iter().map(SecretKey::public_key).collect::<Vec<_>>();
    let public_key_refs = public_keys.iter().collect::<Vec<_>>();
    assert!(result.fast_aggregate_verify(Hash256::from(claim.signing_root), &public_key_refs));
}

#[test]
fn aggregate_and_aggregate_contributions_compose() {
    let keys = [secret_key(1), secret_key(2), secret_key(3), secret_key(4)];
    let claim = claim(0x42);
    let signers = keys
        .iter()
        .enumerate()
        .map(|(index, key)| signer(index as u64, key))
        .collect::<Vec<_>>();
    let mut first = evidence(&keys[0], claim);
    first.add_assign_aggregate(&evidence(&keys[1], claim));
    let mut second = evidence(&keys[2], claim);
    second.add_assign_aggregate(&evidence(&keys[3], claim));

    aggregate(AggregationJob {
        claim,
        expected_signers: signers.clone(),
        contributions: vec![
            contribution(signers[..2].to_vec(), first),
            contribution(signers[2..].to_vec(), second),
        ],
    })
    .expect("aggregate plus aggregate composes");
}

#[test]
fn evidence_is_bound_to_the_common_claim_and_exact_declared_signers() {
    let first_key = secret_key(1);
    let second_key = secret_key(2);
    let correct_claim = claim(0x42);
    let wrong_claim = claim(0x43);

    for job in [
        AggregationJob {
            claim: wrong_claim,
            expected_signers: vec![signer(0, &first_key)],
            contributions: vec![contribution(
                vec![signer(0, &first_key)],
                evidence(&first_key, correct_claim),
            )],
        },
        AggregationJob {
            claim: correct_claim,
            expected_signers: vec![signer(0, &second_key)],
            contributions: vec![contribution(
                vec![signer(0, &second_key)],
                evidence(&first_key, correct_claim),
            )],
        },
    ] {
        assert_eq!(aggregate(job), Err(AggregationError::InvalidEvidence));
    }
}

#[test]
fn malformed_job_structure_is_not_peer_blame() {
    let first_key = secret_key(1);
    let second_key = secret_key(2);
    let claim = claim(0x42);
    let first = signer(1, &first_key);
    let second = signer(2, &second_key);
    let first_evidence = evidence(&first_key, claim);
    let second_evidence = evidence(&second_key, claim);

    let jobs = [
        AggregationJob {
            claim,
            expected_signers: vec![],
            contributions: vec![],
        },
        AggregationJob {
            claim,
            expected_signers: vec![second.clone(), first.clone()],
            contributions: vec![contribution(
                vec![second.clone(), first.clone()],
                first_evidence.clone(),
            )],
        },
        AggregationJob {
            claim,
            expected_signers: vec![first.clone(), first.clone()],
            contributions: vec![contribution(vec![first.clone()], first_evidence.clone())],
        },
        AggregationJob {
            claim,
            expected_signers: vec![
                first.clone(),
                AggregationSigner {
                    validator_index: 2,
                    public_key: first.public_key,
                },
            ],
            contributions: vec![contribution(vec![first.clone()], first_evidence.clone())],
        },
        AggregationJob {
            claim,
            expected_signers: vec![first.clone(), second.clone()],
            contributions: vec![
                contribution(vec![first.clone()], first_evidence.clone()),
                contribution(vec![first.clone()], first_evidence.clone()),
            ],
        },
        AggregationJob {
            claim,
            expected_signers: vec![first.clone(), second.clone()],
            contributions: vec![contribution(vec![first.clone()], first_evidence.clone())],
        },
        AggregationJob {
            claim,
            expected_signers: vec![first.clone(), second.clone()],
            contributions: vec![
                contribution(vec![first], first_evidence),
                contribution(vec![], second_evidence),
            ],
        },
    ];

    for job in jobs {
        assert!(matches!(
            aggregate(job),
            Err(AggregationError::InvalidJob(_))
        ));
    }
}

#[test]
fn v1_caps_are_checked_before_backend_work() {
    let key = secret_key(1);
    let claim = claim(0x42);
    let one_signer = signer(0, &key);
    let one_evidence = evidence(&key, claim);

    let too_many_signers = (0..=V1_MAX_AGGREGATION_SIGNERS)
        .map(|index| AggregationSigner {
            validator_index: index as u64,
            public_key: one_signer.public_key,
        })
        .collect();
    assert!(matches!(
        aggregate(AggregationJob {
            claim,
            expected_signers: too_many_signers,
            contributions: vec![contribution(vec![one_signer.clone()], one_evidence.clone())],
        }),
        Err(AggregationError::ResourceExhausted(_))
    ));

    let too_many_contributions = (0..=V1_MAX_AGGREGATION_CONTRIBUTIONS)
        .map(|_| contribution(vec![one_signer.clone()], one_evidence.clone()))
        .collect();
    assert!(matches!(
        aggregate(AggregationJob {
            claim,
            expected_signers: vec![one_signer],
            contributions: too_many_contributions,
        }),
        Err(AggregationError::ResourceExhausted(_))
    ));
}
