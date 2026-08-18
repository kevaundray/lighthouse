use consensus_signature::{OneTimeUseId, SigningDuty, pq::PqSigningClaim};
use pq_signing::{
    PqKeyUnlock, PqKeystore, PqSigningAuthority, PqSigningError, provision_usage_journal,
    validate_usage_journal,
};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"correct horse battery staple";

#[test]
fn encrypted_key_provisions_opens_and_signs() {
    let temporary_directory = TempDir::new().expect("temporary directory");
    let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
    let keystore = PqKeystore::from_seed([7; 32], 0..=7, PASSWORD).expect("keystore");
    let restart_keystore = keystore.clone();
    let metadata = keystore.authenticate(PASSWORD).expect("authentication");
    provision_usage_journal(&journal_path, [3; 32], std::slice::from_ref(&metadata))
        .expect("provision");
    validate_usage_journal(&journal_path, [3; 32], &[metadata]).expect("validate");

    let authority = PqSigningAuthority::open(
        &journal_path,
        [3; 32],
        vec![PqKeyUnlock::new(keystore, PASSWORD).expect("unlock")],
    )
    .expect("authority");
    let signer = authority
        .signer(&authority.public_keys()[0])
        .expect("bound signer");
    let one_time_use_id =
        OneTimeUseId::for_lean_pq_devnet_v1(0, SigningDuty::Attestation).expect("signing ID");
    let claim = PqSigningClaim::new([9; 32], one_time_use_id);
    let signature = signer.sign(claim).expect("signature");
    consensus_signature::pq::verify_raw(&signature, &authority.public_keys()[0], &claim)
        .expect("valid raw signature");

    let retry = signer.sign(claim).expect("same-root retry");
    assert_eq!(retry.as_bytes(), signature.as_bytes());

    let conflicting_claim = PqSigningClaim::new([10; 32], one_time_use_id);
    assert!(matches!(
        signer.sign(conflicting_claim),
        Err(PqSigningError::Journal(_))
    ));
    let out_of_range = OneTimeUseId::for_lean_pq_devnet_v1(1, SigningDuty::RandaoReveal)
        .expect("out-of-range signing ID");
    assert!(matches!(
        signer.sign(PqSigningClaim::new([11; 32], out_of_range)),
        Err(PqSigningError::InvalidSigningRequest)
    ));

    let locked_attempt = PqSigningAuthority::open(
        &journal_path,
        [3; 32],
        vec![PqKeyUnlock::new(restart_keystore.clone(), b"wrong password").expect("unlock")],
    );
    assert!(matches!(locked_attempt, Err(PqSigningError::Journal(_))));

    let duplicate_attempt = PqSigningAuthority::open(
        &journal_path,
        [3; 32],
        vec![
            PqKeyUnlock::new(restart_keystore.clone(), b"wrong password").expect("unlock"),
            PqKeyUnlock::new(restart_keystore.clone(), b"wrong password").expect("unlock"),
        ],
    );
    assert!(matches!(
        duplicate_attempt,
        Err(PqSigningError::DuplicatePublicKey)
    ));

    drop(signer);
    drop(authority);

    let wrong_root_attempt = PqSigningAuthority::open(
        &journal_path,
        [4; 32],
        vec![PqKeyUnlock::new(restart_keystore.clone(), b"wrong password").expect("unlock")],
    );
    assert!(matches!(
        wrong_root_attempt,
        Err(PqSigningError::Journal(_))
    ));

    let restarted = PqSigningAuthority::open(
        &journal_path,
        [3; 32],
        vec![PqKeyUnlock::new(restart_keystore.clone(), PASSWORD).expect("unlock")],
    )
    .expect("restart authority");
    let restarted_signer = restarted
        .signer(&restarted.public_keys()[0])
        .expect("restart signer");
    let restarted_signature = restarted_signer.sign(claim).expect("restart retry");
    assert_eq!(restarted_signature.as_bytes(), signature.as_bytes());

    let missing_attempt = PqSigningAuthority::open(
        &temporary_directory.path().join("missing.sqlite"),
        [3; 32],
        vec![PqKeyUnlock::new(restart_keystore, b"wrong password").expect("unlock")],
    );
    assert!(matches!(missing_attempt, Err(PqSigningError::Journal(_))));
}
