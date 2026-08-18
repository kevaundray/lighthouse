use eth2_keystore::{
    MAX_PQ_ONE_TIME_USE_IDS, MAX_PQ_PASSWORD_BYTES, PqKeystore, PqKeystoreBuilder, PqKeystoreError,
};
use fs2::FileExt;
use lean_multisig::SecretKey;
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read};
use std::sync::OnceLock;
use std::time::Instant;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"correct horse battery staple";
const PUBLIC_KEY_LEN: usize = 32;
type JsonMutation = (&'static str, &'static dyn Fn(&mut Value));

fn pq_work_lock() -> File {
    let path = std::env::temp_dir().join("lighthouse-pq-crypto-tests.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("open PQ test lock");
    file.lock_exclusive().expect("lock PQ test work");
    file
}

fn valid_keystore() -> PqKeystore {
    static KEYSTORE: OnceLock<PqKeystore> = OnceLock::new();
    KEYSTORE
        .get_or_init(|| {
            let key = SecretKey::from_seed([42; 32], 100..=115).expect("small key");
            PqKeystoreBuilder::new(&key, PASSWORD)
                .expect("builder")
                .build()
                .expect("keystore")
        })
        .clone()
}

fn mutate_json(mutator: impl FnOnce(&mut Value)) -> PqKeystore {
    let mut value = serde_json::to_value(valid_keystore()).expect("serialize");
    mutator(&mut value);
    PqKeystore::from_json_str(&serde_json::to_string(&value).expect("JSON"))
        .expect("outer JSON remains syntactically valid")
}

#[test]
fn encrypted_key_round_trips_with_identity_and_inclusive_range() {
    let _work_lock = pq_work_lock();
    let keystore = valid_keystore();

    assert_eq!(keystore.public_key().len(), PUBLIC_KEY_LEN);
    assert_eq!(keystore.one_time_use_range(), 100..=115);
    keystore
        .validate_password(PASSWORD)
        .expect("decrypt and validate");

    let json = keystore.to_json_string().expect("JSON");
    let restored = PqKeystore::from_json_str(&json).expect("parse");
    assert_eq!(restored, keystore);
    restored.validate_password(PASSWORD).expect("reload");
}

#[test]
fn generated_key_can_be_reloaded() {
    let _work_lock = pq_work_lock();
    let keystore = PqKeystore::generate(200..=207, PASSWORD).expect("generate");
    keystore
        .validate_password(PASSWORD)
        .expect("decrypt and validate");
    assert_eq!(keystore.one_time_use_range(), 200..=207);
}

#[test]
fn wrong_password_is_rejected() {
    let _work_lock = pq_work_lock();
    assert!(matches!(
        valid_keystore().validate_password(b"incorrect"),
        Err(PqKeystoreError::Crypto(_))
    ));
}

#[test]
fn all_outer_security_metadata_is_bound_to_ciphertext() {
    let _work_lock = pq_work_lock();
    let mutations: &[JsonMutation] = &[
        ("format", &|v| v["format"] = json!("other")),
        ("version", &|v| v["version"] = json!(2)),
        ("scheme", &|v| v["scheme"] = json!("other")),
        ("parameter_set", &|v| v["parameter_set"] = json!("other")),
        ("bindings_revision", &|v| {
            v["bindings_revision"] = json!("other")
        }),
        ("backend_revision", &|v| {
            v["backend_revision"] = json!("other")
        }),
        ("public_key", &|v| v["public_key"] = json!("00".repeat(32))),
        ("range start", &|v| {
            v["one_time_use_range"]["start"] = json!(99)
        }),
        ("range end", &|v| {
            v["one_time_use_range"]["end"] = json!(116)
        }),
    ];

    for (name, mutate) in mutations {
        let tampered = mutate_json(mutate);
        assert!(
            tampered.validate_password(PASSWORD).is_err(),
            "outer {name} tampering must be detected"
        );
    }
}

#[test]
fn unsupported_outer_versions_are_rejected_before_key_use() {
    let _work_lock = pq_work_lock();
    for (field, value) in [
        ("format", json!("unknown-format")),
        ("version", json!(99)),
        ("scheme", json!("unknown-scheme")),
        ("parameter_set", json!("unknown-parameter-set")),
        ("bindings_revision", json!("unknown-bindings")),
        ("backend_revision", json!("unknown-backend")),
    ] {
        let keystore = mutate_json(|json| json[field] = value);
        assert!(keystore.validate_password(PASSWORD).is_err(), "{field}");
    }
}

#[test]
fn noncanonical_and_hostile_crypto_parameters_are_rejected_before_derivation() {
    let _work_lock = pq_work_lock();
    for (name, mutate) in [
        ("high-cost scrypt", ("n", json!(1_048_576))),
        ("weak scrypt", ("n", json!(131_072))),
        ("noncanonical block size", ("r", json!(7))),
        ("noncanonical parallelism", ("p", json!(2))),
    ] {
        let keystore = mutate_json(|json| {
            json["crypto"]["kdf"]["params"][mutate.0] = mutate.1;
        });
        assert!(
            matches!(
                keystore.validate_password(PASSWORD),
                Err(PqKeystoreError::UnsupportedCryptoProfile)
            ),
            "{name}"
        );
    }

    let short_salt = mutate_json(|json| {
        json["crypto"]["kdf"]["params"]["salt"] = json!("00".repeat(31));
    });
    assert!(matches!(
        short_salt.validate_password(PASSWORD),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));

    let short_iv = mutate_json(|json| {
        json["crypto"]["cipher"]["params"]["iv"] = json!("00".repeat(15));
    });
    assert!(matches!(
        short_iv.validate_password(PASSWORD),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));

    let wrong_dklen = mutate_json(|json| {
        json["crypto"]["kdf"]["params"]["dklen"] = json!(31);
    });
    assert!(matches!(
        wrong_dklen.validate_metadata(),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));

    let mismatched_kdf_function = mutate_json(|json| {
        json["crypto"]["kdf"]["function"] = json!("pbkdf2");
    });
    assert!(matches!(
        mismatched_kdf_function.validate_metadata(),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));

    let short_checksum = mutate_json(|json| {
        json["crypto"]["checksum"]["message"] = json!("00".repeat(31));
    });
    assert!(matches!(
        short_checksum.validate_metadata(),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));

    let mut value = serde_json::to_value(valid_keystore()).expect("serialize");
    value["crypto"]["checksum"]["function"] = json!("sha512");
    assert!(matches!(
        PqKeystore::from_json_str(&serde_json::to_string(&value).expect("JSON")),
        Err(PqKeystoreError::Json(_))
    ));
}

#[test]
fn unknown_json_fields_are_rejected() {
    let _work_lock = pq_work_lock();
    let mut value = serde_json::to_value(valid_keystore()).expect("serialize");
    value["usage_state"] = json!({"last_used": 100});
    assert!(PqKeystore::from_json_str(&serde_json::to_string(&value).expect("JSON")).is_err());
}

#[test]
fn public_key_json_requires_canonical_lowercase_hex() {
    let _work_lock = pq_work_lock();
    let value = serde_json::to_value(valid_keystore()).expect("serialize");
    for malformed in [
        "AA".repeat(32),
        format!("0x{}", "00".repeat(32)),
        "0".repeat(63),
        "0".repeat(65),
        "00".repeat(31),
        "00".repeat(33),
        "gg".repeat(32),
    ] {
        let mut malformed_value = value.clone();
        malformed_value["public_key"] = json!(malformed);
        assert!(matches!(
            PqKeystore::from_json_str(&serde_json::to_string(&malformed_value).expect("JSON")),
            Err(PqKeystoreError::Json(_))
        ));
    }
}

#[test]
fn public_json_ingress_is_bounded_before_parsing() {
    let _work_lock = pq_work_lock();
    let mut oversized = valid_keystore().to_json_string().expect("JSON");
    oversized.extend(std::iter::repeat_n(
        ' ',
        eth2_keystore::MAX_PQ_KEYSTORE_JSON_BYTES,
    ));
    assert!(matches!(
        PqKeystore::from_json_str(&oversized),
        Err(PqKeystoreError::InputTooLarge)
    ));

    assert!(matches!(
        PqKeystore::from_json_reader(Cursor::new(oversized.as_bytes())),
        Err(PqKeystoreError::InputTooLarge)
    ));

    struct ErroringReader;
    impl Read for ErroringReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected reader failure"))
        }
    }
    assert!(matches!(
        PqKeystore::from_json_reader(ErroringReader),
        Err(PqKeystoreError::Io(_))
    ));
}

#[test]
fn inverted_range_and_oversized_ciphertext_are_rejected_before_derivation() {
    let _work_lock = pq_work_lock();
    let inverted = mutate_json(|json| {
        json["one_time_use_range"]["start"] = json!(116);
        json["one_time_use_range"]["end"] = json!(115);
    });
    assert!(matches!(
        inverted.validate_metadata(),
        Err(PqKeystoreError::InvalidOneTimeUseRange)
    ));

    let oversized_range = mutate_json(|json| {
        json["one_time_use_range"]["start"] = json!(0);
        json["one_time_use_range"]["end"] = json!(MAX_PQ_ONE_TIME_USE_IDS);
    });
    assert!(matches!(
        oversized_range.validate_metadata(),
        Err(PqKeystoreError::InvalidOneTimeUseRange)
    ));

    let full_u32_range = mutate_json(|json| {
        json["one_time_use_range"]["start"] = json!(0);
        json["one_time_use_range"]["end"] = json!(u32::MAX);
    });
    assert!(matches!(
        full_u32_range.validate_metadata(),
        Err(PqKeystoreError::InvalidOneTimeUseRange)
    ));

    let oversized_ciphertext = mutate_json(|json| {
        json["crypto"]["cipher"]["message"] = json!("00".repeat(4 * 1024 * 1024 + 1));
    });
    assert!(matches!(
        oversized_ciphertext.validate_metadata(),
        Err(PqKeystoreError::UnsupportedCryptoProfile)
    ));
}

#[test]
fn oversized_password_is_rejected_before_crypto() {
    let _work_lock = pq_work_lock();
    assert!(matches!(
        valid_keystore().validate_password(&vec![0; MAX_PQ_PASSWORD_BYTES + 1]),
        Err(PqKeystoreError::PasswordTooLong)
    ));
}

#[test]
fn password_with_stripped_controls_encrypts_and_decrypts_consistently() {
    let _work_lock = pq_work_lock();
    let keystore = PqKeystore::from_seed(
        [0x5c; 32],
        0..=7,
        b"\0correct horse\x7f\xc2\x85 battery staple",
    )
    .expect("encrypt with controls");

    keystore
        .validate_password(b"correct horse battery staple")
        .expect("decrypt with effective EIP-2335 password");
}

#[test]
#[ignore = "manual performance measurement; runs real sequential XMSS keygen and scrypt"]
fn measure_eight_leaf_key_storage() {
    let _work_lock = pq_work_lock();
    let keygen_started = Instant::now();
    let key = SecretKey::from_seed([0x5a; 32], 0..=7).expect("small key");
    let keygen_elapsed = keygen_started.elapsed();
    let upstream_bytes = Zeroizing::new(key.to_bytes());

    let encryption_started = Instant::now();
    let keystore = PqKeystoreBuilder::new(&key, PASSWORD)
        .expect("builder")
        .build()
        .expect("keystore");
    let encryption_elapsed = encryption_started.elapsed();
    let json = keystore.to_json_string().expect("JSON");

    let load_started = Instant::now();
    keystore.validate_password(PASSWORD).expect("load");
    let load_elapsed = load_started.elapsed();

    eprintln!(
        "8-leaf upstream_bytes={} json_bytes={} keygen={keygen_elapsed:?} encryption={encryption_elapsed:?} load={load_elapsed:?}",
        upstream_bytes.len(),
        json.len(),
    );
}

#[test]
#[ignore = "manual real-range measurement; generates 1,120 XMSS leaves and runs real scrypt"]
fn measure_full_1120_leaf_key_storage() {
    let _work_lock = pq_work_lock();
    let keygen_started = Instant::now();
    let key = SecretKey::from_seed([0x6b; 32], 0..=1119).expect("real-range key");
    let keygen_elapsed = keygen_started.elapsed();
    let upstream_bytes = Zeroizing::new(key.to_bytes());

    let encryption_started = Instant::now();
    let keystore = PqKeystoreBuilder::new(&key, PASSWORD)
        .expect("builder")
        .build()
        .expect("keystore");
    let encryption_elapsed = encryption_started.elapsed();
    let json = keystore.to_json_string().expect("JSON");

    let load_started = Instant::now();
    keystore.validate_password(PASSWORD).expect("load");
    let load_elapsed = load_started.elapsed();

    eprintln!(
        "1,120-leaf upstream_bytes={} json_bytes={} keygen={keygen_elapsed:?} encryption={encryption_elapsed:?} load={load_elapsed:?}",
        upstream_bytes.len(),
        json.len(),
    );
}
