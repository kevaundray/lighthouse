//! Creates, and optionally submits, an EIP-8450 `SignedPqKeyRegistration`.

use account_utils::eth2_keystore::{Keystore, keypair_from_secret};
use account_utils::read_password;
use bls::{Keypair, PublicKeyBytes, SecretKey};
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::types::{StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use eth2_wallet::bip39::{Language, Mnemonic, Seed};
use eth2_wallet::{KeyType, recover_validator_secret_from_mnemonic};
use lean_pq::xmss;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use types::{
    ChainSpec, Config, Domain, Epoch, EthSpec, Hash256, PQ_POSSESSION_XMSS_INDEX, PqKeyPossession,
    PqKeyRegistration, PqPublicKeys, SignedPqKeyRegistration, SignedRoot, VrfRoot, XmssPublicKey,
    XmssSignature,
};
use zeroize::Zeroizing;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// What the beacon node tells us about the chain and the validator.
struct ChainContext {
    spec: ChainSpec,
    genesis_validators_root: Hash256,
    on_chain_pubkey: bls::PublicKeyBytes,
    previous_change_epoch: Epoch,
}

pub fn run<E: EthSpec>(env: Environment<E>, matches: &ArgMatches) -> Result<(), String> {
    let beacon_url: SensitiveUrl = parse_required(matches, "beacon-node")?;
    let validator_index: u64 = parse_required(matches, "validator-index")?;
    let vrf_root = parse_hex32(
        &parse_required::<String>(matches, "vrf-root")?,
        "--vrf-root",
    )?;
    let previous_change_epoch_override: Option<Epoch> =
        parse_optional::<u64>(matches, "previous-change-epoch")?.map(Epoch::new);
    let xmss_seed_file: Option<PathBuf> = parse_optional(matches, "xmss-seed-file")?;
    let xmss_seed_out: Option<PathBuf> = parse_optional(matches, "xmss-seed-out")?;
    let output_path: Option<PathBuf> = parse_optional(matches, "output")?;
    let submit = matches.get_flag("submit");

    // Read an existing key, or fail early if a new one has nowhere to go. The seed file is only
    // created at write time, with `create_new`, so this check cannot cause an overwrite.
    let key_source = match (xmss_seed_file, xmss_seed_out) {
        (Some(path), _) => {
            let seed_file = read_xmss_seed_file(&path, validator_index)?;
            XmssKeySource::Reuse { path, seed_file }
        }
        (None, Some(path)) if path.exists() => {
            return Err(format!(
                "Refusing to overwrite existing XMSS seed file {}; use --xmss-seed-file to \
                 reuse it",
                path.display()
            ));
        }
        (None, Some(path)) => XmssKeySource::Create { path },
        (None, None) => {
            return Err(
                "One of --xmss-seed-file or --xmss-seed-out is required, otherwise a generated \
                 leanXMSS key and its proof of possession would be lost"
                    .to_string(),
            );
        }
    };

    let bls_keypair = load_bls_keypair(matches, validator_index)?;

    let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
    let handle = env
        .core_context()
        .executor
        .handle()
        .ok_or("shutdown in progress")?;

    let context = handle.block_on(fetch_chain_context::<E>(
        &client,
        validator_index,
        previous_change_epoch_override,
    ))?;

    if context.on_chain_pubkey != bls_keypair.pk.compress() {
        return Err(format!(
            "BLS public key {} does not match the on-chain public key {} of validator {}",
            bls_keypair.pk.as_hex_string(),
            context.on_chain_pubkey.as_hex_string(),
            validator_index
        ));
    }

    // Leaf `PQ_POSSESSION_XMSS_INDEX` of a key signs once, when the key is created. Reusing a key
    // reuses the proof stored with it and never reaches a signing call.
    let key_start = Instant::now();
    let xmss_key = match &key_source {
        XmssKeySource::Reuse { path, seed_file } => {
            let key = possessed_key_from_seed_file(
                seed_file,
                path,
                &context.on_chain_pubkey,
                context.genesis_validators_root,
                &context.spec,
            )?;
            eprintln!(
                "Reusing the proof of possession stored in {}",
                path.display()
            );
            key
        }
        XmssKeySource::Create { path } => {
            let key = create_xmss_key(
                path,
                validator_index,
                &context.on_chain_pubkey,
                context.genesis_validators_root,
                &context.spec,
            )?;
            eprintln!(
                "Wrote the new XMSS seed and its proof of possession for validator {} to {}",
                validator_index,
                path.display()
            );
            key
        }
    };
    let key_time = key_start.elapsed();

    let sign_start = Instant::now();
    let signed_registration = build_signed_registration(
        validator_index,
        &bls_keypair,
        &xmss_key,
        vrf_root,
        context.previous_change_epoch,
        context.genesis_validators_root,
        &context.spec,
    )?;
    let sign_time = sign_start.elapsed();

    eprintln!(
        "xmss_public_key: 0x{}",
        hex::encode(&signed_registration.message.public_keys.xmss_public_key[..])
    );
    eprintln!("xmss_leaf_index: {}", PQ_POSSESSION_XMSS_INDEX);
    eprintln!(
        "previous_change_epoch: {}",
        signed_registration.message.previous_change_epoch
    );
    if matches!(key_source, XmssKeySource::Reuse { .. }) {
        eprintln!(
            "Deriving the XMSS public key and verifying the stored proof took {:?}, \
             signing the registration took {:?}",
            key_time, sign_time
        );
    } else {
        eprintln!(
            "XMSS key generation and proof of possession took {:?}, signing the registration \
             took {:?}",
            key_time, sign_time
        );
    }

    let registrations = vec![signed_registration];
    let json = serde_json::to_string_pretty(&registrations)
        .map_err(|e| format!("Unable to serialize registration: {:?}", e))?;

    if let Some(path) = &output_path {
        fs::write(path, &json)
            .map_err(|e| format!("Unable to write {}: {:?}", path.display(), e))?;
        eprintln!("Wrote registration to {}", path.display());
    }

    if submit {
        handle
            .block_on(client.post_beacon_pool_pq_key_registrations(&registrations))
            .map_err(|e| format!("Beacon node rejected the registration: {}", e))?;
        eprintln!("Beacon node accepted the registration");
    }

    Ok(())
}

/// Fetches the chain parameters, the validator's on-chain public key and the epoch of its last
/// post-quantum key change.
async fn fetch_chain_context<E: EthSpec>(
    client: &BeaconNodeHttpClient,
    validator_index: u64,
    previous_change_epoch_override: Option<Epoch>,
) -> Result<ChainContext, String> {
    let genesis = client
        .get_beacon_genesis()
        .await
        .map_err(|e| format!("Unable to fetch genesis from the beacon node: {}", e))?
        .data;

    let config = client
        .get_config_spec::<Config>()
        .await
        .map_err(|e| format!("Unable to fetch the spec from the beacon node: {}", e))?
        .data;
    let spec = ChainSpec::from_config::<E>(&config)
        .ok_or("The preset of the beacon node does not match --spec (mainnet/minimal/gnosis)")?;
    if spec.genesis_fork_version != genesis.genesis_fork_version {
        return Err(format!(
            "Genesis fork version mismatch: spec has 0x{}, genesis has 0x{}",
            hex::encode(spec.genesis_fork_version),
            hex::encode(genesis.genesis_fork_version)
        ));
    }

    let validator = client
        .get_beacon_states_validator_id(StateId::Head, &ValidatorId::Index(validator_index))
        .await
        .map_err(|e| format!("Unable to fetch validator {}: {}", validator_index, e))?
        .ok_or_else(|| format!("Validator {} is unknown at head", validator_index))?
        .data;
    eprintln!(
        "Validator {} status: {:?}, pubkey: {}",
        validator_index,
        validator.status,
        validator.validator.pubkey.as_hex_string()
    );
    if validator.validator.exit_epoch != spec.far_future_epoch {
        return Err(format!(
            "Validator {} has initiated an exit (exit epoch {}) and cannot register keys",
            validator_index, validator.validator.exit_epoch
        ));
    }

    let previous_change_epoch = match previous_change_epoch_override {
        Some(epoch) => epoch,
        None => {
            let keys = client
                .get_beacon_states_pq_public_keys(StateId::Head, Some(&[validator_index]))
                .await
                .map_err(|e| {
                    format!(
                        "Unable to fetch the post-quantum keys of validator {}: {}",
                        validator_index, e
                    )
                })?
                .ok_or("Head state not found when fetching post-quantum keys")?
                .data;
            let entry = keys
                .into_iter()
                .find(|entry| entry.index == validator_index)
                .ok_or_else(|| {
                    format!(
                        "Beacon node returned no post-quantum keys for validator {}",
                        validator_index
                    )
                })?;
            if entry.change_epoch == spec.far_future_epoch {
                eprintln!("Validator {validator_index} has no registered post-quantum keys");
            } else {
                eprintln!(
                    "Current post-quantum keys: xmss_public_key 0x{}, vrf_root {:?}, \
                     change_epoch {}",
                    hex::encode(&entry.xmss_public_key[..]),
                    entry.vrf_root,
                    entry.change_epoch
                );
            }
            entry.change_epoch
        }
    };

    Ok(ChainContext {
        spec,
        genesis_validators_root: genesis.genesis_validators_root,
        on_chain_pubkey: validator.validator.pubkey,
        previous_change_epoch,
    })
}

/// Where the leanXMSS key of the registration comes from.
enum XmssKeySource {
    /// A key created by an earlier run, with the proof of possession it signed then.
    Reuse {
        path: PathBuf,
        seed_file: XmssSeedFile,
    },
    /// A new key, saved with its proof of possession to a new file at `path`.
    Create { path: PathBuf },
}

/// A leanXMSS public key and the proof of possession its key signed at leaf index
/// `PQ_POSSESSION_XMSS_INDEX` when it was created: the only proof that key ever signs, which
/// every registration of the key carries.
#[derive(Debug, Clone, PartialEq)]
pub struct PossessedXmssKey {
    pub xmss_public_key: XmssPublicKey,
    pub possession: XmssSignature,
}

/// Returns the signing root of the `PqKeyPossession` of `xmss_public_key` for the validator
/// holding `validator_pubkey`, as `get_pq_possession_signing_root` in `state_processing`: the
/// domain uses the genesis fork version.
fn possession_signing_root(
    validator_pubkey: &PublicKeyBytes,
    xmss_public_key: &XmssPublicKey,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Hash256 {
    let domain = spec.compute_domain(
        Domain::PqKeyPossession,
        spec.genesis_fork_version,
        genesis_validators_root,
    );
    PqKeyPossession {
        validator_pubkey: *validator_pubkey,
        xmss_public_key: xmss_public_key.clone(),
    }
    .signing_root(domain)
}

/// Checks that `possession` is a signature at leaf index `PQ_POSSESSION_XMSS_INDEX` by
/// `xmss_public_key` of its `PqKeyPossession` for `validator_pubkey`, as
/// `is_valid_pq_possession_proof` in `state_processing`.
fn verify_possession(
    validator_pubkey: &PublicKeyBytes,
    xmss_public_key: &XmssPublicKey,
    possession: &XmssSignature,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), String> {
    let signature = xmss::Signature::from_bytes(possession)
        .map_err(|e| format!("Invalid proof of possession: {}", e))?;
    if signature.leaf_index() != PQ_POSSESSION_XMSS_INDEX {
        return Err(format!(
            "Proof of possession is at leaf index {}, expected {}",
            signature.leaf_index(),
            PQ_POSSESSION_XMSS_INDEX
        ));
    }
    let public_key = xmss::PublicKey::from_bytes(xmss_public_key)
        .map_err(|e| format!("Invalid XMSS public key: {}", e))?;
    let signing_root = possession_signing_root(
        validator_pubkey,
        xmss_public_key,
        genesis_validators_root,
        spec,
    );
    public_key.verify(&signing_root.0, &signature).map_err(|e| {
        format!(
            "Proof of possession does not verify for validator public key {} and XMSS \
                 public key 0x{} on this network: {}",
            validator_pubkey.as_hex_string(),
            hex::encode(&xmss_public_key[..]),
            e
        )
    })
}

/// Returns the SSZ form of a leanXMSS public key.
fn encode_xmss_public_key(public_key: &xmss::PublicKey) -> Result<XmssPublicKey, String> {
    XmssPublicKey::new(public_key.to_bytes().to_vec())
        .map_err(|e| format!("Invalid XMSS public key length: {:?}", e))
}

/// Signs, at leaf index `PQ_POSSESSION_XMSS_INDEX`, the proof of possession of
/// `xmss_secret_key`'s public key for the validator holding `validator_pubkey`.
///
/// A key signs at a leaf index at most once. Call this only for a key that was just created, and
/// store the result with the key: it is the only proof the key may ever sign.
fn sign_possession(
    xmss_secret_key: &xmss::SecretKey,
    validator_pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    let xmss_public_key = encode_xmss_public_key(&xmss_secret_key.public_key())?;
    let signing_root = possession_signing_root(
        validator_pubkey,
        &xmss_public_key,
        genesis_validators_root,
        spec,
    );
    let signature = xmss_secret_key
        .sign(&signing_root.0, PQ_POSSESSION_XMSS_INDEX)
        .map_err(|e| format!("Unable to sign the proof of possession: {}", e))?;
    let possession = XmssSignature::new(signature.to_bytes().to_vec())
        .map_err(|e| format!("Invalid XMSS signature length: {:?}", e))?;
    verify_possession(
        validator_pubkey,
        &xmss_public_key,
        &possession,
        genesis_validators_root,
        spec,
    )?;
    Ok(PossessedXmssKey {
        xmss_public_key,
        possession,
    })
}

/// Creates a leanXMSS key from OS randomness for the validator holding `validator_pubkey`, and
/// saves it with its proof of possession (see `save_new_xmss_key`).
fn create_xmss_key(
    path: &Path,
    validator_index: u64,
    validator_pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    save_new_xmss_key(
        path,
        xmss::SecretKey::generate(),
        validator_index,
        validator_pubkey,
        genesis_validators_root,
        spec,
    )
}

/// Signs the proof of possession of a just-created `xmss_secret_key` for the validator holding
/// `validator_pubkey`, and saves both, with `validator_index`, to a new seed file at `path`.
///
/// Takes the secret key by value, so it does not outlive this function. If the file cannot be
/// created, the key and its proof are discarded unused.
fn save_new_xmss_key(
    path: &Path,
    xmss_secret_key: xmss::SecretKey,
    validator_index: u64,
    validator_pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    let key = sign_possession(
        &xmss_secret_key,
        validator_pubkey,
        genesis_validators_root,
        spec,
    )?;
    write_xmss_seed_file(
        path,
        &XmssSeedFile {
            seed: Zeroizing::new(format!(
                "0x{}",
                hex::encode(Zeroizing::new(xmss_secret_key.to_bytes()))
            )),
            validator_index,
            validator_pubkey: *validator_pubkey,
            possession: key.possession.clone(),
        },
    )?;
    Ok(key)
}

/// Returns the key of `seed_file`, read from `path`, with the proof of possession stored in it,
/// after checking that the proof is a valid proof of the seed's key for `validator_pubkey`, the
/// validator's on-chain public key. Never signs.
fn possessed_key_from_seed_file(
    seed_file: &XmssSeedFile,
    path: &Path,
    validator_pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    if seed_file.validator_pubkey != *validator_pubkey {
        return Err(format!(
            "XMSS seed file {} holds a proof of possession for BLS public key {}, but the \
             validator's public key is {}",
            path.display(),
            seed_file.validator_pubkey.as_hex_string(),
            validator_pubkey.as_hex_string()
        ));
    }
    let seed = Zeroizing::new(parse_hex32(&seed_file.seed, "XMSS seed")?);
    // Only the public key is needed: the secret key is dropped here, unused.
    let xmss_public_key = encode_xmss_public_key(&xmss::SecretKey::from_seed(*seed).public_key())?;
    verify_possession(
        validator_pubkey,
        &xmss_public_key,
        &seed_file.possession,
        genesis_validators_root,
        spec,
    )
    .map_err(|e| {
        format!(
            "Refusing the proof of possession stored in XMSS seed file {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(PossessedXmssKey {
        xmss_public_key,
        possession: seed_file.possession.clone(),
    })
}

/// Builds a registration of `xmss_key` and `vrf_root` for `validator_index`, carrying the key's
/// stored proof of possession and signed by `bls_keypair`, then verifies both signatures.
///
/// The proof must be for the public key of `bls_keypair`, which the caller checks against the
/// validator's on-chain public key. The signing root matches `pq_key_registration_signature_set`
/// in `state_processing`: the domain uses the genesis fork version.
pub fn build_signed_registration(
    validator_index: u64,
    bls_keypair: &Keypair,
    xmss_key: &PossessedXmssKey,
    vrf_root: [u8; 32],
    previous_change_epoch: Epoch,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<SignedPqKeyRegistration, String> {
    verify_possession(
        &bls_keypair.pk.compress(),
        &xmss_key.xmss_public_key,
        &xmss_key.possession,
        genesis_validators_root,
        spec,
    )?;

    let signed_registration = PqKeyRegistration {
        validator_index,
        public_keys: PqPublicKeys {
            xmss_public_key: xmss_key.xmss_public_key.clone(),
            vrf_root: VrfRoot::from(vrf_root),
        },
        previous_change_epoch,
    }
    .sign(
        xmss_key.possession.clone(),
        &bls_keypair.sk,
        genesis_validators_root,
        spec,
    );

    let registration_domain = spec.compute_domain(
        Domain::PqKeyRegistration,
        spec.genesis_fork_version,
        genesis_validators_root,
    );
    let registration_root = signed_registration
        .message
        .signing_root(registration_domain);
    if !signed_registration
        .signature
        .verify(&bls_keypair.pk, registration_root)
    {
        return Err("BLS signature of the registration does not verify".to_string());
    }

    Ok(signed_registration)
}

/// Loads the validator's BLS signing key from exactly one of `--mnemonic`, `--mnemonic-file`,
/// `--keystore`, `--bls-secret-key` or `--bls-secret-key-file`.
fn load_bls_keypair(matches: &ArgMatches, validator_index: u64) -> Result<Keypair, String> {
    let phrase = match (
        parse_optional::<String>(matches, "mnemonic")?,
        parse_optional::<PathBuf>(matches, "mnemonic-file")?,
    ) {
        (Some(phrase), _) => Some(Zeroizing::new(phrase)),
        (None, Some(path)) => Some(read_mnemonic_file(&path)?),
        (None, None) => None,
    };
    if let Some(phrase) = phrase {
        let derivation_index = match parse_optional::<u32>(matches, "derivation-index")? {
            Some(index) => index,
            None => u32::try_from(validator_index).map_err(|_| {
                format!(
                    "Validator index {} does not fit a derivation index, use --derivation-index",
                    validator_index
                )
            })?,
        };
        return keypair_from_mnemonic(&phrase, derivation_index);
    }

    if let Some(keystore_path) = parse_optional::<PathBuf>(matches, "keystore")? {
        let password_path: PathBuf = parse_required(matches, "password-file")?;
        let keystore = Keystore::from_json_file(&keystore_path).map_err(|e| {
            format!(
                "Unable to read keystore {}: {:?}",
                keystore_path.display(),
                e
            )
        })?;
        let password = read_password(&password_path).map_err(|e| {
            format!(
                "Unable to read password file {}: {:?}",
                password_path.display(),
                e
            )
        })?;
        return keystore
            .decrypt_keypair(password.as_bytes())
            .map_err(|e| format!("Unable to decrypt keystore: {:?}", e));
    }

    let secret_hex = match (
        parse_optional::<String>(matches, "bls-secret-key")?,
        parse_optional::<PathBuf>(matches, "bls-secret-key-file")?,
    ) {
        (Some(secret_hex), _) => Zeroizing::new(secret_hex),
        (None, Some(path)) => read_secret_file(&path)?,
        (None, None) => {
            return Err(
                "One of --mnemonic, --mnemonic-file, --keystore, --bls-secret-key or \
                 --bls-secret-key-file is required"
                    .to_string(),
            );
        }
    };
    keypair_from_secret_hex(&secret_hex)
}

/// Builds a keypair from a 0x-prefixed hex BLS secret key.
fn keypair_from_secret_hex(secret_hex: &str) -> Result<Keypair, String> {
    let secret = Zeroizing::new(parse_hex32(secret_hex, "BLS secret key")?);
    let sk =
        SecretKey::deserialize(&*secret).map_err(|e| format!("Invalid BLS secret key: {:?}", e))?;
    Ok(Keypair::from_components(sk.public_key(), sk))
}

/// Reads a secret from a file, with surrounding whitespace removed.
fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let contents = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("Unable to read {}: {:?}", path.display(), e))?,
    );
    Ok(Zeroizing::new(contents.trim().to_string()))
}

/// Reads a mnemonic phrase from a file, normalizing whitespace between its words.
fn read_mnemonic_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let contents = read_secret_file(path)?;
    Ok(Zeroizing::new(
        contents.split_whitespace().collect::<Vec<_>>().join(" "),
    ))
}

/// Derives the EIP-2334 signing key `m/12381/3600/{derivation_index}/0/0` from `phrase`.
pub fn keypair_from_mnemonic(phrase: &str, derivation_index: u32) -> Result<Keypair, String> {
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
        .map_err(|e| format!("Invalid mnemonic: {:?}", e))?;
    let seed = Seed::new(&mnemonic, "");
    let (secret, path) =
        recover_validator_secret_from_mnemonic(seed.as_bytes(), derivation_index, KeyType::Voting)
            .map_err(|e| format!("Unable to derive the signing key: {:?}", e))?;
    eprintln!("Derived BLS signing key at path {}", path);
    keypair_from_secret(secret.as_bytes())
        .map_err(|e| format!("Unable to build the BLS keypair: {:?}", e))
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    let bytes = Zeroizing::new(
        hex::decode(value.strip_prefix("0x").unwrap_or(value))
            .map_err(|e| format!("{} is not valid hex: {}", name, e))?,
    );
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{} must be 32 bytes, got {}", name, bytes.len()))
}

/// The contents of an XMSS seed file: a leanXMSS seed, the validator it was created for, and the
/// proof of possession the key signed then at leaf index `PQ_POSSESSION_XMSS_INDEX`.
///
/// That proof is the only one the key ever signs: every registration of the key, including a
/// resubmission or a VRF-root-only change, carries these bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct XmssSeedFile {
    /// 0x-prefixed hex of the 32-byte seed.
    seed: Zeroizing<String>,
    #[serde(with = "serde_utils::quoted_u64")]
    validator_index: u64,
    /// BLS public key of the validator, which the proof of possession names.
    validator_pubkey: PublicKeyBytes,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    possession: XmssSignature,
}

/// A seed file written before seed files stored the proof of possession.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyXmssSeedFile {
    #[serde(rename = "seed")]
    _seed: IgnoredAny,
    #[serde(rename = "validator_index")]
    _validator_index: IgnoredAny,
}

/// Reads an XMSS seed file, refusing a file of another validator, and a file in the earlier
/// format, which has no stored proof of possession.
fn read_xmss_seed_file(path: &Path, validator_index: u64) -> Result<XmssSeedFile, String> {
    let contents = read_secret_file(path)?;
    let seed_file: XmssSeedFile = serde_json::from_str(&contents).map_err(|e| {
        if serde_json::from_str::<LegacyXmssSeedFile>(&contents).is_ok() {
            format!(
                "XMSS seed file {} predates stored proofs of possession. Its key already signed \
                 its proof of possession at leaf index {}, and signing there again would be a \
                 second signature at that leaf, so this tool will not re-sign it. The original \
                 proof is in the registration output of the run that created the key. Create a \
                 new key with --xmss-seed-out",
                path.display(),
                PQ_POSSESSION_XMSS_INDEX
            )
        } else {
            format!("Invalid XMSS seed file {}: {}", path.display(), e)
        }
    })?;
    if seed_file.validator_index != validator_index {
        return Err(format!(
            "XMSS seed file {} belongs to validator {}, refusing to register its key for \
             validator {}",
            path.display(),
            seed_file.validator_index,
            validator_index
        ));
    }
    Ok(seed_file)
}

/// Writes `seed_file` to a new file at `path` that only the owner can read. Fails if `path`
/// already exists, so an existing seed is never overwritten.
fn write_xmss_seed_file(path: &Path, seed_file: &XmssSeedFile) -> Result<(), String> {
    let contents = Zeroizing::new(
        serde_json::to_string(seed_file)
            .map_err(|e| format!("Unable to serialize XMSS seed: {:?}", e))?,
    );

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| {
        format!(
            "Unable to create new XMSS seed file {}: {}",
            path.display(),
            e
        )
    })?;
    #[cfg(windows)]
    filesystem::restrict_file_permissions(path).map_err(|e| {
        format!(
            "Unable to restrict permissions of {}: {:?}",
            path.display(),
            e
        )
    })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("Unable to write XMSS seed to {}: {:?}", path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_processing::per_block_processing::errors::BlockOperationError;
    use state_processing::per_block_processing::{
        VerifySignatures, errors::PqKeyRegistrationInvalid, is_valid_pq_possession_proof,
        process_operations::process_pq_key_registrations, verify_pq_key_registration,
    };
    use types::test_utils::generate_deterministic_keypair;
    use types::{BeaconState, ForkName, MinimalEthSpec};

    type E = MinimalEthSpec;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";
    const VALIDATOR_INDEX: u64 = 1;
    const XMSS_SEED: [u8; 32] = [7; 32];
    const OTHER_XMSS_SEED: [u8; 32] = [8; 32];

    /// An Eip8450 genesis state whose validator `VALIDATOR_INDEX` uses the key derived from
    /// `MNEMONIC` at the default derivation index (the validator index).
    fn genesis_state(spec: &ChainSpec) -> (BeaconState<E>, Keypair) {
        let keypair = keypair_from_mnemonic(MNEMONIC, VALIDATOR_INDEX as u32).unwrap();
        let keypairs = (0..64)
            .map(|i| {
                if i == VALIDATOR_INDEX as usize {
                    keypair.clone()
                } else {
                    generate_deterministic_keypair(i)
                }
            })
            .collect::<Vec<_>>();
        let state = genesis::interop_genesis_state::<E>(
            &keypairs,
            0,
            Hash256::repeat_byte(0x42),
            None,
            spec,
        )
        .unwrap();
        assert_eq!(state.fork_name_unchecked(), ForkName::Eip8450);
        (state, keypair)
    }

    /// The BLS public key of validator `index` in `state`.
    fn pubkey_of(state: &BeaconState<E>, index: u64) -> PublicKeyBytes {
        state.get_validator(index as usize).unwrap().pubkey
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    /// Reads the seed file at `path` and returns its key, as the reuse path of `run` does.
    fn reuse(
        path: &Path,
        validator_pubkey: &PublicKeyBytes,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<PossessedXmssKey, String> {
        let seed_file = read_xmss_seed_file(path, VALIDATOR_INDEX)?;
        possessed_key_from_seed_file(
            &seed_file,
            path,
            validator_pubkey,
            state.genesis_validators_root(),
            spec,
        )
    }

    #[test]
    fn stored_proof_is_the_proof_of_every_registration() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, keypair) = genesis_state(&spec);
        let validator_pubkey = pubkey_of(&state, VALIDATOR_INDEX);
        assert_eq!(validator_pubkey, keypair.pk.compress());
        // A first registration names the validator's stored entry, `FAR_FUTURE_EPOCH`.
        let previous_change_epoch = *state
            .pq_key_change_epochs()
            .unwrap()
            .get(VALIDATOR_INDEX as usize)
            .unwrap();
        assert_eq!(previous_change_epoch, spec.far_future_epoch);

        // Creating the key signs its proof of possession and stores it with the seed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        let created = save_new_xmss_key(
            &path,
            xmss::SecretKey::from_seed(XMSS_SEED),
            VALIDATOR_INDEX,
            &validator_pubkey,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        let stored = read_json(&path);
        assert_eq!(
            stored["possession"],
            format!("0x{}", hex::encode(&created.possession[..]))
        );
        assert_eq!(stored["validator_pubkey"], validator_pubkey.as_hex_string());
        assert_eq!(stored["validator_index"], VALIDATOR_INDEX.to_string());
        assert_eq!(
            xmss::Signature::from_bytes(&created.possession)
                .unwrap()
                .leaf_index(),
            PQ_POSSESSION_XMSS_INDEX
        );
        assert!(is_valid_pq_possession_proof(
            &state,
            &validator_pubkey,
            &created.xmss_public_key,
            &created.possession,
            &spec
        ));
        assert!(!is_valid_pq_possession_proof(
            &state,
            &pubkey_of(&state, 0),
            &created.xmss_public_key,
            &created.possession,
            &spec
        ));

        let first = build_signed_registration(
            VALIDATOR_INDEX,
            &keypair,
            &created,
            [9; 32],
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(first.possession, created.possession);
        assert_eq!(first.message.public_keys.vrf_root, Hash256::repeat_byte(9));
        assert_eq!(first.message.previous_change_epoch, spec.far_future_epoch);
        verify_pq_key_registration(&state, &first, VerifySignatures::True, &spec).unwrap();

        // The JSON written by the command round-trips.
        let json = serde_json::to_string(&vec![first.clone()]).unwrap();
        let decoded: Vec<SignedPqKeyRegistration> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, vec![first.clone()]);

        // The registration applies to the state.
        let mut applied = state.clone();
        process_pq_key_registrations(
            &mut applied,
            std::slice::from_ref(&first),
            VerifySignatures::True,
            &spec,
        )
        .unwrap();
        assert_eq!(
            applied
                .pq_public_keys()
                .unwrap()
                .get(VALIDATOR_INDEX as usize)
                .unwrap(),
            &first.message.public_keys
        );

        // Reusing the file yields the stored proof, byte for byte, without signing.
        let reused = reuse(&path, &validator_pubkey, &state, &spec).unwrap();
        assert_eq!(reused, created);

        // A resubmission, e.g. after an orphaned block, is the same registration.
        let resubmission = build_signed_registration(
            VALIDATOR_INDEX,
            &keypair,
            &reused,
            [9; 32],
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(resubmission, first);

        // A VRF-root-only change carries the same proof.
        let vrf_change = build_signed_registration(
            VALIDATOR_INDEX,
            &keypair,
            &reuse(&path, &validator_pubkey, &state, &spec).unwrap(),
            [10; 32],
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(vrf_change.possession, created.possession);
        assert_eq!(
            vrf_change.message.public_keys.xmss_public_key,
            created.xmss_public_key
        );
        assert_eq!(
            vrf_change.message.public_keys.vrf_root,
            Hash256::repeat_byte(10)
        );
        verify_pq_key_registration(&state, &vrf_change, VerifySignatures::True, &spec).unwrap();

        // The file was only read.
        assert_eq!(read_json(&path), stored);

        // Signatures are bound to the network via the genesis validators root.
        *state.genesis_validators_root_mut() = Hash256::repeat_byte(0x01);
        assert!(matches!(
            verify_pq_key_registration(&state, &first, VerifySignatures::True, &spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::BadSignature
            ))
        ));
        let err = reuse(&path, &validator_pubkey, &state, &spec).unwrap_err();
        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn seed_file_with_a_foreign_or_corrupted_proof_is_refused() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (state, _) = genesis_state(&spec);
        let gvr = state.genesis_validators_root();
        let validator_pubkey = pubkey_of(&state, VALIDATOR_INDEX);
        let other_pubkey = pubkey_of(&state, 0);
        let dir = tempfile::tempdir().unwrap();

        let path = dir.path().join("good.json");
        let created = save_new_xmss_key(
            &path,
            xmss::SecretKey::from_seed(XMSS_SEED),
            VALIDATOR_INDEX,
            &validator_pubkey,
            gvr,
            &spec,
        )
        .unwrap();
        assert_eq!(
            reuse(&path, &validator_pubkey, &state, &spec).unwrap(),
            created
        );
        let good = read_xmss_seed_file(&path, VALIDATOR_INDEX).unwrap();
        let other_key = sign_possession(
            &xmss::SecretKey::from_seed(OTHER_XMSS_SEED),
            &other_pubkey,
            gvr,
            &spec,
        )
        .unwrap();

        let variant = |name: &str, edit: &dyn Fn(&mut XmssSeedFile)| -> String {
            let mut seed_file = XmssSeedFile {
                seed: good.seed.clone(),
                validator_index: good.validator_index,
                validator_pubkey: good.validator_pubkey,
                possession: good.possession.clone(),
            };
            edit(&mut seed_file);
            let path = dir.path().join(name);
            write_xmss_seed_file(&path, &seed_file).unwrap();
            reuse(&path, &validator_pubkey, &state, &spec).unwrap_err()
        };

        // The file names another validator's public key.
        let err = variant("other_pubkey.json", &|f| f.validator_pubkey = other_pubkey);
        assert!(
            err.contains("holds a proof of possession for BLS public key"),
            "{err}"
        );

        // The stored proof is for another validator's public key.
        let err = variant("foreign_proof.json", &|f| {
            f.seed = Zeroizing::new(format!("0x{}", hex::encode(OTHER_XMSS_SEED)));
            f.possession = other_key.possession.clone();
        });
        assert!(err.contains("does not verify"), "{err}");

        // The stored proof is for another key.
        let err = variant("other_seed.json", &|f| {
            f.seed = Zeroizing::new(format!("0x{}", hex::encode(OTHER_XMSS_SEED)));
        });
        assert!(err.contains("does not verify"), "{err}");

        // The stored proof is corrupted.
        let err = variant("corrupted.json", &|f| f.possession[1000] ^= 1);
        assert!(err.contains("does not verify"), "{err}");

        // The stored proof is not at the leaf index reserved for it.
        let err = variant("leaf_index.json", &|f| f.possession[0] = 1);
        assert!(err.contains("at leaf index 1, expected 0"), "{err}");
    }

    #[test]
    fn legacy_seed_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");
        fs::write(
            &path,
            format!(
                r#"{{"seed":"0x{}","validator_index":"{}"}}"#,
                "07".repeat(32),
                VALIDATOR_INDEX
            ),
        )
        .unwrap();
        let err = read_xmss_seed_file(&path, VALIDATOR_INDEX).err().unwrap();
        assert!(
            err.contains("predates stored proofs of possession"),
            "{err}"
        );
        assert!(err.contains("will not re-sign"), "{err}");
    }

    #[test]
    fn created_key_is_saved_with_its_proof() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (state, _) = genesis_state(&spec);
        let validator_pubkey = pubkey_of(&state, VALIDATOR_INDEX);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        let created = create_xmss_key(
            &path,
            VALIDATOR_INDEX,
            &validator_pubkey,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(
            reuse(&path, &validator_pubkey, &state, &spec).unwrap(),
            created
        );
    }

    #[test]
    fn xmss_seed_file_is_private_never_overwritten_and_bound_to_its_validator() {
        let seed_file = |seed: [u8; 32]| XmssSeedFile {
            seed: Zeroizing::new(format!("0x{}", hex::encode(seed))),
            validator_index: VALIDATOR_INDEX,
            validator_pubkey: generate_deterministic_keypair(1).pk.compress(),
            possession: XmssSignature::new(vec![0; 2404]).unwrap(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        write_xmss_seed_file(&path, &seed_file(XMSS_SEED)).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let json = read_json(&path);
        assert_eq!(json["seed"], format!("0x{}", "07".repeat(32)));
        assert_eq!(json["validator_index"], VALIDATOR_INDEX.to_string());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // An existing file is never replaced.
        assert!(write_xmss_seed_file(&path, &seed_file(OTHER_XMSS_SEED)).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);

        let read = read_xmss_seed_file(&path, VALIDATOR_INDEX).unwrap();
        assert_eq!(*read.seed, format!("0x{}", "07".repeat(32)));
        let err = read_xmss_seed_file(&path, VALIDATOR_INDEX + 1)
            .err()
            .unwrap();
        assert!(err.contains("belongs to validator 1"), "{err}");

        // A planted symlink, even a dangling one, is not followed.
        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(write_xmss_seed_file(&link, &seed_file(XMSS_SEED)).is_err());
            assert!(!target.exists());
        }

        // Unknown fields and malformed files are rejected.
        let mut extra = json.clone();
        extra["extra"] = 1.into();
        let bad = dir.path().join("bad.json");
        fs::write(&bad, extra.to_string()).unwrap();
        let err = read_xmss_seed_file(&bad, VALIDATOR_INDEX).err().unwrap();
        assert!(err.contains("unknown field"), "{err}");
        let mut short = json.clone();
        short["possession"] = "0x0000".into();
        fs::write(&bad, short.to_string()).unwrap();
        assert!(read_xmss_seed_file(&bad, VALIDATOR_INDEX).is_err());
    }

    #[test]
    fn secret_files_match_command_line_values() {
        let dir = tempfile::tempdir().unwrap();

        let mnemonic_path = dir.path().join("mnemonic");
        fs::write(
            &mnemonic_path,
            format!("  {}\n\n", MNEMONIC.replace(' ', "  \n")),
        )
        .unwrap();
        let from_file =
            keypair_from_mnemonic(&read_mnemonic_file(&mnemonic_path).unwrap(), 3).unwrap();
        assert_eq!(from_file.pk, keypair_from_mnemonic(MNEMONIC, 3).unwrap().pk);

        let expected = generate_deterministic_keypair(3);
        let secret_hex = format!("0x{}", hex::encode(expected.sk.serialize().as_bytes()));
        let secret_path = dir.path().join("bls_secret");
        fs::write(&secret_path, format!("{secret_hex}\r\n")).unwrap();
        let from_file = keypair_from_secret_hex(&read_secret_file(&secret_path).unwrap()).unwrap();
        assert_eq!(from_file.pk, expected.pk);
        assert_eq!(
            keypair_from_secret_hex(&secret_hex).unwrap().pk,
            expected.pk
        );
    }

    #[test]
    fn parse_hex32_checks_length() {
        assert_eq!(
            parse_hex32(&format!("0x{}", "ab".repeat(32)), "x").unwrap(),
            [0xab; 32]
        );
        assert_eq!(parse_hex32(&"cd".repeat(32), "x").unwrap(), [0xcd; 32]);
        assert!(parse_hex32("0xabcd", "x").is_err());
        assert!(parse_hex32("0xzz", "x").is_err());
    }
}
