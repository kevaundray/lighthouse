//! Creates, and optionally submits, an EIP-8450 `SignedPqKeyRegistration`.

use account_utils::eth2_keystore::{Keystore, keypair_from_secret};
use account_utils::read_password;
use bls::{Keypair, SecretKey};
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::types::{StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use eth2_wallet::bip39::{Language, Mnemonic, Seed};
use eth2_wallet::{KeyType, recover_validator_secret_from_mnemonic};
use lean_pq::xmss;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use types::{
    ChainSpec, Config, Domain, Epoch, EthSpec, Hash256, PQ_KEYS_VERSION_1,
    PQ_POSSESSION_XMSS_INDEX, PqKeyPossession, PqKeyRegistration, PqPublicKeys,
    SignedPqKeyRegistration, SignedRoot, VrfRoot, XmssPublicKey, XmssSignature,
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

    // Read an existing seed, or fail early if a generated one has nowhere to go. The seed file
    // is only created at write time, with `create_new`, so this check cannot cause an overwrite.
    let existing_xmss_seed = match (&xmss_seed_file, &xmss_seed_out) {
        (Some(path), _) => Some(read_xmss_seed_file(path, validator_index)?),
        (None, Some(path)) if path.exists() => {
            return Err(format!(
                "Refusing to overwrite existing XMSS seed file {}; use --xmss-seed-file to \
                 reuse it",
                path.display()
            ));
        }
        (None, Some(_)) => None,
        (None, None) => {
            return Err(
                "One of --xmss-seed-file or --xmss-seed-out is required, otherwise a generated \
                 leanXMSS key would be lost"
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

    let keygen_start = Instant::now();
    let xmss_secret_key = match existing_xmss_seed {
        Some(seed) => xmss::SecretKey::from_seed(seed),
        None => {
            let secret_key = xmss::SecretKey::generate();
            // Checked above: a generated seed always has a destination.
            let path = xmss_seed_out
                .as_ref()
                .ok_or("missing --xmss-seed-out for a generated XMSS seed")?;
            // Bind the key to this validator before leaf `PQ_POSSESSION_XMSS_INDEX` signs.
            write_xmss_seed_file(path, &secret_key.to_bytes(), validator_index)?;
            eprintln!(
                "Wrote generated XMSS seed for validator {} to {}",
                validator_index,
                path.display()
            );
            secret_key
        }
    };
    let keygen_time = keygen_start.elapsed();

    let sign_start = Instant::now();
    let signed_registration = build_signed_registration(
        validator_index,
        &bls_keypair,
        &xmss_secret_key,
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
    eprintln!(
        "XMSS key generation took {:?}, signing and verifying the registration took {:?}",
        keygen_time, sign_time
    );

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
            eprintln!(
                "Current post-quantum keys: version {}, xmss_public_key 0x{}, change_epoch {}",
                entry.version,
                hex::encode(&entry.xmss_public_key[..]),
                entry.change_epoch
            );
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

/// Builds a registration of `xmss_secret_key`'s public key and `vrf_root` for `validator_index`,
/// signed by `bls_keypair` and carrying a proof of possession, then verifies both signatures.
///
/// Signing roots match `get_pq_possession_signing_root` and `pq_key_registration_signature_set`
/// in `state_processing`: both domains use the genesis fork version.
pub fn build_signed_registration(
    validator_index: u64,
    bls_keypair: &Keypair,
    xmss_secret_key: &xmss::SecretKey,
    vrf_root: [u8; 32],
    previous_change_epoch: Epoch,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<SignedPqKeyRegistration, String> {
    let xmss_public_key = xmss_secret_key.public_key();
    let xmss_public_key_bytes = XmssPublicKey::new(xmss_public_key.to_bytes().to_vec())
        .map_err(|e| format!("Invalid XMSS public key length: {:?}", e))?;
    let vrf_root =
        VrfRoot::new(vrf_root.to_vec()).map_err(|e| format!("Invalid VRF root length: {:?}", e))?;

    let possession_domain = spec.compute_domain(
        Domain::PqKeyPossession,
        spec.genesis_fork_version,
        genesis_validators_root,
    );
    let possession_root = PqKeyPossession {
        validator_index,
        xmss_public_key: xmss_public_key_bytes.clone(),
    }
    .signing_root(possession_domain);
    let possession = xmss_secret_key
        .sign(&possession_root.0, PQ_POSSESSION_XMSS_INDEX)
        .map_err(|e| format!("Unable to sign the possession proof: {}", e))?;
    if possession.leaf_index() != PQ_POSSESSION_XMSS_INDEX {
        return Err(format!(
            "Possession proof signed at leaf index {}, expected {}",
            possession.leaf_index(),
            PQ_POSSESSION_XMSS_INDEX
        ));
    }
    xmss_public_key
        .verify(&possession_root.0, &possession)
        .map_err(|e| format!("Possession proof does not verify: {}", e))?;

    let signed_registration = PqKeyRegistration {
        validator_index,
        public_keys: PqPublicKeys {
            version: PQ_KEYS_VERSION_1,
            xmss_public_key: xmss_public_key_bytes,
            vrf_root,
        },
        previous_change_epoch,
    }
    .sign(
        XmssSignature::new(possession.to_bytes().to_vec())
            .map_err(|e| format!("Invalid XMSS signature length: {:?}", e))?,
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

/// The contents of an XMSS seed file: a leanXMSS seed and the only validator index whose proof
/// of possession it may sign at leaf index `PQ_POSSESSION_XMSS_INDEX`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct XmssSeedFile {
    /// 0x-prefixed hex of the 32-byte seed.
    seed: Zeroizing<String>,
    #[serde(with = "serde_utils::quoted_u64")]
    validator_index: u64,
}

/// Reads the seed from an XMSS seed file, refusing a file bound to another validator: leaf index
/// `PQ_POSSESSION_XMSS_INDEX` of a key only ever signs the possession of one validator index.
fn read_xmss_seed_file(path: &Path, validator_index: u64) -> Result<[u8; 32], String> {
    let contents = read_secret_file(path)?;
    let seed_file: XmssSeedFile = serde_json::from_str(&contents)
        .map_err(|e| format!("Invalid XMSS seed file {}: {}", path.display(), e))?;
    if seed_file.validator_index != validator_index {
        return Err(format!(
            "XMSS seed file {} belongs to validator {}, refusing to sign a proof of possession \
             for validator {} with the same key",
            path.display(),
            seed_file.validator_index,
            validator_index
        ));
    }
    parse_hex32(&seed_file.seed, "XMSS seed")
}

/// Writes `seed`, bound to `validator_index`, to a new file at `path` that only the owner can
/// read. Fails if `path` already exists, so an existing seed is never overwritten.
fn write_xmss_seed_file(path: &Path, seed: &[u8; 32], validator_index: u64) -> Result<(), String> {
    let contents = Zeroizing::new(
        serde_json::to_string(&XmssSeedFile {
            seed: Zeroizing::new(format!("0x{}", hex::encode(seed))),
            validator_index,
        })
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

    #[test]
    fn registration_passes_state_verification() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, keypair) = genesis_state(&spec);
        let xmss_secret_key = xmss::SecretKey::from_seed(XMSS_SEED);

        let signed = build_signed_registration(
            VALIDATOR_INDEX,
            &keypair,
            &xmss_secret_key,
            [9; 32],
            Epoch::new(0),
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();

        assert_eq!(signed.message.public_keys.version, PQ_KEYS_VERSION_1);
        assert_eq!(
            xmss::Signature::from_bytes(&signed.possession)
                .unwrap()
                .leaf_index(),
            PQ_POSSESSION_XMSS_INDEX
        );
        assert!(is_valid_pq_possession_proof(
            &state,
            VALIDATOR_INDEX,
            &signed.message.public_keys.xmss_public_key,
            &signed.possession,
            &spec
        ));
        verify_pq_key_registration(&state, &signed, VerifySignatures::True, &spec).unwrap();

        // The JSON written by the command round-trips.
        let json = serde_json::to_string(&vec![signed.clone()]).unwrap();
        let decoded: Vec<SignedPqKeyRegistration> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, vec![signed.clone()]);

        // The registration applies to the state.
        let mut applied = state.clone();
        process_pq_key_registrations(
            &mut applied,
            std::slice::from_ref(&signed),
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
            &signed.message.public_keys
        );

        // Reusing the seed file for a VRF-root-only change re-signs leaf 0 identically.
        let dir = tempfile::tempdir().unwrap();
        let seed_path = dir.path().join("xmss_seed.json");
        write_xmss_seed_file(&seed_path, &XMSS_SEED, VALIDATOR_INDEX).unwrap();
        let reused_key =
            xmss::SecretKey::from_seed(read_xmss_seed_file(&seed_path, VALIDATOR_INDEX).unwrap());
        let vrf_change = build_signed_registration(
            VALIDATOR_INDEX,
            &keypair,
            &reused_key,
            [10; 32],
            Epoch::new(0),
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(vrf_change.possession, signed.possession);
        assert_eq!(
            vrf_change.message.public_keys.xmss_public_key,
            signed.message.public_keys.xmss_public_key
        );
        verify_pq_key_registration(&state, &vrf_change, VerifySignatures::True, &spec).unwrap();

        // Signatures are bound to the network via the genesis validators root.
        *state.genesis_validators_root_mut() = Hash256::repeat_byte(0x01);
        assert!(matches!(
            verify_pq_key_registration(&state, &signed, VerifySignatures::True, &spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::BadSignature
            ))
        ));
    }

    #[test]
    fn xmss_seed_file_is_private_never_overwritten_and_bound_to_its_validator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        write_xmss_seed_file(&path, &XMSS_SEED, VALIDATOR_INDEX).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(json["seed"], format!("0x{}", "07".repeat(32)));
        assert_eq!(json["validator_index"], VALIDATOR_INDEX.to_string());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // An existing file is never replaced.
        assert!(write_xmss_seed_file(&path, &[8; 32], VALIDATOR_INDEX).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);

        assert_eq!(
            read_xmss_seed_file(&path, VALIDATOR_INDEX).unwrap(),
            XMSS_SEED
        );
        let err = read_xmss_seed_file(&path, VALIDATOR_INDEX + 1).unwrap_err();
        assert!(err.contains("belongs to validator 1"), "{err}");

        // A planted symlink, even a dangling one, is not followed.
        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(write_xmss_seed_file(&link, &XMSS_SEED, VALIDATOR_INDEX).is_err());
            assert!(!target.exists());
        }

        // Unknown fields and malformed seeds are rejected.
        let bad = dir.path().join("bad.json");
        fs::write(&bad, r#"{"seed": "0x0707", "validator_index": "1"}"#).unwrap();
        assert!(read_xmss_seed_file(&bad, VALIDATOR_INDEX).is_err());
        fs::write(
            &bad,
            format!(
                r#"{{"seed": "0x{}", "validator_index": "1", "extra": 1}}"#,
                "07".repeat(32)
            ),
        )
        .unwrap();
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
