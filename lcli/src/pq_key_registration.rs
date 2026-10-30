//! Creates, and optionally submits, an EIP-8450 `SignedPqKeyRegistration` for a validator or a
//! builder.

use account_utils::eth2_keystore::{Keystore, keypair_from_secret};
use account_utils::read_password;
use bls::{Keypair, PublicKeyBytes, SecretKey};
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::types::{BuilderData, BuilderId, BuilderStatus, StateId, ValidatorId};
use eth2::{BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use eth2_wallet::bip39::{Language, Mnemonic, Seed};
use eth2_wallet::{KeyType, recover_validator_secret_from_mnemonic};
use lean_pq::xmss;
use serde::{Deserialize, Serialize};
use state_processing::per_block_processing::builder::is_builder_index;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use types::builder::BuilderIndex;
use types::{
    ChainSpec, Config, Domain, Epoch, EthSpec, Hash256, PQ_POSSESSION_XMSS_INDEX, PqKeyMaterial,
    PqKeyPossession, PqKeyRegistration, PqRegistryIndex, SignedPqKeyRegistration, SignedRoot,
    VrfRoot, XmssPublicKey, XmssSignature,
};
use zeroize::Zeroizing;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns the validator or builder given by exactly one of `--validator-index` and
/// `--builder-index`. Neither may carry `BUILDER_INDEX_FLAG`: the registration's index carries it
/// for a builder.
fn registrant_from_indices(
    validator_index: Option<u64>,
    builder_index: Option<BuilderIndex>,
) -> Result<PqRegistryIndex, String> {
    let (name, index, registrant) = match (validator_index, builder_index) {
        (Some(index), None) => ("Validator", index, PqRegistryIndex::Validator(index)),
        (None, Some(index)) => ("Builder", index, PqRegistryIndex::Builder(index)),
        _ => {
            return Err(
                "Exactly one of --validator-index and --builder-index is required".to_string(),
            );
        }
    };
    if is_builder_index(index) {
        return Err(format!(
            "{} index {} has BUILDER_INDEX_FLAG set; give a builder's index in the builder \
             registry, without the flag, to --builder-index",
            name, index
        ));
    }
    Ok(registrant)
}

/// Names `registrant` in messages, a builder by its index in the builder registry.
fn describe(registrant: PqRegistryIndex) -> String {
    match registrant {
        PqRegistryIndex::Validator(index) => format!("validator {}", index),
        PqRegistryIndex::Builder(index) => format!("builder {}", index),
    }
}

/// Returns the VRF root that `registrant` registers given `--vrf-root`: the given root for a
/// validator, which must give one, and zero for a builder, which makes no selection proofs and
/// so registers no VRF tree.
fn registered_vrf_root(
    registrant: PqRegistryIndex,
    vrf_root: Option<[u8; 32]>,
) -> Result<[u8; 32], String> {
    match (registrant, vrf_root) {
        (PqRegistryIndex::Validator(_), Some(vrf_root)) => Ok(vrf_root),
        (PqRegistryIndex::Validator(_), None) => {
            Err("--vrf-root is required for a validator".to_string())
        }
        (PqRegistryIndex::Builder(_), None) => Ok([0; 32]),
        (PqRegistryIndex::Builder(_), Some(vrf_root)) if vrf_root == [0; 32] => Ok(vrf_root),
        (PqRegistryIndex::Builder(builder_index), Some(vrf_root)) => Err(format!(
            "Builder {} must register a zero VRF root, not 0x{}: builders make no selection \
             proofs",
            builder_index,
            hex::encode(vrf_root)
        )),
    }
}

/// What the beacon node tells us about the chain and the validator or builder.
struct ChainContext {
    spec: ChainSpec,
    genesis_validators_root: Hash256,
    on_chain_pubkey: bls::PublicKeyBytes,
    previous_change_epoch: Epoch,
}

pub fn run<E: EthSpec>(env: Environment<E>, matches: &ArgMatches) -> Result<(), String> {
    let beacon_url: SensitiveUrl = parse_required(matches, "beacon-node")?;
    let registrant = registrant_from_indices(
        parse_optional(matches, "validator-index")?,
        parse_optional(matches, "builder-index")?,
    )?;
    let vrf_root = registered_vrf_root(
        registrant,
        parse_optional::<String>(matches, "vrf-root")?
            .map(|vrf_root| parse_hex32(&vrf_root, "--vrf-root"))
            .transpose()?,
    )?;
    let previous_change_epoch_override: Option<Epoch> =
        parse_optional::<u64>(matches, "previous-change-epoch")?.map(Epoch::new);
    let xmss_seed_out: PathBuf = parse_required(matches, "xmss-seed-out")?;
    let output_path: Option<PathBuf> = parse_optional(matches, "output")?;
    let submit = matches.get_flag("submit");

    // Fail early if the new key has nowhere to go. The seed file is only created at write time,
    // with `create_new`, so this check cannot cause an overwrite.
    if xmss_seed_out.exists() {
        return Err(format!(
            "Refusing to overwrite existing XMSS seed file {}. Every registration needs a new \
             key, so give a new path; a registration that was not included is resubmitted by \
             POSTing its --output file unchanged",
            xmss_seed_out.display()
        ));
    }

    let bls_keypair = load_bls_keypair(matches, registrant)?;

    let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
    let handle = env
        .core_context()
        .executor
        .handle()
        .ok_or("shutdown in progress")?;

    let context = handle.block_on(fetch_chain_context::<E>(
        &client,
        registrant,
        previous_change_epoch_override,
    ))?;

    if context.on_chain_pubkey != bls_keypair.pk.compress() {
        return Err(format!(
            "BLS public key {} does not match the on-chain public key {} of {}",
            bls_keypair.pk.as_hex_string(),
            context.on_chain_pubkey.as_hex_string(),
            describe(registrant)
        ));
    }

    // Every registration carries a new key: leaf `PQ_POSSESSION_XMSS_INDEX` of the key created
    // here signs its proof of possession once, and no other run ever signs with this key.
    let key_start = Instant::now();
    let xmss_key = create_xmss_key(
        &xmss_seed_out,
        registrant,
        &context.on_chain_pubkey,
        context.genesis_validators_root,
        &context.spec,
    )?;
    let key_time = key_start.elapsed();
    eprintln!(
        "Wrote the new XMSS seed for {} to {}",
        describe(registrant),
        xmss_seed_out.display()
    );

    let sign_start = Instant::now();
    let signed_registration = build_signed_registration(
        registrant,
        &bls_keypair,
        &xmss_key,
        vrf_root,
        context.previous_change_epoch,
        context.genesis_validators_root,
        &context.spec,
    )?;
    let sign_time = sign_start.elapsed();

    eprintln!("index: {}", signed_registration.message.index);
    eprintln!(
        "xmss_public_key: 0x{}",
        hex::encode(&signed_registration.message.key_material.xmss_public_key[..])
    );
    eprintln!(
        "vrf_root: {:?}",
        signed_registration.message.key_material.vrf_root
    );
    eprintln!("xmss_leaf_index: {}", PQ_POSSESSION_XMSS_INDEX);
    eprintln!(
        "previous_change_epoch: {}",
        signed_registration.message.previous_change_epoch
    );
    eprintln!(
        "XMSS key generation and proof of possession took {:?}, signing the registration took \
         {:?}",
        key_time, sign_time
    );

    let registrations = vec![signed_registration];

    if let Some(path) = &output_path {
        write_registration_output(path, &registrations)?;
        eprintln!(
            "Wrote registration to {}. If it is not included, resubmit this file unchanged to \
             POST /eth/v1/beacon/pool/pq_key_registrations",
            path.display()
        );
    }

    if submit {
        handle
            .block_on(client.post_beacon_pool_pq_key_registrations(&registrations))
            .map_err(|e| format!("Beacon node rejected the registration: {}", e))?;
        eprintln!("Beacon node accepted the registration");
    }

    Ok(())
}

/// Fetches the chain parameters, the on-chain public key of `registrant` and the epoch of its
/// last post-quantum key change.
async fn fetch_chain_context<E: EthSpec>(
    client: &BeaconNodeHttpClient,
    registrant: PqRegistryIndex,
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

    // The public key, and the stored change epoch of an entry that has never registered keys.
    let (on_chain_pubkey, unregistered_epoch) = match registrant {
        PqRegistryIndex::Validator(validator_index) => (
            fetch_validator_pubkey(client, validator_index, &spec).await?,
            spec.far_future_epoch,
        ),
        PqRegistryIndex::Builder(builder_index) => {
            let builder = fetch_builder(client, builder_index).await?;
            check_builder_active(&builder, &spec)?;
            (builder.builder.pubkey, builder.builder.deposit_epoch)
        }
    };

    let previous_change_epoch = match previous_change_epoch_override {
        Some(epoch) => epoch,
        None => {
            let index = registrant.as_u64();
            let entries = client
                .get_beacon_states_pq_key_material(StateId::Head, Some(&[index]))
                .await
                .map_err(|e| {
                    format!(
                        "Unable to fetch the post-quantum key material of {}: {}",
                        describe(registrant),
                        e
                    )
                })?
                .ok_or("Head state not found when fetching post-quantum key material")?
                .data;
            let entry = entries
                .into_iter()
                .find(|entry| entry.index == index)
                .ok_or_else(|| {
                    format!(
                        "Beacon node returned no post-quantum key material for {}",
                        describe(registrant)
                    )
                })?;
            if entry.change_epoch == unregistered_epoch {
                eprintln!(
                    "The {} has no registered post-quantum keys",
                    describe(registrant)
                );
            } else {
                eprintln!(
                    "Current post-quantum key material: xmss_public_key 0x{}, vrf_root {:?}, \
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
        on_chain_pubkey,
        previous_change_epoch,
    })
}

/// Fetches the public key of validator `validator_index` at head, which must not have initiated
/// an exit.
async fn fetch_validator_pubkey(
    client: &BeaconNodeHttpClient,
    validator_index: u64,
    spec: &ChainSpec,
) -> Result<PublicKeyBytes, String> {
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
    Ok(validator.validator.pubkey)
}

/// Fetches builder `builder_index` and its status at head.
async fn fetch_builder(
    client: &BeaconNodeHttpClient,
    builder_index: BuilderIndex,
) -> Result<BuilderData, String> {
    let builder = client
        .post_beacon_states_builders(
            StateId::Head,
            Some(vec![BuilderId::Index(builder_index)]),
            None,
        )
        .await
        .map_err(|e| format!("Unable to fetch builder {}: {}", builder_index, e))?
        .ok_or("Head state not found when fetching the builder")?
        .data
        .into_iter()
        .find(|builder| builder.index == builder_index)
        .ok_or_else(|| format!("Builder {} is unknown at head", builder_index))?;
    eprintln!(
        "Builder {} status: {:?}, pubkey: {}, deposit epoch: {}",
        builder_index,
        builder.status,
        builder.builder.pubkey.as_hex_string(),
        builder.builder.deposit_epoch
    );
    Ok(builder)
}

/// Checks that `builder` is active, as a builder registration requires (`is_active_builder`):
/// it has not initiated an exit, and its deposit epoch is finalized. Its status is computed
/// against the finalized checkpoint of the state it was fetched from.
fn check_builder_active(builder: &BuilderData, spec: &ChainSpec) -> Result<(), String> {
    if builder.builder.withdrawable_epoch != spec.far_future_epoch {
        return Err(format!(
            "Builder {} has initiated an exit (withdrawable epoch {}) and cannot register keys",
            builder.index, builder.builder.withdrawable_epoch
        ));
    }
    if builder.status != BuilderStatus::Active {
        return Err(format!(
            "Builder {} is not active: its deposit epoch {} is not finalized yet. It can register \
             keys once the finalized checkpoint is past epoch {}",
            builder.index, builder.builder.deposit_epoch, builder.builder.deposit_epoch
        ));
    }
    Ok(())
}

/// A leanXMSS public key and the proof of possession its key signed at leaf index
/// `PQ_POSSESSION_XMSS_INDEX` when it was created: the only proof that key ever signs, carried by
/// its one registration.
#[derive(Debug, Clone, PartialEq)]
pub struct PossessedXmssKey {
    pub xmss_public_key: XmssPublicKey,
    pub possession: XmssSignature,
}

/// Returns the signing root of the `PqKeyPossession` of `xmss_public_key` for the validator or
/// builder holding `pubkey`, as `get_pq_possession_signing_root` in `state_processing`: the
/// domain uses the genesis fork version.
fn possession_signing_root(
    pubkey: &PublicKeyBytes,
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
        pubkey: *pubkey,
        xmss_public_key: xmss_public_key.clone(),
    }
    .signing_root(domain)
}

/// Checks that `possession` is a signature at leaf index `PQ_POSSESSION_XMSS_INDEX` by
/// `xmss_public_key` of its `PqKeyPossession` for `pubkey`, as `is_valid_pq_possession_proof` in
/// `state_processing`.
fn verify_possession(
    pubkey: &PublicKeyBytes,
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
    let signing_root =
        possession_signing_root(pubkey, xmss_public_key, genesis_validators_root, spec);
    public_key.verify(&signing_root.0, &signature).map_err(|e| {
        format!(
            "Proof of possession does not verify for BLS public key {} and XMSS public key 0x{} \
             on this network: {}",
            pubkey.as_hex_string(),
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
/// `xmss_secret_key`'s public key for the validator or builder holding `pubkey`.
///
/// A key signs at a leaf index at most once. Call this only for a key that was just created: every
/// registration carries a new key, so this is the only proof the key ever signs.
fn sign_possession(
    xmss_secret_key: &xmss::SecretKey,
    pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    let xmss_public_key = encode_xmss_public_key(&xmss_secret_key.public_key())?;
    let signing_root =
        possession_signing_root(pubkey, &xmss_public_key, genesis_validators_root, spec);
    let signature = xmss_secret_key
        .sign(&signing_root.0, PQ_POSSESSION_XMSS_INDEX)
        .map_err(|e| format!("Unable to sign the proof of possession: {}", e))?;
    let possession = XmssSignature::new(signature.to_bytes().to_vec())
        .map_err(|e| format!("Invalid XMSS signature length: {:?}", e))?;
    verify_possession(
        pubkey,
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

/// Creates a leanXMSS key from OS randomness for `registrant`, holding `pubkey`, saves its seed
/// to a new seed file at `path`, then signs its proof of possession.
///
/// The seed is saved before the key signs anything, so the signer of the key's later duties has
/// it. If the file cannot be created, the key is discarded without having signed.
fn create_xmss_key(
    path: &Path,
    registrant: PqRegistryIndex,
    pubkey: &PublicKeyBytes,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<PossessedXmssKey, String> {
    let xmss_secret_key = xmss::SecretKey::generate();
    write_xmss_seed_file(
        path,
        &XmssSeedFile {
            seed: Zeroizing::new(format!(
                "0x{}",
                hex::encode(Zeroizing::new(xmss_secret_key.to_bytes()))
            )),
            index: registrant.as_u64(),
            pubkey: *pubkey,
        },
    )?;
    sign_possession(&xmss_secret_key, pubkey, genesis_validators_root, spec)
}

/// Builds a registration of `xmss_key` and `vrf_root` for `registrant`, carrying the key's
/// proof of possession and signed by `bls_keypair`, then verifies both signatures. A builder's
/// `vrf_root` must be zero.
///
/// The proof must be for the public key of `bls_keypair`, which the caller checks against the
/// on-chain public key of the validator or builder. The signing root matches
/// `pq_key_registration_signature_set` in `state_processing`: the domain uses the genesis fork
/// version.
pub fn build_signed_registration(
    registrant: PqRegistryIndex,
    bls_keypair: &Keypair,
    xmss_key: &PossessedXmssKey,
    vrf_root: [u8; 32],
    previous_change_epoch: Epoch,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<SignedPqKeyRegistration, String> {
    let vrf_root = registered_vrf_root(registrant, Some(vrf_root))?;
    verify_possession(
        &bls_keypair.pk.compress(),
        &xmss_key.xmss_public_key,
        &xmss_key.possession,
        genesis_validators_root,
        spec,
    )?;

    let signed_registration = PqKeyRegistration {
        index: registrant.as_u64(),
        key_material: PqKeyMaterial {
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

/// Loads the BLS signing key of `registrant` from exactly one of `--mnemonic`, `--mnemonic-file`,
/// `--keystore`, `--bls-secret-key` or `--bls-secret-key-file`. A mnemonic derives validator
/// keys only.
fn load_bls_keypair(matches: &ArgMatches, registrant: PqRegistryIndex) -> Result<Keypair, String> {
    let phrase = match (
        parse_optional::<String>(matches, "mnemonic")?,
        parse_optional::<PathBuf>(matches, "mnemonic-file")?,
    ) {
        (Some(phrase), _) => Some(Zeroizing::new(phrase)),
        (None, Some(path)) => Some(read_mnemonic_file(&path)?),
        (None, None) => None,
    };
    if let Some(phrase) = phrase {
        let validator_index = match registrant {
            PqRegistryIndex::Validator(validator_index) => validator_index,
            PqRegistryIndex::Builder(_) => {
                return Err(
                    "--mnemonic is not supported for builders: Lighthouse has no mnemonic \
                     derivation for builder keys. Use --keystore, --bls-secret-key or \
                     --bls-secret-key-file"
                        .to_string(),
                );
            }
        };
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

/// The contents of an XMSS seed file: what the signer of the validator or builder needs for the
/// key's later duties, namely the leanXMSS seed and the registrant it was created for.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct XmssSeedFile {
    /// 0x-prefixed hex of the 32-byte seed.
    seed: Zeroizing<String>,
    /// The registration's index: a validator index, or a builder index with
    /// `BUILDER_INDEX_FLAG` set.
    #[serde(with = "serde_utils::quoted_u64")]
    index: u64,
    /// BLS public key of the validator or builder, which the key's proof of possession names.
    pubkey: PublicKeyBytes,
}

/// Writes `registrations` to `path` as the JSON body of
/// `POST /eth/v1/beacon/pool/pq_key_registrations`. A registration that is not included is
/// resubmitted by POSTing this file unchanged.
fn write_registration_output(
    path: &Path,
    registrations: &[SignedPqKeyRegistration],
) -> Result<(), String> {
    let json = serde_json::to_string_pretty(registrations)
        .map_err(|e| format!("Unable to serialize registration: {:?}", e))?;
    fs::write(path, json).map_err(|e| format!("Unable to write {}: {:?}", path.display(), e))
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
    use types::consts::gloas::{BUILDER_INDEX_FLAG, PAYLOAD_BUILDER_VERSION};
    use types::test_utils::generate_deterministic_keypair;
    use types::{BeaconState, Checkpoint, ForkName, MinimalEthSpec, Slot};

    type E = MinimalEthSpec;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon about";
    const VALIDATOR_INDEX: u64 = 1;
    const VALIDATOR: PqRegistryIndex = PqRegistryIndex::Validator(VALIDATOR_INDEX);
    /// Deterministic keypair index of the builder's BLS key, past the genesis validators.
    const BUILDER_KEYPAIR: usize = 100;
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

    /// Reads a seed file as the signer of the validator or builder would.
    fn read_seed_file(path: &Path) -> Result<XmssSeedFile, serde_json::Error> {
        serde_json::from_str(&fs::read_to_string(path).unwrap())
    }

    /// Adds a builder holding the BLS key `BUILDER_KEYPAIR`, deposited at epoch 0, to `state`,
    /// then moves `state` to epoch 2 with epoch 1 finalized, so that the builder is active.
    /// Returns its builder index and its BLS key, loaded from hex as `--bls-secret-key` does.
    fn add_active_builder(state: &mut BeaconState<E>, spec: &ChainSpec) -> (BuilderIndex, Keypair) {
        let deterministic = generate_deterministic_keypair(BUILDER_KEYPAIR);
        let keypair = keypair_from_secret_hex(&format!(
            "0x{}",
            hex::encode(deterministic.sk.serialize().as_bytes())
        ))
        .unwrap();
        let builder_index = state
            .add_builder_to_registry(
                keypair.pk.compress(),
                PAYLOAD_BUILDER_VERSION,
                Hash256::ZERO,
                spec.min_deposit_amount,
                Slot::new(0),
                spec,
            )
            .unwrap();
        *state.slot_mut() = Slot::new(2 * E::slots_per_epoch());
        *state.finalized_checkpoint_mut() = Checkpoint {
            epoch: Epoch::new(1),
            root: Hash256::ZERO,
        };
        (builder_index, keypair)
    }

    /// The builder `builder_index` of `state`, with its status as the beacon node reports it.
    fn builder_data(state: &BeaconState<E>, builder_index: u64, spec: &ChainSpec) -> BuilderData {
        let builder = state
            .builders()
            .unwrap()
            .get(builder_index as usize)
            .unwrap()
            .clone();
        BuilderData {
            index: builder_index,
            status: BuilderStatus::from_builder(
                &builder,
                state.finalized_checkpoint().epoch,
                spec.far_future_epoch,
            ),
            builder,
        }
    }

    /// The stored change epoch of validator `VALIDATOR_INDEX`, which its registration names.
    fn previous_change_epoch(state: &BeaconState<E>) -> Epoch {
        *state
            .pq_key_change_epochs()
            .unwrap()
            .get(VALIDATOR_INDEX as usize)
            .unwrap()
    }

    /// Creates a key for validator `VALIDATOR_INDEX` in a new seed file at `path`, as a run does.
    fn new_key(path: &Path, state: &BeaconState<E>, spec: &ChainSpec) -> PossessedXmssKey {
        create_xmss_key(
            path,
            VALIDATOR,
            &pubkey_of(state, VALIDATOR_INDEX),
            state.genesis_validators_root(),
            spec,
        )
        .unwrap()
    }

    /// Builds the registration of `key` with a VRF root of `vrf_byte`s, as a run does.
    fn register(
        key: &PossessedXmssKey,
        keypair: &Keypair,
        vrf_byte: u8,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> SignedPqKeyRegistration {
        build_signed_registration(
            VALIDATOR,
            keypair,
            key,
            [vrf_byte; 32],
            previous_change_epoch(state),
            state.genesis_validators_root(),
            spec,
        )
        .unwrap()
    }

    #[test]
    fn run_creates_a_key_and_saves_only_its_seed() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (state, _) = genesis_state(&spec);
        let validator_pubkey = pubkey_of(&state, VALIDATOR_INDEX);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        let created = new_key(&path, &state, &spec);

        let stored = read_json(&path);
        let mut fields = stored
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(fields, ["index", "pubkey", "seed"]);
        assert_eq!(stored["index"], VALIDATOR_INDEX.to_string());
        assert_eq!(stored["pubkey"], validator_pubkey.as_hex_string());

        // The stored seed is the seed of the created key.
        let seed_file = read_seed_file(&path).unwrap();
        let seed = Zeroizing::new(parse_hex32(&seed_file.seed, "XMSS seed").unwrap());
        assert_eq!(
            encode_xmss_public_key(&xmss::SecretKey::from_seed(*seed).public_key()).unwrap(),
            created.xmss_public_key
        );

        // The key signed its proof of possession at the reserved leaf, for this validator only.
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
    }

    #[test]
    fn registration_verifies_against_an_eip8450_state() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, keypair) = genesis_state(&spec);
        assert_eq!(pubkey_of(&state, VALIDATOR_INDEX), keypair.pk.compress());
        // A first registration names the validator's stored entry, `FAR_FUTURE_EPOCH`.
        assert_eq!(previous_change_epoch(&state), spec.far_future_epoch);
        let dir = tempfile::tempdir().unwrap();
        let key = new_key(&dir.path().join("xmss_seed.json"), &state, &spec);

        let registration = register(&key, &keypair, 9, &state, &spec);
        assert_eq!(registration.possession, key.possession);
        assert_eq!(
            registration.message.key_material.xmss_public_key,
            key.xmss_public_key
        );
        assert_eq!(
            registration.message.key_material.vrf_root,
            Hash256::repeat_byte(9)
        );
        assert_eq!(
            registration.message.previous_change_epoch,
            spec.far_future_epoch
        );
        verify_pq_key_registration(&state, &registration, VerifySignatures::True, &spec).unwrap();

        // The registration applies to the state.
        let mut applied = state.clone();
        process_pq_key_registrations(
            &mut applied,
            std::slice::from_ref(&registration),
            VerifySignatures::True,
            &spec,
        )
        .unwrap();
        assert_eq!(
            applied
                .pq_key_material()
                .unwrap()
                .get(VALIDATOR_INDEX as usize)
                .unwrap(),
            &registration.message.key_material
        );

        // Signatures are bound to the network via the genesis validators root.
        *state.genesis_validators_root_mut() = Hash256::repeat_byte(0x01);
        assert!(matches!(
            verify_pq_key_registration(&state, &registration, VerifySignatures::True, &spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::BadSignature
            ))
        ));
    }

    #[test]
    fn builder_registration_verifies_against_an_eip8450_state() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, _) = genesis_state(&spec);
        let (builder_index, keypair) = add_active_builder(&mut state, &spec);
        let builder = PqRegistryIndex::Builder(builder_index);
        let data = builder_data(&state, builder_index, &spec);
        check_builder_active(&data, &spec).unwrap();
        assert_eq!(data.builder.pubkey, keypair.pk.compress());
        // A builder that has never registered keys stores its deposit epoch, which a first
        // registration names.
        let previous_change_epoch = *state
            .builder_pq_key_change_epochs()
            .unwrap()
            .get(builder_index as usize)
            .unwrap();
        assert_eq!(previous_change_epoch, data.builder.deposit_epoch);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        let key = create_xmss_key(
            &path,
            builder,
            &data.builder.pubkey,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        // The seed file names the flagged index and the builder's public key.
        let seed_file = read_seed_file(&path).unwrap();
        assert_eq!(seed_file.index, builder_index | BUILDER_INDEX_FLAG);
        assert_eq!(seed_file.pubkey, data.builder.pubkey);

        let registration = build_signed_registration(
            builder,
            &keypair,
            &key,
            registered_vrf_root(builder, None).unwrap(),
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        assert_eq!(
            registration.message.index,
            builder_index | BUILDER_INDEX_FLAG
        );
        assert_eq!(registration.message.key_material.vrf_root, Hash256::ZERO);
        assert_eq!(registration.possession, key.possession);
        verify_pq_key_registration(&state, &registration, VerifySignatures::True, &spec).unwrap();

        // The registration applies to the builder's entry.
        let mut applied = state.clone();
        process_pq_key_registrations(
            &mut applied,
            std::slice::from_ref(&registration),
            VerifySignatures::True,
            &spec,
        )
        .unwrap();
        assert_eq!(
            applied
                .builder_pq_key_material()
                .unwrap()
                .get(builder_index as usize)
                .unwrap(),
            &registration.message.key_material
        );
        assert_eq!(
            *applied
                .builder_pq_key_change_epochs()
                .unwrap()
                .get(builder_index as usize)
                .unwrap(),
            applied.current_epoch()
        );
        // The change moved the stored epoch off the deposit epoch: the builder is registered.
        assert_ne!(applied.current_epoch(), data.builder.deposit_epoch);
    }

    #[test]
    fn builder_registration_refuses_a_non_zero_vrf_root() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, _) = genesis_state(&spec);
        let (builder_index, keypair) = add_active_builder(&mut state, &spec);
        let builder = PqRegistryIndex::Builder(builder_index);

        // A builder may omit --vrf-root or give zero; any other root is refused. A validator
        // must give one.
        assert_eq!(registered_vrf_root(builder, None), Ok([0; 32]));
        assert_eq!(registered_vrf_root(builder, Some([0; 32])), Ok([0; 32]));
        let err = registered_vrf_root(builder, Some([9; 32])).unwrap_err();
        assert!(err.contains("zero VRF root"), "{err}");
        assert_eq!(registered_vrf_root(VALIDATOR, Some([9; 32])), Ok([9; 32]));
        assert!(registered_vrf_root(VALIDATOR, None).is_err());

        let pubkey = builder_data(&state, builder_index, &spec).builder.pubkey;
        let previous_change_epoch = *state
            .builder_pq_key_change_epochs()
            .unwrap()
            .get(builder_index as usize)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = create_xmss_key(
            &dir.path().join("xmss_seed.json"),
            builder,
            &pubkey,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        let err = build_signed_registration(
            builder,
            &keypair,
            &key,
            [9; 32],
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap_err();
        assert!(err.contains("zero VRF root"), "{err}");

        // Consensus rejects the registration the tool refuses to build.
        let signed = PqKeyRegistration {
            index: builder.as_u64(),
            key_material: PqKeyMaterial {
                xmss_public_key: key.xmss_public_key.clone(),
                vrf_root: Hash256::repeat_byte(9),
            },
            previous_change_epoch,
        }
        .sign(
            key.possession.clone(),
            &keypair.sk,
            state.genesis_validators_root(),
            &spec,
        );
        assert!(matches!(
            verify_pq_key_registration(&state, &signed, VerifySignatures::True, &spec),
            Err(BlockOperationError::Invalid(
                PqKeyRegistrationInvalid::BuilderNonZeroVrfRoot(_)
            ))
        ));
    }

    #[test]
    fn inactive_builders_are_refused() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (mut state, _) = genesis_state(&spec);
        let (builder_index, keypair) = add_active_builder(&mut state, &spec);
        let builder = PqRegistryIndex::Builder(builder_index);
        let pubkey = builder_data(&state, builder_index, &spec).builder.pubkey;
        let previous_change_epoch = *state
            .builder_pq_key_change_epochs()
            .unwrap()
            .get(builder_index as usize)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = create_xmss_key(
            &dir.path().join("xmss_seed.json"),
            builder,
            &pubkey,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        let registration = build_signed_registration(
            builder,
            &keypair,
            &key,
            [0; 32],
            previous_change_epoch,
            state.genesis_validators_root(),
            &spec,
        )
        .unwrap();
        let rejected = |state: &BeaconState<E>| {
            matches!(
                verify_pq_key_registration(state, &registration, VerifySignatures::True, &spec),
                Err(BlockOperationError::Invalid(
                    PqKeyRegistrationInvalid::BuilderNotActive(_)
                ))
            )
        };

        // The builder's deposit epoch is not finalized yet.
        let mut pending = state.clone();
        *pending.finalized_checkpoint_mut() = Checkpoint {
            epoch: Epoch::new(0),
            root: Hash256::ZERO,
        };
        let err =
            check_builder_active(&builder_data(&pending, builder_index, &spec), &spec).unwrap_err();
        assert!(err.contains("is not finalized"), "{err}");
        assert!(rejected(&pending));

        // The builder has initiated an exit.
        let mut exiting = state.clone();
        exiting
            .builders_mut()
            .unwrap()
            .get_mut(builder_index as usize)
            .unwrap()
            .withdrawable_epoch = Epoch::new(5);
        let err =
            check_builder_active(&builder_data(&exiting, builder_index, &spec), &spec).unwrap_err();
        assert!(err.contains("initiated an exit"), "{err}");
        assert!(rejected(&exiting));

        // The active builder passes both.
        check_builder_active(&builder_data(&state, builder_index, &spec), &spec).unwrap();
        assert!(!rejected(&state));
    }

    #[test]
    fn registrant_comes_from_one_unflagged_index() {
        assert_eq!(
            registrant_from_indices(Some(3), None),
            Ok(PqRegistryIndex::Validator(3))
        );
        let builder = registrant_from_indices(None, Some(3)).unwrap();
        assert_eq!(builder, PqRegistryIndex::Builder(3));
        assert_eq!(builder.as_u64(), 3 | BUILDER_INDEX_FLAG);
        // A given index never carries the flag: the registration adds it for a builder.
        assert!(registrant_from_indices(Some(3 | BUILDER_INDEX_FLAG), None).is_err());
        assert!(registrant_from_indices(None, Some(3 | BUILDER_INDEX_FLAG)).is_err());
        assert!(registrant_from_indices(None, None).is_err());
        assert!(registrant_from_indices(Some(3), Some(3)).is_err());
    }

    #[test]
    fn each_run_creates_a_different_key() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (state, keypair) = genesis_state(&spec);
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first.json");
        let second_path = dir.path().join("second.json");
        let first = new_key(&first_path, &state, &spec);
        let second = new_key(&second_path, &state, &spec);

        assert_ne!(first.xmss_public_key, second.xmss_public_key);
        assert_ne!(first.possession, second.possession);
        assert_ne!(
            read_json(&first_path)["seed"],
            read_json(&second_path)["seed"]
        );

        // Each run's registration carries its own key and the proof that key signed.
        for key in [&first, &second] {
            let registration = register(key, &keypair, 9, &state, &spec);
            assert_eq!(
                registration.message.key_material.xmss_public_key,
                key.xmss_public_key
            );
            assert_eq!(registration.possession, key.possession);
            verify_pq_key_registration(&state, &registration, VerifySignatures::True, &spec)
                .unwrap();
        }
    }

    #[test]
    fn output_file_round_trips_unchanged() {
        let spec = ForkName::Eip8450.make_genesis_spec(E::default_spec());
        let (state, keypair) = genesis_state(&spec);
        let dir = tempfile::tempdir().unwrap();
        let key = new_key(&dir.path().join("xmss_seed.json"), &state, &spec);
        let registrations = vec![register(&key, &keypair, 9, &state, &spec)];

        let path = dir.path().join("registration.json");
        write_registration_output(&path, &registrations).unwrap();
        let contents = fs::read_to_string(&path).unwrap();

        // The file decodes to the signed registration, which re-encodes to the same bytes: a
        // resubmission POSTs exactly what was signed.
        let decoded: Vec<SignedPqKeyRegistration> = serde_json::from_str(&contents).unwrap();
        assert_eq!(decoded, registrations);
        assert_eq!(serde_json::to_string_pretty(&decoded).unwrap(), contents);
        verify_pq_key_registration(&state, &decoded[0], VerifySignatures::True, &spec).unwrap();
    }

    #[test]
    fn xmss_seed_file_is_private_and_never_overwritten() {
        let seed_file = |seed: [u8; 32]| XmssSeedFile {
            seed: Zeroizing::new(format!("0x{}", hex::encode(seed))),
            index: VALIDATOR_INDEX,
            pubkey: generate_deterministic_keypair(1).pk.compress(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xmss_seed.json");
        write_xmss_seed_file(&path, &seed_file(XMSS_SEED)).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let json = read_json(&path);
        assert_eq!(json["seed"], format!("0x{}", "07".repeat(32)));
        assert_eq!(json["index"], VALIDATOR_INDEX.to_string());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // An existing file is never replaced.
        assert!(write_xmss_seed_file(&path, &seed_file(OTHER_XMSS_SEED)).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), contents);

        let read = read_seed_file(&path).unwrap();
        assert_eq!(*read.seed, format!("0x{}", "07".repeat(32)));
        assert_eq!(read.index, VALIDATOR_INDEX);

        // A planted symlink, even a dangling one, is not followed.
        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(write_xmss_seed_file(&link, &seed_file(XMSS_SEED)).is_err());
            assert!(!target.exists());
        }

        // Unknown fields are rejected.
        let mut extra = json.clone();
        extra["extra"] = 1.into();
        let bad = dir.path().join("bad.json");
        fs::write(&bad, extra.to_string()).unwrap();
        let err = read_seed_file(&bad).err().unwrap().to_string();
        assert!(err.contains("unknown field"), "{err}");
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
