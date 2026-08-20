#![cfg(feature = "pq-beacon-startup-testing")]

use beacon_node::{PqLaunchCliError, parse_pq_launch_cli};
use clap::{Arg, ArgAction, Command};
use std::time::{SystemTime, UNIX_EPOCH};

fn lighthouse_pq_command() -> Command {
    Command::new("lighthouse")
        .arg(
            Arg::new("testnet-dir")
                .long("testnet-dir")
                .action(ArgAction::Set)
                .global(true),
        )
        .subcommand(beacon_node::cli_app())
}

#[test]
fn requires_an_explicit_public_testnet_directory() {
    let matches = lighthouse_pq_command()
        .try_get_matches_from([
            "lighthouse",
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
        ])
        .expect("syntactically valid PQ beacon-node CLI");
    let beacon_node_matches = matches
        .subcommand_matches("beacon_node")
        .expect("beacon-node subcommand");

    assert_eq!(
        parse_pq_launch_cli(beacon_node_matches).expect_err("testnet directory is mandatory"),
        PqLaunchCliError::MissingTestnetDir,
    );
}

#[test]
fn retains_the_exact_public_testnet_path_without_filesystem_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-launch-cli-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("public-testnet");
    let matches = lighthouse_pq_command()
        .try_get_matches_from([
            std::ffi::OsStr::new("lighthouse"),
            std::ffi::OsStr::new("--testnet-dir"),
            testnet.as_os_str(),
            std::ffi::OsStr::new("beacon_node"),
            std::ffi::OsStr::new("--execution-endpoint"),
            std::ffi::OsStr::new("http://127.0.0.1:8551"),
        ])
        .expect("syntactically valid PQ beacon-node CLI");
    let plan = parse_pq_launch_cli(
        matches
            .subcommand_matches("beacon_node")
            .expect("beacon-node subcommand"),
    )
    .expect("pure PQ launch plan");

    assert_eq!(plan.testnet_dir(), testnet);
    assert!(
        !root.exists(),
        "CLI planning must not probe or create paths"
    );
}

#[cfg(not(feature = "pq-proposer"))]
#[test]
fn verifier_profile_rejects_a_validator_bundle_without_filesystem_io() {
    let root = std::env::temp_dir().join("lighthouse-pq-launch-verifier-no-bundle");
    let testnet = root.join("public-testnet");
    let bundle = root.join("private-bundle");
    let matches = lighthouse_pq_command()
        .try_get_matches_from([
            std::ffi::OsStr::new("lighthouse"),
            std::ffi::OsStr::new("--testnet-dir"),
            testnet.as_os_str(),
            std::ffi::OsStr::new("beacon_node"),
            std::ffi::OsStr::new("--execution-endpoint"),
            std::ffi::OsStr::new("http://127.0.0.1:8551"),
            std::ffi::OsStr::new("--http"),
            std::ffi::OsStr::new("--pq-validator-bundle"),
            bundle.as_os_str(),
        ])
        .expect("syntactically valid but feature-disabled proposer CLI");

    assert_eq!(
        parse_pq_launch_cli(
            matches
                .subcommand_matches("beacon_node")
                .expect("beacon-node subcommand"),
        )
        .expect_err("verifier build must reject private validator input"),
        PqLaunchCliError::ProposerFeatureDisabled,
    );
    assert!(!root.exists(), "feature rejection must remain pure");
}

#[cfg(feature = "pq-proposer")]
#[test]
fn retains_one_optional_authenticated_bundle_without_filesystem_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-launch-proposer-{}-{unique}",
        std::process::id()
    ));
    let testnet = root.join("public-testnet");
    let bundle = root.join("private-bundle");
    let matches = lighthouse_pq_command()
        .try_get_matches_from([
            std::ffi::OsStr::new("lighthouse"),
            std::ffi::OsStr::new("--testnet-dir"),
            testnet.as_os_str(),
            std::ffi::OsStr::new("beacon_node"),
            std::ffi::OsStr::new("--execution-endpoint"),
            std::ffi::OsStr::new("http://127.0.0.1:8551"),
            std::ffi::OsStr::new("--http"),
            std::ffi::OsStr::new("--pq-validator-bundle"),
            bundle.as_os_str(),
        ])
        .expect("syntactically valid PQ proposer CLI");
    let plan = parse_pq_launch_cli(
        matches
            .subcommand_matches("beacon_node")
            .expect("beacon-node subcommand"),
    )
    .expect("pure PQ proposer launch plan");

    assert_eq!(plan.testnet_dir(), testnet);
    assert_eq!(plan.validator_bundle(), Some(bundle.as_path()));
    assert!(
        !root.exists(),
        "CLI planning must not probe or create paths"
    );
}

#[cfg(feature = "pq-proposer")]
#[test]
fn proposer_bundle_requires_the_narrow_http_surface() {
    let matches = lighthouse_pq_command()
        .try_get_matches_from([
            "lighthouse",
            "--testnet-dir",
            "public-testnet",
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--pq-validator-bundle",
            "private-bundle",
        ])
        .expect("syntactically valid PQ proposer CLI");

    assert_eq!(
        parse_pq_launch_cli(
            matches
                .subcommand_matches("beacon_node")
                .expect("beacon-node subcommand"),
        )
        .expect_err("a proposer without HTTP cannot serve its validator client"),
        PqLaunchCliError::ProposerRequiresHttp,
    );
}

#[test]
fn rejects_every_command_line_option_outside_the_positive_allowlist() {
    for (arguments, expected) in [
        (
            vec!["--http", "--http-allow-origin", "*"],
            "--http-allow-origin",
        ),
        (
            vec![
                "--http",
                "--http-tls-cert",
                "certificate.pem",
                "--http-tls-key",
                "key.pem",
                "--http-enable-tls",
            ],
            "--http-enable-tls",
        ),
        (vec!["--metrics"], "--metrics"),
        (
            vec!["--monitoring-endpoint", "https://monitor.invalid"],
            "--monitoring-endpoint",
        ),
        (vec!["--subscribe-all-subnets"], "--subscribe-all-subnets"),
        (
            vec![
                "--suggested-fee-recipient",
                "0x0000000000000000000000000000000000000000",
            ],
            "--suggested-fee-recipient",
        ),
        (vec!["--purge-db"], "--purge-db"),
    ] {
        let mut command_line = vec![
            "lighthouse",
            "--testnet-dir",
            "public-testnet",
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
        ];
        command_line.extend(arguments);
        let matches = lighthouse_pq_command()
            .try_get_matches_from(command_line)
            .expect("syntactically valid unsupported option");
        let error = parse_pq_launch_cli(
            matches
                .subcommand_matches("beacon_node")
                .expect("beacon-node subcommand"),
        )
        .expect_err("option outside the PQ launch allowlist");
        assert_eq!(error, PqLaunchCliError::UnsupportedOption(expected));
    }
}
