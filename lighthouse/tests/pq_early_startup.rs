#![cfg(feature = "pq-devnet")]

use clap::{Arg, ArgAction, Command as ClapCommand};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn pq_launch_config_is_built_purely_from_the_positive_cli_profile() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-pure-launch-config-{}-{unique}",
        std::process::id()
    ));
    let jwt = root.join("jwt.hex");
    let testnet = root.join("testnet");
    let matches = ClapCommand::new("lighthouse")
        .arg(
            Arg::new("datadir")
                .long("datadir")
                .action(ArgAction::Set)
                .global(true),
        )
        .arg(
            Arg::new("testnet-dir")
                .long("testnet-dir")
                .action(ArgAction::Set)
                .global(true),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .action(ArgAction::Set)
                .global(true),
        )
        .subcommand(beacon_node::cli_app())
        .try_get_matches_from([
            "lighthouse",
            "--testnet-dir",
            path_text(&testnet),
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt",
            path_text(&jwt),
            "--http",
            "--http-address",
            "0.0.0.0",
            "--zero-ports",
        ])
        .expect("syntactically valid PQ launch arguments");
    let matches = matches
        .subcommand_matches("beacon_node")
        .expect("beacon-node subcommand");

    let config = beacon_node::build_pq_runtime_config(&matches)
        .expect("positive PQ arguments should build an opaque runtime config");
    let debug = format!("{config:?}");
    assert!(debug.contains(path_text(&testnet)));
    assert!(debug.contains("tcp_port: 0"));
    assert!(debug.contains("disc_port: 0"));
    assert!(debug.contains("quic_port: 0"));
    let http_config = debug
        .split("http_api: PqHttpApiConfig")
        .nth(1)
        .expect("debug output contains the sealed PQ HTTP configuration")
        .split('}')
        .next()
        .expect("bounded HTTP configuration debug section");
    assert!(
        http_config.contains("listen_port: 0"),
        "--zero-ports must override the clap default HTTP port: {http_config}",
    );
    assert!(!debug.contains("addr: ::"));
    assert!(!root.exists(), "pure config building must perform no I/O");
}

#[test]
fn pq_launch_config_rejects_enr_hostnames_instead_of_resolving_them() {
    let matches = ClapCommand::new("lighthouse")
        .arg(
            Arg::new("datadir")
                .long("datadir")
                .action(ArgAction::Set)
                .global(true),
        )
        .arg(
            Arg::new("testnet-dir")
                .long("testnet-dir")
                .action(ArgAction::Set)
                .global(true),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .action(ArgAction::Set)
                .global(true),
        )
        .subcommand(beacon_node::cli_app())
        .try_get_matches_from([
            "lighthouse",
            "--testnet-dir",
            "/unread/testnet",
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt",
            "/unread/jwt.hex",
            "--enr-address",
            "localhost",
        ])
        .expect("syntactically valid PQ launch arguments");
    let matches = matches
        .subcommand_matches("beacon_node")
        .expect("beacon-node subcommand");

    let error = match beacon_node::build_pq_runtime_config(matches) {
        Err(error) => error,
        Ok(_) => panic!("PQ config parsing must never resolve ENR hostnames"),
    };
    assert!(error.to_string().contains("literal IP address"));
}

#[test]
fn pq_cli_requires_a_public_testnet_before_creating_the_data_directory() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let data_dir = std::env::temp_dir().join(format!(
        "lighthouse-pq-early-startup-{}-{unique}",
        std::process::id()
    ));
    assert!(!data_dir.exists(), "test data directory must start absent");

    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&data_dir), "beacon_node"])
        .args(["--execution-endpoint", "http://127.0.0.1:8551"])
        .output()
        .expect("run the PQ Lighthouse binary");

    assert!(
        !output.status.success(),
        "the staged runtime must be deferred"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("lean PQ devnet V1 requires --testnet-dir"),
        "binary should format the typed missing-testnet boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !data_dir.exists(),
        "early PQ rejection must not create its configured data directory"
    );
}

#[test]
fn valid_pq_launch_paths_enter_async_runtime_and_bounded_public_loading() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-launch-boundary-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet_dir = root.join("testnet");
    let jwt = std::env::temp_dir().join(format!(
        "lighthouse-pq-launch-jwt-{}-{unique}",
        std::process::id()
    ));
    std::fs::write(&jwt, "11".repeat(32)).expect("write isolated JWT fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&data_dir)])
        .args(["--testnet-dir", path_text(&testnet_dir)])
        .args([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt",
            path_text(&jwt),
        ])
        .output()
        .expect("run the PQ Lighthouse binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not read"),
        "binary should enter bounded public testnet loading: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.exists(), "pure launch parsing must not create paths");
    std::fs::remove_file(jwt).expect("remove JWT fixture");
}

#[cfg(feature = "pq-proposer")]
#[test]
fn proposer_bundle_path_enters_async_runtime_before_bundle_authentication() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-proposer-launch-boundary-{}-{unique}",
        std::process::id()
    ));
    let data_dir = root.join("node");
    let testnet_dir = root.join("testnet");
    let bundle_dir = root.join("bundle");
    let jwt = std::env::temp_dir().join(format!(
        "lighthouse-pq-proposer-jwt-{}-{unique}",
        std::process::id()
    ));
    std::fs::write(&jwt, "11".repeat(32)).expect("write isolated JWT fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&data_dir)])
        .args(["--testnet-dir", path_text(&testnet_dir)])
        .args([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt",
            path_text(&jwt),
            "--http",
            "--pq-validator-bundle",
            path_text(&bundle_dir),
        ])
        .output()
        .expect("run the PQ proposer Lighthouse binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not read"),
        "binary should load the sealed public testnet before bundle authentication: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.exists(), "pure launch parsing must not create paths");
    std::fs::remove_file(jwt).expect("remove JWT fixture");
}

#[test]
fn pq_cli_rejects_inline_jwt_secret_before_filesystem_io() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "lighthouse-pq-inline-jwt-{}-{unique}",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&root.join("node"))])
        .args(["--testnet-dir", path_text(&root.join("testnet"))])
        .args([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt-secret-key",
            &"11".repeat(32),
        ])
        .output()
        .expect("run the PQ Lighthouse binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--execution-jwt-secret-key"),
        "inline secret rejection should name the unsupported option: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !root.exists(),
        "pure rejection must not create launch paths"
    );
}

fn path_text(path: &PathBuf) -> &str {
    path.to_str().expect("temporary directory path is UTF-8")
}
