#![cfg(feature = "pq-devnet")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn valid_pq_launch_paths_reach_only_the_deferred_runtime_boundary() {
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

    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&data_dir)])
        .args(["--testnet-dir", path_text(&testnet_dir)])
        .args([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
        ])
        .output()
        .expect("run the PQ Lighthouse binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "lean PQ devnet network-service assembly, HTTP, timers and validator duties are deferred"
        ),
        "binary should retain the typed deferred runtime boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.exists(), "pure launch parsing must not create paths");
}

#[cfg(feature = "pq-proposer")]
#[test]
fn proposer_bundle_path_reaches_only_the_deferred_runtime_boundary() {
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

    let output = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
        .args(["--datadir", path_text(&data_dir)])
        .args(["--testnet-dir", path_text(&testnet_dir)])
        .args([
            "beacon_node",
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--http",
            "--pq-validator-bundle",
            path_text(&bundle_dir),
        ])
        .output()
        .expect("run the PQ proposer Lighthouse binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "lean PQ devnet network-service assembly, HTTP, timers and validator duties are deferred"
        ),
        "binary should retain the typed deferred runtime boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.exists(), "pure launch parsing must not create paths");
}

fn path_text(path: &PathBuf) -> &str {
    path.to_str().expect("temporary directory path is UTF-8")
}
