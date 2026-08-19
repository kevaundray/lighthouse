#![cfg(feature = "pq-devnet")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn deferred_pq_cli_boundary_does_not_create_the_data_directory() {
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
        String::from_utf8_lossy(&output.stderr).contains(
            "lean PQ devnet networking, HTTP, timers, import and production are deferred"
        ),
        "binary should format the typed deferred boundary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !data_dir.exists(),
        "early PQ rejection must not create its configured data directory"
    );
}

fn path_text(path: &PathBuf) -> &str {
    path.to_str().expect("temporary directory path is UTF-8")
}
