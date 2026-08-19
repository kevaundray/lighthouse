use std::path::Path;
use std::process::Command;

#[test]
fn production_builder_has_no_raw_canonical_head_entry_point() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let output = Command::new(env!("CARGO"))
        .current_dir(&workspace_root)
        .env(
            "CARGO_TARGET_DIR",
            workspace_root.join("target/pq-api-privacy"),
        )
        .args([
            "check",
            "--locked",
            "--color",
            "never",
            "-p",
            "pq-raw-canonical-head-compile-fail",
            "--no-default-features",
            "--features",
            "compile-fail",
            "--bin",
            "raw-canonical-head-must-not-compile",
        ])
        .output()
        .expect("run the pinned compile-fail fixture");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "raw canonical-head fixture unexpectedly compiled:\n{stderr}"
    );
    assert!(
        stderr.contains("error[E0599]")
            && stderr.contains("no function or associated item named `canonical_head`"),
        "fixture failed for a reason other than the missing production API:\n{stderr}"
    );
}
