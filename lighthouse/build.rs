// This is also a stub for determining the build profile, see `build_profile_name`.
fn main() {
    let enabled = |feature: &str| std::env::var_os(feature).is_some();
    if enabled("CARGO_FEATURE_PQ_DEVNET")
        && [
            "CARGO_FEATURE_FULL_CLI",
            "CARGO_FEATURE_BEACON_NODE_RUNTIME",
            "CARGO_FEATURE_SLASHER_LMDB",
            "CARGO_FEATURE_SLASHER_MDBX",
            "CARGO_FEATURE_SLASHER_REDB",
            "CARGO_FEATURE_LIGHTHOUSE_INTEGRATION_TESTS",
        ]
        .into_iter()
        .any(enabled)
    {
        panic!(
            "pq-devnet is a beacon-node-only startup profile and is incompatible with full-cli, \
             beacon-node-runtime, slasher backend features, and lighthouse-integration-tests"
        );
    }
}
