fn main() {
    let full_runtime = std::env::var_os("CARGO_FEATURE_FULL_RUNTIME").is_some();
    let pq_devnet = std::env::var_os("CARGO_FEATURE_PQ_DEVNET").is_some();

    match (full_runtime, pq_devnet) {
        (true, false) | (false, true) => {}
        (false, false) => panic!(
            "beacon_node requires exactly one runtime profile: enable full-runtime or pq-devnet"
        ),
        (true, true) => {
            panic!("beacon_node runtime profiles full-runtime and pq-devnet are mutually exclusive")
        }
    }
}
