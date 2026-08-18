#[cfg(not(feature = "pq-devnet"))]
mod bls_generator {
    include!("test_generator_bls.rs");
}

#[cfg(not(feature = "pq-devnet"))]
fn main() {
    bls_generator::run();
}

#[cfg(feature = "pq-devnet")]
fn main() {
    eprintln!("EIP-3076 test generation is unavailable in the PQ devnet profile");
}
