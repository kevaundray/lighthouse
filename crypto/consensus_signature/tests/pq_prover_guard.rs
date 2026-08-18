#![cfg(all(
    feature = "pq-devnet",
    target_arch = "x86_64",
    not(target_feature = "avx2")
))]

use consensus_signature::pq::{PqProver, ProverError, ProverUnavailable};

#[test]
fn pq_prover_refuses_a_build_without_avx2() {
    assert!(matches!(
        PqProver::new(),
        Err(ProverError::Unavailable(
            ProverUnavailable::Avx2NotEnabledAtCompileTime
        ))
    ));
}
