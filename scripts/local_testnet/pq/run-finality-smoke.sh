#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
log_dir="${PQ_FINALITY_LOG_DIR:-${repo_root}/target/pq-finality-logs}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_path="${log_dir}/two-process-slot32-${timestamp}.log"

mkdir -p -- "${log_dir}"
cd -- "${repo_root}"

unset PQ_E4F_VERIFIER_ONLY_DIAGNOSTIC

echo "Writing the two-process PQ finality trace to ${log_path}"
RUSTFLAGS="-D warnings -C target-feature=+avx2" \
    cargo +1.88 test \
        -p lighthouse \
        --no-default-features \
        --features pq-proposer,pq-startup-testing \
        --test pq_e4f_launch \
        two_real_processes_finalize_epoch_two_at_slot_32 \
        -- --exact --ignored --nocapture \
    2>&1 | tee "${log_path}"
