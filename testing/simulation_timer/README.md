# Unbounded simulated request deadlines

This is a MadSim timer compatibility defect found by running the actual Lighthouse validator EventSource path. It is not a claimed production Lighthouse timeout failure.

MadSim `519950efb4711464f300ed7edf2967ed62d5f502` added every requested duration directly to an `Instant`. A `Duration::MAX` request timeout therefore panicked before an HTTP response could be observed. Tokio 1.53.2 instead uses a representable far-future deadline when addition overflows. Lighthouse's event-stream client legitimately uses an unbounded request deadline.

The case-first commit `3d0c91682` was observed failing with `overflow when adding duration to instant`. The immediately following fix uses checked deadline addition and Tokio's same approximately thirty-year fallback for unrepresentable deadlines. It does not change the EventSource request or special-case Lighthouse input.

```sh
make test-simulation-unbounded-timers
RUSTFLAGS='--cfg madsim --check-cfg=cfg(madsim)' \
  cargo check --locked --manifest-path testing/simulation_timer/Cargo.toml
cargo fmt --manifest-path testing/simulation_timer/Cargo.toml --check
```

Observed after the fix: `unbounded_sleep_reset_request_completion_and_finite_timeout=verified`. The case checks that the long sleep stays pending while a short timer completes, that resetting it restores a finite deadline, that an unbounded request can complete, and that ordinary finite timeouts still expire. A one-second virtual runtime limit bounds the fixture.

The standalone package shares the pinned, license-preserved simulator source introduced by the TCP lifecycle qualification. It leaves Lighthouse's production dependency graph unchanged. No whole-node replay claim follows from this timer case alone.
