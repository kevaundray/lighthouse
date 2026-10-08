# TCP lifecycle qualification for whole-node simulation

These are defects in the selected **MadSim transport model**, not discovered Lighthouse protocol failures. The standalone package does not change Lighthouse's production dependency graph.

Upstream source: [madsim-rs/madsim](https://github.com/madsim-rs/madsim/tree/519950efb4711464f300ed7edf2967ed62d5f502), revision `519950efb4711464f300ed7edf2967ed62d5f502`, MadSim 0.2.34. The fixture uses two virtual IPv4 hosts and seed 42.

## Reproductions

```sh
make test-simulation-tcp-listener
make test-simulation-tcp-half-close
```

The case-first commit `e93e4ad02` runs against the unmodified pinned upstream dependency. Both commands were observed failing:

- **Listener ownership:** after dropping the listener while keeping its accepted stream alive, a fresh connect succeeds and rebinding fails with `AddrInUse`. The established stream still works, so this is not a general network outage.
- **Write-half shutdown:** `shutdown()` neither flushes buffered request bytes nor delivers EOF. The request/response exchange reaches its virtual timeout. The fixture also requires the read half to remain usable, repeated shutdown to succeed, and later writes to fail with `BrokenPipe`.

The immediately following fix commit retains the same cases and patches the pinned source under `testing/simulation/deps/madsim-0.2.34`:

- Listener registration is owned exclusively by the listener; accepted connections do not retain it.
- Established TCP traffic checks its source/destination node link independently of listener registration. Existing latency, loss and partition checks remain active.
- Write shutdown flushes and closes only the sending channel. Reading remains available until peer EOF.

The listener case additionally checks that an old connection survives rebinding and that dropping it cannot unregister the replacement listener.

## Verification

```sh
RUSTFLAGS='--cfg madsim --check-cfg=cfg(madsim)' \
  cargo check --locked --manifest-path testing/simulation_tcp_lifecycle/Cargo.toml
make test-simulation-tcp-lifecycle
cargo fmt --manifest-path testing/simulation_tcp_lifecycle/Cargo.toml --check
```

Observed after the fix: `listener_lifecycle=verified` and `half_close_flush_eof_response_and_write_rejection=verified`, both exit successfully.

This qualifies these stream-lifecycle boundaries only. It does not model kernel TCP buffering, congestion control, packet-level retransmission or instruction-level scheduling, and it is not whole-node replay proof. The vendored source retains its Apache-2.0 license; manifest-only adjustments preserve the pinned macro dependency and make the source package usable outside its original workspace.
