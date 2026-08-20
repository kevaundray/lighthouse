# Vendored libp2p gossipsub

This directory vendors `protocols/gossipsub` version `0.50.0` from Sigma Prime's
`rust-libp2p` fork at exact revision
`c774d4e71357d7cd2f792c4767d616d2dd369ee3`:

<https://github.com/sigp/rust-libp2p/tree/c774d4e71357d7cd2f792c4767d616d2dd369ee3/protocols/gossipsub>

The root `LICENSE` from that revision is retained verbatim in this directory. The crate remains
MIT licensed. It is deliberately excluded from the Lighthouse workspace and selected only by the
exact source patch in the root `Cargo.toml`.

## Lighthouse changes

The patch is intentionally limited to the PQ beacon-block ingress and publication boundaries:

- an optional source-aware admission callback runs after inbound transform/message-ID calculation
  but before ordinary duplicate-cache and message-cache insertion;
- admitted messages live in a separate bounded pending map and have typed retryable, terminal,
  accepted, and commit-without-repropagation outcomes;
- an accepted admission returns a sealed commit capability, retaining its admission guard until
  the network owner resolves detached Engine/DB work;
- retryable resolution removes the exact duplicate-cache, message-cache, every matching heartbeat
  history entry, and bounded-admission history entry, while terminal/committed resolution retains
  them;
- optional local-publish recipient filtering lets Lighthouse select only peers authenticated by
  the PQ Status exchange; and
- when bounded PQ admission is configured, local publish commits duplicate/message-cache history
  only after an eligible peer queue accepts; `AllQueuesFull` therefore releases only its bounded
  validation-history reservation and leaves no stale heartbeat entry that could evict a later exact
  retry. With admission disabled, the exact upstream cache-before-queue and Duplicate-on-retry
  behavior is preserved.

Both optional callbacks default to `None`. With those defaults, ordinary Lighthouse/default
gossipsub admission and recipient selection follow the upstream path.

## Updating

1. Fetch the intended `sigp/rust-libp2p` revision and record the full commit hash.
2. Replace this directory with that revision's `protocols/gossipsub` contents and copy its root
   `LICENSE` here verbatim.
3. Recreate the standalone dependency declarations in `Cargo.toml` from the upstream workspace
   dependency versions, without broadening them or adding the vendor crate to workspace members.
4. Reapply the small Lighthouse patch described above and update this provenance record.
5. Update the exact root source patch and regenerate `Cargo.lock`. Confirm that unrelated package
   versions do not change.
6. Run the vendor admission/default tests and the Lighthouse PQ/default network gates below.

## Focused verification

```text
RUSTFLAGS='-D warnings' cargo +1.88 test --manifest-path vendor/libp2p-gossipsub/Cargo.toml validation_admission
RUSTFLAGS='-D warnings' cargo +1.88 test --manifest-path vendor/libp2p-gossipsub/Cargo.toml all_queues_full_rolls_back_exact_local_admission_and_cache_state
RUSTFLAGS='-D warnings' cargo +1.88 test --manifest-path vendor/libp2p-gossipsub/Cargo.toml publish_uses_only_the_exact_application_eligible_recipient_set
RUSTFLAGS='-D warnings' cargo +1.88 test --manifest-path vendor/libp2p-gossipsub/Cargo.toml --no-run
RUSTFLAGS='-D warnings' cargo +1.88 test -p lighthouse_network --no-default-features --features pq-devnet --test lighthouse_network_tests
RUSTFLAGS='-D warnings' cargo +1.88 check -p lighthouse_network
cargo +1.88 metadata --locked --no-deps --format-version=1
```

The vendor tests pin the optional-default regression, bounded 16-remote/1-local/17-window history,
pending expiry, typed commit retention/release, recipient filtering, and queue-full rollback. The
Lighthouse tests pin the shared Status-compatible peer set and exact lower-network publication
behavior.
