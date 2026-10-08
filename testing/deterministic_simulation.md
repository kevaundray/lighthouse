# Deterministic simulation: RPC quota clock

`RPCRateLimiter` must account for quota using the same monotonic clock as its Tokio pruning timer and delayed-request wakeups. Using `std::time::Instant` prevents quota from replenishing when a test advances Tokio virtual time, even though the queued-request timer expires.

The regression consumes a one-token quota, confirms the next request is rejected, advances 60 virtual seconds, and checks that exactly one token is available again:

```bash
cargo test -p lighthouse_network --lib \
  rpc::deterministic_simulation::quota_replenishes_on_virtual_time -- --exact --nocapture
```

The reproducer fails with the old clock at `quota replenishment after 60 virtual seconds`. The fix uses `tokio::time::Instant`; ordinary execution still uses monotonic time, while simulation uses the runtime's virtual clock.

This establishes simulation-clock incompatibility, not a demonstrated failure of normal wall-clock production traffic. A separate public-RPC smoke scenario also confirmed that a queued request is released after advancing 60 virtual seconds after the fix.
