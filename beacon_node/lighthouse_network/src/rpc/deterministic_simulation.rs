//! Regression for RPC quota accounting under virtual time.

use super::config::RateLimiterConfig;
use super::rate_limiter::{Quota, RPCRateLimiter, RateLimitedErr};
use super::{Ping, RequestType};
use libp2p::PeerId;
use std::sync::Arc;
use std::time::Duration;
use types::{EthSpec, ForkContext, Hash256, MainnetEthSpec, Slot};

fn fork_context() -> Arc<ForkContext> {
    Arc::new(ForkContext::new::<MainnetEthSpec>(
        Slot::new(0),
        Hash256::ZERO,
        &MainnetEthSpec::default_spec(),
    ))
}

fn peer(label: u8) -> PeerId {
    // A stable SHA-256 multihash peer identity; no key generation or OS entropy.
    let mut bytes = [label; 34];
    bytes[0] = 0x12;
    bytes[1] = 32;
    PeerId::from_bytes(&bytes).expect("fixed SHA-256 peer identity")
}

/// A timer waking on Tokio time must observe replenished quota on the same clock.
/// With std::Instant token accounting this fails after advancing only virtual time.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn quota_replenishes_on_virtual_time() {
    let mut limiter = RPCRateLimiter::new_with_config(
        RateLimiterConfig {
            ping_quota: Quota::one_every(60),
            ..Default::default()
        },
        fork_context(),
    )
    .expect("seed=0 event=configure quota");
    let request = RequestType::<MainnetEthSpec>::Ping(Ping { data: 0 });
    let peer = peer(1);
    assert!(
        limiter.allows(&peer, &request).is_ok(),
        "seed=0 event=initial token"
    );
    assert!(
        matches!(
            limiter.allows(&peer, &request),
            Err(RateLimitedErr::TooSoon(_))
        ),
        "seed=0 event=exhausted quota"
    );
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(
        limiter.allows(&peer, &request).is_ok(),
        "seed=0 event=quota replenishment after 60 virtual seconds"
    );
    assert!(
        matches!(
            limiter.allows(&peer, &request),
            Err(RateLimitedErr::TooSoon(_))
        ),
        "seed=0 event=replenished token consumed exactly once"
    );
}
