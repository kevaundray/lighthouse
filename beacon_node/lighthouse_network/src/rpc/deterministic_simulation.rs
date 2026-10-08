//! Deterministic component tests, not a simulated libp2p transport or whole node.
//! Queue residence metrics use wall time and are deliberately absent from semantic traces.

use super::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig, RateLimiterConfig};
use super::rate_limiter::{Quota, RPCRateLimiter, RateLimitedErr};
use super::response_limiter::{QueuedResponse, ResponseLimiter};
use super::self_limiter::SelfRateLimiter;
use super::{
    BehaviourAction, MAX_CONCURRENT_REQUESTS, Ping, Protocol, RPCSend, RequestType, RpcResponse,
    RpcSuccessResponse, SubstreamId,
};
use futures::task::noop_waker;
use libp2p::{PeerId, swarm::ConnectionId};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::task::{Context, Poll};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Queued,
    Active,
    Completed,
    Cancelled,
    // The limiter does not own active transport cancellation. We stop delivering that
    // connection's completions, just as the connection owner must on reconnection.
    Detached,
    Sent,
    Dropped,
}

#[derive(Debug)]
struct Work {
    peer: u8,
    generation: usize,
    outcome: Outcome,
}

#[derive(Debug)]
enum Event {
    Burst {
        peer: u8,
        generation: usize,
        count: usize,
    },
    Disconnect,
    Complete(usize),
}

struct Simulation {
    seed: u64,
    rng: ChaCha20Rng,
    now: u64,
    sequence: usize,
    events: BTreeMap<(u64, usize), Event>,
    trace: Vec<String>,
    requests: BTreeMap<usize, Work>,
    responses: BTreeMap<usize, Work>,
    outbound: SelfRateLimiter<usize, MainnetEthSpec>,
    inbound: ResponseLimiter<MainnetEthSpec>,
    last_request: [Option<u64>; 2],
    last_response: [Option<u64>; 2],
    last_request_id: [Option<usize>; 2],
    last_response_id: [Option<usize>; 2],
    concurrency_gate_observed: bool,
}

impl Simulation {
    fn new(seed: u64) -> Self {
        let config = RateLimiterConfig {
            ping_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        };
        let mut sim = Self {
            seed,
            rng: ChaCha20Rng::seed_from_u64(seed),
            now: 0,
            sequence: 0,
            events: BTreeMap::new(),
            trace: vec![],
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            outbound: SelfRateLimiter::new(
                Some(OutboundRateLimiterConfig(config.clone())),
                fork_context(),
            )
            .unwrap_or_else(|e| panic!("seed={seed} event=configure outbound: {e}")),
            inbound: ResponseLimiter::new(InboundRateLimiterConfig(config), fork_context())
                .unwrap_or_else(|e| panic!("seed={seed} event=configure inbound: {e}")),
            last_request: [None; 2],
            last_response: [None; 2],
            last_request_id: [None; 2],
            last_response_id: [None; 2],
            concurrency_gate_observed: false,
        };
        let first_burst = sim.rng.random_range(4..=7);
        let independent_burst = sim.rng.random_range(5..=8);
        let independent_arrival = sim.rng.random_range(1..=2) * 10;
        let disconnect = sim.rng.random_range(4..=7) * 10;
        let recovered_burst = sim.rng.random_range(3..=5);
        sim.schedule(
            0,
            Event::Burst {
                peer: 0,
                generation: 0,
                count: first_burst,
            },
        );
        sim.schedule(
            independent_arrival,
            Event::Burst {
                peer: 1,
                generation: 0,
                count: independent_burst,
            },
        );
        sim.schedule(disconnect, Event::Disconnect);
        // Reconnect before the old connection's 100ms timer expires. Old and new
        // timer entries may now refer to the same peer/protocol, but not old work.
        sim.schedule(
            disconnect + 10,
            Event::Burst {
                peer: 0,
                generation: 1,
                count: recovered_burst,
            },
        );
        sim
    }

    fn record(&mut self, event: impl std::fmt::Debug) {
        let line = format!("seed={} t={} {event:?}", self.seed, self.now);
        if std::env::var_os("LIGHTHOUSE_SIMULATION_SEED").is_some() {
            eprintln!("{line}");
        }
        self.trace.push(line);
    }

    fn schedule(&mut self, time: u64, event: Event) {
        self.events.insert((time, self.sequence), event);
        self.sequence += 1;
    }

    fn active(&self, label: u8) -> usize {
        self.requests
            .values()
            .filter(|work| work.peer == label && work.outcome == Outcome::Active)
            .count()
    }

    fn sent_request(&mut self, label: u8, id: usize, request: RequestType<MainnetEthSpec>) {
        assert!(
            matches!(request, RequestType::Ping(Ping { data }) if data == id as u64),
            "seed={} event=request payload id={id}",
            self.seed
        );
        let work = self.requests.get_mut(&id).unwrap();
        assert_eq!(
            work.peer, label,
            "seed={} event=request peer id={id}",
            self.seed
        );
        assert_eq!(
            work.outcome,
            Outcome::Queued,
            "seed={} event=duplicate or resurrected request id={id} t={}",
            self.seed,
            self.now
        );
        work.outcome = Outcome::Active;
        assert!(
            self.active(label) <= MAX_CONCURRENT_REQUESTS,
            "seed={} event=concurrency exceeded peer={label} t={}",
            self.seed,
            self.now
        );
        let index = usize::from(label);
        if let Some(previous) = self.last_request[index] {
            assert!(
                self.now - previous >= 100,
                "seed={} event=request quota exceeded peer={label} t={}",
                self.seed,
                self.now
            );
        }
        if let Some(previous) = self.last_request_id[index] {
            // With a one-token quota each wakeup admits only one request. This
            // checks queued order without claiming FIFO for multi-token ready batches.
            assert!(
                id > previous,
                "seed={} event=request order id={id}",
                self.seed
            );
        }
        self.last_request[index] = Some(self.now);
        self.last_request_id[index] = Some(id);
        self.record(("request sent", label, id));
        let delay = self.rng.random_range(25..=35) * 10;
        self.schedule(self.now + delay, Event::Complete(id));
    }

    fn sent_response(&mut self, label: u8, id: usize) {
        let work = self.responses.get_mut(&id).unwrap();
        assert_eq!(
            work.peer, label,
            "seed={} event=response peer id={id}",
            self.seed
        );
        assert_eq!(
            work.outcome,
            Outcome::Queued,
            "seed={} event=duplicate or resurrected response id={id} t={}",
            self.seed,
            self.now
        );
        work.outcome = Outcome::Sent;
        let index = usize::from(label);
        if let Some(previous) = self.last_response[index] {
            assert!(
                self.now - previous >= 100,
                "seed={} event=response quota exceeded peer={label} t={}",
                self.seed,
                self.now
            );
        }
        if let Some(previous) = self.last_response_id[index] {
            assert!(
                id > previous,
                "seed={} event=response FIFO id={id}",
                self.seed
            );
        }
        self.last_response[index] = Some(self.now);
        self.last_response_id[index] = Some(id);
        self.record(("response sent", label, id));
    }

    fn burst(&mut self, label: u8, generation: usize, count: usize) {
        for _ in 0..count {
            let id = self.requests.len();
            self.requests.insert(
                id,
                Work {
                    peer: label,
                    generation,
                    outcome: Outcome::Queued,
                },
            );
            self.responses.insert(
                id,
                Work {
                    peer: label,
                    generation,
                    outcome: Outcome::Queued,
                },
            );
            match self
                .outbound
                .allows(peer(label), id, RequestType::Ping(Ping { data: id as u64 }))
            {
                Ok(RPCSend::Request(sent_id, request)) => {
                    self.sent_request(label, sent_id, request)
                }
                Ok(other) => panic!(
                    "seed={} event=unexpected immediate output {other:?}",
                    self.seed
                ),
                Err(_) => self.record(("request queued", label, id)),
            }
            if self.inbound.allows(
                peer(label),
                Protocol::Ping,
                ConnectionId::new_unchecked(generation * 2 + usize::from(label)),
                SubstreamId::new(id),
                RpcResponse::Success(RpcSuccessResponse::Pong(Ping { data: id as u64 })),
            ) {
                self.sent_response(label, id);
            } else {
                self.record(("response queued", label, id));
            }
        }
    }

    fn disconnect(&mut self) {
        let expected: Vec<_> = self
            .requests
            .iter()
            .filter(|(_, work)| work.peer == 0 && work.outcome == Outcome::Queued)
            .map(|(id, _)| *id)
            .collect();
        let mut cancelled = self.outbound.peer_disconnected(peer(0));
        assert!(
            cancelled
                .iter()
                .all(|(_, protocol)| *protocol == Protocol::Ping),
            "seed={} event=cancel protocol",
            self.seed
        );
        // The API returns a set of failures, not an ordering contract.
        cancelled.sort_unstable_by_key(|(id, _)| *id);
        assert_eq!(
            cancelled.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            expected,
            "seed={} event=exactly-once queued cancellation",
            self.seed
        );
        for id in expected {
            self.requests.get_mut(&id).unwrap().outcome = Outcome::Cancelled;
            self.record(("request cancelled", id));
        }
        for work in self.requests.values_mut() {
            if work.peer == 0 && work.outcome == Outcome::Active {
                work.outcome = Outcome::Detached;
            }
        }
        assert!(
            self.outbound.peer_disconnected(peer(0)).is_empty(),
            "seed={} event=repeated disconnect cannot duplicate failures",
            self.seed
        );
        self.inbound.peer_disconnected(peer(0));
        let dropped: Vec<_> = self
            .responses
            .iter()
            .filter(|(_, work)| work.peer == 0 && work.outcome == Outcome::Queued)
            .map(|(id, _)| *id)
            .collect();
        for id in dropped {
            self.responses.get_mut(&id).unwrap().outcome = Outcome::Dropped;
            self.record(("response dropped", id));
        }
    }

    fn complete(&mut self, id: usize) {
        let work = self.requests.get_mut(&id).unwrap();
        match work.outcome {
            Outcome::Active => {
                work.outcome = Outcome::Completed;
                self.outbound
                    .request_completed(&peer(work.peer), Protocol::Ping);
                self.record(("request completed", id));
            }
            Outcome::Detached => {
                // request_completed has no connection or request ID. Connection
                // ownership/late callback suppression is explicitly outside this test.
                self.record(("old connection completion withheld", id));
            }
            outcome => panic!(
                "seed={} event=invalid completion id={id} {outcome:?}",
                self.seed
            ),
        }
    }

    fn receive_response(&mut self, response: QueuedResponse<MainnetEthSpec>) {
        let RpcResponse::Success(RpcSuccessResponse::Pong(Ping { data })) = response.response
        else {
            panic!("seed={} event=unexpected response", self.seed);
        };
        let id = usize::try_from(data).unwrap();
        let work = self.responses.get(&id).unwrap();
        assert_eq!(
            response.peer_id,
            peer(work.peer),
            "seed={} event=queued response peer id={id}",
            self.seed
        );
        assert_eq!(
            response.connection_id,
            ConnectionId::new_unchecked(work.generation * 2 + usize::from(work.peer)),
            "seed={} event=queued response connection id={id}",
            self.seed
        );
        assert_eq!(
            response.substream_id,
            SubstreamId::new(id),
            "seed={} event=queued response substream id={id}",
            self.seed
        );
        assert_eq!(
            response.protocol,
            Protocol::Ping,
            "seed={} event=response protocol",
            self.seed
        );
        self.sent_response(work.peer, id);
    }

    fn poll(&mut self) {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        // SelfRateLimiter may consume a stale timer and return Pending even with
        // another timer ready. A fixed poll budget exercises those real timers
        // without calling private readiness callbacks or risking an unbounded loop.
        for _ in 0..32 {
            if let Poll::Ready(output) = self.outbound.poll_ready(&mut cx) {
                match output {
                    BehaviourAction::NotifyHandler {
                        peer_id,
                        event: RPCSend::Request(id, request),
                        ..
                    } => {
                        let label = self.requests.get(&id).unwrap().peer;
                        assert_eq!(
                            peer_id,
                            peer(label),
                            "seed={} event=outbound peer",
                            self.seed
                        );
                        self.sent_request(label, id, request);
                    }
                    other => panic!(
                        "seed={} event=unexpected queued output {other:?}",
                        self.seed
                    ),
                }
            }
            if let Poll::Ready(responses) = self.inbound.poll_ready(&mut cx) {
                for response in responses {
                    self.receive_response(response);
                }
            }
        }
    }

    async fn run(mut self) -> Vec<String> {
        for tick in 0..=300 {
            self.now = tick * 10;
            if tick != 0 {
                tokio::time::advance(Duration::from_millis(10)).await;
                tokio::task::yield_now().await;
            }
            while self
                .events
                .first_key_value()
                .is_some_and(|((time, _), _)| *time <= self.now)
            {
                let ((_, sequence), event) = self.events.pop_first().unwrap();
                self.record(("input", sequence, &event));
                match event {
                    Event::Burst {
                        peer,
                        generation,
                        count,
                    } => self.burst(peer, generation, count),
                    Event::Disconnect => self.disconnect(),
                    Event::Complete(id) => self.complete(id),
                }
            }
            self.poll();
            if self.now == 230 {
                // Peer B has two active requests, and quota is replenished for a
                // third, but neither delayed completion has arrived. Removing the
                // concurrency check must fail this assertion (or active bound).
                assert_eq!(
                    self.active(1),
                    2,
                    "seed={} event=delayed completion gate",
                    self.seed
                );
                assert!(
                    self.requests
                        .values()
                        .any(|w| w.peer == 1 && w.outcome == Outcome::Queued),
                    "seed={} event=concurrency-gated work retained",
                    self.seed
                );
                self.concurrency_gate_observed = true;
            }
            if self.now == 140 {
                // A's disconnect and still-blocked recovery must not stall B.
                assert_eq!(
                    self.active(1),
                    2,
                    "seed={} event=independent peer progress",
                    self.seed
                );
                assert_eq!(
                    self.responses
                        .values()
                        .filter(|w| w.peer == 1 && w.outcome == Outcome::Sent)
                        .count(),
                    2,
                    "seed={} event=independent response progress",
                    self.seed
                );
            }
        }
        assert!(
            self.events.is_empty(),
            "seed={} event=bounded event recovery",
            self.seed
        );
        assert!(
            self.concurrency_gate_observed,
            "seed={} event=gate coverage",
            self.seed
        );
        for (id, work) in &self.requests {
            let expected = if work.peer == 0 && work.generation == 0 {
                if *id == 0 {
                    Outcome::Detached
                } else {
                    Outcome::Cancelled
                }
            } else {
                Outcome::Completed
            };
            assert_eq!(
                work.outcome, expected,
                "seed={} event=terminal request accounting id={id}",
                self.seed
            );
        }
        for (id, work) in &self.responses {
            let expected = if work.peer == 0 && work.generation == 0 && *id != 0 {
                Outcome::Dropped
            } else {
                Outcome::Sent
            };
            assert_eq!(
                work.outcome, expected,
                "seed={} event=terminal response accounting id={id}",
                self.seed
            );
        }
        for label in 0..2 {
            assert!(
                self.outbound.peer_disconnected(peer(label)).is_empty(),
                "seed={} event=no stranded request queue peer={label}",
                self.seed
            );
        }
        // An empty response queue must be removed, not left as a tombstone that
        // silently queues fresh traffic forever after the old timers are gone.
        for label in 0..2 {
            let id = self.responses.len() + usize::from(label);
            assert!(
                self.inbound.allows(
                    peer(label),
                    Protocol::Ping,
                    ConnectionId::new_unchecked(10 + usize::from(label)),
                    SubstreamId::new(id),
                    RpcResponse::Success(RpcSuccessResponse::Pong(Ping { data: id as u64 })),
                ),
                "seed={} event=response queue cleanup peer={label}",
                self.seed
            );
            self.record(("fresh response after queue drain", label, id));
        }
        self.record("all queued work terminal; old active transport work excluded");
        self.trace
    }
}

fn replay(seed: u64) -> Vec<String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| panic!("seed={seed} event=runtime: {e}"))
        .block_on(async { Simulation::new(seed).run().await })
}

/// Fault model: burst overload plus delayed completions, a disconnect while queued,
/// stale timer expiry after reconnect, and recovery using fresh request/stream IDs.
/// Protects against quota bypass, concurrency oversubscription, cross-peer blocking,
/// duplicate/missing outcomes and disconnected work being resurrected.
#[test]
fn seeded_rpc_lifecycle_replays() {
    let seeds = match std::env::var("LIGHTHOUSE_SIMULATION_SEED") {
        Ok(value) => vec![
            value
                .parse::<u64>()
                .expect("LIGHTHOUSE_SIMULATION_SEED must be a decimal u64"),
        ],
        Err(std::env::VarError::NotPresent) => vec![0, 1, 7, 42, 0x5eed, u64::MAX],
        Err(error) => panic!("invalid LIGHTHOUSE_SIMULATION_SEED: {error}"),
    };
    for seed in seeds {
        assert_eq!(
            replay(seed),
            replay(seed),
            "seed={seed} event=independent semantic replay"
        );
    }
}

/// A single timer can admit a batch into the ready buffer. Disconnect must cancel
/// both the buffered-but-unemitted request and work still blocked by concurrency,
/// without claiming to cancel the request already emitted to the transport.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn disconnect_cancels_ready_and_delayed_work() {
    let mut limiter = SelfRateLimiter::<usize, MainnetEthSpec>::new(None, fork_context())
        .expect("seed=0 event=configure ready cancellation");
    for id in 0..5 {
        let result = limiter.allows(peer(0), id, RequestType::Ping(Ping { data: id as u64 }));
        assert_eq!(result.is_ok(), id < 2, "seed=0 event=initial burst id={id}");
    }
    limiter.request_completed(&peer(0), Protocol::Ping);
    limiter.request_completed(&peer(0), Protocol::Ping);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        limiter.poll_ready(&mut cx).is_pending(),
        "seed=0 event=timer not elapsed"
    );
    tokio::time::advance(Duration::from_millis(110)).await;
    tokio::task::yield_now().await;
    let emitted = match limiter.poll_ready(&mut cx) {
        Poll::Ready(BehaviourAction::NotifyHandler {
            peer_id,
            event: RPCSend::Request(id, _),
            ..
        }) => {
            assert_eq!(peer_id, peer(0), "seed=0 event=ready peer");
            assert!(
                [2, 3].contains(&id),
                "seed=0 event=oldest queued batch admitted id={id}"
            );
            id
        }
        other => panic!("seed=0 event=ready batch after real timer: {other:?}"),
    };
    let mut cancelled = limiter.peer_disconnected(peer(0));
    cancelled.sort_unstable_by_key(|(id, _)| *id);
    let expected: Vec<_> = (2..5)
        .filter(|id| *id != emitted)
        .map(|id| (id, Protocol::Ping))
        .collect();
    assert_eq!(
        cancelled, expected,
        "seed=0 event=ready and delayed cancellation"
    );
    assert!(
        limiter.peer_disconnected(peer(0)).is_empty(),
        "seed=0 event=duplicate cancellation"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    for event in 0..8 {
        assert!(
            limiter.poll_ready(&mut cx).is_pending(),
            "seed=0 event=stale timer {event}"
        );
    }
    assert!(
        matches!(
            limiter.allows(peer(0), 5, RequestType::Ping(Ping { data: 5 })),
            Ok(RPCSend::Request(5, _))
        ),
        "seed=0 event=fresh request after disconnected ready batch"
    );
}
