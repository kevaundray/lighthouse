use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

/// A delay driven by the current simulated node's clock, without a timer thread.
#[derive(Debug)]
pub struct Delay {
    sleep: Sleep,
}

impl Delay {
    /// Creates a future that completes after `duration` on the simulated clock.
    pub fn new(duration: Duration) -> Self {
        Self {
            sleep: tokio::time::sleep(duration),
        }
    }

    /// Restarts this delay relative to the current simulated time.
    pub fn reset(&mut self, duration: Duration) {
        Pin::new(&mut self.sleep).reset(Instant::now() + duration);
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.sleep).poll(cx)
    }
}
