use std::{future::pending, time::Duration};
use tokio::time::{sleep, timeout, Instant};

fn main() {
    let mut runtime = madsim::runtime::Runtime::with_seed_and_config(42, Default::default());
    runtime.set_time_limit(Duration::from_secs(1));
    runtime.block_on(async {
        // EventSource requests use Duration::MAX to disable their request deadline.
        let long_sleep = sleep(Duration::MAX);
        tokio::pin!(long_sleep);
        tokio::select! {
            _ = &mut long_sleep => panic!("unbounded deadline expired before a finite timer"),
            _ = sleep(Duration::from_millis(20)) => {},
        }

        let reset_at = Instant::now() + Duration::from_millis(30);
        long_sleep.as_mut().reset(reset_at);
        long_sleep.await;
        assert!(Instant::now() >= reset_at);
        assert!(Instant::now() - reset_at < Duration::from_millis(1));

        let response = timeout(Duration::MAX, async {
            sleep(Duration::from_millis(20)).await;
            "response completed"
        })
        .await
        .expect("an unbounded request timed out");
        assert_eq!(response, "response completed");
        assert!(timeout(Duration::from_millis(5), pending::<()>())
            .await
            .is_err());
        println!("unbounded_sleep_reset_request_completion_and_finite_timeout=verified");
    });
}
