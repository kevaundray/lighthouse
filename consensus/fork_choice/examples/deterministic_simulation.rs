#[path = "../tests/support/deterministic_simulation.rs"]
mod deterministic_simulation;

use deterministic_simulation::{Corpus, block_boundaries, replay, vote_boundaries};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let seed = args
        .next()
        .unwrap_or_else(|| "42".into())
        .parse::<u64>()
        .map_err(|error| format!("expected an unsigned integer seed: {error}"))?;
    if args.next().is_some() {
        return Err(format!(
            "seed={seed}: usage: deterministic_simulation [seed]"
        ));
    }
    let corpus = Corpus::build(seed).await?;
    // Fixture generation has finished. Everything below is synchronous logical-time execution.
    for line in replay(&corpus, seed)?
        .into_iter()
        .chain(vote_boundaries(&corpus, seed)?)
        .chain(block_boundaries(&corpus, seed)?)
    {
        println!("{line}");
    }
    Ok(())
}
