use clap::Parser;
use pq_devnet::{production_config, provision_devnet};
use std::path::PathBuf;
use std::process::ExitCode;

/// Provision the frozen Lighthouse Lean-PQ devnet V1 profile.
#[derive(Debug, Parser)]
#[command(name = "lcli-pq-devnet")]
struct Cli {
    /// Final devnet directory. An existing final or sibling staging path is rejected.
    #[arg(long)]
    output_dir: PathBuf,

    /// Path to a private 0600 file containing exactly 32 raw master-seed bytes.
    #[arg(long)]
    master_seed_file: PathBuf,

    /// Path to a private 0600 file containing the bounded keystore password.
    #[arg(long)]
    password_file: PathBuf,

    /// Execution-layer timestamp used to derive the consensus genesis time.
    #[arg(long)]
    eth1_timestamp: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = production_config(cli.output_dir, cli.eth1_timestamp);
    match provision_devnet(config, cli.master_seed_file, cli.password_file) {
        Ok(provisioned) => {
            println!(
                "PQ devnet written to {}",
                provisioned.output_dir().display()
            );
            println!(
                "genesis_validators_root=0x{}",
                hex::encode(provisioned.genesis_validators_root())
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("PQ devnet provisioning failed: {error}");
            ExitCode::FAILURE
        }
    }
}
