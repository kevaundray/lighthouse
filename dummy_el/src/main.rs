use clap::Parser;
use dummy_el::DummyElConfig;
use std::path::PathBuf;
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "8551", help = "Engine API port")]
    port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(long, help = "Path to JWT secret file (hex encoded)")]
    jwt_secret: Option<PathBuf>,

    #[arg(long, default_value = "8545", help = "HTTP RPC port")]
    rpc_port: u16,

    #[arg(long, default_value = "8546", help = "WebSocket port")]
    ws_port: u16,

    #[arg(long, default_value = "9001", help = "Metrics port")]
    metrics_port: u16,

    #[arg(long, default_value = "30303", help = "P2P discovery port (TCP/UDP)")]
    p2p_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let config = DummyElConfig {
        host: args.host,
        engine_port: args.port,
        rpc_port: args.rpc_port,
        ws_port: args.ws_port,
        metrics_port: args.metrics_port,
        p2p_port: args.p2p_port,
        jwt_secret_path: args.jwt_secret,
    };

    dummy_el::start_dummy_el(config).await
}
