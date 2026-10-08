#[cfg(all(feature = "testing", not(madsim)))]
pub mod test_utils;

mod api_secret;
#[cfg(not(madsim))]
mod builder_config;
#[cfg(not(madsim))]
mod create_signed_voluntary_exit;
#[cfg(not(madsim))]
mod create_validator;
#[cfg(not(madsim))]
mod graffiti;
#[cfg(not(madsim))]
mod keystores;
#[cfg(not(madsim))]
mod remotekeys;
// Live validator management relies on native blocking coordination. Keep the
// default-off server out of simulation rather than substituting fake handlers.
#[cfg(not(madsim))]
mod server;
#[cfg(not(madsim))]
mod tests;

pub use api_secret::{ApiSecret, PK_FILENAME};
#[cfg(not(madsim))]
pub use server::{Context, Error, serve};

use directory::{DEFAULT_HARDCODED_NETWORK, DEFAULT_ROOT_DIR, DEFAULT_VALIDATOR_DIR};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub allow_keystore_export: bool,
    pub store_passwords_in_secrets_dir: bool,
    pub http_token_path: PathBuf,
    pub bn_long_timeouts: bool,
}

impl Default for Config {
    fn default() -> Self {
        // This value is always overridden when building config from CLI.
        let http_token_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK)
            .join(DEFAULT_VALIDATOR_DIR)
            .join(PK_FILENAME);
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 5062,
            allow_origin: None,
            allow_keystore_export: false,
            store_passwords_in_secrets_dir: false,
            http_token_path,
            bn_long_timeouts: false,
        }
    }
}
