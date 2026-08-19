/// This crate provides the network server for Lighthouse.
#[cfg(not(feature = "pq-devnet"))]
pub mod service;

#[cfg(not(feature = "pq-devnet"))]
mod metrics;
#[cfg(not(feature = "pq-devnet"))]
mod nat;
#[cfg(not(feature = "pq-devnet"))]
mod network_beacon_processor;
#[cfg(not(feature = "pq-devnet"))]
mod persisted_dht;
#[cfg(feature = "pq-devnet")]
mod pq_runtime;
#[cfg(not(feature = "pq-devnet"))]
mod router;
#[cfg(not(feature = "pq-devnet"))]
mod status;
#[cfg(not(feature = "pq-devnet"))]
mod subnet_service;
#[cfg(not(feature = "pq-devnet"))]
mod sync;

pub use lighthouse_network::NetworkConfig;
#[cfg(not(feature = "pq-devnet"))]
pub use network_beacon_processor::NetworkBeaconProcessor;
#[cfg(feature = "pq-devnet")]
pub use pq_runtime::{PqGossipBlockDisposition, PqNetworkBlockProcessor};
#[cfg(not(feature = "pq-devnet"))]
pub use service::{
    NetworkMessage, NetworkReceivers, NetworkSenders, NetworkService, ValidatorSubscriptionMessage,
};
