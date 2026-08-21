use crate::peer_manager::config::DEFAULT_TARGET_PEERS;
use crate::rpc::config::{InboundRateLimiterConfig, OutboundRateLimiterConfig};
use crate::types::GossipKind;
use crate::{Enr, PeerIdSerialized};
use directory::{
    DEFAULT_BEACON_NODE_DIR, DEFAULT_HARDCODED_NETWORK, DEFAULT_NETWORK_DIR, DEFAULT_ROOT_DIR,
};
use if_addrs::get_if_addrs;
use libp2p::{Multiaddr, gossipsub};
use network_utils::listen_addr::{ListenAddr, ListenAddress};
#[cfg(feature = "pq-devnet")]
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "pq-devnet")]
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use types::ForkContext;

pub const DEFAULT_IPV4_ADDRESS: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
pub const DEFAULT_TCP_PORT: u16 = 9000u16;
pub const DEFAULT_DISC_PORT: u16 = 9000u16;
pub const DEFAULT_QUIC_PORT: u16 = 9001u16;
pub const DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD: usize = 1000usize;

#[cfg(feature = "pq-devnet")]
pub const PQ_COMPATIBLE_PEER_CAPACITY: usize = 16;

#[cfg(feature = "pq-devnet")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqCompatiblePeerAdmission {
    Added,
    Existing,
    Capacity,
}

#[cfg(feature = "pq-devnet")]
const PQ_GOSSIP_ACTIVE_CAPACITY: usize = 2;

#[cfg(feature = "pq-devnet")]
#[derive(Default)]
struct PqGossipValidationAdmissionState {
    compatible_peers: HashSet<libp2p::PeerId>,
    active_by_peer: HashMap<libp2p::PeerId, usize>,
    active_total: usize,
}

/// Shared PQ-only source gate used by Status handling and gossipsub pre-cache admission.
#[cfg(feature = "pq-devnet")]
#[derive(Default)]
pub struct PqGossipValidationAdmission {
    state: Mutex<PqGossipValidationAdmissionState>,
}

#[cfg(feature = "pq-devnet")]
impl PqGossipValidationAdmission {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admit_compatible(&self, peer: libp2p::PeerId) -> PqCompatiblePeerAdmission {
        let mut state = self.state.lock();
        if state.compatible_peers.contains(&peer) {
            return PqCompatiblePeerAdmission::Existing;
        }
        if state.compatible_peers.len() >= PQ_COMPATIBLE_PEER_CAPACITY {
            return PqCompatiblePeerAdmission::Capacity;
        }
        state.compatible_peers.insert(peer);
        PqCompatiblePeerAdmission::Added
    }

    pub fn try_add_compatible(&self, peer: libp2p::PeerId) -> bool {
        !matches!(
            self.admit_compatible(peer),
            PqCompatiblePeerAdmission::Capacity
        )
    }

    pub fn remove_compatible(&self, peer: &libp2p::PeerId) {
        self.state.lock().compatible_peers.remove(peer);
    }

    pub fn has_compatible_peers(&self) -> bool {
        !self.state.lock().compatible_peers.is_empty()
    }

    fn is_compatible(&self, peer: &libp2p::PeerId) -> bool {
        self.state.lock().compatible_peers.contains(peer)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_active_total(&self) -> usize {
        self.state.lock().active_total
    }

    pub(crate) fn try_admit(
        self: &Arc<Self>,
        peer: &libp2p::PeerId,
    ) -> Option<PqGossipValidationGuard> {
        let mut state = self.state.lock();
        if !state.compatible_peers.contains(peer)
            || state.active_total >= PQ_GOSSIP_ACTIVE_CAPACITY
            || state.active_by_peer.contains_key(peer)
        {
            return None;
        }
        state.active_total += 1;
        state.active_by_peer.insert(*peer, 1);
        Some(PqGossipValidationGuard {
            controller: Arc::clone(self),
            peer: *peer,
        })
    }
}

#[cfg(feature = "pq-devnet")]
pub(crate) struct PqGossipValidationGuard {
    controller: Arc<PqGossipValidationAdmission>,
    peer: libp2p::PeerId,
}

#[cfg(feature = "pq-devnet")]
impl Drop for PqGossipValidationGuard {
    fn drop(&mut self) {
        let mut state = self.controller.state.lock();
        state.active_by_peer.remove(&self.peer);
        state.active_total = state.active_total.saturating_sub(1);
    }
}

pub struct GossipsubConfigParams {
    pub message_domain_valid_snappy: [u8; 4],
    pub gossipsub_max_transmit_size: usize,
}

#[derive(Clone)]
pub(crate) enum GossipsubProfile {
    Full,
    #[cfg(feature = "pq-devnet")]
    Pq(Arc<PqGossipValidationAdmission>),
}

#[cfg(feature = "pq-devnet")]
const PQ_SLOT_DURATION: Duration = Duration::from_secs(300);

#[cfg(feature = "pq-devnet")]
fn pq_unique_messages_per_validation_window() -> Result<usize, &'static str> {
    const INTERSECTING_SLOTS: usize = 2;
    const MESSAGES_PER_SLOT: usize = 3;

    INTERSECTING_SLOTS
        .checked_mul(MESSAGES_PER_SLOT)
        .ok_or("PQ per-source validation-history capacity overflow")
}

#[cfg(feature = "pq-devnet")]
fn pq_validation_retained_windows(
    duplicate_cache_time: Duration,
    window: Duration,
) -> Result<usize, &'static str> {
    let window_nanos = window.as_nanos();
    if window_nanos == 0 {
        return Err("PQ validation-admission window must be non-zero");
    }
    let rounded_up = duplicate_cache_time
        .as_nanos()
        .checked_add(window_nanos - 1)
        .ok_or("PQ validation-admission retention overflow")?
        / window_nanos;
    let retained = rounded_up
        .checked_add(1)
        .ok_or("PQ validation-admission retention overflow")?;
    usize::try_from(retained).map_err(|_| "PQ validation-admission retention exceeds usize")
}

#[cfg(feature = "pq-devnet")]
fn pq_validation_retained_id_capacity(
    limits: &gossipsub::ValidationAdmissionConfig,
) -> Result<usize, &'static str> {
    limits
        .remote_unique_capacity_per_window
        .checked_add(limits.local_unique_capacity_per_window)
        .and_then(|per_window| per_window.checked_mul(limits.retained_windows))
        .ok_or("PQ retained validation-history capacity overflow")
}

#[cfg(feature = "pq-devnet")]
fn pq_validation_raw_mcache_id_bound(
    limits: &gossipsub::ValidationAdmissionConfig,
) -> Result<usize, &'static str> {
    // The PQ mcache lifetime is one slot plus two heartbeat buckets, so it can intersect at most
    // three 300-second validation-admission windows. `max_publish_messages` is an unrelated
    // per-RPC wire limit and must not be used as the cache inventory bound.
    const INTERSECTING_ADMISSION_WINDOWS: usize = 3;

    limits
        .remote_unique_capacity_per_window
        .checked_add(limits.local_unique_capacity_per_window)
        .and_then(|per_window| per_window.checked_mul(INTERSECTING_ADMISSION_WINDOWS))
        .ok_or("PQ raw mcache validation-ID bound overflow")
}

#[cfg(feature = "pq-devnet")]
fn pq_validation_admission_limits(
    retained_windows: usize,
) -> Result<gossipsub::ValidationAdmissionConfig, &'static str> {
    let unique_capacity_per_source = pq_unique_messages_per_validation_window()?;
    let remote_unique_capacity_per_window = PQ_COMPATIBLE_PEER_CAPACITY
        .checked_mul(unique_capacity_per_source)
        .ok_or("PQ global remote validation-history capacity overflow")?;
    let limits = gossipsub::ValidationAdmissionConfig {
        pending_capacity: 2,
        per_peer_pending_capacity: 1,
        remote_unique_capacity_per_window,
        remote_unique_capacity_per_peer_per_window: unique_capacity_per_source,
        local_unique_capacity_per_window: unique_capacity_per_source,
        pending_timeout: PQ_SLOT_DURATION,
        window: PQ_SLOT_DURATION,
        retained_windows,
    };
    pq_validation_retained_id_capacity(&limits)?;
    pq_validation_raw_mcache_id_bound(&limits)?;
    Ok(limits)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
/// Network configuration for lighthouse.
pub struct Config {
    /// Data directory where node's keyfile is stored
    pub network_dir: PathBuf,

    /// IP addresses to listen on.
    pub(crate) listen_addresses: ListenAddress,

    /// The address to broadcast to peers about which address we are listening on. None indicates
    /// that no discovery address has been set in the CLI args.
    pub enr_address: (Option<Ipv4Addr>, Option<Ipv6Addr>),

    /// The udp ipv4 port to broadcast to peers in order to reach back for discovery.
    pub enr_udp4_port: Option<NonZeroU16>,

    /// The quic ipv4 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_quic4_port: Option<NonZeroU16>,

    /// The tcp ipv4 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_tcp4_port: Option<NonZeroU16>,

    /// The udp ipv6 port to broadcast to peers in order to reach back for discovery.
    pub enr_udp6_port: Option<NonZeroU16>,

    /// The tcp ipv6 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_tcp6_port: Option<NonZeroU16>,

    /// The quic ipv6 port to broadcast to peers in order to reach back for libp2p services.
    pub enr_quic6_port: Option<NonZeroU16>,

    /// Target number of connected peers.
    pub target_peers: usize,

    /// Discv5 configuration parameters.
    #[serde(skip)]
    pub discv5_config: discv5::Config,

    /// List of nodes to initially connect to.
    pub boot_nodes_enr: Vec<Enr>,

    /// List of nodes to initially connect to, on Multiaddr format.
    pub boot_nodes_multiaddr: Vec<Multiaddr>,

    /// List of libp2p nodes to initially connect to.
    pub libp2p_nodes: Vec<Multiaddr>,

    /// List of trusted libp2p nodes which are not scored and marked as explicit.
    pub trusted_peers: Vec<PeerIdSerialized>,

    /// Disables peer scoring altogether.
    pub disable_peer_scoring: bool,

    /// Client version
    pub client_version: String,

    /// Disables the discovery protocol from starting.
    pub disable_discovery: bool,

    /// Disables quic support.
    pub disable_quic_support: bool,

    /// Attempt to construct external port mappings with UPnP.
    pub upnp_enabled: bool,

    /// Subscribe to all subnets for the duration of the runtime.
    pub subscribe_all_subnets: bool,

    /// Import/aggregate all attestations received on subscribed subnets for the duration of the
    /// runtime.
    pub import_all_attestations: bool,

    /// A setting specifying a range of values that tune the network parameters of lighthouse. The
    /// lower the value the less bandwidth used, but the slower messages will be received.
    pub network_load: u8,

    /// Indicates if the user has set the network to be in private mode. Currently this
    /// prevents sending client identifying information over identify and prevents
    /// EIP-7636 indentifiable information being provided in the ENR.
    pub private: bool,

    /// Shutdown beacon node after sync is completed.
    pub shutdown_after_sync: bool,

    /// List of extra topics to initially subscribe to as strings.
    pub topics: Vec<GossipKind>,

    /// Whether we are running a block proposer only node.
    pub proposer_only: bool,

    /// Whether metrics are enabled.
    pub metrics_enabled: bool,

    /// Whether light client protocols should be enabled.
    pub enable_light_client_server: bool,

    /// Whether to enable the mplex multiplexer alongside yamux. Enabled by default.
    pub enable_mplex: bool,

    /// Configuration for the outbound rate limiter (requests made by this node).
    pub outbound_rate_limiter_config: Option<OutboundRateLimiterConfig>,

    /// Configures if/where invalid blocks should be stored.
    pub invalid_block_storage: Option<PathBuf>,

    /// Configuration for the inbound rate limiter (requests received by this node).
    pub inbound_rate_limiter_config: Option<InboundRateLimiterConfig>,

    /// Configuration for the minimum message size for which IDONTWANT messages are send in the mesh.
    /// Lower the value reduces the optimization effect of the IDONTWANT messages.
    pub idontwant_message_size_threshold: usize,

    /// Flag for advertising a fake CGC to peers for testing ONLY.
    pub advertise_false_custody_group_count: Option<u64>,

    /// Whether to enable partial data column support.
    pub enable_partial_columns: bool,
}

impl Config {
    /// Sets the listening address to use an ipv4 address. The discv5 ip_mode and table filter are
    /// adjusted accordingly to ensure addresses that are present in the enr are globally
    /// reachable.
    pub fn set_ipv4_listening_address(
        &mut self,
        addr: Ipv4Addr,
        tcp_port: u16,
        disc_port: u16,
        quic_port: u16,
    ) {
        self.listen_addresses = ListenAddress::V4(ListenAddr {
            addr,
            disc_port,
            quic_port,
            tcp_port,
        });
        self.discv5_config.listen_config = discv5::ListenConfig::from_ip(addr.into(), disc_port);
        self.discv5_config.table_filter = |enr| enr.ip4().as_ref().is_some_and(is_global_ipv4)
    }

    /// Sets the listening address to use an ipv6 address. The discv5 ip_mode and table filter is
    /// adjusted accordingly to ensure addresses that are present in the enr are globally
    /// reachable.
    pub fn set_ipv6_listening_address(
        &mut self,
        addr: Ipv6Addr,
        tcp_port: u16,
        disc_port: u16,
        quic_port: u16,
    ) {
        self.listen_addresses = ListenAddress::V6(ListenAddr {
            addr,
            disc_port,
            quic_port,
            tcp_port,
        });

        self.discv5_config.listen_config = discv5::ListenConfig::from_ip(addr.into(), disc_port);
        self.discv5_config.table_filter = |enr| enr.ip6().as_ref().is_some_and(is_global_ipv6)
    }

    /// Sets the listening address to use both an ipv4 and ipv6 address. The discv5 ip_mode and
    /// table filter is adjusted accordingly to ensure addresses that are present in the enr are
    /// globally reachable.
    #[allow(clippy::too_many_arguments)]
    pub fn set_ipv4_ipv6_listening_addresses(
        &mut self,
        v4_addr: Ipv4Addr,
        tcp4_port: u16,
        disc4_port: u16,
        quic4_port: u16,
        v6_addr: Ipv6Addr,
        tcp6_port: u16,
        disc6_port: u16,
        quic6_port: u16,
    ) {
        self.listen_addresses = ListenAddress::DualStack(
            ListenAddr {
                addr: v4_addr,
                disc_port: disc4_port,
                quic_port: quic4_port,
                tcp_port: tcp4_port,
            },
            ListenAddr {
                addr: v6_addr,
                disc_port: disc6_port,
                quic_port: quic6_port,
                tcp_port: tcp6_port,
            },
        );
        self.discv5_config.listen_config = discv5::ListenConfig::default()
            .with_ipv4(v4_addr, disc4_port)
            .with_ipv6(v6_addr, disc6_port);

        self.discv5_config.table_filter = |enr| match (&enr.ip4(), &enr.ip6()) {
            (None, None) => false,
            (None, Some(ip6)) => is_global_ipv6(ip6),
            (Some(ip4), None) => is_global_ipv4(ip4),
            (Some(ip4), Some(ip6)) => is_global_ipv4(ip4) && is_global_ipv6(ip6),
        };
    }

    pub fn set_listening_addr(&mut self, listen_addr: ListenAddress) {
        match listen_addr {
            ListenAddress::V4(ListenAddr {
                addr,
                disc_port,
                quic_port,
                tcp_port,
            }) => self.set_ipv4_listening_address(addr, tcp_port, disc_port, quic_port),
            ListenAddress::V6(ListenAddr {
                addr,
                disc_port,
                quic_port,
                tcp_port,
            }) => self.set_ipv6_listening_address(addr, tcp_port, disc_port, quic_port),
            ListenAddress::DualStack(
                ListenAddr {
                    addr: ip4addr,
                    disc_port: disc4_port,
                    quic_port: quic4_port,
                    tcp_port: tcp4_port,
                },
                ListenAddr {
                    addr: ip6addr,
                    disc_port: disc6_port,
                    quic_port: quic6_port,
                    tcp_port: tcp6_port,
                },
            ) => self.set_ipv4_ipv6_listening_addresses(
                ip4addr, tcp4_port, disc4_port, quic4_port, ip6addr, tcp6_port, disc6_port,
                quic6_port,
            ),
        }
    }

    /// A helper function to check if the local host has a globally routeable IPv6 address. If so,
    /// returns true.
    pub fn is_ipv6_supported() -> bool {
        let Ok(addrs) = get_if_addrs() else {
            return false;
        };

        addrs.iter().any(
            |iface| matches!(iface.addr, if_addrs::IfAddr::V6(ref v6) if is_global_ipv6(&v6.ip)),
        )
    }

    pub fn listen_addrs(&self) -> &ListenAddress {
        &self.listen_addresses
    }
}

impl Default for Config {
    /// Generate a default network configuration.
    fn default() -> Self {
        // WARNING: this directory default should be always overwritten with parameters
        // from cli for specific networks.
        let network_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK)
            .join(DEFAULT_BEACON_NODE_DIR)
            .join(DEFAULT_NETWORK_DIR);

        // Discv5 Unsolicited Packet Rate Limiter
        let filter_rate_limiter = Some(
            discv5::RateLimiterBuilder::new()
                .total_n_every(10, Duration::from_secs(1)) // Allow bursts, average 10 per second
                .ip_n_every(9, Duration::from_secs(1)) // Allow bursts, average 9 per second
                .node_n_every(8, Duration::from_secs(1)) // Allow bursts, average 8 per second
                .build()
                .expect("The total rate limit has been specified"),
        );
        let listen_addresses = ListenAddress::V4(ListenAddr {
            addr: DEFAULT_IPV4_ADDRESS,
            disc_port: DEFAULT_DISC_PORT,
            quic_port: DEFAULT_QUIC_PORT,
            tcp_port: DEFAULT_TCP_PORT,
        });

        let discv5_listen_config =
            discv5::ListenConfig::from_ip(Ipv4Addr::UNSPECIFIED.into(), 9000);

        // discv5 configuration
        let discv5_config = discv5::ConfigBuilder::new(discv5_listen_config)
            .enable_packet_filter()
            .session_cache_capacity(5000)
            .request_timeout(Duration::from_secs(2))
            .query_peer_timeout(Duration::from_secs(2))
            .query_timeout(Duration::from_secs(30))
            .request_retries(1)
            .enr_peer_update_min(10)
            .query_parallelism(8)
            .disable_report_discovered_peers()
            .ip_limit() // limits /24 IP's in buckets.
            .incoming_bucket_limit(8) // half the bucket size
            .filter_rate_limiter(filter_rate_limiter)
            .filter_max_bans_per_ip(Some(5))
            .filter_max_nodes_per_ip(Some(10))
            .table_filter(|enr| enr.ip4().is_some_and(|ip| is_global_ipv4(&ip))) // Filter non-global IPs
            .ban_duration(Some(Duration::from_secs(3600)))
            .ping_interval(Duration::from_secs(300))
            .build();

        // NOTE: Some of these get overridden by the corresponding CLI default values.
        Config {
            network_dir,
            listen_addresses,
            enr_address: (None, None),
            enr_udp4_port: None,
            enr_quic4_port: None,
            enr_tcp4_port: None,
            enr_udp6_port: None,
            enr_quic6_port: None,
            enr_tcp6_port: None,
            target_peers: DEFAULT_TARGET_PEERS,
            discv5_config,
            boot_nodes_enr: vec![],
            boot_nodes_multiaddr: vec![],
            libp2p_nodes: vec![],
            trusted_peers: vec![],
            disable_peer_scoring: false,
            client_version: lighthouse_version::version_with_platform(),
            disable_discovery: false,
            disable_quic_support: false,
            upnp_enabled: true,
            network_load: 3,
            private: false,
            subscribe_all_subnets: false,
            import_all_attestations: false,
            shutdown_after_sync: false,
            topics: Vec::new(),
            proposer_only: false,
            metrics_enabled: false,
            enable_light_client_server: true,
            enable_mplex: true,
            outbound_rate_limiter_config: None,
            invalid_block_storage: None,
            inbound_rate_limiter_config: None,
            idontwant_message_size_threshold: DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD,
            advertise_false_custody_group_count: None,
            enable_partial_columns: false,
        }
    }
}

/// Controls sizes of gossipsub meshes to tune a Lighthouse node's bandwidth/performance.
pub struct NetworkLoad {
    pub name: &'static str,
    pub mesh_n_low: usize,
    pub outbound_min: usize,
    pub mesh_n: usize,
    pub mesh_n_high: usize,
    pub gossip_lazy: usize,
    pub history_gossip: usize,
    pub heartbeat_interval: Duration,
}

impl From<u8> for NetworkLoad {
    fn from(load: u8) -> NetworkLoad {
        match load {
            1 => NetworkLoad {
                name: "Low",
                mesh_n_low: 1,
                outbound_min: 1,
                mesh_n: 3,
                mesh_n_high: 4,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1200),
            },
            2 => NetworkLoad {
                name: "Low",
                mesh_n_low: 2,
                outbound_min: 2,
                mesh_n: 4,
                mesh_n_high: 8,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1000),
            },
            3 => NetworkLoad {
                name: "Average",
                mesh_n_low: 3,
                outbound_min: 2,
                mesh_n: 5,
                mesh_n_high: 10,
                gossip_lazy: 3,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1000),
            },
            4 => NetworkLoad {
                name: "Average",
                mesh_n_low: 4,
                outbound_min: 3,
                mesh_n: 8,
                mesh_n_high: 10,
                gossip_lazy: 2,
                history_gossip: 3,
                heartbeat_interval: Duration::from_millis(1000),
            },
            // 5 and above
            _ => NetworkLoad {
                name: "High",
                mesh_n_low: 5,
                outbound_min: 3,
                mesh_n: 10,
                mesh_n_high: 15,
                gossip_lazy: 5,
                history_gossip: 6,
                heartbeat_interval: Duration::from_millis(700),
            },
        }
    }
}

/// Return a Lighthouse specific `GossipsubConfig` where the `message_id_fn` depends on the current fork.
#[cfg(feature = "pq-devnet")]
fn pq_validation_history_length(
    slot_duration: Duration,
    heartbeat_interval: Duration,
) -> Result<usize, &'static str> {
    let slot_nanos = slot_duration.as_nanos();
    let heartbeat_nanos = heartbeat_interval.as_nanos();
    if heartbeat_nanos == 0 {
        return Err("PQ gossipsub heartbeat interval must be non-zero");
    }

    let rounded_up = slot_nanos
        .checked_add(heartbeat_nanos - 1)
        .ok_or("PQ gossipsub validation history overflow")?
        / heartbeat_nanos;
    let history_length = rounded_up
        .checked_add(2)
        .ok_or("PQ gossipsub validation history overflow")?;
    usize::try_from(history_length).map_err(|_| "PQ gossipsub validation history exceeds usize")
}

pub fn gossipsub_config(
    network_load: u8,
    fork_context: Arc<ForkContext>,
    gossipsub_config_params: GossipsubConfigParams,
    slot_duration: Duration,
    slots_per_epoch: u64,
    idontwant_message_size_threshold: usize,
    profile: GossipsubProfile,
) -> Result<gossipsub::Config, String> {
    #[cfg(feature = "pq-devnet")]
    if matches!(&profile, GossipsubProfile::Pq(_)) && slot_duration != PQ_SLOT_DURATION {
        return Err("PQ gossipsub requires an exact 300-second slot".to_owned());
    }

    fn prefix(
        prefix: [u8; 4],
        message: &gossipsub::Message,
        fork_context: Arc<ForkContext>,
    ) -> Vec<u8> {
        let topic_bytes = message.topic.as_str().as_bytes();

        if fork_context.current_fork_name().altair_enabled() {
            let topic_len_bytes = topic_bytes.len().to_le_bytes();
            let mut vec = Vec::with_capacity(
                prefix.len() + topic_len_bytes.len() + topic_bytes.len() + message.data.len(),
            );
            vec.extend_from_slice(&prefix);
            vec.extend_from_slice(&topic_len_bytes);
            vec.extend_from_slice(topic_bytes);
            vec.extend_from_slice(&message.data);
            vec
        } else {
            let mut vec = Vec::with_capacity(prefix.len() + message.data.len());
            vec.extend_from_slice(&prefix);
            vec.extend_from_slice(&message.data);
            vec
        }
    }
    let message_domain_valid_snappy = gossipsub_config_params.message_domain_valid_snappy;
    let gossip_message_id = move |message: &gossipsub::Message| {
        gossipsub::MessageId::from(
            &Sha256::digest(
                prefix(message_domain_valid_snappy, message, fork_context.clone()).as_slice(),
            )[..20],
        )
    };

    let load = NetworkLoad::from(network_load);
    let history_length = match &profile {
        GossipsubProfile::Full => 12,
        #[cfg(feature = "pq-devnet")]
        GossipsubProfile::Pq(_) => {
            pq_validation_history_length(slot_duration, load.heartbeat_interval)
                .map_err(str::to_owned)?
        }
    };

    // Since EIP 7045 (activated at the deneb fork), we allow attestations that are
    // 2 epochs old to be circulated around the p2p network.
    // To accommodate the increase, we should increase the duplicate cache time to filter older seen messages.
    // 2 epochs is quite sane for pre-deneb network parameters as well.
    // Hence we keep the same parameters for pre-deneb networks as well to avoid switching at the fork.
    let duplicate_slots = slots_per_epoch
        .checked_mul(2)
        .and_then(|slots| u32::try_from(slots).ok())
        .ok_or_else(|| "gossipsub duplicate-cache slot count overflow".to_owned())?;
    let duplicate_cache_time = slot_duration
        .checked_mul(duplicate_slots)
        .ok_or_else(|| "gossipsub duplicate-cache duration overflow".to_owned())?;

    let mut builder = gossipsub::ConfigBuilder::default();
    builder
        .max_transmit_size(gossipsub_config_params.gossipsub_max_transmit_size)
        .heartbeat_interval(load.heartbeat_interval)
        .mesh_n(load.mesh_n)
        .mesh_n_low(load.mesh_n_low)
        .mesh_outbound_min(load.outbound_min)
        .mesh_n_high(load.mesh_n_high)
        .gossip_lazy(load.gossip_lazy)
        .fanout_ttl(Duration::from_secs(60))
        .history_length(history_length)
        .flood_publish(false)
        .max_publish_messages(500) // Responses to IWANT can be quite large
        .max_control_messages_sent(500)
        .max_control_message_size(128 << 10) // 128KB
        .history_gossip(load.history_gossip)
        .validate_messages() // require validation before propagation
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        .duplicate_cache_time(duplicate_cache_time)
        .message_id_fn(gossip_message_id)
        .allow_self_origin(true)
        .idontwant_message_size_threshold(idontwant_message_size_threshold);

    #[cfg(feature = "pq-devnet")]
    if let GossipsubProfile::Pq(admission) = profile {
        let retained_windows = pq_validation_retained_windows(duplicate_cache_time, slot_duration)
            .map_err(str::to_owned)?;
        if retained_windows != 17 {
            return Err(format!(
                "PQ gossipsub requires exactly 17 retained validation windows, got {retained_windows}"
            ));
        }
        let publish_admission = Arc::clone(&admission);
        let admission_limits =
            pq_validation_admission_limits(retained_windows).map_err(str::to_owned)?;
        builder
            .publish_peer_filter(move |peer, _| publish_admission.is_compatible(peer))
            .validation_admission(admission_limits, move |source, _, _, _| {
                match admission.try_admit(source) {
                    Some(guard) => gossipsub::ValidationAdmission::Admit(
                        gossipsub::ValidationAdmissionGuard::new(guard),
                    ),
                    None => gossipsub::ValidationAdmission::IgnoreWithoutCaching,
                }
            });
    }

    builder.build().map_err(|error| error.to_string())
}

#[cfg(all(test, feature = "pq-devnet"))]
mod pq_tests {
    use super::*;
    use types::{EthSpec, ForkName, Hash256, MinimalEthSpec};

    #[test]
    fn pq_validation_history_spans_one_slot_at_every_network_load() {
        let slot = Duration::from_secs(300);

        assert_eq!(
            pq_validation_history_length(slot, Duration::from_millis(1_200)),
            Ok(252)
        );
        assert_eq!(
            pq_validation_history_length(slot, Duration::from_millis(1_000)),
            Ok(302)
        );
        assert_eq!(
            pq_validation_history_length(slot, Duration::from_millis(700)),
            Ok(431)
        );
        assert!(pq_validation_history_length(slot, Duration::ZERO).is_err());
    }

    #[test]
    fn pq_local_retained_unique_capacity_is_exactly_six() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(limits.local_unique_capacity_per_window, 6);
    }

    #[test]
    fn pq_remote_retained_unique_capacity_per_peer_is_exactly_six() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(limits.remote_unique_capacity_per_peer_per_window, 6);
    }

    #[test]
    fn pq_remote_retained_unique_global_capacity_is_exactly_ninety_six() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(limits.remote_unique_capacity_per_window, 96);
    }

    #[test]
    fn pq_pending_admission_capacity_is_global_two_per_peer_one() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(limits.pending_capacity, 2);
        assert_eq!(limits.per_peer_pending_capacity, 1);
    }

    #[test]
    fn pq_phase_shifted_window_covers_two_slots_of_block_and_two_singles() {
        assert_eq!(
            pq_unique_messages_per_validation_window(),
            Ok(6),
            "an arbitrary 300-second window can intersect two slots, each with one block and two singles",
        );
    }

    #[test]
    fn pq_checked_retained_id_inventory_is_exactly_one_thousand_seven_hundred_thirty_four() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(pq_validation_retained_id_capacity(&limits), Ok(1_734),);
    }

    #[test]
    fn pq_checked_raw_mcache_id_bound_is_exactly_three_hundred_six() {
        let limits = pq_validation_admission_limits(17).expect("frozen PQ admission limits");
        assert_eq!(pq_validation_raw_mcache_id_bound(&limits), Ok(306));
    }

    #[test]
    fn pq_validation_admission_limits_reject_retained_inventory_overflow() {
        assert_eq!(
            pq_validation_admission_limits(usize::MAX).unwrap_err(),
            "PQ retained validation-history capacity overflow",
        );
    }

    #[test]
    fn pq_gossipsub_profile_retains_validation_for_one_slot_only_in_pq_mode() {
        let spec = ForkName::Electra
            .make_genesis_spec(MinimalEthSpec::default_spec())
            .set_slot_duration_ms::<MinimalEthSpec>(300_000);
        let fork_context = Arc::new(ForkContext::new::<MinimalEthSpec>(
            spec.genesis_slot,
            Hash256::ZERO,
            &spec,
        ));
        let config_params = || GossipsubConfigParams {
            message_domain_valid_snappy: spec.message_domain_valid_snappy,
            gossipsub_max_transmit_size: spec.max_message_size(),
        };

        let full = gossipsub_config(
            3,
            Arc::clone(&fork_context),
            config_params(),
            spec.get_slot_duration(),
            MinimalEthSpec::slots_per_epoch(),
            DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD,
            GossipsubProfile::Full,
        )
        .expect("full gossipsub config");
        let pq = gossipsub_config(
            3,
            fork_context,
            config_params(),
            spec.get_slot_duration(),
            MinimalEthSpec::slots_per_epoch(),
            DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD,
            GossipsubProfile::Pq(Arc::new(PqGossipValidationAdmission::new())),
        )
        .expect("PQ gossipsub config");

        assert_eq!(full.history_length(), 12);
        assert_eq!(pq.history_length(), 302);
    }

    #[test]
    fn pq_gossipsub_rejects_any_slot_duration_other_than_exactly_three_hundred_seconds() {
        let spec = ForkName::Electra.make_genesis_spec(MinimalEthSpec::default_spec());
        let fork_context = Arc::new(ForkContext::new::<MinimalEthSpec>(
            spec.genesis_slot,
            Hash256::ZERO,
            &spec,
        ));
        let config_params = || GossipsubConfigParams {
            message_domain_valid_snappy: spec.message_domain_valid_snappy,
            gossipsub_max_transmit_size: spec.max_message_size(),
        };

        for seconds in [299, 301] {
            let error = gossipsub_config(
                3,
                Arc::clone(&fork_context),
                config_params(),
                Duration::from_secs(seconds),
                MinimalEthSpec::slots_per_epoch(),
                DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD,
                GossipsubProfile::Pq(Arc::new(PqGossipValidationAdmission::new())),
            )
            .expect_err("non-frozen PQ slot duration");
            assert_eq!(error, "PQ gossipsub requires an exact 300-second slot");

            let full = gossipsub_config(
                3,
                Arc::clone(&fork_context),
                config_params(),
                Duration::from_secs(seconds),
                MinimalEthSpec::slots_per_epoch(),
                DEFAULT_IDONTWANT_MESSAGE_SIZE_THRESHOLD,
                GossipsubProfile::Full,
            )
            .expect("ordinary profile keeps its configured slot timing");
            let duplicate_slots = u32::try_from(MinimalEthSpec::slots_per_epoch() * 2)
                .expect("minimal duplicate slot count");
            assert_eq!(
                full.duplicate_cache_time(),
                Duration::from_secs(seconds)
                    .checked_mul(duplicate_slots)
                    .expect("ordinary duplicate-cache timing"),
            );
            assert_eq!(full.history_length(), 12);
        }
    }

    #[test]
    fn pq_compatible_peer_set_is_hard_sixteen_and_admission_is_two_per_peer_one() {
        let controller = Arc::new(PqGossipValidationAdmission::new());
        let peers = (0..17)
            .map(|_| libp2p::PeerId::random())
            .collect::<Vec<_>>();
        for peer in &peers[..16] {
            assert!(controller.try_add_compatible(*peer));
        }
        assert!(!controller.try_add_compatible(peers[16]));

        let first = controller
            .try_admit(&peers[0])
            .expect("first peer admitted");
        assert!(controller.try_admit(&peers[0]).is_none());
        let second = controller
            .try_admit(&peers[1])
            .expect("second peer admitted");
        assert!(controller.try_admit(&peers[2]).is_none());
        drop(first);
        assert!(controller.try_admit(&peers[2]).is_some());
        drop(second);

        controller.remove_compatible(&peers[0]);
        assert!(controller.try_add_compatible(peers[16]));
        assert!(controller.try_admit(&peers[0]).is_none());
    }
}

/// Helper function to determine if the IpAddr is a global address or not. The `is_global()`
/// function is not yet stable on IpAddr.
#[allow(clippy::nonminimal_bool)]
fn is_global_ipv4(addr: &Ipv4Addr) -> bool {
    // check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
    // globally routable addresses in the 192.0.0.0/24 range.
    if u32::from_be_bytes(addr.octets()) == 0xc0000009
        || u32::from_be_bytes(addr.octets()) == 0xc000000a
    {
        return true;
    }
    !addr.is_private()
            && !addr.is_loopback()
            && !addr.is_link_local()
            && !addr.is_broadcast()
            && !addr.is_documentation()
            // shared
            && !(addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)) &&!(addr.octets()[0] & 240 == 240 && !addr.is_broadcast())
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // reserved
            && !(addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
            // Make sure the address is not in 0.0.0.0/8
            && addr.octets()[0] != 0
}

/// NOTE: Docs taken from https://doc.rust-lang.org/stable/std/net/struct.Ipv6Addr.html#method.is_global
///
/// Returns true if the address appears to be globally reachable as specified by the IANA IPv6
/// Special-Purpose Address Registry. Whether or not an address is practically reachable will
/// depend on your network configuration.
///
/// Most IPv6 addresses are globally reachable; unless they are specifically defined as not
/// globally reachable.
///
/// Non-exhaustive list of notable addresses that are not globally reachable:
///
/// - The unspecified address (is_unspecified)
/// - The loopback address (is_loopback)
/// - IPv4-mapped addresses
/// - Addresses reserved for benchmarking
/// - Addresses reserved for documentation (is_documentation)
/// - Unique local addresses (is_unique_local)
/// - Unicast addresses with link-local scope (is_unicast_link_local)
// TODO: replace with [`Ipv6Addr::is_global`] once
//       [Ip](https://github.com/rust-lang/rust/issues/27709) is stable.
pub const fn is_global_ipv6(addr: &Ipv6Addr) -> bool {
    const fn is_documentation(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
    }
    const fn is_unique_local(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xfe00) == 0xfc00
    }
    const fn is_unicast_link_local(addr: &Ipv6Addr) -> bool {
        (addr.segments()[0] & 0xffc0) == 0xfe80
    }
    !(addr.is_unspecified()
            || addr.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
                ))
            || is_documentation(addr)
            || is_unique_local(addr)
            || is_unicast_link_local(addr))
}
