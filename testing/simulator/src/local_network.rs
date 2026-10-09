use crate::checks::epoch_delay;
use beacon_chain::custody_context::NodeCustodyType;
use kzg::trusted_setup::get_trusted_setup;
use node_test_rig::{
    ClientConfig, ClientGenesis, LocalBeaconNode, LocalExecutionNode, LocalValidatorClient,
    MockExecutionConfig, MockServerConfig, ValidatorConfig, ValidatorFiles,
    environment::RuntimeContext,
    eth2::{BeaconNodeHttpClient, types::StateId},
    testing_client_config,
};
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use std::{
    net::Ipv4Addr,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use types::{ChainSpec, Epoch, EthSpec};

const BOOTNODE_PORT: u16 = 42424;
const QUIC_PORT: u16 = 43424;

pub const EXECUTION_PORT: u16 = 4000;

pub const TERMINAL_BLOCK: u64 = 0;

pub struct LocalNetworkParams {
    pub validator_count: usize,
    pub node_count: usize,
    pub proposer_nodes: usize,
    pub extra_nodes: usize,
    pub genesis_delay: u64,
}

fn default_client_config(network_params: LocalNetworkParams, genesis_time: u64) -> ClientConfig {
    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::InteropMerge {
        validator_count: network_params.validator_count,
        genesis_time,
    };
    beacon_config.network.target_peers =
        network_params.node_count + network_params.proposer_nodes + network_params.extra_nodes - 1;
    beacon_config.network.enr_address = (Some(Ipv4Addr::LOCALHOST), None);
    beacon_config.network.enable_light_client_server = true;
    beacon_config.network.discv5_config.enable_packet_filter = false;
    beacon_config.chain.enable_light_client_server = true;
    beacon_config.chain.optimistic_finalized_sync = false;
    beacon_config.chain.node_custody_type = NodeCustodyType::Supernode;
    beacon_config.trusted_setup = get_trusted_setup();

    let el_config = execution_layer::Config {
        execution_endpoint: Some(
            SensitiveUrl::parse(&format!("http://localhost:{}", EXECUTION_PORT)).unwrap(),
        ),
        ..Default::default()
    };
    beacon_config.execution_layer = Some(el_config);
    beacon_config
}

fn default_mock_execution_config<E: EthSpec>(
    spec: &ChainSpec,
    genesis_time: u64,
) -> MockExecutionConfig {
    let mut mock_execution_config = MockExecutionConfig {
        server_config: MockServerConfig {
            listen_port: EXECUTION_PORT,
            ..Default::default()
        },
        ..Default::default()
    };

    if let Some(capella_fork_epoch) = spec.capella_fork_epoch {
        mock_execution_config.shanghai_time = Some(
            genesis_time
                + (spec.get_slot_duration().as_secs())
                    * E::slots_per_epoch()
                    * capella_fork_epoch.as_u64(),
        )
    }
    if let Some(deneb_fork_epoch) = spec.deneb_fork_epoch {
        mock_execution_config.cancun_time = Some(
            genesis_time
                + (spec.get_slot_duration().as_secs())
                    * E::slots_per_epoch()
                    * deneb_fork_epoch.as_u64(),
        )
    }
    if let Some(electra_fork_epoch) = spec.electra_fork_epoch {
        mock_execution_config.prague_time = Some(
            genesis_time
                + (spec.get_slot_duration().as_secs())
                    * E::slots_per_epoch()
                    * electra_fork_epoch.as_u64(),
        )
    }
    if let Some(fulu_fork_epoch) = spec.fulu_fork_epoch {
        mock_execution_config.osaka_time = Some(
            genesis_time
                + (spec.get_slot_duration().as_secs())
                    * E::slots_per_epoch()
                    * fulu_fork_epoch.as_u64(),
        )
    }

    if let Some(gloas_fork_epoch) = spec.gloas_fork_epoch {
        mock_execution_config.amsterdam_time = Some(
            genesis_time
                + (spec.get_slot_duration().as_secs())
                    * E::slots_per_epoch()
                    * gloas_fork_epoch.as_u64(),
        )
    }

    mock_execution_config
}

/// Helper struct to reduce `Arc` usage.
pub struct Inner<E: EthSpec> {
    pub context: RuntimeContext<E>,
    pub beacon_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub proposer_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub validator_clients: RwLock<Vec<LocalValidatorClient<E>>>,
    pub execution_nodes: RwLock<Vec<LocalExecutionNode<E>>>,
    #[cfg(madsim)]
    pub execution_hosts: RwLock<Vec<madsim::runtime::NodeHandle>>,
    #[cfg(madsim)]
    pub beacon_configs: RwLock<Vec<ClientConfig>>,
    #[cfg(madsim)]
    node_controls: RwLock<Vec<SimulationNodeControl>>,
}

#[cfg(madsim)]
struct SimulationNodeControl {
    exit: async_channel::Sender<()>,
    shutdown: futures::channel::mpsc::Receiver<task_executor::ShutdownReason>,
}

/// Represents a set of interconnected `LocalBeaconNode` and `LocalValidatorClient`.
///
/// Provides functions to allow adding new beacon nodes and validators.
pub struct LocalNetwork<E: EthSpec> {
    inner: Arc<Inner<E>>,
}

impl<E: EthSpec> Clone for LocalNetwork<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: EthSpec> Deref for LocalNetwork<E> {
    type Target = Inner<E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<E: EthSpec> LocalNetwork<E> {
    pub async fn create_local_network(
        client_config: Option<ClientConfig>,
        mock_execution_config: Option<MockExecutionConfig>,
        network_params: LocalNetworkParams,
        context: RuntimeContext<E>,
    ) -> Result<(LocalNetwork<E>, ClientConfig, MockExecutionConfig), String> {
        let genesis_time: u64 = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "should get system time")?
            + Duration::from_secs(network_params.genesis_delay))
        .as_secs();

        let beacon_config = if let Some(config) = client_config {
            config
        } else {
            default_client_config(network_params, genesis_time)
        };

        let execution_config = if let Some(config) = mock_execution_config {
            config
        } else {
            default_mock_execution_config::<E>(&context.eth2_config().spec, genesis_time)
        };

        let network = Self {
            inner: Arc::new(Inner {
                context,
                beacon_nodes: RwLock::new(vec![]),
                proposer_nodes: RwLock::new(vec![]),
                execution_nodes: RwLock::new(vec![]),
                validator_clients: RwLock::new(vec![]),
                #[cfg(madsim)]
                execution_hosts: RwLock::new(vec![]),
                #[cfg(madsim)]
                beacon_configs: RwLock::new(vec![]),
                #[cfg(madsim)]
                node_controls: RwLock::new(vec![]),
            }),
        };

        Ok((network, beacon_config, execution_config))
    }

    /// Returns the number of beacon nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn beacon_node_count(&self) -> usize {
        self.beacon_nodes.read().len()
    }

    /// Returns the number of proposer nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn proposer_node_count(&self) -> usize {
        self.proposer_nodes.read().len()
    }

    /// Returns the number of validator clients in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn validator_client_count(&self) -> usize {
        self.validator_clients.read().len()
    }

    #[cfg(madsim)]
    pub fn fresh_beacon_context(&self, index: usize) -> RuntimeContext<E> {
        let (exit, exit_rx) = async_channel::bounded(1);
        let (shutdown_tx, shutdown) = futures::channel::mpsc::channel(16);
        let mut context = self.context.clone();
        context.executor = task_executor::TaskExecutor::new(
            tokio::runtime::Handle::current(),
            exit_rx,
            shutdown_tx,
        );
        let control = SimulationNodeControl { exit, shutdown };
        let mut controls = self.node_controls.write();
        if index == controls.len() {
            controls.push(control);
        } else {
            controls[index] = control;
        }
        context
    }

    #[cfg(madsim)]
    pub fn node_shutdown(&self, index: usize) -> Option<task_executor::ShutdownReason> {
        self.node_controls.write()[index].shutdown.try_recv().ok()
    }

    #[cfg(madsim)]
    pub fn stop_beacon_nodes(&self) {
        for control in self.node_controls.read().iter() {
            control.exit.close();
        }
    }

    #[cfg(madsim)]
    async fn simulated_execution_node(
        &self,
        config: MockExecutionConfig,
        index: usize,
    ) -> Result<LocalExecutionNode<E>, String> {
        let host = self.execution_hosts.read().get(index).cloned();
        let context = self.context.clone();
        if let Some(host) = host {
            host.spawn(async move { LocalExecutionNode::new(context, config).await })
                .await
                .map_err(|error| format!("execution node {index} startup: {error}"))
        } else {
            Ok(LocalExecutionNode::new(context, config).await)
        }
    }

    async fn configured_beacon_node(
        &self,
        config: ClientConfig,
    ) -> Result<LocalBeaconNode<E>, String> {
        #[cfg(not(madsim))]
        let context = self.context.clone();
        #[cfg(madsim)]
        let context = {
            let index = self.beacon_node_count() + self.proposer_node_count();
            self.beacon_configs.write().push(config.clone());
            self.fresh_beacon_context(index)
        };
        LocalBeaconNode::production(context, config).await
    }

    async fn construct_boot_node(
        &self,
        mut beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
    ) -> Result<(LocalBeaconNode<E>, LocalExecutionNode<E>), String> {
        #[cfg(not(madsim))]
        beacon_config.network.set_ipv4_listening_address(
            std::net::Ipv4Addr::UNSPECIFIED,
            BOOTNODE_PORT,
            BOOTNODE_PORT,
            QUIC_PORT,
        );

        beacon_config.network.enr_udp4_port = Some(BOOTNODE_PORT.try_into().expect("non zero"));
        beacon_config.network.enr_tcp4_port = Some(BOOTNODE_PORT.try_into().expect("non zero"));
        beacon_config.network.discv5_config.table_filter = |_| true;

        #[cfg(madsim)]
        let execution_node = self
            .simulated_execution_node(mock_execution_config, 0)
            .await?;
        #[cfg(not(madsim))]
        let execution_node =
            LocalExecutionNode::new(self.context.clone(), mock_execution_config).await;

        beacon_config.execution_layer = Some(execution_layer::Config {
            execution_endpoint: Some(SensitiveUrl::parse(&execution_node.server.url()).unwrap()),
            default_datadir: execution_node.datadir.path().to_path_buf(),
            secret_file: Some(execution_node.datadir.path().join("jwt.hex")),
            ..Default::default()
        });

        let beacon_node = self.configured_beacon_node(beacon_config).await?;

        Ok((beacon_node, execution_node))
    }

    async fn construct_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
        mut mock_execution_config: MockExecutionConfig,
        is_proposer: bool,
    ) -> Result<(LocalBeaconNode<E>, LocalExecutionNode<E>), String> {
        let count = (self.beacon_node_count() + self.proposer_node_count()) as u16;

        // Set config.
        let libp2p_tcp_port = BOOTNODE_PORT + count;
        let discv5_port = BOOTNODE_PORT + count;
        #[cfg(not(madsim))]
        beacon_config.network.set_ipv4_listening_address(
            std::net::Ipv4Addr::UNSPECIFIED,
            libp2p_tcp_port,
            discv5_port,
            QUIC_PORT + count,
        );
        beacon_config.network.enr_udp4_port = Some(discv5_port.try_into().unwrap());
        beacon_config.network.enr_tcp4_port = Some(libp2p_tcp_port.try_into().unwrap());
        beacon_config.network.discv5_config.table_filter = |_| true;
        beacon_config.network.proposer_only = is_proposer;

        mock_execution_config.server_config.listen_port = EXECUTION_PORT + count;

        // Construct execution node.
        #[cfg(madsim)]
        let execution_node = self
            .simulated_execution_node(mock_execution_config, count as usize)
            .await?;
        #[cfg(not(madsim))]
        let execution_node =
            LocalExecutionNode::new(self.context.clone(), mock_execution_config).await;

        // Pair the beacon node and execution node.
        beacon_config.execution_layer = Some(execution_layer::Config {
            execution_endpoint: Some(SensitiveUrl::parse(&execution_node.server.url()).unwrap()),
            default_datadir: execution_node.datadir.path().to_path_buf(),
            secret_file: Some(execution_node.datadir.path().join("jwt.hex")),
            ..Default::default()
        });

        // Construct beacon node using the config,
        let beacon_node = self.configured_beacon_node(beacon_config).await?;

        Ok((beacon_node, execution_node))
    }

    /// Adds a beacon node, connecting to node zero through discovery or a static simulation peer.
    pub async fn add_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
        is_proposer: bool,
    ) -> Result<(), String> {
        let first_bn_exists: bool;
        {
            let read_lock = self.beacon_nodes.read();
            let boot_node = read_lock.first();
            first_bn_exists = boot_node.is_some();

            if let Some(boot_node) = boot_node {
                // Modify beacon_config to add boot node details.
                #[cfg(not(madsim))]
                beacon_config.network.boot_nodes_enr.push(
                    boot_node
                        .client
                        .enr()
                        .expect("Bootnode must have a network."),
                );
                #[cfg(madsim)]
                {
                    let enr = boot_node.client.enr().ok_or("boot node has no ENR")?;
                    if !beacon_config.network.disable_discovery {
                        beacon_config.network.boot_nodes_enr.push(enr);
                    } else {
                        let ip = enr
                            .ip4()
                            .ok_or("simulation boot node has no IPv4 address")?;
                        let port = enr.tcp4().ok_or("simulation boot node has no TCP port")?;
                        let address = format!("/ip4/{ip}/tcp/{port}")
                            .parse()
                            .map_err(|error| format!("invalid static simulation peer: {error}"))?;
                        beacon_config.network.boot_nodes_multiaddr.push(address);
                    }
                }
            }
        }
        let (beacon_node, execution_node) = if first_bn_exists {
            // Network already exists. We construct a new node.
            self.construct_beacon_node(beacon_config, mock_execution_config, is_proposer)
                .await?
        } else {
            // Network does not exist. We construct a boot node.
            self.construct_boot_node(beacon_config, mock_execution_config)
                .await?
        };
        // Add nodes to the network.
        self.execution_nodes.write().push(execution_node);
        if is_proposer {
            self.proposer_nodes.write().push(beacon_node);
        } else {
            self.beacon_nodes.write().push(beacon_node);
        }
        Ok(())
    }

    // Add a new node with a delay. This node will not have validators and is only used to test
    // sync.
    pub async fn add_beacon_node_with_delay(
        &self,
        beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
        wait_until_epoch: u64,
        slot_duration: Duration,
        slots_per_epoch: u64,
    ) -> Result<(), String> {
        epoch_delay(Epoch::new(wait_until_epoch), slot_duration, slots_per_epoch).await;

        self.add_beacon_node(beacon_config, mock_execution_config, false)
            .await?;

        Ok(())
    }

    /// Adds a validator client to the network, connecting it to the beacon node with index
    /// `beacon_node`.
    pub async fn add_validator_client(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_node: usize,
        validator_files: ValidatorFiles,
    ) -> Result<(), String> {
        let context = self.context.clone();
        let self_1 = self.clone();
        let socket_addr = {
            let read_lock = self.beacon_nodes.read();
            let beacon_node = read_lock
                .get(beacon_node)
                .ok_or_else(|| format!("No beacon node for index {}", beacon_node))?;
            beacon_node
                .client
                .http_api_listen_addr()
                .expect("Must have http started")
        };
        // If there is a proposer node for the same index, we will use that for proposing
        let proposer_socket_addr = {
            let read_lock = self.proposer_nodes.read();
            read_lock.get(beacon_node).map(|proposer_node| {
                proposer_node
                    .client
                    .http_api_listen_addr()
                    .expect("Must have http started")
            })
        };

        let beacon_node = SensitiveUrl::parse(
            format!("http://{}:{}", socket_addr.ip(), socket_addr.port()).as_str(),
        )
        .unwrap();
        validator_config.beacon_nodes = vec![beacon_node];

        // If we have a proposer node established, use it.
        if let Some(proposer_socket_addr) = proposer_socket_addr {
            let url = SensitiveUrl::parse(
                format!(
                    "http://{}:{}",
                    proposer_socket_addr.ip(),
                    proposer_socket_addr.port()
                )
                .as_str(),
            )
            .unwrap();
            validator_config.proposer_nodes = vec![url];
        }

        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;
        self_1.validator_clients.write().push(validator_client);
        Ok(())
    }

    pub async fn add_validator_client_with_fallbacks(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_nodes: Vec<usize>,
        validator_files: ValidatorFiles,
    ) -> Result<(), String> {
        let context = self.context.clone();
        let self_1 = self.clone();
        let mut beacon_node_urls = vec![];
        for beacon_node in beacon_nodes {
            let socket_addr = {
                let read_lock = self.beacon_nodes.read();
                let beacon_node = read_lock
                    .get(beacon_node)
                    .ok_or_else(|| format!("No beacon node for index {}", beacon_node))?;
                beacon_node
                    .client
                    .http_api_listen_addr()
                    .expect("Must have http started")
            };
            let beacon_node_url = SensitiveUrl::parse(
                format!("http://{}:{}", socket_addr.ip(), socket_addr.port()).as_str(),
            )
            .unwrap();
            beacon_node_urls.push(beacon_node_url);
        }

        validator_config.beacon_nodes = beacon_node_urls;

        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;
        self_1.validator_clients.write().push(validator_client);
        Ok(())
    }

    /// For all beacon nodes in `Self`, return a HTTP client to access each nodes HTTP API.
    pub fn remote_nodes(&self) -> Result<Vec<BeaconNodeHttpClient>, String> {
        let beacon_nodes = self.beacon_nodes.read();
        let proposer_nodes = self.proposer_nodes.read();

        beacon_nodes
            .iter()
            .chain(proposer_nodes.iter())
            .map(|beacon_node| beacon_node.remote_node())
            .collect()
    }

    /// Return current epoch of bootnode.
    pub async fn _bootnode_epoch(&self) -> Result<Epoch, String> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        bootnode
            .get_beacon_states_finality_checkpoints(StateId::Head)
            .await
            .map_err(|e| format!("Cannot get head: {:?}", e))
            .map(|body| body.unwrap().data.finalized.epoch)
    }

    pub async fn duration_to_genesis(&self) -> Result<Duration, &'static str> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let genesis_time = Duration::from_secs(
            bootnode
                .get_beacon_genesis()
                .await
                .unwrap()
                .data
                .genesis_time,
        );
        genesis_time.checked_sub(now).ok_or(
            "The genesis time has already passed since all nodes started. The node startup time \
            may have regressed, and the current `GENESIS_DELAY` is no longer sufficient.",
        )
    }
}
