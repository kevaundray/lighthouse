//! Whole-node execution over a controlled runtime, not direct fork-choice injection.

#[cfg(madsim)]
mod simulation_guard;

#[cfg(not(madsim))]
fn main() -> Result<(), String> {
    Err(
        "build with --config .cargo/config-simulation.toml; see testing/whole_node_simulation.md"
            .into(),
    )
}

#[cfg(madsim)]
fn main() -> Result<(), String> {
    const CHILD: &str = "LIGHTHOUSE_SIMULATION_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return simulation::run();
    }
    // Isolate synchronous fixture files between concurrent replays. Only the
    // fresh child constructs a runtime, so host setup cannot pre-seed its hashes.
    let directory = tempfile::tempdir().map_err(|error| format!("fixture directory: {error}"))?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let status = std::process::Command::new(executable)
        .args(std::env::args_os().skip(1))
        .env(CHILD, "1")
        .env("TMPDIR", directory.path())
        .status()
        .map_err(|error| format!("simulation child: {error}"))?;
    if !status.success() {
        return Err(format!("simulation child failed: {status}"));
    }
    Ok(())
}

#[cfg(madsim)]
mod simulation {
    use super::simulation_guard;
    use environment::EnvironmentBuilder;
    use madsim::{
        net::NetSim,
        plugin,
        runtime::{NodeHandle, Runtime},
    };
    use node_test_rig::{
        ClientConfig, LocalBeaconNode, MockExecutionConfig, ValidatorFiles,
        testing_validator_config,
    };
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use serde::Serialize;
    use simulator::local_network::{LocalNetwork, LocalNetworkParams};
    use std::{collections::BTreeMap, io::Write, net::Ipv4Addr, sync::Arc, time::Duration};
    use store::{SimulationCrash, SimulationStorage};
    use tokio::time::{Instant, sleep, sleep_until};
    use types::{Checkpoint, Epoch, ForkName, Hash256, MinimalEthSpec, Slot};

    const VALIDATORS_PER_NODE: usize = 32;
    const GENESIS_DELAY: u64 = 38;
    const END_SLOT: u64 = 128;
    const LATE_JOIN_SLOT: u64 = 80;

    #[derive(Clone, Copy, PartialEq)]
    enum Scenario {
        Baseline,
        Faults,
        Discovery,
        Restart,
        Storage,
        Forks,
    }

    impl Scenario {
        fn name(self) -> &'static str {
            match self {
                Self::Baseline => "baseline",
                Self::Faults => "faults",
                Self::Discovery => "discovery",
                Self::Restart => "restart",
                Self::Storage => "storage",
                Self::Forks => "forks",
            }
        }

        fn restarts(self) -> bool {
            matches!(self, Self::Restart | Self::Storage)
        }

        fn link_faults(self) -> bool {
            matches!(self, Self::Faults | Self::Discovery | Self::Forks)
        }
    }

    #[derive(Serialize)]
    #[serde(tag = "event", rename_all = "snake_case")]
    enum Event {
        Manifest {
            seed: u64,
            scenario: &'static str,
            partition: u64,
            heal: u64,
            execution_syncing: u64,
            execution_valid: u64,
            late_join: u64,
            process_crash: Option<u64>,
            storage_failure: Option<u64>,
            fork_slots: [u64; 1],
            end: u64,
        },
        Fault {
            slot: u64,
            action: &'static str,
        },
        Observation {
            slot: u64,
            node: usize,
            head_slot: u64,
            head_root: Hash256,
            proposer: u64,
            finalized_epoch: Epoch,
            finalized_root: Hash256,
            optimistic: bool,
            fork: ForkName,
        },
        Crash {
            slot: u64,
            node: usize,
            mode: &'static str,
            head_slot: u64,
            finalized_epoch: Epoch,
            observed_storage_faults: u64,
        },
        Restarted {
            slot: u64,
            node: usize,
            head_slot: u64,
            head_root: Hash256,
            finalized_epoch: Epoch,
        },
        DiscoverySessions {
            node: usize,
            active_sessions: usize,
            bytes_sent: usize,
            bytes_received: usize,
        },
        PeerRecovery {
            slot: u64,
            node: usize,
            peers: serde_json::Value,
        },
        Passed {
            slot: u64,
            head_root: Hash256,
            finalized_epoch: Epoch,
            partition_observed: bool,
            optimism_observed: bool,
            proposals_resumed: [bool; 2],
            restarted: bool,
            storage_failure_observed: bool,
            forks_observed: Vec<ForkName>,
        },
        Stopped,
    }

    fn emit(event: Event) -> Result<(), String> {
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        serde_json::to_writer(&mut output, &event).map_err(|error| error.to_string())?;
        writeln!(output).map_err(|error| error.to_string())
    }

    #[derive(Clone, Copy)]
    struct Snapshot {
        slot: u64,
        root: Hash256,
        proposer: u64,
        finalized: Checkpoint,
        optimistic: bool,
        fork: ForkName,
    }

    fn snapshots(
        network: &LocalNetwork<MinimalEthSpec>,
        output: &mut Vec<Snapshot>,
    ) -> Result<(), String> {
        output.clear();
        for node in network.beacon_nodes.read().iter() {
            let chain = node
                .client
                .beacon_chain()
                .ok_or("node has no beacon chain")?;
            if chain.canonical_head.fork_choice_poisoned() {
                return Err("node poisoned fork choice".into());
            }
            let head = chain.head();
            let fork = head
                .snapshot
                .beacon_block
                .fork_name(&chain.spec)
                .map_err(|error| format!("head fork disagrees with its slot: {error:?}"))?;
            let state_fork = head
                .snapshot
                .beacon_state
                .fork_name(&chain.spec)
                .map_err(|error| format!("head state fork disagrees with its slot: {error:?}"))?;
            if fork != state_fork {
                return Err("canonical head block and state have different forks".into());
            }
            output.push(Snapshot {
                slot: head.head_slot().as_u64(),
                root: head.head_block_root(),
                proposer: head.snapshot.beacon_block.message().proposer_index(),
                finalized: head.finalized_checkpoint(),
                fork,
                optimistic: chain
                    .is_optimistic_or_invalid_head()
                    .map_err(|error| format!("execution verdict: {error:?}"))?,
            });
        }
        Ok(())
    }

    fn node_config(mut config: ClientConfig, index: usize, scenario: Scenario) -> ClientConfig {
        let ip = Ipv4Addr::new(10, 0, 0, index as u8 + 1);
        let port = 42424 + index as u16;
        config
            .network
            .set_ipv4_listening_address(ip, port, port, 43424 + index as u16);
        config.network.enr_address = (Some(ip), None);
        config.network.disable_discovery = scenario != Scenario::Discovery;
        config.network.disable_peer_scoring = false;
        config.network.trusted_peers.clear();
        config.network.discv5_config.listen_config = discv5::ListenConfig::Ipv4 { ip, port };
        config.network.disable_quic_support = true;
        config.network.upnp_enabled = false;
        config.network.metrics_enabled = false;
        config.network.enable_mplex = false;
        config.network.boot_nodes_enr.clear();
        config.http_api.listen_addr = ip.into();
        config.http_metrics.enabled = false;
        config.slasher = None;
        config.monitoring_api = None;
        config
    }

    async fn start_node(
        host: &NodeHandle,
        network: LocalNetwork<MinimalEthSpec>,
        config: ClientConfig,
        execution: MockExecutionConfig,
        index: usize,
        scenario: Scenario,
    ) -> Result<(), String> {
        host.spawn(async move {
            let mut execution = execution;
            if scenario.restarts() {
                execution.server_config.listen_addr = Ipv4Addr::new(10, 0, 1, index as u8 + 1);
            }
            network
                .add_beacon_node(node_config(config, index, scenario), execution, false)
                .await?;
            network.execution_nodes.read()[index]
                .server
                .all_payloads_valid();
            Ok::<(), String>(())
        })
        .await
        .map_err(|error| format!("node {index} startup task: {error}"))?
    }

    pub fn run() -> Result<(), String> {
        // Do not initialize clap/logging/Rayon HashMaps before MadSim seeds the
        // standard library's thread-local RandomState. Each replay is a process.
        let mut args = std::env::args().skip(1);
        let seed = args
            .next()
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|error| format!("expected decimal seed: {error}"))?
            .unwrap_or(42);
        let scenario = match args.next().as_deref() {
            None | Some("faults") => Scenario::Faults,
            Some("baseline") => Scenario::Baseline,
            Some("discovery") => Scenario::Discovery,
            Some("restart") => Scenario::Restart,
            Some("storage") => Scenario::Storage,
            Some("forks") => Scenario::Forks,
            Some(_) => {
                return Err(
                    "scenario must be baseline, faults, discovery, restart, storage, or forks"
                        .into(),
                );
            }
        };
        if args.next().is_some() {
            return Err("usage: deterministic-simulation [seed] [baseline|faults|discovery|restart|storage|forks]".into());
        }
        let mut runtime = Runtime::with_seed_and_config(seed, Default::default());
        runtime.add_simulator::<discv5::SimulationState>();
        task_executor::initialize_simulation_rayon()
            .map_err(|error| format!("simulation Rayon initialization: {error}"))?;
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_new(
                    std::env::var("RUST_LOG").unwrap_or_else(|_| "error".into()),
                )
                .map_err(|error| format!("simulation log filter: {error}"))?,
            )
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|error| format!("simulation logging: {error}"))?;
        runtime.set_time_limit(Duration::from_secs(2000));
        let hosts: Vec<_> = (1..=3)
            .map(|index| {
                runtime
                    .create_node()
                    .ip(Ipv4Addr::new(10, 0, 0, index).into())
                    .build()
            })
            .collect();
        let execution_hosts: Vec<_> = if scenario.restarts() {
            (1..=3)
                .map(|index| {
                    runtime
                        .create_node()
                        .ip(Ipv4Addr::new(10, 0, 1, index).into())
                        .build()
                })
                .collect()
        } else {
            vec![]
        };
        let supervisor = runtime
            .create_node()
            .ip(Ipv4Addr::new(10, 0, 0, 100).into())
            .build();
        let stop_hosts: Vec<_> = hosts.iter().chain(&execution_hosts).cloned().collect();
        let result = runtime
            .block_on(supervisor.spawn(async move {
                simulation_guard::install()?;
                world(seed, scenario, hosts, execution_hosts).await
            }))
            .map_err(|error| format!("simulation supervisor: {error}"))?;
        for host in stop_hosts {
            runtime.handle().kill(host.id());
        }
        result?;
        emit(Event::Stopped)
    }

    async fn world(
        seed: u64,
        scenario: Scenario,
        hosts: Vec<NodeHandle>,
        execution_hosts: Vec<NodeHandle>,
    ) -> Result<(), String> {
        let mut environment = EnvironmentBuilder::minimal()
            .multi_threaded_tokio_runtime()?
            .build()?;
        let mut spec = (*environment.eth2_config.spec)
            .clone()
            .set_slot_duration_ms::<MinimalEthSpec>(3000);
        spec.genesis_delay = GENESIS_DELAY;
        spec.min_genesis_time = 0;
        spec.min_genesis_active_validator_count = (2 * VALIDATORS_PER_NODE) as u64;
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(0));
        spec.deneb_fork_epoch = Some(Epoch::new(0));
        spec.electra_fork_epoch = Some(Epoch::new(0));
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = None;
        if scenario == Scenario::Forks {
            spec.gloas_fork_epoch = Some(Epoch::new(12));
        }
        let slot_duration = spec.get_slot_duration();
        environment.eth2_config.spec = Arc::new(spec);
        let (network, config, execution) = LocalNetwork::create_local_network(
            None,
            None,
            LocalNetworkParams {
                validator_count: 2 * VALIDATORS_PER_NODE,
                node_count: 2,
                proposer_nodes: 0,
                extra_nodes: 1,
                genesis_delay: GENESIS_DELAY,
            },
            environment.core_context(),
        )
        .await?;
        *network.execution_hosts.write() = execution_hosts;
        for (index, host) in hosts.iter().take(2).enumerate() {
            start_node(
                host,
                network.clone(),
                config.clone(),
                execution.clone(),
                index,
                scenario,
            )
            .await?;
        }
        if scenario != Scenario::Discovery {
            // Bootstrap multiaddresses are one-shot dials. With discovery disabled,
            // configure persistent static peering through the real operator API.
            // Trusted-peer scoring is intentionally outside this topology's coverage.
            let peers = network
                .beacon_nodes
                .read()
                .iter()
                .map(|node| {
                    node.client
                        .enr()
                        .map(|enr| node_test_rig::eth2::types::AdminPeer {
                            enr: enr.to_base64(),
                        })
                        .ok_or("static peer has no ENR")
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (index, remote) in network.remote_nodes()?.into_iter().enumerate() {
                remote
                    .post_lighthouse_add_peer(peers[1 - index].clone())
                    .await
                    .map_err(|error| format!("configure static peer for node {index}: {error}"))?;
            }
        }
        let mut initial = Vec::with_capacity(3);
        snapshots(&network, &mut initial)?;
        if initial[0].root != initial[1].root {
            return Err("independent nodes did not construct the same genesis".into());
        }
        let until_genesis = network.duration_to_genesis().await.map_err(str::to_owned)?;
        let genesis = Instant::now() + until_genesis;
        // VC service startup waits for genesis. Start both concurrently and
        // anchor observations before awaiting their readiness.
        let mut validator_starts = Vec::with_capacity(2);
        for (index, host) in hosts.iter().take(2).enumerate() {
            let network = network.clone();
            validator_starts.push(host.spawn(async move {
                let indices: Vec<_> =
                    (index * VALIDATORS_PER_NODE..(index + 1) * VALIDATORS_PER_NODE).collect();
                let files = ValidatorFiles::with_keystores(&indices)?;
                let mut validator = testing_validator_config();
                validator.http_metrics.enabled = false;
                validator.monitoring_api = None;
                validator.http_api.enabled = false;
                validator.validator_store.fee_recipient = Some([1u8; 20].into());
                // Only this node receives submissions through the Validator API.
                // Other nodes must learn blocks/votes over the production p2p stack.
                network.add_validator_client(validator, index, files).await
            }));
        }
        for (index, startup) in validator_starts.into_iter().enumerate() {
            startup
                .await
                .map_err(|error| format!("validator {index} startup task: {error}"))??;
        }
        let workload = exercise(
            seed,
            scenario,
            network.clone(),
            config,
            execution,
            hosts,
            genesis,
            slot_duration,
        );
        let result = tokio::select! {
            result = workload => result,
            reason = environment.shutdown_requested() => Err(format!("unexpected node shutdown: {reason:?}")),
        };
        environment.fire_signal();
        network.stop_beacon_nodes();
        // HTTP connections have the ordinary five-second graceful-drain budget.
        sleep(Duration::from_secs(6)).await;
        drop(network);
        environment.shutdown_on_idle();
        result
    }

    struct PendingRestart {
        config: ClientConfig,
        datadir: Arc<tempfile::TempDir>,
        storage: SimulationStorage,
        canonical_roots: Vec<Hash256>,
        first_ancestry_slot: u64,
        restart_at: u64,
    }

    fn crash_node(
        network: &LocalNetwork<MinimalEthSpec>,
        host: &NodeHandle,
        slot: u64,
        mode: SimulationCrash,
    ) -> Result<PendingRestart, String> {
        let node = network
            .beacon_nodes
            .write()
            .pop()
            .ok_or("missing crash target")?;
        let chain = node
            .client
            .beacon_chain()
            .ok_or("crash target has no chain")?;
        let head = chain.head();
        if head.head_slot().as_u64() + 2 < slot {
            return Err("crash target had not caught up before the crash".into());
        }
        let first_ancestry_slot = head
            .head_slot()
            .as_u64()
            .saturating_sub(<MinimalEthSpec as types::EthSpec>::slots_per_historical_root() as u64);
        let mut canonical_roots = (first_ancestry_slot..head.head_slot().as_u64())
            .map(|slot| {
                head.snapshot
                    .beacon_state
                    .get_block_root(Slot::new(slot))
                    .copied()
                    .map_err(|error| format!("pre-crash ancestry: {error:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        canonical_roots.push(head.head_block_root());
        let pending = PendingRestart {
            config: network.beacon_configs.read()[2].clone(),
            datadir: node.datadir.clone(),
            storage: node.simulation_storage.clone(),
            canonical_roots,
            first_ancestry_slot,
            restart_at: slot + 2,
        };
        emit(Event::Crash {
            slot,
            node: 2,
            mode: match mode {
                SimulationCrash::Process => "process",
                SimulationCrash::PowerLoss => "power_loss",
            },
            head_slot: head.head_slot().as_u64(),
            finalized_epoch: head.finalized_checkpoint().epoch,
            observed_storage_faults: pending.storage.observed_fault_count(),
        })?;
        // Fence before cancellation/destructors: abrupt crashes must never acquire
        // the durability of BeaconChain's graceful Drop persistence.
        pending.storage.crash(mode);
        madsim::runtime::Handle::current().kill(host.id());
        drop(head);
        drop(chain);
        drop(node);
        Ok(pending)
    }

    async fn restart_node(
        network: LocalNetwork<MinimalEthSpec>,
        old_host: &NodeHandle,
        pending: PendingRestart,
        slot: u64,
    ) -> Result<Epoch, String> {
        let runtime = madsim::runtime::Handle::current();
        runtime.restart(old_host.id());
        let host = runtime
            .get_node(old_host.id())
            .ok_or("restarted host is absent")?;
        host.spawn(async move {
            let context = network.fresh_beacon_context(2);
            let node = LocalBeaconNode::production_with_simulation_storage(
                context,
                pending.config,
                pending.datadir,
                pending.storage,
            )
            .await?;
            let chain = node
                .client
                .beacon_chain()
                .ok_or("restarted node has no chain")?;
            let head = chain.head();
            let restored_slot = head.head_slot().as_u64();
            if restored_slot == 0
                || restored_slot
                    .checked_sub(pending.first_ancestry_slot)
                    .and_then(|offset| pending.canonical_roots.get(offset as usize))
                    != Some(&head.head_block_root())
            {
                return Err(
                    "restart did not restore a non-genesis canonical checkpoint from storage"
                        .into(),
                );
            }
            let finalized = head.finalized_checkpoint();
            if chain.canonical_head.fork_choice_poisoned() {
                return Err("freshly reopened fork choice is poisoned".into());
            }
            emit(Event::Restarted {
                slot,
                node: 2,
                head_slot: restored_slot,
                head_root: head.head_block_root(),
                finalized_epoch: finalized.epoch,
            })?;
            drop(head);
            drop(chain);
            network.beacon_nodes.write().push(node);
            Ok(finalized.epoch)
        })
        .await
        .map_err(|error| format!("node restart task: {error}"))?
    }

    async fn observe_untrusted_peers(
        network: &LocalNetwork<MinimalEthSpec>,
        slot: u64,
    ) -> Result<(), String> {
        let client = reqwest::Client::new();
        for (index, remote) in network.remote_nodes()?.iter().enumerate() {
            let url = remote
                .server()
                .expose_full()
                .join("lighthouse/peers")
                .map_err(|error| format!("peer observation URL: {error}"))?;
            let mut peers: serde_json::Value = client
                .get(url)
                .timeout(Duration::from_secs(8))
                .send()
                .await
                .map_err(|error| format!("peer observation: {error}"))?
                .error_for_status()
                .map_err(|error| format!("peer observation status: {error}"))?
                .json()
                .await
                .map_err(|error| format!("peer observation response: {error}"))?;
            for peer in peers
                .as_array_mut()
                .ok_or("peer response is not an array")?
            {
                let info = peer
                    .get_mut("peer_info")
                    .and_then(serde_json::Value::as_object_mut)
                    .ok_or("peer response has no peer info")?;
                if info.get("is_trusted").and_then(serde_json::Value::as_bool) != Some(false) {
                    return Err("discovery scenario used a trusted peer".into());
                }
                info.retain(|field, _| {
                    matches!(field.as_str(), "is_trusted" | "connection_status" | "score")
                });
            }
            emit(Event::PeerRecovery {
                slot,
                node: index,
                peers,
            })?;
        }
        Ok(())
    }

    async fn exercise(
        seed: u64,
        scenario: Scenario,
        network: LocalNetwork<MinimalEthSpec>,
        config: ClientConfig,
        execution: MockExecutionConfig,
        hosts: Vec<NodeHandle>,
        genesis: Instant,
        slot_duration: Duration,
    ) -> Result<(), String> {
        let mut fault_rng = StdRng::seed_from_u64(seed);
        let partition = 40 + fault_rng.random_range(0..3u64);
        let heal = partition + 16;
        let execution_syncing = heal + 8;
        let execution_valid = execution_syncing + 8;
        let restart_fault = partition + 54;
        let proposals_after = match scenario {
            Scenario::Forks => 104,
            Scenario::Restart | Scenario::Storage => restart_fault + 16,
            _ => execution_valid + 8,
        };
        // Scoring uses real seconds (600-second half-life), not accelerated epochs.
        // Allow normal score decay, discovery/redial and fresh finality without
        // changing production thresholds or trusting a disconnected peer.
        let end_slot = if scenario == Scenario::Discovery {
            512
        } else {
            END_SLOT
        };
        emit(Event::Manifest {
            seed,
            scenario: scenario.name(),
            partition,
            heal,
            execution_syncing,
            execution_valid,
            late_join: LATE_JOIN_SLOT,
            process_crash: (scenario == Scenario::Restart).then_some(restart_fault),
            storage_failure: (scenario == Scenario::Storage).then_some(restart_fault),
            fork_slots: if scenario == Scenario::Forks {
                [96]
            } else {
                [0]
            },
            end: end_slot,
        })?;
        let net = plugin::simulator::<NetSim>();
        let mut finalized_roots = BTreeMap::new();
        let mut last_finalized = [Epoch::new(0); 3];
        let mut saw_partition = false;
        let mut saw_optimism = false;
        let mut proposals_resumed = [false; 2];
        let mut observed = Vec::with_capacity(3);
        let mut pending_restart = None;
        let mut restarted = false;
        let mut storage_failure_observed = false;
        let mut forks_observed = Vec::with_capacity(2);
        for slot in 0..=end_slot {
            sleep_until(genesis + slot_duration * slot as u32 + slot_duration * 3 / 4).await;
            if scenario.link_faults() {
                if slot == partition {
                    net.clog_link(hosts[0].id(), hosts[1].id());
                    net.clog_link(hosts[1].id(), hosts[0].id());
                    emit(Event::Fault {
                        slot,
                        action: "partition",
                    })?;
                } else if slot == heal {
                    net.unclog_link(hosts[0].id(), hosts[1].id());
                    net.unclog_link(hosts[1].id(), hosts[0].id());
                    emit(Event::Fault {
                        slot,
                        action: "heal",
                    })?;
                } else if slot == execution_syncing {
                    // Model an EL that learns payloads while reporting SYNCING,
                    // then completes that sync at execution_valid.
                    network.execution_nodes.read()[1]
                        .server
                        .all_payloads_syncing(true);
                    emit(Event::Fault {
                        slot,
                        action: "execution_syncing",
                    })?;
                } else if slot == execution_valid {
                    network.execution_nodes.read()[1]
                        .server
                        .all_payloads_valid();
                    emit(Event::Fault {
                        slot,
                        action: "execution_valid",
                    })?;
                }
            }
            if slot == LATE_JOIN_SLOT {
                start_node(
                    &hosts[2],
                    network.clone(),
                    config.clone(),
                    execution.clone(),
                    2,
                    scenario,
                )
                .await?;
                emit(Event::Fault {
                    slot,
                    action: "late_join",
                })?;
            }
            if slot == restart_fault && scenario == Scenario::Storage {
                network.beacon_nodes.read()[2]
                    .simulation_storage
                    .arm_failed_next_block_batch();
                emit(Event::Fault {
                    slot,
                    action: "storage_failure",
                })?;
            }
            let storage_failed = scenario == Scenario::Storage
                && !restarted
                && pending_restart.is_none()
                && network
                    .beacon_nodes
                    .read()
                    .get(2)
                    .is_some_and(|node| node.simulation_storage.observed_fault_count() > 0);
            for index in 0..network.beacon_node_count() {
                if let Some(reason) = network.node_shutdown(index) {
                    if !(storage_failed
                        && index == 2
                        && reason
                            == task_executor::ShutdownReason::Failure(
                                "Database write failure during block import",
                            ))
                    {
                        return Err(format!("unexpected shutdown from node {index}: {reason:?}"));
                    }
                    storage_failure_observed = true;
                }
            }
            if storage_failed {
                let poisoned = network.beacon_nodes.read()[2]
                    .client
                    .beacon_chain()
                    .ok_or("failed node has no chain")?
                    .canonical_head
                    .fork_choice_poisoned();
                if !storage_failure_observed || !poisoned {
                    return Err(
                        "failed block write did not poison fork choice and request shutdown".into(),
                    );
                }
                pending_restart = Some(crash_node(
                    &network,
                    &hosts[2],
                    slot,
                    SimulationCrash::PowerLoss,
                )?);
            } else if slot == restart_fault && scenario == Scenario::Restart {
                emit(Event::Fault {
                    slot,
                    action: "process_crash",
                })?;
                pending_restart = Some(crash_node(
                    &network,
                    &hosts[2],
                    slot,
                    SimulationCrash::Process,
                )?);
            }
            if pending_restart
                .as_ref()
                .is_some_and(|pending: &PendingRestart| slot == pending.restart_at)
            {
                let pending = pending_restart.take().ok_or("missing restart state")?;
                let restored = restart_node(network.clone(), &hosts[2], pending, slot).await?;
                // A crash may discard a newer in-memory checkpoint. Keep the global
                // finalized-root oracle; start this process's monotonicity at its
                // explicitly recorded recovered checkpoint.
                last_finalized[2] = restored;
                restarted = true;
            }
            if scenario == Scenario::Storage
                && slot == restart_fault + 4
                && !storage_failure_observed
            {
                return Err("armed block-write failure was not exercised within four slots".into());
            }
            if scenario == Scenario::Discovery && slot == END_SLOT {
                observe_untrusted_peers(&network, slot).await?;
            }
            snapshots(&network, &mut observed)?;
            for (index, snapshot) in observed.iter().enumerate() {
                if index == 0 && forks_observed.last() != Some(&snapshot.fork) {
                    forks_observed.push(snapshot.fork);
                }
                if snapshot.finalized.epoch < last_finalized[index] {
                    return Err(format!("node {index} reverted finality at slot {slot}"));
                }
                last_finalized[index] = snapshot.finalized.epoch;
                if snapshot.finalized.epoch > Epoch::new(0) {
                    if let Some(previous) =
                        finalized_roots.insert(snapshot.finalized.epoch, snapshot.finalized.root)
                    {
                        if previous != snapshot.finalized.root {
                            return Err(format!(
                                "conflicting finalized roots at epoch {}",
                                snapshot.finalized.epoch
                            ));
                        }
                    }
                }
                emit(Event::Observation {
                    slot,
                    node: index,
                    head_slot: snapshot.slot,
                    head_root: snapshot.root,
                    proposer: snapshot.proposer,
                    finalized_epoch: snapshot.finalized.epoch,
                    finalized_root: snapshot.finalized.root,
                    optimistic: snapshot.optimistic,
                    fork: snapshot.fork,
                })?;
            }
            if observed[0].slot > proposals_after && !observed[0].optimistic {
                let group = observed[0].proposer as usize / VALIDATORS_PER_NODE;
                *proposals_resumed
                    .get_mut(group)
                    .ok_or("head proposer outside validator set")? = true;
            }
            if slot > partition && slot < heal && observed[0].root != observed[1].root {
                saw_partition = true;
            }
            if slot > execution_syncing && slot < execution_valid && observed[1].optimistic {
                saw_optimism = true;
            }
            if slot == 32
                && observed
                    .iter()
                    .any(|snapshot| snapshot.finalized.epoch != Epoch::new(2))
            {
                return Err("nodes did not finalize at the first opportunity before faults".into());
            }
        }
        if scenario.link_faults() && (!saw_partition || !saw_optimism) {
            return Err(format!(
                "faults were not observed: partition={saw_partition}, optimism={saw_optimism}"
            ));
        }
        if scenario.restarts() && !restarted {
            return Err("node never reopened from retained storage".into());
        }
        if scenario == Scenario::Forks && forks_observed != [ForkName::Fulu, ForkName::Gloas] {
            return Err(format!(
                "missing or out-of-order actual block fork transitions: {forks_observed:?}"
            ));
        }
        if scenario == Scenario::Discovery {
            observe_untrusted_peers(&network, end_slot).await?;
        }
        if proposals_resumed != [true; 2] {
            return Err(format!(
                "validator clients did not both resume proposals after recovery: {proposals_resumed:?}"
            ));
        }
        let expected = observed[0];
        if observed.len() != 3
            || observed.iter().any(|snapshot| {
                snapshot.root != expected.root
                    || snapshot.finalized != expected.finalized
                    || snapshot.slot < end_slot - 1
                    || snapshot.finalized.epoch < Epoch::new(end_slot / 8 - 4)
                    || snapshot.optimistic
            })
        {
            let mut peers = Vec::with_capacity(3);
            for remote in network.remote_nodes()? {
                peers.push(format!("{:?}", remote.get_node_peer_count().await));
            }
            return Err(format!(
                "nodes failed bounded head/finality/execution recovery, including the late joining node; peer counts: {peers:?}"
            ));
        }
        let finalized_slot = expected
            .finalized
            .epoch
            .start_slot(<MinimalEthSpec as types::EthSpec>::slots_per_epoch());
        for node in network.beacon_nodes.read().iter() {
            let chain = node
                .client
                .beacon_chain()
                .ok_or("node has no beacon chain")?;
            let head = chain.head();
            let ancestor = head
                .snapshot
                .beacon_state
                .get_block_root(finalized_slot)
                .map_err(|error| format!("finalized ancestry lookup: {error:?}"))?;
            if *ancestor != expected.finalized.root {
                return Err("finalized checkpoint is not in the canonical head ancestry".into());
            }
        }
        // Exercise the actual HTTP observation path as well as local safety state.
        for remote in network.remote_nodes()? {
            let block = remote
                .get_beacon_blocks::<MinimalEthSpec>(node_test_rig::eth2::types::BlockId::Head)
                .await
                .map_err(|error| format!("final HTTP head: {error}"))?
                .ok_or("final HTTP head is absent")?
                .into_data();
            if block.canonical_root() != expected.root {
                return Err("HTTP head disagrees with the converged node head".into());
            }
        }
        if scenario == Scenario::Discovery {
            for (index, host) in hosts.iter().enumerate() {
                let metrics = host
                    .spawn(async { discv5::Discv5::metrics() })
                    .await
                    .map_err(|error| format!("discovery observation task: {error}"))?;
                if metrics.active_sessions == 0
                    || metrics.bytes_sent == 0
                    || metrics.bytes_recv == 0
                {
                    return Err(format!(
                        "node {index} did not establish real UDP discovery sessions"
                    ));
                }
                emit(Event::DiscoverySessions {
                    node: index,
                    active_sessions: metrics.active_sessions,
                    bytes_sent: metrics.bytes_sent,
                    bytes_received: metrics.bytes_recv,
                })?;
            }
        }
        emit(Event::Passed {
            slot: end_slot,
            head_root: expected.root,
            finalized_epoch: expected.finalized.epoch,
            partition_observed: saw_partition,
            optimism_observed: saw_optimism,
            proposals_resumed,
            restarted,
            storage_failure_observed,
            forks_observed,
        })
    }
}
