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
        ClientConfig, MockExecutionConfig, ValidatorFiles, testing_validator_config,
    };
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use serde::Serialize;
    use simulator::local_network::{LocalNetwork, LocalNetworkParams};
    use std::{collections::BTreeMap, io::Write, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::time::{Instant, sleep, sleep_until};
    use types::{Checkpoint, Epoch, Hash256, MinimalEthSpec};

    const VALIDATORS_PER_NODE: usize = 32;
    const GENESIS_DELAY: u64 = 38;
    const END_SLOT: u64 = 128;
    const LATE_JOIN_SLOT: u64 = 80;

    #[derive(Clone, Copy, PartialEq)]
    enum Scenario {
        Baseline,
        Faults,
    }

    impl Scenario {
        fn name(self) -> &'static str {
            match self {
                Self::Baseline => "baseline",
                Self::Faults => "faults",
            }
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
        },
        Passed {
            slot: u64,
            head_root: Hash256,
            finalized_epoch: Epoch,
            partition_observed: bool,
            optimism_observed: bool,
            proposals_resumed: [bool; 2],
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
            output.push(Snapshot {
                slot: head.head_slot().as_u64(),
                root: head.head_block_root(),
                proposer: head.snapshot.beacon_block.message().proposer_index(),
                finalized: head.finalized_checkpoint(),
                optimistic: chain
                    .is_optimistic_or_invalid_head()
                    .map_err(|error| format!("execution verdict: {error:?}"))?,
            });
        }
        Ok(())
    }

    fn node_config(mut config: ClientConfig, index: usize) -> ClientConfig {
        let ip = Ipv4Addr::new(10, 0, 0, index as u8 + 1);
        let port = 42424 + index as u16;
        config
            .network
            .set_ipv4_listening_address(ip, port, port, 43424 + index as u16);
        config.network.enr_address = (Some(ip), None);
        config.network.disable_discovery = true;
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
    ) -> Result<(), String> {
        host.spawn(async move {
            network
                .add_beacon_node(node_config(config, index), execution, false)
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
            Some(_) => return Err("scenario must be baseline or faults".into()),
        };
        if args.next().is_some() {
            return Err("usage: deterministic-simulation [seed] [baseline|faults]".into());
        }
        let mut runtime = Runtime::with_seed_and_config(seed, Default::default());
        task_executor::initialize_simulation_rayon()
            .map_err(|error| format!("simulation Rayon initialization: {error}"))?;
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
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
        let supervisor = runtime
            .create_node()
            .ip(Ipv4Addr::new(10, 0, 0, 100).into())
            .build();
        let stop_hosts = hosts.clone();
        let result = runtime
            .block_on(supervisor.spawn(async move {
                simulation_guard::install()?;
                world(seed, scenario, hosts).await
            }))
            .map_err(|error| format!("simulation supervisor: {error}"))?;
        for host in stop_hosts {
            runtime.handle().kill(host.id());
        }
        result?;
        emit(Event::Stopped)
    }

    async fn world(seed: u64, scenario: Scenario, hosts: Vec<NodeHandle>) -> Result<(), String> {
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
        for (index, host) in hosts.iter().take(2).enumerate() {
            start_node(
                host,
                network.clone(),
                config.clone(),
                execution.clone(),
                index,
            )
            .await?;
        }
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
        // HTTP connections have the ordinary five-second graceful-drain budget.
        sleep(Duration::from_secs(6)).await;
        drop(network);
        environment.shutdown_on_idle();
        result
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
        emit(Event::Manifest {
            seed,
            scenario: scenario.name(),
            partition,
            heal,
            execution_syncing,
            execution_valid,
            late_join: LATE_JOIN_SLOT,
            end: END_SLOT,
        })?;
        let net = plugin::simulator::<NetSim>();
        let mut finalized_roots = BTreeMap::new();
        let mut last_finalized = [Epoch::new(0); 3];
        let mut saw_partition = false;
        let mut saw_optimism = false;
        let mut proposals_resumed = [false; 2];
        let mut observed = Vec::with_capacity(3);
        for slot in 0..=END_SLOT {
            sleep_until(genesis + slot_duration * slot as u32 + slot_duration * 3 / 4).await;
            if scenario == Scenario::Faults {
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
                )
                .await?;
                emit(Event::Fault {
                    slot,
                    action: "late_join",
                })?;
            }
            snapshots(&network, &mut observed)?;
            for (index, snapshot) in observed.iter().enumerate() {
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
                })?;
            }
            if observed[0].slot > execution_valid + 8 && !observed[0].optimistic {
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
        if scenario == Scenario::Faults && (!saw_partition || !saw_optimism) {
            return Err(format!(
                "faults were not observed: partition={saw_partition}, optimism={saw_optimism}"
            ));
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
                    || snapshot.slot < END_SLOT - 1
                    || snapshot.finalized.epoch < Epoch::new(12)
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
        emit(Event::Passed {
            slot: END_SLOT,
            head_root: expected.root,
            finalized_epoch: expected.finalized.epoch,
            partition_observed: saw_partition,
            optimism_observed: saw_optimism,
            proposals_resumed,
        })
    }
}
