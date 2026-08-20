#![cfg(all(feature = "pq-proposer", target_os = "linux"))]

use beacon_node::beacon_chain::{
    PqOperationalEvent, PqOperationalEventRole, PqOperationalEventSink,
};
use consensus_signature::PqValidatorRegistryEntry;
use execution_layer::auth::JwtKey;
use execution_layer::test_utils::{DEFAULT_JWT_SECRET, MockServer};
use fs2::FileExt;
use network_utils::enr_ext::EnrExt;
use pq_devnet::{production_config, provision_devnet};
use rusqlite::{Connection, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use types::{BeaconState, EthSpec, ExecutionBlockHash, ForkName, MinimalEthSpec, Uint256};
use validator_dir::{PqDevnetBundle, PqDevnetManifest};

const PQ_EVENT_PREFIX: &str = "PQ_EVENT_V1";
const MAX_LOG_FRAME_BYTES: usize = 64 * 1024;
const MAX_RETAINED_LOG_FRAMES: usize = 512;
const MAX_RETAINED_PQ_EVENTS: usize = 64;
const MAX_ENR_BYTES: u64 = 4096;
const MAX_TEMPLATE_ENTRIES: usize = 128;
const MAX_TEMPLATE_BYTES: u64 = 256 * 1024 * 1024;
const TEMPLATE_VERSION: &str = "pq-e4f-template-v1";
const PINNED_TEMPLATE_SEMANTIC_SHA256: &str =
    "0ce1ebc8555a9a65e11d470bda2f697f652b444acc4d1e214bf737288d76addb";
const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(900);
const STATUS_EVENT_TIMEOUT: Duration = Duration::from_secs(240);
const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct BoundedProcessLog {
    state: Mutex<BoundedProcessLogState>,
    changed: Condvar,
}

struct BoundedProcessLogState {
    frames: VecDeque<String>,
    events: VecDeque<PqProcessEvent>,
    event_failure: Option<PqProcessEventFailure>,
    next_event_sequence: u64,
}

impl Default for BoundedProcessLogState {
    fn default() -> Self {
        Self {
            frames: VecDeque::new(),
            events: VecDeque::new(),
            event_failure: None,
            next_event_sequence: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessRole {
    Proposer,
    Verifier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessStatusDirection {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessStatusRejection {
    ForkDigest,
    FinalizedEpoch,
    FinalizedRoot,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessEventKind {
    EventWriterReady,
    PeerConnected {
        peer_digest: [u8; 16],
        direction: PqProcessConnectionDirection,
    },
    StatusSent {
        peer_digest: [u8; 16],
        direction: PqProcessStatusDirection,
    },
    StatusRejected {
        peer_digest: [u8; 16],
        code: PqProcessStatusRejection,
    },
    PeerCompatible {
        peer_digest: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PqProcessEvent {
    sequence: u64,
    role: PqProcessRole,
    kind: PqProcessEventKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqProcessEventFailure {
    Malformed,
    Sequence,
    Capacity,
}

fn exact_field<'a>(field: &'a str, name: &str) -> Result<&'a str, PqProcessEventFailure> {
    field
        .strip_prefix(name)
        .filter(|value| !value.is_empty())
        .ok_or(PqProcessEventFailure::Malformed)
}

fn parse_peer_digest(field: &str) -> Result<[u8; 16], PqProcessEventFailure> {
    let encoded = exact_field(field, "peer_digest=")?;
    if encoded.len() != 32 || encoded.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let mut digest = [0; 16];
    hex::decode_to_slice(encoded, &mut digest).map_err(|_| PqProcessEventFailure::Malformed)?;
    Ok(digest)
}

fn parse_pq_process_event(line: &str) -> Result<PqProcessEvent, PqProcessEventFailure> {
    let fields = line.split(' ').collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) || fields.first() != Some(&PQ_EVENT_PREFIX) {
        return Err(PqProcessEventFailure::Malformed);
    }
    let event = exact_field(
        fields
            .get(1)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "event=",
    )?;
    let sequence_text = exact_field(
        fields
            .get(2)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "sequence=",
    )?;
    let sequence = sequence_text
        .parse::<u64>()
        .map_err(|_| PqProcessEventFailure::Malformed)?;
    if sequence.to_string() != sequence_text || sequence == 0 {
        return Err(PqProcessEventFailure::Malformed);
    }
    let role = match exact_field(
        fields
            .get(3)
            .copied()
            .ok_or(PqProcessEventFailure::Malformed)?,
        "role=",
    )? {
        "proposer" => PqProcessRole::Proposer,
        "verifier" => PqProcessRole::Verifier,
        _ => return Err(PqProcessEventFailure::Malformed),
    };
    let kind = match event {
        "EventWriterReady" if fields.len() == 4 => PqProcessEventKind::EventWriterReady,
        "PeerConnected" if fields.len() == 6 => PqProcessEventKind::PeerConnected {
            peer_digest: parse_peer_digest(fields[4])?,
            direction: match exact_field(fields[5], "direction=")? {
                "incoming" => PqProcessConnectionDirection::Incoming,
                "outgoing" => PqProcessConnectionDirection::Outgoing,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "StatusSent" if fields.len() == 6 => PqProcessEventKind::StatusSent {
            peer_digest: parse_peer_digest(fields[4])?,
            direction: match exact_field(fields[5], "direction=")? {
                "request" => PqProcessStatusDirection::Request,
                "response" => PqProcessStatusDirection::Response,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "StatusRejected" if fields.len() == 6 => PqProcessEventKind::StatusRejected {
            peer_digest: parse_peer_digest(fields[4])?,
            code: match exact_field(fields[5], "code=")? {
                "fork_digest" => PqProcessStatusRejection::ForkDigest,
                "finalized_epoch" => PqProcessStatusRejection::FinalizedEpoch,
                "finalized_root" => PqProcessStatusRejection::FinalizedRoot,
                "capacity" => PqProcessStatusRejection::Capacity,
                _ => return Err(PqProcessEventFailure::Malformed),
            },
        },
        "PeerCompatible" if fields.len() == 5 => PqProcessEventKind::PeerCompatible {
            peer_digest: parse_peer_digest(fields[4])?,
        },
        _ => return Err(PqProcessEventFailure::Malformed),
    };
    Ok(PqProcessEvent {
        sequence,
        role,
        kind,
    })
}

fn peer_digest_from_enr(enr: &discv5::enr::Enr<discv5::enr::CombinedKey>) -> [u8; 16] {
    let digest = Sha256::digest(enr.peer_id().to_bytes());
    let mut peer_digest = [0; 16];
    peer_digest.copy_from_slice(&digest[..16]);
    peer_digest
}

fn validate_compatible_event_trace(
    events: &[PqProcessEvent],
    role: PqProcessRole,
    connection_direction: PqProcessConnectionDirection,
    peer_digest: [u8; 16],
) -> Result<(), String> {
    let expected_prefix = [
        PqProcessEvent {
            sequence: 1,
            role,
            kind: PqProcessEventKind::EventWriterReady,
        },
        PqProcessEvent {
            sequence: 2,
            role,
            kind: PqProcessEventKind::PeerConnected {
                peer_digest,
                direction: connection_direction,
            },
        },
        PqProcessEvent {
            sequence: 3,
            role,
            kind: PqProcessEventKind::StatusSent {
                peer_digest,
                direction: PqProcessStatusDirection::Request,
            },
        },
    ];
    if events.len() != 5 || events[..3] != expected_prefix {
        return Err(format!("invalid PQ compatible event prefix: {events:?}"));
    }
    let response = PqProcessEventKind::StatusSent {
        peer_digest,
        direction: PqProcessStatusDirection::Response,
    };
    let compatible = PqProcessEventKind::PeerCompatible { peer_digest };
    let suffix = [events[3].kind, events[4].kind];
    if suffix != [response, compatible] && suffix != [compatible, response] {
        return Err(format!("invalid PQ compatible event suffix: {events:?}"));
    }
    for (offset, event) in events[3..].iter().enumerate() {
        if event.sequence != u64::try_from(offset + 4).map_err(|error| error.to_string())?
            || event.role != role
        {
            return Err(format!("invalid PQ compatible event topology: {events:?}"));
        }
    }
    Ok(())
}

impl BoundedProcessLog {
    fn push(&self, stream: &'static str, frame: &[u8]) {
        let mut state = self.state.lock().expect("process log lock");
        if stream == "stdout" && frame.starts_with(PQ_EVENT_PREFIX.as_bytes()) {
            if state.event_failure.is_some() {
                return;
            }
            let event = std::str::from_utf8(frame)
                .map_err(|_| PqProcessEventFailure::Malformed)
                .and_then(parse_pq_process_event);
            match event {
                Ok(event) if event.sequence != state.next_event_sequence => {
                    state.event_failure = Some(PqProcessEventFailure::Sequence);
                }
                Ok(_) if state.events.len() == MAX_RETAINED_PQ_EVENTS => {
                    state.event_failure = Some(PqProcessEventFailure::Capacity);
                }
                Ok(event) => {
                    state.next_event_sequence = match state.next_event_sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => {
                            state.event_failure = Some(PqProcessEventFailure::Sequence);
                            return;
                        }
                    };
                    state.events.push_back(event);
                }
                Err(error) => state.event_failure = Some(error),
            }
            self.changed.notify_all();
            return;
        }
        if state.frames.len() == MAX_RETAINED_LOG_FRAMES {
            state.frames.pop_front();
        }
        let rendered = format!("{stream}:{}", String::from_utf8_lossy(frame).trim_end());
        state.frames.push_back(rendered);
        self.changed.notify_all();
    }

    fn contains_frame(&self, needle: &str) -> bool {
        let state = self.state.lock().expect("process log lock");
        state.frames.iter().any(|frame| frame.contains(needle))
    }

    fn events(&self) -> Result<Vec<PqProcessEvent>, PqProcessEventFailure> {
        let state = self.state.lock().expect("process log lock");
        match state.event_failure {
            Some(error) => Err(error),
            None => Ok(state.events.iter().copied().collect()),
        }
    }

    fn event_failure(&self) -> Option<PqProcessEventFailure> {
        self.state.lock().expect("process log lock").event_failure
    }

    fn snapshot(&self) -> String {
        let state = self.state.lock().expect("process log lock");
        let mut snapshot = state
            .events
            .iter()
            .map(|event| format!("event:{event:?}"))
            .collect::<Vec<_>>();
        if let Some(error) = state.event_failure {
            snapshot.push(format!("event_failure:{error:?}"));
        }
        snapshot.extend(state.frames.iter().cloned());
        snapshot.join("\n")
    }
}

struct ChildNode {
    name: &'static str,
    child: Child,
    log: Arc<BoundedProcessLog>,
    readers: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
enum ChildStartupError {
    EarlyExit {
        status: std::process::ExitStatus,
        diagnostics: String,
    },
    EnrTimeout {
        diagnostics: String,
    },
    EnrInspection(String),
}

impl std::fmt::Display for ChildStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EarlyExit {
                status,
                diagnostics,
            } => write!(
                formatter,
                "child exited during startup: {status}\n{diagnostics}"
            ),
            Self::EnrTimeout { diagnostics } => {
                write!(
                    formatter,
                    "timed out waiting for bounded ENR\n{diagnostics}"
                )
            }
            Self::EnrInspection(error) => write!(formatter, "inspect bounded ENR: {error}"),
        }
    }
}

impl ChildNode {
    fn spawn(name: &'static str, args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lighthouse"))
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("start {name} Lighthouse process: {error}"));
        let log = Arc::new(BoundedProcessLog::default());
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let readers = vec![
            spawn_bounded_reader("stdout", stdout, Arc::clone(&log)),
            spawn_bounded_reader("stderr", stderr, Arc::clone(&log)),
        ];
        Self {
            name,
            child,
            log,
            readers,
        }
    }

    async fn wait_for_event_count(
        &mut self,
        event_count: usize,
        timeout: Duration,
    ) -> Vec<PqProcessEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.log.events() {
                Ok(events) if events.len() >= event_count => return events,
                Ok(_) => {}
                Err(error) => panic!(
                    "{} emitted an invalid PQ event stream: {error:?}\n{}",
                    self.name,
                    self.log.snapshot()
                ),
            }
            if let Some(status) = self.child.try_wait().expect("poll Lighthouse child") {
                panic!(
                    "{} exited before {event_count} PQ events: {status}\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            if Instant::now() >= deadline {
                panic!(
                    "{} did not emit {event_count} PQ events before timeout\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_enr(
        &mut self,
        network_dir: &Path,
        timeout: Duration,
    ) -> Result<String, ChildStartupError> {
        let path = network_dir.join("enr.dat");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|error| {
                ChildStartupError::EnrInspection(format!("poll Lighthouse child: {error}"))
            })? {
                self.join_readers();
                return Err(ChildStartupError::EarlyExit {
                    status,
                    diagnostics: self.log.snapshot(),
                });
            }
            match open_bounded_regular_nofollow(&path, MAX_ENR_BYTES) {
                Ok(bytes) => {
                    let enr = String::from_utf8(bytes)
                        .map_err(|_| ChildStartupError::EnrInspection("ENR is not UTF-8".into()))?;
                    let enr = enr.trim();
                    if enr
                        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
                        .is_ok()
                    {
                        return Ok(enr.to_owned());
                    }
                }
                Err(error)
                    if error.contains("No such file") || error.contains("changed while read") => {}
                Err(error) => return Err(ChildStartupError::EnrInspection(error)),
            }
            if Instant::now() >= deadline {
                return Err(ChildStartupError::EnrTimeout {
                    diagnostics: self.log.snapshot(),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            reader.join().expect("bounded pipe reader");
        }
    }

    fn signal_interrupt(&mut self) {
        assert!(
            self.child
                .try_wait()
                .expect("poll child before SIGINT")
                .is_none(),
            "{} exited before SIGINT",
            self.name
        );
        let pid = libc::pid_t::try_from(self.child.id()).expect("child PID fits pid_t");
        // SAFETY: the PID belongs to the live child owned by this guard.
        let result = unsafe { libc::kill(pid, libc::SIGINT) };
        assert_eq!(result, 0, "send SIGINT to {}", self.name);
    }

    async fn stop(mut self) {
        self.signal_interrupt();
        let deadline = Instant::now() + PROCESS_STOP_TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll stopped child") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let status = self.child.wait().expect("reap killed Lighthouse child");
                panic!(
                    "{} did not stop after SIGINT: {status}\n{}",
                    self.name,
                    self.log.snapshot()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        self.join_readers();
        assert!(
            status.success(),
            "{} failed during graceful shutdown: {status}\n{}",
            self.name,
            self.log.snapshot()
        );
    }
}

impl Drop for ChildNode {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    stream: &'static str,
    mut reader: R,
    log: Arc<BoundedProcessLog>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        let mut frame = Vec::with_capacity(8192);
        loop {
            let count = match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            for byte in &chunk[..count] {
                if *byte == b'\n' {
                    log.push(stream, &frame);
                    frame.clear();
                } else if frame.len() < MAX_LOG_FRAME_BYTES {
                    frame.push(*byte);
                } else {
                    log.push(stream, b"<oversized child log frame discarded>");
                    frame.clear();
                }
            }
        }
        if !frame.is_empty() {
            log.push(stream, &frame);
        }
    })
}

struct LaunchFixture {
    _root: TempDir,
    testnet_dir: PathBuf,
    bundle_dir: PathBuf,
    jwt_proposer: PathBuf,
    jwt_verifier: PathBuf,
    proposer_data: PathBuf,
    proposer_network: PathBuf,
    verifier_data: PathBuf,
    verifier_network: PathBuf,
}

impl LaunchFixture {
    fn materialize(
        template: &Path,
        authenticated: &AuthenticatedTemplate,
        preparation: &mut TemplatePreparationAudit,
    ) -> Self {
        let root = tempfile::tempdir().expect("e4f test root");
        let staging = root.path().join("container.staging");
        copy_tree_exact(&template.join("container"), &staging).expect("private template clone");
        let copied = inventory_tree(&staging).expect("inventory private template clone");
        assert_eq!(
            copied, authenticated.inventory,
            "the exact copied source must still match the authenticated cache instance"
        );
        preparation
            .record_copy()
            .expect("record exact template copy");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("fixture genesis clock")
            .as_secs();
        let genesis_time = preparation
            .select_genesis_time(now)
            .expect("select genesis only after expensive authentication and copy");
        rebase_network_identity(&staging, genesis_time).expect("atomic network identity rebase");
        let rebased =
            validate_network_identity(&staging).expect("bounded post-rebase network identity");
        assert_eq!(
            authenticated.identity.genesis_validators_root,
            rebased.genesis_validators_root
        );
        assert_eq!(authenticated.identity.registry, rebased.registry);
        assert_eq!(rebased.genesis_time, genesis_time);
        let container = root.path().join("container");
        fs::rename(&staging, &container).expect("publish private run container");
        File::open(root.path())
            .expect("run root")
            .sync_all()
            .expect("sync private run container");
        let testnet_dir = container.join("testnet");
        let bundle_dir = container.join("bundle");
        let published =
            validate_network_identity(&container).expect("bounded published network identity");
        assert_eq!(
            published.genesis_validators_root,
            authenticated.identity.genesis_validators_root
        );
        assert_eq!(published.registry, authenticated.identity.registry);
        assert_eq!(published.genesis_time, genesis_time);

        let jwt_proposer = root.path().join("proposer.jwt");
        let jwt_verifier = root.path().join("verifier.jwt");
        write_private(&jwt_proposer, hex::encode(DEFAULT_JWT_SECRET).as_bytes());
        write_private(&jwt_verifier, hex::encode(DEFAULT_JWT_SECRET).as_bytes());
        assert_ne!(jwt_proposer, jwt_verifier);

        Self {
            proposer_data: root.path().join("proposer-data"),
            proposer_network: root.path().join("proposer-network"),
            verifier_data: root.path().join("verifier-data"),
            verifier_network: root.path().join("verifier-network"),
            _root: root,
            testnet_dir,
            bundle_dir,
            jwt_proposer,
            jwt_verifier,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TemplateInventory {
    entries: usize,
    bytes: u64,
    digest: String,
}

impl TemplateInventory {
    fn encode(&self) -> String {
        format!(
            "version={TEMPLATE_VERSION}\nentries={}\nbytes={}\nsha256={}\n",
            self.entries, self.bytes, self.digest
        )
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1024 {
            return Err("template inventory is oversized".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "template inventory is not UTF-8")?;
        let mut lines = text.lines();
        if lines.next() != Some(&format!("version={TEMPLATE_VERSION}")) {
            return Err("template inventory version mismatch".into());
        }
        let entries = parse_inventory_number(lines.next(), "entries")?;
        let bytes = parse_inventory_number(lines.next(), "bytes")?;
        let digest = lines
            .next()
            .and_then(|line| line.strip_prefix("sha256="))
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or("invalid template inventory digest")?
            .to_owned();
        if lines.next().is_some() {
            return Err("unexpected template inventory fields".into());
        }
        Ok(Self {
            entries: usize::try_from(entries).map_err(|_| "entry count does not fit usize")?,
            bytes,
            digest,
        })
    }
}

fn parse_inventory_number(line: Option<&str>, field: &str) -> Result<u64, String> {
    line.and_then(|line| line.strip_prefix(&format!("{field}=")))
        .ok_or_else(|| format!("missing template inventory {field}"))?
        .parse()
        .map_err(|_| format!("invalid template inventory {field}"))
}

fn prepare_launch_fixture() -> LaunchFixture {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target");
    let target = open_directory_nofollow(&target, None).expect("open target directory once");
    let lock = open_fixture_lock(&target).expect("anchored fixture lock");
    lock.lock_exclusive()
        .expect("exclusive fixture-generation lock");
    let template = anchored_path(&target).join(TEMPLATE_VERSION);
    let mut preparation = TemplatePreparationAudit::default();
    let authenticated = ensure_template(&template, &mut preparation);
    let fixture = LaunchFixture::materialize(&template, &authenticated, &mut preparation);
    preparation
        .finish()
        .expect("one authentication, one copy, one late genesis selection");
    FileExt::unlock(&lock).expect("unlock fixture generation");
    fixture
}

fn open_fixture_lock(target: &File) -> Result<File, String> {
    let lock_path = anchored_path(target).join("pq-e4f-template.lock");
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lock = lock_options
        .open(&lock_path)
        .map_err(|error| format!("open anchored fixture lock: {error}"))?;
    let lock_metadata = lock
        .metadata()
        .map_err(|error| format!("fstat anchored fixture lock: {error}"))?;
    if !lock_metadata.file_type().is_file()
        || lock_metadata.nlink() != 1
        || lock_metadata.mode() & 0o7777 != 0o600
    {
        return Err("fixture lock must be one private regular inode".into());
    }
    Ok(lock)
}

fn ensure_template(
    template: &Path,
    preparation: &mut TemplatePreparationAudit,
) -> AuthenticatedTemplate {
    if open_directory_nofollow(template, Some(0o700)).is_ok() {
        let authenticated =
            validate_template(template).expect("validate immutable PQ template before reuse");
        preparation
            .record_authentication()
            .expect("authenticate immutable template exactly once");
        return authenticated;
    }
    let parent = template.parent().expect("template parent");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("template staging clock")
        .as_nanos();
    let staging = parent.join(format!(
        ".{TEMPLATE_VERSION}.owned-staging-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&staging).expect("template staging directory");
    let mut cleanup = OwnedStaging::new(staging.clone());
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .expect("template staging mode");

    let generation = tempfile::tempdir().expect("template generation root");
    let seed = generation.path().join("seed");
    let password = generation.path().join("password");
    write_private(&seed, &[42; 32]);
    write_private(&password, b"e4f deterministic private fixture password");
    let provisioned = provision_devnet(
        production_config(generation.path().join("container"), 0),
        &seed,
        &password,
    )
    .expect("provision deterministic 16-validator immutable template");
    copy_tree_exact(provisioned.output_dir(), &staging.join("container"))
        .expect("copy provisioned immutable template");
    let inventory = inventory_tree(&staging.join("container")).expect("template inventory");
    atomic_replace(
        &staging.join("inventory"),
        inventory.encode().as_bytes(),
        0o600,
    )
    .expect("write template inventory");
    validate_template_structure(&staging).expect("validate template structure before auth");
    let identity = validate_authenticated_container(&staging.join("container"))
        .expect("authenticate deterministic template exactly once");
    preparation
        .record_authentication()
        .expect("authenticate generated template exactly once");
    validate_frozen_template_identity(&identity).expect("generated template has exact frozen time");
    let semantic = identity
        .semantic_digest()
        .expect("bounded semantic template identity");
    if validate_semantic_anchor(&identity, PINNED_TEMPLATE_SEMANTIC_SHA256).is_err() {
        panic!("deterministic PQ semantic anchor required: sha256={semantic}");
    }
    fs::rename(&staging, template).expect("atomically publish immutable template");
    cleanup.disarm();
    File::open(parent)
        .expect("template parent")
        .sync_all()
        .expect("sync immutable template publication");
    AuthenticatedTemplate {
        inventory,
        identity,
    }
}

struct OwnedStaging {
    path: Option<PathBuf>,
}

impl OwnedStaging {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for OwnedStaging {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_template(template: &Path) -> Result<AuthenticatedTemplate, String> {
    let inventory = validate_template_structure(template)?;
    let identity = validate_authenticated_container(&template.join("container"))?;
    validate_frozen_template_identity(&identity)?;
    validate_semantic_anchor(&identity, PINNED_TEMPLATE_SEMANTIC_SHA256)?;
    Ok(AuthenticatedTemplate {
        inventory,
        identity,
    })
}

fn validate_template_structure(template: &Path) -> Result<TemplateInventory, String> {
    let root = open_directory_nofollow(template, Some(0o700))?;
    let mut root_entries = read_anchored_names(&root)?;
    root_entries.sort();
    if root_entries != ["container", "inventory"] {
        return Err("template contains unexpected mutable state".into());
    }
    let expected =
        TemplateInventory::decode(&read_named_bounded(&root, "inventory", 0o600, 1024)?)?;
    let container = open_anchored_directory(&root, "container", Some(0o755))?;
    let actual = inventory_tree_from_fd(&container)?;
    if actual != expected {
        return Err("template inventory mismatch".into());
    }
    validate_template_layout(&container)?;
    validate_pristine_journal(&anchored_path(&container).join("bundle/xmss_usage.sqlite"))?;
    Ok(actual)
}

struct AuthenticatedTemplate {
    inventory: TemplateInventory,
    identity: PqNetworkIdentity,
}

#[derive(Default)]
struct TemplatePreparationAudit {
    authentications: u8,
    copied: bool,
    genesis_selected: bool,
}

impl TemplatePreparationAudit {
    fn record_authentication(&mut self) -> Result<(), String> {
        if self.authentications != 0 || self.copied || self.genesis_selected {
            return Err("template authentication is not exactly once and before copy".into());
        }
        self.authentications = 1;
        Ok(())
    }

    fn record_copy(&mut self) -> Result<(), String> {
        if self.authentications != 1 || self.copied || self.genesis_selected {
            return Err("template copy must follow its sole authentication".into());
        }
        self.copied = true;
        Ok(())
    }

    fn select_genesis_time(&mut self, now: u64) -> Result<u64, String> {
        if self.authentications != 1 || !self.copied || self.genesis_selected {
            return Err("genesis time must be selected once after authentication and copy".into());
        }
        self.genesis_selected = true;
        now.checked_add(900)
            .ok_or_else(|| "fixture genesis time overflow".into())
    }

    fn finish(&self) -> Result<(), String> {
        if self.authentications == 1 && self.copied && self.genesis_selected {
            Ok(())
        } else {
            Err("incomplete template preparation lifecycle".into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PqNetworkIdentity {
    genesis_validators_root: [u8; 32],
    genesis_time: u64,
    eth1_timestamp: u64,
    registry: Vec<PqValidatorRegistryEntry>,
    one_time_use_start: u32,
    one_time_use_end: u32,
}

impl PqNetworkIdentity {
    fn semantic_digest(&self) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"lighthouse/pq-e4f/semantic-template/v1");
        hasher.update(b"minimal/electra/300");
        hasher.update(self.genesis_validators_root);
        hasher.update(self.genesis_time.to_le_bytes());
        hasher.update(self.one_time_use_start.to_le_bytes());
        hasher.update(self.one_time_use_end.to_le_bytes());
        let registry_len = u32::try_from(self.registry.len())
            .map_err(|_| "semantic registry length does not fit u32")?;
        hasher.update(registry_len.to_le_bytes());
        for entry in &self.registry {
            hasher.update(entry.validator_index().to_le_bytes());
            hasher.update(entry.public_key().serialize());
            hasher.update(entry.withdrawal_credentials());
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

fn validate_frozen_template_identity(identity: &PqNetworkIdentity) -> Result<(), String> {
    if identity.genesis_time != 300 || identity.eth1_timestamp != 0 {
        return Err("immutable template timing must be genesis=300 and eth1=0".into());
    }
    Ok(())
}

fn validate_semantic_anchor(
    identity: &PqNetworkIdentity,
    trusted_digest: &str,
) -> Result<(), String> {
    let actual = identity.semantic_digest()?;
    if actual == trusted_digest {
        Ok(())
    } else {
        Err(format!(
            "template does not match the trusted semantic anchor: {actual}"
        ))
    }
}

fn validate_authenticated_container(container: &Path) -> Result<PqNetworkIdentity, String> {
    let identity = validate_network_identity(container)?;
    let container = open_directory_nofollow(container, Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let bundle_path = bundle_loader_path(&bundle);
    let loaded = PqDevnetBundle::load_for_network_registry(
        &bundle_path,
        identity.genesis_validators_root,
        identity.genesis_time,
        &identity.registry,
    )
    .map_err(|error| format!("authenticated template bundle: {error}"))?;
    if loaded.registry() != identity.registry || loaded.unlock_count() != identity.registry.len() {
        return Err("authenticated bundle registry mismatch".into());
    }
    let authority = loaded
        .open_authority(identity.genesis_validators_root)
        .map_err(|error| format!("fresh exact template journal: {error}"))?;
    if authority.public_keys()
        != identity
            .registry
            .iter()
            .map(PqValidatorRegistryEntry::public_key)
            .collect::<Vec<_>>()
    {
        return Err("journal authority key set mismatch".into());
    }
    drop(authority);
    Ok(identity)
}

fn validate_network_identity(container: &Path) -> Result<PqNetworkIdentity, String> {
    let container = open_directory_nofollow(container, Some(0o755))?;
    let testnet = open_anchored_directory(&container, "testnet", Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let mut public_names = read_anchored_names(&testnet)?;
    public_names.sort();
    if public_names
        != [
            "bootstrap_nodes.yaml",
            "config.yaml",
            "deposit_contract_block.txt",
            "genesis.ssz",
        ]
    {
        return Err("bounded public testnet layout mismatch".into());
    }
    let config_bytes = read_named_bounded(&testnet, "config.yaml", 0o644, 64 * 1024)?;
    let config: types::Config = yaml_serde::from_reader(config_bytes.as_slice())
        .map_err(|error| format!("public config YAML: {error}"))?;
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    if config != types::Config::from_chain_spec::<MinimalEthSpec>(&spec) {
        return Err("public config is not frozen Minimal Electra/300".into());
    }
    let deposit_bytes = read_named_bounded(&testnet, "deposit_contract_block.txt", 0o644, 1024)?;
    let deposit: u64 = yaml_serde::from_reader(deposit_bytes.as_slice())
        .map_err(|_| "invalid public deposit block")?;
    if deposit != 0 {
        return Err("public deposit block must be zero".into());
    }
    let bootstrap_bytes = read_named_bounded(&testnet, "bootstrap_nodes.yaml", 0o644, 64 * 1024)?;
    let bootstrap: Vec<String> = yaml_serde::from_reader(bootstrap_bytes.as_slice())
        .map_err(|_| "invalid public bootstrap list")?;
    if !bootstrap.is_empty() {
        return Err("public bootstrap list must be empty".into());
    }
    let genesis_bytes = read_named_bounded(&testnet, "genesis.ssz", 0o644, 128 * 1024 * 1024)?;
    let state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&genesis_bytes, &spec)
        .map_err(|error| format!("public genesis decode: {error:?}"))?;
    state_processing::validate_lean_pq_devnet_v1(&state, &spec, state.slot())
        .map_err(|error| format!("public genesis profile: {error:?}"))?;
    let genesis_validators_root = state
        .genesis_validators_root()
        .as_slice()
        .try_into()
        .map_err(|_| "genesis validators root length")?;
    let registry = state
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            Ok(PqValidatorRegistryEntry::new(
                u64::try_from(index).map_err(|_| "validator index overflow")?,
                validator.pubkey,
                validator.withdrawal_credentials.0,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if registry.len() != 16 {
        return Err("public registry must contain exactly 16 validators".into());
    }
    let manifest = PqDevnetManifest::from_json_slice(&read_named_bounded(
        &bundle,
        "pq-devnet.json",
        0o600,
        1024 * 1024,
    )?)
    .map_err(|error| format!("template manifest: {error}"))?;
    let validated = manifest
        .validate_for_network_registry(genesis_validators_root, state.genesis_time(), &registry)
        .map_err(|error| format!("template manifest network binding: {error}"))?;
    Ok(PqNetworkIdentity {
        genesis_validators_root,
        genesis_time: state.genesis_time(),
        eth1_timestamp: validated.eth1_timestamp(),
        registry,
        one_time_use_start: validated.one_time_use_start(),
        one_time_use_end: validated.one_time_use_end(),
    })
}

fn read_named_bounded(
    directory: &File,
    name: &str,
    mode: u32,
    max: u64,
) -> Result<Vec<u8>, String> {
    let mut file = open_anchored_file(directory, name, Some(mode))?;
    read_held_bounded(&mut file, max)
}

fn validate_template_layout(container: &File) -> Result<(), String> {
    validate_held_directory(container, Some(0o755))?;
    let mut container_entries = read_anchored_names(container)?;
    container_entries.sort();
    if container_entries != ["bundle", "testnet"] {
        return Err("template container layout mismatch".into());
    }
    let testnet = open_anchored_directory(container, "testnet", Some(0o755))?;
    let mut public = read_anchored_names(&testnet)?;
    public.sort();
    if public
        != [
            "bootstrap_nodes.yaml",
            "config.yaml",
            "deposit_contract_block.txt",
            "genesis.ssz",
        ]
    {
        return Err("template public layout mismatch".into());
    }
    for file in public {
        open_anchored_file(&testnet, &file, Some(0o644))?;
    }
    let bundle = open_anchored_directory(container, "bundle", Some(0o700))?;
    let mut private = read_anchored_names(&bundle)?;
    private.sort();
    if private
        != [
            "pq-devnet.json",
            "secrets",
            "validators",
            "xmss_usage.sqlite",
            "xmss_usage.sqlite.lock",
        ]
    {
        return Err("template private layout mismatch".into());
    }
    for file in [
        "pq-devnet.json",
        "xmss_usage.sqlite",
        "xmss_usage.sqlite.lock",
    ] {
        open_anchored_file(&bundle, file, Some(0o600))?;
    }
    for directory_name in ["validators", "secrets"] {
        let directory = open_anchored_directory(&bundle, directory_name, Some(0o700))?;
        let names = read_anchored_names(&directory)?;
        if names.len() != 16 {
            return Err(format!("template {directory_name} count mismatch"));
        }
        for name in names {
            if directory_name == "validators" {
                open_anchored_directory(&directory, &name, Some(0o700))?;
            } else {
                open_anchored_file(&directory, &name, Some(0o600))?;
            }
        }
    }
    Ok(())
}

fn validate_pristine_journal(path: &Path) -> Result<(), String> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| format!("open pristine journal: {error}"))?;
    let keys: i64 = connection
        .query_row("SELECT count(*) FROM xmss_keys", [], |row| row.get(0))
        .map_err(|error| format!("count journal keys: {error}"))?;
    let reservations: i64 = connection
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .map_err(|error| format!("count journal reservations: {error}"))?;
    if keys != 16 || reservations != 0 {
        return Err(format!(
            "template journal is not pristine: keys={keys}, reservations={reservations}"
        ));
    }
    Ok(())
}

fn inventory_tree(root: &Path) -> Result<TemplateInventory, String> {
    let root = open_directory_nofollow(root, None)?;
    inventory_tree_from_fd(&root)
}

fn inventory_tree_from_fd(root: &File) -> Result<TemplateInventory, String> {
    let mut hasher = Sha256::new();
    let mut accounting = TemplateAccounting::default();
    inventory_directory(root, "", &mut hasher, &mut accounting)?;
    Ok(TemplateInventory {
        entries: accounting.entries,
        bytes: accounting.bytes,
        digest: hex::encode(hasher.finalize()),
    })
}

#[derive(Default)]
struct TemplateAccounting {
    entries: usize,
    bytes: u64,
}

fn inventory_directory(
    directory: &File,
    prefix: &str,
    hasher: &mut Sha256,
    accounting: &mut TemplateAccounting,
) -> Result<(), String> {
    for name in read_anchored_names(directory)? {
        accounting.entries = accounting
            .entries
            .checked_add(1)
            .ok_or("template entry count overflow")?;
        if accounting.entries > MAX_TEMPLATE_ENTRIES {
            return Err("template entry cap exceeded".into());
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        hasher.update(relative.len().to_le_bytes());
        hasher.update(relative.as_bytes());
        if let Ok(child) = open_anchored_directory(directory, &name, None) {
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat inventory directory: {error}"))?;
            hasher.update((metadata.mode() & 0o7777).to_le_bytes());
            hasher.update(b"d");
            inventory_directory(&child, &relative, hasher, accounting)?;
        } else {
            let mut child = open_anchored_file(directory, &name, None)?;
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat inventory file: {error}"))?;
            hasher.update((metadata.mode() & 0o7777).to_le_bytes());
            hasher.update(b"f");
            let remaining = MAX_TEMPLATE_BYTES
                .checked_sub(accounting.bytes)
                .ok_or("template byte accounting underflow")?;
            let bytes = read_held_bounded(&mut child, remaining)?;
            accounting.bytes = accounting
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "file length overflow")?)
                .ok_or("template byte count overflow")?;
            hasher.update(bytes.len().to_le_bytes());
            hasher.update(bytes);
        }
    }
    Ok(())
}

fn copy_tree_exact(source: &Path, destination: &Path) -> Result<(), String> {
    copy_tree_exact_with_hooks(source, destination, || {}, || {})
}

fn copy_tree_exact_with_hooks(
    source: &Path,
    destination: &Path,
    after_source_enumerated: impl FnOnce(),
    after_destination_opened: impl FnOnce(),
) -> Result<(), String> {
    let source = open_directory_nofollow(source, None)?;
    let source_names = read_anchored_names(&source)?;
    after_source_enumerated();
    let destination_parent = destination
        .parent()
        .ok_or("copy destination has no parent")?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("copy destination name is not UTF-8")?;
    let destination_parent = open_directory_nofollow(destination_parent, None)?;
    let destination =
        create_anchored_destination_directory(&destination_parent, destination_name, &source)?;
    after_destination_opened();
    let mut accounting = TemplateAccounting::default();
    copy_directory_entries(&source, &destination, source_names, &mut accounting)?;
    verify_anchored_directory_binding(&destination_parent, destination_name, &destination)
}

fn copy_directory_entries(
    source: &File,
    destination: &File,
    names: Vec<String>,
    accounting: &mut TemplateAccounting,
) -> Result<(), String> {
    for name in names {
        accounting.entries = accounting
            .entries
            .checked_add(1)
            .ok_or("copy entry count overflow")?;
        if accounting.entries > MAX_TEMPLATE_ENTRIES {
            return Err("copy source entry cap exceeded".into());
        }
        if let Ok(child) = open_anchored_directory(source, &name, None) {
            let child_names = read_anchored_names(&child)?;
            let destination_child =
                create_anchored_destination_directory(destination, &name, &child)?;
            copy_directory_entries(&child, &destination_child, child_names, accounting)?;
            verify_anchored_directory_binding(destination, &name, &destination_child)?;
        } else {
            let mut child = open_anchored_file(source, &name, None)?;
            let metadata = child
                .metadata()
                .map_err(|error| format!("fstat copy source file: {error}"))?;
            let remaining = MAX_TEMPLATE_BYTES
                .checked_sub(accounting.bytes)
                .ok_or("copy byte accounting underflow")?;
            let bytes = read_held_bounded(&mut child, remaining)?;
            accounting.bytes = accounting
                .bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| "copy length overflow")?)
                .ok_or("copy byte count overflow")?;
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(metadata.mode() & 0o7777)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut destination_file = options
                .open(anchored_path(destination).join(&name))
                .map_err(|error| format!("create copied file: {error}"))?;
            destination_file
                .write_all(&bytes)
                .map_err(|error| format!("write copied file: {error}"))?;
            destination_file
                .set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))
                .map_err(|error| format!("set copied file mode: {error}"))?;
            let copied = destination_file
                .metadata()
                .map_err(|error| format!("fstat copied file: {error}"))?;
            if metadata.mode() & 0o7000 != 0
                || copied.nlink() != 1
                || copied.mode() & 0o7777 != metadata.mode() & 0o7777
                || (copied.dev() == metadata.dev() && copied.ino() == metadata.ino())
            {
                return Err("copied file identity or mode mismatch".into());
            }
            destination_file
                .sync_all()
                .map_err(|error| format!("sync copied file: {error}"))?;
            verify_anchored_file_binding(destination, &name, &destination_file)?;
        }
    }
    destination
        .sync_all()
        .map_err(|error| format!("sync copied directory: {error}"))?;
    Ok(())
}

fn create_anchored_destination_directory(
    parent: &File,
    name: &str,
    source: &File,
) -> Result<File, String> {
    let source_metadata = source
        .metadata()
        .map_err(|error| format!("fstat copy source directory: {error}"))?;
    let mode = source_metadata.mode() & 0o7777;
    if mode & 0o7000 != 0 {
        return Err("copy source directory has special permission bits".into());
    }
    let destination_path = anchored_path(parent).join(name);
    fs::create_dir(&destination_path)
        .map_err(|error| format!("create anchored clone directory: {error}"))?;
    let destination = open_anchored_directory(parent, name, None)?;
    destination
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set held clone directory mode: {error}"))?;
    let destination_metadata = destination
        .metadata()
        .map_err(|error| format!("fstat held clone directory: {error}"))?;
    if destination_metadata.mode() & 0o7777 != mode
        || (destination_metadata.dev() == source_metadata.dev()
            && destination_metadata.ino() == source_metadata.ino())
    {
        return Err("copied directory identity or mode mismatch".into());
    }
    destination
        .sync_all()
        .map_err(|error| format!("sync created clone directory: {error}"))?;
    Ok(destination)
}

fn verify_anchored_directory_binding(parent: &File, name: &str, held: &File) -> Result<(), String> {
    let current = open_anchored_directory(parent, name, None)?;
    let current = current
        .metadata()
        .map_err(|error| format!("fstat current destination binding: {error}"))?;
    let held = held
        .metadata()
        .map_err(|error| format!("fstat held destination binding: {error}"))?;
    if current.dev() != held.dev() || current.ino() != held.ino() {
        return Err("destination binding changed during copy".into());
    }
    Ok(())
}

fn verify_anchored_file_binding(parent: &File, name: &str, held: &File) -> Result<(), String> {
    let current = open_anchored_file(parent, name, None)?;
    let current = current
        .metadata()
        .map_err(|error| format!("fstat current destination file: {error}"))?;
    let held = held
        .metadata()
        .map_err(|error| format!("fstat held destination file: {error}"))?;
    if current.dev() != held.dev() || current.ino() != held.ino() {
        return Err("destination file binding changed during copy".into());
    }
    Ok(())
}

fn open_directory_nofollow(path: &Path, mode: Option<u32>) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    let file = options
        .open(path)
        .map_err(|error| format!("open directory {}: {error}", path.display()))?;
    validate_held_directory(&file, mode)?;
    Ok(file)
}

fn open_anchored_directory(parent: &File, name: &str, mode: Option<u32>) -> Result<File, String> {
    open_directory_nofollow(&anchored_path(parent).join(name), mode)
}

fn open_anchored_file(parent: &File, name: &str, mode: Option<u32>) -> Result<File, String> {
    let path = anchored_path(parent).join(name);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(&path)
        .map_err(|error| format!("open anchored file {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat anchored file: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
    {
        return Err(format!("unsafe anchored file {}", path.display()));
    }
    Ok(file)
}

fn validate_held_directory(directory: &File, mode: Option<u32>) -> Result<(), String> {
    let metadata = directory
        .metadata()
        .map_err(|error| format!("fstat held directory: {error}"))?;
    if !metadata.file_type().is_dir() || mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode) {
        return Err("unsafe held directory".into());
    }
    Ok(())
}

fn anchored_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn bundle_loader_path(directory: &File) -> PathBuf {
    anchored_path(directory).join(".")
}

fn read_anchored_names(directory: &File) -> Result<Vec<String>, String> {
    let mut entries = fs::read_dir(anchored_path(directory))
        .map_err(|error| format!("read anchored directory: {error}"))?
        .take(MAX_TEMPLATE_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read anchored entry: {error}"))?;
    if entries.len() > MAX_TEMPLATE_ENTRIES {
        return Err("anchored directory entry cap exceeded".into());
    }
    entries.sort_by_key(|entry| entry.file_name());
    entries
        .into_iter()
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .map_err(|_| "anchored entry name is not UTF-8".into())
        })
        .collect()
}

fn read_held_bounded(file: &mut File, max: u64) -> Result<Vec<u8>, String> {
    let before = file
        .metadata()
        .map_err(|error| format!("fstat bounded file: {error}"))?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > max {
        return Err("unsafe or oversized held file".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(max.checked_add(1).ok_or("bounded held read overflow")?)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read held file: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("post-read fstat held file: {error}"))?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("held file changed while read".into());
    }
    Ok(bytes)
}

fn rebase_network_identity(container: &Path, genesis_time: u64) -> Result<(), String> {
    let eth1_timestamp = genesis_time
        .checked_sub(300)
        .ok_or("genesis time is below frozen genesis delay")?;
    let spec = ForkName::Electra
        .make_genesis_spec(MinimalEthSpec::default_spec())
        .set_slot_duration_ms::<MinimalEthSpec>(300_000);
    let container = open_directory_nofollow(container, Some(0o755))?;
    let testnet = open_anchored_directory(&container, "testnet", Some(0o755))?;
    let bundle = open_anchored_directory(&container, "bundle", Some(0o700))?;
    let genesis_path = anchored_path(&testnet).join("genesis.ssz");
    let genesis = read_named_bounded(&testnet, "genesis.ssz", 0o644, 128 * 1024 * 1024)?;
    let mut state = BeaconState::<MinimalEthSpec>::from_ssz_bytes(&genesis, &spec)
        .map_err(|error| format!("decode genesis: {error:?}"))?;
    *state.genesis_time_mut() = genesis_time;
    atomic_replace(&genesis_path, &state.as_ssz_bytes(), 0o644)?;

    let manifest_path = anchored_path(&bundle).join("pq-devnet.json");
    let bytes = read_named_bounded(&bundle, "pq-devnet.json", 0o600, 1024 * 1024)?;
    let mut manifest: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("decode manifest JSON: {error}"))?;
    *manifest
        .get_mut("eth1_timestamp")
        .ok_or("manifest timestamp missing")? = Value::from(eth1_timestamp);
    let rebased = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("encode rebased manifest: {error}"))?;
    atomic_replace(&manifest_path, &rebased, 0o600)?;
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("replacement path has no parent")?;
    let temporary = parent.join(format!(
        ".{}.rebase-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("replacement filename is not UTF-8")?,
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create replacement: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write replacement: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("set replacement mode: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat replacement: {error}"))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.mode() & 0o7777 != mode
    {
        return Err("replacement inode or mode mismatch".into());
    }
    file.sync_all()
        .map_err(|error| format!("sync replacement: {error}"))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| format!("publish replacement: {error}"))?;
    let published = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open published replacement: {error}"))?;
    let published_metadata = published
        .metadata()
        .map_err(|error| format!("fstat published replacement: {error}"))?;
    if !published_metadata.file_type().is_file()
        || published_metadata.nlink() != 1
        || published_metadata.mode() & 0o7777 != mode
    {
        return Err("published replacement inode or mode mismatch".into());
    }
    File::open(parent)
        .map_err(|error| format!("open replacement parent: {error}"))?
        .sync_all()
        .map_err(|error| format!("sync replacement parent: {error}"))?;
    Ok(())
}

fn validate_manifest_network_identity(
    manifest: &PqDevnetManifest,
    root: [u8; 32],
    genesis_time: u64,
) -> Result<(), String> {
    manifest
        .validate_for_network_identity(root, genesis_time)
        .map(|_| ())
        .map_err(|error| format!("manifest network binding: {error}"))
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path).expect("create private fixture input");
    file.write_all(bytes).expect("write private fixture input");
    file.sync_all().expect("sync private fixture input");
}

fn reserve_tcp_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve TCP port")
        .local_addr()
        .expect("TCP address")
        .port()
}

fn reserve_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("reserve UDP port")
        .local_addr()
        .expect("UDP address")
        .port()
}

fn require_pq_avx2_launch_profile() {
    #[cfg(target_arch = "x86_64")]
    {
        assert!(
            std::is_x86_feature_detected!("avx2"),
            "pq_e4f_launch requires an AVX2-capable host"
        );
        assert!(
            cfg!(target_feature = "avx2"),
            "pq_e4f_launch requires test and CARGO_BIN_EXE_lighthouse compiled with AVX2"
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    panic!("pq_e4f_launch requires an x86_64 AVX2 host");
}

fn open_bounded_regular_nofollow(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    open_bounded_regular_nofollow_with_hook(path, max, || {})
}

fn open_bounded_regular_nofollow_with_hook(
    path: &Path,
    max: u64,
    after_initial_fstat: impl FnOnce(),
) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let before = file
        .metadata()
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    let mode = before.mode() & 0o7777;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || !matches!(mode, 0o600 | 0o604 | 0o640 | 0o644)
        || before.len() > max
    {
        return Err(format!("unsafe bounded file {}", path.display()));
    }
    after_initial_fstat();
    let limit = max.checked_add(1).ok_or("bounded read limit overflow")?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("bounded read {}: {error}", path.display()))?;
    let after = file
        .metadata()
        .map_err(|error| format!("post-read fstat {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).map_err(|_| "bounded read length overflow")? > max
        || bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(format!(
            "bounded file changed while read: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn node_args(
    data_dir: &Path,
    network_dir: &Path,
    testnet_dir: &Path,
    execution_url: &str,
    jwt: &Path,
    tcp_port: u16,
    udp_port: u16,
    boot_node: Option<&str>,
    bundle: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "--datadir".into(),
        path_text(data_dir),
        "--testnet-dir".into(),
        path_text(testnet_dir),
        "beacon_node".into(),
        "--network-dir".into(),
        path_text(network_dir),
        "--execution-endpoint".into(),
        execution_url.into(),
        "--execution-jwt".into(),
        path_text(jwt),
        "--listen-address".into(),
        "127.0.0.1".into(),
        "--port".into(),
        tcp_port.to_string(),
        "--discovery-port".into(),
        udp_port.to_string(),
        "--disable-quic".into(),
        "--disable-upnp".into(),
        "--enr-address".into(),
        "127.0.0.1".into(),
        "--enr-tcp-port".into(),
        tcp_port.to_string(),
        "--enr-udp-port".into(),
        udp_port.to_string(),
        "--target-peers".into(),
        "1".into(),
    ];
    if let Some(enr) = boot_node {
        args.extend(["--boot-nodes".into(), enr.into()]);
    }
    if let Some(bundle) = bundle {
        args.extend([
            "--http".into(),
            "--http-address".into(),
            "127.0.0.1".into(),
            "--http-port".into(),
            "0".into(),
            "--pq-validator-bundle".into(),
            path_text(bundle),
        ]);
    }
    args
}

fn path_text(path: &Path) -> String {
    path.to_str().expect("UTF-8 test path").to_owned()
}

fn synthetic_template() -> TempDir {
    let root = tempfile::tempdir().expect("synthetic template root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("synthetic root mode");
    let container = root.path().join("container");
    fs::create_dir(&container).expect("synthetic container");
    fs::set_permissions(&container, fs::Permissions::from_mode(0o755))
        .expect("synthetic container mode");
    let testnet = container.join("testnet");
    fs::create_dir(&testnet).expect("synthetic public directory");
    fs::set_permissions(&testnet, fs::Permissions::from_mode(0o755))
        .expect("synthetic public mode");
    for file in [
        "bootstrap_nodes.yaml",
        "config.yaml",
        "deposit_contract_block.txt",
        "genesis.ssz",
    ] {
        fs::write(testnet.join(file), file.as_bytes()).expect("synthetic public file");
        fs::set_permissions(testnet.join(file), fs::Permissions::from_mode(0o644))
            .expect("synthetic public file mode");
    }
    let bundle = container.join("bundle");
    fs::create_dir(&bundle).expect("synthetic bundle");
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o700)).expect("synthetic bundle mode");
    for directory in ["validators", "secrets"] {
        let directory = bundle.join(directory);
        fs::create_dir(&directory).expect("synthetic private directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("synthetic private directory mode");
        for index in 0..16 {
            let entry = directory.join(format!("{index:02}"));
            if directory.ends_with("validators") {
                fs::create_dir(&entry).expect("synthetic validator directory");
                fs::set_permissions(entry, fs::Permissions::from_mode(0o700))
                    .expect("synthetic validator directory mode");
            } else {
                fs::write(&entry, [u8::try_from(index).expect("small index")])
                    .expect("synthetic secret entry");
                fs::set_permissions(entry, fs::Permissions::from_mode(0o600))
                    .expect("synthetic secret entry mode");
            }
        }
    }
    for file in ["pq-devnet.json", "xmss_usage.sqlite.lock"] {
        fs::write(bundle.join(file), b"synthetic").expect("synthetic bundle file");
        fs::set_permissions(bundle.join(file), fs::Permissions::from_mode(0o600))
            .expect("synthetic bundle file mode");
    }
    let journal_path = bundle.join("xmss_usage.sqlite");
    let connection = Connection::open(&journal_path).expect("synthetic journal");
    connection
        .execute_batch(
            "CREATE TABLE xmss_keys (stable_key_id BLOB PRIMARY KEY NOT NULL);
             CREATE TABLE reservations (
                stable_key_id BLOB NOT NULL,
                one_time_use_id INTEGER NOT NULL,
                signing_root BLOB NOT NULL
             );",
        )
        .expect("synthetic journal schema");
    for index in 0..16_u8 {
        connection
            .execute(
                "INSERT INTO xmss_keys (stable_key_id) VALUES (?1)",
                params![vec![index; 32]],
            )
            .expect("synthetic journal key");
    }
    drop(connection);
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600))
        .expect("synthetic journal mode");
    let inventory = inventory_tree(&container).expect("synthetic inventory");
    atomic_replace(
        &root.path().join("inventory"),
        inventory.encode().as_bytes(),
        0o600,
    )
    .expect("synthetic inventory file");
    root
}

#[test]
fn immutable_template_validation_rejects_rewritten_inventory_and_private_mutations() {
    let root = synthetic_template();
    validate_template_structure(root.path()).expect("synthetic template baseline");

    let journal_path = root.path().join("container/bundle/xmss_usage.sqlite");
    let connection = Connection::open(&journal_path).expect("mutation journal");
    let stable_key_id: Vec<u8> = connection
        .query_row("SELECT stable_key_id FROM xmss_keys LIMIT 1", [], |row| {
            row.get(0)
        })
        .expect("mutation key");
    connection
        .execute(
            "INSERT INTO reservations (stable_key_id, one_time_use_id, signing_root) VALUES (?1, ?2, ?3)",
            params![stable_key_id, 0_i64, vec![7_u8; 32]],
        )
        .expect("reservation mutation");
    drop(connection);
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("attacker-rewritten inventory");
    assert!(
        validate_template_structure(root.path())
            .expect_err("a reserved journal is never an immutable template")
            .contains("not pristine")
    );

    let root = synthetic_template();
    fs::set_permissions(
        root.path().join("container/testnet/genesis.ssz"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("mode mutation");
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("attacker-rewritten inventory");
    assert!(validate_template_structure(root.path()).is_err());

    let root = synthetic_template();
    fs::set_permissions(
        root.path().join("container/testnet/config.yaml"),
        fs::Permissions::from_mode(0o4644),
    )
    .expect("setuid mode mutation");
    let rewritten = inventory_tree(&root.path().join("container")).expect("rewritten inventory");
    atomic_replace(
        &root.path().join("inventory"),
        rewritten.encode().as_bytes(),
        0o600,
    )
    .expect("setuid inventory rewrite");
    assert!(
        validate_template_structure(root.path()).is_err(),
        "special mode bits must remain visible to exact validation"
    );
}

#[test]
fn semantic_anchor_accepts_randomized_encryption_and_rejects_substituted_registry() {
    use consensus_signature::PqPublicKey;

    let registry = vec![PqValidatorRegistryEntry::new(
        0,
        PqPublicKey::deserialize(&[0x11; 32]).expect("canonical semantic key"),
        [0x22; 32],
    )];
    let identity = PqNetworkIdentity {
        genesis_validators_root: [0x33; 32],
        genesis_time: 300,
        eth1_timestamp: 0,
        registry,
        one_time_use_start: 0,
        one_time_use_end: 1119,
    };
    let first_encrypted_inventory = TemplateInventory {
        entries: 1,
        bytes: 10,
        digest: "11".repeat(32),
    };
    let second_encrypted_inventory = TemplateInventory {
        entries: 1,
        bytes: 10,
        digest: "22".repeat(32),
    };
    let trusted_semantic_digest = identity.semantic_digest().expect("semantic test identity");
    assert_eq!(
        trusted_semantic_digest, "e880f744fe2e0a3963e81fd79c72f86828dd3b52b6290fbc9c1cf0e8bc0e9f5f",
        "semantic identity uses fixed-width genesis time and u32 registry cardinality"
    );
    let first = AuthenticatedTemplate {
        inventory: first_encrypted_inventory,
        identity: identity.clone(),
    };
    let second = AuthenticatedTemplate {
        inventory: second_encrypted_inventory,
        identity: identity.clone(),
    };
    assert_ne!(first.inventory, second.inventory);
    validate_semantic_anchor(&first.identity, &trusted_semantic_digest)
        .expect("randomized encrypted bytes are outside semantic identity");
    validate_semantic_anchor(&second.identity, &trusted_semantic_digest)
        .expect("a second randomized encryption retains semantic identity");

    let mut substituted = identity.clone();
    substituted.registry[0] = PqValidatorRegistryEntry::new(
        0,
        PqPublicKey::deserialize(&[0x44; 32]).expect("canonical substituted key"),
        [0x22; 32],
    );
    assert!(validate_semantic_anchor(&substituted, &trusted_semantic_digest).is_err());

    let mut wrong_time = identity;
    wrong_time.genesis_time = 301;
    assert!(validate_frozen_template_identity(&wrong_time).is_err());
    assert_ne!(
        wrong_time.semantic_digest().expect("wrong-time digest"),
        trusted_semantic_digest
    );
}

#[test]
fn compiled_semantic_anchor_matches_the_authenticated_cold_capture() {
    assert_eq!(
        PINNED_TEMPLATE_SEMANTIC_SHA256,
        "0ce1ebc8555a9a65e11d470bda2f697f652b444acc4d1e214bf737288d76addb"
    );
}

#[test]
fn pq_launch_profile_preflights_host_and_compile_time_avx2() {
    require_pq_avx2_launch_profile();
}

#[test]
fn bounded_process_log_retains_events_without_lock_order_deadlock() {
    let log = Arc::new(BoundedProcessLog::default());
    let (completed, completion) = std::sync::mpsc::channel();
    let producer_log = Arc::clone(&log);
    let producer_completed = completed.clone();
    let producer = std::thread::spawn(move || {
        for sequence in 1..=32 {
            producer_log.push(
                "stdout",
                format!(
                    "{PQ_EVENT_PREFIX} event=PeerConnected sequence={sequence} role=verifier \
peer_digest=01010101010101010101010101010101 direction=incoming"
                )
                .as_bytes(),
            );
            for _ in 0..32 {
                producer_log.push("stderr", b"ordinary bounded diagnostic");
            }
        }
        producer_completed.send(()).unwrap();
    });
    let consumer_log = Arc::clone(&log);
    let consumer = std::thread::spawn(move || {
        for _ in 0..10_000 {
            let _ = consumer_log.events();
            let _ = consumer_log.contains_frame("ordinary bounded diagnostic");
        }
        completed.send(()).unwrap();
    });
    completion
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded log producer completed");
    completion
        .recv_timeout(Duration::from_secs(5))
        .expect("bounded log consumer completed");
    producer.join().unwrap();
    consumer.join().unwrap();
    let events = log.events().unwrap();
    assert_eq!(events.len(), 32);
    assert_eq!(events.first().unwrap().sequence, 1);
    assert_eq!(events.last().unwrap().sequence, 32);
}

#[test]
fn structured_event_parser_rejects_malformed_topology_and_bounds_overflow() {
    let valid = "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01010101010101010101010101010101 direction=incoming";
    assert!(parse_pq_process_event(valid).is_ok());
    for invalid in [
        "PQ_EVENT_V1 event=Unknown sequence=1 role=proposer",
        "PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer extra=value",
        "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01 direction=incoming",
        "PQ_EVENT_V1 event=PeerConnected sequence=1 role=proposer \
peer_digest=01010101010101010101010101010101 direction=sideways",
    ] {
        assert!(
            parse_pq_process_event(invalid).is_err(),
            "accepted {invalid}"
        );
    }

    let log = BoundedProcessLog::default();
    log.push("stderr", valid.as_bytes());
    assert_eq!(log.events().unwrap(), vec![]);
    log.push("stdout", valid.as_bytes());
    log.push(
        "stdout",
        b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer",
    );
    assert_eq!(log.event_failure(), Some(PqProcessEventFailure::Sequence));

    let gap = BoundedProcessLog::default();
    gap.push(
        "stdout",
        b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=verifier",
    );
    gap.push(
        "stdout",
        b"PQ_EVENT_V1 event=PeerCompatible sequence=3 role=verifier \
peer_digest=02020202020202020202020202020202",
    );
    assert_eq!(gap.event_failure(), Some(PqProcessEventFailure::Sequence));

    let peer_digest = [3; 16];
    let valid_trace = vec![
        PqProcessEvent {
            sequence: 1,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::EventWriterReady,
        },
        PqProcessEvent {
            sequence: 2,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::PeerConnected {
                peer_digest,
                direction: PqProcessConnectionDirection::Incoming,
            },
        },
        PqProcessEvent {
            sequence: 3,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::StatusSent {
                peer_digest,
                direction: PqProcessStatusDirection::Request,
            },
        },
        PqProcessEvent {
            sequence: 4,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::StatusSent {
                peer_digest,
                direction: PqProcessStatusDirection::Response,
            },
        },
        PqProcessEvent {
            sequence: 5,
            role: PqProcessRole::Proposer,
            kind: PqProcessEventKind::PeerCompatible { peer_digest },
        },
    ];
    validate_compatible_event_trace(
        &valid_trace,
        PqProcessRole::Proposer,
        PqProcessConnectionDirection::Incoming,
        peer_digest,
    )
    .unwrap();
    let mut wrong_role = valid_trace.clone();
    wrong_role[4].role = PqProcessRole::Verifier;
    assert!(
        validate_compatible_event_trace(
            &wrong_role,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            peer_digest,
        )
        .is_err()
    );
    let mut wrong_order = valid_trace.clone();
    wrong_order.swap(1, 2);
    assert!(
        validate_compatible_event_trace(
            &wrong_order,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            peer_digest,
        )
        .is_err()
    );
    assert!(
        validate_compatible_event_trace(
            &valid_trace,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Outgoing,
            peer_digest,
        )
        .is_err()
    );
    assert!(
        validate_compatible_event_trace(
            &valid_trace,
            PqProcessRole::Proposer,
            PqProcessConnectionDirection::Incoming,
            [4; 16],
        )
        .is_err()
    );

    let overflow = BoundedProcessLog::default();
    for sequence in 1..=65 {
        overflow.push(
            "stdout",
            format!(
                "PQ_EVENT_V1 event=PeerCompatible sequence={sequence} role=verifier \
peer_digest=02020202020202020202020202020202"
            )
            .as_bytes(),
        );
    }
    overflow.push("stderr", b"ordinary-after-overflow");
    assert_eq!(
        overflow.event_failure(),
        Some(PqProcessEventFailure::Capacity)
    );
    assert_eq!(
        overflow.events().unwrap_err(),
        PqProcessEventFailure::Capacity
    );
    assert!(overflow.contains_frame("ordinary-after-overflow"));
}

#[tokio::test]
async fn pq_operational_event_writer_reaches_process_stdout() {
    let (sink, writer) = PqOperationalEventSink::channel(PqOperationalEventRole::Proposer);
    sink.try_emit(PqOperationalEvent::PeerCompatible {
        peer_digest: [0x5a; 16],
    })
    .expect("bounded operational event");
    drop(sink);
    tokio::task::spawn_blocking(move || writer.run())
        .await
        .expect("operational event writer task")
        .expect("operational event writer");
}

#[test]
fn template_authentication_is_once_and_genesis_selection_follows_copy() {
    let mut early = TemplatePreparationAudit::default();
    assert!(early.select_genesis_time(100).is_err());

    let mut preparation = TemplatePreparationAudit::default();
    preparation
        .record_authentication()
        .expect("first authentication");
    assert!(preparation.record_authentication().is_err());
    assert!(preparation.select_genesis_time(100).is_err());
    preparation
        .record_copy()
        .expect("copy after authentication");
    assert_eq!(
        preparation
            .select_genesis_time(100)
            .expect("late genesis selection"),
        1000
    );
    assert!(preparation.select_genesis_time(100).is_err());
    preparation
        .finish()
        .expect("complete preparation lifecycle");
}

#[test]
fn descriptor_anchoring_rejects_lock_and_special_file_mutations() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::tempdir().expect("descriptor mutation root");
    let target = open_directory_nofollow(root.path(), None).expect("held target directory");
    std::os::unix::fs::symlink("elsewhere", root.path().join("pq-e4f-template.lock"))
        .expect("lock symlink mutation");
    assert!(open_fixture_lock(&target).is_err());

    let oversized = root.path().join("oversized");
    fs::write(&oversized, [0_u8; 5]).expect("oversized fixture");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
        .expect("oversized fixture mode");
    let mut oversized =
        open_anchored_file(&target, "oversized", Some(0o600)).expect("open held oversized fixture");
    assert!(read_held_bounded(&mut oversized, 4).is_err());

    let fifo = root.path().join("fifo");
    let fifo_path =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path has no NUL");
    // SAFETY: the NUL-terminated path is owned for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    let socket = UnixListener::bind(root.path().join("socket")).expect("Unix socket mutation");
    assert!(inventory_tree(root.path()).is_err());
    drop(socket);

    let dev = open_directory_nofollow(Path::new("/dev"), None).expect("held /dev directory");
    assert!(open_anchored_file(&dev, "null", None).is_err());

    for mutation in ["symlink", "hardlink", "fifo", "socket"] {
        let template = synthetic_template();
        let secrets = template.path().join("container/bundle/secrets");
        let first = secrets.join("00");
        fs::remove_file(&first).expect("remove nested secret");
        let mut socket_guard = None;
        match mutation {
            "symlink" => {
                std::os::unix::fs::symlink("01", &first).expect("nested secret symlink mutation")
            }
            "hardlink" => {
                fs::hard_link(secrets.join("01"), &first).expect("nested secret hardlink mutation")
            }
            "fifo" => {
                let path = std::ffi::CString::new(first.as_os_str().as_encoded_bytes())
                    .expect("nested FIFO path has no NUL");
                // SAFETY: the NUL-terminated path is owned for the duration of the call.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "socket" => {
                socket_guard = Some(UnixListener::bind(&first).expect("nested socket mutation"));
            }
            _ => unreachable!(),
        }
        assert!(
            inventory_tree(&template.path().join("container")).is_err(),
            "nested {mutation} must be rejected"
        );
        drop(socket_guard);
    }

    let template = synthetic_template();
    let secrets = template.path().join("container/bundle/secrets");
    for index in 16..=MAX_TEMPLATE_ENTRIES {
        fs::write(secrets.join(format!("extra-{index}")), []).expect("nested overcap entry");
    }
    assert!(inventory_tree(&template.path().join("container")).is_err());
}

#[test]
fn anchored_copy_detects_concurrent_source_replacement_and_entry_overflow() {
    let root = tempfile::tempdir().expect("copy mutation root");
    let source = root.path().join("source");
    fs::create_dir(&source).expect("source directory");
    fs::write(source.join("value"), b"trusted").expect("trusted source");
    let destination = root.path().join("destination");
    let displaced_source = root.path().join("displaced-source");
    copy_tree_exact_with_hooks(
        &source,
        &destination,
        || {
            fs::rename(&source, &displaced_source).expect("displace held source");
            fs::create_dir(&source).expect("replacement source directory");
            fs::write(source.join("value"), b"replacement").expect("replacement source bytes");
        },
        || {},
    )
    .expect("the held source must copy the enumerated inode");
    assert_eq!(
        fs::read(destination.join("value")).expect("copied held bytes"),
        b"trusted"
    );

    let source = root.path().join("second-source");
    fs::create_dir(&source).expect("second source directory");
    fs::write(source.join("value"), b"trusted").expect("second trusted source");
    let destination = root.path().join("second-destination");
    let displaced_destination = root.path().join("displaced-destination");
    let error = copy_tree_exact_with_hooks(
        &source,
        &destination,
        || {},
        || {
            fs::rename(&destination, &displaced_destination).expect("displace held destination");
            fs::create_dir(&destination).expect("replacement destination directory");
        },
    )
    .expect_err("destination pathname replacement must not redirect publication");
    assert!(error.contains("destination binding changed"));

    let overcap = root.path().join("overcap");
    fs::create_dir(&overcap).expect("overcap directory");
    for index in 0..=MAX_TEMPLATE_ENTRIES {
        fs::write(overcap.join(index.to_string()), []).expect("overcap entry");
    }
    assert!(inventory_tree(&overcap).is_err());
}

#[test]
fn rebased_manifest_time_is_exactly_eth1_plus_frozen_delay() {
    use consensus_signature::PqPublicKey;
    use validator_dir::PqManifestValidator;

    let root = [3; 32];
    let manifest = PqDevnetManifest::new(
        1,
        0,
        1119,
        42,
        root,
        vec![PqManifestValidator::new(
            0,
            PqPublicKey::deserialize(&[0x11; 32]).expect("canonical test key"),
            [4; 32],
        )],
    );
    validate_manifest_network_identity(&manifest, root, 342).expect("42 + frozen 300-second delay");
    assert!(validate_manifest_network_identity(&manifest, root, 341).is_err());
    assert!(validate_manifest_network_identity(&manifest, root, 343).is_err());
}

#[test]
fn bounded_enr_read_rejects_symlink_oversize_and_concurrent_rewrite() {
    let root = tempfile::tempdir().expect("ENR mutation root");
    let path = root.path().join("enr.dat");
    fs::write(&path, b"old!").expect("initial ENR bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("initial ENR mode");

    let error = open_bounded_regular_nofollow_with_hook(&path, 8, || {
        fs::write(&path, b"replacement").expect("concurrent ENR rewrite");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("replacement ENR mode");
    })
    .expect_err("a changed held ENR must be rejected");
    assert!(error.contains("changed while read"));

    assert!(open_bounded_regular_nofollow(&path, 4).is_err());
    fs::rename(&path, root.path().join("target")).expect("move ENR target");
    std::os::unix::fs::symlink("target", &path).expect("ENR symlink mutation");
    assert!(open_bounded_regular_nofollow(&path, 16).is_err());

    let modes = root.path().join("mode-enr.dat");
    fs::write(&modes, b"enr").expect("mode ENR bytes");
    for mode in [0o600, 0o604, 0o640, 0o644] {
        fs::set_permissions(&modes, fs::Permissions::from_mode(mode)).expect("safe ENR mode");
        open_bounded_regular_nofollow(&modes, 16).expect("safe restrictive-umask ENR mode");
    }
    for mode in [0o666, 0o620, 0o744, 0o4644] {
        fs::set_permissions(&modes, fs::Permissions::from_mode(mode)).expect("unsafe ENR mode");
        assert!(open_bounded_regular_nofollow(&modes, 16).is_err());
    }

    let fifo = root.path().join("fifo-enr.dat");
    let fifo_path =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path has no NUL");
    // SAFETY: the NUL-terminated path is owned for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o644) }, 0);
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = open_bounded_regular_nofollow(&fifo, 16);
        let _ = finished_tx.send(result);
    });
    assert!(
        finished_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("FIFO inspection must not block")
            .is_err()
    );
}

#[test]
fn authenticated_bundle_loader_accepts_a_held_directory_path() {
    let root = tempfile::tempdir().expect("held bundle root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("held bundle mode");
    let held = open_directory_nofollow(root.path(), Some(0o700)).expect("held bundle directory");
    let error = match PqDevnetBundle::load_for_network_registry(
        bundle_loader_path(&held),
        [0; 32],
        300,
        &[],
    ) {
        Ok(_) => panic!("an empty held bundle remains invalid"),
        Err(error) => error,
    };
    assert!(
        !error
            .to_string()
            .contains("Too many levels of symbolic links"),
        "the real loader must open the held directory before rejecting its contents: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn child_aware_enr_wait_reports_early_exit_with_bounded_diagnostics() {
    let network = tempfile::tempdir().expect("startup wait network directory");
    let mut child = ChildNode::spawn("invalid-startup", &["--pq-e4f-invalid-option".into()]);
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        child.wait_for_enr(network.path(), PROCESS_START_TIMEOUT),
    )
    .await
    .expect("early child exit must beat the long ENR deadline")
    .expect_err("invalid Lighthouse startup must be typed");
    match error {
        ChildStartupError::EarlyExit {
            status,
            diagnostics,
        } => {
            assert!(!status.success());
            assert!(diagnostics.contains("stderr:"));
            assert!(diagnostics.contains("pq-e4f-invalid-option"));
            assert!(diagnostics.len() <= MAX_LOG_FRAME_BYTES * MAX_RETAINED_LOG_FRAMES);
        }
        other => panic!("expected typed early exit, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_real_processes_emit_compatible_status_before_any_proposal() {
    require_pq_avx2_launch_profile();
    let fixture = tokio::task::spawn_blocking(prepare_launch_fixture)
        .await
        .expect("fixture provisioning task");

    let jwt = JwtKey::from_slice(&DEFAULT_JWT_SECRET).expect("JWT key");
    let proposer_engine = MockServer::<MinimalEthSpec>::new(
        &tokio::runtime::Handle::current(),
        jwt.clone(),
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        None,
    );
    let verifier_engine = MockServer::<MinimalEthSpec>::new(
        &tokio::runtime::Handle::current(),
        jwt,
        Some(0),
        Some(0),
        Some(0),
        None,
        None,
        None,
    );
    assert_ne!(proposer_engine.url(), verifier_engine.url());
    for engine in [&proposer_engine, &verifier_engine] {
        engine.full_payload_verification();
        engine
            .execution_block_generator()
            .set_blob_count_range(0, 0);
        engine.insert_pow_block(
            0,
            ExecutionBlockHash::zero(),
            ExecutionBlockHash::zero(),
            Uint256::ZERO,
        );
        assert!(engine.get_block(ExecutionBlockHash::zero()).is_some());
    }

    let proposer_tcp = reserve_tcp_port();
    let proposer_udp = reserve_udp_port();
    let verifier_tcp = reserve_tcp_port();
    let verifier_udp = reserve_udp_port();
    let verifier_only_diagnostic = std::env::var_os("PQ_E4F_VERIFIER_ONLY_DIAGNOSTIC").is_some();
    let proposer_args = node_args(
        &fixture.proposer_data,
        &fixture.proposer_network,
        &fixture.testnet_dir,
        &proposer_engine.url(),
        &fixture.jwt_proposer,
        proposer_tcp,
        proposer_udp,
        None,
        (!verifier_only_diagnostic).then_some(fixture.bundle_dir.as_path()),
    );
    let mut proposer = ChildNode::spawn("proposer", &proposer_args);
    let proposer_enr = proposer
        .wait_for_enr(&fixture.proposer_network, PROCESS_START_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("proposer startup before ENR: {error}"));
    let parsed_proposer_enr = proposer_enr
        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
        .expect("bounded proposer ENR");
    assert_eq!(parsed_proposer_enr.ip4(), Some(Ipv4Addr::LOCALHOST));
    assert_eq!(parsed_proposer_enr.tcp4(), Some(proposer_tcp));
    assert_eq!(parsed_proposer_enr.udp4(), Some(proposer_udp));
    assert_eq!(
        proposer.wait_for_event_count(1, STATUS_EVENT_TIMEOUT).await,
        vec![PqProcessEvent {
            sequence: 1,
            role: if verifier_only_diagnostic {
                PqProcessRole::Verifier
            } else {
                PqProcessRole::Proposer
            },
            kind: PqProcessEventKind::EventWriterReady,
        }]
    );

    let verifier_args = node_args(
        &fixture.verifier_data,
        &fixture.verifier_network,
        &fixture.testnet_dir,
        &verifier_engine.url(),
        &fixture.jwt_verifier,
        verifier_tcp,
        verifier_udp,
        Some(&proposer_enr),
        None,
    );
    let mut verifier = ChildNode::spawn("verifier", &verifier_args);
    let verifier_enr = verifier
        .wait_for_enr(&fixture.verifier_network, PROCESS_START_TIMEOUT)
        .await
        .unwrap_or_else(|error| panic!("verifier startup before ENR: {error}"));
    let parsed_verifier_enr = verifier_enr
        .parse::<discv5::enr::Enr<discv5::enr::CombinedKey>>()
        .expect("bounded verifier ENR");
    assert_eq!(parsed_verifier_enr.ip4(), Some(Ipv4Addr::LOCALHOST));
    assert_eq!(parsed_verifier_enr.tcp4(), Some(verifier_tcp));
    assert_eq!(parsed_verifier_enr.udp4(), Some(verifier_udp));

    let proposer_events = proposer.wait_for_event_count(5, STATUS_EVENT_TIMEOUT).await;
    let verifier_events = verifier.wait_for_event_count(5, STATUS_EVENT_TIMEOUT).await;
    validate_compatible_event_trace(
        &proposer_events,
        if verifier_only_diagnostic {
            PqProcessRole::Verifier
        } else {
            PqProcessRole::Proposer
        },
        PqProcessConnectionDirection::Incoming,
        peer_digest_from_enr(&parsed_verifier_enr),
    )
    .expect("exact proposer-compatible event topology");
    validate_compatible_event_trace(
        &verifier_events,
        PqProcessRole::Verifier,
        PqProcessConnectionDirection::Outgoing,
        peer_digest_from_enr(&parsed_proposer_enr),
    )
    .expect("exact verifier-compatible event topology");

    verifier.stop().await;
    proposer.stop().await;
}
