use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(feature = "pq-startup-testing")]
use std::sync::Arc;
#[cfg(feature = "pq-startup-testing")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::mpsc;
use types::{Epoch, ExecutionBlockHash, Hash256, Slot};

const PQ_OPERATIONAL_EVENT_CAPACITY: usize = 64;
const PQ_OPERATIONAL_EVENT_MAX_LINE_BYTES: usize = 768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqOperationalEventRole {
    Proposer,
    Verifier,
}

impl PqOperationalEventRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Proposer => "proposer",
            Self::Verifier => "verifier",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPeerConnectionDirection {
    Incoming,
    Outgoing,
}

impl PqPeerConnectionDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqStatusMessageDirection {
    Request,
    Response,
}

impl PqStatusMessageDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqStatusRejectionCode {
    ForkDigest,
    FinalizedEpoch,
    FinalizedRoot,
    Capacity,
}

impl PqStatusRejectionCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForkDigest => "fork_digest",
            Self::FinalizedEpoch => "finalized_epoch",
            Self::FinalizedRoot => "finalized_root",
            Self::Capacity => "capacity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqRuntimeStartup {
    Fresh,
    Resume,
}

impl PqRuntimeStartup {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Resume => "resume",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqBlockEventSource {
    Publish,
    Gossip,
}

impl PqBlockEventSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Gossip => "gossip",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqOperationalEvent {
    EventWriterReady,
    RuntimeReady {
        startup: PqRuntimeStartup,
        slot: Slot,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ProposalStarted {
        slot: Slot,
        parent_root: Hash256,
    },
    BlockPersisted {
        source: PqBlockEventSource,
        slot: Slot,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ExecutionReconciled {
        source: PqBlockEventSource,
        slot: Slot,
        block_root: Hash256,
        execution_hash: ExecutionBlockHash,
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    ProposalPublished {
        slot: Slot,
        block_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    GossipImported {
        slot: Slot,
        block_root: Hash256,
        signed_ssz_digest: [u8; 32],
    },
    PeerConnected {
        peer_digest: [u8; 16],
        direction: PqPeerConnectionDirection,
    },
    StatusSent {
        peer_digest: [u8; 16],
        direction: PqStatusMessageDirection,
    },
    StatusRejected {
        peer_digest: [u8; 16],
        code: PqStatusRejectionCode,
    },
    PeerCompatible {
        peer_digest: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqOperationalEventError {
    Capacity,
    Closed,
    SequenceOverflow,
    EncodingOverflow,
    OutputWouldBlock,
    OutputClosed,
    Output,
}

impl std::fmt::Display for PqOperationalEventError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => formatter.write_str("PQ operational event capacity exhausted"),
            Self::Closed => formatter.write_str("PQ operational event writer unavailable"),
            Self::SequenceOverflow => formatter.write_str("PQ operational event sequence overflow"),
            Self::EncodingOverflow => formatter.write_str("PQ operational event line overflow"),
            Self::OutputWouldBlock => {
                formatter.write_str("PQ operational event output would block")
            }
            Self::OutputClosed => formatter.write_str("PQ operational event output closed"),
            Self::Output => formatter.write_str("PQ operational event output unavailable"),
        }
    }
}

impl std::error::Error for PqOperationalEventError {}

#[derive(Clone)]
pub struct PqOperationalEventSink {
    sender: mpsc::Sender<PqOperationalEventCommand>,
    #[cfg(feature = "pq-startup-testing")]
    emitted: Arc<AtomicUsize>,
    #[cfg(feature = "pq-startup-testing")]
    peer_compatible_emitted: Arc<AtomicUsize>,
    #[cfg(feature = "pq-startup-testing")]
    observed: Arc<std::sync::Mutex<Vec<PqOperationalEvent>>>,
    #[cfg(feature = "pq-startup-testing")]
    fail_closed: Arc<AtomicBool>,
}

struct PqOperationalEventCommand {
    event: PqOperationalEvent,
    acknowledgement: Option<tokio::sync::oneshot::Sender<Result<(), PqOperationalEventError>>>,
}

impl PqOperationalEventSink {
    pub fn channel(role: PqOperationalEventRole) -> (Self, PqOperationalEventWriter) {
        Self::channel_with_capacity(role, PQ_OPERATIONAL_EVENT_CAPACITY)
    }

    fn channel_with_capacity(
        role: PqOperationalEventRole,
        capacity: usize,
    ) -> (Self, PqOperationalEventWriter) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Self {
                sender,
                #[cfg(feature = "pq-startup-testing")]
                emitted: Arc::new(AtomicUsize::new(0)),
                #[cfg(feature = "pq-startup-testing")]
                peer_compatible_emitted: Arc::new(AtomicUsize::new(0)),
                #[cfg(feature = "pq-startup-testing")]
                observed: Arc::new(std::sync::Mutex::new(Vec::new())),
                #[cfg(feature = "pq-startup-testing")]
                fail_closed: Arc::new(AtomicBool::new(false)),
            },
            PqOperationalEventWriter {
                role,
                receiver,
                sequence: 0,
            },
        )
    }

    pub fn try_emit(&self, event: PqOperationalEvent) -> Result<(), PqOperationalEventError> {
        self.try_enqueue(event, None)
    }

    pub async fn emit_and_wait(
        &self,
        event: PqOperationalEvent,
    ) -> Result<(), PqOperationalEventError> {
        let (acknowledgement, completion) = tokio::sync::oneshot::channel();
        self.try_enqueue(event, Some(acknowledgement))?;
        completion
            .await
            .map_err(|_| PqOperationalEventError::Closed)?
    }

    fn try_enqueue(
        &self,
        event: PqOperationalEvent,
        acknowledgement: Option<tokio::sync::oneshot::Sender<Result<(), PqOperationalEventError>>>,
    ) -> Result<(), PqOperationalEventError> {
        #[cfg(feature = "pq-startup-testing")]
        if self.fail_closed.load(Ordering::SeqCst) {
            return Err(PqOperationalEventError::Closed);
        }
        #[cfg(feature = "pq-startup-testing")]
        let is_peer_compatible = matches!(event, PqOperationalEvent::PeerCompatible { .. });
        self.sender
            .try_send(PqOperationalEventCommand {
                event,
                acknowledgement,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PqOperationalEventError::Capacity,
                mpsc::error::TrySendError::Closed(_) => PqOperationalEventError::Closed,
            })?;
        #[cfg(feature = "pq-startup-testing")]
        self.emitted.fetch_add(1, Ordering::SeqCst);
        #[cfg(feature = "pq-startup-testing")]
        if is_peer_compatible {
            self.peer_compatible_emitted.fetch_add(1, Ordering::SeqCst);
        }
        #[cfg(feature = "pq-startup-testing")]
        {
            let mut observed = self
                .observed
                .lock()
                .expect("PQ operational event testing observer lock");
            if observed.len() == PQ_OPERATIONAL_EVENT_CAPACITY {
                observed.remove(0);
            }
            observed.push(event);
        }
        Ok(())
    }

    #[cfg(any(test, feature = "pq-startup-testing"))]
    fn testing_channel(
        role: PqOperationalEventRole,
        capacity: usize,
    ) -> (Self, PqOperationalEventWriter) {
        Self::channel_with_capacity(role, capacity)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_emitted_count(&self) -> usize {
        self.emitted.load(Ordering::SeqCst)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_peer_compatible_count(&self) -> usize {
        self.peer_compatible_emitted.load(Ordering::SeqCst)
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_events(&self) -> Vec<PqOperationalEvent> {
        self.observed
            .lock()
            .expect("PQ operational event testing observer lock")
            .clone()
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_fail_closed(&self) {
        self.fail_closed.store(true, Ordering::SeqCst);
    }
}

pub struct PqOperationalEventWriter {
    role: PqOperationalEventRole,
    receiver: mpsc::Receiver<PqOperationalEventCommand>,
    sequence: u64,
}

#[cfg(unix)]
enum PqOperationalEventOutput {
    File(std::fs::File),
    Socket(std::fs::File),
}

#[cfg(unix)]
impl PqOperationalEventOutput {
    fn write_line(&mut self, line: &[u8]) -> Result<(), PqOperationalEventError> {
        match self {
            Self::File(output) => output
                .write_all(line)
                .and_then(|()| output.flush())
                .map_err(PqOperationalEventWriter::map_output_error),
            Self::Socket(output) => {
                // `MSG_DONTWAIT` is local to this call, unlike `O_NONBLOCK` on a duplicated
                // descriptor's shared open-file description. `MSG_NOSIGNAL` turns a closed
                // stdout socket into a typed error instead of terminating the process.
                // SAFETY: `output` owns a live socket descriptor and `line` is readable for its
                // complete length during this call.
                let written = unsafe {
                    libc::send(
                        output.as_raw_fd(),
                        line.as_ptr().cast(),
                        line.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                if written < 0 {
                    return Err(PqOperationalEventWriter::map_output_error(
                        std::io::Error::last_os_error(),
                    ));
                }
                if written as usize != line.len() {
                    return Err(PqOperationalEventError::Output);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PqOperationalEventRecord {
    sequence: u64,
    role: PqOperationalEventRole,
    event: PqOperationalEvent,
}

impl PqOperationalEventWriter {
    #[cfg(any(test, feature = "pq-startup-testing"))]
    async fn next_record(
        &mut self,
    ) -> Result<Option<PqOperationalEventRecord>, PqOperationalEventError> {
        let Some(command) = self.receiver.recv().await else {
            return Ok(None);
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(PqOperationalEventError::SequenceOverflow)?;
        Ok(Some(PqOperationalEventRecord {
            sequence: self.sequence,
            role: self.role,
            event: command.event,
        }))
    }

    fn format_record(record: PqOperationalEventRecord) -> Result<String, PqOperationalEventError> {
        let line = match record.event {
            PqOperationalEvent::EventWriterReady => format!(
                "PQ_EVENT_V1 event=EventWriterReady sequence={} role={}",
                record.sequence,
                record.role.as_str(),
            ),
            PqOperationalEvent::RuntimeReady {
                startup,
                slot,
                block_root,
                execution_hash,
                justified_epoch,
                justified_root,
                finalized_epoch,
                finalized_root,
                signed_ssz_digest,
            } => format!(
                "PQ_EVENT_V1 event=RuntimeReady sequence={} role={} startup={} slot={} block_root={block_root:?} execution_hash={execution_hash:?} justified_epoch={} justified_root={justified_root:?} finalized_epoch={} finalized_root={finalized_root:?} signed_ssz_digest={}",
                record.sequence,
                record.role.as_str(),
                startup.as_str(),
                slot.as_u64(),
                justified_epoch.as_u64(),
                finalized_epoch.as_u64(),
                hex::encode(signed_ssz_digest),
            ),
            PqOperationalEvent::ProposalStarted { slot, parent_root } => format!(
                "PQ_EVENT_V1 event=ProposalStarted sequence={} role={} slot={} parent_root={parent_root:?}",
                record.sequence,
                record.role.as_str(),
                slot.as_u64(),
            ),
            PqOperationalEvent::BlockPersisted {
                source,
                slot,
                block_root,
                execution_hash,
                justified_epoch,
                justified_root,
                finalized_epoch,
                finalized_root,
                signed_ssz_digest,
            } => format!(
                "PQ_EVENT_V1 event=BlockPersisted sequence={} role={} source={} slot={} block_root={block_root:?} execution_hash={execution_hash:?} justified_epoch={} justified_root={justified_root:?} finalized_epoch={} finalized_root={finalized_root:?} signed_ssz_digest={}",
                record.sequence,
                record.role.as_str(),
                source.as_str(),
                slot.as_u64(),
                justified_epoch.as_u64(),
                finalized_epoch.as_u64(),
                hex::encode(signed_ssz_digest),
            ),
            PqOperationalEvent::ExecutionReconciled {
                source,
                slot,
                block_root,
                execution_hash,
                justified_epoch,
                justified_root,
                finalized_epoch,
                finalized_root,
                signed_ssz_digest,
            } => format!(
                "PQ_EVENT_V1 event=ExecutionReconciled sequence={} role={} source={} slot={} block_root={block_root:?} execution_hash={execution_hash:?} justified_epoch={} justified_root={justified_root:?} finalized_epoch={} finalized_root={finalized_root:?} signed_ssz_digest={}",
                record.sequence,
                record.role.as_str(),
                source.as_str(),
                slot.as_u64(),
                justified_epoch.as_u64(),
                finalized_epoch.as_u64(),
                hex::encode(signed_ssz_digest),
            ),
            PqOperationalEvent::ProposalPublished {
                slot,
                block_root,
                signed_ssz_digest,
            } => format!(
                "PQ_EVENT_V1 event=ProposalPublished sequence={} role={} slot={} block_root={block_root:?} signed_ssz_digest={}",
                record.sequence,
                record.role.as_str(),
                slot.as_u64(),
                hex::encode(signed_ssz_digest),
            ),
            PqOperationalEvent::GossipImported {
                slot,
                block_root,
                signed_ssz_digest,
            } => format!(
                "PQ_EVENT_V1 event=GossipImported sequence={} role={} slot={} block_root={block_root:?} signed_ssz_digest={}",
                record.sequence,
                record.role.as_str(),
                slot.as_u64(),
                hex::encode(signed_ssz_digest),
            ),
            PqOperationalEvent::PeerConnected {
                peer_digest,
                direction,
            } => format!(
                "PQ_EVENT_V1 event=PeerConnected sequence={} role={} peer_digest={} direction={}",
                record.sequence,
                record.role.as_str(),
                hex::encode(peer_digest),
                direction.as_str(),
            ),
            PqOperationalEvent::StatusSent {
                peer_digest,
                direction,
            } => format!(
                "PQ_EVENT_V1 event=StatusSent sequence={} role={} peer_digest={} direction={}",
                record.sequence,
                record.role.as_str(),
                hex::encode(peer_digest),
                direction.as_str(),
            ),
            PqOperationalEvent::StatusRejected { peer_digest, code } => format!(
                "PQ_EVENT_V1 event=StatusRejected sequence={} role={} peer_digest={} code={}",
                record.sequence,
                record.role.as_str(),
                hex::encode(peer_digest),
                code.as_str(),
            ),
            PqOperationalEvent::PeerCompatible { peer_digest } => format!(
                "PQ_EVENT_V1 event=PeerCompatible sequence={} role={} peer_digest={}",
                record.sequence,
                record.role.as_str(),
                hex::encode(peer_digest)
            ),
        };
        if line.len() > PQ_OPERATIONAL_EVENT_MAX_LINE_BYTES {
            return Err(PqOperationalEventError::EncodingOverflow);
        }
        Ok(line)
    }

    fn format_record_line(
        record: PqOperationalEventRecord,
    ) -> Result<String, PqOperationalEventError> {
        let mut line = Self::format_record(record)?;
        line.push('\n');
        #[cfg(unix)]
        if line.len() > libc::PIPE_BUF as usize {
            return Err(PqOperationalEventError::EncodingOverflow);
        }
        Ok(line)
    }

    fn map_output_error(error: std::io::Error) -> PqOperationalEventError {
        match error.kind() {
            std::io::ErrorKind::WouldBlock => PqOperationalEventError::OutputWouldBlock,
            std::io::ErrorKind::BrokenPipe => PqOperationalEventError::OutputClosed,
            _ => PqOperationalEventError::Output,
        }
    }

    #[cfg(any(test, feature = "pq-startup-testing"))]
    fn write_record(
        output: &mut impl Write,
        record: PqOperationalEventRecord,
    ) -> Result<(), PqOperationalEventError> {
        let line = Self::format_record_line(record)?;
        output
            .write_all(line.as_bytes())
            .and_then(|()| output.flush())
            .map_err(Self::map_output_error)
    }

    #[cfg(any(test, feature = "pq-startup-testing"))]
    fn run_with_output(mut self, output: &mut impl Write) -> Result<(), PqOperationalEventError> {
        while let Some(command) = self.receiver.blocking_recv() {
            let result = self
                .sequence
                .checked_add(1)
                .ok_or(PqOperationalEventError::SequenceOverflow)
                .and_then(|sequence| {
                    self.sequence = sequence;
                    Self::write_record(
                        output,
                        PqOperationalEventRecord {
                            sequence: self.sequence,
                            role: self.role,
                            event: command.event,
                        },
                    )
                });
            if let Some(acknowledgement) = command.acknowledgement {
                let _ = acknowledgement.send(result);
            }
            result?;
        }
        Ok(())
    }

    #[cfg(feature = "pq-startup-testing")]
    #[doc(hidden)]
    pub fn testing_only_run_with_output(
        self,
        output: &mut impl Write,
    ) -> Result<(), PqOperationalEventError> {
        self.run_with_output(output)
    }

    #[cfg(unix)]
    fn descriptor_stat(descriptor: libc::c_int) -> Result<libc::stat, PqOperationalEventError> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` points to writable storage and `descriptor` is borrowed by the caller.
        let result = unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) };
        if result < 0 {
            Err(PqOperationalEventError::Output)
        } else {
            // SAFETY: successful `fstat` initialized the complete value.
            Ok(unsafe { stat.assume_init() })
        }
    }

    #[cfg(unix)]
    fn descriptor_flags(descriptor: libc::c_int) -> Result<libc::c_int, PqOperationalEventError> {
        // SAFETY: `F_GETFL` reads status flags from the borrowed live descriptor.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0 {
            Err(PqOperationalEventError::Output)
        } else {
            Ok(flags)
        }
    }

    #[cfg(unix)]
    fn reopen_descriptor(
        descriptor: libc::c_int,
        flags: libc::c_int,
    ) -> Result<std::fs::File, PqOperationalEventError> {
        // This procfs magic-link is derived solely from an already-held numeric descriptor.
        // `O_NOFOLLOW` is not viable for descriptor magic-links (it returns `ELOOP`).
        let path = std::ffi::CString::new(format!("/proc/self/fd/{descriptor}"))
            .map_err(|_| PqOperationalEventError::Output)?;
        // SAFETY: `path` is NUL-terminated and the flags do not require a mode argument.
        let reopened = unsafe { libc::open(path.as_ptr(), flags) };
        if reopened < 0 {
            return Err(PqOperationalEventError::Output);
        }
        // SAFETY: `reopened` is a fresh owned descriptor returned by `open` above.
        Ok(unsafe { std::fs::File::from_raw_fd(reopened) })
    }

    #[cfg(unix)]
    fn duplicate_descriptor(
        descriptor: libc::c_int,
    ) -> Result<std::fs::File, PqOperationalEventError> {
        // SAFETY: `F_DUPFD_CLOEXEC` duplicates the borrowed live descriptor without changing its
        // shared status flags or current offset.
        let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(PqOperationalEventError::Output);
        }
        // SAFETY: `duplicate` is a fresh owned descriptor returned by `fcntl` above.
        Ok(unsafe { std::fs::File::from_raw_fd(duplicate) })
    }

    #[cfg(unix)]
    fn output_for_descriptor(
        descriptor: libc::c_int,
    ) -> Result<PqOperationalEventOutput, PqOperationalEventError> {
        let descriptor_stat = Self::descriptor_stat(descriptor)?;
        let descriptor_flags = Self::descriptor_flags(descriptor)?;
        let descriptor_kind = descriptor_stat.st_mode & libc::S_IFMT;
        let (output, socket) = match descriptor_kind {
            libc::S_IFIFO | libc::S_IFCHR => (
                Self::reopen_descriptor(
                    descriptor,
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )?,
                false,
            ),
            libc::S_IFREG if descriptor_flags & libc::O_APPEND != 0 => (
                Self::reopen_descriptor(
                    descriptor,
                    libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC,
                )?,
                false,
            ),
            libc::S_IFREG => (Self::duplicate_descriptor(descriptor)?, false),
            libc::S_IFSOCK => (Self::duplicate_descriptor(descriptor)?, true),
            _ => return Err(PqOperationalEventError::Output),
        };
        let output_stat = Self::descriptor_stat(output.as_raw_fd())?;
        if descriptor_stat.st_dev != output_stat.st_dev
            || descriptor_stat.st_ino != output_stat.st_ino
            || descriptor_kind != output_stat.st_mode & libc::S_IFMT
        {
            return Err(PqOperationalEventError::Output);
        }
        Ok(if socket {
            PqOperationalEventOutput::Socket(output)
        } else {
            PqOperationalEventOutput::File(output)
        })
    }

    #[cfg(unix)]
    fn stdout_output() -> Result<PqOperationalEventOutput, PqOperationalEventError> {
        let descriptor = libc::STDOUT_FILENO;
        let output = Self::output_for_descriptor(descriptor)?;
        // Recheck after construction so a concurrent replacement of fd 1 cannot make the writer
        // silently target a different object than the descriptor validated above.
        let current = Self::descriptor_stat(descriptor)?;
        let bound = match &output {
            PqOperationalEventOutput::File(file) | PqOperationalEventOutput::Socket(file) => {
                Self::descriptor_stat(file.as_raw_fd())?
            }
        };
        if current.st_dev != bound.st_dev
            || current.st_ino != bound.st_ino
            || current.st_mode & libc::S_IFMT != bound.st_mode & libc::S_IFMT
        {
            return Err(PqOperationalEventError::Output);
        }
        Ok(output)
    }

    #[cfg(unix)]
    fn run_with_owned_output(
        mut self,
        mut output: PqOperationalEventOutput,
    ) -> Result<(), PqOperationalEventError> {
        while let Some(command) = self.receiver.blocking_recv() {
            let result = self
                .sequence
                .checked_add(1)
                .ok_or(PqOperationalEventError::SequenceOverflow)
                .and_then(|sequence| {
                    self.sequence = sequence;
                    Self::format_record_line(PqOperationalEventRecord {
                        sequence,
                        role: self.role,
                        event: command.event,
                    })
                })
                .and_then(|line| output.write_line(line.as_bytes()));
            if let Some(acknowledgement) = command.acknowledgement {
                let _ = acknowledgement.send(result);
            }
            result?;
        }
        Ok(())
    }

    #[cfg(all(unix, feature = "pq-startup-testing"))]
    fn testing_write_record_to_descriptor(
        descriptor: libc::c_int,
        record: PqOperationalEventRecord,
    ) -> Result<(), PqOperationalEventError> {
        let mut output = Self::output_for_descriptor(descriptor)?;
        let line = Self::format_record_line(record)?;
        output.write_line(line.as_bytes())
    }

    fn run_after_output_ready(
        self,
        output_ready: impl FnOnce(),
    ) -> Result<(), PqOperationalEventError> {
        #[cfg(unix)]
        {
            let output = Self::stdout_output()?;
            output_ready();
            self.run_with_owned_output(output)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, output_ready);
            Err(PqOperationalEventError::Output)
        }
    }

    pub fn run(self) -> Result<(), PqOperationalEventError> {
        self.run_after_output_ready(|| {})
    }

    #[doc(hidden)]
    pub fn run_with_live_signal(
        self,
        live_sender: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), PqOperationalEventError> {
        self.run_after_output_ready(|| {
            let _ = live_sender.send(());
        })
    }

    #[cfg(any(test, feature = "pq-startup-testing"))]
    async fn testing_next_record(
        &mut self,
    ) -> Result<Option<PqOperationalEventRecord>, PqOperationalEventError> {
        self.next_record().await
    }

    #[cfg(any(test, feature = "pq-startup-testing"))]
    fn testing_set_sequence(&mut self, sequence: u64) {
        self.sequence = sequence;
    }
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqOperationalEventTestTrace {
    pub sequences: Vec<u64>,
    pub roles: Vec<PqOperationalEventRole>,
    pub output: Vec<u8>,
    pub output_error: PqOperationalEventError,
    pub capacity_error: PqOperationalEventError,
    pub closed_error: PqOperationalEventError,
    pub overflow_error: PqOperationalEventError,
    pub forced_closed_error: PqOperationalEventError,
}

#[cfg(feature = "pq-startup-testing")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqOperationalEventAcknowledgementTrace {
    pub pending_before_output: bool,
    pub heartbeat_completed: bool,
    pub result: Result<(), PqOperationalEventError>,
    pub output: Vec<u8>,
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_operational_event_acknowledgement()
-> PqOperationalEventAcknowledgementTrace {
    struct BlockedOutput {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
        bytes: Vec<u8>,
    }

    impl Write for BlockedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.entered
                .send(())
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            self.release
                .recv()
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (sink, writer) =
        PqOperationalEventSink::testing_channel(PqOperationalEventRole::Proposer, 1);
    let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel();
    let writer_thread = std::thread::spawn(move || {
        let mut output = BlockedOutput {
            entered: entered_sender,
            release: release_receiver,
            bytes: vec![],
        };
        let result = writer.run_with_output(&mut output);
        (result, output.bytes)
    });
    let confirmation = tokio::spawn(async move {
        sink.emit_and_wait(PqOperationalEvent::EventWriterReady)
            .await
    });

    entered_receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("writer entered the exact line write");
    let pending_before_output = !confirmation.is_finished();
    let heartbeat_completed = matches!(tokio::spawn(async { 41 }).await, Ok(41));
    release_sender.send(()).expect("release exact line write");
    let result = confirmation.await.expect("acknowledgement task");
    let (writer_result, output) = writer_thread.join().expect("writer thread");
    writer_result.expect("writer completion");
    PqOperationalEventAcknowledgementTrace {
        pending_before_output,
        heartbeat_completed,
        result,
        output,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub async fn testing_only_pq_operational_event_sink() -> PqOperationalEventTestTrace {
    struct BrokenOutput;

    impl Write for BrokenOutput {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    let (sink, mut writer) =
        PqOperationalEventSink::testing_channel(PqOperationalEventRole::Proposer, 2);
    let first = PqOperationalEvent::PeerCompatible {
        peer_digest: [1; 16],
    };
    let second = PqOperationalEvent::PeerCompatible {
        peer_digest: [2; 16],
    };
    sink.try_emit(first).expect("first testing event");
    sink.try_emit(second).expect("second testing event");
    let capacity_error = sink
        .try_emit(first)
        .expect_err("bounded testing event capacity");
    let first_record = writer
        .testing_next_record()
        .await
        .expect("testing sequence")
        .expect("first testing record");
    let second_record = writer
        .testing_next_record()
        .await
        .expect("testing sequence")
        .expect("second testing record");
    let mut output = vec![];
    PqOperationalEventWriter::write_record(&mut output, first_record)
        .expect("bounded testing event output");
    PqOperationalEventWriter::write_record(&mut output, second_record)
        .expect("bounded testing event output");
    let output_error = PqOperationalEventWriter::write_record(&mut BrokenOutput, first_record)
        .expect_err("broken output must fail closed");
    drop(writer);
    let closed_error = sink
        .try_emit(first)
        .expect_err("closed testing event writer");

    let (overflow_sink, mut overflow_writer) =
        PqOperationalEventSink::testing_channel(PqOperationalEventRole::Verifier, 1);
    overflow_sink
        .try_emit(first)
        .expect("overflow testing event");
    overflow_writer.testing_set_sequence(u64::MAX);
    let overflow_error = overflow_writer
        .testing_next_record()
        .await
        .expect_err("checked testing event sequence");
    let (forced_closed_sink, _forced_closed_writer) =
        PqOperationalEventSink::testing_channel(PqOperationalEventRole::Verifier, 1);
    forced_closed_sink.testing_only_fail_closed();
    let forced_closed_error = forced_closed_sink
        .try_emit(first)
        .expect_err("testing forced event failure");
    PqOperationalEventTestTrace {
        sequences: vec![first_record.sequence, second_record.sequence],
        roles: vec![first_record.role, second_record.role],
        output,
        output_error,
        capacity_error,
        closed_error,
        overflow_error,
        forced_closed_error,
    }
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_pq_extended_operational_event_contract() -> Vec<u8> {
    let finalized_root = Hash256::repeat_byte(3);
    let block_root = Hash256::repeat_byte(6);
    let execution_hash = ExecutionBlockHash::repeat_byte(7);
    let signed_ssz_digest = [8; 32];
    let events = [
        PqOperationalEvent::RuntimeReady {
            startup: PqRuntimeStartup::Fresh,
            slot: Slot::new(1),
            block_root: Hash256::repeat_byte(1),
            execution_hash: ExecutionBlockHash::repeat_byte(2),
            justified_epoch: Epoch::new(0),
            justified_root: Hash256::ZERO,
            finalized_epoch: Epoch::new(0),
            finalized_root,
            signed_ssz_digest: [4; 32],
        },
        PqOperationalEvent::ProposalStarted {
            slot: Slot::new(2),
            parent_root: Hash256::repeat_byte(5),
        },
        PqOperationalEvent::BlockPersisted {
            source: PqBlockEventSource::Publish,
            slot: Slot::new(2),
            block_root,
            execution_hash,
            justified_epoch: Epoch::new(0),
            justified_root: Hash256::ZERO,
            finalized_epoch: Epoch::new(0),
            finalized_root,
            signed_ssz_digest,
        },
        PqOperationalEvent::ExecutionReconciled {
            source: PqBlockEventSource::Publish,
            slot: Slot::new(2),
            block_root,
            execution_hash,
            justified_epoch: Epoch::new(0),
            justified_root: Hash256::ZERO,
            finalized_epoch: Epoch::new(0),
            finalized_root,
            signed_ssz_digest,
        },
        PqOperationalEvent::ProposalPublished {
            slot: Slot::new(2),
            block_root,
            signed_ssz_digest,
        },
        PqOperationalEvent::GossipImported {
            slot: Slot::new(2),
            block_root,
            signed_ssz_digest,
        },
    ];
    let mut output = vec![];
    for (offset, event) in events.into_iter().enumerate() {
        PqOperationalEventWriter::write_record(
            &mut output,
            PqOperationalEventRecord {
                sequence: u64::try_from(offset + 1).expect("bounded testing sequence"),
                role: PqOperationalEventRole::Proposer,
                event,
            },
        )
        .expect("bounded extended testing event");
    }
    output
}

#[cfg(feature = "pq-startup-testing")]
#[doc(hidden)]
pub fn testing_only_running_pq_operational_event_sink(
    task_executor: &task_executor::TaskExecutor,
) -> Arc<PqOperationalEventSink> {
    let (sink, writer) = PqOperationalEventSink::channel(PqOperationalEventRole::Verifier);
    let _ = task_executor.spawn_blocking_handle_without_exit(
        move || {
            let _ = writer.run();
        },
        "testing-pq-operational-event-writer",
    );
    Arc::new(sink)
}

#[cfg(all(feature = "pq-startup-testing", unix))]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqOperationalEventNonblockingWriterTrace {
    pub error: PqOperationalEventError,
    pub stdout_flags_unchanged: bool,
    pub dedicated_thread: bool,
    pub heartbeat_completed: bool,
    pub completion_bounded: bool,
}

#[cfg(all(feature = "pq-startup-testing", unix))]
#[doc(hidden)]
pub async fn testing_only_pq_operational_event_nonblocking_writer(
    task_executor: &task_executor::TaskExecutor,
) -> PqOperationalEventNonblockingWriterTrace {
    use std::os::unix::net::UnixStream;

    // SAFETY: `STDOUT_FILENO` is a process-owned descriptor and `F_GETFL` does not mutate it.
    let stdout_flags_before = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
    assert!(stdout_flags_before >= 0, "testing stdout flags");
    let (stdout_sink, stdout_writer) =
        PqOperationalEventSink::channel(PqOperationalEventRole::Verifier);
    let (stdout_live_sender, stdout_live_receiver) = tokio::sync::oneshot::channel();
    let stdout_completion = task_executor
        .spawn_blocking_handle_without_exit(
            move || stdout_writer.run_with_live_signal(stdout_live_sender),
            "testing-pq-stdout-operational-event-writer",
        )
        .expect("testing stdout event writer");
    stdout_live_receiver
        .await
        .expect("testing stdout event writer live");
    // SAFETY: same live process-owned descriptor and read-only command.
    let stdout_flags_during = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
    drop(stdout_sink);
    stdout_completion
        .await
        .expect("testing stdout writer result channel")
        .expect("testing stdout writer task")
        .expect("testing stdout writer completion");
    // SAFETY: same live process-owned descriptor and read-only command.
    let stdout_flags_after = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };

    let (mut output, _undrained_reader) = UnixStream::pair().expect("testing event output pipe");
    output
        .set_nonblocking(true)
        .expect("nonblocking testing event output");
    let fill = [0_u8; 4096];
    loop {
        match output.write(&fill) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill testing event output: {error}"),
        }
    }

    let (sink, writer) = PqOperationalEventSink::channel(PqOperationalEventRole::Verifier);
    let (live_sender, live_receiver) = tokio::sync::oneshot::channel();
    let caller_thread = std::thread::current().id();
    let dedicated_thread = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_dedicated_thread = Arc::clone(&dedicated_thread);
    let completion = task_executor
        .spawn_blocking_handle_without_exit(
            move || {
                task_dedicated_thread.store(
                    std::thread::current().id() != caller_thread,
                    Ordering::SeqCst,
                );
                let _ = live_sender.send(());
                writer.run_with_output(&mut output)
            },
            "testing-pq-nonblocking-operational-event-writer",
        )
        .expect("testing blocking event writer");
    live_receiver.await.expect("testing event writer live");
    sink.try_emit(PqOperationalEvent::EventWriterReady)
        .expect("testing event enqueue");
    let heartbeat_completed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let completion = tokio::time::timeout(std::time::Duration::from_secs(1), completion).await;
    let completion_bounded = completion.is_ok();
    let error = completion
        .expect("testing event writer bounded completion")
        .expect("testing event writer result channel")
        .expect("testing event writer task")
        .expect_err("full nonblocking output must fail closed");
    PqOperationalEventNonblockingWriterTrace {
        error,
        stdout_flags_unchanged: stdout_flags_before == stdout_flags_during
            && stdout_flags_before == stdout_flags_after,
        dedicated_thread: dedicated_thread.load(Ordering::SeqCst),
        heartbeat_completed,
        completion_bounded,
    }
}

#[cfg(all(feature = "pq-startup-testing", unix))]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct PqOperationalEventStdoutKindsTrace {
    pub nonappend_shared_offset_advanced: bool,
    pub nonappend_prefix_preserved: bool,
    pub append_retained: bool,
    pub socket_flags_unchanged: bool,
    pub socket_result: Result<(), PqOperationalEventError>,
    pub pipe_flags_unchanged: bool,
    pub pipe_result: Result<(), PqOperationalEventError>,
}

#[cfg(all(feature = "pq-startup-testing", unix))]
#[doc(hidden)]
pub fn testing_only_pq_operational_event_stdout_kinds() -> PqOperationalEventStdoutKindsTrace {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::net::UnixStream;

    const PREFIX: &[u8; 16] = b"0123456789abcdef";
    const EVENT_LINE: &[u8] = b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=verifier\n";

    let record = PqOperationalEventRecord {
        sequence: 1,
        role: PqOperationalEventRole::Verifier,
        event: PqOperationalEvent::EventWriterReady,
    };
    let descriptor_flags = |descriptor| {
        PqOperationalEventWriter::descriptor_flags(descriptor).expect("testing descriptor flags")
    };

    let mut nonappend = tempfile::tempfile().expect("testing non-append stdout file");
    nonappend
        .write_all(PREFIX)
        .expect("testing non-append prefix");
    nonappend
        .seek(SeekFrom::Start(PREFIX.len() as u64))
        .expect("testing non-append initial offset");
    let nonappend_flags_before = descriptor_flags(nonappend.as_raw_fd());
    PqOperationalEventWriter::testing_write_record_to_descriptor(nonappend.as_raw_fd(), record)
        .expect("testing non-append event");
    let nonappend_offset = nonappend
        .stream_position()
        .expect("testing non-append final offset");
    let nonappend_flags_after = descriptor_flags(nonappend.as_raw_fd());
    nonappend
        .seek(SeekFrom::Start(0))
        .expect("testing non-append rewind");
    let mut nonappend_bytes = vec![];
    nonappend
        .read_to_end(&mut nonappend_bytes)
        .expect("testing non-append contents");
    let nonappend_shared_offset_advanced = nonappend_offset
        == PREFIX.len() as u64 + EVENT_LINE.len() as u64
        && nonappend_flags_before == nonappend_flags_after;
    let nonappend_prefix_preserved = nonappend_bytes == [PREFIX.as_slice(), EVENT_LINE].concat();

    let append_path = tempfile::NamedTempFile::new().expect("testing append stdout path");
    std::fs::write(append_path.path(), PREFIX).expect("testing append prefix");
    let append = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(append_path.path())
        .expect("testing append stdout file");
    let append_flags_before = descriptor_flags(append.as_raw_fd());
    PqOperationalEventWriter::testing_write_record_to_descriptor(append.as_raw_fd(), record)
        .expect("testing append event");
    let append_flags_after = descriptor_flags(append.as_raw_fd());
    let append_bytes = std::fs::read(append_path.path()).expect("testing append contents");
    let append_retained = append_flags_before & libc::O_APPEND != 0
        && append_flags_before == append_flags_after
        && append_bytes == [PREFIX.as_slice(), EVENT_LINE].concat();

    let (socket, mut socket_peer) = UnixStream::pair().expect("testing stdout socket pair");
    socket_peer
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .expect("testing stdout socket timeout");
    let socket_flags_before = descriptor_flags(socket.as_raw_fd());
    let socket_result =
        PqOperationalEventWriter::testing_write_record_to_descriptor(socket.as_raw_fd(), record);
    let socket_flags_after = descriptor_flags(socket.as_raw_fd());
    if socket_result.is_ok() {
        let mut socket_bytes = vec![0; EVENT_LINE.len()];
        socket_peer
            .read_exact(&mut socket_bytes)
            .expect("testing complete stdout socket event");
        assert_eq!(
            socket_bytes, EVENT_LINE,
            "testing exact stdout socket event"
        );
    }

    let mut pipe_descriptors = [-1; 2];
    // SAFETY: `pipe_descriptors` points to two writable integers and `O_CLOEXEC` is valid.
    let pipe_result = unsafe { libc::pipe2(pipe_descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(pipe_result, 0, "testing stdout pipe");
    // SAFETY: both descriptors are freshly owned by this function after successful `pipe2`.
    let _pipe_reader = unsafe { std::fs::File::from_raw_fd(pipe_descriptors[0]) };
    // SAFETY: same as above; the writer is retained in the original blocking mode.
    let pipe_writer = unsafe { std::fs::File::from_raw_fd(pipe_descriptors[1]) };
    let pipe_flags_before = descriptor_flags(pipe_writer.as_raw_fd());
    let mut pipe_filler = PqOperationalEventWriter::reopen_descriptor(
        pipe_writer.as_raw_fd(),
        libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
    .expect("testing independent nonblocking pipe writer");
    let fill = [0_u8; 4096];
    loop {
        match pipe_filler.write(&fill) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill testing stdout pipe: {error}"),
        }
    }
    let pipe_result = PqOperationalEventWriter::testing_write_record_to_descriptor(
        pipe_writer.as_raw_fd(),
        record,
    );
    let pipe_flags_after = descriptor_flags(pipe_writer.as_raw_fd());

    PqOperationalEventStdoutKindsTrace {
        nonappend_shared_offset_advanced,
        nonappend_prefix_preserved,
        append_retained,
        socket_flags_unchanged: socket_flags_before == socket_flags_after,
        socket_result,
        pipe_flags_unchanged: pipe_flags_before == pipe_flags_after,
        pipe_result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_sink_is_bounded_sequenced_and_fail_closed() {
        let (sink, mut writer) =
            PqOperationalEventSink::testing_channel(PqOperationalEventRole::Proposer, 2);
        let first = PqOperationalEvent::PeerCompatible {
            peer_digest: [1; 16],
        };
        let second = PqOperationalEvent::PeerCompatible {
            peer_digest: [2; 16],
        };
        sink.try_emit(first).unwrap();
        sink.try_emit(second).unwrap();
        assert_eq!(sink.try_emit(first), Err(PqOperationalEventError::Capacity));

        let first_record = writer.testing_next_record().await.unwrap().unwrap();
        let second_record = writer.testing_next_record().await.unwrap().unwrap();
        assert_eq!(first_record.sequence, 1);
        assert_eq!(second_record.sequence, 2);
        assert_eq!(first_record.role, PqOperationalEventRole::Proposer);
        assert_eq!(first_record.event, first);
        assert_eq!(second_record.event, second);

        drop(writer);
        assert_eq!(sink.try_emit(first), Err(PqOperationalEventError::Closed));
    }

    #[tokio::test]
    async fn event_sequence_overflow_is_terminal() {
        let (sink, mut writer) =
            PqOperationalEventSink::testing_channel(PqOperationalEventRole::Verifier, 1);
        sink.try_emit(PqOperationalEvent::PeerCompatible {
            peer_digest: [3; 16],
        })
        .unwrap();
        writer.testing_set_sequence(u64::MAX);
        assert_eq!(
            writer.testing_next_record().await,
            Err(PqOperationalEventError::SequenceOverflow)
        );
    }

    struct BrokenOutput;

    impl Write for BrokenOutput {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    #[tokio::test]
    async fn writer_formats_without_a_tracing_subscriber_and_fails_on_broken_output() {
        let (sink, mut writer) =
            PqOperationalEventSink::testing_channel(PqOperationalEventRole::Proposer, 1);
        sink.try_emit(PqOperationalEvent::EventWriterReady).unwrap();
        let record = writer.testing_next_record().await.unwrap().unwrap();
        let mut output = vec![];
        PqOperationalEventWriter::write_record(&mut output, record).unwrap();
        assert_eq!(
            output,
            b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer\n"
        );

        assert_eq!(
            PqOperationalEventWriter::write_record(&mut BrokenOutput, record),
            Err(PqOperationalEventError::OutputClosed)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn result_bearing_emit_waits_for_the_complete_output_line() {
        struct BlockedOutput {
            entered: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
            bytes: Vec<u8>,
        }

        impl Write for BlockedOutput {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.entered
                    .send(())
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                self.release
                    .recv()
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (sink, writer) =
            PqOperationalEventSink::testing_channel(PqOperationalEventRole::Proposer, 1);
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let writer_thread = std::thread::spawn(move || {
            let mut output = BlockedOutput {
                entered: entered_sender,
                release: release_receiver,
                bytes: vec![],
            };
            let result = writer.run_with_output(&mut output);
            (result, output.bytes)
        });
        let confirmation = tokio::spawn(async move {
            sink.emit_and_wait(PqOperationalEvent::EventWriterReady)
                .await
        });

        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("writer entered the exact line write");
        assert!(
            !confirmation.is_finished(),
            "enqueue alone must not acknowledge RuntimeReady"
        );
        assert_eq!(tokio::spawn(async { 41 }).await.unwrap(), 41);
        release_sender.send(()).expect("release exact line write");
        assert_eq!(confirmation.await.unwrap(), Ok(()));
        let (result, bytes) = writer_thread.join().expect("writer thread");
        assert_eq!(result, Ok(()));
        assert_eq!(
            bytes,
            b"PQ_EVENT_V1 event=EventWriterReady sequence=1 role=proposer\n"
        );
    }
}
