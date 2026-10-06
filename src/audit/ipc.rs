//! The inter-process audit channels: how the forked FS/P children send
//! their audit events upstream to the launcher's single file writer.
//!
//! Single writer per run: the launcher (process A) is the only process
//! that touches the log file. The FUSE server (FS) and the in-sandbox
//! network frontends (P) send their events upstream over pre-fork Unix
//! socketpairs ([`set_channel`]/[`add_peer`]): each child runs a
//! [`channel_writer`] task serializing its events into the socket, and
//! the launcher runs one hub reader per channel ([`spawn_hub`])
//! forwarding the frames into its own queue — the same bounded queue
//! the file writer ([`crate::audit::writer::writer`]) consumes.
//! Backpressure is end-to-end and symmetric (full queue → reader
//! suspends → socket fills → child's writer suspends → `record`
//! suspends), so the never-drop, suspend-on-full semantics hold across
//! the process boundary. On the non-isolated path the launcher has no
//! runtime yet unless runtime control is enabled, so the FUSE server
//! there otherwise keeps its own file writer.
//!
//! The same pairs carry the runtime-control plane (`crate::cli::control`)
//! bidirectionally: the launcher pushes `{"upd": ...}` frames down, the
//! child answers `{"ack":true}`/`{"err":...}` up, and the hub reader
//! demultiplexes replies from audit events (see [`UpdReply`]). Upstream
//! writes share the socket between the child's audit batches and its
//! control replies; both go through the one mutex-guarded write stream
//! ([`reply_writer`]), so frames never interleave mid-line. Each child
//! keeps the *read* half in [`channel_reader`] for its control loop.
//!
//! The log file side lives in [`crate::audit::writer`]; the dispatch
//! between the two sinks happens in [`crate::audit`] (`setup`).

use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::mpsc::Sender;

use super::Event;

/// The cap for one serialized event frame on an inter-process channel
/// (the `waf/mod.rs` `MAX_REPLY` precedent). `record` truncates `detail`
/// so a frame always fits; the hub readers enforce the same cap.
pub(crate) const FRAME_CAP: usize = 64 * 1024;

/// Which child a pre-fork socketpair belongs to. The launcher's hub uses
/// the role to route each child's control-plane replies (`fs-set` waits
/// on the FUSE server's channel, `net-set` on the proxy's).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PeerRole {
    /// The FUSE server (FS).
    HostFs,
    /// The in-sandbox network frontend (P; proxy mode only for replies).
    Network,
}

/// A child's reply to a launcher-pushed update frame: `{"ack":true}` or
/// `{"err":"..."}`. Demultiplexed from audit events by the hub reader —
/// the two frame kinds are distinguishable by shape (an audit `Event`
/// always carries `ts`/`pid`/`source`/`op`; a reply has exactly one of
/// `ack`/`err`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum UpdReply {
    Ack,
    Err(String),
}

impl UpdReply {
    /// Parse one channel line as a reply frame; `None` when the line is
    /// not a reply (it may still be a valid audit event).
    ///
    /// SP-2: a frame that carries any event field is never a reply, even
    /// if it also has `"ack"`/`"err"` — a compromised child must not be
    /// able to divert its audit events into the reply channel (where
    /// they would be silently dropped instead of logged) by appending a
    /// reply key to a valid event. The hub parses the `Event` first; a
    /// frame that is an event plus a reply key fails the event parse
    /// (`deny_unknown_fields`) and the reply parse here, so the reader
    /// ends the channel instead of dropping the event.
    pub(crate) fn parse(line: &str) -> Option<UpdReply> {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        // Event fields present ⇒ not a reply, whatever else it says.
        for field in ["ts", "pid", "source", "op"] {
            if value.get(field).is_some() {
                return None;
            }
        }
        if value.get("ack").and_then(serde_json::Value::as_bool) == Some(true) {
            return Some(UpdReply::Ack);
        }
        if let Some(err) = value.get("err") {
            return Some(UpdReply::Err(err.as_str()?.to_string()));
        }
        None
    }
}

/// Whether the inter-process audit channels are enabled: the launcher
/// sets this after [`crate::audit::writer::configure`] (isolated path,
/// or the non-isolated path when runtime control is enabled). Children
/// create their socketpairs only when this is on, so a non-isolated run
/// without control keeps its FUSE-server file writer.
static IPC_ENABLED: AtomicBool = AtomicBool::new(false);

/// This process's upstream channel (the FS/P child end of a pre-fork
/// socketpair), registered right after the fork. `setup` takes it once
/// and splits it into the read half ([`channel_reader`], the control
/// loop's) and the mutex-guarded write half ([`reply_writer`], shared by
/// the audit [`channel_writer`] and the control replies).
static CHANNEL_FD: OnceLock<Mutex<Option<OwnedFd>>> = OnceLock::new();

/// The launcher-side ends of the child channels (the "peers" the hub
/// reads), registered by the code that creates the pairs — tagged with
/// the peer's role. Consumed once by [`spawn_hub`].
static PEERS: OnceLock<Mutex<Vec<(PeerRole, OwnedFd)>>> = OnceLock::new();

/// Duplicated launcher-side peer fds (one per role), from which
/// [`peer_writer`] hands out a fresh non-blocking tokio stream per
/// update push. The hub readers own *other* dups of the same sockets
/// (see [`PEER_RAW_FDS`]); a `push_upd` write and a hub read never
/// interfere — full-duplex sockets.
static PEER_WRITER_FDS: Mutex<Vec<(PeerRole, RawFd)>> = Mutex::new(Vec::new());

/// Raw copies of the peer fds the hub is reading, kept so
/// [`shutdown_peers`] can half-close them after the hub is spawned (the
/// streams themselves are owned by the reader tasks).
static PEER_RAW_FDS: Mutex<Vec<RawFd>> = Mutex::new(Vec::new());

/// The child's mutex-guarded write half of its upstream channel: shared
/// between the audit [`channel_writer`] (batches of events) and the
/// control child loops (single ack/err replies) so frames never tear.
static REPLY_WRITER: OnceLock<Arc<tokio::sync::Mutex<UnixStream>>> = OnceLock::new();

/// The child's read half of its channel (a dup made when the channel fd
/// is consumed), taken once by the control child loop in FS/P.
static CHANNEL_READER: Mutex<Option<StdUnixStream>> = Mutex::new(None);

/// Whether the inter-process audit channels are enabled (see
/// [`set_ipc_enabled`]).
pub fn ipc_enabled() -> bool {
    IPC_ENABLED.load(Ordering::Relaxed)
}

/// Enable the inter-process audit channels. Called by `cli::run` after
/// [`crate::audit::writer::configure`], before any fork: the launcher
/// itself becomes the only audit writer, and FS/P send their events
/// upstream over socketpairs. On the non-isolated path the launcher has
/// no runtime — unless runtime control is enabled, in which case the
/// supervisor's runtime serves the control socket *and* the audit hub.
pub fn set_ipc_enabled(enabled: bool) {
    IPC_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether a pre-fork socketpair should be created for a child: the IPC
/// subsystem must be on, and the pair must have a consumer — an audit
/// log to feed, or the control plane (whose update frames and replies
/// need the channel even without a log).
pub fn ipc_channel_wanted() -> bool {
    ipc_enabled() && (super::writer::configured() || crate::cli::control::running())
}

/// Register this process's upstream channel (the child end of a pre-fork
/// socketpair). Called in FS/P right after the fork, before any other
/// work: from then on `record` sends into the channel instead of a log
/// file. The fd is consumed by `setup` when the writer task is built.
pub fn set_channel(fd: OwnedFd) {
    let _ = CHANNEL_FD.set(Mutex::new(Some(fd)));
}

/// Register a launcher-side end of a child channel (the "peer" the hub
/// reads) with the peer's role. Called by the parent right after
/// creating the pair. Also keeps a dup for [`peer_writer`].
pub fn add_peer(role: PeerRole, fd: OwnedFd) {
    // A dup for the control plane's downstream writes (upd frames). Made
    // here, eagerly, so the raw number exists before any runtime — the
    // tokio stream is built lazily inside [`peer_writer`].
    let dup = match fd.try_clone() {
        Ok(dup) => dup,
        Err(e) => crate::sandbox::die(&format!("Can't set up the audit channel: {e}")),
    };
    PEER_WRITER_FDS
        .lock()
        .unwrap()
        .push((role, dup.into_raw_fd()));
    PEERS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push((role, fd));
}

/// A fresh write end for pushing one update frame to a child: a
/// non-blocking tokio stream over the dup registered in [`add_peer`].
/// Called inside the launcher's runtime (a push is always async).
pub fn peer_writer(role: PeerRole) -> Option<UnixStream> {
    let raw = PEER_WRITER_FDS
        .lock()
        .unwrap()
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, fd)| *fd)?;
    let dup = match unsafe { libc::dup(raw) } {
        d if d >= 0 => unsafe { OwnedFd::from_raw_fd(d) },
        _ => return None,
    };
    let stream = unsafe { StdUnixStream::from_raw_fd(dup.into_raw_fd()) };
    if let Err(e) = stream.set_nonblocking(true) {
        crate::sandbox::die(&format!("Can't set up the audit {role:?} writer: {e}"));
    }
    match UnixStream::from_std(stream) {
        Ok(stream) => Some(stream),
        Err(e) => crate::sandbox::die(&format!("Can't set up the audit {role:?} writer: {e}")),
    }
}

/// Close everything audit-related this process inherited across a fork
/// but must not hold: the launcher's peer ends (a lingering copy in a
/// child would keep the launcher's reader from ever seeing EOF) and, if
/// one was somehow registered, the upstream channel. Called by fork
/// children that are *not* audit children of the pair in question —
/// process P closing the inherited A↔FS peer end.
pub(crate) fn close_inherited() {
    if let Some(peers) = PEERS.get() {
        // Dropping the OwnedFds closes the fds.
        *peers.lock().unwrap() = Vec::new();
    }
    for (_, fd) in PEER_WRITER_FDS.lock().unwrap().drain(..) {
        unsafe { libc::close(fd) };
    }
    if let Some(cell) = CHANNEL_FD.get() {
        *cell.lock().unwrap() = None;
    }
}

/// Close the inherited audit-log fd. Called by audit children (FS/P)
/// right after registering their channel: the launcher is the only
/// process holding the log during the run. `setup`'s file branch then
/// finds no descriptor and would stay inert — but children take the
/// channel branch anyway.
pub(crate) fn drop_log_fd() {
    if let Some(Some(log)) = super::writer::LOG.get() {
        log.file.lock().unwrap().take();
    }
}

/// Take the registered peer fds. Once: the hub consumes them.
fn take_peers() -> Vec<(PeerRole, OwnedFd)> {
    match PEERS.get() {
        Some(peers) => std::mem::take(&mut *peers.lock().unwrap()),
        None => Vec::new(),
    }
}

/// Take this process's upstream channel fd (the child end of a pre-fork
/// socketpair). Once: [`channel_streams`] consumes it.
fn take_channel_fd() -> Option<OwnedFd> {
    CHANNEL_FD
        .get()
        .and_then(|cell| cell.lock().unwrap().take())
}

/// What [`spawn_hub`] hands back: the reader tasks (awaited during the
/// shutdown choreography, so every child's final batch is in the file
/// before the final flush) and one reply receiver per child channel
/// (consumed by the control server's update pusher).
pub struct Hub {
    pub readers: Vec<tokio::task::JoinHandle<()>>,
    pub replies: Vec<(PeerRole, tokio::sync::mpsc::Receiver<UpdReply>)>,
}

/// Spawn one hub reader task per registered peer, all feeding this
/// process's own event queue (the same bounded queue `record` uses) and
/// their per-role reply channel. Must run inside the launcher's runtime;
/// lazy-inits the queue like `record` does.
///
/// Backpressure is end-to-end and symmetric: a full file-writer queue
/// suspends the readers, which fills the sockets, which suspends the
/// children's `channel_writer`s, which suspends their `record` callers —
/// the never-drop, suspend semantics now across process boundaries.
/// The readers are independent tasks that only ever `send` into the
/// queue, so they cannot deadlock with the connector/waf serve loops —
/// and never share an await point with the control-request handler (a
/// full audit queue must not backpressure a child while the control
/// server awaits its apply-ack; replies are therefore demultiplexed
/// here, not queued behind events).
pub fn spawn_hub() -> Hub {
    let sender = super::queue_sender();
    let peers = take_peers();
    let mut readers = Vec::with_capacity(peers.len());
    let mut replies = Vec::with_capacity(peers.len());
    for (role, fd) in peers {
        let raw = fd.into_raw_fd();
        let stream = unsafe { StdUnixStream::from_raw_fd(raw) };
        if let Err(e) = stream.set_nonblocking(true) {
            crate::sandbox::die(&format!("Can't set up the audit hub: {e}"));
        }
        let stream = match UnixStream::from_std(stream) {
            Ok(stream) => stream,
            Err(e) => crate::sandbox::die(&format!("Can't set up the audit hub: {e}")),
        };
        // Keep the raw number for shutdown_peers' half-close; the
        // fd itself is owned (and closed) by the reader task.
        PEER_RAW_FDS.lock().unwrap().push(raw);
        // One reply channel per peer: the control server awaits at most
        // one outstanding update per channel, so a small buffer suffices.
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel::<UpdReply>(8);
        replies.push((role, reply_rx));
        readers.push(tokio::spawn(hub_reader(
            stream,
            role,
            sender.clone(),
            reply_tx,
        )));
    }
    Hub { readers, replies }
}

/// One hub reader: read frames from a child's channel until EOF (the
/// child's "queue flushed" signal). Each frame is either an audit
/// `Event` forwarded into the launcher's queue (dropped when the process
/// has no audit sink: the pair exists for the control plane then) or a
/// control reply ([`UpdReply`], forwarded to the per-role receiver — a
/// missing or gone receiver only means the control server is not
/// running, never a reason to end the reader). The `Event` parse runs
/// first (SP-2): an event always carries `ts`/`pid`/`source`/`op` and
/// rejects unknown fields, so a reply-shaped frame is unambiguously
/// distinguishable and a frame that is an event plus a reply key cannot
//  be diverted to the reply channel (where it would be dropped from the
//  log).
///
/// The event's `source` is cross-checked against the channel's peer role
/// (SP-2): each child is trusted to emit only its own component's source
/// (`hostfs` for FS, `proxy`/`waf` for P), and a claimed source outside
/// that set — e.g. a compromised FS claiming `source: "control"` with
/// the launcher's pid to forge attribution — is overridden with the
/// role's trusted label, with the claimed value preserved in `detail`.
///
/// A malformed frame (over cap, non-UTF-8, NUL, neither reply nor event)
/// is a bug in a trusted fork child, or an attack by a compromised child
/// (see SP-2), not something to tolerate: warn once on stderr and end
/// the reader — a bug in a child must not kill the run, and a child that
/// attacks the audit channel is cut off instead of being obeyed.
pub(crate) async fn hub_reader(
    mut stream: UnixStream,
    role: PeerRole,
    tx: Option<Sender<Event>>,
    reply_tx: Sender<UpdReply>,
) {
    let mut malformed_reported = false;
    let warn = |e: &str, reported: &mut bool| {
        if !*reported {
            *reported = true;
            eprintln!(
                "warning: malformed audit frame from a sandbox child ({e}); closing its channel"
            );
        }
    };
    loop {
        match crate::line::read_frame_limited(&mut stream, FRAME_CAP).await {
            Ok(Some(line)) => {
                match serde_json::from_str::<Event>(&line) {
                    Ok(mut event) => {
                        stamp_source(&mut event, role);
                        if let Some(tx) = &tx
                            && tx.send(event).await.is_err()
                        {
                            // The file writer is gone (process
                            // exiting); nothing to forward to.
                            return;
                        }
                    }
                    // Not an event: a control reply (or malformed).
                    Err(_) => {
                        if let Some(reply) = UpdReply::parse(&line) {
                            // The control plane is not listening on this
                            // channel (or is gone): drop the reply, keep
                            // reading events.
                            let _ = reply_tx.send(reply).await;
                            continue;
                        }
                        warn(
                            &format!(
                                "neither an audit event nor a control reply: {}",
                                &line[..line.len().min(120)]
                            ),
                            &mut malformed_reported,
                        );
                        return;
                    }
                }
            }
            // Clean EOF: the child flushed its queue and closed.
            Ok(None) => return,
            Err(e) => {
                warn(&e.to_string(), &mut malformed_reported);
                return;
            }
        }
    }
}

/// The `source` values each peer role may legitimately claim, and the
/// trusted label a forgery is overridden with (SP-2).
fn stamp_source(event: &mut Event, role: PeerRole) {
    let (allowed, trusted): (&[&str], &str) = match role {
        PeerRole::HostFs => (&["hostfs"], "hostfs"),
        // P serves both the proxy frontends and the waf host.
        PeerRole::Network => (&["proxy", "waf"], "proxy"),
    };
    if !allowed.contains(&event.source.as_str()) {
        let claimed = std::mem::take(&mut event.source);
        event.source = trusted.to_string();
        let note = format!("forged source \"{claimed}\" overridden by hub");
        event.detail = Some(match event.detail.take() {
            Some(d) => format!("{d}; {note}"),
            None => note,
        });
    }
}

/// Tell the children the run is ending: `shutdown(SHUT_WR)` on each hub
/// peer. The child's read side hits EOF and it begins its shutdown; its
/// final events still flow, because this process's read side of the
/// pair stays open until the reader saw the child's EOF. A full `close`
/// would instead EPIPE the child's last batch.
pub fn shutdown_peers() {
    for fd in PEER_RAW_FDS.lock().unwrap().drain(..) {
        unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    }
}

/// Split this process's upstream channel fd into its two halves, once,
/// on first use (inside a runtime):
///
/// * the **read** half is kept as a dup in [`CHANNEL_READER`], handed
///   out by [`channel_reader`] to the child's control loop — reading
///   the launcher's `upd` frames and, at EOF, seeing the run-end signal
///   (which subsumes the old channel-EOF watch);
/// * the **write** half is wrapped in an `Arc<Mutex<UnixStream>>`,
///   stored for [`reply_writer`] (control replies) and returned for the
///   audit [`channel_writer`] (event batches). The mutex serializes the
///   two writers so whole frames never interleave mid-line.
///
/// `None` when this process has no channel (it is not an audit child).
pub(crate) fn channel_streams() -> Option<Arc<tokio::sync::Mutex<UnixStream>>> {
    let fd = take_channel_fd()?;
    let stream = unsafe { StdUnixStream::from_raw_fd(fd.into_raw_fd()) };
    if let Err(e) = stream.set_nonblocking(true) {
        crate::sandbox::die(&format!("Can't set up the audit channel: {e}"));
    }
    // The read dup is created while the fd is still owned here; both
    // halves are non-blocking (O_NONBLOCK lives on the shared file
    // description).
    let read_dup = stream
        .try_clone()
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't set up the audit channel: {e}")));
    *CHANNEL_READER.lock().unwrap() = Some(read_dup);
    let stream = match UnixStream::from_std(stream) {
        Ok(stream) => stream,
        Err(e) => crate::sandbox::die(&format!("Can't set up the audit channel: {e}")),
    };
    let shared = Arc::new(tokio::sync::Mutex::new(stream));
    let _ = REPLY_WRITER.set(Arc::clone(&shared));
    Some(shared)
}

/// The child's channel read half (see [`channel_streams`]). Taken once
/// by the control child loop in FS/P; the tokio conversion must run
/// inside that child's runtime.
pub(crate) fn channel_reader() -> Option<UnixStream> {
    let std = CHANNEL_READER.lock().unwrap().take()?;
    match UnixStream::from_std(std) {
        Ok(stream) => Some(stream),
        Err(e) => crate::sandbox::die(&format!("Can't set up the control channel: {e}")),
    }
}

/// The child's mutex-guarded channel write half, shared by the audit
/// channel writer and the control replies (see [`channel_streams`]).
pub(crate) fn reply_writer() -> Option<Arc<tokio::sync::Mutex<UnixStream>>> {
    REPLY_WRITER.get().cloned()
}

/// Spawn the child's audit sink eagerly instead of on the first
/// `record`: FS/P call this right before registering their control loop,
/// so the channel halves exist by then (the read half for the control
/// loop, the write half for replies). Inert when this process has no
/// channel or already has a sink.
pub fn init_channel_sink() {
    let _ = super::SENDER.get_or_init(super::setup);
}

/// The channel sink's writer: the same batching loop as the file
/// writer ([`crate::audit::writer::writer`]), but each batch is
/// serialized and written into the upstream socketpair (the launcher's
/// hub reads it) instead of the log file. No `MAX_BYTES` chunking and
/// no rotation: there is no `O_APPEND` contract to honor and no file to
/// rotate. Writes take the shared mutex, so a control reply can never
/// split a batch frame.
///
/// On a write error (EPIPE: the launcher is gone) the error is surfaced
/// on stderr once and the remaining queue is discarded — a dead launcher
/// means the run is ending, and a dying child's exit must never be
/// suspended on a dead socket.
pub(crate) async fn channel_writer(
    stream: Arc<tokio::sync::Mutex<UnixStream>>,
    mut rx: tokio::sync::mpsc::Receiver<Event>,
) {
    let mut batch: Vec<Event> = Vec::new();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    batch.push(event);
                    if batch.len() >= super::MAX_EVENTS {
                        send_batch(&stream, &mut batch).await;
                    }
                }
                // All senders are gone: flush what is left and end —
                // which closes the stream, the child's EOF for the hub.
                None => {
                    send_batch(&stream, &mut batch).await;
                    return;
                }
            },
            // A quiet stream must still reach the launcher in bounded
            // time.
            _ = tokio::time::sleep(super::FLUSH_INTERVAL), if !batch.is_empty() => {
                send_batch(&stream, &mut batch).await;
            }
        }
    }
}

/// Serialize a batch as one JSON line per event and write it into the
/// channel. A failed write is reported once per process and the batch
/// dropped (see [`channel_writer`]).
async fn send_batch(stream: &Arc<tokio::sync::Mutex<UnixStream>>, batch: &mut Vec<Event>) {
    if batch.is_empty() {
        return;
    }
    let mut buf = String::new();
    for event in batch.drain(..) {
        buf.push_str(&event.to_line());
        buf.push('\n');
    }
    let mut stream = stream.lock().await;
    if let Err(e) = stream.write_all(buf.as_bytes()).await
        && !super::WRITE_ERROR_REPORTED.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "warning: can't send audit events to the launcher: {e} (further errors are silent)"
        );
    }
}
