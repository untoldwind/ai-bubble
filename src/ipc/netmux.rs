//! The net multiplexer: the transport layer that replaces the filesystem
//! Unix socket between the in-sandbox network process P (`proxy`/`waf`)
//! and the host-side connector (PLAN.md, Phase 1 — wiring is Phase 2).
//!
//! One pre-fork `socketpair` (`SOCK_STREAM|SOCK_CLOEXEC`, created by the
//! caller, exactly like the audit channel) carries every logical
//! connection between P and the connector as a numbered *stream*. There
//! is no filesystem name at all — nothing to bind-mount, nothing for the
//! sandboxed command to reach (this is what retires the AUDIT.md L6
//! caveat about a host `/tmp` bind mount exposing the old socket
//! directory).
//!
//! ## Wire format
//!
//! Every frame is a length-prefixed envelope
//! (`tokio_util::codec::length_delimited`, BE u32) carrying one tag byte,
//! one stream id and one flags byte:
//!
//! * `OPEN` / `ACK` / `ERR` — serde_json control payloads. The payload
//!   types are the [`NetSpec`] associated types, mode-specific and
//!   `deny_unknown_fields`-checked (SP-2 style): a proxy-mode client
//!   cannot even decode a waf-shaped request, and only waf's `Reply` can
//!   carry a private key. The confused-deputy containment the old
//!   one-socket-per-request design got from "which accept loop happens
//!   to answer" now lives in the type system.
//! * `DATA` — opaque bytes, the actual proxied/relayed traffic; the
//!   `FIN` flag is the half-close (the counterpart of `shutdown(Write)`).
//! * `CLOSE` — the sender is done with the stream entirely.
//!
//! Control messages are tiny and infrequent, so JSON costs nothing and
//! keeps frames readable in debug logs; the data plane is raw bytes
//! (HTTP bodies, TLS ciphertext) with no per-frame serde overhead. The
//! framing itself is *not* hand-rolled: the length prefix and its cap
//! come from `LengthDelimitedCodec`, the payload shapes from serde.
//!
//! ## Structure
//!
//! The core is deliberately mode-agnostic (it routes ids and bytes);
//! the mode-specific request/reply types enter through [`NetSpec`]:
//!
//! * connector side: [`serve_pair::<S>`] — decodes every `OPEN` into
//!   `S::Req` (foreign frames fail here and are answered with `ERR`),
//!   gates it on the stream cap, and hands the handler the data-plane
//!   [`MuxStream`]; the handler authorizes and sends its typed reply
//!   with [`MuxStream::ack`] — exactly the old flow (authorize, write
//!   the `OK` line, then relay) — an `Err` return becomes `ERR`;
//! * P side: [`client`] → [`MuxHandle::open`] — opens a stream, waits
//!   for the typed reply, returns the [`MuxStream`].
//!
//! A `DATA`/`CLOSE`-capable stream replaces the old "one fresh Unix
//! socket connection per request" model, so the connector-side
//! connection cap ([`crate::connlimit::ConnLimit`]) becomes a live
//! *stream* cap — one old connection ≙ one stream.
//!
//! ## Lifecycle and flow control
//!
//! The reader task dispatches frames by id into bounded per-stream
//! inboxes; a full inbox suspends the reader, which backpressures the
//! peer's writer end-to-end (the audit channel's suspend-on-full
//! semantics, one stream at a time — head-of-line blocking is accepted
//! at this concurrency). `FIN` propagates half-close, `CLOSE` tears the
//! stream down, and the pair's EOF fails every pending opener and EOFs
//! every stream (the [`drain`] at the end of [`read_loop`]).
//!
//! Streams that are merely dropped (without [`MuxStream::close`]) are
//! pruned from the routing table lazily: the next frame routed to the
//! dead inbox removes the entry. Ids come from a monotonic u32 counter
//! (reused only after 2³² streams); dropping without `close` never
//! leaks a live id, it just delays the table cleanup.
//!
//! ## Peer authentication
//!
//! The connector checks the peer's `SO_PEERCRED` credentials before
//! trusting any frame (see [`check_peer`]): the pair was created by the
//! connector pre-fork, and socketpair credentials are snapshotted at
//! creation time, so the peer must be the connector itself (its own
//! pid/uid/gid). Anything else means an end of the pair leaked to a
//! foreign process — the connection is cut and the attempt is
//! audit-recorded.

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, ready};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use crate::connlimit::ConnLimit;

/// The live-stream cap type. A stream corresponds 1:1 to an old
/// filesystem-socket connection, so the connection cap simply carries
/// over; the cap is enforced at `OPEN` time (the old accept loop's
/// `try_acquire` point) and released when the stream's handler task ends.
pub(crate) type StreamLimit = ConnLimit;

/// Payload cap for one frame: `DATA` writes are chunked to at most this,
/// and any envelope above [`FRAME_MAX`] kills the connection (a hard
/// `Err`, not a silent skip — the audit channel's discipline for
/// protocol violations).
pub(crate) const PAYLOAD_CAP: usize = 256 * 1024;
/// The envelope size cap enforced by the codec (payload cap + headers
/// + slack).
const FRAME_MAX: usize = PAYLOAD_CAP + 64;
/// Envelope header: tag byte + stream id + flags byte.
const HDR_LEN: usize = 6;
/// `OPEN`: the P side opens a stream, payload = serde_json `S::Req`.
const TAG_OPEN: u8 = 1;
/// `ACK`: the connector accepted the stream, payload = serde_json
/// `S::Reply` (sent by the handler, via [`MuxStream::ack`], *after*
/// authorizing — so a pipe kind's client can start relaying while the
/// handler keeps serving the stream).
const TAG_ACK: u8 = 2;
/// `ERR`: the connector refused the stream (undecodable request, cap
/// reached, handler error), payload = serde_json String.
const TAG_ERR: u8 = 3;
/// `DATA`: payload = raw bytes; `FLAG_FIN` = half-close.
const TAG_DATA: u8 = 4;
/// `CLOSE`: no payload.
const TAG_CLOSE: u8 = 5;
/// The `FIN` flag: this `DATA` frame ends the sender's direction.
const FLAG_FIN: u8 = 0x01;
/// Per-stream inbox capacity: the reader suspends (and so backpressures
/// the peer) when a stream's inbox is full.
const STREAM_BUF: usize = 64;

/// One message routed into a stream's inbox.
enum StreamMsg {
    /// Payload bytes of a `DATA` frame.
    Data(Bytes),
    /// `FIN`: the peer half-closed its write side — the read direction
    /// is over, writes stay usable.
    Fin,
    /// `CLOSE` (or pair EOF): the peer is done with the stream entirely
    /// — the read direction is over and further writes fail (the
    /// counterpart of a closed Unix socket).
    Closed,
}

/// What a pending [`MuxHandle::open`] waits for: the `ACK` payload (a
/// generic JSON value; the [`NetSpec`] layer types it) or an `ERR` reason.
type CtrlOutcome = Result<serde_json::Value, String>;

/// The mode-agnostic shared state of one multiplexed pair: the framed
/// write half, the per-stream routing table, the pending-open waiters
/// and the id counter.
struct MuxCore {
    writer: Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<StreamMsg>>>,
    waiters: Mutex<HashMap<u32, oneshot::Sender<CtrlOutcome>>>,
    next_id: AtomicU32,
}

impl MuxCore {
    /// Assemble one wire frame: length prefix + envelope.
    fn wire(tag: u8, id: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut env = Vec::with_capacity(HDR_LEN + payload.len());
        env.push(tag);
        env.extend_from_slice(&id.to_be_bytes());
        env.push(flags);
        env.extend_from_slice(payload);
        let mut wire = Vec::with_capacity(4 + env.len());
        wire.extend_from_slice(&(env.len() as u32).to_be_bytes());
        wire.extend_from_slice(&env);
        wire
    }

    /// Write one control frame (`OPEN`/`ACK`/`ERR`/`CLOSE`). Only ever
    /// called from async contexts, where the shared write half's lock is
    /// awaited (the `audit::ipc` `REPLY_WRITER` discipline: the mutex
    /// serializes writers so frames never tear).
    async fn write_frame(&self, tag: u8, id: u32, flags: u8, payload: &[u8]) -> io::Result<()> {
        let wire = Self::wire(tag, id, flags, payload);
        let mut w = self.writer.lock().await;
        w.write_all(&wire).await
    }
}

/// An `ERR` payload: a serde_json String.
fn err_payload(reason: &str) -> Vec<u8> {
    serde_json::to_vec(reason).expect("a string always serializes")
}

/// The `OPEN` sink the reader loop calls. Only the connector side
/// installs one ([`serve_pair`]'s [`ServeOpen`]); the erased form keeps
/// the reader loop mode-agnostic.
trait OpenSink: Send + Sync + 'static {
    fn on_open(&self, id: u32, payload: &[u8]);
}

/// Build the shared core for one pair end and spawn its reader loop.
fn mux_core(pair: UnixStream, on_open: Option<Arc<dyn OpenSink>>) -> Arc<MuxCore> {
    let (read, write) = pair.into_split();
    let core = core_from_write(write);
    tokio::spawn(read_loop(Arc::clone(&core), read, on_open));
    core
}

/// The core over an already-split write half (see [`mux_core`] and
/// [`serve_pair`], which needs the core before the reader starts).
fn core_from_write(write: OwnedWriteHalf) -> Arc<MuxCore> {
    Arc::new(MuxCore {
        writer: Arc::new(tokio::sync::Mutex::new(write)),
        streams: Mutex::new(HashMap::new()),
        waiters: Mutex::new(HashMap::new()),
        next_id: AtomicU32::new(0),
    })
}

/// A connected socketpair as two non-blocking tokio streams: what the
/// fork-based wiring (`crate::sandbox::netns`) creates pre-fork via
/// `socketpair(2)`, and what the tests use to exercise both ends in one
/// process.
#[cfg(test)]
pub(crate) fn pair() -> io::Result<(UnixStream, UnixStream)> {
    let (a, b) = std::os::unix::net::UnixStream::pair()?;
    a.set_nonblocking(true)?;
    b.set_nonblocking(true)?;
    Ok((UnixStream::from_std(a)?, UnixStream::from_std(b)?))
}

/// Wrap one raw (already `SOCK_CLOEXEC`) socketpair end — the fd a fork
/// child inherited — as a non-blocking tokio stream. Called inside that
/// child's runtime; registration failures are fatal (like the audit
/// channel's stream setup in the same position).
pub(crate) fn stream_from_raw_fd(fd: RawFd) -> UnixStream {
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    if let Err(e) = std_stream.set_nonblocking(true) {
        crate::sandbox::die(&format!("Can't set up the net mux channel: {e}"));
    }
    match UnixStream::from_std(std_stream) {
        Ok(stream) => stream,
        Err(e) => crate::sandbox::die(&format!("Can't register the net mux channel: {e}")),
    }
}

/// The reader loop: parse envelope after envelope off the pair and route
/// them by stream id. Ends — and [`drain`]s — at the pair's EOF or on
/// any protocol violation (over-cap frame, truncated header, unknown
/// tag, undecodable control payload): a bug in a trusted fork child, or
/// an attack by a compromised one, is cut off, not tolerated (the audit
/// hub's precedent).
async fn read_loop(core: Arc<MuxCore>, read: OwnedReadHalf, on_open: Option<Arc<dyn OpenSink>>) {
    let mut framed = FramedRead::new(
        read,
        LengthDelimitedCodec::builder()
            .max_frame_length(FRAME_MAX)
            .length_field_length(4)
            .new_codec(),
    );
    // Every warning below is followed by an immediate `break` — at most
    // one per connection, so no dedupe flag is needed.
    loop {
        let frame = match framed.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => {
                eprintln!(
                    "warning: netmux peer violated the frame protocol ({e}); closing the connection"
                );
                break;
            }
            None => break,
        };
        if frame.len() < HDR_LEN {
            eprintln!("warning: netmux peer sent a truncated frame; closing the connection");
            break;
        }
        let tag = frame[0];
        let id = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let flags = frame[5];
        let payload = &frame[HDR_LEN..];
        match tag {
            TAG_OPEN => match &on_open {
                Some(sink) => sink.on_open(id, payload),
                None => {
                    eprintln!(
                        "warning: netmux peer sent OPEN on a client end; closing the connection"
                    );
                    break;
                }
            },
            TAG_ACK => match serde_json::from_slice::<serde_json::Value>(payload) {
                Ok(value) => settle(&core, id, Ok(value)),
                Err(_) => {
                    eprintln!("warning: netmux peer sent a malformed ACK; closing the connection");
                    break;
                }
            },
            TAG_ERR => match serde_json::from_slice::<String>(payload) {
                Ok(reason) => settle(&core, id, Err(reason)),
                Err(_) => {
                    eprintln!("warning: netmux peer sent a malformed ERR; closing the connection");
                    break;
                }
            },
            TAG_DATA => {
                let fin = flags & FLAG_FIN != 0;
                if !payload.is_empty() {
                    route(&core, id, StreamMsg::Data(Bytes::copy_from_slice(payload))).await;
                }
                if fin {
                    route(&core, id, StreamMsg::Fin).await;
                }
            }
            TAG_CLOSE => {
                // Tell the stream's owner the peer is gone (EOF on reads,
                // writes fail), then drop the routing entry — late frames
                // for this id then prune cleanly. The handler task ends
                // by itself once its relay sees the EOF; dropping the
                // sender here (instead of waiting for it) is what keeps a
                // half-dead relay from holding its `StreamLimit` guard
                // forever.
                route(&core, id, StreamMsg::Closed).await;
                core.streams.lock().unwrap().remove(&id);
            }
            _ => {
                eprintln!(
                    "warning: netmux peer sent an unknown frame tag {tag}; closing the connection"
                );
                break;
            }
        }
    }
    drain(&core);
}

/// Hand an `ACK`/`ERR` outcome to the pending opener of stream `id`.
/// A missing waiter only means the opener gave up (or the pair died
/// before the reply arrived) — never an error worth tearing down.
fn settle(core: &MuxCore, id: u32, outcome: CtrlOutcome) {
    if let Some(tx) = core.waiters.lock().unwrap().remove(&id) {
        let _ = tx.send(outcome);
    }
}

/// Route one stream message into the stream's inbox. `await`ed here on
/// purpose: a full inbox backpressures the reader (and thereby the
/// peer's writer). A failed send means the stream is dropped locally —
/// prune the entry.
async fn route(core: &MuxCore, id: u32, msg: StreamMsg) {
    let sender = core.streams.lock().unwrap().get(&id).cloned();
    if let Some(sender) = sender
        && sender.send(msg).await.is_err()
    {
        core.streams.lock().unwrap().remove(&id);
    }
}

/// The pair is gone or a violation occurred: fail every pending opener
/// and EOF every stream. Dropping the inbox senders is the EOF; the
/// waiters get an explicit error so an `open` never hangs on a dead pair.
fn drain(core: &MuxCore) {
    core.streams.lock().unwrap().clear();
    for (_, tx) in core.waiters.lock().unwrap().drain() {
        let _ = tx.send(Err("connection closed".to_string()));
    }
}

/// The mode-agnostic framing contract: the connector serves one
/// request/reply vocabulary per mode, and the types do the mode
/// separation. `deny_unknown_fields` on the mode types makes a foreign
/// frame undecodable — the P side cannot smuggle a proxy request into
/// the waf server or vice versa (SP-2 shape-checking discipline).
pub(crate) trait NetSpec: Send + 'static {
    /// The mode's command set (e.g. `Proxy { target }` for proxy mode;
    /// `ResolveDns`/`Connect`/`TlsCert`/`TlsConnect` for waf mode).
    type Req: serde::Serialize + DeserializeOwned + Send + 'static;
    /// The mode's reply type (the `ACK` payload, sent by the connector's
    /// handler via [`MuxStream::ack`]).
    type Reply: serde::Serialize + DeserializeOwned + Send + 'static;
}

/// The P-side handle over one multiplexed pair: opens streams of mode
/// `S` and hands back the typed reply plus the data-plane stream. Cloning
/// hands out another handle onto the same pair (the P-side frontends
/// each get their own clone; they all share the one core/reader task).
pub(crate) struct MuxHandle<S: NetSpec> {
    core: Arc<MuxCore>,
    _spec: PhantomData<fn() -> S>,
}

impl<S: NetSpec> Clone for MuxHandle<S> {
    fn clone(&self) -> Self {
        MuxHandle {
            core: Arc::clone(&self.core),
            _spec: PhantomData,
        }
    }
}

impl<S: NetSpec> MuxHandle<S> {
    /// The client end of a pre-fork socketpair. Must run inside a
    /// runtime (spawns the reader task).
    pub(crate) fn client(pair: UnixStream) -> Self {
        MuxHandle {
            core: mux_core(pair, None),
            _spec: PhantomData,
        }
    }

    /// Open a stream: send `OPEN`, await the typed `ACK`/`ERR`. The
    /// returned [`MuxStream`] is the data plane; request/reply kinds
    /// simply drop it. A refused or undecodable request comes back as a
    /// plain I/O error carrying the connector's reason.
    pub(crate) async fn open(&self, req: &S::Req) -> io::Result<(S::Reply, MuxStream)> {
        let id = self.core.next_id.fetch_add(1, Ordering::Relaxed);
        let payload = serde_json::to_vec(req).map_err(|e| io::Error::other(e.to_string()))?;
        let (tx, rx) = mpsc::channel(STREAM_BUF);
        let (otx, orx) = oneshot::channel();
        self.core.streams.lock().unwrap().insert(id, tx);
        self.core.waiters.lock().unwrap().insert(id, otx);
        if let Err(e) = self.core.write_frame(TAG_OPEN, id, 0, &payload).await {
            self.core.streams.lock().unwrap().remove(&id);
            self.core.waiters.lock().unwrap().remove(&id);
            return Err(e);
        }
        match orx.await {
            Ok(Ok(value)) => {
                let reply: S::Reply = serde_json::from_value(value)
                    .map_err(|e| io::Error::other(format!("malformed ACK payload: {e}")))?;
                Ok((reply, MuxStream::new(Arc::clone(&self.core), id, rx)))
            }
            Ok(Err(reason)) => {
                self.core.streams.lock().unwrap().remove(&id);
                Err(io::Error::other(format!(
                    "connector refused the stream: {reason}"
                )))
            }
            Err(_) => {
                self.core.streams.lock().unwrap().remove(&id);
                Err(io::Error::other("netmux connection closed"))
            }
        }
    }
}

/// [`serve_pair`]'s `OPEN` sink: erases the mode-specific handler behind
/// [`OpenSink`] so the reader loop stays mode-agnostic.
struct ServeOpen<S: NetSpec, F> {
    core: Arc<MuxCore>,
    limit: Arc<StreamLimit>,
    handler: Arc<F>,
    _spec: PhantomData<fn() -> S>,
}

impl<S, F, Fut> OpenSink for ServeOpen<S, F>
where
    S: NetSpec,
    F: Fn(S::Req, MuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    fn on_open(&self, id: u32, payload: &[u8]) {
        let core = Arc::clone(&self.core);
        let handler = Arc::clone(&self.handler);
        match serde_json::from_slice::<S::Req>(payload) {
            Ok(req) => match self.limit.try_acquire() {
                // One old connection ≙ one stream: the guard is held for
                // the handler task's whole lifetime.
                Some(guard) => {
                    let (tx, rx) = mpsc::channel(STREAM_BUF);
                    // Safe to route to immediately: this callback runs
                    // inside the reader loop, so any frame for this id
                    // is processed only afterwards.
                    core.streams.lock().unwrap().insert(id, tx);
                    let stream = MuxStream::new(Arc::clone(&core), id, rx);
                    tokio::spawn(async move {
                        let _guard = guard;
                        // The handler authorizes and sends its typed
                        // `ACK` itself (`MuxStream::ack`), then serves or
                        // relays through the stream; only a failure —
                        // refused, or a relay error after the ack — comes
                        // back here and turns into `ERR`.
                        if let Err(e) = handler(req, stream).await {
                            let _ = core
                                .write_frame(TAG_ERR, id, 0, &err_payload(&e.to_string()))
                                .await;
                        }
                    });
                }
                None => {
                    tokio::spawn({
                        let core = Arc::clone(&core);
                        async move {
                            let _ = core
                                .write_frame(TAG_ERR, id, 0, &err_payload("too many concurrent streams"))
                                .await;
                        }
                    });
                }
            },
            Err(e) => {
                // A foreign or malformed request: refuse it, keep the
                // connection (the id space is per-stream, nothing is
                // corrupted) — the P side sees the refusal as an error.
                tokio::spawn({
                    let core = Arc::clone(&core);
                    async move {
                        let _ = core
                            .write_frame(
                                TAG_ERR,
                                id,
                                0,
                                &err_payload(&format!("malformed request: {e}")),
                            )
                            .await;
                    }
                });
            }
        }
    }
}

/// Verify the connector-side peer's credentials (`SO_PEERCRED`). The net
/// mux pair is created by the connector pre-fork, and `socketpair(2)`
/// snapshots the peer credentials at creation time — so whichever
/// process holds the other end, the credentials on this end name the
/// *creator*: this very process (the fork did not change its pid, and
/// the connector never changes its uid/gid before the forks). A
/// mismatch therefore proves an end of the pair was handed to — or
/// leaked into — a foreign process, and no frame from it may be
/// trusted. This runs before the first frame is read; the credentials
/// are immutable per socket, so one check pins the whole connection.
fn check_peer(pair: &UnixStream) -> io::Result<()> {
    let cred = peer_cred(pair.as_raw_fd())?;
    if peer_credentials_ok(&cred) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "peer is pid {}, uid {}, gid {} (expected pid {}, uid {}, gid {})",
            cred.pid,
            cred.uid,
            cred.gid,
            unsafe { libc::getpid() },
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )))
    }
}

/// Fetch a connected AF_UNIX socket's `SO_PEERCRED` credentials (Linux).
/// `ucred` is a plain POD struct, so a direct `getsockopt` keeps this
/// independent of the (still unstable) `UCred` std API.
fn peer_cred(fd: RawFd) -> io::Result<libc::ucred> {
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(cred)
    }
}

/// The credential comparison of [`check_peer`], split out for a direct
/// test: a mismatch on any of pid/uid/gid fails.
fn peer_credentials_ok(cred: &libc::ucred) -> bool {
    unsafe { cred.pid == libc::getpid() && cred.uid == libc::geteuid() && cred.gid == libc::getegid() }
}

/// The connector end of a pre-fork socketpair for mode `S`. Every `OPEN`
/// is decoded into `S::Req` (foreign frames fail here and are answered
/// with `ERR`), gated on the stream cap, and handed to `handler` with
/// the data-plane [`MuxStream`]. The handler authorizes and sends its
/// typed reply with [`MuxStream::ack`]; a returned error becomes `ERR`.
/// Must run inside a runtime (spawns tasks).
///
/// Before the first frame is read, the peer's `SO_PEERCRED` credentials
/// are verified (see [`check_peer`]); a mismatch cuts the connection and
/// audit-records the attempt, and this function parks forever instead of
/// returning — the serve loops' callers treat a serve end as a bug, and
/// the connector must stay alive to watch P's exit status.
///
/// The handler owns the stream for its whole lifetime: it relays through
/// it ([`copy_bidirectional`]) and should [`MuxStream::close`] it when
/// done — dropping without `close` releases the local routing entry only.
pub(crate) async fn serve_pair<S, F, Fut>(pair: UnixStream, limit: Arc<StreamLimit>, handler: F)
where
    S: NetSpec,
    F: Fn(S::Req, MuxStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    if let Err(e) = check_peer(&pair) {
        eprintln!("warning: netmux peer failed the credential check ({e}); closing the connection");
        crate::audit::record(
            "net",
            "mux-peer",
            None,
            Some("denied"),
            Some(format!("peer credential check failed: {e}")),
        )
        .await;
        // Close the pair (dropping both halves) and park: the caller's
        // select treats a serve end as a bug, and this process must stay
        // alive to reap P and finish the run.
        drop(pair);
        loop {
            std::future::pending::<()>().await;
        }
    }
    let (read, write) = pair.into_split();
    let core = core_from_write(write);
    let sink: Arc<dyn OpenSink> = Arc::new(ServeOpen::<S, F> {
        core: Arc::clone(&core),
        limit,
        handler: Arc::new(handler),
        _spec: PhantomData,
    });
    read_loop(core, read, Some(sink)).await;
}

/// One multiplexed stream: the P side's and the connector handler's
/// data-plane handle. Bidirectional raw bytes with half-close (`FIN` via
/// `shutdown`, see [`AsyncWrite::poll_shutdown`]) and full close
/// ([`MuxStream::close`]).
///
/// Implements [`AsyncRead`] + [`AsyncWrite`], so the tokio IO traits
/// (`read_to_end`, `write_all`, `flush`, `shutdown`,
/// [`copy_bidirectional`]) work on it directly. One departure from a
/// Unix socket's semantics: `poll_write` only buffers (bounded by
/// [`PAYLOAD_CAP`] per frame) — the `DATA` frame goes on the wire at
/// `poll_flush` (or `poll_shutdown`). The copy loops and hyper flush as
/// part of their write paths, so relays need no extra calls; a raw
/// `write_all` must be followed by a `flush` for the peer to see the
/// bytes (the mux's own tests do exactly that).
pub(crate) struct MuxStream {
    core: Arc<MuxCore>,
    id: u32,
    inbox: mpsc::Receiver<StreamMsg>,
    buf: BytesMut,
    wbuf: Vec<u8>,
    eof: bool,
    closed: bool,
    fin_sent: bool,
    /// The peer sent `CLOSE` (or the pair ended): reads EOF, writes fail.
    peer_closed: bool,
    /// The in-progress shared-writer acquisition for `poll_flush` /
    /// `poll_shutdown`: the write half's tokio Mutex has no poll-based
    /// API, so the `lock_owned()` future (and then the write future) is
    /// boxed into this slot and polled to completion there. Idle between
    /// frames. `flush` and `shutdown` never interleave (a caller flushes
    /// before it shuts down).
    out: OutState,
}

/// The flush/shutdown state machine (see [`MuxStream::out`]).
enum OutState {
    Idle,
    /// Acquiring the shared write half (`lock_owned`, an owned guard so
    /// the future stays `'static`).
    Locking(Pin<Box<dyn std::future::Future<Output = tokio::sync::OwnedMutexGuard<OwnedWriteHalf>> + Send>>),
    /// Writing the assembled frame through the acquired guard; the usize
    /// is the frame's payload length (the `wbuf` prefix to drop on
    /// success — `poll_write` may have appended more bytes meanwhile).
    Writing(Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>, usize),
}

impl OutState {
    fn reset(&mut self) {
        *self = OutState::Idle;
    }
}

impl MuxStream {
    fn new(core: Arc<MuxCore>, id: u32, inbox: mpsc::Receiver<StreamMsg>) -> Self {
        MuxStream {
            core,
            id,
            inbox,
            buf: BytesMut::new(),
            wbuf: Vec::new(),
            eof: false,
            closed: false,
            fin_sent: false,
            peer_closed: false,
            out: OutState::Idle,
        }
    }

    /// The stream's id (exposed for tests and audit trails).
    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    /// The connector handler's typed reply (`ACK`): sent *after*
    /// authorizing, before any relaying — the client's `open` returns as
    /// soon as it arrives. `&mut self` (not `&self`): the returned
    /// future must be `Send` for the spawned handler task, and
    /// `&MuxStream` would demand `Sync` from the boxed futures in
    /// [`MuxStream::out`], which `dyn Future + Send` does not provide.
    pub(crate) async fn ack<R: serde::Serialize>(&mut self, reply: &R) -> io::Result<()> {
        let payload = serde_json::to_vec(reply).map_err(|e| io::Error::other(e.to_string()))?;
        self.core.write_frame(TAG_ACK, self.id, 0, &payload).await
    }

    /// Full close: send `CLOSE` (best effort — the pair may already be
    /// gone) and release the local routing entry. Further writes fail.
    pub(crate) async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let r = self.core.write_frame(TAG_CLOSE, self.id, 0, &[]).await;
        self.core.streams.lock().unwrap().remove(&self.id);
        r
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        // Release the routing entry; late frames for this id then prune
        // via the failed route. Sending `CLOSE` would need an async
        // context, which `Drop` lacks — a handler that wants the peer to
        // see an orderly stream end must call [`MuxStream::close`].
        self.core.streams.lock().unwrap().remove(&self.id);
    }
}

/// The stream internals are not `Debug` (the boxed futures in `out`
/// aren't); expose the identity and lifecycle state only.
impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("id", &self.id)
            .field("eof", &self.eof)
            .field("closed", &self.closed)
            .field("fin_sent", &self.fin_sent)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.eof {
            return Poll::Ready(Ok(()));
        }
        if this.buf.is_empty() {
            match Pin::new(&mut this.inbox).poll_recv(cx) {
                Poll::Ready(Some(StreamMsg::Data(b))) => this.buf.extend_from_slice(&b),
                // `FIN`: half-close — reads end, writes stay usable.
                Poll::Ready(Some(StreamMsg::Fin)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                // `CLOSE` (peer gone) or the local routing entry dropped
                // (pair EOF / local `close`): reads end and, for a peer
                // `CLOSE`, writes fail too.
                Poll::Ready(Some(StreamMsg::Closed)) | Poll::Ready(None) => {
                    this.eof = true;
                    this.peer_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(this.buf.len());
        let chunk = this.buf.split_to(n);
        buf.put_slice(&chunk);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.peer_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        // Chunk to the payload cap: the caller keeps writing, `poll_flush`
        // emits exactly one bounded `DATA` frame per buffered chunk.
        let n = buf.len().min(PAYLOAD_CAP);
        this.wbuf.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed || this.peer_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }
        if this.wbuf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let wire = MuxCore::wire(TAG_DATA, this.id, 0, &this.wbuf);
        Self::poll_out(this, cx, wire)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Half-close: the copy loops call `shutdown` when one direction
        // is done — that is `FIN`, not `CLOSE` (the counterpart of
        // `shutdown(Write)`); the other direction stays usable. Any
        // buffered-but-unflushed `DATA` goes out first, so a caller that
        // forgets `flush` before `shutdown` still gets its bytes through.
        let this = self.get_mut();
        if this.fin_sent || this.closed || this.peer_closed {
            return Poll::Ready(Ok(()));
        }
        if !this.wbuf.is_empty() {
            let wire = MuxCore::wire(TAG_DATA, this.id, 0, &this.wbuf);
            match Self::poll_out(this, cx, wire) {
                Poll::Ready(Ok(())) => {
                    this.wbuf.clear();
                }
                other => return other,
            }
        }
        let wire = MuxCore::wire(TAG_DATA, this.id, FLAG_FIN, &[]);
        match Self::poll_out(this, cx, wire) {
            Poll::Ready(Ok(())) => {
                this.fin_sent = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl MuxStream {
    /// Drive one frame through the shared write half: acquire the tokio
    /// Mutex via `lock_owned` (an owned guard, so the future is
    /// `'static`), then `write_all` the frame — both boxed into
    /// [`MuxStream::out`] and polled with this stream's waker. The
    /// audit-style serialized-writer discipline: the mutex serializes
    /// all writers so frames never tear.
    fn poll_out(
        this: &mut MuxStream,
        cx: &mut std::task::Context<'_>,
        wire: Vec<u8>,
    ) -> Poll<io::Result<()>> {
        // The frame's payload is `wire` minus its length prefix and the
        // envelope header — exactly what `poll_write` buffered (plus the
        // zero-length FIN marker, whose prefix drop is harmless).
        let payload_len = wire.len() - 4 - HDR_LEN;
        loop {
            match &mut this.out {
                OutState::Idle => {
                    this.out = OutState::Locking(Box::pin(Arc::clone(&this.core.writer).lock_owned()));
                }
                OutState::Locking(fut) => {
                    let guard = ready!(fut.as_mut().poll(cx));
                    let wire = wire.clone();
                    this.out = OutState::Writing(
                        Box::pin(async move {
                            let mut guard = guard;
                            guard.write_all(&wire).await
                        }),
                        payload_len,
                    );
                }
                OutState::Writing(fut, n) => {
                    let r = ready!(fut.as_mut().poll(cx));
                    let n = *n;
                    this.out.reset();
                    if r.is_ok() {
                        // Drop exactly the bytes this frame carried;
                        // `poll_write` may have appended more meanwhile.
                        let _ = this.wbuf.drain(..n.min(this.wbuf.len()));
                    }
                    return Poll::Ready(r);
                }
            }
        }
    }
}

/// Bidirectional relay between a [`MuxStream`] and a real socket — the
/// framed replacement for `tokio::io::copy_bidirectional` in the
/// connector/P handlers. Half-closes propagate: the socket's read EOF
/// `shutdown`s the stream (`FIN`), the stream's `FIN` `shutdown`s the
/// socket's write side. The caller ends the stream with
/// [`MuxStream::close`] when the relay is fully done.
pub(crate) async fn copy_bidirectional<T>(
    stream: &mut MuxStream,
    sock: &mut T,
) -> io::Result<(u64, u64)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(stream, sock).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The test mode's vocabulary; `deny_unknown_fields` makes foreign
    /// frames undecodable (the cross-spec rejection test below).
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct EchoReq {
        msg: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct EchoReply {
        msg: String,
    }

    struct EchoSpec;

    impl NetSpec for EchoSpec {
        type Req = EchoReq;
        type Reply = EchoReply;
    }

    /// A second vocabulary with a disjoint field, for the cross-spec test.
    struct OtherSpec;

    impl NetSpec for OtherSpec {
        type Req = OtherReq;
        type Reply = EchoReply;
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OtherReq {
        n: u32,
    }

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        (
            UnixStream::from_std(a).unwrap(),
            UnixStream::from_std(b).unwrap(),
        )
    }

    /// Connector handler: echo the request into the reply, drop the
    /// stream (request/reply kind).
    async fn echo_handler(req: EchoReq, mut stream: MuxStream) -> io::Result<()> {
        stream.ack(&EchoReply { msg: req.msg }).await
    }

    #[tokio::test]
    async fn request_reply_roundtrip() {
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), echo_handler));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let (reply, stream) = handle
            .open(&EchoReq { msg: "hi".to_string() })
            .await
            .expect("open");
        assert_eq!(reply.msg, "hi");
        drop(stream);
    }

    #[tokio::test]
    async fn stream_limit_refuses_overflow() {
        let (a, b) = pair();
        // The handler acks immediately, then blocks on its stream until
        // the client half-closes — it holds its cap slot meanwhile.
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::with_max(1), |req, mut stream| async move {
            stream.ack(&EchoReply { msg: req.msg }).await?;
            let mut buf = [0u8; 8];
            let _ = stream.read(&mut buf).await;
            stream.close().await
        }));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let (r1, mut s1) = handle
            .open(&EchoReq { msg: "1".to_string() })
            .await
            .expect("first stream at the cap");
        assert_eq!(r1.msg, "1");
        let err = handle
            .open(&EchoReq { msg: "2".to_string() })
            .await
            .expect_err("second stream over the cap");
        assert!(err.to_string().contains("too many concurrent streams"));
        // Releasing the first stream frees the slot again.
        s1.shutdown().await.unwrap();
        let mut eof = Vec::new();
        s1.read_to_end(&mut eof).await.unwrap();
        let (_r3, s3) = handle
            .open(&EchoReq { msg: "3".to_string() })
            .await
            .expect("slot freed");
        drop(s3);
    }

    #[tokio::test]
    async fn data_plane_with_half_close() {
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), |_req, mut stream| async move {
            stream.ack(&EchoReply { msg: "ignored" .to_string()}).await?;
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await?;
            stream.write_all(b"pong").await?;
            stream.flush().await?;
            stream.close().await
        }));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let (reply, mut stream) = handle
            .open(&EchoReq { msg: "unused".to_string() })
            .await
            .expect("open");
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        // Half-close: the handler's read_to_end sees EOF, but the stream
        // stays readable for the handler's reply.
        stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong");
        assert_eq!(reply.msg, "ignored");
    }

    #[tokio::test]
    async fn concurrent_streams_are_independent() {
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), |_req, mut stream| async move {
            stream.ack(&EchoReply { msg: String::new() }).await?;
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await?;
            stream.write_all(&got).await?;
            stream.flush().await?;
            stream.close().await
        }));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let (_r1, mut s1) = handle
            .open(&EchoReq { msg: "one".to_string() })
            .await
            .expect("stream 1");
        let (_r2, mut s2) = handle
            .open(&EchoReq { msg: "two".to_string() })
            .await
            .expect("stream 2");
        assert_ne!(s1.id(), s2.id(), "ids must be unique");
        s1.write_all(b"A").await.unwrap();
        s2.write_all(b"BB").await.unwrap();
        let (mut g1, mut g2) = (Vec::new(), Vec::new());
        tokio::try_join!(
            async {
                s1.shutdown().await?;
                s1.read_to_end(&mut g1).await.map(|_| ())
            },
            async {
                s2.shutdown().await?;
                s2.read_to_end(&mut g2).await.map(|_| ())
            }
        )
        .unwrap();
        assert_eq!(g1.as_slice(), b"A");
        assert_eq!(g2.as_slice(), b"BB");
    }

    #[tokio::test]
    async fn handler_error_becomes_err() {
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), |_req, _stream| {
            std::future::ready(Err(io::Error::other("denied")))
        }));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let err = handle
            .open(&EchoReq { msg: "x".to_string() })
            .await
            .expect_err("handler refused");
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn cross_spec_request_is_refused() {
        // The connector speaks EchoSpec; the client sends an OtherSpec
        // request — undecodable, so refused with ERR, not answered.
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), echo_handler));
        let handle = MuxHandle::<OtherSpec>::client(a);
        let err = handle
            .open(&OtherReq { n: 5 })
            .await
            .expect_err("foreign frame");
        assert!(err.to_string().contains("malformed request"));
    }

    #[tokio::test]
    async fn oversized_frame_kills_connection() {
        // A raw std clone of the client end, so the junk frame can be
        // written asynchronously (the server reader drains on the same
        // runtime — a blocking std write here would deadlock the
        // current-thread test executor).
        let (sa, sb) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let raw_std = sa.try_clone().expect("clone");
        sa.set_nonblocking(true).unwrap();
        sb.set_nonblocking(true).unwrap();
        raw_std.set_nonblocking(true).unwrap();
        let a = UnixStream::from_std(sa).unwrap();
        let b = UnixStream::from_std(sb).unwrap();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), echo_handler));
        // Shove an over-cap frame into the raw client end: the connector
        // must cut the connection.
        let mut junk = Vec::new();
        junk.extend_from_slice(&((FRAME_MAX + 8) as u32).to_be_bytes());
        junk.extend(std::iter::repeat_n(0u8, FRAME_MAX + 8));
        // The connector may cut the connection mid-write (the junk is already
        // refused at the cap), which surfaces as BrokenPipe — either way
        // the connection is dead for subsequent opens.
        let mut raw = UnixStream::from_std(raw_std).unwrap();
        let _ = raw.write_all(&junk).await;
        let handle = MuxHandle::<EchoSpec>::client(a);
        let err = handle
            .open(&EchoReq { msg: "x".to_string() })
            .await
            .expect_err("connection must be cut");
        // Either the OPEN write hits the already-closed socket (EPIPE) or
        // the client's reader saw EOF and drained the waiter — both are
        // the "connection is cut" outcome.
        let msg = err.to_string();
        assert!(
            msg.contains("connection closed") || msg.contains("Broken pipe"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn close_then_reopen_gets_fresh_id() {
        let (a, b) = pair();
        tokio::spawn(serve_pair::<EchoSpec, _, _>(b, StreamLimit::new(), echo_handler));
        let handle = MuxHandle::<EchoSpec>::client(a);
        let (r1, mut s1) = handle
            .open(&EchoReq { msg: "first".to_string() })
            .await
            .expect("open 1");
        let id1 = s1.id();
        s1.close().await.unwrap();
        // Writes after close fail, reads EOF.
        assert!(s1.write_all(b"x").await.is_err());
        let (r2, s2) = handle
            .open(&EchoReq { msg: "second".to_string() })
            .await
            .expect("open 2 after close");
        assert_ne!(id1, s2.id());
        assert_eq!((r1.msg.as_str(), r2.msg.as_str()), ("first", "second"));
    }

    /// The peer-credential check: a genuine pre-fork socketpair (creds
    /// snapshotted by this process at creation) passes; fabricated
    /// foreign credentials — the signature of a leaked pair end — fail
    /// on every field.
    #[tokio::test]
    async fn peer_credential_check() {
        let (a, _b) = pair();
        check_peer(&a).expect("the creator's own end passes");

        unsafe {
            let foreign = libc::ucred {
                pid: libc::getpid() + 1,
                uid: libc::geteuid(),
                gid: libc::getegid(),
            };
            assert!(!peer_credentials_ok(&foreign), "foreign pid must fail");

            let uid_foreign = libc::ucred {
                pid: libc::getpid(),
                uid: libc::geteuid() + 1,
                gid: libc::getegid(),
            };
            assert!(!peer_credentials_ok(&uid_foreign), "foreign uid must fail");

            let gid_foreign = libc::ucred {
                pid: libc::getpid(),
                uid: libc::geteuid(),
                gid: libc::getegid() + 1,
            };
            assert!(!peer_credentials_ok(&gid_foreign), "foreign gid must fail");
        }
    }
}