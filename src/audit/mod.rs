//! The audit subsystem.
//!
//! Every security-relevant event — filesystem access through the hostfs
//! mirror, waf allow/deny decisions, proxy CONNECT attempts — is turned
//! into an audit event and sent over a bounded in-memory channel to a
//! dedicated writer. The writer collects events in batches and appends
//! them as JSON lines to the audit log file configured in the spec's
//! `audit` section.
//!
//! Design notes:
//!
//! * The channel is a tokio mpsc, bounded but generous (65536 events): a
//!   burst of audit events is absorbed in memory. When the buffer is
//!   full the producing task is *suspended* at `record().await` until
//!   the writer catches up — audit events are never dropped, and a
//!   temporary stall is acceptable. Because the producer suspends
//!   instead of blocking, the runtime keeps serving other tasks
//!   meanwhile (important on the current-thread runtimes of the FUSE
//!   server and the network frontends).
//! * The writer runs as a tokio task on the same (per-process) runtime,
//!   batching events and writing each batch through tokio's blocking
//!   pool, so a slow disk never stalls the runtime either.
//! * Single writer per run: the launcher (process A) is the only process
//!   that touches the log file. The FUSE server (FS) and the in-sandbox
//!   network frontends (P) send their events upstream over pre-fork Unix
//!   socketpairs ([`ipc::set_channel`]/[`ipc::add_peer`]): each child
//!   runs an [`ipc::channel_writer`] task serializing its events into
//!   the socket, and the launcher runs one hub reader per channel
//!   ([`ipc::spawn_hub`]) forwarding the frames into its own queue —
//!   the same bounded queue the file writer consumes. Backpressure is
//!   end-to-end and symmetric (full queue → reader suspends → socket
//!   fills → child's writer suspends → `record` suspends), so the
//!   never-drop, suspend-on-full semantics hold across the process
//!   boundary. On the non-isolated path the launcher has no runtime yet,
//!   so the FUSE server there keeps its own file writer (as do the
//!   launcher itself and the tests).
//! * `Event::ts`/`pid` are stamped by the emitting process at `record`
//!   time — not when the line is written. A relay (the launcher's hub)
//!   forwards them verbatim, so a quiet-then-burst stream keeps
//!   truthful timestamps.
//! * Without an audit log configured the whole subsystem is inert:
//!   `record` returns immediately and no writer task is ever spawned.
//! * The log path is constrained at startup (see
//!   [`writer::configure`]): it must live inside the spec directory, or
//!   point at a file that already exists. Otherwise the writer — running
//!   with the operator's uid — would let sandbox-influenced event
//!   content create and append to an arbitrary host file (e.g. the
//!   operator's shell rc). The log is also size-capped: once it
//!   outgrows `MAX_LOG_BYTES` it is rotated to `<name>.1` (one
//!   previous generation kept) before the next batch is written, so a
//!   sandbox spraying events cannot fill the host disk. Write errors
//!   are surfaced on stderr (once per process) instead of being
//!   discarded silently — losing audit events is worth knowing about
//!   even when the run cannot be stopped for it.
//! * The file is opened **eagerly, in [`writer::configure`]** — before
//!   the sandbox and any untrusted command exist — with `O_NOFOLLOW` and
//!   a regular-file check (AUDIT.md finding H4). The opened descriptor
//!   is retained for the process lifetime; the writer never opens the
//!   path again. A sandboxed command can therefore not swap the path
//!   for a symlink (its appends would land in an operator-chosen
//!   target) or a FIFO (the writer would hang and, through the bounded
//!   channel, deadlock every suspending producer) — the descriptor
//!   already points at the validated regular file, and `O_NOFOLLOW`
//!   keeps every later (rotation) open from following a swapped-in
//!   symlink.
//! * Residual, by design: if the audit log lives inside a *sandbox-
//!   writable* mapped directory, the command can open the same file
//!   through the mirror and append, truncate, or fill it with its own
//!   content (the eager open protects the writer's descriptor, not the
//!   file's integrity). Keep the audit log inside the spec directory,
//!   which the sandbox never sees.
//!
//! Module layout:
//!
//! * [`writer`] — the audit log *file*: startup configuration and path
//!   validation, the safe open, the batching file writer and its
//!   rotation.
//! * [`ipc`] — the *inter-process channels*: the pre-fork socketpairs,
//!   the children's channel writer, the launcher's hub readers and the
//!   shutdown choreography.
//! * this module — the shared event type, the per-process queue, and
//!   the dispatch between the two sinks (`record`/`setup`/`drain`).

mod ipc;
pub(crate) mod writer;

use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Sender};

// The public API, unchanged for every caller outside this directory:
// `crate::audit::<name>` keeps working exactly as before.
pub(crate) use ipc::{FRAME_CAP, UpdReply, channel_reader, reply_writer};
pub use ipc::{
    PeerRole, add_peer, init_channel_sink, ipc_channel_wanted, peer_writer, set_channel,
    set_ipc_enabled, shutdown_peers, spawn_hub,
};
pub(crate) use ipc::{close_inherited, drop_log_fd};
pub use writer::configure;
pub(crate) use writer::safe_open;

/// The channel capacity: how many events may pile up in memory before a
/// producer is suspended. Generous on purpose — spikes (e.g. a build
/// touching thousands of files) must be absorbed, not dropped.
const CAPACITY: usize = 65536;

/// Flush at least this often, so a quiet stream still reaches the sink
/// in bounded time.
pub(crate) const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// Never batch more than this many events before flushing.
pub(crate) const MAX_EVENTS: usize = 4096;

/// The marker appended to a `detail` truncated to fit
/// [`ipc::FRAME_CAP`].
const TRUNCATED: &str = "…[truncated]";

/// Set on the first failed write in this process, so the error is
/// surfaced on stderr once instead of spamming or being discarded.
pub(crate) static WRITE_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);

/// The per-process channel to the writer. `None` when auditing is
/// disabled (no `audit.log` in the spec) — `record` then does nothing.
/// The writer task is spawned lazily, on the first `record` (which runs
/// inside a runtime); the static is filled then.
///
/// The sender is held behind a `Mutex<Option<_>>` so [`drain`] can take
/// (and drop) it: the writer ends — after a final flush — when all
/// senders are gone, which is exactly what drain awaits.
static SENDER: OnceLock<Option<SenderCell>> = OnceLock::new();

struct SenderCell {
    tx: std::sync::Mutex<Option<Sender<Event>>>,
    writer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Record one audit event. When the buffer is full, the producing task
/// is suspended until the writer catches up: audit events are never
/// dropped. Inert without a configured log path.
pub async fn record(
    source: &str,
    op: &str,
    path: Option<&str>,
    result: Option<&str>,
    detail: Option<String>,
) {
    let Some(sender) = queue_sender() else {
        return;
    };
    // A closed channel can only mean the writer task is gone (it dies
    // with the process anyway); there is nothing to audit to then.
    let _ = sender
        .send(Event {
            // Stamped here, by the emitting process: a relay (the
            // launcher's hub) forwards the frame verbatim.
            ts: now_micros(),
            pid: std::process::id(),
            source: fit_field(source),
            op: fit_field(op),
            path: path.map(fit_field),
            result: result.map(fit_field),
            detail: detail.map(fit_detail),
        })
        .await;
}

/// Microseconds since the Unix epoch (0 if the clock is before it).
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Truncate a `detail` string so the serialized event frame fits
/// [`ipc::FRAME_CAP`]. Oversized details cannot occur today (far above
/// any current event's size), but a frame that exceeds the hub readers'
/// line cap would be treated as malformed and end the channel — so
/// `record` guarantees the fit instead. Escaping can expand characters
/// (control bytes become `\u00XX`, up to sixfold), so the raw-byte
/// budget is a sixth of the cap: the serialized frame then fits no
/// matter what the detail contains.
fn fit_detail(mut detail: String) -> String {
    let event = |d: &str| {
        serde_json::json!({
            "ts": 0u64,
            "pid": 0u32,
            "source": "",
            "op": "",
            "path": Option::<&str>::None,
            "result": Option::<&str>::None,
            "detail": d,
        })
        .to_string()
        .len()
    };
    // The rest of the frame (fields, JSON syntax) adds at most a few
    // dozen bytes over the detail's serialized length. Escaping can
    // expand a raw byte up to sixfold (`\u00XX` for a control byte), so
    // budget the raw bytes at a sixth of the cap: the serialized frame
    // then fits no matter what the detail contains.
    let budget = ipc::FRAME_CAP.saturating_sub(event("") + TRUNCATED.len() + 8) / 6;
    if detail.len() <= budget {
        return detail;
    }
    while detail.len() > budget {
        // Cut at a UTF-8 character boundary.
        let mut cut = detail.len() * 3 / 4;
        while !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
    }
    detail.push_str(TRUNCATED);
    detail
}

/// The per-field cap for `source`/`op`/`path`/`result` (SP-9): like
/// `detail`, these arrive from code paths that could in principle carry
/// very long strings (a path with thousands of components), and an
/// over-cap frame would be treated as malformed by the hub readers and
/// kill that child's whole audit channel. Capped with the same
/// truncation discipline as `detail`.
const MAX_FIELD: usize = 4096;

/// Truncate a `source`/`op`/`path`/`result` field to [`MAX_FIELD`] bytes
/// at a UTF-8 character boundary.
fn fit_field(s: &str) -> String {
    if s.len() <= MAX_FIELD {
        return s.to_string();
    }
    let mut cut = MAX_FIELD;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = s[..cut].to_string();
    out.push_str(TRUNCATED);
    out
}

/// A sender into this process's event queue, spawning the queue (and
/// its writer task) lazily on first use. Must run inside a tokio
/// runtime (it is only ever called from `record`/`spawn_hub`, which
/// are async or spawn tasks); `None` when this process has no audit
/// sink.
fn queue_sender() -> Option<Sender<Event>> {
    SENDER
        .get_or_init(setup)
        .as_ref()
        .and_then(|cell| cell.tx.lock().unwrap().clone())
}

/// Create the channel and spawn the writer task. Must run inside a
/// tokio runtime (it is only ever called from `record`, which is
/// async); `None` when this process has no audit sink.
///
/// The sink choice, in order:
///
/// * a registered upstream channel ([`ipc::take_channel_fd`], set in
///   FS/P right after the fork): events are serialized into the
///   socketpair for the launcher's hub — this process holds no log fd.
///   The channel fd is split here (see [`ipc::channel_streams`]): the
///   read half is parked for the child's control loop, the write half
///   is shared (mutex-guarded) by the audit batches and the control
///   replies;
/// * the configured log file (the launcher itself, tests, and the
///   non-isolated FUSE server without runtime control): a fresh
///   descriptor per process (`try_clone` dups the fd — forked
///   processes must not share the mutex guarding the file), never the
///   path;
/// * neither: inert.
fn setup() -> Option<SenderCell> {
    let (tx, rx) = mpsc::channel(CAPACITY);
    // Child with an upstream channel: ownership of the write half moves
    // to the channel writer task, which closes it (its `UnixStream`
    // drops) when it ends after a final flush — that close is the
    // child's "queue flushed" EOF for the launcher's reader.
    if let Some(write) = ipc::channel_streams() {
        let writer = tokio::spawn(ipc::channel_writer(write, rx));
        return Some(SenderCell {
            tx: std::sync::Mutex::new(Some(tx)),
            writer: std::sync::Mutex::new(Some(writer)),
        });
    }
    let log = writer::LOG.get()?.as_ref()?;
    // A fresh descriptor per process (`try_clone` dups the fd): forked
    // processes must not share the mutex guarding the file. The log fd
    // may have been dropped (an audit child that never got a channel —
    // not a state that occurs); without a descriptor there is nothing
    // to write to.
    let guard = log.file.lock().unwrap();
    let file = guard.as_ref()?;
    let file = file.try_clone().unwrap_or_else(|e| {
        crate::sandbox::die(&format!("Can't open the audit log for writing: {e}"))
    });
    drop(guard);
    let writer_task = tokio::spawn(writer::writer(log.path.clone(), file, rx));
    Some(SenderCell {
        tx: std::sync::Mutex::new(Some(tx)),
        writer: std::sync::Mutex::new(Some(writer_task)),
    })
}

/// Wait for this process's writer to catch up. Call on any clean
/// process exit path, inside the process's runtime: the sender is
/// dropped so the writer's `rx.recv()` returns `None` (it then flushes
/// its final batch and ends), and the writer task is awaited — no fixed
/// sleeps, no guessing about backlogs (AUDIT.md L7): every event
/// recorded before `drain` is delivered when it returns. Inert when
/// this process has no writer (and never spawns one on its own).
///
/// The semantics differ by sink:
///
/// * *child* (channel sink): the final batch is flushed into the
///   socketpair, whose read end in the launcher stays open; when the
///   writer task ends it closes the stream, which the launcher's hub
///   reader sees as EOF ("my queue is flushed"). The caller does not
///   need to close anything.
/// * *launcher* (file sink): this is the final file flush; the caller
///   must first await the hub readers' EOF so every child's events are
///   in the queue.
pub async fn drain() {
    // Only act when this process already has a writer: if auditing is
    // disabled (or nothing was ever recorded) there is nothing to wait
    // for — and drain must not spawn one on its own.
    let Some(cell) = SENDER.get().and_then(|s| s.as_ref()) else {
        return;
    };
    // Drop this process's sender: the writer ends when all senders are
    // gone. (Other senders may still exist from concurrent `record`
    // callers; `await` below waits until *they* are done too — the
    // writer only returns after a final flush.)
    let handle = {
        cell.tx.lock().unwrap().take();
        cell.writer.lock().unwrap().take()
    };
    if let Some(handle) = handle {
        let _ = handle.await;
    }
}

/// One audit event, as it flows through the channel — and, serialized,
/// as one JSON line in the log and as one frame on the inter-process
/// audit channels (the frame *is* the line: the launcher's hub
/// deserializes and re-serializes it, so there is one code path and no
/// format drift). `ts`/`pid` are stamped by the emitting process at
/// `record` time and forwarded verbatim by relays. `source` is
/// cross-checked by the launcher's hub against the channel's peer role
/// (SP-2): a child cannot claim another component's source (e.g. a
/// compromised FS emitting `source: "control"` with the launcher's pid).
#[derive(Serialize, Deserialize)]
// Unknown fields are rejected so a frame that is an event *plus* a
// control-reply key (`"ack"`) cannot be diverted to the reply channel by
// the hub's demultiplexer — an audit-suppression primitive for a
// compromised child (SP-2). With this, such a frame fails the event
// parse; the reply parse (which now refuses frames carrying event
// fields) fails too, so the reader treats it as malformed and closes the
// offending channel — fail-closed.
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    ts: u64,
    pid: u32,
    source: String,
    op: String,
    path: Option<String>,
    result: Option<String>,
    detail: Option<String>,
}

impl Event {
    /// The event as one JSON line — purely mechanical, no stamping.
    pub(crate) fn to_line(&self) -> String {
        serde_json::json!({
            "ts": self.ts,
            "pid": self.pid,
            "source": self.source,
            "op": self.op,
            "path": self.path,
            "result": self.result,
            "detail": self.detail,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;
    use std::sync::Arc;

    use ipc::FRAME_CAP;
    use writer::{rotate, validate_path};

    /// Without a configured log path the whole subsystem is inert.
    #[tokio::test]
    async fn inert_without_config() {
        record("test", "op", None, None, None).await;
        assert!(SENDER.get_or_init(|| None).is_none());
    }

    /// The audit log path must live inside the spec directory or point
    /// at an already existing file: the writer appends with the
    /// operator's uid, so an arbitrary creatable path would be an
    /// arbitrary file create/append primitive (finding M8).
    #[test]
    fn audit_log_must_live_in_the_spec_dir_or_pre_exist() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let spec_dir = dir.join("spec");
        std::fs::create_dir_all(&spec_dir).unwrap();

        // Inside the spec directory: allowed even though the file does
        // not exist yet (the writer creates it there).
        assert!(validate_path(&spec_dir.join("audit.jsonl"), &spec_dir).is_ok());

        // Outside, but pre-existing: allowed (append-only, nothing new
        // is created).
        let outside = dir.join("existing.jsonl");
        std::fs::write(&outside, b"").unwrap();
        assert!(validate_path(&outside, &spec_dir).is_ok());

        // Outside and missing: refused.
        assert!(validate_path(&dir.join("missing.jsonl"), &spec_dir).is_err());

        // A `..` inside the path that would escape the spec directory:
        // the parent is canonicalized, so this is judged as
        // `<dir>/escape.jsonl` — outside, missing, refused.
        assert!(validate_path(&spec_dir.join("../escape.jsonl"), &spec_dir).is_err());

        // AUDIT.md L7: the spec's policy and secret files must not be log
        // targets — an audit append on `spec.json` or the env file would
        // corrupt the security policy event by event.
        assert!(validate_path(&spec_dir.join("spec.json"), &spec_dir).is_err());
        assert!(validate_path(&spec_dir.join(".env"), &spec_dir).is_err());
        // The spec directory itself is not a file, reject it up front.
        assert!(validate_path(&spec_dir, &spec_dir).is_err());
        // Other names inside the spec directory are still fine.
        assert!(validate_path(&spec_dir.join("audit.jsonl"), &spec_dir).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `safe_open` creates new files with mode `0600` (AUDIT.md L7): the
    /// audit log records security-relevant events and must not be
    /// world-readable on a shared host (the umask would give `0644`).
    #[test]
    fn safe_open_creates_files_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");

        let f = safe_open(&log, "audit log").unwrap();
        drop(f);
        let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `drain` drops the sender and awaits the writer (AUDIT.md L7): every
    /// event recorded before it is in the file when it returns, without
    /// fixed sleeps.
    #[tokio::test]
    async fn drain_awaits_the_writer() {
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-audit-drain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");

        let (tx, rx) = mpsc::channel::<Event>(CAPACITY);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        let writer = tokio::spawn(writer::writer(log.clone(), file, rx));

        tx.send(Event {
            ts: 1,
            pid: 2,
            source: "test".into(),
            op: "op".into(),
            path: None,
            result: None,
            detail: None,
        })
        .await
        .unwrap();
        // Drop the sender exactly like `drain` does, then await the
        // writer; the event must already be flushed when the await ends.
        drop(tx);
        writer.await.unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotating an oversized log moves the old file to `<name>.1` and
    /// points the writer at a fresh log.
    #[test]
    fn rotate_moves_the_log_to_a_backup() {
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-audit-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let backup = dir.join("audit.jsonl.1");

        std::fs::write(&log, b"first\n").unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();

        rotate(&log, &mut file);
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "first\n");

        // The writer now appends to a fresh log at the original path.
        file.write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "second\n");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "first\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Events end up as JSON lines in the file, in order.
    #[tokio::test]
    async fn writes_json_lines() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");

        // A writer on a channel of our own (no fork involved).
        let (tx, rx) = mpsc::channel::<Event>(CAPACITY);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        let path = log.clone();
        let handle = tokio::spawn(writer::writer(path, file, rx));

        for i in 0..3 {
            tx.send(Event {
                ts: 1,
                pid: 2,
                source: "test".into(),
                op: format!("op{i}"),
                path: Some("/x".into()),
                result: Some("ok".into()),
                detail: None,
            })
            .await
            .unwrap();
        }
        // Dropping the sender ends the writer after a final flush.
        drop(tx);
        handle.await.unwrap();

        let mut text = String::new();
        std::fs::File::open(&log)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(event["source"], "test");
            assert_eq!(event["op"], format!("op{i}"));
            assert_eq!(event["path"], "/x");
            assert_eq!(event["result"], "ok");
            assert!(event["detail"].is_null());
            assert!(event["ts"].is_u64());
            assert!(event["pid"].is_u64());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `safe_open` refuses anything that is not a regular file (AUDIT.md
    /// finding H4): a FIFO renamed over the audit path must not be opened
    /// (the writer would hang on it and, through the bounded channel,
    /// deadlock every suspending producer).
    #[test]
    fn safe_open_refuses_a_fifo() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("audit.jsonl");
        nix_fifo(&fifo);

        assert!(safe_open(&fifo, "audit log").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `safe_open` must not follow a symlink (AUDIT.md finding H4): a
    /// symlink swapped in over the audit path must be refused, not
    /// followed to its (operator-chosen) target.
    #[test]
    fn safe_open_refuses_a_symlink() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.jsonl");
        std::fs::write(&target, b"").unwrap();
        let link = dir.join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(safe_open(&link, "audit log").is_err());
        // The target must not have been written (append-only guarantee
        // applies to the validated file, not to whatever the path points
        // at when the swap happened).
        assert_eq!(std::fs::read(&target).unwrap(), b"");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotating must never open the attacker-influenceable path blindly
    /// (AUDIT.md finding H4): with the path swapped for a FIFO and the
    /// rename blocked, both fresh opens fail and the writer keeps
    /// appending to the descriptor it already holds.
    #[test]
    fn rotation_does_not_follow_a_swapped_in_fifo() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");
        let backup = dir.join("audit.jsonl.1");

        std::fs::write(&log, b"first\n").unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();

        // A non-empty directory at the backup path makes the rename fail
        // (oldpath is not a directory, newpath is): the rotation cannot
        // get the FIFO at `log` out of the way.
        std::fs::create_dir(&backup).unwrap();
        std::fs::write(backup.join("blocker"), b"").unwrap();
        // Simulate the sandbox's swap: the path is now a FIFO.
        std::fs::remove_file(&log).unwrap();
        nix_fifo(&log);

        rotate(&log, &mut file);
        // Writing through the retained descriptor must still work: the
        // writer never re-opened the (FIFO) path, and it did not hang on
        // it either (it is O_NONBLOCK + refused before any I/O anyway).
        file.write_all(b"second\n").unwrap();

        // Nothing followed or opened the FIFO: the path still is the
        // FIFO the sandbox swapped in, and the rename (blocked by the
        // non-empty backup directory) did not happen.
        assert!(std::fs::metadata(&log).unwrap().file_type().is_fifo());
        assert!(backup.join("blocker").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An `Event` round-trips through its serialized line — the same
    /// seven-field JSON shape as before the single-writer refactor (the
    /// frame *is* the line, so the launcher's hub re-serialization keeps
    /// the log format identical).
    #[test]
    fn event_round_trip_and_line_shape() {
        let event = Event {
            ts: 1728000000123456,
            pid: 1234,
            source: "hostfs".into(),
            op: "write".into(),
            path: Some("/work/x.rs".into()),
            result: Some("ok".into()),
            detail: None,
        };
        let line = event.to_line();
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back.ts, event.ts);
        assert_eq!(back.pid, event.pid);
        assert_eq!(back.source, event.source);
        assert_eq!(back.op, event.op);
        assert_eq!(back.path, event.path);
        assert_eq!(back.result, event.result);
        assert_eq!(back.detail, event.detail);
        // Re-serializing the round-tripped event gives the same line.
        assert_eq!(back.to_line(), line);

        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["ts"], 1728000000123456u64);
        assert_eq!(v["pid"], 1234u64);
        assert_eq!(v["source"], "hostfs");
        assert_eq!(v["op"], "write");
        assert_eq!(v["path"], "/work/x.rs");
        assert_eq!(v["result"], "ok");
        assert!(v["detail"].is_null());
    }

    /// `fit_detail` truncates an oversized `detail` so the serialized frame
    /// fits the hub readers' line cap, with a truncation marker.
    #[test]
    fn fit_detail_truncates_an_oversized_detail() {
        let huge: String = "x".repeat(4 * FRAME_CAP);
        let fitted = fit_detail(huge.clone());
        assert!(fitted.ends_with(TRUNCATED));
        assert!(fitted.len() < huge.len());
        // The whole event frame must fit (worst-case escaping accounted).
        let event = Event {
            ts: 0,
            pid: 0,
            source: "hostfs".into(),
            op: "write".into(),
            path: Some("/x".into()),
            result: Some("ok".into()),
            detail: Some(fitted.clone()),
        };
        assert!(event.to_line().len() < FRAME_CAP);

        // Worst case for escaping: control bytes expand to `\u00XX`.
        let hostile: String = "\u{1}".repeat(4 * FRAME_CAP);
        let event = Event {
            ts: 0,
            pid: 0,
            source: "hostfs".into(),
            op: "write".into(),
            path: None,
            result: None,
            detail: Some(fit_detail(hostile)),
        };
        assert!(event.to_line().len() < FRAME_CAP);
        // Small details pass through untouched.
        assert_eq!(fit_detail("small".into()), "small");
    }

    /// The full isolated-path pipeline, in one process: a channel sink
    /// (child side) → the socketpair → a hub reader (launcher side) → the
    /// file writer. Every event arrives as one intact JSON line with its
    /// original `ts`/`pid` — including events sent *after* the launcher
    /// half-closed its end (the drain choreography's load-bearing
    /// half-close).
    #[tokio::test]
    async fn channel_sink_through_hub_to_file() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-ipc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("audit.jsonl");

        let (child_std, hub_std) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = child_std.set_nonblocking(false);

        // Child side: channel_writer serializes events into the socket.
        let (tx, rx) = mpsc::channel::<Event>(CAPACITY);
        let _ = child_std.set_nonblocking(true);
        let child = tokio::spawn(ipc::channel_writer(
            Arc::new(tokio::sync::Mutex::new(
                tokio::net::UnixStream::from_std(child_std).unwrap(),
            )),
            rx,
        ));

        // Launcher side: the hub reader forwards into the file writer's
        // queue (spawned first so the child can be flushed into it).
        let (file_tx, file_rx) = mpsc::channel::<Event>(CAPACITY);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        let file_writer = tokio::spawn(writer::writer(log.clone(), file, file_rx));

        let hub_raw = hub_std.into_raw_fd();
        let hub_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(hub_raw) };
        let _ = hub_stream.set_nonblocking(true);
        // No control plane in this test: the reply receiver is dropped,
        // which the reader tolerates (it keeps forwarding events).
        let (reply_tx, _reply_rx) = tokio::sync::mpsc::channel::<UpdReply>(8);
        let hub = tokio::spawn(ipc::hub_reader(
            tokio::net::UnixStream::from_std(hub_stream).unwrap(),
            ipc::PeerRole::HostFs,
            Some(file_tx.clone()),
            reply_tx,
        ));
        // The hub holds the only remaining sender: when it ends (child
        // EOF), the file writer flushes and finishes.
        drop(file_tx);

        let event = |i: usize| Event {
            ts: 1000 + i as u64,
            pid: 42,
            source: "hostfs".into(),
            op: format!("op{i}"),
            path: Some("/x".into()),
            result: Some("ok".into()),
            detail: None,
        };
        for i in 0..3 {
            tx.send(event(i)).await.unwrap();
        }
        // The launcher says "the run is ending": half-close its end. The
        // child's writer must still be able to flush afterwards.
        unsafe { libc::shutdown(hub_raw, libc::SHUT_WR) };
        for i in 3..6 {
            tx.send(event(i)).await.unwrap();
        }
        // Child done: drop the sender — the writer flushes its final batch
        // and closes the stream, which ends the hub reader.
        drop(tx);
        child.await.unwrap();
        hub.await.unwrap();
        // Launcher: the hub dropped the queue's sender when it ended; the
        // file writer flushes and finishes.
        file_writer.await.unwrap();

        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6);
        for (i, line) in lines.iter().enumerate() {
            let back: Event = serde_json::from_str(line).unwrap();
            assert_eq!(back.ts, 1000 + i as u64);
            assert_eq!(back.pid, 42);
            assert_eq!(back.op, format!("op{i}"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A malformed frame (here: not an `Event`) ends its hub reader — a bug
    /// in a trusted child must not kill the run — while events from other
    /// peers keep flowing through the same queue.
    #[tokio::test]
    async fn hub_reader_ends_on_a_malformed_frame() {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = a.set_nonblocking(true);
        let _ = b.set_nonblocking(true);

        let (file_tx, mut file_rx) = mpsc::channel::<Event>(CAPACITY);
        // No control plane in this test either.
        let (reply_tx, _reply_rx) = tokio::sync::mpsc::channel::<UpdReply>(8);
        let reader = tokio::spawn(ipc::hub_reader(
            tokio::net::UnixStream::from_std(b).unwrap(),
            ipc::PeerRole::HostFs,
            Some(file_tx),
            reply_tx,
        ));

        // Valid event first, then garbage.
        let event = Event {
            ts: 7,
            pid: 8,
            source: "hostfs".into(),
            op: "op".into(),
            path: None,
            result: None,
            detail: None,
        };
        a.write_all(format!("{}\n", event.to_line()).as_bytes())
            .unwrap();
        a.write_all(b"this is not json\n").unwrap();
        a.flush().unwrap();

        // The valid event is forwarded; then the reader ends.
        let forwarded = file_rx.recv().await.unwrap();
        assert_eq!(forwarded.ts, 7);
        // The reader task finished (did not panic or hang).
        tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("hub reader must end after a malformed frame")
            .unwrap();
        // The hub dropped the queue's only sender when it ended; the queue
        // (here the file_rx we hold) was untouched by the malformed peer.
        assert!(file_rx.recv().await.is_none());
    }

    /// Create a FIFO for the refusal tests.
    fn nix_fifo(path: &Path) {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(ret, 0, "mkfifo failed");
    }

    /// SP-2: a child cannot forge another component's source. An event
    /// claiming `source: "control"` on the FS channel is stamped back to
    /// the channel's trusted label, with the claimed value preserved in
    /// `detail`.
    #[tokio::test]
    async fn hub_reader_overrides_a_forged_source() {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = a.set_nonblocking(true);
        let _ = b.set_nonblocking(true);
        let (file_tx, mut file_rx) = mpsc::channel::<Event>(CAPACITY);
        let (reply_tx, _reply_rx) = tokio::sync::mpsc::channel::<UpdReply>(8);
        let reader = tokio::spawn(ipc::hub_reader(
            tokio::net::UnixStream::from_std(b).unwrap(),
            ipc::PeerRole::HostFs,
            Some(file_tx),
            reply_tx,
        ));
        let event = Event {
            ts: 7,
            pid: 8,
            source: "control".into(),
            op: "op".into(),
            path: None,
            result: None,
            detail: None,
        };
        a.write_all(format!("{}\n", event.to_line()).as_bytes())
            .unwrap();
        a.flush().unwrap();
        let forwarded = file_rx.recv().await.unwrap();
        assert_eq!(forwarded.source, "hostfs");
        let detail = forwarded.detail.unwrap();
        assert!(detail.contains("forged source"), "{detail}");
        // A legit source passes through unchanged.
        let mut event = event;
        event.source = "hostfs".into();
        event.ts = 9;
        a.write_all(format!("{}\n", event.to_line()).as_bytes())
            .unwrap();
        a.flush().unwrap();
        let forwarded = file_rx.recv().await.unwrap();
        assert_eq!(forwarded.source, "hostfs");
        assert!(forwarded.detail.is_none());
        drop(a);
        tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("reader must end at EOF")
            .unwrap();
    }

    /// SP-2: a frame that is a valid event *plus* a control-reply key
    /// (`"ack": true`) must not be diverted to the reply channel and
    /// silently dropped from the log. `Event` rejects unknown fields and
    /// the reply parse refuses frames carrying event fields, so such a
    /// frame is malformed: the reader ends the channel (fail-closed)
    /// instead of suppressing the event.
    #[tokio::test]
    async fn hub_reader_fails_closed_on_event_plus_reply_key() {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let _ = a.set_nonblocking(true);
        let _ = b.set_nonblocking(true);
        let (file_tx, mut file_rx) = mpsc::channel::<Event>(CAPACITY);
        let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<UpdReply>(8);
        let reader = tokio::spawn(ipc::hub_reader(
            tokio::net::UnixStream::from_std(b).unwrap(),
            ipc::PeerRole::HostFs,
            Some(file_tx),
            reply_tx,
        ));
        // A real reply still demultiplexes cleanly.
        a.write_all(b"{\"ack\":true}\n").unwrap();
        a.flush().unwrap();
        assert_eq!(reply_rx.recv().await, Some(ipc::UpdReply::Ack));
        // The attack frame: event fields + a reply key.
        let event = Event {
            ts: 7,
            pid: 8,
            source: "hostfs".into(),
            op: "op".into(),
            path: None,
            result: None,
            detail: None,
        };
        let mut line = event.to_line();
        line.truncate(line.len() - 1); // drop the closing brace
        a.write_all(format!("{line}, \"ack\": true}}\n").as_bytes())
            .unwrap();
        a.flush().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("hub reader must end on the attack frame")
            .unwrap();
        // Nothing was diverted: no reply, and no silently-dropped event
        // (the reader ended before forwarding anything).
        assert!(reply_rx.try_recv().is_err());
        assert!(file_rx.try_recv().is_err());
    }
}
