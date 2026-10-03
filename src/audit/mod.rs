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
//! * The channel lives per process. The FUSE server, process P (the
//!   in-sandbox network frontends) and the connector all `fork` from the
//!   original process, and channels cannot be shared across `fork` — so
//!   each process initializes its own channel/writer pair and appends to
//!   the same log file. The file is opened in append mode and every
//!   batch is written with a single small `write`, so concurrent writers
//!   do not tear lines apart.
//! * Without an audit log configured the whole subsystem is inert:
//!   `record` returns immediately and no writer task is ever spawned.
//! * The log path is constrained at startup (see [`configure`]): it must
//!   live inside the spec directory, or point at a file that already
//!   exists. Otherwise the writer — running with the operator's uid —
//!   would let sandbox-influenced event content create and append to an
//!   arbitrary host file (e.g. the operator's shell rc). The log is also
//!   size-capped: once it outgrows [`MAX_LOG_BYTES`] it is rotated to
//!   `<name>.1` (one previous generation kept) before the next batch is
//!   written, so a sandbox spraying events cannot fill the host disk.
//!   Write errors are surfaced on stderr (once per process) instead of
//!   being discarded silently — losing audit events is worth knowing
//!   about even when the run cannot be stopped for it.
//! * The file is opened **eagerly, in [`configure`]** — before the
//!   sandbox and any untrusted command exist — with `O_NOFOLLOW` and a
//!   regular-file check (AUDIT.md finding H4). The opened descriptor is
//!   retained for the process lifetime; the writer never opens the path
//!   again. A sandboxed command can therefore not swap the path for a
//!   symlink (its appends would land in an operator-chosen target) or a
//!   FIFO (the writer would hang and, through the bounded channel,
//!   deadlock every suspending producer) — the descriptor already points
//!   at the validated regular file, and `O_NOFOLLOW` keeps every later
//!   (rotation) open from following a swapped-in symlink.
//! * Residual, by design: if the audit log lives inside a *sandbox-
//!   writable* mapped directory, the command can open the same file
//!   through the mirror and append, truncate, or fill it with its own
//!   content (the eager open protects the writer's descriptor, not the
//!   file's integrity). Keep the audit log inside the spec directory,
//!   which the sandbox never sees.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc::{self, Sender};

/// The channel capacity: how many events may pile up in memory before a
/// producer is suspended. Generous on purpose — spikes (e.g. a build
/// touching thousands of files) must be absorbed, not dropped.
const CAPACITY: usize = 65536;

/// Flush at least this often, so a quiet stream still reaches the file
/// in bounded time.
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// Never batch more than this many events before flushing.
const MAX_EVENTS: usize = 4096;

/// The audit log's size cap: once the file outgrows this, it is rotated
/// to `<name>.1` (the previous backup is replaced) before the next batch
/// is appended. Generous enough that normal runs never rotate; small
/// enough that a sandbox spraying audit events cannot fill the host
/// disk.
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// Set on the first failed write in this process, so the error is
/// surfaced on stderr once instead of spamming or being discarded.
static WRITE_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);

/// Start a write once a batch exceeds roughly this size: small enough
/// for a single `write(2)` on an `O_APPEND` file (which concurrent
/// writers from the forked ai-bubble processes rely on to keep lines
/// intact), large enough to batch a burst.
const MAX_BYTES: usize = 32 * 1024;

/// The audit log path and its eagerly opened descriptor, configured
/// once before any process forks. `None` when auditing is disabled.
static LOG: OnceLock<Option<AuditLog>> = OnceLock::new();

/// The configured audit log: its (canonical) path — used only for
/// rotation — and the file opened in [`configure`], before any untrusted
/// code runs. Writers clone the descriptor; nothing ever opens the path
/// again except rotation.
struct AuditLog {
    path: PathBuf,
    file: std::fs::File,
}

/// The per-process channel to the writer. `None` when auditing is
/// disabled (no `audit.log` in the spec) — `record` then does nothing.
/// The writer task is spawned lazily, on the first `record` (which runs
/// inside a runtime); the static is filled then.
static SENDER: OnceLock<Option<Sender<Event>>> = OnceLock::new();

/// Open the audit log eagerly and store path + descriptor. Called once
/// by `main`, before any fork; every forked process clones the
/// descriptor for its own writer lazily on first use.
///
/// The path is validated here, with the operator's authority, before any
/// untrusted work runs: the writer appends with the operator's uid, so
/// without this check sandbox-influenced event content could be appended
/// to an arbitrary operator-writable file. The path must either live
/// inside the spec directory (created automatically — the spec directory
/// is the run's trusted configuration area) or point at a file that
/// already exists (append-only, nothing new is created). Anything else
/// is a hard startup error.
///
/// The file is opened right here, before the sandbox exists (AUDIT.md
/// finding H4): with `O_NOFOLLOW` (a path swapped to a symlink is
/// refused instead of being followed), after a regular-file check (a
/// FIFO would hang the writer, and through the bounded channel deadlock
/// every suspending producer), and the descriptor is retained for the
/// process lifetime — the sandbox cannot influence it afterwards.
pub fn configure(log: Option<PathBuf>, spec_dir: &Path) {
    let _ = LOG.set(match log {
        None => None,
        Some(path) => {
            // `validate_path` returns the canonical path to open:
            // symlinks resolved, `..` collapsed — so the `O_NOFOLLOW`
            // open below races nothing, and rotation operates on the
            // real file even when the configured path was a link.
            let path = match validate_path(&path, spec_dir) {
                Ok(resolved) => resolved,
                Err(e) => crate::sandbox::die(&e),
            };
            let file = match safe_open(&path, "audit log") {
                Ok(file) => file,
                Err(e) => crate::sandbox::die(&format!(
                    "Can't open audit log {}: {e}",
                    path.display()
                )),
            };
            Some(AuditLog { path, file })
        }
    });
}

/// Check the audit log path against the constraint described in
/// [`configure`] and return the canonical path to open (symlinks
/// resolved as far as the path exists, `..` collapsed).
fn validate_path(path: &Path, spec_dir: &Path) -> Result<PathBuf, String> {
    // Resolve symlinks and `..` as far as the path exists: an existing
    // file (or one whose parent exists) is judged by what it really is.
    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(_) => {
            // The file itself does not exist yet: judge by its parent
            // directory (which must exist for the writer to create the
            // file later anyway).
            match path.parent().zip(path.file_name()) {
                Some((parent, name)) => {
                    let parent = std::fs::canonicalize(parent)
                        .unwrap_or_else(|_| parent.to_path_buf());
                    parent.join(name)
                }
                // No parent component (e.g. a bare file name): judge the
                // path as written.
                None => path.to_path_buf(),
            }
        }
    };
    let spec_dir = std::fs::canonicalize(spec_dir).unwrap_or_else(|_| spec_dir.to_path_buf());
    // Inside the spec directory: fine, the writer may create it there.
    if resolved.starts_with(&spec_dir) {
        return Ok(resolved);
    }
    // Outside the spec directory: only a pre-existing file is allowed.
    if resolved.exists() {
        return Ok(resolved);
    }
    Err(format!(
        "audit log {} is not inside the spec directory {} and does not exist; \
         the audit log must live in the spec directory (it is created there \
         automatically) or point at an already existing file — refusing to \
         create or append to an arbitrary host path",
        path.display(),
        spec_dir.display()
    ))
}

/// Open a log file safely: `O_CREAT|O_APPEND` plus `O_NOFOLLOW` (a
/// swapped-in symlink must never be followed) and `O_NONBLOCK` (an
/// unfortunately named FIFO must not block the open), then a
/// regular-file check — anything else (FIFO, device, socket) is refused
/// with an error instead of being written to or hung on (AUDIT.md H4).
/// `what` names the log in error messages. Also `O_CLOEXEC`: the fd is
/// opened before the forks and must not leak into the executed command
/// (the sandbox's fd sweep covers the same thing, this is belt and braces).
pub(crate) fn safe_open(path: &Path, what: &str) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "not a regular file (the {what} must be one)"
        )));
    }
    Ok(file)
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
    let Some(sender) = SENDER.get_or_init(setup).as_ref() else {
        return;
    };
    // A closed channel can only mean the writer task is gone (it dies
    // with the process anyway); there is nothing to audit to then.
    let _ = sender
        .send(Event {
            source: source.to_string(),
            op: op.to_string(),
            path: path.map(|p| p.to_string()),
            result: result.map(|r| r.to_string()),
            detail,
        })
        .await;
}

/// Create the channel and spawn the writer task. Must run inside a
/// tokio runtime (it is only ever called from `record`, which is
/// async); `None` when auditing is disabled. The writer clones the
/// descriptor opened in [`configure`] — it never opens the log path
/// itself.
fn setup() -> Option<Sender<Event>> {
    let log = LOG.get()?.as_ref()?;
    // A fresh descriptor per process (`try_clone` dups the fd): forked
    // processes must not share the mutex guarding the file.
    let file = match log.file.try_clone() {
        Ok(file) => file,
        Err(e) => crate::sandbox::die(&format!("Can't open the audit log for writing: {e}")),
    };
    let (tx, rx) = mpsc::channel(CAPACITY);
    tokio::spawn(writer(log.path.clone(), file, rx));
    Some(tx)
}

/// Wait for the writer to catch up. Call on any clean process exit
/// path, inside the process's runtime: the writer batches with
/// [`FLUSH_INTERVAL`] granularity, and a plain `exit(0)` would kill the
/// task before the last batch reaches the file. Inert when auditing is
/// off (and never spawns a writer on its own).
pub async fn drain() {
    // Only act when this process already has a writer: if auditing is
    // disabled (or nothing was ever recorded) there is nothing to wait
    // for — and drain must not spawn one on its own.
    if SENDER.get().and_then(|s| s.as_ref()).is_none() {
        return;
    }
    // Two rounds of "wait one flush interval": the writer flushes at
    // most one interval after the last event, and events may still
    // trickle in while we wait.
    for _ in 0..2 {
        tokio::time::sleep(FLUSH_INTERVAL).await;
    }
}

/// One audit event, as it flows through the channel.
struct Event {
    source: String,
    op: String,
    path: Option<String>,
    result: Option<String>,
    detail: Option<String>,
}

impl Event {
    /// The event as one JSON line.
    fn to_line(&self) -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        serde_json::json!({
            "ts": ts,
            "pid": std::process::id(),
            "source": self.source,
            "op": self.op,
            "path": self.path,
            "result": self.result,
            "detail": self.detail,
        })
        .to_string()
    }
}

/// The writer: collect events from the channel and append them to the
/// log file in batches. Runs as a tokio task for the process's
/// lifetime; ends when all senders are gone (process exit).
///
/// The file arrives already open (from [`configure`], via [`setup`]):
/// the attacker-influenceable path is never opened here, so a sandboxed
/// command cannot redirect the writer to a symlink or FIFO mid-run
/// (AUDIT.md H4). Rotation is the only path-based operation left, and it
/// opens exclusively through [`safe_open`].
async fn writer(path: PathBuf, file: std::fs::File, mut rx: mpsc::Receiver<Event>) {
    // Shared with the blocking-pool writes below.
    let file = Arc::new(Mutex::new(file));

    let mut batch: Vec<Event> = Vec::new();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    batch.push(event);
                    if batch.len() >= MAX_EVENTS {
                        flush(&path, &file, std::mem::take(&mut batch)).await;
                    }
                }
                // All senders are gone: flush what is left and end.
                None => {
                    flush(&path, &file, batch).await;
                    return;
                }
            },
            // A quiet stream must still reach the file in bounded time.
            _ = tokio::time::sleep(FLUSH_INTERVAL), if !batch.is_empty() => {
                flush(&path, &file, std::mem::take(&mut batch)).await;
            }
        }
    }
}

/// Serialize a batch to JSON lines and append it to the file, on the
/// blocking pool. The batch is written in chunks of at most
/// [`MAX_BYTES`]: every chunk is one `write(2)` on the `O_APPEND` file,
/// which concurrent writers (the other forked ai-bubble processes)
/// cannot interleave into.
///
/// Before the batch is written, the file size is checked against
/// [`MAX_LOG_BYTES`]: an oversized log is rotated to `<name>.1` first,
/// so a sandbox spraying audit events cannot fill the host disk. Write
/// errors are surfaced on stderr (once per process) — they are not
/// fatal, but silently losing audit events would be worse.
async fn flush(path: &Path, file: &Arc<Mutex<std::fs::File>>, batch: Vec<Event>) {
    if batch.is_empty() {
        return;
    }
    let mut chunks: Vec<String> = Vec::new();
    let mut chunk = String::new();
    for event in batch {
        chunk.push_str(&event.to_line());
        chunk.push('\n');
        if chunk.len() >= MAX_BYTES {
            chunks.push(std::mem::take(&mut chunk));
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    let file = file.clone();
    let path = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        let mut file = file.lock().unwrap();
        // Size cap: rotate before this batch pushes the log further past
        // it. The rename keeps the (still open) old file as the backup.
        if let Ok(meta) = file.metadata()
            && meta.len() >= MAX_LOG_BYTES {
                rotate(&path, &mut file);
            }
        for chunk in chunks {
            if let Err(e) = file.write_all(chunk.as_bytes())
                && !WRITE_ERROR_REPORTED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "warning: can't write the audit log {}: {e} (further errors are silent)",
                        path.display()
                    );
                }
        }
    })
    .await;
    if result.is_err() {
        crate::sandbox::die("The audit writer panicked while writing the log");
    }
}

/// Rotate the audit log at `path`: move the (possibly still open) file
/// to `<name>.1`, replacing any previous backup, and point `file` at a
/// fresh log. Failures are ignored — rotating is best effort, and it is
/// always better to keep appending (to the old or the fresh file) than
/// to lose audit events.
fn rotate(path: &Path, file: &mut std::fs::File) {
    let backup = match path.file_name() {
        Some(name) => {
            let mut backup = name.to_os_string();
            backup.push(".1");
            path.with_file_name(backup)
        }
        // A path without a file name component cannot be rotated.
        None => return,
    };
    // `rename` atomically replaces an earlier `<name>.1`. If it fails
    // (e.g. a concurrent rotation by one of the other forked ai-bubble
    // processes won the race), fall through: the fresh open below either
    // finds the rotated-away file (and creates a new one) or the
    // original. Both re-opens go through `safe_open` (`O_NOFOLLOW`,
    // regular-file check): a path the sandbox swapped for a symlink or
    // FIFO must not be followed or hung on — and when the safe open
    // fails, the writer keeps appending to the descriptor it already
    // holds, which the sandbox cannot touch (AUDIT.md H4).
    if std::fs::rename(path, &backup).is_ok()
        && let Ok(fresh) = safe_open(path, "audit log")
    {
            *file = fresh;
            return;
        }
    // Renaming or re-opening failed: try to re-open the original path so
    // `file` at least tracks the canonical location again. When even that
    // fails, keep writing to the old descriptor (the renamed backup).
    if let Ok(reopened) = safe_open(path, "audit log") {
        *file = reopened;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;

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

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotating an oversized log moves the old file to `<name>.1` and
    /// points the writer at a fresh log.
    #[test]
    fn rotate_moves_the_log_to_a_backup() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-audit-rotate-{}", std::process::id()));
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
        let handle = tokio::spawn(writer(path, file, rx));

        for i in 0..3 {
            tx.send(Event {
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
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-audit-link-{}", std::process::id()));
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
/// rename blocked, both fresh opens fail and the writer keeps appending
/// to the descriptor it already holds.
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

    /// Create a FIFO for the refusal tests.
    fn nix_fifo(path: &Path) {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(ret, 0, "mkfifo failed");
    }
}
