//! The audit log file: configuration, safe opening, and the file writer.
//!
//! This module owns everything that touches the audit log *file*: the
//! startup-time configuration and validation ([`configure`], with the
//! operator's authority, before any untrusted code runs), the eagerly
//! opened descriptor ([`safe_open`]), the batching file writer
//! ([`writer`]) with its rotation ([`flush`]/[`rotate`]) — the side of
//! the subsystem used by the launcher, the tests, and the non-isolated
//! FUSE server.
//!
//! The inter-process channel side lives in [`crate::audit::ipc`]; the
//! dispatch between the two sinks happens in [`crate::audit`] (`setup`).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;

use super::Event;

/// The audit log's size cap: once the file outgrows this, it is rotated
/// to `<name>.1` (the previous backup is replaced) before the next batch
/// is appended. Generous enough that normal runs never rotate; small
/// enough that a sandbox spraying audit events cannot fill the host
/// disk.
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

/// Start a write once a batch exceeds roughly this size: small enough
/// for a single `write(2)` on an `O_APPEND` file (which concurrent
/// writers from the forked ai-bubble processes rely on to keep lines
/// intact), large enough to batch a burst.
const MAX_BYTES: usize = 32 * 1024;

/// The audit log path and its eagerly opened descriptor, configured
/// once before any process forks. `None` when auditing is disabled.
pub(crate) static LOG: OnceLock<Option<AuditLog>> = OnceLock::new();

/// The configured audit log: its (canonical) path — used only for
/// rotation — and the file opened in [`configure`], before any untrusted
/// code runs. The file sits behind a `Mutex<Option<_>>` so a fork child
/// that becomes an audit child can drop the inherited fd
/// ([`crate::audit::ipc::drop_log_fd`]) — only the launcher keeps
/// writing the file. Writers clone the descriptor; nothing ever opens
/// the path again except rotation.
pub(crate) struct AuditLog {
    pub(crate) path: PathBuf,
    pub(crate) file: Mutex<Option<std::fs::File>>,
}

/// Whether an audit log is configured at all (the channels are only
/// worth creating when something listens at the end of them).
pub fn configured() -> bool {
    matches!(LOG.get(), Some(Some(_)))
}

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
                Err(e) => {
                    crate::sandbox::die(&format!("Can't open audit log {}: {e}", path.display()))
                }
            };
            Some(AuditLog {
                path,
                file: Mutex::new(Some(file)),
            })
        }
    });
}

/// Check the audit log path against the constraint described in
/// [`configure`] and return the canonical path to open (symlinks
/// resolved as far as the path exists, `..` collapsed). Tested from
/// [`crate::audit`]'s test module.
pub(crate) fn validate_path(path: &Path, spec_dir: &Path) -> Result<PathBuf, String> {
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
                    let parent =
                        std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
                    parent.join(name)
                }
                // No parent component (e.g. a bare file name): judge the
                // path as written.
                None => path.to_path_buf(),
            }
        }
    };
    let spec_dir = std::fs::canonicalize(spec_dir).unwrap_or_else(|_| spec_dir.to_path_buf());
    // AUDIT.md L7: audit appends must never land on the policy itself —
    // the spec file (`spec.json`) and the default env file (`.env`) hold
    // the security policy and secrets; a log configured onto either would
    // corrupt them event by event. Same for the spec directory itself
    // (a directory cannot be a log anyway, but the rejection message
    // should say so up front).
    if resolved == spec_dir {
        return Err(format!(
            "audit log {} is the spec directory itself; it must be a file inside \
             it (or a pre-existing file elsewhere)",
            path.display()
        ));
    }
    if resolved.parent() == Some(spec_dir.as_path()) {
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        if name.as_deref() == Some("spec.json") || name.as_deref() == Some(".env") {
            return Err(format!(
                "audit log {} would overwrite the spec's policy file; pick a \
                 different name inside the spec directory",
                path.display()
            ));
        }
    }
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
/// Created files get `0600` (AUDIT.md L7): the log records
/// security-relevant events (paths, targets) and must not be
/// world-readable on a shared host — the `umask` would otherwise leave it
/// `0644`.
pub(crate) fn safe_open(path: &Path, what: &str) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "not a regular file (the {what} must be one)"
        )));
    }
    Ok(file)
}

/// The writer: collect events from the channel and append them to the
/// log file in batches. Runs as a tokio task for the process's
/// lifetime; ends when all senders are gone (process exit).
///
/// The file arrives already open (from [`configure`], via the caller):
/// the attacker-influenceable path is never opened here, so a sandboxed
/// command cannot redirect the writer to a symlink or FIFO mid-run
/// (AUDIT.md H4). Rotation is the only path-based operation left, and it
/// opens exclusively through [`safe_open`].
pub(crate) async fn writer(path: PathBuf, file: std::fs::File, mut rx: mpsc::Receiver<Event>) {
    // Shared with the blocking-pool writes below.
    let file = Arc::new(Mutex::new(file));

    let mut batch: Vec<Event> = Vec::new();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    batch.push(event);
                    if batch.len() >= super::MAX_EVENTS {
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

/// Flush at least this often, so a quiet stream still reaches the file
/// in bounded time.
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

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
            && meta.len() >= MAX_LOG_BYTES
        {
            rotate(&path, &mut file);
        }
        for chunk in chunks {
            if let Err(e) = file.write_all(chunk.as_bytes())
                && !super::WRITE_ERROR_REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
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
/// to lose audit events. Tested from [`crate::audit`]'s test module.
pub(crate) fn rotate(path: &Path, file: &mut std::fs::File) {
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
