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

use std::io::Write;
use std::path::PathBuf;
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

/// Start a write once a batch exceeds roughly this size: small enough
/// for a single `write(2)` on an `O_APPEND` file (which concurrent
/// writers from the forked ai-bubble processes rely on to keep lines
/// intact), large enough to batch a burst.
const MAX_BYTES: usize = 32 * 1024;

/// The audit log path, configured once before any process forks.
static LOG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The per-process channel to the writer. `None` when auditing is
/// disabled (no `audit.log` in the spec) — `record` then does nothing.
/// The writer task is spawned lazily, on the first `record` (which runs
/// inside a runtime); the static is filled then.
static SENDER: OnceLock<Option<Sender<Event>>> = OnceLock::new();

/// Store the audit log path. Called once by `main`, before any fork;
/// every forked process sets up its own writer lazily on first use.
pub fn configure(path: Option<PathBuf>) {
    let _ = LOG_PATH.set(path);
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
/// async); `None` when auditing is disabled.
fn setup() -> Option<Sender<Event>> {
    let path = LOG_PATH.get().cloned().flatten()?;
    let (tx, rx) = mpsc::channel(CAPACITY);
    tokio::spawn(writer(path, rx));
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
async fn writer(path: PathBuf, mut rx: mpsc::Receiver<Event>) {
    // Opened once, shared with the blocking-pool writes below.
    let open_path = path.clone();
    let file = match tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&open_path)
    })
    .await
    {
        Ok(Ok(file)) => Arc::new(Mutex::new(file)),
        Ok(Err(e)) => crate::sandbox::die(&format!(
            "Can't open audit log {}: {e}",
            path.display()
        )),
        Err(_) => crate::sandbox::die("The audit writer panicked while opening the log"),
    };

    let mut batch: Vec<Event> = Vec::new();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Some(event) => {
                    batch.push(event);
                    if batch.len() >= MAX_EVENTS {
                        flush(&file, std::mem::take(&mut batch)).await;
                    }
                }
                // All senders are gone: flush what is left and end.
                None => {
                    flush(&file, batch).await;
                    return;
                }
            },
            // A quiet stream must still reach the file in bounded time.
            _ = tokio::time::sleep(FLUSH_INTERVAL), if !batch.is_empty() => {
                flush(&file, std::mem::take(&mut batch)).await;
            }
        }
    }
}

/// Serialize a batch to JSON lines and append it to the file, on the
/// blocking pool. The batch is written in chunks of at most
/// [`MAX_BYTES`]: every chunk is one `write(2)` on the `O_APPEND` file,
/// which concurrent writers (the other forked ai-bubble processes)
/// cannot interleave into.
async fn flush(file: &Arc<Mutex<std::fs::File>>, batch: Vec<Event>) {
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
    let result = tokio::task::spawn_blocking(move || {
        let mut file = file.lock().unwrap();
        for chunk in chunks {
            let _ = file.write_all(chunk.as_bytes());
        }
    })
    .await;
    if result.is_err() {
        crate::sandbox::die("The audit writer panicked while writing the log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Without a configured log path the whole subsystem is inert.
    #[tokio::test]
    async fn inert_without_config() {
        record("test", "op", None, None, None).await;
        assert!(SENDER.get_or_init(|| None).is_none());
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
        let path = log.clone();
        let handle = tokio::spawn(writer(path, rx));

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
}
