//! Temporary, env-gated request tracing for debugging the hostfs mirror
//! (`RS_BUBBLE_FUSE_LOG=<file>`): one line per logged event, appended to the
//! given file. Inert (and allocation-free on the request path) when the
//! variable is unset.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn file() -> Option<&'static Mutex<File>> {
    LOG.get_or_init(|| {
        std::env::var_os("RS_BUBBLE_FUSE_LOG")
            .map(|p| Mutex::new(OpenOptions::new().create(true).append(true).open(p).unwrap()))
    })
    .as_ref()
}

/// Append one line to the log file, when logging is enabled.
pub fn event(msg: &str) {
    if let Some(file) = file() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        let tid = unsafe { libc::gettid() };
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "{ts} [{tid}] {msg}");
        }
    }
}

/// A path for logging.
pub fn path_string(p: &std::ffi::OsStr) -> String {
    p.to_string_lossy().into_owned()
}
