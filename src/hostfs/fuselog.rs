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
        std::env::var_os("RS_BUBBLE_FUSE_LOG").map(|p| {
            Mutex::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .unwrap(),
            )
        })
    })
    .as_ref()
}

/// Whether the log file is open (i.e. `RS_BUBBLE_FUSE_LOG` is set). Lets the
/// [`event!`] macro skip formatting entirely when logging is off.
pub fn enabled() -> bool {
    file().is_some()
}

/// Append one line to the log file, when logging is enabled.
pub(crate) fn event(msg: &str) {
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

/// Log one event, formatting the message only when logging is enabled.
///
/// Usage mirrors `format!`: `fuselog::event!("SERVER start mountpoint={}", p.display())`.
#[macro_export]
macro_rules! event {
    ($($arg:tt)*) => {
        if $crate::hostfs::fuselog::enabled() {
            $crate::hostfs::fuselog::event(&format!($($arg)*))
        }
    };
}

// Expose the macro under this module's path too, so call sites can write
// `fuselog::event!(...)` (the macro lives at the crate root because
// `macro_rules!` can only be exported there).
pub(crate) use crate::event;
