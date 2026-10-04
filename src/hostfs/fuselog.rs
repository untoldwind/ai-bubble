//! Temporary, env-gated request tracing for debugging the hostfs mirror
//! (`RS_BUBBLE_FUSE_LOG=<file>`): one line per logged event, appended to the
//! given file. Inert (and allocation-free on the request path) when the
//! variable is unset or the log could not be opened.
//!
//! The file is opened **eagerly**, before the fork that starts the FUSE
//! server (see [`init`] and its call in `server::start_host_fs`), with the
//! same safe-open discipline as the audit log — `O_NOFOLLOW`, `O_NONBLOCK`
//! (a FIFO must not hang the open) and a regular-file check. The old lazy
//! open inside the FUSE server violated all three and panicked the server
//! on an open error (AUDIT.md M3).

use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();

/// Open the log file named by `RS_BUBBLE_FUSE_LOG`, before the fork that
/// starts the FUSE server. Must be called exactly once, early; later calls
/// are no-ops (the `OnceLock` is already taken). On an unset variable, or
/// when the file cannot be opened safely, logging stays off — a debug
/// helper must never take the sandbox down.
pub fn init() {
    LOG.get_or_init(|| {
        let path = std::env::var_os("RS_BUBBLE_FUSE_LOG")?;
        match crate::audit::safe_open(std::path::Path::new(&path), "FUSE request log") {
            Ok(file) => Some(Mutex::new(file)),
            Err(e) => {
                eprintln!(
                    "ai-bubble: disabling the FUSE request log {}: {e}",
                    path.to_string_lossy()
                );
                None
            }
        }
    });
}

fn file() -> Option<&'static Mutex<File>> {
    // Only the eager `init` populates the lock; without it, logging is off.
    LOG.get().and_then(|log| log.as_ref())
}

/// Whether the log file is open (i.e. `RS_BUBBLE_FUSE_LOG` is set and the
/// file was opened by [`init`]). Lets the [`event!`] macro skip formatting
/// entirely when logging is off.
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

/// A sandbox-visible path for logging, safely escaped: everything the log
/// line could be forged or decorated with — newlines, terminal escape
/// sequences, quotes, backslashes — is rendered by the string `Debug`
/// formatting as `\n`, `\u{1b}`, `\"` … So a file the sandbox named
/// `a\n…FS open ok mirrored=/etc/shadow` stays one clearly delimited field
/// instead of a second log line, and viewing the log in a terminal cannot
/// be turned into escape-sequence injection (AUDIT.md M3a).
pub fn path_string(p: &std::ffi::OsStr) -> String {
    format!("{:?}", p.to_string_lossy())
}

/// Log one event, formatting the message only when logging is enabled.
///
/// Usage mirrors `format!`: `fuselog::event!("SERVER start mountpoint={}", p.display())`.
/// Paths that the sandbox can influence go through [`path_string`].
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

#[cfg(test)]
mod tests {
    use super::path_string;
    use std::os::unix::ffi::OsStrExt;

    /// The escaped path rendering: control bytes and quotes become escape
    /// sequences, so a log line cannot be forged with an embedded newline
    /// and a terminal cannot be attacked with raw escape bytes.
    #[test]
    fn paths_are_logged_escaped() {
        assert_eq!(
            path_string(std::ffi::OsStr::new("plain/file")),
            "\"plain/file\""
        );
        assert_eq!(
            path_string(std::ffi::OsStr::new("a\nFS open ok mirrored=/etc/shadow")),
            "\"a\\nFS open ok mirrored=/etc/shadow\""
        );
        assert_eq!(
            path_string(std::ffi::OsStr::new("\x1b[31mred\x1b[0m")),
            "\"\\u{1b}[31mred\\u{1b}[0m\""
        );
        assert_eq!(
            path_string(std::ffi::OsStr::new("q\"uote\\")),
            "\"q\\\"uote\\\\\""
        );
        // Non-UTF-8 bytes become replacement characters (lossy), still
        // inside the quotes.
        assert_eq!(
            path_string(std::ffi::OsStr::from_bytes(b"bad\xffbyte")),
            "\"bad\u{fffd}byte\""
        );
    }

    /// `init` opens the log with the audit log's safe-open discipline: a
    /// FIFO (or symlink, device, …) named by the env var must disable
    /// logging instead of being opened — the open used to happen lazily
    /// inside the single-threaded FUSE server, where a FIFO would hang the
    /// open forever and any error would panic the server (AUDIT.md M3b).
    #[test]
    fn init_refuses_a_fifo_and_stays_inert() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-fuselog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fuse.log");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes().to_vec()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) },
            0,
            "mkfifo failed"
        );
        unsafe { std::env::set_var("RS_BUBBLE_FUSE_LOG", &fifo) };
        super::init();
        unsafe { std::env::remove_var("RS_BUBBLE_FUSE_LOG") };
        assert!(!super::enabled());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
