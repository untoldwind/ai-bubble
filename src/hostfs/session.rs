//! The per-run session-cache directory (from the spec's `session-cache`
//! mappings): created fresh per run, recorded process-wide, and wiped by
//! an `atexit` handler when ai-bubble terminates.

use std::path::{Path, PathBuf};

/// The per-run session-cache directory (from the spec's `session-cache`
/// mappings), wiped when ai-bubble terminates. Set by the sandbox parent
/// before `start_host_fs` forks.
static SESSION_CACHE_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Record the per-run session-cache directory (see
/// `crate::spec::hostfs::HostFsConfig::prepare_caches`) and arm its wipe:
/// an `atexit` handler removes the whole tree when this process exits.
/// The handler is inherited by every fork — in particular by the mirrored-fs
/// server, which is the process that survives until the sandbox is done and
/// then wipes the directory; the sandbox parent itself execs into the
/// sandboxed command, which clears the handler there. Must be called before
/// `start_host_fs` forks.
pub fn set_session_cache_root(path: &Path) {
    let _ = SESSION_CACHE_ROOT.set(path.to_path_buf());
    unsafe { libc::atexit(wipe_session_cache) };
}
/// Create the fresh per-run session-cache tmp directory (`mkdtemp`, like
/// the mirrored-fs mountpoint). The caller records it with
/// [`set_session_cache_root`] so it is wiped when ai-bubble terminates.
pub fn new_session_cache_dir() -> PathBuf {
    crate::sandbox::mkdtemp_dir(
        b"/tmp/ai-bubble.cache.XXXXXX",
        "Can't create temporary session-cache directory",
    )
}

/// Whether any `session-cache` mapping exists (so a per-run tmp directory
/// must be created); convenience for the run path in `main`.
pub fn session_cache_needed(has: bool) -> Option<PathBuf> {
    has.then(new_session_cache_dir)
}

/// The `atexit` handler: remove the session-cache directory tree, if one
/// was set. Best effort: a directory that can't be removed (still busy, or
/// already gone) is left to the next reboot.
extern "C" fn wipe_session_cache() {
    if let Some(root) = SESSION_CACHE_ROOT.get() {
        let _ = std::fs::remove_dir_all(root);
    }
}