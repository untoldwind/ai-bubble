//! The host-side FUSE filesystem.
//!
//! The *host* process exposes a mirror of parts of the real filesystem via
//! FUSE. The mirrored paths are selected by the spec's ordered
//! `hostfs.mappings` list, each carrying a permission (`"ro"` mirrors a
//! matched path read-only, `"rw"` mirrors it read-write, `"hide"` hides it,
//! `"empty"` exposes it empty, `"redirect-ro"`/`"redirect-rw"` show a
//! *different* host path (the mapping's `source`) at the matched path —
//! a lightweight bind routed through the mirror itself; when a path matches
//! several mappings, the last match wins); the result is the sandbox root:
//! the **full host paths**
//! are reproduced — a mapping `/etc/*.conf` makes `/etc/foo.conf` available
//! at `/etc/foo.conf`. A pattern that matches a directory exactly
//! (`/usr/share/doc`) mirrors that directory recursively (or, when hidden,
//! hides it with its whole subtree); `**` matches across directory
//! boundaries.
//!
//! The patterns are *not* expanded at startup: the host tree is never
//! crawled. Every FUSE operation matches the requested path against the
//! compiled patterns on the fly (see `pattern.rs` for the supported glob
//! syntax), so startup is O(patterns) and a huge host tree costs nothing.
//! (`readdir` lists the real directory and filters out every entry that
//! matches no pattern.)
//!
//! Because a FUSE session must keep running while the sandboxed command runs,
//! and because tokio runtimes must never be shared across `fork` (see
//! `netns.rs`), the server lives in its *own* forked child process: the parent
//! (the sandbox) forks it first, waits for a readiness byte on a pipe, and only
//! then proceeds with the namespace setup. When the parent dies, the FUSE
//! server unmounts and exits. The termination signals that would otherwise
//! kill the server mid-mount (Ctrl-C to the process group, `SIGTERM`, …) are
//! blocked around the fork and ignored inside it, and a failed unmount falls
//! back to a lazy unmount — the mount is detached even when something still
//! holds it busy.
//!
//! `hostfs.mappings` is an ordered pattern → permission list: `"ro"`/`"rw"`
//! mirror the matched paths (read-only or read-write), `"hide"` hides them
//! (a hidden directory hides its whole subtree) and `"empty"` exposes them
//! empty — an empty, unwritable directory when the path is (or would be) a
//! directory, an empty file when it matches a real file. Empty paths take
//! precedence over the mirror: nothing below them is visible, which makes
//! them the mount points for the sandbox to stack `/dev`, `/proc`, tmpfs
//! (or its whole root) on top of. When a path matches several patterns the
//! last match wins.
//!
//! Writes: a path is writable only when the last pattern naming it (or its
//! nearest mirrored ancestor — an exactly-named or `**`-covered directory
//! is a recursive mirror, so its permission governs everything below it)
//! says `"rw"`, **and** the real host filesystem allows the operation. The
//! FUSE mount is mounted read-only unless some pattern says `"rw"`.
//!
//! The FUSE handlers are async: the pure pattern matching runs inline, but
//! every blocking host operation (std::fs, raw libc calls) is pushed to
//! tokio's blocking pool (`tokio::fs` / `spawn_blocking`), so a slow read
//! or a hung network filesystem never stalls the mount's event loop.
//!
//! Symlinks: every access to the **real host filesystem** uses
//! no-follow semantics — host paths are always opened with `O_NOFOLLOW`
//! and stated with `symlink_metadata`. A mirrored symlink is therefore
//! visible only *as a symlink* (its target can be read with `readlink`),
//! never followed: opening one for reading or writing fails with `ELOOP`,
//! and the target's content is not exposed unless the target itself
//! matches a pattern. This keeps the "only mapped paths are visible"
//! guarantee intact even when the host contains links pointing elsewhere.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::SeekFrom;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fuse3::raw::reply::{
    DirectoryEntry, DirectoryEntryPlus, FileAttr, ReplyAttr, ReplyCreated, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs, ReplyWrite,
};
use fuse3::raw::{Filesystem, Request, Session};
use fuse3::{FileType, Inode, MountOptions, Result, SetAttr, Timestamp};
use futures_util::stream;

use tokio::fs as tokio_fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::sandbox::die_with_error;

pub(crate) mod fuselog;
mod inodes;
pub(crate) mod pattern;
pub(crate) mod patterns;
mod perf;

use inodes::InodeMap;
use pattern::{Pattern, Walk};
use patterns::{Patterns, Permission};

/// Log a failed FUSE op with the mirrored and the real host path (debug
/// helper, only active with `RS_BUBBLE_FUSE_LOG` set) and turn it into an
/// audit event.
async fn log_op_err(op: &str, mirrored: &Path, real: Option<&Path>, err: &std::io::Error) {
    fuselog::event!(
        "FS {op} err={err} mirrored={} real={}",
        mirrored.display(),
        real.map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into()),
    );
    crate::audit::record(
        "hostfs",
        op,
        Some(&mirrored.to_string_lossy()),
        Some(&format!("err: {err}")),
        real.map(|p| p.to_string_lossy().into_owned()),
    )
    .await;
}

/// Log a successful structural op (create/mkdir/…) with its paths, and
/// turn it into an audit event.
async fn log_op_ok(op: &str, mirrored: &Path, real: &Path) {
    fuselog::event!(
        "FS {op} ok mirrored={} real={}",
        mirrored.display(),
        real.display()
    );
    crate::audit::record(
        "hostfs",
        op,
        Some(&mirrored.to_string_lossy()),
        Some("ok"),
        Some(real.to_string_lossy().into_owned()),
    )
    .await;
}

/// The effective permission of a path under compiled patterns — the one
/// piece of semantics both the standalone [`permission_of`] (spec side:
/// `ls`, tests) and the running mirror ([`HostFs`], which keeps its
/// patterns pre-compiled) must agree on.
///
/// `direct` answers which permission the **last** pattern naming the path
/// itself (exactly, or via a `**` that covers it) carries, and `hidden`
/// whether a `hide` pattern names the path itself or a strict ancestor of
/// it (see [`HostFs::hidden`] for the mirror side).
///
/// The semantics, identical on both sides:
///
/// * everything strictly below an `empty` or `inject` path is invisible —
///   an empty path is meant to be covered by a mount inside the sandbox
///   and an injected path is a virtual file, so neither has content below
///   it (`None`),
/// * a `hide` pattern naming the path itself or a strict ancestor wins
///   over everything else — a hidden path is not visible, no matter which
///   pattern comes last (`hide`),
/// * otherwise the **last** pattern naming the path itself decides —
///   including `empty` and `inject`,
/// * otherwise the permission of the **nearest** mirrored (`ro`/`rw`/
///   redirect) ancestor is inherited: an exactly-named or `**`-covered
///   directory is a recursive mirror, so its permission governs
///   everything below,
/// * otherwise the path is not visible in the sandbox at all (`None`).
///
/// This lives with the matcher rather than with [`Patterns`] because the
/// glob engine is hostfs-internal (and the build-time schema generation
/// compiles `spec` without it).
const HIDE: Permission = Permission::Hide;

fn effective_permission<'p>(
    path: &Path,
    direct: impl Fn(&Path) -> Option<&'p Permission>,
    hidden: impl Fn(&Path) -> bool,
) -> Option<&'p Permission> {
    // Everything strictly below an empty or an injected path is invisible:
    // an empty path is covered by a mount inside the sandbox, an injected
    // path is a virtual file — neither has content below it, whatever
    // pattern matches below.
    if path.ancestors().skip(1).any(|a| {
        matches!(
            direct(a),
            Some(Permission::Empty) | Some(Permission::Inject { .. })
        )
    }) {
        return None;
    }

    // A hidden path is never visible — the mirror enforces this
    // unconditionally (`HostFs::hidden` checks every `hide` pattern,
    // naming the path itself or a strict ancestor, before any direct
    // permission), so the last-match rule below only applies among the
    // non-`hide` patterns.
    if hidden(path) {
        return Some(&HIDE);
    }

    // The last pattern naming the path itself decides.
    if let Some(permission) = direct(path) {
        return Some(permission);
    }

    // Otherwise the nearest mirrored ancestor governs: the mirror is
    // recursive, so its permission extends to everything below it.
    path.ancestors()
        .skip(1)
        .find_map(|a| direct(a).filter(|p| p.is_mirrored()))
}

pub fn permission_of(patterns: &Patterns, path: &Path) -> Option<Permission> {
    let compiled: Vec<(Pattern, Permission)> = patterns
        .iter()
        .filter_map(|(pattern, permission)| {
            Pattern::new(pattern)
                .ok()
                .map(|compiled| (compiled, permission.clone()))
        })
        .collect();
    effective_permission(
        path,
        |p| {
            compiled
                .iter()
                .rev()
                .find(|(compiled, _)| compiled.matches(p))
                .map(|(_, permission)| permission)
        },
        |p| {
            compiled.iter().any(|(compiled, permission)| {
                *permission == Permission::Hide
                    && (compiled.matches(p) || compiled.walk(p) == Walk::Ancestor)
            })
        },
    )
    .cloned()
}

/// Whether any pattern grants write access: the FUSE mount is mounted
/// read-only unless it does.
fn has_writable_patterns(patterns: &Patterns) -> bool {
    patterns
        .iter()
        .any(|(_, permission)| permission.is_writable())
}

/// The sandbox-absolute path the host filesystem is mounted at.
pub const SANDBOX_MOUNT_POINT: &str = "/mirrored";

/// Whether the host filesystem should become the sandbox root instead of
/// being mounted at `/host`. Set once before any fork.
static ROOT_MODE: AtomicBool = AtomicBool::new(false);

/// Select hostfs-root mode. Must be called before any process forks.
pub fn set_root_mode(on: bool) {
    ROOT_MODE.store(on, Ordering::SeqCst);
}

/// Whether hostfs-root mode is active (read after the forks).
pub(crate) fn root_mode() -> bool {
    ROOT_MODE.load(Ordering::SeqCst)
}

/// The host-side mountpoint of the FUSE filesystem, if it has been started.
pub(crate) fn host_mount_point() -> Option<&'static PathBuf> {
    HOST_MOUNT_POINT.get()
}

/// The mountpoint of the running host filesystem, set by `start_host_fs`
/// before any fork. Needed by the sandbox child to create the bind mount.
pub(crate) static HOST_MOUNT_POINT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// PID of the sandbox (host) process; the FUSE server exits when it dies.
static HOST_PID: AtomicI32 = AtomicI32::new(0);

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
    let mut tmpl: Vec<u8> = b"/tmp/ai-bubble.cache.XXXXXX".to_vec();
    tmpl.push(0);
    let raw = unsafe { libc::mkdtemp(CString::from_vec_with_nul(tmpl).unwrap().into_raw()) };
    if raw.is_null() {
        die_with_error("Can't create temporary session-cache directory");
    }
    PathBuf::from(
        unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned(),
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

const TTL: Duration = Duration::from_secs(1);

/// One compiled mirror pattern, with the permission it carries.
#[derive(Clone)]
struct MirrorPattern {
    pattern: Pattern,
    permission: Permission,
}

impl MirrorPattern {
    /// Whether the pattern names the path itself (exactly, or via a `**`
    /// that covers it).
    fn names(&self, mirrored: &Path) -> bool {
        self.pattern.matches(mirrored)
    }
}

/// The mirror filesystem: a view of the paths selected by the spec's
/// ordered `hostfs.mappings` pattern → permission list, reproduced at
/// the same absolute host paths (the filesystem is the sandbox root).
/// Nothing is pre-expanded; every operation matches against the patterns
/// directly.
///
/// This is a **raw** fuse3 `Filesystem`: the kernel hands over nodeids and
/// this implementation resolves each one to its mirrored path through
/// [`InodeMap`] — the job the vendored fuse3 path bridge (`InodePathBridge`)
/// used to do, and which broke on rename (see `FINDINGS.md`). Owning the map
/// removes the vendored dependency entirely.
///
/// Paths matched with the `"empty"` permission are exposed empty: as an
/// empty, unwritable directory when the path is (or would be) a directory,
/// or as an empty file when it matches a real file. They take
/// *precedence* over the mirror: nothing below an empty path is visible
/// (it is meant to be covered by a mount inside the sandbox, e.g. the
/// sandbox root itself or `/dev`). Ancestors of empty paths stay
/// navigable even when the mirror knows nothing about them.
///
/// Permissions: the **last** pattern that names a path (exactly or via
/// `**`) decides whether it is mirrored read-only (`ro`), mirrored
/// read-write (`rw`), empty (`empty`), hidden (`hide`) or redirected
/// (`redirect-ro`/`redirect-rw`: the host path the mapping's `source`
/// names is shown at the matched path instead of the path's own
/// content); a hidden path —
/// or one below a hidden directory — is not visible at all. Ancestors of
/// visible matches stay navigable as long as no hidden pattern stands
/// between them and the matches below. Writes additionally require the
/// `rw` permission (see [`HostFs::write_permission`]).
struct HostFs {
    uid: u32,
    gid: u32,
    patterns: Vec<MirrorPattern>,
    /// The nodeid ↔ mirrored-path map (see [`inodes`]). There is exactly one
    /// map per FUSE session: the filesystem is *moved* into the mount, and
    /// the mount fallback builds a fresh filesystem (the failed attempt never
    /// reached the kernel, so an empty map is correct there).
    inodes: tokio::sync::RwLock<InodeMap>,
    /// Open host files keyed by FUSE handle (`fh`): stateful IO — the file
    /// is opened once (`open`/`create`) and reused for every `read`/`write`
    /// on the handle, instead of being reopened per request. `fh = 0` stays
    /// stateless (injected files, directories); an unknown `fh` falls back
    /// to the stateless reopen, so a lost entry degrades instead of failing.
    handles: std::sync::Mutex<HashMap<u64, std::sync::Arc<OpenHandle>>>,
    /// The next `fh` to hand out; 0 is reserved for stateless IO.
    next_fh: AtomicU64,
}

/// One open host file behind a FUSE handle. The file is kept open for the
/// handle's lifetime (released with it in `release`), so sequential reads
/// and writes skip the per-request open/seek/close cycle. The per-handle
/// mutex serializes the shared cursor; concurrent access to one handle is
/// rare and only costs lock wait, never a reopen.
struct OpenHandle {
    file: tokio::sync::Mutex<tokio_fs::File>,
    /// The mirrored path the handle was opened with, cached for the handle's
    /// lifetime. `read`/`write` never look the inode up in the map on this
    /// fast path; the path is only consulted for error logging.
    path: PathBuf,
    /// Opened with `O_APPEND`: every write goes to the end, offsets ignored.
    append: bool,
    /// Spec verdict cached at open time: whether the spec says the mirrored
    /// path is writable (`rw`). The pattern list never changes during a
    /// session, so the verdict stays valid for the handle's lifetime —
    /// `write` uses it instead of re-matching every pattern per request.
    /// (A real handle can only come from `open`/`create`, which already
    /// established that the path exists, is not injected and not empty:
    /// those checks are skipped on the handle's read/write fast path too.)
    writable: bool,
}

impl HostFs {
    /// Compile the mirror patterns. Invalid patterns are a hard error.
    fn collect(patterns: &Patterns) -> HostFs {
        let compiled = patterns
            .iter()
            .map(|(p, perm)| MirrorPattern {
                pattern: compile(p),
                permission: perm.clone(),
            })
            .collect();
        HostFs {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            patterns: compiled,
            inodes: tokio::sync::RwLock::new(InodeMap::new()),
            handles: std::sync::Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
        }
    }

    /// Allocate a fresh FUSE handle (`fh`) for a newly opened host file.
    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }

    /// Register an opened host file under a fresh `fh`.
    fn insert_handle(
        &self,
        file: tokio_fs::File,
        path: PathBuf,
        append: bool,
        writable: bool,
    ) -> u64 {
        let fh = self.alloc_fh();
        self.handles
            .lock()
            .expect("hostfs handle table poisoned")
            .insert(
                fh,
                std::sync::Arc::new(OpenHandle {
                    file: tokio::sync::Mutex::new(file),
                    path,
                    append,
                    writable,
                }),
            );
        fh
    }

    /// Take a handle's file out of the table (`release`): dropping the
    /// `OpenHandle` closes the host file.
    fn remove_handle(&self, fh: u64) {
        self.handles
            .lock()
            .expect("hostfs handle table poisoned")
            .remove(&fh);
    }

    /// A cloned reference to the handle's entry, or `None` for an unknown
    /// (or stateless, `fh = 0`) handle — the caller falls back to the
    /// stateless reopen in that case.
    fn handle_of(&self, fh: u64) -> Option<std::sync::Arc<OpenHandle>> {
        self.handles
            .lock()
            .expect("hostfs handle table poisoned")
            .get(&fh)
            .cloned()
    }

    /// Resolve a nodeid to its mirrored path (falling back to a zombie's
    /// last path while open handles remain), or ENOENT when the kernel
    /// dentry is unknown to the map.
    ///
    /// The map stores mirrored paths already, so the result is used directly:
    /// there is no second `mirror_path` parse on the hot path. The lock guard
    /// is dropped before returning, hence the single owned clone.
    async fn resolve(&self, inode: Inode) -> std::io::Result<PathBuf> {
        self.inodes
            .read()
            .await
            .path_of(inode)
            .map(Path::to_path_buf)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))
    }

    /// Whether the mirrored path is matched with the `empty` permission (by
    /// the last pattern naming it): it is exposed empty — as an empty
    /// directory when it is (or would be) a directory, an empty file when
    /// it matches a real file.
    fn is_empty(&self, mirrored: &Path) -> bool {
        matches!(self.permission_of(mirrored), Some(Permission::Empty))
    }

    /// The in-memory content of the mirrored path when it is matched with
    /// the `inject` permission (by the last pattern naming it): the path
    /// is a purely virtual file served from the mirror's memory, with no
    /// host counterpart at all. Borrowed: this is consulted on every
    /// operation touching the path.
    fn is_inject(&self, mirrored: &Path) -> Option<&str> {
        match self.permission_of(mirrored) {
            Some(Permission::Inject { content }) => Some(content.as_str()),
            _ => None,
        }
    }

    /// Whether some `inject` pattern could still match something *strictly
    /// below* the given mirrored path — i.e. the path acts as a (possibly
    /// purely virtual) directory leading to injected files, and must stay
    /// navigable (and listable) even when the mirror knows nothing about
    /// it otherwise.
    fn is_inject_prefix(&self, mirrored: &Path) -> bool {
        self.patterns.iter().any(|p| {
            matches!(p.permission, Permission::Inject { .. })
                && p.pattern.walk(mirrored) == Walk::CouldReach
        })
    }

    /// Whether the mirrored path lies strictly *below* an empty path (so it is
    /// shadowed by the empty path's precedence and never visible).
    fn under_empty(&self, mirrored: &Path) -> bool {
        mirrored.ancestors().skip(1).any(|a| self.is_empty(a))
    }

    /// Whether the mirrored path lies strictly *below* an injected path: an
    /// injected path is a virtual file with no content below it, so such
    /// paths are never visible — not even when another pattern matches them.
    fn under_inject(&self, mirrored: &Path) -> bool {
        mirrored
            .ancestors()
            .skip(1)
            .any(|a| self.is_inject(a).is_some())
    }

    /// The effective permission of a mirrored path — exactly the semantics
    /// of the standalone [`permission_of`] (see [`effective_permission`]),
    /// applied to the mirror's pre-compiled patterns (borrowed: this runs
    /// on every operation, often several times per path).
    ///
    /// One deliberate exception to the shared semantics: a path with a
    /// non-UTF-8 component fails closed (see [`Pattern::matches`]) — the
    /// mirror answers "not visible, not writable" for it, while the
    /// standalone function (which only *annotates*) still inherits the
    /// nearest mirrored ancestor.
    fn effective(&self, mirrored: &Path) -> Option<&Permission> {
        // Fail closed: a non-UTF-8 component can never match a pattern, so
        // its permission could never be derived from the spec — a hidden
        // name spelled with invalid UTF-8 bytes must not become visible or
        // writable (or creatable) through the mirror.
        if Pattern::has_non_utf8_component(mirrored) {
            return None;
        }
        effective_permission(mirrored, |p| self.permission_of(p), |p| self.hidden(p))
    }

    /// Whether some `empty` pattern could still match something *strictly
    /// below* the given mirrored path — i.e. the path acts as a (possibly
    /// purely virtual) directory leading to empty paths, and must stay
    /// navigable even when the mirror knows nothing about it.
    fn is_empty_prefix(&self, mirrored: &Path) -> bool {
        self.patterns
            .iter()
            .any(|p| p.permission == Permission::Empty && self.pattern_reaches(p, mirrored))
    }

    /// Whether the path is purely virtual, so its access is answered
    /// directly instead of by the real filesystem: empty paths, injected
    /// paths, and purely virtual ancestors of empty or injected paths
    /// whose real host path does not exist. Such paths are readable
    /// directories (mode 0555) — or injected files — that are never
    /// writable. Async: it stats the real host filesystem.
    async fn virtual_only(&self, mirrored: &Path) -> bool {
        self.is_empty(mirrored)
            || self.is_inject(mirrored).is_some()
            || (self.is_empty_prefix(mirrored) || self.is_inject_prefix(mirrored))
                && tokio_fs::symlink_metadata(self.redirect(mirrored))
                    .await
                    .is_err()
    }

    /// The **real host path** the given **mirrored path** resolves to:
    /// the mirrored path itself — unless a redirect permission remaps it.
    /// The **last** pattern
    /// naming the path decides (as everywhere else); when no pattern names
    /// the path itself, the nearest *directly matched* mirrored ancestor
    /// does: a redirected directory shows its whole subtree, so everything
    /// below it is remapped onto the source plus the remaining path
    /// components. Redirects only ever map literal paths, so the remap is a
    /// simple prefix replacement.
    fn redirect(&self, mirrored: &Path) -> PathBuf {
        let direct = |p: &Path| self.patterns.iter().rev().find(|mp| mp.names(p));
        // The path itself: the last matching pattern says whether (and
        // where) it is redirected.
        if let Some(p) = direct(mirrored) {
            if let Some(source) = p.permission.redirect_source() {
                return source.to_path_buf();
            }
            return mirrored.to_path_buf();
        }
        // Otherwise the nearest directly matched mirrored ancestor decides
        // (the mirror is recursive, so its redirect extends to everything
        // below it). Non-mirrored ancestors are skipped, exactly like in
        // `permission_of`.
        for ancestor in mirrored.ancestors().skip(1) {
            if let Some(p) = direct(ancestor)
                && p.permission.is_mirrored()
            {
                if let Some(source) = p.permission.redirect_source()
                    && let Ok(rest) = mirrored.strip_prefix(ancestor)
                {
                    return source.join(rest);
                }
                return mirrored.to_path_buf();
            }
        }
        mirrored.to_path_buf()
    }

    /// Whether a mirrored path matches one of the patterns directly (as a file,
    /// symlink, or a directory named by the pattern itself), with the
    /// **last** matching pattern mirroring it. Empty paths and everything
    /// below them take precedence over the mirror.
    fn matches(&self, mirrored: &Path) -> bool {
        matches!(self.effective(mirrored), Some(p) if p.is_mirrored())
    }

    /// The spec-level permission that governs **writing** to the mirrored path
    /// (modifying its content or metadata, creating or deleting it): the
    /// last pattern naming the path itself decides, or — when no pattern
    /// names it directly — the permission of the *nearest* mirrored
    /// ancestor (an exactly-named or `**`-covered directory is a recursive
    /// mirror, so its permission governs everything below it). Empty paths
    /// and everything below them, injected paths and everything below them,
    /// and hidden paths are never writable.
    ///
    /// The result is only the *spec* side: the real host filesystem may
    /// still deny the operation (the server acts with the real host
    /// credentials, so the underlying file or directory permissions apply).
    fn write_permission(&self, mirrored: &Path) -> Option<&Permission> {
        match self.effective(mirrored) {
            Some(p) if p.is_mirrored() => Some(p),
            _ => None,
        }
    }

    /// Whether writes to the mirrored path are allowed: the spec must say `rw`.
    /// (Whether the *real* file or directory actually allows it is decided
    /// by the host filesystem when the operation is performed.)
    fn writable(&self, mirrored: &Path) -> bool {
        self.write_permission(mirrored)
            .is_some_and(|p| p.is_writable())
    }

    /// The permission of the **last** pattern that names the path itself
    /// (exactly, or via a `**` that covers it), or `None` when no pattern
    /// names it. Borrowed from the compiled pattern list: this runs on
    /// every operation (often several times per path), and a clone would
    /// copy an `Inject` permission's whole content each time.
    fn permission_of(&self, mirrored: &Path) -> Option<&Permission> {
        // `*` must not cross directory separators, like in a shell.
        self.patterns
            .iter()
            .rev()
            .find(|p| p.names(mirrored))
            .map(|p| &p.permission)
    }

    /// Whether the path is hidden because a pattern hides it directly, or
    /// a hidden pattern names one of its strict ancestors (a hidden
    /// directory hides its whole subtree).
    fn hidden(&self, mirrored: &Path) -> bool {
        self.patterns.iter().any(|p| {
            p.permission == Permission::Hide
                && (p.names(mirrored) || matches!(p.pattern.walk(mirrored), Walk::Ancestor))
        })
    }

    /// Whether the mirrored path exists at all: it either is mirrored
    /// by the last matching pattern itself, is empty (an empty dir or
    /// empty file), is an ancestor of something that is (so the tree under
    /// `/host` stays navigable down to the matched leaves), or is an
    /// ancestor leading to an empty path — and nothing hides it directly
    /// or via an ancestor.
    fn exists(&self, mirrored: &Path) -> bool {
        if self.under_empty(mirrored) || self.under_inject(mirrored) || self.hidden(mirrored) {
            return false;
        }
        if self.is_empty(mirrored) {
            return true;
        }
        if self.is_inject(mirrored).is_some() {
            return true;
        }
        self.matches(mirrored) || self.dir_prefix(mirrored) || self.is_empty_prefix(mirrored)
    }

    /// Whether some **mirrored** pattern could still match something
    /// *strictly below* the given mirrored path — i.e. the path acts as a
    /// (possibly virtual) directory of the mirror, leading to matches
    /// deeper down. Denied patterns never make a path navigable.
    fn dir_prefix(&self, mirrored: &Path) -> bool {
        if mirrored == Path::new("/") {
            return self.patterns.iter().any(|p| {
                matches!(
                    p.permission,
                    Permission::Ro | Permission::Rw | Permission::Empty | Permission::Inject { .. }
                )
            });
        }
        self.patterns.iter().any(|p| match p.permission {
            // An injected pattern is an exact file: only paths
            // *strictly above* it (CouldReach) are navigable as its
            // virtual parent directories — a path below the injected
            // file (Ancestor) exists just as little as the file's
            // non-existent children.
            Permission::Inject { .. } => p.pattern.walk(mirrored) == Walk::CouldReach,
            _ => p.permission.is_mirrored() && self.pattern_reaches(p, mirrored),
        }) || self.is_empty_prefix(mirrored)
    }

    /// Whether the pattern could make the path visible as a directory
    /// leading to content: it has components left after the path is
    /// consumed, or the path hit (or ends at) a `**`, or the pattern names
    /// a strict ancestor of the path — an exactly-named directory is
    /// mirrored recursively, so everything below it is visible.
    fn pattern_reaches(&self, p: &MirrorPattern, mirrored: &Path) -> bool {
        matches!(
            p.pattern.walk(mirrored),
            Walk::CouldReach | Walk::StarStar | Walk::Ancestor
        )
    }

    /// Whether some `hide` or `ro` pattern might apply to a path strictly
    /// below the given mirrored directory — without being uniformly
    /// shadowed there by a writable pattern that covers the whole subtree.
    ///
    /// This is the rename-restriction check: a directory rename carries
    /// every child from one pattern context to another, so a `hide` or
    /// `ro` rule that might govern a child must block the move — moving
    /// the directory out of such a rule's reach would expose (or make
    /// writable) content that the spec hides or keeps read-only, and
    /// moving *into* such a subtree would plant content that a later
    /// move back out could expose the same way. Checked for both the
    /// source and the destination of a directory rename.
    fn subtree_restricted(&self, dir: &Path) -> bool {
        for (idx, p) in self.patterns.iter().enumerate() {
            if !matches!(p.permission, Permission::Ro | Permission::Hide) {
                continue;
            }
            let Some((walk, depth)) = p.pattern.walk_depth(dir) else {
                continue;
            };
            // How the pattern might govern a strictly-below path:
            //
            // * `StarStar`/`CouldReach`: the pattern matches — or could
            //   match — paths below the directory *directly*, so the
            //   last-match rule applies and only a **later** pattern
            //   naming every possible child can shadow it (`**` covers
            //   the directory and everything below it).
            // * `Exact`: the pattern names the directory itself — a `hide`
            //   hides the whole subtree (never shadowable), an `ro` mirror
            //   is recursive, so its permission reaches every child.
            // * `Ancestor`: the pattern names a strict ancestor — it
            //   governs children only through the hide-ancestor rule
            //   (`hide`, never shadowable) or the nearest-mirrored-
            //   ancestor fallback (`ro`), which a *deeper* mirrored
            //   writable ancestor replaces regardless of list order.
            let shadowed = if matches!(walk, Walk::StarStar | Walk::CouldReach) {
                self.patterns[idx + 1..].iter().any(|q| {
                    q.permission.is_writable() && matches!(q.pattern.walk(dir), Walk::StarStar)
                })
            } else if walk == Walk::Exact {
                // The last pattern naming the directory itself decides
                // the children's fallback permission; a writable one
                // replaces the `ro` (a `hide` there would have hidden
                // the directory, and the rename is rejected before this
                // check even runs).
                self.patterns[idx + 1..]
                    .iter()
                    .rev()
                    .find(|q| q.names(dir))
                    .is_some_and(|q| q.permission.is_writable())
            } else {
                // Walk::Ancestor: any writable mirrored pattern that
                // covers the directory itself (or reaches deeper than
                // this pattern does) is the nearer mirrored ancestor of
                // every child.
                self.patterns.iter().any(|q| {
                    q.permission.is_writable()
                        && q.pattern.walk_depth(dir).is_some_and(|(w, d)| match w {
                            Walk::StarStar | Walk::Exact => true,
                            Walk::Ancestor => d > depth,
                            Walk::CouldReach | Walk::Fail => false,
                        })
                })
            };
            if !shadowed {
                return true;
            }
        }
        false
    }

    /// The attributes of an empty path (or a purely virtual ancestor of
    /// one): a mode-0555 directory, so nothing can be created inside it.
    /// (`ino` is filled in by the callers that know the nodeid.)
    fn empty_dir_attr(&self) -> FileAttr {
        FileAttr {
            ino: 0,
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH.into(),
            mtime: SystemTime::UNIX_EPOCH.into(),
            ctime: SystemTime::UNIX_EPOCH.into(),
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
        }
    }

    /// The attributes of an empty file: the real metadata, but with no
    /// content (the host file is never read).
    fn empty_file_attr(md: &std::fs::Metadata) -> FileAttr {
        let mut attr = attr_from_metadata(md);
        attr.size = 0;
        attr.blocks = 0;
        attr
    }

    /// The attributes of an injected file: a read-only regular file whose
    /// size is the in-memory content's length (the content itself is
    /// served by `read`).
    fn inject_file_attr(&self, content: &[u8]) -> FileAttr {
        FileAttr {
            ino: 0,
            size: content.len() as u64,
            blocks: (content.len() as u64).div_ceil(512),
            atime: SystemTime::UNIX_EPOCH.into(),
            mtime: SystemTime::UNIX_EPOCH.into(),
            ctime: SystemTime::UNIX_EPOCH.into(),
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
        }
    }

    /// Whether the given **host** path can act as a listable directory
    /// without following symlinks: it must really be a directory (a
    /// symlink to a directory is not followed).
    async fn is_host_dir(&self, real: &Path) -> bool {
        tokio_fs::symlink_metadata(real)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
    }

    /// The `lstat`-style attribute of a mirrored path, or ENOENT. Async: it
    /// stats the real host filesystem (`tokio::fs` runs the syscall on
    /// tokio's blocking pool) and must never run on the FUSE event loop.
    async fn attr(&self, mirrored: &Path) -> std::io::Result<FileAttr> {
        // Injected paths take precedence over everything: they are purely
        // virtual files served from memory.
        if let Some(content) = self.is_inject(mirrored) {
            return Ok(self.inject_file_attr(content.as_bytes()));
        }
        // Empty paths take precedence: they appear even when the real host
        // path exists (with different attributes) — as an empty directory
        // when the path is (or would be) a directory, as an empty file
        // when it matches a real file.
        if self.is_empty(mirrored) {
            return match tokio_fs::symlink_metadata(mirrored).await {
                Ok(md) if !md.is_dir() => Ok(Self::empty_file_attr(&md)),
                _ => Ok(self.empty_dir_attr()),
            };
        }
        let real = self.redirect(mirrored);
        match tokio_fs::symlink_metadata(&real).await {
            Ok(md) => Ok(attr_from_metadata(&md)),
            // A purely virtual ancestor of an empty path has no real
            // counterpart; present it as a directory. The same holds for
            // purely virtual ancestors of injected files: `exists`/`readdir`
            // advertise them (they lead to the injected file), so their
            // attributes must not fail — a single failing entry attribute
            // turns the whole `readdir` reply into an error (which glibc's
            // `readdir` then silently reports as end-of-directory: an empty
            // listing despite the entries being lookable).
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && (self.is_empty_prefix(mirrored) || self.is_inject_prefix(mirrored)) =>
            {
                Ok(self.empty_dir_attr())
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the mirrored path is a listable directory: a real one (a
    /// host symlink to a directory is not followed), an empty
    /// path, or a purely virtual ancestor of an empty path. Async: it
    /// stats the real host filesystem (`tokio::fs`).
    async fn is_listable_dir(&self, mirrored: &Path) -> bool {
        if self.is_empty(mirrored)
            || self.is_empty_prefix(mirrored)
            || self.is_inject_prefix(mirrored)
        {
            return true;
        }
        self.is_host_dir(&self.redirect(mirrored)).await
    }

    /// The visible entries of a mirrored directory, sorted by name: every
    /// real entry that matches a pattern (directly or as an ancestor of a
    /// match) — and, when the directory is itself matched by a pattern, all
    /// of its real entries. Everything below an empty path is shadowed by
    /// its precedence; empty paths that live directly under the directory
    /// are always shown. Symlinks are never followed: a host symlink
    /// standing for the directory is not listed through. Async: it reads
    /// and stats the real host directory (`tokio::fs`).
    async fn dir_entries(
        &self,
        mirrored: &Path,
    ) -> Vec<(std::ffi::OsString, std::io::Result<FileAttr>)> {
        // A directory named by a mirrored pattern itself is a recursive
        // mirror: all of its real entries are visible, not only pattern
        // matches (still minus hidden ones).
        let unfiltered = self.matches(mirrored);
        let mut names: Vec<std::ffi::OsString> = if self.is_host_dir(&self.redirect(mirrored)).await
        {
            match tokio_fs::read_dir(self.redirect(mirrored)).await {
                Ok(mut entries) => {
                    let mut names = Vec::new();
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let name = entry.file_name();
                        // Fail closed for names that can never match a
                        // pattern: they are not creatable through the
                        // mirror, so they must not be listed either —
                        // otherwise readdir would advertise entries lookup
                        // can never resolve (undeletable "ghost" entries).
                        if name.to_str().is_none() {
                            continue;
                        }
                        let child = mirrored.join(&name);
                        // Empty-path precedence: nothing below an empty path is
                        // visible, not even a mirror match. Denied entries (and
                        // everything below a hidden directory) are hidden even
                        // inside a recursively mirrored directory.
                        if self.under_empty(&child) || self.hidden(&child) {
                            continue;
                        }
                        if unfiltered || self.exists(&child) {
                            names.push(name);
                        }
                    }
                    names
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        // Empty-path entries living directly under this directory (also
        // when the real directory itself cannot be listed): every `empty`
        // pattern with a purely literal next component contributes one.
        for p in &self.patterns {
            if p.permission != Permission::Empty {
                continue;
            }
            if let Some(name) = p.pattern.next_literal(mirrored) {
                let child = mirrored.join(&name);
                if !names.iter().any(|n| n.as_os_str() == OsStr::new(&name)) && self.exists(&child)
                {
                    names.push(OsString::from(name));
                }
            }
        }
        // Injected files living directly under this directory (also when
        // the real directory itself cannot be listed): every `inject`
        // pattern with a purely literal next component contributes one.
        for p in &self.patterns {
            if !matches!(p.permission, Permission::Inject { .. }) {
                continue;
            }
            if let Some(name) = p.pattern.next_literal(mirrored) {
                let child = mirrored.join(&name);
                if !names.iter().any(|n| n.as_os_str() == OsStr::new(&name)) && self.exists(&child)
                {
                    names.push(OsString::from(name));
                }
            }
        }
        // Redirected paths living directly under this directory (also when
        // the real directory itself cannot be listed): every `redirect`
        // pattern with a purely literal next component contributes one.
        // Without this a redirected file inside, say, a redirected
        // directory would be lookable (`stat`/`open` resolve it through
        // its redirect) but never listed — readdir would advertise a
        // directory without its visible entries.
        for p in &self.patterns {
            if p.permission.redirect_source().is_none() {
                continue;
            }
            if let Some(name) = p.pattern.next_literal(mirrored) {
                let child = mirrored.join(&name);
                // Only listed when the redirect target really exists on
                // the host — otherwise the entry would advertise a
                // lookup that fails (an undeletable "ghost").
                if !names.iter().any(|n| n.as_os_str() == OsStr::new(&name))
                    && self.exists(&child)
                    && tokio_fs::symlink_metadata(
                        p.permission.redirect_source().expect("checked above"),
                    )
                    .await
                    .is_ok()
                {
                    names.push(OsString::from(name));
                }
            }
        }
        names.sort();
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let child = mirrored.join(&name);
            entries.push((name, self.attr(&child).await));
        }
        entries
    }
}

fn compile(pattern: &str) -> Pattern {
    Pattern::new(pattern).unwrap_or_else(|e| die(&format!("Invalid hostfs pattern: {e}")))
}

fn attr_from_metadata(md: &std::fs::Metadata) -> FileAttr {
    let kind = md.file_type();
    let kind = if kind.is_dir() {
        FileType::Directory
    } else if kind.is_symlink() {
        FileType::Symlink
    } else if kind.is_char_device() {
        FileType::CharDevice
    } else if kind.is_block_device() {
        FileType::BlockDevice
    } else if kind.is_fifo() {
        FileType::NamedPipe
    } else if kind.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    };
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: md.size(),
        blocks: md.blocks(),
        atime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.atime().max(0) as u64, md.atime_nsec().max(0) as u32))
        .into(),
        mtime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.mtime().max(0) as u64, md.mtime_nsec().max(0) as u32))
        .into(),
        ctime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.ctime().max(0) as u64, md.ctime_nsec().max(0) as u32))
        .into(),
        kind,
        perm: (md.mode() & 0o7777) as u16,
        nlink: md.nlink() as u32,
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev() as u32,
        blksize: md.blksize() as u32,
    }
}

fn root_attr(uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH.into(),
        mtime: SystemTime::UNIX_EPOCH.into(),
        ctime: SystemTime::UNIX_EPOCH.into(),
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
    }
}

/// The bridge passes absolute paths ("/etc/passwd") and is lenient about a
/// missing leading slash.
fn is_root(path: &OsStr) -> bool {
    path == Path::new("/") || path.is_empty()
}

impl Filesystem for HostFs {
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        perf::fuse_op!("init");
        // Advertise a large max write (the kernel clamps it to its own
        // limit): with a tiny value the kernel splits every write into
        // small FUSE requests, multiplying the per-request overhead.
        Ok(ReplyInit {
            max_write: NonZeroU32::new(1024 * 1024).unwrap(),
        })
    }

    async fn destroy(&self, _req: Request) {
        perf::fuse_op!("destroy");
    }

    /// A forgotten nodeid loses its mapping (the kernel is done with the
    /// dentry); a nodeid with open handles keeps its last path as a zombie.
    async fn forget(&self, _req: Request, inode: Inode, nlookup: u64) {
        perf::fuse_op!("forget");
        let path = self.inodes.write().await.forget(inode);
        fuselog::event!(
            "INODE forget inode={inode} nlookup={nlookup} path={}",
            path.map(|p| fuselog::path_string(p.as_os_str()))
                .unwrap_or_else(|| "<gone>".into())
        );
    }

    async fn batch_forget(&self, _req: Request, inodes: &[Inode]) {
        perf::fuse_op!("batch_forget");
        let mut map = self.inodes.write().await;
        for &inode in inodes {
            let path = map.forget(inode);
            fuselog::event!(
                "INODE batch-forget inode={inode} path={}",
                path.map(|p| fuselog::path_string(p.as_os_str()))
                    .unwrap_or_else(|| "<gone>".into())
            );
        }
    }

    async fn lookup(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<ReplyEntry> {
        perf::fuse_op!("lookup");
        // The nodeid resolves to the parent's mirrored path; "/" means the
        // root directory itself.
        let parent_path = match self.resolve(parent).await {
            Ok(p) => p,
            Err(e) => {
                fuselog::event!(
                    "INODE lookup no-parent inode={parent} name={}",
                    fuselog::path_string(name)
                );
                return Err(e.into());
            }
        };
        let mirrored = parent_path.join(name);
        if self.exists(&mirrored) {
            match self.attr(&mirrored).await {
                Ok(mut attr) => {
                    let inode = self.inodes.write().await.get_or_insert(&mirrored, parent);
                    attr.ino = inode;
                    return Ok(ReplyEntry {
                        ttl: TTL,
                        attr,
                        generation: 0,
                    });
                }
                Err(e) => {
                    log_op_err("lookup", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // The kernel dentry is stale: drop the mapping so the
                        // next lookup re-maps the path (a zombie stays while
                        // open handles remain).
                        self.inodes.write().await.release_path(&mirrored);
                    }
                    return Err(e.into());
                }
            }
        }
        log_op_err(
            "lookup",
            &mirrored,
            None,
            &std::io::Error::from_raw_os_error(libc::ENOENT),
        )
        .await;
        self.inodes.write().await.release_path(&mirrored);
        Err(libc::ENOENT.into())
    }

    async fn getattr(
        &self,
        _req: Request,
        inode: Inode,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        perf::fuse_op!("getattr");
        let mirrored = match self.resolve(inode).await {
            Ok(p) => p,
            Err(e) => {
                fuselog::event(&format!("INODE getattr no-path inode={inode}"));
                return Err(e.into());
            }
        };
        if is_root(mirrored.as_os_str()) {
            let mut attr = root_attr(self.uid, self.gid);
            attr.ino = inode;
            return Ok(ReplyAttr { ttl: TTL, attr });
        }
        if self.exists(&mirrored) {
            match self.attr(&mirrored).await {
                Ok(mut attr) => {
                    attr.ino = inode;
                    return Ok(ReplyAttr { ttl: TTL, attr });
                }
                Err(e) => {
                    log_op_err("getattr", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                    return Err(e.into());
                }
            }
        }
        log_op_err(
            "getattr",
            &mirrored,
            None,
            &std::io::Error::from_raw_os_error(libc::ENOENT),
        )
        .await;
        Err(libc::ENOENT.into())
    }

    async fn readlink(&self, _req: Request, inode: Inode) -> Result<ReplyData> {
        perf::fuse_op!("readlink");
        let mirrored = self.resolve(inode).await?;
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        let target = tokio_fs::read_link(self.redirect(&mirrored)).await?;
        Ok(ReplyData::from(Bytes::copy_from_slice(
            target.as_os_str().as_encoded_bytes(),
        )))
    }

    async fn open(&self, _req: Request, inode: Inode, flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("open");
        let mirrored = self.resolve(inode).await?;
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not).
        if !self.exists(&mirrored) {
            log_op_err(
                "open",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // An injected path is a purely virtual file: served from memory,
        // never writable, the host is not consulted at all.
        if let Some(_content) = self.is_inject(&mirrored) {
            let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
            if write_flags {
                log_op_err(
                    "open",
                    &mirrored,
                    None,
                    &std::io::Error::from_raw_os_error(libc::EACCES),
                )
                .await;
                return Err(libc::EACCES.into());
            }
            self.inodes.write().await.open_handle(inode);
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not), and
        // symlinks are never followed: a host symlink cannot be opened
        // through the mirror (its target may not be mirrored at all).
        let md = match tokio_fs::symlink_metadata(self.redirect(&mirrored)).await {
            Ok(md) => md,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                // A purely virtual directory (ancestor of an empty or
                // injected path with no real counterpart) is not openable,
                // exactly like a real one that `open` refuses: report it as
                // a directory rather than as missing (the kernel only asks
                // to open directories it has already resolved).
                if e.kind() == std::io::ErrorKind::NotFound
                    && (self.is_empty_prefix(&mirrored) || self.is_inject_prefix(&mirrored))
                {
                    return Err(libc::EISDIR.into());
                }
                return Err(libc::ENOENT.into());
            }
        };
        if md.file_type().is_symlink() {
            log_op_err(
                "open",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::ELOOP),
            )
            .await;
            return Err(libc::ELOOP.into());
        }
        if md.is_dir() {
            log_op_err(
                "open",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EISDIR),
            )
            .await;
            return Err(libc::EISDIR.into());
        }
        let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
        if write_flags && !self.writable(&mirrored) {
            // `ro` paths (and anything below an empty or hidden pattern) are
            // never writable; the real file permissions are checked by the
            // host filesystem on the actual write.
            log_op_err(
                "open",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // The kernel passes O_TRUNC through to the server: the server must
        // do the truncation itself. Write paths (rustc, cargo, …) always
        // open their outputs with O_TRUNC, so ignoring it would leave the
        // tail of the old content in place behind the newly written data.
        // The truncation happens in the open below (the file is opened for
        // real and kept for the handle's lifetime).
        let append = flags & libc::O_APPEND as u32 != 0;
        let mut opts = tokio_fs::OpenOptions::new();
        if !write_flags || flags & libc::O_RDWR as u32 != 0 {
            opts.read(true);
        }
        if write_flags {
            opts.write(true);
        }
        if append {
            opts.append(true);
        }
        if write_flags && flags & libc::O_TRUNC as u32 != 0 {
            opts.truncate(true);
        }
        opts.custom_flags(libc::O_NOFOLLOW);
        let file = match opts.open(self.redirect(&mirrored)).await {
            Ok(f) => f,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        // Stateful IO: the opened host file is reused for every read/write
        // on this handle (released with it in `release`).
        self.inodes.write().await.open_handle(inode);
        let writable = self.writable(&mirrored);
        let fh = self.insert_handle(file, mirrored, append, writable);
        Ok(ReplyOpen { fh, flags: 0 })
    }

    async fn read(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        perf::fuse_op!("read");
        // Stateful IO first: a real handle can only come from `open`/`create`,
        // which already established that the path is mirrored (exists), not
        // injected and not empty — the per-request spec checks below are
        // skipped entirely on this path (they re-match every pattern).
        if fh != 0
            && let Some(handle) = self.handle_of(fh)
        {
            // The handle caches the mirrored path from open time; the path is
            // only used for error logging here, so the inode map is never
            // consulted on this fast path.
            let mut file = handle.file.lock().await;
            file.seek(SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; size as usize];
            let n = match file.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    log_op_err(
                        "read-io",
                        &handle.path,
                        Some(&self.redirect(&handle.path)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
            buf.truncate(n);
            return Ok(ReplyData::from(Bytes::from(buf)));
        }
        let mirrored = match self.resolve(inode).await {
            Ok(p) => p,
            Err(e) => {
                log_op_err(
                    "read",
                    Path::new("<none>"),
                    None,
                    &std::io::Error::from_raw_os_error(libc::ENOENT),
                )
                .await;
                return Err(e.into());
            }
        };
        if !self.exists(&mirrored) {
            log_op_err(
                "read",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // An injected path is served from memory: slice the content at
        // the requested offset (nothing is read from the host).
        if let Some(content) = self.is_inject(&mirrored) {
            let bytes = content.as_bytes();
            let offset = offset.min(bytes.len() as u64) as usize;
            let end = (offset + size as usize).min(bytes.len());
            return Ok(ReplyData::from(Bytes::copy_from_slice(&bytes[offset..end])));
        }
        // An empty path has no content: an empty file reads as empty (the
        // host file is never opened).
        if self.is_empty(&mirrored) {
            return Ok(ReplyData::from(Bytes::new()));
        }
        // Stateless IO fallback: reopen the host file — never following
        // symlinks (a host symlink is visible only as a link, and its
        // target may not be mirrored at all).
        let mut file = match tokio_fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.redirect(&mirrored))
            .await
        {
            Ok(f) => f,
            Err(e) => {
                log_op_err("read", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        file.seek(SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; size as usize];
        let n = match file.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                log_op_err("read-io", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        buf.truncate(n);
        Ok(ReplyData::from(Bytes::from(buf)))
    }

    async fn write(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        perf::fuse_op!("write");
        // The handle is looked up before the path: a real handle caches the
        // mirrored path from open time, so the stateful fast path never
        // consults the inode map.
        let handle = if fh != 0 { self.handle_of(fh) } else { None };
        let mirrored = match &handle {
            // Only used for logging on this path; the IO goes through the
            // cached file descriptor.
            Some(h) => h.path.clone(),
            None => match self.resolve(inode).await {
                Ok(p) => p,
                Err(e) => {
                    log_op_err(
                        "write",
                        Path::new("<none>"),
                        None,
                        &std::io::Error::from_raw_os_error(libc::ENOENT),
                    )
                    .await;
                    return Err(e.into());
                }
            },
        };
        // A real handle caches the spec verdict (`writable`) from open time;
        // the exists/inject/empty checks are skipped entirely on this path
        // (they re-match every pattern per request). Injected paths are
        // never writable and never get a real handle, so only the writable
        // verdict matters here.
        let writable = match &handle {
            Some(h) => h.writable,
            None => self.writable(&mirrored),
        };
        if handle.is_none() && !self.exists(&mirrored) {
            log_op_err(
                "write",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !writable {
            // The spec must say `rw`; the real file permissions are
            // enforced by the host filesystem on the open below.
            log_op_err(
                "write",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Stateful IO: the handle keeps the host file open — reuse it instead
        // of reopening per request. An unknown `fh` falls back to the
        // stateless reopen below.
        let append = flags & libc::O_APPEND as u32 != 0;
        if let Some(handle) = handle {
            let mut file = handle.file.lock().await;
            if !handle.append {
                file.seek(SeekFrom::Start(offset)).await?;
            }
            let n = match file.write(data).await {
                Ok(n) => n,
                Err(e) => {
                    log_op_err("write-io", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                    return Err(e.into());
                }
            };
            drop(file);
            crate::audit::record(
                "hostfs",
                "write",
                Some(&mirrored.to_string_lossy()),
                Some("ok"),
                Some(format!("{} bytes at offset {}", n, offset)),
            )
            .await;
            return Ok(ReplyWrite { written: n as u32 });
        }
        // Stateless IO fallback: reopen the host file — never following
        // symlinks (a host symlink is never written through; its target
        // may not be mirrored at all).
        let mut file = match tokio_fs::OpenOptions::new()
            .write(true)
            .append(append)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.redirect(&mirrored))
            .await
        {
            Ok(f) => f,
            Err(e) => {
                log_op_err("write", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        if !append {
            file.seek(SeekFrom::Start(offset)).await?;
        }
        let n = match file.write(data).await {
            Ok(n) => n,
            Err(e) => {
                log_op_err("write-io", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        crate::audit::record(
            "hostfs",
            "write",
            Some(&mirrored.to_string_lossy()),
            Some("ok"),
            Some(format!("{} bytes at offset {}", n, offset)),
        )
        .await;
        Ok(ReplyWrite { written: n as u32 })
    }
    async fn statfs(&self, _req: Request, inode: Inode) -> Result<ReplyStatFs> {
        perf::fuse_op!("statfs");
        // Report the real filesystem holding the mirrored path (or "/" for
        // the root), so tools like `df` behave sensibly. The path is opened
        // with `O_NOFOLLOW` and `fstatvfs` runs on the descriptor: symlinks
        // are never followed to a filesystem outside the mirror.
        let mirrored = self.resolve(inode).await?;
        // An injected path has no host counterpart: report a minimal,
        // self-consistent statfs instead of opening anything. The same
        // holds for a purely virtual ancestor of an injected (or empty)
        // path with no real counterpart: it is a virtual directory, and
        // there is nothing to open on the host.
        if self.is_inject(&mirrored).is_some()
            || (self.is_empty_prefix(&mirrored) || self.is_inject_prefix(&mirrored))
                && tokio_fs::symlink_metadata(self.redirect(&mirrored))
                    .await
                    .is_err()
        {
            return Ok(ReplyStatFs {
                blocks: 1,
                bfree: 0,
                bavail: 0,
                files: 1,
                ffree: 0,
                bsize: 512,
                namelen: 255,
                frsize: 512,
            });
        }
        let mirrored = if is_root(mirrored.as_os_str()) {
            PathBuf::from("/")
        } else {
            self.redirect(&mirrored)
        };
        let cpath =
            CString::new(mirrored.as_os_str().as_encoded_bytes()).map_err(|_| libc::ENOENT)?;
        // errno is per-thread: capture the error on the blocking thread.
        blocking(move || {
            // O_PATH works on any file type (including directories) and
            // O_NOFOLLOW keeps symlinked paths from being followed.
            let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstatvfs(fd, &mut vfs) };
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            if rc != 0 { Err(err) } else { Ok(vfs) }
        })
        .await
        .map(|vfs| {
            Ok(ReplyStatFs {
                blocks: vfs.f_blocks,
                bfree: vfs.f_bfree,
                bavail: vfs.f_bavail,
                files: vfs.f_files,
                ffree: vfs.f_ffree,
                bsize: vfs.f_bsize as u32,
                namelen: vfs.f_namemax as u32,
                frsize: vfs.f_frsize as u32,
            })
        })?
    }

    async fn opendir(&self, _req: Request, inode: Inode, _flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("opendir");
        let mirrored = self.resolve(inode).await?;
        if !self.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored).await
        {
            return Err(libc::ENOENT.into());
        }
        self.inodes.write().await.open_handle(inode);
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn readdir<'a>(
        &'a self,
        _req: Request,
        parent: Inode,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl futures_util::Stream<Item = Result<DirectoryEntry>> + Send + 'a>>
    {
        perf::fuse_op!("readdir");
        let mirrored = self.resolve(parent).await?;
        if !self.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored).await
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .await
            .into_iter()
            .skip(offset.max(0) as usize)
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid.
        let mut map = self.inodes.write().await;
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(i, (name, attr))| {
                let inode = if name == *OsStr::new(".") {
                    parent
                } else if name == *OsStr::new("..") {
                    map.parent_of(parent).unwrap_or(inodes::ROOT_INODE)
                } else {
                    map.get_or_insert(&mirrored.join(&name), parent)
                };
                Ok(DirectoryEntry {
                    inode,
                    kind: attr.map(|a| a.kind).unwrap_or(FileType::RegularFile),
                    name,
                    offset: offset.max(0) + i as i64 + 1,
                })
            })
            .collect();
        Ok(ReplyDirectory {
            entries: stream::iter(entries),
        })
    }

    async fn readdirplus<'a>(
        &'a self,
        _req: Request,
        parent: Inode,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<
        ReplyDirectoryPlus<
            impl futures_util::Stream<Item = Result<DirectoryEntryPlus>> + Send + 'a,
        >,
    > {
        perf::fuse_op!("readdirplus");
        let mirrored = self.resolve(parent).await?;
        if !self.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored).await
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .await
            .into_iter()
            .skip(offset as usize)
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid — and carries
        // its attributes with the nodeid filled in.
        let mut map = self.inodes.write().await;
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(i, (name, attr))| {
                let inode = if name == *OsStr::new(".") {
                    parent
                } else if name == *OsStr::new("..") {
                    map.parent_of(parent).unwrap_or(inodes::ROOT_INODE)
                } else {
                    map.get_or_insert(&mirrored.join(&name), parent)
                };
                let mut attr = attr;
                if let Ok(a) = attr.as_mut() {
                    a.ino = inode;
                }
                Ok(DirectoryEntryPlus {
                    inode,
                    generation: 0,
                    kind: attr
                        .as_ref()
                        .map(|a| a.kind)
                        .unwrap_or(FileType::RegularFile),
                    name,
                    offset: (offset + i as u64 + 1) as i64,
                    attr: attr?,
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                })
            })
            .collect();
        Ok(ReplyDirectoryPlus {
            entries: stream::iter(entries),
        })
    }

    async fn access(&self, _req: Request, inode: Inode, mask: u32) -> Result<()> {
        perf::fuse_op!("access");
        let mirrored = self.resolve(inode).await?;
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // Empty paths (and purely virtual ancestors) are unwritable by
        // definition; answer directly instead of asking the real filesystem.
        // Injected paths are virtual, too: readable, never writable. The
        // same holds for purely virtual ancestors of injected files: the
        // kernel consults `access` for `chdir` (MAY_CHDIR), so an
        // unanswered ENOENT here would make a directory that `ls` lists
        // and `stat` resolves impossible to `cd` into.
        if self.virtual_only(&mirrored).await {
            if mask & libc::W_OK as u32 != 0 {
                return Err(libc::EACCES.into());
            }
            return Ok(());
        }
        // W_OK is answered by the spec: only `rw` paths may be written (the
        // real file permissions are checked when a write is attempted).
        let non_write = mask & !(libc::W_OK as u32);
        if mask & libc::W_OK as u32 != 0 && !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        // The rest (R_OK, X_OK) is decided by the real filesystem, with the
        // server's real (host) credentials.
        if non_write == 0 {
            return Ok(());
        }
        let real = self.redirect(&mirrored);
        let cpath = CString::new(real.as_os_str().as_encoded_bytes()).map_err(|_| libc::ENOENT)?;
        // errno is per-thread: capture the error on the blocking thread.
        // `faccessat` with `AT_SYMLINK_NOFOLLOW` — never follow symlinks
        // when deciding access on the real host filesystem.
        blocking(move || {
            if unsafe {
                libc::faccessat(
                    libc::AT_FDCWD,
                    cpath.as_ptr(),
                    non_write as libc::c_int,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(fuse3::Errno::from)?;
        Ok(())
    }

    async fn setattr(
        &self,
        _req: Request,
        inode: Inode,
        _fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        perf::fuse_op!("setattr");
        let mirrored = self.resolve(inode).await?;
        if self.is_empty(&mirrored) {
            // Empty paths are virtual: nothing to change.
            return Err(libc::EACCES.into());
        }
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        let real = self.redirect(&mirrored);
        if let Some(size) = set_attr.size {
            // Never follow symlinks: a host symlink is not truncated
            // through (its target may not be mirrored at all).
            let f = tokio_fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&real)
                .await?;
            f.set_len(size).await?;
        }
        if let Some(mode) = set_attr.mode {
            let perms = std::fs::Permissions::from_mode(mode);
            tokio_fs::set_permissions(&real, perms).await?;
        }
        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            let cpath = cstring_of(&real)?;
            let uid = set_attr.uid.unwrap_or(u32::MAX);
            let gid = set_attr.gid.unwrap_or(u32::MAX);
            // errno is per-thread: capture the error on the blocking thread.
            blocking(move || {
                if unsafe { libc::lchown(cpath.as_ptr(), uid, gid) } != 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })
            .await?;
        }
        if set_attr.atime.is_some() || set_attr.mtime.is_some() {
            let times = [
                ts_to_timespec(set_attr.atime),
                ts_to_timespec(set_attr.mtime),
            ];
            let cpath = cstring_of(&real)?;
            // errno is per-thread: capture the error on the blocking thread.
            blocking(move || {
                if unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        cpath.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            })
            .await?;
        }
        let mut attr = self.attr(&mirrored).await?;
        attr.ino = inode;
        Ok(ReplyAttr { ttl: TTL, attr })
    }

    async fn mkdir(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        _umask: u32,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("mkdir");
        let parent_path = self.resolve(parent).await?;
        let mirrored = parent_path.join(name);
        if !self.writable(&mirrored) {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only a *real* entry at the target means EEXIST; a path merely
        // matched by a wildcard pattern may not exist yet.
        if tokio_fs::symlink_metadata(self.redirect(&mirrored))
            .await
            .is_ok()
        {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EEXIST),
            )
            .await;
            return Err(libc::EEXIST.into());
        }
        // errno is per-thread: capture the error on the blocking thread.
        let cpath = cstring_of(&self.redirect(&mirrored))?;
        if let Err(e) = blocking(move || {
            if unsafe { libc::mkdir(cpath.as_ptr(), (mode & 0o7777) as libc::mode_t) } != 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
        .await
        {
            log_op_err("mkdir", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
            return Err(fuse3::Errno::from(e));
        }
        log_op_ok("mkdir", &mirrored, &self.redirect(&mirrored)).await;
        let inode = self.inodes.write().await.get_or_insert(&mirrored, parent);
        let mut attr = self.attr(&mirrored).await?;
        attr.ino = inode;
        Ok(ReplyEntry {
            ttl: TTL,
            attr,
            generation: 0,
        })
    }

    async fn unlink(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("unlink");
        let parent_path = self.resolve(parent).await?;
        let mirrored = parent_path.join(name);
        if self.is_empty(&mirrored) {
            // Empty paths are virtual mount points; they cannot be removed.
            return Err(libc::EACCES.into());
        }
        if !self.exists(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if let Err(e) = tokio_fs::remove_file(self.redirect(&mirrored)).await {
            log_op_err("unlink", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes.write().await.release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::EISDIR) {
                // Unlinking a directory: the kernel keeps the dentry, so the
                // name must stay resolvable.
                self.inodes.write().await.get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("unlink", &mirrored, &self.redirect(&mirrored)).await;
        self.inodes.write().await.release_path(&mirrored);
        Ok(())
    }
    async fn rmdir(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("rmdir");
        let parent_path = self.resolve(parent).await?;
        let mirrored = parent_path.join(name);
        if self.is_empty(&mirrored) {
            return Err(libc::EACCES.into());
        }
        if !self.exists(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if let Err(e) = tokio_fs::remove_dir(self.redirect(&mirrored)).await {
            log_op_err("rmdir", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes.write().await.release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                // Rmdir of a non-directory: the kernel keeps the dentry, so
                // the name must stay resolvable.
                self.inodes.write().await.get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("rmdir", &mirrored, &self.redirect(&mirrored)).await;
        self.inodes.write().await.release_path(&mirrored);
        Ok(())
    }

    async fn rename(
        &self,
        _req: Request,
        origin_parent: Inode,
        origin_name: &OsStr,
        parent: Inode,
        name: &OsStr,
    ) -> Result<()> {
        perf::fuse_op!("rename");
        let origin_parent_path = self.resolve(origin_parent).await?;
        let new_parent_path = self.resolve(parent).await?;
        let old = origin_parent_path.join(origin_name);
        let new = new_parent_path.join(name);
        if self.is_empty(&old) || self.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.exists(&old) {
            log_op_err(
                "rename",
                &old,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&old) || !self.writable(&new) {
            log_op_err(
                "rename",
                &old,
                Some(&self.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // A *directory* rename carries every child from one pattern
        // context to another: a `hide` or `ro` rule that might apply to a
        // child of the source (or of the destination) must block the
        // move. Moving the directory out of such a rule's reach would
        // expose — or make writable — content the spec hides or keeps
        // read-only (e.g. `/project/src` is `rw` but
        // `/project/src/**/*.bin` is `hide`); moving another directory
        // *into* such a subtree is denied as well, so content cannot be
        // planted there and carried back out with the same effect.
        let dir_rename = self.is_host_dir(&self.redirect(&old)).await
            || self.is_host_dir(&self.redirect(&new)).await;
        if dir_rename && (self.subtree_restricted(&old) || self.subtree_restricted(&new)) {
            log_op_err(
                "rename",
                &old,
                Some(&self.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if let Err(e) = tokio_fs::rename(self.redirect(&old), self.redirect(&new)).await {
            log_op_err("rename", &old, Some(&self.redirect(&new)), &e).await;
            return Err(e.into());
        }
        log_op_ok("rename", &old, &self.redirect(&new)).await;

        // The kernel moves the dentry on rename, re-hashing `old` as `new`
        // *keeping the source's nodeid*. Re-point the new path at the source
        // nodeid — dropping the overwritten target's mapping, which the
        // kernel is about to forget — so every operation arriving on the
        // moved dentry still resolves (see `FINDINGS.md`).
        let mut map = self.inodes.write().await;
        let source_inode = map.inode_of(&old);
        let old_target = map.inode_of(&new);
        fuselog::event!(
            "INODE rename src_inode={} new={} old_target_inode={}",
            source_inode
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            fuselog::path_string(new.as_os_str()),
            old_target
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
        );
        map.rename(&old, &new, parent);
        Ok(())
    }

    /// Create a symlink: always denied. A host symlink visible through the
    /// mirror is only ever shown *as a symlink* (never followed), and
    /// creating one in the sandbox could link outside the mirrored paths —
    /// so the operation is refused outright. `EACCES` ("Permission denied")
    /// reports this as the policy decision it is; the implicit `ENOSYS`
    /// default would instead pretend the feature is missing.
    async fn symlink(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        _link: &std::ffi::OsStr,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("symlink");
        let parent_path = self.resolve(parent).await?;
        let mirrored = parent_path.join(name);
        log_op_err(
            "symlink",
            &mirrored,
            Some(&self.redirect(&mirrored)),
            &std::io::Error::from_raw_os_error(libc::EACCES),
        )
        .await;
        Err(libc::EACCES.into())
    }

    /// Create a hard link: the new name points at the *same real host file*
    /// as the source (`link` on the host filesystem), so writes through
    /// either name are visible through both. The new name gets a **fresh
    /// nodeid** mapping to the new path: the mirror's pattern permissions
    /// are decided per path, and a hard-linked name is an independent path
    /// (the source nodeid keeps its mapping; renaming one name must not
    /// affect the other's).
    ///
    /// **Both** names must be writable. Checking only the new name would
    /// let the sandbox link a *read-only* mapped file (say, from
    /// `~/.rustup`) into a writable path and then write through the link —
    /// the write follows the host inode, bypassing the source path's
    /// `ro` permission. Rejecting cross-policy links also avoids the
    /// residual risk of a linked file living under two paths that disagree
    /// on the write policy (a hard link is one host file; the per-path
    /// model cannot express that).
    async fn link(
        &self,
        _req: Request,
        inode: Inode,
        new_parent: Inode,
        new_name: &OsStr,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("link");
        let source_path = self.resolve(inode).await?;
        let new_parent_path = self.resolve(new_parent).await?;
        let old = source_path;
        let new = new_parent_path.join(new_name);
        if self.is_empty(&old) || self.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.exists(&old) {
            log_op_err(
                "link",
                &old,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // The source must be writable, too: a read-only source must not be
        // linked into a writable path (the write would follow the host
        // inode and bypass the source path's `ro` permission).
        if !self.writable(&old) {
            log_op_err(
                "link",
                &old,
                Some(&self.redirect(&old)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if !self.writable(&new) {
            log_op_err(
                "link",
                &new,
                Some(&self.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if let Err(e) = tokio_fs::hard_link(self.redirect(&old), self.redirect(&new)).await {
            log_op_err("link", &new, Some(&self.redirect(&new)), &e).await;
            return Err(e.into());
        }
        log_op_ok("link", &new, &self.redirect(&new)).await;
        let inode = self.inodes.write().await.get_or_insert(&new, new_parent);
        let mut attr = self.attr(&new).await?;
        attr.ino = inode;
        Ok(ReplyEntry {
            ttl: TTL,
            attr,
            generation: 0,
        })
    }

    async fn create(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        perf::fuse_op!("create");
        let parent_path = self.resolve(parent).await?;
        let mirrored = parent_path.join(name);
        let writable = self.writable(&mirrored);
        if !writable {
            log_op_err(
                "create",
                &mirrored,
                Some(&self.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only with O_EXCL does a *real* entry at the target mean EEXIST;
        // a plain O_CREAT (without O_EXCL) opens an existing file like the
        // host filesystem would. A path merely matched by a wildcard
        // pattern may not exist yet.
        let existing = tokio_fs::symlink_metadata(self.redirect(&mirrored))
            .await
            .ok();
        let excl = flags & libc::O_EXCL as u32 != 0;
        let truncate = flags & libc::O_TRUNC as u32 != 0;
        let append = flags & libc::O_APPEND as u32 != 0;
        if let Some(md) = existing {
            if md.file_type().is_symlink() {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&self.redirect(&mirrored)),
                    &std::io::Error::from_raw_os_error(libc::ELOOP),
                )
                .await;
                return Err(libc::ELOOP.into());
            }
            if excl {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&self.redirect(&mirrored)),
                    &std::io::Error::from_raw_os_error(libc::EEXIST),
                )
                .await;
                return Err(libc::EEXIST.into());
            }
            if md.is_dir() {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&self.redirect(&mirrored)),
                    &std::io::Error::from_raw_os_error(libc::EISDIR),
                )
                .await;
                return Err(libc::EISDIR.into());
            }
            let mut opts = tokio_fs::OpenOptions::new();
            opts.write(true).custom_flags(libc::O_NOFOLLOW);
            if truncate {
                opts.truncate(true);
            }
            if append {
                opts.append(true);
            }
            let file = match opts.open(self.redirect(&mirrored)).await {
                Ok(f) => f,
                Err(e) => {
                    log_op_err("create", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                    return Err(e.into());
                }
            };
            let md = file.metadata().await?;
            log_op_ok("create", &mirrored, &self.redirect(&mirrored)).await;
            let inode = self.inodes.write().await.get_or_insert(&mirrored, parent);
            self.inodes.write().await.open_handle(inode);
            let fh = self.insert_handle(file, mirrored, append, writable);
            let mut attr = attr_from_metadata(&md);
            attr.ino = inode;
            return Ok(ReplyCreated {
                ttl: TTL,
                attr,
                generation: 0,
                fh,
                flags: 0,
            });
        }
        let mut opts = tokio_fs::OpenOptions::new();
        opts.write(true).create_new(true);
        if flags & libc::O_RDWR as u32 != 0 {
            opts.read(true);
        }
        if flags & libc::O_APPEND as u32 != 0 {
            opts.append(true);
        }
        let file = match opts
            .mode(mode & 0o7777)
            .open(self.redirect(&mirrored))
            .await
        {
            Ok(f) => f,
            Err(e) => {
                log_op_err("create-new", &mirrored, Some(&self.redirect(&mirrored)), &e).await;
                return Err(e.into());
            }
        };
        let md = file.metadata().await?;
        let mut attr = attr_from_metadata(&md);
        log_op_ok("create-new", &mirrored, &self.redirect(&mirrored)).await;
        let inode = self.inodes.write().await.get_or_insert(&mirrored, parent);
        self.inodes.write().await.open_handle(inode);
        let fh = self.insert_handle(file, mirrored, append, writable);
        attr.ino = inode;
        Ok(ReplyCreated {
            ttl: TTL,
            attr,
            generation: 0,
            fh,
            flags: 0,
        })
    }

    /// Release an open file: the cached host file is dropped (closing it);
    /// there is nothing to flush. The reply mirrors the path API's default
    /// (`ENOSYS`), which the kernel does not propagate to `close()`.
    async fn release(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> Result<()> {
        perf::fuse_op!("release");
        // Drop the cached host file (closing it); the handle bookkeeping
        // is all that remains — IO is stateful but needs no flush.
        self.remove_handle(fh);
        self.inodes.write().await.close_handle(inode);
        Err(libc::ENOSYS.into())
    }

    async fn releasedir(&self, _req: Request, inode: Inode, _fh: u64, _flags: u32) -> Result<()> {
        perf::fuse_op!("releasedir");
        self.inodes.write().await.close_handle(inode);
        Ok(())
    }
}

/// A host path as a NUL-terminated C string, for the libc calls.
fn cstring_of(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOENT))
}

/// Map a fuse3 timestamp to a `utimensat` timespec; `None` means "leave
/// this time unchanged" (`UTIME_OMIT`).
fn ts_to_timespec(ts: Option<Timestamp>) -> libc::timespec {
    match ts {
        Some(t) => libc::timespec {
            tv_sec: t.sec,
            tv_nsec: t.nsec as libc::c_long,
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT as libc::c_long,
        },
    }
}

/// The signals that must never kill the FUSE server child: the ones that
/// terminate ai-bubble on the user's request (`SIGINT` from Ctrl-C, and the
/// usual `SIGTERM`/`SIGQUIT`/`SIGHUP`), plus `SIGPIPE` (the readiness pipe's
/// write end would otherwise kill the server when the parent has already
/// died before reading the readiness byte). Blocked around the fork, ignored
/// (and unblocked) inside the server: the server terminates on the parent's
/// death, not on a signal — that is what lets it unmount cleanly.
const SERVER_SIGNALS: [libc::c_int; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGQUIT,
    libc::SIGHUP,
    libc::SIGPIPE,
];

/// A no-op signal handler: the signal is received and discarded.
extern "C" fn swallow_signal(_: libc::c_int) {}

/// Disarm the termination signals in the FUSE server child: install the
/// no-op handler (a handler, not `SIG_IGN`, so an `exec`ed `fusermount3`
/// gets back its default disposition instead of inheriting ignore flags)
/// and unblock whatever the parent blocked around the fork — a pending
/// signal is then received and discarded.
///
/// # Safety
/// Raw `sigaction`/`sigprocmask` calls; must run in the freshly forked
/// server child before it serves.
unsafe fn disarm_signals() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = swallow_signal as extern "C" fn(libc::c_int) as usize;
        sa.sa_flags = libc::SA_RESTART;
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        for sig in SERVER_SIGNALS {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
            libc::sigaddset(&mut blocked, sig);
        }
        libc::sigprocmask(libc::SIG_UNBLOCK, &blocked, std::ptr::null_mut());
    }
}

/// Fork the FUSE server process, wait for it to mount, and record the
/// mountpoint for the sandbox child. Must run before any namespace setup.
///
/// `patterns` is the internal pattern → permission list built from the
/// spec's `hostfs` section; the patterns are compiled inside the server
/// process (after the fork).
///
/// On success the mountpoint path is stored in `HOST_MOUNT_POINT` (inherited
/// by every later fork). On any failure the process dies.
pub fn start_host_fs(patterns: &Patterns) {
    // Create the mountpoint directory in the parent so both the server and the
    // sandbox (and its children) can agree on a stable path.
    let mut tmpl: Vec<u8> = b"/tmp/ai-bubble.host.XXXXXX".to_vec();
    tmpl.push(0);
    let mountpoint = unsafe {
        let raw = libc::mkdtemp(CString::from_vec_with_nul(tmpl).unwrap().into_raw());
        if raw.is_null() {
            die_with_error("Can't create temporary mirrored-fs mountpoint");
        }
        PathBuf::from(CStr::from_ptr(raw).to_string_lossy().into_owned())
    };

    let _ = HOST_MOUNT_POINT.set(mountpoint.clone());
    HOST_PID.store(unsafe { libc::getpid() }, Ordering::SeqCst);

    // Readiness pipe: the server writes one byte after a successful mount.
    let mut fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        die_with_error("Can't create readiness pipe");
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Block the signals that terminate ai-bubble (plus SIGPIPE) *around the
    // fork*: the server child inherits the blocked mask, so a SIGINT/SIGTERM
    // delivered to the process group — even in the window between the fork
    // and the child's own signal setup — cannot kill the server before it
    // has mounted (and later unmounted cleanly). The server exits when the
    // parent dies, never on a signal. The parent restores its own mask right
    // after the fork, so it stays killable as usual.
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        for sig in SERVER_SIGNALS {
            libc::sigaddset(&mut blocked, sig);
        }
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut old_mask);
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die_with_error("Can't fork mirrored-fs server");
    }
    if pid == 0 {
        // Child: serve the FUSE filesystem forever (or until the host dies).
        unsafe {
            libc::close(read_fd);
            disarm_signals();
        }
        serve(patterns.clone(), mountpoint, write_fd);
        // serve never returns
    }
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };

    // Parent: wait for readiness.
    unsafe { libc::close(write_fd) };
    let mut byte: u8 = 0;
    let n = unsafe { libc::read(read_fd, (&mut byte) as *mut u8 as *mut libc::c_void, 1) };
    unsafe { libc::close(read_fd) };
    if n != 1 {
        // The child printed a detailed error before exiting.
        let _ = std::fs::remove_dir(&mountpoint);
        crate::sandbox::die("Can't mount mirrored filesystem (is fusermount3 installed?)");
    }
}

/// The FUSE server child: mount and serve until the parent process is gone.
///
/// The whole lifecycle runs inside a single `block_on`: the session's request
/// loop is a spawned task, and a current-thread runtime only polls its tasks
/// while `block_on` is running — returning early would silently stall the
/// event loop and every filesystem access would hang.
fn serve(patterns: Patterns, mountpoint: PathBuf, ready_fd: libc::c_int) -> ! {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't build tokio runtime: {e}")));

    let outcome = {
        let mp = mountpoint.clone();
        let server_mountpoint = mountpoint.clone();
        fuselog::event!("SERVER start mountpoint={}", mountpoint.display());
        runtime.block_on(async move {
            let handle = match mount_with_fallback(
                &mp,
                uid,
                gid,
                &patterns,
                !has_writable_patterns(&patterns),
            )
            .await
            {
                Ok(handle) => handle,
                Err(e) => return Err(e),
            };

            fuselog::event!("SERVER mounted");

            // Signal readiness to the parent.
            let byte: u8 = 1;
            let _ =
                unsafe { libc::write(ready_fd, (&byte) as *const u8 as *const libc::c_void, 1) };
            unsafe { libc::close(ready_fd) };

            // Serve until the sandbox process dies, then unmount cleanly. The
            // session task runs concurrently on this runtime.
            let mut heartbeat = 0u64;
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if unsafe { libc::getppid() } != HOST_PID.load(Ordering::SeqCst) {
                    break;
                }
                heartbeat += 1;
                if heartbeat.is_multiple_of(10) {
                    fuselog::event!("SERVER alive");
                }
            }

            fuselog::event!("SERVER parent-gone, unmounting");
            let mut outcome = handle.unmount().await;
            if let Err(e) = &outcome {
                // fuse3's unmount is a single attempt (`fusermount3 -u`, or
                // a plain `umount` on the privileged route) and fails with
                // EBUSY when anything still holds the mount — e.g. a daemon
                // child of the sandboxed command that outlived it. Fall back
                // to a *lazy* unmount so the mount is detached regardless.
                fuselog::event!("SERVER unmount failed ({e}), trying lazy unmount");
                outcome = lazy_unmount(&server_mountpoint).await;
            }
            fuselog::event!("SERVER unmount outcome={outcome:?}");
            // Give the audit writer a chance to flush the last batch
            // before this process exits.
            crate::audit::drain().await;
            outcome
        })
    };

    if let Err(e) = outcome {
        eprintln!(
            "ai-bubble: Can't mount mirrored filesystem at {}: {e}",
            mountpoint.display()
        );
    }
    let _ = std::fs::remove_dir(&mountpoint);
    std::process::exit(0);
}

/// Mount the host filesystem, preferring the unprivileged fusermount3 route
/// and falling back to a direct (root-only) mount. The mount is read-only
/// unless `read_only` is false (some pattern grants write access).
async fn mount_with_fallback(
    mountpoint: &Path,
    uid: u32,
    gid: u32,
    patterns: &Patterns,
    read_only: bool,
) -> std::io::Result<fuse3::raw::MountHandle> {
    // The mount consumes the filesystem, so each attempt builds its own
    // `HostFs` — cheap (pattern compilation only), and correct: a failed
    // attempt never reached the kernel, so its inode map was never touched.
    let options = || {
        let mut o = MountOptions::default();
        o.uid(uid)
            .gid(gid)
            .rootmode(0o755)
            .read_only(read_only)
            .allow_other(false)
            .nonempty(true);
        o
    };
    match Session::new(options())
        .mount_with_unprivileged(HostFs::collect(patterns), mountpoint)
        .await
    {
        Ok(handle) => Ok(handle),
        Err(unprivileged_err) => Session::new(options())
            .mount(HostFs::collect(patterns), mountpoint)
            .await
            .map_err(|privileged_err| {
                std::io::Error::other(format!(
                    "unprivileged: {unprivileged_err}; privileged: {privileged_err}"
                ))
            }),
    }
}

/// Last-resort unmount after fuse3's own unmount failed (typically EBUSY):
/// first a lazy unprivileged `fusermount3 -uz`, then a direct
/// `umount2(MNT_DETACH)` (the privileged route, or when fusermount3 is not
/// available). A lazy unmount detaches the mount immediately even while
/// busy; it disappears for good once the last user is gone — better than a
/// mount left dangling until the next reboot.
async fn lazy_unmount(mountpoint: &Path) -> std::io::Result<()> {
    let mountpoint = mountpoint.to_path_buf();
    blocking(move || {
        let via_fusermount = match std::process::Command::new("fusermount3")
            .args(["-uz"])
            .arg(&mountpoint)
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            Ok(_) => Err(std::io::Error::other("fusermount3 -uz failed")),
            Err(e) => Err(e),
        };
        via_fusermount.or_else(|_| {
            let c = CString::new(mountpoint.as_os_str().as_bytes()).expect("no NUL in mountpoint");
            if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    })
    .await
}

fn die(msg: &str) -> ! {
    crate::sandbox::die(msg)
}

/// Run a raw libc call (which has no tokio wrapper) on tokio's blocking
/// pool, so the FUSE session's event loop is never stalled by host IO. The
/// `HostFs` itself is cloned in: it holds only the compiled patterns, so
/// cloning is cheap. Everything that has a `tokio::fs` equivalent uses
/// that directly instead.
async fn blocking<T, F>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking hostfs task panicked")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(entries: &[(&str, Permission)]) -> HostFs {
        HostFs::collect(&Patterns(
            entries
                .iter()
                .map(|(p, perm)| (p.to_string(), perm.clone()))
                .collect(),
        ))
    }

    /// Alias for readability in the empty-path tests.
    fn fs_with_empties(entries: &[(&str, Permission)]) -> HostFs {
        fs(entries)
    }

    #[test]
    fn permission_of_follows_hostfs_semantics() {
        // Direct matches: the last pattern naming the path decides.
        let patterns = Patterns(vec![
            ("/etc".to_string(), Permission::Ro),
            ("/etc/*.conf".to_string(), Permission::Rw),
            ("/etc/passwd".to_string(), Permission::Hide),
            ("/dev".to_string(), Permission::Empty),
        ]);
        assert_eq!(
            permission_of(&patterns, Path::new("/etc")),
            Some(Permission::Ro)
        );
        assert_eq!(
            permission_of(&patterns, Path::new("/etc/hosts.conf")),
            Some(Permission::Rw)
        );
        assert_eq!(
            permission_of(&patterns, Path::new("/etc/passwd")),
            Some(Permission::Hide)
        );
        assert_eq!(
            permission_of(&patterns, Path::new("/dev")),
            Some(Permission::Empty)
        );

        // No direct match: mirrored directories are recursive, so their
        // permission is inherited by everything below them.
        let patterns = Patterns(vec![("/home/me/project".to_string(), Permission::Rw)]);
        assert_eq!(
            permission_of(&patterns, Path::new("/home/me/project/src/main.rs")),
            Some(Permission::Rw)
        );
        // ...and the nearest mirrored ancestor wins over a farther one.
        let patterns = Patterns(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project".to_string(), Permission::Ro),
        ]);
        assert_eq!(
            permission_of(&patterns, Path::new("/home/me/project/src/main.rs")),
            Some(Permission::Ro)
        );

        // A hidden directory hides its whole subtree.
        let patterns = Patterns(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project/target".to_string(), Permission::Hide),
        ]);
        assert_eq!(
            permission_of(&patterns, Path::new("/home/me/project/target/debug")),
            Some(Permission::Hide)
        );

        // Everything strictly below an empty path is invisible.
        let patterns = Patterns(vec![
            ("/etc".to_string(), Permission::Ro),
            ("/dev".to_string(), Permission::Empty),
        ]);
        assert_eq!(permission_of(&patterns, Path::new("/dev/null")), None);
        // Unrelated paths stay invisible, too.
        assert_eq!(permission_of(&patterns, Path::new("/opt")), None);
    }

    /// The async HostFs methods (`attr`, `dir_entries`, …) run their host
    /// syscalls via `tokio::fs` on the blocking pool; the synchronous tests
    /// await them on a throwaway current-thread runtime.
    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn empty_paths_are_virtual_unwritable_directories() {
        let f = fs_with_empties(&[("/dev", Permission::Empty)]);

        // The dir itself exists, with no write permission...
        assert!(f.exists(Path::new("/dev")));
        assert!(f.is_empty(Path::new("/dev")));
        assert_eq!(block(f.attr(Path::new("/dev"))).unwrap().perm, 0o555);
        assert_eq!(
            block(f.attr(Path::new("/dev"))).unwrap().kind,
            FileType::Directory
        );
        // ...and it is empty even though the real host /dev has entries.
        assert!(block(f.dir_entries(Path::new("/dev"))).is_empty());
        // Deeper paths are shadowed by the precedence.
        assert!(!f.exists(Path::new("/dev/null")));
        assert!(!f.matches(Path::new("/dev/null")));
        // The empty pattern "reaches" below /dev (so ancestors stay
        // navigable), but the precedence keeps /dev/null non-existent.
        assert!(f.dir_prefix(Path::new("/dev/null")));
        assert!(!f.exists(Path::new("/dev/null")));
        // The mountpoint dir is not itself a dir-prefix.
        assert!(!f.dir_prefix(Path::new("/dev")));
    }

    #[test]
    fn empty_paths_take_precedence_over_mirror() {
        let f = fs(&[
            ("/etc/*", Permission::Ro),
            ("/etc", Permission::Ro),
            ("/etc", Permission::Empty),
        ]);
        assert!(f.is_empty(Path::new("/etc")));
        // Mirror contents below the empty dir are hidden.
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(block(f.dir_entries(Path::new("/etc"))).is_empty());
        // But /etc still appears at the root listing.
        let names: Vec<_> = block(f.dir_entries(Path::new("/")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["etc"]);
    }

    #[test]
    fn injected_paths_are_virtual_read_only_files() {
        let f = fs(&[(
            "/etc/resolv.conf",
            Permission::Inject {
                content: "nameserver 127.0.0.2\n".to_string(),
            },
        )]);

        // The injected path exists and is a visible mirror match.
        assert!(f.exists(Path::new("/etc/resolv.conf")));
        assert!(f.matches(Path::new("/etc/resolv.conf")));

        // Its attributes: a read-only regular file sized like the content.
        let attr = block(f.attr(Path::new("/etc/resolv.conf"))).unwrap();
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, 0o444);
        assert_eq!(attr.size, "nameserver 127.0.0.2\n".len() as u64);

        // Ancestors stay navigable (even without any host mapping for
        // /etc), and the file shows up in its (virtual) directory.
        assert!(f.exists(Path::new("/etc")));
        assert!(f.dir_prefix(Path::new("/etc")));
        assert!(block(f.is_listable_dir(Path::new("/etc"))));
        let names: Vec<_> = block(f.dir_entries(Path::new("/etc")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["resolv.conf"]);

        // Read-only: nothing can be written to it (or created below it —
        // the injected path is a file).
        assert!(!f.writable(Path::new("/etc/resolv.conf")));
        assert!(!f.writable(Path::new("/etc/resolv.conf/sub")));

        // Nothing below the injected path is visible at all.
        assert!(!f.exists(Path::new("/etc/resolv.conf/x")));
        assert_eq!(
            permission_of(
                &Patterns(vec![(
                    "/etc/resolv.conf".to_string(),
                    Permission::Inject {
                        content: "x".to_string()
                    }
                )]),
                Path::new("/etc/resolv.conf/x"),
            ),
            None
        );
    }

    #[test]
    fn injected_path_ancestors_are_virtual_directories_for_access() {
        let f = fs(&[(
            "/etc/pki/tls/certs/ca-bundle.crt",
            Permission::Inject {
                content: "x".to_string(),
            },
        )]);

        // The purely virtual ancestors of an injected file are answered
        // directly by `access` (the kernel consults it for `chdir`), as
        // long as the real host path does not exist; where a real host
        // directory exists, the real filesystem decides.
        for p in ["/etc", "/etc/pki", "/etc/pki/tls", "/etc/pki/tls/certs"] {
            let p = Path::new(p);
            assert_eq!(
                block(f.virtual_only(p)),
                !f.redirect(p).exists(),
                "virtual_only({p:?})"
            );
        }
        // An injected file itself is always purely virtual.
        assert!(block(
            f.virtual_only(Path::new("/etc/pki/tls/certs/ca-bundle.crt"))
        ));

        // A real mirror path is not: the real filesystem decides.
        assert!(!block(f.virtual_only(Path::new("/usr/bin"))));
    }

    #[test]
    fn empty_paths_match_real_files_as_empty_files() {
        let base = std::env::temp_dir().join(format!(
            "ai-bubble-hostfs-empty-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("f.txt"), b"content").unwrap();
        std::fs::create_dir_all(base.join("d")).unwrap();

        let f = fs(&[(&format!("{}/*", base.display()), Permission::Empty)]);
        // The real file is shown empty.
        let file = block(f.attr(&base.join("f.txt"))).unwrap();
        assert_eq!(file.kind, FileType::RegularFile);
        assert_eq!(file.size, 0);
        // The real directory is shown as an empty directory.
        let dir = block(f.attr(&base.join("d"))).unwrap();
        assert_eq!(dir.kind, FileType::Directory);
        assert_eq!(dir.perm, 0o555);
        assert!(block(f.dir_entries(&base.join("d"))).is_empty());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn empty_path_ancestors_stay_navigable() {
        // A nested empty path; /var exists only as a virtual ancestor.
        let f = fs_with_empties(&[("/var/tmp", Permission::Empty)]);
        assert!(f.exists(Path::new("/var")));
        assert!(f.is_empty_prefix(Path::new("/var")));
        assert!(f.exists(Path::new("/var/tmp")));
        assert!(!f.exists(Path::new("/var/tmp/other")));
        assert!(!f.exists(Path::new("/var/etc")));
        // The root listing contains both levels of the chain.
        let root: Vec<_> = block(f.dir_entries(Path::new("/")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(root, ["var"]);
        let var: Vec<_> = block(f.dir_entries(Path::new("/var")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(var, ["tmp"]);
    }

    #[test]
    fn empty_paths_coexist_with_mirror() {
        // /dev is empty, /etc/passwd is mirrored normally; siblings of the
        // empty path are listed together with it.
        let f = fs(&[("/etc/passwd", Permission::Ro), ("/dev", Permission::Empty)]);
        let names: Vec<_> = block(f.dir_entries(Path::new("/")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["dev", "etc"]);
        assert!(f.exists(Path::new("/etc/passwd")));
        assert!(!f.exists(Path::new("/dev/whatever")));
    }

    #[test]
    fn redirect_resolves_to_the_source_path() {
        let f = HostFs::collect(&Patterns(vec![
            (
                "/bla".to_string(),
                Permission::Redirect {
                    source: PathBuf::from("/otherdir"),
                    writable: false,
                },
            ),
            ("/etc/passwd".to_string(), Permission::Ro),
        ]));

        // The redirect destination maps exactly onto the source.
        assert_eq!(f.redirect(Path::new("/bla")), PathBuf::from("/otherdir"));
        // ...and everything below it onto the source plus the rest.
        assert_eq!(
            f.redirect(Path::new("/bla/sub/file.txt")),
            PathBuf::from("/otherdir/sub/file.txt")
        );
        // Non-redirected paths resolve to themselves.
        assert_eq!(
            f.redirect(Path::new("/etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(f.redirect(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn redirect_obeys_last_match_wins() {
        // A later plain mapping naming the redirected path (or something
        // below it) wins over the redirect, like with every mapping.
        let f = HostFs::collect(&Patterns(vec![
            (
                "/bla".to_string(),
                Permission::Redirect {
                    source: PathBuf::from("/otherdir"),
                    writable: false,
                },
            ),
            ("/bla/plain".to_string(), Permission::Ro),
        ]));
        // /bla itself is still redirected...
        assert_eq!(f.redirect(Path::new("/bla")), PathBuf::from("/otherdir"));
        // ...but /bla/plain is mirrored plainly (its own last match), and
        // /bla/plain/x inherits the *plain* mirror, not the redirect.
        assert_eq!(
            f.redirect(Path::new("/bla/plain")),
            PathBuf::from("/bla/plain")
        );
        assert_eq!(
            f.redirect(Path::new("/bla/plain/x")),
            PathBuf::from("/bla/plain/x")
        );
        // Everything else below /bla follows the redirect.
        assert_eq!(
            f.redirect(Path::new("/bla/other/x")),
            PathBuf::from("/otherdir/other/x")
        );
    }

    #[test]
    fn redirected_paths_show_the_source_content() {
        let base = std::env::temp_dir().join(format!(
            "ai-bubble-hostfs-redirect-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::fs::write(base.join("real/file.txt"), b"redirected").unwrap();

        let f = HostFs::collect(&Patterns(vec![(
            "/virtual".to_string(),
            Permission::Redirect {
                source: base.join("real"),
                writable: false,
            },
        )]));

        // The redirected path is visible and shows the source's content.
        assert!(f.exists(Path::new("/virtual")));
        assert!(f.matches(Path::new("/virtual")));
        let attr = block(f.attr(Path::new("/virtual"))).unwrap();
        assert_eq!(attr.kind, FileType::Directory);

        // Its entries are the source dir's entries, listed under the
        // redirected name.
        let mut names: Vec<_> = block(f.dir_entries(Path::new("/virtual")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["file.txt", "sub"]);

        // A file below the redirect reads the real source file.
        let attr = block(f.attr(Path::new("/virtual/file.txt"))).unwrap();
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.size, 10);

        // Read-only: not writable despite existing.
        assert!(!f.writable(Path::new("/virtual/file.txt")));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn redirected_files_are_listed_in_their_directory() {
        let base = std::env::temp_dir().join(format!(
            "ai-bubble-hostfs-test-redirect-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("cfg.json"), b"redirected").unwrap();

        // A redirected file inside a directory that is itself redirected
        // to an empty (or otherwise non-matching) directory: the file is
        // lookable, so it must be listed, too — even though the listing
        // of its parent does not come from the host directory containing
        // the redirect target.
        let f = HostFs::collect(&Patterns(vec![
            (
                "/conf".to_string(),
                Permission::Redirect {
                    source: base.join("cache"),
                    writable: false,
                },
            ),
            (
                "/conf/cfg.json".to_string(),
                Permission::Redirect {
                    source: base.join("cfg.json"),
                    writable: false,
                },
            ),
        ]));
        let names: Vec<_> = block(f.dir_entries(Path::new("/conf")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["cfg.json"]);

        // A redirect whose source does not exist is not listed (no
        // "ghost" entry advertising a lookup that fails).
        let f = HostFs::collect(&Patterns(vec![(
            "/conf/missing.json".to_string(),
            Permission::Redirect {
                source: base.join("missing.json"),
                writable: false,
            },
        )]));
        assert!(block(f.dir_entries(Path::new("/conf"))).is_empty());

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn redirect_rw_is_writable_and_ro_is_not() {
        let ro = HostFs::collect(&Patterns(vec![(
            "/a".to_string(),
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: false,
            },
        )]));
        let rw = HostFs::collect(&Patterns(vec![(
            "/a".to_string(),
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: true,
            },
        )]));
        assert!(!ro.writable(Path::new("/a/f")));
        assert!(!has_writable_patterns(&Patterns(vec![(
            "/a".to_string(),
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: false,
            },
        )])));
        assert!(rw.writable(Path::new("/a/f")));
        assert!(has_writable_patterns(&Patterns(vec![(
            "/a".to_string(),
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: true,
            },
        )])));
    }

    #[test]
    fn pattern_matching_per_operation() {
        let f = fs(&[
            ("/etc/*.conf", Permission::Ro),
            ("/home/me/project", Permission::Ro),
        ]);

        // Direct matches.
        assert!(f.matches(Path::new("/etc/foo.conf")));
        assert!(f.matches(Path::new("/home/me/project")));
        assert!(!f.matches(Path::new("/etc/passwd")));

        // exists: matches plus ancestor directories.
        assert!(f.exists(Path::new("/etc/foo.conf")));
        assert!(f.exists(Path::new("/etc"))); // ancestor of a match
        assert!(f.exists(Path::new("/"))); // root
        assert!(f.exists(Path::new("/home/me/project")));
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(!f.exists(Path::new("/etc/nothing")));

        // dir_prefix: only true for ancestors of matches — an exactly
        // matched path (file or recursively mirrored directory) is not a
        // prefix itself.
        assert!(f.dir_prefix(Path::new("/etc")));
        assert!(f.dir_prefix(Path::new("/home")));
        assert!(f.dir_prefix(Path::new("/home/me")));
        assert!(!f.dir_prefix(Path::new("/home/me/project")));
        assert!(!f.dir_prefix(Path::new("/etc/passwd")));
        assert!(!f.dir_prefix(Path::new("/etc/foo.conf")));
    }

    #[test]
    fn double_star_spans_directories() {
        let f = fs(&[("/usr/share/**/*.rs", Permission::Ro)]);
        assert!(f.exists(Path::new("/usr/share")));
        assert!(f.dir_prefix(Path::new("/usr/share/doc")));
        assert!(f.matches(Path::new("/usr/share/doc/x/y.rs")));
        assert!(!f.matches(Path::new("/usr/share/doc/x/y.c")));
    }

    #[test]
    fn readdir_filters_non_matching_entries() {
        let base = std::env::temp_dir().join(format!(
            "ai-bubble-hostfs-test-readdir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("a.conf"), b"a").unwrap();
        std::fs::write(base.join("b.txt"), b"b").unwrap();
        std::fs::create_dir(base.join("c.conf.dir")).unwrap();
        std::fs::write(base.join("c.conf.dir/x"), b"x").unwrap();
        std::fs::create_dir(base.join("d.conf")).unwrap();
        std::fs::write(base.join("d.conf/y"), b"y").unwrap();

        let f = fs(&[(&format!("{}/*.conf", base.display()), Permission::Ro)]);

        // Only matching entries (and entries leading to matches) survive.
        let names: Vec<_> = block(f.dir_entries(&base))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.conf".to_string()));
        assert!(names.contains(&"d.conf".to_string())); // a directory named by the pattern
        assert!(!names.contains(&"b.txt".to_string()));
        assert!(!names.contains(&"c.conf.dir".to_string()));

        // An entry that only leads to a match (virtual ancestor) is shown.
        let f = fs(&[(&format!("{}/c.conf.dir/x", base.display()), Permission::Ro)]);
        let names: Vec<_> = block(f.dir_entries(&base))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"c.conf.dir".to_string()));
        assert!(!names.contains(&"a.conf".to_string()));
        assert!(!names.contains(&"b.txt".to_string()));

        // An exactly matched directory is a recursive mirror: all real
        // entries are visible.
        let f = fs(&[(
            &format!("{}", base.join("c.conf.dir").display()),
            Permission::Ro,
        )]);
        let names: Vec<_> = block(f.dir_entries(&base.join("c.conf.dir")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["x"]);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn empty_mirror_matches_nothing() {
        let f = fs(&[]);
        assert!(!f.exists(Path::new("/")));
        assert!(block(f.dir_entries(Path::new("/"))).is_empty());
    }

    #[test]
    fn empty_patterns_only_still_show_root() {
        let f = fs_with_empties(&[("/dev", Permission::Empty)]);
        assert!(f.exists(Path::new("/")));
        assert_eq!(
            block(f.dir_entries(Path::new("/")))
                .into_iter()
                .map(|(n, _)| n.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["dev"]
        );
    }

    #[test]
    fn last_matching_pattern_wins() {
        // The later hide hides the file inside the mirrored tree...
        let f = fs(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Hide)]);
        assert!(f.exists(Path::new("/etc")));
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(!f.matches(Path::new("/etc/passwd")));
        // ...and the reverse order shows *other* files under /etc again:
        // the last pattern that names a path decides. "/etc/passwd" is
        // still hidden (its own hide pattern is the only one naming it),
        // but a sibling is visible via the later recursive mirror.
        let f = fs(&[("/etc/passwd", Permission::Hide), ("/etc", Permission::Ro)]);
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(f.exists(Path::new("/etc/hosts")));
    }

    #[test]
    fn hidden_directories_hide_their_subtree() {
        let f = fs(&[
            ("/etc", Permission::Ro),
            ("/etc/passwd", Permission::Ro),
            ("/etc", Permission::Hide),
        ]);
        // The hide pattern matches /etc last and shadows everything below.
        assert!(!f.exists(Path::new("/etc")));
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(block(f.dir_entries(Path::new("/"))).is_empty());
        // Siblings are unaffected; the hide is scoped to /etc.
        let base =
            std::env::temp_dir().join(format!("ai-bubble-hostfs-hide-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("foo.conf"), b"f").unwrap();
        std::fs::create_dir_all(base.join("secret")).unwrap();
        let base_str = base.display().to_string();
        let f = fs(&[
            (&format!("{base_str}/*"), Permission::Ro),
            (&format!("{base_str}/secret"), Permission::Hide),
        ]);
        assert!(f.exists(&base.join("foo.conf")));
        assert!(!f.exists(&base.join("secret")));
        // The parent stays navigable for the still-mirrored matches.
        assert!(f.exists(&base));
        let names: Vec<_> = block(f.dir_entries(&base))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["foo.conf"]);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn hidden_patterns_do_not_make_paths_navigable() {
        // Only a hide pattern: nothing appears, not even ancestor dirs.
        let f = fs(&[("/etc/passwd", Permission::Hide)]);
        assert!(!f.exists(Path::new("/")));
        assert!(!f.exists(Path::new("/etc")));
    }

    #[test]
    fn write_permission_follows_the_last_pattern() {
        let f = fs(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Rw)]);
        assert!(matches!(
            f.write_permission(Path::new("/etc")),
            Some(Permission::Ro)
        ));
        assert!(matches!(
            f.write_permission(Path::new("/etc/passwd")),
            Some(Permission::Rw)
        ));
        assert!(!f.writable(Path::new("/etc")));
        assert!(f.writable(Path::new("/etc/passwd")));
        // The root is never writable.
        assert!(!f.writable(Path::new("/")));
    }

    #[test]
    fn rw_directories_are_recursively_writable() {
        let f = fs(&[("/proj", Permission::Rw), ("/proj/secret", Permission::Ro)]);
        // Children of an exactly-named rw dir inherit its permission.
        assert!(f.writable(Path::new("/proj/newfile")));
        assert!(f.writable(Path::new("/proj/sub/x")));
        // The nearest mirrored ancestor decides: `ro` wins below /secret.
        assert!(!f.writable(Path::new("/proj/secret")));
        assert!(!f.writable(Path::new("/proj/secret/x")));
    }

    #[test]
    fn wildcard_rw_patterns_allow_creating_matching_children() {
        let f = fs(&[("/out/*.txt", Permission::Rw)]);
        assert!(f.writable(Path::new("/out/a.txt")));
        assert!(!f.writable(Path::new("/out/a.conf")));
        // The parent dir itself is only a wildcard ancestor, not writable.
        assert!(!f.writable(Path::new("/out")));
    }

    #[test]
    fn star_star_rw_covers_everything_below() {
        let f = fs(&[("/work/**", Permission::Rw)]);
        assert!(f.writable(Path::new("/work")));
        assert!(f.writable(Path::new("/work/a/b/c")));
    }

    #[test]
    fn hide_and_empty_block_writes() {
        let f = fs(&[
            ("/a", Permission::Rw),
            ("/a/h", Permission::Hide),
            ("/a/e", Permission::Empty),
        ]);
        assert!(!f.writable(Path::new("/a/h/x")));
        assert!(!f.writable(Path::new("/a/e")));
        assert!(!f.writable(Path::new("/a/e/x")));
    }

    #[test]
    fn nothing_below_an_injected_path_is_visible() {
        // An injected path is a virtual file: even a pattern matching below
        // it must not resurrect its subtree (the standalone `permission_of`
        // and the mirror must agree on this).
        let f = fs(&[
            (
                "/etc/resolv.conf",
                Permission::Inject {
                    content: "nameserver 1.1.1.1".into(),
                },
            ),
            ("/etc/resolv.conf/extra", Permission::Rw),
        ]);
        assert!(f.exists(Path::new("/etc/resolv.conf")));
        assert!(!f.exists(Path::new("/etc/resolv.conf/extra")));
        assert!(!f.writable(Path::new("/etc/resolv.conf/extra")));
    }

    #[test]
    fn hide_beats_a_direct_empty_or_inject_match() {
        // A later `empty`/`inject` pattern must not override an earlier
        // `hide` naming the same path.
        let f = fs(&[
            ("/etc/passwd", Permission::Hide),
            ("/etc/passwd", Permission::Empty),
        ]);
        assert!(!f.exists(Path::new("/etc/passwd")));

        let f = fs(&[
            ("/etc/hosts", Permission::Hide),
            (
                "/etc/hosts",
                Permission::Inject {
                    content: "planted".into(),
                },
            ),
        ]);
        assert!(!f.exists(Path::new("/etc/hosts")));
    }

    #[test]
    fn nothing_below_an_empty_path_is_visible_even_with_a_matching_pattern() {
        // `/dev/null` matching an `rw` pattern must not make it (or anything
        // below it) visible inside the empty `/dev` mount point.
        let f = fs(&[
            ("/dev", Permission::Empty),
            ("/dev/null/**", Permission::Rw),
        ]);
        assert!(f.is_empty(Path::new("/dev")));
        assert!(!f.matches(Path::new("/dev/null/deep")));
        assert!(!f.exists(Path::new("/dev/null/deep")));
        assert!(!f.writable(Path::new("/dev/null/deep")));
    }

    #[test]
    fn writable_patterns_are_detected_for_the_mount_options() {
        assert!(!has_writable_patterns(&Patterns(vec![(
            "/etc".to_string(),
            Permission::Ro
        )])));
        assert!(has_writable_patterns(&Patterns(vec![
            ("/etc".to_string(), Permission::Ro),
            ("/tmp/x".to_string(), Permission::Rw),
        ])));
        assert!(!has_writable_patterns(&Patterns(vec![])));
    }

    #[test]
    fn non_utf8_components_fail_closed_for_writes() {
        use std::os::unix::ffi::OsStrExt;
        // A non-UTF-8 component can never match a pattern, so its write
        // permission could never be derived from the spec: deny even
        // under a `**`-covered `rw` mirror that would allow a UTF-8 name.
        let f = fs(&[
            ("/work/**", Permission::Rw),
            ("/work/*secret*", Permission::Hide),
        ]);
        assert!(f.writable(Path::new("/work/plain")));
        let weird = Path::new("/work").join(OsStr::from_bytes(b"\xffsecret\xff"));
        assert!(!f.writable(&weird));
        assert!(!f.exists(&weird));
        // The UTF-8 spelling of the same name stays hidden.
        assert!(!f.writable(Path::new("/work/secret")));
    }

    #[test]
    fn walk_depth_reports_how_deep_a_pattern_reaches() {
        let p = Pattern::new("/etc/*.conf").unwrap();
        assert_eq!(p.walk_depth(Path::new("/etc")), Some((Walk::CouldReach, 1)));
        assert_eq!(
            p.walk_depth(Path::new("/etc/foo.conf")),
            Some((Walk::Exact, 2))
        );
        assert_eq!(p.walk_depth(Path::new("/var")), None);

        let p = Pattern::new("/usr/share/**").unwrap();
        assert_eq!(
            p.walk_depth(Path::new("/usr/share/doc")),
            Some((Walk::StarStar, 2))
        );
        assert_eq!(
            p.walk_depth(Path::new("/usr/share")),
            Some((Walk::StarStar, 2))
        );

        let p = Pattern::new("/etc").unwrap();
        assert_eq!(
            p.walk_depth(Path::new("/etc/passwd")),
            Some((Walk::Ancestor, 1))
        );
    }

    #[test]
    fn restricted_subtrees_block_directory_renames() {
        // The motivating case: `/project/src` is rw, but a followup hide
        // glob might apply to one of its children — the directory must
        // not be renamable (out of, or into, its pattern context).
        let f = fs(&[
            ("/project/src", Permission::Rw),
            ("/project/src/**/*.bin", Permission::Hide),
        ]);
        assert!(f.writable(Path::new("/project/src")));
        assert!(f.subtree_restricted(Path::new("/project/src")));
        // Moving some other directory to /project/src is restricted, too:
        // the *destination* subtree carries the hide rule.
        assert!(f.subtree_restricted(Path::new("/project/src")));
        assert!(!f.subtree_restricted(Path::new("/elsewhere")));
        // Unrelated directories are not restricted.
        assert!(!f.subtree_restricted(Path::new("/other/place")));

        // The same holds for an ro glob below a writable directory.
        let f = fs(&[
            ("/project/src", Permission::Rw),
            ("/project/src/**/*.bin", Permission::Ro),
        ]);
        assert!(f.subtree_restricted(Path::new("/project/src")));

        // An exactly-named ro directory is a recursive mirror: its
        // children are read-only, so it must not be renamable either.
        let f = fs(&[
            ("/project", Permission::Rw),
            ("/project/src", Permission::Ro),
        ]);
        assert!(f.subtree_restricted(Path::new("/project/src")));
        // ...and the writable parent is restricted, too: the ro child
        // (and its subtree) would travel with the rename.
        assert!(f.subtree_restricted(Path::new("/project")));
        // A sibling subtree without the ro rule inside stays free.
        assert!(!f.subtree_restricted(Path::new("/project/other")));
    }

    #[test]
    fn a_writable_recursive_mirror_shadows_ro_ancestors() {
        // A broad ro pattern above a deeper rw mirror: the rw mirror is
        // the nearer mirrored ancestor of everything below it, so the ro
        // pattern never governs the children — renames inside stay free.
        let f = fs(&[("/", Permission::Ro), ("/home/me/work", Permission::Rw)]);
        assert!(!f.subtree_restricted(Path::new("/home/me/work/sub")));
        // Outside the rw mirror the ro ancestor still governs.
        assert!(f.subtree_restricted(Path::new("/home/elsewhere")));

        // A `**` rw pattern shadows equally (it names every child).
        let f = fs(&[("/home", Permission::Ro), ("/home/me/**", Permission::Rw)]);
        assert!(!f.subtree_restricted(Path::new("/home/me/work")));
        // ...but only from below the `**`: /home itself is still ro-governed.
        assert!(f.subtree_restricted(Path::new("/home/other")));

        // Shadowing needs the shadowing pattern to come *after* the
        // restrictive one: here the later ro re-restricts the subtree.
        let f = fs(&[
            ("/home", Permission::Ro),
            ("/home/me/**", Permission::Rw),
            ("/home/me/work/*.key", Permission::Ro),
        ]);
        assert!(f.subtree_restricted(Path::new("/home/me/work")));
    }

    #[test]
    fn an_rw_dir_named_after_the_ro_rule_shadows_it() {
        // The ro pattern names the directory itself; a later rw pattern
        // naming it too hands the children's fallback permission to the
        // writable mirror — renames stay allowed.
        let f = fs(&[
            ("/project/src", Permission::Ro),
            ("/project/src", Permission::Rw),
        ]);
        assert!(!f.subtree_restricted(Path::new("/project/src")));
        // Without the later rw, the ro governs: restricted.
        let f = fs(&[("/project/src", Permission::Ro)]);
        assert!(f.subtree_restricted(Path::new("/project/src")));
    }

    #[test]
    fn hidden_directories_are_always_restricted_subtrees() {
        let f = fs(&[("/project/src", Permission::Hide)]);
        assert!(f.subtree_restricted(Path::new("/project/src")));
        assert!(f.subtree_restricted(Path::new("/project")));
        assert!(!f.subtree_restricted(Path::new("/other")));
    }
}
