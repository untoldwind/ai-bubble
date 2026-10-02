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
//! The FUSE handlers are async (fuse3's trait demands it), but every host
//! operation runs *synchronously* inline: plain `std::fs` calls and raw
//! libc calls. Wrapping them in `tokio::fs`/`spawn_blocking` was measured
//! (see `perf.rs`) to cost far more CPU per op than the syscalls themselves
//! — task spawning, cross-thread handoffs and wakers for what are
//! microsecond-fast local syscalls — while buying no concurrency (the IO
//! was blocking anyway). A genuinely slow host filesystem (a hung network
//! mount) now delays the event loop instead of only the blocking pool; for
//! the local mirror this process serves, that trade is the right one.
//!
//! Symlinks: every access to the **real host filesystem** is dirfd-anchored
//! (see [`anchored`]) — the real path is walked component-wise from a pinned
//! root descriptor with `openat(O_NOFOLLOW|O_DIRECTORY)`, and the final
//! operation runs `*at()`-relative to the pinned parent with
//! `AT_SYMLINK_NOFOLLOW` / `O_NOFOLLOW`. Host paths are never resolved as
//! strings through the kernel's path walking, so a host symlink is never
//! followed — neither a *final* component (a mirrored symlink is visible
//! only *as a symlink*: its target can be read with `readlink`, opening one
//! for reading or writing fails with `ELOOP`) nor an *intermediate* one,
//! which could otherwise re-point a mirrored path at content outside every
//! mapping — deterministically, by swapping a symlink into place between
//! two FUSE requests (audit finding C1). A link's target's content is not
//! exposed unless the target itself matches a pattern.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::SeekFrom;
use std::io::{Read, Seek, Write};
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
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

use crate::sandbox::die_with_error;

pub(crate) mod fuselog;
mod inodes;
pub(crate) mod pattern;
pub(crate) mod patterns;
mod perf;

mod anchored;

use inodes::InodeMap;
use patterns::Patterns;

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
/// `rw` permission (see [`Patterns::write_permission`]).
struct HostFs {
    uid: u32,
    gid: u32,
    /// The spec's pattern list, in order and **pre-compiled** (by
    /// [`Patterns::new`] at spec-compile time) — the single source of every
    /// permission and structural decision (see
    /// [`Patterns::permission_of`]).
    patterns: Patterns,
    /// The pinned host root directory descriptor every host-path walk
    /// anchors on (see [`anchored`]). Host paths are *never* resolved as
    /// strings through the kernel's path walking: each operation walks the
    /// real path component-wise from this descriptor with `openat(
    /// O_NOFOLLOW|O_DIRECTORY)`, so a host symlink at any intermediate
    /// component — pre-existing, or swapped in between FUSE requests — can
    /// never redirect an access outside the mirror (audit finding C1).
    root: anchored::RootDir,
    /// The nodeid ↔ mirrored-path map (see [`inodes`]). There is exactly one
    /// map per FUSE session: the filesystem is *moved* into the mount, and
    /// the mount fallback builds a fresh filesystem (the failed attempt never
    /// reached the kernel, so an empty map is correct there).
    inodes: std::sync::RwLock<InodeMap>,
    /// Open host files keyed by FUSE handle (`fh`): stateful IO — the file
    /// is opened once (`open`/`create`) and reused for every `read`/`write`
    /// on the handle, instead of being reopened per request. `fh = 0` stays
    /// stateless (injected files, directories); an unknown `fh` falls back
    /// to the stateless reopen, so a lost entry degrades instead of failing.
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
    file: std::sync::Mutex<std::fs::File>,
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
    /// Build the filesystem. The patterns arrive already compiled (see
    /// [`Patterns::new`]) — the same compiled list backs every decision.
    fn collect(patterns: &Patterns) -> HostFs {
        HostFs {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            patterns: patterns.clone(),
            root: anchored::RootDir::open()
                .unwrap_or_else(|e| die(&format!("Can't pin the host root directory: {e}"))),
            inodes: std::sync::RwLock::new(InodeMap::new()),
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
        file: std::fs::File,
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
                    file: std::sync::Mutex::new(file),
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
    fn resolve(&self, inode: Inode) -> std::io::Result<PathBuf> {
        self.inodes
            .read()
            .expect("hostfs inode map poisoned")
            .path_of(inode)
            .map(Path::to_path_buf)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))
    }

    /// Whether the path is purely virtual, so its access is answered
    /// directly instead of by the real filesystem: empty paths, injected
    /// paths, and purely virtual ancestors of empty or injected paths
    /// whose real host path does not exist. Such paths are readable
    /// directories (mode 0555) — or injected files — that are never
    /// writable. It stats the real host filesystem (anchored, no-follow).
    fn virtual_only(&self, mirrored: &Path) -> bool {
        self.patterns.is_empty(mirrored)
            || self.patterns.is_inject(mirrored).is_some()
            || (self.patterns.is_empty_prefix(mirrored) || self.patterns.is_inject_prefix(mirrored))
                && !self.real_exists(&self.patterns.redirect(mirrored))
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
    fn empty_file_attr(md: &libc::stat) -> FileAttr {
        let mut attr = attr_from_stat(md);
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
    /// symlink to a directory is not followed — and neither is anything
    /// above it: the check is dirfd-anchored, see [`anchored`]).
    fn is_host_dir(&self, real: &Path) -> bool {
        Self::stat_is_dir(
            &self
                .real_lstat(real)
                .unwrap_or_else(|_| unsafe { std::mem::zeroed() }),
        )
    }

    /// Whether a raw `stat` result describes a directory.
    fn stat_is_dir(st: &libc::stat) -> bool {
        st.st_mode & libc::S_IFMT == libc::S_IFDIR
    }

    /// Whether a raw `stat` result describes a symlink.
    fn stat_is_symlink(st: &libc::stat) -> bool {
        st.st_mode & libc::S_IFMT == libc::S_IFLNK
    }

    /// Anchored `lstat` of a real host path: every component no-follow
    /// (the anchored `symlink_metadata`).
    fn real_lstat(&self, real: &Path) -> std::io::Result<libc::stat> {
        anchored::lstat(&self.root, real)
    }

    /// Whether the real host path exists at all (anchored `lstat` succeeds).
    fn real_exists(&self, real: &Path) -> bool {
        self.real_lstat(real).is_ok()
    }

    /// The `lstat`-style attribute of a mirrored path, or ENOENT. It
    /// stats the real host filesystem.
    fn attr(&self, mirrored: &Path) -> std::io::Result<FileAttr> {
        // Injected paths take precedence over everything: they are purely
        // virtual files served from memory.
        if let Some(content) = self.patterns.is_inject(mirrored) {
            return Ok(self.inject_file_attr(content.as_bytes()));
        }
        // Empty paths take precedence: they appear even when the real host
        // path exists (with different attributes) — as an empty directory
        // when the path is (or would be) a directory, as an empty file
        // when it matches a real file.
        if self.patterns.is_empty(mirrored) {
            return match self.real_lstat(mirrored) {
                Ok(st) if !Self::stat_is_dir(&st) => Ok(Self::empty_file_attr(&st)),
                _ => Ok(self.empty_dir_attr()),
            };
        }
        let real = self.patterns.redirect(mirrored);
        match self.real_lstat(&real) {
            Ok(md) => Ok(attr_from_stat(&md)),
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
                    && (self.patterns.is_empty_prefix(mirrored)
                        || self.patterns.is_inject_prefix(mirrored)) =>
            {
                Ok(self.empty_dir_attr())
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the mirrored path is a listable directory: a real one (a
    /// host symlink to a directory is not followed), an empty
    /// path, or a purely virtual ancestor of an empty path. It
    /// stats the real host filesystem.
    fn is_listable_dir(&self, mirrored: &Path) -> bool {
        if self.patterns.is_empty(mirrored)
            || self.patterns.is_empty_prefix(mirrored)
            || self.patterns.is_inject_prefix(mirrored)
        {
            return true;
        }
        self.is_host_dir(&self.patterns.redirect(mirrored))
    }

    /// The visible entries of a mirrored directory, sorted by name: every
    /// real entry that matches a pattern (directly or as an ancestor of a
    /// match) — and, when the directory is itself matched by a pattern, all
    /// of its real entries. Everything below an empty path is shadowed by
    /// its precedence; empty paths that live directly under the directory
    /// are always shown. Symlinks are never followed: a host symlink
    /// standing for the directory is not listed through. It reads and
    /// stats the real host directory, with the directory's descriptor
    /// pinned before the entries are listed and each entry's attributes
    /// taken from that descriptor (anchored, see [`anchored`]).
    fn dir_entries(&self, mirrored: &Path) -> Vec<(std::ffi::OsString, std::io::Result<FileAttr>)> {
        // A directory named by a mirrored pattern itself is a recursive
        // mirror: all of its real entries are visible, not only pattern
        // matches (still minus hidden ones).
        let unfiltered = self.patterns.matches(mirrored);
        let base_real = self.patterns.redirect(mirrored);
        let mut dir: Option<std::os::fd::OwnedFd> = None;
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        if let Ok(opened) = anchored::open_dir(&self.root, &base_real) {
            // `readdir_names` consumes its descriptor (fdopendir/closedir
            // own it), so it lists a *duplicate*; the original stays
            // pinned below for the entries' attributes.
            let listing = opened
                .try_clone()
                .map(anchored::readdir_names)
                .unwrap_or_default();
            dir = Some(opened);
            for name in listing {
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
                if self.patterns.under_empty(&child) || self.patterns.hidden(&child) {
                    continue;
                }
                if unfiltered || self.patterns.exists(&child) {
                    names.push(name);
                }
            }
            // Not a listable directory (or not a real one): the empty
            // listing only leaves the virtual entries below.
        }
        // Virtual entries living directly under this directory (also when
        // the real directory itself cannot be listed): every `empty`,
        // `inject` or `redirect` pattern with a purely literal next
        // component contributes one. Without this a redirected file
        // inside, say, a redirected directory would be lookable
        // (`stat`/`open` resolve it through its redirect) but never
        // listed — readdir would advertise a directory without its
        // visible entries.
        for (name, permission) in self.patterns.virtual_children(mirrored) {
            let child = mirrored.join(&name);
            if names.iter().any(|n| n.as_os_str() == OsStr::new(&name))
                || !self.patterns.exists(&child)
            {
                continue;
            }
            // A redirected entry is only listed when the redirect target
            // really exists on the host — otherwise the entry would
            // advertise a lookup that fails (an undeletable "ghost").
            if let Some(source) = permission.redirect_source()
                && !self.real_exists(source)
            {
                continue;
            }
            names.push(OsString::from(name));
        }
        names.sort();
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let child = mirrored.join(&name);
            let attr = self.child_attr(dir.as_ref().map(|d| d.as_fd()), &base_real, &child, &name);
            entries.push((name, attr));
        }
        entries
    }

    /// The attributes of one listed child. Fast path: when the child's
    /// real host path is exactly the listed directory joined with its name
    /// (no redirect anywhere in between), the child is stat'ed on the
    /// directory descriptor the listing came from — no second walk. Any
    /// virtual or redirected child (and any path the pinned descriptor
    /// cannot answer for) falls back to the plain anchored
    /// [`HostFs::attr`].
    fn child_attr(
        &self,
        dir: Option<std::os::fd::BorrowedFd<'_>>,
        base_real: &Path,
        child: &Path,
        name: &OsStr,
    ) -> std::io::Result<FileAttr> {
        // Virtual children (empty paths, injected files and their purely
        // virtual ancestors) never resolve inside the listed directory.
        let plain = self.patterns.is_inject(child).is_none()
            && !self.patterns.is_empty(child)
            && !self.patterns.is_empty_prefix(child)
            && !self.patterns.is_inject_prefix(child)
            && self.patterns.redirect(child) == child
            && base_real.join(name) == child;
        if plain && let Some(dir) = dir {
            let cname = cstring_of(Path::new(name))?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: valid descriptor, NUL-terminated name, writable buffer.
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    cname.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(attr_from_stat(&st));
        }
        self.attr(child)
    }
}

/// The attribute of a raw `stat` — same conversion as
/// [`attr_from_metadata`], for the dirfd-anchored stat results (see
/// [`anchored`]). `ino` is filled in by the reply sites that know it.
fn attr_from_stat(st: &libc::stat) -> FileAttr {
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    };
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: st.st_size as u64,
        blocks: st.st_blocks as u64,
        atime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_atime.max(0) as u64, st.st_atime_nsec.max(0) as u32))
        .into(),
        mtime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_mtime.max(0) as u64, st.st_mtime_nsec.max(0) as u32))
        .into(),
        ctime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_ctime.max(0) as u64, st.st_ctime_nsec.max(0) as u32))
        .into(),
        kind,
        perm: (st.st_mode & 0o7777) as u16,
        nlink: st.st_nlink as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev as u32,
        blksize: st.st_blksize as u32,
    }
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
        let path = self
            .inodes
            .write()
            .expect("hostfs inode map poisoned")
            .forget(inode);
        fuselog::event!(
            "INODE forget inode={inode} nlookup={nlookup} path={}",
            path.map(|p| fuselog::path_string(p.as_os_str()))
                .unwrap_or_else(|| "<gone>".into())
        );
    }

    async fn batch_forget(&self, _req: Request, inodes: &[Inode]) {
        perf::fuse_op!("batch_forget");
        let mut map = self.inodes.write().expect("hostfs inode map poisoned");
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
        let parent_path = match self.resolve(parent) {
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
        if self.patterns.exists(&mirrored) {
            match self.attr(&mirrored) {
                Ok(mut attr) => {
                    let inode = self
                        .inodes
                        .write()
                        .expect("hostfs inode map poisoned")
                        .get_or_insert(&mirrored, parent);
                    attr.ino = inode;
                    return Ok(ReplyEntry {
                        ttl: TTL,
                        attr,
                        generation: 0,
                    });
                }
                Err(e) => {
                    log_op_err(
                        "lookup",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // The kernel dentry is stale: drop the mapping so the
                        // next lookup re-maps the path (a zombie stays while
                        // open handles remain).
                        self.inodes
                            .write()
                            .expect("hostfs inode map poisoned")
                            .release_path(&mirrored);
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
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .release_path(&mirrored);
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
        let mirrored = match self.resolve(inode) {
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
        if self.patterns.exists(&mirrored) {
            match self.attr(&mirrored) {
                Ok(mut attr) => {
                    attr.ino = inode;
                    return Ok(ReplyAttr { ttl: TTL, attr });
                }
                Err(e) => {
                    log_op_err(
                        "getattr",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
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
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        let target = anchored::read_link(&self.root, &self.patterns.redirect(&mirrored))?;
        Ok(ReplyData::from(Bytes::copy_from_slice(
            target.as_os_str().as_encoded_bytes(),
        )))
    }

    async fn open(&self, _req: Request, inode: Inode, flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("open");
        let mirrored = self.resolve(inode)?;
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not).
        if !self.patterns.exists(&mirrored) {
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
        if let Some(_content) = self.patterns.is_inject(&mirrored) {
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
            self.inodes
                .write()
                .expect("hostfs inode map poisoned")
                .open_handle(inode);
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        // An `empty` path is blanked out of the sandbox: like an injected
        // path it is a purely virtual file (served as empty, never writable,
        // the host file — which may really exist — is never opened). Without
        // this check, opening a real host file under an `empty` mapping would
        // register a stateful handle serving the real bytes, defeating the
        // mapping (the stateless read path already serves zero bytes for
        // empty paths; only the handle fast-path bypasses the spec check).
        if self.patterns.is_empty(&mirrored) {
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
            self.inodes
                .write()
                .expect("hostfs inode map poisoned")
                .open_handle(inode);
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not), and
        // symlinks are never followed: a host symlink cannot be opened
        // through the mirror (its target may not be mirrored at all). The
        // metadata is taken from the dirfd-anchored path: no intermediate
        // component may resolve through a host symlink.
        let real = self.patterns.redirect(&mirrored);
        let md_stat = match self.real_lstat(&real) {
            Ok(st) => st,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&real), &e).await;
                // A purely virtual directory (ancestor of an empty or
                // injected path with no real counterpart) is not openable,
                // exactly like a real one that `open` refuses: report it as
                // a directory rather than as missing (the kernel only asks
                // to open directories it has already resolved).
                if e.kind() == std::io::ErrorKind::NotFound
                    && (self.patterns.is_empty_prefix(&mirrored)
                        || self.patterns.is_inject_prefix(&mirrored))
                {
                    return Err(libc::EISDIR.into());
                }
                return Err(libc::ENOENT.into());
            }
        };
        if Self::stat_is_symlink(&md_stat) {
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
                &std::io::Error::from_raw_os_error(libc::ELOOP),
            )
            .await;
            return Err(libc::ELOOP.into());
        }
        if Self::stat_is_dir(&md_stat) {
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
                &std::io::Error::from_raw_os_error(libc::EISDIR),
            )
            .await;
            return Err(libc::EISDIR.into());
        }
        let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
        if write_flags && !self.patterns.writable(&mirrored) {
            // `ro` paths (and anything below an empty or hidden pattern) are
            // never writable; the real file permissions are checked by the
            // host filesystem on the actual write.
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
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
        let mut oflags = if !write_flags {
            libc::O_RDONLY
        } else if flags & libc::O_RDWR as u32 != 0 {
            libc::O_RDWR
        } else {
            libc::O_WRONLY
        };
        if append {
            oflags |= libc::O_APPEND;
        }
        if write_flags && flags & libc::O_TRUNC as u32 != 0 {
            oflags |= libc::O_TRUNC;
        }
        // Anchored open relative to the pinned parent, final component
        // `O_NOFOLLOW` (see [`anchored`]).
        let file = match anchored::open_at(&self.root, &real, oflags, 0) {
            Ok(f) => f,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&real), &e).await;
                return Err(e.into());
            }
        };
        // Stateful IO: the opened host file is reused for every read/write
        // on this handle (released with it in `release`).
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .open_handle(inode);
        let writable = self.patterns.writable(&mirrored);
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
            // consulted on this fast path. The guard's scope ends before any
            // await (a std MutexGuard is not Send, and the sync IO makes the
            // await-free block trivial).
            let read_result = {
                let mut file = handle.file.lock().expect("hostfs handle poisoned");
                file.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; size as usize];
                file.read(&mut buf).map(|n| {
                    buf.truncate(n);
                    buf
                })
            };
            let buf = match read_result {
                Ok(buf) => buf,
                Err(e) => {
                    log_op_err(
                        "read-io",
                        &handle.path,
                        Some(&self.patterns.redirect(&handle.path)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
            return Ok(ReplyData::from(Bytes::from(buf)));
        }
        let mirrored = match self.resolve(inode) {
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
        if !self.patterns.exists(&mirrored) {
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
        if let Some(content) = self.patterns.is_inject(&mirrored) {
            let bytes = content.as_bytes();
            let offset = offset.min(bytes.len() as u64) as usize;
            let end = (offset + size as usize).min(bytes.len());
            return Ok(ReplyData::from(Bytes::copy_from_slice(&bytes[offset..end])));
        }
        // An empty path has no content: an empty file reads as empty (the
        // host file is never opened).
        if self.patterns.is_empty(&mirrored) {
            return Ok(ReplyData::from(Bytes::new()));
        }
        // Stateless IO fallback: reopen the host file relative to the pinned
        // parent — never following symlinks (a host symlink is visible only
        // as a link, and its target may not be mirrored at all; and no
        // intermediate component is followed either).
        let mut file = match anchored::open_at(
            &self.root,
            &self.patterns.redirect(&mirrored),
            libc::O_RDONLY,
            0,
        ) {
            Ok(f) => f,
            Err(e) => {
                log_op_err(
                    "read",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
                return Err(e.into());
            }
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size as usize];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                log_op_err(
                    "read-io",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
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
            None => match self.resolve(inode) {
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
            None => self.patterns.writable(&mirrored),
        };
        if handle.is_none() && !self.patterns.exists(&mirrored) {
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
                Some(&self.patterns.redirect(&mirrored)),
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
            // The guard's scope ends before any await (a std MutexGuard is
            // not Send, and the sync IO makes the await-free block trivial).
            let write_result = {
                let mut file = handle.file.lock().expect("hostfs handle poisoned");
                if !handle.append {
                    file.seek(SeekFrom::Start(offset))?;
                }
                file.write(data)
            };
            let n = match write_result {
                Ok(n) => n,
                Err(e) => {
                    log_op_err(
                        "write-io",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
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
            return Ok(ReplyWrite { written: n as u32 });
        }
        // Stateless IO fallback: reopen the host file relative to the pinned
        // parent — never following symlinks (a host symlink is never
        // written through; its target may not be mirrored at all; and no
        // intermediate component is followed either).
        let mut oflags = libc::O_WRONLY;
        if append {
            oflags |= libc::O_APPEND;
        }
        let mut file =
            match anchored::open_at(&self.root, &self.patterns.redirect(&mirrored), oflags, 0) {
                Ok(f) => f,
                Err(e) => {
                    log_op_err(
                        "write",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
        if !append {
            file.seek(SeekFrom::Start(offset))?;
        }
        let n = match file.write(data) {
            Ok(n) => n,
            Err(e) => {
                log_op_err(
                    "write-io",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
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
        let mirrored = self.resolve(inode)?;
        // An injected path has no host counterpart: report a minimal,
        // self-consistent statfs instead of opening anything. The same
        // holds for a purely virtual ancestor of an injected (or empty)
        // path with no real counterpart: it is a virtual directory, and
        // there is nothing to open on the host.
        if self.patterns.is_inject(&mirrored).is_some()
            || (self.patterns.is_empty_prefix(&mirrored)
                || self.patterns.is_inject_prefix(&mirrored))
                && !self.real_exists(&self.patterns.redirect(&mirrored))
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
        let real = if is_root(mirrored.as_os_str()) {
            PathBuf::from("/")
        } else {
            self.patterns.redirect(&mirrored)
        };
        // O_PATH works on any file type (including directories) and
        // O_NOFOLLOW keeps symlinked final components from being followed —
        // anchored, so intermediate components are not either.
        let fd = match anchored::open_full(&self.root, &real, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(e) => return Err(e.into()),
        };
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor and a writable `statvfs` buffer.
        let rc = unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut vfs) };
        let err = std::io::Error::last_os_error();
        drop(fd);
        if rc != 0 {
            return Err(err.into());
        }
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
    }

    async fn opendir(&self, _req: Request, inode: Inode, _flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("opendir");
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .open_handle(inode);
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
        let mirrored = self.resolve(parent)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .into_iter()
            .skip(offset.max(0) as usize)
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid.
        let mut map = self.inodes.write().expect("hostfs inode map poisoned");
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
        let mirrored = self.resolve(parent)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .into_iter()
            .skip(offset as usize)
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid — and carries
        // its attributes with the nodeid filled in.
        let mut map = self.inodes.write().expect("hostfs inode map poisoned");
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
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // Empty paths (and purely virtual ancestors) are unwritable by
        // definition; answer directly instead of asking the real filesystem.
        // Injected paths are virtual, too: readable, never writable. The
        // same holds for purely virtual ancestors of injected files: the
        // kernel consults `access` for `chdir` (MAY_CHDIR), so an
        // unanswered ENOENT here would make a directory that `ls` lists
        // and `stat` resolves impossible to `cd` into.
        if self.virtual_only(&mirrored) {
            if mask & libc::W_OK as u32 != 0 {
                return Err(libc::EACCES.into());
            }
            return Ok(());
        }
        // W_OK is answered by the spec: only `rw` paths may be written (the
        // real file permissions are checked when a write is attempted).
        let non_write = mask & !(libc::W_OK as u32);
        if mask & libc::W_OK as u32 != 0 && !self.patterns.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        // The rest (R_OK, X_OK) is decided by the real filesystem, with the
        // server's real (host) credentials.
        if non_write == 0 {
            return Ok(());
        }
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real).map_err(|e| {
            // ENOENT mapping preserved from the old cpath construction.
            if e.raw_os_error() == Some(libc::EINVAL) {
                return std::io::Error::from_raw_os_error(libc::ENOENT);
            }
            e
        })?;
        // `faccessat` with `AT_SYMLINK_NOFOLLOW` on the pinned parent —
        // never follow symlinks (final component or otherwise) when
        // deciding access on the real host filesystem.
        if unsafe {
            libc::faccessat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                non_write as libc::c_int,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
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
        let mirrored = self.resolve(inode)?;
        if self.patterns.is_empty(&mirrored) {
            // Empty paths are virtual: nothing to change.
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        let real = self.patterns.redirect(&mirrored);
        // Anchor the parent once: every operation below is an `*at()`
        // syscall relative to the pinned parent descriptor, so no component
        // of the path can resolve through a host symlink (final-component
        // no-follow semantics are kept per operation, as before).
        let anchored = anchored::anchor_parent(&self.root, &real)?;
        let dirfd = anchored.dir().as_raw_fd();
        let name = anchored.name().as_ptr();
        if let Some(size) = set_attr.size {
            // Never follow symlinks: a host symlink is not truncated
            // through (its target may not be mirrored at all).
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    name,
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            let f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
            f.set_len(size)?;
        }
        if let Some(mode) = set_attr.mode {
            // fchmodat without AT_SYMLINK_NOFOLLOW keeps the old chmod
            // semantics for the final component (it follows a symlink
            // standing there, see finding M4); the anchored parent keeps
            // every intermediate component honest.
            if unsafe { libc::fchmodat(dirfd, name, mode as libc::mode_t, 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            let uid = set_attr.uid.unwrap_or(u32::MAX);
            let gid = set_attr.gid.unwrap_or(u32::MAX);
            if unsafe { libc::fchownat(dirfd, name, uid, gid, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if set_attr.atime.is_some() || set_attr.mtime.is_some() {
            let times = [
                ts_to_timespec(set_attr.atime),
                ts_to_timespec(set_attr.mtime),
            ];
            if unsafe { libc::utimensat(dirfd, name, times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let mut attr = self.attr(&mirrored)?;
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
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only a *real* entry at the target means EEXIST; a path merely
        // matched by a wildcard pattern may not exist yet. (Anchored:
        // no symlink is followed anywhere on the host path.)
        if self.real_exists(&self.patterns.redirect(&mirrored)) {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EEXIST),
            )
            .await;
            return Err(libc::EEXIST.into());
        }
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real).map_err(|e| {
            if e.raw_os_error() == Some(libc::EINVAL) {
                return std::io::Error::from_raw_os_error(libc::ENOENT);
            }
            e
        })?;
        let rc = unsafe {
            libc::mkdirat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        if rc != 0 {
            // Capture the error right after the syscall (errno is per-thread
            // and any intervening call would clobber it).
            let e = std::io::Error::last_os_error();
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            return Err(fuse3::Errno::from(e));
        }
        log_op_ok("mkdir", &mirrored, &self.patterns.redirect(&mirrored)).await;
        let inode = self
            .inodes
            .write()
            .expect("hostfs inode map poisoned")
            .get_or_insert(&mirrored, parent);
        let mut attr = self.attr(&mirrored)?;
        attr.ino = inode;
        Ok(ReplyEntry {
            ttl: TTL,
            attr,
            generation: 0,
        })
    }

    async fn unlink(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("unlink");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if self.patterns.is_empty(&mirrored) {
            // Empty paths are virtual mount points; they cannot be removed.
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&mirrored))?;
        if unsafe { libc::unlinkat(anchored.dir().as_raw_fd(), anchored.name().as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            log_op_err(
                "unlink",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes
                    .write()
                    .expect("hostfs inode map poisoned")
                    .release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::EISDIR) {
                // Unlinking a directory: the kernel keeps the dentry, so the
                // name must stay resolvable.
                self.inodes
                    .write()
                    .expect("hostfs inode map poisoned")
                    .get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("unlink", &mirrored, &self.patterns.redirect(&mirrored)).await;
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .release_path(&mirrored);
        Ok(())
    }
    async fn rmdir(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("rmdir");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if self.patterns.is_empty(&mirrored) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&mirrored))?;
        if unsafe {
            libc::unlinkat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            log_op_err(
                "rmdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes
                    .write()
                    .expect("hostfs inode map poisoned")
                    .release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                // Rmdir of a non-directory: the kernel keeps the dentry, so
                // the name must stay resolvable.
                self.inodes
                    .write()
                    .expect("hostfs inode map poisoned")
                    .get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("rmdir", &mirrored, &self.patterns.redirect(&mirrored)).await;
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .release_path(&mirrored);
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
        let origin_parent_path = self.resolve(origin_parent)?;
        let new_parent_path = self.resolve(parent)?;
        let old = origin_parent_path.join(origin_name);
        let new = new_parent_path.join(name);
        if self.patterns.is_empty(&old) || self.patterns.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&old) {
            log_op_err(
                "rename",
                &old,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&old) || !self.patterns.writable(&new) {
            log_op_err(
                "rename",
                &old,
                Some(&self.patterns.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let old_real = self.patterns.redirect(&old);
        let new_real = self.patterns.redirect(&new);
        // A *directory* rename carries every child from one pattern
        // context to another: a `hide` or `ro` rule that might apply to a
        // child of the source (or of the destination) must block the
        // move. Moving the directory out of such a rule's reach would
        // expose — or make writable — content the spec hides or keeps
        // read-only (e.g. `/project/src` is `rw` but
        // `/project/src/**/*.bin` is `hide`); moving another directory
        // *into* such a subtree is denied as well, so content cannot be
        // planted there and carried back out with the same effect.
        let dir_rename = self.is_host_dir(&old_real) || self.is_host_dir(&new_real);
        if dir_rename
            && (self.patterns.subtree_restricted(&old) || self.patterns.subtree_restricted(&new))
        {
            log_op_err(
                "rename",
                &old,
                Some(&new_real),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Both parents are pinned before the atomic `renameat` between
        // them: no component of either path can resolve through a host
        // symlink, and a swap between the two resolutions cannot re-point
        // either name (the operation acts *inside* the pinned directories).
        let old_anchored = anchored::anchor_parent(&self.root, &old_real)?;
        let new_anchored = anchored::anchor_parent(&self.root, &new_real)?;
        if unsafe {
            libc::renameat(
                old_anchored.dir().as_raw_fd(),
                old_anchored.name().as_ptr(),
                new_anchored.dir().as_raw_fd(),
                new_anchored.name().as_ptr(),
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            log_op_err("rename", &old, Some(&new_real), &e).await;
            return Err(e.into());
        }
        log_op_ok("rename", &old, &new_real).await;

        // The kernel moves the dentry on rename, re-hashing `old` as `new`
        // *keeping the source's nodeid*. Re-point the new path at the source
        // nodeid — dropping the overwritten target's mapping, which the
        // kernel is about to forget — so every operation arriving on the
        // moved dentry still resolves (see `FINDINGS.md`).
        let mut map = self.inodes.write().expect("hostfs inode map poisoned");
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
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        log_op_err(
            "symlink",
            &mirrored,
            Some(&self.patterns.redirect(&mirrored)),
            &std::io::Error::from_raw_os_error(libc::EACCES),
        )
        .await;
        Err(libc::EACCES.into())
    }

    /// Create a hard link: the new name points at the *same real host file*
    /// as the source (`linkat` on the host filesystem), so writes through
    /// either name are visible through both. The new name gets a **fresh
    /// nodeid** mapping to the new path: the mirror's pattern permissions
    /// are decided per path, and a hard-linked name is an independent path
    /// (the source nodeid keeps its mapping; renaming one name must not
    /// affect the other's).
    ///
    /// The source is **never followed**: a host symlink at the source name is
    /// linked as the link itself (re-created with the same target — Linux
    /// `linkat` cannot no-follow the source), because its target may live
    /// outside every mapping and following it would be a variant of the C1
    /// escape the anchored resolution closes.
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
        let source_path = self.resolve(inode)?;
        let new_parent_path = self.resolve(new_parent)?;
        let old = source_path;
        let new = new_parent_path.join(new_name);
        if self.patterns.is_empty(&old) || self.patterns.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&old) {
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
        if !self.patterns.writable(&old) {
            log_op_err(
                "link",
                &old,
                Some(&self.patterns.redirect(&old)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if !self.patterns.writable(&new) {
            log_op_err(
                "link",
                &new,
                Some(&self.patterns.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Both parents pinned. The source entry is stat'ed first (anchored): a
        // host symlink standing at the source name must be linked *as a
        // link*, never followed to its target — the target may live
        // outside every mapping, and following it here would be a variant
        // of the C1 escape (Linux `linkat` cannot no-follow the source, so
        // a link source is re-created as an identical symlink instead). The
        // check and the syscall below run in one await-free block — on the
        // single-threaded runtime nothing can swap the entry in between.
        let old_anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&old))?;
        let new_anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&new))?;
        let source_stat = anchored::stat_entry(&old_anchored)?;
        let link_result = if Self::stat_is_symlink(&source_stat) {
            let target = anchored::read_link_at(&old_anchored)?;
            let ctarget = cstring_of(Path::new(&target))?;
            // SAFETY: valid descriptors and NUL-terminated names.
            unsafe {
                libc::symlinkat(
                    ctarget.as_ptr(),
                    new_anchored.dir().as_raw_fd(),
                    new_anchored.name().as_ptr(),
                )
            }
        } else {
            // SAFETY: valid descriptors and NUL-terminated names.
            unsafe {
                libc::linkat(
                    old_anchored.dir().as_raw_fd(),
                    old_anchored.name().as_ptr(),
                    new_anchored.dir().as_raw_fd(),
                    new_anchored.name().as_ptr(),
                    0,
                )
            }
        };
        if link_result != 0 {
            let e = std::io::Error::last_os_error();
            log_op_err("link", &new, Some(&self.patterns.redirect(&new)), &e).await;
            return Err(e.into());
        }
        log_op_ok("link", &new, &self.patterns.redirect(&new)).await;
        let inode = self
            .inodes
            .write()
            .expect("hostfs inode map poisoned")
            .get_or_insert(&new, new_parent);
        let mut attr = self.attr(&new)?;
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
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        let writable = self.patterns.writable(&mirrored);
        if !writable {
            log_op_err(
                "create",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only with O_EXCL does a *real* entry at the target mean EEXIST;
        // a plain O_CREAT (without O_EXCL) opens an existing file like the
        // host filesystem would. A path merely matched by a wildcard
        // pattern may not exist yet. The parent is pinned first and the
        // existing-entry check runs on it (`fstatat(AT_SYMLINK_NOFOLLOW)`):
        // a host symlink standing at the target is never followed — neither
        // by the check nor by the open below.
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real)?;
        let excl = flags & libc::O_EXCL as u32 != 0;
        let truncate = flags & libc::O_TRUNC as u32 != 0;
        let append = flags & libc::O_APPEND as u32 != 0;
        let existing = anchored::stat_entry(&anchored).ok();
        if let Some(st) = existing {
            if Self::stat_is_symlink(&st) {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::ELOOP),
                )
                .await;
                return Err(libc::ELOOP.into());
            }
            if excl {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::EEXIST),
                )
                .await;
                return Err(libc::EEXIST.into());
            }
            if Self::stat_is_dir(&st) {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::EISDIR),
                )
                .await;
                return Err(libc::EISDIR.into());
            }
            let mut oflags = libc::O_WRONLY;
            if truncate {
                oflags |= libc::O_TRUNC;
            }
            if append {
                oflags |= libc::O_APPEND;
            }
            let file = match anchored::open_at(&self.root, &real, oflags, 0) {
                Ok(f) => f,
                Err(e) => {
                    log_op_err("create", &mirrored, Some(&real), &e).await;
                    return Err(e.into());
                }
            };
            let md = file.metadata()?;
            log_op_ok("create", &mirrored, &real).await;
            let inode = self
                .inodes
                .write()
                .expect("hostfs inode map poisoned")
                .get_or_insert(&mirrored, parent);
            self.inodes
                .write()
                .expect("hostfs inode map poisoned")
                .open_handle(inode);
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
        let base = if flags & libc::O_RDWR as u32 != 0 {
            libc::O_RDWR
        } else {
            libc::O_WRONLY
        };
        let mut oflags = libc::O_CREAT | libc::O_EXCL | base;
        if append {
            oflags |= libc::O_APPEND;
        }
        let file =
            match anchored::open_at(&self.root, &real, oflags, (mode & 0o7777) as libc::mode_t) {
                Ok(f) => f,
                Err(e) => {
                    log_op_err("create-new", &mirrored, Some(&real), &e).await;
                    return Err(e.into());
                }
            };
        let md = file.metadata()?;
        let mut attr = attr_from_metadata(&md);
        log_op_ok("create-new", &mirrored, &real).await;
        let inode = self
            .inodes
            .write()
            .expect("hostfs inode map poisoned")
            .get_or_insert(&mirrored, parent);
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .open_handle(inode);
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
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .close_handle(inode);
        Err(libc::ENOSYS.into())
    }

    async fn releasedir(&self, _req: Request, inode: Inode, _fh: u64, _flags: u32) -> Result<()> {
        perf::fuse_op!("releasedir");
        self.inodes
            .write()
            .expect("hostfs inode map poisoned")
            .close_handle(inode);
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
            let handle =
                match mount_with_fallback(&mp, uid, gid, &patterns, !patterns.any_writable()).await
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
                outcome = lazy_unmount(&server_mountpoint);
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
fn lazy_unmount(mountpoint: &Path) -> std::io::Result<()> {
    let via_fusermount = match std::process::Command::new("fusermount3")
        .args(["-uz"])
        .arg(mountpoint)
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
}

fn die(msg: &str) -> ! {
    crate::sandbox::die(msg)
}

#[cfg(test)]
mod tests;
