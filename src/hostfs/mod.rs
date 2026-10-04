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
use std::ffi::{CString, OsStr, OsString};
use std::io::SeekFrom;
use std::io::{Read, Seek, Write};
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fuse3::raw::reply::{
    DirectoryEntry, DirectoryEntryPlus, FileAttr, ReplyAttr, ReplyCreated, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs, ReplyWrite,
};
use fuse3::raw::{Filesystem, Request};
use fuse3::{FileType, Inode, Result, SetAttr, Timestamp};
use futures_util::stream;

mod anchored;
mod fuse_ops;
pub(crate) mod fuselog;
mod inodes;
pub(crate) mod pattern;
pub(crate) mod patterns;
mod perf;
mod server;
mod session;

pub use server::start_host_fs;

// `new_session_cache_dir` is only referenced by a test outside this
// module (spec/hostfs.rs), so the non-test build warns about it.
#[allow(unused_imports)]
pub use session::{new_session_cache_dir, session_cache_needed, set_session_cache_root};

use fuse_ops::{attr_from_stat, cstring_of};
use inodes::InodeMap;
use patterns::Patterns;

/// Log a failed FUSE op with the mirrored and the real host path (debug
/// helper, only active with `RS_BUBBLE_FUSE_LOG` set) and turn it into an
/// audit event.
async fn log_op_err(op: &str, mirrored: &Path, real: Option<&Path>, err: &std::io::Error) {
    fuselog::event!(
        "FS {op} err={err} mirrored={} real={}",
        fuselog::path_string(mirrored.as_os_str()),
        real.map(|p| fuselog::path_string(p.as_os_str()))
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
        fuselog::path_string(mirrored.as_os_str()),
        fuselog::path_string(real.as_os_str())
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

const TTL: Duration = Duration::from_secs(1);

/// The compiled pattern set, shared between the launcher and the FUSE
/// server so it can be **swapped at runtime**.
///
/// Every FUSE operation reads the currently active set through
/// [`SharedPatterns::load`] (or [`SharedPatterns::snapshot`], where the
/// decision and a validity stamp must come from the same generation) and
/// matches against it on the fly. Swapping is a **full replacement**
/// (`set`), never a delta: the whole compiled list is replaced atomically
/// — a reader sees either the old or the new set, never a mix.
///
/// The set is cheap to clone (an `Arc` bump), so the launcher (`A`) can
/// keep its own authoritative handle while the FUSE server (`FS`) holds
/// another to the same instance; `FS`'s control loop applies a
/// launcher-pushed update with [`SharedPatterns::set`], and every
/// follow-up FUSE request — including reads and writes through
/// *already-open* file handles — applies the new rules. In-flight
/// operations are not interrupted.
///
/// Locks follow the module-wide poisoning convention: a poisoned lock is
/// recovered (`into_inner`), never panicked on.
#[derive(Clone)]
pub struct SharedPatterns {
    inner: std::sync::Arc<SharedPatternsInner>,
}

struct SharedPatternsInner {
    /// The currently active compiled set. Readers clone the `Arc` (a
    /// cheap reference-count bump); a swap replaces the `Arc` under the
    /// write lock.
    current: std::sync::RwLock<std::sync::Arc<Patterns>>,
    /// Bumped on every [`SharedPatterns::set`]. Consumers with derived
    /// state (the readdir [`DirNames`] cache) stamp their entries with it
    /// and treat any other generation as stale — the swap invalidates the
    /// derived state automatically, without walking it.
    generation: std::sync::atomic::AtomicU64,
}

impl SharedPatterns {
    /// Wrap the compiled pattern set (see [`Patterns::new`]).
    pub fn new(patterns: Patterns) -> SharedPatterns {
        SharedPatterns {
            inner: std::sync::Arc::new(SharedPatternsInner {
                current: std::sync::RwLock::new(std::sync::Arc::new(patterns)),
                generation: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// A handle to the currently active set. The `Arc` keeps it alive even
    /// if a swap happens mid-operation: the operation keeps matching
    /// against the set it loaded.
    pub fn load(&self) -> std::sync::Arc<Patterns> {
        self.inner
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The current set *and* its generation, read atomically: for callers
    /// that stamp derived state with the generation.
    pub fn snapshot(&self) -> (std::sync::Arc<Patterns>, u64) {
        let guard = self.inner.current.read().unwrap_or_else(|e| e.into_inner());
        (guard.clone(), self.inner.generation.load(Ordering::SeqCst))
    }

    /// The current generation (bumped on every [`SharedPatterns::set`]).
    // `generation`/`set` have no in-crate caller yet: their consumer is the
    // runtime-control wiring (`control::fs_apply` swaps the set, and the
    // readdir cache reads the generation), which lands with the control
    // channel in the FUSE server's serve loop.
    #[allow(dead_code)]
    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::SeqCst)
    }

    /// Replace the whole pattern set with a newly compiled one. Returns
    /// the new generation. In-flight operations that already loaded the
    /// old set finish against it; every later request applies the new
    /// rules. (See `generation` for why this is currently unused.)
    #[allow(dead_code)]
    pub fn set(&self, patterns: Patterns) -> u64 {
        let mut guard = self
            .inner
            .current
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = std::sync::Arc::new(patterns);
        // Bumped while the write lock is held, so [`SharedPatterns::snapshot`]
        // never pairs a set with the wrong generation.
        self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1
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
/// Mutex poisoning: every lock on the tables below recovers the inner
/// data (`unwrap_or_else(|e| e.into_inner())`) instead of panicking. A
/// panic in one FUSE-op thread must not poison the tables for every
/// later operation — the server is a long-lived fork; a poisoned mutex
/// would turn a single bug into a filesystem that hangs or panics on
/// every subsequent request. The tables' invariants are re-established
/// per operation (each op re-resolves nodeids through [`InodeMap`]), so
/// the recovered data stays usable.
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
    /// The compiled pattern list, in order and **pre-compiled** (by
    /// [`Patterns::new`] at spec-compile time) — the single source of every
    /// permission and structural decision (see
    /// [`Patterns::permission_of`]). Shared with the launcher and
    /// **swappable at runtime** (see [`SharedPatterns`]): every operation
    /// loads the currently active set on the fly, so a swap applies to
    /// every follow-up request without touching open handles or the
    /// session.
    patterns: SharedPatterns,
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
    /// Cached real-entry names per directory inode, validated by the
    /// directory's mtime/ctime (AUDIT.md L14: readdir must not re-list
    /// and re-filter the whole directory on every follow-up call). A
    /// stamped entry stays valid as long as the host directory's
    /// timestamps do *and* the policy generation is unchanged — swapping
    /// the pattern set (see [`SharedPatterns::set`]) invalidates every
    /// cached listing without walking the cache, because the filtered
    /// names depend on the pattern list, not on the host timestamps.
    dir_cache: std::sync::Mutex<HashMap<u64, DirNames>>,
    /// The next `fh` to hand out; 0 is reserved for stateless IO.
    next_fh: AtomicU64,
}

/// A cached directory listing: the host directory's (mtime, mtime-nsec,
/// ctime, ctime-nsec) stamp at listing time, the policy generation the
/// listing was filtered under (a pattern-set swap bumps it and stales
/// every entry — the host directory's timestamps do not change when the
/// patterns do), and the filtered, sorted names. Inode numbers are never
/// reused, so a stale entry can only be memory, never a wrong listing
/// (the stamp and generation checks re-list on change).
struct DirNames {
    stamp: (libc::time_t, libc::c_long, libc::time_t, libc::c_long),
    policy_gen: u64,
    names: Vec<std::ffi::OsString>,
}

/// The number of cached directory listings kept at most (see `dir_cache`).
const DIR_CACHE_MAX: usize = 64;

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
    // No cached `writable` verdict here: the pattern set can be swapped at
    // runtime, so the write path re-checks
    // `patterns.writable(&self.path)` on every write — tightening a
    // mapping `rw` → `ro` must also stop writes through an already-open
    // handle. (The open-time exists/inject/empty checks stay skipped on
    // the handle's fast path: a real handle only comes from
    // `open`/`create`, which established them.)
}

impl HostFs {
    /// Build the filesystem. The patterns arrive already compiled (see
    /// [`Patterns::new`]) and wrapped in a [`SharedPatterns`] — the same
    /// shared instance backs every decision and any later runtime swap.
    fn collect(patterns: &SharedPatterns) -> HostFs {
        HostFs {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            patterns: patterns.clone(),
            root: anchored::RootDir::open()
                .unwrap_or_else(|e| die(&format!("Can't pin the host root directory: {e}"))),
            inodes: std::sync::RwLock::new(InodeMap::new()),
            handles: std::sync::Mutex::new(HashMap::new()),
            dir_cache: std::sync::Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
        }
    }

    /// Allocate a fresh FUSE handle (`fh`) for a newly opened host file.
    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }

    /// The cap on simultaneously open host-file handles (AUDIT.md L14:
    /// unbounded open handles let a malicious command exhaust the FUSE
    /// server's memory and host fds). An open over the cap fails with
    /// ENFILE — the same error the kernel reports when the system-wide
    /// table is full.
    const MAX_HANDLES: usize = 8192;

    /// Register an opened host file under a fresh `fh`. Fails with ENFILE
    /// when the handle table is full. No permission verdict is stored
    /// here: the write path re-checks the (runtime-swappable) pattern set
    /// per request.
    fn insert_handle(
        &self,
        file: std::fs::File,
        path: PathBuf,
        append: bool,
    ) -> std::io::Result<u64> {
        let mut table = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        if table.len() >= Self::MAX_HANDLES {
            return Err(std::io::Error::from_raw_os_error(libc::ENFILE));
        }
        let fh = self.alloc_fh();
        table.insert(
            fh,
            std::sync::Arc::new(OpenHandle {
                file: std::sync::Mutex::new(file),
                path,
                append,
            }),
        );
        Ok(fh)
    }

    /// Take a handle's file out of the table (`release`): dropping the
    /// `OpenHandle` closes the host file.
    fn remove_handle(&self, fh: u64) {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fh);
    }

    /// A cloned reference to the handle's entry, or `None` for an unknown
    /// (or stateless, `fh = 0`) handle — the caller falls back to the
    /// stateless reopen in that case.
    fn handle_of(&self, fh: u64) -> Option<std::sync::Arc<OpenHandle>> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
            .unwrap_or_else(|e| e.into_inner())
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
        self.patterns.load().is_empty(mirrored)
            || self.patterns.load().is_inject(mirrored).is_some()
            || (self.patterns.load().is_empty_prefix(mirrored)
                || self.patterns.load().is_inject_prefix(mirrored))
                && !self.real_exists(&self.patterns.load().redirect(mirrored))
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
        if let Some(content) = self.patterns.load().is_inject(mirrored) {
            return Ok(self.inject_file_attr(content.as_bytes()));
        }
        // Empty paths take precedence: they appear even when the real host
        // path exists (with different attributes) — as an empty directory
        // when the path is (or would be) a directory, as an empty file
        // when it matches a real file.
        if self.patterns.load().is_empty(mirrored) {
            return match self.real_lstat(mirrored) {
                Ok(st) if !Self::stat_is_dir(&st) => Ok(Self::empty_file_attr(&st)),
                _ => Ok(self.empty_dir_attr()),
            };
        }
        let real = self.patterns.load().redirect(mirrored);
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
                    && (self.patterns.load().is_empty_prefix(mirrored)
                        || self.patterns.load().is_inject_prefix(mirrored)) =>
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
        if self.patterns.load().is_empty(mirrored)
            || self.patterns.load().is_empty_prefix(mirrored)
            || self.patterns.load().is_inject_prefix(mirrored)
        {
            return true;
        }
        self.is_host_dir(&self.patterns.load().redirect(mirrored))
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
    fn dir_entries(
        &self,
        mirrored: &Path,
        inode: Inode,
        offset: usize,
    ) -> Vec<(std::ffi::OsString, std::io::Result<FileAttr>)> {
        // One snapshot for the whole listing: the filter decisions, the
        // cache validation and the cached entry's generation must come
        // from the same pattern set, or a swap mid-listing could insert a
        // cache entry stamped with a generation it was not filtered under.
        let (patterns, policy_gen) = self.patterns.snapshot();
        // A directory named by a mirrored pattern itself is a recursive
        // mirror: all of its real entries are visible, not only pattern
        // matches (still minus hidden ones).
        let unfiltered = patterns.matches(mirrored);
        let base_real = patterns.redirect(mirrored);
        let mut dir: Option<std::os::fd::OwnedFd> = None;
        let names: Vec<std::ffi::OsString> = match anchored::open_dir(&self.root, &base_real) {
            Ok(opened) => {
                // `readdir_names` consumes its descriptor (fdopendir/closedir
                // owns it), so it lists a *duplicate*; the original stays
                // pinned below for the entries' attributes.
                let stamp = match anchored::fstat(opened.as_fd()) {
                    Ok(st) => (st.st_mtime, st.st_mtime_nsec, st.st_ctime, st.st_ctime_nsec),
                    Err(_) => (0, 0, 0, 0),
                };
                let mut cache = self.dir_cache.lock().unwrap_or_else(|e| e.into_inner());
                let cached = cache
                    .get(&inode)
                    // A pattern-set swap (a different generation) stales the
                    // entry even though the host timestamps are unchanged:
                    // the filtered names depend on the patterns.
                    .filter(|hit| hit.stamp == stamp && hit.policy_gen == policy_gen)
                    .map(|hit| hit.names.clone());
                let names = cached.unwrap_or_else(|| {
                    if cache.len() > DIR_CACHE_MAX {
                        // Inode numbers are never reused, so entries are
                        // never wrong — they are just memory. Cap the cache
                        // with a blunt clear instead of an LRU.
                        cache.clear();
                    }
                    let mut names: Vec<std::ffi::OsString> = Vec::new();
                    let listing = opened
                        .try_clone()
                        .map(anchored::readdir_names)
                        .unwrap_or_default();
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
                        if patterns.under_empty(&child) || patterns.hidden(&child) {
                            continue;
                        }
                        if unfiltered || patterns.exists(&child) {
                            names.push(name);
                        }
                    }
                    names.sort();
                    cache.insert(
                        inode,
                        DirNames {
                            stamp,
                            policy_gen,
                            names: names.clone(),
                        },
                    );
                    names
                });
                dir = Some(opened);
                names
            }
            // Not a listable directory (or not a real one): the empty
            // listing only leaves the virtual entries below.
            Err(_) => Vec::new(),
        };
        // Virtual entries living directly under this directory (also when
        // the real directory itself cannot be listed): every `empty`,
        // `inject` or `redirect` pattern with a purely literal next
        // component contributes one. Without this a redirected file
        // inside, say, a redirected directory would be lookable
        // (`stat`/`open` resolve it through its redirect) but never
        // listed — readdir would advertise a directory without its
        // visible entries.
        let mut names = names;
        for (name, permission) in patterns.virtual_children(mirrored) {
            let child = mirrored.join(&name);
            if names.iter().any(|n| n.as_os_str() == OsStr::new(&name)) || !patterns.exists(&child)
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
        // Only the requested slice is attributed: the per-call cost is
        // proportional to the reply, not the directory (AUDIT.md L14 —
        // the previous `skip()` re-listed and re-stat'ed the whole
        // directory on every call, making readdir of a large directory
        // quadratic). The sorted, stamp-validated name cache above keeps
        // the repeated listing of one directory to O(1) per follow-up call.
        names
            .into_iter()
            .skip(offset)
            .map(|name| {
                let child = mirrored.join(&name);
                let attr =
                    self.child_attr(dir.as_ref().map(|d| d.as_fd()), &base_real, &child, &name);
                (name, attr)
            })
            .collect()
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
        // One snapshot: the five checks must agree on one pattern set.
        let patterns = self.patterns.load();
        let plain = patterns.is_inject(child).is_none()
            && !patterns.is_empty(child)
            && !patterns.is_empty_prefix(child)
            && !patterns.is_inject_prefix(child)
            && patterns.redirect(child) == child
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

fn die(msg: &str) -> ! {
    crate::sandbox::die(msg)
}

#[cfg(test)]
mod tests;
