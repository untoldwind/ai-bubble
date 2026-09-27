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
//! server unmounts and exits.
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

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::SeekFrom;
use std::num::NonZeroU32;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fuse3::path::reply::{
    DirectoryEntry, DirectoryEntryPlus, FileAttr, ReplyAttr, ReplyCreated, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs, ReplyWrite,
};
use fuse3::path::{PathFilesystem, Session};
use fuse3::{FileType, MountOptions, Result, SetAttr, Timestamp};
use futures_util::stream;

use tokio::fs as tokio_fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::sandbox::die_with_error;
use crate::spec::internal::{Patterns, Permission};

pub(crate) mod pattern;
use pattern::{Pattern, Walk};

/// The effective permission of a mirrored path under the given pattern list,
/// with the same semantics the FUSE mirror applies:
///
/// * a strict ancestor exposed `empty` shadows everything below it —
///   nothing below an empty path is visible (`None`),
/// * otherwise the **last** pattern naming the path itself decides —
///   including `hide` (a hidden path is not visible) and `empty`,
/// * otherwise a `hide` pattern naming a strict ancestor hides the
///   whole subtree (`hide`),
/// * otherwise the permission of the **nearest** mirrored (`ro`/`rw`)
///   ancestor is inherited: an exactly-named or `**`-covered directory
///   is a recursive mirror, so its permission governs everything below,
/// * otherwise the path is not visible in the sandbox at all (`None`).
///
/// This lives with the matcher rather than with [`Patterns`] because the
/// glob engine is hostfs-internal (and the build-time schema generation
/// compiles `spec` without it).
pub fn permission_of(patterns: &Patterns, path: &Path) -> Option<Permission> {
    let compiled: Vec<(Pattern, Permission)> = patterns
        .iter()
        .filter_map(|(pattern, permission)| {
            Pattern::new(pattern)
                .ok()
                .map(|compiled| (compiled, permission.clone()))
        })
        .collect();
    let direct = |p: &Path| {
        compiled
            .iter()
            .rev()
            .find(|(compiled, _)| compiled.matches(p))
            .map(|(_, permission)| permission.clone())
    };

    // Everything strictly below an empty path is invisible.
    if path
        .ancestors()
        .skip(1)
        .any(|a| direct(a) == Some(Permission::Empty))
    {
        return None;
    }

    // The last pattern naming the path itself decides.
    if let Some(permission) = direct(path) {
        return Some(permission);
    }

    // A hidden directory hides its whole subtree.
    if compiled
        .iter()
        .any(|(p, permission)| *permission == Permission::Hide && p.walk(path) == Walk::Ancestor)
    {
        return Some(Permission::Hide);
    }

    // Otherwise the nearest mirrored ancestor governs: the mirror is
    // recursive, so its permission extends to everything below it.
    path.ancestors()
        .skip(1)
        .find_map(|a| direct(a).filter(|p| p.is_mirrored()))
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
/// mappings), wiped when rs-bubble terminates. Set by the sandbox parent
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
/// [`set_session_cache_root`] so it is wiped when rs-bubble terminates.
pub fn new_session_cache_dir() -> PathBuf {
    let mut tmpl: Vec<u8> = b"/tmp/rs-bubble.cache.XXXXXX".to_vec();
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
#[derive(Clone)]
struct HostFs {
    uid: u32,
    gid: u32,
    patterns: Vec<MirrorPattern>,
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
        }
    }

    /// Whether the mirrored path is matched with the `empty` permission (by
    /// the last pattern naming it): it is exposed empty — as an empty
    /// directory when it is (or would be) a directory, an empty file when
    /// it matches a real file.
    fn is_empty(&self, mirrored: &Path) -> bool {
        self.permission_of(mirrored) == Some(Permission::Empty)
    }

    /// Whether the mirrored path lies strictly *below* an empty path (so it is
    /// shadowed by the empty path's precedence and never visible).
    fn under_empty(&self, mirrored: &Path) -> bool {
        mirrored.ancestors().skip(1).any(|a| self.is_empty(a))
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

    /// Map a sandbox-relative path (as passed by the FUSE bridge, without a
    /// leading slash) to the **mirrored** path: the path as the mirror — and
    /// thus the sandboxed child — sees it. The mirror reproduces full host
    /// paths, so `/host/etc/passwd` maps to `/etc/passwd`. (Only a redirect
    /// makes the mirrored path differ from the real host path; see
    /// [`HostFs::redirect`].)
    fn mirror_path(&self, path: &OsStr) -> PathBuf {
        let rel = Path::new(path);
        let mut mirrored = PathBuf::from("/");
        for component in rel.components() {
            mirrored.push(component);
        }
        mirrored
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
        if self.is_empty(mirrored) || self.under_empty(mirrored) {
            return false;
        }
        matches!(self.permission_of(mirrored), Some(p) if p.is_mirrored())
    }

    /// The spec-level permission that governs **writing** to the mirrored path
    /// (modifying its content or metadata, creating or deleting it): the
    /// last pattern naming the path itself decides, or — when no pattern
    /// names it directly — the permission of the *nearest* mirrored
    /// ancestor (an exactly-named or `**`-covered directory is a recursive
    /// mirror, so its permission governs everything below it). Empty paths
    /// and hidden paths are never writable.
    ///
    /// The result is only the *spec* side: the real host filesystem may
    /// still deny the operation (the server acts with the real host
    /// credentials, so the underlying file or directory permissions apply).
    fn write_permission(&self, mirrored: &Path) -> Option<Permission> {
        if self.is_empty(mirrored) || self.under_empty(mirrored) || self.hidden(mirrored) {
            return None;
        }
        if let Some(p) = self.permission_of(mirrored) {
            return p.is_mirrored().then_some(p);
        }
        mirrored
            .ancestors()
            .skip(1)
            .find_map(|a| self.permission_of(a).filter(|p| p.is_mirrored()))
    }

    /// Whether writes to the mirrored path are allowed: the spec must say `rw`.
    /// (Whether the *real* file or directory actually allows it is decided
    /// by the host filesystem when the operation is performed.)
    fn writable(&self, mirrored: &Path) -> bool {
        self.write_permission(mirrored)
            .is_some_and(|p| p.is_writable())
    }

    /// Whether any pattern grants write access: the FUSE mount is mounted
    /// read-only unless it does.
    fn has_writable_patterns(&self) -> bool {
        self.patterns.iter().any(|p| p.permission.is_writable())
    }

    /// The permission of the **last** pattern that names the path itself
    /// (exactly, or via a `**` that covers it), or `None` when no pattern
    /// names it.
    fn permission_of(&self, mirrored: &Path) -> Option<Permission> {
        // `*` must not cross directory separators, like in a shell.
        self.patterns
            .iter()
            .rev()
            .find(|p| p.names(mirrored))
            .map(|p| p.permission.clone())
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
        if self.under_empty(mirrored) {
            return false;
        }
        if self.is_empty(mirrored) {
            return true;
        }
        if self.hidden(mirrored) {
            return false;
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
                    Permission::Ro | Permission::Rw | Permission::Empty
                )
            });
        }
        self.patterns
            .iter()
            .any(|p| p.permission.is_mirrored() && self.pattern_reaches(p, mirrored))
            || self.is_empty_prefix(mirrored)
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

    /// The attributes of an empty path (or a purely virtual ancestor of
    /// one): a mode-0555 directory, so nothing can be created inside it.
    fn empty_dir_attr(&self) -> FileAttr {
        FileAttr {
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
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
            // counterpart; present it as a directory.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && self.is_empty_prefix(mirrored) =>
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
        if self.is_empty(mirrored) || self.is_empty_prefix(mirrored) {
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
        let mut names: Vec<std::ffi::OsString> =
            if self.is_host_dir(&self.redirect(mirrored)).await {
                match tokio_fs::read_dir(self.redirect(mirrored)).await {
                    Ok(mut entries) => {
                        let mut names = Vec::new();
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let name = entry.file_name();
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
        size: md.size(),
        blocks: md.blocks(),
        atime: SystemTime::UNIX_EPOCH
            + Duration::new(md.atime().max(0) as u64, md.atime_nsec().max(0) as u32),
        mtime: SystemTime::UNIX_EPOCH
            + Duration::new(md.mtime().max(0) as u64, md.mtime_nsec().max(0) as u32),
        ctime: SystemTime::UNIX_EPOCH
            + Duration::new(md.ctime().max(0) as u64, md.ctime_nsec().max(0) as u32),
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
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
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

impl PathFilesystem for HostFs {
    async fn init(&self, _req: fuse3::raw::Request) -> Result<ReplyInit> {
        Ok(ReplyInit {
            max_write: NonZeroU32::new(4096).unwrap(),
        })
    }

    async fn destroy(&self, _req: fuse3::raw::Request) {}

    async fn lookup(
        &self,
        _req: fuse3::raw::Request,
        parent: &OsStr,
        name: &OsStr,
    ) -> Result<ReplyEntry> {
        // The path-based API calls lookup with the parent path; "/" means the
        // root directory itself.
        let mirrored = self.mirror_path(parent).join(name);
        if self.exists(&mirrored) {
            let attr = self.attr(&mirrored).await?;
            return Ok(ReplyEntry { ttl: TTL, attr });
        }
        Err(libc::ENOENT.into())
    }

    async fn getattr(
        &self,
        _req: fuse3::raw::Request,
        path: Option<&OsStr>,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        match path {
            Some(p) if is_root(p) => Ok(ReplyAttr {
                ttl: TTL,
                attr: root_attr(self.uid, self.gid),
            }),
            Some(p) => {
                let mirrored = self.mirror_path(p);
                if self.exists(&mirrored) {
                    let attr = self.attr(&mirrored).await?;
                    return Ok(ReplyAttr { ttl: TTL, attr });
                }
                Err(libc::ENOENT.into())
            }
            None => Err(libc::ENOENT.into()),
        }
    }

    async fn readlink(&self, _req: fuse3::raw::Request, path: &OsStr) -> Result<ReplyData> {
        let mirrored = self.mirror_path(path);
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        let target = tokio_fs::read_link(self.redirect(&mirrored)).await?;
        Ok(ReplyData::from(Bytes::copy_from_slice(
            target.as_os_str().as_encoded_bytes(),
        )))
    }

    async fn open(&self, _req: fuse3::raw::Request, path: &OsStr, flags: u32) -> Result<ReplyOpen> {
        let mirrored = self.mirror_path(path);
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not).
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not), and
        // symlinks are never followed: a host symlink cannot be opened
        // through the mirror (its target may not be mirrored at all).
        let md = match tokio_fs::symlink_metadata(self.redirect(&mirrored)).await {
            Ok(md) => md,
            Err(_) => return Err(libc::ENOENT.into()),
        };
        if md.file_type().is_symlink() {
            return Err(libc::ELOOP.into());
        }
        if md.is_dir() {
            return Err(libc::EISDIR.into());
        }
        let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
        if write_flags && !self.writable(&mirrored) {
            // `ro` paths (and anything below an empty or hidden pattern) are
            // never writable; the real file permissions are checked by the
            // host filesystem on the actual write.
            return Err(libc::EACCES.into());
        }
        // The kernel passes O_TRUNC through to the server: the server must
        // do the truncation itself. Write paths (rustc, cargo, …) always
        // open their outputs with O_TRUNC, so ignoring it would leave the
        // tail of the old content in place behind the newly written data.
        if write_flags && flags & libc::O_TRUNC as u32 != 0 {
            tokio_fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.redirect(&mirrored))
                .await?;
        }
        // fh 0 = stateless IO; every read re-opens the host file.
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn read(
        &self,
        _req: fuse3::raw::Request,
        path: Option<&OsStr>,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        let Some(p) = path else {
            return Err(libc::ENOENT.into());
        };
        let mirrored = self.mirror_path(p);
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // An empty path has no content: an empty file reads as empty (the
        // host file is never opened).
        if self.is_empty(&mirrored) {
            return Ok(ReplyData::from(Bytes::new()));
        }
        // Stateless IO: reopen the host file for every read — never
        // following symlinks (a host symlink is visible only as a link,
        // and its target may not be mirrored at all).
        let mut file = tokio_fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.redirect(&mirrored))
            .await?;
        file.seek(SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; size as usize];
        let n = file.read(&mut buf).await?;
        buf.truncate(n);
        Ok(ReplyData::from(Bytes::from(buf)))
    }

    async fn write(
        &self,
        _req: fuse3::raw::Request,
        path: Option<&OsStr>,
        _fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        let Some(p) = path else {
            return Err(libc::ENOENT.into());
        };
        let mirrored = self.mirror_path(p);
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            // The spec must say `rw`; the real file permissions are
            // enforced by the host filesystem on the open below.
            return Err(libc::EACCES.into());
        }
        // Stateless IO: reopen the host file for every write — never
        // following symlinks (a host symlink is never written through;
        // its target may not be mirrored at all).
        let append = flags & libc::O_APPEND as u32 != 0;
        let mut file = tokio_fs::OpenOptions::new()
            .write(true)
            .append(append)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.redirect(&mirrored))
            .await?;
        if !append {
            file.seek(SeekFrom::Start(offset)).await?;
        }
        let n = file.write(data).await?;
        Ok(ReplyWrite { written: n as u32 })
    }
    async fn statfs(&self, _req: fuse3::raw::Request, path: &OsStr) -> Result<ReplyStatFs> {
        // Report the real filesystem holding the mirrored path (or "/" for
        // the root), so tools like `df` behave sensibly. The path is opened
        // with `O_NOFOLLOW` and `fstatvfs` runs on the descriptor: symlinks
        // are never followed to a filesystem outside the mirror.
        let mirrored = if is_root(path) {
            PathBuf::from("/")
        } else {
            self.redirect(&self.mirror_path(path))
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
            if rc != 0 {
                Err(err)
            } else {
                Ok(vfs)
            }
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

    async fn opendir(
        &self,
        _req: fuse3::raw::Request,
        path: &OsStr,
        _flags: u32,
    ) -> Result<ReplyOpen> {
        let mirrored = self.mirror_path(path);
        if !self.exists(&mirrored) || !is_root(path) && !self.is_listable_dir(&mirrored).await {
            return Err(libc::ENOENT.into());
        }
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn readdir<'a>(
        &'a self,
        _req: fuse3::raw::Request,
        path: &'a OsStr,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl futures_util::Stream<Item = Result<DirectoryEntry>> + Send + 'a>>
    {
        let mirrored = self.mirror_path(path);
        if !self.exists(&mirrored) || !is_root(path) && !self.is_listable_dir(&mirrored).await {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .await
            .into_iter()
            .skip(offset.max(0) as usize)
            .enumerate()
            .map(|(i, (name, attr))| {
                Ok(DirectoryEntry {
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
        _req: fuse3::raw::Request,
        path: &'a OsStr,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<
        ReplyDirectoryPlus<
            impl futures_util::Stream<Item = Result<DirectoryEntryPlus>> + Send + 'a,
        >,
    > {
        let mirrored = self.mirror_path(path);
        if !self.exists(&mirrored) || !is_root(path) && !self.is_listable_dir(&mirrored).await {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored)
            .await
            .into_iter()
            .skip(offset as usize)
            .enumerate()
            .map(|(i, (name, attr))| {
                Ok(DirectoryEntryPlus {
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

    async fn access(&self, _req: fuse3::raw::Request, path: &OsStr, mask: u32) -> Result<()> {
        let mirrored = self.mirror_path(path);
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // Empty paths (and purely virtual ancestors) are unwritable by
        // definition; answer directly instead of asking the real filesystem.
        if self.is_empty(&mirrored)
            || self.is_empty_prefix(&mirrored)
                && tokio_fs::symlink_metadata(self.redirect(&mirrored))
                    .await
                    .is_err()
        {
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
        _req: fuse3::raw::Request,
        path: Option<&OsStr>,
        _fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        let Some(p) = path else {
            return Err(libc::ENOENT.into());
        };
        let mirrored = self.mirror_path(p);
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
        let attr = self.attr(&mirrored).await?;
        Ok(ReplyAttr { ttl: TTL, attr })
    }

    async fn mkdir(
        &self,
        _req: fuse3::raw::Request,
        parent: &OsStr,
        name: &OsStr,
        mode: u32,
        _umask: u32,
    ) -> Result<ReplyEntry> {
        let mirrored = self.mirror_path(parent).join(name);
        if !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        // Only a *real* entry at the target means EEXIST; a path merely
        // matched by a wildcard pattern may not exist yet.
        if tokio_fs::symlink_metadata(self.redirect(&mirrored))
            .await
            .is_ok()
        {
            return Err(libc::EEXIST.into());
        }
        // errno is per-thread: capture the error on the blocking thread.
        let cpath = cstring_of(&self.redirect(&mirrored))?;
        blocking(move || {
            if unsafe { libc::mkdir(cpath.as_ptr(), (mode & 0o7777) as libc::mode_t) } != 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
        .await
        .map_err(fuse3::Errno::from)?;
        let attr = self.attr(&mirrored).await?;
        Ok(ReplyEntry { ttl: TTL, attr })
    }

    async fn unlink(&self, _req: fuse3::raw::Request, parent: &OsStr, name: &OsStr) -> Result<()> {
        let mirrored = self.mirror_path(parent).join(name);
        if self.is_empty(&mirrored) {
            // Empty paths are virtual mount points; they cannot be removed.
            return Err(libc::EACCES.into());
        }
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        tokio_fs::remove_file(self.redirect(&mirrored)).await?;
        Ok(())
    }
    async fn rmdir(&self, _req: fuse3::raw::Request, parent: &OsStr, name: &OsStr) -> Result<()> {
        let mirrored = self.mirror_path(parent).join(name);
        if self.is_empty(&mirrored) {
            return Err(libc::EACCES.into());
        }
        if !self.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        tokio_fs::remove_dir(self.redirect(&mirrored)).await?;
        Ok(())
    }

    async fn rename(
        &self,
        _req: fuse3::raw::Request,
        origin_parent: &OsStr,
        origin_name: &OsStr,
        parent: &OsStr,
        name: &OsStr,
    ) -> Result<()> {
        let old = self.mirror_path(origin_parent).join(origin_name);
        let new = self.mirror_path(parent).join(name);
        if self.is_empty(&old) || self.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.exists(&old) {
            return Err(libc::ENOENT.into());
        }
        if !self.writable(&old) || !self.writable(&new) {
            return Err(libc::EACCES.into());
        }
        tokio_fs::rename(self.redirect(&old), self.redirect(&new)).await?;
        Ok(())
    }

    async fn create(
        &self,
        _req: fuse3::raw::Request,
        parent: &OsStr,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        let mirrored = self.mirror_path(parent).join(name);
        if !self.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        // Only with O_EXCL does a *real* entry at the target mean EEXIST;
        // a plain O_CREAT (without O_EXCL) opens an existing file like the
        // host filesystem would. A path merely matched by a wildcard
        // pattern may not exist yet.
        let existing = match tokio_fs::symlink_metadata(self.redirect(&mirrored)).await {
            Ok(md) => Some(md),
            Err(_) => None,
        };
        let excl = flags & libc::O_EXCL as u32 != 0;
        let truncate = flags & libc::O_TRUNC as u32 != 0;
        if let Some(md) = existing {
            if md.file_type().is_symlink() {
                return Err(libc::ELOOP.into());
            }
            if excl {
                return Err(libc::EEXIST.into());
            }
            if md.is_dir() {
                return Err(libc::EISDIR.into());
            }
            let mut opts = tokio_fs::OpenOptions::new();
            opts.write(true).custom_flags(libc::O_NOFOLLOW);
            if truncate {
                opts.truncate(true);
            }
            let file = opts.open(self.redirect(&mirrored)).await?;
            let md = file.metadata().await?;
            return Ok(ReplyCreated {
                ttl: TTL,
                attr: attr_from_metadata(&md),
                generation: 0,
                fh: 0,
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
        let file = opts
            .mode(mode & 0o7777)
            .open(self.redirect(&mirrored))
            .await?;
        let md = file.metadata().await?;
        let attr = attr_from_metadata(&md);
        Ok(ReplyCreated {
            ttl: TTL,
            attr,
            generation: 0,
            fh: 0,
            flags: 0,
        })
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

/// Fork the FUSE server process, wait for it to mount, and record the
/// mountpoint for the sandbox child. Must run before any namespace setup.
///
/// `patterns` is the internal pattern → permission list built from the
/// spec's `hostfs` section; the patterns are compiled inside the server
/// process (after the fork).
///
/// On success the mountpoint path is stored in `HOST_MOUNT_POINT` (inherited
/// by every later fork). On any failure the process dies.
pub fn start_host_fs(patterns: &crate::spec::internal::Patterns) {
    // Create the mountpoint directory in the parent so both the server and the
    // sandbox (and its children) can agree on a stable path.
    let mut tmpl: Vec<u8> = b"/tmp/rs-bubble.host.XXXXXX".to_vec();
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

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die_with_error("Can't fork mirrored-fs server");
    }
    if pid == 0 {
        // Child: serve the FUSE filesystem forever (or until the host dies).
        unsafe { libc::close(read_fd) };
        serve(patterns.clone(), mountpoint, write_fd);
        // serve never returns
    }

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
    let fs = HostFs::collect(&patterns);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't build tokio runtime: {e}")));

    let outcome = {
        let mp = mountpoint.clone();
        runtime.block_on(async move {
            let handle =
                match mount_with_fallback(&mp, uid, gid, &fs, !fs.has_writable_patterns()).await {
                    Ok(handle) => handle,
                    Err(e) => return Err(e),
                };

            // Signal readiness to the parent.
            let byte: u8 = 1;
            let _ =
                unsafe { libc::write(ready_fd, (&byte) as *const u8 as *const libc::c_void, 1) };
            unsafe { libc::close(ready_fd) };

            // Serve until the sandbox process dies, then unmount cleanly. The
            // session task runs concurrently on this runtime.
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if unsafe { libc::getppid() } != HOST_PID.load(Ordering::SeqCst) {
                    break;
                }
            }

            handle.unmount().await
        })
    };

    if let Err(e) = outcome {
        eprintln!(
            "rs-bubble: Can't mount mirrored filesystem at {}: {e}",
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
    fs: &HostFs,
    read_only: bool,
) -> std::io::Result<fuse3::raw::MountHandle> {
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
        .mount_with_unprivileged(fs.clone(), mountpoint)
        .await
    {
        Ok(handle) => Ok(handle),
        Err(unprivileged_err) => Session::new(options())
            .mount(fs.clone(), mountpoint)
            .await
            .map_err(|privileged_err| {
                std::io::Error::other(format!(
                    "unprivileged: {unprivileged_err}; privileged: {privileged_err}"
                ))
            }),
    }
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
    fn empty_paths_match_real_files_as_empty_files() {
        let base = std::env::temp_dir().join(format!(
            "rs-bubble-hostfs-empty-test-{}",
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
    fn mirror_path_maps_sandbox_paths_to_absolute_mirrored_paths() {
        let f = fs(&[]);
        assert_eq!(
            f.mirror_path(OsStr::new("/etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        // The bridge may omit the leading slash.
        assert_eq!(
            f.mirror_path(OsStr::new("etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(f.mirror_path(OsStr::new("")), PathBuf::from("/"));
        assert_eq!(f.mirror_path(OsStr::new("/")), PathBuf::from("/"));
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
            "rs-bubble-hostfs-redirect-test-{}",
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
        assert!(!ro.has_writable_patterns());
        assert!(rw.writable(Path::new("/a/f")));
        assert!(rw.has_writable_patterns());
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
        let base =
            std::env::temp_dir().join(format!("rs-bubble-hostfs-test-{}", std::process::id()));
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
            std::env::temp_dir().join(format!("rs-bubble-hostfs-hide-test-{}", std::process::id()));
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
        assert_eq!(f.write_permission(Path::new("/etc")), Some(Permission::Ro));
        assert_eq!(
            f.write_permission(Path::new("/etc/passwd")),
            Some(Permission::Rw)
        );
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
    fn writable_patterns_are_detected_for_the_mount_options() {
        assert!(!fs(&[("/etc", Permission::Ro)]).has_writable_patterns());
        assert!(
            fs(&[("/etc", Permission::Ro), ("/tmp/x", Permission::Rw)]).has_writable_patterns()
        );
        assert!(!fs(&[]).has_writable_patterns());
    }
}
