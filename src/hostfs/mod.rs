//! The host-side FUSE filesystem.
//!
//! The *host* process exposes a read-only mirror of parts of the real
//! filesystem via FUSE. The mirrored paths are selected by the spec file's
//! ordered `hostfs.mirror` glob → permission map (`"mirror"` mirrors a
//! matched path, `"hide"` hides it; when a path matches several patterns,
//! the last match wins); the sandboxed command gets
//! the result bind-mounted at `/host`, where the **full host paths** are
//! reproduced: a pattern `/etc/*.conf` makes `/etc/foo.conf` available as
//! `/host/etc/foo.conf`. A pattern that matches a directory exactly
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
//! The spec's `hostfs.emptyDirs` entries are exposed as empty, unwritable
//! directories that take precedence over the mirror — mount points for the
//! sandbox to stack `/dev`, `/proc`, tmpfs (or, with `hostfs.root`, its
//! whole root) on top of.
//!
//! `hostfs.mirror` is an ordered glob → permission map: `"mirror"` mirrors
//! the matched paths, `"hide"` hides them (a hidden directory hides its
//! whole subtree); when a path matches several patterns the last match
//! wins.

use std::ffi::{CStr, CString, OsStr};
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU32;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fuse3::path::reply::{
    DirectoryEntry, DirectoryEntryPlus, FileAttr, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyOpen, ReplyStatFs,
};
use fuse3::path::{PathFilesystem, Session};
use fuse3::{FileType, MountOptions, Result};
use futures_util::stream;

use crate::sandbox::die_with_error;
use crate::spec::hostfs::{Mirror, Permission};

mod pattern;
use pattern::{Pattern, Walk};

/// The sandbox-absolute path the host filesystem is mounted at.
pub const SANDBOX_MOUNT_POINT: &str = "/host";

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

/// One compiled mirror pattern, with the permission it carries.
#[derive(Clone)]
struct MirrorPattern {
    pattern: Pattern,
    permission: Permission,
}

impl MirrorPattern {
    /// Whether the pattern names the path itself (exactly, or via a `**`
    /// that covers it).
    fn names(&self, host: &Path) -> bool {
        self.pattern.matches(host)
    }
}

/// The mirror filesystem: a read-only view of the paths selected by the
/// spec's ordered `hostfs.mirror` glob → permission map, reproduced at
/// the same absolute paths below `/host`. Nothing is pre-expanded; every
/// operation matches against the patterns directly.
///
/// `empty_dirs` (the spec's `hostfs.emptyDirs`) are absolute paths exposed
/// as empty, unwritable directories regardless of the mirror patterns. They
/// take *precedence* over the mirror: nothing below an empty-dir path is
/// visible (it is meant to be covered by a mount inside the sandbox, e.g.
/// the sandbox root itself or `/dev`). Ancestors of empty-dir paths stay
/// navigable even when the mirror knows nothing about them.
///
/// Permissions: the **last** pattern that names a path (exactly or via
/// `**`) decides whether it is mirrored (`mirror`) or hidden (`hide`); a
/// hidden path — or one below a hidden directory — is not visible at all.
/// Ancestors of visible matches stay navigable as long as no hidden
/// pattern stands between them and the matches below.
#[derive(Clone)]
struct HostFs {
    uid: u32,
    gid: u32,
    patterns: Vec<MirrorPattern>,
    empty_dirs: Vec<PathBuf>,
}

impl HostFs {
    /// Compile the mirror patterns. Invalid patterns are a hard error.
    fn collect(mirror: &Mirror, empty_dirs: &[String]) -> HostFs {
        let compiled = mirror
            .iter()
            .map(|(p, perm)| MirrorPattern {
                pattern: compile(p),
                permission: *perm,
            })
            .collect();
        let empties = empty_dirs
            .iter()
            .map(|p| {
                let path = PathBuf::from(p);
                if !path.is_absolute() {
                    die(&format!(
                        "hostfs emptyDirs entry {p:?} is not an absolute path"
                    ));
                }
                path
            })
            .collect();
        HostFs {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            patterns: compiled,
            empty_dirs: empties,
        }
    }

    /// Whether the host path is exactly one of the empty dirs.
    fn is_empty_dir(&self, host: &Path) -> bool {
        self.empty_dirs.iter().any(|v| v.as_path() == host)
    }

    /// Whether the host path lies strictly *below* an empty dir (so it is
    /// shadowed by the empty dir's precedence and never visible).
    fn under_empty_dir(&self, host: &Path) -> bool {
        self.empty_dirs
            .iter()
            .any(|v| host.starts_with(v) && v.as_path() != host)
    }

    /// Whether the host path is a proper ancestor of an empty dir (so it
    /// must stay navigable even if the mirror would not show it).
    fn is_empty_prefix(&self, host: &Path) -> bool {
        self.empty_dirs
            .iter()
            .any(|v| v.starts_with(host) && v.as_path() != host)
    }

    /// Map a sandbox-relative path (as passed by the FUSE bridge, without a
    /// leading slash) to the mirrored host path. The mirror reproduces full
    /// host paths, so `/host/etc/passwd` maps to host `/etc/passwd`.
    fn host_path(&self, path: &OsStr) -> PathBuf {
        let rel = Path::new(path);
        let mut host = PathBuf::from("/");
        for component in rel.components() {
            host.push(component);
        }
        host
    }

    /// Whether a host path matches one of the patterns directly (as a file,
    /// symlink, or a directory named by the pattern itself), with the
    /// **last** matching pattern mirroring it. Empty dirs and everything
    /// below them take precedence over the mirror.
    fn matches(&self, host: &Path) -> bool {
        if self.is_empty_dir(host) || self.under_empty_dir(host) {
            return false;
        }
        self.permission_of(host) == Some(Permission::Mirror)
    }

    /// The permission of the **last** pattern that names the path itself
    /// (exactly, or via a `**` that covers it), or `None` when no pattern
    /// names it.
    fn permission_of(&self, host: &Path) -> Option<Permission> {
        // `*` must not cross directory separators, like in a shell.
        self.patterns
            .iter()
            .rev()
            .find(|p| p.names(host))
            .map(|p| p.permission)
    }

    /// Whether the path is hidden because a pattern hides it directly, or
    /// a hidden pattern names one of its strict ancestors (a hidden
    /// directory hides its whole subtree).
    fn hidden(&self, host: &Path) -> bool {
        self.patterns.iter().any(|p| {
            p.permission == Permission::Hide
                && (p.names(host) || matches!(p.pattern.walk(host), Walk::Ancestor))
        })
    }

    /// Whether the mirrored host path exists at all: it either is mirrored
    /// by the last matching pattern itself, is an ancestor of something
    /// that is (so the tree under `/host` stays navigable down to the
    /// matched leaves), or is an empty dir (or an ancestor leading to
    /// one) — and nothing hides it directly or via an ancestor.
    fn exists(&self, host: &Path) -> bool {
        if self.is_empty_dir(host) {
            return true;
        }
        if self.under_empty_dir(host) {
            return false;
        }
        if self.hidden(host) {
            return false;
        }
        self.matches(host) || self.dir_prefix(host) || self.is_empty_prefix(host)
    }

    /// Whether some **mirrored** pattern could still match something
    /// *strictly below* the given host path — i.e. the path acts as a
    /// (possibly virtual) directory of the mirror, leading to matches
    /// deeper down. Denied patterns never make a path navigable.
    fn dir_prefix(&self, host: &Path) -> bool {
        if host == Path::new("/") {
            return self
                .patterns
                .iter()
                .any(|p| p.permission == Permission::Mirror)
                || !self.empty_dirs.is_empty();
        }
        self.patterns
            .iter()
            .any(|p| p.permission == Permission::Mirror && self.pattern_reaches(p, host))
            || self.is_empty_prefix(host)
    }

    /// Whether the pattern could make the path visible as a directory
    /// leading to content: it has components left after the path is
    /// consumed, or the path hit (or ends at) a `**`, or the pattern names
    /// a strict ancestor of the path — an exactly-named directory is
    /// mirrored recursively, so everything below it is visible.
    fn pattern_reaches(&self, p: &MirrorPattern, host: &Path) -> bool {
        matches!(
            p.pattern.walk(host),
            Walk::CouldReach | Walk::StarStar | Walk::Ancestor
        )
    }

    /// The attributes of an empty dir (or a purely virtual ancestor of one):
    /// a mode-0555 directory, so nothing can be created inside it.
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

    /// The `lstat`-style attribute of a mirrored path, or ENOENT.
    fn attr(&self, host: &Path) -> std::io::Result<FileAttr> {
        // Empty dirs take precedence: they appear even when the real host
        // path exists (with different attributes).
        if self.is_empty_dir(host) {
            return Ok(self.empty_dir_attr());
        }
        match std::fs::symlink_metadata(host) {
            Ok(md) => Ok(attr_from_metadata(&md)),
            // A purely virtual ancestor of an empty dir has no real
            // counterpart; present it as a directory.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.is_empty_prefix(host) => {
                Ok(self.empty_dir_attr())
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the host path refers to a real directory (following
    /// symlinks); used by opendir/readdir to reject files.
    fn is_real_dir(&self, host: &Path) -> bool {
        std::fs::metadata(host).map(|m| m.is_dir()).unwrap_or(false)
    }

    /// Whether the host path is a listable directory: a real one, an empty
    /// dir, or a purely virtual ancestor of an empty dir.
    fn is_listable_dir(&self, host: &Path) -> bool {
        self.is_real_dir(host) || self.is_empty_dir(host) || self.is_empty_prefix(host)
    }

    /// The visible entries of a mirrored directory, sorted by name: every
    /// real entry that matches a pattern (directly or as an ancestor of a
    /// match) — and, when the directory is itself matched by a pattern, all
    /// of its real entries. Empty dirs (and everything below them) are
    /// shadowed by their precedence; empty-dir entries that live directly
    /// under the directory are always shown.
    fn dir_entries(&self, host: &Path) -> Vec<(std::ffi::OsString, std::io::Result<FileAttr>)> {
        // A directory named by a mirrored pattern itself is a recursive
        // mirror: all of its real entries are visible, not only pattern
        // matches (still minus hidden ones).
        let unfiltered = self.matches(host);
        let mut names: Vec<std::ffi::OsString> = match std::fs::read_dir(host) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.file_name())
                .filter(|name| {
                    let child = host.join(name);
                    // Empty-dir precedence: nothing below an empty dir is
                    // visible, not even a mirror match. Denied entries (and
                    // everything below a hidden directory) are hidden even
                    // inside a recursively mirrored directory.
                    if self.under_empty_dir(&child) || self.hidden(&child) {
                        return false;
                    }
                    unfiltered || self.exists(&child)
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        // Empty-dir entries living directly under this directory (also when
        // the real directory itself cannot be listed).
        for v in &self.empty_dirs {
            if let (Some(parent), Some(name)) = (v.parent(), v.file_name())
                && parent == host
                && !names.iter().any(|n| n == name)
            {
                names.push(name.to_os_string());
            }
        }
        names.sort();
        names
            .into_iter()
            .map(|name| {
                let child = host.join(&name);
                (name, self.attr(&child))
            })
            .collect()
    }
}

fn compile(pattern: &str) -> Pattern {
    Pattern::new(pattern).unwrap_or_else(|e| die(&format!("Invalid hostfs mirror pattern: {e}")))
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
        let host = self.host_path(parent).join(name);
        if self.exists(&host) {
            return Ok(ReplyEntry {
                ttl: TTL,
                attr: self.attr(&host)?,
            });
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
                let host = self.host_path(p);
                if self.exists(&host) {
                    return Ok(ReplyAttr {
                        ttl: TTL,
                        attr: self.attr(&host)?,
                    });
                }
                Err(libc::ENOENT.into())
            }
            None => Err(libc::ENOENT.into()),
        }
    }

    async fn readlink(&self, _req: fuse3::raw::Request, path: &OsStr) -> Result<ReplyData> {
        let host = self.host_path(path);
        if !self.exists(&host) {
            return Err(libc::ENOENT.into());
        }
        let target = std::fs::read_link(&host)?;
        Ok(ReplyData::from(Bytes::copy_from_slice(
            target.as_os_str().as_encoded_bytes(),
        )))
    }

    async fn open(&self, _req: fuse3::raw::Request, path: &OsStr, flags: u32) -> Result<ReplyOpen> {
        let host = self.host_path(path);
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not).
        if !self.exists(&host) {
            return Err(libc::ENOENT.into());
        }
        if std::fs::metadata(&host).map(|m| m.is_dir()).unwrap_or(true) {
            return Err(libc::EISDIR.into());
        }
        if flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0 {
            // The mirror is read-only; the kernel usually rejects writes on
            // the read-only mount already, but be defensive.
            return Err(libc::EACCES.into());
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
        let host = self.host_path(p);
        if !self.exists(&host) {
            return Err(libc::ENOENT.into());
        }
        let mut file = std::fs::File::open(&host)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size as usize];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(ReplyData::from(Bytes::from(buf)))
    }

    async fn statfs(&self, _req: fuse3::raw::Request, path: &OsStr) -> Result<ReplyStatFs> {
        // Report the real filesystem holding the mirrored path (or "/" for
        // the root), so tools like `df` behave sensibly.
        let host = if is_root(path) {
            PathBuf::from("/")
        } else {
            self.host_path(path)
        };
        let cpath = CString::new(host.as_os_str().as_encoded_bytes()).map_err(|_| libc::ENOENT)?;
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut vfs) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
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

    async fn opendir(
        &self,
        _req: fuse3::raw::Request,
        path: &OsStr,
        _flags: u32,
    ) -> Result<ReplyOpen> {
        let host = self.host_path(path);
        if !self.exists(&host) || !is_root(path) && !self.is_listable_dir(&host) {
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
        let host = self.host_path(path);
        if !self.exists(&host) || !is_root(path) && !self.is_listable_dir(&host) {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&host)
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
        let host = self.host_path(path);
        if !self.exists(&host) || !is_root(path) && !self.is_listable_dir(&host) {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&host)
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
        let host = self.host_path(path);
        if !self.exists(&host) {
            return Err(libc::ENOENT.into());
        }
        // Empty dirs (and purely virtual ancestors) are unwritable by
        // definition; answer directly instead of asking the real filesystem.
        if self.is_empty_dir(&host)
            || self.is_empty_prefix(&host) && std::fs::symlink_metadata(&host).is_err()
        {
            if mask & libc::W_OK as u32 != 0 {
                return Err(libc::EACCES.into());
            }
            return Ok(());
        }
        // Ask the real filesystem, with the server's real (host) credentials.
        let cpath = CString::new(host.as_os_str().as_encoded_bytes()).map_err(|_| libc::ENOENT)?;
        if unsafe { libc::access(cpath.as_ptr(), mask as libc::c_int) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

/// Fork the FUSE server process, wait for it to mount, and record the
/// mountpoint for the sandbox child. Must run before any namespace setup.
///
/// `config` is the spec's `hostfs` section; the patterns are compiled inside
/// the server process (after the fork).
///
/// On success the mountpoint path is stored in `HOST_MOUNT_POINT` (inherited
/// by every later fork). On any failure the process dies.
pub fn start_host_fs(config: &crate::spec::HostFsConfig) {
    // Create the mountpoint directory in the parent so both the server and the
    // sandbox (and its children) can agree on a stable path.
    let mut tmpl: Vec<u8> = b"/tmp/rs-bubble.host.XXXXXX".to_vec();
    tmpl.push(0);
    let mountpoint = unsafe {
        let raw = libc::mkdtemp(CString::from_vec_with_nul(tmpl).unwrap().into_raw());
        if raw.is_null() {
            die_with_error("Can't create temporary host-fs mountpoint");
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
        die_with_error("Can't fork host-fs server");
    }
    if pid == 0 {
        // Child: serve the FUSE filesystem forever (or until the host dies).
        unsafe { libc::close(read_fd) };
        serve(
            config.mirror.clone(),
            config.empty_dirs.clone(),
            mountpoint,
            write_fd,
        );
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
        crate::sandbox::die("Can't mount host filesystem (is fusermount3 installed?)");
    }
}

/// The FUSE server child: mount and serve until the parent process is gone.
///
/// The whole lifecycle runs inside a single `block_on`: the session's request
/// loop is a spawned task, and a current-thread runtime only polls its tasks
/// while `block_on` is running — returning early would silently stall the
/// event loop and every filesystem access would hang.
fn serve(mirror: Mirror, empty_dirs: Vec<String>, mountpoint: PathBuf, ready_fd: libc::c_int) -> ! {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let fs = HostFs::collect(&mirror, &empty_dirs);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't build tokio runtime: {e}")));

    let outcome = {
        let mp = mountpoint.clone();
        runtime.block_on(async move {
            let handle = match mount_with_fallback(&mp, uid, gid, &fs).await {
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
            "rs-bubble: Can't mount host filesystem at {}: {e}",
            mountpoint.display()
        );
    }
    let _ = std::fs::remove_dir(&mountpoint);
    std::process::exit(0);
}

/// Mount the host filesystem, preferring the unprivileged fusermount3 route
/// and falling back to a direct (root-only) mount.
async fn mount_with_fallback(
    mountpoint: &Path,
    uid: u32,
    gid: u32,
    fs: &HostFs,
) -> std::io::Result<fuse3::raw::MountHandle> {
    let options = || {
        let mut o = MountOptions::default();
        o.uid(uid)
            .gid(gid)
            .rootmode(0o755)
            .read_only(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(entries: &[(&str, Permission)]) -> HostFs {
        HostFs::collect(
            &Mirror(
                entries
                    .iter()
                    .map(|(p, perm)| (p.to_string(), *perm))
                    .collect(),
            ),
            &[],
        )
    }

    fn fs_with_empty_dirs(entries: &[(&str, Permission)], empty: &[&str]) -> HostFs {
        HostFs::collect(
            &Mirror(
                entries
                    .iter()
                    .map(|(p, perm)| (p.to_string(), *perm))
                    .collect(),
            ),
            &empty.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
        )
    }

    #[test]
    fn empty_dirs_are_virtual_unwritable_directories() {
        let f = fs_with_empty_dirs(&[], &["/dev"]);

        // The dir itself exists, with no write permission...
        assert!(f.exists(Path::new("/dev")));
        assert!(f.is_empty_dir(Path::new("/dev")));
        assert_eq!(f.attr(Path::new("/dev")).unwrap().perm, 0o555);
        assert_eq!(f.attr(Path::new("/dev")).unwrap().kind, FileType::Directory);
        // ...and it is empty even though the real host /dev has entries.
        assert!(f.dir_entries(Path::new("/dev")).is_empty());
        // Deeper paths are shadowed by the precedence.
        assert!(!f.exists(Path::new("/dev/null")));
        assert!(!f.matches(Path::new("/dev/null")));
        assert!(!f.dir_prefix(Path::new("/dev/null")));
        // The mountpoint dir is not itself a dir-prefix.
        assert!(!f.dir_prefix(Path::new("/dev")));
    }

    #[test]
    fn empty_dirs_take_precedence_over_mirror() {
        let f = fs_with_empty_dirs(
            &[("/etc/*", Permission::Mirror), ("/etc", Permission::Mirror)],
            &["/etc"],
        );
        assert!(f.is_empty_dir(Path::new("/etc")));
        // Mirror contents below the empty dir are hidden.
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(f.dir_entries(Path::new("/etc")).is_empty());
        // But /etc still appears at the root listing.
        let names: Vec<_> = f
            .dir_entries(Path::new("/"))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["etc"]);
    }

    #[test]
    fn empty_dir_ancestors_stay_navigable() {
        // A nested empty dir; /var exists only as a virtual ancestor.
        let f = fs_with_empty_dirs(&[], &["/var/tmp"]);
        assert!(f.exists(Path::new("/var")));
        assert!(f.is_empty_prefix(Path::new("/var")));
        assert!(f.exists(Path::new("/var/tmp")));
        assert!(!f.exists(Path::new("/var/tmp/other")));
        assert!(!f.exists(Path::new("/var/etc")));
        // The root listing contains both levels of the chain.
        let root: Vec<_> = f
            .dir_entries(Path::new("/"))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(root, ["var"]);
        let var: Vec<_> = f
            .dir_entries(Path::new("/var"))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(var, ["tmp"]);
    }

    #[test]
    fn empty_dirs_coexist_with_mirror() {
        // /dev is empty, /etc is mirrored normally; siblings of the empty
        // dir are listed together with it.
        let f = fs_with_empty_dirs(&[("/etc/passwd", Permission::Mirror)], &["/dev"]);
        let names: Vec<_> = f
            .dir_entries(Path::new("/"))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["dev", "etc"]);
        assert!(f.exists(Path::new("/etc/passwd")));
        assert!(!f.exists(Path::new("/dev/whatever")));
    }

    #[test]
    fn host_path_maps_sandbox_paths_to_absolute_host_paths() {
        let f = fs(&[]);
        assert_eq!(
            f.host_path(OsStr::new("/etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        // The bridge may omit the leading slash.
        assert_eq!(
            f.host_path(OsStr::new("etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(f.host_path(OsStr::new("")), PathBuf::from("/"));
        assert_eq!(f.host_path(OsStr::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn pattern_matching_per_operation() {
        let f = fs(&[
            ("/etc/*.conf", Permission::Mirror),
            ("/home/me/project", Permission::Mirror),
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
        let f = fs(&[("/usr/share/**/*.rs", Permission::Mirror)]);
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

        let f = fs(&[(&format!("{}/*.conf", base.display()), Permission::Mirror)]);

        // Only matching entries (and entries leading to matches) survive.
        let names: Vec<_> = f
            .dir_entries(&base)
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.conf".to_string()));
        assert!(names.contains(&"d.conf".to_string())); // a directory named by the pattern
        assert!(!names.contains(&"b.txt".to_string()));
        assert!(!names.contains(&"c.conf.dir".to_string()));

        // An entry that only leads to a match (virtual ancestor) is shown.
        let f = fs(&[(
            &format!("{}/c.conf.dir/x", base.display()),
            Permission::Mirror,
        )]);
        let names: Vec<_> = f
            .dir_entries(&base)
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
            Permission::Mirror,
        )]);
        let names: Vec<_> = f
            .dir_entries(&base.join("c.conf.dir"))
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
        assert!(f.dir_entries(Path::new("/")).is_empty());
    }

    #[test]
    fn empty_dirs_only_still_show_root() {
        let f = fs_with_empty_dirs(&[], &["/dev"]);
        assert!(f.exists(Path::new("/")));
        assert_eq!(
            f.dir_entries(Path::new("/"))
                .into_iter()
                .map(|(n, _)| n.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["dev"]
        );
    }

    #[test]
    fn last_matching_pattern_wins() {
        // The later hide hides the file inside the mirrored tree...
        let f = fs(&[
            ("/etc", Permission::Mirror),
            ("/etc/passwd", Permission::Hide),
        ]);
        assert!(f.exists(Path::new("/etc")));
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(!f.matches(Path::new("/etc/passwd")));
        // ...and the reverse order shows *other* files under /etc again:
        // the last pattern that names a path decides. "/etc/passwd" is
        // still hidden (its own hide pattern is the only one naming it),
        // but a sibling is visible via the later recursive mirror.
        let f = fs(&[
            ("/etc/passwd", Permission::Hide),
            ("/etc", Permission::Mirror),
        ]);
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(f.exists(Path::new("/etc/hosts")));
    }

    #[test]
    fn hidden_directories_hide_their_subtree() {
        let f = fs(&[
            ("/etc", Permission::Mirror),
            ("/etc/passwd", Permission::Mirror),
            ("/etc", Permission::Hide),
        ]);
        // The hide pattern matches /etc last and shadows everything below.
        assert!(!f.exists(Path::new("/etc")));
        assert!(!f.exists(Path::new("/etc/passwd")));
        assert!(f.dir_entries(Path::new("/")).is_empty());
        // Siblings are unaffected; the hide is scoped to /etc.
        let base =
            std::env::temp_dir().join(format!("rs-bubble-hostfs-hide-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("foo.conf"), b"f").unwrap();
        std::fs::create_dir_all(base.join("secret")).unwrap();
        let base_str = base.display().to_string();
        let f = fs(&[
            (&format!("{base_str}/*"), Permission::Mirror),
            (&format!("{base_str}/secret"), Permission::Hide),
        ]);
        assert!(f.exists(&base.join("foo.conf")));
        assert!(!f.exists(&base.join("secret")));
        // The parent stays navigable for the still-mirrored matches.
        assert!(f.exists(&base));
        let names: Vec<_> = f
            .dir_entries(&base)
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
}
