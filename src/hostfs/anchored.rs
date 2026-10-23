//! Dirfd-anchored host-path resolution.
//!
//! Every host access in the mirror resolves its real path **component-wise**
//! with `openat(…, O_NOFOLLOW|O_DIRECTORY)` starting from a pinned root
//! directory descriptor, and performs its final operation with `*at()`
//! syscalls relative to the pinned parent directory. No host path is ever
//! resolved as a string through the kernel's path walking.
//!
//! This closes the mirror escape (audit finding C1): a host symlink standing
//! at any *intermediate* component — pre-existing, or swapped in between two
//! FUSE requests by renaming an entry inside a writable mapping — can never
//! be followed, because every component is re-verified on every request and
//! opened no-follow. The final component keeps the no-follow semantics the
//! mirror always had (`O_NOFOLLOW` opens, `lstat`-style metadata), and the
//! operation itself is anchored on the parent's descriptor, so a concurrent
//! swap cannot re-point an already-resolved path either.
//!
//! Intermediate symlinks are **not** followed — deliberately. The kernel
//! never drives a mirrored path through a host symlink: it resolves symlinks
//! *inside the sandbox mount* (each hop re-enters `lookup` on the FUSE
//! server), so every directory component the server is asked about was
//! looked up as a real directory. Traffic that legitimately traverses host
//! symlinks (merged-`/usr`, `/lib` → `usr/lib`, …) therefore never needs an
//! intermediate-symlink hop *on the host side*. A spec `redirect` source with
//! symlink components fails closed (`ELOOP`/`ENOENT`).
//!
//! Per-request cost: one `openat` per path component plus one final
//! operation — a few syscalls where the old path-based code needed one.
//! Local filesystems resolve these in microseconds; the security property
//! is worth the constant factor.

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};

/// The pinned host root directory: the anchor every host-path walk starts
/// from. Opened once per FUSE server (after the fork, so it is the `/` of
/// the server's own host mount namespace) and never re-resolved.
pub(crate) struct RootDir(OwnedFd);

impl RootDir {
    /// Pin `/` as an `O_PATH` descriptor (the descriptor is only ever used
    /// as the starting point of `openat` walks, never read or written).
    pub(crate) fn open() -> io::Result<Self> {
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            c"/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self(fd))
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// Walk `comps` from the anchor (absolute paths) or the current directory
    /// (relative redirect sources, resolved like the old path-based code did),
    /// opening every component `O_PATH|O_NOFOLLOW|O_DIRECTORY`. A symlink at any
    /// component fails the walk with `ELOOP`.
    fn walk(&self, absolute: bool, comps: &[CString]) -> io::Result<OwnedFd> {
        // No intermediate components: the parent *is* the anchor (or, for a
        // relative path, the current directory).
        if comps.is_empty() {
            if absolute {
                // `OwnedFd::try_clone` dups with F_DUPFD_CLOEXEC, same as the
                // raw call this replaced (AUDIT-unsafe.md, std-only swaps).
                return self.0.try_clone();
            }
            return self.open_full(
                Path::new("."),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            );
        }
        let mut dir: Option<OwnedFd> = None;
        for comp in comps {
            let start: BorrowedFd<'_> = match &dir {
                Some(d) => d.as_fd(),
                None if absolute => self.as_fd(),
                None => rustix::fs::CWD,
            };
            let fd = rustix::fs::openat(
                start,
                comp,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            dir = Some(fd);
        }
        let dir = dir.expect("walk with non-empty components");
        Ok(dir)
    }

    /// Walk to the **parent** of `path` and pin it, returning the descriptor and
    /// the final component's name. For the root itself (`/`, which has no
    /// parent) the anchor directory is returned with the name `.`: every
    /// `*at()` operation then acts on the root directory, exactly like the
    /// path-based code operating on the redirected root path did (`faccessat`
    /// checks the root itself; creation ops fail closed — `.` cannot be
    /// created, unlinked or renamed).
    pub(crate) fn anchor_parent(&self, path: &Path) -> io::Result<AnchoredParent> {
        let mut comps = components_of(path)?;
        let name = match comps.pop() {
            Some(name) => name,
            None if path.is_absolute() => {
                return Ok(AnchoredParent {
                    dir: self.walk(true, &[])?,
                    name: cstring(OsStr::new("."))?,
                });
            }
            // A relative path with no components (`.`): resolve it like the old
            // path-based code did — against the server's current directory.
            None => return Err(io::Error::from_raw_os_error(libc::ENOENT)),
        };
        let dir = self.walk(path.is_absolute(), &comps)?;
        Ok(AnchoredParent { dir, name })
    }

    /// Open `path` itself — every component walked no-follow, the final one
    /// opened with the caller's `flags` **plus `O_NOFOLLOW`/`O_CLOEXEC`**: the
    /// final component is *always* no-follow, exactly like [`RootDir::open_at`]
    /// — a caller cannot opt out, so a symlink at the last component fails with
    /// `ELOOP` instead of re-pointing the open at unmirrored content (C1).
    /// Used for whole-path opens (`O_PATH` for `statfs`,
    /// `O_RDONLY|O_DIRECTORY` for directory listings).
    pub(crate) fn open_full(&self, path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
        let mut comps = components_of(path)?;
        let Some(name) = comps.pop() else {
            // The root itself (or an empty relative path): resolve `/` directly —
            // the anchor's own target, which cannot be a symlink.
            if !path.is_absolute() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            return rustix::fs::openat(
                rustix::fs::CWD,
                c"/",
                OFlags::from_bits_retain((flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u32),
                Mode::empty(),
            )
            .map_err(io::Error::from);
        };
        let dir = self.walk(path.is_absolute(), &comps)?;
        rustix::fs::openat(
            dir,
            name,
            OFlags::from_bits_retain((flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u32),
            Mode::empty(),
        )
        .map_err(io::Error::from)
    }

    /// Open (or create) the anchored final component relative to its pinned
    /// parent, always with `O_NOFOLLOW` (and `O_CLOEXEC`). This is the anchored
    /// equivalent of the old `OpenOptions::…custom_flags(O_NOFOLLOW).open(path)`.
    /// `mode` only matters together with `O_CREAT`.
    ///
    /// The open itself is made with `O_NONBLOCK` (AUDIT.md L8): the FUSE
    /// server is single-threaded, and a plain open of a mirrored host **FIFO**
    /// for reading would block it — every later sandbox filesystem request
    /// stalls — until some host-side writer appears. Opening non-blocking
    /// returns immediately; the flag is cleared again on the descriptor before
    /// it is handed out, so the sandbox keeps the normal blocking I/O
    /// semantics on the open file (for regular files/directories `O_NONBLOCK`
    /// is a no-op all along). A FIFO opened *for writing* with no reader
    /// fails with `ENXIO` — fail-closed instead of hanging the server.
    pub(crate) fn open_at(
        &self,
        path: &Path,
        mut flags: libc::c_int,
        mode: libc::mode_t,
    ) -> io::Result<std::fs::File> {
        let anchored = self.anchor_parent(path)?;
        flags |= libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = rustix::fs::openat(
            anchored.dir(),
            anchored.name(),
            OFlags::from_bits_retain(flags as u32),
            Mode::from_raw_mode(mode),
        )?;
        // Clear `O_NONBLOCK` again: only the *open* must not block, not the
        // subsequent I/O on the descriptor.
        if let Ok(fl) = rustix::fs::fcntl_getfl(&fd) {
            let _ = rustix::fs::fcntl_setfl(&fd, fl & !OFlags::NONBLOCK);
        }
        Ok(std::fs::File::from(fd))
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)` on the anchored path — the anchored
    /// equivalent of `symlink_metadata`: the final component is never followed,
    /// and (unlike the string-based call) neither is anything above it.
    pub(crate) fn lstat(&self, path: &Path) -> io::Result<rustix::fs::Stat> {
        if path == Path::new("/") {
            return rustix::fs::fstat(self.as_fd()).map_err(io::Error::from);
        }
        let anchored = self.anchor_parent(path)?;
        rustix::fs::statat(anchored.dir(), anchored.name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
    }

    /// Open the anchored path as a real (readable) directory descriptor —
    /// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, every intermediate component
    /// no-follow. The result is an owned descriptor usable with `fdopendir`.
    pub(crate) fn open_dir(&self, path: &Path) -> io::Result<OwnedFd> {
        self.open_full(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)
    }

    /// `readlinkat` on the anchored path, growing the buffer until the target
    /// fits — the anchored equivalent of `std::fs::read_link`.
    pub(crate) fn read_link(&self, path: &Path) -> io::Result<std::ffi::OsString> {
        let anchored = self.anchor_parent(path)?;
        let mut size = 4096usize;
        loop {
            let mut buf = vec![0u8; size];
            let n =
                rustix::fs::readlinkat_raw(anchored.dir(), anchored.name(), buf.as_mut_slice())?;
            if n < size {
                return Ok(OsStr::from_bytes(&buf[..n]).to_os_string());
            }
            // Truncated: retry with a larger buffer (a few rounds cover any
            // real target; give up far beyond `PATH_MAX`).
            if size >= 1 << 20 {
                return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
            }
            size *= 2;
        }
    }
}

/// A pinned parent directory descriptor plus the final component's name —
/// everything the caller's `*at()` operation needs.
pub(crate) struct AnchoredParent {
    dir: OwnedFd,
    name: CString,
}

impl AnchoredParent {
    /// The pinned parent directory descriptor (an `O_PATH|O_DIRECTORY` fd —
    /// usable as the dirfd of every `*at()` syscall, including creation).
    pub(crate) fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// The final path component as a NUL-terminated C string.
    pub(crate) fn name(&self) -> &CStr {
        &self.name
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)` on the pinned parent + final name — the
    /// anchored "does this entry exist, and what is it" check.
    pub(crate) fn stat_entry(&self) -> io::Result<rustix::fs::Stat> {
        rustix::fs::statat(self.dir(), self.name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
    }
}

/// A path as a NUL-terminated C string; embedded NULs fail with `ENOENT`
/// (the kernel never hands the server a name containing one, and host paths
/// built from mirrored paths cannot grow one).
fn cstring(component: &OsStr) -> io::Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::ENOENT))
}

/// The path's components as C strings. `RootDir` and `CurDir` contribute
/// nothing; `ParentDir` (`..`) and Windows prefixes are rejected outright:
/// mirrored paths are built from kernel-provided names (which cannot contain
/// `..`) and spec-validated redirect sources (which are checked `..`-free at
/// load time) — a `..` here would mean resolution escaping the walk.
fn components_of(path: &Path) -> io::Result<Vec<CString>> {
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(os) => out.push(cstring(os)?),
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) | std::path::Component::ParentDir => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        }
    }
    Ok(out)
}

/// `fstat` of an already-open descriptor (used to stamp the pinned
/// directory descriptor for the readdir cache).
pub(crate) fn fstat(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<rustix::fs::Stat> {
    rustix::fs::fstat(fd).map_err(io::Error::from)
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` on an already-pinned directory descriptor
/// plus a component name — used where the caller holds a raw dirfd from the
/// walk itself.
pub(crate) fn statat_nofollow(
    dir: std::os::fd::BorrowedFd<'_>,
    name: &CStr,
) -> io::Result<rustix::fs::Stat> {
    rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
}

/// The entry names of the anchored directory (excluding `.` and `..`), in
/// filesystem order — the `fd`-based equivalent of `std::fs::read_dir`'s
/// name iterator. Consumes the descriptor (`closedir` closes it).
pub(crate) fn readdir_names(dir: OwnedFd) -> Vec<std::ffi::OsString> {
    // `Dir::new` is the safe `fdopendir`: it consumes the descriptor and
    // closes it when the iterator ends (no double-close juggling).
    let mut stream = match rustix::fs::Dir::new(dir) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let Ok(entry) = entry else { break };
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(OsStr::from_bytes(bytes).to_os_string());
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opening a mirrored host FIFO must not block the (single-threaded)
    /// server (AUDIT.md L8): `open_at` opens it `O_NONBLOCK` and clears
    /// the flag again, so the open returns immediately while the
    /// descriptor keeps normal blocking I/O semantics.
    #[test]
    fn open_at_does_not_block_on_a_fifo() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-fifo-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        if let Err(e) = rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
        ) {
            panic!("mkfifo failed: {e}");
        }

        let root = RootDir::open().unwrap();
        // The FIFO has no writer; a plain blocking open would hang here.
        let f = root.open_at(&fifo, libc::O_RDONLY, 0).unwrap();

        // The descriptor is not left in non-blocking mode: the flag is
        // cleared after the open, so sandbox-side I/O keeps its normal
        // blocking semantics.
        let fl = rustix::fs::fcntl_getfl(&f).unwrap();
        assert!(!fl.contains(rustix::fs::OFlags::NONBLOCK));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `open_full` must never follow a symlink at the final component, even
    /// when the caller passes flags *without* `O_NOFOLLOW`: the no-follow
    /// property is enforced by the helper, not by its call sites (C1).
    /// Without the fix the open would follow `link` and hand out the target.
    #[test]
    fn open_full_never_follows_a_final_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "ai-bubble-open-full-nofollow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("target"), b"HOST-SECRET").unwrap();
        std::os::unix::fs::symlink("target", dir.join("link")).unwrap();

        let root = RootDir::open().unwrap();
        // No `O_NOFOLLOW` from the caller: the helper must add it itself.
        let err = root
            .open_full(&dir.join("link"), libc::O_RDONLY)
            .expect_err("open_full must not follow a final symlink");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));

        // A real file still opens normally.
        root.open_full(&dir.join("target"), libc::O_RDONLY)
            .expect("open_full of a regular file succeeds");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
