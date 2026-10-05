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
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The pinned host root directory: the anchor every host-path walk starts
/// from. Opened once per FUSE server (after the fork, so it is the `/` of
/// the server's own host mount namespace) and never re-resolved.
pub(crate) struct RootDir(OwnedFd);

impl RootDir {
    /// Pin `/` as an `O_PATH` descriptor (the descriptor is only ever used
    /// as the starting point of `openat` walks, never read or written).
    pub(crate) fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a freshly opened, owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
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
                // SAFETY: valid descriptor; the duplicate is owned by the caller.
                let fd =
                    unsafe { libc::fcntl(self.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: `fd` is a freshly dup'ed, owned descriptor.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            return self.open_full(
                Path::new("."),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            );
        }
        let mut dir: Option<OwnedFd> = None;
        for comp in comps {
            let start = match &dir {
                Some(d) => d.as_raw_fd(),
                None if absolute => self.as_fd().as_raw_fd(),
                None => libc::AT_FDCWD,
            };
            // SAFETY: `start` is a valid descriptor (or AT_FDCWD) and `comp`
            // points to a NUL-terminated string outliving the call.
            let fd = unsafe {
                libc::openat(
                    start,
                    comp.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
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
    /// opened with the caller's `flags` (include `O_NOFOLLOW` where the caller
    /// wants final-component no-follow semantics). Used for whole-path opens
    /// (`O_PATH` for `statfs`, `O_RDONLY|O_DIRECTORY` for directory listings).
    pub(crate) fn open_full(&self, path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
        let mut comps = components_of(path)?;
        let Some(name) = comps.pop() else {
            // The root itself (or an empty relative path): resolve `/` directly —
            // the anchor's own target, which cannot be a symlink.
            if !path.is_absolute() {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            // SAFETY: string literal outliving the call.
            let fd = unsafe { libc::open(c"/".as_ptr(), flags | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        };
        let dir = self.walk(path.is_absolute(), &comps)?;
        // SAFETY: valid descriptor and NUL-terminated name.
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a freshly opened, owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
        // SAFETY: valid descriptor and NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                flags,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Clear `O_NONBLOCK` again: only the *open* must not block, not the
        // subsequent I/O on the descriptor.
        // SAFETY: `fd` is a freshly opened, owned descriptor we still hold.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK) };
        }
        // SAFETY: `fd` is a freshly opened, owned descriptor.
        Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)` on the anchored path — the anchored
    /// equivalent of `symlink_metadata`: the final component is never followed,
    /// and (unlike the string-based call) neither is anything above it.
    pub(crate) fn lstat(&self, path: &Path) -> io::Result<libc::stat> {
        if path == Path::new("/") {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: valid descriptor and a writable `stat` buffer.
            if unsafe { libc::fstat(self.as_fd().as_raw_fd(), &mut st) } != 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(st);
        }
        let anchored = self.anchor_parent(path)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor, NUL-terminated name, writable buffer.
        if unsafe {
            libc::fstatat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    /// Open the anchored path as a real (readable) directory descriptor —
    /// `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, every intermediate component
    /// no-follow. The result is an owned descriptor usable with `fdopendir`.
    pub(crate) fn open_dir(&self, path: &Path) -> io::Result<OwnedFd> {
        self.open_full(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    }

    /// `readlinkat` on the anchored path, growing the buffer until the target
    /// fits — the anchored equivalent of `std::fs::read_link`.
    pub(crate) fn read_link(&self, path: &Path) -> io::Result<std::ffi::OsString> {
        let anchored = self.anchor_parent(path)?;
        let mut size = 4096usize;
        loop {
            let mut buf = vec![0u8; size];
            // SAFETY: valid descriptor, NUL-terminated name, `buf` writable for
            // `size` bytes.
            let n = unsafe {
                libc::readlinkat(
                    anchored.dir().as_raw_fd(),
                    anchored.name().as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    size,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < size {
                buf.truncate(n);
                return Ok(OsStr::from_bytes(&buf).to_os_string());
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
    pub(crate) fn stat_entry(&self) -> io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor, NUL-terminated name, writable buffer.
        if unsafe {
            libc::fstatat(
                self.dir().as_raw_fd(),
                self.name().as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
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
pub(crate) fn fstat(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and a writable `stat` buffer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The entry names of the anchored directory (excluding `.` and `..`), in
/// filesystem order — the `fd`-based equivalent of `std::fs::read_dir`'s
/// name iterator. Consumes the descriptor (`closedir` closes it).
pub(crate) fn readdir_names(dir: OwnedFd) -> Vec<std::ffi::OsString> {
    // SAFETY: `dir` is a valid, open directory descriptor.
    let stream = unsafe { libc::fdopendir(dir.as_raw_fd()) };
    if stream.is_null() {
        return Vec::new();
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is a valid DIR handle; `readdir` returns NULL at
        // the end of the directory (errno is irrelevant here).
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `readdir` returned a valid dirent whose `d_name` is
        // NUL-terminated and valid until the next `readdir` call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(OsStr::from_bytes(bytes).to_os_string());
    }
    // SAFETY: `closedir` also closes the descriptor; the `OwnedFd` is
    // forgotten so it is not closed a second time.
    unsafe { libc::closedir(stream) };
    std::mem::forget(dir);
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
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let root = RootDir::open().unwrap();
        // The FIFO has no writer; a plain blocking open would hang here.
        let f = root.open_at(&fifo, libc::O_RDONLY, 0).unwrap();

        // The descriptor is not left in non-blocking mode: the flag is
        // cleared after the open, so sandbox-side I/O keeps its normal
        // blocking semantics.
        let fl = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(fl & libc::O_NONBLOCK, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
