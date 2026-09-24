//! The host-side FUSE filesystem.
//!
//! The *host* process exposes a small virtual filesystem (currently just a
//! read-only `hello.txt`) via FUSE. The sandboxed command gets it bind-mounted
//! at `/host`, so it can reach host-provided data without any other access to
//! the real filesystem.
//!
//! Because a FUSE session must keep running while the sandboxed command runs,
//! and because tokio runtimes must never be shared across `fork` (see
//! `netns.rs`), the server lives in its *own* forked child process: the parent
//! (the sandbox) forks it first, waits for a readiness byte on a pipe, and only
//! then proceeds with the namespace setup. When the parent dies, the FUSE
//! server unmounts and exits.

use std::ffi::OsStr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
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

/// The sandbox-absolute path the host filesystem is mounted at.
pub const SANDBOX_MOUNT_POINT: &str = "/host";

/// The host-side mountpoint of the FUSE filesystem, if it has been started.
pub(crate) fn host_mount_point() -> Option<&'static PathBuf> {
    HOST_MOUNT_POINT.get()
}

/// The mountpoint of the running host filesystem, set by `start_host_fs`
/// before any fork. Needed by the sandbox child to create the bind mount.
pub(crate) static HOST_MOUNT_POINT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// PID of the sandbox (host) process; the FUSE server exits when it dies.
static HOST_PID: AtomicI32 = AtomicI32::new(0);

/// A trivial read-only filesystem containing a single virtual file.
struct HelloFs {
    uid: u32,
    gid: u32,
}

const HELLO_CONTENT: &[u8] = b"Hello from the rs-bubble host filesystem!\n";

const TTL: Duration = Duration::from_secs(1);

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

fn hello_attr(uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        size: HELLO_CONTENT.len() as u64,
        blocks: 1,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o444,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
    }
}

const HELLO_NAME: &str = "hello.txt";

/// The bridge passes absolute paths ("/hello.txt"); accept those and be
/// lenient about a missing leading slash.
fn is_hello(path: &OsStr) -> bool {
    let p = Path::new(path);
    p == Path::new(HELLO_NAME) || p == Path::new("/").join(HELLO_NAME)
}

fn is_root(path: &OsStr) -> bool {
    path == Path::new("/") || path.is_empty()
}

impl PathFilesystem for HelloFs {
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
        if parent == Path::new("/") && name == Path::new(HELLO_NAME) {
            return Ok(ReplyEntry {
                ttl: TTL,
                attr: hello_attr(self.uid, self.gid),
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
            Some(p) if is_hello(p) => Ok(ReplyAttr {
                ttl: TTL,
                attr: hello_attr(self.uid, self.gid),
            }),
            _ => Err(libc::ENOENT.into()),
        }
    }

    async fn open(
        &self,
        _req: fuse3::raw::Request,
        path: &OsStr,
        _flags: u32,
    ) -> Result<ReplyOpen> {
        if is_hello(path) {
            // fh 0 = stateless IO; the filesystem is read-only, so any write
            // flags would already have been rejected by the kernel.
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        Err(libc::ENOENT.into())
    }

    async fn read(
        &self,
        _req: fuse3::raw::Request,
        path: Option<&OsStr>,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        match path {
            Some(p) if is_hello(p) => {
                let start = (offset as usize).min(HELLO_CONTENT.len());
                let end = (start + size as usize).min(HELLO_CONTENT.len());
                Ok(ReplyData::from(Bytes::copy_from_slice(
                    &HELLO_CONTENT[start..end],
                )))
            }
            _ => Err(libc::ENOENT.into()),
        }
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
        if !is_root(path) {
            return Err(libc::ENOENT.into());
        }
        // One entry; `offset` is the offset of the *next* entry, so a single
        // entry always has offset 1.
        let entries = if offset == 0 {
            vec![Ok(DirectoryEntryPlus {
                kind: FileType::RegularFile,
                name: HELLO_NAME.into(),
                offset: 1,
                attr: hello_attr(self.uid, self.gid),
                entry_ttl: TTL,
                attr_ttl: TTL,
            })]
        } else {
            Vec::new()
        };
        Ok(ReplyDirectoryPlus {
            entries: stream::iter(entries),
        })
    }

    async fn access(&self, _req: fuse3::raw::Request, path: &OsStr, _mask: u32) -> Result<()> {
        if is_root(path) || is_hello(path) {
            Ok(())
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn statfs(&self, _req: fuse3::raw::Request, _path: &OsStr) -> Result<ReplyStatFs> {
        Ok(ReplyStatFs {
            blocks: 1,
            bfree: 0,
            bavail: 0,
            files: 1,
            ffree: 0,
            bsize: 4096,
            namelen: 255,
            frsize: 4096,
        })
    }

    async fn opendir(
        &self,
        _req: fuse3::raw::Request,
        path: &OsStr,
        _flags: u32,
    ) -> Result<ReplyOpen> {
        if is_root(path) {
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        Err(libc::ENOENT.into())
    }

    async fn readdir<'a>(
        &'a self,
        _req: fuse3::raw::Request,
        path: &'a OsStr,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl futures_util::Stream<Item = Result<DirectoryEntry>> + Send + 'a>>
    {
        if !is_root(path) {
            return Err(libc::ENOENT.into());
        }
        // One entry; `offset` is the offset of the *next* entry, so a single
        // entry always has offset 1.
        let entries = if offset <= 0 {
            vec![Ok(DirectoryEntry {
                kind: FileType::RegularFile,
                name: HELLO_NAME.into(),
                offset: 1,
            })]
        } else {
            Vec::new()
        };
        Ok(ReplyDirectory {
            entries: stream::iter(entries),
        })
    }
}

/// Fork the FUSE server process, wait for it to mount, and record the
/// mountpoint for the sandbox child. Must run before any namespace setup.
///
/// On success the mountpoint path is stored in `HOST_MOUNT_POINT` (inherited
/// by every later fork). On any failure the process dies.
pub fn start_host_fs() {
    // Create the mountpoint directory in the parent so both the server and the
    // sandbox (and its children) can agree on a stable path.
    let mut tmpl: Vec<u8> = b"/tmp/rs-bubble.host.XXXXXX".to_vec();
    tmpl.push(0);
    let mountpoint = unsafe {
        let raw = libc::mkdtemp(
            std::ffi::CString::from_vec_with_nul(tmpl)
                .unwrap()
                .into_raw(),
        );
        if raw.is_null() {
            die_with_error("Can't create temporary host-fs mountpoint");
        }
        PathBuf::from(std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned())
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
        serve(mountpoint, write_fd);
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
fn serve(mountpoint: PathBuf, ready_fd: libc::c_int) -> ! {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't build tokio runtime: {e}")));

    let outcome = {
        let mp = mountpoint.clone();
        runtime.block_on(async move {
            let handle = match mount_with_fallback(&mp, uid, gid).await {
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
        .mount_with_unprivileged(HelloFs { uid, gid }, mountpoint)
        .await
    {
        Ok(handle) => Ok(handle),
        Err(unprivileged_err) => Session::new(options())
            .mount(HelloFs { uid, gid }, mountpoint)
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
