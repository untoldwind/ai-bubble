//! The FUSE server process lifecycle: forking the server (with its
//! readiness pipe and signal handling), mounting the mirror, serving the
//! session, and the last-resort unmounts.

use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use fuse3::MountOptions;
use fuse3::raw::Session;

use super::{HOST_MOUNT_POINT, HOST_PID, HostFs, SharedPatterns, fuse_ops::cstring_of, fuselog};
use crate::sandbox::{die, die_with_error};

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
/// `policy` is the shared, runtime-swappable pattern set (see
/// [`crate::hostfs::SharedPatterns`]) — the launcher holds the
/// authoritative handle and may push a full replacement at runtime; the
/// server reads the currently active set on every operation.
///
/// On success the mountpoint path is stored in `HOST_MOUNT_POINT` (inherited
/// by every later fork). On any failure the process dies.
pub fn start_host_fs(patterns: &SharedPatterns) {
    // Open the request log (if requested) eagerly, before the fork: the
    // server child inherits the fd and never opens the path itself — a
    // lazy open inside the single-threaded FUSE server could hang on a
    // FIFO, follow a swapped-in symlink or panic the server (AUDIT.md M3).
    crate::hostfs::fuselog::init();

    // Create the mountpoint directory in the parent so both the server and the
    // sandbox (and its children) can agree on a stable path.
    let mountpoint = crate::sandbox::mkdtemp_dir(
        b"/tmp/ai-bubble.host.XXXXXX",
        "Can't create temporary mirrored-fs mountpoint",
    );

    let _ = HOST_MOUNT_POINT.set(mountpoint.clone());
    HOST_PID.store(unsafe { libc::getpid() }, Ordering::SeqCst);

    // Readiness pipe: the server writes one byte after a successful mount.
    let mut fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        die_with_error("Can't create readiness pipe");
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Audit channel (single-writer refactor): on the isolated path the
    // server's events go to the launcher over this pre-fork socketpair.
    // `SOCK_CLOEXEC` on both ends — neither side may survive an `exec`.
    // `sv[0]` stays with the launcher (its hub reads it), `sv[1]` goes
    // to the server child.
    let mut audit_pair: Option<[libc::c_int; 2]> = None;
    if crate::audit::ipc_channel_wanted() {
        let mut sv: [libc::c_int; 2] = [0; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        } != 0
        {
            die_with_error("Can't create audit channel");
        }
        audit_pair = Some(sv);
    }

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
        // The FUSE server never signs certificates; drop the waf CA private
        // key fork-copied into this address space (AUDIT.md, TLS MITM key hygiene).
        crate::waf::host::wipe_after_fork();
        // Audit first, before any other work: register the upstream
        // channel (from here on this process's events go to the launcher
        // over the socketpair) and close the inherited audit-log fd —
        // the launcher is the only process holding the log. Also close
        // the inherited control listener: this child never serves
        // control, and a lingering copy would keep the abstract socket
        // name bound after the launcher exits.
        crate::cli::control::close_inherited_listener();
        if let Some(sv) = audit_pair {
            unsafe { libc::close(sv[0]) };
            crate::audit::set_channel(unsafe { OwnedFd::from_raw_fd(sv[1]) });
            crate::audit::drop_log_fd();
        }
        serve(patterns.clone(), mountpoint, write_fd);
        // serve never returns
    }
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };

    // Parent: register our end of the audit channel for the hub, then
    // wait for readiness.
    if let Some(sv) = audit_pair {
        unsafe { libc::close(sv[1]) };
        crate::audit::add_peer(crate::audit::PeerRole::HostFs, unsafe {
            OwnedFd::from_raw_fd(sv[0])
        });
    }
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
fn serve(policy: SharedPatterns, mountpoint: PathBuf, ready_fd: libc::c_int) -> ! {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't build tokio runtime: {e}")));

    let outcome = {
        let mp = mountpoint.clone();
        let server_mountpoint = mountpoint.clone();
        fuselog::event!(
            "SERVER start mountpoint={}",
            fuselog::path_string(mountpoint.as_os_str())
        );
        runtime.block_on(async move {
            // The audit channel's halves (if this child has one): the
            // read half feeds the control loop below (its EOF *is* the
            // run-end signal, subsuming the old channel-EOF watch), the
            // shared write half carries both the audit batches and the
            // control replies.
            crate::audit::init_channel_sink();
            let control_read = crate::audit::channel_reader();
            let control_reply = crate::audit::reply_writer();
            // The mount's read-only decision is taken once, from the *initial*
            // set: fuse3's mount handle has no remount. A runtime swap can
            // only ever widen/narrow within what the mount allows — except
            // when the run was started with control enabled (the default): then the mount is
            // writable regardless (an all-`ro` initial set must still be
            // able to grant writes later), giving up the kernel read-only
            // backstop in favor of the per-operation pattern checks (the
            // accepted, opt-in trade-off of the runtime-control plan).
            let initial = policy.load();
            let read_only = !crate::cli::control::running() && !initial.any_writable();
            let handle = match mount_with_fallback(&mp, uid, gid, &policy, read_only).await {
                Ok(handle) => handle,
                Err(e) => return Err(e),
            };

            fuselog::event!("SERVER mounted");

            // Signal readiness to the parent.
            let byte: u8 = 1;
            let _ =
                unsafe { libc::write(ready_fd, (&byte) as *const u8 as *const libc::c_void, 1) };
            unsafe { libc::close(ready_fd) };

            // Serve until the launcher says the run is ending, or until
            // the launcher process dies, then unmount cleanly. The
            // session task runs concurrently on this runtime.
            //
            // Shutdown triggers, in order of precedence:
            // 1. the control loop ending — the launcher half-closed the
            //    channel's write side (`SHUT_WR`) to say "the run is
            //    ending; finish and exit". This is the primary, prompt
            //    trigger; the final audit events still flow, because the
            //    opposite direction of the pair stays open until the
            //    drain below.
            // 2. the 200 ms `getppid()` poll — the backstop for abnormal
            //    launcher death (a SIGKILLed launcher EOFs the channel
            //    anyway; the poll is redundant but harmless) and for
            //    channel-less runs.
            let mut child_loop = match (control_read, control_reply) {
                (Some(read), Some(reply)) => Some(tokio::spawn(crate::cli::control::fs_child_loop(
                    read,
                    reply,
                    policy.clone(),
                ))),
                _ => None,
            };
            let mut heartbeat = 0u64;
            loop {
                tokio::select! {
                    _ = async {
                        match &mut child_loop {
                            Some(task) => {
                                let _ = (&mut *task).await;
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => break,
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if unsafe { libc::getppid() } != HOST_PID.load(Ordering::SeqCst) {
                            break;
                        }
                        heartbeat += 1;
                        if heartbeat.is_multiple_of(10) {
                            fuselog::event!("SERVER alive");
                        }
                    }
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
            // into the launcher's still-open channel read end (that is
            // why the launcher half-closes instead of closing). When
            // the writer task ends it closes the channel, which the
            // launcher's hub reader sees as EOF.
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
    policy: &SharedPatterns,
    read_only: bool,
) -> std::io::Result<fuse3::raw::MountHandle> {
    // The mount consumes the filesystem, so each attempt builds its own
    // `HostFs` — cheap, and correct: a failed attempt never reached the
    // kernel, so its inode map was never touched. Both attempts share the
    // same `SharedPatterns` instance, so a runtime swap reaches whichever
    // one actually serves.
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
        .mount_with_unprivileged(HostFs::collect(policy), mountpoint)
        .await
    {
        Ok(handle) => Ok(handle),
        Err(unprivileged_err) => {
            let handle = Session::new(options())
                .mount(HostFs::collect(policy), mountpoint)
                .await
                .map_err(|privileged_err| {
                    std::io::Error::other(format!(
                        "unprivileged: {unprivileged_err}; privileged: {privileged_err}"
                    ))
                })?;
            // AUDIT.md L7: the unprivileged fusermount3 route forces
            // `nosuid,nodev` itself; the direct root-only mount above
            // does not — the mount flags must be brought to parity, or a
            // mirrored device node would be opened by the kernel's device
            // layer (I/O bypassing the mirror) and setuid execution from
            // the mirror would be defused only by the user namespace. A
            // plain remount of the same mountpoint flips the per-mount
            // flags (root-only, which is exactly the fallback's case).
            // `default_permissions` deliberately stays off (it would break
            // the uid-translation model).
            let flags = libc::MS_REMOUNT
                | libc::MS_NODEV
                | libc::MS_NOSUID
                | if read_only { libc::MS_RDONLY } else { 0 };
            let path = cstring_of(mountpoint)?;
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    path.as_ptr(),
                    std::ptr::null(),
                    flags,
                    std::ptr::null(),
                )
            } != 0
            {
                let err = std::io::Error::last_os_error();
                drop(handle);
                return Err(std::io::Error::other(format!(
                    "Can't apply nosuid/nodev to the privileged FUSE mount at {}: {err}",
                    mountpoint.display()
                )));
            }
            Ok(handle)
        }
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
