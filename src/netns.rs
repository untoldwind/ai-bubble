//! The `--isolated-net` orchestration: process tree, namespaces and
//! lifecycle. The byte-shuffling itself lives in `proxy`.
//!
//! Process tree with --isolated-net:
//!
//!   original (host netns) — the "connector": answers proxy requests with
//!                           real TCP connections, waits for P, reports P's
//!                           exit status.
//!     └─ P — unshares user+network+UTS namespaces, brings up loopback,
//!            listens on 127.0.0.2:3128 (HTTP CONNECT) and forwards the
//!            child's exit status.
//!         └─ C — unshares the mount namespace, builds the tmpfs sandbox
//!                and execs COMMAND in its own PID and IPC namespaces (see
//!                sandbox::pidns_and_exec).
//!
//! The network namespace is shared by P and C, so COMMAND can reach the
//! proxy transparently at 127.0.0.2, while it stays fully isolated from
//! the host network (the namespace has no interfaces besides loopback).
//! P's outbound connections to real targets are made by the original
//! process over Unix-domain sockets, which cross network namespaces via
//! the filesystem (the socket directory is bind-mounted at /net).
//!
//! Tokio runtimes are created strictly *after* every fork, in the process
//! that actually runs async code — a forked child must never share a
//! runtime with its parent, and the exec'd command must not inherit one.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};

use crate::proxy::{PROXY_ADDR, PROXY_URL};
use crate::sandbox::{
    die, die_with_error, exit_with_status, handle_die_with_parent, pidns_and_exec, userns_id,
    write_id_map,
};
use crate::spec::internal::{Net, Op};

/// Temporary host directory holding the proxy socket. It is bind-mounted
/// at /net inside the sandbox so that the (network-isolated) child can
/// reach the connector.
pub unsafe fn run(ops: &[Op], command: &[String], net: &Net, die_with_parent: bool) -> ! {
    unsafe {
        // The connector binds its lifecycle to rs-bubble's caller (see
        // handle_die_with_parent); P and the sandboxed child set their own
        // PDEATHSIG after the forks below.
        handle_die_with_parent(die_with_parent);

        let netdir = create_socket_dir();
        let listener = match StdUnixListener::bind(netdir.join("sock")) {
            Ok(l) => l,
            Err(e) => die(&format!("Can't create proxy socket: {e}")),
        };
        // The command must not inherit the listening socket.
        let _ = libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);

        // Fork P. This must happen before any runtime or proxy task exists.
        let pid = libc::fork();
        if pid < 0 {
            die_with_error("Can't fork");
        }
        if pid == 0 {
            drop(listener);
            isolated_parent(&netdir, net, ops, command, die_with_parent);
        }

        // Connector: serve proxy connections from the host side and watch
        // for P's exit.
        let allow = net.allow.clone();
        let status = block_on(async move {
            let _ = listener.set_nonblocking(true);
            let l = tokio::net::UnixListener::from_std(listener)
                .unwrap_or_else(|e| die(&format!("Can't register proxy socket: {e}")));
            tokio::select! {
                _ = crate::proxy::serve_connector(l, allow) => {
                    unreachable!("connector accept loop never ends")
                }
                st = wait_status(pid) => st,
            }
        });

        let _ = std::fs::remove_dir_all(&netdir);
        exit_with_status(status);
    }
}

/// P: owns the sandbox network namespace and runs the HTTP CONNECT proxy on
/// 127.0.0.2. Forks C for the filesystem sandbox and exec, then reports C's
/// exit status.
unsafe fn isolated_parent(
    netdir: &Path,
    net: &Net,
    ops: &[Op],
    command: &[String],
    die_with_parent: bool,
) -> ! {
    unsafe {
        // P binds its lifecycle to the connector (which itself set
        // PR_SET_PDEATHSIG in netns::run); PR_SET_PDEATHSIG does not survive
        // fork, so P sets it again for itself here.
        handle_die_with_parent(die_with_parent);

        // Prevent gaining privileges via execve of setuid binaries. C inherits
        // this, which is what matters (C is the process that execs).
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            die_with_error("Can't set PR_SET_NO_NEW_PRIVS");
        }

        // Capture the real uid/gid BEFORE unsharing (see sandbox::setup_and_exec).
        let (real_uid, real_gid) = (libc::getuid(), libc::getgid());

        // P and C share this user namespace, so the maps must be set up exactly
        // once, here. C unshares only the mount namespace and inherits the
        // already-mapped ids. As in sandbox::setup_and_exec, the real uid/gid
        // is mapped onto SANDBOX_ID (not 0), so the command never runs as root.
        let old_userns = userns_id();
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWUTS) != 0 {
            die_with_error("Can't unshare user/network namespaces");
        }
        crate::sandbox::check_new_userns(old_userns);
        write_id_map(
            "/proc/self/uid_map",
            &format!("{} {real_uid} 1\n", crate::sandbox::SANDBOX_ID),
        );
        write_id_map("/proc/self/setgroups", "deny\n");
        write_id_map(
            "/proc/self/gid_map",
            &format!("{} {real_gid} 1\n", crate::sandbox::SANDBOX_ID),
        );

        // The loopback interface starts DOWN; bring it up so the proxy at
        // 127.0.0.2 (and any local servers) are reachable.
        bring_up_loopback();

        let proxy_listener = match std::net::TcpListener::bind(PROXY_ADDR) {
            Ok(l) => l,
            Err(e) => die(&format!("Can't bind proxy listener on {PROXY_ADDR}: {e}")),
        };
        let _ = libc::fcntl(proxy_listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);

        // Make standard tools (curl, wget, git, ...) use the proxy.
        for (key, val) in [
            ("http_proxy", PROXY_URL),
            ("HTTP_PROXY", PROXY_URL),
            ("https_proxy", PROXY_URL),
            ("HTTPS_PROXY", PROXY_URL),
            ("all_proxy", PROXY_URL),
            ("ALL_PROXY", PROXY_URL),
            ("NO_PROXY", "localhost,127.0.0.1,::1"),
            ("RS_BUBBLE_PROXY", "/net/sock"),
        ] {
            std::env::set_var(key, val);
        }

        let child_ops: Vec<Op> = std::iter::once(Op::Bind {
            src: netdir.display().to_string(),
            dest: PathBuf::from("/net"),
        })
        .chain(ops.iter().cloned())
        .collect();

        let child_pid = libc::fork();
        if child_pid < 0 {
            die_with_error("Can't fork sandboxed command");
        }
        if child_pid == 0 {
            // PID 1 of its own PID namespace (see pidns_and_exec).
            pidns_and_exec(&child_ops, command, die_with_parent);
        }

        // Serve CONNECT requests while the command runs.
        let allow = net.allow.clone();
        let sock = netdir.join("sock");
        let status = block_on(async move {
            let _ = proxy_listener.set_nonblocking(true);
            let l = tokio::net::TcpListener::from_std(proxy_listener)
                .unwrap_or_else(|e| die(&format!("Can't register proxy listener: {e}")));
            tokio::select! {
                _ = crate::proxy::serve_sandbox_proxy(l, sock, allow) => {
                    unreachable!("proxy accept loop never ends")
                }
                st = wait_status(child_pid) => st,
            }
        });

        exit_with_status(status);
    }
}

/// Create the temporary host directory for the proxy socket via mkdtemp(3).
fn create_socket_dir() -> PathBuf {
    let mut tmpl: Vec<u8> = b"/tmp/rs-bubble-net.XXXXXX".to_vec();
    tmpl.push(0);
    unsafe {
        let tmpl_ptr = CString::from_vec_with_nul(tmpl).unwrap();
        let dir_ptr = libc::mkdtemp(tmpl_ptr.into_raw() as *mut libc::c_char);
        if dir_ptr.is_null() {
            die_with_error("Can't create proxy socket directory");
        }
        PathBuf::from(CStr::from_ptr(dir_ptr).to_string_lossy().into_owned())
    }
}

/// Wait for `pid` on a blocking thread and return its raw waitpid status,
/// so the async accept loops above are never stalled by waitpid.
async fn wait_status(pid: libc::pid_t) -> libc::c_int {
    tokio::task::spawn_blocking(move || {
        let mut status: libc::c_int = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r == pid {
                return status;
            }
            if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                die_with_error("Can't wait for sandboxed command");
            }
        }
    })
    .await
    .unwrap_or_else(|_| die("waitpid task panicked"))
}

/// Run `fut` on a fresh current-thread tokio runtime.
/// Called after every fork, so no runtime is ever shared across processes.
fn block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("Can't start async runtime: {e}")));
    rt.block_on(fut)
}

/// Bring up the loopback interface in the current network namespace.
fn bring_up_loopback() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        die_with_error("Can't create socket for loopback setup");
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) } != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        die_with_error(&format!("Can't get loopback flags: {e}"));
    }
    // The flags live at offset 0 of the ifr_ifru union.
    unsafe {
        let flags_ptr = &mut ifr.ifr_ifru as *mut _ as *mut libc::c_short;
        *flags_ptr |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(fd, libc::SIOCSIFFLAGS, &mut ifr) != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            die_with_error(&format!("Can't bring up loopback: {e}"));
        }
        libc::close(fd);
    }
}
