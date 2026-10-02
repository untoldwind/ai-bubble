//! The `--isolated-net` orchestration: process tree, namespaces and
//! lifecycle. The network serving itself lives in `proxy` (HTTP CONNECT
//! mode) and `waf` (DNS/HTTP/HTTPS mode).
//!
//! Process tree with isolated networking:
//!
//!   original (host netns) — the "connector": answers proxy/waf requests
//!                           with real TCP connections, waits for P, reports
//!                           P's exit status.
//!     └─ P — unshares user+network+cgroup+UTS namespaces, brings up
//!            loopback and serves the mode's in-sandbox network frontends
//!            on 127.0.0.2 (proxy: HTTP CONNECT on 3128; waf: DNS on 53,
//!            HTTP on 80, HTTPS on 443 — see `crate::waf`). It forks the
//!            actual sandboxed command.
//!         └─ C — unshares the mount namespace, builds the tmpfs sandbox
//!                and execs COMMAND in its own PID and IPC namespaces (see
//!                sandbox::pidns_and_exec).
//!
//! The network namespace is shared by P and C, so COMMAND reaches P's
//! frontends transparently at 127.0.0.2, while it stays fully isolated
//! from the host network (the namespace has no interfaces besides
//! loopback). P's outbound connections to real targets are made by the
//! original process over Unix-domain sockets, which cross network
//! namespaces via the filesystem — but the socket directory is *not*
//! mounted into the sandbox (an earlier `/net` bind mount was never
//! implemented; see the note on `create_socket_dir`). By default the
//! command cannot reach the connector socket at all; should a `/net`
//! mount ever be added, it must come with a `SO_PEERCRED` check that the
//! peer is P (AUDIT.md L11).
//!
//! Tokio runtimes are created strictly *after* every fork, in the process
//! that actually runs async code — a forked child must never share a
//! runtime with its parent, and the exec'd command must not inherit one.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};

use crate::proxy::{PROXY_ADDR, PROXY_URL};
use crate::sandbox::{
    die, die_with_error, exit_with_status, handle_die_with_parent, pidns_and_exec, userns_id,
    write_id_map,
};
use crate::spec::internal::{Net, NetMode, Op, SeccompPolicy};
use crate::waf;

/// Temporary host directory holding the proxy socket. It is *not* mounted
/// into the sandbox: a `/net` bind mount was considered but never
/// implemented (stale comments used to claim otherwise), so the command
/// cannot reach the connector at all — the safer state (AUDIT.md L11).
/// If the mount is ever added, verify with `SO_PEERCRED` that the peer is
/// P before serving it.
///
/// `env` is the sandbox's isolated environment (the spec's `env` section);
/// the proxy variables are merged into it below. `cwd` is the command's
/// working directory inside the sandbox (see `sandbox::mount_and_exec`).
#[allow(clippy::too_many_arguments)]
pub fn run(
    ops: &[Op],
    command: &[String],
    net: &Net,
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    seccomp: Option<&SeccompPolicy>,
) -> ! {
    unsafe {
        // The connector binds its lifecycle to ai-bubble's caller (see
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
            // P only relays `tls-cert` requests to the connector; the CA
            // private key fork-copied into its address space is dropped
            // here (AUDIT.md L8).
            waf::host::wipe_after_fork();
            isolated_parent(
                &netdir,
                net,
                ops,
                command,
                env,
                cwd,
                die_with_parent,
                new_session,
                seccomp,
            );
        }

        // Connector: serve proxy/waf requests from the host side and
        // watch for P's exit.
        let allow = net.allow.clone();
        let allow_private = net.allow_private;
        let status = block_on(async move {
            let _ = listener.set_nonblocking(true);
            let l = tokio::net::UnixListener::from_std(listener)
                .unwrap_or_else(|e| die(&format!("Can't register proxy socket: {e}")));
            let status = tokio::select! {
                _ = async {
                    match net.mode {
                        NetMode::Proxy => {
                            crate::proxy::serve_connector(l, allow, allow_private).await
                        }
                        NetMode::Waf => waf::host::serve_host(l, allow, allow_private).await,
                    }
                } => {
                    unreachable!("connector accept loop never ends")
                }
                st = wait_status(pid) => st,
            };
            // Give the audit writer a chance to flush the last batch
            // before this process exits.
            crate::audit::drain().await;
            status
        });

        let _ = std::fs::remove_dir_all(&netdir);
        exit_with_status(status);
    }
}

/// P: owns the sandbox network namespace and runs the HTTP CONNECT proxy on
/// 127.0.0.2. Forks C for the filesystem sandbox and exec, then reports C's
/// exit status.
// The parameter list mirrors the sandbox setup pipeline (each function
// forwards everything to the next one); one more parameter than clippy's
// default limit is fine here.
#[allow(clippy::too_many_arguments)]
fn isolated_parent(
    netdir: &Path,
    net: &Net,
    ops: &[Op],
    command: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    seccomp: Option<&SeccompPolicy>,
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
        // The cgroup namespace is unshared in the same call (like bwrap's
        // --unshare-all; it must be combined with CLONE_NEWUSER — see
        // sandbox::cgroup_ns_flags).
        if libc::unshare(
            libc::CLONE_NEWUSER
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWUTS
                | crate::sandbox::cgroup_ns_flags(),
        ) != 0
        {
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

        // The loopback interface starts DOWN; bring it up so the servers
        // at 127.0.0.2 are reachable.
        bring_up_loopback();

        // Set up the mode's in-sandbox listeners (all on 127.0.0.2, the
        // address the waf DNS server resolves to) and its environment
        // before forking the child. Entries from the spec's `env` section
        // are applied afterwards and so win over these: an explicit spec
        // value is the user's authoritative choice.
        let mut proxy_listener = None;
        let mut waf_listeners = None;
        let mut child_env: BTreeMap<String, String> = BTreeMap::new();
        match net.mode {
            NetMode::Proxy => {
                let listener = match std::net::TcpListener::bind(PROXY_ADDR) {
                    Ok(l) => l,
                    Err(e) => die(&format!("Can't bind proxy listener on {PROXY_ADDR}: {e}")),
                };
                let _ = libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                proxy_listener = Some(listener);
                // Make standard tools (curl, wget, git, ...) use the proxy
                // by adding the proxy variables to the sandbox's isolated
                // environment.
                child_env.extend(
                    [
                        ("http_proxy", PROXY_URL),
                        ("HTTP_PROXY", PROXY_URL),
                        ("https_proxy", PROXY_URL),
                        ("HTTPS_PROXY", PROXY_URL),
                        ("all_proxy", PROXY_URL),
                        ("ALL_PROXY", PROXY_URL),
                        ("NO_PROXY", "localhost,127.0.0.1,::1"),
                    ]
                    .into_iter()
                    .map(|(key, val)| (key.to_string(), val.to_string())),
                );
            }
            NetMode::Waf => {
                let (tcp53, tcp80, tcp443) = (
                    std::net::TcpListener::bind("127.0.0.2:53"),
                    std::net::TcpListener::bind("127.0.0.2:80"),
                    std::net::TcpListener::bind("127.0.0.2:443"),
                );
                let udp53 = std::net::UdpSocket::bind("127.0.0.2:53");
                let (tcp53, tcp80, tcp443, udp53) = match (tcp53, tcp80, tcp443, udp53) {
                    (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
                    _ => die("Can't bind the waf listeners on 127.0.0.2 (ports 53, 80, 443)"),
                };
                for fd in [&tcp53, &tcp80, &tcp443] {
                    let _ = libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                }
                let _ = libc::fcntl(udp53.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
                waf_listeners = Some((tcp53, tcp80, tcp443, udp53));
                // No proxy variables here — the DNS server and the
                // 127.0.0.2 servers take care of the redirection. The waf
                // mode injects its MITM CA as the sandbox's trust anchor
                // (see `main`); point OpenSSL-based clients at it
                // explicitly so a distro with a different default bundle
                // path still finds it.
                child_env.insert(
                    "SSL_CERT_FILE".to_string(),
                    "/etc/ssl/certs/ca-certificates.crt".to_string(),
                );
            }
        }
        child_env.extend(env.iter().map(|(k, v)| (k.clone(), v.clone())));

        let child_pid = libc::fork();
        if child_pid < 0 {
            die_with_error("Can't fork sandboxed command");
        }
        if child_pid == 0 {
            // PR_SET_PDEATHSIG does not survive fork: like the child of
            // `pidns_and_exec`, this intermediate process must bind its own
            // lifecycle to its parent (P) before doing anything else, or a
            // dead P leaves the sandbox re-parented to init.
            handle_die_with_parent(die_with_parent);
            // PID 1 of its own PID namespace (see pidns_and_exec).
            pidns_and_exec(ops, command, &child_env, cwd, die_with_parent, new_session, seccomp);
        }

        // Serve the mode's network frontends while the command runs.
        let allow = net.allow.clone();
        let sock = netdir.join("sock");
        let status = block_on(async move {
            let status = match (net.mode, proxy_listener, waf_listeners) {
                (NetMode::Proxy, Some(listener), _) => {
                    let _ = listener.set_nonblocking(true);
                    let l = tokio::net::TcpListener::from_std(listener)
                        .unwrap_or_else(|e| die(&format!("Can't register proxy listener: {e}")));
                    tokio::select! {
                        _ = crate::proxy::serve_sandbox_proxy(l, sock, allow) => {
                            unreachable!("proxy accept loop never ends")
                        }
                        st = wait_status(child_pid) => st,
                    }
                }
                (NetMode::Waf, _, Some((tcp53, tcp80, tcp443, udp53))) => {
                    let _ = tcp53.set_nonblocking(true);
                    let _ = tcp80.set_nonblocking(true);
                    let _ = tcp443.set_nonblocking(true);
                    let _ = udp53.set_nonblocking(true);
                    let tcp53 = tokio::net::TcpListener::from_std(tcp53)
                        .unwrap_or_else(|e| die(&format!("Can't register DNS TCP listener: {e}")));
                    let tcp80 = tokio::net::TcpListener::from_std(tcp80)
                        .unwrap_or_else(|e| die(&format!("Can't register HTTP listener: {e}")));
                    let tcp443 = tokio::net::TcpListener::from_std(tcp443)
                        .unwrap_or_else(|e| die(&format!("Can't register HTTPS listener: {e}")));
                    let udp53 = tokio::net::UdpSocket::from_std(udp53)
                        .unwrap_or_else(|e| die(&format!("Can't register DNS UDP socket: {e}")));
                    tokio::spawn(waf::dns::serve_tcp(tcp53, sock.clone()));
                    tokio::spawn(waf::http::serve_http(tcp80, sock.clone()));
                    tokio::spawn(waf::https::serve_https(tcp443, sock.clone()));
                    tokio::select! {
                        // The UDP DNS loop never ends; it keeps the runtime
                        // busy while wait_status delivers the exit status.
                        _ = waf::dns::serve_udp(udp53, sock) => {
                            unreachable!("DNS accept loop never ends")
                        }
                        st = wait_status(child_pid) => st,
                    }
                }
                _ => unreachable!("mode and listeners agree"),
            };
            // Give the audit writer a chance to flush the last batch
            // before this process exits.
            crate::audit::drain().await;
            status
        });

        exit_with_status(status);
    }
}

/// Create the temporary host directory for the proxy socket via mkdtemp(3).
fn create_socket_dir() -> PathBuf {
    crate::sandbox::mkdtemp_dir(
        b"/tmp/ai-bubble-net.XXXXXX",
        "Can't create proxy socket directory",
    )
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
