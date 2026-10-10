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
//! original process over a pre-fork socketpair (the net mux channel, see
//! `crate::ipc::netmux`): the connector keeps `sv[0]`, P inherits
//! `sv[1]`. The pair has no filesystem name at all — it exists only as
//! fds in the two processes — so there is nothing to mount and nothing
//! the sandboxed command could reach, by construction (this retires the
//! AUDIT.md L6 caveat about a host `/tmp` bind mount exposing the old
//! socket directory). Every protocol request is still re-authorized
//! host-side. `SOCK_CLOEXEC` on both ends: the exec'd command never
//! sees either side, and the forks drop the end they do not use (P
//! closes the connector's `sv[0]` before running; the connector closes
//! P's `sv[1]`).
//!
//! Tokio runtimes are created strictly *after* every fork, in the process
//! that actually runs async code — a forked child must never share a
//! runtime with its parent, and the exec'd command must not inherit one.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;

use crate::proxy::PROXY_URL;
use crate::sandbox::{
    die, die_with_error, exit_with_status, handle_die_with_parent, pidns_and_exec, userns_id,
    write_id_map,
};
use crate::spec::internal::{Net, NetMode, Op, SeccompPolicy};
use crate::waf;

/// Run one isolated-network sandbox. `net` carries the mode (HTTP
/// CONNECT proxy or waf), its allow-list and the `allow_private` opt-out.
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

        // The net mux channel (PLAN.md Phases 2-3): one pre-fork
        // socketpair carries every proxy/waf logical connection as a
        // numbered stream — no filesystem name, nothing to bind-mount,
        // nothing the sandboxed command can reach. `SOCK_CLOEXEC` on
        // both ends; the forks below close the end they do not use.
        // `sv[0]` stays with the connector (it serves the mux), `sv[1]`
        // goes to P.
        let mut net_sv: [libc::c_int; 2] = [0; 2];
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            net_sv.as_mut_ptr(),
        ) != 0
        {
            die_with_error("Can't create the net mux channel");
        }

        // Audit channel (single-writer refactor): P's events go to the
        // connector over this pre-fork socketpair. `SOCK_CLOEXEC` on
        // both ends — the exec'd sandboxed command never sees either
        // side. `sv[0]` stays with the connector (its hub reads it),
        // `sv[1]` goes to P. The pair carries only P's upstream audit
        // events: P holds no control state, so nothing is ever pushed
        // downstream over it.
        let mut audit_pair: Option<[libc::c_int; 2]> = None;
        if crate::audit::ipc_channel_wanted() {
            let mut sv: [libc::c_int; 2] = [0; 2];
            if libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            ) != 0
            {
                die_with_error("Can't create audit channel");
            }
            audit_pair = Some(sv);
        }

        // Fork P. This must happen before any runtime or proxy task exists.
        let pid = libc::fork();
        if pid < 0 {
            die_with_error("Can't fork");
        }
        if pid == 0 {
            // P must not hold the connector's mux end (a lingering copy
            // would keep the connector's reader from ever seeing EOF —
            // same reasoning as the audit pair below).
            libc::close(net_sv[0]);
            // Audit first, before any other work: P inherited the
            // connector's A↔FS hub peer across this fork and must not
            // hold it (a lingering copy would keep the FS hub reader
            // from ever seeing EOF), registers its own channel end, and
            // drops the inherited audit-log fd — the connector is the
            // only audit writer. P also closes the inherited control
            // listener: it must never serve control (its network
            // namespace would not even see the abstract name).
            crate::audit::close_inherited();
            crate::cli::control::close_inherited_listener();
            if let Some(sv) = audit_pair {
                libc::close(sv[0]);
                crate::audit::set_channel(OwnedFd::from_raw_fd(sv[1]));
                crate::audit::drop_log_fd();
            }
            // P only relays `tls-cert` requests to the connector; the CA
            // private key fork-copied into its address space is dropped
            // here (AUDIT.md, TLS MITM key hygiene).
            waf::host::wipe_after_fork();
            isolated_parent(
                net_sv[1],
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

        // Connector: close P's mux end, register our end of the audit
        // channel for the hub, then serve proxy/waf requests from the
        // host side and watch for P's exit.
        libc::close(net_sv[1]);
        if let Some(sv) = audit_pair {
            libc::close(sv[1]);
            crate::audit::add_peer(crate::audit::PeerRole::Network, OwnedFd::from_raw_fd(sv[0]));
        }
        // The shared allow-list: the launcher keeps this authoritative
        // handle (the control plane's `net-set` swaps it at runtime), the
        // connector/waf host serves from clones of the same instance. A
        // swap affects new connections only — every accepted connection
        // snapshots the list (see `proxy::allowlist::SharedAllow`).
        let allow = crate::proxy::allowlist::shared(net.allow.clone());
        // Hand the authoritative copy to the control plane.
        crate::cli::control::set_allow(std::sync::Arc::clone(&allow));
        let allow_private = net.allow_private;
        let status = block_on(async move {
            // Serve the mux pair (PLAN.md Phase 2): the connector end,
            // wrapped from the inherited raw fd. Unlike the old
            // Unix-listener accept loop, this serve loop *does* end —
            // at the pair's EOF, i.e. P closing its end as it exits (a
            // frame-protocol violation ends it too, which costs the
            // sandbox its networking but not the run). It is therefore
            // a background task that nothing waits on: P's exit, reaped
            // by the select below, drives the shutdown, and a serve end
            // racing `wait_status` is harmless instead of a panic (the
            // io driver sees the mux EOF before the blocking waitpid's
            // result makes it back here).
            let mode = net.mode;
            let pair = crate::ipc::netmux::stream_from_raw_fd(net_sv[0]);
            let serve = tokio::spawn(async move {
                match mode {
                    NetMode::Proxy => {
                        crate::proxy::serve_connector(pair, allow, allow_private).await
                    }
                    NetMode::Waf => waf::host::serve_host(pair, allow, allow_private).await,
                }
            });
            // The audit hub: one reader per child channel (FS and P),
            // each forwarding into this process's own event queue — the
            // file writer below is the run's only audit writer. The hub
            // also demultiplexes the children's control replies.
            let hub = crate::audit::spawn_hub();
            let replies = crate::cli::control::Replies::from_peers(hub.replies);
            let status = tokio::select! {
                // P's exit is the run's shutdown trigger: reap it and
                // report its status.
                st = wait_status(pid) => st,
                // The control server: pending forever when control is
                // off (a `--no-control` run never wakes this
                // arm), the accept loop otherwise.
                _ = crate::cli::control::serve_task(replies) => {
                    unreachable!("control accept loop never ends")
                }
                // The SIGHUP reload shim (sugar over `spec-reload`):
                // pending forever when control is off.
                _ = crate::cli::control::reload_task() => {
                    unreachable!("SIGHUP reload loop never ends")
                }
            };
            // Stop serving the mux: P's end closed with it (abort is a
            // no-op if the serve loop already saw the EOF), so nothing
            // records past the audit drain below.
            serve.abort();
            // P is gone (its status was just reaped; its channel end
            // closed with it). Tell FS the run is ending: half-close
            // the hub peers' write side, so FS's read side EOFs and it
            // shuts down — its final events still flow, because this
            // side's read half stays open until each reader saw EOF.
            crate::audit::shutdown_peers();
            // Wait for every child's final batch: a reader ends at EOF,
            // the child's "queue flushed" signal.
            for reader in hub.readers {
                let _ = reader.await;
            }
            // Final file flush: every child event is in the queue now.
            crate::audit::drain().await;
            status
        });

        exit_with_status(status);
    }
}

/// P: owns the sandbox network namespace and runs the mode's in-sandbox
/// frontends on 127.0.0.2 (HTTP CONNECT proxy, or the waf triple). Forks
/// C for the filesystem sandbox and exec, then reports C's exit status.
///
/// `net_fd` is P's end of the net mux socketpair (raw fd, already
/// `SOCK_CLOEXEC`); it is wrapped into a tokio stream inside P's runtime
/// and handed to the frontends as the mux client handle.
// The parameter list mirrors the sandbox setup pipeline (each function
// forwards everything to the next one); one more parameter than clippy's
// default limit is fine here.
#[allow(clippy::too_many_arguments)]
fn isolated_parent(
    net_fd: libc::c_int,
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
        let old_netns = crate::sandbox::netns_id();
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
        crate::sandbox::check_new_netns(old_netns);
        // SB-11: the unshare included CLONE_NEWUTS — replace the copied
        // host hostname with a neutral one (best effort).
        crate::sandbox::set_neutral_hostname_pub();
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

        // Set up the mode's pre-fork environment. The proxy binds its
        // in-sandbox listener (on 127.0.0.2) in `ProxyService::new`, the
        // waf services bind their own listeners (DNS on 127.0.0.2:53,
        // HTTP/HTTPS on 127.0.0.2:80/443) — all after the child fork,
        // once the mux handles exist (see the serving block below).
        // Entries from the spec's `env` section are applied afterwards
        // and so win over these: an explicit spec value is the user's
        // authoritative choice.
        let mut child_env: BTreeMap<String, String> = BTreeMap::new();
        match net.mode {
            NetMode::Proxy => {
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
                        // SB-7: some tools honor only the lowercase form;
                        // without it they would route localhost traffic
                        // through the proxy (breakage, and a
                        // confused-deputy with a wildcard allow entry).
                        ("no_proxy", "localhost,127.0.0.1,::1"),
                    ]
                    .into_iter()
                    .map(|(key, val)| (key.to_string(), val.to_string())),
                );
            }
            NetMode::Waf => {
                // No proxy variables — the DNS server and the
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
            pidns_and_exec(
                ops,
                command,
                &child_env,
                cwd,
                die_with_parent,
                new_session,
                seccomp,
            );
        }

        // Serve the mode's network frontends while the command runs.
        // The allow-list lives entirely in A: the connector re-checks
        // every OPEN host-side (and filters the resolved address), so P
        // holds no list of its own and nothing needs to be pushed to it
        // when the control plane swaps the list.
        let status = block_on(async move {
            // The P end of the net mux channel (PLAN.md Phase 2): the
            // frontends open their host-side requests as mux streams on
            // it. Wrapped inside the runtime, like the audit channel.
            let net_pair = crate::ipc::netmux::stream_from_raw_fd(net_fd);
            // The audit sink must exist before any `record` fires; there
            // is no P-side control loop any more (the allow-list is
            // A-local), so the channel's read half stays unused.
            crate::audit::init_channel_sink();
            let status = match net.mode {
                NetMode::Proxy => {
                    // The proxy service owns the mux handle and binds
                    // its listener (HTTP CONNECT on 127.0.0.2:3128)
                    // here, like the waf services; the accept loop
                    // never ends, so the service lives until
                    // `wait_status` below reports the child's exit.
                    let mux =
                        crate::ipc::netmux::MuxHandle::<crate::proxy::ProxySpec>::client(net_pair);
                    let _proxy_service = crate::proxy::ProxyService::new(mux);
                    let _loops = _proxy_service.spawn();
                    // The accept loop keeps the runtime busy while
                    // wait_status delivers the exit status.
                    wait_status(child_pid).await
                }
                NetMode::Waf => {
                    // Both waf services own the mux handle (cloned off
                    // the one client handle); each binds its own
                    // listeners here and holds its accept loops' join
                    // handles (and the DNS-over-TCP connection cap). The
                    // loops never end, so the services live until
                    // `wait_status` below reports the child's exit.
                    let mux =
                        crate::ipc::netmux::MuxHandle::<crate::waf::WafSpec>::client(net_pair);
                    let _dns_service = waf::DnsService::new(mux.clone());
                    let _http_service = waf::HttpService::new(mux.clone());
                    let _dns_loops = _dns_service.spawn();
                    let _http_loops = _http_service.spawn();
                    // The accept loops keep the runtime busy while
                    // wait_status delivers the exit status.
                    wait_status(child_pid).await
                }
            };
            // Flush the last batch into the connector's still-open channel
            // read end. When the writer task ends it closes the channel,
            // which the connector's hub reader sees as EOF ("queue
            // flushed") — before P exits.
            crate::audit::drain().await;
            status
        });

        exit_with_status(status);
    }
}

/// Wait for `pid` on a blocking thread and return its raw waitpid status,
/// so the async accept loops above are never stalled by waitpid. Also
/// used by the non-isolated supervisor's control-serving branch (see
/// `sandbox::pidns_and_exec`).
pub(crate) async fn wait_status(pid: libc::pid_t) -> libc::c_int {
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
    crate::sandbox::block_on(fut)
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
