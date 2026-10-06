//! Runtime control of a running instance: an abstract-namespace Unix
//! socket owned by the launcher (process A), authenticated with a per-run
//! token, carrying the control protocol (`policy-get`, `fs-set`,
//! `net-set`).
//!
//! # Placement and attack surface
//!
//! The socket lives in the Linux **abstract namespace**
//! (`@ai-bubble-control-<hash(spec dir)>`) in the host network namespace.
//! Abstract addresses are not filesystem objects: on the isolated-network
//! paths the sandbox has its own network namespace and the name does not
//! exist there at all — no mapping, bind or mount can expose it. In host
//! mode the sandbox shares the host network namespace, so the name *is*
//! reachable; the per-run token is the second line of defense there (host
//! mode stays trusted-commands-only, like the spec's `.env`).
//!
//! `SO_PEERCRED` is useless for authentication: inside the sandbox's user
//! namespace the operator's uid maps to 65535, but on the host side of the
//! socket every sandboxed process connects with the operator's real uid —
//! indistinguishable from the operator's own tools. Hence the token.
//!
//! # The control protocol
//!
//! One connection, two phases:
//!
//! 1. a **token preamble**: the first line is the 128-bit token as 32
//!    lowercase hex characters (read from `<spec-dir>/run/control-token`,
//!    mode `0600`). A mismatched, over-long or malformed preamble closes
//!    the connection with no hints.
//! 2. JSON-line commands; each gets exactly one JSON-line reply. Lines are
//!    capped at [`crate::audit`] frame cap (64 KiB) and read with
//!    [`crate::line::read_frame_limited`]; anything malformed closes the
//!    connection.
//!
//! ```text
//! → <hex token>
//! → { "cmd": "policy-get" }
//! ← { "ok": true, "fs": {...}|null, "net": {...}|null }
//! → { "cmd": "fs-set", "mappings": [ ...spec hostfs mapping objects... ] }
//! ← { "ok": true }
//! → { "cmd": "net-set", "allow": [ "example.com:443", ... ] }
//! ← { "ok": true }
//! → { "cmd": "spec-reload" }
//! ← { "ok": false, "err": "immutable section changed: seccomp" }
//! ```
//!
//! Errors reply `{"ok": false, "err": "..."}`.
//!
//! # Propagation
//!
//! `A` is the single control hub. `fs-set` swaps the whole compiled
//! pattern set in the FUSE server (FS); `net-set` swaps the allow-list in
//! `A` and — on the proxy path only — in the in-sandbox proxy (P). The
//! updates travel over the pre-fork `A`↔FS / `A`↔P socketpairs as
//! tagged line-JSON frames: `{"upd": {...}}` downstream, `{"ack": true}` /
//! `{"err": "..."}` upstream (audit events share the same pairs as
//! `{"audit": {...}}` — see [`crate::audit::ipc`]).
//!
//! Correlation is positional, not by id: **at most one outstanding update
//! per channel** (the update gate below serializes applies), and each
//! child replies to the last `upd` in FIFO order.
//!
//! # Semantics
//!
//! * **Full replacement per domain** — never deltas.
//! * **Not retroactive**: both the connector and the proxy snapshot the
//!   allow-list per accepted connection; a swap affects new connections
//!   only. Pattern swaps apply to every new filesystem operation (and
//!   invalidate the readdir cache), but the kernel-level read-only mount
//!   flag, if the run started fully read-only *without* control
//!   (i.e. with `--no-control`),
//!   cannot be re-gained — which is exactly why control is opt-in: a
//!   control-enabled run mounts the FUSE mirror writable and relies on
//!   the per-operation pattern checks alone.
//! * **A keeps the authoritative copy** of both mutable domains (updated
//!   on each accepted `fs-set`/`net-set`, reverted if a child rejects the
//!   apply) — `policy-get` reads it.
//! * Immutable parts (seccomp, mounts, env, `net.allow_private`, the
//!   address-family gates, ...) cannot be changed at runtime.
//!   `spec-reload` re-reads the spec file and applies the *mutable*
//!   subset, but hard-errors naming every changed immutable section
//!   instead of silently ignoring it (see `spec_reload_inner`). SIGHUP
//!   (`kill -HUP` on the launcher) runs the same reload as a shim.

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio::sync::mpsc::Receiver;

use crate::spec::hostfs::Mapping;
use crate::{audit, line, sandbox};

/// Cap for control-protocol command and reply lines: the same budget as
/// the inter-process frames (`waf/mod.rs` `MAX_REPLY` precedent).
pub(crate) const FRAME_CAP: usize = 64 * 1024;

/// How long `A` waits for a child's `ack`/`err` reply to an `upd` frame.
/// The child replies directly on its channel reader (audit backpressure
/// cannot delay the reply); a timeout means the child is wedged and the
/// apply fails (and is reverted).
const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a control client may take to present the token preamble.
const TOKEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The name of the abstract socket for a spec directory:
/// `ai-bubble-control-<16 hex chars of sha256(canonical spec dir)>`.
/// The leading `@` of the abstract address is a NUL byte in `sun_path`.
pub fn socket_name(spec_dir: &Path) -> String {
    let canonical = std::fs::canonicalize(spec_dir)
        .map(|p| p.into_os_string())
        .unwrap_or_else(|_| spec_dir.as_os_str().to_os_string());
    let digest = sha256(canonical.as_encoded_bytes());
    let mut hex = String::with_capacity(16);
    for byte in &digest[..8] {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("ai-bubble-control-{hex}")
}

/// Whether the control server is running in this process (bound socket +
/// written token). Off when control was disabled (`--no-control`), or when the
/// abstract name was already bound (a second concurrent run of the same
/// spec directory runs *without* control — concurrent runs are
/// legitimate and must not be blocked).
pub fn running() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Whether this process still holds the control listener. True in the
/// launcher; false in every fork child after
/// [`close_inherited_listener`] — the fork children must not serve (or
/// think they serve) control. Used by the non-isolated supervisor to
/// decide between the plain waitpid loop and the control-serving
/// runtime, and by `ipc_channel_wanted` (the control plane needs the
/// pre-fork channels even without an audit log).
pub fn listening() -> bool {
    LISTENER_FD.load(Ordering::Relaxed) >= 0 && ACTIVE.load(Ordering::Relaxed)
}

/// The raw fd of the control listener, so fork children that never exec
/// (FS, P) can close it immediately after the fork (`FD_CLOEXEC` only
/// takes effect at `exec`): a lingering copy in a child would keep the
/// abstract name bound after `A` exits. `-1` when control is off or the
/// fd was already closed.
static LISTENER_FD: AtomicI32 = AtomicI32::new(-1);

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The bound server, with its token and bookkeeping for the token file.
static SERVER: OnceLock<Server> = OnceLock::new();

/// The authoritative mutable policy state (see the module docs).
static FS_POLICY: Mutex<Option<Vec<Value>>> = Mutex::new(None);
static FS_AVAILABLE: AtomicBool = AtomicBool::new(false);
static NET_APPLICABLE: AtomicBool = AtomicBool::new(false);
static NET_PROXY: AtomicBool = AtomicBool::new(false);

/// The authoritative compiled configuration the run started with (see
/// [`Start::config`]) and where the spec lives — the baseline and the
/// inputs of `spec-reload`.
static RUNNING_CONFIG: Mutex<Option<crate::spec::internal::SandboxConfig>> = Mutex::new(None);
static SPEC_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
static SESSION_CACHE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// The allow-list `A` enforces itself (the connector / waf host reads
/// this same `Arc`). `None` on the non-isolated path (no allow-list
/// exists there at all).
static NET_ALLOW: OnceLock<crate::proxy::allowlist::SharedAllow> = OnceLock::new();

/// Serializes applies: at most one outstanding `upd` per channel, and
/// only one apply sequence at a time (multiple concurrent control
/// connections must not interleave updates to one child).
static UPD_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The control-plane setup, done by `cli::run` **before any fork**.
pub struct Start {
    pub fs_initial: Option<Vec<Value>>,
    /// A network allow-list exists in `A` (isolated networking).
    pub net_applicable: bool,
    /// The in-sandbox proxy (P) holds its own copy (proxy mode only; the
    /// waf mode's P forwards every decision to `A` and keeps no list).
    pub net_proxy: bool,
    /// The authoritative compiled configuration this run started with:
    /// the baseline `spec-reload` diffs the freshly compiled spec
    /// against (immutable fields must not change).
    pub config: crate::spec::internal::SandboxConfig,
    /// The spec directory, canonicalized: `spec-reload` re-reads the
    /// spec from here, and the SIGHUP shim reports against it.
    pub spec_dir: PathBuf,
    /// The per-run session-cache root (if the spec has session-cache
    /// mappings): reload must resolve the *same* backing directory, or
    /// the replayed preprocessing would diff as a (pointless) mapping
    /// change and reset the session cache mid-run.
    pub session_cache: Option<PathBuf>,
}

struct Server {
    /// The bound listening socket, held for the process lifetime: the
    /// abstract name lives exactly as long as the run.
    listener: std::os::unix::net::UnixListener,
    token: [u8; 16],
    token_path: PathBuf,
}

/// Record the initial policy state (see [`Start`]): the authoritative
/// copies that `policy-get` reads and `fs-set`/`net-set` replace. Called
/// whether or not the server itself is enabled.
pub fn record_initial(cfg: Start) {
    let fs_initial = cfg.fs_initial;
    FS_POLICY
        .lock()
        .unwrap()
        .replace(fs_initial.clone().unwrap_or_default());
    FS_AVAILABLE.store(fs_initial.is_some(), Ordering::Relaxed);
    NET_APPLICABLE.store(cfg.net_applicable, Ordering::Relaxed);
    NET_PROXY.store(cfg.net_proxy, Ordering::Relaxed);
    *RUNNING_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg.config);
    *SPEC_DIR.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg.spec_dir);
    *SESSION_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = cfg.session_cache;
}

/// Bind the abstract socket and write the per-run token, in that order —
/// on `EADDRINUSE` the token file of the *first* run's clients must not
/// be clobbered. Dies when the token file cannot be written; warns and
/// continues *without* control when the abstract name is already taken
/// (a second concurrent run of the same spec directory runs without
/// control; concurrent runs are legitimate and must not be blocked).
pub fn start(spec_dir: &Path) {
    let name = socket_name(spec_dir);
    use std::os::linux::net::SocketAddrExt as _;
    let addr = match std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
        Ok(addr) => addr,
        Err(e) => sandbox::die(&format!("Can't build the control socket address: {e}")),
    };
    let listener = match std::os::unix::net::UnixListener::bind_addr(&addr) {
        Ok(l) => l,
        // A second concurrent run of the same spec directory: warn loudly
        // and run without the control server (never clobber the token!).
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!(
                "ai-bubble: control socket {} already in use — another run of this spec \
                 directory is serving control; this run continues WITHOUT runtime control",
                name
            );
            return;
        }
        Err(e) => sandbox::die(&format!("Can't bind the control socket {name}: {e}")),
    };

    // CLOEXEC: the exec'd sandboxed command (and everything it spawns)
    // must never inherit the listening socket.
    unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    LISTENER_FD.store(listener.as_raw_fd(), Ordering::Relaxed);

    // Bind succeeded — this run owns the name and may write the token.
    let token_path = token_path(spec_dir);
    let token = write_token(&token_path);
    let server = Server {
        listener,
        token,
        token_path,
    };
    if SERVER.set(server).is_err() {
        sandbox::die("control server started twice");
    }
    ACTIVE.store(true, Ordering::Relaxed);
    // The token file must be removed when the run ends — including the
    // abnormal ones (every `die` path leaves via `std::process::exit`,
    // which runs atexit hooks). The listener fd itself needs no hook:
    // the abstract name disappears when the process dies.
    if unsafe { libc::atexit(cleanup_atexit) } != 0 {
        sandbox::die("Can't register the control cleanup hook");
    }
}

/// atexit hook for [`cleanup`] (see [`start`]).
extern "C" fn cleanup_atexit() {
    cleanup();
}

/// `<spec-dir>/run/control-token` (public: the CLI client reads it).
pub fn token_path_for(spec_dir: &Path) -> PathBuf {
    token_path(spec_dir)
}

/// `<spec-dir>/run/control-token`.
fn token_path(spec_dir: &Path) -> PathBuf {
    spec_dir.join("run").join("control-token")
}

/// Generate the per-run token and write it, hex-encoded, mode `0600`,
/// into `<spec-dir>/run/control-token` (the `run/` directory is created
/// `0700` if missing; the file is opened `O_NOFOLLOW`, like the audit
/// log's `safe_open`). The token never enters the sandbox: not via env,
/// not via an injected file, never logged.
fn write_token(path: &Path) -> [u8; 16] {
    let mut token = [0u8; 16];
    fill_random(&mut token);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir(parent)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            sandbox::die(&format!("Can't create {}: {e}", parent.display()));
        }
        // Best effort: the run directory must not be group/other accessible.
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
    let file = open_token_file(path);
    let mut file = file;
    if file.write_all(hex.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
        sandbox::die(&format!("Can't write {}", path.display()));
    }
    token
}

/// Open (create or truncate) the token file `0600` without following a
/// swapped-in symlink (`O_NOFOLLOW`, like [`audit::safe_open`]). This
/// run owns the socket name, so any pre-existing file is a stale token
/// from a crashed run and may be overwritten.
fn open_token_file(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .unwrap_or_else(|e| sandbox::die(&format!("Can't open {}: {e}", path.display())))
}

/// Fill a buffer with kernel randomness (getrandom(2), via libc; no
/// `rand` dependency exists in this crate).
fn fill_random(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        let n =
            unsafe { libc::getrandom(buf[filled..].as_mut_ptr().cast(), buf.len() - filled, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            sandbox::die(&format!("Can't generate the control token: {err}"));
        }
        filled += n as usize;
    }
}

/// Remove this run's token file (best effort). Called on the launcher's
/// clean exit paths.
pub fn cleanup() {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    // NET-3: only the process that still *holds the control listener* may
    // remove the token file. The atexit hook registered by `start` is
    // inherited by fork children, and `std::process::exit` (every `die()`
    // path) runs atexit handlers — without this gate, a mid-run `die()`
    // in P or FS (e.g. a frontend bind failure) would delete
    // `<spec-dir>/run/control-token` while A is still serving, silently
    // killing runtime control for the rest of the run. The child's
    // `close_inherited_listener` already reset the fd to -1; A keeps its
    // own copy and still cleans up.
    if LISTENER_FD.load(Ordering::Relaxed) < 0 {
        return;
    }
    ACTIVE.store(false, Ordering::Relaxed);
    if let Some(server) = SERVER.get() {
        let _ = std::fs::remove_file(&server.token_path);
    }
    let fd = LISTENER_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        // Best effort: close so the abstract name disappears promptly
        // even while the process is still exiting.
        unsafe { libc::close(fd) };
    }
}

/// Close the inherited control listener in a fork child that never execs
/// (FS, P — called immediately after the fork). Without this the child
/// would hold the abstract socket name open after the launcher exits.
pub fn close_inherited_listener() {
    let fd = LISTENER_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    // NET-3: see `cleanup` — the child no longer holds the listener, so
    // its inherited atexit hook becomes a no-op (the token file stays;
    // the launcher's own hook removes it when the run ends).
}

/// Hand `A`'s authoritative allow-list to the control plane. Called by
/// `netns::run` (isolated path) with the same `Arc` the connector / waf
/// host serves from.
pub fn set_allow(allow: crate::proxy::allowlist::SharedAllow) {
    let _ = NET_ALLOW.set(allow);
}

/// The control server's future for the launcher's `select!`: pending
/// forever when control is off (a `--no-control` run never wakes
/// this arm), the accept loop otherwise.
pub async fn serve_task(replies: Replies) {
    if !running() {
        std::future::pending::<()>().await;
        unreachable!();
    }
    serve(replies).await;
}

// ---------------------------------------------------------------------------
// SHA-256 (no `sha2` dependency in this crate; FIPS 180-4)
// ---------------------------------------------------------------------------

/// SHA-256 of `data`, as 32 bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

/// Per-peer reply plumbing handed over from [`audit::ipc::spawn_hub`]:
/// one receiver per child channel, carrying the child's `ack`/`err`
/// reply frames (demultiplexed from audit events by the hub reader).
pub(crate) struct Replies {
    pub fs: Option<Receiver<audit::UpdReply>>,
    pub net: Option<Receiver<audit::UpdReply>>,
}

impl Replies {
    /// Build from [`audit::ipc::spawn_hub`]'s `(role, receiver)` list.
    pub(crate) fn from_peers(peers: Vec<(audit::PeerRole, Receiver<audit::UpdReply>)>) -> Replies {
        let mut fs = None;
        let mut net = None;
        for (role, rx) in peers {
            match role {
                audit::PeerRole::HostFs => fs = Some(rx),
                audit::PeerRole::Network => net = Some(rx),
            }
        }
        Replies { fs, net }
    }
}

/// The control server's accept loop. Never ends (like every other accept
/// loop, it is selected against the launcher's wait; the run's end takes
/// the process down). Does nothing when control is off.
pub async fn serve(replies: Replies) {
    let Some(server) = SERVER.get() else {
        std::future::pending::<()>().await;
        unreachable!();
    };
    // Duplicate the listener fd: the server keeps the original open (the
    // abstract name must live as long as the run); the tokio listener
    // owns the duplicate.
    let raw = unsafe { libc::dup(server.listener.as_raw_fd()) };
    if raw < 0 {
        sandbox::die("Can't serve the control socket");
    }
    let dup = unsafe { std::os::unix::net::UnixListener::from_raw_fd(raw) };
    let _ = dup.set_nonblocking(true);
    let listener = match tokio::net::UnixListener::from_std(dup) {
        Ok(l) => l,
        Err(e) => sandbox::die(&format!("Can't register the control socket: {e}")),
    };
    // Install the per-peer reply receivers the update pusher awaits.
    *FS_REPLIES.lock().unwrap_or_else(|e| e.into_inner()) = replies.fs;
    *NET_REPLIES.lock().unwrap_or_else(|e| e.into_inner()) = replies.net;

    let token = server.token;
    // NET-2: every other listener caps its connections (see
    // `crate::connlimit`); the control listener must too. Without a cap,
    // the sandboxed command in host-network mode (with `unix_sockets`)
    // can compute the deterministic abstract socket name and open
    // hundreds of token-less connections — each holding an fd for up to
    // TOKEN_TIMEOUT — exhausting A's fds. A is also the network
    // connector, so this is a full network DoS of the run; the listener
    // is likewise exposed to any same-uid host process.
    let limit = crate::connlimit::ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Some(guard) = limit.try_acquire() else {
                    continue; // at capacity: drop the connection
                };
                tokio::spawn(async move {
                    let _guard = guard;
                    handle_connection(stream, token).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One authenticated control connection: token preamble, then JSON-line
/// commands with one reply each. Close on any malformed input (no
/// banner, no hints, no second chance).
async fn handle_connection(mut stream: UnixStream, token: [u8; 16]) {
    // The token preamble, length-bounded. A mismatch closes silently.
    let preamble = match tokio::time::timeout(
        TOKEN_TIMEOUT,
        line::read_line_limited(&mut stream, 128),
    )
    .await
    {
        Ok(Ok(Some(hex))) => hex,
        _ => return,
    };
    if !ct_eq_hex(&preamble, &token) {
        return;
    }
    loop {
        match line::read_frame_limited(&mut stream, FRAME_CAP).await {
            Ok(Some(cmd)) => {
                // Malformed input (non-JSON, no "cmd") closes the
                // connection without a reply; a well-formed command gets
                // exactly one reply (errors included).
                let value: Value = match serde_json::from_str(&cmd) {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if value.get("cmd").and_then(|c| c.as_str()).is_none() {
                    return;
                }
                let reply = handle_command(value).await;
                let mut line = serde_json::to_string(&reply)
                    .unwrap_or_else(|_| r#"{"ok":false,"err":"internal error"}"#.to_string());
                line.push('\n');
                if stream.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
            }
            // EOF or malformed: close.
            _ => return,
        }
    }
}

/// Constant-time comparison of a hex-encoded token against the run's
/// token (the sandboxed command in host mode connects with the
/// operator's real uid, so timing must not leak the token).
fn ct_eq_hex(hex: &str, token: &[u8; 16]) -> bool {
    let mut want = String::with_capacity(32);
    for b in token {
        want.push_str(&format!("{b:02x}"));
    }
    let a = hex.as_bytes();
    let b = want.as_bytes();
    // Length mismatch is itself information-free (the client knows the
    // format); the byte comparison is constant-time.
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize)]
struct Reply {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    net: Option<Value>,
}

fn ok_reply() -> Reply {
    Reply {
        ok: true,
        err: None,
        fs: None,
        net: None,
    }
}

fn err_reply(err: impl Into<String>) -> Reply {
    Reply {
        ok: false,
        err: Some(err.into()),
        fs: None,
        net: None,
    }
}

/// Dispatch one command. Malformed shapes are errors (the connection
/// stays open; only framing errors — non-JSON, no "cmd" — close it).
async fn handle_command(value: Value) -> Reply {
    let Some(name) = value.get("cmd").and_then(|c| c.as_str()) else {
        return err_reply("missing \"cmd\"");
    };
    match name {
        "policy-get" => policy_get(),
        "fs-set" => fs_set(&value).await,
        "net-set" => net_set(&value).await,
        "spec-reload" => match spec_reload_inner().await {
            Ok(()) => {
                audit::record(
                    "control",
                    "policy-change",
                    None,
                    Some("ok"),
                    Some("spec-reload".into()),
                )
                .await;
                ok_reply()
            }
            Err(e) => err_reply(e),
        },
        other => err_reply(format!("unknown command {other:?}")),
    }
}

/// The current mutable policy: the `fs` domain (the raw spec mapping
/// objects) and the `net` domain (the allow-list), each `null` when not
/// applicable to this run.
fn policy_get() -> Reply {
    let fs = FS_AVAILABLE
        .load(Ordering::Relaxed)
        .then(|| {
            FS_POLICY
                .lock()
                .unwrap()
                .clone()
                .map(|mappings| serde_json::json!({ "mappings": mappings }))
        })
        .flatten();
    let net = if NET_APPLICABLE.load(Ordering::Relaxed) {
        NET_ALLOW.get().map(|allow| {
            let allow = allow.read().unwrap_or_else(|e| e.into_inner()).clone();
            serde_json::json!({ "allow": allow })
        })
    } else {
        None
    };
    Reply {
        ok: true,
        err: None,
        fs,
        net,
    }
}

/// Replace the whole FUSE pattern set: validate the client's mapping
/// objects (the same shapes as the spec's `hostfs.mappings`), push them
/// to FS over the control channel and — only after FS acknowledged —
/// commit them as the authoritative copy.
async fn fs_set(value: &Value) -> Reply {
    if !FS_AVAILABLE.load(Ordering::Relaxed) {
        return err_reply("no FUSE filesystem in this run");
    }
    let Some(mappings) = value.get("mappings") else {
        return err_reply("missing \"mappings\"");
    };
    let Some(mappings) = mappings.as_array() else {
        return err_reply("\"mappings\" must be an array");
    };
    match fs_apply_list(mappings).await {
        Ok(()) => {
            audit::record(
                "control",
                "policy-change",
                None,
                Some("ok"),
                Some("fs-set".into()),
            )
            .await;
            ok_reply()
        }
        Err(e) => err_reply(e),
    }
}

/// Validate a mapping list against the spec parser's rules and swap it
/// in (FS push + authoritative-commit). Shared by the `fs-set` command
/// and `spec-reload`; the caller audits the change. The whole sequence
/// is serialized behind [`UPD_GATE`] (one outstanding update per
/// channel, and no interleaved applies from concurrent control
/// connections or the SIGHUP shim).
async fn fs_apply_list(mappings: &[Value]) -> Result<(), String> {
    // Validate exactly what the spec parser would accept (glob compile
    // failures included), *before* anything is swapped anywhere.
    let parsed: Vec<Mapping> = match mappings
        .iter()
        .map(|raw| serde_json::from_value::<Mapping>(raw.clone()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(parsed) => parsed,
        Err(e) => return Err(format!("invalid mapping: {e}")),
    };
    crate::spec::hostfs::patterns_from_mappings(&parsed)?;
    // Apply the spec-directory protection invariants (SP-1): reject
    // bind/redirect sources covering the spec directory and re-append the
    // auto-hide mapping, exactly like the spec loader does — otherwise a
    // token holder could re-open spec.json, the env file (secrets) and
    // the control token, or silently drop the auto-hide pattern with a
    // hand-written full-replacement list.
    let spec_dir = SPEC_DIR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("no spec directory recorded for this run")?;
    let parsed = crate::spec::file::Spec::control_plane_mapping_list(parsed, &spec_dir)?;
    let owned: Vec<Value> = parsed
        .iter()
        .map(|m| serde_json::to_value(m).expect("mapping serializes"))
        .collect();
    let _gate = UPD_GATE.lock().await;
    match push_upd(serde_json::json!({ "fs": { "mappings": owned } }), Role::Fs).await {
        Ok(()) => {
            *FS_POLICY.lock().unwrap() = Some(owned);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Replace the whole network allow-list: swap `A`'s copy first (the
/// connector / waf host serves from it), then — on the proxy path only —
/// push the same list to P. If P rejects (or times out), `A`'s copy is
/// reverted so the two sides never disagree. Not retroactive to
/// in-flight flows (both sides snapshot the list per connection).
async fn net_set(value: &Value) -> Reply {
    if !NET_APPLICABLE.load(Ordering::Relaxed) {
        return err_reply("no network allow-list in this run (host networking)");
    }
    let Some(allow) = value.get("allow") else {
        return err_reply("missing \"allow\"");
    };
    let Some(allow) = allow.as_array() else {
        return err_reply("\"allow\" must be an array");
    };
    let list = match allow_entries(allow) {
        Ok(list) => list,
        Err(e) => return err_reply(e),
    };
    match net_apply_list(list).await {
        Ok(()) => {
            audit::record(
                "control",
                "policy-change",
                None,
                Some("ok"),
                Some("net-set".into()),
            )
            .await;
            ok_reply()
        }
        Err(e) => err_reply(e),
    }
}

/// Validate the `allow` array's entries (strings, non-empty, printable,
/// bounded length).
fn allow_entries(allow: &[Value]) -> Result<Vec<String>, String> {
    let mut list = Vec::with_capacity(allow.len());
    for entry in allow {
        let Some(entry) = entry.as_str() else {
            return Err("\"allow\" entries must be strings".to_string());
        };
        let entry = entry.trim();
        if entry.is_empty() || entry.len() > 253 || !entry.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("invalid allow-list entry {entry:?}"));
        }
        // NET-6: reject dead entries at load — a port suffix that does
        // not parse can never match, and the spec parse does no
        // validation otherwise (the control plane validating what the
        // spec file accepts would be inconsistent).
        crate::proxy::allowlist::validate_entry(entry)?;
        list.push(entry.to_string());
    }
    Ok(list)
}

/// Swap the allow-list in `A` (and, on the proxy path, in P) — shared by
/// the `net-set` command and `spec-reload`; the caller audits the
/// change. Serialized behind [`UPD_GATE`] like [`fs_apply_list`].
async fn net_apply_list(list: Vec<String>) -> Result<(), String> {
    let _gate = UPD_GATE.lock().await;
    let Some(shared) = NET_ALLOW.get() else {
        return Err("no network allow-list in this run".to_string());
    };
    let previous = {
        let mut guard = shared.write().unwrap_or_else(|e| e.into_inner());
        std::mem::replace(&mut *guard, list)
    };
    // Proxy mode only: P holds its own copy and answers 403 early.
    let push = if NET_PROXY.load(Ordering::Relaxed) {
        push_upd(
            serde_json::json!({ "net": { "allow": shared.read().unwrap_or_else(|e| e.into_inner()).clone() } }),
            Role::Net,
        )
        .await
    } else {
        Ok(())
    };
    match push {
        Ok(()) => Ok(()),
        Err(e) => {
            // Revert: `A`'s copy must never diverge from the children's.
            *shared.write().unwrap_or_else(|e| e.into_inner()) = previous;
            Err(e)
        }
    }
}

/// Which child channel an update is pushed to.
#[derive(Clone, Copy, PartialEq)]
enum Role {
    Fs,
    Net,
}

impl Role {
    fn peer(self) -> audit::PeerRole {
        match self {
            Role::Fs => audit::PeerRole::HostFs,
            Role::Net => audit::PeerRole::Network,
        }
    }
}

/// The per-peer reply receivers, filled by `serve`'s caller from
/// [`audit::ipc::spawn_hub`]'s return value.
static FS_REPLIES: Mutex<Option<Receiver<audit::UpdReply>>> = Mutex::new(None);
static NET_REPLIES: Mutex<Option<Receiver<audit::UpdReply>>> = Mutex::new(None);

/// Send one `upd` frame to a child and await its reply (FIFO, positional
/// correlation — at most one outstanding update per channel, enforced by
/// [`UPD_GATE`]). The reply is awaited with a timeout: a wedged child
/// fails the apply instead of wedging the control client.
async fn push_upd(upd: Value, role: Role) -> Result<(), String> {
    let rx_slot = match role {
        Role::Fs => &FS_REPLIES,
        Role::Net => &NET_REPLIES,
    };
    let Some(mut stream) = audit::peer_writer(role.peer()) else {
        return Err(match role {
            Role::Fs => "the FUSE server is not reachable".to_string(),
            Role::Net => "the sandbox proxy is not reachable".to_string(),
        });
    };
    let mut frame =
        serde_json::to_string(&upd).map_err(|e| format!("can't serialize the update: {e}"))?;
    if frame.len() > FRAME_CAP {
        return Err("update too large".to_string());
    }
    frame.push('\n');
    if stream.write_all(frame.as_bytes()).await.is_err() {
        return Err("can't send the update to the sandbox child".to_string());
    }
    let mut rx = rx_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
    let reply = tokio::time::timeout(REPLY_TIMEOUT, async {
        match &mut rx {
            Some(rx) => rx.recv().await,
            None => None,
        }
    })
    .await;
    // The receiver goes back for the next update (one outstanding per
    // channel is enforced by the gate, so this is race-free).
    if rx.is_some() {
        *rx_slot.lock().unwrap_or_else(|e| e.into_inner()) = rx.take();
    }
    match reply {
        Ok(Some(audit::UpdReply::Ack)) => Ok(()),
        Ok(Some(audit::UpdReply::Err(e))) => Err(e),
        _ => Err("the sandbox child did not acknowledge the update".to_string()),
    }
}

// ---------------------------------------------------------------------------
// spec-reload (and the SIGHUP shim over it)
// ---------------------------------------------------------------------------

/// `spec-reload`: re-read the spec file, replay the same preprocessing
/// `ai-bubble run` applied to it (waf's injected resolver/CA mappings,
/// the cache-mapping resolution), compile it *fallibly*, and apply the
/// mutable domains — **only if** every immutable part is unchanged.
///
/// The diff runs over the compiled configurations, field by field:
/// `ops`, `env`, `cwd`, `seccomp`, `rlimits`, `audit` and the immutable
/// `net` fields (`isolated`/`mode`/`allow_private`/the address-family
/// gates) must be identical to what the run started with; only
/// `hostfs.mappings` (the pattern set) and `net.allow` may change. A
/// changed immutable part is an error that *names* the sections —
/// otherwise an operator would believe they tightened seccomp when
/// nothing happened.
///
/// The mutable domains are applied as full replacements (exactly like
/// `fs-set`/`net-set`, through the same [`UPD_GATE`] serialization);
/// unchanged domains are not pushed at all. If the second domain's
/// apply fails after the first succeeded, the first is reverted, so the
/// run is never left half-reloaded.
async fn spec_reload_inner() -> Result<(), String> {
    let Some(spec_dir) = SPEC_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
        return Err("no spec directory recorded for this run".to_string());
    };
    let Some(running) = RUNNING_CONFIG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    else {
        return Err("no running configuration recorded for this run".to_string());
    };
    // Replay the run's preprocessing *idempotently*: `prepare_caches`
    // resolves the cache mappings against the same backing directories
    // (the run's session-cache root and the spec directory's `cache`
    // folder), so a reload never diffs as a spurious mapping change and
    // never resets the session cache mid-run.
    let session_cache = SESSION_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut spec = crate::spec::Spec::try_load(Some(spec_dir.as_path()))?;
    crate::cli::preprocess_spec(&mut spec, spec_dir.as_path(), session_cache.as_deref())?;
    let fresh = crate::spec::internal::SandboxConfig::try_compile(&spec)?;

    let changed = immutable_changes(&running, &fresh);
    if !changed.is_empty() {
        return Err(format!(
            "immutable section changed: {}; the running sandbox cannot change \
             mounts, env, cwd, seccomp, rlimits, the audit log or the immutable \
             network settings — restart the run instead",
            changed.join(", ")
        ));
    }

    // The previous mutable state, for the revert below.
    let previous_mappings = FS_POLICY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default();
    let previous_allow = NET_ALLOW
        .get()
        .map(|allow| allow.read().unwrap_or_else(|e| e.into_inner()).clone());

    // The fs domain: only a *changed* mapping list is pushed (and only
    // when a FUSE filesystem exists to push it to — a run without
    // hostfs mappings cannot grow any, because the sandbox root is
    // already a plain tmpfs).
    let mappings = serde_json::to_value(&spec.hostfs.mappings)
        .map(|value| value.as_array().cloned().unwrap_or_default())
        .unwrap_or_default();
    let fs_changed = mappings != previous_mappings;
    if fs_changed && !FS_AVAILABLE.load(Ordering::Relaxed) {
        return Err(
            "the new spec adds hostfs mappings, but this run has no FUSE \
             filesystem to apply them to"
                .to_string(),
        );
    }
    if fs_changed {
        fs_apply_list(&mappings).await?;
    }

    // The net domain: same "only when changed" rule; a host-networking
    // run has no allow-list, so a change there cannot be applied.
    let net_changed = match previous_allow {
        Some(previous) => fresh.net.allow != previous,
        None => false,
    };
    if net_changed && !NET_APPLICABLE.load(Ordering::Relaxed) {
        // The fs domain may have been applied above: revert it, so the
        // run is never left half-reloaded.
        if fs_changed {
            let _ = fs_apply_list(&previous_mappings).await;
        }
        return Err(
            "the new spec changes net.allow, but this run has no network \
             allow-list to apply it to (host networking)"
                .to_string(),
        );
    }
    if let Err(e) = async {
        if net_changed {
            net_apply_list(fresh.net.allow.clone()).await?;
        }
        Ok::<(), String>(())
    }
    .await
    {
        // Revert the fs domain: never half-reloaded.
        if fs_changed {
            let _ = fs_apply_list(&previous_mappings).await;
        }
        return Err(e);
    }

    // The authoritative copy moves forward only after every apply
    // succeeded.
    *RUNNING_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(fresh);
    Ok(())
}

/// Which immutable sections differ between the running configuration
/// and the freshly compiled one (see [`spec_reload_inner`]).
fn immutable_changes(
    running: &crate::spec::internal::SandboxConfig,
    fresh: &crate::spec::internal::SandboxConfig,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if running.ops != fresh.ops {
        changed.push("ops (mounts/symlinks)");
    }
    if running.env != fresh.env {
        changed.push("env");
    }
    if running.cwd != fresh.cwd {
        changed.push("cwd");
    }
    if running.seccomp != fresh.seccomp {
        changed.push("seccomp");
    }
    if running.rlimits != fresh.rlimits {
        changed.push("rlimits");
    }
    if running.audit_log != fresh.audit_log {
        changed.push("audit (the log path)");
    }
    if running.net.isolated != fresh.net.isolated
        || running.net.mode != fresh.net.mode
        || running.net.allow_private != fresh.net.allow_private
        || running.net.unix_sockets != fresh.net.unix_sockets
        || running.net.netlink != fresh.net.netlink
        || running.net.vsock != fresh.net.vsock
        || running.net.bluetooth != fresh.net.bluetooth
    {
        changed.push("net (mode/allow_private/family gates)");
    }
    changed
}

/// The SIGHUP reload shim: `kill -HUP <the ai-bubble run's pid>` runs
/// the same [`spec_reload_inner`] as the `spec-reload` control command
/// — sugar for setups where no control client is at hand. The task is
/// selected alongside the launcher's other loops; it is inert (and
/// SIGHUP keeps its default terminate semantics) whenever the run is
/// not control-enabled.
pub async fn reload_task() {
    if !running() {
        std::future::pending::<()>().await;
        unreachable!();
    }
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(hup) => hup,
        Err(e) => {
            eprintln!("ai-bubble: warning: Can't install the SIGHUP reload handler: {e}");
            std::future::pending::<()>().await;
            unreachable!();
        }
    };
    loop {
        hup.recv().await;
        match spec_reload_inner().await {
            Ok(()) => {
                audit::record(
                    "control",
                    "policy-change",
                    None,
                    Some("ok"),
                    Some("spec-reload (SIGHUP)".into()),
                )
                .await;
                eprintln!("ai-bubble: spec reloaded on SIGHUP");
            }
            Err(e) => eprintln!("ai-bubble: SIGHUP spec reload rejected: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Child side (FS and P): the control reader on the pre-fork channel
// ---------------------------------------------------------------------------

/// One downstream update frame: `{"upd": {"fs": {...}, "net": {...}}}`.
/// A child applies the domains it owns; unknown/foreign domains are an
/// error reply, not a swap.
#[derive(Deserialize)]
pub(crate) struct UpdFrame {
    upd: Upd,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Upd {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fs: Option<FsUpd>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    net: Option<NetUpd>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FsUpd {
    mappings: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetUpd {
    allow: Vec<String>,
}

/// The child's shared channel write half: audit batches and control
/// replies go through the same mutex-guarded stream, so whole frames
/// never interleave mid-line (see [`crate::audit::ipc::channel_streams`]).
pub(crate) type SharedWrite = std::sync::Arc<tokio::sync::Mutex<UnixStream>>;

/// Write the child's reply directly on the channel — never through the
/// audit batch queue — so an audit backlog can never delay a reply `A`
/// is awaiting (the reply is a small, self-contained write). The shared
/// mutex keeps it from splitting a concurrent audit batch.
pub(crate) async fn write_reply(stream: &SharedWrite, reply: Result<(), String>) {
    let line = match reply {
        Ok(()) => "{\"ack\":true}\n".to_string(),
        Err(e) => {
            // Keep the frame under the cap no matter what the message is.
            let mut err = e;
            while err.len() > FRAME_CAP / 2 {
                let mut cut = err.len() * 3 / 4;
                while !err.is_char_boundary(cut) {
                    cut -= 1;
                }
                err.truncate(cut);
            }
            format!(
                "{{\"err\":{}}}\n",
                serde_json::to_string(&err).unwrap_or_else(|_| "\"error\"".into())
            )
        }
    };
    let mut stream = stream.lock().await;
    let _ = stream.write_all(line.as_bytes()).await;
}

/// Parse and apply one downstream frame on the FUSE server side: swap
/// the whole compiled pattern set. The readdir cache is invalidated
/// automatically via the policy generation (see
/// [`crate::hostfs::SharedPatterns`]).
pub(crate) async fn fs_apply(
    upd: Upd,
    policy: &crate::hostfs::SharedPatterns,
) -> Result<(), String> {
    let Some(fs) = upd.fs else {
        if upd.net.is_some() {
            return Err("net updates are not handled by the filesystem server".into());
        }
        return Ok(());
    };
    let mappings = fs
        .mappings
        .iter()
        .map(|raw| serde_json::from_value::<Mapping>(raw.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid mapping: {e}"))?;
    let patterns = crate::spec::hostfs::patterns_from_mappings(&mappings)?;
    policy.set(patterns);
    Ok(())
}

/// Parse and apply one downstream frame on the sandbox proxy side (P,
/// proxy mode): swap the allow-list. Affects new connections only.
pub(crate) async fn net_apply(
    upd: Upd,
    allow: &crate::proxy::allowlist::SharedAllow,
) -> Result<(), String> {
    let Some(net) = upd.net else {
        if upd.fs.is_some() {
            return Err("fs updates are not handled by the network proxy".into());
        }
        return Ok(());
    };
    *allow.write().unwrap_or_else(|e| e.into_inner()) = net.allow;
    Ok(())
}

/// The FUSE server's control loop: read one downstream frame from the
/// channel's read half, apply it, reply on the shared write half —
/// until the launcher half-closes the channel (EOF: the run is ending)
/// or the channel errors. This subsumes the old
/// `spawn_channel_eof_watch`: the frames *are* the launcher→child
/// direction now, and its EOF is the shutdown signal.
pub(crate) async fn fs_child_loop(
    mut stream: UnixStream,
    reply: SharedWrite,
    policy: crate::hostfs::SharedPatterns,
) {
    let mut malformed_reported = false;
    loop {
        match line::read_frame_limited(&mut stream, audit::FRAME_CAP).await {
            Ok(Some(frame)) => {
                let r = match serde_json::from_str::<UpdFrame>(&frame) {
                    Ok(parsed) => fs_apply(parsed.upd, &policy).await,
                    Err(e) => {
                        // A bug in a trusted child's counterpart, not an
                        // attack: warn once, keep the channel (the audit
                        // direction is unaffected), reply with an error.
                        if !malformed_reported {
                            malformed_reported = true;
                            eprintln!("warning: malformed control frame from the launcher: {e}");
                        }
                        Err(format!("malformed update: {e}"))
                    }
                };
                write_reply(&reply, r).await;
            }
            // Clean EOF: the launcher said "the run is ending".
            Ok(None) => return,
            Err(e) => {
                if !malformed_reported {
                    eprintln!("warning: control channel error: {e}");
                }
                return;
            }
        }
    }
}

/// The sandbox proxy's control loop (P, proxy mode): same discipline as
/// [`fs_child_loop`], swapping the allow-list. P's shutdown stays driven
/// by the sandboxed command's exit (`wait_status`); this loop simply
/// ends at the launcher's EOF.
pub(crate) async fn net_child_loop(
    mut stream: UnixStream,
    reply: SharedWrite,
    allow: crate::proxy::allowlist::SharedAllow,
) {
    let mut malformed_reported = false;
    loop {
        match line::read_frame_limited(&mut stream, audit::FRAME_CAP).await {
            Ok(Some(frame)) => {
                let r = match serde_json::from_str::<UpdFrame>(&frame) {
                    Ok(parsed) => net_apply(parsed.upd, &allow).await,
                    Err(e) => {
                        if !malformed_reported {
                            malformed_reported = true;
                            eprintln!("warning: malformed control frame from the launcher: {e}");
                        }
                        Err(format!("malformed update: {e}"))
                    }
                };
                write_reply(&reply, r).await;
            }
            Ok(None) => return,
            Err(e) => {
                if !malformed_reported {
                    eprintln!("warning: control channel error: {e}");
                }
                return;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test-only access to the pieces the real paths wire up.
    pub(crate) use super::{fs_apply, net_apply};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The statics these tests mutate are process-global and the tests
    /// run concurrently: serialize them.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A guard that is dropped before any `await` (a plain `MutexGuard`
    /// is not `Send` and must not be held across one — clippy's rule, and
    /// these tests never need it across an await anyway).
    fn scope_guard() -> impl Drop {
        lock()
    }

    /// SHA-256 reference vectors (FIPS 180-4 / NIST).
    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex_of(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_of(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_of(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // One million 'a' characters, in 1000-byte blocks (the padding
        // path exercised by multi-block messages).
        let block = [b'a'; 1000];
        let mut data = Vec::with_capacity(1_000_000);
        for _ in 0..1000 {
            data.extend_from_slice(&block);
        }
        assert_eq!(
            hex_of(sha256(&data)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    fn hex_of(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The socket name is deterministic for the same spec directory and
    /// differs between directories; relative and absolute spellings of
    /// the *same* directory must hash identically (both `A` and the CLI
    /// client realpath before hashing).
    #[test]
    fn socket_name_is_canonical_path_keyed() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-ctl-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = socket_name(&dir);
        let b = socket_name(&dir);
        assert_eq!(a, b);
        assert!(a.starts_with("ai-bubble-control-"));
        assert_eq!(a.len(), "ai-bubble-control-".len() + 16);

        let rel = std::path::Path::new(".").canonicalize().unwrap();
        let nested = dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let from_parent = socket_name(&nested);
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let from_inside = socket_name(std::path::Path::new("nested"));
        std::env::set_current_dir(cwd).unwrap();
        assert_eq!(from_parent, from_inside);
        assert_ne!(from_parent, socket_name(&rel));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The token comparison is constant-time and exact.
    #[test]
    fn token_comparison() {
        let token = [
            0xa7, 0x1b, 0x3c, 0x9d, 0x5e, 0x2f, 0x60, 0x81, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
            0x08, 0x19,
        ];
        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        assert!(ct_eq_hex(&hex, &token));
        assert!(!ct_eq_hex(&hex.to_uppercase(), &token));
        assert!(!ct_eq_hex(&hex[..31], &token));
        assert!(!ct_eq_hex("00000000000000000000000000000000", &token));
        // Malformed preambles never authenticate.
        assert!(!ct_eq_hex("", &token));
    }

    /// The generated token file is mode `0600` and holds the same token
    /// that `start` would later authenticate against.
    #[test]
    fn token_file_is_written_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ai-bubble-ctl-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("run").join("control-token");
        let token = write_token(&path);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let hex = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            hex.trim(),
            token.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        // The run directory is not group/other accessible.
        let run = std::fs::metadata(dir.join("run")).unwrap();
        assert_eq!(run.permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `policy-get` echoes the authoritative state; `fs-set`/`net-set`
    /// reject inapplicable domains without touching anything.
    #[tokio::test]
    async fn command_dispatch_and_applicability() {
        let _guard = scope_guard();
        // No FUSE, no network allow-list configured.
        FS_POLICY.lock().unwrap().replace(Vec::new());
        FS_AVAILABLE.store(false, Ordering::Relaxed);
        NET_APPLICABLE.store(false, Ordering::Relaxed);
        NET_PROXY.store(false, Ordering::Relaxed);

        let reply = handle_command(serde_json::json!({"cmd": "policy-get"})).await;
        assert!(reply.ok);
        assert!(reply.fs.is_none(), "no FUSE filesystem in this run");
        assert!(reply.net.is_none());

        let reply = handle_command(serde_json::json!({"cmd": "fs-set", "mappings": []})).await;
        assert!(!reply.ok, "fs-set must fail without a FUSE filesystem");

        let reply = handle_command(serde_json::json!({"cmd": "net-set", "allow": []})).await;
        assert!(!reply.ok, "net-set must fail without a network allow-list");

        let reply = handle_command(serde_json::json!({"cmd": "bogus"})).await;
        assert!(!reply.ok);
    }

    /// An invalid mapping object is rejected client-side (the same
    /// validation the spec parser applies) — nothing is swapped.
    #[tokio::test]
    async fn fs_set_validates_mappings() {
        let _guard = scope_guard();
        FS_POLICY.lock().unwrap().replace(Vec::new());
        FS_AVAILABLE.store(true, Ordering::Relaxed);
        NET_APPLICABLE.store(false, Ordering::Relaxed);
        // No FS peer registered: the push itself would fail — but
        // validation must fail *first*, with the mapping error.
        let reply = handle_command(serde_json::json!({"cmd": "fs-set", "mappings": [
            {"type": "ro", "glob": "relative/path"}
        ]}))
        .await;
        assert!(!reply.ok);
        assert!(reply.err.unwrap().contains("absolute"));
        FS_AVAILABLE.store(false, Ordering::Relaxed);
    }

    /// Allow-list entries are validated: strings, non-empty, printable,
    /// bounded length.
    #[tokio::test]
    async fn net_set_validates_entries() {
        let _guard = scope_guard();
        FS_AVAILABLE.store(false, Ordering::Relaxed);
        NET_APPLICABLE.store(true, Ordering::Relaxed);
        NET_PROXY.store(false, Ordering::Relaxed);
        // `NET_ALLOW` is a process-global OnceLock; if another test in
        // this process (e.g. the end-to-end one) already set it, reuse
        // that instance and reset its contents.
        let shared = crate::cli::control::NET_ALLOW.get().cloned().unwrap_or_else(|| {
            let shared = Arc::new(std::sync::RwLock::new(Vec::new()));
            let _ = crate::cli::control::NET_ALLOW.set(std::sync::Arc::clone(&shared));
            shared
        });
        *shared.write().unwrap() = vec!["initial.example:443".to_string()];

        let reply =
            handle_command(serde_json::json!({"cmd": "net-set", "allow": ["ok.example:443"]}))
                .await;
        assert!(reply.ok, "{:?}", reply.err);
        assert_eq!(*shared.read().unwrap(), vec!["ok.example:443".to_string()]);

        for bad in [
            serde_json::json!({"cmd": "net-set", "allow": ["has space.example"]}),
            serde_json::json!({"cmd": "net-set", "allow": [""]}),
            serde_json::json!({"cmd": "net-set", "allow": [42]}),
        ] {
            let reply = handle_command(bad.clone()).await;
            assert!(!reply.ok, "{bad}");
        }
        // The list is untouched by the failures.
        assert_eq!(*shared.read().unwrap(), vec!["ok.example:443".to_string()]);
        NET_APPLICABLE.store(false, Ordering::Relaxed);
    }

    /// The downstream frame parses, and the child-side appliers swap the
    /// shared state (patterns with a generation bump, allow-list) and
    /// reject foreign domains.
    #[tokio::test]
    async fn child_appliers_swap_shared_state() {
        use crate::hostfs::{SharedPatterns, patterns::Permission};
        let policy = Arc::new(SharedPatterns::new(crate::hostfs::patterns::Patterns::new(
            vec![("/etc".to_string(), Permission::Ro)],
        )));
        let gen0 = policy.generation();

        let frame = r#"{"upd":{"fs":{"mappings":[{"type":"rw","glob":"/work"}]}}}"#;
        let parsed: UpdFrame = serde_json::from_str(frame).unwrap();
        testing::fs_apply(parsed.upd, &policy).await.unwrap();
        assert_eq!(policy.generation(), gen0 + 1);
        let patterns = policy.snapshot().0;
        assert!(patterns.writable(std::path::Path::new("/work/x")));
        assert!(!patterns.writable(std::path::Path::new("/etc")));

        // A foreign domain is an error, not a silent no-op.
        let frame = r#"{"upd":{"net":{"allow":["example.com"]}}}"#;
        let parsed: UpdFrame = serde_json::from_str(frame).unwrap();
        assert!(testing::fs_apply(parsed.upd, &policy).await.is_err());

        // The net applier swaps the allow-list; fs frames are foreign.
        let shared = Arc::new(std::sync::RwLock::new(Vec::new()));
        let frame = r#"{"upd":{"net":{"allow":["example.com:443"]}}}"#;
        let parsed: UpdFrame = serde_json::from_str(frame).unwrap();
        testing::net_apply(parsed.upd, &shared).await.unwrap();
        assert_eq!(*shared.read().unwrap(), vec!["example.com:443".to_string()]);
        let frame = r#"{"upd":{"fs":{"mappings":[]}}}"#;
        let parsed: UpdFrame = serde_json::from_str(frame).unwrap();
        assert!(testing::net_apply(parsed.upd, &shared).await.is_err());
    }

    use tokio::io::AsyncReadExt as _;

    /// End-to-end through a real socketpair: `net_child_loop` swaps the
    /// allow-list and answers `{"ack":true}` on the same stream.
    #[tokio::test]
    async fn net_child_loop_swaps_and_acks() {
        let (launcher_std, child_std) = std::os::unix::net::UnixStream::pair().unwrap();
        // Split the child end into its read half (control loop) and the
        // mutex-shared write half (replies), like `ipc::channel_streams`.
        let child_read = child_std.try_clone().unwrap();
        let _ = child_read.set_nonblocking(true);
        let _ = child_std.set_nonblocking(true);
        let _ = launcher_std.set_nonblocking(true);
        let mut launcher = tokio::net::UnixStream::from_std(launcher_std).unwrap();
        let child = tokio::net::UnixStream::from_std(child_read).unwrap();
        let reply: crate::cli::control::SharedWrite = Arc::new(tokio::sync::Mutex::new(
            tokio::net::UnixStream::from_std(child_std).unwrap(),
        ));
        let shared = Arc::new(std::sync::RwLock::new(Vec::new()));
        let loop_task = tokio::spawn(crate::cli::control::net_child_loop(
            child,
            reply,
            std::sync::Arc::clone(&shared),
        ));
        launcher
            .write_all(b"{\"upd\":{\"net\":{\"allow\":[\"example.com:443\"]}}}\n")
            .await
            .unwrap();
        let mut reply = String::new();
        let mut byte = [0u8; 1];
        loop {
            let n = launcher.read(&mut byte).await.unwrap();
            assert!(n > 0, "no reply");
            if byte[0] == b'\n' {
                break;
            }
            reply.push(byte[0] as char);
        }
        assert_eq!(reply, "{\"ack\":true}");
        assert_eq!(*shared.read().unwrap(), vec!["example.com:443".to_string()]);
        // The launcher's half-close ends the loop (the shutdown signal on
        // the FS path; P's loop simply ends here too).
        let _ = launcher.shutdown().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), loop_task)
            .await
            .expect("child loop must end at the launcher's EOF")
            .unwrap();
    }

    /// The FS loop applies a pattern swap and answers an error for a
    /// mapping list the spec parser would reject — without swapping
    /// anything.
    #[tokio::test]
    async fn fs_child_loop_swaps_and_rejects() {
        use crate::hostfs::patterns::Permission;
        let (launcher_std, child_std) = std::os::unix::net::UnixStream::pair().unwrap();
        let child_read = child_std.try_clone().unwrap();
        let _ = child_read.set_nonblocking(true);
        let _ = child_std.set_nonblocking(true);
        let _ = launcher_std.set_nonblocking(true);
        let mut launcher = tokio::net::UnixStream::from_std(launcher_std).unwrap();
        let child = tokio::net::UnixStream::from_std(child_read).unwrap();
        let reply: crate::cli::control::SharedWrite = Arc::new(tokio::sync::Mutex::new(
            tokio::net::UnixStream::from_std(child_std).unwrap(),
        ));
        let policy = Arc::new(crate::hostfs::SharedPatterns::new(
            crate::hostfs::patterns::Patterns::new(vec![("/etc".to_string(), Permission::Ro)]),
        ));
        let gen0 = policy.generation();
        let loop_task = tokio::spawn(crate::cli::control::fs_child_loop(
            child,
            reply,
            (*policy).clone(),
        ));
        launcher
            .write_all(
                b"{\"upd\":{\"fs\":{\"mappings\":[{\"type\":\"rw\",\"glob\":\"/work\"}]}}}\n",
            )
            .await
            .unwrap();
        read_ack(&mut launcher).await;
        assert_eq!(policy.generation(), gen0 + 1);
        assert!(
            policy
                .snapshot()
                .0
                .writable(std::path::Path::new("/work/x"))
        );

        // A bad glob is an `err` reply; the patterns are untouched.
        launcher
            .write_all(
                b"{\"upd\":{\"fs\":{\"mappings\":[{\"type\":\"rw\",\"glob\":\"/work/[\"}]}}}\n",
            )
            .await
            .unwrap();
        let mut reply = String::new();
        let mut byte = [0u8; 1];
        loop {
            let n = launcher.read(&mut byte).await.unwrap();
            assert!(n > 0, "no reply");
            if byte[0] == b'\n' {
                break;
            }
            reply.push(byte[0] as char);
        }
        assert!(reply.starts_with("{\"err\":"), "{reply}");
        assert_eq!(policy.generation(), gen0 + 1);
        let _ = launcher.shutdown().await;
        let _ = loop_task.await;
    }

    /// Read one line and assert it is the ack frame.
    async fn read_ack(stream: &mut tokio::net::UnixStream) {
        use tokio::io::AsyncReadExt as _;
        let mut reply = String::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n > 0, "no reply");
            if byte[0] == b'\n' {
                break;
            }
            reply.push(byte[0] as char);
        }
        assert_eq!(reply, "{\"ack\":true}", "{reply}");
    }

    /// The real server, end to end: `record_initial` + `start` (binding the
    /// actual abstract socket and writing the real token file), the real
    /// accept loop, and a client speaking the token-preamble protocol —
    /// exactly what `ai-bubble control` does.
    ///
    /// The client runs on `spawn_blocking` on purpose: it uses *blocking*
    /// std I/O (like the real CLI does), and this test's runtime is the
    /// default current-thread one — blocking reads directly on it would
    /// stall the very runtime the spawned server tasks need (a deadlock).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the test lock must span the blocking client's await
    async fn control_server_end_to_end() {
        use std::io::Read as _;
        use std::os::unix::net::UnixStream as StdUnixStream;

        let _guard = lock();
        let dir = std::env::temp_dir().join(format!("ai-bubble-ctl-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("spec")).unwrap();

        crate::cli::control::record_initial(crate::cli::control::Start {
            fs_initial: Some(vec![serde_json::json!({"type": "ro", "glob": "/etc"})]),
            net_applicable: true,
            net_proxy: false,
            config: crate::spec::internal::SandboxConfig::compile(
                &serde_json::from_str(r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]}}"#)
                    .unwrap(),
            ),
            spec_dir: dir.join("spec"),
            session_cache: None,
        });
        // A shared allow-list, like netns::run sets up. `NET_ALLOW` is a
        // OnceLock: if another test in this process already set it, the
        // authoritative list is whatever it holds — reuse *that* Arc
        // (the server swaps what `NET_ALLOW` holds, so asserting on a
        // fresh Arc here would race the setter) and reset the contents.
        let shared = crate::cli::control::NET_ALLOW.get().cloned().unwrap_or_else(|| {
            let shared = Arc::new(std::sync::RwLock::new(vec!["example.com:443".to_string()]));
            let _ = crate::cli::control::NET_ALLOW.set(std::sync::Arc::clone(&shared));
            shared
        });
        *shared.write().unwrap() = vec!["example.com:443".to_string()];
        crate::cli::control::start(&dir.join("spec"));
        assert!(crate::cli::control::running());

        let spec_dir = dir.join("spec");
        let _server = tokio::spawn(crate::cli::control::serve(crate::cli::control::Replies {
            fs: None,
            net: None,
        }));

        // The whole client exchange, blocking I/O and all, off the
        // runtime's only thread (see the test's doc comment).
        let client_spec_dir = spec_dir.clone();
        let client_shared = std::sync::Arc::clone(&shared);
        tokio::task::spawn_blocking(move || {
            let spec_dir = client_spec_dir;
            let shared = client_shared;
            let connect = || {
                let name = crate::cli::control::socket_name(&spec_dir);
                use std::os::linux::net::SocketAddrExt as _;
                let addr =
                    std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
                StdUnixStream::connect_addr(&addr).unwrap()
            };

            // Without the token: the connection is closed without a reply.
            let mut bad = connect();
            bad.write_all(b"00000000000000000000000000000000\n")
                .unwrap();
            assert_eq!(bad.read(&mut [0u8; 1]).unwrap_or(0), 0, "no reply expected");

            // With the token: the protocol works.
            let token = std::fs::read_to_string(crate::cli::control::token_path_for(&spec_dir))
                .unwrap()
                .trim()
                .to_string();
            let mut conn = connect();
            conn.write_all(format!("{token}\n").as_bytes()).unwrap();
            conn.write_all(b"{\"cmd\":\"policy-get\"}\n").unwrap();
            let reply: serde_json::Value = serde_json::from_str(&read_line(&mut conn)).unwrap();
            assert_eq!(reply["ok"], true);
            assert_eq!(reply["fs"]["mappings"][0]["type"], "ro");
            assert_eq!(reply["net"]["allow"][0], "example.com:443");

            // net-set (no proxy peer: A-local only, P push skipped) swaps the
            // authoritative list.
            let mut conn = connect();
            conn.write_all(format!("{token}\n").as_bytes()).unwrap();
            conn.write_all(b"{\"cmd\":\"net-set\",\"allow\":[\"api.example:443\"]}\n")
                .unwrap();
            let reply: serde_json::Value = serde_json::from_str(&read_line(&mut conn)).unwrap();
            assert_eq!(reply["ok"], true, "{reply}");
            assert_eq!(*shared.read().unwrap(), vec!["api.example:443".to_string()]);

            // An fs-set without a live FS peer fails cleanly (the push errors).
            let mut conn = connect();
            conn.write_all(format!("{token}\n").as_bytes()).unwrap();
            conn.write_all(b"{\"cmd\":\"fs-set\",\"mappings\":[]}\n")
                .unwrap();
            let reply: serde_json::Value = serde_json::from_str(&read_line(&mut conn)).unwrap();
            assert_eq!(reply["ok"], false);

            // A malformed command line closes the connection.
            let mut conn = connect();
            conn.write_all(format!("{token}\n").as_bytes()).unwrap();
            conn.write_all(b"not json\n").unwrap();
            assert_eq!(conn.read(&mut [0u8; 1]).unwrap_or(0), 0);
        })
        .await
        .expect("the blocking client task must not fail");

        crate::cli::control::cleanup();
        assert!(!crate::cli::control::running());
        assert!(!crate::cli::control::token_path_for(&spec_dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Read one reply line (blocking, the client's own loop).
    fn read_line(stream: &mut std::os::unix::net::UnixStream) -> String {
        use std::io::Read as _;
        let mut reply = String::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).unwrap();
            assert!(n > 0, "connection closed without a reply");
            if byte[0] == b'\n' {
                break;
            }
            reply.push(byte[0] as char);
        }
        reply
    }

    /// `spec-reload` end to end against the real statics: an unchanged
    /// spec reloads cleanly (and only the diff decides what is pushed),
    /// a changed immutable section is an error naming it, a changed
    /// allow-list that the proxy cannot acknowledge is reverted, and
    /// added mappings without a FUSE filesystem are refused.
    #[tokio::test]
    async fn spec_reload_diffs_and_applies() {
        let _guard = scope_guard();
        let dir = std::env::temp_dir().join(format!("ai-bubble-ctl-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let spec_dir = dir.join("spec");
        std::fs::create_dir_all(&spec_dir).unwrap();
        let write_spec = |text: &str| std::fs::write(spec_dir.join("spec.json"), text).unwrap();
        write_spec(
            r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                "net":{"mode":"proxy","allow":["example.com:443"]}}"#,
        );

        // The run-time baseline, exactly like cli::run builds it.
        let mut spec = crate::spec::Spec::try_load(Some(&spec_dir)).unwrap();
        crate::cli::preprocess_spec(&mut spec, &spec_dir, None).unwrap();
        let config = crate::spec::internal::SandboxConfig::compile(&spec);
        let mappings = serde_json::to_value(&spec.hostfs.mappings)
            .unwrap()
            .as_array()
            .cloned()
            .unwrap();

        crate::cli::control::record_initial(crate::cli::control::Start {
            fs_initial: Some(mappings),
            net_applicable: true,
            net_proxy: true,
            config,
            spec_dir: spec_dir.clone(),
            session_cache: None,
        });
        FS_AVAILABLE.store(true, Ordering::Relaxed);
        // `NET_ALLOW` is a OnceLock: reuse the authoritative Arc (the
        // server swaps what `NET_ALLOW` holds) and reset the contents.
        let shared = crate::cli::control::NET_ALLOW.get().cloned().unwrap_or_else(|| {
            let shared = Arc::new(std::sync::RwLock::new(vec!["example.com:443".to_string()]));
            let _ = crate::cli::control::NET_ALLOW.set(std::sync::Arc::clone(&shared));
            shared
        });
        *shared.write().unwrap() = vec!["example.com:443".to_string()];

        // 1. Unchanged spec: reloads cleanly (no push happens — there
        // is no live FS/P peer, and that must not matter).
        assert!(
            spec_reload_inner().await.is_ok(),
            "{:?}",
            spec_reload_inner().await
        );

        // 2. A changed immutable section is named in the error, and
        // nothing is applied.
        write_spec(
            r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                "net":{"mode":"proxy","allow":["example.com:443"]},
                "seccomp":{"block":["ptrace"]}}"#,
        );
        let err = spec_reload_inner().await.unwrap_err();
        assert!(err.contains("seccomp"), "{err}");

        // 3. A changed allow-list with no live proxy peer: the push
        // fails and the authoritative copy is reverted — the run is
        // never left half-reloaded.
        write_spec(
            r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                "net":{"mode":"proxy","allow":["other.example:443"]}}"#,
        );
        let err = spec_reload_inner().await.unwrap_err();
        assert!(
            err.contains("proxy is not reachable") || err.contains("did not acknowledge"),
            "{err}"
        );
        assert_eq!(
            shared.read().unwrap().clone(),
            vec!["example.com:443".to_string()]
        );

        // 4. Added mappings without a FUSE filesystem: refused.
        FS_AVAILABLE.store(false, Ordering::Relaxed);
        write_spec(
            r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"},{"type":"rw","glob":"/work"}]},
                "net":{"mode":"proxy","allow":["example.com:443"]}}"#,
        );
        let err = spec_reload_inner().await.unwrap_err();
        assert!(err.contains("no FUSE"), "{err}");

        // 5. The unchanged reload above moved the authoritative config;
        // a reload against a spec whose cwd changed is named too.
        FS_AVAILABLE.store(true, Ordering::Relaxed);
        write_spec(
            r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                "net":{"mode":"proxy","allow":["example.com:443"]},
                "cwd":"/other"}"#,
        );
        let err = spec_reload_inner().await.unwrap_err();
        assert!(err.contains("cwd"), "{err}");

        FS_AVAILABLE.store(false, Ordering::Relaxed);
        NET_APPLICABLE.store(false, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The immutable diff names exactly the changed sections.
    #[test]
    fn immutable_changes_names_the_changed_sections() {
        let base = r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
            "net":{"mode":"proxy","allow":["example.com:443"]}}"#;
        let running = crate::spec::internal::SandboxConfig::compile(
            &serde_json::from_str::<crate::spec::Spec>(base).unwrap(),
        );
        // The mutable domains differ: not immutable changes.
        let mutable = r#"{"hostfs":{"mappings":[{"type":"rw","glob":"/work"}]},
            "net":{"mode":"proxy","allow":["other.example:443"]}}"#;
        let fresh = crate::spec::internal::SandboxConfig::compile(
            &serde_json::from_str::<crate::spec::Spec>(mutable).unwrap(),
        );
        assert!(immutable_changes(&running, &fresh).is_empty());

        // One changed immutable field at a time (plus the net bundle).
        for (spec_json, needle) in [
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"]},
                    "env":{"values":{"PATH":"/bin"}}}"#,
                "env",
            ),
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"]},
                    "cwd":"/x"}"#,
                "cwd",
            ),
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"]},
                    "rlimits":{"nofile":64}}"#,
                "rlimits",
            ),
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"]},
                    "audit":{"log":"/x.jsonl"}}"#,
                "audit",
            ),
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"],
                           "allow_private":true}}"#,
                "net",
            ),
            (
                r#"{"hostfs":{"mappings":[{"type":"ro","glob":"/etc"},{"type":"dev"}]},
                    "net":{"mode":"proxy","allow":["example.com:443"]}}"#,
                "ops",
            ),
        ] {
            let fresh = crate::spec::internal::SandboxConfig::compile(
                &serde_json::from_str::<crate::spec::Spec>(spec_json).unwrap(),
            );
            let changed = immutable_changes(&running, &fresh);
            assert_eq!(changed.len(), 1, "{changed:?} for {needle}");
            assert!(changed[0].contains(needle), "{changed:?} for {needle}");
        }
    }

    /// A malformed downstream frame is a parse error (the child replies
    /// with an error and keeps the channel).
    #[test]
    fn malformed_upd_frames_are_rejected() {
        // An `upd` with no domain at all is a valid (empty) no-op; the
        // genuinely malformed shapes are rejected:
        for frame in [
            r#"{"upd":{"fs":{"mappings":"nope"}}}"#,
            r#"{"upd":{"fs":{"mappings":[],"extra":1}}}"#,
            r#"{"nope":{}}"#,
        ] {
            assert!(
                serde_json::from_str::<UpdFrame>(frame).is_err(),
                "{frame} must be rejected"
            );
        }
    }
}
