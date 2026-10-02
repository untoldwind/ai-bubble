//! The privileged filesystem sandbox: user/mount namespaces, tmpfs root,
//! bind mounts and symlinks, and the final exec.
//!
//! Everything in this module runs *inside* the namespace-building process;
//! it never touches the network (that is `netns`/`proxy` territory).

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::OnceLock;

use crate::spec::internal::{Op, SeccompPolicy, SeccompViolation};
use crate::spec::rlimits::Rlimits;
use crate::spec::tmpfs::TmpfsPerms;

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("ai-bubble: {msg}");
    exit(1)
}

pub(crate) fn die_with_error(msg: &str) -> ! {
    eprintln!("ai-bubble: {msg}: {}", io::Error::last_os_error());
    exit(1)
}

/// The spec's `rlimits` section, registered when the spec is compiled
/// ([`crate::spec::internal::SandboxConfig::compile`]) and applied by
/// `mount_and_exec` in the sandboxed child (see [`apply_rlimits`]).
///
/// Why a static: the compiled `SandboxConfig` is not handed down the
/// exec pipeline as a whole — `setup_and_exec`/`netns::run` receive
/// individual pieces (`ops`, `net`, `env`, seccomp) — and the compile
/// runs in the original ai-bubble process before every fork, so the
/// registration is inherited across fork with the rest of the address
/// space, exactly like the values that are handed down explicitly.
static RLIMITS: OnceLock<Rlimits> = OnceLock::new();

/// Record the spec's `rlimits` for the exec path (see [`RLIMITS`]).
/// Called from the spec compile step; the first compile wins (a re-run
/// in the same process is not a supported scenario).
pub(crate) fn register_rlimits(rlimits: Rlimits) {
    let _ = RLIMITS.set(rlimits);
}

/// The registered rlimits (the inert default when nothing was
/// registered).
fn current_rlimits() -> Rlimits {
    *RLIMITS.get().unwrap_or(&Rlimits::default())
}

/// Apply the spec's `rlimits` section to this process with setrlimit:
/// every present field is set with **soft == hard**, so the sandboxed
/// command cannot raise the limit back up after exec. Absent fields are
/// left untouched — the sandbox does not guess limits the operator did
/// not configure (a too-low limit turns a legitimate build into a
/// mysterious `EMFILE`/`EAGAIN`/`ENOMEM`). A failed setrlimit is a hard
/// error: a limit the operator asked for but that cannot be applied
/// must not silently go missing.
///
/// These limits protect the *host* (AUDIT.md M10, resource isolation):
/// they bound the command's process count (`RLIMIT_NPROC`, the fork-bomb
/// brake), its file-descriptor table (`RLIMIT_NOFILE`) and its address
/// space (`RLIMIT_AS`, the memory brake). They are applied only to the
/// sandboxed process — `mount_and_exec` runs in the PID-1 child after
/// all forks — so ai-bubble's supervisor and its host-side servers are
/// never restricted by them, and the command inherits them across
/// exec, covering everything it forks.
pub(crate) fn apply_rlimits(rlimits: &Rlimits) {
    if let Some(value) = rlimits.nproc {
        set_rlimit(libc::RLIMIT_NPROC, value, "RLIMIT_NPROC");
    }
    if let Some(value) = rlimits.nofile {
        set_rlimit(libc::RLIMIT_NOFILE, value, "RLIMIT_NOFILE");
    }
    if let Some(value) = rlimits.as_ {
        set_rlimit(libc::RLIMIT_AS, value, "RLIMIT_AS");
    }
}

/// Set one resource limit, soft == hard (see [`apply_rlimits`]).
fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64, name: &str) {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        die_with_error(&format!("Can't set {name} to {value}"));
    }
}

/// A CString for a spec-supplied path (or any other OS string). NUL bytes
/// in a spec file are reported as a clean error instead of a panic.
pub(crate) fn cstring(s: &OsStr) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| die(&format!("Path contains NUL byte: {s:?}")))
}

/// Exit with the raw waitpid status of the sandboxed command.
pub fn exit_with_status(status: libc::c_int) -> ! {
    if libc::WIFEXITED(status) {
        exit(libc::WEXITSTATUS(status));
    } else if libc::WIFSIGNALED(status) {
        exit(128 + libc::WTERMSIG(status));
    }
    exit(1);
}

/// Join an absolute sandbox path onto the new root, stripping the leading '/'.
pub fn sandbox_path(newroot: &Path, dest: &Path) -> PathBuf {
    let rel = dest.strip_prefix("/").unwrap_or(dest);
    debug_assert!(!rel.starts_with("/"));
    newroot.join(rel)
}

/// mkdir -p for a sandbox-absolute destination (leading '/' stripped),
/// relative to the new root. Path::join with an absolute path would replace
/// the new root and create the directory on the *host* filesystem, so the
/// prefix must be stripped first.
pub(crate) fn mkdir_p(newroot: &Path, dest: &Path) {
    let rel = dest.strip_prefix("/").unwrap_or(dest);
    let full = newroot.join(rel);
    if fs::create_dir_all(&full).is_err() {
        die_with_error(&format!("Can't create directory {}", full.display()));
    }
}

/// Make sure `dest` exists under `newroot` before mounting something on it.
///
/// On a tmpfs root the directory is simply created (like bwrap). In
/// hostfs-root mode the FUSE filesystem only exposes the mirrored paths, so
/// the directory must already be provided by the mirror; anything else is
/// a hard error with a hint.
fn ensure_dir(newroot: &Path, dest: &Path) {
    if crate::hostfs::root_mode() {
        let full = sandbox_path(newroot, dest);
        match fs::metadata(&full) {
            Ok(_) => {}
            Err(_) => die(&format!(
                "Mount point {} does not exist in the hostfs root; \
                 add a ro/rw mapping for it (or a parent directory) to hostfs.mappings",
                dest.display()
            )),
        }
    } else {
        mkdir_p(newroot, dest);
    }
}

/// Write a map file for the current process, following bwrap's order
/// (uid_map, then setgroups, then gid_map) and semantics.
pub(crate) fn write_id_map(file: &str, data: &str) {
    if fs::write(PathBuf::from(file), data).is_err() {
        die_with_error(&format!(
            "Can't write {file}; uid={}, euid={}, gid={}, egid={}",
            unsafe { libc::getuid() },
            unsafe { libc::geteuid() },
            unsafe { libc::getgid() },
            unsafe { libc::getegid() }
        ));
    }
}

/// Return the (device, inode) pair identifying the current user namespace,
/// or None if it can't be determined.
pub(crate) fn userns_id() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::metadata("/proc/self/ns/user").ok()?;
    Some((md.dev(), md.ino()))
}

/// The cgroup namespace part of the unshare flags, bwrap-style
/// (`--unshare-cgroup-try`): `CLONE_NEWCGROUP` only when the kernel exposes
/// `/proc/self/ns/cgroup` (on pre-4.6 kernels it does not exist and the flag
/// would make unshare() fail with EINVAL), 0 otherwise.
///
/// This flag must be combined with `CLONE_NEWUSER` *in the same unshare()/clone
/// call* — like bubblewrap does in `bubblewrap.c` (clone_flags, around
/// `clone_flags |= CLONE_NEWCGROUP`). Creating a cgroup namespace requires
/// `CAP_SYS_ADMIN` in the user namespace owning the *current* cgroup namespace
/// (the initial one). That authority only exists in the window where
/// `CLONE_NEWUSER` is being created: the kernel switches the user namespace
/// first, so the combined call's privilege check happens against the fresh
/// user namespace. After a separate `unshare(CLONE_NEWUSER)` it is too late —
/// the caller would no longer have any capabilities in the initial user
/// namespace and the cgroup unshare would fail with EPERM.
pub(crate) fn cgroup_ns_flags() -> libc::c_int {
    if fs::metadata("/proc/self/ns/cgroup").is_ok() {
        libc::CLONE_NEWCGROUP
    } else {
        0
    }
}

/// Verify that unshare() really created a new user namespace. Some
/// sandboxes (seccomp supervisors, gVisor, LSMs) silently strip
/// CLONE_NEWUSER from the flags, which would otherwise only show up later
/// as a confusing EPERM when writing the uid/gid maps.
pub(crate) fn check_new_userns(old_userns: Option<(u64, u64)>) {
    let new_userns = userns_id();
    if new_userns.is_none() || new_userns == old_userns {
        die(
            "unshare() returned success, but the user namespace was not created.\n\
             Your environment (seccomp filter, sandbox or LSM) may be blocking \
             CLONE_NEWUSER.",
        );
    }
}

/// If `--die-with-parent` was given, ask the kernel to SIGKILL this process
/// when its parent dies — bubblewrap's `handle_die_with_parent()`:
///
///     if (opt_die_with_parent && prctl (PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
///         die_with_error ("prctl");
///
/// PR_SET_PDEATHSIG is cleared in a forked child but survives execve, so
/// every process in the chain must set it for itself: the launcher (in
/// `setup_and_exec`, or `netns::run` for the connector and
/// `netns::isolated_parent` for P) and the sandboxed child before exec (in
/// `pidns_and_exec`). That way the death of ai-bubble's caller ripples down
/// and kills the whole process tree including the exec'd command.
pub(crate) fn handle_die_with_parent(enabled: bool) {
    unsafe {
        if enabled && libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            die_with_error("Can't set PR_SET_PDEATHSIG");
        }
        // Close the classic fork→prctl race: if the parent died between the
        // fork and the prctl above, the signal was armed against the *new*
        // (re-parented) parent and will never fire. Every caller's parent is
        // an ai-bubble process in the host PID namespace, so getppid() == 1
        // unambiguously means the real parent is already gone — exit rather
        // than linger. (In `pidns_and_exec`'s forked child the parent lives
        // outside the new PID namespace, so getppid() returns 0 there, never
        // a namespace-local 1.)
        if enabled && libc::getppid() == 1 {
            die("Parent died before PR_SET_PDEATHSIG was armed");
        }
    }
}

/// The uid/gid the sandboxed command runs as inside the user namespace.
/// This id is deliberately *not* mapped from any host account: only the
/// caller's own real uid/gid is mapped, and it is mapped onto this id, so
/// the command never runs as root — not even as the (namespace-local)
/// root 0.
pub(crate) const SANDBOX_ID: libc::c_uint = 65535;

/// Highest capability number on the Linux versions this supports; passing
/// unknown values to PR_CAPBSET_DROP only yields a harmless EINVAL, which
/// is tolerated, so a slightly stale constant is safe.
const CAP_LAST: libc::c_ulong = 40; // CAP_CHECKPOINT_RESTORE

/// Non-isolated entry point: new user + mount namespaces with fresh id
/// mappings, then the sandbox filesystem and exec.
///
/// `env` is the sandbox's isolated environment (see [`mount_and_exec`]).
/// `cwd` is the command's working directory *inside* the sandbox
/// (see [`mount_and_exec`]).
pub fn setup_and_exec(
    ops: &[Op],
    command: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    seccomp: Option<&SeccompPolicy>,
) -> ! {
    unsafe {
        // Optionally bind our lifecycle to that of the caller: when ai-bubble's
        // parent dies, the kernel SIGKILLs this launcher (the sandboxed child
        // sets its own PDEATHSIG in pidns_and_exec, mirroring bwrap).
        handle_die_with_parent(die_with_parent);

        // Prevent gaining privileges via execve of setuid binaries.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            die_with_error("Can't set PR_SET_NO_NEW_PRIVS");
        }

        // Capture the real uid/gid BEFORE unsharing: after unshare they are not
        // mapped in the new user namespace and getuid()/getgid() would return the
        // overflow id (65534), which must not be used in the map (bwrap captures
        // real_uid/real_gid the same way).
        let (real_uid, real_gid) = (libc::getuid(), libc::getgid());

        // Unshare the user namespace. After this we have CAP_SYS_ADMIN in the
        // new user namespace and can mount freely. (The mount namespace is
        // unshared in mount_and_exec, shared by both entry points.)
        let old_userns = userns_id();
        // The cgroup namespace is unshared in the same call (like bwrap's
        // --unshare-all; see cgroup_ns_flags for why it must be combined
        // with CLONE_NEWUSER).
        if libc::unshare(libc::CLONE_NEWUSER | cgroup_ns_flags()) != 0 {
            die_with_error("Can't unshare user namespace");
        }
        check_new_userns(old_userns);

        // Also give the sandbox its own UTS namespace, like bwrap's
        // --unshare-all: the command then can't see the host's hostname and
        // domainname (and couldn't change it either way — that needs
        // CAP_SYS_ADMIN over the owning user namespace). CLONE_NEWUTS takes
        // effect immediately and needs the same authority as CLONE_NEWUSER,
        // so this mirrors the netns path, which unshares user|net|uts in one
        // go in netns::isolated_parent.
        if libc::unshare(libc::CLONE_NEWUTS) != 0 {
            die_with_error("Can't unshare UTS namespace");
        }

        // Set up the id mappings in the same order as bwrap: uid_map, then
        // setgroups deny, then gid_map. The setgroups deny is required before
        // gid_map unless the writer has CAP_SETGID in the parent namespace.
        //
        // The real uid/gid is mapped onto SANDBOX_ID instead of 0: there is no
        // root (0) in this user namespace at all, and the command's uid/gid
        // (SANDBOX_ID) does not correspond to any host account.
        write_id_map(
            "/proc/self/uid_map",
            &format!("{SANDBOX_ID} {real_uid} 1\n"),
        );
        write_id_map("/proc/self/setgroups", "deny\n");
        write_id_map(
            "/proc/self/gid_map",
            &format!("{SANDBOX_ID} {real_gid} 1\n"),
        );

        // The command must also run in its own PID namespace (and get a
        // fresh /proc), like bwrap's --unshare-pid + --proc.
        pidns_and_exec(ops, command, env, cwd, die_with_parent, new_session, seccomp);
    }
}

/// Unshare a fresh IPC namespace and then a fresh PID namespace and run the
/// sandbox setup + exec there.
///
/// The IPC namespace is part of bwrap's `--unshare-all`: it gives the sandbox
/// its own copy of all SysV IPC objects (shared memory segments, semaphores,
/// message queues) and POSIX message queues, so the command can neither see
/// nor attach to any host IPC object. `unshare(CLONE_NEWIPC)` takes effect
/// immediately for the calling process (unlike `CLONE_NEWPID`) and only
/// requires `CAP_SYS_ADMIN` over the current user namespace, which both
/// entry points (this one and `netns::isolated_parent`) hold at this point.
/// Doing it here means both paths get the same isolation.
///
/// `unshare(CLONE_NEWPID)` only takes effect for *later* forks: the calling
/// process stays in the old PID namespace. Like bwrap (which passes
/// CLONE_NEWPID in the clone() flags, making the setup process the first
/// process of the new namespace), we therefore fork here: the child is the
/// first process (PID 1) of the new PID namespace and does the entire
/// sandbox setup and exec inside it. Only then can a fresh procfs instance
/// be mounted that shows just the sandbox's processes.
///
/// A PID namespace always needs a PID 1; making the command itself PID 1
/// corresponds to bwrap's `--as-pid-1` mode.
///
/// Detach the (forked) sandboxed child from the caller's controlling
/// terminal — bwrap's `--new-session`. Must run in a freshly forked child
/// (never a process-group leader, so `setsid()` cannot fail with EPERM).
///
/// `setsid()` alone suffices: a new session has no controlling terminal,
/// so the command cannot reach the user's tty through `/dev/tty` (it fails
/// with ENXIO) and `TIOCSTI` on fd 0/2 no longer targets *its* controlling
/// terminal — the escape where a malicious command pushes keystrokes into
/// the user's shell. `TIOCNOTTY` is issued first anyway (harmless if not a
/// tty) so a caller that already had a session still loses the ctty when
/// `setsid()` would fail.
///
/// The corresponding mount-side change is in `mount_and_exec`: the host
/// pts (`/dev/console`) and the `/dev/tty` bind are skipped in this mode.
pub(crate) unsafe fn new_terminal_session() {
    unsafe {
        let _ = libc::ioctl(0, libc::TIOCNOTTY);
        if libc::setsid() < 0 {
            die_with_error("Can't start a new terminal session");
        }
    }
}

/// The parent keeps waiting for the child and forwards its exit status.
///
/// Pty mode ([`crate::pty::wanted`]): when new-session is requested and
/// the caller's stdin/stdout are ttys, a *private* pty is allocated
/// before the fork ([`crate::pty::open`]). The child gets the slave as
/// fds 0/1/2 and controlling terminal ([`crate::pty::child_attach`]);
/// this process (the one that waitpid()s) becomes the stdio ⇄ master
/// relay ([`crate::pty::parent_relay`]). See the `pty` module docs for
/// why this keeps new-session's security properties while restoring full
/// controlling-terminal functionality (job control, SIGWINCH, …).
pub(crate) unsafe fn pidns_and_exec(
    ops: &[Op],
    command: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    seccomp: Option<&SeccompPolicy>,
) -> ! {
    unsafe {
        if libc::unshare(libc::CLONE_NEWIPC) != 0 {
            die_with_error("Can't unshare IPC namespace");
        }
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            die_with_error("Can't unshare PID namespace");
        }
        // Pty mode: allocate the private pty before the fork, so both
        // sides inherit their end. With pipes on stdin/stdout (or
        // --no-new-session) this stays None and the behaviour below is
        // exactly as before.
        let pty = if crate::pty::wanted(new_session) {
            Some(crate::pty::open())
        } else {
            None
        };
        let stderr_is_tty = libc::isatty(2) == 1;
        let pid = libc::fork();
        if pid < 0 {
            die_with_error("Can't fork sandboxed command");
        }
        if pid == 0 {
            // Like bwrap's child: PR_SET_PDEATHSIG does not survive fork, so
            // the sandboxed process must bind its own lifecycle to the
            // launcher before doing anything else.
            handle_die_with_parent(die_with_parent);
            // Terminal setup, in order of preference: pty mode (private
            // controlling terminal, see the pty module docs), otherwise
            // the plain new-session detach (bwrap's --new-session).
            // Done in this forked child — which is never a process-group
            // leader, so setsid() cannot fail with EPERM — so both entry
            // points get it.
            if let Some(p) = &pty {
                crate::pty::child_attach(p, stderr_is_tty);
            } else if new_session {
                new_terminal_session();
            }
            mount_and_exec(
                ops,
                command,
                env,
                cwd,
                new_session,
                pty.as_ref().map(|p| p.slave_path.as_str()),
                seccomp,
            );
        }

        // Parent: the child must not keep the slave open, or the master
        // would never see EOF when the command exits.
        if let Some(p) = &pty {
            crate::pty::close_slave(p);
            // Relay stdio ⇄ master until the pty closes or a fatal
            // signal arrives; the terminal is restored before returning.
            crate::pty::parent_relay(p, pid);
        }

        // Supervise the PID-1 child and forward its exit status.
        let mut status: libc::c_int = 0;
        loop {
            let r = libc::waitpid(pid, &mut status, 0);
            if r == pid {
                exit_with_status(status);
            }
            if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                die_with_error("Can't wait for sandboxed command");
            }
        }
    }
}

/// Drop every capability, from every set and the bounding set — the
/// equivalent of bubblewrap's `--cap-drop ALL`.
///
/// Must run while the process still holds CAP_SETPCAP (i.e. before the
/// exec'd command loses its capabilities). Because the command then execs
/// as a non-root uid (SANDBOX_ID), execve would clear the permitted and
/// effective sets anyway; dropping the bounding set additionally makes it
/// impossible to regain any capability, even via file capabilities.
pub(crate) unsafe fn drop_all_capabilities() {
    unsafe {
        // Remove every capability from the bounding set so it can never be
        // regained. EINVAL for caps the kernel doesn't know is tolerable.
        for cap in 0..=CAP_LAST {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
            {
                die_with_error("Can't drop capability from bounding set");
            }
        }

        // Clear ambient capabilities (they would otherwise survive exec).
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
        {
            let err = io::Error::last_os_error().raw_os_error();
            if err != Some(libc::EINVAL) && err != Some(libc::ENOTSUP) {
                die_with_error("Can't clear ambient capabilities");
            }
        }

        // Explicitly empty permitted/effective/inheritable (caps v1: one
        // 32-bit set each), so nothing is left even before execve.
        #[repr(C)]
        struct CapHeader {
            version: libc::c_int,
            pid: libc::c_int,
        }
        #[repr(C)]
        struct CapData {
            effective: libc::c_uint,
            permitted: libc::c_uint,
            inheritable: libc::c_uint,
        }
        let hdr = CapHeader {
            version: 0x19980330, // _LINUX_CAPABILITY_VERSION_1
            pid: 0,
        };
        let data = CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        };
        if libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapHeader,
            &data as *const CapData,
        ) != 0
        {
            die_with_error("Can't clear capability sets");
        }
    }
}

/// Mount a fresh tmpfs on `dest_abs` (a path inside the new sandbox root),
/// like bwrap's `setup_op_tmpfs_mount`: `MS_NOSUID | MS_NODEV`, a `mode=`
/// option and an optional `size=` (bytes; 0 means the kernel default).
pub(crate) unsafe fn mount_tmpfs(
    dest_abs: &Path,
    perms: TmpfsPerms,
    size: Option<u64>,
    display: &Path,
) {
    let mut options = perms.mount_option();
    if let Some(bytes) = size {
        if bytes == 0 {
            die("Invalid tmpfs size 0");
        }
        options.push_str(&format!(",size={bytes}"));
    }
    let dest_c = CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
    let options_c = CString::new(options).unwrap();
    if unsafe {
        libc::mount(
            CString::new("tmpfs").unwrap().as_ptr(),
            dest_c.as_ptr(),
            CString::new("tmpfs").unwrap().as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            options_c.as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        die_with_error(&format!("Can't mount tmpfs on {}", display.display()));
    }
}

/// Build the tmpfs sandbox filesystem and exec COMMAND.
///
/// Must run as PID 1 of a fresh PID namespace (see pidns_and_exec) so that
/// a fresh procfs instance (`Op::Proc`) is bound to it.
///
/// The command runs with an *isolated* environment: `env` is the complete
/// set of variables it sees (compiled from the spec's `env` section, plus
/// the proxy variables on the netns path — see `netns::isolated_parent`).
/// Everything inherited from the host is dropped first, so nothing leaks
/// in by accident; the spec decides what exists.
///
/// `cwd` is the command's working directory *inside* the sandbox, from
/// the spec's `cwd` field (already `${VAR}`-expanded and validated as an
/// absolute, `..`-free path at parse time). It is entered after the
/// chroot; the sandbox machinery never verifies that it exists beyond
/// the chdir itself, which fails with a clean error when it doesn't.
/// `None` means the sandbox root, `/`.
///
/// Unshares the mount namespace. This requires CAP_SYS_ADMIN over the user
/// namespace owning the *current* mount namespace, so the isolated path
/// must reach this in the child that inherited the fresh user namespace
/// created by `netns::isolated_parent` (the new mount namespace is then
/// owned by that same user namespace).
/// `pty_slave_path` is set in pty mode (see the `pty` module docs): the
/// host path of the private pty's slave, which is then bind-mounted as
/// `/dev/console` (so ttyname-style paths resolve) — and `/dev/tty` is
/// provided too, because the command's controlling terminal is now the
/// private pty, not the caller's. In plain new-session mode both stay
/// out of the sandbox, exactly as before.
pub(crate) unsafe fn mount_and_exec(
    ops: &[Op],
    command: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    new_session: bool,
    pty_slave_path: Option<&str>,
    seccomp: Option<&SeccompPolicy>,
) -> ! {
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            die_with_error("Can't unshare mount namespace");
        }

        // Make our mount tree a slave of the parent, so nothing we mount
        // propagates back to the host.
        let root = CString::new("/").unwrap();
        if libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_SLAVE | libc::MS_REC,
            std::ptr::null(),
        ) != 0
        {
            die_with_error("Can't make mount tree private");
        }

        // In hostfs-root mode the FUSE filesystem itself is the sandbox
        // root: the ops are mounted on top of it and the process chroots
        // into it below. No tmpfs root is created.
        let newroot: PathBuf = if crate::hostfs::root_mode() {
            match crate::hostfs::host_mount_point() {
                Some(mountpoint) => mountpoint.clone(),
                None => die("hostfs root requested but no host filesystem is mounted"),
            }
        } else {
            // Create a fresh tmpfs to serve as the sandbox root.
            let mut tmpl: Vec<u8> = b"/tmp/ai-bubble.XXXXXX".to_vec();
            tmpl.push(0);
            let tmpl_ptr = CString::from_vec_with_nul(tmpl).unwrap();
            let root_path = libc::mkdtemp(tmpl_ptr.into_raw() as *mut libc::c_char);
            if root_path.is_null() {
                die_with_error("Can't create temporary sandbox root");
            }
            let newroot = PathBuf::from(CStr::from_ptr(root_path).to_string_lossy().into_owned());

            let newroot_c = CString::new(newroot.as_os_str().as_bytes()).unwrap();
            if libc::mount(
                CString::new("tmpfs").unwrap().as_ptr(),
                newroot_c.as_ptr(),
                CString::new("tmpfs").unwrap().as_ptr(),
                0,
                std::ptr::null(),
            ) != 0
            {
                die_with_error("Can't mount tmpfs sandbox root");
            }
            // Root of the sandbox should be traversable by everyone.
            let _ = fs::set_permissions(&newroot, fs::Permissions::from_mode(0o755));
            newroot
        };

        // Bind the host FUSE filesystem into the sandbox at /host. This must
        // happen before chroot, while the host mountpoint path is still
        // resolvable. (The FUSE server keeps running in the host process.)
        // In hostfs-root mode the FUSE filesystem *is* the root, so there is
        // no /host.
        if let Some(host_mount) =
            crate::hostfs::host_mount_point().filter(|_| !crate::hostfs::root_mode())
        {
            mkdir_p(&newroot, Path::new(crate::hostfs::SANDBOX_MOUNT_POINT));
            let dest_abs = sandbox_path(&newroot, Path::new(crate::hostfs::SANDBOX_MOUNT_POINT));
            let src_c = CString::new(host_mount.as_os_str().as_bytes()).unwrap();
            let dest_c = CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
            if libc::mount(
                src_c.as_ptr(),
                dest_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
            {
                die_with_error("Can't bind mount host filesystem to /host");
            }
        }

        // Apply the setup operations in order.
        for op in ops {
            match op {
                Op::Bind { src, dest, rw } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid bind destination {}", dest.display()));
                    }
                    let src_c = cstring(OsStr::new(src));
                    let mut src_stat: libc::stat = std::mem::zeroed();
                    if libc::stat(src_c.as_ptr(), &mut src_stat) != 0 {
                        die_with_error(&format!("Can't find source {src}"));
                    }
                    let dest_abs = sandbox_path(&newroot, dest);
                    // Bind targets must exist; create missing directories on
                    // the tmpfs root (bwrap does the same for its new root).
                    // In hostfs-root mode they must already exist in the
                    // mirror (the FUSE filesystem only exposes mirrored paths).
                    ensure_dir(&newroot, dest);
                    let dest_c = cstring(dest_abs.as_os_str());
                    if libc::mount(
                        src_c.as_ptr(),
                        dest_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) != 0
                    {
                        die_with_error(&format!("Can't bind mount {src} -> {}", dest.display()));
                    }
                    // Bind mounts are read-only unless explicitly asked for
                    // (they bypass the FUSE mirror's write policy). The
                    // read-only flag is applied with a remount: MS_BIND
                    // mounts do not reliably pick up MS_RDONLY in the
                    // initial mount call.
                    if !rw
                        && libc::mount(
                            std::ptr::null(),
                            dest_c.as_ptr(),
                            std::ptr::null(),
                            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                            std::ptr::null(),
                        ) != 0
                    {
                        die_with_error(&format!(
                            "Can't make bind mount {src} -> {} read-only",
                            dest.display()
                        ));
                    }
                }
                Op::Proc { dest } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid proc mount point {}", dest.display()));
                    }
                    ensure_dir(&newroot, dest);
                    let dest_abs = sandbox_path(&newroot, dest);
                    let dest_c = cstring(dest_abs.as_os_str());
                    // Mount a *fresh* procfs, like bwrap's --proc does when a
                    // new PID namespace exists: this instance shows only the
                    // sandbox's processes. (We are inside the new PID
                    // namespace here — pidns_and_exec forked before the setup
                    // — which is what binds the instance to it.)
                    if libc::mount(
                        CString::new("proc").unwrap().as_ptr(),
                        dest_c.as_ptr(),
                        CString::new("proc").unwrap().as_ptr(),
                        libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
                        std::ptr::null(),
                    ) != 0
                    {
                        die_with_error(&format!("Can't mount proc on {}", dest.display()));
                    }
                }
                Op::Tmpfs { dest, perms, size } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid tmpfs mount point {}", dest.display()));
                    }
                    ensure_dir(&newroot, dest);
                    let dest_abs = sandbox_path(&newroot, dest);
                    mount_tmpfs(&dest_abs, perms.unwrap_or(TmpfsPerms::DEFAULT), *size, dest);
                }
                Op::Dev { dest } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid dev mount point {}", dest.display()));
                    }
                    ensure_dir(&newroot, dest);
                    let dev_abs = sandbox_path(&newroot, dest);
                    // Like bwrap's --dev: a fresh mode-0755 tmpfs, populated
                    // with the standard device nodes and symlinks below.
                    mount_tmpfs(&dev_abs, TmpfsPerms(0o755), None, dest);

                    /// Bind-mount a host path over `name` inside the dev tmpfs.
                    unsafe fn bind_into_dev(src: &str, dest_abs: &Path, name: &str) {
                        let src_c = CString::new(src).unwrap();
                        let dest_c =
                            CString::new(dest_abs.join(name).as_os_str().as_bytes()).unwrap();
                        if unsafe {
                            libc::mount(
                                src_c.as_ptr(),
                                dest_c.as_ptr(),
                                std::ptr::null(),
                                libc::MS_BIND,
                                std::ptr::null(),
                            )
                        } != 0
                        {
                            die_with_error(&format!("Can't bind mount {src} to /{name}"));
                        }
                    }

                    // The device nodes: bwrap creates a read-only placeholder
                    // file and bind-mounts the host node over it (device
                    // access works because the bind mount carries it over).
                    // In plain new-session mode /dev/tty is skipped: the
                    // command has no controlling terminal, so a bind of the
                    // host's /dev/tty node (which resolves to the *caller's*
                    // ctty on the host) would only re-expose it. In pty mode
                    // the ctty is the *private* pty, so /dev/tty resolves to
                    // that and is safe to provide.
                    let dev_names: &[&str] = if new_session && pty_slave_path.is_none() {
                        &["null", "zero", "full", "random", "urandom"]
                    } else {
                        &["null", "zero", "full", "random", "urandom", "tty"]
                    };
                    for name in dev_names.iter().copied() {
                        let node = dev_abs.join(name);
                        if fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o444)
                            .open(&node)
                            .is_err()
                        {
                            die_with_error(&format!("Can't create device placeholder {name}"));
                        }
                        bind_into_dev(&format!("/dev/{name}"), &dev_abs, name);
                    }

                    // The stdio symlinks and the legacy /dev/fd, /dev/core.
                    for (name, target) in [
                        ("stdin", "/proc/self/fd/0"),
                        ("stdout", "/proc/self/fd/1"),
                        ("stderr", "/proc/self/fd/2"),
                        ("fd", "/proc/self/fd"),
                        ("core", "/proc/kcore"),
                    ] {
                        let dest_c =
                            CString::new(dev_abs.join(name).as_os_str().as_bytes()).unwrap();
                        let target_c = CString::new(target).unwrap();
                        if libc::symlink(target_c.as_ptr(), dest_c.as_ptr()) != 0 {
                            die_with_error(&format!("Can't make symlink {name} -> {target}"));
                        }
                    }

                    let dir_mode = fs::Permissions::from_mode(0o755);
                    for name in ["shm", "pts"] {
                        let dir = dev_abs.join(name);
                        if fs::create_dir(&dir).is_err() {
                            die_with_error(&format!("Can't create {name} in dev"));
                        }
                        let _ = fs::set_permissions(&dir, dir_mode.clone());
                    }

                    // A fresh devpts instance on /dev/pts, with the ptmx
                    // symlink, exactly like bwrap's --dev.
                    let pts_c = CString::new(dev_abs.join("pts").as_os_str().as_bytes()).unwrap();
                    if libc::mount(
                        CString::new("devpts").unwrap().as_ptr(),
                        pts_c.as_ptr(),
                        CString::new("devpts").unwrap().as_ptr(),
                        libc::MS_NOSUID | libc::MS_NOEXEC,
                        CString::new("newinstance,ptmxmode=0666,mode=620")
                            .unwrap()
                            .as_ptr() as *const libc::c_void,
                    ) != 0
                    {
                        die_with_error("Can't mount devpts on /dev/pts");
                    }
                    let ptmx_c = CString::new(dev_abs.join("ptmx").as_os_str().as_bytes()).unwrap();
                    let target_c = CString::new("pts/ptmx").unwrap();
                    if libc::symlink(target_c.as_ptr(), ptmx_c.as_ptr()) != 0 {
                        die_with_error("Can't make symlink ptmx -> pts/ptmx");
                    }

                    // Bind a terminal device as /dev/console so ttyname()-style paths
                    // resolve in the sandbox (bwrap does the same; it grants
                    // no extra access). Which device: in pty mode the
                    // private pty's slave — *not* the caller's terminal
                    // device; in shared (--no-new-session) mode the caller's
                    // terminal; in plain new-session mode nothing, because
                    // the command has no controlling tty at all.
                    let console_src: Option<String> = if new_session {
                        pty_slave_path.map(str::to_string)
                    } else {
                        let tty = libc::ttyname(0);
                        if tty.is_null() {
                            None
                        } else {
                            let host_tty = CStr::from_ptr(tty).to_string_lossy().into_owned();
                            (!host_tty.is_empty()).then_some(host_tty)
                        }
                    };
                    if let Some(src) = console_src {
                        if fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o444)
                            .open(dev_abs.join("console"))
                            .is_err()
                        {
                            die_with_error("Can't create device placeholder console");
                        }
                        bind_into_dev(&src, &dev_abs, "console");
                    }
                }
                Op::Symlink { src, dest } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid symlink destination {}", dest.display()));
                    }
                    // Create the parent directories on the tmpfs root, like
                    // bwrap does for op destinations.
                    let parent = match dest.parent() {
                        Some(p) if p.as_os_str().is_empty() => None,
                        p => p,
                    };
                    if let Some(p) = parent {
                        ensure_dir(&newroot, p);
                    }
                    let dest_abs = sandbox_path(&newroot, dest);
                    let dest_c = cstring(dest_abs.as_os_str());
                    let src_c = cstring(OsStr::new(src));
                    if libc::symlink(src_c.as_ptr(), dest_c.as_ptr()) != 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            // Mirror bwrap: same target is fine, otherwise it's
                            // an error.
                            match fs::read_link(&dest_abs) {
                                Ok(existing) if existing == Path::new(src) => {}
                                Ok(existing) => die(&format!(
                                    "Can't make symlink at {}: existing destination is {}",
                                    dest.display(),
                                    existing.display()
                                )),
                                Err(_) => die(&format!(
                                    "Can't make symlink at {}: destination exists and is not a symlink",
                                    dest.display()
                                )),
                            }
                        } else {
                            let hint = if crate::hostfs::root_mode() {
                                " (the hostfs root only exposes mirrored paths; the symlink \
                                 must already exist in one)"
                            } else {
                                ""
                            };
                            die_with_error(&format!(
                                "Can't make symlink at {}{hint}",
                                dest.display()
                            ));
                        }
                    }
                }
            }
        }

        // Enter the sandbox and run the command.
        let newroot_c = CString::new(newroot.as_os_str().as_bytes()).unwrap();
        if libc::chdir(newroot_c.as_ptr()) != 0 {
            die_with_error("Can't chdir to sandbox root");
        }
        if libc::chroot(CString::new(".").unwrap().as_ptr()) != 0 {
            die_with_error("Can't chroot into sandbox");
        }

        // The command's working directory: the spec's `cwd` (already
        // validated as absolute and `..`-free at parse time; re-checked
        // here defensively), or the sandbox root. The chdir is the point
        // where a non-existent directory surfaces — with a hint pointing
        // at the spec, since the sandbox does not create it.
        let workdir: PathBuf = match cwd {
            Some(cwd) => {
                if !cwd.is_absolute()
                    || cwd
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    die(&format!("Invalid working directory {}", cwd.display()));
                }
                cwd.to_path_buf()
            }
            None => PathBuf::from("/"),
        };
        if libc::chdir(cstring(workdir.as_os_str()).as_ptr()) != 0 {
            let hint = if crate::hostfs::root_mode() {
                " (the hostfs root only exposes mirrored paths; add a mapping for it \
                 or a parent directory to hostfs.mappings)"
            } else {
                " (create it with a hostfs mapping or mount it, e.g. with a tmpfs mapping)"
            };
            die_with_error(&format!(
                "Can't chdir to working directory {}{hint}",
                workdir.display()
            ));
        }

        // Detach from the caller's kernel keyrings. The keyring is not
        // namespaced: permission checks use real kuids, and the command
        // runs with the caller's kuid (only the in-namespace *view* is
        // remapped to 65534/65535). Without this, the command would inherit
        // the caller's session keyring and could read cached credentials
        // (cifs/NFS/Kerberos session keys) and add keys on the caller's
        // behalf. Joining a fresh *anonymous* session keyring (name = NULL
        // → the kernel generates a unique name, so an existing keyring of
        // the caller can never be matched) gives the command an empty
        // keyring of its own: keys it adds stay in that run-scoped keyring
        // and are destroyed when the last reference goes away — they never
        // reach the session or user keyrings that outlive the run, and the
        // caller's session keyring is no longer reachable. Needs no
        // capabilities, and runs before the seccomp filter is installed
        // (which may deny `keyctl` to the command).
        const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
        // `keyctl(KEYCTL_JOIN_SESSION_KEYRING, ...)` returns the serial of
        // the (new) session keyring — a positive nonzero value — so success
        // must be checked against the -1 error sentinel, not 0.
        if libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        ) == -1
        {
            die_with_error("Can't join a fresh anonymous session keyring");
        }

        // Resource limits (the spec's `rlimits` section): applied only
        // to this sandboxed process, after all forks, so the supervisor
        // is never restricted by them (see `apply_rlimits` and
        // AUDIT.md M10). Absent fields are left untouched.
        apply_rlimits(&current_rlimits());

        // All privileged work is done; run the command with as little
        // authority as possible: no capabilities at all, and as a uid/gid
        // that does not exist on the host.
        drop_all_capabilities();

        // Isolated environment: drop everything inherited from the host,
        // then set exactly what the spec (and, on the netns path, the
        // proxy setup) provides. `execvp` searches PATH from the process
        // environment — with no PATH in the spec, that falls back to the
        // default confstr path (/bin:/usr/bin), like execvp with an empty
        // environment always does.
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(&key);
        }
        for (key, value) in env {
            // Guard against set_var's panic conditions with a clean
            // message instead.
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                die(&format!("Invalid environment variable name {key:?}"));
            }
            std::env::set_var(key, value);
        }

        // The seccomp filter, installed last so that everything above
        // (mounts, chroot, the uid change) still uses the full syscall
        // surface. `PR_SET_NO_NEW_PRIVS` is already set (it survives
        // fork and exec and is required for an unprivileged filter
        // load). Once the filter is live, only the allowed syscalls are
        // available to the code below — which is why it is applied
        // immediately before exec, when nothing but `execvp` itself (and
        // the exec-failure message) is left to do. An allowlist that
        // omits `execve` denies exactly that exec, so the command cannot
        // start at all.
        if let Some(policy) = seccomp {
            apply_seccomp(policy);
        }

        let argv: Vec<CString> = command
            .iter()
            .map(|a| {
                CString::new(a.as_bytes()).unwrap_or_else(|_| die("Command contains NUL byte"))
            })
            .collect();
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let _ = io::Write::flush(&mut io::stdout());
        libc::execvp(argv[0].as_ptr(), argv_ptrs.as_ptr());
        die_with_error(&format!("Can't exec {}", command[0]));
    }
}

/// Compile the internal seccomp policy into a BPF program with
/// [seccompiler](https://docs.rs/seccompiler) and install it for this
/// process (and, after exec, the sandboxed command).
///
/// The policy is syscall-number based only (seccomp filters see no
/// arguments here): an allowlist permits exactly the listed syscalls and
/// denies everything else; a blocklist denies exactly the listed ones.
/// A denied syscall either fails with `EPERM` or kills the process with
/// `SIGSYS`, per the spec's `on_violation`.
///
/// Requires `PR_SET_NO_NEW_PRIVS` to be set (it is, on both exec paths)
/// — without it, an unprivileged process could not load a filter.
fn apply_seccomp(policy: &SeccompPolicy) {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    // One unconditional rule per syscall: the syscall maps to an empty
    // rule vector, which seccompiler treats as "matches regardless of
    // the arguments".
    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = policy
        .syscalls()
        .iter()
        .map(|&nr| (nr, Vec::new()))
        .collect();
    let deny = match policy.on_violation() {
        SeccompViolation::Errno => SeccompAction::Errno(libc::EPERM as u32),
        SeccompViolation::Kill => SeccompAction::KillProcess,
    };
    // Allowlist: listed syscalls are allowed, everything else denied.
    // Blocklist: listed syscalls denied, everything else allowed.
    let (mismatch, m) = if policy.is_allowlist() {
        (deny, SeccompAction::Allow)
    } else {
        (SeccompAction::Allow, deny)
    };

    // Unix-domain sockets are denied unless the spec opted in via
    // `net.*.unix_sockets` (AUDIT.md M3: abstract-namespace sockets live
    // in the network namespace, so host-network mode would otherwise
    // expose the D-Bus system bus, `systemd --user`, ... to the command).
    // socket(2) and socketpair(2) take the address family as a *value*
    // argument, so seccomp can gate them on `domain == AF_UNIX` without
    // dereferencing anything (unlike connect(2), whose address is behind
    // a pointer). io_uring_setup is denied outright, because
    // IORING_OP_SOCKET creates sockets without going through socket(2).
    if !policy.unix_sockets() {
        use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
        let af_unix = libc::AF_UNIX as u64;
        let af_unix_rule = |op: SeccompCmpOp| {
            let cond = SeccompCondition::new(0, SeccompCmpArgLen::Qword, op, af_unix)
                .unwrap_or_else(|e| die(&format!("Can't compile the AF_UNIX condition: {e}")));
            SeccompRule::new(vec![cond])
                .unwrap_or_else(|e| die(&format!("Can't compile the AF_UNIX rule: {e}")))
        };
        let allowlist = policy.is_allowlist();
        for nr in [syscalls::Sysno::socket as i64, syscalls::Sysno::socketpair as i64] {
            match rules.remove(&nr) {
                Some(existing) => {
                    if allowlist {
                        // The allowlist lists the syscall; narrow it to
                        // "everything but AF_UNIX": a matching rule yields
                        // Allow, AF_UNIX falls to the mismatch action.
                        rules.insert(nr, vec![af_unix_rule(SeccompCmpOp::Ne)]);
                    } else {
                        // The blocklist denies it unconditionally; that
                        // stands (and covers AF_UNIX).
                        rules.insert(nr, existing);
                    }
                }
                None => {
                    if allowlist {
                        // Absent from the allowlist: already denied.
                    } else {
                        // Deny only AF_UNIX dials; other families fall to
                        // the mismatch action (Allow).
                        rules.insert(nr, vec![af_unix_rule(SeccompCmpOp::Eq)]);
                    }
                }
            }
        }
        let io_uring = syscalls::Sysno::io_uring_setup as i64;
        if allowlist {
            // Absent already means denied; present would allow socket
            // creation through io_uring, so drop it.
            rules.remove(&io_uring);
        } else {
            // An empty rule vector matches regardless of the arguments.
            rules.entry(io_uring).or_default();
        }
    }
    let arch: TargetArch = match std::env::consts::ARCH.try_into() {
        Ok(arch) => arch,
        Err(_) => die(&format!(
            "seccomp is not supported on this architecture ({})",
            std::env::consts::ARCH
        )),
    };
    let filter = match SeccompFilter::new(rules, mismatch, m, arch) {
        Ok(filter) => filter,
        Err(e) => die(&format!("Can't compile the seccomp filter: {e}")),
    };
    let bpf: BpfProgram = match filter.try_into() {
        Ok(bpf) => bpf,
        Err(e) => die(&format!("Can't compile the seccomp filter: {e}")),
    };
    if let Err(e) = seccompiler::apply_filter(&bpf) {
        die_with_error(&format!("Can't install the seccomp filter: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read one rlimit as (soft, hard).
    fn get_rlimit(resource: libc::__rlimit_resource_t) -> (u64, u64) {
        let mut lim: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::getrlimit(resource, &mut lim) }, 0);
        (lim.rlim_cur, lim.rlim_max)
    }

    #[test]
    fn rlimits_are_applied_to_the_process() {
        // apply_rlimits mutates the calling process, so run it in a
        // forked child (like the seccomp tests) and verify with
        // getrlimit there.
        let code = unsafe {
            run_in_child(|| {
                apply_rlimits(&Rlimits {
                    nproc: Some(256),
                    nofile: Some(128),
                    as_: Some(1 << 28),
                });
                // Soft == hard for every limit, so the command cannot
                // raise them again.
                if get_rlimit(libc::RLIMIT_NPROC) == (256, 256)
                    && get_rlimit(libc::RLIMIT_NOFILE) == (128, 128)
                    && get_rlimit(libc::RLIMIT_AS) == (1 << 28, 1 << 28)
                {
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "rlimits were not applied as configured");
    }

    #[test]
    fn rlimits_absent_fields_leave_the_process_untouched() {
        // The default (all-None) section must not change any limit.
        let code = unsafe {
            run_in_child(|| {
                let before = (
                    get_rlimit(libc::RLIMIT_NPROC),
                    get_rlimit(libc::RLIMIT_NOFILE),
                    get_rlimit(libc::RLIMIT_AS),
                );
                apply_rlimits(&Rlimits::default());
                let after = (
                    get_rlimit(libc::RLIMIT_NPROC),
                    get_rlimit(libc::RLIMIT_NOFILE),
                    get_rlimit(libc::RLIMIT_AS),
                );
                if before == after {
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "an absent rlimits section must not set anything");
    }

    #[test]
    fn sandbox_path_joins_under_newroot() {
        assert_eq!(
            sandbox_path(Path::new("/tmp/xyz"), Path::new("/usr/lib"))
                .display()
                .to_string(),
            "/tmp/xyz/usr/lib"
        );
    }

    #[test]
    fn mkdir_p_creates_nested_dirs() {
        let base = std::env::temp_dir().join("ai-bubble-test-mkdir-p");
        let _ = fs::remove_dir_all(&base);
        mkdir_p(&base, Path::new("a/b/c"));
        assert!(base.join("a/b/c").is_dir());
        // Idempotent.
        mkdir_p(&base, Path::new("a/b/c"));
        assert!(base.join("a/b/c").is_dir());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn mkdir_p_keeps_absolute_dest_under_newroot() {
        // Regression: Path::join("/usr") would replace the new root and
        // target the host filesystem instead.
        let base = std::env::temp_dir().join("ai-bubble-test-mkdir-abs");
        let _ = fs::remove_dir_all(&base);
        mkdir_p(&base, Path::new("/usr/lib"));
        assert!(base.join("usr/lib").is_dir());
        let _ = fs::remove_dir_all(&base);
    }

    /// Run `body` in a forked child (so the filter cannot leak into the
    /// test process) and return its exit status.
    unsafe fn run_in_child<F: FnOnce()>(body: F) -> i32 {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                // A seccomp filter without NO_NEW_PRIVS requires
                // CAP_SYS_ADMIN; set it like every exec path does.
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                body();
                libc::_exit(1);
            }
            let mut status: libc::c_int = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            }
        }
    }

    #[test]
    fn seccomp_blocklist_denies_listed_syscalls() {
        // A blocklist denies exactly the listed syscalls: getpid fails
        // with EPERM, an unlisted one (getuid) still succeeds.
        let code = unsafe {
            run_in_child(|| {
                let policy = SeccompPolicy::Block {
                    syscalls: vec![syscalls::Sysno::getpid as i64],
                    on_violation: SeccompViolation::Errno,
                    unix_sockets: true,
                };
                apply_seccomp(&policy);
                // Raw syscalls: the seccomp ERRNO action makes the raw
                // syscall return -1 with errno EPERM (glibc's wrappers
                // for "always successful" calls don't expose that).
                if libc::syscall(libc::SYS_getpid) == -1 && libc::syscall(libc::SYS_getuid) != -1 {
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "blocklist did not deny getpid as expected");
    }

    #[test]
    fn seccomp_allowlist_permits_only_listed_syscalls() {
        // An allowlist permits exactly the listed syscalls: getpid works,
        // the unlisted getuid fails with EPERM.
        let code = unsafe {
            run_in_child(|| {
                let policy = SeccompPolicy::Allow {
                    syscalls: vec![
                        syscalls::Sysno::getpid as i64,
                        syscalls::Sysno::exit_group as i64,
                    ],
                    on_violation: SeccompViolation::Errno,
                    unix_sockets: true,
                };
                apply_seccomp(&policy);
                if libc::syscall(libc::SYS_getpid) >= 0 && libc::syscall(libc::SYS_getuid) == -1 {
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "allowlist did not gate syscalls as expected");
    }

    #[test]
    fn unix_sockets_are_denied_unless_opted_in() {
        // The default policy (no seccomp section, no opt-in) denies
        // socket(2)/socketpair(2) for AF_UNIX and io_uring_setup (which
        // can create sockets without socket(2)), while AF_INET keeps
        // working (AUDIT.md M3).
        let code = unsafe {
            run_in_child(|| {
                let policy = SeccompPolicy::Block {
                    syscalls: vec![],
                    on_violation: SeccompViolation::Errno,
                    unix_sockets: false,
                };
                apply_seccomp(&policy);
                let unix_fd =
                    libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
                let inet_fd = libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                let mut sv = [0 as libc::c_int; 2];
                let paired =
                    libc::syscall(libc::SYS_socketpair, libc::AF_UNIX, libc::SOCK_STREAM, 0,
                                  sv.as_mut_ptr());
                let uring = libc::syscall(libc::SYS_io_uring_setup, 4, std::ptr::null::<()>());
                if unix_fd == -1
                    && inet_fd >= 0
                    && paired == -1
                    && uring == -1
                {
                    libc::close(inet_fd as libc::c_int);
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "AF_UNIX must be denied while AF_INET keeps working");

        // With the opt-in, AF_UNIX works again.
        let code = unsafe {
            run_in_child(|| {
                let policy = SeccompPolicy::Block {
                    syscalls: vec![],
                    on_violation: SeccompViolation::Errno,
                    unix_sockets: true,
                };
                apply_seccomp(&policy);
                let fd = libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd >= 0 {
                    libc::close(fd as libc::c_int);
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "unix_sockets opt-in must allow socket(AF_UNIX)");
    }

    #[test]
    fn unix_socket_denial_narrows_an_allowlist() {
        // An allowlist that lists socket(2) is narrowed: AF_UNIX is
        // denied even though socket(2) is allowed, and unlisted syscalls
        // stay denied.
        let code = unsafe {
            run_in_child(|| {
                let policy = SeccompPolicy::Allow {
                    syscalls: vec![
                        syscalls::Sysno::socket as i64,
                        syscalls::Sysno::exit_group as i64,
                    ],
                    on_violation: SeccompViolation::Errno,
                    unix_sockets: false,
                };
                apply_seccomp(&policy);
                let unix_fd =
                    libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
                let inet_fd = libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                let getuid = libc::syscall(libc::SYS_getuid);
                if unix_fd == -1 && inet_fd >= 0 && getuid == -1 {
                    libc::close(inet_fd as libc::c_int);
                    libc::_exit(0);
                }
            })
        };
        assert_eq!(code, 0, "allowlist with socket(2) must still deny AF_UNIX");
    }

    #[test]
    fn seccomp_kill_on_violation_kills_the_process() {
        // With on_violation=kill the denied syscall raises SIGSYS: the
        // child dies by signal instead of observing an error.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let policy = SeccompPolicy::Block {
                    syscalls: vec![syscalls::Sysno::getpid as i64],
                    on_violation: SeccompViolation::Kill,
                    unix_sockets: true,
                };
                apply_seccomp(&policy);
                let _ = libc::getpid();
                libc::_exit(0);
            }
            let mut status: libc::c_int = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
                "expected the child to die from SIGSYS, status {status:#x}"
            );
        }
    }
}
