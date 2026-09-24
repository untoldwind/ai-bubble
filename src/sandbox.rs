//! The privileged filesystem sandbox: user/mount namespaces, tmpfs root,
//! bind mounts and symlinks, and the final exec.
//!
//! Everything in this module runs *inside* the namespace-building process;
//! it never touches the network (that is `netns`/`proxy` territory).

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::exit;

use crate::cli::Op;

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("rs-bubble: {msg}");
    exit(1)
}

pub(crate) fn die_with_error(msg: &str) -> ! {
    eprintln!("rs-bubble: {msg}: {}", io::Error::last_os_error());
    exit(1)
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
pub unsafe fn setup_and_exec(ops: &[Op], command: &[String]) -> ! {
    unsafe {
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
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            die_with_error("Can't unshare user namespace");
        }
        check_new_userns(old_userns);

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
        pidns_and_exec(ops, command);
    }
}

/// Unshare a fresh PID namespace and run the sandbox setup + exec there.
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
/// The parent keeps waiting for the child and forwards its exit status.
pub(crate) unsafe fn pidns_and_exec(ops: &[Op], command: &[String]) -> ! {
    unsafe {
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            die_with_error("Can't unshare PID namespace");
        }
        let pid = libc::fork();
        if pid < 0 {
            die_with_error("Can't fork sandboxed command");
        }
        if pid == 0 {
            mount_and_exec(ops, command);
        }

        // Parent: supervise the PID-1 child and forward its exit status.
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

/// Build the tmpfs sandbox filesystem and exec COMMAND.
///
/// Must run as PID 1 of a fresh PID namespace (see pidns_and_exec) so that
/// a fresh procfs instance (`Op::Proc`) is bound to it.
///
/// Unshares the mount namespace. This requires CAP_SYS_ADMIN over the user
/// namespace owning the *current* mount namespace, so the isolated path
/// must reach this in the child that inherited the fresh user namespace
/// created by `netns::isolated_parent` (the new mount namespace is then
/// owned by that same user namespace).
pub(crate) unsafe fn mount_and_exec(ops: &[Op], command: &[String]) -> ! {
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

        // Create a fresh tmpfs to serve as the sandbox root.
        let mut tmpl: Vec<u8> = b"/tmp/rs-bubble.XXXXXX".to_vec();
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

        // Bind the host FUSE filesystem into the sandbox at /host. This must
        // happen before chroot, while the host mountpoint path is still
        // resolvable. (The FUSE server keeps running in the host process.)
        if let Some(host_mount) = crate::hostfs::host_mount_point() {
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
                Op::Bind { src, dest } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid bind destination {}", dest.display()));
                    }
                    let src_c = CString::new(src.as_bytes()).unwrap();
                    let mut src_stat: libc::stat = std::mem::zeroed();
                    if libc::stat(src_c.as_ptr(), &mut src_stat) != 0 {
                        die_with_error(&format!("Can't find source {src}"));
                    }
                    let dest_abs = sandbox_path(&newroot, dest);
                    // Bind targets must exist; create missing directories on the
                    // tmpfs root (bwrap does the same for its new root).
                    mkdir_p(&newroot, dest);
                    let dest_c = CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
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
                }
                Op::Proc { dest } => {
                    if dest
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        die(&format!("Invalid proc mount point {}", dest.display()));
                    }
                    mkdir_p(&newroot, dest);
                    let dest_abs = sandbox_path(&newroot, dest);
                    let dest_c = CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
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
                        mkdir_p(&newroot, p);
                    }
                    let dest_abs = sandbox_path(&newroot, dest);
                    let dest_c = CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
                    let src_c = CString::new(src.as_bytes()).unwrap();
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
                            die_with_error(&format!("Can't make symlink at {}", dest.display()));
                        }
                    }
                }
            }
        }

        // Enter the sandbox and run the command.
        if libc::chdir(newroot_c.as_ptr()) != 0 {
            die_with_error("Can't chdir to sandbox root");
        }
        if libc::chroot(CString::new(".").unwrap().as_ptr()) != 0 {
            die_with_error("Can't chroot into sandbox");
        }
        if libc::chdir(CString::new("/").unwrap().as_ptr()) != 0 {
            die_with_error("Can't chdir to / in sandbox");
        }

        // All privileged work is done; run the command with as little
        // authority as possible: no capabilities at all, and as a uid/gid
        // that does not exist on the host.
        drop_all_capabilities();

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

#[cfg(test)]
mod tests {
    use super::*;

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
        let base = std::env::temp_dir().join("rs-bubble-test-mkdir-p");
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
        let base = std::env::temp_dir().join("rs-bubble-test-mkdir-abs");
        let _ = fs::remove_dir_all(&base);
        mkdir_p(&base, Path::new("/usr/lib"));
        assert!(base.join("usr/lib").is_dir());
        assert!(base.is_dir());
        let _ = fs::remove_dir_all(&base);
    }
}
