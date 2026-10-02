//! Tests for the sandbox helpers. These run in ordinary test processes
//! (no namespaces, no exec): they exercise the parts of `sandbox` that
//! work without the privileged exec path.

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
fn unix_socket_denial_survives_garbage_upper_argument_bits() {
    // Regression for AUDIT.md H1: the kernel truncates the `domain`
    // argument of socket(2)/socketpair(2) to a C `int`, so untrusted code
    // calling `syscall(SYS_socket, AF_UNIX | (1 << 32), ...)` must still
    // be denied. A full 64-bit comparison would miss it.
    let code = unsafe {
        run_in_child(|| {
            let policy = SeccompPolicy::Block {
                syscalls: vec![],
                on_violation: SeccompViolation::Errno,
                unix_sockets: false,
            };
            apply_seccomp(&policy);
            let mangled_unix =
                libc::syscall(libc::SYS_socket, libc::AF_UNIX as u64 | (1u64 << 32),
                              libc::SOCK_STREAM, 0);
            let mangled_pair =
                libc::syscall(libc::SYS_socketpair, libc::AF_UNIX as u64 | (1u64 << 32),
                              libc::SOCK_STREAM, 0, std::ptr::null_mut::<libc::c_int>());
            // AF_INET with garbage in the upper bits must still work:
            // the kernel sees plain AF_INET.
            let mangled_inet =
                libc::syscall(libc::SYS_socket, libc::AF_INET as u64 | (1u64 << 32),
                              libc::SOCK_STREAM, 0);
            if mangled_unix == -1 && mangled_pair == -1 && mangled_inet >= 0 {
                libc::close(mangled_inet as libc::c_int);
                libc::_exit(0);
            }
        })
    };
    assert_eq!(code, 0, "AF_UNIX must be denied even with garbage upper arg bits");

    // Same in allowlist mode, where socket(2) is listed and narrowed
    // with a Ne(AF_UNIX) rule: the mangled AF_UNIX call must fall to
    // the mismatch action (deny), not to Allow.
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
            let mangled_unix =
                libc::syscall(libc::SYS_socket, libc::AF_UNIX as u64 | (1u64 << 32),
                              libc::SOCK_STREAM, 0);
            if mangled_unix == -1 {
                libc::_exit(0);
            }
        })
    };
    assert_eq!(code, 0, "allowlist Ne rule must not be fooled by garbage upper arg bits");
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

