use clap::Parser;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::exit;

/// A minimal reimplementation of bubblewrap's basic functionality.
///
/// Runs COMMAND inside a fresh sandbox (new user + mount namespace, empty
/// tmpfs root), supporting the --bind and --symlink options.
#[derive(Parser, Debug)]
#[command(
    name = "rs-bubble",
    version,
    about = "Minimal bubblewrap-like sandboxing CLI (supports --bind and --symlink)"
)]
struct Args {}

#[derive(Debug)]
enum Op {
    Bind { src: String, dest: PathBuf },
    Symlink { src: String, dest: PathBuf },
}

fn die(msg: &str) -> ! {
    eprintln!("rs-bubble: {msg}");
    exit(1)
}

fn die_with_error(msg: &str) -> ! {
    eprintln!("rs-bubble: {msg}: {}", io::Error::last_os_error());
    exit(1)
}

/// Join an absolute sandbox path onto the new root, stripping the leading '/'.
fn sandbox_path(newroot: &Path, dest: &Path) -> PathBuf {
    let rel = dest.strip_prefix("/").unwrap_or(dest);
    debug_assert!(!rel.starts_with("/"));
    newroot.join(rel)
}

/// mkdir -p for a sandbox-absolute destination (leading '/' stripped),
/// relative to the new root. Path::join with an absolute path would replace
/// the new root and create the directory on the *host* filesystem, so the
/// prefix must be stripped first.
fn mkdir_p(newroot: &Path, dest: &Path) {
    let rel = dest.strip_prefix("/").unwrap_or(dest);
    let full = newroot.join(rel);
    if fs::create_dir_all(&full).is_err() {
        die_with_error(&format!("Can't create directory {}", full.display()));
    }
}

/// Write a map file for the current process, following bwrap's order
/// (uid_map, then setgroups, then gid_map) and semantics.
fn write_id_map(file: &str, data: &str) {
    if let Err(_) = fs::write(PathBuf::from(file), data) {
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
fn userns_id() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::metadata("/proc/self/ns/user").ok()?;
    Some((md.dev(), md.ino()))
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (ops, command) = parse_cli(&argv);

    if command.is_empty() {
        die("No command given; usage: rs-bubble [options] -- COMMAND [args...]");
    }

    unsafe { setup_and_exec(&ops, &command) };
}

/// Parse the command line by hand so that the order of --bind and --symlink
/// options is preserved (clap groups each option's values by id, which would
/// lose the interleaved order that bwrap semantics rely on).
/// clap is still used for --help, --version and unknown-option errors.
fn parse_cli(argv: &[String]) -> (Vec<Op>, Vec<String>) {
    let mut ops: Vec<Op> = Vec::new();
    let mut command: Vec<String> = Vec::new();
    let mut i = 0;
    let mut after_ddash = false;

    while i < argv.len() {
        let a = &argv[i];
        if after_ddash {
            command.push(a.clone());
            i += 1;
            continue;
        }
        match a.as_str() {
            "--" => {
                after_ddash = true;
                i += 1;
            }
            "--bind" | "--symlink" => {
                let (Some(src), Some(dest)) = (argv.get(i + 1), argv.get(i + 2))
                else {
                    die(&format!("{a} takes two arguments"));
                };
                if a == "--bind" {
                    ops.push(Op::Bind {
                        src: src.clone(),
                        dest: PathBuf::from(dest),
                    });
                } else {
                    ops.push(Op::Symlink {
                        src: src.clone(),
                        dest: PathBuf::from(dest),
                    });
                }
                i += 3;
            }
            _ => {
                if a.starts_with('-') && a.len() > 1 {
                    // Unknown option: let clap produce the error message.
                    if let Err(e) = Args::try_parse_from([
                        std::env::args().next().unwrap_or_default(),
                        a.clone(),
                    ]) {
                        e.exit();
                    }
                    die("unreachable");
                }
                // First non-option argument starts the command.
                command.extend(argv[i..].iter().cloned());
                break;
            }
        }
    }

    (ops, command)
}

unsafe fn setup_and_exec(ops: &[Op], command: &[String]) -> ! {
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

    // Unshare the user and mount namespaces. After this we have
    // CAP_SYS_ADMIN in the new user namespace and can mount freely.
    let old_userns = userns_id();
    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
        die_with_error("Can't unshare user/mount namespaces");
    }
    // Verify the user namespace was really created. Some sandboxes (seccomp
    // supervisors, gVisor, LSMs) silently strip CLONE_NEWUSER from the flags,
    // which would otherwise only show up later as a confusing EPERM when
    // writing the uid/gid maps.
    let new_userns = userns_id();
    if new_userns.is_none() || new_userns == old_userns {
        die(
            "unshare() returned success, but the user namespace was not created.\n\
             Your environment (seccomp filter, sandbox or LSM) may be blocking \
             CLONE_NEWUSER.",
        );
    }

    // Set up the id mappings in the same order as bwrap: uid_map, then
    // setgroups deny, then gid_map. The setgroups deny is required before
    // gid_map unless the writer has CAP_SETGID in the parent namespace.
    write_id_map("/proc/self/uid_map", &format!("0 {real_uid} 1\n"));
    write_id_map("/proc/self/setgroups", "deny\n");
    write_id_map("/proc/self/gid_map", &format!("0 {real_gid} 1\n"));

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
    let tmpl_ptr = CString::from_vec_with_nul(tmpl.clone()).unwrap();
    let root_path = libc::mkdtemp(tmpl_ptr.into_raw() as *mut libc::c_char);
    if root_path.is_null() {
        die_with_error("Can't create temporary sandbox root");
    }
    let newroot = PathBuf::from(
        CStr::from_ptr(root_path).to_string_lossy().into_owned(),
    );

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
    let _ = fs::set_permissions(
        &newroot,
        fs::Permissions::from_mode(0o755),
    );

    // Apply the setup operations in order.
    for op in ops {
        match op {
            Op::Bind { src, dest } => {
                if dest.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
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
                let dest_c =
                    CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
                if libc::mount(
                    src_c.as_ptr(),
                    dest_c.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    die_with_error(&format!(
                        "Can't bind mount {src} -> {}",
                        dest.display()
                    ));
                }
            }
            Op::Symlink { src, dest } => {
                if dest.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
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
                let dest_c =
                    CString::new(dest_abs.as_os_str().as_bytes()).unwrap();
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
                        die_with_error(&format!(
                            "Can't make symlink at {}",
                            dest.display()
                        ));
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

    let argv: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| die("Command contains NUL byte")))
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> =
        argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let _ = io::stdout().flush();
    libc::execvp(argv[0].as_ptr(), argv_ptrs.as_ptr());
    die_with_error(&format!("Can't exec {}", command[0]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ops_preserve_cli_order() {
        let (ops, command) = parse_cli(&argv(&[
            "--symlink", "x", "/a", "--bind", "/usr", "/usr",
            "--symlink", "y", "/b", "--", "sh", "-c", "echo hi",
        ]));
        assert_eq!(ops.len(), 3);
        assert!(matches!(&ops[0], Op::Symlink { src, dest } if src == "x" && dest == Path::new("/a")));
        assert!(matches!(&ops[1], Op::Bind { src, dest } if src == "/usr" && dest == Path::new("/usr")));
        assert!(matches!(&ops[2], Op::Symlink { src, dest } if src == "y" && dest == Path::new("/b")));
        assert_eq!(command, argv(&["sh", "-c", "echo hi"]));
    }

    #[test]
    fn command_without_ddash() {
        let (ops, command) = parse_cli(&argv(&["--bind", "/tmp", "/tmp", "ls", "-l"]));
        assert_eq!(ops.len(), 1);
        assert_eq!(command, argv(&["ls", "-l"]));
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
