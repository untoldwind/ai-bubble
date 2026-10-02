use super::*;
use crate::hostfs::pattern::{Pattern, Walk};
use crate::hostfs::patterns::Permission;
use std::os::unix::fs::PermissionsExt;

fn fs(entries: &[(&str, Permission)]) -> HostFs {
    HostFs::collect(&Patterns::new(
        entries
            .iter()
            .map(|(p, perm)| (p.to_string(), perm.clone()))
            .collect(),
    ))
}

/// Alias for readability in the empty-path tests.
fn fs_with_empties(entries: &[(&str, Permission)]) -> HostFs {
    fs(entries)
}

/// Run a FUSE-handler future to completion (the handlers are async only
/// because the trait demands it — the IO inside is synchronous).
fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

/// The kernel consults `access` during `chdir`'s permission check —
/// including for the mount root itself (the sandbox chroots into the FUSE
/// mount in root mode). The root has no parent component; the anchored
/// parent must resolve to the pinned anchor with the name `.` and the
/// real filesystem (here: the root itself, a readable directory) decides.
/// A silent ENOENT here made `chdir` into the sandbox root fail with
/// ENOENT (a regression of the C1 fix).
#[test]
fn access_on_the_root_inode_is_answered_by_the_real_fs() {
    let f = fs(&[("/usr", Permission::Ro)]);
    block(async {
        f.access(Request::default(), inodes::ROOT_INODE, libc::X_OK as u32)
            .await
            .expect("access(X_OK) on the root inode");
        f.access(Request::default(), inodes::ROOT_INODE, libc::R_OK as u32)
            .await
            .expect("access(R_OK) on the root inode");
    });
}

#[test]
fn empty_paths_are_virtual_unwritable_directories() {
    let f = fs_with_empties(&[("/dev", Permission::Empty)]);

    // The dir itself exists, with no write permission...
    assert!(f.patterns.exists(Path::new("/dev")));
    assert!(f.patterns.is_empty(Path::new("/dev")));
    assert_eq!(f.attr(Path::new("/dev")).unwrap().perm, 0o555);
    assert_eq!(f.attr(Path::new("/dev")).unwrap().kind, FileType::Directory);
    // ...and it is empty even though the real host /dev has entries.
    assert!(f.dir_entries(Path::new("/dev")).is_empty());
    // Deeper paths are shadowed by the precedence.
    assert!(!f.patterns.exists(Path::new("/dev/null")));
    assert!(!f.patterns.matches(Path::new("/dev/null")));
    // The empty pattern "reaches" below /dev (so ancestors stay
    // navigable), but the precedence keeps /dev/null non-existent.
    assert!(f.patterns.dir_prefix(Path::new("/dev/null")));
    assert!(!f.patterns.exists(Path::new("/dev/null")));
    // The mountpoint dir is not itself a dir-prefix.
    assert!(!f.patterns.dir_prefix(Path::new("/dev")));
}

#[test]
fn empty_paths_take_precedence_over_mirror() {
    let f = fs(&[
        ("/etc/*", Permission::Ro),
        ("/etc", Permission::Ro),
        ("/etc", Permission::Empty),
    ]);
    assert!(f.patterns.is_empty(Path::new("/etc")));
    // Mirror contents below the empty dir are hidden.
    assert!(!f.patterns.exists(Path::new("/etc/passwd")));
    assert!(f.dir_entries(Path::new("/etc")).is_empty());
    // But /etc still appears at the root listing.
    let names: Vec<_> = f
        .dir_entries(Path::new("/"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["etc"]);
}

#[test]
fn injected_paths_are_virtual_read_only_files() {
    let f = fs(&[(
        "/etc/resolv.conf",
        Permission::Inject {
            content: "nameserver 127.0.0.2\n".to_string(),
        },
    )]);

    // The injected path exists and is a visible mirror match.
    assert!(f.patterns.exists(Path::new("/etc/resolv.conf")));
    assert!(f.patterns.matches(Path::new("/etc/resolv.conf")));

    // Its attributes: a read-only regular file sized like the content.
    let attr = f.attr(Path::new("/etc/resolv.conf")).unwrap();
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.perm, 0o444);
    assert_eq!(attr.size, "nameserver 127.0.0.2\n".len() as u64);

    // Ancestors stay navigable (even without any host mapping for
    // /etc), and the file shows up in its (virtual) directory.
    assert!(f.patterns.exists(Path::new("/etc")));
    assert!(f.patterns.dir_prefix(Path::new("/etc")));
    assert!(f.is_listable_dir(Path::new("/etc")));
    let names: Vec<_> = f
        .dir_entries(Path::new("/etc"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["resolv.conf"]);

    // Read-only: nothing can be written to it (or created below it —
    // the injected path is a file).
    assert!(!f.patterns.writable(Path::new("/etc/resolv.conf")));
    assert!(!f.patterns.writable(Path::new("/etc/resolv.conf/sub")));

    // Nothing below the injected path is visible at all.
    assert!(!f.patterns.exists(Path::new("/etc/resolv.conf/x")));
    assert_eq!(
        Patterns::new(vec![(
            "/etc/resolv.conf".to_string(),
            Permission::Inject {
                content: "x".to_string()
            }
        )])
        .permission_of(Path::new("/etc/resolv.conf/x")),
        None
    );
}

#[test]
fn injected_path_ancestors_are_virtual_directories_for_access() {
    let f = fs(&[(
        "/etc/pki/tls/certs/ca-bundle.crt",
        Permission::Inject {
            content: "x".to_string(),
        },
    )]);

    // The purely virtual ancestors of an injected file are answered
    // directly by `access` (the kernel consults it for `chdir`), as
    // long as the real host path does not exist; where a real host
    // directory exists, the real filesystem decides.
    for p in ["/etc", "/etc/pki", "/etc/pki/tls", "/etc/pki/tls/certs"] {
        let p = Path::new(p);
        assert_eq!(
            f.virtual_only(p),
            !f.patterns.redirect(p).exists(),
            "virtual_only({p:?})"
        );
    }
    // An injected file itself is always purely virtual.
    assert!(f.virtual_only(Path::new("/etc/pki/tls/certs/ca-bundle.crt")));

    // A real mirror path is not: the real filesystem decides.
    assert!(!f.virtual_only(Path::new("/usr/bin")));
}

#[test]
fn empty_paths_match_real_files_as_empty_files() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-empty-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("f.txt"), b"content").unwrap();
    std::fs::create_dir_all(base.join("d")).unwrap();

    let f = fs(&[(&format!("{}/*", base.display()), Permission::Empty)]);
    // The real file is shown empty.
    let file = f.attr(&base.join("f.txt")).unwrap();
    assert_eq!(file.kind, FileType::RegularFile);
    assert_eq!(file.size, 0);
    // The real directory is shown as an empty directory.
    let dir = f.attr(&base.join("d")).unwrap();
    assert_eq!(dir.kind, FileType::Directory);
    assert_eq!(dir.perm, 0o555);
    assert!(f.dir_entries(&base.join("d")).is_empty());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn empty_path_ancestors_stay_navigable() {
    // A nested empty path; /var exists only as a virtual ancestor.
    let f = fs_with_empties(&[("/var/tmp", Permission::Empty)]);
    assert!(f.patterns.exists(Path::new("/var")));
    assert!(f.patterns.is_empty_prefix(Path::new("/var")));
    assert!(f.patterns.exists(Path::new("/var/tmp")));
    assert!(!f.patterns.exists(Path::new("/var/tmp/other")));
    assert!(!f.patterns.exists(Path::new("/var/etc")));
    // The root listing contains both levels of the chain.
    let root: Vec<_> = f
        .dir_entries(Path::new("/"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(root, ["var"]);
    let var: Vec<_> = f
        .dir_entries(Path::new("/var"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(var, ["tmp"]);
}

#[test]
fn empty_paths_coexist_with_mirror() {
    // /dev is empty, /etc/passwd is mirrored normally; siblings of the
    // empty path are listed together with it.
    let f = fs(&[("/etc/passwd", Permission::Ro), ("/dev", Permission::Empty)]);
    let names: Vec<_> = f
        .dir_entries(Path::new("/"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["dev", "etc"]);
    assert!(f.patterns.exists(Path::new("/etc/passwd")));
    assert!(!f.patterns.exists(Path::new("/dev/whatever")));
}

#[test]
fn redirected_paths_show_the_source_content() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-redirect-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(base.join("real/sub")).unwrap();
    std::fs::write(base.join("real/file.txt"), b"redirected").unwrap();

    let f = HostFs::collect(&Patterns::new(vec![(
        "/virtual".to_string(),
        Permission::Redirect {
            source: base.join("real"),
            writable: false,
        },
    )]));

    // The redirected path is visible and shows the source's content.
    assert!(f.patterns.exists(Path::new("/virtual")));
    assert!(f.patterns.matches(Path::new("/virtual")));
    let attr = f.attr(Path::new("/virtual")).unwrap();
    assert_eq!(attr.kind, FileType::Directory);

    // Its entries are the source dir's entries, listed under the
    // redirected name.
    let mut names: Vec<_> = f
        .dir_entries(Path::new("/virtual"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["file.txt", "sub"]);

    // A file below the redirect reads the real source file.
    let attr = f.attr(Path::new("/virtual/file.txt")).unwrap();
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.size, 10);

    // Read-only: not writable despite existing.
    assert!(!f.patterns.writable(Path::new("/virtual/file.txt")));

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn redirected_files_are_listed_in_their_directory() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-test-redirect-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("cfg.json"), b"redirected").unwrap();

    // A redirected file inside a directory that is itself redirected
    // to an empty (or otherwise non-matching) directory: the file is
    // lookable, so it must be listed, too — even though the listing
    // of its parent does not come from the host directory containing
    // the redirect target.
    let f = HostFs::collect(&Patterns::new(vec![
        (
            "/conf".to_string(),
            Permission::Redirect {
                source: base.join("cache"),
                writable: false,
            },
        ),
        (
            "/conf/cfg.json".to_string(),
            Permission::Redirect {
                source: base.join("cfg.json"),
                writable: false,
            },
        ),
    ]));
    let names: Vec<_> = f
        .dir_entries(Path::new("/conf"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["cfg.json"]);

    // A redirect whose source does not exist is not listed (no
    // "ghost" entry advertising a lookup that fails).
    let f = HostFs::collect(&Patterns::new(vec![(
        "/conf/missing.json".to_string(),
        Permission::Redirect {
            source: base.join("missing.json"),
            writable: false,
        },
    )]));
    assert!(f.dir_entries(Path::new("/conf")).is_empty());

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn readdir_filters_non_matching_entries() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-test-readdir-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("a.conf"), b"a").unwrap();
    std::fs::write(base.join("b.txt"), b"b").unwrap();
    std::fs::create_dir(base.join("c.conf.dir")).unwrap();
    std::fs::write(base.join("c.conf.dir/x"), b"x").unwrap();
    std::fs::create_dir(base.join("d.conf")).unwrap();
    std::fs::write(base.join("d.conf/y"), b"y").unwrap();

    let f = fs(&[(&format!("{}/*.conf", base.display()), Permission::Ro)]);

    // Only matching entries (and entries leading to matches) survive.
    let names: Vec<_> = f
        .dir_entries(&base)
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"a.conf".to_string()));
    assert!(names.contains(&"d.conf".to_string())); // a directory named by the pattern
    assert!(!names.contains(&"b.txt".to_string()));
    assert!(!names.contains(&"c.conf.dir".to_string()));

    // An entry that only leads to a match (virtual ancestor) is shown.
    let f = fs(&[(&format!("{}/c.conf.dir/x", base.display()), Permission::Ro)]);
    let names: Vec<_> = f
        .dir_entries(&base)
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"c.conf.dir".to_string()));
    assert!(!names.contains(&"a.conf".to_string()));
    assert!(!names.contains(&"b.txt".to_string()));

    // An exactly matched directory is a recursive mirror: all real
    // entries are visible.
    let f = fs(&[(
        &format!("{}", base.join("c.conf.dir").display()),
        Permission::Ro,
    )]);
    let names: Vec<_> = f
        .dir_entries(&base.join("c.conf.dir"))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["x"]);

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn empty_mirror_matches_nothing() {
    let f = fs(&[]);
    assert!(!f.patterns.exists(Path::new("/")));
    assert!(f.dir_entries(Path::new("/")).is_empty());
}

#[test]
fn empty_patterns_only_still_show_root() {
    let f = fs_with_empties(&[("/dev", Permission::Empty)]);
    assert!(f.patterns.exists(Path::new("/")));
    assert_eq!(
        f.dir_entries(Path::new("/"))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["dev"]
    );
}

#[test]
fn hidden_directories_hide_their_subtree() {
    let f = fs(&[
        ("/etc", Permission::Ro),
        ("/etc/passwd", Permission::Ro),
        ("/etc", Permission::Hide),
    ]);
    // The hide pattern matches /etc last and shadows everything below.
    assert!(!f.patterns.exists(Path::new("/etc")));
    assert!(!f.patterns.exists(Path::new("/etc/passwd")));
    assert!(f.dir_entries(Path::new("/")).is_empty());
    // Siblings are unaffected; the hide is scoped to /etc.
    let base =
        std::env::temp_dir().join(format!("ai-bubble-hostfs-hide-test-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("foo.conf"), b"f").unwrap();
    std::fs::create_dir_all(base.join("secret")).unwrap();
    let base_str = base.display().to_string();
    let f = fs(&[
        (&format!("{base_str}/*"), Permission::Ro),
        (&format!("{base_str}/secret"), Permission::Hide),
    ]);
    assert!(f.patterns.exists(&base.join("foo.conf")));
    assert!(!f.patterns.exists(&base.join("secret")));
    // The parent stays navigable for the still-mirrored matches.
    assert!(f.patterns.exists(&base));
    let names: Vec<_> = f
        .dir_entries(&base)
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["foo.conf"]);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn walk_depth_reports_how_deep_a_pattern_reaches() {
    let p = Pattern::new("/etc/*.conf").unwrap();
    assert_eq!(p.walk_depth(Path::new("/etc")), Some((Walk::CouldReach, 1)));
    assert_eq!(
        p.walk_depth(Path::new("/etc/foo.conf")),
        Some((Walk::Exact, 2))
    );
    assert_eq!(p.walk_depth(Path::new("/var")), None);

    let p = Pattern::new("/usr/share/**").unwrap();
    assert_eq!(
        p.walk_depth(Path::new("/usr/share/doc")),
        Some((Walk::StarStar, 2))
    );
    assert_eq!(
        p.walk_depth(Path::new("/usr/share")),
        Some((Walk::StarStar, 2))
    );

    let p = Pattern::new("/etc").unwrap();
    assert_eq!(
        p.walk_depth(Path::new("/etc/passwd")),
        Some((Walk::Ancestor, 1))
    );
}

/// A base directory with a pre-existing host symlink (`evil`) pointing at
/// `outside`, plus a real `real/.ssh` skeleton — the exact layout of the
/// audit's C1 attack.
fn escape_fixture(tag: &str) -> (PathBuf, PathBuf) {
    let base =
        std::env::temp_dir().join(format!("ai-bubble-hostfs-c1-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("real/.ssh")).unwrap();
    std::fs::create_dir_all(base.join("outside")).unwrap();
    std::fs::write(base.join("outside/authorized_keys"), b"HOST-SECRET").unwrap();
    std::os::unix::fs::symlink(base.join("outside"), base.join("evil")).unwrap();
    (base.clone(), base.join("outside/authorized_keys"))
}

/// The audit's C1 attack, exercised through the FUSE handlers: the sandbox
/// looks up the real directory skeleton, then (out of band, e.g. through a
/// bind mount) swaps a symlink into its place — and must not be able to
/// read or write the symlink's target through the mirrored path afterwards.
#[test]
fn intermediate_symlink_swap_cannot_redirect_host_access() {
    let (base, outside_file) = escape_fixture("open");
    let f = fs(&[(base.to_str().unwrap(), Permission::Rw)]);

    // Establish the directory dentries (cached nodeids), as the kernel
    // would during the attack.
    let base_ino = f
        .inodes
        .write()
        .expect("inode map poisoned")
        .get_or_insert(&base, inodes::ROOT_INODE);
    let real_ino = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("real"))
            .await
            .expect("lookup real")
            .attr
            .ino
    });
    let ssh_ino = block(async {
        f.lookup(Request::default(), real_ino, OsStr::new(".ssh"))
            .await
            .expect("lookup .ssh")
            .attr
            .ino
    });

    // The swap: `real` becomes the host symlink (renamed out of band —
    // through a bind mount, or between FUSE requests). No race involved:
    // the mirrored path now persistently resolves through the link.
    std::fs::rename(base.join("real"), base.join("real.bak")).unwrap();
    std::fs::rename(base.join("evil"), base.join("real")).unwrap();

    // Every operation on the cached paths must fail — never resolve
    // through the host symlink to `outside`.
    let res = block(async {
        f.open(Request::default(), ssh_ino, libc::O_RDONLY as u32)
            .await
    });
    assert!(res.is_err(), "open through swapped symlink must fail");
    let res = block(async { f.read(Request::default(), ssh_ino, 0, 0, 64).await });
    assert!(
        res.is_err(),
        "stateless read through swapped symlink must fail"
    );
    let res = block(async { f.getattr(Request::default(), real_ino, None, 0).await });
    // `getattr` succeeds — the symlink is shown *as a symlink* — but it is
    // never followed: the access below cannot reach its target.
    let attr = res.expect("getattr on the swapped path succeeds");
    assert_eq!(attr.attr.kind, FileType::Symlink);

    // The target file is untouched and was never readable through the mirror.
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"HOST-SECRET");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A symlink at an intermediate host-path component (pre-existing, not
/// swapped) is never followed by any host access either: attributes of a
/// path *through* it fail, while the symlink itself still shows as one.
#[test]
fn intermediate_symlinks_are_never_followed_by_host_access() {
    let (base, outside_file) = escape_fixture("walk");
    std::fs::write(base.join("real/.ssh/authorized_keys"), b"skeleton").unwrap();
    let f = fs(&[(base.to_str().unwrap(), Permission::Rw)]);

    // Through the link: the path cannot be resolved (no content leaks).
    assert!(f.attr(&base.join("evil/authorized_keys")).is_err());
    // The link itself is still visible *as a symlink*.
    let attr = f.attr(&base.join("evil")).unwrap();
    assert_eq!(attr.kind, FileType::Symlink);
    // …and the real file behind the link is untouched.
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"HOST-SECRET");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A symlink standing at a *final* component is linked as a link (never
/// followed to its target), and the new name cannot be used to reach the
/// target either.
#[test]
fn hard_linking_a_symlink_links_the_link_not_the_target() {
    let (base, outside_file) = escape_fixture("link");
    let f = fs(&[(base.to_str().unwrap(), Permission::Rw)]);
    let base_ino = f
        .inodes
        .write()
        .expect("inode map poisoned")
        .get_or_insert(&base, inodes::ROOT_INODE);

    // The sandbox links the symlink `evil` to a new name `copy`.
    let evil_ino = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("evil"))
            .await
            .expect("lookup evil")
            .attr
            .ino
    });
    block(async {
        f.link(Request::default(), evil_ino, base_ino, OsStr::new("copy"))
            .await
            .expect("link of the symlink succeeds");
    });

    // The new name is a symlink (its target was not hard-linked through).
    let attr = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("copy"))
            .await
            .expect("lookup copy")
            .attr
    });
    assert_eq!(attr.kind, FileType::Symlink);
    // Opening it fails like any mirror symlink: the target stays unreachable.
    let copy_ino = attr.ino;
    let res = block(async {
        f.open(Request::default(), copy_ino, libc::O_RDONLY as u32)
            .await
    });
    assert!(res.is_err());
    assert_eq!(std::fs::read(&outside_file).unwrap(), b"HOST-SECRET");

    std::fs::remove_dir_all(&base).unwrap();
}

/// The audit's H1 finding, exercised through the FUSE handlers: an `empty`
/// mapping that names a *real existing host file* must blank the file out
/// even for `open()`. Before the fix, `open(O_RDONLY)` lstat'ed and opened
/// the real file and registered a stateful handle, whose read fast-path
/// served the real bytes without any spec re-check — exactly what the
/// mapping was supposed to prevent.
#[test]
fn open_of_an_empty_path_never_opens_the_real_file() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-h1-empty-open-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("secret"), b"HOST-SECRET").unwrap();
    let secret = base.join("secret");
    let f = fs(&[
        (base.to_str().unwrap(), Permission::Ro),
        (secret.to_str().unwrap(), Permission::Empty),
    ]);

    let base_ino = f
        .inodes
        .write()
        .expect("inode map poisoned")
        .get_or_insert(&base, inodes::ROOT_INODE);
    let secret_ino = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("secret"))
            .await
            .expect("lookup secret")
            .attr
            .ino
    });

    // The lookup advertised a size-0 file (the empty-file attr); the open
    // must agree with it: a virtual handle (fh 0), not the real host file.
    let opened = block(async {
        f.open(Request::default(), secret_ino, libc::O_RDONLY as u32)
            .await
            .expect("open of an empty path succeeds")
    });
    assert_eq!(opened.fh, 0, "empty path must get the virtual fh 0");

    // The read goes down the stateless path, which serves zero bytes for
    // empty paths — never the real file's content.
    let data = block(async {
        f.read(Request::default(), secret_ino, opened.fh, 0, 64)
            .await
            .expect("read of an empty path succeeds")
    });
    assert!(data.data.is_empty(), "empty path reads as empty");
    assert_eq!(data.data.len(), 0);

    // Write opens are refused like for injected paths.
    let res = block(async {
        f.open(
            Request::default(),
            secret_ino,
            (libc::O_WRONLY | libc::O_TRUNC) as u32,
        )
        .await
    });
    let Err(res) = res else { unreachable!() };
    assert_eq!(
        <fuse3::Errno>::from(libc::EACCES),
        res,
        "write open of an empty path must be EACCES"
    );

    // The real file is untouched and its content never left the host side.
    assert_eq!(std::fs::read(&secret).unwrap(), b"HOST-SECRET");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A chmod (`setattr` with a mode) on a mirrored path that is a host symlink
/// at a writable location must never chmod the symlink's TARGET: the target
/// may live outside every mapping (audit finding M4). Before the fix,
/// `fchmodat` without `AT_SYMLINK_NOFOLLOW` followed the link and changed the
/// permissions of the file it pointed at.
#[test]
fn setattr_chmod_does_not_follow_a_final_symlink() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-m4-chmod-link-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("target"), b"HOST-SECRET").unwrap();
    std::os::unix::fs::symlink("target", base.join("evil")).unwrap();
    let f = fs(&[(base.to_str().unwrap(), Permission::Rw)]);

    let base_ino = f
        .inodes
        .write()
        .expect("inode map poisoned")
        .get_or_insert(&base, inodes::ROOT_INODE);
    let evil_ino = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("evil"))
            .await
            .expect("lookup evil")
            .attr
            .ino
    });

    // chmod through the mirror: either refused, or applied to the link
    // itself — but the target must keep its mode either way.
    let res = block(async {
        f.setattr(
            Request::default(),
            evil_ino,
            None,
            SetAttr {
                mode: Some(0o700),
                ..SetAttr::default()
            },
        )
        .await
    });
    if let Err(res) = &res {
        assert_eq!(
            <fuse3::Errno>::from(libc::EACCES),
            *res,
            "chmod of a mirror symlink must fail with EACCES"
        );
    }

    // The symlink is still a symlink, and its target's permissions are
    // exactly what they were before the attempted chmod.
    let link_meta = std::fs::symlink_metadata(base.join("evil")).unwrap();
    assert!(link_meta.file_type().is_symlink(), "evil stays a symlink");
    let target_mode = std::fs::metadata(base.join("target")).unwrap().permissions().mode();
    assert_eq!(
        target_mode & 0o7777,
        0o644,
        "the symlink target's mode must be unchanged"
    );
    assert_eq!(std::fs::read(base.join("target")).unwrap(), b"HOST-SECRET");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A chmod through the mirror must not be able to plant setuid/setgid bits
/// on a real host file: the requested mode is masked to `0o7777` with the
/// `0o6000` bits stripped (audit finding L6 — harmless for unprivileged
/// users, dangerous if ai-bubble runs as root).
#[test]
fn setattr_chmod_strips_setuid_and_setgid_bits() {
    let base = std::env::temp_dir().join(format!(
        "ai-bubble-hostfs-l6-setuid-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("file"), b"data").unwrap();
    let f = fs(&[(base.to_str().unwrap(), Permission::Rw)]);

    let base_ino = f
        .inodes
        .write()
        .expect("inode map poisoned")
        .get_or_insert(&base, inodes::ROOT_INODE);
    let file_ino = block(async {
        f.lookup(Request::default(), base_ino, OsStr::new("file"))
            .await
            .expect("lookup file")
            .attr
            .ino
    });

    block(async {
        f.setattr(
            Request::default(),
            file_ino,
            None,
            SetAttr {
                mode: Some(0o4755),
                ..SetAttr::default()
            },
        )
        .await
        .expect("chmod of a regular file succeeds")
    });

    let mode = std::fs::metadata(base.join("file")).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o7777,
        0o755,
        "the setuid/setgid bits must be stripped silently"
    );

    std::fs::remove_dir_all(&base).unwrap();
}
