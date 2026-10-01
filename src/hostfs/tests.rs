use super::*;
use crate::hostfs::pattern::Walk;

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

/// The async HostFs methods (`attr`, `dir_entries`, …) run their host
/// syscalls via `tokio::fs` on the blocking pool; the synchronous tests
/// await them on a throwaway current-thread runtime.
fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

#[test]
fn empty_paths_are_virtual_unwritable_directories() {
    let f = fs_with_empties(&[("/dev", Permission::Empty)]);

    // The dir itself exists, with no write permission...
    assert!(f.exists(Path::new("/dev")));
    assert!(f.is_empty(Path::new("/dev")));
    assert_eq!(block(f.attr(Path::new("/dev"))).unwrap().perm, 0o555);
    assert_eq!(
        block(f.attr(Path::new("/dev"))).unwrap().kind,
        FileType::Directory
    );
    // ...and it is empty even though the real host /dev has entries.
    assert!(block(f.dir_entries(Path::new("/dev"))).is_empty());
    // Deeper paths are shadowed by the precedence.
    assert!(!f.exists(Path::new("/dev/null")));
    assert!(!f.matches(Path::new("/dev/null")));
    // The empty pattern "reaches" below /dev (so ancestors stay
    // navigable), but the precedence keeps /dev/null non-existent.
    assert!(f.patterns.dir_prefix(Path::new("/dev/null")));
    assert!(!f.exists(Path::new("/dev/null")));
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
    assert!(f.is_empty(Path::new("/etc")));
    // Mirror contents below the empty dir are hidden.
    assert!(!f.exists(Path::new("/etc/passwd")));
    assert!(block(f.dir_entries(Path::new("/etc"))).is_empty());
    // But /etc still appears at the root listing.
    let names: Vec<_> = block(f.dir_entries(Path::new("/")))
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
    assert!(f.exists(Path::new("/etc/resolv.conf")));
    assert!(f.matches(Path::new("/etc/resolv.conf")));

    // Its attributes: a read-only regular file sized like the content.
    let attr = block(f.attr(Path::new("/etc/resolv.conf"))).unwrap();
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.perm, 0o444);
    assert_eq!(attr.size, "nameserver 127.0.0.2\n".len() as u64);

    // Ancestors stay navigable (even without any host mapping for
    // /etc), and the file shows up in its (virtual) directory.
    assert!(f.exists(Path::new("/etc")));
    assert!(f.patterns.dir_prefix(Path::new("/etc")));
    assert!(block(f.is_listable_dir(Path::new("/etc"))));
    let names: Vec<_> = block(f.dir_entries(Path::new("/etc")))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["resolv.conf"]);

    // Read-only: nothing can be written to it (or created below it —
    // the injected path is a file).
    assert!(!f.writable(Path::new("/etc/resolv.conf")));
    assert!(!f.writable(Path::new("/etc/resolv.conf/sub")));

    // Nothing below the injected path is visible at all.
    assert!(!f.exists(Path::new("/etc/resolv.conf/x")));
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
            block(f.virtual_only(p)),
            !f.patterns.redirect(p).exists(),
            "virtual_only({p:?})"
        );
    }
    // An injected file itself is always purely virtual.
    assert!(block(
        f.virtual_only(Path::new("/etc/pki/tls/certs/ca-bundle.crt"))
    ));

    // A real mirror path is not: the real filesystem decides.
    assert!(!block(f.virtual_only(Path::new("/usr/bin"))));
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
    let file = block(f.attr(&base.join("f.txt"))).unwrap();
    assert_eq!(file.kind, FileType::RegularFile);
    assert_eq!(file.size, 0);
    // The real directory is shown as an empty directory.
    let dir = block(f.attr(&base.join("d"))).unwrap();
    assert_eq!(dir.kind, FileType::Directory);
    assert_eq!(dir.perm, 0o555);
    assert!(block(f.dir_entries(&base.join("d"))).is_empty());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn empty_path_ancestors_stay_navigable() {
    // A nested empty path; /var exists only as a virtual ancestor.
    let f = fs_with_empties(&[("/var/tmp", Permission::Empty)]);
    assert!(f.exists(Path::new("/var")));
    assert!(f.patterns.is_empty_prefix(Path::new("/var")));
    assert!(f.exists(Path::new("/var/tmp")));
    assert!(!f.exists(Path::new("/var/tmp/other")));
    assert!(!f.exists(Path::new("/var/etc")));
    // The root listing contains both levels of the chain.
    let root: Vec<_> = block(f.dir_entries(Path::new("/")))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(root, ["var"]);
    let var: Vec<_> = block(f.dir_entries(Path::new("/var")))
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
    let names: Vec<_> = block(f.dir_entries(Path::new("/")))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["dev", "etc"]);
    assert!(f.exists(Path::new("/etc/passwd")));
    assert!(!f.exists(Path::new("/dev/whatever")));
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
    assert!(f.exists(Path::new("/virtual")));
    assert!(f.matches(Path::new("/virtual")));
    let attr = block(f.attr(Path::new("/virtual"))).unwrap();
    assert_eq!(attr.kind, FileType::Directory);

    // Its entries are the source dir's entries, listed under the
    // redirected name.
    let mut names: Vec<_> = block(f.dir_entries(Path::new("/virtual")))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["file.txt", "sub"]);

    // A file below the redirect reads the real source file.
    let attr = block(f.attr(Path::new("/virtual/file.txt"))).unwrap();
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.size, 10);

    // Read-only: not writable despite existing.
    assert!(!f.writable(Path::new("/virtual/file.txt")));

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
    let names: Vec<_> = block(f.dir_entries(Path::new("/conf")))
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
    assert!(block(f.dir_entries(Path::new("/conf"))).is_empty());

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn redirect_rw_is_writable_and_ro_is_not() {
    let ro = HostFs::collect(&Patterns::new(vec![(
        "/a".to_string(),
        Permission::Redirect {
            source: PathBuf::from("/x"),
            writable: false,
        },
    )]));
    let rw = HostFs::collect(&Patterns::new(vec![(
        "/a".to_string(),
        Permission::Redirect {
            source: PathBuf::from("/x"),
            writable: true,
        },
    )]));
    assert!(!ro.writable(Path::new("/a/f")));
    assert!(!has_writable_patterns(&Patterns::new(vec![(
        "/a".to_string(),
        Permission::Redirect {
            source: PathBuf::from("/x"),
            writable: false,
        },
    )])));
    assert!(rw.writable(Path::new("/a/f")));
    assert!(has_writable_patterns(&Patterns::new(vec![(
        "/a".to_string(),
        Permission::Redirect {
            source: PathBuf::from("/x"),
            writable: true,
        },
    )])));
}

#[test]
fn pattern_matching_per_operation() {
    let f = fs(&[
        ("/etc/*.conf", Permission::Ro),
        ("/home/me/project", Permission::Ro),
    ]);

    // Direct matches.
    assert!(f.matches(Path::new("/etc/foo.conf")));
    assert!(f.matches(Path::new("/home/me/project")));
    assert!(!f.matches(Path::new("/etc/passwd")));

    // exists: matches plus ancestor directories.
    assert!(f.exists(Path::new("/etc/foo.conf")));
    assert!(f.exists(Path::new("/etc"))); // ancestor of a match
    assert!(f.exists(Path::new("/"))); // root
    assert!(f.exists(Path::new("/home/me/project")));
    assert!(!f.exists(Path::new("/etc/passwd")));
    assert!(!f.exists(Path::new("/etc/nothing")));

    // dir_prefix: only true for ancestors of matches — an exactly
    // matched path (file or recursively mirrored directory) is not a
    // prefix itself.
    assert!(f.patterns.dir_prefix(Path::new("/etc")));
    assert!(f.patterns.dir_prefix(Path::new("/home")));
    assert!(f.patterns.dir_prefix(Path::new("/home/me")));
    assert!(!f.patterns.dir_prefix(Path::new("/home/me/project")));
    assert!(!f.patterns.dir_prefix(Path::new("/etc/passwd")));
    assert!(!f.patterns.dir_prefix(Path::new("/etc/foo.conf")));
}

#[test]
fn double_star_spans_directories() {
    let f = fs(&[("/usr/share/**/*.rs", Permission::Ro)]);
    assert!(f.exists(Path::new("/usr/share")));
    assert!(f.patterns.dir_prefix(Path::new("/usr/share/doc")));
    assert!(f.matches(Path::new("/usr/share/doc/x/y.rs")));
    assert!(!f.matches(Path::new("/usr/share/doc/x/y.c")));
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
    let names: Vec<_> = block(f.dir_entries(&base))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"a.conf".to_string()));
    assert!(names.contains(&"d.conf".to_string())); // a directory named by the pattern
    assert!(!names.contains(&"b.txt".to_string()));
    assert!(!names.contains(&"c.conf.dir".to_string()));

    // An entry that only leads to a match (virtual ancestor) is shown.
    let f = fs(&[(&format!("{}/c.conf.dir/x", base.display()), Permission::Ro)]);
    let names: Vec<_> = block(f.dir_entries(&base))
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
    let names: Vec<_> = block(f.dir_entries(&base.join("c.conf.dir")))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["x"]);

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn empty_mirror_matches_nothing() {
    let f = fs(&[]);
    assert!(!f.exists(Path::new("/")));
    assert!(block(f.dir_entries(Path::new("/"))).is_empty());
}

#[test]
fn empty_patterns_only_still_show_root() {
    let f = fs_with_empties(&[("/dev", Permission::Empty)]);
    assert!(f.exists(Path::new("/")));
    assert_eq!(
        block(f.dir_entries(Path::new("/")))
            .into_iter()
            .map(|(n, _)| n.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["dev"]
    );
}

#[test]
fn last_matching_pattern_wins() {
    // The later hide hides the file inside the mirrored tree...
    let f = fs(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Hide)]);
    assert!(f.exists(Path::new("/etc")));
    assert!(!f.exists(Path::new("/etc/passwd")));
    assert!(!f.matches(Path::new("/etc/passwd")));
    // ...and the reverse order shows *other* files under /etc again:
    // the last pattern that names a path decides. "/etc/passwd" is
    // still hidden (its own hide pattern is the only one naming it),
    // but a sibling is visible via the later recursive mirror.
    let f = fs(&[("/etc/passwd", Permission::Hide), ("/etc", Permission::Ro)]);
    assert!(!f.exists(Path::new("/etc/passwd")));
    assert!(f.exists(Path::new("/etc/hosts")));
}

#[test]
fn hidden_directories_hide_their_subtree() {
    let f = fs(&[
        ("/etc", Permission::Ro),
        ("/etc/passwd", Permission::Ro),
        ("/etc", Permission::Hide),
    ]);
    // The hide pattern matches /etc last and shadows everything below.
    assert!(!f.exists(Path::new("/etc")));
    assert!(!f.exists(Path::new("/etc/passwd")));
    assert!(block(f.dir_entries(Path::new("/"))).is_empty());
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
    assert!(f.exists(&base.join("foo.conf")));
    assert!(!f.exists(&base.join("secret")));
    // The parent stays navigable for the still-mirrored matches.
    assert!(f.exists(&base));
    let names: Vec<_> = block(f.dir_entries(&base))
        .into_iter()
        .map(|(n, _)| n.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["foo.conf"]);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn hidden_patterns_do_not_make_paths_navigable() {
    // Only a hide pattern: nothing appears, not even ancestor dirs.
    let f = fs(&[("/etc/passwd", Permission::Hide)]);
    assert!(!f.exists(Path::new("/")));
    assert!(!f.exists(Path::new("/etc")));
}

#[test]
fn write_permission_follows_the_last_pattern() {
    let f = fs(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Rw)]);
    assert!(matches!(
        f.write_permission(Path::new("/etc")),
        Some(Permission::Ro)
    ));
    assert!(matches!(
        f.write_permission(Path::new("/etc/passwd")),
        Some(Permission::Rw)
    ));
    assert!(!f.writable(Path::new("/etc")));
    assert!(f.writable(Path::new("/etc/passwd")));
    // The root is never writable.
    assert!(!f.writable(Path::new("/")));
}

#[test]
fn rw_directories_are_recursively_writable() {
    let f = fs(&[("/proj", Permission::Rw), ("/proj/secret", Permission::Ro)]);
    // Children of an exactly-named rw dir inherit its permission.
    assert!(f.writable(Path::new("/proj/newfile")));
    assert!(f.writable(Path::new("/proj/sub/x")));
    // The nearest mirrored ancestor decides: `ro` wins below /secret.
    assert!(!f.writable(Path::new("/proj/secret")));
    assert!(!f.writable(Path::new("/proj/secret/x")));
}

#[test]
fn wildcard_rw_patterns_allow_creating_matching_children() {
    let f = fs(&[("/out/*.txt", Permission::Rw)]);
    assert!(f.writable(Path::new("/out/a.txt")));
    assert!(!f.writable(Path::new("/out/a.conf")));
    // The parent dir itself is only a wildcard ancestor, not writable.
    assert!(!f.writable(Path::new("/out")));
}

#[test]
fn star_star_rw_covers_everything_below() {
    let f = fs(&[("/work/**", Permission::Rw)]);
    assert!(f.writable(Path::new("/work")));
    assert!(f.writable(Path::new("/work/a/b/c")));
}

#[test]
fn hide_and_empty_block_writes() {
    let f = fs(&[
        ("/a", Permission::Rw),
        ("/a/h", Permission::Hide),
        ("/a/e", Permission::Empty),
    ]);
    assert!(!f.writable(Path::new("/a/h/x")));
    assert!(!f.writable(Path::new("/a/e")));
    assert!(!f.writable(Path::new("/a/e/x")));
}

#[test]
fn writable_patterns_are_detected_for_the_mount_options() {
    assert!(!has_writable_patterns(&Patterns::new(vec![(
        "/etc".to_string(),
        Permission::Ro
    )])));
    assert!(has_writable_patterns(&Patterns::new(vec![
        ("/etc".to_string(), Permission::Ro),
        ("/tmp/x".to_string(), Permission::Rw),
    ])));
    assert!(!has_writable_patterns(&Patterns::new(vec![])));
}

#[test]
fn non_utf8_components_fail_closed_for_writes() {
    use std::os::unix::ffi::OsStrExt;
    // A non-UTF-8 component can never match a pattern, so its write
    // permission could never be derived from the spec: deny even
    // under a `**`-covered `rw` mirror that would allow a UTF-8 name.
    let f = fs(&[
        ("/work/**", Permission::Rw),
        ("/work/*secret*", Permission::Hide),
    ]);
    assert!(f.writable(Path::new("/work/plain")));
    let weird = Path::new("/work").join(OsStr::from_bytes(b"\xffsecret\xff"));
    assert!(!f.writable(&weird));
    assert!(!f.exists(&weird));
    // The UTF-8 spelling of the same name stays hidden.
    assert!(!f.writable(Path::new("/work/secret")));
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
