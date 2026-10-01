use crate::hostfs::pattern::{Pattern, Walk};
use std::path::{Path, PathBuf};

/// The permission a hostfs pattern grants inside the sandbox: the
/// internal representation of a mapping's `type` (see
/// [`crate::spec::hostfs::Mapping`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// The matched paths are mirrored into the sandbox **read-only**: they can
    /// be read (and executed, when the underlying file or directory has the
    /// exec bits), but never modified.
    Ro,
    /// The matched paths are mirrored into the sandbox **read-write**: they can
    /// also be modified, created or deleted — as far as the underlying host
    /// file or directory really allows it (the real permissions apply).
    Rw,
    /// The matched paths are hidden. A hidden **directory** hides its
    /// whole subtree, too.
    Hide,
    /// The matched paths are exposed **empty**: as an empty, unwritable
    /// directory when the path is (or would be) a directory, or as an
    /// empty file when it matches a real file. Nothing below an empty
    /// path is visible. Meant as mount points inside the sandbox, e.g.
    /// `/dev`, `/tmp`, `/proc`.
    Empty,
    /// The matched paths are **redirected**: instead of showing the host
    /// content that lives at the path itself, the host path `source`
    /// (a single file or directory) is shown in its place — the FUSE
    /// equivalent of a bind mount, but routed through the host
    /// filesystem (and thus monitored with it). A redirected directory
    /// shows its whole subtree; everything the pattern names is mapped
    /// onto the source (the path itself maps to the source, and paths
    /// below it to the source plus the remaining path components).
    /// `writable` decides between redirect-ro and redirect-rw; as with
    /// plain mirrors, writes additionally require the real host
    /// permissions to allow them.
    Redirect { source: PathBuf, writable: bool },
    /// The matched path is a **purely virtual, in-memory file**: it has no
    /// counterpart on the host at all — its content (`content`) is served
    /// from the mirror's memory. Read-only by definition (a write to it
    /// would have nowhere to go), and nothing below it is visible: an
    /// injected path is always a regular file. Used to plant small
    /// configuration files (e.g. `/etc/resolv.conf` in waf mode) into the
    /// sandbox without any host-side trace.
    Inject { content: String },
}

impl Permission {
    /// Whether the permission mirrors real host content (`ro`, `rw` or
    /// a redirect).
    pub fn is_mirrored(&self) -> bool {
        matches!(
            self,
            Permission::Ro
                | Permission::Rw
                | Permission::Redirect { .. }
                | Permission::Inject { .. }
        )
    }

    /// Whether the permission additionally allows writing (`rw` and
    /// redirect-rw).
    pub fn is_writable(&self) -> bool {
        match self {
            Permission::Rw => true,
            Permission::Redirect { writable, .. } => *writable,
            _ => false,
        }
    }

    /// The host path the permission redirects to, if any.
    pub fn redirect_source(&self) -> Option<&Path> {
        match self {
            Permission::Redirect { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Permission::Ro => "ro",
            Permission::Rw => "rw",
            Permission::Hide => "hide",
            Permission::Empty => "empty",
            Permission::Redirect { writable, .. } if *writable => "redirect-rw",
            Permission::Redirect { .. } => "redirect-ro",
            Permission::Inject { .. } => "inject",
        })
    }
}

/// The internal `hostfs` representation: an *ordered* list of
/// (glob pattern, permission) pairs — the compiled-down form of the
/// spec's [`crate::spec::hostfs::Mapping`] list. That order matters: when
/// a path matches several patterns, the **last** matching pattern decides.
///
/// The globs are compiled once, at construction ([`Patterns::new`]): an
/// invalid pattern is a hard error there, not a silently ignored entry.
/// The type is opaque — permission questions go through
/// [`Patterns::permission_of`]; the compiled patterns stay inside.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Patterns {
    patterns: Vec<(Pattern, Permission)>,
}

impl Patterns {
    /// Compile the pattern → permission list. Invalid patterns are a hard
    /// error: a spec that cannot be compiled must not run at all.
    pub fn new(patterns: Vec<(String, Permission)>) -> Patterns {
        Patterns {
            patterns: patterns
                .into_iter()
                .map(|(pattern, permission)| {
                    let compiled = Pattern::new(&pattern).unwrap_or_else(|e| {
                        crate::sandbox::die(&format!("Invalid hostfs pattern: {e}"))
                    });
                    (compiled, permission)
                })
                .collect(),
        }
    }

    /// Whether the pattern list is non-empty (at least one hostfs mapping).
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Whether any pattern grants write access: the FUSE mount is mounted
    /// read-only unless it does.
    pub fn any_writable(&self) -> bool {
        self.patterns
            .iter()
            .any(|(_, permission)| permission.is_writable())
    }

    /// The permission governing the path in the sandbox: the single source
    /// of permission decisions — the spec side (`ls`' annotation) and the
    /// running FUSE mirror (the `HostFs` filesystem in `hostfs/mod.rs`)
    /// use it alike. In order:
    ///
    /// * everything strictly below an `empty` or `inject` path is invisible —
    ///   an empty path is meant to be covered by a mount inside the sandbox
    ///   and an injected path is a virtual file, so neither has content below
    ///   it (`None`),
    /// * a `hide` pattern naming the path itself or a strict ancestor wins
    ///   over everything else — a hidden path is not visible, no matter
    ///   which pattern comes last (`hide`),
    /// * otherwise the **last** pattern naming the path itself decides —
    ///   including `empty` and `inject`,
    /// * otherwise the permission of the **nearest** mirrored (`ro`/`rw`/
    ///   redirect) ancestor is inherited: an exactly-named or `**`-covered
    ///   directory is a recursive mirror, so its permission governs
    ///   everything below,
    /// * otherwise the path is not visible in the sandbox at all (`None`).
    pub fn permission_of(&self, path: &Path) -> Option<&Permission> {
        let direct = |p: &Path| {
            self.patterns
                .iter()
                .rev()
                .find(|(pattern, _)| pattern.matches(p))
                .map(|(_, permission)| permission)
        };
        // Everything strictly below an empty or an injected path is
        // invisible: an empty path is covered by a mount inside the
        // sandbox, an injected path is a virtual file — neither has
        // content below it, whatever pattern matches below.
        if path.ancestors().skip(1).any(|a| {
            matches!(
                direct(a),
                Some(Permission::Empty) | Some(Permission::Inject { .. })
            )
        }) {
            return None;
        }
        // A hidden path is never visible — the mirror enforces this
        // unconditionally (`Patterns::hidden` checks every `hide` pattern,
        // naming the path itself or a strict ancestor, before any direct
        // permission), so the last-match rule below only applies among
        // the non-`hide` patterns.
        if let Some((_, permission)) = self.patterns.iter().find(|(pattern, permission)| {
            *permission == Permission::Hide
                && (pattern.matches(path) || pattern.walk(path) == Walk::Ancestor)
        }) {
            return Some(permission);
        }
        // The last pattern naming the path itself decides.
        if let Some(permission) = direct(path) {
            return Some(permission);
        }
        // Otherwise the nearest mirrored ancestor governs: the mirror is
        // recursive, so its permission extends to everything below it.
        path.ancestors()
            .skip(1)
            .find_map(|a| direct(a).filter(|p| p.is_mirrored()))
    }

    /// Whether the mirrored path is matched with the `empty` permission (by
    /// the last pattern naming it): it is exposed empty — as an empty
    /// directory when it is (or would be) a directory, an empty file when
    /// it matches a real file.
    pub fn is_empty(&self, mirrored: &Path) -> bool {
        matches!(self.permission_of(mirrored), Some(Permission::Empty))
    }

    /// The in-memory content of the mirrored path when it is matched with
    /// the `inject` permission (by the last pattern naming it): the path
    /// is a purely virtual file served from the mirror's memory, with no
    /// host counterpart at all. Borrowed: this is consulted on every
    /// operation touching the path.
    pub fn is_inject(&self, mirrored: &Path) -> Option<&str> {
        match self.permission_of(mirrored) {
            Some(Permission::Inject { content }) => Some(content.as_str()),
            _ => None,
        }
    }

    /// Whether the mirrored path lies strictly *below* an empty path (so it is
    /// shadowed by the empty path's precedence and never visible).
    pub fn under_empty(&self, mirrored: &Path) -> bool {
        mirrored.ancestors().skip(1).any(|a| self.is_empty(a))
    }

    /// The spec-level permission governing the mirrored path: the shared
    /// semantics of [`Patterns::permission_of`] — with one deliberate
    /// fail-closed exception: a path with a non-UTF-8 component can never
    /// match a pattern, so its permission could never be derived from the
    /// spec — a hidden name spelled with invalid UTF-8 bytes must not
    /// become visible or writable (or creatable) through the mirror.
    fn effective(&self, mirrored: &Path) -> Option<&Permission> {
        if Pattern::has_non_utf8_component(mirrored) {
            return None;
        }
        self.permission_of(mirrored)
    }

    /// Whether a mirrored path matches one of the patterns directly (as a file,
    /// symlink, or a directory named by the pattern itself), with the
    /// **last** matching pattern mirroring it. Empty paths and everything
    /// below them take precedence over the mirror.
    pub fn matches(&self, mirrored: &Path) -> bool {
        matches!(self.effective(mirrored), Some(p) if p.is_mirrored())
    }

    /// The spec-level permission that governs **writing** to the mirrored path
    /// (modifying its content or metadata, creating or deleting it): the
    /// last pattern naming the path itself decides, or — when no pattern
    /// names it directly — the permission of the *nearest* mirrored
    /// ancestor (an exactly-named or `**`-covered directory is a recursive
    /// mirror, so its permission governs everything below it). Empty paths
    /// and hidden paths are never writable.
    ///
    /// The result is only the *spec* side: the real host filesystem may
    /// still deny the operation (the server acts with the real host
    /// credentials, so the underlying file or directory permissions apply).
    pub fn write_permission(&self, mirrored: &Path) -> Option<&Permission> {
        match self.effective(mirrored) {
            Some(p) if p.is_mirrored() => Some(p),
            _ => None,
        }
    }

    /// Whether writes to the mirrored path are allowed: the spec must say `rw`.
    /// (Whether the *real* file or directory actually allows it is decided
    /// by the host filesystem when the operation is performed.)
    pub fn writable(&self, mirrored: &Path) -> bool {
        self.write_permission(mirrored)
            .is_some_and(|p| p.is_writable())
    }

    /// Whether the mirrored path exists at all: it either is mirrored
    /// by the last matching pattern itself, is empty (an empty dir or
    /// empty file), is an ancestor of something that is (so the tree under
    /// `/host` stays navigable down to the matched leaves), or is an
    /// ancestor leading to an empty path — and nothing hides it directly
    /// or via an ancestor.
    pub fn exists(&self, mirrored: &Path) -> bool {
        if self.under_empty(mirrored) {
            return false;
        }
        if self.is_empty(mirrored) {
            return true;
        }
        if self.is_inject(mirrored).is_some() {
            return true;
        }
        if self.hidden(mirrored) {
            return false;
        }
        self.matches(mirrored) || self.dir_prefix(mirrored) || self.is_empty_prefix(mirrored)
    }

    /// Whether the path is hidden because a pattern hides it directly, or
    /// a hidden pattern names one of its strict ancestors (a hidden
    /// directory hides its whole subtree).
    pub fn hidden(&self, mirrored: &Path) -> bool {
        self.patterns.iter().any(|(pattern, permission)| {
            *permission == Permission::Hide
                && (pattern.matches(mirrored) || pattern.walk(mirrored) == Walk::Ancestor)
        })
    }

    /// Whether some `empty` pattern could still match something *strictly
    /// below* the given path — i.e. the path acts as a (possibly purely
    /// virtual) directory leading to empty paths, and must stay navigable
    /// even when the mirror knows nothing about it.
    pub fn is_empty_prefix(&self, mirrored: &Path) -> bool {
        self.patterns.iter().any(|(pattern, permission)| {
            *permission == Permission::Empty && self.pattern_reaches(pattern, mirrored)
        })
    }

    /// Whether some `inject` pattern could still match something *strictly
    /// below* the given path — i.e. the path acts as a (possibly purely
    /// virtual) directory leading to injected files, and must stay
    /// navigable (and listable) even when the mirror knows nothing about
    /// it otherwise.
    pub fn is_inject_prefix(&self, mirrored: &Path) -> bool {
        self.patterns.iter().any(|(pattern, permission)| {
            matches!(permission, Permission::Inject { .. })
                && pattern.walk(mirrored) == Walk::CouldReach
        })
    }

    /// Whether some **mirrored** pattern could still match something
    /// *strictly below* the given path — i.e. the path acts as a
    /// (possibly virtual) directory of the mirror, leading to matches
    /// deeper down. Denied patterns never make a path navigable.
    pub fn dir_prefix(&self, mirrored: &Path) -> bool {
        if mirrored == Path::new("/") {
            return self.patterns.iter().any(|(_, permission)| {
                matches!(
                    permission,
                    Permission::Ro | Permission::Rw | Permission::Empty | Permission::Inject { .. }
                )
            });
        }
        self.patterns
            .iter()
            .any(|(pattern, permission)| match permission {
                // An injected pattern is an exact file: only paths
                // *strictly above* it (CouldReach) are navigable as its
                // virtual parent directories — a path below the injected
                // file (Ancestor) exists just as little as the file's
                // non-existent children.
                Permission::Inject { .. } => pattern.walk(mirrored) == Walk::CouldReach,
                _ => permission.is_mirrored() && self.pattern_reaches(pattern, mirrored),
            })
            || self.is_empty_prefix(mirrored)
    }

    /// The **real host path** the given **mirrored path** resolves to:
    /// the mirrored path itself — unless a redirect permission remaps it.
    /// The **last** pattern
    /// naming the path decides (as everywhere else); when no pattern names
    /// the path itself, the nearest *directly matched* mirrored ancestor
    /// does: a redirected directory shows its whole subtree, so everything
    /// below it is remapped onto the source plus the remaining path
    /// components. Redirects only ever map literal paths, so the remap is a
    /// simple prefix replacement.
    pub fn redirect(&self, mirrored: &Path) -> PathBuf {
        let direct = |p: &Path| {
            self.patterns
                .iter()
                .rev()
                .find(|(pattern, _)| pattern.matches(p))
        };
        // The path itself: the last matching pattern says whether (and
        // where) it is redirected.
        if let Some((_, permission)) = direct(mirrored) {
            if let Some(source) = permission.redirect_source() {
                return source.to_path_buf();
            }
            return mirrored.to_path_buf();
        }
        // Otherwise the nearest directly matched mirrored ancestor decides
        // (the mirror is recursive, so its redirect extends to everything
        // below it). Non-mirrored ancestors are skipped, exactly like in
        // `permission_of`.
        for ancestor in mirrored.ancestors().skip(1) {
            if let Some((_, permission)) = direct(ancestor)
                && permission.is_mirrored()
            {
                if let Some(source) = permission.redirect_source()
                    && let Ok(rest) = mirrored.strip_prefix(ancestor)
                {
                    return source.join(rest);
                }
                return mirrored.to_path_buf();
            }
        }
        mirrored.to_path_buf()
    }

    /// Whether some `hide` or `ro` pattern might apply to a path strictly
    /// below the given directory — without being uniformly shadowed there
    /// by a writable pattern that covers the whole subtree.
    ///
    /// This is the rename-restriction check: a directory rename carries
    /// every child from one pattern context to another, so a `hide` or
    /// `ro` rule that might govern a child must block the move — moving
    /// the directory out of such a rule's reach would expose (or make
    /// writable) content that the spec hides or keeps read-only, and
    /// moving *into* such a subtree would plant content that a later
    /// move back out could expose the same way. Checked for both the
    /// source and the destination of a directory rename.
    pub fn subtree_restricted(&self, dir: &Path) -> bool {
        for (idx, (pattern, permission)) in self.patterns.iter().enumerate() {
            if !matches!(permission, Permission::Ro | Permission::Hide) {
                continue;
            }
            let Some((walk, depth)) = pattern.walk_depth(dir) else {
                continue;
            };
            // How the pattern might govern a strictly-below path:
            //
            // * `StarStar`/`CouldReach`: the pattern matches — or could
            //   match — paths below the directory *directly*, so the
            //   last-match rule applies and only a **later** pattern
            //   naming every possible child can shadow it (`**` covers
            //   the directory and everything below it).
            // * `Exact`: the pattern names the directory itself — a `hide`
            //   hides the whole subtree (never shadowable), an `ro` mirror
            //   is recursive, so its permission reaches every child.
            // * `Ancestor`: the pattern names a strict ancestor — it
            //   governs children only through the hide-ancestor rule
            //   (`hide`, never shadowable) or the nearest-mirrored-
            //   ancestor fallback (`ro`), which a *deeper* mirrored
            //   writable ancestor replaces regardless of list order.
            let shadowed = if matches!(walk, Walk::StarStar | Walk::CouldReach) {
                self.patterns[idx + 1..].iter().any(|(q, q_permission)| {
                    q_permission.is_writable() && matches!(q.walk(dir), Walk::StarStar)
                })
            } else if walk == Walk::Exact {
                // The last pattern naming the directory itself decides
                // the children's fallback permission; a writable one
                // replaces the `ro` (a `hide` there would have hidden
                // the directory, and the rename is rejected before this
                // check even runs).
                self.patterns[idx + 1..]
                    .iter()
                    .rev()
                    .find(|(q, _)| q.matches(dir))
                    .is_some_and(|(_, q)| q.is_writable())
            } else {
                // Walk::Ancestor: any writable mirrored pattern that
                // covers the directory itself (or reaches deeper than
                // this pattern does) is the nearer mirrored ancestor of
                // every child.
                self.patterns.iter().any(|(q, q_permission)| {
                    q_permission.is_writable()
                        && q.walk_depth(dir).is_some_and(|(w, d)| match w {
                            Walk::StarStar | Walk::Exact => true,
                            Walk::Ancestor => d > depth,
                            Walk::CouldReach | Walk::Fail => false,
                        })
                })
            };
            if !shadowed {
                return true;
            }
        }
        false
    }

    /// The path components the patterns could name **directly** below the
    /// given directory with a purely literal next component — the virtual
    /// directory entries the real host directory cannot provide: `empty`
    /// paths, injected files and redirect destinations. Deduplicated, in
    /// pattern order. The mirror still decides visibility (it checks the
    /// child's existence and, for redirects, whether the target is there).
    pub fn virtual_children(&self, dir: &Path) -> Vec<(String, &Permission)> {
        let mut out = Vec::new();
        for (pattern, permission) in &self.patterns {
            if !matches!(
                permission,
                Permission::Empty | Permission::Inject { .. } | Permission::Redirect { .. }
            ) {
                continue;
            }
            if let Some(name) = pattern.next_literal(dir)
                && out.iter().all(|(n, _)| *n != name)
            {
                out.push((name, permission));
            }
        }
        out
    }

    /// Whether the pattern could make the path visible as a directory
    /// leading to content: it has components left after the path is
    /// consumed, or the path hit (or ends at) a `**`, or the pattern names
    /// a strict ancestor of the path — an exactly-named directory is
    /// mirrored recursively, so everything below it is visible.
    fn pattern_reaches(&self, pattern: &Pattern, mirrored: &Path) -> bool {
        matches!(
            pattern.walk(mirrored),
            Walk::CouldReach | Walk::StarStar | Walk::Ancestor
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_of_follows_hostfs_semantics() {
        // Direct matches: the last pattern naming the path decides.
        let patterns = Patterns::new(vec![
            ("/etc".to_string(), Permission::Ro),
            ("/etc/*.conf".to_string(), Permission::Rw),
            ("/etc/passwd".to_string(), Permission::Hide),
            ("/dev".to_string(), Permission::Empty),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/etc")),
            Some(&Permission::Ro)
        );
        assert_eq!(
            patterns.permission_of(Path::new("/etc/hosts.conf")),
            Some(&Permission::Rw)
        );
        assert_eq!(
            patterns.permission_of(Path::new("/etc/passwd")),
            Some(&Permission::Hide)
        );
        assert_eq!(
            patterns.permission_of(Path::new("/dev")),
            Some(&Permission::Empty)
        );

        // No direct match: mirrored directories are recursive, so their
        // permission is inherited by everything below them.
        let patterns = Patterns::new(vec![("/home/me/project".to_string(), Permission::Rw)]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/src/main.rs")),
            Some(&Permission::Rw)
        );
        // ...and the nearest mirrored ancestor wins over a farther one.
        let patterns = Patterns::new(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project".to_string(), Permission::Ro),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/src/main.rs")),
            Some(&Permission::Ro)
        );

        // A hidden directory hides its whole subtree.
        let patterns = Patterns::new(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project/target".to_string(), Permission::Hide),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/target/debug")),
            Some(&Permission::Hide)
        );

        // Everything strictly below an empty path is invisible.
        let patterns = Patterns::new(vec![
            ("/etc".to_string(), Permission::Ro),
            ("/dev".to_string(), Permission::Empty),
        ]);
        assert_eq!(patterns.permission_of(Path::new("/dev/null")), None);
        // Unrelated paths stay invisible, too.
        assert_eq!(patterns.permission_of(Path::new("/opt")), None);
    }

    #[test]
    fn spec_dir_is_always_hidden() {
        use crate::spec::hostfs::Mapping;
        use std::path::Path;

        // A spec that mirrors everything — including the directory the
        // spec file lives in.
        let parent =
            std::env::temp_dir().join(format!("ai-bubble-spec-hide-{}", std::process::id()));
        let dir = parent.join(".ai-bubble");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(crate::spec::file::SPEC_FILE),
            r#"{ "hostfs": { "mappings": [ { "type": "rw", "glob": "/**" } ] } }"#,
        )
        .unwrap();
        let spec = crate::spec::Spec::load(Some(&dir));

        // Loading appends a hide mapping for the spec directory.
        match spec.hostfs.mappings.last() {
            Some(Mapping::Hide { glob }) => {
                let [glob] = &glob.0[..] else {
                    panic!("expected a single glob")
                };
                assert_eq!(Path::new(glob), std::fs::canonicalize(&dir).unwrap())
            }
            other => panic!("expected a trailing hide mapping, got {other:?}"),
        }
        // The hide wins over the earlier rw mapping: the directory and
        // everything below it are invisible — also in the compiled config
        // the sandbox machinery runs with.
        let spec_path = std::fs::canonicalize(&dir).unwrap();
        let compiled = crate::spec::internal::SandboxConfig::compile(&spec);
        for patterns in [&spec.hostfs.patterns(), &compiled.patterns] {
            assert_eq!(patterns.permission_of(&spec_path), Some(&Permission::Hide));
            assert_eq!(
                patterns.permission_of(&spec_path.join("spec.json")),
                Some(&Permission::Hide)
            );
            assert_eq!(
                patterns.permission_of(&spec_path.join("cache/deep/file")),
                Some(&Permission::Hide)
            );
        }
        // But paths outside the spec directory stay visible.
        assert_eq!(
            compiled.patterns.permission_of(Path::new("/etc/passwd")),
            Some(&Permission::Rw)
        );
        std::fs::remove_dir_all(&parent).ok();
    }

    /// A `Patterns` from (pattern, permission) pairs, like the mirror's
    /// spec lists — but without involving the FUSE filesystem.
    fn ps(entries: &[(&str, Permission)]) -> Patterns {
        Patterns::new(
            entries
                .iter()
                .map(|(p, perm)| (p.to_string(), perm.clone()))
                .collect(),
        )
    }

    #[test]
    fn redirect_resolves_to_the_source_path() {
        let patterns = ps(&[
            (
                "/bla",
                Permission::Redirect {
                    source: PathBuf::from("/otherdir"),
                    writable: false,
                },
            ),
            ("/etc/passwd", Permission::Ro),
        ]);

        // The redirect destination maps exactly onto the source.
        assert_eq!(
            patterns.redirect(Path::new("/bla")),
            PathBuf::from("/otherdir")
        );
        // ...and everything below it onto the source plus the rest.
        assert_eq!(
            patterns.redirect(Path::new("/bla/sub/file.txt")),
            PathBuf::from("/otherdir/sub/file.txt")
        );
        // Non-redirected paths resolve to themselves.
        assert_eq!(
            patterns.redirect(Path::new("/etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        assert_eq!(patterns.redirect(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn redirect_obeys_last_match_wins() {
        // A later plain mapping naming the redirected path (or something
        // below it) wins over the redirect, like with every mapping.
        let patterns = ps(&[
            (
                "/bla",
                Permission::Redirect {
                    source: PathBuf::from("/otherdir"),
                    writable: false,
                },
            ),
            ("/bla/plain", Permission::Ro),
        ]);
        // /bla itself is still redirected...
        assert_eq!(
            patterns.redirect(Path::new("/bla")),
            PathBuf::from("/otherdir")
        );
        // ...but /bla/plain is mirrored plainly (its own last match), and
        // /bla/plain/x inherits the *plain* mirror, not the redirect.
        assert_eq!(
            patterns.redirect(Path::new("/bla/plain")),
            PathBuf::from("/bla/plain")
        );
        assert_eq!(
            patterns.redirect(Path::new("/bla/plain/x")),
            PathBuf::from("/bla/plain/x")
        );
        // Everything else below /bla follows the redirect.
        assert_eq!(
            patterns.redirect(Path::new("/bla/other/x")),
            PathBuf::from("/otherdir/other/x")
        );
    }

    #[test]
    fn restricted_subtrees_block_directory_renames() {
        // The motivating case: `/project/src` is rw, but a followup hide
        // glob might apply to one of its children — the directory must
        // not be renamable (out of, or into, its pattern context).
        let patterns = ps(&[
            ("/project/src", Permission::Rw),
            ("/project/src/**/*.bin", Permission::Hide),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/project/src")),
            Some(&Permission::Rw)
        );
        assert!(patterns.subtree_restricted(Path::new("/project/src")));
        // Moving some other directory to /project/src is restricted, too:
        // the *destination* subtree carries the hide rule.
        assert!(patterns.subtree_restricted(Path::new("/project/src")));
        assert!(!patterns.subtree_restricted(Path::new("/elsewhere")));
        // Unrelated directories are not restricted.
        assert!(!patterns.subtree_restricted(Path::new("/other/place")));

        // The same holds for an ro glob below a writable directory.
        let patterns = ps(&[
            ("/project/src", Permission::Rw),
            ("/project/src/**/*.bin", Permission::Ro),
        ]);
        assert!(patterns.subtree_restricted(Path::new("/project/src")));

        // An exactly-named ro directory is a recursive mirror: its
        // children are read-only, so it must not be renamable either.
        let patterns = ps(&[
            ("/project", Permission::Rw),
            ("/project/src", Permission::Ro),
        ]);
        assert!(patterns.subtree_restricted(Path::new("/project/src")));
        // ...and the writable parent is restricted, too: the ro child
        // (and its subtree) would travel with the rename.
        assert!(patterns.subtree_restricted(Path::new("/project")));
        // A sibling subtree without the ro rule inside stays free.
        assert!(!patterns.subtree_restricted(Path::new("/project/other")));
    }

    #[test]
    fn a_writable_recursive_mirror_shadows_ro_ancestors() {
        // A broad ro pattern above a deeper rw mirror: the rw mirror is
        // the nearer mirrored ancestor of everything below it, so the ro
        // pattern never governs the children — renames inside stay free.
        let patterns = ps(&[("/", Permission::Ro), ("/home/me/work", Permission::Rw)]);
        assert!(!patterns.subtree_restricted(Path::new("/home/me/work/sub")));
        // Outside the rw mirror the ro ancestor still governs.
        assert!(patterns.subtree_restricted(Path::new("/home/elsewhere")));

        // A `**` rw pattern shadows equally (it names every child).
        let patterns = ps(&[("/home", Permission::Ro), ("/home/me/**", Permission::Rw)]);
        assert!(!patterns.subtree_restricted(Path::new("/home/me/work")));
        // ...but only from below the `**`: /home itself is still ro-governed.
        assert!(patterns.subtree_restricted(Path::new("/home/other")));

        // Shadowing needs the shadowing pattern to come *after* the
        // restrictive one: here the later ro re-restricts the subtree.
        let patterns = ps(&[
            ("/home", Permission::Ro),
            ("/home/me/**", Permission::Rw),
            ("/home/me/work/*.key", Permission::Ro),
        ]);
        assert!(patterns.subtree_restricted(Path::new("/home/me/work")));
    }

    #[test]
    fn an_rw_dir_named_after_the_ro_rule_shadows_it() {
        // The ro pattern names the directory itself; a later rw pattern
        // naming it too hands the children's fallback permission to the
        // writable mirror — renames stay allowed.
        let patterns = ps(&[
            ("/project/src", Permission::Ro),
            ("/project/src", Permission::Rw),
        ]);
        assert!(!patterns.subtree_restricted(Path::new("/project/src")));
        // Without the later rw, the ro governs: restricted.
        let patterns = ps(&[("/project/src", Permission::Ro)]);
        assert!(patterns.subtree_restricted(Path::new("/project/src")));
    }

    #[test]
    fn hidden_directories_are_always_restricted_subtrees() {
        let patterns = ps(&[("/project/src", Permission::Hide)]);
        assert!(patterns.subtree_restricted(Path::new("/project/src")));
        assert!(patterns.subtree_restricted(Path::new("/project")));
        assert!(!patterns.subtree_restricted(Path::new("/other")));
    }

    #[test]
    fn pattern_matching_per_operation() {
        let patterns = ps(&[
            ("/etc/*.conf", Permission::Ro),
            ("/home/me/project", Permission::Ro),
        ]);

        // Direct matches.
        assert!(patterns.matches(Path::new("/etc/foo.conf")));
        assert!(patterns.matches(Path::new("/home/me/project")));
        assert!(!patterns.matches(Path::new("/etc/passwd")));

        // exists: matches plus ancestor directories.
        assert!(patterns.exists(Path::new("/etc/foo.conf")));
        assert!(patterns.exists(Path::new("/etc"))); // ancestor of a match
        assert!(patterns.exists(Path::new("/"))); // root
        assert!(patterns.exists(Path::new("/home/me/project")));
        assert!(!patterns.exists(Path::new("/etc/passwd")));
        assert!(!patterns.exists(Path::new("/etc/nothing")));

        // dir_prefix: only true for ancestors of matches — an exactly
        // matched path (file or recursively mirrored directory) is not a
        // prefix itself.
        assert!(patterns.dir_prefix(Path::new("/etc")));
        assert!(patterns.dir_prefix(Path::new("/home")));
        assert!(patterns.dir_prefix(Path::new("/home/me")));
        assert!(!patterns.dir_prefix(Path::new("/home/me/project")));
        assert!(!patterns.dir_prefix(Path::new("/etc/passwd")));
        assert!(!patterns.dir_prefix(Path::new("/etc/foo.conf")));
    }

    #[test]
    fn double_star_spans_directories() {
        let patterns = ps(&[("/usr/share/**/*.rs", Permission::Ro)]);
        assert!(patterns.exists(Path::new("/usr/share")));
        assert!(patterns.dir_prefix(Path::new("/usr/share/doc")));
        assert!(patterns.matches(Path::new("/usr/share/doc/x/y.rs")));
        assert!(!patterns.matches(Path::new("/usr/share/doc/x/y.c")));
    }

    #[test]
    fn last_matching_pattern_wins() {
        // The later hide hides the file inside the mirrored tree...
        let patterns = ps(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Hide)]);
        assert!(patterns.exists(Path::new("/etc")));
        assert!(!patterns.exists(Path::new("/etc/passwd")));
        assert!(!patterns.matches(Path::new("/etc/passwd")));
        // ...and the reverse order shows *other* files under /etc again:
        // the last pattern that names a path decides. "/etc/passwd" is
        // still hidden (its own hide pattern is the only one naming it),
        // but a sibling is visible via the later recursive mirror.
        let patterns = ps(&[("/etc/passwd", Permission::Hide), ("/etc", Permission::Ro)]);
        assert!(!patterns.exists(Path::new("/etc/passwd")));
        assert!(patterns.exists(Path::new("/etc/hosts")));
    }

    #[test]
    fn hidden_patterns_do_not_make_paths_navigable() {
        // Only a hide pattern: nothing appears, not even ancestor dirs.
        let patterns = ps(&[("/etc/passwd", Permission::Hide)]);
        assert!(!patterns.exists(Path::new("/")));
        assert!(!patterns.exists(Path::new("/etc")));
    }

    #[test]
    fn write_permission_follows_the_last_pattern() {
        let patterns = ps(&[("/etc", Permission::Ro), ("/etc/passwd", Permission::Rw)]);
        assert!(matches!(
            patterns.write_permission(Path::new("/etc")),
            Some(Permission::Ro)
        ));
        assert!(matches!(
            patterns.write_permission(Path::new("/etc/passwd")),
            Some(Permission::Rw)
        ));
        assert!(!patterns.writable(Path::new("/etc")));
        assert!(patterns.writable(Path::new("/etc/passwd")));
        // The root is never writable.
        assert!(!patterns.writable(Path::new("/")));
    }

    #[test]
    fn rw_directories_are_recursively_writable() {
        let patterns = ps(&[("/proj", Permission::Rw), ("/proj/secret", Permission::Ro)]);
        // Children of an exactly-named rw dir inherit its permission.
        assert!(patterns.writable(Path::new("/proj/newfile")));
        assert!(patterns.writable(Path::new("/proj/sub/x")));
        // The nearest mirrored ancestor decides: `ro` wins below /secret.
        assert!(!patterns.writable(Path::new("/proj/secret")));
        assert!(!patterns.writable(Path::new("/proj/secret/x")));
    }

    #[test]
    fn wildcard_rw_patterns_allow_creating_matching_children() {
        let patterns = ps(&[("/out/*.txt", Permission::Rw)]);
        assert!(patterns.writable(Path::new("/out/a.txt")));
        assert!(!patterns.writable(Path::new("/out/a.conf")));
        // The parent dir itself is only a wildcard ancestor, not writable.
        assert!(!patterns.writable(Path::new("/out")));
    }

    #[test]
    fn star_star_rw_covers_everything_below() {
        let patterns = ps(&[("/work/**", Permission::Rw)]);
        assert!(patterns.writable(Path::new("/work")));
        assert!(patterns.writable(Path::new("/work/a/b/c")));
    }

    #[test]
    fn hide_and_empty_block_writes() {
        let patterns = ps(&[
            ("/a", Permission::Rw),
            ("/a/h", Permission::Hide),
            ("/a/e", Permission::Empty),
        ]);
        assert!(!patterns.writable(Path::new("/a/h/x")));
        assert!(!patterns.writable(Path::new("/a/e")));
        assert!(!patterns.writable(Path::new("/a/e/x")));
    }

    #[test]
    fn redirect_rw_is_writable_and_ro_is_not() {
        let ro = ps(&[(
            "/a",
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: false,
            },
        )]);
        let rw = ps(&[(
            "/a",
            Permission::Redirect {
                source: PathBuf::from("/x"),
                writable: true,
            },
        )]);
        assert!(!ro.writable(Path::new("/a/f")));
        assert!(!ro.any_writable());
        assert!(rw.writable(Path::new("/a/f")));
        assert!(rw.any_writable());
    }

    #[test]
    fn writable_patterns_are_detected_for_the_mount_options() {
        assert!(!ps(&[("/etc", Permission::Ro)]).any_writable());
        assert!(ps(&[("/etc", Permission::Ro), ("/tmp/x", Permission::Rw),]).any_writable());
        let empty = ps(&[]);
        assert!(!empty.any_writable());
        assert!(!empty.has_patterns());
    }

    #[test]
    fn non_utf8_components_fail_closed_for_writes() {
        use std::os::unix::ffi::OsStrExt;
        // A non-UTF-8 component can never match a pattern, so its write
        // permission could never be derived from the spec: deny even
        // under a `**`-covered `rw` mirror that would allow a UTF-8 name.
        let patterns = ps(&[
            ("/work/**", Permission::Rw),
            ("/work/*secret*", Permission::Hide),
        ]);
        assert!(patterns.writable(Path::new("/work/plain")));
        let weird = Path::new("/work").join(std::ffi::OsStr::from_bytes(b"\xffsecret\xff"));
        assert!(!patterns.writable(&weird));
        assert!(!patterns.exists(&weird));
        // The UTF-8 spelling of the same name stays hidden.
        assert!(!patterns.writable(Path::new("/work/secret")));
    }
}
