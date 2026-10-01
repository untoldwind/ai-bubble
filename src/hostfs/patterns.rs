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
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Patterns(pub Vec<(String, Permission)>);

impl Patterns {
    /// The pattern/permission pairs, in spec order.
    pub fn iter(&self) -> impl Iterator<Item = &(String, Permission)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
        // `*` must not cross directory separators, like in a shell.
        let compiled: Vec<(Pattern, &Permission)> = self
            .0
            .iter()
            .filter_map(|(pattern, permission)| Pattern::new(pattern).ok().map(|p| (p, permission)))
            .collect();
        let direct = |p: &Path| {
            compiled
                .iter()
                .rev()
                .find(|(pattern, _)| pattern.matches(p))
                .map(|(_, permission)| *permission)
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
        // unconditionally (`HostFs::hidden` checks every `hide` pattern,
        // naming the path itself or a strict ancestor, before any direct
        // permission), so the last-match rule below only applies among
        // the non-`hide` patterns.
        if compiled.iter().any(|(pattern, permission)| {
            **permission == Permission::Hide
                && (pattern.matches(path) || pattern.walk(path) == Walk::Ancestor)
        }) {
            return Some(&Permission::Hide);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_of_follows_hostfs_semantics() {
        // Direct matches: the last pattern naming the path decides.
        let patterns = Patterns(vec![
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
        let patterns = Patterns(vec![("/home/me/project".to_string(), Permission::Rw)]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/src/main.rs")),
            Some(&Permission::Rw)
        );
        // ...and the nearest mirrored ancestor wins over a farther one.
        let patterns = Patterns(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project".to_string(), Permission::Ro),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/src/main.rs")),
            Some(&Permission::Ro)
        );

        // A hidden directory hides its whole subtree.
        let patterns = Patterns(vec![
            ("/home/me".to_string(), Permission::Rw),
            ("/home/me/project/target".to_string(), Permission::Hide),
        ]);
        assert_eq!(
            patterns.permission_of(Path::new("/home/me/project/target/debug")),
            Some(&Permission::Hide)
        );

        // Everything strictly below an empty path is invisible.
        let patterns = Patterns(vec![
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
}
