//! The `hostfs` section of the spec file: what the FUSE filesystem —
//! which is always the sandbox root — exposes of the host.
//!
//! This is only the *spec-file* view: [`HostFsConfig::patterns`] maps it
//! onto the internal [`Patterns`] representation the FUSE filesystem
//! itself works with.

use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

use schemars::JsonSchema;

use super::op::Op;
use super::TmpfsPerms;

/// What happens to a path matched by one of the mirror patterns
/// (the internal representation of a mapping's `type`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
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
}

impl Permission {
    /// Whether the permission mirrors real host content (`ro` or `rw`).
    pub fn is_mirrored(self) -> bool {
        matches!(self, Permission::Ro | Permission::Rw)
    }

    /// Whether the permission additionally allows writing (`rw` only).
    pub fn is_writable(self) -> bool {
        self == Permission::Rw
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Permission::Ro => "ro",
            Permission::Rw => "rw",
            Permission::Hide => "hide",
            Permission::Empty => "empty",
        })
    }
}

/// The spec's `hostfs.mappings` setting: an *ordered* list of mappings,
/// each selecting host paths for one treatment.
///
/// A `ro`, `rw` or `hide` mapping selects paths with a **glob** pattern of
/// absolute host paths; every other mapping names a single absolute host
/// **path** exactly (it makes no sense to glob a mount point). The `dev`
/// and `proc` mappings default their path to `/dev` and `/proc`.
/// The list order matters: when a path matches several mappings, the
/// **last** matching mapping decides.
///
/// The mount-point mappings (`dev`, `tmpfs`, `proc`, `bind`) are
/// shorthand for an `empty` mapping *plus* the corresponding mount op
/// (see [`Mapping::op`]): the FUSE filesystem exposes the path empty so
/// it can be mounted on, and the sandbox stacks the real mount on top of
/// it.
#[derive(Debug, Clone, PartialEq, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Mapping {
    /// The matched paths are mirrored **read-only**.
    Ro {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`).
        glob: String,
    },
    /// The matched paths are mirrored **read-write** (as far as the real
    /// host permissions allow).
    Rw {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`).
        glob: String,
    },
    /// The matched paths are hidden (a hidden directory hides its whole
    /// subtree).
    Hide {
        /// A glob pattern of absolute host paths (`*`, `?`, `[...]`, `**`).
        glob: String,
    },
    /// The named path is exposed **empty** — a mount point for the
    /// sandbox's ops.
    Empty {
        /// An absolute host path, named exactly (no wildcards).
        path: String,
    },
    /// Shorthand for `empty` at `path` **plus** a minimal `/dev` mount
    /// (like bwrap's `--dev`) on top of it. `path` defaults to `/dev`.
    Dev {
        /// An absolute host path, named exactly (no wildcards).
        #[serde(default = "default_dev_path")]
        path: String,
    },
    /// Shorthand for `empty` at `path` **plus** a fresh tmpfs (like
    /// bwrap's `--tmpfs`) on top of it.
    Tmpfs {
        /// An absolute host path, named exactly (no wildcards).
        path: String,
        /// Octal mode of the tmpfs root, e.g. `"1777"` or `1777`.
        /// Default: `0755`.
        perms: Option<TmpfsPerms>,
        /// Maximum tmpfs size in bytes.
        size: Option<u64>,
    },
    /// Shorthand for `empty` at `path` **plus** a fresh procfs instance
    /// (showing only the sandbox's own processes) on top of it. `path`
    /// defaults to `/proc`.
    Proc {
        /// An absolute host path, named exactly (no wildcards).
        #[serde(default = "default_proc_path")]
        path: String,
    },
    /// Shorthand for `empty` at `path` **plus** a bind mount of the real
    /// host path at the same path on top of it.
    Bind {
        /// An absolute host path, named exactly (no wildcards).
        path: String,
    },
}

/// The default path of the `dev` mapping's mount point.
fn default_dev_path() -> String {
    "/dev".to_string()
}

/// The default path of the `proc` mapping's mount point.
fn default_proc_path() -> String {
    "/proc".to_string()
}

/// The mapping as it is written in the spec file, before validation.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum UncheckedMapping {
    Ro { glob: String },
    Rw { glob: String },
    Hide { glob: String },
    Empty { path: String },
    Dev {
        #[serde(default = "default_dev_path")]
        path: String,
    },
    Tmpfs {
        path: String,
        perms: Option<TmpfsPerms>,
        size: Option<u64>,
    },
    Proc {
        #[serde(default = "default_proc_path")]
        path: String,
    },
    Bind { path: String },
}

impl TryFrom<UncheckedMapping> for Mapping {
    type Error = String;

    fn try_from(raw: UncheckedMapping) -> Result<Self, Self::Error> {
        fn absolute(kind: &str, field: &str, value: String) -> Result<String, String> {
            if value.starts_with('/') {
                Ok(value)
            } else {
                Err(format!(
                    "hostfs {kind} mapping: {field} {value:?} is not an absolute path"
                ))
            }
        }
        Ok(match raw {
            UncheckedMapping::Ro { glob } => Mapping::Ro {
                glob: absolute("ro", "glob", glob)?,
            },
            UncheckedMapping::Rw { glob } => Mapping::Rw {
                glob: absolute("rw", "glob", glob)?,
            },
            UncheckedMapping::Hide { glob } => Mapping::Hide {
                glob: absolute("hide", "glob", glob)?,
            },
            UncheckedMapping::Empty { path } => Mapping::Empty {
                path: absolute("empty", "path", path)?,
            },
            UncheckedMapping::Dev { path } => Mapping::Dev {
                path: absolute("dev", "path", path)?,
            },
            UncheckedMapping::Tmpfs { path, perms, size } => Mapping::Tmpfs {
                path: absolute("tmpfs", "path", path)?,
                perms,
                size,
            },
            UncheckedMapping::Proc { path } => Mapping::Proc {
                path: absolute("proc", "path", path)?,
            },
            UncheckedMapping::Bind { path } => Mapping::Bind {
                path: absolute("bind", "path", path)?,
            },
        })
    }
}

impl<'de> Deserialize<'de> for Mapping {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        UncheckedMapping::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl Mapping {
    /// The internal glob pattern the mapping selects paths with. The
    /// mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`)
    /// name their single path as a wildcard-free "pattern".
    fn pattern(&self) -> &str {
        match self {
            Mapping::Ro { glob } | Mapping::Rw { glob } | Mapping::Hide { glob } => glob,
            Mapping::Empty { path }
            | Mapping::Dev { path }
            | Mapping::Tmpfs { path, .. }
            | Mapping::Proc { path }
            | Mapping::Bind { path } => path,
        }
    }

    /// The internal permission the mapping expresses. Every mount-point
    /// mapping exposes its path empty, like [`Mapping::Empty`].
    fn permission(&self) -> Permission {
        match self {
            Mapping::Ro { .. } => Permission::Ro,
            Mapping::Rw { .. } => Permission::Rw,
            Mapping::Hide { .. } => Permission::Hide,
            Mapping::Empty { .. } => Permission::Empty,
            Mapping::Dev { .. }
            | Mapping::Tmpfs { .. }
            | Mapping::Proc { .. }
            | Mapping::Bind { .. } => Permission::Empty,
        }
    }

    /// The mount op the mapping stands for, if any. The mount-point
    /// mappings (`dev`, `tmpfs`, `proc`, `bind`) produce the op that is
    /// stacked on top of the empty path they expose; every other mapping
    /// produces none.
    pub fn op(&self) -> Option<Op> {
        match self {
            Mapping::Dev { path } => Some(Op::Dev {
                dest: PathBuf::from(path),
            }),
            Mapping::Tmpfs { path, perms, size } => Some(Op::Tmpfs {
                dest: PathBuf::from(path),
                perms: *perms,
                size: *size,
            }),
            Mapping::Proc { path } => Some(Op::Proc {
                dest: PathBuf::from(path),
            }),
            Mapping::Bind { path } => Some(Op::Bind {
                src: path.clone(),
                dest: PathBuf::from(path),
            }),
            _ => None,
        }
    }
}

/// The internal `hostfs` representation: an *ordered* list of
/// (glob pattern, permission) pairs — the compiled-down form of the
/// spec's [`Mapping`] list. That order matters: when a path matches
/// several patterns, the **last** matching pattern decides.
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
}

/// The spec file's `hostfs` section: what the FUSE filesystem — which is
/// always the sandbox root — exposes of the host.
#[derive(Debug, Default, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HostFsConfig {
    /// An ordered list of mappings. `ro`, `rw` and `hide` select paths
    /// with a glob pattern (`glob`) of absolute host paths: matched paths
    /// are mirrored into the sandbox — read-only (`ro`) or read-write
    /// (`rw`, as far as the underlying host permissions allow) — or
    /// hidden (`hide`). `empty` names a single absolute path (`path`) and
    /// exposes it empty: an empty, unwritable directory, or an empty file
    /// when the path matches a real file. Order matters — when a path
    /// matches several mappings, the **last** matching mapping decides.
    /// Matched paths appear at the same absolute path inside the sandbox
    /// (`/etc/passwd` → `/etc/passwd`); matched directories are mirrored
    /// recursively (or, when hidden, disappear with their whole subtree).
    /// Nothing below an empty path is visible, and empty paths are shown
    /// even when a mirror mapping (or the real host path) covers them.
    /// Missing or empty mappings expose nothing.
    pub mappings: Vec<Mapping>,
}

impl HostFsConfig {
    /// The internal pattern → permission list, in spec order. The
    /// mount-point mappings (`dev`, `tmpfs`, `proc`, `bind`) contribute
    /// an `empty` pattern for their path, exactly like [`Mapping::Empty`].
    pub fn patterns(&self) -> Patterns {
        Patterns(
            self.mappings
                .iter()
                .map(|m| (m.pattern().to_string(), m.permission()))
                .collect(),
        )
    }

    /// The mount ops the mappings stand for, in mapping order (only the
    /// mount-point mappings contribute — see [`Mapping::op`]).
    pub fn ops(&self) -> Vec<Op> {
        self.mappings.iter().filter_map(Mapping::op).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse;
    use super::*;

    #[test]
    fn hostfs_mappings_parse() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "ro", "glob": "/etc/*.conf" },
                { "type": "rw", "glob": "/home/me/project" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns(vec![
                ("/etc/*.conf".to_string(), Permission::Ro),
                ("/home/me/project".to_string(), Permission::Rw)
            ])
        );
    }

    #[test]
    fn hostfs_mappings_preserve_order_and_permissions() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "rw", "glob": "/etc" },
                { "type": "hide", "glob": "/etc/passwd" },
                { "type": "empty", "path": "/dev" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns(vec![
                ("/etc".to_string(), Permission::Rw),
                ("/etc/passwd".to_string(), Permission::Hide),
                ("/dev".to_string(), Permission::Empty)
            ])
        );
    }

    #[test]
    fn hostfs_mappings_reject_relative_paths_and_bad_types() {
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "etc" } ] } }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "empty", "path": "dev" } ] } }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "nope", "glob": "/etc" } ] } }"#
            )
            .is_err()
        );
    }

    #[test]
    fn hostfs_mappings_reject_wrong_fields_per_type() {
        // A glob does not make sense for "empty", and "path" not for the
        // mirrored kinds: unknown (or mismatched) fields are rejected.
        for mapping in [
            r#"{ "type": "empty", "path": "/dev", "glob": "/dev" }"#,
            r#"{ "type": "empty", "glob": "/dev" }"#,
            r#"{ "type": "ro", "path": "/etc" }"#,
            r#"{ "type": "rw", "glob": "/etc", "path": "/etc" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn hostfs_empty_mappings() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "empty", "path": "/dev" },
                { "type": "empty", "path": "/tmp" }
            ] } }"#,
        );
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/tmp".to_string(), Permission::Empty)
            ])
        );
        assert!(parse("{}").hostfs.patterns().is_empty());
    }

    #[test]
    fn hostfs_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "nope": true } }"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "root": true } }"#)
                .is_err()
        );
    }

    #[test]
    fn mount_point_mappings_expose_empty_and_produce_ops() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "dev", "path": "/dev" },
                { "type": "tmpfs", "path": "/tmp", "perms": "1777", "size": 1048576 },
                { "type": "tmpfs", "path": "/var/tmp" },
                { "type": "proc", "path": "/proc" },
                { "type": "bind", "path": "/usr" }
            ] } }"#,
        );
        // The FUSE side sees an empty path for every mount-point mapping.
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/tmp".to_string(), Permission::Empty),
                ("/var/tmp".to_string(), Permission::Empty),
                ("/proc".to_string(), Permission::Empty),
                ("/usr".to_string(), Permission::Empty),
            ])
        );
        // The sandbox side gets the ops, in mapping order.
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                Op::Tmpfs {
                    dest: PathBuf::from("/tmp"),
                    perms: Some(TmpfsPerms(0o1777)),
                    size: Some(1048576)
                },
                Op::Tmpfs {
                    dest: PathBuf::from("/var/tmp"),
                    perms: None,
                    size: None
                },
                Op::Proc {
                    dest: PathBuf::from("/proc")
                },
                Op::Bind {
                    src: "/usr".to_string(),
                    dest: PathBuf::from("/usr")
                },
            ]
        );
    }

    #[test]
    fn dev_and_proc_mappings_default_their_path() {
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "dev" }, { "type": "proc" } ] } }"#);
        assert_eq!(
            spec.hostfs.patterns(),
            Patterns(vec![
                ("/dev".to_string(), Permission::Empty),
                ("/proc".to_string(), Permission::Empty)
            ])
        );
        assert_eq!(
            spec.hostfs.ops(),
            vec![
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                Op::Proc {
                    dest: PathBuf::from("/proc")
                }
            ]
        );
    }

    #[test]
    fn empty_tmpfs_and_bind_require_a_path() {
        for mapping in [
            r#"{ "type": "empty" }"#,
            r#"{ "type": "tmpfs" }"#,
            r#"{ "type": "bind" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn mount_point_mappings_reject_relative_paths_and_bad_fields() {
        for mapping in [
            r#"{ "type": "dev", "path": "dev" }"#,
            r#"{ "type": "tmpfs", "path": "/tmp", "perms": "abc" }"#,
            r#"{ "type": "proc", "path": "/proc", "glob": "/proc" }"#,
            r#"{ "type": "bind", "path": "/usr", "src": "/other" }"#,
        ] {
            assert!(
                serde_json::from_str::<crate::spec::Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {mapping} ] }} }}"#
                ))
                .is_err(),
                "should reject {mapping}"
            );
        }
    }

    #[test]
    fn mapped_ops_run_before_explicit_ops() {
        let spec = parse(
            r#"{ "ops": [ { "type": "symlink", "src": "usr/bin", "dest": "/bin" } ],
                 "hostfs": { "mappings": [ { "type": "dev", "path": "/dev" } ] } }"#,
        );
        assert_eq!(
            spec.filesystem_ops(),
            vec![
                // the dev mapping's op
                Op::Dev {
                    dest: PathBuf::from("/dev")
                },
                // the explicit op, last
                Op::Symlink {
                    src: "usr/bin".to_string(),
                    dest: PathBuf::from("/bin")
                },
            ]
        );
    }

    #[test]
    fn proc_mapping_mounts_procfs() {
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "proc", "path": "/proc" } ] } }"#);
        assert_eq!(
            spec.filesystem_ops(),
            vec![Op::Proc {
                dest: PathBuf::from("/proc")
            }]
        );
        // And without any mount-point mapping, no procfs (and nothing
        // else) is mounted.
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "/etc" } ] } }"#);
        assert_eq!(spec.filesystem_ops(), vec![]);
    }
}
