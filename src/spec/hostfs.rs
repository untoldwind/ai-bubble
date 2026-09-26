//! The `hostfs` section of the spec file: what the FUSE filesystem —
//! which is always the sandbox root — exposes of the host.
//!
//! This is only the *spec-file* view: [`HostFsConfig::patterns`] maps it
//! onto the internal [`Patterns`] representation the FUSE filesystem
//! itself works with.

use std::fmt;

use serde::Deserialize;

use schemars::JsonSchema;

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
/// absolute host paths; an `empty` mapping names a single absolute host
/// **path** exactly (it makes no sense to glob an empty mount point).
/// The list order matters: when a path matches several mappings, the
/// **last** matching mapping decides.
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
}

/// The mapping as it is written in the spec file, before validation.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum UncheckedMapping {
    Ro { glob: String },
    Rw { glob: String },
    Hide { glob: String },
    Empty { path: String },
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
    /// The internal glob pattern the mapping selects paths with. `empty`
    /// mappings name their single path as a wildcard-free "pattern".
    fn pattern(&self) -> &str {
        match self {
            Mapping::Ro { glob } | Mapping::Rw { glob } | Mapping::Hide { glob } => glob,
            Mapping::Empty { path } => path,
        }
    }

    /// The internal permission the mapping expresses.
    fn permission(&self) -> Permission {
        match self {
            Mapping::Ro { .. } => Permission::Ro,
            Mapping::Rw { .. } => Permission::Rw,
            Mapping::Hide { .. } => Permission::Hide,
            Mapping::Empty { .. } => Permission::Empty,
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
    /// The internal pattern → permission list, in spec order.
    pub fn patterns(&self) -> Patterns {
        Patterns(
            self.mappings
                .iter()
                .map(|m| (m.pattern().to_string(), m.permission()))
                .collect(),
        )
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
}
