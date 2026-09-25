//! The `hostfs` section of the spec file: what the FUSE filesystem
//! mounted at `/host` exposes.

use std::fmt;

use serde::Deserialize;

use schemars::JsonSchema;

/// What happens to a path matched by a `hostfs.mirror` glob pattern:
/// it is mirrored (and readable) under `/host`, or hidden.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// The matched paths are mirrored under `/host` (read-only).
    Mirror,
    /// The matched paths are hidden. A hidden **directory** hides its
    /// whole subtree, too.
    Hide,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Permission::Mirror => "mirror",
            Permission::Hide => "hide",
        })
    }
}

/// The spec's `hostfs.mirror` setting: an *ordered* mapping from glob
/// patterns (absolute host paths) to [`Permission`]s.
///
/// JSON objects do not guarantee key order, so this is deserialized by
/// hand into a list of pattern/permission pairs that keeps the order the
/// patterns were written in. That order matters: when a path matches
/// several patterns, the **last** matching pattern decides.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Mirror(pub Vec<(String, Permission)>);

impl Mirror {
    /// The pattern/permission pairs, in spec order.
    pub fn iter(&self) -> impl Iterator<Item = &(String, Permission)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for Mirror {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Mirror;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object mapping glob patterns to \"mirror\" or \"hide\"")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Mirror, A::Error> {
                let mut entries = Vec::new();
                while let Some((pattern, permission)) =
                    map.next_entry::<String, Permission>()?
                {
                    if !pattern.starts_with('/') {
                        return Err(serde::de::Error::custom(format!(
                            "hostfs mirror pattern {pattern:?} is not an absolute path"
                        )));
                    }
                    entries.push((pattern, permission));
                }
                Ok(Mirror(entries))
            }
        }
        deserializer.deserialize_map(V)
    }
}

impl JsonSchema for Mirror {
    fn schema_name() -> String {
        "Mirror".to_string()
    }

    fn is_referenceable() -> bool {
        // Inline: the type has no name in the JSON format.
        false
    }

    fn json_schema(r#gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, ObjectValidation, Schema, SchemaObject};
        Schema::Object(SchemaObject {
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "An **ordered** mapping from glob patterns (absolute host paths) to \
                     permissions. Matched paths are mirrored read-only under `/host` \
                     (`\"mirror\"`) or hidden (`\"hide\"`). Order matters: when a path \
                     matches several patterns, the **last** matching pattern decides. \
                     A pattern that names a directory exactly mirrors (or hides) it \
                     recursively; a hidden directory hides its whole subtree. Empty \
                     mirrors nothing."
                        .to_string(),
                ),
                ..Default::default()
            })),
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(ObjectValidation {
                additional_properties: Some(Box::new(r#gen.subschema_for::<Permission>())),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

/// The spec file's `hostfs` section: what the FUSE filesystem mounted at
/// `/host` exposes.
#[derive(Debug, Default, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HostFsConfig {
    /// An ordered mapping from glob patterns (absolute host paths) to
    /// permissions: matched paths are mirrored read-only under `/host`
    /// (`"mirror"`) or hidden (`"hide"`). Order matters — when a path
    /// matches several patterns, the **last** matching pattern decides.
    /// Matched paths appear at the same absolute path below `/host`
    /// (`/etc/passwd` → `/host/etc/passwd`); matched directories are
    /// mirrored recursively (or, when hidden, disappear with their whole
    /// subtree). Empty mirrors nothing.
    pub mirror: Mirror,
    /// Absolute paths exposed as **empty, unwritable directories**
    /// (mode 0555, no contents), taking *precedence* over `mirror`:
    /// nothing below an entry is visible, and the entry itself is shown
    /// even when a mirror pattern (or the real host path) covers it.
    /// Meant as mount points inside the sandbox, e.g. `/dev`, `/tmp`,
    /// `/proc` — or the sandbox root itself with `hostfs.root`.
    #[serde(rename = "emptyDirs")]
    pub empty_dirs: Vec<String>,
    /// **Experimental:** use the FUSE filesystem itself as the sandbox
    /// root instead of mounting it at `/host`. Everything mirrored appears
    /// at its absolute host path; the ops (`dev`, `tmpfs`, `proc`, binds)
    /// are mounted on top of it. Because the FUSE filesystem is read-only,
    /// every mount point must be listed in `emptyDirs` (or exist in the
    /// mirror).
    pub root: bool,
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse;
    use super::*;

    #[test]
    fn hostfs_mirror_parses() {
        let spec = parse(
            r#"{ "hostfs": { "mirror": { "/etc/*.conf": "mirror", "/home/me/project": "mirror" } } }"#,
        );
        assert_eq!(
            spec.hostfs.mirror,
            Mirror(vec![
                ("/etc/*.conf".to_string(), Permission::Mirror),
                ("/home/me/project".to_string(), Permission::Mirror)
            ])
        );
    }

    #[test]
    fn hostfs_mirror_preserves_order_and_permissions() {
        let spec = parse(
            r#"{ "hostfs": { "mirror": { "/etc": "mirror", "/etc/passwd": "hide" } } }"#,
        );
        assert_eq!(
            spec.hostfs.mirror,
            Mirror(vec![
                ("/etc".to_string(), Permission::Mirror),
                ("/etc/passwd".to_string(), Permission::Hide)
            ])
        );
    }

    #[test]
    fn hostfs_mirror_rejects_relative_patterns_and_bad_permissions() {
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "mirror": { "etc": "mirror" } } }"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "mirror": { "/etc": "rw" } } }"#)
                .is_err()
        );
    }

    #[test]
    fn hostfs_root_flag_parses() {
        assert!(!parse("{}").hostfs.root);
        let spec = parse(r#"{ "hostfs": { "root": true, "mirror": { "/etc": "mirror" } } }"#);
        assert!(spec.hostfs.root);
        assert_eq!(
            spec.hostfs.mirror,
            Mirror(vec![("/etc".to_string(), Permission::Mirror)])
        );
    }

    #[test]
    fn hostfs_empty_dirs_parse() {
        let spec = parse(r#"{ "hostfs": { "emptyDirs": ["/dev", "/tmp"] } }"#);
        assert_eq!(spec.hostfs.empty_dirs, ["/dev".to_string(), "/tmp".to_string()]);
        assert!(parse("{}").hostfs.empty_dirs.is_empty());
    }

    #[test]
    fn hostfs_defaults_to_no_mirror() {
        let spec = parse("{}");
        assert!(spec.hostfs.mirror.is_empty());
    }

    #[test]
    fn hostfs_rejects_unknown_fields() {
        assert!(serde_json::from_str::<crate::spec::Spec>(r#"{ "hostfs": { "nope": true } }"#).is_err());
    }
}
