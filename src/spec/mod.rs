//! The sandbox specification file (JSON).
//!
//! Everything that used to be configured on the command line — the mount
//! operations and the isolated-network settings — now lives in a single
//! spec file. The default location is `.rs-bubble.json` in the current
//! directory; `--spec FILE` on the command line overrides it.
//!
//! A JSON Schema for this format is generated from this very file at
//! build time (see `build.rs`): all the serde attributes are honored,
//! and `TmpfsPerms`' hand-written deserializer is described manually in
//! its `JsonSchema` impl. The main crate embeds the generated schema as
//! `crate::SPEC_SCHEMA` and prints it via `--print-schema`, so editors
//! can validate and auto-complete spec files against it.
//!
//! Format:
//!
//! ```json
//! {
//!   "ops": [
//!     { "type": "bind",    "src": "/usr", "dest": "/usr" },
//!     { "type": "dev",     "dest": "/dev" },
//!     { "type": "tmpfs",   "dest": "/tmp", "perms": "1777", "size": 1048576 },
//!     { "type": "symlink", "src": "usr/lib", "dest": "/lib" }
//!   ],
//!   "proc": "/proc",
//!   "net": { "isolated": true, "allow": ["example.com:443"] },
//!   "hostfs": { "mappings": [ { "type": "ro", "glob": "/etc/*.conf" } ] }
//! }
//! ```
//!
//! All fields are optional: `proc` defaults to `/proc` (a fresh procfs
//! instance), and without `net.isolated` the command shares the host
//! network. `allow` is the proxy allow-list; an empty list (or a missing
//! `allow`) allows every target. The `hostfs` mappings make the FUSE
//! filesystem the sandbox root; without any mappings the sandbox gets a
//! plain tmpfs root and no FUSE filesystem is started.

pub mod hostfs;
pub mod net;
pub mod op;
pub mod tmpfs;

use std::path::{Path, PathBuf};

use serde::Deserialize;

use schemars::JsonSchema;

pub use self::hostfs::HostFsConfig;
pub use self::net::NetConfig;
pub use self::op::Op;
pub use self::tmpfs::TmpfsPerms;

/// The default spec file, looked up relative to the current directory.
pub const DEFAULT_SPEC: &str = ".rs-bubble.json";

/// The whole sandbox specification.
#[derive(Debug, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    /// The mount operations, in application order.
    pub ops: Vec<Op>,
    /// Where to mount a fresh procfs instance. `None` mounts nothing;
    /// see [`Spec::filesystem_ops`] for the default of `/proc`.
    pub proc: Option<PathBuf>,
    /// Isolated-network configuration.
    pub net: NetConfig,
    /// The host filesystem: it is always the sandbox root, exposing the
    /// paths selected by its mappings.
    pub hostfs: HostFsConfig,
    /// Accepted for editor tooling only: it names the JSON schema
    /// (`--print-schema`) so the spec file can get completion and
    /// validation. Never serialized back out.
    #[serde(rename = "$schema", default, skip_serializing)]
    pub schema: Option<String>,
}

impl Spec {
    /// Load the spec from `path` (typically `--spec FILE` or the default
    /// `.rs-bubble.json`). A missing default file is fine: an empty spec
    /// (empty root, fresh `/proc`, host network) is used in that case,
    /// while an explicit `--spec` file that cannot be read is a hard error.
    pub fn load(explicit: Option<&Path>) -> Spec {
        match explicit {
            Some(path) => Self::read(path),
            None => {
                let path = Path::new(DEFAULT_SPEC);
                if path.exists() {
                    Self::read(path)
                } else {
                    Spec::default()
                }
            }
        }
    }

    fn read(path: &Path) -> Spec {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => crate::sandbox::die(&format!("Can't read spec file {}: {e}", path.display())),
        };
        match serde_json::from_str(&text) {
            Ok(spec) => spec,
            Err(e) => crate::sandbox::die(&format!("Invalid spec file {}: {e}", path.display())),
        }
    }

    /// The filesystem setup operations, with `/proc` ensured.
    ///
    /// The sandboxed command runs in its own PID namespace, so a *fresh*
    /// procfs instance (which only shows the sandbox's processes, like bwrap
    /// with `--unshare-pid --proc /proc`) is what the child needs. If the
    /// spec set `proc` explicitly, that is used instead.
    ///
    /// The proc op is *prepended*, so explicit ops targeting paths below
    /// `/proc` still layer on top of it.
    pub fn filesystem_ops(&self) -> Vec<Op> {
        if let Some(dest) = self.proc.clone() {
            // Explicit "proc": used verbatim, prepended in front of the ops.
            return std::iter::once(Op::Proc { dest })
                .chain(self.ops.iter().cloned())
                .collect();
        }
        if self.ops.iter().any(|op| matches!(op, Op::Proc { .. })) {
            self.ops.clone()
        } else {
            std::iter::once(Op::Proc {
                dest: PathBuf::from("/proc"),
            })
            .chain(self.ops.iter().cloned())
            .collect()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Parse a spec file from a JSON snippet, like `serde_json::from_str`.
    pub(crate) fn parse(json: &str) -> Spec {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn ops_preserve_spec_order() {
        let spec = parse(
            r#"{
                "ops": [
                    { "type": "symlink", "src": "x", "dest": "/a" },
                    { "type": "bind", "src": "/usr", "dest": "/usr" },
                    { "type": "symlink", "src": "y", "dest": "/b" }
                ]
            }"#,
        );
        assert_eq!(spec.net, NetConfig::default());
        assert_eq!(spec.ops.len(), 3);
        assert_eq!(
            spec.ops[0],
            Op::Symlink {
                src: "x".into(),
                dest: PathBuf::from("/a")
            }
        );
        assert_eq!(
            spec.ops[1],
            Op::Bind {
                src: "/usr".into(),
                dest: PathBuf::from("/usr")
            }
        );
        assert_eq!(
            spec.ops[2],
            Op::Symlink {
                src: "y".into(),
                dest: PathBuf::from("/b")
            }
        );
    }

    #[test]
    fn explicit_proc_is_used_verbatim() {
        let spec = parse(r#"{ "proc": "/sys/proc" }"#);
        assert_eq!(
            spec.filesystem_ops(),
            vec![Op::Proc {
                dest: PathBuf::from("/sys/proc")
            }]
        );
    }

    #[test]
    fn default_proc_is_prepended_once() {
        // Without "proc": a fresh procfs at /proc is prepended, in front of
        // the spec's ops so they can layer on top of it.
        let spec = parse(r#"{ "ops": [ { "type": "bind", "src": "/usr", "dest": "/usr" } ] }"#);
        assert_eq!(
            spec.filesystem_ops()[0],
            Op::Proc {
                dest: PathBuf::from("/proc")
            }
        );
        assert_eq!(spec.filesystem_ops().len(), 2);
    }

    #[test]
    fn tmpfs_options() {
        // Default mode is 0755, like bwrap's --tmpfs.
        let spec = parse(r#"{ "ops": [ { "type": "tmpfs", "dest": "/tmp" } ] }"#);
        assert_eq!(
            spec.ops,
            vec![Op::Tmpfs {
                dest: PathBuf::from("/tmp"),
                perms: None,
                size: None
            }]
        );

        // perms and size are accepted as octal number or string.
        let spec = parse(
            r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "0700", "size": 1048576 } ] }"#,
        );
        assert_eq!(
            spec.ops[0],
            Op::Tmpfs {
                dest: PathBuf::from("/x"),
                perms: Some(TmpfsPerms(0o700)),
                size: Some(1048576)
            }
        );
        let spec = parse(r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": 700 } ] }"#);
        assert_eq!(
            spec.ops[0],
            Op::Tmpfs {
                dest: PathBuf::from("/x"),
                perms: Some(TmpfsPerms(0o700)),
                size: None
            }
        );
    }

    #[test]
    fn tmpfs_rejects_bad_perms() {
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "abc" } ] }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "999" } ] }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "777777777777" } ] }"#
            )
            .is_err()
        );
    }

    #[test]
    fn dev_op_parses() {
        let spec = parse(r#"{ "ops": [ { "type": "dev", "dest": "/dev" } ] }"#);
        assert_eq!(
            spec.ops,
            vec![Op::Dev {
                dest: PathBuf::from("/dev")
            }]
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<Spec>(r#"{ "nope": true }"#).is_err());
    }

    #[test]
    fn schema_key_is_accepted_but_ignored() {
        let spec = parse(r#"{ "$schema": "./rs-bubble.spec.schema.json", "ops": [] }"#);
        assert!(spec.ops.is_empty());
        assert_eq!(spec.schema.as_deref(), Some("./rs-bubble.spec.schema.json"));
        // It must be advertised in the generated schema (it's a real
        // field with skip_serializing), so editors accept it.
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert!(schema["properties"]["$schema"].is_object());
    }

    #[test]
    fn embedded_schema_is_valid_json_and_covers_all_op_types() {
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
        assert_eq!(schema["title"], "rs-bubble sandbox spec");
        // The ops are a "type"-tagged enum: every variant's tag must show
        // up in the generated schema.
        for tag in ["bind", "symlink", "proc", "dev", "tmpfs"] {
            assert!(
                crate::SPEC_SCHEMA.contains(&format!("\"{tag}\"")),
                "{tag} missing from schema"
            );
        }
        // So are the hostfs mappings.
        for tag in ["ro", "rw", "hide", "empty"] {
            assert!(
                crate::SPEC_SCHEMA.contains(&format!("\"{tag}\"")),
                "{tag} mapping missing from schema"
            );
        }
        // deny_unknown_fields on Spec must surface in the schema.
        assert_eq!(schema["additionalProperties"], false);
        // The hand-written TmpfsPerms schema: number or octal string.
        // The hand-written TmpfsPerms schema is inlined, not a $ref.
        assert!(crate::SPEC_SCHEMA.contains(r#""pattern": "^[0-7]{1,4}$""#));
        assert_eq!(schema["$defs"], serde_json::Value::Null);
        // The op variants are described in a referenced definition.
        assert!(schema["definitions"]["Op"]["oneOf"].is_array());
    }

    #[test]
    fn missing_default_file_is_an_empty_spec() {
        let dir = std::env::temp_dir().join(format!("rs-bubble-spec-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let spec = Spec::load(None);
        std::env::set_current_dir(saved).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(spec, Spec::default());
    }

    #[test]
    fn explicit_spec_file_is_required() {
        let dir = std::env::temp_dir().join(format!("rs-bubble-spec-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.json");
        std::fs::write(&path, r#"{ "net": { "isolated": true } }"#).unwrap();
        let spec = Spec::load(Some(&path));
        std::fs::remove_dir_all(&dir).ok();
        assert!(spec.net.isolated);
    }
}
