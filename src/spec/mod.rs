//! The sandbox specification: its **config-file** view and its
//! **internal** representation.
//!
//! The module is split into two deliberately separate layers:
//!
//! * The config file — [`file::Spec`] and its sections ([`hostfs`],
//!   [`net`], [`tmpfs`]): everything that maps 1:1 onto what the user
//!   writes in the JSON spec file (`.rs-bubble.json`, or `--spec FILE`).
//!   These types carry the serde and JSON-schema attributes and are
//!   documented for the file format.
//! * The internal configuration — [`internal`]: what the sandbox
//!   machinery (`crate::sandbox`, `crate::hostfs`, `crate::netns`)
//!   actually runs with, compiled down from the parsed file by
//!   [`internal::SandboxConfig::compile`]. Internal code never touches
//!   the config-file types.
//!
//! A JSON Schema for the config file is generated from these very files
//! at build time (see `build.rs`): all the serde attributes are honored,
//! and `TmpfsPerms`' hand-written deserializer is described manually in
//! its `JsonSchema` impl. The main crate embeds the generated schema as
//! `crate::SPEC_SCHEMA` and prints it via `--print-schema`, so editors
//! can validate and auto-complete spec files against it.

pub mod file;
pub mod hostfs;
pub mod internal;
pub mod net;
pub mod tmpfs;

pub use self::file::Spec;

#[cfg(test)]
pub(crate) mod tests {
    use super::file::Spec;
    use super::internal::{Op, SandboxConfig};
    use super::tmpfs::TmpfsPerms;
    use std::path::PathBuf;

    /// Parse a spec file from a JSON snippet, like `serde_json::from_str`.
    pub(crate) fn parse(json: &str) -> Spec {
        serde_json::from_str(json).unwrap()
    }

    /// The compiled-down ops of a spec file snippet.
    pub(crate) fn compile_ops(json: &str) -> Vec<Op> {
        SandboxConfig::compile(&parse(json)).ops
    }

    #[test]
    fn mapping_ops_preserve_spec_order() {
        // Every op comes from the mappings, applied in mapping order.
        assert_eq!(
            compile_ops(
                r#"{
                    "hostfs": { "mappings": [
                        { "type": "symlink", "src": "x", "dest": "/a" },
                        { "type": "bind", "src": "/usr" },
                        { "type": "symlink", "src": "y", "dest": "/b" }
                    ] }
                }"#
            ),
            vec![
                Op::Symlink {
                    src: "x".into(),
                    dest: PathBuf::from("/a")
                },
                Op::Bind {
                    src: "/usr".into(),
                    dest: PathBuf::from("/usr")
                },
                Op::Symlink {
                    src: "y".into(),
                    dest: PathBuf::from("/b")
                },
            ]
        );
    }

    #[test]
    fn proc_mapping_relocates_procfs() {
        // Procfs only appears where the spec asks for it: a proc mapping
        // chooses where — and whether at all.
        assert_eq!(
            compile_ops(
                r#"{ "hostfs": { "mappings": [ { "type": "proc", "path": "/sys/proc" } ] } }"#
            ),
            vec![Op::Proc {
                dest: PathBuf::from("/sys/proc")
            }]
        );
    }

    #[test]
    fn no_proc_mount_without_a_proc_mapping() {
        // Mappings mount procfs only when asked: no default /proc mount
        // happens.
        assert_eq!(
            compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/usr" } ] } }"#)
                .len(),
            1
        );
        assert_eq!(
            compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "dev", "path": "/dev" } ] } }"#)
                .len(),
            1
        );
    }

    #[test]
    fn tmpfs_mapping_options() {
        // Default mode is 0755, like bwrap's --tmpfs.
        assert_eq!(
            compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "tmpfs", "path": "/tmp" } ] } }"#),
            vec![Op::Tmpfs {
                dest: PathBuf::from("/tmp"),
                perms: None,
                size: None
            }]
        );

        // perms and size are accepted as octal number or string.
        assert_eq!(
            compile_ops(
                r#"{ "hostfs": { "mappings": [ { "type": "tmpfs", "path": "/x", "perms": "0700", "size": 1048576 } ] } }"#
            ),
            vec![Op::Tmpfs {
                dest: PathBuf::from("/x"),
                perms: Some(TmpfsPerms(0o700)),
                size: Some(1048576)
            }]
        );
        assert_eq!(
            compile_ops(
                r#"{ "hostfs": { "mappings": [ { "type": "tmpfs", "path": "/x", "perms": 700 } ] } }"#
            ),
            vec![Op::Tmpfs {
                dest: PathBuf::from("/x"),
                perms: Some(TmpfsPerms(0o700)),
                size: None
            }]
        );
    }

    #[test]
    fn tmpfs_mapping_rejects_bad_perms() {
        for perms in ["\"abc\"", "\"999\"", "\"777777777777\""] {
            assert!(
                serde_json::from_str::<Spec>(&format!(
                    r#"{{ "hostfs": {{ "mappings": [ {{ "type": "tmpfs", "path": "/x", "perms": {perms} }} ] }} }}"#
                ))
                .is_err(),
                "should reject perms {perms}"
            );
        }
    }

    #[test]
    fn dev_mapping_parses() {
        assert_eq!(
            compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "dev", "path": "/dev" } ] } }"#),
            vec![Op::Dev {
                dest: PathBuf::from("/dev")
            }]
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<Spec>(r#"{ "nope": true }"#).is_err());
        // The top-level "proc" field is gone: procfs is configured with a
        // `proc` mapping instead.
        assert!(serde_json::from_str::<Spec>(r#"{ "proc": "/proc" }"#).is_err());
        // So is the top-level "ops" array: everything is a mapping now.
        assert!(serde_json::from_str::<Spec>(r#"{ "ops": [] }"#).is_err());
    }

    #[test]
    fn schema_key_is_accepted_but_ignored() {
        let spec = parse(r#"{ "$schema": "./rs-bubble.spec.schema.json" }"#);
        assert_eq!(spec.schema.as_deref(), Some("./rs-bubble.spec.schema.json"));
        // It must be advertised in the generated schema (it's a real
        // field with skip_serializing), so editors accept it.
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert!(schema["properties"]["$schema"].is_object());
    }

    #[test]
    fn embedded_schema_is_valid_json_and_covers_all_mapping_types() {
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
        assert_eq!(schema["title"], "rs-bubble sandbox spec");
        // The mappings are a "type"-tagged enum: every variant's tag must
        // show up in the generated schema.
        for tag in [
            "ro", "rw", "hide", "empty", "dev", "tmpfs", "proc", "bind", "symlink",
        ] {
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
