//! The sandbox specification: its **config-file** view and its
//! **internal** representation.
//!
//! The module is split into two deliberately separate layers:
//!
//! * The config file — [`file::Spec`] and its sections ([`env`],
//!   [`hostfs`], [`net`], [`tmpfs`]): everything that maps 1:1 onto what the user
//!   writes in the JSON spec file (`.ai-bubble/spec.json`, or
//!   `--spec-dir DIR`).
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

pub mod env;
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

    /// Parse a spec file snippet that is expected to fail, returning the
    /// error (or panicking when it unexpectedly parses).
    pub(crate) fn parse_err(json: &str) -> Option<serde_json::Error> {
        serde_json::from_str::<Spec>(json).err()
    }

    /// The compiled-down ops of a spec file snippet.
    pub(crate) fn compile_ops(json: &str) -> Vec<Op> {
        SandboxConfig::compile(&parse(json)).ops
    }

    #[test]
    fn env_section_is_parsed_and_expanded() {
        unsafe { std::env::set_var("RS_BUBBLE_TEST_ENV_HOME", "/home/me") };
        // The env section gives the sandbox its complete environment:
        // values are ${VAR}-expanded from the host, like the path-like
        // mapping fields.
        let spec = parse(
            r#"{ "env": { "values": {
                    "PATH": "${PATH}",
                    "HOME": "${RS_BUBBLE_TEST_ENV_HOME}/sandbox",
                    "EMPTY": ""
                } } }"#,
        );
        let env: std::collections::BTreeMap<_, _> = spec
            .env
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect();
        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some("/home/me/sandbox")
        );
        assert_eq!(env.get("EMPTY").map(String::as_str), Some(""));
        let compiled = SandboxConfig::compile(&spec);
        assert_eq!(
            compiled.env.get("HOME").map(String::as_str),
            Some("/home/me/sandbox")
        );
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_ENV_HOME") };
    }

    #[test]
    fn unset_env_var_in_env_section_is_a_deserialize_error() {
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
        // Referencing an unset host variable is an error, so a typo in
        // the env section doesn't silently drop the variable.
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "env": { "values": { "PATH": "${RS_BUBBLE_TEST_UNSET}" } } }"#
            )
            .is_err()
        );
        // But a plain, non-referencing value is always fine.
        assert!(
            serde_json::from_str::<Spec>(r#"{ "env": { "values": { "FOO": "bar" } } }"#).is_ok()
        );
        // Unknown fields inside the env section are rejected.
        assert!(serde_json::from_str::<Spec>(r#"{ "env": { "nope": true } }"#).is_err());
    }

    #[test]
    fn env_file_entries_are_merged_into_values() {
        unsafe { std::env::set_var("RS_BUBBLE_TEST_ENV_FILE_HOME", "/home/me") };
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-spec-envfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(crate::spec::file::SPEC_FILE),
            r#"{ "env": {
                "values": { "FROM_SPEC": "spec value", "HOME": "${RS_BUBBLE_TEST_ENV_FILE_HOME}/sandbox" },
                "env_file": "secrets.env"
            } }"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("secrets.env"),
            r#"
# a comment
FILE_ONLY=file value
FROM_SPEC=file value (overridden)
QUOTED="quoted file value"
        "#,
        )
        .unwrap();
        let spec = Spec::load(Some(&dir));
        std::fs::remove_dir_all(&dir).ok();
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_ENV_FILE_HOME") };
        let env: std::collections::BTreeMap<_, _> = spec
            .env
            .values
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect();
        // File-only entries are loaded, and `${VAR}` in them is expanded
        // like in the spec values...
        assert_eq!(env.get("FILE_ONLY").map(String::as_str), Some("file value"));
        assert_eq!(
            env.get("QUOTED").map(String::as_str),
            Some("quoted file value")
        );
        // ...spec values win over file entries, including an expanded one.
        assert_eq!(env.get("FROM_SPEC").map(String::as_str), Some("spec value"));
        assert_eq!(
            env.get("HOME").map(String::as_str),
            Some("/home/me/sandbox")
        );
        let compiled = SandboxConfig::compile(&spec);
        assert_eq!(compiled.env, env);
    }

    #[test]
    fn missing_env_file_is_an_error() {
        use super::env::EnvConfig;
        let mut env = EnvConfig {
            env_file: Some("does-not-exist.env".to_string()),
            values: Default::default(),
        };
        assert!(
            env.load_env_file(std::path::Path::new("/nonexistent-spec-dir"))
                .is_err()
        );
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
                    dest: PathBuf::from("/usr"),
                    rw: false,
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
    fn cwd_is_parsed_expanded_and_compiled() {
        unsafe { std::env::set_var("RS_BUBBLE_TEST_CWD", "/work") };
        let spec = parse(r#"{ "cwd": "${RS_BUBBLE_TEST_CWD}/project" }"#);
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_CWD") };
        assert_eq!(spec.cwd.as_deref(), Some("/work/project"));
        let compiled = SandboxConfig::compile(&spec);
        assert_eq!(compiled.cwd, Some(PathBuf::from("/work/project")));

        // Without a cwd the command starts at the sandbox root.
        assert_eq!(SandboxConfig::compile(&parse(r#"{}"#)).cwd, None);
    }

    #[test]
    fn cwd_must_be_absolute_and_dotdot_free() {
        for bad in [
            r#"{ "cwd": "relative/dir" }"#,
            r#"{ "cwd": "/a/../.."}"#,
            r#"{ "cwd": "" }"#,
        ] {
            assert!(
                serde_json::from_str::<Spec>(bad).is_err(),
                "should reject cwd {bad}"
            );
        }
        // `..` inside a component name is fine; it is not a parent ref.
        assert!(serde_json::from_str::<Spec>(r#"{ "cwd": "/a..b/c" }"#).is_ok());
    }

    #[test]
    fn unset_env_var_in_cwd_is_a_deserialize_error() {
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
        assert!(serde_json::from_str::<Spec>(r#"{ "cwd": "${RS_BUBBLE_TEST_UNSET}/x" }"#).is_err());
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
        let spec = parse(r#"{ "$schema": "./ai-bubble.spec.schema.json" }"#);
        assert_eq!(spec.schema.as_deref(), Some("./ai-bubble.spec.schema.json"));
        // It must be advertised in the generated schema (it's a real
        // field with skip_serializing), so editors accept it.
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert!(schema["properties"]["$schema"].is_object());
    }

    #[test]
    fn redirect_sources_are_resolved_relative_to_the_spec_dir() {
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-spec-redirect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::spec::file::SPEC_FILE);
        std::fs::write(
            &path,
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-ro", "dest": "/bla", "source": "otherdir" },
                { "type": "redirect-rw", "dest": "/abs", "source": "/elsewhere" }
            ] } }"#,
        )
        .unwrap();
        let spec = Spec::load(Some(&dir));
        use crate::spec::hostfs::Mapping;
        use std::path::Path;
        match &spec.hostfs.mappings[0] {
            Mapping::RedirectRo { source, .. } => {
                // The relative source is resolved against the spec file's
                // directory (canonicalized, like the dir itself).
                assert_eq!(
                    Path::new(source),
                    std::fs::canonicalize(&dir).unwrap().join("otherdir")
                );
            }
            other => panic!("expected a redirect-ro mapping, got {other:?}"),
        }
        // An absolute source is left alone.
        match &spec.hostfs.mappings[1] {
            Mapping::RedirectRw { source, .. } => assert_eq!(source, "/elsewhere"),
            other => panic!("expected a redirect-rw mapping, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn embedded_schema_is_valid_json_and_covers_all_mapping_types() {
        let schema: serde_json::Value = serde_json::from_str(crate::SPEC_SCHEMA).unwrap();
        assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
        assert_eq!(schema["title"], "ai-bubble sandbox spec");
        // The mappings are a "type"-tagged enum: every variant's tag must
        // show up in the generated schema.
        for tag in [
            "ro",
            "rw",
            "hide",
            "empty",
            "dev",
            "tmpfs",
            "proc",
            "bind",
            "symlink",
            "redirect-ro",
            "redirect-rw",
            "session-cache",
            "project-cache",
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
    fn spec_dir_is_always_hidden() {
        use crate::hostfs::permission_of;
        use crate::spec::hostfs::Mapping;
        use crate::spec::internal::Permission;
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
        let spec = Spec::load(Some(&dir));

        // Loading appends a hide mapping for the spec directory.
        match spec.hostfs.mappings.last() {
            Some(Mapping::Hide { glob }) => {
                assert_eq!(Path::new(glob), std::fs::canonicalize(&dir).unwrap())
            }
            other => panic!("expected a trailing hide mapping, got {other:?}"),
        }
        // The hide wins over the earlier rw mapping: the directory and
        // everything below it are invisible — also in the compiled config
        // the sandbox machinery runs with.
        let spec_path = std::fs::canonicalize(&dir).unwrap();
        let compiled = SandboxConfig::compile(&spec);
        for patterns in [&spec.hostfs.patterns(), &compiled.patterns] {
            assert_eq!(permission_of(patterns, &spec_path), Some(Permission::Hide));
            assert_eq!(
                permission_of(patterns, &spec_path.join("spec.json")),
                Some(Permission::Hide)
            );
            assert_eq!(
                permission_of(patterns, &spec_path.join("cache/deep/file")),
                Some(Permission::Hide)
            );
        }
        // But paths outside the spec directory stay visible.
        assert_eq!(
            permission_of(&compiled.patterns, Path::new("/etc/passwd")),
            Some(Permission::Rw)
        );
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn no_spec_dir_no_hide() {
        // Without a spec file (and thus without a spec directory) nothing
        // is hidden: the spec stays empty.
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-spec-nohide-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let spec = Spec::load(None);
        std::env::set_current_dir(saved).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(spec, Spec::default());
        assert!(spec.hostfs.patterns().is_empty());
    }

    #[test]
    fn missing_default_file_is_an_empty_spec() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-spec-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let spec = Spec::load(None);
        std::env::set_current_dir(saved).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(spec, Spec::default());
    }

    #[test]
    fn explicit_spec_dir_is_required() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-spec-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::spec::file::SPEC_FILE);
        std::fs::write(&path, r#"{ "net": { "mode": "proxy", "allow": [] } }"#).unwrap();
        let spec = Spec::load(Some(&dir));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            spec.net,
            crate::spec::net::NetConfig::Proxy { allow: vec![] }
        );
    }

    #[test]
    fn env_vars_are_expanded_in_spec_strings() {
        // Every string value in the spec file may reference environment
        // variables as ${VAR}: they are expanded right after the file is
        // read, so the parsed spec only ever sees the expanded text.
        let dir = std::env::temp_dir().join(format!("ai-bubble-spec-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::spec::file::SPEC_FILE);
        std::fs::write(
            &path,
            r#"{ "hostfs": { "mappings": [
                { "type": "rw", "glob": "${RS_BUBBLE_TEST_HOME}/project" },
                { "type": "bind", "src": "${RS_BUBBLE_TEST_HOME}/etc" }
            ] } }"#,
        )
        .unwrap();
        // SAFETY: tests are single-threaded per process here and the
        // variable name is unique to this test.
        unsafe { std::env::set_var("RS_BUBBLE_TEST_HOME", "/home/me") };
        let spec = Spec::load(Some(&dir));
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_HOME") };
        std::fs::remove_dir_all(&dir).ok();
        use crate::spec::hostfs::Mapping;
        match &spec.hostfs.mappings[0] {
            Mapping::Rw { glob } => assert_eq!(glob, "/home/me/project"),
            other => panic!("expected an rw mapping, got {other:?}"),
        }
        match &spec.hostfs.mappings[1] {
            Mapping::Bind {
                src, dest: None, ..
            } => assert_eq!(src, "/home/me/etc"),
            other => panic!("expected a bind mapping, got {other:?}"),
        }
    }

    #[test]
    fn unset_env_vars_are_an_error_and_literals_pass_through() {
        use crate::spec::file::expand_str;
        // An unset variable is an error, so typos don't silently produce
        // bogus paths.
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
        assert!(expand_str("${RS_BUBBLE_TEST_UNSET}/x").is_err());
        // A set variable expands, several times in one string.
        unsafe { std::env::set_var("RS_BUBBLE_TEST_VAR", "v") };
        assert_eq!(
            expand_str("${RS_BUBBLE_TEST_VAR}/${RS_BUBBLE_TEST_VAR}").unwrap(),
            "v/v"
        );
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_VAR") };
        // Only the ${VAR} form is recognized: a bare $ stays untouched,
        // as does an unterminated ${.
        assert_eq!(expand_str("$HOME/x").unwrap(), "$HOME/x");
        assert_eq!(expand_str("/a${b").unwrap(), "/a${b");
    }

    #[test]
    fn env_expansion_applies_only_to_path_like_mapping_fields() {
        unsafe { std::env::set_var("RS_BUBBLE_TEST_HOME", "/home/me") };
        // The path-like mapping fields are expanded...
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "ro", "glob": "${RS_BUBBLE_TEST_HOME}/project" },
                { "type": "empty", "path": "${RS_BUBBLE_TEST_HOME}/empty" },
                { "type": "dev", "path": "${RS_BUBBLE_TEST_HOME}/dev" },
                { "type": "tmpfs", "path": "${RS_BUBBLE_TEST_HOME}/tmp" },
                { "type": "proc", "path": "${RS_BUBBLE_TEST_HOME}/proc" },
                { "type": "bind", "src": "${RS_BUBBLE_TEST_HOME}/src", "dest": "${RS_BUBBLE_TEST_HOME}/dest" },
                { "type": "redirect-rw", "dest": "${RS_BUBBLE_TEST_HOME}/at", "source": "${RS_BUBBLE_TEST_HOME}/src" },
                { "type": "symlink", "src": "${RS_BUBBLE_TEST_HOME}/target", "dest": "/link" }
            ] } }"#,
        );
        let patterns: Vec<_> = spec
            .hostfs
            .patterns()
            .0
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        assert_eq!(
            patterns,
            vec![
                "/home/me/project",
                "/home/me/empty",
                "/home/me/dev",
                "/home/me/tmp",
                "/home/me/proc",
                "/home/me/dest",
                "/home/me/at",
            ]
        );
        let ops = spec.hostfs.ops();
        if let [
            Op::Dev { .. },
            Op::Tmpfs { .. },
            Op::Proc { .. },
            Op::Bind { src, dest, .. },
            Op::Symlink {
                src: symlink_src, ..
            },
        ] = &ops[..]
        {
            assert_eq!(src, "/home/me/src");
            assert_eq!(dest, &PathBuf::from("/home/me/dest"));
            assert_eq!(symlink_src, "/home/me/target");
        } else {
            panic!("unexpected ops: {ops:?}");
        }
        // ...while other string fields are left untouched: an ${VAR}
        // reference in net.allow or $schema is a literal (and here just
        // an odd, but legal, allow entry).
        let spec =
            parse(r#"{ "net": { "mode": "proxy", "allow": ["${RS_BUBBLE_TEST_HOME}:443"] } }"#);
        assert_eq!(
            spec.net,
            crate::spec::net::NetConfig::Proxy {
                allow: vec!["${RS_BUBBLE_TEST_HOME}:443".to_string()]
            }
        );
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_HOME") };
    }

    #[test]
    fn unset_env_var_in_a_mapping_field_is_a_deserialize_error() {
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "${RS_BUBBLE_TEST_UNSET}/x" } ] } }"#
            )
            .is_err()
        );
        // The same reference outside the mapping fields is accepted (in
        // proxy mode — a `net` object must name its `mode`).
        assert!(
            serde_json::from_str::<Spec>(
                r#"{ "net": { "mode": "proxy", "allow": ["${RS_BUBBLE_TEST_UNSET}:443"] } }"#
            )
            .is_ok()
        );
    }
}
