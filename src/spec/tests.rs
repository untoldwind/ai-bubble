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
fn env_values_are_expanded_at_compile_time() {
    unsafe { std::env::set_var("RS_BUBBLE_TEST_ENV_HOME", "/home/me") };
    // The env section gives the sandbox its complete environment.
    // Parsing keeps every value exactly as written...
    let spec = parse(
        r#"{ "env": { "values": {
                "PATH": "${PATH}",
                "HOME": "${RS_BUBBLE_TEST_ENV_HOME}/sandbox",
                "EMPTY": ""
            } } }"#,
    );
    assert_eq!(
        spec.env.values.get("HOME").map(|v| v.0.as_str()),
        Some("${RS_BUBBLE_TEST_ENV_HOME}/sandbox")
    );
    // ...and the `${VAR}` references are replaced from the host
    // environment when the spec is compiled down to the internal
    // config.
    let compiled = SandboxConfig::compile(&spec);
    assert_eq!(
        compiled.env.get("HOME").map(String::as_str),
        Some("/home/me/sandbox")
    );
    assert_eq!(compiled.env.get("EMPTY").map(String::as_str), Some(""));
    assert_eq!(
        compiled.env.get("PATH").map(String::as_str),
        std::env::var("PATH").ok().as_deref()
    );
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_ENV_HOME") };
}

#[test]
fn unset_env_var_in_env_section_is_a_compile_error() {
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
    // Referencing an unset host variable is an error, so a typo in
    // the env section doesn't silently drop the variable. The
    // reference is only resolved when the config is compiled, so
    // parsing still succeeds...
    let spec = parse(r#"{ "env": { "values": { "PATH": "${RS_BUBBLE_TEST_UNSET}" } } }"#);
    assert!(spec.env.expand_values().is_err());
    // ...while a plain, non-referencing value always expands fine.
    let spec = parse(r#"{ "env": { "values": { "FOO": "bar" } } }"#);
    assert_eq!(
        spec.env
            .expand_values()
            .unwrap()
            .get("FOO")
            .map(String::as_str),
        Some("bar")
    );
    // Unknown fields inside the env section are rejected at parse time.
    assert!(serde_json::from_str::<Spec>(r#"{ "env": { "nope": true } }"#).is_err());
}

#[test]
fn env_file_entries_are_merged_into_values() {
    unsafe { std::env::set_var("RS_BUBBLE_TEST_ENV_FILE_HOME", "/home/me") };
    let dir = std::env::temp_dir().join(format!("ai-bubble-spec-envfile-{}", std::process::id()));
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
    // The file entries are merged into `values` as written, with the
    // spec's entries winning over the file's...
    assert_eq!(
        spec.env.values.get("FILE_ONLY").map(|v| v.0.as_str()),
        Some("file value")
    );
    assert_eq!(
        spec.env.values.get("QUOTED").map(|v| v.0.as_str()),
        Some("quoted file value")
    );
    assert_eq!(
        spec.env.values.get("FROM_SPEC").map(|v| v.0.as_str()),
        Some("spec value")
    );
    assert_eq!(
        spec.env.values.get("HOME").map(|v| v.0.as_str()),
        Some("${RS_BUBBLE_TEST_ENV_FILE_HOME}/sandbox")
    );
    // ...and every value is `${VAR}`-expanded when the config is
    // compiled down, spec entries and file entries alike.
    let compiled = SandboxConfig::compile(&spec);
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_ENV_FILE_HOME") };
    assert_eq!(
        compiled.env.get("FILE_ONLY").map(String::as_str),
        Some("file value")
    );
    assert_eq!(
        compiled.env.get("QUOTED").map(String::as_str),
        Some("quoted file value")
    );
    assert_eq!(
        compiled.env.get("FROM_SPEC").map(String::as_str),
        Some("spec value")
    );
    assert_eq!(
        compiled.env.get("HOME").map(String::as_str),
        Some("/home/me/sandbox")
    );
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
        compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "proc", "path": "/sys/proc" } ] } }"#),
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
        compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/usr" } ] } }"#).len(),
        1
    );
    assert_eq!(
        compile_ops(r#"{ "hostfs": { "mappings": [ { "type": "dev", "path": "/dev" } ] } }"#).len(),
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
fn cwd_is_parsed_as_written_and_expanded_at_compile_time() {
    unsafe { std::env::set_var("RS_BUBBLE_TEST_CWD", "/work") };
    // Parsing keeps the raw text exactly as written...
    let spec = parse(r#"{ "cwd": "${RS_BUBBLE_TEST_CWD}/project" }"#);
    assert_eq!(spec.cwd.as_deref(), Some("${RS_BUBBLE_TEST_CWD}/project"));
    // ...and the `${VAR}` reference is resolved when the spec is compiled
    // down to the internal config.
    let compiled = SandboxConfig::compile(&spec);
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_CWD") };
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
        // Any cwd parses as written...
        let spec = parse(bad);
        // ...but compiling it rejects the bad ones.
        assert!(spec.expand_cwd().is_err(), "should reject cwd {bad}");
    }
    // `..` inside a component name is fine; it is not a parent ref.
    assert_eq!(
        parse(r#"{ "cwd": "/a..b/c" }"#).expand_cwd().unwrap(),
        Some(PathBuf::from("/a..b/c"))
    );
}

#[test]
fn unset_env_var_in_cwd_is_a_compile_error() {
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
    // The reference is only resolved when the config is compiled, so
    // parsing still succeeds...
    let spec = parse(r#"{ "cwd": "${RS_BUBBLE_TEST_UNSET}/x" }"#);
    assert_eq!(spec.cwd.as_deref(), Some("${RS_BUBBLE_TEST_UNSET}/x"));
    // ...while compiling it fails on the unset variable.
    assert!(spec.expand_cwd().is_err());
}

#[test]
fn spec_fields_are_kept_as_written_at_parse_time() {
    // The config-file view holds exactly what the user wrote: expanding
    // `${VAR}` (and validating) is the compile step's job, so a spec can
    // be assembled programmatically and only resolved when it is run.
    // This is the invariant `cwd` and the `env` values follow.
    //
    // The path-like hostfs mapping fields are the documented exception:
    // they are expanded and validated while the field is deserialized
    // (see `crate::spec::hostfs::env_string`). `Spec::load` goes further
    // and expands `audit.log`, resolves relative redirect sources, merges
    // the env file and appends the spec-dir hide mapping.
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
    let spec = parse(
        r#"{
            "$schema": "${RS_BUBBLE_TEST_UNSET}/schema.json",
            "cwd": "${RS_BUBBLE_TEST_UNSET}/work",
            "env": {
                "values": { "HOME": "${RS_BUBBLE_TEST_UNSET}/home" },
                "env_file": "${RS_BUBBLE_TEST_UNSET}/.env"
            },
            "net": { "mode": "proxy", "allow": ["${RS_BUBBLE_TEST_UNSET}:443"] },
            "seccomp": { "block": ["ptrace", "mount"] }
        }"#,
    );
    assert_eq!(
        spec.schema.as_deref(),
        Some("${RS_BUBBLE_TEST_UNSET}/schema.json")
    );
    assert_eq!(spec.cwd.as_deref(), Some("${RS_BUBBLE_TEST_UNSET}/work"));
    assert_eq!(
        spec.env.values.get("HOME").map(|v| v.0.as_str()),
        Some("${RS_BUBBLE_TEST_UNSET}/home")
    );
    assert_eq!(
        spec.env.env_file.as_deref(),
        Some("${RS_BUBBLE_TEST_UNSET}/.env")
    );
    assert_eq!(
        spec.net,
        crate::spec::net::NetConfig::Proxy {
            allow: vec!["${RS_BUBBLE_TEST_UNSET}:443".to_string()],
            allow_private: false
        }
    );
    assert_eq!(
        spec.seccomp.block,
        Some(vec!["ptrace".to_string(), "mount".to_string()])
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
    let spec = parse(r#"{ "$schema": "./ai-bubble.spec.schema.json" }"#);
    assert_eq!(spec.schema.as_deref(), Some("./ai-bubble.spec.schema.json"));
    // It must be advertised in the generated schema (it's a real
    // field with skip_serializing), so editors accept it.
    let schema: serde_json::Value = serde_json::from_str(&crate::spec_schema()).unwrap();
    assert!(schema["properties"]["$schema"].is_object());
}

#[test]
fn redirect_sources_are_resolved_relative_to_the_spec_dir() {
    let dir = std::env::temp_dir().join(format!("ai-bubble-spec-redirect-{}", std::process::id()));
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
    let schema: serde_json::Value = serde_json::from_str(&crate::spec_schema()).unwrap();
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
            crate::spec_schema().contains(&format!("\"{tag}\"")),
            "{tag} mapping missing from schema"
        );
    }
    // deny_unknown_fields on Spec must surface in the schema.
    assert_eq!(schema["additionalProperties"], false);
    // The hand-written TmpfsPerms schema: number or octal string.
    // The hand-written TmpfsPerms schema is inlined, not a $ref.
    assert!(crate::spec_schema().contains(r#""pattern": "^[0-7]{1,4}$""#));
    assert_eq!(schema["$defs"], serde_json::Value::Null);
}

#[test]
fn no_spec_dir_no_hide() {
    // Without a spec file (and thus without a spec directory) nothing
    // is hidden: the spec stays empty.
    let dir = std::env::temp_dir().join(format!("ai-bubble-spec-nohide-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let saved = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();
    let spec = Spec::load(None);
    std::env::set_current_dir(saved).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(spec, Spec::default());
    assert!(!spec.hostfs.patterns().has_patterns());
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
        crate::spec::net::NetConfig::Proxy { allow: vec![], allow_private: false }
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
            { "type": "rw", "glob": "${RS_BUBBLE_TEST_SPEC_HOME}/project" },
            { "type": "bind", "src": "${RS_BUBBLE_TEST_SPEC_HOME}/etc" }
        ] } }"#,
    )
    .unwrap();
    // SAFETY: the variable name is unique to this test, so parallel
    // tests never race on it.
    unsafe { std::env::set_var("RS_BUBBLE_TEST_SPEC_HOME", "/home/me") };
    let spec = Spec::load(Some(&dir));
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_SPEC_HOME") };
    std::fs::remove_dir_all(&dir).ok();
    use crate::spec::hostfs::Mapping;
    match &spec.hostfs.mappings[0] {
        Mapping::Rw { glob } => assert_eq!(glob.0, vec!["/home/me/project"]),
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
fn unset_env_vars_are_an_error_and_refs_expand() {
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
    // The bare $VAR form expands, too — shell semantics now.
    unsafe { std::env::set_var("RS_BUBBLE_TEST_VAR", "v") };
    assert_eq!(expand_str("$RS_BUBBLE_TEST_VAR/x").unwrap(), "v/x");
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_VAR") };
}

#[test]
fn env_expansion_applies_only_to_path_like_mapping_fields() {
    use crate::hostfs::patterns::{Patterns, Permission};

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
    assert_eq!(
        spec.hostfs.patterns(),
        Patterns::new(vec![
            ("/home/me/project".to_string(), Permission::Ro),
            ("/home/me/empty".to_string(), Permission::Empty),
            ("/home/me/dev".to_string(), Permission::Empty),
            ("/home/me/tmp".to_string(), Permission::Empty),
            ("/home/me/proc".to_string(), Permission::Empty),
            ("/home/me/dest".to_string(), Permission::Empty),
            (
                "/home/me/at".to_string(),
                Permission::Redirect {
                    source: PathBuf::from("/home/me/src"),
                    writable: true
                }
            ),
        ])
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
    let spec = parse(r#"{ "net": { "mode": "proxy", "allow": ["${RS_BUBBLE_TEST_HOME}:443"] } }"#);
    assert_eq!(
        spec.net,
        crate::spec::net::NetConfig::Proxy {
            allow: vec!["${RS_BUBBLE_TEST_HOME}:443".to_string()],
            allow_private: false
        }
    );
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_HOME") };
}

#[test]
fn unset_env_var_in_a_mapping_field_is_a_deserialize_error() {
    unsafe { std::env::remove_var("RS_BUBBLE_TEST_UNSET") };
    assert!(serde_json::from_str::<Spec>(
        r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "${RS_BUBBLE_TEST_UNSET}/x" } ] } }"#
    )
    .is_err());
    // The same reference outside the mapping fields is accepted (in
    // proxy mode — a `net` object must name its `mode`).
    assert!(
        serde_json::from_str::<Spec>(
            r#"{ "net": { "mode": "proxy", "allow": ["${RS_BUBBLE_TEST_UNSET}:443"] } }"#
        )
        .is_ok()
    );
}
