//! The `init` sub-command: bootstrap a spec directory (`.ai-bubble` by
//! default) with a starter `spec.json` and the matching JSON Schema, so
//! `ai-bubble run -- /bin/sh` works out of the box.

use clap::Args;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::{sandbox, spec};

/// Bootstrap the spec directory (`.ai-bubble`, or `--spec-dir DIR`) if
/// it does not exist yet (see the CLI docs for the full behaviour).
#[derive(Debug, Args, PartialEq, Default)]
pub struct InitCommand;

/// The starter spec written by `init`, as a template. The
/// `{{PROJECT_DIR}}` placeholder is replaced with the JSON-quoted absolute
/// path of the project directory (the current directory), so the spec
/// pins down one exact host path instead of relying on `$PWD` being set
/// and pointing where the user expects.
///
/// It exposes just enough of the host (the usual `/bin`, `/etc`, `/lib`,
/// `/lib64`, `/usr` trees, plus a fresh `/dev`, `/tmp` and `/proc`) to let
/// a shell and common tools run, and passes the host's `PATH`/`HOME`
/// through — a safe starting point to tighten from. It also leads by
/// example on resource limits (AUDIT.md M4): `nproc`/`nofile` rlimits and
/// a `size` cap on the `/tmp` tmpfs, so a fork bomb or a tmpfs-filling
/// command hits a per-command brake instead of the invoking user's global
/// budgets (there is no cgroup limiting; see `spec::rlimits`). The `$schema`
/// reference points at the schema file `init` writes next to it.
const STARTER_SPEC_TEMPLATE: &str = r#"{
  "$schema": "./ai-bubble.spec.schema.json",
  "hostfs": {
    "mappings": [
      { "type": "rw", "glob": {{PROJECT_DIR}} },
      { "type": "ro", "glob": ["/bin", "/etc", "/lib", "/lib64", "/usr"] },
      { "type": "project-cache", "path": ["${HOME}/.cargo", "${HOME}/.local", "${HOME}/.config/opencode"] },
      { "type": "session-cache", "path": "${HOME}/.cache" },
      { "type": "dev" },
      { "type": "tmpfs", "path": "/tmp", "perms": "1777", "size": 1073741824 },
      { "type": "proc" }
    ]
  },
  "cwd": {{PROJECT_DIR}},
  "seccomp": { "preset": "default" },
  "net": { "mode": "proxy", "allow": ["example.com:443"] },
  "rlimits": { "nproc": 1024, "nofile": 4096 },
  "env": {
    "values": { "PATH": "${PATH}", "HOME": "${HOME}", "TERM": "${TERM}" }
  }
}
"#;

/// The name of the schema file `init` drops next to the starter spec, so
/// the spec's `$schema` reference resolves without a separate
/// `--print-schema` round-trip.
const SCHEMA_FILE: &str = "ai-bubble.spec.schema.json";

/// Renders the starter spec for `project_dir`: the template with the
/// `{{PROJECT_DIR}}` placeholder replaced by the directory's absolute
/// path as a JSON string (so awkward characters in the path — quotes,
/// backslashes — cannot break the JSON or inject spec fields).
fn starter_spec(project_dir: &Path) -> String {
    let quoted = serde_json::to_string(project_dir.to_string_lossy().as_ref())
        .expect("serializing a path string cannot fail");
    STARTER_SPEC_TEMPLATE.replace("{{PROJECT_DIR}}", &quoted)
}

impl InitCommand {
    /// Bootstraps the spec directory `dir` (defaulting to `.ai-bubble` in the
    /// current directory) if it does not exist yet: creates it, writes a
    /// starter `spec.json` and the JSON Schema for it. An existing directory
    /// is left completely untouched.
    ///
    /// When the current directory is a git repository, a `.gitignore`
    /// containing a single `*` entry is created inside the spec directory
    /// (unless one already exists), so its contents — above all the
    /// disposable cache backing store — stay out of version control. The
    /// project directory's own `.gitignore` is deliberately left untouched.
    /// Note the trade-off: with everything ignored, tampering with
    /// `spec.json` no longer shows up in `git status`, so keep a reviewable
    /// copy of the policy elsewhere if that matters.
    pub fn run(self, spec_dir: Option<&Path>) {
        let dir = spec_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(spec::file::DEFAULT_SPEC_DIR));

        if dir.exists() {
            eprintln!("{} already exists; leaving it untouched", dir.display());
            return;
        }

        if let Err(e) = std::fs::create_dir_all(&dir) {
            sandbox::die(&format!("Can't create {}: {e}", dir.display()));
        }
        // AUDIT.md L10: the spec directory holds the env file with its
        // secrets. `create_dir_all` honors the umask (typically 0755), so the
        // mode is enforced explicitly after creation.
        if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
            sandbox::die(&format!("Can't set the mode of {}: {e}", dir.display()));
        }

        // The project directory is the current directory: that is what the
        // starter spec maps and uses as `cwd`. Resolve it to an absolute path
        // so the spec no longer depends on `${PWD}`.
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let project_dir = absolute(&cwd);

        let spec_path = dir.join(spec::file::SPEC_FILE);
        if let Err(e) = std::fs::write(&spec_path, starter_spec(&project_dir)) {
            sandbox::die(&format!("Can't write {}: {e}", spec_path.display()));
        }
        if let Err(e) = std::fs::set_permissions(&spec_path, std::fs::Permissions::from_mode(0o600))
        {
            sandbox::die(&format!(
                "Can't set the mode of {}: {e}",
                spec_path.display()
            ));
        }

        let schema_path = dir.join(SCHEMA_FILE);
        if let Err(e) = std::fs::write(&schema_path, crate::spec_schema()) {
            sandbox::die(&format!("Can't write {}: {e}", schema_path.display()));
        }

        ensure_ignored(&project_dir, &absolute(&dir));

        // The spec directory's contents are now ignored via its own
        // `.gitignore`. The security policy (`spec.json`, the env file with
        // its secrets) therefore no longer shows up in `git status`: warn
        // the user so they keep a reviewable copy of the policy elsewhere.
        eprintln!(
            "warning: {} holds the security policy (spec.json, env file, cache) and is a trusted, \
         tamper-sensitive asset — its contents are gitignored, so tampering will not show up \
         in `git status`; keep the policy under review another way",
            dir.display()
        );

        eprintln!(
            "Bootstrapped {} ({} + {})",
            dir.display(),
            spec::file::SPEC_FILE,
            SCHEMA_FILE
        );
    }
}

/// Canonicalizes `path` if possible, so relative paths and symlinks are
/// resolved against the current directory; falls back to the path as
/// given when it cannot be canonicalized.
fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

/// Creates a `.gitignore` with a single `*` entry inside `spec_dir` when
/// the project directory is a git repository, so nothing within the spec
/// directory is tracked by git. The project directory's own `.gitignore`
/// is deliberately left untouched. An existing `.gitignore` inside the
/// spec directory is never modified — the user may have narrowed or
/// widened the ignore rules deliberately.
fn ensure_ignored(project_dir: &Path, spec_dir: &Path) {
    if !project_dir.join(".git").exists() {
        return;
    }
    let path = spec_dir.join(GITIGNORE_FILE);
    if path.exists() {
        return;
    }
    if let Err(e) = std::fs::write(&path, GITIGNORE_ALL_CONTENTS) {
        eprintln!("warning: can't write {}: {e}", path.display());
    }
}

/// The name of the `.gitignore` `init` creates *inside* the spec directory.
const GITIGNORE_FILE: &str = ".gitignore";

/// The contents of that `.gitignore`: ignore everything in the spec
/// directory (cache, env file, …).
const GITIGNORE_ALL_CONTENTS: &str = "*\n";

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp path for one test, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "ai-bubble-init-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn bootstraps_a_missing_directory() {
        let dir = TempDir::new("missing");
        InitCommand.run(Some(&dir.0));

        let spec_path = dir.0.join("spec.json");
        assert!(spec_path.is_file());
        assert!(dir.0.join("ai-bubble.spec.schema.json").is_file());

        // The starter spec is syntactically valid JSON (the `${VAR}`
        // references are only expanded when the spec is actually read).
        let text = std::fs::read_to_string(&spec_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(!value["hostfs"]["mappings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn leaves_an_existing_directory_untouched() {
        let dir = TempDir::new("existing");
        std::fs::create_dir_all(&dir.0).unwrap();
        std::fs::write(dir.0.join("spec.json"), r#"{"keep": true}"#).unwrap();

        InitCommand.run(Some(&dir.0));

        assert_eq!(
            std::fs::read_to_string(dir.0.join("spec.json")).unwrap(),
            r#"{"keep": true}"#
        );
        assert!(!dir.0.join("ai-bubble.spec.schema.json").exists());
    }

    #[test]
    fn starter_spec_pins_the_absolute_project_directory() {
        let spec = starter_spec(Path::new("/home/me/project"));
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();

        assert_eq!(
            value["hostfs"]["mappings"][0]["glob"],
            serde_json::json!("/home/me/project")
        );
        assert_eq!(value["cwd"], serde_json::json!("/home/me/project"));
        // The environment references are still expanded at read time.
        assert_eq!(value["env"]["values"]["PATH"], serde_json::json!("${PATH}"));
    }

    #[test]
    fn starter_spec_escapes_awkward_paths() {
        let spec = starter_spec(Path::new("/tmp/we\"ird\\path"));
        // Must stay valid JSON, with the path preserved verbatim.
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(value["cwd"], serde_json::json!("/tmp/we\"ird\\path"));
    }

    #[test]
    fn ensure_ignored_creates_a_gitignore_in_the_spec_dir() {
        let dir = TempDir::new("gitignore-create");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        // The spec directory's own `.gitignore` ignores everything.
        let text = std::fs::read_to_string(dir.0.join(".ai-bubble/.gitignore")).unwrap();
        assert_eq!(text, "*\n");
        // The project directory's `.gitignore` must NOT be touched.
        assert!(!dir.0.join(".gitignore").exists(), "{text:?}");
    }

    #[test]
    fn ensure_ignored_leaves_an_existing_gitignore_untouched() {
        let dir = TempDir::new("gitignore-existing");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();
        std::fs::write(dir.0.join(".ai-bubble/.gitignore"), "/cache/\n").unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        assert_eq!(
            std::fs::read_to_string(dir.0.join(".ai-bubble/.gitignore")).unwrap(),
            "/cache/\n"
        );
    }

    #[test]
    fn ensure_ignored_is_idempotent() {
        let dir = TempDir::new("gitignore-idempotent");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));
        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        assert_eq!(
            std::fs::read_to_string(dir.0.join(".ai-bubble/.gitignore")).unwrap(),
            "*\n"
        );
    }

    #[test]
    fn ensure_ignored_skips_non_repositories() {
        let dir = TempDir::new("gitignore-norepo");
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        assert!(!dir.0.join(".ai-bubble/.gitignore").exists());
    }

    /// AUDIT.md M4: the starter spec must lead by example on resource
    /// limits — `rlimits` set (nproc/nofile) and a `size` cap on the
    /// `/tmp` tmpfs — and of course stay a valid spec.
    #[test]
    fn starter_spec_is_valid_and_sets_resource_limits() {
        let rendered = starter_spec(std::path::Path::new("/home/me/project"));
        let spec: crate::spec::Spec =
            serde_json::from_str(&rendered).expect("the starter spec must parse as a Spec");

        assert_eq!(spec.rlimits.nproc, Some(1024));
        assert_eq!(spec.rlimits.nofile, Some(4096));

        let tmpfs = spec
            .hostfs
            .mappings
            .iter()
            .find_map(|m| match m {
                crate::spec::hostfs::Mapping::Tmpfs { path, size, .. }
                    if path.0 == ["/tmp".to_string()] =>
                {
                    Some(*size)
                }
                _ => None,
            })
            .expect("the starter spec has a /tmp tmpfs mapping");
        assert_eq!(
            tmpfs,
            Some(1073741824),
            "the /tmp tmpfs must be size-capped"
        );
    }
}
