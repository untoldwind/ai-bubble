//! The `init` sub-command: bootstrap a spec directory (`.ai-bubble` by
//! default) with a starter `spec.json` and the matching JSON Schema, so
//! `ai-bubble run -- /bin/sh` works out of the box.

use std::path::{Path, PathBuf};

use crate::{sandbox, spec};

/// The starter spec written by `init`, as a template. The
/// `{{PROJECT_DIR}}` placeholder is replaced with the JSON-quoted absolute
/// path of the project directory (the current directory), so the spec
/// pins down one exact host path instead of relying on `$PWD` being set
/// and pointing where the user expects.
///
/// It exposes just enough of the host (the usual `/bin`, `/etc`, `/lib`,
/// `/lib64`, `/usr` trees, plus a fresh `/dev`, `/tmp` and `/proc`) to let
/// a shell and common tools run, and passes the host's `PATH`/`HOME`
/// through — a safe starting point to tighten from. The `$schema`
/// reference points at the schema file `init` writes next to it.
const STARTER_SPEC_TEMPLATE: &str = r#"{
  "$schema": "./ai-bubble.spec.schema.json",
  "hostfs": {
    "mappings": [
      { "type": "rw", "glob": {{PROJECT_DIR}} },
      { "type": "ro", "globs": ["/bin", "/etc", "/lib", "/lib64", "/usr"] },
      { "type": "project-cache", "path": ["${HOME}/.cargo", "${HOME}/.local", "${HOME}/.config/opencode"] },
      { "type": "session-cache", "path": "${HOME}/.cache" },
      { "type": "dev" },
      { "type": "tmpfs", "path": "/tmp", "perms": "1777" },
      { "type": "proc" }
    ]
  },
  "cwd": {{PROJECT_DIR}},
  "net": { "mode": "host" },
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

/// Bootstraps the spec directory `dir` (defaulting to `.ai-bubble` in the
/// current directory) if it does not exist yet: creates it, writes a
/// starter `spec.json` and the JSON Schema for it. An existing directory
/// is left completely untouched.
///
/// When the current directory is a git repository, the spec directory is
/// also added to its `.gitignore` (created if missing, extended
/// otherwise), so the bootstrap stays out of version control.
pub fn init(spec_dir: Option<&Path>) {
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

    // The project directory is the current directory: that is what the
    // starter spec maps and uses as `cwd`. Resolve it to an absolute path
    // so the spec no longer depends on `${PWD}`.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let project_dir = absolute(&cwd);

    let spec_path = dir.join(spec::file::SPEC_FILE);
    if let Err(e) = std::fs::write(&spec_path, starter_spec(&project_dir)) {
        sandbox::die(&format!("Can't write {}: {e}", spec_path.display()));
    }

    let schema_path = dir.join(SCHEMA_FILE);
    if let Err(e) = std::fs::write(&schema_path, crate::spec_schema()) {
        sandbox::die(&format!("Can't write {}: {e}", schema_path.display()));
    }

    ensure_ignored(&project_dir, &absolute(&dir));

    eprintln!(
        "Bootstrapped {} ({} + {})",
        dir.display(),
        spec::file::SPEC_FILE,
        SCHEMA_FILE
    );
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

/// Adds `spec_dir` to the `.gitignore` of `project_dir` when that is a git
/// repository. A missing `.gitignore` is created; an existing one is kept
/// and only extended. Nothing happens when `project_dir` is not a git
/// repository or when `spec_dir` lies outside it (an ignore rule can only
/// describe paths below the `.gitignore`'s own directory).
fn ensure_ignored(project_dir: &Path, spec_dir: &Path) {
    if !project_dir.join(".git").exists() {
        return;
    }
    let Some(entry) = gitignore_entry(project_dir, spec_dir) else {
        return;
    };

    let path = project_dir.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Already ignored? Accept the entry with and without the trailing
    // slash, and tolerate surrounding whitespace.
    let bare = entry.trim_end_matches('/');
    if existing
        .lines()
        .any(|line| line.trim() == entry || line.trim() == bare)
    {
        return;
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&entry);
    updated.push('\n');

    if let Err(e) = std::fs::write(&path, updated) {
        eprintln!("warning: can't update {}: {e}", path.display());
    }
}

/// The `.gitignore` line that ignores `spec_dir`, relative to
/// `project_dir` and slash-terminated (so it matches a directory), or
/// `None` when `spec_dir` is not inside `project_dir`.
fn gitignore_entry(project_dir: &Path, spec_dir: &Path) -> Option<String> {
    let relative = spec_dir.strip_prefix(project_dir).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    let mut entry = relative.to_string_lossy().replace('\\', "/");
    entry.push('/');
    Some(entry)
}

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
        init(Some(&dir.0));

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

        init(Some(&dir.0));

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
    fn gitignore_entry_is_relative_and_slash_terminated() {
        assert_eq!(
            gitignore_entry(Path::new("/repo"), Path::new("/repo/.ai-bubble")),
            Some(".ai-bubble/".to_string())
        );
        assert_eq!(
            gitignore_entry(Path::new("/repo"), Path::new("/repo")),
            None
        );
        assert_eq!(
            gitignore_entry(Path::new("/repo"), Path::new("/other/.ai-bubble")),
            None
        );
    }

    #[test]
    fn ensure_ignored_creates_a_gitignore() {
        let dir = TempDir::new("gitignore-create");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        let text = std::fs::read_to_string(dir.0.join(".gitignore")).unwrap();
        assert!(text.lines().any(|line| line == ".ai-bubble/"), "{text:?}");
    }

    #[test]
    fn ensure_ignored_extends_an_existing_gitignore() {
        let dir = TempDir::new("gitignore-extend");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();
        std::fs::write(dir.0.join(".gitignore"), "/target").unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        let text = std::fs::read_to_string(dir.0.join(".gitignore")).unwrap();
        assert!(text.starts_with("/target\n"), "{text:?}");
        assert!(text.lines().any(|line| line == ".ai-bubble/"), "{text:?}");
    }

    #[test]
    fn ensure_ignored_is_idempotent_and_respects_a_bare_entry() {
        let dir = TempDir::new("gitignore-idempotent");
        std::fs::create_dir_all(dir.0.join(".git")).unwrap();
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();
        std::fs::write(dir.0.join(".gitignore"), ".ai-bubble\n").unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        // The existing bare entry already covers it: nothing is appended.
        assert_eq!(
            std::fs::read_to_string(dir.0.join(".gitignore")).unwrap(),
            ".ai-bubble\n"
        );
    }

    #[test]
    fn ensure_ignored_skips_non_repositories() {
        let dir = TempDir::new("gitignore-norepo");
        std::fs::create_dir_all(dir.0.join(".ai-bubble")).unwrap();

        ensure_ignored(&dir.0, &dir.0.join(".ai-bubble"));

        assert!(!dir.0.join(".gitignore").exists());
    }
}
