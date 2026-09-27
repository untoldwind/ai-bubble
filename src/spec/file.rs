//! The spec file itself (JSON): the config-file view of the sandbox
//! specification, and everything that maps 1:1 onto what the user writes.
//!
//! The default location is `.ai-bubble/spec.json` in the current
//! directory; `--spec-dir DIR` on the command line overrides it.
//!
//! Format:
//!
//! ```json
//! {
//!   "hostfs": { "mappings": [
//!     { "type": "ro",    "glob": "/usr" },
//!     { "type": "bind",  "path": "/etc" },
//!     { "type": "dev" },
//!     { "type": "tmpfs", "path": "/tmp", "perms": "1777", "size": 1048576 },
//!     { "type": "symlink", "src": "usr/bin", "dest": "/bin" },
//!     { "type": "redirect-ro", "dest": "/bla", "source": "/otherdir" },
//!     { "type": "session-cache", "path": "/home/me/.cache" },
//!     { "type": "project-cache", "path": "/home/me/.local" }
//!   ] },
//!   "net": { "isolated": true, "allow": ["example.com:443", "*.github.com"] },
//!   "env": {
//!     "values": { "PATH": "${PATH}", "HOME": "${HOME}" },
//!     "env_file": ".env"
//!   },
//!   "cwd": "/work"
//! }
//! ```
//!
//! All fields are optional: without `net.isolated` the command shares the
//! host network. `allow` is the proxy allow-list; entries are
//! `HOST[:PORT]`, and an entry host may start with `*.` to match any
//! subdomains of that domain (but not the domain itself); an empty list (or a
//! missing `allow`) allows every target. Nothing is mounted
//! automatically: procfs only appears where the spec asks for it (a
//! `proc` mapping). The `hostfs` mappings make the FUSE filesystem the
//! sandbox root — `ro`/`rw`/`hide` mirror or hide host paths, while the
//! mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`) expose
//! a path empty *and* stack the corresponding mount op on top of it;
//! `symlink` mappings only add a symlink op. All the ops a spec produces
//! are applied in mapping order. Without any mappings the sandbox gets a
//! plain tmpfs root and no FUSE filesystem is started. The cache mappings
//! (`session-cache`, `project-cache`) are a writable redirect onto a
//! per-run tmp directory (wiped when ai-bubble terminates) or the spec
//! directory's `cache` folder, respectively.
//!
//! This is only the *file* view: the sandbox machinery runs with the
//! compiled-down internal representation in `crate::spec::internal`.
//!
//! Environment variables: the path-like fields of the hostfs mappings
//! (`glob`, `path`, `src`, `dest`, `source`) may reference environment
//! variables as `${VAR}` (e.g. `"glob": "${HOME}/project"`). Expansion
//! happens per field, while the spec is deserialized (see
//! [`super::hostfs::env_string`]) — so everything downstream only ever
//! sees the fully expanded text. Other fields (e.g. `net.allow`) are
//! never expanded. Referencing an unset variable is an error.
//!
//! The environment: the sandboxed command does *not* inherit the host's
//! environment — like the filesystem, the environment is isolated, and
//! the `env` section decides what exists inside it (see
//! [`super::env`]). Its `values` map may use `${VAR}` to copy host
//! variables in explicitly, and its optional `env_file` loads
//! dotenv-style entries from a file next to the spec. Without an `env`
//! section (or with an empty one) the command runs with an empty
//! environment.
//!
//! The working directory: `cwd` sets the directory the command starts
//! in *inside* the sandbox (default: `/`). Like the path-like mapping
//! fields it may use `${VAR}` references, must be an absolute sandbox
//! path without `..` components, and must exist inside the sandbox (be
//! it through a hostfs mapping or as a mount point).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use schemars::JsonSchema;

use super::env::EnvConfig;
use super::hostfs::HostFsConfig;
use super::net::NetConfig;

/// The default spec directory, looked up relative to the current
/// directory.
pub const DEFAULT_SPEC_DIR: &str = ".ai-bubble";

/// The name of the spec file inside the spec directory.
pub const SPEC_FILE: &str = "spec.json";

/// The host path of the spec directory as an absolute glob pattern:
/// canonicalized when possible, otherwise resolved against the current
/// directory — so the auto-hide pattern (see [`Spec::hide_spec_dir`])
/// always matches host-absolute mirrored paths.
fn absolute_dir(dir: &Path) -> PathBuf {
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if dir.is_absolute() {
        dir
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(dir),
            Err(_) => dir,
        }
    }
}

/// The whole sandbox specification, as written by the user. Parsing
/// only — no side effects beyond reading the file. The sandbox machinery
/// never sees this type; it runs with the compiled-down
/// `internal::SandboxConfig`.
#[derive(Debug, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    /// Isolated-network configuration.
    pub net: NetConfig,
    /// The host filesystem: it is always the sandbox root, exposing the
    /// paths selected by its mappings.
    pub hostfs: HostFsConfig,
    /// The isolated environment: the *complete* set of environment
    /// variables the sandboxed command sees. Nothing is inherited from
    /// the host; use `${VAR}` in the values to copy host variables in
    /// explicitly, and `env_file` to load dotenv-style entries from a
    /// file (see [`super::env`]).
    pub env: EnvConfig,
    /// The working directory of the sandboxed command, *inside* the
    /// sandbox (default: `/`). Like the path-like mapping fields the
    /// value may reference host environment variables as `${VAR}`; it
    /// must be an absolute sandbox path without `..` components. The
    /// directory must exist inside the sandbox — in hostfs-root mode
    /// through a mapping, on the tmpfs root because a mount or symlink
    /// created it. Nothing is created automatically: a missing directory
    /// is a hard error right before exec.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "cwd_string"
    )]
    pub cwd: Option<String>,
    /// Accepted for editor tooling only: it names the JSON schema
    /// (`--print-schema`) so the spec file can get completion and
    /// validation. Never serialized back out.
    #[serde(rename = "$schema", default, skip_serializing)]
    pub schema: Option<String>,
}

impl Spec {
    /// Load the spec from the spec directory (typically `--spec-dir DIR`
    /// or the default `.ai-bubble`). The directory is expected to contain
    /// a `spec.json` file. A missing default spec directory is fine: an
    /// empty spec (empty root, no mounts, host network) is used in that
    /// case, while an explicit `--spec-dir` that cannot be read is a hard
    /// error.
    pub fn load(explicit: Option<&Path>) -> Spec {
        match explicit {
            Some(dir) => Self::read(&dir.join(SPEC_FILE)),
            None => {
                let path = Path::new(DEFAULT_SPEC_DIR).join(SPEC_FILE);
                if path.exists() {
                    Self::read(&path)
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
        match serde_json::from_str::<Spec>(&text) {
            Ok(mut spec) => {
                // Redirect sources may be relative: they are resolved
                // relative to the directory the spec file lives in.
                if let Some(dir) = path.parent() {
                    spec.hostfs.resolve_relative_sources(dir);
                    // Same for the env file: it is resolved against the
                    // spec directory and its entries merged into
                    // `env.values` right away.
                    if let Err(e) = spec.env.load_env_file(dir) {
                        crate::sandbox::die(&e);
                    }
                    // The spec directory itself is always hidden from the
                    // sandboxed command — no matter what the spec maps:
                    // `spec.json`, the env file, and the project cache
                    // must never be visible inside the sandbox, even when
                    // a mapping mirrors the directory containing them.
                    spec.hide_spec_dir(dir);
                }
                spec
            }
            Err(e) => crate::sandbox::die(&format!("Invalid spec file {}: {e}", path.display())),
        }
    }

    /// Append a `hide` mapping for `spec_dir` (the directory containing
    /// the spec file) to the hostfs mappings. Hide patterns always win —
    /// a hidden directory hides its whole subtree — so this keeps the
    /// spec directory (and everything in it, like `spec.json` and the
    /// project cache) invisible inside the sandbox even when another
    /// mapping mirrors the directory containing it. Redirect sources are
    /// unaffected: they resolve the host path directly, without consulting
    /// the pattern list, so `project-cache` mappings keep working.
    ///
    /// The pattern is the spec directory's absolute host path, matched
    /// literally by every ordinary component (a glob metacharacter in a
    /// directory name would be interpreted as a wildcard — which can only
    /// ever hide *more*, never expose the spec directory).
    pub fn hide_spec_dir(&mut self, spec_dir: &Path) {
        self.hostfs.mappings.push(super::hostfs::Mapping::Hide {
            glob: absolute_dir(spec_dir).to_string_lossy().into_owned(),
        });
    }
}

/// Deserialize the spec's `cwd` field: a `${VAR}`-expanded, absolute
/// sandbox path without `..` components (see [`expand_str`] and
/// [`Spec::cwd`]). The checks run at parse time so a bad working
/// directory is reported like any other spec error, not as a late
/// failure right before exec.
fn cwd_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let raw = String::deserialize(deserializer)?;
    let expanded = expand_str(&raw).map_err(serde::de::Error::custom)?;
    let path = Path::new(&expanded);
    if !path.is_absolute() {
        return Err(serde::de::Error::custom(format!(
            "cwd {expanded:?} is not an absolute sandbox path"
        )));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(serde::de::Error::custom(format!(
            "cwd {expanded:?} must not contain \"..\" components"
        )));
    }
    Ok(Some(expanded))
}

/// Expand the `${VAR}` references in one string. Only the `${VAR}` form
/// is recognized (not bare `$VAR`), so a literal `$` stays untouched.
/// Used by the path-like mapping fields (see
/// [`super::hostfs::env_string`]); unset variables (and empty or
/// unterminated references) are errors, so typos don't silently produce
/// bogus paths.
pub(crate) fn expand_str(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                if name.is_empty() {
                    return Err("empty environment-variable reference \"${}\"".to_string());
                }
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    Err(_) => {
                        return Err(format!(
                            "environment variable {name:?} referenced as {s:?} is not set"
                        ));
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                // No closing brace: leave the rest as it is.
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}
