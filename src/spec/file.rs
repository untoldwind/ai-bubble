//! The spec file itself (JSON): the config-file view of the sandbox
//! specification, and everything that maps 1:1 onto what the user writes.
//!
//! The default location is `.rs-bubble/spec.json` in the current
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
//!     { "type": "redirect-ro", "dest": "/bla", "source": "/otherdir" }
//!   ] },
//!   "net": { "isolated": true, "allow": ["example.com:443"] }
//! }
//! ```
//!
//! All fields are optional: without `net.isolated` the command shares the
//! host network. `allow` is the proxy allow-list; an empty list (or a
//! missing `allow`) allows every target. Nothing is mounted
//! automatically: procfs only appears where the spec asks for it (a
//! `proc` mapping). The `hostfs` mappings make the FUSE filesystem the
//! sandbox root — `ro`/`rw`/`hide` mirror or hide host paths, while the
//! mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`) expose
//! a path empty *and* stack the corresponding mount op on top of it;
//! `symlink` mappings only add a symlink op. All the ops a spec produces
//! are applied in mapping order. Without any mappings the sandbox gets a
//! plain tmpfs root and no FUSE filesystem is started.
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

use std::path::Path;

use serde::Deserialize;

use schemars::JsonSchema;

use super::hostfs::HostFsConfig;
use super::net::NetConfig;

/// The default spec directory, looked up relative to the current
/// directory.
pub const DEFAULT_SPEC_DIR: &str = ".rs-bubble";

/// The name of the spec file inside the spec directory.
pub const SPEC_FILE: &str = "spec.json";

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
    /// Accepted for editor tooling only: it names the JSON schema
    /// (`--print-schema`) so the spec file can get completion and
    /// validation. Never serialized back out.
    #[serde(rename = "$schema", default, skip_serializing)]
    pub schema: Option<String>,
}

impl Spec {
    /// Load the spec from the spec directory (typically `--spec-dir DIR`
    /// or the default `.rs-bubble`). The directory is expected to contain
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
                }
                spec
            }
            Err(e) => crate::sandbox::die(&format!("Invalid spec file {}: {e}", path.display())),
        }
    }
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
