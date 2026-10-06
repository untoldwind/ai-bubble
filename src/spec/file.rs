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
//!     { "type": "ro",    "globs": ["/usr", "/lib"] },
//!     { "type": "bind",  "path": "/etc" },
//!     { "type": "dev" },
//!     { "type": "tmpfs", "path": "/tmp", "perms": "1777", "size": 1048576 },
//!     { "type": "symlink", "src": "usr/bin", "dest": "/bin" },
//!     { "type": "redirect-ro", "dest": "/bla", "source": "/otherdir" },
//!     { "type": "session-cache", "path": "/home/me/.cache" },
//!     { "type": "project-cache", "path": "/home/me/.local" }
//!   ] },
//!   "net": { "mode": "proxy", "allow": ["example.com:443", "*.github.com"] },
//!   "audit": { "log": "${HOME}/.cache/ai-bubble/audit.jsonl" },
//!   "env": {
//!     "values": { "PATH": "${PATH}", "HOME": "${HOME}" },
//!     "env_file": ".env"
//!   },
//!   "cwd": "/work",
//!   "seccomp": { "block": ["ptrace", "mount"], "on_violation": "errno" },
//!   "rlimits": { "nproc": 256, "nofile": 1024, "as": 536870912 }
//! }
//! ```
//!
//! All fields are optional: without `net` (or with `"mode": "host"`) the
//! command shares the host network. In `proxy` mode the command runs in a
//! fresh network namespace and its connections are proxied from the host
//! side, gated by `allow`: entries are `HOST[:PORT]`, and an entry host
//! may start with `*.` to match any subdomains of that domain (but not
//! the domain itself). `allow` is mandatory in proxy mode; an empty list
//! proxies nothing — every target must be listed explicitly. Nothing is mounted
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
//! variables as `${VAR}` or `$VAR` (e.g. `"glob": "${HOME}/project"`),
//! expanded with [`shellexpand`]. Expansion happens per field, while the
//! spec is deserialized (see [`super::hostfs::env_string`]) — so
//! everything downstream only ever sees the fully expanded text. Other
//! fields (e.g. `net.allow`) are never expanded. Referencing an unset
//! variable is an error.
//!
//! The environment: the sandboxed command does *not* inherit the host's
//! environment — like the filesystem, the environment is isolated, and
//! the `env` section decides what exists inside it (see
//! [`super::env`]). Its `values` map may use `${VAR}` to copy host
//! variables in explicitly, and its optional `env_file` loads
//! dotenv-style entries from a file next to the spec. The values are
//! kept as written while the file is parsed and only expanded when the
//! spec is compiled down to the internal config. Without an `env`
//! section (or with an empty one) the command runs with an empty
//! environment.
//!
//! The working directory: `cwd` sets the directory the command starts
//! in *inside* the sandbox (default: `/`). The value is kept as written
//! while the file is parsed; like the `env` values its `${VAR}`
//! references are only expanded when the spec is compiled down to the
//! internal config. The expanded value must be an absolute sandbox path
//! without `..` components, and must exist inside the sandbox (be it
//! through a hostfs mapping or as a mount point).
//!
//! The syscall filter: the `seccomp` section installs a seccomp-bpf
//! filter for the sandboxed command right before exec (see
//! [`super::seccomp`]). Either `allow` (only these syscalls may be
//! issued) or `block` (exactly these are denied) — giving both is a
//! parse error, giving neither installs no filter. A `preset` instead
//! seeds a blocklist from one of the built-in blocklists (`none`,
//! `default`, `strict`): `block` then adds to it and `allow` takes
//! exceptions back out. `on_violation` selects between `EPERM` (default)
//! and `SIGSYS` for denied syscalls.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use schemars::JsonSchema;

use super::env::EnvConfig;
use super::hostfs::HostFsConfig;
use super::net::NetConfig;
use super::seccomp::SeccompConfig;

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
    /// Audit logging: where the audit event stream (filesystem access
    /// through the hostfs mirror, waf allow/deny decisions, proxy
    /// CONNECT attempts) is written. Without a `log` path the audit
    /// subsystem is disabled (see [`super::audit::AuditConfig`]).
    #[serde(default)]
    pub audit: super::audit::AuditConfig,
    /// The isolated environment: the *complete* set of environment
    /// variables the sandboxed command sees. Nothing is inherited from
    /// the host; use `${VAR}` in the values to copy host variables in
    /// explicitly, and `env_file` to load dotenv-style entries from a
    /// file (see [`super::env`]). The values are kept as written and the
    /// `${VAR}` references are expanded when the spec is compiled down to
    /// the internal config.
    pub env: EnvConfig,
    /// The working directory of the sandboxed command, *inside* the
    /// sandbox (default: `/`). The value is kept exactly as written while
    /// the file is parsed and may reference host environment variables as
    /// `${VAR}`; the references are expanded — and the result validated as
    /// an absolute sandbox path without `..` components — when the spec is
    /// compiled down to the internal config (see [`Spec::expand_cwd`]).
    /// The directory must exist inside the sandbox — in hostfs-root mode
    /// through a mapping, on the tmpfs root because a mount or symlink
    /// created it. Nothing is created automatically: a missing directory
    /// is a hard error right before exec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The syscall filter installed for the sandboxed command right
    /// before exec (see [`super::seccomp`]). Either an `allow` or a
    /// `block` list of syscall names (mutually exclusive, enforced at
    /// parse time), a `preset` blocklist baseline (`block` adds to it,
    /// `allow` takes exceptions back out); without any of these no
    /// filter is installed.
    #[serde(default)]
    pub seccomp: SeccompConfig,
    /// Resource limits (setrlimit) for the sandboxed command, applied
    /// right before exec (see [`super::rlimits`]). They protect the host
    /// supervisor from a resource-hungry or malicious command (fork
    /// bombs, fd exhaustion, memory hoarding — AUDIT.md M4); every
    /// field is optional and absent fields mean the limit is not set.
    #[serde(default)]
    pub rlimits: super::rlimits::Rlimits,
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
        Self::try_load(explicit).unwrap_or_else(|e| crate::sandbox::die(&e))
    }

    /// The fallible [`Spec::load`]: every hard error (unreadable file,
    /// invalid JSON, failed source validation) is reported to the caller
    /// instead of killing the process. Used by `spec-reload` (see
    /// [`crate::cli::control`]): a broken spec file mid-run must be an error
    /// reply to the control client, not the end of the launcher — which
    /// is supervising a live sandbox at that point.
    pub fn try_load(explicit: Option<&Path>) -> Result<Spec, String> {
        match explicit {
            Some(dir) => Self::try_read(&dir.join(SPEC_FILE)),
            None => {
                let path = Path::new(DEFAULT_SPEC_DIR).join(SPEC_FILE);
                if path.exists() {
                    Self::try_read(&path)
                } else {
                    // Falling back to an empty policy is silent otherwise —
                    // running from the wrong CWD (or after an attacker
                    // renamed the spec dir) would quietly change the
                    // effective policy from "restricted" to "empty tmpfs
                    // root + host network" (AUDIT.md L9). Warn on stderr.
                    eprintln!(
                        "ai-bubble: warning: no spec file at {}; using an empty \
                         policy (empty tmpfs root, host network, no mappings)",
                        path.display()
                    );
                    Ok(Spec::default())
                }
            }
        }
    }

    fn try_read(path: &Path) -> Result<Spec, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Can't read spec file {}: {e}", path.display()))?;
        match serde_json::from_str::<Spec>(&text) {
            Ok(mut spec) => {
                // Redirect sources may be relative: they are resolved
                // relative to the directory the spec file lives in.
                if let Some(dir) = path.parent() {
                    spec.hostfs.resolve_relative_sources(dir);
                    // Bind and redirect sources bypass the pattern list
                    // (see `validate_sources`): reject any that cover the
                    // spec directory — now, after the relative sources
                    // have been resolved to absolute host paths.
                    spec.validate_sources(dir)?;
                    // Same for the env file: it is resolved against the
                    // spec directory and its entries merged into
                    // `env.values` (the values are still unexpanded; see
                    // `SandboxConfig::compile`).
                    spec.env.load_env_file(dir)?;
                    // The spec directory itself is always hidden from the
                    // sandboxed command — no matter what the spec maps:
                    // `spec.json`, the env file, and the project cache
                    // must never be visible inside the sandbox, even when
                    // a mapping mirrors the directory containing them.
                    // (Path-based limitation, AUDIT.md L12: a host
                    // bind-mount alias of the project tree or a
                    // case-folding filesystem can bypass this —
                    // documented in the README.)
                    spec.hide_spec_dir(dir);
                }
                // The audit log path is host path-like, too: expand its
                // `${VAR}` references here, so downstream code only ever
                // sees the fully expanded path.
                if let Some(log) = &spec.audit.log {
                    match expand_str(log) {
                        Ok(expanded) => spec.audit.log = Some(expanded),
                        Err(e) => return Err(format!("Invalid audit log path: {e}")),
                    }
                }
                Ok(spec)
            }
            Err(e) => Err(format!("Invalid spec file {}: {e}", path.display())),
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
    /// The pattern is the spec directory's absolute host path, escaped
    /// **per component** with [`crate::hostfs::pattern::escape_glob`]: a
    /// glob metacharacter in a directory name (e.g. a path segment
    /// `job[42]` — `[` always opens a character class in the matcher) must
    /// match itself literally, or the auto-hide pattern would silently
    /// fail to name the real directory and the spec directory would be
    /// exposed by any mapping that mirrors its parent.
    pub fn hide_spec_dir(&mut self, spec_dir: &Path) {
        let dir = absolute_dir(spec_dir);
        // Rebuild the absolute path as a pattern: a `/` root plus one
        // escaped component per directory level. Non-UTF-8 components are
        // lossy-converted; they can never match a pattern in
        // the first place, so every derived decision fails closed.
        let pattern = format!(
            "/{}",
            dir.components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(name) => {
                        Some(crate::hostfs::pattern::escape_glob(&name.to_string_lossy()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/")
        );
        self.hostfs.mappings.push(super::hostfs::Mapping::Hide {
            glob: super::hostfs::Globs(vec![pattern]),
        });
    }

    /// Security validation of the mappings whose host paths bypass the
    /// pattern list entirely: `bind` mounts resolve directly on the host
    /// (no FUSE policy applies to them), and `redirect-ro`/`redirect-rw`
    /// sources resolve directly too — the redirect destination is what
    /// the patterns govern, not the source. A bind or redirect whose
    /// source is the spec directory itself (or an ancestor of it) would
    /// therefore expose `.ai-bubble/` — the spec file, the env file with
    /// its secrets, and the cache — no matter how carefully the auto-hide
    /// patterns are built; with `rw: true` (or a redirect-rw) the
    /// sandboxed command could even rewrite `spec.json`, escalating the
    /// policy persistently across runs. Such mappings are rejected as a
    /// hard error at spec load time.
    ///
    /// Sources *inside* the spec directory are restricted, not outright
    /// rejected: targeting a **subdirectory** of the spec directory (and
    /// anything below it) is a deliberate, supported design — e.g. a
    /// `conf/` folder the sandbox may rewrite. But a **top-level file**
    /// inside the spec directory (its parent is the spec directory
    /// itself) is rejected — that is where `spec.json` and the env file
    /// live — and so is a top-level *entry* whose type cannot be verified
    /// as a directory (nonexistent, or a symlink to a file). Use with
    /// care: a writable source inside the spec directory is still outside
    /// the pattern-based policy and hidden from the sandbox except at its
    /// redirect destination.
    ///
    /// Deliberately *not* checked: `session-cache` (its backing store is a
    /// per-run tmp directory) and `project-cache` (its backing store is
    /// `spec_dir/cache`, which is exactly the intended, hidden location).
    /// Called by [`Spec::read`] after [`HostFsConfig::
    /// resolve_relative_sources`], so redirect sources are already
    /// absolute.
    fn validate_sources(&self, spec_dir: &Path) -> Result<(), String> {
        let spec_dir = absolute_dir(spec_dir);
        for mapping in &self.hostfs.mappings {
            let (kind, source) = match mapping {
                super::hostfs::Mapping::Bind { src, .. } => ("bind", src.as_str()),
                super::hostfs::Mapping::RedirectRo { source, .. } => {
                    ("redirect-ro", source.as_str())
                }
                super::hostfs::Mapping::RedirectRw { source, .. } => {
                    ("redirect-rw", source.as_str())
                }
                _ => continue,
            };
            // Resolve like `absolute_dir` does, so the comparison is
            // against the same canonical form as the spec dir. Redirect
            // sources are absolute by now; a bind source is required to
            // be absolute anyway.
            let source = absolute_dir(Path::new(source));
            // `starts_with` is component-wise: it is true when the source
            // *is* the spec directory and when it is a strict ancestor
            // (e.g. the project dir or `/`), but not for mere string
            // prefixes (`/repo/.ai-bubble-x`).
            if spec_dir.starts_with(&source) {
                return Err(format!(
                    "the {kind} source {} covers the spec directory {}: bind and redirect \
                     sources must not cover the spec directory — it holds the security policy \
                     (spec.json, the env file and the cache), which bind mounts and redirect \
                     sources reach without the pattern-based write policy",
                    source.display(),
                    spec_dir.display()
                ));
            }
            // A source strictly *inside* the spec directory is restricted
            // rather than rejected (see the doc comment above): the design
            // deliberately allows rewriting a conf directory kept inside
            // `.ai-bubble/`. Everything at least two levels below the spec
            // directory is allowed. A top-level entry (its parent *is* the
            // spec directory) is allowed only if it is verifiably a
            // directory — a nonexistent entry or a file (including a
            // symlink to one, since `absolute_dir` canonicalized the
            // source) is rejected, fail-closed: that is the layer where
            // `spec.json` and the env file live.
            if source.starts_with(&spec_dir) {
                let depth = source
                    .strip_prefix(&spec_dir)
                    .unwrap_or(&source)
                    .components()
                    .count();
                if depth == 1 {
                    match std::fs::metadata(&source) {
                        Ok(md) if md.is_dir() => {}
                        Ok(_) => {
                            return Err(format!(
                                "the {kind} source {} is a file directly inside the spec \
                                 directory {}: files there — spec.json, the env file — hold the \
                                 security policy and its secrets; target a path inside a \
                                 subdirectory of the spec directory instead",
                                source.display(),
                                spec_dir.display()
                            ));
                        }
                        Err(e) => {
                            return Err(format!(
                                "the {kind} source {} is directly inside the spec directory \
                                 {} and cannot be verified to be a directory ({e}); files \
                                 there — spec.json, the env file — hold the security policy \
                                 and its secrets, so only a subdirectory of the spec \
                                 directory may be targeted",
                                source.display(),
                                spec_dir.display()
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Security validation and hardening of a *replacement* mapping list
    /// applied through the control plane (SP-1): runs
    /// [`Spec::validate_sources`] (which rejects bind/redirect sources
    /// covering the spec directory) against `spec_dir` and appends the
    /// [`Spec::hide_spec_dir`] auto-hide pattern, so a runtime `fs-set`
    /// can never re-expose the spec directory or silently drop the
    /// auto-hide mapping. Returns the hardened list to swap in.
    pub(crate) fn control_plane_mapping_list(
        mut mappings: Vec<super::hostfs::Mapping>,
        spec_dir: &Path,
    ) -> Result<Vec<super::hostfs::Mapping>, String> {
        let mut spec = Spec::default();
        spec.hostfs.mappings = mappings;
        spec.validate_sources(spec_dir)?;
        spec.hide_spec_dir(spec_dir);
        mappings = spec.hostfs.mappings;
        Ok(mappings)
    }

    /// Expand and validate the [`Spec::cwd`] field for compilation: the
    /// `${VAR}` references are resolved from the **host** environment
    /// (like the `env` values, see [`expand_str`]), and the result must be
    /// an absolute sandbox path without `..` components. `None` stays
    /// `None` (the sandbox root). Called when the spec is compiled down to
    /// the internal config, so a programmatically updated spec is expanded
    /// and validated too, and a bad working directory is reported as a
    /// compile error rather than a late failure right before exec.
    pub(crate) fn expand_cwd(&self) -> Result<Option<PathBuf>, String> {
        let Some(raw) = &self.cwd else {
            return Ok(None);
        };
        let expanded = expand_str(raw).map_err(|e| format!("Invalid cwd {raw:?}: {e}"))?;
        let path = Path::new(&expanded);
        if !path.is_absolute() {
            return Err(format!("cwd {expanded:?} is not an absolute sandbox path"));
        }
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(format!(
                "cwd {expanded:?} must not contain \"..\" components"
            ));
        }
        Ok(Some(PathBuf::from(expanded)))
    }
}

/// Expand the `${VAR}` references in one string with
/// [`shellexpand`]: both the `${VAR}` and the bare `$VAR` forms are
/// recognized, as in a shell. Used by the path-like mapping fields (see
/// [`super::hostfs::env_string`]), the `env` values (see
/// [`super::env::EnvConfig::expand_values`]) and the `cwd`/audit-log
/// fields (see [`Spec::expand_cwd`]); unset variables are errors, so
/// typos don't silently produce bogus paths.
pub(crate) fn expand_str(s: &str) -> Result<String, String> {
    validate_expansion(s)?;
    shellexpand::env(s).map(Cow::into_owned).map_err(|e| {
        format!(
            "environment variable {:?} referenced as {s:?} is not set",
            e.var_name
        )
    })
}

/// Strict pre-validation of the `${VAR}` expansion syntax.
///
/// [`shellexpand`] implements more of the shell's parameter expansion than
/// this spec's promise ("referencing an unset variable is an error") allows:
/// `${VAR:-default}` silently expands an unset (or empty) variable to the
/// operator's default literal instead of erroring — which lets a
/// programmatically assembled spec smuggle an operator-unintended absolute
/// path (e.g. `${X:-/etc}`) past the post-expansion validation — and an
/// unterminated `${BOGUS` passes through expansion *verbatim*, producing a
/// bogus path instead of an error. Both (and a few more ambiguous shell
/// forms) are rejected here, fail-closed, before the expansion runs; only
/// plain `${NAME}` / `$NAME` references and a literal `$` survive:
///
/// * `${NAME:-default}` (the default-value operator) — error: unset
///   variables must error, not fall back to a literal,
/// * an unterminated `${` without a closing `}` — error,
/// * `$$` — error (in a shell this is the PID; ambiguous, and a literal
///   `$` next to a reference must be written differently),
/// * anything but a plain ASCII variable name inside `${...}` — error
///   (closes nested braces and the remaining shell operators such as
///   `:+`, `#`, `%` that would otherwise be looked up as weird names or
///   mis-parsed by shellexpand's first-`}` brace search),
/// * a bare `$` not starting a reference (before a space, punctuation,
///   or at the end of the string) — left verbatim, as before.
fn validate_expansion(s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    let mut idx = 0;
    while let Some(off) = s[idx..].find('$') {
        let dollar = idx + off;
        idx = dollar + 1;
        match bytes.get(idx) {
            // A trailing `$` stays literal, exactly as shellexpand leaves it.
            None => break,
            Some(b'{') => {
                let content_start = idx + 1;
                let Some(close_off) = s[content_start..].find('}') else {
                    return Err(format!(
                        "unterminated `${{` in {s:?}: the reference must be closed with `}}`, \
                         otherwise the text passes through expansion verbatim"
                    ));
                };
                let name = &s[content_start..content_start + close_off];
                if name.contains(":-") {
                    return Err(format!(
                        "the default-value operator `:-` in {s:?} is not supported: \
                         an unset variable must be an error, not silently expand to a default"
                    ));
                }
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err(format!(
                        "invalid variable name {name:?} in {s:?}: only ASCII letters, digits \
                         and `_` are allowed between `${{` and `}}`"
                    ));
                }
                idx = content_start + close_off + 1;
            }
            Some(b'$') => {
                return Err(format!(
                    "`$$` in {s:?} is not supported: write a plain literal `$` instead"
                ));
            }
            Some(_) => {
                // A bare `$VAR` reference: skip its name exactly the way
                // shellexpand delimits it (Unicode alphanumeric or `_`), so
                // the scan continues behind it.
                idx = s[idx..]
                    .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .map_or(s.len(), |end| idx + end);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a spec from JSON text (the file-level view only; the
    /// `${VAR}` expansion happens later, at compile time).
    fn parse(text: &str) -> Spec {
        serde_json::from_str(text).expect("valid spec JSON")
    }
    /// `try_load` reports instead of dying: an explicit spec directory
    /// that cannot be read is an error the caller controls (the run
    /// path dies on it; `spec-reload` returns it to the client).
    #[test]
    fn try_load_reports_an_unreadable_spec() {
        let dir =
            std::env::temp_dir().join(format!("ai-bubble-spec-tryload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Missing file, explicit dir: error.
        assert!(Spec::try_load(Some(&dir)).is_err());
        // Invalid JSON, explicit dir: error.
        std::fs::write(dir.join(SPEC_FILE), "{ not json").unwrap();
        assert!(Spec::try_load(Some(&dir)).is_err());
        // A source covering the spec directory: error (validation runs
        // in the fallible path too).
        std::fs::write(
            dir.join(SPEC_FILE),
            r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/" } ] } }"#,
        )
        .unwrap();
        assert!(Spec::try_load(Some(&dir)).is_err());
        // A valid spec: Ok.
        std::fs::write(
            dir.join(SPEC_FILE),
            r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "/etc" } ] } }"#,
        )
        .unwrap();
        assert!(Spec::try_load(Some(&dir)).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hide_spec_dir_escapes_metacharacters_per_component() {
        let mut spec = Spec::default();
        spec.hide_spec_dir(Path::new("/builds/job[42]/proj*2"));
        match spec.hostfs.mappings.last() {
            Some(crate::spec::hostfs::Mapping::Hide { glob }) => {
                let [pattern] = &glob.0[..] else {
                    panic!("expected a single glob")
                };
                // Every metacharacter is escaped, per component: the
                // pattern names the literal directory, not a glob.
                assert_eq!(pattern, "/builds/job\\[42\\]/proj\\*2");
            }
            other => panic!("expected a trailing hide mapping, got {other:?}"),
        }
    }

    #[test]
    fn a_metacharacter_spec_dir_is_hidden_and_a_lookalike_is_not() {
        use crate::spec::hostfs::Mapping;

        // A spec directory whose name contains `[2]` and `*`, under a
        // spec that mirrors everything.
        let parent =
            std::env::temp_dir().join(format!("ai-bubble-spec-glob-{}", std::process::id()));
        let dir = parent.join("proj[2]*");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(crate::spec::file::SPEC_FILE),
            r#"{ "hostfs": { "mappings": [ { "type": "rw", "glob": "/**" } ] } }"#,
        )
        .unwrap();
        // A lookalike sibling without the metacharacters.
        let sibling = parent.join("proj2");
        std::fs::create_dir_all(&sibling).unwrap();

        let spec = crate::spec::Spec::load(Some(&dir));
        use crate::hostfs::patterns::Permission as P;
        match spec.hostfs.mappings.last() {
            Some(Mapping::Hide { glob }) => {
                let [pattern] = &glob.0[..] else {
                    panic!("expected a single glob")
                };
                assert_eq!(
                    pattern.as_str(),
                    format!("{}/proj\\[2\\]\\*", parent.display())
                );
            }
            other => panic!("expected a trailing hide mapping, got {other:?}"),
        }

        // Through the pattern engine: the literal directory is hidden
        // (despite the rw /** mirror), the lookalike sibling is not —
        // it stays covered by the rw mirror.
        let compiled = crate::spec::internal::SandboxConfig::compile(&spec);
        let spec_path = std::fs::canonicalize(&dir).unwrap();
        let sibling_path = std::fs::canonicalize(&sibling).unwrap();
        assert_eq!(compiled.patterns.permission_of(&spec_path), Some(&P::Hide));
        assert!(compiled.patterns.hidden(&spec_path));
        assert!(!compiled.patterns.hidden(&sibling_path));
        assert_eq!(compiled.patterns.permission_of(&sibling_path), Some(&P::Rw));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn a_bind_source_covering_the_spec_dir_is_rejected() {
        // Binding `/` exposes everything — including the spec directory —
        // regardless of the hide patterns.
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/" } ] } }"#);
        let err = spec
            .validate_sources(Path::new("/repo/.ai-bubble"))
            .expect_err("a bind of / must be rejected");
        assert!(err.contains("bind"), "{err}");
        assert!(err.contains("spec directory"), "{err}");

        // The spec directory itself as a bind source is rejected, too.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/repo/.ai-bubble" } ] } }"#,
        );
        assert!(
            spec.validate_sources(Path::new("/repo/.ai-bubble"))
                .is_err()
        );
    }

    #[test]
    fn a_redirect_source_resolving_to_the_spec_dir_is_rejected() {
        // A relative source `.` resolves against the spec directory —
        // exactly the directory the auto-hide protects.
        let parent =
            std::env::temp_dir().join(format!("ai-bubble-spec-src-{}", std::process::id()));
        let spec_dir = parent.join(".ai-bubble");
        std::fs::create_dir_all(&spec_dir).unwrap();
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-ro", "dest": "/x", "source": "." }
            ] } }"#,
        );
        // Mirror what `Spec::read` does: resolve the relative source first.
        let mut spec = spec;
        spec.hostfs.resolve_relative_sources(&spec_dir);
        let err = spec
            .validate_sources(&spec_dir)
            .expect_err("a redirect onto the spec dir must be rejected");
        assert!(err.contains("redirect-ro"), "{err}");
        std::fs::remove_dir_all(&parent).ok();
    }

    /// AUDIT.md H1/M6: a bind/redirect source *strictly inside* the spec
    /// directory bypasses the pattern list and the auto-hide just like a
    /// source covering the spec directory. Top-level entries are rejected
    /// (that is where `spec.json` and the env file live); a directory
    /// directly inside the spec directory is allowed by design (the conf
    /// directory a sandbox may rewrite), and so is anything inside a
    /// subdirectory — including the project-cache backing store
    /// `<spec-dir>/cache/`.
    #[test]
    fn a_source_inside_the_spec_dir_is_restricted() {
        let parent =
            std::env::temp_dir().join(format!("ai-bubble-spec-src-inside-{}", std::process::id()));
        let spec_dir = parent.join(".ai-bubble");
        std::fs::create_dir_all(&spec_dir).unwrap();

        // A redirect onto spec.json — the documented escalation scenario.
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-rw", "dest": "/loot", "source": "spec.json" }
            ] } }"#,
        );
        spec.hostfs.resolve_relative_sources(&spec_dir);
        let err = spec
            .validate_sources(&spec_dir)
            .expect_err("a redirect-rw onto spec.json must be rejected");
        assert!(err.contains("inside the spec directory"), "{err}");

        // A bind of the spec file is rejected, too.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
            { "type": "bind", "src": "/repo/.ai-bubble/spec.json" }
        ] } }"#,
        );
        assert!(
            spec.validate_sources(Path::new("/repo/.ai-bubble"))
                .is_err()
        );

        // The project-cache backing store remains deliberately allowed.
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
            { "type": "bind", "src": "/repo/.ai-bubble/cache/data" }
        ] } }"#,
        );
        spec.validate_sources(Path::new("/repo/.ai-bubble"))
            .expect("the cache backing store may be targeted");

        // A file two levels below the spec directory is allowed by design
        // (the conf-directory use case): the sandbox may rewrite it.
        let conf = spec_dir.join("conf");
        std::fs::create_dir_all(&conf).unwrap();
        std::fs::write(conf.join("settings.json"), "{}").unwrap();
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-rw", "dest": "/conf", "source": "conf/settings.json" }
            ] } }"#,
        );
        spec.hostfs.resolve_relative_sources(&spec_dir);
        spec.validate_sources(&spec_dir)
            .expect("a file inside a subdirectory of the spec dir may be targeted");

        // A directory directly inside the spec directory is allowed, too.
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-rw", "dest": "/conf", "source": "conf" }
            ] } }"#,
        );
        spec.hostfs.resolve_relative_sources(&spec_dir);
        spec.validate_sources(&spec_dir)
            .expect("a subdirectory of the spec dir may be targeted");

        // A top-level file is rejected — spec.json and the env file live
        // at that level.
        std::fs::write(spec_dir.join("secrets.env"), "TOKEN=x").unwrap();
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-rw", "dest": "/loot", "source": "secrets.env" }
            ] } }"#,
        );
        spec.hostfs.resolve_relative_sources(&spec_dir);
        let err = spec
            .validate_sources(&spec_dir)
            .expect_err("a redirect-rw onto a top-level file must be rejected");
        assert!(err.contains("inside the spec directory"), "{err}");

        // A nonexistent top-level entry fails closed as well: it cannot
        // be verified to be a directory.
        let mut spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "redirect-rw", "dest": "/x", "source": "maybe-a-dir" }
            ] } }"#,
        );
        spec.hostfs.resolve_relative_sources(&spec_dir);
        assert!(spec.validate_sources(&spec_dir).is_err());

        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn a_sibling_directory_source_is_accepted() {
        let spec = parse(
            r#"{ "hostfs": { "mappings": [
                { "type": "bind", "src": "/repo/other" },
                { "type": "redirect-rw", "dest": "/out", "source": "/repo/other/out" }
            ] } }"#,
        );
        // The sources are outside the spec directory: no error.
        spec.validate_sources(Path::new("/repo/.ai-bubble"))
            .expect("sources outside the spec dir are fine");
    }

    #[test]
    fn reading_a_spec_with_a_safe_bind_source_succeeds() {
        let parent =
            std::env::temp_dir().join(format!("ai-bubble-spec-read-{}", std::process::id()));
        let spec_dir = parent.join(".ai-bubble");
        std::fs::create_dir_all(&spec_dir).unwrap();
        std::fs::write(
            spec_dir.join(crate::spec::file::SPEC_FILE),
            r#"{ "hostfs": { "mappings": [ { "type": "bind", "src": "/repo/other" } ] } }"#,
        )
        .unwrap();
        let spec = crate::spec::Spec::load(Some(&spec_dir));
        // The bind mapping survives (plus the appended auto-hide).
        assert_eq!(spec.hostfs.mappings.len(), 2);
        std::fs::remove_dir_all(&parent).ok();
    }

    /// AUDIT.md M2: `shellexpand` implements more of the shell's parameter
    /// expansion than the spec's promise ("referencing an unset variable is
    /// an error") allows. `${VAR:-default}` silently expands an unset (or
    /// empty) variable to the default literal — a programmatically assembled
    /// spec can smuggle an absolute path past post-expansion validation —
    /// and an unterminated `${BOGUS` passes through verbatim. Both (and
    /// other ambiguous shell forms) must be hard errors before expansion.
    #[test]
    fn expansion_rejects_shell_extras_and_keeps_plain_references() {
        // The documented behavior still works: set variables expand, unset
        // ones error, and a literal `$` away from a name stays verbatim.
        unsafe { std::env::set_var("RS_BUBBLE_TEST_EXP", "value") };
        assert_eq!(
            expand_str("x${RS_BUBBLE_TEST_EXP}y/$RS_BUBBLE_TEST_EXP/$ z$").unwrap(),
            "xvaluey/value/$ z$"
        );
        assert!(expand_str("${RS_BUBBLE_TEST_UNSET_VAR}").is_err());
        unsafe { std::env::remove_var("RS_BUBBLE_TEST_EXP") };

        // The default-value operator: the audit's exact smuggling vector.
        // (Live-verified against shellexpand 3.1.2: this used to expand to
        // `x/etcy` with `UNSET` unset.)
        assert!(expand_str("x${UNSET:-/etc}y").is_err());
        assert!(
            expand_str("${HOME:-/root}").is_err(),
            "even a set variable \
            must not silently switch to the operator's default"
        );
        // Unterminated braces used to pass through verbatim.
        assert!(expand_str("x${BOGUS").is_err());
        // The remaining ambiguous shell forms: PID-style `$$` and non-name
        // content inside the braces (nested braces, other operators).
        assert!(expand_str("$$").is_err());
        assert!(expand_str("$$HOME").is_err());
        assert!(expand_str("${A${B}}").is_err());
        assert!(expand_str("${HOME:+/other}").is_err());
        assert!(expand_str("${HOME#prefix}").is_err());
        assert!(expand_str("${}").is_err());
        assert!(expand_str("${HOME /a/b}").is_err());
    }
}
