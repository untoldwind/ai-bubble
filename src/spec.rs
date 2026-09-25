//! The sandbox specification file (JSON).
//!
//! Everything that used to be configured on the command line — the mount
//! operations and the isolated-network settings — now lives in a single
//! spec file. The default location is `.rs-bubble.json` in the current
//! directory; `--spec FILE` on the command line overrides it.
//!
//! Format:
//!
//! ```json
//! {
//!   "ops": [
//!     { "type": "bind",    "src": "/usr", "dest": "/usr" },
//!     { "type": "symlink", "src": "usr/lib", "dest": "/lib" }
//!   ],
//!   "proc": "/proc",
//!   "net": { "isolated": true, "allow": ["example.com:443"] }
//! }
//! ```
//!
//! All fields are optional: `proc` defaults to `/proc` (a fresh procfs
//! instance), and without `net.isolated` the command shares the host
//! network. `allow` is the proxy allow-list; an empty list (or a missing
//! `allow`) allows every target.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The default spec file, looked up relative to the current directory.
pub const DEFAULT_SPEC: &str = ".rs-bubble.json";

/// One sandbox setup operation. The JSON `type` tag selects the variant,
/// and the order of the list is the order in which the operations are
/// applied inside the sandbox (order matters, exactly like bwrap).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Op {
    Bind {
        src: String,
        dest: PathBuf,
    },
    Symlink {
        src: String,
        dest: PathBuf,
    },
    /// Mount a fresh procfs instance. Usually set via the top-level
    /// `proc` field rather than as an explicit op, but kept here so the
    /// sandbox can treat it uniformly.
    Proc {
        dest: PathBuf,
    },
}

/// Network-related configuration for isolated networking.
#[derive(Debug, Default, PartialEq, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Run the command in a fresh network namespace and proxy its
    /// connections from the host side.
    pub isolated: bool,
    /// Allow-list of `host` or `host:port` targets for the proxy.
    /// Empty means: allow everything.
    pub allow: Vec<String>,
}

/// The whole sandbox specification.
#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    /// The mount operations, in application order.
    pub ops: Vec<Op>,
    /// Where to mount a fresh procfs instance. `None` mounts nothing;
    /// see [`Spec::filesystem_ops`] for the default of `/proc`.
    pub proc: Option<PathBuf>,
    /// Isolated-network configuration.
    pub net: NetConfig,
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
mod tests {
    use super::*;

    fn parse(json: &str) -> Spec {
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
    fn net_options() {
        let spec =
            parse(r#"{ "net": { "isolated": true, "allow": ["example.com:443", "localhost"] } }"#);
        assert!(spec.net.isolated);
        assert_eq!(spec.net.allow, ["example.com:443", "localhost"]);
    }

    #[test]
    fn empty_spec_is_default() {
        let spec = parse("{}");
        assert_eq!(spec, Spec::default());
        assert!(!spec.net.isolated);
        assert_eq!(spec.ops, Vec::new());
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
    fn unknown_fields_are_rejected() {
        assert!(serde_json::from_str::<Spec>(r#"{ "nope": true }"#).is_err());
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
