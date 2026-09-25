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
//!     { "type": "dev",     "dest": "/dev" },
//!     { "type": "tmpfs",   "dest": "/tmp", "perms": "1777", "size": 1048576 },
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
    /// Mount a minimal `/dev`, like bwrap's `--dev`: a fresh tmpfs (mode
    /// 0755, `MS_NOSUID|MS_NODEV`) populated with the usual device nodes
    /// (`null`, `zero`, `full`, `random`, `urandom`, `tty`), the stdio
    /// symlinks, `/dev/shm`, a fresh devpts instance at `pts` plus the
    /// `ptmx` symlink, and `/dev/console` bound to the host tty when stdin
    /// is one.
    Dev {
        dest: PathBuf,
    },
    /// Mount a fresh tmpfs instance, like bwrap's `--tmpfs`. Options mirror
    /// bwrap: `perms` is the octal mode of the mount root (default 0755) and
    /// `size` the maximum size in bytes (default: unlimited/half of RAM).
    /// The mount is made with `MS_NOSUID | MS_NODEV`, like bwrap's.
    Tmpfs {
        dest: PathBuf,
        /// Octal mode, e.g. `"0755"` or `755`. Default: 0755.
        perms: Option<TmpfsPerms>,
        /// Maximum tmpfs size in bytes.
        size: Option<u64>,
    },
}

/// An octal permission mode (`--perms` for bwrap's `--tmpfs`).
///
/// Accepts either a JSON number (`755`) or string (`"0755"`); both are
/// interpreted as *octal*, like bwrap does on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpfsPerms(pub u32);

impl<'de> Deserialize<'de> for TmpfsPerms {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = TmpfsPerms;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an octal permission mode (number or string, e.g. 755 or \"0755\")")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                // A JSON number is a sequence of octal digits, like bwrap's
                // --perms: 755 means 0o755.
                match u64::from_str_radix(&v.to_string(), 8) {
                    Ok(octal) => octal_from_u64(octal).map_err(E::custom).map(TmpfsPerms),
                    Err(_) => Err(E::invalid_value(
                        serde::de::Unexpected::Unsigned(v), &self)),
                }
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let digits = s.trim_start_matches('0');
                let digits = if digits.is_empty() { "0" } else { digits };
                match u64::from_str_radix(digits, 8) {
                    Ok(v) => octal_from_u64(v).map_err(E::custom).map(TmpfsPerms),
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Str(s), &self)),
                }
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// Reject octal-digit strings that don't fit in a mode_t (like bwrap does).
fn octal_from_u64(v: u64) -> Result<u32, String> {
    if v <= 0o7777 {
        Ok(v as u32)
    } else {
        Err(format!("mode {v:o} is too large"))
    }
}

impl TmpfsPerms {
    pub const DEFAULT: TmpfsPerms = TmpfsPerms(0o755);

    /// The mode as a tmpfs mount option, like bwrap's `mode=%#o` format.
    pub fn mount_option(&self) -> String {
        format!("mode=0{:o}", self.0)
    }
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

/// The spec file's `hostfs` section: what the FUSE filesystem mounted at
/// `/host` exposes.
#[derive(Debug, Default, PartialEq, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct HostFsConfig {
    /// Glob patterns (absolute host paths) mirrored under `/host`.
    /// Matched paths appear at the same absolute path below `/host`
    /// (`/etc/passwd` → `/host/etc/passwd`); matched directories are
    /// mirrored recursively. Empty mirrors nothing.
    pub mirror: Vec<String>,
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
    /// The host filesystem mounted at `/host`.
    pub hostfs: HostFsConfig,
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
        assert_eq!(spec.ops[0], Op::Tmpfs { dest: PathBuf::from("/x"), perms: Some(TmpfsPerms(0o700)), size: None });

        assert_eq!(TmpfsPerms::DEFAULT.mount_option(), "mode=0755");
        assert_eq!(TmpfsPerms(0o700).mount_option(), "mode=0700");
    }

    #[test]
    fn tmpfs_rejects_bad_perms() {
        assert!(serde_json::from_str::<Spec>(r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "abc" } ] }"#).is_err());
        assert!(serde_json::from_str::<Spec>(r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "999" } ] }"#).is_err());
        assert!(serde_json::from_str::<Spec>(r#"{ "ops": [ { "type": "tmpfs", "dest": "/x", "perms": "777777777777" } ] }"#).is_err());
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
    fn hostfs_mirror_parses() {
        let spec = parse(
            r#"{ "hostfs": { "mirror": ["/etc/*.conf", "/home/me/project"] } }"#,
        );
        assert_eq!(
            spec.hostfs.mirror,
            ["/etc/*.conf".to_string(), "/home/me/project".to_string()]
        );
    }

    #[test]
    fn hostfs_defaults_to_no_mirror() {
        let spec = parse("{}");
        assert!(spec.hostfs.mirror.is_empty());
    }

    #[test]
    fn hostfs_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Spec>(r#"{ "hostfs": { "nope": true } }"#).is_err());
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
