//! The *internal* sandbox configuration.
//!
//! This module is deliberately separate from the spec-file view (the
//! sibling modules `file`, `hostfs`, `net` and `tmpfs`): these are the
//! types the sandbox machinery — `crate::sandbox`, `crate::hostfs` and
//! `crate::sandbox::netns` — actually runs with. Nothing here is ever
//! (de)serialized from the spec file: the config-file types are compiled
//! down into these by [`SandboxConfig::compile`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::hostfs::patterns::Patterns;

use super::Spec;
use super::net::NetConfig;
use super::rlimits::Rlimits;
use super::seccomp::{SeccompConfig, Violation};
use super::tmpfs::TmpfsPerms;

/// What happens to a syscall the seccomp filter denies: the internal
/// form of the spec's `seccomp.on_violation` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompViolation {
    /// The denied syscall fails with `EPERM`.
    Errno,
    /// The process is killed with `SIGSYS`.
    Kill,
}

impl From<Violation> for SeccompViolation {
    fn from(v: Violation) -> SeccompViolation {
        match v {
            Violation::Errno => SeccompViolation::Errno,
            Violation::Kill => SeccompViolation::Kill,
        }
    }
}

/// The address families the sandboxed command may create sockets for,
/// compiled down from the spec's `net.*` opt-in flags. Each is `false`
/// (deny) by default in host-network mode; the isolated
/// network-namespace modes always allow (their fresh netns isolates the
/// namespace-scoped families).
///
/// The denial is implemented as argument-gated seccomp rules on
/// `socket(2)`/`socketpair(2)` in `crate::sandbox::apply_seccomp` (see
/// AUDIT.md M3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketGate {
    /// Unix-domain sockets (spec `net.host.unix_sockets`).
    pub unix_sockets: bool,
    /// Netlink sockets (spec `net.host.netlink`).
    pub netlink: bool,
    /// AF_VSOCK sockets (spec `net.host.vsock`).
    pub vsock: bool,
    /// AF_BLUETOOTH sockets (spec `net.host.bluetooth`).
    pub bluetooth: bool,
}

impl SocketGate {
    /// Whether every family is allowed (so no socket-gating filter is
    /// needed at all).
    pub fn all_allowed(&self) -> bool {
        self.unix_sockets && self.netlink && self.vsock && self.bluetooth
    }
}

/// The seccomp filter to install for the sandboxed command: either an
/// allowlist (only the listed syscalls are permitted) or a blocklist
/// (exactly these are denied). Compiled down from the spec's `seccomp`
/// section, with the syscall names already resolved to numbers.
///
/// Independently of the mode, `sockets` records the spec's `net.*`
/// opt-ins: the families that are *not* opted in (the dangerous
/// defaults — `SocketGate::default()` denies all four) are denied by
/// argument-gated rules on `socket(2)`/`socketpair(2)` (see
/// [`SocketGate`] and [`SeccompPolicy::sockets`]).
#[derive(Debug, Clone, PartialEq)]
pub enum SeccompPolicy {
    Allow {
        syscalls: Vec<i64>,
        on_violation: SeccompViolation,
        sockets: SocketGate,
    },
    Block {
        syscalls: Vec<i64>,
        on_violation: SeccompViolation,
        sockets: SocketGate,
    },
}

impl SeccompPolicy {
    /// The filter's syscall numbers (whatever the mode).
    pub fn syscalls(&self) -> &[i64] {
        match self {
            SeccompPolicy::Allow { syscalls, .. } | SeccompPolicy::Block { syscalls, .. } => {
                syscalls
            }
        }
    }

    /// The action for syscalls the filter denies.
    pub fn on_violation(&self) -> SeccompViolation {
        match self {
            SeccompPolicy::Allow { on_violation, .. }
            | SeccompPolicy::Block { on_violation, .. } => *on_violation,
        }
    }

    /// Whether this is an allowlist (as opposed to a blocklist).
    pub fn is_allowlist(&self) -> bool {
        matches!(self, SeccompPolicy::Allow { .. })
    }

    /// The address-family gate this policy carries (see
    /// [`SocketGate`]).
    pub fn sockets(&self) -> &SocketGate {
        match self {
            SeccompPolicy::Allow { sockets, .. } | SeccompPolicy::Block { sockets, .. } => sockets,
        }
    }
}

/// Which kind of in-sandbox servers an isolated network namespace runs:
/// the mode selected in the spec's `net` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    /// An HTTP CONNECT proxy on 127.0.0.2:3128 (see [`crate::proxy`]).
    Proxy,
    /// DNS on 53, HTTP on 80 and HTTPS on 443 on 127.0.0.2 (see
    /// [`crate::waf`]).
    Waf,
}

/// The sandbox's internal network configuration: what [`crate::sandbox::netns`]
/// runs with, compiled down from the spec file's [`NetConfig`].
#[derive(Debug, Clone, PartialEq)]
pub struct Net {
    /// Run the command in a fresh network namespace (proxy or waf mode).
    pub isolated: bool,
    /// Which in-sandbox servers to run in an isolated namespace.
    pub mode: NetMode,
    /// The allow-list; empty means: allow nothing. Entries may use a
    /// `*.` subdomain wildcard.
    pub allow: Vec<String>,
    /// Whether the host-side connectors may dial resolved addresses in
    /// private/loopback/link-local ranges (see `NetConfig`'s
    /// `allow_private` and AUDIT.md H3). Off by default.
    pub allow_private: bool,
    /// Whether the command may create Unix-domain sockets (see
    /// `NetConfig::Host`'s `unix_sockets` and AUDIT.md M3). Host mode
    /// defaults to denying them; the isolated netns modes always allow.
    pub unix_sockets: bool,
    /// Whether the command may create netlink sockets (spec
    /// `net.host.netlink`; AUDIT.md M3). Same defaults as
    /// `unix_sockets`.
    pub netlink: bool,
    /// Whether the command may create AF_VSOCK sockets (spec
    /// `net.host.vsock`; AUDIT.md M3). Same defaults as `unix_sockets`.
    pub vsock: bool,
    /// Whether the command may create AF_BLUETOOTH sockets (spec
    /// `net.host.bluetooth`; AUDIT.md M3). Same defaults as
    /// `unix_sockets`.
    pub bluetooth: bool,
}

impl From<&NetConfig> for Net {
    fn from(net: &NetConfig) -> Net {
        match net {
            NetConfig::Host {
                unix_sockets,
                netlink,
                vsock,
                bluetooth,
            } => Net {
                isolated: false,
                mode: NetMode::Proxy,
                allow: vec![],
                allow_private: false,
                unix_sockets: *unix_sockets,
                netlink: *netlink,
                vsock: *vsock,
                bluetooth: *bluetooth,
            },
            NetConfig::Proxy {
                allow,
                allow_private,
            } => {
                // NET-6: validate the entries at load time, so a dead
                // entry (`example.com:443x`) is a spec error instead of a
                // silently never-matching rule.
                for entry in allow {
                    crate::proxy::allowlist::validate_entry(entry)
                        .unwrap_or_else(|e| crate::sandbox::die(&e));
                }
                Net {
                    isolated: true,
                    mode: NetMode::Proxy,
                    allow: allow.clone(),
                    allow_private: *allow_private,
                    // The fresh network namespace already isolates abstract
                    // sockets; all four families are always allowed here.
                    unix_sockets: true,
                    netlink: true,
                    vsock: true,
                    bluetooth: true,
                }
            }
            NetConfig::Waf {
                allow,
                allow_private,
            } => {
                // NET-6: see the Proxy arm.
                for entry in allow {
                    crate::proxy::allowlist::validate_entry(entry)
                        .unwrap_or_else(|e| crate::sandbox::die(&e));
                }
                Net {
                    isolated: true,
                    mode: NetMode::Waf,
                    allow: allow.clone(),
                    allow_private: *allow_private,
                    unix_sockets: true,
                    netlink: true,
                    vsock: true,
                    bluetooth: true,
                }
            }
        }
    }
}

/// The sandbox's *internal* configuration: the compiled-down form of the
/// spec file, and everything the sandbox machinery consumes. The
/// config-file view is [`Spec`]; this is what [`crate::sandbox`],
/// [`crate::hostfs`] and [`crate::sandbox::netns`] see.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxConfig {
    /// The filesystem setup operations: all of them are generated by the
    /// `hostfs` mappings, in mapping order (see [`Spec::hostfs`]).
    pub ops: Vec<Op>,
    /// The internal network configuration.
    pub net: Net,
    /// The hostfs pattern → permission list backing the FUSE filesystem.
    pub patterns: Patterns,
    /// The environment of the sandboxed command: exactly what the spec's
    /// `env.values` lists, with the `env_file` entries (if any) merged
    /// in and the `${VAR}` references resolved at compile time (see
    /// [`super::env::EnvConfig::expand_values`]). The command inherits
    /// nothing else from the host.
    pub env: BTreeMap<String, String>,
    /// The working directory of the sandboxed command *inside* the
    /// sandbox, from the spec's `cwd` field (default: none, meaning `/`).
    /// Expanded and validated as an absolute, `..`-free path when the
    /// config is compiled (see [`Spec::expand_cwd`]).
    pub cwd: Option<PathBuf>,
    /// The audit log path from the spec's `audit` section (with `${VAR}`
    /// references already expanded at parse time), or `None` when
    /// auditing is disabled.
    pub audit_log: Option<PathBuf>,
    /// The seccomp policy to install for the sandboxed command, compiled
    /// down from the spec's `seccomp` section (with syscall names
    /// resolved to numbers) — or, when the spec configures no filter but
    /// denies a dangerous address family (the default, see `net.*` and
    /// AUDIT.md M3), a minimal policy carrying only that denial.
    /// `None` when nothing needs a filter.
    pub seccomp: Option<SeccompPolicy>,
    /// The resource limits (setrlimit) for the sandboxed command,
    /// compiled down verbatim from the spec's `rlimits` section (there
    /// are no names to resolve, so the file type is the internal type,
    /// see [`super::rlimits`]). All-`None` (the default) applies
    /// nothing.
    pub rlimits: Rlimits,
}

impl SandboxConfig {
    /// Compile a parsed spec file down into the internal configuration.
    ///
    /// The filesystem ops are the ops the `hostfs.mappings` stand for,
    /// applied in mapping order: the mount-point mappings (`dev`,
    /// `tmpfs`, `proc` and `bind` — see
    /// [`crate::spec::hostfs::HostFsConfig::ops`]) and the `symlink`
    /// mappings each contribute their op.
    ///
    /// Nothing is mounted automatically — in particular, procfs is only
    /// mounted when the spec says so: a `proc` mapping chooses where (and
    /// whether at all) a fresh procfs instance appears.
    pub fn compile(spec: &Spec) -> SandboxConfig {
        let config = Self::try_compile(spec).unwrap_or_else(|e| crate::sandbox::die(&e));
        // The rlimits are applied by `mount_and_exec` (crate::sandbox)
        // in the sandboxed child, whose call chain — `setup_and_exec` /
        // `netns::run` — does not carry the whole compiled config, so
        // the exec path reads them from here. compile() runs in the
        // original ai-bubble process before every fork, and the
        // registration is inherited across fork with the rest of the
        // address space — exactly like the ops, env and seccomp values
        // handed down explicitly. `try_compile` (the `spec-reload`
        // path) does NOT register: the reload runs long after the
        // sandboxed child has forked and exec'd, and overwriting the
        // registration there would be a no-op at best — the child's
        // limits are already applied and immutable.
        crate::sandbox::register_rlimits(config.rlimits);
        config
    }

    /// The fallible [`SandboxConfig::compile`]: every hard error (a bad
    /// `${VAR}` in `env`/`cwd`, an invalid glob, an unknown syscall
    /// name) is returned instead of killing the process. Used by
    /// `spec-reload` (see [`crate::control`]): a spec that cannot be
    /// compiled mid-run must be an error reply to the control client,
    /// not the end of the launcher. Unlike `compile` it does not
    /// register the rlimits (see `compile`'s comment).
    pub fn try_compile(spec: &Spec) -> Result<SandboxConfig, String> {
        let net = Net::from(&spec.net);
        // Compile the family gate from the NetConfig accessors (the
        // same semantics the isolated modes get from `Net::from`).
        let sockets = SocketGate {
            unix_sockets: spec.net.unix_sockets(),
            netlink: spec.net.netlink(),
            vsock: spec.net.vsock(),
            bluetooth: spec.net.bluetooth(),
        };
        let config = SandboxConfig {
            ops: spec.hostfs.ops(),
            net: net.clone(),
            patterns: crate::spec::hostfs::patterns_from_mappings(&spec.hostfs.mappings)?,
            env: spec.env.expand_values()?,
            cwd: spec.expand_cwd()?,
            audit_log: spec.audit.log.as_deref().map(PathBuf::from),
            seccomp: compile_seccomp(&spec.seccomp, sockets)?,
            rlimits: spec.rlimits,
        };
        Ok(config)
    }
}

/// Compile the spec file's `seccomp` section into the internal policy:
/// resolve the syscall names to numbers (an unknown name is a hard
/// error, so a typo is reported like any other spec problem), dedupe
/// and keep them sorted for deterministic BPF generation. A section
/// that names neither `allow`, `block` nor a `preset` compiles to no
/// filter — *unless* the spec denies a dangerous address family (the
/// `net.*` opt-ins, all denied by default in host mode; AUDIT.md M3):
/// that denial is itself a filter, so one is installed even without a
/// `seccomp` section. A preset-based section always compiles to a
/// blocklist (the preset baseline plus `block` entries minus `allow`
/// exceptions, see [`SeccompConfig::resolved`]).
fn compile_seccomp(
    config: &SeccompConfig,
    sockets: SocketGate,
) -> Result<Option<SeccompPolicy>, String> {
    use std::str::FromStr;
    let configured = config.is_configured();
    if !configured && sockets.all_allowed() {
        return Ok(None);
    }
    let (names, allowlist) = if configured {
        config.resolved()
    } else {
        (Vec::new(), false)
    };
    let mut syscalls: Vec<i64> = names
        .iter()
        .map(|name| {
            syscalls::Sysno::from_str(name)
                .map(|sysno| sysno as i64)
                .map_err(|_| format!("Unknown syscall {name:?} in the seccomp section"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    syscalls.sort_unstable();
    syscalls.dedup();
    let on_violation = config.on_violation.into();
    Ok(Some(if allowlist {
        SeccompPolicy::Allow {
            syscalls,
            on_violation,
            sockets,
        }
    } else {
        SeccompPolicy::Block {
            syscalls,
            on_violation,
            sockets,
        }
    }))
}

impl Op {
    /// One-line human description of the op: what it does and where. Used
    /// by `ai-bubble ls` to show the mount/symlink "actions" the config
    /// performs.
    pub fn describe(&self) -> String {
        match self {
            Op::Bind { src, dest, rw } => {
                let kind = if *rw { "bind-rw" } else { "bind-ro" };
                if src == &dest.to_string_lossy() {
                    format!("{kind} {src}")
                } else {
                    format!("{kind} {src} -> {}", dest.display())
                }
            }
            Op::Symlink { src, dest } => format!("symlink {} -> {src}", dest.display()),
            Op::Proc { dest } => format!("procfs at {}", dest.display()),
            Op::Dev { dest } => format!("minimal dev at {}", dest.display()),
            Op::Tmpfs { dest, perms, size } => {
                let mut detail = String::new();
                if let Some(perms) = perms {
                    detail.push_str(&format!(" perms={:04o}", perms.0));
                }
                if let Some(size) = size {
                    detail.push_str(&format!(" size={size}"));
                }
                format!("tmpfs  {}{detail}", dest.display())
            }
        }
    }
}

/// One sandbox setup operation, applied inside the sandbox in list order
/// (order matters, exactly like bwrap). Purely internal: the spec file
/// expresses all of these through `hostfs` mappings — see
/// [`crate::spec::hostfs::Mapping::op`].
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// Bind-mount the host path `src` at `dest` inside the sandbox.
    /// Bind mounts bypass the FUSE mirror's policy, so they are mounted
    /// read-only unless `rw` is set (see [`crate::spec::hostfs::Mapping::Bind`]).
    Bind {
        src: String,
        dest: PathBuf,
        rw: bool,
    },
    Symlink {
        src: String,
        dest: PathBuf,
    },
    /// Mount a fresh procfs instance. Produced by a `proc` mapping, and
    /// kept here so the sandbox can treat all ops uniformly.
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
    /// `size` the maximum size in bytes (default: capped at 512 MiB, SB-3 —
    /// tmpfs pages are host memory and `RLIMIT_AS` does not cover tmpfs).
    /// The mount is made with `MS_NOSUID | MS_NODEV`, like bwrap's.
    Tmpfs {
        dest: PathBuf,
        /// Octal mode, e.g. `"0755"` or `755`. Default: 0755.
        perms: Option<TmpfsPerms>,
        /// Maximum tmpfs size in bytes.
        size: Option<u64>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::spec::tests::parse;

    /// A spec that compiles at all compiles identically through the
    /// fallible path (the `spec-reload` baseline): `try_compile` must
    /// agree with `compile` — including a compile of the *preprocessed*
    /// spec, which is the shape `spec-reload` actually diffs.
    #[test]
    fn try_compile_agrees_with_compile() {
        let spec = parse(
            r#"{
                "hostfs": { "mappings": [
                    { "type": "ro", "glob": "/etc/*.conf" },
                    { "type": "rw", "glob": "/home/me" },
                    { "type": "session-cache", "path": "/home/me/.cache" }
                ] },
                "net": { "mode": "proxy", "allow": ["example.com:443"] },
                "env": { "values": { "PATH": "/usr/bin" } },
                "cwd": "/home/me",
                "seccomp": { "block": ["ptrace"], "on_violation": "errno" }
            }"#,
        );
        // Preprocess exactly like the run path (a session root so the
        // cache mapping resolves the same way on both sides).
        let mut spec = spec;
        let root = crate::hostfs::session_cache_needed(true).unwrap();
        crate::cli::preprocess_spec(&mut spec, Path::new("/repo/.ai-bubble"), Some(&root)).unwrap();
        let compiled = SandboxConfig::compile(&spec);
        let tried = SandboxConfig::try_compile(&spec).unwrap();
        assert_eq!(compiled, tried);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Every compile-time hard error of `compile` is a returned error in
    /// `try_compile` — a mid-run `spec-reload` of a broken spec must
    /// report to the control client, not kill the launcher.
    #[test]
    fn try_compile_reports_instead_of_dying() {
        // An unset ${VAR} in env.
        let spec = parse(r#"{ "env": { "values": { "X": "${DEFINITELY_UNSET_VAR_XY}" } } }"#);
        assert!(
            SandboxConfig::try_compile(&spec)
                .unwrap_err()
                .contains("DEFINITELY_UNSET_VAR_XY")
        );

        // A relative cwd.
        let spec = parse(r#"{ "cwd": "relative/dir" }"#);
        assert!(
            SandboxConfig::try_compile(&spec)
                .unwrap_err()
                .contains("absolute")
        );

        // An unknown seccomp syscall name.
        let spec = parse(r#"{ "seccomp": { "block": ["definitely_not_a_syscall_xyz"] } }"#);
        assert!(
            SandboxConfig::try_compile(&spec)
                .unwrap_err()
                .contains("definitely_not_a_syscall_xyz")
        );

        // An unclosed character class: accepted by the mapping parser
        // (it validates paths, not glob syntax), rejected by the
        // pattern compiler.
        let spec = parse(r#"{ "hostfs": { "mappings": [ { "type": "ro", "glob": "/[oops" } ] } }"#);
        assert!(
            SandboxConfig::try_compile(&spec)
                .unwrap_err()
                .contains("invalid hostfs pattern")
        );
    }
}
