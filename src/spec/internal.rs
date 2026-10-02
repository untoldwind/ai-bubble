//! The *internal* sandbox configuration.
//!
//! This module is deliberately separate from the spec-file view (the
//! sibling modules `file`, `hostfs`, `net` and `tmpfs`): these are the
//! types the sandbox machinery — `crate::sandbox`, `crate::hostfs` and
//! `crate::netns` — actually runs with. Nothing here is ever
//! (de)serialized from the spec file: the config-file types are compiled
//! down into these by [`SandboxConfig::compile`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::hostfs::patterns::Patterns;

use super::Spec;
use super::net::NetConfig;
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

/// The seccomp filter to install for the sandboxed command: either an
/// allowlist (only the listed syscalls are permitted) or a blocklist
/// (exactly these are denied). Compiled down from the spec's `seccomp`
/// section, with the syscall names already resolved to numbers.
///
/// Independently of the mode, `unix_sockets` records the spec's
/// `net.*.unix_sockets` opt-in: when `false` (the default), the sandbox
/// additionally denies the creation of Unix-domain sockets (see
/// [`SeccompPolicy::deny_unix_sockets`]).
#[derive(Debug, Clone, PartialEq)]
pub enum SeccompPolicy {
    Allow {
        syscalls: Vec<i64>,
        on_violation: SeccompViolation,
        unix_sockets: bool,
    },
    Block {
        syscalls: Vec<i64>,
        on_violation: SeccompViolation,
        unix_sockets: bool,
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

    /// Whether Unix-domain sockets are allowed (the spec's
    /// `net.*.unix_sockets`; `false` = deny, the default).
    pub fn unix_sockets(&self) -> bool {
        match self {
            SeccompPolicy::Allow { unix_sockets, .. } | SeccompPolicy::Block { unix_sockets, .. } => {
                *unix_sockets
            }
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

/// The sandbox's internal network configuration: what [`crate::netns`]
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
}

impl From<&NetConfig> for Net {
    fn from(net: &NetConfig) -> Net {
        match net {
            NetConfig::Host { unix_sockets } => Net {
                isolated: false,
                mode: NetMode::Proxy,
                allow: vec![],
                allow_private: false,
                unix_sockets: *unix_sockets,
            },
            NetConfig::Proxy {
                allow,
                allow_private,
            } => Net {
                isolated: true,
                mode: NetMode::Proxy,
                allow: allow.clone(),
                allow_private: *allow_private,
                // The fresh network namespace already isolates abstract
                // sockets; AF_UNIX is always allowed here.
                unix_sockets: true,
            },
            NetConfig::Waf {
                allow,
                allow_private,
            } => Net {
                isolated: true,
                mode: NetMode::Waf,
                allow: allow.clone(),
                allow_private: *allow_private,
                unix_sockets: true,
            },
        }
    }
}

/// The sandbox's *internal* configuration: the compiled-down form of the
/// spec file, and everything the sandbox machinery consumes. The
/// config-file view is [`Spec`]; this is what [`crate::sandbox`],
/// [`crate::hostfs`] and [`crate::netns`] see.
#[derive(Debug, PartialEq)]
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
    /// denies Unix-domain sockets (the default, see `net.*.unix_sockets`
    /// and AUDIT.md M3), a minimal policy carrying only that denial.
    /// `None` when nothing needs a filter.
    pub seccomp: Option<SeccompPolicy>,
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
        SandboxConfig {
            ops: spec.hostfs.ops(),
            net: Net::from(&spec.net),
            patterns: spec.hostfs.patterns(),
            env: spec
                .env
                .expand_values()
                .unwrap_or_else(|e| crate::sandbox::die(&e)),
            cwd: spec
                .expand_cwd()
                .unwrap_or_else(|e| crate::sandbox::die(&e)),
            audit_log: spec.audit.log.as_deref().map(PathBuf::from),
            seccomp: compile_seccomp(&spec.seccomp, spec.net.unix_sockets()),
        }
    }
}

/// Compile the spec file's `seccomp` section into the internal policy:
/// resolve the syscall names to numbers (an unknown name is a hard
/// error, so a typo is reported like any other spec problem), dedupe
/// and keep them sorted for deterministic BPF generation. A section
/// that names neither `allow`, `block` nor a `preset` compiles to no
/// filter — *unless* the spec denies Unix-domain sockets
/// (`net.*.unix_sockets`, the default; AUDIT.md M3): that denial is
/// itself a filter, so one is installed even without a `seccomp`
/// section. A preset-based section always compiles to a blocklist (the
/// preset baseline plus `block` entries minus `allow` exceptions, see
/// [`SeccompConfig::resolved`]).
fn compile_seccomp(config: &SeccompConfig, unix_sockets: bool) -> Option<SeccompPolicy> {
    use std::str::FromStr;
    let configured = config.is_configured();
    if !configured && unix_sockets {
        return None;
    }
    let (names, allowlist) = if configured {
        config.resolved()
    } else {
        (Vec::new(), false)
    };
    let mut syscalls: Vec<i64> = names
        .iter()
        .map(|name| match syscalls::Sysno::from_str(name) {
            Ok(sysno) => sysno as i64,
            Err(_) => {
                crate::sandbox::die(&format!("Unknown syscall {name:?} in the seccomp section"))
            }
        })
        .collect();
    syscalls.sort_unstable();
    syscalls.dedup();
    let on_violation = config.on_violation.into();
    Some(if allowlist {
        SeccompPolicy::Allow {
            syscalls,
            on_violation,
            unix_sockets,
        }
    } else {
        SeccompPolicy::Block {
            syscalls,
            on_violation,
            unix_sockets,
        }
    })
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
