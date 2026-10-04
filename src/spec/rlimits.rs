//! The spec file's `rlimits` section: resource limits (setrlimit) for
//! the sandboxed command (see [`crate::sandbox`]).
//!
//! These limits protect the **host supervisor** from a malicious
//! command — the resource-isolation concern AUDIT.md M4. The
//! namespace/capability isolation keeps the command from *reaching*
//! host resources, but it does not bound how much of them the command
//! may consume: an unbounded fork loop, an unbounded number of open
//! files, or a single `malloc`-hoarding process all translate directly
//! into host resource exhaustion (kernel memory, fd tables, RAM). The
//! limits here are the per-process brake on that: they are applied to
//! the sandboxed process (and inherited by everything it forks) right
//! before exec, so neither ai-bubble's supervisor processes nor the
//! host-side FUSE/network servers are affected by them.
//!
//! Every field is optional; an absent field (or an absent section)
//! means that limit is **not** set at all — the sandbox does not guess
//! limits the operator did not ask for, because a too-low limit turns a
//! legitimate build into a mysterious `EMFILE`/`EAGAIN`/`ENOMEM`
//! failure. Each limit is applied with soft == hard, so the command
//! cannot raise the soft limit back up again afterwards.
//!
//! Fields:
//!
//! * `nproc` — [`RLIMIT_NPROC`]: the maximum number of processes (and
//!   threads) the command's real uid may run under. This is the fork-
//!   bomb brake; it bounds the process count below what a fork bomb
//!   could otherwise reach. (The user namespace does *not* provide this
//!   brake on its own: since kernel 5.11 the userns has its own ucount,
//!   but the limit actually enforced is the one inherited from the
//!   caller — typically the host's large per-uid default — so without
//!   an explicit `nproc` here a fork bomb consumes the invoking user's
//!   global process budget. AUDIT.md M4.)
//! * `nofile` — [`RLIMIT_NOFILE`]: the maximum number of open file
//!   descriptors. Bounds fd-table (kernel) memory and keeps a leaking
//!   command from hitting the system-wide fd ceiling that the host's
//!   other processes share.
//! * `as` — [`RLIMIT_AS`]: the maximum size of the process's address
//!   space in bytes. Bounds host RAM (and tmpfs-backed allocations the
//!   command makes) per process; combined with `nproc` this gives a
//!   rough per-command memory ceiling.
//!
//! [`RLIMIT_NPROC`]: libc::RLIMIT_NPROC
//! [`RLIMIT_NOFILE`]: libc::RLIMIT_NOFILE
//! [`RLIMIT_AS`]: libc::RLIMIT_AS

use serde::Deserialize;

use schemars::JsonSchema;

/// The spec file's `rlimits` section (see the module docs).
///
/// The same type serves as the internal representation (no names to
/// resolve, unlike the seccomp section), so [`super::internal`]
/// compiles this section down by value and [`crate::sandbox`] applies
/// it with setrlimit right before exec (see `crate::sandbox::
/// apply_rlimits`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Rlimits {
    /// The maximum number of processes/threads for the command's real
    /// uid (soft == hard). Absent: not set.
    pub nproc: Option<u64>,
    /// The maximum number of open file descriptors (soft == hard).
    /// Absent: not set.
    pub nofile: Option<u64>,
    /// The maximum address-space size in bytes (soft == hard). Absent:
    /// not set.
    #[serde(rename = "as")]
    pub as_: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::Rlimits;
    use crate::spec::internal::SandboxConfig;
    use crate::spec::tests::{parse, parse_err};

    #[test]
    fn rlimits_section_is_parsed() {
        let spec = parse(r#"{ "rlimits": { "nproc": 256, "nofile": 1024, "as": 536870912 } }"#);
        assert_eq!(
            spec.rlimits,
            Rlimits {
                nproc: Some(256),
                nofile: Some(1024),
                as_: Some(536870912),
            }
        );
    }

    #[test]
    fn rlimits_default_to_nothing() {
        // Without the section (or with an empty one) no limit is set.
        assert_eq!(parse("{}").rlimits, Rlimits::default());
        assert_eq!(parse(r#"{ "rlimits": {} }"#).rlimits, Rlimits::default());
        // Individual fields are optional.
        assert_eq!(
            parse(r#"{ "rlimits": { "nproc": 64 } }"#).rlimits,
            Rlimits {
                nproc: Some(64),
                ..Rlimits::default()
            }
        );
    }

    #[test]
    fn rlimits_unknown_fields_are_rejected() {
        assert!(parse_err(r#"{ "rlimits": { "cpu": 10 } }"#).is_some());
    }

    #[test]
    fn rlimits_compile_into_the_internal_config() {
        let spec = parse(r#"{ "rlimits": { "nofile": 512 } }"#);
        let compiled = SandboxConfig::compile(&spec);
        assert_eq!(compiled.rlimits.nofile, Some(512));
        assert_eq!(compiled.rlimits.nproc, None);
        // An absent section compiles to the (inert) default.
        assert_eq!(
            SandboxConfig::compile(&parse("{}")).rlimits,
            Rlimits::default()
        );
    }
}
