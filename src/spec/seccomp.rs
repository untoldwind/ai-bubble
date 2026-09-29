//! The spec file's `seccomp` section: the syscall filter applied to the
//! sandboxed command (see [`crate::sandbox`]).
//!
//! The filter is either an **allowlist** (`"allow"`: only the listed
//! syscalls may be executed) or a **blocklist** (`"block"`: the listed
//! syscalls are denied). Giving both is a deserialize error; giving
//! neither disables the filter entirely (the default — the sandbox then
//! only relies on its namespace/capability isolation).
//!
//! Syscalls are named exactly like the kernel's syscall table entries
//! (e.g. `execve`, `openat`, `clone3`); the names are resolved to
//! syscall numbers when the spec is compiled (see
//! [`super::internal::SandboxConfig::compile`]), and an unknown name is
//! a hard error there.

use serde::Deserialize;

use schemars::JsonSchema;

/// What happens to a syscall the filter denies (the spec's
/// `on_violation` field, default `errno`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Violation {
    /// The denied syscall simply fails with `EPERM`. Lets the command
    /// observe (and perhaps work around) the restriction.
    #[default]
    Errno,
    /// The sandboxed process is killed with `SIGSYS` the moment it
    /// issues a denied syscall.
    Kill,
}

/// The spec file's `seccomp` section (see the module docs).
///
/// The custom `Deserialize` impl (backed by a derived internal struct)
/// enforces that `allow` and `block` are mutually exclusive at parse
/// time, so a contradictory spec is rejected like any other spec error.
#[derive(Debug, Default, PartialEq, JsonSchema)]
pub struct SeccompConfig {
    /// Syscall allowlist: when present, *only* these syscalls may be
    /// executed by the sandboxed command (everything else is denied per
    /// `on_violation`). An allowlist must be complete — including
    /// `execve`, `exit_group`, `mmap` and friends — or the command
    /// cannot run at all.
    pub allow: Option<Vec<String>>,
    /// Syscall blocklist: when present, exactly these syscalls are
    /// denied; everything else stays allowed. Useful to forbid specific
    /// dangerous entry points (`ptrace`, `mount`, `keyctl`, `bpf`, ...)
    /// without enumerating the whole syscall surface.
    pub block: Option<Vec<String>>,
    /// What happens to a denied syscall (see [`Violation`]).
    pub on_violation: Violation,
}

impl<'de> Deserialize<'de> for SeccompConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The derived shape: same fields, same defaults, same
        // unknown-field rejection as every other spec section.
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Raw {
            allow: Option<Vec<String>>,
            block: Option<Vec<String>>,
            on_violation: Violation,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.allow.is_some() && raw.block.is_some() {
            return Err(serde::de::Error::custom(
                "the seccomp section accepts either \"allow\" or \"block\", not both",
            ));
        }
        Ok(SeccompConfig {
            allow: raw.allow,
            block: raw.block,
            on_violation: raw.on_violation,
        })
    }
}

impl SeccompConfig {
    /// Whether the section configures a filter at all (i.e. it names at
    /// least one of `allow` and `block`).
    pub fn is_configured(&self) -> bool {
        self.allow.is_some() || self.block.is_some()
    }

    /// The list of syscall names this filter names (whatever the mode).
    pub(crate) fn syscalls(&self) -> &[String] {
        self.allow
            .as_deref()
            .or(self.block.as_deref())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::SeccompConfig;
    use crate::spec::tests::parse;

    #[test]
    fn seccomp_section_is_parsed() {
        let spec =
            parse(r#"{ "seccomp": { "block": ["ptrace", "mount"], "on_violation": "kill" } }"#);
        assert_eq!(
            spec.seccomp,
            SeccompConfig {
                allow: None,
                block: Some(vec!["ptrace".to_string(), "mount".to_string()]),
                on_violation: super::Violation::Kill,
            }
        );
        assert!(spec.seccomp.is_configured());
    }

    #[test]
    fn seccomp_defaults_to_no_filter_and_errno() {
        // Without a seccomp section the sandbox installs no filter.
        let spec = parse("{}");
        assert!(!spec.seccomp.is_configured());
        // A section with only on_violation is legal but inert.
        let spec = parse(r#"{ "seccomp": { "on_violation": "kill" } }"#);
        assert!(!spec.seccomp.is_configured());
        assert_eq!(spec.seccomp.on_violation, super::Violation::Kill);
        // The default violation action is errno.
        let spec = parse(r#"{ "seccomp": { "allow": ["read"] } }"#);
        assert_eq!(spec.seccomp.on_violation, super::Violation::Errno);
    }

    #[test]
    fn seccomp_allow_and_block_are_mutually_exclusive() {
        assert!(
            crate::spec::tests::parse_err(
                r#"{ "seccomp": { "allow": ["read"], "block": ["ptrace"] } }"#
            )
            .is_some()
        );
    }

    #[test]
    fn seccomp_unknown_fields_are_rejected() {
        assert!(
            crate::spec::tests::parse_err(r#"{ "seccomp": { "deny": ["ptrace"] } }"#).is_some()
        );
    }
}
