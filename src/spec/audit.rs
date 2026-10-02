//! The `audit` section of the spec file: where audit events are logged.
//!
//! This is only the *config-file* view: [`AuditConfig::log`] is compiled
//! down into [`crate::spec::internal::SandboxConfig::audit_log`] (with
//! `${VAR}` references expanded, like the other path-like fields) and
//! consumed by `crate::audit`.

use serde::Deserialize;

use schemars::JsonSchema;

/// Audit logging configuration. Without a `log` path (the default) the
/// audit subsystem is disabled entirely: no events are collected and no
/// file is written.
///
/// The path is constrained at startup: it must live inside the spec
/// directory (where it is created automatically) or point at a file that
/// already exists. This keeps the audit writers — which append with the
/// operator's uid — from turning a spec-controlled path into an
/// arbitrary file create/append primitive on the host. The log is also
/// size-capped: when it outgrows 64 MiB it is rotated to `<name>.1`
/// before the next batch is appended, so a sandbox spraying audit
/// events cannot fill the host disk.
#[derive(Debug, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// The audit log file, as a host path. Audit events (filesystem
    /// operations through the hostfs mirror, waf allow/deny decisions,
    /// proxy CONNECT attempts) are appended as JSON lines; the file is
    /// created if it does not exist. The value may reference host
    /// environment variables as `${VAR}`.
    pub log: Option<String>,
}
