//! The sandbox specification: its **config-file** view and its
//! **internal** representation.
//!
//! The module is split into two deliberately separate layers:
//!
//! * The config file — [`file::Spec`] and its sections ([`env`],
//!   [`hostfs`], [`net`], [`tmpfs`]): everything that maps 1:1 onto what the user
//!   writes in the JSON spec file (`.ai-bubble/spec.json`, or
//!   `--spec-dir DIR`).
//!   These types carry the serde and JSON-schema attributes and are
//!   documented for the file format.
//! * The internal configuration — [`internal`]: what the sandbox
//!   machinery (`crate::sandbox`, `crate::hostfs`, `crate::netns`)
//!   actually runs with, compiled down from the parsed file by
//!   [`internal::SandboxConfig::compile`]. Internal code never touches
//!   the config-file types.
//!
//! A JSON Schema for the config file is generated at runtime from these
//! very files (`crate::spec_schema()`): all the serde attributes are
//! honored, and `TmpfsPerms`' hand-written deserializer is described
//! manually in its `JsonSchema` impl. The main crate prints it via
//! `--print-schema`, so editors can validate and auto-complete spec files
//! against it.

pub mod audit;
pub mod env;
pub mod file;
pub mod hostfs;
pub mod internal;
pub mod net;
pub mod rlimits;
pub mod seccomp;
pub mod tmpfs;

pub use self::file::Spec;

#[cfg(test)]
pub(crate) mod tests;
