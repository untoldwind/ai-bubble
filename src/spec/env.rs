//! The spec file's `env` section: the sandbox's isolated environment.
//!
//! The sandboxed command does **not** inherit the host's environment:
//! like the filesystem, the environment is isolated, and the spec
//! decides what exists inside. The `env` section is that decision — a
//! plain object mapping variable names to values:
//!
//! ```json
//! { "env": { "PATH": "${PATH}", "HOME": "${HOME}", "TERM": "${TERM}" } }
//! ```
//!
//! Every value may reference *host* environment variables as `${VAR}`
//! (see [`super::file::expand_str`]): this is how a variable is copied
//! from the host into the sandbox — explicitly, one by one, instead of
//! the whole host environment being mirrored wholesale. Referencing an
//! unset host variable is an error, so typos don't silently drop
//! entries.
//!
//! In isolated-network mode rs-bubble additionally injects its proxy
//! variables (see [`crate::netns`]); entries from this section win over
//! those — an explicit spec value is the user's authoritative choice.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;

/// The `env` section: variable name → value. A `BTreeMap` keeps the
/// iteration order deterministic.
///
/// The variable names are used as-is (they become the names the
/// sandboxed command sees); only the values are `${VAR}`-expanded.
#[derive(Debug, Default, PartialEq, Deserialize, JsonSchema)]
pub struct EnvConfig(pub BTreeMap<String, EnvVar>);

/// One environment value: a string whose `${VAR}` references are
/// expanded from the **host** environment while the spec is read (see
/// [`super::file::expand_str`]), so everything downstream only ever sees
/// the fully expanded text.
#[derive(Debug, PartialEq, Deserialize, JsonSchema)]
pub struct EnvVar(#[serde(deserialize_with = "env_var_value")] pub String);

/// Deserialize one `env` value with `${VAR}` expansion: the field is
/// read as a plain string, then the references are resolved against the
/// host environment. An unset host variable is a deserialization error.
fn env_var_value<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    super::file::expand_str(&raw).map_err(serde::de::Error::custom)
}
