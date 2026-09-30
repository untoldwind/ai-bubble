//! The spec file's `env` section: the sandbox's isolated environment.
//!
//! The sandboxed command does **not** inherit the host's environment:
//! like the filesystem, the environment is isolated, and the spec
//! decides what exists inside. The `env` section is that decision:
//!
//! ```json
//! { "env": {
//!       "values": { "PATH": "${PATH}", "HOME": "${HOME}" },
//!       "env_file": ".env"
//!   } }
//! ```
//!
//! * `values` maps variable names to values. A `BTreeMap` keeps the
//!   iteration order deterministic. Every value may reference *host*
//!   environment variables as `${VAR}` (see [`super::file::expand_str`]):
//!   this is how a variable is copied from the host into the sandbox —
//!   explicitly, one by one, instead of the whole host environment being
//!   mirrored wholesale. Referencing an unset host variable is an error,
//!   so typos don't silently drop entries.
//! * `env_file` optionally names a dotenv-style file (relative to the
//!   spec directory) whose `KEY=VALUE` lines are loaded into the
//!   environment as well (see [`parse_dotenv`]). Entries already present
//!   in `values` win: the spec is the user's explicit choice, the file
//!   fills in the rest.

use std::collections::BTreeMap;
use std::path::Path;

use schemars::JsonSchema;
use serde::Deserialize;

/// The `env` section: the variables of the sandbox's isolated
/// environment.
#[derive(Debug, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EnvConfig {
    /// The environment variables, name → value. A `BTreeMap` keeps the
    /// iteration order deterministic.
    ///
    /// The variable names are used as-is (they become the names the
    /// sandboxed command sees); only the values are `${VAR}`-expanded.
    pub values: BTreeMap<String, EnvVar>,
    /// An optional dotenv-style file (relative to the spec directory)
    /// whose `KEY=VALUE` lines are loaded into the environment. Entries
    /// already present in [`EnvConfig::values`] win over the file.
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "env_file_path"
    )]
    pub env_file: Option<String>,
}

impl EnvConfig {
    /// Load the dotenv-style file named by [`EnvConfig::env_file`] (if
    /// any) and merge its entries into [`EnvConfig::values`] — without
    /// overwriting entries the spec already lists. The path is resolved
    /// relative to the spec directory (like the redirect sources); a
    /// missing file, a malformed line or an unset `${VAR}` reference in
    /// a file value is an error.
    pub fn load_env_file(&mut self, spec_dir: &Path) -> Result<(), String> {
        let Some(file) = &self.env_file else {
            return Ok(());
        };
        let path = spec_dir.join(file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("Can't read env file {}: {e}", path.display()))?;
        let entries = parse_dotenv(&text).map_err(|e| format!("Invalid env file {path:?}: {e}"))?;
        for (name, raw) in entries {
            let value = super::file::expand_str(&raw)
                .map_err(|e| format!("Invalid env file {path:?}: {e}"))?;
            self.values.entry(name).or_insert(EnvVar(value));
        }
        Ok(())
    }
}

/// One environment value: a string whose `${VAR}` references are
/// expanded from the **host** environment while the spec is read (see
/// [`super::file::expand_str`]), so everything downstream only ever sees
/// the fully expanded text.
#[derive(Debug, PartialEq, Deserialize, JsonSchema)]
pub struct EnvVar(#[serde(deserialize_with = "env_var_value")] pub String);

/// Deserialize the `env_file` field: a path-like value whose `${VAR}`
/// references are expanded (see [`super::file::expand_str`]).
fn env_file_path<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let raw = String::deserialize(deserializer)?;
    super::file::expand_str(&raw)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

/// Deserialize one `env` value with `${VAR}` expansion: the field is
/// read as a plain string, then the references are resolved against the
/// host environment. An unset host variable is a deserialization error.
fn env_var_value<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let raw = String::deserialize(deserializer)?;
    super::file::expand_str(&raw).map_err(serde::de::Error::custom)
}

/// Parse a dotenv-style file into `KEY → raw value` entries:
///
/// * blank lines and lines starting with `#` (after leading whitespace)
///   are skipped;
/// * an optional `export ` prefix is accepted and ignored;
/// * each remaining line must be `KEY=VALUE`; whitespace around the key
///   and the `=` is trimmed;
/// * a value may be wrapped in single or double quotes; double-quoted
///   values keep their content verbatim (no escape processing).
///
/// Empty values are allowed (`KEY=`). Anything else is an error, so a
/// typo in the file is reported instead of silently dropping entries.
fn parse_dotenv(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut entries = BTreeMap::new();
    for (no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!(
                "line {}: expected KEY=VALUE, found {line:?}",
                no + 1
            ));
        };
        let name = name.trim();
        let value = unquote(value.trim());
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("line {}: invalid variable name {name:?}", no + 1));
        }
        entries.insert(name.to_string(), value);
    }
    Ok(entries)
}

/// Strip one pair of matching quotes from a dotenv value.
fn unquote(value: &str) -> String {
    for quote in ['"', '\''] {
        if let Some(rest) = value.strip_prefix(quote)
            && let Some(stripped) = rest.strip_suffix(quote)
        {
            return stripped.to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parses_plain_quoted_and_exported_lines() {
        let entries = parse_dotenv(
            r#"
# a comment
PLAIN=value
SPACED  =  spaced value
QUOTED="double quoted"
SINGLE='single quoted'
EMPTY=
export EXPORTED=exported
        "#,
        )
        .unwrap();
        assert_eq!(
            entries,
            BTreeMap::from([
                ("PLAIN".to_string(), "value".to_string()),
                ("SPACED".to_string(), "spaced value".to_string()),
                ("QUOTED".to_string(), "double quoted".to_string()),
                ("SINGLE".to_string(), "single quoted".to_string()),
                ("EMPTY".to_string(), String::new()),
                ("EXPORTED".to_string(), "exported".to_string()),
            ])
        );
    }

    #[test]
    fn dotenv_rejects_malformed_lines() {
        for bad in ["KEY", "=novalue", "B@d=x"] {
            assert!(parse_dotenv(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn dotenv_keeps_hash_inside_values() {
        let entries = parse_dotenv("KEY=a#b\n# full comment\n").unwrap();
        assert_eq!(entries.get("KEY").map(String::as_str), Some("a#b"));
    }
}
