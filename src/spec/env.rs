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
//!
//! Neither the value `${VAR}` references nor the reference in `env_file`
//! are expanded while the file is parsed: this type holds exactly what
//! the user wrote. The value expansion happens when the spec is compiled
//! down to the internal config (see [`EnvConfig::expand_values`]), so a
//! programmatically updated spec is expanded too.

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
    /// The expansion happens at compile time (see
    /// [`EnvConfig::expand_values`]), not while the file is parsed.
    pub values: BTreeMap<String, EnvVar>,
    /// An optional dotenv-style file (relative to the spec directory)
    /// whose `KEY=VALUE` lines are loaded into the environment. Entries
    /// already present in [`EnvConfig::values`] win over the file.
    ///
    /// The path itself may reference host environment variables as
    /// `${VAR}`; it is expanded when the file is loaded (see
    /// [`EnvConfig::load_env_file`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
}

impl EnvConfig {
    /// Load the dotenv-style file named by [`EnvConfig::env_file`] (if
    /// any) and merge its entries into [`EnvConfig::values`] — without
    /// overwriting entries the spec already lists. The path is resolved
    /// relative to the spec directory (like the redirect sources); a
    /// missing file or a malformed line is an error.
    ///
    /// The file entries are merged as written: their `${VAR}` references
    /// are expanded later, together with the spec values, when the config
    /// is compiled (see [`EnvConfig::expand_values`]).
    pub fn load_env_file(&mut self, spec_dir: &Path) -> Result<(), String> {
        let Some(file) = &self.env_file else {
            return Ok(());
        };
        let file = super::file::expand_str(file)
            .map_err(|e| format!("Invalid env file path {file:?}: {e}"))?;
        let path = spec_dir.join(file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("Can't read env file {}: {e}", path.display()))?;
        let entries = parse_dotenv(&text).map_err(|e| format!("Invalid env file {path:?}: {e}"))?;
        for (name, raw) in entries {
            self.values.entry(name).or_insert(EnvVar(raw));
        }
        Ok(())
    }

    /// The fully expanded environment: [`EnvConfig::values`] with every
    /// `${VAR}` reference resolved from the **host** environment (see
    /// [`super::file::expand_str`]), ready to hand to the sandboxed
    /// command. An unset host variable is an error; the caller reports it.
    ///
    /// This is the environment-value replacement; it runs when the spec is
    /// compiled down to the internal config, so values a program
    /// assembled after parsing are expanded as well.
    pub fn expand_values(&self) -> Result<BTreeMap<String, String>, String> {
        self.values
            .iter()
            .map(|(name, value)| {
                super::file::expand_str(&value.0)
                    .map(|expanded| (name.clone(), expanded))
                    .map_err(|e| format!("Invalid env value {name:?}: {e}"))
            })
            .collect()
    }
}

/// One environment value, exactly as written in the spec file. The
/// `${VAR}` references are expanded from the **host** environment when
/// the config is compiled down (see [`EnvConfig::expand_values`]), so the
/// spec-file view keeps the raw text and the sandbox machinery only ever
/// sees the fully expanded text.
#[derive(Debug, PartialEq, Deserialize, JsonSchema)]
pub struct EnvVar(pub String);

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
