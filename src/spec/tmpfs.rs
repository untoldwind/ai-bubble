//! Octal tmpfs permission modes (`--perms` for bwrap's `--tmpfs`).

use serde::Deserialize;

/// An octal permission mode (`--perms` for bwrap's `--tmpfs`).
///
/// Accepts either a JSON number (`755`) or string (`"0755"`); both are
/// interpreted as *octal*, like bwrap does on the command line.
///
/// Its schema is described by hand in the [`schemars::JsonSchema`]
/// implementation below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpfsPerms(pub u32);

impl serde::Serialize for TmpfsPerms {
    /// Serialized as the octal digit string the spec file spells (the
    /// deserializer accepts a number or such a string; a bare number
    /// would be re-read as *decimal* and change the mode).
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:o}", self.0))
    }
}

impl schemars::JsonSchema for TmpfsPerms {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TmpfsPerms".into()
    }

    fn inline_schema() -> bool {
        // Inline the oneOf; the type has no name in the JSON format.
        true
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An octal permission mode like bwrap's `--perms`: a JSON number \
                            (`755`) or string (\"0755\"), both interpreted as *octal*.",
            "oneOf": [
                // A bare number is a sequence of octal digits, like
                // bwrap's command line: 755 means 0o755.
                {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 0o7777_i64,
                },
                // A string of (leading-zero-tolerant) octal digits.
                {
                    "type": "string",
                    "pattern": "^[0-7]{1,4}$",
                },
            ],
        })
    }
}

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
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Unsigned(v), &self)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_option_formatting() {
        assert_eq!(TmpfsPerms::DEFAULT.mount_option(), "mode=0755");
        assert_eq!(TmpfsPerms(0o700).mount_option(), "mode=0700");
    }

    #[test]
    fn octal_modes_fit_in_mode_t() {
        assert_eq!(octal_from_u64(0).unwrap(), 0);
        assert_eq!(octal_from_u64(0o7777).unwrap(), 0o7777);
        assert!(octal_from_u64(0o10000).is_err());
    }
}
