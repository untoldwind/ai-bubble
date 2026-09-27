//! Isolated-network configuration for the spec file.

use serde::Deserialize;

use schemars::JsonSchema;

/// Network-related configuration for isolated networking.
#[derive(Debug, Default, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Run the command in a fresh network namespace and proxy its
    /// connections from the host side.
    pub isolated: bool,
    /// Allow-list of `host`, `host:port`, or `*.domain[:port]` targets for
    /// the proxy. A `*.domain` entry matches subdomains of `domain` at any
    /// depth, but not `domain` itself.
    /// Empty means: allow everything.
    pub allow: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse;

    #[test]
    fn net_options() {
        let spec =
            parse(r#"{ "net": { "isolated": true, "allow": ["example.com:443", "localhost"] } }"#);
        assert!(spec.net.isolated);
        assert_eq!(spec.net.allow, ["example.com:443", "localhost"]);
    }

    #[test]
    fn empty_spec_is_default() {
        let spec = parse("{}");
        assert_eq!(spec, crate::spec::Spec::default());
        assert!(!spec.net.isolated);
        assert_eq!(spec.hostfs.mappings.len(), 0);
    }
}
