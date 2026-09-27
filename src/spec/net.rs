//! Network configuration for the spec file.

use serde::Deserialize;

use schemars::JsonSchema;

/// Network-related configuration for the sandboxed command: how it
/// reaches the network.
///
/// - `{"mode": "host"}` (the default): the command shares the host
///   network.
/// - `{"mode": "proxy", "allow": [...]}`: the command runs in a fresh
///   network namespace and its connections are proxied from the host
///   side, gated by `allow`.
#[derive(Debug, Default, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum NetConfig {
    /// Share the host network (the default).
    #[default]
    Host,
    /// Run the command in a fresh network namespace and proxy its
    /// connections from the host side.
    Proxy {
        /// Allow-list of `host`, `host:port`, or `*.domain[:port]` targets
        /// for the proxy. A `*.domain` entry matches subdomains of `domain`
        /// at any depth, but not `domain` itself.
        /// Required in proxy mode. Empty means: nothing is proxied — every
        /// target must be listed explicitly.
        allow: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse;
    use super::NetConfig;

    #[test]
    fn net_options() {
        let spec = parse(
            r#"{ "net": { "mode": "proxy", "allow": ["example.com:443", "localhost"] } }"#,
        );
        assert_eq!(
            spec.net,
            NetConfig::Proxy {
                allow: vec!["example.com:443".to_string(), "localhost".to_string()]
            }
        );
    }

    #[test]
    fn proxy_mode_requires_allow() {
        // `allow` is mandatory: proxy mode without it is a spec error, so
        // there is never an implicit "proxy everything" default.
        assert!(
            super::super::tests::parse_err(r#"{ "net": { "mode": "proxy" } }"#).is_some(),
            "proxy mode without allow must be rejected"
        );
    }

    #[test]
    fn host_mode_is_default() {
        let spec = parse("{}");
        assert_eq!(spec.net, NetConfig::Host);
        assert_eq!(spec.net, NetConfig::default());
    }

    #[test]
    fn net_rejects_unknown_fields() {
        // Unknown fields are rejected in proxy mode...
        assert!(super::super::tests::parse_err(
            r#"{ "net": { "mode": "proxy", "allow": ["x"], "nope": true } }"#
        )
        .is_some());
        // ...but a unit variant like host has no fields to deny (serde's
        // internally-tagged enums cannot deny unknown fields for unit
        // variants).
        let spec = parse(r#"{ "net": { "mode": "host", "allow": ["x"] } }"#);
        assert_eq!(spec.net, NetConfig::Host);
    }

    #[test]
    fn empty_spec_is_default() {
        let spec = parse("{}");
        assert_eq!(spec, crate::spec::Spec::default());
        assert_eq!(spec.net, NetConfig::Host);
        assert_eq!(spec.hostfs.mappings.len(), 0);
    }
}
