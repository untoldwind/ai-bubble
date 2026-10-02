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
/// - `{"mode": "waf", "allow": [...]}`: like proxy, but the sandbox
///   gets DNS/HTTP/HTTPS servers on 127.0.0.2 (ports 53, 80, 443) that
///   resolve allow-listed names to 127.0.0.2 and forward the traffic
///   from the host side over a Unix socket.
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
        /// Let the connector dial resolved addresses in private, loopback
        /// or link-local ranges (10/8, 172.16/12, 192.168/16, 127/8,
        /// 169.254/16 including the cloud metadata endpoint, ...). Off by
        /// default: an allowed *name* that resolves into such a range would
        /// otherwise become an SSRF primitive dialing from the host's
        /// network position. Turn this on only if the sandbox legitimately
        /// needs LAN/localhost targets — it includes cloud metadata and
        /// loopback services.
        #[serde(default)]
        allow_private: bool,
    },
    /// Run the command in a fresh network namespace behind the in-sandbox
    /// DNS/HTTP/HTTPS servers on 127.0.0.2 (see `crate::waf`).
    Waf {
        /// Allow-list of `host`, `host:port`, or `*.domain[:port]` targets.
        /// A bare `host` entry (no port) is both resolved by the DNS server
        /// (to 127.0.0.2) and connectable. Empty means: nothing is allowed.
        allow: Vec<String>,
        /// See the proxy mode's `allow_private`: the same opt-out, applied
        /// to the waf host's `connect`/`tls-connect` dialing.
        #[serde(default)]
        allow_private: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::super::tests::parse;
    use super::NetConfig;

    #[test]
    fn net_options() {
        let spec = parse(
            r#"{ "net": { "mode": "proxy", "allow": ["example.com:443", "localhost"],
                 "allow_private": true } }"#,
        );
        assert_eq!(
            spec.net,
            NetConfig::Proxy {
                allow: vec!["example.com:443".to_string(), "localhost".to_string()],
                allow_private: true,
            }
        );
        // `allow_private` defaults to false (SSRF protection on).
        let spec = parse(r#"{ "net": { "mode": "proxy", "allow": ["example.com"] } }"#);
        assert!(matches!(
            spec.net,
            NetConfig::Proxy { allow_private: false, .. }
        ));
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
    fn waf_mode() {
        let spec =
            parse(r#"{ "net": { "mode": "waf", "allow": ["example.com:443", "*.example.com"] } }"#);
        assert_eq!(
            spec.net,
            NetConfig::Waf {
                allow: vec!["example.com:443".to_string(), "*.example.com".to_string()],
                allow_private: false,
            }
        );
        // `allow` is mandatory here, too.
        assert!(super::super::tests::parse_err(r#"{ "net": { "mode": "waf" } }"#).is_some());
        // Unknown fields are rejected.
        assert!(
            super::super::tests::parse_err(
                r#"{ "net": { "mode": "waf", "allow": ["x"], "nope": 1 } }"#
            )
            .is_some()
        );
        // And it compiles down to the isolated waf configuration.
        let compiled = super::super::internal::SandboxConfig::compile(&spec);
        assert!(compiled.net.isolated);
        assert_eq!(compiled.net.mode, super::super::internal::NetMode::Waf);
        assert_eq!(
            compiled.net.allow,
            vec!["example.com:443".to_string(), "*.example.com".to_string()]
        );
    }

    #[test]
    fn net_rejects_unknown_fields() {
        // Unknown fields are rejected in proxy mode...
        assert!(
            super::super::tests::parse_err(
                r#"{ "net": { "mode": "proxy", "allow": ["x"], "nope": true } }"#
            )
            .is_some()
        );
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
