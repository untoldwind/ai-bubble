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
///
/// Host mode carries four opt-in flags (all default `false`) for the
/// address families that are *not* the point of host networking and are
/// dangerous by default:
///
/// - `unix_sockets` (default `false`): whether the command may create
///   Unix-domain sockets. Off by default — Unix sockets are a
///   local-IPC escape hatch (abstract-namespace sockets like the D-Bus
///   system bus live in the *network namespace*, so host-network mode
///   without this default would expose them to an untrusted command;
///   see AUDIT.md M3).
/// - `netlink` (default `false`): whether the command may create
///   netlink sockets. Unprivileged `NETLINK_ROUTE`/`NETLINK_SOCK_DIAG`
///   hand the command the host's network state and unix-socket
///   inventory (reconnaissance), and the netlink surface is a
///   recurring kernel-CVE area (AUDIT.md M3).
/// - `vsock` (default `false`): whether the command may create
///   AF_VSOCK sockets. Socket creation is unprivileged and vsock is
///   *not* network-namespaced, so on VMs the command could connect to
///   host/hypervisor vsock services (e.g. CID 2) (AUDIT.md M3).
/// - `bluetooth` (default `false`): whether the command may create
///   AF_BLUETOOTH sockets (AUDIT.md M3).
///
/// Proxy/waf modes run in a fresh network namespace, where the
/// abstract-socket exposure does not exist, and always allow all four
/// families.
#[derive(Debug, PartialEq, Deserialize, Clone, JsonSchema)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum NetConfig {
    /// Share the host network (the default).
    Host {
        /// Whether the command may create Unix-domain sockets (abstract
        /// or filesystem). Off by default: a seccomp filter denies
        /// `socket(AF_UNIX)`/`socketpair(AF_UNIX)` (and `io_uring_setup`,
        /// which can create sockets without `socket(2)`).
        #[serde(default)]
        unix_sockets: bool,
        /// Whether the command may create netlink sockets. Off by
        /// default: unprivileged netlink exposes the host's network
        /// state (reconnaissance) and is a recurring kernel-CVE area.
        #[serde(default)]
        netlink: bool,
        /// Whether the command may create AF_VSOCK sockets. Off by
        /// default: creation is unprivileged and vsock is not
        /// network-namespaced, so on VMs the command could reach
        /// host/hypervisor vsock services.
        #[serde(default)]
        vsock: bool,
        /// Whether the command may create AF_BLUETOOTH sockets. Off by
        /// default.
        #[serde(default)]
        bluetooth: bool,
    },
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

impl Default for NetConfig {
    /// Host mode, every dangerous family denied (the safe default).
    fn default() -> Self {
        NetConfig::Host {
            unix_sockets: false,
            netlink: false,
            vsock: false,
            bluetooth: false,
        }
    }
}

impl NetConfig {
    /// Whether the sandboxed command may create Unix-domain sockets.
    /// Only host mode can deny them (the spec's `net.host.unix_sockets`,
    /// default `false`); the isolated network-namespace modes always
    /// allow them.
    pub fn unix_sockets(&self) -> bool {
        match self {
            NetConfig::Host { unix_sockets, .. } => *unix_sockets,
            NetConfig::Proxy { .. } | NetConfig::Waf { .. } => true,
        }
    }

    /// Whether the sandboxed command may create netlink sockets (the
    /// spec's `net.host.netlink`, default `false`; isolated modes
    /// always allow).
    pub fn netlink(&self) -> bool {
        match self {
            NetConfig::Host { netlink, .. } => *netlink,
            NetConfig::Proxy { .. } | NetConfig::Waf { .. } => true,
        }
    }

    /// Whether the sandboxed command may create AF_VSOCK sockets (the
    /// spec's `net.host.vsock`, default `false`; isolated modes always
    /// allow).
    pub fn vsock(&self) -> bool {
        match self {
            NetConfig::Host { vsock, .. } => *vsock,
            NetConfig::Proxy { .. } | NetConfig::Waf { .. } => true,
        }
    }

    /// Whether the sandboxed command may create AF_BLUETOOTH sockets
    /// (the spec's `net.host.bluetooth`, default `false`; isolated
    /// modes always allow).
    pub fn bluetooth(&self) -> bool {
        match self {
            NetConfig::Host { bluetooth, .. } => *bluetooth,
            NetConfig::Proxy { .. } | NetConfig::Waf { .. } => true,
        }
    }
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
            NetConfig::Proxy {
                allow_private: false,
                ..
            }
        ));
    }

    #[test]
    fn unix_sockets_are_denied_by_default_in_host_mode() {
        // Host mode defaults to denying Unix-domain sockets (AUDIT.md
        // M3); the user must actively opt in.
        for json in ["{}", r#"{ "net": { "mode": "host" } }"#] {
            let spec = parse(json);
            assert!(
                !spec.net.unix_sockets(),
                "spec {json} must default to no AF_UNIX"
            );
        }
        let spec = parse(r#"{ "net": { "mode": "host", "unix_sockets": true } }"#);
        assert!(spec.net.unix_sockets(), "opt-in must allow AF_UNIX");
        // The isolated modes always allow them (their network namespace
        // already isolates abstract sockets).
        for json in [
            r#"{ "net": { "mode": "proxy", "allow": ["example.com"] } }"#,
            r#"{ "net": { "mode": "waf", "allow": ["example.com"] } }"#,
        ] {
            let spec = parse(json);
            assert!(spec.net.unix_sockets(), "spec {json} must allow AF_UNIX");
        }
        // ...and reject the meaningless flag there.
        for json in [
            r#"{ "net": { "mode": "proxy", "allow": [], "unix_sockets": true } }"#,
            r#"{ "net": { "mode": "waf", "allow": [], "unix_sockets": false } }"#,
        ] {
            assert!(
                super::super::tests::parse_err(json).is_some(),
                "{json} must be rejected"
            );
        }
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
        assert_eq!(spec.net, NetConfig::default());
        assert!(!spec.net.unix_sockets());
        assert!(!spec.net.netlink());
        assert!(!spec.net.vsock());
        assert!(!spec.net.bluetooth());
    }

    #[test]
    fn dangerous_families_are_denied_by_default_in_host_mode() {
        // AUDIT.md M3: besides AF_UNIX, the other dangerous-but
        // unprivileged-creatable families (netlink, vsock, bluetooth)
        // are denied by default in host mode and need an explicit opt-in.
        for json in [
            r#"{ "net": { "mode": "host", "netlink": true } }"#,
            r#"{ "net": { "mode": "host", "vsock": true } }"#,
            r#"{ "net": { "mode": "host", "bluetooth": true } }"#,
        ] {
            let spec = parse(json);
            assert!(!spec.net.unix_sockets(), "{json}: AF_UNIX stays denied");
        }
        let spec = parse(r#"{ "net": { "mode": "host", "netlink": true } }"#);
        assert!(spec.net.netlink(), "netlink opt-in must allow AF_NETLINK");
        assert!(!spec.net.vsock(), "netlink opt-in must not touch vsock");
        let spec = parse(r#"{ "net": { "mode": "host", "vsock": true } }"#);
        assert!(spec.net.vsock(), "vsock opt-in must allow AF_VSOCK");
        let spec = parse(r#"{ "net": { "mode": "host", "bluetooth": true } }"#);
        assert!(
            spec.net.bluetooth(),
            "bluetooth opt-in must allow AF_BLUETOOTH"
        );
        // The isolated modes always allow all four (their network
        // namespace already isolates the namespace-scoped families).
        for json in [
            r#"{ "net": { "mode": "proxy", "allow": ["example.com"] } }"#,
            r#"{ "net": { "mode": "waf", "allow": ["example.com"] } }"#,
        ] {
            let spec = parse(json);
            assert!(spec.net.netlink(), "{json} must allow AF_NETLINK");
            assert!(spec.net.vsock(), "{json} must allow AF_VSOCK");
            assert!(spec.net.bluetooth(), "{json} must allow AF_BLUETOOTH");
        }
        // ...and reject the meaningless flags there.
        for json in [
            r#"{ "net": { "mode": "proxy", "allow": [], "netlink": true } }"#,
            r#"{ "net": { "mode": "waf", "allow": [], "vsock": true } }"#,
            r#"{ "net": { "mode": "waf", "allow": [], "bluetooth": false } }"#,
        ] {
            assert!(
                super::super::tests::parse_err(json).is_some(),
                "{json} must be rejected"
            );
        }
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
        // ...and the host variant, too — now that it is a struct variant with
        // its own fields (this also fixes the L7 silent-discard for host
        // mode; the allow list makes no sense there).
        assert!(
            super::super::tests::parse_err(r#"{ "net": { "mode": "host", "allow": ["x"] } }"#)
                .is_some()
        );
        // The host-mode family flags are the only fields there.
        let spec = parse(
            r#"{ "net": { "mode": "host", "unix_sockets": true, "netlink": false,
                 "vsock": false, "bluetooth": true } }"#,
        );
        assert_eq!(
            spec.net,
            NetConfig::Host {
                unix_sockets: true,
                netlink: false,
                vsock: false,
                bluetooth: true,
            }
        );
    }

    #[test]
    fn unix_sockets_compile_into_the_seccomp_policy() {
        use super::super::internal::SandboxConfig;
        use super::super::tests::parse;
        // Default (denied): a filter exists even without a `seccomp`
        // section — the AF_UNIX denial is its only content.
        let compiled = SandboxConfig::compile(&parse("{}"));
        let policy = compiled.seccomp.expect("default must install a filter");
        assert_eq!(
            policy.sockets(),
            &super::super::internal::SocketGate::default(),
            "default must deny every gated family"
        );
        assert_eq!(policy.syscalls(), &[] as &[i64], "no extra denies needed");
        assert!(!policy.is_allowlist());

        // Opting in to every family with no seccomp section compiles to no
        // filter at all.
        let compiled = SandboxConfig::compile(&parse(
            r#"{ "net": { "mode": "host", "unix_sockets": true, "netlink": true,
                 "vsock": true, "bluetooth": true } }"#,
        ));
        assert!(compiled.seccomp.is_none());

        // A partial opt-in (some family still denied) keeps the filter.
        let compiled = SandboxConfig::compile(&parse(
            r#"{ "net": { "mode": "host", "unix_sockets": true, "netlink": true } }"#,
        ));
        let policy = compiled
            .seccomp
            .expect("partial opt-in must keep the filter");
        assert!(policy.sockets().unix_sockets && policy.sockets().netlink);
        assert!(!policy.sockets().vsock && !policy.sockets().bluetooth);

        // Opting in with a seccomp section keeps that section's policy
        // (with the flag recorded for the sandbox to honor).
        let compiled = SandboxConfig::compile(&parse(
            r#"{ "net": { "mode": "host", "unix_sockets": true },
                 "seccomp": { "block": ["ptrace"] } }"#,
        ));
        let policy = compiled.seccomp.expect("seccomp section kept");
        assert!(policy.sockets().unix_sockets);
        assert_eq!(policy.syscalls(), &[syscalls::Sysno::ptrace as i64]);

        // And a seccomp section without the opt-in keeps the denial.
        let compiled = SandboxConfig::compile(&parse(r#"{ "seccomp": { "block": ["ptrace"] } }"#));
        let policy = compiled.seccomp.expect("seccomp section kept");
        assert!(!policy.sockets().unix_sockets);

        // The isolated modes always allow AF_UNIX: no flag, no filter
        // unless the spec configures a seccomp section.
        let compiled = SandboxConfig::compile(&parse(
            r#"{ "net": { "mode": "proxy", "allow": ["example.com"] } }"#,
        ));
        assert!(compiled.seccomp.is_none());
        let compiled = SandboxConfig::compile(&parse(
            r#"{ "net": { "mode": "waf", "allow": ["example.com"] } }"#,
        ));
        assert!(compiled.seccomp.is_none());
    }

    #[test]
    fn empty_spec_is_default() {
        let spec = parse("{}");
        assert_eq!(spec, crate::spec::Spec::default());
        assert_eq!(spec.net, NetConfig::default());
        assert_eq!(spec.hostfs.mappings.len(), 0);
    }
}
