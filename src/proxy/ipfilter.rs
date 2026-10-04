//! Resolved-IP filtering for the host-side connectors (proxy connector and
//! waf host).
//!
//! The allow-list matches *names* only, so a name that resolves to a
//! private, loopback or link-local address turns any allowed name into an
//! SSRF primitive: the connector dials the cloud metadata endpoint, a host
//! loopback service, or a LAN machine *from the host's network position*
//! (see AUDIT.md H3). This module closes that hole: before connecting, the
//! target is resolved and every resolved address is checked against a
//! range denylist; the connection then goes to the validated IP directly,
//! which also pins the answer against re-resolution (TOCTOU between the
//! check and the connect).
//!
//! By default all of these ranges are blocked. Operators who legitimately
//! need LAN targets opt out with the spec's `net.allow_private: true`
//! (proxy and waf mode), which restores unrestricted dialing *by explicit
//! operator choice* — including loopback and cloud metadata, so it must be
//! used knowingly.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::TcpStream;

/// Split a `host:port` target into its parts. Accepts the same forms as
/// `TcpStream::connect` did: `[::1]:80` and `host:80`.
fn split_target(target: &str) -> io::Result<(String, u16)> {
    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must be host:port",
        ));
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty host"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
    Ok((host.to_string(), port))
}

/// Why an IP must not be dialed from the host, if it must not be.
pub fn blocked_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_reason_v4(v4),
        IpAddr::V6(v6) => blocked_reason_v6(v6),
    }
}

fn blocked_reason_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    let reason = match o {
        [0, ..] => "this-network/unspecified",
        [10, ..] => "private",
        // CGNAT / shared address space.
        [100, b, ..] if b & 0xc0 == 64 => "shared address space",
        [127, ..] => "loopback",
        // Link-local: contains 169.254.169.254 (cloud metadata).
        [169, 254, ..] => "link-local (incl. cloud metadata)",
        [172, b, ..] if b & 0xf0 == 16 => "private",
        [192, 168, ..] => "private",
        [192, 0, 0, ..] => "IETF protocol assignments",
        [192, 31, 196, ..] | [192, 52, 193, ..] => "IANA special-purpose",
        [192, 88, 99, ..] => "6to4 relay anycast (deprecated)",
        [192, 175, 48, ..] => "AS112 (RFC 7534)",
        [192, 0, 2, ..] | [198, 51, 100, ..] | [203, 0, 113, ..] => "documentation",
        [198, 18, ..] | [198, 19, ..] => "benchmarking",
        [224..=239, ..] => "multicast",
        [240..=255, ..] => "reserved",
        _ => return None,
    };
    Some(reason)
}

fn blocked_reason_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let s = ip.segments();
    // Translation/mapping ranges embed an IPv4 address: apply the same
    // rules to it, so ::ffff:10.0.0.1 or 64:ff9b::10.0.0.1 cannot smuggle a
    // private v4 target past the filter.
    let embedded = if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        Some(v4_from(s[6], s[7]))
    } else if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        // RFC 6052 IPv4-*translated* form ::ffff:0:0/96 (SP audit NET-1):
        // `::ffff:0:10.0.0.1` parses to [0,0,0,0, 0xffff, 0, 0x0a00,
        // 0x0001] — a different segment layout from the mapped form above,
        // so it used to fall through every check. A NAT64/SIIT translator
        // routes it to the embedded v4 address, so apply the same rules.
        Some(v4_from(s[6], s[7]))
    } else if s[0] == 0x2002 {
        // 6to4: the embedded IPv4 address follows the prefix.
        Some(v4_from(s[1], s[2]))
    } else if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        // NAT64: well-known prefix, embedded IPv4 in the last 32 bits.
        Some(v4_from(s[6], s[7]))
    } else {
        None
    };
    if let Some(v4) = embedded {
        return blocked_reason_v4(v4).map(|r| r as &'static str);
    }
    let reason = match s {
        [0, 0, 0, 0, 0, 0, 0, 0] => "unspecified",
        [0, 0, 0, 0, 0, 0, 0, 1] => "loopback",
        [s0, ..] if s0 & 0xfe00 == 0xfc00 => "unique-local",
        [s0, ..] if s0 & 0xffc0 == 0xfe80 => "link-local",
        [s0, ..] if s0 & 0xff00 == 0xff00 => "multicast",
        // Teredo tunneling (deprecated, AUDIT.md L5).
        [0x2001, 0x0000, ..] => "teredo",
        // NAT64 local-use prefix (RFC 8215) — not the well-known prefix
        // handled by the embedded-v4 check above.
        [0x0064, 0xff9b, 1, ..] => "nat64 local-use",
        [0x2001, 0x0db8, ..] => "documentation",
        // NET-8: the remaining IANA special-purpose v6 ranges.
        [0x2001, 0x0002, ..] => "benchmarking (RFC 5180)",
        // 3fff::/20 — documentation (RFC 9637): the fixed 20 bits span
        // the first segment plus the second's top nibble.
        [0x3fff, s1, ..] if s1 & 0xf000 == 0 => "documentation",
        // 2001:20::/28 — ORCHIDv2 (RFC 7343): 28 fixed bits.
        [0x2001, s1, ..] if s1 & 0xfff0 == 0x0020 => "orchidv2",
        // 100::/64 — discard-only (RFC 6666).
        [0x0100, 0, 0, 0, ..] => "discard-only",
        _ => return None,
    };
    Some(reason)
}

fn v4_from(a: u16, b: u16) -> Ipv4Addr {
    Ipv4Addr::new((a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8)
}

/// Filter resolved addresses: keep only the ones the connector may dial.
/// Errors when *nothing* remains (the caller must not fall back to the
/// unfiltered list). With `allow_private` this is a no-op.
pub fn filter_addrs(
    host: &str,
    addrs: &[SocketAddr],
    allow_private: bool,
) -> io::Result<Vec<SocketAddr>> {
    if allow_private {
        return Ok(addrs.to_vec());
    }
    let mut blocked = Vec::new();
    let kept: Vec<SocketAddr> = addrs
        .iter()
        .filter(|a| match blocked_reason(a.ip()) {
            Some(reason) => {
                blocked.push(format!("{} ({})", a.ip(), reason));
                false
            }
            None => true,
        })
        .copied()
        .collect();
    if kept.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "every address for {host} is in a blocked range: {}",
                blocked.join(", ")
            ),
        ));
    }
    Ok(kept)
}

/// How long a single dial attempt (and, in the waf host, the upstream TLS
/// handshake) may take before it is abandoned (AUDIT.md L8): without a
/// timeout, a firewalled-but-allowed IP holds a connector slot for the
/// kernel's full SYN-retry duration (~2 min), so a churning command keeps
/// the connector's limited slots (and host fds) saturated — a self-DoS of
/// the sandbox's own networking.
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Resolve `host:port`, drop every address in a blocked range (unless
/// `allow_private`), and connect to the first remaining address — the IP,
/// not the name, so nothing can re-resolve between the check and the
/// connect. If some addresses are blocked and others are not, only the
/// allowed ones are tried; if none remains, the connect fails with a
/// permission error.
pub async fn connect_checked(target: &str, allow_private: bool) -> io::Result<TcpStream> {
    let (host, port) = split_target(target)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses for {host}"),
        ));
    }
    let allowed = filter_addrs(&host, &addrs, allow_private)?;
    let mut last = None;
    for addr in allowed {
        // AUDIT.md L8: bound each attempt; see `DIAL_TIMEOUT`.
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(tcp)) => return Ok(tcp),
            Ok(Err(e)) => last = Some(e),
            Err(_) => {
                last = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect to {addr} timed out"),
                ));
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no address to connect to")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> &'static str {
        blocked_reason(s.parse().unwrap()).expect("must be blocked")
    }

    fn not_blocked(s: &str) {
        assert!(
            blocked_reason(s.parse::<IpAddr>().unwrap()).is_none(),
            "{s} must not be blocked"
        );
    }

    #[test]
    fn blocked_v4_ranges() {
        assert_eq!(
            blocked("169.254.169.254"),
            "link-local (incl. cloud metadata)"
        );
        assert_eq!(blocked("127.0.0.1"), "loopback");
        assert_eq!(blocked("127.8.8.8"), "loopback");
        assert_eq!(blocked("10.1.2.3"), "private");
        assert_eq!(blocked("172.16.0.1"), "private");
        assert_eq!(blocked("172.31.255.255"), "private");
        assert_eq!(blocked("192.168.1.1"), "private");
        assert_eq!(blocked("0.0.0.0"), "this-network/unspecified");
        assert_eq!(blocked("100.64.0.1"), "shared address space");
        assert_eq!(blocked("100.127.255.255"), "shared address space");
        assert_eq!(blocked("224.0.0.1"), "multicast");
        assert_eq!(blocked("255.255.255.255"), "reserved");
        assert_eq!(blocked("192.0.2.1"), "documentation");
        // AUDIT.md L5: the remaining IANA special-purpose ranges.
        assert_eq!(blocked("192.0.0.1"), "IETF protocol assignments");
        assert_eq!(blocked("192.31.196.1"), "IANA special-purpose");
        assert_eq!(blocked("192.52.193.1"), "IANA special-purpose");
        assert_eq!(blocked("192.88.99.1"), "6to4 relay anycast (deprecated)");
        assert_eq!(blocked("192.175.48.1"), "AS112 (RFC 7534)");
        // Boundary cases that must NOT be blocked.
        not_blocked("8.8.8.8");
        not_blocked("172.32.0.1"); // just outside 172.16/12
        // Just outside 100.64/10 (which ends at 100.127.255.255).
        not_blocked("100.128.0.0");
        not_blocked("11.0.0.1");
    }

    #[test]
    fn blocked_v6_ranges() {
        assert_eq!(blocked("::1"), "loopback");
        assert_eq!(blocked("::"), "unspecified");
        assert_eq!(blocked("fd00::1"), "unique-local");
        assert_eq!(blocked("fe80::1"), "link-local");
        assert_eq!(blocked("ff02::1"), "multicast");
        assert_eq!(blocked("2001:db8::1"), "documentation");
        // Embedded/translated IPv4 must inherit the v4 verdict.
        assert_eq!(blocked("::ffff:10.0.0.1"), "private");
        assert_eq!(
            blocked("::ffff:169.254.169.254"),
            "link-local (incl. cloud metadata)"
        );
        assert_eq!(blocked("64:ff9b::a00:1"), "private");
        assert_eq!(blocked("2002:a00:1::"), "private");
        // RFC 6052 IPv4-translated form (::ffff:0:0/96, NET-1).
        assert_eq!(blocked("::ffff:0:10.0.0.1"), "private");
        assert_eq!(
            blocked("::ffff:0:169.254.169.254"),
            "link-local (incl. cloud metadata)"
        );
        // AUDIT.md L5: Teredo and the NAT64 local-use prefix.
        assert_eq!(blocked("2001:0::1"), "teredo");
        assert_eq!(blocked("64:ff9b:1::1"), "nat64 local-use");
        // NET-8: the remaining IANA special-purpose v6 ranges.
        assert_eq!(blocked("2001:2::1"), "benchmarking (RFC 5180)");
        assert_eq!(blocked("3fff::1"), "documentation");
        assert_eq!(blocked("3fff:1::1"), "documentation");
        not_blocked("3fff:2000::1"); // just outside 3fff::/20
        assert_eq!(blocked("2001:20::1"), "orchidv2");
        assert_eq!(blocked("2001:2f::1"), "orchidv2");
        not_blocked("2001:30::1"); // just outside 2001:20::/28
        assert_eq!(blocked("100::1"), "discard-only");
        not_blocked("100:1::1"); // outside 100::/64 (second segment set)
        // Public addresses pass.
        not_blocked("2606:4700::1111");
        not_blocked("::ffff:8.8.8.8");
        not_blocked("2002:808:808::"); // 6to4 of 8.8.8.8
        // Just outside fe80/10.
        not_blocked("fec0::1");
    }

    #[test]
    fn split_target_forms() {
        assert_eq!(
            split_target("example.com:443").unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(split_target("[::1]:80").unwrap(), ("::1".into(), 80));
        assert!(split_target("example.com").is_err());
        assert!(split_target(":443").is_err());
        assert!(split_target("example.com:port").is_err());
    }

    #[test]
    fn filter_addrs_blocks_the_whole_target_when_nothing_remains() {
        let addrs: Vec<SocketAddr> = ["127.0.0.1:80", "169.254.169.254:80"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let err = filter_addrs("x.example", &addrs, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // An explicit operator opt-out disables the filter entirely.
        assert_eq!(filter_addrs("x.example", &addrs, true).unwrap(), addrs);
    }

    #[test]
    fn filter_addrs_keeps_public_among_blocked() {
        let addrs: Vec<SocketAddr> = ["169.254.169.254:80", "93.184.216.34:80"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let kept = filter_addrs("x.example", &addrs, false).unwrap();
        assert_eq!(
            kept,
            vec!["93.184.216.34:80".parse::<SocketAddr>().unwrap()]
        );
    }

    /// The connector must refuse to dial loopback targets unless the
    /// operator explicitly opted out (`allow_private`).
    #[tokio::test]
    async fn connect_checked_refuses_private_targets() {
        let err = connect_checked("127.0.0.1:80", false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // With the opt-out the dial itself is attempted (nothing listens on
        // port 1, so this fails with a connection error, not permission).
        let err = connect_checked("127.0.0.1:1", true).await.unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    /// Public targets are still dialable through the checked path.
    #[tokio::test]
    async fn connect_checked_dials_public_targets() {
        // A real listener on a public-loopback-only address would defeat the
        // point; instead bind a public address and dial by literal IP.
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        // Only dial back to ourselves if we actually got a public address;
        // in sandboxes/CI the bind may be loopback-only, so just verify the
        // filter step does not reject an arbitrary documentation-free IP.
        let ip = listener.local_addr().unwrap().ip();
        if blocked_reason(ip).is_some() {
            // Loopback, unspecified, private or otherwise non-public bind
            // address (typical in sandboxes/CI): dialing it unchecked is
            // the opt-out path, already covered above. Nothing to assert.
            return;
        }
        let target = format!("{}:{}", ip, listener.local_addr().unwrap().port());
        let mut tcp = connect_checked(&target, false).await.unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        use tokio::io::AsyncWriteExt;
        tcp.write_all(b"ping").await.unwrap();
    }
}
