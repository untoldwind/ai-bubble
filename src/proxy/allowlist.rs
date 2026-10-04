//! The allow-list, shared by the proxy and the waf mode.
//!
//! The list is built on the host from the spec's `net` section. The
//! proxy's connector and the waf host (`crate::waf::host`) re-check every
//! request; the sandbox-side HTTP CONNECT proxy answers CONNECT requests
//! early with 403.

//! The list is runtime-swappable: the launcher and each frontend hold a
//! cheap-clone [`SharedAllow`] handle to the same instance, and a swap
//! replaces the whole list (`net-set` semantics — see `PLAN.md`). The
//! convention mirrors `crate::hostfs::SharedPatterns`: locks are recovered
//! when poisoned (`unwrap_or_else(|e| e.into_inner())`), never panicked
//! on, and swaps are full replacements — a reader sees either the old or
//! the new list, never a mix.

/// The allow-list, shared between the launcher (which keeps the
/// authoritative copy) and the frontends (connector, sandbox CONNECT
/// proxy, waf host), so it can be **swapped at runtime**.
///
/// Every accepted connection takes a snapshot ([`load`]) and keeps it for
/// its whole lifetime: a swap affects *new* connections only, never
/// already-established ones or the raw pipes behind them. This is the
/// shape `PLAN.md` records ("clone the allow-list per accepted
/// connection") and the one `crate::control` already codes against.
pub type SharedAllow = std::sync::Arc<std::sync::RwLock<Vec<String>>>;

/// Wrap the compiled allow-list in a shared handle (see [`SharedAllow`]).
pub fn shared(allow: Vec<String>) -> SharedAllow {
    std::sync::Arc::new(std::sync::RwLock::new(allow))
}

/// A snapshot of the currently active list, taken when a connection is
/// accepted: the connection then checks against this copy for its whole
/// lifetime, whatever swaps happen meanwhile.
pub fn load(allow: &SharedAllow) -> Vec<String> {
    allow.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Check a `host:port` target against the allow-list. An empty list allows
/// nothing: every target must be listed explicitly. List entries are `host`
/// (any port) or `host:port`. An entry host may start with `*.` for a simple
/// subdomain wildcard: `*.github.com` matches `api.github.com` (any suffix
/// ending in `.github.com`), but not `github.com` itself. Matching is
/// case-insensitive.
pub fn target_allowed(target: &str, allow: &[String]) -> bool {
    if allow.is_empty() {
        return false;
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (target, None),
    };
    allow.iter().any(|entry| match entry.rsplit_once(':') {
        Some((ehost, eport)) => match eport.parse::<u16>() {
            Ok(eport) => host_matches(ehost, host) && Some(eport) == port,
            Err(_) => host_matches(entry, host),
        },
        None => host_matches(entry, host),
    })
}

/// Check a bare host name against the allow-list, ignoring entry ports.
/// Used for name resolution (DNS): a listed `host:port` entry also
/// permits resolving `host`, since the port restriction is enforced
/// again on every `connect`. An empty list allows nothing.
pub fn host_allowed(host: &str, allow: &[String]) -> bool {
    if allow.is_empty() {
        return false;
    }
    allow
        .iter()
        .any(|entry| host_matches(entry.rsplit_once(':').map_or(entry, |(h, _)| h), host))
}

/// Match an allow-list host pattern against a target host. A leading `*.`
/// matches any host whose remainder is a non-empty dot-separated suffix, so
/// `*.example.com` matches `api.example.com` and `a.b.example.com` but not
/// `example.com`.
fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        !suffix.is_empty()
            && !suffix.contains('*')
            && ends_with_ignore_ascii_case(host, suffix)
            && host[..host.len() - suffix.len()].ends_with('.')
            && !host.contains('*')
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Case-insensitive `str::ends_with`.
fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    haystack.len() >= suffix.len()
        && haystack[haystack.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_matching() {
        let allow: Vec<String> = ["example.com:443", "localhost"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(target_allowed("example.com:443", &allow));
        assert!(!target_allowed("example.com:80", &allow));
        assert!(!target_allowed("evil.com:443", &allow));
        // "localhost" has no port: any port is fine.
        assert!(target_allowed("localhost:1234", &allow));
        // Empty list allows nothing: every target must be listed
        // explicitly.
        assert!(!target_allowed("anything.example:9999", &[]));
    }

    #[test]
    fn allow_list_host_only_check() {
        // For DNS resolution, port restrictions are not the question: a
        // listed host is resolvable, with or without a port on the entry.
        let allow: Vec<String> = ["example.com:443", "*.github.com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(host_allowed("example.com", &allow));
        assert!(host_allowed("api.github.com", &allow));
        assert!(!host_allowed("evil.com", &allow));
        assert!(!host_allowed("github.com", &allow));
        assert!(!host_allowed("example.com", &[]));
    }

    #[test]
    fn allow_list_subdomain_wildcards() {
        let allow: Vec<String> = ["github.com:443", "*.github.com", "*.example.com:443"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Exact entry still matches exactly, not subdomains.
        assert!(target_allowed("github.com:443", &allow));
        assert!(!target_allowed("evil.com:443", &allow));
        // Wildcard matches subdomains at any depth, on any port when the
        // entry carries none.
        assert!(target_allowed("api.github.com:80", &allow));
        assert!(target_allowed("a.b.github.com:80", &allow));
        // The wildcard alone does not match the bare domain.
        let bare: Vec<String> = ["*.github.com"].iter().map(|s| s.to_string()).collect();
        assert!(!target_allowed("github.com:443", &bare));
        // Wildcard entries can carry a port.
        assert!(target_allowed("api.example.com:443", &allow));
        assert!(!target_allowed("api.example.com:80", &allow));
        // No cross-domain tricks.
        assert!(!target_allowed("notgithub.com:443", &allow));
        assert!(!target_allowed("evil.com:443", &allow));
        // Case-insensitive.
        assert!(target_allowed("API.GitHub.com:443", &allow));
    }

    /// Swapping the shared list affects new connections only: a snapshot
    /// taken before the swap keeps checking against the old list.
    #[test]
    fn swap_affects_new_connections_only() {
        let shared = shared(vec!["old.example:443".to_string()]);
        let established = load(&shared);
        assert!(target_allowed("old.example:443", &established));

        // The runtime swap (what `control::net_apply` does).
        *shared.write().unwrap_or_else(|e| e.into_inner()) = vec!["new.example:443".to_string()];

        // The established connection keeps its snapshot.
        assert!(target_allowed("old.example:443", &established));
        assert!(!target_allowed("new.example:443", &established));
        // A new connection sees the new rules.
        let fresh = load(&shared);
        assert!(target_allowed("new.example:443", &fresh));
        assert!(!target_allowed("old.example:443", &fresh));
    }
}
