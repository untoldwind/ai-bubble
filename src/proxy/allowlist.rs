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

/// Split a `host:port` string IPv6-bracket-aware (NET-6): the naive
/// `rsplit_once(':')` mis-parses IPv6 literals (`::1` → host `:`, port
/// `1`), so `host_allowed` could never match one and `example.com:443x`
/// became a silently dead entry. Returns `(host, port_suffix)`:
///
/// * `[::1]:443` → (`::1`, Some(`443`))
/// * `[::1]` → (`::1`, None)
/// * `example.com:443` → (`example.com`, Some(`443`))
/// * `::1` (a bare IPv6 literal, several colons) → (`::1`, None)
/// * `example.com` → (`example.com`, None)
///
/// A suffix is only recognized as a port when it is non-empty and all
/// digits and the host part contains no colon — anything else (`443x`,
/// an empty port, a second colon) is not a port, so the caller sees the
/// entry/target as a whole and can reject it.
fn split_host_port(s: &str) -> (&str, Option<&str>) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        return (host, rest[end + 1..].strip_prefix(':'));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        _ => (s, None),
    }
}

/// Validate one allow-list entry (NET-6): the port suffix, if any, must
/// parse as a port number. Called at load time (spec parse and the
/// control plane) so a dead entry (`example.com:443x`, `host:`) is
/// rejected instead of silently never matching. Unlike
/// [`split_host_port`] (which must stay lenient for *targets*), a
/// load-time entry with a colon must be unambiguous.
pub(crate) fn validate_entry(entry: &str) -> Result<(), String> {
    let invalid = |why: &str| format!("invalid allow entry {entry:?}: {why}").to_string();
    if entry.is_empty() {
        return Err(invalid("empty entry"));
    }
    if entry.starts_with('[') {
        let Some(end) = entry.find(']') else {
            return Err(invalid("unterminated IPv6 bracket"));
        };
        let after = &entry[end + 1..];
        if let Some(port) = after.strip_prefix(':') {
            port.parse::<u16>()
                .map_err(|_| invalid(&format!("{port:?} is not a port number")))?;
        } else if !after.is_empty() {
            return Err(invalid("trailing garbage after the IPv6 literal"));
        }
        if &entry[1..end] == "" {
            return Err(invalid("empty host"));
        }
        return Ok(());
    }
    if let Some(idx) = entry.rfind(':') {
        let (host, port) = (&entry[..idx], &entry[idx + 1..]);
        if host.contains(':') {
            // A bare IPv6 literal (several colons): no port suffix.
            return Ok(());
        }
        port.parse::<u16>()
            .map_err(|_| invalid(&format!("{port:?} is not a port number")))?;
    }
    Ok(())
}

/// Check a `host:port` target against the allow-list. An empty list allows
/// nothing: every target must be listed explicitly. List entries are `host`
/// (any port) or `host:port`. An entry host may start with `*.` for a simple
/// subdomain wildcard: `*.github.com` matches `api.github.com` (any suffix
/// ending in `.github.com`), but not `github.com` itself. Matching is
/// case-insensitive. IPv6 targets and entries are matched bracket-free
/// ([`split_host_port`]).
pub fn target_allowed(target: &str, allow: &[String]) -> bool {
    if allow.is_empty() {
        return false;
    }
    let (host, port) = split_host_port(target);
    let port = port.and_then(|p| p.parse::<u16>().ok());
    allow.iter().any(|entry| {
        let (ehost, eport) = split_host_port(entry);
        match eport {
            // A port-less entry allows any port.
            None => host_matches(ehost, host),
            Some(p) => match p.parse::<u16>() {
                Ok(eport) => host_matches(ehost, host) && Some(eport) == port,
                // Not a valid port: the entry is dead (rejected at load
                // time); it matches nothing here — fail closed.
                Err(_) => false,
            },
        }
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
        .any(|entry| host_matches(split_host_port(entry).0, host))
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
    fn ipv6_targets_and_entries() {
        // NET-6: bracket-aware parsing — a bare IPv6 literal used to be
        // mis-split into host ":" port 1, so it could never match.
        let allow: Vec<String> = ["[::1]:443", "[2001:db8::1]", "example.com:443"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(target_allowed("[::1]:443", &allow));
        assert!(!target_allowed("[::1]:80", &allow));
        assert!(target_allowed("[2001:db8::1]:9999", &allow)); // no port on entry
        assert!(!target_allowed("[2001:db8::2]:9999", &allow));
        assert!(host_allowed("::1", &allow));
        assert!(host_allowed("2001:db8::1", &allow));
        assert!(!host_allowed("2001:db8::2", &allow));
    }

    #[test]
    fn validate_entry_rejects_dead_entries() {
        assert!(validate_entry("example.com:443").is_ok());
        assert!(validate_entry("[::1]:443").is_ok());
        assert!(validate_entry("::1").is_ok());
        assert!(validate_entry("example.com:443x").is_err());
        assert!(validate_entry("example.com:").is_err());
        assert!(validate_entry("example.com:99999").is_err());
        assert!(validate_entry("").is_err());
    }

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
