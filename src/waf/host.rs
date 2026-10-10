//! The host side of the waf command protocol.
//!
//! This code runs in the original ai-bubble process, i.e. in the host
//! network namespace. It serves the pre-fork net mux socketpair
//! ([`crate::ipc::netmux`]) — which the command cannot reach at all: the
//! pair has no filesystem name and lives only as fds in P and this
//! process (see `netns.rs`) — and executes the command vocabulary of
//! [`super`](crate::waf): `resolve-dns`, `connect`, `tls-cert` and
//! `tls-connect`. Every request is checked against the allow-list here —
//! the single enforcement point of this mode.
//!
//! For HTTPS the host also owns the fake PKI: it generates a self-signed
//! CA (see [`ca_certificate_pem`], injected into the sandbox as its trust
//! anchor), signs a leaf certificate for every SNI the in-sandbox HTTPS
//! server asks for (`tls-cert`), and terminates the *upstream* TLS
//! connection itself (`tls-connect`) — the sandbox has no real trust
//! anchors, so only the host can verify the real server's certificate.
//!
//! Known information-leak trade-offs (AUDIT.md L12, accepted): the
//! `resolve-dns` command is an allow-list membership oracle (also
//! enumerable via the DNS front-end), and the `connect`/`tls-connect`
//! error strings relay host-side OS/TLS errors, revealing port state on
//! allowed hosts' resolved IPs. Both are inherent to relaying host-side
//! network decisions to an untrusted client that needs the answers.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpStream, UnixStream};

use crate::connlimit::ConnLimit as StreamLimit;
use crate::ipc::netmux::{self, MuxStream};
use crate::proxy::allowlist::{SharedAllow, host_allowed, target_allowed};
use crate::proxy::ipfilter::connect_checked;
use crate::waf::{WafReply, WafReq, WafSpec};

/// The address the in-sandbox servers redirect to (their own listener
/// address, inside the sandbox network namespace).
pub const REDIRECT_ADDR: &str = "127.0.0.2";

/// Serve the host end of the net mux pair: one command per stream.
/// Concurrent streams are capped (see [`crate::connlimit`]): one stream
/// ≙ one old filesystem-socket connection, so the cap and its semantics
/// carry over unchanged. At capacity the open is refused with `ERR`.
///
/// The allow-list snapshot is taken per stream at `OPEN` time (the old
/// accept-time snapshot), so a runtime swap (`crate::cli::control`'s
/// `net-set`) affects new streams only. The old `COMMAND_TIMEOUT`
/// (bounding the sandbox-side client's command line) is gone with the
/// line protocol: the command arrives as the `OPEN` frame's payload, so
/// there is no idle first-read to bound.
pub async fn serve_host(pair: UnixStream, allow: SharedAllow, allow_private: bool) {
    netmux::serve_pair::<WafSpec, _, _>(pair, StreamLimit::new(), move |req, mut stream| {
        let allow = allow.clone();
        async move {
            handle_host_req(
                req,
                &crate::proxy::allowlist::load(&allow),
                allow_private,
                &mut stream,
            )
            .await
        }
    })
    .await;
}

/// One command stream from the sandbox: an `OPEN` frame carrying a
/// [`WafReq`], answered with a typed [`WafReply`] (sent via
/// [`MuxStream::ack`]) or, for pipe kinds, followed by a raw
/// bidirectional data stream. Refusals are *replies* (`denied`/`failed`),
/// not `ERR` frames: the P side maps them to `PermissionDenied` and
/// plain errors exactly as the line protocol's `ERR` lines mapped.
async fn handle_host_req(
    req: WafReq,
    allow: &[String],
    allow_private: bool,
    stream: &mut MuxStream,
) -> io::Result<()> {
    match req {
        WafReq::ResolveDns { name } => {
            if !valid_name(&name) || !host_allowed(&name, allow) {
                eprintln!("ai-bubble waf: DNS lookup of {name} denied");
                crate::audit::record("waf", "resolve-dns", Some(&name), Some("denied"), None).await;
                return stream
                    .ack(&WafReply::Denied {
                        reason: "name not on the allow list".to_string(),
                    })
                    .await;
            }
            crate::audit::record("waf", "resolve-dns", Some(&name), Some("ok"), None).await;
            stream
                .ack(&WafReply::Dns {
                    addr: REDIRECT_ADDR.to_string(),
                })
                .await
        }
        WafReq::Connect { target } => {
            if !valid_target(&target) || !target_allowed(&target, allow) {
                eprintln!("ai-bubble waf: connection to {target} denied");
                crate::audit::record("waf", "connect", Some(&target), Some("denied"), None).await;
                return stream
                    .ack(&WafReply::Denied {
                        reason: "target not on the allow list".to_string(),
                    })
                    .await;
            }
            // Resolve the name here and refuse private/loopback/link-local
            // ranges (SSRF via DNS rebinding, AUDIT.md H3): the dial goes to
            // the validated IP directly.
            let mut tcp = match connect_checked(&target, allow_private).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ai-bubble waf: can't connect to {target}: {e}");
                    crate::audit::record(
                        "waf",
                        "connect",
                        Some(&target),
                        Some("err"),
                        Some(format!("{e}")),
                    )
                    .await;
                    return stream
                        .ack(&WafReply::Failed {
                            reason: format!("can't connect: {e}"),
                        })
                        .await;
                }
            };
            crate::audit::record("waf", "connect", Some(&target), Some("ok"), None).await;
            stream.ack(&WafReply::Open).await?;
            let _ = netmux::copy_bidirectional(stream, &mut tcp).await;
            let _ = stream.close().await;
            Ok(())
        }
        WafReq::TlsCert { name } => {
            // Hand out a leaf certificate for the HTTPS MITM: signed by the
            // waf CA, valid for exactly the SNI the client connected to.
            if !valid_name(&name) || !host_allowed(&name, allow) {
                eprintln!("ai-bubble waf: TLS certificate for {name} denied");
                crate::audit::record("waf", "tls-cert", Some(&name), Some("denied"), None).await;
                return stream
                    .ack(&WafReply::Denied {
                        reason: "name not on the allow list".to_string(),
                    })
                    .await;
            }
            // A certificate is generated once per domain and then cached (see
            // [`CERT_CACHE`]), so the normal flow — a browser hitting the same
            // handful of hosts repeatedly — never touches the keygen throttle.
            // Only *fresh* keygens (new domains, cache misses) are rate-limited:
            // keygen costs real host CPU (a fresh key pair plus a signature),
            // and the rate limit stops the sandbox from burning the
            // supervisor's CPU by requesting certificates for endlessly
            // different names in a loop (AUDIT.md, resource limits on the
            // frontends). Excess requests get a `denied`, which the in-sandbox
            // HTTPS server already handles as a failed MITM.
            let (cert, key) = if let Some(pair) = cached_cert(&name) {
                pair
            } else {
                if !take_keygen_token().await {
                    eprintln!("ai-bubble waf: tls-cert for {name} rate-limited");
                    crate::audit::record(
                        "waf",
                        "tls-cert",
                        Some(&name),
                        Some("rate-limited"),
                        None,
                    )
                    .await;
                    return stream
                        .ack(&WafReply::Denied {
                            reason: "too many certificate requests".to_string(),
                        })
                        .await;
                }
                let pair = match sign_leaf(&name) {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("ai-bubble waf: can't sign a certificate for {name}: {e}");
                        crate::audit::record(
                            "waf",
                            "tls-cert",
                            Some(&name),
                            Some("err"),
                            Some(format!("{e}")),
                        )
                        .await;
                        return stream
                            .ack(&WafReply::Failed {
                                reason: "can't sign certificate".to_string(),
                            })
                            .await;
                    }
                };
                cached_cert_insert(&name, &pair);
                pair
            };
            crate::audit::record("waf", "tls-cert", Some(&name), Some("ok"), None).await;
            // One frame: base64(DER cert) SP base64(DER PKCS#8 key).
            stream
                .ack(&WafReply::Cert {
                    cert: base64::engine::general_purpose::STANDARD.encode(&cert),
                    key: base64::engine::general_purpose::STANDARD.encode(&key),
                })
                .await
        }
        WafReq::TlsConnect { target } => {
            // Like `connect`, but the host also performs the TLS client
            // handshake (with the *real* root certificates), so the sandbox
            // receives a pipe carrying already-decrypted plaintext and the
            // server certificate is verified where the trust anchors live.
            if !valid_target(&target) || !target_allowed(&target, allow) {
                eprintln!("ai-bubble waf: connection to {target} denied");
                crate::audit::record("waf", "tls-connect", Some(&target), Some("denied"), None)
                    .await;
                return stream
                    .ack(&WafReply::Denied {
                        reason: "target not on the allow list".to_string(),
                    })
                    .await;
            }
            let Some((host, _port)) = target.rsplit_once(':') else {
                return Ok(());
            };
            // See `connect` above: resolved-IP filtering pins the dial to a
            // validated address; TLS still verifies the *name*.
            let tcp = match connect_checked(&target, allow_private).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("ai-bubble waf: can't connect to {target}: {e}");
                    crate::audit::record(
                        "waf",
                        "tls-connect",
                        Some(&target),
                        Some("err"),
                        Some(format!("{e}")),
                    )
                    .await;
                    return stream
                        .ack(&WafReply::Failed {
                            reason: format!("can't connect: {e}"),
                        })
                        .await;
                }
            };
            let Ok(name) = ServerName::try_from(host.to_string()) else {
                return stream
                    .ack(&WafReply::Failed {
                        reason: "invalid server name".to_string(),
                    })
                    .await;
            };
            // AUDIT.md L8: bound the upstream handshake, so a black-holed
            // target cannot hold a connector slot for the kernel's full SYN/
            // TLS-retry duration (see `ipfilter::DIAL_TIMEOUT`).
            let mut tls = match tokio::time::timeout(
                crate::proxy::ipfilter::DIAL_TIMEOUT,
                tls_client_stream(name, tcp),
            )
            .await
            {
                Ok(Ok(t)) => t,
                Err(_) => {
                    let e = io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out");
                    eprintln!("ai-bubble waf: TLS handshake with {target} failed: {e}");
                    crate::audit::record(
                        "waf",
                        "tls-connect",
                        Some(&target),
                        Some("err"),
                        Some(format!("{e}")),
                    )
                    .await;
                    return stream
                        .ack(&WafReply::Failed {
                            reason: format!("TLS handshake failed: {e}"),
                        })
                        .await;
                }
                Ok(Err(e)) => {
                    eprintln!("ai-bubble waf: TLS handshake with {target} failed: {e}");
                    crate::audit::record(
                        "waf",
                        "tls-connect",
                        Some(&target),
                        Some("err"),
                        Some(format!("{e}")),
                    )
                    .await;
                    return stream
                        .ack(&WafReply::Failed {
                            reason: format!("TLS handshake failed: {e}"),
                        })
                        .await;
                }
            };
            crate::audit::record("waf", "tls-connect", Some(&target), Some("ok"), None).await;
            stream.ack(&WafReply::Open).await?;
            // Both streams are full duplex; the pipe carries plaintext now.
            let _ = netmux::copy_bidirectional(stream, &mut tls).await;
            let _ = stream.close().await;
            Ok(())
        }
    }
}

/// A token bucket throttling leaf-key generation (`tls-cert`). Each
/// request consumes one token; tokens refill at one per
/// [`KEYGEN_INTERVAL`] up to [`KEYGEN_BURST`], so a burst of
/// [`KEYGEN_BURST`] immediate requests is served and the sustained rate
/// is one keygen every [`KEYGEN_INTERVAL`]. This bounds the host CPU a
/// malicious sandbox can burn with certificate requests (AUDIT.md, resource limits on the frontends):
/// leaf keygen is expensive (fresh key pair + signature per request).
struct KeygenThrottle {
    tokens: u32,
    last: Instant,
}

/// Refill rate: one new keygen token per interval.
const KEYGEN_INTERVAL: Duration = Duration::from_millis(250);
/// Burst allowance: how many keygens may run back-to-back before the
/// throttle kicks in.
const KEYGEN_BURST: u32 = 4;

impl KeygenThrottle {
    fn new() -> Self {
        KeygenThrottle {
            tokens: KEYGEN_BURST,
            last: Instant::now(),
        }
    }

    /// Consume one token, refilling first. `false` when throttled.
    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last);
        if elapsed >= KEYGEN_INTERVAL {
            // Refill every fully elapsed interval, keeping the remainder
            // in `last` so the sustained rate is honored exactly.
            let ticks = (elapsed.as_millis() / KEYGEN_INTERVAL.as_millis()) as u32;
            self.tokens = self.tokens.saturating_add(ticks).min(KEYGEN_BURST);
            self.last += KEYGEN_INTERVAL * ticks;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// The process-wide throttle, shared by all command connections.
static KEYGEN_THROTTLE: OnceLock<tokio::sync::Mutex<KeygenThrottle>> = OnceLock::new();

/// Take one keygen token (see [`KeygenThrottle`]). `false` when the
/// request is throttled and should be answered with an ERR. Only cache
/// misses (`tls-cert` for a name not currently cached) reach this.
async fn take_keygen_token() -> bool {
    let throttle = KEYGEN_THROTTLE.get_or_init(|| tokio::sync::Mutex::new(KeygenThrottle::new()));
    let mut throttle = throttle.lock().await;
    throttle.take()
}

/// How long a cached leaf certificate (and its key) stays valid. Short
/// enough that a domain's identity rotates regularly — the real blast
/// radius is bounded by the per-run CA anyway — but long enough that a
/// browser session's repeated SNI requests never regenerate a key.
const CERT_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
/// Cache size bound: at most this many domains, so the memory held for
/// leaf key material stays bounded even if the sandbox tours the whole
/// allow list. Eviction drops the entry expiring soonest.
const CERT_CACHE_MAX: usize = 256;

/// Per-domain cache of signed leaf certificates. Each `tls-cert` request
/// for an already-cached domain is answered from here without a fresh
/// keygen, so the [`KeygenThrottle`] only throttles genuinely new
/// domains — the "rate limit triggers too often" symptom. The leaf key
/// is reused across handshakes for that one domain instead of being
/// generated per request.
struct CertCache {
    /// name -> (DER cert, DER PKCS#8 key, cache expiry).
    entries: HashMap<String, (Vec<u8>, Vec<u8>, Instant)>,
}

impl CertCache {
    fn get(&self, name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let (cert, key, expiry) = self.entries.get(name)?;
        (Instant::now() < *expiry).then(|| (cert.clone(), key.clone()))
    }

    fn insert(&mut self, name: String, cert: Vec<u8>, key: Vec<u8>) {
        let now = Instant::now();
        self.entries.retain(|_, (_, _, expiry)| *expiry > now);
        if self.entries.len() >= CERT_CACHE_MAX {
            // Evict whichever entry expires soonest (LRU-ish: it was the
            // longest-ago insert that survived every TTL sweep).
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, (_, _, expiry))| *expiry)
                .map(|(name, _)| name.clone());
            if let Some(victim) = victim {
                self.entries.remove(&victim);
            }
        }
        self.entries.insert(name, (cert, key, now + CERT_CACHE_TTL));
    }
}

/// The per-domain certificate cache. An `Option` behind a std (non-async)
/// mutex so [`wipe_after_fork`] can take and drop it synchronously — the
/// cached leaf keys are private key material, and a forked child that
/// never signs must not hold them (same reasoning as [`PKI`]). The lock
/// is held only for map lookups/inserts, never across an `.await`.
static CERT_CACHE: std::sync::Mutex<Option<CertCache>> = std::sync::Mutex::new(None);

/// Cached leaf pair for `name`, if present and unexpired.
fn cached_cert(name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let cache = CERT_CACHE.lock().expect("certificate cache poisoned");
    cache.as_ref()?.get(name)
}

/// Store a freshly signed leaf pair for `name` in the cache.
fn cached_cert_insert(name: &str, (cert, key): &(Vec<u8>, Vec<u8>)) {
    let mut cache = CERT_CACHE.lock().expect("certificate cache poisoned");
    cache
        .get_or_insert_with(|| CertCache {
            entries: HashMap::new(),
        })
        .insert(name.to_string(), cert.clone(), key.clone());
}

/// Sanity-check a DNS name before it reaches the allow-list matcher.
/// Only printable ASCII (`0x21..=0x7e`) is accepted: the name is
/// echoed into audit records and error strings, and a control byte could
/// forge log lines or terminal escape sequences there (AUDIT.md L1/L4 —
/// the old command-line injection concern is gone with the framed
/// protocol, but the log-hygiene reason stands). Whether `name` is a DNS
/// name safe to handle: ASCII only, no control bytes or whitespace, no
/// leading label wildcards (see the tests). Used by both the waf
/// HTTP/CONNECT frontends (against the allow-list) and the DNS server
/// (NET-5: the raw qname is validated *before* it is sent to the host).
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains([' ', '*', '\0'])
        && name.len() <= 253
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        // ASCII-graphic covers the `is_ascii` check the per-label closure
        // used to repeat (AUDIT.md cleanup): no control bytes, no space.
        && name.bytes().all(|b| b.is_ascii_graphic())
}

/// Sanity-check a `host:port` connect target.
fn valid_target(target: &str) -> bool {
    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().is_ok() && !target.contains([' ', '\0'])
}

/// The per-process fake PKI: a self-signed CA whose private key never
/// leaves the host, plus the client configuration used for the upstream
/// `tls-connect` handshakes (real root certificates, loaded once).
struct Pki {
    /// The CA certificate (DER) and its signing key pair.
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    /// The rustls client config verifying real servers (native roots).
    client: Arc<ClientConfig>,
}

/// The PKI is kept in an `Option` behind a mutex so that a forked child
/// that must never sign (P, FS — they only relay or serve the FUSE tree)
/// can *take* and drop it (AUDIT.md, TLS MITM key hygiene): `fork` copies the parent's whole
/// address space, so a plain `OnceLock` would leave the CA private key in
/// every child's memory. `wipe_after_fork` runs immediately after the fork
/// in such children; dropping the key pair releases its key material
/// (ring zeroizes private keys on drop). The original process keeps its
/// own `Arc` clone — it is the only signer.
static PKI: std::sync::Mutex<Option<Arc<Pki>>> = std::sync::Mutex::new(None);

/// The waf fake PKI, generated once per process (lazily, via [`pki`]).
/// The crypto provider must be installed before the sandbox is forked so
/// every child inherits the provider state; forked children that never
/// sign drop the key again via [`wipe_after_fork`].
fn pki() -> Arc<Pki> {
    let mut slot = PKI.lock().expect("PKI poisoned");
    if let Some(pki) = slot.as_ref() {
        return pki.clone();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_key = rcgen::KeyPair::generate()
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't generate the waf CA key: {e}")));
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't set up the waf CA: {e}")));
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "ai-bubble waf sandbox CA (not a real authority)",
    );
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca = rcgen::CertifiedIssuer::self_signed(params, ca_key)
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't create the waf CA: {e}")));

    let mut roots = RootCertStore::empty();
    let result = rustls_native_certs::load_native_certs();
    for cert in result.certs {
        let _ = roots.add(cert);
    }
    if !result.errors.is_empty() {
        crate::sandbox::die(&format!(
            "Can't load the system root certificates: {:?}",
            result.errors
        ));
    }
    let builder =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't set up TLS: {e}")));
    let client = builder.with_root_certificates(roots).with_no_client_auth();
    let pki = Arc::new(Pki {
        ca,
        client: Arc::new(client),
    });
    *slot = Some(pki.clone());
    pki
}

/// Drop the CA private key from this process's memory (AUDIT.md, TLS MITM key hygiene). Must
/// be called by every forked child that never signs anything (the network
/// parent P, the FUSE server FS) directly after the fork: `fork` copied
/// the parent's address space, key material and all. Also drops the
/// cached leaf certificates — their keys are private key material, too.
/// The original process — the only signer — keeps its `Arc` and is
/// unaffected.
pub fn wipe_after_fork() {
    let _ = PKI.lock().expect("PKI poisoned").take();
    let _ = CERT_CACHE
        .lock()
        .expect("certificate cache poisoned")
        .take();
}

/// The CA certificate in PEM form, for injection into the sandbox as its
/// trust anchor (see `main`).
pub fn ca_certificate_pem() -> String {
    pki().ca.pem()
}

/// The CA certificate in DER form (for tests that pin it as the only
/// trust anchor of a rustls client).
#[cfg(test)]
pub fn ca_certificate_der() -> Vec<u8> {
    pki().ca.der().to_vec()
}

/// Sign a leaf certificate for `name` (a SAN, and the SNI the
/// sandbox client used). Returns the DER-encoded certificate and the
/// DER-encoded PKCS#8 key. Only called on cache misses — the result is
/// cached per domain (see [`CERT_CACHE`]), so repeated SNI requests for
/// one domain reuse the key instead of generating a fresh one per
/// request. (Note: the *validity window* is
/// rcgen's default — not deliberately short; per-run CA generation,
/// not leaf expiry, is what limits the blast radius.)
pub fn sign_leaf(name: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let pki = pki();
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("ai-bubble waf interception: {name}"),
    );
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate()
        .map_err(|e| io::Error::other(format!("can't generate a leaf key: {e}")))?;
    let leaf = params
        .signed_by(&key, &pki.ca)
        .map_err(|e| io::Error::other(format!("can't sign the leaf certificate: {e}")))?;
    Ok((leaf.der().to_vec(), key.serialize_der()))
}

/// Perform the TLS client handshake for the upstream connection: the
/// real server certificate is verified here, on the host, where the real
/// root certificates live. On success the returned stream carries
/// decrypted plaintext in both directions.
async fn tls_client_stream(
    name: ServerName<'static>,
    tcp: TcpStream,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = pki().client.clone();
    let connector = tokio_rustls::TlsConnector::from(config);
    connector.connect(name, tcp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::netmux::MuxHandle;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn allow(entries: &[&str]) -> crate::proxy::allowlist::SharedAllow {
        crate::proxy::allowlist::shared(entries.iter().map(|s| s.to_string()).collect())
    }

    #[tokio::test]
    async fn resolve_dns_allowed_and_denied() {
        let (a, b) = netmux::pair().unwrap();
        tokio::spawn(serve_host(
            a,
            allow(&["example.com", "*.github.com:443"]),
            false,
        ));
        let mux = MuxHandle::<WafSpec>::client(b);

        // Allowed: the redirect address comes back as a typed reply.
        let (reply, mut s) = mux
            .open(&WafReq::ResolveDns {
                name: "example.com".to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(reply, WafReply::Dns { ref addr } if addr == REDIRECT_ADDR));
        let _ = s.close().await;

        // Denied: a `denied` reply, which the P side maps to NXDOMAIN.
        let (reply, mut s) = mux
            .open(&WafReq::ResolveDns {
                name: "evil.com".to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(reply, WafReply::Denied { .. }));
        let _ = s.close().await;

        // A port-restricted entry still permits resolving the host.
        let (reply, mut s) = mux
            .open(&WafReq::ResolveDns {
                name: "api.github.com".to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(reply, WafReply::Dns { .. }));
        let _ = s.close().await;
    }

    #[tokio::test]
    async fn connect_denied_and_piped() {
        // Echo server on the "host".
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let (a, b) = netmux::pair().unwrap();
        tokio::spawn(serve_host(
            a,
            allow(&[&format!("127.0.0.1:{}", echo_addr.port())]),
            true,
        ));
        let mux = MuxHandle::<WafSpec>::client(b);

        // Denied target.
        let (reply, mut s) = mux
            .open(&WafReq::Connect {
                target: "evil.example:443".to_string(),
            })
            .await
            .unwrap();
        assert!(matches!(reply, WafReply::Denied { .. }));
        let _ = s.close().await;

        // Allowed target: open, then a raw data stream.
        let (_, mut stream) = mux
            .open(&WafReq::Connect {
                target: format!("127.0.0.1:{}", echo_addr.port()),
            })
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        let _ = stream.close().await;
    }

    /// AUDIT.md H3: an allowed *name* whose DNS resolves into a private or
    /// loopback range must not become an SSRF primitive — the host refuses
    /// to dial blocked ranges unless the operator opted out with
    /// `allow_private`.
    #[tokio::test]
    async fn connect_to_blocked_ranges_is_refused_unless_allow_private() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        for allow_private in [false, true] {
            let (a, b) = netmux::pair().unwrap();
            tokio::spawn(serve_host(
                a,
                allow(&[&format!("127.0.0.1:{}", echo_addr.port())]),
                allow_private,
            ));
            let mux = MuxHandle::<WafSpec>::client(b);
            let (reply, mut s) = mux
                .open(&WafReq::Connect {
                    target: format!("127.0.0.1:{}", echo_addr.port()),
                })
                .await
                .unwrap();
            if allow_private {
                // Opted out: the dial succeeds and the stream is a live
                // raw pipe.
                assert!(
                    matches!(reply, WafReply::Open),
                    "allow_private={allow_private}"
                );
                s.write_all(b"ping").await.unwrap();
                s.flush().await.unwrap();
                let mut echo = [0u8; 4];
                s.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"ping");
            } else {
                // Default: the resolved loopback address is refused —
                // before the TLS/plaintext pipe is ever opened.
                assert!(
                    matches!(&reply, WafReply::Failed { reason } if reason.contains("blocked range")),
                    "allow_private={allow_private}: {reply:?}"
                );
            }
            let _ = s.close().await;
        }
    }

    /// The keygen throttle serves its burst allowance, then refuses,
    /// and refills one token per interval (AUDIT.md, resource limits on the frontends).
    #[test]
    fn keygen_throttle_bounds_burst_and_refills() {
        let mut t = KeygenThrottle::new();
        for _ in 0..KEYGEN_BURST {
            assert!(t.take());
        }
        assert!(!t.take(), "burst exhausted but a token was still granted");
        // After one interval a fresh token appears (and only one).
        std::thread::sleep(KEYGEN_INTERVAL + Duration::from_millis(30));
        assert!(t.take());
        assert!(!t.take());
    }

    /// The per-domain certificate cache serves a repeat request without
    /// a fresh keygen (same DER pair both times), inserts only on
    /// misses, and evicts the soonest-expiring entry at capacity.
    #[test]
    fn cert_cache_serves_repeat_requests() {
        // Clean slate for this test's entries.
        let _ = CERT_CACHE.lock().unwrap().take();

        let first = sign_leaf("cached.example.com").unwrap();
        cached_cert_insert("cached.example.com", &first);
        // A cache hit returns the identical pair — no second keygen.
        assert_eq!(cached_cert("cached.example.com").as_ref(), Some(&first));

        // A different name is a miss even though another name is cached.
        assert_eq!(cached_cert("other.example.com"), None);

        // Expiry: entries past their TTL are not served.
        let past = CERT_CACHE_TTL + Duration::from_secs(1);
        {
            let mut cache = CERT_CACHE.lock().unwrap();
            let cache = cache.get_or_insert_with(|| CertCache {
                entries: HashMap::new(),
            });
            let (_, _, expiry) = cache.entries.get_mut("cached.example.com").unwrap();
            *expiry -= past;
        }
        assert_eq!(cached_cert("cached.example.com"), None);

        // Size bound: filling the cache evicts the soonest-expiring entry.
        let _ = CERT_CACHE.lock().unwrap().take();
        let dummy = first.clone();
        for i in 0..CERT_CACHE_MAX + 1 {
            cached_cert_insert(
                &format!("fill-{i}.example.com"),
                &(dummy.0.clone(), dummy.1.clone()),
            );
        }
        let cache = CERT_CACHE.lock().unwrap();
        let cache = cache.as_ref().unwrap();
        assert_eq!(cache.entries.len(), CERT_CACHE_MAX);
        assert!(!cache.entries.contains_key("fill-0.example.com"));
        assert!(
            cache
                .entries
                .contains_key(&format!("fill-{CERT_CACHE_MAX}.example.com"))
        );
    }

    #[test]
    fn name_and_target_checks() {
        assert!(valid_name("example.com"));
        assert!(valid_name("a.b.example.com"));
        assert!(!valid_name(""));
        assert!(!valid_name("evil .com"));
        assert!(!valid_name("*.example.com"));
        assert!(!valid_name("exa\0mple.com"));
        // AUDIT.md L4/L1: control characters (and other non-printables)
        // must be refused — the name is echoed into audit records and
        // error strings, where it could forge log lines.
        assert!(!valid_name("exa\nmple.com"));
        assert!(!valid_name("exa\rmple.com"));
        assert!(!valid_name("exa\u{1}mple.com"));
        assert!(!valid_name("exa\u{7f}mple.com"));
        assert!(valid_target("example.com:443"));
        assert!(valid_target("127.0.0.1:8080"));
        assert!(!valid_target("example.com"));
        assert!(!valid_target(":443"));
        assert!(!valid_target("example.com:notaport"));
        assert!(!valid_target("evil .com:443"));
    }
}

/// The CA private key is dropped in forked children that never sign
/// (AUDIT.md, TLS MITM key hygiene): after `wipe_after_fork`, the PKI slot must be empty —
/// the forked child no longer holds key material — and the *parent's* PKI
/// must be unaffected. Runs in a forked child so the wipe cannot race the
/// other tests' use of the process-global PKI.
#[test]
fn wipe_after_fork_drops_the_private_key_in_the_child() {
    // Ensure the parent has a PKI before forking.
    let _ = ca_certificate_pem();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        wipe_after_fork();
        let dropped = PKI.lock().unwrap().is_none();
        unsafe { libc::_exit(if dropped { 0 } else { 1 }) };
    }
    let mut status: libc::c_int = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the child must drop the PKI (status {status:#x})"
    );
    // The parent keeps its own copy: signing still works.
    assert!(sign_leaf("wipe-test.example.com").is_ok());
}
