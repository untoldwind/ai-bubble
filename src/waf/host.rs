//! The host side of the waf command protocol.
//!
//! This code runs in the original ai-bubble process, i.e. in the host
//! network namespace. It listens on a Unix-domain socket that is *not*
//! mounted into the sandbox (the command cannot reach it directly; see
//! `netns.rs` — a `/net` mount was never implemented) and executes the
//! simple command protocol of
//! [`super`](crate::waf): `resolve-dns <name>`, `connect <host>:<port>`,
//! `tls-cert <name>` and `tls-connect <host>:<port>`. Every request is
//! checked against the allow-list here — the single enforcement point of
//! this mode.
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

use std::io;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use crate::connlimit::ConnLimit;
use crate::proxy::allowlist::{host_allowed, target_allowed};
use crate::proxy::ipfilter::connect_checked;

/// The address the in-sandbox servers redirect to (their own listener
/// address, inside the sandbox network namespace).
pub const REDIRECT_ADDR: &str = "127.0.0.2";

/// How long a sandbox-side client may take to send its one command line.
/// A command that opens command connections but never sends must not
/// hold a task (and a supervisor file descriptor) forever — part of
/// AUDIT.md M10. The timeout guards only the command line; a piped
/// connection after a successful `connect`/`tls-connect` is never
/// timed out.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept loop on the host side: one command per connection.
/// Concurrent connections are capped (see [`crate::connlimit`]): each
/// accepted connection holds a file descriptor of the supervisor, so an
/// unbounded number of idle connections would exhaust them. At capacity
/// the new connection is dropped immediately.
pub async fn serve_host(listener: UnixListener, allow: Vec<String>, allow_private: bool) {
    let limit = ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Some(guard) = limit.try_acquire() else {
                    continue; // at capacity: drop the connection
                };
                let allow = allow.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    handle_host_conn(stream, &allow, allow_private).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One command connection from the sandbox: a single line, answered with
/// a single reply line (`OK ...` / `ERR <reason>`). A `connect` command
/// turns the connection into a raw bidirectional pipe after `OK`.
async fn handle_host_conn(mut stream: UnixStream, allow: &[String], allow_private: bool) {
    // The command line must arrive within COMMAND_TIMEOUT (see the
    // constant's doc); a timed-out read is handled like a closed one.
    let cmd = match tokio::time::timeout(COMMAND_TIMEOUT, read_line(&mut stream)).await {
        Ok(cmd) => cmd,
        Err(_) => return,
    };
    let Some(cmd) = cmd else {
        return;
    };
    let cmd = cmd.trim();
    if let Some(name) = cmd.strip_prefix("resolve-dns ") {
        if !valid_name(name) || !host_allowed(name, allow) {
            eprintln!("ai-bubble waf: DNS lookup of {name} denied");
            crate::audit::record("waf", "resolve-dns", Some(name), Some("denied"), None).await;
            let _ = stream.write_all(b"ERR name not on the allow list\n").await;
            return;
        }
        crate::audit::record("waf", "resolve-dns", Some(name), Some("ok"), None).await;
        let _ = stream
            .write_all(format!("OK {REDIRECT_ADDR}\n").as_bytes())
            .await;
    } else if let Some(target) = cmd.strip_prefix("connect ") {
        if !valid_target(target) || !target_allowed(target, allow) {
            eprintln!("ai-bubble waf: connection to {target} denied");
            crate::audit::record("waf", "connect", Some(target), Some("denied"), None).await;
            let _ = stream
                .write_all(b"ERR target not on the allow list\n")
                .await;
            return;
        }
        // Resolve the name here and refuse private/loopback/link-local
        // ranges (SSRF via DNS rebinding, AUDIT.md H3): the dial goes to
        // the validated IP directly.
        let mut tcp = match connect_checked(target, allow_private).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ai-bubble waf: can't connect to {target}: {e}");
                crate::audit::record(
                    "waf",
                    "connect",
                    Some(target),
                    Some("err"),
                    Some(format!("{e}")),
                )
                .await;
                let _ = stream
                    .write_all(format!("ERR can't connect: {e}\n").as_bytes())
                    .await;
                return;
            }
        };
        crate::audit::record("waf", "connect", Some(target), Some("ok"), None).await;
        if stream.write_all(b"OK\n").await.is_err() {
            return;
        }
        let _ = copy_bidirectional(&mut stream, &mut tcp).await;
    } else if let Some(name) = cmd.strip_prefix("tls-cert ") {
        // Hand out a leaf certificate for the HTTPS MITM: signed by the
        // waf CA, valid for exactly the SNI the client connected to.
        if !valid_name(name) || !host_allowed(name, allow) {
            eprintln!("ai-bubble waf: TLS certificate for {name} denied");
            crate::audit::record("waf", "tls-cert", Some(name), Some("denied"), None).await;
            let _ = stream.write_all(b"ERR name not on the allow list\n").await;
            return;
        }
        // Keygen costs real host CPU (a fresh RSA-grade key pair plus a
        // signature per request). Rate-limit it so the sandbox cannot
        // burn the supervisor's CPU by requesting certificates in a
        // loop (AUDIT.md M10); excess requests get an ERR, which the
        // in-sandbox HTTPS server already handles as a failed MITM.
        if !take_keygen_token().await {
            eprintln!("ai-bubble waf: tls-cert for {name} rate-limited");
            crate::audit::record("waf", "tls-cert", Some(name), Some("rate-limited"), None).await;
            let _ = stream.write_all(b"ERR too many certificate requests\n").await;
            return;
        }
        let (cert, key) = match sign_leaf(name) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("ai-bubble waf: can't sign a certificate for {name}: {e}");
                crate::audit::record(
                    "waf",
                    "tls-cert",
                    Some(name),
                    Some("err"),
                    Some(format!("{e}")),
                )
                .await;
                let _ = stream.write_all(b"ERR can't sign certificate\n").await;
                return;
            }
        };
        crate::audit::record("waf", "tls-cert", Some(name), Some("ok"), None).await;
        // One line: base64(DER cert) SP base64(DER PKCS#8 key).
        let reply = format!(
            "OK {} {}\n",
            base64::engine::general_purpose::STANDARD.encode(&cert),
            base64::engine::general_purpose::STANDARD.encode(&key)
        );
        let _ = stream.write_all(reply.as_bytes()).await;
    } else if let Some(target) = cmd.strip_prefix("tls-connect ") {
        // Like `connect`, but the host also performs the TLS client
        // handshake (with the *real* root certificates), so the sandbox
        // receives a pipe carrying already-decrypted plaintext and the
        // server certificate is verified where the trust anchors live.
        if !valid_target(target) || !target_allowed(target, allow) {
            eprintln!("ai-bubble waf: connection to {target} denied");
            crate::audit::record("waf", "tls-connect", Some(target), Some("denied"), None).await;
            let _ = stream
                .write_all(b"ERR target not on the allow list\n")
                .await;
            return;
        }
        let Some((host, _port)) = target.rsplit_once(':') else {
            return;
        };
        // See `connect` above: resolved-IP filtering pins the dial to a
        // validated address; TLS still verifies the *name*.
        let tcp = match connect_checked(target, allow_private).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ai-bubble waf: can't connect to {target}: {e}");
                crate::audit::record(
                    "waf",
                    "tls-connect",
                    Some(target),
                    Some("err"),
                    Some(format!("{e}")),
                )
                .await;
                let _ = stream
                    .write_all(format!("ERR can't connect: {e}\n").as_bytes())
                    .await;
                return;
            }
        };
        let Ok(name) = ServerName::try_from(host.to_string()) else {
            let _ = stream.write_all(b"ERR invalid server name\n").await;
            return;
        };
        let mut tls = match tls_client_stream(name, tcp).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("ai-bubble waf: TLS handshake with {target} failed: {e}");
                crate::audit::record(
                    "waf",
                    "tls-connect",
                    Some(target),
                    Some("err"),
                    Some(format!("{e}")),
                )
                .await;
                let _ = stream
                    .write_all(format!("ERR TLS handshake failed: {e}\n").as_bytes())
                    .await;
                return;
            }
        };
        crate::audit::record("waf", "tls-connect", Some(target), Some("ok"), None).await;
        if stream.write_all(b"OK\n").await.is_err() {
            return;
        }
        // Both streams are full duplex; the pipe carries plaintext now.
        let _ = copy_bidirectional(&mut stream, &mut tls).await;
    } else {
        let _ = stream.write_all(b"ERR unknown command\n").await;
    }
}

/// Read one line (the command) from the connection.
async fn read_line(stream: &mut UnixStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > 512 {
                    return None;
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    let s = String::from_utf8(buf).ok()?;
    let t = s.trim().to_string();
    if t.is_empty() || t.contains('\0') {
        return None;
    }
    Some(t)
}

/// A token bucket throttling leaf-key generation (`tls-cert`). Each
/// request consumes one token; tokens refill at one per
/// [`KEYGEN_INTERVAL`] up to [`KEYGEN_BURST`], so a burst of
/// [`KEYGEN_BURST`] immediate requests is served and the sustained rate
/// is one keygen every [`KEYGEN_INTERVAL`]. This bounds the host CPU a
/// malicious sandbox can burn with certificate requests (AUDIT.md M10):
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
/// request is throttled and should be answered with an ERR.
async fn take_keygen_token() -> bool {
    let throttle = KEYGEN_THROTTLE.get_or_init(|| tokio::sync::Mutex::new(KeygenThrottle::new()));
    let mut throttle = throttle.lock().await;
    throttle.take()
}

/// Sanity-check a DNS name before it reaches the allow-list matcher.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains([' ', '*', '\0'])
        && name.len() <= 253
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63 && name.is_ascii())
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
/// can *take* and drop it (AUDIT.md L8): `fork` copies the parent's whole
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
    let ca_key = rcgen::KeyPair::generate().unwrap_or_else(|e| {
        crate::sandbox::die(&format!("Can't generate the waf CA key: {e}"))
    });
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

/// Drop the CA private key from this process's memory (AUDIT.md L8). Must
/// be called by every forked child that never signs anything (the network
/// parent P, the FUSE server FS) directly after the fork: `fork` copied
/// the parent's address space, key material and all. The original process
/// — the only signer — keeps its `Arc` and is unaffected.
pub fn wipe_after_fork() {
    let _ = PKI.lock().expect("PKI poisoned").take();
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
/// DER-encoded PKCS#8 key. The key exists only for this handshake —
/// freshly generated per request. (Note: the *validity window* is
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn allow(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn resolve_dns_allowed_and_denied() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-waf-dns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(serve_host(
            listener,
            allow(&["example.com", "*.github.com:443"]),
            false,
        ));

        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"resolve-dns example.com\n").await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply.trim(), "OK 127.0.0.2");

        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"resolve-dns evil.com\n").await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("ERR"));

        // A port-restricted entry still permits resolving the host.
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"resolve-dns api.github.com\n").await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply.trim(), "OK 127.0.0.2");

        let _ = std::fs::remove_dir_all(&dir);
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

        let dir = std::env::temp_dir().join(format!("ai-bubble-waf-conn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(serve_host(
            listener,
            allow(&[&format!("127.0.0.1:{}", echo_addr.port())]),
            true,
        ));

        // Denied target.
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"connect evil.example:443\n").await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("ERR"));

        // Allowed target: OK, then a raw pipe.
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(format!("connect 127.0.0.1:{}\n", echo_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut buf = [0u8; 3];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..3], b"OK\n");
        c.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        // Unknown commands get an ERR, too.
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"make http-request example.com /\n")
            .await
            .unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("ERR"));

        let _ = std::fs::remove_dir_all(&dir);
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
            let dir = std::env::temp_dir().join(format!(
                "ai-bubble-waf-ssrf-{}-{allow_private}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let sock = dir.join("sock");
            let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            let _ = std_listener.set_nonblocking(true);
            let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
            tokio::spawn(serve_host(
                listener,
                allow(&[&format!("127.0.0.1:{}", echo_addr.port())]),
                allow_private,
            ));

            let mut c = UnixStream::connect(&sock).await.unwrap();
            c.write_all(format!("connect 127.0.0.1:{}\n", echo_addr.port()).as_bytes())
                .await
                .unwrap();
            let mut reply = String::new();
            if allow_private {
                // The connection stays open as a raw pipe, so the reply
                // must be read by length, not to EOF.
                let mut ok = [0u8; 3];
                c.read_exact(&mut ok).await.unwrap();
                reply = String::from_utf8_lossy(&ok).into_owned();
            } else {
                c.read_to_string(&mut reply).await.unwrap();
            }
            if allow_private {
                // Opted out: the dial succeeds and the pipe is live. The
                // connection stays open as a raw pipe, so the reply must
                // be read by length, not to EOF.
                assert_eq!(reply, "OK\n", "allow_private={allow_private}");
            } else {
                // Default: the resolved loopback address is refused —
                // before the TLS/plaintext pipe is ever opened.
                assert!(
                    reply.starts_with("ERR can't connect"),
                    "allow_private={allow_private}: {reply:?}"
                );
                assert!(reply.contains("blocked range"));
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The keygen throttle serves its burst allowance, then refuses,
    /// and refills one token per interval (AUDIT.md M10).
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

    #[test]
    fn name_and_target_checks() {
        assert!(valid_name("example.com"));
        assert!(valid_name("a.b.example.com"));
        assert!(!valid_name(""));
        assert!(!valid_name("evil .com"));
        assert!(!valid_name("*.example.com"));
        assert!(!valid_name("exa\0mple.com"));
        assert!(valid_target("example.com:443"));
        assert!(valid_target("127.0.0.1:8080"));
        assert!(!valid_target("example.com"));
        assert!(!valid_target(":443"));
        assert!(!valid_target("example.com:notaport"));
        assert!(!valid_target("evil .com:443"));
    }
}

/// The CA private key is dropped in forked children that never sign
/// (AUDIT.md L8): after `wipe_after_fork`, the PKI slot must be empty —
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
