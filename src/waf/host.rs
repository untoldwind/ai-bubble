//! The host side of the waf command protocol.
//!
//! This code runs in the original ai-bubble process, i.e. in the host
//! network namespace. It listens on a Unix-domain socket mounted into
//! the sandbox and executes the simple command protocol of
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

use std::io;
use std::sync::{Arc, OnceLock};

use base64::Engine as _;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use crate::proxy::allowlist::{host_allowed, target_allowed};

/// The address the in-sandbox servers redirect to (their own listener
/// address, inside the sandbox network namespace).
pub const REDIRECT_ADDR: &str = "127.0.0.2";

/// Accept loop on the host side: one command per connection.
pub async fn serve_host(listener: UnixListener, allow: Vec<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let allow = allow.clone();
                tokio::spawn(async move {
                    handle_host_conn(stream, &allow).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One command connection from the sandbox: a single line, answered with
/// a single reply line (`OK ...` / `ERR <reason>`). A `connect` command
/// turns the connection into a raw bidirectional pipe after `OK`.
async fn handle_host_conn(mut stream: UnixStream, allow: &[String]) {
    let Some(cmd) = read_line(&mut stream).await else {
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
        let mut tcp = match TcpStream::connect(target).await {
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
        if stream.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
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
        let tcp = match TcpStream::connect(target).await {
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
    ca: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    /// The rustls client config verifying real servers (native roots).
    client: Arc<ClientConfig>,
}

static PKI: OnceLock<Pki> = OnceLock::new();

/// The waf fake PKI, generated once per process. Must run before the
/// sandbox is forked so every child inherits the installed crypto
/// provider state.
fn pki() -> &'static Pki {
    PKI.get_or_init(|| {
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
        let ca = params
            .self_signed(&ca_key)
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
        Pki {
            ca,
            ca_key,
            client: Arc::new(client),
        }
    })
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

/// Sign a short-lived leaf certificate for `name` (a SAN, and the SNI the
/// sandbox client used). Returns the DER-encoded certificate and the
/// DER-encoded PKCS#8 key. The key exists only for this handshake —
/// freshly generated per request.
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
        .signed_by(&key, &pki.ca, &pki.ca_key)
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
