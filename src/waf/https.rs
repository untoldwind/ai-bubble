//! The in-sandbox HTTPS MITM server (127.0.0.2:443).
//!
//! Runs inside the sandbox network namespace (process P of the waf mode).
//! Because every allow-listed name resolves to `127.0.0.2` (see
//! [`super::dns`]), a client's TLS connection lands here — with the
//! ClientHello still carrying the server name it really wanted (SNI).
//! This server terminates the TLS handshake itself: it asks the host for
//! a leaf certificate for the SNI (the `tls-cert` command, signed by the
//! waf CA that was injected into the sandbox as the clients' trust
//! anchor), serves it via rustls/ring, and — this is the important part
//! (AUDIT.md finding M2) — does **not** pipe the decrypted plaintext
//! verbatim to the upstream. A raw pipe would leave HTTP-level domain
//! fronting open: a client could open the TLS connection with an
//! allow-listed SNI but send `Host: evil.com` inside, and shared
//! infrastructure would route the request there. Instead the decrypted
//! stream is parsed by hyper, every request's `Host` header is checked
//! against the SNI (mismatches get a 400 and are never forwarded), and
//! the request is replayed with the dialed authority (`SNI:443`) as the
//! `Host` header through the host side's `tls-connect` command — which
//! performs the *real* TLS handshake with the genuine endpoint, with
//! proper certificate verification on the host (the sandbox has no real
//! trust anchors, so it cannot do that itself). The decrypted plaintext
//! flows through the sandbox, which is exactly the visibility the waf
//! mode wants.

use std::io;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue};
use hyper::http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

use super::{WafSpec, tls_cert, tls_connect_target};
use crate::connlimit::ConnLimit;
use crate::ipc::netmux::MuxHandle;

/// The response body type: the upstream's streamed body, or an empty
/// one for the proxy's own error responses.
type BodyT = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// How long a client may take to deliver a complete TLS ClientHello (and
/// then finish the TLS handshake). A client that opens a connection but
/// never sends — or trickles hello bytes — must not hold a task forever
/// (the slowloris half of the resource-DoS concern (AUDIT.md, resource limits on the frontends)). The timeout guards only these
/// initial reads; the tunneled traffic afterwards is never timed out.
const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept loop on `127.0.0.2:443`. Concurrent connections are capped
/// (see [`crate::connlimit`]); at capacity the newly accepted connection
/// is dropped immediately instead of spawning a task for it.
pub async fn serve_https(listener: TcpListener, mux: MuxHandle<WafSpec>) {
    let limit = ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let Some(guard) = limit.try_acquire() else {
                    continue; // at capacity: drop the connection
                };
                let mux = mux.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    handle_tls(tcp, mux).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One connection: let rustls parse the ClientHello (via
/// [`LazyConfigAcceptor`], which buffers and replays the hello bytes
/// itself), extract the SNI, obtain a forged certificate for it from the
/// host, terminate TLS and tunnel the plaintext to the real endpoint
/// through the host's `tls-connect`. Anything that is not a ClientHello
/// with a SNI (or whose SNI is denied) is dropped.
async fn handle_tls(tcp: TcpStream, mux: MuxHandle<WafSpec>) {
    // Slowloris guard (AUDIT.md, resource limits on the frontends): the ClientHello — and the rest of
    // the TLS handshake, which the client could equally stall — must
    // complete within HELLO_TIMEOUT. On timeout the connection is simply
    // dropped. `LazyConfigAcceptor` resolves once a complete ClientHello
    // has arrived; the second timeout below bounds the rest of the
    // handshake.
    let start = match tokio::time::timeout(
        HELLO_TIMEOUT,
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp),
    )
    .await
    {
        Ok(Ok(start)) => start,
        Ok(Err(_)) => return, // not a usable TLS hello: just close
        Err(_) => return,     // timeout: drop the connection
    };
    let hello = start.client_hello();
    let sni = hello.server_name().and_then(printable_sni);
    let Some(sni) = sni else {
        // Either no SNI (we cannot know the target, so nothing to
        // forward) or one that fails the printable-ASCII check (AUDIT.md
        // L4: control bytes must not reach the host side).
        return;
    };
    let (cert, key) = match tls_cert(&mux, &sni).await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("ai-bubble waf: HTTPS MITM of {sni} failed: {e}");
            return;
        }
    };
    let config = match server_config(&cert, &key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ai-bubble waf: can't set up TLS for {sni}: {e}");
            return;
        }
    };
    // The client's side of the handshake is time-boxed too (see the
    // HELLO_TIMEOUT doc).
    let mut tls = match tokio::time::timeout(HELLO_TIMEOUT, start.into_stream(Arc::new(config)))
        .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            eprintln!("ai-bubble waf: TLS handshake with client for {sni} failed: {e}");
            return;
        }
        Err(_) => return, // handshake timed out: drop the connection
    };
    // AUDIT.md finding M2: the decrypted plaintext used to be piped
    // verbatim to the upstream (a raw `copy_bidirectional`), which left
    // HTTP-level domain fronting open: a client could open the TLS
    // connection with an allow-listed SNI but send `Host: evil.com`
    // inside, and shared infrastructure would route the request there —
    // exactly the class waf mode exists to close. The decrypted stream
    // is therefore parsed by hyper and every request is re-authorized
    // against the SNI before it is forwarded (see [`handle_request`]).
    let sni_service = sni.clone();
    let svc = service_fn(move |req| {
        let mux = mux.clone();
        let sni = sni_service.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_request(&mux, &sni, req).await) }
    });
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(&mut tls), svc)
        .await;
}

/// One decrypted HTTP request: enforce `Host == SNI`, rewrite the
/// request to origin-form against the dialed authority, and forward it
/// to the real endpoint through the host's `tls-connect`.
async fn handle_request(
    mux: &MuxHandle<WafSpec>,
    sni: &str,
    req: Request<Incoming>,
) -> Response<BodyT> {
    // HTTP-level fronting check (AUDIT.md M2): the `Host` header of the
    // decrypted request must name the same host the TLS ClientHello's
    // SNI did (and that the allow-list admitted). Anything else is a
    // fronting attempt — refused with a 400 instead of being forwarded.
    if !host_header_matches(req.headers(), sni) {
        return empty_response(StatusCode::BAD_REQUEST);
    }

    // The upstream request keeps its origin-form target (the part after
    // the authority); hyper serializes origin-form request lines and
    // needs the dialed authority as the `Host` header. `insert` (not
    // `or_insert`): the header was just verified to be the SNI, but the
    // forwarded request must carry exactly the authority that was
    // dialed, with no attacker-controlled residue.
    let (mut parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .to_string();
    let Ok(uri) = Uri::builder().path_and_query(path).build() else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    parts.uri = uri;
    let Ok(host) = HeaderValue::from_str(sni) else {
        return empty_response(StatusCode::BAD_REQUEST);
    };
    parts.headers.insert(hyper::header::HOST, host);

    let upstream = match tls_connect_target(mux, &format!("{sni}:443")).await {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("ai-bubble waf: HTTPS forward to {sni} failed: {e}");
            return empty_response(StatusCode::BAD_GATEWAY);
        }
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTPS connection to {sni} failed: {e}");
                return empty_response(StatusCode::BAD_GATEWAY);
            }
        };
    tokio::spawn(conn);
    let response = match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("ai-bubble waf: HTTPS request to {sni} failed: {e}");
            return empty_response(StatusCode::BAD_GATEWAY);
        }
    };

    // One request per upstream connection: tell the client not to reuse
    // this one for more than the hyper server connection manages.
    let (mut parts, body) = response.into_parts();
    parts
        .headers
        .insert(CONNECTION, HeaderValue::from_static("close"));
    Response::from_parts(parts, body.boxed())
}

/// Whether the request's `Host` header names the allow-listed SNI: the
/// parsed authority's host part must equal the SNI (case-insensitive);
/// the port (if any) is irrelevant — routing is by name, and the
/// upstream is dialed at `SNI:443` regardless (AUDIT.md finding M2).
fn host_header_matches(headers: &hyper::HeaderMap, sni: &str) -> bool {
    headers
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.parse::<Authority>().ok())
        .is_some_and(|a| a.host().eq_ignore_ascii_case(sni))
}

/// An empty response with the given status, closing the connection after
/// it (a refused request never deserves keep-alive).
fn empty_response(status: StatusCode) -> Response<BodyT> {
    Response::builder()
        .status(status)
        .header(CONNECTION, HeaderValue::from_static("close"))
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response")
}

/// A rustls server configuration serving exactly one certificate: the
/// forged leaf (DER cert + DER PKCS#8 key) obtained from the host.
fn server_config(cert: &[u8], key: &[u8]) -> io::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("can't set up TLS versions: {e}")))?;
    builder
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|e| io::Error::other(format!("bad leaf certificate from the host: {e}")))
}

/// Validate and normalize a SNI that rustls has already parsed out of a
/// ClientHello: only printable ASCII, no backslash (AUDIT.md L4) —
/// control bytes here would be re-emitted verbatim into audit records
/// and error strings on the host (`tls-cert`); refusing them keeps those
/// escape-proof. Returned lowercased, as the rest of the waf compares
/// names case-insensitively.
fn printable_sni(sni: &str) -> Option<String> {
    if !sni.is_empty() && sni.bytes().all(|b| b.is_ascii_graphic()) && !sni.contains('\\') {
        Some(sni.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::{WafReply, WafReq, host};
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// The SNI validation behind AUDIT.md L4: the SNI must consist of
    /// printable ASCII only — control bytes would be re-emitted verbatim
    /// into the host's audit records and error strings.
    #[test]
    fn sni_must_be_printable() {
        assert_eq!(
            printable_sni("Example.COM").as_deref(),
            Some("example.com")
        );
        for evil in [
            "evil\nexample.com",
            "evil\r.com",
            "e\x01vil.com",
            "evil\x7f.com",
            "evil\\example.com",
            "",
        ] {
            assert_eq!(
                printable_sni(evil),
                None,
                "SNI {evil:?} must be refused"
            );
        }
    }

    /// A stand-in for the host command server: `tls-cert` requests are
    /// answered with really signed leaves, `tls-connect` streams (as if a
    /// TLS handshake had succeeded) pipe to a plain TCP echo server.
    async fn fake_host(pair: tokio::net::UnixStream, echo_port: u16) {
        use crate::ipc::netmux::{copy_bidirectional, serve_pair};
        serve_pair::<WafSpec, _, _>(
            pair,
            crate::ipc::netmux::StreamLimit::new(),
            move |req, mut stream| async move {
                match req {
                    WafReq::TlsCert { name } => {
                        if name == "evil.example" {
                            return stream
                                .ack(&WafReply::Denied {
                                    reason: "denied".to_string(),
                                })
                                .await;
                        }
                        match host::sign_leaf(&name) {
                            Ok((cert, key)) => {
                                let enc =
                                    |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
                                stream
                                    .ack(&WafReply::Cert {
                                        cert: enc(&cert),
                                        key: enc(&key),
                                    })
                                    .await
                            }
                            Err(e) => {
                                stream
                                    .ack(&WafReply::Failed {
                                        reason: e.to_string(),
                                    })
                                    .await
                            }
                        }
                    }
                    WafReq::TlsConnect { target } => {
                        if target == "evil.example:443" {
                            return stream
                                .ack(&WafReply::Denied {
                                    reason: "denied".to_string(),
                                })
                                .await;
                        }
                        let Ok(mut tcp) = TcpStream::connect(("127.0.0.1", echo_port)).await else {
                            return stream
                                .ack(&WafReply::Failed {
                                    reason: "no target".to_string(),
                                })
                                .await;
                        };
                        stream.ack(&WafReply::Open).await?;
                        let _ = copy_bidirectional(&mut stream, &mut tcp).await;
                        let _ = stream.close().await;
                        Ok(())
                    }
                    _ => {
                        stream
                            .ack(&WafReply::Failed {
                                reason: "unknown".to_string(),
                            })
                            .await
                    }
                }
            },
        )
        .await;
    }

    /// Full MITM pipeline: a rustls client trusting only the waf CA ->
    /// the HTTPS server (SNI extraction, forged certificate, TLS
    /// termination) -> the command socket (tls-cert + tls-connect) -> a
    /// plain TCP echo server; the decrypted plaintext must reach it and
    /// its reply must come back through the TLS session.
    #[tokio::test]
    async fn end_to_end_mitm() {
        use crate::waf::host;

        // The echo answers decrypted HTTP requests whose head it echoes
        // back inside the body — so the test can assert exactly what the
        // upstream received (rewritten request line and Host header).
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 512];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let _ = s
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{head}",
                                head.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });

        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(fake_host(a, echo_addr.port()));
        let mux = crate::ipc::netmux::MuxHandle::<WafSpec>::client(b);

        let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls.local_addr().unwrap();
        tokio::spawn(serve_https(tls, mux));

        // A rustls client that trusts only the waf CA — exactly what the
        // injected /etc/ssl/certs/ca-certificates.crt amounts to.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(host::ca_certificate_der()))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let name: rustls::pki_types::ServerName<'static> = "example.com".try_into().unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        // A genuine request: the Host header matches the SNI, so the
        // request is forwarded — origin-form request line, dialed
        // authority as Host (AUDIT.md M2).
        tls.write_all(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        let mut chunk = [0u8; 1024];
        while !reply.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before a response arrived");
            reply.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&reply).to_string();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "reply: {text:?}");
        let body = text.split("\r\n\r\n").nth(1).expect("body after the head");
        assert!(
            body.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "replayed head: {body:?}"
        );
        assert!(
            body.contains("host: example.com") || body.contains("Host: example.com"),
            "replayed Host must be the dialed authority: {body:?}"
        );

        // HTTP-level domain fronting (AUDIT.md M2): SNI `example.com` in
        // the TLS handshake but `Host: evil.example` inside the request
        // must be refused with a 400 — and never reach the upstream.
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let name: rustls::pki_types::ServerName<'static> = "example.com".try_into().unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n")
            .await
            .unwrap();
        let mut reply = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tls.read_to_end(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        let text = String::from_utf8_lossy(&reply).to_string();
        assert!(
            text.starts_with("HTTP/1.1 400"),
            "fronting attempt must be refused: {text:?}"
        );

        // A denied SNI gets nothing (connection closed during the
        // handshake).
        let tcp = TcpStream::connect(tls_addr).await.unwrap();
        let name: rustls::pki_types::ServerName<'static> = "evil.example".try_into().unwrap();
        assert!(connector.connect(name, tcp).await.is_err());
    }

    /// The `Host` header check behind the M2 fix: the parsed authority's
    /// host part must equal the SNI (case-insensitive, port ignored) —
    /// and it must not fall for prefix/suffix look-alikes.
    #[test]
    fn host_header_must_match_the_sni() {
        use hyper::header::HeaderValue;
        let ok = |h: &str| {
            host_header_matches(
                &{
                    let mut m = hyper::HeaderMap::new();
                    m.insert(hyper::header::HOST, HeaderValue::from_str(h).unwrap());
                    m
                },
                "example.com",
            )
        };
        // Matching forms.
        assert!(ok("example.com"));
        assert!(ok("example.com:443"));
        assert!(ok("EXAMPLE.com"));
        assert!(ok("Example.Com:443"));
        // Fronting attempts.
        assert!(!ok("evil.com"));
        assert!(!ok("evilexample.com"));
        assert!(!ok("example.com.evil.com"));
        assert!(!ok("sub.example.com"));
        // Missing or malformed Host.
        assert!(!host_header_matches(
            &hyper::HeaderMap::new(),
            "example.com"
        ));
    }

    /// The forged leaf for a host verifies under the waf CA.
    #[tokio::test]
    async fn leaf_matches_ca() {
        use crate::waf::host;

        let (cert, key) = host::sign_leaf("example.com").unwrap();
        let config = server_config(&cert, &key).unwrap();
        // Sanity: the config accepted the key/cert pair.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(host::ca_certificate_der()))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Serve and verify the handshake end-to-end.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(tcp)
                .await
                .unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name: rustls::pki_types::ServerName<'static> = "example.com".try_into().unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(name, tcp)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            None,
            "no ALPN negotiated by default"
        );
    }
}
