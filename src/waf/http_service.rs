//! The in-sandbox HTTP frontends of the waf mode as one service:
//! [`HttpService`], the plain HTTP proxy (127.0.0.2:80) and the HTTPS
//! MITM server (127.0.0.2:443).
//!
//! Runs inside the sandbox network namespace (process P of the waf
//! mode). The struct owns the mux handle both frontends forward through
//! (and that the DNS server clones from it) and the connection cap
//! shared by both listeners: one cap over ports 80 + 443 (AUDIT.md,
//! resource limits on the frontends) instead of one per listener, so
//! doubling up across both ports cannot double the footprint.
//!
//! Every mux interaction of the two frontends is a method here — the
//! callers take the handle from `self` rather than passing one around.
//! Because the struct is [`Clone`] (the handle and the cap are cheap to
//! clone), it doubles as hyper's per-connection `Service` in the HTTP
//! proxy and as the closure state of the HTTPS MITM.
//!
//! ## The plain HTTP proxy (127.0.0.2:80)
//!
//! It exists only to test the transparent-redirect design: clients that
//! speak plain HTTP to `127.0.0.2:80` (absolute-form requests, i.e. the
//! proxy form) or to a name that the DNS server resolved to `127.0.0.2`
//! (origin-form requests) have their request forwarded to the real
//! target through the host side's `connect` command. It will probably be
//! removed once the HTTPS path is proven.
//!
//! The HTTP framing itself is handled by [`hyper`]: the inbound
//! connection is a `hyper::server::conn::http1` connection whose service
//! ([`HttpService`]) opens the upstream connection (via the host side)
//! and replays the request through a `hyper::client::conn::http1`
//! connection; the upstream response is streamed back through the server
//! connection.
//!
//! ## The HTTPS MITM (127.0.0.2:443)
//!
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

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONNECTION;
use hyper::http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::{Service, service_fn};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::LazyConfigAcceptor;

use super::{WafReply, WafReq, WafSpec};
use crate::connlimit::ConnLimit;
use crate::ipc::netmux::{MuxHandle, MuxStream};

/// The response body type: the upstream's streamed body, or an empty
/// one for the proxy's own error responses.
type BodyT = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// The whole-connection timeout of the plain HTTP proxy. This proxy
/// serves exactly one request per connection (responses carry
/// `Connection: close`, see `HttpService::handle_http`), so a hard cap
/// on the connection's total lifetime is a safe slowloris guard
/// (AUDIT.md, resource limits on the frontends): a client that connects
/// but never sends a request — or dribbles one — is cut off here instead
/// of holding a task forever. It also bounds long-running downloads
/// through this test-only frontend; the real traffic path is HTTPS (see
/// [`HttpService::serve_https`]), which has no such cap.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a client may take to deliver a complete TLS ClientHello (and
/// then finish the TLS handshake). A client that opens a connection but
/// never sends — or trickles hello bytes — must not hold a task forever
/// (the slowloris half of the resource-DoS concern (AUDIT.md, resource limits on the frontends)). The timeout guards only these
/// initial reads; the tunneled traffic afterwards is never timed out.
const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The plain-HTTP and HTTPS frontends of the waf mode as one service:
/// the mux handle they forward through and the connection cap shared by
/// both accept loops (see the module docs).
#[derive(Clone)]
pub(crate) struct HttpService {
    mux: MuxHandle<WafSpec>,
    limit: Arc<ConnLimit>,
}

impl HttpService {
    /// A service forwarding through the given mux handle, with the
    /// default connection cap (one cap over both frontends).
    pub(crate) fn new(mux: MuxHandle<WafSpec>) -> Self {
        HttpService {
            mux,
            limit: ConnLimit::new(),
        }
    }

    /// Spawn both accept loops over the given listeners (clones of this
    /// service serve them; the shared cap and mux come from `self`).
    /// Returns the join handles of the two loops (they never end on
    /// their own; the supervisor keeps them for the sandbox's whole
    /// lifetime).
    pub(crate) fn spawn(
        &self,
        http: TcpListener,
        https: TcpListener,
    ) -> [tokio::task::JoinHandle<()>; 2] {
        [
            tokio::spawn(self.clone().serve_http(http)),
            tokio::spawn(self.clone().serve_https(https)),
        ]
    }

    /// Open a raw data stream to `host:port` through the host's
    /// `connect` command: returned only when the host replies `open`.
    async fn connect_target(&self, target: &str) -> io::Result<MuxStream> {
        pipe_command(
            &self.mux,
            WafReq::Connect {
                target: target.to_string(),
            },
            "connect",
        )
        .await
    }

    /// Like [`HttpService::connect_target`], but for the host's
    /// `tls-connect` command: the returned stream carries *decrypted*
    /// traffic (the host has already done the TLS client handshake
    /// against the real server).
    async fn tls_connect_target(&self, target: &str) -> io::Result<MuxStream> {
        pipe_command(
            &self.mux,
            WafReq::TlsConnect {
                target: target.to_string(),
            },
            "tls-connect",
        )
        .await
    }

    /// Ask the host for a leaf certificate (and key) for the HTTPS MITM,
    /// signed by the waf CA: DER cert + DER PKCS#8 key, base64'd in the
    /// reply frame.
    async fn tls_cert(&self, name: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let (reply, mut stream) = self
            .mux
            .open(&WafReq::TlsCert {
                name: name.to_string(),
            })
            .await?;
        let r = match reply {
            WafReply::Cert { cert, key } => {
                let dec = |s: &str| {
                    base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .map_err(|e| io::Error::other(format!("bad tls-cert reply: {e}")))
                };
                match (dec(&cert), dec(&key)) {
                    (Ok(cert), Ok(key)) => Ok((cert, key)),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                }
            }
            WafReply::Denied { reason } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("tls-cert {name} denied: {reason}"),
            )),
            WafReply::Failed { reason } => {
                Err(io::Error::other(format!("tls-cert {name}: {reason}")))
            }
            _ => Err(io::Error::other("unexpected reply to tls-cert")),
        };
        let _ = stream.close().await;
        r
    }

    /// An empty response with the given status, closing the connection
    /// after it (both frontends do one request per connection).
    fn empty_response(status: StatusCode) -> Response<BodyT> {
        Response::builder()
            .status(status)
            .header(CONNECTION, hyper::header::HeaderValue::from_static("close"))
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("static response")
    }

    // ------------------------------------------------------------------
    // The plain HTTP proxy
    // ------------------------------------------------------------------

    /// Accept loop on `127.0.0.2:80`. One HTTP request (or one
    /// connection, once the target is known) per connection. Concurrent
    /// connections are capped by the service's limit (shared with the
    /// HTTPS frontend); at capacity the newly accepted connection is
    /// dropped immediately instead of spawning a task for it.
    async fn serve_http(self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    let Some(guard) = self.limit.try_acquire() else {
                        continue; // at capacity: drop the connection
                    };
                    let service = self.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        // hyper has no built-in read timer; the one-request-
                        // per-connection shape (see CONNECTION_TIMEOUT) makes
                        // a whole-connection timeout the simplest equivalent.
                        let _ = tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            http1::Builder::new().serve_connection(TokioIo::new(tcp), service),
                        )
                        .await;
                    });
                }
                Err(_) => return,
            }
        }
    }

    /// One plain-HTTP request: resolve the request's target host
    /// (absolute-form URI or `Host` header), open the upstream through
    /// the host side and pipe the response back.
    async fn handle_http(self, req: Request<Incoming>) -> Response<BodyT> {
        let Some(target) = extract_target(&req) else {
            return Self::empty_response(StatusCode::BAD_REQUEST);
        };
        let upstream = match self.connect_target(&target).await {
            Ok(pipe) => pipe,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTP proxy to {target} failed: {e}");
                let status = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::BAD_GATEWAY
                };
                return Self::empty_response(status);
            }
        };

        // The upstream request keeps its origin-form target (the part
        // after the authority); hyper serializes origin-form request
        // lines and needs the authority as the `Host` header.
        let (mut parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .to_string();
        let Ok(uri) = Uri::builder().path_and_query(path).build() else {
            return Self::empty_response(StatusCode::BAD_REQUEST);
        };
        parts.uri = uri;
        let host = match hyper::header::HeaderValue::from_str(&target) {
            Ok(host) => host,
            Err(_) => return Self::empty_response(StatusCode::BAD_REQUEST),
        };
        // `insert`, not `or_insert` (AUDIT.md finding M2): an
        // attacker-supplied `Host` header must never survive. The dialed
        // authority decides where the request goes (the allow-list
        // checked *that*), so the forwarded request must name it too —
        // otherwise shared infrastructure could route the request
        // elsewhere via the original `Host`.
        parts.headers.insert(hyper::header::HOST, host);

        // NET-7: strip hop-by-hop headers (RFC 7230 §6.1) — they belong
        // to *this* connection, not to the forwarded request, and
        // `Proxy-Authorization` in particular must never be relayed to
        // the upstream. CONNECT/Upgrade requests are not supported by
        // this frontend (test-only plain HTTP) and fail above.
        for header in [
            "proxy-authorization",
            "proxy-authenticate",
            "proxy-connection",
            "connection",
            "te",
            "trailer",
            "transfer-encoding",
            "keep-alive",
            "upgrade",
        ] {
            parts.headers.remove(header);
        }

        let (mut sender, conn) =
            match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("ai-bubble waf: HTTP connection to {target} failed: {e}");
                    return Self::empty_response(StatusCode::BAD_GATEWAY);
                }
            };
        tokio::spawn(conn);
        let response = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTP request to {target} failed: {e}");
                return Self::empty_response(StatusCode::BAD_GATEWAY);
            }
        };

        // One request per connection: close after this response. The
        // body is boxed so it can be handed back to the server side.
        let (mut parts, body) = response.into_parts();
        parts
            .headers
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
        Response::from_parts(parts, body.boxed())
    }

    // ------------------------------------------------------------------
    // The HTTPS MITM
    // ------------------------------------------------------------------

    /// Accept loop on `127.0.0.2:443`. Concurrent connections are capped
    /// by the service's limit (shared with the plain-HTTP frontend); at
    /// capacity the newly accepted connection is dropped immediately
    /// instead of spawning a task for it.
    async fn serve_https(self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    let Some(guard) = self.limit.try_acquire() else {
                        continue; // at capacity: drop the connection
                    };
                    let service = self.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        service.handle_tls(tcp).await;
                    });
                }
                Err(_) => return,
            }
        }
    }

    /// One TLS connection: let rustls parse the ClientHello (via
    /// [`LazyConfigAcceptor`], which buffers and replays the hello bytes
    /// itself), extract the SNI, obtain a forged certificate for it from
    /// the host, terminate TLS and tunnel the plaintext to the real
    /// endpoint through the host's `tls-connect`. Anything that is not a
    /// ClientHello with a SNI (or whose SNI is denied) is dropped.
    async fn handle_tls(&self, tcp: TcpStream) {
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
        let (cert, key) = match self.tls_cert(&sni).await {
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
        let mut tls =
            match tokio::time::timeout(HELLO_TIMEOUT, start.into_stream(Arc::new(config))).await {
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
        // against the SNI before it is forwarded (see
        // [`HttpService::handle_https`]).
        let sni_service = sni.clone();
        let service = self.clone();
        let svc = service_fn(move |req| {
            let service = service.clone();
            let sni = sni_service.clone();
            async move { Ok::<_, std::convert::Infallible>(service.handle_https(&sni, req).await) }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(&mut tls), svc)
            .await;
    }

    /// One decrypted HTTP request: enforce `Host == SNI`, rewrite the
    /// request to origin-form against the dialed authority, and forward
    /// it to the real endpoint through the host's `tls-connect`.
    async fn handle_https(&self, sni: &str, req: Request<Incoming>) -> Response<BodyT> {
        // HTTP-level fronting check (AUDIT.md M2): the `Host` header of the
        // decrypted request must name the same host the TLS ClientHello's
        // SNI did (and that the allow-list admitted). Anything else is a
        // fronting attempt — refused with a 400 instead of being forwarded.
        if !host_header_matches(req.headers(), sni) {
            return Self::empty_response(StatusCode::BAD_REQUEST);
        }

        // The upstream request keeps its origin-form target (the part
        // after the authority); hyper serializes origin-form request
        // lines and needs the dialed authority as the `Host` header.
        // `insert` (not `or_insert`): the header was just verified to be
        // the SNI, but the forwarded request must carry exactly the
        // authority that was dialed, with no attacker-controlled residue.
        let (mut parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .to_string();
        let Ok(uri) = Uri::builder().path_and_query(path).build() else {
            return Self::empty_response(StatusCode::BAD_REQUEST);
        };
        parts.uri = uri;
        let Ok(host) = hyper::header::HeaderValue::from_str(sni) else {
            return Self::empty_response(StatusCode::BAD_REQUEST);
        };
        parts.headers.insert(hyper::header::HOST, host);

        let upstream = match self.tls_connect_target(&format!("{sni}:443")).await {
            Ok(pipe) => pipe,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTPS forward to {sni} failed: {e}");
                return Self::empty_response(StatusCode::BAD_GATEWAY);
            }
        };
        let (mut sender, conn) =
            match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("ai-bubble waf: HTTPS connection to {sni} failed: {e}");
                    return Self::empty_response(StatusCode::BAD_GATEWAY);
                }
            };
        tokio::spawn(conn);
        let response = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTPS request to {sni} failed: {e}");
                return Self::empty_response(StatusCode::BAD_GATEWAY);
            }
        };

        // One request per upstream connection: tell the client not to reuse
        // this one for more than the hyper server connection manages.
        let (mut parts, body) = response.into_parts();
        parts
            .headers
            .insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
        Response::from_parts(parts, body.boxed())
    }
}

/// The plain-HTTP proxy is hyper's per-connection service: a clone of
/// the [`HttpService`] (mux handle and shared connection cap included).
impl Service<Request<Incoming>> for HttpService {
    type Response = Response<BodyT>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<BodyT>, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { Ok(service.handle_http(req).await) })
    }
}

/// Send a command whose success turns the stream into a raw bidirectional
/// data pipe; returns that stream once the host replies `open`.
async fn pipe_command(mux: &MuxHandle<WafSpec>, req: WafReq, what: &str) -> io::Result<MuxStream> {
    let (reply, mut stream) = mux.open(&req).await?;
    match reply {
        WafReply::Open => Ok(stream),
        WafReply::Denied { reason } => {
            let _ = stream.close().await;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{what} denied: {reason}"),
            ))
        }
        WafReply::Failed { reason } => {
            let _ = stream.close().await;
            Err(io::Error::other(format!("{what} failed: {reason}")))
        }
        _ => {
            let _ = stream.close().await;
            Err(io::Error::other(format!("unexpected reply to {what}")))
        }
    }
}

/// The `host:port` this request is for: the authority of an absolute-form
/// target, or the Host header (defaulting the port to 80).
fn extract_target<B>(req: &Request<B>) -> Option<String> {
    let uri = req.uri();
    let authority = if uri.scheme().is_some_and(|s| s.as_str() == "http") {
        uri.authority()?.clone()
    } else {
        req.headers()
            .get(hyper::header::HOST)?
            .to_str()
            .ok()?
            .parse::<Authority>()
            .ok()?
    };
    Some(authority_target(&authority))
}

/// Turn an authority into `host:port`, defaulting the port to 80.
/// (The authority's host keeps the brackets of an IPv6 literal.)
fn authority_target(authority: &Authority) -> String {
    format!(
        "{}:{}",
        authority.host(),
        authority.port_u16().unwrap_or(80)
    )
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
    use crate::waf::host;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `HttpService::connect_target` must surface the host's denial as an
    /// error of kind `PermissionDenied` (the frontends map that to 403).
    #[tokio::test]
    async fn connect_target_reports_denial() {
        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(host::serve_host(
            a,
            crate::proxy::allowlist::shared(vec![]),
            false,
        ));

        let service = HttpService::new(MuxHandle::<WafSpec>::client(b));
        let err = service.connect_target("example.com:443").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn target_extraction() {
        let absolute = Request::builder()
            .uri("http://example.com/path?q=1")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&absolute).as_deref(), Some("example.com:80"));
        let origin = Request::builder()
            .uri("/path")
            .header("host", "example.com:8080")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&origin).as_deref(), Some("example.com:8080"));
        let literal = Request::builder()
            .uri("/")
            .header("host", "[::1]")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&literal).as_deref(), Some("[::1]:80"));
        // Non-HTTP absolute-form URIs are not proxied.
        let other = Request::builder()
            .uri("ftp://example.com/x")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&other), None);
        let nothing = Request::builder()
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&nothing), None);
    }

    /// The SNI validation behind AUDIT.md L4: the SNI must consist of
    /// printable ASCII only — control bytes would be re-emitted verbatim
    /// into the host's audit records and error strings.
    #[test]
    fn sni_must_be_printable() {
        assert_eq!(printable_sni("Example.COM").as_deref(), Some("example.com"));
        for evil in [
            "evil\nexample.com",
            "evil\r.com",
            "e\x01vil.com",
            "evil\x7f.com",
            "evil\\example.com",
            "",
        ] {
            assert_eq!(printable_sni(evil), None, "SNI {evil:?} must be refused");
        }
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

    /// Full pipeline: an absolute-form GET -> the HTTP proxy -> the host
    /// connector -> a TCP echo server, with the request replayed there.
    #[tokio::test]
    async fn end_to_end_http_proxy() {
        // "Server": echoes the request head inside the response body, so
        // the test can assert exactly what the upstream received.
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
                    assert!(
                        head.starts_with("GET /path?x=1 HTTP/1.1\r\n"),
                        "replayed head: {head:?}"
                    );
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
        tokio::spawn(host::serve_host(
            a,
            crate::proxy::allowlist::shared(vec![format!("127.0.0.1:{}", echo_addr.port())]),
            true,
        ));
        let service = HttpService::new(MuxHandle::<WafSpec>::client(b));

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        tokio::spawn(service.clone().serve_http(http));

        let mut c = TcpStream::connect(http_addr).await.unwrap();
        c.write_all(
            format!(
                "GET http://127.0.0.1:{}/path?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                echo_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let body = String::from_utf8_lossy(&resp).to_string();
        let body = body.split("\r\n\r\n").nth(1).expect("echo body");
        assert!(
            body.contains(&format!("host: 127.0.0.1:{}", echo_addr.port())),
            "replayed Host must be the dialed authority: {body:?}"
        );

        // HTTP-level fronting (AUDIT.md M2): an attacker-supplied `Host`
        // header must be overwritten with the dialed authority — the
        // allow-list checked the URI's target, and shared infrastructure
        // would route by the `Host` header instead.
        let mut c = TcpStream::connect(http_addr).await.unwrap();
        c.write_all(
            format!(
                "GET http://127.0.0.1:{}/path?x=1 HTTP/1.1\r\nHost: evil.example\r\n\r\n",
                echo_addr.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let body = String::from_utf8_lossy(&resp).to_string();
        let body = body.split("\r\n\r\n").nth(1).expect("echo body");
        assert!(
            body.contains(&format!("host: 127.0.0.1:{}", echo_addr.port())),
            "replayed Host must be the dialed authority: {body:?}"
        );
        assert!(
            !body.to_ascii_lowercase().contains("evil.example"),
            "attacker-supplied Host must not survive: {body:?}"
        );

        // Denied targets get a 403 (empty allow list).
        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(host::serve_host(
            a,
            crate::proxy::allowlist::shared(vec![]),
            false,
        ));
        let service = HttpService::new(MuxHandle::<WafSpec>::client(b));
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        tokio::spawn(service.serve_http(http));
        let mut c = TcpStream::connect(http_addr).await.unwrap();
        c.write_all(b"GET http://evil.example/x HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 403"));
    }

    /// A stand-in for the host command server: `tls-cert` requests are
    /// answered with really signed leaves, `tls-connect` streams (as if a
    /// TLS handshake had succeeded) pipe to a plain TCP echo server.
    async fn fake_host(pair: tokio::net::UnixStream, echo_port: u16) {
        use crate::ipc::netmux::{StreamLimit, copy_bidirectional, serve_pair};
        serve_pair::<WafSpec, _, _>(
            pair,
            StreamLimit::new(),
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
        let service = HttpService::new(MuxHandle::<WafSpec>::client(b));

        let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls.local_addr().unwrap();
        tokio::spawn(service.serve_https(tls));

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
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

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

    /// The forged leaf for a host verifies under the waf CA.
    #[tokio::test]
    async fn leaf_matches_ca() {
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
