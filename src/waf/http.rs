//! The in-sandbox plain HTTP proxy (127.0.0.2:80).
//!
//! Runs inside the sandbox network namespace (process P of the waf mode).
//! It exists only to test the transparent-redirect design: clients that
//! speak plain HTTP to `127.0.0.2:80` (absolute-form requests, i.e. the
//! proxy form) or to a name that the DNS server resolved to `127.0.0.2`
//! (origin-form requests) have their request forwarded to the real
//! target through the host side's `connect` command. It will probably be
//! removed once the HTTPS path is proven.
//!
//! The HTTP framing itself is handled by [`hyper`]: the inbound
//! connection is a `hyper::server::conn::http1` connection whose service
//! opens the upstream connection (via the host side) and replays the
//! request through a `hyper::client::conn::http1` connection; the
//! upstream response is streamed back through the server connection.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue};
use hyper::http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::connect_target;
use crate::connlimit::ConnLimit;

/// The response body type: the upstream's streamed body, or an empty
/// one for the proxy's own error responses.
type BodyT = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// The whole-connection timeout of the plain HTTP proxy. This proxy
/// serves exactly one request per connection (responses carry
/// `Connection: close`, see `Proxy::handle`), so a hard cap on the
/// connection's total lifetime is a safe slowloris guard (AUDIT.md M10):
/// a client that connects but never sends a request — or dribbles one —
/// is cut off here instead of holding a task forever. It also bounds
/// long-running downloads through this test-only frontend; the real
/// traffic path is HTTPS (see `super::https`), which has no such cap.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Accept loop on `127.0.0.2:80`. One HTTP request (or one connection,
/// once the target is known) per connection. Concurrent connections are
/// capped (see [`crate::connlimit`]); at capacity the newly accepted
/// connection is dropped immediately instead of spawning a task for it.
pub async fn serve_http(listener: TcpListener, sock: PathBuf) {
    let sock = Arc::new(sock);
    let limit = ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let Some(guard) = limit.try_acquire() else {
                    continue; // at capacity: drop the connection
                };
                let sock = sock.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    // hyper has no built-in read timer; the one-request-
                    // per-connection shape (see CONNECTION_TIMEOUT) makes
                    // a whole-connection timeout the simplest equivalent.
                    let _ = tokio::time::timeout(
                        CONNECTION_TIMEOUT,
                        http1::Builder::new().serve_connection(TokioIo::new(tcp), Proxy { sock }),
                    )
                    .await;
                });
            }
            Err(_) => return,
        }
    }
}

/// The per-connection HTTP service: resolve the request's target host
/// (absolute-form URI or `Host` header), open the upstream through the
/// host side and pipe the response back.
#[derive(Clone)]
struct Proxy {
    sock: Arc<PathBuf>,
}

impl Service<Request<Incoming>> for Proxy {
    type Response = Response<BodyT>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<BodyT>, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let proxy = self.clone();
        Box::pin(async move { Ok(proxy.handle(req).await) })
    }
}

impl Proxy {
    async fn handle(self, req: Request<Incoming>) -> Response<BodyT> {
        let Some(target) = extract_target(&req) else {
            return empty_response(StatusCode::BAD_REQUEST);
        };
        let upstream = match connect_target(&self.sock, &target).await {
            Ok(pipe) => pipe,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTP proxy to {target} failed: {e}");
                let status = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::BAD_GATEWAY
                };
                return empty_response(status);
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
            return empty_response(StatusCode::BAD_REQUEST);
        };
        parts.uri = uri;
        let host = match HeaderValue::from_str(&target) {
            Ok(host) => host,
            Err(_) => return empty_response(StatusCode::BAD_REQUEST),
        };
        parts.headers.entry(hyper::header::HOST).or_insert(host);

        let (mut sender, conn) =
            match hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("ai-bubble waf: HTTP connection to {target} failed: {e}");
                    return empty_response(StatusCode::BAD_GATEWAY);
                }
            };
        tokio::spawn(conn);
        let response = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("ai-bubble waf: HTTP request to {target} failed: {e}");
                return empty_response(StatusCode::BAD_GATEWAY);
            }
        };

        // One request per connection: close after this response. The
        // body is boxed so it can be handed back to the server side.
        let (mut parts, body) = response.into_parts();
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("close"));
        Response::from_parts(parts, body.boxed())
    }
}

/// An empty response with the given status, closing the connection after
/// it (this proxy does one request per connection).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::host;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

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

    /// Full pipeline: an absolute-form GET -> the HTTP proxy -> the host
    /// connector -> a TCP echo server, with the request replayed there.
    #[tokio::test]
    async fn end_to_end_http_proxy() {
        // "Server": echoes a fixed response after the request head; the
        // replayed request must carry the rewritten (origin-form) request
        // line.
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
                    let text = String::from_utf8_lossy(&buf).to_string();
                    assert!(
                        text.starts_with("GET /path?x=1 HTTP/1.1\r\n"),
                        "replayed head: {text:?}"
                    );
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });

        let dir = std::env::temp_dir().join(format!("ai-bubble-waf-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("sock");
        let std_listener = StdUnixListener::bind(&sock).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(host::serve_host(
            listener,
            vec![format!("127.0.0.1:{}", echo_addr.port())],
            true,
        ));

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        tokio::spawn(serve_http(http, sock));

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

        // Denied targets get a 403 (empty allow list).
        let dir2 = std::env::temp_dir().join(format!("ai-bubble-waf-http2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir2);
        std::fs::create_dir_all(&dir2).unwrap();
        let sock2 = dir2.join("sock");
        let std_listener = StdUnixListener::bind(&sock2).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(host::serve_host(listener, vec![], false));
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        tokio::spawn(serve_http(http, sock2));
        let mut c = TcpStream::connect(http_addr).await.unwrap();
        c.write_all(b"GET http://evil.example/x HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 403"));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// A POST request with no target is rejected too.
    #[test]
    fn method_round_trip() {
        let req: Request<Full<Bytes>> = Request::builder()
            .method("POST")
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(extract_target(&req), None);
    }
}
