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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::{tls_cert, tls_connect_target};
use crate::connlimit::ConnLimit;

/// The response body type: the upstream's streamed body, or an empty
/// one for the proxy's own error responses.
type BodyT = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// How long a client may take to deliver a complete TLS ClientHello (and
/// then finish the TLS handshake). A client that opens a connection but
/// never sends — or trickles hello bytes — must not hold a task forever
/// (the slowloris half of AUDIT.md M10). The timeout guards only these
/// initial reads; the tunneled traffic afterwards is never timed out.
const HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept loop on `127.0.0.2:443`. Concurrent connections are capped
/// (see [`crate::connlimit`]); at capacity the newly accepted connection
/// is dropped immediately instead of spawning a task for it.
pub async fn serve_https(listener: TcpListener, sock: PathBuf) {
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
                    handle_tls(tcp, &sock).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One connection: read the TLS ClientHello, extract the SNI, obtain a
/// forged certificate for it from the host, terminate TLS and tunnel the
/// plaintext to the real endpoint through the host's `tls-connect`.
/// Anything that is not a ClientHello with a SNI (or whose SNI is denied)
/// is dropped.
async fn handle_tls(mut tcp: TcpStream, sock: &Path) {
    // Slowloris guard (AUDIT.md M10): the ClientHello — and the rest of
    // the TLS handshake, which the client could equally stall — must
    // complete within HELLO_TIMEOUT. On timeout the connection is simply
    // dropped.
    let (hello, sni) = match tokio::time::timeout(HELLO_TIMEOUT, read_client_hello(&mut tcp)).await {
        Ok(Some(pair)) => pair,
        _ => return, // timeout, EOF or not a usable TLS hello: just close
    };
    let Some(sni) = sni else {
        return; // no SNI: we cannot know the target, so nothing to forward
    };
    let (cert, key) = match tls_cert(sock, &sni).await {
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
    let acceptor = TlsAcceptor::from(Arc::new(config));
    // The hello bytes were already consumed from the socket; hand them
    // back to rustls via a prefix stream. The client's side of the
    // handshake is time-boxed too (see the HELLO_TIMEOUT doc).
    let mut tls = match tokio::time::timeout(
        HELLO_TIMEOUT,
        acceptor.accept(PrefixedStream::new(hello, tcp)),
    )
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
    let sock = sock.to_path_buf();
    let sni_service = sni.clone();
    let svc = service_fn(move |req| {
        let sock = sock.clone();
        let sni = sni_service.clone();
        async move {
            Ok::<_, std::convert::Infallible>(handle_request(&sock, &sni, req).await)
        }
    });
    let _ = http1::Builder::new().serve_connection(TokioIo::new(&mut tls), svc).await;
}

/// One decrypted HTTP request: enforce `Host == SNI`, rewrite the
/// request to origin-form against the dialed authority, and forward it
/// to the real endpoint through the host's `tls-connect`.
async fn handle_request(sock: &Path, sni: &str, req: Request<Incoming>) -> Response<BodyT> {
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

    let upstream = match tls_connect_target(sock, &format!("{sni}:443")).await {
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

/// A [`TcpStream`] prefixed with bytes already read from it (the TLS
/// ClientHello consumed during SNI extraction): reads first replay the
/// prefix, then continue with the socket.
struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Read the ClientHello (possibly spanning several TLS records until the
/// handshake message is complete, bounded by a sane limit) and extract
/// the SNI. Returns the bytes read so far — the hello itself, ready to be
/// replayed — and the SNI if it was found.
async fn read_client_hello(tcp: &mut TcpStream) -> Option<(Vec<u8>, Option<String>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut hello_len = None;
    loop {
        match tcp.read(&mut chunk).await {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        if hello_len.is_none() {
            // First record: a 5-byte header (content type, version,
            // length), then the handshake message header (type, 3-byte
            // length).
            if buf.len() < 5 {
                continue;
            }
            if buf[0] != 0x16 {
                return None; // not a handshake record
            }
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if record_len == 0 || record_len > 16 * 1024 {
                return None;
            }
            if buf.len() < 9 {
                continue;
            }
            if buf[5] != 0x01 {
                return None; // not a ClientHello
            }
            let len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
            if len == 0 || len > 64 * 1024 {
                return None;
            }
            hello_len = Some(len);
        }
        let len = hello_len.unwrap();
        if buf.len() < 9 + len {
            continue; // the hello is not complete yet: keep reading
        }
        let sni = sni_from_client_hello(&buf[9..9 + len]);
        buf.truncate(9 + len);
        return Some((buf, sni));
    }
}

/// Extract the SNI host name from a ClientHello body (the handshake
/// message without its 4-byte header): parse down to the `server_name`
/// (type 0x0000) extension and return its `host_name` entry, lowercased.
/// `None` means: no SNI, or a structure this parser does not understand.
fn sni_from_client_hello(hello: &[u8]) -> Option<String> {
    // client version (2) + random (32)
    let mut pos = 34usize;
    // session id
    let sid_len = *hello.get(pos)?;
    pos += 1 + usize::from(sid_len);
    // cipher suites
    if pos + 2 > hello.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    // compression methods
    let comp_len = *hello.get(pos)?;
    pos += 1 + usize::from(comp_len);
    if pos + 2 > hello.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(hello.len());
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let elen = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            return None;
        }
        if etype == 0x0000 {
            // server_name: a list of named entries; take the host_name
            // (type 0) one.
            let data = &hello[pos..pos + elen];
            if data.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let list_end = (2 + list_len).min(data.len());
            let mut p = 2usize;
            while p + 3 <= list_end {
                let name_type = data[p];
                let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
                p += 3;
                if p + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    let name = &data[p..p + name_len];
                    return if name.iter().all(|&b| b.is_ascii() && b != 0 && b != b'\\') {
                        Some(String::from_utf8_lossy(name).to_ascii_lowercase())
                    } else {
                        None
                    };
                }
                p += name_len;
            }
            return None;
        }
        pos += elen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// Build a ClientHello record with the given SNI (or none).
    fn make_client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(sni) = sni {
            let mut entry = vec![0u8]; // host_name
            entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            entry.extend_from_slice(sni.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            exts.extend_from_slice(&0u16.to_be_bytes()); // server_name type
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes()); // one cipher suite
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // one compression method
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = vec![0x01]; // ClientHello type
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sni_extraction() {
        let record = make_client_hello(Some("Example.COM"));
        // Strip the record header (5) and handshake header (4) bytes.
        assert_eq!(
            sni_from_client_hello(&record[9..]).as_deref(),
            Some("example.com")
        );

        let record = make_client_hello(None);
        assert_eq!(sni_from_client_hello(&record[9..]), None);

        // Truncated input is rejected outright.
        assert_eq!(sni_from_client_hello(&record[9..20]), None);
    }

    /// A stand-in for the host command server: `tls-cert` requests are
    /// answered with really signed leaves, `tls-connect` pipes (as if a
    /// TLS handshake had succeeded) to a plain TCP echo server.
    async fn fake_host(
        listener: tokio::net::UnixListener,
        echo_port: u16,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            use super::super::host;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Read the command line.
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while line.last() != Some(&b'\n') {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => line.push(byte[0]),
                    }
                }
                let cmd = String::from_utf8_lossy(&line).trim().to_string();
                if let Some(name) = cmd.strip_prefix("tls-cert ") {
                    if name == "evil.example" {
                        let _ = stream.write_all(b"ERR denied\n").await;
                        continue;
                    }
                    match host::sign_leaf(name) {
                        Ok((cert, key)) => {
                            let enc =
                                |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);
                            let _ = stream
                                .write_all(format!("OK {} {}\n", enc(&cert), enc(&key)).as_bytes())
                                .await;
                        }
                        Err(e) => {
                            let _ = stream.write_all(format!("ERR {e}\n").as_bytes()).await;
                        }
                    }
                    continue;
                }
                if cmd == "tls-connect evil.example:443" {
                    let _ = stream.write_all(b"ERR denied\n").await;
                    continue;
                }
                if let Some(_target) = cmd.strip_prefix("tls-connect ") {
                    let Ok(tcp) = TcpStream::connect(("127.0.0.1", echo_port)).await else {
                        let _ = stream.write_all(b"ERR no target\n").await;
                        continue;
                    };
                    let _ = stream.write_all(b"OK\n").await;
                    let (mut rs, mut ws) = stream.into_split();
                    let (mut rt, mut wt) = tcp.into_split();
                    tokio::select! {
                        _ = tokio::io::copy(&mut rs, &mut wt) => {}
                        _ = tokio::io::copy(&mut rt, &mut ws) => {}
                    }
                    continue;
                }
                let _ = stream.write_all(b"ERR unknown\n").await;
            }
        })
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

        let dir = std::env::temp_dir().join(format!("ai-bubble-waf-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(fake_host(listener, echo_addr.port()));

        let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls.local_addr().unwrap();
        tokio::spawn(serve_https(tls, sock));

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

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `Host` header check behind the M2 fix: the parsed authority's
    /// host part must equal the SNI (case-insensitive, port ignored) —
    /// and it must not fall for prefix/suffix look-alikes.
    #[test]
    fn host_header_must_match_the_sni() {
        use hyper::header::HeaderValue;
        let ok = |h: &str| host_header_matches(
            &{
                let mut m = hyper::HeaderMap::new();
                m.insert(hyper::header::HOST, HeaderValue::from_str(h).unwrap());
                m
            },
            "example.com",
        );
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
        assert!(!host_header_matches(&hyper::HeaderMap::new(), "example.com"));
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
            let _ = TlsAcceptor::from(Arc::new(config))
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
