//! The network proxy, fully async on tokio.
//!
//! Two independent servers live here, one per network namespace side:
//!
//! * `serve_connector` runs in the *host* network namespace (the original
//!   rs-bubble process). It listens on a Unix-domain socket mounted into
//!   the sandbox and turns `host:port` requests into real TCP connections.
//!
//! * `serve_sandbox_proxy` runs *inside* the sandbox network namespace
//!   (process P). It is a minimal HTTP CONNECT proxy on 127.0.0.2:3128 that
//!   forwards every connection over the Unix socket to the connector.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// Address of the in-sandbox HTTP CONNECT proxy.
pub const PROXY_ADDR: &str = "127.0.0.2:3128";

/// URL form of the proxy address for the http_proxy family of
/// environment variables.
pub const PROXY_URL: &str = "http://127.0.0.2:3128";

/// Check a `host:port` target against the allow-list. An empty list allows
/// everything. List entries are `host` (any port) or `host:port`.
pub fn target_allowed(target: &str, allow: &[String]) -> bool {
    if allow.is_empty() {
        return true;
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (target, None),
    };
    allow.iter().any(|entry| match entry.rsplit_once(':') {
        Some((ehost, eport)) => match eport.parse::<u16>() {
            Ok(eport) => ehost.eq_ignore_ascii_case(host) && Some(eport) == port,
            Err(_) => entry.eq_ignore_ascii_case(host),
        },
        None => entry.eq_ignore_ascii_case(host),
    })
}

/// Accept loop on the host side: every connection becomes a raw pipe to the
/// requested TCP target (or an error byte if denied/failed).
pub async fn serve_connector(listener: UnixListener, allow: Vec<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let allow = allow.clone();
                tokio::spawn(async move {
                    handle_connector_conn(stream, &allow).await;
                });
            }
            Err(_) => return,
        }
    }
}

/// One proxy connection from the sandbox: the client sends `host:port\n`,
/// we reply with a single status byte (`K` = connected, `E` =
/// failed/denied) and then the connection becomes a raw bidirectional pipe
/// to the real TCP target on the host side.
async fn handle_connector_conn(mut stream: UnixStream, allow: &[String]) {
    let Some(target) = read_line_target(&mut stream).await else {
        return;
    };
    if !target_allowed(&target, allow) {
        eprintln!("rs-bubble proxy: connection to {target} denied");
        let _ = stream.write_all(b"E").await;
        return;
    }
    let mut tcp = match TcpStream::connect(&target).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rs-bubble proxy: can't connect to {target}: {e}");
            let _ = stream.write_all(b"E").await;
            return;
        }
    };
    if stream.write_all(b"K").await.is_err() {
        return;
    }
    let _ = copy_bidirectional(&mut stream, &mut tcp).await;
}

/// Accept loop inside the sandbox network namespace: handle one HTTP
/// CONNECT request per connection. The actual connection is made by the
/// connector process (host network namespace) over the Unix socket.
pub async fn serve_sandbox_proxy(listener: TcpListener, sock: PathBuf, allow: Vec<String>) {
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let sock = sock.clone();
                let allow = allow.clone();
                tokio::spawn(async move {
                    handle_connect_proxy(tcp, &sock, &allow).await;
                });
            }
            Err(_) => return,
        }
    }
}

async fn handle_connect_proxy(mut tcp: TcpStream, sock: &Path, allow: &[String]) {
    let Some(target) = read_connect_target(&mut tcp).await else {
        let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return;
    };
    if !target_allowed(&target, allow) {
        eprintln!("rs-bubble proxy: CONNECT to {target} denied");
        let _ = tcp.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return;
    }
    let mut unix = match UnixStream::connect(sock).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("rs-bubble proxy: can't reach connector: {e}");
            let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };
    let mut line = target.clone().into_bytes();
    line.push(b'\n');
    if unix.write_all(&line).await.is_err() {
        let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        return;
    }
    // Wait for the connector's status byte before answering the client.
    let mut status = [0u8; 1];
    if unix.read_exact(&mut status).await.is_err() || status[0] != b'K' {
        let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        return;
    }
    let _ = tcp
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await;
    let _ = copy_bidirectional(&mut unix, &mut tcp).await;
}

/// Read one HTTP CONNECT request and return the `host:port` target.
async fn read_connect_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() > 8192 {
            return None;
        }
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    parse_connect_request(&buf)
}

/// Parse a complete HTTP request head and extract the CONNECT target.
fn parse_connect_request(buf: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    let first = text.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    if target.is_empty() || target.contains('\0') {
        return None;
    }
    Some(target.to_string())
}

/// Read one line (the proxy target) from the connection.
async fn read_line_target(stream: &mut UnixStream) -> Option<String> {
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
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
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
        // Empty list allows everything.
        assert!(target_allowed("anything.example:9999", &[]));
    }

    #[tokio::test]
    async fn read_connect_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let t = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            read_connect_target(&mut s).await
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(t.await.unwrap().as_deref(), Some("example.com:443"));
    }

    #[tokio::test]
    async fn read_connect_rejects_get() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let t = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            read_connect_target(&mut s).await
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(t.await.unwrap(), None);
    }

    #[test]
    fn parse_connect_request_units() {
        assert_eq!(
            parse_connect_request(b"CONNECT host:123 HTTP/1.1\r\nX: y\r\n\r\n"),
            Some("host:123".to_string())
        );
        assert_eq!(
            parse_connect_request(b"connect host HTTP/1.1\r\n\r\n"),
            Some("host".to_string())
        );
        assert_eq!(parse_connect_request(b"\r\n\r\n"), None);
    }

    /// Full pipeline without namespaces: client -> sandbox CONNECT proxy ->
    /// Unix socket -> connector -> TCP echo server.
    #[tokio::test]
    async fn end_to_end_proxy_pipeline() {
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

        // Connector on a temporary Unix socket.
        let dir = std::env::temp_dir().join(format!("rs-bubble-proxy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let unix = tokio::net::UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(serve_connector(unix, vec![]));

        // Sandbox-side CONNECT proxy.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(serve_sandbox_proxy(
            proxy,
            sock_path.clone(),
            vec![format!("127.0.0.1:{}", echo_addr.port())],
        ));

        // Client: CONNECT, then echo through the tunnel.
        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            c.read_exact(&mut buf).await.unwrap();
            head.push(buf[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));

        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A denied target must get a 403 instead of a tunnel.
    #[tokio::test]
    async fn connect_denied_by_allow_list() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!("rs-bubble-deny-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        tokio::spawn(serve_sandbox_proxy(
            proxy,
            dir.join("sock"),
            vec!["allowed.example:443".to_string()],
        ));

        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 12];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"HTTP/1.1 403");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
