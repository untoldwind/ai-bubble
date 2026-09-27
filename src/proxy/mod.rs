//! The network proxy, fully async on tokio.
//!
//! Two independent servers live here, one per network namespace side:
//!
//! * `connector` runs in the *host* network namespace (the original
//!   ai-bubble process). It listens on a Unix-domain socket mounted into
//!   the sandbox and turns `host:port` requests into real TCP connections.
//!
//! * `sandbox` runs *inside* the sandbox network namespace (process P). It
//!   is a minimal HTTP CONNECT proxy on 127.0.0.2:3128 that forwards every
//!   connection over the Unix socket to the connector.
//!
//! The allow-list check is shared by both sides (see `allowlist`).

pub mod allowlist;
pub mod connector;
pub mod sandbox;

pub use self::connector::serve_connector;
pub use self::sandbox::serve_sandbox_proxy;

/// Address of the in-sandbox HTTP CONNECT proxy.
pub const PROXY_ADDR: &str = "127.0.0.2:3128";

/// URL form of the proxy address for the http_proxy family of
/// environment variables.
pub const PROXY_URL: &str = "http://127.0.0.2:3128";

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UnixListener};

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
        let dir = std::env::temp_dir().join(format!("ai-bubble-proxy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("sock");
        let std_listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let unix = UnixListener::from_std(std_listener).unwrap();
        tokio::spawn(serve_connector(
            unix,
            vec![format!("127.0.0.1:{}", echo_addr.port())],
        ));

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
}
