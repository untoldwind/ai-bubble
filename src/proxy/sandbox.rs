//! The in-sandbox HTTP CONNECT proxy server.
//!
//! This code runs inside the sandbox network namespace (process P). It is
//! a minimal HTTP CONNECT proxy on `PROXY_ADDR` that forwards every
//! connection as a netmux stream (see [`crate::ipc::netmux`]) to the
//! connector, which lives on the host side (see `super::connector`) and
//! holds the real network access.

use std::io::ErrorKind;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{ProxyReq, ProxySpec};
use crate::connlimit::ConnLimit;
use crate::ipc::netmux::{self, MuxHandle};

/// How long a client may take to deliver a complete HTTP CONNECT request
/// head. A client that opens a connection but never sends (or trickles
/// bytes) must not hold a task and its connection forever — that is the
/// slowloris half of the resource-DoS concern (AUDIT.md L8 and Verified prevented). The timeout guards *only* this
/// request-head read: bytes after `connect` (part of the piped payload,
/// see `super::connector` and AUDIT.md Verified-safe #7) are read later,
/// without a timeout.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept loop inside the sandbox network namespace: handle one HTTP
/// CONNECT request per connection. The actual connection is made by the
/// connector process (host network namespace) over the net mux pair,
/// which is also where the allow-list is enforced: P deliberately holds
/// no list of its own, so there is nothing to keep in sync with the
/// control plane's `net-set` swaps. Concurrent connections are capped
/// (see [`crate::connlimit`]); when the cap is reached the newly
/// accepted connection is dropped instead of spawning a task for it.
pub async fn serve_sandbox_proxy(listener: TcpListener, mux: MuxHandle<ProxySpec>) {
    let limit = ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                // At capacity: drop the new connection immediately. The
                // client sees a plain close, as for any refused request.
                let Some(guard) = limit.try_acquire() else {
                    continue;
                };
                let mux = mux.clone();
                tokio::spawn(async move {
                    // Hold the connection slot for the task's lifetime.
                    let _guard = guard;
                    handle_connect_proxy(tcp, mux).await;
                });
            }
            Err(_) => return,
        }
    }
}

async fn handle_connect_proxy(mut tcp: TcpStream, mux: MuxHandle<ProxySpec>) {
    // The request head must arrive within HEADER_TIMEOUT (see the
    // constant's doc); a timed-out or malformed head gets the same 400.
    let target = match tokio::time::timeout(HEADER_TIMEOUT, read_connect_target(&mut tcp)).await {
        Ok(Some(target)) => target,
        _ => {
            let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        }
    };
    // Open the mux stream: the connector authorizes host-side (its own
    // allow-list snapshot at OPEN, plus the private-range filter on the
    // resolved address), dials the target and acks once the tunnel is
    // live. A denial arrives as an `ERR` frame, which the client sees as
    // a 502 below.
    let (_, mut stream) = match mux
        .open(&ProxyReq {
            target: target.clone(),
        })
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("ai-bubble proxy: can't reach connector: {e}");
            crate::audit::record("proxy", "CONNECT", Some(&target), Some("err"), None).await;
            let _ = tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };
    crate::audit::record("proxy", "CONNECT", Some(&target), Some("ok"), None).await;
    let _ = tcp
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await;
    let _ = netmux::copy_bidirectional(&mut stream, &mut tcp).await;
    let _ = stream.close().await;
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A denied target must not get a tunnel. The mux pair's connector
    /// end is served with an empty allow-list: the connector (the host
    /// side, and the only allow-list holder) denies the OPEN, and the
    /// proxy relays the failure as a 502.
    #[tokio::test]
    async fn connect_denied_by_connector() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (a, b) = netmux::pair().unwrap();
        tokio::spawn(crate::proxy::serve_connector(
            a,
            crate::proxy::allowlist::shared(vec![]),
            false,
        ));
        tokio::spawn(serve_sandbox_proxy(
            proxy,
            MuxHandle::<ProxySpec>::client(b),
        ));

        let mut c = TcpStream::connect(proxy_addr).await.unwrap();
        c.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 12];
        c.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"HTTP/1.1 502");
    }
}
