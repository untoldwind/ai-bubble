//! The network proxy, fully async on tokio.
//!
//! Two independent servers live here, one per network namespace side:
//!
//! * `connector` runs in the *host* network namespace (the original
//!   ai-bubble process). It serves the pre-fork net socketpair
//!   ([`crate::ipc::netmux`]) and turns `host:port` requests into real
//!   TCP connections.
//!
//! * `sandbox` runs *inside* the sandbox network namespace (process P). It
//!   is a minimal HTTP CONNECT proxy on 127.0.0.2:3128 that forwards every
//!   connection as a stream over the mux socketpair to the connector.
//!
//! The allow-list check is shared by both sides (see `allowlist`). The
//! mode's mux vocabulary (`ProxySpec`) lives here: both ends decode the
//! same `deny_unknown_fields` types, so a foreign frame cannot even be
//! decoded (the confused-deputy containment of PLAN.md Phase 1).

pub mod allowlist;
pub mod connector;
pub mod ipfilter;
pub mod sandbox;

pub use self::connector::serve_connector;
pub(crate) use self::sandbox::ProxyService;

use crate::ipc::netmux::NetSpec;
use serde::{Deserialize, Serialize};

/// The proxy mode's mux request: the CONNECT target. One `OPEN` frame per
/// tunneled connection (the old `host:port\n` line, now shape-checked).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyReq {
    pub(crate) target: String,
}

/// The proxy mode's successful reply: "connected, the stream is now a raw
/// pipe". Refusals arrive as `ERR` frames instead (the connector has no
/// rich reply vocabulary in this mode).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyReply {}

/// The proxy mode's mux vocabulary.
pub(crate) struct ProxySpec;

impl NetSpec for ProxySpec {
    type Req = ProxyReq;
    type Reply = ProxyReply;
}

/// Render a sandbox-controlled target for the operator's stderr: the
/// target line is only NUL/length-checked at the protocol level, so it may
/// contain control bytes — printed raw they would forge log lines
/// (embedded newlines) and inject terminal escape sequences when the
/// operator views the output (AUDIT.md L1). Rust's `Debug` for `str`
/// escapes `\n`, `\x1b`, `\"` and friends while leaving ordinary printable
/// text readable.
pub(crate) fn log_target(target: &str) -> String {
    format!("{target:?}")
}

/// Address of the in-sandbox HTTP CONNECT proxy.
pub const PROXY_ADDR: &str = "127.0.0.2:3128";

/// URL form of the proxy address for the http_proxy family of
/// environment variables.
pub const PROXY_URL: &str = "http://127.0.0.2:3128";

#[cfg(test)]
mod tests {
    use super::*;

    /// A sandbox-supplied target with control bytes must not be printable
    /// as-is (AUDIT.md L1): forged log lines and terminal escape
    /// injection are closed by the `Debug` escaping.
    #[test]
    fn log_target_escapes_control_bytes() {
        assert_eq!(log_target("example.com:443"), "\"example.com:443\"");
        assert_eq!(
            log_target("a\nFOO \u{1b}[31m bar"),
            "\"a\\nFOO \\u{1b}[31m bar\""
        );
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Full pipeline without namespaces: client -> sandbox CONNECT proxy ->
    /// netmux stream -> connector -> TCP echo server.
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

        // Connector on one end of a netmux pair.
        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(serve_connector(
            a,
            crate::proxy::allowlist::shared(vec![format!("127.0.0.1:{}", echo_addr.port())]),
            true,
        ));

        // Sandbox-side CONNECT proxy on the other end.
        let proxy = ProxyService::for_tests(crate::ipc::netmux::MuxHandle::<ProxySpec>::client(b));
        let proxy_addr = proxy.addr();
        // The loop is detached: its join handle is not needed here.
        proxy.spawn();

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
    }
}
