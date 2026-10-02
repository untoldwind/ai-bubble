//! The "waf" network mode: a DNS/HTTP/HTTPS server triple inside the
//! sandbox that transparently redirects allow-listed traffic to the host.
//!
//! Unlike the HTTP CONNECT `proxy` mode (see [`crate::proxy`]), this mode
//! does not rely on proxy environment variables: every host on the
//! allow-list resolves (via the in-sandbox DNS server on `127.0.0.2:53`)
//! to `127.0.0.2`, so a client's connections land directly on the
//! in-sandbox servers (HTTP on port 80 — for testing only, HTTPS on port
//! 443 — identified by its TLS ClientHello SNI). Those servers then
//! forward the traffic to the outside world through the host side.
//!
//! The sandbox keeps a fresh, fully isolated network namespace (only a
//! brought-up loopback); all real networking is done on the host side
//! through a Unix-domain socket, which crosses namespace boundaries via
//! the filesystem (mounted at `/net`).
//!
//! The socket carries a simple line-based command protocol, executed on
//! the host (see [`host`]):
//!
//! * `resolve-dns <name>` → `OK <addr>` or `ERR <reason>`
//! * `connect <host>:<port>` → `OK` (then a raw bidirectional pipe) or
//!   `ERR <reason>`
//! * `tls-cert <name>` → `OK <base64 cert> <base64 key>` (a leaf
//!   certificate for the HTTPS MITM, signed by the waf CA whose PEM form
//!   is injected into the sandbox as its trust anchor)
//! * `tls-connect <host>:<port>` → `OK` (then a bidirectional pipe
//!   carrying *decrypted* traffic: the host performs the TLS client
//!   handshake with the real root certificates, since the sandbox has no
//!   real trust anchors by design)
//!
//! The allow-list (from the spec's `net.allow`) is enforced on the host
//! side only, so the sandbox cannot talk to anything else: unresolved
//! names fail in the DNS server, and non-listed `connect`/`tls-connect`
//! targets are denied by the host.

pub mod dns;
pub mod host;
pub mod http;
pub mod https;

use std::io;
use std::path::Path;

use base64::Engine as _;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

/// The largest reply line accepted from the host (certificates are
/// transferred as base64 within one line).
const MAX_REPLY: usize = 64 * 1024;

/// Send one command line on the socket and read the one-line reply.
/// The reply is `OK ...` on success or `ERR <reason>` otherwise.
pub async fn command(sock: &Path, cmd: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(sock).await?;
    stream.write_all(cmd.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    read_reply(&mut stream).await
}

/// Read the one-line reply of a command connection: `OK ...` or
/// `ERR <reason>`.
async fn read_reply(stream: &mut UnixStream) -> io::Result<String> {
    // An over-limit reply (see [`MAX_REPLY`]) comes back as `None`: a
    // reply that long is malformed for the protocol, so it fails the
    // command instead of being silently truncated into a plausibly
    // different reply.
    crate::line::read_line_limited(stream, MAX_REPLY)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "bad reply from host"))
}

/// Open a raw pipe to `host:port` through the socket's `connect`
/// command: the command and the pipe share one connection, which is
/// returned only when the host replies `OK`.
pub async fn connect_target(sock: &Path, target: &str) -> io::Result<UnixStream> {
    pipe_command(sock, &format!("connect {target}")).await
}

/// Like [`connect_target`], but for the host's `tls-connect` command: the
/// returned pipe carries *decrypted* traffic (the host has already done
/// the TLS client handshake against the real server).
pub async fn tls_connect_target(sock: &Path, target: &str) -> io::Result<UnixStream> {
    pipe_command(sock, &format!("tls-connect {target}")).await
}

/// Send a command whose success turns the connection into a raw
/// bidirectional pipe; returns that pipe once the host replies `OK`.
async fn pipe_command(sock: &Path, cmd: &str) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(sock).await?;
    stream.write_all(format!("{cmd}\n").as_bytes()).await?;
    let reply = read_reply(&mut stream).await?;
    if !reply.starts_with("OK") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{cmd} denied: {reply}"),
        ));
    }
    Ok(stream)
}

/// Ask the host for a leaf certificate (and key) for the HTTPS MITM,
/// signed by the waf CA: DER cert + DER PKCS#8 key, base64'd into the
/// reply line.
pub async fn tls_cert(sock: &Path, name: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let reply = command(sock, &format!("tls-cert {name}")).await?;
    if !reply.starts_with("OK ") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("tls-cert {name} denied: {reply}"),
        ));
    }
    let mut parts = reply[3..].split(' ');
    let (Some(cert), Some(key), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(io::Error::other("malformed tls-cert reply"));
    };
    let dec = |s: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| io::Error::other(format!("bad tls-cert reply: {e}")))
    };
    Ok((dec(cert)?, dec(key)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener as StdUnixListener;

    /// `connect_target` must surface the host's denial as an error.
    #[tokio::test]
    async fn connect_target_reports_denial() {
        let dir = std::env::temp_dir().join(format!("ai-bubble-waf-mod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("sock");
        let std_listener = StdUnixListener::bind(&sock).unwrap();
        let _ = std_listener.set_nonblocking(true);
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();
        // Deny everything.
        tokio::spawn(host::serve_host(listener, vec![], false));

        let err = connect_target(&sock, "example.com:443").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
