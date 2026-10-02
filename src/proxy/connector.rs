//! The connector: the *host*-side proxy server.
//!
//! This code runs in the original ai-bubble process, i.e. in the host
//! network namespace. It listens on a Unix-domain socket mounted into the
//! sandbox and turns `host:port` requests into real TCP connections on the
//! host network.

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{UnixListener, UnixStream};

use super::allowlist::target_allowed;
use super::ipfilter::connect_checked;

/// Accept loop on the host side: every connection becomes a raw pipe to the
/// requested TCP target (or an error byte if denied/failed).
pub async fn serve_connector(listener: UnixListener, allow: Vec<String>, allow_private: bool) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let allow = allow.clone();
                tokio::spawn(async move {
                    handle_connector_conn(stream, &allow, allow_private).await;
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
async fn handle_connector_conn(mut stream: UnixStream, allow: &[String], allow_private: bool) {
    let Some(target) = read_line_target(&mut stream).await else {
        return;
    };
    if !target_allowed(&target, allow) {
        eprintln!("ai-bubble proxy: connection to {target} denied");
        crate::audit::record("proxy", "connect", Some(&target), Some("denied"), None).await;
        let _ = stream.write_all(b"E").await;
        return;
    }
    // Resolve the name here and refuse private/loopback/link-local ranges
    // (SSRF via DNS rebinding, AUDIT.md H3): the dial goes to the validated
    // IP directly.
    let mut tcp = match connect_checked(&target, allow_private).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ai-bubble proxy: can't connect to {target}: {e}");
            crate::audit::record(
                "proxy",
                "connect",
                Some(&target),
                Some("err"),
                Some(format!("{e}")),
            )
            .await;
            let _ = stream.write_all(b"E").await;
            return;
        }
    };
    crate::audit::record("proxy", "connect", Some(&target), Some("ok"), None).await;
    if stream.write_all(b"K").await.is_err() {
        return;
    }
    let _ = copy_bidirectional(&mut stream, &mut tcp).await;
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
