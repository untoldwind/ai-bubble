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
use crate::connlimit::ConnLimit;

/// How long the sandbox-side client may take to send its `host:port`
/// target line. A command that opens many connections to the proxy
/// socket but never sends must not hold a task (and, worse, a file
/// descriptor of *this host-side process*) forever — the idle-connection
/// half of AUDIT.md M10's resource-isolation finding.
const TARGET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept loop on the host side: every connection becomes a raw pipe to the
/// requested TCP target (or an error byte if denied/failed). Concurrent
/// connections are capped (see [`crate::connlimit`]): each accepted
/// connection holds a file descriptor of the supervisor, so an unbounded
/// number of idle connections would exhaust them. At capacity the new
/// connection is dropped immediately.
pub async fn serve_connector(listener: UnixListener, allow: Vec<String>, allow_private: bool) {
    let limit = ConnLimit::new();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Some(guard) = limit.try_acquire() else {
                    continue; // at capacity: drop the connection
                };
                let allow = allow.clone();
                tokio::spawn(async move {
                    let _guard = guard;
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
    // The target line must arrive within TARGET_TIMEOUT (see the
    // constant's doc): the timeout guards only this first read, not the
    // piped traffic that follows a successful connect.
    let target = match tokio::time::timeout(TARGET_TIMEOUT, read_line_target(&mut stream)).await {
        Ok(Some(target)) => target,
        _ => return,
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
