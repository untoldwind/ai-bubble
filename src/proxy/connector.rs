//! The connector: the *host*-side proxy server.
//!
//! This code runs in the original ai-bubble process, i.e. in the host
//! network namespace. It serves the pre-fork net socketpair
//! ([`crate::ipc::netmux`]) and turns `host:port` stream-open requests
//! into real TCP connections on the host network. The pair has no
//! filesystem name — the sandboxed command cannot reach it by
//! construction (PLAN.md Phase 2; the AUDIT.md L6 caveat about a host
//! `/tmp` bind mount is moot).

use std::io;

use tokio::net::TcpStream;
use tokio::net::UnixStream;

use super::allowlist::{SharedAllow, target_allowed};
use super::ipfilter::connect_checked;
use super::{ProxyReply, ProxyReq, ProxySpec};
use crate::ipc::netmux::{self, MuxStream};

/// Serve the connector end of the net mux pair: every `OPEN` stream
/// becomes a raw pipe to the requested TCP target (or an `ERR` frame if
/// denied/failed). Concurrent streams are capped (see
/// [`crate::connlimit`] via [`netmux::StreamLimit`]): one stream ≙ one old
/// filesystem-socket connection, so the cap, its guard and its semantics
/// carry over unchanged. At capacity the open is refused with `ERR`.
///
/// The allow-list snapshot is taken per stream at `OPEN` time (the old
/// accept-time snapshot), so a runtime swap (`crate::cli::control`'s
/// `net-set`) affects new streams only.
///
/// The old `TARGET_TIMEOUT` (bounding the client's `host:port` line) is
/// gone with the line protocol: the target arrives as the `OPEN` frame's
/// payload, so there is no idle first-read to bound.
pub async fn serve_connector(pair: UnixStream, allow: SharedAllow, allow_private: bool) {
    netmux::serve_pair::<ProxySpec, _, _>(
        pair,
        netmux::StreamLimit::new(),
        move |req, mut stream| {
            let allow = allow.clone();
            async move {
                handle_connector_conn(
                    req,
                    &super::allowlist::load(&allow),
                    allow_private,
                    &mut stream,
                )
                .await
            }
        },
    )
    .await;
}

/// One proxy stream from the sandbox: the `OPEN` carries the target; on
/// success the connector acks (the old `K` status byte) and the stream
/// becomes a raw bidirectional pipe to the real TCP target. A denial or
/// dial failure returns `Err`, which the mux delivers to the client as an
/// `ERR` frame carrying this reason (the old `E` status byte).
async fn handle_connector_conn(
    req: ProxyReq,
    allow: &[String],
    allow_private: bool,
    stream: &mut MuxStream,
) -> io::Result<()> {
    let target = req.target;
    if !target_allowed(&target, allow) {
        eprintln!(
            "ai-bubble proxy: connection to {} denied",
            super::log_target(&target)
        );
        crate::audit::record("proxy", "connect", Some(&target), Some("denied"), None).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target not on the allow list",
        ));
    }
    // Resolve the name here and refuse private/loopback/link-local ranges
    // (SSRF via DNS rebinding, AUDIT.md H3): the dial goes to the validated
    // IP directly.
    let mut tcp: TcpStream = match connect_checked(&target, allow_private).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "ai-bubble proxy: can't connect to {}: {e}",
                super::log_target(&target)
            );
            crate::audit::record(
                "proxy",
                "connect",
                Some(&target),
                Some("err"),
                Some(format!("{e}")),
            )
            .await;
            return Err(io::Error::other(format!("can't connect: {e}")));
        }
    };
    crate::audit::record("proxy", "connect", Some(&target), Some("ok"), None).await;
    // The old flow's status byte: the ack tells the client the pipe is
    // live, then the tunnel carries its payload.
    stream.ack(&ProxyReply {}).await?;
    let _ = netmux::copy_bidirectional(stream, &mut tcp).await;
    let _ = stream.close().await;
    Ok(())
}
