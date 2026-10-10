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
//! through the pre-fork net mux socketpair ([`crate::ipc::netmux`]),
//! which crosses namespace boundaries as an inherited file descriptor —
//! there is no filesystem name to mount or leak (PLAN.md Phase 2).
//!
//! The pair carries the mode's mux vocabulary (`WafSpec` below), executed
//! on the host (see [`host`]):
//!
//! * `resolve-dns { name }` → `dns { addr }` or `denied { reason }`
//! * `connect { target }` → `open` (then a raw bidirectional data
//!   stream) or `denied`/`failed`
//! * `tls-cert { name }` → `cert { cert, key }` (base64 DER leaf
//!   certificate for the HTTPS MITM, signed by the waf CA whose PEM form
//!   is injected into the sandbox as its trust anchor)
//! * `tls-connect { target }` → `open` (then a data stream carrying
//!   *decrypted* traffic: the host performs the TLS client handshake
//!   with the real root certificates, since the sandbox has no real
//!   trust anchors by design)
//!
//! Requests and replies are typed serde frames with
//! `deny_unknown_fields` (SP-2 shape-checking): a proxy-mode client
//! cannot even decode a waf request, and only [`WafReply`] can carry
//! private key material. Every request is re-authorized host-side
//! against the allow-list; refusals come back as `denied`/`failed`
//! replies, which map to `PermissionDenied`/plain errors exactly like
//! the old line protocol's `ERR` lines did.
//!
//! The allow-list (from the spec's `net.allow`) is enforced on the host
//! side only, so the sandbox cannot talk to anything else: unresolved
//! names fail in the DNS server, and non-listed `connect`/`tls-connect`
//! targets are denied by the host.

pub mod dns;
pub mod host;

use std::io;

use serde::{Deserialize, Serialize};

use crate::ipc::netmux::{MuxHandle, NetSpec};

pub(crate) mod http_service;
pub(crate) use http_service::HttpService;

/// The waf mode's command set. Externally tagged (`deny_unknown_fields`
/// is not supported on internally tagged enums): each frame names its
/// command, e.g. `{"resolve-dns":{"name":"example.com"}}`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum WafReq {
    ResolveDns { name: String },
    Connect { target: String },
    TlsCert { name: String },
    TlsConnect { target: String },
}

/// The waf mode's reply. `denied` (allow-list refusal) and `failed`
/// (host-side dial/TLS/keygen error) replace the line protocol's
/// `ERR <reason>`; the client maps them to `PermissionDenied` and plain
/// errors respectively, preserving the old error-kind semantics.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum WafReply {
    /// `resolve-dns`: the redirect address the name resolves to.
    Dns { addr: String },
    /// `connect`/`tls-connect` accepted: the stream is now a raw
    /// bidirectional data pipe.
    Open,
    /// `tls-cert`: base64(DER cert) and base64(DER PKCS#8 key).
    Cert { cert: String, key: String },
    /// The request was refused by the allow-list (or otherwise denied).
    Denied { reason: String },
    /// The host-side action failed (dial, TLS handshake, keygen).
    Failed { reason: String },
}

/// The waf mode's mux vocabulary.
pub(crate) struct WafSpec;

impl NetSpec for WafSpec {
    type Req = WafReq;
    type Reply = WafReply;
}

/// Ask the host whether `name` may be resolved (the `resolve-dns`
/// command): `Ok(true)` means allowed (the in-sandbox servers take over
/// from here), `Ok(false)`: not on the allow list. A failed round trip
/// (the host may already be tearing down) is an error, answered with
/// SERVFAIL by the DNS server.
pub(crate) async fn resolve_name(mux: &MuxHandle<WafSpec>, name: &str) -> io::Result<bool> {
    let (reply, mut stream) = mux
        .open(&WafReq::ResolveDns {
            name: name.to_string(),
        })
        .await?;
    let r = match reply {
        WafReply::Dns { .. } => Ok(true),
        // An allow-list refusal is a "no", like the old ERR line — the
        // DNS server answers NXDOMAIN, not SERVFAIL.
        WafReply::Denied { .. } => Ok(false),
        WafReply::Failed { reason } => Err(io::Error::other(reason)),
        _ => Err(io::Error::other("unexpected reply to resolve-dns")),
    };
    let _ = stream.close().await;
    r
}
