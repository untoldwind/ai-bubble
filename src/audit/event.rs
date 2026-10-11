//! The audit event type.
//!
//! One audit event, as it flows through the channel — and, serialized,
//! as one JSON line in the log and as one frame on the inter-process
//! audit channels (the frame *is* the line: the launcher's hub
//! deserializes and re-serializes it, so there is one code path and no
//! format drift). Serialization is left entirely to serde (and thus to
//! the transport: the writer and the channel writer encode, the hub
//! decodes) — this module only defines the shape.
//!
//! The event is an enum by component: each source (`hostfs`, `proxy`,
//! `waf`, `control`, `net`) has its own payload type, and hostfs events
//! name their filesystem operation. `ts`/`pid` are stamped by the
//! emitting process at `record` time and forwarded verbatim by relays.
//! The kind is cross-checked by the launcher's hub against the
//! channel's peer role (SP-2): a child cannot claim another component's
//! event (e.g. a compromised FS emitting a `control` event with the
//! launcher's pid).

use serde::{Deserialize, Serialize};

/// One audit event. `ts`/`pid` are stamped by `record` in the emitting
/// process; everything event-specific — the path or connection target,
/// free-form notes — lives in the component payload under `kind`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// Unknown fields are rejected so a frame that is an event *plus* a
// control-reply key (`"ack"`) cannot be diverted to the reply channel by
// the hub's demultiplexer — an audit-suppression primitive for a
// compromised child (SP-2). With this, such a frame fails the event
// parse; the reply parse (which now refuses frames carrying event
// fields) fails too, so the reader treats it as malformed and closes the
// offending channel — fail-closed.
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    pub(crate) ts: u64,
    pub(crate) pid: u32,
    /// Which component emitted the event, and what happened.
    pub(crate) kind: Kind,
}

impl Event {
    /// A hostfs event: the FUSE operation, whether it succeeded, and the
    /// real (host) path it was served from, when known.
    pub(crate) fn hostfs(
        op: FsOp,
        path: &str,
        outcome: Outcome,
        real: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Event {
            ts: 0,
            pid: 0,
            kind: Kind::Hostfs(HostfsEvent {
                op,
                path: path.to_string(),
                outcome,
                real,
                detail,
            }),
        }
    }

    /// A proxy event: an in-sandbox connection request through the
    /// sandbox's HTTP CONNECT frontend, allowed or denied.
    pub(crate) fn proxy(op: ProxyOp, target: &str, outcome: Outcome) -> Self {
        Event {
            ts: 0,
            pid: 0,
            kind: Kind::Proxy(ProxyEvent {
                op,
                target: target.to_string(),
                outcome,
            }),
        }
    }

    /// A waf event: a connection-related request adjudicated by the waf
    /// (DNS resolution, plain or TLS CONNECT, leaf-certificate signing),
    /// allowed or denied.
    pub(crate) fn waf(op: WafOp, target: &str, outcome: Outcome) -> Self {
        Event {
            ts: 0,
            pid: 0,
            kind: Kind::Waf(WafEvent {
                op,
                target: target.to_string(),
                outcome,
            }),
        }
    }

    /// A control-plane event: the mutable policy was changed at runtime.
    pub(crate) fn policy_change(change: String) -> Self {
        Event {
            ts: 0,
            pid: 0,
            kind: Kind::Control(ControlEvent {
                op: ControlOp::PolicyChange,
                change: Some(change),
                detail: None,
            }),
        }
    }

    /// A netmux event: a peer credential check on a mux connection
    /// failed (the connection is denied).
    pub(crate) fn mux_peer_denied(error: String) -> Self {
        Event {
            ts: 0,
            pid: 0,
            kind: Kind::Net(NetEvent {
                op: NetOp::MuxPeer,
                error,
            }),
        }
    }
}

/// Which component emitted the event, and its component-specific
/// payload. Serialized with a `source` tag so a log line says who spoke.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub(crate) enum Kind {
    /// The FUSE server mirroring the host filesystem (FS).
    Hostfs(HostfsEvent),
    /// The in-sandbox HTTP CONNECT frontend (P).
    Proxy(ProxyEvent),
    /// The host-side waf adjudicating network requests.
    Waf(WafEvent),
    /// The launcher's control plane (runtime policy changes).
    Control(ControlEvent),
    /// The netmux peer-credential gate.
    Net(NetEvent),
}

impl Kind {
    /// The trusted source label for this event's component — what the
    /// hub cross-checks the channel's peer role against (SP-2).
    pub(crate) fn source(&self) -> &'static str {
        match self {
            Kind::Hostfs(_) => "hostfs",
            Kind::Proxy(_) => "proxy",
            Kind::Waf(_) => "waf",
            Kind::Control(_) => "control",
            Kind::Net(_) => "net",
        }
    }
}

/// A hostfs event: one FUSE operation on the mirrored filesystem.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostfsEvent {
    /// Which filesystem operation.
    pub(crate) op: FsOp,
    /// The sandbox-visible path the operation acted on.
    pub(crate) path: String,
    /// Whether it succeeded (and why not, when it failed).
    pub(crate) outcome: Outcome,
    /// The real (host) path the operation was served from, when known.
    pub(crate) real: Option<String>,
    /// A free-form note (e.g. write sizes and offsets).
    pub(crate) detail: Option<String>,
}

/// The hostfs filesystem operations that are audited.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FsOp {
    /// A path lookup during resolution.
    Lookup,
    /// A metadata (stat) request.
    Getattr,
    /// Opening a file.
    Open,
    /// Reading file contents.
    Read,
    /// Writing file contents.
    Write,
    /// Creating a file.
    Create,
    /// Creating a directory.
    Mkdir,
    /// Creating a symlink.
    Symlink,
    /// Removing a file.
    Unlink,
    /// Removing a directory.
    Rmdir,
    /// Renaming (moving) a path.
    Rename,
    /// Creating a hard link.
    Link,
}

/// A proxy event: one connection request through the sandbox's HTTP
/// CONNECT frontend.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyEvent {
    /// Which request.
    pub(crate) op: ProxyOp,
    /// The connection target (host:port).
    pub(crate) target: String,
    /// Whether the request was allowed (and served) or denied.
    pub(crate) outcome: Outcome,
}

/// The proxy connection-request types.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProxyOp {
    /// An HTTP CONNECT tunnel request.
    Connect,
}

/// A waf event: one connection-related request adjudicated by the waf.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WafEvent {
    /// Which request.
    pub(crate) op: WafOp,
    /// The connection target (host:port, or the resolved name for DNS
    /// and certificate requests).
    pub(crate) target: String,
    /// Whether the request was allowed or denied.
    pub(crate) outcome: Outcome,
}

/// The waf request types. Connection requests are the point (CONNECT,
/// plain and TLS); DNS resolution and leaf-certificate signing are the
/// auxiliary steps a connection goes through and are audited too.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WafOp {
    /// A plain CONNECT request.
    Connect,
    /// A DNS resolution request from the sandbox.
    DnsResolve,
    /// A leaf-certificate request for the HTTPS MITM.
    TlsCert,
    /// A TLS CONNECT request (MITM'd HTTPS).
    TlsConnect,
}

/// A control-plane event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlEvent {
    /// Which control event.
    pub(crate) op: ControlOp,
    /// For a policy change: which domain changed. For a forged-source
    /// note: the source label the child claimed.
    pub(crate) change: Option<String>,
    /// For a forged-source note: the hub's free-form note about the
    /// override.
    pub(crate) detail: Option<String>,
}

/// The control-plane event types.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ControlOp {
    /// The runtime-mutable policy was changed (`fs-set`, `net-set`,
    /// spec reload, SIGHUP).
    PolicyChange,
    /// The hub overrode a child's forged source claim (SP-2).
    ForgedSource,
}

/// A netmux event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetEvent {
    /// Which netmux event.
    pub(crate) op: NetOp,
    /// Why the peer was refused.
    pub(crate) error: String,
}

/// The netmux event types.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NetOp {
    /// A mux connection failed its peer-credential check.
    MuxPeer,
}

/// Whether an adjudicated request was allowed, denied, or failed — the
/// typed form of the old `"ok"`/`"denied"`/`"err: ..."` result strings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    /// The request was allowed (and, for connection requests, served).
    Ok,
    /// The request was denied by policy.
    Denied,
    /// The request was refused for another reason: rate limiting, or an
    /// error while serving it.
    RateLimited,
    /// The request passed policy but the operation failed.
    Err { error: String },
}
