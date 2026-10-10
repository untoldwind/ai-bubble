//! The in-sandbox DNS server (127.0.0.2:53) as one service:
//! [`DnsService`], DNS over UDP (the transport glibc and most resolvers
//! use first) and DNS over TCP (the fallback transport resolvers use
//! for larger replies), both on port 53.
//!
//! Runs inside the sandbox network namespace (process P of the waf mode,
//! see `crate::sandbox::netns`). It answers every name-resolution question by
//! asking the host over the net mux pair (`resolve-dns`, see
//! `super::host`): allowed names get `127.0.0.2` as their A record,
//! so all further client traffic lands on the in-sandbox HTTP/HTTPS
//! servers; anything else gets NXDOMAIN.
//!
//! Packet parsing and building is delegated to the `simple-dns` crate.
//! The protocol support is intentionally minimal: one standard query
//! with a single IN-class question per packet, no recursion, no caching.
//! A-queries about allowed names are answered with the redirect address;
//! everything else is answered with NXDOMAIN, SERVFAIL (host unreachable)
//! or FORMERR (unsupported query).
//!
//! Like [`super::http::HttpService`], the struct owns the mux
//! handle the server forwards through and its own listeners, bound in
//! [`DnsService::new`] and spawned by [`DnsService::spawn`]; the
//! connection cap bounds the DNS-over-TCP accept loop (AUDIT.md,
//! resource limits on the frontends; UDP is connectionless and needs
//! no such guard).

use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, OPCODE, Packet, PacketFlag, QCLASS, QTYPE, RCODE, ResourceRecord};
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::connlimit::ConnLimit;
use crate::ipc::netmux::MuxHandle;

use super::WafSpec;

/// How long a DNS-over-TCP client may take to send the length prefix and
/// the query of one message. A client that opens a TCP connection but
/// never sends must not hold a task forever (the slowloris half of
/// AUDIT.md, resource limits on the frontends); UDP is connectionless and needs no such guard.
const TCP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The redirect address as an [`std::net::Ipv4Addr`] (parsed from
/// [`super::host::REDIRECT_ADDR`] once per use; it is a compile-time
/// constant, so the expect never fires).
fn redirect_addr() -> std::net::Ipv4Addr {
    super::host::REDIRECT_ADDR
        .parse()
        .expect("redirect address")
}

/// The DNS transport address: the in-sandbox loopback alias the waf
/// DNS server is authoritative for.
const DNS_ADDR: &str = "127.0.0.2:53";

/// The in-sandbox DNS server as one service: the mux handle it forwards
/// through, the connection cap of the DNS-over-TCP accept loop and its
/// own UDP socket and TCP listener on 127.0.0.2:53, bound by
/// [`DnsService::new`].
pub(crate) struct DnsService {
    mux: MuxHandle<WafSpec>,
    limit: std::sync::Arc<ConnLimit>,
    /// The std listener and socket bound in [`DnsService::new`];
    /// [`DnsService::spawn`] registers clones of them with P's tokio
    /// runtime.
    tcp: std::net::TcpListener,
    udp: std::net::UdpSocket,
}

impl Clone for DnsService {
    fn clone(&self) -> Self {
        DnsService {
            mux: self.mux.clone(),
            limit: std::sync::Arc::clone(&self.limit),
            // `dup`s of the same sockets: the loop clones are cheap and
            // never bind or close the port.
            tcp: clone_socket(&self.tcp),
            udp: clone_socket(&self.udp),
        }
    }
}

/// `dup` a socket; a failed dup is a broken sandbox, not a per-connection
/// condition.
fn clone_socket<S>(socket: &S) -> S
where
    S: std::os::fd::AsFd + From<std::os::fd::OwnedFd>,
{
    let owned = socket
        .as_fd()
        .try_clone_to_owned()
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't clone a waf DNS socket: {e}")));
    S::from(owned)
}

/// Bind a DNS listener/socket on port 53, `SOCK_CLOEXEC` (the exec'd
/// sandboxed command must never see it).
fn bind_dns_tcp() -> std::net::TcpListener {
    let listener = std::net::TcpListener::bind(DNS_ADDR).unwrap_or_else(|e| {
        crate::sandbox::die(&format!(
            "Can't bind waf DNS TCP listener on {DNS_ADDR}: {e}"
        ))
    });
    let _ = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    listener
}

fn bind_dns_udp() -> std::net::UdpSocket {
    let socket = std::net::UdpSocket::bind(DNS_ADDR).unwrap_or_else(|e| {
        crate::sandbox::die(&format!("Can't bind waf DNS UDP socket on {DNS_ADDR}: {e}"))
    });
    let _ = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    socket
}

impl DnsService {
    /// A service forwarding through the given mux handle, with the
    /// default connection cap and its own UDP + TCP listeners on
    /// 127.0.0.2:53 already bound. Runs in process P, inside the sandbox
    /// network namespace.
    pub(crate) fn new(mux: MuxHandle<WafSpec>) -> Self {
        DnsService {
            mux,
            limit: ConnLimit::new(),
            tcp: bind_dns_tcp(),
            udp: bind_dns_udp(),
        }
    }

    /// Test-only construction: the unit tests must not claim
    /// 127.0.0.2:53 (they run unprivileged, and parallel test runs
    /// would collide anyway); they bind ephemeral ports instead.
    #[cfg(test)]
    fn for_tests(mux: MuxHandle<WafSpec>) -> Self {
        DnsService {
            mux,
            limit: ConnLimit::new(),
            tcp: std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            udp: std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        }
    }

    /// The test server's UDP address (the tests bind ephemeral ports).
    #[cfg(test)]
    fn udp_addr(&self) -> std::net::SocketAddr {
        self.udp.local_addr().unwrap()
    }

    /// Spawn both serve loops over the service's own sockets (clones of
    /// this service run them; the shared cap and mux come from `self`).
    /// Returns the join handles of the two loops (they never end on
    /// their own; the supervisor keeps them for the sandbox's whole
    /// lifetime).
    pub(crate) fn spawn(&self) -> [tokio::task::JoinHandle<()>; 2] {
        let udp = register_udp(&self.udp);
        let tcp = register_tcp(&self.tcp);
        [
            tokio::spawn(self.clone().serve_udp(udp)),
            tokio::spawn(self.clone().serve_tcp(tcp)),
        ]
    }

    /// Serve DNS over UDP: the transport glibc and most resolvers use
    /// first. Runs until the socket errors out.
    async fn serve_udp(self, socket: UdpSocket) {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let response = reply(&self.mux, &buf[..len]).await;
            if socket.send_to(&response, peer).await.is_err() {
                return;
            }
        }
    }

    /// Serve DNS over TCP (2-byte length-prefixed messages): the
    /// fallback transport resolvers use for larger replies. Runs until
    /// the listener errors out. Concurrent connections are capped (see
    /// [`crate::connlimit`]); at capacity the newly accepted connection
    /// is dropped immediately instead of spawning a task for it.
    async fn serve_tcp(self, listener: TcpListener) {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Some(guard) = self.limit.try_acquire() else {
                continue; // at capacity: drop the connection
            };
            let mux = self.mux.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let _ = serve_tcp_conn(tcp, &mux).await;
            });
        }
    }
}

/// Register the std UDP socket with the current tokio runtime
/// (nonblocking, `SOCK_CLOEXEC` on the fresh fd). Dies on failure: the
/// waf mode cannot serve without DNS.
fn register_udp(socket: &std::net::UdpSocket) -> UdpSocket {
    let fd = clone_socket(socket);
    let _ = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    let _ = fd.set_nonblocking(true);
    UdpSocket::from_std(fd)
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't register DNS UDP socket: {e}")))
}

/// Register the std TCP listener with the current tokio runtime (see
/// [`register_udp`]).
fn register_tcp(listener: &std::net::TcpListener) -> TcpListener {
    let fd = clone_socket(listener);
    let _ = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    let _ = fd.set_nonblocking(true);
    TcpListener::from_std(fd)
        .unwrap_or_else(|e| crate::sandbox::die(&format!("Can't register DNS TCP listener: {e}")))
}

/// `read_exact` with the per-message [`TCP_QUERY_TIMEOUT`]: a client that
/// stalls between (or within) messages is dropped instead of holding the
/// task forever.
async fn read_exact_timed(tcp: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    match tokio::time::timeout(TCP_QUERY_TIMEOUT, tcp.read_exact(buf)).await {
        // `read_exact` filled `buf` (the byte count is irrelevant here);
        // a plain I/O error is propagated as-is.
        Ok(result) => result.map(|_| ()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS-over-TCP message did not arrive in time",
        )),
    }
}

async fn serve_tcp_conn(mut tcp: TcpStream, mux: &MuxHandle<WafSpec>) -> std::io::Result<()> {
    let mut len_buf = [0u8; 2];
    loop {
        read_exact_timed(&mut tcp, &mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 4096 {
            return Ok(());
        }
        let mut query = vec![0u8; len];
        read_exact_timed(&mut tcp, &mut query).await?;
        let response = reply(mux, &query).await;
        tcp.write_all(
            u16::try_from(response.len())
                .unwrap_or(0)
                .to_be_bytes()
                .as_slice(),
        )
        .await?;
        tcp.write_all(&response).await?;
    }
}

/// Ask the host whether `name` may be resolved (via the `resolve-dns`
/// command). `Ok(true)` means: allowed (the in-sandbox servers take over
/// from here), `Ok(false)`: not on the allow list. A failed round trip
/// (the host may already be tearing down) is an error, answered with
/// SERVFAIL.
async fn resolve(mux: &MuxHandle<WafSpec>, name: &str) -> std::io::Result<bool> {
    super::resolve_name(mux, name).await
}

/// Whether this packet is a query this server answers: not a response,
/// standard opcode, exactly one IN-class question.
fn is_supported_query(packet: &Packet<'_>) -> bool {
    !packet.has_flags(PacketFlag::RESPONSE)
        && packet.opcode() == OPCODE::StandardQuery
        && packet.questions.len() == 1
        && packet.questions[0].qclass == QCLASS::CLASS(CLASS::IN)
}

/// Answer one query: parse it (FORMERR on failure or unsupported shape),
/// ask the host for the allow-list decision and build the reply — an A
/// record for the redirect address on allowed A queries, NXDOMAIN
/// otherwise, SERVFAIL when the host cannot be reached.
async fn reply(mux: &MuxHandle<WafSpec>, query: &[u8]) -> Vec<u8> {
    let Ok(packet) = Packet::parse(query) else {
        return formerr(query);
    };
    if !is_supported_query(&packet) {
        return formerr(query);
    }
    // The question borrows from the query buffer; copy out what the
    // reply needs before the packet is turned into a reply.
    let question = packet.questions[0].clone();
    let name = question.qname.to_string().to_ascii_lowercase();
    // NET-5: the qname is sent to the host as the `resolve-dns` frame's
    // payload; validate it here, before sending — the waf frontends'
    // `valid_name` rejects control bytes (which would otherwise reach
    // audit records and error strings unescaped).
    if !super::host::valid_name(&name) {
        return formerr(query);
    }
    let (rcode, answer) = match resolve(mux, &name).await {
        Ok(true) => match question.qtype {
            QTYPE::TYPE(simple_dns::TYPE::A) => (RCODE::NoError, Some(redirect_addr())),
            _ => (RCODE::NoError, None),
        },
        Ok(false) => (RCODE::NameError, None), // NXDOMAIN
        Err(_) => (RCODE::ServerFailure, None),
    };
    let mut reply = packet.into_reply();
    // Mirror the original build_response flags: recursion desired (from
    // the query) and available.
    reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
    *reply.rcode_mut() = rcode;
    if let Some(address) = answer {
        reply.answers.push(ResourceRecord::new(
            question.qname,
            CLASS::IN,
            60,
            RData::A(A::from(address)),
        ));
    }
    reply.build_bytes_vec().unwrap_or_else(|_| formerr(query))
}

/// A FORMERR response for packets that could not be parsed or are not
/// supported: a bare reply header (echoing what of the id is readable).
fn formerr(query: &[u8]) -> Vec<u8> {
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    let mut packet = Packet::new_reply(id);
    *packet.rcode_mut() = RCODE::FormatError;
    packet.build_bytes_vec().expect("formerr packet")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::host;

    /// Build a query packet for `name` with type `A`.
    fn make_query(name: &str) -> Vec<u8> {
        let mut out = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    #[test]
    fn query_parsing() {
        let query = make_query("Example.COM");
        let packet = Packet::parse(&query).unwrap();
        assert_eq!(packet.id(), 0xABCD);
        assert!(is_supported_query(&packet));
        assert_eq!(packet.questions[0].qname.to_string(), "Example.COM"); // case preserved by the parser, lowercased for the allow-list lookup
        assert_eq!(packet.questions[0].qtype, QTYPE::TYPE(simple_dns::TYPE::A));
        // Multiple questions, responses, non-standard opcodes and
        // non-IN classes are not supported (answered with FORMERR).
        let mut multi = make_query("a.com");
        multi[5] = 2;
        assert!(
            !Packet::parse(&multi)
                .map(|p| is_supported_query(&p))
                .unwrap_or(false)
        );
        let mut class = make_query("a.com");
        *class.last_mut().unwrap() = 255;
        assert!(!is_supported_query(&Packet::parse(&class).unwrap()));
        let mut response = make_query("a.com");
        response[2] |= 0x80;
        assert!(!is_supported_query(&Packet::parse(&response).unwrap()));
        // Garbage does not parse at all.
        assert!(Packet::parse(b"too short").is_err());
        // FORMERR echoes the id.
        assert_eq!(&formerr(b"\x12\x34junk")[..2], &[0x12, 0x34]);
        assert_eq!(formerr(b"x").len(), 12);
        assert_eq!(formerr(b"\x12\x34junk")[3] & 0x0F, 1); // rcode FORMERR
    }

    #[test]
    fn response_building() {
        let query = make_query("example.com");
        let packet = Packet::parse(&query).unwrap();
        let question = packet.questions[0].clone();

        // A reply with an answer carries the redirect address.
        let mut reply = packet.clone().into_reply();
        reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        *reply.rcode_mut() = RCODE::NoError;
        reply.answers.push(ResourceRecord::new(
            question.qname.clone(),
            CLASS::IN,
            60,
            RData::A(A::from(redirect_addr())),
        ));
        let response = reply.build_bytes_vec().unwrap();
        assert_eq!(&response[..2], &[0xAB, 0xCD]);
        assert_eq!(&response[2..4], &[0x81, 0x80]);
        assert_eq!(&response[6..8], &[0, 1]); // one answer
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 2]);

        // NXDOMAIN carries no answer.
        let mut reply = packet.into_reply();
        reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        *reply.rcode_mut() = RCODE::NameError;
        let response = reply.build_bytes_vec().unwrap();
        assert_eq!(&response[2..4], &[0x81, 0x83]);
        assert_eq!(&response[6..8], &[0, 0]);

        // A supported query about another type carries no answer either.
        let (rcode, answer) = match question.qtype {
            QTYPE::TYPE(simple_dns::TYPE::A) => (RCODE::NoError, Some(redirect_addr())),
            _ => (RCODE::NoError, None),
        };
        assert_eq!(answer.is_some(), rcode == RCODE::NoError);
    }

    /// Full pipeline: a DNS query over UDP -> the DNS server -> the
    /// mux pair (denied by an empty allow list) -> NXDOMAIN.
    #[tokio::test]
    async fn end_to_end_denial() {
        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(host::serve_host(
            a,
            crate::proxy::allowlist::shared(vec![]),
            false,
        ));
        let service = DnsService::for_tests(MuxHandle::<WafSpec>::client(b));
        let server_addr = service.udp_addr();
        let _loops = service.spawn();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = make_query("example.com");
        client.send_to(&query, server_addr).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let (_, _) = client.recv_from(&mut buf).await.unwrap();
        // NXDOMAIN: rcode 3 in the flags, no answers.
        assert_eq!(buf[3] & 0x0F, 3);
        assert_eq!(&buf[6..8], &[0, 0]);

        // An allowed name gets the redirect address as its A record.
        let (a, b) = crate::ipc::netmux::pair().unwrap();
        tokio::spawn(host::serve_host(
            a,
            crate::proxy::allowlist::shared(vec!["example.com".to_string()]),
            false,
        ));
        let service = DnsService::for_tests(MuxHandle::<WafSpec>::client(b));
        let server2_addr = service.udp_addr();
        let _loops = service.spawn();
        client.send_to(&query, server2_addr).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[3] & 0x0F, 0);
        assert_eq!(&buf[..len][len - 4..], &[127, 0, 0, 2]);
    }
}
