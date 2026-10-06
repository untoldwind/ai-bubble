# PLAN: Replace the connector Unix socket with a socketpair

## 1. Goal

The proxy/waf IPC between the sandboxed network process **P** (netns, serves
the in-sandbox frontends on 127.0.0.2) and the **connector** (original host
process, does the real TCP/TLS work) currently runs over a filesystem-bound
Unix socket in a mkdtemp directory (`/tmp/ai-bubble-net.XXXXXX/sock`,
created in `src/sandbox/netns.rs::create_socket_dir`). Replace it with a
`socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC)` created **pre-fork**, the
same mechanism the audit channel already uses (`netns.rs:96-109`,
`src/audit/ipc.rs`).

Motivation:

- **Reachability by construction.** Today the guarantee that the sandboxed
  command cannot reach the connector rests on the mount table (AUDIT.md L6:
  a host `/tmp` bind mount would expose the socket directory). A socketpair
  has no filesystem name at all — it exists only as fds in P and the
  connector. Nothing to mount, nothing to leak.
- **No cleanup race.** Removes `mkdtemp_dir`, the `FD_CLOEXEC` dance on the
  listener, and `remove_dir_all(&netdir)` at connector exit.
- **Uniform IPC style.** One mechanism (socketpair + framed protocol) for
  audit, control and the network data plane.

## 2. Current state (what has to change)

| Concern | Today | File |
|---|---|---|
| Socket creation | `mkdtemp` dir + `StdUnixListener::bind` | `netns.rs::run`, `create_socket_dir` |
| Connector side | `serve_connector(l: UnixListener, …)` accept loop, `ConnLimit` cap, per-connection allow-list snapshot | `proxy/connector.rs:28-52` |
| Connector side (waf) | `serve_host(l, …)` accept loop, same pattern, line-based command protocol (`resolve-dns`, `connect`, `tls-cert`, `tls-connect`) | `waf/host.rs:59-295` |
| P side (proxy) | Per CONNECT request: `UnixStream::connect(sock)`, send `host:port\n`, wait for `K`/`E` byte, then bidirectional pipe | `proxy/sandbox.rs:61-106` |
| P side (waf) | `command(sock, line)` / `pipe_command(sock, line)` helpers; `sock: PathBuf` threaded through `dns.rs`, `http.rs`, `https.rs`, `mod.rs` | `waf/mod.rs:50-123` |
| Lifecycle | Path passed as `PathBuf` down all call chains; `remove_dir_all` on exit | `netns.rs:387, 416-452, 216` |

Key protocol properties that must be preserved:

- One "request" = one fresh connection today (proxy mode: one CONNECT per
  connection; waf mode: one command per connection, possibly followed by a
  raw pipe for the data stream).
- Every request is **re-authorized host-side** against the allow-list.
- Framing today: newline-terminated lines (`line::read_line_limited`,
  ≤512 B target line, `MAX_REPLY` 64 KiB, `COMMAND_TIMEOUT` 10 s).
- The audit/control channel already shares a socketpair in proxy mode
  (`net-set` updates and acks flow P↔connector over the audit pair).

## 3. Design decision: multiplexing

A socketpair is a single pipe. The old "connect a new socket per request"
model does not map onto it, so P and the connector need a way to carry many
concurrent logical streams over one pair. Two viable options:

### Option A (chosen): abstract connection-id multiplexer

- One socketpair is created pre-fork in `netns.rs::run`; the connector keeps
  `sv[0]`, P keeps `sv[1]` (exactly like the audit pair). No filesystem
  name, no fd passing.
- All traffic is framed with a **stream id**. P opens a stream with
  `OPEN {id, kind, target}` (`kind` ∈ `proxy` / `dns` / `http` /
  `tls-cert` / `tls-connect`); the connector authorizes it against the
  allow-list (identical to today's accept path), replies `ACK {id}` /
  `ERR {id, reason}`, and closes a stream with `CLOSE {id}`.
- Request/reply kinds (`resolve-dns`, `tls-cert`) are one or two frames per
  stream; data kinds (`proxy`, `connect`, `tls-connect`) carry a `DATA`
  frame type with a bounded payload cap, terminated by `CLOSE` (half-close
  via a `FIN` flag on `DATA`/`CLOSE`, mirroring `shutdown(Write)`).
- **Reader:** one task reads the pair, parses frames, and dispatches by id
  into a per-stream `tokio::mpsc` channel; the connector side routes to the
  stream's relay handler, the P side to the awaiting request.
- **Writer:** one shared `Arc<Mutex<UnixStream>>` write half, exactly like
  the audit channel's `REPLY_WRITER` — the lock is held only for a single
  bounded `write_all` of a frame, never across a data copy.
- Relay for data streams: a small `mux::copy(stream, target_fd)` (frame
  ↔ buf, ~30 lines) replaces `copy_bidirectional`. Flow control is
  end-to-end TCP on the real sockets; the mux lock serializes only frame
  emission, not the payload path.
- `ConnLimit` becomes a live-stream counter; per-stream allow-list
  snapshot happens at `OPEN` time; `COMMAND_TIMEOUT` / `MAX_REPLY`
  semantics carry over per stream.

Pros: **no `SCM_RIGHTS` at all** — no cmsg handling (partial reads, cmsg
truncation), no dynamically passed fds to leak or forget to close, and the
"does the command inherit a stale fd?" question cannot even arise. One
lifecycle primitive (`CLOSE`) instead of fd ownership across two
processes. The whole net IPC surface is then the same shape as
`audit::ipc`: socketpair + strict framed lines.

Cons: `copy_bidirectional` is replaced by a framed copy (small, contained
in one helper); a frame-size cap now applies to data payloads (desirable
anyway); writer lock adds one bounded serialization point per frame
(negligible at this concurrency).

### Option B (rejected): fd-passing channel server

Same control pair, but for pipe kinds the connector creates a *second*
socketpair and hands one end to P via `SCM_RIGHTS`. Keeps a raw
`copy_bidirectional` shape, but requires the fiddliest low-level code in
the plan (cmsg send/recv), introduces fds whose lifecycle spans two
processes (extra hygiene/leak-regression surface for zero security gain —
the fds are as unreachable to the command as the pair itself), and still
needs the mux for the request/reply kinds anyway. Not worth it.

## 4. Work breakdown

### Phase 1 — mux framing layer  *(implemented: `src/ipc/netmux.rs`)*

Status: done. Notes on the as-built design vs. the sketch below:

* The handler does **not** return the `ACK` payload; it authorizes and
  sends its typed reply itself via `MuxStream::ack(&Reply)` before
  relaying, and returns `io::Result<()>` (an `Err` becomes `ERR`).
  Without this, `open()` would only return after the whole relay
  finished — the old flow is "authorize, write the `OK` line, then
  pipe", and the mux mirrors it.
* The write half's tokio Mutex has no poll-based lock API, so
  `poll_flush`/`poll_shutdown` drive a small boxed-future state machine
  (`lock_owned` → `write_all`) stored on the stream.
* `poll_shutdown` (the `FIN`) flushes any buffered `DATA` first, so a
  caller that forgets `flush` before `shutdown` still gets its bytes.
* The stream cap is the existing `crate::connlimit::ConnLimit` (aliased
  as `StreamLimit`) — a stream ≙ an old connection, so the cap, its
  guard and its tests carry over unchanged.
* `tokio-util` (`codec` feature) was added to `Cargo.toml` for the
  length-prefix envelope framing (see the dependency note there).

Do **not** hand-roll an encoding. The pair carries a **uniform envelope**:
`tokio_util::codec::length_delimited` provides the outer length-prefix
framing (with back-pressure and a `max_frame_length` cap) for *every*
frame; inside each envelope is one tag byte plus a payload whose encoding
depends on the type:

- **Control payloads** (`Req`/`Reply`, generic per mode via the `NetSpec`
  trait — see Phase 1): serde_json bytes, deserialized into the mode's
  typed request/reply enums with `deny_unknown_fields` (SP-2 discipline;
  size caps enforced by the codec's `max_frame_length` instead of
  `line::read_frame_limited`). These messages are tiny and infrequent;
  JSON costs nothing here and keeps frames human-readable in debug logs.
  Explicitly *not* bincode/rkyv/postcard: for ~6 schema-ful message types
  sent a few times per connection, a binary serde format adds a dependency
  and loses shape-checking/debuggability without measurable gain.
- **Data payloads** (`DATA {id, fin, payload}`): opaque byte streams (HTTP
  bodies, TLS ciphertext) — serde adds nothing and base64/JSON would bloat
  the data plane by ~33%. Raw bytes after the fixed binary header
  (`[u32 id, u8 fin]` + payload, cap ~256 KiB).

This replaces `line::read_frame_limited` for this channel, but reuses the
same audit-style reader *discipline* (hard `Err` on over-cap frames).

1. New module `src/ipc/netmux.rs` (the net counterpart of `audit::ipc`),
   split into a **non-generic core** and a **generic control layer**:
   - Non-generic core (shared by both modes): envelope codec, stream ids,
     `OPEN`/`ACK`/`ERR`/`CLOSE`, `DATA {id, fin}`, `MuxHandle` plumbing
     (shared `Arc<Mutex<UnixStream>>` write half, reader task dispatching
     by id into per-stream `tokio::mpsc` receivers), `StreamLimit`.
   - Generic control layer: a `NetSpec` trait the modes implement:
     ```rust
     trait NetSpec: Sized {
         /// The mode's command set, deserialized with deny_unknown_fields
         /// (proxy: `Proxy { target }`; waf: ResolveDns/Connect/
         /// TlsCert/TlsConnect).
         type Req: serde::de::DeserializeOwned;
         /// The mode's reply (plain reply vs. "pipe follows").
         type Reply;
         /// Connector side: authorize + answer one request.
         fn serve(req: Self::Req, ctx: &HostCtx) -> Result<Self::Reply>;
     }
     ```
     `netmux::serve_pair::<S>(fd, …)` (connector) and
     `netmux::MuxHandle<S>` (P). This preserves the existing file split:
     `proxy::serve_connector` / `waf::host::serve_host` and the P-side
     `waf::mod::command`/`pipe_command` become thin `impl NetSpec` blocks.
   - **Confused-deputy containment by type**: each mode's `Req` rejects
     foreign commands at decode time (`deny_unknown_fields`, unknown
     variant) — a proxy-mode client cannot ask for `tls-cert`, and only
     waf's `Spec::Reply` can carry a private key. This moves the
     enforcement the old design got "by accident" (which accept loop
     happened to answer) into the type system, matching the SP-2
     shape-checking the audit channel already applies to
     `Event`/`UpdReply`.
   - `mux::copy(stream, target_fd)` — the framed replacement for
     `copy_bidirectional` (still non-generic: `DATA` streams are mode-
     agnostic; only their *initiation* differs).
2. `ConnLimit` → `StreamLimit` live-counter type.
3. Unit tests: control-frame round-trip (serde) per mode, caps enforcement,
   concurrent open/close, interleaved `DATA` frames, EOF/half-close
   semantics (`fin`), id reuse after `Close`, and cross-mode decode
   rejection (proxy frame fed to waf spec and vice versa).

### Phase 2 — swap the endpoints

4. Connector side: replace `serve_connector(UnixListener)` /
   `serve_host(UnixListener)` with `serve_pair(fd)` running the mux reader
   and per-stream handlers; per-stream allow-list snapshot at `OPEN`,
   `StreamLimit` cap, per-stream timeouts (`COMMAND_TIMEOUT` /
   `MAX_REPLY`), audit-logging identical to today.
5. P side: expose the mux as async helpers with the **same signatures** as
   today's, minus the `sock: PathBuf` parameter:
   - `proxy/sandbox.rs`: `connect_via_connector(target) -> MuxStream`
   - `waf/mod.rs`: `command(kind, args) -> reply`, `pipe_command(kind,
     args) -> MuxStream` (data kinds return a `MuxStream` that reads/writes
     `DATA` frames transparently).
6. Swap the call sites: remove `sock: PathBuf` from
   `serve_sandbox_proxy`, `serve_tcp/udp`, `serve_http`, `serve_https`,
   `Proxy { sock }`, etc.; pass the mux handle instead.

### Phase 3 — netns wiring

7. `netns.rs::run`: delete `create_socket_dir`, the listener bind, and
   `remove_dir_all`; create the net socketpair next to the audit pair,
   close/assign ends after each fork exactly like the audit pair
   (`sv[0]` → connector `serve_pair`, `sv[1]` → P's mux handle). Mark
   `FD_CLOEXEC` (for the exec'd C, not the forks).
8. Fork hygiene: mirror `audit::close_inherited()` — P must drop the
   connector end before running; the connector must drop P's end. The
   sandboxed command never sees either end (CLOEXEC + close in C's path).
9. Wipe-after-fork: extend `waf::host::wipe_after_fork()` if the pair fd
   must not survive into P's children (it must not — P forks C).

### Phase 4 — hardening & docs

10. `SO_PEERCRED` check on the connector's first frame; on failure, close
    and audit-record the attempt.
11. Update `netns.rs` module docs (the process-tree narrative), AUDIT.md L6
    note (the "reachable via `/tmp` bind mount" caveat is now moot — but
    keep the audit of spec mounts that expose host tmpdirs for *other*
    reasons), and `waf/mod.rs` protocol docs (lines 17-29).
12. Audit-log every `OPEN` decision exactly as the old accept loop did
    (`audit::record` in `connector.rs`/`host.rs`) — no behavior change.

## 5. Ordering, testing, rollout

- Phase 1 lands first with unit tests (frame fuzzing against caps, mux
  concurrent open/close, half-close semantics); Phases 2-3 are the cutover
  commit; keep the old listener path behind a temporary
  `--legacy-net-socket` debug flag for one release if desired, then delete.
- Manual matrix: proxy mode CONNECT allow/deny/502; waf mode DNS (tcp+udp),
  HTTP redirect, HTTPS `tls-cert` (throttle + cache), `tls-connect`
  plaintext pipe; control-plane `net-set` swap while streams are open
  (new streams only, as today); SIGKILL of C/P — connector must half-close
  hub peers and exit with the child's status; `--die-with-parent`.
- Regression check: no fd growth over many connections (`ls
  /proc/<pid>/fd` before/after — with no fd passing, only the two fixed
  pair fds should ever exist), no inherited fds in the exec'd command.

## 6. Risks

- **Writer lock on the shared pair**: held only for one bounded frame
  `write_all`, never across a data copy — negligible at this concurrency,
  same discipline as `audit::REPLY_WRITER`.
- **Frame-size caps now bound data payloads**: choose the `DATA` cap
  deliberately (~256 KiB); a too-small cap adds overhead on bulk transfers,
  a too-large one delays interleaved small requests (e.g. DNS) behind one
  big frame. Bounded, measurable, tunable.
- **Half-close semantics**: `shutdown(Write)` must map to a `fin` flag,
  not connection close — relay code that relies on EOF-after-half-close
  (e.g. `copy_bidirectional`) needs the `fin` handling tested explicitly.
- **Deadlock between net mux and audit hub**: both use socketpairs with
  similar writer disciplines; keep them as separate pairs (do *not* merge
  audit and net traffic — the audit hub's PeerRole demux would need
  rework).