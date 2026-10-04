# Audit refactor: single writer over inter-process channels

Plan for refactoring the audit subsystem from *one writer per process* to
**one writer per run**: the launcher `A` becomes the only process that
touches the audit log; `FS` (the FUSE server) and `P` (the in-sandbox
network frontends) send their events upstream over pre-fork Unix
socketpairs.

This document is the *implementation plan*, written against the current
code (file:line references included). The architectural rationale lives
in PLAN.md (*Audit: a single writer through the control channels*); this
document is the concrete how, scoped so it can land **before and
independently of** the runtime-control feature. The channels introduced
here are exactly the pre-fork socketpairs PLAN.md's control plane will
later reuse for `fs-set`/`net-set` — doing audit first means the control
work starts with proven IPC.

---

## Goals / non-goals

Goals:

* `A` is the only process holding the audit-log fd during the run; `FS`
  and `P` close the inherited fd right after `fork`.
* Line integrity and rotation become single-writer concerns; the
  cross-process `O_APPEND`/32 KiB-chunk contract disappears.
* `audit::record(source, op, path, result, detail)` keeps its exact
  signature and semantics (async, bounded, suspend-on-full, never drop)
  — no call-site changes anywhere.
* Event `ts`/`pid` reflect the *emitting* process and the moment of
  `record`, not the relay.
* Clean shutdown loses no events (graceful drain through the channels).

Non-goals (out of scope here, covered by PLAN.md):

* The abstract control socket, token auth, `fs-set`/`net-set` commands.
* Audit coverage changes (e.g. making the waf frontends emit their own
  events) — trivial to add once this lands, but not this refactor.
* Log streaming to operators (`tail -f` keeps working unchanged).

---

## Current state (what is being replaced)

* `audit::configure` (`src/audit/mod.rs:145`) opens the log eagerly
  pre-fork; the fd sits in the process-global `LOG: OnceLock`
  (`mod.rs:100`) and is inherited by every fork child.
* Each process with a runtime lazily builds its own pipeline in
  `setup()` (`mod.rs:297`): bounded mpsc (`CAPACITY = 65536`,
  `mod.rs:72`) → `writer()` task (`mod.rs:378`) → `try_clone()` of the
  inherited fd → batched `write_all` in ≤`MAX_BYTES` (32 KiB,
  `mod.rs:96`) chunks, with rotation in `flush()`/`rotate()`
  (`mod.rs:417,464`).
* Writers today: `FS` (`hostfs/fuse_ops.rs`, ~55 call sites), `P` in
  proxy mode (`proxy/sandbox.rs:70,91,95`), `A` (`proxy/connector.rs`,
  `waf/host.rs`). Drains: `hostfs/server.rs:202`, `netns.rs:137,333`.
* `Event::to_line` (`mod.rs:351`) stamps `ts`/`pid` **at flush time** —
  a quiet-then-burst stream gets misleading timestamps already today.
* No socketpairs exist anywhere; the only pre-fork IPC is the one-byte
  readiness pipe in `hostfs/server.rs:85-136`.

---

## Target architecture

```
        audit log (0600, O_APPEND, rotated)  ◀── sole writer task
                          ▲                         in A
                          │ own mpsc (CAPACITY, unchanged)
   ┌──────────────────────┴───────────────────────┐
   │ A: hub = reader task per child channel,      │
   │     each forwarding into the same mpsc       │
   └───────▲────────────────────▲─────────────────┘
   A↔FS socketpair      A↔P socketpair (isolated path only)
   (SOCK_STREAM,        (SOCK_STREAM, pre-fork,
    pre-fork,            CLOEXEC both ends)
    CLOEXEC)
           │                    │
   FS: record()→mpsc→    P: record()→mpsc→
   channel writer task   channel writer task
   (no log fd held)      (no log fd held)
```

Both directions of each pair are reserved: this refactor uses only the
child→`A` direction (plus a half-close shutdown signal from `A`); the
`A`→child direction stays idle until the control plane needs it.

---

## Wire protocol

One frame per line, JSON, on `SOCK_STREAM` socketpairs. `A` reads with
the existing `line::read_line_limited` (`src/line.rs:21`) at a cap of
**64 KiB** (the `waf/mod.rs` `MAX_REPLY` precedent).

**Event frame** (child→`A`) — the only frame type in this refactor:

```json
{"ts": 1728000000123456, "pid": 1234, "source": "hostfs", "op": "write",
 "path": "/work/x.rs", "result": "ok", "detail": null}
```

* The frame *is* the serialized `Event` — same seven fields as today's
  log line, so `A` re-serializes with the existing `Event::to_line` and
  the log format is byte-identical to today (one code path, no format
  drift).
* `ts`/`pid` are stamped **at `record()` time** by the emitter (moved
  out of `to_line`; this also fixes the flush-time stamping skew noted
  above). `A` forwards them verbatim.
* A serialized event must fit the 64 KiB line cap: `record()` truncates
  `detail` (with a `…[truncated]` marker) so the frame always fits.
  Today `detail` is unbounded — this is the only behavioural change to
  `record`.
* Malformed line (over cap, non-UTF-8, NUL, or JSON that is not an
  `Event`): `A` warns on stderr once per channel and closes that
  reader. The peer is a trusted fork child, so malformed means bug, not
  attack — but a bug in a child must not kill the run.

**Shutdown signalling** uses connection state, not frames:

* `A`→child: `shutdown(SHUT_WR)` on `A`'s end = "the run is ending;
  finish and exit" (read by `FS` as EOF; see *Drain choreography*).
* child→`A`: closing its end = "my queue is flushed; nothing more
  comes" (read by `A`'s reader as EOF).

---

## Module changes, in detail

### 1. `src/audit/mod.rs` — the sink split

* **`Event` becomes serde**: `#[derive(Serialize, Deserialize)]`, fields
  extended with `ts: u64` and `pid: u32`. `to_line()` keeps the existing
  `json!` serialization (now purely mechanical — no stamping).
* **`record()`** stamps `ts`/`pid` when constructing the `Event`,
  truncates `detail` to fit the 64 KiB frame cap, then sends into the
  per-process mpsc as today. Signature unchanged.
* **New statics** (all set once, post-fork, pre-runtime or lazily):
  ```rust
  /// This process's upstream channel (FS/P child end), inherited as a
  /// raw fd and registered here right after fork.
  static CHANNEL_FD: OnceLock<Option<std::os::fd::OwnedFd>> = OnceLock::new();
  /// A-side ends of the child channels (the "peers" the hub reads).
  /// Filled by `cli::run`/`netns::run` as the pairs are created.
  static PEERS: OnceLock<Mutex<Vec<std::os::fd::OwnedFd>>> = OnceLock::new();
  ```
  with `pub fn set_channel(fd: OwnedFd)` (child side),
  `pub fn add_peer(fd: OwnedFd)` (`A` side), and
  `pub fn close_inherited()` — closes any peer fds and any channel fd
  the current process should not hold (called by fork children that are
  *not* audit children: `P` closing the `A`↔`FS` peer end, see §3).
* **`setup()`** (`mod.rs:297`) chooses the sink:
  * `CHANNEL_FD` set → spawn `channel_writer(stream, rx)`: wrap the fd
    via `UnixStream::from_std` (set nonblocking first), serialize each
    batched `Event` with `to_line() + '\n'`, `write_all` to the stream.
    Keep the existing batching knobs (`MAX_EVENTS`, `FLUSH_INTERVAL`) so
    a FUSE-op burst still coalesces. The 32 KiB `MAX_BYTES` chunking and
    rotation are **not** needed here (no `O_APPEND` contract, no file).
  * else `LOG` configured → the existing file `writer()` (this is `A`
    itself, tests, and the pre-phase-3 fallback on the non-isolated
    path).
  * else inert.
  The `SenderCell` shape is unchanged: `drain()` still means "drop the
  sender, await the writer task" — for a channel sink that flushes the
  remaining queue into the socket and returns; the caller then closes
  the fd.
* **New: `channel_writer`** — same select-loop shape as `writer()`
  (`mod.rs:383-403`), writing to the stream instead of the file. Write
  error (EPIPE = `A` gone): warn once on stderr (reuse the
  `WRITE_ERROR_REPORTED` pattern), then discard until the queue drains
  — a dead `A` means the run is ending; never suspend a dying child's
  exit on a dead socket.
* **New hub API** (used by `A` only):
  ```rust
  /// Take the registered peer fds. Once: the hub consumes them.
  pub fn take_peers() -> Vec<OwnedFd>;
  /// Spawn one reader task per peer, all forwarding into this
  /// process's own event queue. Returns the readers' join handles.
  /// Must run inside A's runtime; lazy-inits the queue like record().
  pub fn spawn_hub() -> Vec<tokio::task::JoinHandle<()>>;
  ```
  Each reader: `read_line_limited` → `serde_json::from_str::<Event>` →
  `tx.send(event).await` (the same bounded queue `record()` uses — get a
  `Sender<Event>` clone out of the `SenderCell`; add a small accessor).
  Backpressure is end-to-end and symmetric: full file-writer queue →
  reader suspends → socket buffer fills → child's `channel_writer`
  suspends → child's `record()` callers suspend. Same "never drop,
  suspend" semantics as today, now across process boundaries.
  **Deadlock rule:** reader tasks must be independent spawned tasks that
  never await anything the connector/waf serve loops await — with this
  structure (readers only ever `send` into the queue) that holds by
  construction.
* **`drain()` semantics split** (documented, code mostly unchanged):
  * In a *child*: flush queue → socket, return; caller closes the fd.
  * In `A`: caller must first await the hub readers' EOF, *then* call
    `drain()` for the final file flush.
* The eager-open security properties (`configure`, `validate_path`,
  `safe_open`, AUDIT.md H4/L7/M8) are untouched — the file is still
  opened pre-fork by the original process; only *who keeps the fd*
  changes.

### 2. `src/hostfs/server.rs` — the `A`↔`FS` pair

* In `start_host_fs` (`server.rs:68`), next to the readiness pipe
  (`server.rs:86-90`), create the pair when auditing is on:
  ```rust
  // SOCK_CLOEXEC on both ends: C/S must never inherit either side.
  let mut sv: [libc::c_int; 2] = [0; 2];
  if unsafe { libc::socketpair(libc::AF_UNIX,
      libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
      die_with_error("Can't create audit channel");
  }
  ```
  Gate on a new `audit::ipc_enabled()` (see §4) so the non-isolated path
  pre-phase-3 does not create a pair nobody reads.
* Child branch (`server.rs:113-124`): `close(sv[0])` (the parent end),
  `audit::set_channel(OwnedFd::from_raw_fd(sv[1]))`, and — new —
  **close the inherited audit-log fd** (a `pub(crate) fn audit::drop_log_fd()`
  that takes the `File` out of the `LOG` static's `AuditLog`... simplest:
  `LOG` stores `Mutex<Option<AuditLog>>`-style interior mutability, or
  `drop_log_fd` swaps the file for `/dev/null`. Pick the minimal change:
  store `AuditLog.file` behind a `Mutex<Option<File>>`; `setup()`'s
  `try_clone` becomes "take a clone if still present".)
* Parent branch: `close(sv[1])`, `audit::add_peer(sv[0])`.
* `serve()` (`server.rs:145`): the heartbeat loop
  (`server.rs:176-186`) becomes a `select!` over
  1. channel-read EOF **or** `A`'s `SHUT_WR` half-close → begin
     shutdown (this is the primary, prompt trigger),
  2. the existing 200 ms `getppid()` poll — kept as a backstop for
     abnormal `A` death (fd loss on SIGKILL delivers EOF anyway, so the
     poll becomes redundant but harmless; keep it during the refactor,
     remove later if desired).
  Shutdown order in the child: unmount (existing code) →
  `audit::drain().await` (flushes into the socket, whose read end in `A`
  is still open — that is the point of the half-close) → close channel
  fd → exit.

### 3. `src/netns.rs` — the `A`↔`P` pair and the hub wiring

* In `run()` (`netns.rs:66`), before `fork()` (`netns.rs:91`), create
  the `A`↔`P` pair (same helper/shape as §2, gated on
  `audit::ipc_enabled()`).
* `P` child branch (`netns.rs:95-112`):
  * `audit::close_inherited()` — closes `A`'s `A`↔`FS` peer fd (inherited
    across this fork; `P` must not hold it, or `A`'s `FS` reader never
    sees EOF and a dead fd lingers in the most exposed process);
  * close the pair's parent end, `audit::set_channel(child end)`;
  * close the audit-log fd (same `drop_log_fd` as `FS`).
  * Note `P`'s later fork of `C` (`netns.rs:274`) needs nothing:
    `C` execs, and `SOCK_CLOEXEC` strips the channel at `exec`.
* Connector (`A`) side (`netns.rs:118-139`): the `block_on` body becomes
  the hub:
  ```rust
  let readers = audit::spawn_hub();          // FS peer + P peer
  let status = tokio::select! {              // as today
      _ = serve_connector / serve_host => unreachable!(...),
      st = wait_status(pid) => st,
  };
  audit::shutdown_peers();                   // SHUT_WR on the FS peer
  for r in readers { let _ = r.await; }      // EOF = children flushed
  audit::drain().await;                      // final file flush
  ```
  New tiny helpers: `audit::shutdown_peers()` (`libc::shutdown(fd,
  SHUT_WR)` on each peer) — the peers must stay open for reading until
  EOF, so `spawn_hub` retains raw-fd copies for the shutdown call.
* `P`'s drain (`netns.rs:333`) is unchanged in shape — `drain()` now
  flushes into the socket; add `audit::close_channel()` after it so
  `A`'s reader sees EOF promptly (before `P` exits).

### 4. `src/cli/run.rs` — the enable flag

* After `audit::configure` (`run.rs:95-98`):
  ```rust
  // IPC audit (single writer) needs a runtime in A; the non-isolated
  // path has none until phase 3, so FS keeps its own writer there.
  audit::set_ipc_enabled(sandbox_config.net.isolated);
  ```
  (Once phase 3 lands, this becomes unconditional and the flag goes.)

### 5. `src/sandbox.rs` — phase 3 only: the non-isolated `A`

Today `pidns_and_exec`'s supervisor (`sandbox.rs:599-607`) is a blocking
`waitpid` loop with no runtime, and the non-isolated `A` runs *in* that
function. Phase 3 gives the supervisor a current-thread runtime that
selects over `wait_status` (the `netns.rs:351` pattern) and the hub
readers, then runs the same shutdown/drain sequence as §3. After it
lands: `set_ipc_enabled(true)` unconditionally, and the file-writer
branch of `setup()` serves only `A` and tests. (This is deliberately the
same restructuring PLAN.md phase 3 needs for the control socket — one
runtime serves both.)

---

## fd discipline (who holds what, when)

| fd | created in | `A` | `FS` | `P` | `C`/`S` |
|---|---|---|---|---|---|
| log file | `configure`, pre-fork | keeps (writer) | inherited → **closed post-fork** | inherited → **closed post-fork** | CLOEXEC at exec |
| A↔FS parent end | `start_host_fs` | keeps (hub peer) | closes post-fork | inherited → **closed via `close_inherited()`** | never sees it |
| A↔FS child end | `start_host_fs` | closes post-fork | keeps (channel) | never created yet | — |
| A↔P parent end | `netns::run` | keeps (hub peer) | — | closes post-fork | CLOEXEC at exec |
| A↔P child end | `netns::run` | closes post-fork | — | keeps (channel) | CLOEXEC at exec |

Rule of thumb mirroring the existing listener discipline
(`netns.rs:87-88`): every end is `SOCK_CLOEXEC`, every fork child
closes what it does not own *before* doing any other work.

---

## Drain choreography (no lost events on clean shutdown)

Isolated path:

1. `C` exits → `P`'s `select!` returns → `P` `drain()`s (queue →
   socket) → closes its channel end → exits.
2. `A`'s `wait_status(P)` returns → `A` calls `shutdown_peers()`
   (`SHUT_WR` on the `FS` peer) → `FS`'s read side hits EOF → `FS`
   unmounts, `drain()`s into the still-open write half, closes, exits.
3. `A`'s two readers each end at EOF (all events delivered) → `A`
   `drain()`s (final file flush) → removes the socket dir → exits.

The half-close is load-bearing: `FS` only learns "shut down" from `A`,
but its final events still need the opposite direction open. A full
`close` by `A` would EPIPE `FS`'s last batch.

Abnormal cases:

* `A` SIGKILLed: both peers EOF; `P` is already dead or dying
  (PDEATHSIG chain); `FS`'s ppid backstop fires, its final writes
  EPIPE — those events are lost, same class of loss as killing any
  multi-process pipeline. Acceptable; the run is over.
* `FS`/`P` crash: their end closes → reader EOFs; undelivered queued
  events are lost (the process is dead); `A`'s own wait/heartbeat path
  records the death. Same guarantee as today.

---

## Phases

**Phase 1 — single writer on the isolated path.**
1. `Event` serde + record-time `ts`/`pid` + `detail` truncation;
   `to_line` de-stamped. Existing tests updated (they construct `Event`
   literally — add `ts`/`pid` fields).
2. Sink split in `setup()` + `channel_writer` + hub
   (`take_peers`/`spawn_hub`/`shutdown_peers`/`close_inherited`/
   `drop_log_fd`/`set_ipc_enabled`).
3. `A`↔`FS` pair in `start_host_fs`; `FS` child registration, log-fd
   close, `serve()` select-loop shutdown; parent peer registration.
4. `A`↔`P` pair + `P` registration/close + connector hub wiring and the
   shutdown sequence in `netns.rs`.
5. `set_ipc_enabled(net.isolated)` in `cli::run`.
6. Tests (below). At this point an isolated-mode run has exactly one
   audit writer; `lsof` on the log shows one process.

**Phase 2 — hardening & verification.**
Property tests / integration runs: burst load (build in the mirror)
shows no torn lines and no lost events (count sent vs. lines in log);
shutdown ordering test (events recorded during unmount still land);
malformed-frame handling (unit: feed garbage, reader closes, run
survives).

**Phase 3 — non-isolated path.**
Runtime in `pidns_and_exec`'s supervisor; hub wiring there; make IPC
unconditional; delete the fallback-writer special case from `setup()`
docs. (Shared with PLAN.md phase 3.)

---

## Test plan

* `src/audit/mod.rs` unit tests (alongside the existing ones, which
  keep passing against the file-writer branch):
  * `Event` serde round-trip; `to_line` output identical shape to the
    pre-refactor format (golden line).
  * `record` truncates an oversized `detail` to fit the frame cap.
  * Channel sink → hub → file: `UnixStream::pair()`, one
    `channel_writer`, one hub reader, one file `writer()`; send N
    events, close, assert N intact JSONL lines with original `ts`/`pid`.
  * EOF choreography: half-close the hub side, assert the child writer
    can still flush and its close propagates EOF to the reader.
  * Malformed frame: reader warns once and ends; writer task of `A`
    keeps serving the other peer.
* Integration (manual/scripted, mirroring existing test style): run
  with an audit log in proxy mode and waf mode; assert the log contains
  `hostfs`, `proxy`/`waf` events, all lines parse, and `fuser`/fd
  inspection shows only `A` holding the log.

---

## Risks / decisions to confirm before starting

* **Backpressure across a process boundary** is the one new failure
  mode: a stalled `A` reader suspends `FS`/`P` data paths (today a
  stalled disk suspends only the local process). Mitigated by the
  dedicated-reader rule, but if that proves too fragile in practice,
  the fallback is drop-oldest-with-counter on the child sink — a
  semantics change, so it is *not* the default.
* **Event `ts` moves to record-time.** Slightly different meaning from
  today (better); worth one line in the changelog/commit.
* **`detail` truncation** is new; 64 KiB frames are far above any
  current event, so this should never fire in practice.
* Keep the ppid backstop in `FS` during the refactor even though the
  channel EOF subsumes it; remove only after the channel shutdown path
  is proven in the field.
