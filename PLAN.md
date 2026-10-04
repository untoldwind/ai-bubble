# Runtime control of a running instance

Plan for controlling a running `ai-bubble run` at runtime: viewing the
audit log, and tweaking file and network permissions while the sandboxed
command is live.

This document is the *plan*, not documentation of an implemented feature.
It was revised against the current code; see **Revision notes** at the end
for what changed and why.

Decisions taken so far:

* **Transport: a Unix-domain socket API**, owned by the launcher process
  `A` — not a config-file watch, not a web socket in the core.
* **Placement: an abstract-namespace socket** in the host network
  namespace, plus a per-run authentication token.
* **Propagation: `A` is the single control hub**; policy updates reach
  the FUSE server (`FS`) and, on the proxy path, the in-sandbox network
  frontends (`P`) over pre-fork `SOCK_STREAM` socketpairs (see *The
  propagation channels*).
* **Audit: a single writer.** `FS` and `P` send their audit events
  upstream over the same pre-fork socketpairs; `A` is the only process
  that ever writes the audit log (see *Audit: a single writer*).
* **Enablement: opt-in.** Runtime control is off unless the run is
  started with it (see *Enabling control*); a control-enabled run also
  mounts the FUSE mirror writable (see below).
* **Web UI: out of scope for the core.** Long term, a standalone bridge
  app (WebSocket/HTTP ↔ the Unix control socket) serves a web UI — the
  way dockerd's socket is consumed by Portainer. The core exposes one
  small, stable protocol; everything webby lives outside.

---

## What is (not) runtime-mutable

Only a subset of the spec can ever change at runtime; the plan is shaped
by this fact.

| Policy | Enforced in | Mutable at runtime? |
|---|---|---|
| `hostfs` mirror permissions (`ro`/`rw`/`hide`/empty/redirect/inject globs) | `FS` (FUSE server) — every FUSE op matches the requested path against the compiled patterns on the fly | ✅ yes — swap the pattern set in `FS` (with the caveats below) |
| `net.allow` | `A` (connector / waf host) **and, on the proxy path only, `P`** (the in-sandbox CONNECT proxy answers 403 early) — each holds its own copy | ✅ yes — the update must reach **A and, in proxy mode, `P`** |
| `net.allow_private`, `net.*.unix_sockets`/`netlink`/`vsock`/`bluetooth`, `net.isolated`/`mode` | `A`/`P` dial policy, and the AF-family gate compiled into the seccomp filter | ❌ the family gate is in the kernel filter; `allow_private` is host dial policy but treated as immutable (see `spec-reload`) |
| mounts (`bind`, `tmpfs`, `proc`, `dev`, `symlink`) | `S`, once, before exec | ❌ `S` has exec'd away |
| `seccomp` filter | the kernel, installed right before exec | ❌ installed; cannot be changed (but `A` still *holds* the compiled policy, so `spec-reload` can compare it) |
| `env`, `cwd`, `rlimits`, uid map | exec-time | ❌ |

Consequences:

1. **No "reload the whole spec" semantics.** The honest API is "replace
   the mutable policy subset". A `spec-reload` command may exist as
   sugar, but it must diff the freshly read (and freshly *preprocessed*,
   see `spec-reload`) spec against the running one and **hard-error when
   any immutable part changed** — otherwise operators believe they
   tightened seccomp when nothing happened.
2. **Mount-time constraint for `fs-set`:** the FUSE mount is mounted
   read-only unless *some* mapping said `rw` at startup
   (`MountOptions::read_only` in `hostfs/server.rs::mount_with_fallback`,
   and the `MS_RDONLY` flag of the privileged-fallback remount). A run
   that started fully read-only cannot grant writes later — fuse3's mount
   handle has no remount. When runtime control is enabled, the mount must
   be made writable regardless. This gives up the kernel-level read-only
   backstop and relies entirely on the per-operation pattern checks; that
   is an accepted trade-off, and it is the reason control is **opt-in**.
3. **`fs-set` has three non-obvious correctness hazards** (all present in
   the current code):
   * `HostFs.patterns` is a plain `Patterns`, moved into the FUSE session
     — it must become shared, mutable state (`Arc<ArcSwap<Patterns>>`, or
     an `RwLock`) read by every FUSE op.
   * `OpenHandle.writable` caches the spec's `rw` verdict **at open
     time** (`hostfs/mod.rs`, `hostfs/fuse_ops.rs::write`). After
     `fs-set`, an already-open handle would keep its old verdict —
     tightening `rw → ro` would *not* stop writes through an open handle.
     The cached bool must be removed and the write path must re-check
     `patterns.writable(&handle.path)` on every write.
   * `HostFs.dir_cache` caches per-directory name listings, validated by
     the host directory's mtime/ctime. Swapping patterns does not change
     the host timestamps, so stale visibility would persist. The cache
     must be cleared on every pattern swap.
4. **Audit-log viewing needs no API.** The audit log is a host-side JSONL
   file, written by a single process (`A` — children forward their
   events over the control channels, see *Audit: a single writer*), so
   lines never tear and any process can `tail -f` it. Building log
   streaming into the control protocol would re-implement `tail` with
   added attack surface. (A convenience `ai-bubble audit --follow`
   subcommand may be added later, purely as sugar.)

---

## Socket placement

### Choice: abstract-namespace socket in the host network namespace

```
@ai-bubble-control-<16 hex chars of sha256(canonical spec-dir path)>
```

In the Linux abstract namespace the leading `@` is really a leading NUL
byte in `sun_path`; tools render it as `@`. There is a deliberate
symmetry with the existing bridge socket: that one is a **filesystem**
socket precisely because it *must* cross the network namespace boundary
(Unix sockets cross network namespaces via the filesystem). The control
socket needs the exact opposite property — it must never be reachable
from inside the sandbox — so it uses the other kind of address.

**Namespace reality check.** `A` is not in host namespaces generally. In
the non-isolated path, `sandbox::setup_and_exec` runs *in `A`* and
unshares user+cgroup, UTS, then IPC+PID before forking `S`; `A` therefore
already lives in the sandbox's user/UTS/IPC/PID namespaces. What holds in
**both** paths is the part that matters here: `A` stays in the **host
network namespace** (only `P` unshares `CLONE_NEWNET`, and `S` inherits
it) and in the **host mount namespace**. `FS` is genuinely in host
namespaces. The abstract socket lives in the network namespace, and `A`'s
netns is the host's in every shape.

Properties this buys:

* **Proxy/waf mode: categorically unreachable from the sandbox.** The
  sandbox has its own network namespace; the name does not exist there.
  No mapping, bind, glob or mount trick can expose it — it is not a
  filesystem object at all. (The spec dir's auto-hide is only a `hide`
  glob in the FUSE mirror — it cannot protect filesystem objects against
  `bind` mounts, which bypass the FUSE layer entirely, and sandboxed
  processes run with the operator's real host uid, so file permission
  bits don't stop them either. Placement must not rely on either.)
* **Host mode:** the sandbox shares the host netns, so the name *is*
  reachable; the AF_UNIX seccomp gate denies it only if the spec left
  `net.host.unix_sockets` false (host mode defaults to denying), and that
  gate is best-effort under IA32 emulation. Host mode is documented as
  trusted-commands-only; the token is the second line of defense, and the
  token file inherits the same "spec dir not exposed" assumption as
  `.env` (see below).
* **Multiple projects:** the name hashes the canonical spec-dir path, so
  different projects get different sockets. Both `A` and the CLI client
  must `realpath` the spec dir before hashing, or a relative vs. absolute
  `--spec-dir` would address different names.
* **One control endpoint per project:** a second concurrent run on the
  same spec dir gets `EADDRINUSE` on bind. Behaviour then: warn loudly on
  stderr (and audit-log it), and run *without* the control server —
  concurrent runs of the same project are legitimate and must not be
  blocked. (Hard exclusivity would be a one-line change. A per-run
  endpoint — hash + launcher PID, one token file per run — is the
  alternative if client-side run selection is wanted; see Revision notes.)
* **No `sun_path` length limit:** a filesystem socket under `.ai-bubble/`
  breaks at ~107 bytes of path; deep project directories would hit
  this. The abstract name is fully controlled and ~45 bytes.
* **No stale-socket cleanup:** the name disappears when the last fd to
  the listening socket closes. This only holds if the listener fd is not
  inherited and held open by a long-lived child — see the fd discipline
  below.
* **Discovery without a pointer file:** tooling recomputes the hash
  from `--spec-dir`; enumerating all running instances is
  `grep @ai-bubble-control /proc/net/unix`.

### Authentication: a per-run token

`SO_PEERCRED` is **useless** here: the sandbox's user namespace maps the
operator's uid to 65535 only *inside*; on the host the sandboxed command
connects with the operator's real (kernel) uid, indistinguishable from
the operator's own tools. Therefore:

* `A` generates 128 random bits at startup (no `rand` dependency exists;
  use `getrandom(2)` via libc, or read `/dev/urandom`) and writes them
  `0600` to `<spec-dir>/run/control-token` (create `run/` with `0700` if
  missing; write with `O_NOFOLLOW|O_EXCL` semantics like
  `audit::safe_open`).
* **Ordering matters.** Bind the abstract socket *first*; only if the
  bind succeeds, write the token file. On `EADDRINUSE`, do **not** touch
  the token file — otherwise a second run would clobber the token the
  first run's clients are using and silently lock them out. On exit, the
  owner removes the token file it wrote (best effort).
* Every connection must present the token as its first length-bounded
  line; a mismatch closes the connection. No banner, no hints. Compare
  with a constant-time comparison.
* The token file inherits an assumption the design already makes: the
  spec directory must not be bind-aliased into the sandbox — the env file
  with its secrets lives there today under exactly that assumption (and
  the FUSE auto-hide mapping covers it only in mirror mode). No *new*
  requirement is introduced, but note the corollary: in host mode, where
  the sandbox can reach the socket directly, the token is only as secret
  as the spec directory is out of reach. Host mode stays
  trusted-commands-only.
* The token never enters the sandbox: not via `env`, not via an
  `Inject`ed file, never logged.

---

## Minimizing the sandbox's attack surface

In order of strength:

1. **Placement** (above): on the recommended isolated-network modes the
   socket does not exist for the sandbox. This is the only measure
   independent of operator mistakes. In host mode it does exist for the
   sandbox, and only the token stands in the way.
2. **Token auth** (above): covers host mode, the IA32 hole, and nosy
   same-uid host processes.
3. **Protocol discipline**, same as the existing parsers: strict
   request/response, length-capped lines (precedent: 8 KiB CONNECT
   header, 64 KiB ClientHello, and `line::read_line_limited`), no
   streaming *into* the socket, close on any malformed input (including
   non-UTF-8 and embedded NUL, which `read_line_limited` already rejects).
   The sandbox must never make `A` parse anything complex.
4. **Bind late / close in children (fd discipline).** `FD_CLOEXEC` only
   takes effect at `exec`, so `FS` and `P` — which never exec — would
   inherit and hold the control listener across `fork`, keeping the
   abstract name bound after `A` exits, and `S` would hold it until it
   execs COMMAND. Either bind the listener in `A` **after** every fork
   (in the serve loop), or explicitly close it in each child immediately
   after `fork`. The token fd, if any, follows the same rule.
5. **Audit every accepted control command** as a `policy-change` event.
   With the single-writer audit design (below), `A` emits the event
   itself when the child acks the apply (or immediately, for `A`-local
   changes) — no per-process emitters, and no event is written for a
   change a child rejected. The listener fd must be `CLOEXEC` so the
   exec'd COMMAND never inherits it.

---

## Who owns the socket: only `A`; propagation via socketpairs

Per-subprocess sockets were considered and rejected:

* **`P` cannot own a control socket, period.** `P` lives in the
  *sandbox's* network namespace — an abstract listener created by `P`
  would be **directly connectable by the sandboxed command**. A
  filesystem listener in `P` would sit in the host mount namespace but
  be exposable through mappings. And `P` is already the most exposed
  parser of untrusted input; it must not grow a second protocol.
* `FS` could technically own one, but N sockets mean N auth mechanisms,
  N lifecycles and N discovery problems.
* `A` is the natural hub: parent of both `FS` and `P`, always in the
  host network namespace, already runs a tokio runtime on the net path
  (the connector / waf host), and already holds one copy of the
  allow-list.

### The propagation channels

`A` pushes policy updates down **socketpairs created before the fork**
— the readiness-pipe pattern (`hostfs::start_host_fs`) extended from
one byte to messages:

* `socketpair(AF_UNIX, ...)` — one for `A`↔`FS`, one for `A`↔`P` (the
  latter only exists on the isolated-network path).
* **Framing: prefer `SOCK_STREAM` + the existing line reader over
  `SOCK_SEQPACKET`.** The stated reason for `SOCK_SEQPACKET` ("framing
  for free") does not survive contact with tokio: there is no native
  `SOCK_SEQPACKET` `UnixStream`, so a SEQPACKET channel needs an
  `AsyncFd<OwnedFd>` wrapper plus hand-rolled `recv` bounds on the child
  side, whereas `SOCK_STREAM` pairs work directly with
  `tokio::net::UnixStream` and the already-audited
  `line::read_line_limited` framing. These channels carry only trusted
  `A`↔child traffic, so newline-JSON is sufficient. (If SEQPACKET is
  kept for its message boundaries, document the `AsyncFd` requirement and
  the per-message cap explicitly.)
* The channel is **bidirectional**: `FS`/`P` send apply-acks or errors
  back, which the request/response API needs anyway ("did `fs-set`
  actually take effect?"), and — in the same upstream direction — their
  audit event stream (see *Audit: a single writer*).
* Each child registers its end into **its own** tokio runtime after the
  fork — consistent with the "no runtime across fork" rule; the fd is
  just an inherited number until then.
* **Unnamed = zero addressability:** nothing anywhere can connect to
  these channels; the minimal attack surface IPC can have.
* CLOEXEC on both ends matters especially for `P`'s end: `P` forks `S`,
  which execs COMMAND — COMMAND must not inherit the channel into `A`.

### Update semantics

* **Full replacement per domain**, never deltas: `fs-set` swaps the
  entire compiled pattern set in `FS`; `net-set` swaps the entire
  allow-list in `A` **and, on the proxy path, pushes it to `P`**. No
  delta-application ordering issues, and `spec-reload` degenerates to
  "recompile spec → verify immutable parts unchanged → push both
  domains".
* **Proxy vs. waf asymmetry.** Only the proxy path's `P` holds an
  allow-list (`proxy::serve_sandbox_proxy`); the waf path's `P` (DNS,
  HTTP, HTTPS frontends) forwards every decision to `A`'s host side and
  keeps no list of its own. So `net-set` pushes to `P` in proxy mode and
  to `A` only in waf mode.
* **Not retroactive to in-flight flows.** Both `A` and `P` clone the
  allow-list per accepted connection; a swap affects new connections,
  not already-established tunnels. State this in the API semantics.
* **A keeps the authoritative copy.** `A` currently only passes a
  `Patterns` clone into `start_host_fs` and never tracks later changes;
  for `policy-get` and rollback-on-reject, `A` must own the
  authoritative current mutable state (updated on each accepted
  `fs-set`/`net-set`, reverted if the child rejects the apply).
* **Graceful degradation per shape:** no `hostfs` mappings → `fs-set`
  answers "no FUSE filesystem in this run"; host network mode
  (`net.isolated == false`, empty allow-list) → `net-set` answers "not
  applicable"; waf mode → the `P` push is skipped.

### Overall shape

```
operator / future webui-bridge
   │  @ai-bubble-control-<hash(specdir)>  + token (first line)
   ▼
A ──socketpair──▶ FS   (swap pattern set; clear dir cache; ack)
 │ ◀─────────────┘     (FS audit events, upstream on the same pair)
 ├──socketpair──▶ P    (proxy path only: swap allow-list; ack)
 │ ◀─────────────┘     (P audit events, proxy mode)
 └── sole audit-log writer: own events + forwarded FS/P events
```

---

## Audit: a single writer through the control channels

**Current state (verified against the code).** The audit log already has
*multiple* writers — "only HostFS audits" is not accurate: `FS` records
hostfs ops (`hostfs/fuse_ops.rs`), `P` records proxy CONNECT results
(`proxy/sandbox.rs`), and `A` records connector and waf-host decisions
(`proxy/connector.rs`, `waf/host.rs`). `audit::configure` opens the log
eagerly before any fork; every process with a tokio runtime lazily
spawns its own mpsc → writer-task pipeline, `dup`s the inherited fd,
and appends ≤32 KiB `O_APPEND` chunks. The genuine coverage gaps are
the waf *in-sandbox frontends* in `P` (DNS/HTTP/HTTPS audit nothing of
their own — their decisions are forwarded to `A`, which audits) and the
non-isolated `A`, which cannot audit at all (no runtime).

**Why one writer.** Multi-writer works, but only through discipline that
must be re-imposed on every future writer: the ≤32 KiB single-write
chunk contract that keeps lines from tearing, the tolerated rotation
races (every writer rotates independently), and a log fd held open by
every child for its whole lifetime. Since the control design already
gives `A` a pre-fork, unnamed, bidirectional channel to each child,
audit events should ride the same channels upstream and leave `A` as
the **only process that ever writes the log file**:

* line integrity and rotation become structural, not conventional —
  one writer, one rotator, and the cross-process `O_APPEND` chunk-size
  reasoning disappears;
* children never hold the log fd: they close the inherited descriptor
  right after `fork` (same fd discipline as the control listener), so
  the log file leaves `FS`'s/`P`'s fd footprint entirely;
* per-channel FIFO order is preserved, and `ts`/`pid` are stamped by
  the *emitting* process, so the log keeps true origin and timing
  while gaining a natural per-source ordering;
* any future process that can hold a channel end can audit — no log
  fd, no rotation logic, no writer task of its own.

**Design.**

* **API unchanged.** `FS` and `P` keep calling `audit::record(...)`;
  only the sink changes. When the process inherited a channel fd, the
  writer task serializes the same JSON lines onto the channel (still
  batched, still suspend-on-full) instead of onto the file. When no
  channel exists, the legacy per-process file writer remains as the
  fallback (needed on the non-isolated path until phase 3).
* **Frame format.** Child→`A` frames on the socketpair are either
  control replies or audit records; keep them self-describing:
  `{ "ok": ... }` / `{ "err": ... }` for replies,
  `{ "audit": { "ts": ..., "pid": ..., "source": ..., "op": ...,
  "path": ..., "result": ..., "detail": ... } }` for events. `A`
  re-serializes the event fields into the log line **verbatim** — the
  child's `ts`/`pid` stand — and never inspects `path`/`detail` beyond
  the JSON decode and the channel's line cap. Oversized `detail` is
  truncated at the source so a serialized event always fits the cap.
* **`A`'s writer multiplexes.** A per-channel reader task feeds decoded
  events into the same bounded queue that `A`'s own connector/waf-host
  events use; the single writer task batches and appends as today. The
  reader tasks must never share a lock or an await point with the
  control-request handler — otherwise a full audit queue could
  backpressure a child exactly while `A` awaits its apply-ack.
* **Backpressure.** Semantics stay "never drop": a full channel
  suspends the child's `record` callers, just as a full mpsc suspends
  them today. The new failure mode is an `A`-side reader stall (hence
  the dedicated-task rule above). If a child dies, its channel EOFs
  and its undelivered events are lost — acceptable: the child is dead,
  and `A`'s own wait/heartbeat path records the death.
* **Drain/EOF.** A child's `drain()` flushes its queue into the channel
  and closes its end; `A`'s reader finishes at EOF; `A`'s final flush
  runs once the readers have ended (children exit before `A` in every
  shutdown path today).
* **When the pairs exist.** The socketpairs are created whenever the
  run has an audit log **or** control is enabled — they are run
  infrastructure, and `--control` only adds the external socket and
  the writable mount. A conditional single writer (multi-writer
  whenever control is off) would defeat the point. Until phase 3
  lands, the non-isolated path is the one exception: `A` has no
  runtime there, so `FS` keeps the legacy fallback writer on that
  path.
* **Policy-change events simplify.** The "audit every accepted control
  command" rule no longer needs each applying process to emit: `A`
  emits the `policy-change` event itself when the child acks (or when
  it applied the change locally), and the event is written only after
  the apply succeeded everywhere it had to — no half-applied lies in
  the log.

---

## Protocol sketch

Token as a **preamble line**, then JSON-lines commands on the same
connection (the previous sketch put the token in every command, which
contradicted the "first line" requirement and re-exposed the secret per
message; one preamble per connection is simpler and keeps the token out
of the JSON):

```
→ <hex token>\n
→ { "cmd": "policy-get" }
← { "ok": true, "fs": {...} | null, "net": {...} | null }

→ { "cmd": "fs-set", "mappings": [...] }
← { "ok": true }                     // after FS acked

→ { "cmd": "net-set", "allow": [...] }
← { "ok": true }                     // applied in A, after P acked (proxy mode)

→ { "cmd": "spec-reload" }
← { "ok": false, "err": "immutable section changed: seccomp" }
```

Requirements: strict request/response, a hard per-line length cap, and
close-on-malformed. Reuse `line::read_line_limited` for the framing.

A small CLI subcommand (`ai-bubble control ...`, with `--spec-dir` as the
existing pre-subcommand global option) that speaks this protocol doubles
as the reference client and the debugging tool.

---

## Enabling control

The plan previously said "when runtime control is enabled" without
defining the switch. Define it now:

* `ai-bubble run --control ...` turns control on for that run (default
  **off**). Off is the conservative default: it keeps the FUSE mirror
  read-only when the spec is all-`ro`, keeps the abstract socket
  unbound, and keeps the token file unwritten.
* When on, `A` binds the abstract socket, writes the token, and passes
  `read_only = false` to `mount_with_fallback`.
* A spec-file `control` field is a reasonable alternative (declarative,
  travels with the project) but is stricter to load/serialize; the CLI
  flag is the smaller first step. Decide before implementing phase 1.

---

## Implementation phases

1. **Control server in `A` + token auth + `policy-get`/`net-set`**
   end-to-end through the `A`→`P` socketpair on the proxy path
   (smallest slice that exercises the whole machinery: abstract socket,
   token, protocol, pre-fork socketpair, runtime registration in `P`,
   allow-list swap in both processes, ack, audit event). This requires
   introducing a shared allow-list type (`Arc<ArcSwap<Vec<String>>>` or
   `Arc<RwLock<Vec<String>>>`) in `proxy::serve_connector` /
   `serve_sandbox_proxy` / `waf::host::serve_host`. The same phase
   lands the audit plumbing: the `A`↔`P` pair is created whenever an
   audit log is configured, `A`'s reader tasks + multiplexed writer
   make it the sole log writer, `P`'s `"proxy"/"CONNECT"` events move
   onto the channel, and `P` closes the inherited log fd right after
   `fork`.
2. **`fs-set`**: shared `Patterns`, remove the open-handle `writable`
   cache (re-check per write), clear `dir_cache` on swap, the
   mount-writability change, `A`→`FS` socketpair + control task in the
   FUSE server's `serve` loop (select over the heartbeat and the
   channel). `FS`'s hostfs events move onto the pair (and `FS` closes
   the log fd); the legacy per-process writer survives only as the
   no-channel fallback.
3. **Non-isolated-path serving.** On the non-isolated path `A` is the
   `waitpid` supervisor inside `sandbox::pidns_and_exec` and runs no
   tokio runtime; today it cannot serve the control socket at all. Give
   `A`'s supervisor loop a runtime that selects over the control
   listener and the wait, mirroring the connector's `select!`. Without
   this, control works only on the isolated-network path. This is also
   what completes single-writer audit: until then, `FS` on the
   non-isolated path keeps the fallback writer.
4. **`spec-reload`** as sugar — the hardest phase, see below.
5. Optional sugar later: `ai-bubble audit --follow`, `SIGHUP` reload as
   a shim over `spec-reload`, the standalone web UI bridge.

### `spec-reload` is harder than it looks

Several current code paths make "re-read the spec and diff" non-trivial:

* **`die`-based compilation.** `SandboxConfig::compile` hard-dies on bad
  `env`/`cwd`/patterns (`Patterns::new` calls `die`). Reload needs a
  fallible compile (`try_compile`, `Patterns::try_new`) returning an
  error to the client instead of killing the launcher.
* **Preprocessing must be replayed.** `cli::run` mutates the parsed spec
  before compiling: waf mode appends the injected `/etc/resolv.conf` and
  CA-bundle mappings, and `prepare_caches` resolves `session-cache` /
  `project-cache` against backing directories. A naive re-read would
  diff a raw spec against a preprocessed one. Reload must replay the same
  preprocessing (idempotently) before comparing.
* **Diff over the compiled config, field by field.** `SandboxConfig` and
  its member types derive `PartialEq`, so compare the immutable fields
  (`ops`, `env`, `cwd`, `seccomp`, `rlimits`, `audit_log`, and the
  immutable `net` fields `isolated`/`mode`/`allow_private`/family gates)
  and error with the list of changed ones. Mutable fields are `patterns`
  and `net.allow`. Note the plan's earlier claim that seccomp "cannot
  even be read back" is wrong: `A` holds the compiled `SeccompPolicy`
  and can compare it — what it cannot do is change the installed filter.
* **Audit log path changes** would move where events go; treat as
  immutable (it is opened eagerly before any fork).

---

## Out of scope (for now)

Delta updates, multiple concurrent control connections with
subscriptions, streaming audit follow over the socket, web UI in the
core, per-run endpoints / client-side run selection.

---

## Revision notes

What changed from the previous revision, and why:

0. **The `fs-set` hazards 3.1–3.3 are now prepared in the code.**
   `HostFs.patterns` is a shared, runtime-swappable
   `hostfs::SharedPatterns` (cheap-clone `Arc`, full-replacement `set`,
   monotonically increasing generation — the API `control::fs_apply`
   already calls); every FUSE op loads the currently active set, the
   open-handle `writable` verdict cache is removed (`write` re-checks
   the current set per request, so `rw` → `ro` also stops an
   already-open handle), and the readdir `dir_cache` stamps entries with
   the policy generation, so a swap invalidates cached listings
   automatically. `start_host_fs`/`serve`/`mount_with_fallback` thread
   the shared handle through; `cli::run` creates it (the launcher keeps
   the authoritative instance). The mount's read-only decision still
   comes from the *initial* set (fuse3 has no remount). Covered by
   `hostfs::tests::pattern_swap_applies_to_open_handles_and_dir_cache`.
   Still missing for `fs-set`: the `A`→`FS` control channel in `FS`'s
   serve loop and the control-enabled writable-mount flag.

1. **"A is always in host namespaces" corrected to "host netns + host
   mount ns".** In the non-isolated path `A` unshares user/cgroup, UTS,
   IPC and PID before forking `S`. The abstract-socket argument only
   needs the network namespace, which holds.
2. **Added the non-isolated-path gap** (new phase 3): `A` is a blocking
   `waitpid` supervisor there and runs no runtime, so control cannot be
   served without restructuring it.
3. **Corrected the `net-set` propagation model:** only the proxy path's
   `P` holds an allow-list; waf's `P` does not. Added "not retroactive to
   in-flight flows" and "`A` keeps the authoritative mutable copy".
4. **Added the three `fs-set` correctness hazards** (shared `Patterns`,
   the open-handle `writable` cache — a real tightening bypass — and the
   stale `dir_cache`), plus the loss of the kernel read-only backstop.
5. **Fixed the token-file race:** bind before writing the token; never
   clobber on `EADDRINUSE`; remove on exit. Documented the token file's
   exposure in host mode.
6. **Replaced `SOCK_SEQPACKET` with `SOCK_STREAM` + `line.rs`** (tokio
   has no native SEQPACKET `UnixStream`; SEQPACKET needs `AsyncFd`), with
   the alternative documented.
7. **Resolved the token-in-protocol contradiction** (preamble line, not
   per-command field).
8. **Added fd-discipline rules** for the listener across `fork`/`exec`.
9. **Defined the enablement switch** (`run --control`, default off) and
   tied the FUSE read-write change to it.
10. **Expanded `spec-reload`** into the hardest phase: fallible compile,
    replay of waf/cache preprocessing, per-field immutable diff.
11. **Audit re-architected to a single writer.** The audit story did not
    fit the process structure: events now route upstream over the same
    pre-fork socketpairs used for control propagation, and `A` is the
    only log writer (new section *Audit: a single writer*; consequence
    4, attack-surface item 5, the propagation-channel bullets, the
    shape diagram and phases 1–3 updated to match). Corrected the
    factual record along the way: the log already had three writers
    (`FS`, `P` for proxy CONNECT, `A` for connector/waf-host) — the
    real gaps were the waf in-sandbox frontends and the runtime-less
    non-isolated `A`.
12. **Refreshed the stale `SOCK_SEQPACKET` mention** in the decisions
    list (superseded by revision note 6).
13. **The allow-list swap is prepared in the code.** The allow-list is
    now a shared, runtime-swappable `proxy::allowlist::SharedAllow`
    (cheap-clone `Arc<RwLock<Vec<String>>>` handle, full-replacement
    swap — the shape `control::net_apply` codes against): every accepted
    connection takes a snapshot in `serve_connector`,
    `serve_sandbox_proxy` and `waf::host::serve_host`, so a swap affects
    new connections only, never established tunnels or the raw pipes
    behind them. `netns::run` creates the handle on both the launcher
    side (the authoritative copy `A` serves from) and the P side (the
    in-sandbox proxy's copy). Covered by
    `proxy::allowlist::tests::swap_affects_new_connections_only`. Still
    missing for `net-set`: the `A`→`P` control channel in P's serve
    loop and the control-plane registration in `cli::run`.
14. **Phases 1–3 implemented** (the note above's "still missing" items
    included). What landed:
    * the `A`↔child socketpairs now carry the control plane
      bidirectionally: `{"upd": ...}` downstream, `{"ack":true}` /
      `{"err":...}` upstream, demultiplexed from audit events by the
      hub readers (an audit `Event` and a reply are distinguishable by
      shape). The child's channel fd is split into a read half (its
      control loop, in `FS`'s serve select and P's proxy select) and a
      mutex-shared write half (audit batches *and* replies — whole
      frames never interleave mid-line); this subsumes the old
      `spawn_channel_eof_watch`.
    * `cli::run` grew `--control` (default off): it registers the
      authoritative policy state, binds the abstract socket, writes the
      token and enables the IPC channels; `A` serves the control
      socket in its `select!` on the isolated path and — phase 3 — the
      non-isolated supervisor grew the runtime + hub branch (pty mode
      refuses `--control` instead of silently serving only while the
      relay idles). A `control` sub-command (`ai-bubble control
      --policy-get|--fs-set|--net-set`) is the reference client.
    * a control-enabled run mounts its FUSE mirror writable regardless
      of the initial set (`read_only = !control && !any_writable`).
    * enabling control also enables the audit channels on the
      non-isolated path (`ipc_channel_wanted` accepts "control needs
      the pair" even without a log), completing single-writer audit
      there too; hub readers tolerate a channel that exists only for
      the control plane (events dropped, replies still routed).
    * support work: `Patterns::try_new` (fallible compile),
      `spec::hostfs::patterns_from_mappings` (rejects unresolved cache
      mappings and relative redirect sources), `Serialize` for
      `Mapping`/`TmpfsPerms` (octal-string, so `perms` round-trips) —
      and a latent `Globs`/`Paths` deserializer bug fixed (its seq
      visitor demanded borrowed strings, failing every list-form glob
      from an owned `serde_json::Value`, which is exactly the `fs-set`
      validation path).
    * still open: phase 4 (`spec-reload`) and the optional sugar (audit
      `--follow`, SIGHUP shim, web bridge).
15. **Phase 4 and the core-side sugar implemented.** What landed:
    * `spec-reload` (phase 4): `Spec::try_load`/`SandboxConfig::try_compile`
      (fallible load + compile — `compile_seccomp` returns errors instead
      of dying, bad globs/env/cwd report to the client, `try_compile`
      does not re-register the rlimits), the preprocessing factored out
      of `cli::run` into `cli::preprocess_spec` so the reload replays
      *exactly* the run's preprocessing (same session-cache root, so a
      reload never rewrites the resolved redirects or resets the session
      cache), and `control::spec_reload_inner`: per-field immutable diff
      over the compiled configs (`ops`/`env`/`cwd`/`seccomp`/`rlimits`/
      `audit`/immutable `net` fields) that names every changed section,
      then full-replacement applies of the mutable domains — unchanged
      domains are not pushed, and a second-domain failure reverts the
      first, so the run is never left half-reloaded. The launcher keeps
      the authoritative compiled config (`control::Start::config`).
      Client side: `ai-bubble control --spec-reload`.
    * the SIGHUP shim: `control::reload_task` runs the same reload on
      `kill -HUP` (selected in both launchers' loops; inert — SIGHUP
      keeps its default terminate semantics — whenever `--control` is
      off).
    * `ai-bubble audit [--follow [--lines N]]`: the plan's "audit
      viewing needs no API" made real as sugar — the sub-command
      resolves the configured log path from the spec and tails it
      (rotation-aware by inode), no protocol involved.
    * still open: the standalone web UI bridge (out of the core's scope
      by design).
