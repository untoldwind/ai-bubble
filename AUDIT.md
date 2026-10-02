# Security audit — ai-bubble

Date: 2026-10-02
Scope: full source review of the sandbox-escape surface: `hostfs` FUSE mirror,
sandbox/namespace setup, seccomp, network proxy/waf layer, spec parsing, CLI,
audit subsystem. Method: static analysis (read-only review, no live
exploitation). Threat model: the sandboxed command is fully untrusted; the
spec file is trusted input from the operator (but lives inside the
partially-untrusted project directory).

> **Note on historical references.** Code comments throughout the repository
> refer to an earlier `AUDIT.md` (e.g. "AUDIT.md M3" in `src/sandbox.rs:1265`,
> "finding M4" in `src/hostfs/fuse_ops.rs:993`) that was not present in the
> repository. This document supersedes it; the IDs below are new and do not
> correspond to the old numbering. Code comments should be updated to point
> here when the fixes land.

## Severity legend

- **Critical/High** — direct containment breach or privilege escalation path.
- **Medium** — containment weakening under specific (but realistic)
  configurations, or a documented guarantee that does not hold.
- **Low** — hardening gaps, DoS, latent issues, documentation drift.

---

## High severity

### H1 — AF_UNIX seccomp gate bypassable via the upper 32 bits of the `domain` argument

> **✅ FIXED (2026-10-02).** The condition now compares only the low 32 bits
> (`SeccompCmpArgLen::Dword` in `src/sandbox.rs`), which closes the bypass in
> both blocklist and allowlist modes. Regression test:
> `unix_socket_denial_survives_garbage_upper_argument_bits` in
> `src/sandbox/tests.rs` (verified to fail against the old `Qword` code and
> pass with `Dword`). H2 remains open; the ia32 note in the "Suggested fix
> order" still applies to it.

**Files:** `src/sandbox.rs:1273-1317` (`apply_seccomp`), merged at
`src/spec/internal.rs:260-296`; default policy in `src/spec/net.rs:31-39`.

**What the code does.** In host-network mode with `unix_sockets: false` (the
default), protection against local-IPC escapes rests entirely on a seccomp
rule comparing argument 0 of `socket`/`socketpair` as a **full 64-bit value**:

```rust
let af_unix = libc::AF_UNIX as u64;
let cond = SeccompCondition::new(0, SeccompCmpArgLen::Qword, op, af_unix)
```

(seccompiler 0.5's BPF backend emits, for `Qword`+`Eq`, a `JEQ` on the
most-significant 32 bits — which must be 0 — *and* a `JEQ` on the
least-significant 32 bits. Both must match for the rule to fire.)

**Attack path.** The kernel's `sys_socket(int family, ...)` truncates the
register to a C `int`. A raw syscall with garbage in the upper 32 bits —
glibc's wrapper zero-extends, so the command must call `syscall(2)` directly,
which is trivial for untrusted code:

```c
syscall(SYS_socket, (long)AF_UNIX | (1L << 32), SOCK_STREAM, 0);
```

The filter's msb check fails (`0x1 != 0`), so the rule does not match:

- blocklist mode (default filter): mismatch action = **Allow**;
- allowlist mode with `socket` listed: the `Ne(AF_UNIX)` rule matches →
  **Allow**.

The kernel then sees `family == AF_UNIX` and creates the socket. Both `socket`
and `socketpair` are affected (`io_uring_setup` is denied unconditionally with
an empty rule vector, so it is **not** bypassable this way).

**Impact.** Reopens exactly the hole the mitigation was built to close: the
command connects to abstract-namespace sockets as the invoking user —
`@/run/dbus/system_bus_socket`, the session bus, `systemd --user` (transient
units run arbitrary host commands as the user), `@/tmp/.X11-unix/X0`
(keystroke injection into the user's session) — plus filesystem sockets under
any mapped `/run`. The README claims this hole is closed
(`README.md:357-362`, `527-539`); it is not.

**Fix.** Compare only the low 32 bits:

```rust
SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, af_unix)
```

(Dword comparisons in seccomp BPF operate on the low half of the argument
word; the high half is ignored by the kernel's ABI for `int` arguments
anyway.) Alternatively keep Qword but add a companion rule that denies
`arg0_hi32 != 0` for these syscalls. Add a regression test that issues
`syscall(SYS_socket, 0x1_0000_0001, SOCK_STREAM, 0)` under the filter and
expects `EPERM`/`EAFNOSUPPORT`.

---

### H2 — ia32 `int $0x80` socketcall bypass of the same mitigation

> **✅ MITIGATED via documentation (2026-10-02).** Fix options 1 and 2 are
> not implementable: option 1 denies x86_64 `getuid` (unacceptable), and
> option 2 — an arch-keyed filter entry — is what seccompiler already
> emits; the arch check passes because `int $0x80` from a 64-bit process
> still reports `AUDIT_ARCH_X86_64`. Only option 3 applies. Done:
> - `README.md` "Unix-domain sockets" section now carries a loud
>   ⚠️ "Best-effort on kernels with IA32 emulation" callout, and the
>   host-network-mode warning at the top is softened accordingly
>   ("closes ... **on kernels without IA32 emulation**; not a security
>   boundary; prefer proxy/waf for untrusted commands").
> - The known-limitation note in `src/spec/seccomp.rs` (module docs) now
>   states explicitly that for the AF_UNIX gate the ia32 hole is an
>   immediate breakout, not merely attack-surface exposure, and why no
>   seccomp rule can close it.
> - The gate comment in `src/sandbox.rs` `apply_seccomp` documents the
>   residual and points here.
>
> No filter-only fix exists; the honest statement stands: on
> `CONFIG_IA32_EMULATION` kernels the AF_UNIX gate is best-effort and
> host-network mode must be treated as full local IPC for untrusted
> commands.

**File:** `src/spec/seccomp.rs:56-69` (known-limitation note), filter build in
`src/sandbox.rs:1273-1317`.

**Attack path.** On x86-64 kernels with `CONFIG_IA32_EMULATION` (the common
distro default), `int $0x80` executed from a 64-bit process keeps
`AUDIT_ARCH_X86_64` — so seccompiler's architecture check passes — while the
syscall *number* is taken from the ia32 table. ia32 `socketcall` is syscall
102, which the filter interprets as x86-64 syscall 102 (`getuid`, not gated).
The kernel dispatches `socket(AF_UNIX, …)` through the socketcall
multiplexer. Result: AF_UNIX sockets despite the filter, in both blocklist
and allowlist modes, with no seccomp rule able to distinguish the case
(because the *number* is ambiguous, not the arguments).

**Impact.** Same as H1. The existing doc note frames the ia32 hole as
"kernel attack-surface exposure … not an immediate breakout"; for the AF_UNIX
gate it **is** an immediate breakout. Unlike H1, this requires
`CONFIG_IA32_EMULATION`.

**Fix options (pick one or more):**

1. Add an explicit rule denying the ia32 `socketcall` number (102) — with the
   caveat that this also denies x86-64 `getuid`, which is unacceptable in
   practice, so this alone does not work.
2. Set `PR_SET_NO_NEW_PRIVS` is already set; the reliable fix is to also
   install a filter entry keyed on the *x86* arch (seccomp filters can match
   `seccomp_data.arch`): deny any syscall whose `arch != AUDIT_ARCH_X86_64`.
   seccompiler supports this via its arch validation; verify the generated
   BPF actually kills rather than skips on arch mismatch.
3. Document loudly, next to `unix_sockets` in the README, that the mitigation
   is best-effort on kernels with IA32 emulation, and recommend proxy/waf
   mode for untrusted commands.

Combined with H1, the honest interim statement is: **the AF_UNIX gate is
currently not a security boundary**; operators must treat host-network mode
as full local IPC until fixed.

---

### H3 — `create()`/`mkdir()` keep setuid/setgid bits (setuid-root planting when run as root)

> **✅ FIXED (2026-10-02).** Both creation paths now mask the mode with
> `SAFE_MODE` (`0o7777 & !0o6000`), the same mask the `setattr` chmod
> path already applied. Regression tests:
> `create_strips_setuid_and_setgid_bits` (fails against the old
> `0o7777` mask on tmpfs — the kernel honors the setuid bit on
> `open(O_CREAT)`) and `mkdir_strips_setuid_and_setgid_bits` in
> `src/hostfs/tests.rs` (defense-in-depth: whether the kernel strips
> the bits anyway is fs-dependent).

**Files:** `src/hostfs/fuse_ops.rs:1620-1625` (`create`, O_CREAT|O_EXCL path),
`src/hostfs/fuse_ops.rs:1103-1109` (`mkdir`). Contrast with the chmod path at
`src/hostfs/fuse_ops.rs:1002-1008`.

**What the code does.** `create` passes the mode straight through with only a
`0o7777` mask:

```rust
anchored::open_at(&self.root, &real, oflags, (mode & 0o7777) as libc::mode_t)
```

`0o7777` **keeps** `0o6000` (setuid/setgid). `mkdir` does the same. The
kernel honors setuid bits in the `open(O_CREAT)` mode (umask only masks
`0777`; `inode_init_owner` clears S_ISGID only for group non-members, and
never S_ISUID).

The sibling `setattr(chmod)` path already strips them:

```rust
let mode = (mode & 0o7777 & !0o6000) as libc::mode_t;
```

with a comment explicitly acknowledging "ai-bubble may legitimately run
elevated (root in a container), and then a mode like 0o4755 through the
mirror would plant dangerous privilege bits on the host".

**Attack path.** The sandboxed command runs
`open("/rw-mapped/dir/helper", O_CREAT|O_WRONLY, 04755)` and writes a payload
binary. The FUSE server creates it **with the invoking user's uid** and the
setuid bit set. Then:

- ai-bubble runs as an ordinary user → setuid-to-self, inert;
- ai-bubble runs as **root** (e.g. in a container) → a **setuid-root binary**
  now sits in an rw-mapped host directory. With a `project-cache` mapping it
  persists across runs in `.ai-bubble/cache/` (hidden from the sandbox but
  visible to the host); any later host-side execution is a root escalation.

**Fix.** Apply the same mask in both places:

```rust
const SAFE_MODE: libc::mode_t = 0o7777 & !0o6000;
// create:  anchored::open_at(&self.root, &real, oflags, (mode & SAFE_MODE) as libc::mode_t)
// mkdir:   same mask on its mode argument
```

Add tests: `create` with mode `0o4755` must yield a `0o755` host file;
`mkdir` with `0o2755` must yield `0o755`.

---

### H4 — Audit log can be swapped for a symlink/FIFO by the sandboxed command

> **✅ FIXED (2026-10-02).** Implemented exactly the fixes below (1, 2 and 4;
> 3 is documented as the residual):
> - `configure()` now opens the log **eagerly** — before the sandbox and any
>   untrusted code exist — through `safe_open()` (`O_CREAT|O_APPEND` plus
>   `O_NOFOLLOW` and `O_NONBLOCK`), rejects non-regular files via a
>   post-open `fstat` (`S_ISREG` or die), and retains the `File` in a
>   static. The writer (and each forked process, via `try_clone`) appends
>   through that descriptor and never opens the path again.
> - `validate_path` now returns the canonicalized path (symlinks resolved,
>   `..` collapsed), which is what gets opened and rotated — so a
>   symlinked configured path keeps working while nothing is ever followed
>   at open time.
> - Rotation still renames the path and opens a fresh file, but every
>   re-open goes through `safe_open`; on failure the writer keeps
>   appending to the descriptor it already holds, which the sandbox cannot
>   touch. This closes both attack variants: a pre-existing (or
>   rename-planted) symlink is refused at startup instead of being
>   followed, and a FIFO refuses to open (no writer hang, no
>   channel-fill/sandbox-wide deadlock).
> - Residual (documented in the module docs of `src/audit/mod.rs`): an
>   audit log placed inside a *sandbox-writable* mapped directory can
>   still be appended/truncated/filled by the command through the mirror —
>   the eager open protects the writer's descriptor, not the file's
>   integrity. Recommendation stands: keep the audit log inside the spec
>   directory, which the sandbox never sees.
> - Regression tests: `safe_open_refuses_a_fifo`,
>   `safe_open_refuses_a_symlink`, `rotation_does_not_follow_a_swapped_in_fifo`
>   in `src/audit/tests` (`src/audit/mod.rs`).

**Files:** `src/audit/mod.rs:101-149` (`configure`/`validate_path`),
`src/audit/mod.rs:239-253` (writer open), rotation re-open at
`src/audit/mod.rs:352-360`.

**What the code does.** The path is validated **once, at startup, by
time-of-check**: outside the spec dir, the file merely has to exist
(`validate_path`, lines 137-140). The file itself is opened **lazily** — on
the first recorded event, in `setup()` (lines 180-185) → `writer`
(lines 242-247) — by path, **following symlinks**:

```rust
std::fs::OpenOptions::new().create(true).append(true).open(&open_path)
```

No `O_NOFOLLOW`, no retained fd, and rotation re-opens the path the same way
mid-run. The race window is the entire lifetime of the run.

**Attack path.** Configuration: `{"type": "rw", "glob": "/work"}` plus
`"audit": {"log": "/work/audit.log"}` (after `touch /work/audit.log`) passes
validation.

1. The sandbox cannot *create* symlinks through the FUSE mirror (`symlink` is
   hard-denied, `fuse_ops.rs:1369-1387`) — but it **can `rename` any
   pre-existing host symlink** that sits anywhere inside the rw-mapped tree
   (mirrored symlinks are *visible*, only following them is denied; `rename`
   within a writable mapping is allowed). Home/project directories almost
   always contain some symlink.
2. `mv audit.log x && mv /some/existing/symlink audit.log`.
3. The next flush appends attacker-influenced JSON lines to the symlink's
   target with the **operator's uid**. serde_json escaping preserves JSON
   integrity, but content injection into a file later *interpreted* by the
   operator (e.g. `~/.bashrc`: `$( )` still expands inside double quotes when
   bash reads the file) is dangerous even as valid JSON.
4. FIFO variant: rename a host FIFO onto the path → the writer's blocking
   `open` hangs forever in `spawn_blocking` → the 65536-event channel fills →
   every FUSE op suspends in `record().await` (lines 166-174) → sandbox-wide
   deadlock plus unbounded suspended-task accumulation.

**Fix.**

1. Open the log **eagerly in `configure()`** (fail at startup, before the
   sandbox exists), with `O_NOFOLLOW` in addition to `O_CREAT|O_APPEND`:
   `OpenOptions::new().create(true).append(true).custom_flags(libc::O_NOFOLLOW)`.
2. Retain the `File` (in a `OnceLock<Arc<Mutex<File>>>` or similar) and pass
   it to the writer instead of the path; rotation must rotate by renaming the
   path and opening a *new* file with the same flags — never re-open the
   attacker-influenceable path blindly.
3. Reject (at validation time) audit paths that resolve into any rw-mapped
   directory — or at minimum document that an audit log in sandbox-writable
   territory is unsafe. The strongest guarantee remains: keep the log inside
   the spec dir (which is hidden from the sandbox).
4. Refuse to open non-regular files (`fstat` after open: `S_ISREG` or die) —
   closes the FIFO-hang variant even if the path check is bypassed.

---

## Medium severity

### M1 — `setattr` on the FUSE root inode operates on the host `/` directory

> **✅ FIXED (2026-10-02).** The mirror root is now treated as the synthetic
> inode it is (like `getattr` already did) in all three audited ops:
> - `setattr` refuses the root unconditionally with `EACCES` — its parent
>   anchor is the pinned host-root directory with the name `.`, and a
>   chmod/chown/utimens there would operate on the host `/`.
> - `access` answers the root from policy instead of `faccessat` on the
>   host root: `W_OK` follows `patterns.writable("/")`, `R_OK`/`X_OK` are
>   inherent to the synthetic root (it is always listable/navigable —
>   `chdir` into the sandbox root keeps working, preserving the earlier
>   C1 regression fix).
> - `statfs` returns the same minimal, self-consistent statfs as virtual
>   paths (factored into `minimal_statfs()`) instead of `fstatvfs` on the
>   host `/` — the host root's total/free space and filesystem type no
>   longer leak into the sandbox.
>
> Regression tests in `src/hostfs/tests.rs`:
> `setattr_on_the_root_inode_is_refused` (with a `rw /**` spec, failing
> against the old code which reached the host root),
> `access_write_on_the_root_inode_follows_the_policy`,
> `statfs_on_the_root_inode_reports_the_synthetic_statfs`; the existing
> root-access test was updated to the policy-based semantics and renamed
> to `access_on_the_root_inode_is_answered_by_policy`.

**Files:** `src/hostfs/anchored.rs:167-183` (`anchor_parent("/")` returns the
pinned host-root descriptor with name `"."`), `src/hostfs/fuse_ops.rs:952-1056`
(`setattr`).

**What happens.** `setattr` requires only `patterns.writable("/")`. A glob of
`/**` matches `/` (verified in the matcher: zero-component consumption), so a
spec like `{ "type": "rw", "glob": "/**" }` — exactly the spec used by the
project's own test at `patterns.rs:666` — makes the mirror root writable.
Then `chmod("/", …)` inside the sandbox passes `notify_change` (the FUSE
root's `i_uid` is the server's uid, which equals the sandbox's mapped kuid)
and executes `fchmodat(host_root_fd, ".", mode, AT_SYMLINK_NOFOLLOW)` against
the **host `/`** with the invoking user's credentials. Same for `utimensat`
and `fchownat` on `"."`.

**Impact.** Non-root invoker: every variant fails with EPERM (host `/` is
root-owned) — nil. Root invoker: the sandbox can chmod/chown/utimens the host
root directory. The `anchor_parent` comment anticipates that "creation ops
fail closed" for `"."`, but the *metadata* ops in `setattr` succeed.

**Fix.** Special-case the mirror root in `setattr` (and audit `statfs` /
`access` for the same shape) the way `getattr` already does
(`fuse_ops.rs:230-234`): if `mirrored == Path::new("/")`, return `EACCES` (or
`EPERM`) without touching the anchor.

---

### M2 — waf mode does not close HTTP-level domain fronting (README overclaims)

> **✅ FIXED (2026-10-02).** Fix option 1 (for HTTPS) and option 2 (for HTTP)
> are both implemented:
> - `src/waf/https.rs`: the decrypted plaintext is no longer a raw
>   `copy_bidirectional` pipe. The TLS stream is served by hyper's HTTP/1
>   server, and every request goes through `handle_request`:
>   `host_header_matches` parses the `Host` header as an authority and
>   requires its host part to equal the SNI (case-insensitive, port
>   ignored — routing is by name, and the upstream is dialed at
>   `SNI:443` regardless). A mismatch gets a 400 and is never forwarded.
>   The request is then rewritten to origin-form with the dialed
>   authority as `Host` (`insert`, not `or_insert`) and replayed through
>   the host's `tls-connect` as before.
> - `src/waf/http.rs`: the `Host` header of forwarded requests is now
>   always set (`insert`) to the URI authority that was dialed and
>   allow-listed — an attacker-supplied `Host` can no longer survive.
> - `README.md`: the waf-mode claim now says both layers are closed
>   (TLS SNI allow-list + per-request `Host == SNI` check and `Host`
>   rewrite), matching reality.
>
> Regression tests:
> - `src/waf/https.rs`: `host_header_must_match_the_sni` (matching forms
>   incl. `:443` and case variants; fronting, prefix/suffix look-alikes,
>   subdomain, missing/malformed `Host` all refused) and an extended
>   `end_to_end_mitm` (a genuine request is replayed with origin-form
>   request line and `Host: <sni>`; an SNI `example.com` / `Host:
>   evil.example` request gets a 400 and never reaches the upstream).
> - `src/waf/http.rs`: `end_to_end_http_proxy` now echoes the request
>   head back and asserts the replayed `Host` is always the dialed
>   authority — including for a request that supplied
>   `Host: evil.example` (must not survive).

**Files:** `README.md:617-622` (claim), `src/waf/https.rs:110-117`,
`src/waf/http.rs:135`, `src/waf/host.rs:194-221`.

**What the code does.** TLS-level fronting **is** closed: the HTTPS frontend
dials `tls-connect <sni>:443` — the dialed host is the SNI by construction —
and the host side builds the upstream `ServerName` from that same dialed
host, so upstream SNI and certificate verification always match the
allow-listed target; port 443 is hard-coded and the allow-list port check
applies.

HTTP-level fronting is **not** closed: after MITM, `handle_tls` ends in
`copy_bidirectional(&mut tls, &mut upstream)` — a raw pipe. The decrypted
`Host:` header is never compared against the SNI.

**Attack path.** Sandbox opens TLS to `127.0.0.2:443` with SNI
`allowed-cdn.com`, completes the handshake with the forged cert, then sends
`GET / HTTP/1.1\r\nHost: evil.com\r\n`. The host pipes it verbatim to
`allowed-cdn.com:443`, and shared infrastructure routes the request to
`evil.com`. Same capability proxy mode has — but the README states the waf
mode "exists precisely to close" this. Related: the HTTP :80 frontend
preserves a mismatching original `Host` header when the absolute-form URI
authority was used for dialing (`parts.headers.entry(HOST).or_insert(host)`,
`http.rs:135`) — `or_insert` does not overwrite an attacker-supplied `Host`.

**Fix options.**

1. Parse the decrypted HTTP in `https.rs` (hyper server-side) and enforce
   `Host == SNI` on every request before forwarding — turn the pipe into a
   request-level proxy. This is the only fix that makes the README claim true.
2. In `http.rs`, always set the `Host` header to the dialed authority
   (`insert`, not `or_insert`).
3. Until (1) lands, soften the README: waf closes TLS-layer fronting only.

Impact is limited to CDN/shared-IP targets, but it is exactly the class waf
mode advertises as fixed.

---

### M3 — Host-net mode leaves other dangerous socket address families open

> **✅ FIXED (2026-10-02).** Fix option 1 is implemented: the default
> socket gate in `apply_seccomp` (`src/sandbox.rs`) now denies
> `AF_NETLINK`, `AF_VSOCK` and `AF_BLUETOOTH` in addition to `AF_UNIX`,
> each via a Dword comparison (H1's fix applies to every gated family).
> Opt-ins mirroring `unix_sockets` were added to the spec's host mode:
> `net.host.netlink`, `net.host.vsock`, `net.host.bluetooth` (all default
> `false`; `src/spec/net.rs`), carried through the compiled policy as a
> `SocketGate` (`src/spec/internal.rs`). In allowlist mode, a listed
> `socket`/`socketpair` is narrowed to "none of the gated families"
> (conditions ANDed inside one rule); in blocklist mode the per-family
> `Eq` rules are ORed. `AF_INET`/`AF_INET6` stay ungated (the point of
> host mode); the ia32 `socketcall` residual (H2) now applies to all
> gated families and is documented as such. Regression tests:
> `dangerous_families_are_denied_unless_opted_in` and
> `socket_gate_narrows_an_allowlist_for_every_dangerous_family` in
> `src/sandbox/tests.rs`, plus spec-parsing coverage in
> `src/spec/net.rs`. Fix option 2 is likewise done: the README's
> "Unix-domain sockets" section now documents all four flags, the
> residual surface (`AF_INET`/`AF_INET6` loopback reachability by
> design, `AF_PACKET` blocked by `CAP_NET_RAW`), and the IA32 caveat.

**Files:** `src/sandbox.rs:1273-1317`, `src/spec/net.rs:30-39`.

**What happens.** The `unix_sockets` filter gates `socket`/`socketpair` on
`domain == AF_UNIX` only (modulo H1/H2). Verified status of the other
families in host-network mode:

- **AF_INET / AF_INET6 loopback** — reachable by design: services bound on
  host `127.0.0.1`/`::1` (dev servers, databases, docker-over-TCP) are fully
  reachable. Documented meaning of host mode, but the `unix_sockets`
  mitigation does nothing for it and operators may over-trust the flag.
- **AF_NETLINK** — *not blocked*; `socket(AF_NETLINK, …)` needs no
  capability. `NETLINK_ROUTE`/`NETLINK_SOCK_DIAG` hand the command the host's
  network state and unix-socket inventory (reconnaissance); the netlink
  surface is also a recurring kernel-CVE area. Privileged operations fail
  (need `CAP_NET_ADMIN` in the *init* userns).
- **AF_VSOCK** — *not blocked*; creation is unprivileged and vsock is **not**
  network-namespaced. On VMs the command can connect to host/hypervisor
  vsock services (e.g. CID 2).
- **AF_BLUETOOTH** and other families — creatable; usable to the extent the
  stack allows unprivileged.
- **AF_PACKET** — correctly blocked: raw and cooked packet sockets require
  `CAP_NET_RAW` in the user namespace owning the (host) netns; the command's
  capabilities were only ever valid in its child userns and are dropped
  anyway.

**Fix options.**

1. Extend the default denial to `AF_NETLINK`, `AF_VSOCK`, `AF_BLUETOOTH`
   (Dword comparison — see H1), with opt-ins mirroring `unix_sockets`
   (`net.host.netlink: true`, ...). `AF_INET`/`AF_INET6` must stay (that is
   the point of host mode).
2. At minimum, document the residual surface next to `unix_sockets` in the
   README.

---

### M4 — No default resource limits; fork-bomb/DoS runs against the host user's budgets

**Files:** `src/spec/rlimits.rs:16-21, 54-67, 89-98`; applied at
`src/sandbox.rs:97-118`; `ARCHITECTURE.md:157-159`.

**What happens.** `nproc`, `nofile` and `as` are all optional and default to
*unset*; no cgroup controllers are created ("There is no cgroup-based
resource limiting"). The command's real uid is the host user's uid, so a fork
bomb inside the sandbox consumes the caller's global per-uid process count
(typically ~63k) and CPU; `tmpfs` mappings without `size` can each grow to
half of RAM.

The comment at `rlimits.rs:28-29` ("complementing the RLIMIT_NPROC the kernel
already enforces inside the user namespace") is misleading: post-5.11 ucounts
give the userns its own counter, but the enforced limit is the one inherited
from the caller — no practical brake. The P/FS/connector frontends are
individually capped (`connlimit.rs`, header timeouts, keygen token bucket in
`waf/host.rs:255-310`); the exec'd command tree is not.

**Fix.**

1. Ship conservative defaults in the `init` starter spec (`cli/init.rs`),
   e.g. `rlimits: { "nproc": 1024, "nofile": 4096 }`, and a `size` on the
   starter `/tmp` tmpfs mapping.
2. Correct the `rlimits.rs` comment.
3. Consider a built-in floor (e.g. never allow `nproc` above some fraction of
   the inherited limit without an explicit spec key) — optional; spec opt-in
   is acceptable if the starter spec leads by example.

---

### M5 — `link()` lets the sandbox clone host symlinks into writable host directories

**File:** `src/hostfs/fuse_ops.rs:1467-1492`.

**What happens.** When the `link()` source is a host symlink, the server
re-creates it on the host with `symlinkat(target, new_dir, new_name)` using
the server's credentials. The target string is copied verbatim from an
existing symlink at a writable mirrored path — it cannot be made arbitrary —
and symlinks are inert inside the mirror (never followed). But it is a real
symlink creation on the host at any writable mapped location, and it
partially defeats the otherwise-absolute "the sandbox can never create
symlinks" property (`symlink` is unconditionally EACCES,
`fuse_ops.rs:1369-1387`).

**Impact.** Low for a non-root server (the invoking user could create those
links anyway); wider when the server runs as root (symlink planted in
root-owned rw-mapped directories, pointing into locations processed later by
root tooling). It also interacts with H4: it is one more way to place a
symlink at a chosen writable spot (though H4's rename-based variant needs no
`link()` at all).

**Fix.** In `link()`, when `lstat` shows the source is a symlink, return
`EACCES` (matching the `symlink` op's denial style) instead of the
`symlinkat` fallback; hard links to regular files are unaffected. If
preserving link-of-symlink is desired for compatibility, document it as a
deliberate exception to the no-symlink-creation invariant.

---

### M6 — `validate_sources` rejects bind/redirect sources that *cover* the spec dir, but not sources strictly *inside* it

**File:** `src/spec/file.rs:324-354`.

**What happens.** The check is one-directional:

```rust
if spec_dir.starts_with(&source) {   // source == spec_dir or an ancestor
    return Err(...);
}
```

A source that is a **descendant** of the spec dir passes:

```json
{ "type": "redirect-rw", "dest": "/loot", "source": "spec.json" }
{ "type": "bind", "src": "/repo/.ai-bubble/env", "rw": true }
```

(`resolve_relative_sources` resolves `"spec.json"` to `<spec_dir>/spec.json`;
`spec_dir.starts_with(source)` is false for a descendant.) Because bind
mounts and redirect sources "resolve the host path directly, without
consulting the pattern list" (see the doc comment on `hide_spec_dir`,
`spec/file.rs:266-273`), the guaranteed auto-hide has **no effect** on them.

**Impact.** The sandbox reads the env file (secrets) and — with
`redirect-rw` / `rw: true` — rewrites `spec.json`, escalating the policy
persistently across runs: exactly the scenario the function's own comment
says must be prevented. The descendant case is deliberately unchecked only
for `project-cache` (backing store `cache/` is the intended location); raw
redirect/bind sources pointing at `spec.json`, the env file, or other
siblings are an oversight. Trusted-spec caveat applies (a malicious spec can
do worse), but this breaks the documented invariant that spec dir contents
"can never be exposed".

**Fix.** Extend the rejection to sources *inside* the spec dir:

```rust
if spec_dir.starts_with(&source) || source.starts_with(&spec_dir) {
    // ... allow only paths under spec_dir/cache/ (the project-cache backing)
}
```

Keep the `cache/` carve-out consistent with `project-cache`'s own validation.

---

## Low severity

### L1 — PDEATHSIG race check is ineffective exactly in the sandboxed child

**File:** `src/sandbox.rs:278-295` (`handle_die_with_parent`) vs. fork at
`sandbox.rs:482-490`.

The fork→prctl race guard (`getppid() == 1 → die`) cannot fire in
`pidns_and_exec`'s child: it is the first process of the new PID namespace,
its parent lives outside the namespace, so `getppid()` returns **0**, never 1
(the code comment acknowledges this). If the launcher (host mode) or P (net
mode) is SIGKILLed inside the fork→prctl window, the command re-parents to
host init, arms PDEATHSIG against init, and lingers unsupervised. Still fully
confined (chroot, no caps, pidns); in hostfs-root mode the FUSE server exits
when its watched PID dies (`server.rs:173`), pulling the root fs out — but in
tmpfs-root mode the command runs indefinitely with no supervisor.
**Fix:** in the PID-1 child, additionally verify the *sandbox-side* parent
liveness by another channel (e.g. a pipe held by the supervisor whose EOF
triggers exit), or accept and document the residual.

### L2 — pty relay: signal handlers never restored; forwarded signals dropped by pidns-init

**File:** `src/pty.rs:226-267`.

Custom handlers for SIGINT/SIGQUIT/SIGTERM/SIGHUP/SIGWINCH are never
restored. On the `RelayEnd::Signal` path (lines 250-265) the relay forwards
the signal to the command — but the command is PID 1 of its pidns and the
kernel silently drops non-SIGKILL/SIGSTOP signals for which pidns-init has no
handler: `ai-bubble run sleep 1000` drops SIGINT/SIGTERM. The subsequent
`waitpid` cannot be interrupted (terminal restored to cooked mode; the
leftover handler swallows SIGINT with `PIPE_W == -1`). Only `kill -9`
recovers. Same on the `MasterClosed` path with a command that closes fds
0/1/2 but keeps running. **Fix:** restore `SIG_DFL` for the five signals when
the relay ends (before the bare `waitpid` loop), or keep the relay alive
until the child exits so forwarded signals keep a live channel.

### L3 — Terminal escape-sequence passthrough is undocumented

**File:** `src/pty.rs:377-402` (master → fd 1 verbatim copy).

The relay writes untrusted command output to the user's real terminal
unfiltered: OSC 52 (clipboard write), title/palette changes, and
terminal-emulator escape-parsing CVEs all pass through. This matches `ssh` to
an untrusted host / `script(1)`, so it is arguably accepted — but unlike the
thorough TIOCSTI analysis, the escape-sequence risk is not mentioned in
`pty.rs` or the README. **Fix:** document it (pty mode and plain new-session
mode with a tty on stdout are both affected).

### L4 — Control-character injection into the host socket protocol (latent)

**Files:** `src/waf/https.rs:295` (SNI byte filter),
`src/waf/dns.rs:151` (qname → `resolve-dns` line), consumer
`src/waf/host.rs:80-248`, validator `host.rs:313-320`.

Two untrusted-name paths put attacker bytes verbatim into command lines on
the host socket: the SNI filter allows `\n`/`\r`/space/`:` (it excludes only
NUL and backslash), and `simple-dns 0.12`'s `Label` Display is
`String::from_utf8_lossy` with no escaping — a query label containing `0x0a`
produces `resolve-dns <prefix>\n<injected>`. **Currently neutralized**:
`handle_host_conn` reads exactly one line per connection, and the
`tls-cert`-before-`tls-connect` ordering makes crafted first lines fail.
This is accidental robustness: `valid_name` itself does not reject control
characters, so any future multi-command-per-connection change turns this into
host-side command injection (bounded by the allow-list).
**Fix:** reject `b < 0x21 || b == 0x7f` in the SNI filter and in
`valid_name`, or escape qname labels before interpolation.

### L5 — ipfilter range-completeness gaps

**File:** `src/proxy/ipfilter.rs`.

Core properties hold: loopback, RFC1918, CGNAT 100.64/10, link-local
(incl. 169.254.169.254), v4-mapped `::ffff:x`, 6to4, NAT64 WKP, ULA,
multicast, doc ranges are blocked; the dial is pinned to the validated IP
(`connect_checked`, lines 152-172), closing the resolve→connect TOCTOU and
DNS-rebinding window; `filter_addrs` fails closed when everything is blocked.
Gaps, all marginal: v4-**translated** `::ffff:0:0/96` (the embedded-v4 check
at line 81 requires `s[..5]==[0;5] && s[5]==0xffff`), NAT64 local-use
`64:ff9b:1::/48`, Teredo `2001::/32`, `192.88.99.0/24`, `192.0.0.0/24`,
`192.31.196.0/24`, `192.52.193.0/24`, `192.175.48.0/24` (AS112). None reach
loopback/metadata/LAN on a normal host.
**Fix:** extend `is_public` to the full IANA special-purpose registry, or
switch to a maintained crate for the range table.

### L6 — Connector socket reachable beyond P (no SO_PEERCRED); a `/tmp` hostfs bind exposes it to the command

**Files:** `src/netns.rs:27-54, 336-341`; socket dir creation
`src/sandbox.rs:45-53`.

The socket dir is `mkdtemp` (mode 0700, unpredictable, atomic — no `/tmp`
symlink race), but **any host process of the invoking user** can connect and
issue commands; there is no `SO_PEERCRED` check. The allow-list + ipfilter
still gate everything, so a same-uid process gains nothing it cannot do
directly. More notable: the sandbox uid 65535 is the *owner* of the socket
directory through the userns map, and the only thing preventing the command
from speaking the raw protocol is that the directory is never mounted into
the sandbox — a spec bind-mounting host `/tmp` gives the command direct
socket access as the owning uid. Impact remains bounded (every command is
re-authorized host-side, `host.rs:92,103,140,186`; the raw protocol offers
nothing the frontends don't), but the "cannot reach the connector at all"
claim is conditional on the mount table, not enforced.
**Fix:** add the anticipated `SO_PEERCRED` check (accept only P's uid/pid
family), or at minimum note the mount-table dependency where `unix_sockets`
is documented.

### L7 — Privileged FUSE mount fallback lacks `MS_NODEV`/`MS_NOSUID`

**File:** `src/hostfs/server.rs:224-233`.

Only `uid/gid/rootmode/read_only/allow_other(false)/nonempty(true)` are set.
The unprivileged `fusermount3` route forces `nosuid,nodev` itself; the
root-only fallback `Session::new(...).mount(...)` does not. Consequences: a
mirrored device node is opened by the kernel's device layer directly (the
ro/rw model still gates it via the `access` op, but IO bypasses the mirror),
and setuid execution from the mirror is defused only by the user namespace.
**Fix:** add `.nodev(true).nosuid(true)` to the fallback options for parity.
(`default_permissions` must stay off — it would break the uid-translation
model; the per-op checks in `fuse_ops.rs` are the only gate, and they held up
in review.)

### L8 — No upstream dial timeout; connector slots holdable for minutes

**Files:** `src/proxy/ipfilter.rs:152-172` (`connect_checked`), TLS handshake
in `src/waf/host.rs:221`.

A firewalled-but-allowed IP holds each of the host connector's 256
`ConnLimit` slots for the kernel's full SYN-retry duration (~2 min); churning
keeps networking saturated (plus 256 host fds / half-open upstream sockets).
Self-DoS of the sandbox's own networking; the host process survives.
**Fix:** wrap the dial and the upstream TLS handshake in a timeout
(e.g. 10-30 s), consistent with the existing `TARGET_TIMEOUT` family.

### L9 — Missing spec silently degrades to empty root + host network

**File:** `src/spec/file.rs:195-217`.

A missing `.ai-bubble/spec.json` (wrong CWD, or an attacker renamed it) falls
back to `Spec::default()` — empty tmpfs root but **host network**. A stderr
warning exists (lines 208-212) and the default
`NetConfig::Host { unix_sockets: false }` still installs the AF_UNIX filter
(modulo H1/H2), but the untrusted command keeps TCP/UDP host networking in a
degraded-but-running sandbox. **Fix:** add a `--require-spec` (or make an
explicit `--spec-dir` with no spec a hard error — it already is — and offer
the same for the default path via flag).

### L10 — `init` creates the spec dir/files with umask-default permissions

**File:** `src/cli/init.rs:68-98`.

The pre-existing-symlink attack is handled (`dir.exists()` follows symlinks;
a dangling symlink fails `create_dir_all` with EEXIST), but
`std::fs::write`/`create_dir_all` yield `0666 & ~umask` / `0777 & ~umask` —
typically 0644/0755 — for a directory documented as holding secrets (the env
file). Minor TOCTOU between `exists()` and `create_dir_all` (needs a local
attacker racing the operator). **Fix:** `DirBuilder::mode(0o700)` (and chmod
after creation to defeat a permissive umask), `0600` for `spec.json`/starter
env.

### L11 — `ls` prints raw host filenames to the terminal

**File:** `src/cli/ls.rs:53-60`.

`entry.file_name().to_string_lossy()` printed verbatim: a hostile filename
can emit terminal escape sequences into the operator's tty (same class as
GNU `ls` pre-quoting). **Fix:** quote/control-escape names the way modern
coreutils `ls` does (`\e` → `\x1b` etc.), at least when stdout is a tty.

### L12 — Spec-dir auto-hide and `hide` globs are defeated by host bind-mount aliases and case-folding filesystems

**Files:** `src/spec/file.rs:282-303` (`hide_spec_dir`, canonicalized path +
per-component glob escaping — good), matcher `src/hostfs/pattern.rs`
(case-sensitive by design).

(a) A host **bind mount** exposing the project tree at a second location
gives the spec dir a second, non-canonical absolute path that neither the
hide pattern nor `validate_sources`' `starts_with` covers — a broad
`rw /**` mapping then exposes `spec.json`, the env file, and the project
cache via the alias. (b) On case-folding filesystems (ext4 casefold),
matching is byte-exact, so a `hide` of `secret` is bypassed by `SECRET` under
a broad rw mapping. Both are inherent to path-based policy (bubblewrap shares
it). **Fix:** document the limitation; optionally have the FUSE server record
the spec dir's `(dev, ino)` at startup and refuse ops whose anchored walk
lands on it (inode-based identity survives path aliases).

### L13 — Inode handle-count leak on `insert_handle` failure

**Files:** `src/hostfs/fuse_ops.rs:423-430`, `1594-1604`, `1635-1645`.

`open_handle(inode)` is incremented **before** `insert_handle`; if the handle
table is full (`MAX_HANDLES = 8192`, `mod.rs:330`), the op fails with ENFILE
but the inode's `open_handles` is never decremented → after `forget`, a
permanent zombie entry holding a `PathBuf`. Bounded (~8192 entries), no
security impact beyond memory litter. **Fix:** decrement on the error path
(or make `insert_handle` take the inode lock and do the increment itself).

### L14 — `Patterns::exists()` and `Patterns::permission_of()` disagree on nested shadow patterns

**File:** `src/hostfs/patterns.rs:196-240` vs. `321-371`.

`exists` records the **shallowest** `empty`/`inject` ancestor; `permission_of`
breaks at the **deepest**. With an `inject` at a shallower ancestor than an
`empty`/mirror pattern (e.g. `inject /a` + `ro /a/b/c`), interior paths
report `exists() == true` while `permission_of() == None`. Traced and found
**not exploitable**: every such path has a broken parent chain, so the kernel
can never traverse to it, and `readdir` filtering uses the same `exists()`
per child. Latent consistency hazard only. **Fix:** reconcile the two walks
(same deepest-first rule) or assert their agreement in tests.

---

## Verified prevented (suspected attacks that do not work)

- **Symlink following anywhere in the mirror.** Every host access is
  dirfd-anchored with per-component `openat(O_PATH|O_NOFOLLOW|O_DIRECTORY)`
  and final-op `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW` (`anchored.rs` passim;
  `open` fuse_ops.rs:339-420, `read`/`write` 519-536/665-678, `setattr`
  963-1056, `statfs` 741, `access` 930-937, `unlink`/`rmdir` 1165/1222,
  `rename` 1324-1333, `create` 1542-1591). The lstat→open TOCTOU in `open()`
  is closed by `O_NOFOLLOW` on the final component regardless of any swap.
- **Permission-check TOCTOU.** The FUSE server runs on a
  `new_current_thread` runtime (`server.rs:143`) and every op's
  check→syscall sequence is await-free on its success path; the sandbox
  cannot interleave a second request to swap entries mid-op. The `link()`
  check-and-create block is explicitly atomic (`fuse_ops.rs:1465-1466`).
- **Hardlink ro→rw escape.** `link()` requires `writable(&old) &&
  writable(&new)` (`fuse_ops.rs:1436-1458`) and `linkat` uses flags=0
  (source never followed).
- **Rename across permission boundaries.** Both endpoints must be writable
  (`fuse_ops.rs:1286`); directory renames additionally pass
  `subtree_restricted` on both sides (`fuse_ops.rs:1307-1319`), including
  `**` shadowing and later-writable-pattern overrides (tested,
  `patterns.rs:783-872`).
- **fh mode confusion.** The cached `OpenHandle.writable` verdict cannot
  elevate: the stored fd's mode matches the original open (an O_RDONLY handle
  fails writes with EBADF at the host), and permission verdicts are
  path-static (`mod.rs:285-301`).
- **chown escalation.** `setattr` passes uid/gid to `fchownat` as the host
  user, but the sandbox can only *name* uids mapped in its user namespace
  (65535→host uid); anything else fails `make_kuid`, and `notify_change`
  denies real uid changes without CAP_CHOWN in the initial userns. No-op even
  when the server runs as root.
- **`..` / repeated-slash / `.` traversal.** Kernel-supplied names cannot
  contain `..`; `anchored::components_of` rejects `ParentDir`
  (`anchored.rs:97-109`); patterns normalize `//` and trailing `/`; a literal
  `.` in a pattern never matches (fail closed).
- **Non-UTF-8 components** fail closed in `exists`/`writable`/`effective` and
  are skipped in `readdir`; the ancestor-walk ordering keeps hidden subtrees
  hidden.
- **Spec-dir auto-hide vs. later mappings.** `hide_spec_dir` appends last
  with per-component glob escaping (`escape_glob`), *and* hide patterns are
  consulted before the last-match rule (`patterns.rs:227-232, 376-381`); a
  later `rw ${PWD}/**` cannot unhide the spec dir (tested,
  `patterns.rs:654-703`). Residual bypasses are bind/redirect sources (M6)
  and host-side path aliases (L12).
- **redirect/session-cache/project-cache containment.** Dests are wildcard-
  and `..`-free (`spec/hostfs.rs:507-523`); relative sources canonicalized
  against the canonicalized spec dir (`hostfs.rs:810-831`); cache sub-paths
  `..`-free (`hostfs.rs:920-925`); backing dirs are `mkdtemp` 0700
  (`sandbox.rs:45-53`); symlink creation through FUSE is denied (modulo M5);
  session-cache wipe via `remove_dir_all` is fd-based and never follows
  symlinks (`session.rs:20-47`).
- **uid/gid map order.** uid_map → `setgroups` `deny` → gid_map
  (`sandbox.rs:384-392`, `netns.rs:191-199`); every write failure is fatal;
  real uid → 65535 only; **no uid-0 mapping exists anywhere**.
- **Capability drop.** Bounding-set loop `0..=cap_last_cap` **inclusive**
  (read from `/proc/sys/kernel/cap_last_cap`, fallback 40), ambient cleared,
  capset v3 zeroes all sets (`sandbox.rs:544-612`). Bounding-set drop before
  exec defeats file-capability regain; exec as non-root clears the rest.
- **Nested-userns capability regain.** Not blocked by seccomp in the default
  config, but both exec paths chroot before exec, and `create_user_ns()`
  refuses EPERM when the caller is chrooted (kernel ≥ 4.9 — the central
  invariant, worth a runtime regression test).
- **Mount propagation & chroot.** `MS_SLAVE|MS_REC` on `/` is the first op
  after `CLONE_NEWNS` (`sandbox.rs:674-690`); mount-destination ops reject
  `..` and symlink traversal (`refuse_symlink_dest`, `sandbox.rs:185-204`);
  `chdir(newroot)` → `chroot(".")` → `chdir(cwd)`; `close_range(3, UINT_MAX)`
  right before exec (`sandbox.rs:1213-1221`) removes caller-leaked dirfds
  (fchdir-out-of-chroot escape closed); all internal fds are O_CLOEXEC.
- **`PR_SET_NO_NEW_PRIVS`** set before unshare on both exec paths
  (`sandbox.rs:344`, `netns.rs:166`), inherited into the command; anonymous
  session keyring before seccomp (`sandbox.rs:1133-1144`).
- **Environment/exec.** Environment fully cleared then rebuilt from the spec
  only (`sandbox.rs:1163-1178`) — no `LD_PRELOAD` leak; NUL/`=`/empty-name
  guards; `execvp` runs after chroot, so PATH lookup only sees the sandbox
  fs. Every setup failure path calls `die()` — no log-and-continue found.
- **Env expansion.** `shellexpand::env` only (no tilde/command substitution),
  at parse/compile time only — no runtime expansion anywhere; unset variables
  are hard errors; expansion cannot inject `..` into a *matched* path
  (matcher is component-wise against kernel-supplied names).
- **dotenv parsing.** Line-based (no multi-line value injection), keys
  `[A-Za-z0-9_]`, `export`/quotes/comments handled, spec `values` win, file
  path canonicalized and confined to the spec dir (`env.rs:84-99,144-166`).
- **CLI.** `trailing_var_arg` on `command` (`cli/mod.rs:98`): everything from
  the first bare argument is the command; ai-bubble flags cannot be injected
  after it (tested, `cli/mod.rs:129-222`).
- **Serde hygiene.** `deny_unknown_fields` on every spec struct/enum;
  duplicate JSON keys rejected; no panic reachable from spec content.
  tmpfs/rlimits numeric fields are `u64` — no negative/overflow wrapping;
  perms parsed as octal and bounded to `0o7777` (`tmpfs.rs:55-83`).
- **Wildcard/port parsing.** `*.github.com` matches neither bare
  `github.com` nor `evilgithub.com`; case-insensitive ASCII; any-depth
  subdomains; trailing-dot FQDNs fail closed (allowlist.rs:48-58, tested
  102-125). Negative/overflow/empty ports deny; `[::1]:443` parses
  consistently and is loopback-blocked unless `allow_private`.
- **Arbitrary connect via the command protocol.** Every command
  (`resolve-dns`, `connect`, `tls-cert`, `tls-connect`) is re-authorized
  host-side against the same allow-list (`host.rs:92,103,140,186`);
  `tls-cert` for off-list names is denied, so the forged CA never signs them.
- **TLS MITM key hygiene.** CA private key never leaves the supervisor
  process; only `ca.pem()` is injected (`cli/run.rs:47-55`); per-request leaf
  keys; PKI dropped in P and FS after fork (`netns.rs:94`,
  `server.rs:115`). Real upstream verification uses `rustls-native-certs`,
  default protocol versions, `ServerName` from the dialed host, no custom
  verifier (`host.rs:378-393,456-463`).
- **Proxy mode.** CONNECT-only (`proxy/sandbox.rs:128-130`) — absolute-URI
  plain HTTP gets 400; 8 KiB head cap; target NUL/whitespace rejected.
- **DNS covert channel.** `resolve-dns` returns the constant `OK 127.0.0.2`
  (`host.rs:99-101`) — no query ever leaves the host; denied names get
  NXDOMAIN with no data; no cache; `simple-dns 0.12` has
  circular-compression-pointer protection.
- **TLS frontend hardening.** Non-SNI connections dropped; hello bounded at
  64 KiB; no raw-TCP tunneling; payload reaches only `SNI:443`.
- **HTTP :80 smuggling.** hyper parses inbound and re-serializes outbound
  (`http.rs:121-152`) — TE/CL ambiguity does not survive.
- **Resource limits on the frontends.** Per-listener cap 256
  (`connlimit.rs`); process-global keygen token bucket (burst 4, refill
  1/250 ms, mutex — parallel requests cannot bypass); all line reads capped
  (512 B commands, 64 KiB cert replies, 8 KiB CONNECT head, 4 KiB DNS);
  command/header/hello/TCP-query timeouts present. (The *command* side is
  unbounded — M4.)
- **Audit encoding.** serde_json escaping for all fields
  (`audit/mod.rs:223-233`); one event per physical line; ≤32 KiB single
  `write(2)`s on an `O_APPEND` fd (forked writers can't tear lines); 64 MiB
  rotation caps disk fill. (Path-side issues are H4/L10.)
- **Panics on untrusted input.** None found in the network/FUSE paths; all
  `unwrap`/`expect` sites are on constants or guarded values; over-limit
  lines close the connection rather than truncating into a different command
  (`line.rs`).

---

## Not fully verified (assumptions this audit relied on)

1. fuse3 0.9's request-dispatch internals (kernel-supplied `fh` values were
   assumed kernel-integrity-protected).
2. Kernel `create_user_ns()` chroot check (the `sandbox.rs:7-15` central
   invariant) — from kernel knowledge, not re-fetched source; recommend a
   runtime regression test (`unshare(CLONE_NEWUSER)` from inside the sandbox
   must fail with EPERM).
3. seccompiler 0.5 Qword emission — verified by reading the vendored source,
   not by running the compiled BPF; H1 should be confirmed with the suggested
   runtime test.
4. ucounts/RLIMIT_NPROC cross-userns accounting (M4) — from kernel design
   docs, not measured.
5. rustls/webpki, rcgen 0.14, hyper 1.x, simple-dns internals beyond their
   integration points (spot-checked only: `simple-dns` label rendering for
   L4, compression-pointer protection).
6. Whether every host filesystem honors setuid bits on `open(O_CREAT)` (H3's
   root-case impact assumes ext4/tmpfs semantics).
7. The TOCTOU window between spec-load canonicalization and FUSE server start
   (a host bind mount appearing in between could shift L12's assumptions).

---

## Suggested fix order

1. **~~H1~~ (done) + ~~H2~~ (done, documentation)** — H1 is fixed (Dword
   comparison + regression test, 2026-10-02). H2 cannot be fixed in
   seccomp (see its FIXED note): the ia32 story is now documented loudly
   in the README and code comments, and the README's claims are
   softened.
2. **~~H3~~ (done) / ~~M1~~ (done) / M5** — small, mechanical FUSE hardening (one mask, one
   special-case, one denial), each with a regression test. H3 and M1 are fixed.
3. **~~H4~~ (done)** — eager `O_NOFOLLOW` open + retained fd for the audit log.
4. **~~M2~~ (done)** — enforce `Host == SNI` in waf mode, or correct the README.
5. **M6** — extend `validate_sources` to spec-dir descendants.
6. **~~M3~~ (done) / M4** — M3 is fixed (all four dangerous families gated
   with per-family opt-ins + README docs, 2026-10-02). M4 remains: policy
   decisions (starter-spec defaults) with doc updates.
7. Low items and the doc-drift cleanup (ARCHITECTURE.md:186/194,
   README.md:486/635-648, rlimits.rs:28-29, stale AUDIT.md references).
