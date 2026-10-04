# Security & code audit — ai-bubble

Date: 2026-10-04. Scope: full `src/` tree (~25k lines), spec schema, CLI.
Threat model: the sandboxed COMMAND is untrusted and attempts to (a) escape
containment, (b) reach host resources it was not granted, (c) attack the
privileged helper processes (A/connector, P/frontends, FS/FUSE server), or
(d) tamper with the audit trail. The spec file and the control token are
trusted, but validation gaps that silently weaken isolation are in scope.

> Note on numbering: several code comments reference an *earlier* AUDIT.md
> (`AUDIT.md H4`, `L3`, …) that is no longer in the repo. IDs below are
> fresh: **SB-** sandbox/namespaces, **HF-** hostfs/FUSE, **NET-**
> proxy/WAF/control, **SP-** spec/CLI/audit-log.

## Executive summary

The core design is sound and unusually well-hardened: component-wise
anchored `openat` walks with `O_NOFOLLOW` everywhere in the FUSE server,
symlink-destination checks on all mount targets, correct capability
bounding-set drops, CLOEXEC discipline, double-sided allow-list enforcement
on the network bridge, host-side DNS resolution (no rebinding window), and
a strong control-token design. **No unqualified, direct sandbox escape was
found.**

The most important issues:

1. **SB-1 (High)** — the pre-exec fd sweep runs *after* seccomp install;
   on kernels without `close_range` the fallback `close()` loop fails
   silently under a strict allowlist, leaving caller-leaked fds (a host
   directory fd = full chroot escape) open.
2. **SP-1 (High)** — runtime `fs-set` via the control plane skips the
   spec-directory protection invariants (`hide_spec_dir`,
   `validate_sources`), re-opening the exact escalation the loader blocks.
3. **HF-1, HF-2, NET-1, SB-2, SP-3 (Medium)** — rename TOCTOU and
   device-node proxying in the FUSE server; IPv4-translated `::ffff:0:0/96`
   slipping past the SSRF filter; no verification that `CLONE_NEWNET` took
   effect; audit-event forgery/suppression over the IPC hub.

---

## HIGH

### SB-1 — fd-closing sweep runs after seccomp install; leaked host fds survive → chroot escape

`src/sandbox.rs:1333-1364`

```rust
if let Some(policy) = seccomp {
    apply_seccomp(policy);              // filter is now live
}
...
if libc::syscall(libc::SYS_close_range, 3u64, libc::c_uint::MAX, 0u64) != 0 {
    ...
    for fd in 3..fd_sweep_limit() {
        libc::close(fd as libc::c_int); // return value IGNORED
    }
}
libc::execvp(...);
```

The code's own comment states the stakes: a caller-leaked host *directory*
fd lets `fchdir` move the command's cwd outside the chroot — full host-fs
access. But the sweep runs *after* `apply_seccomp()`. With a spec allowlist
that omits `close_range`/`close` (plausible — the operator enumerates what
the *command* needs):

* modern kernel: `close_range` → `EPERM` (not ENOSYS/EINVAL) →
  `die_with_error` — fail-safe but a confusing breakage;
* kernel < 5.9 (no `close_range`): `close_range` → `ENOSYS` → fallback
  loop; every `close()` returns `EPERM`, the error is ignored, and exec
  proceeds with **all leaked fds open**.

**Fix:** move the fd sweep to *before* `apply_seccomp()` (only fds 0/1/2
are needed afterwards anyway), and check `close()` errors in the fallback.

### SP-1 — control-plane `fs-set` bypasses spec-dir protection invariants

`src/control.rs:732-753` (`fs_apply_list`) vs. `src/spec/file.rs:242,257,344-421`

The spec loader enforces (a) the auto-hide mapping for the spec directory
and (b) rejection of bind/redirect sources covering the spec directory.
`fs_apply_list` re-runs only `patterns_from_mappings` (glob compile) —
neither invariant. A token holder can therefore:

```json
fs-set '[{"type":"redirect-rw","dest":"/loot","source":"/repo/.ai-bubble"}]'
```

which is accepted and hands the sandboxed command read/write access to
`spec.json`, the env file (secrets), the caches, and
`run/control-token` — and, being `rw`, rewrites policy persistently across
runs. A hand-written list that omits the auto-hide pattern also silently
drops it (full replacement). The CLI help's claim that "the same validation
the spec loader applies runs before anything is swapped" is false.
`spec-reload` is safe (goes through `Spec::try_load`).

**Fix:** in `fs_apply_list`, re-append `hide_spec_dir` and run
`validate_sources` against the recorded `SPEC_DIR` before pushing.

---

## MEDIUM

### SB-2 — no verification that `CLONE_NEWNET` took effect

`src/netns.rs:258-271`

The code carefully verifies the *user* namespace was really created
(`check_new_userns`, defending against seccomp-notify supervisors that
silently strip `CLONE_NEWUSER`) but performs no equivalent check for the
network namespace. A supervisor that strips `CLONE_NEWNET` leaves P and the
command on the **host network** while the operator believes networking is
proxied — P's frontends bind on host loopback and the command gets direct,
unfiltered Internet/LAN access, bypassing the allow-list entirely.
**Fix:** compare `/proc/self/ns/net` before/after, like `userns_id()`.

### SB-3 — root tmpfs (and default tmpfs mounts) have no size limit — host memory DoS

`src/sandbox.rs:848-859`; `src/spec/internal.rs:438`

The sandbox root tmpfs is mounted with no `size=` option (tmpfs default ≈
50 % of host RAM) and is writable by the command (mode 0755, owned by the
mapped uid). There is no cgroup limiting and `RLIMIT_AS` does not cover
tmpfs, so the command can consume host memory until the OOM killer fires.
Spec-declared tmpfs mounts without `size` have the same issue. The starter
spec caps `/tmp` by example, but the root tmpfs can never be capped.
**Fix:** accept (and default) a root-tmpfs size; document the exposure.

### SB-4 — bind-mount remount omits `MS_NODEV`/`MS_NOSUID`; rw binds get no flag hardening

`src/sandbox.rs:915-943`

The ro remount adds only `MS_RDONLY`; rw binds are not remounted at all, so
both inherit the source mount's flags. bwrap forces `MS_NOSUID` on all
binds and `MS_NODEV` on non-dev binds. Impact is mitigated
(`no_new_privs`, no `CAP_MKNOD`) but device nodes already present on a
bound host tree (e.g. an ro bind of `/`) remain openable per host DAC.

### HF-1 — `rename`: file↔directory TOCTOU bypasses `subtree_restricted`

`src/hostfs/fuse_ops.rs:1444-1476`

`is_host_dir` (an anchored `lstat`) and the `renameat` are separate
syscalls. If the source is a *file* at check time but a *directory* at
`renameat` time (swapped via an out-of-band channel — e.g. a directory that
is both rw-mirrored and rw-`bind`-mounted, or a hostile same-uid host
process), a directory is moved with no subtree analysis: a `hide`d subtree
can be carried into a broad `rw /**` region and becomes visible/writable.
**Fix:** re-`fstatat` via the pinned parent immediately before `renameat`
and treat directory sources as requiring the subtree check unconditionally.

### HF-2 — `open`/`create` proxy host device nodes with the server's credentials

`src/hostfs/fuse_ops.rs:407-469, 1697-1741, 578-595, 726-739`

`open` rejects only symlinks and directories; char/block devices and
sockets fall through to `anchored::open_at`, which opens the **host**
device file with FS's credentials and proxies read/write through the FUSE
handle. The mount's `nodev` does not help (the device open happens on the
host tree). Mirroring a device-containing directory (e.g. `ro /dev`) lets
the sandbox use host devices the invoking user can open (`/dev/ptmx`
allocates a host pty pair, world-writable `/dev/uinput`, …) — precisely the
per-path boundary the mirror exists to police. FIFOs were a deliberate
exception; extend the rejection to `S_ISCHR`/`S_ISBLK`/`S_ISSOCK` in
`open`, `create`'s existing-entry branch, and the stateless read/write
reopens.

### HF-3 — runtime policy tightening bypassed through pre-rename open handles

`src/hostfs/mod.rs:389-404`; `src/hostfs/fuse_ops.rs:476, 629-680`; `src/hostfs/inodes.rs:162-231`

The per-write `writable()` check uses `OpenHandle.path`, captured at open
time and **never updated on rename**: open `/work/f` (rw) → rename to
`/vault/f` → control plane makes `/vault/**` ro → writes through the handle
still check `/work/f` (rw) and succeed on the file now living at `/vault/f`.
Not reachable by the sandbox alone (it cannot tighten policy). **Fix:**
store the inode in `OpenHandle` and resolve the current path via the inode
map per write (the map already repoints descendants on rename).

### NET-1 — ipfilter: IPv4-translated `::ffff:0:0/96` slips past the embedded-v4 check

`src/proxy/ipfilter.rs:82-95`

The mapped-form test requires segments `[0,0,0,0,0, 0xffff, …]`. The
RFC 6052 IPv4-translated form `::ffff:0:10.0.0.1` parses to
`[0,0,0,0, 0xffff, 0, 0x0a00, 0x0001]` — no arm matches, so
`blocked_reason` returns `None`. An attacker who controls DNS for an
allow-listed name (own domain on the list, or a subdomain under a wildcard)
answers AAAA `::ffff:0:169.254.169.254`; on a host network with a
NAT64/SIIT translator the connector dials the cloud metadata endpoint — the
exact SSRF class this module exists to prevent. Same for non-well-known
RFC 6052 NAT64 prefixes. **Fix:** cover `::ffff:0:0/96` (and any address
whose low 32 bits are v4-interpretable under a translation prefix) in the
embedded-v4 check.

### NET-2 — control-socket accept loop has no connection cap

`src/control.rs:540-548`

Every other listener uses `ConnLimit`; the control listener spawns
unbounded tasks, each holding an fd for up to `TOKEN_TIMEOUT` (10 s)
without a token. In host-network mode the sandboxed command (with
`unix_sockets: true`) can compute the deterministic abstract name
(sha256 of the spec dir) and exhaust A's fds — A is also the connector, so
this is a full network DoS of the run. Also exposed to any same-uid host
process. **Fix:** wrap in `ConnLimit` like the other listeners.

### NET-3 — atexit control cleanup is inherited by fork children; a mid-run `die()` in P or FS deletes the token file

`src/control.rs:279-282, 362-376`; `src/sandbox.rs:35-38`

`control::start` registers `cleanup_atexit` before any fork;
`std::process::exit` runs atexit handlers, so a `die()` in P or FS (e.g. a
frontend bind failure) removes `<spec-dir>/run/control-token` while A is
still serving — runtime control is silently dead for the rest of the run.
`close_inherited_listener` resets the fd but not `ACTIVE`. **Fix:** clear
`ACTIVE` in `close_inherited_listener`, or use `_exit` in children.

### SP-2 — audit IPC: children can forge event attribution and suppress their own events

`src/audit/ipc.rs:299-356`, `src/audit/ipc.rs:72-81`; `src/audit/mod.rs:336-344`

* The hub forwards `ts`/`pid`/`source` verbatim and knows each channel's
  `PeerRole` but never stamps/cross-checks it: a compromised FS child can
  emit events claiming `source: "waf"` with the launcher's pid.
* Reply demultiplexing runs **before** event parsing; `Event` derives
  `Deserialize` without `deny_unknown_fields`, so a frame that is a valid
  event *plus* `"ack": true` is diverted to the reply channel and dropped
  from the log — an audit-suppression primitive for a compromised child.

**Fix:** stamp/override `source` per channel in the hub; parse `Event`
first (a reply lacks `ts`/`pid`/`source`/`op`, so the order is
unambiguous).

### SP-3 — `spec-reload` panic from spec input: session-cache `.expect()`

`src/spec/hostfs.rs:1030-1039`, via `src/control.rs:943-948`

If the run started *without* a `session-cache` mapping and a `spec-reload`
adds one, `prepare_caches` hits
`.expect("session root provided whenever session-cache mappings exist")`
and panics in the control task — violating the `try_compile`
"report, don't die" contract. **Fix:** return a clean error ("restart to
add session-cache mappings").

### SP-4 — checked-in JSON schema is stale; rejects valid security fields

`ai-bubble.spec.schema.json` vs. `src/spec/file.rs`, `src/spec/net.rs`
(verified by diffing `--print-schema` output)

* No `rlimits` property at all — with top-level `additionalProperties:
  false`, editors flag the fork-bomb/memory brakes as invalid and users
  will strip them.
* Host-mode net variant lacks `netlink`/`vsock`/`bluetooth`.
* `SeccompConfig` schema requires `on_violation` although the parser
  defaults it.

**Fix:** regenerate the schema in CI (fail on drift).

---

## LOW

### Sandbox / namespaces

* **SB-5** — `src/sandbox.rs:902-914`: file bind mounts broken in
  tmpfs-root mode; `src_stat` is filled but never inspected (`ensure_dir`
  always mkdir's; file source → `ENOTDIR`). Dead code + functional bug:
  create an empty dest file for file sources (bwrap behavior) or reject
  explicitly.
* **SB-6** — `src/spec/seccomp.rs:56-84`, `src/sandbox.rs:1439-1448`: the
  ia32-ABI bypass is documented; the **x32 ABI** (`__X32_SYSCALL_BIT`
  numbers pass the x86_64 arch check) is the same class and undocumented.
  Rare (needs `CONFIG_X86_X32`), worth one doc paragraph.
* **SB-7** — `src/netns.rs:305-317`: sets `NO_PROXY` but not lowercase
  `no_proxy`; tools honoring only the lowercase form route localhost
  through the proxy (breakage; a confused-deputy only with a wildcard
  allow entry).
* **SB-8** — `src/sandbox.rs:570-575`: pty/control conflict error message
  is inverted (condition fires when control *is* enabled; remedy is to
  pass `--no-control`).
* **SB-9** — `src/sandbox.rs:843-846`: host dir `/tmp/ai-bubble.XXXXXX`
  (sandbox root backing) is never removed; leaks one dir per run.
* **SB-10** — `src/sandbox.rs:775-776`: `CString::new(...).unwrap()` in
  `mount_tmpfs` panics on NUL in a spec tmpfs dest instead of the clean
  `die()` used everywhere else via `cstring()`.
* **SB-11** — UTS namespace keeps a copy of the host hostname (mild
  fingerprinting leak); consider setting a neutral hostname after unshare.
* **SB-12** — `src/sandbox.rs:961-970`: fresh procfs mounted whole — no
  `subset=pid`, no `hidepid`; exposes `/proc/sys`, `/proc/kallsyms` (KASLR
  leak when `kptr_restrict=0`) to the command. Modern bwrap uses
  `subset=pid`.
* **SB-13** — `src/spec/seccomp.rs:219-258`: default blocklist blocks
  `pidfd_getfd` ("lateral movement") but not `ptrace` /
  `process_vm_readv/writev`, which are strictly stronger within the
  sandbox. Impact confined to the sandbox; rationale inconsistent.
* **SB-14** — `src/pty.rs:497-535`: blocking fds 0/1 mean a `^S`-stopped
  tty stalls the relay including fatal-signal forwarding (`SA_RESTART`).
  Same class as `script(1)`; document alongside the other relay residuals.
* **SB-15** — PDEATHSIG residuals (restated): `getppid()==1` misses
  re-parenting to a non-init subreaper (systemd user sessions, nested
  bwrap); the `/proc/self/stat` PPid check is skipped when `/proc` is
  unreadable. Both previously accepted — keep on the radar.

### hostfs / FUSE

* **HF-4** — `src/hostfs/perf.rs:133-139`: the stats dumper re-opens
  `RS_BUBBLE_FUSE_STATS` every 10 s, path-based, *following symlinks*, with
  FS's host credentials — the bug class already fixed for `fuselog`. If the
  path is sandbox-writable, a swapped-in symlink gets attacker-influenced
  content appended to an arbitrary user-writable host file. Open once
  eagerly via `audit::safe_open`. (Opt-in env var, hence Low.)
* **HF-5** — `src/hostfs/fuse_ops.rs:863-881`, `src/hostfs/inodes.rs:204-209`:
  plain `readdir` permanently inserts a nodeid + PathBuf per listed name
  with no cap (kernel never sends `forget` for these) — memory growth in a
  host-privileged process walking a large mirror; and every directory
  rename is an O(map) `repoint_descendants` scan on the single-threaded
  runtime (CPU DoS via inflate-then-rename loop). Fix: don't insert child
  mappings in plain `readdir`; cap the map.
* **HF-6** — `src/hostfs/fuse_ops.rs:766-823`: `statfs` skips the
  `exists()`/hidden check (info leak after runtime hide); an `empty`
  mapping over a *real* host path reports the real filesystem instead of
  the synthetic one.
* **HF-7** — `src/hostfs/fuse_ops.rs:310-320`: `readlink` on an
  `empty`-mapped symlink reveals the real host target string (contradicts
  "the host file is never read").
* **HF-8** — `src/hostfs/fuse_ops.rs:1003-1009`: `access` relies on
  `faccessat(AT_SYMLINK_NOFOLLOW)` with no fallback (unlike `chmod` right
  above); on pre-5.8 kernels the check can follow a swapped symlink —
  a 1-bit access oracle.
* **HF-9** — no `fsync` override: fuse3's default is `Ok(())`, a
  durability lie to sandboxed git/cargo/databases. Return `ENOSYS` or
  really fsync the handle.
* **HF-10** — casefold-enabled host directories defeat hide patterns
  (`/work/SECRET` resolves to hidden `secret` via host casefold). Rare;
  document.
* **HF-11** — `src/hostfs/anchored.rs:249-257` + `server.rs:271-279`:
  blocking FIFO reads stall the single-threaded runtime **including the
  200 ms parent-death watchdog** — a parked FIFO read + launcher death
  leaks the mount indefinitely. Self-inflicted; consider a watchdog on its
  own thread.

### Network / proxy / WAF

* **NET-4** — `src/waf/https.rs:362-364`: `read_client_hello` truncates
  the replay prefix at the handshake-message boundary, not the record
  boundary — drops a coalesced CCS record and mishandles fragmented
  ClientHellos (fail-closed interop bug). Truncate at `5 + record_len`.
* **NET-5** — `src/waf/dns.rs:122,151`: raw qname interpolated into the
  host command line (`resolve-dns {name}`); DNS labels may contain `\n`.
  Not exploitable today (one line read per connection; `valid_name`
  rejects control bytes) but a latent injection riding on an accidental
  invariant — validate before sending.
* **NET-6** — `src/proxy/allowlist.rs:49-73`: entry parsing is not
  bracket/IPv6-aware (`::1` → host `:`, port 1; `host_allowed` can never
  match an IPv6 literal; `example.com:443x` is a dead entry); spec parse
  does no `allow`-entry validation. All fail closed — normalize entries
  and targets through one parser and reject at load.
* **NET-7** — `src/waf/http.rs:121-152`: plain-HTTP frontend forwards
  hop-by-hop headers (`Proxy-Authorization`!) verbatim and can't handle
  CONNECT/Upgrade. Module says test-only; if it stays, strip hop-by-hop
  headers.
* **NET-8** — ipfilter does not list `2001:2::/48`, `3fff::/20`,
  `2001:20::/28`, `100::/64`. No private-infrastructure impact; for
  completeness.
* **NET-9** — post-establishment flows have no idle/byte limits; the
  command can park all 256 connection slots and wedge its own egress
  (accepted/self-DoS; an optional idle-timeout knob would help).

### Spec / CLI / audit log

* **SP-5** — `src/cli/mod.rs:70-148`: negatable run flags still parse
  ahead of the command (`--no-new-session` → host pts bound in, TIOCSTI
  injection; `--no-die-with-parent`; `--no-control`) when a wrapper
  forwards untrusted args without `--`. Harden like `--spec-dir` was
  (`allow_hyphen_values`/`trailing_var_arg`).
* **SP-6** — `src/audit/writer.rs:143-154`: log-path blacklist covers
  `spec.json`/`.env` but not `run/control-token` — pointing the audit log
  there bricks control auth (appended events break the strict token
  format).
* **SP-7** — `src/audit/writer.rs:301-331`: concurrent rotation on the
  two-writer non-isolated path can replace the real `log.1` backup with a
  near-empty file (audit history loss).
* **SP-8** — `src/cli/audit_cli.rs:93-96`: `audit --follow` opens the log
  with a plain `File::open` — follows swapped symlinks, blocks on swapped
  FIFOs. Reuse `safe_open` minus `O_CREAT`.
* **SP-9** — `src/audit/mod.rs:111` × `src/audit/ipc.rs:45`: queue bound
  is 65536 events × up to 64 KiB frames ≈ up to ~4 GiB pinned in A by a
  flooding child; `record` never caps `source`/`op`/`path` (only
  `detail`), so an over-cap frame kills that child's channel (self-DoS of
  its audit stream). Consider a byte-based queue budget and capping all
  string fields.
* **SP-10** — no warnings for dangerous-but-legal specs: `rw` over
  `/etc`/`~/.ssh`/`$HOME`, missing `seccomp` section, unvalidated `net
  allow` entries (the control plane validates entries the spec file
  accepts — inconsistent). The `init` starter teaches `net: host` with no
  seccomp preset; given the documented host-mode socket-gate ABI gaps, a
  proxy-mode + `preset: "default"` starter would teach better.
* **SP-11** — `src/audit/writer.rs:291-293`: a panicked blocking-pool
  flush makes the writer `die()` → kills the whole launcher mid-run; the
  inner `file.lock().unwrap()` is poisonable.

---

## Cleanup / refactor candidates

**Dead code & stale docs**

1. `src/sandbox.rs:902-914` — unused `src_stat` (see SB-5).
2. `src/sandbox.rs:67-79` — `mkdtemp_dir` leaks the template `CString`
   (`into_raw`, never reclaimed; once per run).
3. `src/hostfs/anchored.rs:369-399` — `read_link_at` is dead (annotated).
4. `src/hostfs/fuse_ops.rs:866-870, 918-922` — `"."`/`".."` special-casing
   in `readdir`/`readdirplus` is dead (filtered in `readdir_names`); also
   a minor POSIX wart: `ls -la` shows no `.`/`..`.
5. `src/hostfs/fuse_ops.rs:71-110` — `attr_from_metadata` duplicates
   `attr_from_stat` field-for-field; merge.
6. `src/hostfs/mod.rs:344-353` — `handles` doc paragraph duplicated
   verbatim; `:158` doc says `/host` but `SANDBOX_MOUNT_POINT` is
   `/mirrored`.
7. `src/hostfs/fuse_ops.rs:131-132` — `is_root` doc references a removed
   path bridge; `:1538,1604` comments claim "Linux `linkat` cannot
   no-follow the source" (inaccurate — without `AT_SYMLINK_FOLLOW` it
   links the symlink itself; behavior is correct, comment is wrong).
8. `src/hostfs/inodes.rs` — `SharedPatterns::generation`/`set` carry
   `#[allow(dead_code)]` awaiting the control plane; `tests.rs:16-18`
   `fs_with_empties` is a redundant alias.
9. `src/cli/mod.rs:12` — stray garbage in doc comment
   ("`,,,,,,,,,,,,,,,,,,`").
10. `src/cli/init.rs:176-180` — duplicated comment block.
11. `src/audit/writer.rs` — `MAX_BYTES` rationale comment predates the
    single-writer design; `src/spec/file.rs:295` stale "(as before)".
12. `src/audit/mod.rs:99-103` — `#[allow(unused_imports)]` re-exports with
    no in-crate call sites; trim or wire into docs.

**Duplication**

13. Accept-loop scaffolding (ConnLimit + allow-list snapshot +
    spawn-with-guard) duplicated five times (`proxy/connector.rs`,
    `proxy/sandbox.rs`, `waf/dns.rs`, `waf/http.rs`, `waf/https.rs`,
    `waf/host.rs`) — a shared `serve_with_limit` helper would shrink the
    audit surface.
14. `src/netns.rs:493-502` vs `src/sandbox.rs:636-639` — duplicated
    current-thread tokio runtime construction; export and reuse `block_on`.
15. `FLUSH_INTERVAL` defined twice (`src/audit/mod.rs:115`,
    `src/audit/writer.rs:239`); `record()` duplicates `queue_sender()`'s
    get-or-init logic instead of calling it.
16. `src/waf/host.rs:351-359` — `valid_name` checks `is_ascii()`
    redundantly inside the per-label closure.
17. `src/hostfs/mod.rs:504-634` — `virtual_only`/`attr` call
    `patterns.load()` up to five times per decision; take one snapshot.

**Dependency note**

18. `simple-dns` 0.12.0 parses fully attacker-controlled DNS packets
    (compression pointers etc.) — pin and track its advisories.

---

## Explicitly verified safe (selected)

* Anchored FUSE walk: `..` rejected in `components_of`; kernel names are
  single components; no symlink followed at any component; final-component
  `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW` everywhere; symlink creation denied;
  `mknod`/setxattr/`fallocate`/`copy_file_range`/`ioctl` fall through to
  fuse3's `ENOSYS` defaults; chmod masks setuid/setgid; chown clamped.
* `MS_SLAVE|MS_REC` ordering before any sandbox mounts; chroot-before-exec
  invariant on all paths; `PR_SET_NO_NEW_PRIVS` before any unshare; correct
  uid/gid map order; capability bounding-set drop 0..=`cap_last_cap` +
  ambient clear + zeroing `capset`.
* Seccomp compile logic: allowlist/blocklist actions correct; socket-family
  gate uses dword compares; allowlist narrowing / blocklist widening both
  correct; parse-time conflict validation.
* DNS rebinding closed: single host-side resolution in
  `ipfilter::connect_checked`, dial goes to the validated IP literal;
  sandbox DNS only ever returns 127.0.0.2.
* Domain fronting closed: per-request `Host == SNI` on kept-alive TLS;
  `Host` rewritten with `insert` (duplicate-Host smuggling dies);
  absolute-URI neutralized; upstream TLS validated against native roots.
* Control token: 128-bit getrandom, `0600`/`O_NOFOLLOW` file in a `0700`
  dir, constant-time compare, abstract socket unreachable from the
  isolated netns; all reads size-capped and time-boxed (no slowloris).
* Audit log open: eager pre-fork with `O_NOFOLLOW|O_NONBLOCK`, fstat
  regular-file check, `0600`; rotation re-opens via `safe_open` and keeps
  the old fd on failure; log forging impossible (all fields JSON-escaped);
  sandboxed command cannot inherit the log fd (CLOEXEC + fd sweep +
  `drop_log_fd` in FS/P).
* `/tmp` dirs use real `mkdtemp` (0700); session-cache wipe uses
  `remove_dir_all` without symlink following; `init` is symlink-safe and
  sets `0700`/`0600`.
* No panics reachable from network/attacker input in the proxy/WAF paths;
  FUSE mutex poisoning recovered everywhere; `unsafe` fd handling correct
  on re-read.

## Recommended fix order

1. SB-1 (fd sweep before seccomp + check `close()` errors)
2. SP-1 (re-apply spec-dir invariants in `fs_apply_list`)
3. SP-4 (regenerate schema in CI — actively strips security fields today)
4. HF-2 (reject device/socket opens), NET-1 (`::ffff:0:0/96`), SB-2
   (netns check)
5. SP-2 (stamp `source` in hub; parse `Event` before `UpdReply`), SP-3
6. HF-1 (rename re-verification), SB-3 (root tmpfs cap), NET-2/NET-3
7. Low items + cleanup as time permits.
