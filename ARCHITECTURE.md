# Process architecture

This document describes the **process structure** of an `ai-bubble run`:
which processes exist, how they are forked, which namespaces and cgroups each
one lives in, how they talk to each other, and what privileges each one has.
It deliberately stops there — filesystem policy, network policy and the spec
file format are documented elsewhere (`README.md`, the module docs).

There is exactly **one binary**. All "processes" below are forks of the same
`ai-bubble` image; the differences between them are what each fork does after
`fork()` — which namespaces it unshares, which servers it runs, and whether
it execs.

Two top-level shapes exist, selected by the spec's `net` section:

* **No isolated networking** (`net` unset or `"disabled"`): one fork, no
  network namespace.
* **Isolated networking** (`"proxy"` or `"waf"` mode): a deeper tree with a
  dedicated network-namespace owner process and a host-side connector.

In both shapes a **FUSE server** child (`FS`) exists whenever the spec
exposes host paths through the mirrored filesystem; it is forked before any
namespace setup, in either shape (see below).

---

## Process trees

### Without isolated networking

```
caller (shell, CI, ...)
└─ A  ai-bubble run ...            host namespaces; unshares user+UTS,
   │                               then IPC+PID ns; forks; waits and
   │                               forwards S's exit status
   ├─ FS  FUSE server              host namespaces; optional — forked by A
   │                               before the namespace setup whenever the
   │                               spec exposes host paths (see below)
   └─ S  (forked by A)             PID 1 of the new PID namespace;
      │                            does the sandbox filesystem setup,
      │                            drops capabilities, loads seccomp,
      │                            and execs
      └─ COMMAND                   same process after execve
         └─ (any children COMMAND spawns stay inside all of S's namespaces)
```

`A` itself performs `setup_and_exec` (`src/sandbox.rs`): it unshares
`CLONE_NEWUSER | CLONE_NEWCGROUP` (one call), then `CLONE_NEWUTS`, then
`CLONE_NEWIPC` + `CLONE_NEWPID`, and forks. The fork is mandatory because
`unshare(CLONE_NEWPID)` only affects *later* forks — the calling process
stays in the old PID namespace. The forked child `S` is therefore the first
process (PID 1) of the new PID namespace, which is what allows the fresh
procfs instance mounted later to show only the sandbox's processes. `S` runs
`mount_and_exec`, never execs as itself: it execs COMMAND after the setup.
Making COMMAND PID 1 corresponds to bwrap's `--as-pid-1`.

### With isolated networking (proxy or waf mode)

```
caller
└─ A  ai-bubble run ...            host namespaces; runs the *connector*
   │                               (host side of the network bridge) and
   │                               waits for P's exit status
   ├─ FS  FUSE server              host namespaces (see below)
   └─ P  (forked by A)             unshares user+net+uts+cgroup ns in one
      │                            call; brings up loopback; serves the
      │                            in-sandbox network frontends on
      │                            127.0.0.2; forks S; waits for S's
      │                            exit status
      └─ S  (forked by P)          PID 1 of the new PID namespace (unshares
         │                         IPC first, then CLONE_NEWPID, then
         │                         forks); does the sandbox filesystem
         │                         setup, drops capabilities, loads
         │                         seccomp, execs
         └─ COMMAND                same process after execve
```

(`netns::run` forks `P`; `P` forks `S` via `sandbox::pidns_and_exec`, the
same function the non-network path reaches directly from `A`.)

The layering follows the code: `A` never enters the sandbox namespaces and
`P` never builds the filesystem — only `S` (and the exec'd COMMAND) see the
sandbox root. Tokio runtimes are created strictly **after** every fork, in
the process that actually runs async code: a forked child must never share a
runtime with its parent, and the exec'd COMMAND must not inherit one.

### The FUSE server

In *both* shapes, when the spec exposes any host paths (`hostfs.mappings`
non-empty), the mirrored filesystem is served by a dedicated fork, created
**before any namespace setup** — while the future sandbox still shares the
host's namespaces and its FUSE mount is an ordinary host mount. It is
always a direct child of `A`, which is why it appears in both trees above:

```
A
├─ FS  FUSE server                 host namespaces; mounts the mirror at a
│                                  private /tmp/ai-bubble.host.XXXXXX and
│                                  serves it for as long as A lives
└─ S  (or P → S on the net path)   the namespace setup continues below A
```

`FS` is forked by `hostfs::start_host_fs` with a readiness pipe: the parent
blocks until the child has written one byte, which happens only after a
successful FUSE mount. Signals that would terminate ai-bubble (SIGINT,
SIGTERM, …) are blocked around the fork and ignored inside `FS` — the server
is never killed mid-mount; it exits when its parent dies (it watches A's
PID), unmounting (falling back to a lazy unmount) on the way out.

The FUSE mount is consumed in one of two ways:

* **hostfs-root mode** (the mirror *is* the sandbox root): `S` chroots
  directly into the mountpoint.
* otherwise: `S` bind-mounts it at `/host` inside the sandbox before chroot.

Because `S` performs these mounts, the mount must be visible from `S`'s
mount namespace — which it is, since `S`'s mount namespace is a slave of the
host tree and the FUSE mount was made before the unshare.

---

## Namespaces and cgroups, per process

`--unshare-all`-style isolation is the default. Which namespaces a process
ends up in:

| Process | user | mount | pid | ipc | net | uts | cgroup |
|---------|------|-------|-----|-----|-----|-----|--------|
| A, FS   | host | host  | host | host | host | host | host |
| P (net path) | **new** | host | host | host | **new** | **new** | **new** |
| S       | **new** (P's/A's) | **new** | **new** (PID 1) | **new** | **new** (net path) | **new** | **new** |
| COMMAND | = S  | = S   | = S | = S | = S | = S | = S |

Details that are easy to get wrong:

* **user + cgroup in one `unshare()` call.** Creating a cgroup namespace
  requires `CAP_SYS_ADMIN` in the user namespace owning the *current*
  cgroup namespace. That authority exists only in the window where
  `CLONE_NEWUSER` is being created (the kernel switches the user namespace
  first, so the combined call's privilege check happens against the fresh
  namespace). After a separate `unshare(CLONE_NEWUSER)` it is too late —
  the call would fail with `EPERM`. `CLONE_NEWCGROUP` is only passed on
  kernels that expose `/proc/self/ns/cgroup` (pre-4.6 would fail with
  EINVAL). See `sandbox::cgroup_ns_flags`.
* **uid/gid maps.** The user namespace maps exactly one id: the caller's
  real uid/gid → `SANDBOX_ID` (65535), written in bwrap's order
  (`uid_map`, `setgroups` deny, `gid_map`). There is **no namespace-local
  root (0)** at all, and 65535 corresponds to no host account. The maps are
  written once — by `A` (non-net path) or `P` (net path) — and inherited by
  the forks below.
* **mount namespace.** Unshared only in `S` (`mount_and_exec`), which then
  makes its mount tree `MS_SLAVE|MS_REC` of the parent so nothing mounted
  for the sandbox propagates back to the host. In the net path `S` inherits
  `P`'s network namespace by construction (same user namespace, forked
  child), so the COMMAND shares the netns with the frontends on 127.0.0.2.
* **cgroup controllers.** None are created and no limits are applied; the
  cgroup *namespace* is unshared only so the command cannot see the host's
  cgroup hierarchy. There is no cgroup-based resource limiting.
* **userns verification.** After every `unshare(CLONE_NEWUSER)` the code
  compares `/proc/self/ns/user` before and after; a silently stripped
  `CLONE_NEWUSER` (some seccomp filters/LSMs do this) is reported as a
  clean error instead of surfacing later as a confusing EPERM on the uid
  map write.

---

## Privileges, capabilities, seccomp

| Process | Capabilities | seccomp | Other hardening |
|---------|--------------|---------|-----------------|
| A | host caps of the invoking user; none added | none | `PR_SET_PDEATHSIG` (optional) |
| FS | host caps of the invoking user (needed to mount FUSE via fusermount3) | none | signals blocked/ignored; exits with parent |
| P | full caps **inside the new user namespace** (needed for `CLONE_NEWNET`, `SIOCSIFFLAGS` on loopback, binding ports) | none | `PR_SET_NO_NEW_PRIVS` |
| S (before exec) | full caps in the new userns until `drop_all_capabilities()` | none | `PR_SET_NO_NEW_PRIVS` (inherited) |
| S → COMMAND | **none at all** | spec's seccomp filter (optional) | uid/gid 65535, empty env, fresh /proc, devpts/`/dev` |

Key points:

* **`PR_SET_NO_NEW_PRIVS`** is set at the entry of every exec path (`A` on
  the non-net path, `P` on the net path) so it is inherited by everything
  below, including the exec'd COMMAND, and is required to load an
  unprivileged seccomp filter later.
* **Capability dropping** (`sandbox::drop_all_capabilities`) runs in `S`
  immediately before the environment reset and exec, and does three things:
  `PR_CAPBSET_DROP` for every capability 0..=40 (so no capability can ever
  be regained, even via file capabilities), `PR_CAP_AMBIENT_CLEAR_ALL`, and
  an explicit empty `capset` for effective/permitted/inheritable. Because
  COMMAND execs as non-root uid 65535, execve would clear the sets anyway —
  the bounding-set drop is what makes regaining them impossible.
* **Seccomp** is the last thing installed in `S`, immediately before
  `execvp`, so the setup itself (mounts, chroot, id maps) still uses the
  full syscall surface. It is compiled from the spec's `seccomp` section
  (syscall numbers only, no argument filtering) with `seccompiler`:
  *allowlist* permits exactly the listed syscalls; *blocklist* denies
  exactly the listed ones; a violation yields `EPERM` or `SIGSYS` per
  `on_violation`. The filter is installed only in `S` — and therefore
  applies only to COMMAND and its children. A, FS, P and S-before-exec run
  unfiltered.
* **PDEATHSIG.** `PR_SET_PDEATHSIG` does not survive `fork()`, so every
  process in the chain sets it for itself: A (bound to ai-bubble's caller),
  P (bound to A), S (bound to P), COMMAND (set in the PID-1 child of S
  before exec). With `--die-with-parent`, the death of ai-bubble's caller
  ripples down and kills the entire tree.

---

## Inter-process communication

### The network bridge (net path)

The only channel between the network-isolated world and the host is a
**Unix-domain socket** at a private `/tmp/ai-bubble-net.XXXXXX/sock`
directory:

```
COMMAND ──TCP──▶ P's frontends on 127.0.0.2 ──Unix socket──▶ A's connector ──TCP──▶ host
        (sandbox netns)                        (host netns)
```

* `A` (the **connector**) binds the socket and serves it in the *host*
  network namespace. It never enters the sandbox; it answers the socket
  protocol with real TCP connections.
* `P` runs the in-sandbox frontends in the *sandbox* network namespace:
  in proxy mode a minimal HTTP CONNECT proxy on 127.0.0.2:3128 (the
  `http_proxy`-family env vars make standard tools use it); in waf mode a
  DNS/HTTP/HTTPS triple on 127.0.0.2:53/80/443 (DNS answers point at
  127.0.0.2, and waf mode injects its own resolv.conf and MITM CA into the
  sandbox).
* P opens the Unix socket **before** any filesystem sandboxing exists: P is
  forked before the mount namespace is unshared and never chroots, so it
  simply opens `/tmp/ai-bubble-net.XXXXXX/sock` on the host tree. COMMAND
  itself never touches the socket — it only speaks TCP to 127.0.0.2.
* The socket crosses the network-namespace boundary because Unix sockets
  are filesystem objects, not network objects. The listener fds are opened
  with `FD_CLOEXEC` so the exec'd COMMAND can never inherit them.
* Protocol: in proxy mode the connector receives `host:port` CONNECT
  requests; in waf mode a small command protocol (`resolve-dns`, `connect`).
  The allow-list check (`proxy::allowlist`) is shared by both sides.
* Both sides of the socket enforce the same allow-list, so neither a
  sandbox-side bypass nor a host-side over-reach is possible.

### The FUSE channel

COMMAND's filesystem accesses to mirrored host paths are served by `FS` over
the kernel FUSE channel — no direct process-to-process IPC. The only
explicit synchronization is the one-byte readiness pipe at startup.

### The audit log

Every forked process (`FS`, `A`/connector, `P`, `S`) can produce audit
events. Because tokio channels cannot be shared across `fork`, **each
process initializes its own** bounded mpsc channel (65536 events) plus a
writer task, and all of them append to the same audit log file. Writes are
line-buffered with a single small `write` per batch, so concurrent writers
interleave safely. On shutdown each process drains its own channel before
exiting.

### Lifecycle synchronization

* readiness pipe (`FS` → A): one byte after a successful FUSE mount.
* `waitpid` chains: A waits for P (or, on the non-net path, forks S
  directly and waits for it); P waits for S; S's supervisor half waits for
  the PID-1 child. Exit statuses are forwarded verbatim (exit code, or
  `128 + signal`).
* PDEATHSIG chain (above) covers abnormal parent death.

---

## Why the forks are ordered the way they are

1. **FS is forked first**, before any namespace work: its FUSE mount must
   be a plain host mount that `S` can later bind or chroot into, and it
   must outlive every fork below.
2. **P is forked before any tokio runtime exists** in the net path, and
   every runtime is created inside the process that uses it (A's connector,
   P's frontends, FS's server loop). This is the "no runtime across fork"
   rule that shapes the whole tree.
3. **The user namespace is unshared once, at the top** (A or P), and the
   id maps are written immediately after — every process below inherits
   them. Only S unshares mount/IPC/PID namespaces, because those take
   effect for the forking process itself or its descendants and are needed
   exactly at the point where the sandbox root is built.
4. **The seccomp filter and capability drop happen last**, inside S,
   immediately before `execvp` — after everything that needs the full
   syscall surface (mounts, chroot, uid map writes) is done.
