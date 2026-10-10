# Unsafe code audit — library / std replacements

Scope: every `unsafe` block in the project's own source (`src/`), checked against
std, the current dependencies (`Cargo.toml`), and well-known system crates
(`nix`, `rustix`, `caps`, `cap-std`, `getrandom`, `socket2`).
Vendored third-party sources under `.ai-bubble/cache` are out of scope.

Reviewed: 2026-10-10 against the tree as of that date.

**Second pass, same date**: API coverage re-checked against `rustix` 1.1.5 and
`nix` 0.31.3 (docs.rs). rustix 1.x has grown far beyond what the first pass
assumed — it now has safe `mount`/`unmount`, safe `chroot`, `TIOCSCTTY`,
`waitpid`, `getrlimit`, a full `net` module (socketpair / shutdown / peer
credentials), and a `rand` module. **A single `rustix` dependency can replace
~196 of the ~260 unsafe libc call sites; adding `nix` alongside it would add
almost nothing** (see "Single-crate analysis" below). Sections below were
updated accordingly.

Verdict in one line: **most unsafe code is justified** — it is
fork / exec / unshare / signal / mount machinery. The mount and identity
portions *are* expressible safely today via `rustix::mount` (new since the
first pass); the fork/exec/signal core remains hand-rolled. A minority of
sites is mechanically replaceable; see the priority list at the end.

Legend:

- ✅ direct safe replacement exists (std or a well-known crate call)
- ⚠️ a safe crate covers the primitive, but the surrounding pattern must stay hand-rolled
- ❌ no safe equivalent; the unsafe is inherent — keep

---

## ✅ Replaceable with std alone (no new dependency)

**Done** — all five sites below were converted to std calls
(`symlink` → `std::os::unix::fs::symlink`, `stat` → `fs::metadata` +
`FileType::is_file`, `getpid` → `std::process::id()` (comparison cast to
`libc::pid_t`), `F_DUPFD_CLOEXEC` → `OwnedFd::try_clone()`); the table is
kept for reference.

| Location | Current unsafe | std replacement |
|---|---|---|
| `src/sandbox/mod.rs:1243,1274,1328` | `libc::symlink` | `std::os::unix::fs::symlink` |
| `src/sandbox/mod.rs:1054` | `libc::stat` | `std::fs::metadata` + `MetadataExt` |
| `src/ipc/netmux.rs:548,561` (pid only) | `libc::getpid` | `std::process::id()` |
| `src/hostfs/server.rs:85` | `libc::getpid` | `std::process::id()` |
| `src/hostfs/anchored.rs:74–79` | `fcntl(F_DUPFD_CLOEXEC)` | `OwnedFd::try_clone()` |

## ✅ Replaceable with a well-known crate call

**A single new dependency on `rustix` (features: `fs`, `process`, `term`,
`termios`, `event`, `net`, `mount`, `pipe`, `rand`) covers everything in this
section** — plus the `caps` crate for the capability FFI. nix 0.31 covers
almost the same set, but rustix uniquely adds safe `mount`, safe `chroot`,
`ioctl_tiocsctty`, and window-size termios calls; nix uniquely adds
`sigaction`/`sigprocmask`/`mkdtemp`/`cfmakeraw`/`set_no_new_privs`/`execvp`
(all covered elsewhere in this doc as keep-raw or one-liners). See
"Single-crate analysis" for the per-crate site counts.

### Identity getters

`getuid` / `geteuid` / `getgid` / `getegid` / `getppid` / `gettid` /
`getgroups` — all have safe wrappers in `nix::unistd` (and `rustix::process`).
std has `std::process::id()` for the pid but **no** public euid/egid accessor.

- `src/sandbox/mod.rs:283–287, 517`
- `src/sandbox/netns.rs:277, 548–550`
- `src/hostfs/fuse_ops.rs:22–26` (two-phase `getgroups` buffer sizing —
  `nix::unistd::getgroups` returns a `Vec<Gid>` directly), `:1246`
- `src/hostfs/server.rs:190–191`
- `src/hostfs/fuselog.rs:60` (`gettid`)
- `src/ipc/netmux.rs:549–550, 562` (euid/egid in `SO_PEERCRED` comparison)

### rlimits

- `src/sandbox/mod.rs:58` (`getrlimit(RLIMIT_NOFILE)`), `:151` (`setrlimit`)
- `src/sandbox/tests.rs:8–12`
- → `rustix::process::{getrlimit, setrlimit}` (also in `nix::sys::resource`;
  `Rlimit`/`Resource` types instead of `libc::rlimit` + `mem::zeroed`)

### socketpair / pipe2

- `src/sandbox/netns.rs:83–91` (net mux), `:103–112` (audit channel)
- `src/sandbox/pty.rs:304` (self-pipe)
- `src/hostfs/server.rs:89` (readiness pipe — note: plain `pipe`, no CLOEXEC;
  intentional? worth checking when swapping), `:102–112` (socketpair)
- → `rustix::net::socketpair` and `rustix::pipe::{pipe, pipe2}` return
  `OwnedFd`s and handle CLOEXEC (nix `unistd::{socketpair, pipe2}` equivalent).

### mkdtemp

- `src/sandbox/mod.rs:74–87` — manual `CString::into_raw`/`from_raw` juggling.
- → `nix::unistd::mkdtemp` removes the raw-pointer pair entirely. rustix has
  **no** `mkdtemp` — this is the one site in this section that would pull in
  nix (or keep raw; it is 14 lines). (`tempfile` would auto-clean the dir,
  which conflicts with the launcher's ownership of the backing dir.)

### PTY handling — best single-file win (`src/sandbox/pty.rs`)

| Site | Current | Replacement |
|---|---|---|
| `:90` | `isatty(0)`, `isatty(1)` | `rustix::termios::isatty` |
| `:111–124` | `posix_openpt`, `grantpt`, `unlockpt`, `ptsname_r` | `rustix::pty` (all four) |
| `:136` | `libc::open` of the slave | `std::fs::OpenOptions` + `custom_flags(O_NOCTTY\|O_CLOEXEC)` |
| `:171–188` | `dup2`, `setsid`, `TIOCSCTTY` | `rustix::io::dup2`, `rustix::process::setsid`, **`rustix::process::ioctl_tiocsctty`** ✅ |
| `:281–335` | `tcgetattr`/`tcsetattr`/`cfmakeraw` | `rustix::termios::{tcgetattr, tcsetattr}`; `cfmakeraw` has **no** rustix wrapper — either inline the ~6 flag assignments or keep nix for this one call |
| `:408–424` | `ioctl(TIOCGWINSZ/TIOCSWINSZ)` | `rustix::termios::{tcgetwinsize, tcsetwinsize}` ✅ (nix has neither) |
| `:469` | `poll` | `rustix::event::poll` ⚠️ (loop also hand-rolls EAGAIN read/write) |

Note: `:171–188` was previously listed as ❌ for `TIOCSCTTY`; rustix 1.1
provides `rustix::process::ioctl_tiocsctty`, so the whole block is now
mechanically replaceable.

### prctl / capabilities

- `PR_SET_NO_NEW_PRIVS` (`mod.rs:509`, `netns.rs:272`, tests) →
  `nix::sys::prctl::set_no_new_privs` ✅ — nix-only; rustix has **no** NNP
  wrapper. A one-line raw `prctl` is equally fine (it is a constant + 0).
- `PR_SET_PDEATHSIG` (`mod.rs:392`) →
  `rustix::process::set_parent_process_death_signal` ✅ (or
  `nix::sys::prctl::set_pdeathsig`)
- raw `syscall(SYS_capset)` with hand-built v3 `CapHeader`/`CapData`
  (`mod.rs:861–868` — the most error-prone FFI struct in the tree) →
  **`caps` crate**: `caps::set()` with `CapabilitySet::clear()` ✅
- `PR_CAPBSET_DROP` loop (`mod.rs:807–813`) → `caps::drop` ⚠️ (the loop keeps
  EINVAL tolerance for the `0..cap_last()` range)
- `PR_CAP_AMBIENT_CLEAR_ALL` (`mod.rs:816`) → `caps::clear` ✅

### waitpid

`libc::waitpid` + `WIFEXITED`/`WEXITSTATUS`/`WTERMSIG` macros:

- `src/sandbox/mod.rs:178–182, 780`
- `src/sandbox/pty.rs:388`
- `src/sandbox/netns.rs:453`
- → `rustix::process::waitpid` returns a `WaitStatus` enum, removing the
  macros and the EINTR loop (nix `sys::wait::waitpid` equivalent).

### Other file/directory primitives

- `fdopendir`/`readdir`/`closedir` incl. the `mem::forget` double-close
  avoidance (`src/hostfs/anchored.rs:364–388`) → `rustix::fs::Dir` from an
  `OwnedFd` ✅ (nix `dir::Dir::fdopendir` equivalent; std `read_dir` takes a
  path, not an fd — not usable).
- `fstatvfs` (`src/hostfs/fuse_ops.rs:878–880`) → `rustix::fs::fstatvfs` ✅
  (nix `sys::statvfs` equivalent)
- `umount2(MNT_DETACH)` (`src/hostfs/server.rs:407`) →
  `rustix::mount::unmount` ✅ (nix `mount::umount2` equivalent)
- `mkfifo` (test-only: `src/audit/mod.rs:892`, `src/hostfs/anchored.rs:407`,
  `src/hostfs/fuselog.rs:143`) → `rustix::fs::mkfifoat(CWD, …)` ✅
  (nix `unistd::mkfifo`; std has no `mkfifo`)

### Sockets / peer credentials

- `SO_PEERCRED` with `mem::zeroed::<libc::ucred>` (`src/ipc/netmux.rs:565–585`)
  → `rustix::net::sockopt::get_socket_peercred` returns a fully initialized
  `UCred` (nix `sys::socket::getsockopt(PeerCredentials)` equivalent).
  std's `UnixStream::peer_cred()` is stabilized but its Linux pid field is
  still gated (the code's own comment notes this) — hence the hand-rolled
  call. ⚠️/✅ with rustix.
- `shutdown(fd, SHUT_WR)` on a *borrowed* fd number
  (`src/audit/ipc.rs:433`, test at `audit/mod.rs:816`) →
  `rustix::net::shutdown` exists (nix `sys::socket::shutdown` equivalent),
  but the current design keeps only the raw number while the reader task
  owns the fd; swapping would require sharing `Arc<UnixStream>`. ⚠️
- `fcntl(F_SETFD, FD_CLOEXEC)` — 12 near-identical sites:
  `waf/dns.rs:105,113,206,216`, `waf/http.rs:145,162`,
  `proxy/sandbox.rs:69,86`, `cli/control.rs:280`, and related. std has **no**
  per-fd CLOEXEC setter and no bind-time flag, so this is copy-pasted 12
  times today. → `rustix::fd::fcntl_setfd(fd, FdFlags::CLOEXEC)`, or set
  `SOCK_CLOEXEC` at creation via `socket2`. At minimum, collapse into one
  small audited helper. ✅ with a crate.

### Misc

- `getrandom(2)` with a hand-rolled EINTR loop (`src/cli/control.rs:368`) →
  `rustix::rand::fill` ✅ (no separate `getrandom` crate needed)
- `fcntl(F_DUPFD_CLOEXEC)` (`anchored.rs:74–79`) → `OwnedFd::try_clone()` ✅ (std)
- `sethostname` (`src/sandbox/mod.rs:305`) → `nix::unistd::sethostname` —
  nix-only; rustix has no wrapper. One raw `libc::sethostname` call is fine
  to keep.

---

## Single-crate analysis: do we need both nix and rustix?

No. Counted by unsafe libc **call sites** in `src/` (~260 total):

| Category | Sites | Examples |
|---|---|---|
| Covered by **both** nix & rustix | ~181 | close 32, `_exit` 16, fcntl 12, identity getters ~30, `*at()` tails ~18, dup/dup2, socketpair, pty, termios, poll, pipe, Dir, umount2, socket/shutdown/peercred |
| **rustix only** | ~15 | `mount` 10 (nix dropped it), safe `chroot` 1, `ioctl_tiocsctty` 1, winsize 2, `getrandom` 1 |
| **nix only** | ~15 | sigaction 4, sigprocmask 3, NNP prctl 4, `execvp` 1, `mkdtemp` 1, `sethostname` 1, `cfmakeraw` 1 |
| **Neither** (inherent, see ❌) | ~49 | fork 7, unshare 6, atexit 3, raw `syscall` 28 (mostly intentional seccomp probes), IFFLAGS ioctls 2, TIOCNOTTY 1, capbset/ambient prctl 2 (→ `caps`) |

- **rustix alone**: ~196 sites safely wrapped; the 15 nix-only stragglers are
  signal setup (deliberately hand-rolled anyway, see ⚠️ section), NNP (a
  one-line raw `prctl`), and three one-off helpers.
- **nix alone**: also ~196 sites, but it **cannot** cover the mount tree
  (nix deliberately dropped `mount`) or provide safe `chroot`/`TIOCSCTTY` —
  the 15 rustix-only sites are all in the security-critical sandbox core.
- **Conclusion**: pick `rustix` as the sole system crate. nix would only pay
  off if the typed `nix::sys::signal` wrappers are valued enough to justify a
  second dependency; the remaining nix-unique one-offs (`mkdtemp`,
  `sethostname`, `cfmakeraw`) are small enough to keep raw or inline.

Caveat: `rustix::mount` and the `net` module shipped recently (1.0/1.1);
when adding the dependency, verify the feature set compiles and that the
`MountFlags`/`MountPropagationFlags` types map cleanly onto the existing
`MS_*` combinations in `mod.rs`.

---

## ⚠️ Closest match exists — swap is a redesign, not a drop-in

### Dirfd-relative traversal (`src/hostfs/anchored.rs` — the security core)

The component-wise, no-follow `openat` walk (`RootDir::walk`,
`anchor_parent`) plus the `*at()` tails (`fstatat`, `readlinkat`, `faccessat`
with `AT_EMPTY_PATH`, `fchmodat`, `fchownat`, `utimensat`, `mkdirat`,
`unlinkat`, `renameat`, `linkat` — `anchored.rs` and `fuse_ops.rs`):

- **`cap-std`'s `cap_std::fs::Dir`** implements exactly this anti-escape,
  dirfd-relative, no-follow resolution model — the closest "does this
  already" answer. But it resolves walks rather than exposing raw `*at()`
  primitives, and has no `O_PATH`, no `faccessat(AT_EMPTY_PATH)`, no flagged
  `fchmodat`/`utimensat`/`linkat` — the setattr/access tails would still need
  `nix`/`rustix` (which cover each call safely).
- **`openat` crate**: `Dir` with dirfd-relative ops; no `O_PATH`, no flag
  control on the tails.
- Verdict: individually replaceable, architecturally not. Keep hand-rolled
  unless there is a specific motivation (e.g. formal review of the walk).

### Signal handling (`pty.rs:245–360`, `hostfs/server.rs:45–162`)

`sigaction` install/restore and `sigprocmask` block-around-fork have typed
`nix::sys::signal` wrappers, but the handler bodies (self-pipe write,
re-raise) must remain async-signal-safe raw `write`/`kill` regardless.
The fork-context discipline is manual either way. Keep.

---

## ❌ No safe equivalent — correctly unsafe, keep

### Namespace / mount / chroot (`src/sandbox/`, `src/hostfs/server.rs`)

- All `unshare` calls (`mod.rs:526,538,645,648,952`; `netns.rs:288–296`):
  no crate offers a *safe* `unshare` (`nix::sched::unshare` is itself an
  unsafe-marked thin wrapper; rustix has none) — no gain, and the
  flag-ordering comments argue against hiding it. Keep raw.
- All `mount` calls (`mod.rs:909–1271`: tmpfs, MS_SLAVE propagation, root
  tmpfs, hostfs bind, hardened remounts, procfs, devpts, device-node binds;
  `server.rs:367` remount): **the first pass said no crate covers these —
  that is outdated.** `rustix::mount` (new in rustix 1.x) exposes safe
  `mount`, `mount_bind`, `mount_change`, `mount_remount`, `unmount`, and
  `pivot_root` with `MountFlags`/`MountPropagationFlags` types. Technically
  replaceable; whether to swap is a design choice — the hand-rolled version
  keeps the flag-ordering and mount-order comments next to each call, which
  has security-review value. Recommended: swap to `rustix::mount` (typed
  flags catch mistakes the raw ints do not), keeping the comments.
- `chroot` + `chdir` (`mod.rs:1410–1435`): the chroot *is* the security
  backstop, but the call itself is no longer inherently unsafe —
  `rustix::process::chroot` is a safe wrapper (fails with EPERM if
  unauthorized). The chdir could be `std::env::set_current_dir`, but the
  fork-context makes libc `chdir` equally fine. Replace chroot with rustix;
  keep the raw chdir if preferred.
- `umount2` remount hardening in `server.rs:407` is rustix-able
  (`mount::unmount`); the surrounding mount tree likewise.

### Process lifecycle

- `fork()` + `execvp` (`mod.rs:689, 1580`; `netns.rs:116, 364`;
  `hostfs/server.rs:133`; `waf/host.rs:872–883` test): the child must exec
  into an already-namespaced, mounted process — `std::process::Command`
  cannot express this, and `nix::unistd::fork` is unsafe and discouraged.
  Tokio runtimes are deliberately created *after* every fork (`netns.rs:35`
  docs).
- `syscall(SYS_close_range, …)` + close sweep (`mod.rs:1538–1552`): no
  crate exposes the CLOSE_RANGE semantics used here.
- `syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING)` (`mod.rs:1467`): the
  `keyutils` crate is niche; keep raw.
- `TIOCSCTTY` ioctl (`pty.rs:171–188`): ~~no crate wrapper~~ **superseded** —
  `rustix::process::ioctl_tiocsctty` exists as of rustix 1.1; see the PTY
  table above. No longer ❌.
- `SIOCGIFFLAGS`/`SIOCSIFFLAGS` on `ifreq` (`netns.rs:476–500`): no crate
  wrapper (netlink `rtnetlink` would be a redesign, not a swap).
- `libc::atexit` (`cli/control.rs:299`, `hostfs/session.rs:22`): the only
  mechanism for cleanup on `process::exit` paths and inside the abandoned
  FUSE-server process. Keep.
- `shutdown(SHUT_WR)` and fork-inherited `from_raw_fd` adoption
  (`netmux.rs:237`): design-inherent; all audited `from_raw_fd` uses
  (`audit/ipc.rs:207,210,297,452`, `audit/mod.rs:787`, `cli/control.rs:564`,
  `netmux.rs:237`) are ownership-transfer correct.
- Raw `close()` on co-owned fd numbers (`cli/control.rs:406,416`): deliberate
  co-ownership with the `Server`'s listener so the abstract socket name dies
  promptly; std cannot express this. Keep.

### Intentional raw syscalls in tests (`src/sandbox/tests.rs:137–440`)

Raw `syscall(SYS_socket/SYS_socketpair/SYS_getpid/SYS_getuid/
SYS_io_uring_setup)` probes exist to verify seccomp denial of *raw* syscall
numbers and the H1 garbage-bits regression. Wrapping them in libc calls would
defeat the test. Keep.

### Test-only `env::set_var` / `remove_var`

18 sites in `src/spec/tests.rs`, `src/spec/file.rs:948–954`,
`src/hostfs/fuselog.rs:147–149`. Edition 2024 makes these `unsafe`;
all are inside `#[test]`s and correctly marked. No safe std alternative —
the only fully-safe path is injecting an env-lookup closure into
`expand_str` instead of mutating the real environment (API change).
Acceptable as-is.

### Clean files

`src/connlimit.rs`, `src/main.rs` contain no unsafe.

---

## Priority if acting on this

1. **High value / low risk**
   - `caps` crate instead of the hand-built `SYS_capset` FFI (`mod.rs:861–868`).
   - `rustix::mount` for the mount tree (`mod.rs:909–1271`, `server.rs:367`,
     `server.rs:407`): typed `MountFlags` replace raw `MS_*` ints; keep the
     existing flag-ordering comments.
   - `rustix::process::chroot` (safe) at `mod.rs:1410–1435`.
   - One audited `set_cloexec` helper via `rustix::io::fcntl_setfd` replacing
     the 12 copy-pasted `fcntl(FD_CLOEXEC)` sites.
2. **Medium (mechanical, single `rustix` dependency)**
   - `rustix::process::waitpid` (`WaitStatus`) over `WIF*` macros.
   - `rustix::net::socketpair` + `rustix::pipe` and the identity getters.
   - `rustix::pty` + `rustix::termios` (+ `ioctl_tiocsctty`,
     `tcget/tcsetwinsize`) for `pty.rs`.
   - `rustix::rand::fill` for `cli/control.rs:368` (no `getrandom` crate).
   - `rustix::fs::Dir` for `anchored.rs:364–388`.
   - `rustix::io::dup2` / `process::setsid` in the exec paths.
3. **Optional nix (only if the typed wrappers are wanted)**
   - `nix::sys::signal` for `sigaction`/`sigprocmask` (7 sites) — otherwise
     keep raw, the handlers must stay async-signal-safe regardless.
   - `nix::sys::prctl::set_no_new_privs` (4 sites) — a one-line raw `prctl`
     is equally fine.
   - `nix::unistd::mkdtemp` (`mod.rs:74–87`) — otherwise keep the 14-line
     CString juggling.
4. **Skip** — fork, unshare, `execvp`, atexit, raw syscall probes, IFFLAGS
   ioctls, TIOCNOTTY. That unsafe is the product.