# Security Audit: rs-bubble

Date: 2026-09-27
Scope: full source audit plus a live evaluation of the running sandbox.

Context discovered during the audit: **the auditing session itself ran inside
rs-bubble** (uid_map `65535 → 1000` = `SANDBOX_ID`, FUSE root filesystem, no
capabilities, `NoNewPrivs`, own pid/ipc/net/uts/cgroup namespaces). The
"sandbox probe" below is therefore a live evaluation of the audited tool
running under its own spec (`.rs-bubble/spec.json`).

## Findings

### 1. `bind` mappings bypass the FUSE permission model — and are always read-write (High, possibly by design)

`Op::Bind` performs a plain `MS_BIND` with no `MS_RDONLY` (`src/sandbox.rs`,
the `Op::Bind` arm of `mount_and_exec`). The FUSE mirror's `empty` mount
point is stacked under it, so the host path is exposed with its real
permissions and *no* pattern-based write policy. There is no `bind-ro`
mapping variant.

The live spec's `{"type": "bind", "path": "/etc"}` yields `ext4 rw` on
`/etc` (visible in `/proc/mounts`): sandbox processes can write any
user-1000-owned file under the host's `/etc`, and those writes never pass
through the mirror that the documentation says "monitors" everything. Not
exploitable on this particular host (no user-1000-owned files in `/etc`),
but it is the only host path reachable outside the FUSE policy.

**Recommendation:** add a readonly bind variant (`bind-ro`) and/or mount
with `MS_RDONLY` by default; at minimum document that `bind` grants full
read-write host access bypassing the mirror.

### 2. FUSE mirror follows symlinks on open/read/write (Medium)

`read`/`write`/`create` re-open the redirected host path with default flags
(`src/hostfs/mod.rs`, `HostFs::read`, `HostFs::write`, `HostFs::create`),
which follows symlinks, while `attr` uses `symlink_metadata` (no-follow).
A mirrored `ro` symlink therefore exposes its *target's* content (e.g.
`/etc/foo.conf → /etc/secret`) even when the target matches no pattern —
breaking the "only mapped paths are visible" guarantee. `utimensat` and
`lchown` correctly use no-follow semantics, but `setattr`'s size change and
the write path do not.

**Recommendation:** open with `O_NOFOLLOW` and re-check, or explicitly
document that symlink targets are followed outside the mirror policy.

### 3. TOCTOU between pattern check and host open (Medium)

`exists()`/`writable()` are evaluated, then the host file is opened in a
separate step. A concurrent *host* process can swap the checked file for a
symlink between check and open, redirecting a sandbox write to an arbitrary
user-1000 path on the host. The sandbox itself cannot create symlinks
through the FUSE mirror (no symlink op is implemented), which limits
in-sandbox exploitation, but a host-side process racing the sandbox can.

**Recommendation:** open with `O_NOFOLLOW | O_PATH`, verify the resulting
inode matches the checked one, then reopen for real IO via `/proc/self/fd`.

### 4. Glob matcher DoS from inside the sandbox (Low)

`Pattern::match_from` branches exponentially on `**`
(`src/hostfs/pattern.rs`). A spec with many `**` patterns combined with
attacker-chosen deep paths, submitted from inside the sandbox through FUSE,
can burn CPU in the FUSE server process.

**Recommendation:** memoize `(pattern, path-component-index)` results or
bound the `**` expansion.

### 5. Empty allow-list means allow-everything (Low, design)

`net.allow` missing or empty means unrestricted egress (`src/proxy.rs`,
`target_allowed`). A security tool should arguably fail closed. Also: the
allow-list is hostname-based and DNS resolves on the host side
(`TcpStream::connect`), so an allowed hostname resolving to an attacker
IP is inherently permitted — worth documenting.

### 6. `sub_path` traversal in cache mappings (High — spec-level escalation)

`sub_path` (`src/spec/hostfs.rs`) strips only the leading `/` of a
`session-cache`/`project-cache` path. Validation rejects relative paths and
wildcards but **not `..` components**. A mapping such as

```json
{ "type": "session-cache", "path": "/../etc" }
```

maps the writable redirect onto `<tmpdir>/../etc` — a host directory
*outside* the per-run tmp root — as a redirect-rw. Same for `project-cache`
relative to the spec directory's `cache` folder.

**Recommendation:** reject `..` (and `.`) components in cache mapping paths,
or normalize and verify the result stays under the cache root.

### 7. Environment hygiene (Info)

The live spec copies `NEBIUS_TOKEN`/`TOGETHER_AI_TOKEN` into the sandbox;
any sandboxed process can read and exfiltrate them through the allowed
network. Accepted for this use case, but worth being deliberate about.

### 8. Housekeeping (Info)

* Abrupt `SIGKILL` leaves `/tmp/rs-bubble-net.*`, `*.host.*`, `*.cache.*`
  and the tmpfs sandbox-root directory behind (empty, mode 0700 — litter
  only; `atexit` handles the clean path).
* No seccomp filter is installed in the sandbox (an opportunity; hardened
  bwrap setups add one).
* No hardcoded secrets in the repo; `build.rs` is clean; no CI workflows
  present to review.

## Sandbox probe (passive, read-only)

Verified isolation of the running sandbox:

* Fresh user/pid/ipc/net/uts/cgroup namespaces.
* uid/gid 65535 — an id mapped from the caller, not a host account.
* `CapEff = 0`, `CapBnd = 0`, `NoNewPrivs = 1`.
* `cgroup` namespace shows `0::/`.
* Loopback-only network namespace behind the HTTP CONNECT proxy on
  `127.0.0.2:3128`; the Unix-socket connector on `/net/sock` re-checks the
  allow-list, so no bypass found there.
* Isolated environment: only spec-listed variables plus the proxy
  variables are present.
* Fresh procfs instance bound to the sandbox pid namespace.
* The only escape-shaped surface found is finding 1: the `bind /etc` mount
  (`ext4 rw` in `/proc/mounts`) is real host filesystem outside the FUSE
  mirror's policy.

## Tooling limitation

`cargo test` cannot run inside this sandbox: the rustup home directory is
outside the mirror and not writable. If in-sandbox builds are wanted, add
`redirect-rw` mappings for `~/.rustup` and `~/.cargo`.

## Priority order

1. Fix `sub_path` traversal (finding 6).
2. Decide on `bind-ro` / readonly binds (finding 1).
3. Close the symlink-follow gap (finding 2), ideally together with the
   TOCTOU fix (finding 3).
4. Fail-closed allow-list semantics (finding 5).
5. Glob DoS hardening (finding 4).
