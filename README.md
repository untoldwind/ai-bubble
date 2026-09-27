# ai-bubble

A minimal Rust reimplementation of the basic functionality of
[bubblewrap](https://github.com/flatpak/bubblewrap) (`bwrap`), built as a
simple CLI on top of [clap](https://docs.rs/clap).

The sandbox is configured through a **spec file** (JSON), not through
command-line options. By default ai-bubble looks for `.ai-bubble/spec.json`
in the current directory; `--spec-dir DIR` points it at a different spec
directory. The spec directory itself (and everything in it — `spec.json`,
the env file, the project cache) is **always hidden** from the sandboxed
command: ai-bubble appends an internal `hide` mapping for it, so even a
mapping that mirrors the directory containing it cannot expose it.

## Spec file format

All fields are optional. A missing `.ai-bubble/spec.json` means: empty tmpfs
root, no mounts at all (not even procfs), and the host network.

```json
{
  "hostfs": { "mappings": [
    { "type": "ro",    "glob": "/usr" },
    { "type": "bind",  "path": "/etc" },
    { "type": "dev" },
    { "type": "tmpfs", "path": "/tmp", "perms": "1777" }
  ] },
  "net": { "isolated": true, "allow": ["example.com:443"] },
  "env": { "values": { "PATH": "${PATH}", "HOME": "${HOME}" } },
  "cwd": "/work"
}
```

- `env` — the sandbox's **isolated environment**: the *complete* set of
  environment variables the command sees. Nothing is inherited from the
  host; a missing (or empty) `env` section means the command runs with an
  empty environment. `values` maps variable names to values, which may
  reference host variables as `${VAR}`, so the variables the sandbox
  needs are copied over explicitly, one by one (e.g.
  `"PATH": "${PATH}"`). Referencing an unset host variable is an error.
  Optionally, `env_file` names a dotenv-style file (relative to the spec
  directory) whose `KEY=VALUE` lines (comments, quotes and an optional
  `export` prefix are supported) are loaded as well; entries already
  present in `values` win over the file

- `cwd` — the command's **working directory inside the sandbox**
  (default: `/`). An absolute sandbox path without `..` components; it
  may reference host variables as `${VAR}` like the path-like mapping
  fields. The directory must exist inside the sandbox (e.g. via a
  hostfs mapping or a mount-point mapping such as `tmpfs`) — nothing
  is created automatically, and a missing directory is a hard error
  right before exec

- `hostfs.mappings` — an **ordered** array of mappings, each selecting
  host paths for one treatment (`type`); see below for the details.
  The mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`)
  name an absolute path exactly and do two things at once: expose the
  path empty in the host filesystem (a mount point) and stack the
  corresponding mount op on top of it inside the sandbox —
  `dev` a minimal `/dev` (defaulting to `path: "/dev"`), `tmpfs` a fresh
  tmpfs (with optional `perms` and `size`, like bwrap's `--tmpfs`),
  `proc` a fresh procfs instance (defaulting to `path: "/proc"`), and
  `bind` the host path `src` at `dest` (which defaults to `src`). Bind
  mounts bypass the FUSE mirror's permission model, so they are mounted
  **read-only** unless `"rw": true` is set. The
  `symlink` mapping creates a symlink at `dest` pointing to `src` (like
  bwrap's `--symlink`; `src` may be relative to the sandbox root) without
  touching the host filesystem. The `redirect-ro`/`redirect-rw` mappings
  show the host file or directory `source` at the sandbox path `dest` —
  a lightweight bind routed through the FUSE host filesystem (no mount
  happens; `source` may be relative to the spec directory). All generated
  ops are applied in
  mapping order, exactly like bwrap's command line
- `proc` — there is no separate `proc` config: procfs is only mounted
  where the spec asks for it, with a `{"type": "proc", "path": ...}`
  mapping (mounted with `MS_NOSUID|MS_NOEXEC|MS_NODEV`)
- `net.isolated` — run the command in a fresh **network namespace**
  (no interfaces besides loopback, which ai-bubble brings up) while the
  ai-bubble process stays on the host and acts as a **TCP proxy**
- `net.allow` — allow-list for the proxy; entries are `HOST[:PORT]`, and an
  entry host may start with `*.` for a subdomain wildcard (`*.github.com`
  matches `api.github.com` but not `github.com`).
  Empty or missing means every target is allowed
- **Environment variables** — the path-like mapping fields (`glob`,
  `path`, `src`, `dest`, `source`) may reference environment variables
  as `${VAR}` (e.g. `"glob": "${HOME}/project"`); the references are
  expanded while the spec is read, so everything downstream only ever
  sees the fully expanded text. Other fields (`net.allow`, ...) are
  never expanded. Referencing an unset variable is an error; only the
  `${VAR}` form is recognized (a bare `$` stays untouched)
- `hostfs.mappings` — an **ordered** array of mappings, each selecting
  host paths for one treatment (`type`): `ro`, `rw` or `hide` select
  paths with a **glob** pattern of absolute host paths (`"glob"`);
  `empty` names a single absolute path (`"path"`) exactly. Mirrored
  paths are exposed inside the sandbox at their absolute host paths
  (`/etc/passwd` → `/etc/passwd`). A mapping that names a directory
  exactly (`/usr/share/doc`) mirrors that directory **recursively**; `**`
  spans directory levels (`/usr/share/**/*.rs`). Ancestor directories are
  shown so the tree is navigable down to the matched leaves.
  **Order matters**: when a path matches several mappings, the **last**
  matching mapping decides — e.g. mirror `/etc` and then hide
  `/etc/passwd`. A hidden directory hides its whole
  subtree, too. `ro` mirrors the matched paths **read-only** (they can
  be read, and executed when the underlying file has the exec bits);
  `rw` mirrors them **read-write** — content, metadata, creation and
  deletion are passed through as far as the *real* host file or
  directory permissions allow, and only if the last mapping naming the
  path (or its nearest mirrored ancestor) says `rw`. `empty` exposes
  the named path **empty**: as an empty, unwritable directory (mode
  0555) when the path is (or would be) a directory — or as an **empty
  file** when it matches a real file. Empty paths take
  *precedence* over the mirror: nothing below them is visible, and they
  are shown even when a mirror mapping (or the real host path) covers
  them. Their purpose is to provide mount points for the mount-point
  mappings (`dev`, `tmpfs`, `proc`, `bind`) — see below. Missing
  or empty mappings expose nothing.

Everything on the command line (optionally after a `--` separator) is the
command to run inside the sandbox:

```sh
ai-bubble -- /bin/sh
ai-bubble --spec-dir custom /bin/sh
```

### Equivalence with bwrap's namespace flags

Every run of ai-bubble unshares the same namespaces as
`bwrap --unshare-all` (user, cgroup, ipc, pid, uts, mount). The only knob
is the network namespace, which corresponds to bwrap's `--share-net`:

- without `net.isolated` → like `bwrap --unshare-all --share-net`
  (everything unshared, but the command keeps the host network)
- with `"net": { "isolated": true }` → like plain
  `bwrap --unshare-all` (a fresh network namespace with only a brought-up
  loopback interface — bwrap's `loopback_setup()` — plus ai-bubble's proxy)

Not covered by that equivalence (see "Notes" below): ai-bubble's
`/proc` mounts are always fresh procfs instances and the command always
runs as PID 1 of its PID namespace, mirroring `--as-pid-1`.

`--die-with-parent` is on by default (it uses `PR_SET_PDEATHSIG`, like
bwrap's option of the same name): the sandboxed command is killed with
SIGKILL when ai-bubble — or ai-bubble's parent — dies. Pass
`--no-die-with-parent` to switch this off. Every process in the chain
(launcher, isolated-net parent and connector, sandboxed child) sets it for
itself, because the setting does not survive fork.

## How it works

Like bwrap, the tool:

1. Sets `PR_SET_NO_NEW_PRIVS`.
2. Unshares a **user namespace**, a **cgroup namespace** (like bwrap's
   `--unshare-cgroup-try`: only when the kernel supports it, and only because
   it can be combined with the user-namespace unshare — afterwards the
   privilege to create one would be gone) and a **mount namespace**.
3. Maps the real uid/gid to an unprivileged id (`65535`) inside the new
   user namespace — the command therefore runs as a uid/gid that does not
   exist on the host, never as (namespace) root.
4. Unshares fresh **IPC**, **UTS** and **PID namespaces** and forks: the
   command becomes **PID 1** of the new PID namespace (like bwrap's
   `--unshare-pid` + `--as-pid-1`), while the ai-bubble process supervises it
   and forwards its exit status.
5. Marks the mount tree as a **slave**, so nothing mounted inside
   propagates back to the host.
6. Creates a fresh **tmpfs** as the sandbox root — unless the spec has
   `hostfs` mappings, in which case the FUSE filesystem itself becomes
   the root (see below).
7. Applies the filesystem ops (all of them generated by the `hostfs`
   mappings) **in the
   order they were given** (order matters, exactly like bwrap). Because
   the PID namespace is created before the mounts (the mounting process
   is PID 1 of it), a fresh procfs instance only ever shows the
   sandbox's own processes — never host processes.
8. Drops **all capabilities** (permitted, effective, inheritable, ambient
   and the bounding set — like `bwrap --cap-drop ALL`) and `chroot`s into
   the sandbox root, then `execvp`s the command.

The sandbox root starts empty: only what you bind in exists. The standard
bubblewrap example works the same way here:

```json
{
  "hostfs": { "mappings": [
    { "type": "bind", "src": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" },
    { "type": "symlink", "src": "usr/lib64", "dest": "/lib64" },
    { "type": "symlink", "src": "usr/bin", "dest": "/bin" }
  ] }
}
```

`ai-bubble -- /bin/sh` then reproduces:

`/lib`, `/lib64` and `/bin` are symlinks created inside the sandbox, pointing
into the bound `/usr` — exactly like the corresponding
[bubblewrap](https://github.com/flatpak/bubblewrap) example:

```sh
bwrap --bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --symlink usr/bin /bin  /bin/sh
```

Notes:

- Bind/symlink destinations are created on the tmpfs root as needed. If a
  destination lies inside an earlier bind mount, it must already exist there
  (ai-bubble does not create directories inside a bind mount).
- The fresh procfs is mounted with `MS_NOSUID|MS_NOEXEC|MS_NODEV`. Unlike
  bwrap, the `/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq` and `/proc/bus`
  "cover" mounts are not applied; the command runs with no capabilities at
  all, which already keeps it from writing there.
- The command is PID 1 of its PID namespace. Orphaned children are
  re-parented to the command itself (as with bwrap's `--as-pid-1`).
- The temporary host directory backing the tmpfs root is cleaned up when
  the process exits, but the empty staging directory may remain in `/tmp`.

## Isolated networking

With `net.isolated = true` the sandboxed command gets a network namespace that
is completely isolated from the host (only a freshly brought-up loopback
interface; the sandbox also gets its own UTS namespace) — while the
ai-bubble process tree provides a proxy **inside** that namespace, so the
command can reach the outside world transparently.

This mode is the network part of `bwrap --unshare-all`: it unshares the
network namespace like `bwrap --unshare-net` (loopback up, nothing else).
Without it, ai-bubble corresponds to `bwrap --unshare-all --share-net`.

### Architecture

Since `execve` replaces the process, ai-bubble forks into three roles:

- **connector** (stays in the host network namespace): answers proxy
  requests with real TCP connections (name resolution included, so DNS
  also stays outside), and forwards the final exit status.
- **proxy** (`P`): unshares user + network + cgroup + UTS namespaces, brings
  up loopback, and listens on **`127.0.0.2:3128`** as an **HTTP CONNECT
  proxy**. It forks the actual sandboxed command.
- **sandbox** (`C`): unshares the mount namespace, builds the tmpfs
  root and execs COMMAND.

The proxy and the command share the network namespace, which means any
TCP connection to `127.0.0.2` inside the sandbox lands on the proxy —
no veth pairs, no root, no host `CAP_NET_ADMIN` needed. The connector
dials real targets from the host side over Unix-domain sockets (which
cross network namespaces via the filesystem); the socket directory is
bind-mounted at `/net` inside the sandbox.

The sandbox is still network-isolated: the namespace has no interfaces
besides loopback and no routes to the host, so direct connections
(anything that ignores the proxy) simply fail. Targets must pass the
`net.allow` filter in the connector.

### Usage

```sh
ai-bubble --spec-dir isolated -- /bin/sh
```

with `isolated.json`:

```json
{
  "hostfs": { "mappings": [
    { "type": "bind", "src": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" }
  ] },
  "net": { "isolated": true, "allow": ["example.com:443"] }
}
```

Standard tools automatically use the proxy, because the sandbox sets the
following variables in its (isolated) environment — entries from the
spec's `env` section win over these:

- `http_proxy` / `HTTP_PROXY` = `http://127.0.0.2:3128`
- `https_proxy` / `HTTPS_PROXY` = same
- `all_proxy` / `ALL_PROXY` = same
- `RS_BUBBLE_PROXY` = `/net/sock` (raw protocol, see below)

For example, inside the sandbox:

```sh
curl -si https://example.com/ | head -1
```

### Raw protocol on /net/sock

For tools that don't speak HTTP CONNECT, connect a Unix socket to
`/net/sock`, send the target as one line `host:port\n`, read one status
byte (`K` = connected, `E` = failed or denied), and the connection
becomes a raw bidirectional pipe:

```sh
exec 3<>/net/sock
printf 'example.com:443\n' >&3
head -c 1 <&3   # 'K' if the connector connected
```

`net.allow` entries (`HOST[:PORT]`) restrict both proxy paths;
entries without a port allow any port on that host. Without them, every
target is allowed.

Exit status: the connector forwards the sandbox's status; a killed
command yields `128+signal`.

Note on trust: the proxy (`P`) and the command share one user namespace,
so `P`'s files are visible to the command's (non-root) uid — but the
command runs with **no capabilities at all**, so it cannot exercise the
namespace privileges that `P` keeps (loopback setup, ...). In the worst
case a hostile command could kill `P` (cutting its own network access —
it gains nothing else). Fully separating them would require an additional
namespace split.

## The host filesystem as the sandbox root

With `hostfs` mappings, the FUSE filesystem itself becomes the sandbox
root instead of a plain tmpfs (and it is not mounted at `/host`): everything
the mirror exposes appears at its absolute host path, and the ops (`dev`,
`tmpfs`, proc, binds) are mounted **on top of** it. A sandbox without any
`hostfs` mappings gets the plain tmpfs root and does not use FUSE at all:

```json
{
  "hostfs": {
    "mappings": [
      { "type": "ro", "glob": "/bin" },
      { "type": "ro", "glob": "/etc" },
      { "type": "ro", "glob": "/lib" },
      { "type": "ro", "glob": "/lib64" },
      { "type": "ro", "glob": "/usr" },
      { "type": "dev" },
      { "type": "tmpfs", "path": "/tmp", "perms": "1777" },
      { "type": "proc" }
    ]
  }
}
```

- Mappings are standard globs (`*`, `?`, `[...]`, `**`); they must be
  absolute, and `*` does not cross directory separators (use `**` for
  that). A mapping that names a directory exactly mirrors it with its
  whole subtree. The mapping `type` is `ro` (the matched paths are
  mirrored read-only), `rw` (they are mirrored read-write — writes,
  creates and deletes are passed through to the real host file system as
  far as its permissions allow), `hide` (they are hidden; a hidden
  directory hides its whole subtree) or `empty` (the named path is
  exposed empty — an empty, unwritable directory, or an empty file when
  it matches a real file) or `redirect-ro`/`redirect-rw` (the absolute
  path `dest` is named exactly and shows the host path `source` in its
  place — a lightweight bind routed through the FUSE filesystem, so it
  is monitored and permission-checked like any mirrored path; no mount
  happens, and `source` may be relative to the spec directory). The
  mappings are tried in the order they are
  written and the **last** match wins — put more specific mappings after
  broader ones, e.g. mirror `/etc` and then hide `/etc/ssh`.
- Glob semantics: `**` spans directory levels only as a **whole**
  component — inside a longer component (`**secret**`) it degrades to `*`
  and matches only direct children of the named directory (use
  `dir/**/*secret*` for "any entry whose name contains `secret` anywhere
  below `dir`"). Matching is **case-sensitive** (`*secret*` does not match
  `My-Secret.txt`). A path component that is not valid UTF-8 can never
  match a pattern, so such paths are simply not visible and not writable
  through the mirror.
- Hard links (`ln`) require **both** names to be writable, so a read-only
  mapped file cannot be linked into a writable path and written through
  the link (the write would follow the host inode and bypass the source's
  `ro` permission).
- The host tree is **not** crawled at startup: every FUSE operation
  matches the requested path against the patterns on the fly, so a large
  host tree costs nothing and only the accessed paths are touched.
- Host **symlinks are never followed**: a mirrored symlink is visible only
  as a symlink (`readlink` shows its target); opening it for reading or
  writing fails with `ELOOP`, so a mirrored symlink can never expose the
  content of a path the mappings do not select. The same holds for
  directory listings, `statfs` and access checks.
- Writes only go through where a mapping says `rw`: the last mapping
  naming the path (or its nearest mirrored ancestor — an exactly-named or
  `**`-covered directory is a recursive mirror, so its permission governs
  everything below it) decides, and the **real** host file or directory
  permissions still apply on top. The mount itself is read-only unless
  some mapping says `rw`.

### The "empty" mappings are the mount points

```sh
ai-bubble --spec-dir hostfs -- /bin/sh
```

The mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`) expose
their path as an empty, unwritable (mode 0555) directory — a pure mount
point, taking *precedence* over the mirror (nothing below it is visible,
and no mirror pattern can bring content back). It must exist for every
mount point, because ai-bubble does not create directories on the FUSE
filesystem itself — which is exactly why the mount-point mappings provide
it automatically. The `dev` and `tmpfs` mounts (and the fresh procfs,
from a `proc` mapping or `proc` op) then cover
the empty dirs, giving a writable `/dev` and `/tmp` and a
sandbox-only `/proc` on top of the host view.

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- Run tests: `cargo test`

## Status

Starter project — the spec file's `hostfs.mappings` (ro, rw, hide, empty,
dev, tmpfs, proc, bind, symlink, redirect-ro, redirect-rw), `net.isolated`
and `net.allow` are
implemented. Namespace-wise ai-bubble always unshares user, cgroup, ipc,
pid, uts and mount namespaces (see "Equivalence with bwrap's namespace
flags" above); the network namespace is unshared with `net.isolated`.
Natural next steps would be further bubblewrap option coverage.
