# rs-bubble

A minimal Rust reimplementation of the basic functionality of
[bubblewrap](https://github.com/flatpak/bubblewrap) (`bwrap`), built as a
simple CLI on top of [clap](https://docs.rs/clap).

The sandbox is configured through a **spec file** (JSON), not through
command-line options. By default rs-bubble looks for `.rs-bubble.json` in
the current directory; `--spec FILE` points it at a different file.

## Spec file format

All fields are optional. A missing `.rs-bubble.json` means: empty tmpfs
root, a fresh procfs at `/proc`, and the host network.

```json
{
  "ops": [
    { "type": "bind",    "src": "/usr", "dest": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" },
    { "type": "symlink", "src": "usr/lib64", "dest": "/lib64" },
    { "type": "symlink", "src": "usr/bin", "dest": "/bin" }
  ],
  "proc": "/proc",
  "net": { "isolated": true, "allow": ["example.com:443"] },
  "hostfs": { "patterns": { "/etc/*.conf": "mirror" } }
}
```

- `ops` — the mount operations, applied **in this order** (order matters,
  exactly like bwrap):
  - `{"type": "bind", "src": ..., "dest": ...}` — bind-mount `SRC` at
    `DEST` inside the sandbox (read-write, non-recursive)
  - `{"type": "symlink", "src": ..., "dest": ...}` — create a symlink at
    `DEST` pointing to `SRC` (mirrors bwrap: fails if `DEST` exists and is
    not the identical symlink)
  - `{"type": "dev", "dest": ...}` — mount a minimal **`/dev`** at `DEST`
    (like bwrap's `--dev`): the standard device nodes (`null`, `zero`,
    `full`, `random`, `urandom`, `tty`), the stdio symlinks, `/dev/shm`,
    a fresh devpts at `DEST/pts` with the `ptmx` symlink, and
    `/dev/console` bound to the host tty when stdin is one
  - `{"type": "tmpfs", "dest": ..., "perms": ..., "size": ...}` — mount a
    fresh **tmpfs** at `DEST` (like bwrap's `--tmpfs`, with
    `MS_NOSUID|MS_NODEV`). `perms` is the octal mode of the mount root
    (number or string, default `0755`, like bwrap's `--perms`) and `size`
    the maximum size in bytes (bwrap's `--size`); both are optional
- `proc` — where to mount a **fresh procfs instance**
  (like bwrap: `MS_NOSUID|MS_NOEXEC|MS_NODEV`). If not given, a fresh
  procfs is mounted at `/proc` automatically
- `net.isolated` — run the command in a fresh **network namespace**
  (no interfaces besides loopback, which rs-bubble brings up) while the
  rs-bubble process stays on the host and acts as a **TCP proxy**
- `net.allow` — allow-list for the proxy; entries are `HOST[:PORT]`.
  Empty or missing means every target is allowed
- `hostfs.patterns` — an **ordered** mapping from **glob patterns** of
  absolute host paths to permissions (`"mirror"`, `"hide"` or
  `"empty"`). Mirrored paths are exposed read-only under **`/host`**:
  matched paths appear at the same absolute path below `/host`
  (`/etc/passwd` → `/host/etc/passwd`). A pattern that names a directory
  exactly (`/usr/share/doc`) mirrors that directory **recursively**; `**`
  spans directory levels (`/usr/share/**/*.rs`). Ancestor directories are
  shown so the tree is navigable down to the matched leaves.
  **Order matters**: when a path matches several patterns, the **last**
  matching pattern decides — e.g. `{"/etc": "mirror", "/etc/passwd":
  "hide"}` hides `/etc/passwd`. A hidden directory hides its whole
  subtree, too. `"empty"` exposes the matched paths **empty**: as an
  empty, unwritable directory (mode 0555) when the path is (or would be)
  a directory — or as an **empty file** when the pattern matches a real
  file. Empty paths take *precedence* over the mirror: nothing below
  them is visible, and they are shown even when a mirror pattern covers
  them. Their purpose is to provide mount points for the sandbox's ops
  (`dev`, `tmpfs`, `proc`, binds) — see the `hostfs.root` mode below.
  Missing or empty matches nothing.

Everything on the command line (optionally after a `--` separator) is the
command to run inside the sandbox:

```sh
rs-bubble -- /bin/sh
rs-bubble --spec custom.json /bin/sh
```

## How it works

Like bwrap, the tool:

1. Sets `PR_SET_NO_NEW_PRIVS`.
2. Unshares a **user namespace** and a **mount namespace**
   (this is what makes the sandbox work *without* root).
3. Maps the real uid/gid to an unprivileged id (`65535`) inside the new
   user namespace — the command therefore runs as a uid/gid that does not
   exist on the host, never as (namespace) root.
4. Unshares a fresh **PID namespace** and forks: the command becomes
   **PID 1** of the new namespace (like bwrap's `--unshare-pid` +
   `--as-pid-1`), while the rs-bubble process supervises it and forwards
   its exit status.
5. Marks the mount tree as a **slave**, so nothing mounted inside
   propagates back to the host.
6. Creates a fresh **tmpfs** as the sandbox root. (Experimental
   alternative: with `hostfs.root = true` the read-only FUSE filesystem
   itself becomes the root — see below.)
7. Applies the filesystem ops (the spec's `proc` and `ops`) **in the
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
  "ops": [
    { "type": "bind", "src": "/usr", "dest": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" },
    { "type": "symlink", "src": "usr/lib64", "dest": "/lib64" },
    { "type": "symlink", "src": "usr/bin", "dest": "/bin" }
  ]
}
```

`rs-bubble -- /bin/sh` then reproduces:

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
  (creating it would touch the host filesystem, which is read-only inside
  the namespace).
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
rs-bubble process tree provides a proxy **inside** that namespace, so the
command can reach the outside world transparently.

### Architecture

Since `execve` replaces the process, rs-bubble forks into three roles:

- **connector** (stays in the host network namespace): answers proxy
  requests with real TCP connections (name resolution included, so DNS
  also stays outside), and forwards the final exit status.
- **proxy** (`P`): unshares user + network + UTS namespaces, brings up
  loopback, and listens on **`127.0.0.2:3128`** as an **HTTP CONNECT
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
rs-bubble --spec isolated.json -- /bin/sh
```

with `isolated.json`:

```json
{
  "ops": [
    { "type": "bind", "src": "/usr", "dest": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" }
  ],
  "net": { "isolated": true, "allow": ["example.com:443"] }
}
```

Standard tools automatically use the proxy, because the sandbox sets:

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

## The host filesystem at /host

The sandbox always gets a read-only FUSE filesystem mounted at `/host`,
served by a separate forked rs-bubble process. It mirrors the paths
selected by the spec's ordered `hostfs.patterns` glob → permission map at
their absolute host paths:

```json
{
  "hostfs": {
    "patterns": {
      "/etc/*.conf": "mirror",
      "/usr/share/doc": "mirror",
      "/etc/secret.conf": "hide"
    }
  }
}
```

```sh
rs-bubble -- /bin/sh -c 'cat /host/etc/hosts'
```

- Patterns are standard globs (`*`, `?`, `[...]`, `**`); they must be
  absolute, and `*` does not cross directory separators (use `**` for
  that). A pattern that names a directory exactly mirrors it with its
  whole subtree. Each pattern's value is `"mirror"` (the matched paths are
  mirrored), `"hide"` (they are hidden; a hidden directory hides its
  whole subtree) or `"empty"` (they are exposed empty — an empty,
  unwritable directory, or an empty file when the pattern matches a real
  file). Since this is a JSON object, the patterns are tried in
  the order they are written and the **last** match wins — put more
  specific patterns after broader ones, e.g. mirror `/etc` and then hide
  `/etc/ssh`.
- The host tree is **not** crawled at startup: every FUSE operation
  matches the requested path against the patterns on the fly, so a large
  host tree costs nothing and only the accessed paths are touched.
- The mirror is read-only; writes to `/host` fail.

### Experimental: the host filesystem as the sandbox root

With `hostfs.root = true` the FUSE filesystem itself becomes the sandbox
root instead of being mounted at `/host`: everything the mirror exposes
appears at its absolute host path, and the ops (`dev`, `tmpfs`, proc,
binds) are mounted **on top of** it:

```json
{
  "hostfs": {
    "root": true,
    "patterns": {
      "/bin": "mirror",
      "/etc": "mirror",
      "/lib": "mirror",
      "/lib64": "mirror",
      "/usr": "mirror",
      "/dev": "empty",
      "/tmp": "empty",
      "/proc": "empty"
    },
  },
  "ops": [
    { "type": "dev", "dest": "/dev" },
    { "type": "tmpfs", "dest": "/tmp", "perms": "1777" }
  ],
  "proc": "/proc"
}
```

```sh
rs-bubble --spec hostfs-root.json -- /bin/sh
```

The `"empty"` entries are exposed by the FUSE filesystem as empty,
unwritable (mode 0555) directories — pure mount points, taking *precedence*
over the mirror (nothing below them is visible, and no mirror pattern can
bring content back). They must exist for every mount point, because the
read-only FUSE filesystem cannot have directories created on it. The `dev`
and `tmpfs` mounts (and the fresh procfs) then cover the empty dirs,
giving a writable `/dev` and `/tmp` and a sandbox-only `/proc` on top of
the read-only host view.

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- Run tests: `cargo test`

## Status

Starter project — the spec file's `ops` (bind, symlink, dev, tmpfs), `proc`,
`net.isolated`, `net.allow` and `hostfs.patterns` are implemented. Natural next steps would be
read-only binds, `--die-with-parent`, and `--unshare-all`.
