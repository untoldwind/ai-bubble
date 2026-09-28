# ai-bubble

The AI bubble that shall not burst.

Run agents in a sandbox similar to a [bubblewrap](https://github.com/flatpak/bubblewrap) (`bwrap`), but with a more focused setup.

Key differences:

* The sandbox is configured through a **spec file** (JSON), not through
  command-line options. By default ai-bubble looks for `.ai-bubble/spec.json`
  in the current directory; the global `--spec-dir DIR` option points it at a
  different spec directory. The spec directory itself (and everything in it —
  `spec.json`, the env file, the project cache) is **always hidden** from the
  sandboxed command: ai-bubble appends an internal `hide` mapping for it, so
  even a mapping that mirrors the directory containing it cannot expose it.
* Network access can be restricted through an embedded HTTP proxy, or —
  as an alternative — through a DNS/HTTP/HTTPS "waf" server triple
  inside the sandbox (not exposing the host network).
* Filesystem access is served by a FUSE filesystem that is configured via
  glob patterns. It also acts as a uid/gid translation layer so that the
  agent can run with its own uid (within its own user namespace).
* `--unshare-all`, `--cap-drop ALL` is pretty much the default (the only
  exception is the network namespace, which is only unshared when the spec
  asks for proxy mode).

## Usage

ai-bubble has sub-commands; `--spec-dir DIR` is a global option that selects
which spec directory to use (default: `.ai-bubble` in the current
directory).

```sh
# Run COMMAND inside the sandbox configured by the spec file.
# Everything after the first bare argument (or after `--`) is the command,
# and its own flags pass through verbatim:
ai-bubble run -- /bin/sh -c 'ls -l'
ai-bubble run /bin/sh
ai-bubble --spec-dir custom run -- /bin/sh

# List a host path (default: the current directory), annotated with the
# effective sandbox permission of the current spec, plus the spec's
# mappings themselves:
ai-bubble ls /etc

# Print the JSON Schema for the spec file (see below):
ai-bubble --print-schema > ai-bubble.spec.schema.json
```

Notes:

* A missing `.ai-bubble/spec.json` is fine: an **empty spec** is used (empty
  tmpfs root, no mounts, host network). An *explicit* `--spec-dir` that
  cannot be read is a hard error.
* `run` sets `PR_SET_PDEATHSIG` so the sandboxed command is killed with
  SIGKILL when ai-bubble — or ai-bubble's parent — dies (like bwrap's
  `--die-with-parent`, which is the default here); `run
  --no-die-with-parent` switches it off.
* A typical spec directory:

  ```
  .ai-bubble/
  ├── spec.json      # the sandbox spec (see below)
  ├── env            # optional dotenv-style file (spec: env.env_file)
  └── cache/         # backing store of `project-cache` mappings
  ```

### Editor support

The spec file's JSON Schema is generated at build time and printed by
`ai-bubble --print-schema`. Point an editor at it (e.g. VS Code's
`json.schemas` setting) to get completion and validation for
`.ai-bubble/spec.json`; the spec file may also name the schema itself:

```json
{ "$schema": "./ai-bubble.spec.schema.json", "hostfs": { "mappings": [] } }
```

The `$schema` field is accepted for editor tooling only and is otherwise
ignored.

## Spec file format

All fields are optional. A complete example:

```json
{
  "hostfs": { "mappings": [
    { "type": "ro",    "glob": "/usr" },
    { "type": "rw",    "glob": "${HOME}/project" },
    { "type": "dev" },
    { "type": "tmpfs", "path": "/tmp", "perms": "1777" },
    { "type": "proc" },
    { "type": "redirect-ro", "dest": "/etc/motd", "source": "motd" },
    { "type": "session-cache", "path": "/home/agent/.cache" },
    { "type": "project-cache", "path": "/home/agent/.local" },
    { "type": "symlink", "src": "usr/bin", "dest": "/bin" }
  ] },
  "net": { "mode": "proxy", "allow": ["example.com:443", "*.github.com"] },
  // ... or the alternative "waf" mode (see below):
  // "net": { "mode": "waf", "allow": ["example.com"] },
  "env": {
    "values": { "PATH": "${PATH}", "HOME": "${HOME}" },
    "env_file": "env"
  },
  "cwd": "/work"
}
```

- `env` — the sandbox's **isolated environment**: the *complete* set of
  environment variables the command sees. Nothing is inherited from the
  host; a missing (or empty) `env` section means the command runs with an
  empty environment. `values` maps variable names to values, which may
  reference host variables as `${VAR}`, so the variables the sandbox
  needs are copied over explicitly, one by one (e.g. `"PATH": "${PATH}"`).
  Referencing an unset host variable is an error. Optionally, `env_file`
  names a dotenv-style file (relative to the spec directory) whose
  `KEY=VALUE` lines (comments, quotes and an optional `export` prefix are
  supported) are loaded as well; entries already present in `values` win
  over the file. In proxy mode the proxy variables (see
  [Isolated networking](#isolated-networking)) are added to this
  environment, with the spec's `env` entries winning over them.

- `cwd` — the command's **working directory inside the sandbox**
  (default: `/`). An absolute sandbox path without `..` components; it
  may reference host variables as `${VAR}` like the path-like mapping
  fields. The directory must exist inside the sandbox (e.g. via a
  hostfs mapping or a mount-point mapping such as `tmpfs`) — nothing
  is created automatically, and a missing directory is a hard error
  right before exec.

- `hostfs.mappings` — an **ordered** array of mappings, each selecting
  host paths for one treatment (`type`); see below for the details.
  Everything the sandbox sees of the host filesystem comes from these
  mappings; when there are any, the FUSE filesystem itself becomes the
  sandbox root (see [The host filesystem as the sandbox
  root](#the-host-filesystem-as-the-sandbox-root)), otherwise the
  sandbox gets a plain tmpfs root and no FUSE filesystem is started.

- `net` — how the command reaches the network; see
  [Isolated networking](#isolated-networking).

### The mapping types

| `type` | fields | effect |
|---|---|---|
| `ro` / `rw` / `hide` | `glob` | mirror the matched paths read-only / read-write / hide them (with their subtree) |
| `empty` | `path` | expose the path **empty** — a mount point |
| `dev` | `path` (default `/dev`) | `empty` **plus** a minimal `/dev` mount (like bwrap's `--dev`) |
| `tmpfs` | `path`, `perms`, `size` | `empty` **plus** a fresh tmpfs (like bwrap's `--tmpfs`; `perms` is an octal mode, e.g. `"1777"` or `1777`, default `0755`; `size` is the maximum size in bytes) |
| `proc` | `path` (default `/proc`) | `empty` **plus** a fresh procfs instance showing only the sandbox's own processes |
| `bind` | `src`, `dest` (default `src`), `rw` | `empty` at `dest` **plus** a real bind mount of the host path `src` on top of it; read-only unless `"rw": true` |
| `redirect-ro` / `redirect-rw` | `dest`, `source` | show the host path `source` at the sandbox path `dest` — a lightweight bind routed through the FUSE filesystem (no mount happens; `source` may be relative to the spec directory) |
| `session-cache` | `path` | writable, backed by a **per-run temporary directory** (wiped when ai-bubble terminates) |
| `project-cache` | `path` | writable, backed by the spec directory's `cache` folder — **persists across runs** and is shared by every sandbox using that spec directory |
| `symlink` | `src`, `dest` | create a symlink at `dest` pointing to `src` (like bwrap's `--symlink`; `src` may be relative to the sandbox root) without touching the host filesystem |

All generated ops are applied in mapping order, exactly like bwrap's
command line.

### Mapping semantics

- `ro`, `rw` and `hide` select paths with a **glob** pattern of absolute
  host paths (`*`, `?`, `[...]`, `**`); every other mapping names
  absolute **paths** exactly (it makes no sense to glob a mount point).
  Mirrored paths are exposed inside the sandbox at their absolute host
  paths (`/etc/passwd` → `/etc/passwd`). A mapping that names a directory
  exactly (`/usr/share/doc`) mirrors that directory **recursively**; `**`
  spans directory levels (`/usr/share/**/*.rs`). Ancestor directories are
  shown so the tree is navigable down to the matched leaves.
- **Order matters**: when a path matches several mappings, the **last**
  matching mapping decides — e.g. mirror `/etc` and then hide
  `/etc/passwd`. Put more specific mappings after broader ones.
- `empty` exposes the named path **empty**: as an empty, unwritable
  directory (mode 0555) when the path is (or would be) a directory — or as
  an **empty file** when it matches a real file. Empty paths take
  *precedence* over the mirror: nothing below them is visible, and they
  are shown even when a mirror mapping (or the real host path) covers
  them. Their purpose is to provide mount points for the mount-point
  mappings (`dev`, `tmpfs`, `proc`, `bind`), which are shorthand for an
  `empty` mapping *plus* the corresponding mount op.
- `bind` mounts bypass the FUSE mirror's permission model entirely (the
  host path appears with its real permissions), so they are mounted
  **read-only** unless `"rw": true` is set. `redirect-ro`/`redirect-rw`,
  in contrast, live entirely inside the FUSE filesystem: no mount
  happens, and the redirected path is monitored and permission-checked
  like any mirrored path. A redirected path may be a file or a directory
  (which is then shown with its whole subtree); its `dest` must be
  absolute, free of wildcards and of `..` components. A relative
  `source` is resolved relative to the directory the spec file lives in.
- `session-cache` and `project-cache` are writable redirects with a
  managed backing directory. The sandbox path maps onto the backing
  directory plus its relative sub-path (e.g. `/home/a/.cache` →
  `<root>/home/a/.cache`), so several cache mappings share **one**
  backing directory without colliding. `session-cache` backs onto a
  fresh tmp directory per run, wiped once ai-bubble terminates;
  `project-cache` backs onto `cache/<path>` below the spec directory,
  which persists across runs.
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
- Writes only go through where a mapping says `rw` (or a redirect says
  `redirect-rw`): the last mapping naming the path (or its nearest
  mirrored ancestor — an exactly-named or `**`-covered directory is a
  recursive mirror, so its permission governs everything below it)
  decides, and the **real** host file or directory permissions still
  apply on top. The mount itself is read-only unless some mapping says
  `rw`.
- **Environment variables** — the path-like mapping fields (`glob`,
  `path`, `src`, `dest`, `source`) may reference environment variables
  as `${VAR}` (e.g. `"glob": "${HOME}/project"`); the references are
  expanded while the spec is read, so everything downstream only ever
  sees the fully expanded text. Other fields (`net.allow`, ...) are
  never expanded. Referencing an unset variable is an error; only the
  `${VAR}` form is recognized (a bare `$` stays untouched).

## Equivalence with bwrap's namespace flags

Every run of ai-bubble unshares the same namespaces as
`bwrap --unshare-all` (user, cgroup, ipc, pid, uts, mount). The only knob
is the network namespace, which corresponds to bwrap's `--share-net`:

- without `net` (i.e. `"mode": "host"`) → like
  `bwrap --unshare-all --share-net` (everything unshared, but the command
  keeps the host network)
- with `"net": { "mode": "proxy" }` or `"net": { "mode": "waf" }` → like
  plain `bwrap --unshare-all` (a fresh network namespace with only a
  brought-up loopback interface — bwrap's `loopback_setup()` — plus
  ai-bubble's proxy or waf servers)

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
6. Creates the sandbox root: a fresh **tmpfs** — or, when the spec has
   `hostfs` mappings, the FUSE filesystem itself (see below).
7. Applies the filesystem ops (all of them generated by the `hostfs`
   mappings) **in the order they were given** (order matters, exactly like
   bwrap). Because the PID namespace is created before the mounts (the
   mounting process is PID 1 of it), a fresh procfs instance only ever shows
   the sandbox's own processes — never host processes.
8. Drops **all capabilities** (permitted, effective, inheritable, ambient
   and the bounding set — like `bwrap --cap-drop ALL`) and `chroot`s into
   the sandbox root, then `execvp`s the command.

The sandbox root starts empty: only what the mappings expose exists. The standard
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

`ai-bubble run -- /bin/sh` then reproduces:

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

With `"net": { "mode": "proxy" }` or `"net": { "mode": "waf" }` the sandboxed command gets a network namespace that
is completely isolated from the host (only a freshly brought-up loopback
interface; the sandbox also gets its own UTS namespace) — while the
ai-bubble process tree provides network access **inside** that namespace,
so the command can reach the outside world transparently. The two modes
differ in how the in-sandbox side presents itself (see below).

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
- **sandbox** (`C`): unshares the mount namespace, builds the sandbox root
  and execs COMMAND.

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
ai-bubble --spec-dir isolated run -- /bin/sh
```

with `isolated/spec.json`:

```json
{
  "hostfs": { "mappings": [
    { "type": "bind", "src": "/usr" },
    { "type": "symlink", "src": "usr/lib", "dest": "/lib" }
  ] },
  "net": { "mode": "proxy", "allow": ["example.com:443"] }
}
```

`net.allow` is **required** in proxy mode. Entries are `HOST[:PORT]`
(omitting the port allows any port on that host), and an entry host may
start with `*.` for a subdomain wildcard (`*.github.com` matches
`api.github.com` but not `github.com`; it matches subdomains at any
depth). Empty means nothing is proxied — every target must be listed
explicitly.

Standard tools automatically use the proxy, because the sandbox sets the
following variables in its (isolated) environment — entries from the
spec's `env` section win over these:

- `http_proxy` / `HTTP_PROXY` = `http://127.0.0.2:3128`
- `https_proxy` / `HTTPS_PROXY` = same
- `all_proxy` / `ALL_PROXY` = same
- `NO_PROXY` = `localhost,127.0.0.1,::1`
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

`net.allow` restricts both proxy paths.

Exit status: the connector forwards the sandbox's status; a killed
command yields `128+signal`.

Note on trust: the proxy (`P`) and the command share one user namespace,
so `P`'s files are visible to the command's (non-root) uid — but the
command runs with **no capabilities at all**, so it cannot exercise the
namespace privileges that `P` keeps (loopback setup, ...). In the worst
case a hostile command could kill `P` (cutting its own network access —
it gains nothing else). Fully separating them would require an additional
namespace split.

### The alternative: waf mode

`"net": { "mode": "waf", "allow": [...] }` runs the same isolated
network namespace, but instead of a CONNECT proxy on a fixed port it
places three servers on **`127.0.0.2`** inside the sandbox — and resolves
every allow-listed name to that very address, so normal clients (which
just resolve a name and connect) are redirected transparently:

* **DNS** on `127.0.0.2:53` (UDP and TCP): every host on the allow-list
  resolves to `127.0.0.2`; anything else gets NXDOMAIN.
* **HTTPS** on `127.0.0.2:443`: reads the TLS ClientHello, extracts the
  SNI and terminates the TLS session itself with a certificate forged
  for exactly that SNI (see below). The decrypted plaintext is tunneled
  to `<sni>:443` on the host, where the host performs the *real* TLS
  handshake — with the genuine endpoint and proper certificate
  verification, since the sandbox has no real trust anchors by design.
  Connections without a SNI are dropped.
* **HTTP** on `127.0.0.2:80`: a plain forwarder for absolute-form
  (`GET http://host/path`) and Host-header requests — for **testing**
  this mode only, and likely to be removed later.

The HTTPS interception is the TLS-MITM pattern: ai-bubble generates a
fresh self-signed CA per run (its private key never leaves the host
process) and injects that CA as the sandbox's trust anchor — as
`/etc/ssl/certs/ca-certificates.crt` (the default bundle path on
Debian/Ubuntu/Alpine), as `/etc/pki/tls/certs/ca-bundle.crt` (the
Fedora/RHEL equivalent), and via `SSL_CERT_FILE` in the sandbox's
environment. For every SNI the in-sandbox HTTPS server sees, the host
signs a short-lived leaf certificate (`tls-cert` command) and the
sandbox serves it with rustls; clients then see a chain that verifies
against the injected CA. No fake `openssl.cnf` is needed — OpenSSL only
reads its configuration file for creating certificates or config-driven
features, not for plain certificate verification.

The allow-list (`net.allow`) is enforced on the host side, exactly like
in proxy mode; a bare `host` entry is both resolvable (DNS) and
connectable, and a `host:port` entry resolves the host too (the port
restriction is applied again on every `connect`).

The same namespace/process tree is used as in proxy mode; only the
in-sandbox listeners differ. No proxy variables are set in the
environment (there is no proxy to configure).

One caveat: for the sandbox's *resolver* to actually use the in-sandbox
DNS server, it must be pointed at `127.0.0.2` — typically via an
`/etc/resolv.conf` that says `nameserver 127.0.0.2` (provide one through
your mappings, or pass tools their resolver explicitly, e.g.
`unshare --dns`-style options, `dig @127.0.0.2`, ...). Making this
automatic is future work.

#### The command protocol on /net/sock

The Unix socket carries a simple line-based command protocol, executed
by the host-side process (the sandbox servers are its only clients):

```sh
exec 3<>/net/sock
printf 'resolve-dns example.com\n' >&3
head -1 <&3        # "OK 127.0.0.2" (allowed) or "ERR ..." (denied)

printf 'connect example.com:443\n' >&3
head -1 <&3        # "OK" (then this connection IS the pipe to the
                   #  real target) or "ERR ..." (denied or failed)
```

Commands currently understood: `resolve-dns <name>`, `connect
<host>:<port>`, `tls-cert <name>` and `tls-connect <host>:<port>`; more
can be added (e.g. a `make-http-request` command that performs the
request on the host and returns the response).

## The host filesystem as the sandbox root

With `hostfs` mappings, the FUSE filesystem itself becomes the sandbox
root instead of a plain tmpfs: everything the mirror exposes appears at
its absolute host path, and the ops (`dev`, `tmpfs`, `proc`, binds,
symlinks) are mounted **on top of** it. A sandbox without any
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

```sh
ai-bubble --spec-dir hostfs run -- /bin/sh
```

The mount-point mappings (`empty`, `dev`, `tmpfs`, `proc`, `bind`) expose
their path as an empty, unwritable (mode 0555) directory — a pure mount
point, taking *precedence* over the mirror (nothing below it is visible,
and no mirror pattern can bring content back). A mount point must exist,
because ai-bubble does not create directories on the FUSE filesystem
itself — which is exactly why the mount-point mappings provide it
automatically. The `dev` and `tmpfs` mounts (and the fresh procfs, from a
`proc` mapping) then cover the empty dirs, giving a writable `/dev` and
`/tmp` and a sandbox-only `/proc` on top of the host view.

Because the FUSE filesystem is the root, the pattern matching and
permission model of the mappings applies to *every* path in the sandbox
(see [Mapping semantics](#mapping-semantics) above); the `ls` sub-command
shows the effective permission for a host path under the current spec.

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- FUSE support for the host filesystem (`hostfs` mappings).
- Build: `cargo build` (the spec file's JSON Schema is generated from the
  source at build time); run tests: `cargo test`.

## Status

Starter project — the spec file's `hostfs.mappings` (ro, rw, hide, empty,
dev, tmpfs, proc, bind, symlink, redirect-ro, redirect-rw, session-cache,
project-cache), `net.mode` (`host`, `proxy`, `waf`) and `net.allow` are implemented, along
with the `run` and `ls` sub-commands and `--print-schema`. Namespace-wise ai-bubble
always unshares user, cgroup, ipc, pid, uts and mount namespaces (see
"Equivalence with bwrap's namespace flags" above); the network namespace is
unshared with `"net": { "mode": "proxy" }`.
Natural next steps would be further bubblewrap option coverage.

## License

MIT — see [LICENSE](LICENSE).
