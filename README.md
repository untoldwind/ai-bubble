# rs-bubble

A minimal Rust reimplementation of the basic functionality of
[bubblewrap](https://github.com/flatpak/bubblewrap) (`bwrap`), built as a
simple CLI on top of [clap](https://docs.rs/clap).

Currently supported options:

- `--bind SRC DEST` — bind-mount `SRC` at `DEST` inside the sandbox
  (read-write, non-recursive; use `--rbind`-style recursion is not yet supported)
- `--symlink SRC DEST` — create a symlink at `DEST` pointing to `SRC`
  (mirrors bwrap: fails if `DEST` exists and is not the identical symlink)
- `--isolated-net` — run the command in a fresh **network namespace**
  (no interfaces besides loopback, which rs-bubble brings up) while the
  rs-bubble process stays on the host and acts as a **TCP proxy**
- `--allow-net HOST[:PORT]` — allow-list for the proxy; repeatable.
  Without it, every target is allowed

Everything after the options (optionally after a `--` separator) is the
command to run inside the sandbox.

## How it works

Like bwrap, the tool:

1. Sets `PR_SET_NO_NEW_PRIVS`.
2. Unshares a **user namespace** and a **mount namespace**
   (this is what makes the sandbox work *without* root).
3. Maps the real uid/gid to 0 inside the new user namespace.
4. Marks the mount tree as a **slave**, so nothing mounted inside
   propagates back to the host.
5. Creates a fresh **tmpfs** as the sandbox root.
6. Applies `--bind` and `--symlink` operations **in the order they were
   given** (order matters, exactly like bwrap).
7. `chroot`s into the sandbox root and `execvp`s the command.

The sandbox root starts empty: only what you bind in exists. The standard
bubblewrap example works the same way here:

```sh
rs-bubble \
  --bind /usr /usr \
  --symlink usr/lib /lib \
  --symlink usr/lib64 /lib64 \
  --symlink usr/bin /bin \
  /bin/sh
```

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
- The temporary host directory backing the tmpfs root is cleaned up when
  the process exits, but the empty staging directory may remain in `/tmp`.

## Isolated networking

With `--isolated-net` the sandboxed command gets a network namespace that
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
`--allow-net` filter in the connector.

### Usage

```sh
rs-bubble --isolated-net --allow-net example.com:443 \
  --bind /usr /usr --symlink usr/lib /lib -- /bin/sh
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

`--allow-net HOST[:PORT]` (repeatable) restricts both proxy paths;
entries without a port allow any port on that host. Without it, every
target is allowed.

Exit status: the connector forwards the sandbox's status; a killed
command yields `128+signal`.

Note on trust: the proxy (`P`) and the command share one user namespace,
so a hostile command runs as uid 0 there and could, in principle, kill
`P` (cutting its own network access — it gains nothing else). Fully
separating them would require an additional namespace split.

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- Run tests: `cargo test`

## Status

Starter project — only `--bind` and `--symlink` are implemented. Natural
next steps would be `--ro-bind`, `--proc`, `--dev`, `--tmpfs`,
`--die-with-parent`, and `--unshare-all`.
