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

With `--isolated-net` the sandboxed command gets a completely isolated
network stack (only a freshly brought-up loopback; the sandbox also gets
its own UTS namespace). Since `execve` replaces the process, rs-bubble
forks first: the **child** does the isolation and runs the command, the
**parent** stays on the host, runs the TCP proxy, and forwards the
child's exit status (a killed child results in exit status `128+signal`).

The child reaches the proxy through a Unix socket: rs-bubble creates a
temporary host directory containing the socket and bind-mounts it at
`/net` inside the sandbox. Filesystem Unix-domain sockets work across
network namespaces, so this is the single controlled channel out of the
isolated network namespace — no root, no host `CAP_NET_ADMIN`, no veth
pairs needed. The socket path is also exported as `$RS_BUBBLE_PROXY`
(`/net/sock`).

The proxy protocol is deliberately simple: connect to the socket, send
the target as one line `host:port\n`, and the connection becomes a raw
bidirectional pipe to that TCP target (name resolution and the actual
connection happen on the host side, so DNS also stays outside).

```sh
rs-bubble --isolated-net --allow-net example.com:443 \
  --bind /usr /usr --symlink usr/lib /lib -- /bin/sh
```

Inside the sandbox:

```sh
exec 3<>/net/sock
printf 'example.com:443\n' >&3
# fd 3 is now a raw connection to example.com:443 via the host proxy
```

Connections to targets not on the `--allow-net` list are rejected (with
an empty reply and a message on the host's stderr). With no
`--allow-net`, every target is allowed.

Note: regular tools like `curl` speak plain TCP and cannot use the proxy
directly; they would need a wrapper (or a `LD_PRELOAD` shim) that dials
the socket first. Transparent networking for unmodified programs would
require user-space networking such as `slirp4netns` or `pasta` — a
natural next step.

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- Run tests: `cargo test`

## Status

Starter project — only `--bind` and `--symlink` are implemented. Natural
next steps would be `--ro-bind`, `--proc`, `--dev`, `--tmpfs`,
`--die-with-parent`, and `--unshare-all`.
