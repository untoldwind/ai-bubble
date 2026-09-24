# rs-bubble

A minimal Rust reimplementation of the basic functionality of
[bubblewrap](https://github.com/flatpak/bubblewrap) (`bwrap`), built as a
simple CLI on top of [clap](https://docs.rs/clap).

Currently supported options:

- `--bind SRC DEST` — bind-mount `SRC` at `DEST` inside the sandbox
  (read-write, non-recursive; use `--rbind`-style recursion is not yet supported)
- `--symlink SRC DEST` — create a symlink at `DEST` pointing to `SRC`
  (mirrors bwrap: fails if `DEST` exists and is not the identical symlink)

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

## Requirements

- Linux with unprivileged user namespaces enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` must be `1` on Debian/Ubuntu,
  and no LSM must block it).
- Run tests: `cargo test`

## Status

Starter project — only `--bind` and `--symlink` are implemented. Natural
next steps would be `--ro-bind`, `--proc`, `--dev`, `--tmpfs`,
`--die-with-parent`, and `--unshare-all`.
