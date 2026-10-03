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
  This is path-based policy: a host **bind mount** aliasing the project tree
  at a second path, or a **case-folding** filesystem (ext4 `casefold`) under
  a broad rw mapping, can bypass it (AUDIT.md L12) — keep the spec directory
  on a single, case-sensitive mount.
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

# Bootstrap the spec directory (default: .ai-bubble) if it does not exist
# yet, with a starter spec.json and the JSON Schema next to it:
ai-bubble init

# Print the JSON Schema for the spec file (see below):
ai-bubble --print-schema > ai-bubble.spec.schema.json
```

Notes:

* `init` creates the spec directory (default `.ai-bubble`, or `--spec-dir
  DIR`) together with a starter `spec.json` and `ai-bubble.spec.schema.json`
  if it does not exist yet; an existing directory is left untouched. The
  starter spec is a working baseline that exposes `/bin`, `/etc`, `/lib`,
  `/lib64` and `/usr` read-only plus fresh `/dev`, `/tmp` and `/proc`, and
  passes the host's `PATH`/`HOME` through. It pins the project directory by
  its absolute path (rather than `${PWD}`); when the current directory is a
  git repository, the spec directory is also added to its `.gitignore`
  (created if missing, extended otherwise).
* A missing `.ai-bubble/spec.json` is fine: an **empty spec** is used (empty
  tmpfs root, no mounts, host network). An *explicit* `--spec-dir` that
  cannot be read is a hard error. When a policy is mandatory, pass
  `run --require-spec`: a missing default spec file then aborts the run
  instead of degrading to an empty spec with host networking.
* `run` sets `PR_SET_PDEATHSIG` so the sandboxed command is killed with
  SIGKILL when ai-bubble — or ai-bubble's parent — dies (like bwrap's
  `--die-with-parent`, which is the default here); `run
  --no-die-with-parent` switches it off.
* `run` starts the command in a **new terminal session** (like bwrap's
  `--new-session`, also the default here): the command's terminal is not
  the caller's *controlling* tty. A malicious command therefore cannot
  push keystrokes into the user's shell with `TIOCSTI`, and the host pts
  device is not bind-mounted into the sandbox as `/dev/console`.
  When the command actually talks to a terminal (stdin and stdout are
  both ttys), this automatically runs in **pty mode**: the launcher
  allocates a private pty and relays it (like `script(1)`), giving the
  command a real controlling terminal — job control, `^C`, `SIGWINCH`,
  interactive shells, `su` — while still never exposing the host terminal
  device. With pipes on stdin or stdout the plain new-session behaviour
  is kept (the command simply has no controlling tty; `/dev/tty` fails
  with `ENXIO`, as it does in bwrap's `--new-session`).
  Note (AUDIT.md L3): like `ssh` to an untrusted host or `script(1)`, the
  relay copies the command's output **unfiltered** to the user's terminal,
  so terminal escape sequences pass through — OSC 52 clipboard writes,
  title/palette changes, and any terminal-emulator escape-parsing issues.
  This applies to pty mode *and* to plain new-session runs with a tty on
  stdout; treat untrusted output the way you would treat untrusted `ssh`
  output.
  Only if you explicitly need the *shared*-terminal behaviour — the
  command seeing the very same pts device — use `run --no-new-session`,
  which bind-mounts the host terminal into the sandbox; only use it for
  commands you trust.
* A typical spec directory:

  ```
  .ai-bubble/
  ├── spec.json      # the sandbox spec (see below)
  ├── env            # optional dotenv-style file (spec: env.env_file)
  └── cache/         # backing store of `project-cache` mappings
  ```

  You may keep a configuration directory inside the spec directory (e.g.
  `.ai-bubble/conf/`) and expose it to the sandbox with a `bind` or
  `redirect-rw` mapping — **do this with care**: such a source bypasses the
  glob-based write policy and the spec directory's auto-hide, so everything
  under it is readable and (with `rw`) writable by the sandboxed command,
  and whatever it writes there persists into every later run that reads it.
  Only sources **inside a subdirectory** of the spec directory are accepted;
  the spec directory itself, its ancestors, and files directly inside it
  (`spec.json`, the env file) are rejected as sources at spec load time.

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
  "cwd": "/work",
  "seccomp": { "block": ["ptrace", "mount"], "on_violation": "errno" }
}
```

- `env` — the sandbox's **isolated environment**: the *complete* set of
  environment variables the command sees. Nothing is inherited from the
  host; a missing (or empty) `env` section means the command runs with an
  empty environment. `values` maps variable names to values, which may
  reference host variables as `${VAR}`, so the variables the sandbox
  needs are copied over explicitly, one by one (e.g. `"PATH": "${PATH}"`).
  Referencing an unset host variable is an error; the references are
  expanded when the spec is compiled down to the internal config (not
  while the file is parsed), so a programmatically assembled spec is
  expanded too. Optionally, `env_file`
  names a dotenv-style file (relative to the spec directory) whose
  `KEY=VALUE` lines (comments, quotes and an optional `export` prefix are
  supported) are loaded as well; entries already present in `values` win
  over the file. In proxy mode the proxy variables (see
  [Isolated networking](#isolated-networking)) are added to this
  environment, with the spec's `env` entries winning over them.

- `cwd` — the command's **working directory inside the sandbox**
  (default: `/`). An absolute sandbox path without `..` components; it
  may reference host variables as `${VAR}` (expanded when the spec is
  compiled down to the internal config, like the `env` values). The
  directory must exist inside the sandbox (e.g. via a hostfs mapping or
  a mount-point mapping such as `tmpfs`) — nothing is created
  automatically, and a missing directory is a hard error right before
  exec.

- `hostfs.mappings` — an **ordered** array of mappings, each selecting
  host paths for one treatment (`type`); see below for the details.
  Everything the sandbox sees of the host filesystem comes from these
  mappings; when there are any, the FUSE filesystem itself becomes the
  sandbox root (see [The host filesystem as the sandbox
  root](#the-host-filesystem-as-the-sandbox-root)), otherwise the
  sandbox gets a plain tmpfs root and no FUSE filesystem is started.

- `net` — how the command reaches the network; see
  [Isolated networking](#isolated-networking).

- `audit` — optional audit logging: `"audit": { "log": "/path/audit.jsonl" }`
  appends every security-relevant event (filesystem operations through
  the hostfs mirror, waf allow/deny decisions, proxy CONNECT attempts)
  to the file as one JSON object per line. Without a `log` path the
  audit subsystem is disabled entirely. The path may use `${VAR}`
  references to host environment variables. Events are buffered in
  memory (generously) and written in batches by a dedicated writer; if
  the buffer ever fills, producers briefly stall rather than drop
  events.

- `seccomp` — an optional **syscall filter** installed for the sandboxed
  command right before exec (the filter is loaded into the kernel after
  all privileged sandbox setup, so it cannot interfere with it):

  - `"allow": [...]` — an **allowlist**: only the listed syscalls may be
    executed; everything else is denied. The list must be complete
    (include at least `execve`, `exit_group`, `mmap`, ...) or the
    command cannot run at all.
  - `"block": [...]` — a **blocklist**: exactly the listed syscalls are
    denied; everything else stays allowed. Useful to forbid dangerous
    entry points like `ptrace`, `mount`, `keyctl` or `bpf` without
    enumerating the whole syscall surface.
  - `"preset": "..."` — one of the built-in **blocklist presets**, for
    when writing the syscall names yourself is too much: `"none"` (an
    empty baseline), `"default"` (everything a sandboxed command has no
    business calling: kernel-code loading via `init_module`/`finit_module`/
    `delete_module`/`bpf`, kernel replacement via `kexec_load`/
    `kexec_file_load`, host-wide toggles `reboot`/`acct`/`swapon`/
    `swapoff`, mount-table manipulation `mount`/`umount2`/`pivot_root`/
    `open_tree`/`move_mount`/`fsmount`/`fspick`/`mount_setattr`, the exploit-primitive
    surfaces `userfaultfd`/`perf_event_open`/the `io_uring` family and
    `open_by_handle_at`, the isolation escapes `unshare`/`setns`, host
    state tampering via `personality`/`pidfd_getfd`/`settimeofday`/
    `clock_settime`/`adjtimex`, keyring access `add_key`/`keyctl`/
    `request_key`, and `quotactl`/`lookup_dcookie`) and `"strict"`
    (everything in `default` plus the NUMA memory-policy syscalls
    `mbind`/`set_mempolicy`/`move_pages` and the host identity syscalls
    `sethostname`/`setdomainname`).

  A preset turns the section into a blocklist seeded by the preset's
  list; the two other fields then tweak it: `"block"` names *additional*
  syscalls to deny (only ever stricter), and `"allow"` names
  **exceptions** taken back out of the blocklist (only ever more
  permissive). With a preset, `allow` and `block` may appear together —
  a name in both is rejected as ambiguous. Without a preset, `allow`
  and `block` are mutually exclusive as above.

  Syscalls are named as in the kernel's syscall table (`execve`,
  `openat`, `clone3`, ...). `"on_violation"` selects what a denied
  syscall does: `"errno"` (the default — it fails with `EPERM`) or
  `"kill"` (the process is killed with `SIGSYS`). Without a `seccomp`
  section (or with none of `preset`, `allow` and `block`) no filter is
  installed.
  Note that the filter applies to the whole process tree the command
  spawns, and that it sees syscall numbers only — not arguments, paths
  or network addresses (those are the domain of the `hostfs` mappings
  and the `net` section).

- `rlimits` — optional **resource limits** applied to the sandboxed
  process (and inherited by everything it forks) right before exec:
  `"rlimits": { "nproc": 1024, "nofile": 4096, "as": 536870912 }`. Each
  field is optional; an absent field (or section) means the limit is not
  set at all. `nproc` is the fork-bomb brake (there is no cgroup
  limiting; without it a fork bomb consumes the invoking user's global
  per-uid process budget), `nofile` bounds fd-table kernel memory, and
  `as` caps the per-process address space. Every limit is applied with
  soft == hard, so the command cannot raise it back up (AUDIT.md M4).
  The starter spec written by `ai-bubble init` sets `nproc`/`nofile` and
  a `size` cap on its `/tmp` tmpfs by way of example.

### The mapping types

| `type` | fields | effect |
|---|---|---|
| `ro` / `rw` / `hide` | `glob` | mirror the matched paths read-only / read-write / hide them (with their subtree); `glob` is a glob pattern or a list of them (also spellable `globs`) — a list behaves like separate mappings in the listed order |
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

- `ro`, `rw` and `hide` select paths with **glob** patterns of absolute
  host paths (`*`, `?`, `[...]`, `**`); every other mapping names
  absolute **paths** exactly (it makes no sense to glob a mount point).
  `glob` accepts either a single pattern string or a list of them (also
  spellable as `globs`); a list behaves exactly like separate mappings in
  the listed order.
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
  A `source` that covers the spec directory (the directory itself or an
  ancestor) is a hard error; a source *inside* the spec directory must be
  within a subdirectory — the directory itself and top-level files are
  rejected — so a kept-in-`.ai-bubble` conf directory can be shared, while
  `spec.json` and the env file can never be reached (see "A typical spec
  directory" above; do this with care).
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
  as `${VAR}` or `$VAR` (e.g. `"glob": "${HOME}/project"`); the
  references are expanded while the spec is read, so everything
  downstream only ever sees the fully expanded text. Referencing an
  unset variable is an error. Only plain references are supported:
  the shell's parameter-expansion extras (`${VAR:-default}`,
  `$$`, other operators) and unterminated `${` are rejected, so a
  spec field can never silently expand to a literal that was not a
  variable reference. Other mapping
  fields (`content`, ...), `net.allow` and the like are never expanded.
  Referencing an unset variable is an error.

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

> **⚠️ Host-network mode is full local IPC, not just "host networking".**
> Without `net` (i.e. `"mode": "host"`) the command keeps the host
> *network namespace* — and **abstract Unix-domain socket names live in the
> network namespace**, not the filesystem. The command can therefore connect
> to abstract-namespace sockets such as `@/run/dbus/system_bus_socket`, the
> session bus or `systemd --user` **as your uid**, with no filesystem
> mapping involved — e.g. asking `systemd --user` to spawn a transient unit
> that runs an arbitrary host command outside the sandbox. Filesystem
> sockets reachable through `ro`/`bind` mappings of `/run`,
> `/tmp/.X11-unix` & co. carry the same risk. For any command you do not
> fully trust, use `"mode": "proxy"` or `"mode": "waf"` (below), which
> isolate the network namespace; host mode is appropriate only for trusted
> commands that genuinely need the host network stack.
>
> Mitigated in part since 2026-10-02: host-network mode denies
> Unix-domain sockets by default (`net.host.unix_sockets`, see
> [Unix-domain sockets](#unix-domain-sockets) below), which closes the
> abstract-socket hole (and filesystem-socket access) with seccomp —
> **on kernels without IA32 emulation**; see the warning below. Opt in
> only if the command genuinely needs local IPC. Proxy/waf modes isolate
> the network namespace and are not exposed.

Not covered by that equivalence (see "Notes" below): ai-bubble's
`/proc` mounts are always fresh procfs instances and the command always
runs as PID 1 of its PID namespace, mirroring `--as-pid-1`.

`--die-with-parent` is on by default (it uses `PR_SET_PDEATHSIG`, like
bwrap's option of the same name): the sandboxed command is killed with
SIGKILL when ai-bubble — or ai-bubble's parent — dies. Pass
`--no-die-with-parent` to switch this off. Every process in the chain
(launcher, isolated-net parent and connector, sandboxed child) sets it for
itself, because the setting does not survive fork.

`--new-session` (bwrap's option of the same name) is likewise on by
default: the command runs in a fresh terminal session with no controlling
terminal (`setsid()` + `TIOCNOTTY` in the sandboxed child, before exec).
This closes the `TIOCSTI` keystroke-injection escape through the shared
terminal and drops the `/dev/console` and `/dev/tty` host binds that
terminal sharing needs; `--no-new-session` restores them for trusted,
interactive commands.

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

For untrusted commands this is the recommended network mode — host-network
mode (the default, no `net` key) exposes the host's abstract Unix-domain
sockets to the command as your uid (see the warning in
[Equivalence with bwrap's namespace flags](#equivalence-with-bwraps-namespace-flags)).

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
a `mkdtemp`-created 0700 directory on the host and is deliberately
**not** mounted into the sandbox — by default the command cannot reach
the connector at all (AUDIT.md L6). That guarantee is conditional on
the mount table: a spec bind-mounting the host `/tmp` (or wherever the
directory lives) would expose the raw connector protocol to the
command. Every protocol command is re-authorized host-side against the
allow-list, so nothing new becomes reachable — but avoid mapping host
`/tmp` into the sandbox.

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

### Unix-domain sockets

Host-network mode carries a `unix_sockets` flag, **`false` by default**:

```json
{ "net": { "mode": "host", "unix_sockets": true } }
```

With the default, the command cannot create *any* Unix-domain socket: a
seccomp filter denies `socket(AF_UNIX)` and `socketpair(AF_UNIX)` — which
covers both abstract-namespace sockets (`@/run/dbus/system_bus_socket`
and friends, see the warning above) and filesystem sockets (e.g. under a
mapped `/run`) — plus `io_uring_setup`, which can create sockets without
going through `socket(2)`. TCP/UDP (`AF_INET`/`AF_INET6`) are unaffected,
so host networking keeps working.

The same filter denies the other address families that are
unprivileged-creatable but have no business in a sandbox
(AUDIT.md M3), each with its own opt-in flag:

| Family | Flag (default) | Why it is denied by default |
| --- | --- | --- |
| `AF_UNIX` | `unix_sockets` (`false`) | local-IPC escape hatch (see above) |
| `AF_NETLINK` | `netlink` (`false`) | unprivileged `NETLINK_ROUTE`/`NETLINK_SOCK_DIAG` expose the host's network state and unix-socket inventory (reconnaissance), and netlink is a recurring kernel-CVE area |
| `AF_VSOCK` | `vsock` (`false`) | creation is unprivileged and vsock is *not* network-namespaced — on VMs the command could reach host/hypervisor vsock services (e.g. CID 2) |
| `AF_BLUETOOTH` | `bluetooth` (`false`) | unprivileged-creatable; usable to the extent the stack allows |

```json
{ "net": { "mode": "host", "netlink": true } }
```

What the filter deliberately does *not* close in host mode:

- `AF_INET`/`AF_INET6`: that is the point of host networking — every
  service bound on host `127.0.0.1`/`::1` (dev servers, databases,
  docker-over-TCP) is fully reachable. The family flags above do
  nothing about this; do not over-trust them.
- `AF_PACKET`: nothing to do — packet sockets require `CAP_NET_RAW`,
  which the command never has.

If the spec also configures a `seccomp` section, the denials are merged
into it: a blocklist keeps its unconditional entries, and an allowlist
that lists `socket`/`socketpair` is narrowed to non-gated domains (an
allowlist without them was already denying everything). Set any flag to
`true` only if the command genuinely needs that family — each flag
re-opens exactly its family's exposure.

> **⚠️ Best-effort on kernels with IA32 emulation (AUDIT.md H2).** On a
> kernel built with `CONFIG_IA32_EMULATION` (the common distro default),
> a 64-bit process can issue `int $0x80` and reach the *ia32* syscall
> table while seccomp still reports the x86_64 architecture: ia32
> `socketcall` is syscall 102, which the filter can only interpret as
> x86_64 `getuid` — a syscall that cannot be denied — so sockets in any
> gated family (`AF_UNIX` *and* `AF_NETLINK`/`AF_VSOCK`/`AF_BLUETOOTH`)
> remain creatable despite these defaults. No seccomp rule can
> distinguish the case, because the syscall *number* is genuinely
> ambiguous. With IA32 emulation the socket gate is therefore
> best-effort, and host-network mode must be treated as **full local
> IPC** for untrusted commands: prefer `"mode": "proxy"` or `"mode":
> "waf"` there. Kernels without IA32 emulation get the full protection
> described above.

In proxy/waf mode the command runs in a fresh network namespace, where
the abstract-socket exposure does not exist (the namespace's socket
names are its own); Unix-domain sockets are always allowed there, and
the family flags (like `allow`) are rejected in those modes.

Standard tools automatically use the proxy, because the sandbox sets the
following variables in its (isolated) environment — entries from the
spec's `env` section win over these:

- `http_proxy` / `HTTP_PROXY` = `http://127.0.0.2:3128`
- `https_proxy` / `HTTPS_PROXY` = same
- `all_proxy` / `ALL_PROXY` = same
- `NO_PROXY` = `localhost,127.0.0.1,::1`

For example, inside the sandbox:

```sh
curl -si https://example.com/ | head -1
```

Exit status: the connector forwards the sandbox's status; a killed
command yields `128+signal`.

Note on trust: the proxy (`P`) and the command share one user namespace,
so `P`'s files are visible to the command's (non-root) uid — but the
command runs with **no capabilities at all**, so it cannot exercise the
namespace privileges that `P` keeps (loopback setup, ...). Signals are
not a problem: the command lives in its own PID namespace, so it cannot
even *address* `P` (P is in the parent PID namespace — a hostile command
cannot kill it; the claim that it could was inaccurate). The real
residual risk is `P`'s parsing of untrusted input (all length-bounded:
CONNECT header 8 KiB, TLS ClientHello 64 KiB, DNS query 4 KiB) plus
resource exhaustion (bounded by connection caps, timeouts and the
`tls-cert` token bucket). Fully separating the user namespaces would
require an additional namespace split.

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
  for exactly that SNI (see below). The decrypted plaintext is parsed as
  HTTP by the in-sandbox server (it is *not* a raw tunnel): every
  request's `Host` header must name the same host the SNI did — a
  mismatch is refused with a 400 and never reaches the upstream — and
  each request is forwarded to `<sni>:443` on the host with that dialed
  authority as the `Host` header, where the host performs the *real* TLS
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
signs a leaf certificate per SNI (`tls-cert` command; fresh key pair per
request, per-run CA) and the
sandbox serves it with rustls; clients then see a chain that verifies
against the injected CA. No fake `openssl.cnf` is needed — OpenSSL only
reads its configuration file for creating certificates or config-driven
features, not for plain certificate verification.

The allow-list (`net.allow`) is enforced on the host side, exactly like
in proxy mode; a bare `host` entry is both resolvable (DNS) and
connectable, and a `host:port` entry resolves the host too (the port
restriction is applied again on every `connect`).

Note the inherent limit of TCP-layer allow-listing (both modes): a
`host:port` entry cannot distinguish *domains* served by shared
infrastructure — `CONNECT allowed.com:443` with a TLS SNI or HTTP
`Host:` header of `evil.com` on the same CDN reaches the disallowed
domain (domain fronting). The waf mode closes this on both layers: it
matches the TLS SNI against the allow-list before anything is dialed,
and — because it terminates TLS — it also compares the decrypted
request's `Host` header against the SNI on every request (HTTP-level
fronting gets a 400), and rewrites the `Host` of forwarded requests to
the dialed authority.

The same namespace/process tree is used as in proxy mode; only the
in-sandbox listeners differ. No proxy variables are set in the
environment (there is no proxy to configure).

One caveat: for the sandbox's *resolver* to actually use the in-sandbox
DNS server, it must be pointed at `127.0.0.2` — ai-bubble injects an
`/etc/resolv.conf` saying `nameserver 127.0.0.2` automatically in waf
mode (as the last mapping, so an explicit `hide` of the same path still
wins). Unless you hide or override it, plain clients work without
manual resolver configuration.

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
      { "type": "ro", "globs": ["/bin", "/etc", "/lib", "/lib64", "/usr"] },
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
with the `run`, `ls` and `initinit` sub-commands and `--print-schema`. Namespace-wise ai-bubble
always unshares user, cgroup, ipc, pid, uts and mount namespaces (see
"Equivalence with bwrap's namespace flags" above); the network namespace is
unshared with `"net": { "mode": "proxy" }`.
Natural next steps would be further bubblewrap option coverage.

## License

MIT — see [LICENSE](LICENSE).
