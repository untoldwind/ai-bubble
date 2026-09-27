# Findings: erratic `cargo build` failures on the hostfs FUSE mount

## Symptom

Under load, `cargo build` inside the sandbox fails erratically (and converges on
retry). Observed error classes:

* `error: failed to write file target/debug/incremental/.../dep-graph.part.bin: No such file or directory (os error 2)`
* `error: failed to delete invalidated or incompatible incremental compilation session directory contents .../dep-graph.bin: No such file or directory (os error 2)`
* `error: failed to build archive at target/debug/deps/libslab-…​.rlib: couldn't create the temp file: No such file or directory (os error 2)`
* `error: failed to build archive at target/debug/deps/libfutures_core-…​.rlib: Is a directory (os error 21)`
* `cargo build` (outside): `path at target/debug/deps/parking-….d was not valid utf-8` — the dep-info file contained garbage (transient data corruption)
* `warning: failed to garbage collect finalized incremental compilation session directory … : Directory not empty (os error 39)`
* `warning: hard linking files in the incremental compilation cache failed. copying files instead.`
* `warning: corrupt incremental compilation artifact found at …/dep-graph.bin`

All of these involve **paths that were just renamed or just deleted**, and all
disappear once the state settles — matching "re-running `cargo build` eventually
converges".

## Root cause: fuse3 0.9.0 `InodePathBridge` breaks its inode↔path map on rename

The hostfs server uses fuse3's **path-based API** (`PathFilesystem`). Internally,
fuse3 wraps it in `InodePathBridge` (`~/.cargo/registry/src/*/fuse3-0.9.0/src/path/inode_path_bridge.rs`),
which maps kernel inodes ↔ absolute paths in an `InodeNameManager`:

```rust
async fn rename(&self, req, parent, name, new_parent, new_name) -> Result<()> {
    ...
    self.path_filesystem.rename(...).await?;
    inode_name_manager.remove_name(&Name::new(parent, name));      // ← drops the SOURCE inode's mapping
    let new_name = Name::new(new_parent, new_name);
    inode_name_manager
        .get_name_inode(&new_name)                                  // ← reuses the OLD TARGET's inode
        .unwrap_or_else(|| inode_name_manager.insert_name(new_name)); // ← or invents a fresh inode
    Ok(())
}
```

Two things are wrong here, and together they poison the map:

1. **The source mapping is destroyed.** In the Linux kernel, `RENAME` *moves*
   the dentry: the dentry formerly known as `parent/name` is re-hashed at
   `new_parent/new_name` **keeping its inode number (call it Y)**. The bridge
   instead removes the `(parent, name) → Y` mapping and points the new name at
   the old target's inode (or a brand-new one). From now on the kernel holds a
   cached dentry whose inode Y is **unknown to the bridge** — every operation
   through that dentry (`open`, `getattr`, `read`, `write`, `create`, `unlink`,
   `rename`…) resolves `get_absolute_path(Y) → None` and fails with
   `Errno::new_not_exist` (ENOENT).

2. **Rename-over-existing keeps the dead target inode.** When `new_name` already
   existed (with inode Z), the mapping `(new_parent, new_name) → Z` survives.
   The kernel unhashes the old target dentry and drops its reference, so it
   sends `FORGET Z` — and the bridge's `forget()` then **deletes the
   `(new_parent, new_name)` mapping again**, re-breaking the very name it just
   remapped. (If the kernel instead keeps using its moved dentry, case 1 applies.)

### Why it is erratic, and why retries converge

The kernel caches FUSE dentries with the entry TTL. hostfs advertises
`TTL = 1 s` (`src/hostfs/mod.rs:229`). Within that second after a rename, path
walks are served from the (now-wrong) cached dentry and fail with ENOENT; once
the TTL expires, `d_revalidate` forces a fresh `LOOKUP`, the bridge re-inserts
the name under a new inode, and everything works again. The failure window is
timing-dependent, so the build breaks only under load (many renames in flight,
rustc's parallel jobs) and self-heals on retry.

### Why rustc/cargo trip over it constantly

rustc/cargo rename *constantly*:

* incremental compilation: `-working` session dirs are renamed to their
  finalized name, `dep-graph.part.bin` ↔ `dep-graph.bin` link/rename games,
  fingerprint `invoked.timestamp`, …
* crate artifacts: `*.rmeta`/`*.rlib` written to temp names then renamed;
  `hardlink_or_copy` fallbacks.

Any operation that lands on the stale-dentry window produces exactly the ENOENT /
EISDIR errors seen above. The corrupt `.d` file ("not valid utf-8") is the same
class of bug: the kernel's cached attribute/dentry for a just-renamed or
just-truncated path no longer matches reality, so a reader gets stale-sized
(zero-padded) or interleaved content.

## Secondary issues in the same area

* `HostFs` does not implement `PathFilesystem::link` — hardlinks fail with
  ENOSYS (rustc falls back to copying; noisy but not fatal).
* No `getlk`/`setlk` implementation — file locking through the mirror depends
  on fuse3's defaults; the incremental-compilation cache (which relies on
  `flock`) is affected.
* The 1 s attribute TTL also means stale sizes/mtimes can be served for up to a
  second after `write`/`open(O_TRUNC)`/`setattr`, because `ReplyWrite` carries
  no updated attributes.

## Resolution

1. **Drop the vendored path bridge entirely.** The hostfs server now implements
   fuse3's **raw** `Filesystem` (inode-based) directly instead of the
   `PathFilesystem` wrapper, so no `InodePathBridge` — and no vendored fuse3
   (`[patch.crates-io]` is gone; fuse3 0.9.0 comes from crates.io).
   The nodeid ↔ path mapping lives in `src/hostfs/inodes.rs` (`InodeMap`),
   simplified for this filesystem and hardened:
   * on `rename`, the new path is re-pointed at the **source** nodeid (the
     kernel moves the dentry keeping its inode), and the overwritten target's
     mapping is dropped — the kernel then `FORGET`s a nodeid with no mapping,
     which is a no-op (this is the erratic-`cargo build` fix);
   * nodeids are **never reused** (monotonic counter, not a recycled slab), so
     a stale kernel dentry can never alias a new file;
   * a nodeid whose lookup references are gone but which still has open
     handles keeps its last path (a "zombie") so stateless (`fh = 0`) IO on
     those handles still resolves, freed on the last release.
   The debug tracing (`fuselog`, `RS_BUBBLE_FUSE_LOG`) moved from the vendor
   into `src/hostfs/fuselog.rs`.
2. Longer term: implement `link`, and consider smaller TTLs or explicit
   attribute invalidation after writes.
