//! The nodeid ↔ mirrored-path map.
//!
//! The raw FUSE API hands the server kernel nodeids, but `HostFs` is a pure
//! pattern-matching mirror: every operation needs a *path* to match patterns
//! against. This module owns the mapping — the job the vendored fuse3
//! `InodePathBridge` used to do (see `FINDINGS.md`), simplified for this
//! filesystem:
//!
//! * **One path per nodeid.** The bridge supported one inode under several
//!   names (hard links); `link` here gives each *new name* its own fresh
//!   nodeid pointing at the new path — the two names alias the same real
//!   host file (writes through either are visible through both, and
//!   `st_nlink` comes from the real metadata), but they are independent
//!   paths: the mirror's pattern permissions are decided per path, and
//!   renaming one name must not affect the other's mapping. A plain
//!   `path → inode` map therefore still suffices.
//! * **Nodeids are never reused.** The kernel may still hold cached dentries
//!   (or open handles) for a nodeid the server considers dead; handing its
//!   number out again would alias two different files. Allocation is a
//!   monotonic counter instead of a recycled slab.
//! * **Renames keep the source nodeid.** The kernel moves the dentry on
//!   rename, re-hashing `parent/name` as `new_parent/new_name` *keeping the
//!   source's inode* — so the new path is re-pointed at the source nodeid,
//!   and the overwritten target's mapping is dropped (the kernel is about to
//!   forget that nodeid). This is the fix for the erratic `cargo build`
//!   failures: the old bridge dropped the source mapping instead, leaving
//!   the kernel's moved dentry unknown until its TTL expired.
//! * **Zombies.** A nodeid that loses its lookup references (forget, unlink,
//!   failed lookup) while open handles remain keeps its last known path, so
//!   the (stateless, `fh = 0`) IO on those handles still resolves. It is
//!   freed when the last handle is released.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fuse3::Inode;

use super::fuselog;

/// The nodeid of the filesystem root; its parent is itself.
pub(crate) const ROOT_INODE: Inode = 1;

#[derive(Debug, Default)]
pub(crate) struct InodeMap {
    /// The path each live nodeid stands for.
    inode_to_path: HashMap<Inode, PathBuf>,
    /// The nodeid of each path's parent directory (for `..` in `readdir`).
    inode_to_parent: HashMap<Inode, Inode>,
    /// The live nodeid of each mapped path.
    path_to_inode: HashMap<PathBuf, Inode>,
    /// Open handles per nodeid (`open`/`create`/`opendir` minus
    /// `release`/`releasedir`). The kernel keeps sending operations for a
    /// nodeid with open handles — including after its dentry is evicted
    /// (forget) or the file is unlinked — so the mapping must not be dropped
    /// (nor the nodeid reused) until the last handle is closed.
    open_counts: HashMap<Inode, u64>,
    /// Lookup references are gone (the kernel forgot the dentry, or the name
    /// was unlinked) but open handles remain: the last known path is kept so
    /// stateless (`fh = 0`) IO on those handles still resolves. Freed with
    /// the last release.
    zombies: HashMap<Inode, PathBuf>,
    /// The next nodeid to allocate; never reused (see the module docs).
    next_inode: Inode,
}

impl InodeMap {
    /// A fresh map with only the root (inode 1, its own parent).
    pub(crate) fn new() -> Self {
        let mut map = Self {
            next_inode: ROOT_INODE + 1,
            ..Default::default()
        };
        map.inode_to_path.insert(ROOT_INODE, PathBuf::from("/"));
        map.path_to_inode.insert(PathBuf::from("/"), ROOT_INODE);
        map.inode_to_parent.insert(ROOT_INODE, ROOT_INODE);
        map
    }

    /// The path of a nodeid, falling back to the last known path while open
    /// handles remain on a node that lost its lookup references. `None` means
    /// the kernel dentry is unknown to the map — ENOENT for the caller.
    pub(crate) fn path_of(&self, inode: Inode) -> Option<PathBuf> {
        let path = self
            .inode_to_path
            .get(&inode)
            .or_else(|| self.zombies.get(&inode))
            .cloned();
        if path.is_none() {
            fuselog::event(&format!("INODE no-path inode={inode}"));
        }
        path
    }

    /// The nodeid of a path's parent directory (for `..` in `readdir`).
    pub(crate) fn parent_of(&self, inode: Inode) -> Option<Inode> {
        self.inode_to_parent.get(&inode).copied()
    }

    /// The live nodeid mapped to a path, if any.
    pub(crate) fn inode_of(&self, path: &Path) -> Option<Inode> {
        self.path_to_inode.get(path).copied()
    }

    /// The nodeid for a path, allocating a fresh one when unmapped. `parent`
    /// is the nodeid of the path's parent directory (`readdir` and every
    /// name-carrying operation know it).
    pub(crate) fn get_or_insert(&mut self, path: &Path, parent: Inode) -> Inode {
        if path == Path::new("/") {
            return ROOT_INODE;
        }
        if let Some(&inode) = self.path_to_inode.get(path) {
            return inode;
        }
        let inode = self.next_inode;
        self.next_inode += 1;
        self.inode_to_path.insert(inode, path.to_path_buf());
        self.inode_to_parent.insert(inode, parent);
        self.path_to_inode.insert(path.to_path_buf(), inode);
        inode
    }

    /// A rename moved the kernel dentry from `old` to `new`, keeping the
    /// source's nodeid: re-point the new path at it, dropping the overwritten
    /// target's mapping (the kernel is about to forget that nodeid — and its
    /// `forget` finds no mapping anymore, exactly like the bridge's fix).
    ///
    /// When the source was never looked up (its nodeid is unknown), the new
    /// path keeps the target's mapping, or gets a fresh nodeid — the next
    /// `lookup` would re-map it anyway.
    pub(crate) fn rename(&mut self, old: &Path, new: &Path, new_parent: Inode) {
        let source = self.inode_of(old);

        match source {
            Some(source) => {
                let old_target = self.inode_of(new);
                if old_target != Some(source) {
                    self.release_path(new);
                }

                if old != new {
                    self.inode_to_path.insert(source, new.to_path_buf());
                    self.inode_to_parent.insert(source, new_parent);
                    self.path_to_inode.remove(old);
                    self.path_to_inode.insert(new.to_path_buf(), source);
                    self.repoint_descendants(old, new);
                }
            }

            None => {
                fuselog::event(&format!(
                    "INODE rename UNMAPPED-SOURCE {}",
                    fuselog::path_string(old.as_os_str())
                ));
                self.get_or_insert(new, new_parent);
            }
        }
    }

    /// Re-point every mapped path below `old` at `new`. A renamed directory
    /// keeps every child dentry in the kernel's dcache, rehashed under the
    /// new parent with their nodeids unchanged — the kernel does *not*
    /// re-lookup them, so operations arriving directly on those cached
    /// dentries (e.g. `cat new_dir/file` right after `mv old_dir new_dir`)
    /// resolve the child nodeid to a path that must already be the new one.
    fn repoint_descendants(&mut self, old: &Path, new: &Path) {
        // Collect first: the keys borrow the maps being mutated.
        let moved: Vec<(Inode, PathBuf)> = self
            .inode_to_path
            .iter()
            .filter(|(_, path)| **path != *old && path.starts_with(old))
            .map(|(inode, path)| (*inode, path.clone()))
            .collect();
        for (inode, path) in moved {
            let moved_path = new.join(path.strip_prefix(old).expect("prefix checked"));
            self.path_to_inode.remove(&path);

            // A stale mapping at the child's new name (the rename target
            // already had content) belongs to a dentry the kernel is
            // dropping; releasing it keeps a zombie while handles remain.
            if let Some(&prev) = self.path_to_inode.get(&moved_path) {
                if prev != inode {
                    self.release(prev);
                }
            }
            self.inode_to_path.insert(inode, moved_path.clone());
            self.path_to_inode.insert(moved_path, inode);
        }

        // Zombies under the renamed directory keep their handles open; their
        // remembered paths move with the directory too, so stateless (`fh =
        // 0`) IO still resolves after the rename.
        let zombies: Vec<(Inode, PathBuf)> = self
            .zombies
            .iter()
            .filter(|(_, path)| **path != *old && path.starts_with(old))
            .map(|(inode, path)| (*inode, path.clone()))
            .collect();
        for (inode, path) in zombies {
            let moved_path = new.join(path.strip_prefix(old).expect("prefix checked"));
            self.zombies.insert(inode, moved_path);
        }
    }

    /// Record an open handle on a nodeid (from `open`/`create`/`opendir`).
    pub(crate) fn open_handle(&mut self, inode: Inode) {
        *self.open_counts.entry(inode).or_insert(0) += 1;
    }

    /// A handle was released: when it was the last one and no lookup
    /// references remain, the nodeid's zombie record is freed (the nodeid
    /// itself is never reused).
    pub(crate) fn close_handle(&mut self, inode: Inode) {
        if let Some(count) = self.open_counts.get_mut(&inode) {
            *count -= 1;
            if *count == 0 {
                self.open_counts.remove(&inode);

                if !self.inode_to_path.contains_key(&inode) {
                    self.zombies.remove(&inode);
                }
            }
        }
    }

    /// Drop a nodeid's lookup references (`forget`): the mapping goes away,
    /// unless open handles remain — then the last path is remembered for
    /// those handles (a zombie). Returns the released path for logging.
    pub(crate) fn forget(&mut self, inode: Inode) -> Option<PathBuf> {
        // The root is never forgotten while the session runs: the kernel only
        // forgets it on unmount, and dropping the root mapping would break
        // every path resolution afterwards.
        if inode == ROOT_INODE {
            return None;
        }
        let path = self.inode_to_path.get(&inode).cloned();
        if path.is_some() {
            self.release(inode);
        }
        path
    }

    /// Drop the mapping of a path (unlinked, renamed away, or a failed
    /// lookup), keeping a zombie when open handles remain.
    pub(crate) fn release_path(&mut self, path: &Path) {
        if let Some(inode) = self.path_to_inode.remove(path)
            && self.inode_to_path.get(&inode) == Some(&path.to_path_buf())
        {
            self.release(inode);
        }
    }

    /// Remove a nodeid's mapping; keep the last path as a zombie while open
    /// handles remain. The `path_to_inode` entry is only removed while it
    /// still points at this nodeid — a rename may have re-pointed the path at
    /// another nodeid already.
    fn release(&mut self, inode: Inode) {
        if let Some(path) = self.inode_to_path.remove(&inode) {
            if self.path_to_inode.get(&path) == Some(&inode) {
                self.path_to_inode.remove(&path);
            }
            self.inode_to_parent.remove(&inode);

            if self.open_counts.contains_key(&inode) {
                self.zombies.insert(inode, path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_inode_one_and_its_own_parent() {
        let map = InodeMap::new();
        assert_eq!(map.path_of(ROOT_INODE).as_deref(), Some(Path::new("/")));
        assert_eq!(map.parent_of(ROOT_INODE), Some(ROOT_INODE));
    }

    #[test]
    fn get_or_insert_allocates_fresh_nodeids() {
        let mut map = InodeMap::new();
        let a = map.get_or_insert(Path::new("/a"), ROOT_INODE);
        let b = map.get_or_insert(Path::new("/b"), ROOT_INODE);
        let a_again = map.get_or_insert(Path::new("/a"), ROOT_INODE);
        assert_ne!(a, b);
        assert_ne!(a, ROOT_INODE);
        assert_eq!(a_again, a);
        assert_eq!(map.parent_of(b), Some(ROOT_INODE));
    }

    #[test]
    fn rename_keeps_the_source_nodeid() {
        let mut map = InodeMap::new();
        let src = map.get_or_insert(Path::new("/old"), ROOT_INODE);
        let tgt = map.get_or_insert(Path::new("/new"), ROOT_INODE);

        map.rename(Path::new("/old"), Path::new("/new"), ROOT_INODE);

        // The kernel's moved dentry (nodeid `src`) now resolves at /new...
        assert_eq!(map.path_of(src).as_deref(), Some(Path::new("/new")));
        assert_eq!(map.path_to_inode.get(Path::new("/new")), Some(&src));
        assert_eq!(map.inode_of(Path::new("/new")), Some(src));
        // ...and the overwritten target's mapping is gone: its `forget`
        // finds nothing and the nodeid is never reused.
        assert_eq!(map.path_of(tgt), None);
        assert_eq!(map.inode_of(Path::new("/old")), None);
        let fresh = map.get_or_insert(Path::new("/fresh"), ROOT_INODE);
        assert_ne!(fresh, src);
        assert_ne!(fresh, tgt);
    }

    #[test]
    fn rename_to_a_new_name_drops_the_old_mapping() {
        let mut map = InodeMap::new();
        let src = map.get_or_insert(Path::new("/old"), ROOT_INODE);

        map.rename(Path::new("/old"), Path::new("/moved"), ROOT_INODE);

        assert_eq!(map.path_of(src).as_deref(), Some(Path::new("/moved")));
        assert_eq!(map.inode_of(Path::new("/old")), None);
    }

    #[test]
    fn renaming_a_directory_repoints_descendant_paths() {
        let mut map = InodeMap::new();
        let dir = map.get_or_insert(Path::new("/d-working"), ROOT_INODE);
        let file = map.get_or_insert(Path::new("/d-working/f"), dir);
        let sub = map.get_or_insert(Path::new("/d-working/sub"), dir);
        let deep = map.get_or_insert(Path::new("/d-working/sub/deep"), sub);

        map.rename(Path::new("/d-working"), Path::new("/d-final"), ROOT_INODE);

        // The kernel keeps the child dentries (with their nodeids) and
        // rehashes them under the new parent without re-looking them up.
        assert_eq!(map.path_of(dir).as_deref(), Some(Path::new("/d-final")));
        assert_eq!(map.path_of(file).as_deref(), Some(Path::new("/d-final/f")));
        assert_eq!(
            map.path_of(deep).as_deref(),
            Some(Path::new("/d-final/sub/deep"))
        );
        assert_eq!(map.inode_of(Path::new("/d-final/f")), Some(file));
        assert_eq!(map.inode_of(Path::new("/d-final/sub/deep")), Some(deep));
        assert_eq!(map.inode_of(Path::new("/d-working/f")), None);
        // The child's parent pointer still resolves (the nodeids are kept).
        assert_eq!(map.parent_of(file), Some(dir));
    }

    #[test]
    fn renaming_a_directory_does_not_clobber_sibling_prefixed_paths() {
        let mut map = InodeMap::new();
        let dir = map.get_or_insert(Path::new("/d"), ROOT_INODE);
        let file = map.get_or_insert(Path::new("/d/f"), dir);
        let sibling = map.get_or_insert(Path::new("/d-other"), ROOT_INODE);
        let sibling_file = map.get_or_insert(Path::new("/d-other/f"), sibling);

        map.rename(Path::new("/d"), Path::new("/e"), ROOT_INODE);

        assert_eq!(map.path_of(file).as_deref(), Some(Path::new("/e/f")));
        assert_eq!(map.path_of(sibling_file).as_deref(), Some(Path::new("/d-other/f")));
        assert_eq!(map.inode_of(Path::new("/e/f")), Some(file));
        assert_eq!(map.inode_of(Path::new("/d-other/f")), Some(sibling_file));
    }

    #[test]
    fn renaming_a_directory_moves_open_handle_zombies_too() {
        let mut map = InodeMap::new();
        let dir = map.get_or_insert(Path::new("/d-working"), ROOT_INODE);
        let file = map.get_or_insert(Path::new("/d-working/f"), dir);
        map.open_handle(file);

        // The file's name is dropped (its dentry forgotten) but the handle
        // keeps a zombie — then the directory is renamed.
        map.release_path(Path::new("/d-working/f"));
        map.rename(Path::new("/d-working"), Path::new("/d-final"), ROOT_INODE);

        assert_eq!(map.path_of(file).as_deref(), Some(Path::new("/d-final/f")));

        map.close_handle(file);
        assert_eq!(map.path_of(file), None);
    }

    #[test]
    fn rename_with_an_unmapped_source_keeps_the_target() {
        let mut map = InodeMap::new();
        let tgt = map.get_or_insert(Path::new("/new"), ROOT_INODE);

        map.rename(Path::new("/never-looked-up"), Path::new("/new"), ROOT_INODE);

        assert_eq!(map.inode_of(Path::new("/new")), Some(tgt));
    }

    #[test]
    fn forget_drops_the_mapping_but_never_the_root() {
        let mut map = InodeMap::new();
        let a = map.get_or_insert(Path::new("/a"), ROOT_INODE);

        map.forget(a);
        assert_eq!(map.path_of(a), None);

        map.forget(ROOT_INODE);
        assert_eq!(map.path_of(ROOT_INODE).as_deref(), Some(Path::new("/")));
    }

    #[test]
    fn forgotten_nodes_with_open_handles_become_zombies() {
        let mut map = InodeMap::new();
        let a = map.get_or_insert(Path::new("/a"), ROOT_INODE);
        map.open_handle(a);

        map.forget(a);
        // The handle keeps the nodeid (and its last path) alive...
        assert_eq!(map.path_of(a).as_deref(), Some(Path::new("/a")));

        // ...but a fresh node is mapped at the same path independently.
        let b = map.get_or_insert(Path::new("/a"), ROOT_INODE);
        assert_ne!(a, b);

        map.close_handle(a);
        assert_eq!(map.path_of(a), None);
        // The nodeid is never reused.
        let c = map.get_or_insert(Path::new("/c"), ROOT_INODE);
        assert_ne!(c, a);
    }

    #[test]
    fn release_path_keeps_zombies_too() {
        let mut map = InodeMap::new();
        let a = map.get_or_insert(Path::new("/a"), ROOT_INODE);
        map.open_handle(a);

        map.release_path(Path::new("/a"));
        assert_eq!(map.path_of(a).as_deref(), Some(Path::new("/a")));
        assert_eq!(map.inode_of(Path::new("/a")), None);

        map.close_handle(a);
        assert_eq!(map.path_of(a), None);
    }

    #[test]
    fn release_path_does_not_clobber_a_remapped_path() {
        let mut map = InodeMap::new();
        let old = map.get_or_insert(Path::new("/p"), ROOT_INODE);
        let src = map.get_or_insert(Path::new("/src"), ROOT_INODE);
        map.open_handle(old);

        // A rename re-points /p at src's nodeid while old still holds an
        // open handle (zombie candidate).
        map.rename(Path::new("/src"), Path::new("/p"), ROOT_INODE);
        map.release(old);

        // /p still resolves to src — releasing the zombie must not remove
        // the path mapping that now belongs to another nodeid. The zombie
        // keeps its last path for the still-open handle.
        assert_eq!(map.inode_of(Path::new("/p")), Some(src));
        assert_eq!(map.path_of(src).as_deref(), Some(Path::new("/p")));
        assert_eq!(map.path_of(old).as_deref(), Some(Path::new("/p")));

        map.close_handle(old);
        assert_eq!(map.path_of(old), None);
        assert_eq!(map.inode_of(Path::new("/p")), Some(src));
    }
}
