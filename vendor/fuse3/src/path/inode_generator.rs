use slab::Slab;

use crate::Inode;

#[derive(Debug)]
pub struct InodeGenerator {
    slab: Slab<()>,
}

impl InodeGenerator {
    pub fn new() -> Self {
        let mut slab = Slab::new();
        // drop 0 key
        slab.insert(());

        Self { slab }
    }

    pub fn allocate_inode(&mut self) -> Inode {
        self.slab.insert(()) as _
    }

    /// Give a nodeid back.
    ///
    /// This deliberately does **not** hand the number out again: the FUSE
    /// kernel module keeps its inode objects in its icache keyed by nodeid
    /// (open file handles, dirty page-cache pages, and dentries all hold
    /// references that outlive the lookup count — `FORGET` only covers the
    /// lookup references). Reusing a nodeid whose kernel inode object is
    /// still alive makes `fuse_iget` re-attach a *new* dentry to the *old*
    /// inode object — with the old file type, size and attributes — which
    /// produces ESTALE, EISDIR/ENOTDIR, interleaved file content and other
    /// corruption under load (this is exactly what made `cargo build` fail
    /// erratically through the rs-bubble hostfs mirror; see FINDINGS.md).
    ///
    /// The numbers are only ever allocated, never recycled, so they stay
    /// unique for the whole session.
    pub fn release_inode(&mut self, _inode: Inode) {
        // Nodeids are never recycled (see above). The slab grows by one
        // entry per allocated nodeid (~8 bytes) — bounded by the number of
        // distinct inodes a session touches.
    }
}
