//! The raw fuse3 `Filesystem` implementation for [`HostFs`]: every FUSE
//! operation resolves through the [`InodeMap`]/pattern tables owned by
//! the `HostFs` state (see `mod.rs`), and talks to the host via the
//! dirfd-anchored helpers in [`anchored`].

use super::*;

/// The mode mask every *creation* path applies (AUDIT.md H3): the usual
/// `0o7777` permission bits, minus the setuid/setgid bits (`0o6000`).
/// The kernel honors setuid/setgid in the `open(O_CREAT)`/`mkdirat` mode
/// (umask only masks `0777`, and `inode_init_owner` never clears
/// `S_ISUID`), so passing a `0o4755` through unmasked would create a
/// setuid binary owned by the invoking user — inert for an unprivileged
/// ai-bubble, but a setuid-root escalation when ai-bubble runs as root
/// (e.g. in a container). The `setattr` chmod path applies the same mask.
pub(super) const SAFE_MODE: libc::mode_t = 0o7777 & !0o6000;

/// [`attr_from_metadata`], for the dirfd-anchored stat results (see
/// [`anchored`]). `ino` is filled in by the reply sites that know it.
pub(super) fn attr_from_stat(st: &libc::stat) -> FileAttr {
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        libc::S_IFCHR => FileType::CharDevice,
        libc::S_IFBLK => FileType::BlockDevice,
        libc::S_IFIFO => FileType::NamedPipe,
        libc::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    };
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: st.st_size as u64,
        blocks: st.st_blocks as u64,
        atime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_atime.max(0) as u64, st.st_atime_nsec.max(0) as u32))
        .into(),
        mtime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_mtime.max(0) as u64, st.st_mtime_nsec.max(0) as u32))
        .into(),
        ctime: (SystemTime::UNIX_EPOCH
            + Duration::new(st.st_ctime.max(0) as u64, st.st_ctime_nsec.max(0) as u32))
        .into(),
        kind,
        perm: (st.st_mode & 0o7777) as u16,
        nlink: st.st_nlink as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev as u32,
        blksize: st.st_blksize as u32,
    }
}

pub(super) fn attr_from_metadata(md: &std::fs::Metadata) -> FileAttr {
    let kind = md.file_type();
    let kind = if kind.is_dir() {
        FileType::Directory
    } else if kind.is_symlink() {
        FileType::Symlink
    } else if kind.is_char_device() {
        FileType::CharDevice
    } else if kind.is_block_device() {
        FileType::BlockDevice
    } else if kind.is_fifo() {
        FileType::NamedPipe
    } else if kind.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    };
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: md.size(),
        blocks: md.blocks(),
        atime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.atime().max(0) as u64, md.atime_nsec().max(0) as u32))
        .into(),
        mtime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.mtime().max(0) as u64, md.mtime_nsec().max(0) as u32))
        .into(),
        ctime: (SystemTime::UNIX_EPOCH
            + Duration::new(md.ctime().max(0) as u64, md.ctime_nsec().max(0) as u32))
        .into(),
        kind,
        perm: (md.mode() & 0o7777) as u16,
        nlink: md.nlink() as u32,
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev() as u32,
        blksize: md.blksize() as u32,
    }
}

pub(super) fn root_attr(uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        // Filled in by the reply sites that know the nodeid.
        ino: 0,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH.into(),
        mtime: SystemTime::UNIX_EPOCH.into(),
        ctime: SystemTime::UNIX_EPOCH.into(),
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
    }
}

/// The bridge passes absolute paths ("/etc/passwd") and is lenient about a
/// missing leading slash.
pub(super) fn is_root(path: &OsStr) -> bool {
    path == Path::new("/") || path.is_empty()
}

/// A minimal, self-consistent `statfs` for paths with no real host
/// counterpart (virtual/injected paths, and the synthetic mirror root —
/// see the `statfs` op): one block, one file, small fixed sizes.
fn minimal_statfs() -> ReplyStatFs {
    ReplyStatFs {
        blocks: 1,
        bfree: 0,
        bavail: 0,
        files: 1,
        ffree: 0,
        bsize: 512,
        namelen: 255,
        frsize: 512,
    }
}

impl Filesystem for HostFs {
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        perf::fuse_op!("init");
        // Advertise a large max write (the kernel clamps it to its own
        // limit): with a tiny value the kernel splits every write into
        // small FUSE requests, multiplying the per-request overhead.
        Ok(ReplyInit {
            max_write: NonZeroU32::new(1024 * 1024).unwrap(),
        })
    }

    async fn destroy(&self, _req: Request) {
        perf::fuse_op!("destroy");
    }

    /// A forgotten nodeid loses its mapping (the kernel is done with the
    /// dentry); a nodeid with open handles keeps its last path as a zombie.
    async fn forget(&self, _req: Request, inode: Inode, nlookup: u64) {
        perf::fuse_op!("forget");
        let path = self
            .inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .forget(inode);
        fuselog::event!(
            "INODE forget inode={inode} nlookup={nlookup} path={}",
            path.map(|p| fuselog::path_string(p.as_os_str()))
                .unwrap_or_else(|| "<gone>".into())
        );
    }

    async fn batch_forget(&self, _req: Request, inodes: &[Inode]) {
        perf::fuse_op!("batch_forget");
        let mut map = self.inodes.write().unwrap_or_else(|e| e.into_inner());
        for &inode in inodes {
            let path = map.forget(inode);
            fuselog::event!(
                "INODE batch-forget inode={inode} path={}",
                path.map(|p| fuselog::path_string(p.as_os_str()))
                    .unwrap_or_else(|| "<gone>".into())
            );
        }
    }

    async fn lookup(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<ReplyEntry> {
        perf::fuse_op!("lookup");
        // The nodeid resolves to the parent's mirrored path; "/" means the
        // root directory itself.
        let parent_path = match self.resolve(parent) {
            Ok(p) => p,
            Err(e) => {
                fuselog::event!(
                    "INODE lookup no-parent inode={parent} name={}",
                    fuselog::path_string(name)
                );
                return Err(e.into());
            }
        };
        let mirrored = parent_path.join(name);
        if self.patterns.exists(&mirrored) {
            match self.attr(&mirrored) {
                Ok(mut attr) => {
                    let inode = self
                        .inodes
                        .write().unwrap_or_else(|e| e.into_inner())
                        .get_or_insert(&mirrored, parent);
                    attr.ino = inode;
                    return Ok(ReplyEntry {
                        ttl: TTL,
                        attr,
                        generation: 0,
                    });
                }
                Err(e) => {
                    log_op_err(
                        "lookup",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    if e.kind() == std::io::ErrorKind::NotFound {
                        // The kernel dentry is stale: drop the mapping so the
                        // next lookup re-maps the path (a zombie stays while
                        // open handles remain).
                        self.inodes
                            .write().unwrap_or_else(|e| e.into_inner())
                            .release_path(&mirrored);
                    }
                    return Err(e.into());
                }
            }
        }
        log_op_err(
            "lookup",
            &mirrored,
            None,
            &std::io::Error::from_raw_os_error(libc::ENOENT),
        )
        .await;
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .release_path(&mirrored);
        Err(libc::ENOENT.into())
    }

    async fn getattr(
        &self,
        _req: Request,
        inode: Inode,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        perf::fuse_op!("getattr");
        let mirrored = match self.resolve(inode) {
            Ok(p) => p,
            Err(e) => {
                fuselog::event(&format!("INODE getattr no-path inode={inode}"));
                return Err(e.into());
            }
        };
        if is_root(mirrored.as_os_str()) {
            let mut attr = root_attr(self.uid, self.gid);
            attr.ino = inode;
            return Ok(ReplyAttr { ttl: TTL, attr });
        }
        if self.patterns.exists(&mirrored) {
            match self.attr(&mirrored) {
                Ok(mut attr) => {
                    attr.ino = inode;
                    return Ok(ReplyAttr { ttl: TTL, attr });
                }
                Err(e) => {
                    log_op_err(
                        "getattr",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            }
        }
        log_op_err(
            "getattr",
            &mirrored,
            None,
            &std::io::Error::from_raw_os_error(libc::ENOENT),
        )
        .await;
        Err(libc::ENOENT.into())
    }

    async fn readlink(&self, _req: Request, inode: Inode) -> Result<ReplyData> {
        perf::fuse_op!("readlink");
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        let target = anchored::read_link(&self.root, &self.patterns.redirect(&mirrored))?;
        Ok(ReplyData::from(Bytes::copy_from_slice(
            target.as_os_str().as_encoded_bytes(),
        )))
    }

    async fn open(&self, _req: Request, inode: Inode, flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("open");
        let mirrored = self.resolve(inode)?;
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not).
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "open",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // An injected path is a purely virtual file: served from memory,
        // never writable, the host is not consulted at all.
        if let Some(_content) = self.patterns.is_inject(&mirrored) {
            let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
            if write_flags {
                log_op_err(
                    "open",
                    &mirrored,
                    None,
                    &std::io::Error::from_raw_os_error(libc::EACCES),
                )
                .await;
                return Err(libc::EACCES.into());
            }
            self.inodes
                .write().unwrap_or_else(|e| e.into_inner())
                .open_handle(inode);
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        // An `empty` path is blanked out of the sandbox: like an injected
        // path it is a purely virtual file (served as empty, never writable,
        // the host file — which may really exist — is never opened). Without
        // this check, opening a real host file under an `empty` mapping would
        // register a stateful handle serving the real bytes, defeating the
        // mapping (the stateless read path already serves zero bytes for
        // empty paths; only the handle fast-path bypasses the spec check).
        if self.patterns.is_empty(&mirrored) {
            let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
            if write_flags {
                log_op_err(
                    "open",
                    &mirrored,
                    None,
                    &std::io::Error::from_raw_os_error(libc::EACCES),
                )
                .await;
                return Err(libc::EACCES.into());
            }
            self.inodes
                .write().unwrap_or_else(|e| e.into_inner())
                .open_handle(inode);
            return Ok(ReplyOpen { fh: 0, flags: 0 });
        }
        // The path is visible through the mirror; only real files are
        // openable (a directory that merely leads to a match is not), and
        // symlinks are never followed: a host symlink cannot be opened
        // through the mirror (its target may not be mirrored at all). The
        // metadata is taken from the dirfd-anchored path: no intermediate
        // component may resolve through a host symlink.
        let real = self.patterns.redirect(&mirrored);
        let md_stat = match self.real_lstat(&real) {
            Ok(st) => st,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&real), &e).await;
                // A purely virtual directory (ancestor of an empty or
                // injected path with no real counterpart) is not openable,
                // exactly like a real one that `open` refuses: report it as
                // a directory rather than as missing (the kernel only asks
                // to open directories it has already resolved).
                if e.kind() == std::io::ErrorKind::NotFound
                    && (self.patterns.is_empty_prefix(&mirrored)
                        || self.patterns.is_inject_prefix(&mirrored))
                {
                    return Err(libc::EISDIR.into());
                }
                return Err(libc::ENOENT.into());
            }
        };
        if Self::stat_is_symlink(&md_stat) {
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
                &std::io::Error::from_raw_os_error(libc::ELOOP),
            )
            .await;
            return Err(libc::ELOOP.into());
        }
        if Self::stat_is_dir(&md_stat) {
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
                &std::io::Error::from_raw_os_error(libc::EISDIR),
            )
            .await;
            return Err(libc::EISDIR.into());
        }
        let write_flags = flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32) != 0;
        if write_flags && !self.patterns.writable(&mirrored) {
            // `ro` paths (and anything below an empty or hidden pattern) are
            // never writable; the real file permissions are checked by the
            // host filesystem on the actual write.
            log_op_err(
                "open",
                &mirrored,
                Some(&real),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // The kernel passes O_TRUNC through to the server: the server must
        // do the truncation itself. Write paths (rustc, cargo, …) always
        // open their outputs with O_TRUNC, so ignoring it would leave the
        // tail of the old content in place behind the newly written data.
        // The truncation happens in the open below (the file is opened for
        // real and kept for the handle's lifetime).
        let append = flags & libc::O_APPEND as u32 != 0;
        let mut oflags = if !write_flags {
            libc::O_RDONLY
        } else if flags & libc::O_RDWR as u32 != 0 {
            libc::O_RDWR
        } else {
            libc::O_WRONLY
        };
        if append {
            oflags |= libc::O_APPEND;
        }
        if write_flags && flags & libc::O_TRUNC as u32 != 0 {
            oflags |= libc::O_TRUNC;
        }
        // Anchored open relative to the pinned parent, final component
        // `O_NOFOLLOW` (see [`anchored`]).
        let file = match anchored::open_at(&self.root, &real, oflags, 0) {
            Ok(f) => f,
            Err(e) => {
                log_op_err("open", &mirrored, Some(&real), &e).await;
                return Err(e.into());
            }
        };
        // Stateful IO: the opened host file is reused for every read/write
        // on this handle (released with it in `release`).
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .open_handle(inode);
        let writable = self.patterns.writable(&mirrored);
        let fh = match self.insert_handle(file, mirrored, append, writable) {
            Ok(fh) => fh,
            Err(e) => {
                // AUDIT.md L13: the speculative `open_handle` count above
                // must be released when the handle could not be inserted,
                // or the nodeid leaks a permanent zombie entry after
                // `forget`.
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .close_handle(inode);
                return Err(e.into());
            }
        };
        Ok(ReplyOpen { fh, flags: 0 })
    }

    async fn read(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        perf::fuse_op!("read");
        // Stateful IO first: a real handle can only come from `open`/`create`,
        // which already established that the path is mirrored (exists), not
        // injected and not empty — the per-request spec checks below are
        // skipped entirely on this path (they re-match every pattern).
        if fh != 0
            && let Some(handle) = self.handle_of(fh)
        {
            // The handle caches the mirrored path from open time; the path is
            // only used for error logging here, so the inode map is never
            // consulted on this fast path. The guard's scope ends before any
            // await (a std MutexGuard is not Send, and the sync IO makes the
            // await-free block trivial).
            let read_result = {
                let mut file = handle.file.lock().unwrap_or_else(|e| e.into_inner());
                file.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; size as usize];
                file.read(&mut buf).map(|n| {
                    buf.truncate(n);
                    buf
                })
            };
            let buf = match read_result {
                Ok(buf) => buf,
                Err(e) => {
                    log_op_err(
                        "read-io",
                        &handle.path,
                        Some(&self.patterns.redirect(&handle.path)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
            return Ok(ReplyData::from(Bytes::from(buf)));
        }
        let mirrored = match self.resolve(inode) {
            Ok(p) => p,
            Err(e) => {
                log_op_err(
                    "read",
                    Path::new("<none>"),
                    None,
                    &std::io::Error::from_raw_os_error(libc::ENOENT),
                )
                .await;
                return Err(e.into());
            }
        };
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "read",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // An injected path is served from memory: slice the content at
        // the requested offset (nothing is read from the host).
        if let Some(content) = self.patterns.is_inject(&mirrored) {
            let bytes = content.as_bytes();
            let offset = offset.min(bytes.len() as u64) as usize;
            let end = (offset + size as usize).min(bytes.len());
            return Ok(ReplyData::from(Bytes::copy_from_slice(&bytes[offset..end])));
        }
        // An empty path has no content: an empty file reads as empty (the
        // host file is never opened).
        if self.patterns.is_empty(&mirrored) {
            return Ok(ReplyData::from(Bytes::new()));
        }
        // Stateless IO fallback: reopen the host file relative to the pinned
        // parent — never following symlinks (a host symlink is visible only
        // as a link, and its target may not be mirrored at all; and no
        // intermediate component is followed either).
        let mut file = match anchored::open_at(
            &self.root,
            &self.patterns.redirect(&mirrored),
            libc::O_RDONLY,
            0,
        ) {
            Ok(f) => f,
            Err(e) => {
                log_op_err(
                    "read",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
                return Err(e.into());
            }
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size as usize];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                log_op_err(
                    "read-io",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
                return Err(e.into());
            }
        };
        buf.truncate(n);
        Ok(ReplyData::from(Bytes::from(buf)))
    }

    async fn write(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        perf::fuse_op!("write");
        // The handle is looked up before the path: a real handle caches the
        // mirrored path from open time, so the stateful fast path never
        // consults the inode map.
        let handle = if fh != 0 { self.handle_of(fh) } else { None };
        let mirrored = match &handle {
            // Only used for logging on this path; the IO goes through the
            // cached file descriptor.
            Some(h) => h.path.clone(),
            None => match self.resolve(inode) {
                Ok(p) => p,
                Err(e) => {
                    log_op_err(
                        "write",
                        Path::new("<none>"),
                        None,
                        &std::io::Error::from_raw_os_error(libc::ENOENT),
                    )
                    .await;
                    return Err(e.into());
                }
            },
        };
        // A real handle caches the spec verdict (`writable`) from open time;
        // the exists/inject/empty checks are skipped entirely on this path
        // (they re-match every pattern per request). Injected paths are
        // never writable and never get a real handle, so only the writable
        // verdict matters here.
        let writable = match &handle {
            Some(h) => h.writable,
            None => self.patterns.writable(&mirrored),
        };
        if handle.is_none() && !self.patterns.exists(&mirrored) {
            log_op_err(
                "write",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !writable {
            // The spec must say `rw`; the real file permissions are
            // enforced by the host filesystem on the open below.
            log_op_err(
                "write",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Stateful IO: the handle keeps the host file open — reuse it instead
        // of reopening per request. An unknown `fh` falls back to the
        // stateless reopen below.
        let append = flags & libc::O_APPEND as u32 != 0;
        if let Some(handle) = handle {
            // The guard's scope ends before any await (a std MutexGuard is
            // not Send, and the sync IO makes the await-free block trivial).
            let write_result = {
                let mut file = handle.file.lock().unwrap_or_else(|e| e.into_inner());
                if !handle.append {
                    file.seek(SeekFrom::Start(offset))?;
                }
                file.write(data)
            };
            let n = match write_result {
                Ok(n) => n,
                Err(e) => {
                    log_op_err(
                        "write-io",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
            crate::audit::record(
                "hostfs",
                "write",
                Some(&mirrored.to_string_lossy()),
                Some("ok"),
                Some(format!("{} bytes at offset {}", n, offset)),
            )
            .await;
            return Ok(ReplyWrite { written: n as u32 });
        }
        // Stateless IO fallback: reopen the host file relative to the pinned
        // parent — never following symlinks (a host symlink is never
        // written through; its target may not be mirrored at all; and no
        // intermediate component is followed either).
        let mut oflags = libc::O_WRONLY;
        if append {
            oflags |= libc::O_APPEND;
        }
        let mut file =
            match anchored::open_at(&self.root, &self.patterns.redirect(&mirrored), oflags, 0) {
                Ok(f) => f,
                Err(e) => {
                    log_op_err(
                        "write",
                        &mirrored,
                        Some(&self.patterns.redirect(&mirrored)),
                        &e,
                    )
                    .await;
                    return Err(e.into());
                }
            };
        if !append {
            file.seek(SeekFrom::Start(offset))?;
        }
        let n = match file.write(data) {
            Ok(n) => n,
            Err(e) => {
                log_op_err(
                    "write-io",
                    &mirrored,
                    Some(&self.patterns.redirect(&mirrored)),
                    &e,
                )
                .await;
                return Err(e.into());
            }
        };
        crate::audit::record(
            "hostfs",
            "write",
            Some(&mirrored.to_string_lossy()),
            Some("ok"),
            Some(format!("{} bytes at offset {}", n, offset)),
        )
        .await;
        Ok(ReplyWrite { written: n as u32 })
    }
    async fn statfs(&self, _req: Request, inode: Inode) -> Result<ReplyStatFs> {
        perf::fuse_op!("statfs");
        // Report the real filesystem holding the mirrored path (or "/" for
        // the root), so tools like `df` behave sensibly. The path is opened
        // with `O_NOFOLLOW` and `fstatvfs` runs on the descriptor: symlinks
        // are never followed to a filesystem outside the mirror.
        let mirrored = self.resolve(inode)?;
        // The mirror root is synthetic: it must not be resolved to the
        // pinned HOST root directory (whose `fstatvfs` would report the
        // host `/` filesystem — its total/free space and type — to the
        // sandbox; AUDIT.md finding M1). Report the same minimal,
        // self-consistent statfs as virtual paths below.
        if is_root(mirrored.as_os_str()) {
            return Ok(minimal_statfs());
        }
        // An injected path has no host counterpart: report a minimal,
        // self-consistent statfs instead of opening anything. The same
        // holds for a purely virtual ancestor of an injected (or empty)
        // path with no real counterpart: it is a virtual directory, and
        // there is nothing to open on the host.
        if self.patterns.is_inject(&mirrored).is_some()
            || (self.patterns.is_empty_prefix(&mirrored)
                || self.patterns.is_inject_prefix(&mirrored))
                && !self.real_exists(&self.patterns.redirect(&mirrored))
        {
            return Ok(minimal_statfs());
        }
        let real = if is_root(mirrored.as_os_str()) {
            PathBuf::from("/")
        } else {
            self.patterns.redirect(&mirrored)
        };
        // O_PATH works on any file type (including directories) and
        // O_NOFOLLOW keeps symlinked final components from being followed —
        // anchored, so intermediate components are not either.
        let fd = match anchored::open_full(&self.root, &real, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(e) => return Err(e.into()),
        };
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid descriptor and a writable `statvfs` buffer.
        let rc = unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut vfs) };
        let err = std::io::Error::last_os_error();
        drop(fd);
        if rc != 0 {
            return Err(err.into());
        }
        Ok(ReplyStatFs {
            blocks: vfs.f_blocks,
            bfree: vfs.f_bfree,
            bavail: vfs.f_bavail,
            files: vfs.f_files,
            ffree: vfs.f_ffree,
            bsize: vfs.f_bsize as u32,
            namelen: vfs.f_namemax as u32,
            frsize: vfs.f_frsize as u32,
        })
    }

    async fn opendir(&self, _req: Request, inode: Inode, _flags: u32) -> Result<ReplyOpen> {
        perf::fuse_op!("opendir");
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .open_handle(inode);
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn readdir<'a>(
        &'a self,
        _req: Request,
        parent: Inode,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl futures_util::Stream<Item = Result<DirectoryEntry>> + Send + 'a>>
    {
        perf::fuse_op!("readdir");
        let mirrored = self.resolve(parent)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored, parent, offset.max(0) as usize)
            .into_iter()
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid.
        let mut map = self.inodes.write().unwrap_or_else(|e| e.into_inner());
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(i, (name, attr))| {
                let inode = if name == *OsStr::new(".") {
                    parent
                } else if name == *OsStr::new("..") {
                    map.parent_of(parent).unwrap_or(inodes::ROOT_INODE)
                } else {
                    map.get_or_insert(&mirrored.join(&name), parent)
                };
                Ok(DirectoryEntry {
                    inode,
                    kind: attr.map(|a| a.kind).unwrap_or(FileType::RegularFile),
                    name,
                    offset: offset.max(0) + i as i64 + 1,
                })
            })
            .collect();
        Ok(ReplyDirectory {
            entries: stream::iter(entries),
        })
    }

    async fn readdirplus<'a>(
        &'a self,
        _req: Request,
        parent: Inode,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<
        ReplyDirectoryPlus<
            impl futures_util::Stream<Item = Result<DirectoryEntryPlus>> + Send + 'a,
        >,
    > {
        perf::fuse_op!("readdirplus");
        let mirrored = self.resolve(parent)?;
        if !self.patterns.exists(&mirrored)
            || !is_root(mirrored.as_os_str()) && !self.is_listable_dir(&mirrored)
        {
            return Err(libc::ENOENT.into());
        }
        let entries: Vec<_> = self
            .dir_entries(&mirrored, parent, offset as usize)
            .into_iter()
            .enumerate()
            .collect();
        // Every listed entry needs a nodeid for the kernel's dentry cache:
        // "." is the directory itself, ".." its parent, everything else is
        // mapped (or re-mapped) under the directory's nodeid — and carries
        // its attributes with the nodeid filled in.
        let mut map = self.inodes.write().unwrap_or_else(|e| e.into_inner());
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(i, (name, attr))| {
                let inode = if name == *OsStr::new(".") {
                    parent
                } else if name == *OsStr::new("..") {
                    map.parent_of(parent).unwrap_or(inodes::ROOT_INODE)
                } else {
                    map.get_or_insert(&mirrored.join(&name), parent)
                };
                let mut attr = attr;
                if let Ok(a) = attr.as_mut() {
                    a.ino = inode;
                }
                Ok(DirectoryEntryPlus {
                    inode,
                    generation: 0,
                    kind: attr
                        .as_ref()
                        .map(|a| a.kind)
                        .unwrap_or(FileType::RegularFile),
                    name,
                    offset: (offset + i as u64 + 1) as i64,
                    attr: attr?,
                    entry_ttl: TTL,
                    attr_ttl: TTL,
                })
            })
            .collect();
        Ok(ReplyDirectoryPlus {
            entries: stream::iter(entries),
        })
    }

    async fn access(&self, _req: Request, inode: Inode, mask: u32) -> Result<()> {
        perf::fuse_op!("access");
        let mirrored = self.resolve(inode)?;
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        // Empty paths (and purely virtual ancestors) are unwritable by
        // definition; answer directly instead of asking the real filesystem.
        // Injected paths are virtual, too: readable, never writable. The
        // same holds for purely virtual ancestors of injected files: the
        // kernel consults `access` for `chdir` (MAY_CHDIR), so an
        // unanswered ENOENT here would make a directory that `ls` lists
        // and `stat` resolves impossible to `cd` into.
        if self.virtual_only(&mirrored) {
            if mask & libc::W_OK as u32 != 0 {
                return Err(libc::EACCES.into());
            }
            return Ok(());
        }
        // The mirror root is synthetic: answering via the anchor would
        // `faccessat` the HOST root directory (`.` under the pinned
        // host-root descriptor), probing the host root's real permissions
        // (AUDIT.md finding M1). Answer from policy instead: writability
        // is the spec's decision, read/traverse are inherent to the
        // synthetic root (it is always listable and navigable).
        if is_root(mirrored.as_os_str()) {
            if mask & libc::W_OK as u32 != 0 && !self.patterns.writable(&mirrored) {
                return Err(libc::EACCES.into());
            }
            return Ok(());
        }
        // W_OK is answered by the spec: only `rw` paths may be written (the
        // real file permissions are checked when a write is attempted).
        let non_write = mask & !(libc::W_OK as u32);
        if mask & libc::W_OK as u32 != 0 && !self.patterns.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        // The rest (R_OK, X_OK) is decided by the real filesystem, with the
        // server's real (host) credentials.
        if non_write == 0 {
            return Ok(());
        }
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real).map_err(|e| {
            // ENOENT mapping preserved from the old cpath construction.
            if e.raw_os_error() == Some(libc::EINVAL) {
                return std::io::Error::from_raw_os_error(libc::ENOENT);
            }
            e
        })?;
        // `faccessat` with `AT_SYMLINK_NOFOLLOW` on the pinned parent —
        // never follow symlinks (final component or otherwise) when
        // deciding access on the real host filesystem.
        if unsafe {
            libc::faccessat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                non_write as libc::c_int,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    async fn setattr(
        &self,
        _req: Request,
        inode: Inode,
        _fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        perf::fuse_op!("setattr");
        let mirrored = self.resolve(inode)?;
        // The mirror root is a synthetic inode (see `getattr`): it has no
        // host counterpart of its own, and its parent anchor would be the
        // pinned HOST root directory with the name `.` — a setattr here
        // would chmod/chown/utimens the host `/` (AUDIT.md finding M1).
        // Nothing in the mirror needs metadata changes on the synthetic
        // root, so refuse unconditionally.
        if is_root(mirrored.as_os_str()) {
            return Err(libc::EACCES.into());
        }
        if self.patterns.is_empty(&mirrored) {
            // Empty paths are virtual: nothing to change.
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            return Err(libc::EACCES.into());
        }
        let real = self.patterns.redirect(&mirrored);
        // Anchor the parent once: every operation below is an `*at()`
        // syscall relative to the pinned parent descriptor, so no component
        // of the path can resolve through a host symlink (final-component
        // no-follow semantics are kept per operation, as before).
        let anchored = anchored::anchor_parent(&self.root, &real)?;
        let dirfd = anchored.dir().as_raw_fd();
        let name = anchored.name().as_ptr();
        if let Some(size) = set_attr.size {
            // Never follow symlinks: a host symlink is not truncated
            // through (its target may not be mirrored at all).
            let fd = unsafe {
                libc::openat(
                    dirfd,
                    name,
                    libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: `fd` is a freshly opened, owned descriptor.
            let f = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
            f.set_len(size)?;
        }
        if let Some(mode) = set_attr.mode {
            // chmod must not follow a final-component symlink: applied to
            // a mirrored path that is a host symlink at a writable location,
            // a following chmod would change the permissions of the symlink's
            // TARGET, which may live outside every mapping (finding M4).
            // Prefer `fchmodat(AT_SYMLINK_NOFOLLOW)` (glibc 2.32+ forwards it
            // to `fchmodat2`, Linux ≥ 6.6), which changes the mode of the
            // symlink inode itself. On older glibc/kernel combinations the
            // flag is unsupported (EINVAL/ENOSYS/EOPNOTSUPP); fall back to a
            // lstat check: refuse to chmod a symlink at all (EACCES, matching
            // the sibling denial style above) and otherwise chmod the regular
            // file/directory with the historic flags.
            //
            // The requested mode is masked with `SAFE_MODE` (`0o7777` with
            // the setuid/setgid bits (0o6000) stripped silently): for an
            // unprivileged user fchmod cannot set them anyway, but ai-bubble
            // may legitimately run elevated (root in a container), and then
            // a mode like 0o4755 through the mirror would plant dangerous
            // privilege bits on the host.
            let mode = (mode & SAFE_MODE) as libc::mode_t;
            if unsafe { libc::fchmodat(dirfd, name, mode, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {}
                    _ => return Err(err.into()),
                }
                // Flag unsupported: make sure the final component is not a
                // symlink before chmod-following it.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        dirfd,
                        name,
                        &mut st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    // Deny: the entry is a host symlink, its target is not
                    // guaranteed to be mirrored.
                    return Err(libc::EACCES.into());
                }
                if unsafe { libc::fchmodat(dirfd, name, mode, 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
        }
        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            let uid = set_attr.uid.unwrap_or(u32::MAX);
            let gid = set_attr.gid.unwrap_or(u32::MAX);
            if unsafe { libc::fchownat(dirfd, name, uid, gid, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        if set_attr.atime.is_some() || set_attr.mtime.is_some() {
            let times = [
                ts_to_timespec(set_attr.atime),
                ts_to_timespec(set_attr.mtime),
            ];
            if unsafe { libc::utimensat(dirfd, name, times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }
                != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let mut attr = self.attr(&mirrored)?;
        attr.ino = inode;
        Ok(ReplyAttr { ttl: TTL, attr })
    }

    async fn mkdir(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        _umask: u32,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("mkdir");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only a *real* entry at the target means EEXIST; a path merely
        // matched by a wildcard pattern may not exist yet. (Anchored:
        // no symlink is followed anywhere on the host path.)
        if self.real_exists(&self.patterns.redirect(&mirrored)) {
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EEXIST),
            )
            .await;
            return Err(libc::EEXIST.into());
        }
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real).map_err(|e| {
            if e.raw_os_error() == Some(libc::EINVAL) {
                return std::io::Error::from_raw_os_error(libc::ENOENT);
            }
            e
        })?;
        let rc = unsafe {
            libc::mkdirat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                // AUDIT.md H3: `SAFE_MODE` strips the setuid/setgid bits —
                // the kernel honors them in `mkdirat`'s mode.
                (mode & SAFE_MODE) as libc::mode_t,
            )
        };
        if rc != 0 {
            // Capture the error right after the syscall (errno is per-thread
            // and any intervening call would clobber it).
            let e = std::io::Error::last_os_error();
            log_op_err(
                "mkdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            return Err(fuse3::Errno::from(e));
        }
        log_op_ok("mkdir", &mirrored, &self.patterns.redirect(&mirrored)).await;
        let inode = self
            .inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .get_or_insert(&mirrored, parent);
        let mut attr = self.attr(&mirrored)?;
        attr.ino = inode;
        Ok(ReplyEntry {
            ttl: TTL,
            attr,
            generation: 0,
        })
    }

    async fn unlink(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("unlink");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if self.patterns.is_empty(&mirrored) {
            // Empty paths are virtual mount points; they cannot be removed.
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "unlink",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&mirrored))?;
        if unsafe { libc::unlinkat(anchored.dir().as_raw_fd(), anchored.name().as_ptr(), 0) } != 0 {
            let e = std::io::Error::last_os_error();
            log_op_err(
                "unlink",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::EISDIR) {
                // Unlinking a directory: the kernel keeps the dentry, so the
                // name must stay resolvable.
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("unlink", &mirrored, &self.patterns.redirect(&mirrored)).await;
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .release_path(&mirrored);
        Ok(())
    }
    async fn rmdir(&self, _req: Request, parent: Inode, name: &OsStr) -> Result<()> {
        perf::fuse_op!("rmdir");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        if self.patterns.is_empty(&mirrored) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&mirrored) {
            log_op_err(
                "rmdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&mirrored))?;
        if unsafe {
            libc::unlinkat(
                anchored.dir().as_raw_fd(),
                anchored.name().as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            log_op_err(
                "rmdir",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &e,
            )
            .await;
            if e.kind() == std::io::ErrorKind::NotFound {
                // A stale kernel dentry: drop the mapping.
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .release_path(&mirrored);
            } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                // Rmdir of a non-directory: the kernel keeps the dentry, so
                // the name must stay resolvable.
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .get_or_insert(&mirrored, parent);
            }
            return Err(e.into());
        }
        log_op_ok("rmdir", &mirrored, &self.patterns.redirect(&mirrored)).await;
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .release_path(&mirrored);
        Ok(())
    }

    async fn rename(
        &self,
        _req: Request,
        origin_parent: Inode,
        origin_name: &OsStr,
        parent: Inode,
        name: &OsStr,
    ) -> Result<()> {
        perf::fuse_op!("rename");
        let origin_parent_path = self.resolve(origin_parent)?;
        let new_parent_path = self.resolve(parent)?;
        let old = origin_parent_path.join(origin_name);
        let new = new_parent_path.join(name);
        if self.patterns.is_empty(&old) || self.patterns.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&old) {
            log_op_err(
                "rename",
                &old,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        if !self.patterns.writable(&old) || !self.patterns.writable(&new) {
            log_op_err(
                "rename",
                &old,
                Some(&self.patterns.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        let old_real = self.patterns.redirect(&old);
        let new_real = self.patterns.redirect(&new);
        // A *directory* rename carries every child from one pattern
        // context to another: a `hide` or `ro` rule that might apply to a
        // child of the source (or of the destination) must block the
        // move. Moving the directory out of such a rule's reach would
        // expose — or make writable — content the spec hides or keeps
        // read-only (e.g. `/project/src` is `rw` but
        // `/project/src/**/*.bin` is `hide`); moving another directory
        // *into* such a subtree is denied as well, so content cannot be
        // planted there and carried back out with the same effect.
        let dir_rename = self.is_host_dir(&old_real) || self.is_host_dir(&new_real);
        if dir_rename
            && (self.patterns.subtree_restricted(&old) || self.patterns.subtree_restricted(&new))
        {
            log_op_err(
                "rename",
                &old,
                Some(&new_real),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Both parents are pinned before the atomic `renameat` between
        // them: no component of either path can resolve through a host
        // symlink, and a swap between the two resolutions cannot re-point
        // either name (the operation acts *inside* the pinned directories).
        let old_anchored = anchored::anchor_parent(&self.root, &old_real)?;
        let new_anchored = anchored::anchor_parent(&self.root, &new_real)?;
        if unsafe {
            libc::renameat(
                old_anchored.dir().as_raw_fd(),
                old_anchored.name().as_ptr(),
                new_anchored.dir().as_raw_fd(),
                new_anchored.name().as_ptr(),
            )
        } != 0
        {
            let e = std::io::Error::last_os_error();
            log_op_err("rename", &old, Some(&new_real), &e).await;
            return Err(e.into());
        }
        log_op_ok("rename", &old, &new_real).await;

        // The kernel moves the dentry on rename, re-hashing `old` as `new`
        // *keeping the source's nodeid*. Re-point the new path at the source
        // nodeid — dropping the overwritten target's mapping, which the
        // kernel is about to forget — so every operation arriving on the
        // moved dentry still resolves (see `FINDINGS.md`).
        let mut map = self.inodes.write().unwrap_or_else(|e| e.into_inner());
        let source_inode = map.inode_of(&old);
        let old_target = map.inode_of(&new);
        fuselog::event!(
            "INODE rename src_inode={} new={} old_target_inode={}",
            source_inode
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            fuselog::path_string(new.as_os_str()),
            old_target
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
        );
        map.rename(&old, &new, parent);
        Ok(())
    }

    /// Create a symlink: always denied. A host symlink visible through the
    /// mirror is only ever shown *as a symlink* (never followed), and
    /// creating one in the sandbox could link outside the mirrored paths —
    /// so the operation is refused outright. `EACCES` ("Permission denied")
    /// reports this as the policy decision it is; the implicit `ENOSYS`
    /// default would instead pretend the feature is missing.
    async fn symlink(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        _link: &std::ffi::OsStr,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("symlink");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        log_op_err(
            "symlink",
            &mirrored,
            Some(&self.patterns.redirect(&mirrored)),
            &std::io::Error::from_raw_os_error(libc::EACCES),
        )
        .await;
        Err(libc::EACCES.into())
    }

    /// Create a hard link: the new name points at the *same real host file*
    /// as the source (`linkat` on the host filesystem), so writes through
    /// either name are visible through both. The new name gets a **fresh
    /// nodeid** mapping to the new path: the mirror's pattern permissions
    /// are decided per path, and a hard-linked name is an independent path
    /// (the source nodeid keeps its mapping; renaming one name must not
    /// affect the other's).
    ///
    /// The source is **never followed**, and a host symlink at the source
    /// name is not linked at all: Linux `linkat` cannot no-follow the
    /// source, and re-creating the symlink (as this used to do) would be
    /// a real symlink creation on the host — the `symlink` op is
    /// unconditionally denied, so `link` of a symlink is denied too
    /// (AUDIT.md M5). A symlink's target may also live outside every
    /// mapping; following it would be a variant of the C1 escape the
    /// anchored resolution closes.
    ///
    /// **Both** names must be writable. Checking only the new name would
    /// let the sandbox link a *read-only* mapped file (say, from
    /// `~/.rustup`) into a writable path and then write through the link —
    /// the write follows the host inode, bypassing the source path's
    /// `ro` permission. Rejecting cross-policy links also avoids the
    /// residual risk of a linked file living under two paths that disagree
    /// on the write policy (a hard link is one host file; the per-path
    /// model cannot express that).
    async fn link(
        &self,
        _req: Request,
        inode: Inode,
        new_parent: Inode,
        new_name: &OsStr,
    ) -> Result<ReplyEntry> {
        perf::fuse_op!("link");
        let source_path = self.resolve(inode)?;
        let new_parent_path = self.resolve(new_parent)?;
        let old = source_path;
        let new = new_parent_path.join(new_name);
        if self.patterns.is_empty(&old) || self.patterns.is_empty(&new) {
            return Err(libc::EACCES.into());
        }
        if !self.patterns.exists(&old) {
            log_op_err(
                "link",
                &old,
                None,
                &std::io::Error::from_raw_os_error(libc::ENOENT),
            )
            .await;
            return Err(libc::ENOENT.into());
        }
        // The source must be writable, too: a read-only source must not be
        // linked into a writable path (the write would follow the host
        // inode and bypass the source path's `ro` permission).
        if !self.patterns.writable(&old) {
            log_op_err(
                "link",
                &old,
                Some(&self.patterns.redirect(&old)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        if !self.patterns.writable(&new) {
            log_op_err(
                "link",
                &new,
                Some(&self.patterns.redirect(&new)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Both parents pinned. The source entry is stat'ed first (anchored): a
        // host symlink standing at the source name must be linked *as a
        // link*, never followed to its target — the target may live
        // outside every mapping, and following it here would be a variant
        // of the C1 escape (Linux `linkat` cannot no-follow the source, so
        // a link source is re-created as an identical symlink instead). The
        // check and the syscall below run in one await-free block — on the
        // single-threaded runtime nothing can swap the entry in between.
        let old_anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&old))?;
        let new_anchored = anchored::anchor_parent(&self.root, &self.patterns.redirect(&new))?;
        let source_stat = anchored::stat_entry(&old_anchored)?;
        if Self::stat_is_symlink(&source_stat) {
            // AUDIT.md M5: linking a host symlink used to re-create it on
            // the host (`symlinkat` with the server's credentials) — a
            // real symlink creation at an arbitrary writable mapped
            // location, defeating the absolute "the sandbox can never
            // create symlinks" invariant (the `symlink` op is
            // unconditionally EACCES). The target string is copied
            // verbatim and symlinks are inert inside the mirror, so this
            // was low-impact — but the invariant is worth more than the
            // compatibility. Hard links to regular files are unaffected.
            log_op_err(
                "link",
                &old,
                Some(&self.patterns.redirect(&old)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // SAFETY: valid descriptors and NUL-terminated names.
        let link_result = unsafe {
            libc::linkat(
                old_anchored.dir().as_raw_fd(),
                old_anchored.name().as_ptr(),
                new_anchored.dir().as_raw_fd(),
                new_anchored.name().as_ptr(),
                0,
            )
        };
        if link_result != 0 {
            let e = std::io::Error::last_os_error();
            log_op_err("link", &new, Some(&self.patterns.redirect(&new)), &e).await;
            return Err(e.into());
        }
        log_op_ok("link", &new, &self.patterns.redirect(&new)).await;
        let inode = self
            .inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .get_or_insert(&new, new_parent);
        let mut attr = self.attr(&new)?;
        attr.ino = inode;
        Ok(ReplyEntry {
            ttl: TTL,
            attr,
            generation: 0,
        })
    }

    async fn create(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        perf::fuse_op!("create");
        let parent_path = self.resolve(parent)?;
        let mirrored = parent_path.join(name);
        let writable = self.patterns.writable(&mirrored);
        if !writable {
            log_op_err(
                "create",
                &mirrored,
                Some(&self.patterns.redirect(&mirrored)),
                &std::io::Error::from_raw_os_error(libc::EACCES),
            )
            .await;
            return Err(libc::EACCES.into());
        }
        // Only with O_EXCL does a *real* entry at the target mean EEXIST;
        // a plain O_CREAT (without O_EXCL) opens an existing file like the
        // host filesystem would. A path merely matched by a wildcard
        // pattern may not exist yet. The parent is pinned first and the
        // existing-entry check runs on it (`fstatat(AT_SYMLINK_NOFOLLOW)`):
        // a host symlink standing at the target is never followed — neither
        // by the check nor by the open below.
        let real = self.patterns.redirect(&mirrored);
        let anchored = anchored::anchor_parent(&self.root, &real)?;
        let excl = flags & libc::O_EXCL as u32 != 0;
        let truncate = flags & libc::O_TRUNC as u32 != 0;
        let append = flags & libc::O_APPEND as u32 != 0;
        let existing = anchored::stat_entry(&anchored).ok();
        if let Some(st) = existing {
            if Self::stat_is_symlink(&st) {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::ELOOP),
                )
                .await;
                return Err(libc::ELOOP.into());
            }
            if excl {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::EEXIST),
                )
                .await;
                return Err(libc::EEXIST.into());
            }
            if Self::stat_is_dir(&st) {
                log_op_err(
                    "create",
                    &mirrored,
                    Some(&real),
                    &std::io::Error::from_raw_os_error(libc::EISDIR),
                )
                .await;
                return Err(libc::EISDIR.into());
            }
            let mut oflags = libc::O_WRONLY;
            if truncate {
                oflags |= libc::O_TRUNC;
            }
            if append {
                oflags |= libc::O_APPEND;
            }
            let file = match anchored::open_at(&self.root, &real, oflags, 0) {
                Ok(f) => f,
                Err(e) => {
                    log_op_err("create", &mirrored, Some(&real), &e).await;
                    return Err(e.into());
                }
            };
            let md = file.metadata()?;
            log_op_ok("create", &mirrored, &real).await;
            let inode = self
                .inodes
                .write().unwrap_or_else(|e| e.into_inner())
                .get_or_insert(&mirrored, parent);
            self.inodes
                .write().unwrap_or_else(|e| e.into_inner())
                .open_handle(inode);
            let fh = match self.insert_handle(file, mirrored, append, writable) {
            Ok(fh) => fh,
            Err(e) => {
                // AUDIT.md L13: release the speculative `open_handle`
                // count (see the `open` op for the rationale).
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .close_handle(inode);
                return Err(e.into());
            }
        };
            let mut attr = attr_from_metadata(&md);
            attr.ino = inode;
            return Ok(ReplyCreated {
                ttl: TTL,
                attr,
                generation: 0,
                fh,
                flags: 0,
            });
        }
        let base = if flags & libc::O_RDWR as u32 != 0 {
            libc::O_RDWR
        } else {
            libc::O_WRONLY
        };
        let mut oflags = libc::O_CREAT | libc::O_EXCL | base;
        if append {
            oflags |= libc::O_APPEND;
        }
        let file =
            match anchored::open_at(&self.root, &real, oflags, (mode & SAFE_MODE) as libc::mode_t)
            {
                Ok(f) => f,
                Err(e) => {
                    log_op_err("create-new", &mirrored, Some(&real), &e).await;
                    return Err(e.into());
                }
            };
        let md = file.metadata()?;
        let mut attr = attr_from_metadata(&md);
        log_op_ok("create-new", &mirrored, &real).await;
        let inode = self
            .inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .get_or_insert(&mirrored, parent);
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .open_handle(inode);
        let fh = match self.insert_handle(file, mirrored, append, writable) {
            Ok(fh) => fh,
            Err(e) => {
                // AUDIT.md L13: release the speculative `open_handle`
                // count (see the `open` op for the rationale).
                self.inodes
                    .write().unwrap_or_else(|e| e.into_inner())
                    .close_handle(inode);
                return Err(e.into());
            }
        };
        attr.ino = inode;
        Ok(ReplyCreated {
            ttl: TTL,
            attr,
            generation: 0,
            fh,
            flags: 0,
        })
    }

    /// Release an open file: the cached host file is dropped (closing it);
    /// there is nothing to flush. The reply mirrors the path API's default
    /// (`ENOSYS`), which the kernel does not propagate to `close()`.
    async fn release(
        &self,
        _req: Request,
        inode: Inode,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> Result<()> {
        perf::fuse_op!("release");
        // Drop the cached host file (closing it); the handle bookkeeping
        // is all that remains — IO is stateful but needs no flush.
        self.remove_handle(fh);
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .close_handle(inode);
        Err(libc::ENOSYS.into())
    }

    async fn releasedir(&self, _req: Request, inode: Inode, _fh: u64, _flags: u32) -> Result<()> {
        perf::fuse_op!("releasedir");
        self.inodes
            .write().unwrap_or_else(|e| e.into_inner())
            .close_handle(inode);
        Ok(())
    }
}

/// A host path as a NUL-terminated C string, for the libc calls.
pub(super) fn cstring_of(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOENT))
}

/// Map a fuse3 timestamp to a `utimensat` timespec; `None` means "leave
/// this time unchanged" (`UTIME_OMIT`).
pub(super) fn ts_to_timespec(ts: Option<Timestamp>) -> libc::timespec {
    match ts {
        Some(t) => libc::timespec {
            tv_sec: t.sec,
            tv_nsec: t.nsec as libc::c_long,
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT as libc::c_long,
        },
    }
}
