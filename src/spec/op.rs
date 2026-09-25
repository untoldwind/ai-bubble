//! Mount operations: the tagged-union `ops` entries of the spec file.

use std::path::PathBuf;

use serde::Deserialize;

use schemars::JsonSchema;

use super::TmpfsPerms;

/// One sandbox setup operation. The JSON `type` tag selects the variant,
/// and the order of the list is the order in which the operations are
/// applied inside the sandbox (order matters, exactly like bwrap).
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Op {
    Bind {
        src: String,
        dest: PathBuf,
    },
    Symlink {
        src: String,
        dest: PathBuf,
    },
    /// Mount a fresh procfs instance. Usually set via the top-level
    /// `proc` field rather than as an explicit op, but kept here so the
    /// sandbox can treat it uniformly.
    Proc {
        dest: PathBuf,
    },
    /// Mount a minimal `/dev`, like bwrap's `--dev`: a fresh tmpfs (mode
    /// 0755, `MS_NOSUID|MS_NODEV`) populated with the usual device nodes
    /// (`null`, `zero`, `full`, `random`, `urandom`, `tty`), the stdio
    /// symlinks, `/dev/shm`, a fresh devpts instance at `pts` plus the
    /// `ptmx` symlink, and `/dev/console` bound to the host tty when stdin
    /// is one.
    Dev {
        dest: PathBuf,
    },
    /// Mount a fresh tmpfs instance, like bwrap's `--tmpfs`. Options mirror
    /// bwrap: `perms` is the octal mode of the mount root (default 0755) and
    /// `size` the maximum size in bytes (default: unlimited/half of RAM).
    /// The mount is made with `MS_NOSUID | MS_NODEV`, like bwrap's.
    Tmpfs {
        dest: PathBuf,
        /// Octal mode, e.g. `"0755"` or `755`. Default: 0755.
        perms: Option<TmpfsPerms>,
        /// Maximum tmpfs size in bytes.
        size: Option<u64>,
    },
}
