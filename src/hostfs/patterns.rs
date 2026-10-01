use std::path::{Path, PathBuf};

/// The permission a hostfs pattern grants inside the sandbox: the
/// internal representation of a mapping's `type` (see
/// [`crate::spec::hostfs::Mapping`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// The matched paths are mirrored into the sandbox **read-only**: they can
    /// be read (and executed, when the underlying file or directory has the
    /// exec bits), but never modified.
    Ro,
    /// The matched paths are mirrored into the sandbox **read-write**: they can
    /// also be modified, created or deleted — as far as the underlying host
    /// file or directory really allows it (the real permissions apply).
    Rw,
    /// The matched paths are hidden. A hidden **directory** hides its
    /// whole subtree, too.
    Hide,
    /// The matched paths are exposed **empty**: as an empty, unwritable
    /// directory when the path is (or would be) a directory, or as an
    /// empty file when it matches a real file. Nothing below an empty
    /// path is visible. Meant as mount points inside the sandbox, e.g.
    /// `/dev`, `/tmp`, `/proc`.
    Empty,
    /// The matched paths are **redirected**: instead of showing the host
    /// content that lives at the path itself, the host path `source`
    /// (a single file or directory) is shown in its place — the FUSE
    /// equivalent of a bind mount, but routed through the host
    /// filesystem (and thus monitored with it). A redirected directory
    /// shows its whole subtree; everything the pattern names is mapped
    /// onto the source (the path itself maps to the source, and paths
    /// below it to the source plus the remaining path components).
    /// `writable` decides between redirect-ro and redirect-rw; as with
    /// plain mirrors, writes additionally require the real host
    /// permissions to allow them.
    Redirect { source: PathBuf, writable: bool },
    /// The matched path is a **purely virtual, in-memory file**: it has no
    /// counterpart on the host at all — its content (`content`) is served
    /// from the mirror's memory. Read-only by definition (a write to it
    /// would have nowhere to go), and nothing below it is visible: an
    /// injected path is always a regular file. Used to plant small
    /// configuration files (e.g. `/etc/resolv.conf` in waf mode) into the
    /// sandbox without any host-side trace.
    Inject { content: String },
}

impl Permission {
    /// Whether the permission mirrors real host content (`ro`, `rw` or
    /// a redirect).
    pub fn is_mirrored(&self) -> bool {
        matches!(
            self,
            Permission::Ro
                | Permission::Rw
                | Permission::Redirect { .. }
                | Permission::Inject { .. }
        )
    }

    /// Whether the permission additionally allows writing (`rw` and
    /// redirect-rw).
    pub fn is_writable(&self) -> bool {
        match self {
            Permission::Rw => true,
            Permission::Redirect { writable, .. } => *writable,
            _ => false,
        }
    }

    /// The host path the permission redirects to, if any.
    pub fn redirect_source(&self) -> Option<&Path> {
        match self {
            Permission::Redirect { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Permission::Ro => "ro",
            Permission::Rw => "rw",
            Permission::Hide => "hide",
            Permission::Empty => "empty",
            Permission::Redirect { writable, .. } if *writable => "redirect-rw",
            Permission::Redirect { .. } => "redirect-ro",
            Permission::Inject { .. } => "inject",
        })
    }
}

/// The internal `hostfs` representation: an *ordered* list of
/// (glob pattern, permission) pairs — the compiled-down form of the
/// spec's [`crate::spec::hostfs::Mapping`] list. That order matters: when
/// a path matches several patterns, the **last** matching pattern decides.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Patterns(pub Vec<(String, Permission)>);

impl Patterns {
    /// The pattern/permission pairs, in spec order.
    pub fn iter(&self) -> impl Iterator<Item = &(String, Permission)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
