//! Symlink-target translation between the sandbox mount and the host.
//!
//! The mirror reproduces full host paths, so a symlink that lives on the
//! host and is visible through the mirror must have its target **rewritten**
//! before the sandbox ever sees it: the kernel resolves the target string we
//! return from `readlink` *inside the sandbox*, against the mirror's paths —
//! not against the host tree. Two directions:
//!
//! * **host → sandbox** (`readlink`): the raw host target is turned into an
//!   absolute host path (relative targets resolve against the link's host
//!   directory), mapped back into mirror space ([`Patterns::host_to_mirror`],
//!   the inverse of a redirect plus the identity mapping), and emitted
//!   relative to the link's mirrored directory when it stays below it.
//!   A target that is not mounted anywhere has no mirror path: the link stays
//!   visible, but resolves to a path that does not exist — a *broken* link,
//!   which build tools tolerate far better than a vanishing entry.
//! * **sandbox → host** (`symlink`): the target the sandbox passed is turned
//!   into a mirror path (relative targets resolve against the link's mirrored
//!   directory, absolute ones lose the mount prefix), mapped to host space
//!   with [`Patterns::redirect`], and stored — relative to the link's host
//!   directory when it stays below it. A symlink that works in the sandbox
//!   therefore works on the host, and vice versa.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use super::patterns::Patterns;

/// Translate a **host** symlink target (as returned by `readlink` on the real
/// host path `real` of the mirrored link `mirrored`) into the target the
/// sandbox should see. `mirror_is_root` says whether the mirror is the
/// sandbox root (hostfs-root mode) or is mounted at
/// [`crate::hostfs::SANDBOX_MOUNT_POINT`]: in the latter case an absolute
/// result carries the mount prefix so the kernel resolves it back into the
/// mirror rather than the sandbox's own root.
pub(super) fn host_to_sandbox_target(
    patterns: &Patterns,
    mirrored: &Path,
    real: &Path,
    target: &OsStr,
    mirror_is_root: bool,
) -> OsString {
    let host_abs = absolute_host_target(real, target);
    // Keep the raw target verbatim when it already resolves, *inside the
    // mirror*, to the same host path — the common identity case, which also
    // keeps ordinary relative targets (including ones that step up with
    // `..`) byte-for-byte.
    if let Some(mirror_of_raw) = raw_mirror_path(mirrored, target, mirror_is_root)
        && patterns.exists(&mirror_of_raw)
        && patterns.redirect(&mirror_of_raw) == host_abs
    {
        return target.to_os_string();
    }
    let mirror_abs = patterns.host_to_mirror(&host_abs);
    relative_or_absolute(mirrored, &mirror_abs, !mirror_is_root)
}

/// Translate a **sandbox** symlink target (the string the sandbox passed to
/// `symlink` at the mirrored link `mirrored`, whose real host path is `real`)
/// into the target to store on the host. See [`host_to_sandbox_target`] for
/// `mirror_is_root`.
pub(super) fn sandbox_to_host_target(
    patterns: &Patterns,
    mirrored: &Path,
    real: &Path,
    target: &OsStr,
    mirror_is_root: bool,
) -> OsString {
    // A target outside the mirror mount (an absolute sandbox path that is not
    // under the mount point) names a sandbox-root path the mirror knows
    // nothing about — the mirror reproduces host paths, so such a path is
    // already a host path; store it verbatim.
    let mirror_abs = if is_absolute(target) {
        match mirror_absolute(target, mirror_is_root) {
            Some(abs) => abs,
            None => return target.to_os_string(),
        }
    } else {
        let dir = mirrored.parent().unwrap_or_else(|| Path::new("/"));
        normalize(&dir.join(target))
    };
    let host_abs = patterns.redirect(&mirror_abs);
    // Keep the raw target verbatim when the *host* already resolves it to the
    // same path the sandbox target denotes (the common identity case).
    if host_resolution(real, target) == host_abs {
        return target.to_os_string();
    }
    relative_or_absolute(real, &host_abs, false)
}

/// The mirror-space path a raw sandbox target denotes at the link `mirrored`
/// (how the kernel would resolve it inside the sandbox). `None` for an
/// absolute target that lies outside the (non-root) mount.
fn raw_mirror_path(mirrored: &Path, target: &OsStr, mirror_is_root: bool) -> Option<PathBuf> {
    if is_absolute(target) {
        mirror_absolute(target, mirror_is_root)
    } else {
        let dir = mirrored.parent().unwrap_or_else(|| Path::new("/"));
        Some(normalize(&dir.join(target)))
    }
}

/// The host path the host would resolve a raw target to at the link's host
/// path `real`.
fn host_resolution(real: &Path, target: &OsStr) -> PathBuf {
    if is_absolute(target) {
        normalize(Path::new(target))
    } else {
        let dir = real.parent().unwrap_or_else(|| Path::new("/"));
        normalize(&dir.join(target))
    }
}

/// Whether a target string starts with `/`.
fn is_absolute(target: &OsStr) -> bool {
    target.as_bytes().first() == Some(&b'/')
}

/// The absolute host path an absolute-or-relative host target denotes,
/// resolved lexically (without following any symlink) against the link's
/// host directory `real`.
fn absolute_host_target(real: &Path, target: &OsStr) -> PathBuf {
    if is_absolute(target) {
        normalize(Path::new(target))
    } else {
        let dir = real.parent().unwrap_or_else(|| Path::new("/"));
        normalize(&dir.join(target))
    }
}

/// Strip the sandbox mount prefix from an absolute sandbox path, yielding the
/// mirror-space path (absolute). `None` when the path lies outside the mount
/// (only possible when the mirror is *not* the sandbox root).
fn mirror_absolute(sandbox_abs: &OsStr, mirror_is_root: bool) -> Option<PathBuf> {
    if mirror_is_root {
        return Some(normalize(Path::new(sandbox_abs)));
    }
    let prefix = Path::new(super::SANDBOX_MOUNT_POINT);
    let stripped = Path::new(sandbox_abs).strip_prefix(prefix).ok()?;
    if stripped.as_os_str().is_empty() {
        return Some(PathBuf::from("/"));
    }
    Some(Path::new("/").join(stripped))
}

/// Express `abs` relative to the link's directory (`link`'s parent) when it
/// stays below it — keeping ordinary relative links relative (and therefore
/// independent of the mount prefix) — and absolute otherwise. When
/// `add_prefix` is set and the result must be absolute (sandbox-facing
/// output in non-root mode), the sandbox mount prefix is prepended.
fn relative_or_absolute(link: &Path, abs: &Path, add_prefix: bool) -> OsString {
    let dir = link.parent().unwrap_or_else(|| Path::new("/"));
    if let Ok(rel) = abs.strip_prefix(dir) {
        if rel.as_os_str().is_empty() {
            return OsString::from(".");
        }
        return rel.as_os_str().to_os_string();
    }
    let out = if add_prefix {
        sandbox_absolute(abs)
    } else {
        abs.to_path_buf()
    };
    out.into_os_string()
}

/// Prepend the sandbox mount prefix to an absolute mirror path.
fn sandbox_absolute(mirror_abs: &Path) -> PathBuf {
    let prefix = Path::new(super::SANDBOX_MOUNT_POINT);
    match mirror_abs.strip_prefix("/") {
        Ok(rest) if !rest.as_os_str().is_empty() => prefix.join(rest),
        _ => prefix.to_path_buf(),
    }
}

/// Lexically normalize a path: drop `.`, apply `..` by popping the previous
/// component (never past the root) and collapse duplicate separators — all
/// without touching the filesystem (a symlink target must not be resolved,
/// only understood). Leading `..` on a relative path is preserved.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && out.as_os_str().is_empty() {
                    out.push("..");
                }
            }
            Component::Prefix(_) => {}
            Component::Normal(name) => out.push(name),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostfs::patterns::Permission;

    fn ps(entries: &[(&str, Permission)]) -> Patterns {
        Patterns::new(
            entries
                .iter()
                .map(|(p, perm)| (p.to_string(), perm.clone()))
                .collect(),
        )
    }

    fn redirect(source: &str) -> Permission {
        Permission::Redirect {
            source: PathBuf::from(source),
            writable: false,
        }
    }

    #[test]
    fn relative_host_target_stays_relative_under_a_recursive_mirror() {
        let patterns = ps(&[("/a", Permission::Rw)]);
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("sub/file"),
            true,
        );
        assert_eq!(out, OsStr::new("sub/file"));
    }

    #[test]
    fn host_target_already_valid_in_mirror_space_is_kept_verbatim() {
        let patterns = ps(&[("/a", Permission::Rw)]);
        // An absolute host target that resolves to the same content through
        // the (identity) mirror is kept byte-for-byte...
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("/a/sub"),
            true,
        );
        assert_eq!(out, OsStr::new("/a/sub"));
        // ...as is a relative target that steps up with `..`.
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/a/b/link"),
            Path::new("/a/b/link"),
            OsStr::new("../sub"),
            true,
        );
        assert_eq!(out, OsStr::new("../sub"));
    }

    #[test]
    fn unmapped_host_target_is_presented_but_broken() {
        let patterns = ps(&[("/a", Permission::Rw)]);
        // Absolute, outside the mirror: stays absolute (root mode).
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("/outside/x"),
            true,
        );
        assert_eq!(out, OsStr::new("/outside/x"));
        // Non-root: the same target is prefixed so it cannot accidentally
        // resolve to a *different* sandbox file at `/outside/x`.
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("/outside/x"),
            false,
        );
        assert_eq!(out, OsStr::new("/mirrored/outside/x"));
    }

    #[test]
    fn host_target_below_a_redirect_maps_onto_its_destination() {
        let patterns = ps(&[("/work", redirect("/home/u/work"))]);
        // Relative target within the redirected tree.
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/work/link"),
            Path::new("/home/u/work/link"),
            OsStr::new("sub"),
            true,
        );
        assert_eq!(out, OsStr::new("sub"));
        // Absolute host target within the redirected tree.
        let out = host_to_sandbox_target(
            &patterns,
            Path::new("/work/link"),
            Path::new("/home/u/work/link"),
            OsStr::new("/home/u/work/other"),
            true,
        );
        assert_eq!(out, OsStr::new("other"));
    }

    #[test]
    fn sandbox_relative_target_becomes_a_host_target() {
        let patterns = ps(&[("/work", redirect("/home/u/work"))]);
        let out = sandbox_to_host_target(
            &patterns,
            Path::new("/work/link"),
            Path::new("/home/u/work/link"),
            OsStr::new("sub"),
            true,
        );
        assert_eq!(out, OsStr::new("sub"));
    }

    #[test]
    fn sandbox_absolute_target_is_redirected_to_the_host_tree() {
        let patterns = ps(&[("/work", redirect("/home/u/work"))]);
        let out = sandbox_to_host_target(
            &patterns,
            Path::new("/work/link"),
            Path::new("/home/u/work/link"),
            OsStr::new("/work/other"),
            true,
        );
        assert_eq!(out, OsStr::new("other"));
    }

    #[test]
    fn sandbox_relative_target_is_kept_when_it_resolves_the_same_on_the_host() {
        let patterns = ps(&[("/a", Permission::Rw)]);
        // `../x` resolves to `/x` both inside the sandbox and on the host:
        // it is stored verbatim.
        let out = sandbox_to_host_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("../x"),
            true,
        );
        assert_eq!(out, OsStr::new("../x"));
    }

    #[test]
    fn non_root_mount_prefix_round_trips() {
        let patterns = ps(&[("/a", Permission::Rw)]);
        // The sandbox says `/mirrored/a/target`; the host side is `/a/target`.
        let out = sandbox_to_host_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("/mirrored/a/target"),
            false,
        );
        assert_eq!(out, OsStr::new("target"));
        // A sandbox path outside the mount is stored verbatim.
        let out = sandbox_to_host_target(
            &patterns,
            Path::new("/a/link"),
            Path::new("/a/link"),
            OsStr::new("/etc/hosts"),
            false,
        );
        assert_eq!(out, OsStr::new("/etc/hosts"));
    }

    #[test]
    fn normalize_handles_dot_and_dotdot() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
        assert_eq!(normalize(Path::new("/../a")), PathBuf::from("/a"));
        assert_eq!(normalize(Path::new("..")), PathBuf::from(".."));
        assert_eq!(normalize(Path::new(".")), PathBuf::from("."));
    }
}
