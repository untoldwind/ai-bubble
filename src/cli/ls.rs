//! The `ls` sub-command: list a host path, annotated with the permission
//! the current config gives each entry in the sandbox, plus the mappings
//! (permissions/actions) of the current config itself.

use std::path::{Path, PathBuf};

use crate::{hostfs, sandbox, spec};

/// Lists `path` on the host filesystem, annotated with the effective
/// sandbox permission of the current config, and shows the config's
/// mappings (permissions/actions). `spec_dir` is the `--spec-dir` value
/// (if given).
pub fn ls(spec_dir: Option<&Path>, path: &Path) {
    let spec = spec::Spec::load(spec_dir);

    // The mappings of the current config: permissions and mount/symlink
    // actions, in spec order.
    let shown_spec = spec_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(spec::file::DEFAULT_SPEC_DIR));
    println!("mappings ({}):", shown_spec.display());
    for mapping in &spec.hostfs.mappings {
        println!("  {}", mapping.describe());
    }
    for op in spec.hostfs.ops() {
        println!("  {}", op.describe());
    }

    // The listed path itself, and every entry, with the effective
    // permission the config gives it (the last matching pattern wins;
    // `None` means not visible in the sandbox at all).
    let target = match std::fs::canonicalize(path) {
        Ok(target) => target,
        Err(err) => sandbox::die(&format!("cannot list {}: {err}", path.display())),
    };
    let patterns = spec.hostfs.patterns();
    let permission_of = |p: &Path| hostfs::permission_of(&patterns, p);

    let label = |permission: Option<spec::internal::Permission>| match permission {
        Some(p) => format!("{p}"),
        None => "-".to_string(),
    };
    println!("{} ({}):", target.display(), label(permission_of(&target)));

    let mut entries: Vec<_> = match std::fs::read_dir(&target) {
        Ok(entries) => entries.filter_map(|e| e.ok()).collect(),
        Err(err) => sandbox::die(&format!("cannot list {}: {err}", target.display())),
    };
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let full = target.join(entry.file_name());
        println!(
            "  {} ({})",
            entry.file_name().to_string_lossy(),
            label(permission_of(&full))
        );
    }
}

