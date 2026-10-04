//! The `ls` sub-command: list a host path, annotated with the permission
//! the current config gives each entry in the sandbox, plus the mappings
//! (permissions/actions) of the current config itself.

use clap::Args;
use std::path::{Path, PathBuf};

use crate::{hostfs, sandbox, spec};

/// List PATH on the host filesystem, annotated with the permission the
/// current config gives each entry in the sandbox, plus the mappings
/// (permissions/actions) of the current config itself.
#[derive(Debug, Args, PartialEq)]
pub struct LsCommand {
    /// The host path to list. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub(crate) path: PathBuf,
}

impl LsCommand {
    /// Lists `path` on the host filesystem, annotated with the effective
    /// sandbox permission of the current config, and shows the config's
    /// mappings (permissions/actions). `spec_dir` is the `--spec-dir` value
    /// (if given).
    pub fn run(self, spec_dir: Option<&Path>) {
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
        let target = match std::fs::canonicalize(&self.path) {
            Ok(target) => target,
            Err(err) => sandbox::die(&format!("cannot list {}: {err}", self.path.display())),
        };
        let patterns = spec.hostfs.patterns();

        let label = |permission: Option<&hostfs::patterns::Permission>| match permission {
            Some(p) => format!("{p}"),
            None => "-".to_string(),
        };
        println!(
            "{} ({}):",
            target.display(),
            label(patterns.permission_of(&target))
        );

        let mut entries: Vec<_> = match std::fs::read_dir(&target) {
            Ok(entries) => entries.filter_map(|e| e.ok()).collect(),
            Err(err) => sandbox::die(&format!("cannot list {}: {err}", target.display())),
        };
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let full = target.join(entry.file_name());
            println!(
                "  {} ({})",
                quote_name(&entry.file_name()),
                label(patterns.permission_of(&full))
            );
        }
    }
}

/// Render a host filename for the operator's terminal (AUDIT.md L11):
/// hostile filenames can otherwise emit terminal escape sequences (OSC 52
/// clipboard writes, title changes, terminal-emulator CVEs) into the tty.
/// Names are printed verbatim while they are plain; anything containing
/// quotes, backslashes or control characters is single-quoted with
/// `\xNN` escapes for control bytes — the same idea as modern coreutils
/// `ls` quoting.
fn quote_name(name: &std::ffi::OsStr) -> String {
    let lossy = name.to_string_lossy();
    let needs_quoting = lossy
        .chars()
        .any(|c| c.is_control() || matches!(c, '\'' | '"' | '\\'));
    if !needs_quoting {
        return lossy.into_owned();
    }
    let mut out = String::with_capacity(lossy.len() + 2);
    out.push('\'');
    for c in lossy.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}
#[cfg(test)]
mod tests {
    use super::quote_name;

    #[test]
    fn filenames_with_control_characters_are_escaped() {
        // Plain names pass through verbatim.
        assert_eq!(quote_name(std::ffi::OsStr::new("plain.txt")), "plain.txt");
        // Control bytes (terminal escape injection, AUDIT.md L11) are
        // quoted and hex-escaped.
        assert_eq!(
            quote_name(std::ffi::OsStr::new("\x1b]0;pwned\x07")),
            "'\\x1b]0;pwned\\x07'"
        );
        assert_eq!(quote_name(std::ffi::OsStr::new("a\nb")), "'a\\x0ab'");
        assert_eq!(quote_name(std::ffi::OsStr::new("del\x7fx")), "'del\\x7fx'");
        // Quotes and backslashes are quoted/escaped.
        assert_eq!(quote_name(std::ffi::OsStr::new("it's")), "'it\\'s'");
        assert_eq!(
            quote_name(std::ffi::OsStr::new("back\\slash")),
            "'back\\\\slash'"
        );
    }
}
