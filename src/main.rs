//! ai-bubble: a minimal bubblewrap-like sandbox.
//!
//! Module layout (who is allowed to do what):
//!
//! * `cli`     — argument parsing only (clap derive); no side effects.
//! * `spec`    — the sandbox spec file (JSON), in two layers: the
//!   config-file view (`spec`, `env`, `hostfs`, `net`, `tmpfs`) and the internal
//!   configuration (`spec::internal`) the sandbox machinery runs with,
//!   compiled down from the parsed file. Parsing only; no side effects
//!   beyond reading the file.
//! * `sandbox` — the privileged filesystem part: user/mount namespaces,
//!   tmpfs root, bind mounts, symlinks, proc, exec. Never touches the
//!   network.
//! * `hostfs`  — the host-side FUSE filesystem server process and the virtual
//!   filesystem it serves; bind-mounted into the sandbox at `/host`.
//! * `netns`   — the isolated-network process tree: forks, user/network
//!   namespaces, id maps, loopback setup, waitpid lifecycle.
//! * `proxy`   — pure async networking (tokio): the host-side connector on
//!   a Unix socket and the in-sandbox HTTP CONNECT proxy. No namespace or
//!   process management.

use clap::Parser;
use std::path::{Path, PathBuf};

mod cli;
mod hostfs;
mod netns;
mod proxy;
mod sandbox;
mod spec;

use cli::Command;

/// The JSON Schema for the spec file, generated from `src/spec/mod.rs` by
/// `build.rs` at compile time. Printed by `--print-schema`; point an
/// editor (e.g. VS Code's `json.schemas`) at it to get completion and
/// validation for `.ai-bubble/spec.json`.
pub const SPEC_SCHEMA: &str = include_str!(concat!(env!("OUT_DIR"), "/ai-bubble-schema.json"));

fn main() {
    let cli = cli::Cli::parse();

    if cli.print_schema {
        print!("{}", SPEC_SCHEMA);
        return;
    }

    match cli.command {
        Some(Command::Run {
            die_with_parent,
            mut command,
        }) => {
            if command.is_empty() {
                sandbox::die(
                    "No command given; usage: ai-bubble run [--spec-dir DIR] -- COMMAND [args...]",
                );
            }
            let mut spec = spec::Spec::load(cli.spec.as_deref());

            // Resolve the cache mappings (`session-cache`,
            // `project-cache`) against their backing directories before
            // anything is compiled: the session-cache tmp directory is
            // created here and wiped once ai-bubble terminates (the
            // mirrored-fs server inherits the wipe).
            let spec_dir = cli
                .spec
                .as_deref()
                .unwrap_or(Path::new(spec::file::DEFAULT_SPEC_DIR));
            let session_cache = hostfs::session_cache_needed(spec.hostfs.has_session_caches());
            spec.hostfs
                .prepare_caches(spec_dir, session_cache.as_deref());

            // Compile the config-file spec down into the internal
            // configuration (ops, hostfs patterns, net settings) the
            // sandbox machinery runs with.
            let sandbox_config = spec::internal::SandboxConfig::compile(&spec);

            // Start the host FUSE filesystem server (in its own child
            // process) before any namespace setup: its filesystem becomes
            // the sandbox root, with the ops (dev, tmpfs, proc, binds)
            // mounted on top of it. Only when the spec actually exposes
            // something: a sandbox without any hostfs mappings must not
            // depend on (or fail for the lack of) FUSE.
            if !sandbox_config.patterns.is_empty() {
                hostfs::set_root_mode(true);
                if let Some(root) = &session_cache {
                    hostfs::set_session_cache_root(root);
                }
                hostfs::start_host_fs(&sandbox_config.patterns);
            }

            let command = std::mem::take(&mut command);
            unsafe {
                if sandbox_config.net.isolated {
                    netns::run(
                        &sandbox_config.ops,
                        &command,
                        &sandbox_config.net,
                        &sandbox_config.env,
                        sandbox_config.cwd.as_deref(),
                        die_with_parent,
                    );
                } else {
                    sandbox::setup_and_exec(
                        &sandbox_config.ops,
                        &command,
                        &sandbox_config.env,
                        sandbox_config.cwd.as_deref(),
                        die_with_parent,
                    );
                }
            }
        }

        Some(Command::Ls { path }) => ls(cli.spec.as_deref(), &path),

        None => sandbox::die("No sub-command given; usage: ai-bubble run|ls ..."),
    }
}

/// The `ls` sub-command: list `path` on the host filesystem, annotated
/// with the effective sandbox permission of the current config, and show
/// the config's mappings (permissions/actions).
fn ls(spec_path: Option<&Path>, path: &Path) {
    let spec = spec::Spec::load(spec_path);

    // The mappings of the current config: permissions and mount/symlink
    // actions, in spec order.
    let shown_spec = spec_path
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
