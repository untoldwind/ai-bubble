//! rs-bubble: a minimal bubblewrap-like sandbox.
//!
//! Module layout (who is allowed to do what):
//!
//! * `cli`     — argument parsing only (clap derive); no side effects.
//! * `spec`    — the sandbox spec file (JSON): mount operations and
//!   network configuration. Parsing only; no side effects beyond reading
//!   the file.
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

mod cli;
mod hostfs;
mod netns;
mod proxy;
mod sandbox;
mod spec;

/// The JSON Schema for the spec file, generated from `src/spec/mod.rs` by
/// `build.rs` at compile time. Printed by `--print-schema`; point an
/// editor (e.g. VS Code's `json.schemas`) at it to get completion and
/// validation for `.rs-bubble.json`.
pub const SPEC_SCHEMA: &str = include_str!(concat!(env!("OUT_DIR"), "/rs-bubble-schema.json"));

fn main() {
    let mut args = cli::Cli::parse();

    if args.print_schema {
        print!("{}", SPEC_SCHEMA);
        return;
    }

    let spec = spec::Spec::load(args.spec.as_deref());
    let command = std::mem::take(&mut args.command);
    if command.is_empty() {
        sandbox::die("No command given; usage: rs-bubble [--spec FILE] -- COMMAND [args...]");
    }

    // Start the host FUSE filesystem server (in its own child process) before
    // any namespace setup: its filesystem becomes the sandbox root, with the
    // ops (dev, tmpfs, proc, binds) mounted on top of it. Only when the spec
    // actually exposes something: a sandbox without any hostfs mappings must
    // not depend on (or fail for the lack of) FUSE.
    let patterns = spec.hostfs.patterns();
    if !patterns.is_empty() {
        hostfs::set_root_mode(true);
        hostfs::start_host_fs(&patterns);
    }

    let net = &spec.net;
    let ops = spec.filesystem_ops();

    unsafe {
        if net.isolated {
            netns::run(&ops, &command, net);
        } else {
            sandbox::setup_and_exec(&ops, &command);
        }
    }
}
