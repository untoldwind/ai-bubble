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
//! * `waf`     — the alternative isolated-network mode: DNS/HTTP/HTTPS
//!   servers inside the sandbox on 127.0.0.2 that redirect allow-listed
//!   traffic to the host side over the same style of Unix socket, using a
//!   simple command protocol (`resolve-dns`, `connect`).

use clap::Parser;

mod audit;
mod cli;
mod hostfs;
mod netns;
mod proxy;
mod sandbox;
mod spec;
mod waf;

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
            command,
        }) => cli::run(cli.spec.as_deref(), die_with_parent, command),

        Some(Command::Ls { path }) => cli::ls(cli.spec.as_deref(), &path),

        Some(Command::Init) => cli::init(cli.spec.as_deref()),

        None => sandbox::die("No sub-command given; usage: ai-bubble run|ls|init ..."),
    }
}
