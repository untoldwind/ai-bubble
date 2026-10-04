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
//! * `pty`     — the private-pty terminal mode: a launcher-created pty
//!   pair, the stdio ⇄ master relay in the launcher-side parent, and the
//!   child-side `setsid()` + `TIOCSCTTY` that give the sandboxed command
//!   a real controlling terminal without exposing the caller's tty.
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
//! * `line`    — the one-line command/reply protocol shared by the
//!   in-sandbox frontends and the host-side connector (see `proxy`/`waf`).

use clap::Parser;

mod audit;
mod cli;
mod connlimit;
mod control;
mod hostfs;
mod line;
mod netns;
mod proxy;
mod pty;
mod sandbox;
mod spec;
mod waf;

use cli::Command;

/// The JSON Schema for the spec file, generated on demand from the
/// `schemars` derive impls on the config-file types in `src/spec/`.
/// Printed by `--print-schema`; point an editor (e.g. VS Code's
/// `json.schemas`) at it to get completion and validation for
/// `.ai-bubble/spec.json`.
pub fn spec_schema() -> String {
    let mut schema = schemars::generate::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<spec::Spec>();
    schema
        .ensure_object()
        .insert("title".to_string(), "ai-bubble sandbox spec".into());
    let mut json = serde_json::to_string_pretty(&schema).unwrap();
    json.push('\n');
    json
}

fn main() {
    let cli = cli::Cli::parse();

    if cli.print_schema {
        print!("{}", spec_schema());
        return;
    }

    match cli.command {
        Some(Command::Run(cmd)) => cmd.run(cli.spec.as_deref()),

        Some(Command::Ls(cmd)) => cmd.run(cli.spec.as_deref()),

        Some(Command::Init(cmd)) => cmd.run(cli.spec.as_deref()),

        Some(Command::Control(cmd)) => cmd.run(cli.spec.as_deref()),

        Some(Command::Audit(cmd)) => cmd.run(cli.spec.as_deref()),

        None => sandbox::die("No sub-command given; usage: ai-bubble run|ls|init|control ..."),
    }
}
