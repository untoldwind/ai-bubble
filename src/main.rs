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

mod cli;
mod hostfs;
mod netns;
mod proxy;
mod sandbox;
mod spec;

fn main() {
    let args = match cli::Cli::parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => sandbox::die(&e),
    };

    let command = args.command.clone();
    if command.is_empty() {
        sandbox::die("No command given; usage: rs-bubble [--spec FILE] -- COMMAND [args...]");
    }

    let spec = spec::Spec::load(args.spec.as_deref());

    // Start the host FUSE filesystem server (in its own child process) before
    // any namespace setup, so the sandbox can bind-mount it at /host.
    hostfs::start_host_fs();

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
