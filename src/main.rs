//! rs-bubble: a minimal bubblewrap-like sandbox.
//!
//! Module layout (who is allowed to do what):
//!
//! * `cli`     — argument parsing only (clap derive); no side effects.
//! * `sandbox` — the privileged filesystem part: user/mount namespaces,
//!   tmpfs root, bind mounts, symlinks, proc, exec. Never touches the
//!   network.
//! * `netns`   — the `--isolated-net` process tree: forks, user/network
//!   namespaces, id maps, loopback setup, waitpid lifecycle.
//! * `proxy`   — pure async networking (tokio): the host-side connector on
//!   a Unix socket and the in-sandbox HTTP CONNECT proxy. No namespace or
//!   process management.

mod cli;
mod netns;
mod proxy;
mod sandbox;

fn main() {
    let args = cli::Cli::parse_args(std::env::args().skip(1));

    let command = args.command.clone();
    if command.is_empty() {
        sandbox::die("No command given; usage: rs-bubble [options] -- COMMAND [args...]");
    }

    let net = args.net();
    let ops = args.filesystem_ops();

    unsafe {
        if net.isolated {
            netns::run(&ops, &command, &net);
        } else {
            sandbox::setup_and_exec(&ops, &command);
        }
    }
}
