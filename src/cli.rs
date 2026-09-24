//! Command-line parsing (clap derive).
//!
//! All options are declared with clap's derive API (--help, --version and
//! unknown-option errors come for free). One caveat: clap groups the values
//! of each option by id, so it cannot preserve the *interleaved order* of
//! repeated `--bind` and `--symlink` options, which bwrap semantics rely on
//! (e.g. a `--symlink` may create a directory that a later `--bind` mounts
//! into). Those two options are therefore pulled out by a small scanning
//! pass before clap sees the remaining arguments; everything else — the
//! flags, `--` handling and the trailing command — is clap's job.

use clap::Parser;
use std::path::PathBuf;

/// Network-related options for `--isolated-net`.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct NetConfig {
    /// Run the command in a fresh network namespace and proxy its
    /// connections from the host side.
    pub isolated: bool,
    /// Allow-list of `host` or `host:port` targets for the proxy.
    /// Empty means: allow everything.
    pub allow: Vec<String>,
}

/// One sandbox setup operation.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Bind { src: String, dest: PathBuf },
    Symlink { src: String, dest: PathBuf },
    Proc { dest: PathBuf },
}

/// A minimal reimplementation of bubblewrap's basic functionality.
///
/// Runs COMMAND inside a fresh sandbox (new user + mount namespace, empty
/// tmpfs root), supporting the --bind and --symlink options.
///
/// With --isolated-net the command additionally runs in a fresh network
/// namespace (no interfaces besides loopback) while rs-bubble stays alive in
/// the host network namespace and acts as a TCP proxy reachable through the
/// Unix socket mounted at /net/sock inside the sandbox.
#[derive(Parser, Debug)]
#[command(
    name = "rs-bubble",
    version,
    about = "Minimal bubblewrap-like sandboxing CLI (supports --bind, --symlink, --isolated-net)"
)]
pub struct Cli {
    /// Run the command in a fresh network namespace and proxy its
    /// connections from the host side.
    #[arg(long = "isolated-net")]
    pub isolated_net: bool,

    /// Allow-list entry for the proxy: `host` (any port) or `host:port`.
    /// Repeatable; an empty list allows everything.
    #[arg(long = "allow-net", value_name = "TARGET")]
    pub allow_net: Vec<String>,

    /// The command to run inside the sandbox (everything after the first
    /// bare argument or after `--`). `parse_args` inserts a `--` before the
    /// command so that its own flags (e.g. `ls -l`) pass through verbatim.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// The --bind/--symlink operations, in command-line order.
    #[arg(skip)]
    pub ops: Vec<Op>,
}

impl Cli {
    /// Parse the argument list (without argv[0]).
    pub fn parse_args<I>(argv: I) -> Cli
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let argv: Vec<String> = argv.into_iter().map(Into::into).collect();
        let (ops, rest) = extract_ops(&argv);
        let mut cli = Cli::parse_from(std::iter::once("rs-bubble".to_string()).chain(rest));
        cli.ops = ops;
        cli
    }

    /// The network configuration derived from the parsed options.
    pub fn net(&self) -> NetConfig {
        NetConfig {
            isolated: self.isolated_net,
            allow: self.allow_net.clone(),
        }
    }

    /// The filesystem setup operations, with `/proc` ensured.
    ///
    /// The sandboxed command runs in its own PID namespace, so a *fresh*
    /// procfs instance (which only shows the sandbox's processes, like bwrap
    /// with `--unshare-pid --proc /proc`) is what the child needs. If the
    /// user passed `--proc DEST` explicitly, that is used instead.
    ///
    /// The default is *prepended*, so explicit `--bind`s targeting paths
    /// below `/proc` still layer on top of it.
    pub fn filesystem_ops(&self) -> Vec<Op> {
        if self.ops.iter().any(|op| matches!(op, Op::Proc { .. })) {
            self.ops.clone()
        } else {
            std::iter::once(Op::Proc {
                dest: PathBuf::from("/proc"),
            })
            .chain(self.ops.iter().cloned())
            .collect()
        }
    }
}

/// Pull the `--bind`/`--symlink` operations (with their two values each)
/// out of the argument list, preserving order. When the command starts
/// (at `--` or the first bare argument), everything from there on is
/// handed to clap behind a `--` so its flags pass through verbatim.
fn extract_ops(argv: &[String]) -> (Vec<Op>, Vec<String>) {
    let mut ops: Vec<Op> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;

    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
            "--" => {
                // The rest is the command, verbatim.
                rest.extend(argv[i..].iter().cloned());
                break;
            }
            "--bind" | "--symlink" => {
                let (Some(src), Some(dest)) = (argv.get(i + 1), argv.get(i + 2)) else {
                    crate::sandbox::die(&format!("{a} takes two arguments"));
                };
                ops.push(if a == "--bind" {
                    Op::Bind {
                        src: src.clone(),
                        dest: PathBuf::from(dest),
                    }
                } else {
                    Op::Symlink {
                        src: src.clone(),
                        dest: PathBuf::from(dest),
                    }
                });
                i += 3;
            }
            "--proc" => {
                let Some(dest) = argv.get(i + 1) else {
                    crate::sandbox::die("--proc takes one argument");
                };
                ops.push(Op::Proc {
                    dest: PathBuf::from(dest),
                });
                i += 2;
            }
            _ => {
                if !a.starts_with('-') || a.len() == 1 {
                    // A bare argument starts the command; protect the rest
                    // of the line (including its own flags) with `--`.
                    rest.push("--".into());
                    rest.extend(argv[i..].iter().cloned());
                    break;
                }
                rest.push(a.clone());
                i += 1;
                // A value-taking option's value must not be mistaken for
                // the command start, so consume it here as well.
                if a == "--allow-net" && argv.len() > i {
                    rest.push(argv[i].clone());
                    i += 1;
                }
            }
        }
    }

    (ops, rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn ops_preserve_cli_order() {
        let cli = parse(&[
            "--symlink",
            "x",
            "/a",
            "--bind",
            "/usr",
            "/usr",
            "--symlink",
            "y",
            "/b",
            "--",
            "sh",
            "-c",
            "echo hi",
        ]);
        assert_eq!(cli.net(), NetConfig::default());
        assert_eq!(cli.ops.len(), 3);
        assert_eq!(
            cli.ops[0],
            Op::Symlink {
                src: "x".into(),
                dest: PathBuf::from("/a")
            }
        );
        assert_eq!(
            cli.ops[1],
            Op::Bind {
                src: "/usr".into(),
                dest: PathBuf::from("/usr")
            }
        );
        assert_eq!(
            cli.ops[2],
            Op::Symlink {
                src: "y".into(),
                dest: PathBuf::from("/b")
            }
        );
        assert_eq!(cli.command, ["sh", "-c", "echo hi"]);
    }

    #[test]
    fn command_without_ddash() {
        let cli = parse(&["--bind", "/tmp", "/tmp", "ls", "-l"]);
        assert_eq!(cli.ops.len(), 1);
        assert_eq!(cli.command, ["ls", "-l"]);
    }

    #[test]
    fn isolated_net_options() {
        let cli = parse(&[
            "--isolated-net",
            "--allow-net",
            "example.com:443",
            "--allow-net",
            "localhost",
            "sh",
        ]);
        let net = cli.net();
        assert!(net.isolated);
        assert_eq!(net.allow, ["example.com:443", "localhost"]);
        assert_eq!(cli.command, ["sh"]);
    }

    #[test]
    fn ops_between_options() {
        // Options and ops interleaved must both be parsed correctly.
        let cli = parse(&[
            "--bind",
            "/usr",
            "/usr",
            "--isolated-net",
            "--symlink",
            "y",
            "/b",
            "sh",
        ]);
        assert!(cli.isolated_net);
        assert_eq!(cli.ops.len(), 2);
        assert_eq!(cli.command, ["sh"]);
    }

    #[test]
    fn proc_option_takes_dest() {
        let cli = parse(&["--proc", "/proc", "--bind", "/usr", "/usr", "sh"]);
        assert_eq!(cli.ops[0], Op::Proc { dest: PathBuf::from("/proc") });
        assert_eq!(cli.command, ["sh"]);
    }

    #[test]
    fn default_proc_is_prepended_once() {
        // Without --proc: a fresh procfs at /proc is prepended, in front of
        // the user's ops so they can layer on top of it.
        let cli = parse(&["--bind", "/usr", "/usr", "sh"]);
        assert_eq!(
            cli.filesystem_ops()[0],
            Op::Proc { dest: PathBuf::from("/proc") }
        );
        assert_eq!(cli.filesystem_ops().len(), 2);

        // With an explicit --proc: used verbatim, no extra default.
        let cli = parse(&["--proc", "/sys/proc", "--", "sh"]);
        assert_eq!(
            cli.filesystem_ops(),
            vec![Op::Proc { dest: PathBuf::from("/sys/proc") }]
        );
    }
}
