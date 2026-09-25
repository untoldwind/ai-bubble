//! Command-line parsing (clap derive).
//!
//! All sandbox configuration — mounts and networking — lives in the spec
//! file (see `spec`); the command line only selects which spec file to use
//! (`--spec FILE`, default `.rs-bubble.json`) and carries the command to
//! run inside the sandbox.

use clap::Parser;
use std::path::PathBuf;

/// rs-bubble: a minimal bubblewrap-like sandbox.
///
/// Runs COMMAND inside a fresh sandbox (new user + mount namespace, empty
/// tmpfs root) configured by the spec file. See `.rs-bubble.json` and
/// `--spec FILE`.
#[derive(Parser, Debug)]
#[command(
    name = "rs-bubble",
    version,
    about = "Minimal bubblewrap-like sandboxing CLI, configured via a spec file"
)]
pub struct Cli {
    /// Path to the sandbox spec file. Defaults to `.rs-bubble.json` in the
    /// current directory.
    #[arg(long = "spec", value_name = "FILE")]
    pub spec: Option<PathBuf>,

    /// The command to run inside the sandbox (everything after the first
    /// bare argument or after `--`). `parse_args` inserts a `--` before the
    /// command so that its own flags (e.g. `ls -l`) pass through verbatim.
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn spec_and_command() {
        let cli = parse(&["rs-bubble", "--spec", "s.json", "--", "sh", "-c", "echo hi"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("s.json")));
        assert_eq!(cli.command, ["sh", "-c", "echo hi"]);
    }

    #[test]
    fn no_spec_option() {
        let cli = parse(&["rs-bubble", "sh", "-c", "echo hi"]);
        assert_eq!(cli.spec, None);
        assert_eq!(cli.command, ["sh", "-c", "echo hi"]);
    }

    #[test]
    fn command_flags_pass_through() {
        let cli = parse(&["rs-bubble", "ls", "-l", "--color"]);
        assert_eq!(cli.command, ["ls", "-l", "--color"]);
    }

    #[test]
    fn spec_before_bare_command() {
        let cli = parse(&["rs-bubble", "--spec", "other.json", "sh"]);
        assert_eq!(
            cli.spec.as_deref(),
            Some(std::path::Path::new("other.json"))
        );
        assert_eq!(cli.command, ["sh"]);
    }

    #[test]
    fn spec_without_value_is_an_error() {
        let err = Cli::try_parse_from(["rs-bubble", "--spec"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--spec"), "{err}");
    }

    #[test]
    fn unknown_option_is_an_error() {
        let err = Cli::try_parse_from(["rs-bubble", "--bind", "/usr", "/usr", "sh"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unexpected") || err.contains("--bind"),
            "{err}"
        );
    }
}
