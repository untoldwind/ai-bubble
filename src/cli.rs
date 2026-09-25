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

impl Cli {
    /// Parse the argument list (without argv[0]).
    ///
    /// Errors are returned instead of exiting so that tests don't kill the
    /// harness; `main` turns them into the usual diagnostic + exit.
    pub fn parse_args<I>(argv: I) -> Result<Cli, String>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let argv: Vec<String> = argv.into_iter().map(Into::into).collect();
        let rest = protect_command(&argv);
        Cli::try_parse_from(std::iter::once("rs-bubble".to_string()).chain(rest))
            .map_err(|e| e.to_string())
    }
}

/// Options that take a value (the value must not be mistaken for the start
/// of the command).
const VALUE_OPTIONS: [&str; 1] = ["--spec"];

/// Everything from the first bare argument (or from `--`) is the command;
/// guard it behind a `--` so its own flags (e.g. `ls -l`) pass through
/// verbatim instead of being mistaken for rs-bubble options.
fn protect_command(argv: &[String]) -> Vec<String> {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            return argv.to_vec();
        }
        if !a.starts_with('-') || a.len() == 1 {
            let mut rest = argv[..i].to_vec();
            rest.push("--".into());
            rest.extend(argv[i..].iter().cloned());
            return rest;
        }
        // Skip a value-taking option's value so it stays attached.
        i += if VALUE_OPTIONS.contains(&a.as_str()) {
            2
        } else {
            1
        };
    }
    argv.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_args(args.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn spec_and_command() {
        let cli = parse(&["--spec", "s.json", "--", "sh", "-c", "echo hi"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("s.json")));
        assert_eq!(cli.command, ["sh", "-c", "echo hi"]);
    }

    #[test]
    fn no_spec_option() {
        let cli = parse(&["sh", "-c", "echo hi"]);
        assert_eq!(cli.spec, None);
        assert_eq!(cli.command, ["sh", "-c", "echo hi"]);
    }

    #[test]
    fn command_flags_pass_through() {
        let cli = parse(&["ls", "-l", "--color"]);
        assert_eq!(cli.command, ["ls", "-l", "--color"]);
    }

    #[test]
    fn spec_before_bare_command() {
        let cli = parse(&["--spec", "other.json", "sh"]);
        assert_eq!(
            cli.spec.as_deref(),
            Some(std::path::Path::new("other.json"))
        );
        assert_eq!(cli.command, ["sh"]);
    }

    #[test]
    fn spec_without_value_is_an_error() {
        let err = Cli::parse_args(["--spec"]).unwrap_err();
        assert!(err.contains("--spec"), "{err}");
    }

    #[test]
    fn unknown_option_is_an_error() {
        let err = Cli::parse_args(["--bind", "/usr", "/usr", "sh"]).unwrap_err();
        assert!(
            err.contains("unexpected") || err.contains("--bind"),
            "{err}"
        );
    }
}
