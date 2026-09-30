//! Command-line parsing (clap derive).
//!
//! All sandbox configuration — mounts and networking — lives in the spec
//! file (see `spec`); the command line selects which spec directory to use
//! (`--spec-dir DIR`, default `.ai-bubble`) and a sub-command:
//!
//! * `run` — run COMMAND inside the sandbox configured by the spec file
//!   (the original, and still the default-ish, behaviour),
//! * `ls`  — list a host path and show the mappings of the current config.
//!
//! Each sub-command's implementation lives in its own module (`run`, `ls`);
//! this module holds only the argument parsing.

mod ls;
mod run;

pub use ls::ls;
pub use run::run;

use clap::Parser;
use std::path::PathBuf;

/// ai-bubble: a minimal bubblewrap-like sandbox.
///
/// Configured entirely via the spec file (`--spec-dir DIR`, default
/// `.ai-bubble`); see the sub-commands for what it can do.
#[derive(Parser, Debug)]
#[command(
    name = "ai-bubble",
    version,
    about = "Minimal bubblewrap-like sandboxing CLI, configured via a spec file"
)]
pub struct Cli {
    /// Path to the sandbox spec directory (expected to contain a
    /// `spec.json` file). Defaults to `.ai-bubble` in the current
    /// directory.
    #[arg(long = "spec-dir", value_name = "DIR", global = true)]
    pub spec: Option<PathBuf>,

    /// Print the JSON Schema for the spec file to stdout and exit. Useful
    /// to hand to editors: point `json.schemas` (VS Code) or a similar
    /// setting at the output of
    /// `ai-bubble --print-schema > ai-bubble.schema.json` to get
    /// completion and validation for `.ai-bubble/spec.json`.
    #[arg(long = "print-schema")]
    pub print_schema: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(clap::Subcommand, Debug, PartialEq)]
pub enum Command {
    /// Run COMMAND inside a fresh sandbox (new user + mount namespace,
    /// empty tmpfs root) configured by the spec file.
    Run {
        /// Use PR_SET_PDEATHSIG so the sandboxed command is killed with
        /// SIGKILL when ai-bubble (or ai-bubble's parent) dies — on by
        /// default, like bubblewrap's `--die-with-parent`. This option
        /// switches it off.
        #[arg(
            long = "no-die-with-parent",
            action = clap::ArgAction::SetFalse,
            default_value_t = true
        )]
        die_with_parent: bool,

        /// The command to run inside the sandbox (everything after the
        /// first bare argument or after `--`). Its own flags (e.g.
        /// `ls -l`) pass through verbatim.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// List PATH on the host filesystem, annotated with the permission the
    /// current config gives each entry in the sandbox, plus the mappings
    /// (permissions/actions) of the current config itself.
    Ls {
        /// The host path to list. Defaults to the current directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn spec_dir_and_run_command() {
        let cli = parse(&[
            "ai-bubble",
            "--spec-dir",
            "somedir",
            "run",
            "--",
            "sh",
            "-c",
            "echo hi",
        ]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("somedir")));
        assert_eq!(
            cli.command,
            Some(Command::Run {
                die_with_parent: true,
                command: ["sh", "-c", "echo hi"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            })
        );
    }

    #[test]
    fn run_without_spec_option() {
        let cli = parse(&["ai-bubble", "run", "sh", "-c", "echo hi"]);
        assert_eq!(cli.spec, None);
        match cli.command {
            Some(Command::Run { command, .. }) => assert_eq!(command, ["sh", "-c", "echo hi"]),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn run_command_flags_pass_through() {
        let cli = parse(&["ai-bubble", "run", "ls", "-l", "--color"]);
        match cli.command {
            Some(Command::Run { command, .. }) => assert_eq!(command, ["ls", "-l", "--color"]),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn spec_dir_before_run_subcommand() {
        let cli = parse(&["ai-bubble", "--spec-dir", "otherdir", "run", "sh"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("otherdir")));
        match cli.command {
            Some(Command::Run { command, .. }) => assert_eq!(command, ["sh"]),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn spec_dir_without_value_is_an_error() {
        let err = Cli::try_parse_from(["ai-bubble", "--spec-dir"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--spec-dir"), "{err}");
    }

    #[test]
    fn die_with_parent_flag() {
        let run = |args: &[&str]| match parse(args).command {
            Some(Command::Run {
                die_with_parent, ..
            }) => die_with_parent,
            other => panic!("expected run, got {other:?}"),
        };
        assert!(run(&["ai-bubble", "run", "sh"]));
        assert!(!run(&["ai-bubble", "run", "--no-die-with-parent", "sh"]));
    }

    #[test]
    fn unknown_option_is_an_error() {
        let err = Cli::try_parse_from(["ai-bubble", "run", "--bind", "/usr", "/usr", "sh"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unexpected") || err.contains("--bind"),
            "{err}"
        );
    }

    #[test]
    fn ls_defaults_to_the_current_directory() {
        let cli = parse(&["ai-bubble", "ls"]);
        match cli.command {
            Some(Command::Ls { path }) => assert_eq!(path, PathBuf::from(".")),
            other => panic!("expected ls, got {other:?}"),
        }
    }

    #[test]
    fn ls_takes_a_path_and_a_global_spec_dir() {
        let cli = parse(&["ai-bubble", "--spec-dir", "somedir", "ls", "/etc"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("somedir")));
        match cli.command {
            Some(Command::Ls { path }) => assert_eq!(path, PathBuf::from("/etc")),
            other => panic!("expected ls, got {other:?}"),
        }
    }

    #[test]
    fn print_schema_before_the_subcommand() {
        let cli = parse(&["ai-bubble", "--print-schema"]);
        assert!(cli.print_schema);
        assert_eq!(cli.command, None);
    }
}
