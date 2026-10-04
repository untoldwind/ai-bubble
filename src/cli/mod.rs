//! Command-line parsing (clap derive).
//!
//! All sandbox configuration — mounts and networking — lives in the spec
//! file (see `spec`); the command line selects which spec directory to use
//! (`--spec-dir DIR`, default `.ai-bubble`) and a sub-command:
//!
//! * `run` — run COMMAND inside the sandbox configured by the spec file
//!   (the original, and still the default-ish, behaviour),
//! * `ls`  — list a host path and show the mappings of the current config,
//! * `init` — bootstrap a spec directory with a starter spec file.
//!
//! Each sub-command's implementation lives in its own module (`run`, `ls`,
//! `init`); this module holds only the argument parsing.

mod audit_cli;
mod control_cli;
mod init;
mod ls;
mod run;

pub use audit_cli::AuditCommand;
pub use control_cli::ControlCommand;
pub use init::InitCommand;
pub use ls::LsCommand;
pub use run::RunCommand;
pub(crate) use run::preprocess_spec;

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
    ///
    /// Deliberately *not* a clap `global` option (AUDIT.md L6): it must
    /// appear **before** the sub-command. A wrapper that passes untrusted
    /// arguments to `run` without a leading `--` must not be able to swap
    /// the entire security policy with a stray `--spec-dir` (same class as
    /// `run --no-new-session`).
    #[arg(long = "spec-dir", value_name = "DIR")]
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
    Run(RunCommand),

    /// List PATH on the host filesystem, annotated with the permission the
    /// current config gives each entry in the sandbox, plus the mappings
    /// (permissions/actions) of the current config itself.
    Ls(LsCommand),

    /// Bootstrap the spec directory (`.ai-bubble`, or `--spec-dir DIR`) if
    /// it does not exist yet: creates it and writes a starter `spec.json`
    /// (pinning the project directory by absolute path) plus the JSON
    /// Schema for it. When the current directory is a git repository, the
    /// spec directory is also added to its `.gitignore`. An existing
    /// directory is left untouched.
    Init(InitCommand),

    /// Talk to a running instance's control socket (the run must have
    /// been started with control enabled (the default; `--no-control` opts
    /// out), and use the same `--spec-dir`):
    /// read the current mutable policy (`--policy-get`, the default),
    /// replace one of its runtime-mutable domains (`--fs-set` with a JSON
    /// array of hostfs mapping objects, `--net-set` with a JSON array of
    /// allow-list entries), or re-read the spec file and apply its
    /// runtime-mutable subset (`--spec-reload`; every changed immutable
    /// section is named in the error instead of being silently ignored —
    /// `kill -HUP` on the run's launcher does the same). The replacements
    /// are **full** — never deltas — and affect new
    /// operations/connections only. The command exits nonzero when the
    /// reply is not `ok`, so scripts can branch on the result.
    Control(ControlCommand),

    /// Show the audit log path (or follow the audit log with
    /// `--follow`): the log is a host-side JSONL file written solely by
    /// the launcher (single-writer audit), so plain file tailing is all
    /// the streaming there is.
    Audit(AuditCommand),
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
            Some(Command::Run(RunCommand {
                die_with_parent: true,
                new_session: true,
                require_spec: false,
                control: true,
                command: ["sh", "-c", "echo hi"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            }))
        );
    }

    #[test]
    fn run_without_spec_option() {
        let cli = parse(&["ai-bubble", "run", "sh", "-c", "echo hi"]);
        assert_eq!(cli.spec, None);
        match cli.command {
            Some(Command::Run(cmd)) => assert_eq!(cmd.command, ["sh", "-c", "echo hi"]),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn run_command_flags_pass_through() {
        let cli = parse(&["ai-bubble", "run", "ls", "-l", "--color"]);
        match cli.command {
            Some(Command::Run(cmd)) => assert_eq!(cmd.command, ["ls", "-l", "--color"]),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn spec_dir_before_run_subcommand() {
        let cli = parse(&["ai-bubble", "--spec-dir", "otherdir", "run", "sh"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("otherdir")));
        match cli.command {
            Some(Command::Run(cmd)) => assert_eq!(cmd.command, ["sh"]),
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
            Some(Command::Run(cmd)) => cmd.die_with_parent,
            other => panic!("expected run, got {other:?}"),
        };
        assert!(run(&["ai-bubble", "run", "sh"]));
        assert!(!run(&["ai-bubble", "run", "--no-die-with-parent", "sh"]));
    }

    #[test]
    fn new_session_flag() {
        let run = |args: &[&str]| match parse(args).command {
            Some(Command::Run(cmd)) => cmd.new_session,
            other => panic!("expected run, got {other:?}"),
        };
        assert!(run(&["ai-bubble", "run", "sh"]));
        assert!(!run(&["ai-bubble", "run", "--no-new-session", "sh"]));
    }

    #[test]
    fn control_flag() {
        let run = |args: &[&str]| match parse(args).command {
            Some(Command::Run(cmd)) => cmd.control,
            other => panic!("expected run, got {other:?}"),
        };
        // Default: on (runtime control enabled unless opted out).
        assert!(run(&["ai-bubble", "run", "sh"]));
        assert!(!run(&["ai-bubble", "run", "--no-control", "sh"]));
    }

    #[test]
    fn require_spec_flag() {
        let run = |args: &[&str]| match parse(args).command {
            Some(Command::Run(cmd)) => cmd.require_spec,
            other => panic!("expected run, got {other:?}"),
        };
        // Default: off.
        assert!(!run(&["ai-bubble", "run", "sh"]));
        // On when given (AUDIT.md L9): a missing default spec must not
        // silently degrade to an empty policy with host networking.
        assert!(run(&["ai-bubble", "run", "--require-spec", "sh"]));
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

    /// `--spec-dir` is deliberately not a global option (AUDIT.md L6): a
    /// wrapper passing untrusted arguments to `run` without a leading
    /// `--` must not be able to swap the security policy with a stray
    /// `--spec-dir` after the sub-command.
    #[test]
    fn spec_dir_after_the_subcommand_is_rejected() {
        let err = Cli::try_parse_from(["ai-bubble", "run", "--spec-dir", "/tmp/evil", "sh"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--spec-dir"), "{err}");
    }

    /// The audit sub-command parses (and the follow flags).
    #[test]
    fn audit_subcommand() {
        let cli = parse(&["ai-bubble", "audit"]);
        match cli.command {
            Some(Command::Audit(cmd)) => {
                assert!(!cmd.follow);
                assert_eq!(cmd.lines, 10);
            }
            other => panic!("expected audit, got {other:?}"),
        }
        let cli = parse(&[
            "ai-bubble",
            "--spec-dir",
            "d",
            "audit",
            "--follow",
            "--lines",
            "3",
        ]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("d")));
        match cli.command {
            Some(Command::Audit(cmd)) => {
                assert!(cmd.follow);
                assert_eq!(cmd.lines, 3);
            }
            other => panic!("expected audit, got {other:?}"),
        }
    }

    /// The control sub-command parses all four actions.
    #[test]
    fn control_subcommand_actions() {
        let actions = |args: &[&str]| match parse(args).command {
            Some(Command::Control(cmd)) => {
                (cmd.policy_get, cmd.fs_set, cmd.net_set, cmd.spec_reload)
            }
            other => panic!("expected control, got {other:?}"),
        };
        // The bare sub-command parses all-false: `--policy-get` is the
        // *default action* (applied when no flag is given), not a
        // default-on flag (see `control_cli::control`).
        assert_eq!(
            actions(&["ai-bubble", "control"]),
            (false, None, None, false)
        );
        assert_eq!(
            actions(&["ai-bubble", "control", "--spec-reload"]),
            (false, None, None, true)
        );
        assert_eq!(
            actions(&["ai-bubble", "control", "--net-set", r#"["a.example:443"]"#]),
            (false, None, Some(r#"["a.example:443"]"#.to_string()), false)
        );
    }

    #[test]
    fn ls_defaults_to_the_current_directory() {
        let cli = parse(&["ai-bubble", "ls"]);
        match cli.command {
            Some(Command::Ls(cmd)) => assert_eq!(cmd.path, PathBuf::from(".")),
            other => panic!("expected ls, got {other:?}"),
        }
    }

    #[test]
    fn ls_takes_a_path_and_a_global_spec_dir() {
        let cli = parse(&["ai-bubble", "--spec-dir", "somedir", "ls", "/etc"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("somedir")));
        match cli.command {
            Some(Command::Ls(cmd)) => assert_eq!(cmd.path, PathBuf::from("/etc")),
            other => panic!("expected ls, got {other:?}"),
        }
    }

    #[test]
    fn print_schema_before_the_subcommand() {
        let cli = parse(&["ai-bubble", "--print-schema"]);
        assert!(cli.print_schema);
        assert_eq!(cli.command, None);
    }

    #[test]
    fn init_parses_and_takes_the_global_spec_dir() {
        let cli = parse(&["ai-bubble", "init"]);
        assert_eq!(cli.command, Some(Command::Init(InitCommand::default())));

        let cli = parse(&["ai-bubble", "--spec-dir", "somedir", "init"]);
        assert_eq!(cli.spec.as_deref(), Some(std::path::Path::new("somedir")));
        assert_eq!(cli.command, Some(Command::Init(InitCommand::default())));
    }
}
