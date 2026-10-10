//! The `control` sub-command: the reference client (and debugging tool)
//! for a running instance's control protocol.
//!
//! The socket name is recomputed from `--spec-dir` (both sides realpath
//! the directory first, so relative and absolute spellings agree), the
//! token is read from `<spec-dir>/run/control-token`, and one command is
//! sent over the token-preamble + JSON-line protocol with exactly one
//! reply — see [`crate::cli::control`] for the protocol and its security
//! properties.

use clap::Args;
use std::io::{Read as _, Write as _};
use std::path::Path;

use crate::{cli::control, sandbox};

/// Talk to a running instance's control socket (see the CLI docs for the
/// full behaviour and the actions).
#[derive(Debug, Args, PartialEq)]
pub struct ControlCommand {
    /// Print the current mutable policy as JSON: `{"fs":
    /// {"mappings": [...]}}` and/or `{"net": {"allow": [...]}}`,
    /// each `null` when not applicable to the run.
    #[arg(long = "policy-get")]
    pub(crate) policy_get: bool,

    /// Replace the whole hostfs pattern set. The argument is a JSON
    /// array of mapping objects in the exact shape of the spec file's
    /// `hostfs.mappings` (with `session-cache`/`project-cache`
    /// disallowed — use their resolved `redirect-rw` form). The same
    /// validation the spec loader applies runs before anything is
    /// swapped; an accepted replacement is persisted into the spec
    /// file, so the next run starts with the same pattern set.
    #[arg(long = "fs-set", value_name = "JSON")]
    pub(crate) fs_set: Option<String>,

    /// Send `spec-reload`: re-read the spec file and apply the runtime-
    /// mutable subset (hostfs mappings, net allow-list). Every changed
    /// immutable section (seccomp, mounts, env, cwd, rlimits, audit
    /// log, immutable net settings) is named in the error — nothing is
    /// silently ignored. `kill -HUP` on the run's launcher does the
    /// same.
    #[arg(long = "spec-reload")]
    pub(crate) spec_reload: bool,

    /// Network allow-list operations: `net list`, `net add ENTRY`,
    /// `net rm ENTRY` (see [`NetAction`]).
    #[command(subcommand)]
    pub(crate) net: Option<NetCommand>,
}

/// The `net` branch of `control` (a wrapper so the `net` level exists
/// between `control` and [`NetAction`]).
#[derive(Debug, clap::Subcommand, PartialEq)]
pub(crate) enum NetCommand {
    /// Network allow-list operations: list the currently allowed
    /// destinations (`net list`), add one entry (`net add ENTRY`) or
    /// remove one entry (`net rm ENTRY`). `add`/`rm` are deltas on the
    /// currently active list; the resulting list is swapped with the
    /// same full-replacement `net-set` the spec reload uses, so the
    /// same validation applies and the in-sandbox proxy must accept it.
    /// Accepted changes are persisted into the spec file, so the next
    /// run starts with the same allow-list.
    Net {
        /// The allow-list operation (`list`, `add ENTRY`, `rm ENTRY`).
        #[command(subcommand)]
        action: NetAction,
    },
}

/// The `control net` sub-commands (`net list` / `net add ENTRY` /
/// `net rm ENTRY`): read the current allow-list, add one entry to it
/// or remove one entry from it. `add`/`rm` are deltas on the
/// currently active list; the resulting list is swapped with the
/// same full-replacement `net-set` the spec reload uses, so the same
/// validation applies and the in-sandbox proxy must accept it. Accepted
/// changes are persisted into the spec file (the launcher rewrites it),
/// so the next run starts with the same allow-list.
#[derive(Debug, clap::Subcommand, PartialEq)]
pub enum NetAction {
    /// List the currently allowed destinations (one entry per line).
    List,
    /// Add ENTRY to the network allow-list (`host`/`host:port`, `*.`
    /// wildcards included, as in the spec's `net.allow`).
    Add {
        /// The allow-list entry to add.
        entry: String,
    },
    /// Remove ENTRY from the network allow-list (an exact match).
    Rm {
        /// The allow-list entry to remove.
        entry: String,
    },
}

impl NetCommand {
    /// Runs `control net`: fetches the current allow-list with
    /// `policy-get`, applies the delta and swaps the result with
    /// `net-set` (the only replacement primitive the protocol has).
    pub(crate) fn run(self, spec_dir: &Path) {
        let NetCommand::Net { action } = self;
        let reply = request(spec_dir, &serde_json::json!({ "cmd": "policy-get" }));
        ensure_ok(&reply);
        let allow = reply
            .get("net")
            .and_then(|net| net.get("allow"))
            .and_then(|allow| allow.as_array())
            .unwrap_or_else(|| {
                sandbox::die("this run has no network allow-list (net control not applicable)")
            });
        let mut entries: Vec<String> = allow
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
            .collect();
        match action {
            NetAction::List => {
                for entry in &entries {
                    println!("{entry}");
                }
            }
            NetAction::Add { entry } => {
                if entries.contains(&entry) {
                    // Idempotent: the entry is already allowed, and the
                    // current list is authoritative — nothing to swap.
                    return;
                }
                entries.push(entry.clone());
                net_set(spec_dir, entries);
            }
            NetAction::Rm { entry } => {
                if !entries.iter().any(|e| e == &entry) {
                    // Idempotent removal: nothing named ENTRY is on the
                    // list, so the policy is already as requested.
                    return;
                }
                entries.retain(|e| e != &entry);
                net_set(spec_dir, entries);
            }
        }
    }
}

/// Swap the whole network allow-list (the protocol's only replacement
/// primitive), print the reply and exit nonzero when it is not `ok`.
fn net_set(spec_dir: &Path, allow: Vec<String>) {
    let reply = request(
        spec_dir,
        &serde_json::json!({ "cmd": "net-set", "allow": allow }),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&reply).unwrap_or_else(|_| reply.to_string())
    );
    ensure_ok(&reply);
}

/// Exit nonzero when a control reply is not `ok`, so scripts can branch
/// on the result without parsing the JSON.
fn ensure_ok(reply: &serde_json::Value) {
    if reply.get("ok").and_then(|ok| ok.as_bool()) != Some(true) {
        println!(
            "{}",
            serde_json::to_string_pretty(reply).unwrap_or_else(|_| reply.to_string())
        );
        std::process::exit(1);
    }
}

impl ControlCommand {
    /// Runs the `control` sub-command (see the CLI docs): at most one action
    /// is given; `policy_get` is the default when the others are absent.
    pub fn run(self, spec_dir: Option<&Path>) {
        let ControlCommand {
            policy_get,
            fs_set,
            net,
            spec_reload,
        } = self;
        let given =
            policy_get as u8 + fs_set.is_some() as u8 + net.is_some() as u8 + spec_reload as u8;
        if given > 1 {
            sandbox::die(
                "give exactly one of --policy-get, --fs-set, net <subcommand>, --spec-reload",
            );
        }
        let spec_dir = spec_dir.unwrap_or(Path::new(crate::spec::file::DEFAULT_SPEC_DIR));
        if let Some(net) = net {
            net.run(spec_dir);
            return;
        }
        let command = if let Some(json) = fs_set {
            let mappings: serde_json::Value = serde_json::from_str(&json)
                .unwrap_or_else(|e| sandbox::die(&format!("--fs-set is not valid JSON: {e}")));
            if !mappings.is_array() {
                sandbox::die("--fs-set must be a JSON array of mapping objects");
            }
            serde_json::json!({ "cmd": "fs-set", "mappings": mappings })
        } else if spec_reload {
            serde_json::json!({ "cmd": "spec-reload" })
        } else {
            serde_json::json!({ "cmd": "policy-get" })
        };

        let reply = request(spec_dir, &command);
        println!(
            "{}",
            serde_json::to_string_pretty(&reply).unwrap_or_else(|_| reply.to_string())
        );
        // A control failure is the client's exit status: scripts can branch
        // on it instead of parsing the JSON.
        if reply.get("ok").and_then(|ok| ok.as_bool()) != Some(true) {
            std::process::exit(1);
        }
    }
}

/// One full protocol exchange: connect to the abstract socket, present
/// the token preamble, send one command, read one reply.
fn request(spec_dir: &Path, command: &serde_json::Value) -> serde_json::Value {
    let name = control::socket_name(spec_dir);
    use std::os::linux::net::SocketAddrExt as _;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .unwrap_or_else(|e| sandbox::die(&format!("Can't build the control socket address: {e}")));
    let mut stream = std::os::unix::net::UnixStream::connect_addr(&addr).unwrap_or_else(|e| {
        sandbox::die(&format!(
            "Can't connect to the control socket @{name} (is the run started with control enabled (default; --no-control opts out), \
             and does it use this --spec-dir?): {e}"
        ))
    });

    // The token preamble: 32 lowercase hex characters, one line.
    let token_path = control::token_path_for(spec_dir);
    let token = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|e| sandbox::die(&format!("Can't read {}: {e}", token_path.display())));
    let token = token.trim();
    if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        sandbox::die(&format!(
            "{} does not hold a control token",
            token_path.display()
        ));
    }
    write_line(&mut stream, token);

    // One command, one reply.
    write_line(&mut stream, &command.to_string());
    let mut reply = String::new();
    // The reply is a single line; read exactly one (the server closes
    // after it or on any error).
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                reply.push(byte[0] as char);
                if reply.len() > control::FRAME_CAP {
                    sandbox::die("control reply over the size cap");
                }
            }
            Err(e) => sandbox::die(&format!("Can't read the control reply: {e}")),
        }
    }
    if reply.is_empty() {
        sandbox::die("the control server closed the connection without a reply");
    }
    serde_json::from_str(&reply)
        .unwrap_or_else(|e| sandbox::die(&format!("control reply is not valid JSON: {e}")))
}

fn write_line(stream: &mut std::os::unix::net::UnixStream, line: &str) {
    stream
        .write_all(format!("{line}\n").as_bytes())
        .unwrap_or_else(|e| sandbox::die(&format!("Can't write to the control socket: {e}")));
}
