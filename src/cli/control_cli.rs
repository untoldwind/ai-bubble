//! The `control` sub-command: the reference client (and debugging tool)
//! for a running instance's control protocol.
//!
//! The socket name is recomputed from `--spec-dir` (both sides realpath
//! the directory first, so relative and absolute spellings agree), the
//! token is read from `<spec-dir>/run/control-token`, and one command is
//! sent over the token-preamble + JSON-line protocol with exactly one
//! reply — see [`crate::control`] for the protocol and its security
//! properties.

use std::io::{Read as _, Write as _};
use std::path::Path;

use crate::{control, sandbox};

/// Runs the `control` sub-command (see the CLI docs): at most one action
/// is given; `policy_get` is the default when the others are absent.
pub fn control(
    spec_dir: Option<&Path>,
    policy_get: bool,
    fs_set: Option<String>,
    net_set: Option<String>,
    spec_reload: bool,
) {
    let given =
        policy_get as u8 + fs_set.is_some() as u8 + net_set.is_some() as u8 + spec_reload as u8;
    if given > 1 {
        sandbox::die("give exactly one of --policy-get, --fs-set, --net-set, --spec-reload");
    }
    let command = if let Some(json) = fs_set {
        let mappings: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| sandbox::die(&format!("--fs-set is not valid JSON: {e}")));
        if !mappings.is_array() {
            sandbox::die("--fs-set must be a JSON array of mapping objects");
        }
        serde_json::json!({ "cmd": "fs-set", "mappings": mappings })
    } else if let Some(json) = net_set {
        let allow: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| sandbox::die(&format!("--net-set is not valid JSON: {e}")));
        if !allow.is_array() {
            sandbox::die("--net-set must be a JSON array of strings");
        }
        serde_json::json!({ "cmd": "net-set", "allow": allow })
    } else if spec_reload {
        serde_json::json!({ "cmd": "spec-reload" })
    } else {
        serde_json::json!({ "cmd": "policy-get" })
    };

    let spec_dir = spec_dir.unwrap_or(Path::new(crate::spec::file::DEFAULT_SPEC_DIR));
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
