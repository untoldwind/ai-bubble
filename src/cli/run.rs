//! The `run` sub-command: run COMMAND inside a fresh sandbox (new user +
//! mount namespace, empty tmpfs root) configured by the spec file.

use std::path::Path;

use crate::{audit, control, hostfs, netns, sandbox, spec, waf};

/// The preprocessing `ai-bubble run` applies to the freshly loaded spec
/// before compiling it — replayed **idempotently** by `spec-reload` (see
/// `crate::control`), so the reload diffs the same preprocessed spec the
/// run was built from:
///
/// * in waf mode, the injected `/etc/resolv.conf` (pointing at the
///   in-sandbox DNS server) and the MITM CA bundle mappings are appended
///   last (they win over earlier mappings of the same path, but not over
///   an explicit `hide`),
/// * the cache mappings (`session-cache`, `project-cache`) are resolved
///   against their backing directories — the *same* per-run session
///   root on every call, so a reload never rewrites the resolved
///   redirects and never resets the session cache mid-run
///   (`create_dir_all` is idempotent).
pub(crate) fn preprocess_spec(
    spec: &mut spec::Spec,
    spec_dir: &Path,
    session_cache: Option<&Path>,
) -> Result<(), String> {
    if matches!(spec.net, spec::net::NetConfig::Waf { .. }) {
        spec.hostfs.mappings.push(spec::hostfs::Mapping::Inject {
            path: "/etc/resolv.conf".to_string(),
            content: "nameserver 127.0.0.2\noptions timeout:1 attempts:1\n".to_string(),
        });

        // The waf mode MITMs HTTPS: generate (once per run) the
        // self-signed CA the in-sandbox HTTPS server signs its
        // certificates with, and inject it as the sandbox's trust
        // anchor. /etc/ssl/certs/ca-certificates.crt is the
        // bundle path of Debian/Ubuntu/Alpine (what curl and
        // OpenSSL-based clients use by default); /etc/pki/... is
        // the Fedora/RHEL equivalent. Only *verification* needs
        // these files — a fake openssl.cnf is not necessary.
        // Appended last, the mappings win over earlier ones, but
        // not over an explicit `hide` of the same path.
        let ca = waf::host::ca_certificate_pem();
        spec.hostfs.mappings.push(spec::hostfs::Mapping::Inject {
            path: "/etc/ssl/certs/ca-certificates.crt".to_string(),
            content: ca.clone(),
        });
        spec.hostfs.mappings.push(spec::hostfs::Mapping::Inject {
            path: "/etc/pki/tls/certs/ca-bundle.crt".to_string(),
            content: ca,
        });
    }

    // Resolve the cache mappings (`session-cache`, `project-cache`)
    // against their backing directories before anything is compiled:
    // the session-cache tmp directory is created here and wiped once
    // ai-bubble terminates (the mirrored-fs server inherits the wipe).
    spec.hostfs.prepare_caches(spec_dir, session_cache)
}

/// Runs the `run` sub-command. `spec_dir` is the `--spec-dir` value (if
/// given), `die_with_parent` the (negatable) PDEATHSIG flag, `new_session`
/// the (negatable) new-terminal-session flag, `require_spec` the
/// `--require-spec` strictness flag (see above), `control_enabled` the
/// (negatable) runtime-control switch — on by default, off via
/// `--no-control` — `command` the command to execute inside the sandbox.
pub fn run(
    spec_dir: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    require_spec: bool,
    control_enabled: bool,
    mut command: Vec<String>,
) {
    if command.is_empty() {
        sandbox::die(
            "No command given; usage: ai-bubble run [--spec-dir DIR] -- COMMAND [args...]",
        );
    }
    // SP-5: the security-relevant negatable run flags parse ahead of the
    // command, so a wrapper that forwards untrusted arguments *without*
    // `--` could smuggle `--no-new-session` (host pts bound in,
    // TIOCSTI injection), `--no-die-with-parent` or `--no-control` into
    // ai-bubble itself. When one of these flags appears *inside* the
    // forwarded command vector, the arguments were almost certainly
    // mixed with untrusted input — refuse the run and tell the caller to
    // separate the command with `--`. (ai-bubble's own flags are parsed
    // out before this point and never end up in `command`.)
    for arg in &command {
        if matches!(
            arg.as_str(),
            "--no-new-session" | "--no-die-with-parent" | "--no-control"
        ) {
            sandbox::die(&format!(
                "{arg} appears inside the forwarded command; ai-bubble's own options must \
                 come before the command and the command must be separated from them with \
                 `--` (untrusted arguments must never be forwarded without that separator)"
            ));
        }
    }
    // AUDIT.md L9: an explicit `--spec-dir` that cannot be read is a hard
    // error inside `Spec::load` already; `--require-spec` extends the same
    // strictness to the default spec directory, so a missing `.ai-bubble/
    // spec.json` (wrong CWD, renamed spec dir) cannot silently degrade the
    // run to an empty policy with host networking.
    if require_spec {
        let dir = spec_dir.unwrap_or_else(|| Path::new(spec::file::DEFAULT_SPEC_DIR));
        if !dir.join(spec::file::SPEC_FILE).exists() {
            sandbox::die(&format!(
                "--require-spec: no spec file at {}",
                dir.join(spec::file::SPEC_FILE).display()
            ));
        }
    }
    let mut spec = spec::Spec::load(spec_dir);

    // The run's preprocessing (waf injections, cache-mapping
    // resolution) — factored out because `spec-reload` must replay it
    // identically (see `crate::control::spec_reload_inner`).
    // The session-cache tmp directory is created here and wiped once
    // ai-bubble terminates (the mirrored-fs server inherits the wipe).
    let spec_dir = spec_dir.unwrap_or(Path::new(spec::file::DEFAULT_SPEC_DIR));
    warn_risky_spec(&spec, spec_dir);
    let session_cache = hostfs::session_cache_needed(spec.hostfs.has_session_caches());
    preprocess_spec(&mut spec, spec_dir, session_cache.as_deref())
        .unwrap_or_else(|e| crate::sandbox::die(&e));

    // Compile the config-file spec down into the internal
    // configuration (ops, hostfs patterns, net settings) the
    // sandbox machinery runs with.
    let sandbox_config = spec::internal::SandboxConfig::compile(&spec);

    // Store the audit log path (if any) before any fork: every
    // forked process (FUSE server, network frontends) sets up its
    // own audit writer against the same file. The path is validated
    // here (inside the spec directory, or an already existing file):
    // the writers append with the operator's uid, so an arbitrary
    // path would be an arbitrary file create/append primitive.
    audit::configure(sandbox_config.audit_log.clone(), spec_dir);
    // Single-writer audit: on the isolated path the launcher is the only
    // process touching the log; the FUSE server and P send their events
    // upstream over pre-fork socketpairs. On the non-isolated path the
    // launcher has no runtime — unless runtime control is enabled, in
    // which case its supervisor grows one and serves the hub too (see
    // `sandbox::pidns_and_exec`).
    audit::set_ipc_enabled(sandbox_config.net.isolated || control_enabled);

    // Runtime control: register the authoritative mutable policy state
    // (always — the bookkeeping is inert when control is disabled via
    // `--no-control`), then bind
    // the abstract socket and write the token. The bind must happen
    // before the FUSE server forks, so the child can close the inherited
    // listener (and, on `EADDRINUSE`, this run simply continues without
    // control).
    control::record_initial(control::Start {
        fs_initial: sandbox_config
            .patterns
            .has_patterns()
            .then(|| serde_json::to_value(&spec.hostfs.mappings).unwrap_or_default())
            .and_then(|value| value.as_array().cloned()),
        net_applicable: sandbox_config.net.isolated,
        net_proxy: sandbox_config.net.isolated
            && matches!(sandbox_config.net.mode, spec::internal::NetMode::Proxy),
        config: sandbox_config.clone(),
        spec_dir: std::fs::canonicalize(spec_dir).unwrap_or_else(|_| spec_dir.to_path_buf()),
        session_cache: session_cache.clone(),
    });
    if control_enabled {
        control::start(spec_dir);
    }

    // Start the host FUSE filesystem server (in its own child
    // process) before any namespace setup: its filesystem becomes
    // the sandbox root, with the ops (dev, tmpfs, proc, binds)
    // mounted on top of it. Only when the spec actually exposes
    // something: a sandbox without any hostfs mappings must not
    // depend on (or fail for the lack of) FUSE.
    if sandbox_config.patterns.has_patterns() {
        hostfs::set_root_mode(true);
        if let Some(root) = &session_cache {
            hostfs::set_session_cache_root(root);
        }
        // The launcher wraps the compiled set in a shared handle: it keeps
        // the authoritative copy (for later runtime-control updates), and
        // the FUSE server child receives a cheap clone of the same
        // instance.
        let patterns = hostfs::SharedPatterns::new(sandbox_config.patterns.clone());
        hostfs::start_host_fs(&patterns);
    }

    let command = std::mem::take(&mut command);
    if sandbox_config.net.isolated {
        netns::run(
            &sandbox_config.ops,
            &command,
            &sandbox_config.net,
            &sandbox_config.env,
            sandbox_config.cwd.as_deref(),
            die_with_parent,
            new_session,
            sandbox_config.seccomp.as_ref(),
        );
    } else {
        sandbox::setup_and_exec(
            &sandbox_config.ops,
            &command,
            &sandbox_config.env,
            sandbox_config.cwd.as_deref(),
            die_with_parent,
            new_session,
            sandbox_config.seccomp.as_ref(),
        );
    }
}

/// Warn once on stderr about dangerous-but-legal spec constructs (SP-10):
/// the spec is the operator's trusted input, so these are warnings, not
/// errors — but a run that hands the sandbox `$HOME` or `/etc` writable,
/// or runs with no seccomp filter at all, deserves a loudly visible
/// heads-up (the `init` starter now teaches proxy-mode networking plus a
/// seccomp preset instead).
fn warn_risky_spec(spec: &spec::Spec, spec_dir: &Path) {
    fn warn(msg: &str) {
        eprintln!("warning: {msg}");
    }
    for mapping in &spec.hostfs.mappings {
        let globs: Option<&spec::hostfs::Globs> = match mapping {
            spec::hostfs::Mapping::Rw { glob } => Some(glob),
            _ => None,
        };
        if let Some(globs) = globs {
            for g in &globs.0 {
                if g == "/etc" || g == "/etc/**" {
                    warn("the spec maps /etc read-write into the sandbox; system-wide \
                          configuration is writable by the command");
                }
                if g == "${HOME}"
                    || g == "~"
                    || g.starts_with("${HOME}")
                    || g.starts_with("~/")
                {
                    warn(&format!(
                        "the spec maps the home directory ({g}) read-write into the sandbox; \
                         consider narrower mappings (project dir, caches)"
                    ));
                }
                if g.contains(".ssh") {
                    warn(&format!(
                        "the spec maps an .ssh path ({g}) into the sandbox; keys and \
                         configuration are exposed (read-only mappings expose them too)"
                    ));
                }
            }
        }
    }
    // No filter configured: the section is absent (or all-default).
    let no_seccomp = spec.seccomp == spec::seccomp::SeccompConfig::default();
    if no_seccomp {
        warn("the spec has no `seccomp` section: the command runs without a syscall \
              filter. Consider `\"seccomp\": { \"preset\": \"default\" }`.");
    }
    if matches!(spec.net, spec::net::NetConfig::Host { .. }) && no_seccomp {
        warn("host networking without a seccomp filter: the command can reach every \
              address family the kernel allows (see the seccomp module docs for the \
              documented gaps). Proxy or waf mode restricts egress to the allow-list.");
    }
    let _ = spec_dir;
}
