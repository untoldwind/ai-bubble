//! The `run` sub-command: run COMMAND inside a fresh sandbox (new user +
//! mount namespace, empty tmpfs root) configured by the spec file.

use std::path::Path;

use crate::{audit, hostfs, netns, sandbox, spec, waf};

/// Runs the `run` sub-command. `spec_dir` is the `--spec-dir` value (if
/// given), `die_with_parent` the (negatable) PDEATHSIG flag, `new_session`
/// the (negatable) new-terminal-session flag, `require_spec` the
/// `--require-spec` strictness flag (see above), `command` the command to
/// execute inside the sandbox.
pub fn run(
    spec_dir: Option<&Path>,
    die_with_parent: bool,
    new_session: bool,
    require_spec: bool,
    mut command: Vec<String>,
) {
    if command.is_empty() {
        sandbox::die(
            "No command given; usage: ai-bubble run [--spec-dir DIR] -- COMMAND [args...]",
        );
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

    // In waf mode the sandbox has no real resolver configuration:
    // inject a virtual, in-memory `/etc/resolv.conf` pointing at
    // the in-sandbox DNS server (127.0.0.2, see `crate::waf`). The
    // mapping is appended last, so it wins over earlier mappings of
    // the same path (`hide` still wins over it — a hidden path is
    // invisible no matter what).
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

    // Resolve the cache mappings (`session-cache`,
    // `project-cache`) against their backing directories before
    // anything is compiled: the session-cache tmp directory is
    // created here and wiped once ai-bubble terminates (the
    // mirrored-fs server inherits the wipe).
    let spec_dir = spec_dir.unwrap_or(Path::new(spec::file::DEFAULT_SPEC_DIR));
    let session_cache = hostfs::session_cache_needed(spec.hostfs.has_session_caches());
    spec.hostfs
        .prepare_caches(spec_dir, session_cache.as_deref());

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
    audit::configure(
        sandbox_config.audit_log.clone(),
        spec_dir,
    );

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
        hostfs::start_host_fs(&sandbox_config.patterns);
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
