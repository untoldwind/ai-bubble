//! The spec file's `seccomp` section: the syscall filter applied to the
//! sandboxed command (see [`crate::sandbox`]).
//!
//! The filter is either an **allowlist** (`"allow"`: only the listed
//! syscalls may be executed) or a **blocklist** (`"block"`: the listed
//! syscalls are denied). Without a `preset`, giving both is a
//! deserialize error; giving neither disables the filter entirely (the
//! default — the sandbox then only relies on its namespace/capability
//! isolation).
//!
//! A **preset** (`"preset"`) selects one of the built-in blocklist
//! baselines instead of making the user write them out. Because
//! configuring seccomp well is rather complicated — knowing *which*
//! syscalls are dangerous and why is exactly the hard part — the preset
//! fills the blocklist, and the user only tweaks it from there:
//!
//! - `"block"` names additional syscalls to deny on top of the preset
//!   (it only ever makes the filter *stricter*);
//! - `"allow"` names **exceptions**: syscalls taken back out of the
//!   blocklist (it only ever makes the filter *more permissive*).
//!
//! With a preset, `allow` and `block` may therefore appear together —
//! they are no longer modes, just edits to the preset's blocklist. A
//! name that is in both is rejected at parse time (ambiguous: is it a
//! blocklist entry or an exception?).
//!
//! The presets and what they block (see [`Preset`]):
//!
//! - `"none"`: an empty baseline. Purely a mode switch: the filter
//!   becomes a blocklist that denies nothing (yet) — `block` and
//!   `allow` then edit an empty list.
//! - `"default"`: everything a sandboxed command should never need:
//!   kernel-code loading (`init_module`, `finit_module`, `delete_module`,
//!   `bpf`), kernel replacement (`kexec_load`, `kexec_file_load`),
//!   host-wide toggles (`reboot`, `acct`, `swapon`, `swapoff`), mount-table
//!   manipulation (`mount`, `umount2`, `pivot_root`, `open_tree`,
//!   `move_mount`, `fsmount`, `fspick`, `mount_setattr`), kernel-debugging and exploit-primitive
//!   surfaces (`userfaultfd`, `perf_event_open`, the `io_uring` family,
//!   `open_by_handle_at`), isolation escapes (`unshare`, `setns`),
//!   host-state tampering (`personality`, `pidfd_getfd`, `settimeofday`,
//!   `clock_settime`, `adjtimex`), keyring access (`add_key`, `keyctl`,
//!   `request_key`) and misc kernel interfaces (`quotactl`,
//!   `lookup_dcookie`), plus — on x86_64 only — the legacy x86
//!   privilege interfaces (`ioperm`, `iopl`, `modify_ldt`). See
//!   [`Preset::Default`] for the per-syscall rationale.
//! - `"strict"`: the `default` set plus the NUMA memory-policy and host
//!   identity syscalls (`mbind`, `set_mempolicy`, `move_pages`,
//!   `sethostname`, `setdomainname`) — see [`Preset::Strict`].
//!
//! Syscalls are named exactly like the kernel's syscall table entries
//! (e.g. `execve`, `openat`, `clone3`); the names are resolved to
//! syscall numbers when the spec is compiled (see
//! [`super::internal::SandboxConfig::compile`]), and an unknown name is
//! a hard error there.
//!
//! **Known limitation (the ia32 ABI).** The filter is a single-arch
//! program: seccompiler prepends an architecture check that kills
//! foreign-arch syscalls — that handles real 32-bit binaries. However, a
//! 64-bit process issuing `int $0x80` gets the *ia32 syscall table*
//! while the kernel still reports `AUDIT_ARCH_X86_64` (the task is not
//! marked compat): the arch check passes, but the numbers are the ia32
//! ones — e.g. ia32 `io_uring_setup` is 425, not the x86_64 number the
//! blocklist denies. A blocklist preset can therefore be bypassed via
//! `int 0x80` for syscalls whose ia32 numbers differ. Residual risk is
//! kernel attack-surface exposure (an LPE primitive), not an immediate
//! breakout: the capability/namespace isolation backstops the filter.
//! Kernels without `CONFIG_IA32_EMULATION` are unaffected; an allowlist
//! filter is largely unaffected too (the ia32 table's low numbers mostly
//! correspond to syscalls the allowlist also denies).
//!
//! **One exception is an immediate breakout, not surface exposure** (see
//! AUDIT.md H2): the socket gate installed for host-network mode (the
//! `net.host.unix_sockets`/`netlink`/`vsock`/`bluetooth` family flags,
//! all denied by default — AUDIT.md M3) relies on denying x86_64
//! `socket`/`socketpair`. ia32 `socketcall` is syscall **102**, which the
//! filter sees as x86_64 `getuid` — a syscall nothing can afford to deny.
//! `int $0x80; <ia32 socketcall>` therefore creates sockets in any gated
//! family in both blocklist and allowlist modes, and *no* seccomp rule can
//! close the hole: the arch check passes (the task reports
//! `AUDIT_ARCH_X86_64`) and the syscall *number* is genuinely ambiguous
//! between the two tables. On kernels with `CONFIG_IA32_EMULATION` (the
//! common distro default) the socket gate is best-effort only —
//! host-network mode must be treated as full local IPC for untrusted
//! commands; use proxy/waf mode instead.
//!
//! **Known limitation (the x32 ABI, same class).** The x32 ABI
//! (`CONFIG_X86_X32`) has the same shape: syscalls issued through it are
//! x86_64-table numbers ORed with `__X32_SYSCALL_BIT` (0x40000000) and
//! the kernel still reports `AUDIT_ARCH_X86_64`, so the arch check
//! passes and the filter's number-based rules simply do not recognize
//! the offset numbers — a blocklist preset can be bypassed via x32 for
//! syscalls whose plain numbers are denied. Like the ia32 case this is
//! kernel attack-surface exposure (not an immediate breakout), with the
//! same socket-gate caveat when the family gate relies on denying
//! specific x86_64 numbers. Kernels without `CONFIG_X86_X32` are
//! unaffected; the ABI is rare and disabled by default on most distros.

use std::sync::LazyLock;

use serde::Deserialize;

use schemars::JsonSchema;

/// What happens to a syscall the filter denies (the spec's
/// `on_violation` field, default `errno`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Violation {
    /// The denied syscall simply fails with `EPERM`. Lets the command
    /// observe (and perhaps work around) the restriction.
    #[default]
    Errno,
    /// The sandboxed process is killed with `SIGSYS` the moment it
    /// issues a denied syscall.
    Kill,
}

/// The built-in blocklist presets (the spec's `seccomp.preset` field).
///
/// A preset is a curated list of syscalls that a sandboxed command has
/// no business issuing — each entry is a known sandbox-escape vector,
/// a host-state manipulation, or an attack surface that is only ever
/// needed by the *host*, never by a process inside a sandbox. Writing
/// such a list from scratch is exactly the complicated part of
/// configuring seccomp, so the presets ship it; `block` and `allow`
/// adjust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// An **empty** baseline. The filter is still a blocklist — `block`
    /// and `allow` edit an empty list — but nothing is denied by the
    /// preset itself. Useful to start from scratch while keeping the
    /// blocklist mode (e.g. to later subtract exceptions from a `block`
    /// list rather than enumerate a whole allowlist).
    None,
    /// The **default** blocklist: the syscalls no sandboxed command
    /// should ever need, each of them a known danger in a sandbox:
    ///
    /// - `init_module`, `finit_module`, `delete_module`: load and
    ///   unload **kernel code**. Loading a module is unconditional
    ///   compromise of the host — nothing inside a sandbox ever needs it.
    /// - `kexec_load`, `kexec_file_load`: replace the **running kernel**
    ///   with another image. The ultimate host takeover primitive.
    /// - `reboot`, `acct`: host-wide state changes. `reboot` is self-
    ///   explanatory; `acct` turns on kernel process accounting into an
    ///   arbitrary file (host disk fill, and a window into every other
    ///   process on the host).
    /// - `swapon`, `swapoff`: add/remove swap devices. Swapping host
    ///   memory into a sandbox-controlled file would leak other
    ///   processes' memory contents.
    /// - `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`,
    ///   `fsmount`, `fspick`, `mount_setattr`: the mount table is part
    ///   of the sandbox's isolation — rearranging it (detach what it is
    ///   confined to, re-mount something over a sensitive path, change
    ///   mount propagation to make host mounts appear) is a classic
    ///   escape vector. Both the classic interface (`mount`, `umount2`)
    ///   and the new mount-API syscalls are blocked. All sandbox mounts
    ///   are set up *before* the filter is installed, so the command
    ///   never needs these.
    /// - `userfaultfd`: user-space page-fault handling. Its fine-grained
    ///   control over fault timing is a staple of kernel use-after-free
    ///   exploits (it reliably widens race windows), and it is a
    ///   recognized sandbox-escape primitive.
    /// - `bpf`: load and inspect eBPF programs. In the presence of
    ///   historic verifier bugs this is kernel code execution; even
    ///   without capabilities it leaks kernel internals (KASLR) and
    ///   other-process data.
    /// - `perf_event_open`: the kernel profiling interface — historically
    ///   rich in CVEs, a well-known side-channel (and thus KASLR/secret-
    ///   leak) source, and a reconnaissance tool against other processes.
    /// - `io_uring_setup`, `io_uring_enter`, `io_uring_register`: a huge,
    ///   fast-moving, hard-to-audit kernel subsystem that bypasses the
    ///   usual syscall path; a disproportionate share of recent kernel
    ///   LPEs and sandbox escapes involve it (major sandboxes such as
    ///   Docker and gVisor block it by default for exactly this reason).
    ///   Nothing a sandboxed build/test command does needs it.
    /// - `open_by_handle_at`: open a file **by inode handle**, skipping
    ///   the path-based permission checks the FUSE mirror's policy is
    ///   built on. With `CAP_DAC_READ_SEARCH` this is the classic
    ///   "Shocker"-style escape; without it there is still no reason to
    ///   allow an interface designed to bypass path checks.
    /// - `unshare`, `setns`: create or join namespaces. The sandbox's
    ///   isolation rests on the namespaces it sets up before exec;
    ///   letting the command create new ones (unprivileged user/mount
    ///   namespaces) or join others mid-flight undermines exactly that.
    /// - `personality`: change the execution domain — notably disable
    ///   ASLR (`ADDR_NO_RANDOMIZE`) and select alternate syscall
    ///   behaviors, both useful for exploitation and none needed by a
    ///   normal command.
    /// - `pidfd_getfd`: steal a **file descriptor from another process**
    ///   in the sandbox (its files, sockets, pipes) purely by PID —
    ///   lateral movement between the sandbox's processes. (`ptrace` and
    ///   `process_vm_readv/writev` are strictly stronger within the
    ///   sandbox — they read and *write* another process's memory — but
    ///   are deliberately not preset-blocked: they are legitimate tools
    ///   (debuggers) that real workloads need, and everything they can
    ///   reach is already confined inside the sandbox. `pidfd_getfd` has
    ///   no such legitimate use and additionally reaches descriptors of
    ///   processes outside any pid-ns-confined group, so it is denied
    ///   while `ptrace` stays a command choice.)
    /// - `settimeofday`, `clock_settime`, `adjtimex`: the kernel clock is
    ///   shared with the host; changing it falsifies the host's time and
    ///   every audit/log timestamp on the machine.
    /// - `add_key`, `keyctl`, `request_key`: the kernel **keyring**.
    ///   Keys persist in the host session across sandbox runs — both a
    ///   cross-sandbox data channel and a way to poison host lookups.
    /// - `quotactl`: manipulate disk quotas of host filesystems (and
    ///   learn host usage numbers the sandbox has no business seeing).
    /// - `lookup_dcookie`: a kernel-profiling cookie lookup that only
    ///   profiling daemons on the host ever need (and that requires
    ///   capabilities anyway).
    /// - `ioperm`, `iopl`, `modify_ldt` (x86_64 only): the legacy x86
    ///   privilege interfaces. `ioperm`/`iopl` grant user space direct
    ///   **I/O port access** — raw hardware I/O that by bypasses every
    ///   driver, with arbitrary host device access; `modify_ldt` writes
    ///   the local descriptor table, a classic exploit primitive (its
    ///   grant-on-use handling has shipped multiple kernel CVEs, and it
    ///   historically bypassed seccomp's own checks). The syscalls only
    ///   exist on x86_64, so they are blocked only there.
    Default,
    /// The `default` blocklist plus the **NUMA memory policy** and
    /// **host identity** syscalls, for environments that want the extra
    /// margin:
    ///
    /// - `mbind`, `set_mempolicy`, `move_pages`: NUMA memory policy is
    ///   shared kernel state; a sandboxed process can degrade host
    ///   memory placement for every other workload (DoS), and
    ///   `move_pages` is a documented physical-memory probing oracle
    ///   (side-channel reconnaissance).
    /// - `sethostname`, `setdomainname`: rename the machine. When the
    ///   UTS namespace is not isolated (e.g. in hostfs-root or `net:
    ///   host` setups) this renames it *for the host* too, corrupting
    ///   the identity other programs and logs rely on.
    Strict,
}

/// The syscalls every preset shares as its baseline (the `default`
/// preset's list, which `strict` extends).
const DEFAULT_SYSCALLS: &[&str] = &[
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    "reboot",
    "acct",
    "swapon",
    "swapoff",
    // The mount interface, classic and new: rearranging the mount table
    // is the classic sandbox escape (see `Preset::Default`).
    "mount",
    "umount2",
    "pivot_root",
    "open_tree",
    "move_mount",
    "fsmount",
    "fspick",
    "mount_setattr",
    "userfaultfd",
    "bpf",
    "perf_event_open",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "open_by_handle_at",
    "unshare",
    "setns",
    "personality",
    "pidfd_getfd",
    "settimeofday",
    "clock_settime",
    "adjtimex",
    "add_key",
    "keyctl",
    "request_key",
    "quotactl",
    "lookup_dcookie",
];

/// The x86_64-only syscalls [`DEFAULT_SYSCALLS`] gains on that
/// architecture (see [`Preset::Default`]). The names are only real
/// kernel syscall table entries on x86_64 — the `syscalls` crate's
/// per-target resolution would reject them anywhere else — so the
/// table is gated, exactly like the syscall surface itself.
#[cfg(target_arch = "x86_64")]
const X86_64_SYSCALLS: &[&str] = &["ioperm", "iopl", "modify_ldt"];

/// What `strict` adds on top of [`DEFAULT_SYSCALLS`] (see
/// [`Preset::Strict`]).
const STRICT_EXTRA_SYSCALLS: &[&str] = &[
    "mbind",
    "set_mempolicy",
    "move_pages",
    "sethostname",
    "setdomainname",
];

/// The `default` preset's full list: [`DEFAULT_SYSCALLS`] extended by
/// the architecture-specific tables (see [`X86_64_SYSCALLS`]; composed
/// once, on first use).
static DEFAULT_ALL: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    #[cfg(target_arch = "x86_64")]
    let arch_extra: &[&str] = X86_64_SYSCALLS;
    #[cfg(not(target_arch = "x86_64"))]
    let arch_extra: &[&str] = &[];
    DEFAULT_SYSCALLS
        .iter()
        .copied()
        .chain(arch_extra.iter().copied())
        .collect()
});

/// The `strict` preset's full list: [`DEFAULT_SYSCALLS`] extended by
/// [`STRICT_EXTRA_SYSCALLS`] (composed once, on first use).
static STRICT_SYSCALLS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    DEFAULT_ALL
        .iter()
        .copied()
        .chain(STRICT_EXTRA_SYSCALLS.iter().copied())
        .collect()
});

impl Preset {
    /// The syscall names the preset blocks, as kernel syscall table
    /// entries (resolved to numbers when the spec is compiled).
    pub fn syscalls(&self) -> &'static [&'static str] {
        match self {
            Preset::None => &[],
            Preset::Default => &DEFAULT_ALL,
            Preset::Strict => &STRICT_SYSCALLS,
        }
    }
}

/// The spec file's `seccomp` section (see the module docs).
///
/// The custom `Deserialize` impl (backed by a derived internal struct)
/// enforces the mutual exclusions at parse time, so a contradictory
/// spec is rejected like any other spec error: without a `preset`,
/// `allow` and `block` are mutually exclusive; with one, a name in both
/// is ambiguous and rejected.
#[derive(Debug, Default, PartialEq, JsonSchema)]
pub struct SeccompConfig {
    /// The built-in blocklist baseline (see [`Preset`]). When present,
    /// the filter is a blocklist seeded by the preset: `block` adds
    /// entries to it, `allow` takes exceptions back out. Absent, the
    /// section is a plain allowlist (`allow`) or blocklist (`block`).
    pub preset: Option<Preset>,
    /// Syscall allowlist: when present (without a `preset`), *only*
    /// these syscalls may be executed by the sandboxed command
    /// (everything else is denied per `on_violation`). An allowlist must
    /// be complete — including `execve`, `exit_group`, `mmap` and
    /// friends — or the command cannot run at all.
    ///
    /// With a `preset`, this is instead the list of **exceptions**:
    /// syscalls taken back out of the preset's blocklist.
    pub allow: Option<Vec<String>>,
    /// Syscall blocklist: when present, exactly these syscalls are
    /// denied; everything else stays allowed. Useful to forbid specific
    /// dangerous entry points (`ptrace`, `mount`, `keyctl`, `bpf`, ...)
    /// without enumerating the whole syscall surface.
    ///
    /// With a `preset`, these are **added** to the preset's blocklist.
    pub block: Option<Vec<String>>,
    /// What happens to a denied syscall (see [`Violation`]).
    pub on_violation: Violation,
}

impl<'de> Deserialize<'de> for SeccompConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The derived shape: same fields, same defaults, same
        // unknown-field rejection as every other spec section.
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Raw {
            preset: Option<Preset>,
            allow: Option<Vec<String>>,
            block: Option<Vec<String>>,
            on_violation: Violation,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.preset.is_none() && raw.allow.is_some() && raw.block.is_some() {
            return Err(serde::de::Error::custom(
                "the seccomp section accepts either \"allow\" or \"block\", not both \
                 (with a \"preset\" both are allowed: \"block\" adds to it, \
                 \"allow\" takes exceptions back out)",
            ));
        }
        // With a preset both lists may be present — but a name in both
        // is ambiguous: is it a blocklist entry or an exception?
        if let (Some(allow), Some(block)) = (&raw.allow, &raw.block) {
            for name in allow {
                if block.contains(name) {
                    return Err(serde::de::Error::custom(format!(
                        "the seccomp section lists syscall {name:?} in both \"allow\" \
                         and \"block\" — a name cannot be an exception and a denial \
                         at the same time"
                    )));
                }
            }
        }
        Ok(SeccompConfig {
            preset: raw.preset,
            allow: raw.allow,
            block: raw.block,
            on_violation: raw.on_violation,
        })
    }
}

impl SeccompConfig {
    /// Whether the section configures a filter at all. A preset counts
    /// as configured (even `"none"`, whose blocklist is empty), as does
    /// naming either of `allow` and `block`.
    pub fn is_configured(&self) -> bool {
        self.preset.is_some() || self.allow.is_some() || self.block.is_some()
    }

    /// The syscall names the filter effectively names, and whether the
    /// filter is an allowlist. With a preset the filter is always a
    /// blocklist: the preset baseline plus the `block` entries, minus
    /// the `allow` exceptions (the parse-time checks guarantee `allow`
    /// and `block` never name the same syscall). Without, it is exactly
    /// whatever the single present list says.
    pub(crate) fn resolved(&self) -> (Vec<String>, bool) {
        if let Some(preset) = self.preset {
            let mut names: Vec<String> = preset
                .syscalls()
                .iter()
                .map(|name| (*name).to_string())
                .collect();
            if let Some(allow) = &self.allow {
                names.retain(|name| !allow.contains(name));
            }
            if let Some(block) = &self.block {
                names.extend(block.iter().cloned());
            }
            (names, false)
        } else {
            match (&self.allow, &self.block) {
                (Some(allow), _) => (allow.clone(), true),
                (None, Some(block)) => (block.clone(), false),
                // Not configured — `compile` never gets here.
                (None, None) => (vec![], false),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Preset;
    use super::SeccompConfig;
    use crate::spec::tests::parse;

    #[test]
    fn seccomp_section_is_parsed() {
        let spec =
            parse(r#"{ "seccomp": { "block": ["ptrace", "mount"], "on_violation": "kill" } }"#);
        assert_eq!(
            spec.seccomp,
            SeccompConfig {
                preset: None,
                allow: None,
                block: Some(vec!["ptrace".to_string(), "mount".to_string()]),
                on_violation: super::Violation::Kill,
            }
        );
        assert!(spec.seccomp.is_configured());
    }

    #[test]
    fn seccomp_defaults_to_no_filter_and_errno() {
        // Without a seccomp section the sandbox installs no filter.
        let spec = parse("{}");
        assert!(!spec.seccomp.is_configured());
        // A section with only on_violation is legal but inert.
        let spec = parse(r#"{ "seccomp": { "on_violation": "kill" } }"#);
        assert!(!spec.seccomp.is_configured());
        assert_eq!(spec.seccomp.on_violation, super::Violation::Kill);
        // The default violation action is errno.
        let spec = parse(r#"{ "seccomp": { "allow": ["read"] } }"#);
        assert_eq!(spec.seccomp.on_violation, super::Violation::Errno);
    }

    #[test]
    fn seccomp_allow_and_block_are_mutually_exclusive() {
        assert!(
            crate::spec::tests::parse_err(
                r#"{ "seccomp": { "allow": ["read"], "block": ["ptrace"] } }"#
            )
            .is_some()
        );
    }

    #[test]
    fn seccomp_unknown_fields_are_rejected() {
        assert!(
            crate::spec::tests::parse_err(r#"{ "seccomp": { "deny": ["ptrace"] } }"#).is_some()
        );
    }

    #[test]
    fn seccomp_preset_is_parsed() {
        for (json, expected) in [
            ("none", Preset::None),
            ("default", Preset::Default),
            ("strict", Preset::Strict),
        ] {
            let spec = parse(&format!(r#"{{ "seccomp": {{ "preset": "{json}" }} }}"#));
            assert_eq!(spec.seccomp.preset, Some(expected));
            // A preset alone is a (possibly empty) blocklist filter.
            assert!(spec.seccomp.is_configured());
        }
        // Unknown presets are spec errors.
        assert!(
            crate::spec::tests::parse_err(r#"{ "seccomp": { "preset": "paranoid" } }"#).is_some()
        );
    }

    #[test]
    fn seccomp_preset_strict_includes_default() {
        // Every default syscall is also blocked by the strict preset.
        for name in Preset::Default.syscalls() {
            assert!(
                Preset::Strict.syscalls().contains(name),
                "strict does not include {name}"
            );
        }
    }

    #[test]
    fn seccomp_preset_block_adds_and_allow_takes_back() {
        let spec = parse(
            r#"{ "seccomp": { "preset": "default", "block": ["ptrace"],
                                "allow": ["bpf", "unshare"] } }"#,
        );
        let (names, allowlist) = spec.seccomp.resolved();
        assert!(!allowlist);
        // The whole default baseline is there (minus the exceptions) ...
        for name in Preset::Default.syscalls() {
            if *name == "bpf" || *name == "unshare" {
                assert!(
                    !names.contains(&name.to_string()),
                    "{name} not taken back out"
                );
            } else {
                assert!(names.contains(&name.to_string()), "{name} missing");
            }
        }
        // ... plus the extra block entry ...
        assert!(names.contains(&"ptrace".to_string()));
        // ... and nothing else.
        assert_eq!(names.len(), Preset::Default.syscalls().len() - 2 + 1);
    }

    #[test]
    fn seccomp_preset_allow_and_block_may_coexist() {
        // With a preset, allow and block are no longer mutually
        // exclusive — they edit the blocklist from both directions.
        let spec = parse(
            r#"{ "seccomp": { "preset": "strict", "block": ["keyctl"],
                                "allow": ["io_uring_setup"] } }"#,
        );
        let (names, allowlist) = spec.seccomp.resolved();
        assert!(!allowlist);
        assert!(names.contains(&"keyctl".to_string()));
        assert!(!names.contains(&"io_uring_setup".to_string()));
        assert!(names.contains(&"set_mempolicy".to_string()));
    }

    #[test]
    fn seccomp_preset_allow_and_block_overlap_is_rejected() {
        assert!(
            crate::spec::tests::parse_err(
                r#"{ "seccomp": { "preset": "default", "allow": ["bpf"], "block": ["bpf"] } }"#
            )
            .is_some()
        );
    }

    #[test]
    fn seccomp_preset_syscall_names_resolve() {
        // Every preset entry must be a real kernel syscall name, so a
        // typo in the preset tables fails here rather than only when a
        // spec using the preset is compiled.
        use std::str::FromStr;
        for preset in [Preset::None, Preset::Default, Preset::Strict] {
            for name in preset.syscalls() {
                assert!(
                    syscalls::Sysno::from_str(name).is_ok(),
                    "preset {preset:?} names unknown syscall {name:?}"
                );
            }
        }
    }

    #[test]
    fn seccomp_preset_none_yields_an_empty_blocklist() {
        let spec = parse(r#"{ "seccomp": { "preset": "none" } }"#);
        let (names, allowlist) = spec.seccomp.resolved();
        assert!(names.is_empty());
        assert!(!allowlist);
        // And allow/block edit that empty baseline.
        let spec = parse(r#"{ "seccomp": { "preset": "none", "block": ["ptrace"] } }"#);
        let (names, _) = spec.seccomp.resolved();
        assert_eq!(names, vec!["ptrace".to_string()]);
    }
}
