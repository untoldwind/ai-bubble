//! The private pty ("pty mode"): full controlling-terminal functionality
//! inside the sandbox, without exposing the caller's terminal device.
//!
//! New-terminal-session (`--new-session`, the `run` default) detaches the
//! command from the caller's terminal for *security* (no `TIOCSTI` escape,
//! no host pts bind), but interactive programs then find no controlling
//! tty: bash prints "no job control", `su` refuses, readline degrades.
//! `--no-new-session` fixes that by re-exposing the host terminal device —
//! exactly what new-session was introduced to prevent.
//!
//! Pty mode is the third option, and the automatic default whenever
//! new-session is requested *and* the caller's stdin/stdout are both
//! terminals (see [`wanted`]):
//!
//! 1. The launcher creates a fresh pty pair *before* the sandbox forks.
//!    The slave is a device the launcher itself allocated — never the
//!    user's terminal.
//! 2. The launcher-side parent process (the one that also waitpid()s for
//!    the sandboxed command) becomes the relay: it copies bytes between
//!    its own stdio (the user's terminal) and the pty **master**, the way
//!    `script(1)` does. The user's tty is put into raw mode for the
//!    duration, so its line discipline stops editing/echoing — the pty
//!    slave's line discipline takes over both jobs for the command.
//! 3. The sandboxed child keeps the slave fd as fds 0/1/2, and — after
//!    `setsid()`, which makes it a session leader — claims the slave as
//!    its controlling terminal with `TIOCSCTTY`.
//!
//! The security properties of new-session are preserved exactly: the
//! command's controlling tty is the *private* pty, so `TIOCSTI` on fds
//! 0/2 can only push keystrokes into the pty (which the relay reads and
//! discards as ordinary output), `/dev/tty` resolves to the private pty,
//! and the host pts device is never mounted. Only the master fd — a
//! plain byte pipe in effect — crosses the trust boundary, and it is
//! held exclusively by the relay.
//!
//! Because the slave's line discipline is a real one, job control works
//! end to end: ^C is forwarded as a byte by the relay (the user's tty is
//! raw, so it generates no host-side SIGINT), the pty line discipline
//! turns it into SIGINT for the sandbox's foreground process group, and
//! `tcsetpgrp`/`SIGTTOU` inside the sandbox behave normally. Window
//! resizes are relayed the same way (`TIOCGWINSZ` on the user's tty →
//! `TIOCSWINSZ` on the master, which raises SIGWINCH inside the sandbox).
//!
//! Inside the sandbox the slave's host path (its `/dev/pts/N` on the
//! *host* devpts instance) is bind-mounted as `/dev/console` so that
//! `ttyname(0)`-style paths resolve; `/dev/tty` is provided too, because
//! the command's controlling terminal is now the private pty. The fresh
//! `devpts` instance on `/dev/pts` (see `mount_and_exec`) is unchanged.
//!
//! Accepted residual (AUDIT.md L3): the relay copies the command's output
//! to the user's terminal **verbatim** — terminal escape sequences pass
//! through unfiltered, exactly like `ssh` to an untrusted host or
//! `script(1)`. OSC 52 clipboard writes, title/palette changes and any
//! terminal-emulator escape-parsing weaknesses are therefore reachable
//! from untrusted command output (in pty mode and in plain new-session
//! runs with a tty on stdout alike). The TIOCSTI analysis above is
//! unaffected.
//!
//! Accepted residual (SB-14, same class as `script(1)`): the relay's
//! fds 0/1 are blocking, so a user pressing `^S` (flow stop) on the
//! terminal blocks the relay — including the forwarding of fatal
//! signals, which resumes when the terminal is unfrozen (`^Q`). The
//! command sees the same behavior under `script(1)`; a non-blocking
//! relay would instead need a write-buffer implementation.
//!
//! The relay is also transparent **towards the command**: it is a plain
//! bidirectional byte pipe, so a command can issue terminal *queries*
//! (DA, XTGETTCAP, palette/cursor reports) and **receive the real
//! terminal's replies** — the user's terminal answers its stdin, the relay
//! forwards the bytes to the pty. A reply arriving after the relay exits
//! can even land in the user's shell input buffer. This is the same
//! exposure class as `ssh`/`script(1)` (which cannot distinguish a
//! legitimate keystroke from a query reply either) and is documented
//! rather than filtered: query replies cannot be told apart from real
//! keyboard input at the byte level.

use std::process::exit;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::sandbox::{die_with_error, exit_with_status};

/// Should pty mode be used for this run? Only when a new terminal session
/// was requested *and* the command would actually talk to a terminal:
/// both stdin and stdout are ttys (stderr may be a separate tty or a
/// redirected file either way). With pipes on stdin or stdout — build
/// scripts, CI, test harnesses — the plain new-session behaviour is kept,
/// since the relay has no terminal to mirror and the pty would only get
/// in the way of programs that check `isatty` to decide on colours etc.
pub(crate) fn wanted(new_session: bool) -> bool {
    unsafe { new_session && libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}

/// A freshly allocated pty pair, created by the launcher before the
/// sandboxed command is forked.
pub(crate) struct Pty {
    /// Launcher side: the relay's end. Held only by the relay parent.
    master: i32,
    /// Sandbox side: becomes fds 0/1/2 and the controlling terminal.
    slave: i32,
    /// Host path of the slave (`/dev/pts/N`), for the sandbox's
    /// `/dev/console` bind (see the module docs).
    pub(crate) slave_path: String,
}

/// Allocate a fresh pty pair (`posix_openpt`, `grantpt`, `unlockpt`).
/// Both ends are close-on-exec: the launcher's exec paths never leak
/// them, and the sandboxed child keeps only the dup2'd copies on fds
/// 0/1/2 (dup2 clears the flag on the target).
pub(crate) unsafe fn open() -> Pty {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master < 0 {
            die_with_error("Can't allocate a pseudo-terminal");
        }
        if libc::grantpt(master) != 0 {
            die_with_error("Can't grant the pseudo-terminal");
        }
        if libc::unlockpt(master) != 0 {
            die_with_error("Can't unlock the pseudo-terminal");
        }
        let mut buf = [0 as libc::c_char; 128];
        if libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) != 0 {
            die_with_error("Can't determine the pseudo-terminal slave path");
        }
        let path = std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned();
        // The slave path must be passed to open(2) as a proper C string:
        // a `String`'s `as_ptr()` is not NUL-terminated, and `open` would
        // read past the end of it (heap-layout-dependent ENOENT — the bug
        // that only fired for some specs' allocation patterns).
        let path_c = match std::ffi::CString::new(path.clone()) {
            Ok(c) => c,
            Err(_) => die_with_error("Can't open the pseudo-terminal slave: NUL in the path"),
        };
        let slave = libc::open(
            path_c.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if slave < 0 {
            die_with_error(&format!("Can't open the pseudo-terminal slave {path}"));
        }
        Pty {
            master,
            slave,
            slave_path: path,
        }
    }
}

/// Close the slave in the parent (relay) process: only the child keeps
/// the slave side across the fork. The slave must be closed here before
/// the relay starts, or an open slave would keep the master readable
/// forever (never EOF) and mask the child's exit.
pub(crate) unsafe fn close_slave(pty: &Pty) {
    unsafe {
        libc::close(pty.slave);
    }
}

/// Sandbox-side setup, run by the freshly forked PID-1 child before the
/// mount/exec machinery: make the pty slave the command's stdio and its
/// controlling terminal.
///
/// Unlike `sandbox::new_terminal_session`, `setsid()` is followed by
/// `TIOCSCTTY`: the child is a fresh session leader and nobody else holds
/// this pty, so claiming it never needs to "steal" it. From here on the
/// command has a fully functional controlling terminal — the private pty.
pub(crate) unsafe fn child_attach(pty: &Pty, stderr_is_tty: bool) {
    unsafe {
        libc::dup2(pty.slave, 0);
        libc::dup2(pty.slave, 1);
        if stderr_is_tty {
            libc::dup2(pty.slave, 2);
        }
        // The child must hold neither end beyond the dup2s: the original
        // slave fd is redundant, and the master belongs to the relay.
        libc::close(pty.master);
        if libc::setsid() < 0 {
            die_with_error("Can't start a new terminal session");
        }
        // Claim the controlling terminal while the original slave fd is
        // still open (fd 0 is a dup of it and works just as well, but the
        // original keeps the ioctl unambiguous).
        if libc::ioctl(pty.slave, libc::TIOCSCTTY, 0 as libc::c_int) < 0 {
            die_with_error("Can't make the pseudo-terminal the controlling terminal");
        }
        libc::close(pty.slave);
    }
}

/// How the relay ended: the pty closed (command gone from the terminal —
/// normal end) or a fatal signal arrived (forwarded to the command).
enum RelayEnd {
    MasterClosed,
    Signal(i32),
}

/// The signal the self-pipe tells the relay loop about: b'W' for window
/// resizes, otherwise the (fatal) signal number itself. All fatal signals
/// are < 31, so the two can never collide with b'W' (0x57).
const WINCH_BYTE: u8 = b'W';

/// fd of the self-pipe write end, for the signal handlers (async-signal
/// safe `write` only).
static PIPE_W: AtomicI32 = AtomicI32::new(-1);
/// First fatal signal not yet consumed by the relay loop.
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// The user's terminal attributes as they were before the relay switched
/// them to raw mode. Kept in a global so the restore can also happen on
/// `die` paths (AUDIT.md L5): after `tcsetattr(raw)` succeeded, any
/// `die_with_error` (pipe creation, signal-handler installation, a `poll`
/// failure in the relay) would otherwise `exit(1)` with the terminal left
/// in raw mode — no echo, no line editing. The `atexit` hook below runs
/// on every `std::process::exit`, which is how all `die` paths leave.
static SAVED_TERMIOS: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

/// `atexit` hook: put the user's terminal back the way it was. Runs on
/// every normal (non-`SIGKILL`) exit of the process — including all
/// `die` paths — and is idempotent (the relay epilogue restores the
/// terminal too; applying the same saved attributes twice is harmless).
extern "C" fn restore_tty_atexit() {
    if let Ok(saved) = SAVED_TERMIOS.lock()
        && let Some(saved) = saved.as_ref()
    {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, saved);
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    unsafe {
        let w = PIPE_W.load(Ordering::Relaxed);
        if w < 0 {
            // AUDIT.md L5: before (or after) the self-pipe is installed
            // the handler must not silently swallow a fatal signal. With
            // the pipe gone, restore the default action and re-raise:
            // the signal kills (or otherwise defaults) this process the
            // way it would without the relay handler. Both syscalls are
            // async-signal-safe. SIGWINCH's default disposition is to
            // do nothing harmful — just return.
            if sig != libc::SIGWINCH {
                let dfl: libc::sigaction = std::mem::zeroed();
                libc::sigaction(sig, &dfl, std::ptr::null_mut());
                libc::kill(libc::getpid(), sig);
            }
            return;
        }
        if sig == libc::SIGWINCH {
            let byte = WINCH_BYTE;
            libc::write(w, &byte as *const u8 as *const libc::c_void, 1);
        } else {
            // Only the first pending fatal signal matters: the relay
            // forwards it and exits.
            let _ = PENDING_SIGNAL.compare_exchange(0, sig, Ordering::Relaxed, Ordering::Relaxed);
            let byte = sig as u8;
            libc::write(w, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

/// The launcher-side half of pty mode, run by the process that also
/// waitpid()s for the sandboxed command (in `pidns_and_exec`): put the
/// user's terminal into raw mode, relay stdio ⇄ pty master until the pty
/// closes or a fatal signal arrives, then restore the terminal.
///
/// `MasterClosed` returns to the caller, which reaps the command as
/// usual; `Signal` exits here with `128+sig`, after killing and reaping
/// the command with the same signal.
pub(crate) unsafe fn parent_relay(pty: &Pty, child_pid: libc::pid_t) {
    unsafe {
        // Raw mode on the *user's* terminal: its line discipline stops
        // echoing and editing, so every keystroke (including ^C and ^Z)
        // reaches the relay as a plain byte and is forwarded to the pty,
        // where the slave's line discipline takes over signal generation
        // and echo for the sandboxed command. This is what makes full
        // job control work end to end.
        let mut saved: libc::termios = std::mem::zeroed();
        let have_termios = libc::tcgetattr(0, &mut saved) == 0;
        if have_termios {
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                die_with_error("Can't switch the terminal to raw mode");
            }
            // From here on every `die` path must restore the terminal:
            // register the `atexit` hook (it runs on `std::process::exit`,
            // which is how every `die_with_error` leaves) *after* raw mode
            // is live (AUDIT.md L5).
            *SAVED_TERMIOS.lock().unwrap() = Some(saved);
            if libc::atexit(restore_tty_atexit) != 0 {
                die_with_error("Can't register the terminal restore hook");
            }
            // Start with the terminal's current window size; resizes are
            // relayed while the command runs (see the relay loop).
            forward_winsize(pty.master);
        }

        // Self-pipe for the relay loop: SIGWINCH resizes and fatal
        // signals arrive as bytes in an async-signal-safe write().
        let mut pipefd = [-1 as libc::c_int; 2];
        if libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
            die_with_error("Can't create the terminal relay pipe");
        }
        let (pipe_r, pipe_w) = (pipefd[0], pipefd[1]);
        PIPE_W.store(pipe_w, Ordering::Relaxed);
        let handler = on_signal as extern "C" fn(libc::c_int);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_RESTART;
        for sig in [
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGWINCH,
        ] {
            if libc::sigaction(sig, &action, std::ptr::null_mut()) != 0 {
                die_with_error("Can't install the terminal relay signal handler");
            }
        }

        let end = relay(pty, pipe_r);

        // Restore the user's terminal on every path out of the relay.
        // (Only a SIGKILL to this process — the PDEATHSIG chain — can
        // skip this, exactly like script(1); `reset` fixes the terminal.)
        // The terminal is restored *before* the relay handler is
        // disarmed (AUDIT.md L5): with `PIPE_W` still set, a signal in
        // this window is recorded in `PENDING_SIGNAL` and delivered below;
        // nothing is swallowed.
        if have_termios {
            libc::tcsetattr(0, libc::TCSANOW, &saved);
        }
        // AUDIT.md L2: the relay's custom handlers are never restored
        // today, which breaks the epilogue below twice over. On the
        // `RelayEnd::Signal` path the forwarded signal is dropped by the
        // kernel when the command is PID 1 of its PID namespace and has no
        // handler for it (the kernel silently discards non-
        // SIGKILL/SIGSTOP signals for a pidns init) — so the bare waitpid
        // loop can wait indefinitely; and because the leftover relay
        // handler swallows ^C (writing into a closed pipe), the operator
        // cannot even interrupt the wait. Restore SIG_DFL for all five
        // signals before the waitpid loop: ^C/^\/termination kill this
        // process (the script(1) behaviour), SIGWINCH returns to its
        // default-ignore, and the waitpid is interruptible again.
        let default_action: libc::sigaction = std::mem::zeroed();
        for sig in [
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGWINCH,
        ] {
            if libc::sigaction(sig, &default_action, std::ptr::null_mut()) != 0 {
                die_with_error("Can't restore the default signal handlers");
            }
        }
        let _ = libc::close(pipe_r);
        let _ = libc::close(pipe_w);

        // Disarm the self-pipe only after the handlers are back to their
        // defaults: a signal from here on takes the default action
        // directly, and `PIPE_W = -1` makes the handler's fallback
        // (SIG_DFL + re-raise) cover any window that remains.
        PIPE_W.store(-1, Ordering::Relaxed);

        // AUDIT.md L5: a fatal signal that arrived while the relay handler
        // was still installed (after the loop, during the restore above)
        // was recorded but never acted on — deliver it now, under the
        // default dispositions just restored.
        let pending = PENDING_SIGNAL.swap(0, Ordering::Relaxed);
        if pending != 0 {
            libc::kill(libc::getpid(), pending);
        }

        match end {
            RelayEnd::MasterClosed => {} // fall through: reap the command
            RelayEnd::Signal(sig) => {
                // Forward the fatal signal to the command (PID 1 of the
                // sandbox; bash and most shells handle SIGINT/SIGTERM),
                // reap it, and mirror the fate to our own exit status.
                libc::kill(child_pid, sig);
                let mut status: libc::c_int = 0;
                loop {
                    let r = libc::waitpid(child_pid, &mut status, 0);
                    if r == child_pid {
                        exit_with_status(status);
                    }
                    if r < 0 && io_err() != libc::EINTR {
                        exit(128 + sig);
                    }
                }
            }
        }
    }
}

fn io_err() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Copy the user's terminal window size to the pty (master → slave side,
/// which raises SIGWINCH for the sandbox's foreground process group when
/// the size changed).
unsafe fn forward_winsize(master: i32) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(master, libc::TIOCSWINSZ, &ws);
        }
    }
}

/// The relay loop: bidirectional byte copy between the user's terminal
/// (fds 0/1) and the pty master, with `poll(2)` readiness and small
/// pending buffers for each direction (a tty is only writable when its
/// peer drains, so writes can partially complete — the buffers keep the
/// loop non-blocking in both directions). The fds stay in blocking mode:
/// `poll` is only ever trusted for reads here, and write bursts are
/// bounded by the 4 KiB chunks, matching what `script(1)` does.
unsafe fn relay(pty: &Pty, pipe_r: i32) -> RelayEnd {
    unsafe {
        let master = pty.master;
        // Pending bytes: user's tty → master, and master → user's stdout.
        let mut to_master: Vec<u8> = Vec::new();
        let mut to_stdout: Vec<u8> = Vec::new();
        let mut stdin_open = true;
        let mut chunk = [0u8; 4096];

        loop {
            let mut fds = [
                libc::pollfd {
                    fd: 0,
                    events: if stdin_open && to_master.is_empty() {
                        libc::POLLIN
                    } else {
                        0
                    },
                    revents: 0,
                },
                libc::pollfd {
                    fd: 1,
                    events: if !to_stdout.is_empty() {
                        libc::POLLOUT
                    } else {
                        0
                    },
                    revents: 0,
                },
                libc::pollfd {
                    fd: master,
                    events: libc::POLLIN
                        | if to_master.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                    revents: 0,
                },
                libc::pollfd {
                    fd: pipe_r,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let n = libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1);
            if n < 0 {
                if io_err() == libc::EINTR {
                    continue;
                }
                die_with_error("Can't poll the terminal relay");
            }

            // Signals: window resizes are forwarded; a fatal signal ends
            // the relay (the caller restores the terminal, kills and
            // reaps the command, and exits with 128+sig).
            if fds[3].revents & libc::POLLIN != 0 {
                let mut sig_bytes = [0u8; 32];
                let got = libc::read(
                    pipe_r,
                    sig_bytes.as_mut_ptr() as *mut libc::c_void,
                    sig_bytes.len(),
                );
                if got > 0 {
                    if sig_bytes[..got as usize].contains(&WINCH_BYTE) {
                        forward_winsize(master);
                    }
                    let sig = PENDING_SIGNAL.swap(0, Ordering::Relaxed);
                    if sig != 0 {
                        return RelayEnd::Signal(sig);
                    }
                }
            }

            // user's tty → master
            if fds[0].revents & libc::POLLIN != 0 {
                let r = libc::read(0, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
                if r > 0 {
                    to_master.extend_from_slice(&chunk[..r as usize]);
                } else if r == 0 {
                    // The user's terminal closed (e.g. ssh hang-up): stop
                    // feeding input, keep mirroring output until the
                    // command closes the pty.
                    stdin_open = false;
                } else if io_err() != libc::EINTR && io_err() != libc::EAGAIN {
                    stdin_open = false;
                }
            }
            if !to_master.is_empty() {
                let r = libc::write(
                    master,
                    to_master.as_ptr() as *const libc::c_void,
                    to_master.len(),
                );
                if r > 0 {
                    to_master.drain(..r as usize);
                } else if r < 0 && io_err() != libc::EINTR && io_err() != libc::EAGAIN {
                    return RelayEnd::MasterClosed;
                }
            }

            // master → user's stdout
            if fds[2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let r = libc::read(master, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
                if r > 0 {
                    to_stdout.extend_from_slice(&chunk[..r as usize]);
                } else if r == 0 || (r < 0 && io_err() == libc::EIO) {
                    // All slave fds are closed: the command is gone from
                    // the terminal. Normal end of the relay.
                    return RelayEnd::MasterClosed;
                }
            }
            if !to_stdout.is_empty() {
                let r = libc::write(
                    1,
                    to_stdout.as_ptr() as *const libc::c_void,
                    to_stdout.len(),
                );
                if r > 0 {
                    to_stdout.drain(..r as usize);
                } else if r < 0 && io_err() != libc::EINTR && io_err() != libc::EAGAIN {
                    // The user's terminal is gone; nothing left to mirror
                    // into. Keep waiting for the command regardless — the
                    // PDEATHSIG/exit-status machinery still applies.
                    to_stdout.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly opened pty round-trips bytes: write to the master, read
    /// from the slave (through the kernel line discipline).
    #[test]
    fn pty_pair_round_trips() {
        unsafe {
            let pty = open();
            let msg = b"ai-bubble-pty-test\n";
            assert_eq!(
                libc::write(pty.master, msg.as_ptr() as *const libc::c_void, msg.len()),
                msg.len() as isize
            );
            let mut buf = [0u8; 64];
            let r = libc::read(pty.slave, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            assert_eq!(r, msg.len() as isize);
            assert_eq!(&buf[..msg.len()], msg);
            assert!(pty.slave_path.starts_with("/dev/pts/"));
            libc::close(pty.master);
            libc::close(pty.slave);
        }
    }

    /// The slave path resolves as a tty on the host devpts instance.
    #[test]
    fn slave_is_a_terminal() {
        unsafe {
            let pty = open();
            assert_eq!(libc::isatty(pty.slave), 1);
            libc::close(pty.master);
            libc::close(pty.slave);
        }
    }
}
