//! Per-operation performance counters for the FUSE `Filesystem`
//! implementation (`RS_BUBBLE_FUSE_STATS=<file>`).
//!
//! Every instrumented method drops an [`OpGuard`] whose `Drop` records the
//! call count, the wall-clock ("real") time and the process CPU time of the
//! call into a global registry. A background thread appends a table to the
//! configured file every [`DUMP_INTERVAL`]; the registry is reset after each
//! dump, so the table shows the *per-interval* rates alongside the cumulative
//! totals since startup.
//!
//! Notes on CPU time: it is measured process-wide with
//! `CLOCK_PROCESS_CPUTIME_ID` around each call. The calls are async, so the
//! measured window overlaps other tasks on other threads; treat the CPU
//! column as an upper bound for what a single op's work cost, and compare
//! *real* vs *cpu* to see how much time is spent waiting (I/O, scheduling,
//! FUSE kernel round trips) rather than computing.

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// How often the counters are written out (and reset).
const DUMP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Default, Clone, Copy)]
struct OpStats {
    count: u64,
    real_ns: u64,
    cpu_ns: u64,
    max_real_ns: u64,
}

impl OpStats {
    fn add(&mut self, real_ns: u64, cpu_ns: u64) {
        self.count += 1;
        self.real_ns += real_ns;
        self.cpu_ns += cpu_ns;
        self.max_real_ns = self.max_real_ns.max(real_ns);
    }
}

/// `true` when `RS_BUBBLE_FUSE_STATS` is set, i.e. when instrumenting has
/// any effect. Lets disabled builds skip the clock reads.
pub fn enabled() -> bool {
    file().is_some()
}

fn file() -> Option<&'static str> {
    static PATH: OnceLock<Option<String>> = OnceLock::new();
    PATH.get_or_init(|| std::env::var("RS_BUBBLE_FUSE_STATS").ok())
        .as_deref()
}

fn stats() -> &'static Mutex<HashMap<&'static str, OpStats>> {
    static STATS: OnceLock<Mutex<HashMap<&'static str, OpStats>>> = OnceLock::new();
    STATS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Process CPU time in nanoseconds (`CLOCK_PROCESS_CPUTIME_ID`).
fn process_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: plain clock read with a valid, initialized timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) } == 0 {
        (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
    } else {
        0
    }
}

/// Held for the duration of one `Filesystem` method call; `Drop` records the
/// measurement. Guard creation is allocation-free and cheap even while
/// instrumentation is enabled; it is skipped entirely when the env var is
/// unset (the [`crate::fuse_op!`] macro checks `enabled()` first).
pub struct OpGuard {
    op: &'static str,
    real_start: Instant,
    cpu_start: u64,
}

impl OpGuard {
    pub fn new(op: &'static str) -> Self {
        spawn_dump_thread();
        OpGuard {
            op,
            real_start: Instant::now(),
            cpu_start: process_cpu_ns(),
        }
    }
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        if let Ok(mut stats) = stats().lock() {
            stats.entry(self.op).or_default().add(
                self.real_start.elapsed().as_nanos() as u64,
                process_cpu_ns().saturating_sub(self.cpu_start),
            );
        }
    }
}

/// Spawn the periodic dumper exactly once. The counters only exist while
/// guards are created, so there is nothing to dump before that.
fn spawn_dump_thread() {
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    let mut cumulative: HashMap<&'static str, OpStats> = HashMap::new();
    let mut started = Instant::now();
    std::thread::Builder::new()
        .name("fuse-stats-dump".into())
        .spawn(move || {
            let Some(path) = file() else { return };
                // HF-4: open the stats file once, eagerly, through the
                // audit log's safe open (`O_NOFOLLOW` — a sandbox-swapped
                // symlink must never be followed; `O_NONBLOCK` — a
                // swapped-in FIFO must not hang this thread; regular-file
                // check), then keep writing to the descriptor. Re-opening
                // the attacker-influenceable path every interval was the
                // bug class already fixed for the fuselog writer.
                let Ok(f) =
                    crate::audit::writer::safe_open_read(std::path::Path::new(path), "FUSE stats file")
                else {
                    return;
                };
                let f = std::sync::Mutex::new(f);
                loop {
                    std::thread::sleep(DUMP_INTERVAL);
                    let elapsed = started.elapsed();
                    started = Instant::now();
                    // Swap out the interval's counters and fold them into the
                    // cumulative totals.
                    let Ok(mut stats) = stats().lock() else {
                        continue;
                    };
                    let interval = std::mem::take(&mut *stats);
                    drop(stats);
                    for (op, s) in &interval {
                        cumulative.entry(op).or_default().add(s.real_ns, s.cpu_ns);
                    }
                    let Ok(mut f) = f.lock() else {
                        continue;
                    };
                    let _ = write_table(&mut *f, "interval", elapsed, &interval);
                    let _ = write_table(&mut *f, "cumulative", elapsed, &cumulative);
                }
        })
        .ok();
}

fn write_table(
    f: &mut impl Write,
    label: &str,
    elapsed: std::time::Duration,
    table: &HashMap<&'static str, OpStats>,
) -> std::io::Result<()> {
    const HEADER: &str = "op           calls   real-ms   avg-ms   max-ms    cpu-ms  cpu%";
    let secs = elapsed.as_secs_f64().max(1e-9);
    writeln!(f, "==== {label} ({elapsed:.1?})",)?;
    writeln!(f, "{HEADER}")?;
    let mut rows: Vec<_> = table.iter().collect();
    // Busiest op first: sort by accumulated real time.
    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.real_ns));
    for (op, s) in rows {
        writeln!(
            f,
            "{op:<12} {:>6} {:>9.1} {:>8.3} {:>8.3} {:>8.1} {:>4.1}%",
            s.count,
            s.real_ns as f64 / 1e6,
            s.real_ns as f64 / 1e6 / s.count.max(1) as f64,
            s.max_real_ns as f64 / 1e6,
            s.cpu_ns as f64 / 1e6,
            s.cpu_ns as f64 / 1e6 / secs,
        )?;
    }
    writeln!(f)
}

/// Instrument one `Filesystem` method: place this as the first statement of
/// the method body and the call is counted and timed (real + CPU) until the
/// method returns, including early returns. No-op unless
/// `RS_BUBBLE_FUSE_STATS` is set.
///
/// Usage: `fuse_op!("lookup");`
#[macro_export]
macro_rules! fuse_op {
    ($op:literal) => {
        // The guard lives to the end of the enclosing block, so it must be
        // created unconditionally (as an `Option`, zero-cost when off).
        let _fuse_op_guard = if $crate::hostfs::perf::enabled() {
            Some($crate::hostfs::perf::OpGuard::new($op))
        } else {
            None
        };
    };
}

// Expose the macro under this module's path too, so call sites can write
// `perf::fuse_op!(...)` (the macro lives at the crate root because
// `macro_rules!` can only be exported there).
pub(crate) use crate::fuse_op;
