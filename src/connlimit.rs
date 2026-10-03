//! A simple per-listener connection cap (AUDIT.md (Verified prevented: resource limits on the frontends; the command side is M4): resource
//! isolation).
//!
//! Every network frontend of the sandbox (the in-sandbox proxy and waf
//! servers, and the host-side connector and waf command server) accepts
//! one connection per task, unbounded. A malicious sandboxed command
//! could open thousands of idle connections to exhaust the supervisor's
//! file descriptors — and the in-sandbox server's task count with them.
//!
//! [`ConnLimit`] is a tiny counter-based semaphore used *around the
//! accept loop*: a newly accepted connection is registered before the
//! serving task is spawned, and the registration is released when the
//! task's connection closes (via the [`Guard`]'s `Drop`). When the cap
//! is reached the new connection is dropped immediately — the client
//! sees a plain close, which every protocol implemented here survives.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The maximum number of concurrent connections per listener.
pub const MAX_CONNS: usize = 256;

/// The per-listener connection counter. Shared as an `Arc` between the
/// accept loop and every spawned serving task.
#[derive(Debug)]
pub struct ConnLimit {
    max: usize,
    current: AtomicUsize,
}

/// A registration of one connection, held for the connection's whole
/// lifetime. Dropping it releases the slot.
#[derive(Debug)]
pub struct Guard {
    limit: Arc<ConnLimit>,
}

impl ConnLimit {
    /// A fresh counter with the default cap ([`MAX_CONNS`]).
    pub fn new() -> Arc<Self> {
        Self::with_max(MAX_CONNS)
    }

    /// A fresh counter with an explicit cap (used by tests).
    pub fn with_max(max: usize) -> Arc<Self> {
        Arc::new(ConnLimit {
            max,
            current: AtomicUsize::new(0),
        })
    }

    /// Register a newly accepted connection. `None` when the listener is
    /// already at its cap — the caller should drop the connection
    /// immediately without spawning a task for it.
    pub fn try_acquire(self: &Arc<Self>) -> Option<Guard> {
        let mut current = self.current.load(Ordering::Relaxed);
        loop {
            if current >= self.max {
                return None;
            }
            match self.current.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Guard { limit: self.clone() }),
                Err(now) => current = now,
            }
        }
    }

    /// The number of currently registered connections (for tests).
    #[cfg(test)]
    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.limit.current.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_is_enforced_and_released() {
        let limit = ConnLimit::with_max(3);
        let g1 = limit.try_acquire();
        let g2 = limit.try_acquire();
        let g3 = limit.try_acquire();
        assert!(g1.is_some() && g2.is_some() && g3.is_some());
        // At the cap: no further registrations.
        assert!(limit.try_acquire().is_none());
        assert_eq!(limit.current(), 3);
        // Dropping a guard releases the slot again.
        drop(g2);
        assert_eq!(limit.current(), 2);
        assert!(limit.try_acquire().is_some());
    }
}