//! Graceful shutdown.
//!
//! `SIGTERM`'s default action ends the process without running
//! destructors, so the node key and the fleet keyring would never
//! zeroize. [`install`] latches `SIGTERM`/`SIGINT` into a flag before any
//! key is loaded; every loop polls it and `main` returns normally.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM};

use crate::error::{CdnError, Result};

/// A latch that reads `true` once shutdown was requested.
pub trait ShutdownWatch: Send + Sync {
    fn is_pending(&self) -> bool;
}

/// The production latch.
#[derive(Clone)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl ShutdownWatch for Shutdown {
    fn is_pending(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

impl Shutdown {
    /// Latch the flag as if a signal had arrived.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Sleep up to `d`, waking early on shutdown. Returns `false` if
    /// shutdown is pending.
    pub fn sleep(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        while Instant::now() < end {
            if self.is_pending() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200).min(end - Instant::now()));
        }
        !self.is_pending()
    }

    /// A latch with no signal handler (tests).
    pub fn new_for_tests() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Register the `SIGTERM`/`SIGINT` latch.
pub fn install() -> Result<Shutdown> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [SIGTERM, SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&flag))
            .map_err(|_| CdnError::Shutdown("signal-register"))?;
    }
    Ok(Shutdown { flag })
}
