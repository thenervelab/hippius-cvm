//! Graceful-shutdown signal handling.
//!
//! A `systemctl stop` sends `SIGTERM`. With no handler installed,
//! `SIGTERM`'s default action terminates the process **without running
//! Rust destructors** — so the [`HostAttestorSigner`](crate::signer::HostAttestorSigner)'s
//! `Zeroize`-on-drop would never fire.
//!
//! [`install`] registers a `SIGTERM`/`SIGINT` handler **before** the
//! signer key is derived. The handler does one async-signal-safe thing:
//! set an `AtomicBool`. From that point a signal is *latched*, never a
//! default terminate — even one delivered mid-establishment cannot kill
//! the process before the key wipes.
//!
//! The latch is **polled**, not waited on: the beacon loop checks
//! [`ShutdownWatch::is_pending`] between beats, so a `SIGTERM` ends the
//! loop promptly and `main` returns normally — every destructor, and
//! every `Zeroize`, runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use signal_hook::consts::{SIGINT, SIGTERM};

use crate::error::{HostAttestorError, Result};

/// A latch that reads `true` once a shutdown signal has been delivered.
///
/// A trait so the beacon loop — and its tests, which cannot safely raise
/// a process-wide signal under a parallel harness — depend on the
/// *capability*, not on `signal-hook`.
pub trait ShutdownWatch {
    /// Whether a `SIGTERM`/`SIGINT` has been delivered.
    fn is_pending(&self) -> bool;
}

/// The production shutdown latch — an `AtomicBool` set by the
/// `SIGTERM`/`SIGINT` handlers installed by [`install`].
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
    /// Latch the shutdown flag programmatically — as if a
    /// `SIGTERM`/`SIGINT` had been delivered.
    ///
    /// `main` calls this once the beacon loop returns so the vsock-pusher
    /// thread always observes shutdown and its `join()` cannot hang —
    /// even when the loop ended on an error rather than a signal.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// Install the `SIGTERM`/`SIGINT` handlers and return the latch they set.
///
/// MUST be called **before** any secret (the derived key / signer) is
/// established: registering the handler converts the signal's default
/// "terminate immediately" into a latched flag, so a signal delivered
/// during establishment can no longer skip the key's `Zeroize`-on-drop.
pub fn install() -> Result<Shutdown> {
    let flag = Arc::new(AtomicBool::new(false));
    for signal in [SIGTERM, SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&flag))
            .map_err(|_| HostAttestorError::Shutdown("signal-register"))?;
    }
    Ok(Shutdown { flag })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn install_registers_the_handlers_and_starts_unset() {
        let shutdown = install().expect("handler registration must succeed");
        assert!(!shutdown.is_pending());
        assert!(!shutdown.clone().is_pending());
    }

    #[test]
    fn trigger_latches_the_flag_for_every_clone() {
        let shutdown = install().expect("handler registration must succeed");
        let clone = shutdown.clone();
        assert!(!shutdown.is_pending());
        shutdown.trigger();
        assert!(shutdown.is_pending());
        assert!(clone.is_pending());
    }
}
