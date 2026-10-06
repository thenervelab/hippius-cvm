//! Background confirmation of re-adopted vsock CIDs the live domain XML
//! could not vouch for at startup.
//!
//! Re-adoption ([`CvmLifecycle::readopt_running`]) rebuilds a surviving
//! VM's handle from its miner-local sidecar and corrects it against
//! `virsh dumpxml`. When that read fails, the recorded CID is HELD
//! unverified: nobody else is handed it, but ticket pushes and relay
//! routing wait on it, because a stale record would send this VM's ticket
//! to — and attribute frames from — whichever guest the kernel really gave
//! that CID. This loop retries the confirmation until each such CID is
//! verified, re-keyed to the live one, or dropped with its gone domain
//! ([`CvmLifecycle::verify_pending_cids`]). Per-VM backoff lives in the
//! lifecycle; this is only the clock.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::lifecycle::CvmLifecycle;

/// How often the loop looks for due checks. Cheap when nothing is pending
/// (one lock + a length read); the per-VM retry cadence is the lifecycle's
/// capped backoff, not this tick.
const TICK: Duration = Duration::from_secs(1);

/// Drive [`CvmLifecycle::verify_pending_cids`] until `cancel` fires.
pub async fn run(lifecycle: Arc<CvmLifecycle>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(TICK) => {}
        }
        if lifecycle.unverified_cid_count() > 0 || lifecycle.readopt_retry_due() {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = lifecycle.verify_pending_cids(std::time::Instant::now()) => {}
            }
        }
    }
}
