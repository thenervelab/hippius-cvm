//! The periodic **re-enrollment** loop — refreshes the KBS cert before
//! its TTL expires (blackbox host-attestor lifecycle fix).
//!
//! ## Why (the live-found gap)
//!
//! The KBS mints a `SignedHostAttestorCert` with a **2 h TTL**
//! (`HOST_ATTESTOR_CERT_TTL_SECS`). The agent enrolls once at boot
//! ([`crate::establish`] → [`crate::enroll`]) — so ~2 h after boot the vali
//! `HostAttestor` row would flip `attested` → `expired` (observed live on
//! a live miner). Beacons keep `last_seen` fresh but do **not** refresh the
//! cert: only a fresh enrollment (fresh SNP report) re-mints it.
//!
//! This loop closes that gap: on an interval (default hourly, comfortably
//! below the 2 h TTL — see [`crate::config`]) it pulls a **fresh** vali
//! single-use nonce + node_id ([`ChallengeSource`]), requests a **fresh**
//! SNP report bound to them ([`crate::enroll`]), and installs the new
//! enrollment frame into the shared [`EnrollFrameSlot`] for the vsock
//! pusher to re-send on the live connection. The KBS re-mints, vali's
//! ingest bumps `cert_expiry_at`, and the row stays `attested`. This is
//! the design's "per boot + HOURLY" enrollment.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! The **derived key stays a one-time fetch** ([`crate::establish`], the
//! R1 invariant): this loop never re-derives it — the cached signer is
//! reused, and only the challenge + `get_report` repeat. The only
//! `/dev/sev-guest` interaction here is [`crate::enroll`]'s `get_report`.
//! By the time this loop runs, [`crate::establish`] has fully returned
//! (its `Firmware` handle closed) and the boot [`crate::enroll`] has
//! completed on the main thread — after that this loop is the **sole**
//! post-establish opener of the device, and it issues at most one
//! `get_report` at a time (strictly sequential within the loop). The
//! beacon loop signs with Ed25519 only and the vsock pusher does socket
//! I/O only — neither touches the device — so nothing ever races the
//! serialized, sequence-numbered channel.
//!
//! ## Fail-soft (unlike the boot enroll)
//!
//! The BOOT enrollment is fail-**closed** (a host with no cert is not a
//! host we can trust — the process exits). A periodic re-enroll that fails
//! (network blip, vali momentarily down, a transient device error) is
//! fail-**soft**: it logs a static class and retries on the next tick,
//! because the CURRENT cert is still valid until its 2 h expiry — a single
//! missed refresh is recoverable. If re-enroll keeps failing past the cert
//! TTL the vali row does expire (correct: the attestor genuinely cannot
//! refresh). No verification is weakened: every re-enroll still fetches a
//! fresh single-use nonce and mints a fresh AMD-signed report.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::beacon_loop::unix_now;
use crate::challenge::HostChallenge;
use crate::enroll::enroll;
use crate::error::{HostAttestorError, Result};
use crate::frame::encode_enroll_frame;
use crate::nonce::{ChallengeNonceSource, NONCE_LEN};
use crate::shutdown::ShutdownWatch;
use crate::snp::SnpReportProvider;

/// Granularity at which the interval sleep re-checks the shutdown latch —
/// so a `SIGTERM` is never delayed by a full re-enroll interval.
const SHUTDOWN_POLL: Duration = Duration::from_millis(500);

/// A swappable, re-sendable enrollment frame shared between the re-enroll
/// loop (producer) and the [`crate::vsock_pusher::VsockPusher`] (consumer).
///
/// The pusher writes the current frame as the preamble on every fresh
/// connection AND re-sends it on the live connection whenever the
/// `version` changes — so a freshly re-enrolled cert reaches the KBS
/// promptly even on a long-lived vsock connection (the miner relay keeps
/// one connection open for hours). `Clone` shares the same inner slot.
#[derive(Clone)]
pub struct EnrollFrameSlot {
    inner: Arc<Mutex<EnrollFrameState>>,
}

/// The frame currently held + a monotonically-bumped version. The pusher
/// remembers the version it last flushed on a connection and re-sends when
/// it changes.
struct EnrollFrameState {
    frame: Arc<Vec<u8>>,
    version: u64,
}

impl EnrollFrameSlot {
    /// Build a slot holding the initial boot-enrollment frame (version 0).
    pub fn new(initial: Arc<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EnrollFrameState {
                frame: initial,
                version: 0,
            })),
        }
    }

    /// Install a freshly re-enrolled frame, bumping the version so a live
    /// pusher connection re-sends it. Called by the re-enroll loop only.
    /// A poisoned lock (the pusher panicked mid-snapshot — install itself
    /// cannot panic) surfaces as a static class the caller logs.
    pub fn install(&self, frame: Arc<Vec<u8>>) -> Result<()> {
        let mut st = self
            .inner
            .lock()
            .map_err(|_| HostAttestorError::Vsock("enroll-slot-poisoned"))?;
        st.frame = frame;
        st.version = st.version.wrapping_add(1);
        Ok(())
    }

    /// Snapshot the current frame + version — the pusher's read side.
    pub fn snapshot(&self) -> Result<(Arc<Vec<u8>>, u64)> {
        let st = self
            .inner
            .lock()
            .map_err(|_| HostAttestorError::Vsock("enroll-slot-poisoned"))?;
        Ok((Arc::clone(&st.frame), st.version))
    }
}

/// Source of a fresh vali-minted enrollment challenge (single-use nonce +
/// vali-stamped node_id). A trait so the loop is unit-testable with a mock
/// (the production impl dials the miner-agent vsock challenge listener).
///
/// The nonce is single-use, so every re-enroll MUST fetch a NEW one — a
/// stale nonce would be rejected by vali's single-use gate. Fail-closed:
/// no local fallback (a self-generated nonce reopens the pre-generation
/// replay hole).
pub trait ChallengeSource {
    /// Pull one fresh challenge (nonce + node_id). Fail-closed.
    fn fetch(&self) -> Result<HostChallenge>;
}

impl ChallengeSource for ChallengeNonceSource {
    fn fetch(&self) -> Result<HostChallenge> {
        ChallengeNonceSource::fetch(self)
    }
}

/// Perform ONE re-enrollment: fresh challenge → fresh SNP report bound to
/// `{nonce, signer_pubkey, node_id}` → install the new enrollment frame.
///
/// `provider.get_report` is the only `/dev/sev-guest` access — see the
/// module-level R1 note. `signer_pubkey` is the cached boot signer's key
/// (the derived key is NEVER re-fetched); `boot_id` is the stable per-boot
/// id. Returns `Ok(())` after the fresh frame is installed for the pusher.
pub fn reenroll_once(
    provider: &dyn SnpReportProvider,
    challenge: &dyn ChallengeSource,
    signer_pubkey: &[u8; NONCE_LEN],
    boot_id: &str,
    slot: &EnrollFrameSlot,
) -> Result<()> {
    // A FRESH single-use vali nonce + the vali-stamped node_id. Fail-closed
    // — never a local fallback.
    let host_challenge = challenge.fetch()?;
    let issued_at = unix_now()?;
    // The fresh get_report — the sole post-establish device interaction,
    // serialized within this loop (one at a time, no other opener).
    let enrolled = enroll(
        provider,
        signer_pubkey,
        &host_challenge.node_id,
        boot_id,
        &host_challenge.nonce,
        issued_at,
    )?;
    let frame = Arc::new(encode_enroll_frame(&enrolled.enrollment)?);
    slot.install(frame)?;
    Ok(())
}

/// Run the periodic re-enroll loop until shutdown.
///
/// Each `interval` (validated < the cert TTL by [`crate::config`]): wait
/// out the interval (responsive to shutdown), then [`reenroll_once`]. A
/// tick failure is logged by static class and the interval retried —
/// **fail-soft**, because the current cert is still valid until its TTL.
/// Returns `Ok(())` once `shutdown` latches.
pub fn run_reenroll_loop(
    provider: &dyn SnpReportProvider,
    challenge: &dyn ChallengeSource,
    signer_pubkey: &[u8; NONCE_LEN],
    boot_id: &str,
    interval: Duration,
    slot: &EnrollFrameSlot,
    shutdown: &dyn ShutdownWatch,
) -> Result<()> {
    loop {
        if shutdown.is_pending() {
            return Ok(());
        }
        // Wait out the interval BEFORE re-enrolling — the boot enroll
        // already minted the first cert, so the first refresh is due one
        // interval later.
        if sleep_until_due_or_shutdown(interval, shutdown) {
            return Ok(());
        }
        match reenroll_once(provider, challenge, signer_pubkey, boot_id, slot) {
            Ok(()) => {
                eprintln!("hippius-agent-host-attestor: re-enrolled — fresh cert requested");
            }
            // Fail-soft: the current cert is valid until its 2 h TTL, so a
            // transient failure is logged and retried next interval — never
            // fatal (unlike the boot enroll).
            Err(e) => {
                eprintln!(
                    "hippius-agent-host-attestor: re-enroll skipped (fail-soft): {}",
                    e.class()
                );
            }
        }
    }
}

/// Sleep for `interval`, re-checking `shutdown` every [`SHUTDOWN_POLL`].
/// Returns `true` if shutdown became pending during the sleep.
fn sleep_until_due_or_shutdown(interval: Duration, shutdown: &dyn ShutdownWatch) -> bool {
    let mut slept = Duration::ZERO;
    while slept < interval {
        if shutdown.is_pending() {
            return true;
        }
        let chunk = SHUTDOWN_POLL.min(interval - slept);
        thread::sleep(chunk);
        slept += chunk;
    }
    shutdown.is_pending()
}

/// Parameters for [`spawn_reenroll_loop`].
pub struct ReenrollParams {
    /// Host vsock context id — [`crate::vsock_pusher::VSOCK_HOST_CID`].
    pub cid: u32,
    /// Host vsock port the miner-agent's challenge listener binds.
    pub challenge_port: u32,
    /// The cached boot signer's Ed25519 public key (the derived key is
    /// NEVER re-fetched — only the challenge + report repeat).
    pub signer_pubkey: [u8; NONCE_LEN],
    /// The stable per-boot id folded into every (re-)enrollment.
    pub boot_id: String,
    /// Seconds between re-enrollments (validated < the cert TTL).
    pub interval: Duration,
}

/// Spawn the re-enroll loop on its own OS thread (production wiring).
///
/// Constructs the real `/dev/sev-guest` report provider + vsock challenge
/// client inside the thread. After [`crate::establish`] + the boot
/// [`crate::enroll`] on the main thread, THIS thread is the sole
/// post-establish opener of `/dev/sev-guest` (see the module R1 note).
/// The handle joins once `shutdown` latches; `main` joins it (time-bounded)
/// after the beacon loop ends.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn spawn_reenroll_loop<S: ShutdownWatch + Send + 'static>(
    params: ReenrollParams,
    slot: EnrollFrameSlot,
    shutdown: S,
) -> Result<thread::JoinHandle<Result<()>>> {
    thread::Builder::new()
        .name("host-attestor-reenroll".to_string())
        .spawn(move || {
            let provider = crate::snp::SevGuestProvider::new();
            let challenge =
                ChallengeNonceSource::new(params.cid, params.challenge_port, params.signer_pubkey);
            run_reenroll_loop(
                &provider,
                &challenge,
                &params.signer_pubkey,
                &params.boot_id,
                params.interval,
                &slot,
                &shutdown,
            )
        })
        .map_err(|_| HostAttestorError::Enroll("reenroll-thread-spawn"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::snp::{MockSnpReportProvider, SNP_REPORT_LEN};
    use hippius_types::host_attestor::HostEnrollment;
    use hippius_types::report_data::host_attestor;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};

    const REPORT_DATA_OFFSET: usize = 0x50;
    const CHIP_ID_OFFSET: usize = 0x1A0;

    fn planted_report() -> Vec<u8> {
        let mut b = vec![0u8; SNP_REPORT_LEN];
        for (i, byte) in b.iter_mut().skip(CHIP_ID_OFFSET).take(64).enumerate() {
            *byte = 0x80 | (i as u8);
        }
        b
    }

    /// A report provider that plants the caller's REPORT_DATA at 0x50 (so
    /// the installed frame carries the fresh binding) plus a chip_id.
    struct PlantingProvider;
    impl SnpReportProvider for PlantingProvider {
        fn get_report(&self, report_data: crate::snp::ReportData) -> Result<crate::snp::SnpReport> {
            let mut bytes = planted_report();
            bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64]
                .copy_from_slice(report_data.as_bytes());
            Ok(crate::snp::SnpReport(bytes))
        }
    }

    /// A challenge source handing back a canned nonce + node_id, counting
    /// its calls so a test can prove each re-enroll fetches a FRESH nonce.
    struct MockChallenge {
        node_id: String,
        next_nonce: Cell<u8>,
        calls: Cell<u32>,
    }
    impl MockChallenge {
        fn new(node_id: &str) -> Self {
            Self {
                node_id: node_id.to_string(),
                next_nonce: Cell::new(0xA0),
                calls: Cell::new(0),
            }
        }
    }
    impl ChallengeSource for MockChallenge {
        fn fetch(&self) -> Result<HostChallenge> {
            self.calls.set(self.calls.get() + 1);
            let n = self.next_nonce.get();
            self.next_nonce.set(n.wrapping_add(1));
            Ok(HostChallenge {
                nonce: [n; NONCE_LEN],
                node_id: self.node_id.clone(),
            })
        }
    }

    struct FailingChallenge;
    impl ChallengeSource for FailingChallenge {
        fn fetch(&self) -> Result<HostChallenge> {
            Err(HostAttestorError::Nonce("challenge-connect"))
        }
    }

    #[derive(Clone)]
    struct TestShutdown(Arc<AtomicBool>);
    impl TestShutdown {
        fn new() -> Self {
            Self(Arc::new(AtomicBool::new(false)))
        }
    }
    impl ShutdownWatch for TestShutdown {
        fn is_pending(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn slot_install_bumps_the_version_for_a_live_resend() {
        let slot = EnrollFrameSlot::new(Arc::new(vec![1, 2, 3]));
        let (f0, v0) = slot.snapshot().unwrap();
        assert_eq!(*f0, vec![1, 2, 3]);
        assert_eq!(v0, 0);
        slot.install(Arc::new(vec![4, 5, 6])).unwrap();
        let (f1, v1) = slot.snapshot().unwrap();
        assert_eq!(*f1, vec![4, 5, 6]);
        assert_ne!(
            v1, v0,
            "install must bump the version so the pusher re-sends"
        );
    }

    #[test]
    fn reenroll_once_installs_a_fresh_bound_frame() {
        let pk = [0x22u8; NONCE_LEN];
        let slot = EnrollFrameSlot::new(Arc::new(vec![0u8]));
        let challenge = MockChallenge::new("node-host-1");
        reenroll_once(&PlantingProvider, &challenge, &pk, "boot-abc", &slot).unwrap();

        // A fresh nonce was pulled, and the installed frame decodes to an
        // enrollment whose embedded REPORT_DATA is the frozen binding for
        // THAT nonce + pk + node_id.
        assert_eq!(challenge.calls.get(), 1);
        let (frame, version) = slot.snapshot().unwrap();
        assert_ne!(version, 0, "the slot advanced past the boot frame");
        // The frame is a length-prefixed {kind, body} GuestFrame — decode
        // the enrollment out of its body via the frozen decoder.
        let enrollment = decode_enrollment_frame(&frame);
        let expected_rd = host_attestor(&[0xA0u8; NONCE_LEN], &pk, "node-host-1").unwrap();
        let embedded = &enrollment.snp_report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64];
        assert_eq!(embedded, &expected_rd, "fresh REPORT_DATA binding");
        assert_eq!(enrollment.signer_pubkey, pk);
        assert_eq!(enrollment.node_id, "node-host-1");
    }

    #[test]
    fn reenroll_once_fetches_a_new_nonce_every_call() {
        let pk = [0x22u8; NONCE_LEN];
        let slot = EnrollFrameSlot::new(Arc::new(vec![0u8]));
        let challenge = MockChallenge::new("node-host-1");
        reenroll_once(&PlantingProvider, &challenge, &pk, "boot-abc", &slot).unwrap();
        let (_, v1) = slot.snapshot().unwrap();
        reenroll_once(&PlantingProvider, &challenge, &pk, "boot-abc", &slot).unwrap();
        let (frame2, v2) = slot.snapshot().unwrap();
        // Two calls → two fetched nonces → two version bumps.
        assert_eq!(challenge.calls.get(), 2);
        assert_ne!(v1, v2);
        // The second frame carries the SECOND nonce (0xA1) — single-use.
        let enrollment = decode_enrollment_frame(&frame2);
        let expected_rd = host_attestor(&[0xA1u8; NONCE_LEN], &pk, "node-host-1").unwrap();
        let embedded = &enrollment.snp_report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64];
        assert_eq!(embedded, &expected_rd);
    }

    #[test]
    fn reenroll_once_is_fail_soft_on_a_challenge_error() {
        // A challenge failure propagates as an Err — the LOOP swallows it
        // (fail-soft) but reenroll_once itself surfaces it, and crucially
        // the slot is UNCHANGED (the old, still-valid cert frame stays).
        let slot = EnrollFrameSlot::new(Arc::new(vec![9u8]));
        let (_, v0) = slot.snapshot().unwrap();
        let err = reenroll_once(
            &PlantingProvider,
            &FailingChallenge,
            &[0x22u8; NONCE_LEN],
            "boot-abc",
            &slot,
        )
        .expect_err("a challenge failure surfaces");
        assert_eq!(err.class(), "challenge-connect");
        let (frame, v1) = slot.snapshot().unwrap();
        assert_eq!(*frame, vec![9u8], "the previous frame is untouched");
        assert_eq!(v0, v1, "a failed re-enroll never bumps the version");
    }

    #[test]
    fn loop_exits_promptly_when_shutdown_is_already_pending() {
        // With shutdown already latched the loop returns Ok without ever
        // touching the device or the challenge.
        let slot = EnrollFrameSlot::new(Arc::new(vec![0u8]));
        let challenge = MockChallenge::new("node-host-1");
        let shutdown = TestShutdown::new();
        shutdown.0.store(true, Ordering::SeqCst);
        run_reenroll_loop(
            &MockSnpReportProvider::zeroed(),
            &challenge,
            &[0x22u8; NONCE_LEN],
            "boot-abc",
            Duration::from_secs(3600),
            &slot,
            &shutdown,
        )
        .expect("loop returns Ok on an already-pending shutdown");
        assert_eq!(challenge.calls.get(), 0, "no re-enroll when shutting down");
    }

    /// Decode a length-prefixed `{kind, body}` enroll frame back to its
    /// `HostEnrollment` (mirrors the miner relay + the agent-flow test).
    fn decode_enrollment_frame(frame: &[u8]) -> HostEnrollment {
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let body = &frame[4..4 + len];
        let value: ciborium::value::Value = ciborium::de::from_reader(body).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("frame is not a CBOR map");
        };
        let mut inner = None;
        for (k, v) in &entries {
            if k.as_text() == Some("body") {
                inner = v.as_bytes().cloned();
            }
        }
        HostEnrollment::decode(&inner.expect("body")).unwrap()
    }
}
