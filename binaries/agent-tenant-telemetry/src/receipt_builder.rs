//! Builds and signs the next periodic `ServedDeliveryReceipt`.
//!
//! The builder holds the per-VM context that is constant across the
//! lease — `vm_id`, `lease_id`, `family_id`, `node_id`,
//! `resource_class` — plus the two pieces of loop state that advance
//! with every receipt: `monotonic_seq` and the previous interval's
//! `period_end`. Each [`ReceiptBuilder::build_next`] call produces ONE
//! signed receipt and advances that state — but only AFTER the
//! signature succeeds, so a failed interval burns neither a sequence
//! number nor a window.

use hippius_types::served_receipt::{ServedDeliveryReceipt, SignedServedDeliveryReceipt};

use crate::challenge::Challenge;
use crate::disk_stats::{DiskEvidence, DiskEvidenceSource, NoDiskEvidence};
use crate::error::{Result, TelemetryError};
use crate::signer::TelemetrySigner;

/// The first `monotonic_seq` a builder emits. Per §23 the sequence is
/// per-`(vm_id, lease_id)`; a freshly established signer key (the key
/// is RAM-only and regenerated each boot) starts its sequence at 1.
const FIRST_SEQ: u64 = 1;

/// One receipt's window and challenge.
struct Window<'a> {
    challenge: &'a Challenge,
    observed_degradation_bps: u32,
    period_start: u64,
    period_end: u64,
    expiry: u64,
}

/// Builds successive signed `ServedDeliveryReceipt`s for one VM + lease.
pub struct ReceiptBuilder {
    vm_id: String,
    lease_id: String,
    family_id: Vec<u8>,
    node_id: Vec<u8>,
    resource_class: String,
    /// `monotonic_seq` for the NEXT receipt.
    next_seq: u64,
    /// `period_end` of the last receipt — the next `period_start`.
    last_period_end: u64,
    /// The optional disk evidence ([`crate::disk_stats`]); its window
    /// moves with the receipt's.
    disk: Box<dyn DiskEvidenceSource + Send>,
}

impl ReceiptBuilder {
    /// A builder for `vm_id` / `lease_id` whose first receipt covers the
    /// interval starting at `genesis_period_start` (the agent's start
    /// time — typically "now" at loop construction).
    pub fn new(
        vm_id: String,
        lease_id: String,
        family_id: Vec<u8>,
        node_id: Vec<u8>,
        resource_class: String,
        genesis_period_start: u64,
    ) -> Self {
        Self {
            vm_id,
            lease_id,
            family_id,
            node_id,
            resource_class,
            next_seq: FIRST_SEQ,
            last_period_end: genesis_period_start,
            disk: Box::new(NoDiskEvidence),
        }
    }

    /// Carry disk evidence from `source` in every receipt.
    pub fn with_disk_evidence(mut self, source: Box<dyn DiskEvidenceSource + Send>) -> Self {
        self.disk = source;
        self
    }

    /// The `monotonic_seq` the next [`build_next`](Self::build_next)
    /// call will emit.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The `period_start` the next receipt will carry (the previous
    /// receipt's `period_end`).
    pub fn next_period_start(&self) -> u64 {
        self.last_period_end
    }

    fn receipt<'a>(&'a self, w: &Window<'a>, disk: &'a DiskEvidence) -> ServedDeliveryReceipt<'a> {
        ServedDeliveryReceipt {
            validator_id: &w.challenge.validator_id,
            validator_nonce: &w.challenge.validator_nonce,
            epoch: w.challenge.epoch,
            vm_id: &self.vm_id,
            lease_id: &self.lease_id,
            family_id: &self.family_id,
            node_id: &self.node_id,
            resource_class: &self.resource_class,
            monotonic_seq: self.next_seq,
            observed_degradation_bps: w.observed_degradation_bps,
            period_start: w.period_start,
            period_end: w.period_end,
            expiry: w.expiry,
            disk_io: disk.io.as_deref(),
            disk_probe: disk.probe.as_ref(),
        }
    }

    /// Build + sign the receipt for the interval ending at `now_unix`.
    ///
    /// The interval is `[last_period_end, now_unix]`; `expiry` is
    /// `now_unix + ttl_secs`. The receipt commits to `challenge` and
    /// carries `observed_degradation_bps`.
    ///
    /// On success the builder advances `monotonic_seq` and
    /// `last_period_end`; on ANY failure it advances neither — a failed
    /// interval burns no sequence number and does not move the window,
    /// so the next call retries the same window cleanly.
    pub fn build_next(
        &mut self,
        signer: &dyn TelemetrySigner,
        challenge: &Challenge,
        observed_degradation_bps: u32,
        now_unix: u64,
        ttl_secs: u64,
    ) -> Result<SignedServedDeliveryReceipt> {
        let period_start = self.last_period_end;
        let period_end = now_unix;
        // The interval must strictly advance: a non-advancing clock (or
        // a second call within the same whole second — receipts are
        // second-granular) would yield a zero/inverted window.
        // `canonical()` also rejects this, but a typed pre-check gives a
        // precise error class.
        if period_end <= period_start {
            return Err(TelemetryError::Receipt("interval-not-advanced"));
        }
        let expiry = period_end
            .checked_add(ttl_secs)
            .ok_or(TelemetryError::Receipt("expiry-overflow"))?;
        // Compute the post-receipt sequence BEFORE signing, so once a
        // signature exists no fallible step remains — the state commit
        // below is then pure infallible assignment.
        let next_seq_after = self
            .next_seq
            .checked_add(1)
            .ok_or(TelemetryError::Receipt("seq-overflow"))?;

        let (evidence, snapshot) = self.disk.sample();
        let window = Window {
            challenge,
            observed_degradation_bps,
            period_start,
            period_end,
            expiry,
        };

        // Sign — only a successful signature commits the state. Disk
        // evidence is optional: a receipt it would break is signed
        // without it.
        let signed = match signer.sign_served_receipt(&self.receipt(&window, &evidence)) {
            Ok(signed) => signed,
            Err(_) if evidence != DiskEvidence::default() => {
                eprintln!(
                    "hippius-agent-tenant-telemetry: disk evidence refused, receipt sent without it"
                );
                signer.sign_served_receipt(&self.receipt(&window, &DiskEvidence::default()))?
            }
            Err(e) => return Err(e),
        };

        // Signature obtained — commit. Neither assignment can fail.
        self.next_seq = next_seq_after;
        self.last_period_end = period_end;
        self.disk.commit(snapshot);
        Ok(signed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::signer::Ed25519TelemetrySigner;
    use hippius_guest::verify_served_receipt;

    fn challenge() -> Challenge {
        Challenge {
            validator_id: b"validator-1".to_vec(),
            validator_nonce: [4u8; 32],
            epoch: 9,
        }
    }

    fn builder(genesis: u64) -> ReceiptBuilder {
        ReceiptBuilder::new(
            "vm-1".to_string(),
            "lease-1".to_string(),
            b"family-1".to_vec(),
            b"node-1".to_vec(),
            "std".to_string(),
            genesis,
        )
    }

    /// The receipt the builder is EXPECTED to have produced, built
    /// independently — its `canonical()` must equal the signed `body`.
    #[allow(clippy::too_many_arguments)]
    fn expect<'a>(
        ch: &'a Challenge,
        seq: u64,
        deg: u32,
        period_start: u64,
        period_end: u64,
        expiry: u64,
    ) -> ServedDeliveryReceipt<'a> {
        ServedDeliveryReceipt {
            validator_id: &ch.validator_id,
            validator_nonce: &ch.validator_nonce,
            epoch: ch.epoch,
            vm_id: "vm-1",
            lease_id: "lease-1",
            family_id: b"family-1",
            node_id: b"node-1",
            resource_class: "std",
            monotonic_seq: seq,
            observed_degradation_bps: deg,
            period_start,
            period_end,
            expiry,
            disk_io: None,
            disk_probe: None,
        }
    }

    #[test]
    fn build_next_produces_the_expected_body_and_a_valid_signature() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        let mut b = builder(100);
        let signed = b.build_next(&signer, &ch, 250, 160, 3_600).unwrap();

        // The signed body is exactly the canonical CBOR of a receipt
        // with the fields the builder should have set.
        let expected = expect(&ch, 1, 250, 100, 160, 160 + 3_600);
        assert_eq!(signed.body, expected.canonical().unwrap());
        // And the signature verifies under the signer's own key.
        verify_served_receipt(&signer.verifying_key(), &signed, &expected).unwrap();
    }

    /// A scripted disk source: `evidence` every sample, and the commits.
    struct Scripted {
        evidence: DiskEvidence,
        commits: std::sync::Arc<std::sync::Mutex<usize>>,
    }

    impl DiskEvidenceSource for Scripted {
        fn sample(&self) -> (DiskEvidence, crate::disk_stats::Snapshot) {
            (self.evidence.clone(), Default::default())
        }
        fn commit(&self, _snapshot: crate::disk_stats::Snapshot) {
            *self.commits.lock().unwrap() += 1;
        }
    }

    fn io() -> Vec<hippius_types::disk_stats::DiskIoDelta> {
        vec![hippius_types::disk_stats::DiskIoDelta {
            dev: "vda".into(),
            serial: "hippius-os".into(),
            state: hippius_types::disk_stats::DiskIoState::Ok,
            r_ios: 1,
            r_sectors: 2,
            r_ticks_ms: 3,
            w_ios: 4,
            w_sectors: 5,
            w_ticks_ms: 6,
            io_ticks_ms: 7,
            tiq_ms: 8,
            inflight: 0,
            init_percent: None,
        }]
    }

    #[test]
    fn disk_evidence_is_signed_in_and_its_window_moves_only_on_success() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        let commits = std::sync::Arc::new(std::sync::Mutex::new(0));
        let evidence = DiskEvidence {
            io: Some(io()),
            probe: None,
        };
        let mut b = builder(100).with_disk_evidence(Box::new(Scripted {
            evidence: evidence.clone(),
            commits: commits.clone(),
        }));
        // A failed interval does not move the disk window.
        assert!(b.build_next(&signer, &ch, 0, 100, 3_600).is_err());
        assert_eq!(*commits.lock().unwrap(), 0);
        let signed = b.build_next(&signer, &ch, 0, 160, 3_600).unwrap();
        assert_eq!(*commits.lock().unwrap(), 1);
        let mut expected = expect(&ch, 1, 0, 100, 160, 160 + 3_600);
        let list = io();
        expected.disk_io = Some(&list);
        assert_eq!(signed.body, expected.canonical().unwrap());
        verify_served_receipt(&signer.verifying_key(), &signed, &expected).unwrap();
    }

    #[test]
    fn evidence_the_receipt_refuses_is_dropped_not_the_receipt() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        // A probe result naming another VM: `canonical()` refuses it.
        let probe = hippius_types::disk_stats::DiskProbeResult {
            run_id: [1; 16],
            nonce: [2; 32],
            vm_id: "vm-other".into(),
            vcpus: 2,
            kernel: "6.8".into(),
            release_version: 5,
            started_at: 1,
            finished_at: 2,
            targets: vec![hippius_types::disk_stats::DiskProbeTarget {
                slot: "os".into(),
                profile: "v1".into(),
                metrics: vec![("seq_read_mbps".into(), 1)],
                hist_qd1: vec![0; hippius_types::disk_stats::HIST_BUCKETS],
                error: String::new(),
            }],
        };
        let mut b = builder(100).with_disk_evidence(Box::new(Scripted {
            evidence: DiskEvidence {
                io: Some(io()),
                probe: Some(probe),
            },
            commits: Default::default(),
        }));
        let signed = b.build_next(&signer, &ch, 0, 160, 3_600).unwrap();
        assert_eq!(
            signed.body,
            expect(&ch, 1, 0, 100, 160, 160 + 3_600)
                .canonical()
                .unwrap()
        );
    }

    #[test]
    fn successive_receipts_advance_seq_and_chain_the_window() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        let mut b = builder(100);
        assert_eq!(b.next_seq(), 1);

        let r1 = b.build_next(&signer, &ch, 0, 160, 3_600).unwrap();
        assert_eq!(b.next_seq(), 2);
        // Receipt 1: seq 1, window 100..160.
        assert_eq!(
            r1.body,
            expect(&ch, 1, 0, 100, 160, 160 + 3_600)
                .canonical()
                .unwrap()
        );

        let r2 = b.build_next(&signer, &ch, 0, 220, 3_600).unwrap();
        assert_eq!(b.next_seq(), 3);
        // Receipt 2: seq 2, window 160..220 — period_start chains off
        // receipt 1's period_end. No gap, no overlap.
        assert_eq!(
            r2.body,
            expect(&ch, 2, 0, 160, 220, 220 + 3_600)
                .canonical()
                .unwrap()
        );
    }

    #[test]
    fn a_non_advancing_clock_fails_and_does_not_burn_state() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        let mut b = builder(100);

        // now == genesis: the interval has not advanced.
        let err = b
            .build_next(&signer, &ch, 0, 100, 3_600)
            .expect_err("a non-advancing interval must fail");
        assert_eq!(err.class(), "interval-not-advanced");
        // now < last period end: also rejected.
        assert!(b.build_next(&signer, &ch, 0, 99, 3_600).is_err());

        // State is intact — the next valid call still emits seq 1 over
        // the original window.
        assert_eq!(b.next_seq(), 1);
        assert_eq!(b.next_period_start(), 100);
        let ok = b.build_next(&signer, &ch, 0, 160, 3_600).unwrap();
        assert_eq!(
            ok.body,
            expect(&ch, 1, 0, 100, 160, 160 + 3_600)
                .canonical()
                .unwrap()
        );
    }

    #[test]
    fn expiry_overflow_fails_closed() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let ch = challenge();
        let mut b = builder(100);
        let err = b
            .build_next(&signer, &ch, 0, 200, u64::MAX)
            .expect_err("period_end + ttl overflowing u64 must fail");
        assert_eq!(err.class(), "expiry-overflow");
        // The failure burned no state.
        assert_eq!(b.next_seq(), 1);
    }

    #[test]
    fn the_receipt_commits_to_the_supplied_challenge() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let ch = challenge();
        let signed = b.build_next(&signer, &ch, 0, 160, 3_600).unwrap();

        // A receipt built for a DIFFERENT validator does not verify
        // against this signed body — the challenge is bound in.
        let other = Challenge {
            validator_id: b"validator-attacker".to_vec(),
            validator_nonce: [4u8; 32],
            epoch: 9,
        };
        let other_expected = expect(&other, 1, 0, 100, 160, 160 + 3_600);
        assert!(verify_served_receipt(&signer.verifying_key(), &signed, &other_expected).is_err());
    }
}
