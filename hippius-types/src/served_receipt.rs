//! Tenant-VM `ServedDeliveryReceipt` (ARCHITECTURE.md §23).
//!
//! The signed periodic attestation a tenant VM emits to claim "I served
//! work for this lease in this window". Spec §23:
//!
//! > A per-VM telemetry agent key is established inside the measured
//! > guest under the §7/§21 attested release. The guest signs periodic
//! > receipts over `{validator nonce/challenge, epoch, vm_id, lease_id,
//! > family_id, compute node_id, resource_class, monotonic_seq,
//! > observed_degradation, expiry}`. Reward only if the receipt digest
//! > is inside the Audit-VM-co-signed `ServedDeliveryAggregate` within
//! > its nonce window.
//!
//! `RECEIPT_DOMAIN` is distinct from every other signed payload in the
//! stack (release, denial, stopped-ack, audit-vm aggregate) so a
//! signature lifted from one scheme cannot replay into any other.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::cbor::to_canonical_vec;
use crate::disk_stats::{disk_io_to_value, DiskIoDelta, DiskProbeResult};
use crate::{HippiusTypesError, Result};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RECEIPT_DOMAIN: &str = "HIPPIUS_TENANT_SERVED_RECEIPT_V1";

/// `observed_degradation` is a 0–10_000 hundredths-of-percent value the
/// tenant honestly reports about its own delivery. Host-claimed inputs
/// (§23) may only DECREASE or corroborate reward — they never raise it.
/// The validator clamps + uses this as one input to `f`.
pub const DEGRADATION_MAX_BPS: u32 = 10_000;

/// Upper bound on each identifier of a receipt (`validator_id`, `vm_id`,
/// `lease_id`, `family_id`, `node_id`, `resource_class`), in bytes. Far
/// above any real value; it exists so a receipt has a finite worst case
/// that fits the 16 KiB guest frame with its disk evidence at maximum
/// (`worst_case_receipt_fits_the_guest_frame`).
pub const MAX_RECEIPT_ID_LEN: usize = 256;

/// The body the tenant guest signs (and the validator re-derives).
///
/// Fields chosen to make a receipt unique within a (chain, validator,
/// epoch, family, node, vm, lease) window: a hostile party that lifts
/// the bytes cannot re-use them for a different VM, lease, or window
/// — every replay-domain piece is part of the signed body.
///
/// `validator_id` is bound (review round-1 review): with only
/// `validator_nonce` for validator scoping, two validators that reused
/// the same fresh nonce could roll the same receipt into aggregates
/// under different `validator_id`s. Including `validator_id` in the
/// receipt body forces the tenant guest to commit to a specific
/// validator at sign time.
///
/// `monotonic_seq` is per-(vm_id, lease_id); the validator + Audit VM
/// detect any out-of-order or repeated sequence number within a window.
/// `observed_degradation` is in basis points (0–10_000) of "less than
/// full work served"; `canonical()` rejects values > [`DEGRADATION_MAX_BPS`].
///
/// `Debug` is implemented manually to print only field LENGTHS — the
/// schema otherwise leaks identifiers (`vm_id`, `lease_id`, nonce)
/// into operator logs by default. Use a redacted form intentionally
/// (review Low).
///
/// `disk_io` / `disk_probe` are OPTIONAL disk evidence
/// ([`crate::disk_stats`]): each key is emitted only when `Some`, so a
/// receipt with both `None` encodes byte-identically to one built before
/// they existed (the `served_delivery_receipt.basic` vector).
#[derive(Clone)]
pub struct ServedDeliveryReceipt<'a> {
    pub validator_id: &'a [u8],
    pub validator_nonce: &'a [u8; 32],
    pub epoch: u64,
    pub vm_id: &'a str,
    pub lease_id: &'a str,
    pub family_id: &'a [u8],
    pub node_id: &'a [u8],
    pub resource_class: &'a str,
    pub monotonic_seq: u64,
    pub observed_degradation_bps: u32,
    pub period_start: u64,
    pub period_end: u64,
    pub expiry: u64,
    /// Per-device I/O deltas over the window. `Some(&[])` is refused: a
    /// receipt without devices omits the key.
    pub disk_io: Option<&'a [DiskIoDelta]>,
    /// A probe VM's benchmark result; its `vm_id` must be this receipt's.
    pub disk_probe: Option<&'a DiskProbeResult>,
}

impl core::fmt::Debug for ServedDeliveryReceipt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServedDeliveryReceipt")
            .field("validator_id_len", &self.validator_id.len())
            .field("validator_nonce_len", &self.validator_nonce.len())
            .field("epoch", &self.epoch)
            .field("vm_id_len", &self.vm_id.len())
            .field("lease_id_len", &self.lease_id.len())
            .field("family_id_len", &self.family_id.len())
            .field("node_id_len", &self.node_id.len())
            .field("resource_class_len", &self.resource_class.len())
            .field("monotonic_seq", &self.monotonic_seq)
            .field("observed_degradation_bps", &self.observed_degradation_bps)
            .field("period_start", &self.period_start)
            .field("period_end", &self.period_end)
            .field("expiry", &self.expiry)
            .field("disk_io_len", &self.disk_io.map(<[DiskIoDelta]>::len))
            .field("disk_probe", &self.disk_probe.is_some())
            .finish()
    }
}

impl ServedDeliveryReceipt<'_> {
    /// Deterministic-CBOR encoding. Rejects malformed inputs at
    /// encode time so a signature over impossible values (inverted
    /// period, out-of-range degradation) cannot exist — fail closed.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if self.observed_degradation_bps > DEGRADATION_MAX_BPS {
            return Err(HippiusTypesError::Cbor(format!(
                "observed_degradation_bps out of range: {} > {}",
                self.observed_degradation_bps, DEGRADATION_MAX_BPS
            )));
        }
        if self.period_end < self.period_start {
            return Err(HippiusTypesError::Cbor(
                "receipt: period_end < period_start".into(),
            ));
        }
        if self.expiry < self.period_end {
            return Err(HippiusTypesError::Cbor(
                "receipt: expiry < period_end".into(),
            ));
        }
        if [
            self.validator_id.len(),
            self.vm_id.len(),
            self.lease_id.len(),
            self.family_id.len(),
            self.node_id.len(),
            self.resource_class.len(),
        ]
        .iter()
        .any(|len| *len > MAX_RECEIPT_ID_LEN)
        {
            return Err(HippiusTypesError::Cbor(
                "receipt: an identifier exceeds MAX_RECEIPT_ID_LEN".into(),
            ));
        }
        let mut entries = vec![
            (
                Value::Text("domain".into()),
                Value::Text(RECEIPT_DOMAIN.into()),
            ),
            (
                Value::Text("epoch".into()),
                Value::Integer(self.epoch.into()),
            ),
            (
                Value::Text("expiry".into()),
                Value::Integer(self.expiry.into()),
            ),
            (
                Value::Text("family_id".into()),
                Value::Bytes(self.family_id.to_vec()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text(self.lease_id.into()),
            ),
            (
                Value::Text("monotonic_seq".into()),
                Value::Integer(self.monotonic_seq.into()),
            ),
            (
                Value::Text("node_id".into()),
                Value::Bytes(self.node_id.to_vec()),
            ),
            (
                Value::Text("observed_degradation_bps".into()),
                Value::Integer(u64::from(self.observed_degradation_bps).into()),
            ),
            (
                Value::Text("period_end".into()),
                Value::Integer(self.period_end.into()),
            ),
            (
                Value::Text("period_start".into()),
                Value::Integer(self.period_start.into()),
            ),
            (
                Value::Text("resource_class".into()),
                Value::Text(self.resource_class.into()),
            ),
            (
                Value::Text("validator_id".into()),
                Value::Bytes(self.validator_id.to_vec()),
            ),
            (
                Value::Text("validator_nonce".into()),
                Value::Bytes(self.validator_nonce.to_vec()),
            ),
            (Value::Text("vm_id".into()), Value::Text(self.vm_id.into())),
        ];
        if let Some(io) = self.disk_io {
            entries.push((Value::Text("disk_io".into()), disk_io_to_value(io)?));
        }
        if let Some(probe) = self.disk_probe {
            if probe.vm_id != self.vm_id {
                return Err(HippiusTypesError::Cbor(
                    "disk_probe: vm_id is not the receipt's".into(),
                ));
            }
            entries.push((Value::Text("disk_probe".into()), probe.to_value()?));
        }
        to_canonical_vec(&Value::Map(entries))
            .map_err(|e| HippiusTypesError::Cbor(format!("receipt: {e}")))
    }
}

/// Signed envelope. `body` is the canonical CBOR; `sig` is Ed25519
/// over `body` by the tenant telemetry key established via §7/§21.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedServedDeliveryReceipt {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedServedDeliveryReceipt {
    /// Deterministic-CBOR encoding of the signed envelope itself — the
    /// `{body, sig}` map in canonical (RFC 8949 §4.2.1) form.
    ///
    /// `body` is already canonical (it is the inner receipt's
    /// `canonical()` output); this wraps it together with the
    /// signature so the whole envelope re-encodes to byte-identical
    /// bytes on every hop. PR-E2.3's tenant→host vsock frame is a
    /// length-prefixed blob of exactly these bytes.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(self.body.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.sig.clone())),
        ]);
        to_canonical_vec(&v).map_err(|e| HippiusTypesError::Cbor(format!("signed-receipt: {e}")))
    }
}

/// SHA-256 over the `body` of a signed receipt — the value that goes
/// into [`crate::audit_vm::ServedReceiptEntry::digest`] when the
/// Audit VM rolls receipts into a `ServedDeliveryAggregate`.
///
/// We digest the signed envelope's BODY (not body+sig) because the
/// receipt-set digest must be reproducible by any party that holds
/// the body (the body alone is what the validator stores + replays).
/// The signature is verified independently in the audit pipeline.
pub fn receipt_digest(signed: &SignedServedDeliveryReceipt) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(&signed.body).as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::assert_canonical;

    fn base<'a>(nonce: &'a [u8; 32]) -> ServedDeliveryReceipt<'a> {
        ServedDeliveryReceipt {
            validator_id: b"validator-1",
            validator_nonce: nonce,
            epoch: 42,
            vm_id: "abc",
            lease_id: "lease-1",
            family_id: b"family-1",
            node_id: b"node-1",
            resource_class: "std",
            monotonic_seq: 1,
            observed_degradation_bps: 0,
            period_start: 1_000,
            period_end: 1_060,
            expiry: 2_000,
            disk_io: None,
            disk_probe: None,
        }
    }

    #[test]
    fn canonical_is_stable_and_canonical() {
        let n = [3u8; 32];
        let r = base(&n);
        let a = r.canonical().unwrap();
        let b = r.canonical().unwrap();
        assert_eq!(a, b);
        assert_canonical(&a).unwrap();
    }

    #[test]
    fn degradation_out_of_range_rejected() {
        let n = [3u8; 32];
        let mut r = base(&n);
        r.observed_degradation_bps = DEGRADATION_MAX_BPS + 1;
        assert!(r.canonical().is_err());
    }

    #[test]
    fn period_inverted_rejected() {
        let n = [3u8; 32];
        let mut r = base(&n);
        r.period_start = 2_000;
        r.period_end = 1_000;
        assert!(r.canonical().is_err());
    }

    #[test]
    fn expiry_before_period_end_rejected() {
        let n = [3u8; 32];
        let mut r = base(&n);
        r.expiry = 100;
        r.period_end = 1_060;
        assert!(r.canonical().is_err());
    }

    #[test]
    fn changing_any_replay_field_changes_bytes() {
        let n = [3u8; 32];
        let r = base(&n);
        let base_bytes = r.canonical().unwrap();
        // Spot-check a representative field per category.
        let mut bumped = r.clone();
        bumped.epoch = 43;
        assert_ne!(base_bytes, bumped.canonical().unwrap());
        let mut bumped = r.clone();
        bumped.monotonic_seq = 2;
        assert_ne!(base_bytes, bumped.canonical().unwrap());
        let mut bumped = r.clone();
        bumped.resource_class = "high-mem";
        assert_ne!(base_bytes, bumped.canonical().unwrap());
        let mut bumped = r.clone();
        bumped.lease_id = "lease-2";
        assert_ne!(base_bytes, bumped.canonical().unwrap());
        let other = [9u8; 32];
        let mut bumped = r;
        bumped.validator_nonce = &other;
        assert_ne!(base_bytes, bumped.canonical().unwrap());
    }

    #[test]
    fn changing_validator_id_diverges() {
        // Two validators reusing the same fresh nonce would otherwise
        // be able to roll the same receipt into different aggregates.
        // Binding `validator_id` into the signed body kills that.
        let n = [3u8; 32];
        let mut r = base(&n);
        let bytes_a = r.canonical().unwrap();
        r.validator_id = b"validator-attacker";
        let bytes_b = r.canonical().unwrap();
        assert_ne!(bytes_a, bytes_b);
    }

    #[test]
    fn receipt_digest_is_stable() {
        let n = [3u8; 32];
        let body = base(&n).canonical().unwrap();
        let s = SignedServedDeliveryReceipt {
            body,
            sig: vec![0u8; 64],
        };
        let d1 = receipt_digest(&s);
        let d2 = receipt_digest(&s);
        assert_eq!(d1, d2);
        // Length sanity.
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn signed_receipt_canonical_is_stable_and_canonical() {
        let n = [3u8; 32];
        let body = base(&n).canonical().unwrap();
        let s = SignedServedDeliveryReceipt {
            body,
            sig: vec![7u8; 64],
        };
        let a = s.canonical().unwrap();
        let b = s.canonical().unwrap();
        // Deterministic — and genuinely canonical (keys byte-sorted:
        // `sig` encodes shorter than `body`, so the encoder reorders).
        assert_eq!(a, b);
        assert_canonical(&a).unwrap();
    }

    fn io(dev: &str) -> crate::disk_stats::DiskIoDelta {
        crate::disk_stats::DiskIoDelta {
            dev: dev.into(),
            serial: String::new(),
            state: crate::disk_stats::DiskIoState::Ok,
            r_ios: 1,
            r_sectors: 8,
            r_ticks_ms: 1,
            w_ios: 1,
            w_sectors: 8,
            w_ticks_ms: 1,
            io_ticks_ms: 2,
            tiq_ms: 2,
            inflight: 0,
            init_percent: None,
        }
    }

    fn probe(vm_id: &str) -> DiskProbeResult {
        DiskProbeResult {
            run_id: [1; 16],
            nonce: [2; 32],
            vm_id: vm_id.into(),
            vcpus: 2,
            kernel: "6.8".into(),
            release_version: 5,
            started_at: 1,
            finished_at: 2,
            targets: vec![crate::disk_stats::DiskProbeTarget {
                slot: "os".into(),
                profile: "v1".into(),
                metrics: vec![("qd1_p50_us".into(), 90)],
                hist_qd1: vec![0; crate::disk_stats::HIST_BUCKETS],
                error: String::new(),
            }],
        }
    }

    #[test]
    fn disk_keys_are_emitted_only_when_some() {
        let n = [3u8; 32];
        let plain = base(&n).canonical().unwrap();
        let devices = [io("vda"), io("vdb")];
        let mut with_io = base(&n);
        with_io.disk_io = Some(&devices);
        let io_bytes = with_io.canonical().unwrap();
        assert_ne!(plain, io_bytes);
        assert_canonical(&io_bytes).unwrap();
        let p = probe("abc");
        let mut with_probe = base(&n);
        with_probe.disk_probe = Some(&p);
        let probe_bytes = with_probe.canonical().unwrap();
        assert_ne!(plain, probe_bytes);
        assert_canonical(&probe_bytes).unwrap();
    }

    #[test]
    fn an_empty_disk_io_is_refused() {
        let n = [3u8; 32];
        let mut r = base(&n);
        r.disk_io = Some(&[]);
        assert!(r.canonical().is_err());
    }

    #[test]
    fn a_probe_for_another_vm_is_refused() {
        let n = [3u8; 32];
        let p = probe("other-vm");
        let mut r = base(&n);
        r.disk_probe = Some(&p);
        assert!(r.canonical().is_err());
    }

    #[test]
    fn an_over_long_identifier_is_refused() {
        let n = [3u8; 32];
        let long = "v".repeat(MAX_RECEIPT_ID_LEN + 1);
        let mut r = base(&n);
        r.vm_id = &long;
        assert!(r.canonical().is_err());
        let mut r = base(&n);
        r.lease_id = &long[..MAX_RECEIPT_ID_LEN];
        assert!(r.canonical().is_ok());
    }

    /// Every identifier and every disk-evidence bound at its maximum: the
    /// signed envelope still fits the guest's 16 KiB vsock frame
    /// (`agent-tenant-telemetry`'s `MAX_FRAME_BYTES`).
    #[test]
    fn worst_case_receipt_fits_the_guest_frame() {
        use crate::disk_stats::*;
        let id = "i".repeat(MAX_RECEIPT_ID_LEN);
        // A probe receipt's vm_id is also the probe's, so it is bounded by
        // the tighter MAX_PROBE_VM_ID_LEN.
        let vm_id = "v".repeat(MAX_PROBE_VM_ID_LEN);
        let n = [0xffu8; 32];
        // The longest distinct serials: `hippius-x10`..`hippius-x23`,
        // `hippius-os`, then empty.
        let serials: Vec<String> = (10..=23)
            .map(|i| format!("hippius-x{i}"))
            .chain(["hippius-os".to_string(), String::new()])
            .collect();
        assert_eq!(serials.len(), MAX_DISK_IO_DEVICES);
        let io: Vec<DiskIoDelta> = serials
            .into_iter()
            .enumerate()
            .map(|(i, serial)| DiskIoDelta {
                dev: format!("{i:02}{}", "d".repeat(MAX_DEV_LEN - 2)),
                serial,
                state: DiskIoState::Ok,
                r_ios: u64::MAX,
                r_sectors: u64::MAX,
                r_ticks_ms: u64::MAX,
                w_ios: u64::MAX,
                w_sectors: u64::MAX,
                w_ticks_ms: u64::MAX,
                io_ticks_ms: u64::MAX,
                tiq_ms: u64::MAX,
                inflight: u64::MAX,
                init_percent: None,
            })
            .collect();
        let slots: Vec<String> = core::iter::once("os".to_string())
            .chain((10..10 + MAX_PROBE_TARGETS - 1).map(|i| format!("x{i}")))
            .collect();
        let mut slots = slots;
        slots.sort();
        let probe = DiskProbeResult {
            run_id: [0xff; 16],
            nonce: [0xff; 32],
            vm_id: vm_id.clone(),
            vcpus: u32::MAX,
            kernel: "k".repeat(MAX_KERNEL_LEN),
            release_version: u32::MAX,
            started_at: u64::MAX,
            finished_at: u64::MAX,
            targets: slots
                .iter()
                .map(|slot| DiskProbeTarget {
                    slot: slot.clone(),
                    profile: "p".repeat(MAX_PROFILE_LEN),
                    metrics: (0..MAX_PROBE_METRICS)
                        .map(|i| {
                            (
                                format!("{i:02}{}", "m".repeat(MAX_METRIC_KEY_LEN - 2)),
                                u64::MAX,
                            )
                        })
                        .collect(),
                    hist_qd1: vec![u32::MAX; HIST_BUCKETS],
                    error: "e".repeat(48),
                })
                .collect(),
        };
        let r = ServedDeliveryReceipt {
            validator_id: id.as_bytes(),
            validator_nonce: &n,
            epoch: u64::MAX,
            vm_id: &vm_id,
            lease_id: &id,
            family_id: id.as_bytes(),
            node_id: id.as_bytes(),
            resource_class: &id,
            monotonic_seq: u64::MAX,
            observed_degradation_bps: DEGRADATION_MAX_BPS,
            period_start: u64::MAX,
            period_end: u64::MAX,
            expiry: u64::MAX,
            disk_io: Some(&io),
            disk_probe: Some(&probe),
        };
        let signed = SignedServedDeliveryReceipt {
            body: r.canonical().unwrap(),
            sig: vec![0xff; 64],
        }
        .canonical()
        .unwrap();
        // The guest frame wraps it as `{kind: "served-receipt", body}`.
        let frame = to_canonical_vec(&Value::Map(vec![
            (
                Value::Text("kind".into()),
                Value::Text("served-receipt".into()),
            ),
            (Value::Text("body".into()), Value::Bytes(signed)),
        ]))
        .unwrap();
        assert!(
            frame.len() < 16 * 1024,
            "worst-case receipt frame is {} bytes",
            frame.len()
        );
    }
}
