//! Cross-impl conformance test vectors (ARCHITECTURE.md §N).
//!
//! Every signed wire format in the stack has a deterministic-CBOR
//! body. This test file:
//! 1. Computes the canonical body for a small set of fixed inputs.
//! 2. Asserts the SHA-256 of the body matches a committed constant.
//!
//! That constant is the cross-impl source of truth. Any other Hippius
//! impl (TS/Python tooling, the on-chain pallet, an audit tool) MUST
//! reproduce the same hash for the same inputs — if it can't, schemas
//! have drifted and the build/CI fails closed.
//!
//! Updating a fixture (deliberate schema change): run the test, copy
//! the new hash printed in the panic message into the constant. The
//! intent of the change should be documented in the commit message
//! and reflected in `test_vectors/README.md`.
//!
//! Adding a new fixture: append a new test case + its hash. There is
//! no separate generator script — fixtures live as Rust constants so
//! the inputs and expected hashes never get out of sync.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hippius_types::audit_vm::{
    map_root, totals_root, ResourceClassTotal, ServedDeliveryAggregate, ServedReceiptEntry,
};
use hippius_types::digest::userdata_digest;
use hippius_types::disk_stats::{
    DiskIoDelta, DiskIoState, DiskProbeResult, DiskProbeTarget, HIST_BUCKETS,
};
use hippius_types::release::ReleaseContext;
use hippius_types::served_receipt::ServedDeliveryReceipt;
use hippius_types::stopped::StoppedAck;
use sha2::{Digest, Sha256};

fn hex_sha(bytes: &[u8]) -> String {
    let h = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in h.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Helper: assert the SHA-256 of the canonical bytes equals
/// `expected_hex`. On mismatch the panic message includes the actual
/// hex, so the operator can update the constant in one round-trip.
fn check(name: &str, body: &[u8], expected_hex: &str) {
    let got = hex_sha(body);
    assert_eq!(
        got,
        expected_hex,
        "conformance vector `{name}` DRIFTED. \
         Either the schema changed (update the constant + bump the \
         test_vectors version) or a serialization regression slipped in. \
         body_len={} body_sha256={got}",
        body.len()
    );
}

#[test]
fn vector_release_context_luks() {
    // Fixed inputs — DO NOT change without bumping test_vectors/v1.
    let nonce = [0x01u8; 32];
    let meas = [0x07u8; 48];
    let digest = [0xAAu8; 32];
    let ctx = ReleaseContext {
        v: 1,
        ticket_id: "tk-1",
        tenant_id: "t",
        vm_id: "abc",
        vm_generation: 5,
        kbs_nonce: &nonce,
        measurement: &meas,
        kbs_kid: b"kbs-kid",
        secret_type: "luks",
        secret_path: "kbs/vm/abc/luks",
        secret_version: 3,
        allowed_userdata_digest: &digest,
    };
    let body = ctx.canonical().unwrap();
    check(
        "release_context.luks",
        &body,
        "d29fe031eeb9c9b55cf7ffa752ba7eb77ac8850d58ec23e2fcd18950fbe81f09",
    );
}

#[test]
fn vector_release_context_userdata() {
    let nonce = [0x01u8; 32];
    let meas = [0x07u8; 48];
    let digest = [0xAAu8; 32];
    let ctx = ReleaseContext {
        v: 1,
        ticket_id: "tk-1",
        tenant_id: "t",
        vm_id: "abc",
        vm_generation: 5,
        kbs_nonce: &nonce,
        measurement: &meas,
        kbs_kid: b"kbs-kid",
        secret_type: "userdata",
        secret_path: "kbs/vm/abc/ud",
        secret_version: 2,
        allowed_userdata_digest: &digest,
    };
    let body = ctx.canonical().unwrap();
    check(
        "release_context.userdata",
        &body,
        "f04e5768c75ccf1625ba81e8f063bbef7312444bd2ef4e952dfd2d2d51bbef23",
    );
}

#[test]
fn vector_userdata_digest() {
    let d = userdata_digest(
        "t",
        "abc",
        "tk-1",
        "userdata",
        "kbs/vm/abc/ud",
        2,
        b"USERDATA-PAYLOAD",
    );
    check(
        "userdata_digest",
        &d,
        "aea4051243e69321b8f7b482cdb9dcc06059e2dba34d88e4fe0b69e2e4b86176",
    );
}

#[test]
fn vector_stopped_ack() {
    let nonce = [0x33u8; 32];
    let ack = StoppedAck {
        vm_id: "abc",
        lease_id: "lease-1",
        vm_generation: 7,
        nonce: &nonce,
        now_unix: 1_000_000,
    };
    let body = ack.canonical().unwrap();
    check(
        "stopped_ack.basic",
        &body,
        "d8f90394516ec9dfa06300bd8ff061796c7fabb936835a246072285719659367",
    );
}

#[test]
fn vector_served_delivery_receipt() {
    let nonce = [0x44u8; 32];
    let r = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &nonce,
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
    };
    let body = r.canonical().unwrap();
    check(
        "served_delivery_receipt.basic",
        &body,
        "69f4bb21ccf75c904929eaa70d78afcbc4a46e6a8dfd4c0f593e991a4725cb75",
    );
}

/// The `basic` receipt plus `disk_io`: an OS-disk device and a dedicated
/// slot, plus a dedicated slot the guest could not find.
#[test]
fn vector_served_delivery_receipt_disk_io() {
    let nonce = [0x44u8; 32];
    let io = [
        DiskIoDelta {
            dev: String::new(),
            serial: "hippius-x1".into(),
            state: DiskIoState::Missing,
            r_ios: 0,
            r_sectors: 0,
            r_ticks_ms: 0,
            w_ios: 0,
            w_sectors: 0,
            w_ticks_ms: 0,
            io_ticks_ms: 0,
            tiq_ms: 0,
            inflight: 0,
            init_percent: None,
        },
        DiskIoDelta {
            dev: "vda".into(),
            serial: String::new(),
            state: DiskIoState::Ok,
            r_ios: 1_200,
            r_sectors: 96_000,
            r_ticks_ms: 340,
            w_ios: 800,
            w_sectors: 64_000,
            w_ticks_ms: 910,
            io_ticks_ms: 1_100,
            tiq_ms: 1_250,
            inflight: 2,
            init_percent: None,
        },
        DiskIoDelta {
            dev: "vde".into(),
            serial: "hippius-x0".into(),
            state: DiskIoState::Ok,
            r_ios: 30,
            r_sectors: 61_440,
            r_ticks_ms: 450,
            w_ios: 12,
            w_sectors: 24_576,
            w_ticks_ms: 160,
            io_ticks_ms: 600,
            tiq_ms: 610,
            inflight: 0,
            init_percent: None,
        },
    ];
    let r = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &nonce,
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
        disk_io: Some(&io),
        disk_probe: None,
    };
    let body = r.canonical().unwrap();
    check(
        "served_delivery_receipt.disk_io",
        &body,
        "7712fa8220685dce4c53cd5fa36f4b4f10c7dba195678f1f1d65f4033b84138f",
    );
}

/// The `basic` receipt plus `disk_io`: a dedicated integrity slot whose
/// first-boot wipe is 42 % done (`initializing` + `init_percent`, guest
/// release 8), and one that just started (no percent yet).
#[test]
fn vector_served_delivery_receipt_disk_io_initializing() {
    let nonce = [0x44u8; 32];
    let slot = |dev: &str, serial: &str, init_percent: Option<u8>| DiskIoDelta {
        dev: dev.into(),
        serial: serial.into(),
        state: DiskIoState::Initializing,
        r_ios: 0,
        r_sectors: 0,
        r_ticks_ms: 0,
        w_ios: 4_096,
        w_sectors: 33_554_432,
        w_ticks_ms: 52_000,
        io_ticks_ms: 59_000,
        tiq_ms: 410_000,
        inflight: 8,
        init_percent,
    };
    let io = [
        slot("vdb", "hippius-x0", Some(42)),
        slot("vdc", "hippius-x1", None),
    ];
    let r = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &nonce,
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
        disk_io: Some(&io),
        disk_probe: None,
    };
    let body = r.canonical().unwrap();
    check(
        "served_delivery_receipt.disk_io_initializing",
        &body,
        "99a95e50d9d594519059147740bca7a77f2e04636642f1c38937b11a2cd48855",
    );
}

/// The `basic` receipt plus a probe result for the OS disk (profile `v1`)
/// and one dedicated disk (profile `d1`).
#[test]
fn vector_served_delivery_receipt_disk_probe() {
    let nonce = [0x44u8; 32];
    let mut hist = vec![0u32; HIST_BUCKETS];
    hist[6] = 900;
    hist[7] = 95;
    hist[10] = 5;
    let metrics = |pairs: &[(&str, u64)]| -> Vec<(String, u64)> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    };
    let probe = DiskProbeResult {
        run_id: [0x55u8; 16],
        nonce: [0x66u8; 32],
        vm_id: "abc".into(),
        vcpus: 2,
        kernel: "6.8.0-110-generic".into(),
        release_version: 5,
        started_at: 1_010,
        finished_at: 1_290,
        targets: vec![
            DiskProbeTarget {
                slot: "os".into(),
                profile: "v1".into(),
                metrics: metrics(&[
                    ("qd1_p50_us", 92),
                    ("qd1_p99_us", 410),
                    ("rr_iops", 61_000),
                    ("rr_p99_us", 2_900),
                    ("rw_iops", 24_000),
                    ("rw_p99_us", 6_100),
                    ("seq_read_mbps", 2_100),
                    ("seq_write_mbps", 1_150),
                    ("wipe_mbps", 1_400),
                ]),
                hist_qd1: hist.clone(),
                error: String::new(),
            },
            DiskProbeTarget {
                slot: "x0".into(),
                profile: "d1".into(),
                metrics: metrics(&[
                    ("qd1_p50_us", 4_100),
                    ("qd1_p99_us", 24_000),
                    ("rr_iops", 420),
                    ("seq_read_inner_mbps", 110),
                    ("seq_read_outer_mbps", 260),
                    ("surface_errors", 0),
                    ("sustained_rw_iops", 310),
                ]),
                hist_qd1: hist,
                error: String::new(),
            },
        ],
    };
    let r = ServedDeliveryReceipt {
        validator_id: b"validator-1",
        validator_nonce: &nonce,
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
        disk_probe: Some(&probe),
    };
    let body = r.canonical().unwrap();
    check(
        "served_delivery_receipt.disk_probe",
        &body,
        "576cfa368fe962486137e7549ea47852c288171342e08c2834b436ff4da714b1",
    );
}

#[test]
fn vector_served_delivery_aggregate() {
    let cg = [0x11u8; 32];
    let pi = [0x22u8; 32];
    let cn = [0x33u8; 32];
    let mr = [0x44u8; 32];
    let tr = [0x55u8; 32];
    let ph = [0x66u8; 32];
    let agg = ServedDeliveryAggregate {
        chain_genesis: &cg,
        pallet_instance: &pi,
        validator_id: b"validator-1",
        family_id: b"family-1",
        node_id: b"node-1",
        audit_vm_key_id: b"audit-vm-key-1",
        epoch: 100,
        challenge_nonce: &cn,
        interval_start: 1_000,
        interval_end: 1_060,
        map_root: &mr,
        totals_root: &tr,
        prev_aggregate_hash: &ph,
        expiry: 2_000,
    };
    let body = agg.canonical().unwrap();
    check(
        "served_delivery_aggregate.basic",
        &body,
        "3a32cf38a54a24fcfa8dcbb3f24ea4ce88806893eb980b7bdb8127d612e06ac6",
    );
}

#[test]
fn vector_map_root_single() {
    let entries = [ServedReceiptEntry {
        vm_id: "vm-a".into(),
        lease_id: "lease-1".into(),
        monotonic_seq: 1,
        digest: vec![0xAAu8; 32],
    }];
    let root = map_root(&entries).unwrap();
    check(
        "map_root.single_entry",
        &root,
        "2f4d89e2a3cfd26d380141530af690a1b7a9747c96aedac2353617507467a4b6",
    );
}

#[test]
fn vector_totals_root_small_and_large() {
    let totals = [
        ResourceClassTotal {
            class: "high-mem".into(),
            served_units: 100,
        },
        ResourceClassTotal {
            class: "std".into(),
            served_units: u128::from(u64::MAX) + 1,
        },
    ];
    let root = totals_root(&totals).unwrap();
    check(
        "totals_root.boundary",
        &root,
        "169b385866616b549950c11045fbd86766800a774c9443e0755bc259270c33b6",
    );
}
