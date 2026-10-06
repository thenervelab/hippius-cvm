//! The SHARED KBS audit-read wire fixture:
//! `hippius-types/tests/fixtures/kbs_audit_wire_v1.json`.
//!
//! vali's audit ingester (`vali/apps/orchestration/kbs_audit.py`) loads
//! the same file in its tests, so the two sides cannot drift: every page
//! in it is PRODUCED here by the real sinks (`FileAuditSink`,
//! `FileAdminAuditSink`) through the real `read_page` + `to_wire` the
//! `GET /v1/admin/audit` handler serves, and compared byte for byte with
//! the file.
//!
//! It holds three chains: the release and admin chains of one KBS life
//! ("epoch a"), and the release chain of the NEXT life ("epoch b" — a
//! fresh emptyDir after a restart: `seq` restarts at 0 under a new
//! genesis). Pages are cut with a small `limit` so pagination is on the
//! wire too.
//!
//! Two more chains carry a crash: `release_torn` / `admin_torn` are a
//! KBS whose process died mid-append (a torn trailing line) and restarted
//! in the SAME pod — the open truncated the torn line and chained an
//! `audit-truncated` record in its place (`kbs_core::audit_journal`),
//! which vali records as a `torn-tail-truncated` anomaly.
//!
//! Regenerate: `HIPPIUS_REGEN_KBS_AUDIT_WIRE_FIXTURE=1 cargo test -p
//! kbs-core --test kbs_audit_wire_fixture`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use kbs_core::admin_audit::{AdminAuditRecord, FileAdminAuditSink};
use kbs_core::audit::FileAuditSink;
use kbs_core::audit_read::{AuditLogKind, AuditPage};
use serde_json::{json, Value};

const REGEN_ENV: &str = "HIPPIUS_REGEN_KBS_AUDIT_WIRE_FIXTURE";
const CANARY_VM: &str = "3f1c2b9e-6a4d-4e2b-9c1a-0d5e7f8a9b10";
const OTHER_VM: &str = "7d0e5c4b-1a2f-4b3c-8d9e-0f1a2b3c4d5e";
const PAGE_LIMIT: u32 = 2;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../hippius-types/tests/fixtures/kbs_audit_wire_v1.json")
}

/// Every page of a chain, `PAGE_LIMIT` at a time, plus the trailing empty
/// page a caught-up reader sees.
fn pages(read: impl Fn(Option<u64>, u32) -> AuditPage, kind: AuditLogKind) -> Value {
    let mut out = Vec::new();
    let mut after: Option<u64> = None;
    loop {
        let page = read(after, PAGE_LIMIT);
        let text = serde_json::to_string(&page.to_wire(kind)).unwrap();
        out.push(json!({
            "after_seq": after,
            "limit": PAGE_LIMIT,
            "body_text": text,
        }));
        match page.entries.last() {
            Some(e) => after = Some(e.seq),
            None => break,
        }
    }
    Value::Array(out)
}

fn produce() -> Value {
    let td = tempfile::TempDir::new().unwrap();

    // ── epoch a: release chain ────────────────────────────────────
    let rel_a = FileAuditSink::open(td.path().join("a/audit")).unwrap();
    rel_a
        .append(
            false,
            Some("tk-0001"),
            Some(CANARY_VM),
            "measurement_not_allowed",
            1_790_000_000,
        )
        .unwrap();
    rel_a
        .append(
            true,
            Some("tk-0002"),
            Some(CANARY_VM),
            "released",
            1_790_000_060,
        )
        .unwrap();
    rel_a
        .append(false, None, None, "ticket_decode", 1_790_000_120)
        .unwrap();
    rel_a
        .append(
            true,
            Some("tk-0003"),
            Some(OTHER_VM),
            "released",
            1_790_000_180,
        )
        .unwrap();

    // ── epoch a: admin chain ──────────────────────────────────────
    let adm_a = FileAdminAuditSink::open(td.path().join("a/audit/admin")).unwrap();
    let body_sha = [0x5c; 32];
    let rec = |op: &'static str,
               vm: &'static str,
               applied: bool,
               status: u16,
               reason: Option<&'static str>| AdminAuditRecord {
        op,
        url_vm_id: vm,
        ticket_id: Some("tk-0002"),
        vm_id: Some(vm),
        applied,
        status_code: status,
        reason,
        peer_san: Some("spiffe://hippius.network/vali"),
        peer_serial: Some("3a9f"),
        body_sha256: &body_sha,
    };
    adm_a
        .append(
            &rec("register-vm", CANARY_VM, true, 200, None),
            1_789_999_990,
        )
        .unwrap();
    adm_a
        .append(
            &rec("activate", CANARY_VM, false, 409, Some("state-divergent")),
            1_790_000_030,
        )
        .unwrap();
    adm_a
        .append(
            &rec("decommission", OTHER_VM, true, 200, None),
            1_790_000_300,
        )
        .unwrap();

    // ── epoch b: the release chain of the next KBS life ───────────
    let rel_b = FileAuditSink::open(td.path().join("b/audit")).unwrap();
    rel_b
        .append(
            true,
            Some("tk-0004"),
            Some(CANARY_VM),
            "released",
            1_790_086_400,
        )
        .unwrap();
    rel_b
        .append(
            true,
            Some("tk-0005"),
            Some(OTHER_VM),
            "released",
            1_790_086_460,
        )
        .unwrap();

    // ── a crash mid-append, then a restart in the same pod ─────────
    let torn_dir = td.path().join("torn/audit");
    let rel_t = FileAuditSink::open(&torn_dir).unwrap();
    rel_t
        .append(
            true,
            Some("tk-0006"),
            Some(CANARY_VM),
            "released",
            1_790_090_000,
        )
        .unwrap();
    rel_t
        .append(false, None, None, "ticket_decode", 1_790_090_060)
        .unwrap();
    drop(rel_t);
    append_torn(&torn_dir.join("audit.log"), b"2:a8666");
    let rel_t = FileAuditSink::open_at(&torn_dir, 1_790_090_100).unwrap();
    rel_t
        .append(
            true,
            Some("tk-0007"),
            Some(CANARY_VM),
            "released",
            1_790_090_120,
        )
        .unwrap();

    let adm_torn_dir = torn_dir.join("admin");
    let adm_t = FileAdminAuditSink::open(&adm_torn_dir).unwrap();
    adm_t
        .append(
            &rec("register-vm", CANARY_VM, true, 200, None),
            1_790_089_990,
        )
        .unwrap();
    drop(adm_t);
    append_torn(&adm_torn_dir.join("admin.log"), b"1:ae6e02");
    let adm_t = FileAdminAuditSink::open_at(&adm_torn_dir, 1_790_090_100).unwrap();
    adm_t
        .append(&rec("activate", CANARY_VM, true, 200, None), 1_790_090_130)
        .unwrap();

    json!({
        "v": 1,
        "about": "GET /v1/admin/audit pages produced by the real KBS sinks — see \
                  kbs-core/tests/kbs_audit_wire_fixture.rs",
        "canary_vm_id": CANARY_VM,
        "release_epoch_a": pages(|a, l| rel_a.read_page(a, l).unwrap(), AuditLogKind::Release),
        "admin_epoch_a": pages(|a, l| adm_a.read_page(a, l).unwrap(), AuditLogKind::Admin),
        "release_epoch_b": pages(|a, l| rel_b.read_page(a, l).unwrap(), AuditLogKind::Release),
        "release_torn": pages(|a, l| rel_t.read_page(a, l).unwrap(), AuditLogKind::Release),
        "admin_torn": pages(|a, l| adm_t.read_page(a, l).unwrap(), AuditLogKind::Admin),
    })
}

/// What a process killed in the middle of its `write(2)` leaves.
fn append_torn(log: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(log).unwrap();
    f.write_all(bytes).unwrap();
}

#[test]
fn the_torn_lives_carry_their_truncation_marker() {
    let v = produce();
    for (chain, seq, key, want) in [
        (
            "release_torn",
            2,
            "reason",
            "audit-truncated:seq=2:len=7:sha256=",
        ),
        ("admin_torn", 1, "op", "audit-truncated"),
    ] {
        let entries: Vec<Value> = v[chain]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|p| {
                let page: Value = serde_json::from_str(p["body_text"].as_str().unwrap()).unwrap();
                page["entries"].as_array().unwrap().clone()
            })
            .collect();
        let e = entries.iter().find(|e| e["seq"] == seq).unwrap();
        let body = hex::decode(e["body_cbor_hex"].as_str().unwrap()).unwrap();
        let m: ciborium::value::Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let text = m
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .and_then(|(_, v)| v.as_text())
            .unwrap()
            .to_string();
        assert!(text.starts_with(want), "{chain}: {text}");
        assert_eq!(entries.len() as u64, seq + 2, "{chain}: the chain went on");
    }
}

#[test]
fn the_shared_kbs_audit_wire_fixture_matches_the_real_code() {
    let want = serde_json::to_string_pretty(&produce()).unwrap() + "\n";
    let path = fixture_path();
    if std::env::var_os(REGEN_ENV).is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} — regenerate with {REGEN_ENV}=1", path.display()));
    assert!(
        have == want,
        "{} is stale: the audit-read wire changed. If that is intended, regenerate with \
         {REGEN_ENV}=1 and update vali to the new fixture.",
        path.display()
    );
}

#[test]
fn the_two_lives_have_different_genesis_and_both_start_at_seq_0() {
    let v = produce();
    let first = |k: &str| -> Value {
        serde_json::from_str(v[k][0]["body_text"].as_str().unwrap()).unwrap()
    };
    let (a, b) = (first("release_epoch_a"), first("release_epoch_b"));
    assert_eq!(a["entries"][0]["seq"], 0);
    assert_eq!(b["entries"][0]["seq"], 0);
    assert_ne!(a["genesis_hash_hex"], b["genesis_hash_hex"]);
    assert_eq!(a["genesis_hash_hex"], a["entries"][0]["sha256_hex"]);
}
