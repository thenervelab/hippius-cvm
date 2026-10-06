//! The SHARED rollback wire fixtures (contract C-4):
//! `hippius-types/tests/fixtures/rollback_wire_v2.json` (current) and
//! `rollback_wire_v1.json` (frozen).
//!
//! vali loads the same files in its own tests, so the two sides cannot
//! drift: every body in the v2 file is PRODUCED here by the real KBS code
//! (the signed V2 checkpoint, the arm, the status projection, every
//! refusal) and compared byte for byte with the file. A change to any of
//! them fails this test until the fixture is regenerated on purpose — and
//! then vali's tests fail until vali follows.
//!
//! The v1 file is what the KBS produced before stamp protocol v2. It is
//! no longer regenerated (the KBS signs only V2 checkpoints now); it is
//! kept, verbatim, because backups taken before V2 carry V1 checkpoints:
//! it must keep VERIFYING, and must never ARM (`checkpoint-not-timeline-bound`).
//!
//! Regenerate v2: `HIPPIUS_REGEN_ROLLBACK_WIRE_FIXTURE=1 cargo test -p
//! kbs-core --test rollback_wire_fixture`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use hippius_types::guardian::KeyMode;
use hippius_types::rollback::{AdminAuthorizeRollbackRequest, AdminAuthorizeRollbackResponse};
use kbs_core::boot_counter::{BootCounterStore, InMemoryBootCounterStore};
use kbs_core::error::{KbsError, Result};
use kbs_core::lifecycle::{VmState, VmStateStore};
use kbs_core::rollback::{
    process_authorize_rollback, process_rollback_checkpoint, rollback_capable, rollback_status,
    LastRollback, RollbackClear, RollbackErr, RollbackPolicy, CLEAR_DISARMED,
};
use kbs_core::volume_stamp::{
    InMemoryVolumeStampStore, ResolvedRollback, RollbackResolution, VolumeStampStore,
    GUEST_STAMP_PROTOCOL_ROLLBACK_MIN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REGEN_ENV: &str = "HIPPIUS_REGEN_ROLLBACK_WIRE_FIXTURE";

/// Fixed Ed25519 seed of the KBS response key the fixture is signed with.
const SIGNING_SEED: [u8; 32] = [0x5a; 32];
const VM_ID: &str = "3f1c2b9e-6a4d-4e2b-9c1a-0d5e7f8a9b10";
const SRC_CHIP: &str = "8899aabbccddeeff";
const DEST_CHIP: &str = "0011223344556677";
/// When the checkpoint is signed.
const CHECKPOINT_AT: u64 = 1_790_000_000;
/// When the arm is requested (and the status read).
const ARM_AT: u64 = 1_790_086_400;

fn fixture_path(version: u8) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../hippius-types/tests/fixtures/rollback_wire_v{version}.json"
    ))
}

/// The timeline the fixture VM is on at the backup point: it was rolled
/// back once before, so it is not the zero timeline.
const FIXTURE_TIMELINE: [u8; 32] = [0x5c; 32];

struct States(Mutex<HashMap<String, VmState>>);

impl VmStateStore for States {
    fn get(&self, vm_id: &str) -> Result<VmState> {
        self.0
            .lock()
            .map_err(|_| KbsError::Policy("poisoned".into()))?
            .get(vm_id)
            .cloned()
            .ok_or_else(|| KbsError::Lifecycle("no state for vm_id".into()))
    }
    fn key_mode(&self, _vm_id: &str) -> Result<KeyMode> {
        Ok(KeyMode::Hippius)
    }
}

/// One exact HTTP body: its bytes (as UTF-8 text) and the same JSON
/// parsed, for readers that want either.
fn body(status: u16, text: String) -> Value {
    let parsed: Value = serde_json::from_str(&text).unwrap();
    json!({"status": status, "body_text": text, "body": parsed})
}

/// Every refusal the four rollback routes can answer, one per reason.
/// The match is EXHAUSTIVE on purpose: a new `RollbackErr` variant does
/// not compile until it is given a fixture entry (and vali a test).
fn every_refusal() -> Vec<RollbackErr> {
    let samples = vec![
        RollbackErr::BadRequest("vm-id-empty"),
        RollbackErr::BadRequest("bad-restore-id"),
        RollbackErr::BadRequest("bad-manifest-sha256"),
        RollbackErr::BadRequest("bad-dest-platform-id"),
        RollbackErr::BadRequest("bad-requested-by"),
        RollbackErr::BadRequest("bad-new-gen"),
        RollbackErr::BadRequest("bad-point-manifest"),
        RollbackErr::BadCheckpointSignature,
        RollbackErr::CheckpointVmMismatch,
        RollbackErr::NotARollback { stored: 6 },
        RollbackErr::RowNotActivated,
        RollbackErr::ArmExists,
        RollbackErr::RateLimited {
            retry_after_s: 1200,
        },
        RollbackErr::TtlOutOfRange,
        RollbackErr::NoVmRow,
        RollbackErr::NoBootCounter,
        RollbackErr::VmFenced,
        RollbackErr::RestoreIdConsumed,
        RollbackErr::RollbackPending,
        RollbackErr::ClientCertRequired,
        RollbackErr::CheckpointUnstamped,
        RollbackErr::ManifestMismatch,
        RollbackErr::GuestNotRollbackCapable,
        RollbackErr::CheckpointNotTimelineBound,
        RollbackErr::GatewayRateLimited,
        RollbackErr::BodyTooLarge,
        RollbackErr::ClockUnavailable,
        RollbackErr::Unavailable,
        RollbackErr::CheckpointBodyDecode,
        RollbackErr::AuthorizeBodyDecode,
        RollbackErr::AuditUnavailable,
        RollbackErr::Internal("detail never reaches the wire".into()),
    ];
    for e in &samples {
        match e {
            RollbackErr::BadRequest(_)
            | RollbackErr::BadCheckpointSignature
            | RollbackErr::CheckpointVmMismatch
            | RollbackErr::NotARollback { .. }
            | RollbackErr::RowNotActivated
            | RollbackErr::ArmExists
            | RollbackErr::RateLimited { .. }
            | RollbackErr::TtlOutOfRange
            | RollbackErr::NoVmRow
            | RollbackErr::NoBootCounter
            | RollbackErr::VmFenced
            | RollbackErr::RestoreIdConsumed
            | RollbackErr::RollbackPending
            | RollbackErr::ClientCertRequired
            | RollbackErr::CheckpointUnstamped
            | RollbackErr::ManifestMismatch
            | RollbackErr::GuestNotRollbackCapable
            | RollbackErr::CheckpointNotTimelineBound
            | RollbackErr::GatewayRateLimited
            | RollbackErr::BodyTooLarge
            | RollbackErr::ClockUnavailable
            | RollbackErr::Unavailable
            | RollbackErr::CheckpointBodyDecode
            | RollbackErr::AuthorizeBodyDecode
            | RollbackErr::AuditUnavailable
            | RollbackErr::Internal(_) => {}
        }
    }
    samples
}

/// Build the whole fixture with the real code.
fn produce() -> Value {
    let sk = SigningKey::from_bytes(&SIGNING_SEED);
    let states = States(Mutex::new(HashMap::new()));
    let counters = InMemoryBootCounterStore::default();
    let stamps = InMemoryVolumeStampStore::default();

    // The VM at the backup point: gen 2 on SRC, counter 4, confirmed
    // stamp 3, one release since that confirm.
    states.0.lock().unwrap().insert(
        VM_ID.into(),
        VmState::Active {
            gen: 2,
            host: SRC_CHIP.into(),
            lease_id: "lease-1".into(),
        },
    );
    counters.seed(VM_ID, 4).unwrap();
    for v in 1..=3 {
        stamps.confirm(VM_ID, v).unwrap();
    }
    // An earlier (delivered) rollback moved the VM to FIXTURE_TIMELINE.
    stamps
        .apply_rollback(VM_ID, 3, 1, "restore-fixture-0", &FIXTURE_TIMELINE)
        .unwrap();
    stamps
        .finalize_rollback(VM_ID, "restore-fixture-0")
        .unwrap();
    stamps.note_release(VM_ID).unwrap();

    // (a) rollback-checkpoint 200.
    let cp = process_rollback_checkpoint(VM_ID, &states, &counters, &stamps, &sk, CHECKPOINT_AT)
        .unwrap();
    let cp_wire = cp.to_wire();
    let checkpoint_text = serde_json::to_string(&cp_wire).unwrap();

    // (b) the point's manifest (vali's shape: the checkpoint response
    // under `kbs_rollback_checkpoint`) and the authorize-rollback body.
    let manifest = serde_json::to_vec(&json!({
        "vm_id": VM_ID,
        "boot_counter": 4,
        "kbs_rollback_checkpoint": cp_wire,
    }))
    .unwrap();
    let request = AdminAuthorizeRollbackRequest {
        checkpoint_cbor_hex: cp_wire.checkpoint_cbor_hex.clone(),
        signature_hex: cp_wire.signature_hex.clone(),
        point_manifest_sha256_hex: hex::encode(Sha256::digest(&manifest)),
        point_manifest_b64: base64::engine::general_purpose::STANDARD.encode(&manifest),
        new_gen: 3,
        dest_platform_id_hex: DEST_CHIP.into(),
        restore_id: "restore-fixture-2".into(),
        ttl_s: 1800,
        requested_by: "tenant:42".into(),
    };
    let request_text = serde_json::to_string(&request).unwrap();

    // The VM booted twice more, then vali activated gen 3 on DEST; its
    // guest speaks the timeline-bound stamp protocol. The request above
    // then ARMS with the real code (proof it is a valid request).
    counters.check_and_advance(VM_ID, 5).unwrap();
    counters.check_and_advance(VM_ID, 6).unwrap();
    states.0.lock().unwrap().insert(
        VM_ID.into(),
        VmState::Migrating {
            old_gen: 2,
            new_gen: 3,
            source: SRC_CHIP.into(),
            dest: DEST_CHIP.into(),
            lease_id: "lease-1".into(),
        },
    );
    stamps
        .record_guest_stamp_protocol(VM_ID, GUEST_STAMP_PROTOCOL_ROLLBACK_MIN)
        .unwrap();
    let armed = process_authorize_rollback(
        VM_ID,
        &request,
        &states,
        &counters,
        &stamps,
        &sk.verifying_key(),
        &RollbackPolicy::default(),
        Some("spiffe://hippius.network/vali"),
        ARM_AT,
    )
    .unwrap();
    assert!(armed.fresh);
    // The arm recorded its checkpoint's timeline: the `expected` timeline
    // of the one release it admits.
    assert_eq!(
        stamps.arm_timeline(VM_ID, "restore-fixture-2").unwrap(),
        Some(FIXTURE_TIMELINE)
    );
    let armed_text = serde_json::to_string(&AdminAuthorizeRollbackResponse {
        arm: armed.arm.to_wire(),
    })
    .unwrap();

    // (c) GET …/rollback: the live arm, a delivered earlier rollback,
    // and an earlier arm that was disarmed.
    let last = LastRollback {
        restore_id: "restore-fixture-0".into(),
        manifest_sha256_hex: "ab".repeat(32),
        from_counter: 1,
        to_counter: 3,
        stamp: 1,
        consumed_at_unix: CHECKPOINT_AT - 86_400,
        requested_by: "superuser:7".into(),
    };
    let resolution = ResolvedRollback {
        restore_id: "restore-fixture-0".into(),
        resolution: RollbackResolution::Delivered,
    };
    let clear = RollbackClear {
        restore_id: "restore-fixture-1".into(),
        reason: CLEAR_DISARMED.into(),
        at_unix: CHECKPOINT_AT - 3_600,
    };
    let status = rollback_status(
        Some(&armed.arm),
        Some(&last),
        Some(&resolution),
        Some(&clear),
        rollback_capable(VM_ID, &states, &stamps).unwrap(),
        ARM_AT,
    );
    let status_text = serde_json::to_string(&status).unwrap();

    // (d) one refusal body per reason.
    let refusals: Vec<Value> = every_refusal()
        .iter()
        .map(|e| {
            let text = serde_json::to_string(&e.to_wire(VM_ID)).unwrap();
            let mut v = body(e.status_code(), text);
            v["reason"] = json!(e.reason());
            v
        })
        .collect();

    json!({
        "version": 2,
        "about": "C-4 rollback wire, produced by kbs-core/tests/rollback_wire_fixture.rs. \
                  body_text is the exact HTTP body; body is the same JSON parsed.",
        "signing_seed_hex": hex::encode(SIGNING_SEED),
        "vm_id": VM_ID,
        "rollback_checkpoint_response": body(200, checkpoint_text),
        "point_manifest_text": String::from_utf8(manifest).unwrap(),
        "authorize_rollback_request": {
            "body_text": request_text,
            "body": serde_json::from_str::<Value>(&request_text).unwrap(),
        },
        "authorize_rollback_response": body(201, armed_text),
        "rollback_status_response": body(200, status_text),
        "refusals": refusals,
    })
}

#[test]
fn the_shared_rollback_wire_fixture_matches_the_real_code() {
    let want = serde_json::to_string_pretty(&produce()).unwrap() + "\n";
    let path = fixture_path(2);
    if std::env::var_os(REGEN_ENV).is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} — regenerate with {REGEN_ENV}=1", path.display()));
    assert!(
        have == want,
        "{} is stale: the rollback wire changed. If that is intended, regenerate with \
         {REGEN_ENV}=1 and update vali to the new fixture.",
        path.display()
    );
}

/// The names frozen with vali. Renaming any of them is a wire break.
#[test]
fn the_frozen_refusal_names_and_statuses_are_in_the_fixture() {
    let v = produce();
    let got: Vec<(String, u64)> = v["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["reason"].as_str().unwrap().to_string(),
                r["status"].as_u64().unwrap(),
            )
        })
        .collect();
    for (reason, status) in [
        ("checkpoint-unstamped", 409),
        ("manifest-mismatch", 400),
        ("bad-point-manifest", 400),
        ("rate-limited", 429),
        ("rollback-rate-limited", 429),
        ("rollback-unavailable", 503),
        ("guest-not-rollback-capable", 409),
        ("checkpoint-not-timeline-bound", 409),
    ] {
        assert!(
            got.contains(&(reason.to_string(), status)),
            "{reason} {status} missing from {got:?}"
        );
    }
    // One entry per reason.
    let mut reasons: Vec<&String> = got.iter().map(|(r, _)| r).collect();
    reasons.sort();
    reasons.dedup();
    assert_eq!(reasons.len(), got.len());
    // The manifest embeds the checkpoint bytes the request carries.
    let manifest: Value = serde_json::from_str(v["point_manifest_text"].as_str().unwrap()).unwrap();
    assert_eq!(
        manifest["kbs_rollback_checkpoint"]["checkpoint_cbor_hex"],
        v["authorize_rollback_request"]["body"]["checkpoint_cbor_hex"]
    );
    // The checkpoint is V2 and names the VM's timeline, in the JSON and
    // in the signed CBOR the manifest embeds.
    let cp = &v["rollback_checkpoint_response"]["body"]["checkpoint"];
    assert_eq!(cp["domain"], json!("HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V2"));
    assert_eq!(
        cp["volume_stamp_timeline_id_hex"],
        json!(hex::encode(FIXTURE_TIMELINE))
    );
    let st = &v["rollback_status_response"]["body"];
    assert_eq!(st["rollback_capable"], json!(true));
    assert_eq!(st["last_rollback"]["delivered"], json!(true));
    assert_eq!(st["last_rollback"]["reverted"], json!(false));
    assert_eq!(st["last_clear"]["reason"], json!("rollback-disarmed"));
}

/// The FROZEN v1 fixture — what the KBS signed before stamp protocol v2 —
/// still VERIFIES under the same key (a backup taken before V2 carries
/// such a checkpoint), decodes as V1 (no timeline), and is NEVER armed:
/// the very request that armed before V2 is now refused
/// `checkpoint-not-timeline-bound` (409), with nothing stored.
#[test]
fn a_v1_checkpoint_still_verifies_but_never_arms() {
    let raw = std::fs::read_to_string(fixture_path(1)).unwrap();
    let v1: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v1["version"], json!(1));
    let req: AdminAuthorizeRollbackRequest = serde_json::from_str(
        v1["authorize_rollback_request"]["body_text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let sk = SigningKey::from_bytes(&SIGNING_SEED);
    let cp = kbs_core::rollback::verify_checkpoint(
        &sk.verifying_key(),
        &hex::decode(&req.checkpoint_cbor_hex).unwrap(),
        &hex::decode(&req.signature_hex).unwrap(),
    )
    .expect("a V1 checkpoint still verifies");
    assert_eq!(cp.volume_stamp_timeline_id, None);

    // Everything else about the arm is admissible: the same world the v1
    // fixture armed in.
    let states = States(Mutex::new(HashMap::new()));
    let counters = InMemoryBootCounterStore::default();
    let stamps = InMemoryVolumeStampStore::default();
    counters.seed(VM_ID, 6).unwrap();
    states.0.lock().unwrap().insert(
        VM_ID.into(),
        VmState::Migrating {
            old_gen: 2,
            new_gen: 3,
            source: SRC_CHIP.into(),
            dest: DEST_CHIP.into(),
            lease_id: "lease-1".into(),
        },
    );
    stamps
        .record_guest_stamp_protocol(VM_ID, GUEST_STAMP_PROTOCOL_ROLLBACK_MIN)
        .unwrap();
    let out = process_authorize_rollback(
        VM_ID,
        &req,
        &states,
        &counters,
        &stamps,
        &sk.verifying_key(),
        &RollbackPolicy::default(),
        Some("spiffe://hippius.network/vali"),
        ARM_AT,
    );
    assert_eq!(out, Err(RollbackErr::CheckpointNotTimelineBound));
    assert_eq!(
        RollbackErr::CheckpointNotTimelineBound.reason(),
        "checkpoint-not-timeline-bound"
    );
    assert!(
        counters.rollback_state(VM_ID).unwrap().0.is_none(),
        "nothing armed"
    );
    assert_eq!(stamps.arm_timeline(VM_ID, &req.restore_id).unwrap(), None);
}
