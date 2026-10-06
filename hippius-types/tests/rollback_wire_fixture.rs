//! The shared C-4 rollback wire fixtures (`tests/fixtures/rollback_wire_v1.json`,
//! frozen, and `rollback_wire_v2.json`, current), read through the WIRE TYPES
//! alone.
//!
//! `kbs-core/tests/rollback_wire_fixture.rs` produces the file with the
//! real KBS code and pins it byte for byte; vali loads the same file.
//! This test pins the other half: every body in it decodes into its
//! `hippius_types::rollback` type (`deny_unknown_fields`) and re-encodes
//! to the SAME bytes, the signed checkpoint verifies under the fixture's
//! key, and the request's manifest is the one it names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey, Verifier};
use hippius_types::rollback::{
    AdminAuthorizeRollbackRequest, AdminAuthorizeRollbackResponse, AdminRollbackCheckpointResponse,
    AdminRollbackErrorResponse, AdminRollbackStatusResponse, RollbackCheckpoint,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture is JSON")
}

const V1: &str = include_str!("fixtures/rollback_wire_v1.json");
const V2: &str = include_str!("fixtures/rollback_wire_v2.json");

/// Decode `entry.body_text` as `T`, re-encode, and demand the same bytes
/// (and the same JSON as `entry.body`).
fn round_trip<T: Serialize + DeserializeOwned>(entry: &Value) -> T {
    let text = entry["body_text"].as_str().expect("body_text");
    let typed: T = serde_json::from_str(text).expect("decodes into the wire type");
    assert_eq!(serde_json::to_string(&typed).unwrap(), text);
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        entry["body"],
        "body and body_text disagree"
    );
    typed
}

#[test]
fn every_body_round_trips_through_its_wire_type_byte_for_byte() {
    every_body_round_trips(&fixture(V1), None);
    every_body_round_trips(&fixture(V2), Some([0x5c; 32]));
}

/// The V1 file keeps decoding as V1 (no timeline); the V2 file carries the
/// VM's timeline in the signed checkpoint and its JSON projection.
fn every_body_round_trips(f: &Value, timeline: Option<[u8; 32]>) {
    let cp: AdminRollbackCheckpointResponse = round_trip(&f["rollback_checkpoint_response"]);
    let req: AdminAuthorizeRollbackRequest = round_trip(&f["authorize_rollback_request"]);
    let armed: AdminAuthorizeRollbackResponse = round_trip(&f["authorize_rollback_response"]);
    let status: AdminRollbackStatusResponse = round_trip(&f["rollback_status_response"]);
    for r in f["refusals"].as_array().unwrap() {
        let e: AdminRollbackErrorResponse = round_trip(r);
        assert_eq!(e.reason, r["reason"].as_str().unwrap());
        assert_eq!(
            e.retry_after_s.is_some(),
            r["status"] == 429,
            "{}",
            e.reason
        );
    }

    // The checkpoint JSON is the projection of the signed CBOR, and the
    // signature verifies under the fixture's key.
    let cbor = hex::decode(&cp.checkpoint_cbor_hex).unwrap();
    let decoded = RollbackCheckpoint::decode(&cbor).unwrap();
    assert_eq!(decoded.volume_stamp_timeline_id, timeline);
    assert_eq!(
        cp.checkpoint.volume_stamp_timeline_id_hex,
        timeline.map(hex::encode)
    );
    assert_eq!(decoded.to_wire(), cp.checkpoint);
    assert_eq!(decoded.canonical().unwrap(), cbor);
    let seed: [u8; 32] = hex::decode(f["signing_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(hex::encode(vk.to_bytes()), cp.signer_pubkey_hex);
    let sig = Signature::from_slice(&hex::decode(&cp.signature_hex).unwrap()).unwrap();
    vk.verify(&cbor, &sig).unwrap();

    // The request carries that checkpoint, and names the manifest it
    // embeds under `kbs_rollback_checkpoint.checkpoint_cbor_hex`.
    assert_eq!(req.checkpoint_cbor_hex, cp.checkpoint_cbor_hex);
    assert_eq!(req.signature_hex, cp.signature_hex);
    let manifest = base64::engine::general_purpose::STANDARD
        .decode(&req.point_manifest_b64)
        .unwrap();
    assert_eq!(
        manifest,
        f["point_manifest_text"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        hex::encode(Sha256::digest(&manifest)),
        req.point_manifest_sha256_hex
    );
    let m: Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(
        m["kbs_rollback_checkpoint"]["checkpoint_cbor_hex"],
        Value::String(req.checkpoint_cbor_hex.clone())
    );
    assert_eq!(m["vm_id"], f["vm_id"]);

    // The arm and the status agree with the request.
    assert_eq!(armed.arm.restore_id, req.restore_id);
    assert_eq!(armed.arm.from_counter, decoded.boot_counter);
    assert_eq!(armed.arm.to_stamp, decoded.volume_stamp);
    assert_eq!(status.arm.as_ref(), Some(&armed.arm));
    assert!(status.rollback_capable);
}
