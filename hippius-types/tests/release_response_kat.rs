//! Known-answer vectors for the signed KBS release response (§20) across
//! the customer-held-keys change (`KbsResponse::luks` became optional).
//!
//! The M0 vector was computed on the code BEFORE `luks` became an
//! `Option` and is pinned here byte-for-byte: an M0 (`hippius`) or M1
//! (`split`) release must keep producing exactly these bytes and this
//! signature, so every baked guest keeps verifying and parsing it.
//!
//! The M2 (`customer`) vector pins the no-KEK shape: the `luks` key is
//! ABSENT from the canonical map (never CBOR `null`), and a guest built
//! before the change — whose `luks` is a required field — refuses it
//! (fail closed) instead of silently decoding a KEK-less release.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::release::{
    KbsResponse, VolumeStampTransition, WrappedSecret, HPKE_SUITE_ID, RELEASE_DOMAIN,
    RELEASE_DOMAIN_V2,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn secret(t: &str, path: &str, version: u64, fill: u8) -> WrappedSecret {
    WrappedSecret {
        secret_type: t.into(),
        secret_path: path.into(),
        secret_version: version,
        enc: vec![fill; 32],
        ct: vec![fill.wrapping_add(1); 48],
    }
}

/// A fully-populated M0 release — every optional field present, so the
/// vector covers the widest shape a production KBS emits today.
fn m0_response() -> KbsResponse {
    KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: 2,
        ticket_id: "tk-kat-1".into(),
        tenant_id: "tenant-kat".into(),
        vm_id: "vm-kat".into(),
        vm_generation: 7,
        kbs_nonce: vec![0x11; 32],
        measurement: vec![0x22; 48],
        kbs_kid: b"kbs-kid-kat".to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: vec![0x33; 32],
        luks: Some(secret(
            "luks",
            "hippius-compute/kbs/tenants/vm-kat/luks-kek",
            1,
            0x40,
        )),
        userdata: secret(
            "userdata",
            "hippius-compute/kbs/tenants/vm-kat/userdata",
            3,
            0x50,
        ),
        lifecycle_key: Some(secret(
            "lifecycle",
            "hippius-compute/kbs/tenants/vm-kat/lifecycle-key",
            1,
            0x60,
        )),
        boot_counter: 4,
        expected_volume_stamp: 3,
        volume_stamp_token: Some(secret("volume-stamp-token", "kbs/volume-stamp", 4, 0x70)),
        volume_stamp_transition: None,
    }
}

/// The same release to a guest that ATTESTED stamp protocol v2: the V2
/// domain and a timeline transition (here the rollback shape: a restored
/// timeline → a fresh one).
fn v2_response() -> KbsResponse {
    KbsResponse {
        domain: RELEASE_DOMAIN_V2.into(),
        volume_stamp_transition: Some(VolumeStampTransition {
            expected_timeline_id: vec![0xa1; 32],
            target_timeline_id: vec![0xb2; 32],
        }),
        ..m0_response()
    }
}

/// The same release as an M2 (`customer`) KBS emits it: no KEK, no
/// volume-stamp token, no stamp expectation — everything else identical.
fn m2_response() -> KbsResponse {
    KbsResponse {
        luks: None,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
        ..m0_response()
    }
}

/// The KBS's exact body encoding (`kbs_core::crypto::canonical_response`).
fn canonical(resp: &KbsResponse) -> Vec<u8> {
    to_canonical_vec(&Value::serialized(resp).unwrap()).unwrap()
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The guest's parser as it was before `luks` became optional — the
/// shape every golden image baked so far decodes with.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PreChangeKbsResponse {
    domain: String,
    v: u32,
    ticket_id: String,
    tenant_id: String,
    vm_id: String,
    vm_generation: u64,
    #[serde(with = "serde_bytes")]
    kbs_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    measurement: Vec<u8>,
    #[serde(with = "serde_bytes")]
    kbs_kid: Vec<u8>,
    hpke_suite_id: u16,
    #[serde(with = "serde_bytes")]
    allowed_userdata_digest: Vec<u8>,
    luks: WrappedSecret,
    userdata: WrappedSecret,
    #[serde(default)]
    lifecycle_key: Option<WrappedSecret>,
    #[serde(default)]
    boot_counter: u64,
    #[serde(default)]
    expected_volume_stamp: u64,
    #[serde(default)]
    volume_stamp_token: Option<WrappedSecret>,
}

/// Pinned on the pre-change code (`luks: WrappedSecret`). DO NOT update
/// to make a failing run pass: a drift here means M0 releases changed on
/// the wire and every baked guest would be affected.
const M0_BODY_SHA256: &str = "c19081076018edabdacaf5e490fff1413a29082a73b63e400b959e1529a86a55";
const M0_SIG_SHA256: &str = "5459419c32ba6025f0da4ea23a1a87b45b93b830b97a53cd969c03a5f212f851";

#[test]
fn m0_signed_response_is_byte_identical_to_the_pre_change_encoding() {
    let body = canonical(&m0_response());
    assert_canonical(&body).unwrap();
    let sk = SigningKey::from_bytes(&[0x5a; 32]);
    let sig = sk.sign(&body).to_bytes();
    assert_eq!(sha_hex(&body), M0_BODY_SHA256, "M0 release body drifted");
    assert_eq!(sha_hex(&sig), M0_SIG_SHA256, "M0 release signature drifted");
}

#[test]
fn m0_body_decodes_with_the_pre_change_guest_parser() {
    let body = canonical(&m0_response());
    let old: PreChangeKbsResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(Some(old.luks), m0_response().luks);
    let new: KbsResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(new, m0_response());
}

#[test]
fn m2_body_omits_the_luks_key_entirely() {
    let body = canonical(&m2_response());
    assert_canonical(&body).unwrap();
    let Value::Map(entries) = ciborium::de::from_reader::<Value, _>(body.as_slice()).unwrap()
    else {
        panic!("release body is not a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| k.as_text().expect("text key"))
        .collect();
    assert!(
        !keys.contains(&"luks"),
        "M2 body must not carry `luks`: {keys:?}"
    );
    assert!(!keys.contains(&"volume_stamp_token"));
    assert!(keys.contains(&"userdata"));
    assert!(keys.contains(&"lifecycle_key"));
    // Round-trips on the current parser.
    let back: KbsResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(back, m2_response());
    assert!(back.luks.is_none());
}

#[test]
fn m2_body_is_refused_by_the_pre_change_guest_parser() {
    // A guest baked before customer-held keys can never be handed a
    // KEK-less release it would misread: `luks` is required there.
    let body = canonical(&m2_response());
    assert!(ciborium::de::from_reader::<PreChangeKbsResponse, _>(body.as_slice()).is_err());
}

/// Pinned when stamp protocol v2 was introduced: the V2 shape.
const V2_BODY_SHA256: &str = "1194abcb3c4e2d9dea5edc6bb917e40893a00fb4f4e9e8bd8c49c7df9f09a036";

#[test]
fn a_v2_signed_response_is_pinned_and_carries_the_transition() {
    let body = canonical(&v2_response());
    assert_canonical(&body).unwrap();
    assert_eq!(sha_hex(&body), V2_BODY_SHA256, "V2 release body drifted");
    let back: KbsResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(back, v2_response());
    let (e, t) = back.volume_stamp_transition.unwrap().ids().unwrap();
    assert_eq!((e, t), ([0xa1; 32], [0xb2; 32]));
}

/// A guest built before v2 pins `RELEASE_DOMAIN` (`hippius_guest::release`
/// binds `domain` first): a V2 body decodes on its parser but names a
/// domain it refuses, so it can never silently ignore the transition.
#[test]
fn a_v2_body_names_a_domain_the_pre_v2_guest_refuses() {
    let body = canonical(&v2_response());
    let old: PreChangeKbsResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_ne!(old.domain, RELEASE_DOMAIN);
    assert_eq!(old.domain, "HIPPIUS_KBS_RELEASE_V2");
}

/// A v1 release never carries the transition key at all — not even CBOR
/// null — so its bytes are the pinned M0 vector above.
#[test]
fn a_v1_body_omits_the_transition_key_entirely() {
    let body = canonical(&m0_response());
    let Value::Map(entries) = ciborium::de::from_reader::<Value, _>(body.as_slice()).unwrap()
    else {
        panic!("release body is not a map");
    };
    assert!(entries
        .iter()
        .all(|(k, _)| k.as_text() != Some("volume_stamp_transition")));
}

/// A transition id that is not exactly 32 bytes is no transition.
#[test]
fn a_short_timeline_id_is_refused() {
    let t = VolumeStampTransition {
        expected_timeline_id: vec![0; 31],
        target_timeline_id: vec![0; 32],
    };
    assert!(t.ids().is_none());
}
