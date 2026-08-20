//! End-to-end round-trip: KBS-side wrap+sign → guest-side verify+unwrap.
//!
//! These tests exercise ONLY the wire boundary between `kbs-core`'s
//! crypto (server) and `hippius-guest`'s verify+unwrap (client). The
//! upstream `kbs-core::release::process_release` is already validated
//! by kbs-core's own end-to-end test; here we focus on the guarantees
//! the guest agent depends on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use hippius_guest::{verify_and_unwrap_release, ExpectedRelease, GuestError};
use hippius_types::digest::userdata_digest;
use hippius_types::release::{KbsResponse, SignedResponse, HPKE_SUITE_ID, RELEASE_DOMAIN};
use kbs_core::crypto::{hpke_wrap, sign_response, ReleaseContext};

const NONCE: [u8; 32] = [1u8; 32];
const MEAS: [u8; 48] = [7u8; 48];
const KBS_KID: &[u8] = b"kbs-kid";
const TICKET_ID: &str = "tk-1";
const VM_ID: &str = "abc";
const TENANT_ID: &str = "t1";
const VM_GEN: u64 = 5;
const LUKS_PATH: &str = "kbs/vm/abc/luks";
const LUKS_VER: u64 = 3;
const UD_PATH: &str = "kbs/vm/abc/ud";
const UD_VER: u64 = 2;
const SCHEMA_V: u32 = 1;

/// Generate a fresh X25519 keypair (raw 32-byte secret + 32-byte public).
fn gen_x25519() -> ([u8; 32], [u8; 32]) {
    use rand::rngs::OsRng;
    let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    (sk.to_bytes(), pk.to_bytes())
}

/// Build a KBS-signed response carrying the two plaintexts wrapped to
/// `guest_pub`. Mirrors what `kbs_core::release::process_release` emits
/// on a successful release.
fn make_signed_response(
    kbs_sk: &SigningKey,
    guest_pub: &[u8; 32],
    luks_plain: &[u8],
    ud_plain: &[u8],
) -> SignedResponse {
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let luks_ctx = ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        secret_type: "luks",
        secret_path: LUKS_PATH,
        secret_version: LUKS_VER,
        allowed_userdata_digest: &digest,
    };
    let ud_ctx = ReleaseContext {
        secret_type: "userdata",
        secret_path: UD_PATH,
        secret_version: UD_VER,
        ..luks_ctx.clone()
    };
    let luks = hpke_wrap(guest_pub, luks_plain, &luks_ctx).unwrap();
    let userdata = hpke_wrap(guest_pub, ud_plain, &ud_ctx).unwrap();
    let resp = KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.into(),
        tenant_id: TENANT_ID.into(),
        vm_id: VM_ID.into(),
        vm_generation: VM_GEN,
        kbs_nonce: NONCE.to_vec(),
        measurement: MEAS.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: digest.to_vec(),
        luks,
        userdata,
        lifecycle_key: None,
        boot_counter: 0,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
    };
    sign_response(kbs_sk, &resp).unwrap()
}

/// §7 path: `LIFECYCLE-KEY` Vault path the KBS derives + wraps under.
const LIFECYCLE_PATH: &str = "kbs/vm/abc/lifecycle-key";
const LIFECYCLE_VER: u64 = 1;

/// Build a KBS-signed response that ALSO carries a §7 lifecycle signing
/// key wrapped to `guest_pub` (the path/version the KBS would have
/// derived + read). Mirrors a §7-enabled `process_release`.
fn make_signed_response_with_lifecycle(
    kbs_sk: &SigningKey,
    guest_pub: &[u8; 32],
    luks_plain: &[u8],
    ud_plain: &[u8],
    lifecycle_seed: &[u8],
) -> SignedResponse {
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let luks_ctx = ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        secret_type: "luks",
        secret_path: LUKS_PATH,
        secret_version: LUKS_VER,
        allowed_userdata_digest: &digest,
    };
    let ud_ctx = ReleaseContext {
        secret_type: "userdata",
        secret_path: UD_PATH,
        secret_version: UD_VER,
        ..luks_ctx.clone()
    };
    let lc_ctx = ReleaseContext {
        secret_type: "lifecycle",
        secret_path: LIFECYCLE_PATH,
        secret_version: LIFECYCLE_VER,
        ..luks_ctx.clone()
    };
    let luks = hpke_wrap(guest_pub, luks_plain, &luks_ctx).unwrap();
    let userdata = hpke_wrap(guest_pub, ud_plain, &ud_ctx).unwrap();
    let lifecycle_key = Some(hpke_wrap(guest_pub, lifecycle_seed, &lc_ctx).unwrap());
    let resp = KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.into(),
        tenant_id: TENANT_ID.into(),
        vm_id: VM_ID.into(),
        vm_generation: VM_GEN,
        kbs_nonce: NONCE.to_vec(),
        measurement: MEAS.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: digest.to_vec(),
        luks,
        userdata,
        lifecycle_key,
        boot_counter: 0,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
    };
    sign_response(kbs_sk, &resp).unwrap()
}

fn expected<'a>(digest: &'a [u8; 32]) -> ExpectedRelease<'a> {
    ExpectedRelease {
        vm_id: VM_ID,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        luks_path: LUKS_PATH,
        luks_version: LUKS_VER,
        userdata_path: UD_PATH,
        userdata_version: UD_VER,
        expected_allowed_userdata_digest: digest,
        schema_v: SCHEMA_V,
    }
}

/// `kbs-core::volume_stamp` — the fixed domain-separator `secret_path`
/// the KBS always wraps the confirm token under (mirrors the private
/// `VOLUME_STAMP_SECRET_PATH` constant in `hippius_guest::release` and
/// the `"kbs/volume-stamp"` literal in `kbs-core/src/release.rs`).
const VOLUME_STAMP_PATH: &str = "kbs/volume-stamp";

/// Build a KBS-signed response that ALSO carries a volume-stamp confirm
/// token wrapped to `guest_pub`, mirroring `kbs_core::release::process_
/// release`'s `stamp_ctx`. `token_vm_id` lets a test wrap the token
/// under a DIFFERENT vm_id than the response's own `VM_ID` — the
/// guest re-derives the context with ITS OWN vm_id, so a mismatch here
/// diverges the HPKE info+aad and the AEAD open fails.
#[allow(clippy::too_many_arguments)]
fn make_signed_response_with_volume_stamp(
    kbs_sk: &SigningKey,
    guest_pub: &[u8; 32],
    luks_plain: &[u8],
    ud_plain: &[u8],
    expected_volume_stamp: u64,
    token_plain: &[u8; 32],
    token_vm_id: &str,
) -> SignedResponse {
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let luks_ctx = ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        secret_type: "luks",
        secret_path: LUKS_PATH,
        secret_version: LUKS_VER,
        allowed_userdata_digest: &digest,
    };
    let ud_ctx = ReleaseContext {
        secret_type: "userdata",
        secret_path: UD_PATH,
        secret_version: UD_VER,
        ..luks_ctx.clone()
    };
    let target = expected_volume_stamp + 1;
    let stamp_ctx = ReleaseContext {
        vm_id: token_vm_id,
        secret_type: "volume-stamp-token",
        secret_path: VOLUME_STAMP_PATH,
        secret_version: target,
        ..luks_ctx.clone()
    };
    let luks = hpke_wrap(guest_pub, luks_plain, &luks_ctx).unwrap();
    let userdata = hpke_wrap(guest_pub, ud_plain, &ud_ctx).unwrap();
    let volume_stamp_token = Some(hpke_wrap(guest_pub, token_plain, &stamp_ctx).unwrap());
    let resp = KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.into(),
        tenant_id: TENANT_ID.into(),
        vm_id: VM_ID.into(),
        vm_generation: VM_GEN,
        kbs_nonce: NONCE.to_vec(),
        measurement: MEAS.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: digest.to_vec(),
        luks,
        userdata,
        lifecycle_key: None,
        boot_counter: 0,
        expected_volume_stamp,
        volume_stamp_token,
    };
    sign_response(kbs_sk, &resp).unwrap()
}

/// The token unwraps to the exact 32 bytes the KBS wrapped, and the
/// `expected_volume_stamp` field survives the round-trip unmodified —
/// the two pieces of state the caller needs to run the in-guest
/// compare-then-confirm sequence (`kbs-core::volume_stamp` module docs).
#[test]
fn volume_stamp_token_unwraps_to_expected_bytes() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let luks_plain = b"LUKSKEY-32B-XXXXXXXXXXXXXXXXXXXX";
    let ud_plain = b"#cloud-config\nusers:\n  - default";
    let token_plain = [0x42u8; 32];
    let signed = make_signed_response_with_volume_stamp(
        &kbs_sk,
        &guest_pk,
        luks_plain,
        ud_plain,
        4,
        &token_plain,
        VM_ID,
    );
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let exp = expected(&digest);
    let out = verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap();
    assert_eq!(out.expected_volume_stamp, 4);
    let token = out
        .volume_stamp_token
        .expect("response carried a volume-stamp token");
    assert_eq!(*token, token_plain);
}

/// A token HPKE-wrapped under a DIFFERENT context (here: a different
/// `vm_id` — a "wrong vm" release) fails the AEAD open when the guest
/// re-derives the context with its OWN vm_id. This is the same defence
/// that stops a stale/cross-VM `lifecycle_key` from unwrapping, applied
/// to the confirm token: a miner relaying another VM's release cannot
/// hand this guest a usable token.
#[test]
fn volume_stamp_token_wrong_context_fails_closed() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let luks_plain = b"LUKSKEY-32B-XXXXXXXXXXXXXXXXXXXX";
    let ud_plain = b"#cloud-config\nusers:\n  - default";
    let token_plain = [0x42u8; 32];
    let signed = make_signed_response_with_volume_stamp(
        &kbs_sk,
        &guest_pk,
        luks_plain,
        ud_plain,
        4,
        &token_plain,
        "other-vm",
    );
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let exp = expected(&digest);
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    assert!(matches!(err, GuestError::Hpke(_)), "got {err:?}");
}

#[test]
fn happy_path_unwraps_both_secrets() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let luks_plain = b"LUKSKEY-32B-XXXXXXXXXXXXXXXXXXXX";
    let ud_plain = b"#cloud-config\nusers:\n  - default";
    let signed = make_signed_response(&kbs_sk, &guest_pk, luks_plain, ud_plain);
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let exp = expected(&digest);
    let out = verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap();
    assert_eq!(out.luks.as_slice(), luks_plain);
    assert_eq!(out.userdata.as_slice(), ud_plain);
    // §7: a response with no `lifecycle_key` (pre-§7 VM) unwraps to None.
    assert!(out.lifecycle_key.is_none());
}

/// §7 round-trip: a release that carries the lifecycle SIGNING key
/// unwraps it, and the Ed25519 PUBLIC key derived from the unwrapped
/// seed equals the `Vm.lifecycle_vk` vali would have recorded — the
/// guarantee `_verify_ack` relies on (guest-signed ack ⇄ recorded vk).
#[test]
fn lifecycle_key_unwraps_and_pubkey_matches_recorded_vk() {
    use ed25519_dalek::SigningKey as EdSigningKey;

    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let luks_plain = b"LUKSKEY-32B-XXXXXXXXXXXXXXXXXXXX";
    let ud_plain = b"#cloud-config\nusers:\n  - default";

    // The vali-generated lifecycle seed (the PRIVATE key staged in
    // Vault). Its public key is what vali recorded as `Vm.lifecycle_vk`.
    let lifecycle_seed: [u8; 32] = [0x5Au8; 32];
    let recorded_vk = EdSigningKey::from_bytes(&lifecycle_seed)
        .verifying_key()
        .to_bytes();

    let signed = make_signed_response_with_lifecycle(
        &kbs_sk,
        &guest_pk,
        luks_plain,
        ud_plain,
        &lifecycle_seed,
    );
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, ud_plain,
    );
    let exp = expected(&digest);
    let out = verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap();

    let unwrapped = out
        .lifecycle_key
        .expect("§7 release carries a lifecycle key");
    assert_eq!(
        unwrapped.as_slice(),
        &lifecycle_seed,
        "seed survives the HPKE round-trip"
    );
    // The guest reconstructs the SAME signing key vali generated, so a
    // StoppedAck it signs verifies under the vali-recorded vk.
    let guest_signer_vk = EdSigningKey::from_bytes(unwrapped.as_slice().try_into().unwrap())
        .verifying_key()
        .to_bytes();
    assert_eq!(guest_signer_vk, recorded_vk);
}

/// §7 negative: a lifecycle blob whose `secret_type` is not
/// "lifecycle" is rejected (binding gate), and a lifecycle blob wrapped
/// to a DIFFERENT context fails the AEAD open. We verify the
/// AEAD-context binding by wrapping the seed under the WRONG path.
#[test]
fn lifecycle_key_wrong_context_fails_closed() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    // Wrap the lifecycle key under the LUKS context (wrong secret_type
    // + path) but advertise it in the `lifecycle_key` slot — the guest
    // re-derives the "lifecycle" context and the AEAD open fails.
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let wrong_ctx = ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        // secret_type "lifecycle" but a path the guest's re-derivation
        // (which uses the wrapped secret's OWN path) will still match —
        // so to force a mismatch we instead wrap under "luks" type.
        secret_type: "luks",
        secret_path: LIFECYCLE_PATH,
        secret_version: LIFECYCLE_VER,
        allowed_userdata_digest: &digest,
    };
    let luks_ctx = ReleaseContext {
        secret_type: "luks",
        secret_path: LUKS_PATH,
        secret_version: LUKS_VER,
        ..wrong_ctx.clone()
    };
    let ud_ctx = ReleaseContext {
        secret_type: "userdata",
        secret_path: UD_PATH,
        secret_version: UD_VER,
        ..wrong_ctx.clone()
    };
    let mut bad = hpke_wrap(&guest_pk, &[7u8; 32], &wrong_ctx).unwrap();
    // Advertise it as the lifecycle slot with the lifecycle type so the
    // guest's type-binding passes but the AEAD context (secret_type)
    // mismatches → open fails.
    bad.secret_type = "lifecycle".into();
    let luks = hpke_wrap(&guest_pk, b"L", &luks_ctx).unwrap();
    let userdata = hpke_wrap(&guest_pk, b"UD", &ud_ctx).unwrap();
    let resp = KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.into(),
        tenant_id: TENANT_ID.into(),
        vm_id: VM_ID.into(),
        vm_generation: VM_GEN,
        kbs_nonce: NONCE.to_vec(),
        measurement: MEAS.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: digest.to_vec(),
        luks,
        userdata,
        lifecycle_key: Some(bad),
        boot_counter: 0,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
    };
    let signed = sign_response(&kbs_sk, &resp).unwrap();
    let exp = expected(&digest);
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    assert!(matches!(err, GuestError::Hpke(_)), "got {err:?}");
}

#[test]
fn wrong_kbs_pubkey_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let attacker = SigningKey::from_bytes(&[1u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let exp = expected(&digest);
    let err =
        verify_and_unwrap_release(&signed, &attacker.verifying_key(), &guest_sk, &exp).unwrap_err();
    assert!(matches!(err, GuestError::Signature(_)));
}

#[test]
fn tampered_signature_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let mut signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    signed.sig[0] ^= 0xff;
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let exp = expected(&digest);
    assert!(matches!(
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err(),
        GuestError::Signature(_)
    ));
}

#[test]
fn vm_id_mismatch_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let mut exp = expected(&digest);
    exp.vm_id = "other-vm";
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    match err {
        GuestError::Binding { field, .. } => assert_eq!(field, "vm_id"),
        other => panic!("expected Binding(vm_id), got {other:?}"),
    }
}

#[test]
fn measurement_mismatch_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let mut exp = expected(&digest);
    let other = [8u8; 48];
    exp.measurement = &other;
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    match err {
        GuestError::Binding { field, .. } => assert_eq!(field, "measurement"),
        other => panic!("expected Binding(measurement), got {other:?}"),
    }
}

#[test]
fn nonce_mismatch_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let mut exp = expected(&digest);
    let other = [9u8; 32];
    exp.kbs_nonce = &other;
    assert!(matches!(
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err(),
        GuestError::Binding { field, .. } if field == "kbs_nonce"
    ));
}

#[test]
fn ticket_digest_mismatch_against_kbs_signed_response_rejected() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    // Guest's local-ticket digest disagrees with KBS-signed digest.
    let wrong = [0xAAu8; 32];
    let exp = expected(&wrong);
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    match err {
        GuestError::Binding { field, .. } => assert_eq!(field, "allowed_userdata_digest"),
        other => panic!("expected Binding(allowed_userdata_digest), got {other:?}"),
    }
}

#[test]
fn ud_plaintext_does_not_match_digest_rejected() {
    // The KBS-signed response carries the digest of `b"UD"`. We craft a
    // bogus response that wraps a DIFFERENT user-data plaintext while
    // claiming the same digest — the guest's recompute MUST catch it.
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    // Build manually so the digest field doesn't match the wrapped ud.
    // The KBS would have wrapped using the digest of the ACTUAL plaintext
    // it returned; we use the lying digest in BOTH the wrap context and
    // the response field so HPKE open succeeds but the post-unwrap
    // recompute catches the mismatch.
    let lying_digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let luks_ctx = ReleaseContext {
        v: SCHEMA_V,
        ticket_id: TICKET_ID,
        tenant_id: TENANT_ID,
        vm_id: VM_ID,
        vm_generation: VM_GEN,
        kbs_nonce: &NONCE,
        measurement: &MEAS,
        kbs_kid: KBS_KID,
        secret_type: "luks",
        secret_path: LUKS_PATH,
        secret_version: LUKS_VER,
        allowed_userdata_digest: &lying_digest,
    };
    let ud_ctx = ReleaseContext {
        secret_type: "userdata",
        secret_path: UD_PATH,
        secret_version: UD_VER,
        ..luks_ctx.clone()
    };
    let luks = hpke_wrap(&guest_pk, b"L", &luks_ctx).unwrap();
    let userdata = hpke_wrap(&guest_pk, b"DIFFERENT-PLAIN", &ud_ctx).unwrap();
    let lying_digest = lying_digest.to_vec();
    let resp = KbsResponse {
        domain: RELEASE_DOMAIN.into(),
        v: SCHEMA_V,
        ticket_id: TICKET_ID.into(),
        tenant_id: TENANT_ID.into(),
        vm_id: VM_ID.into(),
        vm_generation: VM_GEN,
        kbs_nonce: NONCE.to_vec(),
        measurement: MEAS.to_vec(),
        kbs_kid: KBS_KID.to_vec(),
        hpke_suite_id: HPKE_SUITE_ID,
        allowed_userdata_digest: lying_digest.clone(),
        luks,
        userdata,
        lifecycle_key: None,
        boot_counter: 0,
        expected_volume_stamp: 0,
        volume_stamp_token: None,
    };
    let signed = sign_response(&kbs_sk, &resp).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&lying_digest);
    let exp = expected(&arr);
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    assert!(matches!(err, GuestError::DigestMismatch));
}

#[test]
fn wrong_guest_secret_fails_hpke_open() {
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (_real_sk, guest_pk) = gen_x25519();
    let (attacker_sk, _) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let exp = expected(&digest);
    let err = verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &attacker_sk, &exp)
        .unwrap_err();
    assert!(matches!(err, GuestError::Hpke(_)));
}

#[test]
fn swapped_luks_and_userdata_rejected() {
    // Hostile KBS serves: response.luks carries the userdata WrappedSecret
    // and vice-versa. The guest must catch this via the `secret_type`
    // field on each WrappedSecret — it MUST NOT proceed to HPKE open
    // (which would also fail, but failing earlier means a sharper error
    // and no chance of mis-attribution downstream).
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let mut signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    // Decode → swap → re-sign so the signature still verifies.
    let mut resp: KbsResponse = ciborium::de::from_reader(signed.body.as_slice()).unwrap();
    std::mem::swap(&mut resp.luks, &mut resp.userdata);
    signed = sign_response(&kbs_sk, &resp).unwrap();
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let exp = expected(&digest);
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    // Either `luks_vault_ref` (secret_type mismatch) or `userdata_vault_ref`.
    match err {
        GuestError::Binding { field, .. } => {
            assert!(field == "luks_vault_ref" || field == "userdata_vault_ref");
        }
        other => panic!("expected Binding(luks/userdata_vault_ref), got {other:?}"),
    }
}

#[test]
fn wrong_wrapped_path_rejected() {
    // KBS response includes WrappedSecret.secret_path = LUKS_PATH but the
    // guest's expected path differs ⇒ binding error BEFORE HPKE open.
    let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
    let (guest_sk, guest_pk) = gen_x25519();
    let signed = make_signed_response(&kbs_sk, &guest_pk, b"L", b"UD");
    let digest = userdata_digest(
        TENANT_ID, VM_ID, TICKET_ID, "userdata", UD_PATH, UD_VER, b"UD",
    );
    let mut exp = expected(&digest);
    exp.luks_path = "kbs/vm/other/luks";
    let err =
        verify_and_unwrap_release(&signed, &kbs_sk.verifying_key(), &guest_sk, &exp).unwrap_err();
    match err {
        GuestError::Binding { field, .. } => assert_eq!(field, "luks_vault_ref"),
        other => panic!("expected Binding(luks_vault_ref), got {other:?}"),
    }
}
