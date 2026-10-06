use super::*;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::guardian::{
    encode_canonical, guest_pub_hash, signing_input, stamp_token_hash, GuardianEndpoint,
    LaunchRecipe, SignedGuardianDenial, GUARDIAN_WIRE_V,
};
use kbs_core::crypto::hpke_seal_raw;
use x25519_dalek::{PublicKey, StaticSecret};

const VM: &str = "vm-guardian-1";
const SHARE_C: [u8; 32] = [0xC5; 32];
const TOKEN: [u8; 32] = [0x7E; 32];

struct World {
    gk: SigningKey,
    guest_sk: [u8; 32],
    binding: GuardianBinding,
    request: GuardianReleaseRequest,
}

fn world(mode: KeyMode, share_c_version: Option<u32>) -> World {
    let gk = SigningKey::from_bytes(&[9u8; 32]);
    let sk = StaticSecret::from([3u8; 32]);
    let guest_pub = PublicKey::from(&sk).to_bytes();
    let pk_hex: String = gk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let cmdline = format!(
        "ro boot=hippius-golden hippius.key_mode={} hippius.guardian_pk={pk_hex} \
         hippius.guardian_ep=3130302e36342e302e393a37343433",
        mode.as_wire()
    );
    let binding = GuardianBinding::from_cmdline(&cmdline).unwrap().unwrap();
    let request = GuardianReleaseRequest {
        v: GUARDIAN_WIRE_V,
        vm_id: VM.into(),
        key_mode: mode,
        nonce: vec![0x11; 32],
        snp_report: vec![0; 1184],
        guest_pub: guest_pub.to_vec(),
        vcek_chain: vec![],
        launch_recipe: LaunchRecipe {
            ovmf_sha384: vec![1; 48],
            kernel_sha256: vec![2; 32],
            initrd_sha256: vec![3; 32],
            cmdline,
            vcpus: 2,
            vcpu_type: "EpycGenoa".into(),
            guest_features: 1,
        },
        share_c_version,
    };
    request.validate().unwrap();
    assert_eq!(
        binding.endpoint,
        GuardianEndpoint::parse("100.64.0.9:7443").unwrap()
    );
    World {
        gk,
        guest_sk: sk.to_bytes(),
        binding,
        request,
    }
}

fn seal(to: &[u8], pt: &[u8], info: &[u8], aad: &[u8]) -> GuardianWrapped {
    let to: [u8; 32] = to.try_into().unwrap();
    let (enc, ct) = hpke_seal_raw(&to, pt, info, aad).unwrap();
    GuardianWrapped { enc, ct }
}

/// A response the way an honest guardian builds it: fields first, then
/// both secrets sealed under the aad of those fields.
fn response(w: &World, version: u32) -> GuardianResponse {
    let customer = w.request.key_mode == KeyMode::Customer;
    let mut r = GuardianResponse {
        v: GUARDIAN_WIRE_V,
        vm_id: VM.into(),
        nonce: w.request.nonce.clone(),
        guest_pub_hash: guest_pub_hash(&w.request.guest_pub).to_vec(),
        key_mode: w.request.key_mode,
        share_c_version: version,
        wrapped_share: GuardianWrapped {
            enc: vec![0; 32],
            ct: vec![0; 48],
        },
        expected_volume_stamp: customer.then_some(41),
        stamp_token_wrapped: customer.then(|| GuardianWrapped {
            enc: vec![0; 32],
            ct: vec![0; 48],
        }),
    };
    reseal(w, &mut r);
    r
}

fn reseal(w: &World, r: &mut GuardianResponse) {
    let aad = r.wrap_aad().unwrap();
    r.wrapped_share = seal(&w.request.guest_pub, &SHARE_C, SHARE_HPKE_INFO, &aad);
    if r.stamp_token_wrapped.is_some() {
        r.stamp_token_wrapped = Some(seal(
            &w.request.guest_pub,
            &TOKEN,
            STAMP_TOKEN_HPKE_INFO,
            &aad,
        ));
    }
}

fn sign(key: &SigningKey, domain: &[u8], body: Vec<u8>) -> Vec<u8> {
    let sig = key.sign(&signing_input(domain, &body)).to_bytes().to_vec();
    encode_canonical(&SignedGuardianResponse { body, sig }).unwrap()
}

fn signed_response(w: &World, r: &GuardianResponse) -> Vec<u8> {
    sign(&w.gk, RESP_SIG_DOMAIN, encode_canonical(r).unwrap())
}

fn denial(w: &World, reason: GuardianDenyReason) -> GuardianDenial {
    GuardianDenial {
        v: GUARDIAN_WIRE_V,
        vm_id: VM.into(),
        nonce: w.request.nonce.clone(),
        guest_pub_hash: guest_pub_hash(&w.request.guest_pub).to_vec(),
        reason,
    }
}

fn signed_denial(w: &World, d: &GuardianDenial) -> Vec<u8> {
    let body = encode_canonical(d).unwrap();
    let sig =
        w.gk.sign(&signing_input(DENY_SIG_DOMAIN, &body))
            .to_bytes()
            .to_vec();
    encode_canonical(&SignedGuardianDenial { body, sig }).unwrap()
}

fn open(w: &World, reply: &[u8]) -> Result<GuardianReply> {
    open_guardian_reply(reply, &w.binding, &w.request, &w.guest_sk)
}

#[test]
fn m1_response_opens_to_the_share_and_carries_no_stamp() {
    let w = world(KeyMode::Split, None);
    let GuardianReply::Released(r) = open(&w, &signed_response(&w, &response(&w, 3))).unwrap()
    else {
        panic!("not a release")
    };
    assert_eq!(*r.share_c, SHARE_C);
    assert_eq!(r.share_c_version, 3);
    assert!(r.stamp.is_none());
}

#[test]
fn m2_response_opens_the_share_and_the_stamp_token() {
    let w = world(KeyMode::Customer, Some(2));
    let GuardianReply::Released(r) = open(&w, &signed_response(&w, &response(&w, 2))).unwrap()
    else {
        panic!("not a release")
    };
    assert_eq!(*r.share_c, SHARE_C);
    let stamp = r.stamp.unwrap();
    assert_eq!(stamp.expected, 41);
    assert_eq!(*stamp.token, TOKEN);
}

#[test]
fn a_signed_denial_is_a_decision() {
    let w = world(KeyMode::Split, None);
    for reason in GuardianDenyReason::ALL {
        let d = denial(&w, reason);
        match open(&w, &signed_denial(&w, &d)).unwrap() {
            GuardianReply::Denied(got) => assert_eq!(got, reason),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn a_response_signed_by_another_key_is_noise() {
    let w = world(KeyMode::Split, None);
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let reply = sign(
        &other,
        RESP_SIG_DOMAIN,
        encode_canonical(&response(&w, 1)).unwrap(),
    );
    assert!(matches!(open(&w, &reply), Err(GuestError::Signature(_))));
    // Same for a denial — a forged `erased` is not a decision.
    let body = encode_canonical(&denial(&w, GuardianDenyReason::Erased)).unwrap();
    let reply = sign(&other, DENY_SIG_DOMAIN, body);
    assert!(matches!(open(&w, &reply), Err(GuestError::Signature(_))));
}

#[test]
fn a_flipped_signature_bit_is_noise() {
    let w = world(KeyMode::Split, None);
    let body = encode_canonical(&response(&w, 1)).unwrap();
    let mut sig =
        w.gk.sign(&signing_input(RESP_SIG_DOMAIN, &body))
            .to_bytes()
            .to_vec();
    sig[5] ^= 1;
    let reply = encode_canonical(&SignedGuardianResponse { body, sig }).unwrap();
    assert!(matches!(open(&w, &reply), Err(GuestError::Signature(_))));
}

#[test]
fn the_signature_domain_decides_the_kind() {
    let w = world(KeyMode::Split, None);
    // A denial body signed under the RESPONSE domain decodes as nothing.
    let body = encode_canonical(&denial(&w, GuardianDenyReason::Erased)).unwrap();
    let reply = sign(&w.gk, RESP_SIG_DOMAIN, body);
    assert!(matches!(open(&w, &reply), Err(GuestError::Decode(_))));
    // A response body signed under the DENIAL domain is not a release.
    let reply = sign(
        &w.gk,
        DENY_SIG_DOMAIN,
        encode_canonical(&response(&w, 1)).unwrap(),
    );
    assert!(matches!(open(&w, &reply), Err(GuestError::Decode(_))));
}

#[test]
fn a_replayed_denial_for_another_guest_key_is_noise() {
    let w = world(KeyMode::Split, None);
    let mut d = denial(&w, GuardianDenyReason::Erased);
    d.guest_pub_hash = vec![0xAB; 32];
    assert!(matches!(
        open(&w, &signed_denial(&w, &d)),
        Err(GuestError::Schema(_))
    ));
    let mut d = denial(&w, GuardianDenyReason::Erased);
    d.nonce = vec![0x12; 32];
    assert!(matches!(
        open(&w, &signed_denial(&w, &d)),
        Err(GuestError::Schema(_))
    ));
}

#[test]
fn a_response_for_another_request_is_refused() {
    let w = world(KeyMode::Split, None);
    let mut r = response(&w, 1);
    r.guest_pub_hash = vec![0xAB; 32];
    reseal(&w, &mut r);
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Schema(_))
    ));
    let mut r = response(&w, 1);
    r.vm_id = "vm-other".into();
    reseal(&w, &mut r);
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Schema(_))
    ));
}

#[test]
fn a_different_share_version_than_requested_is_refused() {
    let w = world(KeyMode::Split, Some(4));
    assert!(matches!(
        open(&w, &signed_response(&w, &response(&w, 5))),
        Err(GuestError::Schema(_))
    ));
    assert!(open(&w, &signed_response(&w, &response(&w, 4))).is_ok());
}

#[test]
fn a_mode_other_than_the_measured_one_is_refused() {
    let w = world(KeyMode::Split, None);
    let m2 = world(KeyMode::Customer, None);
    let mut r = response(&m2, 1);
    // Signed by the right key, for the right request — but M2-shaped.
    r.guest_pub_hash = guest_pub_hash(&w.request.guest_pub).to_vec();
    reseal(&w, &mut r);
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Schema(_))
    ));
}

#[test]
fn a_share_sealed_under_other_fields_does_not_open() {
    // The ciphertext is bound (aad) to every field of the signed body:
    // lifting a sealed share into a response with another version fails.
    let w = world(KeyMode::Split, None);
    let mut r = response(&w, 1);
    r.share_c_version = 2;
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Hpke(_))
    ));
}

#[test]
fn a_share_sealed_under_the_stamp_info_does_not_open() {
    let w = world(KeyMode::Split, None);
    let mut r = response(&w, 1);
    let aad = r.wrap_aad().unwrap();
    r.wrapped_share = seal(&w.request.guest_pub, &SHARE_C, STAMP_TOKEN_HPKE_INFO, &aad);
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Hpke(_))
    ));
}

#[test]
fn a_share_for_another_guest_key_does_not_open() {
    let w = world(KeyMode::Split, None);
    let mut other = world(KeyMode::Split, None);
    other.guest_sk = [4u8; 32];
    assert!(matches!(
        open(&other, &signed_response(&w, &response(&w, 1))),
        Err(GuestError::Hpke(_))
    ));
}

#[test]
fn a_short_share_is_refused() {
    let w = world(KeyMode::Split, None);
    let mut r = response(&w, 1);
    let aad = r.wrap_aad().unwrap();
    let (enc, ct) = hpke_seal_raw(
        &w.request.guest_pub.clone().try_into().unwrap(),
        &[0u8; 31],
        SHARE_HPKE_INFO,
        &aad,
    )
    .unwrap();
    // 31 + 16 = 47 bytes: `validate` refuses the length before HPKE.
    r.wrapped_share = GuardianWrapped { enc, ct };
    assert!(open(&w, &signed_response(&w, &r)).is_err());
}

#[test]
fn a_stamp_at_the_top_of_the_range_is_refused() {
    let w = world(KeyMode::Customer, None);
    let mut r = response(&w, 1);
    r.expected_volume_stamp = Some(u64::MAX);
    reseal(&w, &mut r);
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Schema(_))
    ));
}

#[test]
fn a_stamp_token_sealed_under_the_share_info_does_not_open() {
    let w = world(KeyMode::Customer, None);
    let mut r = response(&w, 1);
    let aad = r.wrap_aad().unwrap();
    r.stamp_token_wrapped = Some(seal(&w.request.guest_pub, &TOKEN, SHARE_HPKE_INFO, &aad));
    assert!(matches!(
        open(&w, &signed_response(&w, &r)),
        Err(GuestError::Hpke(_))
    ));
}

#[test]
fn garbage_and_non_canonical_envelopes_are_refused() {
    let w = world(KeyMode::Split, None);
    assert!(matches!(
        open(&w, b"guardian-unreachable"),
        Err(GuestError::Decode(_))
    ));
    assert!(matches!(open(&w, &[]), Err(GuestError::Decode(_))));
    let reply = encode_canonical(&SignedGuardianResponse {
        body: vec![1],
        sig: vec![0; 63],
    })
    .unwrap();
    assert!(matches!(open(&w, &reply), Err(GuestError::Decode(_))));
}

#[test]
fn a_guardian_pk_that_is_not_a_curve_point_is_refused() {
    let mut w = world(KeyMode::Split, None);
    // y = 2 does not decompress to a point on edwards25519.
    let mut pk = [0u8; 32];
    pk[0] = 2;
    w.binding.guardian_pk = pk;
    let reply = signed_response(&w, &response(&w, 1));
    assert!(matches!(open(&w, &reply), Err(GuestError::Signature(_))));
}

#[test]
fn debug_shows_the_decision_never_the_share() {
    let w = world(KeyMode::Customer, None);
    let reply = open(&w, &signed_response(&w, &response(&w, 3))).unwrap();
    let shown = format!("{reply:?}");
    assert!(shown.contains("share_c_version: 3"), "{shown}");
    assert!(shown.contains("stamp_expected: Some(41)"), "{shown}");
    assert!(!shown.to_lowercase().contains("c5"), "{shown}");
    let d = open(
        &w,
        &signed_denial(&w, &denial(&w, GuardianDenyReason::Rate)),
    )
    .unwrap();
    assert_eq!(format!("{d:?}"), "Denied(Rate)");
}

// ── H1b: the signed M2 stamp-confirm ack ─────────────────────────────

fn stamp_confirm(target: u64, token: [u8; 32]) -> GuardianStampConfirm {
    GuardianStampConfirm {
        v: GUARDIAN_WIRE_V,
        vm_id: VM.into(),
        target,
        token: token.to_vec(),
    }
}

fn ack_for(c: &GuardianStampConfirm) -> GuardianStampAck {
    GuardianStampAck {
        v: GUARDIAN_WIRE_V,
        vm_id: c.vm_id.clone(),
        target: c.target,
        token_hash: stamp_token_hash(&c.token).to_vec(),
    }
}

fn signed_ack(key: &SigningKey, domain: &[u8], a: &GuardianStampAck) -> Vec<u8> {
    let body = encode_canonical(a).unwrap();
    let sig = key.sign(&signing_input(domain, &body)).to_bytes().to_vec();
    encode_canonical(&SignedGuardianStampAck { body, sig }).unwrap()
}

#[test]
fn a_signed_ack_for_this_confirm_verifies() {
    let w = world(KeyMode::Customer, Some(1));
    let c = stamp_confirm(42, TOKEN);
    let reply = signed_ack(&w.gk, STAMP_ACK_SIG_DOMAIN, &ack_for(&c));
    verify_stamp_ack(&reply, &w.binding, &c).unwrap();
}

#[test]
fn an_unsigned_or_forged_ack_is_refused() {
    let w = world(KeyMode::Customer, Some(1));
    let c = stamp_confirm(42, TOKEN);
    let a = ack_for(&c);
    // The old bare `{v}` ack, and the bare body with no envelope.
    let bare = encode_canonical(&ack_for(&c)).unwrap();
    for reply in [
        vec![0xa1, 0x61, 0x76, 0x01],
        bare,
        Vec::new(),
        b"ok".to_vec(),
    ] {
        assert!(
            matches!(
                verify_stamp_ack(&reply, &w.binding, &c),
                Err(GuestError::Decode(_))
            ),
            "{reply:02x?}"
        );
    }
    // Signed by another key.
    let other = SigningKey::from_bytes(&[10u8; 32]);
    let reply = signed_ack(&other, STAMP_ACK_SIG_DOMAIN, &a);
    assert!(matches!(
        verify_stamp_ack(&reply, &w.binding, &c),
        Err(GuestError::Signature(_))
    ));
    // Signed by the guardian, but under another guardian domain: a
    // response or denial signature is never an ack.
    for domain in [RESP_SIG_DOMAIN, DENY_SIG_DOMAIN, b"".as_slice()] {
        let reply = signed_ack(&w.gk, domain, &a);
        assert!(matches!(
            verify_stamp_ack(&reply, &w.binding, &c),
            Err(GuestError::Signature(_))
        ));
    }
    // One flipped signature bit, and a zero signature.
    let body = encode_canonical(&a).unwrap();
    let mut sig =
        w.gk.sign(&signing_input(STAMP_ACK_SIG_DOMAIN, &body))
            .to_bytes()
            .to_vec();
    sig[7] ^= 1;
    for sig in [sig, vec![0; 64]] {
        let reply = encode_canonical(&SignedGuardianStampAck {
            body: body.clone(),
            sig,
        })
        .unwrap();
        assert!(verify_stamp_ack(&reply, &w.binding, &c).is_err());
    }
    // A signature of the wrong length.
    let reply = encode_canonical(&SignedGuardianStampAck {
        body,
        sig: vec![0; 63],
    })
    .unwrap();
    assert!(matches!(
        verify_stamp_ack(&reply, &w.binding, &c),
        Err(GuestError::Decode(_))
    ));
}

#[test]
fn a_signed_ack_for_another_confirm_is_refused() {
    let w = world(KeyMode::Customer, Some(1));
    let c = stamp_confirm(42, TOKEN);
    let edits: [fn(&mut GuardianStampAck); 5] = [
        |a| a.vm_id = "vm-other".into(),
        |a| a.target = 43,
        |a| a.target = 41,
        |a| a.token_hash = stamp_token_hash(&[0x7F; 32]).to_vec(),
        |a| a.v = 2,
    ];
    for (i, f) in edits.iter().enumerate() {
        let mut a = ack_for(&c);
        f(&mut a);
        let reply = signed_ack(&w.gk, STAMP_ACK_SIG_DOMAIN, &a);
        assert!(
            matches!(
                verify_stamp_ack(&reply, &w.binding, &c),
                Err(GuestError::Schema(_))
            ),
            "case {i}"
        );
    }
}

#[test]
fn an_ack_replayed_across_a_guardian_epoch_reset_is_refused() {
    // The same (vm_id, target) after a guardian re-init: a new release
    // sealed a NEW token. The relay replays the genuine, correctly signed
    // ack it recorded the first time round.
    let w = world(KeyMode::Customer, Some(1));
    let first = stamp_confirm(1, TOKEN);
    let recorded = signed_ack(&w.gk, STAMP_ACK_SIG_DOMAIN, &ack_for(&first));
    verify_stamp_ack(&recorded, &w.binding, &first).unwrap();
    let again = stamp_confirm(1, [0x3C; 32]);
    assert!(matches!(
        verify_stamp_ack(&recorded, &w.binding, &again),
        Err(GuestError::Schema(_))
    ));
}

#[test]
fn a_non_canonical_ack_body_is_refused() {
    let w = world(KeyMode::Customer, Some(1));
    let c = stamp_confirm(42, TOKEN);
    // The canonical body with its map re-encoded in non-canonical order
    // (`v` last): same value, a second wire image — signed, still refused.
    let a = ack_for(&c);
    let v = |s: &str| ciborium::value::Value::Text(s.into());
    let map = ciborium::value::Value::Map(vec![
        (v("vm_id"), v(VM)),
        (
            v("target"),
            ciborium::value::Value::Integer(a.target.into()),
        ),
        (
            v("token_hash"),
            ciborium::value::Value::Bytes(a.token_hash.clone()),
        ),
        (v("v"), ciborium::value::Value::Integer(1.into())),
    ]);
    let mut body = Vec::new();
    ciborium::ser::into_writer(&map, &mut body).unwrap();
    assert_ne!(body, encode_canonical(&a).unwrap());
    let sig =
        w.gk.sign(&signing_input(STAMP_ACK_SIG_DOMAIN, &body))
            .to_bytes()
            .to_vec();
    let reply = encode_canonical(&SignedGuardianStampAck { body, sig }).unwrap();
    assert!(matches!(
        verify_stamp_ack(&reply, &w.binding, &c),
        Err(GuestError::Decode(_))
    ));
}

/// Independently generated with python3 `cbor2` + `cryptography`
/// (Ed25519 key = 32 × 0x61, domain `hippius-guardian-stamp-ack-v1\0`,
/// ack `{v:1, vm_id:"vm-1", target:300, token_hash: sha256(32 × 0x22)}`).
const FIXTURE_SIGNED_ACK: &str = "a2637369675840a825cb66c625e9527814d5fbde5e652247dc9265e35ac775fb\
     68a7bb49c9b8e4fc323e2b89ccb293437092c8cf908131ebedc4ae97d1018370\
     95a8ceff2bfa0c64626f64795846a461760165766d5f696464766d2d31667461\
     7267657419012c6a746f6b656e5f6861736858209f72ea0cf49536e3c66c787f\
     705186df9a4378083753ae9536d65b3ad7fcddc4";
const FIXTURE_ACK_PK: &str = "af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d";

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_signed_ack_fixture_verifies_and_is_what_a_signer_produces() {
    let key = SigningKey::from_bytes(&[0x61; 32]);
    assert_eq!(
        key.verifying_key().to_bytes().to_vec(),
        unhex(FIXTURE_ACK_PK)
    );
    let cmdline = format!(
        "ro hippius.key_mode=customer hippius.guardian_pk={FIXTURE_ACK_PK} \
         hippius.guardian_ep=3130302e36342e302e393a37343433"
    );
    let binding = GuardianBinding::from_cmdline(&cmdline).unwrap().unwrap();
    let c = GuardianStampConfirm {
        v: 1,
        vm_id: "vm-1".into(),
        target: 300,
        token: vec![0x22; 32],
    };
    let fixture = unhex(FIXTURE_SIGNED_ACK);
    verify_stamp_ack(&fixture, &binding, &c).unwrap();
    // Ed25519 is deterministic: this code signs to the same bytes.
    assert_eq!(
        signed_ack(&key, STAMP_ACK_SIG_DOMAIN, &ack_for(&c)),
        fixture
    );
}
