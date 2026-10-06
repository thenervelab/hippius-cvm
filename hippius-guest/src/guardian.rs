//! Guest side of the customer-held-keys **guardian leg**: turn the bytes
//! a (relayed, untrusted) guardian answered into either `share_C` or a
//! denial the guest may act on — and nothing else.
//!
//! The wire contract lives in [`hippius_types::guardian`]; this module
//! owns the two pieces of crypto that crate stays free of: the Ed25519
//! check against the MEASURED guardian key, and the HPKE open of the
//! sealed share (and, in M2, of the sealed stamp token).
//!
//! Order of work in [`open_guardian_reply`] — any failure is an `Err`,
//! and an `Err` is never a decision (the caller retries):
//!
//! 1. Decode the `{body, sig}` envelope (canonical CBOR only).
//! 2. Verify `sig` with `verify_strict` against `binding.guardian_pk`
//!    over [`RESP_SIG_DOMAIN`]` ‖ body`. On success the body is a
//!    [`GuardianResponse`]; otherwise try [`DENY_SIG_DOMAIN`]` ‖ body`,
//!    whose success makes it a [`GuardianDenial`]. A signature under
//!    neither domain is noise: unsigned, forged, or signed by any key
//!    but the measured one. The domain — not the HTTP status, which the
//!    relay controls — decides which of the two the body is.
//! 3. Decode the body canonically and run the shared
//!    `check_against` rules (vm_id, nonce, `sha256(guest_pub)`, mode,
//!    share version). A denial that fails them is a replay and is noise
//!    too — never a reason to show `refused:*`, least of all `erased`.
//! 4. Response only: HPKE-open the share (and the M2 stamp token) with
//!    the exact `info` / `aad` the guardian sealed under.
//!
//! Signature BEFORE HPKE is load-bearing: in M2 an unauthenticated share
//! on first boot would let the relay choose the key the blank volume is
//! formatted with. HPKE alone only proves the sender knew `guest_pub`,
//! which the relay does.

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::guardian::{
    decode_canonical, GuardianBinding, GuardianDenial, GuardianDenyReason, GuardianReleaseRequest,
    GuardianResponse, GuardianStampAck, GuardianStampConfirm, GuardianWrapped, KeyMode,
    SignedGuardianResponse, SignedGuardianStampAck, DENY_SIG_DOMAIN, KEY_LEN, RESP_SIG_DOMAIN,
    SHARE_HPKE_INFO, STAMP_ACK_SIG_DOMAIN, STAMP_TOKEN_HPKE_INFO,
};
use kbs_core::crypto::hpke_open_raw;
use zeroize::Zeroizing;

/// The M2 volume stamp a verified guardian response carries: the
/// guardian's confirmed stamp `E` and the single-use token that
/// authorises confirming exactly `E + 1`.
pub struct GuardianStamp {
    /// `E` — the guest refuses a volume whose stamp is below it.
    pub expected: u64,
    /// Authorises `/v1/guardian/stamp/confirm` for `expected + 1` only.
    pub token: Zeroizing<[u8; KEY_LEN]>,
}

/// A verified, opened guardian release.
pub struct GuardianRelease {
    /// `share_C`.
    pub share_c: Zeroizing<[u8; KEY_LEN]>,
    /// The version of `share_c` — what the volume's LUKS2 token records.
    pub share_c_version: u32,
    /// M2 only; `None` in M1 (the KBS owns the stamp there).
    pub stamp: Option<GuardianStamp>,
}

/// What a guardian answer means, once verified.
pub enum GuardianReply {
    Released(GuardianRelease),
    Denied(GuardianDenyReason),
}

// Never print key material, even by accident.
impl core::fmt::Debug for GuardianReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GuardianReply::Released(r) => f
                .debug_struct("Released")
                .field("share_c_version", &r.share_c_version)
                .field("stamp_expected", &r.stamp.as_ref().map(|s| s.expected))
                .finish(),
            GuardianReply::Denied(reason) => f.debug_tuple("Denied").field(reason).finish(),
        }
    }
}

/// Verify and open one guardian answer to `request`, sent by a guest
/// whose MEASURED cmdline yielded `binding` and whose ephemeral X25519
/// secret for this request is `guest_sk`. See the module docs for the
/// exact order of checks.
pub fn open_guardian_reply(
    reply: &[u8],
    binding: &GuardianBinding,
    request: &GuardianReleaseRequest,
    guest_sk: &[u8; KEY_LEN],
) -> Result<GuardianReply> {
    // `SignedGuardianResponse` and `SignedGuardianDenial` are the same
    // `{body, sig}` shape; the signature domain tells them apart.
    let signed: SignedGuardianResponse =
        decode_canonical(reply).map_err(|e| GuestError::Decode(format!("guardian: {e}")))?;
    signed
        .validate()
        .map_err(|e| GuestError::Decode(format!("guardian: {e}")))?;
    let vk = VerifyingKey::from_bytes(&binding.guardian_pk)
        .map_err(|_| GuestError::Signature("guardian_pk is not an Ed25519 key".into()))?;
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|_| GuestError::Signature("guardian signature malformed".into()))?;

    if verify(&vk, &sig, RESP_SIG_DOMAIN, &signed.body) {
        let resp: GuardianResponse = decode_canonical(&signed.body)
            .map_err(|e| GuestError::Decode(format!("guardian response: {e}")))?;
        resp.check_against(binding, request)
            .map_err(|e| GuestError::Schema(format!("guardian response: {e}")))?;
        return open_release(&resp, guest_sk).map(GuardianReply::Released);
    }
    if verify(&vk, &sig, DENY_SIG_DOMAIN, &signed.body) {
        let denial: GuardianDenial = decode_canonical(&signed.body)
            .map_err(|e| GuestError::Decode(format!("guardian denial: {e}")))?;
        denial
            .check_against(request)
            .map_err(|e| GuestError::Schema(format!("guardian denial: {e}")))?;
        return Ok(GuardianReply::Denied(denial.reason));
    }
    Err(GuestError::Signature(
        "guardian answer not signed by the measured guardian_pk".into(),
    ))
}

/// Verify the guardian's answer to the M2 stamp `confirm` this guest just
/// sent, for a guest whose MEASURED cmdline yielded `binding`. `Ok` means
/// the guardian itself says it advanced THIS VM's stamp to THIS target on
/// THIS token; anything else is an `Err` and the confirm counts as not
/// done — the answer is relayed by the miner, which could otherwise report
/// a confirm it dropped.
///
/// Checks, in order: canonical `{body, sig}` envelope; `verify_strict`
/// against `binding.guardian_pk` over [`STAMP_ACK_SIG_DOMAIN`]` ‖ body`
/// (a response or denial signature never verifies here); canonical
/// [`GuardianStampAck`] body; [`GuardianStampAck::check_against`] the
/// confirm (`vm_id`, `target`, `sha256(token)`) — which is what stops an
/// ack recorded for an earlier confirm of the same `(vm_id, target)` from
/// being replayed.
pub fn verify_stamp_ack(
    reply: &[u8],
    binding: &GuardianBinding,
    confirm: &GuardianStampConfirm,
) -> Result<()> {
    let signed: SignedGuardianStampAck =
        decode_canonical(reply).map_err(|e| GuestError::Decode(format!("stamp ack: {e}")))?;
    signed
        .validate()
        .map_err(|e| GuestError::Decode(format!("stamp ack: {e}")))?;
    let vk = VerifyingKey::from_bytes(&binding.guardian_pk)
        .map_err(|_| GuestError::Signature("guardian_pk is not an Ed25519 key".into()))?;
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|_| GuestError::Signature("stamp ack signature malformed".into()))?;
    if !verify(&vk, &sig, STAMP_ACK_SIG_DOMAIN, &signed.body) {
        return Err(GuestError::Signature(
            "stamp ack not signed by the measured guardian_pk".into(),
        ));
    }
    let ack: GuardianStampAck = decode_canonical(&signed.body)
        .map_err(|e| GuestError::Decode(format!("stamp ack body: {e}")))?;
    ack.check_against(confirm)
        .map_err(|e| GuestError::Schema(format!("stamp ack: {e}")))
}

fn verify(vk: &VerifyingKey, sig: &Signature, domain: &[u8], body: &[u8]) -> bool {
    let input = hippius_types::guardian::signing_input(domain, body);
    vk.verify_strict(&input, sig).is_ok()
}

fn open_release(resp: &GuardianResponse, guest_sk: &[u8; KEY_LEN]) -> Result<GuardianRelease> {
    let aad = resp
        .wrap_aad()
        .map_err(|e| GuestError::Schema(format!("guardian aad: {e}")))?;
    let share_c = open_32(
        guest_sk,
        &resp.wrapped_share,
        SHARE_HPKE_INFO,
        &aad,
        "share",
    )?;
    // `check_against` already pinned the stamp fields to the mode: both
    // present in M2, both absent in M1.
    let stamp = match (
        resp.key_mode,
        resp.expected_volume_stamp,
        &resp.stamp_token_wrapped,
    ) {
        (KeyMode::Customer, Some(expected), Some(w)) => {
            // The token authorises `expected + 1`; a stamp at the top of
            // the range has no next value to confirm.
            expected
                .checked_add(1)
                .ok_or_else(|| GuestError::Schema("guardian stamp overflow".into()))?;
            let token = open_32(guest_sk, w, STAMP_TOKEN_HPKE_INFO, &aad, "stamp-token")?;
            Some(GuardianStamp { expected, token })
        }
        (KeyMode::Split, None, None) => None,
        _ => {
            return Err(GuestError::Schema(
                "guardian stamp fields do not match key_mode".into(),
            ))
        }
    };
    Ok(GuardianRelease {
        share_c,
        share_c_version: resp.share_c_version,
        stamp,
    })
}

fn open_32(
    guest_sk: &[u8; KEY_LEN],
    w: &GuardianWrapped,
    info: &[u8],
    aad: &[u8],
    what: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let pt = hpke_open_raw(guest_sk, &w.enc, &w.ct, info, aad)
        .map_err(|e| GuestError::Hpke(format!("guardian {what}: {e}")))?;
    if pt.len() != KEY_LEN {
        return Err(GuestError::Hpke(format!(
            "guardian {what}: not {KEY_LEN} bytes"
        )));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests;
