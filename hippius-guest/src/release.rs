//! `verify_and_unwrap_release` — the guest's single trust gate.
//!
//! Order of work (any failure ⇒ Err, no secret returned):
//! 1. Verify the KBS Ed25519 signature on the canonical-CBOR body.
//! 2. Decode the body into `KbsResponse`.
//! 3. For each field the guest knows the expected value of (vm_id,
//!    ticket_id, tenant_id, vm_generation, kbs_nonce, measurement,
//!    kbs_kid), enforce equality. A mismatch ALWAYS means a swapped/
//!    stale response — never accept.
//! 4. Re-derive the canonical [`ReleaseContext`] for `luks` and
//!    `userdata` using the guest's own values + the KBS-signed response
//!    fields. HPKE-unwrap each secret with this context as info+aad —
//!    any context drift fails the AEAD check (§20).
//! 5. Recompute `allowed_userdata_digest` over the user-data plaintext
//!    via `hippius_types::digest::userdata_digest` and constant-time
//!    compare against `response.allowed_userdata_digest` (§6/§19 — the
//!    guest is the LAST line of defense against a KBS-issued response
//!    that points to the wrong KV path/version).
//! 6. Plaintexts are returned in `Zeroizing<Vec<u8>>`; LUKS unlock
//!    consumes the LUKS one, NoCloud writes the user-data one, both
//!    drop before switch_root.

use crate::error::{GuestError, Result};
use ed25519_dalek::VerifyingKey;
use hippius_types::digest::userdata_digest;
use hippius_types::guardian::KeyMode;
use hippius_types::release::{
    KbsResponse, ReleaseContext, SignedResponse, WrappedSecret, HPKE_SUITE_ID, RELEASE_DOMAIN,
    RELEASE_DOMAIN_V2,
};
use kbs_core::crypto::{hpke_unwrap, verify_response};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// `kbs-core::volume_stamp` — the fixed domain-separator `secret_path`
/// the KBS always wraps the confirm token under (see
/// `kbs-core/src/release.rs`'s `stamp_ctx`). Not a real Vault path —
/// the per-VM binding already lives in `vm_id`/`ticket_id`/etc inside
/// the `ReleaseContext`; this is just the label, so the guest can
/// pin it exactly like `luks_path`/`userdata_path`.
const VOLUME_STAMP_SECRET_PATH: &str = "kbs/volume-stamp";

/// Everything the guest knows BEFORE talking to the KBS. These come
/// from the OrderTicket the L1 minted (delivered to the guest via the
/// vali / cloud-init) PLUS the guest's own attestation work
/// (measurement it expects to attest with, kbs_nonce it folded into
/// REPORT_DATA, kbs_kid it accepts).
///
/// `expected_allowed_userdata_digest` is the ticket-pinned 32-byte
/// digest (§6) — the same value the KBS signs back. Comparing the
/// guest's local copy against the KBS-signed response closes the
/// "KBS told me to mount a different VM's user-data" gap (§19) without
/// the guest needing the L1 ticket-signing key.
#[derive(Debug, Clone)]
pub struct ExpectedRelease<'a> {
    pub vm_id: &'a str,
    pub ticket_id: &'a str,
    pub tenant_id: &'a str,
    pub vm_generation: u64,
    pub kbs_nonce: &'a [u8; 32],
    pub measurement: &'a [u8; 48],
    pub kbs_kid: &'a [u8],
    pub luks_path: &'a str,
    pub luks_version: u64,
    pub userdata_path: &'a str,
    pub userdata_version: u64,
    pub expected_allowed_userdata_digest: &'a [u8; 32],
    pub schema_v: u32,
}

/// What the guest gets back. Both secrets `Zeroizing` — drop wipes
/// the plaintext. LUKS unlock should `take`/consume the bytes; user-
/// data should be written to a tmpfs NoCloud seed and then dropped.
pub struct UnwrappedSecrets {
    /// The KBS-released LUKS KEK — the whole keyslot key in `hippius`
    /// (M0) mode and `share_H` in `split` (M1). `None` ONLY for a
    /// `customer` (M2) release, which carries no KEK at all;
    /// [`verify_and_unwrap_release`] (the M0 entry point) never returns
    /// `None`.
    pub luks: Option<Zeroizing<Vec<u8>>>,
    pub userdata: Zeroizing<Vec<u8>>,
    /// §7 per-VM guest lifecycle SIGNING key (Ed25519 seed), `None` when
    /// the KBS response carried no `lifecycle_key` (pre-§7 VM). The
    /// caller writes the bytes to the tmpfs path the measured cmdline's
    /// `hippius.lifecycle_key_path` names (mode 0600), where the `eol`
    /// signer loads it to sign the §24/§25 StoppedAck. `Zeroizing` —
    /// the seed wipes on drop, exactly like `luks`/`userdata`.
    pub lifecycle_key: Option<Zeroizing<Vec<u8>>>,
    /// Phase 2A of audit follow-up Review #2 — the KBS-committed
    /// boot counter for THIS release. The guest persists this
    /// post-unlock so the NEXT boot can submit `prev + 1` and the
    /// KBS detects a rolled-back disk. `0` when the request
    /// omitted `submitted_boot_counter` (pre-Phase-2A wire shape)
    /// AND when an older KBS that doesn't echo the field signs
    /// the response (serde default).
    pub boot_counter: u64,
    /// `kbs-core::volume_stamp` — the last CONFIRMED per-`vm_id` volume
    /// stamp, echoed straight from `KbsResponse::expected_volume_stamp`.
    /// The caller compares this against the stamp stored INSIDE the
    /// encrypted overlay BEFORE assembling the root; `0` means "no
    /// expectation" (fresh VM, a pre-gate VM, or a rebuilt KBS store).
    pub expected_volume_stamp: u64,
    /// The single-use authenticator for `POST /v1/kbs/volume-stamp/
    /// confirm`, unwrapped from `KbsResponse::volume_stamp_token`.
    /// `None` when the KBS response carried no token (pre-gate KBS).
    /// It authorises advancing the KBS's confirmed stamp to EXACTLY
    /// `expected_volume_stamp + 1` — the caller presents it only AFTER
    /// durably writing that value into the encrypted overlay.
    /// `Zeroizing` — wipes on drop, exactly like the other secrets:
    /// an unconfirmed token that leaked would let anyone advance this
    /// VM's expectation ahead of an unstamped volume (a permanent
    /// remote brick — see `kbs-core::volume_stamp` module docs).
    pub volume_stamp_token: Option<Zeroizing<[u8; 32]>>,
    /// Stamp protocol v2 only: `(expected_timeline, target_timeline)` from
    /// the KBS-signed `volume_stamp_transition`. `None` for a release the
    /// guest attested as v1 (the only kind a pre-v2 KBS answers). The
    /// caller accepts its volume only on `expected_timeline` and stamps
    /// `target_timeline` (see the golden overlay's v2 gate).
    pub volume_stamp_transition: Option<([u8; 32], [u8; 32])>,
}

/// The stamp protocol the guest ATTESTED in the SNP report of the release
/// it is verifying (it chose the `REPORT_DATA` layout itself). It decides
/// the ONLY response shape the guest accepts — the KBS derives its answer
/// from that same attested value, so any other shape is a KBS (or a
/// forgery) that is not answering this report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedStampProtocol {
    /// `REPORT_DATA = nonce ‖ pub` (`hippius_types::report_data::tenant`):
    /// the response MUST be `HIPPIUS_KBS_RELEASE_V1` with no transition.
    V1,
    /// `REPORT_DATA = SHA-256(v2 domain ‖ nonce) ‖ pub`
    /// (`hippius_types::report_data::tenant_stamp_v2`): the response MUST
    /// be `HIPPIUS_KBS_RELEASE_V2` with a well-formed transition.
    V2,
}

// `Debug` that NEVER touches plaintext — only field lengths. Useful for
// test scaffolding that wants `.unwrap_err()` (`Result<T, E>` requires
// `T: Debug` for the Ok side); leaking secret bytes would defeat the
// `Zeroizing` discipline.
impl core::fmt::Debug for UnwrappedSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnwrappedSecrets")
            .field("luks_len", &self.luks.as_ref().map(|k| k.len()))
            .field("userdata_len", &self.userdata.len())
            .field(
                "lifecycle_key_len",
                &self.lifecycle_key.as_ref().map(|k| k.len()),
            )
            .field("boot_counter", &self.boot_counter)
            .field("expected_volume_stamp", &self.expected_volume_stamp)
            .field(
                "volume_stamp_token_present",
                &self.volume_stamp_token.is_some(),
            )
            .field(
                "volume_stamp_transition_present",
                &self.volume_stamp_transition.is_some(),
            )
            .finish()
    }
}

/// Verify a KBS `SignedResponse` and unwrap both secrets, enforcing
/// every §6/§7/§19/§20 binding. See module-level doc for the exact
/// order of checks. The `hippius` (M0) key mode: the response MUST carry
/// the LUKS KEK, and the returned [`UnwrappedSecrets::luks`] is always
/// `Some`.
pub fn verify_and_unwrap_release(
    signed: &SignedResponse,
    kbs_vk: &VerifyingKey,
    guest_x25519_sk: &[u8; 32],
    exp: &ExpectedRelease,
) -> Result<UnwrappedSecrets> {
    verify_and_unwrap_release_for_mode(signed, kbs_vk, guest_x25519_sk, exp, KeyMode::Hippius)
}

/// [`verify_and_unwrap_release`] for a VM whose disk key mode is `mode`
/// (customer-held keys). Every binding is identical in every mode; only
/// the KEK's presence differs:
///
/// - `hippius` (M0) and `split` (M1): the response MUST carry `luks` —
///   in M1 it is `share_H`, the Hippius half of the keyslot key;
/// - `customer` (M2): the response MUST NOT carry `luks`. The KBS
///   releases no KEK in M2, so a `luks` secret here is a KBS (or a
///   ticket) that does not know this VM's mode — refused rather than
///   silently dropped, since the guest's KEK must then come from the
///   guardian's share alone.
pub fn verify_and_unwrap_release_for_mode(
    signed: &SignedResponse,
    kbs_vk: &VerifyingKey,
    guest_x25519_sk: &[u8; 32],
    exp: &ExpectedRelease,
    mode: KeyMode,
) -> Result<UnwrappedSecrets> {
    verify_and_unwrap_release_attested(
        signed,
        kbs_vk,
        guest_x25519_sk,
        exp,
        mode,
        AttestedStampProtocol::V1,
    )
}

/// [`verify_and_unwrap_release_for_mode`] for a release whose SNP report
/// attested `attested` (stamp protocol v2). A v1 attestation is exactly
/// the function above; a v2 one accepts ONLY a `HIPPIUS_KBS_RELEASE_V2`
/// response carrying a well-formed `volume_stamp_transition`:
///
/// - both ids exactly 32 bytes;
/// - a move to ANOTHER timeline — an authorized rollback, or the fresh
///   timeline of an unconfirmed (`E = 0`) VM — only to a non-zero target,
///   and at `E = 0` only FROM the zero timeline (gate 5c'); a
///   rollback-style move at `E = 0` is refused.
pub fn verify_and_unwrap_release_attested(
    signed: &SignedResponse,
    kbs_vk: &VerifyingKey,
    guest_x25519_sk: &[u8; 32],
    exp: &ExpectedRelease,
    mode: KeyMode,
    attested: AttestedStampProtocol,
) -> Result<UnwrappedSecrets> {
    // 1+2: signature + decode.
    let resp = verify_response(kbs_vk, signed)
        .map_err(|e| GuestError::Signature(format!("KBS response: {e}")))?;

    // 3: every guest-known binding MUST match. We check each field
    // explicitly (instead of one big eq) so a regression test pins
    // which field drifted. The domain is the one the attested protocol
    // selects — never "either".
    let (want_domain, transition) = match attested {
        AttestedStampProtocol::V1 => {
            if resp.volume_stamp_transition.is_some() {
                return Err(GuestError::Binding {
                    field: "volume_stamp_transition",
                    expected: "absent (stamp protocol v1)".into(),
                    got: "a transition".into(),
                });
            }
            (RELEASE_DOMAIN, None)
        }
        AttestedStampProtocol::V2 => (RELEASE_DOMAIN_V2, Some(check_transition(&resp)?)),
    };
    bind_str("domain", want_domain, &resp.domain)?;
    bind_u32("v", exp.schema_v, resp.v)?;
    bind_str("vm_id", exp.vm_id, &resp.vm_id)?;
    bind_str("ticket_id", exp.ticket_id, &resp.ticket_id)?;
    bind_str("tenant_id", exp.tenant_id, &resp.tenant_id)?;
    bind_u64("vm_generation", exp.vm_generation, resp.vm_generation)?;
    bind_bytes("kbs_nonce", exp.kbs_nonce, &resp.kbs_nonce)?;
    bind_bytes("measurement", exp.measurement, &resp.measurement)?;
    bind_bytes("kbs_kid", exp.kbs_kid, &resp.kbs_kid)?;
    bind_u16("hpke_suite_id", HPKE_SUITE_ID, resp.hpke_suite_id)?;
    // Ticket-pinned digest must equal the KBS-signed digest. If those
    // diverge the KBS or its caller picked a different user-data
    // version than the ticket authorized.
    bind_bytes(
        "allowed_userdata_digest",
        exp.expected_allowed_userdata_digest,
        &resp.allowed_userdata_digest,
    )?;

    // Wrapped-secret refs must match what the guest expects, and the
    // secret_type must be the corresponding type — `luks` is the LUKS
    // slot key, `userdata` is the cloud-init user-data ciphertext-blob.
    // Only a `customer`-mode (M2) release omits the KEK: in every other
    // mode a KEK-less response is a binding failure, never a silently
    // empty KEK, and in M2 a KEK-carrying one is.
    let wrapped_luks = match (mode, resp.luks.as_ref()) {
        (KeyMode::Customer, None) => None,
        (KeyMode::Customer, Some(_)) => {
            return Err(GuestError::Binding {
                field: "luks_vault_ref",
                expected: "absent (key_mode customer)".into(),
                got: "a luks secret".into(),
            })
        }
        (_, Some(w)) => Some(w),
        (_, None) => {
            return Err(GuestError::Binding {
                field: "luks_vault_ref",
                expected: "a luks secret".into(),
                got: "absent".into(),
            })
        }
    };
    if let Some(w) = wrapped_luks {
        expect_wrapped(w, "luks", exp.luks_path, exp.luks_version, "luks_vault_ref")?;
    }
    expect_wrapped(
        &resp.userdata,
        "userdata",
        exp.userdata_path,
        exp.userdata_version,
        "userdata_vault_ref",
    )?;

    // 4: re-derive ReleaseContext per secret and unwrap.
    let luks_ctx = release_ctx_for(&resp, exp, "luks", exp.luks_path, exp.luks_version);
    let ud_ctx = release_ctx_for(
        &resp,
        exp,
        "userdata",
        exp.userdata_path,
        exp.userdata_version,
    );
    let luks = wrapped_luks
        .map(|w| {
            hpke_unwrap(guest_x25519_sk, w, &luks_ctx)
                .map_err(|e| GuestError::Hpke(format!("luks: {e}")))
        })
        .transpose()?;
    let userdata = hpke_unwrap(guest_x25519_sk, &resp.userdata, &ud_ctx)
        .map_err(|e| GuestError::Hpke(format!("userdata: {e}")))?;

    // 5: recompute user-data digest and ct-compare. The streaming
    // SHA-256 helper never copies the plaintext, so the only place it
    // touches non-zeroizing memory is its internal block buffer (which
    // SHA-256 does not surface).
    let recomputed = userdata_digest(
        exp.tenant_id,
        exp.vm_id,
        exp.ticket_id,
        "userdata",
        exp.userdata_path,
        exp.userdata_version,
        &userdata,
    );
    if recomputed
        .ct_eq(&resp.allowed_userdata_digest[..])
        .unwrap_u8()
        != 1
    {
        return Err(GuestError::DigestMismatch);
    }

    // §7: unwrap the lifecycle SIGNING key when present. The KBS sets
    // its `secret_path`/`secret_version` (a per-VM Vault path the guest
    // doesn't know a priori — it's KBS-derived), `secret_type =
    // "lifecycle"`. We re-derive the identical HPKE context from those
    // KBS-signed fields + the guest's own values and unwrap; any drift
    // fails the AEAD open (§20). `None` ⇒ pre-§7 VM, no key released.
    //
    // The seed length is NOT enforced here (the loader / `eol` checks
    // the 32-byte invariant) so this stays a thin unwrap; a wrong-length
    // blob simply makes `eol` skip signing (fail-closed, never a crash).
    let lifecycle_key = match resp.lifecycle_key.as_ref() {
        Some(w) => {
            if w.secret_type != "lifecycle" {
                return Err(GuestError::Binding {
                    field: "lifecycle_key",
                    expected: "type=lifecycle".into(),
                    got: format!("type={}", w.secret_type),
                });
            }
            let lc_ctx = release_ctx_for(&resp, exp, "lifecycle", &w.secret_path, w.secret_version);
            let seed = hpke_unwrap(guest_x25519_sk, w, &lc_ctx)
                .map_err(|e| GuestError::Hpke(format!("lifecycle: {e}")))?;
            Some(seed)
        }
        None => None,
    };

    // `kbs-core::volume_stamp`: unwrap the single-use confirm token when
    // present. Unlike luks/userdata, the guest has no PRIOR expectation
    // of `expected_volume_stamp` — it is KBS-side state — so it is
    // adopted as signed. What the guest CAN and does pin: the token's
    // own `secret_version` must be exactly `expected_volume_stamp + 1`
    // (the value it authorises confirming to) and its `secret_path`
    // must be the fixed domain-separator label — sharp binding checks
    // before the AEAD open, same spirit as `expect_wrapped` for
    // luks/userdata. Any drift (wrong type/path/version, or a token
    // sealed under a different context) fails closed.
    let volume_stamp_token = match resp.volume_stamp_token.as_ref() {
        Some(w) => {
            if w.secret_type != "volume-stamp-token" {
                return Err(GuestError::Binding {
                    field: "volume_stamp_token",
                    expected: "type=volume-stamp-token".into(),
                    got: format!("type={}", w.secret_type),
                });
            }
            let want_version =
                resp.expected_volume_stamp
                    .checked_add(1)
                    .ok_or_else(|| GuestError::Binding {
                        field: "volume_stamp_token",
                        expected: "expected_volume_stamp + 1 (no overflow)".into(),
                        got: format!("expected_volume_stamp={}", resp.expected_volume_stamp),
                    })?;
            if w.secret_version != want_version {
                return Err(GuestError::Binding {
                    field: "volume_stamp_token",
                    expected: format!("version={want_version}"),
                    got: format!("version={}", w.secret_version),
                });
            }
            if w.secret_path != VOLUME_STAMP_SECRET_PATH {
                return Err(GuestError::Binding {
                    field: "volume_stamp_token",
                    expected: format!("path={VOLUME_STAMP_SECRET_PATH}"),
                    got: format!("path={}", w.secret_path),
                });
            }
            let stamp_ctx = release_ctx_for(
                &resp,
                exp,
                "volume-stamp-token",
                &w.secret_path,
                w.secret_version,
            );
            let token = hpke_unwrap(guest_x25519_sk, w, &stamp_ctx)
                .map_err(|e| GuestError::Hpke(format!("volume-stamp-token: {e}")))?;
            let arr: [u8; 32] = token
                .as_slice()
                .try_into()
                .map_err(|_| GuestError::Binding {
                    field: "volume_stamp_token",
                    expected: "32 bytes".into(),
                    got: format!("{} bytes", token.len()),
                })?;
            Some(Zeroizing::new(arr))
        }
        None => None,
    };

    Ok(UnwrappedSecrets {
        luks,
        userdata,
        lifecycle_key,
        boot_counter: resp.boot_counter,
        expected_volume_stamp: resp.expected_volume_stamp,
        volume_stamp_token,
        volume_stamp_transition: transition,
    })
}

/// The v2 response's `volume_stamp_transition`, checked (see
/// [`verify_and_unwrap_release_attested`]).
fn check_transition(resp: &KbsResponse) -> Result<([u8; 32], [u8; 32])> {
    let t = resp
        .volume_stamp_transition
        .as_ref()
        .ok_or_else(|| GuestError::Binding {
            field: "volume_stamp_transition",
            expected: "a transition (stamp protocol v2)".into(),
            got: "absent".into(),
        })?;
    let (expected, target) = t.ids().ok_or_else(|| GuestError::Binding {
        field: "volume_stamp_transition",
        expected: "32-byte timeline ids".into(),
        got: format!(
            "{}/{} bytes",
            t.expected_timeline_id.len(),
            t.target_timeline_id.len()
        ),
    })?;
    // A MOVE (expected != target) must land on a non-zero timeline (the
    // zero timeline is the one every VM counts from after a KBS store
    // wipe — never a target). At `E = 0` the ONLY legitimate move is the
    // zero → fresh one of gate 5c': a v2 release of an unconfirmed VM
    // (fresh, or a wiped KBS row) moves it to a fresh timeline so every
    // older disk is refusable afterwards; with `E = 0` the gate adopts
    // whatever it finds anyway, so writing `(target, 1)` loses nothing. A
    // rollback-style move at `E = 0` (from a NON-zero timeline) is never
    // issued by the KBS — an authorized rollback restores a confirmed
    // point, `E_T > 0` — and would let the E = 0 adopt land any disk on
    // the new timeline: refused (defence in depth).
    let zero = [0u8; 32];
    let is_move = expected != target;
    let move_from_nonzero_at_e0 = resp.expected_volume_stamp == 0 && expected != zero;
    if is_move && (target == zero || move_from_nonzero_at_e0) {
        return Err(GuestError::Binding {
            field: "volume_stamp_transition",
            expected: "a move to a non-zero timeline, and at E = 0 only from the zero timeline"
                .into(),
            got: format!(
                "target_zero={} expected_zero={} expected_volume_stamp={}",
                target == zero,
                expected == zero,
                resp.expected_volume_stamp
            ),
        });
    }
    Ok((expected, target))
}

fn release_ctx_for<'a>(
    resp: &'a KbsResponse,
    exp: &'a ExpectedRelease<'a>,
    secret_type: &'a str,
    secret_path: &'a str,
    secret_version: u64,
) -> ReleaseContext<'a> {
    // measurement/kbs_kid fields in `resp` are Vec — but they were just
    // bound-checked equal to the guest-supplied arrays, so we use the
    // guest's `[u8; 48]` / borrowed `kbs_kid` to satisfy the lifetime.
    // `kbs_nonce` likewise.
    let _ = resp; // resp's values are equal to exp's by check above.
    ReleaseContext {
        v: exp.schema_v,
        ticket_id: exp.ticket_id,
        tenant_id: exp.tenant_id,
        vm_id: exp.vm_id,
        vm_generation: exp.vm_generation,
        kbs_nonce: exp.kbs_nonce,
        measurement: exp.measurement,
        kbs_kid: exp.kbs_kid,
        secret_type,
        secret_path,
        secret_version,
        // §20 ticket-pinned digest is part of the HPKE info+aad —
        // ensures the AEAD tag is bound to the ticket's user-data
        // commitment (defence-in-depth alongside the signature check
        // and the post-unwrap recompute).
        allowed_userdata_digest: exp.expected_allowed_userdata_digest,
    }
}

fn expect_wrapped(
    w: &WrappedSecret,
    want_type: &str,
    want_path: &str,
    want_version: u64,
    field: &'static str,
) -> Result<()> {
    if w.secret_type != want_type {
        return Err(GuestError::Binding {
            field,
            expected: format!("type={want_type}"),
            got: format!("type={}", w.secret_type),
        });
    }
    if w.secret_path != want_path {
        return Err(GuestError::Binding {
            field,
            expected: format!("path={want_path}"),
            got: format!("path={}", w.secret_path),
        });
    }
    if w.secret_version != want_version {
        return Err(GuestError::Binding {
            field,
            expected: format!("version={want_version}"),
            got: format!("version={}", w.secret_version),
        });
    }
    Ok(())
}

// --- small binding helpers (one per type so the error names a field) ---

fn bind_str(field: &'static str, want: &str, got: &str) -> Result<()> {
    if want == got {
        Ok(())
    } else {
        Err(GuestError::Binding {
            field,
            expected: want.into(),
            got: got.into(),
        })
    }
}
fn bind_bytes(field: &'static str, want: &[u8], got: &[u8]) -> Result<()> {
    if want.len() == got.len() && want.ct_eq(got).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(GuestError::Binding {
            field,
            expected: format!("len={}", want.len()),
            got: format!("len={}", got.len()),
        })
    }
}
fn bind_u32(field: &'static str, want: u32, got: u32) -> Result<()> {
    if want == got {
        Ok(())
    } else {
        Err(GuestError::Binding {
            field,
            expected: want.to_string(),
            got: got.to_string(),
        })
    }
}
fn bind_u16(field: &'static str, want: u16, got: u16) -> Result<()> {
    if want == got {
        Ok(())
    } else {
        Err(GuestError::Binding {
            field,
            expected: want.to_string(),
            got: got.to_string(),
        })
    }
}
fn bind_u64(field: &'static str, want: u64, got: u64) -> Result<()> {
    if want == got {
        Ok(())
    } else {
        Err(GuestError::Binding {
            field,
            expected: want.to_string(),
            got: got.to_string(),
        })
    }
}
