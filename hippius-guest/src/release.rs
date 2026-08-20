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
use hippius_types::release::{
    KbsResponse, ReleaseContext, SignedResponse, WrappedSecret, HPKE_SUITE_ID, RELEASE_DOMAIN,
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
    pub luks: Zeroizing<Vec<u8>>,
    pub userdata: Zeroizing<Vec<u8>>,
    /// §7 per-VM guest lifecycle SIGNING key (Ed25519 seed), `None` when
    /// the KBS response carried no `lifecycle_key` (pre-§7 VM). The
    /// caller writes the bytes to the tmpfs path the measured cmdline's
    /// `hippius.lifecycle_key_path` names (mode 0600), where the `eol`
    /// signer loads it to sign the §24/§25 StoppedAck. `Zeroizing` —
    /// the seed wipes on drop, exactly like `luks`/`userdata`.
    pub lifecycle_key: Option<Zeroizing<Vec<u8>>>,
    /// Phase 2A of audit follow-up Codex #2 — the KBS-committed
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
}

// `Debug` that NEVER touches plaintext — only field lengths. Useful for
// test scaffolding that wants `.unwrap_err()` (`Result<T, E>` requires
// `T: Debug` for the Ok side); leaking secret bytes would defeat the
// `Zeroizing` discipline.
impl core::fmt::Debug for UnwrappedSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnwrappedSecrets")
            .field("luks_len", &self.luks.len())
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
            .finish()
    }
}

/// Verify a KBS `SignedResponse` and unwrap both secrets, enforcing
/// every §6/§7/§19/§20 binding. See module-level doc for the exact
/// order of checks.
pub fn verify_and_unwrap_release(
    signed: &SignedResponse,
    kbs_vk: &VerifyingKey,
    guest_x25519_sk: &[u8; 32],
    exp: &ExpectedRelease,
) -> Result<UnwrappedSecrets> {
    // 1+2: signature + decode.
    let resp = verify_response(kbs_vk, signed)
        .map_err(|e| GuestError::Signature(format!("KBS response: {e}")))?;

    // 3: every guest-known binding MUST match. We check each field
    // explicitly (instead of one big eq) so a regression test pins
    // which field drifted.
    bind_str("domain", RELEASE_DOMAIN, &resp.domain)?;
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
    expect_wrapped(
        &resp.luks,
        "luks",
        exp.luks_path,
        exp.luks_version,
        "luks_vault_ref",
    )?;
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
    let luks = hpke_unwrap(guest_x25519_sk, &resp.luks, &luks_ctx)
        .map_err(|e| GuestError::Hpke(format!("luks: {e}")))?;
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
    })
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
