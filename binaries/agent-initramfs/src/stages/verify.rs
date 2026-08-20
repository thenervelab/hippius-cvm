//! Stage 6 — verify the KBS signature and HPKE-unwrap both secrets
//! (PR-E1.3, §6/§7/§19/§20 binding gate).
//!
//! This stage is the ONLY layer that produces the LUKS key and the
//! cloud-init plaintext; every downstream stage (`unlock`, `seed`)
//! consumes the [`Zeroizing`](zeroize::Zeroizing) buffers returned here.
//!
//! The heavy crypto — Ed25519 `verify_strict`, every field binding,
//! HPKE unwrap, the user-data digest recompute — lives in the
//! separately-tested [`hippius_guest::verify_and_unwrap_release`]. This
//! module's job is the **mapping**: assemble an
//! [`ExpectedRelease`](hippius_guest::ExpectedRelease) from the
//! agent's own state — the decoded `OrderTicket`, the KBS nonce, the
//! attestation measurement, the UKI-pinned KBS key id — and hand it to
//! the library.
//!
//! ## Ownership / secret discipline (§20)
//!
//! [`verify_and_unwrap`] takes [`Ephemeral`] **by value**. The §21
//! happy path ends in `switch_root` (`execve(2)`), which does NOT run
//! destructors — so a `Zeroizing` wipe only fires if the drop happens
//! *before* the pivot. Consuming the keypair here forces the X25519
//! secret scalar to wipe the moment this function returns, well before
//! `unlock` / `seed` / `switch_root` start.

use crate::pipeline::AgentError;
use crate::stages::kbs_client::KbsNonce;
use crate::stages::keygen::Ephemeral;
use crate::stages::snp_report::MEASUREMENT_LEN;
use crate::stages::ticket::Ticket;
use ed25519_dalek::VerifyingKey;
use hippius_guest::{verify_and_unwrap_release, ExpectedRelease, UnwrappedSecrets};
use hippius_types::release::SignedResponse;

/// Verify `signed` against the pinned KBS Ed25519 key and unwrap the
/// LUKS + user-data secrets.
///
/// - `keys` — the guest X25519 keypair, **consumed** (see module doc).
/// - `nonce` — the KBS nonce the guest folded into `REPORT_DATA[0..32]`.
/// - `ticket` — the decoded `OrderTicket`, source of the identity /
///   vault-ref / digest bindings.
/// - `measurement` — the guest's OWN launch measurement, read from the
///   SNP report it generated ([`crate::stages::snp_report::measurement`]).
///   Sourced independently so the §20 `measurement` binding actually
///   confirms the KBS is talking about *this* launch.
/// - `pinned_kbs_vk` / `pinned_kbs_kid` — the 32-byte Ed25519 key + its
///   id, baked into the measured UKI (§20).
///
/// Returns the two `Zeroizing` plaintexts on success; any binding
/// mismatch is a fail-closed `Err`.
pub fn verify_and_unwrap(
    signed: &SignedResponse,
    keys: Ephemeral,
    nonce: &KbsNonce,
    ticket: &Ticket,
    measurement: &[u8; MEASUREMENT_LEN],
    pinned_kbs_vk: &[u8; 32],
    pinned_kbs_kid: &[u8],
) -> Result<UnwrappedSecrets, AgentError> {
    // Reconstruct the pinned KBS verifying key from the UKI-baked bytes.
    let kbs_vk = VerifyingKey::from_bytes(pinned_kbs_vk)
        .map_err(|_| AgentError::Verify("pinned-vk-decode"))?;

    let order = ticket.order();
    // The ticket-pinned user-data digest must be exactly 32 bytes (§20).
    let digest: [u8; 32] = order
        .allowed_userdata_digest()
        .try_into()
        .map_err(|_| AgentError::Verify("digest-length"))?;

    // Consume the keypair → the X25519 secret scalar. `into_secret`
    // hands back a `Zeroizing`; `guest_sk` wipes when it drops at the
    // end of this function — before `unlock` / `seed` / `switch_root`.
    let guest_sk = keys.into_secret();

    let expected = ExpectedRelease {
        vm_id: &order.vm_id,
        ticket_id: &order.ticket_id,
        tenant_id: &order.tenant_id,
        vm_generation: order.vm_generation,
        kbs_nonce: &nonce.0,
        measurement,
        kbs_kid: pinned_kbs_kid,
        luks_path: &order.luks_vault_ref.path,
        luks_version: order.luks_vault_ref.version,
        userdata_path: &order.userdata_vault_ref.path,
        userdata_version: order.userdata_vault_ref.version,
        expected_allowed_userdata_digest: &digest,
        schema_v: order.v,
    };

    // The library performs `verify_strict` + every §6/§7/§19/§20
    // binding before it unwraps a single byte. A `GuestError` is
    // wrapped — its `Display` is audited to carry no plaintext, and
    // `main` only logs `AgentError::class()` regardless.
    verify_and_unwrap_release(signed, &kbs_vk, &guest_sk, &expected).map_err(AgentError::Guest)
}
