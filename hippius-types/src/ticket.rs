//! OrderTicket schema (ARCHITECTURE.md §6). This crate carries the
//! **types only** — COSE_Sign1 verification, expiry/now checks, and
//! the `accepts_l1_kid(measurement, kid)` allowlist gate all live in
//! kbs-core (KBS responsibility) so L1 (the minter) can depend on the
//! types without pulling in the verification stack.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::flavor::Flavor;
use crate::guardian::KeyMode;

/// The only OrderTicket schema version this control plane accepts (§6).
///
/// # History
/// - **v1** (initial) — carried `resource_class: String`, a free-form
///   audit label.
/// - **v2** (#312) — `resource_class` retired; replaced with
///   `flavor: Flavor`, the strongly-typed catalogue identifier. Wire
///   bytes change because `Value::Text("flavor")` ≠
///   `Value::Text("resource_class")`. Single-use, short-lived tickets
///   mean there are no in-flight v1 envelopes to migrate.
pub const SCHEMA_V: u32 = 2;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultRef {
    pub path: String,
    pub version: u64,
}

/// All fields are signed (§6). `deny_unknown_fields` — an unknown field
/// is a hard reject (schema is fixed by `v`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderTicket {
    pub v: u32,
    pub ticket_id: String,
    pub issue_time: u64,
    pub expiry: u64,
    /// Ticket single-use nonce. NOTE: the §7 release-once primitive is
    /// keyed by `(ticket_id, KBS_nonce)` — this field is a separate
    /// L1-supplied per-ticket nonce.
    pub nonce: ByteBuf,
    pub tenant_id: String,
    pub user_id: String,
    pub vm_id: String,
    /// §24/§25 lifecycle binding.
    pub lease_id: String,
    pub vm_generation: u64,
    /// Intended placement constraint (§6/§7 lifecycle/generation binding).
    pub node_id: String,
    pub platform_id: String,
    /// Each entry is a 48-byte SNP launch measurement.
    pub allowed_measurements: Vec<ByteBuf>,
    pub userdata_vault_ref: VaultRef,
    pub luks_vault_ref: VaultRef,
    /// 32-byte SHA-256 (§20) of the sealed user-data + binding fields.
    pub allowed_userdata_digest: ByteBuf,
    /// Tenant VM size (§F / #312). Replaces v1's free-form
    /// `resource_class: String`. The mint side picks one variant;
    /// the KBS verifier + the future miner-agent enforcer
    /// authoritatively derive `vcpus` / `memory_mb` / `disk_gb` from
    /// this single signed identifier.
    pub flavor: Flavor,
    pub lifecycle_perms: Vec<String>,
    /// Who holds this VM's disk key (customer-held keys, see
    /// [`crate::guardian`]). Signed like every other field, so the KBS can
    /// trust it: it decides whether the release carries a KEK at all.
    ///
    /// Absent ⇒ [`KeyMode::Hippius`] (M0). A minter that emits no
    /// `key_mode` produces exactly the bytes it always did, so every M0
    /// ticket is unchanged on the wire; `default` makes such a ticket
    /// decode to `None`. A verifier built before this field existed
    /// refuses any ticket that carries it (`deny_unknown_fields`) — an old
    /// KBS or guest can never be handed an M1/M2 ticket it would misread.
    ///
    /// Present ⇒ it must be `split` or `customer`: M0 has exactly ONE
    /// encoding (the absent key). An explicit `hippius` or a CBOR `null`
    /// would be a second, semantically-equal M0 ticket with different
    /// signed bytes, so both are refused at decode, for every verifier
    /// (KBS, guest, vali's ticket-validator) at once.
    ///
    /// Read it through [`OrderTicket::key_mode`], which applies the
    /// default.
    #[serde(default, deserialize_with = "present_key_mode")]
    pub key_mode: Option<KeyMode>,
}

/// `key_mode` when the key is present: `split` or `customer`, nothing
/// else. `null` fails here (a `KeyMode` is never null) and `hippius` is
/// refused explicitly; an absent key never reaches this function.
fn present_key_mode<'de, D>(d: D) -> Result<Option<KeyMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match KeyMode::deserialize(d)? {
        KeyMode::Hippius => Err(serde::de::Error::custom(
            "key_mode=hippius must be omitted (absent means hippius)",
        )),
        mode => Ok(Some(mode)),
    }
}

impl OrderTicket {
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_ref()
    }
    pub fn allowed_userdata_digest(&self) -> &[u8] {
        self.allowed_userdata_digest.as_ref()
    }
    /// The effective key mode: the signed `key_mode`, absent ⇒
    /// [`KeyMode::Hippius`].
    pub fn key_mode(&self) -> KeyMode {
        self.key_mode.unwrap_or(KeyMode::Hippius)
    }
}
