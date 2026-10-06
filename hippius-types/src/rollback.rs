//! Wire types for the KBS **authorized rollback** (A2, "restore a VM to an
//! EARLIER boot") — contract C-4 of the backup/restore plan.
//!
//! Two pieces:
//!
//! 1. [`RollbackCheckpoint`] — a statement the KBS signs with its
//!    PERSISTENT Ed25519 response key over the anti-rollback state it
//!    holds for one VM at one instant (`boot_counter`, the CONFIRMED
//!    `volume_stamp`, `unconfirmed_releases`, the releasable
//!    `generation`). vali stores it next to every completed backup run.
//!    It is the ONLY source of the stamp a rollback lowers to: the KBS
//!    re-verifies its OWN signature when an arm is requested, so neither
//!    vali nor a miner chooses the target values.
//! 2. The JSON request/response bodies of the four mTLS-admin routes
//!    (`rollback-checkpoint`, `authorize-rollback` POST/DELETE,
//!    `rollback` GET).
//!
//! ## Domain separation
//!
//! The same key signs the release response (`HIPPIUS_KBS_RELEASE_V1`),
//! the denial (`HIPPIUS_KBS_DENIAL_V1`), the §280 evidence bundle
//! (`HIPPIUS_EVIDENCE_BUNDLE_V1`) and other statements. A checkpoint
//! carries its own [`ROLLBACK_CHECKPOINT_DOMAIN`] inside the signed map,
//! and [`RollbackCheckpoint::decode`] is strict (canonical bytes, exact
//! field set, exact domain), so bytes signed as any other statement can
//! never decode as a checkpoint, and a checkpoint's bytes can never
//! decode as any of those (each of them requires fields a checkpoint
//! does not carry). Pinned by tests on both sides.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::cbor::{assert_canonical, to_canonical_vec};
use crate::{HippiusTypesError, Result};
use ciborium::value::Value;
use serde::{Deserialize, Serialize};

/// Domain tag of a signed rollback checkpoint. Distinct from every other
/// domain the KBS response key signs under.
pub const ROLLBACK_CHECKPOINT_DOMAIN: &str = "HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V1";

/// Domain tag of a **V2** checkpoint: the V1 field set plus the VM's
/// volume-stamp TIMELINE (`volume_stamp_timeline_id`, stamp protocol v2).
/// Every checkpoint the KBS signs now is V2. A V1 checkpoint still
/// VERIFIES (backups taken before V2 carry one), but it names no
/// timeline, so `authorize-rollback` never arms it
/// (`checkpoint-not-timeline-bound`): a rollback must say which timeline
/// the restored disk is on, or the abandoned timeline's disks would be
/// indistinguishable from it.
pub const ROLLBACK_CHECKPOINT_DOMAIN_V2: &str = "HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V2";

/// Upper bound on a checkpoint body. A real one is ~200 bytes; the cap
/// bounds what a hostile `authorize-rollback` body can make the decoder
/// chew on.
pub const MAX_CHECKPOINT_LEN: usize = 1024;

/// Longest `vm_id` a checkpoint may carry (vali's ids are UUID-shaped).
pub const MAX_CHECKPOINT_VM_ID_LEN: usize = 128;

/// Upper bound on the decoded `point_manifest_b64` of an
/// `authorize-rollback` request. A real manifest is a few KiB (one line
/// per uploaded part); the cap bounds what a body can make the KBS hash
/// and parse.
pub const MAX_POINT_MANIFEST_LEN: usize = 256 * 1024;

/// The KBS-signed anti-rollback checkpoint of one VM.
///
/// Every field is signed. `boot_counter` is the KBS's COMMITTED counter
/// (`stored`), `volume_stamp` its CONFIRMED stamp — the two values an
/// authorized rollback later re-establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackCheckpoint {
    pub vm_id: String,
    /// The committed boot counter (`stored`) at `issued_at_unix`.
    pub boot_counter: u64,
    /// The CONFIRMED volume stamp (`E`) at `issued_at_unix`.
    pub volume_stamp: u64,
    /// Releases granted since the last confirm, at `issued_at_unix`.
    /// Informational; a rollback resets it to 0.
    pub unconfirmed_releases: u64,
    /// The generation the KBS lifecycle row admitted at
    /// `issued_at_unix` (`Active.gen`, or `Migrating.new_gen`).
    pub generation: u64,
    pub issued_at_unix: u64,
    /// The VM's volume-stamp TIMELINE at `issued_at_unix` (all-zero for a
    /// VM never rolled back). `Some` ⇔ a V2 checkpoint
    /// ([`ROLLBACK_CHECKPOINT_DOMAIN_V2`]); `None` ⇔ V1, encoded
    /// byte-identically to every checkpoint signed before V2.
    pub volume_stamp_timeline_id: Option<[u8; 32]>,
}

impl RollbackCheckpoint {
    /// Semantic invariants, run on encode AND decode so a hand-crafted
    /// canonical body cannot carry a value `canonical()` never emits.
    pub fn validate(&self) -> Result<()> {
        if self.vm_id.is_empty() || self.vm_id.len() > MAX_CHECKPOINT_VM_ID_LEN {
            return Err(schema(format!(
                "vm_id must be 1..={MAX_CHECKPOINT_VM_ID_LEN} bytes"
            )));
        }
        // A checkpoint is only minted for a VM that has booted at least
        // once (stored == 0 is refused at the route). A zero here can
        // only be a forged or corrupt body.
        if self.boot_counter == 0 {
            return Err(schema("boot_counter must be non-zero".into()));
        }
        if self.generation == 0 {
            return Err(schema("generation must be non-zero".into()));
        }
        if self.issued_at_unix == 0 {
            return Err(schema("issued_at_unix must be non-zero".into()));
        }
        Ok(())
    }

    /// The domain this checkpoint is signed under.
    pub fn domain(&self) -> &'static str {
        match self.volume_stamp_timeline_id {
            Some(_) => ROLLBACK_CHECKPOINT_DOMAIN_V2,
            None => ROLLBACK_CHECKPOINT_DOMAIN,
        }
    }

    /// Canonical CBOR (RFC 8949 §4.2.1) of the to-be-signed body.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut entries = vec![
            (
                Value::Text("boot_counter".into()),
                Value::Integer(self.boot_counter.into()),
            ),
            (
                Value::Text("domain".into()),
                Value::Text(self.domain().into()),
            ),
            (
                Value::Text("generation".into()),
                Value::Integer(self.generation.into()),
            ),
            (
                Value::Text("issued_at_unix".into()),
                Value::Integer(self.issued_at_unix.into()),
            ),
            (
                Value::Text("unconfirmed_releases".into()),
                Value::Integer(self.unconfirmed_releases.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text(self.vm_id.clone())),
            (
                Value::Text("volume_stamp".into()),
                Value::Integer(self.volume_stamp.into()),
            ),
        ];
        if let Some(t) = self.volume_stamp_timeline_id {
            entries.push((
                Value::Text("volume_stamp_timeline_id".into()),
                Value::Bytes(t.to_vec()),
            ));
        }
        // `to_canonical_vec` sorts the keys.
        let v = Value::Map(entries);
        let bytes = to_canonical_vec(&v).map_err(|e| schema(format!("encode: {e}")))?;
        if bytes.len() > MAX_CHECKPOINT_LEN {
            return Err(schema(format!("body exceeds {MAX_CHECKPOINT_LEN} bytes")));
        }
        Ok(bytes)
    }

    /// Strict decode of hostile-origin bytes: size cap, canonical
    /// encoding, text keys only, no duplicate / missing / unknown field,
    /// exact domain, then [`Self::validate`].
    pub fn decode(body: &[u8]) -> Result<RollbackCheckpoint> {
        if body.len() > MAX_CHECKPOINT_LEN {
            return Err(schema(format!("body exceeds {MAX_CHECKPOINT_LEN} bytes")));
        }
        assert_canonical(body).map_err(|e| schema(format!("body: {e}")))?;
        let value: Value =
            ciborium::de::from_reader(body).map_err(|e| schema(format!("decode: {e}")))?;
        let mut map = into_string_map(value)?;
        let domain = take_text(&mut map, "domain")?;
        let volume_stamp_timeline_id = if domain == ROLLBACK_CHECKPOINT_DOMAIN {
            None
        } else if domain == ROLLBACK_CHECKPOINT_DOMAIN_V2 {
            Some(take_bytes32(&mut map, "volume_stamp_timeline_id")?)
        } else {
            return Err(schema(format!(
                "domain must be {ROLLBACK_CHECKPOINT_DOMAIN:?} or \
                 {ROLLBACK_CHECKPOINT_DOMAIN_V2:?}, got {domain:?}"
            )));
        };
        let cp = RollbackCheckpoint {
            vm_id: take_text(&mut map, "vm_id")?,
            boot_counter: take_u64(&mut map, "boot_counter")?,
            volume_stamp: take_u64(&mut map, "volume_stamp")?,
            unconfirmed_releases: take_u64(&mut map, "unconfirmed_releases")?,
            generation: take_u64(&mut map, "generation")?,
            issued_at_unix: take_u64(&mut map, "issued_at_unix")?,
            volume_stamp_timeline_id,
        };
        if let Some(key) = map.keys().next() {
            return Err(schema(format!("unknown field {key:?}")));
        }
        cp.validate()?;
        Ok(cp)
    }

    /// The JSON projection returned next to the signed bytes.
    pub fn to_wire(&self) -> RollbackCheckpointWire {
        RollbackCheckpointWire {
            domain: self.domain().to_string(),
            vm_id: self.vm_id.clone(),
            boot_counter: self.boot_counter,
            volume_stamp: self.volume_stamp,
            volume_stamp_timeline_id_hex: self.volume_stamp_timeline_id.map(hex_lower),
            unconfirmed_releases: self.unconfirmed_releases,
            generation: self.generation,
            issued_at_unix: self.issued_at_unix,
        }
    }
}

/// JSON view of a [`RollbackCheckpoint`] (C-4 `checkpoint`). Convenience
/// only: the signature covers `checkpoint_cbor_hex`, never this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackCheckpointWire {
    pub domain: String,
    pub vm_id: String,
    pub boot_counter: u64,
    pub volume_stamp: u64,
    /// V2 only: lowercase hex of the 32-byte volume-stamp timeline. Absent
    /// on a V1 checkpoint (whose JSON is then byte-identical to V1's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_stamp_timeline_id_hex: Option<String>,
    pub unconfirmed_releases: u64,
    pub generation: u64,
    pub issued_at_unix: u64,
}

/// `POST /v1/admin/vm/{vm_id}/rollback-checkpoint` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRollbackCheckpointResponse {
    pub checkpoint: RollbackCheckpointWire,
    /// Lowercase hex of the canonical CBOR the signature covers.
    pub checkpoint_cbor_hex: String,
    /// Lowercase hex of the 64-byte Ed25519 signature.
    pub signature_hex: String,
    /// Lowercase hex of the 32-byte KBS response verifying key.
    pub signer_pubkey_hex: String,
}

/// `POST /v1/admin/vm/{vm_id}/authorize-rollback` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthorizeRollbackRequest {
    pub checkpoint_cbor_hex: String,
    pub signature_hex: String,
    /// sha256 of the restore point's `manifest.json` (64 hex chars).
    /// The KBS checks it against [`Self::point_manifest_b64`].
    pub point_manifest_sha256_hex: String,
    /// The EXACT bytes of the restore point's `manifest.json`, standard
    /// base64 (RFC 4648 §4, padded), at most [`MAX_POINT_MANIFEST_LEN`]
    /// bytes decoded. The KBS refuses the arm (400 `manifest-mismatch`)
    /// unless `sha256(bytes) == point_manifest_sha256_hex`, the manifest
    /// is a JSON object whose top-level `vm_id` is the URL's VM, and its
    /// `kbs_rollback_checkpoint.checkpoint_cbor_hex` is byte-for-byte
    /// this request's `checkpoint_cbor_hex` — so an arm names a manifest
    /// that really carries the checkpoint it lowers the stamp to.
    pub point_manifest_b64: String,
    /// The generation vali's `activate` already moved the row to.
    pub new_gen: u64,
    /// The destination chip (`platform_id`, hex) of that activate.
    pub dest_platform_id_hex: String,
    pub restore_id: String,
    pub ttl_s: u64,
    /// Who asked (vali renders `on_behalf_of` into this, e.g.
    /// `tenant:<id>` / `superuser:<id>`). Recorded, never interpreted.
    pub requested_by: String,
}

/// One armed rollback, as reported by the KBS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRollbackArm {
    pub vm_id: String,
    pub restore_id: String,
    pub point_manifest_sha256_hex: String,
    pub new_gen: u64,
    pub dest_platform_id_hex: String,
    /// `C_T` — the checkpoint's counter. The one release the arm admits
    /// submits exactly `from_counter + 1`.
    pub from_counter: u64,
    /// `E_T` — the checkpoint's confirmed stamp the release restores.
    pub to_stamp: u64,
    pub armed_at_unix: u64,
    pub expires_at_unix: u64,
    pub requested_by: String,
}

/// `POST …/authorize-rollback` → 201 (fresh) or 200 (same `restore_id`
/// already armed with the same binding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthorizeRollbackResponse {
    pub arm: AdminRollbackArm,
}

/// The last CONSUMED rollback of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminLastRollback {
    pub restore_id: String,
    pub manifest_sha256_hex: String,
    /// `C_T`, the counter of the point rolled back to.
    pub from_counter: u64,
    /// The counter the consuming release committed (`stored + 1`; the
    /// counter never moves down).
    pub to_counter: u64,
    /// `E_T`, the confirmed stamp the release restored.
    pub stamp: u64,
    pub consumed_at_unix: u64,
    pub requested_by: String,
    /// The consuming release passed every gate and FINALIZED the
    /// rollback: the signed response carrying the key was handed to the
    /// transport. `false` while it is in flight, and for good once it was
    /// reverted. It cannot prove the guest RECEIVED it: a crash or a
    /// dropped connection after the finalize looks the same as a guest
    /// that dropped its confirm — a state the miner can always produce
    /// anyway, so it grants nothing (the accepted residual in
    /// `kbs_core::rollback`).
    pub delivered: bool,
    /// The rollback was consumed but never delivered (a fence/`activate`
    /// landed during the release, a failed write, a crash), and its stamp
    /// was put back. `delivered == false && reverted == false` ⇒ still in
    /// flight.
    pub reverted: bool,
}

/// How a VM's last arm left the store WITHOUT being consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRollbackClear {
    pub restore_id: String,
    /// Stable: `rollback-cleared-by-boot` (a normal boot of the VM),
    /// `rollback-expired`, `rollback-disarmed`, or
    /// `rollback-lifecycle-{activate,decommission,tombstone}`.
    pub reason: String,
    /// Unix seconds of the clear.
    pub at: u64,
}

/// `GET /v1/admin/vm/{vm_id}/rollback` → 200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRollbackStatusResponse {
    pub arm: Option<AdminRollbackArm>,
    pub last_rollback: Option<AdminLastRollback>,
    /// The last arm cleared without a consume, and why.
    pub last_clear: Option<AdminRollbackClear>,
    /// Whether `authorize-rollback` can arm this VM at all: its guest
    /// speaks a timeline-bound volume stamp (recorded from its last
    /// attested release). `false` ⇒ every arm is refused 409
    /// `guest-not-rollback-capable`; vali must not offer a rollback.
    pub rollback_capable: bool,
}

/// JSON error body of the rollback routes. `retry_after_s` is present
/// only on 429 `rollback-rate-limited`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRollbackErrorResponse {
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

// ── decode helpers (module-local, mirroring `evidence_bundle.rs`) ──────

fn schema(msg: String) -> HippiusTypesError {
    HippiusTypesError::RollbackCheckpointSchema(msg)
}

fn into_string_map(value: Value) -> Result<BTreeMap<String, Value>> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(schema("expected a CBOR map".into())),
    };
    let mut out = BTreeMap::new();
    for (k, v) in entries {
        match k {
            Value::Text(name) => {
                if out.insert(name.clone(), v).is_some() {
                    return Err(schema(format!("duplicate map key {name:?}")));
                }
            }
            _ => return Err(schema("map key is not a text string".into())),
        }
    }
    Ok(out)
}

fn take(map: &mut BTreeMap<String, Value>, key: &str) -> Result<Value> {
    map.remove(key)
        .ok_or_else(|| schema(format!("missing field {key:?}")))
}

fn take_text(map: &mut BTreeMap<String, Value>, key: &str) -> Result<String> {
    match take(map, key)? {
        Value::Text(s) => Ok(s),
        _ => Err(schema(format!("field {key:?} is not a text string"))),
    }
}

fn take_bytes32(map: &mut BTreeMap<String, Value>, key: &str) -> Result<[u8; 32]> {
    match take(map, key)? {
        Value::Bytes(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| schema(format!("field {key:?} must be 32 bytes"))),
        _ => Err(schema(format!("field {key:?} is not a byte string"))),
    }
}

fn hex_lower(b: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in b {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0xf)] as char);
    }
    out
}

fn take_u64(map: &mut BTreeMap<String, Value>, key: &str) -> Result<u64> {
    match take(map, key)? {
        Value::Integer(i) => {
            let n: i128 = i.into();
            u64::try_from(n).map_err(|_| schema(format!("field {key:?} out of u64 range")))
        }
        _ => Err(schema(format!("field {key:?} is not an integer"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RollbackCheckpoint {
        RollbackCheckpoint {
            vm_id: "vm-1".into(),
            boot_counter: 4,
            volume_stamp: 3,
            unconfirmed_releases: 1,
            generation: 2,
            issued_at_unix: 1_790_000_000,
            volume_stamp_timeline_id: None,
        }
    }

    fn sample_v2() -> RollbackCheckpoint {
        RollbackCheckpoint {
            volume_stamp_timeline_id: Some([0xa5; 32]),
            ..sample()
        }
    }

    #[test]
    fn a_v2_checkpoint_round_trips_and_carries_its_timeline() {
        let cp = sample_v2();
        let bytes = cp.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        let back = RollbackCheckpoint::decode(&bytes).unwrap();
        assert_eq!(back, cp);
        assert_eq!(back.domain(), ROLLBACK_CHECKPOINT_DOMAIN_V2);
        let w = back.to_wire();
        assert_eq!(w.domain, ROLLBACK_CHECKPOINT_DOMAIN_V2);
        assert_eq!(w.volume_stamp_timeline_id_hex, Some("a5".repeat(32)));
    }

    /// A V1 checkpoint is encoded exactly as before V2 existed (no
    /// timeline key, V1 domain), and still decodes — as V1.
    #[test]
    fn a_v1_checkpoint_is_unchanged_and_decodes_as_v1() {
        let cp = sample();
        let bytes = cp.canonical().unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(entries) = v else { panic!() };
        assert_eq!(entries.len(), 7);
        assert!(entries
            .iter()
            .all(|(k, _)| k.as_text() != Some("volume_stamp_timeline_id")));
        let back = RollbackCheckpoint::decode(&bytes).unwrap();
        assert_eq!(back.volume_stamp_timeline_id, None);
        assert_eq!(back.to_wire().volume_stamp_timeline_id_hex, None);
    }

    /// The field set is tied to the domain: a V1 domain with a timeline,
    /// or a V2 domain without one (or with one of the wrong length),
    /// never decodes — so a V1 checkpoint cannot be dressed up as V2.
    #[test]
    fn the_timeline_field_is_tied_to_the_v2_domain() {
        let base = |domain: &str, timeline: Option<Value>| {
            let mut e = vec![
                (Value::Text("boot_counter".into()), Value::Integer(4.into())),
                (Value::Text("domain".into()), Value::Text(domain.into())),
                (Value::Text("generation".into()), Value::Integer(2.into())),
                (
                    Value::Text("issued_at_unix".into()),
                    Value::Integer(9.into()),
                ),
                (
                    Value::Text("unconfirmed_releases".into()),
                    Value::Integer(0.into()),
                ),
                (Value::Text("vm_id".into()), Value::Text("vm-1".into())),
                (Value::Text("volume_stamp".into()), Value::Integer(3.into())),
            ];
            if let Some(t) = timeline {
                e.push((Value::Text("volume_stamp_timeline_id".into()), t));
            }
            to_canonical_vec(&Value::Map(e)).unwrap()
        };
        let t32 = Some(Value::Bytes(vec![1; 32]));
        assert!(
            RollbackCheckpoint::decode(&base(ROLLBACK_CHECKPOINT_DOMAIN, t32.clone())).is_err()
        );
        assert!(RollbackCheckpoint::decode(&base(ROLLBACK_CHECKPOINT_DOMAIN_V2, None)).is_err());
        assert!(RollbackCheckpoint::decode(&base(
            ROLLBACK_CHECKPOINT_DOMAIN_V2,
            Some(Value::Bytes(vec![1; 31]))
        ))
        .is_err());
        assert!(RollbackCheckpoint::decode(&base(ROLLBACK_CHECKPOINT_DOMAIN_V2, t32)).is_ok());
        assert!(RollbackCheckpoint::decode(&base(ROLLBACK_CHECKPOINT_DOMAIN, None)).is_ok());
    }

    #[test]
    fn canonical_round_trips_and_is_canonical() {
        let cp = sample();
        let bytes = cp.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        assert_eq!(RollbackCheckpoint::decode(&bytes).unwrap(), cp);
    }

    #[test]
    fn decode_refuses_a_wrong_domain() {
        let v = Value::Map(vec![
            (Value::Text("boot_counter".into()), Value::Integer(4.into())),
            (
                Value::Text("domain".into()),
                Value::Text("HIPPIUS_KBS_RELEASE_V1".into()),
            ),
            (Value::Text("generation".into()), Value::Integer(2.into())),
            (
                Value::Text("issued_at_unix".into()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("unconfirmed_releases".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("vm-1".into())),
            (Value::Text("volume_stamp".into()), Value::Integer(3.into())),
        ]);
        let bytes = to_canonical_vec(&v).unwrap();
        assert!(RollbackCheckpoint::decode(&bytes).is_err());
    }

    #[test]
    fn decode_refuses_an_unknown_field_and_a_missing_field() {
        let mut entries = vec![
            (Value::Text("boot_counter".into()), Value::Integer(4.into())),
            (
                Value::Text("domain".into()),
                Value::Text(ROLLBACK_CHECKPOINT_DOMAIN.into()),
            ),
            (Value::Text("generation".into()), Value::Integer(2.into())),
            (
                Value::Text("issued_at_unix".into()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("unconfirmed_releases".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("vm-1".into())),
            (Value::Text("volume_stamp".into()), Value::Integer(3.into())),
        ];
        let good = to_canonical_vec(&Value::Map(entries.clone())).unwrap();
        RollbackCheckpoint::decode(&good).unwrap();
        entries.push((Value::Text("zzz".into()), Value::Integer(1.into())));
        let extra = to_canonical_vec(&Value::Map(entries.clone())).unwrap();
        assert!(RollbackCheckpoint::decode(&extra).is_err());
        entries.pop();
        entries.remove(0);
        let missing = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(RollbackCheckpoint::decode(&missing).is_err());
    }

    #[test]
    fn decode_refuses_non_canonical_bytes() {
        // Same map, keys in NON-sorted order, encoded without canonicalising.
        let v = Value::Map(vec![
            (Value::Text("vm_id".into()), Value::Text("vm-1".into())),
            (Value::Text("boot_counter".into()), Value::Integer(4.into())),
            (
                Value::Text("domain".into()),
                Value::Text(ROLLBACK_CHECKPOINT_DOMAIN.into()),
            ),
            (Value::Text("generation".into()), Value::Integer(2.into())),
            (
                Value::Text("issued_at_unix".into()),
                Value::Integer(9.into()),
            ),
            (
                Value::Text("unconfirmed_releases".into()),
                Value::Integer(0.into()),
            ),
            (Value::Text("volume_stamp".into()), Value::Integer(3.into())),
        ]);
        let mut raw = Vec::new();
        ciborium::ser::into_writer(&v, &mut raw).unwrap();
        assert!(RollbackCheckpoint::decode(&raw).is_err());
    }

    #[test]
    fn a_zero_counter_or_generation_never_decodes() {
        let mut cp = sample();
        cp.boot_counter = 0;
        assert!(cp.canonical().is_err());
        let mut cp = sample();
        cp.generation = 0;
        assert!(cp.canonical().is_err());
    }

    #[test]
    fn the_domain_is_distinct_from_every_other_signed_domain() {
        for other in [
            crate::release::RELEASE_DOMAIN,
            crate::release::RELEASE_DOMAIN_V2,
            crate::release::DENIAL_DOMAIN,
            crate::evidence_bundle::EVIDENCE_BUNDLE_DOMAIN,
            crate::audit_vm_cert::AUDIT_VM_CERT_DOMAIN,
            crate::provenance::PROVENANCE_DOMAIN,
            crate::host_attestor::HOST_ATTESTOR_CERT_DOMAIN,
            crate::live_attestation::LIVE_ATTESTATION_DOMAIN,
            crate::telemetry_cert::TELEMETRY_CERT_DOMAIN,
        ] {
            assert_ne!(ROLLBACK_CHECKPOINT_DOMAIN, other);
            assert_ne!(ROLLBACK_CHECKPOINT_DOMAIN_V2, other);
        }
    }
}
