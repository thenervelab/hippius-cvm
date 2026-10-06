//! Offline allowlist artifact (ARCHITECTURE.md §22).
//!
//! The KBS trust root. Out-of-band, signed by an offline Ed25519 root key
//! whose public part is **compiled into the KBS binary** (rotation =
//! binary redeploy). The artifact maps each approved guest measurement to
//! the L1 ticket-signing `kid`s the KBS will trust and the KBS
//! response-signing `kid`s it may sign with.
//!
//! Strict, fail-closed rules:
//! - wire = COSE_Sign1 (RFC 9052) / EdDSA over deterministic CBOR (§cbor);
//! - root pubkey(s) passed by the binary at construction (no on-the-wire
//!   kid selection); normally a single root, but a SET during a §22 key
//!   rotation — an artifact signed by ANY configured root is accepted
//!   (see [`parse_and_verify_any`]), which lets the re-sign + pubkey-swap
//!   happen without an atomic flag-day;
//! - `deny_unknown_fields`; schema `v == 1`; 48-byte measurements;
//! - **monotonic `epoch`**: an install with `epoch <= high_water_mark`
//!   is **rejected** (anti-rollback);
//! - **atomic staged install**: HWM is durably bumped BEFORE the in-memory
//!   active artifact is swapped — a crash mid-install never leaves the
//!   KBS trusting an older artifact than its HWM advertises;
//! - startup + pre-release revalidation: callers must
//!   [`InstalledAllowlist::revalidate_with`] the persisted bytes (proves
//!   the on-disk artifact still verifies + still epoch-matches the HWM).
//!
//! The HWM lives in tamper-safe Tier-0 storage (§22) — never on the vali
//! cluster's local FS. Modelled here as the [`HighWaterStore`] trait; the
//! production wiring is the §17 step.

use crate::cbor::assert_canonical;
use crate::error::{KbsError, Result};
use crate::snp::{AllowlistClass, MeasurementAllowlist, MEASUREMENT_LEN};
use coset::CborSerializable;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};

/// SHA-256 of `bytes`. Module-local helper for the §22 manifest digest
/// the §280 evidence bundle commits to.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The only allowlist schema version this KBS accepts.
pub const ALLOWLIST_V: u32 = 1;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    pub accepted_l1_kids: Vec<ByteBuf>,
    pub accepted_kbs_response_kids: Vec<ByteBuf>,
    /// §22 trust class of this measurement. Absent in legacy manifests
    /// ⇒ [`AllowlistClass::Tenant`] via `#[serde(default)]`, so every
    /// already-signed manifest decodes unchanged (back-compat). Surfaced
    /// per-measurement by [`MeasurementAllowlist::class_of`].
    #[serde(default)]
    pub class: AllowlistClass,
}

/// One signed body (the inner payload of the COSE_Sign1 envelope).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowlistBody {
    pub v: u32,
    pub epoch: u64,
    /// Sorted (by 48-byte measurement bytes) list of `(measurement, entry)`.
    /// A `Vec<(...)>` rather than a serde map keeps the canonical CBOR
    /// representation unambiguous for byte-string keys.
    pub entries: Vec<(ByteBuf, AllowlistEntry)>,
}

impl AllowlistBody {
    fn into_indexed(self) -> Result<IndexedBody> {
        if self.v != ALLOWLIST_V {
            return Err(KbsError::Policy(format!(
                "allowlist v={} (want {ALLOWLIST_V})",
                self.v
            )));
        }
        let mut map = BTreeMap::<[u8; MEASUREMENT_LEN], AllowlistEntry>::new();
        let mut last: Option<[u8; MEASUREMENT_LEN]> = None;
        for (m, e) in self.entries.into_iter() {
            let bytes: &[u8] = m.as_ref();
            if bytes.len() != MEASUREMENT_LEN {
                return Err(KbsError::Policy(
                    "allowlist measurement must be 48 bytes".into(),
                ));
            }
            let mut arr = [0u8; MEASUREMENT_LEN];
            arr.copy_from_slice(bytes);
            if let Some(prev) = last {
                if arr <= prev {
                    return Err(KbsError::Policy(
                        "allowlist entries must be sorted ascending and unique".into(),
                    ));
                }
            }
            last = Some(arr);
            if e.accepted_l1_kids.is_empty() || e.accepted_kbs_response_kids.is_empty() {
                return Err(KbsError::Policy(
                    "every measurement must list at least one l1 + kbs kid".into(),
                ));
            }
            map.insert(arr, e);
        }
        Ok(IndexedBody {
            epoch: self.epoch,
            entries: map,
        })
    }
}

#[derive(Debug, Clone)]
struct IndexedBody {
    epoch: u64,
    entries: BTreeMap<[u8; MEASUREMENT_LEN], AllowlistEntry>,
}

/// Parse a COSE_Sign1 allowlist artifact, verify the signature against a
/// SET of accepted root verifying keys (the signature is accepted iff ANY
/// of them verifies), and enforce the deterministic encoding + schema
/// rules. Returns the decoded body. No HWM check here — that is done by
/// [`InstalledAllowlist::install`] / `revalidate_with`.
///
/// The multi-root set is the §22 KEY-ROTATION primitive: during a root-key
/// rotation the KBS is configured with BOTH the outgoing (primary) and the
/// incoming (`next`) pubkey, so an artifact signed by either is accepted —
/// the re-signed artifact and the pinned-pubkey swap need not be atomic,
/// eliminating the rotation risk window. Every key in `roots` is a fully
/// trusted §22 authority; an empty set fails closed.
pub fn parse_and_verify_any(cose_bytes: &[u8], roots: &[VerifyingKey]) -> Result<AllowlistBody> {
    if roots.is_empty() {
        return Err(KbsError::Policy(
            "allowlist: no root verifying key configured".into(),
        ));
    }
    parse_and_verify_inner(cose_bytes, roots)
}

/// Single-root convenience wrapper over [`parse_and_verify_any`].
pub fn parse_and_verify(cose_bytes: &[u8], root: &VerifyingKey) -> Result<AllowlistBody> {
    parse_and_verify_inner(cose_bytes, std::slice::from_ref(root))
}

fn parse_and_verify_inner(cose_bytes: &[u8], roots: &[VerifyingKey]) -> Result<AllowlistBody> {
    // §22/§20: the wire bytes themselves must be deterministic — a
    // non-canonical outer wrapper would survive a payload-only check.
    assert_canonical(cose_bytes)?;

    let sign1 = coset::CoseSign1::from_slice(cose_bytes)
        .map_err(|e| KbsError::Policy(format!("allowlist COSE parse: {e:?}")))?;

    match sign1.protected.original_data.as_ref() {
        Some(hdr) if !hdr.is_empty() => assert_canonical(hdr)?,
        _ => {
            return Err(KbsError::Policy(
                "allowlist: missing/empty COSE protected header".into(),
            ));
        }
    }
    match sign1.protected.header.alg.clone() {
        Some(coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)) => {}
        other => {
            return Err(KbsError::Policy(format!(
                "allowlist: alg must be EdDSA, got {other:?}"
            )));
        }
    }

    sign1
        .verify_signature(b"", |sig, tbs| {
            let s = Signature::from_slice(sig)
                .map_err(|e| KbsError::Crypto(format!("allowlist sig decode: {e}")))?;
            // Accept iff ANY configured §22 root key verifies (key rotation:
            // primary OR next). `verify_strict` rejects weak/torsion keys.
            if roots.iter().any(|root| root.verify_strict(tbs, &s).is_ok()) {
                Ok(())
            } else {
                Err(KbsError::Crypto(
                    "allowlist ed25519 verify: no configured §22 root key signed this artifact"
                        .into(),
                ))
            }
        })
        .map_err(|e| KbsError::Policy(format!("allowlist signature invalid: {e}")))?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| KbsError::Policy("allowlist: detached payload not allowed".into()))?;
    assert_canonical(payload)?;
    let body: AllowlistBody = ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| KbsError::Policy(format!("allowlist decode: {e}")))?;
    // Run the indexing/sort/uniqueness checks; the result is discarded —
    // callers that want the indexed form use `install` / `revalidate_with`.
    let _ = body.clone().into_indexed()?;
    Ok(body)
}

/// Persistent, tamper-safe Tier-0 storage of the artifact's monotonic
/// `epoch` (§22). `compare_and_advance` MUST be an **atomic**, durable
/// compare-and-set: either it durably commits a value strictly greater
/// than the current one, or it returns `Err` and the stored value is
/// unchanged. A `get` then separate `set` pair is INSUFFICIENT (TOCTOU);
/// the trait deliberately exposes only the CAS to forbid that mistake.
pub trait HighWaterStore: Send + Sync {
    fn get(&self) -> Result<Option<u64>>;
    /// Atomically advance: succeed iff `new_epoch > current` (or
    /// `current` is `None`), durably committing `new_epoch`. Otherwise
    /// `Err` with the store unchanged.
    fn compare_and_advance(&self, new_epoch: u64) -> Result<()>;
}

/// Reference in-memory HWM. Production deployments MUST back this with a
/// tamper-safe Tier-0 store (Vault path, not the vali FS).
#[derive(Default)]
pub struct InMemoryHwm {
    inner: Mutex<Option<u64>>,
}

impl HighWaterStore for InMemoryHwm {
    fn get(&self) -> Result<Option<u64>> {
        let g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("HWM lock poisoned".into()))?;
        Ok(*g)
    }

    fn compare_and_advance(&self, new_epoch: u64) -> Result<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| KbsError::Policy("HWM lock poisoned".into()))?;
        if let Some(prev) = *g {
            if new_epoch <= prev {
                return Err(KbsError::Policy(format!(
                    "HWM: refuses non-monotonic advance ({new_epoch} <= {prev})"
                )));
            }
        }
        *g = Some(new_epoch);
        Ok(())
    }
}

/// Active body + the verified COSE bytes that produced it. Cached
/// together so `pre_release_validate` can re-verify the in-memory state
/// against the signed wire bytes on every release.
struct Active {
    body: IndexedBody,
    cose: Vec<u8>,
    /// SHA-256 of `cose` — pre-computed at install / revalidate so the
    /// per-release `MeasurementAllowlist::current_manifest_digest` is
    /// O(1) (the cose bytes can be multi-MB once the allowlist scales,
    /// re-hashing on every release would be a measurable cost). The
    /// digest commits the §280 evidence bundle to the exact manifest
    /// the release was admitted under.
    cose_sha256: [u8; 32],
}

/// The active in-memory view of the offline allowlist. Construct ONCE
/// per KBS process with the compiled-in `root` and a tamper-safe HWM.
pub struct InstalledAllowlist {
    /// The set of accepted §22 root verifying keys. >1 only during a
    /// key rotation (primary + next); an artifact signed by any is
    /// accepted. See [`parse_and_verify_any`].
    roots: Vec<VerifyingKey>,
    hwm: Box<dyn HighWaterStore>,
    active: RwLock<Option<Active>>,
}

impl InstalledAllowlist {
    /// Single-root constructor (the steady state — no rotation in flight).
    pub fn new(root: VerifyingKey, hwm: Box<dyn HighWaterStore>) -> Self {
        Self::new_multi(vec![root], hwm)
    }

    /// Multi-root constructor: accept an artifact signed by ANY of `roots`.
    /// Used during a §22 root-key rotation (primary + next). Empty `roots`
    /// makes every install/revalidate fail closed.
    pub fn new_multi(roots: Vec<VerifyingKey>, hwm: Box<dyn HighWaterStore>) -> Self {
        Self {
            roots,
            hwm,
            active: RwLock::new(None),
        }
    }

    /// Install a freshly-signed artifact (operator/staging path).
    /// Order — **race-safe + fail-closed**: take the active write lock
    /// FIRST (so no reader can observe a `(HWM=new, active=old)`
    /// in-between state), then `compare_and_advance` the HWM (durable
    /// CAS — fails if `epoch <= current`), and only then swap the active
    /// body in. On any step failure: HWM is untouched (CAS contract);
    /// the active is left as-is.
    pub fn install(&self, cose_bytes: &[u8]) -> Result<()> {
        let body = parse_and_verify_any(cose_bytes, &self.roots)?;
        let indexed = body.into_indexed()?;
        let mut g = self
            .active
            .write()
            .map_err(|_| KbsError::Policy("active-allowlist lock poisoned".into()))?;
        self.hwm.compare_and_advance(indexed.epoch)?;
        *g = Some(Active {
            body: indexed,
            cose: cose_bytes.to_vec(),
            cose_sha256: sha256(cose_bytes),
        });
        Ok(())
    }

    /// Re-verify `cose_bytes` against the root + HWM and refresh the
    /// active body iff valid. Pre-release path: a tampered or stale
    /// artifact must fail closed — and on failure the active body is
    /// **cleared**, so subsequent reads deny (instead of falling back
    /// to a previously-trusted snapshot). `epoch != HWM` ⇒ tamper.
    pub fn revalidate_with(&self, cose_bytes: &[u8]) -> Result<()> {
        let mut g = self
            .active
            .write()
            .map_err(|_| KbsError::Policy("active-allowlist lock poisoned".into()))?;
        let res = (|| -> Result<IndexedBody> {
            let body = parse_and_verify_any(cose_bytes, &self.roots)?;
            let hwm = self
                .hwm
                .get()?
                .ok_or_else(|| KbsError::Policy("allowlist: no HWM (uninstalled)".into()))?;
            if body.epoch != hwm {
                return Err(KbsError::Policy(format!(
                    "allowlist epoch {} != HWM {} (tamper)",
                    body.epoch, hwm
                )));
            }
            body.into_indexed()
        })();
        match res {
            Ok(indexed) => {
                *g = Some(Active {
                    body: indexed,
                    cose: cose_bytes.to_vec(),
                    cose_sha256: sha256(cose_bytes),
                });
                Ok(())
            }
            Err(e) => {
                // Fail-closed: clear active so post-failure reads deny.
                *g = None;
                Err(e)
            }
        }
    }

    pub fn epoch(&self) -> Result<Option<u64>> {
        let g = self
            .active
            .read()
            .map_err(|_| KbsError::Policy("active-allowlist lock poisoned".into()))?;
        Ok(g.as_ref().map(|a| a.body.epoch))
    }
}

impl MeasurementAllowlist for InstalledAllowlist {
    fn contains(&self, measurement: &[u8; MEASUREMENT_LEN]) -> bool {
        match self.active.read() {
            Ok(g) => g
                .as_ref()
                .map(|a| a.body.entries.contains_key(measurement))
                .unwrap_or(false),
            Err(_) => false, // fail-closed
        }
    }

    fn accepts_l1_kid(&self, measurement: &[u8; MEASUREMENT_LEN], kid: &[u8]) -> bool {
        match self.active.read() {
            Ok(g) => g
                .as_ref()
                .and_then(|a| a.body.entries.get(measurement))
                .map(|e| e.accepted_l1_kids.iter().any(|k| k.as_ref() == kid))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    fn accepts_kbs_kid(&self, measurement: &[u8; MEASUREMENT_LEN], kid: &[u8]) -> bool {
        match self.active.read() {
            Ok(g) => g
                .as_ref()
                .and_then(|a| a.body.entries.get(measurement))
                .map(|e| {
                    e.accepted_kbs_response_kids
                        .iter()
                        .any(|k| k.as_ref() == kid)
                })
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// §22 trust class of `measurement`, or `None` if it is not in the
    /// active allowlist. Legacy entries (no `class` key) resolve to
    /// [`AllowlistClass::Tenant`] at decode time. Read under the active
    /// read lock; fail-closed (`None`) on a poisoned lock. `contains`
    /// stays class-agnostic — this is the precise namespaced check PR-5
    /// will gate host-attestor vs tenant on.
    fn class_of(&self, measurement: &[u8; MEASUREMENT_LEN]) -> Option<AllowlistClass> {
        match self.active.read() {
            Ok(g) => g
                .as_ref()
                .and_then(|a| a.body.entries.get(measurement))
                .map(|e| e.class),
            Err(_) => None, // fail-closed
        }
    }

    /// §22: re-verify the in-memory state against the cached signed
    /// COSE bytes before every release. On any failure, the active body
    /// is cleared (fail-closed): subsequent reads will deny.
    fn pre_release_validate(&self) -> Result<()> {
        // Snapshot the cached bytes under a short read lock, then call
        // `revalidate_with`, which acquires the write lock itself.
        let cose = {
            let g = self
                .active
                .read()
                .map_err(|_| KbsError::Policy("active-allowlist lock poisoned".into()))?;
            match g.as_ref() {
                Some(a) => a.cose.clone(),
                None => {
                    return Err(KbsError::Policy(
                        "allowlist: pre-release validate with no active body".into(),
                    ))
                }
            }
        };
        self.revalidate_with(&cose)
    }

    /// §22 epoch of the currently-installed manifest, or `0` if no
    /// manifest is installed yet. Read under the active read lock —
    /// O(1) field access, no parse. Fail-closed on a poisoned lock.
    fn current_epoch(&self) -> u64 {
        match self.active.read() {
            Ok(g) => g.as_ref().map(|a| a.body.epoch).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// SHA-256 of the currently-installed signed manifest bytes, or
    /// `[0; 32]` if no manifest is installed. Pre-computed at install
    /// / revalidate so this is O(1). The §280 evidence bundle commits
    /// to this digest so a verifier can re-fetch the manifest from the
    /// §22 source + re-hash + compare.
    fn current_manifest_digest(&self) -> [u8; 32] {
        match self.active.read() {
            Ok(g) => g.as_ref().map(|a| a.cose_sha256).unwrap_or([0u8; 32]),
            Err(_) => [0u8; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::to_canonical_vec;
    use crate::snp::AllowlistClass;
    use ciborium::value::Value;
    use coset::CborSerializable;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_artifact(sk: &SigningKey, body_value: &Value) -> Vec<u8> {
        let payload = to_canonical_vec(body_value).unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();
        coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap()
    }

    fn body_value(epoch: u64, measurements: &[[u8; 48]]) -> Value {
        // entries must be canonically sorted by measurement bytes.
        let mut sorted = measurements.to_vec();
        sorted.sort();
        let entries: Vec<Value> = sorted
            .iter()
            .map(|m| {
                Value::Array(vec![
                    Value::Bytes(m.to_vec()),
                    Value::Map(vec![
                        (
                            Value::Text("accepted_kbs_response_kids".into()),
                            Value::Array(vec![Value::Bytes(b"kbs-kid-1".to_vec())]),
                        ),
                        (
                            Value::Text("accepted_l1_kids".into()),
                            Value::Array(vec![Value::Bytes(b"l1-kid-1".to_vec())]),
                        ),
                    ]),
                ])
            })
            .collect();
        Value::Map(vec![
            (Value::Text("entries".into()), Value::Array(entries)),
            (Value::Text("epoch".into()), Value::Integer(epoch.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ])
    }

    /// Like [`body_value`] but each measurement carries an optional
    /// `class` wire string (`None` ⇒ the key is omitted, i.e. a legacy
    /// entry). `to_canonical_vec` reorders the entry map keys, so the
    /// order the `class` pair is pushed in is irrelevant.
    fn body_value_with_classes(epoch: u64, entries: &[([u8; 48], Option<&str>)]) -> Value {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let arr: Vec<Value> = sorted
            .iter()
            .map(|(m, class)| {
                let mut map = vec![
                    (
                        Value::Text("accepted_kbs_response_kids".into()),
                        Value::Array(vec![Value::Bytes(b"kbs-kid-1".to_vec())]),
                    ),
                    (
                        Value::Text("accepted_l1_kids".into()),
                        Value::Array(vec![Value::Bytes(b"l1-kid-1".to_vec())]),
                    ),
                ];
                if let Some(c) = class {
                    map.push((Value::Text("class".into()), Value::Text((*c).into())));
                }
                Value::Array(vec![Value::Bytes(m.to_vec()), Value::Map(map)])
            })
            .collect();
        Value::Map(vec![
            (Value::Text("entries".into()), Value::Array(arr)),
            (Value::Text("epoch".into()), Value::Integer(epoch.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ])
    }

    #[test]
    fn legacy_manifest_defaults_every_entry_to_tenant() {
        // The pre-existing `body_value` helper emits NO `class` key — this
        // is byte-identical to every already-signed manifest in the field.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let cose = sign_artifact(&sk, &body_value(1, &[m]));
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&cose).unwrap();
        // Decodes fine and the missing `class` back-fills to Tenant.
        assert!(al.contains(&m));
        assert_eq!(al.class_of(&m), Some(AllowlistClass::Tenant));
    }

    #[test]
    fn host_attestor_class_is_namespaced_apart_from_tenant() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let host = [7u8; 48];
        let tenant = [9u8; 48];
        let cose = sign_artifact(
            &sk,
            &body_value_with_classes(
                1,
                &[(host, Some("host_attestor")), (tenant, Some("tenant"))],
            ),
        );
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&cose).unwrap();

        // `contains` stays class-agnostic: both measurements are "contained".
        assert!(al.contains(&host));
        assert!(al.contains(&tenant));

        // `class_of` is the precise, namespaced check.
        assert_eq!(al.class_of(&host), Some(AllowlistClass::HostAttestor));
        assert_eq!(al.class_of(&tenant), Some(AllowlistClass::Tenant));

        // A measurement not in the allowlist has no class.
        assert_eq!(al.class_of(&[0u8; 48]), None);
    }

    #[test]
    fn explicit_and_absent_tenant_class_are_equivalent() {
        // An entry that OMITS `class` and one that spells out `"tenant"`
        // must resolve identically (the serde default is the wire value).
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let absent = [1u8; 48];
        let explicit = [2u8; 48];
        let cose = sign_artifact(
            &sk,
            &body_value_with_classes(1, &[(absent, None), (explicit, Some("tenant"))]),
        );
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&cose).unwrap();
        assert_eq!(al.class_of(&absent), Some(AllowlistClass::Tenant));
        assert_eq!(al.class_of(&explicit), Some(AllowlistClass::Tenant));
    }

    #[test]
    fn allowlist_class_wire_strings_are_stable() {
        // Pin the stable wire form — PR-5 verifiers and the offline signer
        // depend on these exact strings.
        assert_eq!(
            serde_json::to_string(&AllowlistClass::Tenant).unwrap(),
            "\"tenant\""
        );
        assert_eq!(
            serde_json::to_string(&AllowlistClass::HostAttestor).unwrap(),
            "\"host_attestor\""
        );
        // Round-trip both variants.
        for c in [AllowlistClass::Tenant, AllowlistClass::HostAttestor] {
            let s = serde_json::to_string(&c).unwrap();
            let back: AllowlistClass = serde_json::from_str(&s).unwrap();
            assert_eq!(back, c);
        }
        // The serde default is Tenant (the back-compat pivot).
        assert_eq!(AllowlistClass::default(), AllowlistClass::Tenant);
    }

    #[test]
    fn install_and_query() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let meas = [7u8; 48];
        let cose = sign_artifact(&sk, &body_value(1, &[meas]));
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&cose).unwrap();
        assert!(al.contains(&meas));
        assert!(al.accepts_kbs_kid(&meas, b"kbs-kid-1"));
        assert!(!al.accepts_kbs_kid(&meas, b"other"));
        assert_eq!(al.epoch().unwrap(), Some(1));
    }

    /// A resize (any accepted relaunch) makes vali install an allowlist
    /// that no longer carries the earlier launch's measurement. The old
    /// ticket names exactly that measurement, so the release gate refuses
    /// it — the old size cannot get its key — while the new launch's
    /// ticket keeps working. Before the eviction lands (a failed relaunch,
    /// the rollback case) the old ticket still releases.
    #[test]
    fn an_evicted_launch_measurement_no_longer_releases() {
        use crate::snp::{check_attestation, LaunchPolicy, VerifiedReport};
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let (old, new) = ([7u8; 48], [8u8; 48]);
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        let rd = [3u8; 64];
        let policy = LaunchPolicy {
            min_tcb: 0,
            required_bits: 0,
            allowed_mask: u64::MAX,
        };
        let release = |measurement: [u8; 48]| {
            let report = VerifiedReport {
                measurement,
                report_data: rd,
                tcb: 1,
                policy: 0,
                chip_id: [0u8; 64],
                chain_pem: Vec::new(),
            };
            // Each launch's ticket allows exactly its own measurement.
            check_attestation(&report, &[measurement.to_vec()], &al, &rd, &policy)
        };

        // The relaunch is pinned (both carried) but not accepted yet.
        al.install(&sign_artifact(&sk, &body_value(1, &[old, new])))
            .unwrap();
        assert!(
            release(old).is_ok(),
            "the old size stays valid until the relaunch is accepted"
        );
        assert!(release(new).is_ok());

        // Accepted ⇒ vali re-installs without the superseded measurement.
        al.install(&sign_artifact(&sk, &body_value(2, &[new])))
            .unwrap();
        let denied = release(old).unwrap_err().to_string();
        assert!(denied.contains("not in offline KBS allowlist"), "{denied}");
        assert!(release(new).is_ok());
        // And the older artifact cannot be replayed to bring it back.
        assert!(al
            .install(&sign_artifact(&sk, &body_value(1, &[old, new])))
            .is_err());
    }

    #[test]
    fn bad_signature_denied() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let wrong = SigningKey::from_bytes(&[2u8; 32]);
        let cose = sign_artifact(&sk, &body_value(1, &[[7u8; 48]]));
        let al = InstalledAllowlist::new(wrong.verifying_key(), Box::new(InMemoryHwm::default()));
        assert!(al.install(&cose).is_err());
    }

    #[test]
    fn multi_root_accepts_either_key_for_rotation() {
        // §22 key rotation: the KBS is configured with the outgoing
        // (primary) + incoming (next) root. An artifact signed by EITHER
        // must install; an artifact signed by a THIRD key must not.
        let primary = SigningKey::from_bytes(&[1u8; 32]);
        let next = SigningKey::from_bytes(&[2u8; 32]);
        let intruder = SigningKey::from_bytes(&[3u8; 32]);
        let meas = [7u8; 48];

        // Artifact signed by the INCOMING key still installs under a
        // multi-root set that lists primary first (the new artifact and
        // the pinned-pubkey swap need not be atomic).
        let cose_next = sign_artifact(&next, &body_value(1, &[meas]));
        let al = InstalledAllowlist::new_multi(
            vec![primary.verifying_key(), next.verifying_key()],
            Box::new(InMemoryHwm::default()),
        );
        al.install(&cose_next).unwrap();
        assert!(al.contains(&meas));

        // An artifact signed by the OUTGOING (primary) key also installs
        // under the same set (epoch must advance past the HWM).
        let cose_primary = sign_artifact(&primary, &body_value(2, &[meas]));
        al.install(&cose_primary).unwrap();
        assert_eq!(al.epoch().unwrap(), Some(2));

        // A key in NEITHER slot is rejected — the set is not "accept any".
        let cose_intruder = sign_artifact(&intruder, &body_value(3, &[meas]));
        assert!(al.install(&cose_intruder).is_err());

        // An empty root set fails closed.
        let al_empty = InstalledAllowlist::new_multi(vec![], Box::new(InMemoryHwm::default()));
        assert!(al_empty.install(&cose_primary).is_err());
    }

    #[test]
    fn unknown_field_denied() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let body = Value::Map(vec![
            (
                Value::Text("entries".into()),
                Value::Array(vec![Value::Array(vec![
                    Value::Bytes(m.to_vec()),
                    Value::Map(vec![
                        (
                            Value::Text("accepted_kbs_response_kids".into()),
                            Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                        ),
                        (
                            Value::Text("accepted_l1_kids".into()),
                            Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                        ),
                    ]),
                ])]),
            ),
            (Value::Text("epoch".into()), Value::Integer(1.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("rogue".into()), Value::Text("x".into())),
        ]);
        let cose = sign_artifact(&sk, &body);
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        assert!(al.install(&cose).is_err());
    }

    #[test]
    fn noncanonical_body_denied() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        // entries in REVERSE order of bytes ⇒ not the canonical map encoding
        let m1 = [1u8; 48];
        let m2 = [9u8; 48];
        let body = Value::Map(vec![
            (
                Value::Text("entries".into()),
                Value::Array(vec![
                    Value::Array(vec![
                        Value::Bytes(m2.to_vec()),
                        Value::Map(vec![
                            (
                                Value::Text("accepted_kbs_response_kids".into()),
                                Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                            ),
                            (
                                Value::Text("accepted_l1_kids".into()),
                                Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                            ),
                        ]),
                    ]),
                    Value::Array(vec![
                        Value::Bytes(m1.to_vec()),
                        Value::Map(vec![
                            (
                                Value::Text("accepted_kbs_response_kids".into()),
                                Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                            ),
                            (
                                Value::Text("accepted_l1_kids".into()),
                                Value::Array(vec![Value::Bytes(b"k".to_vec())]),
                            ),
                        ]),
                    ]),
                ]),
            ),
            (Value::Text("epoch".into()), Value::Integer(1.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ]);
        // Encode without canonicalising; install must reject.
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&body, &mut payload).unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();
        let cose = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap();
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        assert!(al.install(&cose).is_err());
    }

    #[test]
    fn epoch_rollback_denied() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&sign_artifact(&sk, &body_value(2, &[m])))
            .unwrap();
        // same epoch
        assert!(al
            .install(&sign_artifact(&sk, &body_value(2, &[m])))
            .is_err());
        // older epoch
        assert!(al
            .install(&sign_artifact(&sk, &body_value(1, &[m])))
            .is_err());
        // newer epoch OK
        al.install(&sign_artifact(&sk, &body_value(3, &[m])))
            .unwrap();
        assert_eq!(al.epoch().unwrap(), Some(3));
    }

    #[test]
    fn revalidate_detects_tamper() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        let good = sign_artifact(&sk, &body_value(5, &[m]));
        al.install(&good).unwrap();
        // re-verifying the SAME good artifact must succeed.
        al.revalidate_with(&good).unwrap();
        // revalidating an older epoch that doesn't match the HWM ⇒ denied.
        let stale = sign_artifact(&sk, &body_value(4, &[m]));
        assert!(al.revalidate_with(&stale).is_err());
    }

    #[test]
    fn noncanonical_outer_cose_denied() {
        // Build a valid COSE_Sign1 and then append a trailing byte → outer
        // bytes are no longer the canonical encoding of a single CBOR item.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut cose = sign_artifact(&sk, &body_value(1, &[[7u8; 48]]));
        cose.push(0xff);
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        assert!(al.install(&cose).is_err());
    }

    #[test]
    fn revalidate_clears_active_on_failure() {
        // After a failed revalidate, MeasurementAllowlist queries must deny.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&sign_artifact(&sk, &body_value(5, &[m])))
            .unwrap();
        assert!(al.contains(&m));
        let stale = sign_artifact(&sk, &body_value(4, &[m])); // epoch != HWM
        assert!(al.revalidate_with(&stale).is_err());
        // fail-closed: active cleared.
        assert!(!al.contains(&m));
        assert!(!al.accepts_l1_kid(&m, b"l1-kid-1"));
        assert!(!al.accepts_kbs_kid(&m, b"kbs-kid-1"));
    }

    #[test]
    fn accepts_l1_kid_lookup() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        al.install(&sign_artifact(&sk, &body_value(1, &[m])))
            .unwrap();
        assert!(al.accepts_l1_kid(&m, b"l1-kid-1"));
        assert!(!al.accepts_l1_kid(&m, b"l1-kid-2"));
        assert!(!al.accepts_l1_kid(&[0u8; 48], b"l1-kid-1"));
    }

    #[test]
    fn pre_release_validate_happy_and_no_active() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        // No active ⇒ deny.
        assert!(al.pre_release_validate().is_err());
        al.install(&sign_artifact(&sk, &body_value(1, &[[7u8; 48]])))
            .unwrap();
        // With a freshly-installed body, the cached bytes still verify.
        al.pre_release_validate().unwrap();
    }

    #[test]
    fn measurement_allowlist_query_uses_active_body() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let m = [7u8; 48];
        let al = InstalledAllowlist::new(sk.verifying_key(), Box::new(InMemoryHwm::default()));
        // before install everything is denied (fail-closed)
        assert!(!al.contains(&m));
        assert!(!al.accepts_kbs_kid(&m, b"kbs-kid-1"));
        al.install(&sign_artifact(&sk, &body_value(1, &[m])))
            .unwrap();
        assert!(al.contains(&m));
        assert!(al.accepts_kbs_kid(&m, b"kbs-kid-1"));
        assert!(!al.contains(&[0u8; 48]));
    }
}
