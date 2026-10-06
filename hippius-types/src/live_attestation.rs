//! KBS-issued post-boot **live attestation** of a tenant CVM
//! (issue #322 — Phase B of the on-chain attestation work).
//!
//! Once a tenant SEV-SNP CVM is up the guest agent inside it (the
//! "blackbox": the in-VM trust anchor, running under measured launch)
//! periodically asks the kernel for a fresh `SNP_GET_REPORT` and
//! POSTs it to the KBS keepalive endpoint. The KBS re-verifies the
//! report against AMD's silicon root + the §22 allowlist (same trust
//! chain as `process_release`), then signs a [`LiveAttestation`] body
//! committing to "this `vm_id` running on this `node_id` is alive at
//! this unix time" — a statement the on-chain pallet can verify
//! cheaply with the pre-allowlisted KBS L0 verifying key.
//!
//! A validator batches recent signed live-attestations and submits
//! them in a single extrinsic. The pallet:
//! - rejects an attestation outside the current epoch / replay window;
//! - increments `LiveAttestationCount((vm_id, epoch))`;
//! - persists `prev_attestation_hash` for the next monotonic check.
//!
//! At epoch close the pallet scales each miner's weight by the
//! observed uptime ratio. A miner that lets a tenant VM stop emitting
//! live attestations earns proportionally less for that epoch — and
//! cannot lie about it: the only entity allowed to mint a live
//! attestation is a KBS that has just verified a fresh SNP report
//! cryptographically bound to the running CVM.
//!
//! This module owns only the **wire format** — canonical encoder,
//! fail-closed decoder, and the [`SignedLiveAttestation`] envelope.
//! The Ed25519 sign / verify live with their callers so this crate
//! stays crypto-free and `no_std`:
//! - `kbs-core` signs at `/v1/attest/keepalive` grant time with the
//!   L0 KBS key (same key that signs release envelopes + evidence
//!   bundles — distinct `domain` byte prefix means signatures cannot
//!   cross-replay);
//! - the on-chain pallet verifies against the root-allowlisted KBS
//!   `signer_pubkey`.
//!
//! ## Domain separation
//!
//! [`LIVE_ATTESTATION_DOMAIN`] is **distinct** from every other
//! signed payload — including `RELEASE_DOMAIN`,
//! `AUDIT_VM_CERT_DOMAIN`, `EVIDENCE_BUNDLE_DOMAIN`, and the §23
//! aggregate domain. The KBS L0 key signs several of these, but the
//! domain-tag-first body layout means a signature minted over one
//! cannot verify as another (different first-field bytes ⇒ different
//! signed bytes).
//!
//! ## Schema (`v1`) — fixed, fail-closed
//!
//! Every field is mandatory. Decode rejects a non-canonical body, a
//! non-text / duplicated map key, an unknown field, a wrong `domain`,
//! an unknown `schema_version`, a wrong-length byte field, and any
//! semantically invalid value (empty `vm_id`, inverted observation
//! window, zero `attestation_seq`).

#[allow(unused_imports)]
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

/// Replay-domain separator — the first field of every signed live-
/// attestation body. Distinct from every other domain in the stack so
/// a signature lifted from a release / cert / evidence bundle cannot
/// replay as a live-attestation.
pub const LIVE_ATTESTATION_DOMAIN: &str = "HIPPIUS_LIVE_ATTESTATION_V1";

/// The original `schema_version` — no guest binding. Its wire bytes are
/// frozen by the `live_attestation_kat` vector.
pub const LIVE_ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// `schema_version` of a body that also carries the attested GUEST
/// identity ([`GuestBinding`]): the SEV-SNP `CHIP_ID` and firmware
/// `REPORT_ID` of the report the KBS verified, plus where the KBS's
/// expectation for that pair came from.
///
/// Why it exists: a v1 body binds its `vm_id` only through
/// `REPORT_DATA`, which the guest chooses — so root inside ONE running
/// allowlisted guest could mint valid samples for ANY `vm_id`. The KBS
/// now records the `(chip_id, report_id)` of the guest it RELEASED to for
/// each `vm_id` and refuses a keepalive from any other guest; the body
/// states the pair so a consumer can count distinct live guests per chip.
///
/// Additive: a decoder accepts both versions; a v1 body is byte-identical
/// to before.
pub const LIVE_ATTESTATION_SCHEMA_VERSION_BOUND: u32 = 2;

/// `schema_version` of a body that also carries the resources the guest
/// ATTESTED it runs with ([`GuestResources`]). The guest binding stays as
/// in v2 — present iff the KBS runs a binding mode — so a v3 body is a v1
/// or v2 body plus four keys.
///
/// Why it exists: SEV-SNP measures the vCPU count (one VMSA per vCPU) but
/// NOT the memory size, which the VMM announces through the firmware
/// memory map. A miner could launch a VM with less RAM than its flavor
/// and nothing in the launch would see it. The guest therefore reads what
/// it was actually given and folds it into `REPORT_DATA`
/// ([`crate::report_data::live_attestation_with_resources`]); the KBS
/// signs it only after the PSP-signed report matched, so the host that
/// relays the bytes cannot change a single number.
///
/// Additive: a decoder accepts all three versions; v1/v2 bodies are
/// byte-identical to before.
pub const LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES: u32 = 3;

/// `schema_version` of a body that also carries the guest components
/// release the guest ATTESTED it booted, and the health of its agents
/// ([`GuestComponents`], docs/design/guest-component-rollout.md, "Component
/// health in `REPORT_DATA`"). The guest binding and the resources are
/// each optional, exactly as the KBS mode and the guest's own flags make
/// them; the components are required.
///
/// Additive: a decoder accepts all four versions; v1–v3 bodies are
/// byte-identical to before.
pub const LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS: u32 = 4;

/// [`GuestComponents::health`] bits — one per check the keepalive runs.
/// Append-only: a bit keeps its meaning forever; a release declares the
/// checks it ships (`health_mask`) and vali judges against that mask.
pub mod components_health {
    /// `/run/hippius/guest-components` says the release image is mounted.
    pub const MOUNTED: u32 = 1 << 0;
    /// The keepalive itself runs from the release image.
    pub const KEEPALIVE_FROM_RELEASE: u32 = 1 << 1;
    /// `hippius-tenant-telemetry.service` is active.
    pub const TELEMETRY_ACTIVE: u32 = 1 << 2;
    /// `hippius-eol-sign.service` is active (its `ExecStop` signs the
    /// stopped-ack) and the binary it runs is present.
    pub const EOL_SIGN_ARMED: u32 = 1 << 3;
    /// Every check this build of the types knows.
    pub const ALL: u32 = MOUNTED | KEEPALIVE_FROM_RELEASE | TELEMETRY_ACTIVE | EOL_SIGN_ARMED;
}

/// SEV-SNP `CHIP_ID` length.
pub const CHIP_ID_LEN: usize = 64;

/// SEV-SNP `REPORT_ID` length — assigned by the PSP firmware per guest
/// launch; the guest cannot choose it.
pub const REPORT_ID_LEN: usize = 32;

/// Where the KBS's expected `(chip_id, report_id)` for a `vm_id` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingSource {
    /// Recorded at the §20 release to that guest — the strong binding:
    /// only the guest the KBS released the disk key to can match it.
    Release,
    /// No release was on record (e.g. the KBS restarted after the VM
    /// booted): the pair is the guest that ASKED, served unpinned. It is
    /// not proven to be the VM's guest — consumers that need proof (the
    /// capacity tick) ignore these.
    FirstUse,
}

impl BindingSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingSource::Release => "release",
            BindingSource::FirstUse => "first-use",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "release" => Some(BindingSource::Release),
            "first-use" => Some(BindingSource::FirstUse),
            _ => None,
        }
    }
}

/// The attested guest a v2 body is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestBinding {
    pub chip_id: [u8; CHIP_ID_LEN],
    pub report_id: [u8; REPORT_ID_LEN],
    pub source: BindingSource,
}

/// What the guest observed it runs with, attested through `REPORT_DATA`.
///
/// Every value is read inside the guest at report time:
/// - `vcpus_online`: CPUs online (`/sys/devices/system/cpu/online`).
///   The vCPU COUNT is already enforced by the launch measurement; this
///   catches a host that never runs some of the measured vCPUs.
/// - `mem_firmware_kib`: the sum of the `System RAM` ranges of the
///   firmware memory map (`/sys/firmware/memmap`) — the RAM the VMM
///   announced, before the kernel reserves anything. `0` when the guest
///   kernel exposes no firmware map.
/// - `mem_total_kib`: `MemTotal` from `/proc/meminfo` — what the tenant
///   sees, after the kernel's own reservations (memmap, SEV swiotlb).
/// - `mem_unaccepted_kib`: `Unaccepted` from `/proc/meminfo` — RAM the
///   VMM announced that the guest has not accepted (PVALIDATEd) yet, so
///   the host has not had to back it. `0` on a kernel without
///   unaccepted-memory support (the firmware accepted everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestResources {
    pub vcpus_online: u32,
    pub mem_firmware_kib: u64,
    pub mem_total_kib: u64,
    pub mem_unaccepted_kib: u64,
}

/// The guest components release the guest attested it booted, and the
/// health of its agents — read inside the guest at report time and folded
/// into `REPORT_DATA` ([`crate::report_data::live_attestation_with_components`]).
/// `release_version` / `security_epoch` come from the record the measured
/// initramfs wrote (`0` when there is none); `health` is a
/// [`components_health`] bitmap.
///
/// `instance` is a random value the keepalive draws when it starts (a
/// restarted keepalive has another); `unhealthy_ticks` counts that
/// instance's ticks that found a check failing, counted in the guest
/// before any request leaves it — so a sample the host withholds still
/// shows in every later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestComponents {
    pub release_version: u32,
    pub security_epoch: u32,
    pub health: u32,
    pub instance: u32,
    pub unhealthy_ticks: u32,
}

/// Ed25519 public-key length (KBS L0 signer + the `node_id`).
pub const PUBKEY_LEN: usize = 32;

/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

/// SHA-256 output length — `snp_report_digest`, `vcek_chain_digest`,
/// `prev_attestation_hash`, `chain_genesis`.
pub const DIGEST_LEN: usize = 32;

/// SEV-SNP launch-measurement length (3x SHA-384 — see PR-F3).
pub const MEASUREMENT_LEN: usize = 48;

/// One live-attestation body — the KBS L0-signed statement.
///
/// Every field is signed. `signer_pubkey` is bound IN so the
/// signature self-certifies which KBS produced it — the pallet
/// checks it equals the root-allowlisted KBS pubkey before trusting
/// the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAttestation {
    /// Wire-format version. MUST be [`LIVE_ATTESTATION_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// SHA-256 of the substrate compute-chain genesis hash — replay
    /// domain across forks. Mirrors `ServedDeliveryAggregate`.
    pub chain_genesis: [u8; DIGEST_LEN],
    /// Compute-pallet instance discriminator — replay domain across
    /// multiple deployments of the same pallet on one chain. Mirrors
    /// `ServedDeliveryAggregate::pallet_instance` (opaque 32-byte
    /// id pinned at runtime, NOT a sequence number).
    pub pallet_instance: [u8; DIGEST_LEN],
    /// Stable identifier of the tenant CVM this attestation is for.
    /// Same value the miner-agent uses in the §K heartbeat + the §20
    /// `release` request — binds the attestation to one VM lifetime.
    pub vm_id: String,
    /// The miner's persistent node identity (Ed25519 device key, §23)
    /// the VM is running on. Bound IN so the pallet can credit the
    /// right miner without trusting the submitter.
    pub node_id: [u8; PUBKEY_LEN],
    /// Monotonic per-`vm_id` counter — the very first attestation
    /// after release uses `1` and each subsequent attestation
    /// increments. Combined with `prev_attestation_hash` this gives a
    /// total-order replay-tight chain per VM.
    pub attestation_seq: u64,
    /// The compute-pallet epoch the attestation observation falls
    /// into. The miner-side weight at epoch close is scaled by the
    /// uptime ratio observed in this epoch.
    pub epoch: u64,
    /// Start of the observation window (inclusive), Unix seconds —
    /// when the guest issued the underlying `SNP_GET_REPORT`.
    pub observed_at_unix: u64,
    /// End of the observation window (inclusive), Unix seconds —
    /// when the KBS finished verifying the report and signed this
    /// attestation. `>= observed_at_unix`.
    pub verified_at_unix: u64,
    /// SHA-256 of the raw 1184-byte SEV-SNP report verified by KBS.
    /// Lets a third party cross-check against the off-chain evidence
    /// bundle (issue #280) — same digest discipline.
    pub snp_report_digest: [u8; DIGEST_LEN],
    /// SHA-256 of the VCEK → ASK → ARK PEM chain KBS validated the
    /// report against — also cross-checkable vs the evidence bundle.
    pub vcek_chain_digest: [u8; DIGEST_LEN],
    /// SEV-SNP launch measurement KBS confirmed the report carries.
    /// Pins the attestation to the §22 allowlisted UKI build that
    /// booted this VM — a CVM relaunched on a non-allowlisted image
    /// cannot mint a live attestation that verifies.
    pub measurement: [u8; MEASUREMENT_LEN],
    /// Hash-chain back-pointer: SHA-256 of the previous
    /// [`LiveAttestation::canonical`] body for this `vm_id`. The very
    /// first attestation after release uses the all-zero digest.
    pub prev_attestation_hash: [u8; DIGEST_LEN],
    /// Hard expiry, Unix seconds. The pallet rejects an attestation
    /// whose `expiry <= block_unix_now`. Mirrors §23's `expiry` field
    /// so a stale signed attestation cannot be re-submitted weeks
    /// later to inflate uptime.
    pub expiry_unix: u64,
    /// The KBS L0 Ed25519 public key signing this body. Bound IN so a
    /// verifier checks it equals its pinned root-allowlisted KBS
    /// pubkey before trusting the signature.
    pub signer_pubkey: [u8; PUBKEY_LEN],
    /// v2 ([`LIVE_ATTESTATION_SCHEMA_VERSION_BOUND`]) and optionally v3:
    /// the attested guest. Always `None` on a v1 body.
    pub guest: Option<GuestBinding>,
    /// v3 (required) and v4 (optional): the resources the guest
    /// attested. Always `None` on a v1/v2 body.
    pub resources: Option<GuestResources>,
    /// v4 only ([`LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS`]): the guest
    /// components release and its health. `None` exactly for v1–v3.
    pub components: Option<GuestComponents>,
}

impl LiveAttestation {
    /// Every semantic invariant of a well-formed body. Run by BOTH
    /// [`canonical`](Self::canonical) and [`decode`](Self::decode) so a
    /// hand-crafted canonical body cannot skip the encode-time gates.
    pub fn validate(&self) -> Result<()> {
        match (self.schema_version, &self.components) {
            (LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS, None) => {
                return Err(schema("a v4 body must carry the guest components".into()));
            }
            (LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS, Some(_)) | (_, None) => {}
            (_, Some(_)) => {
                return Err(schema("only a v4 body carries guest components".into()));
            }
        }
        match (self.schema_version, &self.guest, &self.resources) {
            // v4: binding and resources each optional (checked above).
            (LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS, _, _) => {}
            (LIVE_ATTESTATION_SCHEMA_VERSION, None, None)
            | (LIVE_ATTESTATION_SCHEMA_VERSION_BOUND, Some(_), None)
            | (LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES, _, Some(_)) => {}
            (LIVE_ATTESTATION_SCHEMA_VERSION, Some(_), _) => {
                return Err(schema("a v1 body carries no guest binding".into()));
            }
            (LIVE_ATTESTATION_SCHEMA_VERSION_BOUND, None, _) => {
                return Err(schema("a v2 body must carry the guest binding".into()));
            }
            (
                LIVE_ATTESTATION_SCHEMA_VERSION | LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
                _,
                Some(_),
            ) => {
                return Err(schema("only a v3 body carries guest resources".into()));
            }
            (LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES, _, None) => {
                return Err(schema("a v3 body must carry the guest resources".into()));
            }
            (v, _, _) => {
                return Err(schema(format!(
                    "unknown schema_version {v} (want {LIVE_ATTESTATION_SCHEMA_VERSION}, \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_BOUND}, \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES} or \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS})"
                )));
            }
        }
        if let Some(r) = &self.resources {
            if r.vcpus_online == 0 {
                return Err(schema("vcpus_online must be > 0".into()));
            }
            if r.mem_total_kib == 0 {
                return Err(schema("mem_total_kib must be > 0".into()));
            }
        }
        if self.vm_id.is_empty() {
            return Err(schema("vm_id must be non-empty".into()));
        }
        if self.attestation_seq == 0 {
            return Err(schema("attestation_seq must be > 0".into()));
        }
        if self.observed_at_unix == 0 {
            return Err(schema("observed_at_unix must be non-zero".into()));
        }
        if self.verified_at_unix < self.observed_at_unix {
            return Err(schema(
                "verified_at_unix must be >= observed_at_unix".into(),
            ));
        }
        if self.expiry_unix <= self.verified_at_unix {
            return Err(schema(
                "expiry_unix must be strictly after verified_at_unix".into(),
            ));
        }
        Ok(())
    }

    /// Deterministic-CBOR encoding of the to-be-signed body. Fails
    /// closed on any [`validate`](Self::validate) violation. Field
    /// ordering: alphabetic on text-keys (RFC 8949 §4.2.1).
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut entries = vec![
            (
                Value::Text("attestation_seq".into()),
                Value::Integer(self.attestation_seq.into()),
            ),
            (
                Value::Text("chain_genesis".into()),
                Value::Bytes(self.chain_genesis.to_vec()),
            ),
            (
                Value::Text("domain".into()),
                Value::Text(LIVE_ATTESTATION_DOMAIN.into()),
            ),
            (
                Value::Text("epoch".into()),
                Value::Integer(self.epoch.into()),
            ),
            (
                Value::Text("expiry_unix".into()),
                Value::Integer(self.expiry_unix.into()),
            ),
            (
                Value::Text("measurement".into()),
                Value::Bytes(self.measurement.to_vec()),
            ),
            (
                Value::Text("node_id".into()),
                Value::Bytes(self.node_id.to_vec()),
            ),
            (
                Value::Text("observed_at_unix".into()),
                Value::Integer(self.observed_at_unix.into()),
            ),
            (
                Value::Text("pallet_instance".into()),
                Value::Bytes(self.pallet_instance.to_vec()),
            ),
            (
                Value::Text("prev_attestation_hash".into()),
                Value::Bytes(self.prev_attestation_hash.to_vec()),
            ),
            (
                Value::Text("schema_version".into()),
                Value::Integer(self.schema_version.into()),
            ),
            (
                Value::Text("signer_pubkey".into()),
                Value::Bytes(self.signer_pubkey.to_vec()),
            ),
            (
                Value::Text("snp_report_digest".into()),
                Value::Bytes(self.snp_report_digest.to_vec()),
            ),
            (
                Value::Text("vcek_chain_digest".into()),
                Value::Bytes(self.vcek_chain_digest.to_vec()),
            ),
            (
                Value::Text("verified_at_unix".into()),
                Value::Integer(self.verified_at_unix.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text(self.vm_id.clone())),
        ];
        // v2 adds three keys; the canonical encoder sorts them in, so a
        // v1 body re-encodes byte-identically to every prior build.
        if let Some(g) = &self.guest {
            entries.extend([
                (
                    Value::Text("binding_source".into()),
                    Value::Text(g.source.as_str().into()),
                ),
                (
                    Value::Text("chip_id".into()),
                    Value::Bytes(g.chip_id.to_vec()),
                ),
                (
                    Value::Text("report_id".into()),
                    Value::Bytes(g.report_id.to_vec()),
                ),
            ]);
        }
        // v3 adds four more, sorted in the same way (optional in v4).
        if let Some(r) = &self.resources {
            entries.extend([
                (
                    Value::Text("mem_firmware_kib".into()),
                    Value::Integer(r.mem_firmware_kib.into()),
                ),
                (
                    Value::Text("mem_total_kib".into()),
                    Value::Integer(r.mem_total_kib.into()),
                ),
                (
                    Value::Text("mem_unaccepted_kib".into()),
                    Value::Integer(r.mem_unaccepted_kib.into()),
                ),
                (
                    Value::Text("vcpus_online".into()),
                    Value::Integer(r.vcpus_online.into()),
                ),
            ]);
        }
        // v4 adds three.
        if let Some(c) = &self.components {
            entries.extend([
                (
                    Value::Text("components_health".into()),
                    Value::Integer(c.health.into()),
                ),
                (
                    Value::Text("components_instance".into()),
                    Value::Integer(c.instance.into()),
                ),
                (
                    Value::Text("components_release_version".into()),
                    Value::Integer(c.release_version.into()),
                ),
                (
                    Value::Text("components_security_epoch".into()),
                    Value::Integer(c.security_epoch.into()),
                ),
                (
                    Value::Text("components_unhealthy_ticks".into()),
                    Value::Integer(c.unhealthy_ticks.into()),
                ),
            ]);
        }
        to_canonical_vec(&Value::Map(entries)).map_err(|e| schema(format!("encode: {e}")))
    }

    /// Decode + validate a canonical-CBOR body. Hostile-origin parser
    /// — never trusts the wire shape. Rejects: non-canonical encoding,
    /// non-text or duplicated map key, unknown field, wrong `domain`,
    /// unknown `schema_version`, wrong-length byte field, or any
    /// semantically invalid value.
    pub fn decode(body: &[u8]) -> Result<LiveAttestation> {
        assert_canonical(body).map_err(|e| schema(format!("body: {e}")))?;
        let value: Value =
            ciborium::de::from_reader(body).map_err(|e| schema(format!("decode: {e}")))?;
        let mut map = into_string_map(value)?;

        let domain = take_text(&mut map, "domain")?;
        if domain != LIVE_ATTESTATION_DOMAIN {
            return Err(schema(format!(
                "domain must be {LIVE_ATTESTATION_DOMAIN:?}, got {domain:?}"
            )));
        }
        let schema_version = take_u32(&mut map, "schema_version")?;
        let (guest, resources, components) = match schema_version {
            LIVE_ATTESTATION_SCHEMA_VERSION => (None, None, None),
            LIVE_ATTESTATION_SCHEMA_VERSION_BOUND => (Some(take_guest(&mut map)?), None, None),
            LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS => {
                // Binding and resources are each all-or-nothing, decided by
                // one key; a stray partial set is left over and refused.
                let guest = if map.contains_key("binding_source") {
                    Some(take_guest(&mut map)?)
                } else {
                    None
                };
                let resources = if map.contains_key("vcpus_online") {
                    Some(take_resources(&mut map)?)
                } else {
                    None
                };
                let components = GuestComponents {
                    release_version: take_u32(&mut map, "components_release_version")?,
                    security_epoch: take_u32(&mut map, "components_security_epoch")?,
                    health: take_u32(&mut map, "components_health")?,
                    instance: take_u32(&mut map, "components_instance")?,
                    unhealthy_ticks: take_u32(&mut map, "components_unhealthy_ticks")?,
                };
                (guest, resources, Some(components))
            }
            LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES => {
                // The binding is all-or-nothing: `binding_source` decides,
                // and a stray `chip_id` / `report_id` without it is left
                // over and refused below.
                let guest = if map.contains_key("binding_source") {
                    Some(take_guest(&mut map)?)
                } else {
                    None
                };
                (guest, Some(take_resources(&mut map)?), None)
            }
            v => {
                return Err(schema(format!(
                    "unknown schema_version {v} (want {LIVE_ATTESTATION_SCHEMA_VERSION}, \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_BOUND}, \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES} or \
                     {LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS})"
                )));
            }
        };
        let chain_genesis = take_byte_array::<DIGEST_LEN>(&mut map, "chain_genesis")?;
        let pallet_instance = take_byte_array::<DIGEST_LEN>(&mut map, "pallet_instance")?;
        let vm_id = take_text(&mut map, "vm_id")?;
        let node_id = take_byte_array::<PUBKEY_LEN>(&mut map, "node_id")?;
        let attestation_seq = take_u64(&mut map, "attestation_seq")?;
        let epoch = take_u64(&mut map, "epoch")?;
        let observed_at_unix = take_u64(&mut map, "observed_at_unix")?;
        let verified_at_unix = take_u64(&mut map, "verified_at_unix")?;
        let snp_report_digest = take_byte_array::<DIGEST_LEN>(&mut map, "snp_report_digest")?;
        let vcek_chain_digest = take_byte_array::<DIGEST_LEN>(&mut map, "vcek_chain_digest")?;
        let measurement = take_byte_array::<MEASUREMENT_LEN>(&mut map, "measurement")?;
        let prev_attestation_hash =
            take_byte_array::<DIGEST_LEN>(&mut map, "prev_attestation_hash")?;
        let expiry_unix = take_u64(&mut map, "expiry_unix")?;
        let signer_pubkey = take_byte_array::<PUBKEY_LEN>(&mut map, "signer_pubkey")?;
        reject_leftover(&map, "live attestation")?;

        let att = LiveAttestation {
            schema_version,
            chain_genesis,
            pallet_instance,
            vm_id,
            node_id,
            attestation_seq,
            epoch,
            observed_at_unix,
            verified_at_unix,
            snp_report_digest,
            vcek_chain_digest,
            measurement,
            prev_attestation_hash,
            expiry_unix,
            signer_pubkey,
            guest,
            resources,
            components,
        };
        att.validate()?;
        Ok(att)
    }
}

/// Signed live-attestation envelope.
///
/// `body` is the canonical CBOR of a [`LiveAttestation`]; `sig` is
/// the 64-byte Ed25519 signature over `body` by the KBS L0 key.
/// Both [`encode`](Self::encode) and [`decode`](Self::decode) keep
/// the outer envelope canonical too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLiveAttestation {
    pub body: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SignedLiveAttestation {
    /// Canonical-CBOR encoding of the `{body, sig}` envelope.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.sig.len() != SIGNATURE_LEN {
            return Err(schema(format!(
                "sig must be {SIGNATURE_LEN} bytes, got {}",
                self.sig.len()
            )));
        }
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(self.body.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.sig.clone())),
        ]);
        to_canonical_vec(&v).map_err(|e| schema(format!("envelope encode: {e}")))
    }

    /// Decode a canonical-CBOR signed envelope. Rejects a
    /// non-canonical wrapper, unknown fields, and a wrong-length sig.
    pub fn decode(bytes: &[u8]) -> Result<SignedLiveAttestation> {
        assert_canonical(bytes).map_err(|e| schema(format!("envelope: {e}")))?;
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| schema(format!("envelope decode: {e}")))?;
        let mut map = into_string_map(value)?;
        let body = take_bytes(&mut map, "body")?;
        let sig = take_bytes(&mut map, "sig")?;
        reject_leftover(&map, "signed live-attestation envelope")?;
        if sig.len() != SIGNATURE_LEN {
            return Err(schema(format!(
                "sig must be {SIGNATURE_LEN} bytes, got {}",
                sig.len()
            )));
        }
        Ok(SignedLiveAttestation { body, sig })
    }
}

// ── decode helpers (module-local, mirroring `audit_vm_cert.rs`) ─────

fn take_resources(map: &mut BTreeMap<String, Value>) -> Result<GuestResources> {
    Ok(GuestResources {
        vcpus_online: take_u32(map, "vcpus_online")?,
        mem_firmware_kib: take_u64(map, "mem_firmware_kib")?,
        mem_total_kib: take_u64(map, "mem_total_kib")?,
        mem_unaccepted_kib: take_u64(map, "mem_unaccepted_kib")?,
    })
}

fn take_guest(map: &mut BTreeMap<String, Value>) -> Result<GuestBinding> {
    let source_text = take_text(map, "binding_source")?;
    let source = BindingSource::parse(&source_text)
        .ok_or_else(|| schema(format!("unknown binding_source {source_text:?}")))?;
    Ok(GuestBinding {
        chip_id: take_byte_array::<CHIP_ID_LEN>(map, "chip_id")?,
        report_id: take_byte_array::<REPORT_ID_LEN>(map, "report_id")?,
        source,
    })
}

fn schema(msg: String) -> HippiusTypesError {
    HippiusTypesError::LiveAttestationSchema(msg)
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

fn take_bytes(map: &mut BTreeMap<String, Value>, key: &str) -> Result<Vec<u8>> {
    match take(map, key)? {
        Value::Bytes(b) => Ok(b),
        _ => Err(schema(format!("field {key:?} is not a byte string"))),
    }
}

fn take_byte_array<const N: usize>(
    map: &mut BTreeMap<String, Value>,
    key: &str,
) -> Result<[u8; N]> {
    let bytes = take_bytes(map, key)?;
    bytes.as_slice().try_into().map_err(|_| {
        schema(format!(
            "field {key:?} must be {N} bytes, got {}",
            bytes.len()
        ))
    })
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

fn take_u32(map: &mut BTreeMap<String, Value>, key: &str) -> Result<u32> {
    let n = take_u64(map, key)?;
    u32::try_from(n).map_err(|_| schema(format!("field {key:?} out of u32 range")))
}

fn reject_leftover(map: &BTreeMap<String, Value>, what: &str) -> Result<()> {
    if let Some(key) = map.keys().next() {
        return Err(schema(format!("unknown field {key:?} in {what}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LiveAttestation {
        LiveAttestation {
            components: None,
            schema_version: LIVE_ATTESTATION_SCHEMA_VERSION,
            chain_genesis: [0xAA; DIGEST_LEN],
            pallet_instance: [0xDD; DIGEST_LEN],
            vm_id: "tnabcd1234".into(),
            node_id: [0xBB; PUBKEY_LEN],
            attestation_seq: 42,
            epoch: 9001,
            observed_at_unix: 1_800_000_000,
            verified_at_unix: 1_800_000_005,
            snp_report_digest: [0x11; DIGEST_LEN],
            vcek_chain_digest: [0x22; DIGEST_LEN],
            measurement: [0x33; MEASUREMENT_LEN],
            prev_attestation_hash: [0x44; DIGEST_LEN],
            expiry_unix: 1_800_000_900,
            signer_pubkey: [0xCC; PUBKEY_LEN],
            guest: None,
            resources: None,
        }
    }

    fn sample_v2() -> LiveAttestation {
        LiveAttestation {
            components: None,
            schema_version: LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
            guest: Some(GuestBinding {
                chip_id: [0x66; CHIP_ID_LEN],
                report_id: [0x77; REPORT_ID_LEN],
                source: BindingSource::Release,
            }),
            ..sample()
        }
    }

    #[test]
    fn v2_round_trips_and_is_v1_plus_three_keys() {
        let a = sample_v2();
        let body = a.canonical().unwrap();
        assert_canonical(&body).unwrap();
        assert_eq!(LiveAttestation::decode(&body).unwrap(), a);
        let v1 = sample().canonical().unwrap();
        let keys = |b: &[u8]| -> Vec<String> {
            let v: Value = ciborium::de::from_reader(b).unwrap();
            match v {
                Value::Map(e) => e
                    .into_iter()
                    .map(|(k, _)| match k {
                        Value::Text(t) => t,
                        _ => panic!(),
                    })
                    .collect(),
                _ => panic!(),
            }
        };
        let mut extra: Vec<String> = keys(&body)
            .into_iter()
            .filter(|k| !keys(&v1).contains(k))
            .collect();
        extra.sort();
        assert_eq!(extra, vec!["binding_source", "chip_id", "report_id"]);
    }

    #[test]
    fn the_guest_binding_is_signed() {
        let base = sample_v2().canonical().unwrap();
        let mutate: &[fn(&mut GuestBinding)] = &[
            |g| g.chip_id[0] ^= 0xFF,
            |g| g.report_id[0] ^= 0xFF,
            |g| g.source = BindingSource::FirstUse,
        ];
        for m in mutate {
            let mut a = sample_v2();
            m(a.guest.as_mut().unwrap());
            assert_ne!(base, a.canonical().unwrap());
        }
    }

    #[test]
    fn version_and_binding_must_agree() {
        let mut v1_with = sample();
        v1_with.guest = sample_v2().guest;
        assert!(v1_with.canonical().is_err());
        let mut v2_without = sample_v2();
        v2_without.guest = None;
        assert!(v2_without.canonical().is_err());
        let mut v3 = sample_v2();
        v3.schema_version = 3;
        assert!(v3.canonical().is_err());
    }

    #[test]
    fn a_v1_body_with_binding_keys_is_refused_on_decode() {
        // Take a v2 body and relabel it v1: the leftover keys must fail.
        let v2 = sample_v2().canonical().unwrap();
        let v: Value = ciborium::de::from_reader(v2.as_slice()).unwrap();
        let Value::Map(entries) = v else { panic!() };
        let relabelled: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, val)| {
                if matches!(&k, Value::Text(t) if t == "schema_version") {
                    (k, Value::Integer(1.into()))
                } else {
                    (k, val)
                }
            })
            .collect();
        let bytes = to_canonical_vec(&Value::Map(relabelled)).unwrap();
        assert!(LiveAttestation::decode(&bytes).is_err());
    }

    fn sample_v3() -> LiveAttestation {
        LiveAttestation {
            components: None,
            schema_version: LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
            resources: Some(GuestResources {
                vcpus_online: 2,
                mem_firmware_kib: 8_386_000,
                mem_total_kib: 7_900_000,
                mem_unaccepted_kib: 0,
            }),
            ..sample_v2()
        }
    }

    /// Re-encode `body` with `schema_version` set to `version`.
    fn relabel(body: &[u8], version: u32) -> Vec<u8> {
        let v: Value = ciborium::de::from_reader(body).unwrap();
        let Value::Map(entries) = v else { panic!() };
        let relabelled: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, val)| {
                if matches!(&k, Value::Text(t) if t == "schema_version") {
                    (k, Value::Integer(version.into()))
                } else {
                    (k, val)
                }
            })
            .collect();
        to_canonical_vec(&Value::Map(relabelled)).unwrap()
    }

    #[test]
    fn v3_round_trips_and_every_resource_is_signed() {
        let a = sample_v3();
        let body = a.canonical().unwrap();
        assert_canonical(&body).unwrap();
        assert_eq!(LiveAttestation::decode(&body).unwrap(), a);
        let mutate: &[fn(&mut GuestResources)] = &[
            |r| r.vcpus_online -= 1,
            |r| r.mem_firmware_kib -= 1,
            |r| r.mem_total_kib -= 1,
            |r| r.mem_unaccepted_kib += 1,
        ];
        for m in mutate {
            let mut b = sample_v3();
            m(b.resources.as_mut().unwrap());
            assert_ne!(body, b.canonical().unwrap());
        }
    }

    #[test]
    fn resource_keys_only_decode_under_v3() {
        let v3 = sample_v3().canonical().unwrap();
        // Relabelled v2 (or v1): the resource keys are left over.
        assert!(LiveAttestation::decode(&relabel(&v3, 2)).is_err());
        assert!(LiveAttestation::decode(&relabel(&v3, 1)).is_err());
        // A v2 body relabelled v3 is missing its resources.
        let v2 = sample_v2().canonical().unwrap();
        assert!(LiveAttestation::decode(&relabel(&v2, 3)).is_err());
        assert!(LiveAttestation::decode(&relabel(&v3, 4)).is_err());
    }

    #[test]
    fn an_unknown_binding_source_is_refused() {
        assert_eq!(
            BindingSource::parse("release"),
            Some(BindingSource::Release)
        );
        assert_eq!(
            BindingSource::parse("first-use"),
            Some(BindingSource::FirstUse)
        );
        assert_eq!(BindingSource::parse("trust-me"), None);
    }

    #[test]
    fn canonical_is_stable_and_canonical() {
        let a = sample();
        let x = a.canonical().unwrap();
        let y = a.canonical().unwrap();
        assert_eq!(x, y);
        assert_canonical(&x).unwrap();
    }

    #[test]
    fn canonical_round_trips_through_decode() {
        let a = sample();
        let body = a.canonical().unwrap();
        let decoded = LiveAttestation::decode(&body).unwrap();
        assert_eq!(a, decoded);
        assert_eq!(body, decoded.canonical().unwrap());
    }

    #[test]
    fn every_field_is_signed() {
        let base = sample().canonical().unwrap();
        let mutate: &[fn(&mut LiveAttestation)] = &[
            |a| a.chain_genesis[0] ^= 0xFF,
            |a| a.pallet_instance[0] ^= 0xFF,
            |a| a.vm_id = "other-vm".into(),
            |a| a.node_id[0] ^= 0xFF,
            |a| a.attestation_seq += 1,
            |a| a.epoch += 1,
            |a| a.observed_at_unix += 1,
            |a| a.verified_at_unix += 1,
            |a| a.snp_report_digest[0] ^= 0xFF,
            |a| a.vcek_chain_digest[0] ^= 0xFF,
            |a| a.measurement[0] ^= 0xFF,
            |a| a.prev_attestation_hash[0] ^= 0xFF,
            |a| a.expiry_unix += 1,
            |a| a.signer_pubkey[0] ^= 0xFF,
        ];
        for m in mutate {
            let mut a = sample();
            m(&mut a);
            assert_ne!(
                base,
                a.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    #[test]
    fn empty_vm_id_rejected_at_encode() {
        let mut a = sample();
        a.vm_id = String::new();
        assert!(a.canonical().is_err());
    }

    #[test]
    fn zero_attestation_seq_rejected_at_encode() {
        let mut a = sample();
        a.attestation_seq = 0;
        assert!(a.canonical().is_err());
    }

    #[test]
    fn inverted_window_rejected_at_encode() {
        let mut a = sample();
        a.verified_at_unix = a.observed_at_unix - 1;
        assert!(a.canonical().is_err());
    }

    #[test]
    fn non_strict_expiry_rejected_at_encode() {
        let mut a = sample();
        a.expiry_unix = a.verified_at_unix;
        assert!(a.canonical().is_err());
        a.expiry_unix = a.verified_at_unix - 1;
        assert!(a.canonical().is_err());
    }

    #[test]
    fn decode_rejects_unknown_field() {
        let a = sample();
        let mut entries =
            match ciborium::de::from_reader::<Value, _>(a.canonical().unwrap().as_slice()).unwrap()
            {
                Value::Map(e) => e,
                _ => unreachable!(),
            };
        entries.push((Value::Text("rogue".into()), Value::Integer(1.into())));
        let body = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(LiveAttestation::decode(&body).is_err());
    }

    #[test]
    fn decode_rejects_wrong_domain() {
        let a = sample();
        let mut entries =
            match ciborium::de::from_reader::<Value, _>(a.canonical().unwrap().as_slice()).unwrap()
            {
                Value::Map(e) => e,
                _ => unreachable!(),
            };
        for (k, v) in &mut entries {
            if matches!(k, Value::Text(t) if t == "domain") {
                *v = Value::Text("HIPPIUS_AUDIT_VM_AGGREGATE_V1".into());
            }
        }
        let body = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(LiveAttestation::decode(&body).is_err());
    }

    #[test]
    fn decode_rejects_unknown_schema_version() {
        let mut a = sample();
        a.schema_version = 99;
        assert!(a.canonical().is_err());
    }

    #[test]
    fn decode_rejects_non_canonical_body() {
        let v = Value::Map(vec![
            (Value::Text("zzz".into()), Value::Integer(1.into())),
            (
                Value::Text("domain".into()),
                Value::Text(LIVE_ATTESTATION_DOMAIN.into()),
            ),
        ]);
        let mut noncanon = Vec::new();
        ciborium::ser::into_writer(&v, &mut noncanon).unwrap();
        assert!(LiveAttestation::decode(&noncanon).is_err());
    }

    #[test]
    fn decode_rejects_short_signer_pubkey() {
        let a = sample();
        let mut entries =
            match ciborium::de::from_reader::<Value, _>(a.canonical().unwrap().as_slice()).unwrap()
            {
                Value::Map(e) => e,
                _ => unreachable!(),
            };
        for (k, v) in &mut entries {
            if matches!(k, Value::Text(t) if t == "signer_pubkey") {
                *v = Value::Bytes(vec![0u8; 31]);
            }
        }
        let body = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(LiveAttestation::decode(&body).is_err());
    }

    #[test]
    fn decode_rejects_short_measurement() {
        let a = sample();
        let mut entries =
            match ciborium::de::from_reader::<Value, _>(a.canonical().unwrap().as_slice()).unwrap()
            {
                Value::Map(e) => e,
                _ => unreachable!(),
            };
        for (k, v) in &mut entries {
            if matches!(k, Value::Text(t) if t == "measurement") {
                *v = Value::Bytes(vec![0u8; 47]);
            }
        }
        let body = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(LiveAttestation::decode(&body).is_err());
    }

    #[test]
    fn signed_envelope_round_trips() {
        let signed = SignedLiveAttestation {
            body: sample().canonical().unwrap(),
            sig: vec![0xAB; SIGNATURE_LEN],
        };
        let bytes = signed.encode().unwrap();
        assert_canonical(&bytes).unwrap();
        assert_eq!(signed, SignedLiveAttestation::decode(&bytes).unwrap());
    }

    #[test]
    fn signed_envelope_rejects_wrong_sig_length() {
        let signed = SignedLiveAttestation {
            body: sample().canonical().unwrap(),
            sig: vec![0u8; 63],
        };
        assert!(signed.encode().is_err());
    }

    #[test]
    fn signed_envelope_decode_rejects_unknown_field() {
        let signed = SignedLiveAttestation {
            body: sample().canonical().unwrap(),
            sig: vec![0xAB; SIGNATURE_LEN],
        };
        let bytes = signed.encode().unwrap();
        let mut entries = match ciborium::de::from_reader::<Value, _>(bytes.as_slice()).unwrap() {
            Value::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((Value::Text("extra".into()), Value::Integer(1.into())));
        let bad = to_canonical_vec(&Value::Map(entries)).unwrap();
        assert!(SignedLiveAttestation::decode(&bad).is_err());
    }
}
