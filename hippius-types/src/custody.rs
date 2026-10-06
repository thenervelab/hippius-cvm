//! Wire contract for the **guest custody lease** — bounded erase latency
//! for a running tenant CVM under an untrusted miner.
//!
//! ## What it is
//!
//! A running guest holds its disk keys only while the KBS keeps renewing a
//! short-lived *custody lease*. An in-guest daemon renews it over the
//! existing vsock KBS relay; when the lease runs out the guest suspends its
//! dm-crypt mappings (`luksSuspend` wipes the key), and when the KBS says
//! the VM is decommissioned it powers itself off. The KBS is the issuer:
//! custody standing is derived from the SAME lifecycle state the release
//! path checks, so "granted" and "releasable" cannot drift apart.
//!
//! "Lease" already means the placement `lease_id` elsewhere in the stack;
//! this module says **custody** everywhere to keep the two apart.
//!
//! ## Three requests, one verdict
//!
//! - **bind** ([`CustodyBindBody`]) — rare: once per boot, per daemon
//!   restart and per KBS restart. SNP-attested (report_data binds the
//!   per-boot lease key, see [`crate::report_data::custody_bind`]) AND
//!   signed by the VM's §7 lifecycle key, because the golden launch
//!   measurement is shared across same-distro tenants and a report alone
//!   does not name the VM.
//! - **renew** ([`CustodyRenewBody`]) — every few minutes, signed by the
//!   per-boot Ed25519 *lease key* the bind registered. No SNP report, so
//!   no AMD KDS round trip and no Vault read on the hot path.
//! - **rekey** ([`CustodyRekeyBody`]) — after a suspend, to get the disk
//!   key back for `luksResume`. Same lease-key auth as renew plus a fresh
//!   X25519 key the KEK is sealed to. Advances neither the boot counter
//!   nor the volume stamp.
//!
//! Every positive or negative *decision* comes back as a
//! [`SignedCustodyVerdict`], signed by the KBS L0 key over
//! [`VERDICT_SIG_DOMAIN`]` ‖ body`. Anything that is not a verdict — a
//! KBS that lost its state, an unknown VM, a Vault or KDS hiccup — is an
//! unsigned HTTP error the guest must treat as "retry, change nothing".
//!
//! ## Domain separation
//!
//! Every signature in this module is over `domain ‖ body`, where each
//! domain is a distinct NUL-terminated ASCII tag. The first byte of every
//! domain is `h` (`0x68`), a CBOR *text-string* head — so a custody
//! signing input can never parse as the CBOR *map* that every other
//! signed body in the stack starts with (release response, denial,
//! live-attestation, stopped-ack, evidence bundle), and vice versa. The
//! same L0 key therefore signs custody verdicts without any new secret or
//! trust-anchor change, and no existing verifier accepts one.
//!
//! This crate stays crypto-free: it owns the schema, the canonical
//! encoding and the signing *inputs*; Ed25519 sign/verify live with the
//! KBS and the guest daemon.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::cbor::{assert_canonical, to_canonical_vec};
use crate::{HippiusTypesError, Result};
use ciborium::value::Value;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The only wire version this build speaks.
pub const CUSTODY_WIRE_V: u32 = 1;

/// Signing domain of the bind body, signed by the VM's §7 lifecycle key.
pub const BIND_SIG_DOMAIN: &[u8] = b"hippius-custody-bind-v1\0";
/// Signing domain of the renew body, signed by the per-boot lease key.
pub const RENEW_SIG_DOMAIN: &[u8] = b"hippius-custody-renew-v1\0";
/// Signing domain of the rekey body, signed by the per-boot lease key.
pub const REKEY_SIG_DOMAIN: &[u8] = b"hippius-custody-rekey-v1\0";
/// Signing domain of the KBS verdict, signed by the KBS L0 key.
pub const VERDICT_SIG_DOMAIN: &[u8] = b"hippius-custody-verdict-v1\0";
/// HPKE `info` for the KEK a rekey Grant seals to the guest's fresh
/// X25519 key. Distinct from the §20 release `HPKE_INFO`, so a rekey
/// ciphertext can never be opened as a release secret or the reverse.
pub const REKEY_HPKE_INFO: &[u8] = b"hippius-custody-rekey-kek-v1";

/// Guest challenge, KBS nonce, lease key and X25519 key length.
pub const KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// Upper bound on the SNP report carried by a bind (the real report is
/// 1184 bytes; the verifier checks the exact layout).
pub const MAX_SNP_REPORT_LEN: usize = 4096;
/// Upper bound on the COSE OrderTicket carried by a bind.
pub const MAX_TICKET_LEN: usize = 16 * 1024;
/// Upper bound on a `vm_id`.
pub const MAX_VM_ID_LEN: usize = 128;
/// Upper bound on a verdict `reason` (closed vocabulary, all short).
pub const MAX_REASON_LEN: usize = 64;

/// Which clock the guest's deadline runs on.
///
/// `Untrusted` is the only mode the fleet can run today: without SEV-SNP
/// Secure TSC the host owns the guest's clocks and can stretch the
/// deadline. The KBS cross-checks the guest's reported monotonic clock
/// against its own wall clock while the guest is reachable — detection,
/// not prevention. `SecureTsc` is reserved for guests launched with
/// Secure TSC once the hosts and guest kernels support it; a guest's
/// *claim* of it is informational until the KBS can prove it from the
/// launch measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockMode {
    Untrusted = 0,
    SecureTsc = 1,
}

impl TryFrom<u8> for ClockMode {
    type Error = HippiusTypesError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Untrusted),
            1 => Ok(Self::SecureTsc),
            other => Err(schema(format!("unknown clock_mode {other}"))),
        }
    }
}

/// The guest daemon's state, reported on every renew/rekey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyPhase {
    Armed = 0,
    Suspended = 1,
    Unbound = 2,
}

impl TryFrom<u8> for CustodyPhase {
    type Error = HippiusTypesError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Armed),
            1 => Ok(Self::Suspended),
            2 => Ok(Self::Unbound),
            other => Err(schema(format!("unknown custody phase {other}"))),
        }
    }
}

/// The three signed decisions. Everything else is an unsigned retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    /// Keep (or get back) the disk keys until the new deadline.
    Grant = 0,
    /// The VM is decommissioning or destroyed: suspend, ack, power off.
    Revoked = 1,
    /// A newer generation or a newer boot of this VM exists: this
    /// instance is a stale copy and must power off (no ack).
    Superseded = 2,
}

impl TryFrom<u8> for Verdict {
    type Error = HippiusTypesError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Grant),
            1 => Ok(Self::Revoked),
            2 => Ok(Self::Superseded),
            other => Err(schema(format!("unknown verdict {other}"))),
        }
    }
}

/// Bind — the attested request that registers this boot's lease key.
///
/// `lease_pub`, `vm_id`, `generation` and `boot_counter` are ALSO folded
/// into the SNP report's `REPORT_DATA` (see
/// [`crate::report_data::custody_bind`]), so the key the KBS registers is
/// the one the attested guest chose. `boot_counter` and `generation` are
/// the values from the guest's *verified* KBS release response, never
/// from the miner-writable state disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyBindBody {
    pub v: u32,
    pub vm_id: String,
    pub generation: u64,
    pub boot_counter: u64,
    /// The COSE OrderTicket this boot was released under. The KBS
    /// re-verifies its signature (not its expiry — a re-bind days after
    /// boot is legitimate) for the measurement set, the placement and the
    /// Vault paths.
    #[serde(with = "serde_bytes")]
    pub cose_ticket: Vec<u8>,
    /// Single-use KBS nonce (`/v1/kbs/nonce`). Folded INTO the
    /// `REPORT_DATA` hash, never placed raw — see
    /// [`crate::report_data::custody_bind`] for why.
    #[serde(with = "serde_bytes")]
    pub kbs_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub snp_report: Vec<u8>,
    /// Per-boot Ed25519 lease public key. The private half never leaves
    /// SNP-encrypted guest RAM.
    #[serde(with = "serde_bytes")]
    pub lease_pub: Vec<u8>,
    /// Fresh guest randomness the verdict must echo.
    #[serde(with = "serde_bytes")]
    pub guest_challenge: Vec<u8>,
    /// Raw `rdtsc` at send time (Secure TSC calibration, later).
    pub tsc: u64,
    /// Guest `CLOCK_MONOTONIC_RAW` at send time, milliseconds — the clock
    /// the untrusted-mode deadline runs on, and the one the KBS skew check
    /// compares against its wall clock.
    pub mono_ms: u64,
    pub clock_mode: u8,
}

impl CustodyBindBody {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        if self.boot_counter == 0 {
            // Custody's duplicate-instance detection IS the boot counter;
            // a guest that never submitted one cannot bind.
            return Err(schema("boot_counter must be >= 1".into()));
        }
        if self.cose_ticket.is_empty() || self.cose_ticket.len() > MAX_TICKET_LEN {
            return Err(schema("cose_ticket length out of bounds".into()));
        }
        check_len("kbs_nonce", &self.kbs_nonce, KEY_LEN)?;
        if self.snp_report.is_empty() || self.snp_report.len() > MAX_SNP_REPORT_LEN {
            return Err(schema("snp_report length out of bounds".into()));
        }
        check_len("lease_pub", &self.lease_pub, KEY_LEN)?;
        check_len("guest_challenge", &self.guest_challenge, KEY_LEN)?;
        ClockMode::try_from(self.clock_mode)?;
        Ok(())
    }
}

/// Bind envelope: `body` is the canonical CBOR of [`CustodyBindBody`],
/// `lifecycle_sig` is Ed25519 by the VM's §7 lifecycle key over
/// [`BIND_SIG_DOMAIN`]` ‖ body`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyBindRequest {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub lifecycle_sig: Vec<u8>,
}

/// The guest daemon's self-report, carried on every renew/rekey so the
/// operator sees a suspended guest even when nothing else would say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyStatus {
    pub phase: u8,
    pub since_last_grant_s: u32,
    pub suspended_s: u32,
}

/// Renew — the cheap periodic request. Authenticated ONLY by the lease
/// key registered at bind (no SNP report, no Vault, no KDS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRenewBody {
    pub v: u32,
    pub vm_id: String,
    pub generation: u64,
    pub boot_counter: u64,
    #[serde(with = "serde_bytes")]
    pub lease_pub: Vec<u8>,
    /// Strictly increasing per lease key; the KBS refuses a replay.
    pub seq: u64,
    #[serde(with = "serde_bytes")]
    pub guest_challenge: Vec<u8>,
    pub tsc: u64,
    pub mono_ms: u64,
    pub clock_mode: u8,
    pub status: CustodyStatus,
}

impl CustodyRenewBody {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        if self.boot_counter == 0 {
            return Err(schema("boot_counter must be >= 1".into()));
        }
        check_len("lease_pub", &self.lease_pub, KEY_LEN)?;
        if self.seq == 0 {
            // seq 0 is the bind's; every renew is strictly after it.
            return Err(schema("seq must be >= 1".into()));
        }
        check_len("guest_challenge", &self.guest_challenge, KEY_LEN)?;
        ClockMode::try_from(self.clock_mode)?;
        CustodyPhase::try_from(self.status.phase)?;
        Ok(())
    }
}

/// Renew envelope: `sig` is Ed25519 by the lease key over
/// [`RENEW_SIG_DOMAIN`]` ‖ body`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRenewRequest {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Rekey — a renew that also asks for the disk key back, sealed to a
/// fresh X25519 key generated for this one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRekeyBody {
    pub v: u32,
    #[serde(with = "serde_bytes")]
    pub hpke_pub: Vec<u8>,
    pub renew: CustodyRenewBody,
}

impl CustodyRekeyBody {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_len("hpke_pub", &self.hpke_pub, KEY_LEN)?;
        self.renew.validate()
    }
}

/// Rekey envelope: `sig` is Ed25519 by the lease key over
/// [`REKEY_SIG_DOMAIN`]` ‖ body`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRekeyRequest {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// The KBS decision. Echoes the request's identity (`vm_id`,
/// `generation`, `boot_counter`, `sha256(lease_pub)`, `guest_challenge`,
/// `seq`) so the guest can refuse a verdict minted for anything but the
/// request it has outstanding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyVerdictBody {
    pub v: u32,
    pub vm_id: String,
    pub generation: u64,
    pub boot_counter: u64,
    #[serde(with = "serde_bytes")]
    pub lease_pub_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub guest_challenge: Vec<u8>,
    pub seq: u64,
    pub verdict: u8,
    /// Lease length from the guest's SEND time. The guest clamps it to
    /// the cap in its measured cmdline.
    pub ttl_s: u32,
    /// How long a suspended guest waits before rebooting itself.
    pub stage2_s: u32,
    /// Renew interval.
    pub renew_s: u32,
    /// Secure-TSC deadline, once the KBS has calibrated the guest's TSC.
    /// Always absent while every guest runs `ClockMode::Untrusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_tsc: Option<u64>,
    /// Informational only — the guest never uses the KBS's clock.
    pub kbs_time_unix: u64,
    /// Closed vocabulary (`granted`, `decommissioning`, `destroyed`,
    /// `generation-superseded`, `boot-superseded`).
    pub reason: String,
}

impl CustodyVerdictBody {
    pub fn validate(&self) -> Result<()> {
        check_v(self.v)?;
        check_vm_id(&self.vm_id)?;
        check_len("lease_pub_hash", &self.lease_pub_hash, KEY_LEN)?;
        check_len("guest_challenge", &self.guest_challenge, KEY_LEN)?;
        let allowed: &[&str] = match Verdict::try_from(self.verdict)? {
            Verdict::Grant => &[verdict_reason::GRANTED],
            Verdict::Revoked => &[verdict_reason::DECOMMISSIONING, verdict_reason::DESTROYED],
            Verdict::Superseded => &[
                verdict_reason::GENERATION_SUPERSEDED,
                verdict_reason::BOOT_SUPERSEDED,
            ],
        };
        // A reason that contradicts its verdict (`Grant` + `destroyed`)
        // is a version-skewed or buggy peer: refuse it rather than guess
        // which half to believe.
        if !allowed.contains(&self.reason.as_str()) {
            return Err(schema("reason does not match the verdict".into()));
        }
        Ok(())
    }
}

/// Signed verdict. `sig` is Ed25519 by the KBS L0 key over
/// [`VERDICT_SIG_DOMAIN`]` ‖ body`; `kid` names that key (the guest pins
/// it at bake, like the release response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCustodyVerdict {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// The disk key a rekey Grant returns: HPKE (the §20 suite) sealed to the
/// request's `hpke_pub`, `info = `[`REKEY_HPKE_INFO`], `aad =
/// `[`rekey_kek_aad`]`(verdict.body)` — so the ciphertext is bound to the
/// exact signed Grant it arrived with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKek {
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// Rekey response. `wrapped_kek` is present iff the verdict is a Grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRekeyResponse {
    pub verdict: SignedCustodyVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_kek: Option<WrappedKek>,
}

impl CustodyRekeyResponse {
    /// Check the envelope against its (already signature-verified and
    /// decoded) verdict body: a key rides with a Grant and with nothing
    /// else, and a Grant without a key is not a usable rekey.
    pub fn validate_against(&self, verdict: &CustodyVerdictBody) -> Result<()> {
        verdict.validate()?;
        let is_grant = Verdict::try_from(verdict.verdict)? == Verdict::Grant;
        match (&self.wrapped_kek, is_grant) {
            (Some(k), true) => {
                check_len("wrapped_kek.enc", &k.enc, KEY_LEN)?;
                if k.ct.is_empty() {
                    return Err(schema("wrapped_kek.ct is empty".into()));
                }
                Ok(())
            }
            (None, false) => Ok(()),
            (Some(_), false) => Err(schema("wrapped_kek on a non-Grant verdict".into())),
            (None, true) => Err(schema("rekey Grant without wrapped_kek".into())),
        }
    }
}

/// Closed vocabulary of a signed verdict's `reason`, per verdict.
pub mod verdict_reason {
    /// The only reason a [`super::Verdict::Grant`] carries.
    pub const GRANTED: &str = "granted";
    /// Revoked: the KBS holds the VM as `Decommissioning`.
    pub const DECOMMISSIONING: &str = "decommissioning";
    /// Revoked: the KBS holds a `Destroyed` tombstone for the VM.
    pub const DESTROYED: &str = "destroyed";
    /// Superseded: a newer generation of the VM is the releasable one.
    pub const GENERATION_SUPERSEDED: &str = "generation-superseded";
    /// Superseded: a newer boot of the same generation committed its
    /// boot counter (this instance is a stale copy).
    pub const BOOT_SUPERSEDED: &str = "boot-superseded";
}

/// Closed vocabulary of the unsigned, retryable outcomes (HTTP 503 body).
/// The guest never changes state on any of them.
pub mod retry_reason {
    /// The KBS holds no binding for this lease key (restart, or a newer
    /// bind replaced it): bind again, from RAM, without rebooting.
    pub const REBIND_REQUIRED: &str = "rebind-required";
    /// No lifecycle row, or a row that cannot be positively matched to
    /// this guest. Never a kill: a wiped or re-seeded KBS must not power
    /// off healthy guests.
    pub const UNKNOWN_VM: &str = "unknown-vm";
    /// Vault / KDS / storage trouble on the KBS side.
    pub const UNAVAILABLE: &str = "unavailable";
    /// The KBS has custody switched off.
    pub const DISABLED: &str = "custody-disabled";
}

/// `domain ‖ body` — the exact bytes every custody signature covers.
pub fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(body);
    out
}

/// `sha256(lease_pub)` as echoed in every verdict.
pub fn lease_pub_hash(lease_pub: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&Sha256::digest(lease_pub));
    out
}

/// AAD of a rekey KEK: `sha256(verdict body)`.
pub fn rekey_kek_aad(verdict_body: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&Sha256::digest(verdict_body));
    out
}

/// Canonical (RFC 8949 §4.2.1) CBOR of any custody struct.
pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = Value::serialized(value).map_err(|e| schema(format!("encode: {e}")))?;
    to_canonical_vec(&v)
}

/// Decode a custody struct, accepting ONLY the exact bytes
/// [`encode_canonical`] would produce for the decoded value.
///
/// `assert_canonical` alone is not enough: it checks the generic CBOR
/// value, while serde's typed decode is more lenient than the encoder —
/// it takes an integer array for a `serde_bytes` field, ignores CBOR
/// tags (which `assert_canonical` does not descend into), and reads an
/// explicit `null` the same as an omitted `Option`. Each of those is a
/// second wire image for one logical message, i.e. two different byte
/// strings a signature or a replay key could disagree about. Re-encoding
/// and demanding byte equality leaves exactly one.
pub fn decode_canonical<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    assert_canonical(bytes)?;
    let value: T = ciborium::de::from_reader(bytes).map_err(|e| schema(format!("decode: {e}")))?;
    if encode_canonical(&value)? != bytes {
        return Err(schema("not the canonical encoding of its own value".into()));
    }
    Ok(value)
}

fn check_v(v: u32) -> Result<()> {
    if v != CUSTODY_WIRE_V {
        return Err(schema(format!("unsupported v={v} (want {CUSTODY_WIRE_V})")));
    }
    Ok(())
}

fn check_vm_id(vm_id: &str) -> Result<()> {
    if vm_id.is_empty() || vm_id.len() > MAX_VM_ID_LEN {
        return Err(schema("vm_id length out of bounds".into()));
    }
    Ok(())
}

fn check_len(field: &str, bytes: &[u8], want: usize) -> Result<()> {
    if bytes.len() != want {
        return Err(schema(format!("{field} must be {want} bytes")));
    }
    Ok(())
}

fn schema(msg: String) -> HippiusTypesError {
    HippiusTypesError::CustodySchema(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn renew() -> CustodyRenewBody {
        CustodyRenewBody {
            v: 1,
            vm_id: "vm-1".into(),
            generation: 3,
            boot_counter: 7,
            lease_pub: vec![1; 32],
            seq: 9,
            guest_challenge: vec![2; 32],
            tsc: 123,
            mono_ms: 456,
            clock_mode: 0,
            status: CustodyStatus {
                phase: 0,
                since_last_grant_s: 600,
                suspended_s: 0,
            },
        }
    }

    fn bind() -> CustodyBindBody {
        CustodyBindBody {
            v: 1,
            vm_id: "vm-1".into(),
            generation: 3,
            boot_counter: 7,
            cose_ticket: vec![0xd2; 40],
            kbs_nonce: vec![3; 32],
            snp_report: vec![0; 1184],
            lease_pub: vec![1; 32],
            guest_challenge: vec![2; 32],
            tsc: 1,
            mono_ms: 2,
            clock_mode: 0,
        }
    }

    #[test]
    fn every_domain_is_distinct_and_starts_with_a_cbor_text_head() {
        let domains = [
            BIND_SIG_DOMAIN,
            RENEW_SIG_DOMAIN,
            REKEY_SIG_DOMAIN,
            VERDICT_SIG_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            // 0x68 = CBOR major type 3 (text string). Every other signed
            // body in the stack is a CBOR map (0xa0..=0xbf), so a custody
            // signing input can never be read as one of them.
            assert_eq!(a[0], 0x68);
            assert_eq!(*a.last().unwrap(), 0, "NUL-terminated");
            for b in &domains[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a));
            }
        }
    }

    #[test]
    fn signing_input_prefixes_the_domain() {
        let si = signing_input(RENEW_SIG_DOMAIN, b"body");
        assert!(si.starts_with(RENEW_SIG_DOMAIN));
        assert!(si.ends_with(b"body"));
        assert_ne!(si, signing_input(REKEY_SIG_DOMAIN, b"body"));
    }

    #[test]
    fn renew_round_trips_canonically() {
        let r = renew();
        let bytes = encode_canonical(&r).unwrap();
        assert_canonical(&bytes).unwrap();
        let back: CustodyRenewBody = decode_canonical(&bytes).unwrap();
        assert_eq!(back, r);
        back.validate().unwrap();
    }

    #[test]
    fn rekey_nests_the_renew_body() {
        let k = CustodyRekeyBody {
            v: 1,
            hpke_pub: vec![5; 32],
            renew: renew(),
        };
        let bytes = encode_canonical(&k).unwrap();
        let back: CustodyRekeyBody = decode_canonical(&bytes).unwrap();
        assert_eq!(back, k);
        back.validate().unwrap();
        // A rekey body is never a renew body (and so a lease signature
        // over one cannot be presented as the other, domain aside).
        assert!(decode_canonical::<CustodyRenewBody>(&bytes).is_err());
    }

    #[test]
    fn unknown_field_is_refused() {
        let r = renew();
        let mut v = Value::serialized(&r).unwrap();
        if let Value::Map(m) = &mut v {
            m.push((Value::Text("rogue".into()), Value::Integer(1.into())));
        }
        let bytes = to_canonical_vec(&v).unwrap();
        assert!(decode_canonical::<CustodyRenewBody>(&bytes).is_err());
    }

    #[test]
    fn non_canonical_bytes_are_refused() {
        let mut bytes = Vec::new();
        // serde emits struct order, which is not the canonical key order.
        ciborium::ser::into_writer(&renew(), &mut bytes).unwrap();
        assert!(decode_canonical::<CustodyRenewBody>(&bytes).is_err());
    }

    #[test]
    fn bind_validation_rejects_each_bad_field() {
        bind().validate().unwrap();
        let mut b = bind();
        b.boot_counter = 0;
        assert!(b.validate().is_err(), "no boot counter, no custody");
        let mut b = bind();
        b.lease_pub = vec![1; 31];
        assert!(b.validate().is_err());
        let mut b = bind();
        b.kbs_nonce = vec![1; 33];
        assert!(b.validate().is_err());
        let mut b = bind();
        b.guest_challenge.clear();
        assert!(b.validate().is_err());
        let mut b = bind();
        b.clock_mode = 2;
        assert!(b.validate().is_err());
        let mut b = bind();
        b.v = 2;
        assert!(b.validate().is_err());
        let mut b = bind();
        b.vm_id.clear();
        assert!(b.validate().is_err());
        let mut b = bind();
        b.snp_report = vec![0; MAX_SNP_REPORT_LEN + 1];
        assert!(b.validate().is_err());
    }

    #[test]
    fn renew_validation_rejects_seq_zero_and_unknown_phase() {
        let mut r = renew();
        r.seq = 0;
        assert!(r.validate().is_err());
        let mut r = renew();
        r.status.phase = 3;
        assert!(r.validate().is_err());
    }

    #[test]
    fn verdict_omits_an_absent_deadline_tsc() {
        let v = CustodyVerdictBody {
            v: 1,
            vm_id: "vm-1".into(),
            generation: 3,
            boot_counter: 7,
            lease_pub_hash: lease_pub_hash(&[1; 32]).to_vec(),
            guest_challenge: vec![2; 32],
            seq: 9,
            verdict: Verdict::Grant as u8,
            ttl_s: 86_400,
            stage2_s: 172_800,
            renew_s: 600,
            deadline_tsc: None,
            kbs_time_unix: 1,
            reason: "granted".into(),
        };
        let bytes = encode_canonical(&v).unwrap();
        let as_value: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(m) = as_value else {
            panic!("verdict body is a map")
        };
        assert!(!m
            .iter()
            .any(|(k, _)| k == &Value::Text("deadline_tsc".into())));
        let back: CustodyVerdictBody = decode_canonical(&bytes).unwrap();
        assert_eq!(back, v);
        back.validate().unwrap();
    }

    fn verdict(v: Verdict, reason: &str) -> CustodyVerdictBody {
        CustodyVerdictBody {
            v: 1,
            vm_id: "vm-1".into(),
            generation: 3,
            boot_counter: 7,
            lease_pub_hash: vec![1; 32],
            guest_challenge: vec![2; 32],
            seq: 9,
            verdict: v as u8,
            ttl_s: 1,
            stage2_s: 1,
            renew_s: 1,
            deadline_tsc: None,
            kbs_time_unix: 1,
            reason: reason.into(),
        }
    }

    #[test]
    fn verdict_reason_must_match_its_verdict() {
        verdict(Verdict::Grant, verdict_reason::GRANTED)
            .validate()
            .unwrap();
        verdict(Verdict::Revoked, verdict_reason::DESTROYED)
            .validate()
            .unwrap();
        verdict(Verdict::Revoked, verdict_reason::DECOMMISSIONING)
            .validate()
            .unwrap();
        verdict(Verdict::Superseded, verdict_reason::BOOT_SUPERSEDED)
            .validate()
            .unwrap();
        verdict(Verdict::Superseded, verdict_reason::GENERATION_SUPERSEDED)
            .validate()
            .unwrap();
        assert!(verdict(Verdict::Grant, verdict_reason::DESTROYED)
            .validate()
            .is_err());
        assert!(verdict(Verdict::Revoked, verdict_reason::GRANTED)
            .validate()
            .is_err());
        assert!(verdict(Verdict::Superseded, "").validate().is_err());
    }

    #[test]
    fn rekey_response_carries_a_key_iff_grant() {
        let signed = SignedCustodyVerdict {
            body: vec![],
            kid: vec![],
            sig: vec![],
        };
        let key = WrappedKek {
            enc: vec![3; 32],
            ct: vec![4; 48],
        };
        let grant = verdict(Verdict::Grant, verdict_reason::GRANTED);
        let revoked = verdict(Verdict::Revoked, verdict_reason::DESTROYED);
        let with = CustodyRekeyResponse {
            verdict: signed.clone(),
            wrapped_kek: Some(key),
        };
        let without = CustodyRekeyResponse {
            verdict: signed,
            wrapped_kek: None,
        };
        with.validate_against(&grant).unwrap();
        without.validate_against(&revoked).unwrap();
        assert!(with.validate_against(&revoked).is_err());
        assert!(without.validate_against(&grant).is_err());
    }

    #[test]
    fn decode_refuses_every_second_wire_image() {
        // An integer array where the struct wants a byte string: generic
        // CBOR-canonical, but not what the encoder emits.
        let r = renew();
        let mut v = Value::serialized(&r).unwrap();
        if let Value::Map(m) = &mut v {
            for (k, val) in m.iter_mut() {
                if k == &Value::Text("lease_pub".into()) {
                    *val = Value::Array(vec![Value::Integer(1.into()); 32]);
                }
            }
        }
        let bytes = to_canonical_vec(&v).unwrap();
        assert!(decode_canonical::<CustodyRenewBody>(&bytes).is_err());

        // An explicit `null` for an omitted Option.
        let body = verdict(Verdict::Grant, verdict_reason::GRANTED);
        let mut v = Value::serialized(&body).unwrap();
        if let Value::Map(m) = &mut v {
            m.push((Value::Text("deadline_tsc".into()), Value::Null));
        }
        let bytes = to_canonical_vec(&v).unwrap();
        assert!(decode_canonical::<CustodyVerdictBody>(&bytes).is_err());

        // A CBOR tag around the whole body.
        let inner = Value::serialized(&r).unwrap();
        let tagged = to_canonical_vec(&Value::Tag(24, Box::new(inner))).unwrap();
        assert!(decode_canonical::<CustodyRenewBody>(&tagged).is_err());

        // …while the encoder's own output still decodes.
        let ok = encode_canonical(&r).unwrap();
        assert_eq!(decode_canonical::<CustodyRenewBody>(&ok).unwrap(), r);
    }

    #[test]
    fn enums_refuse_unknown_discriminants() {
        assert!(Verdict::try_from(3).is_err());
        assert!(ClockMode::try_from(2).is_err());
        assert!(CustodyPhase::try_from(3).is_err());
        assert_eq!(Verdict::try_from(1).unwrap(), Verdict::Revoked);
    }
}
