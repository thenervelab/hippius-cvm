//! Tenant-CVM identity and per-domain state — [`VmId`],
//! [`DomainUuid`], [`CvmHandle`].
//!
//! These are the small value types the lifecycle state machine tracks.
//! [`VmId`] is charset-restricted **at construction** so it can be
//! interpolated into a libvirt domain name and a `virsh` argument
//! vector with no escaping and no injection surface (PR-MA-3 review
//! focus). [`DomainUuid`] is the libvirt domain UUID — generated from
//! the OS CSPRNG so the agent controls a stable id for the domain
//! before `virsh define` ever runs.

use std::path::PathBuf;

use rand_core::{OsRng, RngCore};

use super::libvirt_driver::DomainId;
use super::CvmPhase;
use crate::error::{MinerAgentError, Result};

/// Length in bytes of an AMD SEV-SNP launch digest (384-bit).
pub const LAUNCH_DIGEST_LEN: usize = 48;

/// Which class of domain a [`CvmHandle`] tracks.
///
/// The miner-agent runs at most ONE `Infra` domain (the blackbox
/// host-attestor, PR-7) alongside any number of `Tenant` CVMs. The
/// distinction drives every place the two must NOT be conflated:
///
/// - `Tenant` — a customer SEV-SNP CVM. Today's exact behaviour: it
///   carries a data disk, a vsock CID, a KEK/ticket exchange, and is
///   counted for capacity / heartbeat / billing.
/// - `Infra` — the singleton diskless host-attestor CVM. It boots the
///   measured blackbox UKI (kernel + initrd-as-root, NO disk), has NO
///   CID / KEK / ticket / KBS-proxy, and is FILTERED OUT of every
///   tenant-facing accounting surface (capacity, heartbeat, billing).
///
/// `Default` is `Tenant` so a [`super::adopt::PersistedHandle`] written
/// before PR-7 (no `is_infra` field) deserializes as a tenant CVM —
/// existing on-disk snapshots re-adopt unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainProfile {
    /// A tenant customer CVM — today's exact behaviour, unchanged.
    #[default]
    Tenant,
    /// The singleton diskless blackbox host-attestor CVM (PR-7).
    Infra,
}

impl DomainProfile {
    /// `true` for the diskless host-attestor domain.
    pub fn is_infra(self) -> bool {
        matches!(self, DomainProfile::Infra)
    }
}

/// Upper bound on a [`VmId`] string. Comfortably inside libvirt's
/// domain-name limit once the `hippius-tenant-` prefix is added.
const VM_ID_MAX_LEN: usize = 64;

/// A tenant confidential-VM identifier.
///
/// Validated at construction to `[a-z0-9-]`, 1..=64 chars, no leading
/// or trailing hyphen. That charset is a strict subset of both a
/// libvirt domain name and a shell-safe token, so a `VmId` can be
/// placed into the domain XML and a `virsh` argv element verbatim —
/// there is no XML-injection or argument-injection path through it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId(String);

impl VmId {
    /// Validate `raw` and wrap it. Fail-closed on any disallowed
    /// character — the sub-classifier names which rule was broken.
    pub fn new(raw: &str) -> Result<Self> {
        let len = raw.len();
        if len == 0 || len > VM_ID_MAX_LEN {
            return Err(MinerAgentError::LaunchInput("vm-id-length"));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(MinerAgentError::LaunchInput("vm-id-charset"));
        }
        if raw.starts_with('-') || raw.ends_with('-') {
            return Err(MinerAgentError::LaunchInput("vm-id-hyphen"));
        }
        Ok(Self(raw.to_string()))
    }

    /// The validated id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for VmId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for VmId {
    /// Deserialize **through the validating constructor** — a `VmId`
    /// decoded off a wire order (MA-5) is charset-checked exactly like
    /// one built in-process, so it can never carry an injection
    /// character into a libvirt domain name or a `virsh` argv.
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        VmId::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// A libvirt domain UUID (RFC-4122 textual form, lowercase).
///
/// The agent generates the UUID itself and embeds it in the domain
/// XML, so the domain id is known before `virsh define` and never has
/// to be scraped back out of virsh output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainUuid(String);

impl DomainUuid {
    /// Generate a random version-4 UUID from the OS CSPRNG.
    ///
    /// Fail-closed if the CSPRNG draw fails — a launch must not
    /// proceed without a well-formed domain id.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| MinerAgentError::LaunchFailed("rng"))?;
        // RFC-4122 §4.4: version nibble = 4, variant bits = 10xx.
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let text = format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&bytes[0..4]),
            hex::encode(&bytes[4..6]),
            hex::encode(&bytes[6..8]),
            hex::encode(&bytes[8..10]),
            hex::encode(&bytes[10..16]),
        );
        Ok(Self(text))
    }

    /// Validate + wrap an existing UUID string (used by the domain-XML
    /// known-answer test, which needs a fixed, non-random UUID).
    pub fn parse(raw: &str) -> Result<Self> {
        let bytes = raw.as_bytes();
        if bytes.len() != 36 {
            return Err(MinerAgentError::LaunchInput("uuid-length"));
        }
        for (i, &c) in bytes.iter().enumerate() {
            let ok = match i {
                8 | 13 | 18 | 23 => c == b'-',
                _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
            };
            if !ok {
                return Err(MinerAgentError::LaunchInput("uuid-charset"));
            }
        }
        Ok(Self(raw.to_string()))
    }

    /// The UUID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A running (or failed) tenant CVM the lifecycle is tracking.
///
/// Holds only non-secret control-plane facts: the ids, the current
/// [`CvmPhase`], the pre-flight launch digest (a public measurement,
/// not a secret), the resources charged against the host budget, and
/// the LUKS data-disk *path*. No VM memory and no disk *content* is
/// ever stored here — the disk path is the file location the §24
/// `destroy` capacity-reclaim unlinks, not the ciphertext, and it is a
/// non-secret path under the miner root. The only cmdline held is a
/// customer-keys VM's measured one, inside its guardian recipe (never
/// `Debug`-printed).
#[derive(Debug, Clone)]
pub struct CvmHandle {
    /// The tenant id this CVM was launched for (or the singleton
    /// `host-attestor` id for the Infra domain).
    pub vm_id: VmId,
    /// Whether this handle tracks a `Tenant` CVM (the default, today's
    /// behaviour) or the singleton diskless `Infra` host-attestor (PR-7).
    /// Filtered out of tenant capacity / heartbeat / billing accounting.
    pub profile: DomainProfile,
    /// The libvirt domain id (its name) used for every `virsh` call.
    pub domain_id: DomainId,
    /// The libvirt domain UUID embedded in the domain XML.
    pub domain_uuid: DomainUuid,
    /// Where this CVM is in the lifecycle state machine.
    pub phase: CvmPhase,
    /// The pre-flight SEV-SNP launch digest — what the KBS must see in
    /// the guest's attestation report (§F binding).
    pub launch_digest: [u8; LAUNCH_DIGEST_LEN],
    /// vCPUs charged against the host CPU budget.
    pub cpu_count: u8,
    /// MiB of guest RAM charged against the host memory budget.
    pub memory_mb: u32,
    /// GiB of tenant data disk charged against the host disk budget
    /// (`HostResources::total_disk_gb`). Reserved while the VM is live so
    /// concurrent launches can't over-commit the backing storage.
    pub data_disk_size_gb: u32,
    /// The per-VM LUKS data-disk image path. Retained so a §24
    /// `destroy` can unlink the ciphertext file (capacity reclaim);
    /// the cryptographic erase is the Vault KEK-destroy, never this.
    pub luks_disk_path: PathBuf,
    /// The AF_VSOCK CID the lifecycle allocated for this VM. Cached
    /// alongside the handle so the reboot-watcher can look it up
    /// without re-querying [`crate::vsock::peer::CidAllocator`].
    pub cid: u32,
    /// The L1-signed COSE OrderTicket bytes vali dispatched. Cached
    /// so the reboot-watcher can re-push it via AF_VSOCK whenever
    /// libvirt restarts the domain (guest `sudo reboot` →
    /// `<on_reboot>restart</on_reboot>` → new boot, new keyscript run,
    /// new vsock listener — but the same ticket binding still
    /// authorises release because the §6 fields are stable across
    /// reboots). The bytes are a public placement assertion (no
    /// secrets — see hippius-types::ticket docs), so caching them
    /// in miner state is §20-safe.
    pub cose_ticket: Vec<u8>,
    /// Customer-held keys: the VM's guardian endpoint + launch recipe
    /// (see [`super::guardian::GuardianRoute`]). `None` for an M0 VM —
    /// the guardian relay then refuses its CID. The recipe carries the
    /// measured cmdline, which is why [`GuardianRoute`](super::guardian::GuardianRoute)'s
    /// `Debug` redacts it; like the ticket it is a public measurement
    /// input, not a secret.
    pub guardian: Option<super::guardian::GuardianRoute>,
}

impl CvmHandle {
    /// The launch digest as 96 lowercase-hex characters — the form
    /// logged at launch and compared against the §22 allowlist.
    pub fn launch_digest_hex(&self) -> String {
        hex::encode(self.launch_digest)
    }

    /// `true` when this handle tracks the diskless Infra host-attestor
    /// domain rather than a tenant CVM.
    pub fn is_infra(&self) -> bool {
        self.profile.is_infra()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_id_accepts_a_clean_id() {
        let id = VmId::new("tenant-cvm-01").unwrap();
        assert_eq!(id.as_str(), "tenant-cvm-01");
        assert_eq!(id.to_string(), "tenant-cvm-01");
    }

    #[test]
    fn vm_id_rejects_empty_and_overlong() {
        assert!(matches!(
            VmId::new(""),
            Err(MinerAgentError::LaunchInput("vm-id-length"))
        ));
        let long = "a".repeat(VM_ID_MAX_LEN + 1);
        assert!(matches!(
            VmId::new(&long),
            Err(MinerAgentError::LaunchInput("vm-id-length"))
        ));
    }

    #[test]
    fn vm_id_rejects_injection_characters() {
        // Uppercase, whitespace, XML metacharacters, shell
        // metacharacters and path separators must all be refused.
        for bad in [
            "Tenant", "a b", "a/b", "a<b", "a&b", "a;rm", "a'b", "a\"b", "a$b", "a`b",
        ] {
            assert!(
                matches!(
                    VmId::new(bad),
                    Err(MinerAgentError::LaunchInput("vm-id-charset"))
                ),
                "expected charset rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn vm_id_rejects_leading_or_trailing_hyphen() {
        for bad in ["-tenant", "tenant-"] {
            assert!(matches!(
                VmId::new(bad),
                Err(MinerAgentError::LaunchInput("vm-id-hyphen"))
            ));
        }
    }

    #[test]
    fn domain_uuid_generate_is_well_formed_v4() {
        let u = DomainUuid::generate().unwrap();
        let s = u.as_str();
        assert_eq!(s.len(), 36);
        // Version nibble (index 14) is 4; variant nibble (index 19) is
        // one of 8/9/a/b.
        assert_eq!(s.as_bytes()[14], b'4');
        assert!(matches!(s.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        // Round-trips through the validator.
        assert!(DomainUuid::parse(s).is_ok());
    }

    #[test]
    fn domain_uuid_generate_is_unique() {
        let a = DomainUuid::generate().unwrap();
        let b = DomainUuid::generate().unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn domain_uuid_parse_rejects_malformed() {
        for bad in [
            "",
            "not-a-uuid",
            "00000000-0000-4000-8000-00000000000",   // 35 chars
            "00000000-0000-4000-8000-0000000000000", // 37 chars
            "00000000_0000_4000_8000_000000000000",  // wrong separators
            "00000000-0000-4000-8000-00000000000G",  // non-hex
            "00000000-0000-4000-8000-00000000000A",  // uppercase hex
        ] {
            assert!(
                DomainUuid::parse(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }
}
