//! Startup **re-adoption** of running tenant CVMs — the
//! `[host].skip_shutdown_teardown` (#669) follow-up.
//!
//! With `skip_shutdown_teardown=true` a graceful agent restart leaves
//! the qemu domains running (they live in libvirtd's cgroup). But the
//! agent's in-memory handle-map, CID allocator, capacity accounting,
//! vsock relay and reboot-watcher all start EMPTY, so a surviving CVM
//! becomes UNTRACKED: its cpu/mem is no longer counted (a later launch
//! can over-commit), its served-receipt relay + reboot ticket re-push
//! stop, and its CID leaks (a fresh launch can collide with it).
//!
//! This module closes that gap. Every field of a live [`CvmHandle`] is
//! snapshotted to one JSON file per VM under `<state_root>/adopt/` at
//! launch, and dropped on a clean stop/destroy. At startup
//! [`crate::lifecycle::CvmLifecycle::readopt_running`] reads the
//! snapshots, keeps those whose libvirt domain is still `Running`, and
//! re-inserts the handle + re-reserves its CID.
//!
//! §20: a `CvmHandle` holds ONLY non-secret control-plane facts (see
//! its doc). The `cose_ticket` is a public placement assertion — the
//! CvmHandle doc explicitly calls caching it in miner state §20-safe —
//! so persisting these snapshots leaks nothing.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::cvm_handle::{CvmHandle, DomainProfile, DomainUuid, VmId, LAUNCH_DIGEST_LEN};
use super::libvirt_driver::DomainId;
use super::CvmPhase;
use crate::error::{MinerAgentError, Result};

/// Subdirectory (under the state-disk root) holding one JSON per live
/// CVM. On the same durable volume as the boot-counter state disks, so
/// it survives an agent restart.
const ADOPT_SUBDIR: &str = "adopt";

/// The on-disk, restart-surviving snapshot of a [`CvmHandle`]. All
/// fields are plain scalars / hex strings so the `[u8; 48]` launch
/// digest + the COSE ticket bytes serialize without `serde_big_array`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedHandle {
    pub vm_id: String,
    pub domain_id: String,
    pub domain_uuid: String,
    pub launch_digest_hex: String,
    pub cpu_count: u8,
    pub memory_mb: u32,
    pub data_disk_size_gb: u32,
    pub luks_disk_path: String,
    pub cid: u32,
    pub cose_ticket_hex: String,
    /// PR-7 — `true` for the singleton diskless Infra host-attestor
    /// snapshot. `#[serde(default)]` (⇒ `false` ⇒ [`DomainProfile::Tenant`])
    /// so every pre-PR-7 tenant snapshot on disk deserializes unchanged and
    /// re-adopts exactly as before.
    #[serde(default)]
    pub is_infra: bool,
    /// Customer-held keys: the guardian endpoint and the canonical-CBOR
    /// launch recipe (hex) of a customer-keys VM — so a guest that
    /// (re)boots after an agent restart can still reach its guardian.
    /// Both absent for an M0 VM (and in every pre-H4 snapshot); an agent
    /// that predates the fields ignores them (no `deny_unknown_fields`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_ep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_recipe_cbor_hex: Option<String>,
}

impl From<&CvmHandle> for PersistedHandle {
    fn from(h: &CvmHandle) -> Self {
        Self {
            vm_id: h.vm_id.as_str().to_string(),
            domain_id: h.domain_id.as_str().to_string(),
            domain_uuid: h.domain_uuid.as_str().to_string(),
            launch_digest_hex: hex::encode(h.launch_digest),
            cpu_count: h.cpu_count,
            memory_mb: h.memory_mb,
            data_disk_size_gb: h.data_disk_size_gb,
            luks_disk_path: h.luks_disk_path.to_string_lossy().into_owned(),
            cid: h.cid,
            cose_ticket_hex: hex::encode(&h.cose_ticket),
            is_infra: h.is_infra(),
            guardian_ep: h.guardian.as_ref().map(|g| g.endpoint.clone()),
            // A recipe that was valid at launch always encodes; `None` here
            // only drops the route (the relay then refuses), never the VM.
            guardian_recipe_cbor_hex: h
                .guardian
                .as_ref()
                .and_then(|g| hippius_types::guardian::encode_canonical(&g.recipe).ok())
                .map(hex::encode),
        }
    }
}

impl PersistedHandle {
    /// Rebuild the in-memory [`CvmHandle`] (phase = `Running` — a
    /// re-adopted domain is, by construction, live). Fail-closed on any
    /// malformed field so a corrupt snapshot is skipped, never trusted.
    pub fn into_handle(self) -> Result<CvmHandle> {
        let digest_vec = hex::decode(&self.launch_digest_hex)
            .map_err(|_| MinerAgentError::LaunchInput("adopt-digest-hex"))?;
        let launch_digest: [u8; LAUNCH_DIGEST_LEN] = digest_vec
            .try_into()
            .map_err(|_| MinerAgentError::LaunchInput("adopt-digest-len"))?;
        let cose_ticket = hex::decode(&self.cose_ticket_hex)
            .map_err(|_| MinerAgentError::LaunchInput("adopt-ticket-hex"))?;
        let guardian = self.guardian_route();
        Ok(CvmHandle {
            vm_id: VmId::new(&self.vm_id)?,
            profile: if self.is_infra {
                DomainProfile::Infra
            } else {
                DomainProfile::Tenant
            },
            domain_id: DomainId::new(&self.domain_id)?,
            domain_uuid: DomainUuid::parse(&self.domain_uuid)?,
            phase: CvmPhase::Running,
            launch_digest,
            cpu_count: self.cpu_count,
            memory_mb: self.memory_mb,
            data_disk_size_gb: self.data_disk_size_gb,
            luks_disk_path: PathBuf::from(self.luks_disk_path),
            cid: self.cid,
            cose_ticket,
            guardian,
        })
    }

    /// The persisted guardian route, re-validated. A damaged or partial
    /// one is DROPPED (logged): the VM is still re-adopted — its capacity,
    /// CID and ticket matter more — and the relay refuses its CID rather
    /// than dial an endpoint it can no longer vouch for.
    fn guardian_route(&self) -> Option<super::guardian::GuardianRoute> {
        let (ep, recipe_hex) = match (&self.guardian_ep, &self.guardian_recipe_cbor_hex) {
            (None, None) => return None,
            (Some(ep), Some(recipe)) => (ep, recipe),
            _ => {
                log_guardian_drop(&self.vm_id, "partial");
                return None;
            }
        };
        let route = hex::decode(recipe_hex)
            .ok()
            .and_then(|b| hippius_types::guardian::decode_canonical(&b).ok())
            .map(|recipe| super::guardian::GuardianRoute {
                endpoint: ep.clone(),
                recipe,
            });
        match route {
            Some(r) if r.validate().is_ok() => Some(r),
            _ => {
                log_guardian_drop(&self.vm_id, "invalid");
                None
            }
        }
    }
}

fn log_guardian_drop(vm_id: &str, class: &str) {
    eprintln!(
        "hippius-miner-agent: re-adopt: vm={vm_id} guardian route {class} in snapshot — \
         dropped; the guardian relay will refuse this VM until it is relaunched"
    );
}

/// What libvirt says the host is ACTUALLY running for one domain —
/// parsed out of `virsh dumpxml`.
///
/// This is the ground truth re-adoption reconciles the persisted
/// sidecar against ([`crate::lifecycle::CvmLifecycle::readopt_running`]).
/// The sidecar is a file on the miner's disk: it can be stale (an
/// operator edited the domain), absent (it was never written, or was
/// moved aside), or simply wrong. The `<memory>` / `<vcpu>` / `<vsock>`
/// / `<disk>` elements below are what QEMU was actually started with, so
/// they — not the sidecar — decide what is charged against the host
/// budget and which CID is reserved.
///
/// Every field is a NON-SECRET control-plane fact, the same posture as
/// [`CvmHandle`] itself: a vCPU count, a RAM size, a vsock context id
/// and a ciphertext file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainFacts {
    /// `<vcpu>` — vCPUs the domain actually runs with.
    pub vcpus: u8,
    /// `<memory>` normalised to MiB (libvirt emits KiB by default).
    pub memory_mib: u32,
    /// `<vsock><cid address=…>` — the context id the kernel has bound
    /// for this guest. `None` when the domain has no vsock device.
    pub cid: Option<u32>,
    /// The `vda` disk's backing file — the per-VM WRITABLE volume (the
    /// golden overlay upper, or the legacy LUKS root). `None` when the
    /// domain is diskless (the Infra host-attestor).
    pub writable_disk: Option<PathBuf>,
    /// `<uuid>` — the libvirt domain UUID.
    pub domain_uuid: Option<DomainUuid>,
    /// The `<os>` direct-boot block — what QEMU was started with and so
    /// what was measured. `None` unless loader, kernel, initrd AND cmdline
    /// are all present.
    pub boot: Option<BootFacts>,
}

/// The measured boot inputs of a running domain, read back from its XML:
/// `<loader>` (OVMF), `<kernel>`, `<initrd>` and the exact `<cmdline>`.
/// Used to rebuild a customer-keys VM's guardian route when the adoption
/// snapshot does not carry one.
#[derive(Clone, PartialEq, Eq)]
pub struct BootFacts {
    pub ovmf: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// Unescaped, NOT trimmed: the exact measured string.
    pub cmdline: String,
}

/// Hand-written so the cmdline is never `Debug`-printed.
impl std::fmt::Debug for BootFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootFacts")
            .field("ovmf", &self.ovmf)
            .field("kernel", &self.kernel)
            .field("initrd", &self.initrd)
            .field("cmdline", &"<redacted>")
            .finish()
    }
}

/// The `<os>` block's boot inputs, if all four are there.
fn boot_facts(xml: &str) -> Option<BootFacts> {
    let os = section(xml, "os")?;
    let path = |tag: &str| {
        element(&os, tag)
            .map(|(_, t)| PathBuf::from(xml_unescape(t.trim())))
            .filter(|p| !p.as_os_str().is_empty())
    };
    Some(BootFacts {
        ovmf: path("loader")?,
        kernel: path("kernel")?,
        initrd: path("initrd")?,
        cmdline: element(&os, "cmdline").map(|(_, t)| xml_unescape(&t))?,
    })
}

/// Parse the load-bearing facts out of a libvirt domain XML document.
///
/// Deliberately a narrow scanner rather than a general XML parser: the
/// document is machine-generated by libvirt, we need five values from
/// it, and pulling an XML crate into a `unsafe_code = "forbid"` agent
/// for that is not a trade worth making. Every extraction is anchored on
/// an exact element name and fails CLOSED — a document we cannot read
/// yields `Err`, never a plausible-looking zero (a zero would silently
/// charge nothing against the capacity budget, which is the failure this
/// whole path exists to prevent).
///
/// `<vcpu>` and `<memory>` are REQUIRED (no domain runs without them).
/// The vsock CID, the writable disk and the UUID are optional so the
/// same parser serves the diskless Infra attestor.
pub fn parse_domain_facts(xml: &str) -> Result<DomainFacts> {
    let (_, vcpu_text) =
        element(xml, "vcpu").ok_or(MinerAgentError::LaunchInput("domxml-vcpu-missing"))?;
    let vcpus: u8 = vcpu_text
        .trim()
        .parse()
        .map_err(|_| MinerAgentError::LaunchInput("domxml-vcpu-parse"))?;
    if vcpus == 0 {
        return Err(MinerAgentError::LaunchInput("domxml-vcpu-zero"));
    }

    let (mem_attrs, mem_text) =
        element(xml, "memory").ok_or(MinerAgentError::LaunchInput("domxml-memory-missing"))?;
    let raw: u64 = mem_text
        .trim()
        .parse()
        .map_err(|_| MinerAgentError::LaunchInput("domxml-memory-parse"))?;
    // libvirt's default memory unit is KiB, and `dumpxml` always
    // normalises to it — but the agent's OWN template writes MiB, so both
    // spellings must convert correctly.
    let unit = attr(&mem_attrs, "unit").unwrap_or_else(|| "KiB".to_string());
    let memory_mib = memory_to_mib(raw, &unit)?;
    if memory_mib == 0 {
        return Err(MinerAgentError::LaunchInput("domxml-memory-zero"));
    }

    // `<vsock …><cid auto='no' address='16'/></vsock>` — scoped INSIDE the
    // vsock element so an unrelated `<cid>` elsewhere can never be read as
    // the guest's context id.
    let cid = match section(xml, "vsock") {
        Some(vsock) => match tag_attrs(&vsock, "cid").and_then(|a| attr(&a, "address")) {
            Some(addr) => Some(
                addr.trim()
                    .parse::<u32>()
                    .map_err(|_| MinerAgentError::LaunchInput("domxml-cid-parse"))?,
            ),
            None => None,
        },
        None => None,
    };

    let domain_uuid =
        element(xml, "uuid").and_then(|(_, text)| DomainUuid::parse(text.trim()).ok());

    Ok(DomainFacts {
        vcpus,
        memory_mib,
        cid,
        writable_disk: writable_disk_path(xml),
        domain_uuid,
        boot: boot_facts(xml),
    })
}

/// The backing file of the `vda` disk — the per-VM writable volume in
/// BOTH modes (golden: the overlay upper; legacy: the LUKS root). `vdb`
/// / `vdc` are the read-only dm-verity base, `vdd` the state disk and
/// `vde` the legacy data disk, so anchoring on `vda` is what identifies
/// the volume §24 reclaims.
fn writable_disk_path(xml: &str) -> Option<PathBuf> {
    for block in sections(xml, "disk") {
        let is_vda = tag_attrs(&block, "target")
            .and_then(|a| attr(&a, "dev"))
            .is_some_and(|dev| dev == "vda");
        if !is_vda {
            continue;
        }
        if let Some(file) = tag_attrs(&block, "source").and_then(|a| attr(&a, "file")) {
            return Some(PathBuf::from(xml_unescape(&file)));
        }
    }
    None
}

/// Convert a libvirt memory quantity to MiB, rounding UP so a partial
/// MiB is never under-charged. Fails closed on an unrecognised unit —
/// guessing would mis-size the budget by orders of magnitude.
fn memory_to_mib(value: u64, unit: &str) -> Result<u32> {
    const MIB: u64 = 1024 * 1024;
    let bytes = match unit {
        "b" | "bytes" => Some(value),
        "KB" => value.checked_mul(1_000),
        "k" | "KiB" => value.checked_mul(1_024),
        "MB" => value.checked_mul(1_000_000),
        "M" | "MiB" => value.checked_mul(MIB),
        "GB" => value.checked_mul(1_000_000_000),
        "G" | "GiB" => value.checked_mul(1_024 * MIB),
        "TB" => value.checked_mul(1_000_000_000_000),
        "T" | "TiB" => value.checked_mul(1_024 * 1_024 * MIB),
        _ => return Err(MinerAgentError::LaunchInput("domxml-memory-unit")),
    }
    .ok_or(MinerAgentError::LaunchInput("domxml-memory-overflow"))?;
    let mib = bytes.div_ceil(MIB);
    u32::try_from(mib).map_err(|_| MinerAgentError::LaunchInput("domxml-memory-overflow"))
}

/// Byte after `<tag` must delimit the name, so `<memory` never matches
/// `<memoryBacking`.
fn is_name_end(b: u8) -> bool {
    b == b' ' || b == b'>' || b == b'/' || b == b'\n' || b == b'\r' || b == b'\t'
}

/// Offset of the first `<tag` whose name ends cleanly, at or after
/// `from`.
fn find_open(xml: &str, tag: &str, from: usize) -> Option<usize> {
    let needle = format!("<{tag}");
    let mut cursor = from;
    while let Some(rel) = xml.get(cursor..)?.find(&needle) {
        let at = cursor + rel;
        let after = at + needle.len();
        match xml.as_bytes().get(after) {
            Some(&b) if is_name_end(b) => return Some(at),
            _ => cursor = after,
        }
    }
    None
}

/// `(attributes, text)` of the first `<tag …>text</tag>` element.
fn element(xml: &str, tag: &str) -> Option<(String, String)> {
    let open = find_open(xml, tag, 0)?;
    let gt = xml.get(open..)?.find('>')? + open;
    let attrs = xml.get(open + 1 + tag.len()..gt)?.to_string();
    let close = format!("</{tag}>");
    let end = xml.get(gt + 1..)?.find(&close)? + gt + 1;
    Some((attrs, xml.get(gt + 1..end)?.to_string()))
}

/// The raw attribute text of the first `<tag …>` (or `<tag …/>`).
fn tag_attrs(xml: &str, tag: &str) -> Option<String> {
    let open = find_open(xml, tag, 0)?;
    let gt = xml.get(open..)?.find('>')? + open;
    Some(xml.get(open + 1 + tag.len()..gt)?.to_string())
}

/// The full `<tag …>…</tag>` slice, attributes included.
fn section(xml: &str, tag: &str) -> Option<String> {
    sections(xml, tag).into_iter().next()
}

/// Every `<tag …>…</tag>` slice, in document order.
fn sections(xml: &str, tag: &str) -> Vec<String> {
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(open) = find_open(xml, tag, cursor) {
        let Some(rel_end) = xml.get(open..).and_then(|s| s.find(&close)) else {
            break;
        };
        let end = open + rel_end + close.len();
        if let Some(slice) = xml.get(open..end) {
            out.push(slice.to_string());
        }
        cursor = end;
    }
    out
}

/// The value of `name='…'` / `name="…"` in an attribute string.
fn attr(attrs: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("{name}={quote}");
        if let Some(at) = attrs.find(&needle) {
            let rest = attrs.get(at + needle.len()..)?;
            let end = rest.find(quote)?;
            return Some(rest.get(..end)?.to_string());
        }
    }
    None
}

/// Reverse of the domain template's `xml_escape` — a tenant disk path
/// round-trips exactly.
fn xml_unescape(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` LAST so an escaped `&amp;lt;` does not become `<`.
        .replace("&amp;", "&")
}

fn adopt_dir(state_root: &Path) -> PathBuf {
    state_root.join(ADOPT_SUBDIR)
}

fn snapshot_path(state_root: &Path, vm_id: &str) -> PathBuf {
    adopt_dir(state_root).join(format!("{vm_id}.json"))
}

/// Persist a live CVM's handle so a later agent start can re-adopt it.
/// Atomic (temp + rename) so a crash mid-write never leaves a half-JSON
/// that would fail to parse. Best-effort by CONTRACT: the caller logs +
/// continues on `Err` — a missed snapshot only costs re-adoption after a
/// restart, never the running VM.
pub fn persist(state_root: &Path, handle: &CvmHandle) -> Result<()> {
    let dir = adopt_dir(state_root);
    std::fs::create_dir_all(&dir).map_err(|_| MinerAgentError::LaunchFailed("adopt-mkdir"))?;
    let ph = PersistedHandle::from(handle);
    let json = serde_json::to_vec_pretty(&ph)
        .map_err(|_| MinerAgentError::LaunchFailed("adopt-serialize"))?;
    let final_path = snapshot_path(state_root, handle.vm_id.as_str());
    let tmp_path = final_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json).map_err(|_| MinerAgentError::LaunchFailed("adopt-write"))?;
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|_| MinerAgentError::LaunchFailed("adopt-rename"))?;
    Ok(())
}

/// Drop a CVM's snapshot on a clean stop/destroy so it is NOT re-adopted.
/// Idempotent — a missing file is success.
pub fn forget(state_root: &Path, vm_id: &str) {
    let _ = std::fs::remove_file(snapshot_path(state_root, vm_id));
}

/// Every persisted snapshot. Skips unreadable / unparseable / foreign
/// files rather than failing — one corrupt snapshot must not block
/// adoption of the healthy ones.
pub fn list(state_root: &Path) -> Vec<PersistedHandle> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(adopt_dir(state_root)) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "hippius-miner-agent: re-adopt: UNREADABLE snapshot {} — skipped; \
                 if its domain is live the orphan sweep still accounts for it",
                path.display()
            );
            continue;
        };
        match serde_json::from_slice::<PersistedHandle>(&bytes) {
            Ok(ph) => out.push(ph),
            // Loud, not silent: a snapshot we cannot decode is a VM we
            // may be about to leave untracked. The orphan sweep is the
            // safety net, but an operator must see this happened.
            Err(err) => eprintln!(
                "hippius-miner-agent: re-adopt: UNPARSEABLE snapshot {} ({err}) — skipped; \
                 if its domain is live the orphan sweep still accounts for it",
                path.display()
            ),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handle(vm: &str, cid: u32) -> CvmHandle {
        CvmHandle {
            vm_id: VmId::new(vm).unwrap(),
            profile: DomainProfile::Tenant,
            domain_id: DomainId::new(&format!("hippius-tenant-{vm}")).unwrap(),
            domain_uuid: DomainUuid::generate().unwrap(),
            phase: CvmPhase::Running,
            launch_digest: [7u8; LAUNCH_DIGEST_LEN],
            cpu_count: 4,
            memory_mb: 8192,
            data_disk_size_gb: 32,
            luks_disk_path: PathBuf::from(format!("/var/lib/hippius-miner/data/{vm}.img")),
            cid,
            cose_ticket: vec![0xde, 0xad, 0xbe, 0xef],
            guardian: None,
        }
    }

    fn sample_infra_handle() -> CvmHandle {
        CvmHandle {
            vm_id: VmId::new("host-attestor").unwrap(),
            profile: DomainProfile::Infra,
            domain_id: DomainId::new("hippius-infra-host-attestor").unwrap(),
            domain_uuid: DomainUuid::generate().unwrap(),
            phase: CvmPhase::Running,
            launch_digest: [9u8; LAUNCH_DIGEST_LEN],
            cpu_count: 1,
            memory_mb: 512,
            data_disk_size_gb: 0,
            luks_disk_path: PathBuf::new(),
            cid: 0,
            cose_ticket: Vec::new(),
            guardian: None,
        }
    }

    const GUARDIAN_EP: &str = "100.64.3.4:7443";

    fn sample_route() -> super::super::guardian::GuardianRoute {
        let pk = "ab".repeat(32);
        super::super::guardian::GuardianRoute {
            endpoint: GUARDIAN_EP.into(),
            recipe: hippius_types::guardian::LaunchRecipe {
                ovmf_sha384: vec![1; 48],
                kernel_sha256: vec![2; 32],
                initrd_sha256: vec![3; 32],
                cmdline: format!(
                    "console=hvc0 hippius.key_mode=split hippius.guardian_pk={pk} \
                     hippius.guardian_ep={}",
                    hex::encode(GUARDIAN_EP)
                ),
                vcpus: 4,
                vcpu_type: "EpycTurin".into(),
                guest_features: 1,
            },
        }
    }

    #[test]
    fn boot_facts_read_the_exact_measured_inputs() {
        let xml = "<domain><vcpu>2</vcpu><memory unit='MiB'>512</memory><os>\n    \
                   <type>hvm</type>\n    <loader type='rom'> /x/ovmf.fd </loader>\n    \
                   <kernel>/x/vmlinuz</kernel>\n    <initrd>/x/in&amp;itrd</initrd>\n    \
                   <cmdline> a&lt;b hippius.key_mode=split </cmdline>\n  </os></domain>";
        let b = parse_domain_facts(xml).unwrap().boot.unwrap();
        assert_eq!(b.ovmf, PathBuf::from("/x/ovmf.fd"));
        assert_eq!(b.kernel, PathBuf::from("/x/vmlinuz"));
        assert_eq!(b.initrd, PathBuf::from("/x/in&itrd"));
        // Unescaped but NOT trimmed: the exact string QEMU measured.
        assert_eq!(b.cmdline, " a<b hippius.key_mode=split ");
        assert!(!format!("{b:?}").contains("key_mode"));
        for missing in ["loader", "kernel", "initrd", "cmdline"] {
            let cut = xml.replace(&format!("<{missing}"), &format!("<x{missing}"));
            assert!(
                parse_domain_facts(&cut).unwrap().boot.is_none(),
                "{missing}"
            );
        }
        let empty = xml.replace("<kernel>/x/vmlinuz</kernel>", "<kernel> </kernel>");
        assert!(parse_domain_facts(&empty).unwrap().boot.is_none());
    }

    #[test]
    fn a_guardian_route_survives_persist_and_readopt() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = sample_handle("guarded-1", 6);
        h.guardian = Some(sample_route());
        persist(dir.path(), &h).unwrap();
        let rebuilt = list(dir.path()).pop().unwrap().into_handle().unwrap();
        assert_eq!(rebuilt.guardian, Some(sample_route()));
    }

    #[test]
    fn an_m0_snapshot_carries_no_guardian_keys() {
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &sample_handle("m0-1", 5)).unwrap();
        let raw = std::fs::read_to_string(snapshot_path(dir.path(), "m0-1")).unwrap();
        assert!(!raw.contains("guardian"), "{raw}");
        let rebuilt = list(dir.path()).pop().unwrap().into_handle().unwrap();
        assert!(rebuilt.guardian.is_none());
    }

    #[test]
    fn a_damaged_guardian_route_is_dropped_but_the_vm_is_readopted() {
        let good = {
            let mut h = sample_handle("guarded-2", 7);
            h.guardian = Some(sample_route());
            PersistedHandle::from(&h)
        };
        // Endpoint no longer the one the recipe's cmdline pins.
        let mut other_ep = good.clone();
        other_ep.guardian_ep = Some("100.64.3.5:7443".into());
        // Only one of the two keys.
        let mut partial = good.clone();
        partial.guardian_recipe_cbor_hex = None;
        // Recipe bytes not hex / not canonical CBOR.
        let mut garbage = good.clone();
        garbage.guardian_recipe_cbor_hex = Some("zz".into());
        let mut not_cbor = good.clone();
        not_cbor.guardian_recipe_cbor_hex = Some("00ff".into());
        for ph in [other_ep, partial, garbage, not_cbor] {
            let h = ph.into_handle().unwrap();
            assert_eq!(h.vm_id.as_str(), "guarded-2");
            assert!(h.guardian.is_none());
        }
        assert!(good.into_handle().unwrap().guardian.is_some());
    }

    #[test]
    fn persist_list_roundtrip_reconstructs_the_handle() {
        let dir = tempfile::tempdir().unwrap();
        let h = sample_handle("smoke-1", 5);
        persist(dir.path(), &h).unwrap();

        let listed = list(dir.path());
        assert_eq!(listed.len(), 1);
        let rebuilt = listed.into_iter().next().unwrap().into_handle().unwrap();
        assert_eq!(rebuilt.vm_id.as_str(), "smoke-1");
        assert_eq!(rebuilt.domain_id.as_str(), "hippius-tenant-smoke-1");
        assert_eq!(rebuilt.domain_uuid.as_str(), h.domain_uuid.as_str());
        assert_eq!(rebuilt.launch_digest, [7u8; LAUNCH_DIGEST_LEN]);
        assert_eq!(rebuilt.cpu_count, 4);
        assert_eq!(rebuilt.memory_mb, 8192);
        assert_eq!(rebuilt.data_disk_size_gb, 32);
        assert_eq!(rebuilt.cid, 5);
        assert_eq!(rebuilt.cose_ticket, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(rebuilt.phase, CvmPhase::Running);
        // A tenant snapshot round-trips as `Tenant` (is_infra defaulted).
        assert_eq!(rebuilt.profile, DomainProfile::Tenant);
        assert!(!rebuilt.is_infra());
    }

    #[test]
    fn infra_is_infra_survives_the_persist_roundtrip() {
        // PR-7: the singleton Infra host-attestor snapshot must re-adopt
        // AS infra, so re-adopt skips CID reservation + tenant accounting.
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &sample_infra_handle()).unwrap();
        let rebuilt = list(dir.path())
            .into_iter()
            .next()
            .unwrap()
            .into_handle()
            .unwrap();
        assert!(rebuilt.is_infra());
        assert_eq!(rebuilt.profile, DomainProfile::Infra);
        assert_eq!(rebuilt.vm_id.as_str(), "host-attestor");
    }

    #[test]
    fn a_pre_pr7_snapshot_without_is_infra_deserializes_as_tenant() {
        // Forward-compat: a snapshot written before PR-7 has no
        // `is_infra` key; `#[serde(default)]` must read it as a tenant.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(ADOPT_SUBDIR)).unwrap();
        let legacy = r#"{
            "vm_id": "legacy-1",
            "domain_id": "hippius-tenant-legacy-1",
            "domain_uuid": "11111111-2222-4333-8444-555555555555",
            "launch_digest_hex": "00",
            "cpu_count": 2,
            "memory_mb": 2048,
            "data_disk_size_gb": 0,
            "luks_disk_path": "/var/lib/hippius-miner/data/legacy-1.img",
            "cid": 7,
            "cose_ticket_hex": ""
        }"#;
        std::fs::write(dir.path().join(ADOPT_SUBDIR).join("legacy-1.json"), legacy).unwrap();
        let ph = list(dir.path()).into_iter().next().unwrap();
        assert!(!ph.is_infra);
    }

    #[test]
    fn forget_removes_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let h = sample_handle("smoke-2", 6);
        persist(dir.path(), &h).unwrap();
        assert_eq!(list(dir.path()).len(), 1);
        forget(dir.path(), "smoke-2");
        assert!(list(dir.path()).is_empty());
    }

    #[test]
    fn list_skips_a_corrupt_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        persist(dir.path(), &sample_handle("good", 5)).unwrap();
        std::fs::create_dir_all(dir.path().join(ADOPT_SUBDIR)).unwrap();
        std::fs::write(dir.path().join(ADOPT_SUBDIR).join("bad.json"), b"{not json").unwrap();
        // The good one still parses; the corrupt one is skipped.
        assert_eq!(list(dir.path()).len(), 1);
    }

    #[test]
    fn forget_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        forget(dir.path(), "never-existed"); // no panic, no error
    }

    // ── Domain-XML facts (the libvirt ground truth) ──────────────────

    /// A verbatim excerpt of `virsh dumpxml` for the live golden tenant
    /// on a live miner (2026-08-13). Captured from production so the parser
    /// is tested against libvirt's OWN normalised output — `unit='KiB'`,
    /// injected `<alias>`/`<address>` elements, `<memoryBacking>` sitting
    /// right after `<memory>` — and not merely against the template the
    /// agent writes.
    const LIVE_DUMPXML: &str = r#"<domain type='kvm' id='72'>
  <name>hippius-tenant-legacy-tenant-1</name>
  <uuid>60db1561-e0ed-4ae9-8ab6-216632684de2</uuid>
  <memory unit='KiB'>2097152</memory>
  <currentMemory unit='KiB'>2097152</currentMemory>
  <memoryBacking>
    <source type='memfd'/>
    <access mode='shared'/>
  </memoryBacking>
  <vcpu placement='static'>1</vcpu>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/overlay/legacy-tenant-1.img' index='4'/>
      <target dev='vda' bus='virtio'/>
      <alias name='virtio-disk0'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/staging/legacy-tenant-1/rootfs.img' index='3'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source file='/var/lib/hippius-miner/state/legacy-tenant-1.raw' index='1'/>
      <target dev='vdd' bus='virtio'/>
    </disk>
    <vsock model='virtio'>
      <cid auto='no' address='16'/>
      <alias name='vsock0'/>
      <address type='pci' domain='0x0000' bus='0x07' slot='0x00' function='0x0'/>
    </vsock>
  </devices>
</domain>
"#;

    #[test]
    fn parses_the_live_production_dumpxml() {
        let f = parse_domain_facts(LIVE_DUMPXML).unwrap();
        assert_eq!(f.vcpus, 1);
        // 2097152 KiB == 2048 MiB — exactly what the sidecar records.
        assert_eq!(f.memory_mib, 2048);
        assert_eq!(f.cid, Some(16));
        assert_eq!(
            f.writable_disk,
            Some(PathBuf::from(
                "/var/lib/hippius-miner/overlay/legacy-tenant-1.img"
            )),
            "the vda source is the per-VM writable overlay, never vdb/vdd"
        );
        assert_eq!(
            f.domain_uuid.map(|u| u.as_str().to_string()),
            Some("60db1561-e0ed-4ae9-8ab6-216632684de2".to_string())
        );
    }

    #[test]
    fn memory_element_is_not_confused_with_memory_backing() {
        // `<memoryBacking>` shares the `<memory` prefix. A substring
        // search that does not require the element NAME to end reads the
        // wrong element and mis-sizes RAM. Assert on a document where
        // `<memoryBacking>` comes FIRST, so prefix confusion cannot hide
        // behind document order.
        let xml = "<domain>\
                   <memoryBacking><source type='memfd'/></memoryBacking>\
                   <memory unit='KiB'>2097152</memory>\
                   <vcpu placement='static'>1</vcpu></domain>";
        assert_eq!(parse_domain_facts(xml).unwrap().memory_mib, 2048);
        assert_eq!(parse_domain_facts(LIVE_DUMPXML).unwrap().memory_mib, 2048);
    }

    #[test]
    fn parses_the_agents_own_mib_template() {
        // The agent's template writes MiB; libvirt normalises to KiB on
        // dumpxml. Both must land on the same number.
        let xml = "<domain><name>hippius-tenant-a</name>\
                   <memory unit='MiB'>4096</memory>\
                   <vcpu placement='static'>8</vcpu></domain>";
        let f = parse_domain_facts(xml).unwrap();
        assert_eq!(f.memory_mib, 4096);
        assert_eq!(f.vcpus, 8);
    }

    #[test]
    fn memory_units_convert_and_round_up() {
        assert_eq!(memory_to_mib(1, "GiB").unwrap(), 1024);
        assert_eq!(memory_to_mib(2_097_152, "KiB").unwrap(), 2048);
        assert_eq!(memory_to_mib(1_048_576, "bytes").unwrap(), 1);
        // A partial MiB rounds UP — never under-charge the budget.
        assert_eq!(memory_to_mib(1_048_577, "b").unwrap(), 2);
        assert_eq!(memory_to_mib(1, "MB").unwrap(), 1); // 10^6 B → 1 MiB (ceil)
    }

    #[test]
    fn an_unknown_memory_unit_fails_closed() {
        // Guessing would be wrong by 3+ orders of magnitude in either
        // direction; refuse instead.
        assert!(memory_to_mib(1, "furlongs").is_err());
        let xml = "<domain><memory unit='furlongs'>7</memory><vcpu>1</vcpu></domain>";
        assert!(parse_domain_facts(xml).is_err());
    }

    #[test]
    fn a_missing_unit_attribute_defaults_to_kib() {
        // libvirt's documented default. Reading it as MiB would
        // over-charge the budget 1024x and wedge every later launch.
        let xml = "<domain><memory>2097152</memory><vcpu>2</vcpu></domain>";
        assert_eq!(parse_domain_facts(xml).unwrap().memory_mib, 2048);
    }

    #[test]
    fn missing_or_zero_cpu_and_memory_fail_closed() {
        // A zero would be a SILENT under-charge of the capacity budget —
        // the exact defect re-adoption exists to prevent.
        for bad in [
            "<domain><vcpu>2</vcpu></domain>",                  // no memory
            "<domain><memory unit='MiB'>512</memory></domain>", // no vcpu
            "<domain><memory unit='MiB'>512</memory><vcpu>0</vcpu></domain>",
            "<domain><memory unit='MiB'>0</memory><vcpu>1</vcpu></domain>",
            "<domain><memory unit='MiB'>x</memory><vcpu>1</vcpu></domain>",
        ] {
            assert!(
                parse_domain_facts(bad).is_err(),
                "expected fail-closed for {bad}"
            );
        }
    }

    #[test]
    fn a_diskless_vsockless_domain_parses_with_none_optionals() {
        // The Infra host-attestor shape — required fields only.
        let xml = "<domain><memory unit='MiB'>512</memory><vcpu>1</vcpu></domain>";
        let f = parse_domain_facts(xml).unwrap();
        assert_eq!(f.cid, None);
        assert_eq!(f.writable_disk, None);
        assert_eq!(f.domain_uuid, None);
    }

    #[test]
    fn a_hostile_disk_path_round_trips_through_xml_escaping() {
        // The domain template escapes the path; adoption must unescape it
        // to the SAME bytes, or §24 destroy would unlink the wrong file.
        let hostile = "/var/lib/hippius-miner/overlay/a&b<c>'d\".img";
        let escaped = hostile
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&apos;")
            .replace('"', "&quot;");
        let xml = format!(
            "<domain><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>\
             <disk type='file' device='disk'><source file=\"{escaped}\"/>\
             <target dev='vda' bus='virtio'/></disk></devices></domain>"
        );
        assert_eq!(
            parse_domain_facts(&xml).unwrap().writable_disk,
            Some(PathBuf::from(hostile))
        );
    }

    #[test]
    fn the_writable_disk_is_vda_even_when_another_disk_comes_first() {
        // A golden domain carries vda (writable overlay), vdb/vdc (the
        // READ-ONLY dm-verity base) and vdd (the state disk). Taking "the
        // first disk" would hand §24 destroy the wrong file — deleting a
        // shared base image or the boot counter instead of this VM's
        // volume. Order the document adversarially: vdd, then vdb, then vda.
        let xml = "<domain><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>\
                   <disk type='file' device='disk'><source file='/m/state/x.raw'/>\
                   <target dev='vdd' bus='virtio'/></disk>\
                   <disk type='file' device='disk'><source file='/m/rootfs.img'/>\
                   <target dev='vdb' bus='virtio'/><readonly/></disk>\
                   <disk type='file' device='disk'><source file='/m/overlay/x.img'/>\
                   <target dev='vda' bus='virtio'/></disk>\
                   </devices></domain>";
        assert_eq!(
            parse_domain_facts(xml).unwrap().writable_disk,
            Some(PathBuf::from("/m/overlay/x.img"))
        );
    }

    #[test]
    fn the_cid_is_read_only_from_inside_the_vsock_element() {
        // A `<cid>` outside `<vsock>` must NOT be mistaken for the guest
        // context id — reserving the wrong CID mis-routes the billing
        // relay onto another tenant's frames.
        let xml = "<domain><memory unit='MiB'>512</memory><vcpu>1</vcpu>\
                   <metadata><cid address='999'/></metadata>\
                   <devices><vsock model='virtio'><cid auto='no' address='16'/></vsock></devices>\
                   </domain>";
        assert_eq!(parse_domain_facts(xml).unwrap().cid, Some(16));
    }
}
