//! Tenant SEV-SNP confidential-VM lifecycle.
//!
//! [`CvmLifecycle`] is the fail-closed state machine that provisions
//! and tears down tenant CVMs on this (untrusted) miner host. Its two
//! collaborators are injected so the whole machine is testable on any
//! host with no libvirt and no SEV hardware:
//!
//! - a [`LibvirtDriver`] — production [`VirshDriver`] / test
//!   [`MockLibvirtDriver`];
//! - a [`LaunchDigestComputer`] — production [`SevLaunchDigest`] /
//!   test [`MockLaunchDigest`].
//!
//! ## Launch ordering (fail-closed)
//!
//! `launch` computes the SEV-SNP pre-flight launch digest **before**
//! any `virsh` call: a digest failure aborts the launch with no
//! domain ever defined. It then defines + starts the domain and polls
//! for the running state; any failure tears the domain back down.
//!
//! ## Idempotency + accounting
//!
//! The `handles` map holds only *live* CVMs (a launch that fails is
//! rolled back and its slot freed). A second `launch` for a `VmId`
//! already live is refused (`AlreadyLaunched`) — never a double
//! spawn. Every launch is checked against the host CPU / memory
//! budget with overflow-safe arithmetic before it is admitted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

pub mod adopt;
pub mod cvm_handle;
pub mod data_disk;
pub mod golden;
pub mod infra;
pub mod launch_digest;
pub mod libvirt_driver;
pub mod preflight;
pub mod qemu_config;
pub mod reboot_watcher;
pub mod state_disk;
pub mod ticket_peek;

pub use cvm_handle::{CvmHandle, DomainProfile, DomainUuid, VmId};
pub use infra::{InfraDomainConfig, InfraLaunchOrder, INFRA_VM_ID};
#[cfg(feature = "snp")]
pub use launch_digest::compute_launch_digest_for_generation;
pub use launch_digest::{
    compute_launch_digest, LaunchDigestComputer, MockLaunchDigest, SevLaunchDigest,
};
pub use libvirt_driver::{DomainId, DomainState, LibvirtDriver, MockLibvirtDriver, VirshDriver};
pub use qemu_config::{load_cmdline, QemuConfig};

use crate::error::{MinerAgentError, Result};
use crate::orders::LaunchOrder;
use crate::vsock::peer::CidAllocator;
use cvm_handle::LAUNCH_DIGEST_LEN;

/// Default gap between domain-state polls.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Default number of domain-state polls before a launch / stop times
/// out (with the default interval, a 30-second window).
const DEFAULT_POLL_ATTEMPTS: u32 = 60;

/// How many times `run_domain` re-allocates a fresh guest-cid and retries
/// domain-create after a `failed to set guest cid: Address already in use`
/// (an orphan qemu holds the CID the allocator handed out). Small: real
/// hosts have at most a handful of leaked CIDs; each retry burns one.
const MAX_CID_COLLISION_RETRIES: u32 = 8;

/// The libvirt domain-name prefix every tenant CVM carries
/// (`hippius-tenant-<vm_id>`, see [`qemu_config::QemuConfig::domain_name`]).
/// Startup re-adoption enumerates on it to find live tenant domains.
pub const TENANT_DOMAIN_PREFIX: &str = "hippius-tenant-";

/// Size of `path` in whole GiB, rounded UP, for the capacity budget.
/// An unstattable file reads as 0 — the disk budget then under-counts by
/// this VM's share, which is the pre-existing behaviour for an untracked
/// VM and strictly better than inventing a number.
fn disk_size_gb(path: &std::path::Path) -> u32 {
    const GIB: u64 = 1024 * 1024 * 1024;
    let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    u32::try_from(bytes.div_ceil(GIB)).unwrap_or(u32::MAX)
}

/// Where a tenant CVM is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvmPhase {
    /// Order accepted, not yet being launched. Reserved for the MA-5
    /// serve-loop queue; the direct `launch` path never dwells here.
    Pending,
    /// Building the QEMU config and computing the pre-flight digest.
    LaunchPrep,
    /// The libvirt domain is being defined / started.
    Launching,
    /// The domain is active.
    Running,
    /// A graceful shutdown has been requested.
    Stopping,
    /// The domain has been destroyed.
    Stopped,
    /// The launch failed, or a runtime error was observed.
    Failed,
}

/// The outcome of a read-only tenant-domain liveness probe
/// ([`CvmLifecycle::tenant_domain_liveness`]) — used by the
/// reboot-recovery reconcile loop to ask "is this VM's domain
/// actually running right now?" without going through the `handles`
/// map or any lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLiveness {
    /// The domain is running (or in a running-adjacent state —
    /// blocked / paused / mid-shutdown / PM-suspended).
    Live,
    /// The domain is definitively down (shut off / crashed / no
    /// libvirt state) or was never defined.
    Down,
    /// Libvirt itself could not be reached — neither "live" nor
    /// "down" can be asserted. Callers must NOT treat this as down.
    Unknown,
}

/// The host CPU / memory budget the lifecycle accounts launches
/// against. A launch that would exceed either is refused.
#[derive(Debug, Clone, Copy)]
pub struct HostResources {
    /// Total vCPUs the host will allot to tenant CVMs.
    pub total_cpus: u32,
    /// Total MiB of RAM the host will allot to tenant CVMs.
    pub total_memory_mb: u64,
    /// Total GiB of tenant **data-disk** the host will allot. The
    /// operator's DECLARED capacity (`[host] cvm_disk_gb_budget`) — vali's
    /// scheduler reads the same number for proactive placement, and the
    /// miner reserves against it here so concurrent launches can't
    /// over-commit (the per-create `statvfs` in `data_disk` sees only
    /// CURRENT free space, which sparse disks under-report until the guest
    /// wipes them). 0 disables the disk reservation (cpu/mem still apply).
    pub total_disk_gb: u64,
}

/// The tenant-CVM lifecycle state machine.
pub struct CvmLifecycle {
    driver: Arc<dyn LibvirtDriver>,
    digest: Arc<dyn LaunchDigestComputer>,
    host: HostResources,
    handles: Mutex<HashMap<VmId, CvmHandle>>,
    /// AF_VSOCK context-id allocator (MA-4). Owned by the lifecycle so
    /// `new` keeps its signature: `launch` allocates a CID, `stop` /
    /// `destroy` release it. Shared with the vsock relay listener via
    /// [`Self::cid_allocator`].
    cids: Arc<CidAllocator>,
    poll_interval: Duration,
    poll_attempts: u32,
    /// Phase 2B of audit follow-up Codex #2 — root directory under
    /// which [`state_disk::ensure_state_disk`] creates per-VM 1 MiB
    /// ext4 files (`{root}/state/{vm_id}.raw`).
    ///
    /// Production: [`qemu_config::MINER_ROOT`]. Tests override via
    /// [`Self::with_state_disk_root`] so the integration tests don't
    /// require root on `/var/lib/hippius-miner` (which they cannot
    /// have on a CI runner).
    state_disk_root: std::path::PathBuf,
    /// Test escape hatch: when `true`, skip the actual `mkfs.ext4`
    /// call in `launch`. The state-disk path on the QemuConfig still
    /// points at a (non-existent) file but the libvirt define is
    /// mocked so it never tries to attach the disk. This keeps the
    /// 20+ integration tests around lifecycle semantics independent
    /// of `mkfs.ext4` availability + filesystem side effects.
    /// Production NEVER sets this to true; the real `state_disk`
    /// module tests cover the actual mkfs path.
    ///
    /// The same flag gates the #365 data-disk `set_len` side effect in
    /// `launch` — the mock-libvirt lifecycle tests want neither host
    /// disk touched.
    skip_state_disk_provision: bool,
    /// #365 — root directory under which [`data_disk::ensure_data_disk`]
    /// creates the per-VM blank data disk (`{root}/data/{vm_id}.img`).
    /// Production: [`qemu_config::MINER_ROOT`], the same root the
    /// libvirt XML and the state disk agree on. Tests override via
    /// [`Self::with_state_disk_root`] (which sets both roots in
    /// lockstep) so the integration suite runs without root on
    /// `/var/lib/hippius-miner`.
    data_disk_root: std::path::PathBuf,
    /// Optional display-only guest-boot progress sink. When present, a
    /// successful domain start ([`Self::run_domain`]) fires a fire-and-
    /// forget `booting` milestone for the launching VM so vali's
    /// `boot_phase` can show `booting → kek-released → running`. Fail-
    /// open: absent ⇒ no reporting; a send error is logged and dropped
    /// so it can NEVER affect the launch result (see
    /// [`crate::vsock::vm_progress`]). Mirrors the `kek-released` emit
    /// the kbs-proxy fires on a successful KBS release.
    progress: Option<Arc<dyn crate::vsock::VmProgressSink>>,
}

impl CvmLifecycle {
    /// Construct a lifecycle over `driver` + `digest`, accounting
    /// launches against `host`, with the default poll window.
    pub fn new(
        driver: Arc<dyn LibvirtDriver>,
        digest: Arc<dyn LaunchDigestComputer>,
        host: HostResources,
    ) -> Self {
        Self::new_with_poll(
            driver,
            digest,
            host,
            DEFAULT_POLL_INTERVAL,
            DEFAULT_POLL_ATTEMPTS,
        )
    }

    /// As [`Self::new`] but with an explicit poll window — tests use a
    /// tiny interval so the launch / stop timeout paths run fast.
    pub fn new_with_poll(
        driver: Arc<dyn LibvirtDriver>,
        digest: Arc<dyn LaunchDigestComputer>,
        host: HostResources,
        poll_interval: Duration,
        poll_attempts: u32,
    ) -> Self {
        Self {
            driver,
            digest,
            host,
            handles: Mutex::new(HashMap::new()),
            cids: Arc::new(CidAllocator::new()),
            poll_interval,
            poll_attempts,
            state_disk_root: std::path::PathBuf::from(qemu_config::MINER_ROOT),
            skip_state_disk_provision: false,
            data_disk_root: std::path::PathBuf::from(qemu_config::MINER_ROOT),
            progress: None,
        }
    }

    /// Test escape hatch: skip the actual `mkfs.ext4` invocation in
    /// `launch`. Used by the 20+ lifecycle integration tests that
    /// model libvirt + digest behavior — they don't care about
    /// state-disk plumbing and shouldn't be forced to mkfs ~20
    /// disposable ext4 files. The `state_disk_path` on the
    /// QemuConfig still renders into the libvirt XML; with the
    /// `MockLibvirtDriver` the XML is never executed, so the
    /// missing file is irrelevant.
    pub fn skip_state_disk_provision_for_tests(mut self) -> Self {
        self.skip_state_disk_provision = true;
        self
    }

    /// Override the per-VM state-disk root directory (Phase 2B).
    /// Production should NEVER call this — the default points at
    /// [`qemu_config::MINER_ROOT`] which is where the libvirt /
    /// keyscript / miner-agent triple all agree the disk lives.
    /// Tests use a `tempfile::TempDir` so the integration suite
    /// runs without root on `/var/lib/hippius-miner`.
    ///
    /// Builder-style by-value `mut self` matches the existing
    /// `new_with_poll` chain in test sites:
    /// `CvmLifecycle::new_with_poll(...).with_state_disk_root(tmp)`.
    pub fn with_state_disk_root(mut self, root: std::path::PathBuf) -> Self {
        self.data_disk_root = root.clone();
        self.state_disk_root = root;
        self
    }

    /// Point the per-VM DATA and STATE disk roots at operator-chosen
    /// directories (the `[storage]` config section). Defaults are
    /// [`qemu_config::MINER_ROOT`]; production wires this from config so
    /// tenant data can live on a dedicated mount (e.g. an NVMe RAID)
    /// without a code change. The `data/` and `state/` subdirs are still
    /// appended by `ensure_data_disk` / `ensure_state_disk`, and the
    /// security posture is unchanged (the guest fresh-`luksFormat`s the
    /// data disk with a guest-held key wherever the file lives).
    pub fn with_storage_roots(
        mut self,
        data_disk_root: std::path::PathBuf,
        state_disk_root: std::path::PathBuf,
    ) -> Self {
        self.data_disk_root = data_disk_root;
        self.state_disk_root = state_disk_root;
        self
    }

    /// Resolve the per-VM GOLDEN overlay-upper path
    /// (`<data_disk_root>/overlay/<vm_id>.img`) — the exact path
    /// [`Self::launch`] boots a golden VM's writable `/dev/vda` from
    /// (`golden::overlay_disk_path`, mirrored here so callers outside this
    /// module don't need the private `data_disk_root`). The §25 dest-
    /// activation writes the migrated overlay ciphertext HERE (not the
    /// order's generic `luks_disk_path`) so the golden launch's
    /// `ensure_overlay_disk` finds it already present and PRESERVES it
    /// (never reformats) → the guest `luksOpen`s the migrated data with the
    /// KBS-released KEK. Same idempotency the reboot-recovery relaunch relies on.
    pub fn golden_overlay_path(&self, vm_id: &VmId) -> std::path::PathBuf {
        golden::overlay_disk_path(&self.data_disk_root, vm_id)
    }

    /// Per-VM anti-rollback state-disk path (`<state_disk_root>/state/
    /// <vm_id>.raw`) — mirrored here for the same reason as
    /// [`Self::golden_overlay_path`]: callers outside this module cannot
    /// reach the private `state_disk_root`.
    ///
    /// §25 uses it on BOTH legs. The guest keeps its boot counter on this
    /// disk (`/hippius-state/boot-counter`, mounted from `/dev/vdd` by the
    /// initramfs keyscript) and submits `counter + 1` on every release;
    /// the KBS requires exactly `stored + 1` and refuses an omitted counter
    /// once it holds one (audit-H8). `ensure_state_disk` formats a BLANK
    /// disk whenever the file is absent — so a destination that did not
    /// receive the source's disk submits `1` against a KBS holding `N`, and
    /// the release is refused **before any Vault read**: the migrated guest
    /// never unlocks. Hence the source uploads this file and the dest
    /// restores it before booting.
    pub fn state_disk_path(&self, vm_id: &VmId) -> std::path::PathBuf {
        state_disk::state_disk_path(&self.state_disk_root, vm_id)
    }

    /// Per-VM staging dir (`<root>/staging/<vm_id>`) — the ONLY place this
    /// agent ever writes a boot artifact for `vm_id`.
    ///
    /// Production resolves to [`preflight::STAGING_ROOT`]`/<vm_id>`, byte
    /// for byte with the free function [`preflight::vm_staging_dir`] that
    /// the launch preflight and §24's reclaim use (pinned by a test). This
    /// method exists so the §25 dest-activation can redirect the order's
    /// staging destinations without the integration tests writing into the
    /// real `/var/lib/hippius-miner` — NOT so the layout can vary in
    /// production. §24 must always be able to re-derive a VM's footprint
    /// from its `vm_id` alone, including for VMs staged by older agents.
    pub fn vm_staging_dir(&self, vm_id: &VmId) -> std::path::PathBuf {
        self.state_disk_root.join("staging").join(vm_id.as_str())
    }

    /// Wire the display-only guest-boot progress sink (§K). Production
    /// passes the SAME [`crate::vsock::EdgeVmProgressSink`] the kbs-proxy
    /// uses for the `kek-released` milestone, so a single miner identity
    /// signs the whole `booting → kek-released → running` sequence over
    /// the shared Edge mTLS leg. `None` (the default) leaves boot-progress
    /// reporting off — fail-open, never launch-affecting. Tests inject a
    /// recording spy sink to assert the `booting` emit fires.
    pub fn with_progress_sink(
        mut self,
        progress: Option<Arc<dyn crate::vsock::VmProgressSink>>,
    ) -> Self {
        self.progress = progress;
        self
    }

    /// The AF_VSOCK context-id allocator (MA-4). The serve loop hands
    /// this `Arc` to the vsock relay listener so it can resolve an
    /// inbound connection's CID back to the tenant `VmId`.
    pub fn cid_allocator(&self) -> Arc<CidAllocator> {
        Arc::clone(&self.cids)
    }

    /// Provision and launch a tenant CVM from `order`.
    ///
    /// The pre-flight launch digest is computed before any `virsh`
    /// call; a failure anywhere rolls the domain back and frees the
    /// `VmId`. A second launch for a still-live `VmId` is refused.
    ///
    /// The AF_VSOCK context id (MA-4) is allocated **under the same
    /// lock that reserves the handle**, and only once the launch is
    /// genuinely admitted — a refused duplicate or an over-budget
    /// launch allocates no CID, so there is nothing to leak. A CID is
    /// released only when its domain is gone or was never created: a
    /// launch that reaches the `virsh` stage and then fails keeps the
    /// CID until the domain is *confirmed* down ([`Self::teardown_failed_launch`]),
    /// so a still-running domain's CID can never be handed to another
    /// tenant.
    pub async fn launch(&self, order: LaunchOrder) -> Result<VmId> {
        let vm_id = order.vm_id.clone();
        let domain_uuid = DomainUuid::generate()?;
        // Capture the COSE ticket bytes BEFORE moving the order into the
        // QemuConfig — cached in the handle so the reboot-watcher can
        // re-push it on every libvirt domain restart.
        let cose_ticket: Vec<u8> = order.cose_ticket.clone().into_vec();
        // #312 — refuse the launch if the L1-minted ticket's `flavor`
        // disagrees with the dispatcher's `cpu_count`. The §22
        // allowlist would catch this at KBS release time anyway (vcpus
        // is folded into the SNP launch_digest), but failing here saves
        // an entire guest boot + audit-log entry. The peek is a CBOR
        // decode of the COSE payload only — no L1 signature check, by
        // design (see `lifecycle::ticket_peek` doc-block).
        ticket_peek::enforce_flavor_matches_cpu_count(&cose_ticket, order.cpu_count)?;
        // Phase 2B of audit follow-up Codex #2 — compute the per-VM
        // state-disk path BEFORE constructing the QemuConfig. The path
        // is rooted under `self.state_disk_root` (defaults to
        // `MINER_ROOT`; tests override via [`Self::with_state_disk_root`]).
        // `ensure_state_disk` (just below, after capacity admission)
        // actually allocates + ext4-formats the file.
        let state_disk_path = state_disk::state_disk_path(&self.state_disk_root, &vm_id);

        // GOLDEN-mode (golden-bake PR4) is derived from the SNP-MEASURED
        // cmdline (`dm-verity.root=` present AND `hippius.luks_header_sha256=`
        // absent) — tamper-evident, consistent with vali's emitter, the
        // guest boot script, and the preflight. In golden mode the OS is
        // the SHARED read-only dm-verity base (vdb/vdc) and `/dev/vda` is a
        // BLANK per-VM guest-keyed overlay UPPER the miner derives + creates
        // itself (never a fetched qcow2), sized to the measured
        // `hippius.disk_gb` (== `data_disk_size_gb`). There is NO separate
        // `/dev/vde` in golden: the overlay upper IS the tenant writable
        // space. The LEGACY branch is byte-identical to the pre-golden code.
        let is_golden = golden::is_golden_cmdline(&order.cmdline);
        if is_golden && order.data_disk_size_gb == 0 {
            // The golden overlay upper is the root — it MUST have a size.
            return Err(MinerAgentError::LaunchInput("golden-disk-gb-zero"));
        }
        // The one per-VM writable disk reserved against the host budget:
        // golden's overlay UPPER (vda) OR legacy's data disk (vde) — both
        // sized `data_disk_size_gb`. Accounted identically so a golden VM
        // reserves its overlay just as a legacy VM reserves its data disk.
        let disk_budget_gb = order.data_disk_size_gb;

        // Disk fields differ by mode. `config.data_disk_size_gb` keeps the
        // LEGACY vde semantics (0 ⇒ no vde), so golden sets it 0 (no vde)
        // while `disk_budget_gb` above carries the overlay reservation.
        let (luks_disk_path, luks_disk_size_gb, data_disk_path, config_data_disk_size_gb) =
            if is_golden {
                (
                    // vda = the per-VM overlay upper, derived under the
                    // process-owned storage root (blank; created below).
                    golden::overlay_disk_path(&self.data_disk_root, &vm_id),
                    disk_budget_gb,
                    None,
                    0,
                )
            } else {
                // #365 — the per-VM tenant data disk (`/dev/vde`). Only
                // attached when the order carries a non-zero
                // `data_disk_size_gb`; a zero (older vali deploys, or a
                // flavor without a data disk) renders no vde and runs no
                // `set_len`. The file is allocated by `ensure_data_disk`
                // below, after capacity admission.
                let ddp = if order.data_disk_size_gb > 0 {
                    Some(data_disk::data_disk_path(&self.data_disk_root, &vm_id))
                } else {
                    None
                };
                (
                    order.luks_disk_path,
                    order.luks_disk_size_gb,
                    ddp,
                    order.data_disk_size_gb,
                )
            };
        let mut config = QemuConfig {
            vm_id: order.vm_id,
            domain_uuid,
            ovmf_path: order.ovmf_path,
            kernel_path: order.kernel_path,
            initrd_path: order.initrd_path,
            cmdline: order.cmdline,
            luks_disk_path,
            luks_disk_size_gb,
            rootfs_data_path: order.rootfs_data_path,
            rootfs_hash_path: order.rootfs_hash_path,
            state_disk_path,
            data_disk_path,
            data_disk_size_gb: config_data_disk_size_gb,
            cpu_count: order.cpu_count,
            memory_mb: order.memory_mb,
            golden: is_golden,
            // Placeholder — the real CID is assigned under the lock
            // below, before `to_libvirt_xml` ever runs.
            cid: crate::vsock::peer::MIN_GUEST_CID,
        };
        config.validate()?;
        let domain_id = config.domain_name()?;

        // ── Idempotent admission: reclaim a STALE handle ─────────────
        // A `handles` entry can linger for a `vm_id` whose domain is no
        // longer running — an out-of-band `virsh destroy`, a crash the
        // agent did not initiate, or a teardown that never reached its
        // eager handle-remove. Without this, the relaunch is rejected
        // `AlreadyLaunched` (which `handle_launch` maps to a false
        // "already-launched" no-op) even though NOTHING runs — the live
        // bug that previously forced an `hippius-miner-agent` restart to
        // clear. We reclaim the slot ONLY when libvirt DEFINITIVELY
        // reports the domain down or gone; a genuinely-live domain, or
        // any libvirt uncertainty (unreachable), is still refused —
        // fail-safe: never reclaim a slot whose tenant VM might still be
        // running. The reclaim reuses the failed-launch teardown (eager
        // handle-remove → confirm-down → undefine → conditional CID
        // release) so it cannot yank a CID from a racing relaunch.
        let lingering_domain = {
            let handles = self.lock_handles()?;
            handles.get(&vm_id).map(|h| h.domain_id.clone())
        };
        if let Some(existing) = lingering_domain {
            if self.handle_is_stale(&existing).await {
                self.teardown_failed_launch(&vm_id, &existing).await;
            } else {
                return Err(MinerAgentError::AlreadyLaunched);
            }
        }

        // Reserve the slot, check the host budget, AND allocate the CID
        // — all under one `handles` lock acquisition. The CID is taken
        // only once the launch is admitted: a refused duplicate or an
        // over-budget launch returns here having allocated nothing.
        {
            let mut handles = self.lock_handles()?;
            if handles.contains_key(&vm_id) {
                return Err(MinerAgentError::AlreadyLaunched);
            }
            check_capacity(
                &handles,
                self.host,
                config.cpu_count,
                config.memory_mb,
                // `disk_budget_gb` is the golden overlay upper OR the
                // legacy vde — both are the per-VM writable disk to
                // reserve. (For legacy it equals `config.data_disk_size_gb`.)
                disk_budget_gb,
            )?;
            config.cid = self.cids.allocate(&vm_id)?;
            handles.insert(
                vm_id.clone(),
                CvmHandle {
                    vm_id: vm_id.clone(),
                    profile: DomainProfile::Tenant,
                    domain_id: domain_id.clone(),
                    domain_uuid: config.domain_uuid.clone(),
                    phase: CvmPhase::LaunchPrep,
                    launch_digest: [0u8; LAUNCH_DIGEST_LEN],
                    cpu_count: config.cpu_count,
                    memory_mb: config.memory_mb,
                    // Account the reserved writable disk (overlay or vde)
                    // so concurrent launches + re-adoption sum consistently.
                    data_disk_size_gb: disk_budget_gb,
                    luks_disk_path: config.luks_disk_path.clone(),
                    cid: config.cid,
                    cose_ticket,
                },
            );
        }

        // Pre-flight launch digest — computed BEFORE any virsh call.
        // A digest failure unreserves the slot and releases the CID:
        // NO domain was ever defined, so the CID cannot be in use.
        let digest = match self.digest.compute(&config) {
            Ok(digest) => digest,
            Err(err) => {
                self.unreserve_handle(&vm_id);
                let _ = self.cids.release(&vm_id);
                return Err(err);
            }
        };
        // The launch digest is a public measurement, not a secret —
        // logging it is the §F audit trail (no VM memory / disk /
        // cmdline is ever logged).
        eprintln!(
            "hippius-miner-agent: cvm {vm_id} launch_digest={}",
            hex::encode(digest)
        );

        // Phase 2B of audit follow-up Codex #2 — provision the per-VM
        // 1 MiB ext4 state disk that backs the anti-rollback boot
        // counter. Idempotent: a second launch for the same `vm_id`
        // (after a stop) re-uses the existing file so the counter
        // survives. A failure here is fail-closed BEFORE any `virsh`
        // call, so no domain ever defines; we still unreserve the
        // slot + CID like the digest path above.
        //
        // The `skip_state_disk_provision` escape hatch is for the
        // lifecycle integration tests (`tests/lifecycle_test.rs`)
        // which model libvirt behavior with a mock driver and have
        // no interest in mkfs side effects.
        if !self.skip_state_disk_provision {
            if let Err(err) = state_disk::ensure_state_disk(&self.state_disk_root, &vm_id) {
                self.unreserve_handle(&vm_id);
                let _ = self.cids.release(&vm_id);
                return Err(err);
            }
            if is_golden {
                // GOLDEN (golden-bake PR4) — provision the BLANK per-VM
                // guest-keyed overlay UPPER (`/dev/vda`), sized to the
                // measured `disk_budget_gb`. The miner writes NO structure
                // or secret: a sparse extent the guest luksFormats with a
                // MK generated in-SNP (never leaves), keyslot wrapped by
                // the per-VM KBS KEK — exactly the `/dev/vde` discipline.
                // Idempotent (preserves a relaunched VM's overlay writes),
                // fail-closed BEFORE any `virsh` call.
                if let Err(err) =
                    golden::ensure_overlay_disk(&self.data_disk_root, &vm_id, disk_budget_gb)
                {
                    self.unreserve_handle(&vm_id);
                    let _ = self.cids.release(&vm_id);
                    return Err(err);
                }
            } else if config.data_disk_size_gb > 0 {
                // #365 — provision the blank sparse tenant data disk the
                // guest formats fresh at first boot (`/dev/vde`). Idempotent
                // (preserves a relaunched VM's data), fail-closed BEFORE any
                // `virsh` call. Only when the order requested one.
                if let Err(err) = data_disk::ensure_data_disk(
                    &self.data_disk_root,
                    &vm_id,
                    config.data_disk_size_gb,
                ) {
                    self.unreserve_handle(&vm_id);
                    let _ = self.cids.release(&vm_id);
                    return Err(err);
                }
            }
        }

        // From here a failure HAS entered the virsh stage, so the
        // rollback force-destroys the domain — which is this CVM's own.
        match self.run_domain(&mut config, &domain_id).await {
            Ok(()) => {
                // Promote the reservation to `Running` under the lock,
                // which is released before any further `.await`.
                let promoted = {
                    let mut handles = self.lock_handles()?;
                    match handles.get_mut(&vm_id) {
                        Some(handle) => {
                            handle.phase = CvmPhase::Running;
                            handle.launch_digest = digest;
                            true
                        }
                        None => false,
                    }
                };
                if promoted {
                    // Snapshot the now-live handle so an agent restart
                    // (with `skip_shutdown_teardown`) can re-adopt this
                    // running CVM — capacity, CID, relay + reboot-watcher.
                    // Best-effort: a persist failure only degrades future
                    // re-adoption, it must never fail an otherwise-good
                    // launch (the VM IS running). See `lifecycle::adopt`.
                    let snapshot = self
                        .lock_handles()
                        .ok()
                        .and_then(|h| h.get(&vm_id).cloned());
                    if let Some(handle) = snapshot {
                        if let Err(err) = adopt::persist(&self.state_disk_root, &handle) {
                            eprintln!(
                                "hippius-miner-agent: adopt-persist failed vm={vm_id} \
                                 (re-adoption after restart degraded): {err}"
                            );
                        }
                    }
                    Ok(vm_id)
                } else {
                    // The reservation vanished mid-launch — the
                    // phase-gated `stop` is meant to make this
                    // impossible. Force-destroy the domain just started
                    // and release the CID only on confirmed teardown.
                    self.teardown_failed_launch(&vm_id, &domain_id).await;
                    Err(MinerAgentError::LaunchFailed("handle-lost"))
                }
            }
            Err(err) => {
                // A failed launch is not a live CVM — drop the handle
                // so the `VmId` is free for a clean retry.
                self.teardown_failed_launch(&vm_id, &domain_id).await;
                Err(err)
            }
        }
    }

    /// Remove a tracked handle (a no-op if it is already gone). Also
    /// drops the re-adoption snapshot so a removed VM is never re-adopted
    /// after a restart (`forget` is idempotent — harmless if this vm was
    /// never persisted, e.g. a failed launch).
    fn unreserve_handle(&self, vm_id: &VmId) {
        if let Ok(mut handles) = self.lock_handles() {
            handles.remove(vm_id);
        }
        adopt::forget(&self.state_disk_root, vm_id.as_str());
    }

    /// Roll back a launch that reached the `virsh` stage: drop the
    /// handle EAGERLY (so a concurrent retry of the same `vm_id` is
    /// not refused as `AlreadyLaunched` while we're still awaiting
    /// libvirt), then force-destroy the domain, and release the CID
    /// **only** on positive proof the domain is down AND no retry has
    /// re-claimed the slot.
    ///
    /// True IFF libvirt DEFINITIVELY reports `domain_id` down or gone —
    /// the only condition under which a lingering `handles` entry may be
    /// reclaimed for a fresh launch (see the idempotent-admission block
    /// in [`Self::launch`]). Fail-safe: a live domain, or ANY libvirt
    /// uncertainty (unreachable), returns `false` so the launch is
    /// refused rather than risk destroying a running tenant VM.
    async fn handle_is_stale(&self, domain_id: &DomainId) -> bool {
        match self.driver.query_domain_state(domain_id).await {
            // Defined-but-not-running / crashed / stateless ⇒ reclaimable.
            Ok(DomainState::ShutOff | DomainState::Crashed | DomainState::NoState) => true,
            // Running / Blocked / Paused / Shutdown / PmSuspended ⇒ live.
            Ok(_) => false,
            // `domstate` errored: the domain may be GONE (undefined —
            // reclaimable) or libvirt may be UNREACHABLE (refuse). A
            // successful `list_domains` proves libvirt is reachable: if
            // the domain is absent from it, it is genuinely gone. A
            // failing list ⇒ unreachable ⇒ fail-safe refuse.
            Err(_) => match self.driver.list_domains().await {
                Ok(list) => !list.iter().any(|(id, _)| id == domain_id),
                Err(_) => false,
            },
        }
    }

    /// Ask libvirt whether the tenant domain for `vm_id` is actually
    /// running right now — a read-only liveness probe for the
    /// reboot-recovery reconcile loop (no lifecycle change, no
    /// `handles` lookup: this answers for a `vm_id` the agent may not
    /// even hold a live handle for, e.g. right after an agent
    /// restart).
    ///
    /// The domain id is derived the same deterministic way as
    /// [`qemu_config::QemuConfig::domain_name`]
    /// (`hippius-tenant-<vm_id>`).
    ///
    /// Unlike [`Self::handle_is_stale`] (which fail-safes an
    /// unreachable libvirt to "not stale" so a reclaim is refused),
    /// this method preserves the distinction as
    /// [`DomainLiveness::Unknown`] — the HTTP layer above needs to
    /// tell a definite "down" from "couldn't tell".
    pub async fn tenant_domain_liveness(&self, vm_id: &VmId) -> DomainLiveness {
        let domain_id = match DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str())) {
            Ok(id) => id,
            Err(_) => return DomainLiveness::Unknown,
        };
        self.domain_liveness(&domain_id).await
    }

    /// The same three-valued liveness probe as
    /// [`Self::tenant_domain_liveness`], for a domain id that is already
    /// known (the Infra attestor, or a re-adoption snapshot's recorded
    /// domain). Kept as ONE implementation so every caller inherits the
    /// same `Unknown`-is-not-`Down` discipline.
    async fn domain_liveness(&self, domain_id: &DomainId) -> DomainLiveness {
        match self.driver.query_domain_state(domain_id).await {
            Ok(
                DomainState::Running
                | DomainState::Blocked
                | DomainState::Paused
                | DomainState::Shutdown
                | DomainState::PmSuspended,
            ) => DomainLiveness::Live,
            Ok(DomainState::ShutOff | DomainState::Crashed | DomainState::NoState) => {
                DomainLiveness::Down
            }
            // `domstate` errored: the domain may be gone (undefined —
            // down) or libvirt may be unreachable (unknown). A
            // successful `list_domains` proves libvirt is reachable:
            // if the domain is absent from it, it is genuinely down.
            // A failing list ⇒ libvirt is genuinely unreachable.
            Err(_) => match self.driver.list_domains().await {
                Ok(list) => {
                    if list.iter().any(|(id, _)| id == domain_id) {
                        DomainLiveness::Live
                    } else {
                        DomainLiveness::Down
                    }
                }
                Err(_) => DomainLiveness::Unknown,
            },
        }
    }

    /// Why eager handle-remove
    /// -----------------------
    /// A launch that fails AFTER `run_domain` reached `virsh` returns
    /// to its caller (`handle_launch`) only when this function has
    /// `.await`ed both `destroy_domain` and `query_domain_state` —
    /// each a real subprocess on the production path (sub-second
    /// typically, longer under load). During that window, a quick
    /// operator retry would have observed the stale `handles` entry
    /// and been rejected as `AlreadyLaunched`. The handler maps
    /// `AlreadyLaunched` to `Ok("already-launched")`, so the retry
    /// looks like a successful no-op when in fact NOTHING is running
    /// — exactly the bug observed live (a domain in libvirt
    /// `shut off`, no CVM, retry blocked). Removing the handle BEFORE
    /// awaiting libvirt closes that race.
    ///
    /// Why conditional CID release
    /// ---------------------------
    /// Eager handle-remove + idempotent `CidAllocator::allocate` means
    /// a retry that races in here can immediately re-take the
    /// **same** `vm_id` slot AND re-allocate the **same** CID
    /// (allocate is idempotent per vm_id). Unconditionally releasing
    /// the CID after the late `destroy_domain` would yank the slot
    /// out from under the retry's still-live (or just-launched)
    /// domain and let a future allocation hand the same CID to a
    /// different tenant — a vsock cross-route. So before releasing,
    /// we re-check the handle map: if a fresh handle for `vm_id` is
    /// present, the slot is now owned by the retry and we leave the
    /// CID alone (the "leak, never reuse" §G discipline already
    /// quoted in this file).
    ///
    /// A domain whose teardown cannot be confirmed keeps its CID for
    /// the same reason — the CID range is 65k wide; leak is harmless,
    /// reuse-while-held is not.
    async fn teardown_failed_launch(&self, vm_id: &VmId, domain_id: &DomainId) {
        // ── Phase 1: free the in-process slot SYNCHRONOUSLY ──────────
        // The lock is acquired and released here, before any `.await`,
        // so a concurrent `launch(vm_id)` sees the empty slot the
        // moment this block returns. A poisoned lock means the agent
        // is wedged anyway — log loudly so the cause is visible in
        // the journal, and continue with the libvirt cleanup so a
        // future `virsh` poll can still see the domain go away.
        match self.lock_handles() {
            Ok(mut handles) => {
                handles.remove(vm_id);
            }
            Err(_) => {
                eprintln!(
                    "hippius-miner-agent: lifecycle: teardown_failed_launch: \
                     handles lock poisoned — vm {vm_id} may keep a stale entry"
                );
            }
        }

        // ── Phase 2: confirm the domain is down (async) ──────────────
        let destroyed = self.driver.destroy_domain(domain_id, false).await.is_ok();
        // If the force-destroy did not clearly succeed, confirm with
        // a state query. A query error is treated as "not confirmed
        // down" (it may mean libvirt is unreachable — the same fail-
        // closed reading `run_stop` applies). The query MUST precede
        // any `undefine` — undefine removes the domain record, after
        // which a state query returns "not found" and we'd no longer
        // be able to tell "vanished cleanly" from "libvirt down".
        let down = destroyed
            || matches!(
                self.driver.query_domain_state(domain_id).await,
                Ok(DomainState::ShutOff | DomainState::Crashed | DomainState::NoState)
            );

        // ── Phase 3: undefine the libvirt record ────────────────────
        // Only after the domain is confirmed down. Leaving a `shut off`
        // record behind would make the next launch of the same vm_id
        // fail with `domain already exists with uuid …`. Observed live
        // 2026-05-25 (workaround was a manual `virsh undefine` between
        // every dispatch). An undefine error here is logged but does
        // not fail the teardown — the VM is provably down; a stranded
        // record is a separate ops issue worth surfacing in the
        // journal, never a reason to keep the in-process slot.
        if down && self.driver.undefine_domain(domain_id).await.is_err() {
            eprintln!(
                "hippius-miner-agent: lifecycle: teardown_failed_launch: \
                 vm {vm_id} domain stayed defined after destroy — \
                 libvirt record may need a manual `virsh undefine`"
            );
        }

        // ── Phase 4: release the CID iff down AND no retry ──────────
        // Re-check the handle map under the lock: a retry that won
        // the slot has by now (re-)inserted its own handle for
        // `vm_id`. A poisoned lock fails safe — assume retry, skip
        // release.
        let retried = match self.lock_handles() {
            Ok(handles) => handles.contains_key(vm_id),
            Err(_) => true,
        };
        if down && !retried {
            let _ = self.cids.release(vm_id);
        }
    }

    /// The define → start → poll sequence. On `Ok` the domain is
    /// running; any `Err` leaves the caller to tear it down.
    ///
    /// Retries on a vsock-CID collision (`VsockCid("cid-in-use")` from
    /// `create_domain`): the kernel already had the pinned guest-cid bound
    /// by an ORPHAN qemu the allocator never tracked, so we BURN that CID,
    /// allocate a fresh one, rewrite the domain XML, undefine the stale
    /// definition, and retry — bounded by `MAX_CID_COLLISION_RETRIES`. The
    /// tracked handle's CID is updated in lockstep so the vsock relay
    /// routes to the right guest.
    async fn run_domain(&self, config: &mut QemuConfig, domain_id: &DomainId) -> Result<()> {
        self.set_phase(&config.vm_id, CvmPhase::Launching)?;
        let mut attempt = 0u32;
        loop {
            let xml = config.to_libvirt_xml();
            self.driver.define_domain(&xml).await?;
            match self.driver.create_domain(domain_id).await {
                Ok(()) => break,
                Err(MinerAgentError::VsockCid("cid-in-use"))
                    if attempt < MAX_CID_COLLISION_RETRIES =>
                {
                    attempt += 1;
                    let bad = config.cid;
                    let fresh = self.cids.burn_and_realloc(&config.vm_id, bad)?;
                    config.cid = fresh;
                    if let Ok(mut handles) = self.lock_handles() {
                        if let Some(handle) = handles.get_mut(&config.vm_id) {
                            handle.cid = fresh;
                        }
                    }
                    // Drop the stale definition (pinned the bad CID) so the
                    // next iteration redefines with the fresh-CID XML.
                    let _ = self.driver.undefine_domain(domain_id).await;
                    eprintln!(
                        "hippius-miner-agent: cvm {} guest-cid {} already in \
                         use (orphan qemu) — retrying with cid {} (attempt {})",
                        config.vm_id, bad, fresh, attempt
                    );
                }
                Err(err) => return Err(err),
            }
        }
        // Display-only, fail-open, NON-blocking boot-progress side-channel
        // (§K): `create_domain` just succeeded, so qemu is up and the
        // tenant guest is now BOOTING toward its §21 KBS release. Fire a
        // fire-and-forget `booting` milestone for this vm_id so vali's
        // `boot_phase` shows `booting → kek-released → running`. Spawned
        // detached so it can NEVER delay (or fail) the launch — a send
        // error is logged and dropped inside the sink. Absent sink ⇒ no-op.
        // `booting` ranks BELOW `kek-released` and vali's `boot_phase` is
        // monotonic, so it only shows when it arrives first — which it does,
        // firing at domain start, strictly BEFORE the guest releases the KEK.
        // Mirrors the `kek-released` emit in [`crate::vsock::kbs_proxy`].
        if let Some(sink) = self.progress.as_ref() {
            let sink = Arc::clone(sink);
            let vm_id = config.vm_id.as_str().to_string();
            tokio::spawn(async move {
                sink.report(
                    &vm_id,
                    hippius_types::vm_progress::VmProgressMilestone::Booting,
                )
                .await;
            });
        }
        self.await_running(domain_id).await?;
        Ok(())
    }

    /// Stop a tracked CVM. `graceful` asks for an ACPI shutdown and
    /// force-destroys only if the domain has not powered off within
    /// the poll window; otherwise the domain is force-destroyed at
    /// once. The handle is dropped on a clean stop.
    ///
    /// Only a CVM in `Running` (or already `Stopping`) may be stopped:
    /// while a launch is still in flight (`LaunchPrep` / `Launching`)
    /// that task owns teardown, so a concurrent stop is refused
    /// (`CvmBusy`) — it must not race the launch and leave an
    /// untracked running domain.
    pub async fn stop(&self, vm_id: &VmId, graceful: bool) -> Result<()> {
        let domain_id = {
            let mut handles = self.lock_handles()?;
            let handle = handles.get_mut(vm_id).ok_or(MinerAgentError::VmNotFound)?;
            match handle.phase {
                CvmPhase::Running | CvmPhase::Stopping => {}
                _ => return Err(MinerAgentError::CvmBusy),
            }
            handle.phase = CvmPhase::Stopping;
            handle.domain_id.clone()
        };

        let outcome = self.run_stop(&domain_id, graceful).await;
        if outcome.is_ok() {
            // The runtime is gone — drop the libvirt *record* too.
            // `run_stop`'s graceful-failure escalation makes its final
            // state-query the last thing that needs the domain to be
            // defined; undefining AFTER `run_stop` returns Ok preserves
            // that invariant. An undefine error is logged (a stranded
            // `shut off` record breaks the NEXT launch of the same
            // `vm_id` with `domain already exists with uuid …` —
            // observed live) but does not fail the stop itself.
            if self.driver.undefine_domain(&domain_id).await.is_err() {
                eprintln!(
                    "hippius-miner-agent: lifecycle: stop: \
                     vm {vm_id} domain stayed defined after a clean stop — \
                     libvirt record may need a manual `virsh undefine`"
                );
            }
            // Mark Stopped for any concurrent observer, then drop it.
            if let Ok(mut handles) = self.lock_handles() {
                if let Some(handle) = handles.get_mut(vm_id) {
                    handle.phase = CvmPhase::Stopped;
                }
                handles.remove(vm_id);
            }
            // The CVM is gone — free its AF_VSOCK CID for reuse + drop
            // the re-adoption snapshot so a restart never re-adopts it.
            let _ = self.cids.release(vm_id);
            adopt::forget(&self.state_disk_root, vm_id.as_str());
        }
        outcome
    }

    /// Destroy a CVM — force-stop it, then unlink its LUKS data disk.
    ///
    /// The §24 decommission step the miner performs: stop the domain
    /// and reclaim the disk **capacity**. Cryptographic erasure is the
    /// Vault KEK-destroy (vali's job, §24) — the miner only unlinks the
    /// ciphertext file; it never holds the key that makes the data
    /// readable. Idempotent: a `destroy` of a CVM the lifecycle is not
    /// tracking is a success no-op (§24 — "already destroyed for this
    /// exact `vm_id` ⇒ success, not error").
    pub async fn destroy(&self, vm_id: &VmId) -> Result<()> {
        // The handle carries the LEGACY disk path when we still track the
        // VM. It is OPTIONAL: §24 always sends a graceful `stop` ORDER
        // before the `destroy` order, and that stop drops the handle — so
        // by the time we get here the VM is normally untracked.
        //
        // This used to `return Ok(())` on a missing handle ("already gone
        // — idempotent success"), which made the whole reclaim below
        // UNREACHABLE on the normal §24 path while still reporting
        // `outcome=destroyed`. Every decommissioned VM leaked its 8 GB
        // overlay; ~882 GB had accumulated across three miners by
        // 2026-07-29. The comment above the old capture ("before `stop`
        // drops the handle") shows the intent — it anticipated our OWN
        // internal stop, not vali's external stop order arriving first.
        let handle_disk = {
            let handles = self.lock_handles()?;
            handles.get(vm_id).map(|h| h.luks_disk_path.clone())
        };

        // Assemble the per-VM footprint FIRST, and bail out BEFORE touching
        // libvirt when there is nothing here to reclaim.
        //
        // This is what keeps a MISROUTED destroy harmless. vali deliberately
        // aims the §24 force-stop at any miner that MIGHT hold a domain
        // (`destroy_target_miner_id`, #878), and `effects.py` documents —
        // by file and line — that a destroy which cannot find the VM must
        // be a no-op, or "this widened resolver becomes a §24-FAILURE
        // AMPLIFIER". Proving liveness unconditionally broke exactly that:
        // a merely-possible host whose libvirtd is down (or whose
        // `list_domains` lost a per-domain `domstate` race — it
        // `?`-propagates, so ANY domain vanishing mid-enumeration fails the
        // whole call, and a batch §24 makes that race wide and correlated)
        // would raise, the job would retry to its step timeout, and the VM
        // would pin in `Decommissioning` with no API-reachable recovery.
        //
        // "Nothing to reclaim ⇒ nothing to prove" restores the no-op by
        // CONSTRUCTION while keeping the liveness proof exactly where it
        // matters: on a host that really does hold this VM's disks.
        let mut files: Vec<std::path::PathBuf> = vec![
            self.golden_overlay_path(vm_id),
            crate::orders::migration::restore_marker_path(&self.golden_overlay_path(vm_id)),
            data_disk::data_disk_path(&self.data_disk_root, vm_id),
            state_disk::state_disk_path(&self.state_disk_root, vm_id),
        ];
        if let Some(d) = &handle_disk {
            // The legacy boot disk, plus ITS §25 restore marker — only
            // derivable when we still hold the handle that names it.
            files.push(d.clone());
            files.push(crate::orders::migration::restore_marker_path(d));
        }
        // §24 backward compatibility: derived from `vm_id` alone (via the
        // configured root, which production pins to `MINER_ROOT`), never
        // from a lifecycle record or an order field — so a VM staged by
        // ANY older agent is still reclaimable by this one.
        let staging = self.vm_staging_dir(vm_id);

        // `symlink_metadata`, not `exists()`: a per-VM staging entry that
        // is a DANGLING symlink is still a footprint this destroy owns and
        // must unlink (`exists()` traverses, so it reads `false` and the
        // no-op bail below would strand it). #880's rule — stat before you
        // trust — applied to the entry itself rather than its target.
        let mut anything = staging.symlink_metadata().is_ok();
        for f in &files {
            if !f.as_os_str().is_empty() && f.exists() {
                anything = true;
            }
        }
        if handle_disk.is_none() && !anything {
            // Never hosted here (or already reclaimed) — idempotent success.
            return Ok(());
        }

        if handle_disk.is_some() {
            // Tracked: force-stop through the handle. A concurrent stop
            // that already removed it (`VmNotFound`) is fine.
            match self.stop(vm_id, false).await {
                // `VmNotFound` is NOT proof the domain is down —
                // `teardown_failed_launch` removes the handle eagerly and
                // only then awaits `destroy_domain`, so a destroy that
                // lost that race lands here with the guest possibly still
                // up. The liveness proof BELOW is what covers it: do not
                // "optimize" that proof back inside this branch.
                Ok(()) | Err(MinerAgentError::VmNotFound) => {}
                Err(err) => return Err(err),
            }
        }

        // Prove the domain is DOWN before unlinking — on BOTH branches.
        //
        // The tracked branch needs it too: `teardown_failed_launch` removes
        // the handle EAGERLY and only then awaits `destroy_domain`, so a
        // destroy that lost that race sees `VmNotFound` from `stop` while
        // the domain may still be up. Treating that as "down either way"
        // would unlink under a live guest.
        //
        // `tenant_domain_liveness` already encodes the semantics we need
        // (and tries `domstate` first, falling back to `list_domains` only
        // when the domain is undefined) — reusing it also removes what
        // would have been a FOURTH hardcoded copy of the
        // `hippius-tenant-` prefix. `Unknown` is NOT down: fail closed.
        match self.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Down => {}
            DomainLiveness::Live | DomainLiveness::Unknown => {
                return Err(MinerAgentError::Destroy("domain-still-up"));
            }
        }

        // Unlink the footprint. A missing file is success (idempotent);
        // any other failure is surfaced so vali learns the reclaim is
        // incomplete.
        for path in files {
            if path.as_os_str().is_empty() {
                continue;
            }
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(MinerAgentError::Destroy("disk-remove")),
            }
        }
        // Staged boot artifacts (kernel / initrd / rootfs images fetched
        // for this VM) — a directory, hundreds of MB, and equally per-VM.
        // Best-effort: a failure here is disk space, not correctness, and
        // must not fail a decommission whose data death already happened.
        // The adopt snapshot is part of the footprint too. It self-heals
        // (`readopt_running` prunes a non-Running entry), but leaving it is
        // the same "footprint" sloppiness this fix exists to end.
        //
        // `reclaim_staging_dir`, NOT `remove_dir_all`: the staging ROOT
        // holds the shared `ovmf.fd` / `rootfs.img` / `rootfs.verity`
        // beside the per-VM directories, and a deployment may link those
        // shared artifacts INTO a per-VM directory. Deleting through such
        // a link would take out other tenants' running VMs. The helper
        // unlinks symlinks AS LINKS and refuses to recurse through a
        // per-VM directory that is itself a symlink.
        adopt::forget(&self.state_disk_root, vm_id.as_str());
        if !staging.as_os_str().is_empty() {
            if let Err(e) = preflight::reclaim_staging_dir(&staging) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "hippius-miner-agent: destroy: staging reclaim failed for \
                         vm={} (disk space only)",
                        vm_id.as_str()
                    );
                }
            }
        }
        Ok(())
    }

    /// `virsh shutdown`-then-wait-then-`destroy` for a graceful stop,
    /// or a single force `destroy`.
    ///
    /// The graceful path tolerates a guest that is already down: if
    /// the ACPI shutdown request or the power-off wait fails it
    /// escalates to a force destroy, and confirms the result with a
    /// final state query — succeeding only on positive proof the
    /// domain is down, so a libvirt outage can never make a stop
    /// falsely report success and drop a live CVM's handle.
    async fn run_stop(&self, domain_id: &DomainId, graceful: bool) -> Result<()> {
        if !graceful {
            return self.driver.destroy_domain(domain_id, false).await;
        }
        // Best-effort ACPI shutdown + power-off wait.
        if self.driver.destroy_domain(domain_id, true).await.is_ok()
            && self.await_shutoff(domain_id).await.is_ok()
        {
            return Ok(());
        }
        // Did not cleanly power off — escalate to a force destroy.
        if self.driver.destroy_domain(domain_id, false).await.is_ok() {
            return Ok(());
        }
        // The force destroy failed too. `run_stop` runs before any
        // `undefine_domain` (the caller in `stop` / `teardown_failed_
        // launch` issues that strictly after `run_stop` returns Ok),
        // so the domain is still defined here — a query *error*
        // therefore means libvirt itself is unreachable, not that the
        // VM is gone. Succeed only on a positive shut-off / crashed
        // reading; fail closed on anything else.
        match self.driver.query_domain_state(domain_id).await {
            Ok(DomainState::ShutOff | DomainState::Crashed | DomainState::NoState) => Ok(()),
            Ok(_) | Err(_) => Err(MinerAgentError::LaunchFailed("teardown")),
        }
    }

    /// Stop every tracked CVM gracefully — the SIGTERM teardown path.
    ///
    /// Every CVM is attempted even if an earlier one fails; an
    /// aggregate error is returned if any stop did not complete.
    pub async fn shutdown_all(&self) -> Result<()> {
        let vm_ids: Vec<VmId> = self.lock_handles()?.keys().cloned().collect();
        let mut any_failed = false;
        for vm_id in vm_ids {
            if self.stop(&vm_id, true).await.is_err() {
                any_failed = true;
            }
        }
        if any_failed {
            Err(MinerAgentError::LaunchFailed("teardown"))
        } else {
            Ok(())
        }
    }

    /// Re-adopt every tenant CVM that is still live on this host — the
    /// startup companion to `[host].skip_shutdown_teardown`.
    ///
    /// Called ONCE at agent start, before the orders server + reboot-
    /// watcher come up, so the fresh handle-map, capacity accounting, CID
    /// allocator, vsock (billing) relay and reboot-watcher all track a
    /// survivor exactly as if it had just launched. Returns the number
    /// adopted.
    ///
    /// ## Two passes, in this order
    ///
    /// 1. [`Self::readopt_from_snapshots`] — the persisted `adopt`
    ///    sidecars. These carry the one fact libvirt does NOT hold: the
    ///    vali-signed `cose_ticket`. Each is reconciled against the LIVE
    ///    domain XML before it is trusted for numbers.
    /// 2. [`Self::adopt_orphan_domains`] — every live `hippius-tenant-*`
    ///    domain that pass 1 did not account for. Reconstructed from
    ///    libvirt alone, so a lost/moved/unwritten sidecar can no longer
    ///    leave a running tenant invisible to the capacity gate. An
    ///    orphan is adopted WITHOUT a ticket (see that method's docs) —
    ///    it is counted, never acted upon.
    ///
    /// ## What adoption may and may not grant
    ///
    /// Adoption rebuilds the agent's OWN bookkeeping and nothing else. It
    /// cannot conjure an authorised VM: releasing a KEK still requires an
    /// SEV-SNP attestation at an allowlisted measurement plus the
    /// anti-rollback boot counter, and a `cose_ticket` is L1-signed by
    /// vali and unforgeable here. The one capability an adopted handle
    /// carries is the ticket re-push, and that is exactly why an orphan
    /// (no ticket) gets none.
    ///
    /// ## Fail-safe direction
    ///
    /// Snapshots are pruned ONLY on a DEFINITE `Down` reading. If libvirt
    /// cannot be reached, the sidecar is KEPT and the VM is skipped this
    /// lifetime: an un-adopted VM is recoverable on the next start, a
    /// deleted ticket is gone forever (nothing on the host can re-mint
    /// it), so uncertainty must never delete.
    ///
    /// Idempotent + fail-open: a per-VM error skips that VM (logged) and
    /// never aborts the rest — a re-adoption gap degrades tracking, it
    /// must not stop the agent from serving.
    pub async fn readopt_running(&self) -> Result<usize> {
        let from_snapshots = self.readopt_from_snapshots().await?;
        let orphans = self.adopt_orphan_domains().await?;
        Ok(from_snapshots + orphans)
    }

    /// Pass 1 — re-adopt from the persisted `adopt` sidecars.
    async fn readopt_from_snapshots(&self) -> Result<usize> {
        let snapshots = adopt::list(&self.state_disk_root);
        let mut adopted = 0usize;
        for snapshot in snapshots {
            let vm_id_str = snapshot.vm_id.clone();
            let mut handle = match snapshot.into_handle() {
                Ok(h) => h,
                Err(err) => {
                    // Undecodable: there is no ticket to preserve and no
                    // resources to charge, so the file is pure noise. The
                    // orphan sweep still accounts for the domain if it is live.
                    eprintln!(
                        "hippius-miner-agent: re-adopt: pruning corrupt snapshot vm={vm_id_str}: {err}"
                    );
                    adopt::forget(&self.state_disk_root, &vm_id_str);
                    continue;
                }
            };
            // Is the domain the snapshot names still live? THREE-valued:
            // `Unknown` (libvirt unreachable) must NOT delete the sidecar —
            // it holds the only copy of the vali-signed ticket.
            match self.domain_liveness(&handle.domain_id).await {
                DomainLiveness::Live => {}
                DomainLiveness::Down => {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: pruning stale snapshot vm={vm_id_str} \
                         (domain definitively down)"
                    );
                    adopt::forget(&self.state_disk_root, &vm_id_str);
                    continue;
                }
                DomainLiveness::Unknown => {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm_id_str} libvirt UNREACHABLE — \
                         snapshot RETAINED, VM not tracked this lifetime (restart the agent \
                         once libvirtd is up to re-adopt it)"
                    );
                    continue;
                }
            }
            // Reconcile the sidecar against what libvirt actually runs.
            // The file is miner-local state and can be stale or edited;
            // the domain XML is the ground truth for the numbers.
            self.reconcile_handle_with_libvirt(&mut handle).await;

            let cid = handle.cid;
            let is_infra = handle.is_infra();
            // Reserve the exact CID the running guest already uses so the
            // vsock relay routes correctly after a `skip_shutdown_teardown`
            // restart. This covers BOTH tenant CVMs and — since PR-10b (S1)
            // — the Infra host-attestor, which now carries a real vsock CID.
            // A CID below `MIN_GUEST_CID` is a placeholder / ABI-reserved
            // value (e.g. a legacy pre-S1 Infra snapshot persisted `cid=0`);
            // it names no real vsock device, so we track it WITHOUT touching
            // the allocator (reserving 0/1/2 would fail `reserve-out-of-range`).
            {
                let mut handles = self.lock_handles()?;
                if handles.contains_key(&handle.vm_id) {
                    // Already tracked (a second call, or a race) — nothing to do.
                    // Re-inserting would double-count nothing (the map is keyed
                    // by vm_id) but would clobber a live handle with a snapshot.
                    continue;
                }
                if cid >= crate::vsock::peer::MIN_GUEST_CID {
                    if let Err(err) = self.cids.reserve(&handle.vm_id, cid) {
                        eprintln!(
                            "hippius-miner-agent: re-adopt: CID {cid} for vm={vm_id_str} \
                             unavailable ({err}) — NOT tracked"
                        );
                        continue;
                    }
                }
                handles.insert(handle.vm_id.clone(), handle);
            }
            if is_infra {
                eprintln!(
                    "hippius-miner-agent: re-adopt: infra vm={vm_id_str} — tracked \
                     (host-attestor supervised)"
                );
            } else {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm_id_str} cid={cid} — tracked \
                     (capacity + vsock relay + reboot-watcher restored)"
                );
            }
            adopted += 1;
        }
        Ok(adopted)
    }

    /// Correct a snapshot-rebuilt handle against the LIVE domain XML.
    ///
    /// The sidecar is a plain file under the miner root; the domain XML is
    /// what QEMU was actually started with. Where they disagree the XML
    /// wins, loudly, and each field for its own reason:
    ///
    /// - **cpu / memory** — take the LARGER. The capacity gate exists to
    ///   stop over-commit, so an under-charge is the harmful direction; a
    ///   sidecar claiming less RAM than the domain really has would let a
    ///   later launch oversubscribe the host.
    /// - **vsock CID** — take the XML's. The kernel has that CID bound to
    ///   this guest. Reserving the sidecar's stale value instead would
    ///   leave the real one free for the next launch, and then the running
    ///   guest's relayed frames — its billing receipts — would be
    ///   attributed to a DIFFERENT tenant.
    /// - **writable disk path** — take the XML's `vda` source. That is the
    ///   file this domain writes to, and the file §24 `destroy` unlinks;
    ///   a stale path would reclaim someone else's volume and leak this one.
    ///
    /// An unreadable/unparseable XML leaves the snapshot values in place:
    /// charging the recorded numbers is strictly better than charging
    /// nothing, which is what refusing to adopt would do.
    async fn reconcile_handle_with_libvirt(&self, handle: &mut CvmHandle) {
        let vm = handle.vm_id.as_str().to_string();
        let facts = match self.driver.domain_xml(&handle.domain_id).await {
            Ok(xml) => match adopt::parse_domain_facts(&xml) {
                Ok(facts) => facts,
                Err(err) => {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm} domain XML unparseable ({err}) — \
                         adopting the snapshot's recorded resources unchecked"
                    );
                    return;
                }
            },
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm} dumpxml failed ({err}) — \
                     adopting the snapshot's recorded resources unchecked"
                );
                return;
            }
        };
        if facts.vcpus != handle.cpu_count || facts.memory_mib != handle.memory_mb {
            eprintln!(
                "hippius-miner-agent: re-adopt: vm={vm} SNAPSHOT/XML DISAGREE on resources \
                 (snapshot {}c/{}MiB, libvirt {}c/{}MiB) — charging the larger of each",
                handle.cpu_count, handle.memory_mb, facts.vcpus, facts.memory_mib
            );
            handle.cpu_count = handle.cpu_count.max(facts.vcpus);
            handle.memory_mb = handle.memory_mb.max(facts.memory_mib);
        }
        if let Some(cid) = facts.cid {
            if cid != handle.cid {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm} SNAPSHOT/XML DISAGREE on vsock cid \
                     (snapshot {}, libvirt {cid}) — reserving the LIVE cid",
                    handle.cid
                );
                handle.cid = cid;
            }
        }
        if let Some(disk) = facts.writable_disk {
            if disk != handle.luks_disk_path {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm} SNAPSHOT/XML DISAGREE on the writable \
                     disk (snapshot {}, libvirt {}) — tracking the LIVE path",
                    handle.luks_disk_path.display(),
                    disk.display()
                );
                handle.luks_disk_path = disk;
            }
        }
    }

    /// Pass 2 — account for every live `hippius-tenant-*` domain that no
    /// sidecar covered.
    ///
    /// ## Why this pass exists
    ///
    /// The sidecar is written best-effort after a launch and can be
    /// missing for reasons that have nothing to do with the VM: the write
    /// failed, the directory was moved aside by an operator, the file was
    /// pruned by an earlier agent. Without this pass such a VM is
    /// INVISIBLE forever — its vCPUs and RAM are not charged (so the #668
    /// fit gate over-commits the host), its CID is free for the next
    /// launch to collide with, and the vsock relay rejects its frames as
    /// an `unknown-cid`, which stops its billing.
    ///
    /// ## What an orphan is granted: accounting only
    ///
    /// The one thing libvirt cannot give us is the vali-signed
    /// `cose_ticket`. An orphan is therefore adopted with an EMPTY ticket,
    /// which is load-bearing, not a placeholder: [`Self::ticket_for_vm`]
    /// returns `None`, so the reboot-watcher will neither re-push a ticket
    /// to it nor `virsh start` it back up. The agent counts it and relays
    /// for it; it never acts on its behalf. Nothing here can invent
    /// authority — a KEK release needs an SNP attestation the miner cannot
    /// forge, and the ticket needs vali's L1 signature.
    ///
    /// No sidecar is written for an orphan: this pass re-derives it from
    /// libvirt on every start, and persisting a ticketless record would
    /// make a recoverable degradation look permanent.
    ///
    /// Fail-closed per domain: if the XML cannot be read or parsed we do
    /// NOT invent resource numbers — a fabricated figure in the capacity
    /// budget is worse than a visible, logged gap.
    async fn adopt_orphan_domains(&self) -> Result<usize> {
        let domains = match self.driver.list_domains().await {
            Ok(domains) => domains,
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: re-adopt: orphan sweep skipped — \
                     libvirt list failed ({err})"
                );
                return Ok(0);
            }
        };
        let mut adopted = 0usize;
        for (domain_id, state) in domains {
            // Tenant domains only. The Infra attestor has its own snapshot
            // and its own supervisor; a foreign domain is not ours to count.
            let Some(vm_id) = domain_id
                .as_str()
                .strip_prefix(TENANT_DOMAIN_PREFIX)
                .and_then(|s| VmId::new(s).ok())
            else {
                continue;
            };
            // Live-adjacent states all hold host resources (a paused domain
            // still owns its RAM and its CID).
            if !matches!(
                state,
                DomainState::Running
                    | DomainState::Blocked
                    | DomainState::Paused
                    | DomainState::Shutdown
                    | DomainState::PmSuspended
            ) {
                continue;
            }
            if self.lock_handles()?.contains_key(&vm_id) {
                continue; // pass 1 already accounted for it
            }
            let facts = match self.driver.domain_xml(&domain_id).await {
                Ok(xml) => match adopt::parse_domain_facts(&xml) {
                    Ok(facts) => facts,
                    Err(err) => {
                        eprintln!(
                            "hippius-miner-agent: re-adopt: ORPHAN vm={vm_id} domain XML \
                             unparseable ({err}) — NOT tracked, its capacity is UNCOUNTED"
                        );
                        continue;
                    }
                },
                Err(err) => {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: ORPHAN vm={vm_id} dumpxml failed \
                         ({err}) — NOT tracked, its capacity is UNCOUNTED"
                    );
                    continue;
                }
            };
            // The domain UUID is only ever used to re-render XML; a domain
            // that already exists is never re-defined, so a missing one is
            // not fatal — but an unparseable one means we misread the
            // document, so refuse rather than guess.
            let domain_uuid = match facts.domain_uuid.clone() {
                Some(uuid) => uuid,
                None => match DomainUuid::generate() {
                    Ok(uuid) => uuid,
                    Err(_) => continue,
                },
            };
            let disk_gb = facts
                .writable_disk
                .as_ref()
                .map(|p| disk_size_gb(p))
                .unwrap_or(0);
            let cid = facts.cid.unwrap_or(0);
            {
                let mut handles = self.lock_handles()?;
                if handles.contains_key(&vm_id) {
                    continue;
                }
                if cid >= crate::vsock::peer::MIN_GUEST_CID {
                    if let Err(err) = self.cids.reserve(&vm_id, cid) {
                        eprintln!(
                            "hippius-miner-agent: re-adopt: ORPHAN vm={vm_id} CID {cid} \
                             unavailable ({err}) — NOT tracked, its capacity is UNCOUNTED"
                        );
                        continue;
                    }
                }
                handles.insert(
                    vm_id.clone(),
                    CvmHandle {
                        vm_id: vm_id.clone(),
                        profile: DomainProfile::Tenant,
                        domain_id: domain_id.clone(),
                        domain_uuid,
                        phase: CvmPhase::Running,
                        // Unknown — this VM was not launched in this
                        // process and its measurement is not recorded
                        // anywhere on the host. Never used as an assertion.
                        launch_digest: [0u8; LAUNCH_DIGEST_LEN],
                        cpu_count: facts.vcpus,
                        memory_mb: facts.memory_mib,
                        data_disk_size_gb: disk_gb,
                        luks_disk_path: facts.writable_disk.clone().unwrap_or_default(),
                        cid,
                        // NO TICKET: accounting only, no re-push, no restart.
                        cose_ticket: Vec::new(),
                    },
                );
            }
            eprintln!(
                "hippius-miner-agent: re-adopt: ORPHAN vm={vm_id} cid={cid} \
                 {}c/{}MiB/{}GiB — tracked from libvirt (capacity + vsock relay restored; \
                 NO ticket ⇒ no reboot re-push)",
                facts.vcpus, facts.memory_mib, disk_gb
            );
            adopted += 1;
        }
        Ok(adopted)
    }

    /// Launch (or relaunch) the singleton diskless **Infra** blackbox
    /// host-attestor CVM (PR-7).
    ///
    /// A completely separate path from the tenant [`Self::launch`]: it
    /// boots the measured blackbox UKI diskless (kernel + initrd-as-root),
    /// at a fixed 1 vCPU / 512 MiB, with NO data disk, NO KEK / OrderTicket
    /// / KBS-proxy. It DOES carry a vsock CID (allocated from the shared
    /// [`CidAllocator`], measurement-invisible) so the guest can reach the
    /// host over vsock. It is NOT charged against the tenant capacity budget
    /// and NOT counted in the tenant heartbeat.
    ///
    /// ## Fail-closed measurement pin
    ///
    /// Before any `virsh` call, the local SEV-SNP launch digest is
    /// recomputed over the exact UKI to be booted and asserted equal to
    /// `order.expected_measurement_hex`. A tampered local UKI cannot boot
    /// under the attestor identity — the launch is refused with no domain
    /// ever defined.
    ///
    /// Singleton + idempotent: a still-live host-attestor is refused
    /// (`AlreadyLaunched`); a lingering handle whose domain is gone is
    /// reclaimed (the same discipline as the tenant path).
    pub async fn launch_infra(&self, order: InfraLaunchOrder) -> Result<VmId> {
        let mut config = InfraDomainConfig::from_order(&order)?;
        // Validate + prime the host SNP probe BEFORE any digest / virsh.
        config.validate()?;
        let vm_id = config.vm_id.clone();
        let domain_id = config.domain_name()?;

        // Fail-closed measurement pin — recompute the digest over the UKI
        // we're about to boot and refuse on any disagreement. BEFORE the
        // slot is reserved or any domain is defined.
        let digest = self.digest.compute(&config.to_digest_qemu_config()?)?;
        assert_infra_measurement_pin(&digest, &order.expected_measurement_hex)?;
        eprintln!(
            "hippius-miner-agent: infra host-attestor launch_digest={} (pin OK)",
            hex::encode(digest)
        );

        // Idempotent admission: reclaim a stale infra handle whose domain
        // is definitively gone; refuse a genuinely-live singleton.
        let lingering = {
            let handles = self.lock_handles()?;
            handles.get(&vm_id).map(|h| h.domain_id.clone())
        };
        if let Some(existing) = lingering {
            if self.handle_is_stale(&existing).await {
                self.teardown_failed_launch(&vm_id, &existing).await;
            } else {
                return Err(MinerAgentError::AlreadyLaunched);
            }
        }

        // Reserve the singleton slot + allocate its AF_VSOCK CID (PR-10b,
        // S1) — both under one `handles` lock, exactly as the tenant path
        // does. NO capacity gate (Infra is carved out of the tenant budget).
        // The CID is idempotent per vm_id, so a reclaim-then-relaunch of the
        // singleton keeps the same CID. A failure past here releases it via
        // `teardown_failed_launch` (the CID cannot be in use unless a domain
        // was defined with it — the same discipline as `launch`).
        {
            let mut handles = self.lock_handles()?;
            if handles.contains_key(&vm_id) {
                return Err(MinerAgentError::AlreadyLaunched);
            }
            config.cid = self.cids.allocate(&vm_id)?;
            handles.insert(
                vm_id.clone(),
                CvmHandle {
                    vm_id: vm_id.clone(),
                    profile: DomainProfile::Infra,
                    domain_id: domain_id.clone(),
                    domain_uuid: config.domain_uuid.clone(),
                    phase: CvmPhase::LaunchPrep,
                    launch_digest: [0u8; LAUNCH_DIGEST_LEN],
                    cpu_count: infra::INFRA_CPU_COUNT,
                    memory_mb: infra::INFRA_MEMORY_MB,
                    data_disk_size_gb: 0,
                    // Diskless — no LUKS ciphertext to reclaim.
                    luks_disk_path: std::path::PathBuf::new(),
                    // The allocator-assigned vsock CID (S1) — pinned into the
                    // `<vsock>` device so the attestor guest can dial the host.
                    cid: config.cid,
                    cose_ticket: Vec::new(),
                },
            );
        }

        match self.run_infra_domain(&mut config, &domain_id).await {
            Ok(()) => {
                let promoted = {
                    let mut handles = self.lock_handles()?;
                    match handles.get_mut(&vm_id) {
                        Some(handle) => {
                            handle.phase = CvmPhase::Running;
                            handle.launch_digest = digest;
                            true
                        }
                        None => false,
                    }
                };
                if promoted {
                    // Persist so a restart re-adopts the running attestor
                    // (marked is_infra) — best-effort, never launch-fatal.
                    let snapshot = self
                        .lock_handles()
                        .ok()
                        .and_then(|h| h.get(&vm_id).cloned());
                    if let Some(handle) = snapshot {
                        if let Err(err) = adopt::persist(&self.state_disk_root, &handle) {
                            eprintln!(
                                "hippius-miner-agent: infra adopt-persist failed \
                                 (re-adoption after restart degraded): {err}"
                            );
                        }
                    }
                    Ok(vm_id)
                } else {
                    self.teardown_failed_launch(&vm_id, &domain_id).await;
                    Err(MinerAgentError::LaunchFailed("handle-lost"))
                }
            }
            Err(err) => {
                self.teardown_failed_launch(&vm_id, &domain_id).await;
                Err(err)
            }
        }
    }

    /// The Infra domain's define → start → poll sequence. No boot-progress
    /// sink (the attestor is not a tenant).
    ///
    /// Retries on a vsock-CID collision exactly like the tenant
    /// [`Self::run_domain`] (PR-10b, S1): now that the Infra domain carries
    /// a `<vsock>` device, an orphan qemu the allocator never tracked can
    /// hold the pinned guest-cid (`failed to set guest cid: Address already
    /// in use`). Without a retry the singleton's idempotent `allocate` would
    /// keep handing back the SAME colliding CID and wedge the supervisor, so
    /// we BURN the bad CID, re-allocate a fresh one, rewrite the XML,
    /// undefine the stale definition, and retry — bounded by
    /// [`MAX_CID_COLLISION_RETRIES`]. The tracked handle's CID is updated in
    /// lockstep so re-adoption pins the right value.
    async fn run_infra_domain(
        &self,
        config: &mut InfraDomainConfig,
        domain_id: &DomainId,
    ) -> Result<()> {
        self.set_phase(&config.vm_id, CvmPhase::Launching)?;
        let mut attempt = 0u32;
        loop {
            let xml = config.to_libvirt_xml();
            self.driver.define_domain(&xml).await?;
            match self.driver.create_domain(domain_id).await {
                Ok(()) => break,
                Err(MinerAgentError::VsockCid("cid-in-use"))
                    if attempt < MAX_CID_COLLISION_RETRIES =>
                {
                    attempt += 1;
                    let bad = config.cid;
                    let fresh = self.cids.burn_and_realloc(&config.vm_id, bad)?;
                    config.cid = fresh;
                    if let Ok(mut handles) = self.lock_handles() {
                        if let Some(handle) = handles.get_mut(&config.vm_id) {
                            handle.cid = fresh;
                        }
                    }
                    let _ = self.driver.undefine_domain(domain_id).await;
                    eprintln!(
                        "hippius-miner-agent: infra host-attestor guest-cid {bad} already \
                         in use (orphan qemu) — retrying with cid {fresh} (attempt {attempt})"
                    );
                }
                Err(err) => return Err(err),
            }
        }
        self.await_running(domain_id).await?;
        Ok(())
    }

    /// `true` iff the singleton Infra host-attestor is tracked, marked
    /// `Running`, AND libvirt confirms its domain is actually running.
    /// The supervision loop uses this to decide whether to (re)launch —
    /// a crashed / shut-off attestor reads `false` and is relaunched.
    pub async fn infra_is_running(&self) -> bool {
        let Ok(vm_id) = VmId::new(INFRA_VM_ID) else {
            return false;
        };
        let domain_id = match self.lock_handles() {
            Ok(handles) => match handles.get(&vm_id) {
                Some(h) if h.phase == CvmPhase::Running => h.domain_id.clone(),
                _ => return false,
            },
            Err(_) => return false,
        };
        matches!(
            self.driver.query_domain_state(&domain_id).await,
            Ok(DomainState::Running)
        )
    }

    /// The tracked [`CvmPhase`] of `vm_id`.
    pub async fn query(&self, vm_id: &VmId) -> Result<CvmPhase> {
        self.lock_handles()?
            .get(vm_id)
            .map(|handle| handle.phase)
            .ok_or(MinerAgentError::VmNotFound)
    }

    /// Every tracked CVM and its phase — tenant AND the singleton Infra
    /// host-attestor. Ops/debug surface; tenant-facing accounting uses
    /// [`Self::list_tenants`] instead.
    pub async fn list(&self) -> Result<Vec<(VmId, CvmPhase)>> {
        Ok(self
            .lock_handles()?
            .values()
            .map(|handle| (handle.vm_id.clone(), handle.phase))
            .collect())
    }

    /// Every tracked **tenant** CVM and its phase — the singleton Infra
    /// host-attestor is EXCLUDED. This is the tenant-facing enumeration:
    /// the §K heartbeat's `vm_count_*` (capacity / billing signal to vali)
    /// must never see the infra domain (blackbox attestor plan: "filtered
    /// from capacity/heartbeat/billing").
    pub async fn list_tenants(&self) -> Result<Vec<(VmId, CvmPhase)>> {
        Ok(self
            .lock_handles()?
            .values()
            .filter(|handle| !handle.is_infra())
            .map(|handle| (handle.vm_id.clone(), handle.phase))
            .collect())
    }

    /// Poll until the domain is running, or fail closed on a crashed /
    /// shut-off domain or the poll-window timeout.
    async fn await_running(&self, domain_id: &DomainId) -> Result<()> {
        for _ in 0..self.poll_attempts {
            match self.driver.query_domain_state(domain_id).await? {
                DomainState::Running => return Ok(()),
                DomainState::Crashed | DomainState::ShutOff => {
                    return Err(MinerAgentError::LaunchFailed("domain-error"));
                }
                _ => {}
            }
            tokio::time::sleep(self.poll_interval).await;
        }
        Err(MinerAgentError::LaunchFailed("timeout"))
    }

    /// Poll until the domain has powered off.
    async fn await_shutoff(&self, domain_id: &DomainId) -> Result<()> {
        for _ in 0..self.poll_attempts {
            match self.driver.query_domain_state(domain_id).await? {
                DomainState::ShutOff | DomainState::Crashed | DomainState::NoState => {
                    return Ok(());
                }
                _ => {}
            }
            tokio::time::sleep(self.poll_interval).await;
        }
        Err(MinerAgentError::LaunchFailed("timeout"))
    }

    /// Update a tracked handle's phase (a no-op if it is gone).
    fn set_phase(&self, vm_id: &VmId, phase: CvmPhase) -> Result<()> {
        if let Some(handle) = self.lock_handles()?.get_mut(vm_id) {
            handle.phase = phase;
        }
        Ok(())
    }

    /// Lock the handle map, mapping a poisoned lock to a fail-closed
    /// error rather than panicking.
    fn lock_handles(&self) -> Result<MutexGuard<'_, HashMap<VmId, CvmHandle>>> {
        self.handles
            .lock()
            .map_err(|_| MinerAgentError::LockPoisoned)
    }

    /// Read-only DATA-disk capacity check (no reservation) — the
    /// **preflight fail-fast**.
    ///
    /// A launch whose DATA disk would push the live total past the host's
    /// declared `total_disk_gb` budget is rejected at PREFLIGHT (before
    /// vali mints + KBS-registers the ticket), so vali can re-place onto
    /// another miner. The launch path still re-checks AND reserves under
    /// the `handles` lock (`check_capacity`) — that is the race-safe gate;
    /// this only moves the COMMON rejection earlier, into the window where
    /// vali's re-place actually works (a dispatch-time rejection lands
    /// after KBS-register and can't be cleanly re-placed). `0` budget
    /// disables the check, exactly like `check_capacity`.
    pub fn check_disk_budget(&self, add_disk_gb: u32) -> Result<()> {
        let handles = self.lock_handles()?;
        let mut used_disk: u64 = 0;
        for handle in handles.values() {
            // Infra is diskless — skip it (belt-and-suspenders; its
            // data_disk_size_gb is 0 anyway).
            if handle.is_infra() {
                continue;
            }
            used_disk = used_disk
                .checked_add(u64::from(handle.data_disk_size_gb))
                .ok_or(MinerAgentError::InsufficientResources)?;
        }
        let need_disk = used_disk
            .checked_add(u64::from(add_disk_gb))
            .ok_or(MinerAgentError::InsufficientResources)?;
        if self.host.total_disk_gb > 0 && need_disk > self.host.total_disk_gb {
            return Err(MinerAgentError::InsufficientResources);
        }
        Ok(())
    }

    /// Read-only CPU + memory capacity check (no reservation) — the
    /// **preflight fail-fast**, the cpu/mem twin of [`Self::check_disk_budget`].
    ///
    /// A launch whose vCPUs or RAM would push the live total past the
    /// host's `total_cpus` / `total_memory_mb` budget is rejected at
    /// PREFLIGHT (before vali mints + KBS-registers the ticket), so vali
    /// re-places onto another miner. Without this, a capacity-constrained
    /// miner accepted the preflight (only DATA-disk was gated there) and
    /// only rejected at LAUNCH — AFTER KBS-register — which vali cannot
    /// cleanly re-place (the vm_id→host binding is already fenced in the
    /// KBS, so the re-placement's register 409s `kbs-admin-conflict`).
    /// The launch path still re-checks AND reserves under the `handles`
    /// lock ([`check_capacity`]) — that is the race-safe gate; this only
    /// moves the COMMON rejection into the window where re-place works.
    ///
    /// Delegates to [`check_capacity`] with `add_disk_gb = 0` so the
    /// cpu/mem thresholds are the SAME code the launch reservation runs —
    /// preflight can never admit a launch the reservation would reject on
    /// cpu/mem grounds (the disk half is gated separately by
    /// [`Self::check_disk_budget`]; passing `0` here only re-affirms the
    /// already-admitted existing disk usage, never a new rejection).
    pub fn check_cpu_mem_budget(&self, add_cpu: u8, add_memory_mb: u32) -> Result<()> {
        let handles = self.lock_handles()?;
        check_capacity(&handles, self.host, add_cpu, add_memory_mb, 0)
    }

    /// Snapshot of `(cid, cose_ticket)` for `vm_id`, if the lifecycle
    /// admitted it. Used by the reboot-watcher (`lifecycle::
    /// reboot_watcher`) to re-push the L1-signed OrderTicket via
    /// AF_VSOCK every time libvirt restarts the domain after a guest
    /// `sudo reboot`. Returns `None` if the vm_id is not tracked
    /// (foreign domain) OR the ticket is empty (admitted but ticket
    /// not yet cached — shouldn't happen in practice).
    pub fn ticket_for_vm(&self, vm_id: &VmId) -> Option<(u32, Vec<u8>)> {
        let handles = self.handles.lock().ok()?;
        let h = handles.get(vm_id)?;
        if h.cose_ticket.is_empty() {
            return None;
        }
        Some((h.cid, h.cose_ticket.clone()))
    }

    /// The on-host path of `vm_id`'s writable LUKS2 + dm-integrity data
    /// disk, if the lifecycle is tracking it. `None` for an untracked
    /// `vm_id` (foreign domain, or one already stopped/destroyed).
    ///
    /// §25 migration **M1** reads this to snapshot the writable volume.
    /// The bytes on disk are ALREADY encrypted (the guest holds the
    /// key inside its SNP boundary); the miner only ever copies
    /// ciphertext, so this path is a non-secret control-plane fact —
    /// the same posture as [`Self::ticket_for_vm`] and the §24 `destroy`
    /// capacity-reclaim that also reads `luks_disk_path`.
    ///
    /// Captured at quiesce time (the migration state map snapshots it)
    /// so a subsequent `stop` dropping the handle does not lose the
    /// path the snapshot still needs.
    pub fn luks_disk_path_for(&self, vm_id: &VmId) -> Option<std::path::PathBuf> {
        let handles = self.handles.lock().ok()?;
        handles.get(vm_id).map(|h| h.luks_disk_path.clone())
    }

    /// Number of tenant CVMs currently tracked in the handle map.
    ///
    /// This is a test + ops-debug observation point — the production
    /// orders API never reads it. It is `#[doc(hidden)]` because the
    /// handle map is an implementation detail; existing operator
    /// surfaces (`list`, `query`) remain the documented entry points
    /// for ops. Crucially, tests can now assert handle-cleanup
    /// invariants (e.g. `tracked_count == 0` after a failed launch's
    /// teardown) without exposing the inner `HashMap`.
    #[doc(hidden)]
    pub fn tracked_count(&self) -> Result<usize> {
        Ok(self.lock_handles()?.len())
    }
}

/// Assert the locally-computed Infra launch digest equals the
/// operator/vali-supplied sha256 pin. Fail-closed on a malformed pin
/// (`infra-pin-format`) or any byte disagreement (`infra-pin-mismatch`)
/// so a tampered local UKI cannot boot under the attestor identity.
///
/// The launch digest is a PUBLIC measurement (not a secret), so a plain
/// byte compare is sufficient — there is no timing oracle to defend.
fn assert_infra_measurement_pin(
    digest: &[u8; cvm_handle::LAUNCH_DIGEST_LEN],
    expected_hex: &str,
) -> Result<()> {
    let expected = hex::decode(expected_hex.trim())
        .map_err(|_| MinerAgentError::LaunchDigest("infra-pin-format"))?;
    if expected.len() != cvm_handle::LAUNCH_DIGEST_LEN {
        return Err(MinerAgentError::LaunchDigest("infra-pin-format"));
    }
    if expected.as_slice() != digest.as_slice() {
        return Err(MinerAgentError::LaunchDigest("infra-pin-mismatch"));
    }
    Ok(())
}

/// Refuse a launch that would overcommit the host CPU or memory
/// budget. Every sum is `checked_add` on `u64`, so an accounting
/// overflow fails closed (`InsufficientResources`) rather than
/// wrapping into an apparent free budget.
fn check_capacity(
    handles: &HashMap<VmId, CvmHandle>,
    host: HostResources,
    add_cpu: u8,
    add_memory_mb: u32,
    add_disk_gb: u32,
) -> Result<()> {
    let mut used_cpu: u64 = 0;
    let mut used_memory: u64 = 0;
    let mut used_disk: u64 = 0;
    for handle in handles.values() {
        // The singleton Infra host-attestor is carved out of the tenant
        // budget separately (fixed 1 vCPU / 512 MiB) — never counted
        // against the operator's declared tenant capacity (blackbox
        // attestor plan: "filtered from capacity/heartbeat/billing").
        if handle.is_infra() {
            continue;
        }
        used_cpu = used_cpu
            .checked_add(u64::from(handle.cpu_count))
            .ok_or(MinerAgentError::InsufficientResources)?;
        used_memory = used_memory
            .checked_add(u64::from(handle.memory_mb))
            .ok_or(MinerAgentError::InsufficientResources)?;
        used_disk = used_disk
            .checked_add(u64::from(handle.data_disk_size_gb))
            .ok_or(MinerAgentError::InsufficientResources)?;
    }
    let need_cpu = used_cpu
        .checked_add(u64::from(add_cpu))
        .ok_or(MinerAgentError::InsufficientResources)?;
    let need_memory = used_memory
        .checked_add(u64::from(add_memory_mb))
        .ok_or(MinerAgentError::InsufficientResources)?;
    let need_disk = used_disk
        .checked_add(u64::from(add_disk_gb))
        .ok_or(MinerAgentError::InsufficientResources)?;
    if need_cpu > u64::from(host.total_cpus) || need_memory > host.total_memory_mb {
        return Err(MinerAgentError::InsufficientResources);
    }
    // total_disk_gb == 0 disables the disk reservation (cpu/mem still
    // apply) — back-compat for configs without `cvm_disk_gb_budget`.
    if host.total_disk_gb > 0 && need_disk > host.total_disk_gb {
        return Err(MinerAgentError::InsufficientResources);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a lifecycle whose state-disk + data roots point at `dir`.
    fn reclaim_lifecycle(dir: &std::path::Path) -> CvmLifecycle {
        CvmLifecycle::new(
            std::sync::Arc::new(crate::lifecycle::libvirt_driver::MockLibvirtDriver::new()),
            std::sync::Arc::new(crate::lifecycle::launch_digest::MockLaunchDigest::fixed(
                [0u8; 48],
            )),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(dir.to_path_buf())
    }

    #[tokio::test]
    async fn destroy_reclaims_the_disks_of_an_untracked_vm() {
        // THE §24 LEAK. vali always sends a graceful `stop` ORDER before
        // the `destroy` order, and that stop drops the handle — so by the
        // time `destroy` runs the VM is untracked. `destroy` used to
        // `return Ok(())` on a missing handle, so the reclaim below never
        // ran on the normal path while still reporting `destroyed`. Every
        // decommissioned VM leaked its full-size overlay; ~882 GB had
        // accumulated across three miners by 2026-07-29.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = reclaim_lifecycle(dir.path());
        let vm = VmId::new("tenant-reclaim").unwrap();

        let overlay = lifecycle.golden_overlay_path(&vm);
        let state = lifecycle.state_disk_path(&vm);
        // The #365 legacy data disk — up to ~59 GB on an xlarge, the
        // single biggest per-VM file on the legacy path, and the one my
        // first revision silently omitted while claiming to reclaim "the
        // whole per-VM footprint".
        let data = data_disk::data_disk_path(&lifecycle.data_disk_root, &vm);
        for p in [&overlay, &state, &data] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"ciphertext").unwrap();
        }
        let marker = crate::orders::migration::restore_marker_path(&overlay);
        std::fs::write(&marker, b"migrations/x/y.luks").unwrap();

        // No handle: the VM was already stopped, exactly as §24 leaves it.
        assert!(lifecycle.list().await.unwrap().is_empty());
        lifecycle.destroy(&vm).await.expect("destroy must succeed");

        assert!(!overlay.exists(), "the overlay must be reclaimed");
        assert!(!state.exists(), "the state disk must be reclaimed");
        assert!(!data.exists(), "the legacy data disk must be reclaimed");
        assert!(!marker.exists(), "the restore marker must be reclaimed");
    }

    // ── P9/#16: §24 must still reclaim a VM staged under the OLD scheme ─

    #[tokio::test]
    async fn destroy_reclaims_a_vm_staged_before_the_per_vm_redirect() {
        // BACKWARD COMPATIBILITY IS A DATA-DEATH CONCERN. `legacy-
        // tenant-1` and every other VM on the fleet was staged by an agent
        // that predates the §25 path redirect. §24 has NO lifecycle record
        // to consult — it rebuilds the footprint from `vm_id` alone — so
        // if the staging dir ever stopped being derivable that way, those
        // VMs would become unreclaimable and leak their base images.
        //
        // This test stages the OLD layout (a bare per-VM dir holding the
        // artifacts, no marker of any kind) and requires the reclaim.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = reclaim_lifecycle(dir.path());
        let vm = VmId::new("legacy-tenant-1").unwrap();

        // The LITERAL old-scheme path, spelled out rather than asked for
        // — a test that derives the path the same way the code does would
        // move with any change to that derivation and prove nothing.
        let staging = dir.path().join("staging").join("legacy-tenant-1");
        std::fs::create_dir_all(&staging).unwrap();
        for name in [
            "tenant.vmlinuz",
            "tenant.initrd.img",
            "rootfs.img",
            "rootfs.verity",
        ] {
            std::fs::write(staging.join(name), b"old-scheme-artifact").unwrap();
        }

        lifecycle.destroy(&vm).await.expect("destroy must succeed");

        assert!(
            !staging.exists(),
            "a VM staged under the OLD scheme became unreclaimable by §24"
        );
    }

    #[tokio::test]
    async fn destroy_reclaims_a_dangling_per_vm_staging_link() {
        // #880's rule — stat before you trust — applied to the staging
        // ENTRY. A per-VM dir replaced by a DANGLING symlink reads
        // `exists() == false` (it traverses), so the "nothing to reclaim"
        // bail used to strand it forever. `symlink_metadata` sees the link
        // itself; `reclaim_staging_dir` then unlinks it AS A LINK.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = reclaim_lifecycle(dir.path());
        let vm = VmId::new("tenant-dangling").unwrap();

        let staging = dir.path().join("staging").join("tenant-dangling");
        std::fs::create_dir_all(staging.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone-forever"), &staging).unwrap();
        assert!(!staging.exists(), "precondition: the link dangles");
        assert!(staging.symlink_metadata().is_ok());

        lifecycle.destroy(&vm).await.expect("destroy must succeed");

        assert!(
            staging.symlink_metadata().is_err(),
            "a dangling per-VM staging link was stranded by §24"
        );
    }

    #[test]
    fn the_lifecycle_staging_dir_matches_the_canonical_one_in_production() {
        // The method exists ONLY so tests can root the tree in a tempdir.
        // In production (`state_disk_root == MINER_ROOT`) it must resolve
        // byte-for-byte to the free function §24's reclaim and the launch
        // preflight both use — otherwise the §25 redirect would stage into
        // a directory nothing sweeps.
        let lifecycle = CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::new()),
            Arc::new(MockLaunchDigest::fixed([0u8; 48])),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        );
        let vm = VmId::new("legacy-tenant-1").unwrap();
        assert_eq!(
            lifecycle.vm_staging_dir(&vm),
            preflight::vm_staging_dir(vm.as_str()),
        );
        assert_eq!(
            lifecycle.vm_staging_dir(&vm),
            std::path::PathBuf::from("/var/lib/hippius-miner/staging/legacy-tenant-1"),
        );
    }

    #[tokio::test]
    async fn destroy_is_a_no_op_on_a_host_that_never_held_the_vm_even_if_libvirt_is_dark() {
        // THE MISROUTE INVARIANT, which `effects.py` depends on by name.
        // vali aims the §24 force-stop at any miner that MIGHT hold a
        // domain, so a destroy routinely lands on a host that never had
        // this VM. That must be a no-op — including when libvirtd is down
        // there, or when its domain enumeration lost a benign race.
        //
        // Proving liveness unconditionally broke this: the destroy raised,
        // the job retried to its step timeout, `_destroy_vm` never ran and
        // the VM pinned in `Decommissioning` with no API-reachable
        // recovery. Statting the footprint FIRST restores the no-op by
        // construction.
        struct DarkDriver;
        #[async_trait::async_trait]
        impl crate::lifecycle::libvirt_driver::LibvirtDriver for DarkDriver {
            async fn define_domain(&self, _xml: &str) -> Result<DomainId> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn create_domain(&self, _id: &DomainId) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn destroy_domain(&self, _id: &DomainId, _graceful: bool) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn undefine_domain(&self, _id: &DomainId) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn query_domain_state(&self, _id: &DomainId) -> Result<DomainState> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn domain_xml(&self, _id: &DomainId) -> Result<String> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = CvmLifecycle::new(
            std::sync::Arc::new(DarkDriver),
            std::sync::Arc::new(crate::lifecycle::launch_digest::MockLaunchDigest::fixed(
                [0u8; 48],
            )),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(dir.path().to_path_buf());
        let vm = VmId::new("tenant-elsewhere").unwrap();

        // No handle, no files anywhere: nothing to reclaim, so libvirt is
        // never consulted and the destroy succeeds.
        lifecycle
            .destroy(&vm)
            .await
            .expect("a misrouted destroy must stay a no-op, dark libvirt or not");
    }

    #[tokio::test]
    async fn destroy_fails_closed_when_libvirt_cannot_say_whether_the_domain_is_up() {
        // `DomainLiveness::Unknown` is NOT down. This host demonstrably
        // HOLDS the VM's files, and libvirt cannot tell us whether the
        // guest is running — unlinking on "I don't know" is the
        // catastrophic case the whole guard exists for. One word turns
        // fail-closed into fail-open, so it gets its own test: the
        // `Live` arm is reached by a different route (a driver that
        // ANSWERS) and does not cover this one.
        //
        // It also pins the OTHER edge of the stat gate — that the early
        // return does not over-trigger when there IS something here.
        struct DarkDriver2;
        #[async_trait::async_trait]
        impl crate::lifecycle::libvirt_driver::LibvirtDriver for DarkDriver2 {
            async fn define_domain(&self, _xml: &str) -> Result<DomainId> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn create_domain(&self, _id: &DomainId) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn destroy_domain(&self, _id: &DomainId, _graceful: bool) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn undefine_domain(&self, _id: &DomainId) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn query_domain_state(&self, _id: &DomainId) -> Result<DomainState> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
            async fn domain_xml(&self, _id: &DomainId) -> Result<String> {
                Err(MinerAgentError::LibvirtDriver("dark"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = CvmLifecycle::new(
            std::sync::Arc::new(DarkDriver2),
            std::sync::Arc::new(crate::lifecycle::launch_digest::MockLaunchDigest::fixed(
                [0u8; 48],
            )),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(dir.path().to_path_buf());
        let vm = VmId::new("tenant-unknown").unwrap();

        let overlay = lifecycle.golden_overlay_path(&vm);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"POSSIBLY LIVE GUEST DATA").unwrap();

        let err = lifecycle.destroy(&vm).await.unwrap_err();
        assert!(
            matches!(err, MinerAgentError::Destroy("domain-still-up")),
            "an unknowable domain must fail closed, not be assumed down"
        );
        assert!(
            overlay.exists(),
            "nothing may be unlinked while liveness is unknown"
        );
    }

    #[tokio::test]
    async fn destroy_refuses_to_unlink_under_a_domain_that_is_still_up() {
        // The early return we removed was also the guard against unlinking
        // a LIVE guest's backing file when the handle is missing (an
        // adopt-record loss, say). Replaced by a positive proof: with no
        // handle we consult libvirt BY NAME, and a domain that is up fails
        // the destroy closed rather than corrupting a running tenant.
        let dir = tempfile::tempdir().unwrap();
        let driver =
            std::sync::Arc::new(crate::lifecycle::libvirt_driver::MockLibvirtDriver::new());
        let vm = VmId::new("tenant-live").unwrap();
        let domain =
            crate::lifecycle::libvirt_driver::DomainId::new("hippius-tenant-tenant-live").unwrap();
        driver.seed_domain(domain, DomainState::Running);

        let lifecycle = CvmLifecycle::new(
            driver,
            std::sync::Arc::new(crate::lifecycle::launch_digest::MockLaunchDigest::fixed(
                [0u8; 48],
            )),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .with_state_disk_root(dir.path().to_path_buf());

        let overlay = lifecycle.golden_overlay_path(&vm);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"LIVE GUEST DATA").unwrap();

        let err = lifecycle.destroy(&vm).await.unwrap_err();
        assert!(matches!(err, MinerAgentError::Destroy("domain-still-up")));
        assert!(overlay.exists(), "a live guest's disk must NOT be unlinked");
    }

    #[test]
    fn check_capacity_admits_within_budget() {
        let host = HostResources {
            total_cpus: 8,
            total_memory_mb: 16384,
            total_disk_gb: 0,
        };
        let handles = HashMap::new();
        assert!(check_capacity(&handles, host, 4, 8192, 0).is_ok());
    }

    #[test]
    fn check_capacity_refuses_cpu_overcommit() {
        let host = HostResources {
            total_cpus: 2,
            total_memory_mb: 16384,
            total_disk_gb: 0,
        };
        let handles = HashMap::new();
        assert!(matches!(
            check_capacity(&handles, host, 4, 1024, 0),
            Err(MinerAgentError::InsufficientResources)
        ));
    }

    #[test]
    fn check_capacity_refuses_memory_overcommit() {
        let host = HostResources {
            total_cpus: 8,
            total_memory_mb: 2048,
            total_disk_gb: 0,
        };
        let handles = HashMap::new();
        assert!(matches!(
            check_capacity(&handles, host, 1, 4096, 0),
            Err(MinerAgentError::InsufficientResources)
        ));
    }

    #[test]
    fn check_capacity_refuses_disk_overcommit() {
        // cpu/mem roomy; the DISK budget is the binding constraint.
        let host = HostResources {
            total_cpus: 64,
            total_memory_mb: 1_000_000,
            total_disk_gb: 64,
        };
        let handles = HashMap::new();
        // 128 GiB requested against a 64 GiB declared budget → reject
        // BEFORE the (sparse) disk is even created.
        assert!(matches!(
            check_capacity(&handles, host, 1, 1024, 128),
            Err(MinerAgentError::InsufficientResources)
        ));
        // Exactly at the budget is admitted.
        assert!(check_capacity(&handles, host, 1, 1024, 64).is_ok());
    }

    #[test]
    fn disk_budget_zero_disables_the_reservation() {
        // Back-compat: a config without `cvm_disk_gb_budget` → 0 → the
        // disk reservation is OFF (cpu/mem still apply, and the
        // per-create statvfs backstop still rejects a genuinely full
        // mount). A huge disk request passes the reservation check.
        let host = HostResources {
            total_cpus: 64,
            total_memory_mb: 1_000_000,
            total_disk_gb: 0,
        };
        let handles = HashMap::new();
        assert!(check_capacity(&handles, host, 1, 1024, 1_000_000).is_ok());
    }
}
