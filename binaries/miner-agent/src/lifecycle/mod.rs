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
pub mod cid_verify;
pub mod cvm_handle;
pub mod data_disk;
pub(crate) mod disk_space;
pub mod golden;
pub mod guardian;
pub mod infra;
pub mod launch_digest;
pub mod libvirt_driver;
pub mod power_policy;
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
use crate::vsock::peer::{CidAllocator, CidOwner};
use cvm_handle::LAUNCH_DIGEST_LEN;
use tokio_util::sync::CancellationToken;

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

/// Whether a ticket push may proceed — see
/// [`CvmLifecycle::ticket_push_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketPushState {
    /// The VM is running and owns the CID: deliver.
    Deliver,
    /// The VM is still launching on this CID: not yet, but not never.
    Wait,
    /// The VM is gone, being torn down, or no longer owns this CID or
    /// ticket: stop for good.
    Abort,
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
    /// operator's DECLARED capacity (`[host] cvm_disk_gb_budget`). The
    /// miner reserves against it here so concurrent launches can't
    /// over-commit, and declares it in the `v4` heartbeat, where vali uses
    /// it only as a down-only clamp on its own committed-disk ledger. 0
    /// disables the budget reservation (cpu/mem still apply, and the
    /// measured free-space gate of `disk_space` always does).
    pub total_disk_gb: u64,
}

/// What one process saw of delivering a running VM's ticket (see
/// [`CvmLifecycle::ticket_delivered`]).
#[derive(Debug, Clone, Default)]
struct TicketDelivery {
    cid: u32,
    cose_ticket: Vec<u8>,
    delivered: bool,
    launch_push_failed: bool,
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
    /// Phase 2B of audit follow-up Review #2 — root directory under
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
    /// The reboot-watcher's in-flight ticket re-push task per VM (see
    /// [`Self::begin_ticket_push`]). Cancelled when the VM leaves
    /// `Running` for teardown and BEFORE its CID is released, so no
    /// re-push can outlive the VM and reach the CID's next owner.
    ticket_pushes: Mutex<HashMap<VmId, CancellationToken>>,
    /// What this process has observed about delivering each running VM's
    /// ticket. Cleared when the VM's CID is released.
    ticket_delivery: Mutex<HashMap<VmId, TicketDelivery>>,
    /// Re-adopted VMs whose CID came from the sidecar because the live
    /// domain XML could not be read — held UNVERIFIED in the allocator
    /// until [`Self::verify_pending_cids`] confirms, re-keys or drops them.
    cid_checks: Mutex<HashMap<VmId, CidCheck>>,
    /// Snapshot vm_ids whose re-adoption failed `reserve-collision` — retried
    /// after a verification frees or moves a claim (see
    /// [`Self::retry_collided_readoptions`]).
    readopt_collided: Mutex<std::collections::HashSet<String>>,
    /// Set when a CID is released while collided survivors wait — the
    /// release may have freed exactly the CID that blocked them.
    readopt_retry_due: std::sync::atomic::AtomicBool,
    /// The host's SEV-ES ASID pool reader, for the tenant preflight
    /// ASID gate ([`Self::check_asid_budget`]). Production: the root
    /// cgroup's `misc.*` files; tests inject a fixed reading via
    /// [`Self::with_asid_source`].
    asids: Arc<dyn crate::sev_asid::AsidSource>,
    /// ASIDs promised by a passed tenant preflight whose launch has not
    /// finished yet (`vm_id → when`). `misc.current` only counts a guest
    /// once QEMU holds its ASID, so without these N concurrent preflights
    /// at the edge of the pool would all pass. Expire after
    /// [`ASID_RESERVATION_TTL`]; released when the launch ends.
    asid_reservations: Mutex<HashMap<VmId, std::time::Instant>>,
    /// The net-policy launch latch ([`crate::netpolicy::apply`]). `None`
    /// ⇒ no gate (tests, and agents without the net-policy route).
    net_policy_gate: Option<Arc<crate::netpolicy::NetPolicyEnforcer>>,
    /// What this process saw of each VM's current run — the evidence the
    /// guest-poweroff policy decides on ([`power_policy::GuestRuns`]).
    guest_runs: Arc<power_policy::GuestRuns>,
}

/// How long a preflight's ASID reservation holds without a launch.
pub const ASID_RESERVATION_TTL: Duration = Duration::from_secs(15 * 60);

/// First retry delay for an unverified re-adoption CID; doubles per
/// failure up to [`CID_VERIFY_MAX_BACKOFF`].
pub const CID_VERIFY_BASE_BACKOFF: Duration = Duration::from_secs(5);
/// Ceiling on the retry delay. Well under the reboot-watcher's 10-min
/// re-push window, so a VM that reboots while unverified still gets its
/// CID confirmed — and its ticket — inside that window.
pub const CID_VERIFY_MAX_BACKOFF: Duration = Duration::from_secs(120);
/// Bound on one verification attempt (a few `virsh` calls).
const CID_VERIFY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Retry state for one unverified re-adoption CID.
#[derive(Debug, Clone)]
struct CidCheck {
    /// Unique per scheduled check. A verification attempt awaits libvirt
    /// with no lock held; before it acts it must find THIS generation still
    /// queued — a stop (which drops the check) and a relaunch of the same
    /// `vm_id` in between must not be mutated by the stale result.
    generation: u64,
    failures: u32,
    next_at: std::time::Instant,
    /// The last failure class logged — a repeat is not re-logged.
    last_class: &'static str,
}

/// Source of [`CidCheck::generation`].
static CID_CHECK_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl CidCheck {
    fn backoff(failures: u32) -> Duration {
        let factor = 1u32 << failures.saturating_sub(1).min(16);
        CID_VERIFY_BASE_BACKOFF
            .saturating_mul(factor)
            .min(CID_VERIFY_MAX_BACKOFF)
    }
}

/// What a verification attempt captured before awaiting libvirt — it may
/// act only if all of it still holds.
struct CheckIdentity<'a> {
    generation: u64,
    uuid: &'a DomainUuid,
    held: u32,
}

/// What one verification attempt concluded — see
/// [`CvmLifecycle::verify_pending_cids`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidVerdict {
    /// The live XML shows the recorded CID.
    Verified,
    /// The live XML shows a different CID; the handle + allocator moved to it.
    Rekeyed,
    /// The domain no longer exists; the handle was dropped.
    Dropped,
    /// Still unconfirmed (reason logged on change); retried after backoff.
    Pending,
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
            ticket_pushes: Mutex::new(HashMap::new()),
            ticket_delivery: Mutex::new(HashMap::new()),
            cid_checks: Mutex::new(HashMap::new()),
            readopt_collided: Mutex::new(std::collections::HashSet::new()),
            readopt_retry_due: std::sync::atomic::AtomicBool::new(false),
            asids: Arc::new(crate::sev_asid::SysfsAsidSource::default()),
            asid_reservations: Mutex::new(HashMap::new()),
            net_policy_gate: None,
            guest_runs: Arc::new(power_policy::GuestRuns::new()),
        }
    }

    /// Replace the SEV-ES ASID pool reader (default: the root cgroup's
    /// `misc.capacity` / `misc.current`). Tests inject a fixed reading.
    pub fn with_asid_source(mut self, asids: Arc<dyn crate::sev_asid::AsidSource>) -> Self {
        self.asids = asids;
        self
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

    /// `[storage] data_disk_root` — where the per-VM writable disks live.
    pub fn data_disk_root(&self) -> &std::path::Path {
        &self.data_disk_root
    }

    /// The host disk ledger ([`crate::backup::capture::SpaceLedger::host`])
    /// over this host's per-VM disks — what an in-flight writer (a §25
    /// download) reserves in.
    pub fn disk_space_ledger(&self) -> crate::backup::capture::SpaceLedger {
        crate::backup::capture::SpaceLedger::host(self.data_disk_root.clone())
    }

    /// Root of the per-VM backup work dirs (`<data_disk_root>/backup`).
    /// On the overlay's filesystem, so a restored overlay is renamed into
    /// place atomically and the space guard sees the right mount.
    pub fn backup_root(&self) -> std::path::PathBuf {
        self.data_disk_root.join("backup")
    }

    /// This VM's backup work dir (`<data_disk_root>/backup/<vm_id>`).
    pub fn backup_dir(&self, vm_id: &VmId) -> std::path::PathBuf {
        self.backup_root().join(vm_id.as_str())
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

    /// Refuse tenant launches and migrate-in while `enforcer`'s
    /// edge-mode policy is persisted but not loaded. The infra domain is
    /// not gated.
    pub fn with_net_policy_gate(
        mut self,
        enforcer: Arc<crate::netpolicy::NetPolicyEnforcer>,
    ) -> Self {
        self.net_policy_gate = Some(enforcer);
        self
    }

    /// The net-policy launch latch; `Ok` when no gate is wired.
    pub fn check_net_policy_gate(&self) -> Result<()> {
        match &self.net_policy_gate {
            Some(enforcer) => enforcer.check_launch(),
            None => Ok(()),
        }
    }

    /// The AF_VSOCK context-id allocator (MA-4). The serve loop hands
    /// this `Arc` to the vsock relay listener so it can resolve an
    /// inbound connection's CID back to the tenant `VmId`.
    pub fn cid_allocator(&self) -> Arc<CidAllocator> {
        Arc::clone(&self.cids)
    }

    /// The per-run evidence the guest-poweroff policy decides on — fed by
    /// the reboot-watcher (QMP `SHUTDOWN`, libvirt `Started`) and the
    /// vsock relay (guest userspace up).
    pub fn guest_runs(&self) -> Arc<power_policy::GuestRuns> {
        Arc::clone(&self.guest_runs)
    }

    /// `vm_id`'s guest-poweroff policy (`restart` when it has none).
    pub fn power_policy(&self, vm_id: &VmId) -> Result<crate::orders::OnGuestPoweroff> {
        power_policy::policy(&self.state_disk_root, vm_id)
    }

    /// Change `vm_id`'s guest-poweroff policy in place (a `power-policy`
    /// order). Only for a VM this host has: one the agent tracks, or
    /// whose domain libvirt still defines. `VmNotFound` otherwise — the
    /// next launch carries the policy anyway.
    pub async fn set_power_policy(
        &self,
        vm_id: &VmId,
        policy: crate::orders::OnGuestPoweroff,
    ) -> Result<()> {
        let tracked = self.lock_handles()?.contains_key(vm_id);
        if !tracked {
            match self.tenant_domain_defined(vm_id).await {
                Some(true) => {}
                Some(false) => return Err(MinerAgentError::VmNotFound),
                None => return Err(MinerAgentError::LibvirtDriver("unreachable")),
            }
        }
        power_policy::change(&self.state_disk_root, vm_id, policy)
    }

    /// Whether `vm_id` was left stopped after its guest powered off.
    pub fn stopped_by_guest(&self, vm_id: &VmId) -> bool {
        power_policy::stopped_by_guest(&self.state_disk_root, vm_id)
    }

    /// Leave `vm_id` stopped after its guest powered itself off (policy
    /// `stop`, decided by the reboot-watcher): mark it on disk FIRST — the
    /// mark is what tells vali the VM is stopped and not crashed — then
    /// release it exactly as a clean [`Self::stop`] does (undefine,
    /// handle, CID, re-adoption snapshot), so a later start is the same
    /// relaunch as after an API stop.
    ///
    /// Refuses (and changes nothing) unless the VM is `Running` here and
    /// libvirt reports its domain DOWN. On a failed mark the VM is handed
    /// back `Running` and the error returned: the caller restarts it,
    /// since a VM vali cannot see as stopped would be relaunched anyway.
    pub async fn settle_guest_poweroff(&self, vm_id: &VmId, now_unix: u64) -> Result<()> {
        let domain_id = {
            let mut handles = self.lock_handles()?;
            let handle = handles.get_mut(vm_id).ok_or(MinerAgentError::VmNotFound)?;
            if handle.phase != CvmPhase::Running {
                return Err(MinerAgentError::CvmBusy);
            }
            handle.phase = CvmPhase::Stopping;
            handle.domain_id.clone()
        };
        let back_to_running = |err: MinerAgentError| {
            if let Ok(mut handles) = self.lock_handles() {
                if let Some(handle) = handles.get_mut(vm_id) {
                    if handle.phase == CvmPhase::Stopping {
                        handle.phase = CvmPhase::Running;
                    }
                }
            }
            err
        };
        if self.domain_liveness(&domain_id).await != DomainLiveness::Down {
            return Err(back_to_running(MinerAgentError::CvmBusy));
        }
        power_policy::record_guest_poweroff(&self.state_disk_root, vm_id, now_unix)
            .map_err(back_to_running)?;
        self.cancel_ticket_push(vm_id);
        if self.driver.undefine_domain(&domain_id).await.is_err() {
            eprintln!(
                "hippius-miner-agent: lifecycle: guest-poweroff: vm {vm_id} domain stayed \
                 defined — libvirt record may need a manual `virsh undefine`"
            );
        }
        if let Ok(mut handles) = self.lock_handles() {
            if let Some(handle) = handles.get_mut(vm_id) {
                handle.phase = CvmPhase::Stopped;
            }
            handles.remove(vm_id);
        }
        self.release_cid(vm_id);
        adopt::forget(&self.state_disk_root, vm_id.as_str());
        Ok(())
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
        // Whatever the outcome, the preflight's ASID promise ends here: a
        // started guest now holds a real ASID (`misc.current` counts it),
        // a failed one holds none.
        let result = self.launch_inner(order).await;
        self.release_asid_reservation(&vm_id);
        result
    }

    async fn launch_inner(&self, order: LaunchOrder) -> Result<VmId> {
        // Before anything is reserved: covers order launches, relaunches
        // and the §25 destination's boot.
        self.check_net_policy_gate()?;
        let vm_id = order.vm_id.clone();
        let domain_uuid = DomainUuid::generate()?;
        // Capture the COSE ticket bytes BEFORE moving the order into the
        // QemuConfig — cached in the handle so the reboot-watcher can
        // re-push it on every libvirt domain restart.
        let cose_ticket: Vec<u8> = order.cose_ticket.clone().into_vec();
        let require_existing_disks = order.require_existing_disks;
        let on_guest_poweroff = order.on_guest_poweroff;
        // #312 — refuse the launch if the L1-minted ticket's `flavor`
        // disagrees with the dispatcher's `cpu_count`. The §22
        // allowlist would catch this at KBS release time anyway (vcpus
        // is folded into the SNP launch_digest), but failing here saves
        // an entire guest boot + audit-log entry. The peek is a CBOR
        // decode of the COSE payload only — no L1 signature check, by
        // design (see `lifecycle::ticket_peek` doc-block).
        ticket_peek::enforce_flavor_matches_cpu_count(&cose_ticket, order.cpu_count)?;
        // Customer-held keys: the order's guardian endpoint must be the
        // one the MEASURED cmdline pins (and present iff the cmdline asks
        // for a guardian). Checked before anything is reserved. `None` ⇒
        // an M0 launch, byte-for-byte today's path.
        let guardian_ep =
            guardian::check_order_guardian(&order.cmdline, order.guardian_ep.as_deref())?;
        // Phase 2B of audit follow-up Review #2 — compute the per-VM
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
            net: order.net,
        };
        config.validate()?;
        let domain_id = config.domain_name()?;

        // Customer-keys VM: capture the recipe the digest is computed over
        // (CID-independent) BEFORE anything is reserved, so a failure here
        // has nothing to roll back. It goes into the handle at insertion:
        // the guardian relay only answers a CID whose handle carries a
        // route, and it is there before the guest can first dial.
        // Fail-closed like the digest — a VM whose guardian can never
        // verify it is not started.
        let guardian_route = match guardian_ep {
            Some(ep) => Some(guardian::GuardianRoute {
                endpoint: ep.to_wire(),
                recipe: self
                    .digest
                    .recipe(&guardian::RecipeInputs::from_config(&config))?,
            }),
            None => None,
        };

        // A RELAUNCH must find the VM's disks already here — every
        // `ensure_*` below would otherwise CREATE blank ones (seen in
        // production 2026-09-25: a relaunch onto a host that never held the
        // VM got a blank overlay + a blank boot-counter disk). Checked
        // before anything is reserved, so a refusal leaves nothing behind.
        if require_existing_disks {
            check_relaunch_disks(&config)?;
        }

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
            // A fresh launch supersedes any unverified re-adoption of this
            // vm_id (reclaimed as stale above): its CID is proven by the
            // `create_domain` below, not by a live-XML check.
            self.forget_cid_check(&vm_id);
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
                    guardian: guardian_route,
                },
            );
        }

        // The guest-poweroff policy this order carries, persisted before
        // the domain can start (a guest that powers off at once is read
        // against it). Refused rather than launched without it: a `stop`
        // VM must never silently become a `restart` one.
        if let Err(err) =
            power_policy::apply_launch(&self.state_disk_root, &vm_id, on_guest_poweroff)
        {
            self.unreserve_handle(&vm_id);
            self.release_cid(&vm_id);
            return Err(err);
        }

        // Pre-flight launch digest — computed BEFORE any virsh call.
        // A digest failure unreserves the slot and releases the CID:
        // NO domain was ever defined, so the CID cannot be in use.
        let digest = match self.digest.compute(&config) {
            Ok(digest) => digest,
            Err(err) => {
                self.unreserve_handle(&vm_id);
                self.release_cid(&vm_id);
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

        // Phase 2B of audit follow-up Review #2 — provision the per-VM
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
                self.release_cid(&vm_id);
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
                //
                // Off the async worker: the create waits on the host disk
                // lock and lists the disk directories.
                let (root, id) = (self.data_disk_root.clone(), vm_id.clone());
                let created = tokio::task::spawn_blocking(move || {
                    golden::ensure_overlay_disk(&root, &id, disk_budget_gb)
                })
                .await
                .unwrap_or(Err(MinerAgentError::OverlayDisk("join")));
                if let Err(err) = created {
                    self.unreserve_handle(&vm_id);
                    self.release_cid(&vm_id);
                    return Err(err);
                }
            } else if config.data_disk_size_gb > 0 {
                // #365 — provision the blank sparse tenant data disk the
                // guest formats fresh at first boot (`/dev/vde`). Idempotent
                // (preserves a relaunched VM's data), fail-closed BEFORE any
                // `virsh` call. Only when the order requested one.
                let (root, id, gb) = (
                    self.data_disk_root.clone(),
                    vm_id.clone(),
                    config.data_disk_size_gb,
                );
                let created = tokio::task::spawn_blocking(move || {
                    data_disk::ensure_data_disk(&root, &id, gb)
                })
                .await
                .unwrap_or(Err(MinerAgentError::DataDisk("join")));
                if let Err(err) = created {
                    self.unreserve_handle(&vm_id);
                    self.release_cid(&vm_id);
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

    /// Whether libvirt has a domain (running or not) for tenant `vm_id`.
    /// `None` when libvirt cannot be reached.
    pub async fn tenant_domain_defined(&self, vm_id: &VmId) -> Option<bool> {
        let domain_id = DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str())).ok()?;
        let list = self.driver.list_domains().await.ok()?;
        Some(list.iter().any(|(id, _)| id == &domain_id))
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
            self.release_cid(vm_id);
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
                Ok(()) => {
                    // The kernel just bound `config.cid` to THIS guest — the
                    // strongest proof there is. Clears an unverified mark the
                    // idempotent `allocate` may have handed back from a
                    // reclaimed re-adoption of the same vm_id.
                    let _ = self.cids.mark_verified(&config.vm_id, config.cid);
                    break;
                }
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
        // The VM is being torn down: nothing may deliver its ticket from
        // here on (the guest is going away, and its CID with it).
        self.cancel_ticket_push(vm_id);

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
            self.release_cid(vm_id);
            adopt::forget(&self.state_disk_root, vm_id.as_str());
        }
        outcome
    }

    /// Force a tenant domain down whether or not this process tracks it
    /// (a restore abort must not leave a restored guest running because
    /// the agent restarted under it), then prove it is down. Only the
    /// runtime goes: disks are untouched and the libvirt record is
    /// undefined only on the tracked path, as [`Self::stop`] does.
    pub async fn force_stop_tenant(&self, vm_id: &VmId) -> Result<()> {
        match self.stop(vm_id, false).await {
            Ok(()) => {}
            Err(MinerAgentError::VmNotFound) => {
                self.cancel_ticket_push(vm_id);
                let domain_id = DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str()))?;
                // Errors are settled by the liveness proof below.
                let _ = self.driver.destroy_domain(&domain_id, false).await;
            }
            Err(err) => return Err(err),
        }
        match self.tenant_domain_liveness(vm_id).await {
            DomainLiveness::Down => Ok(()),
            DomainLiveness::Live | DomainLiveness::Unknown => {
                Err(MinerAgentError::Backup("restore-stop-failed"))
            }
        }
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
    ///
    /// `restore`, when the host has staged restores enabled, is asked to
    /// cancel and await any in-flight staging of `vm_id` before its
    /// backup dir is reclaimed below — an in-progress `restore/<rid>/`
    /// staging is otherwise wiped out from under a still-running
    /// `RestoreManager::run_stage`, which then recreates
    /// `backup/<vm>/restore/status.json` for a VM that no longer exists.
    pub async fn destroy(
        &self,
        vm_id: &VmId,
        restore: Option<&crate::backup::staged::RestoreManager>,
    ) -> Result<()> {
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
        // A staged restore's retained originals (`*.pre-restore-<id>`),
        // by the exact paths its persisted record names — never a glob.
        files.extend(crate::backup::staged::retained_files(
            &self.backup_dir(vm_id),
            &self.golden_overlay_path(vm_id),
            &self.state_disk_path(vm_id),
        ));
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
        // The live-backup work dir (`<data root>/backup/<vm_id>`): the run's
        // in-flight marker, an interrupted run's leftovers, a chain
        // restore's pieces. Per-VM like staging, and derived from `vm_id`
        // alone the same way.
        let backup = self.backup_dir(vm_id);

        // `symlink_metadata`, not `exists()`: a per-VM staging entry that
        // is a DANGLING symlink is still a footprint this destroy owns and
        // must unlink (`exists()` traverses, so it reads `false` and the
        // no-op bail below would strand it). #880's rule — stat before you
        // trust — applied to the entry itself rather than its target.
        let mut anything = staging.symlink_metadata().is_ok() || backup.symlink_metadata().is_ok();
        for f in &files {
            if !f.as_os_str().is_empty() && f.exists() {
                anything = true;
            }
        }
        // The guest-poweroff policy dies with the VM — on every path,
        // including the nothing-left no-op below. Logged, not returned: a
        // leftover record names a VM no launch will ever carry again.
        if power_policy::remove(&self.state_disk_root, vm_id).is_err() {
            eprintln!(
                "hippius-miner-agent: destroy: vm {} power-policy record not removed",
                vm_id.as_str()
            );
        }
        if handle_disk.is_none()
            && !anything
            && self.tenant_domain_defined(vm_id).await != Some(true)
        {
            // Never hosted here (or already reclaimed and undefined) —
            // idempotent success. A defined-but-down domain with no files
            // left (a shut-off VM whose disks an earlier destroy already
            // reclaimed) is NOT this case: it falls through so the record
            // is undefined below. A libvirt error (`None`) keeps the
            // misrouted-destroy no-op: "cannot tell" must not fail §24.
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
        // Drop the libvirt record too, now that the domain is proven down
        // and its disks are gone. A shut-off definition otherwise stays
        // forever (only a clean `stop` undefined it), and breaks the next
        // launch of the same vm_id with `domain already exists`. An
        // undefine failure is logged, not returned: data death already
        // happened, and failing here would pin the VM in Decommissioning.
        if let Ok(domain_id) = DomainId::new(&format!("hippius-tenant-{}", vm_id.as_str())) {
            if self.driver.undefine_domain(&domain_id).await.is_err() {
                eprintln!(
                    "hippius-miner-agent: destroy: vm {} domain stayed defined after \
                     reclaim — libvirt record may need a manual `virsh undefine`",
                    vm_id.as_str()
                );
            }
        }
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
        // A staged restore of this VM may still be downloading into
        // `backup/<vm>/restore/<rid>/` right now — the domain going down
        // does not stop it, and it does not hold the restore lock while it
        // runs. Cancel it and wait for it to actually stop writing BEFORE
        // the reclaim below, or a still-running `RestoreManager::run_stage`
        // recreates `restore/status.json` for a VM that no longer exists
        // once it finally does finish, and that file leaks forever (no
        // other cleanup path ever revisits a destroyed VM). Mirrors
        // `RestoreManager::abort`'s own cancellation step: done OUTSIDE
        // the (host-wide) restore lock, so this never blocks an unrelated
        // VM's `migrate-activate` waiting to enter `Activating`. A timeout
        // here fails the destroy rather than risk the race.
        if let Some(restore) = restore {
            restore.cancel_staging(vm_id).await?;
        }
        // The backup work dir, by its exact per-VM path — never the backup
        // root. Safe after the liveness proof above: its in-flight marker
        // only records QEMU-side resources (job, fd-passed target, point
        // bitmap), and those died with the domain, so there is nothing
        // left for a later release to do. A run that was mid-upload keeps
        // reading its already-unlinked target through its open fd; its
        // VM is gone either way. Best-effort, like staging: disk space,
        // not data death.
        if let Err(e) = preflight::reclaim_staging_dir(&backup) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "hippius-miner-agent: destroy: backup work dir reclaim failed for \
                     vm={} (disk space only)",
                    vm_id.as_str()
                );
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
            if self.readopt_one(snapshot).await? {
                adopted += 1;
            }
        }
        Ok(adopted)
    }

    /// Re-adopt ONE persisted snapshot; `Ok(true)` iff it is now tracked.
    async fn readopt_one(&self, snapshot: adopt::PersistedHandle) -> Result<bool> {
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
                return Ok(false);
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
                // A host reboot leaves the persistent definition behind,
                // shut off. The next launch of this vm_id defines a fresh
                // UUID under the same name, and libvirt refuses it
                // (`domain … already exists with uuid …`) until a failed
                // launch's teardown happens to undefine it — live: one
                // wasted reboot-recovery attempt per VM, and a failed
                // host-attestor start, after every miner reboot. The
                // domain is confirmed down, so drop the record now.
                //
                // Only the record: the undefine flags remove libvirt's own
                // per-domain metadata (managed-save, snapshot/checkpoint
                // metadata, a libvirt-managed NVRAM file — none of which a
                // `type='rom'` tenant or attestor domain has), never
                // storage; the overlay, state disk and staging are
                // untouched. And only a definition that is STILL shut off
                // when we get to it: re-read the state right before, so a
                // domain something started since the liveness read is
                // left alone (`virsh undefine` of a running domain would
                // turn it transient). Crashed / unreadable is left too.
                match self.driver.query_domain_state(&handle.domain_id).await {
                    Ok(DomainState::ShutOff) => {
                        if let Err(err) = self.driver.undefine_domain(&handle.domain_id).await {
                            eprintln!(
                                "hippius-miner-agent: re-adopt: vm={vm_id_str} stale definition \
                                 not undefined ({err}) — the next launch may need a retry"
                            );
                        }
                    }
                    Ok(state) => eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm_id_str} definition left in \
                         place (state {state:?} at undefine time)"
                    ),
                    Err(_) => {} // not defined any more — nothing to drop
                }
                return Ok(false);
            }
            DomainLiveness::Unknown => {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm_id_str} libvirt UNREACHABLE — \
                     snapshot RETAINED, VM not tracked this lifetime (restart the agent \
                     once libvirtd is up to re-adopt it)"
                );
                return Ok(false);
            }
        }
        // Reconcile the sidecar against what libvirt actually runs.
        // The file is miner-local state and can be stale or edited;
        // the domain XML is the ground truth for the numbers.
        let cid_verified = self.reconcile_handle_with_libvirt(&mut handle).await;

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
                return Ok(false);
            }
            if cid >= crate::vsock::peer::MIN_GUEST_CID {
                // An unconfirmed CID is HELD (nobody else may take it)
                // but is not an identity until the live XML confirms it:
                // ticket pushes and relay routing wait on it.
                let reserved = if cid_verified {
                    self.cids.reserve(&handle.vm_id, cid)
                } else {
                    self.cids.reserve_unverified(&handle.vm_id, cid)
                };
                if let Err(err) = reserved {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: CID {cid} for vm={vm_id_str} \
                         unavailable ({err}) — NOT tracked"
                    );
                    if matches!(err, MinerAgentError::VsockCid("reserve-collision")) {
                        // Another VM's record holds this CID — possibly a
                        // stale UNVERIFIED claim that verification will later
                        // re-key or drop. Retry this survivor then (#1149).
                        if let Ok(mut collided) = self.readopt_collided.lock() {
                            collided.insert(vm_id_str.clone());
                        }
                    }
                    return Ok(false);
                }
                if !cid_verified {
                    self.schedule_cid_check(&handle.vm_id);
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
        Ok(true)
    }

    /// Retry the re-adoption of survivors whose CID was held by another
    /// record at startup — called after a verification re-keys or drops an
    /// unverified claim, which may have been exactly what blocked them.
    /// Without it such a survivor stayed untracked until the next agent
    /// restart: capacity uncounted, no relay, no reboot supervision (#1149).
    async fn retry_collided_readoptions(&self) -> usize {
        let pending: Vec<String> = match self.readopt_collided.lock() {
            Ok(mut collided) => collided.drain().collect(),
            Err(_) => return 0,
        };
        if pending.is_empty() {
            return 0;
        }
        let mut adopted = 0usize;
        let mut keep: Vec<String> = Vec::new();
        for snapshot in adopt::list(&self.state_disk_root) {
            if !pending.contains(&snapshot.vm_id) {
                continue;
            }
            let vm_id = snapshot.vm_id.clone();
            // Bounded like a verification attempt: `virsh` has no timeout of
            // its own, and this runs inside the verify loop.
            match tokio::time::timeout(CID_VERIFY_ATTEMPT_TIMEOUT, self.readopt_one(snapshot)).await
            {
                Ok(Ok(true)) => adopted += 1,
                // Not adopted: still waiting unless it is tracked now (a
                // fresh launch took over) or its sidecar was pruned. A
                // renewed collision re-records itself; a libvirt blip or a
                // timeout must not silently drop it.
                Ok(Ok(false)) => keep.push(vm_id),
                Ok(Err(err)) => {
                    eprintln!("hippius-miner-agent: re-adopt retry failed vm={vm_id}: {err}");
                    keep.push(vm_id);
                }
                Err(_) => {
                    eprintln!("hippius-miner-agent: re-adopt retry timed out vm={vm_id}");
                    keep.push(vm_id);
                }
            }
        }
        let still_waiting: Vec<String> = keep
            .into_iter()
            .filter(|id| {
                let tracked = VmId::new(id)
                    .ok()
                    .is_some_and(|v| self.lock_handles().is_ok_and(|h| h.contains_key(&v)));
                let has_sidecar = adopt::list(&self.state_disk_root)
                    .iter()
                    .any(|s| &s.vm_id == id);
                !tracked && has_sidecar
            })
            .collect();
        if let Ok(mut collided) = self.readopt_collided.lock() {
            collided.extend(still_waiting);
        }
        adopted
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
    ///
    /// Returns whether the vsock CID was CONFIRMED by the live XML. When it
    /// was not, the caller holds the recorded CID unverified: resources may
    /// be charged on a miner-local record, an identity may not — a stale
    /// CID would route this VM's ticket to, and attribute another guest's
    /// frames from, whoever the kernel really gave it to.
    async fn reconcile_handle_with_libvirt(&self, handle: &mut CvmHandle) -> bool {
        let vm = handle.vm_id.as_str().to_string();
        let facts = match self.driver.domain_xml(&handle.domain_id).await {
            Ok(xml) => match adopt::parse_domain_facts(&xml) {
                Ok(facts) => facts,
                Err(err) => {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm} domain XML unparseable ({err}) — \
                         adopting the snapshot's recorded resources unchecked; cid {} UNVERIFIED \
                         (ticket push + relay wait until the live XML confirms it)",
                        handle.cid
                    );
                    return false;
                }
            },
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: re-adopt: vm={vm} dumpxml failed ({err}) — \
                     adopting the snapshot's recorded resources unchecked; cid {} UNVERIFIED \
                     (ticket push + relay wait until the live XML confirms it)",
                    handle.cid
                );
                return false;
            }
        };
        // A customer-keys VM whose snapshot carries no (valid) route: rebuild
        // it from what the live domain was actually started with.
        if handle.guardian.is_none() && !handle.is_infra() {
            handle.guardian = self.rebuild_guardian_route(&handle.vm_id, &facts);
        }
        if facts.vcpus != handle.cpu_count || facts.memory_mib != handle.memory_mb {
            eprintln!(
                "hippius-miner-agent: re-adopt: vm={vm} SNAPSHOT/XML DISAGREE on resources \
                 (snapshot {}c/{}MiB, libvirt {}c/{}MiB) — charging the larger of each",
                handle.cpu_count, handle.memory_mb, facts.vcpus, facts.memory_mib
            );
            handle.cpu_count = handle.cpu_count.max(facts.vcpus);
            handle.memory_mb = handle.memory_mb.max(facts.memory_mib);
        }
        // The XML speaks for THIS VM only if it is the recorded incarnation
        // (same UUID) and it describes a RUNNING domain — re-read liveness
        // after the dump, since a domain that stopped meanwhile yields its
        // inactive config, which proves nothing about the kernel's CID.
        let same_domain = facts.domain_uuid.as_ref() == Some(&handle.domain_uuid);
        if !same_domain {
            eprintln!(
                "hippius-miner-agent: re-adopt: vm={vm} live domain UUID differs from the \
                 snapshot's — not the recorded incarnation; cid {} UNVERIFIED",
                handle.cid
            );
        }
        let live_after = same_domain && self.domain_running_now(&handle.domain_id).await;
        if same_domain && !live_after {
            eprintln!(
                "hippius-miner-agent: re-adopt: vm={vm} domain not running after the XML read — \
                 cid {} UNVERIFIED",
                handle.cid
            );
        }
        let cid_verified = match facts.cid {
            Some(_) if !live_after => false,
            Some(cid) => {
                if cid != handle.cid {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm} SNAPSHOT/XML DISAGREE on vsock cid \
                         (snapshot {}, libvirt {cid}) — reserving the LIVE cid",
                        handle.cid
                    );
                    handle.cid = cid;
                }
                true
            }
            // A domain with no vsock device: there is no kernel CID to
            // confirm. The Infra attestor's placeholder (< MIN_GUEST_CID)
            // is never reserved; anything else stays unverified.
            None => {
                if handle.cid >= crate::vsock::peer::MIN_GUEST_CID {
                    eprintln!(
                        "hippius-miner-agent: re-adopt: vm={vm} live XML has NO vsock device — \
                         cid {} UNVERIFIED",
                        handle.cid
                    );
                }
                false
            }
        };
        // Another incarnation's disk path must never become this handle's:
        // §24 `destroy` unlinks it.
        if let Some(disk) = facts.writable_disk.filter(|_| same_domain) {
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
        cid_verified
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
            // Hashes the boot artifacts — done before the lock.
            let guardian_route = self.rebuild_guardian_route(&vm_id, &facts);
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
                        // No sidecar: the route, if any, comes from the
                        // live cmdline (absent ⇒ the relay refuses this CID).
                        guardian: guardian_route,
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
                    guardian: None,
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
                Ok(()) => {
                    // Kernel-bound now — see the tenant `run_domain`.
                    let _ = self.cids.mark_verified(&config.vm_id, config.cid);
                    break;
                }
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
    /// Pin `vm_id`'s phase — for tests that need a phase the mock
    /// lifecycle only passes through transiently (e.g. `Launching`).
    #[cfg(test)]
    pub(crate) fn force_phase_for_tests(&self, vm_id: &VmId, phase: CvmPhase) {
        self.set_phase(vm_id, phase).unwrap();
    }

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
            return Err(MinerAgentError::InsufficientDisk);
        }
        Ok(())
    }

    /// Read-only MEASURED disk-space check (no reservation) — the preflight
    /// twin of the free-space gate the launch runs when it creates the
    /// disk (`data_disk` / `golden`, serialised by `disk_space`).
    ///
    /// Refuses `InsufficientDisk` when `add_disk_gb` GiB would not fit in
    /// the free space of `data_disk_root` net of every existing writable
    /// disk's unwritten sparse tail — BEFORE vali mints + KBS-registers, so
    /// vali re-places. A VM whose writable disk already exists here (a
    /// relaunch) needs no new space and is never refused. `0` GiB, or a
    /// filesystem that can't be measured, never refuses here: the launch
    /// gate still runs, and fails closed.
    pub fn check_disk_space(&self, vm_id: &VmId, add_disk_gb: u32) -> Result<()> {
        if add_disk_gb == 0
            || data_disk::data_disk_path(&self.data_disk_root, vm_id).exists()
            || golden::overlay_disk_path(&self.data_disk_root, vm_id).exists()
        {
            return Ok(());
        }
        let reserved = *disk_space::create_lock();
        let Ok(headroom) =
            disk_space::headroom_bytes(reserved, &self.data_disk_root, &self.data_disk_root)
        else {
            return Ok(());
        };
        if headroom < u64::from(add_disk_gb).saturating_mul(1024 * 1024 * 1024) {
            return Err(MinerAgentError::InsufficientDisk);
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

    /// SEV-ES ASID fail-fast at PREFLIGHT (capacity v2 §2.3) — same
    /// pre-register rationale as [`Self::check_cpu_mem_budget`]: an
    /// exhausted ASID pool otherwise fails the launch inside
    /// `sev_common_kvm_init`, after the KBS registered the VM, where vali
    /// cannot re-place cleanly.
    ///
    /// A TENANT launch is refused `InsufficientResources` when starting
    /// it would eat into the ASID reserve kept for the host-attestor / a
    /// migration destination (`used + 1 > capacity - 1`, see
    /// [`crate::sev_asid::AsidUsage::admits_tenant`]). The Infra
    /// host-attestor is NEVER refused here — the reserve exists for it.
    /// An unknown pool (no `misc` controller / no `sev_es` key) never
    /// gates.
    pub fn check_asid_budget(&self, profile: DomainProfile) -> Result<()> {
        if profile.is_infra() {
            return Ok(());
        }
        let reservations = self
            .asid_reservations
            .lock()
            .map_err(|_| MinerAgentError::InsufficientResources)?;
        self.asid_admits(&reservations, None)
    }

    /// [`Self::check_asid_budget`] that also RESERVES one ASID for
    /// `vm_id` until its launch ends ([`Self::release_asid_reservation`])
    /// or [`ASID_RESERVATION_TTL`] passes — so concurrent preflights at
    /// the edge of the pool cannot all pass. A repeat for the same
    /// `vm_id` refreshes its own reservation instead of counting twice.
    pub fn reserve_asid(&self, vm_id: &VmId, profile: DomainProfile) -> Result<()> {
        if profile.is_infra() {
            return Ok(());
        }
        let mut reservations = self
            .asid_reservations
            .lock()
            .map_err(|_| MinerAgentError::InsufficientResources)?;
        let now = std::time::Instant::now();
        reservations.retain(|_, at| now.duration_since(*at) < ASID_RESERVATION_TTL);
        self.asid_admits(&reservations, Some(vm_id))?;
        reservations.insert(vm_id.clone(), now);
        Ok(())
    }

    /// Drop `vm_id`'s ASID reservation — its launch ended (the guest now
    /// holds a real ASID that `misc.current` counts, or it never started).
    pub fn release_asid_reservation(&self, vm_id: &VmId) {
        if let Ok(mut reservations) = self.asid_reservations.lock() {
            reservations.remove(vm_id);
        }
    }

    fn asid_admits(
        &self,
        reservations: &HashMap<VmId, std::time::Instant>,
        own: Option<&VmId>,
    ) -> Result<()> {
        let usage = self.asids.read();
        let outstanding = reservations.keys().filter(|k| Some(*k) != own).count();
        let pending = crate::sev_asid::AsidUsage {
            capacity: usage.capacity,
            used: usage
                .used
                .saturating_add(u32::try_from(outstanding).unwrap_or(u32::MAX)),
        };
        if pending.admits_tenant() {
            Ok(())
        } else {
            Err(MinerAgentError::InsufficientResources)
        }
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

    /// Register a new ticket re-push task for `vm_id` and return its
    /// cancellation token. Supersedes (cancels) any task still running for
    /// the same VM — a fresh `Started` restarts the boot window, and two
    /// tasks racing the same listener buy nothing.
    pub fn begin_ticket_push(&self, vm_id: &VmId) -> CancellationToken {
        let token = CancellationToken::new();
        if let Ok(mut pushes) = self.ticket_pushes.lock() {
            if let Some(prev) = pushes.insert(vm_id.clone(), token.clone()) {
                prev.cancel();
            }
        } else {
            // Poisoned: we cannot track the task, so it must not run.
            token.cancel();
        }
        token
    }

    /// Record that a push of `cose_ticket` to `cid` reached `vm_id`'s
    /// guest — by the launch or by the reboot-watcher's re-push.
    pub fn note_ticket_delivered(&self, vm_id: &VmId, cid: u32, cose_ticket: &[u8]) {
        self.note_ticket_delivery(vm_id, cid, cose_ticket, true);
    }

    /// Record that the launch's own push of `cose_ticket` to `cid` failed.
    pub fn note_ticket_push_failed(&self, vm_id: &VmId, cid: u32, cose_ticket: &[u8]) {
        self.note_ticket_delivery(vm_id, cid, cose_ticket, false);
    }

    fn note_ticket_delivery(&self, vm_id: &VmId, cid: u32, cose_ticket: &[u8], delivered: bool) {
        let Ok(mut map) = self.ticket_delivery.lock() else {
            return;
        };
        let entry = map.entry(vm_id.clone()).or_default();
        if entry.cid != cid || entry.cose_ticket != cose_ticket {
            *entry = TicketDelivery {
                cid,
                cose_ticket: cose_ticket.to_vec(),
                ..TicketDelivery::default()
            };
        }
        if delivered {
            entry.delivered = true;
        } else {
            entry.launch_push_failed = true;
        }
    }

    /// Whether `vm_id`'s current ticket reached its guest (as far as this
    /// process saw).
    pub fn ticket_delivered(&self, vm_id: &VmId) -> bool {
        self.current_delivery(vm_id).is_some_and(|d| d.delivered)
    }

    /// Whether the reboot-watcher still has a live re-push task for
    /// `vm_id` (it cancels its own token when it gives up). Unknown reads
    /// as live, so a caller waiting on it never stops a domain early.
    pub fn ticket_repush_active(&self, vm_id: &VmId) -> bool {
        self.ticket_pushes
            .lock()
            .map(|p| p.get(vm_id).is_some_and(|t| !t.is_cancelled()))
            .unwrap_or(true)
    }

    /// The delivery record for `vm_id`, iff it is about the CID + ticket
    /// the VM runs on now.
    fn current_delivery(&self, vm_id: &VmId) -> Option<TicketDelivery> {
        let (cid, ticket) = {
            let handles = self.handles.lock().ok()?;
            let h = handles.get(vm_id)?;
            (h.cid, h.cose_ticket.clone())
        };
        let map = self.ticket_delivery.lock().ok()?;
        map.get(vm_id)
            .filter(|d| d.cid == cid && d.cose_ticket == ticket)
            .cloned()
    }

    /// Cancel `vm_id`'s ticket re-push task, if any.
    fn cancel_ticket_push(&self, vm_id: &VmId) {
        match self.ticket_pushes.lock() {
            Ok(mut pushes) => {
                if let Some(token) = pushes.remove(vm_id) {
                    token.cancel();
                }
            }
            Err(_) => eprintln!(
                "hippius-miner-agent: lifecycle: ticket_pushes lock poisoned — \
                 vm {vm_id} re-push not cancelled (the per-attempt ownership guard still holds)"
            ),
        }
    }

    /// Free `vm_id`'s AF_VSOCK CID — AFTER cancelling any ticket re-push
    /// still aimed at it. The order is the point: once the CID is free the
    /// next launch may get it, and a push that is still connecting would
    /// hand this VM's ticket to that new tenant's initramfs (KBS 403, no
    /// retry — the new VM is bricked).
    fn release_cid(&self, vm_id: &VmId) {
        self.cancel_ticket_push(vm_id);
        // The VM's run is over: drop what was observed of it.
        self.guest_runs.forget(vm_id);
        // Only once the domain is confirmed down: a stop that fails keeps
        // the VM, and with it what is known about its ticket.
        if let Ok(mut map) = self.ticket_delivery.lock() {
            map.remove(vm_id);
        }
        if let Ok(mut checks) = self.cid_checks.lock() {
            checks.remove(vm_id);
        }
        let _ = self.cids.release(vm_id);
        // A stop/destroy of the VM whose (possibly stale) claim blocked a
        // survivor frees the CID without any verification verdict.
        if self.readopt_collided.lock().is_ok_and(|c| !c.is_empty()) {
            self.readopt_retry_due
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Whether blocked survivors are waiting for a retry that is due — the
    /// verify loop runs even with no unverified CID left in that case.
    pub fn readopt_retry_due(&self) -> bool {
        self.readopt_retry_due
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Queue `vm_id`'s unverified CID for [`Self::verify_pending_cids`],
    /// due immediately.
    fn schedule_cid_check(&self, vm_id: &VmId) {
        if let Ok(mut checks) = self.cid_checks.lock() {
            checks.insert(
                vm_id.clone(),
                CidCheck {
                    generation: CID_CHECK_GENERATION
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    failures: 0,
                    next_at: std::time::Instant::now(),
                    last_class: "re-adopt",
                },
            );
        }
    }

    /// Make `vm_id`'s pending CID check due now — the reboot-watcher calls
    /// this on `Started`: a restarted guest is waiting (bounded) for its
    /// ticket, which waits on this verification.
    pub fn expedite_cid_check(&self, vm_id: &VmId) {
        if let Ok(mut checks) = self.cid_checks.lock() {
            if let Some(check) = checks.get_mut(vm_id) {
                check.next_at = std::time::Instant::now();
            }
        }
    }

    /// Number of re-adopted CIDs still awaiting confirmation.
    pub fn unverified_cid_count(&self) -> usize {
        self.cid_checks.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Try to confirm every unverified re-adoption CID that is due at
    /// `now` against the live domain XML:
    ///
    /// - XML shows the recorded CID → mark it verified.
    /// - XML shows a DIFFERENT CID → re-key the handle + allocator to the
    ///   live one (verified).
    /// - the domain is no longer DEFINED → drop the handle and free the CID.
    ///   Only "gone", never "shut off": a guest `reboot` passes through
    ///   shut-off before the reboot-watcher restarts it, and dropping the
    ///   handle then would strand that legitimate restart.
    /// - anything else (dumpxml failed, unparseable, no vsock device,
    ///   libvirt unreachable, re-key collision) → retry after a doubling
    ///   backoff capped at [`CID_VERIFY_MAX_BACKOFF`].
    ///
    /// Logs once per state change, not per attempt. No lock is held across
    /// an `.await`.
    pub async fn verify_pending_cids(&self, now: std::time::Instant) -> Vec<(VmId, CidVerdict)> {
        let due: Vec<VmId> = match self.cid_checks.lock() {
            Ok(checks) => checks
                .iter()
                .filter(|(_, c)| c.next_at <= now)
                .map(|(vm, _)| vm.clone())
                .collect(),
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::with_capacity(due.len());
        for vm_id in due {
            let Some(generation) = self
                .cid_checks
                .lock()
                .ok()
                .and_then(|c| c.get(&vm_id).map(|c| c.generation))
            else {
                continue; // dropped since it was listed as due
            };
            // `virsh` has no timeout of its own; one hung call must not
            // stall every other survivor's verification behind it.
            let verdict = match tokio::time::timeout(
                CID_VERIFY_ATTEMPT_TIMEOUT,
                self.verify_one_cid(&vm_id, now),
            )
            .await
            {
                Ok(verdict) => verdict,
                Err(_) => {
                    // Back off from NOW, not from the attempt's start — the
                    // attempt itself already took the whole timeout.
                    let now = now.max(std::time::Instant::now());
                    self.record_cid_failure(&vm_id, generation, "timeout", now);
                    CidVerdict::Pending
                }
            };
            out.push((vm_id, verdict));
        }
        let claim_moved = out
            .iter()
            .any(|(_, v)| matches!(v, CidVerdict::Rekeyed | CidVerdict::Dropped));
        let release_seen = self
            .readopt_retry_due
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        if claim_moved || release_seen {
            self.retry_collided_readoptions().await;
        }
        out
    }

    /// Back off `vm_id`'s pending check after a failed attempt, logging the
    /// class only when it changed. `generation` must still be the queued
    /// one — a check superseded meanwhile is left alone.
    fn record_cid_failure(
        &self,
        vm_id: &VmId,
        generation: u64,
        class: &'static str,
        now: std::time::Instant,
    ) {
        let Ok(mut checks) = self.cid_checks.lock() else {
            return;
        };
        let Some(check) = checks.get_mut(vm_id).filter(|c| c.generation == generation) else {
            return;
        };
        check.failures = check.failures.saturating_add(1);
        let delay = CidCheck::backoff(check.failures);
        check.next_at = now + delay;
        if check.last_class != class {
            eprintln!(
                "hippius-miner-agent: cid-verify: vm={vm_id} still UNVERIFIED ({class}) — \
                 retrying with backoff (next in {} s)",
                delay.as_secs()
            );
            check.last_class = class;
        }
    }

    async fn verify_one_cid(&self, vm_id: &VmId, now: std::time::Instant) -> CidVerdict {
        let snapshot = self.lock_handles().ok().and_then(|h| {
            h.get(vm_id)
                .map(|h| (h.domain_id.clone(), h.domain_uuid.clone(), h.cid))
        });
        let generation = self
            .cid_checks
            .lock()
            .ok()
            .and_then(|c| c.get(vm_id).map(|c| c.generation));
        let (Some((domain_id, uuid, held)), Some(generation)) = (snapshot, generation) else {
            // Stopped / destroyed meanwhile — its CID went with it.
            self.forget_cid_check(vm_id);
            return CidVerdict::Dropped;
        };
        let current = CheckIdentity {
            generation,
            uuid: &uuid,
            held,
        };
        let class = match self.domain_liveness(&domain_id).await {
            DomainLiveness::Live => match self.read_live_cid(&domain_id, &uuid).await {
                Ok(live) if live == held => {
                    if self.commit_verified(vm_id, &current) {
                        eprintln!(
                            "hippius-miner-agent: cid-verify: vm={vm_id} cid={held} VERIFIED \
                             against the live domain XML — ticket push + relay resume"
                        );
                        return CidVerdict::Verified;
                    }
                    "superseded"
                }
                Ok(live) => {
                    if self.commit_rekey(vm_id, &current, live) {
                        eprintln!(
                            "hippius-miner-agent: cid-verify: vm={vm_id} RE-KEYED cid {held} → \
                             {live} (the live domain XML wins; the recorded cid is burned)"
                        );
                        return CidVerdict::Rekeyed;
                    }
                    "rekey-refused"
                }
                Err(class) => class,
            },
            // Not running: its XML is the INACTIVE config and proves nothing
            // about which CID the kernel holds. Gone only if undefined — a
            // guest `reboot` passes through shut-off before the
            // reboot-watcher restarts it, and dropping the handle then would
            // strand that legitimate restart.
            DomainLiveness::Down => match self.tenant_domain_defined(vm_id).await {
                Some(false) => {
                    if self.commit_drop(vm_id, &current) {
                        eprintln!(
                            "hippius-miner-agent: cid-verify: vm={vm_id} domain no longer \
                             defined — handle DROPPED, cid {held} freed"
                        );
                        return CidVerdict::Dropped;
                    }
                    "superseded"
                }
                Some(true) => "not-running",
                None => "libvirt-unreachable",
            },
            DomainLiveness::Unknown => "libvirt-unreachable",
        };
        self.record_cid_failure(vm_id, generation, class, now);
        CidVerdict::Pending
    }

    fn forget_cid_check(&self, vm_id: &VmId) {
        if let Ok(mut checks) = self.cid_checks.lock() {
            checks.remove(vm_id);
        }
    }

    /// The vsock CID of the RUNNING domain `domain_id`, read from its XML
    /// and bracketed by liveness: the domain must be live after the read
    /// too, so the XML described the running QEMU and not an inactive
    /// config. Its UUID must match the handle's — a same-name domain
    /// re-created meanwhile is a different guest.
    async fn read_live_cid(
        &self,
        domain_id: &DomainId,
        uuid: &DomainUuid,
    ) -> std::result::Result<u32, &'static str> {
        let xml = self
            .driver
            .domain_xml(domain_id)
            .await
            .map_err(|_| "dumpxml")?;
        let facts = adopt::parse_domain_facts(&xml).map_err(|_| "unparseable")?;
        match facts.domain_uuid.as_ref() {
            Some(u) if u == uuid => {}
            Some(_) => return Err("uuid-mismatch"),
            None => return Err("no-uuid"),
        }
        let live = facts.cid.ok_or("no-vsock")?;
        if !self.domain_running_now(domain_id).await {
            return Err("not-running");
        }
        Ok(live)
    }

    /// Whether `virsh domstate` DIRECTLY reports `domain_id` running — the
    /// standard for "this XML describes a running QEMU". Stricter than
    /// [`Self::domain_liveness`], whose `list_domains` fallback reports
    /// any listed domain `Live` whatever its state: fine for "is it still
    /// there", not proof that the XML is the live config.
    async fn domain_running_now(&self, domain_id: &DomainId) -> bool {
        matches!(
            self.driver.query_domain_state(domain_id).await,
            Ok(DomainState::Running
                | DomainState::Blocked
                | DomainState::Paused
                | DomainState::Shutdown
                | DomainState::PmSuspended)
        )
    }

    /// Whether the check a verification attempt started from is still the
    /// one in force: same generation queued, same handle (UUID) holding the
    /// same CID. Called with the handle lock held (lock order: handles →
    /// cid_checks, as everywhere else).
    fn check_is_current(
        &self,
        handles: &HashMap<VmId, CvmHandle>,
        vm_id: &VmId,
        current: &CheckIdentity<'_>,
    ) -> bool {
        let handle_same = handles
            .get(vm_id)
            .is_some_and(|h| &h.domain_uuid == current.uuid && h.cid == current.held);
        handle_same
            && self.cid_checks.lock().is_ok_and(|c| {
                c.get(vm_id)
                    .is_some_and(|c| c.generation == current.generation)
            })
    }

    fn commit_verified(&self, vm_id: &VmId, current: &CheckIdentity<'_>) -> bool {
        let Ok(handles) = self.lock_handles() else {
            return false;
        };
        if !self.check_is_current(&handles, vm_id, current) {
            return false;
        }
        if !matches!(self.cids.mark_verified(vm_id, current.held), Ok(true)) {
            return false;
        }
        self.forget_cid_check(vm_id);
        true
    }

    /// Move `vm_id`'s handle + allocator mapping from the held CID to
    /// `live`, under the handle lock so no push reads a half-moved pair.
    fn commit_rekey(&self, vm_id: &VmId, current: &CheckIdentity<'_>, live: u32) -> bool {
        let Ok(mut handles) = self.lock_handles() else {
            return false;
        };
        if !self.check_is_current(&handles, vm_id, current) {
            return false;
        }
        if self.cids.rekey_verified(vm_id, current.held, live).is_err() {
            return false;
        }
        if let Some(handle) = handles.get_mut(vm_id) {
            handle.cid = live;
        }
        self.forget_cid_check(vm_id);
        true
    }

    /// The domain of an unverified re-adoption is gone: stop tracking it.
    /// The sidecar goes too — its only purpose was re-adopting a live
    /// domain, and an undefined one can never be restarted from it.
    fn commit_drop(&self, vm_id: &VmId, current: &CheckIdentity<'_>) -> bool {
        {
            let Ok(mut handles) = self.lock_handles() else {
                return false;
            };
            if !self.check_is_current(&handles, vm_id, current) {
                return false;
            }
            handles.remove(vm_id);
            // Still under the handle lock: a relaunch of the same vm_id
            // cannot re-take the allocator entry between the remove and the
            // release and then have its fresh mapping released by us.
            self.release_cid(vm_id);
        }
        adopt::forget(&self.state_disk_root, vm_id.as_str());
        true
    }

    /// Where `vm_id`'s ticket should go right now: its CURRENT CID and
    /// whether to deliver there, wait, or stop. A re-push task resolves
    /// this every attempt rather than trusting the CID it saw at `Started`
    /// — a re-adopted CID can be re-keyed to the live one, and a launch's
    /// CID can be re-allocated after an orphan collision.
    pub fn ticket_push_target(&self, vm_id: &VmId, cose_ticket: &[u8]) -> (TicketPushState, u32) {
        let cid = match self.handles.lock() {
            Ok(handles) => match handles.get(vm_id) {
                Some(h) => h.cid,
                None => return (TicketPushState::Abort, 0),
            },
            Err(_) => return (TicketPushState::Abort, 0),
        };
        (self.ticket_push_state(vm_id, cid, cose_ticket), cid)
    }

    /// Whether `cose_ticket` may be pushed to `cid` on behalf of `vm_id`
    /// right now: the VM is tracked and `Running`, its handle still holds
    /// exactly this `cid` and this ticket, and the CID allocator agrees
    /// `cid` belongs to `vm_id`.
    ///
    /// The ownership guard every ticket push re-checks before each connect
    /// and before the write ([`crate::vsock::ticket_push::TicketPusher::
    /// push_guarded`]). A CID is only an address: after a stop it is free
    /// and the next launch may take it, so "the CID I captured when I
    /// started pushing" is NOT "this VM's guest".
    pub fn ticket_push_current(&self, vm_id: &VmId, cid: u32, cose_ticket: &[u8]) -> bool {
        self.ticket_push_state(vm_id, cid, cose_ticket) == TicketPushState::Deliver
    }

    /// [`Self::ticket_push_current`], distinguishing a VM that is still
    /// `Launching` on this CID + ticket (`Wait`) from one that will never
    /// own them again (`Abort`).
    ///
    /// `Launching` is not deliverable: the CID is only SELECTED there — a
    /// `create_domain` that finds an orphan qemu still bound to it burns it
    /// and re-allocates — so the guest behind it is not yet provably this
    /// VM's. The libvirt `Started` event of a fresh launch fires in that
    /// phase, which is why its re-push task waits rather than gives up.
    pub fn ticket_push_state(&self, vm_id: &VmId, cid: u32, cose_ticket: &[u8]) -> TicketPushState {
        let phase = {
            let Ok(handles) = self.handles.lock() else {
                return TicketPushState::Abort;
            };
            match handles.get(vm_id) {
                Some(h)
                    if h.cid == cid
                        && !h.cose_ticket.is_empty()
                        && h.cose_ticket == cose_ticket =>
                {
                    h.phase
                }
                _ => return TicketPushState::Abort,
            }
        };
        let owner = match self.cids.owner_of(cid) {
            Ok(owner) => owner,
            Err(_) => return TicketPushState::Abort,
        };
        match (owner, phase) {
            (CidOwner::Verified(o), CvmPhase::Running) if &o == vm_id => TicketPushState::Deliver,
            (CidOwner::Verified(o), CvmPhase::Launching) if &o == vm_id => TicketPushState::Wait,
            // A re-adopted VM whose CID the live XML has not confirmed yet:
            // not deliverable, not hopeless — verification may confirm or
            // re-key it.
            (CidOwner::Unverified(o), CvmPhase::Running) if &o == vm_id => TicketPushState::Wait,
            // A fresh launch whose `create_domain` has not yet marked its CID
            // verified — the libvirt `Started` event can beat that mark.
            (CidOwner::Unverified(o), CvmPhase::Launching) if &o == vm_id => TicketPushState::Wait,
            _ => TicketPushState::Abort,
        }
    }

    /// Rebuild a customer-keys VM's [`guardian::GuardianRoute`] from its
    /// LIVE domain XML, for a re-adoption whose snapshot has none (an
    /// orphan, a pre-route or a damaged snapshot).
    ///
    /// Only when the live `<cmdline>` carries a customer-keys binding
    /// (`hippius.key_mode=split|customer`): the endpoint is the MEASURED
    /// `hippius.guardian_ep=` token, DECODED from its hex (the route, like
    /// the order, holds the plain canonical string), and the recipe is
    /// recomputed from the
    /// domain's actual `<loader>` / `<kernel>` / `<initrd>` / `<cmdline>`
    /// and `<vcpu>` — never from anything the miner merely recorded. Any
    /// failure is logged loudly and yields `None`: a route is never
    /// invented, and without one the relay refuses the CID.
    fn rebuild_guardian_route(
        &self,
        vm_id: &VmId,
        facts: &adopt::DomainFacts,
    ) -> Option<guardian::GuardianRoute> {
        let fail = |why: &str| {
            eprintln!(
                "hippius-miner-agent: re-adopt: vm={vm_id} customer-keys VM WITHOUT a guardian \
                 route ({why}) — the guardian relay will REFUSE it until it is relaunched"
            );
            None
        };
        let Some(boot) = facts.boot.as_ref() else {
            // No direct-boot block: nothing to read a key mode from. Only
            // worth a line if the snapshot said nothing either — which is
            // every M0 VM, so stay quiet.
            return None;
        };
        let binding = match hippius_types::guardian::GuardianBinding::from_cmdline(&boot.cmdline) {
            Ok(None) => return None, // M0: no guardian, nothing to rebuild.
            Ok(Some(b)) => b,
            Err(_) => return fail("live cmdline refused by the guardian grammar"),
        };
        let endpoint = binding.endpoint.to_wire();
        if guardian::check_order_guardian(&boot.cmdline, Some(&endpoint)).is_err() {
            return fail("live guardian endpoint not dialable");
        }
        let inputs = guardian::RecipeInputs {
            ovmf: boot.ovmf.clone(),
            kernel: boot.kernel.clone(),
            initrd: boot.initrd.clone(),
            cmdline: boot.cmdline.clone(),
            vcpus: u32::from(facts.vcpus),
        };
        let route = match self.digest.recipe(&inputs) {
            Ok(recipe) => guardian::GuardianRoute { endpoint, recipe },
            Err(_) => return fail("recipe could not be recomputed from the live artifacts"),
        };
        if route.validate().is_err() {
            return fail("rebuilt route failed validation");
        }
        eprintln!(
            "hippius-miner-agent: re-adopt: vm={vm_id} guardian route REBUILT from the live \
             domain (endpoint {})",
            route.endpoint
        );
        Some(route)
    }

    /// Resolve a guardian-relay connection's source CID to the VM that
    /// owns it NOW and that VM's [`guardian::GuardianRoute`].
    ///
    /// The CID is only an address: after a stop it is freed and the next
    /// launch may take it, so nothing about a CID is cached across
    /// connections. Every connection re-reads, under ONE `handles` lock
    /// (taken before the allocator's, the order `launch` uses), that:
    ///
    /// - the allocator holds the CID **verified** for a VM (a fresh
    ///   allocation stays unverified until `create_domain` proves the
    ///   domain was built on it; a re-adoption until the live XML
    ///   confirms it) — `cid-unverified` / `unknown-cid` otherwise;
    /// - that VM's handle still records exactly this CID, is a tenant, and
    ///   is `Launching` or `Running` — `cid-not-current` otherwise;
    /// - it was launched with a guardian — `no-guardian` otherwise.
    ///
    /// Stops and launches change the handle and the allocator under the
    /// same lock, so a replaced domain's route can never be returned for
    /// its successor's CID.
    pub fn guardian_route_for_cid(
        &self,
        cid: u32,
    ) -> std::result::Result<guardian::RouteBinding, &'static str> {
        let handles = self.handles.lock().map_err(|_| "cid-lookup")?;
        let vm_id = match self.cids.owner_of(cid).map_err(|_| "cid-lookup")? {
            CidOwner::Verified(vm_id) => vm_id,
            CidOwner::Unverified(_) => return Err("cid-unverified"),
            CidOwner::Unknown => return Err("unknown-cid"),
        };
        let handle = handles.get(&vm_id).ok_or("cid-not-current")?;
        let live = matches!(handle.phase, CvmPhase::Launching | CvmPhase::Running);
        if handle.cid != cid || handle.is_infra() || !live {
            return Err("cid-not-current");
        }
        let route = handle.guardian.clone().ok_or("no-guardian")?;
        Ok(guardian::RouteBinding {
            domain: handle.domain_uuid.as_str().to_string(),
            vm_id,
            route,
        })
    }

    /// Whether the reboot-watcher may `virsh start` `vm_id` after a
    /// `Stopped` event: only a tracked CVM in `Running` with a cached
    /// ticket — i.e. one whose QEMU exited on its own (in-guest reboot).
    ///
    /// NOT `Stopping`: `stop` flips the phase to `Stopping` BEFORE it
    /// issues `virsh destroy`, so every agent-initiated stop (a §24
    /// force-stop included) produces a `Stopped` event while the handle
    /// still exists. Gating on the ticket alone let the watcher race
    /// that stop and restart the very domain being torn down (observed
    /// live: a destroyed tenant came back within ~30 s).
    pub fn restart_eligible(&self, vm_id: &VmId) -> bool {
        let Ok(handles) = self.handles.lock() else {
            return false;
        };
        handles
            .get(vm_id)
            .is_some_and(|h| h.phase == CvmPhase::Running && !h.cose_ticket.is_empty())
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

/// Refuse a relaunch whose per-VM disks are not on this host.
///
/// The same paths the launch then boots from: the anti-rollback state
/// disk always; the golden overlay upper (`/dev/vda`, which golden mode
/// derives into `luks_disk_path`) or the legacy data disk (`/dev/vde`,
/// only when the order carries one). The legacy `/dev/vda` is NOT
/// checked — it is the order-supplied image the launch preflight stages,
/// not a disk this agent creates.
///
/// `try_exists`, not `exists`: an absent file (`Ok(false)`) is the only
/// verdict that means "this host does not hold the VM". A metadata error
/// (EIO, EACCES, a storage mount not up yet after a reboot) proves
/// nothing either way, so it is its own RETRIABLE refusal — reading it as
/// "missing" would make vali give up on a healthy VM.
fn check_relaunch_disks(config: &QemuConfig) -> Result<()> {
    require_disk(&config.state_disk_path, "state-disk")?;
    if config.golden {
        require_disk(&config.luks_disk_path, "overlay")?;
    } else if let Some(data_disk) = &config.data_disk_path {
        require_disk(data_disk, "data-disk")?;
    }
    Ok(())
}

fn require_disk(path: &std::path::Path, which: &'static str) -> Result<()> {
    match path.try_exists() {
        Ok(true) => Ok(()),
        Ok(false) => Err(MinerAgentError::RelaunchDisksMissing(which)),
        Err(_) => Err(MinerAgentError::RelaunchDisksUnreadable(which)),
    }
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
        return Err(MinerAgentError::InsufficientDisk);
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

    fn facts_with_cmdline(cmdline: &str) -> adopt::DomainFacts {
        adopt::DomainFacts {
            vcpus: 2,
            memory_mib: 512,
            cid: Some(7),
            writable_disk: None,
            domain_uuid: None,
            boot: Some(adopt::BootFacts {
                ovmf: "/x/ovmf".into(),
                kernel: "/x/vmlinuz".into(),
                initrd: "/x/initrd".into(),
                cmdline: cmdline.into(),
            }),
        }
    }

    /// H1b: a route rebuilt from the live domain XML holds the DECODED
    /// endpoint (the plain string the relay dials), never the hex token
    /// the cmdline carries; a live cmdline in the old plain spelling
    /// rebuilds nothing.
    #[test]
    fn a_rebuilt_guardian_route_decodes_the_measured_token() {
        let dir = tempfile::tempdir().unwrap();
        let lc = reclaim_lifecycle(dir.path());
        let vm = VmId::new("g-rebuild").unwrap();
        let pk = "ab".repeat(32);
        for ep in ["100.64.0.1:7443", "guardian.example.cc:443"] {
            let cmdline = format!(
                "console=hvc0 hippius.key_mode=customer hippius.guardian_pk={pk} \
                 hippius.guardian_ep={}",
                hex::encode(ep)
            );
            let route = lc
                .rebuild_guardian_route(&vm, &facts_with_cmdline(&cmdline))
                .unwrap();
            assert_eq!(route.endpoint, ep);
            assert_eq!(route.recipe.cmdline, cmdline);
            route.validate().unwrap();
        }
        let plain = format!(
            "console=hvc0 hippius.key_mode=customer hippius.guardian_pk={pk} \
             hippius.guardian_ep=100.64.0.1:7443"
        );
        assert!(lc
            .rebuild_guardian_route(&vm, &facts_with_cmdline(&plain))
            .is_none());
        assert!(lc
            .rebuild_guardian_route(&vm, &facts_with_cmdline("console=hvc0"))
            .is_none());
    }

    /// A route is served only for a verified CID whose handle is a tenant,
    /// records that very CID, is `Launching`/`Running`, and has a guardian.
    #[test]
    fn a_guardian_route_needs_a_live_tenant_handle_on_that_exact_cid() {
        let dir = tempfile::tempdir().unwrap();
        let lc = reclaim_lifecycle(dir.path());
        let vm = VmId::new("g-1").unwrap();
        let route = guardian::GuardianRoute {
            endpoint: "100.64.0.1:7443".into(),
            recipe: hippius_types::guardian::LaunchRecipe {
                ovmf_sha384: vec![1; 48],
                kernel_sha256: vec![2; 32],
                initrd_sha256: vec![3; 32],
                cmdline: "c".into(),
                vcpus: 1,
                vcpu_type: "EpycGenoa".into(),
                guest_features: 1,
            },
        };
        let cid = lc.cids.allocate(&vm).unwrap();
        assert!(lc.cids.mark_verified(&vm, cid).unwrap());
        let put = |phase: CvmPhase, profile: DomainProfile, handle_cid: u32| {
            lc.handles.lock().unwrap().insert(
                vm.clone(),
                CvmHandle {
                    vm_id: vm.clone(),
                    profile,
                    domain_id: DomainId::new("hippius-tenant-g-1").unwrap(),
                    domain_uuid: DomainUuid::generate().unwrap(),
                    phase,
                    launch_digest: [0u8; LAUNCH_DIGEST_LEN],
                    cpu_count: 1,
                    memory_mb: 512,
                    data_disk_size_gb: 0,
                    luks_disk_path: std::path::PathBuf::new(),
                    cid: handle_cid,
                    cose_ticket: vec![1],
                    guardian: Some(route.clone()),
                },
            );
        };
        for phase in [CvmPhase::Launching, CvmPhase::Running] {
            put(phase, DomainProfile::Tenant, cid);
            let b = lc.guardian_route_for_cid(cid).unwrap();
            assert_eq!((b.vm_id, b.route), (vm.clone(), route.clone()));
        }
        for phase in [
            CvmPhase::Pending,
            CvmPhase::LaunchPrep,
            CvmPhase::Stopping,
            CvmPhase::Stopped,
            CvmPhase::Failed,
        ] {
            put(phase, DomainProfile::Tenant, cid);
            assert_eq!(
                lc.guardian_route_for_cid(cid).unwrap_err(),
                "cid-not-current",
                "{phase:?}"
            );
        }
        // The Infra attestor never gets a guardian route.
        put(CvmPhase::Running, DomainProfile::Infra, cid);
        assert_eq!(
            lc.guardian_route_for_cid(cid).unwrap_err(),
            "cid-not-current"
        );
        // The handle moved to another CID (re-keyed): the old one is stale.
        put(CvmPhase::Running, DomainProfile::Tenant, cid + 1);
        assert_eq!(
            lc.guardian_route_for_cid(cid).unwrap_err(),
            "cid-not-current"
        );
        // No handle at all for the allocator's owner.
        lc.handles.lock().unwrap().clear();
        assert_eq!(
            lc.guardian_route_for_cid(cid).unwrap_err(),
            "cid-not-current"
        );
    }

    #[test]
    fn the_asid_gate_refuses_tenants_but_never_the_host_attestor() {
        let dir = tempfile::tempdir().unwrap();
        let full = crate::sev_asid::AsidUsage {
            capacity: 99,
            used: 98,
        };
        let lc = reclaim_lifecycle(dir.path())
            .with_asid_source(Arc::new(crate::sev_asid::FixedAsidSource(full)));
        assert!(matches!(
            lc.check_asid_budget(DomainProfile::Tenant),
            Err(MinerAgentError::InsufficientResources)
        ));
        assert!(lc.check_asid_budget(DomainProfile::Infra).is_ok());
        let unknown = reclaim_lifecycle(dir.path()).with_asid_source(Arc::new(
            crate::sev_asid::FixedAsidSource(crate::sev_asid::AsidUsage::default()),
        ));
        assert!(unknown.check_asid_budget(DomainProfile::Tenant).is_ok());
    }

    #[test]
    fn asid_reservations_stop_concurrent_preflights_at_the_pool_edge() {
        // 99 capacity, 96 in use: tenants may reach 98 (one kept back).
        let dir = tempfile::tempdir().unwrap();
        let usage = crate::sev_asid::AsidUsage {
            capacity: 99,
            used: 96,
        };
        let lc = reclaim_lifecycle(dir.path())
            .with_asid_source(Arc::new(crate::sev_asid::FixedAsidSource(usage)));
        let vm = |n: &str| crate::VmId::new(n).unwrap();
        lc.reserve_asid(&vm("a"), DomainProfile::Tenant).unwrap(); // 97
        lc.reserve_asid(&vm("b"), DomainProfile::Tenant).unwrap(); // 98
        assert!(matches!(
            lc.reserve_asid(&vm("c"), DomainProfile::Tenant),
            Err(MinerAgentError::InsufficientResources)
        ));
        // A repeat for the same VM refreshes, it does not count twice.
        lc.reserve_asid(&vm("b"), DomainProfile::Tenant).unwrap();
        // The attestor is never gated, and takes no reservation.
        lc.reserve_asid(&vm("attestor"), DomainProfile::Infra)
            .unwrap();
        // A finished launch frees its promise.
        lc.release_asid_reservation(&vm("a"));
        lc.reserve_asid(&vm("c"), DomainProfile::Tenant).unwrap();
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
        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

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

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

        assert!(
            !staging.exists(),
            "a VM staged under the OLD scheme became unreclaimable by §24"
        );
    }

    #[tokio::test]
    async fn destroy_reclaims_the_vm_backup_work_dir_and_nothing_beside_it() {
        // Seen live 2026-09-24: a test VM's `backup/<vm_id>` survived its §24.
        // The work dir is the ONLY leftover here, so this also proves it
        // counts as a footprint (no early "nothing to reclaim" bail), and
        // that a sibling VM's work dir and the backup root are untouched.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = reclaim_lifecycle(dir.path());
        let vm = VmId::new("tenant-backed-up").unwrap();

        // Literal paths, not `backup_dir()`: a test that derives the path
        // the way the code does would follow any change to it.
        let root = dir.path().join("backup");
        let work = root.join("tenant-backed-up");
        let restore = work.join("restore");
        std::fs::create_dir_all(&restore).unwrap();
        std::fs::write(work.join("inflight.json"), b"{}").unwrap();
        std::fs::write(restore.join("0000.full.raw"), b"piece").unwrap();
        let sibling = root.join("tenant-other");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("inflight.json"), b"{}").unwrap();

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

        assert!(
            work.symlink_metadata().is_err(),
            "the VM's backup work dir was stranded"
        );
        assert!(root.is_dir(), "the backup ROOT must never be removed");
        assert!(
            sibling.join("inflight.json").exists(),
            "another VM's backup work dir must be untouched"
        );
    }

    #[tokio::test]
    async fn destroy_unlinks_a_symlinked_backup_work_dir_as_a_link() {
        // A per-VM backup entry that is a SYMLINK is removed as a link;
        // what it points at is never walked.
        let dir = tempfile::tempdir().unwrap();
        let lifecycle = reclaim_lifecycle(dir.path());
        let vm = VmId::new("tenant-linked").unwrap();

        let target = dir.path().join("shared");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.img"), b"shared").unwrap();
        let root = dir.path().join("backup");
        std::fs::create_dir_all(&root).unwrap();
        let work = root.join("tenant-linked");
        std::os::unix::fs::symlink(&target, &work).unwrap();

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

        assert!(work.symlink_metadata().is_err(), "the link must be removed");
        assert!(
            target.join("keep.img").exists(),
            "the link target must be untouched"
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

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

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
            .destroy(&vm, None)
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

        let err = lifecycle.destroy(&vm, None).await.unwrap_err();
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
        let driver_probe = driver.clone();

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

        let err = lifecycle.destroy(&vm, None).await.unwrap_err();
        assert!(matches!(err, MinerAgentError::Destroy("domain-still-up")));
        assert!(overlay.exists(), "a live guest's disk must NOT be unlinked");
        assert_eq!(
            driver_probe.undefine_count(),
            0,
            "a live guest's domain must NOT be undefined"
        );
    }

    // ── §24 destroy drops the libvirt record ────────────────────────────

    /// A lifecycle over a caller-held mock driver, roots under `dir`.
    fn reclaim_lifecycle_with(
        driver: std::sync::Arc<dyn crate::lifecycle::libvirt_driver::LibvirtDriver>,
        dir: &std::path::Path,
    ) -> CvmLifecycle {
        CvmLifecycle::new(
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
        .with_state_disk_root(dir.to_path_buf())
    }

    fn tenant_domain(vm: &VmId) -> DomainId {
        DomainId::new(&format!("hippius-tenant-{}", vm.as_str())).unwrap()
    }

    #[tokio::test]
    async fn destroy_undefines_the_domain_after_reclaiming_its_disks() {
        // A domain that was already shut off when §24 ran stayed defined
        // forever: only a clean `stop` undefined, and destroy never did.
        let dir = tempfile::tempdir().unwrap();
        let driver =
            std::sync::Arc::new(crate::lifecycle::libvirt_driver::MockLibvirtDriver::new());
        let vm = VmId::new("tenant-shutoff").unwrap();
        driver.seed_domain(tenant_domain(&vm), DomainState::ShutOff);
        let lifecycle = reclaim_lifecycle_with(driver.clone(), dir.path());
        let overlay = lifecycle.golden_overlay_path(&vm);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"ciphertext").unwrap();

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

        assert!(!overlay.exists(), "the overlay must be reclaimed");
        assert_eq!(driver.undefine_count(), 1, "the record must be undefined");
        assert_eq!(
            driver.defined_count().unwrap(),
            0,
            "no stale definition left"
        );
    }

    #[tokio::test]
    async fn destroy_undefines_a_shut_off_domain_whose_disks_are_already_gone() {
        // Seen in production: an earlier destroy
        // reclaimed every file but left the shut-off definition. With
        // nothing on disk the early no-op return used to strand it.
        let dir = tempfile::tempdir().unwrap();
        let driver =
            std::sync::Arc::new(crate::lifecycle::libvirt_driver::MockLibvirtDriver::new());
        let vm = VmId::new("tenant-bare-def").unwrap();
        driver.seed_domain(tenant_domain(&vm), DomainState::ShutOff);
        let lifecycle = reclaim_lifecycle_with(driver.clone(), dir.path());

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("destroy must succeed");

        assert_eq!(driver.undefine_count(), 1);
        assert_eq!(driver.defined_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn destroy_on_a_host_without_the_vm_never_undefines() {
        // The misroute no-op stays pure: no files and no domain here ⇒ no
        // libvirt mutation at all.
        let dir = tempfile::tempdir().unwrap();
        let driver =
            std::sync::Arc::new(crate::lifecycle::libvirt_driver::MockLibvirtDriver::new());
        let lifecycle = reclaim_lifecycle_with(driver.clone(), dir.path());
        let vm = VmId::new("tenant-not-here").unwrap();

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("a misrouted destroy is a no-op");

        assert_eq!(driver.undefine_count(), 0);
        assert_eq!(driver.destroy_count(), 0);
    }

    #[tokio::test]
    async fn an_undefine_failure_does_not_fail_the_destroy() {
        // Data death already happened; failing here would pin the VM in
        // Decommissioning for a leftover libvirt record.
        struct UndefineFails(crate::lifecycle::libvirt_driver::MockLibvirtDriver);
        #[async_trait::async_trait]
        impl crate::lifecycle::libvirt_driver::LibvirtDriver for UndefineFails {
            async fn define_domain(&self, xml: &str) -> Result<DomainId> {
                self.0.define_domain(xml).await
            }
            async fn create_domain(&self, id: &DomainId) -> Result<()> {
                self.0.create_domain(id).await
            }
            async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
                self.0.destroy_domain(id, graceful).await
            }
            async fn undefine_domain(&self, _id: &DomainId) -> Result<()> {
                Err(MinerAgentError::LibvirtDriver("undefine"))
            }
            async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
                self.0.query_domain_state(id).await
            }
            async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
                self.0.list_domains().await
            }
            async fn domain_xml(&self, id: &DomainId) -> Result<String> {
                self.0.domain_xml(id).await
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let inner = crate::lifecycle::libvirt_driver::MockLibvirtDriver::new();
        let vm = VmId::new("tenant-undef-err").unwrap();
        inner.seed_domain(tenant_domain(&vm), DomainState::ShutOff);
        let lifecycle =
            reclaim_lifecycle_with(std::sync::Arc::new(UndefineFails(inner)), dir.path());
        let overlay = lifecycle.golden_overlay_path(&vm);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"ciphertext").unwrap();

        lifecycle
            .destroy(&vm, None)
            .await
            .expect("an undefine error must not fail the destroy");
        assert!(!overlay.exists(), "the reclaim still happened");
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
        // Its own class — a full disk is not a full host.
        assert!(matches!(
            check_capacity(&handles, host, 1, 1024, 128),
            Err(MinerAgentError::InsufficientDisk)
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

#[cfg(test)]
mod cid_check_tests {
    use super::*;

    #[test]
    fn cid_check_backoff_doubles_then_caps() {
        let secs: Vec<u64> = (1..=10).map(|n| CidCheck::backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![5, 10, 20, 40, 80, 120, 120, 120, 120, 120]);
        assert_eq!(CidCheck::backoff(u32::MAX), CID_VERIFY_MAX_BACKOFF);
    }
}
