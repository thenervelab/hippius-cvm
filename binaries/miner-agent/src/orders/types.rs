//! Lifecycle-order types — the launch input the lifecycle consumes,
//! and the signed wire envelope the Edge gateway relays (MA-3 + MA-5).
//!
//! ## Wire shape (MA-5)
//!
//! A lifecycle order arrives at the miner-agent as a [`SignedOrder`] —
//! `{body, sig}`, the same shape as every `hippius-types` `SignedX`
//! wrapper. `body` is the CBOR of an [`OrderBody`] and `sig` is the
//! Edge gateway's detached Ed25519 signature over those exact bytes
//! ([`super::auth`]). [`OrderBody`] carries a domain-separation tag, an
//! `order_id` for idempotency, an [`OrderKind`] discriminant, and the
//! kind-specific `payload`.
//!
//! Every wire struct is `#[serde(deny_unknown_fields)]` and is decoded
//! **straight into the typed shape** — never a `ciborium::Value` — so a
//! deeply-nested or extra-field hostile body is rejected structurally,
//! not by walking an attacker-controlled tree.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::lifecycle::VmId;

/// Domain-separation tag bound into every signed [`OrderBody`]. An
/// Edge order signature cannot be reinterpreted as any other signed
/// payload in the stack, and vice versa — the same discipline as the
/// edge-gateway `TELEMETRY_DOMAIN` and the KBS `RELEASE_DOMAIN`.
pub const ORDER_DOMAIN: &str = "HIPPIUS_MINER_ORDER_V1";

/// The lifecycle command an order carries. Cross-checked against the
/// HTTP route it arrived on — a signed launch body replayed onto the
/// `/stop` route is rejected on the `kind` mismatch (defence in depth;
/// the differing `payload` shapes would already fail the typed decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrderKind {
    /// Provision + launch a tenant CVM.
    Launch,
    /// Stop a running CVM (graceful or forced).
    Stop,
    /// Decommission a CVM — stop + reclaim disk capacity (§24).
    Destroy,
    /// Migrate a CVM to another host (§25) — not yet wired.
    Migrate,
    /// §25 migration **M1** — quiesce the source CVM: cleanly stop its
    /// guest so the writable LUKS volume is crash-consistent + static
    /// before a snapshot. Idempotent (already-stopped ⇒ ok).
    MigrateQuiesce,
    /// §25 migration **M1** — snapshot the source CVM's writable LUKS2 +
    /// dm-integrity volume and stream it (still encrypted) to a
    /// presigned S3 PUT URL. Runs async; progress is read back via the
    /// `GET /v1/miner/migration/{vm_id}/status` route.
    MigrateSnapshot,
    /// §25 migration **M2** — activate the DESTINATION CVM: download the
    /// encrypted LUKS snapshot from a presigned S3 GET URL, write it as
    /// the dest's LUKS volume, recreate the libvirt domain, and boot at
    /// `new_gen`. Only ever dispatched AFTER vali's verified source-ack
    /// fence + the KBS `Migrating{new_gen, dest}` transition.
    MigrateActivate,
    /// Live backup of a running golden VM: copy its overlay (full, or the
    /// clusters written since the chain's last run) without pausing the
    /// guest and upload it + the state disk through presigned URLs. Runs
    /// async; read back via `GET /v1/miner/backup/{vm_id}/status`.
    Backup,
    /// Staged restore of a VM from its backups (`stage` / `abort` /
    /// `reclaim`, see [`crate::backup::staged`]). `stage` runs async;
    /// read back via `GET /v1/miner/restore/{vm_id}/status`.
    Restore,
    /// Pre-launch: fetch tenant artifacts via S3 presigned URLs +
    /// verify SHAs + compute the SNP launch_digest. Returns a JSON
    /// envelope vali parses for the digest before minting the
    /// matching `OrderTicket`. Same Edge signing + idempotency +
    /// freshness window as the other kinds.
    TenantPreflight,
    /// Host-wide guest network policy (egress rules, per-VM caps). Names
    /// no VM; replay is refused by a revision persisted on disk
    /// ([`crate::netpolicy`]).
    NetPolicy,
}

impl OrderKind {
    /// Stable static classifier for log lines.
    pub fn as_class_str(self) -> &'static str {
        match self {
            OrderKind::Launch => "launch",
            OrderKind::Stop => "stop",
            OrderKind::Destroy => "destroy",
            OrderKind::Migrate => "migrate",
            OrderKind::MigrateQuiesce => "migrate-quiesce",
            OrderKind::MigrateSnapshot => "migrate-snapshot",
            OrderKind::MigrateActivate => "migrate-activate",
            OrderKind::Backup => "backup",
            OrderKind::Restore => "restore",
            OrderKind::TenantPreflight => "tenant-preflight",
            OrderKind::NetPolicy => "net-policy",
        }
    }
}

/// The signed wire envelope — `{body, sig}`.
///
/// `body` is the CBOR-encoded [`OrderBody`]; `sig` is the Edge
/// gateway's 64-byte detached Ed25519 signature over `body`. The
/// miner-agent verifies `sig` against the pinned Edge order key BEFORE
/// it decodes `body` into a typed order (see [`super::auth`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOrder {
    /// CBOR-encoded [`OrderBody`]. Opaque from the signature's view.
    pub body: ByteBuf,
    /// Detached Ed25519 signature (64 bytes) over `body`.
    pub sig: ByteBuf,
}

/// The signed order body — what [`SignedOrder::sig`] covers.
///
/// Generic over the kind-specific `payload` so each HTTP route decodes
/// exactly one concrete order type (`OrderBody<LaunchOrder>`,
/// `OrderBody<StopOrder>`, …) with no untagged-enum guesswork.
///
/// ## Cross-miner / long-term replay protection
///
/// `target_miner_id` and `issued_at_unix` were added in the §H phase-2
/// order-dispatch follow-up (review r1 High findings): without them,
/// a signed order intercepted on one miner could be replayed to any
/// other miner (every miner pins the SAME Edge order-signing key), and
/// a captured order would remain valid indefinitely. The miner-agent
/// now binds every order to a specific host AND a freshness window
/// — see `process_order`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBody<T> {
    /// Always [`ORDER_DOMAIN`] — checked before dispatch.
    pub domain: String,
    /// Caller-assigned idempotency key. The same `order_id` processed
    /// twice yields the same outcome, the second a no-op success.
    pub order_id: String,
    /// The command discriminant — cross-checked against the route.
    pub kind: OrderKind,
    /// The miner this order is bound to — the receiving miner-agent
    /// asserts `target_miner_id == self.config.miner.miner_id` AFTER
    /// the signature verifies. Closes the cross-miner replay vector:
    /// a signed `Stop` / `Destroy` order issued to miner A is
    /// cryptographically meaningless to miner B even if intercepted.
    pub target_miner_id: String,
    /// Unix-seconds-since-epoch when vali issued the order. The
    /// miner-agent enforces `|now - issued_at_unix| ≤ MAX_ORDER_AGE_SECS`
    /// (±5 min clock-skew window) to bound the long-term-replay vector:
    /// a captured order older than the window is rejected without
    /// dispatch. Stored as `u64` (a value past 2106 is far beyond the
    /// signing key's expected lifetime).
    pub issued_at_unix: u64,
    /// The kind-specific order.
    pub payload: T,
}

/// A request to launch one tenant SEV-SNP confidential VM.
///
/// Carries the already-separated launch components (Option A,
/// PR-MA-3): the pinned OVMF firmware plus the kernel, initrd and
/// cmdline — the exact tuple the launch digest is measured over. The
/// AF_VSOCK CID is **not** an order field — the miner-agent assigns it
/// locally at launch ([`crate::vsock::peer::CidAllocator`]); an order
/// author never dictates host-local context ids.
///
/// Deliberately not `Debug`: the `cmdline` can carry sensitive launch
/// parameters and must not be formattable into a log line. It is,
/// since MA-5, `Serialize`/`Deserialize` so it can travel as the
/// `payload` of a signed [`OrderBody`] — that does not make it
/// printable.
/// Default rootfs-data path the miner-agent will attach to the guest
/// at `/dev/vdb` if a `LaunchOrder` payload arrives without an
/// explicit `rootfs_data_path` field (older vali deploys). The
/// canonical location is the directory `scripts/tenant-uki-stage-
/// miner.sh` lays the rootfs.img into.
fn default_rootfs_data_path() -> PathBuf {
    PathBuf::from("/var/lib/hippius-miner/rootfs.img")
}

/// Default rootfs-hash path (`/dev/vdc`). See
/// [`default_rootfs_data_path`].
fn default_rootfs_hash_path() -> PathBuf {
    PathBuf::from("/var/lib/hippius-miner/rootfs.verity")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchOrder {
    /// Tenant id for the CVM.
    pub vm_id: VmId,
    /// Pinned, SEV-SNP-capable OVMF firmware.
    pub ovmf_path: PathBuf,
    /// Guest kernel.
    pub kernel_path: PathBuf,
    /// Guest initrd.
    pub initrd_path: PathBuf,
    /// Guest kernel command line.
    pub cmdline: String,
    /// Per-VM LUKS data disk image (under `/var/lib/hippius-miner/`).
    pub luks_disk_path: PathBuf,
    /// LUKS data disk size in GiB.
    pub luks_disk_size_gb: u32,
    /// #365 — tenant **data disk** size in GiB (the flavor's `disk_gb`).
    /// The miner creates a blank sparse raw image of this size and
    /// attaches it at `/dev/vde`; the guest formats it fresh (LUKS2 +
    /// dm-integrity) at first boot. `serde(default)` (⇒ 0) for
    /// backward-compat with vali deploys that pre-date the data disk:
    /// 0 means "no data disk" (no vde attached, no host file created).
    /// New vali deploys set this to `flavor.disk_gb`. NOT a measured
    /// launch input — the disk is blank + guest-keyed; its size is
    /// re-checked in the guest against the measured `hippius.disk_gb=`
    /// cmdline token.
    #[serde(default)]
    pub data_disk_size_gb: u32,
    /// Read-only dm-verity rootfs **data** image (the squashfs the §F
    /// tenant-uki build produces as `rootfs.img`). Attached to the
    /// guest at `/dev/vdb`, paired with [`Self::rootfs_hash_path`] by
    /// the in-guest verity stage.
    ///
    /// `serde(default)` for backward-compat with vali deploys that
    /// pre-date the rootfs disk wiring — an absent field becomes the
    /// canonical staging path. New vali deploys ALWAYS set this
    /// explicitly via `--rootfs-data-path` / `build_launch_payload`.
    #[serde(default = "default_rootfs_data_path")]
    pub rootfs_data_path: PathBuf,
    /// Read-only dm-verity rootfs **hash tree** (`rootfs.verity` from
    /// the §F tenant-uki build). Attached at `/dev/vdc`. Same
    /// `serde(default)` rationale as [`Self::rootfs_data_path`].
    #[serde(default = "default_rootfs_hash_path")]
    pub rootfs_hash_path: PathBuf,
    /// vCPU count.
    pub cpu_count: u8,
    /// Guest RAM in MiB.
    pub memory_mb: u32,
    /// COSE_Sign1 envelope of the L1-minted OrderTicket (§6). Opaque to
    /// the miner-agent — it is forwarded byte-for-byte to the guest
    /// initramfs over the host→guest vsock channel
    /// (`hippius_types::ticket_vsock::PORT`) after the launch reaches
    /// `Running`.
    ///
    /// **Why on the LaunchOrder.** The kernel cmdline and any
    /// `-fw_cfg` blob fold into the §22 launch_digest, so per-launch
    /// ticket bytes there would explode the allowlist (one entry per
    /// launch). The vsock push is a runtime — measurement-neutral —
    /// channel, and travelling alongside the launch order keeps the
    /// dispatch atomic: no operator-pre-stage step that could drift
    /// from the dispatched `vm_id`, no side-channel HTTP that needs
    /// its own auth model. Edge re-signs the whole `OrderBody` so the
    /// addition is a `serde` field-set extension only; no Edge
    /// wire-protocol change.
    pub cose_ticket: ByteBuf,
    /// This order RELAUNCHES a VM that already ran on this host (vali's
    /// reboot-recovery and the power API's `start`): its per-VM disks —
    /// the anti-rollback state disk, and the golden overlay upper or the
    /// legacy data disk — must ALREADY be here. `true` makes the launch
    /// refuse with [`crate::error::MinerAgentError::RelaunchDisksMissing`]
    /// instead of creating a blank one: a blank state disk resets the
    /// boot counter the KBS checks, and a blank golden overlay is
    /// `luksFormat`ted by the guest on the first boot that gets a KEK —
    /// a relaunch onto a host that never held the data would destroy
    /// the tenant's disk rather than fail.
    ///
    /// Not measured (the launch digest covers ovmf / kernel / initrd /
    /// cmdline / vcpus only) and not part of the L1 ticket. `serde
    /// (default)` ⇒ `false` = first launch, the pre-existing behaviour;
    /// encoded ONLY when `true`, so a first-launch body is byte-identical
    /// to before and an agent too old to know the field rejects a
    /// relaunch at decode (`deny_unknown_fields`) — fail-closed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_existing_disks: bool,
    /// Customer-held keys (M1/M2): the canonical `host:port` of the VM's
    /// key guardian — the ONLY destination the guardian vsock relay
    /// ([`crate::vsock::guardian_relay`]) dials for this VM's CID.
    ///
    /// Must be the canonical spelling ([`hippius_types::guardian::
    /// GuardianEndpoint`]) and equal the MEASURED `hippius.guardian_ep=`
    /// cmdline token once DECODED (the cmdline carries the lowercase hex
    /// of this string; this field stays plain); a customer-keys cmdline
    /// without it, or it without a
    /// customer-keys cmdline, refuses the launch (see
    /// [`crate::lifecycle::guardian::check_order_guardian`]). Not
    /// measured itself, not part of the L1 ticket.
    ///
    /// `serde(default)` ⇒ `None` = M0, and encoded ONLY when set: an M0
    /// launch body is byte-identical to before, and an agent too old to
    /// know the key refuses a customer-keys launch at decode
    /// (`deny_unknown_fields`) — fail-closed, which is why miner-agents
    /// deploy BEFORE vali.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_ep: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A request to stop a running tenant CVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopOrder {
    /// The CVM to stop.
    pub vm_id: VmId,
    /// `true` asks for an ACPI shutdown with a force-destroy fallback;
    /// `false` force-destroys at once.
    pub graceful: bool,
}

/// A request to decommission a tenant CVM (§24) — stop it and reclaim
/// the disk capacity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestroyOrder {
    /// The CVM to destroy.
    pub vm_id: VmId,
}

/// A request to migrate a tenant CVM to another host (§25).
///
/// MA-5 ships the type + the authenticated, idempotent route; the
/// migration mechanics (quiesce proof, manifest-chained snapshot,
/// generation CAS) are a dedicated follow-up — the handler returns
/// `NotYetWired`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateOrder {
    /// The CVM to migrate.
    pub vm_id: VmId,
}

/// §25 migration **M1** — quiesce the SOURCE CVM.
///
/// Cleanly stops the guest (ACPI shutdown with a bounded force-destroy
/// fallback) so its writable LUKS volume is crash-consistent and static
/// for the subsequent snapshot. Idempotent: a quiesce of an
/// already-stopped (or untracked) CVM is a success no-op.
///
/// `node_id` is carried for symmetry with the vali §25 relay effect
/// (`vali/apps/orchestration/effects.py::relay_quiesce` posts
/// `{"node_id": vm.host}`); the SOURCE binding the miner actually
/// enforces is the signed [`OrderBody::target_miner_id`] check, so
/// `node_id` here is audit/correlation metadata only — the miner does
/// NOT route on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateQuiesceOrder {
    /// The CVM to quiesce.
    pub vm_id: VmId,
    /// The source host id vali addressed (its `vm.host`). Correlation
    /// metadata; see the struct docs.
    pub node_id: String,
    /// §25 M3 — the lease the source `stopped{}` ack binds to. `default`
    /// for an M1 caller (no producer step); when present alongside the
    /// nonce + gen below, the quiesce drives the guest signer.
    #[serde(default)]
    pub lease_id: String,
    /// §25 M3 — the generation the SOURCE guest signs its ack at (the
    /// VM's CURRENT generation, NOT `new_gen`). vali verifies the ack at
    /// exactly this generation. `0` ⇒ no producer step (M1 caller).
    #[serde(default)]
    pub source_gen: u64,
    /// §25 M3 — vali's fresh single-use 32-byte EOL nonce, hex-encoded,
    /// the guest folds into the signed ack. Empty ⇒ no producer step.
    /// Single-use: vali mints it fresh per migration + clears it on
    /// dest-activation, so it can never be replayed.
    #[serde(default)]
    pub eol_nonce_hex: String,
}

impl MigrateQuiesceOrder {
    /// Build the §25 M3 [`SourceAckInputs`] from this order, or `None` if
    /// the order carries no producer fields (an M1 caller / a re-drive) —
    /// then the quiesce degrades to the plain clean stop. Requires BOTH a
    /// non-empty nonce AND a non-zero `source_gen`: a partial set is a
    /// producer bug, so it fails closed to "no ack" (vali times out)
    /// rather than signing at a bogus generation.
    pub fn source_ack_inputs(&self) -> Option<crate::orders::migration::SourceAckInputs> {
        if self.eol_nonce_hex.is_empty() || self.source_gen == 0 {
            return None;
        }
        Some(crate::orders::migration::SourceAckInputs {
            vm_id: self.vm_id.as_str().to_owned(),
            lease_id: self.lease_id.clone(),
            source_gen: self.source_gen,
            eol_nonce_hex: self.eol_nonce_hex.clone(),
        })
    }
}

/// §25 migration **M2** — activate the DESTINATION CVM from a snapshot.
///
/// The dual of [`MigrateSnapshotOrder`]: vali sends this to the
/// DESTINATION miner AFTER it has cryptographically verified the source
/// guest's signed `stopped{}` ack AND moved the KBS VmState to
/// `Migrating{new_gen, dest}` (see
/// `vali/apps/orchestration/service.py::_h_mig_dest_activating`). The
/// dest miner:
///
/// 1. streams the encrypted LUKS snapshot down from `get_url` and writes
///    it as this VM's [`Self::luks_disk_path`] (the same ciphertext the
///    source uploaded — the dest never decrypts);
/// 2. recreates the libvirt domain via the SAME launch path a fresh
///    launch uses, booting the guest at `new_gen`;
/// 3. the guest re-attests at `new_gen`; the KBS — already moved to
///    `Migrating{new_gen, dest}` by vali's fence — releases the SAME
///    rootfs KEK to the dest, which unlocks the migrated disk.
///
/// **Split-brain safety.** This order is NEVER sent before vali's
/// verified-ack fence. The KBS additionally refuses to release the KEK
/// to the dest until its VmState is `Migrating{new_gen, dest}`, and
/// refuses the source at the old generation forever after — so even a
/// replayed / forged `migrate-activate` cannot boot a second live copy
/// without the KEK, which the KBS will not release outside the fence.
///
/// The boot artifacts (OVMF / kernel / initrd) are assumed **pre-staged**
/// on the dest (M3 wires the staging); for M2 the handler fails closed
/// with a clear `dest-artifacts-missing` class if any is absent, rather
/// than booting a half-provisioned domain.
///
/// Not `Debug`: `cmdline` can carry sensitive launch parameters, and
/// `get_url` is a short-TTL secret — neither must be formattable into a
/// log line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateActivateOrder {
    /// The CVM to activate on this (destination) host.
    pub vm_id: VmId,
    /// Short-TTL presigned S3 **GET** URL the encrypted LUKS snapshot is
    /// streamed down from. Never persisted by the miner.
    pub get_url: String,
    /// Short-TTL presigned S3 **GET** URL for the source's anti-rollback
    /// state disk. Restored to this host's `state/{vm_id}.raw` BEFORE the
    /// launch, so `ensure_state_disk` finds it present and does NOT format
    /// a blank one — which would make the guest submit boot counter `1`
    /// against a KBS holding `N` and be refused before any Vault read.
    ///
    /// Empty ⇒ no state disk was carried (a vali predating the field, or a
    /// migration job started before it). The dest then behaves as it did
    /// before: a blank counter. `#[serde(default)]` for the same
    /// forward-compat reason as [`MigrateSnapshotOrder::state_put_url`].
    #[serde(default)]
    pub state_get_url: String,
    /// The snapshot's exact length and lower-case hex sha256, as the
    /// source reported them when it uploaded (vali relays them from the
    /// multipart receipts). The download is checked against both before
    /// the volume is ever attached. `0` / empty ⇒ not known (a single-PUT
    /// snapshot, or a vali predating the fields).
    #[serde(default)]
    pub snapshot_size: u64,
    /// See [`Self::snapshot_size`].
    #[serde(default)]
    pub snapshot_sha256_hex: String,
    /// The forward-only generation the destination boots at. Folded into
    /// the cmdline by vali (`hippius.vm_generation=`) so the guest
    /// re-attests at this generation; the KBS releases the KEK only to
    /// `(new_gen, dest)`. Carried explicitly for audit + a defensive
    /// cross-check against the cmdline token.
    pub new_gen: u64,
    /// Pinned, SEV-SNP-capable OVMF firmware (pre-staged on the dest).
    pub ovmf_path: PathBuf,
    /// Guest kernel (pre-staged on the dest).
    pub kernel_path: PathBuf,
    /// Guest initrd (pre-staged on the dest).
    pub initrd_path: PathBuf,
    /// Guest kernel command line — the same measured cmdline as the
    /// source launch, with `hippius.vm_generation=new_gen` (vali rewrites
    /// it). Folded into the SNP launch digest.
    pub cmdline: String,
    /// Where the downloaded LUKS snapshot is written on the dest (under
    /// `/var/lib/hippius-miner/`). The migrated ciphertext volume.
    pub luks_disk_path: PathBuf,
    /// LUKS disk size in GiB. NOTE: this is the flavor-independent
    /// `ROOTFS_DISK_GB` constant (~10), NOT the tenant's real data/overlay
    /// size — the real size is the MEASURED `hippius.disk_gb=` cmdline token
    /// (`into_launch_order` reads it for a golden overlay's host reservation).
    pub luks_disk_size_gb: u32,
    /// Read-only dm-verity rootfs **data** image (pre-staged). Attached
    /// at `/dev/vdb`. `serde(default)` for back-compat with the launch
    /// payload shape.
    #[serde(default = "default_rootfs_data_path")]
    pub rootfs_data_path: PathBuf,
    /// Read-only dm-verity rootfs **hash tree** (pre-staged). `/dev/vdc`.
    #[serde(default = "default_rootfs_hash_path")]
    pub rootfs_hash_path: PathBuf,
    /// vCPU count.
    pub cpu_count: u8,
    /// Guest RAM in MiB.
    pub memory_mb: u32,
    /// COSE_Sign1 envelope of the L1-minted OrderTicket for the
    /// destination generation (§6). Opaque to the miner; forwarded to
    /// the guest over vsock after the domain reaches `Running`, exactly
    /// as on a fresh launch.
    pub cose_ticket: ByteBuf,
    /// §25 M3 — presigned S3 GET URLs + pinned SHAs for the measured boot
    /// artifacts (OVMF / kernel / initrd / rootfs) the dest must stage to
    /// boot at `new_gen` with the SAME launch_digest the VM launched with.
    /// The dest fetches + sha-verifies + stages each to the canonical path
    /// above (`ovmf_path` / `kernel_path` / …) BEFORE building the domain.
    ///
    /// `serde(default)` ⇒ absent for an M2 caller (or a deployment that
    /// pre-stages the artifacts out-of-band); the dest then relies on the
    /// existence check (`dest-artifacts-missing`) — never a half boot.
    #[serde(default)]
    pub boot_artifacts: Option<crate::orders::migration::DestStagingArtifacts>,
    /// Backup failover: restore the overlay + state disk from this backup
    /// chain instead of `get_url` / `state_get_url` (see
    /// [`crate::orders::migration::activate_dest_with_chain`]). Absent for
    /// a §25 migration.
    #[serde(default)]
    pub backup_chain: Option<crate::backup::restore::RestoreChain>,
    /// vali's `DestActivating` phase deadline, less a safety margin, as
    /// unix seconds: the wall-clock instant by which this host must have
    /// settled the activation (`done` or `failed`). vali measures ONE
    /// deadline from entering the phase and re-dispatches retries as new
    /// orders; every attempt carries the SAME value, so a retry's clock
    /// can no longer outlive vali's (see
    /// [`crate::orders::migration::activate_dest_with_chain`]).
    ///
    /// `0` / absent ⇒ not carried (a vali predating the field): the
    /// per-attempt budget alone applies, as before. Serialized only when
    /// nonzero so an order without it stays byte-identical — and an agent
    /// too old to know the key refuses an order that carries it at decode
    /// (`deny_unknown_fields`), which is why agents deploy before vali.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub settle_by_unix: u64,
    /// Staged restore: boot the disks the `restore` order `stage`d under
    /// this id (see [`crate::backup::staged::swap_in`]) instead of
    /// downloading anything — `get_url` / `state_get_url` /
    /// `backup_chain` must then be empty (`staged-restore-conflict`), and
    /// the staging must be `staged` (`restore-not-staged`). Allowed on the
    /// VM's current host iff its domain is down (`restore-vm-live`).
    /// Empty ⇒ not a staged restore; serialized only when set, for the
    /// same forward-compat reason as [`Self::settle_by_unix`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub staged_restore_id: String,
    /// The VM's key guardian endpoint — see [`LaunchOrder::guardian_ep`].
    /// The destination of a §25 migration / backup failover / staged
    /// restore boots the SAME measured cmdline, so its guest needs the
    /// relay to reach the SAME guardian; [`Self::into_launch_order`]
    /// carries it. Encoded only when set (agents deploy before vali).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_ep: Option<String>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl MigrateActivateOrder {
    /// The field-consistency rule of a staged restore (see
    /// [`Self::staged_restore_id`]). A plain activation always passes.
    pub fn check_staged_restore(&self) -> std::result::Result<(), &'static str> {
        if self.staged_restore_id.is_empty() {
            return Ok(());
        }
        crate::backup::staged::check_restore_id(&self.staged_restore_id)
            .map_err(|_| "restore-bad-id")?;
        if !self.get_url.is_empty() || !self.state_get_url.is_empty() || self.backup_chain.is_some()
        {
            return Err("staged-restore-conflict");
        }
        Ok(())
    }
}

/// §25 migration **M1** — snapshot the SOURCE CVM's writable volume.
///
/// Copies the per-VM LUKS2 + dm-integrity disk image
/// ([`crate::lifecycle::CvmHandle::luks_disk_path`]) and streams it,
/// **still encrypted on disk**, to the presigned S3 PUT `put_url`. The
/// miner never decrypts — it only holds ciphertext; the key lives in
/// the guest's SNP boundary. Runs asynchronously; the upload progress
/// is read back via the `GET /v1/miner/migration/{vm_id}/status` route.
/// Not `Debug`, for the same reason [`MigrateActivateOrder`] is not: it
/// holds TWO short-TTL presigned S3 URLs, each a write capability, and a
/// single `{:?}` in a future log line would emit both.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateSnapshotOrder {
    /// The CVM whose writable volume to snapshot + upload.
    pub vm_id: VmId,
    /// The source host id vali addressed. Correlation metadata only.
    pub node_id: String,
    /// Short-TTL, single-object presigned S3 **PUT** URL the encrypted
    /// volume is streamed to. Never persisted by the miner. Unused (and
    /// may be omitted) when [`Self::disk_part_urls`] is set.
    #[serde(default)]
    pub put_url: String,
    /// Multipart upload of the volume: one presigned `UploadPart` URL per
    /// part (URL `i` is part `i+1`), each part [`Self::part_size`] bytes
    /// but the last. vali completes the upload from the part receipts the
    /// status route reports. A single PUT is refused by the store above a
    /// per-request size a golden overlay exceeds; empty ⇒ the single PUT
    /// to [`Self::put_url`] (a vali predating multipart).
    #[serde(default)]
    pub disk_part_urls: Vec<String>,
    /// Bytes per multipart part (see [`Self::disk_part_urls`]).
    #[serde(default)]
    pub part_size: u64,
    /// Short-TTL presigned S3 **PUT** URL for the per-VM anti-rollback
    /// state disk (`state/{vm_id}.raw`, the guest's `/dev/vdd`). Uploaded
    /// right after the volume; the destination restores it before booting
    /// so the migrated guest submits the boot counter the KBS expects
    /// (see [`crate::lifecycle::CvmLifecycle::state_disk_path`]).
    ///
    /// The bytes are NOT secret: a plaintext u64, nothing else is ever
    /// written to that disk (`hippius-release-core.sh` passes only
    /// `--last/--new-counter-file` at it; the KEK, userdata and §7 seed all
    /// go to tmpfs). So carrying it in the clear grants an attacker no
    /// capability it lacked — the host it comes from and the host it goes
    /// to both already read and write that file directly.
    ///
    /// Note the weaker-than-advertised property: `state_disk.rs` claims
    /// tampering "can only make a release FAIL CLOSED". That holds for
    /// blind tampering only. The stored value is readable from this same
    /// file, so a host that restores an OLD volume and writes the CURRENT
    /// counter gets the release GRANTED over rolled-back ciphertext —
    /// nothing binds the counter to the volume it protects. That is a
    /// pre-existing property of local write access, unchanged by carrying
    /// the file; it is why the counter is a replay guard on the release
    /// protocol and NOT, on its own, a disk-rollback guard.
    ///
    /// `#[serde(default)]` so a vali that predates this field still
    /// dispatches a valid order (the state disk is then not carried — the
    /// pre-fix behaviour) rather than being rejected by
    /// `deny_unknown_fields`. Empty ⇒ skip the upload.
    #[serde(default)]
    pub state_put_url: String,
}

/// Live backup of one running golden VM (see [`OrderKind::Backup`] and
/// [`crate::backup`]).
///
/// Not `Debug`: every URL is a short-TTL write capability.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupOrder {
    /// The VM to back up.
    pub vm_id: VmId,
    /// vali's id for this run (`[a-z0-9-]{1,64}`); names the run's point
    /// bitmap. A repeat of the same run is an idempotent no-op.
    pub run_id: String,
    /// The last run of the chain vali COMMITTED. An incremental copies
    /// what changed since that point (required; `bitmap-missing` if QEMU
    /// no longer has it ⇒ take a full). A full may name one point to keep
    /// so the current chain survives the full failing. Every other point
    /// is pruned.
    #[serde(default)]
    pub parent_run_id: Option<String>,
    /// `full` or `incremental`.
    pub kind: crate::backup::BackupKind,
    /// Multipart part size in bytes (5 MiB ..= 5 GiB).
    pub part_size: u64,
    /// Presigned `UploadPart` URLs for the disk piece, part 1 first. The
    /// miner uses `ceil(len / part_size)` of them and fails
    /// `too-few-part-urls` up front if that is more than given.
    pub disk_part_urls: Vec<String>,
    /// Presigned single PUT for the 1 MiB state disk.
    pub state_put_url: String,
}

impl BackupOrder {
    /// The miner-side request.
    pub fn into_request(self) -> crate::backup::BackupRequest {
        crate::backup::BackupRequest {
            vm_id: self.vm_id,
            run_id: self.run_id,
            parent_run_id: self.parent_run_id,
            kind: self.kind,
            part_size: self.part_size,
            disk_part_urls: self.disk_part_urls,
            state_put_url: self.state_put_url,
        }
    }
}

impl Order for BackupOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

fn default_restore_streams() -> u8 {
    crate::backup::transfer::DEFAULT_STREAMS as u8
}

/// A staged restore op (see [`OrderKind::Restore`] and
/// [`crate::backup::staged`]).
///
/// Not `Debug`: `chain` holds presigned URLs.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOrder {
    /// The VM.
    pub vm_id: VmId,
    /// vali's id for this restore attempt: 32 lower-case hex.
    pub restore_id: String,
    /// `stage`, `abort` or `reclaim`.
    pub op: crate::backup::staged::RestoreOp,
    /// `stage` only (absent otherwise): the point to rebuild. Its
    /// `restore_id` must equal the order's.
    #[serde(default)]
    pub chain: Option<crate::backup::restore::RestoreChain>,
    /// `stage` only: the full's expected size (the VM's disk size); `0`
    /// for `abort` / `reclaim`.
    #[serde(default)]
    pub disk_bytes: u64,
    /// Parallel ranged GETs per piece; clamped to `1..=16`.
    #[serde(default = "default_restore_streams")]
    pub streams: u8,
}

impl RestoreOrder {
    /// Check the id and the op/field consistency; a `stage` chain is also
    /// checked whole (sizes, part layouts) so vali hears about a bad one
    /// on the order response.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::backup::staged::{check_restore_id, RestoreOp};
        use crate::error::MinerAgentError;
        check_restore_id(&self.restore_id)?;
        match self.op {
            RestoreOp::Stage => {
                let chain = self
                    .chain
                    .as_ref()
                    .ok_or(MinerAgentError::Backup("restore-chain-missing"))?;
                if chain.restore_id != self.restore_id {
                    return Err(MinerAgentError::Backup("restore-id-mismatch"));
                }
                if self.disk_bytes == 0 {
                    return Err(MinerAgentError::Backup("restore-disk-bytes"));
                }
                crate::backup::restore::check_chain(chain, Some(self.disk_bytes))
            }
            RestoreOp::Abort | RestoreOp::Reclaim => {
                if self.chain.is_some() || self.disk_bytes != 0 {
                    return Err(MinerAgentError::Backup("restore-fields"));
                }
                Ok(())
            }
        }
    }
}

impl Order for RestoreOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

/// One artifact the miner downloads via an S3 presigned URL during a
/// `tenant-preflight`. The miner sha256-verifies the bytes BEFORE
/// staging — defense-in-depth on top of the presigned URL's
/// authenticity (the URL is short-TTL + bound to a specific object
/// name, but the bake's `sha256_hex` is what vali bound into the
/// OrderTicket via the launch_digest).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightArtifact {
    /// Presigned HTTPS URL (operator-side `aws s3 presign`).
    pub url: String,
    /// Lower-case hex SHA-256 of the artifact bytes.
    pub sha256_hex: String,
}

/// A request to fetch + verify + measure one tenant's launch
/// artifacts in a single trip. The miner-agent writes the verified
/// bytes to canonical paths under `STAGING_ROOT/<vm-id>/`, runs the
/// same `snp_calc_launch_digest` the launch path uses, and returns a
/// JSON body with the digest + staged paths so vali can mint the
/// matching OrderTicket without an out-of-band SSH-to-miner step.
///
/// Not `Debug`: `cmdline` can carry sensitive launch parameters.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPreflightOrder {
    /// Tenant id — used to derive the staging dir + bind the
    /// idempotency key.
    pub vm_id: VmId,
    /// Pinned OVMF firmware path on the miner. NOT downloaded — the
    /// OVMF is operator-staged via the standard miner provisioning
    /// chain (it's the same file every tenant's digest measures
    /// against, so distributing it per-launch would just churn).
    pub ovmf_path: std::path::PathBuf,
    /// {qcow2, vmlinuz, initrd} artifacts, each presigned.
    ///
    /// GOLDEN-mode (golden-bake PR4): there is NO per-VM `tenant.qcow2`.
    /// The `luks_disk` slot instead carries the SHARED read-only golden
    /// dm-verity base **data** image (`rootfs.img`), and
    /// [`Self::rootfs_hash`] carries its **hash tree** (`rootfs.verity`).
    /// Both are fetched + sha-verified through the SAME content-addressed
    /// cache (#823) so a same-distro relaunch HITs. Golden is detected
    /// from [`Self::cmdline`] (`crate::lifecycle::golden::is_golden_cmdline`)
    /// — the measured cmdline, so a miner cannot spoof the mode.
    pub luks_disk: PreflightArtifact,
    pub kernel: PreflightArtifact,
    pub initrd: PreflightArtifact,
    /// GOLDEN-mode only: the golden base's dm-verity **hash tree**
    /// (`rootfs.verity`, attached at `/dev/vdc`). `serde(default)` ⇒
    /// absent on the LEGACY path (byte-identical wire shape). Required
    /// when [`Self::cmdline`] signals golden; the miner fails closed
    /// otherwise.
    #[serde(default)]
    pub rootfs_hash: Option<PreflightArtifact>,
    /// Guest kernel command line — folded into the SNP launch digest.
    pub cmdline: String,
    /// vCPU count — folded into the SNP launch digest.
    pub cpu_count: u8,
}

/// Common surface over the per-VM order kinds — each names exactly one
/// tenant VM.
pub trait Order {
    /// The tenant VM this order concerns.
    fn vm_id(&self) -> &VmId;
}

/// What an order's log lines name: its VM, or `host` for a host-wide
/// order ([`NetPolicyOrder`]).
pub trait OrderSubject {
    /// A charset-safe token for the `vm=` log field.
    fn log_subject(&self) -> &str;
}

impl<T: Order> OrderSubject for T {
    fn log_subject(&self) -> &str {
        self.vm_id().as_str()
    }
}

impl OrderSubject for NetPolicyOrder {
    fn log_subject(&self) -> &str {
        "host"
    }
}

/// `local`: guests leave through the miner's own NAT. `edge`: through
/// the region's edge, the miner allowing only the listed endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetPolicyMode {
    Local,
    Edge,
}

/// What the local-mode rules do with a matching packet: only count it,
/// or drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetPolicyLocalAction {
    Count,
    Drop,
}

/// Transport of an allowed endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetProto {
    Tcp,
    Udp,
}

/// One allowed destination, `ip` in canonical dotted-quad IPv4 form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetEndpoint {
    pub ip: String,
    pub proto: NetProto,
    pub port: u16,
}

/// The host-wide guest network policy (`net-policy`), see
/// `docs/design/egress-and-bandwidth.md` §7.
///
/// `revision` is per miner and monotonic: the agent refuses a lower one,
/// and the same one with other content ([`crate::netpolicy`]). A
/// rollback is a higher revision. `not_after_unix` is the policy's own
/// expiry; vali re-sends within it, so it is left out of the content
/// hash. `uplink_hint` is the only optional field and is not encoded when
/// absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetPolicyOrder {
    pub revision: u64,
    pub not_after_unix: u64,
    /// vali's region code, `[a-z0-9-]`.
    pub region: String,
    pub mode: NetPolicyMode,
    pub enforce: bool,
    pub local_action: NetPolicyLocalAction,
    /// Interface name of the uplink; absent ⇒ the default-route one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_hint: Option<String>,
    /// Edge and infra WireGuard endpoints (edge mode).
    pub infra: Vec<NetEndpoint>,
    /// The region's miners, any UDP port (edge mode), IPv4.
    pub region_miners: Vec<String>,
    /// NetBird management, signal and STUN endpoints (edge mode).
    pub nb_control: Vec<NetEndpoint>,
    /// Per-tap DNS budget, packets per second.
    pub dns_limit_pps: u32,
    /// VMs exempt from the outbound TCP 25 drop.
    pub smtp_allowed_vms: Vec<VmId>,
    /// Per-VM cap in Mbit/s, keyed by VM id.
    pub vm_caps: std::collections::BTreeMap<String, u32>,
}

impl Order for LaunchOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for StopOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for DestroyOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for MigrateOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for MigrateQuiesceOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for MigrateSnapshotOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl Order for MigrateActivateOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

impl MigrateActivateOrder {
    /// Build the [`LaunchOrder`] the dest-activation drives through the
    /// SAME launch path a fresh launch uses (domain build, OVMF/kernel/
    /// initrd staging check, vsock ticket push).
    ///
    /// `data_disk_size_gb` is mode-dependent (mirrors the launch path's
    /// disk semantics in `lifecycle::mod::launch`):
    /// - **LEGACY**: `0` — the migrated VM's data rides inside the
    ///   downloaded LUKS `/dev/vda` volume; provisioning a fresh blank
    ///   `/dev/vde` would strand it.
    /// - **GOLDEN**: the per-VM writable OVERLAY UPPER (`/dev/vda`) IS the
    ///   tenant disk and MUST be sized (`launch` rejects a golden order
    ///   with `data_disk_size_gb == 0` → `golden-disk-gb-zero`, and reserves
    ///   `data_disk_size_gb` against the host disk budget). Size it from the
    ///   MEASURED `hippius.disk_gb=<N>` cmdline token — the SAME source a
    ///   fresh golden launch's capacity gate uses (`handle_tenant_preflight`
    ///   / `parse_disk_gb_token`) — NOT `luks_disk_size_gb`, which is a
    ///   flavor-independent constant (`flavors.ROOTFS_DISK_GB`, ~10 GiB) that
    ///   would silently under-book the real overlay (up to 256 GiB) and
    ///   defeat the disk-capacity admission gate. Golden-ness AND the size
    ///   both come from the SNP-measured cmdline, so a miner cannot spoof
    ///   either.
    ///
    /// The migrated ciphertext is written to the boot overlay path by the
    /// dest-activation BEFORE this launch attaches it (see `activate_dest`).
    pub fn into_launch_order(self) -> LaunchOrder {
        let is_golden = crate::lifecycle::golden::is_golden_cmdline(&self.cmdline);
        let data_disk_size_gb = if is_golden {
            crate::orders::handler::parse_disk_gb_token(&self.cmdline)
        } else {
            0
        };
        LaunchOrder {
            vm_id: self.vm_id,
            ovmf_path: self.ovmf_path,
            kernel_path: self.kernel_path,
            initrd_path: self.initrd_path,
            cmdline: self.cmdline,
            luks_disk_path: self.luks_disk_path,
            luks_disk_size_gb: self.luks_disk_size_gb,
            data_disk_size_gb,
            rootfs_data_path: self.rootfs_data_path,
            rootfs_hash_path: self.rootfs_hash_path,
            cpu_count: self.cpu_count,
            memory_mb: self.memory_mb,
            cose_ticket: self.cose_ticket,
            // The §25 dest-activation writes the migrated disks itself,
            // right before this launch; the relaunch guard is not wired
            // into that path.
            require_existing_disks: false,
            guardian_ep: self.guardian_ep,
        }
    }
}

impl Order for TenantPreflightOrder {
    fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_order_exposes_its_vm_id() {
        let order = LaunchOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet".to_string(),
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/d.img"),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 64,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::new(),
            require_existing_disks: false,
            guardian_ep: None,
        };
        assert_eq!(order.vm_id().as_str(), "tenant-1");
    }

    /// `require_existing_disks` is invisible on a first launch (absent ⇒
    /// `false`, `false` ⇒ not encoded) and survives the wire when set.
    #[test]
    fn require_existing_disks_is_wire_optional_and_round_trips() {
        let order = |require_existing_disks: bool| LaunchOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet".to_string(),
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/d.img"),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 0,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::from(vec![1u8]),
            require_existing_disks,
            guardian_ep: None,
        };
        let encode = |o: &LaunchOrder| {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(o, &mut buf).unwrap();
            buf
        };
        let key = b"require_existing_disks";
        let first = encode(&order(false));
        assert!(!first.windows(key.len()).any(|w| w == key.as_slice()));
        let back: LaunchOrder = ciborium::de::from_reader(first.as_slice()).unwrap();
        assert!(!back.require_existing_disks);

        let relaunch = encode(&order(true));
        let back: LaunchOrder = ciborium::de::from_reader(relaunch.as_slice()).unwrap();
        assert!(back.require_existing_disks);
    }

    #[test]
    fn every_order_kind_round_trips_through_cbor() {
        for kind in [
            OrderKind::Launch,
            OrderKind::Stop,
            OrderKind::Destroy,
            OrderKind::Migrate,
            OrderKind::MigrateQuiesce,
            OrderKind::MigrateSnapshot,
            OrderKind::MigrateActivate,
            OrderKind::Backup,
            OrderKind::Restore,
            OrderKind::TenantPreflight,
            OrderKind::NetPolicy,
        ] {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&kind, &mut buf).unwrap();
            let back: OrderKind = ciborium::de::from_reader(buf.as_slice()).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn stop_order_round_trips_through_an_order_body() {
        let body = OrderBody {
            domain: ORDER_DOMAIN.to_string(),
            order_id: "ord-1".to_string(),
            kind: OrderKind::Stop,
            target_miner_id: "miner-a".to_string(),
            issued_at_unix: 1_770_000_000,
            payload: StopOrder {
                vm_id: VmId::new("tenant-x").unwrap(),
                graceful: true,
            },
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let back: OrderBody<StopOrder> = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.order_id, "ord-1");
        assert_eq!(back.target_miner_id, "miner-a");
        assert_eq!(back.issued_at_unix, 1_770_000_000);
        assert_eq!(back.payload.vm_id.as_str(), "tenant-x");
        assert!(back.payload.graceful);
    }

    #[test]
    fn migrate_kind_route_segments_are_kebab_case() {
        // The Edge builds the miner route segment from these strings;
        // a drift would 404 every relayed quiesce/snapshot.
        assert_eq!(OrderKind::MigrateQuiesce.as_class_str(), "migrate-quiesce");
        assert_eq!(
            OrderKind::MigrateSnapshot.as_class_str(),
            "migrate-snapshot"
        );
        assert_eq!(
            OrderKind::MigrateActivate.as_class_str(),
            "migrate-activate"
        );
    }

    #[test]
    fn activate_order_round_trips_and_builds_a_launch_order() {
        let body = OrderBody {
            domain: ORDER_DOMAIN.to_string(),
            order_id: "mig-activate-1".to_string(),
            kind: OrderKind::MigrateActivate,
            target_miner_id: "dst-miner-b".to_string(),
            issued_at_unix: 1_770_000_000,
            payload: MigrateActivateOrder {
                vm_id: VmId::new("tenant-x").unwrap(),
                get_url: "https://s3.example/snap?sig=abc".to_string(),
                state_get_url: String::new(),
                snapshot_size: 0,
                snapshot_sha256_hex: String::new(),
                new_gen: 6,
                ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
                kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
                initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
                cmdline: "ro hippius.vm_generation=6".to_string(),
                luks_disk_path: PathBuf::from("/var/lib/hippius-miner/d.img"),
                luks_disk_size_gb: 10,
                rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
                rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
                cpu_count: 2,
                memory_mb: 2048,
                cose_ticket: ByteBuf::new(),
                boot_artifacts: None,
                backup_chain: None,
                staged_restore_id: String::new(),
                guardian_ep: None,
                settle_by_unix: 0,
            },
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let back: OrderBody<MigrateActivateOrder> =
            ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.kind, OrderKind::MigrateActivate);
        assert_eq!(back.payload.vm_id.as_str(), "tenant-x");
        assert_eq!(back.payload.new_gen, 6);
        assert_eq!(back.payload.get_url, "https://s3.example/snap?sig=abc");

        // The launch-order conversion preserves the measured tuple and
        // refuses to provision a fresh blank data disk (the migrated
        // data rides inside the downloaded LUKS volume).
        let launch = back.payload.into_launch_order();
        assert_eq!(launch.vm_id.as_str(), "tenant-x");
        assert_eq!(
            launch.luks_disk_path,
            PathBuf::from("/var/lib/hippius-miner/d.img")
        );
        assert_eq!(launch.data_disk_size_gb, 0);
        assert_eq!(launch.cpu_count, 2);
    }

    #[test]
    fn activate_order_rejects_unknown_fields() {
        let json = r#"{"vm_id":"tenant-x","get_url":"u","new_gen":1,"extra":1}"#;
        let parsed: std::result::Result<MigrateActivateOrder, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    /// `settle_by_unix` is invisible when not carried (absent/0 ⇒ the
    /// body is byte-identical to the pre-field wire) and round-trips when
    /// it is.
    #[test]
    fn settle_by_unix_is_wire_optional_and_round_trips() {
        let encode = |settle_by_unix: u64| {
            let mut order = activate_order_with("ro", 10);
            order.settle_by_unix = settle_by_unix;
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&order, &mut buf).unwrap();
            buf
        };
        let key = b"settle_by_unix";
        let absent = encode(0);
        assert!(!absent.windows(key.len()).any(|w| w == key));
        let back: MigrateActivateOrder = ciborium::de::from_reader(absent.as_slice()).unwrap();
        assert_eq!(back.settle_by_unix, 0);

        let carried = encode(1_790_000_000);
        assert!(carried.windows(key.len()).any(|w| w == key));
        let back: MigrateActivateOrder = ciborium::de::from_reader(carried.as_slice()).unwrap();
        assert_eq!(back.settle_by_unix, 1_790_000_000);
    }

    /// Build a `MigrateActivateOrder` with a caller-chosen cmdline +
    /// overlay size — for the mode-dependent `into_launch_order` sizing.
    fn activate_order_with(cmdline: &str, luks_disk_size_gb: u32) -> MigrateActivateOrder {
        MigrateActivateOrder {
            vm_id: VmId::new("mig-x").unwrap(),
            get_url: "https://s3/snap".to_string(),
            state_get_url: String::new(),
            snapshot_size: 0,
            snapshot_sha256_hex: String::new(),
            new_gen: 6,
            ovmf_path: PathBuf::from("/x/ovmf.fd"),
            kernel_path: PathBuf::from("/x/vmlinuz"),
            initrd_path: PathBuf::from("/x/initrd"),
            cmdline: cmdline.to_string(),
            luks_disk_path: PathBuf::from("/x/mig-x.img"),
            luks_disk_size_gb,
            rootfs_data_path: PathBuf::from("/x/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/x/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::new(),
            boot_artifacts: None,
            backup_chain: None,
            staged_restore_id: String::new(),
            guardian_ep: None,
            settle_by_unix: 0,
        }
    }

    #[test]
    fn into_launch_order_sizes_the_golden_overlay_from_the_measured_token() {
        // GOLDEN (dm-verity.root= present, no luks_header): the writable
        // overlay upper (/dev/vda) IS the tenant disk and MUST be sized, or
        // `launch` rejects it (golden-disk-gb-zero). Size comes from the
        // MEASURED `hippius.disk_gb=` token (32), NOT the flavor-independent
        // `luks_disk_size_gb` constant (10) — else the host disk-budget
        // reservation would be silently wrong.
        let order = activate_order_with(
            "ro dm-verity.root=abc123 hippius.disk_gb=32 hippius.vm_generation=6",
            10,
        );
        let launch = order.into_launch_order();
        assert_eq!(
            launch.data_disk_size_gb, 32,
            "golden overlay sized from the measured hippius.disk_gb token"
        );
    }

    #[test]
    fn into_launch_order_golden_without_disk_gb_token_is_zero() {
        // A golden order whose measured cmdline lacks `hippius.disk_gb=`
        // yields 0 → `launch` fails closed (golden-disk-gb-zero) rather than
        // booting an unsized overlay. (vali always bakes the token; a missing
        // one is an old/hand-built cmdline, not an attack.)
        let order = activate_order_with("ro dm-verity.root=abc123", 10);
        assert_eq!(order.into_launch_order().data_disk_size_gb, 0);
    }

    #[test]
    fn into_launch_order_legacy_provisions_no_data_disk() {
        // LEGACY (luks_header present): data rides inside the LUKS /dev/vda;
        // a fresh blank /dev/vde would strand it ⇒ data_disk_size_gb = 0.
        let order = activate_order_with(
            "ro hippius.luks_header_sha256=deadbeef hippius.vm_generation=6",
            20,
        );
        let launch = order.into_launch_order();
        assert_eq!(
            launch.data_disk_size_gb, 0,
            "legacy data rides the LUKS vda"
        );
    }

    #[test]
    fn quiesce_order_round_trips_through_an_order_body() {
        let body = OrderBody {
            domain: ORDER_DOMAIN.to_string(),
            order_id: "mig-quiesce-1".to_string(),
            kind: OrderKind::MigrateQuiesce,
            target_miner_id: "miner-a".to_string(),
            issued_at_unix: 1_770_000_000,
            payload: MigrateQuiesceOrder {
                vm_id: VmId::new("tenant-x").unwrap(),
                node_id: "miner-a".to_string(),
                lease_id: "lease-1".to_string(),
                source_gen: 5,
                eol_nonce_hex: "ab".repeat(32),
            },
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let back: OrderBody<MigrateQuiesceOrder> =
            ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.kind, OrderKind::MigrateQuiesce);
        assert_eq!(back.payload.vm_id.as_str(), "tenant-x");
        assert_eq!(back.payload.node_id, "miner-a");
        // §25 M3 producer fields survive the CBOR round-trip.
        assert_eq!(back.payload.source_gen, 5);
        assert_eq!(back.payload.eol_nonce_hex, "ab".repeat(32));
        assert!(back.payload.source_ack_inputs().is_some());
    }

    #[test]
    fn snapshot_order_round_trips_through_an_order_body() {
        let body = OrderBody {
            domain: ORDER_DOMAIN.to_string(),
            order_id: "mig-snap-1".to_string(),
            kind: OrderKind::MigrateSnapshot,
            target_miner_id: "miner-a".to_string(),
            issued_at_unix: 1_770_000_000,
            payload: MigrateSnapshotOrder {
                vm_id: VmId::new("tenant-x").unwrap(),
                node_id: "miner-a".to_string(),
                put_url: "https://s3.example/snap?sig=abc".to_string(),
                state_put_url: String::new(),
                disk_part_urls: Vec::new(),
                part_size: 0,
            },
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let back: OrderBody<MigrateSnapshotOrder> =
            ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.kind, OrderKind::MigrateSnapshot);
        assert_eq!(back.payload.vm_id.as_str(), "tenant-x");
        assert_eq!(back.payload.put_url, "https://s3.example/snap?sig=abc");
    }

    #[test]
    fn snapshot_order_rejects_unknown_fields() {
        // `deny_unknown_fields` discipline (§C of the M1 scope) — an
        // extra field is rejected structurally.
        let json = r#"{"vm_id":"tenant-x","node_id":"m","put_url":"u","extra":1}"#;
        let parsed: std::result::Result<MigrateSnapshotOrder, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    // ── restore order ───────────────────────────────────────────────

    const RID: &str = "0123456789abcdef0123456789abcdef";

    fn stage_json(extra: &str) -> String {
        let sha = "ab".repeat(32);
        format!(
            r#"{{"vm_id":"tenant-x","restore_id":"{RID}","op":"stage","disk_bytes":1048576,
            "chain":{{"restore_id":"{RID}",
              "full":{{"url":"u/f","sha256_hex":"{sha}","size":1048576,
                       "part_size":5242880,"part_sha256_hex":["{sha}"]}},
              "incrementals":[],
              "state":{{"url":"u/s","sha256_hex":"{sha}","size":1048576}}}}{extra}}}"#
        )
    }

    #[test]
    fn a_stage_order_decodes_and_validates_with_the_defaults() {
        let o: RestoreOrder = serde_json::from_str(&stage_json("")).unwrap();
        assert_eq!(o.streams, 8, "streams defaults to 8");
        let chain = o.chain.as_ref().unwrap();
        assert_eq!(chain.full.part_size, 5 << 20);
        assert_eq!(chain.state.part_size, 0, "absent part fields default");
        assert!(chain.state.part_sha256_hex.is_empty());
        o.validate().unwrap();
        // CBOR through an order body, as the miner decodes it.
        let body = OrderBody {
            domain: ORDER_DOMAIN.to_string(),
            order_id: "r-1".to_string(),
            kind: OrderKind::Restore,
            target_miner_id: "miner-a".to_string(),
            issued_at_unix: 1_770_000_000,
            payload: o,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let back: OrderBody<RestoreOrder> = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.kind.as_class_str(), "restore");
        assert_eq!(back.payload.restore_id, RID);
    }

    #[test]
    fn restore_orders_reject_unknown_fields() {
        assert!(serde_json::from_str::<RestoreOrder>(&stage_json(r#","extra":1"#)).is_err());
        // …in a chain piece too.
        let bad = stage_json("").replace(r#""size":1048576}}}"#, r#""size":1048576,"x":1}}}"#);
        assert_ne!(bad, stage_json(""));
        assert!(serde_json::from_str::<RestoreOrder>(&bad).is_err());
    }

    #[test]
    fn a_restore_order_for_another_id_or_with_stray_fields_is_refused() {
        let class = |json: &str| match serde_json::from_str::<RestoreOrder>(json)
            .unwrap()
            .validate()
        {
            Err(crate::error::MinerAgentError::Backup(c)) => c,
            other => panic!("{:?}", other.err()),
        };
        let other = "fedcba9876543210fedcba9876543210";
        assert_eq!(
            class(&stage_json("").replacen(RID, other, 1)),
            "restore-id-mismatch"
        );
        assert_eq!(
            class(&stage_json("").replace(RID, "0123456789ABCDEF0123456789ABCDEF")),
            "restore-bad-id"
        );
        assert_eq!(
            class(&stage_json("").replace(r#""disk_bytes":1048576,"#, "")),
            "restore-disk-bytes"
        );
        assert_eq!(
            class(&stage_json("").replace(r#""disk_bytes":1048576"#, r#""disk_bytes":2"#)),
            "full-size-mismatch"
        );
        assert_eq!(
            class(&stage_json("").replace(r#""part_sha256_hex":["#, r#""part_sha256_hex":["00","#)),
            "part-sha-count"
        );
        let no_chain =
            format!(r#"{{"vm_id":"tenant-x","restore_id":"{RID}","op":"stage","disk_bytes":1}}"#);
        assert_eq!(class(&no_chain), "restore-chain-missing");
        for op in ["abort", "reclaim"] {
            let ok = format!(r#"{{"vm_id":"tenant-x","restore_id":"{RID}","op":"{op}"}}"#);
            serde_json::from_str::<RestoreOrder>(&ok)
                .unwrap()
                .validate()
                .unwrap();
            let zero = format!(
                r#"{{"vm_id":"tenant-x","restore_id":"{RID}","op":"{op}","disk_bytes":0,"chain":null}}"#
            );
            serde_json::from_str::<RestoreOrder>(&zero)
                .unwrap()
                .validate()
                .unwrap();
            let stray = stage_json("").replace(r#""op":"stage""#, &format!(r#""op":"{op}""#));
            assert_eq!(class(&stray), "restore-fields");
        }
        assert!(serde_json::from_str::<RestoreOrder>(
            &stage_json("").replace(r#""op":"stage""#, r#""op":"swap""#)
        )
        .is_err());
    }

    #[test]
    fn staged_restore_id_is_serialized_only_when_set() {
        let mut order = activate_order_with("ro hippius.vm_generation=6", 0);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&order, &mut buf).unwrap();
        let v: ciborium::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        let has = |v: &ciborium::Value| {
            v.as_map()
                .unwrap()
                .iter()
                .any(|(k, _)| k.as_text() == Some("staged_restore_id"))
        };
        assert!(!has(&v));
        order.staged_restore_id = RID.into();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&order, &mut buf).unwrap();
        let v: ciborium::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert!(has(&v));
        let back: MigrateActivateOrder = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back.staged_restore_id, RID);
    }

    /// The pre-H4 `LaunchOrder` wire shape, field for field.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LaunchOrderPreGuardian {
        vm_id: VmId,
        ovmf_path: PathBuf,
        kernel_path: PathBuf,
        initrd_path: PathBuf,
        cmdline: String,
        luks_disk_path: PathBuf,
        luks_disk_size_gb: u32,
        #[serde(default)]
        data_disk_size_gb: u32,
        #[serde(default = "default_rootfs_data_path")]
        rootfs_data_path: PathBuf,
        #[serde(default = "default_rootfs_hash_path")]
        rootfs_hash_path: PathBuf,
        cpu_count: u8,
        memory_mb: u32,
        cose_ticket: ByteBuf,
        #[serde(default, skip_serializing_if = "is_false")]
        require_existing_disks: bool,
    }

    fn guardian_launch(guardian_ep: Option<&str>) -> LaunchOrder {
        LaunchOrder {
            vm_id: VmId::new("tenant-g").unwrap(),
            ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
            kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
            initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
            cmdline: "quiet".to_string(),
            luks_disk_path: PathBuf::from("/var/lib/hippius-miner/d.img"),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 32,
            rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
            rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: ByteBuf::from(vec![1u8, 2, 3]),
            require_existing_disks: true,
            guardian_ep: guardian_ep.map(String::from),
        }
    }

    fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(v, &mut buf).unwrap();
        buf
    }

    /// An M0 launch (no guardian) encodes BYTE-IDENTICALLY to the pre-H4
    /// shape, and the pre-H4 decoder still reads it — so vali can ship the
    /// field before any VM uses it.
    #[test]
    fn m0_launch_bytes_are_identical_to_the_pre_guardian_shape() {
        let order = guardian_launch(None);
        let old = LaunchOrderPreGuardian {
            vm_id: order.vm_id.clone(),
            ovmf_path: order.ovmf_path.clone(),
            kernel_path: order.kernel_path.clone(),
            initrd_path: order.initrd_path.clone(),
            cmdline: order.cmdline.clone(),
            luks_disk_path: order.luks_disk_path.clone(),
            luks_disk_size_gb: order.luks_disk_size_gb,
            data_disk_size_gb: order.data_disk_size_gb,
            rootfs_data_path: order.rootfs_data_path.clone(),
            rootfs_hash_path: order.rootfs_hash_path.clone(),
            cpu_count: order.cpu_count,
            memory_mb: order.memory_mb,
            cose_ticket: order.cose_ticket.clone(),
            require_existing_disks: order.require_existing_disks,
        };
        let new_bytes = cbor(&order);
        assert_eq!(new_bytes, cbor(&old));
        let _: LaunchOrderPreGuardian = ciborium::de::from_reader(new_bytes.as_slice()).unwrap();
    }

    /// With a guardian the key rides the wire and round-trips; an agent
    /// that predates it REFUSES the order at decode (fail-closed) — the
    /// reason miner-agents deploy before vali.
    #[test]
    fn guardian_ep_round_trips_and_an_old_agent_refuses_it() {
        let bytes = cbor(&guardian_launch(Some("100.64.0.1:7443")));
        let back: LaunchOrder = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.guardian_ep.as_deref(), Some("100.64.0.1:7443"));
        assert!(ciborium::de::from_reader::<LaunchOrderPreGuardian, _>(bytes.as_slice()).is_err());
        let m0: LaunchOrder =
            ciborium::de::from_reader(cbor(&guardian_launch(None)).as_slice()).unwrap();
        assert!(m0.guardian_ep.is_none());
    }

    /// The dest of a §25 migration / restore boots the same measured
    /// cmdline, so it must dial the same guardian.
    #[test]
    fn migrate_activate_carries_the_guardian_into_the_launch() {
        let mut order = activate_order_with("quiet", 10);
        assert!(order.guardian_ep.is_none());
        let key = b"guardian_ep";
        assert!(!cbor(&order).windows(key.len()).any(|w| w == key.as_slice()));
        assert!(activate_order_with("quiet", 10)
            .into_launch_order()
            .guardian_ep
            .is_none());
        order.guardian_ep = Some("[2001:db8::1]:7443".into());
        let bytes = cbor(&order);
        let back: MigrateActivateOrder = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(
            back.into_launch_order().guardian_ep.as_deref(),
            Some("[2001:db8::1]:7443")
        );
    }
}
