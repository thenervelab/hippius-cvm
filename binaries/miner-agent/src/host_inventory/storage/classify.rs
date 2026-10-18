//! What each device is, or could become (§18.9.2): one [`DeviceRole`],
//! the reasons it is not offerable, and the pools it backs.
//!
//! A device's use is the use of everything stacked ABOVE it — its
//! partitions, and its holders (md, dm-crypt, LVM) transitively — so a
//! disk whose partition holds `/` is `system`, and an md member of a
//! pool's array backs that pool. In order:
//!
//! 1. `system`: it, or a stack above it, holds `/`, `/boot`, `/boot/efi`
//!    or swap. A component of that stack (it has holders) is `member`,
//!    with the `system` reason.
//! 2. `state_root`, then `pool_backing`: the same, for the filesystem
//!    holding the agent's state root, or a declared pool (`pool_ids`:
//!    every pool on it). Components are `member`.
//! 3. `dedicated_free`: a by-id name of it is a declared dedicated disk
//!    (its reasons say what the agent's apply-time checks would refuse).
//!    Nothing is assigned to a VM in this phase, so never
//!    `dedicated_assigned`.
//! 4. `member`: a component of any other stack.
//! 5. `eligible_pool`: a mounted ext4 / xfs / btrfs that is none of the
//!    above, writable, not removable.
//! 6. For an unused device: `eligible_dedicated` (a bare whole disk that
//!    passes every check), `needs_prep` (only a plain filesystem
//!    signature or a bare partition table in the way), else `ineligible`.
//!
//! **Fail closed.** A device the dashboard could suggest wiping is
//! `eligible_*` or `needs_prep` only on positive proof. No udev entry (no
//! proof of no signature), any signature but a plain single-device
//! filesystem ([`PLAIN_FILESYSTEMS`]: a stopped array's member, a closed
//! LUKS volume, an exported ZFS pool, inactive swap, an unknown type),
//! a member of a multi-device filesystem (by its
//! shared `ID_FS_UUID`), a stopped array, a partition of the system disk:
//! `ineligible`. When `/` does not resolve to a device, or the agent's
//! view is unknown, nothing at all is offerable.
//!
//! **Boot partitions.** A partition udev types, flags or labels as a boot
//! partition (the ESP or BIOS boot / XBOOTLDR GUID, MBR type `0xef`, the
//! GPT legacy-bootable or MBR active flag, an `EFI*` / `ESP` partition or
//! filesystem label), or that `/etc/fstab` puts on `/boot`, `/boot/efi`
//! or `/efi`, is `ineligible` (`system`) with its whole disk, mounted or
//! not. A boot path configured on a device nothing identifies (an
//! unresolvable fstab spec, an automount with no typed boot partition):
//! nothing is offerable.
//!
//! **The one exception (approved):** a MOUNTED partition of the system
//! disk that qualifies as a pool stays `eligible_pool`. It is a separate
//! mounted filesystem, declaring a pool on it destroys nothing (a pool is
//! a directory on a filesystem as it is), and the agent's apply refuses a
//! pool on `/` (`pool-on-root-fs`). The dashboard copy for
//! `eligible_pool` must therefore never offer `mkfs` or a wipe: only
//! "declare as a pool".

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use hippius_host_inventory::{DeviceKind, DeviceRole, IneligibleReason, Transport};

use super::devices::{HostDisks, Raw};
use super::StorageView;
use crate::storage::dedicated::MIN_DEDICATED_DISK_GB;
use crate::storage::pools::POOL_FSTYPES;

/// Mount points that make their device `system`.
const SYSTEM_MOUNTS: [&str; 3] = ["/", "/boot", "/boot/efi"];

/// The only `ID_FS_TYPE`s an unused device may carry and still be
/// `needs_prep`: plain, single-device filesystems. ANY other signature —
/// every `*_member` (md, LVM1/2, ZFS, vendor RAID), crypto_LUKS,
/// BitLocker, bcache, vdo, stratis, DM_integrity, Ceph, DRBD, swap, or a
/// type this list does not know — may be a component of a stack nothing
/// holds right now (a stopped array, a closed volume, an exported pool):
/// `ineligible`, never offered for preparation, which would destroy it.
/// A btrfs is plain only on one device (a shared `ID_FS_UUID` makes it a
/// member).
const PLAIN_FILESYSTEMS: [&str; 8] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs",
];

/// `md/array_state` of a running array.
const MD_RUNNING: [&str; 3] = ["clean", "active", "active-idle"];

/// How deep a stack is followed (disk → partition → md → crypt → LVM …).
const MAX_STACK_DEPTH: usize = 8;

/// One device's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Class {
    pub(crate) role: DeviceRole,
    pub(crate) reasons: BTreeSet<IneligibleReason>,
    pub(crate) pool_ids: BTreeSet<String>,
    /// The declared dedicated-disk id it matched.
    pub(crate) dedicated_id: Option<String>,
}

/// What the device itself carries.
#[derive(Debug, Default, Clone)]
struct Uses {
    system: bool,
    swap: bool,
    state_root: bool,
    pools: BTreeSet<String>,
    mounted: bool,
}

fn direct_uses(disks: &HostDisks, view: Option<&StorageView>) -> BTreeMap<String, Uses> {
    let mut uses: BTreeMap<String, Uses> = BTreeMap::new();
    for m in &disks.mounts {
        let Some(dev) = &m.device else { continue };
        let u = uses.entry(dev.clone()).or_default();
        u.mounted = true;
        if SYSTEM_MOUNTS.iter().any(|s| m.mount_point == Path::new(s)) {
            u.system = true;
        }
    }
    for dev in &disks.swaps {
        let u = uses.entry(dev.clone()).or_default();
        u.swap = true;
        u.system = true;
    }
    if let Some(view) = view {
        let device_of = |path: &Path| disks.mount_of(path).and_then(|m| m.device.clone());
        if let Some(dev) = device_of(&view.state_root) {
            uses.entry(dev).or_default().state_root = true;
        }
        for pool in &view.pools {
            if let Some(dev) = device_of(&pool.path) {
                uses.entry(dev).or_default().pools.insert(pool.id.clone());
            }
        }
    }
    uses
}

/// Everything stacked above `name`: its partitions, its holders, theirs.
fn above<'a>(disks: &'a HostDisks, name: &str) -> BTreeSet<&'a str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut level: Vec<&str> = disks
        .devices
        .get_key_value(name)
        .map(|(k, _)| vec![k.as_str()])
        .unwrap_or_default();
    for _ in 0..MAX_STACK_DEPTH {
        let mut next = Vec::new();
        for n in level {
            let Some(d) = disks.devices.get(n) else {
                continue;
            };
            for up in d.partitions.iter().chain(&d.holders) {
                if let Some((k, _)) = disks.devices.get_key_value(up) {
                    if seen.insert(k.as_str()) {
                        next.push(k.as_str());
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    seen
}

/// A filesystem the agent could take as a pool.
fn pool_fs(disks: &HostDisks, name: &str) -> bool {
    let mounts: Vec<_> = disks
        .mounts
        .iter()
        .filter(|m| m.device.as_deref() == Some(name))
        .collect();
    !mounts.is_empty()
        && mounts
            .iter()
            .all(|m| POOL_FSTYPES.contains(&m.fstype.as_str()) && !m.read_only)
}

/// The reasons that rule a device out whatever its use: none of them can
/// be fixed by local preparation.
fn hard_reasons(d: &Raw, duplicate: bool) -> BTreeSet<IneligibleReason> {
    let mut r = BTreeSet::new();
    if d.removable {
        r.insert(IneligibleReason::Removable);
    }
    if d.transport == Transport::Usb {
        r.insert(IneligibleReason::Usb);
    }
    // A remote disk (iSCSI, Fibre Channel) is someone else's storage.
    let virtual_disk = d.remote
        || (d.kind == DeviceKind::Disk
            && (d.virtual_path || d.transport == Transport::Virtio || d.name.starts_with("xvd")));
    if virtual_disk || matches!(d.kind, DeviceKind::Virtual | DeviceKind::Dm) {
        r.insert(IneligibleReason::Virtual);
    }
    if d.read_only {
        r.insert(IneligibleReason::ReadOnly);
    }
    if duplicate {
        r.insert(IneligibleReason::DuplicateIdentity);
    }
    r
}

/// What stands between an unused whole disk and a dedicated disk.
fn dedicated_reasons(d: &Raw) -> BTreeSet<IneligibleReason> {
    let mut r = BTreeSet::new();
    if !d.partitions.is_empty() {
        r.insert(IneligibleReason::HasPartitions);
    }
    // No udev entry: nothing proves the device carries no signature.
    if !d.udev.found || d.udev.fs_type.is_some() || d.udev.part_table {
        r.insert(IneligibleReason::HasSignature);
    }
    if d.kind == DeviceKind::Disk {
        if d.size_bytes < MIN_DEDICATED_DISK_GB * 1024 * 1024 * 1024 {
            r.insert(IneligibleReason::TooSmall);
        }
        if d.ids.is_empty() {
            r.insert(IneligibleReason::NoStableId);
        }
        if d.controller.as_ref().is_some_and(|c| c.raid_mode) {
            r.insert(IneligibleReason::BehindControllerRaidMode);
        }
    }
    r
}

/// The devices sharing a filesystem UUID with another (the members of a
/// multi-device btrfs, of an md array): `{name: its peers}`.
fn uuid_peers(disks: &HostDisks) -> BTreeMap<&str, Vec<&str>> {
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for d in disks.devices.values() {
        if let Some(u) = &d.udev.fs_uuid {
            groups.entry(u.as_str()).or_default().push(d.name.as_str());
        }
    }
    let mut out = BTreeMap::new();
    for members in groups.values().filter(|m| m.len() > 1) {
        for m in members {
            out.insert(
                *m,
                members
                    .iter()
                    .copied()
                    .filter(|p| p != m)
                    .collect::<Vec<_>>(),
            );
        }
    }
    out
}

/// Why an UNUSED device is not free, though nothing holds or mounts it:
/// no udev entry (nothing known), a stack member's signature, a member of
/// a multi-device filesystem, an array that is not running.
fn unproven(d: &Raw, multi_device: bool) -> Option<BTreeSet<IneligibleReason>> {
    let mut r = BTreeSet::new();
    // No udev entry: nothing proves it carries no signature.
    if !d.udev.found {
        r.insert(IneligibleReason::HasSignature);
        return Some(r);
    }
    // A partition whose type udev did not record: nothing proves it is no
    // boot partition (the reasons below still say what else it is).
    if d.kind == DeviceKind::Partition && !d.udev.part_entry_typed {
        r.insert(IneligibleReason::HasSignature);
    }
    let fs = d.udev.fs_type.as_deref();
    if fs.is_some_and(|f| !PLAIN_FILESYSTEMS.contains(&f)) || multi_device {
        r.insert(IneligibleReason::HasSignature);
        r.insert(if fs == Some("swap") {
            IneligibleReason::Swap
        } else {
            IneligibleReason::HolderBusy
        });
        return Some(r);
    }
    if !r.is_empty() {
        return Some(r);
    }
    let md_stopped =
        d.md.as_ref()
            .is_some_and(|md| !md.state.as_deref().is_some_and(|s| MD_RUNNING.contains(&s)));
    if md_stopped {
        r.insert(IneligibleReason::HasSignature);
        r.insert(IneligibleReason::HolderBusy);
        return Some(r);
    }
    None
}

/// What the classification could not prove: then nothing is offerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unknown {
    /// The agent config could not be read: no pool, state root or
    /// dedicated disk is known.
    NoView,
    /// `/` does not resolve to a block device of this host (a ZFS root,
    /// `/dev/root` on an anonymous device, no mountinfo).
    RootUnresolved,
    /// A boot path is configured (fstab, an automount) on a device that
    /// could not be identified.
    BootUnresolved,
}

/// Classify every device of `disks` against the agent's `view` (`None`:
/// the config could not be read). Fails closed: when the agent's view or
/// the root filesystem is unknown, no device is `eligible_*` or
/// `needs_prep` (the reasons say `system`: nothing proves it is not), and
/// what is unknown is returned.
pub(crate) fn classify(
    disks: &HostDisks,
    view: Option<&StorageView>,
) -> (BTreeMap<String, Class>, Vec<Unknown>) {
    let direct = direct_uses(disks, view);
    let peers = uuid_peers(disks);
    let mut wwn_count: BTreeMap<&str, usize> = BTreeMap::new();
    for d in disks.devices.values() {
        if d.kind == DeviceKind::Disk {
            if let Some(w) = &d.udev.wwn {
                *wwn_count.entry(w.as_str()).or_default() += 1;
            }
        }
    }
    let dedicated: BTreeSet<&str> = view
        .map(|v| v.dedicated.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let ctx = Ctx {
        disks,
        direct: &direct,
        peers: &peers,
        dedicated: &dedicated,
    };
    let mut classes: BTreeMap<String, Class> = disks
        .devices
        .values()
        .map(|d| {
            let duplicate = d
                .udev
                .wwn
                .as_deref()
                .is_some_and(|w| wwn_count.get(w).copied().unwrap_or(0) > 1);
            (d.name.clone(), classify_one(&ctx, d, duplicate))
        })
        .collect();
    // A partition of the system disk (an ESP behind autofs, BIOS boot, a
    // recovery partition) is never free. The approved exception (module
    // doc): a mounted one that qualifies as a pool stays `eligible_pool`
    // — declaring a pool destroys nothing, and the dashboard never offers
    // mkfs or a wipe for it.
    let system_disks: BTreeSet<String> = classes
        .iter()
        .filter(|(_, c)| c.role == DeviceRole::System)
        .map(|(n, _)| n.clone())
        .collect();
    for d in disks.devices.values() {
        if d.parent.as_ref().is_some_and(|p| system_disks.contains(p)) {
            if let Some(c) = classes.get_mut(&d.name) {
                if matches!(
                    c.role,
                    DeviceRole::EligibleDedicated | DeviceRole::NeedsPrep | DeviceRole::Ineligible
                ) {
                    c.role = DeviceRole::Ineligible;
                    c.reasons.insert(IneligibleReason::System);
                }
            }
        }
    }
    // A boot partition — typed, flagged or labelled so by udev, or
    // configured on a boot path in fstab — and its whole disk are the
    // system's, mounted or not (a separate boot disk, the second ESP of a
    // RAID1-boot host).
    // Any device kind: an assembled md / dm carrying an `EFI*` vfat is a
    // boot device too, and so is everything below it (its slaves, theirs).
    let mut boot: BTreeSet<&str> = disks
        .devices
        .values()
        .filter(|d| d.udev.boot)
        .map(|d| d.name.as_str())
        .chain(disks.boot_configured.iter().map(String::as_str))
        .collect();
    let mut level: Vec<&str> = boot.iter().copied().collect();
    for _ in 0..MAX_STACK_DEPTH {
        let mut next = Vec::new();
        for n in level {
            for s in disks
                .devices
                .get(n)
                .map(|d| d.slaves.as_slice())
                .unwrap_or(&[])
            {
                if let Some((k, _)) = disks.devices.get_key_value(s) {
                    if boot.insert(k.as_str()) {
                        next.push(k.as_str());
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    let mut boot_and_disks: BTreeSet<&str> = boot.clone();
    let mut siblings: BTreeSet<&str> = BTreeSet::new();
    for b in &boot {
        if let Some(parent) = disks.devices.get(*b).and_then(|d| d.parent.as_deref()) {
            boot_and_disks.insert(parent);
            if let Some(p) = disks.devices.get(parent) {
                siblings.extend(p.partitions.iter().map(String::as_str));
            }
        }
    }
    // The boot disk's other partitions: as a system disk's (a mounted
    // pool-capable one stays `eligible_pool`, the approved exception).
    for name in siblings.difference(&boot_and_disks) {
        if let Some(c) = classes.get_mut(*name) {
            if matches!(
                c.role,
                DeviceRole::EligibleDedicated | DeviceRole::NeedsPrep | DeviceRole::Ineligible
            ) {
                c.role = DeviceRole::Ineligible;
                c.reasons.insert(IneligibleReason::System);
            }
        }
    }
    for name in boot_and_disks {
        let Some(c) = classes.get_mut(name) else {
            continue;
        };
        match c.role {
            // A boot stack's component is the system's, not a member of
            // something offerable.
            DeviceRole::EligibleDedicated
            | DeviceRole::EligiblePool
            | DeviceRole::NeedsPrep
            | DeviceRole::Member
            | DeviceRole::Ineligible => {
                c.role = DeviceRole::Ineligible;
                c.reasons.insert(IneligibleReason::System);
            }
            // Declared anyway: the agent's apply-time checks refuse it.
            DeviceRole::DedicatedFree | DeviceRole::DedicatedAssigned => {
                c.reasons.insert(IneligibleReason::System);
            }
            _ => {}
        }
    }
    let mut unknown = Vec::new();
    if disks.boot_unresolved {
        unknown.push(Unknown::BootUnresolved);
    }
    if view.is_none() {
        unknown.push(Unknown::NoView);
    }
    if !disks.root_resolved() {
        unknown.push(Unknown::RootUnresolved);
    }
    if !unknown.is_empty() {
        for c in classes.values_mut() {
            if matches!(
                c.role,
                DeviceRole::EligibleDedicated | DeviceRole::EligiblePool | DeviceRole::NeedsPrep
            ) {
                c.role = DeviceRole::Ineligible;
                c.reasons.insert(IneligibleReason::System);
            }
        }
    }
    (classes, unknown)
}

/// What every device's classification reads.
struct Ctx<'a> {
    disks: &'a HostDisks,
    direct: &'a BTreeMap<String, Uses>,
    peers: &'a BTreeMap<&'a str, Vec<&'a str>>,
    dedicated: &'a BTreeSet<&'a str>,
}

impl Ctx<'_> {
    /// The uses of `name` and of everything stacked above it.
    fn uses(&self, name: &str, into: &mut Uses) {
        let stack = above(self.disks, name);
        for n in std::iter::once(name).chain(stack.iter().copied()) {
            if let Some(u) = self.direct.get(n) {
                into.system |= u.system;
                into.swap |= u.swap;
                into.state_root |= u.state_root;
                into.mounted |= u.mounted;
                into.pools.extend(u.pools.iter().cloned());
            }
        }
    }
}

fn classify_one(ctx: &Ctx<'_>, d: &Raw, duplicate: bool) -> Class {
    let disks = ctx.disks;
    let own = ctx.direct.get(&d.name).cloned().unwrap_or_default();
    let mut all = Uses::default();
    ctx.uses(&d.name, &mut all);
    // A member of a multi-device filesystem is used as the filesystem is
    // (the second device of a btrfs `/` is the system too).
    let peers = ctx.peers.get(d.name.as_str());
    for p in peers.into_iter().flatten() {
        ctx.uses(p, &mut all);
    }
    let multi_device = peers.is_some() && d.udev.fs_type.as_deref() != Some("linux_raid_member");
    let component = !d.holders.is_empty();
    let part_holders = d
        .partitions
        .iter()
        .any(|p| disks.devices.get(p).is_some_and(|p| !p.holders.is_empty()));
    let hard = hard_reasons(d, duplicate);
    let mut reasons = BTreeSet::new();
    if own.mounted || (all.mounted && !d.partitions.is_empty()) {
        reasons.insert(IneligibleReason::Mounted);
    }
    if !d.partitions.is_empty() {
        reasons.insert(IneligibleReason::HasPartitions);
    }
    if component || part_holders {
        reasons.insert(IneligibleReason::HolderBusy);
    }
    if own.swap {
        reasons.insert(IneligibleReason::Swap);
    }
    let class = |role, reasons: BTreeSet<IneligibleReason>| Class {
        role,
        reasons,
        pool_ids: all.pools.clone(),
        dedicated_id: None,
    };
    // In use above: what it backs.
    if all.system {
        reasons.insert(IneligibleReason::System);
        let role = if component {
            DeviceRole::Member
        } else {
            DeviceRole::System
        };
        return class(role, reasons);
    }
    for (used, role) in [
        (all.state_root, DeviceRole::StateRoot),
        (!all.pools.is_empty(), DeviceRole::PoolBacking),
    ] {
        if used {
            let role = if component { DeviceRole::Member } else { role };
            return class(role, reasons);
        }
    }
    if let Some(id) = d.ids.iter().find(|id| ctx.dedicated.contains(id.as_str())) {
        let mut r = reasons;
        r.extend(hard);
        r.extend(dedicated_reasons(d));
        if let Some(u) = unproven(d, multi_device) {
            r.extend(u);
        }
        return Class {
            dedicated_id: Some(id.clone()),
            ..class(DeviceRole::DedicatedFree, r)
        };
    }
    if component || part_holders {
        return class(DeviceRole::Member, reasons);
    }
    if own.mounted {
        reasons.extend(hard.iter().copied());
        let poolable = pool_fs(disks, &d.name)
            && !hard.iter().any(|r| {
                matches!(
                    r,
                    IneligibleReason::Removable
                        | IneligibleReason::Usb
                        | IneligibleReason::ReadOnly
                        | IneligibleReason::Virtual
                )
            })
            && d.kind != DeviceKind::Virtual
            && !multi_device;
        let role = if poolable {
            DeviceRole::EligiblePool
        } else {
            DeviceRole::Ineligible
        };
        return class(role, reasons);
    }
    if all.mounted {
        // A partition of it is mounted (and no pool, no system).
        reasons.extend(hard);
        return class(DeviceRole::Ineligible, reasons);
    }
    // Unused: free only on positive proof.
    reasons.extend(hard.iter().copied());
    reasons.extend(dedicated_reasons(d));
    let mut blocked = unproven(d, multi_device);
    for p in &d.partitions {
        if let Some(p) = disks.devices.get(p) {
            let p_multi = ctx.peers.contains_key(p.name.as_str())
                && p.udev.fs_type.as_deref() != Some("linux_raid_member");
            if let Some(u) = unproven(p, p_multi) {
                blocked.get_or_insert_with(BTreeSet::new).extend(u);
            }
        }
    }
    if let Some(u) = blocked {
        reasons.extend(u);
        return class(DeviceRole::Ineligible, reasons);
    }
    let prep = reasons.contains(&IneligibleReason::HasPartitions)
        || reasons.contains(&IneligibleReason::HasSignature);
    let role = if !hard.is_empty() {
        DeviceRole::Ineligible
    } else {
        match d.kind {
            DeviceKind::Disk if prep => DeviceRole::NeedsPrep,
            DeviceKind::Disk if reasons.is_empty() => DeviceRole::EligibleDedicated,
            DeviceKind::Disk => DeviceRole::Ineligible,
            DeviceKind::Partition | DeviceKind::Md => DeviceRole::NeedsPrep,
            DeviceKind::Dm | DeviceKind::Virtual => DeviceRole::Ineligible,
        }
    };
    class(role, reasons)
}
