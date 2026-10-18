# Design: Verified disk tiers (NVMe / SSD / HDD) and dedicated physical disks

**Status:** Proposed (spec only, nothing implemented) · **Date:** 2026-10-15

This spec spans this repo (guest agents, the miner agent, vali) and
`hippius-backend` (sale, billing, dashboards). Backend paths are cited as
`backend:<path>`.

## 1. Goal

Sell disk performance classes we can stand behind, on hosts we do not trust:

- **An OS disk tier per VM**: `nvme`, `ssd` or `hdd` (the budget offer). The
  OS disk is the golden overlay upper, LUKS2 + dm-integrity, as today. It
  lives on a **storage pool** of the miner: a mounted filesystem the miner
  declares.
- **Dedicated physical disks**: optional whole disks passed through to the
  VM, almost bare metal. A VM can take several and build its own redundancy
  inside (mdadm, ZFS, btrfs). The size is the disk's size.
- **The tier is a verified fact, not a declaration.** A pool or a disk gets a
  tier only from a vali-owned attested probe VM (or an audited operator
  override). Host-reported facts (`lsblk ROTA`, model strings, smartctl) are
  never used to classify: they lie, especially behind RAID controllers. The
  agent reads device identity (by-id name, WWN/serial) only for safety and
  identity binding, never for a tier.

Non-goals in v1: hot-plug, attaching dedicated disks after launch (v1.1),
detach, migrating or backing up dedicated disks, SSD/NVMe dedicated disks as
their own product, sealed probe results.

## 2. Threat model

The miner owns the host: the I/O scheduler, cgroups (`io.max`), where the
backing files live, the libvirt cache mode and the timing. **SEV-SNP gives
confidentiality, integrity and measured launch. It gives no guarantee about
I/O performance or availability.** Every tier claim is therefore
statistical evidence, never a proof.

Two signals, with different trust and different jobs:

| Signal | Forgeable by | Job |
|---|---|---|
| **Active probe**: a vali-owned attested CVM runs a fixed I/O benchmark and returns the result inside its guest-signed telemetry receipt | nobody but vali: the signing key is derived from the KBS-released lifecycle seed, which the miner never holds, and the probe VM has no tenant root | **Verdict.** Assigns, downgrades or upgrades a tier. Feeds cordon and merit. |
| **Passive tenant stats**: every tenant guest adds `/sys/block/vd*/stat` deltas to its signed receipt | in-VM root, for its own VM only (a tenant, or a miner renting from itself) | **Trigger only.** Detects selective throttling of real tenants and schedules a targeted re-probe. It never punishes on its own. |

| Attack | Effect | Mitigation |
|---|---|---|
| Fake host facts (rotational flag, smartctl, model string) | any tier | Never used for a tier. Heartbeat disk numbers stay a clamp-down only. |
| Forge a probe result | fake tier | Signed by the probe VM's lifecycle-derived telemetry key. The probe has no root path: no tenant ssh keys, KBS-released userdata written by vali. vali binds `run_id` + nonce + vm_id + owner to a `DiskProbeRun`, so a tenant writing a fake `disk_probe` field into its own receipts is rejected. |
| Detect the probe and un-throttle only for it | probe passes, tenants suffer | The probe looks like a tenant: common flavor, golden image, backend-shaped owner and vm_id, jittered start and lifetime, NetBird on. Passive tenant stats are the continuous control: selective throttling shows up in real tenants' latency and triggers a re-probe. |
| Back the probe's disk on fast media and tenants on slow media | same | The same passive control. The miner can only separate by identity heuristics. |
| Host page cache or a RAM-backed image (`cache=writeback`, tmpfs) | inflated numbers | 16 GiB working set. **Suspect-cache sanity**: QD1 4 KiB read p50 < 25 µs is implausible through virtio + SNP + crypto, so the probe is `suspect-cache` and counts as **failed**, with an alert. Dedupe/compression is defeated by AES-XTS ciphertext. |
| Throttle later (`io.max`, oversubscription) | degradation after admission | Periodic probes (weekly, random jitter), a probe after an agent upgrade, passive-triggered probes. |
| A tenant forges bad stats to grief a miner | penalty on an honest miner | Passive stats never downgrade, cordon or penalise. Passive-triggered probes are rate-limited per miner (1 per 24 h). Aggregation is per owner first, so one owner is one vote. |
| A miner-as-tenant forges good stats on its own VMs | dilutes the aggregate | Per-owner aggregation; the trigger fires on **any** sustained bad non-internal owner. Internal owners are trusted witnesses. |
| Probe I/O hurts tenants on a weak host | collateral | ≤ ~4-5 min of I/O on a pool, early stop once the tier is decided, never probe a host with fewer than 2 free admission slots. |
| Operator-requested probe (announced by definition) | un-throttle for it | It runs at a random time 6-48 h later, at most once per 7 days per node. It may lower or confirm a tier; an upgrade, or lifting `degraded`, needs the next unannounced probe to pass too. |
| Swap or substitute a dedicated disk | serve another disk's data, or an empty one | The agent binds the by-id name to the device WWN/serial (honest agent). The guest records each slot's LUKS UUID on the integrity-protected OS disk and refuses to format or open a slot whose header is missing or different (`dedicated-disk-mismatch`). The miner cannot forge that record. |

**Dedicated disks, residual risk.** They use LUKS2 AES-XTS without
dm-integrity (an integrity wipe at 18+ TB is not workable). The miner never
reads the data, but it **can corrupt sectors or roll them back** to older
ciphertext undetected, and it sees which blocks are written. Customers who
need authenticity run ZFS/btrfs checksums or dm-integrity on top; the
console says so. On release the LUKS header areas are overwritten and the
disk is re-probed before reuse; even without that, the old keyslot is
unopenable once the VM's KEK is erased.

**Probe identity.** Receipts transit the miner in plaintext, so a miner can
read `disk_probe` after the fact and learn which VM was a probe. v1 accepts
this; identity and timing are jittered. Sealing the result to a vali key is
a v2 option. Operator-facing views show probe history at **day** granularity
only, with no probe vm_id, owner or exact timestamp.

## 3. Tiers and thresholds

### 3.1 Semantics

- A tier is a **verified class of per-VM deliverable I/O** on a pool (or a
  dedicated disk), under the host's real load. It is not what the raw
  device can do. A miner that sets a fair per-VM `io.max` is fine, as long
  as each VM still clears the floor.
- **Order**: `nvme` > `ssd` > `hdd` > `unfit`, plus `unknown` (never
  probed). `unknown` and `unfit` qualify for nothing.
- A requested tier is a **minimum**. An `hdd` disk may land on an nvme pool;
  the score prefers the lowest adequate tier, so fast capacity stays free.
- **Classification = the minimum over all metrics** of the highest tier each
  metric clears. One bad axis caps the tier. Below the hdd floor on any axis
  ⇒ `unfit`.
- Thresholds are **guest-observed** at a fixed probe flavor, through virtio,
  SNP bounce buffers and the disk's crypto layers. They are never
  datasheet numbers. At 2 vCPU the crypto layer is a real bottleneck, so the
  CPU generation and vCPU count are recorded with each result.

### 3.2 Profile `v1` (pools, OS disk)

The probe VM uses the `medium` flavor (2 vCPU / 8 GiB / 80 GiB), a common
tenant shape. The engine is a small static Rust binary
(`hippius-agent-disk-probe`): `O_DIRECT`, N threads issuing blocking
`pread`/`pwrite` (QD = N), offsets drawn from a keyed SHA-256 stream seeded by the
vali nonce, latency in a log-bucket histogram. It runs on a file in the OS
disk's filesystem, i.e. through LUKS2 + dm-integrity.

| # | Phase | Shape | Duration | Outputs |
|---|---|---|---|---|
| 0 | first-boot integrity wipe (already done) | full disk | n/a | wipe MB/s (reported, not graded in v1) |
| 1 | precondition + seq write | 16 GiB file, 1 MiB, QD8 | until written (≤ 180 s) | `seq_write_MBps` |
| 2 | seq read | 1 MiB, QD8 | 30 s (+5 s ramp) | `seq_read_MBps` |
| 3 | random read | 4 KiB, QD32 | 45 s (+5 s) | `rr_iops`, `rr_p99_us` |
| 4 | random write | 4 KiB, QD32 | 45 s (+5 s) | `rw_iops`, `rw_p99_us` |
| 5 | random read | 4 KiB, QD1 | 30 s | `qd1_p50_us`, `qd1_p99_us` |

**Thresholds v1** (starting values; re-fit after the record-only calibration
week, classify table only):

| Metric | nvme | ssd | hdd (floor) |
|---|---|---|---|
| `seq_read_MBps` ≥ | 900 | 300 | 80 |
| `seq_write_MBps` ≥ | 500 | 200 | 60 |
| `rr_iops` (4K QD32) ≥ | 25 000 | 8 000 | 300 |
| `rw_iops` (4K QD32) ≥ | 10 000 | 3 000 | 150 |
| `qd1_p99_us` ≤ | 1 000 | 3 000 | 50 000 |
| `rr_p99_us` (QD32) ≤ | 8 000 | 25 000 | 400 000 |
| sanity: `qd1_p50_us` ≥ | 25 | 25 | 25 |

A failed sanity check ⇒ `suspect-cache` ⇒ the probe is **failed** (not a
tier). Calibration notes:

- A RAID-1 of SATA SSDs can split reads across members and clear nvme
  **read** floors, while a cacheless write path keeps the write metrics at
  ssd. The min-over-metrics rule keeps that honest. If a host clears nvme on
  every axis, nvme is the correct verdict: the tier is delivered
  performance, not the media label.
- If an NVMe host lands under 1.5× an nvme floor in calibration, lower the
  floor. Thresholds are never fitted to a single host.

### 3.3 Profile `d1` (dedicated disks)

Every `pending_probe` dedicated disk of a node (declared, or just
released) is probed by the next probe VM, up to 8 disks per run, one disk at
a time, through
**dm-crypt plain with an ephemeral random key** (the tenant cipher path,
AES-XTS, no header written):

1. zoned sequential read at 0 %, 50 % and 95 % of the LBA range, 1 MiB QD8,
   15 s each (the inner zone is graded);
2. random read 4 KiB QD32 across the full span, 30 s;
3. QD1 4 KiB read p99, 20 s;
4. in a random 8 GiB window: seq write 1 MiB QD8 for 20 s, then
   **sustained** random write 4 KiB QD32 for 60 s (exposes SMR collapse and
   the cache-full cliff);
5. sampled surface read: 2048 × 1 MiB at uniformly spread offsets.

About 3.5 min per disk, so a full run of 8 disks is about half an hour of
I/O. The disks are free (no tenant data, no neighbours on them), so the
pool-probe duration and collateral limits do not apply. **hdd floors, d1:**

| Metric | hdd floor |
|---|---|
| inner-zone seq read | ≥ 60 MB/s |
| outer-zone seq read | ≥ 120 MB/s |
| random read QD32 | ≥ 200 IOPS |
| QD1 p99 | ≤ 60 ms |
| sustained random write QD32 | ≥ 100 IOPS |
| surface sample | 0 I/O errors |

Any I/O error ⇒ `unfit` and the disk is `failed`. The suspect-cache sanity
applies as in v1. Better results classify `ssd`/`nvme`; in v1 every
dedicated disk is sold as `hdd`-minimum, so an SSD offered as a dedicated
disk is fine.

### 3.4 Hysteresis (pools)

- **Admission** (`unknown` → tier): one probe; a second probe within 48 h
  confirms it.
- **Downgrade**: two consecutive probes below the current tier's floor at
  least 6 h apart, **or** one probe below 0.5× the floor.
- **Upgrade**: two consecutive passes at least 24 h apart. An
  operator-requested probe alone never upgrades (§2).

### 3.5 Passive envelopes (trigger only)

Per 60 s receipt window and per device: IOPS, average I/O size, read/write
await, utilisation and average queue depth (Little's law) from the
`/sys/block` deltas. The signal is the latency of **small I/Os (≤ 32 KiB
average) in windows with average QD ≥ 4**.

| Pool tier | suspect if the hourly per-owner median read await (QD ≥ 4 windows) > | sustained |
|---|---|---|
| nvme | 3 ms | ≥ 2 h |
| ssd | 8 ms | ≥ 2 h |
| hdd | 80 ms | ≥ 2 h |

Any non-internal owner suspect (or ≥ 2 owners) ⇒ the pool is `suspect` ⇒ a
re-probe is scheduled (≤ 1 per 24 h per miner). Devices are mapped to their
disk slot by the virtio serial, then to a pool or dedicated disk through the
placement record. Dedicated disks have no neighbours, so their degradation
means the disk itself or host throttling; passive alone still only notifies,
and the disk is probed again at its next release.

## 4. Storage model

### 4.1 Pools (OS disks)

A **pool** is a miner-declared mounted filesystem:

| Field | Notes |
|---|---|
| `pool_id` | stable slug `[a-z0-9-]{1,32}` |
| `path` | absolute, canonical, a mount point |
| `class` | `nvme` / `ssd` / `hdd`: an untrusted **hint** for the probe and the operator |
| `budget_gb` | the miner's declared cap (≥ 200 GiB) |
| `os_disks` | whether the pool may receive OS disks; an hdd pool takes OS disks only when explicitly `true` |
| `state` | `active` / `draining` (no new disks) |

- ≤ 4 pools per miner, each on its own filesystem (distinct `st_dev`).
  HDD-only miners are allowed.
- **Placement rule**: the OS disk of a VM sold at tier T goes on a pool with
  verified tier ≥ T, `os_disks=true`, `active`, not retired or
  pool-cordoned, with room for the flavor disk + the rootfs margin. An
  `hdd`-verified pool takes OS disks only for VMs sold `hdd`. The scheduler
  chooses the pool and records it; vali's choice keeps accounting exact.
- **Capacity per pool**: budget = min(declared budget, reported total −
  reserve, earned ceiling); free = min(budget − Σ committed disks on the
  pool, reported available − reserve). Reported sizes are untrusted and
  clamp down only.
- **Backward compatibility**: a miner with no pool declaration has one
  implicit pool `default` = its current data root, built from today's
  capacity columns. That path is unchanged. Legacy placements count as the
  `os` disk on `default`.
- **The hdd OS tier** is the budget offer. The OS overlay keeps
  dm-integrity, so first boot wipes the whole overlay on a spindle: boot
  budgets become tier-aware (the backend's boot wait in B2, vali's probe and
  synthetic-monitor boot timeouts in E1) and the hdd OS tier is limited to flavors up to
  `large` (`VALI_HDD_OS_MAX_FLAVOR`) unless calibration shows faster wipes.
  Consider a boot cap of 1 per hdd pool.

### 4.2 Dedicated physical disks

- **Declared by stable id only**: a `/dev/disk/by-id/` basename (`wwn-0x…`
  preferred, else `ata-…` / `scsi-…`), never `/dev/sdX`.
- **Agent validation**, on apply and on every boot (read-only: `/sys/block`,
  mountinfo, holders, `blkid -p`):

| Check | Refusal code |
|---|---|
| resolves to a **whole** disk (not a partition) | `disk-not-found` / `disk-not-whole-device` |
| a real SCSI/SATA/NVMe disk, not loop/dm/md/nbd/zram/rbd/virtio | `disk-virtual` |
| no partitions, no holders (md/dm/LVM) | `disk-has-partitions` / `disk-holder-busy` |
| not mounted, not swap, not under a pool, the state root or `/` | `disk-in-use` / `disk-is-system` |
| no on-disk signature (fs, LVM, ZFS, md, LUKS, partition table). The agent **never wipes**; the operator runs `wipefs -a` deliberately. | `disk-has-signature` |
| kernel size ≥ the minimum (1000 GiB) | `disk-too-small` |
| unique id, not the same device under another id | `disk-duplicate` |
| changing/removing a disk assigned to a VM (only `draining` is allowed) | `disk-assigned` |

- A disk behind a RAID controller (single-disk RAID0 rather than HBA mode)
  is accepted with a `behind-controller` warning; the probe decides.
- **Identity binding**: the agent records the device WWN/serial next to the
  by-id name and re-checks it on every boot. A mismatch ⇒ `replaced`, never
  attached.
- While assigned, the agent holds the block device open with `O_EXCL` and a
  udev rule hides it from desktop automounters.
- **Capacity** is the set of `free` disks per node with their sizes. There
  is no pool arithmetic.
- **libvirt**: `type='block'`, virtio-blk, `cache='none' io='native'
  discard='ignore'`, and a **virtual serial** `hippius-x<N>`. The guest sees
  slots, never the real serial or WWN.
- **Guest**: per-slot key `HKDF-SHA256(ikm=released KEK,
  salt="hippius-dedicated-disk-v1", info=vm_id‖slot)` via
  `hippius-guest-release --derive <slot>`. One KBS release per boot opens
  every slot; erasing `kek-<vm_id>` crypto-erases every slot, in the
  customer-held key modes too. First boot of a slot: LUKS2 AES-XTS-plain64,
  512-bit, no integrity (instant), with `{slot, luks_uuid, size}` recorded
  on the OS disk. Later boots open by virtual serial and require the
  recorded UUID. **No filesystem is created**: RAID and filesystems are the
  customer's; a `hippius-disks` helper lists slots and prints example
  mdadm/ZFS commands (never runs them).
- **Measured anchor**: the cmdline carries `hippius.dedicated=x0:<GiB>,…`
  only when dedicated disks exist (otherwise the cmdline is byte-identical).
  The guest refuses a slot smaller than the measured size. A listed but
  absent slot is `missing`: boot continues, the customer's array runs
  degraded, an alert fires.

### 4.3 Data model (`vali/apps/disktier`)

| Model | Holds |
|---|---|
| `MinerStoragePool` | one row per (node, pool): declared class, `os_disks`, total/available/budget/earned GB, `reported_at`, verified `tier` + `tier_since`, operator override + reason, `health` (ok / suspect / degraded / severe) + `health_since`, consecutive pass/fail counters, last run, next probe due, agent version at last probe, `auto_cordoned`, `retired_at` |
| `DedicatedDisk` | one row per (node, disk id): size, desired state (active / draining), state, verified tier, last probe, assignment (vm, slot, at, freed), `behind_controller` |
| `DiskProbeRun` | one probe VM: run_id, nonce, vm_id, node, chip, owner, trigger, state, profile, flavor, timestamps, failure reason, and a per-target result list (pool or dedicated disk, metrics, classified tier, verdict detail) |
| `PlacementDisk` | one row per disk of a placement: slot (`os`, `x0`…`x23`; at most 8 dedicated disks at a time, but slots are never reused after a replacement), kind (pool / dedicated), pool id or dedicated disk, size, required tier |
| `VmDiskIoHourly` | passive accumulator per (vm, device, hour), resolved to slot and pool/disk |
| `MinerDiskHealthHourly` | the evaluator's hourly rollup per (node, pool) |

Every tier, health, cordon and override change writes a `MinerCapacityAudit`
row (actor `disk-tier`, or the operator). Retention: hourly passive rows
30 days, rollups 180 days.

## 5. State machines

### 5.1 Pool

| Event | Transition |
|---|---|
| new pool (heartbeat or desired config) | `tier=unknown`, `health=ok`; probe due now |
| unannounced probe classifies ≥ current tier | pass++, fail := 0, `health=ok`; upgrade after 2 passes ≥ 24 h apart if the classified tier is higher |
| operator-requested probe classifies ≥ current tier | confirms the tier only: it never clears `degraded` or `suspect` and never counts toward an upgrade |
| probe below the current tier's floor | fail++, pass := 0, `health=degraded` (merit multiplier) |
| 2nd consecutive fail ≥ 6 h apart, or one probe < 0.5× the floor | **downgrade** to the classified tier (new placements only) |
| classified `unfit`, `suspect-cache`, or 2 consecutive probe timeouts | `health=severe`: if the pool holds OS disks ⇒ **auto-cordon the node** (`cordon_reason="disk-tier: <detail>"`, `auto_cordoned=true`) + page; otherwise a pool-cordon |
| a severe pool passes 2 probes | auto-uncordon **only if** `auto_cordoned` and the reason still starts with `disk-tier:`; a manual cordon is never touched |
| passive suspect | `health=suspect` (no penalty) + schedule a probe |
| pool vanishes from the heartbeat | `retired_at` set: no new disks; existing ones stay accounted |
| operator override | wins over probes until cleared; audited with a reason |

A probe timeout counts as a **failed probe for health** (a miner cannot
dodge by failing launches) but never downgrades a tier on its own. Under
`VALI_DISK_TIER_CONSEQUENCES=record` only events, metrics and audit rows are
written; under `enforce` everything applies.

### 5.2 Dedicated disk

```
declared → pending_probe → (probe d1) → free | unfit
free → assigned (placement, same transaction, row lock) → released (§24)
released → header wipe → pending_probe → (probe) → free | unfit
any → failed (device vanished, offline, I/O error) | replaced (identity mismatch)
draining: no new assignment; leaves placement once released
```

A released disk **never** goes straight back to `free`: the re-probe proves
the disk is still there, healthy, the same device, and that its LUKS header
is gone. A `crypto_LUKS` signature found after the wipe raises an alert.
Assigned disks are never actively probed (they hold customer data).

## 6. Downgrade policy (running VMs)

A verdict changes a (node, pool) tier and affects every running VM with a
disk on it. **Existing placements are never re-gated**; the tier constrains
only new decisions (launch, migration and failover destinations,
price-watch recommendations).

Per-disk `compliance` in the VM status:
`{sold, measured, state: compliant|degraded|unfit, since, remedy:
none|migration-scheduled|migration-impossible|customer-action}`.

| Case | Customer billing | Remedy (`VALI_DISK_TIER_REMEDIATION=off\|notify\|migrate`) | Miner pay |
|---|---|---|---|
| OS disk, measured below sold but ≥ hdd floor | the **measured** tier's price from observation, never retroactive | §25 migration to a compliant pool in the tenant's maintenance window, within a deadline (default 72 h); placement uses the sold tier | at the measured tier, with the degraded merit penalty |
| OS disk, pool `unfit` or `severe` | the lowest sellable tier's price until fixed | node or pool cordon; **priority** migration, outside the window too | withheld for those disks |
| no compliant capacity anywhere | the measured price, indefinitely | `migration-impossible`, retried daily; the customer is notified after 24 h | at the measured tier |
| VM pinned by dedicated disks, OS pool downgraded | as above for the OS part | no migration (`customer-action`) + notification | as above |
| OS pool better than sold | the sold price (never raised) | none | at the **sold** tier |
| dedicated disk degraded (passive, sustained 24 h) | unchanged (there is no lower tier) | notify + offer **replace** | unchanged |
| dedicated disk `failed` / `mismatch` | that slot billed at 0 from observation | notify + offer **replace** | withheld for that slot |

The backend observes compliance through its existing VM sync (≤ ~2 min lag),
splits the usage segment and bills at `min(sold, measured)`. When compliance
returns, billing goes back to the sold tier. Already-submitted usage periods
are never re-opened, so no credit notes are needed. VMs sold before this
change are implicitly `nvme` and follow the same rules once consequences are
enforced.

### 6.1 Lifecycle of VMs with dedicated disks ("pinned")

| Operation | v1 |
|---|---|
| reboot, relaunch, power stop/start, guest upgrade | ✅ same node, same disks (identity-checked by agent and guest) |
| CPU/RAM resize in place | ✅ |
| §25 migration, auto-failover, restore elsewhere, resize-with-migration | ❌ `dedicated-pinned`; the failover worker skips these VMs |
| `require_failover_peer=true` + dedicated disks | ❌ refused at launch |
| backups | dedicated disks ❌ never. OS-disk backups of a pinned VM are not offered in v1: a restore could only land elsewhere, which is refused (open item 16). The customer owns backups. |
| replace a failed slot | ✅ `POST /v1/vm/{vm_id}/dedicated-disks/replace {slot, when}`: a free disk on the **same node**, a **new slot** (slots are never reused), a superseding relaunch (reboot) with the new measured cmdline; the guest formats only the new slot |
| attach more disks later | v1.1 (same superseding-relaunch mechanism) |
| detach, hot-plug | v2 |
| §24 decommission | crypto-erase via `kek-<vm_id>`, then the agent zeroes the first and last 16 MiB of each released disk, then `pending_probe` |
| miner graceful exit | accepted with a **30-day notice period**: no new placements, non-pinned VMs migrate as today, pinned customers are notified on days 0/7/21/28, pinned VMs are decommissioned on day 30. A miner that goes dark during notice has its remaining weights withheld. |

The backend shows the customer an explicit acknowledgement (no backup, no
migration, no failover, data lost if the host is lost, own redundancy and
backups) and stores its timestamp and text version.

## 7. Launch contract (backend → vali)

### 7.1 `POST /v1/vm/launch` additions

```jsonc
{
  // … existing fields unchanged
  "os_disk_tier": "nvme",          // optional: "nvme" | "ssd" | "hdd"; absent or "" ⇒ VALI_SCHEDULER_DEFAULT_DISK_TIER ("nvme")
                                   // MINIMUM tier
  "dedicated_disks": {             // optional; absent ⇒ none
    "tier": "hdd",                 // v1: only "hdd" (minimum; a verified ssd/nvme dedicated disk qualifies)
    "count": 2,                    // 1..VALI_DEDICATED_MAX_PER_VM (8)
    "min_size_gb": 16000           // GiB; each assigned disk ≥ this; ≥ 1000
  },
  "pinned_ack": true               // required true when dedicated_disks is present
}
```

- Persisted in the launch spec only when non-default, so old specs decode
  unchanged and migration/failover/price-watch read the tier back from it.
- `os_disk_tier` is **not** measured: it drives placement and billing only.
  `hippius.dedicated=` is measured, and only present with dedicated disks.
- **Assignment**: one node that fits the OS disk **and** has ≥ `count` free
  dedicated disks with tier ≥ hdd and size ≥ `min_size_gb`. Best fit: the
  smallest qualifying disks first; ties go to the most recently probed.
  `PlacementDisk` rows and the `assigned` state are written in the same
  transaction as the placement, with row locks, so a disk cannot be assigned
  twice.
- The job `result` adds `disks: [{slot, kind, size_gb, tier}]`. It never
  carries a pool id, path or the miner's disk id. `GET /v1/vm/{vm_id}` adds
  the same `disks[]` plus `compliance` and slot states.
- The order to the agent gains `os_pool` and `extra_disks: [{slot,
  kind:"dedicated", disk_id}]` with serde defaults. vali never sends
  non-default values to a node that has not advertised heartbeat v7.

### 7.2 Error categories

Body `{"error": msg, "category": code}`. 400 = caller mistake, 409 =
state/policy conflict.

| Condition | HTTP | category |
|---|---|---|
| `os_disk_tier` not in the enum | 400 | `disk-tier-invalid` |
| `os_disk_tier` valid but not offered (`VALI_SELLABLE_OS_TIERS`, default `["nvme"]`) | 409 | `disk-tier-not-offered` |
| `os_disk_tier=hdd` with a flavor above `VALI_HDD_OS_MAX_FLAVOR` | 409 | `disk-tier-not-offered` |
| malformed `dedicated_disks` | 400 | `dedicated-invalid` |
| count out of range | 400 | `dedicated-count-invalid` |
| `min_size_gb` below the minimum | 400 | `dedicated-size-invalid` |
| `pinned_ack` missing or false | 400 | `dedicated-ack-required` |
| feature off, or owner not allowed | 409 | `dedicated-not-offered` |
| with `require_failover_peer` | 409 | `dedicated-no-failover` |
| image whose blessed guest release lacks dedicated-disk support | 409 | `dedicated-needs-release` |

Asynchronous placement failures (job `failed`, in the `no-eligible-miner`
family, with `tier_skipped=N` / `dedicated_skipped=M` appended):

| Condition | category |
|---|---|
| no host has an OS pool at ≥ tier with room | `no-miner-at-tier` |
| no node has enough free dedicated disks | `no-dedicated-capacity` |
| disks exist, but not on a node that also fits the OS disk | `no-host-fits-disks` |

The backend maps 400 → 422 (same code), 409 and feasibility `never` → 409,
and keeps today's not-now path. A placement failure after purchase follows
the existing failed-launch refund/void path.

### 7.3 Feasibility and regions

- `GET /v1/scheduler/feasibility?…&os_disk_tier=&dedicated_count=&dedicated_min_size_gb=&dedicated_tier=`.
  Every new parameter is optional; absent parameters give a
  **byte-identical** response. Adds `os_disk_tier` (echo), `HostFit.pools:
  [{tier, free_gb, os_disks}]` (no pool ids for non-operator callers), and
  `dedicated: {count, min_size_gb, placeable, max_count_at_size}`. New
  reasons: `no-miner-at-tier`, `no-dedicated-capacity`,
  `no-host-fits-disks`.
- `GET /v1/operator/regions` adds per region `os_disk_tiers: {nvme|ssd|hdd:
  {placeable, hosts}}` and `dedicated_disks: {hdd: {sizes: [{size_gb, free,
  max_per_host}]}}`. `size_gb` is a size class (actual size floored to
  100 GiB); counts are advisory, the launch is authoritative.
- Resize takes no new fields: tier and dedicated disks are inherited, and
  targets that need a migration are excluded for pinned VMs.

## 8. Billing lines

Prices are append-only `ComputePrice` rows. The ratios below are
**configurable factors**, set by the operator of the platform; this spec
fixes only their shape.

| Item | Resource | Shape |
|---|---|---|
| OS disk | `disk_gb_hour:<tier>` | per-tier factor of the base disk rate; the bare `disk_gb_hour` stays the nvme rate (replay-safe) |
| OS tier, whole VM | `vm_tier_bps:<tier>` | a basis-point multiplier on the vCPU + RAM components (identity for nvme). Needed because the disk alone barely moves a VM's price. |
| Dedicated disk | `dedicated_disk_gb_hour:hdd` | a **separate** rate per disk-GB, independent of the OS-disk rates |

- **OS disk tier stays folded into the VM price**:
  `vm_price = (vcpu + ram) × vm_tier_bps:<os_tier> / 10000 + disk_gb ×
  disk_gb_hour:<os_tier> + vm_fee:<code>`. The usage segment freezes
  `os_disk_tier`; a missing value means nvme.
- **One ledger line per dedicated disk**: `kind="vm_disk"`,
  `resource="dedicated_disk_gb_hour:hdd"`, `ref="<vm_id>/x<N>"`,
  `unit="gb_hour"`, quantity = size class GB × billable seconds / 3600. It
  maps to the existing `UsageKind.COMPUTE` in the chain breakdown (no new
  pallet variant). Each disk has its own segment.
  - Billed **while the VM is stopped** (the disk stays reserved).
  - Stops at destroy, at a slot failure, or at replacement (the new slot
    opens its own segment).
- The runway / launch gate includes the dedicated disks' hourly amount.
- **Miner pay**:
  - OS disks: a per-tier unit factor (`VALI_DISK_TIER_UNIT_FACTOR`,
    configurable, nvme ≥ ssd ≥ hdd) on the VM's units, at the **measured**
    tier from the verdict, and the **sold** tier when the pool is better.
  - Dedicated disks: revenue-proportional units per disk, carried by
    `VmBillingBinding` (authoritative over guest fields) into the usage
    accrual. Withheld for a slot that is `failed`, `unfit` or `mismatch`.
  - Merit multiplier from pool health: no penalty for ok/suspect,
    configurable factors for degraded and severe (severe the strongest),
    capacity-weighted across a node's pools.
  - Every factor is default-off, so epoch weights stay byte-identical until
    flipped.

## 9. Storage-config control plane

Miners configure pools and dedicated disks from the providers dashboard. The
dashboard writes a **desired document** to vali; vali pushes it as a signed
order.

- **Transport**: a new order kind `storage-config` on the existing
  vali → Edge → agent order channel (Edge Ed25519 order key, pinned by the
  agent), with the net-policy state machine: revision bump on content
  change, 409 stale ⇒ jump revision, 422 unsupported ⇒ hold, 500 ⇒ backoff,
  periodic re-push. The agent reports its applied revision in heartbeat v7,
  so vali sees drift or a missed push within one heartbeat.
- **Order body** (`deny_unknown_fields`, full document, never a patch,
  all-or-nothing):

  ```text
  { revision, not_after_unix, dry_run,
    pools: [ { id, path, class, budget_gb, os_disks, state } ],   // 1..=4, sorted by id
    dedicated_disks: [ { id, state } ] }                           // ≤ 24
  ack: "applied:<rev>:<sha>" | "dry-run-ok:<rev>:<sha>"
  refusal: 422 {"code": "<closed enum>", "pool"|"disk": "<id>"}
  ```

- **Agent pool validation** (on apply and every boot): path absolute and
  canonical (`pool-path-invalid`), exists, root-owned, not group/world
  writable (`pool-path-missing` / `pool-path-perms`), a mount point
  (`pool-not-a-mount`), not the root filesystem except the grandfathered
  local `default` pool (`pool-on-root-fs`), fstype ext4/xfs/btrfs
  (`pool-fstype-unsupported`), `O_DIRECT` works
  (`pool-odirect-unsupported`), distinct filesystems (`pool-shared-fs`),
  budget ≤ fs total − reserve (`pool-budget-exceeds-fs`), id syntax and
  count (`pool-id-invalid` / `too-many-pools`).
- **Live-disk safety** (hard refusals): changing the path of a pool holding
  disks, or removing it (`pool-has-disks`; use `draining`); shrinking the
  budget below committed (`pool-budget-below-committed`). Growing the
  budget, changing the class hint and turning `os_disks` off are allowed.
- **For pools and declarations, the agent never formats, mounts, unmounts,
  wipes or moves anything.** (The one write it does to a dedicated disk is
  the LUKS header-area wipe on release, §6.1.) A
  pool whose mount vanished after a reboot is `unavailable`; launches to it
  get `507 pool-unavailable`; nothing is reassigned automatically.
- **Precedence**: applied remote config > local `[[storage.pools]]` /
  `[[storage.dedicated_disks]]` (bootstrap) > implicit `default`.
- **Local only, never remote**: identity, trust anchors (including the order
  signing key), NetBird enrolment, KBS/attestor/backup credentials, the
  state root, auto-upgrade.
- **vali**: `MinerStorageConfig` (desired doc, revision, ack state, last
  refusal, who/when) + an append-only audit. Sync status: `in_sync`,
  `pending`, `refused:<code>:<id>`, `agent-unsupported`, `drift`. Pushed
  only to agents ≥ `VALI_STORAGE_CONFIG_MIN_AGENT_VERSION` and in
  `VALI_STORAGE_CONFIG_MINERS`. Placement reads **applied** state only:
  acked, in a fresh heartbeat, `active`, and verified.
- **Auth for writes**: a dedicated service principal
  (`IsOperatorConfigWriter`, its own token), plus acting-family and
  acting-user headers; vali re-checks on chain that the node belongs to the
  acting family (`not-family-node` ⇒ 403). Every write is audited.
- **Operator endpoints** (node-scoped, proxied by the backend): storage doc
  GET/PUT (`If-Match`), pool CRUD sugar, dry-run validate, adopt
  (desired := applied; the heartbeat carries no pool path, so adopt takes
  one per reported pool), history, disk tiers, probe history (day
  granularity), request a re-probe (1 per 7 days, 429 + `retry_after`),
  passive health aggregates (no tenant VM ids or owners), and the
  dedicated-disk inventory, validate and drain.
- **Dashboard stages**: S-1 generate-and-paste TOML with read-only applied
  state; S-2 opt-in "manage from dashboard" (adopt, edit, validate on
  host); S-3 dashboard by default for new miners.

## 10. Phases and flags

Every flag is default-off. vali accepts a field before anyone sends it.
Chart keys are add-only and must be safe with the image currently pinned.
Every PR touching the UKI closure carries its KAT re-pin.

| Phase | Repo | Scope | Dark mechanism |
|---|---|---|---|
| S1 | compute | this document | n/a |
| V0.1 | vali | lift the synthetic-monitor teardown (§24 decommission + force-destroy fallback) into `orchestration/teardown.py` (pure move) | n/a |
| V0.2 | vali | `apps/disktier`: models, `DiskTier` ranks, `classify.py` (v1 + d1), admin, `GET /v1/operator/disk-profiles`, `vali_set_pool_tier` (audited) | nothing reads the tables |
| T1 | types | receipt `disk_io` (+serial, slot states) / `disk_probe` (per target); heartbeat v7 `disk_pools` + `dedicated_disks` + `storage_config_revision` | additive; old vectors byte-identical |
| T2 | vali | accept receipt fields + heartbeat v7; pool rows from v7 (record only) | `VALI_DISK_IO_INGEST=false` |
| T3 | vali + edge | `storage-config` order kind (encoder allowlist, vector, Edge kind) incl. dedicated disks | no sender |
| A1 | agent | pools engine: local config, per-pool preflight/reservation/adopt/destroy, `insufficient-disk:<pool>`, v7 emission | no config ⇒ single `default` pool, byte-identical |
| A1b | agent | `storage-config` route, validation, dry run, persistence, restart re-validation | vali does not send |
| A3 | agent | dedicated-disk inventory, identity binding, `O_EXCL` hold, header wipe on release | empty inventory ⇒ no-op |
| A4 | agent | launch order `os_pool` / `extra_disks` (dedicated), block-device XML with virtual serial | vali never sends non-defaults |
| V1 | vali | `MinerStorageConfig` + push loop + operator API (incl. dedicated disks) | `VALI_STORAGE_CONFIG_PUSH`, miner allowlist, min agent version |
| B0, U0a/U0b | backend, console | operator storage views; providers StoragePanel | backend flag + beta gate |
| G1-G4 | guest | `DiskStatsSource`; `agent-disk-probe` (v1 + d1); `--derive <slot>`, dedicated-disks unit, `hippius-disks`; guest release | inert without request file / cmdline token |
| P1/P2 | vali | ingest → hourly rows; evaluator per pool | `VALI_DISK_IO_INGEST`, consequences `record` |
| R1/R3 | vali | probe orchestrator per pool; dedicated-disk probe and disk state machine; alerts | `VALI_DISK_PROBE_ENABLED`, CronJobs suspended; calibration week |
| E1/E2 | vali | per-pool fit + tier gate, `os_disk_tier`, feasibility/regions | `VALI_SCHEDULER_DISK_TIER_GATE=off\|record\|enforce` |
| E4 | vali | `dedicated_disks` + `pinned_ack`, assignment, measured `hippius.dedicated=`, pinned refusals, failover skip | `VALI_DEDICATED_ENABLED`, `VALI_DEDICATED_ALLOWED_OWNERS` |
| X2′ | ops | live e2e on a host with a spare whole disk: declare → probe → launch → write → reboot → §24 → KEK 403, header wiped, re-probe → free | internal owner only |
| E5 | vali | replace API, per-slot compliance, exit notice for pinned VMs | flags |
| C1/C2 | vali | pool state machine, cordon / pool-cordon, merit, tier unit factor. **TODO(C1)**: once verdicts change the tier, the probe's "sellable" test (`apps/disktier/probe.py` `_sellable`, today operator-declared/overridden nvme only) must follow what routing actually sells (a pool that holds or can receive OS disks), without an unfit verdict making its own pool unsold | `VALI_DISK_TIER_CONSEQUENCES`, `VALI_REWARD_DISK_HEALTH_PENALTY`, `VALI_DISK_TIER_UNIT_FACTOR` |
| E3 | vali | per-VM compliance + remediation engine | `VALI_DISK_TIER_REMEDIATION=off\|notify\|migrate` |
| B1/B2/B3/B4 | backend | tier prices + segment freeze; launch/feasibility/regions with the tier, tier-aware boot budgets; compliance segment split; dedicated disk lines | `COMPUTE_SELLABLE_OS_TIERS=["nvme"]`, `COMPUTE_DEDICATED_ENABLED=false` |
| U1/U2 | console | OS tier selector; dedicated-disk picker + acknowledgement + slot states | hidden unless sellable |
| F1-F4 | ops | gate enforce → consequences + remediation → sell ssd/hdd OS tiers → sell dedicated disks | one flip at a time, each measured |

Rollout order:

```
S1 → V0.1 → V0.2 → T1 → T2 → T3 → A1 → U0a → A1b → A3 → A4 → V1 → B0 → U0b
   → G1-G4 → P → R1/R3 (calibration) → E1 → E2 → E4 → X2′ → E5
   → C1/C2 → E3 → B1 → B2 → B4 → B3 → U1/U2 → F1 → F2 → F3 → F4 → S-3
```

Hard ordering rules:

- T2 is live before any agent emits v7 or any guest emits the new receipt
  fields.
- vali pushes `storage-config` only to agents at or above the minimum
  version; any later field addition needs a new minimum version or a new
  kind.
- A pool or disk is placeable only once applied (acked + seen in a v7
  heartbeat) **and** probed.
- Under `enforce`, `unknown` qualifies for no tier: the gate flip requires
  zero Active miners with an unknown OS pool.
- Dedicated disks are refused at launch while the blessed guest release
  lacks G3 (`dedicated-needs-release`).

## 11. Open items

| # | Item | Proposed default |
|---|---|---|
| 1 | Re-fit the v1 and d1 thresholds after the record-only calibration week (every host probed 3× over 7 days). No HDD host exists yet, so the hdd floors stay as proposed until one joins. | classify-table PR only |
| 2 | Per-CPU-generation thresholds if the crypto ceiling at 2 vCPU makes an NVMe host on an older generation read as ssd | only if calibration shows it |
| 3 | The dedicated disk rate | set by the platform operator before F4 |
| 4 | Pool limits: ≤ 4 pools, distinct filesystems, ≥ 200 GiB, HDD-only miners allowed | yes |
| 5 | Remote config scope: pools and dedicated disks in v1; host budgets later | v2 |
| 6 | Operator-requested probes: random 6-48 h later, 1 per 7 days, an upgrade needs the next unannounced pass | yes |
| 7 | Operators see day-granularity probe history and aggregate health only | yes |
| 8 | Who edits a miner's storage: any linked family account, no per-change wallet signature in v1 (audited) | yes |
| 9 | hdd OS tier limited to flavors ≤ `large` (integrity wipe vs the boot cap) | yes, unless calibration shows faster wipes |
| 10 | Unfit OS pools: migrate outside the tenant's maintenance window | yes, for unfit only |
| 11 | Full-surface scan of a dedicated disk at declaration (≈ a day at 18 TB) | sampled scan only; optional operator-triggered full scan |
| 12 | Operator secure-erase before reuse | offered in the dashboard, not required |
| 13 | Stake consequences for a miner that goes dark during a pinned-VM exit notice | weights withheld; stake depends on the staking model |
| 14 | A host with a spare HBA-attached whole disk is a prerequisite for the dedicated-disk e2e (X2′) and the first sale (F4) | test host first |
| 15 | Seal `disk_probe` to a vali key (hide probe identity from the miner) | v2 |
| 16 | OS-disk backups for pinned VMs (useful only with an in-place restore, which does not exist today) | not in v1 |
