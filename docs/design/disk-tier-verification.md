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
| Swap or substitute a dedicated disk | serve another disk's data, or an empty one | The agent binds the by-id name to the device WWN/serial (honest agent). The guest records each slot's LUKS UUID on the integrity-protected OS disk and refuses to format or open a slot whose header is missing or different (`dedicated-disk-mismatch`). The miner cannot forge that record. It CAN replay this slot's own ciphertext (header included) onto another disk: that is the corruption/rollback residual risk below, never a confidentiality loss (§4.2.1). |

**Dedicated disks, residual risk.** By default they use LUKS2 AES-XTS
without dm-integrity (an integrity wipe at 18+ TB is not workable). An
integrity slot (`:i`, guest release 8, §4.2.1) adds AEAD (hmac-sha256): a
corrupted or relocated sector reads as an I/O error, but a sector rolled
back to an OLDER version of itself still verifies. Without it the miner
never reads the data, but it **can corrupt sectors or roll them back** to
older ciphertext undetected, and it sees which blocks are written. Customers who
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
AES-XTS, no header written). The probe VM's disks come with their measured
`hippius.dedicated=` anchor like any VM's, so on guest release 6+ the
initramfs opener (§4.2.1) has already formatted each blank slot as LUKS2
and opened it as `hippius-<slot>`; that mapping holds the device, so the
probe closes it before mapping the slot (guest release 7;
`opener-close-failed` when it will not close). The opener's LUKS header
stays on the disk until the miner's §24 release wipe:

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
applies as in v1. Better results classify `ssd`/`nvme` (thresholds and
their calibration: `dedicated-disks-contract.md` §8); the disk is verified
at the lower of that grade and its operator's declared class (`hdd` when
none is declared), and sold at the tier a launch asks, never above.

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
  salt="hippius-dedicated-disk-v1", info=vm_id‖slot)`, derived inside
  `hippius-guest-release --open-dedicated-disks` in the initramfs (§4.2.1).
  One KBS release per boot opens
  every slot; erasing `kek-<vm_id>` crypto-erases every slot, in the
  customer-held key modes too. First boot of a slot: LUKS2 AES-XTS-plain64,
  512-bit, no integrity (instant), with `{slot, luks_uuid, size}` recorded
  on the OS disk; an integrity slot (`:i`) adds hmac-sha256 and a
  first-boot wipe in the booted OS (§4.2.1). Later boots open by virtual serial and require the
  recorded UUID. **No filesystem is created**: RAID and filesystems are the
  customer's; a `hippius-disks` helper lists slots and prints example
  mdadm/ZFS commands (never runs them).
- **Measured anchor**: the cmdline carries `hippius.dedicated=x0:<GiB>,…`
  only when dedicated disks exist (otherwise the cmdline is byte-identical).
  The guest refuses a slot smaller than the measured size. A listed but
  absent slot is `missing`: boot continues, the customer's array runs
  degraded, an alert fires.

### 4.2.1 Guest implementation (G3/G4, guest release 6; integrity slots, release 8)

**Where it runs: the golden initramfs.** `hippius_golden_open_dedicated`
(`scripts/initramfs/hippius-golden-overlay.sh`) runs inside the boot
attempt after the guest-keyed OS volume is open and the overlay mounted,
and before the KEK keyfile is shredded. It calls `hippius-guest-release
--open-dedicated-disks <kek-file>` (`binaries/guest-release/src/dedicated.rs`),
which derives each slot's key in its own memory (`Zeroizing`) and hands it
only to `cryptsetup` on a pipe. Nothing key-bearing is ever written, the KEK
never leaves the initramfs, and no key is handed to the booted OS, where
tenant userspace could read it. The mappings exist before the tenant's
systemd starts, so the customer's mdadm/ZFS/fstab assemble on them at boot.
A slot problem is a slot state, never a failed boot. Without the anchor
the step is a strict no-op.

**Anchor grammar** (measured cmdline, parsed strictly; any doubt refuses
every slot, reported `mismatch` on each `virtio-hippius-x*` device, and
nothing is opened):

```
hippius.dedicated=<entry>[,<entry>]…                exactly one token
  <entry> = <slot>:<GiB>          a plain slot (exactly as in release 6/7)
          | <slot>:<GiB>:i        an integrity slot (release 8)
  <slot> = x[0-9]{1,2}, no leading zero, ≤ x23 (what the receipt wire carries)
  <GiB>  = decimal, no leading zero, 1000 ≤ GiB ≤ 1048576 (the size class)
  1..8 entries, slots unique; hippius.vm_id= present exactly once
```

vali emits `:i` only for integrity slots, so a cmdline without one is
byte-identical. Any other suffix (`:I`, `:`, `:ii`, a fourth field) refuses
every slot (`anchor-mode` / `anchor-entry`). A release before 8 reads
`x0:22300:i` as a bad size and refuses every slot too: it never formats or
opens an integrity slot.

A `/proc/cmdline` at the kernel limit (2047) whose last token is the
anchor is refused (it may have lost its tail).

**Per slot**: `/dev/disk/by-id/virtio-hippius-<slot>` absent (after a 15 s
wait) ⇒ `missing`. A partition, a device with holders or an existing
`hippius-<slot>` mapping, a device two slots resolve to, or one smaller than
`GiB × 2^30` ⇒ `mismatch`. The 64-byte HKDF output is the LUKS2 **volume
key** (aes-xts-plain64, 512-bit), and the slot is opened **by volume key**:
a forged keyslot (the null-cipher keyslot trick) cannot substitute a key the
miner knows, because the header's digest must accept a key only the guest
can compute. What the header still controls is the segment layout (a
`cipher_null` or `linear` segment, or a reencryption "in flight" that maps
part of the disk through one). So the header is first copied into guest RAM
(`luksHeaderBackup`, the #296 pattern), the copy must carry the recorded
UUID and pass a metadata check (exactly one `crypt` segment,
aes-xts-plain64, no integrity, no requirements, only plain `luks2`
keyslots, one digest, no tokens; else `mismatch bad-header`), and the slot
is activated **from that copy** (`--header`), so the host cannot swap the
header between check and use. The **live mapping** is checked again after
activation (`cryptsetup status`: LUKS2, aes-xts-plain64, 512 bits, no
integrity, our device); anything else is closed again ⇒ `mismatch`. The layout is pinned, not autodetected:
data offset 16 MiB, 4096-byte encryption sectors, 16 KiB metadata and a
16744448-byte keyslot area; the metadata check and the live check both
require it. (The keyslot `luksFormat` must create is
keyed with the same 64 bytes, PBKDF2 with 1000 iterations: it wraps nothing
that is not already the key, and no argon2 memory cost in an initramfs.)

| record says | device | action |
|---|---|---|
| nothing | no LUKS header, no signature in the first 4 MiB (LUKS, GPT, MBR, ext, xfs, btrfs, md 1.1/1.2, LVM, ZFS L0/L1, swap, squashfs, verity, f2fs) or the last 1 MiB (md 0.90/1.0, GPT backup, ZFS L2/L3) | record `formatting <new uuid>`, then `luksFormat --uuid`, open, record `ready` |
| nothing | any header or signature | `mismatch not-blank`, untouched |
| `formatting U` | no LUKS header | format again with `U` (nothing was ever opened under it) |
| `formatting U` | header `U` | open; record `ready` |
| `ready U` / `formatting U` | header `U'` ≠ `U` | `mismatch uuid-mismatch`, untouched |
| `ready U` | no LUKS header | `mismatch no-header`, never reformatted |
| `ready U` | header `U`, key refused | `mismatch open-failed` |
| `ready U` / `formatting U` | header `U` but not a header this guest writes | `mismatch bad-header` (never activated) |

The record is `<volume root>/.hippius-dedicated-disks` (mode 0600), next to
the anti-rollback stamp: on the guest-keyed, integrity-protected OS volume,
covered by the stamp, outside the tenant's merged root:

```
hippius-dedicated-disks v1
x0 ready 0b6f8a52-61d4-4c9e-9f2b-3f6e0a1c2d4e 22300
x1 formatting 7c1e0d9a-2b3f-4a5c-8d6e-9f0a1b2c3d4e 22300
x2 ready 5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d 3500 integrity
```

An integrity slot's line carries a 5th field, `integrity`; a plain slot's
line is exactly release 6/7's (a release-7 guest reading a record with an
integrity line refuses the record: it never opens anything). The anchor
and the record must agree on the mode, else `mismatch mode-mismatch`,
untouched. Entries are never removed (slots are never reused). An unreadable or
malformed record opens and formats nothing (every present slot
`mismatch record-*`).

**HKDF vector** (RFC 5869, computed independently with Python
`hmac`/`hashlib`, pinned in `dedicated_tests.rs`): ikm = bytes `00..1f`,
salt = `hippius-dedicated-disk-v1`, L = 64:

| info | OKM |
|---|---|
| `vm-0123456789abcdefx0` | `7dceb685bcecdde450d2c8d64193bde1f16264e39a7060270024c9dd70b2589f3b994e95f31ee59cf9255eba17c4014226d0c933e4bb27a3a736a6cd1b18c73e` |
| `vm-0123456789abcdefx1` | `ee60213aa0bf9c26f1ba1027c7fb6decea40908be6ca9627627761af82f892660caf7c6cdc409b97781da83d2c6b849679a287e7104608b2475bcb738136329b` |
| `vm-fedcba9876543210x0` | `31c71b9a34687fcbeff70ec582288be65aaf506be25a1a619c0484a4990d4557469c354439785c1649a036b1eb7d4dc2983a297124493ded1ade1bb74e844cb7` |

A slot is handed to the tenant only once its `ready` record is durable;
if that write fails the mapping is closed again (`mismatch
record-write-failed`), so `formatting` means "never opened". (Should the
close itself fail, the slot is reported `record-write-failed-mapped`; a
later re-format of that slot writes the same header, same UUID, same
derived key and data offset, and touches no data sector.)

**Integrity slots (`:i`, guest release 8).** LUKS2 with AEAD, the OS
overlay volume's family: aes-xts-plain64 + hmac-sha256, the same pinned
layout (16 MiB, 4096-byte sectors). The 96-byte volume key (512-bit XTS ‖
256-bit HMAC, the keyslot reports 768 bits) is `HKDF-SHA256(KEK, salt =
"hippius-dedicated-disk-aead-v1", info = vm_id‖slot)`, its own salt so it
shares no byte with a plain derivation; the keyslot passphrase is the same
96 bytes. The metadata check requires the segment's `integrity` to be
exactly `{"type": "hmac(sha256)", "journal_encryption": "none",
"journal_integrity": "none"}` (and a plain slot's to be absent), so the
host can neither strip the AEAD off a slot nor add one. The live check
requires `cryptsetup status` to say hmac(sha256), a 768-bit key and 4096-byte
sectors, and the stack in sysfs to be the crypt mapping on exactly one
`<name>_dif` dm-integrity layer on exactly the slot's device. Both modes
(release 8) also require the header's segment to be `"size": "dynamic"`,
`"iv_tweak": "0"`, and the ACTIVE mapping to be at least `GiB × 2^30 − 16
MiB` (97 % of that for an integrity slot, whose tags and journal take ≤ 1.6
%): the host could otherwise shrink a slot under its size class through
the header's segment size or the dm-integrity superblock.

dm-integrity reads a never-written sector as an I/O error, so every sector
is written once on the first boot (about an hour for 3.5 TB of NVMe). That
must not hold the boot, and the KEK must not leave the initramfs, so:

1. *Initramfs* (`--open-dedicated-disks`): record `formatting <U>
   integrity` first, `luksFormat --integrity hmac-sha256
   --integrity-no-wipe` (instant), then — udev's event queue paused — open
   by volume key from the verified header copy as
   `hippius-<slot>-init` with `--integrity-no-journal`, check the live
   stack, write zeros through it at both ends (8 MiB each: everything
   blkid / md / LVM / ZFS probes for), resume udev. No probe ever reads an
   unwritten sector (each would log an AEAD error, and an integrity error
   must only ever mean tampering). The slot is reported `initializing`
   (`init-0`) and listed in `/run/hippius/dedicated/init`.
2. *Booted OS* (`hippius-dedicated-init.service`, started by that list,
   `Type=exec`, off the boot path): `hippius-guest-release
   --dedicated-init-wipe` checks each listed slot (state `initializing`,
   record `formatting <U> integrity`, the `-init` mapping's dm UUID names
   LUKS volume `<U>`; else closed, `mismatch init-mismatch`), writes zeros
   through the mapping (the OS overlay's parallel wipe, all slots at once
   within its 8 × 4 MiB writers budget), keeping `init-<percent>` in the
   state file current, then records `ready` (fsync'd), switches the
   dm-integrity layer to its journal (`dmsetup` table reload, mode `D` →
   `J`: the integrity layer holds no key) and renames the stack
   `hippius-<slot>` (+ `_dif`), and reports `attached`. The record is
   reached by mounting the OS volume's device again in the unit's private
   mount namespace (`PrivateMounts=yes`), never through the tenant's root.
   A failed journal switch or rename only degrades that boot
   (`attached no-journal-this-boot` / `attached init-name`); every later
   boot opens journaled, by name.

This is cryptsetup's own end state (every sector written once through the
AEAD under our key, every tag valid), as for the OS overlay; only the
writers and the place differ. Record transitions:

| record says | header | initramfs does |
|---|---|---|
| nothing | blank (no header, no signature) | `formatting U integrity`, format, open `-init`, prime ⇒ `initializing` |
| `formatting U integrity` | none, or ours (`U`) | the wipe never finished, nothing was ever handed over: format again (same U, same key), open `-init` ⇒ `initializing` (from scratch) |
| `ready U integrity` | `U` | open journaled as `hippius-<slot>` ⇒ `attached` (never re-wiped) |
| `ready U integrity` | none / `U'` | `mismatch no-header` / `uuid-mismatch` |
| either, plain line | — | `mismatch mode-mismatch` |

*Key hand-over: none.* The KEK and the slot key stay in the initramfs
process (`Zeroizing`, down a pipe to `cryptsetup`) exactly as for a plain
slot; what crosses `switch_root` is the open device-mapper mapping, which is
what the tenant gets anyway. A kernel-keyring hand-over was considered and
rejected: cryptsetup verifies a volume key against the header digest in
userspace, so `--volume-key-keyring` needs a readable `user` key, not a
`logon` one; a root-readable slot key would sit in the tenant's own trust
domain (it already reads the plaintext), but there is no reason to put it
anywhere when the mapping suffices. Nothing booted ever holds the KEK, so
no other slot or VM is exposed. (In-guest root can read kernel memory, the
dm-crypt keys included, as for every open volume: within the tenant's own
domain.)

**HKDF vector, integrity slots** (same independent computation),
salt = `hippius-dedicated-disk-aead-v1`, L = 96:

| info | OKM |
|---|---|
| `vm-0123456789abcdefx0` | `b1f729170f6760e4c0fb526a682611c23ab3d149a59344fe9ef9047d0fe1371053a1943cd139ab58e22b657cbd42713a9462620505a44504b1cfe7d4a1a6529265c0533a6eebd3573206a18ee6d30cd8e621c176d3d77fab97d45540b03ab9ae` |
| `vm-0123456789abcdefx1` | `37e755d526b5d9edf239d994f0e2879691dc092a903ec5720c8d0600e0eed56c3170065cfecc1e7e65a52f14afbaf25cd4114750ae5a71f3aaa3a454f8191f52ce10810cfec1bd6f5df2d2f63decf4bc89ad994a30961ac092c5d4464559d9e2` |
| `vm-fedcba9876543210x0` | `3402c6a31afda15640e47a7d77d9976dc247729c4e5ba84632a8ecbcffdc32f4084fd41050e8e5c83c62f3ccab1036bd56cd55d6c0a85201ae0a0806eb876f977d1be677f5e439e26199c526cfad7bc8edd31d82321f879d7c02815cbe9891a7` |

**Residual limits** (none gives the miner plaintext or a key):

- *Integrity slots: per-sector rollback.* The tag binds a sector's
  ciphertext to its position and key, not to time: the host can put back
  an older version of a sector (with its older tag) and it verifies.
  Tampering, relocation and a blank disk read as I/O errors. The
  dm-integrity superblock and journal are unauthenticated metadata, as on
  the OS overlay: forging them can only make sectors unreadable or replay
  old (sector, tag) pairs.
- *Integrity slots: a rolled-back record re-initialises the slot.* The
  record is on the OS volume, whose AEAD is per sector: a host that puts
  back the record file's older sectors (from before `ready`) gets the guest
  to treat the slot as never initialised and format + wipe it again. That
  is destruction the host could always cause, but it then looks like a
  first boot (`initializing`) instead of leaving I/O errors. vali sees it:
  a slot never goes from `attached` back to `initializing` honestly (slots
  are never reused), so that transition in the receipts is tamper evidence
  and must alert.
- *Integrity slots: the booted OS needs `dmsetup`.* Every golden base has
  it (Debian/Ubuntu's cryptsetup depends on it, dracut's dm module needs
  it). A tenant that removes it gets `attached no-journal-this-boot` /
  `init-name` for that boot only.
- *Integrity slots: one boot without a journal.* The wipe runs journal-less
  (as cryptsetup's does); a crash during it restarts the wipe anyway. If
  the journal switch fails after the wipe, that boot runs journal-less
  (`no-journal-this-boot`): a crash mid-write can then leave a torn
  sector that reads as an I/O error.

- *Replay.* Without integrity, nothing binds a header to the data behind
  it. A miner can copy this slot's own header (or any of its ciphertext)
  onto another disk and the guest opens it as the slot: the customer sees
  garbage or old data. That is the "corrupt or roll back sectors" risk of
  §2. ZFS/btrfs checksums on top detect incoherent replay (sectors from
  different times); a coherent rollback of the whole device (old data with
  its matching old metadata and checksums) validates normally: there is no
  freshness guarantee for dedicated disks.
- *Boot-granular record.* The record shares the anti-rollback stamp's
  granularity: the stamp is confirmed before the opener runs, so a miner
  that snapshots the OS volume after the confirm and restores it on a later
  boot can drop that boot's record writes. Combined with a blank disk under
  the slot, the guest then formats the blank disk as a new slot and reports
  it `attached` instead of `mismatch`. The miner can always destroy a
  slot's data; this only hides the swap from the guest's report (the
  agent's identity binding still sees it). Moving the record write before
  the stamp write would narrow it, not close it (the host can mix sectors
  from different times on any unauthenticated-freshness disk).
- *Stalled disks.* The by-id wait is bounded (15 s); I/O to a device that
  never completes is not (virtio-blk has no timeout), so a stalled
  dedicated disk stalls the boot, like a stalled OS disk. A failing honest
  disk returns I/O errors, which are slot states.
- *HKDF state.* The derived key and the HKDF `info` are `Zeroizing`; the
  `hkdf` crate's internal HMAC state is not zeroized (it lives on the stack
  of a process that exits right after).
- *RAM.* The header copy lives in tmpfs for the duration of one open (the
  LUKS2 header plus keyslot area, 16 MiB as we format it, at most ~136 MiB
  for a forged one).

**Reporting.** The opener writes `/run/hippius/dedicated/slots` (tmpfs,
`<slot> <attached|missing|mismatch|initializing> <GiB> <dev|-> <reason>`
per line; an `initializing` line's reason is `init-<percent>`, kept current
by the booted OS's wipe). The telemetry agent folds it into every receipt's
`disk_io`: an attached slot is its device with state `ok`, `mismatch` on the
slot's device, `missing` with no device and zero counters, `initializing`
on the slot's device with its counters and the optional integer
`init_percent` (0..=100; release 8, an additive key of the T1 wire, absent
on every other entry so older entries are byte-identical; the ticket
validator passes it through to vali only when set), and an attached or
initializing slot whose device later vanishes becomes `missing`. Every slot rides the
first receipt (zero counters when there is no window yet) and wins a full
list. vali maps receipt `ok` to `attached`; `failed` stays vali's own
verdict. Like all `disk_io`, these are in-VM-root-forgeable: a tenant can
claim `mismatch` for its own slot, so vali must not zero a slot's billing on
the guest's word alone (cross-check with the agent's identity binding, or
treat a guest-only `mismatch` as notify-only).

**`hippius-disks`** (`scripts/guest/hippius-disks`, shipped at
`/run/hippius/guest/bin/hippius-disks`) lists slot, state, size and mapper
path and prints example ZFS / mdadm / mkfs commands. It never runs them.

**Shipping (guest components release 6).** Everything is in the release
cpio appended to the base initrd: the overlay library and
`hippius-guest-release` in the initramfs part, the telemetry agent and
`hippius-disks` in `components.squashfs`. No re-bake: every golden base
already stages `cryptsetup` and `udevadm` in its initrd. `security_epoch`
stays 1 (an older release ignores the anchor and opens nothing; it never
formats). Steps, in order:

1. Merge (release.conf `version=6`); the `tenant-baker-image` workflow
   builds and signs the baker image at that commit (note its digest).
2. Per live base (ubuntu-b5, ubuntu-b4, debian-b5, debian-3 initrd,
   fedora-b5, cs10-b5): the one-off `guest-initrd-build.sh --build-release
   --commit <C> --source-date-epoch <commit time>` Job (operator note in
   that script), output prefix `tenant/<base prefix>-gr6-<short>/`; then
   `vali_guest_build_register --from-s3-prefix tenant/<base prefix>-gr6-<short>/`.
3. Canary per family (ubuntu, debian, fedora, cs10): `vali_guest_upgrade
   --vm-id <throwaway> --release 6` (dry-run, `--apply`, `--status`); check
   health 15, receipts flowing, and on a VM without dedicated disks that the
   boot log has no `dedicated` line.
4. `vali_bless_guest_release <image> --release 6 --blessed-by …` per image.
5. vali E4 gate: `dedicated-needs-release` unless the image's blessed
   `guest_release ≥ 6` (same shape as `VALI_DISK_PROBE_MIN_GUEST_RELEASE`,
   e.g. `VALI_DEDICATED_MIN_GUEST_RELEASE=6`), and refuse any relaunch of a
   pinned VM onto a build below 6 (the epoch floor does not hold it there).
6. X2′ on an internal VM with a spare disk: first boot formats, reboot
   reopens, `hippius-disks` lists, receipts carry the slot, §24 erases.

**Shipping (guest components release 8: integrity slots, `/dev/vsock`
0600).** Same artefact shape as release 6/7, plus, in
`components.squashfs`, `bin/hippius-guest-release` (the booted-OS wipe),
`units/hippius-dedicated-init.service` and `udev/99-hippius-vsock.rules`
(linked into `/etc/udev/rules.d` by the boot step from the record's new
`udev=` line). `security_epoch` stays 1: release 8 changes no volume a
release 7 cannot read back — a plain slot, its record line and its format
are byte-identical, and an older release refuses an integrity anchor or
record line outright (never formats, never opens). vali holds integrity
slots to release 8 instead (below). The hippius-types `disk_io` change
moves the UKI KATs (re-pinned in the PR from its own CI). Steps, in order:

1. Merge (release.conf `version=8`); the `tenant-baker-image` workflow
   builds and signs the baker image at that commit (note its digest).
2. Per live base (as for release 6/7: ubuntu-b5, ubuntu-b4, debian-b5,
   debian-3 initrd, fedora-b5, cs10-b5): the one-off `guest-initrd-build.sh
   --build-release --commit <C> --source-date-epoch <commit time>` Job,
   output prefix `tenant/<base prefix>-gr8-<short>/`; then
   `vali_guest_build_register --from-s3-prefix tenant/<base prefix>-gr8-<short>/`.
3. Canary per family (ubuntu, debian, fedora, cs10): `vali_guest_upgrade
   --vm-id <throwaway> --release 8` (dry-run, `--apply`, `--status`); check
   health 15, receipts flowing, `stat -c '%a %U:%G' /dev/vsock` = `600
   root:root`, every agent active, and on a VM without dedicated disks no
   `dedicated` line in the boot log and `hippius-dedicated-init.service`
   skipped (condition).
4. `vali_bless_guest_release <image> --release 8 --blessed-by …` per image.
5. vali: integrity slots need `guest_release ≥ 8`
   (`dedicated-needs-release`, as the release-6 gate for plain slots), and
   a pinned VM with an integrity slot is never relaunched onto a build
   below 8. Receipts: `disk_io` state `initializing` + `init_percent` ⇒
   `guest_state: initializing` + its percent; a slot going `attached` →
   `initializing` alerts (tamper evidence, residual limits above).
6. X2′ with `:i` on an internal VM with a spare disk: boot is not held,
   `initializing` with a rising percent in receipts, then `attached`; a
   reboot during the wipe restarts it; a full read after it succeeds;
   reboot reopens (same UUID); §24 erases.

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

**Hard rule: host-reported advisories never decide.** The host inventory's
advisories (§18 of the plan: SMART/NVMe attributes, kernel journal lines,
sensors, PSUs) are self-reported by the miner and vendor-dependent: an SSD's
raw attribute 198 can read 1080 on a healthy drive. They **never** trigger a
cordon, a tier demotion, a merit penalty or a slashing on their own, under
any `VALI_DISK_TIER_CONSEQUENCES`. Only the attested probe (G1/G2/R1: a
vali-owned probe CVM, its result inside the guest-signed receipt) moves a
pool or disk through this state machine. At most, an advisory may schedule a
probe early (like the passive `suspect` row above), and the probe decides.
The guard: `vali/apps/disktier/tests/test_host_inventory.py::
test_only_the_ingest_and_its_own_module_name_the_host_inventory` fails if
any module other than the ingest, its models, the operator reads and the
retention sweep names the host inventory or its advisories, so scheduling,
cordon, rewards and billing code cannot read them. A future C1/§14 change
that wants an advisory to *trigger a probe* goes through that allowlist,
deliberately and reviewed.

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
| G1-G4 | guest | `DiskStatsSource`; `agent-disk-probe` (v1 + d1); `--open-dedicated-disks` (initramfs opener, §4.2.1), slot verdicts in receipts, `hippius-disks`; guest release 6 | inert without request file / cmdline token |
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
- Host-reported advisories (§18) never cordon, demote, penalise or slash on
  their own: only the attested probe does (§5.1 hard rule). C1, the
  remediation engine (E3) and slashing (S-*) must keep it.

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
