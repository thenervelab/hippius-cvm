# Dedicated disks — frozen backend ↔ vali contract (E4)

Status: **FROZEN 2026-10-22.** This is the contract the backend (B4 billing
line, U2 console picker) builds against while vali/agent/guest are built
behind flags. It narrows `disk-tier-verification.md` §7–§8 to what v1 ships;
where the two differ, this file wins. Any change after today is additive
only (a new optional field or a new error category), never a rename.

All sizes are **GiB** (2^30 bytes). A dedicated disk is sold at a tier
`hdd`, `ssd` or `nvme` (a minimum: a disk verified faster also qualifies);
which tiers are on sale is a vali setting, `hdd` only by default (§8,
added 2026-10-23).

## 1. Launch — `POST /v1/vm/launch`

```jsonc
{
  // … existing fields unchanged
  "dedicated_disks": {      // optional; absent or null ⇒ no dedicated disk
    "tier": "hdd",          // required; "hdd" | "ssd" | "nvme" (§8)
    "count": 2,             // required; 1..8
    "min_size_gb": 16000    // required; GiB, ≥ 1000; every assigned disk ≥ this
  },
  "pinned_ack": true        // required, and true, whenever dedicated_disks is present
}
```

- Body checks run before anything is staged (no Vault/KBS write on a refusal).
- `pinned_ack` is the customer's acknowledgement that the VM is pinned: no
  migration, no failover, no backup of any kind, data lost if the host is
  lost. The backend stores its own timestamp and text version; vali keeps
  only the boolean in the launch spec.

### 1.1 Synchronous refusals

Body `{"error": "<msg>", "category": "<code>"}`.

| Condition | HTTP | category |
|---|---|---|
| `dedicated_disks` not an object, unknown key, or a wrong type | 400 | `dedicated-invalid` |
| `tier` other than `hdd`, `ssd`, `nvme` | 400 | `dedicated-invalid` |
| `count` outside 1..8 | 400 | `dedicated-count-invalid` |
| `min_size_gb` below 1000 | 400 | `dedicated-size-invalid` |
| `pinned_ack` absent or not `true` | 400 | `dedicated-ack-required` |
| feature off, or caller/owner not on the allowlist | 409 | `dedicated-disks-not-offered` (the code live today, kept as is) |
| `tier` valid but not on sale (`VALI_DEDICATED_SELLABLE_TIERS`, §8) | 409 | `dedicated-disks-not-offered` |
| together with `require_failover_peer: true` | 409 | `dedicated-no-failover` |
| the image's blessed guest release cannot open dedicated disks | 409 | `dedicated-needs-release` |

### 1.2 Asynchronous placement failures

The launch job ends `failed` with one of these categories (same family as
today's `no-eligible-miner`; the failed-launch refund/void path applies):

| Condition | category |
|---|---|
| no node has `count` free disks of tier ≥ `tier` and size ≥ `min_size_gb` | `no-dedicated-capacity` |
| such disks exist, but not on a node that also fits the VM | `no-host-fits-disks` |

## 2. What the backend reads back

Launch job `result` and `GET /v1/vm/{vm_id}` both carry:

```jsonc
"pinned": true,                    // present and true only with dedicated disks
"disks": [
  {"slot": "os", "kind": "pool",      "size_gb": 40,    "tier": "nvme", "state": "attached"},
  {"slot": "x0", "kind": "dedicated", "size_gb": 22300, "tier": "hdd",  "state": "attached", "guest_state": "attached"},
  {"slot": "x1", "kind": "dedicated", "size_gb": 22300, "tier": "hdd",  "state": "attached", "guest_state": "attached"}
]
```

- `disks` is present only when the VM has at least one dedicated disk; a VM
  without one is byte-identical to today.
- `slot`: `os`, then `x0`, `x1`, … in assignment order. A slot is never
  reused (a replacement gets a new slot).
- `size_gb`: the disk's **size class**, its real size floored to 100 GiB.
  This is the billed quantity.
- `tier`: what the disk is sold at (the launch's `tier`), never the probe's
  grade.
- `state` (dedicated slots): `attached` | `missing` | `failed` | `mismatch` |
  `released`, from **host evidence only** (the miner agent's storage report
  and its re-attach identity check). Never a pool id, a path, a serial or the
  miner's disk id.
- `guest_state` (dedicated slots, informational): what the guest reports for
  the slot — `attached` | `missing` | `mismatch`. Root inside the VM can forge it,
  so it never drives `state` or billing; show it to the customer as a
  warning only.

## 3. Billing (backend side, for reference)

- One ledger line per dedicated slot: `kind="vm_disk"`,
  `resource="dedicated_disk_gb_hour:<tier>"` (the slot's sold `tier`, §2),
  `ref="<vm_id>/<slot>"`,
  `unit="gb_hour"`, quantity = `size_gb` × billable seconds / 3600. Maps to
  the existing `UsageKind.COMPUTE`.
- Billed while the VM is stopped (the disk stays reserved). A slot stops
  billing at destroy, and from the moment its `state` is `failed` or
  `mismatch` (the backend's normal VM sync observes it).

## 4. Feasibility and regions

`GET /v1/scheduler/feasibility` adds three optional query parameters:
`dedicated_count`, `dedicated_min_size_gb`, `dedicated_tier` (`hdd`
default, `ssd`, `nvme`; §8). With
none of them the response is byte-identical to today. With them it adds:

```jsonc
"dedicated": {
  "tier": "hdd", "count": 2, "min_size_gb": 16000,
  "placeable": true,             // a node fits the VM AND has the disks
  "max_count_at_size": 6         // most qualifying free disks on one node that fits the VM
}
```

and the reasons `no-dedicated-capacity` / `no-host-fits-disks` when not
placeable. Invalid parameters ⇒ 400 with the §1.1 categories.

`GET /v1/operator/regions` adds per region:

```jsonc
"dedicated_disks": {"hdd": {"sizes": [{"size_gb": 22300, "free": 3, "max_per_host": 1}]}}
```

Counts are advisory; the launch is authoritative.

## 5. Lifecycle refusals on a pinned VM

| Operation | Result |
|---|---|
| reboot, relaunch, power stop/start, guest upgrade, CPU/RAM resize in place | allowed, same node, same disks |
| §25 migration, failover, restore elsewhere, resize that needs a migration | 409 `dedicated-pinned` (the failover worker skips the VM) |
| backup policy on the VM | 409 `dedicated-pinned` |
| §24 decommission | allowed: the KEK is erased (crypto-erase of every slot), the agent zeroes each disk's head and tail, the disk is re-probed before it is sold again |

## 6. Flags (vali)

| Flag | Default | Meaning |
|---|---|---|
| `VALI_DEDICATED_ENABLED` | `false` | off ⇒ every `dedicated_disks` ⇒ 409 `dedicated-disks-not-offered` |
| `VALI_DEDICATED_ALLOWED_OWNERS` | empty | when set, only these owners may launch with dedicated disks (internal canary) |
| `VALI_DEDICATED_MAX_PER_VM` | `8` | the upper bound of `count` |
| `VALI_DEDICATED_SELLABLE_TIERS` | `hdd` | the tiers on sale (§8) |
| `VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER` | empty | miner pay per sold tier (§8) |

The backend keeps its own `COMPUTE_DEDICATED_ENABLED`; both are flipped in
the same window, after the internal end-to-end test passes.

## 7. Reserved probe-owner ids

User ids **990000000 and above** are reserved for vali's disk-probe VMs
(`VALI_DISK_PROBE_OWNERS`, `<user id>:<SS58>`, fresh addresses with no key
kept). The backend never creates a user in that range (it refuses to), and
has no `ComputeVM` rows for the probe VMs vali mints (`hipc-<id>-<hex>`), so
nothing bills them; vali excludes them from rewards and refuses them at the
public launch intake (`disk-probe-id-reserved`).

## 8. Tiers (added 2026-10-23, additive)

1. **Launch.** `dedicated_disks.tier` is `hdd` | `ssd` | `nvme`, a
   MINIMUM. Anything else ⇒ 400 `dedicated-invalid`. A valid tier not in
   `VALI_DEDICATED_SELLABLE_TIERS` (comma-separated, default `hdd`) ⇒ 409
   `dedicated-disks-not-offered`, after the 400s and before the other 409s.
2. **Placement.** Among the free disks whose VERIFIED tier is ≥ the
   requested one: the lowest qualifying tier first, then the smallest
   qualifying size, then the existing tie-break (most recently probed).
   Same transaction and row locks as before.
3. **Read-back.** `disks[].tier` is the SOLD (requested) tier, never the
   disk's higher verified tier; vali records it per slot. The backend's
   ledger line is `dedicated_disk_gb_hour:<sold tier>`.
4. **Feasibility and regions.** `dedicated_tier` takes `hdd` | `ssd` |
   `nvme`; a tier not on sale reads `never` / `dedicated-disks-not-offered`.
   `regions` lists `dedicated_disks.<tier>.sizes[]` for each tier on sale
   only, each counting every free disk that QUALIFIES for it (an nvme disk
   appears under nvme, ssd and hdd). With the default setting both
   answers are byte-identical to before (only `hdd`).
5. **Verified tier = min(d1 probe grade, the operator's declared
   class).** Downgrade-only; a disk with no declared class is capped at
   `hdd`. The class is an optional `class` (`hdd` | `ssd` | `nvme`) on a
   dedicated-disk entry of vali's storage document. It is **vali-side
   only**: the agent's `storage-config` entry refuses unknown keys
   (`DedicatedDiskSpec`, `deny_unknown_fields`), so vali strips it from
   every push and dry run (the agent's document and digest are unchanged).
   Changing its cap on a disk assigned to a VM ⇒ 409 `disk-assigned`,
   nothing written (absent and `hdd` are the same cap). On a free disk,
   raising it sends the disk back to `pending_probe` (only a probe can
   grant the higher tier); lowering it caps the verified tier at once, in
   any state. A
   class-only change is a new document revision (the agent is re-sent the
   same disks under it). The operator's dedicated-disk listing shows each
   disk's `declared_class`. Disks probed before the ssd/nvme
   thresholds keep `hdd` until re-probed (`vali_dedicated_reprobe`, an
   audited operator command).
6. **d1 thresholds** (`classify.PROFILE_D1`; hdd floors unchanged,
   suspect-cache floor 12 µs):

   | Metric | nvme | ssd | hdd |
   |---|---|---|---|
   | inner-zone seq read ≥ (MB/s) | 1400 | 300 | 60 |
   | outer-zone seq read ≥ (MB/s) | 1400 | 300 | 120 |
   | random read 4K QD32 ≥ (IOPS) | 100 000 | 20 000 | 200 |
   | QD1 p99 ≤ (µs) | 500 | 3 000 | 60 000 |
   | sustained random write 4K QD32 ≥ (IOPS) | 40 000 | 5 000 | 100 |

   Calibrated on a Samsung PM9A3 3.84 TB through the SNP guest
   (2026-10-22: 2190/2380 MB/s, 181-194k IOPS, p99 31-44 µs, 136-158k
   IOPS sustained write), which clears every nvme floor by ≥ 1.5×; no SATA
   link reaches 1400 MB/s, so a SATA SSD is `ssd`; a 24 TB HDD misses `ssd`
   on random read, QD1 p99 and the inner zone.
7. **Miner pay follows the sold tier.** A slot is paid at the rate of the
   tier it was SOLD at, as the customer pays (an nvme disk sold as hdd
   earns hdd pay): `VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER`
   (`tier:milliunits,...`), an unlisted tier at
   `VALI_DEDICATED_MILLIUNITS_PER_GB`. Empty (the default) ⇒ one rate for
   every tier, so accrual is byte-identical until it is set.
