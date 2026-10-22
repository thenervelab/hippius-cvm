# Dedicated disks — frozen backend ↔ vali contract (E4)

Status: **FROZEN 2026-10-22.** This is the contract the backend (B4 billing
line, U2 console picker) builds against while vali/agent/guest are built
behind flags. It narrows `disk-tier-verification.md` §7–§8 to what v1 ships;
where the two differ, this file wins. Any change after today is additive
only (a new optional field or a new error category), never a rename.

All sizes are **GiB** (2^30 bytes). The only dedicated tier sold in v1 is
`hdd` (a minimum: a disk the probe grades ssd/nvme also qualifies).

## 1. Launch — `POST /v1/vm/launch`

```jsonc
{
  // … existing fields unchanged
  "dedicated_disks": {      // optional; absent or null ⇒ no dedicated disk
    "tier": "hdd",          // required; v1: only "hdd"
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
| `tier` other than `hdd` | 400 | `dedicated-invalid` |
| `count` outside 1..8 | 400 | `dedicated-count-invalid` |
| `min_size_gb` below 1000 | 400 | `dedicated-size-invalid` |
| `pinned_ack` absent or not `true` | 400 | `dedicated-ack-required` |
| feature off, or caller/owner not on the allowlist | 409 | `dedicated-disks-not-offered` (the code live today, kept as is) |
| together with `require_failover_peer: true` | 409 | `dedicated-no-failover` |
| the image's blessed guest release cannot open dedicated disks | 409 | `dedicated-needs-release` |

### 1.2 Asynchronous placement failures

The launch job ends `failed` with one of these categories (same family as
today's `no-eligible-miner`; the failed-launch refund/void path applies):

| Condition | category |
|---|---|
| no node has `count` free disks of tier ≥ hdd and size ≥ `min_size_gb` | `no-dedicated-capacity` |
| such disks exist, but not on a node that also fits the VM | `no-host-fits-disks` |

## 2. What the backend reads back

Launch job `result` and `GET /v1/vm/{vm_id}` both carry:

```jsonc
"pinned": true,                    // present and true only with dedicated disks
"disks": [
  {"slot": "os", "kind": "pool",      "size_gb": 40,    "tier": "nvme", "state": "attached"},
  {"slot": "x0", "kind": "dedicated", "size_gb": 22300, "tier": "hdd",  "state": "attached", "guest_state": "ok"},
  {"slot": "x1", "kind": "dedicated", "size_gb": 22300, "tier": "hdd",  "state": "attached", "guest_state": "ok"}
]
```

- `disks` is present only when the VM has at least one dedicated disk; a VM
  without one is byte-identical to today.
- `slot`: `os`, then `x0`, `x1`, … in assignment order. A slot is never
  reused (a replacement gets a new slot).
- `size_gb`: the disk's **size class**, its real size floored to 100 GiB.
  This is the billed quantity.
- `tier`: what the disk is sold at (`hdd` in v1), never the probe's grade.
- `state` (dedicated slots): `attached` | `missing` | `failed` | `mismatch` |
  `released`, from **host evidence only** (the miner agent's storage report
  and its re-attach identity check). Never a pool id, a path, a serial or the
  miner's disk id.
- `guest_state` (dedicated slots, informational): what the guest reports for
  the slot — `ok` | `missing` | `mismatch`. Root inside the VM can forge it,
  so it never drives `state` or billing; show it to the customer as a
  warning only.

## 3. Billing (backend side, for reference)

- One ledger line per dedicated slot: `kind="vm_disk"`,
  `resource="dedicated_disk_gb_hour:hdd"`, `ref="<vm_id>/<slot>"`,
  `unit="gb_hour"`, quantity = `size_gb` × billable seconds / 3600. Maps to
  the existing `UsageKind.COMPUTE`.
- Billed while the VM is stopped (the disk stays reserved). A slot stops
  billing at destroy, and from the moment its `state` is `failed` or
  `mismatch` (the backend's normal VM sync observes it).

## 4. Feasibility and regions

`GET /v1/scheduler/feasibility` adds three optional query parameters:
`dedicated_count`, `dedicated_min_size_gb`, `dedicated_tier` (`hdd`). With
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

The backend keeps its own `COMPUTE_DEDICATED_ENABLED`; both are flipped in
the same window, after the internal end-to-end test passes.
