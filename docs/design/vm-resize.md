# VM resize — vCPU/RAM, data disk unchanged

Status: implemented (`vali/apps/orchestration/resize.py`), operator API only.
The tenant surface lives in hippius-backend (`compute/vm_resize.py`), which
calls the routes below with the orchestration-root token.

## What a resize is

A resize relaunches the VM on the miner that holds its disks, at another
flavor. The overlay, the KEK, the anti-rollback counter and the data disk
all stay the same. The SNP measurement is new: the vCPU count is measured,
and so is the `hippius.resource_class` cmdline token.

The relaunch is the power API's start (`power.start_vm` →
`_reboot_recovery_relaunch` → `launch.launch_on_miner`) with a flavor
override. Everything that path already guarantees carries over:

- the §22 auto-pin of the new measurement (`allowlist_pin`);
- the KBS re-register at the VM's current generation;
- `require_existing_disks` (the miner refuses rather than create blank disks);
- the billing binding rewritten to the new `resource_class`;
- the placement re-bind and the boot-stall clock restart.

Nothing in the resize talks to a miner directly.

## Why the disk cannot change

The tenant data disk (`/dev/vde`) is LUKS2 with `--integrity hmac-sha256`.
cryptsetup refuses to resize such a volume ("Resize of LUKS2 device with
integrity protection is not supported"). The dm-integrity layer underneath
can be grown, but the new region has no valid HMAC tags (EIO on read), and
cryptsetup has no supported way to recalculate them (see
`grow-at-first-boot-365.md`). On top of that, the guest anchors the disk size
in its measured cmdline (`hippius.disk_gb=`) and refuses a disk of a
different size.

So **the disk never follows the flavor**: a resize takes ANY offered flavor's
vCPU and RAM, and the VM keeps the data disk it was launched with. A "large"
can therefore carry a 40 GB disk, and a downsize keeps the bigger disk.

- **Launch record.** The first time the record's flavor moves,
  `spec_json["data_disk_size_gb"]` pins the launch disk
  (`launch_record.data_disk_gb`). `LaunchSpec.data_disk_size_gb` carries it.
- **Relaunch.** `launch.data_disk_gb(spec)` feeds the measured
  `hippius.disk_gb=` token, the pre-pin refusal derivation and the
  LaunchOrder's `data_disk_size_gb`. The flavor only drives `cpu_count`,
  `memory_mb` and `hippius.resource_class`.
- **Miner.** Nothing changes on the agent:
  - the preflight disk gates read the measured token, which is unchanged;
  - `check_disk_space` passes when the VM's disk already exists;
  - `ensure_data_disk` / `ensure_overlay_disk` reuse the existing sparse file
    and never recreate it (and `require_existing_disks` forbids creation);
  - the preflight's RAM check recovers memory from the vCPU count
    (`Flavor::from_vcpus`). vCPU counts stay unique across the catalogue, so
    the target flavor's vCPU maps back to the target's RAM, which is what the
    LaunchOrder carries.
  - The ticket's `flavor` is the target one, whose vCPU count matches the
    order (`ticket_peek`). Nothing in the agent or the KBS ties a flavor to a
    disk size.
- **Capacity.** `Placement.data_disk_gb` records the VM's real disk once a
  resize swapped its placement. The admission ledger, the disk gate of an
  explicit §25/restore/failover destination, and a resize migration's
  destination fit all count that disk, not the target flavor's.
- **Other readers.** The boot-stall deadline and the backup size read the
  pinned disk too.

The tenant price of a resized VM is the backend's call
(`compute.vm_resize.resize_price_rule`, a setting).

## API (operator, root-only)

| Method | Path | |
|---|---|---|
| GET | `/v1/vm/<vm_id>/resize/flavors` | Targets: every offered flavor but the current one. `data_disk_size_gb` is the VM's own disk, which stays. Each has `available`, `fits_current_host`, `needs_migration` and `reason`. `blocked` says why no resize can start right now. |
| POST | `/v1/vm/<vm_id>/resize` `{"flavor": "<name>"}` | Admits the resize synchronously (every refusal happens here) and returns the job, `202`. |
| GET | `/v1/vm/<vm_id>/resize` | The VM's latest resize job. |
| GET | `/v1/vm/<vm_id>/resize/<job_id>` | One job. |

Refusals are `{"error", "category"}`:

- **400**: `wire`, `unknown-flavor`, `flavor-not-offered`, `same-flavor`.
- **409**: `vm-not-active`, `no-bound-miner`, `job-in-flight`,
  `power-op-in-flight`, `no-launch-record`, `no-placement`,
  `resize-no-capacity`, `resize-measurement-pinned`,
  `resize-resource-class-pinned`, `resize-mixed-needs-running` (a stopped
  VM: no single reservation covers a booted size and a next-boot size that
  differ in opposite directions), `resize-pending-boot` (a stopped VM
  already resized and not booted at that size yet). The last one covers a
  launch record carrying an operator-pinned `measurement_hex`: every
  relaunch replays it, and at another vCPU count it is a digest the guest
  cannot produce.

While a resize runs, the power API answers `409 resize-in-flight`. §25
(`start_migration`), §24 (`start_decommission`), restores and backups all
answer `job-in-flight`. Reboot-recovery and the placement sweep skip the VM.
A resize never moves `Vm.state`, so no lifecycle CAS serialises it against
§25/§24. Every job intake (§25 migration, §24 decommission, restore,
failover, restore undo, resize) therefore re-checks the one-active-job rule
under the VM's row lock: two jobs can never both start, and the lock order
is the same on every path (a restore takes its backup chain's lock first,
which nothing taking the VM lock ever waits on). The
handlers refuse to stop or start a VM that is no longer `active` on
`job.node_id` (`vm-moved`).

## State machine (`ResizeJob`)

```
pending ──(stopped VM: swap reservation + launch record)──────────────▶ done
   │
   ├─ grow fits here: reserve new size ─▶ stopping ─▶ relaunching ─▶ (relaunch accepted) ─▶ (guest signal) ─▶ done
   ├─ shrink: (keep old reservation) ───▶ stopping ─▶ relaunching ─▶ (accepted: release to new size) ─▶ done
   └─ grow does not fit here ─▶ migrating (§25 at the old size; dest placement opened at the new size)
                                    └─(migration done)─▶ stopping (on the dest) ─▶ relaunching ─▶ done

stopping / relaunching (before accepted) ──failure──▶ rolling_back ─▶ failed (rolled_back = true)
relaunching (after accepted) ──no guest signal──▶ failed (rolled_back = false, VM at the new size)
```

- **pending**: re-checks the VM (still active, still on the admitted
  host). A stopped VM is finished here. A running grow reserves the new size
  with the fit re-checked under the host's capacity-row lock. If it no longer
  fits, the job looks for a §25 destination; if none fits, it fails with
  `rolled_back`. A mixed change never migrates: §25 first boots the OLD size
  on a destination chosen and reserved for the NEW one, which under-counts
  the dimension a mixed change shrinks. When it does not fit where it is,
  it is refused (at admission, and again at this step, before any stop). If a tick died between starting
  the §25 job and recording it, that job (`resize_to_flavor` = this target,
  started after this resize) is adopted, not orphaned.
- **stopping**: `power.stop_vm(by_migration=True)`. A dispatch failure
  leaves the power API's `stopping` marker. Once that marker goes stale (10
  min), it is settled to what the miner reports (the same
  `_settle_abandoned_power_marker` reboot-recovery applies, which skips a
  VM with a job in flight). If the miner cannot answer, a fresh stop is
  sent, because stopping a stopped domain is a no-op. Deadline 25 min, then
  `rolling_back`. A **mixed** change (more vCPU and less RAM, or the
  reverse) is reserved here, once the old guest is down, with the fit
  re-checked. If it no longer fits, the job goes to `rolling_back`.
- **relaunching**: `power.start_vm(flavor=to_flavor)`. `allowlist-pin-busy`
  is retried. `disks-missing` fails the job: the reservation is released and
  the VM stays stopped for an operator. Three `relaunch-rejected` answers
  lead to `rolling_back`. An accepted relaunch is the point of no rollback:
  `relaunched_at` is stamped first, before anything else can fail. Then the
  books are settled, retried every tick until they hold: the launch record
  names the new flavor, and a shrink releases its extra reservation. The job
  is `done` once they hold and an in-guest signal newer than the relaunch has
  arrived (deadline 20 min).
- **migrating**: waits for the §25 job. If the migration failed, the
  migration's own recovery owns the VM; the resize fails, with `rolled_back`
  true only if the VM never left its miner.
- **rolling_back**: swaps the reservation back. If the VM was running, it is
  started at the old size; the launch record never moved, because the
  relaunch was never accepted. One exception: if the launch record already
  names the new flavor, the relaunch WAS accepted and the tick died inside
  `start_vm` before recording it (before `relaunched_at`, only an accepted
  relaunch writes it). In that case the job goes back to `relaunching` with
  `relaunched_at` stamped and finishes at the new size. A stale `starting`
  marker left by such a tick is settled to what the miner runs first.
- **migrating** never times out while its §25 job is still running. That
  job has its own deadlines and always ends, and failing the resize under
  it would leave the migration opening the destination at the new size
  with nobody to relaunch at it.

Every step is resumable: the state is the durable substate, transitions are
CAS on `(id, version, state)`, and every power dispatch is counted before
it is sent (`attempts`/`attempted_at`, paced by
`VALI_RESIZE_DISPATCH_PACING_S`). A tick that died after an accepted
relaunch is recognised on the next tick: the VM is `running` and only this
job may start it.

## Capacity

The VM's `Placement` is the reservation admission counts.
`scheduler.service.swap_placement_class` closes the row `resized` and opens
a fresh `bound` one, in one transaction, under the host's `MinerCapacity`
row lock, with the fit re-checked (`resize_shortfall`). The fit is computed
with the VM's own reservation released, and its RAM credited back to a fresh
free-RAM report while it runs. The ledger never counts the VM twice or zero
times, and never less than what physically runs:

- a **grow** (no dimension smaller) reserves the new size before the stop
  (the old guest still runs, so the ledger over-counts);
- a **shrink** (no dimension larger) keeps the old size until the new-size
  relaunch is accepted;
- a **mixed** change is checked like a grow at admission and reserved
  after the stop, so the dimension it gives back is never under-counted
  while the old guest still holds it. The post-stop fit credits the old
  guest back only in a miner RAM report taken before the stop;
- a resize that **migrates** opens the destination placement at the new
  size in the §25 activation CAS (`MigrationJob.resize_to_flavor`).

A `resized` row is not a failure. `failure_source=resize`, and it does not
feed the circuit breaker.

A concurrent launch decision does not take the capacity-row lock. That is
the same "count at decision time" bound every placement has. The miner's
preflight gate stays the last word: an over-booked relaunch is refused and
rolled back.

## Launch record

`spec_json["flavor"]` of the VM's latest succeeded `LaunchJob` is what every
relaunch, §25 hop and restore sizes the guest from. `record_relaunch(...,
flavor=)` moves it in the same transaction as the new measurement, so the
record never pairs a measurement with the wrong vCPU count. That write is
best-effort in the relaunch path (a failure is logged, and the measurement
needs `vali_backfill_launch_measurement`, as for any relaunch). The resize
then still moves the flavor with `record_flavor`, retried every tick, so the
next relaunch boots the size the tenant pays for. If the flavor cannot be
moved by the deadline, the job fails loudly with `record-failed`.

For a stopped VM, `record_flavor` moves it with no relaunch: the next start
boots the new size. Until then the record keeps `emit["booted_flavor"]`, the
size its last measured boot ran at. A §25 hop, a restore or a failover
replays that boot, so they size from `launch_record.booted_flavor` (the
dest ticket's flavor and vCPU count must match its measurement). The next
accepted relaunch clears the marker.

A stopped VM resized SMALLER keeps its larger reservation: that is the size a
restore, failover or §25 hop before its next start would boot. Every
accepted relaunch makes the placement follow the size it booted, when that
size is smaller (`service._placement_follows_boot`), so the next start
releases the difference. A stopped GROW is reserved (with the fit checked)
right away. A restore or failover destination must have room for both the
booted size and the next-boot size.

A record whose base cmdline carries its own `hippius.resource_class=` is
refused with `resize-resource-class-pinned`. The launch keeps an
operator-supplied token over the flavor's, so the guest would go on
declaring the old size and every receipt would be refused against the new
billing binding.

## Billing

- **Miner ledger** (`UsageAccrual`): the relaunch rewrites
  `VmBillingBinding.resource_class`, so the new guest's receipts (which
  declare the new class from the measured cmdline) match. A receipt buffered
  by the old guest and metered after the relaunch carries the old class and
  is rejected. That costs the miner at most one receipt window, and never
  over-pays.
- **Tenant bill** (hippius-backend): the usage segment switches flavor at
  the job's `relaunched_at`, not at the request. For a stopped VM it switches
  when the job finishes, because its reservation is the new size from then.

## Failure cases

| Failure | Outcome |
|---|---|
| Different data disk, unknown/unoffered/same flavor | 400 at POST; nothing created |
| No room on the miner and no §25 destination | 409 `resize-no-capacity` at POST; or `failed`, `rolled_back` if the host filled up between POST and the first tick |
| Stop never confirmed | Re-asked once the marker is stale; past 25 min → `rolling_back` |
| Relaunch refused 3× (domain probed down each time) | `rolling_back` → old size started → `failed`, `rolled_back` |
| Relaunch "refused" but the domain runs (an Edge timeout on an order that landed) | `failed` `relaunch-outcome-unknown`, `rolled_back=false`. The domain is probed before EVERY dispatch, so nothing is retried or rolled back over it. The VM is recorded running (no later start boots it again), the larger reservation is kept, and an operator takes over. |
| Rollback finds the domain running although no relaunch was accepted | `failed` `rollback-outcome-unknown`: no second boot, the reservation is not given back, and an operator takes over |
| Miner lacks the disks | `failed` `disks-missing`; reservation released; VM stopped; operator |
| Relaunch accepted, no guest signal in 20 min | `failed` `guest-signal-timeout`, `rolled_back=false`; VM at the new size |
| Migration failed | `failed` `migration-failed: …`; §25 recovery owns the VM |
| Launch record / shrink reservation not settled by the deadline | `failed` `record-failed` / `reservation-not-settled`, `rolled_back=false`; VM at the new size; run `vali_backfill_launch_measurement` |
| Rollback itself stuck | `failed` `rollback-timeout`, `rolled_back=false`; operator |

## Settings

`VALI_RESIZE_DISPATCH_PACING_S` (60), `VALI_RESIZE_PENDING_TIMEOUT_S` (600),
`VALI_RESIZE_STOP_TIMEOUT_S` (1500), `VALI_RESIZE_RELAUNCH_TIMEOUT_S`
(1800), `VALI_RESIZE_GUEST_TIMEOUT_S` (1200),
`VALI_RESIZE_MIGRATION_TIMEOUT_S` (21600), `VALI_RESIZE_ROLLBACK_TIMEOUT_S`
(1800).
