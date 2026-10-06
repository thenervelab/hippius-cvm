# Recovering a VM after a failed guest upgrade

A guest upgrade (`vali_guest_upgrade`, a `GuestRollout`, or `POST
/v1/vm/<vm>/guest-upgrade`) that cannot prove its target booted rolls back —
**unless the target raised the VM's security epoch**. The VM's
`required_epoch` was raised to the target's before anything was stopped (G3,
docs/design/guest-component-rollout.md), so vali never boots the previous
release again, and the job ends:

| job state | VM | means |
|---|---|---|
| `parking` | the job is stopping the target's boot | wait: it ends `upgrade_blocked` once the miner reports the domain DOWN |
| `upgrade_blocked` | **stopped on the target** (or still running the previous release if nothing was ever stopped) | an operator decides — this runbook |
| `failed` | a rollback that did not take (same-epoch target): stopped, on the target or the previous release | an operator decides — this runbook |

On a tenant's VM `upgrade_blocked` is an **outage**. Restore service first
(§1), diagnose second (§2), retry once it is fixed (§3).

This is correct security-wise — a miner that withholds the guest's samples
cannot force a downgrade onto the vulnerable release — and nothing below
weakens it: every path here boots the target (at or above the floor),
through the normal launch path (launch-digest ENFORCE, the §22 auto-pin,
the KBS supersede at register). There is no command that boots a release
below `required_epoch`; the only way down is the audited break-glass
`vali_guest_epoch_lower` (§4).

All commands run in the vali pod:

```sh
kubectl -n vali exec deploy/vali -- python manage.py vali_guest_upgrade --vm-id <vm> --status
```

## Alerts

| alert | severity | fires on |
|---|---|---|
| `GuestUpgradeTenantVmDown` | critical | a VM **with a tenant** whose latest job is `upgrade_blocked` / `failed` / `parking` and whose power state is not `running` |
| `GuestUpgradeVmNeedsOperator` | warning | any such VM (an internal one, or one recovered by §1 but not yet verified by §3) for 30 min |
| `GuestUpgradeFailed` | warning | a job ended `failed` / `upgrade_blocked` in the last 24 h, labelled by `outcome` and `suspect` |
| `GuestUpgradeOverdue` | warning | a job past its state's deadline — a `parking` job whose domain the miner never reports DOWN |

The gauges come from the hourly `guest-report` CronJob: an alert can lag
the event by up to an hour. `--status` is always current.

## §1 — restore service: `--recover start-on-target`

```sh
# dry run: says what it would do, or why it is refused
python manage.py vali_guest_upgrade --vm-id <vm> --recover start-on-target \
    --operator <you> --reason "<ticket / why>"
# do it
python manage.py vali_guest_upgrade --vm-id <vm> --recover start-on-target \
    --operator <you> --reason "<ticket / why>" --apply
```

(API: `POST /v1/vm/<vm>/guest-upgrade/<job_id>/recover`, body
`{"action": "start-on-target", "reason": "..."}`, root-only; the caller is
the recorded operator.)

It starts the VM on the job's **target** release through the power API: the
launch record is CAS-swapped onto the target if it names the previous set,
the start supersedes every earlier launch at the KBS register (the job's
failed attempts included), and the measurement is auto-pinned under
ENFORCE. The VM gets its service back **without** the health gate: the job
stays `upgrade_blocked` / `failed`, and the start is recorded on it
(`recoveries`: who, why, when, result, and an `operator_start` attempt
linked to that boot's pin). `required_epoch` does not move;
`attested_epoch` does not either — the VM runs an **unverified** release
until §3 succeeds.

Refusals (`refused: <category>`):

| category | meaning | do |
|---|---|---|
| `parking` | the job still holds the VM | wait; if `GuestUpgradeOverdue`, check the domain on the miner, then `--release-parked <job> --operator --reason` once you KNOW it is down |
| `domain-running` | the miner reports a domain up | find out what runs (`virsh list` on the miner); never start a second guest on the same disks. Stop it, then retry |
| `domain-unknown` | the miner did not answer | the miner is unreachable — fix that first (a `no-sample` outcome on top of this points at the miner) |
| `vm-not-stopped` | the VM is not recorded `stopped` | it may already run (`--status`, `power=`), or a power op is in flight |
| `start-settling` | an earlier recovery start was answered as refused but may still land | wait: the VM is held `starting` until the dispatch settled (the marker goes stale after 10 min and is settled to what the miner runs); run it again then |
| `superseded` | a newer job took the VM (a pending retry does not count) | recover (or let finish) the newest one |
| `below-floor` | the floor moved above the target since | upgrade onto a release at the new floor (§3) |
| `build-withdrawn` | the target build / release was withdrawn | do not boot it: retry onto a newer release (§3), which starts the stopped VM itself |
| `c2-not-enforced` | launch-digest ENFORCE is off | turn it back on; recovery never launches without it |
| `record-moved` | the launch record names neither the target nor the previous set | someone swapped it by hand — investigate before anything boots |
| `relaunch-rejected` | the miner did not accept the start — or its answer was lost after the order went out | the VM is held `starting` and the attempt open (`unsettled:`) until it settled; then `--apply` again (see below) |
| `disks-missing`, `allowlist-pin-busy` | the miner does not hold the disks / other starts held the pin lock (nothing dispatched) | the VM stays stopped; `disks-missing`: locate the data; pin busy: retry |

The start is claimed (`starting`) in the same transaction as the decision
and the record swap: no other start can slip in between. A refusal that may
hide a launch still landing (an Edge timeout, `relaunch-rejected`) keeps the
claim and leaves the attempt open (`result=unsettled:<reason>`); `--apply`
again settles it first — `refused` once the miner reports the domain DOWN
past the dispatch-settle window, `domain-running` if it came up.

A `failed` job whose previous release is at or above the floor (a
same-epoch target whose rollback did not take) may also be started on that
previous release with a plain power start — the floor allows it.
`start-on-target` always boots the target.

After `--apply`, check:

- `--status`: `power=running`, the recovery line `result=started`, the
  `operator_start accepted` attempt;
- the guest attests live (`GET /v1/vm/<vm>/attestation` — the measurement
  is the `operator_start` attempt's), and the tenant can reach it.

## §2 — diagnose: the job's `outcome`

`--status` prints `outcome=<slug> suspect=<side>` on the failed job; the API
returns them as `outcome` / `suspect`, the logs as `outcome=` on the
`target failed` line, the metrics as labels. `reason` carries the evidence
(which sample, which checks).

`suspect` is a first lead, not a verdict: a hostile miner can break a guest's
disk or network and make any outcome look like ours.

| outcome | suspect | evidence | what to look at |
|---|---|---|---|
| `health-failed` | release | a v4 sample of the target's own boot failed health checks — `reason` names the missing check bits (`misses checks 0x4 (bits 2)`), or a sample without the health leg / another release | the component the bit names (`hippius_types::live_attestation::components_health`) on a throwaway VM of the same base; fix, cut a new release |
| `health-latched` | release | the guest counted failing ticks no sample showed | as above — a check failing intermittently (a withheld sample shows here too) |
| `guest-restarted` | release | the keepalive instance changed during the soak | a guest crash or reboot: serial console / journal of the guest; a miner rebooting the VM also shows here |
| `resources-mismatch` | miner | the guest attested other resources than its flavor's | the miner's domain definition (vCPU / memory) |
| `no-sample` | miner | nothing of the target attested in time | does the target boot at all (try a throwaway VM on another miner)? if it does, the miner is withholding samples or blocking the guest's network — compare with the miner's other VMs |
| `measurement-mismatch` | miner | the VM attested, but another measurement than the job's own boots | the miner runs something else: an old guest kept alive, or a boot it started itself (T4) — check `GuestSupersededGuestRunning` / `GuestLiveOnStoppedVm`, quarantine the miner |
| `dispatch-failed` | miner | the relaunch (or the recover) was refused / rejected | the miner agent's logs; capacity; `disks-missing` |
| `stop-timeout` | miner | the miner never confirmed the stop | the miner is unreachable or ignores stop orders |
| `launch-timeout` | miner | no relaunch was accepted before the deadline | pin-lock contention, the Edge, the miner |
| `c2-not-enforced` | vali | ENFORCE was off when the job had to launch | configuration |
| `vm-moved` | fleet | the VM left its miner under the job | a §25 move or a decommission raced the upgrade |

## §3 — retry

Once the cause is fixed — a new release, the miner repaired, or the
evidence shows a transient — upgrade the VM again:

```sh
python manage.py vali_guest_upgrade --vm-id <vm> --release <N>          # dry run: "(retrying gu-…)"
python manage.py vali_guest_upgrade --vm-id <vm> --release <N> --apply
```

(API: `POST /v1/vm/<vm>/guest-upgrade` `{"release": N}`.)

On a VM whose latest job is `upgrade_blocked` the new job **retries** it
(`retry_of`):

- **the same release**: admitted although the launch record already names
  it. The job keeps the blocked job's previous set as its own, so a failing
  retry blocks again — it never "rolls back" onto the target it is testing,
  and never onto the release below the floor. A new build of the same
  release for the same base is not possible (one build per release and
  base): a fix means a new release.
- **a newer release**: a normal upgrade from the target the record names.
- **the VM may still be stopped**: a retry takes the VM the blocked job left
  stopped — or one whose §1 start failed — and starts it as part of the
  upgrade (one boot, gated). A VM someone stopped on purpose after the
  block (a completed stop order) waits for its next start instead, like any
  stopped VM.

A retry that ends `done` sets `attested_epoch` and clears the VM from
`GuestUpgradeVmNeedsOperator`. Until a retry takes the VM (while it is
pending, or once it is cancelled) the blocked job stays in charge: it is
still the one to recover, and the alerts keep firing. The floor never moves
in either direction.

During a vali deploy, an orchestration tick still on the previous image does
not know retries. It cancels a retry it cannot read (`already-on-target` /
`swap-pending`, or one waiting on a stopped VM) without touching the VM, or
— a newer release on a VM already recovered and running — runs it as an
ordinary upgrade (rolling back onto the recovered target at worst, which
is at the floor). Neither boots below the floor. Admit a cancelled retry
again once the deploy is done.

## §4 — what is NOT a recovery

- **§25 migration** of a blocked VM: it replays the source's boot, which G3
  refuses below the floor. "Upgrade on destination" is not built yet.
- **`vali_guest_epoch_lower`**: the audited break-glass that lowers the
  floor so the previous (vulnerable) release may boot again. Only when the
  target is proven broken AND no fixed release can be cut in time AND the
  tenant accepts running the flaw. It is refused while any job of the VM is
  in flight. Afterwards a new upgrade (or `--rollback`) is the way back.
- **`--release-parked`**: releases a `parking` job without the miner's
  DOWN. Only once you have confirmed the domain is gone on the host; it
  ends the job, it does not restart anything.
