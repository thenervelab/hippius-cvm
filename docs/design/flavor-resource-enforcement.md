# Flavor resources against an untrusted miner — vCPU, RAM, disk

Status: the vCPU count and the disk size are enforced at boot; RAM is
attested by the guest (`vali/apps/telemetry/guest_resources.py`), shipped
dark behind `VALI_GUEST_ATTEST_RESOURCES` / `VALI_GUEST_RESOURCES_ENFORCE`
/ `VALI_GUEST_ACCEPT_MEMORY_EAGER`.

The question: does a VM get the vCPU, RAM and disk it was sold — also
after a resize — when the miner that runs it is not trusted?

## Summary

| Resource | Mechanism | A miner that cheats |
|---|---|---|
| vCPU count | measured: one VMSA per vCPU in the SNP launch digest | gets no KEK; the VM does not boot |
| vCPU brought online | guest attests `vcpus_online` (live attestation v3) | flagged; unpaid under ENFORCE |
| vCPU time share | not observable from inside an SNP guest | **open** — a host may bring every AP online, then starve it |
| RAM announced | guest attests the firmware map's `System RAM` (v3) | flagged; unpaid under ENFORCE |
| RAM backed | `accept_memory=eager` + attested `Unaccepted` | with eager: flagged. Without: **open** — lazily accepted RAM can be overcommitted; it fails only when touched |
| Stale launch (old size after a resize) | KBS binds each VM to its current launch; vali drops superseded launches from the allowlist | gets no KEK, no live attestation; flagged on vali too |
| Disk replaced | LUKS keyslots under the per-VM KEK + volume stamp v2 | boot refused (exception: KBS stamp store rebuilt, below) |
| Disk size | measured `hippius.disk_gb` vs the block device | golden: boot refused. Legacy `/dev/vde`: `/data` stays unmounted |
| Disk backing | first boot writes every sector (dm-integrity wipe) | the host must keep every sector (ciphertext neither compresses nor dedups; a dropped sector fails its integrity tag on read) — on what storage, how fast, is not proven |

## vCPU — enforced by the KBS

- vali recomputes the launch digest with the flavor's `cpu_count`
  (`orchestration/services/launch.py` C2 block →
  `launch_digest.recompute_expected_digest` → `hippius-launch-digest --vcpus`),
  refuses a miner digest that differs (`launchDigestEnforce: true`), and
  pins only its own value into the §22 allowlist and the ticket's
  `allowed_measurements`.
- The KBS releases only when the report's measurement is in both
  (`kbs-core/src/snp.rs::check_attestation`).
- Proofs (#1373): the launch-digest crate's `vcpu_count` test (the real
  binary: every catalogue count and its neighbours have distinct digests on
  Milan, Genoa, Turin) and vali's `test_flavor_resources_launch` (the
  recompute gets the flavor's count; a digest for N±1 is refused before
  anything is pinned or minted).

This proves the VMSA count. It does not prove scheduling: the host decides
how much CPU time each vCPU gets.

## RAM — attested by the guest

SNP does not measure the memory size: the VMM announces it through the
firmware memory map (fw_cfg → OVMF → e820). Nothing checked it before.

A keepalive guest whose MEASURED cmdline carries `hippius.attest_resources=1`
reads, each tick:

- `vcpus_online` — `/sys/devices/system/cpu/online`;
- `mem_firmware_kib` — `System RAM` of `/sys/firmware/memmap` (the boot
  e820 map: what the VMM announced; `0` without `CONFIG_FIRMWARE_MEMMAP`);
- `mem_total_kib` — `MemTotal`;
- `mem_unaccepted_kib` — `Unaccepted`: announced RAM the guest has not
  accepted (PVALIDATEd) yet, i.e. not yet backed by the host. OVMF leaves
  RAM above 4 GiB to the kernel, which accepts it on first use.

They go into `REPORT_DATA` (`hippius_types::report_data::live_attestation_with_resources`,
its own domain) and into the keepalive request. The KBS rebuilds the
expected `REPORT_DATA` from the request: a relay that changes, strips or
invents a value breaks the byte-equality with the PSP-signed report. The
KBS signs them into a schema-v3 `LiveAttestation`; vali decodes them
(`verify-live-attestation`).

### Verdict

Judged against the launch that produced the measurement: the
`MeasurementLedger` row of its pin records the flavor, whether the cmdline
asked for the attestation and for eager acceptance, and `launched_at` once
the miner accepted that launch. Not the VM's current binding — a resize
rewrites that before the new guest boots.

| Verdict | When | Evidence |
|---|---|---|
| `superseded` | a LATER launch of the VM was accepted (`launched_at`), and the sample was verified after that + `VALI_GUEST_SUPERSEDED_GRACE_S` (300, the vali/KBS clock-skew bound). A relaunch that failed after its pin supersedes nothing; a §25 migration replays the same measured cmdline (no new pin) | yes |
| `unattested` | the launch asked, the body has no resources (image too old) | no — the image is measured, not the miner's choice |
| `short` | `vcpus_online` < flavor; firmware RAM more than `VALI_GUEST_MEM_FIRMWARE_SLACK_MIB` (64) below; without a firmware map, `MemTotal` below flavor − 2 % (struct pages) − min(6 %, 1 GiB) (SEV swiotlb) − `VALI_GUEST_MEM_TOTAL_SLACK_MIB` (256); under eager acceptance, unaccepted RAM above the firmware slack | yes |
| `ok` | at least the flavor (more is not a finding) | — |
| blank | the launch did not ask | — |

The firmware slack is absolute, not a ratio: the firmware keeps a fixed
few MiB, and 5 % of a 4xlarge is 6.4 GiB. The `MemTotal` floor models the
kernel's own reservations (~86 % of a small, ~97 % of a 4xlarge) and only
applies to a kernel without a firmware map. All thresholds are defaults to
calibrate on live figures (observe mode) before ENFORCE.

Under `VALI_GUEST_RESOURCES_ENFORCE` — which acts through the uptime
meter, so only with `uptimeLiveness.requireAttestation` armed (it is;
the synthetic check fails if ENFORCE is set without it) — only an `ok`
sample is uptime coverage, and every other sample is a BARRIER: no later sample vouches
back across it (dropping it would let the next good sample's look-back
cover the bad instant). A VM must prove its size to be paid — a launch
from before the attestation was switched on earns nothing until it is
relaunched.

Evidence (`GuestResourceShortfall`, one row per VM × node × flavor,
written in the same transaction as the sample, against the miner vali
credits at that instant — the §25 destination after a cutover, nobody when
custody is unattributable): the VM
shows `resource_shortfall` and its miner the `guest-resource-shortfall`
alert on `/v1/operator/fleet`; the synthetic `guest_resources` check
fails and `GuestResourceShortfall` (critical) fires. Under ENFORCE,
`GuestResourcesUnprovenUnderEnforce` fires for live VMs whose latest
sample is not `ok`.

### What it does not prove

- **Backing without eager acceptance.** The firmware map is what the VMM
  announced. Lazily accepted RAM is backed only when the tenant touches
  it; a host can overcommit it and the guest fails (or the host OOMs) on
  use. `accept_memory=eager` (kernel ≥ 6.5) makes the guest accept all of
  its RAM at boot, so the host must back it before the guest runs; SNP
  private pages cannot then be reclaimed by the host. Boot time grows with
  the RAM size — measure it on the largest flavor before enabling.
- **Root inside the guest.** It can ask `/dev/sev-guest` for a report
  over any `REPORT_DATA`: make its own VM look short, or — as the miner's
  accomplice (a miner renting its own VM) — make a short VM look full.
  Same exclusion as the rest of uptime billing. The evidence therefore
  never removes a miner from placement by itself; an operator reads it.

## Disk — enforced at boot

- Golden (every live VM): the per-VM upper `/dev/vda` is LUKS2+integrity
  with keyslots under the per-VM KEK the KBS releases; a foreign header
  does not open. A blank file is formatted, then the stamp gate decides:
  M0 at `E > 0` refuses a stampless volume unless the VM is still on the
  zero timeline (a pre-stamp-v2 VM: accepted ONCE as a migration); M1/M2
  refuse it at any `E > 0`. At `E == 0` — a fresh VM, or after the KBS
  stamp store was rebuilt — the gate adopts whatever it finds, blank
  included, then moves the VM to a fresh timeline.
- Size: `hippius_golden_open_upper` refuses an upper smaller than the
  measured `hippius.disk_gb` before any cryptsetup call
  (`scripts/initramfs/hippius-golden-overlay.sh`; test
  `scripts/dev/golden-overlay-test.sh` §4b, #1373). The legacy `/dev/vde` unit
  applies the same anchor but runs after boot: a short disk leaves `/data`
  unmounted rather than refusing the boot.
- `hippius.disk_gb` is vali's: an operator-supplied cmdline token wins
  over the flavor's (`_augment_cmdline_with_token`); a miner cannot change
  it (measured).
- A resize keeps the data disk by design (`docs/design/vm-resize.md`): the
  anchor is the disk the VM was launched with, not the target flavor's.
- A disk truncated after boot surfaces as I/O errors in the guest.

## After a resize

The relaunch is a new measured launch at the target flavor (new digest,
new `resource_class`, new pin). A miner that relaunches the old size:

- through vali: impossible — vali pins and tickets only the target count;
- with the PRE-resize ticket (valid up to 24 h): refused by the KBS.
  - **The gate** (`kbs_core::lifecycle::check_current_launch`). The KBS
    binds each VM to its current launch: a measurement and the ticket
    `issue_time` that established it. A ticket for another measurement
    releases only if strictly newer, and then becomes current; an older
    one is refused (`superseded-launch`). Where: at release (checked and
    advanced atomically, re-checked at gate 9 and again at 11d, right
    before the secrets leave), at keepalive, and at custody bind. The
    same launch always releases, whatever its ticket's age (re-minted
    tickets, the ticket the miner re-pushes on an in-guest reboot, a §25
    destination). Persisted next to the VM states
    (`vm-states-launch.json`); a KBS restart wipes it with the rest.
  - **When a launch becomes current.** At its first release — or, for a
    resize relaunch, at its register already: its ticket carries the
    `supersede` lifecycle perm, so the pre-resize ticket is refused before
    the relaunch is even dispatched. That holds for a VM §25 moved too:
    its row stays `Migrating{new_gen, dest, lease}`, and the KBS accepts
    a superseding register the row admits without touching the row. A
    resize asks for `supersede` until one of its relaunches registered
    (`MeasurementLedger.superseded_at_register`): an attempt refused
    before its register dispatched nothing, but a retry after a register
    — or any other relaunch — may meet a domain that is already up
    (`already-launched`) and must not strand it. A VM resized while
    stopped supersedes the same way at its next starts
    (`resize.next_start_supersedes`).
  - **Custody.** A lease remembers the launch that bound it; once the VM
    is on another launch the lease renews and rekeys nothing.
  - **Defence in depth** (vali). The §22 carry-forward keeps, per live
    VM, only its current ACCEPTED launch (`MeasurementLedger.launched_at`,
    never stamped for `already-launched`) and anything pinned after it.
    After each accepted launch vali re-installs the allowlist without the
    superseded ones and stamps them `evicted_at`
    (`allowlist_pin.evict_superseded_measurements`, retried by the
    orchestration tick; `vali_allowlist_evict_superseded` for operators).
- an older KBS (before the moved-VM supersede) answers 409 to the
  superseding register of a §25-moved VM; vali does not fall back, the
  resize relaunch fails (`kbs-admin-conflict`). The KBS deploys before
  vali, with no resize or relaunch in flight during the roll.
- a rollback in which no relaunch registered leaves the pre-resize launch
  current: it is the old size, which the rollback restores.
- the binding is a measurement, not a launch instance: a launch measured
  identically to an earlier one (operator-pinned `validator_nonce` and
  `eol_nonce`, back at the same size) admits that one's tickets and
  custody leases. Both describe the size booked.
- a resize relaunch refused before its register leaves the old launch
  current; the next attempt supersedes again. Once one registered, a
  rollback runs the VM again at the old size with a newer ticket, current
  at its first release.

## Rollout

Three parties: guest (keepalive + shim), KBS (wire + keepalive), vali
(decoder + policy). Nothing changes until vali sets the cmdline token.

1. Deploy vali (migrations `orchestration.0027`, `telemetry.0010`; the v3
   decoder in the image's `hippius-ticket-validator`) and the KBS, every
   replica. A v3 body exists only once a guest sends resources, so their
   order does not matter; the fleet must be complete before step 3. The
   current-launch binding (`orchestration.0028`, `0029`) does impose one:
   KBS first, then vali, with no resize or relaunch in flight.
2. Re-bake the golden images (new `hippius-agent-keepalive` + shim). Inert
   until step 3.
3. `guestResources.attest: true`: every launch/relaunch carries the token;
   running VMs pick it up at their next relaunch. Never before step 1: an
   older KBS refuses the request (`deny_unknown_fields`) and the VM's
   uptime stops being covered.
4. Observe: `VmLiveAttestation.mem_*` / `resource_verdict` fleet-wide per
   distro and flavor; tune the thresholds; relaunch every VM not yet
   proving its size until `hippius_synthetic_guest_resources_unproven_vms`
   reads 0.
5. `guestResources.enforce: true`.
6. Independently: `guestResources.acceptMemoryEager: true` once a canary
   launch of the largest flavor boots within the boot-stall budget.
