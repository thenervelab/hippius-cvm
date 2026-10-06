"""Boot stall: a launch or relaunch whose guest never came up.

## The failure this makes visible

When a miner-agent's ticket push fails right after it starts a domain, it
leaves the domain running on purpose: its reboot-watcher re-pushes the
ticket for about 10 minutes, and a same-miner retry inside that window is
answered `already-launched`, which vali accepts. A guest that never gets its
ticket never unlocks its overlay. Every other readout stays green:

  * `state=active` and the libvirt domain is `running`;
  * `boot_phase` stays at `""` / `booting` on a first launch, and stays at
    whatever the PREVIOUS boot reached on a relaunch (it is monotonic);
  * `guest_liveness` reads `unknown` (never emitted) or `alive` for a while
    (the previous boot's last signal), never `wedged` in time to matter.

## The verdict — basis is the IN-GUEST signal

A VM is `stalled` when all of these hold:

  * it is `active`, powered `running`, and bound to a host;
  * NO in-guest signal (`Vm.guest_signal_at`: §23 served receipt or §322
    live attestation) has landed since its current boot began;
  * more than `deadline_s(disk_gb)` has passed since its current boot began.

`boot_phase` plays no part. `kek_released` does not exempt a VM (a guest can
get its KEK and still hang), and a relaunch is judged on its own boot even
though `boot_phase` still says `running` from the one before.

"Its current boot began" is `Vm.boot_started_at`: stamped when a launch
first binds a host, when a §25 migration activates the VM on its
destination (orchestrated or via the API transition), and when
reboot-recovery or a power start relaunches it. A same-miner launch retry
answered `already-launched` does NOT restamp it (the host is already
bound), so a retry cannot keep pushing the verdict back. Rows from before
the column existed fall back to `created_at`. A stranded migration's restore
to source does NOT restamp it: that code cannot tell whether the source
guest is down, so it is not a new boot.

## The deadline — sized per flavor

A first boot of a golden image formats the per-VM overlay with dm-integrity,
which writes every sector, so it scales with the flavor's data disk
(`hippius.disk_gb`). Measured on the slowest miner (Milan, SATA RAID-1):
~6.8 s/GiB serial (80 GiB ≈ 545 s; 2xlarge 640 GiB ≈ 72 min). #1225's
parallel wipe is faster but inert until the golden bases are re-baked. The
backend follows a boot for 600 s + 15 s/GiB, capped at 3 h; this mirrors it:

    deadline = VALI_BOOT_STALL_S (900)
             + min(VALI_BOOT_STALL_PER_DISK_GB_S (15) × disk_gb,
                   VALI_BOOT_STALL_DISK_CAP_S (10800))

The 900 s base covers the boot to `kek_released` (~340 s on Milan) plus the
first served receipt. small → 25 min, xlarge → 95 min, 4xlarge → 3 h 15 min.
A VM whose flavor vali cannot resolve gets the full cap. The per-GiB term is
applied to every boot, not only the first (a relaunch of an interrupted
first boot formats again), which only errs late.

## Limits

  * An image WITHOUT the telemetry agent never emits a signal, so every VM
    on it reads stalled once past the deadline. Every in-cluster bake
    installs the agent (`binaries/tenant-baker/entrypoint.sh`); images baked
    by hand with `tenant-image-bake.sh` and no `--hippius-telemetry-bin`
    do not.
  * Root inside the guest can stop the agent; a later relaunch then reads
    stalled.

Derived at read time, like `guest_liveness`. Observability only: nothing
here gates a release, and no automated action is driven from it — the
reboot-recovery WEDGED trigger stays keyed on `guest_liveness.classify`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.utils import timezone


def base_s() -> int:
    """The flavor-independent part of the deadline."""
    return max(1, int(getattr(settings, "VALI_BOOT_STALL_S", 900)))


def per_disk_gb_s() -> int:
    return max(0, int(getattr(settings, "VALI_BOOT_STALL_PER_DISK_GB_S", 15)))


def disk_cap_s() -> int:
    return max(0, int(getattr(settings, "VALI_BOOT_STALL_DISK_CAP_S", 10800)))


def deadline_s(disk_gb: int | None) -> int:
    """How long a boot may go without an in-guest signal. `None` (flavor
    unknown) gets the full disk allowance."""
    cap = disk_cap_s()
    disk = cap if disk_gb is None else min(per_disk_gb_s() * max(0, disk_gb), cap)
    return base_s() + disk


@dataclass(frozen=True)
class BootStall:
    """The boot-stall readout for one VM.

    - `stalled`         the verdict.
    - `boot_started_at` when the current boot began (`boot_started_at`,
                        else `created_at` for legacy rows).
    - `elapsed_s`       seconds since `boot_started_at` while no in-guest
                        signal has landed for this boot; `None` otherwise.
    - `deadline_s`      the bound applied to this VM.
    """

    stalled: bool
    boot_started_at: datetime | None
    elapsed_s: int | None
    deadline_s: int


def boot_clock_start(vm) -> datetime | None:
    """When the VM's current boot began."""
    return vm.boot_started_at or vm.created_at


def classify(vm, *, disk_gb: int | None, now: datetime | None = None) -> BootStall:
    """The boot-stall verdict for a `Vm` row. No DB access."""
    from .models import VmPowerState, VmState

    started = boot_clock_start(vm)
    deadline = deadline_s(disk_gb)
    signalled = vm.guest_signal_at is not None and (
        started is None or vm.guest_signal_at >= started
    )
    if started is None or signalled:
        return BootStall(False, started, None, deadline)
    now = now or timezone.now()
    elapsed = max(0, int((now - started).total_seconds()))
    stalled = (
        vm.state == VmState.ACTIVE
        and vm.power_state == VmPowerState.RUNNING
        and bool(vm.host)
        and elapsed > deadline
    )
    return BootStall(stalled, started, elapsed, deadline)


def disk_gb_by_vm_id(vm_ids: Iterable[str]) -> dict[str, int]:
    """`{vm_id: data-disk GiB}` from each VM's most recent `LaunchJob`
    flavor. One query. VMs with no job or an unknown flavor are absent."""
    from apps.orchestration.models import LaunchJob
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor

    ids = list(set(vm_ids))
    if not ids:
        return {}
    out: dict[str, int] = {}
    rows = (
        LaunchJob.objects.filter(vm_id__in=ids)
        .order_by("vm_id", "-started_at")
        .values_list("vm_id", "flavor", "spec_json")
    )
    for vm_id, flavor, spec in rows:
        if vm_id in out:
            continue
        # A resized VM keeps its launch disk, pinned on the spec.
        pinned = int((spec or {}).get("data_disk_size_gb") or 0)
        if pinned:
            out[vm_id] = pinned
            continue
        try:
            out[vm_id] = resolve_flavor(flavor).data_disk_size_gb
        except UnknownFlavor:
            continue
    return out
