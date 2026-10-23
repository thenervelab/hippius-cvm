"""R3: the dedicated-disk probe and the disk state machine
(docs/design/disk-tier-verification.md §3.3, §5.2; contract
docs/design/dedicated-disks-contract.md).

A declared dedicated disk starts `pending_probe`; one §24 released goes
`released → pending_probe` once the agent reports it wiped and free
(`dedicated.reconcile_released`). From there ONLY a passing d1 verdict puts
it on sale:

    pending_probe → probing → free | unfit | failed      (a verdict)
                            → pending_probe + backoff    (no verdict)
    free | pending_probe → released + alert              (a signature after the wipe)
    free → released                                      (held by a VM vali never gave it)

**Selection** (`schedule`, only while `VALI_DEDICATED_PROBE_ENABLED`, on a
node of `VALI_DEDICATED_PROBE_MINERS`): per node, its `pending_probe`
disks that are active (not draining), assigned to no VM, past their
backoff, and reported by the agent free, clean (no refusal code: no
signature, bound, held by no VM) and recent — after the agent's wipe of
any earlier hold — up to 8, one probe VM per node at a time (shared with
the pool probe: 1 run per miner, one fleet cap; the node's capacity row
locks the check). Never an `assigned`, `released`, `draining`,
`replaced`, `failed` or `unfit` disk. The run and the `pending_probe →
probing` moves commit together, every condition re-checked under the
rows' locks, so a disk is in at most one run and never assigned meanwhile
(placement takes `free` disks only).

**The probe VM** is R1's (`apps.disktier.probe.launch`): a probe owner,
`purpose: probe` (never billed, never paid, never capacity proof), the
blessed probe image, pinned to the node's chip, its OS disk on a pool of
the node (`default` when it can). Its targets are the disks, slots
`x0..x7`, profile d1, and nothing else (the OS pool is not measured: pool
probing has its own switch). The launch intent names the disks
(`probe_extra_disks`, accepted from the run's own disk-probe launch only,
`launch_jobs._check_probe_disks`); the launch order carries them as
`extra_disks` and the measured cmdline as `hippius.dedicated=` — always
together, the same slots ([`launch_disks`], `services.launch`).

**What the guest does with them.** On guest release 6+ the initramfs
opener sees the anchor and luksFormats each blank slot, opening it as
`hippius-<slot>`; the probe (guest release 7) closes that mapping and
measures the device through its own ephemeral plain dm-crypt mapping. So
while the probe VM runs the disk carries a LUKS header — expected, and the
agent reports a held disk `assigned` whatever it carries. The header goes
in the agent's release wipe when the probe VM's §24 frees the disks.

**Verdict → state** ([`settle`]), applied once the probe VM is gone
(`torn_down_at`: destroyed or provably never existed), so a disk a probe
VM may still hold is never `free`:

- any I/O error (the guest's `io-error`, surface errors `io-errors`) ⇒
  `failed`, whatever else the result says;
- the disk's target classified `hdd`/`ssd`/`nvme` with no failure ⇒ `free`
  (`verified_tier` = the lower of that grade and the operator's declared
  class, `hdd` when none is declared (`tiers.capped`: downgrade-only),
  `probed_at`, `last_probe`, and `verified_size_bytes` = the size the GUEST
  measured, d1's `size_mib`, guest release 7 — never the miner's figure);
- classified `unfit`, the guest's `disk-too-small`, or a measured size
  below the size class the run measured on the probe VM's cmdline (the
  miner overstated it) ⇒ `unfit`;
- anything else — no accepted result (launch refused or failed, timeout),
  a result carrying slots the run never asked (`targets-mismatch`), the
  target missing, no measured size, the guest unable to measure it
  (`disk-not-found`, `crypt-open-failed`, `opener-close-failed`,
  `probe-timeout`, `suspect-cache`, ...) ⇒ back to `pending_probe`,
  `probe_failures + 1`, next attempt after an exponential backoff. Never
  `free`.

`freed_at` is set at that moment: the probe VM's hold is over and the agent
wipes what it held, so only a later report is post-wipe — the only kind
placement (`dedicated.qualifying`) and the next selection read.

**Signature after the wipe** ([`reconcile_signatures`], on every `v7`
report, whichever switch is on — it only ever takes a disk off sale): a
`free` or `pending_probe` disk a VM held before (`freed_at` set) that the
agent now reports with an on-disk signature (`disk-has-signature`, in a
report newer than `freed_at`), or a `free` disk reported signed at all —
the release wipe left a header, or something wrote to a disk on sale —
goes back to `released` (so it needs a clean report, then a new probe)
and alerts; a `released` one in that state stays and alerts. The agent's
code does not say WHICH signature (crypto_LUKS or another): any is treated
the same. A `free` disk the agent reports held by a VM vali never gave it
(`held-elsewhere`) goes back to `released` too.

Every state change writes a `MinerCapacityAudit` row (actor `disk-tier`,
`dedicated.audit_transition`)."""

from __future__ import annotations

import logging
import secrets
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import transaction
from django.db.models import F, Max, Q, QuerySet

from apps.synthetic import metrics

from . import dedicated
from .classify import FAILURE_IO_ERRORS
from .models import (
    DEDICATED_SLOTS,
    DedicatedDisk,
    DedicatedDiskDesiredState,
    DedicatedDiskState,
    DiskKind,
    DiskProbeRun,
    MinerStoragePool,
    ProbeRunState,
    ProbeTrigger,
)
from .probe_owners import probe_owners
from .routing import REPORT_MAX_AGE
from .storage_doc import DEFAULT_POOL_ID
from .tiers import SELLABLE_TIERS, DiskTier, capped

if TYPE_CHECKING:
    from .probe import TickReport

log = logging.getLogger("apps.disktier.dedicated_probe")

#: The triggers of a dedicated-disk run (a pool run never carries them).
DEDICATED_TRIGGERS: tuple[str, ...] = (ProbeTrigger.DECLARED.value, ProbeTrigger.RELEASED.value)
#: At most this many disks per probe VM (design §3.3; the guest opens 8).
MAX_DISKS_PER_RUN = 8
#: The agent's refusal code for an on-disk signature.
SIGNATURE_ERROR = "disk-has-signature"
#: The guest's and the classifier's I/O-error codes: the disk is `failed`.
IO_ERROR_CODES = frozenset({"io-error", FAILURE_IO_ERRORS})
#: Guest codes that are a verdict about the disk: `unfit`.
UNFIT_CODES = frozenset({"disk-too-small"})
#: A result that is not this run's slots: no disk of it is graded.
_TARGETS_MISMATCH = "targets-mismatch"

# Settle outcomes (the audit `reason` and the metrics label).
PASS = "probe-pass"
BELOW_FLOOR = "probe-below-floor"
TOO_SMALL = "probe-disk-too-small"
IO_ERROR = "probe-io-error"
NO_VERDICT = "probe-no-verdict"
SIGNATURE_AFTER_WIPE = "signature-after-wipe"
SIZE_MISMATCH = "probe-size-mismatch"
HELD_ELSEWHERE = "held-elsewhere"
MIB = 2**20


class ProbeDisksRefused(Exception):
    """A probe launch's `probe_extra_disks` are not its run's disks, or not
    held by its run any more: the order is not sent."""


# ── settings ─────────────────────────────────────────────────────────


def enabled() -> bool:
    return bool(getattr(settings, "VALI_DEDICATED_PROBE_ENABLED", False))


def allowed_miners() -> frozenset[str]:
    return frozenset(
        m.lower() for m in (getattr(settings, "VALI_DEDICATED_PROBE_MINERS", None) or ())
    )


def miner_allowed(node_id: str, allowed: frozenset[str]) -> bool:
    return "*" in allowed or node_id.lower() in allowed


def start_delay_s() -> int:
    from .probe import _rng

    return _rng.randint(
        int(settings.VALI_DEDICATED_PROBE_START_DELAY_MIN_S),
        int(settings.VALI_DEDICATED_PROBE_START_DELAY_MAX_S),
    )


def min_guest_release() -> int:
    """The probe image's floor for a dedicated run: guest release 7 at
    least (the probe closes the opener's slot mapping and reports the
    measured size), and never below the pool probe's own floor."""
    return max(
        int(getattr(settings, "VALI_DEDICATED_PROBE_MIN_GUEST_RELEASE", 7)),
        7,
        int(settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE),
    )


def image_ready() -> bool:
    """The probe image is blessed at [`min_guest_release`] or later."""
    from . import probe

    return probe._image_ready(minimum=min_guest_release())


def run_timeout_s(run: DiskProbeRun) -> int:
    """A dedicated run's verdict window after its start delay: one guest
    target budget per disk (measured one after another) plus the margin."""
    n = max(1, len(_dedicated_targets(run)))
    return n * int(settings.VALI_DEDICATED_PROBE_TARGET_BUDGET_S) + int(
        settings.VALI_DEDICATED_PROBE_MARGIN_S
    )


def isolate_suspects(disks: list[DedicatedDisk]) -> list[DedicatedDisk]:
    """The disks the next run takes: a disk whose last attempt ended
    without a verdict (`probe_failures > 0`: maybe the one that hung a whole
    run) goes alone, so it cannot time out its neighbours again; else all
    of them (up to 8)."""
    suspects = [d for d in disks if d.probe_failures > 0]
    return suspects[:1] if suspects else disks


def backoff(failures: int) -> timedelta:
    """The wait after `failures` (>= 1) attempts in a row without a verdict."""
    base = max(1, int(settings.VALI_DEDICATED_PROBE_RETRY_S))
    cap = max(base, int(settings.VALI_DEDICATED_PROBE_RETRY_MAX_S))
    return timedelta(seconds=min(cap, base * 2 ** min(max(failures, 1) - 1, 20)))


# ── the run's disks ──────────────────────────────────────────────────


def is_dedicated_run(run: DiskProbeRun) -> bool:
    return run.trigger in DEDICATED_TRIGGERS


def pool_runs_q() -> Q:
    """The pool probe's runs (R1 reads only these)."""
    return ~Q(trigger__in=DEDICATED_TRIGGERS)


def _dedicated_targets(run: DiskProbeRun) -> list[dict[str, Any]]:
    return sorted(
        (t for t in run.targets if t.get("kind") == DiskKind.DEDICATED.value),
        key=lambda t: dedicated._slot_index(t["slot"]),
    )


def intent_disks(run: DiskProbeRun) -> list[dict[str, Any]]:
    """What the run's launch intent names (`probe_extra_disks`): its disks
    in slot order, `[]` for a pool run."""
    return [
        {"slot": t["slot"], "disk_id": t["disk_id"], "size_gb": int(t["size_gb"])}
        for t in _dedicated_targets(run)
    ]


def spec_extra_disks(raw: object) -> list[dedicated.ExtraDisk]:
    """A launch spec's `probe_extra_disks` as order entries; `[]` without.
    Fails loudly on a malformed stored value."""
    if not raw:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"malformed probe_extra_disks in a launch spec: {raw!r}")
    out = []
    for entry in raw:
        if not isinstance(entry, Mapping) or set(entry) != {"slot", "disk_id", "size_gb"}:
            raise ValueError(f"malformed probe_extra_disks entry: {entry!r}")
        size = entry["size_gb"]
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError(f"malformed probe_extra_disks entry: {entry!r}")
        out.append(
            dedicated.ExtraDisk(
                slot=str(entry["slot"]), disk_id=str(entry["disk_id"]), size_gb=size
            )
        )
    return out


def launch_disks(vm_id: str, node_id: str, raw: object) -> list[dedicated.ExtraDisk]:
    """The `extra_disks` of a dedicated probe VM's launch order on
    `node_id`: its spec's `probe_extra_disks`, which must be exactly its
    run's disks, the run on this node and not closed, and every disk still
    `probing` for that run on this node and assigned to no VM. Raises
    [`ProbeDisksRefused`] otherwise — a disk is never handed to a probe VM
    it was not selected for."""
    disks = spec_extra_disks(raw)
    run = DiskProbeRun.objects.filter(vm_id=vm_id).first()
    if run is None or not is_dedicated_run(run):
        raise ProbeDisksRefused(f"vm {vm_id} is not a dedicated-disk probe run")
    node = (node_id or "").lower()
    if run.miner_node_id.lower() != node:
        raise ProbeDisksRefused(f"probe run of vm {vm_id} is not on this node")
    if run.torn_down_at is not None or run.state == ProbeRunState.TORN_DOWN:
        raise ProbeDisksRefused(f"probe run of vm {vm_id} is closed")
    expected = [
        dedicated.ExtraDisk(slot=d["slot"], disk_id=d["disk_id"], size_gb=d["size_gb"])
        for d in intent_disks(run)
    ]
    if not disks or disks != expected:
        raise ProbeDisksRefused(f"vm {vm_id} names other disks than its probe run")
    pks = [t.get("disk_pk") for t in _dedicated_targets(run)]
    held = {
        str(d.pk): d
        for d in DedicatedDisk.objects.filter(
            pk__in=pks,
            state=DedicatedDiskState.PROBING,
            last_probe=run,
            assigned_vm__isnull=True,
        )
    }
    for target in _dedicated_targets(run):
        disk = held.get(str(target.get("disk_pk")))
        if disk is None or disk.disk_id != target["disk_id"] or disk.miner_node_id.lower() != node:
            raise ProbeDisksRefused(
                f"disk {target['disk_id']} is no longer probing for vm {vm_id} on this node"
            )
    return disks


# ── selection ────────────────────────────────────────────────────────


def candidate_rows(now: datetime) -> QuerySet[DedicatedDisk]:
    """Every disk a probe may take now (see the module docstring), oldest
    declaration first: `pending_probe`, active, assigned to no VM, past its
    backoff, a size the agent takes, and reported free, held by no VM, with
    no refusal code (no signature), recently — and, for a disk a VM held
    before (`freed_at`), in a report newer than that hold (after the
    agent's release wipe)."""
    from .dedicated import GIB, MAX_SIZE_CLASS_GIB, MIN_SIZE_GB, SIZE_CLASS_GIB

    return (
        DedicatedDisk.objects.filter(
            state=DedicatedDiskState.PENDING_PROBE,
            desired_state=DedicatedDiskDesiredState.ACTIVE,
            assigned_vm__isnull=True,
            reported_state="free",
            reported_vm_id="",
            reported_error="",
            reported_at__gte=now - REPORT_MAX_AGE,
            size_bytes__gte=MIN_SIZE_GB * GIB,
            size_bytes__lt=(MAX_SIZE_CLASS_GIB + SIZE_CLASS_GIB) * GIB,
        )
        .filter(Q(probe_retry_at__isnull=True) | Q(probe_retry_at__lte=now))
        .filter(Q(freed_at__isnull=True) | Q(reported_at__gt=F("freed_at")))
        .order_by(F("declared_at").asc(nulls_last=True), "disk_id")
    )


def candidates(now: datetime) -> dict[str, list[DedicatedDisk]]:
    """`{node lower-cased: [disks]}` of [`candidate_rows`]."""
    out: dict[str, list[DedicatedDisk]] = {}
    for disk in candidate_rows(now):
        out.setdefault(disk.miner_node_id.lower(), []).append(disk)
    return out


def os_pool_for(node_id: str) -> str | None:
    """The pool the probe VM's OS disk goes on: `default` when the node has
    no storage report or reports `default` (an order without `os_pool`);
    else the first pool the probe can pin (`probe.os_pool_skip`); `None`
    when there is none."""
    from .probe import os_pool_skip

    pools = list(
        MinerStoragePool.objects.filter(miner_node_id__iexact=node_id, retired_at__isnull=True)
        .order_by("pool_id")
        .values_list("pool_id", flat=True)
    )
    if not pools or DEFAULT_POOL_ID in pools:
        return DEFAULT_POOL_ID
    for pool_id in pools:
        if not os_pool_skip(node_id.lower(), pool_id):
            return pool_id
    return None


def create_run(
    *, node_id: str, chip_id: str, disks: list[DedicatedDisk], os_pool_id: str, now: datetime
) -> DiskProbeRun | None:
    """A `scheduled` run over `disks` (at most 8, in that order as `x0..`)
    and their `pending_probe → probing` moves, in one transaction under the
    rows' locks. A disk that stopped qualifying meanwhile is left out;
    `None` when none is left. Raises `RuntimeError` without a probe owner."""
    from .probe import _new_vm_id, _rng

    owners = probe_owners()
    if not owners:
        raise RuntimeError("VALI_DISK_PROBE_OWNERS is empty")
    owner = _rng.choice(owners)
    picked = [d.pk for d in disks[:MAX_DISKS_PER_RUN]]
    with transaction.atomic():
        # One probe VM per node, even against a second tick run by hand: the
        # node's capacity row is the node's lock, and an open run on the
        # node (pool or dedicated) wins.
        from apps.scheduler.models import MinerCapacity

        list(MinerCapacity.objects.select_for_update().filter(miner_node_id__iexact=node_id))
        if (
            DiskProbeRun.objects.filter(miner_node_id__iexact=node_id, torn_down_at__isnull=True)
            .exclude(state=ProbeRunState.TORN_DOWN)
            .exists()
        ):
            return None
        # Every selection condition again, under the rows' locks — taken in
        # `disk_id` order, the order every writer of a node's disk rows
        # locks them in (`dedicated.assign`, the storage document's class
        # sync).
        locked = {
            d.pk: d
            for d in candidate_rows(now)
            .select_for_update()
            .filter(pk__in=picked, miner_node_id__iexact=node_id)
            .order_by("disk_id")
        }
        rows = [locked[pk] for pk in picked if pk in locked]
        if not rows:
            return None
        targets = []
        for slot, disk in zip(DEDICATED_SLOTS, rows, strict=False):
            targets.append(
                {
                    "slot": slot,
                    "kind": DiskKind.DEDICATED.value,
                    "disk_pk": str(disk.pk),
                    "disk_id": disk.disk_id,
                    "size_bytes": int(disk.size_bytes or 0),
                    "size_gb": dedicated.size_class_gb(disk.size_bytes),
                    "origin": "released" if disk.freed_at is not None else "declared",
                    "profile": "d1",
                }
            )
        released = any(t["origin"] == "released" for t in targets)
        run = DiskProbeRun.objects.create(
            nonce=secrets.token_bytes(32),
            vm_id=_new_vm_id(owner),
            miner_node_id=node_id.lower(),
            chip_id=chip_id,
            owner=owner.user_id,
            trigger=ProbeTrigger.RELEASED if released else ProbeTrigger.DECLARED,
            state=ProbeRunState.SCHEDULED,
            flavor=str(settings.VALI_DISK_PROBE_FLAVOR),
            os_pool_id=os_pool_id,
            start_delay_s=start_delay_s(),
            targets=targets,
            scheduled_at=now,
        )
        for disk, target in zip(rows, targets, strict=True):
            moved = DedicatedDisk.objects.filter(
                pk=disk.pk, state=DedicatedDiskState.PENDING_PROBE, assigned_vm__isnull=True
            ).update(state=DedicatedDiskState.PROBING, last_probe=run, updated_at=now)
            if moved != 1:  # pragma: no cover — the row is locked
                raise RuntimeError(f"disk {disk.disk_id} moved under its lock")
            dedicated.audit_transition(
                disk,
                before=DedicatedDiskState.PENDING_PROBE,
                after=DedicatedDiskState.PROBING,
                reason="probe-selected",
                detail={"run_id": run.run_id.hex, "slot": target["slot"]},
            )
    return run


def schedule(*, now: datetime, report: TickReport) -> None:
    """Launch dedicated-disk probe VMs (see the module docstring). Queued
    dedicated runs (a transient launch failure) are retried first."""
    from . import probe

    if not probe_owners():
        report.dedicated_skipped["no-probe-owner"] += 1
        return
    if not image_ready():
        report.dedicated_skipped["image-not-ready"] += 1
        return
    allowed = allowed_miners()
    if not allowed:
        report.dedicated_skipped["no-miner-allowed"] += 1
        return
    g = probe._gates(str(settings.VALI_DISK_PROBE_FLAVOR))
    open_runs = probe._open_runs()
    holding = {r.miner_node_id.lower() for r in open_runs if r.state != ProbeRunState.SCHEDULED}
    active = len([r for r in open_runs if r.state != ProbeRunState.SCHEDULED])
    cap = max(0, int(settings.VALI_DISK_PROBE_MAX_CONCURRENT))

    def node_skip(nid: str) -> str:
        if not miner_allowed(nid, allowed):
            return "not-allowed"
        if nid in holding:
            return "busy"
        if active >= cap:
            return "concurrency"
        skip = probe._node_skip(g, nid)
        if skip:
            return skip
        if nid not in dedicated.capable_node_ids([nid]):
            return "agent-without-extra-disks"
        return ""

    queued = sorted(
        (r for r in open_runs if r.state == ProbeRunState.SCHEDULED and is_dedicated_run(r)),
        key=lambda r: r.scheduled_at,
    )
    for run in queued:
        nid = run.miner_node_id.lower()
        skip = node_skip(nid)
        if skip:
            report.dedicated_skipped[skip] += 1
            continue
        holding.add(nid)
        if probe.launch(run, now=now):
            report.dedicated_launched += 1
            active += 1
        else:
            report.dedicated_refused += 1

    queued_nodes = {
        r.miner_node_id.lower() for r in open_runs if r.state == ProbeRunState.SCHEDULED
    }
    for nid, disks in sorted(candidates(now).items()):
        report.dedicated_due += len(disks)
        skip = "busy" if nid in queued_nodes else node_skip(nid)
        if skip:
            report.dedicated_skipped[skip] += 1
            continue
        os_pool = os_pool_for(nid)
        if os_pool is None:
            report.dedicated_skipped["no-os-pool"] += 1
            continue
        run = create_run(
            node_id=nid,
            chip_id=g.chip_by_node[nid],
            disks=isolate_suspects(disks),
            os_pool_id=os_pool,
            now=now,
        )
        if run is None:
            continue
        holding.add(nid)
        if probe.launch(run, now=now):
            report.dedicated_launched += 1
            active += 1
        else:
            report.dedicated_refused += 1


# ── verdict → state ──────────────────────────────────────────────────


def verdict_for(disk: DedicatedDisk, run: DiskProbeRun | None) -> tuple[str, str, dict[str, Any]]:
    """`(new state, reason, fields)` for `disk` once `run` is closed. Pure
    (reads the run's stored grade). See the module docstring."""
    if run is None or not run.result_digest:
        why = probe_failure(run)
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:{why}", {}
    entry = next(
        (t for t in _dedicated_targets(run) if str(t.get("disk_pk")) == str(disk.pk)), None
    )
    if entry is None or entry.get("disk_id") != disk.disk_id:
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:target-missing", {}
    error = str(entry.get("error") or "")
    detail = str(entry.get("verdict_detail") or "")
    tier = str(entry.get("classified_tier") or "")
    probed = {"probed_at": run.result_at, "last_probe": run}
    unfit = {**probed, "verified_tier": DiskTier.UNFIT}
    # An I/O error is a fact about the disk, whatever else the result says.
    if error in IO_ERROR_CODES or detail in IO_ERROR_CODES:
        return DedicatedDiskState.FAILED, IO_ERROR, unfit
    if (run.result_meta or {}).get("extra_slots"):
        # The result carried slots the run never asked: grade nothing else.
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:{_TARGETS_MISMATCH}", {}
    if error in UNFIT_CODES:
        return DedicatedDiskState.UNFIT, TOO_SMALL, unfit
    if error or detail or entry.get("profile") != "d1":
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:{detail or error or 'ungraded'}", {}
    if tier == DiskTier.UNFIT:
        return DedicatedDiskState.UNFIT, BELOW_FLOOR, {**probed, "verified_tier": tier}
    if tier not in SELLABLE_TIERS:
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:ungraded", {}
    # Sold at the size the guest measured (`size_mib`, guest release 7),
    # never at the miner's figure; never below the size class the run
    # measured on the probe VM's cmdline.
    measured_mib = (entry.get("metrics") or {}).get("size_mib")
    if isinstance(measured_mib, bool) or not isinstance(measured_mib, int) or measured_mib <= 0:
        return DedicatedDiskState.PENDING_PROBE, f"{NO_VERDICT}:size-unmeasured", {}
    measured = measured_mib * MIB
    if measured < int(entry.get("size_gb") or 0) * dedicated.GIB:
        return DedicatedDiskState.UNFIT, SIZE_MISMATCH, unfit
    return (
        DedicatedDiskState.FREE,
        PASS,
        {
            **probed,
            "verified_tier": capped(tier, disk.declared_class),
            "verified_size_bytes": measured,
        },
    )


def _classified(disk: DedicatedDisk, run: DiskProbeRun) -> str:
    """The d1 grade the run's target gave `disk`, before the declared cap."""
    entry = next((t for t in _dedicated_targets(run) if str(t.get("disk_pk")) == str(disk.pk)), {})
    return str(entry.get("classified_tier") or "")


def probe_failure(run: DiskProbeRun | None) -> str:
    if run is None:
        return "run-gone"
    from .probe import failure_class

    return failure_class(run.failure_reason) or str(run.state)


def settle(*, now: datetime, report: TickReport) -> None:
    """Apply every closed run's verdict to the disks it held (`probing`
    disks whose `last_probe` is closed), each under a compare-and-set. A run
    still open keeps its disks `probing`."""
    for disk in DedicatedDisk.objects.filter(state=DedicatedDiskState.PROBING).select_related(
        "last_probe"
    ):
        run = disk.last_probe
        if run is not None and run.torn_down_at is None and run.state != ProbeRunState.TORN_DOWN:
            continue
        state, reason, fields = verdict_for(disk, run)
        if state == DedicatedDiskState.PENDING_PROBE:
            failures = disk.probe_failures + 1
            fields = {"probe_failures": failures, "probe_retry_at": now + backoff(failures)}
        else:
            fields = {**fields, "probe_failures": 0, "probe_retry_at": None}
        # The probe VM's hold is over: the agent wipes what it held, so any
        # report from now on is post-wipe (`reconcile_signatures`).
        fields.update(state=state, freed_at=now, updated_at=now)
        current = Q(pk=disk.pk, state=DedicatedDiskState.PROBING)
        current &= Q(last_probe=run) if run is not None else Q(last_probe__isnull=True)
        # The cap was read with the row: a declared class changed meanwhile
        # leaves the disk probing for the next pass (never sold above it).
        current &= (
            Q(declared_class=disk.declared_class)
            if disk.declared_class is not None
            else Q(declared_class__isnull=True)
        )
        with transaction.atomic():
            if not DedicatedDisk.objects.filter(current).update(**fields):
                continue
            detail: dict[str, Any] = {"run_id": run.run_id.hex if run else ""}
            if "verified_tier" in fields:
                detail["verified_tier"] = str(fields["verified_tier"])
            if reason == PASS and run is not None:
                detail["classified_tier"] = _classified(disk, run)
                detail["declared_class"] = disk.declared_class or ""
            if state == DedicatedDiskState.PENDING_PROBE:
                detail["probe_failures"] = fields["probe_failures"]
            dedicated.audit_transition(
                disk, before=DedicatedDiskState.PROBING, after=state, reason=reason, detail=detail
            )
        report.dedicated_settled[reason.split(":", 1)[0]] += 1
        level = logging.WARNING if state in (DedicatedDiskState.FAILED,) else logging.INFO
        log.log(
            level,
            "dedicated probe: disk %s on node %s probing → %s (%s)",
            disk.disk_id,
            disk.miner_node_id[:12],
            state,
            reason,
        )


def probing_exists() -> bool:
    return DedicatedDisk.objects.filter(state=DedicatedDiskState.PROBING).exists()


# ── a signature where a wiped disk was expected ──────────────────────


def _after_wipe() -> Q:
    """A disk a VM held before (`freed_at`), reported with an on-disk
    signature in a report newer than that release."""
    return Q(
        freed_at__isnull=False,
        reported_error=SIGNATURE_ERROR,
        reported_at__gt=F("freed_at"),
    )


def _signed_while_free() -> Q:
    """A `free` disk (vali holds it clean and on sale) reported with an
    on-disk signature after its last hold, if it had one."""
    return Q(state=DedicatedDiskState.FREE, reported_error=SIGNATURE_ERROR) & (
        Q(freed_at__isnull=True) | Q(reported_at__gt=F("freed_at"))
    )


def _reported_held() -> Q:
    """A `free` disk the agent reports held by some VM ([`_held_elsewhere`]
    decides whose)."""
    return Q(state=DedicatedDiskState.FREE, reported_state="assigned") & ~Q(reported_vm_id="")


def _held_elsewhere(disk: DedicatedDisk) -> bool:
    """Held by a VM vali never gave it to: any VM but its last probe VM
    (whose hold a report still in flight may show)."""
    last = disk.last_probe
    return bool(disk.reported_vm_id) and (last is None or disk.reported_vm_id != last.vm_id)


def reconcile_signatures(node_id: str, now: datetime) -> int:
    """On every `v7` report of `node_id` (whichever switch is on: it only
    ever takes a disk OFF sale): → `released`, logged as an error and
    audited, for

    - a `free` or `pending_probe` disk reported with an on-disk signature
      after its wipe (`signature-after-wipe`), and a `free` one reported
      signed at all since its last hold;
    - a `free` disk the agent reports held by a VM vali never gave it to
      (`held-elsewhere`).

    `released` needs a clean report newer than `freed_at`, then a new probe,
    before anyone buys it again. Returns how many moved."""
    moved = 0
    rows = DedicatedDisk.objects.filter(
        _after_wipe() & Q(state__in=(DedicatedDiskState.FREE, DedicatedDiskState.PENDING_PROBE))
        | _signed_while_free()
        | _reported_held(),
        miner_node_id=node_id,
        assigned_vm__isnull=True,
    ).select_related("last_probe")
    for disk in rows:
        signed = disk.reported_error == SIGNATURE_ERROR
        if not signed and not _held_elsewhere(disk):
            continue
        reason = SIGNATURE_AFTER_WIPE if signed else HELD_ELSEWHERE
        if not DedicatedDisk.objects.filter(
            pk=disk.pk, state=disk.state, assigned_vm__isnull=True
        ).update(
            state=DedicatedDiskState.RELEASED,
            freed_at=disk.freed_at or now,
            updated_at=now,
        ):
            continue
        moved += 1
        dedicated.audit_transition(
            disk,
            before=disk.state,
            after=DedicatedDiskState.RELEASED,
            reason=reason,
            detail={} if signed else {"reported_vm_id": disk.reported_vm_id},
        )
        log.error(
            "dedicated disk %s on node %s: %s → released (%s; not for sale until the "
            "agent reports it clean and a probe passes)",
            disk.disk_id,
            node_id[:12],
            disk.state,
            "an on-disk signature after its wipe" if signed else "held by a VM vali never gave it",
        )
    return moved


# ── metrics (pushed by `vali_disk_probe` while the switch is on) ─────

M_ENABLED = "hippius_dedicated_probe_enabled"
M_TICK = "hippius_dedicated_probe_tick"
M_SKIPPED = "hippius_dedicated_probe_skipped"
M_DUE = "hippius_dedicated_probe_due"
M_DISKS = "hippius_dedicated_disks"
M_FAILURES = "hippius_dedicated_disk_probe_failures_max"
M_SIGNATURE = "hippius_dedicated_disk_signature_after_wipe"
M_VERDICTS_7D = "hippius_dedicated_probe_verdicts_7d"

_SKIP_REASONS = (
    "no-probe-owner",
    "image-not-ready",
    "no-miner-allowed",
    "not-allowed",
    "busy",
    "concurrency",
    "gated",
    "no-chip-id",
    "capacity",
    "boot-cap",
    "agent-without-extra-disks",
    "no-os-pool",
)
_OUTCOMES = (
    PASS,
    BELOW_FLOOR,
    TOO_SMALL,
    SIZE_MISMATCH,
    IO_ERROR,
    NO_VERDICT,
    SIGNATURE_AFTER_WIPE,
    HELD_ELSEWHERE,
)
_STATES = tuple(s.value for s in DedicatedDiskState)


def report_metrics(ms: metrics.MetricSet, report: TickReport, *, now: datetime) -> None:
    """Add the dedicated-disk gauges of one tick to `ms`. Per-node series
    cover every node with a dedicated disk not retired."""
    from apps.scheduler.models import MinerCapacityAudit

    ms.gauge(M_ENABLED, 1 if report.dedicated_enabled else 0, help_text="1 while R3 runs.")
    ms.gauge(M_DUE, report.dedicated_due, help_text="Dedicated disks a probe could take now.")
    for what, n in (
        ("launched", report.dedicated_launched),
        ("refused", report.dedicated_refused),
        *((f"settled:{o}", report.dedicated_settled.get(o, 0)) for o in _OUTCOMES),
    ):
        ms.gauge(M_TICK, n, help_text="What the last tick did for dedicated disks.", action=what)
    for reason in _SKIP_REASONS:
        ms.gauge(
            M_SKIPPED,
            report.dedicated_skipped.get(reason, 0),
            help_text="Nodes with probeable dedicated disks skipped at the last tick, by reason.",
            reason=reason,
        )
    rows = DedicatedDisk.objects.exclude(state=DedicatedDiskState.RETIRED)
    by_state: Counter[tuple[str, str]] = Counter(
        (n.lower(), s) for n, s in rows.values_list("miner_node_id", "state")
    )
    nodes = sorted({n for n, _ in by_state})
    for node in nodes:
        for state in _STATES:
            ms.gauge(
                M_DISKS,
                by_state.get((node, state), 0),
                help_text="Dedicated disks per node, by vali state.",
                node=node,
                state=state,
            )
    worst = {
        n.lower(): m or 0
        for n, m in rows.filter(state=DedicatedDiskState.PENDING_PROBE)
        .values_list("miner_node_id")
        .annotate(m=Max("probe_failures"))
        .order_by()
    }
    flagged: Counter[str] = Counter(
        n.lower()
        for n in rows.filter(_after_wipe(), state=DedicatedDiskState.RELEASED).values_list(
            "miner_node_id", flat=True
        )
    )
    for node in nodes:
        ms.gauge(
            M_FAILURES,
            worst.get(node, 0),
            help_text="The most probe attempts in a row without a verdict among the node's "
            "pending_probe disks.",
            node=node,
        )
        ms.gauge(
            M_SIGNATURE,
            flagged.get(node, 0),
            help_text="Released disks the agent reports with an on-disk signature after "
            "their wipe (never for sale).",
            node=node,
        )
    week = now - timedelta(days=7)
    verdicts: Counter[str] = Counter(
        reason.split(":", 1)[0]
        for reason in MinerCapacityAudit.objects.filter(
            Q(reason__in=_OUTCOMES) | Q(reason__startswith=f"{NO_VERDICT}:"),
            actor=dedicated.AUDIT_ACTOR,
            field=dedicated.AUDIT_FIELD,
            created_at__gte=week,
        ).values_list("reason", flat=True)
    )
    for outcome in _OUTCOMES:
        ms.gauge(
            M_VERDICTS_7D,
            verdicts.get(outcome, 0),
            help_text="Dedicated-disk state changes of the last 7 days, by outcome.",
            outcome=outcome,
        )
