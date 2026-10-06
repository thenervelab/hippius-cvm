"""Zombie VMs — a guest that keeps talking after vali killed its data.

§24 destroys a VM's per-VM Transit key FIRST and force-stops its domain
SECOND. The erase is what makes the data unrecoverable, but it only stops
FUTURE unlocks: a running guest keeps its LUKS master key in memory for as
long as its domain lives, and killing the domain needs the miner. On
2026-09-08 three §24 jobs erased their keys, could not reach their miner, and
failed — and the three guests kept running (and sending receipts vali
accepted) for thirteen days.

A guest frame for a VM whose erase has happened is therefore PROOF that
some miner is still running a VM it was told to kill. This module:

- decides whether a VM is past the point of no return ([`kek_erased`]);
- records every such frame ([`observe`]) — the ingest paths then REFUSE
  it, so a zombie earns no billing and no uptime coverage;
- derives, from the FRESH observations only, which miners are
  zombie-quarantined ([`quarantined_node_ids`]): excluded from placement
  and from the epoch reward weight while the signal persists.

The quarantine is DERIVED, never stored: it lifts on its own when the
frames stop (staleness) or the destroy is confirmed, with no operator
action and without touching `MinerIdentity.status` (an operator's state).

Deliberately conservative about what counts:

- **Only after the erase, plus a grace.** A §24 VM is `decommissioning`
  from the first step, and its guest legitimately runs — and bills —
  through `draining` and `awaiting_eol_ack` until it acknowledges the
  stop. Its final telemetry drain can even land just AFTER the erase
  (the stop ack raced it). Frames before `erased_at + grace` are honest
  and keep today's behaviour; only later ones are zombie signals.
- **Never a migrating VM.** `migrating` is not a dead state: both legs of
  a §25 move are expected to talk.
- **Only authenticated, new frames.** Callers invoke [`observe`] after the
  frame's signature verified and after ruling out a byte-identical replay,
  so a relayed copy of an old frame cannot manufacture a zombie.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F, Max, Min
from django.utils import timezone

from .models import Vm, VmPowerState, VmState, ZombieObservation

log = logging.getLogger(__name__)

#: A job in one of these states has run its erase.
_ERASED_JOB_STATES = frozenset({"revoking_netbird", "done"})

#: Frame kinds that cannot be forged without the running guest (KBS-signed
#: live attestation) or without the miner's own key (boot progress). Only
#: these drive the quarantine; see `ZombieObservation.strong_last_seen_at`.
STRONG_KINDS = frozenset({"vm_live_attestation", "vm_progress"})

ATTRIBUTION_PEER = "peer"
ATTRIBUTION_DESTROY_TARGET = "destroy-target"


def window_seconds() -> int:
    """How long one zombie frame keeps its miner quarantined (and how long
    before the same VM alerts again)."""
    return max(60, int(getattr(settings, "VALI_ZOMBIE_WINDOW_S", 900)))


def confirm_grace_seconds() -> int:
    """Slack after a §24 job reports `done` during which a last in-flight
    frame is not held against the miner (relay lag)."""
    return max(0, int(getattr(settings, "VALI_ZOMBIE_CONFIRM_GRACE_S", 120)))


def erase_grace_seconds() -> int:
    """How long after a VM's erase its frames are still taken at face value.

    The guest's final telemetry drain can race the stop ack: vali may
    erase before the last already-produced receipt arrives. Those frames
    are honest (and billable), so a frame only counts as a zombie signal
    once this grace has passed since the erase.
    """
    return max(0, int(getattr(settings, "VALI_ZOMBIE_ERASE_GRACE_S", 300)))


def _decommissions(vm: Vm):
    from apps.orchestration.models import DecommissionJob

    return DecommissionJob.objects.filter(vm=vm)


def erased_at(vm: Vm) -> datetime | None:
    """When `vm`'s §24 crypto-erase happened, or `None` while it is live.

    History-wide, not "the latest job": a redriven §24 opens a new job
    whose own stamp is still empty while an earlier one already erased.

    - the earliest `kek_erased_at` of any of the VM's §24 jobs;
    - else the earliest job that moved PAST the erase step (jobs that
      erased before the stamp existed) — its phase start;
    - else, for a `destroyed` VM (tombstoned by a path that kept no
      stamp: a forced teardown, a launch that never ran), the tombstone's
      `power_state_at` when it reads `off`, else its `updated_at`.

    `active` and `migrating` VMs are live whatever their history.
    """
    return _erased_at_by_vm([vm]).get(vm.pk)


def _erased_at_by_vm(vms: list[Vm]) -> dict[Any, datetime | None]:
    """[`erased_at`] for many VMs at once, keyed by `Vm.pk` — two aggregate
    queries whatever the count, so a fleet-wide read stays flat during a
    zombie incident. The single-VM form is this with a list of one."""
    dead = [vm for vm in vms if vm.state in (VmState.DECOMMISSIONING, VmState.DESTROYED)]
    out: dict[Any, datetime | None] = {vm.pk: None for vm in vms}
    if not dead:
        return out
    from apps.orchestration.models import DecommissionJob

    jobs = DecommissionJob.objects.filter(vm__in=dead)
    stamped = dict(
        jobs.filter(kek_erased_at__isnull=False)
        .values("vm")
        .annotate(t=Min("kek_erased_at"))
        .values_list("vm", "t")
    )
    past = dict(
        jobs.filter(state__in=_ERASED_JOB_STATES)
        .values("vm")
        .annotate(t=Min("phase_started_at"))
        .values_list("vm", "t")
    )
    for vm in dead:
        at = stamped.get(vm.pk) or past.get(vm.pk)
        if at is None and vm.state == VmState.DESTROYED:
            # The tombstone's own stamp (set in its CAS, never moved after);
            # not `updated_at`, which any later write — a liveness frame from
            # the very zombie in question — pushes forward.
            # Only an `off` row's stamp is the tombstone's: a pod predating
            # `off` tombstones without it, leaving a stop/start date there.
            if vm.power_state == VmPowerState.OFF and vm.power_state_at:
                at = vm.power_state_at
            else:
                at = vm.updated_at
        out[vm.pk] = at
    return out


def erase_phrase(vm: Any) -> str:
    """How a refusal names what `vm` is past. An M2 (`key_mode=customer`)
    VM's §24 is NOT a crypto-erase — Hippius never held its disk key
    (`DecommissionJob.data_death=customer-erase-required`) — so it is never
    called one."""
    if getattr(vm, "key_mode", "") == "customer":
        return "§24 decommission"
    return "§24 crypto-erase"


def kek_erased(vm: Vm) -> bool:
    """Is `vm` past its §24 crypto-erase — i.e. must its guest be dead?"""
    return erased_at(vm) is not None


def is_zombie(vm: Vm, now: datetime | None = None) -> bool:
    """Does a frame from `vm` arriving `now` prove a zombie? True once the
    VM is erased AND the post-erase grace has passed."""
    at = erased_at(vm)
    if at is None:
        return False
    now = now or timezone.now()
    return now >= at + timedelta(seconds=erase_grace_seconds())


def erased_vm(vm_id: str, now: datetime | None = None) -> Vm | None:
    """The `Vm` for `vm_id` when a frame from it arriving `now` is a zombie
    signal, else `None`."""
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None or not is_zombie(vm, now):
        return None
    return vm


def _erase_host(vm: Vm) -> str:
    """Where vali had the VM when it erased it (`DecommissionJob.erase_host`)."""
    return (
        _decommissions(vm)
        .exclude(erase_host="")
        .order_by("-kek_erased_at")
        .values_list("erase_host", flat=True)
        .first()
        or ""
    )


def _resolve_miner(vm: Vm, relay_miner_id: str | None) -> tuple[str, str, str]:
    """`(miner_id, chain_node_id, attribution)` for a zombie frame.

    The relaying miner (the Edge-stamped mTLS peer) is the one actually
    carrying the frame, so it wins. Without it, vali's own records: the
    host the VM was on when it was erased — after a §25 move that is the
    DESTINATION — else where the destroy was aimed.
    """
    from apps.miners.models import MinerIdentity

    attribution = ATTRIBUTION_PEER
    miner_id = (relay_miner_id or "").strip()
    if not miner_id:
        attribution = ATTRIBUTION_DESTROY_TARGET
        miner_id = _erase_host(vm)
        if not miner_id:
            from apps.orchestration.effects import destroy_target_miner_id

            try:
                miner_id = destroy_target_miner_id(vm) or ""
            except Exception:  # noqa: BLE001 — attribution must never break ingest.
                log.warning(
                    "zombie: destroy target unresolvable for vm=%s", vm.vm_id, exc_info=True
                )
                miner_id = ""
    node_id = ""
    if miner_id:
        node_id = (
            MinerIdentity.objects.filter(miner_id=miner_id)
            .values_list("chain_node_id", flat=True)
            .first()
            or ""
        )
    return miner_id, node_id, attribution


def observe(
    vm: Vm,
    *,
    kind: str,
    relay_miner_id: str | None = None,
    now: datetime | None = None,
) -> None:
    """Record one authenticated, NEW frame from erased `vm`.

    Never raises: the caller refuses the frame whatever happens here, and
    losing an observation must not turn that refusal into a 500.
    """
    now = now or timezone.now()
    try:
        miner_id, node_id, attribution = _resolve_miner(vm, relay_miner_id)
        with transaction.atomic():
            obs = ZombieObservation.objects.select_for_update().filter(
                vm_id=vm.vm_id, miner_id=miner_id
            ).first()
            if obs is None:
                try:
                    with transaction.atomic():
                        obs = ZombieObservation.objects.create(
                            vm_id=vm.vm_id,
                            miner_id=miner_id,
                            miner_node_id=node_id,
                            attribution=attribution,
                            last_kind=kind,
                            count=1,
                            first_seen_at=now,
                            last_seen_at=now,
                            strong_last_seen_at=now if kind in STRONG_KINDS else None,
                        )
                except IntegrityError:
                    obs = ZombieObservation.objects.select_for_update().get(
                        vm_id=vm.vm_id, miner_id=miner_id
                    )
                    _bump(obs, kind=kind, node_id=node_id, attribution=attribution, now=now)
            else:
                _bump(obs, kind=kind, node_id=node_id, attribution=attribution, now=now)
            if obs.alerted_at is None or now - obs.alerted_at >= timedelta(
                seconds=window_seconds()
            ):
                ZombieObservation.objects.filter(pk=obs.pk).update(alerted_at=now)
                log.error(
                    "ZOMBIE VM: vm=%s state=%s is past its %s but a "
                    "%s frame for it arrived via miner=%s (node=%s, attribution=%s) — "
                    "the domain is still running; refusing the frame and "
                    "quarantining the miner while the signal persists",
                    vm.vm_id,
                    vm.state,
                    erase_phrase(vm),
                    kind,
                    miner_id or "?",
                    (node_id or "?")[:16],
                    attribution,
                )
    except Exception:  # noqa: BLE001 — see docstring.
        log.exception("zombie: failed to record an observation for vm=%s", vm.vm_id)


def _bump(
    obs: ZombieObservation, *, kind: str, node_id: str, attribution: str, now: datetime
) -> None:
    fields: dict = {
        "count": F("count") + 1,
        "last_seen_at": now,
        "last_kind": kind,
        "miner_node_id": node_id or obs.miner_node_id,
        "attribution": attribution,
    }
    if kind in STRONG_KINDS:
        fields["strong_last_seen_at"] = now
    ZombieObservation.objects.filter(pk=obs.pk).update(**fields)


def fresh_observations(
    now: datetime | None = None, *, strong_only: bool = False
) -> list[ZombieObservation]:
    """Observations still holding their miner: seen within the window, and
    not superseded by a CONFIRMED destroy.

    A destroy is confirmed when the VM's latest §24 job is `done` and the
    last frame predates that (plus a small relay-lag grace). A frame that
    arrives AFTER a `done` job is the stronger signal, not a weaker one:
    the miner acknowledged the destroy and the guest is still talking.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=window_seconds())
    grace = timedelta(seconds=confirm_grace_seconds())
    seen_field = "strong_last_seen_at" if strong_only else "last_seen_at"
    rows = list(ZombieObservation.objects.filter(**{f"{seen_field}__gte": cutoff}))
    if not rows:
        return []
    vms = {vm.vm_id: vm for vm in Vm.objects.filter(vm_id__in={r.vm_id for r in rows})}
    # Batched: a constant number of queries however many rows are fresh.
    erased = _erased_at_by_vm(list(vms.values()))
    from apps.orchestration.models import DecommissionJob

    done_by_vm = dict(
        DecommissionJob.objects.filter(vm__in=list(vms.values()), state="done")
        .values("vm")
        .annotate(t=Max("finished_at"))
        .values_list("vm", "t")
    )
    out: list[ZombieObservation] = []
    for row in rows:
        vm = vms.get(row.vm_id)
        if vm is None or erased.get(vm.pk) is None:
            # The row no longer describes a dead VM (e.g. a stale row for
            # a vm_id that is live again) — it holds nobody.
            continue
        done_at = done_by_vm.get(vm.pk)
        seen = getattr(row, seen_field)
        if done_at is not None and seen <= done_at + grace:
            continue
        out.append(row)
    return out


def quarantined_node_ids(now: datetime | None = None) -> frozenset[str]:
    """Chain node_ids currently zombie-quarantined — excluded from
    placement and from the epoch reward weight. Derived on every call, from
    UNFORGEABLE evidence only (`STRONG_KINDS`)."""
    return frozenset(
        row.miner_node_id.lower()
        for row in fresh_observations(now, strong_only=True)
        if row.miner_node_id
    )


def miner_is_quarantined(miner_id: str, now: datetime | None = None) -> bool:
    """Is the miner registered as `miner_id` zombie-quarantined?"""
    from apps.miners.models import MinerIdentity

    if not miner_id:
        return False
    node_id = (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )
    return bool(node_id) and node_id.lower() in quarantined_node_ids(now)
