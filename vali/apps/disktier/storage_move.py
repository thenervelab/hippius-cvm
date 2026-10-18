"""Live storage move (§19): a running VM's OS disk moves to another pool of
its host, with no downtime. vali's half; the agent's is
`lifecycle::storage_move` (the `move-vm-storage` order).

## Who does what

The agent copies (`virsh blockcopy`), pivots, re-defines the VM onto the
target and journals every step; it keeps the source copy until vali sends
`release`. vali admits the request, drives the move with `start` / `status`
/ `cancel` / `release` orders, and releases the source only once a served
receipt from the guest proves it still runs after the pivot.

    requested ─start─▶ moving ─(agent: redefined)─▶ verifying ─receipt─▶ releasing ─▶ done
        │                │                              │
        └──────(agent: aborted)──▶ aborted              └─ no receipt in VERIFY_TIMEOUT_S ─▶ failed

- `start` is idempotent on `move_id`, so a lost answer is re-sent. vali
  never gives up on a move the agent may have started: only the agent's
  own `aborted` / `failed` (or a refusal of the start) ends it before the
  pivot.
- On `redefined` the VM runs and boots from the target: the placement's OS
  disk row names the target pool from then on, and the VM's next backup is
  a full (the dirty bitmap stayed on the source).
- `failed` is for an operator: a verify timeout (the agent keeps the
  source; `vali_storage_move release` once the guest is checked), a pivot
  of unknown outcome, a journal the agent lost.

## Gate (all dark by default)

`VALI_STORAGE_MOVE_ENABLED`, the miner in `VALI_STORAGE_MOVE_MINERS`
(miner_id or node_id, `*` = all) and its agent at least
`VALI_STORAGE_MOVE_MIN_AGENT_VERSION` (empty = nobody). A request is
refused otherwise; `reconcile` does nothing while the flag is off.

## Interlocks

A move in flight counts in `orchestration.service._has_active_job`: no
migration, resize, restore, guest upgrade or backup starts on the VM. A
decommission does start: the agent's destroy aborts the copy and reclaims
both disks, and `reconcile` closes the move once the VM is no longer
active.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F, Max, Q
from django.db.models.functions import Least
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import order_dispatch
from apps.scheduler import usage
from apps.scheduler.models import Placement, PlacementStatus, ReceiptWatermark

from . import routing
from .models import (
    OS_SLOT,
    TERMINAL_MOVE_STATES,
    DiskKind,
    MinerStoragePool,
    PlacementDisk,
    StorageMoveState,
    VmStorageMove,
)
from .storage_config import agent_version, version_at_least
from .tiers import DiskTier

log = logging.getLogger("apps.disktier.storage_move")

KIND = "move-vm-storage"
#: One order's dispatch deadline (re-asks included).
DISPATCH_DEADLINE_S = 90
#: Clock skew allowed between vali and an agent judging a start's validity.
START_SKEW_MARGIN_S = 300
#: The agent's phases (`MovePhase`, kebab-case on the wire).
COPYING_PHASES = frozenset({"prepared", "copying", "pivoting", "pivoted"})
#: The agent's refusal codes of a move (`move_refusal_status`).
_AGENT_CODE_PREFIXES = ("move-", "vm-storage-move-")


class MoveRefused(Exception):
    """A request vali does not send: `code` is the closed reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ─── gate ────────────────────────────────────────────────────────────


def selected(miner: MinerIdentity) -> bool:
    """Whether the miner is in `VALI_STORAGE_MOVE_MINERS` (miner_id or
    node_id; `*` = all)."""
    allow = {m.strip() for m in settings.VALI_STORAGE_MOVE_MINERS if m.strip()}
    return "*" in allow or miner.miner_id in allow or (miner.chain_node_id or "") in allow


def gate(node_id: str) -> tuple[MinerIdentity | None, str]:
    """`(miner, "")` when the node may be sent a `move-vm-storage` order,
    else `(miner or None, why not)`."""
    if not settings.VALI_STORAGE_MOVE_ENABLED:
        return None, "storage-move-disabled"
    miner = MinerIdentity.objects.filter(chain_node_id=node_id).first()
    if miner is None:
        return None, "miner-unknown"
    if not selected(miner):
        return miner, "miner-not-selected"
    if not miner.netbird_ip:
        return miner, "miner-unreachable"
    minimum = str(settings.VALI_STORAGE_MOVE_MIN_AGENT_VERSION or "")
    if not version_at_least(agent_version(node_id), minimum):
        return miner, "agent-version-below-min"
    return miner, ""


def in_flight(vm: Vm) -> bool:
    """The VM has a move that is not over, on the miner it runs on. A move
    still followed on a host the VM left never holds it where it runs now."""
    moves = VmStorageMove.objects.filter(vm=vm, left_host_at__isnull=True).exclude(
        state__in=TERMINAL_MOVE_STATES
    )
    if vm.host:
        moves = moves.filter(Q(miner_id=vm.host) | Q(miner_node_id=vm.host))
    return moves.exists()


def left_host(move: VmStorageMove) -> bool | None:
    """The VM was bound on another node since the move was requested (a
    failover, a §25): what the move's host holds under the source path may
    no longer be what the move copied from — never release it then. `None`
    when vali cannot say (no bound placement: a drained one the sweep has
    not re-bound yet)."""
    # Only a placement that actually took the VM counts: bound on another
    # node since the request — still bound there or handed on (`migrated`:
    # the VM ran there, even if it is back now), or any bound row there
    # while the VM's host is no longer the move's miner. A failover attempt
    # that never landed (pending, failed, never bound) does not.
    elsewhere = Placement.objects.filter(vm=move.vm, bound_at__gt=move.created_at).exclude(
        miner_node_id=move.miner_node_id
    )
    if elsewhere.filter(
        status__in=[PlacementStatus.BOUND.value, PlacementStatus.MIGRATED.value]
    ).exists():
        return True
    if elsewhere.exists() and move.vm.host != move.miner_id:
        return True
    bound = _bound_placement(move.vm)
    if bound is None:
        return None
    return bound.miner_node_id != move.miner_node_id


# ─── request ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Requester:
    principal: str = "vali"
    family: str = ""
    user: str = ""


def _bound_placement(vm: Vm) -> Placement | None:
    return (
        Placement.objects.filter(vm=vm, status=PlacementStatus.BOUND)
        .order_by("-bound_at", "-decided_at")
        .first()
    )


def source_pool(placement: Placement) -> str:
    """The pool the placement's OS disk is on (no row = `default`)."""
    row = PlacementDisk.objects.filter(placement_id=placement.id, slot=OS_SLOT).first()
    return row.pool_id if row is not None and row.pool_id else routing.DEFAULT_POOL_ID


def os_disk_gb(placement: Placement) -> int:
    from apps.scheduler.service import placement_disk_gb

    return int(placement_disk_gb(placement.resource_class, placement.data_disk_gb))


def _check_target(node_id: str, pool_id: str, need_gb: int) -> None:
    """The target takes the disk: the same rules as a first launch's pool
    (`routing.choose_os_pool`), `default` included."""
    pool = MinerStoragePool.objects.filter(
        miner_node_id=node_id, pool_id=pool_id, retired_at__isnull=True
    ).first()
    if pool is None:
        raise MoveRefused("move-pool-unknown", f"the node reports no pool {pool_id!r}")
    if (
        not pool.os_disks
        or pool.reported_state != "active"
        or pool.reported_at is None
        or pool.reported_at < timezone.now() - routing.REPORT_MAX_AGE
    ):
        raise MoveRefused(
            "move-pool-not-active", f"pool {pool_id!r} is not an active, reported OS-disk pool"
        )
    if not routing.sold_as_os_disk_tier(pool):
        raise MoveRefused("move-pool-tier", f"pool {pool_id!r} is not of the OS disk tier")
    free = routing.free_gb(pool)
    if free is None or free < need_gb:
        raise MoveRefused(
            "move-pool-insufficient-space",
            f"pool {pool_id!r} has {free} GB free, the disk needs {need_gb} GB",
        )


#: A guest that served no receipt for this long is not moved.
RECEIPT_FRESH = timedelta(minutes=15)


def _receipting(vm: Vm) -> bool:
    """The guest served a receipt lately: the proof the move's verification
    waits for will come."""
    fresh = timezone.now() - RECEIPT_FRESH
    return ReceiptWatermark.objects.filter(
        vm_id=vm.vm_id,
        updated_at__gte=fresh,
        last_period_end__gte=int(fresh.timestamp()),
    ).exists()


def request_move(
    *,
    vm_id: str,
    target_pool: str,
    bandwidth_mib_s: int | None = None,
    requester: Requester | None = None,
) -> VmStorageMove:
    """Admit a move of `vm_id`'s OS disk to `target_pool` (sent by the next
    `reconcile`), or raise `MoveRefused`."""
    from apps.backup.models import ACTIVE_RUN_STATUSES, BackupRun
    from apps.orchestration.service import _has_active_job

    requester = requester or Requester()
    bandwidth = int(bandwidth_mib_s or settings.VALI_STORAGE_MOVE_BANDWIDTH_MIB_S)
    if not 10 <= bandwidth <= 1000:
        raise MoveRefused("move-bandwidth", "bandwidth_mib_s must be 10..1000")
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None:
        raise MoveRefused("move-vm-not-found", f"no VM {vm_id!r}")
    if vm.state != VmState.ACTIVE or vm.power_state != VmPowerState.RUNNING:
        raise MoveRefused("move-vm-not-running", "the VM is not active and running")
    placement = _bound_placement(vm)
    if placement is None:
        raise MoveRefused("move-vm-not-placed", "the VM has no bound placement")
    node_id = placement.miner_node_id
    miner, why = gate(node_id)
    if why:
        raise MoveRefused(why, f"no storage move on node {node_id[:12]}: {why}")
    assert miner is not None
    if not _receipting(vm):
        raise MoveRefused(
            "move-no-receipts",
            "the guest served no recent receipt, so its move could not be verified; "
            "after a boot, wait for the first periodic receipt (~5 min)",
        )
    source = source_pool(placement)
    if target_pool == source:
        raise MoveRefused("move-same-pool", f"the disk is already on {source!r}")
    _check_target(node_id, target_pool, os_disk_gb(placement))

    with transaction.atomic():
        locked = Vm.objects.select_for_update().get(pk=vm.pk)
        if _has_active_job(locked):
            raise MoveRefused("move-conflict-job", "the VM has a job in flight")
        if BackupRun.objects.filter(vm=locked, status__in=ACTIVE_RUN_STATUSES).exists():
            raise MoveRefused("move-conflict-backup", "the VM has a backup in flight")
        try:
            with transaction.atomic():
                move = VmStorageMove.objects.create(
                    vm=locked,
                    miner_node_id=node_id,
                    miner_id=miner.miner_id,
                    source_pool=source,
                    target_pool=target_pool,
                    bandwidth_mib_s=bandwidth,
                    requested_by_principal=requester.principal[:128],
                    requested_by_family=requester.family[:64],
                    requested_by_user=requester.user[:128],
                )
        except IntegrityError as exc:
            raise MoveRefused("move-in-progress", "the VM already has a move in flight") from exc
    log.info(
        "storage-move: vm=%s %s -> %s on %s requested by %s (move %s)",
        vm_id,
        source,
        target_pool,
        node_id[:12],
        requester.principal,
        move.move_id,
    )
    return move


def cancel(move: VmStorageMove) -> VmStorageMove:
    """Ask the agent to abort the copy. Refused by the agent once the
    pivot started (`move-past-pivot`): the move then carries on."""
    if move.state in TERMINAL_MOVE_STATES:
        return move
    VmStorageMove.objects.filter(pk=move.pk, cancel_requested_at__isnull=True).update(
        cancel_requested_at=timezone.now()
    )
    move.refresh_from_db()
    return move


def abandon(move: VmStorageMove, *, by: str) -> VmStorageMove:
    """An operator takes a move vali cannot finish (a VM stuck fenced, a
    host that never answers) out of vali's hands: nothing is sent, the move
    ends `failed:operator-abandoned` (the next backup is a full), and the
    agent's journal is the operator's to settle on the host."""
    if move.state in TERMINAL_MOVE_STATES:
        raise MoveRefused("move-not-in-flight", "the move is over")
    _finish(move, StorageMoveState.FAILED, "operator-abandoned", now=timezone.now(), error=by)
    log.warning("storage-move: vm=%s move %s abandoned by %s", move.vm.vm_id, move.move_id, by)
    return move


#: The agent stopped mid-pivot and holds the VM: which copy has the last
#: writes is for an operator (docs/operator/storage-move-runbook.md).
PIVOT_UNKNOWN = "move-pivot-unknown"


def resolve_pivot_unknown(move: VmStorageMove, *, on: str, by: str) -> VmStorageMove:
    """Record an operator's resolution of a `move-pivot-unknown` on the
    host (the runbook): the VM boots from the `source` or the `target`
    copy now. On `target` the placement's OS disk row names the target."""
    if on not in ("source", "target"):
        raise MoveRefused("move-resolve-side", "on is source or target")
    if not (move.state == StorageMoveState.FAILED and move.code == PIVOT_UNKNOWN):
        raise MoveRefused("move-not-pivot-unknown", "only a move-pivot-unknown is resolved")
    if on == "target":
        placement = _bound_placement(move.vm)
        if placement is None or placement.miner_node_id != move.miner_node_id:
            raise MoveRefused(
                "move-vm-not-placed", "no bound placement on the move's host to record it on"
            )
    with transaction.atomic():
        updated = VmStorageMove.objects.filter(
            pk=move.pk, state=StorageMoveState.FAILED, code=PIVOT_UNKNOWN
        ).update(code=f"pivot-resolved-{on}", last_error=f"resolved by {by}"[:256])
        if not updated:
            raise MoveRefused("move-not-pivot-unknown", "the move changed meanwhile")
        if on == "target":
            _record_on_target(move)
    log.warning(
        "storage-move: vm=%s move %s pivot-unknown resolved on the %s by %s",
        move.vm.vm_id,
        move.move_id,
        on,
        by,
    )
    move.refresh_from_db()
    return move


#: The failures an operator may hand back to a release, once the guest is
#: checked on the target (the agent re-checks nothing names the source).
RELEASABLE_BY_HAND = ("verify-timeout", "release-refused", "agent-unanswered")


def force_release(move: VmStorageMove, *, by: str) -> VmStorageMove:
    """An operator checked the guest on the target after a verify timeout:
    release the source."""
    if not (move.state == StorageMoveState.FAILED and move.code in RELEASABLE_BY_HAND):
        raise MoveRefused(
            "move-not-releasable",
            f"only a {'/'.join(RELEASABLE_BY_HAND)} move is released by hand",
        )
    if left_host(move) is not False:
        raise MoveRefused("move-vm-left-host", "the VM is not bound on the move's host")
    try:
        with transaction.atomic():
            updated = VmStorageMove.objects.filter(
                pk=move.pk, state=StorageMoveState.FAILED, code=move.code
            ).update(
                state=StorageMoveState.RELEASING,
                code="",
                finished_at=None,
                last_error="",
                failures=0,
                last_polled_at=None,
            )
    except IntegrityError as exc:
        raise MoveRefused("move-in-progress", "the VM has another move in flight") from exc
    if not updated:
        raise MoveRefused("move-not-releasable", "the move changed meanwhile")
    log.info("storage-move: vm=%s move %s release forced by %s", move.vm.vm_id, move.move_id, by)
    move.refresh_from_db()
    return move


# ─── dispatch ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Answer:
    """The agent's answer to one order: its status JSON, or a refusal."""

    status: int
    #: The agent's move status (2xx).
    body: dict[str, Any] | None = None
    #: The refusal code (non-2xx), or the raw classifier.
    code: str = ""
    #: No answer from the agent.
    error: str = ""

    @property
    def agent_refusal(self) -> bool:
        """A 4xx of the agent's own (a 5xx may follow a half-done step)."""
        return (
            self.body is None
            and not self.error
            and 400 <= self.status < 500
            and self.code.startswith(_AGENT_CODE_PREFIXES)
        )


def _order(move: VmStorageMove, action: str, *, now: datetime) -> Answer:
    ttl = max(30, int(settings.VALI_STORAGE_MOVE_ORDER_TTL_S))
    start = action == "start"
    payload = order_dispatch.build_move_vm_storage_payload(
        vm_id=move.vm.vm_id,
        move_id=move.move_id,
        action=action,
        not_after_unix=int(now.timestamp()) + ttl,
        target_pool=move.target_pool if start else None,
        expected_source_pool=move.source_pool if start else None,
        bandwidth_mib_s=move.bandwidth_mib_s if start else None,
    )
    order_id = f"mv-{move.vm.vm_id}-{action}-{uuid.uuid4().hex[:12]}"[:128]
    miner = MinerIdentity.objects.filter(miner_id=move.miner_id).first()
    if miner is None or not miner.netbird_ip:
        return Answer(status=0, error="miner-unreachable")
    try:
        result = order_dispatch.dispatch_order_settled(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=order_id,
            kind=KIND,
            payload_json=json.dumps(payload, sort_keys=True).encode(),
            attempts=2,
            retry_after_s=5.0,
            deadline_s=DISPATCH_DEADLINE_S,
            timeout_s=25.0,
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        return Answer(status=0, error=f"unreachable: {exc}"[:160])
    except order_dispatch.OrderDispatchError as exc:
        return Answer(status=0, error=f"dispatch: {exc}"[:160])
    if not result.ok:
        return Answer(status=result.status, code=result.classifier.strip()[:64])
    try:
        body = json.loads(result.classifier)
    except (json.JSONDecodeError, ValueError):
        body = None
    if not isinstance(body, dict) or body.get("move_id") != move.move_id:
        return Answer(status=result.status, error=f"bad-status: {result.classifier[:120]!r}")
    return Answer(status=result.status, body=body)


# ─── reconcile ───────────────────────────────────────────────────────


@dataclass
class ReconcileReport:
    stepped: int = 0
    finished: int = 0
    errors: list[str] = field(default_factory=list)


def reconcile(*, now: datetime | None = None) -> ReconcileReport:
    """Drive every move in flight one step (orchestration tick).

    `VALI_STORAGE_MOVE_ENABLED` off is a stop for NEW moves: requests are
    refused and a move whose start never went out is dropped, but a move
    the agent may be running is still driven to its end — never left
    holding its VM's backups, migrations and resizes."""
    report = ReconcileReport()
    if not settings.VALI_STORAGE_MOVE_ENABLED:
        for move in VmStorageMove.objects.filter(
            state=StorageMoveState.REQUESTED, start_sent_at__isnull=True
        ).select_related("vm"):
            _finish(
                move, StorageMoveState.ABORTED, "storage-move-disabled", now=now or timezone.now()
            )
            report.finished += 1
    deadline = time.monotonic() + float(settings.VALI_STORAGE_MOVE_TICK_BUDGET_S)
    moves = (
        VmStorageMove.objects.exclude(state__in=TERMINAL_MOVE_STATES)
        .select_related("vm")
        .order_by("created_at")
    )
    for move in moves:
        if time.monotonic() > deadline:
            break
        try:
            step(move, now=now or timezone.now())
        except Exception as exc:  # noqa: BLE001 — one move must not stop the others.
            log.exception("storage-move: move %s step failed", move.move_id)
            report.errors.append(f"{move.move_id}: {exc}"[:200])
            continue
        report.stepped += 1
        if move.state in TERMINAL_MOVE_STATES:
            report.finished += 1
    _push_metrics(now=now or timezone.now())
    return report


def step(move: VmStorageMove, *, now: datetime) -> None:
    """One step of one move (module doc)."""
    if move.vm.state in GONE_VM_STATES:
        # §24 took the VM: the agent's destroy aborted the copy.
        _finish(move, StorageMoveState.ABORTED, "vm-not-active", now=now)
        return
    if move.vm.state != VmState.ACTIVE:
        # A failover fences it: it may revert to this host. Decided once
        # the VM is active again.
        return
    # Once the VM left, the move stays "left" — a later return to this host
    # (a §25 back) must not let a stale move book its target on the new
    # placement.
    left = True if move.left_host_at is not None else left_host(move)
    if left and move.left_host_at is None:
        VmStorageMove.objects.filter(pk=move.pk).update(left_host_at=now)
        move.left_host_at = now
    if left is None and move.state != StorageMoveState.MOVING:
        # No bound placement (drained, not re-bound yet): nothing starts or
        # is released until vali knows the VM is still there. A copy in
        # flight is followed.
        return
    if left:
        # A failover really took the VM (bound elsewhere, hosted there). It
        # no longer holds the VM (`in_flight`). Never sent: dropped. Past the
        # redefine: failed (the next backup is a full); vali releases nothing
        # on the old host — an operator decides, and the agent never deletes
        # a disk the VM's records name. Before it: the old host's copy is
        # still followed (`status` only, never a new start), so a pivot it
        # completes is still booked (full backup) and its end recorded.
        if move.state == StorageMoveState.REQUESTED and move.start_sent_at is None:
            _finish(move, StorageMoveState.ABORTED, "vm-left-host", now=now)
            return
        if move.state not in (StorageMoveState.REQUESTED, StorageMoveState.MOVING):
            _finish(move, StorageMoveState.FAILED, "vm-left-host", now=now)
            return
        if move.failures >= GIVE_UP_FAILURES:
            _finish(move, StorageMoveState.FAILED, "vm-left-host", now=now, error=move.last_error)
            return
        if not _due(move, now=now):
            return
        answer = _order(move, "status", now=now)
        if (
            answer.code == "move-not-found"
            and move.state == StorageMoveState.REQUESTED
            and now > (move.start_sent_at or move.created_at) + _start_validity()
        ):
            # The start never landed and no longer can.
            _finish(move, StorageMoveState.ABORTED, "vm-left-host", now=now)
            return
        _apply(move, answer, now=now)
        return
    if move.failures >= GIVE_UP_FAILURES:
        # The agent's own interlock still holds the VM until it redefined.
        _finish(move, StorageMoveState.FAILED, "agent-unanswered", now=now, error=move.last_error)
        return
    if move.state == StorageMoveState.VERIFYING:
        _verify(move, now=now)
        return
    if not _due(move, now=now):
        return
    if move.state == StorageMoveState.RELEASING:
        _apply(move, _order(move, "release", now=now), now=now)
        return
    # requested / moving
    if move.cancel_requested_at is not None:
        _apply(move, _order(move, "cancel", now=now), now=now, cancelling=True)
        return
    if move.state == StorageMoveState.REQUESTED and not settings.VALI_STORAGE_MOVE_ENABLED:
        # Switched off after a start whose answer never came: no start goes
        # out again. The agent's journal says whether it began; none once
        # the start's validity is over ⇒ it never will.
        answer = _order(move, "status", now=now)
        if answer.code == "move-not-found":
            sent = move.start_sent_at or move.created_at
            if now > sent + _start_validity():
                _finish(move, StorageMoveState.ABORTED, "storage-move-disabled", now=now)
            else:
                VmStorageMove.objects.filter(pk=move.pk).update(last_polled_at=now)
            return
        _apply(move, answer, now=now)
        return
    if move.state == StorageMoveState.REQUESTED:
        # Recorded before it goes: a start that reached the agent is never
        # taken for one that did not (`reconcile` with the flag off).
        VmStorageMove.objects.filter(pk=move.pk).update(last_polled_at=now, start_sent_at=now)
        answer = _order(move, "start", now=now)
        if answer.agent_refusal and move.failures:
            # An earlier start may have landed with its answer lost (and the
            # agent checks some conflicts before it looks the move up): its
            # journal says what is true.
            status = _order(move, "status", now=now)
            if status.body is not None or status.code != "move-not-found":
                answer = status
        _apply(move, answer, now=now, starting=True)
        return
    _apply(move, _order(move, "status", now=now), now=now)


def _start_validity() -> timedelta:
    """How long after it went out a start may still begin a copy: the agent
    refuses one past its `not_after_unix` (`move-order-expired`); on top,
    the dispatch's own deadline and a clock-skew margin."""
    return timedelta(
        seconds=max(30, int(settings.VALI_STORAGE_MOVE_ORDER_TTL_S))
        + DISPATCH_DEADLINE_S
        + START_SKEW_MARGIN_S
    )


#: Cap of the retry backoff, as a power of two of the poll period.
_MAX_BACKOFF_EXP = 5
#: Orders in a row without an answer before the move is left to an
#: operator (~8 h at the default poll period).
GIVE_UP_FAILURES = 36
#: A VM in these states is gone from its host for good.
GONE_VM_STATES = (VmState.DECOMMISSIONING, VmState.DESTROYED)


def _due(move: VmStorageMove, *, now: datetime) -> bool:
    """The first order and a new cancel go at once; then one order every
    `POLL_S`, backing off exponentially while the agent does not answer."""
    if move.last_polled_at is None:
        return True
    if move.cancel_requested_at is not None and move.cancel_requested_at > move.last_polled_at:
        return True
    period = int(settings.VALI_STORAGE_MOVE_POLL_S) * 2 ** min(move.failures, _MAX_BACKOFF_EXP)
    return now - move.last_polled_at >= timedelta(seconds=period)


def _apply(
    move: VmStorageMove,
    answer: Answer,
    *,
    now: datetime,
    starting: bool = False,
    cancelling: bool = False,
) -> None:
    mine = VmStorageMove.objects.filter(pk=move.pk, state=move.state)
    if answer.body is None:
        error = answer.error or f"refused: {answer.status} {answer.code}"
        if starting and answer.agent_refusal:
            # The agent refused the start before creating anything.
            _finish(move, StorageMoveState.ABORTED, answer.code, now=now, error=error)
        elif move.state == StorageMoveState.RELEASING and answer.code in (
            "move-release-in-use",
            "move-not-releasable",
        ):
            # The agent will not delete the source: for an operator, with
            # where the agent stands.
            status = _order(move, "status", now=now)
            phase = status.body.get("phase") if status.body else status.code or status.error
            error = f"{error}; agent phase: {phase}"
            _finish(move, StorageMoveState.FAILED, "release-refused", now=now, error=error)
        elif cancelling and answer.code == "move-past-pivot":
            # Too late to cancel: the move carries on.
            mine.update(cancel_requested_at=None, last_error=error[:256], last_polled_at=now)
        elif answer.code == "move-not-found" and not starting and move.state != "requested":
            # The agent has no journal of a move it started: a destroy, a
            # wiped state root. Which disk the VM is on is for an operator.
            _finish(move, StorageMoveState.FAILED, "agent-move-not-found", now=now, error=error)
        elif answer.code == "move-not-found" and cancelling:
            # A cancel before any start reached the agent.
            _finish(move, StorageMoveState.ABORTED, "move-aborted-operator", now=now, error=error)
        else:
            mine.update(
                last_error=error[:256],
                last_polled_at=now,
                failures=Least(F("failures") + 1, GIVE_UP_FAILURES),
            )
        move.refresh_from_db()
        return

    body = answer.body
    phase = str(body.get("phase") or "")
    code = str(body.get("code") or "")[:48]
    progress = {
        "agent_phase": phase[:16],
        "bytes_total": _int(body.get("bytes_total")),
        "bytes_done": _int(body.get("bytes_done")),
        "last_polled_at": now,
        "last_error": "",
        "failures": 0,
    }
    if phase in COPYING_PHASES:
        mine.update(state=StorageMoveState.MOVING, **progress)
    elif phase == "redefined":
        if move.state in (StorageMoveState.REQUESTED, StorageMoveState.MOVING):
            _redefined(move, now=now, progress=progress)
        else:
            mine.update(**progress)
    elif phase == "done" and code == "move-superseded":
        # The VM went back onto the source path before any release: the move
        # is moot. A redefine already booked: put the source back, or leave
        # it to an operator when that cannot be done.
        if move.redefined_at is None or _record_os_pool(move, move.source_pool):
            _finish(move, StorageMoveState.ABORTED, code, now=now, extra=progress)
        else:
            _finish(move, StorageMoveState.FAILED, code, now=now, extra=progress)
    elif phase == "done":
        if move.redefined_at is None:
            _redefined(move, now=now, progress=progress)
            move.refresh_from_db()
        _record_on_target(move)
        _finish(move, StorageMoveState.DONE, "", now=now, extra=progress)
    elif phase == "aborted":
        _finish(move, StorageMoveState.ABORTED, code or "move-aborted", now=now, extra=progress)
    elif phase == "failed":
        _finish(move, StorageMoveState.FAILED, code or "move-failed", now=now, extra=progress)
    else:
        mine.update(last_error=f"unknown phase {phase[:32]!r}", last_polled_at=now)
    move.refresh_from_db()


def _int(value: Any) -> int:
    return int(value) if isinstance(value, int) and 0 <= value < 2**63 else 0


def _redefined(move: VmStorageMove, *, now: datetime, progress: dict[str, Any]) -> None:
    """The VM runs and boots from the target: the placement's OS disk is
    there now, and the next backup is a full."""
    from apps.backup.models import BackupPolicy

    with transaction.atomic():
        updated = VmStorageMove.objects.filter(pk=move.pk, redefined_at__isnull=True).update(
            state=StorageMoveState.VERIFYING, redefined_at=now, **progress
        )
        if not updated:
            return
        _record_on_target(move)
        BackupPolicy.objects.filter(vm=move.vm).update(full_required=True)
    log.info(
        "storage-move: vm=%s redefined on %s (move %s), verifying",
        move.vm.vm_id,
        move.target_pool,
        move.move_id,
    )


def _record_on_target(move: VmStorageMove) -> bool:
    """The bound placement's OS disk row names the target pool
    (idempotent; re-asserted before the release, as a rebind may have
    carried an older row)."""
    return _record_os_pool(move, move.target_pool)


def _record_os_pool(move: VmStorageMove, pool_id: str) -> bool:
    """The OS disk row of the VM's bound placement on the move's host names
    `pool_id`. False (nothing written) when the VM left that host or has no
    bound placement there."""
    if move.left_host_at is not None:
        # The VM left the move's host: whatever placement it has now is not
        # this move's to change.
        return False
    placement = _bound_placement(move.vm)
    if placement is None or placement.miner_node_id != move.miner_node_id:
        log.warning("storage-move: vm=%s no bound placement to record the move on", move.vm.vm_id)
        return False
    PlacementDisk.objects.update_or_create(
        placement_id=placement.id,
        slot=OS_SLOT,
        defaults={"kind": DiskKind.POOL, "pool_id": pool_id},
        create_defaults={
            "kind": DiskKind.POOL,
            "pool_id": pool_id,
            "size_gb": os_disk_gb(placement),
            "required_tier": DiskTier.NVME,
        },
    )
    return True


def _verify(move: VmStorageMove, *, now: datetime) -> None:
    """A served receipt whose window ends after the redefine: the guest
    runs on the target. Then release the source."""
    assert move.redefined_at is not None
    # Ingested by vali after the redefine too: a guest clock running ahead
    # cannot pass a receipt from before it.
    newest = ReceiptWatermark.objects.filter(
        vm_id=move.vm.vm_id, updated_at__gt=move.redefined_at
    ).aggregate(end=Max("last_period_end"))["end"]
    # A guest clock may run up to the meter's skew ahead of vali's.
    floor = int(move.redefined_at.timestamp()) + usage._receipt_max_skew_seconds()
    if newest is not None and newest > floor:
        VmStorageMove.objects.filter(pk=move.pk, state=StorageMoveState.VERIFYING).update(
            state=StorageMoveState.RELEASING, verified_at=now
        )
        move.refresh_from_db()
        _record_on_target(move)
        _apply(move, _order(move, "release", now=now), now=now)
        return
    timeout = timedelta(seconds=int(settings.VALI_STORAGE_MOVE_VERIFY_TIMEOUT_S))
    if now - move.redefined_at > timeout:
        _finish(
            move,
            StorageMoveState.FAILED,
            "verify-timeout",
            now=now,
            error="no served receipt since the redefine; the agent keeps the source",
        )


def _finish(
    move: VmStorageMove,
    state: str,
    code: str,
    *,
    now: datetime,
    error: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    from apps.backup.models import BackupPolicy

    fields: dict[str, Any] = dict(extra or {})
    fields.update(state=state, code=code[:48], finished_at=now, last_error=error[:256])
    if state == StorageMoveState.FAILED:
        # Which copy the VM runs on is not known for sure: no incremental
        # may build on a bitmap the move may have left behind.
        BackupPolicy.objects.filter(vm=move.vm).update(full_required=True)
    # Only from the state this step read: a concurrent tick's answer wins.
    VmStorageMove.objects.filter(pk=move.pk, state=move.state).exclude(
        state__in=TERMINAL_MOVE_STATES
    ).update(**fields)
    move.refresh_from_db()
    log.info(
        "storage-move: vm=%s %s -> %s (move %s) %s %s",
        move.vm.vm_id,
        move.source_pool,
        move.target_pool,
        move.move_id,
        move.state,
        move.code,
    )


# ─── metrics ─────────────────────────────────────────────────────────

M_ENABLED = "hippius_storage_move_enabled"
M_IN_FLIGHT = "hippius_storage_move_in_flight"
M_PIVOT_UNKNOWN = "hippius_storage_move_pivot_unknown_since_seconds"
M_FAILED = "hippius_storage_move_failed_24h"
M_TIMESTAMP = "hippius_storage_move_report_timestamp_seconds"
PUSH_INTERVAL_S = 60.0
_last_push = 0.0


def report_metrics(*, now: datetime) -> Any:
    from apps.synthetic import metrics

    ms = metrics.MetricSet()
    ms.gauge(
        M_ENABLED,
        1 if settings.VALI_STORAGE_MOVE_ENABLED else 0,
        help_text="1 while new storage moves are admitted.",
    )
    ms.gauge(
        M_IN_FLIGHT,
        VmStorageMove.objects.exclude(state__in=TERMINAL_MOVE_STATES).count(),
        help_text="Storage moves not over.",
    )
    for move in VmStorageMove.objects.filter(
        state=StorageMoveState.FAILED, code=PIVOT_UNKNOWN
    ).select_related("vm"):
        ms.gauge(
            M_PIVOT_UNKNOWN,
            int((move.finished_at or move.updated_at).timestamp()),
            help_text="Since when (unix ts) a move stopped mid-pivot holds its VM, "
            "unresolved (docs/operator/storage-move-runbook.md).",
            vm=move.vm.vm_id,
            miner=move.miner_id,
            move_id=move.move_id,
        )
    failed: dict[str, int] = {}
    for code in VmStorageMove.objects.filter(
        state=StorageMoveState.FAILED, finished_at__gte=now - timedelta(hours=24)
    ).values_list("code", flat=True):
        failed[code] = failed.get(code, 0) + 1
    for code, count in sorted(failed.items()):
        ms.gauge(
            M_FAILED,
            count,
            help_text="Storage moves that ended failed in the last 24 h, by code: each "
            "leaves the agent's journal for an operator (docs/operator/storage-move-runbook.md).",
            code=code,
        )
    ms.gauge(M_TIMESTAMP, int(now.timestamp()), help_text="Unix ts of this report.")
    return ms


def _push_metrics(*, now: datetime) -> None:
    global _last_push
    from apps.synthetic import metrics

    if time.monotonic() - _last_push < PUSH_INTERVAL_S:
        return
    # Nothing to say while off with no move left (no series: no alert).
    if not settings.VALI_STORAGE_MOVE_ENABLED and not (
        VmStorageMove.objects.exclude(state__in=TERMINAL_MOVE_STATES).exists()
        or VmStorageMove.objects.filter(state=StorageMoveState.FAILED, code=PIVOT_UNKNOWN).exists()
        or VmStorageMove.objects.filter(
            state=StorageMoveState.FAILED,
            finished_at__gte=timezone.now() - timedelta(hours=24),
        ).exists()
    ):
        return
    _last_push = time.monotonic()
    try:
        metrics.push(
            report_metrics(now=now),
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_GUEST_REPORT_PUSH_JOB,
            grouping_key={"report": "storage-move"},
            replace=True,
        )
    except Exception:  # noqa: BLE001 — the gauges must not break the pass.
        log.exception("storage-move: metrics push failed")
