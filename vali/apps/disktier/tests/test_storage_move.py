"""§19 live storage move, vali's half (`apps.disktier.storage_move`): the
gate, the request checks, the reconcile state machine against a fake
agent, the receipt verification before release, and the interlocks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import StringIO
from typing import Any

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.backup.models import BackupChain, BackupKind, BackupPolicy, BackupRun, RunStatus
from apps.disktier import storage_move
from apps.disktier.models import (
    OS_SLOT,
    MinerStoragePool,
    PlacementDisk,
    StorageMoveState,
    VmStorageMove,
)
from apps.disktier.storage_move import MoveRefused
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import order_dispatch
from apps.orchestration.tests.factories import make_vm
from apps.scheduler.models import MinerCapacity, Placement, PlacementStatus, ReceiptWatermark
from apps.scheduler.tests.factories import make_dispatchable_identity, make_placement, node_id

pytestmark = pytest.mark.django_db

NODE = node_id(7)
#: The meter's receipt clock skew (`VALI_BILLING_RECEIPT_MAX_SKEW_S`).
SKEW = 600
#: A VM a failover fenced (`Migrating` names its destination).
FENCED: dict[str, Any] = dict(state=VmState.MIGRATING, migration_dest=node_id(8), new_generation=6)
MIN = "v2026.10.17"
VM = "hipc-5150-0e6f350d"


@dataclass
class FakeMoveAgent:
    """The agent's `move-vm-storage` route: one journal per VM, `start`
    idempotent on `move_id`, `cancel` refused past the pivot, `release`
    only from `redefined`. Tests move `phase` to play the copy."""

    #: vm_id -> the agent's journal (`move_id`, `phase`, `code`).
    journals: dict[str, dict[str, Any]] = field(default_factory=dict)
    sent: list[dict[str, Any]] = field(default_factory=list)
    order_ids: list[str] = field(default_factory=list)
    #: Next answers instead of the real one, `(status, body)`.
    script: list[tuple[int, str]] = field(default_factory=list)
    unreachable: bool = False
    #: Apply the next order, then lose its answer (the Edge timed out).
    lose_next_answer: bool = False
    #: Apply the next order, then blow up vali's side (a killed worker).
    crash_after_next: bool = False

    def __call__(self, **kw: Any) -> order_dispatch.DispatchResult:
        assert kw["kind"] == "move-vm-storage"
        if self.unreachable:
            raise order_dispatch.OrderDispatchUnavailable("edge-order: peer unreachable")
        body = json.loads(kw["payload_json"])
        self.sent.append(body)
        self.order_ids.append(kw["order_id"])
        if self.script:
            status, text = self.script.pop(0)
            return order_dispatch.DispatchResult(
                ok=200 <= status < 300, status=status, classifier=text
            )
        status, text = self._serve(body)
        if self.lose_next_answer:
            self.lose_next_answer = False
            raise order_dispatch.OrderDispatchUnavailable("edge-order: forward timed out")
        if self.crash_after_next:
            self.crash_after_next = False
            raise RuntimeError("worker killed")
        return order_dispatch.DispatchResult(ok=status == 200, status=status, classifier=text)

    def phase(self, vm_id: str = VM) -> str:
        return self.journals[vm_id]["phase"]

    def set_phase(self, phase: str, code: str | None = None, vm_id: str = VM) -> None:
        self.journals[vm_id].update(phase=phase, code=code)

    def _serve(self, body: dict[str, Any]) -> tuple[int, str]:
        vm_id, move_id, action = body["vm_id"], body["move_id"], body["action"]
        journal = self.journals.get(vm_id)
        if action == "start":
            if journal is not None and journal["move_id"] == move_id:
                return self._status(journal)
            if journal is not None and journal["phase"] not in ("done", "aborted", "failed"):
                return 409, "move-busy"
            journal = {
                "move_id": move_id,
                "vm_id": vm_id,
                "phase": "copying",
                "code": None,
                "src_pool": body["expected_source_pool"],
                "dst_pool": body["target_pool"],
            }
            self.journals[vm_id] = journal
            return self._status(journal)
        if journal is None or journal["move_id"] != move_id:
            return 404, "move-not-found"
        if action == "cancel":
            if journal["phase"] in ("prepared", "copying"):
                journal.update(phase="aborted", code="move-aborted-operator")
            elif journal["phase"] not in ("aborted", "failed") or (
                journal["code"] == "move-pivot-unknown"
            ):
                return 409, "move-past-pivot"
        elif action == "release":
            if journal["phase"] == "redefined":
                journal["phase"] = "done"
            elif journal["phase"] != "done":
                return 409, "move-not-releasable"
        return self._status(journal)

    @staticmethod
    def _status(journal: dict[str, Any]) -> tuple[int, str]:
        return 200, json.dumps(
            {
                "move_id": journal["move_id"],
                "vm_id": journal["vm_id"],
                "phase": journal["phase"],
                "bytes_total": 50 << 30,
                "bytes_done": 10 << 30,
                "src_pool": journal["src_pool"],
                "dst_pool": journal["dst_pool"],
                "started_at": 1,
                "updated_at": 2,
                "code": journal["code"],
            }
        )


@pytest.fixture(autouse=True)
def _no_pushgateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "")


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> FakeMoveAgent:
    fake = FakeMoveAgent()
    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", fake)
    return fake


@pytest.fixture
def move_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MIN_AGENT_VERSION", MIN)


def _pool(pool_id: str, **kw: Any) -> MinerStoragePool:
    fields: dict[str, Any] = dict(
        os_disks=True,
        reported_state="active",
        reported_at=timezone.now(),
        declared_class="nvme",
        available_gb=1000,
        committed_gb=0,
    )
    fields.update(kw)
    return MinerStoragePool.objects.create(miner_node_id=NODE, pool_id=pool_id, **fields)


@pytest.fixture
def host() -> Vm:
    """A miner at the minimum agent with `default` and `nvme0`, and a
    running VM bound on it with its OS disk on `default` (no row)."""
    make_dispatchable_identity(7)
    MinerCapacity.objects.create(
        miner_node_id=NODE,
        status="active",
        capacity_slots=4,
        observed_epoch=1,
        data_epoch=1,
        refreshed_at=timezone.now(),
        agent_version=MIN,
    )
    _pool("default")
    _pool("nvme0")
    vm = make_vm(VM, host="miner-07")
    make_placement(vm, NODE, status=PlacementStatus.BOUND.value, resource_class="small")
    BackupPolicy.objects.create(vm=vm, interval_s=3600, full_required=False)
    _receipt(int(timezone.now().timestamp()))
    return vm


def _move() -> VmStorageMove:
    return VmStorageMove.objects.get(vm__vm_id=VM)


def _tick(at: datetime | None = None) -> VmStorageMove:
    storage_move.reconcile(now=at or timezone.now())
    return _move()


def _later(seconds: int) -> datetime:
    return timezone.now() + timedelta(seconds=seconds)


def _receipt(period_end: int, *, ingested_at: datetime | None = None) -> None:
    """The VM's watermark, as vali's ingest left it at `ingested_at`."""
    row, _ = ReceiptWatermark.objects.update_or_create(
        vm_id=VM,
        lease_id=f"lease-{VM}",
        defaults={"last_monotonic_seq": 9, "last_period_end": period_end},
    )
    ReceiptWatermark.objects.filter(pk=row.pk).update(updated_at=ingested_at or timezone.now())


def _os_pool() -> str | None:
    row = PlacementDisk.objects.filter(placement__vm__vm_id=VM, slot=OS_SLOT).first()
    return row.pool_id if row is not None else None


# ── gate ────────────────────────────────────────────────────────────


def test_everything_is_dark_by_default(host: Vm, agent: FakeMoveAgent) -> None:
    assert settings.VALI_STORAGE_MOVE_ENABLED is False
    assert settings.VALI_STORAGE_MOVE_MIN_AGENT_VERSION == ""
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == "storage-move-disabled"
    # A row left by an earlier enablement, never sent, is dropped.
    VmStorageMove.objects.create(
        vm=host,
        miner_node_id=NODE,
        miner_id="miner-07",
        source_pool="default",
        target_pool="nvme0",
        bandwidth_mib_s=200,
    )
    storage_move.reconcile()
    assert agent.sent == []
    assert _move().state == StorageMoveState.ABORTED


@pytest.mark.usefixtures("move_on")
@pytest.mark.parametrize(
    ("setting", "value", "code"),
    [
        ("VALI_STORAGE_MOVE_MINERS", ["miner-08"], "miner-not-selected"),
        ("VALI_STORAGE_MOVE_MIN_AGENT_VERSION", "v2026.10.18", "agent-version-below-min"),
        ("VALI_STORAGE_MOVE_MIN_AGENT_VERSION", "", "agent-version-below-min"),
    ],
)
def test_the_gate_refuses_a_miner_outside_it(
    host: Vm, monkeypatch: pytest.MonkeyPatch, setting: str, value: Any, code: str
) -> None:
    monkeypatch.setattr(settings, setting, value)
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == code
    assert not VmStorageMove.objects.exists()


# ── request checks ──────────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
@pytest.mark.parametrize(
    ("target", "pool_change", "code"),
    [
        ("nvme9", None, "move-pool-unknown"),
        ("default", None, "move-same-pool"),
        ("nvme0", dict(reported_state="draining"), "move-pool-not-active"),
        ("nvme0", dict(os_disks=False), "move-pool-not-active"),
        ("nvme0", dict(reported_at=timezone.now() - timedelta(hours=1)), "move-pool-not-active"),
        ("nvme0", dict(declared_class="hdd"), "move-pool-tier"),
        # The "small" disk (data + rootfs) is 50 GB: 49 free is short of it.
        ("nvme0", dict(available_gb=49), "move-pool-insufficient-space"),
        ("nvme0", dict(available_gb=None), "move-pool-insufficient-space"),
        ("nvme0", dict(budget_gb=100, committed_gb=51), "move-pool-insufficient-space"),
    ],
)
def test_a_request_the_target_cannot_take_is_refused(
    host: Vm, target: str, pool_change: dict[str, Any] | None, code: str
) -> None:
    if pool_change:
        MinerStoragePool.objects.filter(miner_node_id=NODE, pool_id="nvme0").update(**pool_change)
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool=target)
    assert exc.value.code == code
    assert not VmStorageMove.objects.exists()


@pytest.mark.usefixtures("move_on")
def test_a_guest_without_recent_receipts_does_not_move(host: Vm) -> None:
    stale = timezone.now() - timedelta(seconds=settings.VALI_STORAGE_MOVE_VERIFY_TIMEOUT_S + 60)
    _receipt(int(stale.timestamp()), ingested_at=stale)
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == "move-no-receipts"
    ReceiptWatermark.objects.all().delete()
    with pytest.raises(MoveRefused):
        storage_move.request_move(vm_id=VM, target_pool="nvme0")


@pytest.mark.usefixtures("move_on")
def test_the_target_needs_room_for_exactly_the_os_disk(host: Vm) -> None:
    MinerStoragePool.objects.filter(pool_id="nvme0").update(available_gb=50)
    move = storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert (move.source_pool, move.target_pool, move.bandwidth_mib_s) == ("default", "nvme0", 200)


@pytest.mark.usefixtures("move_on")
@pytest.mark.parametrize(
    "change",
    [dict(power_state=VmPowerState.STOPPED), dict(state=VmState.DECOMMISSIONING)],
)
def test_only_a_running_active_vm_moves(host: Vm, change: dict[str, Any]) -> None:
    Vm.objects.filter(pk=host.pk).update(**change)
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == "move-vm-not-running"


@pytest.mark.usefixtures("move_on")
def test_a_vm_with_a_job_or_a_backup_in_flight_does_not_move(host: Vm) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == "move-conflict-job", "a move in flight is a job"
    VmStorageMove.objects.all().delete()

    chain = BackupChain.objects.create(vm=host)
    BackupRun.objects.create(
        vm=host,
        chain=chain,
        seq=0,
        kind=BackupKind.FULL,
        status=RunStatus.RUNNING,
        miner_id="miner-07",
        disk_key="d",
        state_key="s",
        manifest_key="m",
        part_size=1,
        part_count=1,
    )
    with pytest.raises(MoveRefused) as exc:
        storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert exc.value.code == "move-conflict-backup"


@pytest.mark.usefixtures("move_on")
def test_the_source_is_the_pool_the_placement_records(host: Vm, agent: FakeMoveAgent) -> None:
    placement = host.placements.get()
    PlacementDisk.objects.create(
        placement=placement,
        slot=OS_SLOT,
        kind="pool",
        pool_id="nvme0",
        size_gb=40,
        required_tier="nvme",
    )
    move = storage_move.request_move(vm_id=VM, target_pool="default", bandwidth_mib_s=50)
    assert (move.source_pool, move.target_pool) == ("nvme0", "default")
    _tick()
    start = agent.sent[0]
    assert start["action"] == "start"
    assert start["expected_source_pool"] == "nvme0"
    assert start["target_pool"] == "default"
    assert start["bandwidth_mib_s"] == 50
    assert start["move_id"] == move.id.hex and len(start["move_id"]) == 32


# ── the state machine ──────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
def test_a_move_runs_to_done_and_releases_only_after_a_receipt(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    assert move.state == StorageMoveState.MOVING
    assert (move.agent_phase, move.bytes_done) == ("copying", 10 << 30)

    # Polled at most every POLL_S.
    _tick()
    assert [o["action"] for o in agent.sent] == ["start"]
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING
    assert move.redefined_at is not None
    # The VM is on the target from now on, and its next backup is a full.
    assert _os_pool() == "nvme0"
    assert BackupPolicy.objects.get(vm=host).full_required is True

    # A receipt whose window may have ended before the redefine (within
    # the meter's clock skew) proves nothing.
    redefined = move.redefined_at
    past = int(redefined.timestamp()) + SKEW
    _receipt(past, ingested_at=redefined + timedelta(seconds=5))
    move = _tick(_later(60))
    assert move.state == StorageMoveState.VERIFYING
    # Nor one claiming a later window that vali ingested before it.
    _receipt(past + 30, ingested_at=redefined - timedelta(seconds=1))
    move = _tick(_later(60))
    assert move.state == StorageMoveState.VERIFYING
    assert "release" not in [o["action"] for o in agent.sent]

    _receipt(past + 30, ingested_at=redefined + timedelta(seconds=30))
    move = _tick(_later(120))
    assert move.state == StorageMoveState.DONE
    assert move.verified_at is not None and move.finished_at is not None
    assert agent.phase() == "done"
    assert [o["action"] for o in agent.sent] == ["start", "status", "release"]
    assert not storage_move.in_flight(host)


@pytest.mark.usefixtures("move_on")
def test_no_receipt_in_time_fails_the_move_and_keeps_the_source(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    timeout = settings.VALI_STORAGE_MOVE_VERIFY_TIMEOUT_S
    move = _tick(move.redefined_at + timedelta(seconds=timeout - 1))
    assert move.state == StorageMoveState.VERIFYING
    move = _tick(move.redefined_at + timedelta(seconds=timeout + 1))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "verify-timeout")
    assert "release" not in [o["action"] for o in agent.sent]
    assert agent.phase() == "redefined", "the agent keeps the source copy"

    # An operator checked the guest: the release is handed back to the tick.
    move = storage_move.force_release(move, by="op:test")
    assert move.state == StorageMoveState.RELEASING
    move = _tick()
    assert move.state == StorageMoveState.DONE
    assert agent.phase() == "done"


@pytest.mark.usefixtures("move_on")
def test_only_a_verify_timeout_is_released_by_hand(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    with pytest.raises(MoveRefused):
        storage_move.force_release(move, by="op:test")
    agent.set_phase("failed", "move-pivot-unknown")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "move-pivot-unknown")
    with pytest.raises(MoveRefused):
        storage_move.force_release(move, by="op:test")


@pytest.mark.usefixtures("move_on")
def test_a_copy_that_fails_mid_way_aborts_with_the_vm_on_its_source(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("aborted", "move-job-failed")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-job-failed")
    assert _os_pool() is None, "the placement still has its disk on default"
    assert BackupPolicy.objects.get(vm=host).full_required is False
    assert "release" not in [o["action"] for o in agent.sent]
    assert not storage_move.in_flight(host)


@pytest.mark.usefixtures("move_on")
def test_a_refused_start_aborts_and_a_lost_one_is_resent(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    # Unreachable: nothing known, re-sent next tick.
    agent.unreachable = True
    move = _tick()
    assert move.state == StorageMoveState.REQUESTED
    assert move.last_error.startswith("unreachable")
    agent.unreachable = False
    # The agent started it, but the answer was lost: the same move_id is
    # re-sent and the agent answers its journal.
    agent.lose_next_answer = True
    poll = settings.VALI_STORAGE_MOVE_POLL_S
    move = _tick(_later(2 * poll + 1))
    assert move.state == StorageMoveState.REQUESTED
    move = _tick(_later(6 * poll + 1))
    assert move.state == StorageMoveState.MOVING
    starts = [o for o in agent.sent if o["action"] == "start"]
    assert len(starts) == 2 and starts[0]["move_id"] == starts[1]["move_id"]
    assert len(set(agent.order_ids)) == len(agent.order_ids), "a fresh order_id each send"

    # A start the agent refuses ends the move: nothing was created.
    VmStorageMove.objects.all().delete()
    agent.journals.clear()
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.script = [(409, "move-busy")]
    move = _tick()
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-busy")


@pytest.mark.usefixtures("move_on")
def test_an_edge_refusal_of_the_start_is_retried_not_aborted(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.script = [(502, "edge-forward-failed"), (500, "move-job-failed"), (409, "in-flight")]
    poll = settings.VALI_STORAGE_MOVE_POLL_S
    assert _tick().state == StorageMoveState.REQUESTED
    move = _tick(_later(2 * poll + 1))
    assert move.state == StorageMoveState.REQUESTED, "a 5xx may have created the journal"
    move = _tick(_later(6 * poll + 1))
    assert move.state == StorageMoveState.REQUESTED, "not the agent's own refusal"
    assert move.failures == 3
    assert _tick(_later(14 * poll + 1)).state == StorageMoveState.MOVING


@pytest.mark.usefixtures("move_on")
def test_an_unanswered_order_backs_off(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.unreachable = True
    t0 = timezone.now()
    _tick(t0)
    _tick(t0 + timedelta(seconds=1))
    assert _move().failures == 1, "not re-sent before the backoff"
    poll = settings.VALI_STORAGE_MOVE_POLL_S
    _tick(t0 + timedelta(seconds=2 * poll))
    assert _move().failures == 2
    _tick(t0 + timedelta(seconds=2 * poll + 3 * poll))
    assert _move().failures == 2, "the period doubled"
    agent.unreachable = False
    move = _tick(t0 + timedelta(seconds=2 * poll + 4 * poll))
    assert (move.state, move.failures) == (StorageMoveState.MOVING, 0)


@pytest.mark.usefixtures("move_on")
def test_a_resent_start_refused_by_a_conflict_reads_the_journal(
    host: Vm, agent: FakeMoveAgent
) -> None:
    """The agent checks a migration/backup conflict before it looks the
    move up: a re-sent start of a move that DID start must not abort it."""
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.lose_next_answer = True
    _tick()
    assert agent.phase() == "copying"
    agent.script = [(409, "move-conflict-backup")]
    move = _tick(_later(2 * settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.MOVING
    assert [o["action"] for o in agent.sent] == ["start", "start", "status"]


@pytest.mark.usefixtures("move_on")
def test_a_release_is_resent_until_the_agent_answers(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    agent.unreachable = True
    move = _tick(_later(60))
    assert (move.state, move.failures) == (StorageMoveState.RELEASING, 1)
    agent.unreachable = False
    move = _tick(_later(60 + 2 * settings.VALI_STORAGE_MOVE_POLL_S))
    assert move.state == StorageMoveState.DONE
    assert agent.phase() == "done"


@pytest.mark.usefixtures("move_on")
def test_a_journal_the_agent_lost_mid_move_is_for_an_operator(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.journals.clear()
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "agent-move-not-found")


# ── cancel ──────────────────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
def test_cancel_aborts_the_copy(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    storage_move.cancel(move)
    move = _tick()
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-aborted-operator")
    assert agent.sent[-1]["action"] == "cancel"
    assert agent.phase() == "aborted"


@pytest.mark.usefixtures("move_on")
def test_cancel_before_the_start_reached_the_agent(host: Vm, agent: FakeMoveAgent) -> None:
    move = storage_move.request_move(vm_id=VM, target_pool="nvme0")
    storage_move.cancel(move)
    move = _tick()
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-aborted-operator")
    assert [o["action"] for o in agent.sent] == ["cancel"], "never started"


@pytest.mark.usefixtures("move_on")
def test_cancel_after_the_pivot_is_refused_and_the_move_carries_on(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    agent.set_phase("pivoted")
    storage_move.cancel(move)
    move = _tick()
    assert move.state == StorageMoveState.MOVING
    assert move.cancel_requested_at is None
    assert "move-past-pivot" in move.last_error
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING


# ── interlocks ──────────────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
def test_a_move_in_flight_holds_the_vm_but_not_a_decommission(
    host: Vm, agent: FakeMoveAgent
) -> None:
    from apps.orchestration import service
    from apps.scheduler.tests.factories import make_service_client

    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert service._has_active_job(host) is True
    assert service._has_active_job(host, ignore_storage_move=True) is False
    job = service.start_decommission(vm=host, decided_by=make_service_client())
    assert job.vm_id == host.pk


@pytest.mark.usefixtures("move_on")
def test_a_move_in_flight_holds_the_backups(host: Vm) -> None:
    from apps.backup import service as backup_service

    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    assert backup_service._orchestration_job_in_flight(host) is True


def _placed(node: str, status: str, *, bound: bool) -> None:
    placement = make_placement(
        Vm.objects.get(vm_id=VM),
        node,
        status=status,
        resource_class="small",
        reason="migrated:failover" if status == PlacementStatus.MIGRATED.value else None,
    )
    Placement.objects.filter(pk=placement.pk).update(
        bound_at=timezone.now() + timedelta(seconds=1) if bound else None
    )


@pytest.mark.usefixtures("move_on")
def test_a_failover_that_never_landed_lets_the_move_complete(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    # Host A flapped: an automatic failover opened a placement on B, which
    # failed (no room); the VM stays on A, copying.
    _placed(node_id(8), PlacementStatus.FAILED.value, bound=False)
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    move = _tick(_later(120))
    assert move.state == StorageMoveState.DONE
    assert _os_pool() == "nvme0", "the target pool is recorded"
    assert BackupPolicy.objects.get(vm=host).full_required is True


@pytest.mark.usefixtures("move_on")
def test_only_a_placement_that_bound_elsewhere_counts(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    # Decided on B, never bound there — even with the VM's host pointing at
    # B mid-way: the VM did not leave.
    _placed(node_id(8), PlacementStatus.FAILED.value, bound=False)
    Vm.objects.filter(pk=host.pk).update(host="miner-08")
    move.refresh_from_db()
    assert storage_move.left_host(move) is False
    # Bound on C, then failed there, the VM never moving off this host.
    Vm.objects.filter(pk=host.pk).update(host="miner-07")
    _placed(node_id(9), PlacementStatus.FAILED.value, bound=True)
    move.refresh_from_db()
    assert storage_move.left_host(move) is False


@pytest.mark.usefixtures("move_on")
def test_a_vm_that_left_is_followed_without_being_held_and_never_released(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    BackupPolicy.objects.filter(vm=host).update(full_required=False)
    # A failover bound it on node 9, and the VM's host moved there.
    _placed(node_id(9), PlacementStatus.FAILED.value, bound=True)
    Vm.objects.filter(pk=host.pk).update(host="miner-09")
    host.refresh_from_db()
    # It does not hold the VM where it runs now...
    assert not storage_move.in_flight(host)
    from apps.orchestration import service

    assert service._has_active_job(host) is False
    # ...while the old host's copy is still followed (status only).
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.MOVING
    assert agent.sent[-1]["action"] == "status"
    # Its pivot there is booked: the next backup is a full.
    agent.set_phase("redefined")
    move = _tick(_later(2 * settings.VALI_STORAGE_MOVE_POLL_S + 2))
    assert move.state == StorageMoveState.VERIFYING
    assert BackupPolicy.objects.get(vm=host).full_required is True
    move = _tick(_later(3 * settings.VALI_STORAGE_MOVE_POLL_S + 3))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "vm-left-host")
    assert {o["action"] for o in agent.sent} == {"start", "status"}, "no start, cancel, release"
    ms = storage_move.report_metrics(now=timezone.now())
    [failed] = [x for x in ms.samples if x.name == storage_move.M_FAILED]
    assert (failed.labels["code"], failed.value) == ("vm-left-host", 1)
    with pytest.raises(MoveRefused):
        storage_move.force_release(move, by="op:test")


@pytest.mark.usefixtures("move_on")
def test_a_move_that_saw_its_vm_leave_stays_left_after_a_return(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    # Failover to node 9 ...
    host.placements.update(status=PlacementStatus.MIGRATED.value, reason="failover")
    _placed(node_id(9), PlacementStatus.BOUND.value, bound=True)
    Vm.objects.filter(pk=host.pk).update(host="miner-09")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.left_host_at is not None and move.state == StorageMoveState.MOVING
    # ... then a §25 back onto the move's host, its disk wherever §25 put it.
    Placement.objects.filter(vm=host, miner_node_id=node_id(9)).update(
        status=PlacementStatus.MIGRATED.value, reason="migrated:back"
    )
    _placed(NODE, PlacementStatus.BOUND.value, bound=True)
    Vm.objects.filter(pk=host.pk).update(host="miner-07")
    host.refresh_from_db()
    assert not storage_move.in_flight(host), "a left move never holds the VM again"
    agent.set_phase("redefined")
    move = _tick(_later(2 * settings.VALI_STORAGE_MOVE_POLL_S + 2))
    move = _tick(_later(3 * settings.VALI_STORAGE_MOVE_POLL_S + 3))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "vm-left-host")
    assert _os_pool() is None, "nothing booked on the new placement"
    assert "release" not in [o["action"] for o in agent.sent]


@pytest.mark.usefixtures("move_on")
def test_a_left_start_that_never_landed_is_dropped_once_expired(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.unreachable = True
    _tick()
    agent.unreachable = False
    _placed(node_id(9), PlacementStatus.FAILED.value, bound=True)
    Vm.objects.filter(pk=host.pk).update(host="miner-09")
    poll = settings.VALI_STORAGE_MOVE_POLL_S
    assert _tick(_later(2 * poll + 1)).state == StorageMoveState.REQUESTED
    late = storage_move._start_validity().total_seconds() + 4 * poll
    move = _tick(_later(int(late)))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "vm-left-host")
    assert {o["action"] for o in agent.sent} == {"status"}


@pytest.mark.usefixtures("move_on")
def test_a_superseded_move_books_nothing(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("done", "move-superseded")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-superseded")
    assert _os_pool() is None


@pytest.mark.usefixtures("move_on")
def test_a_round_trip_unseen_between_two_ticks_still_counts_as_left(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    # A→B→A entirely between two ticks: never sampled away.
    host.placements.update(status=PlacementStatus.MIGRATED.value, reason="failover")
    _placed(node_id(8), PlacementStatus.MIGRATED.value, bound=True)
    _placed(NODE, PlacementStatus.BOUND.value, bound=True)
    assert Vm.objects.get(pk=host.pk).host == "miner-07"
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.left_host_at is not None
    move = _tick(_later(2 * settings.VALI_STORAGE_MOVE_POLL_S + 2))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "vm-left-host")
    assert _os_pool() is None, "nothing booked on the placement the VM came back with"
    # Even as a verify-timeout, no release by hand once the VM went away.
    VmStorageMove.objects.filter(pk=move.pk).update(code="verify-timeout")
    move.refresh_from_db()
    with pytest.raises(MoveRefused) as exc:
        storage_move.force_release(move, by="op:test")
    assert exc.value.code == "move-vm-left-host"


@pytest.mark.usefixtures("move_on")
def test_a_move_superseded_after_its_redefine_gives_the_source_back(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert _os_pool() == "nvme0"
    # The VM went back onto the source path; a release finds it closed.
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    agent.set_phase("done", "move-superseded")
    move = _tick(_later(60))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "move-superseded")
    assert _os_pool() == "default"


@pytest.mark.usefixtures("move_on")
def test_no_bound_placement_holds_only_the_release(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    # Drained while the host was unreachable: vali cannot say where the VM
    # is. The copy is still followed; the source is not released.
    host.placements.update(
        status=PlacementStatus.FAILED.value, reason="drain:miner-stale", failed_at=timezone.now()
    )
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    move = _tick(_later(120))
    assert move.state == StorageMoveState.VERIFYING, "no release while unplaced"
    assert _os_pool() is None, "no bound placement to record it on"
    # Re-bound by the sweep: the row is recorded and the source released.
    _placed(NODE, PlacementStatus.BOUND.value, bound=True)
    move = _tick(_later(180))
    assert move.state == StorageMoveState.DONE
    assert _os_pool() == "nvme0"


@pytest.mark.usefixtures("move_on")
def test_no_start_while_unplaced(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    host.placements.update(
        status=PlacementStatus.FAILED.value, reason="drain:miner-stale", failed_at=timezone.now()
    )
    assert _tick().state == StorageMoveState.REQUESTED
    assert agent.sent == []
    _placed(NODE, PlacementStatus.BOUND.value, bound=True)
    assert _tick().state == StorageMoveState.MOVING


@pytest.mark.usefixtures("move_on")
def test_a_fenced_vm_waits(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    sent = len(agent.sent)
    # A failover fences it: it may revert to this host.
    Vm.objects.filter(pk=host.pk).update(**FENCED)
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.MOVING and len(agent.sent) == sent
    Vm.objects.filter(pk=host.pk).update(
        state=VmState.ACTIVE, migration_dest="", new_generation=None
    )
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING


@pytest.mark.usefixtures("move_on")
def test_a_release_the_agent_refuses_is_for_an_operator(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    BackupPolicy.objects.filter(vm=host).update(full_required=False)
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    agent.script = [(409, "move-release-in-use")]
    move = _tick(_later(60))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "release-refused")
    assert move.last_error.endswith("agent phase: redefined"), move.last_error
    assert BackupPolicy.objects.get(vm=host).full_required is True
    move = storage_move.force_release(move, by="op:test")
    move = _tick()
    assert move.state == StorageMoveState.DONE


@pytest.mark.usefixtures("move_on")
def test_an_agent_that_never_answers_is_given_up(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    VmStorageMove.objects.update(failures=storage_move.GIVE_UP_FAILURES - 1)
    agent.unreachable = True
    move = _tick(_later(3600))
    assert move.failures == storage_move.GIVE_UP_FAILURES
    move = _tick(_later(7200))
    assert (move.state, move.code) == (StorageMoveState.FAILED, "agent-unanswered")
    assert not storage_move.in_flight(host)


@pytest.mark.usefixtures("move_on")
def test_the_failure_counter_is_capped(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    move = _tick()
    VmStorageMove.objects.update(failures=storage_move.GIVE_UP_FAILURES)
    move.refresh_from_db()
    storage_move._apply(move, storage_move.Answer(status=0, error="x"), now=timezone.now())
    assert _move().failures == storage_move.GIVE_UP_FAILURES


def test_switched_off_a_move_in_flight_is_driven_to_its_end(
    host: Vm, agent: FakeMoveAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MIN_AGENT_VERSION", MIN)
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", False)
    # No new move...
    with pytest.raises(MoveRefused):
        storage_move.request_move(vm_id=VM, target_pool="default")
    # ...but this one does not stay holding its VM's backups.
    agent.set_phase("redefined")
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert move.state == StorageMoveState.VERIFYING
    _receipt(int(move.redefined_at.timestamp()) + SKEW + 30, ingested_at=_later(3600))
    move = _tick(_later(120))
    assert move.state == StorageMoveState.DONE
    assert not storage_move.in_flight(host)


def test_switched_off_a_start_that_went_out_is_kept(
    host: Vm, agent: FakeMoveAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MIN_AGENT_VERSION", MIN)
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    # The start reached the agent; vali died before it recorded anything.
    agent.crash_after_next = True
    move = _tick()
    assert move.state == StorageMoveState.REQUESTED and agent.phase() == "copying"
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", False)
    storage_move.reconcile()
    assert _move().state == StorageMoveState.REQUESTED, "it may be copying"
    # Switched off: no start goes out again, the journal is read instead.
    starts = sum(o["action"] == "start" for o in agent.sent)
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert sum(o["action"] == "start" for o in agent.sent) == starts
    assert agent.sent[-1]["action"] == "status"
    assert move.state == StorageMoveState.MOVING


def test_switched_off_a_start_that_never_landed_is_dropped_once_expired(
    host: Vm, agent: FakeMoveAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_MIN_AGENT_VERSION", MIN)
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    agent.unreachable = True
    move = _tick()
    assert move.start_sent_at is not None and move.state == StorageMoveState.REQUESTED
    agent.unreachable = False
    monkeypatch.setattr(settings, "VALI_STORAGE_MOVE_ENABLED", False)
    poll = settings.VALI_STORAGE_MOVE_POLL_S
    # Within the start's validity it may still land: kept.
    move = _tick(_later(2 * poll + 1))
    assert move.state == StorageMoveState.REQUESTED
    ttl = (
        settings.VALI_STORAGE_MOVE_ORDER_TTL_S
        + storage_move.DISPATCH_DEADLINE_S
        + storage_move.START_SKEW_MARGIN_S
    )
    move = _tick(_later(ttl - 30))
    assert move.state == StorageMoveState.REQUESTED, "within validity + deadline + skew"
    move = _tick(_later(ttl + 2 * poll + 1))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "storage-move-disabled")
    assert set(o["action"] for o in agent.sent) == {"status"}, "never re-started"


def test_switched_off_a_move_never_sent_is_dropped(host: Vm, agent: FakeMoveAgent) -> None:
    VmStorageMove.objects.create(
        vm=host,
        miner_node_id=NODE,
        miner_id="miner-07",
        source_pool="default",
        target_pool="nvme0",
        bandwidth_mib_s=200,
    )
    storage_move.reconcile()
    assert (_move().state, _move().code) == (StorageMoveState.ABORTED, "storage-move-disabled")
    assert not storage_move.in_flight(host)
    assert agent.sent == []


@pytest.mark.usefixtures("move_on")
def test_a_vm_that_left_active_ends_its_move(host: Vm, agent: FakeMoveAgent) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    Vm.objects.filter(pk=host.pk).update(state=VmState.DECOMMISSIONING)
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.ABORTED, "vm-not-active")
    assert not storage_move.in_flight(host)


# ── pivot-unknown ───────────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
def test_a_held_pivot_is_alerted_until_an_operator_resolves_it(
    host: Vm, agent: FakeMoveAgent
) -> None:
    storage_move.request_move(vm_id=VM, target_pool="nvme0")
    _tick()
    agent.set_phase("failed", storage_move.PIVOT_UNKNOWN)
    move = _tick(_later(settings.VALI_STORAGE_MOVE_POLL_S + 1))
    assert (move.state, move.code) == (StorageMoveState.FAILED, storage_move.PIVOT_UNKNOWN)
    assert BackupPolicy.objects.get(vm=host).full_required is True

    def held() -> list[Any]:
        ms = storage_move.report_metrics(now=timezone.now())
        return [x for x in ms.samples if x.name == storage_move.M_PIVOT_UNKNOWN]

    [sample] = held()
    assert sample.labels["vm"] == VM
    assert sample.value == int(move.finished_at.timestamp())
    with pytest.raises(MoveRefused):
        storage_move.resolve_pivot_unknown(move, on="sideways", by="op:test")
    # Not bound on its host: the target cannot be recorded, so refused.
    host.placements.update(
        status=PlacementStatus.FAILED.value, reason="drain:miner-stale", failed_at=timezone.now()
    )
    with pytest.raises(MoveRefused) as exc:
        storage_move.resolve_pivot_unknown(move, on="target", by="op:test")
    assert exc.value.code == "move-vm-not-placed"
    _placed(NODE, PlacementStatus.BOUND.value, bound=True)
    out = StringIO()
    call_command(
        "vali_storage_move",
        "resolve",
        "--vm-id",
        VM,
        "--on",
        "target",
        "--by",
        "jd",
        stdout=out,
    )
    assert json.loads(out.getvalue())["code"] == "pivot-resolved-target"
    assert _os_pool() == "nvme0"
    assert held() == []
    with pytest.raises(MoveRefused):
        storage_move.resolve_pivot_unknown(_move(), on="source", by="op:test")


# ── the command ─────────────────────────────────────────────────────


@pytest.mark.usefixtures("move_on")
def test_the_command_starts_shows_and_cancels(host: Vm, agent: FakeMoveAgent) -> None:
    out = StringIO()
    call_command(
        "vali_storage_move", "start", "--vm-id", VM, "--to", "nvme0", "--by", "jd", stdout=out
    )
    row = json.loads(out.getvalue())
    assert (row["state"], row["target_pool"], row["requested_by"]) == (
        "requested",
        "nvme0",
        "op:jd",
    )
    with pytest.raises(CommandError, match="move-conflict-job"):
        call_command("vali_storage_move", "start", "--vm-id", VM, "--to", "nvme0", "--by", "jd")
    out = StringIO()
    call_command("vali_storage_move", "status", stdout=out)
    assert json.loads(out.getvalue())["move_id"] == row["move_id"]
    call_command("vali_storage_move", "cancel", "--vm-id", VM, stdout=StringIO())
    assert _move().cancel_requested_at is not None
    with pytest.raises(CommandError, match="--by"):
        call_command("vali_storage_move", "abandon", "--vm-id", VM)
    call_command("vali_storage_move", "abandon", "--vm-id", VM, "--by", "jd", stdout=StringIO())
    assert (_move().state, _move().code) == (StorageMoveState.FAILED, "operator-abandoned")
    assert BackupPolicy.objects.get(vm=host).full_required is True
    assert agent.sent == [], "nothing sent"
