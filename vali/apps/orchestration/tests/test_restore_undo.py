"""A2 operator undo: put a restore's ORIGINAL back after the commit point
(`restore.start_undo`, `POST /v1/vm/<id>/restore/<job_id>/revert`).

The original is itself an older state once the restored guest committed,
so the undo is a KBS-authorized rollback to the checkpoint vali took of the
original right before the fence — over the miner-agent's existing `abort`
(the retained `*.pre-restore-<id>` files renamed back)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.backup.models import BackupPolicy
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import restore, service
from apps.orchestration.models import (
    MigrationJob,
    MigrationState,
    RollbackEvent,
    RollbackOutcome,
    SourceReclaimState,
)
from apps.orchestration.services import kbs_rollback

from . import test_restore as _tr
from . import test_rollback_restore as _rb
from .conftest import FakeEffects
from .factories import make_service_client
from .test_restore import SRC_CHIP, _advance, _age_phase, _chain, _golden_vm, _grant, _Power
from .test_rollback_restore import FakeKbsRollback

_restore_env = _tr._restore_env
pwr = _tr.pwr
kbs = _rb.kbs

pytestmark = pytest.mark.django_db

SUPERUSER = {"kind": "superuser", "id": "ops-1"}


def _staged(fx: FakeEffects, job: MigrationJob) -> None:
    _tr._staged(fx, job)


def _failed_after_commit(fx: FakeEffects, pwr: _Power) -> MigrationJob:
    """A current-boot restore whose restored guest unlocked (it spoke) but
    whose KBS bundle never came: `failed-after-commit`, the VM left fenced
    `Migrating{6, node-src}`, the original kept."""
    vm = _golden_vm()
    job = _tr._to_verifying(fx, pwr, _tr._start(vm, _chain(vm)[-1]))
    assert job.original_checkpoint is not None
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason.startswith("failed-after-commit"), job.reason
    _retained(fx, job)
    return job


def _retained(fx: FakeEffects, job: MigrationJob) -> None:
    """The host reports this restore swapped in, its original retained."""
    _staged(fx, job)
    fx.restore_status[job.dest_node_id].update(
        swapped=True, pre_restore_present=True, domain_live=True
    )


def _undo(job: MigrationJob, **kw: Any) -> MigrationJob:
    got, started = restore.start_undo(
        job=job,
        decided_by=kw.pop("decided_by", make_service_client()),
        on_behalf_of=kw.pop("on_behalf_of", SUPERUSER),
    )
    assert started
    return got


def _refused(job: MigrationJob, **kw: Any) -> restore.RestoreError:
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_undo(
            job=job,
            decided_by=make_service_client(),
            on_behalf_of=kw.pop("on_behalf_of", SUPERUSER),
        )
    job.refresh_from_db()
    assert job.undo is None
    return exc.value


def _abort_answers(fx: FakeEffects, job: MigrationJob) -> None:
    """The destination knows this restore, original retained (so its
    abort is followed)."""
    _retained(fx, job)


# ── the happy path ───────────────────────────────────────────────────


def test_an_undo_rolls_the_original_back_through_a_kbs_arm(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    vm = job.vm
    cp = job.original_checkpoint
    job = _undo(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    undo = job.undo
    assert undo["undo_gen"] == job.new_gen + 2 == 8 and undo["shape"] == "fenced"
    assert undo["requested_by"] == SUPERUSER and undo["armed"] is None
    event = RollbackEvent.objects.get(job=job, purpose="undo")
    assert event.restore_id == undo["restore_id"] != job.restore_id
    assert event.to_boot_counter == 7 and event.run is None

    _abort_answers(fx, job)
    fx.calls.clear()
    job = _advance(job)
    order = [
        c[0]
        for c in fx.calls
        if c[0] in ("kbs_activate_dest", "authorize_rollback", "dispatch_restore")
    ]
    assert order == ["kbs_activate_dest", "authorize_rollback", "dispatch_restore"]
    assert ("kbs_activate_dest", vm.vm_id, "node-src", 8) in fx.calls
    (arm,) = kbs.armed
    manifest = job.original_manifest.encode()
    assert arm["checkpoint_cbor_hex"] == cp["checkpoint_cbor_hex"] == "b1"
    assert arm["manifest"] == manifest
    assert arm["manifest_sha256_hex"] == event.manifest_sha256
    assert (arm["new_gen"], arm["dest_platform_id_hex"]) == (8, SRC_CHIP)
    assert arm["restore_id"] == undo["restore_id"]
    assert arm["requested_by"] == "superuser:ops-1"
    (abort,) = [p for _m, _o, p in fx.restore_orders if p["op"] == "abort"]
    assert abort["restore_id"] == job.restore_id, "the miner swaps THIS restore's originals back"
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 8)
    assert pwr.started == [(vm.vm_id, True)], "always relaunched: the arm expires"
    assert job.state == MigrationState.RESTORE_UNDOING.value

    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value, "waits for the release"
    kbs.consume_id(undo["restore_id"], delivered=False)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value, "undelivered is no commit"
    kbs.consume_id(undo["restore_id"])
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert job.reason.startswith("undone-after-commit:failed-after-commit")
    assert job.failed_from_state == MigrationState.RESTORE_UNDOING.value
    assert job.restore_keep_original_until is None
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value
    assert job.undo["outcome"] == "done"
    event.refresh_from_db()
    assert event.outcome == RollbackOutcome.COMMITTED and event.committed_at is not None
    assert BackupPolicy.objects.get(vm=vm).full_required
    view = restore.serialize(job)
    assert view["phase"] == "reverted"
    assert view["undo"]["outcome"] == "done" and view["undo"]["rolled_back"] is True
    assert view["undo"]["committed_at"] is not None


def test_an_undo_needs_no_arm_when_the_restored_guest_never_committed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """`blocked:commit-undecidable` may be a restore that never released: the
    KBS counter is still the original's (`not-a-rollback`). The original
    then boots as it is, and a grant at the undo generation proves it."""
    job = _failed_after_commit(fx, pwr)
    job = _undo(job)
    _abort_answers(fx, job)
    kbs.refuse = (409, "not-a-rollback")
    job = _advance(job)
    assert job.undo["armed"] is False and kbs.armed == []
    event = RollbackEvent.objects.get(job=job, purpose="undo")
    assert event.outcome == RollbackOutcome.ABANDONED
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    _grant(fx, job, gen=8)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert restore.serialize(job)["undo"]["rolled_back"] is False


def test_an_activated_restore_that_never_proved_alive_can_be_undone(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm()
    job = _tr._done(fx, pwr, vm)
    MigrationJob.objects.filter(pk=job.pk).update(
        finished_at=timezone.now() - timedelta(hours=7)
    )
    service.reclaim_migrated_sources()  # never proved alive: skipped, original kept
    job.refresh_from_db()
    assert restore.phase(job) == "failed"
    _retained(fx, job)
    vm.refresh_from_db()
    assert (vm.state, vm.generation, vm.power_state) == (
        VmState.ACTIVE,
        6,
        VmPowerState.RUNNING,
    )
    job = _undo(job)
    assert job.undo["shape"] == "activated"
    _abort_answers(fx, job)
    job = _advance(job)
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 8)
    assert pwr.started, "the abort took the restored guest down; the original is relaunched"
    kbs.consume_id(job.undo["restore_id"])
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted


def test_a_replay_answers_the_undo_in_flight(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    again, started = restore.start_undo(
        job=job, decided_by=make_service_client(), on_behalf_of=SUPERUSER
    )
    assert not started and again.undo == job.undo
    assert RollbackEvent.objects.filter(job=job, purpose="undo").count() == 1


# ── what refuses an undo ─────────────────────────────────────────────


def test_only_a_superuser_may_undo(fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback) -> None:
    job = _failed_after_commit(fx, pwr)
    assert _refused(job, on_behalf_of={"kind": "tenant", "id": "u"}).code == (
        "revert-superuser-only"
    )
    assert _refused(job, on_behalf_of=None).code == "on-behalf-of-required"


def test_an_undo_needs_the_rollback_flag(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    job = _failed_after_commit(fx, pwr)
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    assert _refused(job).code == "rollback-unsupported"


def test_only_a_restore_failed_after_its_commit_can_be_undone(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm()
    done = _tr._done(fx, pwr, vm)  # a good restore
    assert _refused(done).code == "revert-not-applicable"


def test_a_vm_moved_on_since_is_not_undone(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    Vm.objects.filter(pk=job.vm_id).update(new_generation=9)
    assert _refused(job).code == "revert-not-applicable"


def test_a_reclaimed_original_cannot_come_back(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    MigrationJob.objects.filter(pk=job.pk).update(
        source_reclaim_state=SourceReclaimState.RECLAIMED.value
    )
    job.refresh_from_db()
    assert _refused(job).code == "revert-not-applicable"


def test_a_host_without_the_original_refuses_the_undo(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """vali's rows are not proof: a reclaim may have deleted the original and
    died before recording it. The miner is asked."""
    job = _failed_after_commit(fx, pwr)
    fx.restore_status[job.dest_node_id]["pre_restore_present"] = False
    assert _refused(job).code == "revert-not-applicable"
    fx.restore_status[job.dest_node_id].update(pre_restore_present=True, state="reclaimed")
    assert _refused(job).code == "revert-not-applicable"
    fx.restore_status.clear()
    assert _refused(job).code == "revert-not-applicable"
    fx.fail.add("poll_restore_status")
    assert _refused(job).code == "restore-unavailable"


def test_the_original_is_rechecked_right_before_the_fence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    fx.restore_status[job.dest_node_id]["pre_restore_present"] = False  # a reclaim raced
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "undo-failed:undo-original-missing:no-pre-restore-files"
    assert not [c for c in fx.calls if c[0] == "kbs_activate_dest" and c[3] == 8]
    assert kbs.armed == []
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.new_generation) == (VmState.MIGRATING, job.new_gen), "untouched"


def test_a_cross_host_restore_is_not_undone_here(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    MigrationJob.objects.filter(pk=job.pk).update(dest_node_id="node-dst")
    Vm.objects.filter(pk=job.vm_id).update(migration_dest="node-dst")
    job.refresh_from_db()
    assert _refused(job).code == "revert-cross-host-unsupported"


def test_a_cross_host_activated_restore_is_not_undone_here(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm()
    job = _tr._done(fx, pwr, vm)
    MigrationJob.objects.filter(pk=job.pk).update(
        finished_at=timezone.now() - timedelta(hours=7)
    )
    service.reclaim_migrated_sources()
    MigrationJob.objects.filter(pk=job.pk).update(dest_node_id="node-dst")
    Vm.objects.filter(pk=vm.pk).update(host="node-dst")
    job.refresh_from_db()
    assert _refused(job).code == "revert-cross-host-unsupported"


@pytest.mark.parametrize("why", ["no-route", "unstamped", "v1-checkpoint"])
def test_no_usable_checkpoint_of_the_original_no_undo(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, why: str
) -> None:
    if why == "no-route":
        kbs.route_missing = True
    elif why == "unstamped":
        kbs.original_stamp = 0
    else:
        # A V1 checkpoint names no volume-stamp timeline: the KBS never
        # arms it (`checkpoint-not-timeline-bound`), so no undo uses it.
        kbs.original_timeline_hex = None
    vm = _golden_vm()
    job = _tr._to_verifying(fx, pwr, _tr._start(vm, _chain(vm)[-1]))
    assert (job.original_checkpoint is None) == (why == "no-route")
    kbs.route_missing = False
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.reason.startswith("failed-after-commit")
    assert _refused(job).code == "revert-no-checkpoint"


def test_an_undo_right_after_a_rollback_is_rate_limited(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    kbs.last_rollback = {
        "restore_id": "ef" * 16,
        "consumed_at_unix": int(timezone.now().timestamp()) - 60,
        "delivered": True,
    }
    err = _refused(job)
    assert err.code == "rollback-rate-limited" and err.extra["retry_after_s"] > 1000


def test_an_undo_of_a_guest_that_is_not_rollback_capable_is_refused_before_the_fence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The KBS refuses every arm of such a guest (`guest-not-rollback-capable`,
    checked before `not-a-rollback`): an undo would fence the VM and then
    fail. Refuse it up front."""
    job = _failed_after_commit(fx, pwr)
    vm = Vm.objects.get(pk=job.vm_id)
    before = (vm.state, vm.host, vm.generation, vm.new_generation)
    calls = len(fx.calls)
    kbs.capable = False
    assert _refused(job).code == "rollback-not-capable"
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation, vm.new_generation) == before
    assert kbs.armed == [] and not [c for c in fx.calls[calls:] if c[0].startswith("kbs_")]


def test_capability_lost_after_the_undo_intake_fails_it_before_the_fence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    kbs.capable = False  # e.g. the KBS restarted between intake and tick
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "undo-failed:rollback-not-capable"
    assert not [c for c in fx.calls if c[0] == "kbs_activate_dest" and c[3] == 8]
    assert kbs.armed == []
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.new_generation) == (VmState.MIGRATING, job.new_gen), "untouched"


# ── an undo that fails ───────────────────────────────────────────────


def test_a_kbs_refusal_past_the_fence_is_retried_not_terminal(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    kbs.refuse = (409, "row-not-activated")
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value, job.reason
    assert job.undo["outcome"] == "pending" and job.undo["armed"] is None
    assert job.undo["arm_refused_reason"] == "rollback-refused:row-not-activated"
    event = RollbackEvent.objects.get(job=job, purpose="undo")
    assert event.outcome == RollbackOutcome.PENDING.value
    assert pwr.started == [] and not [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.migration_dest, vm.new_generation) == (VmState.MIGRATING, "node-src", 8)
    # The KBS takes it on a later tick: the undo goes on, the fence activate
    # is NOT re-driven (it would clear the arm).
    kbs.refuse = None
    job = _advance(job)
    assert job.undo["armed"] is True and len(kbs.armed) == 1
    assert fx.calls.count(("kbs_activate_dest", vm.vm_id, "node-src", 8)) == 1
    event.refresh_from_db()
    assert event.outcome == RollbackOutcome.ARMED.value


def test_a_refusal_past_its_deadline_gives_the_vm_back_never_leaving_it_fenced(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    kbs.refuse = (409, "row-not-activated")
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    first = timezone.now() - timedelta(seconds=restore.undo_arm_retry_s() + 1)
    MigrationJob.objects.filter(pk=job.pk).update(
        undo={**job.undo, "arm_refused_at": first.isoformat()}
    )
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason == "undo-failed:undo-arm-refused:rollback-refused:row-not-activated"
    assert job.undo["outcome"] == "failed" and job.undo["given_back"] is True
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 9)
    assert ("kbs_activate_dest", vm.vm_id, "node-src", 9) in fx.calls
    assert pwr.started == [] and not [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    assert RollbackEvent.objects.get(job=job, purpose="undo").outcome == "refused"
    with pytest.raises(restore.RestoreError) as again:
        restore.start_undo(job=job, decided_by=make_service_client(), on_behalf_of=SUPERUSER)
    assert again.value.code == "revert-not-applicable", "given back: nothing to resume"


def test_the_arm_retry_is_bounded_inside_the_phase_deadline(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_UNDO_ARM_RETRY_S", 10**9)
    assert restore.undo_arm_retry_s() == restore.revert_timeout_s() / 2


def test_an_unknown_arm_chip_fails_the_undo_before_the_fence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    from apps.miners.models import MinerIdentity

    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    MinerIdentity.objects.filter(miner_id="node-src").update(platform_id="")
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "undo-failed:rollback-dest-chip-unknown"
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.migration_dest, vm.new_generation) == (VmState.MIGRATING, "node-src", 6)
    assert not [c for c in fx.calls if c[0] == "kbs_activate_dest" and c[3] >= 8]


def test_a_give_back_that_cannot_reach_the_kbs_is_finished_by_a_resume(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_UNDO_ARM_RETRY_S", 0)
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    kbs.refuse = (409, "row-not-activated")
    # The fence activate at 8 goes through; the give-back's (9) cannot reach
    # the KBS.
    real = restore.effects.kbs_activate_dest
    kbs_down = {"on": True}

    def _activate(vm: Any, *, dest_node_id: str, new_gen: int, get_url: str) -> None:
        if new_gen == 9 and kbs_down["on"]:
            raise restore.EffectError("kbs-admin: unreachable (test)")
        real(vm, dest_node_id=dest_node_id, new_gen=new_gen, get_url=get_url)

    monkeypatch.setattr(restore.effects, "kbs_activate_dest", _activate)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.undo["given_back"] is False and job.undo.get("give_back_at")
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.new_generation) == (VmState.MIGRATING, 8), "fenced: the KBS was down"
    # Asked again: resumed, not refused — and it finishes the give-back,
    # even with a KBS that would now take the arm.
    kbs_down["on"] = False
    kbs.refuse = None
    job = _undo(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    assert job.undo["outcome"] == "pending" and job.undo["resumes"] == 1
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.undo["given_back"] is True
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 9)
    assert kbs.armed == [], "a started give-back is finished, never re-armed"


def test_a_failed_undo_left_fenced_is_resumed_and_arms(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    real_arm = kbs_rollback.authorize_rollback
    busy = {"on": True}

    def _busy_arm(vm_id: str, **kw: Any) -> dict[str, Any]:
        if busy["on"]:  # the admin gateway never takes the arm
            raise kbs_rollback.KbsRateLimited("kbs-admin (test)", retry_after_s=1)
        return real_arm(vm_id, **kw)

    monkeypatch.setattr(kbs_rollback, "authorize_rollback", _busy_arm)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.new_generation) == (VmState.MIGRATING, 8), "fenced, KBS activated"
    real_give_back = restore._undo_give_back

    def _crash(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("vali died before the give-back (test)")

    monkeypatch.setattr(restore, "_undo_give_back", _crash)
    _age_phase(job, restore.revert_timeout_s() + 5)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.undo["given_back"] is False
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.new_generation) == (VmState.MIGRATING, 8)
    # The undo's arm is not settled yet: a resume waits for the sweep.
    assert _refused_keeping(job).code == "revert-not-ready"
    stale = RollbackEvent.objects.get(job=job, purpose="undo")
    assert restore.sweep_rollback_events() == 1
    monkeypatch.setattr(restore, "_undo_give_back", real_give_back)
    busy["on"] = False
    job = _undo(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value and job.undo["armed"] is None
    event = RollbackEvent.objects.get(job=job, purpose="undo")
    assert event.outcome == RollbackOutcome.PENDING.value
    old_id = stale.restore_id
    assert event.restore_id != old_id == job.undo["previous_restore_ids"][-1]
    assert event.restore_id == job.undo["restore_id"]
    assert event.arm_requested_at is None and event.disarmed_at is None
    job = _advance(job)
    assert job.undo["armed"] is True and len(kbs.armed) == 1
    assert kbs.armed[0]["restore_id"] == event.restore_id
    # A stale sweeper still holding the settled event withdraws only the OLD
    # arm id, and cannot settle the resumed event.
    restore.disarm_rollback(vm.vm_id, stale)
    assert event.restore_id in kbs.arms, "the resumed arm survives"
    assert [o for o in fx.restore_orders if o[2]["op"] == "abort"], "the undo goes on"


def _refused_keeping(job: MigrationJob) -> restore.RestoreError:
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_undo(job=job, decided_by=make_service_client(), on_behalf_of=SUPERUSER)
    return exc.value


def test_a_busy_kbs_gateway_is_retried_during_the_undo(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    kbs.busy = 1
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value and kbs.armed == []
    job = _advance(job)
    assert len(kbs.armed) == 1 and job.undo["armed"] is True
    assert fx.calls.count(("kbs_activate_dest", job.vm.vm_id, "node-src", 8)) == 1


def test_an_undo_past_its_swap_never_fails_or_disarms_while_its_arm_lives(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """Once the original is swapped back and relaunched it can ONLY unlock
    through the undo's arm: the deadline does not end the undo (nor does the
    sweep withdraw the arm) until the arm went unused."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    job = _advance(job)
    assert job.undo["armed"] is True
    rid = job.undo["restore_id"]
    _age_phase(job, 3 * restore.revert_timeout_s())
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value, "the arm is live: wait"
    assert restore.sweep_rollback_events() == 0
    assert rid not in kbs.disarmed
    kbs.arms.clear()  # the arm expired unused
    kbs.last_clear = {"restore_id": rid, "reason": "rollback-expired", "at": 1}
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "undo-failed:undo-timeout" and job.undo["outcome"] == "failed"
    assert restore.sweep_rollback_events() == 1
    event = RollbackEvent.objects.get(job=job, purpose="undo")
    assert event.outcome == RollbackOutcome.ABANDONED and event.reason.startswith("arm-unused")
    assert rid not in kbs.disarmed


def test_an_undo_failing_before_its_swap_withdraws_its_arm(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """Armed, but the abort (which may put the original back) was never
    sent: the original still has the restored disk over it, and the arm is
    withdrawn like any failed rollback's."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    real = restore._claim_undo_step

    def no_abort_mark(job_: MigrationJob, field: str, **kw: Any) -> bool:
        if field == "abort_sent_at":
            raise restore.EffectError("store down (test)")
        return real(job_, field, **kw)

    monkeypatch.setattr(restore, "_claim_undo_step", no_abort_mark)
    job = _advance(job)
    assert not [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    assert job.undo["armed"] is True
    assert Vm.objects.get(pk=job.vm_id).state == VmState.MIGRATING
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reason.startswith("undo-failed")
    assert job.undo["given_back"] is True, "never swapped: the vm goes back to the restored disk"
    assert Vm.objects.get(pk=job.vm_id).generation == 9
    assert restore.sweep_rollback_events() == 1
    assert job.undo["restore_id"] in kbs.disarmed


def test_a_give_back_never_runs_under_a_swap_already_sent(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """A stale tick (it read the undo before another armed it and sent the
    abort) fails the undo: it must NOT give the VM back — its KBS activate
    would clear the arm the swapped-back original needs."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    stale = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    job = _advance(job)  # fenced, armed, abort sent (the swap)
    assert job.undo["armed"] is True and job.undo.get("abort_sent_at")
    restore.fail(stale, "stale-tick (test)")
    assert ("kbs_activate_dest", job.vm.vm_id, "node-src", 9) not in fx.calls
    assert not (MigrationJob.objects.get(pk=job.pk).undo or {}).get("give_back_at")
    # It read the undo as stored now: past the swap, with a live arm, the
    # undo is not ended under the relaunched original.
    assert MigrationJob.objects.get(pk=job.pk).state == MigrationState.RESTORE_UNDOING.value
    # And the give-back itself refuses on the stored claim, whatever the
    # caller's copy of the undo says.
    vm = Vm.objects.get(pk=job.vm_id)
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING.value, migration_dest="node-src", new_generation=8
    )
    stale = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    stale.undo = {**stale.undo, "abort_sent_at": None}
    assert restore._undo_give_back(stale, Vm.objects.get(pk=vm.pk), 8) is None
    assert ("kbs_activate_dest", job.vm.vm_id, "node-src", 9) not in fx.calls


def test_a_swap_is_never_sent_once_a_give_back_was_claimed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    real_arm = restore._arm

    def arm_then_another_tick_gives_back(*a: Any, **kw: Any) -> bool:
        armed = real_arm(*a, **kw)
        assert restore._claim_undo_step(a[0], "give_back_at", unless="abort_sent_at")
        return armed

    monkeypatch.setattr(restore, "_arm", arm_then_another_tick_gives_back)
    job = _advance(job)
    assert not [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    assert not (job.undo or {}).get("abort_sent_at")
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "undo-failed:undo-given-back-meanwhile"


def test_a_late_delivered_undo_is_recorded_as_done(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    job = _advance(job)
    rid = job.undo["restore_id"]
    kbs.unreachable = True  # the KBS cannot be read for twice the deadline
    _age_phase(job, 3 * restore.revert_timeout_s())
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    kbs.unreachable = False
    assert restore.sweep_rollback_events() == 0, "a live arm is never withdrawn"
    kbs.consume_id(rid)
    assert restore.sweep_rollback_events() == 1
    job.refresh_from_db()
    assert job.reverted and job.undo["outcome"] == "done"
    assert RollbackEvent.objects.get(job=job, purpose="undo").outcome == RollbackOutcome.COMMITTED


# ── the route ────────────────────────────────────────────────────────


def test_the_revert_route(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, root_client, authed_client
) -> None:
    job = _failed_after_commit(fx, pwr)
    url = f"/v1/vm/{job.vm.vm_id}/restore/{job.job_id}/revert"
    assert authed_client.post(url, {"on_behalf_of": SUPERUSER}, format="json").status_code == 403
    resp = root_client.post(url, {"on_behalf_of": {"kind": "tenant", "id": "u"}}, format="json")
    assert resp.status_code == 403 and resp.json()["error"] == "revert-superuser-only"
    resp = root_client.post(url, {"on_behalf_of": SUPERUSER, "x": 1}, format="json")
    assert resp.status_code == 400
    resp = root_client.post(url, {"on_behalf_of": SUPERUSER}, format="json")
    assert resp.status_code == 202, resp.content
    body = resp.json()
    assert body["phase"] == "activating" and body["undo"]["outcome"] == "pending"
    assert body["undo"]["requested_by"] == SUPERUSER and body["undo"]["generation"] == 8
    again = root_client.post(url, {"on_behalf_of": SUPERUSER}, format="json")
    assert again.status_code == 202 and again.json()["undo"] == body["undo"]
    missing = root_client.post(
        f"/v1/vm/{job.vm.vm_id}/restore/{'0' * 32}/revert",
        {"on_behalf_of": SUPERUSER},
        format="json",
    )
    assert missing.status_code == 404


def test_the_checkpoint_manifest_embeds_the_checkpoint(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _failed_after_commit(fx, pwr)
    manifest = job.original_manifest.encode()
    assert kbs_rollback.manifest_checkpoint_cbor_hex(manifest) == "b1"
    MigrationJob.objects.filter(pk=job.pk).update(original_manifest="{}")
    job.refresh_from_db()
    assert restore.original_checkpoint(job) is None
    assert _refused(job).code == "revert-no-checkpoint"


def test_the_restores_own_rollback_must_be_settled_first(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """Otherwise the sweep would read the undo's KBS record and file the
    restore's own (committed) rollback as abandoned."""
    job = _failed_after_commit(fx, pwr)
    RollbackEvent.objects.create(
        vm=job.vm,
        job=job,
        purpose="restore",
        run=job.restore_run,
        restore_id=job.restore_id,
        to_boot_counter=3,
        point_taken_at=timezone.now(),
        manifest_sha256="d" * 64,
        requested_by_kind="tenant",
        requested_by_id="u",
        outcome=RollbackOutcome.ARMED.value,
    )
    assert _refused(job).code == "revert-not-ready"


def test_the_undo_never_reactivates_the_kbs_once_armed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """A KBS `activate` clears the VM's arms: even with the idempotency
    store losing its records, the undo never activates again after arming."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    monkeypatch.setattr(restore, "_record", lambda key: None)
    monkeypatch.setattr(restore, "_done", lambda key: False)
    fx.restore_reject = ("restore-busy", 409)  # the abort fails: the tick stops there
    job = _advance(job)
    assert job.undo["armed"] is True
    fx.restore_reject = None
    job = _advance(job)
    activates = [c for c in fx.calls if c[0] == "kbs_activate_dest" and c[3] == 8]
    assert len(activates) == 1
    assert Vm.objects.get(pk=job.vm_id).state == VmState.ACTIVE


def test_an_undo_never_runs_beside_a_decommission(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    from .factories import make_decommission_job

    job = _failed_after_commit(fx, pwr)
    make_decommission_job(job.vm)
    assert _refused(job).code == "job-in-flight"


def test_a_reclaim_listed_before_the_undo_never_deletes_the_original(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The reclaim sweep lists its jobs, then works through them: one the
    operator took for an undo in between is skipped under its row lock."""
    vm = _golden_vm()
    stale = _tr._done(fx, pwr, vm)
    _tr._alive(stale)
    stale.refresh_from_db()  # as the sweep listed it: done, reclaim pending
    MigrationJob.objects.filter(pk=stale.pk).update(
        state=MigrationState.RESTORE_UNDOING.value, undo={"restore_id": "ab" * 16}
    )
    service._reclaim_one_source(stale)
    assert not [o for o in fx.restore_orders if o[2]["op"] == "reclaim"]
    stale.refresh_from_db()
    assert stale.source_reclaim_state == SourceReclaimState.PENDING.value


def test_an_undo_stops_the_automatic_reclaim_of_the_original(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value
    assert job.restore_keep_original_until is None
    _abort_answers(fx, job)
    kbs.refuse = (409, "row-not-activated")
    monkeypatch.setattr(settings, "VALI_RESTORE_UNDO_ARM_RETRY_S", 0)
    job = _advance(job)  # the undo fails…
    assert job.state == MigrationState.FAILED.value
    service.reclaim_migrated_sources()  # …and the original is still never reclaimed
    assert not [o for o in fx.restore_orders if o[2]["op"] == "reclaim"]


def test_an_undo_release_in_flight_at_the_deadline_is_waited_for(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    job = _advance(job)  # fenced, armed, swapped back, relaunched
    rid = job.undo["restore_id"]
    kbs.consume_id(rid, delivered=False)  # the original's release is in flight
    _age_phase(job, restore.revert_timeout_s() + 5)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value, "not failed under it"
    kbs.consume_id(rid)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert job.undo["outcome"] == "done"


def test_an_abort_sent_counts_as_the_swap_even_unconfirmed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """The host may have put the original back even though vali never saw
    it confirmed: from the abort on, the arm is the original's only way to
    unlock — never withdrawn, the undo kept alive to finish the relaunch."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    real_confirm = restore._confirm_aborted

    def unconfirmed(job_: MigrationJob) -> None:
        raise restore.EffectError("abort not confirmed (test)")

    monkeypatch.setattr(restore, "_confirm_aborted", unconfirmed)  # never confirmed
    job = _advance(job)
    assert job.undo["armed"] is True and job.undo["abort_sent_at"]
    assert [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    _age_phase(job, 3 * restore.revert_timeout_s())
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    assert restore.sweep_rollback_events() == 0 and kbs.disarmed == []
    monkeypatch.setattr(restore, "_confirm_aborted", real_confirm)
    job = _advance(job)  # confirmed, unfenced, relaunched
    assert Vm.objects.get(pk=job.vm_id).state == VmState.ACTIVE and pwr.started
    kbs.consume_id(job.undo["restore_id"])
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted


def test_an_undo_abandons_backup_runs_of_the_restored_disk(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    abandoned: list[str] = []
    monkeypatch.setattr(restore, "_abandon_backup_runs", lambda vm: abandoned.append(vm.vm_id))
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    job = _advance(job)
    kbs.consume_id(job.undo["restore_id"])
    job = _advance(job)
    assert job.reverted and abandoned == [job.vm.vm_id]


def test_an_unarmed_undo_waits_a_while_for_its_grant(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    kbs.refuse = (409, "not-a-rollback")
    job = _advance(job)
    assert job.undo["armed"] is False
    _age_phase(job, restore.revert_timeout_s() + 5)  # past the deadline, not twice it
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    _grant(fx, job, gen=8)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted


def test_a_failure_never_overwrites_a_recorded_undo_success(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    job = _undo(_failed_after_commit(fx, pwr))
    restore._note_undo(job, outcome="done")
    restore._note_undo(job, outcome="failed", reason="late", only_pending=True)
    job.refresh_from_db()
    assert job.undo["outcome"] == "done" and "reason" not in job.undo


def test_a_tick_that_armed_a_re_keyed_undo_attempt_never_sends_the_swap(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """A tick still inside `authorize-rollback` for arm R1 while the undo was
    failed, settled and resumed as R2: its answer is about R1, so it records
    nothing on R2 and never sends the swap."""
    job = _undo(_failed_after_commit(fx, pwr))
    _abort_answers(fx, job)
    real_arm = kbs_rollback.authorize_rollback

    def arm_then_resumed_elsewhere(vm_id: str, **kw: Any) -> dict[str, Any]:
        got = real_arm(vm_id, **kw)
        undo = {**MigrationJob.objects.get(pk=job.pk).undo, "restore_id": "r2" * 16}
        MigrationJob.objects.filter(pk=job.pk).update(undo=undo)
        RollbackEvent.objects.filter(job=job, purpose="undo").update(
            restore_id="r2" * 16, outcome=RollbackOutcome.PENDING.value
        )
        return got

    monkeypatch.setattr(kbs_rollback, "authorize_rollback", arm_then_resumed_elsewhere)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_UNDOING.value
    stored = MigrationJob.objects.get(pk=job.pk).undo
    assert stored["armed"] is None and not stored.get("abort_sent_at")
    assert not [o for o in fx.restore_orders if o[2]["op"] == "abort"]
    assert RollbackEvent.objects.get(job=job, purpose="undo").outcome == "pending"
