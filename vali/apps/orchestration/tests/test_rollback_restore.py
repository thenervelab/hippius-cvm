"""A2: restore a VM to a point of an EARLIER boot through a KBS-authorized
rollback (`apps.orchestration.restore`, the `rollback` parts).

One test (or a small group) per claim: who may ask, what the KBS is asked
and when, that every failure withdraws the arm, and that the job is done
only when the KBS says THIS restore's arm was consumed."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.backup.models import BackupRun
from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, restore, service
from apps.orchestration.models import (
    DestAuthorization,
    MigrationJob,
    MigrationKind,
    MigrationState,
    RollbackEvent,
    RollbackOutcome,
)
from apps.orchestration.services import kbs_rollback

from . import test_restore as _tr
from .conftest import FakeEffects
from .factories import make_service_client
from .test_restore import (
    DST_CHIP,
    SRC_CHIP,
    _advance,
    _age_phase,
    _chain,
    _golden_vm,
    _grant,
    _original_grant,
    _Power,
    _restore_at_dest_activating,
    _staged,
)

# The restore suite's fixtures, shared (autouse env + the power fake).
_restore_env = _tr._restore_env
pwr = _tr.pwr

pytestmark = pytest.mark.django_db

TENANT = {"kind": "tenant", "id": "u-42"}
MANIFEST_SHA = "d" * 64


class FakeKbsRollback:
    """The four KBS rollback routes, in memory."""

    def __init__(self, fx: FakeEffects) -> None:
        self.fx = fx
        self.arms: dict[str, dict[str, Any]] = {}
        self.armed: list[dict[str, Any]] = []
        self.disarmed: list[str] = []
        self.last_rollback: dict[str, Any] | None = None
        self.last_clear: dict[str, Any] | None = None
        #: `(status, reason)` the next `authorize_rollback` is refused with.
        self.refuse: tuple[int, str] | None = None
        self.route_missing = False
        #: 503 `rollback-unavailable`: the KBS runs without its rollback context.
        self.unavailable = False
        self.unreachable = False
        self.disarm_fails = False
        #: The admin gateway answers the next N calls `429 rate-limited`.
        self.busy = 0
        #: The ORIGINAL's checkpoint the KBS signs before the fence.
        self.original_counter = 7
        self.original_stamp = 2
        #: Its volume-stamp timeline (V2); None = a KBS still signing V1.
        self.original_timeline_hex: str | None = "00" * 32
        #: `GET .../rollback` → `rollback_capable`.
        self.capable = True
        self.status_reads = 0

    def _check(self) -> None:
        if self.unreachable:
            raise effects.EffectUnavailable("kbs-admin: unreachable (test)")
        if self.route_missing:
            raise effects.KbsRouteMissing("kbs-admin: 404 (test)")
        if self.unavailable:
            raise kbs_rollback.RollbackUnavailable("kbs-admin: 503 rollback-unavailable (test)")
        if self.busy:
            self.busy -= 1
            raise kbs_rollback.KbsRateLimited("kbs-admin (test)", retry_after_s=1)

    def fetch_checkpoint(self, vm_id: str, **_kw: Any) -> kbs_rollback.Checkpoint:
        self._check()
        self.fx.calls.append(("fetch_checkpoint", vm_id))
        return kbs_rollback.Checkpoint(
            vm_id=vm_id,
            boot_counter=self.original_counter,
            volume_stamp=self.original_stamp,
            unconfirmed_releases=0,
            generation=5,
            issued_at_unix=1_760_000_000,
            checkpoint_cbor_hex="b1",
            signature_hex="ee" * 64,
            signer_pubkey_hex="ff" * 32,
            volume_stamp_timeline_id_hex=self.original_timeline_hex,
        )

    def authorize_rollback(self, vm_id: str, **kw: Any) -> dict[str, Any]:
        self._check()
        self.fx.calls.append(("authorize_rollback", vm_id, kw["new_gen"]))
        if self.refuse is not None:
            status, reason = self.refuse
            raise kbs_rollback.RollbackRefused(
                "kbs-admin:authorize-rollback", status=status, reason=reason, retry_after_s=None
            )
        arm = {"vm_id": vm_id, **kw}
        self.armed.append(arm)
        self.arms[kw["restore_id"]] = arm
        return arm

    def disarm(self, vm_id: str, restore_id: str) -> None:
        if self.disarm_fails:
            raise effects.EffectUnavailable("kbs-admin: unreachable (test)")
        self.fx.calls.append(("disarm", vm_id, restore_id))
        self.disarmed.append(restore_id)
        self.arms.pop(restore_id, None)

    def rollback_status(self, vm_id: str) -> dict[str, Any]:
        self.status_reads += 1
        self._check()
        arm = next(iter(self.arms.values()), None)
        return {
            "arm": arm,
            "last_rollback": self.last_rollback,
            "last_clear": self.last_clear,
            "rollback_capable": self.capable,
        }

    def consume(self, job: MigrationJob, *, delivered: bool = True) -> None:
        """The restored guest's release consumed the arm."""
        self.consume_id(job.restore_id, delivered=delivered)

    def consume_id(self, restore_id: str, *, delivered: bool = True) -> None:
        self.arms.pop(restore_id, None)
        self.last_rollback = {
            "restore_id": restore_id,
            "manifest_sha256_hex": MANIFEST_SHA,
            "from_counter": 7,
            "to_counter": 8,
            "stamp": 2,
            "consumed_at_unix": int(timezone.now().timestamp()),
            "requested_by": "tenant:u-42",
            "delivered": delivered,
            "reverted": False,
        }


@pytest.fixture
def kbs(monkeypatch: pytest.MonkeyPatch, fx: FakeEffects) -> FakeKbsRollback:
    fake = FakeKbsRollback(fx)
    for name in ("authorize_rollback", "disarm", "rollback_status", "fetch_checkpoint"):
        monkeypatch.setattr(kbs_rollback, name, getattr(fake, name))
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", True)
    return fake


def _checkpoint(vm: Vm, counter: int) -> dict[str, Any]:
    return {
        "checkpoint": {
            "domain": kbs_rollback.CHECKPOINT_DOMAIN_V2,
            "vm_id": vm.vm_id,
            "boot_counter": counter,
            "volume_stamp": 2,
            kbs_rollback.WIRE_CHECKPOINT_TIMELINE: "00" * 32,
            "unconfirmed_releases": 0,
            "generation": 5,
            "issued_at_unix": 1,
        },
        "checkpoint_cbor_hex": "a0",
        "signature_hex": "ee" * 64,
        "signer_pubkey_hex": "ff" * 32,
    }


def _manifest_of(cp: dict[str, Any] | None) -> bytes:
    """A point's manifest.json bytes, embedding its checkpoint."""
    doc = {
        "format": "test",
        "vm_id": (cp or {}).get("checkpoint", {}).get("vm_id"),
        kbs_rollback.MANIFEST_CHECKPOINT_KEY: cp,
    }
    return json.dumps(doc, sort_keys=True, indent=2).encode("utf-8")


def _old_point(vm: Vm, *, checkpoint: bool = True, cp_counter: int = 3) -> BackupRun:
    """A point of boot 3 while the guest is at boot 7 — a rollback point."""
    run = _chain(vm, counter=3)[-1]
    if checkpoint:
        cp = _checkpoint(vm, cp_counter)
        manifest = _manifest_of(cp)
        BackupRun.objects.filter(pk=run.pk).update(
            kbs_checkpoint=cp,
            manifest_sha256=hashlib.sha256(manifest).hexdigest(),
            manifest_json=manifest.decode("utf-8"),
        )
    run.refresh_from_db()
    return run


def _ev(job: MigrationJob, purpose: str = "restore") -> RollbackEvent:
    return RollbackEvent.objects.get(job=job, purpose=purpose)


def _start_rb(vm: Vm, run: BackupRun, **kw: Any) -> MigrationJob:
    kw.setdefault("accept_rollback", True)
    kw.setdefault("on_behalf_of", TENANT)
    job, created = restore.start_restore(
        vm=vm,
        run_id=run.run_id,
        request_id=kw.pop("request_id", f"req-{uuid.uuid4().hex[:8]}"),
        decided_by=make_service_client(),
        **kw,
    )
    assert created
    return job


def _refused(vm: Vm, run: BackupRun, **kw: Any) -> restore.RestoreError:
    with pytest.raises(restore.RestoreError) as exc:
        _start_rb(vm, run, **kw)
    assert not MigrationJob.objects.exists() and not RollbackEvent.objects.exists()
    return exc.value


def _to_dest_activating(fx: FakeEffects, job: MigrationJob) -> MigrationJob:
    _staged(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_STOPPING.value, job.reason
    fx.domain_running = False
    for _ in range(2):
        job = _advance(job)
        if job.state != MigrationState.RESTORE_STOPPING.value:
            break
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    return job


def _to_verifying(fx: FakeEffects, job: MigrationJob) -> MigrationJob:
    job = _to_dest_activating(fx, job)
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    return job


# ── intake: who may ask ──────────────────────────────────────────────


def test_a_rollback_point_is_admitted_and_recorded(kbs: FakeKbsRollback) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    job = _start_rb(vm, run, on_behalf_of={"kind": "superuser", "id": 9})
    auth = job.authorization
    assert auth.accept_rollback and (auth.on_behalf_of_kind, auth.on_behalf_of_id) == (
        "superuser",
        "9",
    )
    event = _ev(job)
    assert (event.from_boot_counter, event.to_boot_counter) == (7, 3)
    assert (event.requested_by_kind, event.requested_by_id) == ("superuser", "9")
    assert event.manifest_sha256 == run.manifest_sha256
    assert event.outcome == RollbackOutcome.PENDING
    view = restore.serialize(job)["rollback"]
    assert view["to_boot_counter"] == 3 and view["committed_at"] is None
    assert view["requested_by"] == {"kind": "superuser", "id": "9"}


def test_the_flag_off_keeps_rollback_unsupported(kbs: FakeKbsRollback, monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm)).code == "rollback-unsupported"


def test_a_point_without_a_checkpoint_is_refused(kbs: FakeKbsRollback) -> None:
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm, checkpoint=False)).code == "rollback-no-checkpoint"


def test_a_checkpoint_of_another_boot_counts_as_none(kbs: FakeKbsRollback) -> None:
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm, cp_counter=4)).code == "rollback-no-checkpoint"


@pytest.mark.parametrize(
    "behalf",
    [None, {"kind": "operator", "id": "x"}, {"kind": "tenant", "id": ""}, {"kind": "tenant"}],
)
def test_a_rollback_needs_on_behalf_of(kbs: FakeKbsRollback, behalf) -> None:
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm), on_behalf_of=behalf).code == "on-behalf-of-required"


@pytest.mark.parametrize("accept", [None, False])
def test_a_rollback_needs_accept_rollback(kbs: FakeKbsRollback, accept) -> None:
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm), accept_rollback=accept).code == "rollback-not-accepted"


def test_one_rollback_per_vm_per_interval(kbs: FakeKbsRollback) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    first = _start_rb(vm, run)
    MigrationJob.objects.filter(pk=first.pk).update(
        state=MigrationState.FAILED.value, finished_at=timezone.now()
    )
    RollbackEvent.objects.filter(job=first).update(
        arm_requested_at=timezone.now() - timedelta(seconds=600)
    )
    with pytest.raises(restore.RestoreError) as exc:
        _start_rb(vm, run)
    assert exc.value.code == "rollback-rate-limited"
    assert 1100 <= exc.value.extra["retry_after_s"] <= 1200
    RollbackEvent.objects.filter(job=first).update(
        arm_requested_at=timezone.now() - timedelta(seconds=1801)
    )
    assert _start_rb(vm, run).pk != first.pk


def test_a_kbs_without_the_routes_is_rollback_unsupported(kbs: FakeKbsRollback) -> None:
    kbs.route_missing = True
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm)).code == "rollback-unsupported"


def test_an_unreachable_kbs_is_restore_unavailable(kbs: FakeKbsRollback) -> None:
    kbs.unreachable = True
    vm = _golden_vm(counter=7)
    assert _refused(vm, _old_point(vm)).code == "restore-unavailable"


def test_a_current_boot_restore_is_never_armed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=3)
    job = _start_rb(vm, _chain(vm, counter=3)[-1])  # accept_rollback sent anyway
    assert not job.authorization.accept_rollback and not RollbackEvent.objects.exists()
    job = _to_verifying(fx, job)
    assert kbs.armed == [] and restore.serialize(job)["rollback"] is None


# ── a failover never rolls back ──────────────────────────────────────


def test_a_failover_refuses_a_rollback_point(kbs: FakeKbsRollback, monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", True)
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_failover(
            vm=vm, request_id="fo-1", run_id=run.run_id, decided_by=make_service_client()
        )
    assert exc.value.code == "rollback-unsupported"
    assert not MigrationJob.objects.exists()


def test_the_failover_route_takes_no_rollback_field(kbs: FakeKbsRollback, monkeypatch) -> None:
    from apps.backup.tests.conftest import ROOT, _bearer
    from apps.identity.models import PrincipalScope

    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", True)
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    api: APIClient = _bearer(ROOT, PrincipalScope.OPERATOR.value)
    for extra in ({"accept_rollback": True}, {"on_behalf_of": TENANT}):
        resp = api.post(
            f"/v1/vm/{vm.vm_id}/failover",
            {"request_id": "fo-1", "run_id": run.run_id, **extra},
            format="json",
        )
        assert resp.status_code == 400 and resp.json()["error"] == "bad-request"


def test_the_guard_refuses_a_failover_authorized_to_roll_back(
    fx: FakeEffects, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _restore_at_dest_activating(
        vm, kind="failover", job_kind=MigrationKind.FAILOVER.value, evidence={"dead": True}
    )
    DestAuthorization.objects.filter(pk=job.authorization_id).update(
        accept_rollback=True, on_behalf_of_kind="tenant", on_behalf_of_id="u"
    )
    job = MigrationJob.objects.select_related("authorization").get(pk=job.pk)
    assert service._migration_guard(job) == "failover-cannot-roll-back"
    assert not restore.is_rollback(job)


def test_the_guard_refuses_a_rollback_without_on_behalf_of(
    fx: FakeEffects, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _restore_at_dest_activating(vm, kind="restore")
    DestAuthorization.objects.filter(pk=job.authorization_id).update(accept_rollback=True)
    job = MigrationJob.objects.select_related("authorization").get(pk=job.pk)
    assert service._migration_guard(job) == "rollback-without-on-behalf-of"
    _advance(job)
    assert kbs.armed == [] and not fx.did("kbs_activate_dest")


# ── the arm ──────────────────────────────────────────────────────────


def test_the_arm_follows_the_activate_and_precedes_the_boot(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    job = _start_rb(vm, run)
    fx.restore_status = {}
    job = _advance(job)  # the stage order goes out
    job = _to_verifying(fx, job)
    order = [c[0] for c in fx.calls if c[0] in (
        "kbs_activate_dest", "authorize_rollback", "dispatch_migrate_activate"
    )]
    assert order[:3] == ["kbs_activate_dest", "authorize_rollback", "dispatch_migrate_activate"]
    (arm,) = kbs.armed
    assert arm == {
        "vm_id": vm.vm_id,
        "checkpoint_cbor_hex": "a0",
        "signature_hex": "ee" * 64,
        "manifest_sha256_hex": run.manifest_sha256,
        "manifest": run.manifest_json.encode("utf-8"),
        "new_gen": 6,
        "dest_platform_id_hex": SRC_CHIP,
        "restore_id": job.restore_id,
        "requested_by": "tenant:u-42",
        "ttl_s": 3600,
    }
    event = _ev(job)
    assert event.outcome == RollbackOutcome.ARMED and event.armed_at is not None
    # Staging carried the old boot's chain (allowed only for this job).
    stage = [p for _m, _o, p in fx.restore_orders if p["op"] == "stage"]
    assert stage and stage[0]["chain"]["restore_id"] == job.restore_id


def test_the_done_gate_waits_for_the_kbs_to_report_this_arm_consumed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _grant(fx, job)  # the KBS evidence at new_gen on the destination chip…
    kbs.last_rollback = {"restore_id": "cd" * 16}  # …but another restore's rollback
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value
    kbs.consume(job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    event = _ev(job)
    assert event.outcome == RollbackOutcome.COMMITTED and event.committed_at is not None
    assert event.kbs_record["restore_id"] == job.restore_id
    assert restore.serialize(job)["rollback"]["committed_at"] is not None
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE and vm.generation == 6


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (400, "bad-checkpoint-signature"),
        (400, "checkpoint-vm-mismatch"),
        (409, "not-a-rollback"),
        (409, "row-not-activated"),
        (409, "arm-exists"),
        (429, "rollback-rate-limited"),
        (400, "ttl-out-of-range"),
        (409, "checkpoint-unstamped"),
        (400, "manifest-mismatch"),
    ],
)
def test_every_kbs_refusal_reverts_before_the_boot(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, status, reason
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.refuse = (status, reason)
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == f"rollback-refused:{reason}"
    assert not fx.did("dispatch_migrate_activate"), "nothing booted without the arm"
    event = _ev(job)
    assert event.outcome == RollbackOutcome.REFUSED and event.reason == f"kbs:{reason}"
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert kbs.disarmed == [job.restore_id]
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 7)


def test_the_kbs_losing_the_route_mid_job_reverts(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.route_missing = True
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "rollback-unsupported"


def test_the_flag_turned_off_mid_job_fails_closed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    vm = _golden_vm(counter=7)
    job = _start_rb(vm, _old_point(vm))
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    fx.restore_status = {}
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "stage-rollback-unsupported"
    assert kbs.armed == [] and not fx.did("kbs_activate_dest")


def test_the_arm_is_refused_when_the_flag_went_off_after_staging(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "rollback-disabled" and kbs.armed == []


def test_an_unreachable_kbs_at_the_arm_is_retried_then_reverts(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.unreachable = True
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, "retried"
    assert not fx.did("dispatch_migrate_activate")
    # Still unreachable past the phase deadline. The KBS cannot say whether
    # a rollback committed — but nothing can have: the destination was never
    # dispatched and no ticket at `new_gen` exists. So it reverts.
    _age_phase(job, service._job_timeout(job) + 5)
    job = _advance(job)
    assert not fx.did("dispatch_migrate_activate")
    assert job.state == MigrationState.RESTORE_REVERTING.value, job.reason


# ── every failure withdraws the arm ─────────────────────────────────


def test_a_revert_after_the_arm_disarms_first(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    assert job.restore_id in kbs.arms
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    job = _advance(job)
    names = [c[0] for c in fx.calls]
    first_disarm = names.index("disarm")
    revert_activate = max(
        i for i, c in enumerate(fx.calls) if c[0] == "kbs_activate_dest" and c[3] == 7
    )
    assert first_disarm < revert_activate, "the arm is withdrawn before the fencing activate"
    assert job.restore_id not in kbs.arms
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert restore.sweep_rollback_events() == 1
    event = _ev(job)
    assert event.outcome == RollbackOutcome.ABANDONED and event.disarmed_at is not None


def test_a_revert_that_cannot_disarm_does_not_proceed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    kbs.disarm_fails = True
    calls = len(fx.calls)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert not [c for c in fx.calls[calls:] if c[0] == "kbs_activate_dest"]


def test_a_rollback_consumed_during_the_revert_blocks_it(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The 4b race: the restored guest released (consuming the arm) just
    before the disarm. Its evidence bundle is not there yet, but the KBS's
    rollback record is: the original is never relaunched into a 403."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    kbs.consume(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason == "revert-failed:blocked:revert-raced-commit:kbs-rollback-consumed"
    assert pwr.started == []
    restore.sweep_rollback_events()
    assert _ev(job).outcome == RollbackOutcome.COMMITTED


def test_a_failure_after_the_arm_is_disarmed_by_the_sweep(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """A job that ends without a revert (undecidable → failed for an
    operator) still never leaves its arm behind."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    fx.kbs_evidence = None  # undecidable
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.restore_id in kbs.arms
    kbs.disarm_fails = True
    assert restore.sweep_rollback_events() == 0
    assert _ev(job).outcome == RollbackOutcome.ARMED
    kbs.disarm_fails = False
    assert restore.sweep_rollback_events() == 1
    assert job.restore_id not in kbs.arms
    event = _ev(job)
    assert event.outcome == RollbackOutcome.ABANDONED and event.disarmed_at is not None


def test_a_cancelled_rollback_is_abandoned_without_touching_the_kbs(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _start_rb(vm, _old_point(vm))
    restore.cancel_restore(job=job, decided_by=make_service_client())
    kbs.unreachable = True
    assert restore.sweep_rollback_events() == 1
    event = _ev(job)
    assert event.outcome == RollbackOutcome.ABANDONED and event.armed_at is None


def test_the_tick_runs_the_rollback_sweep(monkeypatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr(restore, "sweep_rollback_events", lambda **kw: seen.append(True) or 0)
    service.tick_once()
    assert seen == [True]


# ── the API ──────────────────────────────────────────────────────────


def _api(monkeypatch) -> APIClient:
    from apps.backup.tests.conftest import ROOT, _bearer
    from apps.identity.models import PrincipalScope

    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    return _bearer(ROOT, PrincipalScope.OPERATOR.value)


def test_the_restore_route_carries_the_rollback_fields(kbs: FakeKbsRollback, monkeypatch) -> None:
    api = _api(monkeypatch)
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    body = {"run_id": run.run_id, "request_id": "r-1"}
    resp = api.post(f"/v1/vm/{vm.vm_id}/restore", body, format="json")
    assert resp.status_code == 400 and resp.json()["error"] == "on-behalf-of-required"
    resp = api.post(
        f"/v1/vm/{vm.vm_id}/restore", {**body, "on_behalf_of": TENANT}, format="json"
    )
    assert resp.status_code == 409 and resp.json()["error"] == "rollback-not-accepted"
    resp = api.post(
        f"/v1/vm/{vm.vm_id}/restore",
        {**body, "on_behalf_of": TENANT, "accept_rollback": True},
        format="json",
    )
    assert resp.status_code == 202, resp.json()
    assert resp.json()["rollback"]["requested_by"] == TENANT
    job = MigrationJob.objects.get()
    MigrationJob.objects.filter(pk=job.pk).update(
        state=MigrationState.FAILED.value, finished_at=timezone.now()
    )
    RollbackEvent.objects.update(arm_requested_at=timezone.now())
    resp = api.post(
        f"/v1/vm/{vm.vm_id}/restore",
        {**body, "request_id": "r-2", "on_behalf_of": TENANT, "accept_rollback": True},
        format="json",
    )
    assert resp.status_code == 429
    assert resp.json()["error"] == "rollback-rate-limited" and resp.json()["retry_after_s"] > 0


def test_the_backups_view_offers_a_checkpointed_old_point(
    kbs: FakeKbsRollback, monkeypatch
) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    bare = _chain(vm, counter=3, incrementals=0)[0]

    def point_of(r: BackupRun) -> dict[str, Any]:
        view = backup_service.backups_view(vm)
        return next(x for c in view["chains"] for x in c["runs"] if x["run_id"] == r.run_id)

    got = point_of(run)
    assert got["point"]["class"] == "rollback" and got["point"]["restorable"]
    assert got["has_checkpoint"] and got["manifest_sha256"] == run.manifest_sha256
    assert point_of(bare)["point"] == {**point_of(bare)["point"], "restorable": False}
    assert not point_of(bare)["has_checkpoint"]
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    assert not point_of(run)["point"]["restorable"]
    # The newest CURRENT-boot point is never a rollback one.
    assert backup_service.restore_point(vm) is None


def test_the_restore_id_dest_chip_is_the_one_armed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    from apps.miners.models import MinerIdentity
    from apps.scheduler import service as sched

    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    monkeypatch.setattr(
        sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None)
    )
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64)},
    )
    vm = _golden_vm(counter=7)
    job = _start_rb(vm, _old_point(vm), dest_node_id="node-dst")
    _to_verifying(fx, job)
    assert kbs.armed[0]["dest_platform_id_hex"] == DST_CHIP


def test_a_current_boot_restore_whose_vm_rebooted_is_never_rolled_back(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """Admitted as a current-boot restore; the guest reboots during staging,
    so its point is now of an earlier boot. Even with the flag on and a
    checkpoint on the run, a job not authorized as a rollback never becomes
    one: staging refuses."""
    from apps.backup.models import BackupPolicy

    vm = _golden_vm(counter=3)
    run = _old_point(vm)  # boot 3, checkpointed — current at intake
    job = _start_rb(vm, run, accept_rollback=None, on_behalf_of=None)
    assert not restore.is_rollback(job)
    BackupPolicy.objects.filter(vm=vm).update(observed_boot_counter=4)
    fx.restore_status = {}
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "stage-rollback-unsupported"
    assert kbs.armed == [] and not fx.did("kbs_activate_dest")


# ── review fixes: the KBS's own view, lost records, races ────────────


def test_intake_refuses_when_the_kbs_holds_an_arm_or_a_recent_rollback(
    kbs: FakeKbsRollback,
) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    kbs.arms["ef" * 16] = {"restore_id": "ef" * 16}
    assert _refused(vm, run).code == "job-in-flight"
    kbs.arms.clear()
    kbs.last_rollback = {
        "restore_id": "ef" * 16,
        "consumed_at_unix": int(timezone.now().timestamp()) - 60,
    }
    err = _refused(vm, run)
    assert err.code == "rollback-rate-limited" and 1700 <= err.extra["retry_after_s"] <= 1740


def test_a_lost_kbs_rollback_record_never_reverts_over_an_armed_restore(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The arm was live; then the KBS lost its rollback state (a restart, an
    older image) while the evidence bundle still shows the ORIGINAL's older
    grant. Nothing proves the arm unconsumed ⇒ never a revert (the original
    could boot into a 403): the job stops for an operator."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)  # stale, attributable, lower generation
    kbs.arms.clear()
    kbs.last_rollback = None
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason.startswith("blocked:commit-undecidable")
    assert pwr.started == []


def test_the_route_vanishing_after_the_arm_is_undecidable_too(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    kbs.route_missing = True
    assert restore.commit_state(job)[0] == restore.UNDECIDABLE


def test_a_release_between_the_sweeps_read_and_delete_is_recorded_committed(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    fx.kbs_evidence = None
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    real_disarm = kbs.disarm

    def consume_then_delete(vm_id: str, restore_id: str) -> None:
        kbs.consume(job)  # the release lands right before the DELETE
        real_disarm(vm_id, restore_id)

    monkeypatch.setattr(kbs_rollback, "disarm", consume_then_delete)
    assert restore.sweep_rollback_events() == 1
    event = _ev(job)
    assert event.outcome == RollbackOutcome.COMMITTED and event.committed_at is not None


def test_arm_rollback_refuses_a_job_not_authorized_as_a_rollback(
    fx: FakeEffects, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _restore_at_dest_activating(vm, kind="restore")
    MigrationJob.objects.filter(pk=job.pk).update(restore_run=_old_point(vm))
    job = MigrationJob.objects.select_related("authorization").get(pk=job.pk)
    with pytest.raises(restore.StepFailed, match="rollback-not-authorized"):
        restore.arm_rollback(job)
    DestAuthorization.objects.filter(pk=job.authorization_id).update(
        accept_rollback=True, on_behalf_of_kind="operator", on_behalf_of_id="x"
    )
    job = MigrationJob.objects.select_related("authorization").get(pk=job.pk)
    with pytest.raises(restore.StepFailed, match="rollback-without-on-behalf-of"):
        restore.arm_rollback(job)
    assert kbs.armed == []


def test_a_consumed_arm_is_a_commit_even_against_older_evidence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The KBS consumed this restore's arm but its evidence bundle (best
    effort) still shows the original's grant: the failure is AFTER the
    commit — the original is kept, never reverted over."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    kbs.consume(job)
    assert restore.commit_state(job) == (restore.COMMITTED, "kbs-rollback-consumed")
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason.startswith("failed-after-commit")


def test_a_delivered_rollback_that_fails_after_commit_still_tells_the_tenant(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The KBS delivered this restore's arm, then the job failed (verify
    timeout): the tenant-facing `rollback` block says it was rolled back
    (`committed_at`) right away — the layer above decides the email."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    kbs.consume(job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason.startswith("failed-after-commit")
    view = restore.serialize(job)["rollback"]
    assert view is not None and view["committed_at"] is not None
    assert view["to_boot_counter"] == 3
    event = _ev(job)
    assert event.outcome == RollbackOutcome.COMMITTED
    assert event.kbs_record["restore_id"] == job.restore_id


def test_a_kbs_restart_between_consume_and_verify_is_committed_unverified(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The restored disk released at `new_gen` (the evidence says so) but a
    KBS restart lost the `last_rollback` record before vali read it: the
    event is `committed-unverified`, never `abandoned:arm-not-found`."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.consume(job)
    kbs.last_rollback = None  # the KBS restarted
    _grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason.startswith("failed-after-commit")
    event = _ev(job)
    assert event.outcome == RollbackOutcome.COMMITTED_UNVERIFIED, event.reason
    assert event.committed_at is not None
    assert restore.serialize(job)["rollback"]["committed_at"] is not None
    assert restore.sweep_rollback_events() == 0, "settled already"


def test_the_sweep_records_committed_unverified_from_the_evidence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """Same, when the job ended without reading the evidence (the commit
    record not written then): the sweep reads it before calling the arm
    abandoned."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.consume(job)
    kbs.last_rollback = None
    _grant(fx, job)
    service._fail_migration(job, reason="failed-after-commit:test")
    assert _ev(job).committed_at is None
    assert restore.sweep_rollback_events() == 1
    event = _ev(job)
    assert event.outcome == RollbackOutcome.COMMITTED_UNVERIFIED, event.reason


def test_the_sweep_reads_the_evidence_when_the_arm_vanished_during_its_withdrawal(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    """Live at the first read, consumed inside the withdrawal race, its
    record then lost to a KBS restart: the release evidence at `new_gen`
    still makes it `committed-unverified`, not abandoned."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    service._fail_migration(job, reason="failed-after-commit:test")

    def consumed_then_restarted(vm_id: str, restore_id: str) -> None:
        kbs.arms.pop(restore_id, None)
        kbs.last_rollback = None
        _grant(fx, job)

    monkeypatch.setattr(kbs_rollback, "disarm", consumed_then_restarted)
    assert restore.sweep_rollback_events() == 1
    assert _ev(job).outcome == RollbackOutcome.COMMITTED_UNVERIFIED


def test_the_sweep_abandons_an_absent_arm_without_release_evidence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.arms.clear()
    _original_grant(fx, job)
    service._fail_migration(job, reason="failed-after-commit:test")
    assert restore.sweep_rollback_events() == 1
    event = _ev(job)
    assert event.outcome == RollbackOutcome.ABANDONED
    assert event.reason.startswith("arm-not-found")


def test_an_arm_gone_before_the_revert_could_withdraw_it_blocks_the_revert(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The revert finds no arm to withdraw (expired, or lost by a KBS
    restart) and no record of its consumption: nothing proves it was not
    consumed, so the original is not relaunched."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    kbs.arms.clear()
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and not job.reverted
    assert job.reason == "revert-failed:blocked:commit-undecidable:rollback-arm-unaccounted"
    assert _ev(job).disarmed_at is None
    assert pwr.started == []


# ── security review: unstamped, busy gateway, no rollback context, ───
# ── delivery, last_clear ─────────────────────────────────────────────


def test_an_unstamped_checkpoint_is_no_checkpoint(kbs: FakeKbsRollback) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    cp = {**run.kbs_checkpoint}
    cp["checkpoint"] = {**cp["checkpoint"], "volume_stamp": 0}
    manifest = _manifest_of(cp)
    BackupRun.objects.filter(pk=run.pk).update(
        kbs_checkpoint=cp,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        manifest_json=manifest.decode(),
    )
    run.refresh_from_db()
    assert backup_service.checkpoint_of(run) is None
    assert _refused(vm, run).code == "rollback-no-checkpoint"


def test_a_busy_kbs_gateway_at_the_arm_is_retried_not_reverted(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The fence is already down when the arm is asked: a transient 429 from
    the admin gateway must never throw the restore into a revert."""
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.busy = 1
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    assert not fx.did("dispatch_migrate_activate") and kbs.armed == []
    assert _ev(job).outcome == RollbackOutcome.PENDING
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    assert len(kbs.armed) == 1 and _ev(job).outcome == RollbackOutcome.ARMED


def test_a_kbs_without_its_rollback_context_reverts_at_once(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.unavailable = True
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "rollback-unsupported"
    assert not fx.did("dispatch_migrate_activate")


def test_intake_reads_rollback_unavailable_as_unsupported(kbs: FakeKbsRollback) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    kbs.unavailable = True
    assert _refused(vm, run).code == "rollback-unsupported"


def test_verifying_does_not_wait_out_a_kbs_without_rollbacks(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _grant(fx, job)
    kbs.unavailable = True
    job = _advance(job)  # no timeout needed
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "failed-after-commit:rollback-unsupported"


def test_the_done_gate_needs_the_release_delivered(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    _grant(fx, job)
    kbs.consume(job, delivered=False)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value
    kbs.last_rollback = {**kbs.last_rollback, "delivered": True, "reverted": True}
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value
    kbs.consume(job, delivered=True)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    assert _ev(job).outcome == RollbackOutcome.COMMITTED


def test_a_reverted_consumption_is_no_commit_for_the_revert(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The KBS consumed the arm but never delivered the release and took it
    back (`reverted`): the revert proceeds, it does not block as a raced
    commit."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.consume(job, delivered=False)
    kbs.last_rollback["reverted"] = True
    _original_grant(fx, job)
    assert restore.commit_state(job)[0] == restore.NOT_COMMITTED
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    for _ in range(3):
        job = _advance(job)
        if job.state == MigrationState.FAILED.value:
            break
    assert job.state == MigrationState.FAILED.value and job.reverted, job.reason
    assert _ev(job).outcome != RollbackOutcome.COMMITTED


def test_cleared_by_boot_resolves_an_unaccounted_arm_only_on_evidence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.arms.clear()  # the arm vanished; nothing says it was consumed
    kbs.last_rollback = None
    rid = _ev(job).restore_id
    _original_grant(fx, job)
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")
    # A clear of ANOTHER arm says nothing about this one.
    kbs.last_clear = {"restore_id": "cd" * 16, "reason": "rollback-cleared-by-boot", "at": 1}
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")
    kbs.last_clear = {"restore_id": rid, "reason": "rollback-expired", "at": 1}
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")
    kbs.last_clear = {"restore_id": rid, "reason": "rollback-cleared-by-boot", "at": 1}
    assert restore.commit_state(job)[0] == restore.NOT_COMMITTED
    # …but only with the positive evidence of a grant below `new_gen`.
    fx.kbs_evidence = None
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "no-kbs-evidence-bundle")


def test_the_original_is_checkpointed_right_before_the_fence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    names = [c[0] for c in fx.calls]
    # Taken while the domain is down and the KBS not yet moved.
    assert "fetch_checkpoint" in names and "kbs_activate_dest" not in names
    cp = job.original_checkpoint
    assert cp["checkpoint"]["boot_counter"] == 7 and cp["checkpoint_cbor_hex"] == "b1"
    manifest = job.original_manifest.encode()
    assert manifest == restore.original_manifest(job, cp)
    assert kbs_rollback.manifest_checkpoint_cbor_hex(manifest) == "b1"
    assert restore.original_checkpoint(job) is not None


@pytest.mark.parametrize(
    "failure", ["busy", "unreachable", "unavailable", "route_missing", "raises"]
)
def test_a_kbs_failure_at_the_checkpoint_never_holds_up_the_restore(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch, failure: str
) -> None:
    """The original's checkpoint is best effort: whatever the KBS does, the
    restore goes on (one attempt) — only the later undo is lost."""
    vm = _golden_vm(counter=7)
    job = _start_rb(vm, _old_point(vm))
    if failure == "busy":
        kbs.busy = 1
    elif failure == "raises":
        def _boom(vm_id: str, **_kw: Any) -> None:
            raise effects.EffectError("kbs-admin:rollback-checkpoint: 502 (test)")

        monkeypatch.setattr(kbs_rollback, "fetch_checkpoint", _boom)
    else:
        setattr(kbs, failure, True)
    _staged(fx, job)
    job = _advance(job)
    fx.domain_running = False
    job = _advance(job)  # the stop goes out
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    assert job.original_checkpoint is None and restore.original_checkpoint(job) is None


def test_the_checkpoint_is_asked_once_with_a_short_deadline(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback, monkeypatch
) -> None:
    seen: list[dict[str, Any]] = []
    real = kbs.fetch_checkpoint

    def _spy(vm_id: str, **kw: Any) -> kbs_rollback.Checkpoint:
        seen.append(kw)
        return real(vm_id, **kw)

    monkeypatch.setattr(kbs_rollback, "fetch_checkpoint", _spy)
    vm = _golden_vm(counter=7)
    _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    assert seen == [{"timeout": kbs_rollback.CHECKPOINT_TIMEOUT_S}]
    assert kbs_rollback.CHECKPOINT_TIMEOUT_S <= 10


def test_an_a1_restore_never_asks_the_kbs_for_a_checkpoint_with_rollbacks_off(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    """A1 regression guard: with the rollback flag off, the stop phase never
    calls the KBS checkpoint route (a busy KBS there once failed A1 restores)."""
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    calls: list[str] = []

    def _never(vm_id: str, **_kw: Any) -> None:
        calls.append(vm_id)
        raise kbs_rollback.KbsRateLimited("kbs-admin (test)", retry_after_s=1)

    monkeypatch.setattr(kbs_rollback, "fetch_checkpoint", _never)
    vm = _golden_vm()
    job = _tr._start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    fx.domain_running = False
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    assert calls == [] and job.original_checkpoint is None


def test_a_rollback_in_flight_decides_nothing_until_it_settles(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """Consumed, neither delivered nor reverted: the release is being
    processed and may still deliver. Neither a commit nor a revert — and
    the revert's withdrawal waits for the KBS to settle it."""
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    kbs.consume(job, delivered=False)
    _original_grant(fx, job)
    with pytest.raises(effects.EffectError):
        restore.commit_state(job)
    _age_phase(job, 1000)  # past the phase deadline, not twice it
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, "nothing decided"
    with pytest.raises(effects.EffectError):
        restore.disarm_rollback(vm.vm_id, _ev(job))
    kbs.last_rollback["reverted"] = True  # the withdrawal made the KBS revert it
    assert restore.disarm_rollback(vm.vm_id, _ev(job))[0] == restore.DISARM_ABSENT


def test_an_arm_refused_before_any_dispatch_reverts_without_evidence(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    """The KBS restarted without its rollback context AND lost its evidence
    bundles: the arm fails before the destination was ever told to boot and
    before vali minted any ticket at `new_gen` — nothing can have released,
    so the restore reverts instead of blocking for an operator."""
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.unavailable = True
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value, job.reason
    assert not fx.did("dispatch_migrate_activate")
    assert restore.commit_state(job) == (restore.NOT_COMMITTED, "never-dispatched")


def test_a_dispatched_restore_is_never_read_as_undispatched(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_verifying(fx, _start_rb(vm, _old_point(vm)))
    assert job.authorization.evidence.get("dest_dispatch_at")
    kbs.arms.clear()
    fx.kbs_evidence = None
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")
    # A job dispatched before the write-ahead existed: the ticket vali minted
    # at `new_gen` still says it went out.
    from apps.orders.models import OrderTicketIntake

    evidence = {**job.authorization.evidence}
    evidence.pop("dest_dispatch_at")
    DestAuthorization.objects.filter(pk=job.authorization_id).update(evidence=evidence)
    job.refresh_from_db()
    assert restore.commit_state(job) == (restore.NOT_COMMITTED, "never-dispatched")
    OrderTicketIntake.objects.create(
        ticket_id="tk-legacy",
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen,
        issue_time=0,
        expiry=0,
        node_id=job.dest_node_id,
        platform_id=SRC_CHIP,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    assert restore.commit_state(job) == (restore.UNDECIDABLE, "rollback-arm-unaccounted")


# ── rollback_capable (guest stamp protocol v2) ───────────────────────


def test_a_guest_the_kbs_says_is_not_rollback_capable_is_refused_at_intake(
    fx: FakeEffects, kbs: FakeKbsRollback, monkeypatch
) -> None:
    kbs.capable = False
    vm = _golden_vm(counter=7)
    before = (vm.state, vm.host, vm.generation)
    run = _old_point(vm)
    assert _refused(vm, run).code == "rollback-not-capable"
    assert kbs.armed == [] and not [c for c in fx.calls if c[0] != "fetch_checkpoint"]
    resp = _api(monkeypatch).post(
        f"/v1/vm/{vm.vm_id}/restore",
        {"run_id": run.run_id, "request_id": "r-1", "on_behalf_of": TENANT,
         "accept_rollback": True},
        format="json",
    )
    assert resp.status_code == 409 and resp.json()["error"] == "rollback-not-capable"
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == before
    kbs.capable = True
    assert _start_rb(vm, run).pk


def test_guest_not_rollback_capable_at_the_arm_reverts_before_the_boot(
    fx: FakeEffects, pwr: _Power, kbs: FakeKbsRollback
) -> None:
    vm = _golden_vm(counter=7)
    job = _to_dest_activating(fx, _start_rb(vm, _old_point(vm)))
    kbs.refuse = (409, kbs_rollback.REASON_GUEST_NOT_ROLLBACK_CAPABLE)
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "rollback-not-capable"
    assert not fx.did("dispatch_migrate_activate"), "nothing booted without the arm"
    event = _ev(job)
    assert event.outcome == RollbackOutcome.REFUSED
    assert event.reason == "kbs:guest-not-rollback-capable"
    # The listing learns it at once, without another KBS read.
    reads = kbs.status_reads
    assert kbs_rollback.rollback_capable_cached(vm.vm_id) is False
    assert kbs.status_reads == reads
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 7)


def _view_point(vm: Vm, run: BackupRun) -> tuple[dict[str, Any], dict[str, Any]]:
    from apps.backup import service as backup_service

    view = backup_service.backups_view(vm)
    got = next(x for c in view["chains"] for x in c["runs"] if x["run_id"] == run.run_id)
    return view, got["point"]


def test_the_backups_view_carries_rollback_capable_and_gates_rollback_points(
    kbs: FakeKbsRollback, monkeypatch
) -> None:
    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    view, point = _view_point(vm, run)
    assert view["rollback_capable"] is True
    assert point["class"] == "rollback" and point["restorable"] is True

    from django.core.cache import cache

    cache.clear()
    kbs.capable = False
    view, point = _view_point(vm, run)
    assert view["rollback_capable"] is False
    assert point["class"] == "rollback" and point["restorable"] is False
    # Over the API too.
    resp = _api(monkeypatch).get(f"/v1/vm/{vm.vm_id}/backups")
    assert resp.status_code == 200, resp.content
    assert resp.json()["rollback_capable"] is False

    cache.clear()
    kbs.capable = True
    kbs.unreachable = True
    view, point = _view_point(vm, run)
    assert view["rollback_capable"] is None
    # Unknown is not "yes": only a KBS that positively says the guest takes
    # a rollback makes a rollback point restorable.
    assert point["class"] == "rollback" and point["restorable"] is False


@pytest.mark.parametrize(
    ("capable", "rollback_restorable"), [(True, True), (False, False), (None, False)]
)
def test_a_rollback_point_is_restorable_only_when_the_kbs_says_capable(
    kbs: FakeKbsRollback, capable: bool | None, rollback_restorable: bool
) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    rb = backup_service.Point(run=run, klass=backup_service.PointClass.ROLLBACK, runs=(run,))
    assert rb.restorable, "the point itself is rollback-ready"
    got = backup_service._point_view(rb, throughput_bps=1, rollback_capable=capable)
    assert got["class"] == "rollback" and got["restorable"] is rollback_restorable
    # A current-boot point never depends on it.
    cur = backup_service.Point(
        run=run, klass=backup_service.PointClass.CURRENT_BOOT, runs=(run,)
    )
    got = backup_service._point_view(cur, throughput_bps=1, rollback_capable=capable)
    assert got["restorable"] is True


def test_the_backups_view_reads_the_kbs_at_most_once_a_minute(
    kbs: FakeKbsRollback, monkeypatch
) -> None:
    from django.core.cache import cache

    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    for _ in range(3):
        _view_point(vm, run)
    assert kbs.status_reads == 1
    # An unanswered read is remembered too: a down KBS is not hammered.
    cache.clear()
    kbs.unreachable = True
    for _ in range(3):
        assert _view_point(vm, run)[0]["rollback_capable"] is None
    assert kbs.status_reads == 2
    # The intake never trusts the cache: it reads afresh and refreshes it.
    kbs.unreachable = False
    kbs.capable = False
    assert _refused(vm, run).code == "rollback-not-capable"
    assert kbs.status_reads == 3
    assert _view_point(vm, run)[0]["rollback_capable"] is False
    assert kbs.status_reads == 3


def test_the_backups_view_asks_nothing_while_rollbacks_are_off(
    kbs: FakeKbsRollback, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False)
    vm = _golden_vm(counter=7)
    view, point = _view_point(vm, _old_point(vm))
    assert view["rollback_capable"] is None and kbs.status_reads == 0
    assert point["class"] == "rollback" and point["restorable"] is False


def test_the_backups_run_schema_declares_every_field_the_view_returns(
    kbs: FakeKbsRollback,
) -> None:
    """Swagger: `BackupRunSerializer` documents exactly what a run carries
    (`has_checkpoint`, `manifest_sha256` included)."""
    from apps.backup.schemas import BackupRunSerializer

    vm = _golden_vm(counter=7)
    run = _old_point(vm)
    _view, _point = _view_point(vm, run)
    got = next(
        x for c in _view["chains"] for x in c["runs"] if x["run_id"] == run.run_id
    )
    assert set(BackupRunSerializer().fields) == set(got)
    assert {"has_checkpoint", "manifest_sha256"} <= set(BackupRunSerializer().fields)


# ── customer-held keys: an M2 rollback is the customer's (H6b) ────────


def _keyed(vm: Vm, mode: str) -> Vm:
    Vm.objects.filter(pk=vm.pk).update(key_mode=mode)
    vm.refresh_from_db()
    return vm


def test_an_m2_rollback_needs_the_customers_authorization(kbs: FakeKbsRollback) -> None:
    vm = _keyed(_golden_vm(counter=7), "customer")
    run = _old_point(vm)
    err = _refused(vm, run)
    assert err.code == "customer-rollback-authorization-required"
    assert f"guardian authorize-rollback {vm.vm_id}" in err.detail
    assert "customer_authorized: true" in err.detail
    assert run.run_id in err.detail
    # The KBS was neither asked to authorize nor even read.
    assert kbs.armed == [] and kbs.status_reads == 0
    assert ("authorize_rollback", vm.vm_id, 6) not in kbs.fx.calls


def test_an_m2_rollback_is_never_armed_at_the_kbs_even_once_authorized(
    kbs: FakeKbsRollback,
) -> None:
    """The customer authorized it on their guardian; the KBS boot-counter
    fence has no M2 rollback, so vali refuses before touching the VM (and
    never asks the KBS to authorize an M2 rollback)."""
    vm = _keyed(_golden_vm(counter=7), "customer")
    err = _refused(vm, _old_point(vm), customer_authorized=True)
    assert err.code == "rollback-not-capable"
    assert "customer's guardian" in err.detail and "Nothing was touched" in err.detail
    assert kbs.armed == [] and kbs.status_reads == 0


@pytest.mark.parametrize("customer_authorized", [None, True, False])
def test_an_m1_rollback_is_the_kbs_ceremony_as_today(
    kbs: FakeKbsRollback, customer_authorized: bool | None
) -> None:
    vm = _keyed(_golden_vm(counter=7), "split")
    job = _start_rb(vm, _old_point(vm), customer_authorized=customer_authorized)
    assert restore.is_rollback(job)
    assert kbs.status_reads == 1  # the KBS gate ran, as for M0


def test_customer_authorized_must_be_a_boolean(kbs: FakeKbsRollback) -> None:
    vm = _keyed(_golden_vm(counter=7), "customer")
    assert _refused(vm, _old_point(vm), customer_authorized="yes").code == "bad-request"


def test_an_m2_current_boot_restore_needs_no_authorization(kbs: FakeKbsRollback) -> None:
    """A1 is not a rollback: the point's stamp is the guardian's current
    one, so it just needs the guardian up at boot."""
    vm = _keyed(_golden_vm(counter=3), "customer")
    job = _start_rb(vm, _chain(vm, counter=3)[-1], accept_rollback=None, on_behalf_of=None)
    assert not restore.is_rollback(job)
    assert kbs.status_reads == 0


def test_the_kbs_gate_and_the_arm_refuse_an_m2_vm(fx: FakeEffects, kbs: FakeKbsRollback) -> None:
    """Defence in depth behind the intake: the undo's gate and the arm
    itself never reach the KBS for an M2 VM."""
    vm = _golden_vm(counter=7)
    job = _start_rb(vm, _old_point(vm))
    _keyed(vm, "customer")
    reads = kbs.status_reads
    with pytest.raises(restore.RestoreError) as exc:
        restore._rollback_gate(Vm.objects.get(pk=vm.pk))
    assert exc.value.code == "rollback-not-capable"
    job = MigrationJob.objects.select_related("authorization", "vm", "restore_run").get(pk=job.pk)
    with pytest.raises(restore.StepFailed, match="rollback-not-capable"):
        restore.arm_rollback(job)
    assert kbs.armed == [] and kbs.status_reads == reads


def test_the_restore_route_carries_customer_authorized(kbs: FakeKbsRollback, monkeypatch) -> None:
    api = _api(monkeypatch)
    vm = _keyed(_golden_vm(counter=7), "customer")
    run = _old_point(vm)
    body = {
        "run_id": run.run_id,
        "request_id": "r-m2",
        "on_behalf_of": TENANT,
        "accept_rollback": True,
    }
    resp = api.post(f"/v1/vm/{vm.vm_id}/restore", body, format="json")
    assert resp.status_code == 409
    assert resp.json()["error"] == "customer-rollback-authorization-required"
    resp = api.post(
        f"/v1/vm/{vm.vm_id}/restore", {**body, "customer_authorized": True}, format="json"
    )
    assert resp.status_code == 409 and resp.json()["error"] == "rollback-not-capable"
    assert not MigrationJob.objects.exists()
