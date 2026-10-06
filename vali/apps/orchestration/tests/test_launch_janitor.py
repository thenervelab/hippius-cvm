"""A `running` launch job whose worker died is resolved from the facts.

`claim_one` only picks `queued`, so a launch worker that crashes (or is
killed by a deploy) mid-launch leaves its job `running` for ever — and the
in-flight unique index then refuses any new launch of that `vm_id`.
`launch_jobs.reap_orphaned_launch_jobs` (run by the orchestration tick)
closes it: completed when the VM is live on a host, failed when no guest
can exist, left alone when vali cannot tell.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import launch_jobs, service
from apps.orchestration.models import LaunchJob, LaunchJobState, LaunchPhase
from apps.scheduler.models import Placement, PlacementFailureSource, PlacementStatus

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

HOST = "cd" * 32


@pytest.fixture(autouse=True)
def _fresh_warn_memo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch_jobs, "_orphan_warned", set())


@pytest.fixture(autouse=True)
def _miner() -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="miner-b", pubkey_hex="11" * 32, platform_id="aa" * 64, chain_node_id=HOST
    )


def _job(
    vm_id: str = "vm-1",
    *,
    phase: str = LaunchPhase.DISPATCHING.value,
    age_s: int = 4 * 3600,
    state: str = LaunchJobState.RUNNING.value,
) -> LaunchJob:
    return LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=state,
        phase=phase,
        phase_started_at=timezone.now() - timedelta(seconds=age_s),
        decided_by=make_service_client(),
    )


def _pending(vm: Vm, node: str = HOST, **kw: Any) -> Placement:
    return Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=node,
        status=kw.pop("status", PlacementStatus.PENDING.value),
        chain_epoch=10,
        decided_by=make_service_client(),
        **kw,
    )


def _reap() -> tuple[int, int]:
    return launch_jobs.reap_orphaned_launch_jobs()


def test_a_dead_workers_job_for_a_vm_live_on_its_host_is_completed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `Vm.host` is stamped only on an ACCEPTED dispatch: the launch happened.
    vm = make_vm("vm-1", host="miner-b")
    job = _job()
    _pending(vm)  # the job's own placement, on the host...
    Vm.objects.filter(pk=vm.pk).update(boot_phase="running", boot_phase_at=timezone.now())
    errors: list[str] = []
    monkeypatch.setattr(launch_jobs.log, "error", lambda msg, *a: errors.append(msg % a))

    assert _reap() == (1, 0)

    job.refresh_from_db()
    assert (job.state, job.phase, job.miner_id) == (
        LaunchJobState.SUCCEEDED.value,
        LaunchPhase.LAUNCHED.value,
        "miner-b",
    )
    assert job.finished_at is not None
    assert len(errors) == 1
    assert _reap() == (0, 0)


def test_a_young_phase_is_a_launch_still_working_and_is_never_touched() -> None:
    # 20 min in `dispatching`: inside one miner preflight. (Old, the same
    # facts would complete it — only its age protects it.)
    vm = make_vm("vm-1", host="miner-b")
    job = _job(age_s=20 * 60)
    _pending(vm, status=PlacementStatus.BOUND.value, bound_at=timezone.now())

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value


def test_a_queued_job_is_not_an_orphan() -> None:
    # Never claimed: the worker is down or busy, not dead mid-launch.
    job = _job(state=LaunchJobState.QUEUED.value, phase=LaunchPhase.QUEUED.value)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.QUEUED.value


@pytest.mark.parametrize(
    ("make_row", "why"),
    [
        (lambda: None, "no-vm-row"),
        (lambda: make_vm("vm-1", state=VmState.DESTROYED.value, host=""), "vm-destroyed"),
    ],
)
def test_a_job_whose_vm_is_gone_is_failed(make_row: Any, why: str) -> None:
    make_row()
    job = _job()

    assert _reap() == (0, 1)
    job.refresh_from_db()
    assert (job.state, job.reason) == (LaunchJobState.FAILED.value, f"orphaned:{why}")


@pytest.mark.parametrize(
    "phase",
    [LaunchPhase.QUEUED.value, LaunchPhase.STAGING.value, LaunchPhase.PLACING.value, ""],
)
def test_a_job_that_never_dispatched_is_failed(phase: str) -> None:
    vm = make_vm("vm-1", host="")
    job = _job(phase=phase)

    assert _reap() == (0, 1)

    job.refresh_from_db()
    assert (job.state, job.reason) == (LaunchJobState.FAILED.value, "orphaned:never-dispatched")
    # The phantom row is handed to the abandoned-launch sweep.
    vm.refresh_from_db()
    assert vm.launch_abandoned_outcome == "orphaned-launch-job"
    assert vm.launch_abandoned_registered is False


@pytest.mark.parametrize(
    "accept_evidence",
    [
        {},  # none: died before the host accepted
        {"boot_phase": "running", "boot_phase_at": "before-job"},
        {"guest_signal_at": "before-job"},
    ],
)
def test_a_pending_on_a_host_an_earlier_launch_stamped_is_not_success(
    accept_evidence: dict[str, Any],
) -> None:
    # `host=miner-b` is the EARLIER launch's; this job placed on miner-b
    # again and died before the accept. Guest signals older than the job
    # are the earlier guest's, not evidence for this one.
    vm = make_vm("vm-1", host="miner-b")
    before = timezone.now() - timedelta(days=1)
    Vm.objects.filter(pk=vm.pk).update(
        **{k: (before if v == "before-job" else v) for k, v in accept_evidence.items()}
    )
    job = _job()
    _pending(vm)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value


def test_a_host_left_by_an_earlier_launch_is_not_this_jobs_success() -> None:
    # The earlier launch's placement was drained, so this job placed again
    # — on ANOTHER miner — and died dispatching. `Vm.host` is the earlier
    # launch's; nothing proves this job launched anything.
    vm = make_vm("vm-1", host="miner-b")
    job = _job()
    _pending(vm, "ef" * 32)
    # Even with a fresh guest signal: this job's placement is elsewhere.
    Vm.objects.filter(pk=vm.pk).update(boot_phase="running", boot_phase_at=timezone.now())

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value


def test_a_placement_from_before_the_job_does_not_block_never_dispatched() -> None:
    # A Bound placement the EARLIER launch opened is not this job's.
    vm = make_vm("vm-1", host="miner-b")
    old = _pending(vm, status=PlacementStatus.BOUND.value, bound_at=timezone.now())
    Placement.objects.filter(pk=old.pk).update(decided_at=timezone.now() - timedelta(days=2))
    job = _job(phase=LaunchPhase.STAGING.value)

    assert _reap() == (0, 1)
    job.refresh_from_db()
    assert job.reason == "orphaned:never-dispatched"


def test_a_closed_job_grows_no_phase_afterwards() -> None:
    # A worker that was only slow must not paint `dispatching` over a job
    # the janitor already failed.
    job = _job(phase=LaunchPhase.PLACING.value)
    LaunchJob.objects.filter(pk=job.pk).update(
        state=LaunchJobState.FAILED.value, finished_at=timezone.now()
    )

    launch_jobs._set_phase(job, LaunchPhase.DISPATCHING)

    job.refresh_from_db()
    assert job.phase == LaunchPhase.PLACING.value


def test_a_second_launch_of_a_bound_vm_is_never_credited_with_it() -> None:
    # The VM already runs on miner-b from an EARLIER launch; this job died
    # in `staging` and dispatched nothing. It must not read as succeeded,
    # and the live VM's row must not be marked abandoned.
    vm = make_vm("vm-1", host="miner-b")
    job = _job(phase=LaunchPhase.STAGING.value)

    assert _reap() == (0, 1)

    job.refresh_from_db()
    assert job.reason == "orphaned:never-dispatched"
    vm.refresh_from_db()
    assert vm.launch_abandoned_at is None


def test_a_placement_opened_by_the_job_makes_never_dispatched_unprovable() -> None:
    # `dispatching` is emitted right after the Pending placement is
    # recorded, and a phase write is fail-open: the placement is the
    # evidence the job may have gone further than its phase says.
    vm = make_vm("vm-1", host="")
    job = _job(phase=LaunchPhase.PLACING.value)
    pending = _pending(vm)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.PENDING.value


def test_a_dispatch_with_no_host_and_a_day_of_silence_is_failed_and_released() -> None:
    vm = make_vm("vm-1", host="")
    job = _job(age_s=25 * 3600)
    pending = _pending(vm)

    assert _reap() == (0, 1)

    job.refresh_from_db()
    assert job.reason == "orphaned:no-guest-evidence"
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.FAILED.value
    assert pending.reason == "released:orphaned-launch"
    # Never a refusal: the circuit breaker's view of the miner is untouched.
    assert pending.failure_source == PlacementFailureSource.RELEASE.value
    assert pending.version == 2
    # Handed to the abandoned-launch sweep — saying the register is unknown.
    vm.refresh_from_db()
    assert vm.launch_abandoned_outcome == "orphaned-launch-job:register-unknown"


@pytest.mark.parametrize(
    "evidence",
    [
        {"boot_phase": "booting"},
        {"guest_signal_at": timezone.now()},
    ],
)
def test_any_sign_of_a_guest_keeps_a_hostless_dispatch_open(evidence: dict[str, Any]) -> None:
    vm = make_vm("vm-1", host="")
    Vm.objects.filter(pk=vm.pk).update(**evidence)
    job = _job(age_s=25 * 3600)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value


@pytest.mark.parametrize(
    ("state", "host", "age_s"),
    [
        # Died in `dispatching` with no host, 4 h ago: the dispatch may
        # have timed out while the miner still booted the guest.
        (VmState.ACTIVE.value, "", 4 * 3600),
        # Its guest may still run until the §24 stop.
        (VmState.DECOMMISSIONING.value, "miner-b", 4 * 3600),
    ],
)
def test_an_uncertain_orphan_is_left_and_warned_once(
    monkeypatch: pytest.MonkeyPatch, state: str, host: str, age_s: int
) -> None:
    vm = make_vm("vm-1", state=state, host=host)
    job = _job(age_s=age_s)
    if host:
        # Opened by this job, on the host, with a fresh guest signal — so
        # only the VM's `decommissioning` state holds it back.
        Vm.objects.filter(pk=vm.pk).update(boot_phase="running", boot_phase_at=timezone.now())
    pending = _pending(vm)
    warnings: list[str] = []
    monkeypatch.setattr(launch_jobs.log, "warning", lambda msg, *a: warnings.append(msg % a))

    assert _reap() == (0, 0)
    assert _reap() == (0, 0)

    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.PENDING.value
    assert len(warnings) == 1


def test_a_worker_that_moves_on_after_the_verdict_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    # A phase write does not bump `version`: the janitor's CAS must also
    # fence on the phase it judged, or a slow worker that just reached
    # `dispatching` would be failed as never-dispatched.
    make_vm("vm-1", host="")
    job = _job(phase=LaunchPhase.PLACING.value)
    real_finish = launch_jobs._finish

    def _worker_advances_first(j: LaunchJob, *a: Any, **kw: Any) -> bool:
        LaunchJob.objects.filter(pk=j.pk).update(
            phase=LaunchPhase.DISPATCHING.value, phase_started_at=timezone.now()
        )
        return real_finish(j, *a, **kw)

    monkeypatch.setattr(launch_jobs, "_finish", _worker_advances_first)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value


def test_the_orphan_bound_never_drops_below_twice_the_longest_phase(
    settings: Any,
) -> None:
    # 1 + 2 retries × 30 min preflight = 90 min; floor = 3 h.
    settings.VALI_LAUNCH_JOB_ORPHAN_S = 60
    assert launch_jobs.launch_job_orphan_after_s() == 3 * 3600
    settings.VALI_PREFLIGHT_TIMEOUT_SECS = 3600
    assert launch_jobs.launch_job_orphan_after_s() == 6 * 3600


def test_a_worker_that_finishes_first_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    # The janitor judged it (a day-silent hostless dispatch ⇒ fail + release),
    # then the slow worker's own terminal CAS landed: the janitor's
    # `_finish` must lose, and release and mark nothing.
    vm = make_vm("vm-1", host="")
    pending = _pending(vm)
    job = _job(age_s=25 * 3600)
    real_finish = launch_jobs._finish

    def _worker_wins_first(j: LaunchJob, *a: Any, **kw: Any) -> bool:
        LaunchJob.objects.filter(pk=j.pk).update(
            state=LaunchJobState.SUCCEEDED.value,
            version=j.version + 1,
            finished_at=timezone.now(),
        )
        return real_finish(j, *a, **kw)

    monkeypatch.setattr(launch_jobs, "_finish", _worker_wins_first)

    assert _reap() == (0, 0)
    job.refresh_from_db()
    assert job.state == LaunchJobState.SUCCEEDED.value
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.PENDING.value
    vm.refresh_from_db()
    assert vm.launch_abandoned_at is None


def test_the_tick_runs_the_janitor_and_reports_it() -> None:
    vm = make_vm("vm-1", host="miner-b")
    _job()
    _pending(vm, status=PlacementStatus.BOUND.value, bound_at=timezone.now())

    report = service.tick_once()

    assert (report.orphan_launches_completed, report.orphan_launches_failed) == (1, 0)
