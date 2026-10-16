"""A §24 that arrives before the async launch created the `Vm` row.

`POST /v1/vm/launch` only queues a job; the single launch worker creates
the row when it claims the job, which can be minutes later. On 2026-10-08
the owner of a queued launch decommissioned it a minute after asking for
it: `POST /v1/vm/<id>/decommission` answered `404 not-found`, the owner
filed the VM as gone, and the worker launched it two minutes later. Nobody
owned that VM; it stayed `active` for eight days.

A `404` must therefore mean "no launch will ever create this VM":

- a queued launch is cancelled, then `404`;
- a running launch that has not created the row is told not to, and the
  caller gets `409 job-in-flight` (asked again, it then reads `404`);
- a row created by a launch still dispatching gets the ordinary §24,
  which that launch's later steps already respect.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from django.db import connection, connections, transaction
from django.urls import reverse
from rest_framework import status

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import launch_jobs
from apps.orchestration.models import DecommissionJob, LaunchJob, LaunchJobState, LaunchPhase
from apps.orchestration.services import launch

from .factories import make_vm
from .test_launch_api import _intent, _stub_secrets, stub_vault_put  # noqa: F401 — fixture

pytestmark = pytest.mark.usefixtures("located_fr")

VM_ID = "vm-api-1"
LAUNCH_URL = reverse("vm_launch")


def _decommission(client) -> Any:
    return client.post(reverse("vm_decommission", kwargs={"vm_id": VM_ID}), {}, format="json")


def _queue(client) -> LaunchJob:
    resp = client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    return LaunchJob.objects.get(job_id=resp.json()["job_id"])


def _spec_of(job: LaunchJob) -> launch.LaunchSpec:
    return launch.LaunchSpec(**job.spec_json, kek_bytes=None, userdata=b"#cloud-config\n")


def _creates_the_row(spec, decided_by, *, on_phase=None, queued_for_s=0.0):
    """A `launch_vm` that does what the real one does first: create the
    row (`_place_and_launch` → `_ensure_vm_row`), then accept."""
    launch._ensure_vm_row(spec)
    return launch.LaunchResult(ok=True, outcome="miner-accepted", vm_id=spec.vm_id, emit={})


@pytest.mark.django_db
def test_a_queued_launch_is_cancelled_and_never_runs(
    root_client, stub_vault_put, monkeypatch  # noqa: F811
) -> None:
    """THE INCIDENT. The job is queued behind another launch; the owner
    decommissions it. Before: `404`, and the worker launched it later."""
    job = _queue(root_client)

    resp = _decommission(root_client)

    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert resp.json()["category"] == "not-found"
    job.refresh_from_db()
    assert job.state == LaunchJobState.FAILED.value
    assert job.reason == launch_jobs.CANCELLED_BY_DECOMMISSION
    assert job.phase == LaunchPhase.FAILED.value
    assert job.finished_at is not None and job.cancel_requested_at is not None

    _stub_secrets(monkeypatch)
    monkeypatch.setattr(launch_jobs.launch, "launch_vm", _creates_the_row)
    assert launch_jobs.tick_once() is False
    assert not Vm.objects.filter(vm_id=VM_ID).exists()


@pytest.mark.django_db
def test_a_second_decommission_of_a_cancelled_launch_changes_nothing(
    root_client, stub_vault_put  # noqa: F811
) -> None:
    job = _queue(root_client)
    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND
    job.refresh_from_db()
    first = (job.state, job.version, job.finished_at, job.cancel_requested_at)

    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND

    job.refresh_from_db()
    assert (job.state, job.version, job.finished_at, job.cancel_requested_at) == first


@pytest.mark.django_db
def test_a_running_launch_is_told_not_to_create_the_row(
    root_client, stub_vault_put, monkeypatch  # noqa: F811
) -> None:
    """Claimed, still placing (no row yet) when the §24 arrives: `409`,
    and the worker then refuses to create the row. Asked again: `404`."""
    _queue(root_client)
    _stub_secrets(monkeypatch)
    answers: list[int] = []

    def decommissioned_while_placing(spec, decided_by, **kw):
        answers.append(_decommission(root_client).status_code)
        return _creates_the_row(spec, decided_by, **kw)

    monkeypatch.setattr(launch_jobs.launch, "launch_vm", decommissioned_while_placing)

    assert launch_jobs.tick_once() is True

    assert answers == [status.HTTP_409_CONFLICT]
    job = LaunchJob.objects.get(vm_id=VM_ID)
    assert job.state == LaunchJobState.FAILED.value
    assert job.reason == launch_jobs.CANCELLED_BY_DECOMMISSION
    assert not Vm.objects.filter(vm_id=VM_ID).exists()
    resp = _decommission(root_client)
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert resp.json()["category"] == "not-found"


@pytest.mark.django_db
def test_the_running_answer_is_one_the_caller_retries(
    root_client, stub_vault_put  # noqa: F811
) -> None:
    """The caller reads `409 job-in-flight` as "ask again", never as gone."""
    job = _queue(root_client)
    assert launch_jobs.claim_one() is not None

    resp = _decommission(root_client)

    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "job-in-flight"
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value
    assert job.cancel_requested_at is not None


@pytest.mark.django_db
def test_the_real_launch_path_refuses_a_cancelled_job(
    root_client, stub_vault_put, monkeypatch  # noqa: F811
) -> None:
    """Through the REAL `launch_vm`: the refusal is in `_ensure_vm_row`, the
    first thing `_place_and_launch` does, so nothing is placed either."""
    _queue(root_client)
    claimed = launch_jobs.claim_one()
    assert _decommission(root_client).status_code == status.HTTP_409_CONFLICT
    _stub_secrets(monkeypatch)
    placed: list[Any] = []
    monkeypatch.setattr(
        "apps.scheduler.chain.read_miner_status", lambda: placed.append(1)
    )

    launch_jobs.run_job(claimed)

    job = LaunchJob.objects.get(vm_id=VM_ID)
    assert job.state == LaunchJobState.FAILED.value
    assert job.reason == launch_jobs.CANCELLED_BY_DECOMMISSION
    assert placed == []
    assert not Vm.objects.filter(vm_id=VM_ID).exists()


@pytest.mark.django_db
def test_a_row_created_by_a_launch_still_dispatching_gets_the_ordinary_decommission(
    root_client, stub_vault_put  # noqa: F811
) -> None:
    """The row exists, its launch has not settled: the ordinary §24 starts
    (the launch's KBS register is refused once the row leaves `active`, and
    `never_ran_veto` keeps the full ack wait), and the launch is not
    cancelled. Once frozen, no re-place can create the VM again."""
    job = _queue(root_client)
    launch_jobs.claim_one()
    make_vm(VM_ID, state=VmState.ACTIVE)

    assert _decommission(root_client).status_code == status.HTTP_202_ACCEPTED

    assert DecommissionJob.objects.filter(vm__vm_id=VM_ID).count() == 1
    job.refresh_from_db()
    assert job.state == LaunchJobState.RUNNING.value
    assert job.cancel_requested_at is None, "a launch that created its row is not cancelled"
    Vm.objects.filter(vm_id=VM_ID).update(state=VmState.DECOMMISSIONING)
    with pytest.raises(launch.LaunchConfigError, match="decommissioned vm_id cannot"):
        launch._ensure_vm_row(_spec_of(job))


@pytest.mark.django_db
def test_a_cancelled_vm_id_cannot_be_launched_again(
    root_client, stub_vault_put  # noqa: F811
) -> None:
    """The caller was told the VM is gone; its retried launch POST must not
    bring it back."""
    _queue(root_client)
    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND

    resp = root_client.post(LAUNCH_URL, _intent(), format="json")

    assert resp.status_code == status.HTTP_409_CONFLICT
    assert LaunchJob.objects.filter(vm_id=VM_ID).count() == 1


@pytest.mark.django_db
def test_the_worker_refuses_a_cancelled_vm_id_whatever_the_job(
    root_client, stub_vault_put  # noqa: F811
) -> None:
    """Behind intake: a new job for a cancelled vm_id (one that slipped in
    another way) still never creates the row."""
    job = _queue(root_client)
    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND

    with pytest.raises(launch.LaunchCancelled):
        launch._ensure_vm_row(_spec_of(job))
    assert not Vm.objects.filter(vm_id=VM_ID).exists()


@pytest.mark.django_db
def test_no_launch_no_vm_is_still_404(root_client) -> None:
    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND
    assert launch_jobs.fence_launch_for_decommission(VM_ID) == launch_jobs.FENCE_NO_LAUNCH


@pytest.mark.django_db
def test_a_finished_launch_is_not_touched(root_client, stub_vault_put) -> None:  # noqa: F811
    job = _queue(root_client)
    LaunchJob.objects.filter(id=job.id).update(
        state=LaunchJobState.FAILED.value, reason="no-eligible-miner", finished_at=job.started_at
    )

    assert _decommission(root_client).status_code == status.HTTP_404_NOT_FOUND

    job.refresh_from_db()
    assert job.reason == "no-eligible-miner"
    assert job.cancel_requested_at is None


@pytest.mark.django_db
def test_an_ordinary_decommission_is_unchanged(root_client) -> None:
    make_vm(VM_ID, state=VmState.ACTIVE)

    assert _decommission(root_client).status_code == status.HTTP_202_ACCEPTED


# ── the lock, on Postgres (SQLite has no row locks) ──────────────────


def _in_thread(target) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["result"] = target()
        except Exception as exc:  # noqa: BLE001 — asserted by the caller
            out["error"] = exc
        finally:
            connections.close_all()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


def _running_job(client) -> LaunchJob:
    _queue(client)
    return launch_jobs.claim_one()


@pytest.mark.django_db(transaction=True)
def test_the_fence_waits_for_a_row_being_created(
    root_client, stub_vault_put, monkeypatch  # noqa: F811
) -> None:
    """The worker holds the job's lock and is creating the row when the §24
    arrives: the §24 waits, then sees the row (no cancel, no `404`)."""
    if connection.vendor != "postgresql":
        pytest.skip("row locks need Postgres")
    job = _running_job(root_client)
    locked = threading.Event()
    real_refuse = launch._refuse_cancelled_launch

    def refuse_then_pause(vm_id: str) -> None:
        real_refuse(vm_id)
        locked.set()
        time.sleep(0.5)

    monkeypatch.setattr(launch, "_refuse_cancelled_launch", refuse_then_pause)

    worker, worker_out = _in_thread(lambda: launch._ensure_vm_row(_spec_of(job)))
    assert locked.wait(5)
    started = time.monotonic()
    verdict = launch_jobs.fence_launch_for_decommission(VM_ID)
    worker.join(5)

    assert "error" not in worker_out
    assert time.monotonic() - started >= 0.3, "the fence did not wait for the lock"
    assert verdict == launch_jobs.FENCE_VM_EXISTS
    assert LaunchJob.objects.get(vm_id=VM_ID).cancel_requested_at is None


@pytest.mark.django_db(transaction=True)
def test_a_row_creation_waits_for_the_fence(root_client, stub_vault_put) -> None:  # noqa: F811
    """The §24 holds the lock when the worker reaches the row: the worker
    waits, then refuses — the row is never created."""
    if connection.vendor != "postgresql":
        pytest.skip("row locks need Postgres")
    job = _running_job(root_client)
    fenced = threading.Event()

    def fence() -> str:
        with transaction.atomic():
            verdict = launch_jobs.fence_launch_for_decommission(VM_ID)
            fenced.set()
            time.sleep(0.5)
            return verdict

    holder, holder_out = _in_thread(fence)
    assert fenced.wait(5)
    started = time.monotonic()
    with pytest.raises(launch.LaunchCancelled):
        launch._ensure_vm_row(_spec_of(job))
    holder.join(5)

    assert time.monotonic() - started >= 0.3, "the worker did not wait for the lock"

    assert holder_out.get("result") == launch_jobs.FENCE_RUNNING
    assert not Vm.objects.filter(vm_id=VM_ID).exists()
