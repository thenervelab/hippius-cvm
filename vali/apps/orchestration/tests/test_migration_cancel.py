"""§25 migration cancel (#587 Phase 3).

`POST /v1/vm/<vm_id>/migrate/<job_id>/cancel` → graceful `Failed` where
the state machine allows it (pre-`Fencing`); 409 once the migration has
passed the KBS fence (§25 recovery is forward-only) or already terminal.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.orchestration import service
from apps.orchestration.models import MigrationState
from apps.orchestration.service import StartError

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db


def _cancel_url(vm_id: str, job_id: str) -> str:
    return reverse("vm_migrate_cancel", kwargs={"vm_id": vm_id, "job_id": job_id})


# Only DRAINING is cleanly cancellable: the fence (Active→Migrating) now
# happens at QUIESCING — before the graceful stop, so the guest's stopped-ack
# ingests — and the guest is powered off from there on. So QUIESCING and every
# later state are past-fence: a cancel would orphan a stopped VM; §25 recovery
# is forward-only (re-drive or an operator relaunch of the intact source disk).
_PRE_FENCE = [
    MigrationState.DRAINING.value,
]
_PAST_FENCE = [
    MigrationState.QUIESCING.value,
    MigrationState.SNAPSHOTTING.value,
    MigrationState.UPLOADING.value,
    MigrationState.FENCING.value,
    MigrationState.AWAITING_SOURCE_ACK.value,
    MigrationState.DEST_ACTIVATING.value,
]


# ─── service.cancel_migration ────────────────────────────────────────


@pytest.mark.parametrize("state", _PRE_FENCE)
def test_cancel_pre_fence_fails_the_job(state: str) -> None:
    job = make_migration_job(make_vm(), state=state)
    out = service.cancel_migration(job=job, decided_by=make_service_client())
    assert out.state == MigrationState.FAILED.value
    assert "cancelled" in out.reason
    assert out.finished_at is not None


@pytest.mark.parametrize("state", _PAST_FENCE)
def test_cancel_past_fence_raises_and_leaves_job_untouched(state: str) -> None:
    job = make_migration_job(make_vm(), state=state)
    with pytest.raises(StartError) as ei:
        service.cancel_migration(job=job, decided_by=make_service_client())
    assert ei.value.category == "past-fence"
    job.refresh_from_db()
    assert job.state == state  # forward-only: untouched


def test_cancel_already_terminal_raises() -> None:
    job = make_migration_job(make_vm(), state=MigrationState.DONE.value)
    with pytest.raises(StartError) as ei:
        service.cancel_migration(job=job, decided_by=make_service_client())
    assert ei.value.category == "already-terminal"


# ─── POST …/migrate/<job_id>/cancel ──────────────────────────────────


def test_cancel_view_pre_fence_200(root_client: APIClient) -> None:
    vm = make_vm()
    job = make_migration_job(vm, state=MigrationState.DRAINING.value)
    resp = root_client.post(_cancel_url(vm.vm_id, job.job_id))
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "failed"
    assert "cancelled" in body["reason"]
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value


def test_cancel_view_past_fence_409(root_client: APIClient) -> None:
    vm = make_vm()
    job = make_migration_job(vm, state=MigrationState.FENCING.value)
    resp = root_client.post(_cancel_url(vm.vm_id, job.job_id))
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "past-fence"


def test_cancel_view_already_terminal_409(root_client: APIClient) -> None:
    vm = make_vm()
    job = make_migration_job(vm, state=MigrationState.FAILED.value)
    resp = root_client.post(_cancel_url(vm.vm_id, job.job_id))
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "already-terminal"


def test_cancel_view_unknown_job_404(root_client: APIClient) -> None:
    vm = make_vm()
    resp = root_client.post(_cancel_url(vm.vm_id, "no-such-job"))
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_cancel_view_requires_root(authed_client: APIClient) -> None:
    vm = make_vm()
    job = make_migration_job(vm, state=MigrationState.DRAINING.value)
    resp = authed_client.post(_cancel_url(vm.vm_id, job.job_id))
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )
    # the non-root caller did NOT mutate the job
    job.refresh_from_db()
    assert job.state == MigrationState.DRAINING.value


def test_cancel_view_unauthenticated() -> None:
    vm = make_vm()
    job = make_migration_job(vm, state=MigrationState.DRAINING.value)
    resp = APIClient().post(_cancel_url(vm.vm_id, job.job_id))
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )
