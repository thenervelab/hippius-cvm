"""Endpoint tests for the §24/§25 orchestration views."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.lifecycle.models import VmState
from apps.orchestration.models import (
    DecommissionJob,
    DecommissionState,
    MigrationJob,
    MigrationState,
)

from .factories import (
    make_decommission_job,
    make_migration_job,
    make_vm,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """Register the source/dest miners same-generation so §25's same-CPU-gen
    gate in `start_migration` passes (see test_migration for the rationale)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def _migrate_url(vm_id: str) -> str:
    return reverse("vm_migrate", kwargs={"vm_id": vm_id})


def _migrate_job_url(vm_id: str, job_id: str) -> str:
    return reverse("vm_migrate_job", kwargs={"vm_id": vm_id, "job_id": job_id})


def _decommission_url(vm_id: str) -> str:
    return reverse("vm_decommission", kwargs={"vm_id": vm_id})


def _decommission_job_url(vm_id: str, job_id: str) -> str:
    return reverse("vm_decommission_job", kwargs={"vm_id": vm_id, "job_id": job_id})


# ─── POST /v1/vm/<id>/migrate ────────────────────────────────────────


def test_migrate_start_requires_the_root_principal(
    authed_client: APIClient,
) -> None:
    make_vm("vm-1")
    resp = authed_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_migrate_start_unauthenticated_rejected() -> None:
    make_vm("vm-1")
    resp = APIClient().post(
        _migrate_url("vm-1"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_migrate_start_happy_path(root_client: APIClient) -> None:
    make_vm("vm-1", generation=5, host="node-src")
    resp = root_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["state"] == MigrationState.DRAINING.value
    assert body["vm_id"] == "vm-1"
    assert body["source_node_id"] == "node-src"
    assert body["dest_node_id"] == "node-dst"
    assert body["source_gen"] == 5
    assert body["new_gen"] == 6
    assert MigrationJob.objects.filter(vm__vm_id="vm-1").count() == 1


def test_migrate_start_404_unknown_vm(root_client: APIClient) -> None:
    resp = root_client.post(
        _migrate_url("ghost"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_migrate_start_400_missing_dest_node_id(root_client: APIClient) -> None:
    make_vm("vm-1")
    resp = root_client.post(_migrate_url("vm-1"), {}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_migrate_start_400_dest_is_current_host(root_client: APIClient) -> None:
    make_vm("vm-1", host="node-src")
    resp = root_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-src"}, format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "same-node"


def test_migrate_start_409_vm_not_active(root_client: APIClient) -> None:
    make_vm("vm-1", state=VmState.DECOMMISSIONING)
    resp = root_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "vm-not-active"


def test_migrate_start_409_when_a_migration_is_already_in_flight(
    root_client: APIClient,
) -> None:
    make_vm("vm-1")
    first = root_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-dst"}, format="json"
    )
    assert first.status_code == status.HTTP_202_ACCEPTED
    second = root_client.post(
        _migrate_url("vm-1"), {"dest_node_id": "node-other"}, format="json"
    )
    assert second.status_code == status.HTTP_409_CONFLICT
    assert second.json()["category"] == "job-in-flight"
    assert MigrationJob.objects.filter(vm__vm_id="vm-1").count() == 1


# ─── GET /v1/vm/<id>/migrate/<job_id> ────────────────────────────────


def test_migrate_poll_returns_the_job(authed_client: APIClient) -> None:
    vm = make_vm("vm-1")
    job = make_migration_job(vm)
    resp = authed_client.get(_migrate_job_url("vm-1", job.job_id))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["job_id"] == job.job_id
    assert resp.json()["state"] == MigrationState.DRAINING.value


def test_migrate_poll_404_unknown_job(authed_client: APIClient) -> None:
    make_vm("vm-1")
    resp = authed_client.get(_migrate_job_url("vm-1", "nope"))
    assert resp.status_code == status.HTTP_404_NOT_FOUND


# ─── POST /v1/vm/<id>/decommission ───────────────────────────────────


def test_decommission_start_requires_root(authed_client: APIClient) -> None:
    make_vm("vm-1")
    resp = authed_client.post(_decommission_url("vm-1"), {}, format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_decommission_start_happy_path(root_client: APIClient) -> None:
    make_vm("vm-1")
    resp = root_client.post(_decommission_url("vm-1"), {}, format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["state"] == DecommissionState.DRAINING.value
    assert body["vm_id"] == "vm-1"
    assert body["forced"] is False
    assert DecommissionJob.objects.filter(vm__vm_id="vm-1").count() == 1


def test_decommission_start_404_unknown_vm(root_client: APIClient) -> None:
    resp = root_client.post(_decommission_url("ghost"), {}, format="json")
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_decommission_start_409_when_in_flight(root_client: APIClient) -> None:
    make_vm("vm-1")
    first = root_client.post(_decommission_url("vm-1"), {}, format="json")
    assert first.status_code == status.HTTP_202_ACCEPTED
    second = root_client.post(_decommission_url("vm-1"), {}, format="json")
    assert second.status_code == status.HTTP_409_CONFLICT
    assert second.json()["category"] == "job-in-flight"


# ─── GET /v1/vm/<id>/decommission/<job_id> ───────────────────────────


def test_decommission_poll_returns_the_job(authed_client: APIClient) -> None:
    vm = make_vm("vm-1")
    job = make_decommission_job(vm)
    resp = authed_client.get(_decommission_job_url("vm-1", job.job_id))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["job_id"] == job.job_id


def test_decommission_poll_404_unknown_job(authed_client: APIClient) -> None:
    make_vm("vm-1")
    resp = authed_client.get(_decommission_job_url("vm-1", "nope"))
    assert resp.status_code == status.HTTP_404_NOT_FOUND
