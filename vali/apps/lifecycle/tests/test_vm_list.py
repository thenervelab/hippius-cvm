"""Integration tests for `GET /v1/vm` (#587 Phase 2 list endpoint).

The upstream product API calls this with an OPERATOR service principal
to render a tenant's VMs; for that principal `tenant_id` / `lease_id`
filter for DISPLAY only and the upstream owns end-user authz. Every
fixture here is therefore an explicit operator.

The per-tenant gate (P2) is a different claim and lives in
`apps/identity/tests/test_object_scoping.py` — a TENANT-scoped principal
sees only its own rows, and `?tenant_id=` cannot widen that.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle.models import Vm, VmBootPhase, VmState

pytestmark = pytest.mark.django_db


@pytest.fixture
def authed_client() -> APIClient:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="upstream-api")
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c


def _mk_vm(vm_id: str, *, tenant_id: str = "", lease_id: str = "lease-x") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        tenant_id=tenant_id,
        lease_id=lease_id,
        state=VmState.ACTIVE,
        generation=1,
        host="host-a",
        lifecycle_vk=bytes(range(32)),
    )


def test_list_unauthenticated_rejected() -> None:
    resp = APIClient().get(reverse("vm_list"))
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_list_empty(authed_client: APIClient) -> None:
    resp = authed_client.get(reverse("vm_list"))
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body == {"vms": [], "limit": 50, "offset": 0, "total": 0}


def test_list_returns_all_with_tenant_id(authed_client: APIClient) -> None:
    _mk_vm("vm-1", tenant_id="tenant-a")
    _mk_vm("vm-2", tenant_id="tenant-b")
    resp = authed_client.get(reverse("vm_list"))
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["total"] == 2
    ids = {row["vm_id"] for row in body["vms"]}
    assert ids == {"vm-1", "vm-2"}
    # tenant_id is surfaced in each row.
    by_id = {row["vm_id"]: row for row in body["vms"]}
    assert by_id["vm-1"]["tenant_id"] == "tenant-a"
    # eol_nonce stays server-side even in the list.
    assert "eol_nonce" not in body["vms"][0]


def test_filter_by_tenant_id(authed_client: APIClient) -> None:
    _mk_vm("vm-1", tenant_id="tenant-a")
    _mk_vm("vm-2", tenant_id="tenant-b")
    _mk_vm("vm-3", tenant_id="tenant-a")
    resp = authed_client.get(reverse("vm_list"), {"tenant_id": "tenant-a"})
    body = resp.json()
    assert body["total"] == 2
    assert {row["vm_id"] for row in body["vms"]} == {"vm-1", "vm-3"}


def test_filter_by_lease_id(authed_client: APIClient) -> None:
    _mk_vm("vm-1", lease_id="lease-1")
    _mk_vm("vm-2", lease_id="lease-2")
    resp = authed_client.get(reverse("vm_list"), {"lease_id": "lease-2"})
    body = resp.json()
    assert body["total"] == 1
    assert body["vms"][0]["vm_id"] == "vm-2"


def test_filter_empty_tenant_id_matches_unstamped(
    authed_client: APIClient,
) -> None:
    # A pre-Phase-2 row has tenant_id="" — an explicit empty filter must
    # return exactly those (not "all").
    _mk_vm("vm-1", tenant_id="")
    _mk_vm("vm-2", tenant_id="tenant-b")
    resp = authed_client.get(reverse("vm_list"), {"tenant_id": ""})
    body = resp.json()
    assert body["total"] == 1
    assert body["vms"][0]["vm_id"] == "vm-1"


def test_pagination_limit_and_offset(authed_client: APIClient) -> None:
    for i in range(5):
        _mk_vm(f"vm-{i}", tenant_id="tenant-a")
    resp = authed_client.get(
        reverse("vm_list"), {"tenant_id": "tenant-a", "limit": 2, "offset": 0}
    )
    body = resp.json()
    assert body["total"] == 5
    assert body["limit"] == 2
    assert len(body["vms"]) == 2

    resp2 = authed_client.get(
        reverse("vm_list"), {"tenant_id": "tenant-a", "limit": 2, "offset": 4}
    )
    body2 = resp2.json()
    assert body2["total"] == 5
    assert len(body2["vms"]) == 1


def test_limit_clamped_to_max(authed_client: APIClient) -> None:
    resp = authed_client.get(reverse("vm_list"), {"limit": 9999})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["limit"] == 200


def test_bad_pagination_rejected(authed_client: APIClient) -> None:
    resp = authed_client.get(reverse("vm_list"), {"limit": "abc"})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "bad-pagination"

    resp2 = authed_client.get(reverse("vm_list"), {"offset": "-1"})
    assert resp2.status_code == status.HTTP_400_BAD_REQUEST
    assert resp2.json()["category"] == "bad-pagination"


def test_list_exposes_boot_phase_fields(authed_client: APIClient) -> None:
    # An unset VM renders empty boot_phase + null boot_phase_at.
    _mk_vm("vm-unset")
    # A VM that reported a milestone renders its phase + timestamp.
    now = timezone.now()
    vm = _mk_vm("vm-running")
    vm.boot_phase = VmBootPhase.RUNNING.value
    vm.boot_phase_at = now
    vm.save(update_fields=["boot_phase", "boot_phase_at"])

    resp = authed_client.get(reverse("vm_list"))
    assert resp.status_code == status.HTTP_200_OK
    by_id = {row["vm_id"]: row for row in resp.json()["vms"]}

    assert "boot_phase" in by_id["vm-unset"]
    assert by_id["vm-unset"]["boot_phase"] == ""
    assert by_id["vm-unset"]["boot_phase_at"] is None

    assert by_id["vm-running"]["boot_phase"] == VmBootPhase.RUNNING.value
    assert by_id["vm-running"]["boot_phase_at"] is not None


def test_list_applies_each_rows_flavor_deadline(authed_client: APIClient) -> None:
    """A small (40 GiB ⇒ 1500 s) VM silent for 30 min is stalled; the list
    must resolve its flavor rather than fall back to the full cap."""
    from datetime import timedelta

    from apps.orchestration.models import LaunchJob
    from apps.orchestration.tests.factories import make_service_client

    vm = _mk_vm("vm-small")
    Vm.objects.filter(pk=vm.pk).update(
        boot_started_at=timezone.now() - timedelta(minutes=30)
    )
    LaunchJob.objects.create(
        job_id="j-small", vm_id="vm-small", tenant_id="t", flavor="small",
        userdata_vault_path="x", userdata_vault_version=1, kek_vault_path="x",
        phase_started_at=timezone.now(), decided_by=make_service_client(),
    )
    row = authed_client.get(reverse("vm_list")).json()["vms"][0]
    assert row["boot_stalled"] is True
    assert row["guest_liveness"] == "wedged"
