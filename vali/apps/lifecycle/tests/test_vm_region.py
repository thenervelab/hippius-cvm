"""`region` on the VM wire shape: the host's detected, verified country."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.lifecycle.models import Vm, VmState
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation, MinerStatus

pytestmark = pytest.mark.django_db


@pytest.fixture
def client() -> APIClient:
    sc = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="upstream-api")
    _row, token = ServiceToken.issue(client=sc, name="ops", lifetime=TokenLifetime.OPS.value)
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return c


def _miner(
    miner_id: str,
    seed: int,
    country: str | None,
    verdict: str = LocationVerdict.VERIFIED,
    age: timedelta = timedelta(minutes=5),
) -> MinerIdentity:
    m = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{seed:02x}" * 32,
        platform_id=f"{seed:02x}" * 64,
        chain_node_id=f"{seed:064x}",
        status=MinerStatus.ACTIVE,
    )
    if country is not None:
        MinerLocation.objects.create(
            miner=m, country_code=country, verdict=verdict, observed_at=timezone.now() - age
        )
    return m


def _vm(vm_id: str, host: str) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"l-{vm_id}",
        state=VmState.ACTIVE,
        generation=1,
        host=host,
        lifecycle_vk=bytes(range(32)),
    )


def _state(client: APIClient, vm_id: str) -> dict:
    resp = client.get(reverse("vm_state", kwargs={"vm_id": vm_id}))
    assert resp.status_code == 200
    return resp.json()


def test_region_is_the_hosts_verified_country(client: APIClient) -> None:
    _miner("miner-fr", 1, "FR")
    _vm("vm-a", "miner-fr")
    assert _state(client, "vm-a")["region"] == "FR"


def test_unverified_or_stale_or_absent_location_is_null(client: APIClient) -> None:
    _miner("miner-unv", 2, "FR", verdict=LocationVerdict.UNVERIFIED)
    _miner("miner-old", 3, "FR", age=timedelta(days=2))
    _miner("miner-none", 4, None)
    for vm_id, host in (
        ("vm-u", "miner-unv"),
        ("vm-o", "miner-old"),
        ("vm-n", "miner-none"),
        ("vm-x", ""),
    ):
        _vm(vm_id, host)
        assert _state(client, vm_id)["region"] is None, vm_id


def test_list_renders_regions_with_one_location_query(
    client: APIClient, django_assert_max_num_queries
) -> None:
    _miner("miner-fr", 1, "FR")
    _miner("miner-de", 5, "DE")
    for i in range(6):
        _vm(f"vm-{i}", "miner-fr" if i % 2 else "miner-de")
    # 9: +1 for the page's flavor lookup (boot-stall deadline), one query.
    with django_assert_max_num_queries(9):
        body = client.get(reverse("vm_list")).json()
    regions = {row["vm_id"]: row["region"] for row in body["vms"]}
    assert regions["vm-1"] == "FR" and regions["vm-2"] == "DE"
