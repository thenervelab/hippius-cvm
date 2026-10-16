"""The fail-closed region gate on every path that moves an existing VM:
§25 `start_migration` (operator API, price-recommendation approve, drain,
resize), `/place` and `/fail` re-placement. Never another region; a region
that cannot be told refuses — unless an operator states it, recorded."""

from __future__ import annotations

import pytest
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration import service
from apps.orchestration.models import MigrationJob

from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _miners() -> None:
    """Three same-generation miners: the source, an FR and a DE destination."""
    for miner_id, chain, chip in (
        ("node-src", "c" * 64, "11"),
        ("node-fr", "d" * 64, "22"),
        ("node-de", "e" * 64, "33"),
    ):
        MinerIdentity.objects.update_or_create(
            miner_id=miner_id,
            defaults={"pubkey_hex": chain, "platform_id": chip * 64, "chain_node_id": chain},
        )
    _locate("node-fr", "FR")
    _locate("node-de", "DE")


def _locate(miner_id: str, country: str) -> None:
    MinerLocation.objects.update_or_create(
        miner=MinerIdentity.objects.get(miner_id=miner_id),
        defaults={
            "country_code": country,
            "verdict": LocationVerdict.VERIFIED,
            "observed_at": timezone.now(),
            "last_verified_country_code": country,
            "last_verified_at": timezone.now(),
        },
    )


def _start(vm, dest: str, **kw):
    return service.start_migration(vm=vm, dest_node_id=dest, decided_by=make_service_client(), **kw)


def test_a_migration_stays_in_the_launch_region() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-de")
    assert exc.value.category == "cross-region"
    job = _start(vm, "node-fr")
    assert (job.region, job.region_stated_by_operator) == ("FR", False)


def test_a_vm_with_no_launch_region_stays_in_its_hosts_country() -> None:
    vm = make_vm(host="node-src")
    _locate("node-src", "FR")
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-de")
    assert exc.value.category == "cross-region"
    assert _start(vm, "node-fr").region == "FR"


def test_an_unknown_region_refuses_until_an_operator_states_it() -> None:
    vm = make_vm(host="node-src")  # no launch region, host never located
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-fr")
    assert exc.value.category == "region-unknown"
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-de", region="FR")
    assert exc.value.category == "cross-region", "a stated region holds the move too"
    job = _start(vm, "node-fr", region="fr")
    assert (job.region, job.region_stated_by_operator) == ("FR", True)


def test_a_stated_region_never_overrides_a_known_one() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-de", region="DE")
    assert exc.value.category == "region-conflict"
    assert not MigrationJob.objects.exists()


def test_a_destination_not_located_now_is_in_no_region() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    MinerLocation.objects.filter(miner_id="node-fr").update(verdict=LocationVerdict.MISMATCH)
    with pytest.raises(service.StartError) as exc:
        _start(vm, "node-fr")
    assert exc.value.category == "cross-region"


def test_the_migrate_api_takes_and_reports_the_region(root_client: APIClient) -> None:
    make_vm("vm-1", host="node-src")
    url = "/v1/vm/vm-1/migrate"
    resp = root_client.post(url, {"dest_node_id": "node-fr", "region": "FRA"}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    resp = root_client.post(url, {"dest_node_id": "node-fr"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "region-unknown"
    resp = root_client.post(url, {"dest_node_id": "node-fr", "region": "FR"}, format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert (resp.json()["region"], resp.json()["region_stated_by_operator"]) == ("FR", True)


def test_a_resize_never_picks_a_destination_for_a_vm_of_unknown_region() -> None:
    from types import SimpleNamespace

    from apps.orchestration import resize

    vm = make_vm(host="node-src")
    placement = SimpleNamespace(miner_node_id="c" * 64, vm_family="t", owner="u")
    assert resize._pick_destination(vm, placement, "medium") == (None, "region-unknown")
