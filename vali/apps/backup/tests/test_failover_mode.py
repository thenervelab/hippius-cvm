"""`failover_mode` (manual by default), whether automatic failover is
available for a VM, and the migration that moved every policy to manual
(docs/design/backup-failover.md §10)."""

from __future__ import annotations

import importlib

import pytest
from django.apps import apps as django_apps
from rest_framework.test import APIClient

from apps.backup import service
from apps.backup.models import BackupPolicy, FailoverMode

from .conftest import make_vm

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("mock_s3")]

URL = "/v1/vm/vm-1/backup-policy"


@pytest.fixture
def point(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Whether the VM has a current-boot point (`restore_point`)."""
    state: dict[str, object] = {"point": True}
    monkeypatch.setattr(service, "has_current_boot_point", lambda policy: bool(state["point"]))
    return state


def test_a_create_without_a_mode_is_manual(root_client: APIClient) -> None:
    make_vm(region="FR")
    resp = root_client.put(URL, {"interval_s": 3600}, format="json")
    assert resp.status_code == 201
    assert resp.json()["failover_mode"] == "manual"


def test_an_update_without_a_mode_keeps_the_stored_one(root_client: APIClient) -> None:
    make_vm(region="FR")
    root_client.put(URL, {"interval_s": 3600, "failover_mode": "auto"}, format="json")
    resp = root_client.put(URL, {"interval_s": 21600}, format="json")
    assert resp.status_code == 200
    assert resp.json()["failover_mode"] == "auto"
    resp = root_client.put(URL, {"interval_s": 21600, "failover_mode": "manual"}, format="json")
    assert resp.json()["failover_mode"] == "manual"


@pytest.mark.parametrize("region", ["AU", ""])
def test_auto_is_refused_where_backups_are_not_local(root_client: APIClient, region: str) -> None:
    make_vm(region=region)
    resp = root_client.put(URL, {"interval_s": 3600, "failover_mode": "auto"}, format="json")
    assert resp.status_code == 409
    body = resp.json()
    assert body["code"] == body["error"] == "failover-auto-unavailable"
    assert body["blocker"] == "region-backups-not-local" and body["detail"]
    assert not BackupPolicy.objects.exists()


def test_the_auto_regions_are_a_setting(root_client: APIClient, settings) -> None:
    settings.VALI_FAILOVER_AUTO_REGIONS = ["AU"]
    make_vm(region="AU")
    resp = root_client.put(URL, {"interval_s": 3600, "failover_mode": "auto"}, format="json")
    assert resp.status_code == 201 and resp.json()["failover_mode"] == "auto"


def test_a_bad_mode_is_400(root_client: APIClient) -> None:
    make_vm(region="FR")
    resp = root_client.put(URL, {"interval_s": 3600, "failover_mode": "sometimes"}, format="json")
    assert resp.status_code == 400 and resp.json()["error"] == "bad-failover-mode"


@pytest.mark.parametrize(
    ("region", "has_point", "enabled", "blocker"),
    [
        ("FR", True, True, None),
        ("NL", False, True, "no-point"),
        ("AU", True, True, "region-backups-not-local"),
        ("FR", True, False, "disabled"),
    ],
)
def test_eligibility_on_both_views(
    root_client: APIClient,
    point: dict[str, object],
    region: str,
    has_point: bool,
    enabled: bool,
    blocker: str | None,
) -> None:
    vm = make_vm(region=region)
    BackupPolicy.objects.create(vm=vm, interval_s=3600, enabled=enabled)
    point["point"] = has_point
    policy = service.policy_view(BackupPolicy.objects.get())
    assert policy["failover_auto_eligible"] is (blocker is None)
    assert policy["failover_auto_blocker"] == blocker
    if enabled:
        got = root_client.get(URL).json()
        assert (got["failover_auto_eligible"], got["failover_auto_blocker"]) == (
            blocker is None,
            blocker,
        )
        listed = root_client.get("/v1/vm/vm-1/backups").json()["policy"]
        assert listed["failover_auto_blocker"] == blocker
        assert listed["failover_mode"] == "manual"


def test_the_region_falls_back_to_the_hosts_last_known_location() -> None:
    from datetime import timedelta

    from django.utils import timezone

    from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation

    vm = make_vm(region="")
    miner = MinerIdentity.objects.create(
        miner_id=vm.host, pubkey_hex="ab" * 32, platform_id="cd" * 32, chain_node_id="aa" * 32
    )
    assert service.vm_region(vm) == ""
    # Days stale — the host may be the dead miner a failover leaves.
    location = MinerLocation.objects.create(
        miner=miner,
        country_code="NL",
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now() - timedelta(days=3),
    )
    assert service.vm_region(vm) == "NL"
    assert service.failover_region_blocker(vm) is None
    location.verdict = LocationVerdict.MISMATCH
    location.save()
    assert service.vm_region(vm) == ""


def test_the_migration_moves_every_policy_to_manual() -> None:
    vm_a, vm_b = make_vm("vm-a"), make_vm("vm-b")
    BackupPolicy.objects.create(vm=vm_a, interval_s=3600, failover_mode=FailoverMode.AUTO)
    BackupPolicy.objects.create(vm=vm_b, interval_s=3600, failover_mode=FailoverMode.MANUAL)
    module = importlib.import_module("apps.backup.migrations.0005_failover_mode_manual")
    module.every_policy_manual(django_apps, None)
    assert set(BackupPolicy.objects.values_list("failover_mode", flat=True)) == {"manual"}
    assert BackupPolicy._meta.get_field("failover_mode").default == FailoverMode.MANUAL
