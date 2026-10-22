"""E4: no backup policy for a VM pinned by dedicated disks (contract §5:
409 `dedicated-pinned`), on create and on re-enable; disabling stays
allowed."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.backup import service
from apps.backup.models import BackupPolicy
from apps.disktier.models import DedicatedDisk

from .conftest import make_vm

HOUR = 3600

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("mock_s3")]


def _pin(vm) -> None:
    DedicatedDisk.objects.create(
        miner_node_id="n" * 64,
        disk_id="wwn-0x01",
        state="assigned",
        assigned_vm=vm,
        assigned_slot="x0",
        size_bytes=20000 * 2**30,
        verified_tier="hdd",
    )


def test_a_pinned_vm_gets_no_policy() -> None:
    vm = make_vm()
    _pin(vm)
    with pytest.raises(service.BackupError) as exc:
        service.put_policy(vm, interval_s=HOUR)
    assert exc.value.code == "dedicated-pinned"
    assert not BackupPolicy.objects.exists()


def test_a_pinned_vm_cannot_re_enable_one_but_may_disable_it() -> None:
    vm = make_vm()
    service.put_policy(vm, interval_s=HOUR)
    _pin(vm)
    service.disable_policy(vm)
    with pytest.raises(service.BackupError) as exc:
        service.put_policy(vm, interval_s=HOUR)
    assert exc.value.code == "dedicated-pinned"
    assert not BackupPolicy.objects.get(vm=vm).enabled


def test_the_api_answers_409(root_client) -> None:
    vm = make_vm()
    _pin(vm)
    resp = root_client.put(
        reverse("vm_backup_policy", kwargs={"vm_id": vm.vm_id}),
        {"interval_s": HOUR},
        format="json",
    )
    assert resp.status_code == 409, resp.content
    assert resp.json()["error"] == "dedicated-pinned"


def test_an_unpinned_vm_is_as_before() -> None:
    policy, created = service.put_policy(make_vm(), interval_s=HOUR)
    assert created and policy.enabled
