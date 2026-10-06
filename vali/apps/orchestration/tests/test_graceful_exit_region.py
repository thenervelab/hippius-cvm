"""Gate (f) on the graceful-exit drain: an auto-migration off a departing
miner must keep a VM in the region it was launched in.

This is the one placement nobody watches happen — no API call, no
operator approving a destination — so it is exactly where a VM sold as
"in FR" would otherwise quietly end up wherever ranks best. The picker
is the REAL `decide_placement` (via `_departing_drain`), with the region
read back from the VM's `LaunchJob`.

`node-dst` wins on every other signal (identical capacity, identical
load, lower node_id) — see `test_cvm_capability_feedback` — so a change
of destination here can only be the region.
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.scheduler.models import Placement, PlacementStatus

from .factories import make_launch_record, make_service_client, make_vm
from .test_cvm_capability_feedback import (  # noqa: F401 — fixture re-registered here
    DST_NODE,
    SRC_NODE,
    THIRD_NODE,
    _bridged_same_gen_miners,
    _departing_drain,
    _mirror,
)

pytestmark = pytest.mark.django_db


def _locate(miner_id: str, country: str) -> None:
    MinerLocation.objects.create(
        miner=MinerIdentity.objects.get(miner_id=miner_id),
        connection_ip="198.51.100.45",
        country_code=country,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now(),
    )


def _bound_vm_on_source(*, region: str | None):
    vm = make_vm(generation=5, host="node-src")
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=SRC_NODE,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=timezone.now(),
        decided_by=make_service_client(),
    )
    make_launch_record(vm, region=region)
    _mirror(SRC_NODE)
    _mirror(DST_NODE)
    # `_departing_drain` update_or_creates node-third; it must exist first
    # so it can carry a location before the drain runs.
    MinerIdentity.objects.update_or_create(
        miner_id="node-third",
        defaults={"pubkey_hex": "33" * 32, "platform_id": "33" * 64, "chain_node_id": THIRD_NODE},
    )
    return vm


def test_auto_migration_stays_in_the_vm_region(monkeypatch) -> None:
    _bound_vm_on_source(region="FR")
    _locate("node-dst", "DE")
    _locate("node-third", "FR")
    assert _departing_drain(monkeypatch) == ["node-third"]


def test_auto_migration_enrols_nothing_when_no_miner_is_in_the_region(monkeypatch) -> None:
    """No FR destination ⇒ the VM stays where it is (a later tick retries)
    rather than being moved out of the region it was sold in."""
    _bound_vm_on_source(region="FR")
    _locate("node-dst", "DE")
    _locate("node-third", "DE")
    assert _departing_drain(monkeypatch) == []


def test_auto_migration_is_unconstrained_for_a_pre_region_launch(monkeypatch) -> None:
    """A VM whose `spec_json` pre-dates the field asked for nothing; the
    drain must pick exactly as before, even with locations on file."""
    _bound_vm_on_source(region=None)
    _locate("node-dst", "DE")
    _locate("node-third", "FR")
    assert _departing_drain(monkeypatch) == ["node-dst"]


def test_the_auto_enrol_kill_switch_enrols_nothing(monkeypatch, settings) -> None:
    """Off, a departing miner's VMs stay put — the drain that otherwise
    moves this one (see above) opens no migration."""
    _bound_vm_on_source(region="FR")
    _locate("node-dst", "DE")
    _locate("node-third", "FR")
    settings.VALI_MIGRATION_AUTO_ENROL_ENABLED = False
    assert _departing_drain(monkeypatch) == []


def test_auto_migration_asks_capacity_v2_about_the_vms_flavor(monkeypatch) -> None:
    """The destination must fit the MIGRATING VM's flavor, not a reference
    slot: the drain hands the placement's `resource_class` to capacity v2."""
    from apps.scheduler import service
    from apps.scheduler.placement import ResourceFit

    asked: list[str] = []
    real = service.resource_fit

    def record(resource_class: str, **kw: object) -> ResourceFit:
        asked.append(resource_class)
        return real(resource_class, **kw)

    monkeypatch.setattr(service, "resource_fit", record)
    _bound_vm_on_source(region=None)
    _departing_drain(monkeypatch)
    assert asked == ["small"]
