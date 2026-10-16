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


def test_a_pre_region_launch_stays_in_its_hosts_country(monkeypatch) -> None:
    """A VM whose launch asked for no region is in the country its host is
    in: the drain keeps it there, never wherever ranks best."""
    _bound_vm_on_source(region=None)
    _locate("node-src", "FR")
    _locate("node-dst", "DE")
    _locate("node-third", "FR")
    assert _departing_drain(monkeypatch) == ["node-third"]


def test_a_vm_whose_region_cannot_be_told_is_not_moved(monkeypatch) -> None:
    """No launch region, its host never located: nowhere is safe — the VM
    stays (logged), never moved to some other country."""
    _bound_vm_on_source(region=None)
    _locate("node-dst", "DE")
    _locate("node-third", "FR")
    assert _departing_drain(monkeypatch) == []


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
    _bound_vm_on_source(region="FR")
    _locate("node-third", "FR")
    _departing_drain(monkeypatch)
    assert asked == ["small"]


def test_a_vm_the_drain_cannot_move_is_logged_when_the_reason_changes(monkeypatch) -> None:
    """Never silent, never every tick: one ERROR per new reason."""
    from apps.orchestration import service

    errors: list[str] = []

    class _Log:
        def error(self, msg: str, *args: object, **kw: object) -> None:
            errors.append(msg % args)

        def __getattr__(self, name: str) -> object:
            return lambda *a, **k: None

    monkeypatch.setattr(service, "log", _Log())
    monkeypatch.setattr(service, "_drain_stuck", {})
    vm = _bound_vm_on_source(region=None)  # host never located
    _locate("node-dst", "DE")
    _locate("node-third", "DE")
    assert _departing_drain(monkeypatch) == []
    assert _departing_drain(monkeypatch) == []
    _locate("node-src", "FR")  # now known — but nothing in FR
    assert _departing_drain(monkeypatch) == []
    reasons = [m.split("(")[1].split(")")[0] for m in errors if vm.vm_id in m]
    assert reasons == ["region-unknown", "no-miner-in-region"]


def test_the_drain_moves_a_require_failover_peer_vm_even_without_a_peer(monkeypatch) -> None:
    """Exempt from gate (m), never from its region: off a departing miner
    the VM moves in-region, peer or not, and says so at WARNING."""
    from apps.orchestration import service
    from apps.scheduler import service as sched

    warnings: list[str] = []

    class _Log:
        def warning(self, msg: str, *args: object, **kw: object) -> None:
            warnings.append(msg % args)

        def __getattr__(self, name: str) -> object:
            return lambda *a, **k: None

    monkeypatch.setattr(service, "log", _Log())
    vm = _bound_vm_on_source(region="FR")
    make_launch_record(vm, region="FR", require_failover_peer=True)  # the newest
    _locate("node-dst", "FR")
    _locate("node-third", "DE")
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {})
    starts: list[dict] = []
    assert _departing_drain(monkeypatch, starts) == ["node-dst"], "in-region, without a peer"
    assert starts[0].get("failover_peer_exempt") is True, "the §25 intake is told"
    assert any("moved without failover peer" in w for w in warnings)


def test_the_operator_drain_moves_the_vms_to_the_region_it_names(monkeypatch) -> None:
    """The automatic drain keeps an FR VM in FR (nothing there: it stays);
    the operator's drain with a cross-region override sends it to DE."""
    from apps.orchestration import service
    from apps.orchestration.service import CrossRegion

    _bound_vm_on_source(region="FR")
    _locate("node-dst", "DE")
    _locate("node-third", "DE")
    assert _departing_drain(monkeypatch) == []
    over = CrossRegion("DE", "evacuate")
    real_enroll = service.enroll_departing_miner_migrations

    def operator_drain() -> int:
        return real_enroll(only_node=SRC_NODE, cross_region=over, report={})

    monkeypatch.setattr(service, "enroll_departing_miner_migrations", operator_drain)
    assert _departing_drain(monkeypatch) == ["node-dst"]
