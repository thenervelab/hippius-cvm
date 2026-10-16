"""`require_failover_peer`: a VM launched with it lands only on a host
another miner could take its failover from (gate (m)), and keeps that
through every later placement; `failover_capable_node_ids` is the input."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.utils import timezone

from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration import launch_jobs, service
from apps.orchestration.launch_jobs import LaunchIntentError
from apps.orchestration.services import launch
from apps.scheduler import service as sched
from apps.scheduler.placement import NO_FAILOVER_CAPABLE_HOST, PlacementError

from .factories import make_launch_record, make_service_client, make_vm
from .test_power_policy import _decide, _intent, _snapshot

pytestmark = pytest.mark.django_db


def test_intake_records_it_only_when_true() -> None:
    assert "require_failover_peer" not in launch_jobs._build_spec_json(_intent())
    assert "require_failover_peer" not in launch_jobs._build_spec_json(
        _intent(require_failover_peer=False)
    )
    spec = launch_jobs._build_spec_json(_intent(require_failover_peer=True))
    assert spec["require_failover_peer"] is True
    for bad in ["true", 1, "yes"]:
        with pytest.raises(LaunchIntentError) as exc:
            launch_jobs._build_spec_json(_intent(require_failover_peer=bad))
        assert exc.value.category == "bad-field"
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"").require_failover_peer


def test_gate_m_places_only_on_a_failover_capable_host() -> None:
    snap = _snapshot("aa", "bb")
    assert _decide(snap, failover_capable=frozenset({"bb"})) == "bb"
    with pytest.raises(PlacementError) as exc:
        _decide(snap, failover_capable=frozenset())
    assert exc.value.category == NO_FAILOVER_CAPABLE_HOST
    assert _decide(snap) in {"aa", "bb"}, "no gate without the field"


def test_placement_arguments_add_gate_m_only_when_asked(monkeypatch) -> None:
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {"bb": "FR"})
    snap = SimpleNamespace(current_epoch=10, pallet_live=True, miners=[])
    base = dict(snapshot=snap, tenant_id="t", user_id="u", flavor="small", shadow_log=False)
    assert "failover_capable" not in sched.placement_arguments(**base)
    args = sched.placement_arguments(**base, require_failover_peer=True)
    assert args["failover_capable"] == frozenset({"bb"})


def _miner(seed: int, country: str, chip_bytes: int, **kw) -> MinerIdentity:
    miner = MinerIdentity.objects.create(
        miner_id=f"m{seed}",
        pubkey_hex=f"{seed:02x}" * 32,
        platform_id=f"{seed:02x}" * chip_bytes,
        chain_node_id=f"{seed:02x}" * 32,
        netbird_ip=f"100.64.0.{seed}",
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        **kw,
    )
    MinerLocation.objects.create(
        miner=miner,
        country_code=country,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now(),
    )
    _mirror(miner.chain_node_id, "active")
    return miner


def _mirror(node: str, status: str, epoch: int = 10, at: object = None) -> None:
    from apps.scheduler.models import MinerCapacity

    MinerCapacity.objects.update_or_create(
        miner_node_id=node,
        defaults={
            "status": status,
            "capacity_slots": 4,
            "observed_epoch": epoch,
            "data_epoch": epoch,
            "refreshed_at": at or timezone.now(),
        },
    )


def test_the_capable_hosts_are_the_same_generation_pairs_of_a_region() -> None:
    """A region with one Genoa alone and two Turin, plus single-host
    regions — only the two Turin can protect a VM."""
    _miner(1, "FR", 64)
    _miner(2, "FR", 8)
    _miner(3, "FR", 8)
    _miner(4, "NL", 64)
    _miner(5, "AU", 64)
    assert sched.failover_capable_node_ids() == {"02" * 32: "FR", "03" * 32: "FR"}


def test_a_launch_with_the_field_is_read_back_by_later_placements() -> None:
    vm = make_vm(host="node-src")
    assert not sched.launch_requires_failover_peer(vm.vm_id)
    make_launch_record(vm, require_failover_peer=True)
    assert sched.launch_requires_failover_peer(vm.vm_id)
    assert sched.failover_peer_arguments(False) == {}


@pytest.mark.usefixtures("located_fr")
def test_a_migration_keeps_the_constraint(monkeypatch) -> None:
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64, chain_node_id="c" * 64
    )
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64, chain_node_id="d" * 64
    )
    vm = make_vm(host="node-src")
    make_launch_record(vm, require_failover_peer=True)
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {})
    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == NO_FAILOVER_CAPABLE_HOST
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {"d" * 64: "FR"})
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert job.dest_node_id == "node-dst"


@pytest.mark.usefixtures("located_fr")
def test_a_resize_destination_keeps_the_constraint(monkeypatch) -> None:
    from apps.orchestration import resize
    from apps.scheduler import chain

    vm = make_vm(host="node-src")
    make_launch_record(vm, require_failover_peer=True)
    seen: dict = {}

    class _Stop(Exception):
        pass

    def spy(**kw):
        seen.update(kw)
        raise _Stop

    monkeypatch.setattr(chain, "read_miner_status", lambda: object())
    monkeypatch.setattr(sched, "refresh_miner_capacity", lambda snap: None)
    monkeypatch.setattr(sched, "placement_arguments", spy)
    placement = SimpleNamespace(miner_node_id="c" * 64, vm_family="t", owner="u")
    with pytest.raises(_Stop):
        resize._pick_destination(vm, placement, "medium")
    assert seen["require_failover_peer"] is True


def test_a_peer_leaving_on_chain_is_no_peer() -> None:
    """Locally still active, but quarantined on chain (unstaking): the
    drain is about to move its VMs — it protects nobody."""
    _miner(2, "FR", 8)
    _miner(3, "FR", 8)
    assert set(sched.failover_capable_node_ids()) == {"02" * 32, "03" * 32}
    _mirror("03" * 32, "quarantined")
    assert sched.failover_capable_node_ids() == {}


def test_a_peer_needs_a_positive_on_chain_row() -> None:
    """No mirror row is no proof; nor is the last row of a miner the chain
    dropped (the next read leaves it at an older epoch)."""
    from apps.scheduler.models import MinerCapacity

    _miner(2, "FR", 8)
    _miner(3, "FR", 8)
    MinerCapacity.objects.filter(miner_node_id="03" * 32).delete()
    assert sched.failover_capable_node_ids() == {}
    lag = sched.max_epoch_lag()
    later = timezone.now() + timedelta(seconds=1)
    _mirror("03" * 32, "active", epoch=10 - lag - 1)  # gone from the chain since then
    _mirror("02" * 32, "active", at=later)  # the latest refresh
    assert sched.failover_capable_node_ids() == {}
    _mirror("03" * 32, "active", epoch=10 - lag)  # a refresh caught mid-way
    _mirror("02" * 32, "active", at=later + timedelta(seconds=1))
    assert set(sched.failover_capable_node_ids()) == {"02" * 32, "03" * 32}


def test_a_stale_row_from_before_a_chain_reset_disqualifies_nobody() -> None:
    """A row left at a HIGHER epoch (the chain was reset since) is the
    stale one: the live rows, refreshed last, set the line."""
    from apps.scheduler.models import MinerCapacity

    MinerCapacity.objects.create(
        miner_node_id="ff" * 32,
        status="active",
        capacity_slots=4,
        observed_epoch=5000,
        data_epoch=5000,
        refreshed_at=timezone.now() - timedelta(days=30),
    )
    _miner(2, "FR", 8)
    _miner(3, "FR", 8)
    assert set(sched.failover_capable_node_ids()) == {"02" * 32, "03" * 32}


@pytest.mark.usefixtures("located_fr")
def test_only_the_drain_is_exempt_at_the_migration_intake(monkeypatch) -> None:
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64, chain_node_id="c" * 64
    )
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64, chain_node_id="d" * 64
    )
    vm = make_vm(host="node-src")
    make_launch_record(vm, require_failover_peer=True)
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {})
    job = service.start_migration(
        vm=vm,
        dest_node_id="node-dst",
        decided_by=make_service_client(),
        failover_peer_exempt=True,
    )
    assert job.dest_node_id == "node-dst"


def test_the_peer_blocker_needs_a_positive_on_chain_row(monkeypatch) -> None:
    from apps.backup import service as backup_service
    from apps.scheduler.models import MinerCapacity

    host = _miner(2, "FR", 8)
    _miner(3, "FR", 8)
    vm = make_vm(host=host.miner_id)
    make_launch_record(vm, region="FR")
    assert backup_service.failover_peer_blocker(vm) is None
    MinerCapacity.objects.filter(miner_node_id="03" * 32).delete()
    assert backup_service.failover_peer_blocker(vm) == "no-failover-peer"
