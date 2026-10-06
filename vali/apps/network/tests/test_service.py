"""Allocation and lifecycle: attach, detach, quarantine, the edge feed."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation, MinerStatus
from apps.network import service
from apps.network.models import IngressEdge, PublicIP, PublicIpState
from apps.network.service import NetworkError

from .conftest import launch_region, make_edge, make_vm

pytestmark = pytest.mark.django_db


def _located_host(miner_id: str, country: str, seed: int = 7) -> None:
    m = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{seed:02x}" * 32,
        platform_id=f"{seed:02x}" * 64,
        chain_node_id=f"{seed:064x}",
        status=MinerStatus.ACTIVE,
    )
    MinerLocation.objects.create(
        miner=m,
        country_code=country,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now() - timedelta(minutes=5),
    )


def _revision(edge: IngressEdge) -> int:
    edge.refresh_from_db()
    return edge.desired_revision


# ── attach ────────────────────────────────────────────────────────────


def test_attach_takes_a_free_address_and_bumps_the_revision() -> None:
    edge = make_edge()
    vm = make_vm()
    before = _revision(edge)

    ip, created = service.attach(vm)

    assert created
    assert ip.address == "203.0.113.10"
    assert ip.state == PublicIpState.ATTACHED
    assert ip.vm == vm
    assert ip.target_ip is None  # known only once reconcile resolves the peer
    assert ip.attached_at is not None
    assert _revision(edge) == before + 1


def test_attach_is_idempotent() -> None:
    edge = make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    vm = make_vm()
    first, _ = service.attach(vm)
    rev = _revision(edge)

    again, created = service.attach(vm)

    assert not created
    assert again.pk == first.pk
    assert PublicIP.objects.filter(state=PublicIpState.ATTACHED).count() == 1
    assert _revision(edge) == rev


def test_attach_prefers_the_region_the_vm_runs_in() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1", "198.51.100.2", "198.51.100.3"))
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    _located_host("miner-fr", "FR")
    vm = make_vm(host="miner-fr")

    ip, _ = service.attach(vm, region_hint="DE")

    assert ip.edge.name == "edge-fr"


def test_attach_uses_the_hint_when_the_vm_region_is_unknown() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    vm = make_vm()

    ip, _ = service.attach(vm, region_hint="de")

    assert ip.edge.name == "edge-de"


def test_attach_uses_the_launch_region_after_the_hint() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    vm = make_vm(region="")
    launch_region(vm.vm_id, "DE")

    ip, _ = service.attach(vm)

    assert ip.edge.name == "edge-de"


def test_attach_falls_back_to_the_zone_edge_with_most_free_addresses() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    vm = make_vm(region="BE")

    ip, _ = service.attach(vm)

    assert ip.edge.name == "edge-fr"


def test_attach_skips_edges_that_are_not_active() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10",), status="draining")
    make_edge("edge-de", "DE", ("198.51.100.1",))

    ip, _ = service.attach(make_vm(), region_hint="FR")

    assert ip.edge.name == "edge-de"


def test_attach_refuses_when_no_address_is_free() -> None:
    make_edge(addresses=("203.0.113.10",))
    service.attach(make_vm("vm-1"))

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-2"))

    assert exc.value.code == "no-free-public-ip"


# ── zones: an address never crosses one ───────────────────────────────


def _no_free_ip(vm: object, **kw: str) -> None:
    with pytest.raises(NetworkError) as exc:
        service.attach(vm, **kw)  # type: ignore[arg-type]
    assert exc.value.code == "no-free-public-ip"


def test_an_au_vm_is_refused_rather_than_served_from_another_zone() -> None:
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    _located_host("miner-au", "AU")
    service.attach(make_vm("vm-0", host="miner-au", region="AU"))

    # Not even a hint, or a launch that asked for FR, pulls it across.
    _no_free_ip(make_vm("vm-1", host="miner-au", region="FR"), region_hint="FR")

    assert PublicIP.objects.filter(edge__name="edge-fr", state=PublicIpState.FREE).count() == 2


def test_an_fr_vm_is_refused_rather_than_served_from_another_zone() -> None:
    make_edge("edge-fr", "FR", ())
    make_edge("edge-au", "AU", ("192.0.2.1",))
    _located_host("miner-fr", "FR")

    _no_free_ip(make_vm(host="miner-fr"), region_hint="AU")


def test_a_vm_in_a_country_without_an_edge_is_served_from_its_zone() -> None:
    make_edge("edge-au", "AU", ("192.0.2.1", "192.0.2.2", "192.0.2.3"))
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    _located_host("miner-nl", "NL")

    ip, _ = service.attach(make_vm(host="miner-nl", region=""))

    assert ip.edge.name == "edge-fr"


def test_the_placed_country_wins_over_a_hint_in_another_zone() -> None:
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    _located_host("miner-au", "AU")

    ip, _ = service.attach(make_vm(host="miner-au", region="FR"), region_hint="FR")

    assert ip.edge.name == "edge-au"


@pytest.mark.parametrize("launch", ["", "BR"])
def test_without_a_zone_only_an_exact_region_serves(launch: str) -> None:
    """Placed country unknown, and the hint or launch region (if any) in no
    zone: nothing to fall back to."""
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    make_edge("edge-us", "US", ("192.0.2.1",))

    _no_free_ip(make_vm("vm-1", region=launch))

    make_edge("edge-br", "BR", ("198.51.100.1",))
    vm = make_vm("vm-2", region=launch)
    if launch:
        assert service.attach(vm)[0].edge.name == "edge-br"
    else:
        _no_free_ip(vm)


def test_without_a_placement_the_launch_region_anchors_the_zone() -> None:
    """The launch region is recorded; the hint is only the caller's word."""
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10",))

    ip, _ = service.attach(make_vm("vm-1", region="FR"), region_hint="AU")
    assert ip.edge.name == "edge-fr"
    _no_free_ip(make_vm("vm-2", region="FR"), region_hint="AU")


def test_with_nothing_recorded_the_hint_anchors_the_zone() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10",))

    ip, _ = service.attach(make_vm(region=""), region_hint="NL")

    assert ip.edge.name == "edge-fr"


def test_an_edge_in_no_zone_serves_only_its_own_country() -> None:
    make_edge("edge-br", "BR", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ())

    _no_free_ip(make_vm())


def test_a_zoneless_placed_country_ignores_a_hint_elsewhere() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    _located_host("miner-br", "BR")

    _no_free_ip(make_vm(host="miner-br"), region_hint="FR")


def test_an_own_quarantined_address_in_another_zone_is_never_reused() -> None:
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_edge("edge-fr", "FR", ())
    old, _ = service.attach(make_vm("vm-au", tenant_id="tenant-a", region="AU"))
    service.detach(old.vm)
    _located_host("miner-fr", "FR")
    vm = make_vm("vm-fr", host="miner-fr", tenant_id="tenant-a")

    _no_free_ip(vm)
    with pytest.raises(NetworkError) as exc:
        service.attach(vm, address=old.address)
    assert exc.value.code == "address-unavailable"
    old.refresh_from_db()
    assert old.state == PublicIpState.QUARANTINED


def test_an_address_asked_for_in_the_zone_is_granted() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10",))

    ip, _ = service.attach(make_vm(), address="198.51.100.1")

    assert ip.edge.name == "edge-de"


@pytest.mark.parametrize("state", [VmState.DECOMMISSIONING, VmState.DESTROYED])
def test_attach_refuses_a_vm_that_is_not_live(state: str) -> None:
    make_edge()
    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm(state=state))
    assert exc.value.code == "vm-not-live"
    assert not PublicIP.objects.filter(state=PublicIpState.ATTACHED).exists()


def test_one_attached_address_per_vm_is_a_database_constraint() -> None:
    from django.db import IntegrityError, transaction

    edge = make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    vm = make_vm()
    service.attach(vm)
    with pytest.raises(IntegrityError), transaction.atomic():
        PublicIP.objects.filter(edge=edge, state=PublicIpState.FREE).update(
            state=PublicIpState.ATTACHED, vm=vm
        )


# ── detach / quarantine ───────────────────────────────────────────────


def test_detach_quarantines_and_bumps_the_revision() -> None:
    edge = make_edge()
    vm = make_vm()
    service.attach(vm)
    rev = _revision(edge)

    ip = service.detach(vm)

    assert ip is not None
    ip.refresh_from_db()
    assert ip.state == PublicIpState.QUARANTINED
    assert ip.vm == vm  # previous holder kept for audit
    assert ip.released_at is not None
    assert _revision(edge) == rev + 1
    assert service.detach(vm) is None  # idempotent


def test_a_quarantined_address_is_not_reallocated() -> None:
    make_edge(addresses=("203.0.113.10",))
    vm1 = make_vm("vm-1")
    service.attach(vm1)
    service.detach(vm1)

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-2"))
    assert exc.value.code == "no-free-public-ip"


def test_quarantine_expires_only_after_the_window() -> None:
    make_edge(addresses=("203.0.113.10",))
    vm = make_vm()
    service.attach(vm)
    ip = service.detach(vm)
    assert ip is not None

    service.reconcile(now=timezone.now() + timedelta(minutes=59))
    ip.refresh_from_db()
    assert ip.state == PublicIpState.QUARANTINED

    service.reconcile(now=timezone.now() + timedelta(hours=1, seconds=1))
    ip.refresh_from_db()
    assert ip.state == PublicIpState.FREE
    assert ip.vm is None
    assert ip.target_ip is None
    assert ip.last_tenant_id == ""

    other, _ = service.attach(make_vm("vm-2"))
    assert other.pk == ip.pk


# ── edge feed ─────────────────────────────────────────────────────────


def test_desired_state_lists_only_attached_addresses_with_a_known_target() -> None:
    edge = make_edge(addresses=("203.0.113.10", "203.0.113.11", "203.0.113.12"))
    known, unknown, gone = make_vm("vm-known"), make_vm("vm-unknown"), make_vm("vm-gone")
    ip_known, _ = service.attach(known)
    service.attach(unknown)
    ip_gone, _ = service.attach(gone)
    PublicIP.objects.filter(pk__in=[ip_known.pk, ip_gone.pk]).update(target_ip="100.70.0.9")
    PublicIP.objects.filter(pk=ip_known.pk).update(target_ip="100.70.0.5")
    service.detach(gone)

    state = service.desired_state(edge)

    assert state == {
        "edge": edge.name,
        "revision": _revision(edge),
        "per_ip_mbps": 1000,
        "addresses": [
            {"address": ip_known.address, "vm_id": "vm-known", "target_ip": "100.70.0.5"}
        ],
    }


def test_record_applied_stores_the_report_and_refuses_a_future_revision() -> None:
    edge = make_edge()
    rev = _revision(edge)

    service.record_applied(edge, rev, {"errors": []})
    edge.refresh_from_db()
    assert edge.applied_revision == rev
    assert edge.last_seen_at is not None
    assert edge.last_report == {"errors": []}

    with pytest.raises(NetworkError) as exc:
        service.record_applied(edge, rev + 1, {})
    assert exc.value.code == "revision-ahead"

    IngressEdge.objects.filter(pk=edge.pk).delete()
    with pytest.raises(NetworkError) as exc:
        service.record_applied(edge, rev, {})
    assert exc.value.code == "edge-not-found"


def test_availability_counts_active_edges_only() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-us", "US", ("192.0.2.1",), status="disabled")
    service.attach(make_vm(), region_hint="FR")

    assert service.availability() == {
        "total_free": 2,
        "regions": [
            {"region": "DE", "free": 1, "total": 1, "edges": 1},
            {"region": "FR", "free": 1, "total": 2, "edges": 1},
        ],
    }
    assert service.availability("fr") == {
        "total_free": 2,
        "regions": [{"region": "FR", "free": 1, "total": 2, "edges": 1}],
    }


def test_availability_of_a_region_counts_its_zone_only() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_edge("edge-br", "BR", ("198.51.100.1",))

    assert service.availability()["total_free"] == 4
    assert service.availability("AU")["total_free"] == 1
    assert service.availability("NL") == {"total_free": 2, "regions": []}
    assert service.availability("BR")["total_free"] == 1
    assert service.availability("AR")["total_free"] == 0


@pytest.mark.parametrize(
    "raw", ["10.0.0.1", "100.64.1.1", "127.0.0.1", "192.168.1.1", "224.0.0.1", "0.1.2.3",
            "::1", "nope", "172.16.0.1", "255.255.255.255"]
)
def test_parse_public_address_refuses_non_public(raw: str) -> None:
    with pytest.raises(NetworkError):
        service.parse_public_address(raw)


def test_parse_public_address_normalises() -> None:
    assert service.parse_public_address(" 203.0.113.7 ") == "203.0.113.7"
