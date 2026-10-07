"""`reconcile()` and the NetBird exit-routing effects, against `FakeNetbird`."""

from __future__ import annotations

import logging

import pytest
from django.core.cache import cache

from apps.lifecycle.models import Vm, VmState
from apps.network import service
from apps.network.models import IngressEdge, PublicIP, PublicIpState
from apps.orchestration import effects

from .conftest import FakeNetbird, make_edge, make_vm

pytestmark = pytest.mark.django_db


def _edge_with_peer(nb: FakeNetbird, name: str = "edge-a", **kw) -> IngressEdge:
    edge = make_edge(name, **kw)
    peer_id = nb.add_peer(f"edge-{name}", edge.netbird_ip)
    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id=peer_id)
    edge.refresh_from_db()
    return edge


@pytest.fixture
def netlog(caplog: pytest.LogCaptureFixture):
    """`caplog` for `apps.network`: the project's `LOGGING` stops `apps.*`
    from propagating to the root logger caplog listens on, so its handler
    is attached to the logger itself."""
    logger = logging.getLogger("apps.network")
    logger.addHandler(caplog.handler)
    yield caplog
    logger.removeHandler(caplog.handler)


def _reconcile() -> service.ReconcileReport:
    cache.clear()  # past the NetBird throttle
    return service.reconcile()


def _edge_applies(edge: IngressEdge) -> None:
    """The edge agent caught up with everything vali asked of it."""
    edge.refresh_from_db()
    service.record_applied(edge, edge.desired_revision, {})


def _joined(nb: FakeNetbird, edge: IngressEdge, vm_id: str, ip: str) -> str:
    """Attach-time steady state: the VM's peer resolved, the edge applied
    its mapping, the peer joined the edge's group."""
    peer = nb.vm_peer(vm_id, ip)
    _reconcile()
    _edge_applies(edge)
    _reconcile()
    return peer


# ── ensure_edge_routing ───────────────────────────────────────────────


def test_ensure_edge_routing_creates_groups_route_and_policy(fake_netbird: FakeNetbird) -> None:
    edge_peer = fake_netbird.add_peer("edge", "100.90.0.1")

    routing = effects.ensure_edge_routing("edge-a", edge_peer)

    pip = fake_netbird.group_named("hippius-pip-vms-edge-a")
    edge_group = fake_netbird.group_named("hippius-pip-gw-edge-a")
    assert pip is not None and edge_group is not None
    assert routing.pip_group_id == pip["id"]
    assert routing.pip_peer_ids == frozenset()
    assert fake_netbird.member_ids("hippius-pip-gw-edge-a") == {edge_peer}

    [route] = fake_netbird.routes.values()
    assert route["network"] == "0.0.0.0/0"
    assert route["peer"] == edge_peer
    assert route["masquerade"] is False
    assert route["enabled"] is True
    assert route["groups"] == [pip["id"]]
    assert route["network_id"] == "hippius-pip-edge-a"
    assert "peer_groups" not in route

    [policy] = fake_netbird.policies.values()
    [rule] = policy["rules"]
    assert rule["bidirectional"] is True
    assert rule["protocol"] == "all"
    assert rule["action"] == "accept"
    assert rule["sources"] == [pip["id"]]
    assert rule["destinations"] == [edge_group["id"]]


def test_ensure_edge_routing_is_idempotent(fake_netbird: FakeNetbird) -> None:
    edge_peer = fake_netbird.add_peer("edge", "100.90.0.1")
    effects.ensure_edge_routing("edge-a", edge_peer)
    writes = len(fake_netbird.writes)

    effects.ensure_edge_routing("edge-a", edge_peer)

    assert len(fake_netbird.writes) == writes
    assert len(fake_netbird.routes) == 1
    assert len(fake_netbird.policies) == 1
    assert len(fake_netbird.groups) == 2


def test_ensure_edge_routing_repairs_drift(fake_netbird: FakeNetbird) -> None:
    old_peer = fake_netbird.add_peer("edge-old", "100.90.0.1")
    new_peer = fake_netbird.add_peer("edge-new", "100.90.0.2")
    effects.ensure_edge_routing("edge-a", old_peer)
    [route] = fake_netbird.routes.values()
    route["masquerade"] = True

    effects.ensure_edge_routing("edge-a", new_peer)

    [route] = fake_netbird.routes.values()
    assert route["peer"] == new_peer
    assert route["masquerade"] is False
    assert fake_netbird.member_ids("hippius-pip-gw-edge-a") == {new_peer}


def test_group_add_and_remove_peer(fake_netbird: FakeNetbird) -> None:
    edge_peer = fake_netbird.add_peer("edge", "100.90.0.1")
    vm_peer = fake_netbird.vm_peer("vm-1", "100.70.0.5")
    routing = effects.ensure_edge_routing("edge-a", edge_peer)

    effects.group_add_peer(routing.pip_group_id, vm_peer)
    effects.group_add_peer(routing.pip_group_id, vm_peer)
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {vm_peer}

    effects.group_remove_peer(routing.pip_group_id, vm_peer)
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


def test_remove_edge_routing_deletes_everything(fake_netbird: FakeNetbird) -> None:
    edge_peer = fake_netbird.add_peer("edge", "100.90.0.1")
    effects.ensure_edge_routing("edge-a", edge_peer)
    effects.ensure_edge_routing("edge-b", edge_peer)

    effects.remove_edge_routing("edge-a")

    assert [r["network_id"] for r in fake_netbird.routes.values()] == ["hippius-pip-edge-b"]
    assert [p["name"] for p in fake_netbird.policies.values()] == ["hippius-pip-edge-b"]
    assert {g["name"] for g in fake_netbird.groups.values()} == {
        "hippius-pip-vms-edge-b",
        "hippius-pip-gw-edge-b",
    }


# ── reconcile ─────────────────────────────────────────────────────────


def test_reconcile_sets_the_target_then_joins_once_the_edge_applied(
    fake_netbird: FakeNetbird,
) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    vm_peer = fake_netbird.vm_peer(vm.vm_id, "100.70.0.5")
    rev = edge.desired_revision + 1  # the attach

    report = _reconcile()

    ip.refresh_from_db()
    edge.refresh_from_db()
    assert ip.target_ip == "100.70.0.5"
    assert edge.desired_revision == rev + 1
    assert report.retargeted == 1
    assert service.desired_state(edge)["addresses"] == [
        {"address": ip.address, "vm_id": vm.vm_id, "target_ip": "100.70.0.5"}
    ]
    # The edge has not rendered the mapping yet: the VM's default route must
    # not move to it (its egress would be dropped, and the edge may still
    # DNAT a stale address to this overlay IP).
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()

    _edge_applies(edge)
    report = _reconcile()

    assert report.membership_changes == 1
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {vm_peer}


def test_reconcile_follows_a_changed_overlay_address(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    _joined(fake_netbird, edge, vm.vm_id, "100.70.0.5")
    edge.refresh_from_db()
    rev = edge.desired_revision
    ip.refresh_from_db()
    epoch = ip.epoch

    # A relaunch / migration re-enrolled the guest: new peer, new address.
    old_name = f"hippius-tenant-{vm.vm_id}"
    fake_netbird.peers = [p for p in fake_netbird.peers if p["name"] != old_name]
    new_peer = fake_netbird.vm_peer(vm.vm_id, "100.70.0.77")
    _reconcile()

    ip.refresh_from_db()
    edge.refresh_from_db()
    assert ip.target_ip == "100.70.0.77"
    assert ip.epoch == epoch + 1  # a new (vm, target) binding
    assert edge.desired_revision == rev + 1
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()

    _edge_applies(edge)
    _reconcile()
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {new_peer}


def test_reconcile_targets_the_recorded_peer_not_a_peer_under_the_vms_name(
    fake_netbird: FakeNetbird,
) -> None:
    # The VM's own peer is bound (by its setup key) under another name; a
    # second peer claims the VM's name. The public IP must follow the bound
    # one — a name is only the hostname a guest chose to send.
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    mine = fake_netbird.add_peer("my-hostname", "100.70.0.5")
    fake_netbird.vm_peer(vm.vm_id, "100.70.0.66")
    Vm.objects.filter(pk=vm.pk).update(netbird_peer_id=mine)

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip == "100.70.0.5"


def _minted(vm: Vm, key_id: str, *, persistent: bool, peer_id: str = "", age_s: int = 0):
    from datetime import timedelta

    from django.utils import timezone

    from apps.lifecycle.models import VmNetbirdKey

    now = timezone.now()
    key = VmNetbirdKey.objects.create(
        vm=vm,
        setup_key_id=key_id,
        persistent=persistent,
        expires_at=now + timedelta(hours=1),
        peer_id=peer_id,
        settled_at=now if peer_id else None,
    )
    VmNetbirdKey.objects.filter(pk=key.pk).update(created_at=now - timedelta(seconds=age_s))
    return key


def _enrolment(key_id: str, peer_id: str) -> dict:
    return {"activity_code": "peer.setupkey.add", "initiator_id": key_id, "target_id": peer_id}


def test_reconcile_keeps_the_first_launch_peer_over_a_relaunch_key_peer(
    fake_netbird: FakeNetbird,
) -> None:
    # A tenant enrolled an outside machine with a relaunch key: it must not
    # take the VM's public IP while the VM's own persistent peer exists.
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    real = fake_netbird.add_peer("real", "100.70.0.5")
    outside = fake_netbird.add_peer("outside", "100.70.0.66")
    _minted(vm, "sk-first", persistent=True, peer_id=real, age_s=3600)
    _minted(vm, "sk-relaunch", persistent=False, peer_id=outside)

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip == "100.70.0.5"


def test_reconcile_follows_a_connected_relaunch_peer_off_a_dead_first_peer(
    fake_netbird: FakeNetbird,
) -> None:
    # The guest lost its NetBird state and re-enrolled with a relaunch key;
    # its persistent first peer lingers, disconnected, on its old address.
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    dead = fake_netbird.add_peer("first", "100.70.0.5", connected=False)
    live = fake_netbird.add_peer("relaunch", "100.70.0.6")
    _minted(vm, "sk-first", persistent=True, peer_id=dead, age_s=3600)
    _minted(vm, "sk-relaunch", persistent=False, peer_id=live)

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip == "100.70.0.6"


def test_reconcile_binds_a_re_enrolled_peer_before_it_retargets(
    fake_netbird: FakeNetbird,
) -> None:
    # The recorded peer is gone; the guest re-enrolled (under another name)
    # with a newer key vali minted. The address follows it on THIS pass.
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    _minted(vm, "sk-old", persistent=True, peer_id="cgone", age_s=3600)
    _minted(vm, "sk-new", persistent=True)
    new = fake_netbird.add_peer("renamed", "100.70.0.9")
    fake_netbird.events = [_enrolment("sk-new", new)]

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip == "100.70.0.9"


def test_reconcile_never_targets_a_peer_bound_to_another_vm_by_name(
    fake_netbird: FakeNetbird,
) -> None:
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    other = make_vm("vm-other")
    impostor = fake_netbird.vm_peer(vm.vm_id, "100.70.0.66")
    _minted(other, "sk-other", persistent=True, peer_id=impostor)

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip is None


def test_reconcile_is_idempotent(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    service.attach(vm)
    _joined(fake_netbird, edge, vm.vm_id, "100.70.0.5")
    edge.refresh_from_db()
    rev, writes = edge.desired_revision, len(fake_netbird.writes)

    report = _reconcile()

    edge.refresh_from_db()
    assert edge.desired_revision == rev
    assert len(fake_netbird.writes) == writes
    assert report == service.ReconcileReport()


def test_reconcile_keeps_the_target_of_a_disconnected_peer(fake_netbird: FakeNetbird) -> None:
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    fake_netbird.vm_peer(vm.vm_id, "100.70.0.5")
    _reconcile()
    for p in fake_netbird.peers:
        p["connected"] = False  # rebooting: the record stays

    _reconcile()

    ip.refresh_from_db()
    assert ip.target_ip == "100.70.0.5"


def test_reconcile_drops_the_target_when_the_peer_record_is_gone(
    fake_netbird: FakeNetbird,
) -> None:
    """The overlay address of a deleted peer can be handed to another VM:
    the edge must stop forwarding to it at once."""
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    fake_netbird.vm_peer(vm.vm_id, "100.70.0.5")
    _reconcile()
    edge.refresh_from_db()
    rev = edge.desired_revision
    fake_netbird.peers = [p for p in fake_netbird.peers if p["name"].startswith("edge-")]

    report = _reconcile()

    ip.refresh_from_db()
    edge.refresh_from_db()
    assert ip.target_ip is None
    assert ip.state == PublicIpState.ATTACHED
    assert report.retargeted == 1
    assert edge.desired_revision == rev + 1
    assert service.desired_state(edge)["addresses"] == []


def test_reconcile_removes_a_detached_vm_from_the_group(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    service.attach(vm)
    peer = _joined(fake_netbird, edge, vm.vm_id, "100.70.0.5")
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {peer}

    service.detach(vm)
    service.reconcile()  # detach forced the next pass — no cache clear needed

    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


def test_reconcile_releases_the_address_of_a_destroyed_vm(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    edge.refresh_from_db()
    rev = edge.desired_revision

    report = _reconcile()

    ip.refresh_from_db()
    edge.refresh_from_db()
    assert report.released == 1
    assert ip.state == PublicIpState.QUARANTINED
    assert edge.desired_revision == rev + 1


def test_reconcile_never_rebinds_an_edge_to_whoever_holds_its_address(
    fake_netbird: FakeNetbird, netlog: pytest.LogCaptureFixture
) -> None:
    """If the edge's peer disappears and NetBird hands its overlay address
    to another peer, that peer must NOT become the exit router of the
    edge's VMs."""
    edge = _edge_with_peer(fake_netbird)
    old_id = edge.netbird_peer_id
    _reconcile()
    fake_netbird.peers = []
    intruder = fake_netbird.vm_peer("vm-evil", edge.netbird_ip)

    _reconcile()

    edge.refresh_from_db()
    assert edge.netbird_peer_id == old_id
    [route] = fake_netbird.routes.values()
    assert route["peer"] == old_id != intruder
    assert "its NetBird peer" in netlog.text


def test_names_of_different_edges_never_collide(fake_netbird: FakeNetbird) -> None:
    """`edge-a` and `a` are both valid names; their groups must stay
    apart (a shared group would mix one edge's VMs with another's gateway)."""
    a = fake_netbird.add_peer("edge-a", "100.90.0.1")
    b = fake_netbird.add_peer("edge-b", "100.90.0.2")
    effects.ensure_edge_routing("a", a)
    effects.ensure_edge_routing("edge-a", b)
    effects.ensure_edge_routing("a", a)

    names = [g["name"] for g in fake_netbird.groups.values()]
    assert len(names) == len(set(names)) == 4
    assert fake_netbird.member_ids("hippius-pip-gw-a") == {a}
    assert fake_netbird.member_ids("hippius-pip-gw-edge-a") == {b}
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


def test_reconcile_garbage_collects_a_deleted_edges_routing(fake_netbird: FakeNetbird) -> None:
    _edge_with_peer(fake_netbird, "edge-a", addresses=("203.0.113.10",))
    _edge_with_peer(fake_netbird, "edge-b", addresses=("203.0.113.20",))
    _reconcile()
    IngressEdge.objects.filter(name="edge-b").delete()  # its cleanup never ran

    _reconcile()

    assert [r["network_id"] for r in fake_netbird.routes.values()] == ["hippius-pip-edge-a"]
    assert [p["name"] for p in fake_netbird.policies.values()] == ["hippius-pip-edge-a"]
    assert {g["name"] for g in fake_netbird.groups.values()} == {
        "hippius-pip-vms-edge-a",
        "hippius-pip-gw-edge-a",
    }


def test_reconcile_collects_routing_left_by_the_last_edge(fake_netbird: FakeNetbird) -> None:
    """A pass that raced the delete re-created the routing of the only
    edge; once it is gone, the next pass still collects it."""
    edge = _edge_with_peer(fake_netbird)
    effects.ensure_edge_routing(edge.name, edge.netbird_peer_id)
    service.delete_edge(edge)
    assert not IngressEdge.objects.exists()

    service.reconcile()

    assert fake_netbird.routes == {} and fake_netbird.policies == {}
    assert fake_netbird.groups == {}


def test_departures_happen_even_when_the_edge_peer_is_gone(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    service.attach(vm)
    peer = _joined(fake_netbird, edge, vm.vm_id, "100.70.0.5")
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {peer}
    fake_netbird.peers = [p for p in fake_netbird.peers if p["id"] != edge.netbird_peer_id]

    service.detach(vm)
    service.reconcile()

    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


def test_reconcile_uses_a_rebind_that_landed_mid_pass(fake_netbird: FakeNetbird) -> None:
    edge = _edge_with_peer(fake_netbird)
    stale = IngressEdge.objects.get(pk=edge.pk)  # the pass's snapshot
    new_peer = fake_netbird.add_peer("edge-reenrolled", "100.90.7.7")
    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id=new_peer, netbird_ip="100.90.7.7")

    service._sync_routing([stale], fake_netbird.peers, {})

    [route] = fake_netbird.routes.values()
    assert route["peer"] == new_peer


def test_reconcile_refuses_a_tenant_peer_as_an_edge(
    fake_netbird: FakeNetbird, netlog: pytest.LogCaptureFixture
) -> None:
    edge = make_edge()
    tenant = fake_netbird.vm_peer("vm-x", edge.netbird_ip)
    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id=tenant)

    _reconcile()

    assert fake_netbird.routes == {}
    assert "is a tenant VM" in netlog.text


def test_reconcile_survives_netbird_failures(
    fake_netbird: FakeNetbird, netlog: pytest.LogCaptureFixture
) -> None:
    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    fake_netbird.failing = [r"/api/peers$"]

    report = _reconcile()

    ip.refresh_from_db()
    # The database half still ran.
    assert report.released == 1
    assert ip.state == PublicIpState.QUARANTINED
    assert "NetBird peer listing failed" in netlog.text


def test_reconcile_survives_a_failing_edge(
    fake_netbird: FakeNetbird, netlog: pytest.LogCaptureFixture
) -> None:
    _edge_with_peer(fake_netbird, "edge-a", addresses=("203.0.113.10",))
    _edge_with_peer(fake_netbird, "edge-b", addresses=("203.0.113.20",))
    fake_netbird.failing = [r"/api/routes$"]

    _reconcile()

    assert "routing for edge edge-a failed" in netlog.text
    assert "routing for edge edge-b failed" in netlog.text


def test_reconcile_throttles_netbird(fake_netbird: FakeNetbird) -> None:
    _edge_with_peer(fake_netbird)
    _reconcile()
    calls = len(fake_netbird.calls)

    service.reconcile()  # inside the throttle window

    assert len(fake_netbird.calls) == calls


def test_reconcile_without_edges_only_reads(fake_netbird: FakeNetbird) -> None:
    assert _reconcile() == service.ReconcileReport()
    # The peer listing is read for the VMs' overlay addresses
    # (`netbird_binding.refresh_overlay_ips`), edges or not.
    assert sorted(fake_netbird.calls) == [
        ("GET", "/api/groups"), ("GET", "/api/peers"), ("GET", "/api/policies"),
        ("GET", "/api/routes"),
    ]
    assert fake_netbird.writes == []


def test_reconcile_leaves_an_unconfigured_netbird_alone(
    fake_netbird: FakeNetbird, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "")
    assert _reconcile() == service.ReconcileReport()
    assert fake_netbird.calls == []


def test_a_failing_join_never_blocks_a_departure(
    fake_netbird: FakeNetbird, monkeypatch: pytest.MonkeyPatch
) -> None:
    edge = _edge_with_peer(fake_netbird, addresses=("203.0.113.10", "203.0.113.11"))
    leaving, joining = make_vm("vm-leave"), make_vm("vm-join")
    service.attach(leaving)
    _joined(fake_netbird, edge, leaving.vm_id, "100.70.0.5")
    # One pass must both drop `leaving` and admit `joining`.
    service.detach(leaving)
    ip, _ = service.attach(joining)
    fake_netbird.vm_peer(joining.vm_id, "100.70.0.6")
    PublicIP.objects.filter(pk=ip.pk).update(target_ip="100.70.0.6")
    _edge_applies(edge)

    def _refused(*_a: object) -> None:
        raise effects.EffectError("netbird:group-add-peer: API returned HTTP 500")

    monkeypatch.setattr(effects, "group_add_peer", _refused)
    _reconcile()

    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


@pytest.mark.parametrize("edge_caught_up_again", [False, True])
def test_a_join_is_rechecked_right_before_it_happens(
    fake_netbird: FakeNetbird, edge_caught_up_again: bool
) -> None:
    """A detach that lands after the pass took its snapshot stops the join —
    even when the edge has already applied the detach revision, so the
    revision gate alone would pass."""
    edge = _edge_with_peer(fake_netbird)
    vm = make_vm()
    service.attach(vm)
    fake_netbird.vm_peer(vm.vm_id, "100.70.0.5")
    _reconcile()
    _edge_applies(edge)
    peers = effects.list_netbird_peers()
    _, members = service._retarget(peers)

    service.detach(vm)  # between the snapshot and the join
    if edge_caught_up_again:
        _edge_applies(edge)
    service._sync_routing([edge], peers, members)

    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()


def test_a_vm_leaves_its_old_edge_before_joining_the_new_one(
    fake_netbird: FakeNetbird, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Departures run across ALL edges before any join, and a failed
    departure holds every join back: the peer is never on both edges."""
    new_edge = _edge_with_peer(fake_netbird, "edge-a", addresses=("203.0.113.10",))
    old_edge = _edge_with_peer(fake_netbird, "edge-z", addresses=("203.0.113.20",))
    IngressEdge.objects.filter(pk=new_edge.pk).update(status="draining")
    vm = make_vm()
    service.attach(vm)  # lands on edge-z, the only active one
    peer = _joined(fake_netbird, old_edge, vm.vm_id, "100.70.0.5")
    assert fake_netbird.member_ids("hippius-pip-vms-edge-z") == {peer}

    IngressEdge.objects.filter(pk=new_edge.pk).update(status="active")
    IngressEdge.objects.filter(pk=old_edge.pk).update(status="draining")
    service.detach(vm)
    ip, _ = service.attach(vm)
    assert ip.edge == new_edge
    PublicIP.objects.filter(pk=ip.pk).update(target_ip="100.70.0.5")
    _edge_applies(new_edge)

    real_remove = effects.group_remove_peer
    refusing = True

    def _remove(group_id: str, peer_id: str) -> None:
        if refusing:
            raise effects.EffectError("netbird:group-remove-peer: API returned HTTP 500")
        real_remove(group_id, peer_id)

    # The departure from edge-z fails: the join to edge-a must wait.
    monkeypatch.setattr(effects, "group_remove_peer", _remove)
    _reconcile()
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == set()

    refusing = False
    _reconcile()
    assert fake_netbird.member_ids("hippius-pip-vms-edge-z") == set()
    assert fake_netbird.member_ids("hippius-pip-vms-edge-a") == {peer}


def test_the_orchestration_tick_runs_reconcile(fake_netbird: FakeNetbird) -> None:
    from apps.orchestration.service import tick_once

    _edge_with_peer(fake_netbird)
    vm = make_vm()
    ip, _ = service.attach(vm)
    fake_netbird.vm_peer(vm.vm_id, "100.70.0.5")

    report = tick_once()

    ip.refresh_from_db()
    assert report.public_ip_retargets == 1
    assert ip.target_ip == "100.70.0.5"
    assert PublicIP.objects.get(pk=ip.pk).state == PublicIpState.ATTACHED


def test_reconcile_hands_its_peer_listing_to_the_relaunch_key_revoke(
    fake_netbird: FakeNetbird, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same snapshot, after the bindings were closed — and a failure there
    never breaks the routing pass."""
    from apps.orchestration import netbird_binding

    peer = fake_netbird.add_peer("hippius-tenant-vm-x", "100.70.0.4")
    seen: list[list[str]] = []

    def revoke(peers: list[dict]) -> int:
        seen.append([p["id"] for p in peers])
        raise RuntimeError("boom")

    monkeypatch.setattr(netbird_binding, "revoke_unneeded_relaunch_keys", revoke)

    _reconcile()

    assert seen == [[peer]]
