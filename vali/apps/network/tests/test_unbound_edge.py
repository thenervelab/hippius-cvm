"""An edge registered before it has a NetBird peer.

The edge's NetBird setup key is minted for an edge that already exists, so
it cannot enrol before it is registered: `netbird_ip` is optional at
create, and PATCH `netbird_ip` binds it later. Until then the edge is
unbound: no attachment, no routing, no address served.
"""

from __future__ import annotations

import pytest
from django.core.cache import cache
from django.urls import reverse
from rest_framework.test import APIClient

from apps.network import service
from apps.network.models import IngressEdge
from apps.network.service import NetworkError

from .conftest import FakeNetbird, make_vm

pytestmark = pytest.mark.django_db

_CREATE = {"name": "edge-a", "region": "FR", "addresses": ["203.0.113.10"]}


def _create_unbound(client: APIClient) -> dict:
    r = client.post(reverse("network_edges"), _CREATE, format="json")
    assert r.status_code == 201, r.content
    return r.json()


def test_create_without_netbird_ip_is_unbound_and_needs_no_netbird(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    body = _create_unbound(root_client)

    assert body["bound"] is False
    assert body["netbird_ip"] is None
    assert body["netbird_peer_id"] == ""
    assert body["status"] == "active"  # kept as given; eligibility is `bound`
    assert body["counts"]["free"] == 1
    assert fake_netbird.calls == []


def test_two_unbound_edges_can_coexist(root_client: APIClient) -> None:
    _create_unbound(root_client)
    r = root_client.post(
        reverse("network_edges"), {"name": "edge-c", "region": "FR"}, format="json"
    )
    assert r.status_code == 201, r.content


def test_a_bound_edge_reports_bound(root_client: APIClient, fake_netbird: FakeNetbird) -> None:
    fake_netbird.add_peer("edge", "100.90.1.1")
    r = root_client.post(
        reverse("network_edges"), {**_CREATE, "netbird_ip": "100.90.1.1"}, format="json"
    )
    assert r.json()["bound"] is True


def test_attach_skips_an_unbound_edge(root_client: APIClient) -> None:
    _create_unbound(root_client)
    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm(), region_hint="FR")
    assert exc.value.code == "no-free-public-ip"


def test_availability_does_not_count_an_unbound_edge(root_client: APIClient) -> None:
    _create_unbound(root_client)
    assert service.availability() == {"total_free": 0, "regions": []}


def test_desired_state_of_an_unbound_edge_is_empty(root_client: APIClient) -> None:
    _create_unbound(root_client)
    body = root_client.get(reverse("network_edge_desired", kwargs={"name": "edge-a"})).json()
    edge = IngressEdge.objects.get(name="edge-a")
    assert body == {
        "edge": "edge-a",
        "revision": edge.desired_revision,
        "per_ip_mbps": 1000,
        "addresses": [],
    }


def test_desired_state_serves_nothing_once_an_edge_has_no_peer(root_client: APIClient) -> None:
    """Even an attached, targeted address is withheld: nothing could reach
    an edge without a peer over the overlay."""
    from apps.network.models import PublicIP

    _create_unbound(root_client)
    edge = IngressEdge.objects.get(name="edge-a")
    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id="peer1")
    ip, _ = service.attach(make_vm(), region_hint="FR")
    PublicIP.objects.filter(pk=ip.pk).update(target_ip="100.70.0.5")
    assert service.desired_state(edge)["addresses"] != []

    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id="")
    assert service.desired_state(edge)["addresses"] == []


def test_reconcile_gives_an_unbound_edge_no_routing(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    _create_unbound(root_client)
    cache.clear()

    service.reconcile()

    assert fake_netbird.routes == {} and fake_netbird.policies == {}
    assert fake_netbird.groups == {}
    assert fake_netbird.writes == []


def test_reconcile_removes_stale_routing_of_an_unbound_edge(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    """E.g. a name re-created unbound after a delete that raced a pass."""
    from apps.orchestration import effects

    _create_unbound(root_client)
    effects.ensure_edge_routing("edge-a", fake_netbird.add_peer("old", "100.90.9.9"))
    cache.clear()

    service.reconcile()

    assert fake_netbird.routes == {} and fake_netbird.policies == {}
    assert fake_netbird.groups == {}


def test_patch_netbird_ip_binds_it_and_makes_it_usable(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    _create_unbound(root_client)
    peer = fake_netbird.add_peer("edge", "100.90.1.1")

    r = root_client.patch(
        reverse("network_edge", kwargs={"name": "edge-a"}),
        {"netbird_ip": "100.90.1.1"},
        format="json",
    )

    assert r.status_code == 200, r.content
    assert r.json()["bound"] is True
    assert r.json()["netbird_peer_id"] == peer
    ip, _ = service.attach(make_vm(), region_hint="FR")
    assert ip.edge.name == "edge-a"
    service.reconcile()  # the bind requested a NetBird pass
    [route] = fake_netbird.routes.values()
    assert route["peer"] == peer


def test_delete_an_unbound_edge_without_netbird(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    _create_unbound(root_client)
    fake_netbird.failing = [".*"]
    r = root_client.delete(reverse("network_edge", kwargs={"name": "edge-a"}))
    assert r.status_code == 204
    assert not IngressEdge.objects.exists()
