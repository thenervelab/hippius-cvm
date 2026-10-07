"""The HTTP surface: `/v1/vm/<id>/public-ip` and `/v1/network/...`."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import URLPattern, URLResolver, get_resolver, reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity import scoping
from apps.network import service
from apps.network.models import IngressEdge, PublicIP, PublicIpState
from apps.orchestration import effects
from apps.orchestration.permissions import IsOrchestrationRoot

from .conftest import FakeNetbird, make_edge, make_vm

pytestmark = pytest.mark.django_db


def _vm_url(vm_id: str = "vm-1") -> str:
    return reverse("vm_public_ip", kwargs={"vm_id": vm_id})


def _edge_url(name: str, suffix: str = "") -> str:
    return reverse(f"network_edge{suffix}", kwargs={"name": name})


# ── every route is root-only ──────────────────────────────────────────


def _network_routes() -> list[tuple[str, type]]:
    out: list[tuple[str, type]] = []

    def walk(patterns, prefix: str = "") -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                cls = getattr(p.callback, "cls", None)
                if cls is not None and cls.__module__ == "apps.network.views":
                    out.append((prefix + str(p.pattern), cls))

    walk(get_resolver().url_patterns)
    return out


def test_every_network_route_is_root_only_and_operator_scoped() -> None:
    """`/v1/network` is published as a PREFIX on the public Ingress, so a
    route added under it later is public the moment it exists. Pin the gate
    on every one."""
    routes = _network_routes()
    assert len(routes) == 10
    for route, cls in routes:
        assert IsOrchestrationRoot in cls.permission_classes, route
        assert scoping.declared_scope(cls) == scoping.OPERATOR_ONLY, route


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("get", "/v1/vm/vm-1/public-ip"),
        ("post", "/v1/vm/vm-1/public-ip"),
        ("delete", "/v1/vm/vm-1/public-ip"),
        ("get", "/v1/network/availability"),
        ("get", "/v1/network/edges"),
        ("post", "/v1/network/edges"),
        ("get", "/v1/network/edges/edge-a"),
        ("get", "/v1/network/edges/edge-a/desired"),
        ("post", "/v1/network/edges/edge-a/applied"),
        ("get", "/v1/network/egress-regions"),
        ("get", "/v1/network/egress-regions/AU"),
        ("patch", "/v1/network/egress-regions/AU"),
        ("get", "/v1/network/public-ips/203.0.113.10/smtp"),
        ("post", "/v1/network/public-ips/203.0.113.10/smtp"),
    ],
)
def test_tenant_and_non_root_principals_are_refused(
    method: str, url: str, tenant_client: APIClient, operator_client: APIClient
) -> None:
    make_vm()
    make_edge()
    assert getattr(tenant_client, method)(url, {}, format="json").status_code == 403
    assert getattr(operator_client, method)(url, {}, format="json").status_code == 403
    assert getattr(APIClient(), method)(url, {}, format="json").status_code == 401


# ── /v1/vm/<id>/public-ip ─────────────────────────────────────────────


def test_attach_read_detach(root_client: APIClient) -> None:
    make_edge()
    make_vm()

    r = root_client.post(_vm_url(), {"region": "FR"}, format="json")
    assert r.status_code == 201, r.content
    body = r.json()
    assert set(body) == {"vm_id", "address", "edge", "region", "state", "attached_at"}
    assert body["vm_id"] == "vm-1"
    assert body["address"] == "203.0.113.10"
    assert body["edge"] == "edge-a"
    assert body["region"] == "FR"
    assert body["state"] == "attached"

    again = root_client.post(_vm_url(), {}, format="json")
    assert again.status_code == 200
    assert again.json() == body

    assert root_client.get(_vm_url()).json() == body

    assert root_client.delete(_vm_url()).status_code == 204
    gone = root_client.get(_vm_url())
    assert gone.status_code == 404
    assert gone.json()["error"] == "no-public-ip"
    assert root_client.delete(_vm_url()).json()["error"] == "no-public-ip"


def test_attach_with_no_body(root_client: APIClient) -> None:
    make_edge()
    make_vm()
    assert root_client.post(_vm_url()).status_code == 201


def test_attach_errors(root_client: APIClient) -> None:
    make_edge()
    r = root_client.post(_vm_url("nope"), {}, format="json")
    assert (r.status_code, r.json()["error"]) == (404, "vm-not-found")

    make_vm("vm-1")
    r = root_client.post(_vm_url(), {"region": "FRA"}, format="json")
    assert (r.status_code, r.json()["error"]) == (400, "bad-region")
    r = root_client.post(_vm_url(), {"region": "FR\n"}, format="json")
    assert (r.status_code, r.json()["error"]) == (400, "bad-region")

    root_client.post(_vm_url(), {}, format="json")
    make_vm("vm-2")
    r = root_client.post(_vm_url("vm-2"), {}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "no-free-public-ip")

    make_vm("vm-3", state="destroyed")
    r = root_client.post(_vm_url("vm-3"), {}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "vm-not-live")


def test_attach_out_of_zone_is_the_usual_no_free_refusal(root_client: APIClient) -> None:
    """A full zone answers exactly as an empty pool does: same code, same
    status, so callers need no new case."""
    make_edge("edge-au", "AU", ("192.0.2.1",))
    make_vm("vm-1")
    r = root_client.post(_vm_url(), {"region": "FR"}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "no-free-public-ip")


def test_attach_reuses_the_tenants_quarantined_address(root_client: APIClient) -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    make_vm("vm-1", tenant_id="tenant-a")
    make_vm("vm-2", tenant_id="tenant-a")
    make_vm("vm-3", tenant_id="tenant-b")
    first = root_client.post(_vm_url("vm-1"), {}, format="json").json()["address"]
    assert root_client.delete(_vm_url("vm-1")).status_code == 204

    # Another tenant can neither get it by default nor ask for it.
    r = root_client.post(_vm_url("vm-3"), {"address": first}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "address-unavailable")
    r = root_client.post(_vm_url("vm-3"), {}, format="json")
    assert r.status_code == 201
    assert r.json()["address"] != first

    r = root_client.post(_vm_url("vm-2"), {"address": first}, format="json")
    assert r.status_code == 201, r.content
    assert r.json()["address"] == first


def test_attach_address_validation(root_client: APIClient) -> None:
    make_edge()
    make_vm()
    for bad in ("10.0.0.1", "nope", 7):
        r = root_client.post(_vm_url(), {"address": bad}, format="json")
        assert (r.status_code, r.json()["error"]) == (400, "bad-address"), bad
    r = root_client.post(_vm_url(), {"address": None}, format="json")
    assert r.status_code == 201


def test_vm_wire_shape_carries_the_public_ip(root_client: APIClient) -> None:
    make_edge()
    vm = make_vm()
    make_vm("vm-2")

    state = root_client.get(reverse("vm_state", kwargs={"vm_id": "vm-1"})).json()
    assert state["public_ip"] is None

    service.attach(vm)
    state = root_client.get(reverse("vm_state", kwargs={"vm_id": "vm-1"})).json()
    assert state["public_ip"] == {"address": "203.0.113.10", "edge": "edge-a", "region": "FR"}

    rows = {v["vm_id"]: v for v in root_client.get(reverse("vm_list")).json()["vms"]}
    assert rows["vm-1"]["public_ip"]["address"] == "203.0.113.10"
    assert rows["vm-2"]["public_ip"] is None


# ── availability ──────────────────────────────────────────────────────


def test_availability(root_client: APIClient) -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    body = root_client.get(reverse("network_availability"), {"region": "FR"}).json()
    assert body == {
        "total_free": 2,
        "regions": [{"region": "FR", "free": 2, "total": 2, "edges": 1}],
    }
    r = root_client.get(reverse("network_availability"), {"region": "x"})
    assert (r.status_code, r.json()["error"]) == (400, "bad-region")


# ── edges ─────────────────────────────────────────────────────────────


_EDGE_KEYS = {
    "name", "provider", "region", "status", "netbird_ip", "netbird_peer_id", "bound",
    "per_ip_mbps", "egress_ip",
    "desired_revision", "applied_revision", "last_seen_at", "last_report", "counts",
    "counts_by_pool", "addresses",
}


def test_create_edge_resolves_the_peer_and_sets_up_routing(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    peer_id = fake_netbird.add_peer("edge", "100.90.1.1")

    r = root_client.post(
        reverse("network_edges"),
        {
            "name": "edge-a",
            "provider": "some-host",
            "region": "fr",
            "netbird_ip": "100.90.1.1",
            "per_ip_mbps": 500,
            "addresses": ["203.0.113.10", "203.0.113.11", "203.0.113.10"],
        },
        format="json",
    )

    assert r.status_code == 201, r.content
    body = r.json()
    assert set(body) == _EDGE_KEYS
    assert body["region"] == "FR"
    assert body["netbird_peer_id"] == peer_id
    assert body["per_ip_mbps"] == 500
    assert body["counts"] == {"free": 2, "attached": 0, "quarantined": 0}
    assert [a["address"] for a in body["addresses"]] == ["203.0.113.10", "203.0.113.11"]
    assert set(body["addresses"][0]) == {
        "address", "state", "vm_id", "attached_at", "released_at", "last_tenant_id",
        "target_ip", "pool", "cap_mbps",
    }
    assert fake_netbird.routes == {}  # the tick writes NetBird routing
    service.reconcile()
    assert len(fake_netbird.routes) == 1

    dup = root_client.post(
        reverse("network_edges"),
        {"name": "edge-a", "region": "FR", "netbird_ip": "100.90.1.1"},
        format="json",
    )
    assert (dup.status_code, dup.json()["error"]) == (409, "edge-exists")

    listed = root_client.get(reverse("network_edges")).json()
    assert [e["name"] for e in listed["edges"]] == ["edge-a"]


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        ({"name": "Edge_1"}, "bad-name"),
        ({"name": "-edge"}, "bad-name"),
        ({"name": "e" * 29}, "bad-name"),
        ({"region": "FRA"}, "bad-region"),
        ({"region": None}, "bad-region"),
        ({"netbird_ip": "10.0.0.1"}, "bad-netbird-ip"),
        ({"addresses": ["10.0.0.1"]}, "bad-address"),
        ({"per_ip_mbps": 0}, "bad-request"),
        ({"netbird_ip": "100.90.9.9"}, "netbird-peer-not-found"),
        ({"netbird_ip": "100.90.2.2"}, "netbird-peer-not-an-edge"),
    ],
)
def test_create_edge_validation(
    root_client: APIClient, fake_netbird: FakeNetbird, patch: dict, code: str
) -> None:
    fake_netbird.add_peer("edge", "100.90.1.1")
    fake_netbird.vm_peer("vm-9", "100.90.2.2")
    body = {"name": "edge-a", "region": "FR", "netbird_ip": "100.90.1.1", **patch}
    r = root_client.post(reverse("network_edges"), body, format="json")
    assert (r.status_code, r.json()["error"]) == (400, code)
    assert not IngressEdge.objects.exists()


def test_create_edge_with_a_taken_address(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    make_edge("edge-a", addresses=("203.0.113.10",))
    fake_netbird.add_peer("edge", "100.90.1.1")
    r = root_client.post(
        reverse("network_edges"),
        {"name": "edge-b", "region": "FR", "netbird_ip": "100.90.1.1",
         "addresses": ["203.0.113.10"]},
        format="json",
    )
    assert (r.status_code, r.json()["error"]) == (409, "address-taken")
    assert not IngressEdge.objects.filter(name="edge-b").exists()


def test_create_edge_refuses_a_tenant_peer(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    fake_netbird.vm_peer("vm-1", "100.90.1.1")
    r = root_client.post(
        reverse("network_edges"),
        {"name": "edge-a", "region": "FR", "netbird_ip": "100.90.1.1"},
        format="json",
    )
    assert (r.status_code, r.json()["error"]) == (400, "netbird-peer-not-an-edge")


def test_create_edge_requires_the_edge_group_when_configured(
    root_client: APIClient, fake_netbird: FakeNetbird, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_PUBLIC_IP_EDGE_PEER_GROUP", "compute-edge")
    fake_netbird.add_peer("edge", "100.90.1.1")
    body = {"name": "edge-a", "region": "FR", "netbird_ip": "100.90.1.1"}
    r = root_client.post(reverse("network_edges"), body, format="json")
    assert (r.status_code, r.json()["error"]) == (400, "netbird-peer-not-an-edge")

    fake_netbird.peers[0]["groups"] = [{"id": "g1", "name": "compute-edge"}]
    assert root_client.post(reverse("network_edges"), body, format="json").status_code == 201


def test_patch_netbird_ip_rebinds_the_edge_peer(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    make_edge()
    new_peer = fake_netbird.add_peer("edge-reenrolled", "100.90.7.7")

    r = root_client.patch(_edge_url("edge-a"), {"netbird_ip": "100.90.7.7"}, format="json")

    assert r.status_code == 200, r.content
    assert r.json()["netbird_ip"] == "100.90.7.7"
    assert r.json()["netbird_peer_id"] == new_peer
    r = root_client.patch(_edge_url("edge-a"), {"netbird_ip": "100.90.9.9"}, format="json")
    assert (r.status_code, r.json()["error"]) == (400, "netbird-peer-not-found")


def test_create_edge_when_netbird_is_down(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    fake_netbird.failing = [".*"]
    r = root_client.post(
        reverse("network_edges"),
        {"name": "edge-a", "region": "FR", "netbird_ip": "100.90.1.1"},
        format="json",
    )
    assert (r.status_code, r.json()["error"]) == (503, "netbird-unavailable")


def test_patch_edge(root_client: APIClient) -> None:
    edge = make_edge()
    rev = edge.desired_revision

    r = root_client.patch(
        _edge_url("edge-a"), {"status": "draining", "per_ip_mbps": 200}, format="json"
    )

    assert r.status_code == 200, r.content
    assert r.json()["status"] == "draining"
    assert r.json()["per_ip_mbps"] == 200
    assert r.json()["desired_revision"] == rev + 1  # the rate cap is rendered
    bad = root_client.patch(_edge_url("edge-a"), {"region": "DE"}, format="json")
    assert (bad.status_code, bad.json()["error"]) == (400, "bad-request")
    bad = root_client.patch(_edge_url("edge-a"), {"status": "gone"}, format="json")
    assert (bad.status_code, bad.json()["error"]) == (400, "bad-request")
    assert root_client.patch(_edge_url("nope"), {}, format="json").status_code == 404


def test_delete_edge_refused_while_an_address_is_attached_or_quarantined(
    root_client: APIClient, fake_netbird: FakeNetbird
) -> None:
    edge = make_edge()
    edge_peer = fake_netbird.add_peer("edge", edge.netbird_ip)
    effects.ensure_edge_routing(edge.name, edge_peer)
    vm = make_vm()
    service.attach(vm)

    r = root_client.delete(_edge_url("edge-a"))
    assert (r.status_code, r.json()["error"]) == (409, "edge-has-attached-ips")

    service.detach(vm)
    r = root_client.delete(_edge_url("edge-a"))
    assert (r.status_code, r.json()["error"]) == (409, "edge-has-quarantined-ips")

    service.reconcile(now=timezone.now() + timedelta(days=2))
    fake_netbird.failing = [r"/api/policies"]
    r = root_client.delete(_edge_url("edge-a"))
    assert (r.status_code, r.json()["error"]) == (503, "netbird-unavailable")
    assert IngressEdge.objects.filter(name="edge-a").exists()  # retryable

    fake_netbird.failing = []
    assert root_client.delete(_edge_url("edge-a")).status_code == 204
    assert not IngressEdge.objects.exists()
    assert not PublicIP.objects.exists()
    assert fake_netbird.routes == {} and fake_netbird.policies == {}
    assert fake_netbird.groups == {}


def test_add_and_remove_addresses(root_client: APIClient) -> None:
    make_edge(addresses=("203.0.113.10",))
    make_edge("edge-other", addresses=("198.51.100.1",))
    url = _edge_url("edge-a", "_addresses")

    r = root_client.post(url, {"addresses": ["203.0.113.10", "203.0.113.11"]}, format="json")
    assert r.status_code == 200
    assert r.json()["counts"]["free"] == 2

    r = root_client.post(url, {"addresses": ["198.51.100.1"]}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "address-taken")

    service.attach(make_vm())  # takes 203.0.113.10
    r = root_client.delete(url, {"addresses": ["203.0.113.10", "203.0.113.11"]}, format="json")
    assert (r.status_code, r.json()["error"]) == (409, "address-not-free")
    assert PublicIP.objects.filter(edge__name="edge-a").count() == 2  # all or nothing

    r = root_client.delete(url, {"addresses": ["203.0.113.11"]}, format="json")
    assert r.status_code == 200
    assert [a["address"] for a in r.json()["addresses"]] == ["203.0.113.10"]

    r = root_client.delete(url, {"addresses": ["203.0.113.99"]}, format="json")
    assert (r.status_code, r.json()["error"]) == (404, "address-not-found")


def test_desired_and_applied(root_client: APIClient) -> None:
    edge = make_edge()
    vm = make_vm()
    ip, _ = service.attach(vm)
    PublicIP.objects.filter(pk=ip.pk).update(target_ip="100.70.0.5")

    desired = root_client.get(_edge_url("edge-a", "_desired")).json()
    assert desired == {
        "edge": "edge-a",
        "revision": desired["revision"],
        "per_ip_mbps": 1000,
        "addresses": [{"address": "203.0.113.10", "vm_id": "vm-1", "target_ip": "100.70.0.5"}],
    }

    report = {"addresses": {"203.0.113.10": {"bytes_in": 1, "bytes_out": 2}}, "errors": []}
    r = root_client.post(
        _edge_url("edge-a", "_applied"),
        {"revision": desired["revision"], "report": report},
        format="json",
    )
    assert r.status_code == 204
    edge.refresh_from_db()
    assert edge.applied_revision == desired["revision"]
    assert edge.last_report == report
    assert edge.last_seen_at is not None

    stale = root_client.post(
        _edge_url("edge-a", "_applied"), {"revision": 0, "report": {}}, format="json"
    )
    assert stale.status_code == 204
    edge.refresh_from_db()
    assert edge.applied_revision == desired["revision"]  # never moves backwards
    assert edge.last_report == report

    ahead = root_client.post(
        _edge_url("edge-a", "_applied"), {"revision": desired["revision"] + 5}, format="json"
    )
    assert (ahead.status_code, ahead.json()["error"]) == (409, "revision-ahead")
    for bad in ({"revision": "1"}, {"revision": -1}, {"revision": True}, {"revision": 1,
                                                                          "report": []}):
        r = root_client.post(_edge_url("edge-a", "_applied"), bad, format="json")
        assert (r.status_code, r.json()["error"]) == (400, "bad-request"), bad


def test_edge_view_shows_the_holder(root_client: APIClient) -> None:
    make_edge()
    service.attach(make_vm())
    body = root_client.get(_edge_url("edge-a")).json()
    assert body["counts"] == {"free": 0, "attached": 1, "quarantined": 0}
    [addr] = body["addresses"]
    assert addr["state"] == PublicIpState.ATTACHED
    assert addr["vm_id"] == "vm-1"
    assert addr["target_ip"] is None


def test_edge_view_shows_the_releasing_tenant(root_client: APIClient) -> None:
    make_edge()
    vm = make_vm(tenant_id="tenant-a")
    service.attach(vm)
    service.detach(vm)
    [addr] = root_client.get(_edge_url("edge-a")).json()["addresses"]
    assert addr["state"] == PublicIpState.QUARANTINED
    assert addr["last_tenant_id"] == "tenant-a"
