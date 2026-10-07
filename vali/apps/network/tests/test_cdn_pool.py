"""The CDN address pool (docs/design/cdn.md §6.1): CDN addresses go to CDN
nodes only and tenants' to tenants only, a CDN address serves its full
quarantine, and its feed entry carries its own cap — only once the tick
applied `VALI_CDN_ENABLED` to the edge."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.lifecycle.models import Vm
from apps.network import egress, service
from apps.network.models import (
    EgressMode,
    EgressRegion,
    IngressEdge,
    PublicIP,
    PublicIpPool,
    PublicIpState,
)
from apps.network.service import NetworkError

from .conftest import make_edge, make_vm
from .test_net_policy import _flavor, _miner
from .test_service import _located_host

pytestmark = pytest.mark.django_db

CDN_TENANT = "hippius-cdn"
GENERAL_IP = "203.0.113.10"
CDN_IP = "203.0.113.50"


@pytest.fixture(autouse=True)
def _cdn_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN_TENANT)


def _cdn_ips(edge: IngressEdge, *addresses: str, cap: int = 2000) -> None:
    service.add_addresses(edge, list(addresses), PublicIpPool.CDN, cap)


_HOST_SEEDS = iter(range(100, 1000))


def _node(vm_id: str = "cdn-1", country: str = "FR", **kw: Any) -> Vm:
    """A CDN node on its own host, verified in `country` ("" = no
    location)."""
    host = f"miner-{vm_id}"
    if country:
        _located_host(host, country, seed=next(_HOST_SEEDS))
    return make_vm(vm_id, tenant_id=CDN_TENANT, host=host, **kw)


def _tenant_vm(vm_id: str = "vm-1", **kw: Any) -> Vm:
    return make_vm(vm_id, tenant_id="tenant-a", **kw)


def _target(ip: PublicIP, target: str) -> None:
    PublicIP.objects.filter(pk=ip.pk).update(target_ip=target)


def _edge_url(name: str, suffix: str = "") -> str:
    return reverse(f"network_edge{suffix}", kwargs={"name": name})


# ── pool isolation ────────────────────────────────────────────────────


def test_a_tenant_never_gets_a_cdn_address() -> None:
    edge = make_edge(addresses=())
    _cdn_ips(edge, CDN_IP)

    with pytest.raises(NetworkError) as exc:
        service.attach(_tenant_vm())
    assert exc.value.code == "no-free-public-ip"
    assert PublicIP.objects.get(address=CDN_IP).state == PublicIpState.FREE


def test_a_tenant_takes_the_general_address_beside_cdn_ones() -> None:
    # More free CDN addresses on the edge than general ones: the ranking
    # counts the asked pool only, and the pick never strays into the other.
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP, "203.0.113.51", "203.0.113.52")

    ip, created = service.attach(_tenant_vm())

    assert created and ip.address == GENERAL_IP and ip.pool == PublicIpPool.GENERAL


def test_a_tenant_cannot_ask_for_a_cdn_address() -> None:
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)

    with pytest.raises(NetworkError) as exc:
        service.attach(_tenant_vm(), address=CDN_IP)
    assert exc.value.code == "address-unavailable"


def test_a_tenant_cannot_ask_for_a_quarantined_cdn_address() -> None:
    # The requested-address path accepts the caller's own quarantined
    # address; a CDN one is never in reach of it.
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)
    node = _node()
    service.attach_cdn(node)
    service.detach(node)
    vm = _tenant_vm()

    with pytest.raises(NetworkError) as exc:
        service.attach(vm, address=CDN_IP)
    assert exc.value.code == "address-unavailable"


def test_a_cdn_node_takes_only_a_cdn_address() -> None:
    edge = make_edge(addresses=(GENERAL_IP, "203.0.113.11", "203.0.113.12"))
    _cdn_ips(edge, CDN_IP)

    ip, created = service.attach_cdn(_node())

    assert created and ip.address == CDN_IP and ip.pool == PublicIpPool.CDN


def test_a_cdn_node_goes_to_the_edge_with_the_most_free_cdn_addresses() -> None:
    # edge-fr has more free addresses overall, edge-fr-b more CDN ones.
    busy = make_edge("edge-fr", "FR", (GENERAL_IP, "203.0.113.11", "203.0.113.12"))
    _cdn_ips(busy, CDN_IP)
    roomy = make_edge("edge-fr-b", "FR", ())
    _cdn_ips(roomy, "203.0.113.60", "203.0.113.61")

    ip, _ = service.attach_cdn(_node())

    assert ip.edge.name == "edge-fr-b"


def test_a_released_cdn_address_never_comes_back_through_the_general_attach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The CDN tenant setting moves after a node released its address: the
    # old tenant's VMs are no longer CDN nodes and take the general attach,
    # where the same-tenant reuse of a quarantined address must not reach
    # the CDN pool — picked or asked for.
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)
    node = _node()
    service.attach_cdn(node)
    service.detach(node)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "hippius-cdn-2")

    ip, _ = service.attach(make_vm("vm-old-cdn", tenant_id=CDN_TENANT))
    assert ip.address == GENERAL_IP
    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-old-cdn-2", tenant_id=CDN_TENANT), address=CDN_IP)
    assert exc.value.code == "address-unavailable"


def test_a_cdn_node_never_falls_back_on_a_general_address() -> None:
    make_edge(addresses=(GENERAL_IP,))

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node())
    assert exc.value.code == "cdn-no-local-edge"
    assert PublicIP.objects.get(address=GENERAL_IP).state == PublicIpState.FREE


def test_a_cdn_node_is_refused_the_general_attach(root_client: APIClient) -> None:
    make_edge(addresses=(GENERAL_IP,))
    node = _node()

    with pytest.raises(NetworkError) as exc:
        service.attach(node)
    assert exc.value.code == "cdn-vm-uses-cdn-pool"

    r = root_client.post(reverse("vm_public_ip", kwargs={"vm_id": node.vm_id}), {}, format="json")
    assert r.status_code == 409 and r.json()["error"] == "cdn-vm-uses-cdn-pool"
    assert not PublicIP.objects.filter(state=PublicIpState.ATTACHED).exists()


def test_attach_cdn_refuses_a_tenant_vm() -> None:
    edge = make_edge(addresses=())
    _cdn_ips(edge, CDN_IP)

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_tenant_vm())
    assert exc.value.code == "not-a-cdn-vm"


def test_attach_cdn_refuses_while_the_flag_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = make_edge(addresses=())
    _cdn_ips(edge, CDN_IP)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node())
    assert exc.value.code == "cdn-disabled"


def test_attach_cdn_is_idempotent() -> None:
    edge = make_edge(addresses=())
    _cdn_ips(edge, CDN_IP, "203.0.113.51")
    node = _node()

    first, created = service.attach_cdn(node)
    again, created_again = service.attach_cdn(node)

    assert created and not created_again and again.pk == first.pk


def test_a_blank_cdn_tenant_setting_makes_no_vm_a_cdn_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "")
    make_edge(addresses=(GENERAL_IP,))
    vm = make_vm("vm-blank", tenant_id="")

    assert not service.is_cdn_vm(vm)
    ip, _ = service.attach(vm)
    assert ip.address == GENERAL_IP
    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(make_vm("vm-blank-2", tenant_id=""))
    assert exc.value.code == "not-a-cdn-vm"


# ── zones ─────────────────────────────────────────────────────────────


def test_a_cdn_node_never_sits_behind_a_remote_edge() -> None:
    # v1: no zone fallback for CDN — an NL node is not served by FR's edge.
    fr = make_edge("edge-fr", "FR", ())
    _cdn_ips(fr, CDN_IP)

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node("cdn-nl", country="NL", region="NL"))
    assert exc.value.code == "cdn-no-local-edge"
    assert PublicIP.objects.get(address=CDN_IP).state == PublicIpState.FREE


def test_a_cdn_node_takes_its_host_regions_edge() -> None:
    de = make_edge("edge-de", "DE", ())
    _cdn_ips(de, "203.0.113.60", "203.0.113.61")
    fr = make_edge("edge-fr", "FR", ())
    _cdn_ips(fr, CDN_IP)

    ip, _ = service.attach_cdn(_node(country="FR"))

    assert ip.edge.name == "edge-fr"


def test_the_host_decides_not_the_launch_region() -> None:
    # Launch asked for DE, the host is verified in FR: FR's edge, never DE's.
    de = make_edge("edge-de", "DE", ())
    _cdn_ips(de, "203.0.113.60")

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node(country="FR", region="DE"))
    assert exc.value.code == "cdn-no-local-edge"


@pytest.mark.parametrize("how", ["fenced", "job-in-flight"])
def test_a_node_being_moved_gets_no_address(how: str) -> None:
    from apps.lifecycle.models import VmState
    from apps.orchestration.tests.factories import make_migration_job

    fr = make_edge("edge-fr", "FR", ())
    _cdn_ips(fr, CDN_IP)
    node = _node(country="FR")
    if how == "fenced":
        Vm.objects.filter(pk=node.pk).update(
            state=VmState.MIGRATING, migration_dest="miner-elsewhere", new_generation=2
        )
    else:
        make_migration_job(node, dest_node_id="miner-elsewhere")

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(node)
    assert exc.value.code == "cdn-vm-moving"


def test_an_unknown_host_country_is_refused() -> None:
    fr = make_edge("edge-fr", "FR", ())
    _cdn_ips(fr, CDN_IP)

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node(country="", region="FR"))
    assert exc.value.code == "cdn-no-local-edge"


def test_an_unverified_host_country_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.miners.models import LocationVerdict, MinerLocation

    monkeypatch.setattr(settings, "VALI_GEO_REQUIRE_VERIFIED", False)
    fr = make_edge("edge-fr", "FR", ())
    _cdn_ips(fr, CDN_IP)
    node = _node(country="FR")
    MinerLocation.objects.filter(miner__miner_id=node.host).update(
        verdict=LocationVerdict.UNVERIFIED
    )

    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(node)
    assert exc.value.code == "cdn-no-local-edge"


# ── quarantine ────────────────────────────────────────────────────────


def test_a_cdn_address_serves_its_full_quarantine() -> None:
    edge = make_edge(addresses=())
    _cdn_ips(edge, CDN_IP)
    first = _node("cdn-1")
    service.attach_cdn(first)
    service.detach(first)

    # Same tenant, yet no early reuse — unlike a tenant's own address.
    with pytest.raises(NetworkError) as exc:
        service.attach_cdn(_node("cdn-2"))
    assert exc.value.code == "cdn-no-local-edge"

    service.reconcile(now=timezone.now() + timedelta(seconds=service._quarantine_s() + 1))
    ip, _ = service.attach_cdn(_node("cdn-3"))
    assert ip.address == CDN_IP


def test_a_tenant_still_takes_its_own_quarantined_general_address_back() -> None:
    edge = make_edge(addresses=(GENERAL_IP, "203.0.113.11"))
    _cdn_ips(edge, CDN_IP)
    first = _tenant_vm("vm-1")
    held, _ = service.attach(first)
    service.detach(first)

    again, _ = service.attach(_tenant_vm("vm-2"))

    assert again.pk == held.pk


# ── feed ──────────────────────────────────────────────────────────────


def _tick(monkeypatch: pytest.MonkeyPatch, enabled: bool) -> None:
    """The orchestration tick runs with `VALI_CDN_ENABLED=enabled`."""
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", enabled)
    service._sync_cdn_flag()


def _world() -> tuple[IngressEdge, PublicIP, PublicIP]:
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP, cap=2000)
    tenant_ip, _ = service.attach(_tenant_vm())
    cdn_ip, _ = service.attach_cdn(_node())
    _target(tenant_ip, "100.70.0.5")
    _target(cdn_ip, "100.70.0.9")
    service._sync_cdn_flag()
    edge.refresh_from_db()
    return edge, tenant_ip, cdn_ip


def _today(edge: IngressEdge) -> dict[str, Any]:
    """The feed as the pre-CDN code renders it."""
    edge.refresh_from_db()
    return {
        "edge": edge.name,
        "revision": edge.desired_revision,
        "per_ip_mbps": edge.per_ip_mbps,
        "addresses": [
            {"address": a, "vm_id": v, "target_ip": t}
            for a, v, t in PublicIP.objects.filter(
                edge=edge, state=PublicIpState.ATTACHED, target_ip__isnull=False
            )
            .order_by("address")
            .values_list("address", "vm__vm_id", "target_ip")
        ],
    }


def test_the_feed_is_byte_identical_with_the_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    edge, _, _ = _world()
    _tick(monkeypatch, False)

    assert json.dumps(service.desired_state(edge)) == json.dumps(_today(edge))


def test_a_new_edge_starts_byte_identical() -> None:
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)
    ip, _ = service.attach_cdn(_node())
    _target(ip, "100.70.0.9")

    # Not applied by a tick yet: nothing new is served.
    assert json.dumps(service.desired_state(edge)) == json.dumps(_today(edge))


def test_cdn_entries_carry_their_pool_and_own_cap() -> None:
    edge, _, _ = _world()

    feed = service.desired_state(edge)

    assert feed["per_ip_mbps"] == 1000
    assert feed["addresses"] == [
        {"address": GENERAL_IP, "vm_id": "vm-1", "target_ip": "100.70.0.5"},
        {
            "address": CDN_IP,
            "vm_id": "cdn-1",
            "target_ip": "100.70.0.9",
            "pool": "cdn",
            "cap_mbps": 2000,
        },
    ]
    # The tenant entry is byte-identical to today's.
    assert json.dumps(feed["addresses"][0]) == json.dumps(_today(edge)["addresses"][0])


def test_the_feed_follows_the_tick_not_the_serving_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The API pods serving the feed and the tick that bumps its revision
    # roll out apart: what is served must be what the bumped revision says.
    edge, _, _ = _world()
    served_on = service.desired_state(edge)

    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)  # an API pod, tick not run
    assert service.desired_state(edge) == served_on

    service._sync_cdn_flag()  # the tick
    off = service.desired_state(edge)
    assert off["revision"] == served_on["revision"] + 1
    assert json.dumps(off) == json.dumps(_today(edge))


def test_the_desired_view_serves_the_cdn_fields(root_client: APIClient) -> None:
    edge, _, _ = _world()

    body = root_client.get(_edge_url(edge.name, "_desired")).json()

    assert body == service.desired_state(edge)
    assert body["addresses"][1]["pool"] == "cdn"


def _egress_world() -> tuple[IngressEdge, PublicIP, PublicIP]:
    miner = _miner(1, "AU")
    edge = make_edge("edge-au", "AU", ("203.0.113.20",))
    IngressEdge.objects.filter(pk=edge.pk).update(egress_ip="198.51.100.7")
    _cdn_ips(edge, CDN_IP, cap=3000)
    EgressRegion.objects.create(region="AU", mode=EgressMode.EDGE, routing_enabled=True)
    tenant = make_vm("vm-1", host=miner.miner_id, region="", tenant_id="tenant-a")
    node = make_vm("cdn-1", host=miner.miner_id, region="", tenant_id=CDN_TENANT)
    for vm in (tenant, node):
        _flavor(vm.vm_id, "medium")
    tenant_ip, _ = service.attach(tenant, region_hint="AU")
    cdn_ip, _ = service.attach_cdn(node)
    _target(tenant_ip, "100.70.0.5")
    _target(cdn_ip, "100.70.0.9")
    edge.refresh_from_db()
    return edge, tenant_ip, cdn_ip


def test_the_egress_feed_gives_a_cdn_address_its_own_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", True)
    edge, _, _ = _egress_world()
    _tick(monkeypatch, False)
    off = service.desired_state(edge)
    _tick(monkeypatch, True)

    on = service.desired_state(edge)

    tenant_off, cdn_off = off["addresses"]
    tenant_on, cdn_on = on["addresses"]
    assert "egress" in on
    assert json.dumps(tenant_on) == json.dumps(tenant_off)
    assert "pool" not in cdn_off and cdn_off["cap_mbps"] != 3000
    assert cdn_on == {**cdn_off, "pool": "cdn", "cap_mbps": 3000}


def test_a_cdn_flag_flip_re_renders_every_edge_once(monkeypatch: pytest.MonkeyPatch) -> None:
    edge, _, _ = _world()
    other = make_edge("edge-fr-b", "FR", ("203.0.113.30",))
    service._sync_cdn_flag()
    edge.refresh_from_db()
    other.refresh_from_db()
    rev, other_rev = edge.desired_revision, other.desired_revision
    assert edge.cdn_feed and other.cdn_feed

    assert service._sync_cdn_flag() == 0  # unchanged flag: nothing
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    assert service._sync_cdn_flag() == 2
    assert service._sync_cdn_flag() == 0

    edge.refresh_from_db()
    other.refresh_from_db()
    assert (edge.desired_revision, other.desired_revision) == (rev + 1, other_rev + 1)
    assert not edge.cdn_feed and not other.cdn_feed


def test_with_the_flag_off_the_tick_touches_no_edge(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)
    rev = edge.desired_revision

    service.reconcile()

    edge.refresh_from_db()
    assert edge.desired_revision == rev and not edge.cdn_feed


def test_the_egress_digest_follows_the_applied_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", True)
    edge, _, _ = _egress_world()
    _tick(monkeypatch, True)
    egress.sync_revisions()
    edge.refresh_from_db()
    before = egress._digest(edge)

    _tick(monkeypatch, False)
    edge.refresh_from_db()

    assert egress._digest(edge) != before


# ── availability and the operator surface ─────────────────────────────


def test_availability_never_counts_cdn_addresses(root_client: APIClient) -> None:
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP, "203.0.113.51")
    cdn_only = make_edge("edge-de", "DE", ())
    _cdn_ips(cdn_only, "203.0.113.60")

    assert service.availability() == {
        "total_free": 1,
        "regions": [{"region": "FR", "free": 1, "total": 1, "edges": 1}],
    }
    assert service.availability("DE")["total_free"] == 1  # FR is in DE's zone
    assert service.availability("DE")["regions"] == []
    r = root_client.get(reverse("network_availability"))
    assert r.json()["total_free"] == 1


def test_add_cdn_addresses_via_the_api(root_client: APIClient) -> None:
    edge = make_edge(addresses=(GENERAL_IP,))
    url = _edge_url(edge.name, "_addresses")

    r = root_client.post(
        url, {"addresses": [CDN_IP], "pool": "cdn", "cap_mbps": 2000}, format="json"
    )

    assert r.status_code == 200, r.content
    body = r.json()
    rows = {a["address"]: a for a in body["addresses"]}
    assert rows[CDN_IP]["pool"] == "cdn" and rows[CDN_IP]["cap_mbps"] == 2000
    assert rows[GENERAL_IP]["pool"] == "general" and rows[GENERAL_IP]["cap_mbps"] is None
    assert body["counts"] == {"free": 2, "attached": 0, "quarantined": 0}
    assert body["counts_by_pool"] == {
        "general": {"free": 1, "attached": 0, "quarantined": 0},
        "cdn": {"free": 1, "attached": 0, "quarantined": 0},
    }


@pytest.mark.parametrize(
    "body, code",
    [
        ({"addresses": [CDN_IP], "pool": "cdn"}, "bad-request"),
        ({"addresses": [CDN_IP], "cap_mbps": 2000}, "bad-request"),
        ({"addresses": [CDN_IP], "pool": "special", "cap_mbps": 2000}, "bad-request"),
        ({"addresses": [CDN_IP], "pool": ["cdn"], "cap_mbps": 2000}, "bad-request"),
        ({"addresses": [CDN_IP], "pool": "cdn", "cap_mbps": 0}, "bad-request"),
        ({"addresses": [CDN_IP], "pool": "cdn", "cap_mbps": True}, "bad-request"),
    ],
)
def test_add_addresses_validation(root_client: APIClient, body: dict[str, Any], code: str) -> None:
    edge = make_edge(addresses=())

    r = root_client.post(_edge_url(edge.name, "_addresses"), body, format="json")

    assert r.status_code == 400 and r.json()["error"] == code
    assert not PublicIP.objects.exists()


def test_an_address_never_changes_pool_in_place(root_client: APIClient) -> None:
    edge = make_edge(addresses=(GENERAL_IP,))
    _cdn_ips(edge, CDN_IP)
    url = _edge_url(edge.name, "_addresses")

    to_cdn = root_client.post(
        url, {"addresses": [GENERAL_IP], "pool": "cdn", "cap_mbps": 2000}, format="json"
    )
    to_general = root_client.post(url, {"addresses": [CDN_IP]}, format="json")

    assert to_cdn.status_code == 409 and to_cdn.json()["error"] == "address-pool-mismatch"
    assert to_general.status_code == 409 and to_general.json()["error"] == "address-pool-mismatch"
    assert PublicIP.objects.get(address=GENERAL_IP).pool == PublicIpPool.GENERAL
    assert PublicIP.objects.get(address=CDN_IP).pool == PublicIpPool.CDN


def test_re_adding_a_cdn_address_updates_its_cap_and_re_renders(root_client: APIClient) -> None:
    edge, _, cdn_ip = _world()
    rev = edge.desired_revision
    url = _edge_url(edge.name, "_addresses")

    same = root_client.post(
        url, {"addresses": [CDN_IP], "pool": "cdn", "cap_mbps": 2000}, format="json"
    )
    edge.refresh_from_db()
    assert same.status_code == 200 and edge.desired_revision == rev

    r = root_client.post(
        url, {"addresses": [CDN_IP], "pool": "cdn", "cap_mbps": 4000}, format="json"
    )

    assert r.status_code == 200
    edge.refresh_from_db()
    assert edge.desired_revision == rev + 1
    assert service.desired_state(edge)["addresses"][1]["cap_mbps"] == 4000


def test_the_database_keeps_caps_on_cdn_addresses_only() -> None:
    edge = make_edge(addresses=())
    with pytest.raises(IntegrityError), transaction.atomic():
        PublicIP.objects.create(edge=edge, address=CDN_IP, pool=PublicIpPool.CDN)
    with pytest.raises(IntegrityError), transaction.atomic():
        PublicIP.objects.create(edge=edge, address=GENERAL_IP, cap_mbps=500)
