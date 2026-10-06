"""Fixtures for the public-IP suite.

`fake_netbird` stands in for the NetBird management API at the
`urllib.request.urlopen` level, so the real `effects` code — request
shapes, id handling, idempotency — runs against it. It keeps peers,
groups, routes and policies in memory and records every write.
"""

from __future__ import annotations

import json
import re
import secrets
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import pytest
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.lifecycle.models import Vm, VmState
from apps.network.models import IngressEdge, PublicIP
from apps.orchestration.models import LaunchJob
from apps.orchestration.tests.factories import make_service_client

ROOT = "orchestration-root"


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._body = b"" if body is None else json.dumps(body).encode()

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


@dataclass
class FakeNetbird:
    peers: list[dict[str, Any]] = field(default_factory=list)
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    routes: dict[str, dict[str, Any]] = field(default_factory=dict)
    policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: The audit log (`GET /api/events/audit`), newest first.
    events: list[dict[str, Any]] = field(default_factory=list)
    writes: list[tuple[str, str, Any]] = field(default_factory=list)
    #: Every request, reads included.
    calls: list[tuple[str, str]] = field(default_factory=list)
    #: Paths (regex) that answer 500.
    failing: list[str] = field(default_factory=list)
    _seq: int = 0

    def _id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{self._seq:04d}"

    def add_peer(self, name: str, ip: str, *, connected: bool = True) -> str:
        pid = self._id("peer")
        self.peers.append({"id": pid, "name": name, "ip": ip, "connected": connected})
        return pid

    def vm_peer(self, vm_id: str, ip: str) -> str:
        return self.add_peer(f"hippius-tenant-{vm_id}", ip)

    def group_named(self, name: str) -> dict[str, Any] | None:
        return next((g for g in self.groups.values() if g["name"] == name), None)

    def member_ids(self, name: str) -> set[str]:
        g = self.group_named(name)
        return {p["id"] for p in g["peers"]} if g else set()

    def _group_out(self, g: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": g["id"],
            "name": g["name"],
            "peers": [{"id": p["id"], "name": p.get("name", "")} for p in g["peers"]],
            "peers_count": len(g["peers"]),
        }

    def _set_group(self, gid: str, body: dict[str, Any]) -> dict[str, Any]:
        g = {"id": gid, "name": body["name"], "peers": [{"id": p} for p in body.get("peers", [])]}
        self.groups[gid] = g
        return self._group_out(g)

    def handle(self, method: str, path: str, body: Any) -> tuple[int, Any]:
        self.calls.append((method, path))
        if any(re.search(f, path) for f in self.failing):
            return 500, {"message": "boom"}
        if method != "GET":
            self.writes.append((method, path, body))
        parts = path.strip("/").split("/")[1:]  # drop "api"
        kind, oid = parts[0], (parts[1] if len(parts) > 1 else None)
        if kind == "events" and method == "GET":
            return 200, self.events
        if kind == "peers":
            if method == "GET":
                return 200, self.peers
            if method == "DELETE":
                before = len(self.peers)
                self.peers = [p for p in self.peers if p["id"] != oid]
                return (200, None) if len(self.peers) < before else (404, None)
        if kind == "groups":
            if method == "GET" and oid is None:
                return 200, [self._group_out(g) for g in self.groups.values()]
            if method == "GET":
                if oid not in self.groups:
                    return 404, None
                return 200, self._group_out(self.groups[oid])
            if method == "POST":
                return 200, self._set_group(self._id("grp"), body)
            if method == "PUT":
                return 200, self._set_group(oid, body)
            if method == "DELETE":
                self.groups.pop(oid, None)
                return 200, None
        store = {"routes": self.routes, "policies": self.policies}.get(kind)
        if store is not None:
            if method == "GET":
                return 200, list(store.values())
            if method == "POST":
                obj = {**body, "id": self._id(kind[:3])}
                store[obj["id"]] = obj
                return 200, obj
            if method == "PUT":
                store[oid] = {**body, "id": oid}
                return 200, store[oid]
            if method == "DELETE":
                store.pop(oid, None)
                return 200, None
        return 404, None


@pytest.fixture
def fake_netbird(monkeypatch: pytest.MonkeyPatch) -> FakeNetbird:
    nb = FakeNetbird()
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_BASE", "https://nb.test")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "nbp_test")

    def _urlopen(request: urllib.request.Request, timeout: float, **_kw: object) -> _Resp:
        assert request.full_url.startswith("https://nb.test/api/")
        body = json.loads(request.data) if request.data else None
        path = request.full_url[len("https://nb.test") :]
        status, out = nb.handle(request.get_method(), path, body)
        if status >= 400:
            import io
            import urllib.error

            raise urllib.error.HTTPError(request.full_url, status, "err", {}, io.BytesIO(b"{}"))
        return _Resp(status, out)

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return nb


@pytest.fixture(autouse=True)
def _network_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    monkeypatch.setattr(settings, "VALI_PUBLIC_IP_QUARANTINE_S", 3600.0)
    cache.clear()


def _bearer(name: str, scope: str, tenant_id: str = "") -> APIClient:
    sc = ServiceClient.objects.create(scope=scope, name=name, tenant_id=tenant_id)
    _row, token = ServiceToken.issue(client=sc, name="ops", lifetime=TokenLifetime.OPS.value)
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return api


@pytest.fixture
def root_client() -> APIClient:
    return _bearer(ROOT, PrincipalScope.OPERATOR.value)


@pytest.fixture
def operator_client() -> APIClient:
    """Operator-scoped but not the root principal."""
    return _bearer("upstream-api", PrincipalScope.OPERATOR.value)


@pytest.fixture
def tenant_client() -> APIClient:
    return _bearer("portal-a", PrincipalScope.TENANT.value, tenant_id="tenant-a")


def launch_region(vm_id: str, region: str) -> None:
    """Record that `vm_id`'s launch asked for `region`."""
    LaunchJob.objects.create(
        job_id=secrets.token_hex(8),
        vm_id=vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={"vm_id": vm_id, "region": region},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state="succeeded",
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )


def make_vm(
    vm_id: str = "vm-1",
    *,
    host: str = "",
    state: str = VmState.ACTIVE,
    tenant_id: str = "",
    region: str = "FR",
) -> Vm:
    """A VM whose launch asked for `region` (none when blank): an attach
    routes within that region's zone only."""
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id=tenant_id,
        state=state,
        generation=1,
        host=host,
        lifecycle_vk=bytes(32),
    )
    if region:
        launch_region(vm_id, region)
    return vm


def make_edge(
    name: str = "edge-a",
    region: str = "FR",
    addresses: tuple[str, ...] = ("203.0.113.10",),
    *,
    netbird_ip: str = "",
    status: str = "active",
) -> IngressEdge:
    n = IngressEdge.objects.count() + 1
    edge = IngressEdge.objects.create(
        name=name,
        region=region,
        netbird_ip=netbird_ip or f"100.90.0.{n}",
        netbird_peer_id=f"edgepeer{n}",
        status=status,
    )
    PublicIP.objects.bulk_create([PublicIP(edge=edge, address=a) for a in addresses])
    return edge
