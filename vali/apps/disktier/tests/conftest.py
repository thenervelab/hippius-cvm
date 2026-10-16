"""Fixtures for the disk-tier suite. Node ids are synthetic
(`format(seed, "064x")`). The storage-config helpers stub the agent
(`FakeAgent`) and the on-chain family read (`chain`): no subprocess, no
network."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime

from .probe_helpers import probe_on  # noqa: F401 — the disk-probe fixture


def _bearer_client(name: str, scope: str, tenant_id: str = "") -> APIClient:
    client = ServiceClient.objects.create(scope=scope, name=name, tenant_id=tenant_id)
    _row, plaintext = ServiceToken.issue(
        client=client, name="ops", lifetime=TokenLifetime.OPS.value
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@pytest.fixture
def operator_client() -> APIClient:
    """The upstream product API's principal — operator-scoped."""
    return _bearer_client("upstream-api", PrincipalScope.OPERATOR.value)


@pytest.fixture
def tenant_client() -> APIClient:
    """A tenant-scoped principal — refused on an operator-only surface."""
    return _bearer_client("portal-a", PrincipalScope.TENANT.value, tenant_id="tenant-a")


# ─── storage-config helpers ──────────────────────────────────────────

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def ss58_encode(account: bytes, prefix: int = 42) -> str:
    """Test-side SS58 encoder (1-byte network prefix)."""
    body = bytes([prefix]) + account
    data = body + hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


#: Family accounts used across the storage tests.
FAMILY_A = bytes([0xA1] * 32)
FAMILY_B = bytes([0xB2] * 32)


def storage_digest(payload_json: bytes) -> str:
    """Stand-in for `storage-config-digest`: everything but the expiry."""
    body = json.loads(payload_json)
    body.pop("not_after_unix")
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


@dataclass
class FakeAgent:
    """The agent's `storage-config` route: refuses a lower revision and the
    same revision with other content (409 JSON), answers a dry run without
    storing, acks `applied:<rev>:<sha>`."""

    revision: int = 0
    sha: str = ""
    sent: list[dict[str, Any]] = field(default_factory=list)
    order_ids: list[str] = field(default_factory=list)
    #: Next answers instead of the real one, `(status, body)`.
    script: list[tuple[int, str]] = field(default_factory=list)
    unreachable: bool = False

    def __call__(self, **kw: Any) -> Any:
        from apps.orchestration import order_dispatch
        from apps.orchestration.order_dispatch import DispatchResult

        assert kw["kind"] == "storage-config"
        if self.unreachable:
            raise order_dispatch.OrderDispatchUnavailable("edge-order: peer unreachable")
        body = json.loads(kw["payload_json"])
        self.sent.append(body)
        self.order_ids.append(kw["order_id"])
        if self.script:
            status, text = self.script.pop(0)
            return DispatchResult(ok=200 <= status < 300, status=status, classifier=text)
        sha = storage_digest(kw["payload_json"])
        rev = body["revision"]
        if body["dry_run"]:
            return DispatchResult(ok=True, status=200, classifier=f"dry-run-ok:{rev}:{sha}")
        if rev < self.revision:
            return DispatchResult(
                ok=False, status=409, classifier='{"code":"storage-config-stale-revision"}'
            )
        if rev == self.revision and sha != self.sha:
            return DispatchResult(
                ok=False, status=409, classifier='{"code":"storage-config-revision-conflict"}'
            )
        self.revision, self.sha = rev, sha
        return DispatchResult(ok=True, status=200, classifier=f"applied:{rev}:{sha}")


@pytest.fixture
def agent(monkeypatch: pytest.MonkeyPatch) -> FakeAgent:
    from apps.orchestration import order_dispatch

    fake = FakeAgent()
    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", fake)
    monkeypatch.setattr(order_dispatch, "storage_config_digest", storage_digest)
    return fake


@pytest.fixture
def push_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_PUSH", True)
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_MIN_AGENT_VERSION", "v2026.10.01")


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    """`{node_id: NodeFamily | Exception}` the stubbed on-chain read answers
    (no subprocess, no network). Unknown nodes are unregistered."""
    from apps.disktier import node_family

    answers: dict[str, Any] = {}
    calls: list[str] = []

    def _read(node: str) -> node_family.NodeFamily:
        calls.append(node)
        answer = answers.get(node)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            return node_family.NodeFamily(
                node_id=node, block_hash="0x" + "00" * 32, bound=False, reason="no-child"
            )
        return answer

    monkeypatch.setattr(node_family, "read_node_family", _read)
    node_family.clear_cache()
    answers["__calls__"] = calls
    yield answers
    node_family.clear_cache()


def bind(chain: dict[str, Any], node: str, family: bytes, status: str = "active") -> None:
    from apps.disktier import node_family

    chain[node] = node_family.NodeFamily(
        node_id=node,
        block_hash="0x" + "11" * 32,
        bound=True,
        family_hex=family.hex(),
        status=status,
    )


@pytest.fixture
def writer_client(monkeypatch: pytest.MonkeyPatch) -> APIClient:
    """The backend's operator-config principal."""
    monkeypatch.setattr(settings, "VALI_OPERATOR_CONFIG_PRINCIPALS", ["backend-operator-config"])
    return _bearer_client("backend-operator-config", PrincipalScope.OPERATOR.value)
