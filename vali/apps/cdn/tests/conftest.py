"""Fixtures for the CDN suite.

`fake_transit` stands in for Vault at the `vault_kv` function level: an
Ed25519 Transit key held in memory (test only — in production the key never
leaves Vault) and the per-VM lifecycle seeds at KV version 1.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import vault_kv

from ..models import CdnNode, CdnNodeState

ROOT = "orchestration-root"
CDN_TENANT = "hippius-cdn"
PREFIX = "hippius-compute/kbs/tenants"


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class FakeTransit:
    name: str = "cdn-ca"
    versions: list[Ed25519PrivateKey] = field(
        default_factory=lambda: [Ed25519PrivateKey.generate()]
    )
    exportable: bool = False
    allow_plaintext_backup: bool = False
    key_type: str = "ed25519"
    #: Sign with this key instead of the asked version's (a lying Transit).
    rogue: Ed25519PrivateKey | None = None
    #: KV v2 secrets at version 1, by path.
    kv: dict[str, bytes] = field(default_factory=dict)
    signed: list[tuple[str, int, bytes]] = field(default_factory=list)

    def rotate(self) -> None:
        self.versions.append(Ed25519PrivateKey.generate())

    def read_key(self, name: str) -> dict[str, Any]:
        if name != self.name:
            raise vault_kv.VaultNotFound("no such key")
        return {
            "type": self.key_type,
            "exportable": self.exportable,
            "allow_plaintext_backup": self.allow_plaintext_backup,
            "latest_version": len(self.versions),
            "keys": {
                str(i + 1): {
                    "public_key": base64.b64encode(raw_public(k)).decode(),
                    "name": "ed25519",
                }
                for i, k in enumerate(self.versions)
            },
        }

    def sign(self, name: str, message: bytes, *, key_version: int) -> bytes:
        assert name == self.name
        self.signed.append((name, key_version, message))
        key = self.rogue or self.versions[key_version - 1]
        return key.sign(message)

    def get_kv(self, mount: str, path: str, *, version: int | None = None) -> bytes:
        assert version == 1, "the lifecycle seed is read at version 1 only"
        if path not in self.kv:
            raise vault_kv.VaultNotFound("not-found")
        return self.kv[path]


@pytest.fixture
def fake_transit(monkeypatch: pytest.MonkeyPatch) -> FakeTransit:
    t = FakeTransit()
    monkeypatch.setattr(vault_kv, "transit_read_key", t.read_key)
    monkeypatch.setattr(vault_kv, "transit_sign", t.sign)
    monkeypatch.setattr(vault_kv, "get_kv", t.get_kv)
    return t


@pytest.fixture(autouse=True)
def _cdn_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN_TENANT)
    monkeypatch.setattr(settings, "VALI_CDN_CA_TRANSIT_KEY", "cdn-ca")
    monkeypatch.setattr(settings, "VALI_VAULT_KV_PREFIX", PREFIX)


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
    return _bearer("upstream-api", PrincipalScope.OPERATOR.value)


def make_node(
    transit: FakeTransit,
    vm_id: str = "cdn-fr-7k2m",
    *,
    region: str = "FR",
    state: str = CdnNodeState.BOOTING,
    tenant_id: str = CDN_TENANT,
    generation: int = 3,
    seed: bytes | None = None,
) -> CdnNode:
    """A CDN node on an active VM whose lifecycle seed is staged."""
    seed = seed if seed is not None else Ed25519PrivateKey.generate().private_bytes_raw()
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"cdn-{vm_id}",
        tenant_id=tenant_id,
        state=VmState.ACTIVE,
        generation=generation,
        host="miner-a",
        lifecycle_vk=raw_public(Ed25519PrivateKey.from_private_bytes(seed)),
    )
    transit.kv[f"{PREFIX}/{vm_id}/lifecycle-key"] = seed
    return CdnNode.objects.create(vm=vm, node_id=vm_id, region=region, state=state)
