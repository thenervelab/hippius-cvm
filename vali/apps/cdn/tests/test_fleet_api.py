"""`/v1/cdn/nodes`, `/dns-released`, `/drain`, `/v1/cdn/regions` (contract §B),
and the `vali_cdn_node` / `vali_cdn_region` commands."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from io import StringIO
from typing import Any

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command
from django.utils import timezone
from rest_framework.test import APIClient

from .. import fleet, reconcile
from ..models import CdnNode, CdnNodeState, CdnRegion, CdnRevision, DrainReason
from .test_reconcile import (  # noqa: F401 — fixtures
    Fleet,
    _fleet_settings,
    _ready_node,
    _region,
    _tick,
    fleet_fakes,
)

pytestmark = pytest.mark.django_db

_NODE_KEYS = {
    "node_id",
    "vm_id",
    "region",
    "generation",
    "state",
    "public_ip",
    "edge",
    "flavor",
    "host_ref",
    "image",
    "measurement_hex",
    "node_public_key_b64",
    "cert",
    "created_at",
    "ready_at",
    "drain",
}


def _ready(f: Fleet) -> CdnNode:
    _region(desired=1)
    return _ready_node(f)


# ── GET /v1/cdn/nodes ─────────────────────────────────────────────────


def test_nodes_shape(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    fleet.record(
        fleet.SignedFleetKey(
            version=2, x25519_public=b"\x03" * 32, kbs_kid_hex="ab", kbs_signature=b"\x02" * 64
        )
    )
    resp = root_client.get("/v1/cdn/nodes")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"revision", "ca", "fleet_keys", "nodes"}
    assert resp["ETag"] == f'"{body["revision"]}"' and body["revision"] == CdnRevision.current()
    assert body["ca"]["kid"] == "cdnca-1" and body["ca"]["next"] is None
    assert body["ca"]["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert [k["state"] for k in body["fleet_keys"]] == ["active", "pending"]
    key = body["fleet_keys"][1]
    assert set(key) == {
        "version",
        "x25519_public_b64",
        "state",
        "created_at",
        "kbs_kid_hex",
        "kbs_signature_b64",
    }
    assert key["version"] == 2 and key["state"] == "pending"
    [n] = body["nodes"]
    assert set(n) == _NODE_KEYS
    assert n["node_id"] == n["vm_id"] == node.node_id
    assert n["state"] == "ready" and n["region"] == "FR" and n["generation"] == 1
    assert n["public_ip"].startswith("203.0.113.") and n["edge"] == "edge-fr"
    assert n["flavor"] == "xlarge" and n["host_ref"].startswith("h-")
    assert "miner-a" not in str(n)
    assert n["image"]["name"] == "cdn-node" and n["image"]["bake_id"] == "gb-cdn-1"
    assert set(n["cert"]) == {"pem", "serial", "not_before", "not_after"}
    assert n["cert"]["not_after"].endswith("Z") and n["drain"] is None


def test_nodes_etag_and_304(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    _ready(fleet_fakes)
    first = root_client.get("/v1/cdn/nodes")
    same = root_client.get("/v1/cdn/nodes", HTTP_IF_NONE_MATCH=first["ETag"])
    assert same.status_code == 304 and same["ETag"] == first["ETag"]
    node = CdnNode.objects.get()
    reconcile.request_drain(node.node_id, DrainReason.OPERATOR)
    changed = root_client.get("/v1/cdn/nodes", HTTP_IF_NONE_MATCH=first["ETag"])
    assert changed.status_code == 200 and changed["ETag"] != first["ETag"]
    assert changed.json()["nodes"][0]["drain"]["reason"] == "operator"


def test_destroyed_nodes_drop_out(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.DESTROYED)
    assert root_client.get("/v1/cdn/nodes").json()["nodes"] == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/v1/cdn/nodes"),
        ("post", "/v1/cdn/nodes/cdn-fr-x/dns-released"),
        ("post", "/v1/cdn/nodes/cdn-fr-x/drain"),
        ("get", "/v1/cdn/regions"),
        ("patch", "/v1/cdn/regions/FR"),
    ],
)
def test_root_only_and_404_while_disabled(
    root_client: APIClient,
    operator_client: APIClient,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
) -> None:
    assert getattr(operator_client, method)(path, {}, format="json").status_code == 403
    assert getattr(APIClient(), method)(path, {}, format="json").status_code in (401, 403)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    resp = getattr(root_client, method)(path, {}, format="json")
    assert resp.status_code == 404 and resp.json()["code"] == "cdn-disabled"


# ── POST dns-released ─────────────────────────────────────────────────


def _ack(client: APIClient, node_id: str, **body: Any) -> Any:
    payload = {"revision_seen": 1, "change_id": "/change/C1", "insync_at": "2026-10-07T10:00:00Z"}
    payload.update(body)
    return client.post(f"/v1/cdn/nodes/{node_id}/dns-released", payload, format="json")


def test_dns_released_only_while_draining(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    resp = _ack(root_client, node.node_id)
    assert resp.status_code == 409 and resp.json()["code"] == "not-draining"
    node.refresh_from_db()
    assert node.dns_released_at is None

    CdnRegion.objects.update(desired_nodes=0)
    _tick()
    before = timezone.now()
    resp = _ack(root_client, node.node_id)
    assert resp.status_code == 200 and resp.json()["state"] == "draining"
    assert resp.json()["drain"]["dns_released_at"] is not None
    node.refresh_from_db()
    # The grace runs from vali's receipt, not from the body's insync_at.
    assert node.dns_released_at >= before and node.dns_release_change_id == "/change/C1"
    again = _ack(root_client, node.node_id, change_id="/change/C2")
    assert again.status_code == 200
    node.refresh_from_db()
    assert node.dns_release_change_id == "/change/C1", "idempotent"


def test_dns_released_for_a_failed_node(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.FAILED)
    assert _ack(root_client, node.node_id).status_code == 200


@pytest.mark.parametrize(
    "body",
    [{"change_id": 7}, {"revision_seen": "x"}, {"insync_at": "yesterday"}, {"insync_at": 5}],
)
def test_dns_released_validates(root_client: APIClient, fleet_fakes: Fleet, body: dict) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.DRAINING)
    assert _ack(root_client, node.node_id, **body).status_code == 400


def test_dns_released_unknown_node(root_client: APIClient) -> None:
    assert _ack(root_client, "cdn-fr-nope").status_code == 404


# ── POST drain ────────────────────────────────────────────────────────


def test_drain(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    resp = root_client.post(
        f"/v1/cdn/nodes/{node.node_id}/drain", {"reason": "operator"}, format="json"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "ready" and body["drain"]["reason"] == "operator"
    again = root_client.post(f"/v1/cdn/nodes/{node.node_id}/drain", {}, format="json")
    assert again.status_code == 200
    bad = root_client.post(
        f"/v1/cdn/nodes/{node.node_id}/drain", {"reason": "upgrade"}, format="json"
    )
    assert bad.status_code == 400
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.FAILED, drain_requested_at=None)
    late = root_client.post(f"/v1/cdn/nodes/{node.node_id}/drain", {}, format="json")
    assert late.status_code == 409 and late.json()["code"] == "not-drainable"
    assert root_client.post("/v1/cdn/nodes/cdn-fr-nope/drain", {}, format="json").status_code == 404


# ── regions ───────────────────────────────────────────────────────────


def test_regions(root_client: APIClient, fleet_fakes: Fleet) -> None:  # noqa: F811
    _ready(fleet_fakes)
    body = root_client.get("/v1/cdn/regions").json()
    [fr] = body["regions"]
    assert fr == {
        "region": "FR",
        "active": True,
        "desired_nodes": 1,
        "ready_nodes": 1,
        "flavor": "xlarge",
        "edges": ["edge-fr"],
        "cdn_ip_mbps": 2000,
        "pool": {"total": 1, "free": 0, "attached": 1, "quarantined": 0},
        "failover_region": None,
    }


def test_region_patch(root_client: APIClient) -> None:
    CdnRegion.objects.create(region="FR")
    before = CdnRevision.current()
    resp = root_client.patch(
        "/v1/cdn/regions/FR", {"desired_nodes": 2, "active": True}, format="json"
    )
    assert resp.status_code == 200 and resp.json()["desired_nodes"] == 2
    assert CdnRevision.current() > before
    for bad in ({"desired_nodes": -1}, {"active": "yes"}, {"flavor": "huge"}, {"edges": []}, {}):
        assert root_client.patch("/v1/cdn/regions/FR", bad, format="json").status_code == 400
    assert (
        root_client.patch("/v1/cdn/regions/AU", {"active": True}, format="json").status_code == 404
    )


# ── commands ──────────────────────────────────────────────────────────


def test_force_drained(fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    with pytest.raises(CommandError, match="drain it first"):
        call_command("vali_cdn_node", "force-drained", node.node_id, stdout=StringIO())
    CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.DRAINING)
    call_command("vali_cdn_node", "force-drained", node.node_id, stdout=StringIO())
    node.refresh_from_db()
    assert node.dns_released_at is not None and node.dns_release_forced
    out = StringIO()
    call_command("vali_cdn_node", "list", stdout=out)
    assert "dns_released=forced" in out.getvalue()


def test_drain_command(fleet_fakes: Fleet) -> None:  # noqa: F811
    node = _ready(fleet_fakes)
    call_command("vali_cdn_node", "drain", node.node_id, stdout=StringIO())
    node.refresh_from_db()
    assert node.drain_reason == DrainReason.OPERATOR


def test_region_command() -> None:
    call_command("vali_cdn_region", "create", "au", "--failover-region", "fr", stdout=StringIO())
    row = CdnRegion.objects.get(region="AU")
    assert not row.active and row.desired_nodes == 0 and row.failover_region == "FR"
    with pytest.raises(CommandError):
        call_command("vali_cdn_region", "create", "AUS", stdout=StringIO())


# ── fleet keys ────────────────────────────────────────────────────────


def _key(version: int) -> fleet.SignedFleetKey:
    return fleet.SignedFleetKey(
        version=version,
        x25519_public=bytes([version]) * 32,
        kbs_kid_hex="ab",
        kbs_signature=b"\x02" * 64,
    )


@pytest.fixture
def _no_fleet_keys() -> None:
    from ..models import CdnFleetKey

    CdnFleetKey.objects.all().delete()


def test_fleet_key_lifecycle(_no_fleet_keys: None) -> None:
    fleet.record(_key(1))
    fleet.set_state(1, "active")
    fleet.record(_key(2))
    assert [k["state"] for k in fleet.published()] == ["active", "pending"]
    fleet.set_state(2, "active")
    assert [k["state"] for k in fleet.published()] == ["retiring", "active"]
    fleet.set_state(1, "retired")
    assert [k["version"] for k in fleet.published()] == [2]
    with pytest.raises(fleet.FleetKeyError):
        fleet.set_state(2, "pending")
    with pytest.raises(fleet.FleetKeyError):
        fleet.record(_key(2))
    with pytest.raises(fleet.FleetKeyError):
        fleet.record(fleet.SignedFleetKey(3, b"\x00" * 31, "ab", b"\x00" * 64))


_VECTOR = (
    __import__("pathlib").Path(__file__).resolve().parents[4]
    / "test_vectors"
    / "cdn_fleet"
    / "public_key_signature.json"
)


def _vector_answer() -> tuple[dict[str, Any], dict[str, Any]]:
    import json

    v = json.loads(_VECTOR.read_text())
    answer = {
        "v": 1,
        "version": v["version"],
        "x25519_public_b64": v["x25519_public_b64"],
        "kbs_kid_hex": "6b6273",
        "kbs_signature_b64": v["signature_b64"],
        "kbs_public_key_hex": v["kbs_public_key_hex"],
    }
    return v, answer


def test_the_kbs_signature_is_checked_like_the_kbs_makes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared K2 vector: vali's message and check are the KBS's."""
    v, answer = _vector_answer()
    monkeypatch.setattr(settings, "VALI_CDN_KBS_RESPONSE_VK_HEX", v["kbs_public_key_hex"])
    assert (
        fleet.public_key_message(v["version"], bytes.fromhex(v["x25519_public_hex"])).hex()
        == (v["message_hex"])
    )
    key = fleet.verify_kbs_answer(answer, version=v["version"])
    assert key.x25519_public.hex() == v["x25519_public_hex"]

    for field, value in (
        ("version", v["version"] + 1),
        ("kbs_public_key_hex", "00" * 32),
        ("x25519_public_b64", "AAAA"),
    ):
        with pytest.raises(fleet.FleetKeyError) as exc:
            fleet.verify_kbs_answer({**answer, field: value}, version=v["version"])
        assert exc.value.code == "fleet-key-unverified"
    other = __import__("base64").b64encode(b"\x07" * 32).decode()
    with pytest.raises(fleet.FleetKeyError, match="does not verify"):
        fleet.verify_kbs_answer({**answer, "x25519_public_b64": other}, version=v["version"])


@dataclass
class FakeKbs:
    """`hippius-kbs-admin-client cdn-fleet-public`: answers in turn from
    `answers` — a JSON body (exit 0) or `(exit code, stderr)`."""

    answers: list[Any]
    calls: list[list[str]] = dc_field(default_factory=list)

    def run(self, argv: list[str], **kw: Any) -> Any:
        import json
        import subprocess

        self.calls.append(argv)
        answer = self.answers.pop(0)
        if isinstance(answer, dict):
            return subprocess.CompletedProcess(argv, 0, json.dumps(answer).encode() + b"\n", b"")
        code, stderr = answer
        return subprocess.CompletedProcess(argv, code, b"", stderr.encode())


_NOT_MINTED = (66, "kbs-admin-client: 502: cdn-fleet-unwrap-failed: no such version")
_DISABLED = (3, "kbs-admin-client: terminal 404: cdn-fleet-disabled")


@pytest.fixture
def mint_env(
    _no_fleet_keys: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> dict[str, Any]:
    import subprocess

    from apps.orchestration.services import vault_kv

    v, answer = _vector_answer()
    assert v["version"] == 3, "the K2 vector is signed for version 3"
    monkeypatch.setattr(settings, "VALI_CDN_KBS_RESPONSE_VK_HEX", v["kbs_public_key_hex"])
    client = tmp_path / "kbs-admin-client"
    client.write_text("")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_BIN", str(client))
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "http://kbs-admin.test:8001")
    for version in (1, 2):
        fleet.record(_key(version))
    env: dict[str, Any] = {"v": v, "answer": answer, "stored": [], "put_error": None}

    def put_kv(mount: str, path: str, value: bytes, cas: int | None = None) -> None:
        if env["put_error"] is not None:
            raise env["put_error"]
        env["stored"].append((path, value, cas))

    monkeypatch.setattr(vault_kv, "transit_datakey_wrapped", lambda name: b"vault:v1:wrapped")
    monkeypatch.setattr(vault_kv, "put_kv", put_kv)
    env["kbs"] = FakeKbs(answers=[])
    monkeypatch.setattr(subprocess, "run", env["kbs"].run)
    return env


def test_mint(mint_env: dict[str, Any]) -> None:
    """Probe (nothing there) → store once, create-only → the KBS signs."""
    mint_env["kbs"].answers = [_NOT_MINTED, mint_env["answer"]]
    row = fleet.record(fleet.source().mint())
    assert row.version == 3 and row.state == "pending"
    assert mint_env["stored"] == [("hippius-compute/kbs/cdn-fleet/v3", b"vault:v1:wrapped", 0)]
    argv = mint_env["kbs"].calls[-1]
    assert argv[1:4] == ["cdn-fleet-public", "--kbs-url", "http://kbs-admin.test:8001"]
    assert argv[argv.index("--version") + 1] == "3"
    assert argv[argv.index("--kbs-vk-hex") + 1] == mint_env["v"]["kbs_public_key_hex"]


def test_mint_adopts_a_version_the_kbs_already_signs(mint_env: dict[str, Any]) -> None:
    """Stored by an earlier mint that crashed before recording it: adopted,
    nothing written."""
    mint_env["kbs"].answers = [mint_env["answer"]]
    assert fleet.record(fleet.source().mint()).version == 3
    assert mint_env["stored"] == []


@pytest.mark.parametrize(
    "error",
    # Vault 1.18 (`vault server -dev`, a token whose policy is create-only on
    # the path, writing the same version twice) answers the second write 403
    # "permission denied": the ACL check precedes the KV-v2 check-and-set,
    # which would otherwise answer 400. Both are handled.
    ["VaultPermissionDenied", "VaultCasConflict"],
)
def test_mint_recovers_a_version_stored_but_never_recorded(
    mint_env: dict[str, Any], error: str
) -> None:
    from apps.orchestration.services import vault_kv

    mint_env["put_error"] = getattr(vault_kv, error)("exists")
    mint_env["kbs"].answers = [_NOT_MINTED, mint_env["answer"]]
    assert fleet.record(fleet.source().mint()).version == 3


def test_mint_refuses_while_the_kbs_does_not_release(mint_env: dict[str, Any]) -> None:
    """`cdn-fleet-disabled` is not "free": nothing is stored."""
    mint_env["kbs"].answers = [_DISABLED]
    with pytest.raises(fleet.FleetKeyError) as exc:
        fleet.source().mint()
    assert exc.value.code == "fleet-keys-disabled"
    assert mint_env["stored"] == []


@pytest.mark.parametrize("refused", [True, False])
def test_mint_fails_loudly_when_the_kbs_cannot_unwrap(
    mint_env: dict[str, Any], refused: bool
) -> None:
    from apps.orchestration.services import vault_kv

    if refused:
        mint_env["put_error"] = vault_kv.VaultPermissionDenied("exists")
    mint_env["kbs"].answers = [_NOT_MINTED, _NOT_MINTED]
    with pytest.raises(fleet.FleetKeyError) as exc:
        fleet.source().mint()
    assert exc.value.code == "fleet-key-not-minted"
    assert not fleet.CdnFleetKey.objects.filter(version=3).exists()


def test_any_other_kbs_failure_is_raised(mint_env: dict[str, Any]) -> None:
    from apps.orchestration.effects import EffectError

    mint_env["kbs"].answers = [(65, "network: connection refused")]
    with pytest.raises(EffectError):
        fleet.source().mint()
    assert mint_env["stored"] == []


def test_put_kv_names_a_403(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration.services import vault_kv

    monkeypatch.setattr(vault_kv, "_round_trip", lambda *a, **k: (403, b"{}"))
    with pytest.raises(vault_kv.VaultPermissionDenied):
        vault_kv.put_kv("secret", "x", b"y", cas=0)


def test_mint_refuses_without_a_pinned_kbs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration.services import vault_kv

    monkeypatch.setattr(settings, "VALI_CDN_KBS_RESPONSE_VK_HEX", "")
    monkeypatch.setattr(
        vault_kv, "transit_datakey_wrapped", lambda name: pytest.fail("nothing is minted")
    )
    with pytest.raises(fleet.FleetKeyError) as exc:
        fleet.source().mint()
    assert exc.value.code == "fleet-keys-unconfigured"


def test_at_most_four_published_versions(_no_fleet_keys: None) -> None:
    for version in range(1, 5):
        fleet.record(_key(version))
    with pytest.raises(fleet.FleetKeyError) as exc:
        fleet.record(_key(5))
    assert exc.value.code == "fleet-key-too-many"


# ── exactly one active fleet key ──────────────────────────────────────


def test_the_db_refuses_a_second_active_version(_no_fleet_keys: None) -> None:
    from django.db import IntegrityError, transaction

    from ..models import CdnFleetKey

    fleet.record(_key(1))
    fleet.set_state(1, "active")
    fleet.record(_key(2))
    with pytest.raises(IntegrityError), transaction.atomic():
        CdnFleetKey.objects.filter(version=2).update(state="active")


def test_published_never_carries_two_actives(_no_fleet_keys: None) -> None:
    fleet.record(_key(1))
    fleet.set_state(1, "active")
    for version in (2, 3):
        fleet.record(_key(version))
        fleet.set_state(version, "active")
        states = [k["state"] for k in fleet.published()]
        assert states.count("active") == 1
    assert [k["state"] for k in fleet.published()] == ["retiring", "retiring", "active"]


def test_a_constraint_violation_is_a_clear_error(
    _no_fleet_keys: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.db import IntegrityError

    def boom(version: int, state: str) -> None:
        raise IntegrityError("cdn_fleet_one_active")

    monkeypatch.setattr(fleet, "_set_state", boom)
    with pytest.raises(fleet.FleetKeyError) as exc:
        fleet.set_state(2, "active")
    assert exc.value.code == "fleet-key-concurrent-activation"


@pytest.mark.django_db(transaction=True)
def test_concurrent_activations_leave_exactly_one_active() -> None:
    """Two pending versions activated at once (Postgres: two connections).
    The first holds its locks inside `set_state`; the second must wait for
    it, then demote it — never two actives."""
    import threading

    from django.db import connection, connections

    from ..models import CdnFleetKey, CdnRevision

    if connection.vendor != "postgresql":
        pytest.skip("needs two connections to one DB (Postgres lane)")
    CdnFleetKey.objects.all().delete()
    for version in (1, 2):
        fleet.record(_key(version))

    first_in = threading.Event()
    release = threading.Event()
    real_bump = CdnRevision.bump
    calls = {"n": 0}

    def slow_bump() -> int:
        calls["n"] += 1
        if calls["n"] == 1:  # the first activation, inside its transaction
            first_in.set()
            assert release.wait(10)
        return real_bump()

    out: dict[str, Any] = {}

    def run(version: int) -> None:
        try:
            fleet.set_state(version, "active")
            out[version] = "ok"
        except BaseException as exc:  # asserted below
            out[version] = exc
        finally:
            connections.close_all()

    import unittest.mock as um

    with um.patch.object(CdnRevision, "bump", staticmethod(slow_bump)):
        t1 = threading.Thread(target=run, args=(1,))
        t1.start()
        assert first_in.wait(10)
        t2 = threading.Thread(target=run, args=(2,))
        t2.start()
        t2.join(timeout=1.0)
        assert t2.is_alive(), "the second activation waits for the first's locks"
        release.set()
        t1.join(10)
        t2.join(10)
    # The lock serializes them: the second succeeds and demotes the first.
    # (Without it the DB constraint alone would still keep one active, but
    # the second would fail with fleet-key-concurrent-activation.)
    assert out == {1: "ok", 2: "ok"}
    states = dict(CdnFleetKey.objects.values_list("version", "state"))
    assert states == {1: "retiring", 2: "active"}
    CdnFleetKey.objects.all().delete()
