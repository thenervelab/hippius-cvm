"""`GET|POST /v1/admin/miner/<miner_id>/approval` — the external-miner
approve step the backend calls with its miner-admin token."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity, MinerStatus
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit

pytestmark = pytest.mark.django_db()

NODE = "ab" * 32
URL = "/v1/admin/miner/miner-x/approval"


def _identity(chain_node_id: str | None = NODE) -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id="miner-x",
        pubkey_hex="cd" * 32,
        platform_id="ef" * 16,
        chain_node_id=chain_node_id,
        status=MinerStatus.ACTIVE,
    )


def _capacity(**over: object) -> MinerCapacity:
    now = timezone.now()
    fields: dict[str, object] = dict(
        miner_node_id=NODE,
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        declared_cpu_budget=60,
        declared_at=now,
        reported_memory_available_mib=250_000,
        reported_at=now,
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _body(**over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "cpus": 64,
        "memory_mb": 256_000,
        "approved_by": "backend:alice",
        "reason": "external onboarding",
    }
    body.update(over)
    return body


def test_only_the_miner_admin_may_call(plain_client: APIClient) -> None:
    _identity()
    _capacity()
    assert plain_client.get(URL).status_code == 403
    assert plain_client.post(URL, _body(), format="json").status_code == 403
    assert APIClient().post(URL, _body(), format="json").status_code in (401, 403)
    assert MinerCapacity.objects.get().approved_at is None


def test_get_reads_a_pending_miner(admin_client: APIClient, settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _identity()
    _capacity()
    resp = admin_client.get(URL)
    assert resp.status_code == 200
    body = resp.json()
    assert body["miner_id"] == "miner-x" and body["node_id"] == NODE
    assert body["approved"] is False and body["held_back"] is True
    assert body["measured"] == {"cpus": 60, "memory_mb": 250_000, "disk_gb": None}


def test_post_approves_and_audits(admin_client: APIClient, settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _identity()
    _capacity()
    resp = admin_client.post(URL, _body(trust_class="operator"), format="json")
    assert resp.status_code == 200, resp.json()
    body = resp.json()
    assert (body["total_cpus"], body["total_memory_mb"]) == (60, 250_000)
    assert body["approved_by"] == "op:backend:alice"
    row = MinerCapacity.objects.get()
    assert row.approved_at is not None and row.trust_class == "operator"
    assert MinerCapacityAudit.objects.filter(field="approved_at", actor="op:backend:alice").exists()
    assert admin_client.get(URL).json()["held_back"] is False
    # A second approval is a conflict, not a silent re-anchor.
    again = admin_client.post(URL, _body(), format="json")
    assert again.status_code == 409 and again.json()["category"] == "already-approved"


def test_dry_run_writes_nothing(admin_client: APIClient) -> None:
    _identity()
    _capacity()
    resp = admin_client.post(URL + "?dry_run=1", _body(), format="json")
    assert resp.status_code == 200 and resp.json()["dry_run"] is True
    assert MinerCapacity.objects.get().approved_at is None
    assert not MinerCapacityAudit.objects.exists()


@pytest.mark.parametrize(
    ("setup", "body", "code", "category"),
    [
        ("no-identity", {}, 404, "not-found"),
        ("unbridged", {}, 404, "not-found"),
        ("no-capacity", {}, 404, "not-found"),
        ("ok", {"cpus": "lots"}, 400, "wire"),
        ("ok", {"cpus": 0}, 400, "invalid"),
        ("ok", {"trust_class": "root"}, 400, "wire"),
        ("stale", {}, 409, "not-measured"),
    ],
)
def test_refusals_map_to_http(
    admin_client: APIClient, setup: str, body: dict[str, object], code: int, category: str
) -> None:
    if setup != "no-identity":
        _identity(None if setup == "unbridged" else NODE)
    if setup == "ok":
        _capacity()
    if setup == "stale":
        _capacity(reported_at=timezone.now() - timedelta(hours=1))
    resp = admin_client.post(URL, _body(**body), format="json")
    assert resp.status_code == code, resp.json()
    assert resp.json()["category"] == category


# ─── revoke ──────────────────────────────────────────────────────────


def _revoke_body(**over: object) -> dict[str, object]:
    body: dict[str, object] = {"revoke": True, "revoked_by": "backend:bob", "reason": "fraud"}
    body.update(over)
    return body


def test_post_revoke_puts_the_miner_back_to_pending(admin_client: APIClient, settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _identity()
    _capacity(approved_at=timezone.now(), approved_by="grandfathered")
    resp = admin_client.post(URL, _revoke_body(), format="json")
    assert resp.status_code == 200, resp.content
    assert resp.json()["revoked_by"] == "op:backend:bob"
    row = MinerCapacity.objects.get()
    assert row.approved_at is None and row.revoked_at is not None
    readout = admin_client.get(URL).json()
    assert readout["held_back"] is True
    assert readout["revoked_by"] == "op:backend:bob"
    assert readout["auto_approval_blocker"] == "revoked"
    again = admin_client.post(URL, _revoke_body(), format="json")
    assert again.status_code == 409
    assert again.json()["category"] == "already-revoked"


@pytest.mark.parametrize(
    "body",
    [
        _revoke_body(revoke=False),
        _revoke_body(revoked_by=""),
        _revoke_body(reason=""),
        {"revoke": True},
    ],
)
def test_post_revoke_rejects_a_malformed_body(admin_client: APIClient, body: dict) -> None:
    _identity()
    _capacity(approved_at=timezone.now(), approved_by="grandfathered")
    resp = admin_client.post(URL, body, format="json")
    assert resp.status_code == 400, resp.content
    assert MinerCapacity.objects.get().approved_at is not None
    assert not MinerCapacityAudit.objects.exists()


def test_post_revoke_has_no_dry_run(admin_client: APIClient) -> None:
    _identity()
    _capacity(approved_at=timezone.now(), approved_by="grandfathered")
    resp = admin_client.post(URL + "?dry_run=1", _revoke_body(), format="json")
    assert resp.status_code == 400
    assert MinerCapacity.objects.get().revoked_at is None


def test_post_revoke_only_the_miner_admin(plain_client: APIClient) -> None:
    _identity()
    _capacity(approved_at=timezone.now(), approved_by="grandfathered")
    assert plain_client.post(URL, _revoke_body(), format="json").status_code == 403
    assert MinerCapacity.objects.get().revoked_at is None
