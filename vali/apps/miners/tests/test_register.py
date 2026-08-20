"""Tests for `POST /v1/admin/miner/register`."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity
from apps.telemetry.models import TelemetrySource

from .conftest import register_payload

pytestmark = pytest.mark.django_db

REGISTER_URL = reverse("miner_register")


# ─── happy path ──────────────────────────────────────────────────────


def test_register_creates_miner_and_linked_telemetry_source(
    admin_client: APIClient,
) -> None:
    resp = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 201, resp.content
    body = resp.json()
    assert body["miner_id"] == "miner-1"
    assert body["status"] == "active"
    assert body["telemetry_source"] == {
        "source": "miner",
        "source_id": "miner-1",
    }

    miner = MinerIdentity.objects.get(miner_id="miner-1")
    assert miner.pubkey_hex == "ab" * 32
    assert miner.status == "active"

    # The linked TelemetrySource was provisioned atomically with the
    # miner — keyed `miner:<miner_id>`, verifying key = the pubkey.
    src = TelemetrySource.objects.get(
        source="miner", source_id="miner-1"
    )
    assert bytes(src.verifying_key) == bytes.fromhex("ab" * 32)
    assert src.is_active is True


def test_register_normalizes_pubkey_to_lowercase(admin_client: APIClient) -> None:
    resp = admin_client.post(
        REGISTER_URL, register_payload(pubkey_hex="AB" * 32), format="json"
    )
    assert resp.status_code == 201, resp.content
    miner = MinerIdentity.objects.get(miner_id="miner-1")
    assert miner.pubkey_hex == "ab" * 32


def test_register_stores_optional_netbird_fields(
    admin_client: APIClient,
) -> None:
    resp = admin_client.post(
        REGISTER_URL,
        register_payload(netbird_peer_id="peer-xyz", netbird_ip="100.64.0.7"),
        format="json",
    )
    assert resp.status_code == 201, resp.content
    miner = MinerIdentity.objects.get(miner_id="miner-1")
    assert miner.netbird_peer_id == "peer-xyz"
    assert miner.netbird_ip == "100.64.0.7"


# ─── idempotency ─────────────────────────────────────────────────────


def test_register_is_idempotent_for_identical_identity(
    admin_client: APIClient,
) -> None:
    first = admin_client.post(REGISTER_URL, register_payload(), format="json")
    second = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert first.status_code == 201
    # Re-registering the identical identity is a no-op 200, not a 409.
    assert second.status_code == 200, second.content
    assert MinerIdentity.objects.count() == 1
    assert TelemetrySource.objects.filter(source="miner").count() == 1


# ─── conflict detection ──────────────────────────────────────────────


def test_register_same_id_different_pubkey_is_conflict(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    resp = admin_client.post(
        REGISTER_URL, register_payload(pubkey_hex="cd" * 32), format="json"
    )
    assert resp.status_code == 409
    assert resp.json()["category"] == "conflict"


def test_register_pubkey_collision_with_another_miner_is_conflict(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    # Distinct miner_id + platform_id, but the SAME pubkey ⇒ 409.
    resp = admin_client.post(
        REGISTER_URL,
        register_payload(
            miner_id="miner-2", platform_id="amd-chipid-0002"
        ),
        format="json",
    )
    assert resp.status_code == 409
    assert resp.json()["category"] == "conflict"
    assert MinerIdentity.objects.count() == 1


def test_register_platform_collision_with_another_miner_is_conflict(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    # Distinct miner_id + pubkey, but the SAME platform_id ⇒ 409.
    resp = admin_client.post(
        REGISTER_URL,
        register_payload(
            miner_id="miner-2", pubkey_hex="cd" * 32
        ),
        format="json",
    )
    assert resp.status_code == 409
    assert MinerIdentity.objects.count() == 1


# ─── chain_node_id bridge (scheduler ↔ identity) ─────────────────────


def test_register_stores_and_serializes_chain_node_id(
    admin_client: APIClient,
) -> None:
    node = "11" * 32
    resp = admin_client.post(
        REGISTER_URL, register_payload(chain_node_id=node), format="json"
    )
    assert resp.status_code == 201, resp.content
    assert resp.json()["chain_node_id"] == node
    miner = MinerIdentity.objects.get(miner_id="miner-1")
    assert miner.chain_node_id == node


def test_register_chain_node_id_normalized_to_lowercase(
    admin_client: APIClient,
) -> None:
    resp = admin_client.post(
        REGISTER_URL, register_payload(chain_node_id="AB" * 32), format="json"
    )
    assert resp.status_code == 201, resp.content
    miner = MinerIdentity.objects.get(miner_id="miner-1")
    assert miner.chain_node_id == "ab" * 32


def test_register_omitting_chain_node_id_leaves_it_null(
    admin_client: APIClient,
) -> None:
    resp = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 201, resp.content
    assert resp.json()["chain_node_id"] is None
    assert (
        MinerIdentity.objects.get(miner_id="miner-1").chain_node_id
        is None
    )


def test_register_backfills_chain_node_id_from_null(
    admin_client: APIClient,
) -> None:
    # Operator registers first, then learns the on-chain node_id and
    # re-registers to backfill it — an idempotent 200 that sets it.
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    node = "22" * 32
    resp = admin_client.post(
        REGISTER_URL, register_payload(chain_node_id=node), format="json"
    )
    assert resp.status_code == 200, resp.content
    assert resp.json()["chain_node_id"] == node
    assert (
        MinerIdentity.objects.get(miner_id="miner-1").chain_node_id
        == node
    )


def test_register_changing_chain_node_id_is_conflict(
    admin_client: APIClient,
) -> None:
    admin_client.post(
        REGISTER_URL, register_payload(chain_node_id="33" * 32), format="json"
    )
    resp = admin_client.post(
        REGISTER_URL, register_payload(chain_node_id="44" * 32), format="json"
    )
    assert resp.status_code == 409
    assert resp.json()["category"] == "conflict"
    # The stored value is untouched.
    assert (
        MinerIdentity.objects.get(miner_id="miner-1").chain_node_id
        == "33" * 32
    )


def test_register_chain_node_id_collision_with_another_miner_is_conflict(
    admin_client: APIClient,
) -> None:
    admin_client.post(
        REGISTER_URL, register_payload(chain_node_id="55" * 32), format="json"
    )
    # A DIFFERENT miner claiming the SAME on-chain node ⇒ 409 — two
    # miners can never map to one chain identity.
    resp = admin_client.post(
        REGISTER_URL,
        register_payload(
            miner_id="miner-2",
            pubkey_hex="cd" * 32,
            platform_id="amd-chipid-0002",
            chain_node_id="55" * 32,
        ),
        format="json",
    )
    assert resp.status_code == 409
    assert resp.json()["category"] == "conflict"
    assert MinerIdentity.objects.count() == 1


@pytest.mark.parametrize(
    "bad_node",
    ["zz" * 32, "ab" * 16, "ab" * 40],
    ids=["not-hex", "too-short", "too-long"],
)
def test_register_rejects_a_malformed_chain_node_id(
    admin_client: APIClient, bad_node: str
) -> None:
    resp = admin_client.post(
        REGISTER_URL, register_payload(chain_node_id=bad_node), format="json"
    )
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"
    assert MinerIdentity.objects.count() == 0


# ─── auth ────────────────────────────────────────────────────────────


def test_register_requires_the_admin_principal(
    plain_client: APIClient,
) -> None:
    resp = plain_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 403
    assert MinerIdentity.objects.count() == 0


def test_register_unauthenticated_is_rejected() -> None:
    resp = APIClient().post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code in (401, 403)
    assert MinerIdentity.objects.count() == 0


# ─── wire validation ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_pubkey",
    ["zz" * 32, "ab" * 16, "ab" * 40, "xyz"],
    ids=["not-hex", "too-short", "too-long", "tiny"],
)
def test_register_rejects_a_malformed_pubkey(
    admin_client: APIClient, bad_pubkey: str
) -> None:
    resp = admin_client.post(
        REGISTER_URL, register_payload(pubkey_hex=bad_pubkey), format="json"
    )
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"
    assert MinerIdentity.objects.count() == 0


def test_register_rejects_a_missing_field(admin_client: APIClient) -> None:
    payload = register_payload()
    del payload["platform_id"]
    resp = admin_client.post(REGISTER_URL, payload, format="json")
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_register_rejects_an_invalid_netbird_ip(
    admin_client: APIClient,
) -> None:
    resp = admin_client.post(
        REGISTER_URL, register_payload(netbird_ip="not-an-ip"), format="json"
    )
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_register_idempotent_reconciles_a_drifted_telemetry_source(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    # Simulate the linked source drifting out of band — wrong key,
    # wrongly deactivated.
    src = TelemetrySource.objects.get(
        source="miner", source_id="miner-1"
    )
    src.verifying_key = bytes.fromhex("00" * 32)
    src.is_active = False
    src.save(update_fields=["verifying_key", "is_active"])

    # An idempotent re-register reconciles the source back to the
    # registry (the MinerIdentity is the authoritative record).
    resp = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 200, resp.content
    src.refresh_from_db()
    assert bytes(src.verifying_key) == bytes.fromhex("ab" * 32)
    assert src.is_active is True


def test_register_heals_an_orphan_telemetry_source(
    admin_client: APIClient,
) -> None:
    # An orphan `miner:<id>` source — no backing MinerIdentity. A new
    # registration must reconcile it, not collide on the unique
    # (source, source_id) and 409 the operator out.
    TelemetrySource.objects.create(
        source="miner",
        source_id="miner-1",
        verifying_key=bytes.fromhex("00" * 32),
        is_active=False,
    )
    resp = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 201, resp.content
    src = TelemetrySource.objects.get(
        source="miner", source_id="miner-1"
    )
    # Reconciled to the freshly-registered miner.
    assert bytes(src.verifying_key) == bytes.fromhex("ab" * 32)
    assert src.is_active is True
    assert TelemetrySource.objects.filter(source="miner").count() == 1


def test_reregistering_a_quarantined_miner_keeps_its_source_inactive(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    admin_client.post(reverse("miner_quarantine", args=["miner-1"]))

    # Re-registering a quarantined miner is idempotent (200) but must
    # NOT silently re-enable its telemetry — the source reconcile reads
    # the (locked, fresh) quarantined status.
    resp = admin_client.post(REGISTER_URL, register_payload(), format="json")
    assert resp.status_code == 200, resp.content
    src = TelemetrySource.objects.get(
        source="miner", source_id="miner-1"
    )
    assert src.is_active is False
    assert (
        MinerIdentity.objects.get(miner_id="miner-1").status
        == "quarantined"
    )
