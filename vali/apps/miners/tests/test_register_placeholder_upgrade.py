"""`POST /v1/admin/miner/register` over an AUTO-PROVISIONED miner row.

A permissionless miner's first on-chain-gated heartbeat makes vali
auto-provision its `MinerIdentity` with the per-node placeholder
`platform_id = onchain:<node_id>` (`autoprovision_platform_id`; vali
knows the node key, not the AMD CHIP_ID). The operator's register call then UPGRADES that row to
the real CHIP_ID + NetBird coordinates — only from the placeholder, only
with the row's own pubkey. Everything else keeps the 409 rules.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import (
    AUTOPROVISION_PLATFORM_ID,
    MinerIdentity,
    autoprovision_platform_id,
)
from apps.scheduler import service as scheduler_service
from apps.telemetry.models import TelemetrySource

pytestmark = pytest.mark.django_db

REGISTER_URL = reverse("miner_register")

NODE = "5e" * 32  # the miner's on-chain node key == its telemetry key
CHIP_TURIN = "0123456789abcdef"  # 8-byte Turin CHIP_ID
CHIP_OTHER = "fedcba9876543210"


def _autoprovisioned(
    miner_id: str = "miner-d",
    node: str = NODE,
    platform_id: str | None = None,
) -> MinerIdentity:
    """The row `autoprovision_node_heartbeat_source` writes (+ its source).
    `platform_id` overrides the per-node placeholder (legacy-form tests)."""
    miner = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=node,
        platform_id=platform_id or autoprovision_platform_id(node),
        chain_node_id=node,
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=7,
    )
    TelemetrySource.objects.create(
        source="miner",
        source_id=miner_id,
        verifying_key=bytes.fromhex(node),
        is_active=True,
    )
    return miner


def _payload(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "miner_id": "miner-d",
        "pubkey_hex": NODE,
        "platform_id": CHIP_TURIN,
        "netbird_peer_id": "peer-cc4",
        "netbird_ip": "100.87.10.4",
        "chain_node_id": NODE,
        "snp_generation": "turin",
    }
    body.update(overrides)
    return body


def _snapshot(miner_id: str = "miner-d") -> dict[str, Any]:
    m = MinerIdentity.objects.get(miner_id=miner_id)
    return {
        "platform_id": m.platform_id,
        "pubkey_hex": m.pubkey_hex,
        "chain_node_id": m.chain_node_id,
        "netbird_peer_id": m.netbird_peer_id,
        "netbird_ip": m.netbird_ip,
        "snp_generation": m.snp_generation,
        "status": m.status,
    }


# ─── the onboarding §6 step ──────────────────────────────────────────


def test_register_upgrades_the_autoprovisioned_placeholder(admin_client: APIClient) -> None:
    _autoprovisioned()
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["platform_id"] == CHIP_TURIN
    assert body["netbird_ip"] == "100.87.10.4"
    assert body["netbird_peer_id"] == "peer-cc4"
    assert body["chain_node_id"] == NODE
    assert body["snp_generation"] == "turin"

    m = MinerIdentity.objects.get(miner_id="miner-d")
    assert m.platform_id == CHIP_TURIN
    assert m.netbird_ip == "100.87.10.4"
    assert m.netbird_peer_id == "peer-cc4"
    assert m.snp_generation == "turin"
    # Heartbeat state is untouched by the upgrade.
    assert m.last_heartbeat_sequence == 7
    # The linked source is still reconciled + active.
    src = TelemetrySource.objects.get(source="miner", source_id="miner-d")
    assert bytes(src.verifying_key) == bytes.fromhex(NODE)
    assert src.is_active is True
    assert MinerIdentity.objects.count() == 1


def test_upgraded_placeholder_becomes_dispatchable(admin_client: APIClient) -> None:
    _autoprovisioned()
    with override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=False):
        # Before: the placeholder is not a real CHIP_ID and there is no
        # netbird_ip ⇒ the scheduler never places onto this miner.
        assert NODE not in scheduler_service.dispatchable_node_ids()
        resp = admin_client.post(REGISTER_URL, _payload(), format="json")
        assert resp.status_code == 200, resp.content
        assert NODE in scheduler_service.dispatchable_node_ids()


def test_upgrade_is_idempotent_on_repost(admin_client: APIClient) -> None:
    _autoprovisioned()
    first = admin_client.post(REGISTER_URL, _payload(), format="json")
    second = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert first.status_code == 200, first.content
    assert second.status_code == 200, second.content
    assert second.json() == first.json()


def test_upgrade_with_only_the_required_fields(admin_client: APIClient) -> None:
    _autoprovisioned()
    resp = admin_client.post(
        REGISTER_URL,
        {"miner_id": "miner-d", "pubkey_hex": NODE, "platform_id": CHIP_TURIN},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    snap = _snapshot()
    assert snap["platform_id"] == CHIP_TURIN
    assert snap["chain_node_id"] == NODE  # kept from the auto-provision
    assert snap["netbird_ip"] is None
    assert snap["netbird_peer_id"] == ""


def test_placeholder_repost_with_the_placeholder_is_a_noop_200(admin_client: APIClient) -> None:
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(
        REGISTER_URL,
        {
            "miner_id": "miner-d",
            "pubkey_hex": NODE,
            "platform_id": autoprovision_platform_id(NODE),
        },
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert _snapshot() == before


def test_legacy_bare_placeholder_is_still_upgraded(admin_client: APIClient) -> None:
    """A row still carrying the pre-per-node literal is recognised too."""
    _autoprovisioned(platform_id=AUTOPROVISION_PLATFORM_ID)
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert resp.status_code == 200, resp.content
    assert _snapshot()["platform_id"] == CHIP_TURIN


@pytest.mark.parametrize(
    "posted", [AUTOPROVISION_PLATFORM_ID, autoprovision_platform_id("77" * 32)]
)
def test_a_different_placeholder_never_replaces_the_stored_one(
    admin_client: APIClient, posted: str
) -> None:
    """Placeholder → placeholder is not an upgrade: another node's (or
    the legacy) placeholder is a plain platform_id mismatch."""
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(
        REGISTER_URL,
        {"miner_id": "miner-d", "pubkey_hex": NODE, "platform_id": posted},
        format="json",
    )
    assert resp.status_code == 409, resp.content
    assert _snapshot() == before


def test_two_placeholders_upgrade_independently(admin_client: APIClient) -> None:
    """Two unregistered permissionless miners coexist (per-node
    placeholders) and each is registered on its own schedule."""
    other = "6f" * 32
    _autoprovisioned()
    _autoprovisioned(miner_id="miner-e", node=other)
    resp = admin_client.post(
        REGISTER_URL,
        _payload(
            miner_id="miner-e",
            pubkey_hex=other,
            chain_node_id=other,
            platform_id=CHIP_OTHER,
            netbird_peer_id="peer-cc5",
            netbird_ip="100.87.10.5",
        ),
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert _snapshot("miner-e")["platform_id"] == CHIP_OTHER
    # The first miner is still on its own placeholder, and upgrades after.
    assert _snapshot()["platform_id"] == autoprovision_platform_id(NODE)
    assert admin_client.post(REGISTER_URL, _payload(), format="json").status_code == 200
    assert _snapshot()["platform_id"] == CHIP_TURIN


# ─── the rebind guards ───────────────────────────────────────────────


def test_placeholder_with_a_different_pubkey_is_conflict_and_writes_nothing(
    admin_client: APIClient,
) -> None:
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(pubkey_hex="cd" * 32), format="json")
    assert resp.status_code == 409, resp.content
    assert resp.json()["category"] == "conflict"
    assert _snapshot() == before
    src = TelemetrySource.objects.get(source="miner", source_id="miner-d")
    assert bytes(src.verifying_key) == bytes.fromhex(NODE)


def test_real_platform_id_is_never_rebound(admin_client: APIClient) -> None:
    _autoprovisioned()
    assert admin_client.post(REGISTER_URL, _payload(), format="json").status_code == 200
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(platform_id=CHIP_OTHER), format="json")
    assert resp.status_code == 409, resp.content
    assert resp.json()["category"] == "conflict"
    assert _snapshot() == before


def test_upgrade_to_another_miners_chip_id_is_conflict_and_writes_nothing(
    admin_client: APIClient,
) -> None:
    MinerIdentity.objects.create(miner_id="other", pubkey_hex="cd" * 32, platform_id=CHIP_TURIN)
    _autoprovisioned()
    before = _snapshot()
    # Unique-index collision on platform_id — surfaced AFTER the pre-write
    # checks passed; the savepoint must drop the netbird/snp backfills too.
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert resp.status_code == 409, resp.content
    assert resp.json()["category"] == "conflict"
    assert _snapshot() == before


def test_placeholder_upgrade_with_a_different_chain_node_id_is_conflict_and_writes_nothing(
    admin_client: APIClient,
) -> None:
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(chain_node_id="77" * 32), format="json")
    assert resp.status_code == 409, resp.content
    # The placeholder was NOT upgraded and no netbird field was backfilled.
    assert _snapshot() == before


def test_placeholder_upgrade_with_a_bad_netbird_ip_is_400(admin_client: APIClient) -> None:
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(netbird_ip="not-an-ip"), format="json")
    assert resp.status_code == 400, resp.content
    assert _snapshot() == before


# ─── netbird backfill rules on a registered (non-placeholder) row ────


def test_netbird_fields_backfill_from_empty(admin_client: APIClient) -> None:
    base = {"miner_id": "m", "pubkey_hex": "ab" * 32, "platform_id": CHIP_OTHER}
    assert admin_client.post(REGISTER_URL, base, format="json").status_code == 201
    resp = admin_client.post(
        REGISTER_URL,
        {**base, "netbird_peer_id": "peer-m", "netbird_ip": "100.64.9.9"},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    m = MinerIdentity.objects.get(miner_id="m")
    assert m.netbird_peer_id == "peer-m"
    assert m.netbird_ip == "100.64.9.9"


def test_differing_netbird_fields_never_overwrite_a_stored_value(admin_client: APIClient) -> None:
    base = {
        "miner_id": "m",
        "pubkey_hex": "ab" * 32,
        "platform_id": CHIP_OTHER,
        "netbird_peer_id": "peer-m",
        "netbird_ip": "100.64.9.9",
    }
    assert admin_client.post(REGISTER_URL, base, format="json").status_code == 201
    resp = admin_client.post(
        REGISTER_URL,
        {**base, "netbird_peer_id": "peer-x", "netbird_ip": "100.64.1.1"},
        format="json",
    )
    # Unchanged pre-existing behaviour: 200, the stored mesh coordinates kept.
    assert resp.status_code == 200, resp.content
    assert resp.json()["netbird_ip"] == "100.64.9.9"
    m = MinerIdentity.objects.get(miner_id="m")
    assert m.netbird_peer_id == "peer-m"
    assert m.netbird_ip == "100.64.9.9"


# ─── typo guard, quarantine, race, pre-write 409s ────────────────────


@pytest.mark.parametrize(
    "bad",
    ["Onchain ", "amd-chipid-0001", "0123456789abcde", " " + CHIP_TURIN, "0x" + CHIP_TURIN],
)
def test_placeholder_is_only_replaced_by_a_hex_chip_id(admin_client: APIClient, bad: str) -> None:
    _autoprovisioned()
    before = _snapshot()
    resp = admin_client.post(
        REGISTER_URL, _payload(platform_id=bad, snp_generation=None), format="json"
    )
    assert resp.status_code == 400, resp.content
    assert _snapshot() == before
    # The real CHIP_ID can still be posted afterwards.
    assert admin_client.post(REGISTER_URL, _payload(), format="json").status_code == 200


def test_upgrading_a_quarantined_placeholder_keeps_it_quarantined(
    admin_client: APIClient,
) -> None:
    _autoprovisioned()
    admin_client.post(reverse("miner_quarantine", args=["miner-d"]))
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert resp.status_code == 200, resp.content
    snap = _snapshot()
    assert snap["platform_id"] == CHIP_TURIN
    assert snap["status"] == "quarantined"
    src = TelemetrySource.objects.get(source="miner", source_id="miner-d")
    assert src.is_active is False
    with override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=False):
        assert NODE not in scheduler_service.dispatchable_node_ids()


def test_placeholder_upgrade_with_a_conflicting_generation_writes_nothing(
    admin_client: APIClient,
) -> None:
    miner = _autoprovisioned()
    miner.snp_generation = "genoa"
    miner.save(update_fields=["snp_generation"])
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")  # turin
    assert resp.status_code == 409, resp.content
    assert _snapshot() == before


def test_chain_node_id_collision_during_upgrade_writes_nothing(
    admin_client: APIClient,
) -> None:
    MinerIdentity.objects.create(
        miner_id="other", pubkey_hex="cd" * 32, platform_id=CHIP_OTHER, chain_node_id="88" * 32
    )
    miner = _autoprovisioned()
    miner.chain_node_id = None
    miner.save(update_fields=["chain_node_id"])
    before = _snapshot()
    resp = admin_client.post(REGISTER_URL, _payload(chain_node_id="88" * 32), format="json")
    assert resp.status_code == 409, resp.content
    assert _snapshot() == before


def test_register_racing_the_autoprovision_upgrades_instead_of_409(
    admin_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The heartbeat auto-provisions the row between register's lookup
    and its create: the create collides, and the recovery path must
    treat the now-present placeholder like a sequential re-register."""
    from apps.miners import views

    # The heartbeat's commit is modelled as a row already present that
    # register's FIRST lookup does not see (it ran before that commit).
    _autoprovisioned()
    real_lock = views._lock_miner
    calls = {"n": 0}

    def lock_missing_once(miner_id: str) -> MinerIdentity | None:
        calls["n"] += 1
        if calls["n"] == 1:
            return None
        return real_lock(miner_id)

    monkeypatch.setattr(views, "_lock_miner", lock_missing_once)
    resp = admin_client.post(REGISTER_URL, _payload(), format="json")
    assert resp.status_code == 200, resp.content
    assert calls["n"] == 2
    snap = _snapshot()
    assert snap["platform_id"] == CHIP_TURIN
    assert snap["netbird_ip"] == "100.87.10.4"


@pytest.mark.parametrize(
    "placeholder", [AUTOPROVISION_PLATFORM_ID, autoprovision_platform_id("6f" * 32)]
)
def test_a_new_miner_cannot_be_created_on_a_placeholder(
    admin_client: APIClient, placeholder: str
) -> None:
    """Placeholders are vali-written only: an operator row holding
    `onchain:<node>` would squat that node's future auto-provision."""
    resp = admin_client.post(
        REGISTER_URL,
        {"miner_id": "fresh", "pubkey_hex": "cd" * 32, "platform_id": placeholder},
        format="json",
    )
    assert resp.status_code == 400, resp.content
    assert not MinerIdentity.objects.filter(miner_id="fresh").exists()
