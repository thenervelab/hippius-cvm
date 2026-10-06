"""The auto-provision placeholder `platform_id` is PER NODE.

`MinerIdentity.platform_id` is unique. With one shared placeholder
literal, a second permissionless miner heart-beating before the first was
registered hit an IntegrityError on auto-provision (a 500 on the heartbeat
ingest). The placeholder is now `onchain:<node_id>`; every consumer that
recognises it goes through `is_autoprovision_placeholder`, and it is
never a chip id anywhere (scheduler gate, launch-digest mapping).
"""

from __future__ import annotations

from typing import Any

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import override_settings
from django.utils import timezone

from apps.miners.models import (
    AUTOPROVISION_PLATFORM_ID,
    MinerIdentity,
    MinerStatus,
    autoprovision_platform_id,
    is_autoprovision_placeholder,
)
from apps.orchestration.effects import EffectError
from apps.orchestration.services.launch_digest import _vcpu_type_for_platform
from apps.scheduler import service as scheduler_service
from apps.telemetry import service as telemetry_service
from apps.telemetry import verifier
from apps.telemetry.verifier import HeartbeatBody

NODE_A = "aa" * 32
NODE_B = "bb" * 32


# ─── the helpers ─────────────────────────────────────────────────────


def test_placeholder_is_per_node_and_fits_the_column() -> None:
    pid = autoprovision_platform_id(NODE_A.upper())
    assert pid == f"onchain:{NODE_A}"
    assert pid != autoprovision_platform_id(NODE_B)
    max_len = MinerIdentity._meta.get_field("platform_id").max_length
    assert max_len is not None and len(pid) <= max_len


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (autoprovision_platform_id(NODE_A), True),
        (AUTOPROVISION_PLATFORM_ID, True),  # legacy bare literal
        ("onchain:", True),
        ("0123456789abcdef", False),
        ("", False),
        (None, False),
        ("Onchain", False),
        ("onchainx", False),
        ("plat-miner-a", False),
    ],
)
def test_is_autoprovision_placeholder(value: str | None, expected: bool) -> None:
    assert is_autoprovision_placeholder(value) is expected


# ─── auto-provision: two unregistered nodes coexist ──────────────────


def _mock_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """The heartbeat's signed `miner_id` is derived from the node key it
    is verified against, so each node provisions its own row."""
    names = {bytes.fromhex(NODE_A): "miner-a", bytes.fromhex(NODE_B): "miner-b"}

    def verify(*, envelope: bytes, verifying_key: bytes) -> HeartbeatBody:
        return HeartbeatBody(
            schema_version=1,
            domain="hb",
            miner_id=names[bytes(verifying_key)],
            timestamp_unix=0,
            sequence=1,
        )

    monkeypatch.setattr(verifier, "verify_heartbeat", verify)
    monkeypatch.setattr(telemetry_service, "_node_id_is_onchain_active", lambda _h: True)


@pytest.mark.django_db
def test_two_unregistered_nodes_autoprovision_without_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_verify(monkeypatch)
    assert telemetry_service.autoprovision_node_heartbeat_source(NODE_A, b"env") == "miner-a"
    assert telemetry_service.autoprovision_node_heartbeat_source(NODE_B, b"env") == "miner-b"
    # …and a re-heartbeat of either stays idempotent.
    assert telemetry_service.autoprovision_node_heartbeat_source(NODE_A, b"env") == "miner-a"

    a = MinerIdentity.objects.get(miner_id="miner-a")
    b = MinerIdentity.objects.get(miner_id="miner-b")
    assert a.platform_id == autoprovision_platform_id(NODE_A)
    assert b.platform_id == autoprovision_platform_id(NODE_B)
    assert is_autoprovision_placeholder(a.platform_id)
    assert is_autoprovision_placeholder(b.platform_id)


# ─── never a chip id ─────────────────────────────────────────────────


@pytest.mark.django_db
@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=False)
@pytest.mark.parametrize(
    "platform_id", [autoprovision_platform_id(NODE_A), AUTOPROVISION_PLATFORM_ID]
)
def test_placeholder_is_never_dispatchable(platform_id: str) -> None:
    """Every other gate passes; the placeholder alone keeps it off."""
    miner = MinerIdentity.objects.create(
        miner_id="miner-a",
        pubkey_hex=NODE_A,
        platform_id=platform_id,
        chain_node_id=NODE_A,
        netbird_ip="100.64.0.10",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )
    verdict = scheduler_service.dispatchability(miner)
    assert verdict == scheduler_service.Dispatchability(False, "platform-id-invalid")
    assert NODE_A not in scheduler_service.dispatchable_node_ids()


@pytest.mark.parametrize("snp_generation", [None, "", "turin", "genoa", "milan"])
@pytest.mark.parametrize(
    "platform_id",
    [
        autoprovision_platform_id(NODE_A),
        AUTOPROVISION_PLATFORM_ID,
        # A placeholder whose tail alone would parse as a 64-byte chip id.
        "onchain:" + "ab" * 64,
    ],
)
def test_launch_digest_mapping_fails_closed_on_the_placeholder(
    platform_id: str, snp_generation: str | None
) -> None:
    with pytest.raises(EffectError, match="platform-id-autoprovision-placeholder"):
        _vcpu_type_for_platform(platform_id, snp_generation)


# ─── migration 0006: legacy literal → per-node ───────────────────────

_MINERS_0005 = ("miners", "0005_mineridentity_snp_generation")
_MINERS_0006 = ("miners", "0006_autoprovision_placeholder_per_node")


@pytest.mark.django_db(transaction=True)
def test_migration_0006_rewrites_the_legacy_placeholder() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([_MINERS_0005])
    old_apps: Any = executor.loader.project_state([_MINERS_0005]).apps
    OldMiner = old_apps.get_model("miners", "MinerIdentity")

    legacy = OldMiner.objects.create(
        miner_id="legacy",
        pubkey_hex=NODE_A,
        platform_id="onchain",
        chain_node_id=NODE_B.upper(),
    )
    real = OldMiner.objects.create(
        miner_id="real", pubkey_hex="cc" * 32, platform_id="0123456789abcdef"
    )
    try:
        executor.loader.build_graph()
        executor.migrate([_MINERS_0006])
        # Keyed on chain_node_id (lower-cased) when set …
        assert MinerIdentity.objects.get(pk=legacy.pk).platform_id == (
            autoprovision_platform_id(NODE_B)
        )
        # … a real chip id is untouched.
        assert MinerIdentity.objects.get(pk=real.pk).platform_id == "0123456789abcdef"
    finally:
        # Every leaf: going back to 0005 also unapplied what depends on 0006.
        executor.loader.build_graph()
        executor.migrate(executor.loader.graph.leaf_nodes())


@pytest.mark.django_db(transaction=True)
def test_migration_0006_falls_back_to_the_pubkey() -> None:
    executor = MigrationExecutor(connection)
    executor.migrate([_MINERS_0005])
    old_apps: Any = executor.loader.project_state([_MINERS_0005]).apps
    OldMiner = old_apps.get_model("miners", "MinerIdentity")
    legacy = OldMiner.objects.create(
        miner_id="legacy-nochain", pubkey_hex=NODE_A, platform_id="onchain"
    )
    try:
        executor.loader.build_graph()
        executor.migrate([_MINERS_0006])
        assert MinerIdentity.objects.get(pk=legacy.pk).platform_id == (
            autoprovision_platform_id(NODE_A)
        )
    finally:
        # Every leaf: going back to 0005 also unapplied what depends on 0006.
        executor.loader.build_graph()
        executor.migrate(executor.loader.graph.leaf_nodes())
