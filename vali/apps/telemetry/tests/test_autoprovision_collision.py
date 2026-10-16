"""§K auto-provisioning must not let one node take over another's miner_id.

The heartbeat's `miner_id` is operator-chosen in the signed body — a
global namespace any on-chain-Active node can name. Provisioning used to
`update_or_create` the miner `TelemetrySource` under that id with the
CLAIMING node's key, so a node naming an existing miner's id re-keyed
that miner's source: its own heartbeats then failed and the claimant's
verified as it. A miner_id is now claimable only when free or already
bound to the same node.

The verifier + chain reads are mocked (Cargo-/chain-independent). The
last test races two real transactions and runs on Postgres only.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from django.db import connection, connections

from apps.miners.models import MinerIdentity, autoprovision_platform_id
from apps.telemetry import service, verifier
from apps.telemetry.models import SourceType, TelemetrySource
from apps.telemetry.verifier import HeartbeatBody

NODE_A = "aa" * 32
NODE_B = "bb" * 32


@pytest.fixture(autouse=True)
def _onchain_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda _h: True)


def _claims(monkeypatch: pytest.MonkeyPatch, miner_id: str) -> None:
    """Every heartbeat verifies and names `miner_id` in its body."""
    monkeypatch.setattr(
        verifier,
        "verify_heartbeat",
        lambda *, envelope, verifying_key: HeartbeatBody(
            schema_version=1,
            domain="hb",
            miner_id=miner_id,
            timestamp_unix=0,
            sequence=1,
        ),
    )


def _bind(miner_id: str, node_hex: str, *, pubkey_hex: str | None = None) -> None:
    """A provisioned miner: identity + source keyed to `pubkey_hex`."""
    key = pubkey_hex or node_hex
    MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=key,
        platform_id=autoprovision_platform_id(node_hex),
        chain_node_id=node_hex,
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=miner_id,
        verifying_key=bytes.fromhex(key),
    )


def _source_key(miner_id: str) -> bytes:
    return bytes(
        TelemetrySource.objects.get(
            source=SourceType.MINER.value, source_id=miner_id
        ).verifying_key
    )


@pytest.mark.django_db
def test_miner_id_bound_to_another_node_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bind("miner-1", NODE_A)
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") is None

    assert _source_key("miner-1") == bytes.fromhex(NODE_A)
    ident = MinerIdentity.objects.get(miner_id="miner-1")
    assert (ident.pubkey_hex, ident.chain_node_id) == (NODE_A, NODE_A)
    assert MinerIdentity.objects.count() == 1


@pytest.mark.django_db
def test_operator_registered_miner_without_chain_node_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A legacy row (no `chain_node_id` yet) is bound by its `pubkey_hex`."""
    MinerIdentity.objects.create(
        miner_id="miner-1", pubkey_hex=NODE_A, platform_id="chip-1"
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id="miner-1",
        verifying_key=bytes.fromhex(NODE_A),
    )
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") is None
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)


@pytest.mark.django_db
def test_orphan_source_keyed_to_another_node_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id="miner-1",
        verifying_key=bytes.fromhex(NODE_A),
    )
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") is None
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)
    assert not MinerIdentity.objects.exists()


@pytest.mark.django_db
def test_same_node_reheal_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The source went missing; the bound node heals it."""
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex=NODE_A,
        platform_id=autoprovision_platform_id(NODE_A),
        chain_node_id=NODE_A,
    )
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_A, b"env") == "miner-1"
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)


@pytest.mark.django_db
def test_reheal_by_chain_node_id_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """`chain_node_id` alone binds the row to the node (the operator-set
    telemetry key may differ)."""
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex=NODE_B,
        platform_id="chip-1",
        chain_node_id=NODE_A,
    )
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_A, b"env") == "miner-1"


@pytest.mark.django_db
def test_fresh_miner_is_provisioned(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind("miner-1", NODE_A)
    _claims(monkeypatch, "miner-2")

    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") == "miner-2"

    assert _source_key("miner-2") == bytes.fromhex(NODE_B)
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)
    ident = MinerIdentity.objects.get(miner_id="miner-2")
    assert (ident.pubkey_hex, ident.chain_node_id) == (NODE_B, NODE_B)


@pytest.mark.django_db
@pytest.mark.parametrize("bound_by", ["chain_node_id", "pubkey_hex"])
def test_node_already_bound_cannot_claim_a_second_miner_id(
    monkeypatch: pytest.MonkeyPatch, bound_by: str
) -> None:
    """One node, one miner: a node bound under miner-1 naming miner-2 is
    refused cleanly (no 500 on the unique keys), nothing is written."""
    if bound_by == "chain_node_id":
        _bind("miner-1", NODE_A, pubkey_hex=NODE_B)
    else:
        MinerIdentity.objects.create(
            miner_id="miner-1", pubkey_hex=NODE_A, platform_id="chip-1"
        )
    _claims(monkeypatch, "miner-2")

    assert service.autoprovision_node_heartbeat_source(NODE_A, b"env") is None

    assert not MinerIdentity.objects.filter(miner_id="miner-2").exists()
    assert not TelemetrySource.objects.filter(
        source=SourceType.MINER.value, source_id="miner-2"
    ).exists()


@pytest.mark.django_db
def test_claim_lost_to_a_concurrent_winner_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-check passed, but another node's row landed before our
    INSERT: `get_or_create` hands back THAT row, which must be re-checked
    and refused rather than re-keyed."""
    real_check = service._autoprovision_binding_is_free

    def check_then_lose_race(miner_id: str, node_id: bytes, node_hex: str) -> bool:
        free = real_check(miner_id, node_id, node_hex)
        _bind(miner_id, NODE_A)
        return free

    monkeypatch.setattr(service, "_autoprovision_binding_is_free", check_then_lose_race)
    _claims(monkeypatch, "miner-1")

    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") is None
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)


@pytest.mark.django_db
def test_source_rekeyed_before_the_fix_resolves_for_neither_claimant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State left by the old bug: miner-1's source carries NODE_B's key
    while its identity is bound to NODE_A. NODE_B no longer resolves to
    miner-1 (and cannot re-claim it); NODE_A's next heartbeat re-keys the
    source back."""
    from apps.telemetry.views import _NODE_PEER_ID_PREFIX, _resolve_peer_to_miner_id

    _bind("miner-1", NODE_A)
    TelemetrySource.objects.filter(source_id="miner-1").update(
        verifying_key=bytes.fromhex(NODE_B)
    )
    _claims(monkeypatch, "miner-1")

    assert _resolve_peer_to_miner_id(_NODE_PEER_ID_PREFIX + NODE_B) is None
    assert service.autoprovision_node_heartbeat_source(NODE_B, b"env") is None

    assert _resolve_peer_to_miner_id(_NODE_PEER_ID_PREFIX + NODE_A) is None
    assert service.autoprovision_node_heartbeat_source(NODE_A, b"env") == "miner-1"
    assert _source_key("miner-1") == bytes.fromhex(NODE_A)
    assert _resolve_peer_to_miner_id(_NODE_PEER_ID_PREFIX + NODE_A) == "miner-1"


@pytest.mark.django_db(transaction=True)
def test_concurrent_first_heartbeats_bind_the_miner_id_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two nodes' first heartbeats name the same free miner_id at once.
    Both pass the pre-check (no row to lock yet) and race the INSERT; the
    loser must be refused and the winner's key must stand."""
    if connection.vendor != "postgresql":
        pytest.skip("needs real concurrent transactions (settings_test_pg)")
    _claims(monkeypatch, "miner-1")
    barrier = threading.Barrier(2, timeout=10)
    real_check = service._autoprovision_binding_is_free

    def check_together(miner_id: str, node_id: bytes, node_hex: str) -> bool:
        free = real_check(miner_id, node_id, node_hex)
        barrier.wait()
        return free

    monkeypatch.setattr(service, "_autoprovision_binding_is_free", check_together)
    results: dict[str, Any] = {}

    def claim(node_hex: str) -> None:
        try:
            results[node_hex] = service.autoprovision_node_heartbeat_source(
                node_hex, b"env"
            )
        except Exception as exc:  # noqa: BLE001 — asserted below
            results[node_hex] = exc
        finally:
            connections.close_all()

    threads = [threading.Thread(target=claim, args=(n,)) for n in (NODE_A, NODE_B)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert sorted(results.values(), key=repr) == sorted(["miner-1", None], key=repr)
    winner = NODE_A if results[NODE_A] == "miner-1" else NODE_B
    assert _source_key("miner-1") == bytes.fromhex(winner)
    ident = MinerIdentity.objects.get(miner_id="miner-1")
    assert ident.chain_node_id == winner
