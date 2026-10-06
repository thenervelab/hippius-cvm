"""`_resolve_peer_to_miner_id` — the §K heartbeat peer-id → miner_id
resolution for BOTH the legacy `hippius-miner:` and the permissionless
`hippius-node:` (self-signed identity cert) SAN schemes.
"""

from __future__ import annotations

import pytest

from apps.telemetry.views import _NODE_PEER_ID_PREFIX, _resolve_peer_to_miner_id

from .factories import make_source

pytestmark = pytest.mark.django_db


def test_legacy_miner_scheme_strips_prefix() -> None:
    assert (
        _resolve_peer_to_miner_id("hippius-miner:miner-a")
        == "miner-a"
    )


def test_node_scheme_resolves_by_verifying_key() -> None:
    # node_id IS the Ed25519 pubkey == the registered source's vk.
    node_id = bytes([0xE0, 0x50, 0x5D]) + bytes(29)
    make_source(
        source="miner", source_id="miner-a", verifying_key=node_id
    )
    peer = _NODE_PEER_ID_PREFIX + node_id.hex()
    assert _resolve_peer_to_miner_id(peer) == "miner-a"


def test_node_scheme_unknown_node_id_is_none() -> None:
    # The Edge only forwards on-chain-admitted miners; an unknown vk
    # here is a vali provisioning gap → None → caller 400s.
    assert _resolve_peer_to_miner_id(_NODE_PEER_ID_PREFIX + "aa" * 32) is None


def test_malformed_peer_ids_are_none() -> None:
    assert _resolve_peer_to_miner_id("hippius-node:zz") is None  # bad hex
    assert _resolve_peer_to_miner_id("hippius-node:aabb") is None  # not 32 B
    assert _resolve_peer_to_miner_id(None) is None
    assert _resolve_peer_to_miner_id("garbage") is None
