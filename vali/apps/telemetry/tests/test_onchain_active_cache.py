"""Regression: `_node_id_is_onchain_active` decodes the warm
`edge_registry_feed_v1` cache tuple.

The scheduler (`EdgeRegistryFeedView`) stores the feed as a
`(canonical_json_str, sig_hex)` tuple. A prior version of
`_node_id_is_onchain_active` treated the cached value as a dict
(`snapshot.get("miners", …)`) — on a WARM cache that raised
`AttributeError: 'tuple' object has no attribute 'get'`, uncaught, which
500'd the host-attestor cert ingest (and latently the heartbeat
autoprovision). These tests pin the tuple decode + the fail-closed
fall-through to the authoritative chain read.
"""

from __future__ import annotations

import json

import pytest
from django.core.cache import cache

from apps.scheduler import chain
from apps.telemetry import service

pytestmark = pytest.mark.django_db

_CACHE_KEY = "edge_registry_feed_v1"
ACTIVE = "aa" * 32
QUARANTINED = "bb" * 32
UNKNOWN = "cc" * 32


def _feed_tuple(miners: list[dict]) -> tuple[str, str]:
    """The exact `(canonical, sig_hex)` shape the scheduler caches."""
    canonical = json.dumps(
        {"current_epoch": 7, "miners": miners},
        separators=(",", ":"),
        sort_keys=True,
    )
    return (canonical, "de" * 64)


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.delete(_CACHE_KEY)
    yield
    cache.delete(_CACHE_KEY)


def test_warm_cache_tuple_active_returns_true_without_raising(monkeypatch):
    # If the code reaches the chain read here, the cache decode is broken.
    def _boom():
        raise AssertionError("chain read must not run on a valid warm cache")

    monkeypatch.setattr(chain, "read_miner_status", _boom)
    cache.set(
        _CACHE_KEY,
        _feed_tuple(
            [
                {"node_id_hex": ACTIVE, "status": "active"},
                {"node_id_hex": QUARANTINED, "status": "quarantined"},
            ]
        ),
        60,
    )

    assert service._node_id_is_onchain_active(ACTIVE) is True
    assert service._node_id_is_onchain_active(QUARANTINED) is False
    assert service._node_id_is_onchain_active(UNKNOWN) is False


def test_malformed_cache_falls_through_to_chain_fail_closed(monkeypatch):
    calls: list[int] = []

    def _chain():
        calls.append(1)
        raise chain.ChainReadUnavailable("chain down")

    monkeypatch.setattr(chain, "read_miner_status", _chain)

    # A dict (the OLD wrong shape), a non-JSON string, a wrong-arity
    # tuple, and bad JSON must ALL fall through to the chain read — and
    # since the chain is down, fail closed to False. Never raise.
    for bad in (
        {"miners": [{"node_id_hex": ACTIVE, "status": "active"}]},
        ("not-json{", "sig"),
        ("only-one-element",),
        (json.dumps({"miners": "not-a-list"}), "sig"),
    ):
        calls.clear()
        cache.set(_CACHE_KEY, bad, 60)
        assert service._node_id_is_onchain_active(ACTIVE) is False
        assert calls, f"expected chain fall-through for {bad!r}"


def test_cold_cache_reads_chain(monkeypatch):
    from apps.scheduler.chain import ChainSnapshot, MinerView

    snapshot = ChainSnapshot(
        current_epoch=3,
        miners=(
            MinerView(
                node_id=ACTIVE,
                status="active",
                last_transition_epoch=1,
                data_epoch=1,
                quality=0,
            ),
        ),
    )
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)

    assert service._node_id_is_onchain_active(ACTIVE) is True
    assert service._node_id_is_onchain_active(UNKNOWN) is False
