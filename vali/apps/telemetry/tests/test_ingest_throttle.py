"""RA-N4 / RA-N5 — the anon ingress throttles key on the un-spoofable
Edge-stamped ``x-hippius-peer-id``, and ``TelemetryIngestView`` is throttled.

vali is Edge-only (CiliumNetworkPolicy) and the Edge builds a fresh upstream
request stamping the connection's mTLS-verified ``x-hippius-peer-id`` — a
caller cannot rotate it. ``PeerIdScopedRateThrottle`` buckets anonymous
requests on that identity:

- **RA-N4** — the stock ``ScopedRateThrottle`` keyed on the client IP, read
  from a client-supplied ``X-Forwarded-For`` when ``NUM_PROXIES`` is unset;
  an attacker rotated the header for a fresh bucket per request and defeated
  the cap. Keying on the peer-id (and ``NUM_PROXIES = 0``) closes that.
- **RA-N5** — ``TelemetryIngestView`` (the CBOR heartbeat + autoprovision
  path) shells out to the Rust verifier before any backpressure/quarantine
  and was previously unthrottled.

The throttle is checked at dispatch (before the handler), so the body
outcome (400/403/404) is irrelevant — the first N consume the budget and the
(N+1)th is refused with 429.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

pytestmark = pytest.mark.django_db

PEER_A = "hippius-node:" + "aa" * 32
PEER_B = "hippius-node:" + "bb" * 32


@pytest.fixture
def _tiny_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    # `SimpleRateThrottle.THROTTLE_RATES` is a CLASS attribute bound at
    # import (shared via MRO with PeerIdScopedRateThrottle), so patch it to
    # a tiny value so the 3rd request trips the cap.
    monkeypatch.setattr(
        ScopedRateThrottle,
        "THROTTLE_RATES",
        {"telemetry_ingest": "2/min", "graceful_exit": "2/min"},
    )


def _post(
    client: APIClient,
    url: str,
    peer_id: str | None,
    xff: str | None = None,
) -> int:
    extra: dict[str, str] = {}
    if peer_id is not None:
        extra["HTTP_X_HIPPIUS_PEER_ID"] = peer_id
    if xff is not None:
        extra["HTTP_X_FORWARDED_FOR"] = xff
    return client.post(
        url, b"\x00", content_type="application/cbor", **extra
    ).status_code


def test_telemetry_ingest_is_throttled(_tiny_rates: None) -> None:
    # RA-N5 — the CBOR heartbeat path now carries a throttle_scope.
    url = reverse("telemetry_ingest")
    client = APIClient()
    codes = [_post(client, url, PEER_A) for _ in range(3)]
    assert status.HTTP_429_TOO_MANY_REQUESTS not in codes[:2], codes
    assert codes[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes


def test_throttle_buckets_per_peer_id(_tiny_rates: None) -> None:
    # A distinct peer-id is a distinct bucket — one flooder can't starve
    # another miner's budget.
    url = reverse("telemetry_graceful_exit")
    client = APIClient()
    codes_a = [_post(client, url, PEER_A) for _ in range(3)]
    assert codes_a[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes_a
    # Peer B, same client/IP, has its own fresh budget.
    assert _post(client, url, PEER_B) != status.HTTP_429_TOO_MANY_REQUESTS


def test_rotating_xff_does_not_escape_the_cap(_tiny_rates: None) -> None:
    # RA-N4 — same peer-id, a fresh X-Forwarded-For each request: still ONE
    # bucket, so the 3rd is refused. (Pre-fix this returned a fresh bucket
    # per XFF value and never tripped.)
    url = reverse("telemetry_graceful_exit")
    client = APIClient()
    codes = [
        _post(client, url, PEER_A, xff=f"203.0.113.{i}") for i in range(3)
    ]
    assert codes[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes
