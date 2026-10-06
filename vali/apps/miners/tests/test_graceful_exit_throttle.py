"""RA-M2 — the anon graceful-exit ingresses are per-IP rate limited.

Both `POST /v1/miner/<id>/graceful-exit` (path-based) and
`POST /v1/telemetry/graceful-exit` (Edge-relayed) shell out to the Rust
signature verifier BEFORE any auth (the signed envelope is the credential),
so an unthrottled flood would spawn unbounded validator subprocesses. The
`graceful_exit` throttle scope caps this per source IP.

The throttle is checked at dispatch (before the handler), so the request
body outcome (400/403/404) is irrelevant — the first N consume the budget
and the (N+1)th is refused with 429.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

pytestmark = pytest.mark.django_db


def _burst(url: str, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    # `SimpleRateThrottle.THROTTLE_RATES` is a CLASS attribute bound at
    # import, so `override_settings` can't reach it — patch the class rate
    # to a tiny value so the 3rd request trips the throttle.
    monkeypatch.setattr(
        ScopedRateThrottle, "THROTTLE_RATES", {"graceful_exit": "2/min"}
    )
    client = APIClient()  # anonymous — the views set authentication_classes=[]
    codes = []
    for _ in range(3):
        resp = client.post(url, b"\x00", content_type="application/cbor")
        codes.append(resp.status_code)
    return codes


def test_path_graceful_exit_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    url = reverse("miner_graceful_exit", args=["miner-a"])
    codes = _burst(url, monkeypatch)
    assert status.HTTP_429_TOO_MANY_REQUESTS not in codes[:2], codes
    assert codes[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes


def test_edge_relayed_graceful_exit_is_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = reverse("telemetry_graceful_exit")
    codes = _burst(url, monkeypatch)
    assert status.HTTP_429_TOO_MANY_REQUESTS not in codes[:2], codes
    assert codes[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes
