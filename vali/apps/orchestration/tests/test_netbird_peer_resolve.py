"""`resolve_netbird_peer_ip` effect unit tests.

The VM→peer association is anchored on the peer's `name` (the per-VM
setup-key name `hippius-tenant-<vm_id>`), NOT its `hostname` — the live
NetBird API reports `hostname` as the guest OS hostname
(`localhost.localdomain`, or the bare truncated `hippius-tenant` from an
older enrolment bug). These pin that association + the §20 secret
discipline (the token never leaks into an exception).

`urllib.request.urlopen` is patched the same way `test_netbird_setup_key`
does.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest
from django.conf import settings

from apps.orchestration.effects import (
    EffectError,
    EffectUnavailable,
    resolve_netbird_peer,
    resolve_netbird_peer_ip,
)


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _stub_urlopen(monkeypatch: pytest.MonkeyPatch, handler: Any) -> list[Any]:
    captured: list[Any] = []

    def _stub(
        request: urllib.request.Request, timeout: float, **_kw: object
    ) -> _FakeResponse:
        captured.append(
            {"method": request.get_method(), "url": request.full_url,
             "headers": dict(request.header_items())}
        )
        return handler(request)

    monkeypatch.setattr(urllib.request, "urlopen", _stub)
    return captured


def _pin_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_BASE", "https://nb-mgmt.test")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "nbp_test_token")
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_EFFECT_TIMEOUT_S", 5.0)


def _peers(*peers: dict[str, Any]) -> bytes:
    return json.dumps(list(peers)).encode()


# ─── happy path ──────────────────────────────────────────────────────


def test_resolve_matches_by_name_not_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)
    # The real-world shape: `name` carries the vm_id; `hostname` is the
    # guest OS hostname (here the truncated buggy value).
    body = _peers(
        {"name": "hippius-tenant-vm-abc", "hostname": "hippius-tenant",
         "ip": "100.64.0.20", "connected": True},
        {"name": "some-other-peer", "ip": "100.64.0.42", "connected": True},
    )
    captured = _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))

    ip = resolve_netbird_peer_ip("vm-abc")

    assert ip == "100.64.0.20"
    assert len(captured) == 1
    assert captured[0]["method"] == "GET"
    assert captured[0]["url"] == "https://nb-mgmt.test/api/peers"
    auth = captured[0]["headers"].get("Authorization") or captured[0][
        "headers"
    ].get("authorization")
    assert auth == "Token nbp_test_token"


def test_resolve_prefers_connected_on_name_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)
    body = _peers(
        {"name": "hippius-tenant-vm-dup", "ip": "100.1.1.1", "connected": False},
        {"name": "hippius-tenant-vm-dup", "ip": "100.2.2.2", "connected": True},
    )
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    assert resolve_netbird_peer_ip("vm-dup") == "100.2.2.2"


def test_resolve_returns_none_when_no_peer_enrolled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)
    body = _peers({"name": "hippius-tenant-other", "ip": "100.1.1.1"})
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    assert resolve_netbird_peer_ip("vm-missing") is None


def test_resolve_ignores_non_overlay_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)
    # A match without a valid `100.` overlay IP → treated as unresolved.
    body = _peers({"name": "hippius-tenant-vm-x", "ip": "192.168.0.5"})
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    assert resolve_netbird_peer_ip("vm-x") is None


# ─── absent record vs present-but-unassigned (P9/#17) ────────────────
#
# The post-§25 sweep acts on ABSENCE — a deleted peer record means
# NetBird's ephemeral GC removed it and the guest can never re-register
# (its launch key is a consumed one-off). A peer that merely has no
# assigned overlay IP is still REGISTERED, and conflating the two would
# declare a live tenant permanently lost.


def test_peer_absent_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)
    body = _peers({"name": "hippius-tenant-other", "ip": "100.1.1.1"})
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    assert resolve_netbird_peer("vm-missing") is None


def test_peer_without_overlay_ip_is_still_a_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)
    body = _peers(
        {"name": "hippius-tenant-vm-x", "ip": "192.168.0.5", "connected": True}
    )
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    peer = resolve_netbird_peer("vm-x")
    assert peer is not None  # the RECORD exists — not GC'd
    assert peer.ip == ""
    assert peer.connected is True
    # …while the IP projection still reports "unresolved".
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    assert resolve_netbird_peer_ip("vm-x") is None


def test_peer_carries_the_connected_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)
    body = _peers(
        {"name": "hippius-tenant-vm-y", "ip": "100.7.7.7", "connected": False}
    )
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, body))
    peer = resolve_netbird_peer("vm-y")
    assert peer is not None
    assert peer.ip == "100.7.7.7"
    assert peer.connected is False


# ─── failure shapes ──────────────────────────────────────────────────


def test_resolve_raises_on_4xx(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)

    def handler(_r: urllib.request.Request) -> _FakeResponse:
        raise urllib.error.HTTPError(
            "https://nb-mgmt.test/api/peers", 403, "forbidden", {}, None  # type: ignore[arg-type]
        )

    _stub_urlopen(monkeypatch, handler)
    with pytest.raises(EffectError, match="HTTP 403"):
        resolve_netbird_peer_ip("vm-x")


def test_resolve_raises_on_non_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)
    _stub_urlopen(monkeypatch, lambda _r: _FakeResponse(200, b"not json"))
    with pytest.raises(EffectError, match="non-JSON"):
        resolve_netbird_peer_ip("vm-x")


def test_resolve_raises_unavailable_on_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)

    def handler(_r: urllib.request.Request) -> _FakeResponse:
        raise urllib.error.URLError("name resolution")

    _stub_urlopen(monkeypatch, handler)
    with pytest.raises(EffectUnavailable):
        resolve_netbird_peer_ip("vm-x")


def test_resolve_refuses_when_token_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_BASE", "https://nb-mgmt.test")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "")
    with pytest.raises(EffectUnavailable):
        resolve_netbird_peer_ip("vm-x")


# ─── secret discipline ───────────────────────────────────────────────


def test_resolve_error_text_never_carries_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)

    def handler(_r: urllib.request.Request) -> _FakeResponse:
        raise urllib.error.URLError("dial tcp 1.2.3.4:443: connect: refused")

    _stub_urlopen(monkeypatch, handler)
    with pytest.raises(EffectUnavailable) as exc:
        resolve_netbird_peer_ip("vm-leak-check")
    msg = str(exc.value)
    assert "nbp_test_token" not in msg
    assert "https://nb-mgmt.test" not in msg
