"""#306 — `mint_netbird_setup_key` effect unit tests.

The function is one of the §F-secret-sensitive surfaces (the minted
key is treated as a §20 secret end-to-end), so the tests pin:

  - the API URL it talks to (`<base>/api/setup-keys`),
  - the request body shape (one-off + ephemeral + auto-group),
  - the Authorization header carries the configured token,
  - the response `key` field is returned verbatim,
  - failure-mode exceptions (`EffectError` / `EffectUnavailable`)
    NEVER leak the URL or the token.

The transport is `urllib.request.urlopen` — we patch it the same way
existing effect tests do (`monkeypatch.setattr(_, "urlopen", ...)`).
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
)
from apps.orchestration.effects import mint_netbird_setup_key as _real_mint


class _FakeResponse:
    """Stand-in for the `urlopen` context-manager return."""

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
    """Capture the `(method, url, headers, body)` of every
    `urlopen()` call. `handler(request)` returns a `_FakeResponse`
    or raises an `HTTPError` / `URLError`.
    """
    captured: list[Any] = []

    def _stub(
        request: urllib.request.Request, timeout: float, **_kw: object
    ) -> _FakeResponse:
        body = request.data
        captured.append(
            {
                "method": request.get_method(),
                "url": request.full_url,
                "headers": dict(request.header_items()),
                "body": (
                    json.loads(body.decode("utf-8")) if body is not None else None
                ),
            }
        )
        return handler(request)

    monkeypatch.setattr(urllib.request, "urlopen", _stub)
    return captured


def _pin_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings, "VALI_NETBIRD_API_BASE", "https://nb-mgmt.test"
    )
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "nbp_test_token")
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_EFFECT_TIMEOUT_S", 5.0)


# The group list the mint resolves NAMES → IDs against (auto_groups wants
# IDs, not names). `hippius-tenants` → `grp-1`.
_GROUPS_JSON = json.dumps(
    [{"id": "grp-1", "name": "hippius-tenants"}, {"id": "grp-all", "name": "All"}]
).encode()


def _groups_then(post_handler: Any) -> Any:
    """Wrap a POST `/api/setup-keys` handler so the prior
    `GET /api/groups` (name→id resolution) returns a canned group list."""

    def handler(req: urllib.request.Request) -> _FakeResponse:
        if req.get_method() == "GET" and req.full_url.endswith("/api/groups"):
            return _FakeResponse(200, _GROUPS_JSON)
        return post_handler(req)

    return handler


# ─── happy path ──────────────────────────────────────────────────────


def test_mint_setup_key_posts_canonical_body_and_returns_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)

    def handler(_req: urllib.request.Request) -> _FakeResponse:
        return _FakeResponse(
            201,
            json.dumps({"id": "sk-1", "key": "minted-xyz", "name": "..."}).encode(),
        )

    captured = _stub_urlopen(monkeypatch, _groups_then(handler))
    minted = _real_mint(
        vm_id="vm-abc",
        tenant_id="t-acme",
        auto_group_name="hippius-tenants",
        expires_in_seconds=900,
    )

    assert minted == "minted-xyz"
    # Two round-trips: GET /api/groups (name→id), then POST /api/setup-keys.
    assert len(captured) == 2
    assert captured[0]["method"] == "GET"
    assert captured[0]["url"] == "https://nb-mgmt.test/api/groups"
    call = captured[1]
    assert call["method"] == "POST"
    assert call["url"] == "https://nb-mgmt.test/api/setup-keys"
    # Header name-canonicalisation: urllib lower-cases nothing; httplib
    # does title-case. Match either.
    auth = call["headers"].get("Authorization") or call["headers"].get(
        "authorization"
    )
    assert auth == "Token nbp_test_token"
    assert call["body"] == {
        "name": "hippius-tenant-vm-abc",
        "type": "one-off",
        "expires_in": 900,
        "usage_limit": 1,
        # The NAME was resolved to its group ID.
        "auto_groups": ["grp-1"],
        "revoked": False,
        "ephemeral": True,
        "description": "hippius vm_id=vm-abc tenant_id=t-acme",
    }


def test_mint_raises_on_unknown_group(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)
    # GET /api/groups succeeds but the requested group isn't in it.
    _stub_urlopen(
        monkeypatch,
        _groups_then(lambda _req: _FakeResponse(201, b"{}")),
    )
    with pytest.raises(EffectError, match="group not found: 'does-not-exist'"):
        _real_mint(
            vm_id="vm-q",
            tenant_id="t-q",
            auto_group_name="does-not-exist",
        )


# ─── failure shapes ──────────────────────────────────────────────────


def test_mint_setup_key_raises_on_4xx(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin_settings(monkeypatch)

    def handler(_req: urllib.request.Request) -> _FakeResponse:
        # urllib raises HTTPError on 4xx/5xx; the _http helper catches
        # it and synthesises a (status, body) so the caller sees the code.
        raise urllib.error.HTTPError(
            "https://nb-mgmt.test/api/setup-keys",
            403,
            "forbidden",
            {},  # type: ignore[arg-type]
            None,
        )

    _stub_urlopen(monkeypatch, _groups_then(handler))
    with pytest.raises(EffectError, match="HTTP 403"):
        _real_mint(
            vm_id="vm-x",
            tenant_id="t-x",
            auto_group_name="hippius-tenants",
        )


def test_mint_setup_key_raises_on_missing_key_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)

    def handler(_req: urllib.request.Request) -> _FakeResponse:
        # NetBird could in principle return 201 with a malformed body.
        return _FakeResponse(201, json.dumps({"id": "sk-1"}).encode())

    _stub_urlopen(monkeypatch, _groups_then(handler))
    with pytest.raises(EffectError, match="missing 'key'"):
        _real_mint(
            vm_id="vm-y",
            tenant_id="t-y",
            auto_group_name="hippius-tenants",
        )


def test_mint_setup_key_raises_unavailable_on_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin_settings(monkeypatch)

    def handler(_req: urllib.request.Request) -> _FakeResponse:
        raise urllib.error.URLError("name resolution")

    _stub_urlopen(monkeypatch, _groups_then(handler))
    with pytest.raises(EffectUnavailable):
        _real_mint(
            vm_id="vm-z",
            tenant_id="t-z",
            auto_group_name="hippius-tenants",
        )


def test_mint_setup_key_refuses_when_token_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        settings, "VALI_NETBIRD_API_BASE", "https://nb-mgmt.test"
    )
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "")
    with pytest.raises(EffectUnavailable):
        _real_mint(
            vm_id="vm-w",
            tenant_id="t-w",
            auto_group_name="hippius-tenants",
        )


# ─── secret discipline ───────────────────────────────────────────────


def test_mint_setup_key_error_text_never_carries_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§20 secret discipline: the token must NEVER leak into any
    exception message. `_http`'s `EffectUnavailable` carries the
    transport-level exception text but not the URL nor the auth header.
    """
    _pin_settings(monkeypatch)

    def handler(_req: urllib.request.Request) -> _FakeResponse:
        raise urllib.error.URLError("dial tcp 1.2.3.4:443: connect: refused")

    _stub_urlopen(monkeypatch, _groups_then(handler))
    with pytest.raises(EffectUnavailable) as exc:
        _real_mint(
            vm_id="vm-leak-check",
            tenant_id="t-leak-check",
            auto_group_name="hippius-tenants",
        )
    msg = str(exc.value)
    assert "nbp_test_token" not in msg
    assert "https://nb-mgmt.test" not in msg
