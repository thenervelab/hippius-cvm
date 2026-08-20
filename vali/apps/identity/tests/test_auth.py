"""Tests for `apps.identity` — mTLS middleware + auth backends."""

from __future__ import annotations

import hashlib

import pytest
from django.test import RequestFactory, override_settings
from rest_framework.exceptions import AuthenticationFailed

from apps.identity.authentication import (
    MtlsAuthentication,
    ServiceTokenAuthentication,
)
from apps.identity.middleware import MtlsClientCertMiddleware, _parse_cn
from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)

pytestmark = pytest.mark.django_db


def _passthrough(request):
    return request


# ────────────────────────────────────────────────────────────────────
# Middleware — REMOTE_ADDR gating
# ────────────────────────────────────────────────────────────────────


def test_middleware_ignores_headers_without_trusted_proxy() -> None:
    """Even if the headers look fine, an UNTRUSTED REMOTE_ADDR
    means we MUST NOT honor them — otherwise a direct caller could
    spoof an L1 cert.
    """
    rf = RequestFactory()
    req = rf.get(
        "/",
        REMOTE_ADDR="1.2.3.4",  # NOT in trusted-proxies
        HTTP_X_SSL_CLIENT_VERIFY="SUCCESS",
        HTTP_X_SSL_CLIENT_S_DN="CN=l1-prod",
    )
    with override_settings(VALI_MTLS_TRUSTED_PROXIES=["192.0.2.10"]):
        mw = MtlsClientCertMiddleware(_passthrough)
        out = mw(req)
    assert out.mtls_present is False
    assert out.mtls_subject_cn is None


def test_middleware_extracts_cn_when_proxy_is_trusted() -> None:
    rf = RequestFactory()
    req = rf.get(
        "/",
        REMOTE_ADDR="192.0.2.10",
        HTTP_X_SSL_CLIENT_VERIFY="SUCCESS",
        HTTP_X_SSL_CLIENT_S_DN="CN=l1-prod,O=Hippius",
    )
    with override_settings(VALI_MTLS_TRUSTED_PROXIES=["192.0.2.10"]):
        mw = MtlsClientCertMiddleware(_passthrough)
        out = mw(req)
    assert out.mtls_present is True
    assert out.mtls_verify == "SUCCESS"
    assert out.mtls_subject_cn == "l1-prod"


def test_middleware_handles_slash_dn() -> None:
    rf = RequestFactory()
    req = rf.get(
        "/",
        REMOTE_ADDR="192.0.2.10",
        HTTP_X_SSL_CLIENT_VERIFY="SUCCESS",
        HTTP_X_SSL_CLIENT_S_DN="/CN=l1-prod/O=Hippius",
    )
    with override_settings(VALI_MTLS_TRUSTED_PROXIES=["192.0.2.10"]):
        mw = MtlsClientCertMiddleware(_passthrough)
        out = mw(req)
    assert out.mtls_subject_cn == "l1-prod"


def test_parse_cn_rejects_missing_cn() -> None:
    assert _parse_cn("O=Hippius") is None
    assert _parse_cn("") is None
    assert _parse_cn("CN=") is None


# ────────────────────────────────────────────────────────────────────
# MtlsAuthentication
# ────────────────────────────────────────────────────────────────────


def test_mtls_auth_returns_none_when_middleware_inactive() -> None:
    """If the middleware never saw a trusted-proxy request, the auth
    backend should bow out (return None) so DRF tries the next
    backend — NOT raise AuthenticationFailed.
    """
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = False
    backend = MtlsAuthentication()
    assert backend.authenticate(req) is None


def test_mtls_auth_falls_through_when_verdict_is_none() -> None:
    """Trusted proxy reached us but the caller didn't present a client
    cert (`X-SSL-Client-Verify: NONE`). MtlsAuthentication must
    return `None` so DRF tries the next backend (e.g. service token)
    instead of 401'ing the request outright.
    """
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = "NONE"
    req.mtls_subject_cn = None
    backend = MtlsAuthentication()
    assert backend.authenticate(req) is None


def test_mtls_auth_falls_through_when_verdict_is_empty() -> None:
    """`X-SSL-Client-Verify: ""` means the proxy didn't gate mTLS for
    this request. Falls through identically to `NONE`.
    """
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = ""
    req.mtls_subject_cn = None
    backend = MtlsAuthentication()
    assert backend.authenticate(req) is None


def test_mtls_auth_fails_when_verdict_is_not_success() -> None:
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = "FAILED:expired"
    req.mtls_subject_cn = "l1-prod"
    backend = MtlsAuthentication()
    with pytest.raises(AuthenticationFailed, match="not verified"):
        backend.authenticate(req)


def test_mtls_auth_fails_when_cn_not_registered() -> None:
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = "SUCCESS"
    req.mtls_subject_cn = "unknown-client"
    backend = MtlsAuthentication()
    with pytest.raises(AuthenticationFailed, match="not a registered"):
        backend.authenticate(req)


def test_mtls_auth_succeeds_for_active_client() -> None:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="l1-prod")
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = "SUCCESS"
    req.mtls_subject_cn = "l1-prod"
    backend = MtlsAuthentication()
    user, auth = backend.authenticate(req)
    assert user.pk == client.pk
    assert auth is None


def test_mtls_auth_rejects_inactive_client() -> None:
    ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="retired",
        is_active=False,
    )
    rf = RequestFactory()
    req = rf.get("/")
    req.mtls_present = True
    req.mtls_verify = "SUCCESS"
    req.mtls_subject_cn = "retired"
    backend = MtlsAuthentication()
    with pytest.raises(AuthenticationFailed):
        backend.authenticate(req)


# ────────────────────────────────────────────────────────────────────
# ServiceTokenAuthentication
# ────────────────────────────────────────────────────────────────────


def test_service_token_is_stored_only_as_hash() -> None:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="ops")
    row, plaintext = ServiceToken.issue(
        client=client,
        name="ops-2026q2",
        lifetime=TokenLifetime.OPS.value,
    )
    expected_hash = hashlib.sha256(plaintext.encode("ascii")).hexdigest()
    # The DB row stores only the digest — plaintext is NOT a column.
    assert row.token_sha256 == expected_hash
    assert plaintext != row.token_sha256
    assert len(plaintext) >= 32


def test_service_token_auth_succeeds_with_valid_bearer() -> None:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="ops")
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops-token",
        lifetime=TokenLifetime.OPS.value,
    )
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    backend = ServiceTokenAuthentication()
    user, token = backend.authenticate(req)
    assert user.pk == client.pk
    assert token is not None
    # `last_used_at` is bumped on successful auth.
    token.refresh_from_db()
    assert token.last_used_at is not None


def test_service_token_auth_returns_none_without_header() -> None:
    rf = RequestFactory()
    req = rf.get("/")
    backend = ServiceTokenAuthentication()
    assert backend.authenticate(req) is None


def test_service_token_auth_returns_none_on_wrong_scheme() -> None:
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION="Basic abc")
    backend = ServiceTokenAuthentication()
    assert backend.authenticate(req) is None


def test_service_token_auth_rejects_non_ascii_bearer() -> None:
    """A non-ASCII bearer header must NOT bubble `UnicodeEncodeError`
    into a 500; the backend treats it as a structured 401.
    """
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION="Bearer tøken-with-accent")
    backend = ServiceTokenAuthentication()
    with pytest.raises(AuthenticationFailed, match="ASCII"):
        backend.authenticate(req)


def test_service_token_auth_fails_on_unknown_token() -> None:
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION="Bearer not-a-real-token")
    backend = ServiceTokenAuthentication()
    with pytest.raises(AuthenticationFailed, match="invalid service token"):
        backend.authenticate(req)


def test_service_token_auth_fails_on_disabled_client() -> None:
    client = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="retired",
        is_active=False,
    )
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    backend = ServiceTokenAuthentication()
    with pytest.raises(AuthenticationFailed):
        backend.authenticate(req)


def test_service_token_auth_fails_on_expired_token() -> None:
    """THE load-bearing property of #32: a bounded lifetime means
    nothing unless authentication REFUSES a token past it.

    The expired row is built by aging an issued token rather than by
    minting one with a past expiry — `ServiceToken.issue` now refuses
    the latter (see `test_issue_rejects_expiry_in_the_past`), and this
    test is about the AUTH path, not the mint path.
    """
    from datetime import timedelta

    from django.utils import timezone

    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="ops")
    row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    row.expires_at = timezone.now() - timedelta(hours=1)
    row.save(update_fields=["expires_at"])
    rf = RequestFactory()
    req = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    backend = ServiceTokenAuthentication()
    with pytest.raises(AuthenticationFailed, match="expired"):
        backend.authenticate(req)
