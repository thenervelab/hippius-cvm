"""Tests for `sentinel.output.slack_webhook` — the CRITICAL pager.

No network: an `httpx.MockTransport` stands in for Slack and records
every request it receives.
"""

from __future__ import annotations

import json

import httpx
import pytest

from sentinel.analytics.base import Severity
from sentinel.output.channels import DispatchStatus, iso_utc
from sentinel.output.slack_webhook import (
    ENV_WEBHOOK_URL,
    SlackWebhookChannel,
    SlackWebhookConfig,
)
from tests._analytics_helpers import make_finding

_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/abcdefghij0123456789"


def _channel(handler) -> tuple[SlackWebhookChannel, list[httpx.Request]]:
    """Build a channel whose transport runs `handler`; return captured requests."""

    seen: list[httpx.Request] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    channel = SlackWebhookChannel(
        SlackWebhookConfig(webhook_url=_WEBHOOK),
        transport=httpx.MockTransport(_capture),
    )
    return channel, seen


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def test_posts_critical_finding() -> None:
    channel, seen = _channel(_ok)
    result = channel.dispatch(make_finding(severity=Severity.CRITICAL))
    assert result.status is DispatchStatus.CREATED
    assert len(seen) == 1
    payload = json.loads(seen[0].content)
    assert "text" in payload


def test_skips_below_critical() -> None:
    for sev in (Severity.INFO, Severity.WARN, Severity.ALERT):
        channel, seen = _channel(_ok)
        result = channel.dispatch(make_finding(severity=sev))
        assert result.status is DispatchStatus.SKIPPED
        assert seen == []  # nothing was posted


def test_non_2xx_returns_failed() -> None:
    def _rejected(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="invalid_payload")

    channel, _ = _channel(_rejected)
    result = channel.dispatch(make_finding(severity=Severity.CRITICAL))
    assert result.status is DispatchStatus.FAILED
    assert "400" in result.detail


def test_transport_error_returns_failed() -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated connection failure", request=request)

    channel, _ = _channel(_boom)
    result = channel.dispatch(make_finding(severity=Severity.CRITICAL))
    assert result.status is DispatchStatus.FAILED


def test_webhook_url_never_leaks_into_result() -> None:
    """The webhook URL is a bearer secret — never in a result detail."""

    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fail to " + _WEBHOOK, request=request)

    for handler in (_ok, _boom, lambda r: httpx.Response(500, text="oops")):
        channel, _ = _channel(handler)
        result = channel.dispatch(make_finding(severity=Severity.CRITICAL))
        assert _WEBHOOK not in result.detail
        assert "hooks.slack.com" not in result.detail


def test_message_redacts_secret() -> None:
    captured: list[str] = []

    def _grab(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content)["text"])
        return httpx.Response(200, text="ok")

    channel, _ = _channel(_grab)
    channel.dispatch(
        make_finding(
            severity=Severity.CRITICAL,
            summary="leaked sk-ant-api03-abcdefABCDEF0123456789xyz now",
        )
    )
    assert "sk-ant-" not in captured[0]
    assert "[REDACTED]" in captured[0]


def test_message_format_carries_key_fields() -> None:
    captured: list[str] = []

    def _grab(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content)["text"])
        return httpx.Response(200, text="ok")

    channel, _ = _channel(_grab)
    finding = make_finding(
        severity=Severity.CRITICAL,
        rule_name="audit_chain_break",
        fingerprint="break:deadbeef",
        summary="KBS audit chain verification FAILED",
        at_unix=1_700_000_000,
    )
    channel.dispatch(finding)
    text = captured[0]
    assert "CRITICAL" in text
    assert "audit_chain_break" in text
    assert "break:deadbeef" in text
    assert iso_utc(1_700_000_000) in text


def test_from_env_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_WEBHOOK_URL, raising=False)
    assert SlackWebhookConfig.from_env() is None


def test_from_env_reads_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_WEBHOOK_URL, _WEBHOOK)
    cfg = SlackWebhookConfig.from_env()
    assert cfg is not None
    assert cfg.webhook_url == _WEBHOOK


def test_from_env_rejects_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_WEBHOOK_URL, "http://hooks.slack.com/services/x")
    with pytest.raises(ValueError, match="https"):
        SlackWebhookConfig.from_env()
