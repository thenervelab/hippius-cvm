"""Slack webhook output channel (PR-S5).

Posts a short Markdown alert to a Slack incoming webhook for `CRITICAL`
findings only — the acute-paging tier. Lower severities never reach
Slack; they live in the GitHub issue tracker and the daily summary.

## Idempotency

A Slack incoming webhook has no native de-duplication: every POST is a
fresh message. The §S "no spam" invariant is therefore enforced
*upstream*, not here:

  * The PR-S4 analytics loop suppresses identical `(rule, fingerprint)`
    findings for the rule's cooldown, so a flapping condition cannot
    re-page within that window.
  * The `FindingRouter` only routes a CRITICAL finding to Slack when
    the GitHub channel reports `CREATED` — i.e. a genuinely new
    incident. If GitHub reports `DUPLICATE` (an issue is already open),
    the router skips Slack. That piggybacks Slack idempotency onto
    GitHub's durable, search-backed de-dup and covers the
    pod-restart re-emission case.

This channel itself stays a dumb sender so it is trivial to audit.

## Secret hygiene

The webhook URL is itself a bearer secret. It is never logged, never
placed in a `ChannelResult.detail`, and never echoed in an error
string — `httpx` connection errors quote the target URL, so failures
are reported by exception *class name* only. The message body is
rendered from a `redact_finding`-scrubbed copy of the finding.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from sentinel.analytics.base import Finding, Severity
from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    iso_utc,
    severity_at_least,
)
from sentinel.output.redact import redact_finding, redact_text

log = logging.getLogger("sentinel.output.slack_webhook")

CHANNEL_NAME = "slack-webhook"

ENV_WEBHOOK_URL = "SLACK_WEBHOOK_URL"

DEFAULT_TIMEOUT_S = 15.0

# Slack only ever sees CRITICAL — the acute tier.
MIN_SEVERITY = Severity.CRITICAL

# Keep the message compact; Slack truncates very long text awkwardly.
_MAX_SUMMARY_LEN = 600


@dataclass(frozen=True)
class SlackWebhookConfig:
    """Resolved Slack webhook config.

    `from_env` returns `None` when `SLACK_WEBHOOK_URL` is unset — that
    is the supported "Slack disabled" state, not an error: the router
    simply omits the channel.
    """

    webhook_url: str
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SlackWebhookConfig | None:
        src = env if env is not None else os.environ
        url = src.get(ENV_WEBHOOK_URL, "").strip()
        if not url:
            return None
        if not url.startswith("https://"):
            # Fail loud rather than POST a finding to an unexpected
            # plaintext or non-HTTP endpoint.
            raise ValueError(
                f"{ENV_WEBHOOK_URL} must be an https:// URL "
                "(refusing to post findings over a non-TLS endpoint)"
            )
        return cls(webhook_url=url)


class SlackWebhookChannel:
    """Posts CRITICAL findings to a Slack incoming webhook."""

    name = CHANNEL_NAME

    def __init__(
        self,
        config: SlackWebhookConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._transport = transport

    def dispatch(self, finding: Finding) -> ChannelResult:
        """POST `finding` to Slack if it is CRITICAL. Never raises."""

        try:
            if not severity_at_least(finding.severity, MIN_SEVERITY):
                return ChannelResult(
                    self.name,
                    DispatchStatus.SKIPPED,
                    f"severity {finding.severity.value} below {MIN_SEVERITY.value}",
                )
            text = _render_message(redact_finding(finding))
            return self._post(text)
        except Exception as e:  # noqa: BLE001 — a channel must never crash the router
            # Deliberately no `str(e)` — httpx exceptions quote the URL.
            log.warning("slack dispatch failed: %s", type(e).__name__)
            return ChannelResult(
                self.name, DispatchStatus.FAILED, f"unexpected: {type(e).__name__}"
            )

    def _post(self, text: str) -> ChannelResult:
        with httpx.Client(
            transport=self._transport, timeout=self._config.timeout_s
        ) as client:
            try:
                resp = client.post(self._config.webhook_url, json={"text": text})
            except httpx.HTTPError as e:
                # No URL in the message — httpx error strings embed it.
                log.warning("slack POST transport error: %s", type(e).__name__)
                return ChannelResult(
                    self.name,
                    DispatchStatus.FAILED,
                    f"transport error: {type(e).__name__}",
                )
        if resp.status_code == httpx.codes.OK:
            log.info("slack alert posted")
            return ChannelResult(self.name, DispatchStatus.CREATED, "posted")
        # Slack error bodies are short machine codes (`invalid_payload`,
        # `no_service`); redact anyway as defence in depth.
        body = redact_text(resp.text or "")[:200]
        log.warning("slack POST rejected: HTTP %d", resp.status_code)
        return ChannelResult(
            self.name,
            DispatchStatus.FAILED,
            f"HTTP {resp.status_code}: {body}",
        )


# ---------------------------------------------------------------------------
# Rendering (pure — easy to unit-test)
# ---------------------------------------------------------------------------


def _render_message(finding: Finding) -> str:
    """Short Slack-mrkdwn alert. `finding` must already be redacted."""

    summary = " ".join(finding.summary.split()) or "(no summary)"
    if len(summary) > _MAX_SUMMARY_LEN:
        summary = summary[:_MAX_SUMMARY_LEN] + "…"
    return "\n".join(
        [
            f":rotating_light: *{finding.severity.value} · hippius-sentinel*",
            f"*{finding.rule_name}* — {summary}",
            f"fingerprint `{finding.fingerprint}` · detected {iso_utc(finding.at_unix)}",
        ]
    )
