"""Severity-based finding router (PR-S5).

The router is the single fan-out point between the PR-S4 analytics
loop and the output channels. It owns two policies:

## Severity routing

    INFO / WARN   → daily summary only
    ALERT         → GitHub issue + daily summary
    CRITICAL      → Slack + GitHub issue + daily summary

The daily summary receives *every* finding — it is the complete record.
GitHub issues are the structured incident tracker for anything
actionable (ALERT+). Slack is the acute pager, CRITICAL only.

## Idempotency & anti-spam

De-duplication is layered, most of it durable in a way an in-process
cache is not:

  * **PR-S4 loop** — collapses identical `(rule, fingerprint)` findings
    for the rule's cooldown, so a rule firing 1000×/min reaches the
    router at most once per cooldown window.
  * **GitHub channel** — searches for an already-open issue carrying
    the finding's signature; a re-emitted finding collapses onto it.
  * **Slack gate** — the router routes a CRITICAL to Slack only when
    the GitHub channel reports `CREATED` (a genuinely new incident).
    A GitHub `DUPLICATE` means the incident is already tracked and was
    already paged, so Slack is skipped — no re-page on pod restart.
  * **Daily summary** — a deterministic render + `git diff` no-op
    commit; re-running a flush never duplicates.

GitHub and the daily summary need no router-side state — their dedup is
durable, so an *ongoing* incident still re-confirms after the PR-S4
cooldown (the GitHub channel just reports `DUPLICATE`). Slack is the
exception: a webhook has no durable dedup, so the router keeps one
small bounded LRU of Slack-paged signatures. That stops an ongoing
CRITICAL — or one whose GitHub issue could not be filed — from
re-paging every cooldown when GitHub's verdict is unavailable. The LRU
is per-process; a pod restart may re-page a still-active CRITICAL once,
which is acceptable (you want to know live incidents after a restart).

## Rate limiting

The PR-S4 dedup handles the common spam case (one rule re-detecting the
same condition). A `TokenBucket` is the second line of defence against
a *buggy* rule emitting a flood of **distinct** findings: it caps how
many GitHub-issue / Slack writes happen per minute. The daily summary
is never rate-limited — it is a cheap in-memory append, and keeping it
unbounded means a flood is still recorded *somewhere*. CRITICAL
findings bypass an exhausted bucket (fail-open: a missed page is worse
than a burst), but the bypass is logged loudly.
"""

from __future__ import annotations

import logging
import os
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sentinel.analytics.base import Finding, Severity
from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    OutputChannel,
    severity_at_least,
    signature,
)
from sentinel.output.daily_summary import DailySummaryChannel, DailySummaryConfig
from sentinel.output.github_issue import (
    ENV_REPO as ENV_GH_REPO,
)
from sentinel.output.github_issue import (
    GitHubIssueChannel,
    GitHubIssueConfig,
)
from sentinel.output.slack_webhook import SlackWebhookChannel, SlackWebhookConfig

log = logging.getLogger("sentinel.output.router")

ENV_RATE_CAPACITY = "SENTINEL_OUTPUT_RATE_CAPACITY"
ENV_RATE_PER_MIN = "SENTINEL_OUTPUT_RATE_PER_MIN"

# Generous enough that a real incident burst sails through; tight
# enough that a wedged rule cannot open thousands of issues.
DEFAULT_RATE_CAPACITY = 20.0
DEFAULT_RATE_PER_MIN = 10.0

# Bound on the per-process Slack-paged signature LRU. Far above the
# distinct-CRITICAL volume of any real incident window.
_SLACK_PAGED_CAP = 512


class TokenBucket:
    """A small monotonic-clock token bucket.

    Not thread-safe by design — the router is driven from a single
    asyncio task (`sentinel.main`'s output dispatcher). `clock` is an
    injection seam so tests advance time deterministically instead of
    sleeping.
    """

    def __init__(
        self,
        capacity: float,
        refill_per_sec: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity <= 0:
            raise ValueError("token bucket capacity must be positive")
        if refill_per_sec < 0:
            raise ValueError("token bucket refill rate must be non-negative")
        self._capacity = float(capacity)
        self._refill = float(refill_per_sec)
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()

    def _replenish(self) -> None:
        now = self._clock()
        # `max(0.0, …)` guards against a non-monotonic clock injected
        # by a test or a platform quirk.
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill)

    def try_acquire(self, n: float = 1.0) -> bool:
        """Consume `n` tokens; return False (consuming nothing) if short."""

        self._replenish()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False

    @property
    def available(self) -> float:
        self._replenish()
        return self._tokens


@dataclass(frozen=True)
class RoutingResult:
    """Aggregate outcome of routing one finding across all channels."""

    finding: Finding
    results: tuple[ChannelResult, ...]

    @property
    def any_failed(self) -> bool:
        return any(r.status is DispatchStatus.FAILED for r in self.results)

    @property
    def created(self) -> tuple[ChannelResult, ...]:
        return tuple(r for r in self.results if r.status is DispatchStatus.CREATED)


class FindingRouter:
    """Fan one finding out to the channels its severity selects."""

    def __init__(
        self,
        *,
        github: OutputChannel | None = None,
        slack: OutputChannel | None = None,
        daily: OutputChannel | None = None,
        rate_limiter: TokenBucket | None = None,
    ) -> None:
        self._github = github
        self._slack = slack
        self._daily = daily
        self._rate = rate_limiter
        # Bounded LRU of signatures already paged to Slack this process
        # — Slack's only in-router de-dup state (see module docstring).
        self._slack_paged: OrderedDict[str, None] = OrderedDict()

    @property
    def daily(self) -> OutputChannel | None:
        """The daily-summary channel, if configured.

        Exposed so `sentinel.main`'s 09:00-UTC scheduler can call
        `flush()` on the *same* instance the router buffers findings
        into. Returns `None` when no daily summary is wired.
        """

        return self._daily

    def route(self, finding: Finding) -> RoutingResult:
        """Dispatch `finding` to every channel its severity selects.

        Never raises: each channel call is guarded, so one broken
        channel cannot abort the others or the caller (the analytics
        output dispatcher).
        """

        results: list[ChannelResult] = []
        sev = finding.severity

        # 1. Daily summary — every severity, cheap, never rate-limited.
        if self._daily is not None:
            results.append(self._safe_dispatch(self._daily, finding))

        # 2. GitHub issue — ALERT and above.
        github_result: ChannelResult | None = None
        if self._github is not None and severity_at_least(sev, Severity.ALERT):
            github_result = self._gated_dispatch(self._github, finding)
            results.append(github_result)

        # 3. Slack — CRITICAL only, gated on the GitHub idempotency verdict.
        if self._slack is not None and severity_at_least(sev, Severity.CRITICAL):
            results.append(self._route_slack(finding, github_result))

        for r in results:
            log.debug(
                "routed rule=%s sev=%s -> %s: %s (%s)",
                finding.rule_name,
                sev.value,
                r.channel,
                r.status.value,
                r.detail,
            )
        return RoutingResult(finding, tuple(results))

    # -- internals ----------------------------------------------------

    def _route_slack(
        self, finding: Finding, github_result: ChannelResult | None
    ) -> ChannelResult:
        # A GitHub `DUPLICATE` means the incident is already tracked and
        # was already paged on its first occurrence — do not re-page.
        # On GitHub `CREATED` (new incident) or `FAILED`/`SUPPRESSED`
        # (verdict unknown) we still page: fail-open for CRITICAL.
        if (
            github_result is not None
            and github_result.status is DispatchStatus.DUPLICATE
        ):
            return ChannelResult(
                self._slack.name,
                DispatchStatus.SKIPPED,
                "incident already open in GitHub — not re-paging Slack",
            )
        # In-process page ledger: a CRITICAL that re-fires after its
        # PR-S4 cooldown, or one whose GitHub issue could not be filed,
        # must not re-page Slack on every pass. This is the idempotency
        # backstop when GitHub's verdict is unavailable.
        sig = signature(finding)
        if sig in self._slack_paged:
            self._slack_paged.move_to_end(sig)
            return ChannelResult(
                self._slack.name,
                DispatchStatus.SKIPPED,
                "already paged Slack this run for this signature",
            )
        result = self._gated_dispatch(self._slack, finding)
        # Record only a successful page — a FAILED or rate-SUPPRESSED
        # dispatch should be retried on the next pass.
        if result.status is DispatchStatus.CREATED:
            self._slack_paged[sig] = None
            self._slack_paged.move_to_end(sig)
            while len(self._slack_paged) > _SLACK_PAGED_CAP:
                self._slack_paged.popitem(last=False)
        return result

    def _gated_dispatch(
        self, channel: OutputChannel, finding: Finding
    ) -> ChannelResult:
        if self._rate is None or self._rate.try_acquire():
            return self._safe_dispatch(channel, finding)
        # Bucket empty.
        if severity_at_least(finding.severity, Severity.CRITICAL):
            log.error(
                "output rate limiter exhausted — dispatching CRITICAL finding "
                "%s to %s anyway (fail-open)",
                signature(finding),
                channel.name,
            )
            return self._safe_dispatch(channel, finding)
        log.warning(
            "output rate limiter exhausted — suppressing %s dispatch of %s",
            channel.name,
            signature(finding),
        )
        return ChannelResult(
            channel.name,
            DispatchStatus.SUPPRESSED,
            "output rate limit exceeded",
        )

    @staticmethod
    def _safe_dispatch(channel: OutputChannel, finding: Finding) -> ChannelResult:
        # Channels already swallow their own exceptions; this is a
        # belt-and-suspenders guard so a contract violation in one
        # channel cannot break routing.
        try:
            return channel.dispatch(finding)
        except Exception as e:  # noqa: BLE001
            name = getattr(channel, "name", "unknown")
            log.exception("output channel %s raised through dispatch", name)
            return ChannelResult(name, DispatchStatus.FAILED, f"unexpected: {e}")


# ---------------------------------------------------------------------------
# Env-driven construction
# ---------------------------------------------------------------------------


def _read_positive_float(
    src: Mapping[str, str], key: str, default: float
) -> float:
    raw = src.get(key, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        log.warning("%s=%r is not a number; using default %s", key, raw, default)
        return default
    if value <= 0:
        log.warning("%s=%r must be positive; using default %s", key, raw, default)
        return default
    return value


def build_rate_limiter_from_env(env: Mapping[str, str] | None = None) -> TokenBucket:
    """Construct the shared output `TokenBucket` from env."""

    src = env if env is not None else os.environ
    capacity = _read_positive_float(src, ENV_RATE_CAPACITY, DEFAULT_RATE_CAPACITY)
    per_min = _read_positive_float(src, ENV_RATE_PER_MIN, DEFAULT_RATE_PER_MIN)
    return TokenBucket(capacity, per_min / 60.0)


def build_router_from_env(env: Mapping[str, str] | None = None) -> FindingRouter:
    """Build a `FindingRouter` wiring whichever channels env configures.

    A channel is included only when its configuration is present:

      * GitHub  — `SENTINEL_GH_REPO` set.
      * Slack   — `SLACK_WEBHOOK_URL` set.
      * Daily   — `SENTINEL_REPORTS_REPO_DIR` set.

    An unconfigured channel is simply omitted, so a partial deployment
    degrades cleanly instead of emitting a stream of `FAILED` results.
    """

    src = env if env is not None else os.environ

    github: GitHubIssueChannel | None = None
    if src.get(ENV_GH_REPO, "").strip():
        github = GitHubIssueChannel(GitHubIssueConfig.from_env(src))

    slack: SlackWebhookChannel | None = None
    slack_cfg = SlackWebhookConfig.from_env(src)
    if slack_cfg is not None:
        slack = SlackWebhookChannel(slack_cfg)

    daily: DailySummaryChannel | None = None
    daily_cfg = DailySummaryConfig.from_env(src)
    if daily_cfg is not None:
        daily = DailySummaryChannel(daily_cfg)

    if github is None and slack is None and daily is None:
        log.warning(
            "build_router_from_env: no output channel is configured — "
            "findings will be routed nowhere"
        )

    return FindingRouter(
        github=github,
        slack=slack,
        daily=daily,
        rate_limiter=build_rate_limiter_from_env(src),
    )
