"""Tests for `sentinel.output.router` — severity routing + rate limiting."""

from __future__ import annotations

import pytest

from sentinel.analytics.base import Severity
from sentinel.output.channels import ChannelResult, DispatchStatus
from sentinel.output.daily_summary import DailySummaryChannel
from sentinel.output.github_issue import GitHubIssueChannel
from sentinel.output.router import (
    FindingRouter,
    TokenBucket,
    build_router_from_env,
)
from sentinel.output.slack_webhook import SlackWebhookChannel
from tests._analytics_helpers import make_finding


class FakeChannel:
    """Records every finding handed to it; returns a scripted status."""

    def __init__(
        self,
        name: str,
        status: DispatchStatus = DispatchStatus.CREATED,
        *,
        raise_exc: Exception | None = None,
    ) -> None:
        self.name = name
        self.status = status
        self.raise_exc = raise_exc
        self.calls: list = []

    def dispatch(self, finding) -> ChannelResult:
        self.calls.append(finding)
        if self.raise_exc is not None:
            raise self.raise_exc
        return ChannelResult(self.name, self.status, "fake-detail")


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# ===========================================================================
# Severity routing
# ===========================================================================


def test_info_and_warn_route_only_to_daily() -> None:
    for sev in (Severity.INFO, Severity.WARN):
        github, slack, daily = (
            FakeChannel("github-issue"),
            FakeChannel("slack-webhook"),
            FakeChannel("daily-summary"),
        )
        router = FindingRouter(github=github, slack=slack, daily=daily)
        router.route(make_finding(severity=sev))
        assert len(daily.calls) == 1
        assert github.calls == []
        assert slack.calls == []


def test_alert_routes_to_github_and_daily_not_slack() -> None:
    github, slack, daily = (
        FakeChannel("github-issue"),
        FakeChannel("slack-webhook"),
        FakeChannel("daily-summary"),
    )
    router = FindingRouter(github=github, slack=slack, daily=daily)
    router.route(make_finding(severity=Severity.ALERT))
    assert len(github.calls) == 1
    assert len(daily.calls) == 1
    assert slack.calls == []


def test_critical_routes_to_all_three() -> None:
    github, slack, daily = (
        FakeChannel("github-issue"),
        FakeChannel("slack-webhook"),
        FakeChannel("daily-summary"),
    )
    router = FindingRouter(github=github, slack=slack, daily=daily)
    router.route(make_finding(severity=Severity.CRITICAL))
    assert len(github.calls) == 1
    assert len(slack.calls) == 1
    assert len(daily.calls) == 1


# ===========================================================================
# Slack gate on GitHub idempotency verdict
# ===========================================================================


def test_slack_skipped_when_github_reports_duplicate() -> None:
    github = FakeChannel("github-issue", DispatchStatus.DUPLICATE)
    slack = FakeChannel("slack-webhook")
    router = FindingRouter(github=github, slack=slack, daily=FakeChannel("daily"))
    result = router.route(make_finding(severity=Severity.CRITICAL))
    # GitHub already tracks the incident — no re-page.
    assert slack.calls == []
    slack_result = next(r for r in result.results if r.channel == "slack-webhook")
    assert slack_result.status is DispatchStatus.SKIPPED


def test_slack_paged_when_github_created() -> None:
    github = FakeChannel("github-issue", DispatchStatus.CREATED)
    slack = FakeChannel("slack-webhook")
    router = FindingRouter(github=github, slack=slack, daily=FakeChannel("daily"))
    router.route(make_finding(severity=Severity.CRITICAL))
    assert len(slack.calls) == 1


def test_slack_paged_when_github_failed_fail_open() -> None:
    """A missed CRITICAL page is worse than a rare duplicate one."""

    github = FakeChannel("github-issue", DispatchStatus.FAILED)
    slack = FakeChannel("slack-webhook")
    router = FindingRouter(github=github, slack=slack, daily=FakeChannel("daily"))
    router.route(make_finding(severity=Severity.CRITICAL))
    assert len(slack.calls) == 1


def test_slack_not_re_paged_for_same_signature_within_process() -> None:
    """A re-fired CRITICAL must not re-page Slack — even with GitHub down."""

    # GitHub FAILED → verdict unavailable, so the GitHub-DUPLICATE gate
    # cannot help; the router's Slack-paged LRU is what suppresses the
    # second page.
    github = FakeChannel("github-issue", DispatchStatus.FAILED)
    slack = FakeChannel("slack-webhook")
    router = FindingRouter(github=github, slack=slack, daily=FakeChannel("daily"))
    finding = make_finding(severity=Severity.CRITICAL, fingerprint="ongoing")

    router.route(finding)
    second = router.route(finding)

    assert len(slack.calls) == 1  # paged exactly once
    slack_result = next(r for r in second.results if r.channel == "slack-webhook")
    assert slack_result.status is DispatchStatus.SKIPPED


def test_slack_re_paged_for_distinct_signatures() -> None:
    """Distinct CRITICAL incidents each page — the LRU keys on signature."""

    slack = FakeChannel("slack-webhook")
    router = FindingRouter(slack=slack, daily=FakeChannel("daily"))
    router.route(make_finding(severity=Severity.CRITICAL, fingerprint="a"))
    router.route(make_finding(severity=Severity.CRITICAL, fingerprint="b"))
    assert len(slack.calls) == 2


# ===========================================================================
# Rate limiting
# ===========================================================================


def test_rate_limiter_suppresses_alert_github() -> None:
    github, daily = FakeChannel("github-issue"), FakeChannel("daily-summary")
    bucket = TokenBucket(capacity=1, refill_per_sec=0.0, clock=FakeClock())
    router = FindingRouter(github=github, daily=daily, rate_limiter=bucket)

    first = router.route(make_finding(severity=Severity.ALERT, fingerprint="a"))
    second = router.route(make_finding(severity=Severity.ALERT, fingerprint="b"))

    assert len(github.calls) == 1  # second was suppressed before dispatch
    gh_second = next(r for r in second.results if r.channel == "github-issue")
    assert gh_second.status is DispatchStatus.SUPPRESSED
    gh_first = next(r for r in first.results if r.channel == "github-issue")
    assert gh_first.status is DispatchStatus.CREATED


def test_daily_summary_is_never_rate_limited() -> None:
    github, daily = FakeChannel("github-issue"), FakeChannel("daily-summary")
    bucket = TokenBucket(capacity=1, refill_per_sec=0.0, clock=FakeClock())
    router = FindingRouter(github=github, daily=daily, rate_limiter=bucket)
    for i in range(3):
        router.route(make_finding(severity=Severity.ALERT, fingerprint=f"f{i}"))
    # GitHub capped at the single token; the daily summary recorded all.
    assert len(github.calls) == 1
    assert len(daily.calls) == 3


def test_critical_bypasses_exhausted_rate_limiter() -> None:
    github, slack, daily = (
        FakeChannel("github-issue"),
        FakeChannel("slack-webhook"),
        FakeChannel("daily-summary"),
    )
    bucket = TokenBucket(capacity=1, refill_per_sec=0.0, clock=FakeClock())
    router = FindingRouter(
        github=github, slack=slack, daily=daily, rate_limiter=bucket
    )
    # Drain the single token with an ALERT.
    router.route(make_finding(severity=Severity.ALERT, fingerprint="drain"))
    # The CRITICAL must still reach BOTH external channels (fail-open).
    router.route(make_finding(severity=Severity.CRITICAL, fingerprint="crit"))
    assert any(f.fingerprint == "crit" for f in github.calls)
    assert any(f.fingerprint == "crit" for f in slack.calls)


# ===========================================================================
# Robustness
# ===========================================================================


def test_router_survives_a_raising_channel() -> None:
    github = FakeChannel("github-issue", raise_exc=RuntimeError("channel boom"))
    daily = FakeChannel("daily-summary")
    router = FindingRouter(github=github, daily=daily)
    result = router.route(make_finding(severity=Severity.ALERT))
    # Daily still ran; the broken channel surfaced as FAILED, not a crash.
    assert len(daily.calls) == 1
    gh_result = next(r for r in result.results if r.channel == "github-issue")
    assert gh_result.status is DispatchStatus.FAILED


def test_route_with_no_channels_is_a_noop() -> None:
    router = FindingRouter()
    result = router.route(make_finding(severity=Severity.CRITICAL))
    assert result.results == ()
    assert not result.any_failed


# ===========================================================================
# TokenBucket
# ===========================================================================


def test_token_bucket_drains_and_refills() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_sec=1.0, clock=clock)
    assert bucket.try_acquire()
    assert bucket.try_acquire()
    assert not bucket.try_acquire()  # drained
    clock.t += 1.0
    assert bucket.try_acquire()  # one token refilled
    assert not bucket.try_acquire()


def test_token_bucket_caps_at_capacity() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_sec=10.0, clock=clock)
    clock.t += 100.0  # would refill 1000 tokens unbounded
    assert bucket.available == pytest.approx(2.0)


def test_token_bucket_rejects_bad_args() -> None:
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_sec=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1.0, refill_per_sec=-1.0)


# ===========================================================================
# build_router_from_env
# ===========================================================================


def test_build_router_selects_only_configured_channels() -> None:
    router = build_router_from_env({"SENTINEL_GH_REPO": "thenervelab/hippius-compute"})
    assert isinstance(router._github, GitHubIssueChannel)
    assert router._slack is None
    assert router.daily is None


def test_build_router_wires_slack_and_daily(tmp_path) -> None:
    env = {
        "SENTINEL_GH_REPO": "thenervelab/hippius-compute",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T0/B0/secrettoken",
        "SENTINEL_REPORTS_REPO_DIR": str(tmp_path / "reports"),
    }
    router = build_router_from_env(env)
    assert isinstance(router._github, GitHubIssueChannel)
    assert isinstance(router._slack, SlackWebhookChannel)
    assert isinstance(router.daily, DailySummaryChannel)


def test_build_router_empty_env_has_no_channels() -> None:
    router = build_router_from_env({})
    assert router._github is None
    assert router._slack is None
    assert router.daily is None
