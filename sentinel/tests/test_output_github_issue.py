"""Tests for `sentinel.output.github_issue` — the gh-CLI issue channel.

The `gh` binary is never invoked: a `FakeGh` runner stands in for the
subprocess and records every argv it is handed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sentinel.analytics.base import Severity
from sentinel.output.channels import DispatchStatus, signature
from sentinel.output.github_issue import (
    GitHubIssueChannel,
    GitHubIssueConfig,
    GitHubIssueError,
    _GhResult,
)
from tests._analytics_helpers import make_finding


@dataclass
class _Call:
    argv: list[str]
    stdin: str | None


class FakeGh:
    """Scriptable stand-in for the `gh` subprocess runner."""

    def __init__(self) -> None:
        self.calls: list[_Call] = []
        self.open_issues: list[dict[str, int]] = []
        self.list_ok: bool = True
        self.create_ok: bool = True
        self.create_stderr: str = "gh: HTTP 403 (rate limited)"
        self.created_url: str = (
            "https://github.com/thenervelab/hippius-compute/issues/4242"
        )
        self.raise_exc: Exception | None = None

    def __call__(
        self, argv: list[str], *, stdin: str | None, timeout: float
    ) -> _GhResult:
        self.calls.append(_Call(argv=list(argv), stdin=stdin))
        if self.raise_exc is not None:
            raise self.raise_exc
        sub = argv[2] if len(argv) > 2 else ""
        if sub == "list":
            if not self.list_ok:
                return _GhResult(1, "", "gh: issue list failed")
            return _GhResult(0, json.dumps(self.open_issues), "")
        if sub == "create":
            if not self.create_ok:
                return _GhResult(1, "", self.create_stderr)
            return _GhResult(0, f"Creating issue\n{self.created_url}\n", "")
        raise AssertionError(f"unexpected gh argv: {argv}")

    @property
    def list_calls(self) -> list[_Call]:
        return [c for c in self.calls if "list" in c.argv]

    @property
    def create_calls(self) -> list[_Call]:
        return [c for c in self.calls if "create" in c.argv]


def _channel(gh: FakeGh, *, repo: str | None = None) -> GitHubIssueChannel:
    return GitHubIssueChannel(GitHubIssueConfig(repo=repo), runner=gh)


def test_creates_issue_when_none_open() -> None:
    gh = FakeGh()
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.CREATED
    assert "#4242" in result.detail
    assert len(gh.list_calls) == 1
    assert len(gh.create_calls) == 1


def test_duplicate_when_open_issue_exists() -> None:
    gh = FakeGh()
    gh.open_issues = [{"number": 17}]
    result = _channel(gh).dispatch(make_finding(severity=Severity.CRITICAL))
    assert result.status is DispatchStatus.DUPLICATE
    assert "#17" in result.detail
    # Idempotency: an already-open issue means NO create call.
    assert gh.create_calls == []


def test_skips_below_alert_severity() -> None:
    for sev in (Severity.INFO, Severity.WARN):
        gh = FakeGh()
        result = _channel(gh).dispatch(make_finding(severity=sev))
        assert result.status is DispatchStatus.SKIPPED
        assert gh.calls == []  # nothing touched gh at all


def test_create_failure_returns_failed() -> None:
    gh = FakeGh()
    gh.create_ok = False
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.FAILED
    assert "create" in result.detail


def test_list_failure_returns_failed() -> None:
    gh = FakeGh()
    gh.list_ok = False
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.FAILED
    # A failed lookup must NOT fall through to creating an issue.
    assert gh.create_calls == []


def test_runner_exception_returns_failed() -> None:
    gh = FakeGh()
    gh.raise_exc = GitHubIssueError("gh binary not found: 'gh'")
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.FAILED
    assert "not found" in result.detail


def test_unparseable_create_output_returns_failed() -> None:
    gh = FakeGh()
    gh.created_url = "no url here"
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.FAILED


def test_failure_detail_is_redacted() -> None:
    """gh stderr can echo a token-bearing remote URL — scrub it."""

    gh = FakeGh()
    gh.create_ok = False
    gh.create_stderr = (
        "fatal: could not read from "
        "https://x-token:ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@github.com/o/r"
    )
    result = _channel(gh).dispatch(make_finding(severity=Severity.ALERT))
    assert result.status is DispatchStatus.FAILED
    assert "ghp_" not in result.detail
    assert "x-token" not in result.detail


def test_body_embeds_signature_marker() -> None:
    gh = FakeGh()
    finding = make_finding(severity=Severity.ALERT, rule_name="cert_expiry")
    sig = signature(finding)
    _channel(gh).dispatch(finding)
    body = gh.create_calls[0].stdin or ""
    # Signature appears both visibly and as an HTML comment so the
    # open-issue search can always find it.
    assert f"<!-- sentinel-signature: {sig} -->" in body
    assert sig in body


def test_search_query_uses_signature() -> None:
    gh = FakeGh()
    finding = make_finding(severity=Severity.ALERT)
    sig = signature(finding)
    _channel(gh).dispatch(finding)
    list_argv = gh.list_calls[0].argv
    search_idx = list_argv.index("--search")
    search_query = list_argv[search_idx + 1]
    assert sig in search_query
    assert "in:body" in search_query
    assert "state:open" in search_query


def test_body_redacts_secret() -> None:
    gh = FakeGh()
    finding = make_finding(
        severity=Severity.CRITICAL,
        summary="leaked sk-ant-api03-abcdefABCDEF0123456789xyz token",
        details={"aws": "AKIAIOSFODNN7EXAMPLE"},
    )
    _channel(gh).dispatch(finding)
    body = gh.create_calls[0].stdin or ""
    assert "sk-ant-" not in body
    assert "AKIA" not in body
    assert "[REDACTED]" in body


def test_title_is_single_line_and_capped() -> None:
    gh = FakeGh()
    finding = make_finding(
        severity=Severity.ALERT,
        summary="x" * 500 + "\nsecond line that must not survive",
    )
    _channel(gh).dispatch(finding)
    argv = gh.create_calls[0].argv
    title_arg = next(a for a in argv if a.startswith("--title="))
    title = title_arg[len("--title=") :]
    assert "\n" not in title
    assert len(title) <= 240


def test_repo_flag_passed_only_when_configured() -> None:
    gh_with = FakeGh()
    _channel(gh_with, repo="thenervelab/hippius-compute").dispatch(
        make_finding(severity=Severity.ALERT)
    )
    assert any(
        a == "--repo=thenervelab/hippius-compute"
        for a in gh_with.create_calls[0].argv
    )
    assert "--repo" in gh_with.list_calls[0].argv

    gh_without = FakeGh()
    _channel(gh_without, repo=None).dispatch(make_finding(severity=Severity.ALERT))
    assert not any(a.startswith("--repo") for a in gh_without.create_calls[0].argv)
    assert "--repo" not in gh_without.list_calls[0].argv


def test_signature_is_stable_across_redaction() -> None:
    """A secret in the summary must not shift the idempotency key."""

    clean = make_finding(rule_name="replay_attempts", fingerprint="kid:abc")
    dirty = make_finding(
        rule_name="replay_attempts",
        fingerprint="kid:abc",
        summary="sk-ant-api03-abcdefABCDEF0123456789xyz",
    )
    assert signature(clean) == signature(dirty)
