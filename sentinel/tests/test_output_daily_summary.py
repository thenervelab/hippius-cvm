"""Tests for `sentinel.output.daily_summary`.

`render_daily_summary` is exercised as a pure function (the "format
stable" contract). `DailySummaryChannel.flush` is exercised against a
*real* throwaway git repo + bare remote — that is the honest test for
commit / push / idempotency, and CI always has git.
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
from pathlib import Path

import pytest

import sentinel.output.daily_summary as ds
from sentinel.analytics.base import Severity
from sentinel.output.channels import DispatchStatus
from sentinel.output.daily_summary import (
    DailySummaryChannel,
    DailySummaryConfig,
    render_daily_summary,
)
from tests._analytics_helpers import make_finding

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="git binary not available"
)

_BRANCH = "sentinel-reports/main"


def _ts(year: int, month: int, day: int, hour: int = 12) -> int:
    return int(dt.datetime(year, month, day, hour, tzinfo=dt.UTC).timestamp())


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def _init_bare(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    res = _git(["init", "--bare", "-q", "."], cwd=path)
    assert res.returncode == 0, res.stderr
    return path


def _remote_commit_count(bare: Path, branch: str = _BRANCH) -> int:
    res = _git(["rev-list", "--count", branch], cwd=bare)
    if res.returncode != 0:
        return 0
    return int(res.stdout.strip())


def _remote_file(bare: Path, rel: str, branch: str = _BRANCH) -> str:
    res = _git(["show", f"{branch}:{rel}"], cwd=bare)
    assert res.returncode == 0, res.stderr
    return res.stdout


# ===========================================================================
# render_daily_summary — pure, deterministic
# ===========================================================================


def test_render_empty_day() -> None:
    out = render_daily_summary("2026-05-19", [])
    assert "2026-05-19" in out
    assert "No findings recorded" in out


def test_render_is_deterministic_under_shuffle() -> None:
    findings = [
        make_finding(at_unix=_ts(2026, 5, 19, 3), fingerprint="a", rule_name="r1"),
        make_finding(
            at_unix=_ts(2026, 5, 19, 9),
            fingerprint="b",
            rule_name="r2",
            severity=Severity.CRITICAL,
        ),
        make_finding(at_unix=_ts(2026, 5, 19, 6), fingerprint="c", rule_name="r3"),
    ]
    forward = render_daily_summary("2026-05-19", findings)
    reverse = render_daily_summary("2026-05-19", list(reversed(findings)))
    assert forward == reverse


def test_render_severity_breakdown() -> None:
    findings = [
        make_finding(severity=Severity.CRITICAL, fingerprint="x"),
        make_finding(severity=Severity.WARN, fingerprint="y"),
        make_finding(severity=Severity.WARN, fingerprint="z"),
    ]
    out = render_daily_summary("2026-05-19", findings)
    assert "**Findings:** 3 — CRITICAL 1 · ALERT 0 · WARN 2 · INFO 0" in out


def test_render_sorted_chronologically() -> None:
    findings = [
        make_finding(at_unix=_ts(2026, 5, 19, 20), fingerprint="late", summary="LATE"),
        make_finding(
            at_unix=_ts(2026, 5, 19, 2), fingerprint="early", summary="EARLY"
        ),
    ]
    out = render_daily_summary("2026-05-19", findings)
    assert out.index("EARLY") < out.index("LATE")


def test_render_redacts_secret() -> None:
    finding = make_finding(
        summary="exposed AKIAIOSFODNN7EXAMPLE in the wild",
        severity=Severity.ALERT,
    )
    out = render_daily_summary("2026-05-19", [finding])
    assert "AKIA" not in out
    assert "[REDACTED]" in out


def test_render_dropped_note() -> None:
    out = render_daily_summary("2026-05-19", [make_finding()], dropped=12)
    assert "12 finding(s) were dropped" in out


def test_render_signature_matches_github_dedup_key() -> None:
    """The summary's Signature column must equal the GitHub de-dup key."""

    from sentinel.output.channels import signature

    finding = make_finding(rule_name="cert_expiry", fingerprint="stale:/x/y.crt")
    out = render_daily_summary("2026-05-19", [finding])
    assert f"`{signature(finding)}`" in out


# ===========================================================================
# DailySummaryChannel.dispatch — buffering
# ===========================================================================


def test_dispatch_buffers_by_utc_day(tmp_path: Path) -> None:
    channel = DailySummaryChannel(DailySummaryConfig(repo_dir=tmp_path / "repo"))
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 18)))
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 19), fingerprint="b"))
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 19), fingerprint="c"))
    assert channel.buffered_days == ["2026-05-18", "2026-05-19"]


def test_dispatch_buffer_cap_suppresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ds, "_MAX_FINDINGS_PER_DAY", 2)
    channel = DailySummaryChannel(DailySummaryConfig(repo_dir=tmp_path / "repo"))
    day = _ts(2026, 5, 19)
    assert channel.dispatch(make_finding(at_unix=day, fingerprint="1")).status is (
        DispatchStatus.CREATED
    )
    assert channel.dispatch(make_finding(at_unix=day, fingerprint="2")).status is (
        DispatchStatus.CREATED
    )
    third = channel.dispatch(make_finding(at_unix=day, fingerprint="3"))
    assert third.status is DispatchStatus.SUPPRESSED


# ===========================================================================
# DailySummaryChannel.flush — real git
# ===========================================================================


def test_flush_commits_and_pushes(tmp_path: Path) -> None:
    bare = _init_bare(tmp_path / "remote.git")
    cfg = DailySummaryConfig(
        repo_dir=tmp_path / "repo", remote_url=str(bare), branch=_BRANCH
    )
    channel = DailySummaryChannel(cfg)
    channel.dispatch(
        make_finding(at_unix=_ts(2026, 5, 19), summary="something happened")
    )

    result = channel.flush(now_unix=_ts(2026, 5, 20))
    assert result.status is DispatchStatus.CREATED
    assert _remote_commit_count(bare) == 1
    content = _remote_file(bare, "incidents/2026-05-19.md")
    assert "Sentinel incident summary — 2026-05-19" in content
    assert "something happened" in content
    # Buffer cleared after a successful flush.
    assert channel.buffered_days == []


def test_flush_idempotent_rerun_makes_no_duplicate(tmp_path: Path) -> None:
    bare = _init_bare(tmp_path / "remote.git")
    cfg = DailySummaryConfig(
        repo_dir=tmp_path / "repo", remote_url=str(bare), branch=_BRANCH
    )
    finding = make_finding(at_unix=_ts(2026, 5, 19), summary="incident text")

    first = DailySummaryChannel(cfg)
    first.dispatch(finding)
    assert first.flush(now_unix=_ts(2026, 5, 20)).status is DispatchStatus.CREATED

    # A fresh channel (simulating a pod restart) re-buffers the *same*
    # finding and flushes again — must collapse onto the existing commit.
    second = DailySummaryChannel(cfg)
    second.dispatch(finding)
    rerun = second.flush(now_unix=_ts(2026, 5, 20))
    assert rerun.status is DispatchStatus.DUPLICATE
    assert _remote_commit_count(bare) == 1


def test_flush_skips_when_no_complete_day(tmp_path: Path) -> None:
    cfg = DailySummaryConfig(repo_dir=tmp_path / "repo")
    channel = DailySummaryChannel(cfg)
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 20, 8)))
    # "today" is still in progress — nothing to flush yet.
    result = channel.flush(now_unix=_ts(2026, 5, 20, 23))
    assert result.status is DispatchStatus.SKIPPED


def test_flush_local_only_when_no_remote(tmp_path: Path) -> None:
    cfg = DailySummaryConfig(repo_dir=tmp_path / "repo", remote_url=None)
    channel = DailySummaryChannel(cfg)
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 19)))
    result = channel.flush(now_unix=_ts(2026, 5, 20))
    assert result.status is DispatchStatus.CREATED
    # Committed locally on the report branch.
    log = _git(["rev-list", "--count", _BRANCH], cwd=cfg.repo_dir)
    assert log.returncode == 0
    assert int(log.stdout.strip()) == 1


def test_flush_push_failure_keeps_buffer(tmp_path: Path) -> None:
    cfg = DailySummaryConfig(
        repo_dir=tmp_path / "repo",
        remote_url=str(tmp_path / "nonexistent-remote.git"),
        branch=_BRANCH,
    )
    channel = DailySummaryChannel(cfg)
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 19)))
    result = channel.flush(now_unix=_ts(2026, 5, 20))
    assert result.status is DispatchStatus.FAILED
    # Buffer is retained so the next flush retries.
    assert channel.buffered_days == ["2026-05-19"]


def test_flush_writes_one_file_per_complete_day(tmp_path: Path) -> None:
    bare = _init_bare(tmp_path / "remote.git")
    cfg = DailySummaryConfig(
        repo_dir=tmp_path / "repo", remote_url=str(bare), branch=_BRANCH
    )
    channel = DailySummaryChannel(cfg)
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 17), fingerprint="a"))
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 18), fingerprint="b"))
    result = channel.flush(now_unix=_ts(2026, 5, 19))
    assert result.status is DispatchStatus.CREATED
    assert "Sentinel" in _remote_file(bare, "incidents/2026-05-17.md")
    assert "Sentinel" in _remote_file(bare, "incidents/2026-05-18.md")


def test_report_branch_first_commit_is_a_root(tmp_path: Path) -> None:
    """The report branch is an orphan — its history never touches main."""

    bare = _init_bare(tmp_path / "remote.git")
    cfg = DailySummaryConfig(
        repo_dir=tmp_path / "repo", remote_url=str(bare), branch=_BRANCH
    )
    channel = DailySummaryChannel(cfg)
    channel.dispatch(make_finding(at_unix=_ts(2026, 5, 19)))
    channel.flush(now_unix=_ts(2026, 5, 20))
    # A root commit (no parents) — proof the branch shares no ancestry.
    roots = _git(["rev-list", "--max-parents=0", _BRANCH], cwd=bare)
    assert roots.returncode == 0
    assert len(roots.stdout.split()) == 1
