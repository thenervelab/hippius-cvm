"""Daily incident-summary output channel (PR-S5).

Every finding — at any severity — is buffered here, bucketed by its
UTC day. Once a day is complete the channel renders a Markdown
`incidents/YYYY-MM-DD.md`, commits it onto a dedicated git branch
(`sentinel-reports/main`, default) and pushes it. The production loop
calls `flush()` once a day at 09:00 UTC; by then "yesterday" is a
complete day and gets written.

## Why a separate branch

The summaries are an operational artefact, not source code — committing
them onto `main` would churn its history. `sentinel-reports/main` is an
*orphan* branch (no shared history with `main`): it holds only
`incidents/*.md`, so the report stream never collides with development.

## Dedicated working directory

`repo_dir` MUST be a directory the sentinel owns exclusively — the
channel checks out, force-creates and hard-resets the report branch
inside it. In the pod that is an `emptyDir`; the channel `git init`s it
on first flush and pushes to `remote_url`. Pointing `repo_dir` at a
real dev checkout would be destructive, hence the loud contract.

## Idempotency

`render_daily_summary` is a pure, deterministic function: the same
findings (in any order) yield byte-identical Markdown. Each flush
`git add`s the rendered files and commits *only if something changed*
(`git diff --cached --quiet`). Re-running a flush for an already-written
day therefore produces no new commit — the §S "rerun = no duplicate"
invariant. `push` runs every flush regardless, so a commit that was
made but not pushed (e.g. a previous network failure) still reaches the
remote on the next pass; pushing an already-synced branch is a no-op.

## Secret hygiene

Raw findings are buffered (as the analytics loop's own `RecentFindings`
ring already does — in-process memory is inside the trust boundary).
`render_daily_summary` redacts every field it writes, so no secret ever
reaches a committed file; it also derives each row's idempotency
signature from the *raw* `(rule, fingerprint)` so those signatures
still match the GitHub-issue de-dup key.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinel.analytics.base import Finding, Severity
from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    iso_utc,
    md_table_cell,
    signature,
    utc_day,
)
from sentinel.output.redact import redact_finding, redact_text

log = logging.getLogger("sentinel.output.daily_summary")

CHANNEL_NAME = "daily-summary"

ENV_REPO_DIR = "SENTINEL_REPORTS_REPO_DIR"
ENV_REMOTE_URL = "SENTINEL_REPORTS_REMOTE_URL"
ENV_BRANCH = "SENTINEL_REPORTS_BRANCH"
ENV_AUTHOR_NAME = "SENTINEL_REPORTS_AUTHOR_NAME"
ENV_AUTHOR_EMAIL = "SENTINEL_REPORTS_AUTHOR_EMAIL"

DEFAULT_BRANCH = "sentinel-reports/main"
DEFAULT_AUTHOR_NAME = "hippius-sentinel"
DEFAULT_AUTHOR_EMAIL = "sentinel@hippius-compute.local"
DEFAULT_GIT_TIMEOUT_S = 60.0

INCIDENTS_DIR = "incidents"

# Defensive bounds so a runaway rule cannot exhaust memory between
# flushes. A real day stays far below these.
_MAX_FINDINGS_PER_DAY = 5000
_MAX_DAYS_BUFFERED = 31

# Markdown rendering caps.
_MAX_SUMMARY_CELL = 160

# Severity ordering for deterministic, highest-first sorting within a
# day. Index into this tuple is the rank.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.WARN,
    Severity.ALERT,
    Severity.CRITICAL,
)


class GitError(RuntimeError):
    """Raised when a git invocation fails or git is unavailable."""


@dataclass(frozen=True)
class _GitResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class DailySummaryConfig:
    """Resolved config for the daily-summary channel.

    `from_env` returns `None` when `SENTINEL_REPORTS_REPO_DIR` is unset
    — the supported "daily summary disabled" state. When `remote_url`
    is `None` the channel still commits locally but never pushes
    (useful for air-gapped runs and tests).
    """

    repo_dir: Path
    remote_url: str | None = None
    branch: str = DEFAULT_BRANCH
    author_name: str = DEFAULT_AUTHOR_NAME
    author_email: str = DEFAULT_AUTHOR_EMAIL
    git_timeout_s: float = DEFAULT_GIT_TIMEOUT_S

    @property
    def push_enabled(self) -> bool:
        return self.remote_url is not None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> DailySummaryConfig | None:
        src = env if env is not None else os.environ
        repo_dir = src.get(ENV_REPO_DIR, "").strip()
        if not repo_dir:
            return None
        return cls(
            repo_dir=Path(repo_dir),
            remote_url=src.get(ENV_REMOTE_URL, "").strip() or None,
            branch=src.get(ENV_BRANCH, "").strip() or DEFAULT_BRANCH,
            author_name=src.get(ENV_AUTHOR_NAME, "").strip() or DEFAULT_AUTHOR_NAME,
            author_email=src.get(ENV_AUTHOR_EMAIL, "").strip() or DEFAULT_AUTHOR_EMAIL,
        )


class DailySummaryChannel:
    """Buffers findings and flushes one Markdown file per complete UTC day."""

    name = CHANNEL_NAME

    def __init__(
        self,
        config: DailySummaryConfig,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._config = config
        # `clock` is an injection seam for tests; production uses wall
        # time. It only feeds the "is this finding's day complete yet"
        # decision — `flush` takes an explicit `now_unix` of its own.
        self._clock = clock or (lambda: int(time.time()))
        self._buffer: dict[str, list[Finding]] = {}
        self._dropped: dict[str, int] = {}
        # `dispatch` (output-dispatcher thread) and `flush` (daily-summary
        # scheduler thread) run on separate `asyncio.to_thread` workers,
        # so every read/write of `_buffer`/`_dropped` is guarded. The
        # lock is only ever held for fast dict ops — never across git I/O.
        self._lock = threading.Lock()

    # -- dispatch (buffering) -----------------------------------------

    def dispatch(self, finding: Finding) -> ChannelResult:
        """Buffer `finding` under its UTC day. Never raises, never blocks."""

        try:
            at = finding.at_unix if finding.at_unix > 0 else self._clock()
            day = utc_day(at)
            with self._lock:
                if (
                    len(self._buffer) >= _MAX_DAYS_BUFFERED
                    and day not in self._buffer
                ):
                    # Flush is not running; shed the oldest buffered day
                    # so memory stays bounded rather than growing forever.
                    oldest = min(self._buffer)
                    evicted = len(self._buffer.pop(oldest))
                    self._dropped.pop(oldest, None)
                    log.warning(
                        "daily summary: evicted unflushed day %s (%d findings) "
                        "— is flush() running?",
                        oldest,
                        evicted,
                    )
                bucket = self._buffer.setdefault(day, [])
                if len(bucket) >= _MAX_FINDINGS_PER_DAY:
                    self._dropped[day] = self._dropped.get(day, 0) + 1
                    return ChannelResult(
                        self.name,
                        DispatchStatus.SUPPRESSED,
                        f"daily buffer for {day} at cap ({_MAX_FINDINGS_PER_DAY})",
                    )
                # The raw finding is buffered; `render_daily_summary`
                # redacts at write time and derives each row's signature
                # from the raw `(rule, fingerprint)` pair.
                bucket.append(finding)
            return ChannelResult(
                self.name, DispatchStatus.CREATED, f"buffered for {day}"
            )
        except Exception as e:  # noqa: BLE001 — a channel must never crash the router
            log.exception("daily summary buffering failed")
            return ChannelResult(
                self.name, DispatchStatus.FAILED, redact_text(f"unexpected: {e}")
            )

    @property
    def buffered_days(self) -> list[str]:
        with self._lock:
            return sorted(self._buffer)

    # -- flush (render + git) -----------------------------------------

    def flush(self, *, now_unix: int | None = None) -> ChannelResult:
        """Render every *complete* buffered day, commit and push.

        A day is "complete" once its UTC date is strictly before the
        UTC date of `now_unix`. The in-progress current day stays
        buffered. Never raises — git failure surfaces as `FAILED` and
        the buffer is kept so the next flush retries.
        """

        now = now_unix if now_unix is not None else int(time.time())
        today = utc_day(now)

        # Snapshot the complete days under the lock: a concurrent
        # `dispatch` must not mutate `_buffer` mid-iteration, and the
        # findings we are about to render must not be lost. Rendering +
        # git run OUTSIDE the lock — git I/O is slow and `dispatch` has
        # to stay responsive.
        with self._lock:
            complete_days = sorted(d for d in self._buffer if d < today)
            snapshot = {d: list(self._buffer[d]) for d in complete_days}
            dropped = {d: self._dropped.get(d, 0) for d in complete_days}
        if not complete_days:
            return ChannelResult(
                self.name, DispatchStatus.SKIPPED, "no complete day to flush"
            )

        try:
            self._ensure_repo()
            for day in complete_days:
                self._write_day(day, snapshot[day], dropped[day])
            self._git(["add", "--", INCIDENTS_DIR])
            created = not self._index_is_clean()
            if created:
                self._commit(complete_days)
            if self._config.push_enabled:
                # Run every flush: this also ships a commit that an
                # earlier flush made but failed to push.
                self._push()
        except GitError as e:
            detail = redact_text(str(e))
            log.warning("daily summary flush failed: %s", detail)
            return ChannelResult(self.name, DispatchStatus.FAILED, detail)
        except Exception as e:  # noqa: BLE001 — never crash the caller
            log.exception("daily summary flush: unexpected failure")
            return ChannelResult(
                self.name, DispatchStatus.FAILED, redact_text(f"unexpected: {e}")
            )

        # Success: drop exactly the findings we flushed, keeping anything
        # `dispatch` appended to those days while git was running.
        with self._lock:
            for day in complete_days:
                rest = self._buffer.get(day, [])[len(snapshot[day]) :]
                if rest:
                    self._buffer[day] = rest
                else:
                    self._buffer.pop(day, None)
                self._dropped.pop(day, None)

        span = complete_days[0]
        if len(complete_days) > 1:
            span = f"{complete_days[0]}..{complete_days[-1]}"
        if created:
            log.info("daily summary committed: %s", span)
            return ChannelResult(
                self.name,
                DispatchStatus.CREATED,
                f"committed {len(complete_days)} day(s): {span}",
            )
        return ChannelResult(
            self.name,
            DispatchStatus.DUPLICATE,
            f"{span}: already committed (no change)",
        )

    # -- internals: rendering -----------------------------------------

    def _write_day(
        self, day: str, findings: Sequence[Finding], dropped: int
    ) -> None:
        content = render_daily_summary(day, findings, dropped=dropped)
        path = self._config.repo_dir / INCIDENTS_DIR / f"{day}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # -- internals: git -----------------------------------------------

    def _git(self, args: list[str], *, check: bool = True) -> _GitResult:
        res = _run_git(
            args, cwd=self._config.repo_dir, timeout=self._config.git_timeout_s
        )
        if check and res.returncode != 0:
            raise GitError(
                f"git {args[0]} failed (exit {res.returncode}): {_tail(res.stderr)}"
            )
        return res

    def _ref_exists(self, ref: str) -> bool:
        return (
            self._git(["rev-parse", "--verify", "--quiet", ref], check=False).returncode
            == 0
        )

    def _ensure_repo(self) -> None:
        cfg = self._config
        cfg.repo_dir.mkdir(parents=True, exist_ok=True)
        if not (cfg.repo_dir / ".git").exists():
            self._git(["init", "-q"])
        if cfg.remote_url is not None:
            self._ensure_remote(cfg.remote_url)
        self._sync_branch()

    def _ensure_remote(self, url: str) -> None:
        res = self._git(["remote", "get-url", "origin"], check=False)
        if res.returncode != 0:
            self._git(["remote", "add", "origin", url])
        elif res.stdout.strip() != url:
            self._git(["remote", "set-url", "origin", url])

    def _sync_branch(self) -> None:
        """Put `repo_dir` on the report branch, aligned with the remote."""

        branch = self._config.branch
        if self._config.remote_url is not None:
            # Best-effort: an unreachable remote or a not-yet-created
            # branch must not block a local commit.
            self._git(["fetch", "--quiet", "origin", branch], check=False)
        if self._ref_exists(f"refs/remotes/origin/{branch}"):
            self._git(["checkout", "-q", "-B", branch, f"origin/{branch}"])
            self._git(["reset", "--hard", "-q", f"origin/{branch}"])
            return
        if self._ref_exists(f"refs/heads/{branch}"):
            self._git(["checkout", "-q", branch])
            return
        # Brand-new report branch: an orphan so it shares no history
        # with main. The dir was just `git init`-ed (empty worktree) or
        # only ever held `incidents/`, so no destructive clean is run.
        res = self._git(["checkout", "-q", "--orphan", branch], check=False)
        if res.returncode != 0:
            current = self._git(["branch", "--show-current"], check=False)
            if current.stdout.strip() != branch:
                raise GitError(
                    f"could not create orphan branch {branch}: {_tail(res.stderr)}"
                )
        # Drop anything an inherited branch may have left staged.
        self._git(["reset", "-q"], check=False)

    def _index_is_clean(self) -> bool:
        # `git diff --cached --quiet` exits 0 when nothing is staged.
        return (
            self._git(
                ["diff", "--cached", "--quiet", "--", INCIDENTS_DIR], check=False
            ).returncode
            == 0
        )

    def _commit(self, days: Sequence[str]) -> None:
        span = days[0] if len(days) == 1 else f"{days[0]}..{days[-1]}"
        message = f"chore(sentinel-reports): daily incident summary {span}"
        self._git(
            [
                "-c",
                f"user.name={self._config.author_name}",
                "-c",
                f"user.email={self._config.author_email}",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "-m",
                message,
            ]
        )

    def _push(self) -> None:
        branch = self._config.branch
        res = self._git(
            ["push", "--quiet", "origin", f"HEAD:refs/heads/{branch}"], check=False
        )
        if res.returncode != 0:
            # Buffer is kept (exception aborts flush before _clear_days);
            # the next flush re-syncs and retries.
            raise GitError(f"git push failed (exit {res.returncode}): {_tail(res.stderr)}")


# ---------------------------------------------------------------------------
# git subprocess wrapper
# ---------------------------------------------------------------------------


def _run_git(args: list[str], *, cwd: Path, timeout: float) -> _GitResult:
    """Run `git <args>` in `cwd` with no shell. Raises `GitError` on setup faults."""

    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell, fixed binary
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise GitError("git binary not found") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git timed out after {timeout:.0f}s: git {args[0]}") from e
    return _GitResult(proc.returncode, proc.stdout or "", proc.stderr or "")


def _tail(text: str, limit: int = 400) -> str:
    """Single-lined, redacted tail of `text` for safe error reporting.

    git stderr can echo a credential-bearing remote URL
    (`https://x-token:SECRET@host/...`); `redact_text`'s userinfo rule
    scrubs it before it reaches a `GitError` message or a log line.
    """

    flat = redact_text(" ".join((text or "").split()))
    return flat[-limit:]


# ---------------------------------------------------------------------------
# Rendering (pure + deterministic — the "format stable" contract)
# ---------------------------------------------------------------------------


def _severity_rank(severity: Severity) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


def _sort_key(finding: Finding) -> tuple[int, int, str, str]:
    # Chronological, then highest-severity-first as a tiebreak, then
    # stable on rule + fingerprint so ordering is fully deterministic
    # and independent of buffer insertion order.
    return (
        finding.at_unix,
        -_severity_rank(finding.severity),
        finding.rule_name,
        finding.fingerprint,
    )


def render_daily_summary(
    day: str, findings: Sequence[Finding], *, dropped: int = 0
) -> str:
    """Render the Markdown incident summary for one UTC day.

    Pure and deterministic: the same `(day, findings, dropped)` — with
    `findings` in *any* order — always produces byte-identical output.
    No wall-clock or environment input.

    `findings` are the *raw* findings: this function sorts them
    deterministically, derives each row's signature from the raw
    `(rule, fingerprint)`, and redacts every rendered field — so a
    direct caller cannot leak a secret and the signatures still match
    the GitHub-issue de-dup key.
    """

    ordered = sorted(findings, key=_sort_key)

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in ordered:
        if f.severity in counts:
            counts[f.severity] += 1

    lines: list[str] = [
        f"# Sentinel incident summary — {day}",
        "",
        "_Generated by hippius-sentinel (§S PR-S5). Read-only observability agent._",
        "",
    ]

    if dropped > 0:
        lines += [
            f"> ⚠️ {dropped} finding(s) were dropped before reaching this report "
            f"— the daily buffer cap ({_MAX_FINDINGS_PER_DAY}) was hit.",
            "",
        ]

    breakdown = " · ".join(
        f"{sev.value} {counts[sev]}" for sev in reversed(_SEVERITY_ORDER)
    )
    lines.append(f"**Findings:** {len(ordered)} — {breakdown}")
    lines.append("")

    if not ordered:
        lines.append("_No findings recorded for this day._")
        return "\n".join(lines) + "\n"

    lines += [
        "| Time (UTC) | Severity | Rule | Summary | Signature |",
        "| --- | --- | --- | --- | --- |",
    ]
    for raw in ordered:
        # Signature from the raw finding; every rendered field redacted.
        sig = signature(raw)
        f = redact_finding(raw)
        summary = " ".join(f.summary.split()) or "(no summary)"
        row = (
            f"| {iso_utc(f.at_unix)} "
            f"| {f.severity.value} "
            f"| `{md_table_cell(f.rule_name, max_len=_MAX_SUMMARY_CELL)}` "
            f"| {md_table_cell(summary, max_len=_MAX_SUMMARY_CELL)} "
            f"| `{sig}` |"
        )
        lines.append(row)

    return "\n".join(lines) + "\n"
