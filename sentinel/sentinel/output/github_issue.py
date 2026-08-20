"""GitHub issue output channel (PR-S5).

Files a structured GitHub issue for any finding at `ALERT` severity or
above, driving the `gh` CLI via `subprocess` rather than the REST API
(the pod already carries a `gh` auth token for the post-merge tracking
script; reusing it keeps the credential surface to one).

## Idempotency — the §S "create 2x the same issue = bug" invariant

Each finding has a stable `signature()` derived from
`(rule_name, fingerprint)`. Before creating an issue the channel runs
`gh issue list --state open --search "<signature> in:body"`; if an open
issue already carries the signature, the channel reports `DUPLICATE`
and does nothing.

Two layers make this robust against re-runs:

  1. **In-process** — the PR-S4 analytics loop dedups identical
     `(rule, fingerprint)` findings for `cooldown_seconds` (≥ 300s for
     every rule, 900s for `audit_chain_break`). A finding therefore
     cannot re-reach this channel inside that window at all.
  2. **Cross-restart** — when the pod restarts the in-process dedup
     LRU is lost, so the same finding *can* be re-emitted. By then far
     more than GitHub's search-index latency (seconds) has elapsed, so
     the open-issue search reliably finds the prior issue.

The signature is embedded both visibly and as an HTML comment in the
issue body so the search term is always present in the raw markdown
GitHub indexes.

## Why a body marker, not one label per signature

`gh issue create --label X` requires `X` to already exist, and minting
one GitHub label per `(rule, fingerprint)` would balloon the repo's
label namespace (the PR-S4 dedup index alone is sized for 1024 unique
fingerprints). A body marker needs no repo-global mutable state and is
just as searchable.

## No-secret posture

Title and body are rendered exclusively from `Finding` fields, and the
finding is passed through `redact_finding` first. Operational ids
(`vm_id`, `ticket_id`, node ids) are *not* secrets and are kept — that
matches the locked §S posture (issue #57). `gh` stderr is truncated
before it reaches a log line; the `gh` auth token never appears in any
argv we build.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sentinel.analytics.base import Finding, Severity
from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    iso_utc,
    md_table_cell,
    severity_at_least,
    signature,
)
from sentinel.output.redact import redact_finding, redact_text

log = logging.getLogger("sentinel.output.github_issue")

CHANNEL_NAME = "github-issue"

ENV_REPO = "SENTINEL_GH_REPO"
ENV_GH_BINARY = "SENTINEL_GH_BINARY"

DEFAULT_GH_BINARY = "gh"
DEFAULT_TIMEOUT_S = 30.0

# Only ALERT and CRITICAL findings open a GitHub issue. The router
# enforces this; the channel re-checks so a direct caller cannot file
# an INFO/WARN issue by accident.
MIN_SEVERITY = Severity.ALERT

# Defensive caps so a misbehaving rule cannot bloat an issue or a log.
_MAX_TITLE_LEN = 240          # GitHub's hard limit is 256.
_MAX_DETAIL_ROWS = 50
_MAX_DETAIL_VALUE_LEN = 500
_STDERR_TAIL = 400

_ISSUE_URL_RE = re.compile(r"https://github\.com/[^\s]+/issues/(\d+)")


class GitHubIssueError(RuntimeError):
    """Raised when a `gh` invocation fails or returns something unparseable."""


@dataclass(frozen=True)
class _GhResult:
    returncode: int
    stdout: str
    stderr: str


class GhRunner(Protocol):
    """Injection seam for the `gh` subprocess — mocked in tests."""

    def __call__(
        self, argv: list[str], *, stdin: str | None, timeout: float
    ) -> _GhResult: ...


def _subprocess_gh_runner(
    argv: list[str], *, stdin: str | None, timeout: float
) -> _GhResult:
    """Production `GhRunner` — a thin, no-shell `subprocess.run` wrapper.

    `argv` is passed as a list (never a shell string) so finding text
    can never be interpreted as a shell metacharacter.
    """

    try:
        proc = subprocess.run(  # noqa: S603 — argv list, no shell, fixed binary
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise GitHubIssueError(f"gh binary not found: {argv[0]!r}") from e
    except subprocess.TimeoutExpired as e:
        raise GitHubIssueError(f"gh timed out after {timeout:.0f}s") from e
    return _GhResult(proc.returncode, proc.stdout or "", proc.stderr or "")


@dataclass(frozen=True)
class GitHubIssueConfig:
    """Resolved config for the GitHub issue channel.

    `repo` is `owner/name`; when `None`, `gh` infers the repo from the
    current directory's git remote. In the sentinel pod there is no
    checkout, so `SENTINEL_GH_REPO` should always be set in production.
    """

    repo: str | None = None
    gh_binary: str = DEFAULT_GH_BINARY
    timeout_s: float = DEFAULT_TIMEOUT_S

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> GitHubIssueConfig:
        src = env if env is not None else os.environ
        repo = src.get(ENV_REPO, "").strip() or None
        gh_binary = src.get(ENV_GH_BINARY, "").strip() or DEFAULT_GH_BINARY
        return cls(repo=repo, gh_binary=gh_binary)


class GitHubIssueChannel:
    """Idempotent GitHub-issue filer for ALERT+ findings."""

    name = CHANNEL_NAME

    def __init__(
        self, config: GitHubIssueConfig, *, runner: GhRunner | None = None
    ) -> None:
        self._config = config
        self._runner = runner or _subprocess_gh_runner

    def dispatch(self, finding: Finding) -> ChannelResult:
        """File (or de-dup) a GitHub issue for `finding`. Never raises."""

        try:
            if not severity_at_least(finding.severity, MIN_SEVERITY):
                return ChannelResult(
                    self.name,
                    DispatchStatus.SKIPPED,
                    f"severity {finding.severity.value} below {MIN_SEVERITY.value}",
                )
            # Signature from the RAW finding — `redact_finding` scrubs
            # the fingerprint for display, which would shift the key.
            sig = signature(finding)
            safe = redact_finding(finding)
            existing = self._find_open_issue(sig)
            if existing is not None:
                return ChannelResult(
                    self.name,
                    DispatchStatus.DUPLICATE,
                    f"issue #{existing} already open for signature {sig}",
                )
            number, url = self._create_issue(safe, sig)
            log.info(
                "github issue filed: #%d rule=%s severity=%s sig=%s",
                number,
                safe.rule_name,
                safe.severity.value,
                sig,
            )
            return ChannelResult(
                self.name, DispatchStatus.CREATED, f"issue #{number}: {url}"
            )
        except GitHubIssueError as e:
            detail = redact_text(str(e))
            log.warning("github issue dispatch failed: %s", detail)
            return ChannelResult(self.name, DispatchStatus.FAILED, detail)
        except Exception as e:  # noqa: BLE001 — a channel must never crash the router
            log.exception("github issue dispatch: unexpected failure")
            return ChannelResult(
                self.name, DispatchStatus.FAILED, redact_text(f"unexpected: {e}")
            )

    # -- internals ----------------------------------------------------

    def _gh(self, argv: list[str], *, stdin: str | None = None) -> _GhResult:
        full = [self._config.gh_binary, *argv]
        return self._runner(full, stdin=stdin, timeout=self._config.timeout_s)

    def _find_open_issue(self, sig: str) -> int | None:
        """Return the number of an open issue carrying `sig`, or None."""

        # `state:open` is folded into the search string itself rather
        # than passed as `--state` — when `--search` is present, `gh`
        # hands the query straight to GitHub's search API, and the
        # search API only honours an in-query `state:` qualifier.
        argv = [
            "issue",
            "list",
            "--search",
            f"{sig} in:body state:open",
            "--json",
            "number",
            "--limit",
            "1",
        ]
        if self._config.repo:
            argv += ["--repo", self._config.repo]
        res = self._gh(argv)
        if res.returncode != 0:
            raise GitHubIssueError(
                f"gh issue list failed (exit {res.returncode}): "
                f"{_tail(res.stderr)}"
            )
        try:
            data = json.loads(res.stdout or "[]")
        except json.JSONDecodeError as e:
            raise GitHubIssueError(f"gh issue list returned non-JSON: {e}") from e
        if not isinstance(data, list):
            raise GitHubIssueError(
                f"gh issue list returned non-list: {type(data).__name__}"
            )
        for item in data:
            number = item.get("number") if isinstance(item, dict) else None
            if isinstance(number, int):
                return number
        return None

    def _create_issue(self, finding: Finding, sig: str) -> tuple[int, str]:
        """Create the issue; return `(number, url)`."""

        title = _render_title(finding)
        body = _render_body(finding, sig)
        # `--key=value` form so a summary that begins with '-' is never
        # parsed as a flag; `--body-file=-` reads the (possibly large)
        # body from stdin, dodging argv length limits entirely.
        argv = ["issue", "create", f"--title={title}", "--body-file=-"]
        if self._config.repo:
            argv += [f"--repo={self._config.repo}"]
        res = self._gh(argv, stdin=body)
        if res.returncode != 0:
            raise GitHubIssueError(
                f"gh issue create failed (exit {res.returncode}): "
                f"{_tail(res.stderr)}"
            )
        match = _ISSUE_URL_RE.search(res.stdout or "")
        if match is None:
            raise GitHubIssueError(
                f"gh issue create gave no parseable issue URL: {_tail(res.stdout)}"
            )
        return int(match.group(1)), match.group(0)


# ---------------------------------------------------------------------------
# Rendering helpers (pure — easy to unit-test)
# ---------------------------------------------------------------------------


def _tail(text: str) -> str:
    """Last `_STDERR_TAIL` chars of `text` — single-lined, redacted.

    `gh` stderr is operator-facing and low-risk, but it is surfaced in
    a `ChannelResult.detail` and a log line, so it is scrubbed like any
    other output.
    """

    flat = redact_text(" ".join((text or "").split()))
    return flat[-_STDERR_TAIL:]


def _render_title(finding: Finding) -> str:
    """`[sentinel] SEVERITY: summary`, single-lined and length-capped."""

    summary = " ".join(finding.summary.split()) or "(no summary)"
    title = f"[sentinel] {finding.severity.value}: {summary}"
    if len(title) > _MAX_TITLE_LEN:
        title = title[: _MAX_TITLE_LEN - 1].rstrip() + "…"
    return title


def _render_details_table(details: Mapping[str, Any]) -> str:
    if not details:
        return "_No structured details._"
    rows = ["| Field | Value |", "| --- | --- |"]
    for i, (key, value) in enumerate(sorted(details.items())):
        if i >= _MAX_DETAIL_ROWS:
            rows.append(f"| _… {len(details) - _MAX_DETAIL_ROWS} more_ | |")
            break
        cell_key = md_table_cell(key, max_len=_MAX_DETAIL_VALUE_LEN)
        cell_value = md_table_cell(value, max_len=_MAX_DETAIL_VALUE_LEN)
        rows.append(f"| `{cell_key}` | `{cell_value}` |")
    return "\n".join(rows)


def _render_body(finding: Finding, sig: str) -> str:
    """Render the full Markdown issue body. `finding` must be redacted."""

    summary = " ".join(finding.summary.split()) or "(no summary)"
    return "\n".join(
        [
            f"**Severity:** `{finding.severity.value}`",
            f"**Rule:** `{finding.rule_name}`",
            f"**Detected:** {iso_utc(finding.at_unix)}",
            f"**Fingerprint:** `{finding.fingerprint}`",
            "",
            f"> {summary}",
            "",
            "### Details",
            "",
            _render_details_table(finding.details),
            "",
            "---",
            "",
            "_Filed automatically by **hippius-sentinel** (§S PR-S5). This issue "
            "is the de-duplication anchor for its incident signature — the "
            "sentinel will not open another issue for the same "
            "`(rule, fingerprint)` while this one stays open._",
            "",
            f"Sentinel idempotency signature: `{sig}`",
            f"<!-- sentinel-signature: {sig} -->",
        ]
    )
