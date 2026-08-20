"""Shared types for sentinel output channels (PR-S5).

Every output channel — GitHub issue, Slack webhook, daily summary —
returns a `ChannelResult` so the `FindingRouter` can reason uniformly
about what happened to a finding without knowing channel internals.

The `signature()` helper derives the idempotency key from a Finding's
`(rule_name, fingerprint)` pair — the *same* pair the PR-S4 analytics
loop dedups on. That is deliberate: a finding that re-fires after its
PR-S4 cooldown maps to the same signature, so the GitHub channel
collapses it onto the already-open issue instead of filing a duplicate.

The framework here is intentionally tiny and dependency-free so the §S
security review can audit the whole output surface quickly.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from sentinel.analytics.base import Finding, Severity

# Length (hex chars) of the idempotency signature embedded in GitHub
# issue bodies and used as the de-dup search key. 16 hex = 64 bits —
# far below any realistic collision risk for the ~1k unique
# fingerprints the PR-S4 dedup index is sized for.
SIGNATURE_HEX_LEN = 16


class DispatchStatus(StrEnum):
    """Outcome of handing one Finding to one output channel.

    Ordered loosely from "did something" to "did nothing" to "broke" so
    log scans read naturally; callers compare by identity, not order.
    """

    CREATED = "created"        # a new external artifact was emitted
    DUPLICATE = "duplicate"    # idempotency hit — artifact already existed
    SKIPPED = "skipped"        # severity routing excluded this channel
    SUPPRESSED = "suppressed"  # rate limiter dropped the external write
    FAILED = "failed"          # the channel raised / returned an error


@dataclass(frozen=True)
class ChannelResult:
    """What one channel did with one finding.

    `detail` is a short human string for logs — it MUST NOT carry
    secrets (channels redact before they build it). `ok` is false only
    for `FAILED`; `SKIPPED`/`SUPPRESSED`/`DUPLICATE` are all expected,
    non-error outcomes.
    """

    channel: str
    status: DispatchStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not DispatchStatus.FAILED


@runtime_checkable
class OutputChannel(Protocol):
    """Minimal contract every output channel satisfies.

    `dispatch` MUST NOT raise — a channel failure surfaces as a
    `ChannelResult` with `FAILED` status so the router (and, upstream,
    the analytics loop) stays alive. This mirrors the PR-S4 rule
    isolation invariant.
    """

    name: str

    def dispatch(self, finding: Finding) -> ChannelResult: ...


def signature(finding: Finding) -> str:
    """Stable idempotency key for a Finding.

    Derived only from `(rule_name, fingerprint)` — the same pair the
    PR-S4 loop dedups on — so a finding that re-fires after its
    cooldown maps to the same signature and collapses onto the existing
    GitHub issue instead of opening a new one.

    The NUL separator makes the concatenation unambiguous: a rule name
    cannot contain a NUL, so `("ab", "c")` and `("a", "bc")` can never
    alias to the same signature.

    IMPORTANT: call this on the **raw** finding, before
    `redact.redact_finding`. Redaction scrubs the `fingerprint` field
    for display, which would shift the signature — and the signature
    must stay byte-stable across process restarts for cross-restart
    idempotency to hold.
    """

    raw = f"{finding.rule_name}\x00{finding.fingerprint}"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    return digest[:SIGNATURE_HEX_LEN]


def md_table_cell(value: object, *, max_len: int) -> str:
    """Render `value` so it is safe inside one Markdown table cell.

    Flattens newlines, escapes the `|` column delimiter and backslash,
    and truncates to `max_len`. Used by every channel that emits a
    Markdown table so a long or pipe-laden detail value can never break
    the table layout.
    """

    text = str(value)
    if len(text) > max_len:
        text = text[:max_len] + "…"
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    """True iff `severity` is at or above `threshold` on the §S ladder.

    This relies only on `Severity.__lt__` — the one comparison PR-S4
    overrides correctly. The bare `>=` operator is unsafe for routing:
    `Severity` is a `StrEnum`, so `severity >= threshold` would
    silently fall back to *string* comparison, where `"INFO" >=
    "ALERT"` is True (alphabetical 'I' > 'A'). Every severity gate in
    the output layer must go through this helper.
    """

    return not (severity < threshold)


def iso_utc(at_unix: int) -> str:
    """Render a unix timestamp as a stable `YYYY-MM-DDTHH:MM:SSZ` string.

    Used in every channel's rendered output. `at_unix <= 0` (a finding
    the loop never stamped) renders as the literal `unknown` rather
    than the misleading 1970 epoch.
    """

    if at_unix <= 0:
        return "unknown"
    return dt.datetime.fromtimestamp(at_unix, tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_day(at_unix: int) -> str:
    """Render a unix timestamp as a `YYYY-MM-DD` UTC date string.

    This is the bucketing key for the daily summary. `at_unix <= 0`
    raises — a finding must be timestamped before it can be filed
    under a day (the loop stamps every emitted finding).
    """

    if at_unix <= 0:
        raise ValueError("utc_day requires a positive timestamp")
    return dt.datetime.fromtimestamp(at_unix, tz=dt.UTC).strftime("%Y-%m-%d")
