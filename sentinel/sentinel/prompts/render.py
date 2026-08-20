"""Dynamic user-prompt construction from analytics findings (PR-S6).

Each agent turn delivers the batch of findings emitted since the last
turn. `build_user_prompt` renders that batch:

  * **Verbatim** when the batch is small — every finding in full.
  * **Aggregated** when the batch exceeds `aggregate_threshold` — one
    block per `(severity, rule)` group with counts and a few example
    summaries. This is the context-budget guard: a flood of findings
    (a wedged rule, a real storm) can never blow the model's context
    window or burn a huge token bill.

Every finding is passed through `redact_finding` before it reaches the
prompt — defence in depth on the §S "no plaintext secret leaves the
control plane" invariant, even though the PR-S4 rules already project
LLM-safe shapes.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from sentinel.analytics.base import Finding, Severity
from sentinel.output.channels import iso_utc
from sentinel.output.redact import redact_finding

# Worst-first severity order for stable grouping + sorting.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.ALERT,
    Severity.WARN,
    Severity.INFO,
)

# Caps applied when rendering — keep a single finding (or group) from
# dominating the prompt.
_MAX_EXAMPLES_PER_GROUP = 3
_MAX_DETAIL_ITEMS = 8
_MAX_DETAIL_VALUE_LEN = 200

_TURN_INSTRUCTION = (
    "Analyze the findings above as a senior SRE. Investigate with the "
    "read-only tools where it changes your verdict, then produce one "
    "Markdown assessment per finding — or per (severity, rule) group "
    "when the batch is aggregated — in the format defined by your "
    "system prompt. Lead with the most severe."
)


def _severity_rank(severity: Severity) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


def _sort_key(finding: Finding) -> tuple[int, int, str, str]:
    return (
        _severity_rank(finding.severity),
        finding.at_unix,
        finding.rule_name,
        finding.fingerprint,
    )


def _render_details(details: Mapping[str, Any]) -> str:
    if not details:
        return ""
    pieces: list[str] = []
    for i, (key, value) in enumerate(sorted(details.items())):
        if i >= _MAX_DETAIL_ITEMS:
            pieces.append(f"(+{len(details) - _MAX_DETAIL_ITEMS} more)")
            break
        text = str(value)
        if len(text) > _MAX_DETAIL_VALUE_LEN:
            text = text[:_MAX_DETAIL_VALUE_LEN] + "…"
        pieces.append(f"{key}={text}")
    return ", ".join(pieces)


def _render_finding(finding: Finding) -> str:
    lines = [
        f"### [{finding.severity.value}] {finding.rule_name}",
        f"- summary: {finding.summary}",
        f"- detected: {iso_utc(finding.at_unix)}",
        f"- fingerprint: {finding.fingerprint}",
    ]
    details = _render_details(finding.details)
    if details:
        lines.append(f"- details: {details}")
    return "\n".join(lines)


def aggregate_findings(findings: Sequence[Finding]) -> str:
    """Render a batch as a per-(severity, rule) aggregate summary.

    Public + pure so it is directly unit-testable. `findings` should
    already be redacted by the caller; `build_user_prompt` does that.
    """

    groups: dict[tuple[Severity, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.severity, finding.rule_name), []).append(finding)

    ordered_keys = sorted(
        groups, key=lambda k: (_severity_rank(k[0]), -len(groups[k]), k[1])
    )

    blocks: list[str] = []
    for severity, rule_name in ordered_keys:
        group = groups[(severity, rule_name)]
        block = [f"### [{severity.value}] {rule_name} — {len(group)} finding(s)"]
        # A few representative summaries — most recent first.
        recent = sorted(group, key=lambda f: f.at_unix, reverse=True)
        for finding in recent[:_MAX_EXAMPLES_PER_GROUP]:
            block.append(f"- {iso_utc(finding.at_unix)}: {finding.summary}")
        if len(group) > _MAX_EXAMPLES_PER_GROUP:
            block.append(f"- (+{len(group) - _MAX_EXAMPLES_PER_GROUP} more)")
        blocks.append("\n".join(block))

    return "\n\n".join(blocks)


def build_user_prompt(
    findings: Sequence[Finding],
    *,
    dropped: int = 0,
    aggregate_threshold: int = 20,
) -> str:
    """Render the per-turn user prompt from a batch of findings.

    `findings` are raw; this function redacts them. `dropped` is the
    count of findings the agent's buffer shed before this turn (it is
    surfaced so the model knows its view is incomplete).
    """

    safe = sorted((redact_finding(f) for f in findings), key=_sort_key)

    counts = Counter(f.severity.value for f in safe)
    breakdown = " · ".join(
        f"{sev.value} {counts.get(sev.value, 0)}" for sev in _SEVERITY_ORDER
    )

    header = [
        "# Sentinel patrol — findings since the last turn",
        "",
        f"**{len(safe)} finding(s)** — {breakdown}",
    ]
    if dropped > 0:
        header.append(
            f"\n> NOTE: {dropped} further finding(s) were dropped before this "
            "turn (agent buffer overflow) — your view is incomplete; weight "
            "the aggregate counts accordingly."
        )

    aggregated = len(safe) > aggregate_threshold
    if aggregated:
        header.append(
            f"\n> The batch exceeds the context budget ({aggregate_threshold}); "
            "it has been aggregated by (severity, rule)."
        )
        body = aggregate_findings(safe)
    else:
        body = "\n\n".join(_render_finding(f) for f in safe)

    if not body:
        body = "_No findings._"

    return "\n".join(header) + "\n\n" + body + "\n\n" + _TURN_INSTRUCTION
