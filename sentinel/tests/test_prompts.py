"""Tests for `sentinel.prompts` — system prompt, few-shot, user prompt."""

from __future__ import annotations

from sentinel.analytics.base import Severity
from sentinel.output.redact import redact_text
from sentinel.prompts import (
    aggregate_findings,
    build_system_prompt,
    build_user_prompt,
    load_few_shot_examples,
    load_system_prompt,
)
from tests._analytics_helpers import make_finding

# --- system prompt + few-shot ---------------------------------------------


def test_load_system_prompt_is_the_senior_sre_brief() -> None:
    prompt = load_system_prompt()
    lowered = prompt.lower()
    assert "senior" in lowered and "sre" in lowered
    assert "Severity ladder" in prompt
    assert "read-only" in lowered


def test_few_shot_examples_loaded_in_severity_order() -> None:
    examples = load_few_shot_examples()
    assert [e.name for e in examples] == [
        "info_release_rate_normal",
        "alert_replay_attempts_spike",
        "critical_audit_chain_break",
    ]
    assert all(e.content.strip() for e in examples)


def test_build_system_prompt_embeds_base_and_examples() -> None:
    full = build_system_prompt()
    assert load_system_prompt() in full
    assert "Worked examples" in full
    for example in load_few_shot_examples():
        assert example.content in full


def test_build_system_prompt_carries_no_secret_shapes() -> None:
    """The static prompt assets must contain nothing redaction flags."""

    full = build_system_prompt()
    # If redaction is a no-op, no secret-shaped substring exists.
    assert redact_text(full) == full


# --- user prompt: verbatim vs aggregate -----------------------------------


def test_user_prompt_small_batch_is_verbatim() -> None:
    findings = [
        make_finding(
            rule_name="cert_expiry",
            summary="server cert 5d past rotation window",
            severity=Severity.ALERT,
        )
    ]
    prompt = build_user_prompt(findings, aggregate_threshold=20)
    assert "server cert 5d past rotation window" in prompt
    assert "cert_expiry" in prompt
    # Rendered verbatim: a per-finding block, no aggregation note.
    assert "- summary:" in prompt
    assert "context budget" not in prompt


def test_user_prompt_large_batch_is_aggregated() -> None:
    findings = [
        make_finding(rule_name="release_anomaly", fingerprint=f"f{i}", summary=f"s{i}")
        for i in range(25)
    ]
    prompt = build_user_prompt(findings, aggregate_threshold=10)
    assert "aggregated" in prompt.lower()
    assert "release_anomaly" in prompt
    assert "25 finding(s)" in prompt


def test_user_prompt_redacts_secrets() -> None:
    findings = [make_finding(summary="leaked AKIAIOSFODNN7EXAMPLE in a log")]
    prompt = build_user_prompt(findings)
    assert "AKIA" not in prompt
    assert "[REDACTED]" in prompt


def test_user_prompt_reports_dropped_findings() -> None:
    prompt = build_user_prompt([make_finding()], dropped=7)
    assert "7" in prompt
    assert "dropped" in prompt.lower()


def test_user_prompt_empty_batch() -> None:
    prompt = build_user_prompt([])
    assert "0 finding(s)" in prompt


# --- aggregation ----------------------------------------------------------


def test_aggregate_findings_groups_worst_first() -> None:
    findings = [
        make_finding(
            severity=Severity.CRITICAL, rule_name="audit_chain_break", fingerprint=f"c{i}"
        )
        for i in range(3)
    ] + [
        make_finding(
            severity=Severity.WARN, rule_name="release_anomaly", fingerprint=f"w{i}"
        )
        for i in range(2)
    ]
    out = aggregate_findings(findings)
    assert "[CRITICAL] audit_chain_break — 3 finding(s)" in out
    assert "[WARN] release_anomaly — 2 finding(s)" in out
    # Worst severity rendered first.
    assert out.index("CRITICAL") < out.index("WARN")
