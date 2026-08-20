"""Tests for `sentinel.output.channels` — shared helpers."""

from __future__ import annotations

import pytest

from sentinel.analytics.base import Severity
from sentinel.output.channels import (
    ChannelResult,
    DispatchStatus,
    iso_utc,
    md_table_cell,
    severity_at_least,
    signature,
    utc_day,
)
from tests._analytics_helpers import make_finding


def test_signature_depends_only_on_rule_and_fingerprint() -> None:
    a = make_finding(rule_name="r", fingerprint="fp", summary="one")
    b = make_finding(
        rule_name="r", fingerprint="fp", summary="two", severity=Severity.CRITICAL
    )
    assert signature(a) == signature(b)


def test_signature_differs_on_fingerprint() -> None:
    a = make_finding(rule_name="r", fingerprint="fp1")
    b = make_finding(rule_name="r", fingerprint="fp2")
    assert signature(a) != signature(b)


def test_signature_has_no_concatenation_aliasing() -> None:
    """The NUL separator stops ("ab","c") aliasing to ("a","bc")."""

    a = make_finding(rule_name="ab", fingerprint="c")
    b = make_finding(rule_name="a", fingerprint="bc")
    assert signature(a) != signature(b)


def test_signature_length_is_16_hex() -> None:
    sig = signature(make_finding())
    assert len(sig) == 16
    assert all(c in "0123456789abcdef" for c in sig)


def test_severity_at_least() -> None:
    assert severity_at_least(Severity.CRITICAL, Severity.ALERT)
    assert severity_at_least(Severity.ALERT, Severity.ALERT)
    assert not severity_at_least(Severity.WARN, Severity.ALERT)
    assert not severity_at_least(Severity.INFO, Severity.ALERT)


def test_severity_at_least_avoids_string_comparison_trap() -> None:
    """`"INFO" >= "ALERT"` is True alphabetically — the helper must not be."""

    assert not severity_at_least(Severity.INFO, Severity.CRITICAL)
    assert not severity_at_least(Severity.WARN, Severity.CRITICAL)


def test_iso_utc() -> None:
    assert iso_utc(1_700_000_000) == "2023-11-14T22:13:20Z"
    assert iso_utc(0) == "unknown"
    assert iso_utc(-5) == "unknown"


def test_utc_day() -> None:
    assert utc_day(1_700_000_000) == "2023-11-14"
    with pytest.raises(ValueError):
        utc_day(0)


def test_md_table_cell_escapes_and_truncates() -> None:
    assert md_table_cell("a|b", max_len=100) == "a\\|b"
    assert md_table_cell("line1\nline2", max_len=100) == "line1 line2"
    assert md_table_cell("c:\\path", max_len=100) == "c:\\\\path"
    long = md_table_cell("x" * 200, max_len=10)
    assert long.endswith("…")
    assert len(long) == 11


def test_channel_result_ok() -> None:
    assert ChannelResult("c", DispatchStatus.CREATED).ok
    assert ChannelResult("c", DispatchStatus.DUPLICATE).ok
    assert ChannelResult("c", DispatchStatus.SKIPPED).ok
    assert ChannelResult("c", DispatchStatus.SUPPRESSED).ok
    assert not ChannelResult("c", DispatchStatus.FAILED).ok
