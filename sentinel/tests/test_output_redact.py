"""Tests for `sentinel.output.redact` — the no-plaintext-secret guard."""

from __future__ import annotations

from sentinel.analytics.base import Severity
from sentinel.output.redact import (
    REDACTED,
    redact_finding,
    redact_mapping,
    redact_text,
)
from tests._analytics_helpers import make_finding

# --- secret shapes ARE redacted -------------------------------------------


def test_redacts_aws_access_key() -> None:
    out = redact_text("creds AKIAIOSFODNN7EXAMPLE end")
    assert "AKIA" not in out
    assert REDACTED in out


def test_redacts_anthropic_key() -> None:
    out = redact_text("key=sk-ant-api03-abcdefABCDEF0123456789xyz tail")
    assert "sk-ant-" not in out
    assert REDACTED in out


def test_redacts_github_token() -> None:
    for token in (
        "ghp_0123456789abcdefABCDEF0123456789abcd",
        "ghs_0123456789abcdefABCDEF0123456789abcd",
        "github_pat_11ABCDEFG0123456789_abcdefghij",
    ):
        out = redact_text(f"token {token} done")
        assert token not in out
        assert REDACTED in out


def test_redacts_slack_token_and_webhook_url() -> None:
    assert "xoxb-" not in redact_text("xoxb-1234567890-abcdefghijkl")
    url = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    out = redact_text(f"posting to {url} now")
    assert "hooks.slack.com" not in out
    assert REDACTED in out


def test_redacts_vault_token_and_signature() -> None:
    assert "hvs." not in redact_text("hvs.ABCDEFGHIJKLMNOPQRSTUVWX")
    sig = "vault:v3:abcdEFGH0123456789+/=ABCDabcd"
    assert sig not in redact_text(f"sig={sig}")


def test_redacts_jwt() -> None:
    jwt = "eyJhbGciOi.eyJzdWIiOiITEST.signaturePARTxyz"
    assert jwt not in redact_text(f"bearer body {jwt}")


def test_redacts_pem_private_key() -> None:
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAACSECRETKEYBYTES\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    out = redact_text(f"leaked:\n{pem}\nafter")
    assert "PRIVATE KEY" not in out
    assert "SECRETKEYBYTES" not in out
    assert REDACTED in out


def test_redacts_url_userinfo() -> None:
    out = redact_text("postgres://admin:hunter2@db.internal:5432/vali")
    assert "hunter2" not in out
    assert "admin" not in out
    # The scheme + host structure survives so the report stays readable.
    assert "db.internal" in out


def test_redacts_bearer_header() -> None:
    out = redact_text("Authorization: Bearer abcdefghijklmnop0123456789")
    assert "abcdefghijklmnop0123456789" not in out


def test_redacts_openai_project_key() -> None:
    out = redact_text("using sk-proj-abcDEF0123456789ghijKLMNopqrST tail")
    assert "sk-proj-" not in out
    assert REDACTED in out


def test_redacts_key_name_contexts() -> None:
    for text in (
        "password=hunter2supersecret",
        "api_key: akeyvalue0123456789",
        "client_secret = abcdef-ghijkl-mnopqr",
        "auth_token=zzzzzzzzzzzzzzzz",
    ):
        assert REDACTED in redact_text(text)


def test_key_context_keeps_the_key_name() -> None:
    out = redact_text("password=hunter2")
    assert out.startswith("password=")
    assert "hunter2" not in out


def test_key_context_leaves_ordinary_finding_text_intact() -> None:
    """Findings carry `threshold=30`, `epoch=2207` — never a secret name."""

    text = "grant rate spike threshold=30 epoch=2207 count=915 denied=12"
    assert redact_text(text) == text


# --- legitimate finding data is NOT redacted ------------------------------


def test_keeps_audit_chain_hashes() -> None:
    """Bare hex digests (head hashes, error digests) must survive."""

    digest = "a1b2c3d4e5f6a7b8"
    head = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    text = f"chain break digest={digest} head={head}"
    assert redact_text(text) == text


def test_keeps_operational_ids() -> None:
    text = "vm_id=vm-4471 ticket_id=tk-99 node=0xdeadbeef epoch=2207"
    assert redact_text(text) == text


# --- structure-aware helpers ----------------------------------------------


def test_redact_is_idempotent() -> None:
    once = redact_text("key sk-ant-api03-abcdefABCDEF0123456789xyz")
    assert redact_text(once) == once


def test_redact_mapping_recurses_and_keeps_scalars() -> None:
    out = redact_mapping(
        {
            "count": 7,
            "ok": True,
            "note": "token ghp_0123456789abcdefABCDEF0123456789abcd",
            "nested": {"inner": "AKIAIOSFODNN7EXAMPLE"},
        }
    )
    assert out["count"] == 7
    assert out["ok"] is True
    assert "ghp_" not in out["note"]
    assert "AKIA" not in out["nested"]["inner"]


def test_redact_finding_scrubs_summary_and_details() -> None:
    finding = make_finding(
        summary="leaked sk-ant-api03-abcdefABCDEF0123456789xyz in summary",
        details={"blob": "AKIAIOSFODNN7EXAMPLE", "n": 3},
    )
    safe = redact_finding(finding)
    assert "sk-ant-" not in safe.summary
    assert "AKIA" not in safe.details["blob"]
    assert safe.details["n"] == 3


def test_redact_finding_keeps_rule_name_and_metadata() -> None:
    """rule_name is verbatim (compile-time id); severity/at_unix kept."""

    finding = make_finding(
        rule_name="audit_chain_break",
        fingerprint="break:a1b2c3d4e5f6a7b8",
        severity=Severity.CRITICAL,
    )
    safe = redact_finding(finding)
    assert safe.rule_name == finding.rule_name
    assert safe.severity == finding.severity
    assert safe.at_unix == finding.at_unix
    # A clean fingerprint carries no secret shape, so redaction is a
    # no-op on it — but it IS passed through the scrubber.
    assert safe.fingerprint == "break:a1b2c3d4e5f6a7b8"


def test_redact_finding_scrubs_secret_shaped_fingerprint() -> None:
    """A fingerprint that happens to carry a secret shape is scrubbed."""

    finding = make_finding(fingerprint="leak:AKIAIOSFODNN7EXAMPLE")
    safe = redact_finding(finding)
    assert "AKIA" not in safe.fingerprint
    assert REDACTED in safe.fingerprint
