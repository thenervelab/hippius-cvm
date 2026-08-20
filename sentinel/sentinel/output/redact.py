"""Defence-in-depth secret scrubbing for sentinel outputs (PR-S5).

The §S invariant (issue #57) is that no plaintext secret ever leaves
the control plane. The analytics rules already project narrow,
LLM-safe shapes — scalars: ints, hashes, operational ids — see
`analytics/loop.py` invariant #2, so by construction a `Finding`
should not carry a secret. This module is the *belt* to that
*suspenders*: every string a channel is about to write into a GitHub
issue, a Slack message, the daily summary, or a log line is passed
through `redact_text` first.

## Patterns

Two complementary families:

  * **Prefix-anchored credential shapes** — `AKIA…`, `sk-…`, `ghp_…`,
    `vault:v1:…`, Slack tokens, PEM headers, JWTs. High precision.
  * **Key-name contexts** — `password=…`, `api_key: …`, a URL's
    `user:pass@` userinfo. These scrub the *value* and keep the
    structural context (key name, URL scheme/host) so the report
    stays readable.

We do NOT redact bare long hex / base64 runs: Findings legitimately
carry audit-chain head hashes, body digests, and 32-byte node ids, and
a greedy redactor would corrupt them.

## `redact_finding`

Scrubs `summary`, `fingerprint`, and `details` — every field a channel
renders. `rule_name` is left verbatim: it is a compile-time rule
identifier (`cert_expiry`, `audit_chain_break`, …), never a secret.

The idempotency *signature* must be computed from the **raw**
`(rule_name, fingerprint)` BEFORE redaction — `redact_finding` may
alter the fingerprint, which would shift the signature. See
`channels.signature`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from sentinel.analytics.base import Finding

REDACTED = "[REDACTED]"

# (compiled pattern, replacement) pairs. `replacement` may reference
# capture groups so a pattern keeps structural context while scrubbing
# only the secret payload. `redact_text` applies them in order.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # AWS access key id.
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED),
    # `sk-` API keys — Anthropic (`sk-ant-…`) and OpenAI (`sk-proj-…`).
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), REDACTED),
    # GitHub tokens (classic `ghp_`/`gho_`/… and fine-grained).
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    # Slack bot/user/app tokens.
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    # Slack incoming-webhook URL — the webhook itself is a bearer secret.
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+"), REDACTED),
    # HashiCorp Vault tokens (`hvs.`/`hvb.`) and transit signatures.
    (re.compile(r"hv[sb]\.[A-Za-z0-9._-]{20,}"), REDACTED),
    (re.compile(r"vault:v\d+:[A-Za-z0-9+/=_-]{16,}"), REDACTED),
    # JSON Web Tokens.
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),
        REDACTED,
    ),
    # PEM-encoded private keys (any flavour).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        REDACTED,
    ),
    # `Authorization: Bearer <token>` headers.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"), REDACTED),
    # `secret-name = value` / `: value` contexts — keep the key name,
    # scrub the value. Anchors on a closed set of high-signal names so
    # ordinary finding text (`threshold=30d`, `epoch=2207`) is untouched.
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|client[_-]?secret"
            r"|access[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key)\b"
            r"\s*[=:]\s*)\S+"
        ),
        r"\g<1>" + REDACTED,
    ),
    # Credentials embedded in a URL's userinfo (`scheme://user:pass@host`).
    # Keeps the `://` and `@` so the scheme + host stay legible — this
    # also catches a token-bearing git remote URL leaking via git stderr.
    (re.compile(r"(://)[^/\s:@]+:[^/\s:@]+(@)"), r"\g<1>" + REDACTED + r"\g<2>"),
)


def redact_text(value: str) -> str:
    """Replace every recognised secret shape in `value` with a marker.

    Idempotent: re-running it is a no-op — the `[REDACTED]` marker
    contains no character any pattern can latch onto (no `:` for the
    userinfo rule, no recognised prefix for the rest).
    """

    out = value
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside scalars / mappings / sequences.

    Non-string scalars (int/float/bool/None) pass through untouched —
    a number cannot be a secret and stays useful in the report.
    """

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {k: redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def redact_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Redact every string value in a mapping (keys are left as-is).

    Keys in a `Finding.details` mapping are static, rule-defined field
    names — never secrets — so only values are scrubbed.
    """

    return {k: redact_value(v) for k, v in mapping.items()}


def redact_finding(finding: Finding) -> Finding:
    """Return a copy of `finding` with every rendered field scrubbed.

    `summary`, `fingerprint` and `details` are all redacted — each is
    written verbatim into a GitHub issue / Slack message / daily
    summary. `rule_name` is the one field left as-is: it is a
    compile-time rule identifier, never a secret.

    IMPORTANT: compute `channels.signature()` from the **raw** finding
    *before* calling this — redaction may change the fingerprint, and
    the signature must stay byte-stable for cross-restart idempotency.
    """

    return Finding(
        rule_name=finding.rule_name,
        severity=finding.severity,
        summary=redact_text(finding.summary),
        fingerprint=redact_text(finding.fingerprint),
        details=redact_mapping(finding.details),
        at_unix=finding.at_unix,
    )
