"""Shell-out wrapper for the `hippius-ticket-validator` Rust binary.

Spec of record: ARCHITECTURE.md §3 / §6 / §20. vali is opaque-
transport — this wrapper only **parses** the COSE_Sign1 envelope to
extract indexable metadata. Signature verification (Ed25519 against
the §22 allowlist) is the KBS's responsibility.

Wire contract with the binary:

- stdin: raw COSE_Sign1 bytes.
- stdout: JSON, either `{"tag": "ok", "ticket": {...}}` or
  `{"tag": "err", "error": "...", "category": "..."}`.
- exit: 0 on ok, 2 on structured validation failure, 1 on internal
  error.

See `binaries/ticket-validator/src/main.rs` for the canonical schema.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger("apps.orders.validator")


class ValidatorError(Exception):
    """Base class for validator wrapper failures."""


class ValidatorUnavailable(ValidatorError):
    """The Rust binary couldn't run / returned non-structured output.

    Mapped to HTTP 503 by the view: vali itself is misconfigured,
    NOT a problem with the caller's ticket. Surface to ops.
    """


@dataclass(frozen=True)
class ValidatorFailed(ValidatorError):
    """The Rust binary parsed the input and rejected it.

    Mapped to HTTP 400 by the view: the caller's ticket is bad.
    """

    message: str
    category: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.message}"


@dataclass(frozen=True)
class ParsedTicket:
    """Subset of fields the view persists to `OrderTicketIntake`.

    The validator returns more (hex-encoded measurements, vault refs,
    nonce, etc.) — those are useful for PR-G2 / PR-G4 indexing but
    PR-G1 stores only the columns that have direct equivalents in the
    DB model.
    """

    ticket_id: str
    vm_id: str
    tenant_id: str
    user_id: str
    lease_id: str
    vm_generation: int
    issue_time: int
    expiry: int
    node_id: str
    platform_id: str
    resource_class: str
    kid_hex: str


def validate_ticket(cose_bytes: bytes) -> ParsedTicket:
    """Run the Rust validator over `cose_bytes` and return parsed metadata.

    Raises [`ValidatorFailed`] on a structured rejection (400) and
    [`ValidatorUnavailable`] on a binary-side problem (503). Never
    logs the COSE bytes — only the `ticket_id` / `category` strings.
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ValidatorUnavailable(f"validator binary not found at {bin_path}")

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            # PR-G2: the binary now exposes subcommands; preserve the
            # existing behaviour by explicitly passing `verify-ticket`.
            [str(bin_path), "verify-ticket"],
            input=cose_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("validator timeout after %.2fs", timeout)
        raise ValidatorUnavailable(f"validator timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("validator spawn failed: %s", exc)
        raise ValidatorUnavailable(f"validator spawn failed: {exc}") from exc

    # Exit codes 0 (ok) and 2 (structured rejection) both write a
    # JSON envelope to stdout. Anything else is an internal failure
    # — the stderr (NOT the COSE blob, by binary's contract) gets
    # captured for ops review but stays out of the HTTP response.
    if completed.returncode not in (0, 2):
        log.error(
            "validator internal failure: rc=%s stderr=%r",
            completed.returncode,
            _safe_truncate(completed.stderr),
        )
        raise ValidatorUnavailable(
            f"validator exited with code {completed.returncode}"
        )

    # `json.loads` on a non-UTF8 bytes stdout raises `UnicodeDecodeError`
    # (a subclass of `ValueError`, NOT `json.JSONDecodeError`), so we
    # catch the broader hierarchy. Either way the binary's stdout
    # contract is violated and the wrapper surfaces it as 503.
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("validator non-JSON stdout (rc=%s): %s", completed.returncode, exc)
        raise ValidatorUnavailable("validator stdout is not JSON") from exc

    if not isinstance(payload, dict) or "tag" not in payload:
        raise ValidatorUnavailable("validator stdout missing 'tag' field")

    tag = payload["tag"]
    if tag == "err":
        msg = str(payload.get("error", "validator rejected ticket"))
        category = str(payload.get("category", "unknown"))
        raise ValidatorFailed(message=msg, category=category)
    if tag != "ok":
        raise ValidatorUnavailable(f"validator returned unknown tag={tag!r}")

    ticket = payload.get("ticket")
    if not isinstance(ticket, dict):
        raise ValidatorUnavailable("validator ok-output missing 'ticket' object")

    try:
        return _coerce_parsed(ticket)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorUnavailable(f"validator ticket has unexpected shape: {exc}") from exc


def _coerce_parsed(ticket: dict[str, Any]) -> ParsedTicket:
    """Project the validator JSON into the strongly-typed dataclass.

    Raises `KeyError` / `TypeError` / `ValueError` on shape drift —
    caller maps to `ValidatorUnavailable` (503) since it means the
    Rust binary and the Django side disagree on schema, which is a
    deployment bug, not a caller bug.
    """
    return ParsedTicket(
        ticket_id=str(ticket["ticket_id"]),
        vm_id=str(ticket["vm_id"]),
        tenant_id=str(ticket["tenant_id"]),
        user_id=str(ticket["user_id"]),
        lease_id=str(ticket["lease_id"]),
        vm_generation=int(ticket["vm_generation"]),
        issue_time=int(ticket["issue_time"]),
        expiry=int(ticket["expiry"]),
        node_id=str(ticket["node_id"]),
        platform_id=str(ticket["platform_id"]),
        # #312 renamed the ticket's `resource_class: String` to `flavor`;
        # the validator binary's `verify-ticket` output now emits `flavor`.
        # Read it (falling back to the legacy `resource_class` key so an
        # older validator binary still parses) and keep the dataclass field
        # name `resource_class` for the downstream `OrderTicketIntake.
        # resource_class` column.
        resource_class=str(
            ticket["flavor"] if "flavor" in ticket else ticket["resource_class"]
        ),
        kid_hex=str(ticket["kid_hex"]),
    )


def _safe_truncate(b: bytes, limit: int = 512) -> str:
    """Stderr capture for logs. The validator binary's stderr contract
    is: only diagnostic strings, never ticket bytes. Still capped to
    a sane length so a runaway log line can't OOM the logging
    backend.
    """
    if not b:
        return ""
    s = b.decode("utf-8", errors="replace")
    if len(s) > limit:
        return s[:limit] + f"...<+{len(s) - limit} chars>"
    return s
