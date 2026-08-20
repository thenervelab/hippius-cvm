"""Shell-out wrapper for `hippius-ticket-validator verify-stopped-ack`.

The Rust binary owns the canonical-CBOR + Ed25519 semantics
(`hippius_guest::verify_stopped_ack`); this module is a thin Python
wrapper that:

  1. Spawns the binary with `verify-stopped-ack <args>` (subcommand).
  2. Pipes the signed CBOR bytes through stdin.
  3. Parses the JSON envelope on stdout, mapping exit codes:
       0  →  ValidatorOk { now_unix }
       2  →  ValidatorFailed { message, category }   (HTTP 400)
       1  →  ValidatorUnavailable                    (HTTP 503)

The expected fields (`vm_id`, `lease_id`, `vm_generation`,
`nonce_hex`, `now_unix_min/max`, `lifecycle_vk_hex`) are supplied by
vali — the Rust binary is a stateless verifier.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger("apps.lifecycle.validator")


class ValidatorError(Exception):
    """Base class — never raised directly."""


class ValidatorUnavailable(ValidatorError):
    """Mapped to HTTP 503 by the view: the Rust binary couldn't run /
    returned non-structured output. Surface to ops.
    """


@dataclass(frozen=True)
class ValidatorFailed(ValidatorError):
    """The Rust binary parsed the input and rejected it. Mapped to
    HTTP 400. `category` ∈ {stopped-decode, stopped-body-mismatch,
    stopped-signature, stopped-window} (stable strings, see
    `binaries/ticket-validator/src/main.rs::category`).
    """

    message: str
    category: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.message}"


@dataclass(frozen=True)
class VerifiedStoppedAck:
    """Result on success. `now_unix` is the guest-signed timestamp the
    binary extracted from the body (always inside the window the
    caller supplied — the binary rejects otherwise)."""

    now_unix: int


def verify_stopped_ack(
    *,
    signed_bytes: bytes,
    lifecycle_vk_hex: str,
    vm_id: str,
    lease_id: str,
    vm_generation: int,
    nonce_hex: str,
    now_unix_min: int,
    now_unix_max: int,
) -> VerifiedStoppedAck:
    """Run the binary's `verify-stopped-ack` subcommand.

    Every kwarg maps to one CLI flag — keeps the call site readable
    AND prevents positional mistakes (subprocess argv is sensitive).
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ValidatorUnavailable(f"validator binary not found at {bin_path}")
    if not signed_bytes:
        # Bypass the spawn — the binary would just return
        # stopped-decode anyway. Keep the failure category stable.
        raise ValidatorFailed(message="empty signed ack", category="stopped-decode")

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [
        str(bin_path),
        "verify-stopped-ack",
        "--vk-hex",
        lifecycle_vk_hex,
        "--vm-id",
        vm_id,
        "--lease-id",
        lease_id,
        "--vm-generation",
        str(vm_generation),
        "--nonce-hex",
        nonce_hex,
        "--now-unix-min",
        str(now_unix_min),
        "--now-unix-max",
        str(now_unix_max),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=signed_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("verify-stopped-ack timeout after %.2fs", timeout)
        raise ValidatorUnavailable(f"validator timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("verify-stopped-ack spawn failed: %s", exc)
        raise ValidatorUnavailable(f"validator spawn failed: {exc}") from exc

    if completed.returncode not in (0, 2):
        log.error(
            "verify-stopped-ack internal failure: rc=%s stderr=%r",
            completed.returncode,
            _safe_truncate(completed.stderr),
        )
        raise ValidatorUnavailable(f"validator exited with code {completed.returncode}")

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("verify-stopped-ack non-JSON stdout (rc=%s): %s", completed.returncode, exc)
        raise ValidatorUnavailable("validator stdout is not JSON") from exc

    if not isinstance(payload, dict) or "tag" not in payload:
        raise ValidatorUnavailable("validator stdout missing 'tag' field")

    tag = payload["tag"]
    if tag == "err":
        msg = str(payload.get("error", "validator rejected ack"))
        category = str(payload.get("category", "unknown"))
        raise ValidatorFailed(message=msg, category=category)
    if tag != "ok":
        raise ValidatorUnavailable(f"validator returned unknown tag={tag!r}")

    try:
        return _coerce_ok(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidatorUnavailable(f"validator ok-output unexpected shape: {exc}") from exc


def _coerce_ok(payload: dict[str, Any]) -> VerifiedStoppedAck:
    return VerifiedStoppedAck(now_unix=int(payload["now_unix"]))


def _safe_truncate(b: bytes, limit: int = 512) -> str:
    """stderr capture for logs. The binary's stderr contract is
    diagnostic strings only — never ack bytes — but we cap length
    anyway so a runaway log can't OOM the logging backend.
    """
    if not b:
        return ""
    s = b.decode("utf-8", errors="replace")
    if len(s) > limit:
        return s[:limit] + f"...<+{len(s) - limit} chars>"
    return s
