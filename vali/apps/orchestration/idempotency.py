"""Shell-out wrapper for the §14 idempotency-key store.

The §24/§25 orchestrator advances a job one step per tick. A tick
that crashes after an external side-effect but before the job's
state CAS would re-run the side-effect. Every side-effectful step is
therefore wrapped: `recall` before (skip if already done), `record`
after.

The durable file-backed store is `kbs_core::persist::FileIdempotencyStore`
(PR #45); vali reaches it by shelling out to the
`idempotency-record` / `idempotency-recall` subcommands of
`hippius-ticket-validator` — no PyO3 binding, the durable format
stays single-sourced in Rust.

The store directory is handed to the binary via the `IDEMPOTENCY_DIR`
environment variable (never argv).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from django.conf import settings

log = logging.getLogger("apps.orchestration.idempotency")


class IdempotencyUnavailable(Exception):
    """The idempotency store could not be reached (binary missing,
    `VALI_IDEMPOTENCY_DIR` unset, store I/O error). The orchestrator
    treats a guarded step as failed-this-tick and retries.
    """


def _binary_and_env() -> tuple[Path, dict[str, str]]:
    # Validate the (cheap, local) config BEFORE the external binary — a
    # misconfigured `VALI_IDEMPOTENCY_DIR` should fail fast with its own
    # clear error rather than being masked by an absent validator binary.
    idem_dir = str(getattr(settings, "VALI_IDEMPOTENCY_DIR", "") or "").strip()
    if not idem_dir:
        raise IdempotencyUnavailable("VALI_IDEMPOTENCY_DIR is not configured")
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise IdempotencyUnavailable(f"validator binary not found at {bin_path}")
    ttl = int(getattr(settings, "VALI_IDEMPOTENCY_TTL_SECS", 86_400))
    child_env = {
        **os.environ,
        "IDEMPOTENCY_DIR": idem_dir,
        "IDEMPOTENCY_TTL_SECS": str(ttl),
    }
    return bin_path, child_env


def _run(argv: list[str]) -> dict[str, Any]:
    """Spawn a subcommand, return the parsed `{"tag":"ok",...}` JSON.

    Both subcommands exit 0 (ok) or 2 (structured failure); both
    write a JSON envelope. Any failure mode raises
    `IdempotencyUnavailable` — the store is infrastructure, not a
    caller-fault path.
    """
    bin_path, child_env = _binary_and_env()
    timeout = float(getattr(settings, "VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0))
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), *argv],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise IdempotencyUnavailable(f"idempotency timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        raise IdempotencyUnavailable(f"idempotency spawn failed: {exc}") from exc

    if completed.returncode not in (0, 2):
        raise IdempotencyUnavailable(
            f"idempotency exited with code {completed.returncode}"
        )
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise IdempotencyUnavailable("idempotency stdout is not JSON") from exc
    if not isinstance(payload, dict) or "tag" not in payload:
        raise IdempotencyUnavailable("idempotency stdout missing 'tag'")
    tag = payload["tag"]
    if tag == "err":
        category = str(payload.get("category", "unknown"))
        raise IdempotencyUnavailable(f"[{category}] {payload.get('error', '')}")
    if tag != "ok":
        raise IdempotencyUnavailable(f"idempotency returned unknown tag={tag!r}")
    return payload


def _key_hex(key: str) -> str:
    """Hex-encode an orchestration step key for the `--key-hex` flag."""
    return key.encode("utf-8").hex()


def recall(key: str) -> str | None:
    """Return the recorded response-hash hex for `key`, or `None` if
    the key was never recorded (or its TTL elapsed).
    """
    payload = _run(["idempotency-recall", "--key-hex", _key_hex(key)])
    if payload.get("found"):
        return str(payload.get("hash"))
    return None


def record(key: str, response_hash_hex: str) -> bool:
    """Record `(key → response_hash)`. Returns `True` when THIS call
    wrote the entry, `False` when the key was already present (a
    benign concurrent-tick replay — the step is already done).
    """
    payload = _run(
        [
            "idempotency-record",
            "--key-hex",
            _key_hex(key),
            "--response-hash-hex",
            response_hash_hex,
        ]
    )
    return bool(payload.get("recorded"))


def marker_hash(key: str) -> str:
    """Deterministic 32-byte (hex) marker for steps with no meaningful
    response to dedup against — the idempotency entry only needs to
    record *that the step ran*, not a re-derivable response.
    """
    return hashlib.sha256(f"orchestration-step:{key}".encode()).hexdigest()
