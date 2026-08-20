"""§23 — derive the per-VM tenant telemetry PUBLIC key from the lifecycle
seed.

The telemetry signing key the tenant guest signs `ServedDeliveryReceipt`s
with is NOT a fresh secret: it is HKDF-derived from the §7 lifecycle seed
vali already generated (so the guest can reproduce it from the lifecycle
key it receives in the §21 release). vali only needs the PUBLIC key — to
provision the `TelemetrySource` it verifies the guest's receipts against.

Like `lifecycle_keygen`, vali has no Python crypto dependency: the
derivation (HKDF-SHA256 + Ed25519) is shelled out to the
`hippius-ticket-validator derive-telemetry-key` subcommand, which reads the
lifecycle seed hex on stdin (§20 — never argv) and emits `{"vk_hex"}`. The
derived signing seed never leaves that process; vali does not stage it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from django.conf import settings


class TelemetryKeygenError(Exception):
    """The derive subprocess could not run or returned bad output."""


def derive_telemetry_vk(lifecycle_seed: bytes) -> bytes:
    """Return the 32-byte telemetry verifying key derived from
    `lifecycle_seed`. Raises `TelemetryKeygenError` on any binary / parse /
    shape problem.
    """
    if len(lifecycle_seed) != 32:
        raise TelemetryKeygenError(
            f"lifecycle seed must be 32 bytes (got {len(lifecycle_seed)})"
        )

    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise TelemetryKeygenError(f"validator binary not found at {bin_path}")

    timeout = float(getattr(settings, "VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0))
    # The lifecycle seed is a secret — pass it on stdin, never argv (§20).
    seed_hex = lifecycle_seed.hex().encode("ascii")
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "derive-telemetry-key"],
            input=seed_hex,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TelemetryKeygenError("derive-telemetry-key: validator timeout") from exc
    except OSError as exc:
        raise TelemetryKeygenError(
            f"derive-telemetry-key: spawn failed: {exc}"
        ) from exc
    finally:
        seed_hex = b"\x00" * len(seed_hex)

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise TelemetryKeygenError(
            f"derive-telemetry-key: validator exit {completed.returncode}: {stderr}"
        )

    import json

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise TelemetryKeygenError("derive-telemetry-key: stdout is not JSON") from exc
    if not isinstance(payload, dict):
        raise TelemetryKeygenError("derive-telemetry-key: stdout is not a JSON object")

    vk_hex = payload.get("vk_hex")
    if not isinstance(vk_hex, str):
        raise TelemetryKeygenError("derive-telemetry-key: missing vk_hex")
    try:
        vk = bytes.fromhex(vk_hex)
    except ValueError as exc:
        raise TelemetryKeygenError("derive-telemetry-key: vk_hex not hex") from exc
    if len(vk) != 32:
        raise TelemetryKeygenError(
            f"derive-telemetry-key: vk must be 32 bytes (got {len(vk)})"
        )
    return vk
