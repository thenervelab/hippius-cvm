"""§7 — generate a per-VM guest lifecycle Ed25519 keypair.

vali has no Python crypto dependency (``cryptography`` / ``pynacl`` are
deliberately absent — see ``vali/pyproject.toml``); every Ed25519
operation is shelled out to the ``hippius-ticket-validator`` binary. This
module wraps its ``gen-lifecycle-key`` subcommand, which emits
``{"seed_hex","vk_hex"}`` on stdout.

The caller (the launch choreography) then:
  - stages the ``seed`` (PRIVATE / signing key) into Vault at the per-VM
    ``…/lifecycle-key`` path — the key the KBS releases over the §21
    attested channel to the guest, HPKE-sealed so the miner never sees
    it; and
  - records the ``vk`` (PUBLIC key) as ``Vm.lifecycle_vk`` so
    ``_verify_ack`` / ``lifecycle_vk_hex()`` can verify a guest-signed
    §24/§25 StoppedAck.

§20: the seed IS a secret. It crosses exactly one process boundary
(the binary's stdout → this wrapper → the Vault put), is never logged
(only static error classes reach the log), and the caller zeroizes its
buffer reference after staging. The returned ``LifecycleKeypair`` holds
the raw seed bytes; treat it as secret-bearing.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings


class LifecycleKeygenError(Exception):
    """The keygen subprocess could not run or returned bad output. The
    launch path turns this into a TERMINAL outcome — a VM without a
    lifecycle key would silently lose the §24/§25 guest-signed fence.
    """


@dataclass(frozen=True)
class LifecycleKeypair:
    """A freshly generated §7 lifecycle keypair.

    ``seed`` is the 32-byte Ed25519 PRIVATE key (SECRET — stage in Vault,
    never log). ``vk`` is the 32-byte PUBLIC key (non-secret — record on
    ``Vm.lifecycle_vk``).
    """

    seed: bytes
    vk: bytes


def generate_lifecycle_keypair() -> LifecycleKeypair:
    """Run ``hippius-ticket-validator gen-lifecycle-key`` and parse it.

    Raises :class:`LifecycleKeygenError` on any binary / parse / shape
    problem (the caller fails the launch closed rather than provision a
    VM with no lifecycle key).
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise LifecycleKeygenError(f"validator binary not found at {bin_path}")

    timeout = float(getattr(settings, "VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0))
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "gen-lifecycle-key"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LifecycleKeygenError("gen-lifecycle-key: validator timeout") from exc
    except OSError as exc:
        # Never echo the seed; OSError carries no secret here.
        raise LifecycleKeygenError(f"gen-lifecycle-key: spawn failed: {exc}") from exc

    if completed.returncode != 0:
        # stderr is a static classifier; stdout could carry the seed —
        # NEVER surface stdout (§20).
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise LifecycleKeygenError(
            f"gen-lifecycle-key: validator exit {completed.returncode}: {stderr}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        # Do NOT include the raw stdout in the message — it is the seed.
        raise LifecycleKeygenError("gen-lifecycle-key: stdout is not JSON") from exc

    if not isinstance(payload, dict):
        raise LifecycleKeygenError("gen-lifecycle-key: stdout is not a JSON object")

    seed_hex = payload.get("seed_hex")
    vk_hex = payload.get("vk_hex")
    if not isinstance(seed_hex, str) or not isinstance(vk_hex, str):
        raise LifecycleKeygenError("gen-lifecycle-key: missing seed_hex / vk_hex")

    try:
        seed = bytes.fromhex(seed_hex)
        vk = bytes.fromhex(vk_hex)
    except ValueError as exc:
        raise LifecycleKeygenError("gen-lifecycle-key: seed_hex / vk_hex not hex") from exc

    if len(seed) != 32 or len(vk) != 32:
        raise LifecycleKeygenError(
            f"gen-lifecycle-key: seed/vk must be 32 bytes (got {len(seed)}/{len(vk)})"
        )

    return LifecycleKeypair(seed=seed, vk=vk)


def derive_lifecycle_vk(seed: bytes) -> bytes:
    """Run ``hippius-ticket-validator derive-lifecycle-vk`` — re-derive
    the lifecycle PUBLIC key from an already-staged seed.

    Used by the first-write-wins re-launch path: the KBS reads the per-VM
    lifecycle seed at pinned Vault version 1 forever, so a re-launch reuses
    the version-1 seed and re-derives the matching vk instead of rotating
    the keypair (which would desync ``Vm.lifecycle_vk`` + the telemetry
    source from the key the guest actually holds).

    §20: ``seed`` is a secret — passed on STDIN (never argv), never logged.
    Raises :class:`LifecycleKeygenError` on any binary / parse problem.
    """
    if len(seed) != 32:
        raise LifecycleKeygenError(
            f"derive-lifecycle-vk: seed must be 32 bytes (got {len(seed)})"
        )
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise LifecycleKeygenError(f"validator binary not found at {bin_path}")

    timeout = float(getattr(settings, "VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0))
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "derive-lifecycle-vk"],
            input=seed.hex().encode("ascii"),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LifecycleKeygenError("derive-lifecycle-vk: validator timeout") from exc
    except OSError as exc:
        raise LifecycleKeygenError(
            f"derive-lifecycle-vk: spawn failed: {exc}"
        ) from exc

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise LifecycleKeygenError(
            f"derive-lifecycle-vk: validator exit {completed.returncode}: {stderr}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise LifecycleKeygenError("derive-lifecycle-vk: stdout is not JSON") from exc

    vk_hex = payload.get("vk_hex") if isinstance(payload, dict) else None
    if not isinstance(vk_hex, str):
        raise LifecycleKeygenError("derive-lifecycle-vk: missing vk_hex")
    try:
        vk = bytes.fromhex(vk_hex)
    except ValueError as exc:
        raise LifecycleKeygenError("derive-lifecycle-vk: vk_hex not hex") from exc
    if len(vk) != 32:
        raise LifecycleKeygenError(
            f"derive-lifecycle-vk: vk must be 32 bytes (got {len(vk)})"
        )
    return vk
