"""Shell-out wrapper for the §9 telemetry verifier subcommands.

The Rust binary owns the canonical-CBOR + Ed25519 semantics; this
module is the thin Python boundary. vali **never decodes CBOR
itself** — the hostile-origin envelope body is hex-decoded (trivial,
safe) and piped straight to the parser-hardened Rust validator,
which canonical-gates it before any structural decode.

Wire contract with the binary (`verify-edge-telemetry` /
`verify-served-receipt`):

- argv: `--vk-hex <source key>` `--sig-hex <detached sig>`. Both are
  PUBLIC crypto material — no secret ever rides argv.
- stdin: the canonical-CBOR telemetry `body`.
- stdout: `{"tag":"ok"}` or `{"tag":"err","error":"…","category":"…"}`.
- exit: 0 ok, 2 structured rejection, 1 internal.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from .models import EnvelopeKind

log = logging.getLogger("apps.telemetry.verifier")

# `kind` → validator subcommand.
_SUBCOMMAND: dict[str, str] = {
    EnvelopeKind.EDGE_TELEMETRY.value: "verify-edge-telemetry",
    EnvelopeKind.SERVED_RECEIPT.value: "verify-served-receipt",
}


class VerifierError(Exception):
    """Base class — never raised directly."""


class VerifierUnavailable(VerifierError):
    """The Rust binary couldn't run / returned non-structured output.

    Mapped to HTTP 503 — vali is misconfigured / the binary is
    broken, NOT the source's fault. Does NOT count as a poison
    strike against the source.
    """


@dataclass(frozen=True)
class VerifierFailed(VerifierError):
    """The binary parsed the envelope and rejected it.

    Mapped to HTTP 400 and counted as a §9 poison strike against the
    source. `category` ∈ {decode, non-canonical, signature, cbor,
    domain} — see `binaries/ticket-validator/src/telemetry.rs`.
    """

    message: str
    category: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.message}"


def verify_envelope(
    *, kind: str, body: bytes, sig: bytes, verifying_key: bytes
) -> None:
    """Verify one signed telemetry envelope. Returns `None` on
    success; raises `VerifierFailed` (bad envelope) or
    `VerifierUnavailable` (binary problem).
    """
    subcommand = _SUBCOMMAND.get(kind)
    if subcommand is None:
        # An unknown kind should have been rejected before this call.
        raise VerifierUnavailable(f"no verifier subcommand for kind {kind!r}")

    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not body:
        raise VerifierFailed(message="empty telemetry body", category="decode")

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [
        str(bin_path),
        subcommand,
        "--vk-hex",
        verifying_key.hex(),
        "--sig-hex",
        sig.hex(),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=body,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("%s timed out after %.2fs", subcommand, timeout)
        raise VerifierUnavailable(
            f"verifier timed out after {timeout:.2f}s"
        ) from exc
    except OSError as exc:
        log.error("%s spawn failed: %s", subcommand, exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    # Exit 0 (ok) + 2 (structured rejection) both write a JSON
    # envelope; anything else is an internal failure.
    if completed.returncode not in (0, 2):
        log.error(
            "%s internal failure: rc=%s", subcommand, completed.returncode
        )
        raise VerifierUnavailable(
            f"verifier exited with code {completed.returncode}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("%s non-JSON stdout (rc=%s)", subcommand, completed.returncode)
        raise VerifierUnavailable("verifier stdout is not JSON") from exc

    if not isinstance(payload, dict) or "tag" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'tag' field")

    tag = payload["tag"]
    if tag == "ok":
        return
    if tag == "err":
        raise VerifierFailed(
            message=str(payload.get("error", "verifier rejected envelope")),
            category=str(payload.get("category", "unknown")),
        )
    raise VerifierUnavailable(f"verifier returned unknown tag={tag!r}")


@dataclass(frozen=True)
class ServedReceiptFields:
    """The attested billing fields of a verified served-delivery receipt
    (the data-bearing `verify-served-receipt` output). Every field is
    covered by the guest's Ed25519 signature — the miner that relayed the
    receipt cannot forge them."""

    vm_id: str
    lease_id: str
    node_id_hex: str
    epoch: int
    resource_class: str
    period_start: int
    period_end: int
    monotonic_seq: int
    observed_degradation_bps: int


def verify_served_receipt(
    *, body: bytes, sig: bytes, verifying_key: bytes
) -> ServedReceiptFields:
    """Verify a `SignedServedDeliveryReceipt` and return its attested
    billing fields.

    Same shell-out contract as [`verify_envelope`] (`tag` ok/err, exit
    0/2), but the served-receipt `Ok` is **data-bearing** — it carries
    the parsed fields the usage meter bills on, so vali never re-decodes
    the CBOR body. Raises `VerifierFailed` (bad receipt) or
    `VerifierUnavailable` (binary problem).
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not body:
        raise VerifierFailed(message="empty served receipt body", category="decode")

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [
        str(bin_path),
        "verify-served-receipt",
        "--vk-hex",
        verifying_key.hex(),
        "--sig-hex",
        sig.hex(),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=body,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("verify-served-receipt timed out after %.2fs", timeout)
        raise VerifierUnavailable(f"verifier timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("verify-served-receipt spawn failed: %s", exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    if completed.returncode not in (0, 2):
        log.error("verify-served-receipt internal failure: rc=%s", completed.returncode)
        raise VerifierUnavailable(f"verifier exited with code {completed.returncode}")

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise VerifierUnavailable("verifier stdout is not JSON") from exc
    if not isinstance(payload, dict) or "tag" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'tag' field")

    tag = payload["tag"]
    if tag == "err":
        raise VerifierFailed(
            message=str(payload.get("error", "verifier rejected receipt")),
            category=str(payload.get("category", "unknown")),
        )
    if tag != "ok":
        raise VerifierUnavailable(f"verifier returned unknown tag={tag!r}")
    return _served_receipt_fields(payload)


def _served_receipt_fields(payload: dict) -> ServedReceiptFields:
    """Coerce the data-bearing `verify-served-receipt` ok payload into a
    typed `ServedReceiptFields` (fail-closed on a shape drift)."""
    try:
        return ServedReceiptFields(
            vm_id=str(payload["vm_id"]),
            lease_id=str(payload["lease_id"]),
            node_id_hex=str(payload["node_id_hex"]),
            epoch=int(payload["epoch"]),
            resource_class=str(payload["resource_class"]),
            period_start=int(payload["period_start"]),
            period_end=int(payload["period_end"]),
            monotonic_seq=int(payload["monotonic_seq"]),
            observed_degradation_bps=int(payload["observed_degradation_bps"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierUnavailable(
            f"served-receipt ok payload has unexpected shape: {exc}"
        ) from exc


# ─── heartbeat verification (§K / PR-Part4-B) ────────────────────────
#
# `verify-heartbeat` is a SEPARATE shell-out contract from the
# `verify-edge-telemetry` / `verify-served-receipt` pair above:
#
# - it is **data-bearing** — a success returns the decoded body, not
#   just `{"tag":"ok"}` — because vali's §K ingest gate must act on the
#   `timestamp_unix` + `sequence` it can only get from the (Rust-
#   decoded) body;
# - the whole `SignedMinerHeartbeat` envelope rides stdin (no detached
#   `--sig-hex`); only `--vk-hex` is on argv;
# - it exits `0` for ANY validation outcome — the JSON `{"ok":…}`
#   carries the verdict.

# Closed `error_class` vocabulary the `verify-heartbeat` subcommand
# emits on a reject — mirrors `error_class` in
# `binaries/ticket-validator/src/heartbeat.rs`. A value outside this
# set means the binary's contract drifted: a `VerifierUnavailable`.
HEARTBEAT_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "body_too_large",
        "not_canonical_cbor",
        "envelope_decode_failed",
        "signature_invalid",
        "body_decode_failed",
        "wrong_schema_version",
        "wrong_domain",
        "miner_id_invalid",
        # `v3` only: `asid_used > asid_capacity` with a known capacity.
        "capacity_invalid",
        # `v6` only: `agent_version` outside `[0-9A-Za-z._-]{1,32}`.
        "agent_version_invalid",
    }
)

# The four `v3` capacity-declaration keys `verify-heartbeat` emits for a
# `v3` body ONLY (never for `v1`/`v2`).
HEARTBEAT_CAPACITY_KEYS: tuple[str, ...] = (
    "cvm_cpu_budget",
    "cvm_memory_mb_budget",
    "asid_capacity",
    "asid_used",
)


# The four `v4` disk keys `verify-heartbeat` emits for a `v4` body ONLY
# (never for `v1`/`v2`/`v3`). All GiB; `0` = unknown / undeclared.
HEARTBEAT_DISK_KEYS: tuple[str, ...] = (
    "cvm_disk_gb_budget",
    "data_disk_total_gb",
    "data_disk_available_gb",
    "staging_disk_available_gb",
)


# The four `v5` host-health keys `verify-heartbeat` emits for a `v5` body
# ONLY. `snp_enabled` is a JSON bool, the other three integers.
HEARTBEAT_HOST_HEALTH_KEYS: tuple[str, ...] = (
    "snp_enabled",
    "cpus_offline",
    "snp_launches_since_boot",
    "df_flush_failures",
)


# The `v6` `agent_version` (the miner-agent's release tag) — emitted for a
# `v6` body ONLY, after the binary checked it against this same rule
# (`hippius_types::heartbeat::is_valid_agent_version`). Re-checked here as
# defence in depth: the value lands in a DB column and a metric label.
HEARTBEAT_AGENT_VERSION_RE = re.compile(r"[0-9A-Za-z._-]{1,32}")


@dataclass(frozen=True)
class DeclaredHostHealth:
    """A `v5` heartbeat's UNTRUSTED SEV-SNP host-health report, raw.

    - `snp_enabled`             kvm_amd runs with SEV-SNP on.
    - `cpus_offline`            present CPUs that are offline. With
                                SNP on, the firmware then refuses the
                                `DF_FLUSH` that recycles ASIDs, so the host
                                stops launching once its pool is used up.
    - `snp_launches_since_boot` guest starts the agent issued since boot.
    - `df_flush_failures`       kernel `DF_FLUSH failed` lines since boot:
                                every new SNP guest fails until a reboot.

    Observability only — alerted on, never used for placement.
    """

    snp_enabled: bool
    cpus_offline: int
    snp_launches_since_boot: int
    df_flush_failures: int


@dataclass(frozen=True)
class DeclaredDisk:
    """A `v4` heartbeat's UNTRUSTED disk figures, raw (GiB, `0` = unknown).

    - `cvm_disk_gb_budget`        the operator's `[host] cvm_disk_gb_budget`.
    - `data_disk_total_gb` / `data_disk_available_gb`
                                  statvfs total / available (f_bavail) of
                                  the fs holding `[storage].data_disk_root`.
    - `staging_disk_available_gb` statvfs available of the staging fs.

    Disk cannot be attested: the scheduler uses these only as DOWN-ONLY
    terms of the disk budget, so inflating them gains nothing.
    """

    cvm_disk_gb_budget: int
    data_disk_total_gb: int
    data_disk_available_gb: int
    staging_disk_available_gb: int


@dataclass(frozen=True)
class DeclaredCapacity:
    """A `v3` heartbeat's UNTRUSTED capacity declarations, raw.

    `0` in any field means the miner could not read it (unknown). The
    scheduler uses them only as DOWN-ONLY clamps (capacity v2 §2.4), so a
    miner inflating them gains nothing.
    """

    cvm_cpu_budget: int
    cvm_memory_mb_budget: int
    asid_capacity: int
    asid_used: int


@dataclass(frozen=True)
class HeartbeatBody:
    """The decoded heartbeat fields the §K ingest gate acts on.

    A faithful subset of what `verify-heartbeat` returns on success —
    only the fields the replay / skew / identity gates need.
    """

    schema_version: int
    domain: str
    miner_id: str
    timestamp_unix: int
    sequence: int
    # UNTRUSTED self-reported free host RAM (MiB) from the heartbeat body
    # (`verify-heartbeat` echoes it on accept). Used ONLY as a DOWN-ONLY
    # throttle on the scheduler's trusted computed capacity — it can never
    # RAISE a miner's admission bound. `None` when the body carried no
    # metrics (the 5-field graceful-exit body shares this decoder).
    memory_available_mib: int | None = None
    # The `v2` graceful-exit flag (transport (B)). The Rust verifier
    # always emits the key (`false` for a `v1` body), but it is parsed
    # with a `False` default so a `v1`-era verifier output — which never
    # carried the key — still deserialises unchanged. A `True` value
    # means the heartbeat is ALSO a self-requested graceful exit.
    graceful_exit_requested: bool = False
    # The `v3` capacity declarations. `None` for a `v1`/`v2` heartbeat
    # (the verifier emits the keys ONLY for `v3`) — the ingest then leaves
    # the stored declaration untouched rather than clearing it.
    declared_capacity: DeclaredCapacity | None = None
    # The `v4` disk figures. `None` for a `v1`/`v2`/`v3` heartbeat (the
    # verifier emits the keys ONLY for `v4`) — the ingest then leaves the
    # stored figures untouched, exactly like `declared_capacity`.
    declared_disk: DeclaredDisk | None = None
    # The `v5` host-health report. `None` before `v5`, same discipline.
    declared_host_health: DeclaredHostHealth | None = None
    # The `v6` miner-agent release tag. UNTRUSTED, observability only.
    # `None` before `v6`, same discipline.
    agent_version: str | None = None


def verify_heartbeat(*, envelope: bytes, verifying_key: bytes) -> HeartbeatBody:
    """Verify a `SignedMinerHeartbeat` and return its decoded body.

    Shells out to the **data-bearing** `verify-heartbeat` subcommand
    (PR-Part4-A): unlike `verify_envelope`, a success here carries the
    decoded `{timestamp_unix, sequence, miner_id, …}` the §K ingest
    gate needs. The whole canonical-CBOR envelope rides stdin;
    `--vk-hex` is the miner's registered Ed25519 key (public material,
    safe on argv).

    Returns `HeartbeatBody` on accept; raises `VerifierFailed` (the
    envelope was rejected — a §9 poison strike) or `VerifierUnavailable`
    (the binary could not run / answered malformed — vali-side, no
    strike).
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not envelope:
        raise VerifierFailed(
            message="empty heartbeat envelope",
            category="envelope_decode_failed",
        )

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [str(bin_path), "verify-heartbeat", "--vk-hex", verifying_key.hex()]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=envelope,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("verify-heartbeat timed out after %.2fs", timeout)
        raise VerifierUnavailable(
            f"verifier timed out after {timeout:.2f}s"
        ) from exc
    except OSError as exc:
        log.error("verify-heartbeat spawn failed: %s", exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    # `verify-heartbeat` exits 0 for ANY validation outcome (accept OR
    # reject — the JSON `{"ok":…}` carries the verdict). Exit 2 means
    # vali built a malformed `--vk-hex` (a vali bug); exit 1 a
    # stdin/stdout IO failure. Both are vali-side, never the miner's
    # fault — surface as `VerifierUnavailable` (503, no poison strike).
    if completed.returncode != 0:
        log.error("verify-heartbeat non-zero exit: rc=%s", completed.returncode)
        raise VerifierUnavailable(
            f"verifier exited with code {completed.returncode}"
        )

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("verify-heartbeat non-JSON stdout")
        raise VerifierUnavailable("verifier stdout is not JSON") from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'ok' field")

    if payload["ok"] is False:
        error_class = payload.get("error_class")
        if (
            not isinstance(error_class, str)
            or error_class not in HEARTBEAT_ERROR_CLASSES
        ):
            raise VerifierUnavailable(
                "verifier reject carried an unknown error_class"
            )
        raise VerifierFailed(
            message="heartbeat verification failed", category=error_class
        )
    if payload["ok"] is not True:
        raise VerifierUnavailable("verifier 'ok' field is not a boolean")

    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("verifier accept carried no body object")
    return _heartbeat_body(body)


# ── graceful-exit ────────────────────────────────────────────────────
# The miner-self-service graceful-exit request shares the SAME
# data-bearing shell-out contract as the heartbeat (envelope on stdin,
# `--vk-hex` on argv, exit 0 for any verdict, `{ok, body | error_class}`
# JSON), against the `verify-graceful-exit` subcommand. Its body carries
# exactly the five identity/replay fields a `HeartbeatBody` already
# models, so the same dataclass + `_data_bearing_body` parser are reused.

# Closed `error_class` vocabulary `verify-graceful-exit` emits — mirrors
# `error_class` in `binaries/ticket-validator/src/graceful_exit.rs`.
GRACEFUL_EXIT_ERROR_CLASSES: frozenset[str] = HEARTBEAT_ERROR_CLASSES


def verify_graceful_exit(*, envelope: bytes, verifying_key: bytes) -> HeartbeatBody:
    """Verify a `SignedGracefulExit` envelope and return its decoded body.

    Same data-bearing shell-out as [`verify_heartbeat`], against the
    `verify-graceful-exit` subcommand: the whole canonical-CBOR envelope
    rides stdin, `--vk-hex` is the miner's registered key. Returns the
    five-field body (`schema_version, domain, miner_id, timestamp_unix,
    sequence`) so the endpoint can run the skew + replay gates. Raises
    `VerifierFailed` (miner-side reject) or `VerifierUnavailable`.
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not envelope:
        raise VerifierFailed(
            message="empty graceful-exit envelope",
            category="envelope_decode_failed",
        )

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [str(bin_path), "verify-graceful-exit", "--vk-hex", verifying_key.hex()]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=envelope,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("verify-graceful-exit timed out after %.2fs", timeout)
        raise VerifierUnavailable(f"verifier timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("verify-graceful-exit spawn failed: %s", exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    if completed.returncode != 0:
        log.error("verify-graceful-exit non-zero exit: rc=%s", completed.returncode)
        raise VerifierUnavailable(f"verifier exited with code {completed.returncode}")

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("verify-graceful-exit non-JSON stdout")
        raise VerifierUnavailable("verifier stdout is not JSON") from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'ok' field")

    if payload["ok"] is False:
        error_class = payload.get("error_class")
        if not isinstance(error_class, str) or error_class not in GRACEFUL_EXIT_ERROR_CLASSES:
            raise VerifierUnavailable("verifier reject carried an unknown error_class")
        raise VerifierFailed(message="graceful-exit verification failed", category=error_class)
    if payload["ok"] is not True:
        raise VerifierUnavailable("verifier 'ok' field is not a boolean")

    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("verifier accept carried no body object")
    return _heartbeat_body(body)


# ── vm boot-progress ─────────────────────────────────────────────────
# The miner-agent's guest-boot progress milestone shares the SAME
# data-bearing shell-out contract as the heartbeat / graceful-exit
# (envelope on stdin, `--vk-hex` on argv, exit 0 for any verdict,
# `{ok, body | error_class}` JSON), against the `verify-vm-progress`
# subcommand. Its body carries a `vm_id` + a `milestone` on top of the
# usual identity/replay fields, so it gets its own `VmProgressBody`.

# Closed `error_class` vocabulary `verify-vm-progress` emits — the
# graceful-exit set PLUS the two vm-progress-specific rejects
# (`vm_id_invalid`, `milestone_invalid`). Mirrors `error_class` in
# `binaries/ticket-validator/src/vm_progress.rs`.
VM_PROGRESS_ERROR_CLASSES: frozenset[str] = GRACEFUL_EXIT_ERROR_CLASSES | frozenset(
    {
        "vm_id_invalid",
        "milestone_invalid",
    }
)


@dataclass(frozen=True)
class VmProgressBody:
    """The decoded guest-boot progress fields the ingest gate acts on.

    A faithful subset of what `verify-vm-progress` returns on success.
    `milestone` is the HYPHEN wire value (`booting` | `kek-released` |
    `running` | `awaiting-guardian`); the endpoint maps the first three to
    the underscore `VmBootPhase` choice via `Vm.advance_boot_phase`.
    `reason` is the closed-vocabulary guardian wait reason the binary
    verified alongside `awaiting-guardian` (the only milestone with one),
    else `None`.
    """

    schema_version: int
    domain: str
    miner_id: str
    vm_id: str
    milestone: str
    timestamp_unix: int
    reason: str | None = None


def verify_vm_progress(*, envelope: bytes, verifying_key: bytes) -> VmProgressBody:
    """Verify a `SignedVmProgress` envelope and return its decoded body.

    Same data-bearing shell-out as [`verify_graceful_exit`], against the
    `verify-vm-progress` subcommand: the whole canonical-CBOR envelope
    rides stdin, `--vk-hex` is the miner's registered key. Returns the
    six-field body (`schema_version, domain, miner_id, vm_id, milestone,
    timestamp_unix`), plus `reason` for an `awaiting-guardian` milestone,
    so the endpoint can run the identity + skew gates and advance the VM's
    boot phase. Raises `VerifierFailed` (miner-side
    reject) or `VerifierUnavailable`.
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not envelope:
        raise VerifierFailed(
            message="empty vm-progress envelope",
            category="envelope_decode_failed",
        )

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [str(bin_path), "verify-vm-progress", "--vk-hex", verifying_key.hex()]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=envelope,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("verify-vm-progress timed out after %.2fs", timeout)
        raise VerifierUnavailable(f"verifier timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("verify-vm-progress spawn failed: %s", exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    if completed.returncode != 0:
        log.error("verify-vm-progress non-zero exit: rc=%s", completed.returncode)
        raise VerifierUnavailable(f"verifier exited with code {completed.returncode}")

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("verify-vm-progress non-JSON stdout")
        raise VerifierUnavailable("verifier stdout is not JSON") from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'ok' field")

    if payload["ok"] is False:
        error_class = payload.get("error_class")
        if not isinstance(error_class, str) or error_class not in VM_PROGRESS_ERROR_CLASSES:
            raise VerifierUnavailable("verifier reject carried an unknown error_class")
        raise VerifierFailed(message="vm-progress verification failed", category=error_class)
    if payload["ok"] is not True:
        raise VerifierUnavailable("verifier 'ok' field is not a boolean")

    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("verifier accept carried no body object")
    return _vm_progress_body(body)


def _vm_progress_body(body: dict[str, object]) -> VmProgressBody:
    """Extract + type-check the vm-progress fields the gate needs.

    The Rust binary already guarantees the shape; this is defence in
    depth. A missing / wrong-typed field means the binary's contract
    drifted — a `VerifierUnavailable` (vali-side), not a miner fault.
    """

    def _int(name: str) -> int:
        value = body.get(name)
        # JSON booleans are `bool`, an `int` subclass — exclude them.
        if isinstance(value, bool) or not isinstance(value, int):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not an integer"
            )
        return value

    def _str(name: str) -> str:
        value = body.get(name)
        if not isinstance(value, str):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not a string"
            )
        return value

    milestone = _str("milestone")
    reason: str | None = None
    if "reason" in body:
        reason = _str("reason")
    # The binary pairs them (a reason iff `awaiting-guardian`); a body that
    # does not is a drifted contract, never something to act on.
    if (reason is not None) != (milestone == "awaiting-guardian"):
        raise VerifierUnavailable("verifier body pairs milestone and reason inconsistently")
    return VmProgressBody(
        schema_version=_int("schema_version"),
        domain=_str("domain"),
        miner_id=_str("miner_id"),
        vm_id=_str("vm_id"),
        milestone=milestone,
        timestamp_unix=_int("timestamp_unix"),
        reason=reason,
    )


# ── blackbox host-attestor (PR-8, INERT) ─────────────────────────────
#
# Two more data-bearing shell-outs, same contract as `verify-vm-progress`
# (envelope on stdin, `--vk-hex` on argv, exit 0 for any verdict,
# `{ok, body | error_class}` JSON): `verify-host-attestor-cert` and
# `verify-host-beacon`. vali never decodes the host-attestor CBOR in
# Python — the parser-hardened Rust validator owns the canonical-CBOR +
# Ed25519 semantics and returns the decoded fields the ingest gate acts
# on (chip_id / measurement / node_id / seq / expiry).

# Closed `error_class` vocabulary shared by both host-attestor
# subcommands — mirrors `error_class` in
# `binaries/ticket-validator/src/{host_attestor_cert,host_beacon}.rs`.
HOST_ATTESTOR_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "body_too_large",
        "not_canonical_cbor",
        "envelope_decode_failed",
        "signature_invalid",
        "body_decode_failed",
    }
)


@dataclass(frozen=True)
class HostAttestorCertFields:
    """The decoded, KBS-attested fields of a host-attestor enrollment cert.

    `verified` echoes whether the Rust binary actually checked the KBS L0
    signature (`True` only when vali supplied the KBS L0 verifying key).
    When `False`, every other field is structurally decoded but the KBS
    L0 signature was NOT verified — the ingest gate MUST treat the row as
    `pending` (see `service.ingest_host_attestor_cert`).
    """

    verified: bool
    schema_version: int
    node_id: str
    chip_id_hex: str
    attestor_pubkey_hex: str
    measurement_hex: str
    tcb: int
    nonce_hex: str
    expiry_unix: int


@dataclass(frozen=True)
class HostBeaconFields:
    """The decoded fields of a host-attestor liveness beacon, verified
    against the CERTIFIED `signer_pubkey` vali supplied (never the
    beacon's self-declared key)."""

    schema_version: int
    chip_id_hex: str
    measurement_hex: str
    node_id: str
    boot_id: str
    seq: int
    observed_at_unix: int
    policy: int
    nonce_hex: str
    signer_pubkey_hex: str
    expiry_unix: int


def _run_host_attestor(
    subcommand: str, *, envelope: bytes, argv_extra: list[str]
) -> dict[str, object]:
    """Shared data-bearing shell-out for the host-attestor subcommands.

    Returns the parsed `{ok, ...}` JSON dict on a clean run; raises
    `VerifierFailed` (a closed-vocabulary `error_class` reject — a §9
    poison strike) or `VerifierUnavailable` (the binary could not run /
    answered malformed — vali-side, no strike).
    """
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise VerifierUnavailable(f"validator binary not found at {bin_path}")
    if not envelope:
        raise VerifierFailed(
            message=f"empty {subcommand} envelope",
            category="envelope_decode_failed",
        )

    timeout = float(settings.VALI_TICKET_VALIDATOR_TIMEOUT_S)
    argv = [str(bin_path), subcommand, *argv_extra]
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            argv,
            input=envelope,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        log.error("%s timed out after %.2fs", subcommand, timeout)
        raise VerifierUnavailable(f"verifier timed out after {timeout:.2f}s") from exc
    except OSError as exc:
        log.error("%s spawn failed: %s", subcommand, exc)
        raise VerifierUnavailable(f"verifier spawn failed: {exc}") from exc

    # Exit 0 for ANY validation outcome; 2 = malformed argv (vali bug),
    # 1 = stdin/stdout IO. Both are vali-side (503, no poison strike).
    if completed.returncode != 0:
        log.error("%s non-zero exit: rc=%s", subcommand, completed.returncode)
        raise VerifierUnavailable(f"verifier exited with code {completed.returncode}")

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        log.error("%s non-JSON stdout", subcommand)
        raise VerifierUnavailable("verifier stdout is not JSON") from exc
    if not isinstance(payload, dict) or "ok" not in payload:
        raise VerifierUnavailable("verifier stdout missing 'ok' field")

    if payload["ok"] is False:
        error_class = payload.get("error_class")
        if (
            not isinstance(error_class, str)
            or error_class not in HOST_ATTESTOR_ERROR_CLASSES
        ):
            raise VerifierUnavailable("verifier reject carried an unknown error_class")
        raise VerifierFailed(
            message=f"{subcommand} verification failed", category=error_class
        )
    if payload["ok"] is not True:
        raise VerifierUnavailable("verifier 'ok' field is not a boolean")
    return payload


def verify_host_attestor_cert(
    *, envelope: bytes, verifying_key: bytes | None
) -> HostAttestorCertFields:
    """Verify + decode a `SignedHostAttestorCert` (blackbox host-attestor
    PR-8).

    `verifying_key` is the KBS L0 Ed25519 public key OR `None`. When a key
    is supplied the Rust binary Ed25519-verifies the cert signature and
    returns `verified=True`; when `None` (vali does not hold the KBS L0
    pubkey — the documented seam) the cert is decode-only and returns
    `verified=False`, and the ingest gate persists a `pending` row.

    Raises `VerifierFailed` (a malformed / bad-signature cert) or
    `VerifierUnavailable` (the binary could not run).
    """
    argv_extra = [] if verifying_key is None else ["--vk-hex", verifying_key.hex()]
    payload = _run_host_attestor(
        "verify-host-attestor-cert", envelope=envelope, argv_extra=argv_extra
    )
    verified = payload.get("verified")
    if not isinstance(verified, bool):
        raise VerifierUnavailable("cert accept carried no boolean 'verified'")
    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("cert accept carried no body object")
    return _host_cert_fields(verified, body)


def verify_host_beacon(*, envelope: bytes, verifying_key: bytes) -> HostBeaconFields:
    """Verify + decode a `SignedHostBeacon` against the CERTIFIED attestor
    key `verifying_key` (blackbox host-attestor PR-8).

    `verifying_key` is the `signer_pubkey` the KBS L0 cert pinned for this
    host (read from the stored `HostAttestor` row) — a beacon signed by
    any other key (including its own self-declared `signer_pubkey`) fails
    closed in the Rust binary. Raises `VerifierFailed` (bad beacon) or
    `VerifierUnavailable` (the binary could not run).
    """
    payload = _run_host_attestor(
        "verify-host-beacon",
        envelope=envelope,
        argv_extra=["--vk-hex", verifying_key.hex()],
    )
    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("beacon accept carried no body object")
    return _host_beacon_fields(body)


@dataclass(frozen=True)
class HostChallengeRequestFields:
    """The decoded fields of a host-attestor nonce-challenge request
    (blackbox host-attestor PR-10). Decode-only — the request carries no
    signature; vali binds the minted nonce to `{peer-stamped node_id,
    signer_pubkey_hex}`."""

    schema_version: int
    signer_pubkey_hex: str


def verify_host_challenge_request(*, envelope: bytes) -> HostChallengeRequestFields:
    """Decode a hostile-origin `HostChallengeRequest` (blackbox
    host-attestor PR-10) and surface the `signer_pubkey` WITHOUT decoding
    CBOR in Python.

    Decode-only (no signature). Raises `VerifierFailed` (malformed request)
    or `VerifierUnavailable` (the binary could not run)."""
    payload = _run_host_attestor(
        "verify-host-challenge-request", envelope=envelope, argv_extra=[]
    )
    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("challenge-request accept carried no body object")
    try:
        return HostChallengeRequestFields(
            schema_version=_ha_int(body, "schema_version"),
            signer_pubkey_hex=_ha_str(body, "signer_pubkey_hex"),
        )
    except VerifierUnavailable:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierUnavailable(
            f"challenge-request body has unexpected shape: {exc}"
        ) from exc


def _host_cert_fields(verified: bool, body: dict[str, object]) -> HostAttestorCertFields:
    """Type-check the host-attestor cert body (defence in depth — the Rust
    binary already guarantees the shape; a drift is a `VerifierUnavailable`)."""
    try:
        return HostAttestorCertFields(
            verified=verified,
            schema_version=_ha_int(body, "schema_version"),
            node_id=_ha_str(body, "node_id"),
            chip_id_hex=_ha_str(body, "chip_id_hex"),
            attestor_pubkey_hex=_ha_str(body, "attestor_pubkey_hex"),
            measurement_hex=_ha_str(body, "measurement_hex"),
            tcb=_ha_int(body, "tcb"),
            nonce_hex=_ha_str(body, "nonce_hex"),
            expiry_unix=_ha_int(body, "expiry_unix"),
        )
    except VerifierUnavailable:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierUnavailable(f"cert body has unexpected shape: {exc}") from exc


def _host_beacon_fields(body: dict[str, object]) -> HostBeaconFields:
    """Type-check the host-attestor beacon body (defence in depth)."""
    try:
        return HostBeaconFields(
            schema_version=_ha_int(body, "schema_version"),
            chip_id_hex=_ha_str(body, "chip_id_hex"),
            measurement_hex=_ha_str(body, "measurement_hex"),
            node_id=_ha_str(body, "node_id"),
            boot_id=_ha_str(body, "boot_id"),
            seq=_ha_int(body, "seq"),
            observed_at_unix=_ha_int(body, "observed_at_unix"),
            policy=_ha_int(body, "policy"),
            nonce_hex=_ha_str(body, "nonce_hex"),
            signer_pubkey_hex=_ha_str(body, "signer_pubkey_hex"),
            expiry_unix=_ha_int(body, "expiry_unix"),
        )
    except VerifierUnavailable:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierUnavailable(f"beacon body has unexpected shape: {exc}") from exc


def _ha_int(body: dict[str, object], name: str) -> int:
    value = body.get(name)
    # JSON booleans are `bool`, an `int` subclass — exclude them.
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerifierUnavailable(f"host-attestor body field {name!r} is not an integer")
    return value


def _ha_str(body: dict[str, object], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str):
        raise VerifierUnavailable(f"host-attestor body field {name!r} is not a string")
    return value


def _heartbeat_body(body: dict[str, object]) -> HeartbeatBody:
    """Extract + type-check the heartbeat fields the gate needs.

    The Rust binary already guarantees the shape; this is defence in
    depth. A missing / wrong-typed field means the binary's contract
    drifted — a `VerifierUnavailable` (vali-side), not a miner fault.
    """

    def _int(name: str) -> int:
        value = body.get(name)
        # JSON booleans are `bool`, an `int` subclass — exclude them.
        if isinstance(value, bool) or not isinstance(value, int):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not an integer"
            )
        return value

    def _str(name: str) -> str:
        value = body.get(name)
        if not isinstance(value, str):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not a string"
            )
        return value

    def _opt_uint(name: str) -> int | None:
        # An OPTIONAL non-negative metric. ABSENT (the 5-field graceful-
        # exit body) → `None`. PRESENT must be a non-negative, non-bool
        # int, else the binary's contract drifted (`VerifierUnavailable`,
        # vali-side — not a miner fault).
        value = body.get(name)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not an integer"
            )
        if value < 0:
            raise VerifierUnavailable(
                f"verifier body field {name!r} is negative"
            )
        return value

    def _bool_default_false(name: str) -> bool:
        # The `v2` flag. ABSENT is the backward-compatible case (a `v1`
        # body, or the graceful-exit verifier's 5-field body) → `False`.
        # PRESENT must be a genuine JSON bool, else the binary's contract
        # drifted (a `VerifierUnavailable`, vali-side — not a miner fault).
        value = body.get(name)
        if value is None:
            return False
        if not isinstance(value, bool):
            raise VerifierUnavailable(
                f"verifier body field {name!r} is not a boolean"
            )
        return value

    def _declared_capacity() -> DeclaredCapacity | None:
        # All four keys or none: the binary emits them together for a
        # `v3` body only. A partial set is contract drift.
        present = [key for key in HEARTBEAT_CAPACITY_KEYS if key in body]
        if not present:
            return None
        if len(present) != len(HEARTBEAT_CAPACITY_KEYS):
            raise VerifierUnavailable(
                "verifier body carried a partial capacity declaration"
            )
        values = {key: _opt_uint(key) for key in HEARTBEAT_CAPACITY_KEYS}
        if any(v is None for v in values.values()):
            raise VerifierUnavailable(
                "verifier body carried a null capacity declaration"
            )
        return DeclaredCapacity(
            cvm_cpu_budget=_int("cvm_cpu_budget"),
            cvm_memory_mb_budget=_int("cvm_memory_mb_budget"),
            asid_capacity=_int("asid_capacity"),
            asid_used=_int("asid_used"),
        )

    def _declared_disk() -> DeclaredDisk | None:
        # All four keys or none: the binary emits them together for a `v4`
        # body only. A partial set is contract drift.
        present = [key for key in HEARTBEAT_DISK_KEYS if key in body]
        if not present:
            return None
        if len(present) != len(HEARTBEAT_DISK_KEYS):
            raise VerifierUnavailable("verifier body carried a partial disk declaration")
        values = {key: _opt_uint(key) for key in HEARTBEAT_DISK_KEYS}
        if any(v is None for v in values.values()):
            raise VerifierUnavailable("verifier body carried a null disk declaration")
        return DeclaredDisk(
            cvm_disk_gb_budget=_int("cvm_disk_gb_budget"),
            data_disk_total_gb=_int("data_disk_total_gb"),
            data_disk_available_gb=_int("data_disk_available_gb"),
            staging_disk_available_gb=_int("staging_disk_available_gb"),
        )

    def _declared_host_health() -> DeclaredHostHealth | None:
        # All four keys or none: the binary emits them together for a `v5`
        # body only. A partial set, or a wrong type, is contract drift.
        present = [key for key in HEARTBEAT_HOST_HEALTH_KEYS if key in body]
        if not present:
            return None
        if len(present) != len(HEARTBEAT_HOST_HEALTH_KEYS):
            raise VerifierUnavailable(
                "verifier body carried a partial host-health report"
            )
        if not isinstance(body["snp_enabled"], bool):
            raise VerifierUnavailable(
                "verifier body field 'snp_enabled' is not a boolean"
            )
        counts = {key: _opt_uint(key) for key in HEARTBEAT_HOST_HEALTH_KEYS[1:]}
        if any(v is None for v in counts.values()):
            raise VerifierUnavailable("verifier body carried a null host-health report")
        return DeclaredHostHealth(
            snp_enabled=body["snp_enabled"],
            cpus_offline=_int("cpus_offline"),
            snp_launches_since_boot=_int("snp_launches_since_boot"),
            df_flush_failures=_int("df_flush_failures"),
        )

    def _agent_version(host_health: DeclaredHostHealth | None) -> str | None:
        # `v6` only, and `v6` is a superset of `v5`: the key without the
        # host-health report, a non-string, or a value outside the charset
        # is contract drift.
        if "agent_version" not in body:
            return None
        value = body["agent_version"]
        if not isinstance(value, str) or not HEARTBEAT_AGENT_VERSION_RE.fullmatch(value):
            raise VerifierUnavailable("verifier body field 'agent_version' is malformed")
        if host_health is None:
            raise VerifierUnavailable(
                "verifier body carried agent_version without a host-health report"
            )
        return value

    host_health = _declared_host_health()
    return HeartbeatBody(
        schema_version=_int("schema_version"),
        domain=_str("domain"),
        miner_id=_str("miner_id"),
        timestamp_unix=_int("timestamp_unix"),
        sequence=_int("sequence"),
        memory_available_mib=_opt_uint("memory_available_mib"),
        graceful_exit_requested=_bool_default_false("graceful_exit_requested"),
        declared_capacity=_declared_capacity(),
        declared_disk=_declared_disk(),
        declared_host_health=host_health,
        agent_version=_agent_version(host_health),
    )


# ─── tenant-CVM live attestation (§23 uptime-coverage meter) ─────────
#
# `verify-live-attestation` — one more data-bearing shell-out, same
# contract as the host-attestor pair (envelope on stdin, `--vk-hex` on
# argv, exit 0 for any verdict, `{ok, body | error_class}` JSON).
#
# ONE DIFFERENCE, deliberate: `--vk-hex` is REQUIRED. The host-attestor
# cert path has a documented "KBS L0 pubkey not wired" seam that returns
# `verified:false` and persists a `pending` row. There is no such seam
# here — an unverified live attestation is worth nothing (a miner could
# mint one itself), so vali refuses to call the binary at all without a
# key rather than handle a decode-only result it might mistake for
# coverage.


# Closed `error_class` vocabulary — mirrors `error_class` in
# `binaries/ticket-validator/src/live_attestation.rs`.
LIVE_ATTESTATION_ERROR_CLASSES: frozenset[str] = frozenset(
    {
        "body_too_large",
        "not_canonical_cbor",
        "envelope_decode_failed",
        "signature_invalid",
        "body_decode_failed",
        "signer_mismatch",
    }
)


@dataclass(frozen=True)
class LiveAttestationFields:
    """The decoded body of a KBS-L0-signed tenant-CVM live attestation.

    Every field here is a value the KBS attested AFTER verifying a fresh
    SNP report against AMD's silicon root + the §22 measurement
    allowlist, with a single-use KBS nonce bound into `REPORT_DATA`. None
    of it is relay-declared: the miner that carried the bytes cannot
    change any of them without breaking the L0 signature.
    """

    schema_version: int
    vm_id: str
    node_id_hex: str
    attestation_seq: int
    epoch: int
    observed_at_unix: int
    verified_at_unix: int
    expiry_unix: int
    measurement_hex: str
    snp_report_digest_hex: str
    vcek_chain_digest_hex: str
    prev_attestation_hash_hex: str
    signer_pubkey_hex: str
    chain_genesis_hex: str
    pallet_instance_hex: str
    body_digest_hex: str
    # Schema v2 only (all three `None` on v1): the guest the KBS bound
    # this `vm_id` to — its SNP CHIP_ID and PSP-assigned REPORT_ID, and
    # whether that binding was recorded at the §20 release (`release`) or
    # is merely the guest that asked, with no release on record — e.g.
    # after a KBS restart (`first-use`).
    binding_source: str | None = None
    chip_id_hex: str | None = None
    report_id_hex: str | None = None
    # Schema v3 only (all four `None` before): what the guest attested it
    # runs with — vCPUs online, the firmware map's `System RAM` (KiB, `0`
    # when the guest kernel has no firmware map), `MemTotal` (KiB) and the
    # RAM it has not accepted yet (KiB). Bound into the PSP-signed
    # REPORT_DATA, so the relaying miner cannot change them; see
    # `apps.telemetry.guest_resources`.
    vcpus_online: int | None = None
    mem_firmware_kib: int | None = None
    mem_total_kib: int | None = None
    mem_unaccepted_kib: int | None = None
    # Schema v4 only (all `None` before): the guest components release the
    # guest attested it booted, its security epoch, the health bitmap of
    # its agents (`hippius_types::live_attestation::components_health`),
    # the keepalive process's random instance and how many of that
    # process's ticks found a check failing (counted in the guest before
    # anything leaves it). See docs/design/guest-component-rollout.md.
    components_release_version: int | None = None
    components_security_epoch: int | None = None
    components_health: int | None = None
    components_instance: int | None = None
    components_unhealthy_ticks: int | None = None


#: `schema_version` of a body that carries the guest binding.
LIVE_ATTESTATION_SCHEMA_VERSION_BOUND = 2
#: `schema_version` of a body that carries the attested guest resources
#: (and the guest binding when the KBS runs a binding mode).
LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES = 3
#: `schema_version` of a body that carries the attested guest components
#: (the binding and the resources each optional).
LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS = 4
_U32_MAX = 2**32 - 1
LIVE_ATTESTATION_BINDING_SOURCES: frozenset[str] = frozenset({"release", "first-use"})
_CHIP_ID_HEX_LEN = 128
_REPORT_ID_HEX_LEN = 64


def _live_attestation_binding(
    body: dict[str, object], schema_version: int
) -> tuple[str | None, str | None, str | None]:
    """The v2 guest-binding triple, or all `None` on v1. The Rust binary
    guarantees v1 ⇔ absent and v2 ⇔ present; a drift is vali-side."""
    names = ("binding_source", "chip_id_hex", "report_id_hex")
    present = [body.get(n) is not None for n in names]
    if (
        schema_version
        in (LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES, LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS)
        and not any(present)
    ):
        return None, None, None
    if schema_version not in (
        LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
        LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
        LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS,
    ):
        if any(present):
            raise VerifierUnavailable("v1 live-attestation body carries a guest binding")
        return None, None, None
    source, chip, report = (_ha_str(body, n) for n in names)
    if source not in LIVE_ATTESTATION_BINDING_SOURCES:
        raise VerifierUnavailable(f"unknown live-attestation binding_source {source!r}")
    for name, value, length in (
        ("chip_id_hex", chip, _CHIP_ID_HEX_LEN),
        ("report_id_hex", report, _REPORT_ID_HEX_LEN),
    ):
        if len(value) != length or not all(c in "0123456789abcdef" for c in value):
            raise VerifierUnavailable(f"live-attestation {name} is not {length} lower hex")
    return source, chip, report


def _live_attestation_resources(
    body: dict[str, object], schema_version: int
) -> tuple[int | None, int | None, int | None, int | None]:
    """The resource quadruple: required on v3, optional (all or none) on
    v4, absent before. As for the binding, the Rust binary guarantees the
    shape; a drift is vali-side."""
    names = ("vcpus_online", "mem_firmware_kib", "mem_total_kib", "mem_unaccepted_kib")
    if schema_version == LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS and not any(
        body.get(n) is not None for n in names
    ):
        return None, None, None, None
    if schema_version not in (
        LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
        LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS,
    ):
        if any(body.get(n) is not None for n in names):
            raise VerifierUnavailable("pre-v3 live-attestation body carries guest resources")
        return None, None, None, None
    vcpus, mem_fw, mem_total, mem_unaccepted = (_ha_int(body, n) for n in names)
    if vcpus <= 0 or mem_total <= 0 or mem_fw < 0 or mem_unaccepted < 0:
        raise VerifierUnavailable("live-attestation guest resources out of range")
    return vcpus, mem_fw, mem_total, mem_unaccepted


_COMPONENT_NAMES = (
    "components_release_version",
    "components_security_epoch",
    "components_health",
    "components_instance",
    "components_unhealthy_ticks",
)


def _live_attestation_components(
    body: dict[str, object], schema_version: int
) -> tuple[int | None, int | None, int | None, int | None, int | None]:
    """The v4 components quintuple, or all `None` before v4."""
    if schema_version != LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS:
        if any(body.get(n) is not None for n in _COMPONENT_NAMES):
            raise VerifierUnavailable("pre-v4 live-attestation body carries guest components")
        return None, None, None, None, None
    values = tuple(_ha_int(body, n) for n in _COMPONENT_NAMES)
    if any(v < 0 or v > _U32_MAX for v in values):
        raise VerifierUnavailable("live-attestation guest components out of range")
    return values  # type: ignore[return-value]


def verify_live_attestation(
    *, envelope: bytes, verifying_key: bytes | None
) -> LiveAttestationFields:
    """Verify + decode a `SignedLiveAttestation` against the pinned KBS L0
    key (§23 uptime coverage).

    `verifying_key` is MANDATORY and must be the 32-byte KBS L0 public
    key. A `None`/short key is a `VerifierUnavailable` (a vali
    misconfiguration, not a miner fault) — never a silent decode-only
    pass. Raises `VerifierFailed` on any bad attestation.
    """
    if not verifying_key or len(verifying_key) != 32:
        raise VerifierUnavailable(
            "live-attestation verification requires a 32-byte KBS L0 key"
        )
    payload = _run_host_attestor(
        "verify-live-attestation",
        envelope=envelope,
        argv_extra=["--vk-hex", verifying_key.hex()],
    )
    body = payload.get("body")
    if not isinstance(body, dict):
        raise VerifierUnavailable("live-attestation accept carried no body object")
    try:
        schema_version = _ha_int(body, "schema_version")
        binding_source, chip_id_hex, report_id_hex = _live_attestation_binding(
            body, schema_version
        )
        vcpus_online, mem_firmware_kib, mem_total_kib, mem_unaccepted_kib = (
            _live_attestation_resources(body, schema_version)
        )
        (
            components_release_version,
            components_security_epoch,
            components_health,
            components_instance,
            components_unhealthy_ticks,
        ) = _live_attestation_components(body, schema_version)
        return LiveAttestationFields(
            schema_version=schema_version,
            vm_id=_ha_str(body, "vm_id"),
            node_id_hex=_ha_str(body, "node_id_hex"),
            attestation_seq=_ha_int(body, "attestation_seq"),
            epoch=_ha_int(body, "epoch"),
            observed_at_unix=_ha_int(body, "observed_at_unix"),
            verified_at_unix=_ha_int(body, "verified_at_unix"),
            expiry_unix=_ha_int(body, "expiry_unix"),
            measurement_hex=_ha_str(body, "measurement_hex"),
            snp_report_digest_hex=_ha_str(body, "snp_report_digest_hex"),
            vcek_chain_digest_hex=_ha_str(body, "vcek_chain_digest_hex"),
            prev_attestation_hash_hex=_ha_str(body, "prev_attestation_hash_hex"),
            signer_pubkey_hex=_ha_str(body, "signer_pubkey_hex"),
            chain_genesis_hex=_ha_str(body, "chain_genesis_hex"),
            pallet_instance_hex=_ha_str(body, "pallet_instance_hex"),
            body_digest_hex=_ha_str(body, "body_digest_hex"),
            binding_source=binding_source,
            chip_id_hex=chip_id_hex,
            report_id_hex=report_id_hex,
            vcpus_online=vcpus_online,
            mem_firmware_kib=mem_firmware_kib,
            mem_total_kib=mem_total_kib,
            mem_unaccepted_kib=mem_unaccepted_kib,
            components_release_version=components_release_version,
            components_security_epoch=components_security_epoch,
            components_health=components_health,
            components_instance=components_instance,
            components_unhealthy_ticks=components_unhealthy_ticks,
        )
    except VerifierUnavailable:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise VerifierUnavailable(
            f"live-attestation body has unexpected shape: {exc}"
        ) from exc
