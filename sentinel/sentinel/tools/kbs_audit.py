"""KBS audit-log reader + chain verifier (PR-S2).

Mirrors `kbs_core::audit::walk_log` in Python so the sentinel can
independently verify the on-disk hash chain produced by
`FileAuditSink`. The Rust implementation is the source of truth — every
canonical-CBOR + domain + prev_hash + body-SHA256 rule that produces
records must be reflected here exactly, otherwise the verifier silently
accepts tampered records (or rejects valid ones).

## Wire format (must stay aligned with `kbs-core/src/audit.rs`)

`audit.log` is newline-delimited; each line is

    {seq_decimal}:{hex_body}:{hex_hash}\\n

where `body` is the canonical-CBOR encoding (RFC 8949 §4.2.1) of a
fixed map:

    {
      "domain":    "HIPPIUS_KBS_AUDIT_V1",
      "granted":   bool,
      "now_unix":  uint64,
      "prev_hash": bstr(32),         # all-zeros for seq==0
      "reason":    text,
      "seq":       uint64,           # must equal the line seq
      "ticket_id": text,             # "" if absent
      "vm_id":     text,             # "" if absent
    }

`hash` is `SHA256(body)`. `head.sha256` is a 32-byte binary file
containing the last record's hash; an empty / all-zero head means the
chain is fresh.

## Tamper-detection surface

`verify_chain` matches the Rust `walk_log` checks:

  - Canonical CBOR (decoded → re-encoded canonical == original bytes).
    Catches map-key-reorder, indefinite-length, non-shortest-int.
  - Strict schema (exactly the 8 keys above, correct types, no extras).
  - `domain == AUDIT_DOMAIN`.
  - Line `seq` decimal == body `seq` == position in the log.
  - On-disk hash bytes == `SHA256(body)`.
  - `body.prev_hash == sha256(previous body)`, with all-zeros for the
    first record. Catches any record being inserted, removed, or
    reordered.
  - If `head.sha256` exists, it equals the recomputed tail hash.
  - If the log is empty/missing while `head.sha256` is non-zero, the
    chain is treated as tampered.

The verifier does NOT take the cross-process advisory lock the Rust
sink uses for writes. Sentinel is read-only — concurrent appends from
KBS will at worst cause the verifier to see a torn final line (which
fails parsing, surfaces as a transient error, and retries cleanly on
the next loop iteration).
"""

from __future__ import annotations

import binascii
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cbor2
from claude_agent_sdk import tool

log = logging.getLogger("sentinel.tools.kbs_audit")

# Pinned to the Rust constant. Any change MUST land in lockstep with
# `kbs-core/src/audit.rs::AUDIT_DOMAIN` — `tests/fixtures/audit_known_good`
# is the cross-impl compatibility witness.
AUDIT_DOMAIN = "HIPPIUS_KBS_AUDIT_V1"
LOG_FILENAME = "audit.log"
HEAD_FILENAME = "head.sha256"

# Required schema. Order is irrelevant for verification (we re-encode
# canonically) but each key is mandatory and there must be no extras.
_REQUIRED_KEYS: frozenset[str] = frozenset({
    "domain",
    "granted",
    "now_unix",
    "prev_hash",
    "reason",
    "seq",
    "ticket_id",
    "vm_id",
})

_ZERO32: bytes = bytes(32)

ENV_AUDIT_DIR = "KBS_AUDIT_LOG_PATH"

# Bound on how many tail records the agent can pull in one call. The
# LLM prompt window is small and KBS audit logs grow without bound;
# capping here protects the sentinel from accidental full-log dumps.
MAX_TAIL_N = 1000


class AuditVerifyError(RuntimeError):
    """Raised when the audit chain fails any tamper-detection check."""


@dataclass(frozen=True)
class VerifiedAudit:
    """Successful verification result."""

    records: int
    head: bytes  # 32-byte SHA-256 of the last record body, or zeros


@dataclass(frozen=True)
class AuditRecord:
    """One decoded + verified audit record (returned by `read_tail`)."""

    seq: int
    domain: str
    granted: bool
    now_unix: int
    prev_hash: bytes
    reason: str
    ticket_id: str
    vm_id: str
    body_sha256: bytes


def _audit_dir(override: str | os.PathLike[str] | None = None) -> Path:
    if override is not None:
        return Path(override)
    raw = os.environ.get(ENV_AUDIT_DIR, "").strip()
    if not raw:
        raise RuntimeError(
            f"{ENV_AUDIT_DIR} is not set; PR-S2 sentinel readers cannot find "
            "the KBS audit-log directory."
        )
    return Path(raw)


def _read_head(dir_: Path) -> bytes | None:
    """Return `head.sha256` contents or None if absent.

    A present-but-empty file is treated as "zero head" (fresh chain),
    matching the Rust `walk_log` behavior.
    """

    head_path = dir_ / HEAD_FILENAME
    try:
        data = head_path.read_bytes()
    except FileNotFoundError:
        return None
    if not data:
        return _ZERO32
    if len(data) != 32:
        raise AuditVerifyError(
            f"head.sha256 has unexpected length {len(data)} (want 0 or 32)"
        )
    return data


def _is_zero_or_empty(head: bytes | None) -> bool:
    return head is None or head == _ZERO32 or not head


def _parse_line(lineno: int, raw: str) -> tuple[int, bytes, bytes]:
    """Split + hex-decode one audit-log line."""

    parts = raw.split(":", 2)
    if len(parts) != 3:
        raise AuditVerifyError(f"audit line {lineno}: missing seq/body/hash separators")
    seq_str, body_hex, hash_hex = parts
    try:
        line_seq = int(seq_str, 10)
        if line_seq < 0:
            raise ValueError
    except ValueError as e:
        raise AuditVerifyError(f"audit line {lineno}: bad seq {seq_str!r}") from e
    try:
        body = binascii.unhexlify(body_hex)
    except binascii.Error as e:
        raise AuditVerifyError(f"audit line {lineno}: bad body hex") from e
    try:
        on_disk_hash = binascii.unhexlify(hash_hex)
    except binascii.Error as e:
        raise AuditVerifyError(f"audit line {lineno}: bad hash hex") from e
    if len(on_disk_hash) != 32:
        raise AuditVerifyError(
            f"audit line {lineno}: hash length {len(on_disk_hash)} != 32"
        )
    return line_seq, body, on_disk_hash


def _decode_record_strict(lineno: int, body: bytes) -> dict[str, Any]:
    """Decode + schema-check a record body.

    Enforces canonical CBOR by round-tripping through
    `cbor2.dumps(..., canonical=True)` — this is the Python equivalent
    of Rust's `assert_canonical`. Empirically validated against the
    committed Rust-produced fixture (see `tests/fixtures/audit_known_good`).
    """

    try:
        decoded = cbor2.loads(body)
    except (cbor2.CBORDecodeError, ValueError, OSError) as e:
        raise AuditVerifyError(f"audit line {lineno}: CBOR decode failed: {e}") from e
    if not isinstance(decoded, dict):
        raise AuditVerifyError(f"audit line {lineno}: body is not a map")

    # Canonical-CBOR re-encode check. Catches map-key-reorder, indef
    # length, non-shortest int, duplicate keys.
    try:
        re_enc = cbor2.dumps(decoded, canonical=True)
    except (cbor2.CBOREncodeError, ValueError) as e:
        raise AuditVerifyError(
            f"audit line {lineno}: canonical re-encode failed: {e}"
        ) from e
    if re_enc != body:
        raise AuditVerifyError(f"audit line {lineno}: non-canonical CBOR encoding")

    keys = set(decoded)
    if keys != _REQUIRED_KEYS:
        missing = _REQUIRED_KEYS - keys
        extra = keys - _REQUIRED_KEYS
        raise AuditVerifyError(
            f"audit line {lineno}: schema mismatch (missing={sorted(missing)}, "
            f"extra={sorted(extra)})"
        )

    def _check_type(key: str, value: Any, want: str) -> None:
        # bool is a subclass of int in Python — handle that case explicitly
        # so the "int" checks reject CBOR true/false snuck into a numeric
        # field and the "bool" check rejects the converse.
        if want == "bool" and not isinstance(value, bool):
            raise AuditVerifyError(f"audit line {lineno}: {key!r} must be bool")
        if want == "uint":
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise AuditVerifyError(
                    f"audit line {lineno}: {key!r} must be a non-negative int"
                )
        if want == "text" and not isinstance(value, str):
            raise AuditVerifyError(f"audit line {lineno}: {key!r} must be text")
        if want == "bytes32":
            if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
                raise AuditVerifyError(
                    f"audit line {lineno}: {key!r} must be 32 bytes"
                )

    _check_type("domain", decoded["domain"], "text")
    _check_type("granted", decoded["granted"], "bool")
    _check_type("now_unix", decoded["now_unix"], "uint")
    _check_type("prev_hash", decoded["prev_hash"], "bytes32")
    _check_type("reason", decoded["reason"], "text")
    _check_type("seq", decoded["seq"], "uint")
    _check_type("ticket_id", decoded["ticket_id"], "text")
    _check_type("vm_id", decoded["vm_id"], "text")

    domain = decoded["domain"]
    granted = decoded["granted"]
    now_unix = decoded["now_unix"]
    prev_hash = bytes(decoded["prev_hash"])
    reason = decoded["reason"]
    seq = decoded["seq"]
    ticket_id = decoded["ticket_id"]
    vm_id = decoded["vm_id"]

    return {
        "domain": domain,
        "granted": granted,
        "now_unix": now_unix,
        "prev_hash": bytes(prev_hash),
        "reason": reason,
        "seq": seq,
        "ticket_id": ticket_id,
        "vm_id": vm_id,
    }


def walk_log(dir_: Path) -> VerifiedAudit:
    """Read + decode + chain-check the log file.

    Returns the record count and the recomputed tail hash. Does NOT
    touch `head.sha256` — the caller decides whether to reconcile, just
    like the Rust `walk_log`.
    """

    log_path = dir_ / LOG_FILENAME
    head = _read_head(dir_)
    try:
        raw = log_path.read_bytes()
    except FileNotFoundError:
        # Log missing. If head exists and is non-zero, the log was
        # deleted out from under us → tamper.
        if not _is_zero_or_empty(head):
            raise AuditVerifyError(
                "audit log missing but head.sha256 references records (tamper)"
            ) from None
        return VerifiedAudit(records=0, head=_ZERO32)

    if not raw:
        if not _is_zero_or_empty(head):
            raise AuditVerifyError(
                "audit log empty but head.sha256 references records (tamper)"
            )
        return VerifiedAudit(records=0, head=_ZERO32)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise AuditVerifyError(f"audit log not utf8: {e}") from e

    expected_prev = _ZERO32
    records = 0
    last_hash = _ZERO32
    for lineno, line in enumerate(text.splitlines()):
        line_seq, body, on_disk_hash = _parse_line(lineno, line)
        if line_seq != records:
            raise AuditVerifyError(
                f"audit line {lineno}: seq {line_seq} != expected {records}"
            )
        decoded = _decode_record_strict(lineno, body)
        if decoded["domain"] != AUDIT_DOMAIN:
            raise AuditVerifyError(f"audit line {lineno}: wrong domain")
        if decoded["seq"] != line_seq:
            raise AuditVerifyError(
                f"audit line {lineno}: body seq {decoded['seq']} != line seq {line_seq}"
            )
        recomputed = hashlib.sha256(body).digest()
        if on_disk_hash != recomputed:
            raise AuditVerifyError(
                f"audit line {lineno}: hash mismatch — body tampered"
            )
        if decoded["prev_hash"] != expected_prev:
            raise AuditVerifyError(
                f"audit line {lineno}: chain broken (prev_hash != expected)"
            )
        expected_prev = recomputed
        last_hash = recomputed
        records += 1

    return VerifiedAudit(records=records, head=last_hash)


def verify_chain(dir_: str | os.PathLike[str] | None = None) -> VerifiedAudit:
    """Walk the log AND reconcile against `head.sha256`.

    Mirrors `FileAuditSink::verify`: succeeds only if the recomputed
    tail equals the on-disk head pointer (or both are zero/absent).
    """

    d = _audit_dir(dir_)
    v = walk_log(d)
    head = _read_head(d)
    if head is None:
        if v.records > 0:
            raise AuditVerifyError(
                "audit head.sha256 missing while log has records (tamper)"
            )
        return v
    if head == v.head:
        return v
    if v.records == 0 and _is_zero_or_empty(head):
        return v
    raise AuditVerifyError("audit head.sha256 disagrees with computed tail")


def read_tail(n: int = 100, dir_: str | os.PathLike[str] | None = None) -> list[AuditRecord]:
    """Verify the entire chain, then return the last `n` decoded records.

    Reading the tail without first verifying the chain would let a
    tampered earlier record poison the report the sentinel emits, so
    we always walk first.
    """

    if n <= 0:
        return []
    n = min(n, MAX_TAIL_N)

    d = _audit_dir(dir_)
    verify_chain(d)  # raises on tamper

    try:
        text = (d / LOG_FILENAME).read_bytes().decode("utf-8")
    except FileNotFoundError:
        return []
    out: list[AuditRecord] = []
    for lineno, line in enumerate(text.splitlines()):
        _line_seq, body, on_disk_hash = _parse_line(lineno, line)
        decoded = _decode_record_strict(lineno, body)
        out.append(
            AuditRecord(
                seq=decoded["seq"],
                domain=decoded["domain"],
                granted=decoded["granted"],
                now_unix=decoded["now_unix"],
                prev_hash=decoded["prev_hash"],
                reason=decoded["reason"],
                ticket_id=decoded["ticket_id"],
                vm_id=decoded["vm_id"],
                body_sha256=on_disk_hash,
            )
        )
    return out[-n:]


# ---------------------------------------------------------------------------
# Agent-facing MCP tool wrappers
# ---------------------------------------------------------------------------


def _record_to_jsonable(rec: AuditRecord) -> dict[str, Any]:
    # This dict is handed to the LLM by `read_kbs_audit_tail`. The
    # fields are operational (issue #57 posture 1 accepts sending
    # operational ids to the API), but `reason` is free text written
    # by KBS — scrub any secret-shaped substring as defence in depth.
    # `redact_text` is prefix-anchored, so ordinary ids (vm-1234,
    # tk-99) and the domain constant pass through untouched. Imported
    # lazily: a module-level import would cycle via `analytics.base`.
    # (PR-S6 review — review HIGH.)
    from sentinel.output.redact import redact_text

    return {
        "seq": rec.seq,
        "domain": rec.domain,
        "granted": rec.granted,
        "now_unix": rec.now_unix,
        "prev_hash_hex": rec.prev_hash.hex(),
        "reason": redact_text(rec.reason),
        "ticket_id": redact_text(rec.ticket_id),
        "vm_id": redact_text(rec.vm_id),
        "body_sha256_hex": rec.body_sha256.hex(),
    }


async def _read_kbs_audit_tail_impl(args: dict[str, Any]) -> dict[str, Any]:
    n = int(args.get("n", 100))
    try:
        records = read_tail(n)
    except AuditVerifyError as e:
        log.warning("read_kbs_audit_tail: chain verification failed: %s", e)
        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        "AUDIT TAMPER DETECTED — sentinel refused to return tail "
                        f"because the chain failed verification: {e}"
                    ),
                }
            ],
            "isError": True,
        }
    except Exception as e:  # noqa: BLE001 — surface a structured error to the agent
        log.exception("read_kbs_audit_tail: unexpected failure")
        return {
            "content": [{"type": "text", "text": f"read_tail failed: {e}"}],
            "isError": True,
        }

    summary = {
        "returned_count": len(records),
        "records": [_record_to_jsonable(r) for r in records],
    }
    return {"content": [{"type": "text", "text": _stable_json(summary)}]}


async def _verify_kbs_audit_chain_impl(_args: dict[str, Any]) -> dict[str, Any]:
    try:
        v = verify_chain()
    except AuditVerifyError as e:
        log.warning("verify_kbs_audit_chain: tamper detected: %s", e)
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"AUDIT TAMPER DETECTED: {e}",
                }
            ],
            "isError": True,
        }
    except Exception as e:  # noqa: BLE001
        log.exception("verify_kbs_audit_chain: unexpected failure")
        return {
            "content": [{"type": "text", "text": f"verify_chain failed: {e}"}],
            "isError": True,
        }
    return {
        "content": [
            {
                "type": "text",
                "text": _stable_json(
                    {
                        "ok": True,
                        "records": v.records,
                        "head_hex": v.head.hex(),
                    }
                ),
            }
        ]
    }


def _stable_json(obj: Any) -> str:
    """JSON dump with stable key ordering, used for tool-call responses."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


read_kbs_audit_tail = tool(
    "read_kbs_audit_tail",
    "Return the last N decoded KBS audit records as JSON. Verifies the "
    "entire chain first; refuses to return data if any tamper-detection "
    "check fails. N defaults to 100, capped at 1000.",
    {"n": int},
)(_read_kbs_audit_tail_impl)


verify_kbs_audit_chain = tool(
    "verify_kbs_audit_chain",
    "Walk the KBS audit log and confirm the hash chain is intact. "
    "Returns ok + record count + tail head hex on success; surfaces a "
    "structured AUDIT TAMPER DETECTED error otherwise.",
    {},
)(_verify_kbs_audit_chain_impl)
