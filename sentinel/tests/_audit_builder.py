"""Test helper that builds an audit log identical to the Rust producer.

Used by the tamper-detection tests so each test can produce a clean
on-disk chain in a tempdir without invoking cargo. The canonical-CBOR
encoding matches `kbs_core::audit::FileAuditSink::build_record` — the
`tests/fixtures/audit_known_good` Rust fixture is the cross-impl witness
that this helper stays in lockstep.
"""

from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass
from pathlib import Path

import cbor2

from sentinel.tools.kbs_audit import AUDIT_DOMAIN, HEAD_FILENAME, LOG_FILENAME


@dataclass
class _AppendResult:
    seq: int
    body: bytes
    hash_: bytes
    line: str


def _build_record(
    *,
    prev_hash: bytes,
    seq: int,
    granted: bool,
    ticket_id: str,
    vm_id: str,
    reason: str,
    now_unix: int,
    domain: str = AUDIT_DOMAIN,
) -> bytes:
    """Canonical-CBOR body builder mirroring the Rust `build_record`.

    Key set + types are pinned. The map insertion order is irrelevant
    because cbor2 with `canonical=True` re-sorts keys by encoded
    bytes — same rule as ciborium's `canonicalize`.
    """

    return cbor2.dumps(
        {
            "domain": domain,
            "granted": granted,
            "now_unix": now_unix,
            "prev_hash": prev_hash,
            "reason": reason,
            "seq": seq,
            "ticket_id": ticket_id,
            "vm_id": vm_id,
        },
        canonical=True,
    )


def build_chain(
    dir_: Path,
    records: list[dict] | None = None,
) -> list[_AppendResult]:
    """Write a fresh `audit.log` + `head.sha256` from a list of record dicts.

    Each dict has the schema fields except `seq` + `prev_hash`, which
    are derived. A default 3-record chain is produced if `records` is
    None.
    """

    dir_.mkdir(parents=True, exist_ok=True)
    if records is None:
        records = [
            {
                "granted": True, "ticket_id": "tk-A", "vm_id": "vm-1",
                "reason": "released", "now_unix": 100,
            },
            {
                "granted": False, "ticket_id": "tk-B", "vm_id": "vm-2",
                "reason": "expired", "now_unix": 110,
            },
            {
                "granted": True, "ticket_id": "tk-C", "vm_id": "vm-3",
                "reason": "released", "now_unix": 120,
            },
        ]

    prev = bytes(32)
    out: list[_AppendResult] = []
    log_lines: list[str] = []
    for seq, r in enumerate(records):
        body = _build_record(
            prev_hash=prev,
            seq=seq,
            granted=r["granted"],
            ticket_id=r["ticket_id"],
            vm_id=r["vm_id"],
            reason=r["reason"],
            now_unix=r["now_unix"],
            domain=r.get("domain", AUDIT_DOMAIN),
        )
        h = hashlib.sha256(body).digest()
        line = f"{seq}:{binascii.hexlify(body).decode()}:{binascii.hexlify(h).decode()}\n"
        log_lines.append(line)
        out.append(_AppendResult(seq=seq, body=body, hash_=h, line=line))
        prev = h

    (dir_ / LOG_FILENAME).write_text("".join(log_lines))
    if out:
        (dir_ / HEAD_FILENAME).write_bytes(out[-1].hash_)
    return out


def rewrite_log(dir_: Path, lines: list[str], *, head: bytes | None = None) -> None:
    """Overwrite the log + head with custom contents (for tamper tests)."""

    (dir_ / LOG_FILENAME).write_text("".join(lines))
    if head is not None:
        (dir_ / HEAD_FILENAME).write_bytes(head)
