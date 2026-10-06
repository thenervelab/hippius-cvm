"""Copy the KBS hash-chained audit logs out of the KBS CVM, verifying them.

## Why

The KBS runs in a Kata SEV-SNP CVM and keeps two hash-chained audit
logs on an emptyDir there: every §7 release decision (`log=release`,
`kbs-core/src/audit.rs`) and every admin operation (`log=admin`,
`kbs-core/src/admin_audit.rs`). The host cannot read them and a KBS
restart wipes them. `GET /v1/admin/audit` (mTLS admin listener) serves
them page by page; this module pulls them into `KbsAuditEntry` rows so
"did the canary's release say `reason=released`?" is a query
(`manage.py vali_kbs_audit --vm <id> --log release`).

## Verification (the KBS vouching for itself proves nothing)

Every entry is re-checked before it is stored:

- `seq` is the next one expected (no gap, no repeat);
- `sha256(body)` equals the stored hash;
- the body is canonical CBOR carrying the chain's domain tag and the same
  `seq`;
- its `prev_hash` (in the body, and as served) is the previous record's
  hash — the zero hash for `seq=0`.

A record that fails is STORED, flagged `chain_ok=False` with the reason,
and logged at ERROR — never skipped: a break is evidence. It also BREAKS
its epoch (`KbsAuditCursor.broken_at_seq`): every later record of that
epoch is still fetched and stored, but as "unverified" — nothing is ever
trusted by chaining onto an unverified predecessor. A break with no
record of its own (a cut, a rewrite, an equivocation, a withheld record,
a forged genesis) is a durable `KbsAuditAnomaly` row.

## KBS restarts are epochs, not tamper

`kbs_epoch` is the chain's genesis hash (`sha256` of its `seq=0`
record), served as `genesis_hash_hex`. A restarted KBS starts a new
chain at `seq=0` under a new genesis, so a changed genesis is a new
epoch (WARNING: whatever the old life appended after vali's last read is
gone) and ingest restarts at `seq=0` — provided the served `seq=0`
record really hashes to that genesis; a KBS naming a genesis it does not
have is a `genesis-mismatch` anomaly, not a restart. The SAME genesis with a head below
what vali already holds — or a different hash at vali's last `seq` — is
a chain cut or rewrite within one life: ERROR, cursor not moved.

## A crash mid-append is a torn tail, not a tamper

The KBS's audit dir survives a container restart inside the same pod.
A process killed in the middle of an append leaves a torn trailing line;
the next open truncates it and chains ONE `audit-truncated` record in its
place, at the seq the torn record would have had
(`kbs-core/src/audit_journal.rs`): release `granted=false, ticket_id="",
vm_id="", reason="audit-truncated:seq=<N>:len=<L>:sha256=<16 hex>"`;
admin `op="audit-truncated"` with the same `reason`. It is an ordinary,
verified chain record — stored like any other — and ALSO a
`torn-tail-truncated` `KbsAuditAnomaly` (WARNING: availability evidence,
not a break). A torn record was never served (the KBS indexes a record
only once it is fsynced), so vali never held what was dropped; if vali
DOES hold a different record at that seq, the rewrite is caught as an
`equivocation` as well.

## Flag

`VALI_KBS_AUDIT_INGEST_ENABLED` (default off). A KBS without the route
answers 404 and the ingest skips quietly; any other failure is logged
and retried next run. The route shares the KBS admin rate-limit bucket
with launches, hence the per-run page budget and the interval throttle.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from apps.orchestration import effects
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.models import (
    KbsAuditAnomaly,
    KbsAuditCursor,
    KbsAuditEntry,
    KbsAuditLog,
)
from apps.orchestration.services.kbs_rollback import CborError, decode_cbor

log = logging.getLogger("apps.orchestration.kbs_audit")

#: The domain tag each chain's records carry (`AUDIT_DOMAIN` /
#: `ADMIN_AUDIT_DOMAIN` in kbs-core). A record of one chain cannot pass
#: as the other's.
DOMAINS: dict[str, str] = {
    KbsAuditLog.RELEASE: "HIPPIUS_KBS_AUDIT_V1",
    KbsAuditLog.ADMIN: "HIPPIUS_KBS_ADMIN_V1",
}
ZERO_HASH = "00" * 32
#: `op` (admin) / `reason` prefix (both) of the record a KBS chains in
#: place of a torn trailing record it truncated at open
#: (`kbs_core::audit_journal::AUDIT_TRUNCATED`).
AUDIT_TRUNCATED = "audit-truncated"
#: The anomaly kind vali records for one.
TORN_TAIL_TRUNCATED = "torn-tail-truncated"

#: The exact key set and value types of each chain's record body
#: (`FileAuditSink::build_record` / `FileAdminAuditSink::build_record`).
#: A body with a key missing, extra, or of the wrong type does not verify:
#: a record that hashes and chains but says nothing is not a record.
_TEXT, _UINT, _BOOL, _HASH = "text", "uint", "bool", "hash32"
SCHEMAS: dict[str, dict[str, str]] = {
    KbsAuditLog.RELEASE: {
        "domain": _TEXT, "granted": _BOOL, "now_unix": _UINT, "prev_hash": _HASH,
        "reason": _TEXT, "seq": _UINT, "ticket_id": _TEXT, "vm_id": _TEXT,
    },
    KbsAuditLog.ADMIN: {
        "applied": _BOOL, "body_sha256": _HASH, "domain": _TEXT, "now_unix": _UINT,
        "op": _TEXT, "peer_san": _TEXT, "peer_serial": _TEXT, "prev_hash": _HASH,
        "reason": _TEXT, "seq": _UINT, "status_code": _UINT, "ticket_id": _TEXT,
        "url_vm_id": _TEXT, "vm_id": _TEXT,
    },
}


def _schema_errors(decoded: dict[str, Any], log_name: str) -> list[str]:
    schema = SCHEMAS[log_name]
    errors = []
    if set(decoded) != set(schema):
        errors.append(
            "schema-mismatch: missing "
            f"{sorted(set(schema) - set(decoded))} extra {sorted(set(decoded) - set(schema))}"
        )
    for key, kind in schema.items():
        v = decoded.get(key)
        ok = {
            _TEXT: isinstance(v, str),
            _UINT: _uint(v) is not None,
            _BOOL: isinstance(v, bool),
            _HASH: isinstance(v, bytes) and len(v) == 32,
        }[kind]
        if key in decoded and not ok:
            errors.append(f"schema-type: {key}")
    # RFC 8949 §4.2.1: map keys sorted by their encoded bytes — for these
    # short text keys, by length then bytes. `decode_cbor` keeps order.
    keys = list(decoded)
    if keys != sorted(keys, key=lambda k: (len(str(k).encode()), str(k).encode())):
        errors.append("non-canonical-key-order")
    return errors
_HEX64 = frozenset("0123456789abcdef")


class KbsAuditRouteMissing(EffectError):
    """404: the deployed KBS predates `GET /v1/admin/audit`."""


class KbsAuditRateLimited(EffectError):
    """429: the shared admin bucket is empty — stop this run."""


#: `(log, after_seq, limit) -> page` — the one network call, injectable.
Fetch = Callable[[str, "int | None", int], dict[str, Any]]


def fetch_page(log_name: str, after_seq: int | None, limit: int) -> dict[str, Any]:
    """`GET {VALI_KBS_ADMIN_URL}/v1/admin/audit` through the admin transport
    every vali→KBS admin call uses (`services.kbs_admin_tls`)."""
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_transport,
    )

    try:
        transport = admin_transport()
    except KbsAdminTlsMisconfigured as exc:
        raise EffectUnavailable(str(exc)) from exc
    query = f"log={log_name}&limit={int(limit)}"
    if after_seq is not None:
        query += f"&after_seq={int(after_seq)}"
    status, body = effects._http(
        "GET",
        transport.url(f"/v1/admin/audit?{query}"),
        label="kbs-audit",
        context=transport.context,
    )
    if status == 404:
        raise KbsAuditRouteMissing("kbs-audit: the KBS does not serve /v1/admin/audit")
    if status == 429:
        raise KbsAuditRateLimited("kbs-audit: KBS admin rate limit")
    if status != 200:
        raise EffectError(f"kbs-audit: HTTP {status}")
    return effects._json(body, label="kbs-audit")


# ─── verification ────────────────────────────────────────────────────


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _uint(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


@dataclass(frozen=True)
class CheckedEntry:
    """One served entry after verification. `errors` empty ⇔ it chains."""

    seq: int
    body: bytes
    sha256: str
    prev_hash: str
    #: `sha256(body)` as recomputed — what the NEXT record must chain onto.
    actual_hash: str
    decoded: dict[str, Any] | None
    errors: tuple[str, ...]


def check_entry(
    entry: Any, *, log_name: str, expected_seq: int, expected_prev: str
) -> CheckedEntry:
    """Verify one served entry against the chain position it must occupy.
    Never raises on bad data — every problem is an item of `errors`."""
    errors: list[str] = []
    if not isinstance(entry, dict):
        entry = {}
        errors.append("entry-not-an-object")
    seq = _uint(entry.get("seq"))
    if seq is None:
        errors.append("seq-invalid")
        seq = expected_seq
    elif seq != expected_seq:
        errors.append(f"seq-gap: got {seq}, want {expected_seq}")

    body = b""
    body_hex = entry.get("body_cbor_hex")
    try:
        if not isinstance(body_hex, str):
            raise ValueError
        body = bytes.fromhex(body_hex)
    except ValueError:
        errors.append("body-hex-invalid")
    actual = hashlib.sha256(body).hexdigest()

    stored = entry.get("sha256_hex")
    if not _is_hex64(stored):
        errors.append("sha256-invalid")
        stored = actual
    elif stored != actual:
        errors.append("hash-mismatch: sha256(body) != stored hash")

    served_prev = entry.get("prev_hash_hex")
    if not _is_hex64(served_prev):
        errors.append("prev-hash-invalid")
        served_prev = ""

    decoded: dict[str, Any] | None = None
    if body:
        try:
            value = decode_cbor(body, canonical=True)
        except CborError as exc:
            errors.append(f"body-not-canonical-cbor: {exc}")
        else:
            if isinstance(value, dict):
                decoded = value
            else:
                errors.append("body-not-a-map")
    if decoded is not None:
        errors.extend(_schema_errors(decoded, log_name))
        if decoded.get("domain") != DOMAINS[log_name]:
            errors.append("wrong-domain")
        if decoded.get("seq") != seq:
            errors.append("body-seq-mismatch")
        body_prev = decoded.get("prev_hash")
        body_prev_hex = body_prev.hex() if isinstance(body_prev, bytes) else None
        if body_prev_hex != served_prev:
            errors.append("served-prev-hash-disagrees-with-body")
        if body_prev_hex != expected_prev:
            errors.append("chain-broken: prev_hash is not the previous record's hash")
    elif not body and "body-hex-invalid" not in errors:
        errors.append("body-empty")

    return CheckedEntry(
        seq=seq,
        body=body,
        sha256=stored,
        prev_hash=served_prev,
        actual_hash=actual,
        decoded=decoded,
        errors=tuple(errors),
    )


def _str(d: dict[str, Any], key: str, limit: int | None) -> str:
    """`d[key]` when it is a string (cut to `limit` chars; `None` = whole)."""
    v = d.get(key)
    if not isinstance(v, str):
        return ""
    return v if limit is None else v[:limit]


def _row(
    checked: CheckedEntry, *, log_name: str, epoch: str, fetched_at: Any, errors: list[str]
) -> KbsAuditEntry:
    d = checked.decoded or {}
    is_release = log_name == KbsAuditLog.RELEASE
    vm_id = _str(d, "vm_id", 64) or _str(d, "url_vm_id", 64)
    status = d.get("status_code")
    return KbsAuditEntry(
        log=log_name,
        kbs_epoch=epoch,
        seq=checked.seq,
        body_cbor=checked.body,
        sha256=checked.sha256,
        prev_hash=checked.prev_hash,
        fetched_at=fetched_at,
        chain_ok=not errors,
        chain_error="; ".join(errors)[:256],
        event_unix=_uint(d.get("now_unix")),
        op="release" if is_release and checked.decoded is not None else _str(d, "op", 64),
        vm_id=vm_id,
        ticket_id=_str(d, "ticket_id", 128),
        reason=_str(d, "reason", None),
        granted=d.get("granted") if isinstance(d.get("granted"), bool) else None,
        status_code=_uint(status),
        applied=d.get("applied") if isinstance(d.get("applied"), bool) else None,
        peer_san=_str(d, "peer_san", 256),
    )


# ─── ingest ──────────────────────────────────────────────────────────


@dataclass
class IngestResult:
    stored: int = 0
    breaks: int = 0
    new_epochs: int = 0
    #: Why nothing was fetched ("route-missing", "rate-limited", …), or "".
    skipped: str = ""
    per_log: dict[str, int] = field(default_factory=dict)


def _page_ok(page: Any, log_name: str) -> bool:
    """Shape AND internal consistency of a served page. An empty log is
    exactly `genesis=None, head_seq=None, head=0…0, entries=[]`; a
    non-empty one has all three set, and no entry past its head."""
    if not (
        isinstance(page, dict)
        and page.get("v") == 1
        and page.get("log") == log_name
        and isinstance(page.get("entries"), list)
        and _is_hex64(page.get("head_hash_hex"))
    ):
        return False
    genesis, head_seq = page.get("genesis_hash_hex"), page.get("head_seq")
    if genesis is None or head_seq is None:
        return (
            genesis is None
            and head_seq is None
            and page["head_hash_hex"] == ZERO_HASH
            and not page["entries"]
        )
    if not _is_hex64(genesis) or _uint(head_seq) is None:
        return False
    return all(
        isinstance(e, dict) and _uint(e.get("seq")) is not None and e["seq"] <= head_seq
        for e in page["entries"]
    )


def _fetch_page(fetch: Fetch, log_name: str, after: int | None, limit: int) -> dict[str, Any]:
    page = fetch(log_name, after, limit)
    if not _page_ok(page, log_name):
        raise EffectError(f"kbs-audit {log_name}: malformed or self-contradictory page")
    return page


def _anomaly(
    log_name: str,
    epoch: str,
    kind: str,
    *,
    seq: int | None,
    observed: str,
    detail: str,
    level: int = logging.ERROR,
) -> None:
    """Durable record of a break that has no entry of its own to flag (a
    cut, a rewrite, an equivocation, a withheld record, a forged genesis),
    or of a torn tail the KBS truncated. Deduplicated per `(log, epoch,
    kind, seq, observed)`; `count` and `last_seen_at` move every time it is
    seen again. An ERROR, except a torn tail (WARNING)."""
    log.log(
        level,
        "KBS AUDIT %s log=%s epoch=%s seq=%s: %s",
        kind.upper(), log_name, epoch[:16], "-" if seq is None else seq, detail,
    )
    now = timezone.now()
    row, created = KbsAuditAnomaly.objects.get_or_create(
        log=log_name,
        kbs_epoch=epoch,
        kind=kind,
        seq=-1 if seq is None else seq,
        observed=observed,
        defaults={"detail": detail[:256], "first_seen_at": now, "last_seen_at": now},
    )
    if not created:
        KbsAuditAnomaly.objects.filter(pk=row.pk).update(
            count=F("count") + 1, last_seen_at=now
        )


def truncation_marker(decoded: dict[str, Any] | None, log_name: str) -> str | None:
    """The `reason` of an `audit-truncated` record, or None if `decoded` is
    not one (see the module docstring for its exact shape)."""
    if decoded is None:
        return None
    reason = decoded.get("reason")
    if not isinstance(reason, str) or not reason.startswith(f"{AUDIT_TRUNCATED}:"):
        return None
    if log_name == KbsAuditLog.RELEASE:
        is_marker = (
            decoded.get("granted") is False
            and decoded.get("ticket_id") == ""
            and decoded.get("vm_id") == ""
        )
    else:
        is_marker = decoded.get("op") == AUDIT_TRUNCATED and decoded.get("applied") is False
    return reason if is_marker else None


@dataclass
class _PageOutcome:
    stored: int = 0
    breaks: int = 0
    #: The last record processed — the cursor's new position.
    last: CheckedEntry | None = None
    #: The first seq of the epoch that did not verify, or None.
    broken_at: int | None = None
    #: The page stopped at a hole / repeat: do not ask past it this run.
    stopped: bool = False


def _ingest_page(
    log_name: str,
    epoch: str,
    entries: list[Any],
    *,
    expected_seq: int,
    expected_prev: str,
    broken_at: int | None,
    fetched_at: Any,
) -> _PageOutcome:
    """Verify and store one page and move the cursor past it — atomically.

    - Every served record is stored (a held identical one is skipped).
    - A record that does not verify is stored `chain_ok=False` with its
      reason, and BREAKS the epoch: every later record of it is stored
      "unverified" as well — it chains onto an unverified predecessor, so
      nothing after a break is ever trusted.
    - A record held with DIFFERENT bytes for the same `(log, epoch, seq)`
      is an equivocation: the held row is kept, an anomaly recorded, and
      the epoch breaks there too.
    """
    out = _PageOutcome(broken_at=broken_at)
    with transaction.atomic():
        held = {
            e.seq: (e.sha256, bytes(e.body_cbor))
            for e in KbsAuditEntry.objects.filter(
                log=log_name, kbs_epoch=epoch, seq__in=[e["seq"] for e in entries]
            ).only("seq", "sha256", "body_cbor")
        }
        for entry in entries:
            if entry["seq"] != expected_seq:
                # A page that jumps (a record withheld) or repeats one. Not
                # stored past: the cursor stays before the hole, so the
                # next run asks for the missing seq again — and a record
                # served then still has to chain onto the verified prefix.
                kind = "withheld" if entry["seq"] > expected_seq else "duplicate"
                out.breaks += 1
                _anomaly(
                    log_name, epoch, kind,
                    seq=expected_seq,
                    observed=str(entry.get("sha256_hex", ""))[:64],
                    detail=f"the page serves seq {entry['seq']} where seq {expected_seq} "
                    "must come next",
                )
                out.stopped = True
                break
            checked = check_entry(
                entry, log_name=log_name, expected_seq=expected_seq, expected_prev=expected_prev
            )
            errors = list(checked.errors)
            if errors:
                out.breaks += 1
                log.error(
                    "KBS AUDIT CHAIN BREAK log=%s epoch=%s seq=%d: %s — stored flagged",
                    log_name, epoch[:16], checked.seq, "; ".join(errors),
                )
            if out.broken_at is not None and out.broken_at < checked.seq:
                errors.append(f"unverified: follows the break at seq {out.broken_at}")
            if errors and out.broken_at is None:
                out.broken_at = checked.seq
            prior = held.get(checked.seq)
            if prior is not None and prior != (checked.sha256, checked.body):
                out.breaks += 1
                _anomaly(
                    log_name, epoch, "equivocation",
                    seq=checked.seq,
                    observed=checked.actual_hash,
                    detail=f"the KBS now serves hash {checked.sha256} where vali holds {prior[0]}",
                )
                if out.broken_at is None:
                    out.broken_at = checked.seq
            elif prior is None:
                _row(
                    checked, log_name=log_name, epoch=epoch, fetched_at=fetched_at,
                    errors=errors,
                ).save(force_insert=True)
                out.stored += 1
                marker = None if errors else truncation_marker(checked.decoded, log_name)
                if marker is not None:
                    _anomaly(
                        log_name, epoch, TORN_TAIL_TRUNCATED,
                        seq=checked.seq,
                        observed=checked.actual_hash,
                        detail=f"the KBS truncated a torn trailing record at open ({marker}) "
                        "— a crash mid-append, not a tamper",
                        level=logging.WARNING,
                    )
            out.last = checked
            expected_seq, expected_prev = checked.seq + 1, checked.actual_hash
        if out.last is not None:
            KbsAuditCursor.objects.update_or_create(
                log=log_name,
                defaults={
                    "kbs_epoch": epoch,
                    "last_seq": out.last.seq,
                    "last_hash": out.last.actual_hash,
                    "broken_at_seq": out.broken_at,
                },
            )
    return out


def _genesis_record_ok(page: dict[str, Any], genesis: str) -> bool:
    """A new epoch is only a restart if its genesis IS the hash of the
    `seq=0` record it serves — otherwise the KBS is naming a genesis it
    does not have (e.g. to present a rewritten tail of the SAME chain,
    whose real `seq=0` hashes to the old epoch, as a fresh one)."""
    entries = page["entries"]
    if not entries or entries[0].get("seq") != 0:
        return False
    try:
        body = bytes.fromhex(entries[0].get("body_cbor_hex", ""))
    except (TypeError, ValueError):
        return False
    return bool(body) and hashlib.sha256(body).hexdigest() == genesis


def ingest_log(log_name: str, *, fetch: Fetch = fetch_page) -> IngestResult:
    """Pull every record of one chain vali does not hold yet (up to the
    per-run page budget), verify it, store it. Raises
    `KbsAuditRouteMissing` / `KbsAuditRateLimited` / `EffectError` /
    `EffectUnavailable` from the fetch."""
    result = IngestResult()
    limit = max(1, int(settings.VALI_KBS_AUDIT_PAGE_LIMIT))
    budget = max(1, int(settings.VALI_KBS_AUDIT_MAX_PAGES_PER_RUN))

    cursor = KbsAuditCursor.objects.filter(log=log_name).first()
    after = cursor.last_seq if cursor else None
    page = _fetch_page(fetch, log_name, after, limit)
    budget -= 1
    genesis = page["genesis_hash_hex"]

    if genesis is None:
        if cursor is not None:
            log.warning(
                "kbs-audit %s: the KBS log is EMPTY but vali holds epoch %s up to seq %d — "
                "the KBS restarted; its new epoch begins with its first record",
                log_name, cursor.kbs_epoch[:16], cursor.last_seq,
            )
        return result

    if cursor is None or genesis != cursor.kbs_epoch:
        if after is not None:
            page = _fetch_page(fetch, log_name, None, limit)
            budget -= 1
            if page["genesis_hash_hex"] != genesis:
                # Restarted AGAIN between two calls; the next run sorts it out.
                return result
        if not _genesis_record_ok(page, genesis):
            result.breaks += 1
            _anomaly(
                log_name, genesis, "genesis-mismatch",
                seq=0,
                observed=genesis,
                detail="the served genesis is not the hash of the served seq=0 record — "
                "not accepted as a KBS restart",
            )
            return result
        if cursor is not None:
            log.warning(
                "kbs-audit %s: NEW KBS epoch %s (was %s, last seq %d) — the KBS restarted; "
                "anything its previous life appended after seq %d is gone",
                log_name, genesis[:16], cursor.kbs_epoch[:16], cursor.last_seq,
                cursor.last_seq,
            )
        result.new_epochs += 1
        expected_seq, expected_prev, broken_at = 0, ZERO_HASH, None
    else:
        head_seq = page["head_seq"]
        if head_seq < cursor.last_seq:
            result.breaks += 1
            _anomaly(
                log_name, genesis, "cut",
                seq=cursor.last_seq,
                observed=page["head_hash_hex"],
                detail=f"vali holds seq {cursor.last_seq} but the KBS reports head seq "
                f"{head_seq} in the SAME epoch — records were removed inside the KBS",
            )
            return result
        if head_seq == cursor.last_seq and page["head_hash_hex"] != cursor.last_hash:
            result.breaks += 1
            _anomaly(
                log_name, genesis, "rewrite",
                seq=cursor.last_seq,
                observed=page["head_hash_hex"],
                detail=f"the KBS head at seq {head_seq} is {page['head_hash_hex']}, vali "
                f"holds {cursor.last_hash} — the record was rewritten inside the KBS",
            )
            return result
        expected_seq, expected_prev = cursor.last_seq + 1, cursor.last_hash
        broken_at = cursor.broken_at_seq

    fetched_at = timezone.now()
    while True:
        entries, head_seq = page["entries"], page["head_seq"]
        if not entries:
            if head_seq >= expected_seq:
                result.breaks += 1
                _anomaly(
                    log_name, genesis, "withheld",
                    seq=expected_seq,
                    observed=page["head_hash_hex"],
                    detail=f"an empty page after seq {expected_seq - 1} while the KBS "
                    f"reports head seq {head_seq}",
                )
            break
        out = _ingest_page(
            log_name, genesis, entries,
            expected_seq=expected_seq, expected_prev=expected_prev,
            broken_at=broken_at, fetched_at=fetched_at,
        )
        result.stored += out.stored
        result.breaks += out.breaks
        broken_at = out.broken_at
        last = out.last
        if last is None or out.stopped:
            break
        if last.seq == head_seq and last.actual_hash != page["head_hash_hex"]:
            result.breaks += 1
            _anomaly(
                log_name, genesis, "head-mismatch",
                seq=head_seq,
                observed=page["head_hash_hex"],
                detail=f"the served head hash is not the hash of the served seq {head_seq}",
            )
        expected_seq, expected_prev = last.seq + 1, last.actual_hash
        if last.seq >= head_seq or budget <= 0:
            break
        page = _fetch_page(fetch, log_name, last.seq, limit)
        budget -= 1
        if page["genesis_hash_hex"] != genesis:
            break  # restarted mid-run: the next run opens the new epoch
    result.per_log[log_name] = result.stored
    return result


_last_run_monotonic: float | None = None


def prune() -> int:
    """Apply `VALI_KBS_AUDIT_RETENTION_DAYS` (0 ⇒ keep everything). Never
    deletes a flagged (`chain_ok=False`) entry."""
    days = int(settings.VALI_KBS_AUDIT_RETENTION_DAYS)
    if days <= 0:
        return 0
    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = KbsAuditEntry.objects.filter(chain_ok=True, fetched_at__lt=cutoff).delete()
    return deleted


def ingest_tick(
    *, fetch: Fetch = fetch_page, now: Callable[[], float] = time.monotonic
) -> IngestResult:
    """The orchestration-tick hook: both chains, throttled, never raising
    for a KBS-side problem."""
    global _last_run_monotonic
    total = IngestResult()
    if not settings.VALI_KBS_AUDIT_INGEST_ENABLED:
        return total
    t = now()
    interval = float(settings.VALI_KBS_AUDIT_INGEST_INTERVAL_S)
    if _last_run_monotonic is not None and t - _last_run_monotonic < interval:
        total.skipped = "throttled"
        return total
    _last_run_monotonic = t

    for log_name in (KbsAuditLog.RELEASE, KbsAuditLog.ADMIN):
        try:
            r = ingest_log(log_name, fetch=fetch)
        except KbsAuditRouteMissing:
            log.debug("kbs-audit: the KBS predates /v1/admin/audit — skipping")
            total.skipped = "route-missing"
            break
        except KbsAuditRateLimited:
            log.info("kbs-audit %s: KBS admin rate limit — resuming next run", log_name)
            total.skipped = "rate-limited"
            break
        except EffectUnavailable as exc:
            log.warning("kbs-audit %s: KBS unreachable — resuming next run: %s", log_name, exc)
            total.skipped = "unavailable"
            break
        except EffectError as exc:
            log.warning("kbs-audit %s: ingest failed, retrying next run: %s", log_name, exc)
            continue
        total.stored += r.stored
        total.breaks += r.breaks
        total.new_epochs += r.new_epochs
        total.per_log[log_name] = r.stored
    try:
        prune()
    except Exception:  # noqa: BLE001 — retention must not break the ingest.
        log.exception("kbs-audit: retention prune failed")
    return total


def decode_body(body: bytes) -> dict[str, Any] | None:
    """Decode a stored body for display, or `None` if it does not decode."""
    try:
        value = decode_cbor(bytes(body), canonical=True)
    except CborError:
        return None
    return value if isinstance(value, dict) else None
