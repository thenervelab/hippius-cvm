"""`vali_kbs_audit` — query the KBS audit entries vali copied out of the KBS.

Read-only. Rows come from `KbsAuditEntry` (filled by the orchestration
tick when `VALI_KBS_AUDIT_INGEST_ENABLED`); each body is decoded from
its stored canonical CBOR for display.

    # did the canary's release say reason=released?
    manage.py vali_kbs_audit --vm <vm_id> --log release --reason released

    # everything the KBS recorded about a VM since a time
    manage.py vali_kbs_audit --vm <vm_id> --since 2026-09-28T00:00:00Z

    # every chain break vali has seen (flagged entries + anomalies: cuts,
    # rewrites, equivocations, withheld records, forged genesis)
    manage.py vali_kbs_audit --breaks

`--since` / `--until` filter on the KBS's own clock at append time
(`now_unix`), as ISO-8601 or unix seconds. Exit status 1 when nothing
matched, so a script can assert "this record exists".
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.orchestration.kbs_audit import decode_body
from apps.orchestration.models import KbsAuditAnomaly, KbsAuditEntry, KbsAuditLog


def _unix(value: str) -> int:
    value = value.strip()
    if value.isdigit():
        return int(value)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CommandError(f"not ISO-8601 or unix seconds: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _when(unix: int | None) -> str:
    if unix is None:
        return "-"
    return datetime.fromtimestamp(unix, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Command(BaseCommand):
    help = "Query the KBS audit entries vali ingested (decoded). Read-only."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm", help="vm_id (the ticket's, or the admin URL's)")
        parser.add_argument("--log", choices=[c.value for c in KbsAuditLog])
        parser.add_argument("--since", help="KBS time lower bound (ISO-8601 / unix)")
        parser.add_argument("--until", help="KBS time upper bound (ISO-8601 / unix)")
        parser.add_argument("--op", help="admin op, e.g. register-vm")
        parser.add_argument("--reason", help="exact reason, e.g. released")
        parser.add_argument(
            "--reason-contains",
            help="substring of the reason, e.g. a timeline_to=<hex> or a restore id",
        )
        parser.add_argument("--epoch", help="kbs_epoch (genesis hash) prefix")
        parser.add_argument("--breaks", action="store_true", help="only chain breaks")
        parser.add_argument("--limit", type=int, default=200)
        parser.add_argument("--json", action="store_true", help="one JSON object per line")

    def handle(self, *args: Any, **o: Any) -> None:
        qs = KbsAuditEntry.objects.all()
        if o["vm"]:
            qs = qs.filter(vm_id=o["vm"])
        if o["log"]:
            qs = qs.filter(log=o["log"])
        if o["since"]:
            qs = qs.filter(event_unix__gte=_unix(o["since"]))
        if o["until"]:
            qs = qs.filter(event_unix__lte=_unix(o["until"]))
        if o["op"]:
            qs = qs.filter(op=o["op"])
        if o["reason"]:
            qs = qs.filter(reason=o["reason"])
        if o["reason_contains"]:
            qs = qs.filter(reason__contains=o["reason_contains"])
        if o["epoch"]:
            qs = qs.filter(kbs_epoch__startswith=o["epoch"])
        if o["breaks"]:
            qs = qs.filter(chain_ok=False)
        rows = list(qs.order_by("event_unix", "log", "fetched_at", "seq")[: max(1, o["limit"])])

        for e in rows:
            body = decode_body(e.body_cbor)
            if o["json"]:
                self.stdout.write(
                    json.dumps(
                        {
                            "log": e.log,
                            "kbs_epoch": e.kbs_epoch,
                            "seq": e.seq,
                            "chain_ok": e.chain_ok,
                            "chain_error": e.chain_error,
                            "sha256": e.sha256,
                            "fetched_at": e.fetched_at.isoformat(),
                            "body": _jsonable(body) if body is not None else None,
                        },
                        sort_keys=True,
                    )
                )
                continue
            fields = [
                _when(e.event_unix),
                e.log,
                f"epoch={e.kbs_epoch[:12]}",
                f"seq={e.seq}",
                f"op={e.op or '-'}",
                f"vm={e.vm_id or '-'}",
                f"reason={e.reason or '-'}",
            ]
            if e.log == KbsAuditLog.RELEASE:
                fields.append(f"granted={e.granted}")
            else:
                fields += [
                    f"status={e.status_code}",
                    f"applied={e.applied}",
                    f"peer={e.peer_san or '-'}",
                ]
            fields.append("chain=ok" if e.chain_ok else f"chain=BROKEN({e.chain_error})")
            self.stdout.write(" ".join(fields))

        anomalies: list[KbsAuditAnomaly] = []
        if o["breaks"] and not o["vm"]:
            aq = KbsAuditAnomaly.objects.all()
            if o["log"]:
                aq = aq.filter(log=o["log"])
            if o["epoch"]:
                aq = aq.filter(kbs_epoch__startswith=o["epoch"])
            anomalies = list(aq.order_by("first_seen_at")[: max(1, o["limit"])])
        for a in anomalies:
            if o["json"]:
                self.stdout.write(
                    json.dumps(
                        {
                            "anomaly": a.kind,
                            "log": a.log,
                            "kbs_epoch": a.kbs_epoch,
                            "seq": None if a.seq < 0 else a.seq,
                            "observed": a.observed,
                            "detail": a.detail,
                            "count": a.count,
                            "first_seen_at": a.first_seen_at.isoformat(),
                            "last_seen_at": a.last_seen_at.isoformat(),
                        },
                        sort_keys=True,
                    )
                )
            else:
                self.stdout.write(
                    f"ANOMALY {a.kind} {a.log} epoch={a.kbs_epoch[:12]} "
                    f"seq={'-' if a.seq < 0 else a.seq} count={a.count} "
                    f"first={a.first_seen_at.isoformat()} {a.detail}"
                )

        if not rows and not anomalies:
            self.stderr.write("no matching KBS audit entries")
            raise SystemExit(1)
