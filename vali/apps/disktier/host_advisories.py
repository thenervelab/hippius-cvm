"""§18.5 host disk advisories, fed by the §18.10 host inventory.

UNTRUSTED, owner-facing only, like the inventory they come from: shown to
the node's owner and pushed as ops-only gauges, read by nothing that
decides (`tests/test_host_inventory.py` pins who may import them).

- `merge_advisories`: the storage section of each accepted report upserts
  `HostDiskAdvisory` rows (one per node, subject and code); a severity
  change or a reopening appends a `HostDiskAdvisoryEvent`. A row absent
  from a COMPLETE report (`status: ok`, advisories not truncated) is
  resolved. Runs inside the report's merge transaction.
- `advisories_readout`: the operator feed (`GET …/host-disk-advisories`).
- `push_node_metrics`: `hippius_host_info` and `hippius_host_advisory`
  for one node, after its report commits. Labels carry models, versions
  and counts — never a serial, a by-id name or a subject.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from django.conf import settings

from .models import (
    AdvisoryTransition,
    HostDiskAdvisory,
    HostDiskAdvisoryEvent,
    HostInventorySection,
)

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3}
HISTORY_DAYS_MAX = 90
HISTORY_MAX = 200
#: Open advisories one node may hold (a report carries at most 64): past
#: it, the least recently seen are resolved to make room.
MAX_OPEN_PER_NODE = 256
#: An open advisory no report has carried for this long is resolved, so
#: a host that never sends a complete report cannot pile them up.
STALE_OPEN = timedelta(days=7)
_I64_MAX = 2**63 - 1
#: Label values are host-controlled text: bounded.
_LABEL_MAX = 64

#: The action the dashboard suggests per code — a closed vocabulary the
#: backend renders as text (§18.5). None: nothing for the owner to do.
SUGGESTED_ACTIONS: dict[str, str | None] = {
    "smart_overall_failed": "replace_disk",
    "reallocated_sectors": "replace_disk",
    "pending_sectors": "replace_disk",
    "offline_uncorrectable": "replace_disk",
    "udma_crc_errors": "check_cabling",
    "temperature_high": "check_cooling",
    "power_on_hours": None,
    "nvme_critical_warning": "replace_disk",
    "nvme_media_errors": "replace_disk",
    "nvme_spare_low": "replace_disk",
    "nvme_wear_high": "replace_disk",
    "smart_unavailable_behind_controller": "switch_controller_to_hba_mode",
    "smart_unavailable": "install_smartmontools",
    "kernel_io_error": "check_cabling",
    "kernel_timeout_reset": "check_cabling",
    "kernel_medium_error": "replace_disk",
    "fs_error": "fsck_and_remount",
    "fs_remounted_ro": "fsck_and_remount",
    "md_degraded": "rebuild_array",
    "md_rebuilding": None,
    "btrfs_device_errors": "replace_disk",
    "mount_missing": "fsck_and_remount",
    "mount_ro": "fsck_and_remount",
    "collector_missing_tools": "install_smartmontools",
    "collector_timeout": "investigate_collector_timeout",
    "collector_stale": "investigate_collector_timeout",
    "collector_partial": "investigate_collector_timeout",
}

M_HOST_INFO = "hippius_host_info"
M_HOST_ADVISORY = "hippius_host_advisory"
_PUSH_TIMEOUT_S = 3.0

_Key = tuple[str, str, str]


def _ts(unix: Any, now: datetime) -> datetime:
    """A host-reported unix time, clamped to [epoch, now + skew]: the
    crate bounds neither end, and a wild value must not fail the report."""
    ceiling = int(now.timestamp()) + int(settings.VALI_HOST_INVENTORY_MAX_SKEW_S)
    return datetime.fromtimestamp(min(max(int(unix), 0), ceiling), tz=UTC)


def _event(node_id: str, key: _Key, transition: str, severity: str, at: datetime) -> None:
    kind, ref, code = key
    HostDiskAdvisoryEvent.objects.create(
        miner_node_id=node_id,
        subject_kind=kind,
        subject_ref=ref,
        code=code,
        transition=transition,
        severity=severity,
        at=at,
    )


def merge_advisories(node_id: str, storage: dict[str, Any], now: datetime) -> None:
    """Upsert `node_id`'s advisories from one storage section. Call inside
    the report's transaction."""
    rows: dict[_Key, HostDiskAdvisory] = {
        (r.subject_kind, r.subject_ref, r.code): r
        for r in HostDiskAdvisory.objects.select_for_update().filter(miner_node_id=node_id)
    }
    seen: set[_Key] = set()
    for a in storage.get("advisories") or []:
        key: _Key = (str(a["subject_kind"]), str(a["subject"]), str(a["code"]))
        seen.add(key)
        severity = str(a["severity"])
        first_seen = _ts(a["first_seen_unix"], now)
        fields = {
            "severity": severity,
            # u64 on the wire, a signed bigint here.
            "count": min(int(a["count"]), _I64_MAX),
            "value": int(a["value"]),
            "first_seen": first_seen,
            "last_seen": max(_ts(a["last_seen_unix"], now), first_seen),
            "sample": str(a.get("sample") or ""),
            "resolved_at": None,
            "updated_at": now,
        }
        row = rows.get(key)
        if row is None:
            row = HostDiskAdvisory.objects.create(
                miner_node_id=node_id,
                subject_kind=key[0],
                subject_ref=key[1],
                code=key[2],
                **fields,
            )
            rows[key] = row
            _event(node_id, key, AdvisoryTransition.OPENED, severity, now)
            continue
        if row.resolved_at is not None:
            _event(node_id, key, AdvisoryTransition.OPENED, severity, now)
        elif row.severity != severity:
            up = SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(row.severity, 0)
            transition = AdvisoryTransition.ESCALATED if up else AdvisoryTransition.DEESCALATED
            _event(node_id, key, transition, severity, now)
        for name, value in fields.items():
            setattr(row, name, value)
        row.save(update_fields=list(fields))

    complete = storage.get("status") == "ok" and not storage.get("advisories_truncated", False)
    unseen = [
        (key, row) for key, row in rows.items() if key not in seen and row.resolved_at is None
    ]
    # Absent from a complete report, or carried by none for a week.
    gone = [kr for kr in unseen if complete or now - kr[1].updated_at > STALE_OPEN]
    # Over the cap: the least recently seen go first.
    kept = sorted((kr for kr in unseen if kr not in gone), key=lambda kr: kr[1].last_seen)
    excess = len(seen) + len(kept) - MAX_OPEN_PER_NODE
    gone += kept[: max(0, excess)]
    for key, row in gone:
        row.resolved_at = now
        row.updated_at = now
        row.save(update_fields=["resolved_at", "updated_at"])
        _event(node_id, key, AdvisoryTransition.RESOLVED, row.severity, now)


def _advisory(row: HostDiskAdvisory) -> dict[str, Any]:
    return {
        "code": row.code,
        "severity": row.severity,
        "count": row.count,
        "value": row.value,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "sample": row.sample or None,
        "suggested_action": SUGGESTED_ACTIONS.get(row.code),
        "resolved_at": row.resolved_at,
    }


def advisories_readout(
    node_id: str, *, include_resolved: bool, history_days: int, now: datetime
) -> dict[str, Any]:
    from .host_inventory import section_status

    storage = HostInventorySection.objects.filter(miner_node_id=node_id, section="storage").first()
    status = section_status(storage, now)
    rows = HostDiskAdvisory.objects.filter(miner_node_id=node_id)
    if not include_resolved:
        rows = rows.filter(resolved_at__isnull=True)
    subjects: dict[tuple[str, str], list[HostDiskAdvisory]] = {}
    for row in rows.order_by("subject_kind", "subject_ref", "code"):
        subjects.setdefault((row.subject_kind, row.subject_ref), []).append(row)

    def worst(items: list[HostDiskAdvisory]) -> str:
        open_ = [r.severity for r in items if r.resolved_at is None]
        return max(open_, key=lambda s: SEVERITY_RANK.get(s, 0)) if open_ else "ok"

    out: dict[str, Any] = {
        "node_id": node_id,
        "verified": False,
        "reported_at": storage.reported_at if storage else None,
        "collector": {"status": status},
        "subjects": [
            {
                "kind": kind,
                "ref": ref,
                "severity": worst(items),
                "advisories": [_advisory(r) for r in items],
            }
            for (kind, ref), items in subjects.items()
        ],
        "truncated": bool(storage and storage.body.get("advisories_truncated", False)),
    }
    if history_days > 0:
        events = list(
            HostDiskAdvisoryEvent.objects.filter(
                miner_node_id=node_id, at__gte=now - timedelta(days=history_days)
            ).order_by("-at", "-id")[: HISTORY_MAX + 1]
        )
        out["history_truncated"] = len(events) > HISTORY_MAX
        out["history"] = [
            {
                "at": e.at,
                "kind": e.subject_kind,
                "subject": e.subject_ref,
                "code": e.code,
                "transition": e.transition,
                "severity": e.severity,
            }
            for e in events[:HISTORY_MAX]
        ]
    return out


def _info_labels(sections: dict[str, dict[str, Any]]) -> dict[str, str]:
    def text(section: str, key: str) -> str:
        value = (sections.get(section) or {}).get(key)
        return value[:_LABEL_MAX] if isinstance(value, str) else ""

    return {
        "cpu_model": text("cpu", "model"),
        "bios_version": text("system", "bios_version"),
        "kernel": text("software", "kernel"),
    }


def push_node_metrics(node_id: str) -> None:
    """Replace `node_id`'s metric group. Never raises: a gateway outage
    must not cost the report."""
    gateway = str(getattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "") or "")
    if not gateway:
        return
    try:
        from apps.synthetic import metrics

        sections = {
            r.section: r.body
            for r in HostInventorySection.objects.filter(
                miner_node_id=node_id, section__in=("cpu", "system", "software")
            )
        }
        ms = metrics.MetricSet()
        ms.gauge(
            M_HOST_INFO,
            1,
            help_text="Host-reported (UNTRUSTED) hardware/software of a node.",
            node_id=node_id,
            **_info_labels(sections),
        )
        open_counts = Counter(
            HostDiskAdvisory.objects.filter(
                miner_node_id=node_id, resolved_at__isnull=True
            ).values_list("subject_kind", "code", "severity")
        )
        for (kind, code, severity), n in sorted(open_counts.items()):
            ms.gauge(
                M_HOST_ADVISORY,
                n,
                help_text="Open host-reported (UNTRUSTED) disk advisories of a node.",
                node_id=node_id,
                kind=kind,
                code=code,
                severity=severity,
            )
        metrics.push(
            ms,
            gateway_url=gateway,
            job="vali-host-inventory",
            grouping_key={"node_id": node_id},
            replace=True,
            timeout_s=_PUSH_TIMEOUT_S,
        )
    except Exception:  # noqa: BLE001 — observability must never cost the report.
        log.exception("host-inventory metrics push failed: node=%s…", node_id[:16])
