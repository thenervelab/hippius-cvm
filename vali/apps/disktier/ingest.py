"""Record a miner's `v7` storage report (docs/design/disk-tier-verification.md
§4, §9) — RECORD ONLY.

The report is an untrusted self-report: it fills the miner-reported columns
of `MinerStoragePool` / `DedicatedDisk` (and the reported revision of a
node's `MinerStorageConfig`) and nothing else. It never sets a
tier, a health, a vali-side disk state or an assignment, and nothing reads
these rows for placement yet.

- A reported pool is upserted and un-retired; a known pool missing from
  the report is marked retired (its rows stay, so committed disks stay
  accounted once anything reads them).
- The report's `storage_config_revision` lands on the node's
  `MinerStorageConfig`, when it has one (`apps.disktier.storage_config`).
- A reported dedicated disk is created on first sight in `pending_probe`
  (vali's own state machine starts there); later reports only refresh the
  reported columns and the size. A disk missing from the report is left
  alone: vali alone decides when a disk leaves its inventory.

Sizes follow the `v4` convention: `0` on the wire is "unknown" (NULL), a
value above the column's range is not a real host (NULL), and an
`available` of 0 next to a known total is a full disk (kept).

The second half of this module is the passive receipt ingest (design §3.5,
phase P1, `on_verified_receipt`), also RECORD ONLY; see its docstring.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.telemetry.verifier import DeclaredStorage, DiskIoDelta, ServedReceiptFields

if TYPE_CHECKING:
    from apps.scheduler.models import Placement

from . import probe_results
from .models import (
    OS_SLOT,
    DedicatedDisk,
    DiskIngestCounter,
    DiskIoReceipt,
    DiskKind,
    MinerStoragePool,
    PlacementDisk,
    VmDiskIoHourly,
)
from .storage_config import desired_disk_states, record_reported_revision

_MIB = 1024 * 1024
# The `PositiveIntegerField` range shared by every backend.
_GB_MAX = 2_147_483_647
# The `PositiveBigIntegerField` range.
_BYTES_MAX = 9_223_372_036_854_775_807


def _known(value: int) -> int | None:
    return value if 0 < value <= _GB_MAX else None


def _available(value: int, total: int | None) -> int | None:
    if value == 0 and total is not None:
        return 0
    return _known(value)


def record_storage_report(node_id: str, report: DeclaredStorage, now: datetime) -> None:
    """Upsert `node_id`'s pools and dedicated disks from `report`."""
    with transaction.atomic():
        reported_pools = set()
        before = {
            p.pool_id: p.reported_error
            for p in MinerStoragePool.objects.filter(
                miner_node_id=node_id, reported_state="unavailable"
            ).only("pool_id", "reported_error")
        }
        for pool in report.pools:
            reported_pools.add(pool.pool_id)
            total = _known(pool.total_gb)
            MinerStoragePool.objects.update_or_create(
                miner_node_id=node_id,
                pool_id=pool.pool_id,
                defaults={
                    "declared_class": pool.declared_class,
                    "os_disks": pool.os_disks,
                    "total_gb": total,
                    "available_gb": _available(pool.available_gb, total),
                    "budget_gb": _known(pool.budget_gb),
                    "committed_gb": pool.committed_gb if pool.committed_gb <= _GB_MAX else None,
                    "reported_state": pool.state,
                    "reported_error": pool.error,
                    "reported_at": now,
                    "retired_at": None,
                },
            )
        MinerStoragePool.objects.filter(miner_node_id=node_id, retired_at__isnull=True).exclude(
            pool_id__in=reported_pools
        ).update(retired_at=now, unavailable_since=None)
        # How long a pool has been unavailable without a break (#1638).
        pools = MinerStoragePool.objects.filter(miner_node_id=node_id, pool_id__in=reported_pools)
        pools.filter(reported_state="unavailable", unavailable_since__isnull=True).update(
            unavailable_since=now
        )
        # Another reason is another outage: its clock starts now.
        changed = [
            p.pool_id
            for p in report.pools
            if p.state == "unavailable" and p.pool_id in before and before[p.pool_id] != p.error
        ]
        if changed:
            pools.filter(pool_id__in=changed).update(unavailable_since=now)
        pools.exclude(reported_state="unavailable").exclude(unavailable_since=None).update(
            unavailable_since=None
        )

        # A disk first seen after the desired document named it takes the
        # document's state from the start (a `draining` declaration must
        # not read as `active` until the next write).
        desired = desired_disk_states(node_id)
        for disk in report.dedicated_disks:
            reported = {
                "size_bytes": (
                    disk.size_mb * _MIB if 0 < disk.size_mb * _MIB <= _BYTES_MAX else None
                ),
                "reported_state": disk.state,
                "reported_error": disk.error,
                "reported_vm_id": disk.vm,
                "reported_at": now,
            }
            row, created = DedicatedDisk.objects.get_or_create(
                miner_node_id=node_id,
                disk_id=disk.disk_id,
                defaults={
                    **reported,
                    "declared_at": now,
                    "desired_state": desired.get(disk.disk_id, "active"),
                },
            )
            if not created:
                DedicatedDisk.objects.filter(pk=row.pk).update(**reported)

        # The revision of the vali-pushed document the agent has in force
        # (0 = its local config): the storage-config sync status and drift
        # repair read it. Only a node with a desired document keeps it.
        record_reported_revision(node_id, report.storage_config_revision, now)


# ─── passive receipt ingest (design §3.5, phase P1) ───────────────────
#
# `on_verified_receipt` folds the `disk_io` deltas of ONE verified served
# receipt into `VmDiskIoHourly`, keyed (vm_id, device, hour):
#
# - Hour: the whole window goes to the hour of its MIDPOINT. The guest
#   sends 60 s windows and the ingest takes none longer than
#   `VALI_DISK_IO_MAX_WINDOW_S` (300 s), so a split would move at most a
#   couple of minutes of I/O between neighbouring hours and cost a second
#   upsert per device for nothing the hourly median can see.
# - Miner: the one credited for the window's start in the §25 custody
#   history (`billing.credited_node_id`, as billing does), not "where the
#   VM is now": a source's buffered receipts are metered after a cutover.
#   Placement: that miner's placement of the VM (the active one, else its
#   newest one there, closed by a move or a release: the last minutes of a
#   destroyed VM still land on the miner that served them). An
#   unattributable window, or one with no placement on that miner, is
#   dropped.
# - Slot: the device's virtio serial (`hippius-<slot>`). Pool / dedicated
#   disk: that placement's `PlacementDisk` rows; a
#   placement without rows is the legacy layout, the OS disk on pool
#   `default`. A device whose serial names no slot (today every legacy
#   guest: the agent sets no disk serial yet), or a slot the placement does
#   not hold, is still recorded, with an empty slot / pool: the evaluator
#   grades only resolved devices.
# - Owner: that placement's `Placement.owner` (hashed when longer than
#   the column). An hour straddling a §25 move keeps the miner of its first
#   receipt: a device whose row for the hour already names another miner
#   is skipped (counted), never folded into the other miner's pool.
# - Counters above 2^40 in one window are not a disk (a device doing 2^40
#   I/Os in five minutes): the device is skipped, so a forged value can
#   never overflow the 63-bit columns.
# - `mismatch` / `missing` entries (dedicated-slot verdicts) carry no
#   counters to fold: they are counted and logged only.
# - QD >= 4 small-I/O bucket, per window: average queue depth
#   `tiq_ms / window_ms` >= 4 (Little's law) AND average I/O size
#   `(r_sectors + w_sectors) * 512 / (r_ios + w_ios)` <= 32 KiB. Such a
#   window adds its ios and r+w ticks to `qd4_small_ios` /
#   `qd4_small_ticks_ms`, and its reads alone to `qd4_small_r_*` (the
#   evaluator grades the read await). Integer math only, both bounds
#   inclusive.
#
# Replay: one `DiskIoReceipt` row per receipt body (SHA-256 of the
# guest-signed CBOR), inserted in the same transaction as the upserts, so a
# re-queued or replayed receipt is folded at most once whatever the billing
# watermark says. A receipt whose window is implausible (empty, longer than
# the max, stale, or in the future) is dropped and counted.
#
# The hook never fails or slows the receipt ingest: `on_verified_receipt_safe`
# catches and counts every exception; the work is bounded by the verifier's
# 16-device cap (one dedupe insert, two lookups, at most 16 upserts). While
# `VALI_DISK_IO_INGEST` and `VALI_DISK_PROBE_ENABLED` are both false it
# returns before touching the database; with only the probe on, it routes
# `disk_probe` (`probe_results.route`) and folds no `disk_io`.

log = logging.getLogger("apps.disktier.ingest")

#: The small-I/O bound: 32 KiB, in 512-byte sectors.
_SMALL_IO_SECTORS = 64
_SECTOR_BYTES = 512
#: The queue-depth bound of a graded window.
_MIN_QD = 4
#: Where a legacy placement (no `PlacementDisk` rows) keeps its OS disk.
LEGACY_POOL_ID = "default"
#: Placement statuses that hold a VM's disks.
_ACTIVE_PLACEMENT = ("pending", "bound")
#: The largest counter one window may carry (see the section comment).
_MAX_WINDOW_COUNTER = 2**40
_COUNTER_FIELDS = (
    "r_ios",
    "r_sectors",
    "r_ticks_ms",
    "w_ios",
    "w_sectors",
    "w_ticks_ms",
    "io_ticks_ms",
    "tiq_ms",
)
#: `VmDiskIoHourly.owner`.
_OWNER_MAX_LEN = 128

_COUNTER_NAMES = (
    # Receipts the flag dropped (process-local, never written: the flag
    # off must leave the database alone).
    "skipped_flag_off",
    # Receipts with disk evidence folded in, and the device-hour upserts.
    "receipts_ingested",
    "ingested_rows",
    # A replay of a receipt already folded.
    "dedupe_hits",
    # Devices recorded without a pool / dedicated disk.
    "unresolved_slots",
    # `mismatch` / `missing` dedicated-slot verdicts seen.
    "slot_verdicts",
    # Windows that landed in the QD >= 4 small-I/O bucket.
    "qd4_small_windows",
    # Receipts dropped: implausible window, no placement on the credited
    # miner (or unattributable custody), vm_id not the source's.
    "rejected_window",
    "rejected_no_placement",
    "rejected_source",
    # Devices skipped: an implausible counter; an hour already folded on
    # another miner (a §25 move inside the hour).
    "rejected_counters",
    "straddled_move",
    # `disk_probe` results seen (routed while VALI_DISK_PROBE_ENABLED, else
    # only logged), and what routing concluded (`probe_results.route`).
    "probe_results",
    "probe_accepted",
    "probe_repeat",
    "probe_rejected_not_probe_vm",
    "probe_rejected_unknown_run",
    "probe_rejected_wrong_nonce",
    "probe_rejected_wrong_node",
    "probe_rejected_wrong_owner",
    "probe_rejected_run_terminal",
    "probe_rejected_not_launched",
    # Exceptions the safe wrapper swallowed.
    "errors",
)

_lock = threading.Lock()
_pending: Counter[str] = Counter()


def _count(name: str, n: int = 1) -> None:
    assert name in _COUNTER_NAMES, name
    with _lock:
        _pending[name] += n


def drain_counters() -> dict[str, int]:
    """Take (and reset) the tallies since the last drain."""
    with _lock:
        out = {k: v for k, v in _pending.items() if v}
        _pending.clear()
    return out


def flush_counters_safe() -> dict[str, int]:
    """Fold the drained tallies into `DiskIngestCounter` (only while the
    ingest is on) and return them for the caller's log line. Never raises:
    a lost tally is logged, the receipt ingest goes on."""
    drained = drain_counters()
    if not drained or not (settings.VALI_DISK_IO_INGEST or settings.VALI_DISK_PROBE_ENABLED):
        return drained
    try:
        with transaction.atomic():
            for name, n in sorted(drained.items()):
                if name == "skipped_flag_off":
                    continue
                DiskIngestCounter.objects.get_or_create(name=name)
                DiskIngestCounter.objects.filter(name=name).update(value=F("value") + n)
    except Exception:  # noqa: BLE001 — counters must never break the meter.
        log.exception("disk ingest: counter flush failed, %s lost", drained)
    return drained


def qd4_small(delta: DiskIoDelta, window_s: int) -> bool:
    """Whether a window is a QD >= 4 small-I/O window (inclusive bounds):
    average queue depth `tiq_ms / (window_s * 1000)` >= 4 and average I/O
    size `(r_sectors + w_sectors) * 512 / (r_ios + w_ios)` <= 32 KiB."""
    ios = delta.r_ios + delta.w_ios
    if ios == 0 or window_s <= 0:
        return False
    deep = delta.tiq_ms >= _MIN_QD * window_s * 1000
    small = (delta.r_sectors + delta.w_sectors) <= _SMALL_IO_SECTORS * ios
    return deep and small


def hour_of_window(period_start: int, period_end: int) -> datetime:
    """The hour a window is attributed to: the hour of its midpoint."""
    mid = (period_start + period_end) // 2
    return datetime.fromtimestamp(mid - mid % 3600, tz=UTC)


def receipt_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class _Target:
    slot: str
    pool_id: str
    disk_id: str


def _slot_of_serial(serial: str) -> str:
    """`hippius-<slot>` → `<slot>`; anything else (an empty serial) → ""."""
    prefix = "hippius-"
    return serial[len(prefix) :] if serial.startswith(prefix) else ""


def _targets(placement_id: object) -> dict[str, _Target]:
    rows = list(
        PlacementDisk.objects.filter(placement_id=placement_id).values(
            "slot", "kind", "pool_id", "dedicated_disk__disk_id"
        )
    )
    if not rows:
        return {OS_SLOT: _Target(OS_SLOT, LEGACY_POOL_ID, "")}
    out: dict[str, _Target] = {}
    for r in rows:
        if r["kind"] == DiskKind.POOL:
            out[r["slot"]] = _Target(r["slot"], r["pool_id"], "")
        else:
            out[r["slot"]] = _Target(r["slot"], "", r["dedicated_disk__disk_id"] or "")
    return out


def owner_key(owner: str) -> str:
    """The owner as stored: itself, or a digest when longer than the
    column (a prefix could merge two owners into one vote)."""
    if len(owner) <= _OWNER_MAX_LEN:
        return owner
    return "sha256:" + hashlib.sha256(owner.encode()).hexdigest()


def _placement_for_window(vm_id: str, at_unix: int) -> Placement | None:
    """The placement that served `vm_id` at `at_unix`: the one on the
    miner the custody history credits then (falling back to the active
    placement's miner when no history covers it), else `None`."""
    from apps.scheduler import billing
    from apps.scheduler.models import Placement

    fields = ("id", "miner_node_id", "owner")
    active = (
        Placement.objects.filter(vm__vm_id=vm_id, status__in=_ACTIVE_PLACEMENT)
        .only(*fields)
        .first()
    )
    credited = billing.credited_node_id(
        vm_id=vm_id,
        at_unix=at_unix,
        fallback_node_id_hex=active.miner_node_id if active is not None else "",
    )
    if not credited:
        return None
    if active is not None and active.miner_node_id.lower() == credited.lower():
        return active
    return (
        Placement.objects.filter(vm__vm_id=vm_id, miner_node_id__iexact=credited)
        .order_by("-decided_at")
        .only(*fields)
        .first()
    )


def _window_ok(fields: ServedReceiptFields, now: datetime) -> bool:
    window = fields.period_end - fields.period_start
    if window <= 0 or window > int(settings.VALI_DISK_IO_MAX_WINDOW_S):
        return False
    now_unix = int(now.timestamp())
    if fields.period_end < now_unix - int(settings.VALI_DISK_IO_MAX_AGE_S):
        return False
    return fields.period_end <= now_unix + int(settings.VALI_DISK_IO_MAX_SKEW_S)


def on_verified_receipt(
    fields: ServedReceiptFields,
    *,
    body: bytes,
    source_id: str,
    now: datetime | None = None,
) -> str:
    """Fold one verified served receipt's disk evidence (see the section
    comment above). Returns what happened, for tests and logs: `off`,
    `empty`, `rejected-*`, `duplicate`, `ingested`, or `probe-<outcome>`
    when only a probe result was routed. May raise: callers on the receipt
    path use `on_verified_receipt_safe`.

    Two switches: `VALI_DISK_IO_INGEST` folds `disk_io`;
    `VALI_DISK_PROBE_ENABLED` routes `disk_probe` to its run
    (`probe_results.route`), whichever the other is."""
    io_on = bool(settings.VALI_DISK_IO_INGEST)
    probe_on = bool(settings.VALI_DISK_PROBE_ENABLED) and fields.disk_probe is not None
    if not io_on and not probe_on:
        _count("skipped_flag_off")
        return "off"
    if not fields.disk_io and fields.disk_probe is None:
        return "empty"
    if fields.vm_id != source_id:
        # Verified under `source_id`'s key, about another VM: not evidence
        # about either.
        _count("rejected_source")
        return "rejected-source"
    now = now or timezone.now()
    if not _window_ok(fields, now):
        _count("rejected_window")
        return "rejected-window"

    placement = _placement_for_window(fields.vm_id, fields.period_start)
    if placement is None:
        _count("rejected_no_placement")
        return "rejected-no-placement"

    digest = receipt_digest(body)
    probe_outcome = _route_probe(fields, placement, digest, now) if probe_on else ""
    if not io_on:
        return f"probe-{probe_outcome}"
    window_s = fields.period_end - fields.period_start
    hour = hour_of_window(fields.period_start, fields.period_end)
    with transaction.atomic():
        try:
            with transaction.atomic():
                DiskIoReceipt.objects.create(
                    receipt_digest=digest, vm_id=fields.vm_id, ingested_at=now
                )
        except IntegrityError:
            _count("dedupe_hits")
            return "duplicate"
        if fields.disk_probe is not None and not probe_on:
            _count("probe_results")
            probe_results.record_unverified(
                fields.disk_probe, vm_id=fields.vm_id, receipt_digest=digest
            )
        targets = _targets(placement.pk) if fields.disk_io else {}
        rows = 0
        for delta in fields.disk_io:
            if delta.state != "ok":
                _count("slot_verdicts")
                log.info(
                    "disk ingest: slot verdict %s for %s on vm=%s (recorded only)",
                    delta.state,
                    delta.serial,
                    fields.vm_id,
                )
                continue
            if any(getattr(delta, k) > _MAX_WINDOW_COUNTER for k in _COUNTER_FIELDS):
                _count("rejected_counters")
                continue
            slot = _slot_of_serial(delta.serial)
            target = targets.get(slot) if slot else None
            if target is None:
                _count("unresolved_slots")
                target = _Target(slot, "", "")
            if _upsert(
                fields=fields,
                delta=delta,
                target=target,
                miner_node_id=placement.miner_node_id,
                owner=owner_key(placement.owner),
                hour=hour,
                window_s=window_s,
            ):
                rows += 1
    _count("receipts_ingested")
    if rows:
        _count("ingested_rows", rows)
    return "ingested"


def _route_probe(
    fields: ServedReceiptFields, placement: Placement, digest: str, now: datetime
) -> str:
    """Route the receipt's `disk_probe` to its run, in its own transaction:
    a failure here is counted and never costs the receipt its `disk_io`."""
    from .probe import linger_s

    assert fields.disk_probe is not None
    _count("probe_results")
    try:
        with transaction.atomic():
            outcome = probe_results.route(
                fields.disk_probe,
                receipt_node_id=fields.node_id_hex,
                placement_node_id=placement.miner_node_id,
                placement_owner=placement.owner,
                receipt_digest=digest,
                linger_s=linger_s(),
                now=now,
            )
    except Exception:  # noqa: BLE001 — the receipt ingest must never fail here.
        _count("errors")
        log.exception("disk-probe routing failed for vm=%s (receipt unaffected)", fields.vm_id)
        return "error"
    _count(f"probe_{outcome}")
    if outcome.startswith("rejected"):
        log.warning("disk-probe result from vm=%s %s", fields.vm_id, outcome)
    return outcome


def _upsert(
    *,
    fields: ServedReceiptFields,
    delta: DiskIoDelta,
    target: _Target,
    miner_node_id: str,
    owner: str,
    hour: datetime,
    window_s: int,
) -> bool:
    """Fold one device window; `False` when the hour belongs to another
    miner (see the section comment)."""
    row, created = VmDiskIoHourly.objects.get_or_create(
        vm_id=fields.vm_id,
        device=delta.dev,
        hour=hour,
        defaults={
            "miner_node_id": miner_node_id,
            "owner": owner,
            "slot": target.slot,
            "pool_id": target.pool_id,
            "disk_id": target.disk_id,
        },
    )
    if not created and row.miner_node_id.lower() != miner_node_id.lower():
        _count("straddled_move")
        return False
    bucket = qd4_small(delta, window_s)
    if bucket:
        _count("qd4_small_windows")
    increments = {
        "windows": F("windows") + 1,
        "seconds": F("seconds") + window_s,
        "r_ios": F("r_ios") + delta.r_ios,
        "w_ios": F("w_ios") + delta.w_ios,
        "r_sectors": F("r_sectors") + delta.r_sectors,
        "w_sectors": F("w_sectors") + delta.w_sectors,
        "r_ticks_ms": F("r_ticks_ms") + delta.r_ticks_ms,
        "w_ticks_ms": F("w_ticks_ms") + delta.w_ticks_ms,
        "io_ticks_ms": F("io_ticks_ms") + delta.io_ticks_ms,
        "tiq_ms": F("tiq_ms") + delta.tiq_ms,
    }
    if bucket:
        increments.update(
            qd4_small_ios=F("qd4_small_ios") + delta.r_ios + delta.w_ios,
            qd4_small_ticks_ms=F("qd4_small_ticks_ms") + delta.r_ticks_ms + delta.w_ticks_ms,
            qd4_small_r_ios=F("qd4_small_r_ios") + delta.r_ios,
            qd4_small_r_ticks_ms=F("qd4_small_r_ticks_ms") + delta.r_ticks_ms,
        )
    VmDiskIoHourly.objects.filter(pk=row.pk).update(**increments)
    return True


def on_verified_receipt_safe(fields: ServedReceiptFields, *, body: bytes, source_id: str) -> str:
    """`on_verified_receipt` for the receipt path: never raises. Every
    exception is logged and counted (`errors`); the caller's billing and
    acceptance of the receipt are untouched."""
    try:
        return on_verified_receipt(fields, body=body, source_id=source_id)
    except Exception:  # noqa: BLE001 — the receipt ingest must never fail here.
        _count("errors")
        log.exception("disk ingest failed for vm=%s (receipt unaffected)", fields.vm_id)
        return "error"


def dedupe_keep() -> timedelta:
    """How long a `DiskIoReceipt` must outlive its receipt: past this, the
    receipt's window is too old for `_window_ok`, so a replay is refused
    without it."""
    return timedelta(
        seconds=int(settings.VALI_DISK_IO_MAX_AGE_S)
        + int(settings.VALI_DISK_IO_MAX_SKEW_S)
        + int(settings.VALI_DISK_IO_MAX_WINDOW_S)
        + 3600
    )
