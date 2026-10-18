"""§18.10 host inventory: the per-section merge of a verified report.

UNTRUSTED and owner-facing only: what this module stores is shown to the
node's owner and read by nothing else (no tier, placement, cordon, pay,
strike or bill — `tests/test_host_inventory.py`). A report is
verified, bounded and canonical before it gets here (the Rust
`verify-host-inventory`); this module enforces the per-node order and
budget and keeps the latest state of each section:

- `sequence` strictly above the last accepted one of the same registry
  identity (replay floor; a node re-registered under a new identity
  starts a new floor, as the agent's persisted sequence does);
- at most `VALI_HOST_INVENTORY_MAX_PER_HOUR` verified reports per node and
  hour, counted whether accepted or not;
- each section present replaces the stored one as a whole; a section
  absent is unchanged, never removed; a changed digest records which
  top-level fields changed (`HostInventoryChange`).

Never log a body: sections carry serials and by-id names."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction

from .host_advisories import merge_advisories, push_node_metrics
from .models import (
    HostInventoryChange,
    HostInventorySection,
    HostInventorySectionName,
    HostInventoryState,
)

log = logging.getLogger(__name__)

SECTIONS: tuple[str, ...] = tuple(HostInventorySectionName.values)

_WINDOW = timedelta(hours=1)

#: Sections a `counters` report refreshes every 6 h: stale past two missed
#: refreshes and an hour. The others come with the daily `full` report.
COUNTER_SECTIONS = frozenset({"memory", "storage", "sensors", "software"})
STALE_COUNTERS = timedelta(hours=13)
STALE_FULL = timedelta(hours=26)


def is_stale(row: HostInventorySection, now: datetime) -> bool:
    limit = STALE_COUNTERS if row.section in COUNTER_SECTIONS else STALE_FULL
    return now - row.reported_at > limit


def section_status(row: HostInventorySection | None, now: datetime) -> str:
    """The collector's own status, else `stale` past the section's cadence,
    else `never` when no report carried it."""
    if row is None:
        return "never"
    return "stale" if is_stale(row, now) else str(row.body.get("status", ""))


class InventoryRefused(Exception):
    """A verified report vali does not take: `category` is the wire
    error category, `retry_after_s` set on a budget refusal."""

    def __init__(self, message: str, category: str, *, retry_after_s: int | None = None):
        super().__init__(message)
        self.category = category
        self.retry_after_s = retry_after_s


@dataclass(frozen=True)
class Recorded:
    sections: tuple[str, ...]
    changed: tuple[str, ...]


def _changed_fields(before: Any, after: Any) -> list[str]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    return sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))


def _take_budget(node_id: str, now: datetime) -> None:
    """Count this report in `node_id`'s hour window, committed on its own
    so a refused report still spends it; refuse past the budget."""
    with transaction.atomic():
        state, _ = HostInventoryState.objects.select_for_update().get_or_create(
            miner_node_id=node_id,
            defaults={"window_started_at": now, "window_count": 0},
        )
        if now - state.window_started_at >= _WINDOW or now < state.window_started_at:
            state.window_started_at = now
            state.window_count = 0
        state.window_count += 1
        state.save(update_fields=["window_started_at", "window_count"])
        count, started = state.window_count, state.window_started_at
    if count > int(settings.VALI_HOST_INVENTORY_MAX_PER_HOUR):
        retry = started + _WINDOW - now
        raise InventoryRefused(
            "host-inventory report budget exhausted",
            "rate-limited",
            retry_after_s=max(1, int(retry.total_seconds())),
        )


def record_host_inventory(
    node_id: str,
    miner_id: str,
    body: dict[str, Any],
    digests: dict[str, str],
    *,
    reported_at: datetime,
    now: datetime,
) -> Recorded:
    """Merge one verified report of `node_id`. Raises `InventoryRefused`
    (replay, budget); the budget count survives the refusal."""
    sequence = int(body["sequence"])
    sections: dict[str, Any] = body.get("sections") or {}
    present = tuple(name for name in SECTIONS if sections.get(name) is not None)
    if set(present) != set(digests):
        # The verifier digests exactly the sections the body carries.
        raise InventoryRefused("section digests do not match the body", "internal")

    _take_budget(node_id, now)
    with transaction.atomic():
        state = HostInventoryState.objects.select_for_update().get(miner_node_id=node_id)
        if state.miner_id != miner_id:
            if state.last_sequence is not None:
                log.info(
                    "host inventory floor reset: node=%s… identity %s → %s",
                    node_id[:16],
                    state.miner_id or "-",
                    miner_id,
                )
            state.last_sequence = None
        if state.last_sequence is not None and sequence <= state.last_sequence:
            raise InventoryRefused("sequence not above the last accepted report", "replay")

        stored = {
            row.section: row
            for row in HostInventorySection.objects.select_for_update().filter(
                miner_node_id=node_id, section__in=present
            )
        }
        changed: list[str] = []
        for name in present:
            section = sections[name]
            old = stored.get(name)
            if old is not None and old.digest != digests[name]:
                changed.append(name)
                HostInventoryChange.objects.create(
                    miner_node_id=node_id,
                    section=name,
                    at=now,
                    fields=_changed_fields(old.body, section),
                )
            HostInventorySection.objects.update_or_create(
                miner_node_id=node_id,
                section=name,
                defaults={
                    "digest": digests[name],
                    "body": section,
                    "status": str(section.get("status", "")),
                    "reported_at": reported_at,
                    "sequence": sequence,
                    "received_at": now,
                },
            )
        state.miner_id = miner_id
        state.last_sequence = sequence
        state.last_reported_at = reported_at
        state.received_at = now
        state.save(update_fields=["miner_id", "last_sequence", "last_reported_at", "received_at"])
        if "storage" in present:
            merge_advisories(node_id, sections["storage"], now)

    push_node_metrics(node_id)

    log.info(
        "host inventory recorded: node=%s… seq=%s report=%s sections=%d changed=%s",
        node_id[:16],
        sequence,
        body.get("report"),
        len(present),
        ",".join(changed) or "-",
    )
    return Recorded(sections=present, changed=tuple(changed))
