"""Builders for the dedicated-disk tests (`apps.disktier.dedicated`).
Plain helpers, not fixtures; the row builders need `@django_db`."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

from apps.disktier.dedicated import GIB
from apps.disktier.models import DedicatedDisk, DedicatedDiskState
from apps.scheduler.models import MinerCapacity
from apps.scheduler.tests.factories import node_id

#: The agent release the tests treat as the first that takes `extra_disks`.
AGENT_MIN = "v2026.10.20"
#: Flags for a canary that may launch with dedicated disks.
ON: dict[str, Any] = dict(
    VALI_DEDICATED_ENABLED=True,
    VALI_DEDICATED_MIN_GUEST_RELEASE=5,
    VALI_DEDICATED_MIN_AGENT_VERSION=AGENT_MIN,
)


def capable(node: str, version: str = AGENT_MIN) -> MinerCapacity:
    """A node whose agent reports `version` (v6)."""
    now = timezone.now()
    row, _ = MinerCapacity.objects.update_or_create(
        miner_node_id=node,
        defaults=dict(
            status="active",
            capacity_slots=4,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=now,
            agent_version=version,
            agent_version_reported_at=now,
            host_health_reported_at=now,
        ),
    )
    return row


def make_disk(
    disk_id: str,
    *,
    node: str | None = None,
    size_gib: int = 22354,
    tier: str = "hdd",
    state: str = DedicatedDiskState.FREE,
    probed_at: datetime | None = None,
    **kw: Any,
) -> DedicatedDisk:
    """A disk vali would sell: free, probed (tier and size), reported free
    just now at the probed size."""
    now = timezone.now()
    fields: dict[str, Any] = dict(
        size_bytes=size_gib * GIB,
        verified_size_bytes=size_gib * GIB,
        verified_tier=tier,
        state=state,
        probed_at=probed_at or now - timedelta(days=1),
        reported_state="free",
        reported_vm_id="",
        reported_at=now,
    )
    fields.update(kw)
    return DedicatedDisk.objects.create(miner_node_id=node or node_id(1), disk_id=disk_id, **fields)
