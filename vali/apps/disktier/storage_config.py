"""The `storage-config` order: stage the desired document, push it, record
the agent's verdict (docs/design/disk-tier-verification.md §9).

The state machine is net-policy's (`apps.network.net_policy`), with the
document written by an operator instead of built by vali.

## Revision

`MinerStorageConfig.revision` is per node and monotonic: the agent refuses
a lower revision (`409 storage-config-stale-revision`) and the same one
with other content (`409 storage-config-revision-conflict`). A write bumps
it only when the content changes. After a `409` vali jumps past the
agent's revision (to the one its heartbeat reports when that is higher)
and re-stages, so the operator's revision moves under it too: the next
`If-Match` must carry the new value.

## Push cadence (`reconcile`, in the orchestration tick)

Nothing at all while `VALI_STORAGE_CONFIG_PUSH` is off. A node is pushed
only when it has a desired document, its miner is in
`VALI_STORAGE_CONFIG_MINERS` (miner_id or node_id, `*` = all) and its
agent's v6 `agent_version` is at least
`VALI_STORAGE_CONFIG_MIN_AGENT_VERSION` (empty = nobody; `*` = any agent,
dev builds included). A due node is sent its document at once after a
change, every `VALI_STORAGE_CONFIG_RETRY_S` while it is not acked —
doubled per `422` refusal or `500` store failure, up to
`VALI_STORAGE_CONFIG_APPLY_BACKOFF_MAX_S` — and every
`VALI_STORAGE_CONFIG_SYNC_S` once acked (expiry renewal). A heartbeat
that reports another revision than the acked one after the ack (the agent
restarted onto its local config) is drift: re-sent after `RETRY_S`. An
agent without the route (`404`) or with it switched off (`503
storage-config-disabled`) is left alone for
`VALI_STORAGE_CONFIG_UNSUPPORTED_RETRY_S`. Every push carries a fresh
`order_id`.

## Draining pools

`DELETE …/pools/{id}` marks a pool `draining` (no new disk). The pass
removes it from the document — a new revision — once the agent acked the
draining document, its heartbeat reports that revision in force, and the
pool reports `committed_gb == 0` (or left the report). Removing a pool
that still holds disks would only earn a `pool-has-disks` refusal.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from apps.miners.models import MinerIdentity
from apps.orchestration import order_dispatch

from . import node_family, storage_doc
from .models import (
    DedicatedDisk,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
)

log = logging.getLogger("apps.disktier.storage_config")

#: The agent refuses an order valid for longer than this.
MAX_TTL_S = 7 * 24 * 3600
#: The revision columns are signed 64-bit; the agent's revision a `u64`.
MAX_REVISION = 2**63 - 1
KIND = "storage-config"

STALE_REVISION = "storage-config-stale-revision"
REVISION_CONFLICT = "storage-config-revision-conflict"
STORE_FAILED = "storage-config-store"
DISABLED = "storage-config-disabled"

#: Sync states (`sync_status`). `refused` is reported as
#: `refused:<code>:<pool or disk>`.
IN_SYNC = "in_sync"
PENDING = "pending"
REFUSED = "refused"
AGENT_UNSUPPORTED = "agent-unsupported"
DRIFT = "drift"
UNMANAGED = "unmanaged"
SYNC_STATES = (IN_SYNC, PENDING, REFUSED, AGENT_UNSUPPORTED, DRIFT)

#: Who an automatic change is attributed to in the audit.
SYSTEM_PRINCIPAL = "vali"


class StageConflict(Exception):
    """`If-Match` named another revision than the current one."""

    def __init__(self, current: int) -> None:
        super().__init__(f"the current revision is {current}")
        self.current = current


@dataclass(frozen=True)
class Actor:
    """Who a write is made by: the service principal and the family +
    backend user it acts for. `account` is the family's 32-byte account
    (hex), the one the chain check verified; empty for vali itself."""

    principal: str
    family: str = ""
    user: str = ""
    account: str = ""

    @property
    def system(self) -> bool:
        return not self.account


SYSTEM = Actor(principal=SYSTEM_PRINCIPAL)


# ─── staging ─────────────────────────────────────────────────────────


def local_limits(node_id: str, account: str = "") -> dict[str, Any]:
    """What vali knows of the node's local facts, as `storage_doc.normalize`
    keywords: the host budget its agent reports for `default`; and from
    the last document the agent accepted, `default`'s path (its data root)
    and the paths of the pools it reports holding disks. The accepted
    document binds (and is disclosed through refusals) only for the family
    that wrote it, `account` (empty = vali itself)."""
    reported = {
        p.pool_id: p
        for p in MinerStoragePool.objects.filter(miner_node_id=node_id, retired_at__isnull=True)
    }
    default = reported.get(storage_doc.DEFAULT_POOL_ID)
    row = MinerStorageConfig.objects.filter(miner_node_id=node_id).first()
    # Only while the accepted document is the one in force: an agent that
    # reports another revision (0 after its local config changed, e.g. a
    # new data root) may no longer hold those facts.
    in_force = (
        row is not None
        and row.acked_revision > 0
        and row.reported_revision == row.acked_revision
        and (not account or row.owner_family == account)
    )
    accepted = row.acked_body if in_force and row is not None else {}
    paths = {p["id"]: p["path"] for p in accepted.get("pools", [])}
    held = {
        pool_id: path
        for pool_id, path in paths.items()
        if pool_id in reported and (reported[pool_id].committed_gb or 0) > 0
    }
    return {
        "default_budget_gb": default.budget_gb if default is not None else None,
        "default_path": paths.get(storage_doc.DEFAULT_POOL_ID),
        "held_paths": held,
    }


def audit(
    node_id: str,
    revision: int,
    action: str,
    actor: Actor,
    *,
    doc: dict[str, Any] | None = None,
    outcome: str = "",
    now: datetime | None = None,
) -> None:
    MinerStorageConfigAudit.objects.create(
        miner_node_id=node_id,
        revision=revision,
        action=action,
        principal=actor.principal[:128],
        family=actor.family[:64],
        family_account=actor.account[:64],
        user=actor.user[:128],
        doc=doc or {},
        outcome=outcome[:192],
        at=now or timezone.now(),
    )


def owned_by(row: MinerStorageConfig | None, account: str) -> MinerStorageConfig | None:
    """`row` when it holds a document of the family `account`, else `None`.
    A node keeps its row (and its revision floor) when it changes hands on
    chain, but the former family's document is not the new family's: it
    reads as no document, the first write replaces it, and it is never
    pushed (`sync_node`)."""
    if row is None or row.revision == 0 or row.owner_family != account:
        return None
    return row


def visible_revision(row: MinerStorageConfig | None, actor: Actor) -> int:
    """The revision `If-Match` is compared with: 0 when `actor`'s family
    has no document on the node."""
    if row is None:
        return 0
    if actor.system:
        return row.revision
    return row.revision if owned_by(row, actor.account) is not None else 0


def _lock_node(node_id: str) -> None:
    """Lock the node's miner identity row first, in every writer of the
    desired document: the heartbeat ingest holds that lock while it writes
    the pools, the disks and then this row, so taking it first keeps one
    lock order (no deadlock) and serializes a write with a report."""
    list(MinerIdentity.objects.select_for_update().filter(chain_node_id=node_id))


def stage(
    node_id: str,
    doc: dict[str, Any],
    *,
    actor: Actor,
    action: str,
    if_match: int | None = None,
    now: datetime | None = None,
) -> tuple[MinerStorageConfig, bool]:
    """Make the canonical `doc` the node's desired document, owned by
    `actor`'s family. Returns `(row, changed)`: unchanged content of the
    same family keeps the revision. Raises `StageConflict` when `if_match`
    is not the revision `actor` sees (0 = no document of its family).
    Audited either way."""
    now = now or timezone.now()
    key = storage_doc.content_key(doc)
    with transaction.atomic():
        _lock_node(node_id)
        row, _ = MinerStorageConfig.objects.select_for_update().get_or_create(miner_node_id=node_id)
        seen = visible_revision(row, actor)
        if if_match is not None and if_match != seen:
            raise StageConflict(seen)
        new_owner = not actor.system and row.owner_family != actor.account
        if row.revision > 0 and row.content_key == key and not new_owner:
            audit(node_id, row.revision, action, actor, doc=doc, outcome="unchanged", now=now)
            return row, False
        _bump(row, doc, key)
        if new_owner:
            row.owner_family = actor.account
            row.owner_since = now
            # What the agent accepted from the former family is not this
            # family's to see or be held to.
            row.acked_body = {}
        row.updated_by_principal = actor.principal[:128]
        row.updated_by_family = actor.family[:64]
        row.updated_by_user = actor.user[:128]
        row.updated_at = now
        row.save()
        _sync_disk_desired_states(node_id, doc)
        audit(node_id, row.revision, action, actor, doc=doc, outcome="staged", now=now)
        return row, True


def desired_disk_states(node_id: str) -> dict[str, str]:
    """`{disk_id: state}` the node's desired document declares."""
    body = (
        MinerStorageConfig.objects.filter(miner_node_id=node_id, revision__gt=0)
        .values_list("body", flat=True)
        .first()
    ) or {}
    return {d["id"]: d["state"] for d in body.get("dedicated_disks", [])}


def _sync_disk_desired_states(node_id: str, doc: dict[str, Any]) -> None:
    """Mirror the document's dedicated-disk states onto vali's known
    disks at once: a disk being drained takes no new assignment even
    before the agent acks."""
    for state in storage_doc.DESIRED_STATES:
        ids = [d["id"] for d in doc.get("dedicated_disks", []) if d["state"] == state]
        if ids:
            DedicatedDisk.objects.filter(miner_node_id=node_id, disk_id__in=ids).exclude(
                desired_state=state
            ).update(desired_state=state)


def _bump(row: MinerStorageConfig, doc: dict[str, Any], key: str) -> None:
    """One revision up for `doc`; the digest is the push loop's to fill."""
    if row.revision >= MAX_REVISION:
        raise storage_doc.DocError(
            "storage-config-revision-exhausted", "the node's revision counter is exhausted"
        )
    row.revision += 1
    row.body = doc
    row.content_key = key
    row.body_sha = ""
    row.apply_failures = 0
    row.last_error = ""
    row.refusal_code = row.refusal_pool = row.refusal_disk = ""


def edit(
    node_id: str,
    change: Any,
    *,
    actor: Actor,
    action: str,
    if_match: int | None = None,
    now: datetime | None = None,
) -> tuple[MinerStorageConfig, bool]:
    """Read-modify-write of the current document under the row lock:
    `change(doc) -> doc` gets a copy and returns the new raw document,
    which is validated like a `PUT`. Raises `LookupError` when the node has
    no document, `StageConflict`, `storage_doc.DocError`."""
    limits = local_limits(node_id, actor.account)
    with transaction.atomic():
        _lock_node(node_id)
        row = MinerStorageConfig.objects.select_for_update().filter(miner_node_id=node_id).first()
        if visible_revision(row, actor) == 0:
            raise LookupError("the node has no desired storage document")
        assert row is not None
        if if_match is not None and if_match != row.revision:
            raise StageConflict(row.revision)
        new = storage_doc.normalize(change(json.loads(json.dumps(row.body))), **limits)
        return stage(node_id, new, actor=actor, action=action, now=now)


def adopt_document(node_id: str, overrides: dict[str, Any], account: str = "") -> dict[str, Any]:
    """The document equal to what the node's agent reports (heartbeat v7):
    its live pools with their class, budget, OS-disk flag and state, and
    the dedicated disks of its latest report. The heartbeat carries no
    path, so `overrides` (`{pool_id: {"path": …, "class"?: …}}`) supplies
    each pool's path, and the class of a pool reported without one.
    Raises `storage_doc.DocError` (code `storage-report-missing`,
    `adopt-path-required`, `adopt-class-required`, `pool-budget-unknown`,
    or a static check).

    The miner's identity row is locked first: the heartbeat ingest holds
    that lock while it writes a report (pools and disks in one
    transaction), so what is read here is one whole report."""
    with transaction.atomic():
        _lock_node(node_id)
        return _adopt_document(node_id, overrides, account)


def _adopt_document(node_id: str, overrides: dict[str, Any], account: str) -> dict[str, Any]:
    pools = list(
        MinerStoragePool.objects.filter(miner_node_id=node_id, retired_at__isnull=True).order_by(
            "pool_id"
        )
    )
    if not pools:
        raise storage_doc.DocError(
            "storage-report-missing", "the node has sent no v7 storage report yet"
        )
    if not isinstance(overrides, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) and set(v) <= {"path", "class"}
        for k, v in overrides.items()
    ):
        raise storage_doc.DocError("storage-config-malformed", "pools is {pool_id: {path, class?}}")
    unknown = set(overrides) - {p.pool_id for p in pools}
    if unknown:
        raise storage_doc.DocError(
            "adopt-unknown-pool",
            "the miner reports no such pool",
            pool=sorted(unknown)[0][:32],
        )
    out: list[dict[str, Any]] = []
    for pool in pools:
        given = overrides.get(pool.pool_id, {})
        path = given.get("path")
        if not isinstance(path, str) or not path:
            raise storage_doc.DocError(
                "adopt-path-required",
                "the heartbeat carries no path: give one per reported pool",
                pool=pool.pool_id,
            )
        klass = given.get("class") or pool.declared_class
        if not klass:
            raise storage_doc.DocError(
                "adopt-class-required",
                "the pool is reported without a class: give one",
                pool=pool.pool_id,
            )
        if pool.budget_gb is None:
            raise storage_doc.DocError(
                "pool-budget-unknown", "the pool is reported without a budget", pool=pool.pool_id
            )
        out.append(
            {
                "id": pool.pool_id,
                "path": path,
                "class": klass,
                "budget_gb": pool.budget_gb,
                "os_disks": pool.os_disks,
                "state": "draining" if pool.reported_state == "draining" else "active",
            }
        )
    latest = max(p.reported_at for p in pools if p.reported_at is not None)
    disks = [
        {"id": d.disk_id, "state": "draining" if d.reported_state == "draining" else "active"}
        for d in DedicatedDisk.objects.filter(miner_node_id=node_id, reported_at=latest)
    ]
    return storage_doc.normalize(
        {"pools": out, "dedicated_disks": disks}, **local_limits(node_id, account)
    )


def adopt(
    node_id: str, overrides: dict[str, Any], *, actor: Actor, force: bool
) -> tuple[MinerStorageConfig, bool]:
    """Desired := applied. Raises `StageConflict` when a document
    exists, unless `force` (then it is one revision up, never back). The
    first adoption is revision 1, so its push is a no-op apply. The check
    and the write happen under the row lock (`if_match=0`)."""
    with transaction.atomic():
        doc = adopt_document(node_id, overrides, actor.account)
        return stage(node_id, doc, actor=actor, action="adopt", if_match=None if force else 0)


def record_reported_revision(node_id: str, revision: int, at: datetime) -> None:
    """The `storage_config_revision` of a v7 heartbeat (heartbeat ingest).
    The wire is a `u64`; the column a signed 64-bit integer: a larger
    (hostile) value is kept as the column's maximum rather than failing
    the whole storage report."""
    MinerStorageConfig.objects.filter(miner_node_id=node_id).update(
        reported_revision=min(revision, MAX_REVISION), reported_at=at
    )


# ─── gates ───────────────────────────────────────────────────────────


def selected(miner: MinerIdentity) -> bool:
    """Whether the miner is in `VALI_STORAGE_CONFIG_MINERS` (miner_id or
    node_id; `*` = all)."""
    allow = {m.strip() for m in settings.VALI_STORAGE_CONFIG_MINERS if m.strip()}
    return "*" in allow or miner.miner_id in allow or (miner.chain_node_id or "") in allow


_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)*)")


def _version_tuple(value: str) -> tuple[int, ...] | None:
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def version_at_least(version: str, minimum: str) -> bool:
    """`vYYYY.MM.DD[.N]` (or dotted numbers) compared numerically.
    `minimum` empty = nobody; `*` = any agent. An agent version that does
    not parse (`dev`, missing) is below every numeric minimum."""
    minimum = minimum.strip()
    if not minimum:
        return False
    if minimum == "*":
        return True
    want = _version_tuple(minimum)
    have = _version_tuple(version or "")
    if want is None or have is None:
        return False
    width = max(len(want), len(have))
    return have + (0,) * (width - len(have)) >= want + (0,) * (width - len(want))


def agent_version(node_id: str) -> str:
    from apps.scheduler.models import MinerCapacity

    row = MinerCapacity.objects.filter(miner_node_id=node_id).only("agent_version").first()
    return row.agent_version if row is not None else ""


def push_gate(node_id: str) -> tuple[MinerIdentity | None, str]:
    """`(miner, "")` when the node may be sent a `storage-config` order,
    else `(miner or None, why not)`."""
    if not settings.VALI_STORAGE_CONFIG_PUSH:
        return None, "storage-config-push-disabled"
    miner = MinerIdentity.objects.filter(chain_node_id=node_id).first()
    if miner is None:
        return None, "miner-unknown"
    if not selected(miner):
        return miner, "miner-not-selected"
    if not miner.netbird_ip:
        return miner, "miner-unreachable"
    minimum = str(settings.VALI_STORAGE_CONFIG_MIN_AGENT_VERSION or "")
    if not version_at_least(agent_version(node_id), minimum):
        return miner, "agent-version-below-min"
    return miner, ""


# ─── sync status ─────────────────────────────────────────────────────


def unsupported_held(row: MinerStorageConfig, *, now: datetime) -> bool:
    if row.agent_unsupported_at is None:
        return False
    hold = timedelta(seconds=int(settings.VALI_STORAGE_CONFIG_UNSUPPORTED_RETRY_S))
    return now - row.agent_unsupported_at < hold


def drifted(row: MinerStorageConfig) -> bool:
    """The agent acked the current revision, then a LATER heartbeat
    reported another one in force."""
    return (
        row.acked_current
        and row.reported_revision is not None
        and row.reported_at is not None
        and row.acked_at is not None
        and row.reported_at > row.acked_at
        and row.reported_revision != row.acked_revision
    )


def sync_status(row: MinerStorageConfig | None, *, now: datetime | None = None) -> str:
    """`in_sync` | `pending` | `refused:<code>:<id>` | `agent-unsupported`
    | `drift`, or `unmanaged` (no desired document)."""
    if row is None or row.revision == 0:
        return UNMANAGED
    now = now or timezone.now()
    if unsupported_held(row, now=now):
        return AGENT_UNSUPPORTED
    if row.refusal_code:
        return f"{REFUSED}:{row.refusal_code}:{row.refusal_pool or row.refusal_disk}"
    if drifted(row):
        return DRIFT
    if row.acked_current and row.reported_revision == row.revision:
        return IN_SYNC
    return PENDING


def sync_state(status: str) -> str:
    """The metric label of a `sync_status`: the part before the code."""
    return status.split(":", 1)[0]


# ─── reconcile ───────────────────────────────────────────────────────


@dataclass
class ReconcileReport:
    enabled: bool = False
    pushed: int = 0
    acked: int = 0
    failed: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    #: Nodes left for the next pass (tick budget spent).
    deferred: int = 0


def reconcile(*, now: datetime | None = None) -> ReconcileReport:
    """One push pass over the nodes with a desired document. Nothing at
    all while `VALI_STORAGE_CONFIG_PUSH` is off."""
    report = ReconcileReport(enabled=bool(settings.VALI_STORAGE_CONFIG_PUSH))
    if not report.enabled:
        return report
    epoch = timezone.make_aware(datetime(1970, 1, 1))
    rows = sorted(
        MinerStorageConfig.objects.filter(revision__gt=0),
        key=lambda r: r.sent_at or epoch,  # least recently sent first
    )
    started = time.monotonic()
    budget = float(settings.VALI_STORAGE_CONFIG_TICK_BUDGET_S)
    for i, row in enumerate(rows):
        if time.monotonic() - started > budget:
            report.deferred = len(rows) - i
            log.warning("storage-config: tick budget spent, %d node(s) deferred", report.deferred)
            break
        try:
            outcome = sync_node(row.miner_node_id, now=now)
        except Exception:  # noqa: BLE001 — one node must not stop the pass.
            log.exception("storage-config: node=%s unhandled error", row.miner_node_id)
            report.failed.append(row.miner_node_id)
            continue
        if outcome == "acked":
            report.pushed += 1
            report.acked += 1
        elif outcome == "failed":
            report.pushed += 1
            report.failed.append(row.miner_node_id)
        elif outcome != "skipped":
            report.skipped[row.miner_node_id] = outcome
    return report


def _retry_period_s(row: MinerStorageConfig) -> int:
    base = int(settings.VALI_STORAGE_CONFIG_RETRY_S)
    if row.apply_failures:
        cap = int(settings.VALI_STORAGE_CONFIG_APPLY_BACKOFF_MAX_S)
        return min(base << min(row.apply_failures - 1, 20), max(cap, base))
    if row.acked_current:
        return base if drifted(row) else int(settings.VALI_STORAGE_CONFIG_SYNC_S)
    return base


def _due(row: MinerStorageConfig, *, now: datetime) -> bool:
    if unsupported_held(row, now=now):
        return False
    if row.sent_at is None or row.sent_revision != row.revision:
        return True
    return now - row.sent_at >= timedelta(seconds=_retry_period_s(row))


def _remove_drained_pools(row: MinerStorageConfig, *, now: datetime) -> MinerStorageConfig:
    """Drop the `draining` pools the agent reports empty under the
    current, acked revision (module docstring). Returns the fresh row."""
    if not row.acked_current or row.reported_revision != row.revision:
        return row
    if row.reported_at is None or row.acked_at is None or row.reported_at <= row.acked_at:
        return row
    draining = [
        p["id"]
        for p in row.body.get("pools", [])
        if p["state"] == "draining" and p["id"] != storage_doc.DEFAULT_POOL_ID
    ]
    if not draining:
        return row
    reported = {
        p.pool_id: p
        for p in MinerStoragePool.objects.filter(
            miner_node_id=row.miner_node_id, pool_id__in=draining
        )
    }
    empty = set()
    for pool_id in draining:
        pool = reported.get(pool_id)
        if pool is None or pool.retired_at is not None:
            empty.add(pool_id)
        elif pool.reported_state == "draining" and pool.committed_gb == 0:
            empty.add(pool_id)
    if not empty:
        return row

    def _drop(doc: dict[str, Any]) -> dict[str, Any]:
        doc["pools"] = [p for p in doc["pools"] if p["id"] not in empty]
        return doc

    try:
        new_row, changed = edit(
            row.miner_node_id,
            _drop,
            actor=SYSTEM,
            action="pool-removed",
            if_match=row.revision,
            now=now,
        )
    except (StageConflict, LookupError, storage_doc.DocError):
        # An operator wrote meanwhile (or the document no longer passes):
        # the next pass looks again.
        return MinerStorageConfig.objects.get(pk=row.pk)
    if changed:
        log.info(
            "storage-config: node=%s drained pool(s) %s removed, revision %d",
            row.miner_node_id,
            sorted(empty),
            new_row.revision,
        )
    return new_row


def _restage_after_jump(row: MinerStorageConfig) -> MinerStorageConfig:
    """After a `409` jump the content key is cleared: one revision up for
    the same document. The new revision waits out the backoff of the 409s
    that led to it (counted in `apply_failures`, as if already sent): an
    agent that answers 409 to everything costs one push per backoff
    period, not one per tick."""
    if row.content_key:
        return row
    with transaction.atomic():
        locked = MinerStorageConfig.objects.select_for_update().get(pk=row.pk)
        if not locked.content_key:
            failures = locked.apply_failures
            _bump(locked, locked.body, storage_doc.content_key(locked.body))
            locked.apply_failures = failures + 1
            locked.sent_revision = locked.revision
            locked.save()
            audit(
                locked.miner_node_id,
                locked.revision,
                "rebase",
                SYSTEM,
                doc=locked.body,
                outcome="staged",
            )
        return locked


def _ensure_digest(row: MinerStorageConfig) -> MinerStorageConfig:
    """Fill `body_sha` for the current revision (digest leaves the expiry
    out, so any `not_after_unix` works)."""
    if row.body_sha:
        return row
    sha = order_dispatch.storage_config_digest(
        storage_doc.order_payload(row.body, revision=row.revision, not_after_unix=0, dry_run=False)
    )
    MinerStorageConfig.objects.filter(pk=row.pk, revision=row.revision, body_sha="").update(
        body_sha=sha
    )
    return MinerStorageConfig.objects.get(pk=row.pk)


def _owner_hold(row: MinerStorageConfig) -> str:
    """`""` when the family that wrote the document still runs the node on
    chain (an `Active` child of it), else why the push is held: a node
    that changed hands is never sent its former family's document."""
    try:
        binding = node_family.node_family(row.miner_node_id, fresh=True)
    except node_family.FamilyCheckUnavailable:
        return "chain-unavailable"
    if not row.owner_family or not binding.active or binding.family_hex != row.owner_family:
        return "family-changed"
    return ""


def sync_node(node_id: str, *, now: datetime | None = None, force: bool = False) -> str:
    """Bring one node's agent up to its desired document. Returns
    `skipped` (not due), `acked`, `failed`, or the gate that held it
    (`push_gate`)."""
    now = now or timezone.now()
    row = MinerStorageConfig.objects.filter(miner_node_id=node_id, revision__gt=0).first()
    if row is None:
        return "skipped"
    miner, why = push_gate(node_id)
    if why:
        held = f"held: {why}"[:256]
        MinerStorageConfig.objects.filter(pk=row.pk).exclude(last_error=held).update(
            last_error=held
        )
        return why
    assert miner is not None
    try:
        row = _remove_drained_pools(row, now=now)
        row = _restage_after_jump(row)
        row = _ensure_digest(row)
    except storage_doc.DocError as exc:
        # Only a spent revision counter gets here; never a crash loop.
        MinerStorageConfig.objects.filter(pk=row.pk).update(last_error=f"stage: {exc.code}"[:256])
        return "failed"
    except order_dispatch.OrderDispatchError as exc:
        MinerStorageConfig.objects.filter(pk=row.pk).update(last_error=f"digest: {exc}"[:256])
        return "failed"
    if not force and not _due(row, now=now):
        return "skipped"
    # The fresh chain read happens only for a push about to go out.
    held = _owner_hold(row)
    if held:
        # Counted as an attempt, so a held node is looked at again after
        # the retry period, not on every tick.
        MinerStorageConfig.objects.filter(pk=row.pk, revision=row.revision).update(
            sent_at=now, sent_revision=row.revision, last_error=f"held: {held}"
        )
        return held
    return _push(miner, row, now=now)


@dataclass(frozen=True)
class Verdict:
    """The agent's answer to one push, parsed."""

    ok: bool
    status: int
    #: `applied:<rev>:<sha>` / `dry-run-ok:<rev>:<sha>` on success, else
    #: the refusal code (or the raw classifier when it is not JSON).
    code: str
    pool: str = ""
    disk: str = ""
    #: Transport / dispatch failure text (no answer from the agent).
    error: str = ""

    @property
    def outcome(self) -> str:
        if self.error:
            return f"error:{self.error}"[:192]
        if self.ok:
            return self.code.split(":", 1)[0]
        if self.status == 422:
            return f"{REFUSED}:{self.code}:{self.pool or self.disk}"[:192]
        if self.status == 404 or (self.status == 503 and self.code == DISABLED):
            return AGENT_UNSUPPORTED
        return f"status-{self.status}:{self.code}"[:192]

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": self.ok, "status": self.status, "code": self.code}
        if self.pool:
            out["pool"] = self.pool
        if self.disk:
            out["disk"] = self.disk
        if self.error:
            out["error"] = self.error
        return out


def parse_answer(result: order_dispatch.DispatchResult) -> Verdict:
    """The agent's 4xx/5xx body is `{"code", "pool"|"disk"}` JSON (a
    `503 storage-config-disabled` and the Edge's own refusals are plain
    text)."""
    text = result.classifier
    if result.ok:
        return Verdict(ok=True, status=result.status, code=text[:160])
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("code"), str):
        pool = parsed.get("pool")
        disk = parsed.get("disk")
        return Verdict(
            ok=False,
            status=result.status,
            code=parsed["code"][:64],
            pool=pool[:32] if isinstance(pool, str) else "",
            disk=disk[:96] if isinstance(disk, str) else "",
        )
    return Verdict(ok=False, status=result.status, code=text[:64])


def dispatch(
    miner: MinerIdentity,
    payload: bytes,
    *,
    revision: int,
    dry_run: bool = False,
    deadline_s: float = 60.0,
) -> Verdict:
    """One `storage-config` order to `miner`, settled, under a fresh
    `order_id`."""
    tag = "scv" if dry_run else "sc"
    order_id = f"{tag}-{miner.miner_id}-r{revision}-{uuid.uuid4().hex[:12]}"[:128]
    try:
        result = order_dispatch.dispatch_order_settled(
            miner_id=miner.miner_id,
            netbird_ip=str(miner.netbird_ip),
            order_id=order_id,
            kind=KIND,
            payload_json=payload,
            attempts=2,
            retry_after_s=5.0,
            deadline_s=deadline_s,
            timeout_s=25.0,
        )
    except order_dispatch.OrderDispatchUnavailable as exc:
        return Verdict(ok=False, status=0, code="", error=f"unreachable: {exc}"[:160])
    except order_dispatch.OrderDispatchError as exc:
        return Verdict(ok=False, status=0, code="", error=f"dispatch: {exc}"[:160])
    return parse_answer(result)


def _push(miner: MinerIdentity, row: MinerStorageConfig, *, now: datetime) -> str:
    ttl = max(1, min(int(settings.VALI_STORAGE_CONFIG_TTL_S), MAX_TTL_S))
    payload = storage_doc.order_payload(
        row.body,
        revision=row.revision,
        not_after_unix=int(now.timestamp()) + ttl,
        dry_run=False,
    )
    verdict = dispatch(miner, payload, revision=row.revision)
    want = f"applied:{row.revision}:{row.body_sha}"
    mine = MinerStorageConfig.objects.filter(pk=row.pk)
    current = mine.filter(revision=row.revision)

    error = ""
    jump = ""
    if verdict.error:
        error = verdict.error
    elif verdict.ok and verdict.code == want:
        pass
    elif verdict.ok:
        error = f"ack-mismatch: {verdict.code[:160]!r}"
    elif verdict.status == 409 and verdict.code in (STALE_REVISION, REVISION_CONFLICT):
        error = f"refused: 409 {verdict.code}"
        jump = verdict.code
    elif verdict.status == 422:
        error = f"refused: 422 {verdict.code} {verdict.pool or verdict.disk}".rstrip()
        current.update(
            refusal_code=verdict.code,
            refusal_pool=verdict.pool,
            refusal_disk=verdict.disk,
            apply_failures=F("apply_failures") + 1,
        )
    elif verdict.status == 404 or (verdict.status == 503 and verdict.code == DISABLED):
        error = f"unsupported: {verdict.status} {verdict.code}".rstrip()
        current.update(agent_unsupported_at=now)
    elif verdict.status == 500 and verdict.code == STORE_FAILED:
        error = f"refused: 500 {verdict.code}"
        current.update(apply_failures=F("apply_failures") + 1)
    else:
        error = f"refused: status={verdict.status} class={verdict.code[:120]!r}"

    # Bookkeeping of THIS revision's attempt: the answer to an older push
    # that came back late must not touch a newer revision's state.
    if jump == STALE_REVISION and _jump_target(row) <= row.revision:
        # No jump will clear the content key: back off like a refusal.
        error += " (revision counter exhausted)"
        current.update(apply_failures=F("apply_failures") + 1)
    current.update(sent_at=now, sent_revision=row.revision, last_error=error[:256])
    if jump:
        _jump_revision(row, stale=jump == STALE_REVISION)
    if not error:
        # A slower push of an older revision must not overwrite a newer ack,
        # nor land on a document another family has written since.
        first = not row.acked_current
        acked = mine.filter(acked_revision__lte=row.revision, owner_family=row.owner_family)
        acked.update(
            acked_revision=row.revision,
            acked_sha=row.body_sha,
            acked_body=row.body,
            acked_at=now,
            agent_unsupported_at=None,
        )
        acked.filter(revision=row.revision).update(
            apply_failures=0, refusal_code="", refusal_pool="", refusal_disk=""
        )
        if first:
            audit(row.miner_node_id, row.revision, "push", SYSTEM, outcome="applied", now=now)
        log.info("storage-config: node=%s revision=%d acked", row.miner_node_id, row.revision)
        return "acked"
    # One audit row per change of verdict on a revision, not per retry.
    if verdict.outcome != (
        MinerStorageConfigAudit.objects.filter(
            miner_node_id=row.miner_node_id, revision=row.revision, action="push"
        )
        .values_list("outcome", flat=True)
        .first()
    ):
        audit(row.miner_node_id, row.revision, "push", SYSTEM, outcome=verdict.outcome, now=now)
    log.warning(
        "storage-config: node=%s revision=%d not acked: %s", row.miner_node_id, row.revision, error
    )
    return "failed"


def _jump_target(row: MinerStorageConfig) -> int:
    """The first revision past a stale one: doubled, or past the revision
    the agent's heartbeat reports, within the counter."""
    target = max(row.revision * 2, row.revision + 1, (row.reported_revision or 0) + 1)
    return min(target, MAX_REVISION)


def _jump_revision(row: MinerStorageConfig, *, stale: bool) -> bool:
    """The agent holds a revision vali no longer knows about. Clear the
    content key so the next pass stages a new revision past it: one up for
    a conflict, doubled for a stale one — or straight past the revision
    the agent's heartbeat reports, when that is higher."""
    target = _jump_target(row) if stale else min(row.revision + 1, MAX_REVISION)
    if target <= row.revision:
        # Nothing above the agent's revision fits the counter: hold, loudly,
        # rather than loop on a re-stage that cannot happen.
        log.error("storage-config: node=%s revision counter exhausted", row.miner_node_id)
        return False
    MinerStorageConfig.objects.filter(pk=row.pk, revision=row.revision).update(
        revision=target - 1, content_key="", body_sha=""
    )
    return True


# ─── dry run ─────────────────────────────────────────────────────────


class DryRunUnavailable(Exception):
    """The node cannot be sent an order right now (`push_gate`)."""


def dry_run(node_id: str, doc: dict[str, Any], *, revision: int) -> Verdict:
    """Ask the agent to judge `doc` without applying it (≤ 60 s). Raises
    `DryRunUnavailable` with the gate's reason."""
    miner, why = push_gate(node_id)
    if why:
        raise DryRunUnavailable(why)
    assert miner is not None
    revision = max(revision, 1)
    now = timezone.now()
    ttl = max(1, min(int(settings.VALI_STORAGE_CONFIG_TTL_S), MAX_TTL_S))
    payload = storage_doc.order_payload(
        doc, revision=revision, not_after_unix=int(now.timestamp()) + ttl, dry_run=True
    )
    sha = order_dispatch.storage_config_digest(payload)
    verdict = dispatch(miner, payload, revision=revision, dry_run=True, deadline_s=55.0)
    if verdict.ok and verdict.code != f"dry-run-ok:{revision}:{sha}":
        return Verdict(ok=False, status=verdict.status, code="ack-mismatch")
    return verdict
