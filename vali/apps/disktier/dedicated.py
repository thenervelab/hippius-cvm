"""E4: dedicated physical disks — vali's side of the frozen contract
(docs/design/dedicated-disks-contract.md; background
docs/design/disk-tier-verification.md §4.2, §5.2, §6.1, §7, §8).

- Intake ([`check_launch`]): the `dedicated_disks` request and its
  `pinned_ack`, with the contract's 400 / 409 categories. Off
  (`VALI_DEDICATED_ENABLED`) ⇒ any value but null is today's 409
  `dedicated-disks-not-offered`. Kept in the launch spec only when present.
- Capacity ([`free_counts`]): per node, the `free` disks a request could
  take — active, verified at ≥ the sold tier, at least `min_size_gb` GiB,
  reported free in a recent `v7` heartbeat — on a node whose agent takes
  `extra_disks` (`VALI_DEDICATED_MIN_AGENT_VERSION`, empty = none).
- Assignment ([`assign`]): in the placement's own transaction, row-locked,
  smallest qualifying disks first (ties: most recently probed). A disk can
  never be assigned twice: the rows are locked and moved `free → assigned`
  under a compare-and-set.
- The order and the measured cmdline ([`extra_disks`], [`cmdline_value`],
  [`order_entries`]) come from the VM's placement rows, so every launch of
  the VM — first launch, relaunch, resize relaunch, guest upgrade — sends
  the same disks and the same `hippius.dedicated=` token.
- The read-back ([`read_back`]): `pinned` + `disks[]`, only for a VM with
  a dedicated disk; never a disk id, path, serial or pool id.

A disk's size is billed and measured as its SIZE CLASS: its real size
floored to 100 GiB.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models import F, QuerySet
from django.utils import timezone

from .models import (
    DEDICATED_SLOTS,
    DedicatedDisk,
    DedicatedDiskDesiredState,
    DedicatedDiskState,
    DiskKind,
    PlacementDisk,
)
from .routing import REPORT_MAX_AGE
from .storage_config import version_at_least
from .tiers import SELLABLE_TIERS, DiskTier, satisfies

GIB = 2**30
#: The size class step: a disk is sold (and measured) as its size floored to it.
SIZE_CLASS_GIB = 100
#: The smallest `min_size_gb` a launch may ask (the agent refuses smaller disks).
MIN_SIZE_GB = 1000
#: The largest size class the guest takes on its measured cmdline (1 PiB).
MAX_SIZE_CLASS_GIB = 1_048_576
#: The only dedicated tier sold in v1 (a minimum).
SOLD_TIERS: tuple[str, ...] = (DiskTier.HDD,)
#: The measured cmdline token: `hippius.dedicated=x0:<GiB>,x1:<GiB>`.
CMDLINE_KEY = "hippius.dedicated"
#: The guest opens at most this many slots.
MAX_SLOTS = 8

_REQUEST_KEYS = frozenset({"tier", "count", "min_size_gb"})
_SLOT_RE = re.compile(r"^x(0|[1-9][0-9]?)$")

# Launch intake (contract §1.1).
CATEGORY_INVALID = "dedicated-invalid"
CATEGORY_COUNT_INVALID = "dedicated-count-invalid"
CATEGORY_SIZE_INVALID = "dedicated-size-invalid"
CATEGORY_ACK_REQUIRED = "dedicated-ack-required"
CATEGORY_NOT_OFFERED = "dedicated-disks-not-offered"
CATEGORY_NO_FAILOVER = "dedicated-no-failover"
CATEGORY_NEEDS_RELEASE = "dedicated-needs-release"
#: A lifecycle operation that would move a pinned VM off its host (§5).
CATEGORY_PINNED = "dedicated-pinned"
#: The 409 categories of the intake (the rest are 400).
CONFLICT_CATEGORIES = frozenset(
    {CATEGORY_NOT_OFFERED, CATEGORY_NO_FAILOVER, CATEGORY_NEEDS_RELEASE}
)
# Asynchronous placement failures (contract §1.2).
NO_DEDICATED_CAPACITY = "no-dedicated-capacity"
NO_HOST_FITS_DISKS = "no-host-fits-disks"

# Slot states shown to the backend (contract §2).
SLOT_ATTACHED = "attached"
SLOT_MISSING = "missing"
SLOT_FAILED = "failed"
SLOT_MISMATCH = "mismatch"
SLOT_RELEASED = "released"
#: A held disk's `state` comes from HOST evidence only — the agent's own
#: `v7` report on it (`_held_slot_state`). The guest's receipt verdicts are
#: forgeable by root in the VM (a tenant could claim `mismatch` to stop a
#: slot's billing), so they never set `state`: they are shown apart, as
#: `guest_state`.
#: The guest's receipt verdicts for a dedicated slot (`disk_io[].state`),
#: informational only (`guest_state`).
_GUEST_TO_SLOT = {"ok": SLOT_ATTACHED, "missing": SLOT_MISSING, "mismatch": SLOT_MISMATCH}


class DedicatedError(Exception):
    """A launch's `dedicated_disks` refused at intake; `category` is the
    contract's code."""

    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.message = message
        self.category = category


class DisksTaken(Exception):
    """The disks the scheduler counted on a node are gone (assigned by a
    concurrent placement, or no longer qualifying): place elsewhere."""


@dataclass(frozen=True)
class DedicatedRequest:
    tier: str
    count: int
    min_size_gb: int

    def as_spec(self) -> dict[str, Any]:
        return {"tier": self.tier, "count": self.count, "min_size_gb": self.min_size_gb}

    @property
    def min_size_bytes(self) -> int:
        return self.min_size_gb * GIB


@dataclass(frozen=True)
class ExtraDisk:
    """One dedicated disk of a launch order: its slot, the miner's by-id
    name (operator-side only) and its size class."""

    slot: str
    disk_id: str
    size_gb: int


# ── settings ─────────────────────────────────────────────────────────


def enabled() -> bool:
    return bool(getattr(settings, "VALI_DEDICATED_ENABLED", False))


def allowed_owners() -> frozenset[str]:
    return frozenset(getattr(settings, "VALI_DEDICATED_ALLOWED_OWNERS", None) or ())


def max_per_vm() -> int:
    return int(getattr(settings, "VALI_DEDICATED_MAX_PER_VM", MAX_SLOTS))


def min_guest_release() -> int | None:
    value = getattr(settings, "VALI_DEDICATED_MIN_GUEST_RELEASE", None)
    return int(value) if value is not None else None


def min_agent_version() -> str:
    return str(getattr(settings, "VALI_DEDICATED_MIN_AGENT_VERSION", "") or "")


# ── intake ───────────────────────────────────────────────────────────


def _strict_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_request(raw: object) -> DedicatedRequest:
    """The `dedicated_disks` object, validated (contract §1.1), or
    `DedicatedError` with its 400 category."""
    if not isinstance(raw, dict):
        raise DedicatedError("dedicated_disks must be an object", CATEGORY_INVALID)
    keys = set(raw)
    if keys != _REQUEST_KEYS:
        unknown = sorted(str(k) for k in keys - _REQUEST_KEYS)
        missing = sorted(_REQUEST_KEYS - keys)
        raise DedicatedError(
            "dedicated_disks takes exactly tier, count and min_size_gb"
            + (f" (unknown: {', '.join(unknown)})" if unknown else "")
            + (f" (missing: {', '.join(missing)})" if missing else ""),
            CATEGORY_INVALID,
        )
    tier = raw["tier"]
    if not isinstance(tier, str) or tier not in SOLD_TIERS:
        raise DedicatedError(
            f"dedicated_disks.tier must be one of: {', '.join(SOLD_TIERS)}", CATEGORY_INVALID
        )
    count = _strict_int(raw["count"])
    if count is None:
        raise DedicatedError("dedicated_disks.count must be an integer", CATEGORY_INVALID)
    if not 1 <= count <= max_per_vm():
        raise DedicatedError(
            f"dedicated_disks.count must be between 1 and {max_per_vm()}",
            CATEGORY_COUNT_INVALID,
        )
    size = _strict_int(raw["min_size_gb"])
    if size is None:
        raise DedicatedError("dedicated_disks.min_size_gb must be an integer", CATEGORY_INVALID)
    if size < MIN_SIZE_GB:
        raise DedicatedError(
            f"dedicated_disks.min_size_gb must be at least {MIN_SIZE_GB} (GiB)",
            CATEGORY_SIZE_INVALID,
        )
    return DedicatedRequest(tier=tier, count=count, min_size_gb=size)


def check_launch(
    raw: object,
    *,
    pinned_ack: object,
    tenant_id: str,
    user_id: str,
    require_failover_peer: bool,
    guest_release: int | None,
) -> DedicatedRequest:
    """The intake of a launch whose `dedicated_disks` is not null, in the
    contract's order: not offered (flag off, or an owner off the allowlist)
    before anything about the body, so a caller that may not buy learns
    nothing else; then the body (400); then the conflicts (409).
    `guest_release` is the blessed guest release of the launched image
    (`None` for a launch that is not by image)."""
    if not enabled():
        raise DedicatedError(
            "dedicated_disks is not offered on this validator", CATEGORY_NOT_OFFERED
        )
    owners = allowed_owners()
    if owners and not ({tenant_id, user_id} & owners):
        raise DedicatedError("dedicated_disks is not offered to this owner", CATEGORY_NOT_OFFERED)
    request = parse_request(raw)
    if pinned_ack is not True:
        raise DedicatedError(
            "pinned_ack must be true with dedicated_disks: the VM is pinned to its host "
            "(no migration, no failover, no backup)",
            CATEGORY_ACK_REQUIRED,
        )
    if require_failover_peer:
        raise DedicatedError(
            "a VM with dedicated disks is pinned to its host: it cannot require a failover peer",
            CATEGORY_NO_FAILOVER,
        )
    minimum = min_guest_release()
    if minimum is None or guest_release is None or int(guest_release) < minimum:
        raise DedicatedError(
            "the image's blessed guest release cannot open dedicated disks"
            + (f" (needs release {minimum} or later)" if minimum is not None else ""),
            CATEGORY_NEEDS_RELEASE,
        )
    return request


def spec_request(spec: Mapping[str, Any] | Any) -> DedicatedRequest | None:
    """The request a launch spec (`spec_json` or a `LaunchSpec`) carries,
    `None` without one. Fails loudly on a malformed stored value: a launch
    that was sold dedicated disks never boots without them."""
    raw = (
        spec.get("dedicated_disks")
        if isinstance(spec, Mapping)
        else getattr(spec, "dedicated_disks", None)
    )
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError(f"malformed dedicated_disks in a launch spec: {raw!r}")
    tier, count, size = (
        raw.get("tier"),
        _strict_int(raw.get("count")),
        _strict_int(raw.get("min_size_gb")),
    )
    if tier not in SELLABLE_TIERS or count is None or count < 1 or size is None or size < 1:
        raise ValueError(f"malformed dedicated_disks in a launch spec: {dict(raw)!r}")
    return DedicatedRequest(tier=str(tier), count=count, min_size_gb=size)


# ── capacity ─────────────────────────────────────────────────────────


def size_class_gb(size_bytes: int | None) -> int:
    """A disk's size class (GiB): its size floored to 100 GiB."""
    if not size_bytes:
        return 0
    return (int(size_bytes) // GIB // SIZE_CLASS_GIB) * SIZE_CLASS_GIB


def _tiers_at_least(tier: str) -> list[str]:
    return [t for t in SELLABLE_TIERS if satisfies(t, tier)]


def qualifying(request: DedicatedRequest, *, now: datetime | None = None) -> QuerySet:
    """Every disk fleet-wide the request could take, ignoring the node's
    agent: free and active in vali, verified at ≥ the tier and big enough
    BY THE PROBE (`verified_size_bytes`, never the miner's own figure), still
    reported at least that big, and reported free (no VM) in a recent `v7`
    heartbeat."""
    now = now or timezone.now()
    return DedicatedDisk.objects.filter(
        state=DedicatedDiskState.FREE,
        desired_state=DedicatedDiskDesiredState.ACTIVE,
        verified_tier__in=_tiers_at_least(request.tier),
        verified_size_bytes__gte=request.min_size_bytes,
        verified_size_bytes__lt=(MAX_SIZE_CLASS_GIB + SIZE_CLASS_GIB) * GIB,
        size_bytes__gte=F("verified_size_bytes"),
        reported_state="free",
        reported_vm_id="",
        reported_at__gte=now - REPORT_MAX_AGE,
    )


def capable_node_ids(node_ids: Iterable[str]) -> frozenset[str]:
    """Lower-cased: those of `node_ids` whose agent takes `extra_disks`
    (its `v6` release tag at or above `VALI_DEDICATED_MIN_AGENT_VERSION`;
    empty = none)."""
    from apps.scheduler.models import MinerCapacity

    minimum = min_agent_version()
    wanted = {n.lower() for n in node_ids if n}
    if not minimum or not wanted:
        return frozenset()
    rows = MinerCapacity.objects.exclude(agent_version="").values_list(
        "miner_node_id", "agent_version"
    )
    return frozenset(
        node.lower()
        for node, version in rows
        if node.lower() in wanted and version_at_least(version, minimum)
    )


def free_counts(request: DedicatedRequest, node_ids: Iterable[str]) -> dict[str, int]:
    """`{node_id lower-cased: qualifying free disks}` for those of
    `node_ids` whose agent takes `extra_disks`; a node with none is absent."""
    capable = capable_node_ids(node_ids)
    if not capable:
        return {}
    out: dict[str, int] = {}
    for node in qualifying(request).values_list("miner_node_id", flat=True):
        key = node.lower()
        if key in capable:
            out[key] = out.get(key, 0) + 1
    return out


def free_sizes(request: DedicatedRequest, node_ids: Iterable[str]) -> dict[str, list[int]]:
    """`{node_id lower-cased: [size classes of its qualifying free disks]}`,
    same scope as [`free_counts`]."""
    capable = capable_node_ids(node_ids)
    if not capable:
        return {}
    out: dict[str, list[int]] = {}
    for node, size in qualifying(request).values_list("miner_node_id", "verified_size_bytes"):
        if node.lower() in capable:
            out.setdefault(node.lower(), []).append(size_class_gb(size))
    return out


# ── assignment ───────────────────────────────────────────────────────


def _slot_index(slot: str) -> int:
    m = _SLOT_RE.match(slot or "")
    if m is None:
        raise ValueError(f"not a dedicated slot: {slot!r}")
    return int(m.group(1))


def _next_slot_index(vm: Any) -> int:
    """The VM's next never-used slot index: one past the highest it ever
    held (a slot is never reused)."""
    used = list(
        PlacementDisk.objects.filter(placement__vm=vm, kind=DiskKind.DEDICATED).values_list(
            "slot", flat=True
        )
    ) + list(DedicatedDisk.objects.filter(assigned_vm=vm).values_list("assigned_slot", flat=True))
    return max((_slot_index(s) for s in used if s), default=-1) + 1


def assign(placement: Any, vm: Any, request: DedicatedRequest) -> list[PlacementDisk]:
    """Assign `request.count` disks of the placement's node to `vm`, and
    record them on `placement`. MUST run inside the transaction that
    creates the placement: the qualifying rows are locked
    (`select_for_update`) and each moves `free → assigned` under a
    compare-and-set, so two placements can never take one disk. Raises
    [`DisksTaken`] when the node no longer has enough: the caller rolls the
    placement back and places elsewhere.

    A VM that already holds disks (an earlier launch attempt got past the
    KBS register, so an order may have named them) takes those again, on
    their node only, with their slots: never a second set."""
    node = placement.miner_node_id
    held = held_disks(vm)
    if held:
        return _reuse(placement, held, request)
    if node.lower() not in capable_node_ids([node]):
        raise DisksTaken(f"node {node} does not take extra_disks")
    now = timezone.now()
    rows = list(
        qualifying(request, now=now)
        .filter(miner_node_id__iexact=node)
        .select_for_update()
        .order_by("verified_size_bytes", F("probed_at").desc(nulls_last=True), "disk_id")[
            : request.count
        ]
    )
    if len(rows) < request.count:
        raise DisksTaken(f"node {node} has {len(rows)} of {request.count} qualifying disks free")
    first = _next_slot_index(vm)
    if first + request.count > len(DEDICATED_SLOTS):
        raise DisksTaken(f"vm {vm.vm_id} has used every dedicated slot")
    out: list[PlacementDisk] = []
    for offset, disk in enumerate(rows):
        slot = DEDICATED_SLOTS[first + offset]
        won = DedicatedDisk.objects.filter(pk=disk.pk, state=DedicatedDiskState.FREE).update(
            state=DedicatedDiskState.ASSIGNED,
            assigned_vm=vm,
            assigned_slot=slot,
            assigned_at=now,
            freed_at=None,
            updated_at=now,
        )
        if won != 1:
            raise DisksTaken(f"disk {disk.disk_id} was taken meanwhile")
        out.append(
            PlacementDisk.objects.create(
                placement=placement,
                slot=slot,
                kind=DiskKind.DEDICATED,
                dedicated_disk=disk,
                size_gb=size_class_gb(disk.verified_size_bytes),
                required_tier=request.tier,
            )
        )
    return out


def held_disks(vm: Any) -> list[DedicatedDisk]:
    """The disks `vm` holds (`assigned` to it), in slot order."""
    rows = list(DedicatedDisk.objects.filter(assigned_vm=vm, state=DedicatedDiskState.ASSIGNED))
    return sorted(rows, key=lambda d: _slot_index(d.assigned_slot))


def _reuse(
    placement: Any, held: list[DedicatedDisk], request: DedicatedRequest
) -> list[PlacementDisk]:
    """Record the disks the VM already holds on `placement`, with their
    slots and the size classes they were measured at: only on their node,
    and only when they are the disks the VM was sold."""
    node = placement.miner_node_id.lower()
    if {d.miner_node_id.lower() for d in held} != {node} or len(held) != request.count:
        raise DisksTaken(
            f"vm holds {len(held)} dedicated disk(s) on another node or of another count"
        )
    sizes = {
        r["dedicated_disk_id"]: r["size_gb"]
        for r in PlacementDisk.objects.filter(
            dedicated_disk__in=held, placement__vm_id=placement.vm_id
        )
        .order_by("created_at")
        .values("dedicated_disk_id", "size_gb")
    }
    return [
        PlacementDisk.objects.create(
            placement=placement,
            slot=disk.assigned_slot,
            kind=DiskKind.DEDICATED,
            dedicated_disk=disk,
            size_gb=sizes.get(disk.pk) or size_class_gb(disk.verified_size_bytes),
            required_tier=request.tier,
        )
        for disk in held
    ]


def held_counts(vm_id: str) -> dict[str, int] | None:
    """`{node lower-cased: disks}` the VM `vm_id` already holds, `None` when
    it holds none (the scheduler's gate (o) then counts free disks)."""
    held = DedicatedDisk.objects.filter(
        assigned_vm__vm_id=vm_id, state=DedicatedDiskState.ASSIGNED
    ).values_list("miner_node_id", flat=True)
    out: dict[str, int] = {}
    for node in held:
        out[node.lower()] = out.get(node.lower(), 0) + 1
    return out or None


def revert_unused(placement: Any) -> int:
    """Give back the disks [`assign`] took for `placement`, which failed
    BEFORE the KBS register — so before any launch order named them: no
    guest ever opened them, and they go straight back to `free`. (A disk a
    launch order may have named is released by §24 instead, and re-probed
    before it is sold again.) Returns how many."""
    n = 0
    with transaction.atomic():
        rows = list(
            PlacementDisk.objects.select_for_update().filter(
                placement_id=placement.pk, kind=DiskKind.DEDICATED
            )
        )
        for row in rows:
            n += DedicatedDisk.objects.filter(
                pk=row.dedicated_disk_id,
                state=DedicatedDiskState.ASSIGNED,
                assigned_vm_id=placement.vm_id,
                assigned_slot=row.slot,
            ).update(
                state=DedicatedDiskState.FREE,
                assigned_vm=None,
                assigned_slot="",
                assigned_at=None,
                updated_at=timezone.now(),
            )
            row.delete()
    return n


# ── the order and the measured cmdline ───────────────────────────────


def extra_disks(vm_id: str, node_id: str) -> list[ExtraDisk]:
    """The dedicated disks of `vm_id`'s active placement on `node_id`, in
    slot order — what its launch order and measured cmdline name. Empty
    when the VM has none there."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    placement = (
        Placement.objects.filter(vm__vm_id=vm_id, status__in=ACTIVE_PLACEMENT_STATES)
        .only("id", "miner_node_id")
        .first()
    )
    if placement is None or placement.miner_node_id.lower() != (node_id or "").lower():
        return []
    rows = PlacementDisk.objects.filter(
        placement=placement, kind=DiskKind.DEDICATED
    ).select_related("dedicated_disk")
    disks = [
        ExtraDisk(slot=r.slot, disk_id=r.dedicated_disk.disk_id, size_gb=r.size_gb)
        for r in rows
        if r.dedicated_disk is not None
    ]
    return sorted(disks, key=lambda d: _slot_index(d.slot))


def cmdline_value(disks: Iterable[ExtraDisk]) -> str | None:
    """`x0:<GiB>,x1:<GiB>` in the guest's grammar — slots `x0`..`x23` (no
    leading zero), 1 to 8 of them, unique; sizes as size classes, decimal,
    1000..1048576 GiB — or `None` without disks. Anything else raises: a
    launch never measures a token the guest would refuse."""
    disks = list(disks)
    if not disks:
        return None
    slots = [d.slot for d in disks]
    if len(disks) > MAX_SLOTS or len(set(slots)) != len(slots):
        raise ValueError(f"dedicated slots out of the guest's grammar: {slots}")
    for d in disks:
        if _slot_index(d.slot) >= len(DEDICATED_SLOTS):
            raise ValueError(f"dedicated slot {d.slot} is past x{len(DEDICATED_SLOTS) - 1}")
        if not MIN_SIZE_GB <= d.size_gb <= MAX_SIZE_CLASS_GIB:
            raise ValueError(f"dedicated slot {d.slot} size {d.size_gb} GiB is out of range")
    return ",".join(f"{d.slot}:{d.size_gb}" for d in disks)


def stand_in_cmdline_value(request: DedicatedRequest) -> str:
    """A value at least as long as any real [`cmdline_value`] of
    `request`, for the measured-cmdline length checks run before the disks
    are assigned."""
    widest = f"x{len(DEDICATED_SLOTS) - 1}:{MAX_SIZE_CLASS_GIB}"
    return ",".join([widest] * request.count)


def order_entries(disks: Iterable[ExtraDisk]) -> list[dict[str, str]]:
    """The launch order's `extra_disks`."""
    return [{"slot": d.slot, "kind": "dedicated", "disk_id": d.disk_id} for d in disks]


# ── the read-back ────────────────────────────────────────────────────


def _slot_state(row: PlacementDisk, vm: Any, *, destroyed: bool) -> str:
    disk = row.dedicated_disk
    if destroyed or disk is None:
        return SLOT_RELEASED
    held = disk.state == DedicatedDiskState.ASSIGNED and disk.assigned_vm_id == vm.pk
    if held:
        return _held_slot_state(disk, vm)
    if disk.freed_at is None and disk.state == DedicatedDiskState.FAILED:
        return SLOT_FAILED
    if disk.freed_at is None and disk.state == DedicatedDiskState.REPLACED:
        return SLOT_MISMATCH
    return SLOT_RELEASED


def _held_slot_state(disk: DedicatedDisk, vm: Any) -> str:
    """A held disk's state from HOST evidence only, and `attached` only on
    positive evidence: the agent's fresh `v7` report says it holds the disk
    FOR THIS VM, at no less than the probed size. The agent reporting it
    failed ⇒ `failed`; replaced, held for another VM, or smaller than probed
    ⇒ `mismatch`; anything else — free, unavailable, draining, never or no
    longer reported — ⇒ `missing`."""
    if disk.reported_state == "failed":
        return SLOT_FAILED
    shrunk = (
        disk.verified_size_bytes is not None
        and disk.size_bytes is not None
        and disk.size_bytes < disk.verified_size_bytes
    )
    if disk.reported_state == "replaced" or shrunk:
        return SLOT_MISMATCH
    fresh = disk.reported_at is not None and disk.reported_at >= timezone.now() - REPORT_MAX_AGE
    if disk.reported_state == "assigned" and fresh:
        return SLOT_ATTACHED if disk.reported_vm_id == vm.vm_id else SLOT_MISMATCH
    return SLOT_MISSING


def _rows_by_vm(vms: list[Any]) -> dict[Any, list[PlacementDisk]]:
    """Per VM, the dedicated rows of its active placement, else of its
    newest placement that had any (a destroyed VM shows its slots
    released)."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES

    rows = (
        PlacementDisk.objects.filter(placement__vm__in=vms, kind=DiskKind.DEDICATED)
        .select_related("placement", "dedicated_disk")
        .order_by("placement__decided_at")
    )
    by_placement: dict[Any, list[PlacementDisk]] = {}
    for row in rows:
        by_placement.setdefault(row.placement_id, []).append(row)
    out: dict[Any, list[PlacementDisk]] = {}
    for group in by_placement.values():
        placement = group[0].placement
        current = out.get(placement.vm_id)
        active = placement.status in ACTIVE_PLACEMENT_STATES
        if current is None or active or current[0].placement.status not in ACTIVE_PLACEMENT_STATES:
            out[placement.vm_id] = group
    return out


def read_back_many(
    vms: list[Any], *, os_disks: Mapping[Any, tuple[int, str]] | None = None
) -> dict[Any, dict[str, Any]]:
    """`{vm.pk: {"pinned": True, "disks": [...]}}` for those of `vms` with a
    dedicated disk (contract §2); every other VM is absent (its response
    stays byte-identical). `os_disks` may give a VM's OS disk as `(size_gb,
    tier)`; otherwise it is read from its launch record."""
    from apps.lifecycle.models import VmState

    vms = [vm for vm in vms if vm is not None]
    if not vms:
        return {}
    by_vm = _rows_by_vm(vms)
    out: dict[Any, dict[str, Any]] = {}
    for vm in vms:
        rows = by_vm.get(vm.pk)
        if not rows:
            continue
        size_gb, tier = (os_disks or {}).get(vm.pk) or _os_disk_of(vm.vm_id)
        destroyed = vm.state == VmState.DESTROYED
        disks: list[dict[str, Any]] = [
            {"slot": "os", "kind": "pool", "size_gb": size_gb, "tier": tier, "state": "attached"}
        ]
        for row in sorted(rows, key=lambda r: _slot_index(r.slot)):
            entry: dict[str, Any] = {
                "slot": row.slot,
                "kind": DiskKind.DEDICATED.value,
                "size_gb": row.size_gb,
                "tier": row.required_tier,
                "state": _slot_state(row, vm, destroyed=destroyed),
            }
            # Additive to the contract: what the guest itself last said of
            # the slot (forgeable, informational), once it said anything.
            if not destroyed and row.observed_state in _GUEST_TO_SLOT:
                entry["guest_state"] = _GUEST_TO_SLOT[row.observed_state]
            disks.append(entry)
        out[vm.pk] = {"pinned": True, "disks": disks}
    return out


def read_back(vm: Any, *, os_disk: tuple[int, str] | None = None) -> dict[str, Any]:
    """[`read_back_many`] for one VM: `{}` without a dedicated disk."""
    if vm is None:
        return {}
    return read_back_many([vm], os_disks={vm.pk: os_disk} if os_disk else None).get(vm.pk, {})


def _os_disk_of(vm_id: str) -> tuple[int, str]:
    """`(size_gb, tier)` of the VM's OS disk as sold: its data disk and its
    OS-disk tier, from its launch record."""
    from apps.orchestration.services import launch_record

    from . import os_tier

    return launch_record.vm_data_disk_gb(vm_id), os_tier.launch_tier(vm_id)


# ── pinned VMs (contract §5) ─────────────────────────────────────────


def is_pinned(vm: Any) -> bool:
    """`vm` holds (or was sold) dedicated disks: it never leaves its host —
    no §25 migration, failover, restore elsewhere, migrating resize or
    backup policy (`dedicated-pinned`). Fails closed on a malformed launch
    record."""
    if PlacementDisk.objects.filter(placement__vm=vm, kind=DiskKind.DEDICATED).exists():
        return True
    if DedicatedDisk.objects.filter(assigned_vm=vm).exists():
        return True
    from apps.scheduler.service import _launch_spec

    try:
        return spec_request(_launch_spec(vm.vm_id)) is not None
    except ValueError:
        return True


def guest_release_refusal(vm: Any, release: int | None) -> str:
    """Why `vm` must not boot guest release `release` (`""` when it may):
    a VM with dedicated disks never boots a guest below
    `VALI_DEDICATED_MIN_GUEST_RELEASE` (an older guest ignores its disks) —
    guest upgrades, initrd swaps. `None` = a build of no known release."""
    if not is_pinned(vm):
        return ""
    minimum = min_guest_release()
    if minimum is not None and release is not None and int(release) >= minimum:
        return ""
    return (
        f"vm {vm.vm_id} has dedicated disks: its guest must stay at release "
        f"{minimum if minimum is not None else '(none set)'} or later, not {release}"
    )


def pinned_message(vm: Any, operation: str) -> str:
    return f"vm {vm.vm_id} has dedicated disks: it is pinned to its host and cannot be {operation}"


# ── §24 release and the way back to sale (design §5.2) ───────────────


def release_for_destroyed_vm(vm: Any) -> int:
    """§24 destroyed `vm`: each disk it holds goes `assigned → released`
    (`freed_at` now); its `PlacementDisk` rows stay as history. A disk that
    failed or was replaced while the VM held it gets its `freed_at` too (its
    slot is over). A released disk is NEVER placeable: it waits for the
    agent to report it wiped and free ([`reconcile_released`]), then for a
    probe. Idempotent. Returns how many disks were released."""
    now = timezone.now()
    with transaction.atomic():
        released = DedicatedDisk.objects.filter(
            assigned_vm=vm, state=DedicatedDiskState.ASSIGNED
        ).update(
            state=DedicatedDiskState.RELEASED,
            assigned_vm=None,
            assigned_slot="",
            freed_at=now,
            updated_at=now,
        )
        held = PlacementDisk.objects.filter(placement__vm=vm, kind=DiskKind.DEDICATED).values_list(
            "dedicated_disk_id", flat=True
        )
        DedicatedDisk.objects.filter(
            pk__in=list(held),
            state__in=(DedicatedDiskState.FAILED, DedicatedDiskState.REPLACED),
            assigned_vm__isnull=True,
            freed_at__isnull=True,
        ).update(freed_at=now, updated_at=now)
    return released


def reconcile_released(node_id: str, now: datetime) -> int:
    """A released disk the agent now reports `free` — no VM, no error, in a
    report newer than its release (the agent zeroed its head and tail) —
    goes to `pending_probe`. Never to `free`: only a probe that proves it is
    still there, healthy, the same device and without its LUKS header puts
    it back on sale (R3). Returns how many moved.

    First, the safety net of §24: a disk still assigned to a VM that is
    already destroyed (a crash between the tombstone and the release) is
    released now — and so cannot move on in this same pass (its release is
    not older than this report)."""
    from apps.lifecycle.models import Vm, VmState

    for vm in Vm.objects.filter(
        pk__in=DedicatedDisk.objects.filter(
            miner_node_id=node_id,
            state=DedicatedDiskState.ASSIGNED,
            assigned_vm__state=VmState.DESTROYED,
        ).values("assigned_vm")
    ):
        release_for_destroyed_vm(vm)
    return DedicatedDisk.objects.filter(
        miner_node_id=node_id,
        state=DedicatedDiskState.RELEASED,
        reported_state="free",
        reported_vm_id="",
        reported_error="",
        freed_at__isnull=False,
        reported_at__gt=F("freed_at"),
    ).update(state=DedicatedDiskState.PENDING_PROBE, updated_at=now)


# ── the receipt's slot verdicts ──────────────────────────────────────


_VERDICTS = frozenset({"ok", "missing", "mismatch"})


def slot_verdicts(disk_io: Iterable[Any]) -> dict[str, str]:
    """`{slot: verdict}` for the dedicated slots (`hippius-x<N>` serials)
    a verified receipt's `disk_io` reports on. Pure."""
    out: dict[str, str] = {}
    for delta in disk_io:
        serial = str(getattr(delta, "serial", "") or "")
        slot = serial[len("hippius-") :] if serial.startswith("hippius-") else ""
        state = str(getattr(delta, "state", "") or "")
        if _SLOT_RE.match(slot) and state in _VERDICTS:
            out[slot] = state
    return out


def record_slot_verdicts(placement_id: Any, verdicts: Mapping[str, str], at: datetime) -> int:
    """Store the guest's latest verdict per dedicated slot of the
    placement (`ok` | `missing` | `mismatch`, from a verified receipt's
    `disk_io`, `at` the end of its window). Every newer window advances the
    slot's `observed_at`, the same verdict included, so a late older
    window can never overwrite it. Returns rows updated."""
    from django.db.models import Q

    n = 0
    for slot, verdict in verdicts.items():
        if verdict not in _VERDICTS:
            continue
        n += (
            PlacementDisk.objects.filter(
                placement_id=placement_id, slot=slot, kind=DiskKind.DEDICATED
            )
            .filter(Q(observed_at__isnull=True) | Q(observed_at__lt=at))
            .update(observed_state=verdict, observed_at=at)
        )
    return n
