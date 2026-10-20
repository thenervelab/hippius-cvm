"""Compute requires storage: a compute family must also run Arion storage.

Rule v1 (`VALI_COMPUTE_REQUIRES_STORAGE`, default off): a compute family
needs at least `VALI_COMPUTE_STORAGE_MIN_NODES` (1) HEALTHY Arion storage
node(s). Without, its compute nodes take NO new VM (folded into the cordon
gate with the reason `no-storage`, `service.cordoned_node_ids`) and earn NO
reward weight (dropped from the epoch weights, `scoring`). The VMs already on
them are untouched — the same "no new work" posture as a cordon.

## Healthy

An Arion child of the family counts when it passes the filters the Arion
pallet itself applies to a child before counting it toward its family's paid
weight (`compute_family_weight_from_nodes`, thebrain `pallets/arion-pallet`)
— aligned with the on-chain design, read on chain:

1. `Arion.ChildRegistrations[child]` exists, names THIS family, and is
   `Active` (an `Unbonding` child has its deposit on the way out);
2. it is NOT one of the family's compute children, nor registered with one
   of its compute node ids: a compute machine cannot be its own storage
   alibi;
3. its validator-reported weight is FRESH — `NodeWeightLastBucket` within
   `StaleChildBuckets` (the runtime constant, read from metadata) of
   `CurrentWeightBucket`;
4. the validator has a `NodeQuality` on record for it (the pallet skips a
   child without one).

Every input is written by the Arion weight authority or the registration
extrinsics, never by the miner itself: a miner cannot claim storage it does
not serve. What it cannot prove is physical separation: one machine
registered under a second account and node id passes condition 2 — it still
has to be reported, fresh, by the validator. (A storage node with no shards
yet can be healthy: requiring stored bytes would refuse every new one.)

## Lapse and grace

Per family, `FamilyStorageState` keeps the clock [`advance`] moves on every
read, and survives a restart:

- `unhealthy_since`: the first read of the current run without healthy
  storage;
- `lapsed_since`: set to `unhealthy_since` once that run has lasted
  `VALI_COMPUTE_STORAGE_LAPSE_DEBOUNCE_S` (2 h) — a short gap (an Arion
  migration, a re-key) never lapses; cleared, with `unhealthy_since`, by the
  next healthy read.

The rights end at `grace_until = lapsed_since + VALI_COMPUTE_STORAGE_GRACE_S`
(72 h). A family never seen with storage lapses at its first read, with no
debounce and no grace: it is cut at once. The clock only runs while the
requirement is on, so a family that lost its storage before the switch was
turned on starts its debounce at the flip. Run `vali_storage_requirement
--evaluate` before turning it on.

Per compute node, [`node_requirements`] is the readout `/v1/operator/nodes`
serves: `state` (`ok` | `grace` | `lapsed` | `exempt` | `off`),
`family_storage_children` (the healthy count), `lapsed_since`,
`grace_until` — what the backend needs to warn an operator before the cut.

## Exemptions

`VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES`: SS58 family accounts never cut. An
entry that does not decode makes the WHOLE gate inert (logged): a typo must
not cut the families it was meant to protect.

## Failure

The gate decides from the last successful read. A failed read keeps it (a
family with storage stays allowed; a family's grace keeps running). Before the
first successful read there is nothing to act on. How old that read is shows
in `--evaluate` (`last_refresh_at`) and in the pushed gauge
`hippius_storage_requirement_refresh_timestamp_seconds`, beside the number of
families and of cut compute nodes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .chain import ChainReadUnavailable
from .models import FamilyStorageState
from .reasons import REASON_NO_STORAGE

log = logging.getLogger("apps.scheduler.storage_requirement")


#: Why an Arion child did not count, in the order they are checked.
CHILD_NOT_REGISTERED = "not-registered"
CHILD_OTHER_FAMILY = "other-family"
CHILD_NOT_ACTIVE = "not-active"
CHILD_COMPUTE = "compute-child"
CHILD_STALE = "stale"
CHILD_NO_QUALITY = "no-quality"

#: A family's (and its compute nodes') storage state.
STATE_OK = "ok"
STATE_GRACE = "grace"
STATE_LAPSED = "lapsed"
STATE_EXEMPT = "exempt"
STATE_OFF = "off"

_HEX64 = frozenset("0123456789abcdef")


# ─── settings ────────────────────────────────────────────────────────


def required() -> bool:
    return bool(getattr(settings, "VALI_COMPUTE_REQUIRES_STORAGE", False))


def grace_s() -> int:
    return int(getattr(settings, "VALI_COMPUTE_STORAGE_GRACE_S", 259200))


def debounce_s() -> int:
    return int(getattr(settings, "VALI_COMPUTE_STORAGE_LAPSE_DEBOUNCE_S", 7200))


def min_nodes() -> int:
    return max(1, int(getattr(settings, "VALI_COMPUTE_STORAGE_MIN_NODES", 1)))


class ExemptionInvalid(ValueError):
    """`VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES` holds an entry that is not an
    SS58 account."""


def exempt_families() -> frozenset[str]:
    """The exempt families as 64-hex account ids. Raises
    [`ExemptionInvalid`] naming the first bad entry."""
    from apps.disktier.node_family import ss58_decode

    out: set[str] = set()
    for entry in getattr(settings, "VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES", []) or []:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            out.add(ss58_decode(entry).hex())
        except ValueError as exc:
            raise ExemptionInvalid(f"exempt family {entry!r}: {exc}") from exc
    return frozenset(out)


def ss58_encode(account_hex: str, prefix: int = 42) -> str:
    """A 32-byte account as SS58 (generic prefix 42) — for readouts, so an
    operator can paste a family into the exemption list as is."""
    body = bytes([prefix]) + bytes.fromhex(account_hex)
    checksum = hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
    data = body + checksum
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


# ─── the chain read ──────────────────────────────────────────────────


@dataclass(frozen=True)
class StorageChild:
    child: str
    #: `None` when `ChildRegistrations[child]` is absent.
    reg_family: str | None
    reg_node_id: str | None
    reg_status: str | None
    node_weight: int
    last_bucket: int
    has_quality: bool
    uptime_permille: int | None


@dataclass(frozen=True)
class ComputeFamily:
    family: str
    #: `(node_id, child)` of each Active compute node.
    compute: tuple[tuple[str, str], ...]
    storage: tuple[StorageChild, ...]


@dataclass(frozen=True)
class StorageSnapshot:
    block_hash: str
    current_weight_bucket: int
    stale_child_buckets: int
    families: tuple[ComputeFamily, ...]


def read_storage_families() -> StorageSnapshot:
    """Shell out to `hippius-ticket-validator read-storage-families`. Same
    contract as `apps.scheduler.chain` (RPC URL in the environment, never
    argv); raises `ChainReadUnavailable` on every failure."""
    rpc_url = str(getattr(settings, "VALI_THEBRAIN_RPC_URL", "") or "").strip()
    if not rpc_url:
        raise ChainReadUnavailable("VALI_THEBRAIN_RPC_URL is not configured")
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise ChainReadUnavailable(f"validator binary not found at {bin_path}")
    compute = str(getattr(settings, "VALI_THEBRAIN_PALLET_NAME", "ComputeScoring"))
    arion = str(getattr(settings, "VALI_ARION_PALLET_NAME", "Arion"))
    timeout = float(getattr(settings, "VALI_THEBRAIN_RPC_TIMEOUT_S", 30.0)) * 4
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [
                str(bin_path),
                "read-storage-families",
                "--compute-pallet",
                compute,
                "--arion-pallet",
                arion,
            ],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "THEBRAIN_RPC_URL": rpc_url},
        )
    except subprocess.TimeoutExpired as exc:
        raise ChainReadUnavailable(f"read-storage-families timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise ChainReadUnavailable(f"read-storage-families spawn failed: {exc}") from exc
    if completed.returncode not in (0, 2):
        raise ChainReadUnavailable(f"read-storage-families exited with {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ChainReadUnavailable("read-storage-families stdout is not JSON") from exc
    if not isinstance(payload, dict):
        raise ChainReadUnavailable("read-storage-families stdout is not an object")
    if payload.get("tag") == "err":
        category = str(payload.get("category", "unknown"))
        raise ChainReadUnavailable(f"[{category}] {payload.get('error', 'chain read failed')}")
    if payload.get("tag") != "ok" or completed.returncode != 0:
        raise ChainReadUnavailable("read-storage-families returned no ok result")
    try:
        return parse_snapshot(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ChainReadUnavailable(
            f"read-storage-families output has unexpected shape: {exc}"
        ) from exc


def _hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX64:
        raise ValueError(f"{name} is not 64 lower-case hex")
    return value


def _uint(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"{name} is not a non-negative integer")
    return value


def parse_snapshot(payload: dict[str, Any]) -> StorageSnapshot:
    """The `read-storage-families` JSON as a [`StorageSnapshot`]; strict."""
    families: list[ComputeFamily] = []
    for f in payload["families"]:
        storage: list[StorageChild] = []
        for s in f["storage"]:
            reg = s["registration"]
            quality = s["quality"]
            if reg is not None and reg["status"] not in ("active", "unbonding"):
                raise ValueError(f"unknown child status {reg['status']!r}")
            storage.append(
                StorageChild(
                    child=_hex64(s["child_hex"], "child_hex"),
                    reg_family=_hex64(reg["family_hex"], "family_hex") if reg else None,
                    reg_node_id=_hex64(reg["node_id_hex"], "node_id_hex") if reg else None,
                    reg_status=str(reg["status"]) if reg else None,
                    node_weight=_uint(s["node_weight"], "node_weight"),
                    last_bucket=_uint(s["last_bucket"], "last_bucket"),
                    has_quality=quality is not None,
                    uptime_permille=(
                        _uint(quality["uptime_permille"], "uptime_permille") if quality else None
                    ),
                )
            )
        families.append(
            ComputeFamily(
                family=_hex64(f["family_hex"], "family_hex"),
                compute=tuple(
                    (_hex64(c["node_id_hex"], "node_id_hex"), _hex64(c["child_hex"], "child_hex"))
                    for c in f["compute"]
                ),
                storage=tuple(storage),
            )
        )
    block_hash = payload["block_hash"]
    if not isinstance(block_hash, str):
        raise TypeError("block_hash is not a string")
    return StorageSnapshot(
        block_hash=block_hash,
        current_weight_bucket=_uint(payload["current_weight_bucket"], "current_weight_bucket"),
        stale_child_buckets=_uint(payload["stale_child_buckets"], "stale_child_buckets"),
        families=tuple(families),
    )


# ─── judging a family (pure) ─────────────────────────────────────────


@dataclass(frozen=True)
class ChildVerdict:
    child: str
    counted: bool
    #: Why it did not count (`None` when counted).
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {"child": self.child, "counted": self.counted, "reason": self.reason}


@dataclass(frozen=True)
class FamilyVerdict:
    family: str
    compute_node_ids: tuple[str, ...]
    children: tuple[ChildVerdict, ...]

    @property
    def counted(self) -> int:
        return sum(1 for c in self.children if c.counted)

    @property
    def healthy(self) -> bool:
        return self.counted >= min_nodes()


def judge_child(
    child: StorageChild, family: ComputeFamily, *, current_bucket: int, stale_buckets: int
) -> str | None:
    """Why `child` does not count as `family`'s storage, or `None` when it
    does (module docstring, "Healthy")."""
    if child.reg_family is None:
        return CHILD_NOT_REGISTERED
    if child.reg_family != family.family:
        return CHILD_OTHER_FAMILY
    if child.reg_status != "active":
        return CHILD_NOT_ACTIVE
    compute_nodes = {n for n, _c in family.compute}
    compute_children = {c for _n, c in family.compute}
    if child.child in compute_children or child.reg_node_id in compute_nodes:
        return CHILD_COMPUTE
    if current_bucket - child.last_bucket > stale_buckets:
        return CHILD_STALE
    if not child.has_quality:
        return CHILD_NO_QUALITY
    return None


def judge(snapshot: StorageSnapshot) -> list[FamilyVerdict]:
    out: list[FamilyVerdict] = []
    for family in snapshot.families:
        children = []
        for child in family.storage:
            reason = judge_child(
                child,
                family,
                current_bucket=snapshot.current_weight_bucket,
                stale_buckets=snapshot.stale_child_buckets,
            )
            children.append(ChildVerdict(child.child, reason is None, reason))
        out.append(
            FamilyVerdict(
                family=family.family,
                compute_node_ids=tuple(n for n, _c in family.compute),
                children=tuple(children),
            )
        )
    return out


@dataclass(frozen=True)
class Clock:
    """A family's lapse clock (module docstring, "Lapse and grace")."""

    last_healthy_at: datetime | None
    unhealthy_since: datetime | None
    lapsed_since: datetime | None


def advance(prev: Clock | None, *, healthy: bool, now: datetime) -> Clock:
    """The clock after a read at `now` that found the family `healthy` or
    not; `prev` is `None` for a family read for the first time."""
    if healthy:
        return Clock(now, None, None)
    if prev is None:
        # First read, no storage: a new family lapses at once.
        return Clock(None, now, now)
    if prev.last_healthy_at is None:
        since = prev.lapsed_since or prev.unhealthy_since or now
        return Clock(None, prev.unhealthy_since or since, since)
    unhealthy_since = prev.unhealthy_since or now
    lapsed_since = prev.lapsed_since
    if lapsed_since is None and now - unhealthy_since >= timedelta(seconds=debounce_s()):
        lapsed_since = unhealthy_since
    return Clock(prev.last_healthy_at, unhealthy_since, lapsed_since)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    #: `ok` | `grace` | `lapsed` | `exempt`.
    state: str
    lapsed_since: datetime | None = None
    #: `lapsed_since + grace`; `None` for a family that never had storage.
    grace_until: datetime | None = None


def decide(
    *,
    family: str,
    has_storage: bool,
    clock: Clock,
    exempt: frozenset[str],
    now: datetime,
) -> Decision:
    if has_storage:
        return Decision(True, STATE_OK)
    if family in exempt:
        return Decision(True, STATE_EXEMPT, clock.lapsed_since)
    if clock.last_healthy_at is None:
        return Decision(False, STATE_LAPSED, clock.lapsed_since)
    if clock.lapsed_since is None:
        # Inside the debounce: not lapsed (yet).
        return Decision(True, STATE_OK)
    until = clock.lapsed_since + timedelta(seconds=grace_s())
    if now <= until:
        return Decision(True, STATE_GRACE, clock.lapsed_since, until)
    return Decision(False, STATE_LAPSED, clock.lapsed_since, until)


def _clock(row: FamilyStorageState) -> Clock:
    return Clock(row.last_healthy_at, row.unhealthy_since, row.lapsed_since)


# ─── the cached state and the gate ───────────────────────────────────


def refresh(snapshot: StorageSnapshot | None = None, *, now: datetime | None = None) -> int:
    """Read the chain (unless given `snapshot`) and record every compute
    family's storage in `FamilyStorageState`, in one transaction. Families
    no longer on chain are dropped. Returns the number of families. Raises
    `ChainReadUnavailable` and writes nothing when the read fails."""
    snapshot = snapshot or read_storage_families()
    now = now or timezone.now()
    verdicts = judge(snapshot)
    with transaction.atomic():
        existing = {r.family: r for r in FamilyStorageState.objects.select_for_update()}
        for v in verdicts:
            row = existing.pop(v.family, None)
            healthy = v.healthy
            fields = {
                "compute_node_ids": list(v.compute_node_ids),
                "storage_counted": v.counted,
                "has_storage": healthy,
                "storage_detail": [c.as_dict() for c in v.children],
                "refreshed_at": now,
                "block_hash": snapshot.block_hash,
            }
            clock = advance(_clock(row) if row else None, healthy=healthy, now=now)
            fields.update(
                last_healthy_at=clock.last_healthy_at,
                unhealthy_since=clock.unhealthy_since,
                lapsed_since=clock.lapsed_since,
            )
            if row is None:
                FamilyStorageState.objects.create(family=v.family, first_seen_at=now, **fields)
                continue
            if clock.lapsed_since is not None and row.lapsed_since is None:
                log.warning(
                    "storage requirement: family %s LAPSED (no healthy storage since %s); "
                    "grace until %s",
                    v.family[:16],
                    clock.lapsed_since.isoformat(),
                    (clock.lapsed_since + timedelta(seconds=grace_s())).isoformat(),
                )
            FamilyStorageState.objects.filter(pk=row.pk).update(**fields)
        if existing:
            FamilyStorageState.objects.filter(pk__in=list(existing)).delete()
    return len(verdicts)


def denied_node_ids(*, now: datetime | None = None) -> dict[str, str]:
    """`{compute node_id: "no-storage"}` of every compute node whose family
    is cut; `{}` while the requirement is off, before any successful read,
    or while the exemption list is invalid (logged)."""
    if not required():
        return {}
    try:
        exempt = exempt_families()
    except ExemptionInvalid as exc:
        _log_inert(str(exc))
        return {}
    now = now or timezone.now()
    out: dict[str, str] = {}
    for row in FamilyStorageState.objects.all():
        decision = decide(
            family=row.family,
            has_storage=row.has_storage,
            clock=_clock(row),
            exempt=exempt,
            now=now,
        )
        if not decision.allowed:
            for node_id in row.compute_node_ids:
                out[str(node_id).lower()] = REASON_NO_STORAGE
    return out


def _iso(at: datetime | None) -> str | None:
    return at.isoformat() if at else None


#: The per-node readout while the requirement is off (or inert).
OFF_READOUT: dict[str, Any] = {
    "state": STATE_OFF,
    "family_storage_children": None,
    "lapsed_since": None,
    "grace_until": None,
}


def node_requirements(*, now: datetime | None = None) -> dict[str, dict[str, Any]] | None:
    """`{compute node_id: readout}` — the per-node `storage_requirement`
    `/v1/operator/nodes` serves: `{state, family_storage_children,
    lapsed_since, grace_until}`. `None` while the requirement is off (or
    inert on a bad exemption list): every node then reads [`OFF_READOUT`].
    A node absent from the map is not a compute node vali has read on
    chain: the caller serves `null` for it."""
    if not required():
        return None
    try:
        exempt = exempt_families()
    except ExemptionInvalid as exc:
        _log_inert(str(exc))
        return None
    now = now or timezone.now()
    out: dict[str, dict[str, Any]] = {}
    for row in FamilyStorageState.objects.all():
        decision = decide(
            family=row.family,
            has_storage=row.has_storage,
            clock=_clock(row),
            exempt=exempt,
            now=now,
        )
        readout = {
            "state": decision.state,
            "family_storage_children": row.storage_counted,
            "lapsed_since": _iso(decision.lapsed_since),
            "grace_until": _iso(decision.grace_until),
        }
        for node_id in row.compute_node_ids:
            out[str(node_id).lower()] = readout
    return out


def withhold_weights(base: dict[str, int]) -> dict[str, int]:
    """Drop the compute nodes of every family cut for want of storage from
    `base` (the epoch weights), loudly. Unchanged while off."""
    denied = denied_node_ids()
    if not denied:
        return base
    kept = {n: w for n, w in base.items() if n.lower() not in denied}
    for node_id in sorted(set(base) - set(kept)):
        log.error(
            "scoring: WITHHOLDING reward weight %d from node %s — its family runs "
            "no healthy Arion storage node (storage requirement)",
            base[node_id],
            node_id[:16],
        )
    return kept


_last_refresh_attempt: float | None = None
_last_inert_log: float | None = None


def _log_inert(why: str) -> None:
    """The gate is read on every placement: say it is inert once a minute,
    not once a call."""
    global _last_inert_log
    now_mono = time.monotonic()
    if _last_inert_log is None or now_mono - _last_inert_log >= 60:
        _last_inert_log = now_mono
        log.error("storage requirement INERT: %s", why)


M_REFRESH_TS = "hippius_storage_requirement_refresh_timestamp_seconds"
M_FAMILIES = "hippius_storage_requirement_families"
M_CUT_NODES = "hippius_storage_requirement_cut_nodes"


def _push_gauges() -> None:
    """The age of the data the gate decides from, and what it decides. Never
    raises; nothing without a Pushgateway."""
    gateway = str(getattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "") or "")
    if not gateway:
        return
    try:
        from django.db.models import Max

        from apps.synthetic import metrics

        last = FamilyStorageState.objects.aggregate(at=Max("refreshed_at"))["at"]
        ms = metrics.MetricSet()
        if last is not None:
            ms.gauge(M_REFRESH_TS, last.timestamp())
        ms.gauge(M_FAMILIES, float(FamilyStorageState.objects.count()))
        ms.gauge(M_CUT_NODES, float(len(denied_node_ids())))
        metrics.push(
            ms, gateway_url=gateway, job="vali-storage-requirement", grouping_key={}, replace=True
        )
    except Exception:  # noqa: BLE001 — observability must never break the loop.
        log.exception("storage requirement gauges not pushed")


def refresh_if_due() -> None:
    """The reeval loop's hook: refresh at most every
    `VALI_COMPUTE_STORAGE_REFRESH_S`, only while the requirement is on.
    Never raises."""
    global _last_refresh_attempt
    if not required():
        return
    period = float(getattr(settings, "VALI_COMPUTE_STORAGE_REFRESH_S", 300))
    now_mono = time.monotonic()
    if _last_refresh_attempt is not None and now_mono - _last_refresh_attempt < period:
        return
    _last_refresh_attempt = now_mono
    try:
        families = refresh()
    except ChainReadUnavailable as exc:
        log.error("storage requirement: chain read failed, keeping the last decision: %s", exc)
        _push_gauges()
        return
    except Exception:  # noqa: BLE001 — the loop must survive.
        log.exception("storage requirement refresh raised")
        _push_gauges()
        return
    _push_gauges()
    log.info(
        "storage requirement: %d compute family(ies) read, %d node(s) cut",
        families,
        len(denied_node_ids()),
    )


# ─── read-only evaluation ────────────────────────────────────────────


def evaluate(snapshot: StorageSnapshot | None = None, *, now: datetime | None = None) -> dict:
    """What the requirement decides for every compute family RIGHT NOW,
    from a fresh chain read and the recorded grace clock. Writes nothing.

    A family with no recorded state is judged as new (no grace) — which is
    what the first refresh after turning the requirement on would do."""
    snapshot = snapshot or read_storage_families()
    now = now or timezone.now()
    try:
        exempt = exempt_families()
        exemption_error = None
    except ExemptionInvalid as exc:
        exempt, exemption_error = frozenset(), str(exc)
    rows = {r.family: r for r in FamilyStorageState.objects.all()}
    last_refresh = max((r.refreshed_at for r in rows.values()), default=None)
    families = []
    for v in judge(snapshot):
        row = rows.get(v.family)
        healthy = v.healthy
        # The clock as the next refresh would move it — computed, not stored.
        clock = advance(_clock(row) if row else None, healthy=healthy, now=now)
        decision = decide(
            family=v.family,
            has_storage=healthy,
            clock=clock,
            exempt=exempt,
            now=now,
        )
        families.append(
            {
                "family": v.family,
                "family_ss58": ss58_encode(v.family),
                "compute_node_ids": list(v.compute_node_ids),
                "family_storage_children": v.counted,
                "storage_required": min_nodes(),
                "healthy": healthy,
                "children": [c.as_dict() for c in v.children],
                "tracked": row is not None,
                "state": decision.state,
                "allowed": decision.allowed,
                "unhealthy_since": _iso(clock.unhealthy_since),
                "lapsed_since": _iso(decision.lapsed_since),
                "grace_until": _iso(decision.grace_until),
            }
        )
    return {
        "requirement_on": required(),
        "gate_inert": exemption_error is not None,
        "exemption_error": exemption_error,
        "block_hash": snapshot.block_hash,
        "current_weight_bucket": snapshot.current_weight_bucket,
        "stale_child_buckets": snapshot.stale_child_buckets,
        "grace_s": grace_s(),
        "lapse_debounce_s": debounce_s(),
        "last_refresh_at": last_refresh.isoformat() if last_refresh else None,
        "families": families,
    }
