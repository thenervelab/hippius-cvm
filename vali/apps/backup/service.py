"""Live VM backups: policy, the backup tick, restorability, pruning.

See `docs/design/backup-failover.md` for the model. In short:

- A **full** backup copies the whole golden overlay while the guest runs and
  (re)starts the miner's in-memory dirty bitmap; an **incremental** copies
  only the clusters dirtied since the previous successful run. A full plus
  its incrementals is a **chain**, always taken within one boot.
- Only a chain taken at the guest's CURRENT boot is restorable (the KBS
  boot counter and the guest's volume stamp only move forward), so a new
  boot — seen through the miner's boot-counter / bitmap probe — triggers a
  full at once.
- vali opens each multipart upload itself, hands the miner presigned part
  URLs only, and completes the upload with the ETags the miner reports. The
  bucket is vali's own; tenants have no right on it.

Everything that talks to another service goes through `apps.orchestration.
effects` (miner orders and polls) or `apps.storage.s3` (the bucket), which
the tests replace.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import effects
from apps.storage import s3

from .models import (
    ACTIVE_RUN_STATUSES,
    BackupChain,
    BackupInterval,
    BackupKind,
    BackupPolicy,
    BackupRun,
    ChainState,
    FailoverMode,
    RunStatus,
)

log = logging.getLogger("apps.backup")

GIB = 1024**3
MIB = 1024**2

#: The most presigned part URLs one `backup` order may carry (the 2 MiB
#: multipart order body).
MAX_PARTS = s3.MAX_ORDER_PARTS
#: Multipart part bounds: S3's floor, and the store's 512 MiB ceiling
#: (hippius-s3 refuses a larger part with `EntityTooLarge`).
MIN_S3_PART_BYTES = s3.MIN_PART_BYTES
MAX_S3_PART_BYTES = s3.MAX_PART_BYTES
#: The anti-rollback state disk every run uploads whole.
STATE_DISK_BYTES = 1 * MIB
#: Mirrors the miner-agent's `MAX_RESTORE_PIECES`: a full plus its
#: incrementals in one `migrate-activate` order.
MAX_RESTORE_PIECES = 64
#: Headroom over the raw disk size for an incremental qcow2 whose every
#: cluster is dirty: qcow2 metadata (L1/L2 tables, refcounts) on top of the
#: data. 1/64 plus a fixed 64 MiB is far above what qcow2 needs.
_QCOW2_SLACK_DIVISOR = 64
_QCOW2_SLACK_FIXED = 64 * MIB

#: Retention bounds a policy may ask for.
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 365
DEFAULT_RETENTION_DAYS = 7

#: `vm_id` charset — the same rule the launch API enforces; the vm_id is
#: interpolated into object keys.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z0-9-]{1,64}$")

_DISK_MODE_GOLDEN_VERITY = "golden_verity_overlay"
_MANIFEST_FORMAT = "hippius-vm-backup/1"


class BackupError(Exception):
    """A backup operation was refused. `code` is the stable error the view
    returns; `detail` is for humans."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ─── settings ────────────────────────────────────────────────────────


def enabled() -> bool:
    return bool(getattr(settings, "VALI_BACKUP_ENABLED", False))


def rollback_enabled() -> bool:
    """`VALI_RESTORE_ROLLBACK_ENABLED`: a point of an EARLIER boot (with a
    KBS checkpoint) may be restored, through a KBS-authorized rollback.
    Off by default; also the kill switch for rollback jobs in flight."""
    return bool(getattr(settings, "VALI_RESTORE_ROLLBACK_ENABLED", False))


def _bucket() -> str:
    """The configured backup bucket. It must be set, and it must not be one
    of the buckets vali shares with other uses: the images bucket is
    public-read, and the janitor lists and deletes under `backups/` and
    `uploads/`, which must never touch anything else."""
    bucket = str(getattr(settings, "VALI_BACKUP_BUCKET", "") or "").strip()
    if not bucket:
        raise BackupError("backup-unavailable", "VALI_BACKUP_BUCKET is not configured")
    shared = {
        str(getattr(settings, name, "") or "").strip()
        for name in ("VALI_PACKER_IMAGES_BUCKET", "VALI_ORCHESTRATION_SNAPSHOT_BUCKET")
    } - {""}
    if bucket in shared:
        raise BackupError(
            "backup-unavailable",
            f"VALI_BACKUP_BUCKET {bucket!r} is a shared bucket (images / migration "
            "snapshots); backups need a dedicated private bucket",
        )
    return bucket


_CLIENT_LOCK = threading.Lock()
_CLIENT_CACHE: dict[tuple[str, str, str], s3.HippiusS3Client] = {}


def backup_s3_client() -> s3.HippiusS3Client:
    """The S3 client for the backup bucket — built from its OWN credentials
    (`VALI_BACKUP_S3_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` /
    `_ENDPOINT_URL`), never the shared default chain vali's images key
    rides. That key is scoped to the one bucket at object level: object
    reads/writes and multipart, no bucket-admin calls — so nothing here
    makes one. Path-style + SigV4, like every Hippius S3 client.

    Raises `BackupError("backup-unavailable")` when the credentials are not
    configured. The secret never reaches a log line or an error message."""
    key_id = str(getattr(settings, "VALI_BACKUP_S3_ACCESS_KEY_ID", "") or "").strip()
    secret = str(getattr(settings, "VALI_BACKUP_S3_SECRET_ACCESS_KEY", "") or "").strip()
    endpoint = str(getattr(settings, "VALI_BACKUP_S3_ENDPOINT_URL", "") or "").strip()
    missing = [
        name
        for name, value in (
            ("VALI_BACKUP_S3_ACCESS_KEY_ID", key_id),
            ("VALI_BACKUP_S3_SECRET_ACCESS_KEY", secret),
            ("VALI_BACKUP_S3_ENDPOINT_URL", endpoint),
        )
        if not value
    ]
    if missing:
        raise BackupError("backup-unavailable", f"{', '.join(missing)} not configured")
    cache_key = (endpoint, key_id, secret)
    with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get(cache_key)
        if client is None:
            region = str(getattr(settings, "HIPPIUS_S3_REGION_NAME", "") or "") or None
            try:
                client = s3.BotoHippiusS3Client(
                    endpoint_url=endpoint,
                    region_name=region,
                    aws_access_key_id=key_id,
                    aws_secret_access_key=secret,
                )
            except s3.S3ClientUnavailable as exc:
                raise BackupError("backup-unavailable", f"backup S3 client: {exc}") from exc
            _CLIENT_CACHE.clear()  # credentials rotated: drop the old client
            _CLIENT_CACHE[cache_key] = client
        return client


#: When the backup bucket was last proven reachable, per bucket name. A
#: process-local cache: a fresh process re-checks on its first use.
_BUCKET_OK: dict[str, datetime] = {}
_BUCKET_RECHECK = timedelta(minutes=10)
_BUCKET_PROBE_KEY = "backups/.vali-bucket-probe"


def ensure_bucket(*, now: datetime | None = None) -> str:
    """The backup bucket, after proving vali's key can reach it (a GET of a
    key that never exists, re-proven every ten minutes). Raises
    `BackupError("backup-unavailable")` with the reason otherwise — the
    tick logs it as an ERROR and does nothing else, so a missing or
    unreachable bucket is loud from the first tick rather than surfacing as
    every run failing one by one."""
    bucket = _bucket()
    now = now or timezone.now()
    checked = _BUCKET_OK.get(bucket)
    if checked is not None and now - checked < _BUCKET_RECHECK:
        return bucket
    try:
        # A GET of a key that is never written: a reachable bucket answers
        # NoSuchKey (→ None); NoSuchBucket / AccessDenied / a transport error
        # raise. Constant cost, unlike a listing a store may not bound.
        backup_s3_client().get_object(bucket=bucket, key=_BUCKET_PROBE_KEY, max_bytes=1024)
    except s3.S3ClientUnavailable as exc:
        _BUCKET_OK.pop(bucket, None)
        raise BackupError(
            "backup-unavailable", f"backup bucket {bucket!r} is not reachable: {exc}"
        ) from exc
    _BUCKET_OK[bucket] = now
    return bucket


def _max_chain() -> int:
    # A restore order carries at most `MAX_RESTORE_PIECES` pieces: the full
    # plus this many incrementals must fit.
    raw = int(getattr(settings, "VALI_BACKUP_MAX_CHAIN", 24))
    return min(max(1, raw), MAX_RESTORE_PIECES - 1)


def _run_timeout() -> timedelta:
    secs = int(getattr(settings, "VALI_BACKUP_RUN_TIMEOUT_S", 6 * 3600))
    return timedelta(seconds=min(max(secs, 60), s3.MAX_TTL_SECONDS))


def _lost_grace() -> timedelta:
    return timedelta(seconds=int(getattr(settings, "VALI_BACKUP_LOST_GRACE_S", 180)))


def _probe_interval() -> timedelta:
    return timedelta(seconds=int(getattr(settings, "VALI_BACKUP_PROBE_INTERVAL_S", 300)))


def _retry_after() -> timedelta:
    return timedelta(seconds=int(getattr(settings, "VALI_BACKUP_RETRY_AFTER_S", 900)))


def _min_part_bytes() -> int:
    raw = int(getattr(settings, "VALI_BACKUP_MIN_PART_BYTES", MAX_S3_PART_BYTES))
    return min(max(raw, MIN_S3_PART_BYTES), MAX_S3_PART_BYTES)


# ─── what gets backed up ─────────────────────────────────────────────


def max_disk_bytes() -> int:
    """The largest overlay a run can carry: `MAX_PARTS` parts of at most
    `MAX_S3_PART_BYTES`, less the incremental headroom `plan_parts` adds."""
    budget = MAX_PARTS * MAX_S3_PART_BYTES - _QCOW2_SLACK_FIXED
    return budget * _QCOW2_SLACK_DIVISOR // (_QCOW2_SLACK_DIVISOR + 1)


def plan_parts(disk_bytes: int) -> tuple[int, int]:
    """`(part_size, part_count)` covering the largest piece a run of a
    `disk_bytes` overlay can produce — the full raw image, or an incremental
    qcow2 with every cluster dirty. Parts are whole MiB, at least
    `VALI_BACKUP_MIN_PART_BYTES`, and at most `MAX_PARTS` of them. Raises
    `BackupError("disk-too-large")` when `MAX_S3_PART_BYTES` parts are not
    enough."""
    if disk_bytes <= 0:
        raise ValueError("disk_bytes must be positive")
    bound = disk_bytes + disk_bytes // _QCOW2_SLACK_DIVISOR + _QCOW2_SLACK_FIXED
    part_size = max(_min_part_bytes(), math.ceil(bound / MAX_PARTS))
    part_size = math.ceil(part_size / MIB) * MIB
    if part_size > MAX_S3_PART_BYTES:
        raise BackupError(
            "disk-too-large",
            f"a {disk_bytes // GIB} GiB disk exceeds the {max_disk_bytes() // GIB} GiB "
            "a backup can carry",
        )
    return part_size, math.ceil(bound / part_size)


def source_disk_bytes(vm: Vm) -> int:
    """Size of the VM's writable golden overlay — what a full backup copies.

    Read from the VM's latest successful launch record, the same record the
    §25 dest-activation reads. Only golden VMs can be backed up: a legacy
    VM keeps data on a second disk (`/dev/vde`) no backup carries.
    """
    from apps.orchestration.models import LaunchJob, LaunchJobState

    record = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )
    if record is None:
        raise BackupError("no-launch-record", "the vm has no successful launch record")
    spec = record.spec_json or {}
    if str(spec.get("disk_mode") or "") != _DISK_MODE_GOLDEN_VERITY:
        raise BackupError("not-golden", "only golden-image VMs can be backed up")
    # The disk it was launched with: a resize moves the flavor, never the
    # disk (`launch_record.data_disk_gb`).
    from apps.orchestration.services.launch_record import data_disk_gb

    disk_gb = data_disk_gb(record)
    if not disk_gb:
        raise BackupError("no-launch-record", "the launch record has no known flavor")
    return int(disk_gb) * GIB


# ─── miner status wire (the miner-agent's backup status route) ───────
#
# `GET /v1/miner/backup/{vm_id}/status` →
#   {"vm_id", "live": {"boot_counter": u64|null, "point_run_ids": [str]},
#    "run": RunStatus|null}
# where RunStatus is the miner's `backup::RunStatus`:
#   {"run_id", "parent_run_id"|null, "kind", "status", "error"|null,
#    "bitmap_present"|null, "boot_counter"|null, "virtual_size"|null,
#    "disk": Piece|null, "state": Piece|null}
#   Piece = {"parts": [{"part_number", "etag", "sha256_hex", "size"}],
#            "size", "sha256_hex"}


@dataclass(frozen=True)
class Part:
    part_number: int
    etag: str
    sha256_hex: str
    size: int


@dataclass(frozen=True)
class Piece:
    parts: list[Part]
    size: int
    sha256_hex: str


@dataclass(frozen=True)
class RunReport:
    run_id: str
    parent_run_id: str | None
    kind: str
    status: str
    error: str
    bitmap_present: bool | None
    boot_counter: int | None
    virtual_size: int | None
    disk: Piece | None
    state: Piece | None


@dataclass(frozen=True)
class MinerBackupStatus:
    vm_id: str
    #: Read at poll time from the VM's state disk; None when unreadable.
    live_boot_counter: int | None
    #: run_ids whose point bitmap exists on the overlay right now — the
    #: runs an incremental can still be taken from. None when the miner
    #: gave no live reading.
    live_points: list[str] | None
    run: RunReport | None


def _uint(obj: dict[str, Any], name: str) -> int:
    v = obj.get(name)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return v


def _opt_uint(obj: dict[str, Any], name: str) -> int | None:
    return None if obj.get(name) is None else _uint(obj, name)


def _str(obj: dict[str, Any], name: str) -> str:
    v = obj.get(name)
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _opt_str(obj: dict[str, Any], name: str) -> str | None:
    return None if obj.get(name) is None else _str(obj, name)


def _obj(v: Any, name: str) -> dict[str, Any]:
    if not isinstance(v, dict):
        raise ValueError(f"{name} must be an object")
    return v


def _piece(raw: Any, name: str) -> Piece | None:
    if raw is None:
        return None
    raw = _obj(raw, name)
    parts_raw = raw.get("parts")
    if not isinstance(parts_raw, list) or len(parts_raw) > MAX_PARTS:
        raise ValueError(f"{name}.parts must be a list of at most {MAX_PARTS}")
    parts = []
    for p in parts_raw:
        p = _obj(p, f"{name}.parts[]")
        parts.append(
            Part(
                part_number=_uint(p, "part_number"),
                etag=_str(p, "etag"),
                sha256_hex=_str(p, "sha256_hex"),
                size=_uint(p, "size"),
            )
        )
    return Piece(parts=parts, size=_uint(raw, "size"), sha256_hex=_str(raw, "sha256_hex"))


def _run_report(r: dict[str, Any]) -> RunReport:
    kind = _str(r, "kind")
    if kind not in BackupKind.values:
        raise ValueError("run.kind is unknown")
    status = _str(r, "status")
    if status not in ("running", "done", "failed"):
        raise ValueError("run.status is unknown")
    bitmap = r.get("bitmap_present")
    if bitmap is not None and not isinstance(bitmap, bool):
        raise ValueError("run.bitmap_present must be a boolean or null")
    return RunReport(
        run_id=_str(r, "run_id"),
        parent_run_id=_opt_str(r, "parent_run_id"),
        kind=kind,
        status=status,
        error=_opt_str(r, "error") or "",
        bitmap_present=bitmap,
        boot_counter=_opt_uint(r, "boot_counter"),
        virtual_size=_opt_uint(r, "virtual_size"),
        disk=_piece(r.get("disk"), "run.disk"),
        state=_piece(r.get("state"), "run.state"),
    )


def parse_status(raw: dict[str, Any], *, vm_id: str) -> MinerBackupStatus:
    """Parse the miner's status JSON for `vm_id`. The miner is untrusted:
    every field is type-checked here and `ValueError` raised on anything
    off-shape; what the values MEAN is checked where they are used
    (`_validate_done`).

    The miner-agent answers `{vm_id, live: {boot_counter, point_run_ids},
    run}` (`run` null when it has run nothing since it started). The bare
    `RunStatus` of an earlier agent build is still accepted; it carries no
    live reading, so a reboot between runs is then learnt from the next
    run only."""
    if "live" not in raw:
        return MinerBackupStatus(
            vm_id=vm_id, live_boot_counter=None, live_points=None, run=_run_report(raw)
        )
    live = _obj(raw.get("live"), "live")
    points = live.get("point_run_ids")
    if not isinstance(points, list) or not all(isinstance(x, str) for x in points):
        raise ValueError("live.point_run_ids must be a list of strings")
    if len(points) > 16:
        raise ValueError("live.point_run_ids is implausibly long")
    if _str(raw, "vm_id") != vm_id:
        raise ValueError("status is about another vm")
    return MinerBackupStatus(
        vm_id=vm_id,
        live_boot_counter=_opt_uint(live, "boot_counter"),
        live_points=list(points),
        run=_run_report(_obj(raw["run"], "run")) if raw.get("run") is not None else None,
    )


def _poll(vm_id: str, miner_id: str) -> MinerBackupStatus | None:
    """Poll and parse one miner status; None on 404 — that host has no
    domain for the VM. A 503 (`status-unavailable`: libvirt or QMP down)
    raises `EffectUnavailable` and is retried, never read as "no points".
    Raises `ValueError` on an off-shape answer, including one about another
    VM."""
    raw = effects.poll_backup_status(vm_id=vm_id, miner_id=miner_id)
    if raw is None:
        return None
    return parse_status(raw, vm_id=vm_id)


#: Miner failure classes after which only a full can follow: the parent
#: point is gone (`bitmap-missing`) or the guest booted mid-run
#: (`state-changed`).
_FULL_REQUIRED_ERRORS = frozenset({"bitmap-missing", "state-changed"})


def _reason(raw: str, fallback: str) -> str:
    """A miner-supplied classifier, kept only if it looks like one."""
    return raw if _REASON_RE.fullmatch(raw or "") else fallback


# ─── policy ──────────────────────────────────────────────────────────


def _validate_policy_fields(
    interval_s: Any, retention_days: Any, failover_mode: Any
) -> tuple[int, int, str]:
    if isinstance(interval_s, bool) or interval_s not in BackupInterval.values:
        raise BackupError(
            "bad-interval",
            "interval_s must be one of " + ", ".join(str(v) for v in BackupInterval.values),
        )
    if (
        isinstance(retention_days, bool)
        or not isinstance(retention_days, int)
        or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS
    ):
        raise BackupError(
            "bad-retention",
            f"retention_days must be an integer in {MIN_RETENTION_DAYS}..{MAX_RETENTION_DAYS}",
        )
    if failover_mode not in FailoverMode.values:
        raise BackupError("bad-failover-mode", "failover_mode must be 'auto' or 'manual'")
    return int(interval_s), int(retention_days), str(failover_mode)


def put_policy(
    vm: Vm,
    *,
    interval_s: Any,
    retention_days: Any = DEFAULT_RETENTION_DAYS,
    failover_mode: Any = FailoverMode.AUTO,
) -> tuple[BackupPolicy, bool]:
    """Create or replace the VM's backup policy. Returns `(policy, created)`
    — `created` is also true when a disabled policy is re-enabled.

    A (re-)enabled policy starts with a full at the next tick. Changing only
    the interval or retention of an enabled policy keeps its chain."""
    if not enabled():
        raise BackupError("backup-unavailable", "backups are not enabled on this deployment")
    interval, retention, mode = _validate_policy_fields(interval_s, retention_days, failover_mode)
    if vm.state in (VmState.DESTROYED, VmState.DECOMMISSIONING):
        raise BackupError("vm-not-live", "the vm is being or has been destroyed")
    plan_parts(source_disk_bytes(vm))  # refuses legacy and oversize VMs
    ensure_bucket()
    with transaction.atomic():
        policy = BackupPolicy.objects.select_for_update().filter(vm=vm).first()
        if policy is None:
            policy = BackupPolicy.objects.create(
                vm=vm, interval_s=interval, retention_days=retention, failover_mode=mode
            )
            return policy, True
        created = not policy.enabled
        policy.interval_s = interval
        policy.retention_days = retention
        policy.failover_mode = mode
        if created:
            policy.enabled = True
            policy.disabled_at = None
            policy.full_required = True
        policy.save()
    return policy, created


def disable_policy(vm: Vm, *, now: datetime | None = None) -> BackupPolicy:
    """Stop backing the VM up. Its chains are closed now and pruned once
    `retention_days` have passed, like any superseded chain."""
    now = now or timezone.now()
    with transaction.atomic():
        policy = BackupPolicy.objects.select_for_update().filter(vm=vm, enabled=True).first()
        if policy is None:
            raise BackupError("no-backup-policy", "the vm has no backup policy")
        policy.enabled = False
        policy.disabled_at = now
        policy.save(update_fields=["enabled", "disabled_at", "updated_at"])
        BackupChain.objects.filter(vm=vm, state=ChainState.OPEN).update(
            state=ChainState.CLOSED, closed_at=now
        )
    return policy


def get_policy(vm: Vm) -> BackupPolicy:
    policy = BackupPolicy.objects.filter(vm=vm, enabled=True).first()
    if policy is None:
        raise BackupError("no-backup-policy", "the vm has no backup policy")
    return policy


# ─── restorability ───────────────────────────────────────────────────


class PointClass:
    """What restoring one DONE run would take.

    - `current-boot`: taken at the guest's CURRENT boot. Its state disk
      holds the counter the KBS stores and its volume stamp is the one the
      KBS expects, so it restores with no KBS change.
    - `rollback`: taken at an earlier boot. Restorable only through a
      KBS-authorized rollback: the run must carry a KBS checkpoint of its own
      boot counter, and `VALI_RESTORE_ROLLBACK_ENABLED` must be on.
    - `unavailable`: not a point at all — the run did not finish, its chain
      failed or was pruned, a run it builds on is missing, or the VM is
      being destroyed.
    """

    CURRENT_BOOT = "current-boot"
    ROLLBACK = "rollback"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Point:
    """One run classified as a restore point. `runs` is what restoring it
    applies, in order: the chain's full, then every incremental up to and
    including `run` (empty when `klass` is unavailable)."""

    run: BackupRun
    klass: str
    runs: tuple[BackupRun, ...]

    @property
    def restorable(self) -> bool:
        if self.klass == PointClass.CURRENT_BOOT:
            return True
        # A2: an earlier boot, only through a KBS arm built from the run's
        # own signed checkpoint.
        return self.klass == PointClass.ROLLBACK and self.rollback_ready

    @property
    def rollback_ready(self) -> bool:
        """A rollback point the KBS can be asked to authorize: the flag is
        on and the run carries a checkpoint of its own boot counter."""
        return (
            self.klass == PointClass.ROLLBACK
            and rollback_enabled()
            and checkpoint_of(self.run) is not None
        )


def checkpoint_of(run: BackupRun) -> dict[str, Any] | None:
    """The run's stored KBS checkpoint (`Checkpoint.wire()` shape) when it
    is usable for a rollback, None otherwise. Usable means all of:

    - present, about this VM, of the run's own boot counter;
    - STAMPED (`volume_stamp > 0`): an unstamped checkpoint cannot tell the
      KBS which volume stamp the point carries, so the KBS refuses to arm
      it (`checkpoint-unstamped`) — such a run is not rollback-capable;
    - TIMELINE-BOUND (a V2 checkpoint): a V1 one names no volume-stamp
      timeline, so the KBS refuses to arm it
      (`checkpoint-not-timeline-bound`) — a run backed up before the KBS
      signed V2 checkpoints is not rollback-capable;
    - the run's exact manifest bytes kept, within the KBS's size bound,
      hashing to `manifest_sha256`, naming the VM and embedding this very
      checkpoint (what the KBS verifies) — so a point the KBS would refuse
      is refused at intake, before the VM is stopped and fenced."""
    from apps.orchestration.services import kbs_rollback

    cp = run.kbs_checkpoint
    if not isinstance(cp, dict) or not run.manifest_sha256 or not run.manifest_json:
        return None
    body = cp.get("checkpoint")
    if not isinstance(body, dict):
        return None
    if body.get("vm_id") != run.vm.vm_id or body.get("boot_counter") != run.boot_counter:
        return None
    stamp = body.get("volume_stamp")
    if isinstance(stamp, bool) or not isinstance(stamp, int) or stamp <= 0:
        return None
    if not kbs_rollback.checkpoint_is_timeline_bound(cp):
        return None
    cbor_hex = cp.get("checkpoint_cbor_hex")
    if not isinstance(cbor_hex, str) or not isinstance(cp.get("signature_hex"), str):
        return None
    try:
        kbs_rollback.check_point_manifest(
            run.manifest_json.encode("utf-8"),
            vm_id=run.vm.vm_id,
            sha256_hex=run.manifest_sha256,
            checkpoint_cbor_hex=cbor_hex,
        )
    except kbs_rollback.PointManifestInvalid:
        return None
    return cp


def boot_epoch_start(vm: Vm) -> datetime | None:
    """When the VM's current boot can have begun at the latest, as far as
    vali's own records know: the end of its newest completed migration,
    restore or failover. Every one of those booted the guest anew on its
    destination, so a chain whose full was taken before it belongs to an
    earlier boot even while the host-read counter has not caught up yet."""
    from apps.orchestration.models import MigrationJob, MigrationState

    return (
        MigrationJob.objects.filter(vm=vm, state=MigrationState.DONE.value)
        .order_by("-finished_at")
        .values_list("finished_at", flat=True)
        .first()
    )


def _chain_is_current_boot(
    chain: BackupChain, policy: BackupPolicy | None, epoch_start: datetime | None
) -> bool:
    if policy is None or not policy.enabled or policy.observed_boot_counter is None:
        # A disabled policy is no longer probed: its counter says nothing
        # about the boot the guest is in now.
        return False
    if chain.boot_counter is None or chain.boot_counter != policy.observed_boot_counter:
        return False
    return epoch_start is None or chain.created_at >= epoch_start


def chain_points(
    vm: Vm,
    chain: BackupChain,
    runs: list[BackupRun],
    *,
    policy: BackupPolicy | None,
    epoch_start: datetime | None,
) -> dict[Any, Point]:
    """`{run pk: Point}` for every run of `chain` (`runs`, in `seq`
    order).

    A DONE run is a point iff every run it builds on is there: the chain's
    first DONE run is its full, and each DONE incremental names the DONE
    run just before it as its parent (a failed run in between is skipped by
    construction — the next incremental is taken from the last committed
    run). The first broken link makes it and everything after it
    unavailable."""
    points: dict[Any, Point] = {}
    dead = (
        vm.state in (VmState.DESTROYED, VmState.DECOMMISSIONING)
        or chain.state in (ChainState.FAILED, ChainState.PRUNED)
        or chain.pruned_at is not None  # being pruned
        or chain.boot_counter is None
    )
    klass = (
        PointClass.CURRENT_BOOT
        if _chain_is_current_boot(chain, policy, epoch_start)
        else PointClass.ROLLBACK
    )
    prefix: list[BackupRun] = []
    broken = dead
    for run in runs:
        if run.status != RunStatus.DONE:
            points[run.pk] = Point(run=run, klass=PointClass.UNAVAILABLE, runs=())
            continue
        if not broken:
            if not prefix:
                broken = run.kind != BackupKind.FULL
            else:
                broken = (
                    run.kind != BackupKind.INCREMENTAL
                    or run.parent_run_id != prefix[-1].run_id
                )
        if broken:
            points[run.pk] = Point(run=run, klass=PointClass.UNAVAILABLE, runs=())
            continue
        prefix.append(run)
        points[run.pk] = Point(run=run, klass=klass, runs=tuple(prefix))
    return points


def classify_run(vm: Vm, run: BackupRun) -> Point:
    """The restore point `run` of `vm` is (`PointClass`)."""
    if run.vm_id != vm.pk:
        return Point(run=run, klass=PointClass.UNAVAILABLE, runs=())
    chain = run.chain
    runs = list(chain.runs.order_by("seq"))
    policy = BackupPolicy.objects.filter(vm=vm).first()
    points = chain_points(vm, chain, runs, policy=policy, epoch_start=boot_epoch_start(vm))
    return points.get(run.pk) or Point(run=run, klass=PointClass.UNAVAILABLE, runs=())


@dataclass(frozen=True)
class RestorePoint:
    """The newest restorable state: a chain's full plus every DONE
    incremental of it, in `seq` order. Restoring means applying `runs` in
    order and restoring the LAST run's state disk."""

    chain: BackupChain
    runs: list[BackupRun]

    @property
    def latest(self) -> BackupRun:
        return self.runs[-1]


def restore_point(vm: Vm, policy: BackupPolicy | None = None) -> RestorePoint | None:
    """The VM's newest restorable point, or None.

    Restorable ⇔ taken at the guest's CURRENT boot (`PointClass`): the
    chain's boot counter equals the counter the miner last reported for the
    VM, and the chain began after the VM's last completed move (a move
    boots the guest anew). A reboot moves the counter forward and every
    earlier chain drops out of here until the post-boot full lands.

    "Current" is as fresh as the last miner reading (at most one probe
    interval old). A lying miner can only make a restore fail closed: the
    KBS refuses a counter that is not `stored + 1` before the commit
    point, and the restore then reverts."""
    if vm.state in (VmState.DESTROYED, VmState.DECOMMISSIONING):
        # §24 erases the VM's key: its backups can never be decrypted.
        return None
    if policy is None:
        policy = BackupPolicy.objects.filter(vm=vm).first()
    if policy is None or policy.observed_boot_counter is None:
        return None
    epoch_start = boot_epoch_start(vm)
    for chain in BackupChain.objects.filter(
        vm=vm,
        state__in=[ChainState.OPEN, ChainState.CLOSED],
        boot_counter=policy.observed_boot_counter,
    ).order_by("-created_at"):
        if not _chain_is_current_boot(chain, policy, epoch_start):
            continue
        runs = list(chain.runs.order_by("seq"))
        points = [
            p
            for p in chain_points(vm, chain, runs, policy=policy, epoch_start=epoch_start).values()
            if p.klass == PointClass.CURRENT_BOOT
        ]
        if not points:
            continue
        newest = max(points, key=lambda p: p.run.seq)
        return RestorePoint(chain=chain, runs=list(newest.runs))
    return None


#: Throughput assumed for a destination with no measured full backup.
DEFAULT_RESTORE_THROUGHPUT_BPS = 100 * 10**6
#: Recent full backups a destination's throughput is measured over.
_THROUGHPUT_SAMPLE = 5


def dest_throughput_bps(miner_id: str) -> int:
    """Bytes per second the miner moved in its recent full backups (upload
    to the backup store), the best proxy vali has for how fast it downloads
    from it. `VALI_RESTORE_DEFAULT_THROUGHPUT_BPS` (100 MB/s) without a
    sample."""
    default = int(
        getattr(settings, "VALI_RESTORE_DEFAULT_THROUGHPUT_BPS", DEFAULT_RESTORE_THROUGHPUT_BPS)
    )
    rows = list(
        BackupRun.objects.filter(
            miner_id=miner_id,
            kind=BackupKind.FULL,
            status=RunStatus.DONE,
            miner_duration_s__gt=0,
        )
        .order_by("-finished_at")
        .values_list("disk_bytes", "miner_duration_s")[:_THROUGHPUT_SAMPLE]
    )
    total_bytes = sum(int(b) for b, _ in rows)
    total_s = sum(int(s) for _, s in rows)
    if total_bytes <= 0 or total_s <= 0:
        return max(1, default)
    return max(1, total_bytes // total_s)


def point_bytes(runs: tuple[BackupRun, ...] | list[BackupRun]) -> int:
    """Bytes a restore of the point downloads: every disk piece plus the
    last run's state disk."""
    if not runs:
        return 0
    return sum(int(r.disk_bytes) for r in runs) + int(runs[-1].state_bytes)


def restore_eta_s(runs: tuple[BackupRun, ...] | list[BackupRun], *, throughput_bps: int) -> int:
    """Seconds to download `runs` at `throughput_bps` (at least 1)."""
    return max(1, math.ceil(point_bytes(runs) / max(1, throughput_bps)))


#: Presigned restore URLs live at least this long…
RESTORE_TTL_FLOOR_S = 3600
#: …and long enough to fetch the point at this pessimistic rate…
RESTORE_TTL_RATE_BPS = 5 * 10**6
#: …capped here.
RESTORE_TTL_CAP_S = 12 * 3600


def restore_ttl_s(total_bytes: int) -> int:
    """TTL of a restore's presigned GETs: `max(1 h, size / 5 MB/s)`,
    capped at 12 h."""
    return min(
        RESTORE_TTL_CAP_S,
        max(RESTORE_TTL_FLOOR_S, math.ceil(max(0, total_bytes) / RESTORE_TTL_RATE_BPS)),
    )


_RESTORE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _part_plan(run: BackupRun) -> tuple[int, list[str]]:
    """`(part_size, part_sha256_hex)` of a run's disk piece, or `(0, [])`
    (whole-object only) when the recorded parts do not tile it."""
    shas = [str(h) for h in (run.part_sha256_hex or [])]
    size = int(run.part_size or 0)
    if (
        size <= 0
        or not shas
        or len(shas) != math.ceil(int(run.disk_bytes) / size)
        or not all(_SHA256_RE.fullmatch(h) for h in shas)
    ):
        return 0, []
    return size, shas


def restore_chain(
    vm: Vm, *, run_id: str, restore_id: str, allow_rollback: bool = False
) -> dict[str, Any]:
    """The miner-agent's `RestoreChain` for restoring `vm` to run `run_id`:
    the chain's full, every incremental up to and including that run, and
    that run's state disk. Each piece carries its multipart plan
    (`part_size`, `part_sha256_hex`) so the destination can fetch it in
    verified ranges. `restore_id` (32 lower hex) keys the destination's
    staging directory.

    Raises `BackupError("point-not-restorable")` unless the run is a
    restorable point, `("rollback-unsupported")` for a point of an earlier
    boot — unless `allow_rollback` (a restore job authorized as a rollback)
    and the point is `rollback_ready`. The URLs are short-lived read
    capabilities (`restore_ttl_s`) — hand them to the order, never log or store them."""
    if not _RESTORE_ID_RE.fullmatch(restore_id):
        raise ValueError("restore_id must be 32 lower-case hex characters")
    try:
        pk = uuid.UUID(hex=run_id)
    except (TypeError, ValueError) as exc:
        raise BackupError("point-not-restorable", "unknown backup run") from exc
    run = BackupRun.objects.filter(pk=pk, vm=vm).select_related("chain").first()
    if run is None:
        raise BackupError("point-not-restorable", "unknown backup run")
    point = classify_run(vm, run)
    if point.klass == PointClass.ROLLBACK and not (allow_rollback and point.rollback_ready):
        raise BackupError(
            "rollback-unsupported", "the point was taken at an earlier boot of the vm"
        )
    if not point.restorable:
        raise BackupError("point-not-restorable", "the run is not a restorable point")
    client = backup_s3_client()
    bucket = _bucket()
    ttl = restore_ttl_s(point_bytes(point.runs))

    def piece(
        key: str, sha256_hex: str, size: int, part_size: int, part_shas: list[str]
    ) -> dict[str, Any]:
        url = client.presign_get(bucket=bucket, key=key, ttl_seconds=ttl).url
        return {
            "url": url,
            "sha256_hex": sha256_hex,
            "size": int(size),
            "part_size": int(part_size),
            "part_sha256_hex": list(part_shas),
        }

    def disk(r: BackupRun) -> dict[str, Any]:
        part_size, shas = _part_plan(r)
        return piece(r.disk_key, r.disk_sha256_hex, r.disk_bytes, part_size, shas)

    full, *incrementals = point.runs
    latest = point.runs[-1]
    return {
        "restore_id": restore_id,
        "full": disk(full),
        "incrementals": [disk(r) for r in incrementals],
        "state": piece(latest.state_key, latest.state_sha256_hex, latest.state_bytes, 0, []),
    }


# ─── backup state (VM wire shape) ────────────────────────────────────


class BackupState:
    #: No enabled policy.
    DISABLED = "disabled"
    #: Enabled; no run has completed yet.
    PENDING = "pending"
    #: A restore point exists and is no older than `fresh_for` (one
    #: interval plus two hours), or the run replacing it is in flight: a
    #: full of a large disk can take longer than the slack.
    OK = "ok"
    #: Enabled, but no restore point (e.g. the guest rebooted and the new
    #: full has not landed) or the newest one is too old.
    STALE = "stale"


def backup_state(vm: Vm, policy: BackupPolicy | None, *, now: datetime | None = None) -> str:
    if policy is None or not policy.enabled:
        return BackupState.DISABLED
    now = now or timezone.now()
    point = restore_point(vm, policy)
    if point is None:
        if not BackupRun.objects.filter(vm=vm, status=RunStatus.DONE).exists():
            return BackupState.PENDING
        return BackupState.STALE
    finished = point.latest.finished_at or point.latest.created_at
    if now - finished <= fresh_for(policy):
        return BackupState.OK
    # A run that never concludes times out and fails, so this cannot hide
    # a stuck backup for longer than the run timeout.
    if BackupRun.objects.filter(vm=vm, status__in=ACTIVE_RUN_STATUSES).exists():
        return BackupState.OK
    return BackupState.STALE


def fresh_for(policy: BackupPolicy) -> timedelta:
    """How old the newest restore point may be before it is late: one
    interval, plus two hours for the run to start and land (a full of a
    large disk takes the better part of an hour)."""
    return timedelta(seconds=policy.interval_s + 2 * 3600)


def backup_state_by_vm(vms: list[Vm]) -> dict[Any, str]:
    """`{vm pk: backup_state}` for a page of VMs. VMs without an enabled
    policy cost nothing beyond the one policy query."""
    policies = {
        p.vm_id: p for p in BackupPolicy.objects.filter(vm__in=[v.pk for v in vms], enabled=True)
    }
    now = timezone.now()
    return {
        vm.pk: backup_state(vm, policies.get(vm.pk), now=now)
        if vm.pk in policies
        else BackupState.DISABLED
        for vm in vms
    }


# ─── the tick ────────────────────────────────────────────────────────


@dataclass
class BackupTickReport:
    started: int = 0
    completed: int = 0
    failed: int = 0
    pruned: int = 0
    probed: int = 0
    janitor_aborted: int = 0
    janitor_deleted: int = 0
    errors: list[str] = field(default_factory=list)


def tick(*, now: datetime | None = None) -> BackupTickReport:
    """One pass: follow in-flight runs, start the runs that are due, prune.

    Inert unless `VALI_BACKUP_ENABLED`. Each VM is handled on its own — one
    VM's failure is logged and never stops the others."""
    report = BackupTickReport()
    if not enabled():
        return report
    now = now or timezone.now()
    try:
        ensure_bucket(now=now)
    except BackupError as exc:
        log.error("backup: %s — no backup work this tick", exc.detail)
        report.errors.append(exc.code)
        return report
    for run in BackupRun.objects.filter(status__in=ACTIVE_RUN_STATUSES).select_related(
        "chain", "vm"
    ):
        try:
            _advance_run(run, now, report)
        except Exception as exc:  # noqa: BLE001 — one run must not stop the tick.
            log.exception("backup: run %s: unhandled error", run.run_id)
            report.errors.append(f"run {run.run_id}: {type(exc).__name__}")
    for policy in BackupPolicy.objects.filter(enabled=True).select_related("vm"):
        try:
            _maybe_start(policy, now, report)
        except Exception as exc:  # noqa: BLE001
            log.exception("backup: vm %s: unhandled error", policy.vm.vm_id)
            report.errors.append(f"vm {policy.vm.vm_id}: {type(exc).__name__}")
    try:
        report.pruned = prune(now=now)
    except Exception as exc:  # noqa: BLE001
        log.exception("backup: prune: unhandled error")
        report.errors.append(f"prune: {type(exc).__name__}")
    try:
        from .janitor import sweep

        swept = sweep(now=now)
        report.janitor_aborted, report.janitor_deleted = swept.aborted, swept.deleted
    except Exception as exc:  # noqa: BLE001
        log.exception("backup: janitor: unhandled error")
        report.errors.append(f"janitor: {type(exc).__name__}")
    return report


def _open_chain(vm: Vm) -> BackupChain | None:
    """The VM's newest open chain whose full is done."""
    return (
        BackupChain.objects.filter(vm=vm, state=ChainState.OPEN, boot_counter__isnull=False)
        .order_by("-created_at")
        .first()
    )


def _maybe_start(policy: BackupPolicy, now: datetime, report: BackupTickReport) -> None:
    vm = policy.vm
    if vm.state == VmState.DESTROYED:
        # Nothing left to back up; `prune` removes its chains.
        policy.enabled = False
        policy.disabled_at = now
        policy.save(update_fields=["enabled", "disabled_at", "updated_at"])
        return
    if vm.state != VmState.ACTIVE or vm.power_state != VmPowerState.RUNNING or not vm.host:
        return
    if BackupRun.objects.filter(vm=vm, status__in=ACTIVE_RUN_STATUSES).exists():
        return
    if _orchestration_job_in_flight(vm):
        # A restore stages from, then replaces, this disk; a migration moves
        # it. Backups resume once the job is over.
        return
    if _probe_if_due(policy, now):
        report.probed += 1
    kind = _next_kind(policy)
    if not _is_due(policy, now):
        return
    if _start_run(policy, kind, now):
        report.started += 1


def _orchestration_job_in_flight(vm: Vm) -> bool:
    from apps.orchestration.service import _has_active_job

    return _has_active_job(vm)


def _probe_if_due(policy: BackupPolicy, now: datetime) -> bool:
    """Read the live boot counter + point bitmaps from the VM's miner at
    most every `VALI_BACKUP_PROBE_INTERVAL_S`. Returns whether it probed."""
    if policy.last_probe_at is not None and now - policy.last_probe_at < _probe_interval():
        return False
    vm = policy.vm
    policy.last_probe_at = now
    try:
        status = _poll(vm.vm_id, vm.host)
    except (effects.EffectError, ValueError) as exc:
        log.warning("backup: vm=%s probe failed: %s", vm.vm_id, exc)
        status = None
    if status is not None:
        _observe(policy, status, now)
    policy.save()
    return True


def _note_boot_counter(policy: BackupPolicy, boot_counter: int, now: datetime) -> bool:
    """Fold a boot counter the miner read LIVE into the policy (not saved
    here). The counter only moves forward: a higher one is a new boot —
    every earlier chain stops being restorable and a full is required; a
    lower one is never adopted (it would re-qualify an old chain). Returns
    whether the counter went backwards — a miner misreporting."""
    observed = policy.observed_boot_counter
    if observed is not None and boot_counter < observed:
        log.warning(
            "backup: vm=%s miner reported boot counter %d below the %d already seen — "
            "ignored; taking a full",
            policy.vm.vm_id,
            boot_counter,
            observed,
        )
        policy.full_required = True
        return True
    if observed != boot_counter:
        if observed is not None:
            log.info(
                "backup: vm=%s new boot (counter %s → %s) — earlier backups are no "
                "longer restorable; taking a full",
                policy.vm.vm_id,
                observed,
                boot_counter,
            )
        policy.observed_boot_counter = boot_counter
        policy.observed_at = now
        policy.full_required = True
    return False


def _observe(policy: BackupPolicy, status: MinerBackupStatus, now: datetime) -> None:
    """Fold one live miner reading into the policy (not saved here). A new
    boot counter, or the chain's newest point bitmap gone from QEMU (a
    reboot, a QEMU restart), means the next run must be a full."""
    if status.live_boot_counter is not None:
        _note_boot_counter(policy, status.live_boot_counter, now)
    chain = _open_chain(policy.vm)
    parent = _latest_committed(chain) if chain is not None else None
    if (
        chain is None
        or parent is None
        or chain.boot_counter != policy.observed_boot_counter
        or (status.live_points is not None and parent.run_id not in status.live_points)
    ):
        policy.full_required = True


def _latest_committed(chain: BackupChain) -> BackupRun | None:
    """The chain's newest DONE run — the point the next incremental is
    taken from (its `parent_run_id`)."""
    return chain.runs.filter(status=RunStatus.DONE).order_by("-seq").first()


def _next_kind(policy: BackupPolicy) -> str:
    if policy.full_required:
        return BackupKind.FULL
    chain = _open_chain(policy.vm)
    if chain is None or chain.boot_counter != policy.observed_boot_counter:
        return BackupKind.FULL
    if chain.incremental_count >= _max_chain():
        return BackupKind.FULL
    if chain.incremental_bytes * 2 > chain.full_bytes:
        return BackupKind.FULL
    return BackupKind.INCREMENTAL


def _is_due(policy: BackupPolicy, now: datetime) -> bool:
    last = BackupRun.objects.filter(vm=policy.vm).order_by("-created_at").first()
    if last is None:
        return True
    if last.status == RunStatus.FAILED:
        wait = min(_retry_after(), timedelta(seconds=policy.interval_s))
        return now >= (last.finished_at or last.created_at) + wait
    # The last run is DONE. A required full (a new boot, a lost bitmap, a
    # re-enabled policy) is taken now; anything else waits for the interval.
    if policy.full_required:
        return True
    started = last.dispatched_at or last.created_at
    return now >= started + timedelta(seconds=policy.interval_s)


def object_keys(vm_id: str, chain_id: str, seq: int, kind: str) -> tuple[str, str, str]:
    """`(disk, state, manifest)` object keys of one run."""
    if not _VM_ID_RE.fullmatch(vm_id):
        raise ValueError("vm_id is not a valid VM id")
    base = f"backups/{vm_id}/{chain_id}/{seq:04d}"
    disk = f"{base}.full.raw" if kind == BackupKind.FULL else f"{base}.inc.qcow2"
    return disk, f"{base}.state", f"{base}.manifest.json"


def _start_run(policy: BackupPolicy, kind: str, now: datetime) -> bool:
    vm = policy.vm
    try:
        part_size, part_count = plan_parts(source_disk_bytes(vm))
        _bucket()  # refuse early when unconfigured
    except BackupError as exc:
        log.warning("backup: vm=%s cannot be backed up: %s", vm.vm_id, exc.detail)
        return False
    try:
        with transaction.atomic():
            # Decided under the VM's row lock, like every operation that
            # moves the VM (power, §25, §24, resize, guest upgrade): a job
            # that took it since this tick checked is seen here, and none
            # can start between this check and the run's row.
            Vm.objects.select_for_update().filter(pk=vm.pk).first()
            if _orchestration_job_in_flight(vm):
                return False
            # Re-read under a lock: a DELETE of the policy since this tick
            # loaded it must win, or the run would open a chain nothing
            # ever closes.
            if (
                not BackupPolicy.objects.select_for_update()
                .filter(pk=policy.pk, enabled=True)
                .exists()
            ):
                return False
            if kind == BackupKind.FULL:
                chain = BackupChain.objects.create(vm=vm)
            else:
                open_chain = _open_chain(vm)
                if open_chain is None:
                    return False
                chain = BackupChain.objects.select_for_update().get(pk=open_chain.pk)
            seq = chain.next_seq
            chain.next_seq = seq + 1
            chain.save(update_fields=["next_seq"])
            # The committed point this run is taken from (incremental), or
            # the one a full keeps alive so the current chain survives the
            # full failing (full).
            current = chain if kind == BackupKind.INCREMENTAL else _open_chain(vm)
            parent = _latest_committed(current) if current is not None else None
            if kind == BackupKind.INCREMENTAL and parent is None:
                return False
            disk_key, state_key, manifest_key = object_keys(vm.vm_id, chain.chain_id, seq, kind)
            # The row exists BEFORE the upload is opened, so an upload is
            # never opened that nothing can clean up.
            run = BackupRun.objects.create(
                id=uuid.uuid4(),
                vm=vm,
                chain=chain,
                seq=seq,
                kind=kind,
                miner_id=vm.host,
                disk_key=disk_key,
                state_key=state_key,
                manifest_key=manifest_key,
                parent_run_id=parent.run_id if parent is not None else "",
                part_size=part_size,
                part_count=part_count,
            )
    except IntegrityError:
        # Another run of this VM got there first.
        return False
    log.info(
        "backup: vm=%s run=%s %s #%d started on %s (%d × %d MiB parts)",
        vm.vm_id,
        run.run_id,
        kind,
        seq,
        run.miner_id,
        part_count,
        part_size // MIB,
    )
    _dispatch(run, now)
    return True


def staging_state_key(run: BackupRun) -> str:
    """Where the miner PUTs the state disk. vali verifies it and copies it
    to `run.state_key`, which no presigned URL ever pointed at — so the
    miner cannot rewrite a state disk once its run is done. Under its own
    prefix so the janitor (`janitor.py`) can expire strays."""
    return "uploads/" + run.state_key.removeprefix("backups/")


def _ensure_upload(run: BackupRun) -> None:
    """Open the run's multipart upload if it is not open yet."""
    if run.upload_id:
        return
    run.upload_id = backup_s3_client().create_multipart_upload(bucket=_bucket(), key=run.disk_key)
    run.upload_open = True
    run.save(update_fields=["upload_id", "upload_open"])


def _order_payload(run: BackupRun) -> dict[str, Any]:
    """The miner-agent's `BackupOrder`. `chain_id` / `seq` stay vali-side:
    the miner only needs the point to copy from (`parent_run_id`)."""
    client = backup_s3_client()
    bucket = _bucket()
    ttl = int(_run_timeout().total_seconds())
    payload: dict[str, Any] = {
        "vm_id": run.vm.vm_id,
        "run_id": run.run_id,
        "kind": run.kind,
        "part_size": int(run.part_size),
        "disk_part_urls": [
            client.presign_upload_part(
                bucket=bucket,
                key=run.disk_key,
                upload_id=run.upload_id,
                part_number=n,
                ttl_seconds=ttl,
            ).url
            for n in range(1, run.part_count + 1)
        ],
        "state_put_url": client.presign_put(
            bucket=bucket, key=staging_state_key(run), ttl_seconds=ttl
        ).url,
    }
    if run.parent_run_id:
        payload["parent_run_id"] = run.parent_run_id
    return payload


def _dispatch(run: BackupRun, now: datetime) -> None:
    """Send (or re-send) the run's order. The miner dedups on the order id,
    so a re-send after a lost answer is harmless."""
    try:
        _ensure_upload(run)
        effects.dispatch_backup(
            miner_id=run.miner_id, order_id=f"backup-{run.run_id}", payload=_order_payload(run)
        )
    except effects.BackupRejected as exc:
        # A definite refusal: the miner never started. Only a missing parent
        # point forces a full.
        classifier = _reason(exc.classifier, "rejected")
        if classifier == "run-exists":
            # The miner already took this very run (our earlier dispatch was
            # accepted but its answer lost): follow it through the status.
            run.status = RunStatus.RUNNING
            run.dispatched_at = now
            run.save(update_fields=["status", "dispatched_at"])
            return
        _fail(run, classifier, now, full_required=classifier in _FULL_REQUIRED_ERRORS)
        return
    except (effects.EffectError, s3.S3ClientUnavailable, BackupError) as exc:
        log.warning("backup: run=%s dispatch failed (will retry): %s", run.run_id, exc)
        if now - run.created_at > _lost_grace():
            # Even if the order ran, it never consumes its parent's point
            # (the miner copies from the parent bitmap with
            # `bitmap-mode=never`): the next run retries from the same
            # parent, or learns from `bitmap-missing` that it must be a full.
            _fail(run, "dispatch-failed", now, full_required=False)
        return
    run.status = RunStatus.RUNNING
    run.dispatched_at = now
    run.save(update_fields=["status", "dispatched_at"])


def _note_poll_miss(run: BackupRun, exc: Exception) -> None:
    """Count a failed status poll. Isolated misses are expected (a run's own
    QMP setup holds the domain's monitor), so only a streak reaching
    `VALI_BACKUP_POLL_MISS_WARN` is a WARNING. Nothing else changes: the run
    still fails only on its timeout."""
    run.poll_misses += 1
    run.save(update_fields=["poll_misses"])
    threshold = max(1, int(getattr(settings, "VALI_BACKUP_POLL_MISS_WARN", 3)))
    level = logging.WARNING if run.poll_misses >= threshold else logging.INFO
    log.log(
        level,
        "backup: run=%s poll failed (%d in a row): %s",
        run.run_id,
        run.poll_misses,
        exc,
    )


def _advance_run(run: BackupRun, now: datetime, report: BackupTickReport) -> None:
    if run.status == RunStatus.PENDING:
        _dispatch(run, now)
        if run.status == RunStatus.FAILED:
            report.failed += 1
        return
    dispatched = run.dispatched_at or run.created_at
    timed_out = now - dispatched > _run_timeout()
    try:
        status = _poll(run.vm.vm_id, run.miner_id)
    except (effects.EffectError, ValueError) as exc:
        _note_poll_miss(run, exc)
        if timed_out:
            _fail(run, "timeout", now, full_required=False)
            report.failed += 1
        return
    if run.poll_misses:
        run.poll_misses = 0
        run.save(update_fields=["poll_misses"])
    if (
        status is not None
        and run.miner_id == run.vm.host
        and status.live_boot_counter is not None
        and _note_live_counter(run.vm, status.live_boot_counter, now)
    ):
        # The LIVE counter, not only the run's: a reboot during the run
        # must stop an older chain from being offered at once. A counter
        # going BACKWARDS is a miner misreporting — nothing it says about
        # this run is taken.
        _fail(run, "boot-counter-regressed", now, full_required=True)
        report.failed += 1
        return
    got = status.run if status is not None else None
    if got is None or got.run_id != run.run_id:
        # The miner does not know this run (agent restart, or the VM left
        # that host). The parent point is untouched either way; if it is
        # gone, the next incremental is refused `bitmap-missing`.
        if now - dispatched > _lost_grace():
            _fail(run, "lost", now, full_required=False)
            report.failed += 1
        return
    if got.status == "running":
        if timed_out:
            _fail(run, "timeout", now, full_required=False)
            report.failed += 1
        return
    if got.status == "failed":
        reason = _reason(got.error, "miner-failed")
        _fail(run, reason, now, full_required=reason in _FULL_REQUIRED_ERRORS)
        report.failed += 1
        return
    # Finalising talks only to the store, not to the miner: a store outage
    # there gets a second timeout's worth of retries before the run is
    # given up, rather than discarding a backup that may be complete.
    finalise_expired = now - dispatched > 2 * _run_timeout()
    if _complete(run, got, now, timed_out=finalise_expired):
        report.completed += 1
    elif run.status == RunStatus.FAILED:
        report.failed += 1


def _note_live_counter(vm: Vm, boot_counter: int, now: datetime) -> bool:
    """Fold the live counter of a run's poll. Returns whether it went
    backwards."""
    with transaction.atomic():
        policy = BackupPolicy.objects.select_for_update().filter(vm=vm).first()
        if policy is None:
            return False
        before = (policy.observed_boot_counter, policy.full_required)
        regressed = _note_boot_counter(policy, boot_counter, now)
        if (policy.observed_boot_counter, policy.full_required) != before:
            policy.save()
        return regressed


def _validate_done(run: BackupRun, got: RunReport) -> str:
    """Empty when the miner's `done` report is consistent with the order
    vali sent; else the static reason the run fails with."""
    if got.kind != run.kind:
        return "report-kind-mismatch"
    if (got.parent_run_id or "") != run.parent_run_id:
        return "report-parent-mismatch"
    disk, state = got.disk, got.state
    if disk is None or state is None:
        return "report-missing-piece"
    if disk.size <= 0:
        return "report-empty-disk"
    used = math.ceil(disk.size / run.part_size)
    if used > run.part_count:
        return "report-too-many-parts"
    if len(disk.parts) != used:
        return "report-part-count-mismatch"
    for i, part in enumerate(disk.parts):
        last = i == used - 1
        if part.part_number != i + 1:
            return "report-part-numbering"
        if (not last and part.size != run.part_size) or not 0 < part.size <= run.part_size:
            return "report-part-size"
        if not part.etag or len(part.etag) > 256:
            return "report-bad-etag"
        if not _SHA256_RE.fullmatch(part.sha256_hex):
            return "report-bad-sha256"
    if sum(p.size for p in disk.parts) != disk.size:
        return "report-part-size"
    if not _SHA256_RE.fullmatch(disk.sha256_hex):
        return "report-bad-sha256"
    if state.size != STATE_DISK_BYTES or not _SHA256_RE.fullmatch(state.sha256_hex):
        return "report-bad-state"
    if got.boot_counter is None or got.boot_counter < 1:
        # No committed counter ⇒ nothing the KBS would ever accept.
        return "report-bad-boot-counter"
    if run.kind == BackupKind.INCREMENTAL and got.boot_counter != run.chain.boot_counter:
        # The guest rebooted under the chain: this incremental belongs to
        # no restorable chain.
        return "boot-changed"
    if run.kind == BackupKind.FULL:
        try:
            if disk.size != source_disk_bytes(run.vm):
                # A full is the whole overlay, byte for byte.
                return "report-bad-size"
        except BackupError:
            return "report-bad-size"
    return ""


def _manifest(
    run: BackupRun, got: RunReport, now: datetime, checkpoint: dict[str, Any] | None = None
) -> bytes:
    parent = (
        run.chain.runs.filter(status=RunStatus.DONE, seq__lt=run.seq)
        .order_by("-seq")
        .values_list("seq", flat=True)
        .first()
    )
    from apps.orchestration.services import kbs_rollback

    doc = {
        "format": _MANIFEST_FORMAT,
        "vm_id": run.vm.vm_id,
        "chain_id": run.chain.chain_id,
        "run_id": run.run_id,
        "seq": run.seq,
        "parent_seq": parent,
        "kind": run.kind,
        "boot_counter": got.boot_counter,
        "generation": run.vm.generation,
        "miner_id": run.miner_id,
        "disk": {
            "key": run.disk_key,
            "bytes": got.disk.size,
            "sha256_hex": got.disk.sha256_hex,
            "part_size": run.part_size,
            "parts": [
                {"part_number": p.part_number, "size": p.size, "sha256_hex": p.sha256_hex}
                for p in got.disk.parts
            ],
        },
        "state": {
            "key": run.state_key,
            "bytes": got.state.size,
            "sha256_hex": got.state.sha256_hex,
        },
        "parent_run_id": run.parent_run_id or None,
        "completed_at": now.isoformat(),
        # The KBS-signed anti-rollback checkpoint of this run's boot (null
        # when the KBS gave none). The sha256 of these bytes is what an
        # authorized rollback to this point binds to.
        kbs_rollback.MANIFEST_CHECKPOINT_KEY: checkpoint,
    }
    return json.dumps(doc, sort_keys=True, indent=2).encode("utf-8")


#: Why a checkpoint was not taken, already logged once by this process.
_CHECKPOINT_LOGGED: set[str] = set()


def _log_once(key: str, level: int, msg: str, *args: Any) -> None:
    if key in _CHECKPOINT_LOGGED:
        log.debug(msg, *args)
        return
    _CHECKPOINT_LOGGED.add(key)
    log.log(level, msg, *args)


def rollback_checkpoint(vm_id: str, *, boot_counter: int | None) -> dict[str, Any] | None:
    """The KBS's signed rollback checkpoint for a run that just completed
    at `boot_counter`, in the shape stored on the run and in its manifest —
    or None. NEVER raises: a missing checkpoint only means the run can
    never be restored as a rollback, it never costs the backup.

    Kept only when the KBS's stored counter IS the run's own: the guest
    rebooted between the snapshot and now ⇒ the checkpoint describes
    another boot ⇒ dropped. A KBS without the route (or with no row / no
    counter for the VM) is logged once per process, not per run."""
    from apps.orchestration.services import kbs_rollback

    try:
        cp = kbs_rollback.fetch_checkpoint(vm_id)
    except effects.KbsRouteMissing:
        _log_once(
            "route-missing",
            logging.INFO,
            "backup: the KBS serves no rollback-checkpoint route — runs are stored "
            "without a checkpoint (not rollback-restorable)",
        )
        return None
    except kbs_rollback.RollbackRefused as exc:
        _log_once(
            f"refused:{exc.reason}",
            logging.INFO,
            "backup: the KBS gives no rollback checkpoint (%s), e.g. for vm=%s",
            exc.reason,
            vm_id,
        )
        return None
    except kbs_rollback.CheckpointMalformed as exc:
        # vali and the KBS disagree on the checkpoint wire (C-4): every run
        # silently losing rollback-restorability is exactly what must be
        # loud. Logged at ERROR on every run until fixed.
        log.error(
            "backup: vm=%s KBS rollback checkpoint REJECTED, not stored (%s) — vali and "
            "the KBS disagree on the checkpoint contract",
            vm_id,
            exc,
        )
        return None
    except effects.EffectError as exc:
        # EffectUnavailable included: an unreachable / unconfigured KBS.
        _log_once(
            f"error:{type(exc).__name__}",
            logging.WARNING,
            "backup: rollback checkpoint unavailable (%s), e.g. for vm=%s",
            exc,
            vm_id,
        )
        return None
    except Exception:  # noqa: BLE001 — the backup must never fail on this
        log.exception("backup: rollback checkpoint for vm=%s failed unexpectedly", vm_id)
        return None
    if cp.volume_stamp <= 0:
        # The KBS never stamped this VM's volume (a pre-stamp guest, or a
        # store wiped by a KBS restart): it refuses to arm such a
        # checkpoint (`checkpoint-unstamped`), so it is not kept.
        _log_once(
            "unstamped",
            logging.INFO,
            "backup: the KBS checkpoint is unstamped (volume_stamp=0), e.g. for vm=%s — "
            "the run is not rollback-restorable",
            vm_id,
        )
        return None
    if boot_counter is None or cp.boot_counter != boot_counter:
        log.warning(
            "backup: vm=%s KBS checkpoint counter %d != the run's %s — the guest "
            "rebooted since the snapshot; no checkpoint kept",
            vm_id,
            cp.boot_counter,
            boot_counter,
        )
        return None
    return cp.wire()


def _complete(run: BackupRun, got: RunReport, now: datetime, *, timed_out: bool) -> bool:
    """Close a run the miner reports done. Returns True once it is DONE; a
    transient store failure leaves it RUNNING for the next tick (until the
    run times out).

    The miner is untrusted, so its report is checked against the order
    first, then against the STORE: the state disk it PUT is read back and
    must match the reported size and sha256 before vali copies it to a key
    no presigned URL ever pointed at; the completed disk object must have
    exactly the reported size. Every step is idempotent, and the row is
    locked for the whole finalisation, so a crash or a second tick in the
    middle converges instead of failing a good run: a `NoSuchUpload` on
    complete is accepted when the object is already there at the right size.
    """
    problem = _validate_done(run, got)
    if problem:
        log.warning("backup: run=%s refused the miner's report: %s", run.run_id, problem)
        _fail(run, problem, now, full_required=True)
        return False
    client = backup_s3_client()
    bucket = _bucket()
    # Outside the row lock: a KBS call. Never fails the run.
    checkpoint = rollback_checkpoint(run.vm.vm_id, boot_counter=got.boot_counter)
    manifest = _manifest(run, got, now, checkpoint)
    with transaction.atomic():
        locked = (
            BackupRun.objects.select_for_update()
            .filter(pk=run.pk, status=RunStatus.RUNNING)
            .first()
        )
        if locked is None:
            return False  # finalised or failed by someone else meanwhile
        try:
            problem = _finalise_objects(client, bucket, run, got, manifest)
        except s3.S3ClientUnavailable as exc:
            log.warning("backup: run=%s finalising the upload failed: %s", run.run_id, exc)
            if timed_out:
                _fail(run, "timeout", now, full_required=True)
            return False
        if problem:
            log.warning("backup: run=%s store disagrees with the report: %s", run.run_id, problem)
            _fail(run, problem, now, full_required=True)
            return False
        run.status = RunStatus.DONE
        run.finished_at = now
        run.upload_open = False
        run.disk_bytes = got.disk.size
        run.disk_sha256_hex = got.disk.sha256_hex
        run.part_etags = [p.etag for p in got.disk.parts]
        run.part_sha256_hex = [p.sha256_hex for p in got.disk.parts]
        run.state_bytes = got.state.size
        run.state_sha256_hex = got.state.sha256_hex
        run.boot_counter = got.boot_counter
        run.bitmap_present = got.bitmap_present
        run.manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        run.manifest_json = manifest.decode("utf-8")
        run.kbs_checkpoint = checkpoint
        if run.dispatched_at is not None:
            run.miner_duration_s = max(0, int((now - run.dispatched_at).total_seconds()))
        run.save()
        chain = BackupChain.objects.select_for_update().get(pk=run.chain_id)
        if run.kind == BackupKind.FULL:
            chain.boot_counter = got.boot_counter
            chain.full_bytes = got.disk.size
            # The new chain supersedes every older open chain of the VM.
            BackupChain.objects.filter(vm=run.vm, state=ChainState.OPEN).exclude(
                pk=chain.pk
            ).update(state=ChainState.CLOSED, closed_at=now)
        else:
            chain.incremental_count += 1
            chain.incremental_bytes += got.disk.size
        chain.save()
        policy = BackupPolicy.objects.select_for_update().filter(vm=run.vm).first()
        if policy is not None:
            regressed = _note_boot_counter(policy, got.boot_counter, now)
            # Clear `full_required` only when this run leaves an incremental
            # possible: the bitmap is intact AND the run belongs to the boot
            # the guest is in now.
            policy.full_required = (
                regressed
                or got.bitmap_present is not True
                or got.boot_counter != policy.observed_boot_counter
            )
            policy.save()
    try:
        client.delete_object(bucket=bucket, key=staging_state_key(run))
    except s3.S3ClientUnavailable as exc:
        log.warning("backup: run=%s staging state not deleted: %s", run.run_id, exc)
    log.info(
        "backup: vm=%s run=%s %s #%d done: %d bytes, boot counter %d",
        run.vm.vm_id,
        run.run_id,
        run.kind,
        run.seq,
        got.disk.size,
        got.boot_counter,
    )
    return True


def _finalise_objects(
    client: s3.HippiusS3Client, bucket: str, run: BackupRun, got: RunReport, manifest: bytes
) -> str:
    """Store-side half of `_complete`. Returns a failure reason, "" when
    the objects are final. Raises `S3ClientUnavailable` on a transient
    store error (the caller retries)."""
    state = client.get_object(
        bucket=bucket, key=run.state_key, max_bytes=STATE_DISK_BYTES
    )  # already promoted by an interrupted earlier pass?
    if state is None:
        try:
            state = client.get_object(
                bucket=bucket, key=staging_state_key(run), max_bytes=STATE_DISK_BYTES
            )
        except s3.S3RequestRejected:
            return "state-mismatch"
        if state is None:
            return "state-missing"
    if len(state) != got.state.size or hashlib.sha256(state).hexdigest() != got.state.sha256_hex:
        return "state-mismatch"
    client.put_object(
        bucket=bucket, key=run.state_key, body=state, content_type="application/octet-stream"
    )
    client.put_object(
        bucket=bucket,
        key=run.manifest_key,
        body=manifest,
        content_type="application/json",
    )
    parts = [s3.CompletedPart(part_number=p.part_number, etag=p.etag) for p in got.disk.parts]
    try:
        client.complete_multipart_upload(
            bucket=bucket, key=run.disk_key, upload_id=run.upload_id, parts=parts
        )
    except s3.S3RequestRejected as exc:
        # Completed by an earlier pass that died before recording it?
        if client.head_object(bucket=bucket, key=run.disk_key) != got.disk.size:
            log.warning("backup: run=%s upload refused by the store: %s", run.run_id, exc)
            return "complete-rejected"
    if client.head_object(bucket=bucket, key=run.disk_key) != got.disk.size:
        return "store-size-mismatch"
    return ""


def _abort_upload(run: BackupRun) -> None:
    """Abort the run's multipart upload if it is open. A store failure is
    logged and left for pruning to retry (`upload_open` stays set)."""
    if not run.upload_id or not run.upload_open:
        return
    try:
        backup_s3_client().abort_multipart_upload(
            bucket=_bucket(), key=run.disk_key, upload_id=run.upload_id
        )
    except (s3.S3ClientUnavailable, BackupError) as exc:
        log.warning("backup: aborting upload of %s failed: %s", run.disk_key, exc)
        return
    run.upload_open = False
    BackupRun.objects.filter(pk=run.pk).update(upload_open=False)


def _mark_chain_failed(chain: BackupChain, now: datetime) -> None:
    BackupChain.objects.filter(pk=chain.pk, state=ChainState.OPEN).update(
        state=ChainState.FAILED, closed_at=now
    )


def _fail(run: BackupRun, reason: str, now: datetime, *, full_required: bool) -> None:
    """Fail a run: abort its upload and, when the dirty bitmap may now miss
    writes, require a full next."""
    _abort_upload(run)
    with transaction.atomic():
        run.status = RunStatus.FAILED
        run.reason = reason[:64]
        run.finished_at = now
        run.save(update_fields=["status", "reason", "finished_at"])
        if run.kind == BackupKind.FULL:
            _mark_chain_failed(run.chain, now)
        if full_required:
            BackupPolicy.objects.filter(vm=run.vm).update(full_required=True)
    log.warning(
        "backup: vm=%s run=%s %s #%d failed: %s",
        run.vm.vm_id,
        run.run_id,
        run.kind,
        run.seq,
        reason,
    )


# ─── pruning ─────────────────────────────────────────────────────────


def _pinned_by_restore(chain: BackupChain) -> bool:
    """A restore job that is not terminal is restoring from this chain."""
    from apps.orchestration.models import TERMINAL_MIGRATION_STATES, MigrationJob

    return (
        MigrationJob.objects.filter(restore_run__chain=chain)
        .exclude(state__in=TERMINAL_MIGRATION_STATES)
        .exists()
    )


def _prunable(chain: BackupChain, policy: BackupPolicy | None, now: datetime) -> bool:
    if chain.runs.filter(status__in=ACTIVE_RUN_STATUSES).exists():
        return False
    if _pinned_by_restore(chain):
        return False
    if chain.vm.state == VmState.DESTROYED:
        # §24 destroyed the VM's key: its backups can never be decrypted.
        return True
    if chain.state == ChainState.FAILED:
        return True
    if chain.state == ChainState.CLOSED:
        retention = policy.retention_days if policy is not None else DEFAULT_RETENTION_DAYS
        return now - (chain.closed_at or chain.created_at) > timedelta(days=retention)
    return False


def prune(*, now: datetime | None = None) -> int:
    """Delete whole chains that can no longer serve: failed ones at once,
    superseded ones after the policy's `retention_days`, all of a destroyed
    VM's. Chains are never pruned partially — an incremental without its
    full is useless. Also retries the abort of any failed run whose upload
    is still open. Returns the number of chains pruned."""
    now = now or timezone.now()
    for run in BackupRun.objects.filter(status=RunStatus.FAILED, upload_open=True):
        _abort_upload(run)
    pruned = 0
    chains = (
        BackupChain.objects.exclude(state=ChainState.PRUNED)
        .filter(~Q(state=ChainState.OPEN) | Q(vm__state=VmState.DESTROYED))
        .select_related("vm")
    )
    for chain in chains:
        policy = BackupPolicy.objects.filter(vm=chain.vm).first()
        if not _prunable(chain, policy, now):
            continue
        if _prune_chain(chain, now):
            pruned += 1
    return pruned


def _prune_chain(chain: BackupChain, now: datetime) -> bool:
    client = backup_s3_client()
    bucket = _bucket()
    with transaction.atomic():
        # Marked under the chain's row lock before anything is deleted, and
        # re-checked against the restore pin there: a restore intake takes
        # the same lock and refuses a marked chain, so a chain is never
        # deleted under a restore that pinned it (`pruned_at` set and the
        # state not yet `pruned` = being pruned; a failed delete is retried).
        locked = BackupChain.objects.select_for_update().filter(pk=chain.pk).first()
        if locked is None or locked.state == ChainState.PRUNED:
            return False
        if _pinned_by_restore(locked):
            return False
        if locked.pruned_at is None:
            locked.pruned_at = now
            locked.save(update_fields=["pruned_at"])
        chain.pruned_at = locked.pruned_at
    try:
        for run in chain.runs.all():
            if run.upload_id and run.upload_open:
                client.abort_multipart_upload(
                    bucket=bucket, key=run.disk_key, upload_id=run.upload_id
                )
                BackupRun.objects.filter(pk=run.pk).update(upload_open=False)
            for key in (run.disk_key, run.state_key, run.manifest_key, staging_state_key(run)):
                client.delete_object(bucket=bucket, key=key)
    except s3.S3ClientUnavailable as exc:
        log.warning("backup: pruning chain %s failed (will retry): %s", chain.chain_id, exc)
        return False
    chain.state = ChainState.PRUNED
    chain.pruned_at = now
    chain.closed_at = chain.closed_at or now
    chain.save(update_fields=["state", "pruned_at", "closed_at"])
    log.info("backup: vm=%s chain %s pruned", chain.vm.vm_id, chain.chain_id)
    return True


# ─── views' data ─────────────────────────────────────────────────────


def policy_view(policy: BackupPolicy) -> dict[str, Any]:
    return {
        "vm_id": policy.vm.vm_id,
        "enabled": policy.enabled,
        "interval_s": policy.interval_s,
        "retention_days": policy.retention_days,
        "failover_mode": policy.failover_mode,
        "created_at": policy.created_at.isoformat(),
        "updated_at": policy.updated_at.isoformat(),
    }


def _point_view(
    point: Point | None, *, throughput_bps: int, rollback_capable: bool | None = None
) -> dict[str, Any]:
    if point is None or point.klass == PointClass.UNAVAILABLE:
        return {"restorable": False, "class": PointClass.UNAVAILABLE, "eta_s": None}
    restorable = point.restorable
    if point.klass == PointClass.ROLLBACK and rollback_capable is not True:
        # Only a KBS that positively says the guest takes a rollback makes
        # a rollback point restorable: `False` — or unknown (`None`: KBS
        # unread, no answer) — is what the intake refuses
        # (`rollback-not-capable`). Still a rollback point.
        restorable = False
    return {
        "restorable": restorable,
        "class": point.klass,
        "eta_s": restore_eta_s(point.runs, throughput_bps=throughput_bps),
    }


def _run_view(
    run: BackupRun,
    point: Point | None = None,
    *,
    throughput_bps: int = 1,
    rollback_capable: bool | None = None,
) -> dict[str, Any]:
    return {
        "point": _point_view(
            point, throughput_bps=throughput_bps, rollback_capable=rollback_capable
        ),
        "run_id": run.run_id,
        "seq": run.seq,
        "kind": run.kind,
        "status": run.status,
        "reason": run.reason,
        "disk_bytes": int(run.disk_bytes),
        "state_bytes": int(run.state_bytes),
        "boot_counter": run.boot_counter,
        "manifest_sha256": run.manifest_sha256 or None,
        "has_checkpoint": checkpoint_of(run) is not None,
        "created_at": run.created_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


def _last_failure(vm: Vm, policy: BackupPolicy | None) -> dict[str, Any] | None:
    """The newest settled run of the VM when it FAILED, else None — and None
    while no policy is enabled.

    Read across every chain, pruned ones included: a failed full fails its
    chain, which is pruned on the next tick, so `chains` alone would lose
    the failure the tenant most needs to hear about (the first full never
    landing). A later DONE run clears it. Independent of `backup_state`: one
    failed incremental shows here while the restore point is still fresh.
    Relies on run rows never being deleted (pruning keeps them)."""
    if policy is None or not policy.enabled:
        return None
    run = (
        BackupRun.objects.filter(vm=vm, status__in=[RunStatus.DONE, RunStatus.FAILED])
        .order_by("-created_at", "-finished_at")
        .first()
    )
    if run is None or run.status != RunStatus.FAILED:
        return None
    return {
        "run_id": run.run_id,
        "kind": run.kind,
        "created_at": run.created_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "reason": run.reason,
    }


def _rollback_capable(vm: Vm) -> bool | None:
    """The KBS's `rollback_capable` for `vm` (cached briefly), None when it
    does not answer — or when rollbacks are off here, or the VM has no host
    any more, where nothing is asked."""
    from apps.orchestration.services import kbs_rollback

    if not rollback_enabled() or vm.state != VmState.ACTIVE:
        return None
    return kbs_rollback.rollback_capable_cached(vm.vm_id)


def backups_view(vm: Vm, *, now: datetime | None = None) -> dict[str, Any]:
    """Everything the layer above needs to show and bill a VM's backups:
    the state, the restore point, every chain not yet pruned with its runs,
    and the bytes stored (DONE runs of unpruned chains)."""
    now = now or timezone.now()
    policy = BackupPolicy.objects.filter(vm=vm).first()
    point = restore_point(vm, policy)
    epoch_start = boot_epoch_start(vm)
    throughput = dest_throughput_bps(vm.host) if vm.host else DEFAULT_RESTORE_THROUGHPUT_BPS
    capable = _rollback_capable(vm)
    chains = []
    stored = 0
    for chain in (
        BackupChain.objects.filter(vm=vm).exclude(state=ChainState.PRUNED).order_by("-created_at")
    ):
        runs = list(chain.runs.order_by("seq"))
        points = chain_points(vm, chain, runs, policy=policy, epoch_start=epoch_start)
        chain_bytes = sum(r.stored_bytes for r in runs if r.status == RunStatus.DONE)
        stored += chain_bytes
        chains.append(
            {
                "chain_id": chain.chain_id,
                "state": chain.state,
                "boot_counter": chain.boot_counter,
                "restorable": point is not None and point.chain.pk == chain.pk,
                "stored_bytes": chain_bytes,
                "created_at": chain.created_at.isoformat(),
                "closed_at": chain.closed_at.isoformat() if chain.closed_at else None,
                "runs": [
                    _run_view(
                        r,
                        points.get(r.pk),
                        throughput_bps=throughput,
                        rollback_capable=capable,
                    )
                    for r in runs
                ],
            }
        )
    return {
        "vm_id": vm.vm_id,
        "rollback_capable": capable,
        "backup_state": backup_state(vm, policy, now=now),
        "policy": policy_view(policy) if policy is not None and policy.enabled else None,
        "restore_point": (
            {
                "chain_id": point.chain.chain_id,
                "run_id": point.latest.run_id,
                "seq": point.latest.seq,
                "boot_counter": point.chain.boot_counter,
                "taken_at": point.latest.created_at.isoformat(),
                "finished_at": (
                    point.latest.finished_at.isoformat() if point.latest.finished_at else None
                ),
            }
            if point is not None
            else None
        ),
        "stored_bytes": stored,
        "chains": chains,
        "last_failure": _last_failure(vm, policy),
    }
