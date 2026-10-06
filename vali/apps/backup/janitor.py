"""The backup bucket janitor: the two lifecycle rules the bucket needs,
enforced by vali because Hippius S3 acknowledges `PutBucketLifecycle`
without persisting or enforcing it.

1. Abort multipart uploads under `backups/` older than
   `VALI_BACKUP_MPU_MAX_AGE_S` that no active run owns. They are what a
   crash between opening an upload and recording it leaves behind (the
   run row is written first, so only a crash or a failed abort can do it),
   and a store keeps their parts — billed — until they are aborted.
2. Delete staged state disks under `uploads/` older than
   `VALI_BACKUP_STAGING_MAX_AGE_S` that no active run owns. A miner can
   PUT to its staging URL until that URL expires, even after its run
   ended.

Work is bounded: each tick handles at most `VALI_BACKUP_JANITOR_BATCH`
items per rule, and a sweep that does not fit resumes from the store's
listing marker on the next tick. A finished sweep starts again after
`VALI_BACKUP_JANITOR_INTERVAL_S`. Nothing outside those two prefixes of
the dedicated backup bucket is ever listed or touched.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

from apps.storage import s3

from . import service
from .models import ACTIVE_RUN_STATUSES, BackupJanitorState, BackupRun

log = logging.getLogger("apps.backup.janitor")

UPLOADS_PREFIX = "backups/"
STAGING_PREFIX = "uploads/"


@dataclass
class JanitorReport:
    aborted: int = 0
    deleted: int = 0


def _setting(name: str, default: int) -> int:
    return int(getattr(settings, name, default))


def _max_age(name: str) -> timedelta:
    # Never younger than twice a run's lifetime (its finalisation deadline):
    # an active run is protected anyway, this is belt and braces.
    floor = 2 * int(getattr(settings, "VALI_BACKUP_RUN_TIMEOUT_S", 6 * 3600))
    return timedelta(seconds=max(_setting(name, 2 * 86400), floor))


def _batch() -> int:
    return min(max(1, _setting("VALI_BACKUP_JANITOR_BATCH", 100)), 1000)


def _interval() -> timedelta:
    return timedelta(seconds=_setting("VALI_BACKUP_JANITOR_INTERVAL_S", 3600))


def _due(finished_at: datetime | None, now: datetime) -> bool:
    """Due unless a sweep finished — or a listing failed — less than
    `VALI_BACKUP_JANITOR_INTERVAL_S` ago. A sweep in progress keeps an old
    `finished_at`, so it goes on every tick."""
    return finished_at is None or now - finished_at >= _interval()


def _marker(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        return None  # a corrupt marker restarts the sweep
    return tuple(raw)


def sweep(*, now: datetime | None = None) -> JanitorReport:
    """One bounded step of each rule. Raises `BackupError` when the bucket
    is not configured; a store error ends this tick's step for that rule
    (the marker is kept, so the sweep resumes where it was)."""
    now = now or timezone.now()
    bucket = service._bucket()
    state, _ = BackupJanitorState.objects.get_or_create(pk=1)
    report = JanitorReport()
    if _due(state.mpu_sweep_finished_at, now):
        try:
            report.aborted = _abort_stale_uploads(bucket, state, now)
        except s3.S3ClientUnavailable as exc:
            # Back off one interval (the marker is kept): a key without
            # listing rights must not log every tick.
            log.warning(
                "backup janitor: listing multipart uploads failed — retrying in %s: %s",
                _interval(),
                exc,
            )
            state.mpu_sweep_finished_at = now
            state.save(update_fields=["mpu_sweep_finished_at"])
    if _due(state.staging_sweep_finished_at, now):
        try:
            report.deleted = _delete_stale_staging(bucket, state, now)
        except s3.S3ClientUnavailable as exc:
            log.warning(
                "backup janitor: listing staged objects failed — retrying in %s: %s",
                _interval(),
                exc,
            )
            state.staging_sweep_finished_at = now
            state.save(update_fields=["staging_sweep_finished_at"])
    return report


def _abort_stale_uploads(bucket: str, state: BackupJanitorState, now: datetime) -> int:
    client = service.backup_s3_client()
    page = client.list_multipart_uploads(
        bucket=bucket, prefix=UPLOADS_PREFIX, marker=_marker(state.mpu_marker), max_items=_batch()
    )
    ids = [u.upload_id for u in page.items]
    active = set(
        BackupRun.objects.filter(status__in=ACTIVE_RUN_STATUSES, upload_id__in=ids).values_list(
            "upload_id", flat=True
        )
    )
    cutoff = now - _max_age("VALI_BACKUP_MPU_MAX_AGE_S")
    aborted = 0
    for upload in page.items:
        if not upload.key.startswith(UPLOADS_PREFIX):
            continue  # a store ignoring the prefix must not widen the sweep
        if upload.upload_id in active or upload.initiated > cutoff:
            continue
        try:
            client.abort_multipart_upload(bucket=bucket, key=upload.key, upload_id=upload.upload_id)
        except s3.S3ClientUnavailable as exc:
            # One upload the store refuses must not pin the sweep: move on,
            # the next sweep retries it.
            log.warning("backup janitor: aborting %s failed: %s", upload.key, exc)
            continue
        BackupRun.objects.filter(upload_id=upload.upload_id).update(upload_open=False)
        log.info(
            "backup janitor: aborted a stale multipart upload of %s (opened %s)",
            upload.key,
            upload.initiated.isoformat(),
        )
        aborted += 1
    state.mpu_marker = list(page.next_marker) if page.next_marker else None
    if page.next_marker is None:
        state.mpu_sweep_finished_at = now
    state.save(update_fields=["mpu_marker", "mpu_sweep_finished_at"])
    return aborted


def _delete_stale_staging(bucket: str, state: BackupJanitorState, now: datetime) -> int:
    client = service.backup_s3_client()
    page = client.list_objects(
        bucket=bucket,
        prefix=STAGING_PREFIX,
        marker=_marker(state.staging_marker),
        max_items=_batch(),
    )
    # Only the runs this page could belong to: the final key of every
    # listed staging key, looked up in one indexed query.
    finals = {
        o.key: "backups/" + o.key.removeprefix(STAGING_PREFIX)
        for o in page.items
        if o.key.startswith(STAGING_PREFIX)
    }
    active = set(
        BackupRun.objects.filter(
            status__in=ACTIVE_RUN_STATUSES, state_key__in=list(finals.values())
        ).values_list("state_key", flat=True)
    )
    cutoff = now - _max_age("VALI_BACKUP_STAGING_MAX_AGE_S")
    deleted = 0
    for obj in page.items:
        if obj.key not in finals:
            continue
        if finals[obj.key] in active or obj.last_modified > cutoff:
            continue
        try:
            client.delete_object(bucket=bucket, key=obj.key)
        except s3.S3ClientUnavailable as exc:
            log.warning("backup janitor: deleting %s failed: %s", obj.key, exc)
            continue
        log.info("backup janitor: deleted a stale staged state disk %s", obj.key)
        deleted += 1
    state.staging_marker = list(page.next_marker) if page.next_marker else None
    if page.next_marker is None:
        state.staging_sweep_finished_at = now
    state.save(update_fields=["staging_marker", "staging_sweep_finished_at"])
    return deleted
