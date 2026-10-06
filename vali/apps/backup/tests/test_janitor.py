"""The bucket janitor (lifecycle rules vali enforces itself) and the
backup-bucket guard."""

from __future__ import annotations

import os
from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.backup import janitor, service
from apps.backup.models import BackupJanitorState, BackupRun, RunStatus
from apps.backup.service import BackupError
from apps.storage import s3

from .conftest import FakeMiner, make_vm

pytestmark = pytest.mark.django_db

BUCKET = "vm-backups"
DAY = timedelta(days=1)


def _stale_upload(mock: s3.MockHippiusS3Client, key: str, age: timedelta) -> str:
    upload_id = mock.create_multipart_upload(bucket=BUCKET, key=key)
    mock.initiated[upload_id] = timezone.now() - age
    return upload_id


def _staged(mock: s3.MockHippiusS3Client, key: str, age: timedelta) -> None:
    mock.put_object(bucket=BUCKET, key=key, body=b"x", content_type="x")
    mock.modified[(BUCKET, key)] = timezone.now() - age


# ── multipart uploads ─────────────────────────────────────────────────


def test_stale_orphan_uploads_are_aborted_young_ones_kept(
    mock_s3: s3.MockHippiusS3Client,
) -> None:
    old = _stale_upload(mock_s3, "backups/vm-1/c/0000.full.raw", 3 * DAY)
    young = _stale_upload(mock_s3, "backups/vm-1/c/0001.inc.qcow2", DAY)
    report = janitor.sweep()
    assert report.aborted == 1
    assert old in mock_s3.aborted and young not in mock_s3.aborted


def test_an_active_runs_upload_is_never_aborted(
    fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    service.put_policy(make_vm(), interval_s=3600)
    service.tick()
    run = BackupRun.objects.get()
    assert run.status == RunStatus.RUNNING
    mock_s3.initiated[run.upload_id] = timezone.now() - 10 * DAY
    assert janitor.sweep().aborted == 0
    assert run.upload_id not in mock_s3.aborted


def test_a_failed_runs_leftover_upload_is_aborted_and_recorded_closed(
    fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    service.put_policy(make_vm(), interval_s=3600)
    service.tick()
    run = BackupRun.objects.get()

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("abort failed")

    real = mock_s3.abort_multipart_upload
    monkeypatch.setattr(mock_s3, "abort_multipart_upload", down)
    service._fail(run, "qmp-failed", timezone.now(), full_required=False)
    run.refresh_from_db()
    assert run.status == RunStatus.FAILED and run.upload_open
    monkeypatch.setattr(mock_s3, "abort_multipart_upload", real)
    mock_s3.initiated[run.upload_id] = timezone.now() - 3 * DAY
    # The tick above already ran a sweep; the next one is due an interval on.
    assert janitor.sweep(now=timezone.now() + timedelta(hours=2)).aborted == 1
    run.refresh_from_db()
    assert not run.upload_open


def test_the_sweep_is_bounded_and_resumes(
    mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_JANITOR_BATCH", 2)
    ids = [_stale_upload(mock_s3, f"backups/vm-1/c/{i:04d}.inc.qcow2", 3 * DAY) for i in range(5)]
    now = timezone.now()
    assert [janitor.sweep(now=now).aborted for _ in range(3)] == [2, 2, 1]
    assert set(ids) <= mock_s3.aborted
    state = BackupJanitorState.objects.get()
    assert state.mpu_marker is None and state.mpu_sweep_finished_at == now

    # Finished: nothing new until the interval has passed.
    late = _stale_upload(mock_s3, "backups/vm-2/c/0000.full.raw", 3 * DAY)
    assert janitor.sweep(now=now + timedelta(minutes=30)).aborted == 0
    assert janitor.sweep(now=now + timedelta(hours=1)).aborted == 1
    assert late in mock_s3.aborted


def test_a_store_failure_keeps_the_marker(
    mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_JANITOR_BATCH", 1)
    for i in range(3):
        _stale_upload(mock_s3, f"backups/vm-1/c/{i:04d}.inc.qcow2", 3 * DAY)
    janitor.sweep()
    marker = BackupJanitorState.objects.get().mpu_marker
    assert marker is not None

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("list failed")

    monkeypatch.setattr(mock_s3, "list_multipart_uploads", down)
    now = timezone.now()
    assert janitor.sweep(now=now).aborted == 0
    assert BackupJanitorState.objects.get().mpu_marker == marker
    # Backs off an interval instead of retrying (and logging) every tick,
    # then resumes from the kept marker.
    calls: list[int] = []
    monkeypatch.setattr(mock_s3, "list_multipart_uploads", lambda **kw: calls.append(1) or down())
    janitor.sweep(now=now + timedelta(minutes=5))
    assert calls == []
    monkeypatch.undo()
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", BUCKET)
    monkeypatch.setattr(settings, "VALI_BACKUP_JANITOR_BATCH", 1)
    monkeypatch.setattr(service, "backup_s3_client", lambda: mock_s3)
    assert janitor.sweep(now=now + timedelta(hours=1)).aborted == 1


def test_uploads_outside_backups_are_never_touched(mock_s3: s3.MockHippiusS3Client) -> None:
    other = _stale_upload(mock_s3, "something-else/big.bin", 30 * DAY)
    janitor.sweep()
    assert other not in mock_s3.aborted


def test_max_age_never_drops_below_twice_the_run_timeout(
    mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_MPU_MAX_AGE_S", 60)
    young = _stale_upload(mock_s3, "backups/vm-1/c/0000.full.raw", timedelta(hours=11))
    old = _stale_upload(mock_s3, "backups/vm-1/c/0001.inc.qcow2", timedelta(hours=13))
    janitor.sweep()
    assert young not in mock_s3.aborted and old in mock_s3.aborted


# ── staged state disks ───────────────────────────────────────────────


def test_stale_staging_objects_are_deleted_young_and_active_kept(
    fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    service.put_policy(make_vm(), interval_s=3600)
    service.tick()
    run = BackupRun.objects.get()
    active_key = service.staging_state_key(run)
    _staged(mock_s3, active_key, 10 * DAY)
    _staged(mock_s3, "uploads/vm-9/c/0000.state", 3 * DAY)
    _staged(mock_s3, "uploads/vm-9/c/0001.state", DAY)
    _staged(mock_s3, "backups/vm-9/c/0000.state", 30 * DAY)  # a real backup
    assert janitor.sweep(now=timezone.now() + timedelta(hours=2)).deleted == 1
    assert (BUCKET, "uploads/vm-9/c/0000.state") not in mock_s3.objects
    for kept in (active_key, "uploads/vm-9/c/0001.state", "backups/vm-9/c/0000.state"):
        assert (BUCKET, kept) in mock_s3.objects


def test_the_tick_runs_the_janitor(fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client) -> None:
    old = _stale_upload(mock_s3, "backups/vm-1/c/0000.full.raw", 3 * DAY)
    _staged(mock_s3, "uploads/vm-1/c/0000.state", 3 * DAY)
    report = service.tick()
    assert report.janitor_aborted == 1 and report.janitor_deleted == 1
    assert old in mock_s3.aborted


# ── the backup bucket ────────────────────────────────────────────────


def test_the_bucket_has_no_default() -> None:
    from vali import settings as base

    if "VALI_BACKUP_BUCKET" not in os.environ:
        assert base.VALI_BACKUP_BUCKET == ""
    assert base.VALI_BACKUP_BUCKET != base.VALI_PACKER_IMAGES_BUCKET


@pytest.mark.parametrize("bucket", ["", "  ", "images-public", "migrations"])
def test_an_unset_or_shared_bucket_is_refused(
    bucket: str, monkeypatch: pytest.MonkeyPatch, mock_s3
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", bucket)
    with pytest.raises(BackupError) as exc:
        service.ensure_bucket()
    assert exc.value.code == "backup-unavailable"


def test_an_unreachable_bucket_stops_the_tick_loudly(
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service.put_policy(make_vm(), interval_s=3600)
    service._BUCKET_OK.clear()

    def denied(**_kw: object) -> None:
        raise s3.S3RequestRejected("get_object rejected: AccessDenied")

    monkeypatch.setattr(mock_s3, "get_object", denied)
    errors: list[str] = []
    monkeypatch.setattr(service.log, "error", lambda msg, *a: errors.append(msg % a))
    report = service.tick()
    assert report.errors == ["backup-unavailable"] and report.started == 0
    assert fake_miner.orders == []
    assert any("not reachable" in e and "AccessDenied" in e for e in errors)


def test_a_policy_is_refused_when_the_bucket_is_unreachable(
    root_client: APIClient, mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm()

    def denied(**_kw: object) -> None:
        raise s3.S3RequestRejected("get_object rejected: NoSuchBucket")

    monkeypatch.setattr(mock_s3, "get_object", denied)
    resp = root_client.put("/v1/vm/vm-1/backup-policy", {"interval_s": 3600}, format="json")
    assert resp.status_code == 503 and resp.json()["error"] == "backup-unavailable"


def test_reachability_is_cached_then_rechecked(
    mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    real = mock_s3.get_object

    def counting(**kw: object) -> bytes | None:
        calls.append(1)
        return real(**kw)

    monkeypatch.setattr(mock_s3, "get_object", counting)
    now = timezone.now()
    service.ensure_bucket(now=now)
    service.ensure_bucket(now=now + timedelta(minutes=5))
    assert len(calls) == 1
    service.ensure_bucket(now=now + timedelta(minutes=11))
    assert len(calls) == 2


def test_one_refused_abort_does_not_pin_the_sweep(
    mock_s3: s3.MockHippiusS3Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_JANITOR_BATCH", 2)
    ids = [_stale_upload(mock_s3, f"backups/vm-1/c/{i:04d}.inc.qcow2", 3 * DAY) for i in range(4)]
    real = mock_s3.abort_multipart_upload

    def picky(**kw: object) -> None:
        if kw["upload_id"] == ids[0]:
            raise s3.S3RequestRejected("abort_multipart_upload rejected: AccessDenied")
        real(**kw)

    monkeypatch.setattr(mock_s3, "abort_multipart_upload", picky)
    now = timezone.now()
    assert [janitor.sweep(now=now).aborted for _ in range(2)] == [1, 2]
    assert ids[0] not in mock_s3.aborted and set(ids[1:]) <= mock_s3.aborted
    assert BackupJanitorState.objects.get().mpu_marker is None


# ── the backup bucket's own credentials ──────────────────────────────


def test_the_backup_client_uses_its_own_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never the shared default chain: an explicit key, path-style SigV4."""
    seen: dict[str, object] = {}

    class _Boto:
        def client(self, _svc: str, **kw: object) -> object:
            seen.update(kw)
            return object()

    real_init = s3.BotoHippiusS3Client.__init__

    def init(self: s3.BotoHippiusS3Client, **kw: object) -> None:
        real_init(self, boto3_module=_Boto(), **kw)

    monkeypatch.setattr(s3.BotoHippiusS3Client, "__init__", init)
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_ACCESS_KEY_ID", "hip_backup")
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_SECRET_ACCESS_KEY", "s3cr3t-value")
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_ENDPOINT_URL", "https://s3.hippius.com")
    service._CLIENT_CACHE.clear()
    client = service.backup_s3_client()
    assert isinstance(client, s3.BotoHippiusS3Client)
    assert seen["aws_access_key_id"] == "hip_backup"
    assert seen["aws_secret_access_key"] == "s3cr3t-value"
    assert seen["endpoint_url"] == "https://s3.hippius.com"
    config = seen["config"]
    assert config.signature_version == "s3v4"  # type: ignore[attr-defined]
    assert config.s3 == {"addressing_style": "path"}  # type: ignore[attr-defined]
    assert service.backup_s3_client() is client  # cached
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_SECRET_ACCESS_KEY", "rotated")
    assert service.backup_s3_client() is not client  # rotation rebuilds


@pytest.mark.parametrize(
    "missing",
    [
        "VALI_BACKUP_S3_ACCESS_KEY_ID",
        "VALI_BACKUP_S3_SECRET_ACCESS_KEY",
        "VALI_BACKUP_S3_ENDPOINT_URL",
    ],
)
def test_missing_backup_credentials_are_refused_without_leaking_the_secret(
    missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_ACCESS_KEY_ID", "hip_backup")
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_SECRET_ACCESS_KEY", "s3cr3t-value")
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_ENDPOINT_URL", "https://s3.hippius.com")
    monkeypatch.setattr(settings, missing, "")
    with pytest.raises(BackupError) as exc:
        service.backup_s3_client()
    assert exc.value.code == "backup-unavailable" and missing in exc.value.detail
    assert "s3cr3t-value" not in str(exc.value)


def test_unconfigured_credentials_stop_the_tick(
    fake_miner: FakeMiner, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.backup import service as svc

    monkeypatch.undo()  # drop the mock client the fixtures installed
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", BUCKET)
    monkeypatch.setattr(settings, "VALI_BACKUP_S3_ACCESS_KEY_ID", "")
    svc._BUCKET_OK.clear()
    report = svc.tick()
    assert report.errors == ["backup-unavailable"]
