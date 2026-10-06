"""§25 snapshot as a MULTIPART upload (golden VMs).

vali's operator S3 account refuses any single request over ~10 GiB, and a
golden overlay is 40 GiB: the single PUT failed every golden migration. A
golden VM's snapshot now goes up as presigned parts that vali completes
from the miner's receipts; a legacy VM keeps the single PUT."""

from __future__ import annotations

import pytest

from apps.orchestration import service
from apps.orchestration.models import MigrationJob, MigrationState
from apps.storage import s3

from .conftest import FakeEffects
from .factories import make_launch_record, make_service_client, make_vm
from .test_migration import (  # noqa: F401 — autouse fixture
    _GOLDEN_MEASURED,
    _drive_until,
    _same_gen_miners,
)

pytestmark = pytest.mark.django_db

GIB = 1024**3
PART = 512 * 1024**2  # the store's per-part ceiling


def _golden_migration() -> MigrationJob:
    """A golden `small` VM (40 GiB overlay) whose migration is Uploading."""
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(
        vm, disk_mode="golden_verity_overlay", flavor="small", measured_cmdline=_GOLDEN_MEASURED
    )
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    _drive_until(job, MigrationState.UPLOADING.value)
    job.refresh_from_db()
    return job


def _miner_uploads(fx: FakeEffects, job: MigrationJob, part_bytes: list[int]) -> None:
    """What the source miner does: PUT each part, then report receipts."""
    client = s3.get_s3_client()
    for n, size in enumerate(part_bytes, start=1):
        client.record_part(upload_id=job.snapshot_upload_id, part_number=n, size=size)
    fx.snapshot_disk = {
        "parts": [
            {"part_number": n, "etag": f'"e{n}"', "sha256_hex": "00" * 32, "size": size}
            for n, size in enumerate(part_bytes, start=1)
        ],
        "size": sum(part_bytes),
        "sha256_hex": "11" * 32,
    }


def test_a_golden_snapshot_is_dispatched_as_parts(fx: FakeEffects) -> None:
    job = _golden_migration()
    assert job.snapshot_upload_id, "the upload is opened + recorded before dispatch"
    assert (job.snapshot_part_size, job.snapshot_part_count) == (PART, 81)
    assert [c[0] for c in fx.calls if "snapshot" in c[0]] == ["trigger_multipart_snapshot"]
    part_size, urls = fx.multipart
    assert part_size == PART and len(urls) == 81
    assert "part_number=81" in urls[-1] and job.snapshot_upload_id in urls[0]


def test_the_upload_is_completed_from_the_miners_receipts(fx: FakeEffects) -> None:
    job = _golden_migration()
    fx.snapshot_status = "running"
    _drive_until(job, MigrationState.UPLOADING.value)
    _miner_uploads(fx, job, [PART] * 80)  # the 40 GiB file needs 80 of the 81 parts
    fx.snapshot_status = "done"
    upload_id = job.snapshot_upload_id

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.FENCING.value
    assert job.snapshot_upload_id == "", "closed once completed"
    client = s3.get_s3_client()
    assert client.head_object(bucket=job.snapshot_bucket, key=job.snapshot_key) == 40 * GIB
    assert upload_id in client.completed
    assert (job.snapshot_size, job.snapshot_sha256) == (40 * GIB, "11" * 32)


def test_the_destination_is_told_what_to_verify(fx: FakeEffects) -> None:
    """Live: a GET right after the multipart completion ended cleanly at
    2.5 GiB of 40, and the dest booted it. The dest now gets the source's
    length + sha256 and refuses a download that does not match."""
    job = _golden_migration()
    _miner_uploads(fx, job, [PART] * 80)
    fx.snapshot_status = "done"
    _drive_until(job, MigrationState.DONE.value)
    assert fx.activate_snapshot == (40 * GIB, "11" * 32)


def test_a_receipt_without_a_valid_sha256_fails_closed(fx: FakeEffects) -> None:
    job = _golden_migration()
    _miner_uploads(fx, job, [PART] * 80)
    fx.snapshot_disk["sha256_hex"] = "XYZ"
    fx.snapshot_status = "done"
    service.advance_migration_job(job)
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value


def test_a_failed_miner_upload_fails_the_job_at_once_and_aborts(fx: FakeEffects) -> None:
    """The miner's upload task has ENDED — re-polling for the (now hour-long)
    upload window would only keep the tenant down."""
    job = _golden_migration()
    upload_id = job.snapshot_upload_id
    fx.snapshot_status = "failed"

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert job.failed_from_state == MigrationState.UPLOADING.value
    assert upload_id in s3.get_s3_client().aborted


@pytest.mark.parametrize(
    ("parts", "reported"),
    [
        ([PART] * 39 + [PART // 2] + [PART] * 40, None),  # a short non-last part
        ([PART] * 82, None),  # more parts than were presigned
        ([PART] * 80, 41 * GIB),  # parts do not add up to the object
        ([PART] * 79, None),  # a whole object, but not the whole overlay
    ],
)
def test_receipts_that_do_not_tile_one_object_fail_closed(
    fx: FakeEffects, parts: list[int], reported: int | None
) -> None:
    job = _golden_migration()
    _miner_uploads(fx, job, parts)
    if reported is not None:
        fx.snapshot_disk["size"] = reported
    fx.snapshot_status = "done"

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    client = s3.get_s3_client()
    assert client.head_object(bucket=job.snapshot_bucket, key=job.snapshot_key) is None


def test_a_re_driven_snapshotting_tick_reuses_the_open_upload(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(
        vm, disk_mode="golden_verity_overlay", flavor="small", measured_cmdline=_GOLDEN_MEASURED
    )
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    _drive_until(job, MigrationState.SNAPSHOTTING.value)
    fx.fail.add("trigger_multipart_snapshot")
    service.advance_migration_job(job)  # opens the upload, dispatch fails
    job.refresh_from_db()
    first = job.snapshot_upload_id
    fx.fail.discard("trigger_multipart_snapshot")
    opened = s3.get_s3_client()._upload_seq
    service.advance_migration_job(job)
    job.refresh_from_db()
    assert job.state == MigrationState.UPLOADING.value
    assert job.snapshot_upload_id == first
    assert s3.get_s3_client()._upload_seq == opened, "no second upload is opened"
    assert fx.multipart is not None and first in fx.multipart[1][0]


def test_a_legacy_vm_keeps_the_single_put(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="legacy_luks")
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    _drive_until(job, MigrationState.UPLOADING.value)
    job.refresh_from_db()
    assert job.snapshot_upload_id == ""
    assert [c[0] for c in fx.calls if "snapshot" in c[0]] == ["trigger_snapshot"]


@pytest.mark.parametrize(
    ("disk_gib", "part_size", "count"),
    [
        (40, PART, 81),
        (1280, PART, 2561),  # the largest flavor
    ],
)
def test_the_part_plan(monkeypatch, disk_gib: int, part_size: int, count: int) -> None:
    from apps.backup import service as backup_service

    monkeypatch.setattr(backup_service, "source_disk_bytes", lambda vm: disk_gib * GIB)
    got = service._plan_snapshot_parts(make_vm())
    assert got == (part_size, count)
    assert got[0] * got[1] >= disk_gib * GIB


def test_an_overlay_past_the_multipart_bound_is_refused(monkeypatch) -> None:
    from apps.backup import service as backup_service

    monkeypatch.setattr(backup_service, "source_disk_bytes", lambda vm: 1600 * GIB)
    with pytest.raises(service._StepFailed):
        service._plan_snapshot_parts(make_vm())


def test_a_long_upload_outlives_the_step_timeout(fx: FakeEffects) -> None:
    """40 GiB goes up in minutes to tens of minutes — far past the 5-minute
    step timeout every other migration step keeps."""
    from datetime import timedelta

    from django.utils import timezone

    job = _golden_migration()
    fx.snapshot_status = "running"
    MigrationJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timedelta(minutes=30)
    )
    job.refresh_from_db()

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.UPLOADING.value


def test_a_failure_before_uploading_aborts_the_upload_it_opened(fx: FakeEffects) -> None:
    """The upload is recorded (with its bucket + key) before the dispatch,
    so a snapshot that never gets dispatched still has it aborted."""
    from datetime import timedelta

    from django.utils import timezone

    vm = make_vm(generation=5, host="node-src")
    make_launch_record(
        vm, disk_mode="golden_verity_overlay", flavor="small", measured_cmdline=_GOLDEN_MEASURED
    )
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    _drive_until(job, MigrationState.SNAPSHOTTING.value)
    fx.fail.add("trigger_multipart_snapshot")
    service.advance_migration_job(job)
    job.refresh_from_db()
    upload_id = job.snapshot_upload_id
    assert upload_id and job.snapshot_bucket and job.snapshot_key
    MigrationJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )
    job.refresh_from_db()

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert upload_id in s3.get_s3_client().aborted


def test_a_failed_single_put_fails_the_job_at_once_too(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    _drive_until(job, MigrationState.UPLOADING.value)
    fx.snapshot_status = "failed"
    job.refresh_from_db()

    service.advance_migration_job(job)

    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (None, None),  # launched outside the pipeline: single PUT
        ({"disk_mode": "legacy_luks"}, None),
        ({"disk_mode": "golden_verity_overlay"}, 40 * GIB),
        ({"disk_mode": "golden_verity_overlay", "flavor": "no-such"}, service._StepFailed),
    ],
)
def test_the_overlay_size_and_who_keeps_the_single_put(record, expected) -> None:
    vm = make_vm(generation=5, host="node-src")
    if record is not None:
        make_launch_record(vm, **record)
    if expected is service._StepFailed:
        with pytest.raises(service._StepFailed):
            service._golden_overlay_bytes(vm)
    else:
        assert service._golden_overlay_bytes(vm) == expected
