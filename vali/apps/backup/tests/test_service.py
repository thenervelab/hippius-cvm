"""The backup tick, restorability and pruning, against an in-memory miner
and the mock object store."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import pytest
from django.conf import settings
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.utils import timezone

from apps.backup import service
from apps.backup.models import (
    BackupChain,
    BackupKind,
    BackupPolicy,
    BackupRun,
    ChainState,
    RunStatus,
)
from apps.backup.service import BackupError, BackupState
from apps.lifecycle.models import VmPowerState, VmState
from apps.orchestration.services import flavors
from apps.storage import s3

from .conftest import HOST, FakeMiner, make_vm

pytestmark = pytest.mark.django_db

GIB = 1024**3
MIB = 1024**2
HOUR = 3600


class Clock:
    def __init__(self) -> None:
        self.now = timezone.now()

    def advance(self, seconds: float) -> datetime:
        self.now += timedelta(seconds=seconds)
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _policy(vm, interval_s: int = HOUR, **kw) -> BackupPolicy:
    policy, _ = service.put_policy(vm, interval_s=interval_s, **kw)
    return policy


def _tick(clock: Clock) -> service.BackupTickReport:
    report = service.tick(now=clock.now)
    assert report.errors == []
    return report


def _run() -> BackupRun:
    return BackupRun.objects.order_by("-created_at").first()


def _full_done(clock: Clock, miner: FakeMiner, vm_id: str = "vm-1") -> BackupRun:
    """Start and finish the first full of a fresh policy."""
    assert _tick(clock).started == 1
    miner.finish(vm_id, disk_bytes=40 * GIB)
    assert _tick(clock).completed == 1
    run = _run()
    assert run.status == RunStatus.DONE and run.kind == BackupKind.FULL
    return run


def _incremental_done(
    clock: Clock, miner: FakeMiner, *, disk_bytes: int = 100 * MIB, after: int = HOUR
) -> BackupRun:
    clock.advance(after)
    assert _tick(clock).started == 1
    assert miner.last["kind"] == "incremental"
    miner.finish(disk_bytes=disk_bytes)
    assert _tick(clock).completed == 1
    return _run()


# ── part planning ─────────────────────────────────────────────────────


def test_parts_default_to_the_stores_ceiling() -> None:
    import vali.settings as base

    assert base.VALI_BACKUP_MIN_PART_BYTES == 512 * MIB
    # The fewest parts: a small (40 GiB) VM's order stays within 100 URLs.
    part_size, count = service.plan_parts(40 * GIB)
    assert (part_size, count) == (512 * MIB, 82)
    assert service.plan_parts(1280 * GIB) == (512 * MIB, 2601)


def test_a_smaller_floor_grows_to_keep_the_part_list_within_one_order() -> None:
    with override_settings(VALI_BACKUP_MIN_PART_BYTES=256 * MIB):
        assert service.plan_parts(10 * GIB)[0] == 256 * MIB
        part_size, count = service.plan_parts(1280 * GIB)
    assert 256 * MIB < part_size <= 512 * MIB and part_size % MIB == 0
    assert count <= service.MAX_PARTS
    assert part_size * count >= 1280 * GIB + 1280 * GIB // 64 + 64 * MIB


@pytest.mark.parametrize("disk_gib", [40, 80, 160, 500, 1280])
def test_every_part_fits_the_stores_512_mib_ceiling(disk_gib: int) -> None:
    # hippius-s3 refuses a part over 512 MiB (`EntityTooLarge`): a medium
    # (80 GiB) disk used to plan ~833 MiB parts and could never upload.
    part_size, count = service.plan_parts(disk_gib * GIB)
    assert part_size <= 512 * MIB
    assert part_size % MIB == 0
    assert count <= service.MAX_PARTS <= s3.MAX_PART_NUMBER
    # Covers an incremental with every cluster dirty, not just the raw disk.
    assert part_size * count >= disk_gib * GIB + disk_gib * GIB // 64 + 64 * MIB


def test_the_part_ceiling_is_the_stores() -> None:
    assert service.MAX_S3_PART_BYTES == s3.MAX_PART_BYTES == 512 * MIB
    # A floor configured above the ceiling is clamped to it.
    with override_settings(VALI_BACKUP_MIN_PART_BYTES=2 * GIB):
        part_size, _ = service.plan_parts(40 * GIB)
    assert part_size == 512 * MIB


def test_a_disk_beyond_what_one_order_can_carry_is_refused() -> None:
    part_size, count = service.plan_parts(service.max_disk_bytes())
    assert (part_size, count) == (512 * MIB, service.MAX_PARTS)
    with pytest.raises(BackupError) as exc:
        service.plan_parts(service.max_disk_bytes() + GIB)
    assert exc.value.code == "disk-too-large"


# ── policy ────────────────────────────────────────────────────────────


def test_policy_is_refused_while_backups_are_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", False)
    with pytest.raises(BackupError) as exc:
        service.put_policy(make_vm(), interval_s=HOUR)
    assert exc.value.code == "backup-unavailable"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"interval_s": 1800}, "bad-interval"),
        ({"interval_s": True}, "bad-interval"),
        ({"interval_s": HOUR, "retention_days": 0}, "bad-retention"),
        ({"interval_s": HOUR, "retention_days": 366}, "bad-retention"),
        ({"interval_s": HOUR, "retention_days": "7"}, "bad-retention"),
        ({"interval_s": HOUR, "failover_mode": "sometimes"}, "bad-failover-mode"),
    ],
)
def test_policy_fields_are_validated(kwargs: dict, code: str) -> None:
    with pytest.raises(BackupError) as exc:
        service.put_policy(make_vm(), **kwargs)
    assert exc.value.code == code


def test_legacy_vms_cannot_be_backed_up() -> None:
    with pytest.raises(BackupError) as exc:
        service.put_policy(make_vm(golden=False), interval_s=HOUR)
    assert exc.value.code == "not-golden"


def test_a_disk_too_large_for_one_order_is_refused_at_policy_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "MAX_PARTS", 100)  # 512 MiB x 100 < 640 GiB
    with pytest.raises(BackupError) as exc:
        service.put_policy(make_vm(flavor="2xlarge"), interval_s=HOUR)
    assert exc.value.code == "disk-too-large"


@pytest.mark.parametrize("flavor", sorted(flavors._CATALOGUE))
def test_every_published_flavor_fits_one_backup_order(flavor: str) -> None:
    part_size, count = service.plan_parts(flavors.resolve_flavor(flavor).data_disk_size_gb * GIB)
    assert part_size <= s3.MAX_PART_BYTES and count <= service.MAX_PARTS


def test_a_destroyed_vm_cannot_get_a_policy() -> None:
    with pytest.raises(BackupError) as exc:
        service.put_policy(make_vm(state=VmState.DESTROYED), interval_s=HOUR)
    assert exc.value.code == "vm-not-live"


def test_updating_a_policy_keeps_its_chain_and_re_enabling_restarts_it(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    policy, created = service.put_policy(vm, interval_s=HOUR)
    assert created and policy.full_required
    _full_done(clock, fake_miner)

    policy, created = service.put_policy(vm, interval_s=900, retention_days=30)
    assert not created
    assert policy.interval_s == 900 and policy.retention_days == 30
    assert not policy.full_required

    service.disable_policy(vm)
    assert BackupChain.objects.get().state == ChainState.CLOSED
    policy, created = service.put_policy(vm, interval_s=HOUR)
    assert created and policy.enabled and policy.full_required


def test_disabling_without_a_policy_is_refused() -> None:
    with pytest.raises(BackupError) as exc:
        service.disable_policy(make_vm())
    assert exc.value.code == "no-backup-policy"


# ── the tick ─────────────────────────────────────────────────────────


def test_the_tick_is_inert_while_backups_are_disabled(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(make_vm())
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", False)
    assert service.tick(now=clock.now) == service.BackupTickReport()
    assert fake_miner.orders == []


def test_the_first_run_is_a_full_through_presigned_parts(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    _policy(make_vm())
    assert _tick(clock).started == 1

    order = fake_miner.orders[0]
    run = _run()
    assert order["miner_id"] == HOST
    assert order["order_id"] == f"backup-{run.run_id}"
    payload = order["payload"]
    assert payload["kind"] == "full" and run.seq == 0
    assert payload["run_id"] == run.run_id
    assert "parent_run_id" not in payload  # the chain's first full keeps nothing
    assert payload["part_size"] == run.part_size
    assert len(payload["disk_part_urls"]) == run.part_count <= service.MAX_PARTS
    assert all("op=upload_part" in u and run.upload_id in u for u in payload["disk_part_urls"])
    assert "op=put" in payload["state_put_url"]
    assert run.status == RunStatus.RUNNING
    assert run.disk_key == f"backups/vm-1/{run.chain.chain_id}/0000.full.raw"
    assert mock_s3.uploads[run.upload_id] == ("vm-backups", run.disk_key)


def test_a_done_full_completes_the_upload_and_becomes_the_restore_point(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    _policy(vm)
    run = _full_done(clock, fake_miner)

    parts = mock_s3.completed[run.upload_id]
    assert [p.part_number for p in parts] == list(range(1, len(parts) + 1))
    assert parts[0].etag == '"etag-1"'
    assert ("vm-backups", run.manifest_key) in mock_s3.objects
    assert b'"boot_counter": 3' in mock_s3.objects[("vm-backups", run.manifest_key)]

    chain = run.chain
    chain.refresh_from_db()
    assert chain.boot_counter == 3 and chain.full_bytes == 40 * GIB
    policy = BackupPolicy.objects.get()
    assert policy.observed_boot_counter == 3 and not policy.full_required

    point = service.restore_point(vm)
    assert point is not None and point.runs == [run]
    assert service.backup_state(vm, policy, now=clock.now) == BackupState.OK


def test_incrementals_follow_at_the_interval_on_the_same_chain(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)

    clock.advance(HOUR - 60)
    assert _tick(clock).started == 0  # not due yet

    inc = _incremental_done(clock, fake_miner, after=60)
    assert inc.chain_id == full.chain_id and inc.seq == 1
    assert inc.disk_key.endswith("0001.inc.qcow2")
    chain = BackupChain.objects.get()
    assert chain.incremental_count == 1 and chain.incremental_bytes == 100 * MIB
    assert [r.pk for r in service.restore_point(vm).runs] == [full.pk, inc.pk]


def test_the_chain_is_rebased_after_max_chain_incrementals(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_MAX_CHAIN", 2)
    vm = make_vm()
    _policy(vm)
    first = _full_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)

    clock.advance(HOUR)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"
    # The old chain stays the restore point until the new full lands.
    assert service.restore_point(vm).chain.pk == first.chain_id
    fake_miner.finish(disk_bytes=40 * GIB)
    _tick(clock)

    old = BackupChain.objects.get(pk=first.chain_id)
    assert old.state == ChainState.CLOSED
    point = service.restore_point(vm)
    assert point.chain.pk != old.pk and len(point.runs) == 1


def test_the_chain_is_rebased_once_incrementals_outgrow_half_the_full(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    _incremental_done(clock, fake_miner, disk_bytes=21 * GIB)
    clock.advance(HOUR)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"


def test_a_reboot_seen_by_the_probe_makes_old_backups_unrestorable_and_takes_a_full_now(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm, interval_s=86400)
    _full_done(clock, fake_miner)

    fake_miner.boot_counter = 4
    fake_miner.bitmap_present = False
    clock.advance(301)  # past the probe interval, far before the next interval
    report = _tick(clock)
    assert report.probed == 1 and report.started == 1
    assert fake_miner.last["kind"] == "full"
    assert service.restore_point(vm) is None
    policy = BackupPolicy.objects.get()
    assert service.backup_state(vm, policy, now=clock.now) == BackupState.STALE

    fake_miner.finish(disk_bytes=40 * GIB)
    _tick(clock)
    point = service.restore_point(vm)
    assert point is not None and point.chain.boot_counter == 4


def test_the_probe_is_rate_limited(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm(), interval_s=86400)
    _full_done(clock, fake_miner)
    clock.advance(60)
    assert _tick(clock).probed == 0
    clock.advance(300)
    assert _tick(clock).probed == 1


def test_a_vanished_bitmap_forces_a_full_at_once(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm(), interval_s=86400)
    _full_done(clock, fake_miner)
    fake_miner.bitmap_present = False  # e.g. QEMU restarted under an agent re-adopt
    clock.advance(301)
    assert _tick(clock).started == 1
    assert fake_miner.last["kind"] == "full"


def test_a_failed_incremental_is_retried_from_the_same_parent(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    parent = fake_miner.last["parent_run_id"]
    fake_miner.finish(status="failed", reason="upload-failed")
    assert _tick(clock).failed == 1
    failed = BackupRun.objects.get(seq=1)
    assert failed.status == RunStatus.FAILED and failed.reason == "upload-failed"
    assert failed.upload_id in mock_s3.aborted

    clock.advance(899)
    assert _tick(clock).started == 0  # retry-after not elapsed
    clock.advance(1)
    _tick(clock)
    assert fake_miner.last["kind"] == "incremental"
    # The failed run never committed: the retry copies from the same point,
    # so nothing written since is skipped.
    assert fake_miner.last["parent_run_id"] == parent
    assert _run().seq == 2  # a failed run never reuses its key


def test_a_failed_incremental_is_the_last_failure_beside_a_fresh_point(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="upload-failed")
    _tick(clock)
    view = service.backups_view(vm)
    assert view["restore_point"] is not None
    assert view["last_failure"]["kind"] == "incremental"
    assert view["last_failure"]["reason"] == "upload-failed"
    # Nothing is reported once the policy is off.
    service.disable_policy(vm)
    assert service.backups_view(vm)["last_failure"] is None


def test_a_missing_parent_point_requires_a_full(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="bitmap-missing")
    _tick(clock)
    assert BackupPolicy.objects.get().full_required
    clock.advance(900)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"


def test_a_failed_full_fails_its_chain_which_is_pruned(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    _policy(vm)
    _tick(clock)
    fake_miner.finish(status="failed", reason="qmp-failed", bitmap_present=False)
    report = _tick(clock)
    assert report.failed == 1 and report.pruned == 1
    chain = BackupChain.objects.get()
    assert chain.state == ChainState.PRUNED
    assert service.restore_point(vm) is None
    # The failure outlives its pruned chain in the view...
    view = service.backups_view(vm)
    assert view["chains"] == []
    assert view["last_failure"]["reason"] == "qmp-failed"
    assert view["last_failure"]["kind"] == "full"
    # ...until a later run succeeds.
    clock.advance(900)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"
    fake_miner.finish()
    _tick(clock)
    assert service.backups_view(vm)["last_failure"] is None


def test_an_unknown_reason_from_the_miner_is_not_stored_verbatim(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(status="failed", reason="https://s3/secret?sig=x", bitmap_present=False)
    _tick(clock)
    assert _run().reason == "miner-failed"


def test_a_run_the_miner_forgot_is_lost_after_the_grace(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.runs.clear()  # agent restarted
    clock.advance(179)
    assert _tick(clock).failed == 0
    clock.advance(2)
    assert _tick(clock).failed == 1
    lost = BackupRun.objects.get(seq=1)
    assert lost.reason == "lost" and lost.upload_id in mock_s3.aborted
    # The parent point is untouched: the retry is still an incremental.
    assert not BackupPolicy.objects.get().full_required


def test_a_run_past_its_timeout_fails(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm())
    _tick(clock)
    clock.advance(6 * HOUR + 1)
    assert _tick(clock).failed == 1
    assert _run().reason == "timeout"


def test_an_unreachable_miner_times_the_run_out(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.poll_unavailable = True
    clock.advance(HOUR)
    assert _tick(clock).failed == 0
    clock.advance(6 * HOUR)
    assert _tick(clock).failed == 1


def test_isolated_poll_misses_are_info_and_a_streak_warns(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch, settings
) -> None:
    """A miss while the run sets up its QMP job is normal: INFO until
    `VALI_BACKUP_POLL_MISS_WARN` in a row, then WARNING; a good poll resets
    the streak, and none of it fails the run before its timeout."""
    settings.VALI_BACKUP_POLL_MISS_WARN = 3
    _policy(make_vm())
    _tick(clock)
    levels: list[int] = []
    real_log = service.log.log

    def spy(level: int, msg: str, *args: object) -> None:
        if "poll failed" in msg:
            levels.append(level)
        real_log(level, msg, *args)

    monkeypatch.setattr(service.log, "log", spy)

    def misses() -> list[int]:
        return list(levels)

    fake_miner.poll_unavailable = True
    for _ in range(2):
        clock.advance(20)
        assert _tick(clock).failed == 0
    assert misses() == [logging.INFO, logging.INFO]
    assert _run().poll_misses == 2

    fake_miner.poll_unavailable = False
    clock.advance(20)
    _tick(clock)
    assert _run().poll_misses == 0

    levels.clear()
    fake_miner.poll_unavailable = True
    for _ in range(3):
        clock.advance(20)
        assert _tick(clock).failed == 0
    assert misses() == [logging.INFO, logging.INFO, logging.WARNING]
    assert _run().status == RunStatus.RUNNING


def test_a_bitmap_missing_refusal_requires_a_full(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    fake_miner.reject = ("bitmap-missing", 409)
    _tick(clock)
    run = _run()
    assert run.status == RunStatus.FAILED and run.reason == "bitmap-missing"
    assert BackupPolicy.objects.get().full_required


def test_an_unreachable_miner_leaves_the_run_pending_then_fails_it(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    fake_miner.unavailable = True
    _tick(clock)
    run = _run()
    assert run.status == RunStatus.PENDING
    # Retried with the SAME order id (the miner dedups on it).
    fake_miner.unavailable = False
    clock.advance(10)
    _tick(clock)
    run.refresh_from_db()
    assert run.status == RunStatus.RUNNING
    assert fake_miner.orders[-1]["order_id"] == f"backup-{run.run_id}"


def test_a_pending_run_that_never_dispatches_fails(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    fake_miner.unavailable = True
    _tick(clock)
    clock.advance(181)
    assert _tick(clock).failed == 1
    assert _run().reason == "dispatch-failed"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"kind": "incremental"}, "report-kind-mismatch"),
        ({"part_etags": []}, "report-part-count-mismatch"),
        ({"part_sha256_hex": ["zz"]}, "report-bad-sha256"),
        ({"disk_sha256_hex": "A" * 64}, "report-bad-sha256"),
        ({"state_bytes": 4096}, "report-bad-state"),
        ({"part_etags": [""]}, "report-bad-etag"),
        ({"boot_counter": 0}, "report-bad-boot-counter"),
    ],
)
def test_an_inconsistent_done_report_fails_the_run_without_completing(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    overrides: dict,
    reason: str,
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(disk_bytes=100 * MIB, **overrides)
    _tick(clock)
    run = BackupRun.objects.get(seq=0)
    assert run.status == RunStatus.FAILED and run.reason == reason
    assert run.upload_id not in mock_s3.completed
    assert BackupPolicy.objects.get().full_required


def test_a_report_using_more_parts_than_presigned_is_refused(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Few, large parts, so one part too many still parses.
    monkeypatch.setattr(settings, "VALI_BACKUP_MIN_PART_BYTES", 5 * GIB)
    _policy(make_vm())
    _tick(clock)
    order = fake_miner.last
    fake_miner.finish(disk_bytes=order["part_size"] * (len(order["disk_part_urls"]) + 1))
    _tick(clock)
    assert _run().reason == "report-too-many-parts"


def test_an_incremental_across_a_reboot_is_refused(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.boot_counter = 9
    fake_miner.finish()
    _tick(clock)
    assert _run().reason == "boot-changed"


def test_a_store_that_refuses_the_part_list_fails_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish()

    def refuse(**_kw: object) -> None:
        raise s3.S3RequestRejected("complete_multipart_upload rejected: InvalidPart")

    monkeypatch.setattr(mock_s3, "complete_multipart_upload", refuse)
    _tick(clock)
    assert _run().reason == "complete-rejected"


def test_a_store_outage_while_completing_is_retried(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish()
    real = mock_s3.complete_multipart_upload

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("complete_multipart_upload failed: SlowDown")

    monkeypatch.setattr(mock_s3, "complete_multipart_upload", down)
    assert _tick(clock).completed == 0
    assert _run().status == RunStatus.RUNNING
    monkeypatch.setattr(mock_s3, "complete_multipart_upload", real)
    assert _tick(clock).completed == 1


def test_one_run_per_vm_at_a_time(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm())
    _tick(clock)
    clock.advance(2 * HOUR)
    assert _tick(clock).started == 0
    run = _run()
    with pytest.raises(IntegrityError), transaction.atomic():
        BackupRun.objects.create(
            vm=run.vm,
            chain=run.chain,
            seq=99,
            kind=BackupKind.INCREMENTAL,
            miner_id=HOST,
            disk_key="k",
            state_key="k",
            manifest_key="k",
            upload_id="u",
            part_size=1,
            part_count=1,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"power_state": VmPowerState.STOPPED},
        {"state": VmState.MIGRATING, "migration_dest": "miner-b", "new_generation": 2},
        {"host": ""},
    ],
)
def test_vms_that_are_not_running_are_skipped(
    clock: Clock, fake_miner: FakeMiner, mock_s3, change: dict
) -> None:
    vm = make_vm()
    _policy(vm)
    for k, v in change.items():
        setattr(vm, k, v)
    vm.save()
    assert _tick(clock).started == 0


def test_a_destroyed_vm_loses_its_policy_and_its_backups(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    _policy(vm)
    run = _full_done(clock, fake_miner)
    vm.state = VmState.DESTROYED
    vm.save()
    report = _tick(clock)
    assert report.pruned == 1
    assert not BackupPolicy.objects.get().enabled
    assert BackupChain.objects.get().state == ChainState.PRUNED
    for key in (run.disk_key, run.state_key, run.manifest_key):
        assert ("vm-backups", key) not in mock_s3.objects


def test_superseded_chains_are_kept_for_the_retention_then_pruned_whole(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    _policy(vm, retention_days=2)
    first = _full_done(clock, fake_miner)
    inc = _incremental_done(clock, fake_miner)
    service.disable_policy(vm, now=clock.now)

    clock.advance(2 * 86400 - 60)
    assert _tick(clock).pruned == 0
    clock.advance(120)
    assert _tick(clock).pruned == 1
    for run in (first, inc):
        assert ("vm-backups", run.disk_key) not in mock_s3.objects
        assert ("vm-backups", run.manifest_key) not in mock_s3.objects


def test_the_restore_point_chain_is_never_pruned(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm, retention_days=1)
    _full_done(clock, fake_miner)
    clock.advance(30 * 86400)
    fake_miner.bitmap_present = True
    _tick(clock)
    fake_miner.finish()
    _tick(clock)
    assert BackupChain.objects.get().state == ChainState.OPEN
    assert service.restore_point(vm) is not None


def test_a_prune_that_hits_a_store_outage_is_retried(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    vm.state = VmState.DESTROYED
    vm.save()

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("delete_object failed")

    monkeypatch.setattr(mock_s3, "delete_object", down)
    assert _tick(clock).pruned == 0
    assert BackupChain.objects.get().state != ChainState.PRUNED
    monkeypatch.undo()
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", "vm-backups")
    monkeypatch.setattr(s3, "get_s3_client", lambda: mock_s3)
    monkeypatch.setattr(service, "backup_s3_client", lambda: mock_s3)
    assert service.prune(now=clock.now) == 1


# ── restore chain ────────────────────────────────────────────────────


RID = "0123456789abcdef0123456789abcdef"


def test_restore_chain_lists_the_full_then_each_incremental(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    inc = _incremental_done(clock, fake_miner)

    chain = service.restore_chain(vm, run_id=inc.run_id, restore_id=RID)
    assert set(chain) == {"restore_id", "full", "incrementals", "state"}
    assert chain["restore_id"] == RID
    assert chain["full"]["size"] == 40 * GIB
    assert "0000.full.raw" in chain["full"]["url"]
    # Each disk piece carries its multipart plan, for verified ranged GETs.
    assert chain["full"]["part_size"] == full.part_size
    assert chain["full"]["part_sha256_hex"] == full.part_sha256_hex
    assert len(chain["full"]["part_sha256_hex"]) == 80
    [piece] = chain["incrementals"]
    assert piece["size"] == 100 * MIB and "0001.inc.qcow2" in piece["url"]
    assert piece["part_size"] == inc.part_size and piece["part_sha256_hex"] == ["b" * 64]
    assert chain["full"]["sha256_hex"] == piece["sha256_hex"] == "a" * 64
    assert chain["state"] == {
        "url": chain["state"]["url"],
        "sha256_hex": inc.state_sha256_hex,
        "size": 1024 * 1024,
        "part_size": 0,
        "part_sha256_hex": [],
    }
    # The state disk served is vali's verified copy, not the miner's upload.
    assert "backups%2Fvm-1" in chain["state"]["url"] and "0001.state" in chain["state"]["url"]
    assert full.pk != inc.pk
    with pytest.raises(ValueError):
        service.restore_chain(vm, run_id=inc.run_id, restore_id="Bad_Id")


def test_restore_chain_skips_failed_runs(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="upload-failed")
    _tick(clock)
    inc = _incremental_done(clock, fake_miner, after=900)
    chain = service.restore_chain(vm, run_id=inc.run_id, restore_id=RID)
    assert "0000.full.raw" in chain["full"]["url"]
    assert [p["url"].split("?")[0].endswith("0002.inc.qcow2") for p in chain["incrementals"]] == [
        True
    ]


def test_restore_chain_of_an_unknown_run_is_refused(mock_s3) -> None:
    vm = make_vm()
    _policy(vm)
    with pytest.raises(BackupError) as exc:
        service.restore_chain(vm, run_id="f" * 32, restore_id=RID)
    assert exc.value.code == "point-not-restorable"


# ── status parsing ───────────────────────────────────────────────────


def _status(**run_overrides: object) -> dict:
    run = {
        "run_id": "r",
        "parent_run_id": None,
        "kind": "full",
        "status": "done",
        "error": None,
        "bitmap_present": True,
        "boot_counter": 1,
        "virtual_size": 10,
        "disk": {
            "parts": [{"part_number": 1, "etag": '"e"', "sha256_hex": "a" * 64, "size": 10}],
            "size": 10,
            "sha256_hex": "a" * 64,
        },
        "state": {"parts": [], "size": 1, "sha256_hex": "b" * 64},
    }
    run.update(run_overrides)
    return {"vm_id": "vm-1", "live": {"boot_counter": 1, "point_run_ids": ["r"]}, "run": run}


def test_parse_status_accepts_the_miner_shape() -> None:
    parsed = service.parse_status(_status(), vm_id="vm-1")
    assert parsed.run is not None and parsed.run.kind == "full"
    assert parsed.run.disk is not None and parsed.run.disk.parts[0].etag == '"e"'
    assert parsed.live_points == ["r"]
    running = service.parse_status(
        _status(status="running", disk=None, state=None, boot_counter=None, bitmap_present=None),
        vm_id="vm-1",
    )
    assert running.run is not None and running.run.disk is None
    idle = service.parse_status(
        {"vm_id": "v", "live": {"boot_counter": None, "point_run_ids": []}, "run": None},
        vm_id="v",
    )
    assert idle.run is None and idle.live_boot_counter is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "paused"},
        {"kind": "diff"},
        {"boot_counter": "3"},
        {"boot_counter": -1},
        {"bitmap_present": 1},
        {"error": 5},
        {"disk": {"parts": [], "size": True, "sha256_hex": ""}},
        {"disk": {"parts": [{"part_number": 1}] * 101, "size": 1, "sha256_hex": ""}},
        {"disk": {"parts": [1], "size": 1, "sha256_hex": ""}},
    ],
)
def test_parse_status_rejects_off_shape_reports(overrides: dict) -> None:
    with pytest.raises(ValueError):
        service.parse_status(_status(**overrides), vm_id="vm-1")


def test_parse_status_accepts_the_bare_run_status() -> None:
    """Today's miner-agent answers the latest run's `RunStatus` alone."""
    raw = _status()["run"]
    parsed = service.parse_status(raw, vm_id="vm-1")
    assert parsed.run is not None and parsed.run.run_id == "r"
    assert parsed.live_boot_counter is None and parsed.live_points is None
    with pytest.raises(ValueError):
        service.parse_status({**raw, "status": "paused"}, vm_id="vm-1")


def test_a_wrapped_status_about_another_vm_is_refused() -> None:
    with pytest.raises(ValueError):
        service.parse_status(_status(), vm_id="vm-2")


# ── backup state ─────────────────────────────────────────────────────


def test_backup_state_moves_from_pending_to_ok_to_stale(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    assert service.backup_state(vm, None) == BackupState.DISABLED
    policy = _policy(vm)
    assert service.backup_state(vm, policy, now=clock.now) == BackupState.PENDING
    _full_done(clock, fake_miner)
    policy.refresh_from_db()
    assert service.backup_state(vm, policy, now=clock.now) == BackupState.OK
    assert service.backup_state(vm, policy, now=clock.now + timedelta(hours=4)) == (
        BackupState.STALE
    )
    other = make_vm("vm-2")
    states = service.backup_state_by_vm([vm, other])
    assert states == {vm.pk: BackupState.OK, other.pk: BackupState.DISABLED}


def test_a_daily_restore_point_goes_stale_after_26_hours_unless_a_run_is_in_flight(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    policy = _policy(vm)
    _full_done(clock, fake_miner)
    BackupPolicy.objects.filter(pk=policy.pk).update(interval_s=86400)
    policy.refresh_from_db()
    landed = clock.now
    assert service.backup_state(vm, policy, now=landed + timedelta(hours=26)) == BackupState.OK
    late = landed + timedelta(hours=26, seconds=1)
    assert service.backup_state(vm, policy, now=late) == BackupState.STALE
    point = service.restore_point(vm, policy)
    assert point is not None
    BackupRun.objects.create(
        vm=vm,
        chain=point.chain,
        seq=point.chain.next_seq,
        kind=BackupKind.INCREMENTAL,
        status=RunStatus.RUNNING,
        miner_id="m",
        disk_key="d",
        state_key="s-in-flight",
        manifest_key="m",
        part_size=1,
        part_count=1,
    )
    assert service.backup_state(vm, policy, now=late) == BackupState.OK


@pytest.mark.parametrize(
    ("interval_s", "window"),
    [
        (86400, timedelta(hours=26)),
        (21600, timedelta(hours=8)),
        (3600, timedelta(hours=3)),
        (900, timedelta(hours=2, minutes=15)),
    ],
)
def test_a_restore_point_is_fresh_for_one_interval_plus_two_hours(
    interval_s: int, window: timedelta
) -> None:
    assert service.fresh_for(BackupPolicy(interval_s=interval_s)) == window


# ── review regressions ───────────────────────────────────────────────


def test_an_ambiguous_dispatch_failure_retries_from_the_same_parent(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    """An order whose answer was lost may have run — but a run never consumes
    its parent's point, so the retry from that parent misses nothing."""
    _policy(make_vm())
    full = _full_done(clock, fake_miner)
    clock.advance(HOUR)
    fake_miner.unavailable = True
    _tick(clock)
    clock.advance(181)
    _tick(clock)
    assert _run().reason == "dispatch-failed"
    fake_miner.unavailable = False
    clock.advance(900)
    _tick(clock)
    assert fake_miner.last["kind"] == "incremental"
    assert fake_miner.last["parent_run_id"] == full.run_id


def test_an_incremental_always_names_the_newest_committed_parent(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    full = _full_done(clock, fake_miner)
    inc1 = _incremental_done(clock, fake_miner)
    assert inc1.parent_run_id == full.run_id
    inc2 = _incremental_done(clock, fake_miner)
    assert inc2.parent_run_id == inc1.run_id


def test_a_rebase_full_keeps_the_current_chain_point_alive(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_MAX_CHAIN", 1)
    _policy(make_vm())
    _full_done(clock, fake_miner)
    inc = _incremental_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"
    assert fake_miner.last["parent_run_id"] == inc.run_id


def test_the_probe_sees_the_parent_point_gone(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm(), interval_s=86400)
    _full_done(clock, fake_miner)
    fake_miner.points = {"some-other-run"}
    clock.advance(301)
    assert _tick(clock).started == 1
    assert fake_miner.last["kind"] == "full"


def test_a_report_that_does_not_echo_the_parent_is_refused(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(parent_run_id="someone-else")
    _tick(clock)
    assert _run().reason == "report-parent-mismatch"


def test_the_live_counter_seen_during_a_run_retires_the_old_chain_at_once(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)  # incremental in flight
    fake_miner.boot_counter = 4  # the guest rebooted meanwhile
    _tick(clock)
    assert service.restore_point(vm) is None
    assert BackupPolicy.objects.get().observed_boot_counter == 4


def test_a_done_full_from_a_boot_already_superseded_is_not_restorable(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    _tick(clock)
    fake_miner.finish()  # taken at counter 3 …
    fake_miner.boot_counter = 4  # … but the guest is at 4 when vali polls
    fake_miner.runs["vm-1"]["boot_counter"] = 3
    _tick(clock)
    policy = BackupPolicy.objects.get()
    assert policy.observed_boot_counter == 4 and policy.full_required
    assert service.restore_point(vm) is None


def test_a_lower_boot_counter_is_never_adopted(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm, interval_s=86400)
    _full_done(clock, fake_miner)
    fake_miner.boot_counter = 2
    clock.advance(301)
    _tick(clock)
    policy = BackupPolicy.objects.get()
    assert policy.observed_boot_counter == 3
    assert fake_miner.last["kind"] == "full"


def test_a_status_about_another_vm_is_ignored(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish()
    real = fake_miner.poll
    monkeypatch.setattr(
        service.effects,
        "poll_backup_status",
        lambda **kw: {**real(**kw), "vm_id": "vm-other"},
    )
    assert _tick(clock).completed == 0
    assert _run().status == RunStatus.RUNNING


def test_a_missing_state_disk_fails_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(put_state=False)
    _tick(clock)
    run = _run()
    assert run.status == RunStatus.FAILED and run.reason == "state-missing"
    assert run.upload_id in mock_s3.aborted


def test_a_state_disk_that_does_not_match_the_report_fails_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(state_sha256_hex="d" * 64)
    _tick(clock)
    assert _run().reason == "state-mismatch"


def test_parts_never_uploaded_fail_the_run(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(upload=False)
    _tick(clock)
    assert _run().reason == "complete-rejected"


def test_a_disk_object_shorter_than_reported_fails_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    order = fake_miner.last
    fake_miner.finish(disk_bytes=100 * MIB)
    # The miner PUT a truncated last part but reports the full length.
    upload_id = order["disk_part_urls"][0].split("upload_id=")[1].split("&")[0]
    mock_s3.record_part(upload_id=upload_id, part_number=1, size=10)
    _tick(clock)
    assert _run().reason == "store-size-mismatch"
    assert len(service.restore_point(vm).runs) == 1


def test_a_full_that_is_not_the_whole_overlay_is_refused(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish(disk_bytes=39 * GIB)
    _tick(clock)
    assert _run().reason == "report-bad-size"


def test_the_miner_cannot_rewrite_a_state_disk_once_the_run_is_done(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    run = (_policy(make_vm()), _full_done(clock, fake_miner))[1]
    final = mock_s3.objects[("vm-backups", run.state_key)]
    assert final == fake_miner.state_disk()
    staging = service.staging_state_key(run)
    assert staging.startswith("uploads/") and ("vm-backups", staging) not in mock_s3.objects
    # A late PUT through the still-valid URL lands on the staging key only.
    mock_s3.put_object(bucket="vm-backups", key=staging, body=b"evil", content_type="x")
    assert mock_s3.objects[("vm-backups", run.state_key)] == final


def test_finalisation_survives_a_crash_after_the_upload_was_completed(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client
) -> None:
    """vali completed the multipart upload, then died before recording it:
    the retry meets `NoSuchUpload` and must accept the finished object."""
    vm = make_vm()
    _policy(vm)
    _tick(clock)
    got_raw = fake_miner.finish()
    run = _run()
    got = service.parse_status(fake_miner.poll(vm_id="vm-1", miner_id=HOST), vm_id="vm-1").run
    assert got is not None and got.run_id == got_raw["run_id"]
    manifest = service._manifest(run, got, clock.now)
    assert service._finalise_objects(mock_s3, "vm-backups", run, got, manifest) == ""
    assert _tick(clock).completed == 1
    assert _run().status == RunStatus.DONE
    assert service.restore_point(vm) is not None


def test_a_policy_disabled_under_the_tick_starts_nothing(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    policy = _policy(vm)
    stale = BackupPolicy.objects.get(pk=policy.pk)
    service.disable_policy(vm)
    assert service._start_run(stale, BackupKind.FULL, clock.now) is False
    assert not BackupChain.objects.exists() and fake_miner.orders == []


def test_an_abort_that_failed_is_retried_by_pruning(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    real_abort = mock_s3.abort_multipart_upload

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("abort failed")

    monkeypatch.setattr(mock_s3, "abort_multipart_upload", down)
    fake_miner.finish(status="failed", reason="upload-failed", bitmap_present=True)
    _tick(clock)
    failed = BackupRun.objects.get(seq=1)
    assert failed.status == RunStatus.FAILED and failed.upload_open
    monkeypatch.setattr(mock_s3, "abort_multipart_upload", real_abort)
    _tick(clock)
    failed.refresh_from_db()
    assert not failed.upload_open and failed.upload_id in mock_s3.aborted


def test_a_destroyed_vm_offers_no_restore_point(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    vm.state = VmState.DESTROYED
    vm.save()
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", False)  # nothing prunes
    assert service.restore_point(vm) is None
    with pytest.raises(BackupError):
        service.restore_chain(vm, run_id=_run().run_id, restore_id=RID)


def test_max_chain_is_capped_by_what_one_restore_order_carries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_MAX_CHAIN", 10_000)
    assert service._max_chain() == service.MAX_RESTORE_PIECES - 1


def test_a_live_counter_going_backwards_fails_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish()  # the run itself claims counter 3 …
    fake_miner.boot_counter = 2  # … while the live read goes backwards
    fake_miner.runs["vm-1"]["boot_counter"] = 3
    _tick(clock)
    run = _run()
    assert run.status == RunStatus.FAILED and run.reason == "boot-counter-regressed"
    policy = BackupPolicy.objects.get()
    assert policy.observed_boot_counter == 3 and policy.full_required


def test_a_store_outage_while_finalising_outlasts_the_run_timeout(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The miner is done; only the store is down. A backup that may be
    complete is not thrown away at the first timeout."""
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish()
    real = mock_s3.complete_multipart_upload

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("complete_multipart_upload failed: SlowDown")

    monkeypatch.setattr(mock_s3, "complete_multipart_upload", down)
    clock.advance(6 * HOUR + 60)
    _tick(clock)
    assert _run().status == RunStatus.RUNNING
    monkeypatch.setattr(mock_s3, "complete_multipart_upload", real)
    assert _tick(clock).completed == 1


def test_finalising_gives_up_after_twice_the_run_timeout(
    clock: Clock, fake_miner: FakeMiner, mock_s3, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.finish()

    def down(**_kw: object) -> None:
        raise s3.S3ClientUnavailable("complete_multipart_upload failed: SlowDown")

    monkeypatch.setattr(mock_s3, "complete_multipart_upload", down)
    clock.advance(12 * HOUR + 60)
    _tick(clock)
    assert _run().reason == "timeout"


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        (lambda r: r.update(state=None), "report-missing-piece"),
        (lambda r: r["disk"]["parts"][0].update(part_number=2), "report-part-numbering"),
        (lambda r: r["disk"]["parts"][0].update(size=1), "report-part-size"),
        (lambda r: r["disk"].update(size=r["disk"]["size"] + 1), "report-part-size"),
        (lambda r: r.update(boot_counter=None), "report-bad-boot-counter"),
    ],
)
def test_a_done_report_whose_pieces_do_not_add_up_is_refused(
    clock: Clock, fake_miner: FakeMiner, mock_s3, tamper, reason: str
) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    tamper(fake_miner.finish())
    _tick(clock)
    assert _run().reason == reason


def test_a_done_run_without_its_point_requires_a_full(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    first = _run()
    fake_miner.finish(bitmap_present=False)
    _tick(clock)
    first.refresh_from_db()
    assert first.status == RunStatus.DONE
    # It cannot be a parent, so the next run — started at once — is a full.
    assert _run().pk != first.pk and fake_miner.last["kind"] == "full"


# ── today's miner-agent: bare RunStatus, no live reading ─────────────


def test_a_chain_is_built_against_the_bare_status(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    fake_miner.bare = True
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    inc = _incremental_done(clock, fake_miner)
    assert inc.parent_run_id == full.run_id
    assert [r.pk for r in service.restore_point(vm).runs] == [full.pk, inc.pk]


def test_without_a_live_reading_a_reboot_is_learnt_from_the_next_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    fake_miner.bare = True
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    fake_miner.boot_counter = 4
    fake_miner.points.clear()
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="bitmap-missing")
    _tick(clock)
    assert BackupPolicy.objects.get().full_required
    clock.advance(900)
    _tick(clock)
    assert fake_miner.last["kind"] == "full"
    fake_miner.finish()
    _tick(clock)
    assert service.restore_point(vm).chain.boot_counter == 4


def test_state_changed_requires_a_full(clock: Clock, fake_miner: FakeMiner, mock_s3) -> None:
    _policy(make_vm())
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="state-changed")
    _tick(clock)
    assert _run().reason == "state-changed"
    assert BackupPolicy.objects.get().full_required


def test_run_exists_means_the_miner_already_has_the_run(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    fake_miner.unavailable = True
    _tick(clock)  # the order ran on the miner, but its answer was lost
    fake_miner.unavailable = False
    run = _run()
    fake_miner.dispatch(miner_id=HOST, order_id="x", payload=service._order_payload(run))
    fake_miner.reject = ("run-exists", 409)
    clock.advance(10)
    _tick(clock)
    run.refresh_from_db()
    assert run.status == RunStatus.RUNNING
    fake_miner.reject = None
    fake_miner.finish()
    assert _tick(clock).completed == 1


# ── the miner's final status semantics ───────────────────────────────


def test_status_unavailable_is_retried_never_read_as_no_points(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    """A 503 from the probe must not look like "the parent point is gone"."""
    _policy(make_vm())
    _full_done(clock, fake_miner)
    fake_miner.poll_unavailable = True  # the relay's 503 → EffectUnavailable
    clock.advance(301)
    assert _tick(clock).probed == 1
    assert not BackupPolicy.objects.get().full_required
    fake_miner.poll_unavailable = False
    clock.advance(HOUR)
    _tick(clock)
    assert fake_miner.last["kind"] == "incremental"


def test_no_domain_on_the_run_host_loses_the_run_after_the_grace(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    _policy(make_vm())
    _tick(clock)
    fake_miner.unknown.add("vm-1")  # 404 no-domain
    clock.advance(179)
    assert _tick(clock).failed == 0
    clock.advance(2)
    assert _tick(clock).failed == 1
    assert _run().reason == "lost"


def test_a_domain_without_a_run_answers_run_null(
    clock: Clock, fake_miner: FakeMiner, mock_s3
) -> None:
    """200 with run null (agent restarted) is read, and its live points
    still decide whether an incremental can follow."""
    _policy(make_vm())
    full = _full_done(clock, fake_miner)
    fake_miner.runs.clear()
    got = service.parse_status(fake_miner.poll(vm_id="vm-1", miner_id=HOST), vm_id="vm-1")
    assert got.run is None and got.live_points == [full.run_id]
    clock.advance(HOUR)
    _tick(clock)
    assert fake_miner.last["kind"] == "incremental"
