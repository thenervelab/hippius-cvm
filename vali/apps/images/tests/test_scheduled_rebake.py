"""`vali_scheduled_golden_rebake` (F6) — sequencing, no concurrent bakes,
no auto-bless, flag off = no-op, freshness gauges.

The baker is simulated by the injected `sleep`: each call is one poll tick
of a fake worker that finishes the oldest in-flight bake. Asserting inside
that tick is what proves "never two bakes in flight" — it observes the DB
exactly when a real bake Job would be running.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone

from apps.images import rebake
from apps.images.models import GoldenImage
from apps.tenant_bake.models import (
    TenantBake,
    TenantBakeDiskMode,
    TenantBakeState,
    live_in_flight_q,
)

pytestmark = pytest.mark.django_db

IMAGES = ("ubuntu", "debian", "cs10", "fedora")
STAMP = "20261101"


def _bless_all(make_golden_bake) -> dict[str, TenantBake]:
    blessed = {}
    for image in IMAGES:
        bake = make_golden_bake(
            bake_id=f"blessed-{image}",
            vm_id=f"golden-{image}-dp",
            base_image_url=f"https://images.example/{image}-20260801.qcow2",
            base_image_sha256=image[0] * 64,
            s3_output_prefix=f"tenant/golden-{image}-dp/",
            finished_at=timezone.now() - timedelta(days=30),
        )
        GoldenImage.objects.create(
            image_name=image,
            distro=image,
            bake_id=bake.bake_id,
            blessed_at=timezone.now() - timedelta(days=29),
            blessed_by="ops",
        )
        blessed[image] = bake
    return blessed


def _succeed(bake: TenantBake) -> None:
    bake.state = TenantBakeState.SUCCEEDED.value
    bake.kernel_sha256 = "2" * 64
    bake.initrd_sha256 = "3" * 64
    bake.rootfs_img_sha256 = "4" * 64
    bake.rootfs_verity_sha256 = "5" * 64
    bake.verity_root_hash = "6" * 64
    bake.finished_at = timezone.now()
    bake.save()


def _fail(bake: TenantBake) -> None:
    bake.state = TenantBakeState.FAILED.value
    bake.failure_reason = "losetup: device node /dev/loop9 is lost"
    bake.finished_at = timezone.now()
    bake.save()


def _claim(bake: TenantBake) -> None:
    """Stand-in for `spawn_bake_job`: the Job starts and the worker claims
    the row (Queued → Running), as the real entrypoint does."""
    bake.refresh_from_db()
    if bake.state == TenantBakeState.QUEUED.value:
        bake.state = TenantBakeState.RUNNING.value
        bake.started_at = timezone.now()
        bake.save()


@pytest.fixture(autouse=True)
def _fake_k8s(monkeypatch) -> None:
    from apps.tenant_bake import k8s_jobs

    monkeypatch.setattr(k8s_jobs, "spawn_bake_job", _claim)


class FakeWorker:
    """One `sleep` = one poll tick of the cluster:

    1. every bake that was Running at the previous tick finishes (Succeeded,
       or Failed for `fail`; `hold` never finishes);
    2. the REAL `vali_bake_spawn` sweep runs — its serial gate decides what
       starts (`_claim` stands in for the k8s Job).

    Records the peak number of live Running bakes while a re-bake is
    Running (must stay 1) and the vm_id order bakes finished in."""

    def __init__(self, *, fail: set[str] = frozenset(), hold: set[str] = frozenset()) -> None:
        self.fail = fail
        self.hold = hold
        self.peak_in_flight = 0
        self.finished: list[str] = []
        self.ticks = 0
        self._t = 0.0
        self._running: set[str] = set()

    @staticmethod
    def live_in_flight():
        return TenantBake.objects.filter(live_in_flight_q(6 * 3600)).order_by("requested_at")

    def _running_live(self) -> list[TenantBake]:
        return list(self.live_in_flight().filter(state=TenantBakeState.RUNNING.value))

    def sleep(self, _s: float) -> None:
        from apps.tenant_bake.management.commands.vali_bake_spawn import spawn_queued_bakes

        self.ticks += 1
        self._t += _s
        for bake in self._running_live():
            if bake.bake_id in self._running and bake.vm_id not in self.hold:
                (_fail if bake.vm_id in self.fail else _succeed)(bake)
                self.finished.append(bake.vm_id)
        spawn_queued_bakes()
        running = self._running_live()
        self._running = {b.bake_id for b in running}
        if any(b.package_refresh for b in running):
            self.peak_in_flight = max(self.peak_in_flight, len(running))

    def monotonic(self) -> float:
        return self._t


def _timing(worker: FakeWorker, **kw) -> rebake.Timing:
    return rebake.Timing(
        poll_interval_s=kw.get("poll", 30.0),
        idle_timeout_s=kw.get("idle", 600.0),
        bake_timeout_s=kw.get("bake", 600.0),
        orphan_running_after_s=6 * 3600,
        monotonic=worker.monotonic,
        sleep=worker.sleep,
    )


def _rebake_rows() -> list[TenantBake]:
    return list(
        TenantBake.objects.filter(vm_id__contains="-rebake-").order_by("requested_at")
    )


# ── sequencing / no concurrency ──────────────────────────────────────


def test_rebakes_every_image_in_order_one_at_a_time(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    worker = FakeWorker()
    outcome = rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(worker))

    assert outcome.success
    assert worker.peak_in_flight == 1
    assert worker.finished == [f"golden-{i}-rebake-{STAMP}" for i in IMAGES]
    assert [r.state for r in outcome.results] == ["succeeded"] * 4


def test_next_bake_is_not_queued_while_the_previous_is_in_flight(make_golden_bake) -> None:
    """Stronger than the peak: at the moment each row is created, no other
    live bake exists."""
    _bless_all(make_golden_bake)
    worker = FakeWorker()
    seen_at_create: list[int] = []
    real_queue = rebake._queue

    def spy(blessed, vm_id, stamp):
        seen_at_create.append(worker.live_in_flight().count())
        return real_queue(blessed, vm_id, stamp)

    rebake._queue = spy
    try:
        rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(worker))
    finally:
        rebake._queue = real_queue
    assert seen_at_create == [0, 0, 0, 0]


def test_rebake_clones_the_blessed_inputs_with_a_package_refresh(make_golden_bake) -> None:
    blessed = _bless_all(make_golden_bake)
    rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(FakeWorker()))

    rows = {r.vm_id: r for r in _rebake_rows()}
    for image in IMAGES:
        row = rows[f"golden-{image}-rebake-{STAMP}"]
        src = blessed[image]
        assert row.base_image_url == src.base_image_url
        assert row.base_image_sha256 == src.base_image_sha256
        assert row.size_gb == src.size_gb
        assert row.s3_output_bucket == src.s3_output_bucket
        assert row.disk_mode == TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value
        assert row.package_refresh == STAMP
        # A fresh prefix: the golden's fixed keys must never overwrite the
        # blessed bake's artifacts.
        assert row.s3_output_prefix == f"tenant/{row.vm_id}/"
        assert row.s3_output_prefix != src.s3_output_prefix


def test_waits_for_an_unrelated_in_flight_bake_first(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    other = make_golden_bake(
        bake_id="someone-else", vm_id="tenant-vm-1", state=TenantBakeState.RUNNING.value
    )
    worker = FakeWorker()
    rebake.run_rebake(images=("ubuntu",), stamp=STAMP, timing=_timing(worker))

    other.refresh_from_db()
    assert worker.finished[0] == "tenant-vm-1"
    assert worker.peak_in_flight == 1
    (row,) = _rebake_rows()
    assert row.requested_at > other.finished_at


def test_an_orphan_in_flight_row_does_not_block(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    orphan = make_golden_bake(
        bake_id="orphan", vm_id="bake-orphan", state=TenantBakeState.RUNNING.value
    )
    TenantBake.objects.filter(pk=orphan.pk).update(
        requested_at=timezone.now() - timedelta(days=85),
        started_at=timezone.now() - timedelta(days=80),
    )
    outcome = rebake.run_rebake(images=("ubuntu",), stamp=STAMP, timing=_timing(FakeWorker()))
    assert outcome.success
    orphan.refresh_from_db()
    assert orphan.state == TenantBakeState.RUNNING.value  # untouched


def test_an_old_queued_row_is_never_an_orphan(make_golden_bake) -> None:
    """vali_bake_spawn re-spawns a Queued row whatever its age, so an old
    Queued row can start baking at any moment — it must block."""
    _bless_all(make_golden_bake)
    old = make_golden_bake(bake_id="old-q", vm_id="old-q", state=TenantBakeState.QUEUED.value)
    TenantBake.objects.filter(pk=old.pk).update(requested_at=timezone.now() - timedelta(days=30))
    worker = FakeWorker(hold={"old-q"})
    outcome = rebake.run_rebake(images=("ubuntu",), stamp=STAMP, timing=_timing(worker, idle=120.0))
    assert outcome.aborted
    assert _rebake_rows() == []


def test_a_long_queued_bake_that_just_started_is_live(make_golden_bake) -> None:
    """Orphans are aged from the worker's claim (`started_at`), not from
    `requested_at`: a bake queued days ago but claimed a minute ago is
    baking right now."""
    _bless_all(make_golden_bake)
    late = make_golden_bake(bake_id="late", vm_id="late", state=TenantBakeState.RUNNING.value)
    TenantBake.objects.filter(pk=late.pk).update(
        requested_at=timezone.now() - timedelta(days=3),
        started_at=timezone.now() - timedelta(minutes=1),
    )
    worker = FakeWorker(hold={"late"})
    outcome = rebake.run_rebake(images=("ubuntu",), stamp=STAMP, timing=_timing(worker, idle=120.0))
    assert outcome.aborted
    assert _rebake_rows() == []


def test_a_bake_queued_in_the_check_to_insert_window_never_overlaps(make_golden_bake) -> None:
    """The race the command's own check cannot close: another creator (the
    HTTP API, vali_tenant_bake_create) inserts a bake between "nothing in
    flight" and our INSERT. The spawner's serial gate keeps the re-bake
    from starting until that bake is done."""
    _bless_all(make_golden_bake)
    worker = FakeWorker()
    real_queue = rebake._queue
    raced: list[str] = []

    def racing_queue(blessed, vm_id, stamp):
        if not raced:
            raced.append(make_golden_bake(
                bake_id="racer", vm_id="tenant-racer", state=TenantBakeState.QUEUED.value
            ).vm_id)
        return real_queue(blessed, vm_id, stamp)

    rebake._queue = racing_queue
    try:
        outcome = rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(worker))
    finally:
        rebake._queue = real_queue
    assert outcome.success
    assert worker.peak_in_flight == 1
    assert worker.finished[0] == "tenant-racer"


def test_a_bake_queued_behind_a_live_rebake_waits_for_it(make_golden_bake) -> None:
    """The other direction: a bake requested after a live re-bake row is
    held by the spawner until the re-bake is terminal."""
    from apps.tenant_bake.management.commands.vali_bake_spawn import spawn_queued_bakes

    blessed = _bless_all(make_golden_bake)
    ours = rebake._queue(blessed["ubuntu"], f"golden-ubuntu-rebake-{STAMP}", STAMP)
    later = make_golden_bake(
        bake_id="later", vm_id="tenant-later", state=TenantBakeState.QUEUED.value
    )

    spawn_queued_bakes()
    ours.refresh_from_db()
    later.refresh_from_db()
    assert ours.state == TenantBakeState.RUNNING.value
    assert later.state == TenantBakeState.QUEUED.value

    _succeed(ours)
    spawn_queued_bakes()
    later.refresh_from_db()
    assert later.state == TenantBakeState.RUNNING.value


def test_spawner_unchanged_without_a_rebake_row(make_golden_bake) -> None:
    """Ordinary bakes still spawn side by side, exactly as before F6."""
    from apps.tenant_bake.management.commands.vali_bake_spawn import spawn_queued_bakes

    a = make_golden_bake(bake_id="a", vm_id="tenant-a", state=TenantBakeState.QUEUED.value)
    b = make_golden_bake(bake_id="b", vm_id="tenant-b", state=TenantBakeState.QUEUED.value)
    assert spawn_queued_bakes() == 2
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == b.state == TenantBakeState.RUNNING.value


def test_idle_timeout_aborts_without_queueing(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    make_golden_bake(bake_id="stuck", vm_id="stuck-vm", state=TenantBakeState.RUNNING.value)
    worker = FakeWorker(hold={"stuck-vm"})
    outcome = rebake.run_rebake(
        images=IMAGES, stamp=STAMP, timing=_timing(worker, idle=120.0)
    )
    assert outcome.aborted
    assert not outcome.success
    assert _rebake_rows() == []


def test_a_bake_still_running_at_timeout_stops_the_run(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    worker = FakeWorker(hold={f"golden-ubuntu-rebake-{STAMP}"})
    outcome = rebake.run_rebake(
        images=IMAGES, stamp=STAMP, timing=_timing(worker, bake=120.0)
    )
    assert outcome.aborted
    # Only the stuck one was queued: debian would have baked next to it.
    assert [r.vm_id for r in _rebake_rows()] == [f"golden-ubuntu-rebake-{STAMP}"]
    # The images the run never reached are reported, not dropped.
    assert [r.state for r in outcome.results[1:]] == [rebake.NOT_RUN] * 3
    text = rebake.rebake_metrics(outcome).render()
    assert 'hippius_golden_rebake_bake_success{distro="fedora"} 0' in text


def test_a_failed_bake_does_not_stop_the_others(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    worker = FakeWorker(fail={f"golden-debian-rebake-{STAMP}"})
    outcome = rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(worker))

    assert not outcome.success
    assert [r.state for r in outcome.results] == ["succeeded", "failed", "succeeded", "succeeded"]
    assert worker.peak_in_flight == 1
    text = rebake.rebake_metrics(outcome).render()
    assert 'hippius_golden_rebake_bake_success{distro="debian"} 0' in text
    assert 'hippius_golden_rebake_bake_success{distro="ubuntu"} 1' in text


def test_rerun_of_the_same_stamp_reuses_succeeded_and_retries_failed(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    rebake.run_rebake(
        images=("ubuntu", "debian"),
        stamp=STAMP,
        timing=_timing(FakeWorker(fail={f"golden-debian-rebake-{STAMP}"})),
    )
    outcome = rebake.run_rebake(
        images=("ubuntu", "debian"), stamp=STAMP, timing=_timing(FakeWorker())
    )
    assert outcome.success
    vm_ids = [r.vm_id for r in _rebake_rows()]
    assert vm_ids.count(f"golden-ubuntu-rebake-{STAMP}") == 1
    assert vm_ids.count(f"golden-debian-rebake-{STAMP}") == 2


def test_an_unblessed_image_is_reported_not_baked(make_golden_bake) -> None:
    outcome = rebake.run_rebake(images=("ubuntu",), stamp=STAMP, timing=_timing(FakeWorker()))
    assert outcome.results[0].state == rebake.NOT_BLESSED
    assert not outcome.success
    assert _rebake_rows() == []
    # A config choice, not a bake failure: no bake_success sample to page on.
    assert "hippius_golden_rebake_bake_success" not in rebake.rebake_metrics(outcome).render()


@pytest.mark.parametrize("stamp", ["2026 11", "2026.11", "Nov", "a_b", "x" * 33, ""])
def test_rejects_a_stamp_that_is_not_a_vm_id_suffix(stamp: str) -> None:
    with pytest.raises(ValueError):
        rebake.run_rebake(images=IMAGES, stamp=stamp, timing=_timing(FakeWorker()))
    assert _rebake_rows() == []


# ── never bless ──────────────────────────────────────────────────────


def test_progress_is_published_after_every_image(make_golden_bake) -> None:
    """A run killed mid-way must already have pushed what it did."""
    _bless_all(make_golden_bake)
    pushes: list[tuple[int, bool]] = []
    rebake.run_rebake(
        images=IMAGES,
        stamp=STAMP,
        timing=_timing(FakeWorker(fail={f"golden-debian-rebake-{STAMP}"})),
        on_progress=lambda o: pushes.append((len(o.results), o.completed)),
    )
    assert pushes == [(1, False), (2, False), (3, False), (4, False), (4, True)]
    partial = rebake.RebakeOutcome(stamp=STAMP)
    assert "hippius_golden_rebake_run_completed 0" in rebake.rebake_metrics(partial).render()


def test_never_blesses(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    before = list(GoldenImage.objects.order_by("image_name").values())
    outcome = rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(FakeWorker()))
    assert outcome.success
    assert list(GoldenImage.objects.order_by("image_name").values()) == before


# ── e2e on the unblessed bake ────────────────────────────────────────


def test_e2e_runs_on_each_new_bake_not_the_blessed_one(make_golden_bake) -> None:
    blessed = _bless_all(make_golden_bake)
    calls: list[tuple[str, str]] = []

    def e2e(image: str, bake_id: str) -> bool:
        calls.append((image, bake_id))
        return image != "cs10"

    outcome = rebake.run_rebake(
        images=IMAGES, stamp=STAMP, timing=_timing(FakeWorker()), e2e=e2e
    )
    new_ids = {r.vm_id: r.bake_id for r in _rebake_rows()}
    assert calls == [(i, new_ids[f"golden-{i}-rebake-{STAMP}"]) for i in IMAGES]
    assert all(bid != blessed[i].bake_id for i, bid in calls)
    assert not outcome.success
    text = rebake.rebake_metrics(outcome).render()
    assert 'hippius_golden_rebake_e2e_success{distro="cs10"} 0' in text


def test_e2e_is_skipped_for_a_failed_bake(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    calls: list[str] = []
    rebake.run_rebake(
        images=("ubuntu",),
        stamp=STAMP,
        timing=_timing(FakeWorker(fail={f"golden-ubuntu-rebake-{STAMP}"})),
        e2e=lambda image, bake_id: calls.append(image) or True,
    )
    assert calls == []


def test_build_launch_body_bake_id_override(make_golden_bake) -> None:
    from apps.synthetic import e2e

    _bless_all(make_golden_bake)
    assert e2e.build_launch_body("ubuntu", "synmon-ubuntu-1")["bake_id"] == "blessed-ubuntu"
    body = e2e.build_launch_body("ubuntu", "synmon-ubuntu-1", "new-bake")
    assert body["bake_id"] == "new-bake"


# ── freshness ────────────────────────────────────────────────────────


def test_freshness_reports_age_and_awaiting_bless(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    rows = {f.image: f for f in rebake.freshness(IMAGES)}
    assert not rows["ubuntu"].awaiting_bless
    text = rebake.freshness_metrics(list(rows.values())).render()
    assert 'hippius_golden_rebake_awaiting_bless{distro="ubuntu"} 0' in text
    assert 'hippius_golden_blessed_age_days{distro="ubuntu"} 30' in text

    rebake.run_rebake(images=IMAGES, stamp=STAMP, timing=_timing(FakeWorker()))
    rows = {f.image: f for f in rebake.freshness(IMAGES)}
    assert all(f.awaiting_bless for f in rows.values())
    assert rows["ubuntu"].ready_bake_id == TenantBake.objects.get(
        vm_id=f"golden-ubuntu-rebake-{STAMP}"
    ).bake_id

    # The human blesses ubuntu → no longer awaiting, age resets.
    new = rows["ubuntu"].ready_bake_id
    call_command("vali_bless_golden_image", "ubuntu", new)
    rows = {f.image: f for f in rebake.freshness(IMAGES)}
    assert not rows["ubuntu"].awaiting_bless
    assert rows["debian"].awaiting_bless
    text = rebake.freshness_metrics(list(rows.values())).render()
    assert 'hippius_golden_blessed_age_days{distro="ubuntu"} 0' in text


def test_an_e2e_failed_rebake_is_not_awaiting_bless(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    rebake.run_rebake(
        images=("ubuntu", "debian"),
        stamp=STAMP,
        timing=_timing(FakeWorker()),
        e2e=lambda image, bake_id: image == "debian",
    )
    rows = {f.image: f for f in rebake.freshness(("ubuntu", "debian"))}
    assert not rows["ubuntu"].awaiting_bless
    assert rows["debian"].awaiting_bless
    assert TenantBake.objects.get(
        vm_id=f"golden-ubuntu-rebake-{STAMP}"
    ).rebake_e2e_passed is False


def test_a_failed_rebake_is_not_awaiting_bless(make_golden_bake) -> None:
    _bless_all(make_golden_bake)
    rebake.run_rebake(
        images=("ubuntu",),
        stamp=STAMP,
        timing=_timing(FakeWorker(fail={f"golden-ubuntu-rebake-{STAMP}"})),
    )
    (row,) = [f for f in rebake.freshness(("ubuntu",))]
    assert not row.awaiting_bless


# ── command ──────────────────────────────────────────────────────────


@override_settings(VALI_GOLDEN_REBAKE_ENABLED=False)
def test_command_flag_off_is_a_noop(make_golden_bake, capsys) -> None:
    _bless_all(make_golden_bake)
    before = TenantBake.objects.count()
    call_command("vali_scheduled_golden_rebake", "--no-push")
    assert TenantBake.objects.count() == before
    assert "disabled" in capsys.readouterr().out


@override_settings(VALI_GOLDEN_REBAKE_ENABLED=False)
def test_command_report_only_reads_and_never_queues(make_golden_bake, capsys) -> None:
    _bless_all(make_golden_bake)
    before = TenantBake.objects.count()
    call_command("vali_scheduled_golden_rebake", "--report-only", "--no-push")
    assert TenantBake.objects.count() == before
    out = capsys.readouterr().out
    assert 'hippius_golden_blessed_age_days{distro="fedora"}' in out


@override_settings(VALI_GOLDEN_REBAKE_ENABLED=True, VALI_GOLDEN_REBAKE_E2E=True)
def test_command_reaps_leaked_e2e_vms_before_launching(make_golden_bake, monkeypatch) -> None:
    """A Job killed mid-e2e cannot run its teardown; the next run reaps
    the leaked synthetic VMs before it launches anything."""
    from apps.synthetic import e2e

    order: list[str] = []

    def fake_rebake(**_kw) -> rebake.RebakeOutcome:
        order.append("rebake")
        return rebake.RebakeOutcome(stamp=STAMP)

    monkeypatch.setattr(e2e, "run_reaper", lambda: order.append("reap") or e2e.ReaperResult())
    monkeypatch.setattr(rebake, "run_rebake", fake_rebake)
    call_command("vali_scheduled_golden_rebake", "--no-push", "--stamp", STAMP)
    assert order == ["reap", "rebake"]


@override_settings(
    VALI_GOLDEN_REBAKE_ENABLED=True,
    VALI_GOLDEN_REBAKE_E2E=False,
    VALI_GOLDEN_REBAKE_POLL_INTERVAL_S=1.0,
)
def test_command_enabled_rebakes_and_pushes(make_golden_bake, monkeypatch, capsys) -> None:
    _bless_all(make_golden_bake)
    worker = FakeWorker()
    monkeypatch.setattr(rebake.time, "sleep", worker.sleep)
    monkeypatch.setattr(rebake.time, "monotonic", worker.monotonic)
    before = list(GoldenImage.objects.order_by("image_name").values())

    call_command("vali_scheduled_golden_rebake", "--no-push", "--stamp", STAMP)

    out = capsys.readouterr().out
    assert worker.peak_in_flight == 1
    assert len(_rebake_rows()) == 4
    assert 'hippius_golden_rebake_bake_success{distro="ubuntu"} 1' in out
    assert 'hippius_golden_rebake_awaiting_bless{distro="ubuntu"} 1' in out
    assert list(GoldenImage.objects.order_by("image_name").values()) == before


@pytest.mark.django_db
def test_a_rebake_keeps_the_bake_profile(make_golden_bake) -> None:
    """CDN plan I3 — re-baking a cdn-node golden rebuilds a cdn-node image."""
    blessed = make_golden_bake("cdn-golden-1", profile="cdn-node")
    row = rebake._queue(blessed, "cdn-rebake-1", "stamp-1")
    assert row.profile == "cdn-node"
    std = make_golden_bake("std-golden-1")
    assert rebake._queue(std, "std-rebake-1", "stamp-2").profile == "standard"


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("backend", "queued"),
    [("https://api.hippius.com", True), ("https://api.hippius.com/", False), ("", False)],
)
def test_a_cdn_node_rebake_needs_a_bare_https_origin(
    make_golden_bake, settings, backend: str, queued: bool
) -> None:
    """The URL is measured into the image: a bad one never gets re-baked."""
    settings.VALI_CDN_BACKEND_URL = backend
    bake = make_golden_bake(
        bake_id="blessed-cdn-node",
        vm_id="golden-cdn-node-dp",
        s3_output_prefix="tenant/golden-cdn-node-dp/",
        profile="cdn-node",
        finished_at=timezone.now() - timedelta(days=30),
    )
    GoldenImage.objects.create(
        image_name="cdn-node",
        distro="debian",
        bake_id=bake.bake_id,
        blessed_at=timezone.now() - timedelta(days=29),
        blessed_by="ops",
        restricted_tenant="hippius-cdn",
    )
    outcome = rebake.run_rebake(images=("cdn-node",), stamp=STAMP, timing=_timing(FakeWorker()))
    rows = _rebake_rows()
    assert bool(rows) is queued
    if queued:
        assert rows[0].cdn_backend_url == backend
    else:
        assert outcome.results[0].state == rebake.NOT_RUN
