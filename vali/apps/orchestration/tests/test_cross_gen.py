"""Cross-generation restore and failover (`apps.orchestration.cross_gen`):
behind `VALI_FAILOVER_CROSS_GEN_ENABLED`, a destination of another SNP
generation gets its own digest — pinned before the KBS moves, carried by
its ticket, recorded at the commit — and both digests stay pinned until the
source is reclaimed. Off, nothing changes."""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.backup import service as backup_service
from apps.backup.models import BackupPolicy
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration import cross_gen, restore
from apps.orchestration.models import (
    MeasurementLedger,
    MigrationJob,
    MigrationState,
    SourceReclaimState,
)
from apps.orchestration.services import allowlist_pin, launch_digest, launch_record
from apps.scheduler import service as sched

from .conftest import FakeEffects
from .test_failover import (  # noqa: F401 — autouse fixture
    _REAL_VALIDATE,
    _advance,
    _failover,
    _failover_env,
    _World,
)
from .test_restore import (  # noqa: F401 — autouse fixture
    _chain,
    _golden_vm,
    _grant,
    _restore_env,
)

pytestmark = pytest.mark.django_db

TURIN = "44" * 8  # an 8-byte CHIP_ID: Turin
DEST_DIGEST = "ab" * 48


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> _World:
    return _World(monkeypatch)


@pytest.fixture
def on(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The flag on, vali's recompute available, the destination's digest
    stubbed, and every pin recorded."""
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_ENABLED", True)
    monkeypatch.setattr(launch_digest, "is_enabled", lambda: True)
    monkeypatch.setattr(cross_gen, "dest_digest", lambda vm, dest: DEST_DIGEST)
    pins: list[dict[str, Any]] = []
    monkeypatch.setattr(allowlist_pin, "pin_measurement", lambda **kw: pins.append(kw))
    return pins


def _turin_dest() -> None:
    MinerIdentity.objects.filter(miner_id="node-dst").update(platform_id=TURIN)


# ── the gates ─────────────────────────────────────────────────────────


def test_off_a_destination_of_another_generation_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    vm = _golden_vm()
    _turin_dest()
    with pytest.raises(restore.RestoreError) as exc:
        _REAL_VALIDATE(vm, "node-dst", region="FR")
    assert "generation" in exc.value.detail
    assert not cross_gen.allowed(vm)


def test_on_another_generation_is_a_destination_but_not_for_a_pinned_measurement(
    on, monkeypatch
) -> None:
    vm = _golden_vm()
    assert cross_gen.allowed(vm)
    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    record.spec_json = {**record.spec_json, "measurement_hex": "cd" * 48}
    record.save(update_fields=["spec_json"])
    assert not cross_gen.allowed(vm), "an operator-pinned measurement never crosses"


def test_the_flag_needs_valis_own_recompute(on, monkeypatch) -> None:
    monkeypatch.setattr(launch_digest, "is_enabled", lambda: False)
    assert not cross_gen.enabled()


def test_the_pick_prefers_the_sources_generation(on, world, monkeypatch) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    vm = _golden_vm()
    MinerIdentity.objects.create(
        miner_id="node-turin", pubkey_hex="dd" * 32, platform_id=TURIN, chain_node_id="e" * 64
    )
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "FR", "e" * 64: "FR"})
    roomy = sched.HostResources(256 * 1024, 64, 10**7, 64)
    tight = sched.HostResources(64 * 1024, 8, 10**6, 64)
    monkeypatch.setattr(sched, "host_resources_by_node", lambda: {"d" * 64: tight, "e" * 64: roomy})
    assert restore._pick_failover_dest(vm, "node-src") == "node-dst", "same generation first"
    monkeypatch.setattr(sched, "cordoned_node_ids", lambda: {"d" * 64: "disk"})
    assert restore._pick_failover_dest(vm, "node-src") == "node-turin", "then any"


def test_the_pick_prefers_a_newer_generation_to_an_older_one(on, world, monkeypatch) -> None:
    """A Turin VM with no Turin left: a Genoa before a Milan, however much
    room the Milan has (the SIGILL risk grows with the gap)."""
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest, **kw: None)
    vm = _golden_vm()
    MinerIdentity.objects.filter(miner_id="node-src").update(platform_id="55" * 8)  # Turin
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    MinerIdentity.objects.create(
        miner_id="node-milan",
        pubkey_hex="dd" * 32,
        platform_id="77" * 64,
        snp_generation="milan",
        chain_node_id="e" * 64,
    )
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "FR", "e" * 64: "FR"})
    roomy = sched.HostResources(256 * 1024, 64, 10**7, 64)
    tight = sched.HostResources(64 * 1024, 8, 10**6, 64)
    monkeypatch.setattr(sched, "host_resources_by_node", lambda: {"d" * 64: tight, "e" * 64: roomy})
    assert restore._pick_failover_dest(vm, "node-src") == "node-dst"


def _active_on_chain(miner_id: str, chain_node_id: str) -> None:
    from apps.scheduler.models import MinerCapacity

    MinerIdentity.objects.filter(miner_id=miner_id).update(chain_node_id=chain_node_id)
    MinerCapacity.objects.update_or_create(
        miner_node_id=chain_node_id,
        defaults={
            "status": "active",
            "capacity_slots": 4,
            "observed_epoch": 10,
            "data_epoch": 10,
            "refreshed_at": timezone.now(),
        },
    )


def _locate(miner_id: str, country: str) -> None:
    MinerLocation.objects.update_or_create(
        miner=MinerIdentity.objects.get(miner_id=miner_id),
        defaults={
            "country_code": country,
            "verdict": LocationVerdict.VERIFIED,
            "observed_at": timezone.now(),
        },
    )


def test_the_policy_says_cross_generation_and_warns_toward_an_older_one(on, monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    vm = _golden_vm()  # on node-src, a Genoa
    _turin_dest()
    _active_on_chain("node-dst", "d" * 64)
    _locate("node-dst", "FR")
    policy = BackupPolicy.objects.get(vm=vm)
    view = backup_service.policy_view(policy)
    assert view["failover_cross_generation"] is True
    assert view["failover_cross_generation_warning"] is None, "Genoa → Turin: newer"
    # The VM on the Turin, its only peer the Genoa: older.
    MinerIdentity.objects.filter(miner_id="node-src").update(platform_id="55" * 8)
    MinerIdentity.objects.filter(miner_id="node-dst").update(platform_id="66" * 64)
    view = backup_service.policy_view(policy)
    assert view["failover_cross_generation_warning"] == cross_gen.OLDER_GENERATION_WARNING
    assert backup_service.failover_peer_blocker(vm) is None


def test_off_the_policy_reads_as_before(monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    vm = _golden_vm()
    _turin_dest()
    _active_on_chain("node-dst", "d" * 64)  # a real peer, but of another generation
    _locate("node-dst", "FR")
    view = backup_service.policy_view(BackupPolicy.objects.get(vm=vm))
    assert view["failover_cross_generation"] is False
    assert backup_service.failover_peer_blocker(vm) == "no-failover-peer"


# ── the destination's digest ─────────────────────────────────────────


def test_a_cross_generation_failover_pins_carries_and_records_its_digest(
    on, fx: FakeEffects, world
) -> None:
    vm = _golden_vm()
    _chain(vm)
    _turin_dest()
    MeasurementLedger.objects.create(
        allowlist_epoch=10,
        vm_id=vm.vm_id,
        launch_digest_hex=launch_record.recorded_measurement(vm.vm_id),
        measurement_class=allowlist_pin.ALLOWLIST_CLASS_TENANT,
        flavor="small",
        launched_at=timezone.now(),
    )
    world.kill()
    job = _failover(vm)
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    [pin] = on
    assert pin["measurement_hex"] == DEST_DIGEST
    assert pin["measurement_class"] == allowlist_pin.ALLOWLIST_CLASS_TENANT
    assert pin["ledger"].node_id == "node-dst" and pin["ledger"].launch_ref == job.job_id
    assert job.dest_measurement_hex == DEST_DIGEST
    assert fx.activate_measurement == DEST_DIGEST, "the destination's ticket carries it"
    # The pin precedes the KBS move.
    assert ("kbs_activate_dest", vm.vm_id, "node-dst", 6) in fx.calls
    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value, job.reason
    assert launch_record.recorded_measurement(vm.vm_id) == DEST_DIGEST


def test_a_same_generation_failover_is_untouched(on, fx: FakeEffects, world) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    fx.kbs_evidence = None
    job = _advance(job)
    assert on == [] and job.dest_measurement_hex == ""
    assert fx.activate_measurement == ""


def test_off_a_cross_generation_job_fails_before_the_kbs_moves(
    on, fx: FakeEffects, world, monkeypatch
) -> None:
    """A job opened while on, the flag turned off before its activation:
    nothing is pinned, the KBS is never asked."""
    vm = _golden_vm()
    _chain(vm)
    _turin_dest()
    world.kill()
    job = _failover(vm)
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_ENABLED", False)
    from apps.orchestration import service

    with pytest.raises(service._StepFailed):
        cross_gen.prepare_dest_measurement(MigrationJob.objects.get(pk=job.pk))
    assert on == [] and not fx.did("kbs_activate_dest")


def test_the_digest_is_computed_once(on, world, monkeypatch) -> None:
    vm = _golden_vm()
    _chain(vm)
    _turin_dest()
    world.kill()
    job = _failover(vm)
    computed: list[str] = []
    monkeypatch.setattr(
        cross_gen, "dest_digest", lambda vm, dest: computed.append(dest) or DEST_DIGEST
    )
    cross_gen.prepare_dest_measurement(job)
    cross_gen.prepare_dest_measurement(MigrationJob.objects.get(pk=job.pk))
    assert computed == ["node-dst"] and len(on) == 1, (
        "the state re-runs every tick: pinned once, never recomputed"
    )


# ── both digests pinned until the source is reclaimed ─────────────────


def _moved(vm, world, *, source: str) -> MigrationJob:
    """A committed cross-generation failover of `vm`, its record moved to
    the destination's digest, the source not reclaimed."""
    _chain(vm)
    world.kill()
    job = _failover(vm)
    MigrationJob.objects.filter(pk=job.pk).update(
        dest_measurement_hex=DEST_DIGEST,
        source_measurement_hex=source,
        state=MigrationState.DONE.value,
        finished_at=timezone.now(),
        committed_at=timezone.now(),
    )
    launch_record.record_cross_generation(vm.vm_id, DEST_DIGEST, reason="t")
    return MigrationJob.objects.get(pk=job.pk)


def _ledger(vm, digest: str, **kw: Any) -> None:
    MeasurementLedger.objects.create(
        allowlist_epoch=10, vm_id=vm.vm_id, launch_digest_hex=digest, pinned_at=timezone.now(), **kw
    )


def test_the_source_digest_stays_pinned_until_the_source_is_reclaimed(on, world) -> None:
    vm = _golden_vm()
    source, older = "cd" * 48, "ef" * 48
    _ledger(vm, older, launched_at=timezone.now())  # a launch before, evicted long ago
    _ledger(vm, source, launched_at=timezone.now())
    _ledger(vm, DEST_DIGEST)
    job = _moved(vm, world, source=source)
    carried = allowlist_pin._query_carry_forward_classes()
    assert source in carried and DEST_DIGEST in carried
    assert older not in carried, "only the source's digest is held, never older ones"
    assert [r.launch_digest_hex for r in allowlist_pin.pending_superseded_pins()] == [older]
    MigrationJob.objects.filter(pk=job.pk).update(source_reclaim_state=SourceReclaimState.RECLAIMED)
    carried = allowlist_pin._query_carry_forward_classes()
    assert source not in carried and DEST_DIGEST in carried
    assert {r.launch_digest_hex for r in allowlist_pin.pending_superseded_pins()} == {
        older,
        source,
    }


def test_a_relaunch_on_the_destination_ends_the_hold(on, world) -> None:
    """The failover's source never comes back: the hold ends with the next
    launch, not never."""
    vm = _golden_vm()
    source, relaunch = "cd" * 48, "12" * 48
    _ledger(vm, source, launched_at=timezone.now())
    _ledger(vm, DEST_DIGEST)
    _moved(vm, world, source=source)
    assert source in allowlist_pin._query_carry_forward_classes()
    _ledger(vm, relaunch)
    launch_record.record_relaunch(vm.vm_id, {"measurement_hex": relaunch}, reason="relaunch")
    assert source not in allowlist_pin._query_carry_forward_classes()


def test_a_job_that_failed_before_its_commit_holds_nothing(on, world) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    MigrationJob.objects.filter(pk=job.pk).update(
        dest_measurement_hex=DEST_DIGEST,
        source_measurement_hex="cd" * 48,
        state=MigrationState.FAILED.value,
        finished_at=timezone.now(),
    )
    assert cross_gen.held_source_digests({vm.vm_id: (DEST_DIGEST, timezone.now())}) == set()


def test_the_commit_keeps_the_booted_flavor_marker(on, world) -> None:
    """A stopped VM resized on the books boots its old size until a start:
    the cross-generation commit changes the measurement, nothing else."""
    vm = _golden_vm()
    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    record.result_json = {"emit": {"measurement_hex": "cd" * 48, "booted_flavor": "small"}}
    record.save(update_fields=["result_json"])
    launch_record.record_cross_generation(vm.vm_id, DEST_DIGEST, reason="t")
    record.refresh_from_db()
    assert record.result_json["emit"]["measurement_hex"] == DEST_DIGEST
    assert record.result_json["emit"]["booted_flavor"] == "small"


def test_a_job_that_failed_past_its_commit_records_the_destination(on, world) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    MigrationJob.objects.filter(pk=job.pk).update(dest_measurement_hex=DEST_DIGEST)
    restore._stamp_committed(MigrationJob.objects.get(pk=job.pk))
    assert launch_record.recorded_measurement(vm.vm_id) == DEST_DIGEST


def test_milan_and_the_lab_list_gate_the_move(on, monkeypatch) -> None:
    vm = _golden_vm()
    assert cross_gen.allowed(vm, "EpycGenoa", "EpycTurin")
    assert not cross_gen.allowed(vm, "EpycTurin", "EpycMilan"), "Milan until proven"
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_VM_IDS", ["vm-lab"])
    assert not cross_gen.allowed(vm, "EpycGenoa", "EpycTurin"), "the lab window: listed VMs only"


def test_the_failover_capable_regions_pool_every_generation_when_on(on, monkeypatch) -> None:
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    for seed, chip_bytes in ((71, 8), (72, 64)):
        miner = make_dispatchable_identity(seed)
        MinerIdentity.objects.filter(pk=miner.pk).update(platform_id=f"{seed:02x}" * chip_bytes)
        MinerLocation.objects.create(
            miner=miner,
            country_code="FR",
            verdict=LocationVerdict.VERIFIED,
            observed_at=timezone.now(),
        )
        _active_on_chain(miner.miner_id, node_id(seed))
    assert set(sched.failover_capable_node_ids()) == {node_id(71), node_id(72)}
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_ENABLED", False)
    assert sched.failover_capable_node_ids() == {}


# ── the lab tool ─────────────────────────────────────────────────────


@pytest.mark.parametrize(("miner", "code"), [(DEST_DIGEST.upper(), 0), ("cd" * 48, 1)])
def test_the_lab_digest_tool_compares_vali_and_the_miner(on, monkeypatch, capsys, miner, code):
    import json

    from django.core.management import call_command

    from apps.orchestration.services import preflight as preflight_svc

    vm = _golden_vm()
    _turin_dest()
    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    record.spec_json = {
        **record.spec_json,
        **{k: "x" for k in ("tenant_id", "user_id", "lease_id", "s3_bucket", "s3_key_prefix")},
        **{
            k: "a" * 64
            for k in (
                "luks_disk_sha256_hex",
                "kernel_sha256_hex",
                "initrd_sha256_hex",
                "rootfs_img_sha256_hex",
                "rootfs_verity_sha256_hex",
            )
        },
        "luks_header_sha256_hex": "a" * 64,
    }
    record.result_json = {"emit": {"measured_cmdline": "ro console=ttyS0 hippius.x=1"}}
    record.save(update_fields=["spec_json", "result_json"])
    seen: dict[str, Any] = {}

    def fake_preflight(**kw: Any) -> Any:
        seen.update(kw)
        return preflight_svc.PreflightResult(
            launch_digest_hex=miner, luks_disk_path="", kernel_path="", initrd_path=""
        )

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", fake_preflight)
    try:
        call_command("vali_cross_gen_digest", vm_id=vm.vm_id, dest="node-dst", preflight=True)
        exit_code = 0
    except SystemExit as exc:
        exit_code = int(exc.code)
    out = json.loads(capsys.readouterr().out)
    assert exit_code == code, (out.get("miner_error"), out.get("vali_error"))
    assert out["vali_digest"] == DEST_DIGEST and out["dest_generation"] == "EpycTurin"
    assert seen["miner_id"] == "node-dst" and seen["vm_id"] == f"xgen-probe-{vm.vm_id}"


def test_the_dest_digest_is_the_destinations_recompute_of_the_recorded_boot(monkeypatch):
    from apps.orchestration.services import flavors

    vm = _golden_vm()
    _turin_dest()
    MinerIdentity.objects.filter(miner_id="node-dst").update(snp_generation="turin")
    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    record.result_json = {"emit": {"measured_cmdline": "ro console=ttyS0 hippius.x=1"}}
    record.save(update_fields=["result_json"])
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        launch_digest, "recompute_expected_digest", lambda **kw: seen.update(kw) or "ee" * 48
    )
    assert cross_gen.dest_digest(vm, "node-dst") == "ee" * 48
    assert (seen["platform_id"], seen["snp_generation"]) == (TURIN, "turin")
    assert seen["cmdline"] == "ro console=ttyS0 hippius.x=1", "the cmdline the dest is sent"
    assert (
        seen["cpu_count"] == flavors.resolve_flavor(launch_record.booted_flavor(record)).cpu_count
    )


def test_a_pinned_measurement_vm_counts_only_same_generation_peers(on, monkeypatch) -> None:
    vm = _golden_vm()
    asked: list[bool] = []
    monkeypatch.setattr(
        sched, "failover_capable_node_ids", lambda **kw: asked.append(kw["same_generation"]) or {}
    )
    sched.failover_peer_arguments(True, vm.vm_id)
    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    record.spec_json = {**record.spec_json, "measurement_hex": "cd" * 48}
    record.save(update_fields=["spec_json"])
    sched.failover_peer_arguments(True, vm.vm_id)
    assert asked == [False, True]


def test_off_the_handler_fails_a_cross_generation_job_at_once(
    on, fx: FakeEffects, world, monkeypatch
) -> None:
    vm = _golden_vm()
    _chain(vm)
    _turin_dest()
    world.kill()
    job = _failover(vm)
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_ENABLED", False)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value, (job.state, job.reason)
    assert on == [] and not fx.did("kbs_activate_dest")


def test_a_lab_window_pools_no_generation(on, monkeypatch) -> None:
    assert cross_gen.pool("EpycTurin") == "*"
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_VM_IDS", ["vm-lab"])
    assert cross_gen.pool("EpycTurin") == "EpycTurin", "only the lab VMs may cross"


def test_vali_refuses_to_start_on_an_unknown_generation(monkeypatch) -> None:
    """A typo (`genoa`) would silently disable crossing: `settings.py`
    raises instead. Loaded as a fresh copy, never over the live settings."""
    import importlib.util

    from vali import settings as vali_settings

    def load() -> None:
        spec = importlib.util.spec_from_file_location("_settings_copy", vali_settings.__file__)
        spec.loader.exec_module(importlib.util.module_from_spec(spec))

    monkeypatch.setenv("VALI_FAILOVER_CROSS_GEN_GENERATIONS", "genoa,EpycTurin")
    with pytest.raises(RuntimeError, match="genoa"):
        load()
    monkeypatch.setenv("VALI_FAILOVER_CROSS_GEN_GENERATIONS", ",".join(cross_gen.GENERATION_ORDER))
    load()  # every model `cross_gen` orders is accepted


def test_a_vm_outside_the_lab_list_keeps_its_own_generation_everywhere(on, monkeypatch) -> None:
    """The backend flag is live for customers: during a lab window a
    customer VM must never see another generation — no destination, no
    peer, no pool, no policy flag."""
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    monkeypatch.setattr(settings, "VALI_FAILOVER_CROSS_GEN_VM_IDS", ["vm-lab"])
    vm = _golden_vm()  # vm-1, not in the list
    _turin_dest()
    _active_on_chain("node-dst", "d" * 64)
    _locate("node-dst", "FR")
    assert not cross_gen.allowed(vm, "EpycGenoa", "EpycTurin")
    assert backup_service.failover_peer_blocker(vm) == "no-failover-peer"
    view = backup_service.policy_view(BackupPolicy.objects.get(vm=vm))
    assert view["failover_cross_generation"] is False
    assert cross_gen.pool("EpycTurin") == "EpycTurin"
