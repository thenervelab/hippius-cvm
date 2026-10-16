"""`disk_probe` result matching (`apps.disktier.probe_results`, phase R1),
through the receipt hook (`ingest.on_verified_receipt`): what is accepted,
every rejection and its counter, the classification wiring, and that a
verdict changes nothing but the run (record only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.disktier import probe_results
from apps.disktier.ingest import drain_counters, flush_counters_safe, on_verified_receipt
from apps.disktier.models import (
    DiskIngestCounter,
    DiskProbeRun,
    MinerStoragePool,
    ProbeRunState,
    VmDiskIoHourly,
)
from apps.scheduler.models import Placement, PlacementStatus
from apps.scheduler.tests.factories import make_placement, make_vm
from apps.telemetry.verifier import DiskProbeResult, ServedReceiptFields

from .probe_helpers import NODE, NODE2, USER, V1_NVME, make_run, result_for

pytestmark = pytest.mark.django_db

NOW = datetime(2026, 10, 16, 12, 30, tzinfo=UTC)
T0 = int(NOW.timestamp()) - 600


@pytest.fixture(autouse=True)
def _probe_on(settings: Any) -> None:
    settings.VALI_DISK_PROBE_ENABLED = True
    settings.VALI_DISK_IO_INGEST = False
    drain_counters()


def _placed(run: DiskProbeRun, *, owner: str = USER, node: str = NODE) -> Placement:
    vm = make_vm(run.vm_id, run.vm_id)
    return make_placement(vm, node, status=PlacementStatus.BOUND.value, owner=owner)


def _receipt(
    probe: DiskProbeResult, *, node: str = NODE, vm_id: str | None = None
) -> ServedReceiptFields:
    vm = vm_id or probe.vm_id
    return ServedReceiptFields(
        vm_id=vm,
        lease_id=vm,
        node_id_hex=node,
        epoch=5,
        resource_class="medium",
        period_start=T0,
        period_end=T0 + 60,
        monotonic_seq=1,
        observed_degradation_bps=0,
        disk_probe=probe,
    )


def _ingest(fields: ServedReceiptFields, body: bytes = b"receipt-1") -> str:
    return on_verified_receipt(fields, body=body, source_id=fields.vm_id, now=NOW)


def _running(**kw: Any) -> DiskProbeRun:
    run = make_run(state=ProbeRunState.RUNNING, **kw)
    _placed(run)
    return run


# ─── accept ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("state", [ProbeRunState.RUNNING, ProbeRunState.LAUNCHING])
def test_a_matching_result_is_verified_and_classified(state: str) -> None:
    run = make_run(state=state)
    _placed(run)
    assert _ingest(_receipt(result_for(run))) == "probe-accepted"
    run.refresh_from_db()
    assert run.state == ProbeRunState.VERIFIED
    assert run.failure_reason == ""
    (target,) = run.targets
    assert target["slot"] == "os" and target["pool_id"] == "default"
    assert target["classified_tier"] == "nvme"
    assert target["verdict_detail"] == ""
    assert target["metrics"] == V1_NVME
    assert len(target["hist_qd1"]) == 32
    assert set(target["per_metric"].values()) == {"nvme"}
    assert run.release_version == 5
    assert run.result_meta == {
        "vcpus": 2, "kernel": "6.8.0", "started_at": 1_000, "finished_at": 1_300
    }
    assert run.result_at == run.finished_at == NOW
    # Lifetime jitter: torn down 10-60 min later, by the orchestrator.
    assert timedelta(minutes=10) <= run.teardown_after - NOW <= timedelta(minutes=60)
    assert run.torn_down_at is None
    assert drain_counters() == {"probe_results": 1, "probe_accepted": 1}


def test_the_os_tier_is_the_minimum_over_metrics() -> None:
    run = _running()
    _ingest(_receipt(result_for(run, metrics={**V1_NVME, "rw_iops": 4_000})))
    run.refresh_from_db()
    assert run.state == ProbeRunState.VERIFIED
    assert run.targets[0]["classified_tier"] == "ssd"


# ─── reject ──────────────────────────────────────────────────────────


def test_a_result_forged_by_a_tenant_vm_is_rejected() -> None:
    """A tenant writes a `disk_probe` into its own signed receipts."""
    run = _running()
    vm = make_vm("tenant-vm", "tenant-vm")
    make_placement(vm, NODE, status=PlacementStatus.BOUND.value, owner="77")
    forged = result_for(run, vm_id="tenant-vm")
    assert _ingest(_receipt(forged)) == "probe-rejected_not_probe_vm"
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING and run.result_digest == ""
    assert drain_counters()["probe_rejected_not_probe_vm"] == 1


@pytest.mark.parametrize(
    ("mutate", "outcome"),
    [
        ({"nonce_hex": "00" * 32}, "rejected_wrong_nonce"),
        ({"run_id_hex": "11" * 16}, "rejected_unknown_run"),
    ],
)
def test_a_result_without_the_runs_secret_is_rejected(mutate: dict, outcome: str) -> None:
    run = _running()
    assert _ingest(_receipt(result_for(run, **mutate))) == f"probe-{outcome}"
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING
    assert drain_counters()[f"probe_{outcome}"] == 1


def test_a_result_relayed_by_another_node_is_rejected() -> None:
    run = _running()
    assert _ingest(_receipt(result_for(run), node=NODE2)) == "probe-rejected_wrong_node"
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING


def test_a_result_from_a_vm_placed_on_another_node_is_rejected() -> None:
    run = make_run(state=ProbeRunState.RUNNING)
    _placed(run, node=NODE2)
    assert _ingest(_receipt(result_for(run), node=NODE2)) == "probe-rejected_wrong_node"


def test_a_result_from_a_vm_of_another_owner_is_rejected() -> None:
    run = make_run(state=ProbeRunState.RUNNING)
    _placed(run, owner="77")
    assert _ingest(_receipt(result_for(run))) == "probe-rejected_wrong_owner"


@pytest.mark.parametrize("state", [ProbeRunState.TIMEOUT, ProbeRunState.FAILED])
def test_a_result_for_a_terminal_run_changes_nothing(state: str) -> None:
    run = make_run(state=state, failure_reason="probe-timeout", finished_at=NOW)
    _placed(run)
    assert _ingest(_receipt(result_for(run))) == "probe-rejected_run_terminal"
    run.refresh_from_db()
    assert run.state == state and run.failure_reason == "probe-timeout"


def test_every_later_receipt_repeats_the_result() -> None:
    run = _running()
    assert _ingest(_receipt(result_for(run)), b"r1") == "probe-accepted"
    run.refresh_from_db()
    first = (run.state, run.result_digest, run.teardown_after)
    # The same result, carried by the next receipt — and a different one.
    assert _ingest(_receipt(result_for(run)), b"r2") == "probe-repeat"
    assert _ingest(_receipt(result_for(run, metrics={**V1_NVME, "rr_iops": 1})), b"r3") == (
        "probe-repeat"
    )
    run.refresh_from_db()
    assert (run.state, run.result_digest, run.teardown_after) == first


# ─── classification wiring ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"metrics": {**V1_NVME, "qd1_p50_us": 12}}, "suspect-cache"),
        ({"error": "io-error"}, "io-error"),
        ({"error": "precondition-incomplete"}, "precondition-incomplete"),
        ({"metrics": {**V1_NVME, "bogus_metric": 1}}, "malformed-metrics"),
        ({"profile": "d1"}, "profile-mismatch"),
        ({"slots": ("os", "x0")}, "targets-mismatch"),
    ],
)
def test_a_bad_result_fails_the_run_with_its_reason(kw: dict, reason: str) -> None:
    run = _running()
    assert _ingest(_receipt(result_for(run, **kw))) == "probe-accepted"
    run.refresh_from_db()
    assert run.state == ProbeRunState.FAILED
    assert run.failure_reason == reason
    # Failed runs are torn down after the same jitter.
    assert run.teardown_after is not None


def test_suspect_cache_yields_no_tier() -> None:
    run = _running()
    _ingest(_receipt(result_for(run, metrics={**V1_NVME, "qd1_p50_us": 3})))
    run.refresh_from_db()
    assert run.targets[0]["classified_tier"] == "unknown"
    assert run.targets[0]["verdict_detail"] == "suspect-cache"


# ─── record only, the flags, the counters ────────────────────────────


def test_a_verdict_changes_no_pool_tier_or_health() -> None:
    pool = MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="default")
    before = MinerStoragePool.objects.filter(pk=pool.pk).values().get()
    run = _running()
    _ingest(_receipt(result_for(run, metrics={**V1_NVME, "seq_read_mbps": 1})))
    run.refresh_from_db()
    assert run.targets[0]["classified_tier"] == "unfit"
    assert MinerStoragePool.objects.filter(pk=pool.pk).values().get() == before


def test_probe_off_only_counts(settings: Any) -> None:
    settings.VALI_DISK_PROBE_ENABLED = False
    settings.VALI_DISK_IO_INGEST = True
    run = _running()
    assert _ingest(_receipt(result_for(run))) == "ingested"
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING and run.result_digest == ""
    assert drain_counters()["probe_results"] == 1


def test_both_off_writes_nothing(settings: Any) -> None:
    settings.VALI_DISK_PROBE_ENABLED = False
    run = _running()
    assert _ingest(_receipt(result_for(run))) == "off"
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING


def test_probe_on_folds_no_disk_io_while_the_ingest_is_off() -> None:
    from apps.disktier.tests.test_passive_ingest import delta

    run = _running()
    fields = _receipt(result_for(run))
    fields = ServedReceiptFields(**{**fields.__dict__, "disk_io": (delta(),)})
    assert _ingest(fields) == "probe-accepted"
    assert not VmDiskIoHourly.objects.exists()


def test_both_on_routes_and_folds(settings: Any) -> None:
    from apps.disktier.tests.test_passive_ingest import delta

    settings.VALI_DISK_IO_INGEST = True
    run = _running()
    fields = _receipt(result_for(run))
    fields = ServedReceiptFields(**{**fields.__dict__, "disk_io": (delta(),)})
    assert _ingest(fields) == "ingested"
    run.refresh_from_db()
    assert run.state == ProbeRunState.VERIFIED
    assert VmDiskIoHourly.objects.count() == 1


def test_the_counters_persist_with_only_the_probe_on() -> None:
    run = _running()
    _ingest(_receipt(result_for(run, nonce_hex="00" * 32)))
    flush_counters_safe()
    assert DiskIngestCounter.objects.get(name="probe_rejected_wrong_nonce").value == 1


def test_a_routing_error_is_counted_and_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    run = _running()

    def boom(*a: Any, **kw: Any) -> str:
        raise RuntimeError("db on fire")

    monkeypatch.setattr(probe_results, "route", boom)
    assert _ingest(_receipt(result_for(run))) == "probe-error"
    assert drain_counters()["errors"] == 1


def test_the_nonce_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    run = _running()
    with caplog.at_level("DEBUG"):
        _ingest(_receipt(result_for(run)))
        _ingest(_receipt(result_for(run, nonce_hex="00" * 32)), b"r2")
    assert bytes(run.nonce).hex() not in caplog.text


def test_a_result_before_the_run_is_adopted_is_counted_apart() -> None:
    run = make_run(state=ProbeRunState.SCHEDULED)
    _placed(run)
    assert _ingest(_receipt(result_for(run))) == "probe-rejected_not_launched"
