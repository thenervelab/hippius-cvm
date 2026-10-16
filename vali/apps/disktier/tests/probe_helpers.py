"""Shared helpers for the disk-probe orchestrator tests (R1): a stub
launch intake, scripted node gates, and run / result builders. No
network, no Vault, no subprocess."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.disktier import probe
from apps.disktier.models import DiskProbeRun, ProbeRunState, ProbeTrigger
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.scheduler.tests.factories import node_id
from apps.telemetry.verifier import DiskProbeResult, DiskProbeTarget

USER = "4242"
TENANT = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
OWNER = f"{USER}:{TENANT}"
NODE = node_id(1)
NODE2 = node_id(2)
NODE3 = node_id(3)
CHIP = "ab" * 32
NOW = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

#: A v1 result that clears every nvme floor.
V1_NVME = {
    "seq_read_mbps": 2000,
    "seq_write_mbps": 1500,
    "rr_iops": 60_000,
    "rr_p99_us": 2_000,
    "rw_iops": 30_000,
    "rw_p99_us": 3_000,
    "qd1_p50_us": 90,
    "qd1_p99_us": 400,
}


def gates(
    *,
    eligible: tuple[str, ...] = (NODE,),
    dispatchable: tuple[str, ...] | None = None,
    free: dict[str, int] | None = None,
    booting: dict[str, int] | None = None,
    caps: dict[str, int] | None = None,
    fleet_cap: int = 3,
    chips: dict[str, str] | None = None,
) -> probe._Gates:
    nodes = tuple(dispatchable if dispatchable is not None else eligible)
    return probe._Gates(
        dispatchable=frozenset(nodes),
        eligible=frozenset(eligible),
        chip_by_node=chips if chips is not None else {n: CHIP for n in nodes},
        free_by_node=free if free is not None else {n: 10 for n in nodes},
        booting=booting or {},
        boot_cap_by_node=caps or {},
        fleet_boot_cap=fleet_cap,
    )


@dataclass
class FakeIntake:
    """`launch_jobs.start_launch` stand-in: records the call and writes the
    `LaunchJob` the real intake would, or raises `refuse`."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    refuse: str = ""

    def __call__(
        self,
        *,
        intent: dict[str, Any],
        userdata: bytes,
        decided_by: Any,
        cdn_node: bool = False,
        disk_probe: bool = False,
    ) -> LaunchJob:
        from apps.orchestration.launch_jobs import LaunchIntentError

        self.calls.append(
            {"intent": dict(intent), "userdata": userdata, "disk_probe": disk_probe}
        )
        if self.refuse:
            raise LaunchIntentError("refused by the test", self.refuse)
        return LaunchJob.objects.create(
            job_id=secrets.token_hex(8),
            vm_id=intent["vm_id"],
            tenant_id=intent["tenant_id"],
            flavor=intent["flavor"],
            spec_json={"vm_id": intent["vm_id"]},
            userdata_vault_path=f"x/{intent['vm_id']}/userdata-intake",
            userdata_vault_version=1,
            kek_vault_path=f"x/{intent['vm_id']}/luks-kek",
            state=LaunchJobState.QUEUED.value,
            phase_started_at=NOW,
            decided_by=decided_by,
        )


@pytest.fixture
def probe_on(settings: Any, monkeypatch: pytest.MonkeyPatch) -> FakeIntake:
    """The probe on, one owner, the image ready, a stub intake, and one
    eligible node with room."""
    from apps.orchestration import launch_jobs

    settings.VALI_DISK_PROBE_ENABLED = True
    settings.VALI_DISK_PROBE_OWNERS = [OWNER]
    settings.VALI_DISK_PROBE_MAX_CONCURRENT = 3
    intake = FakeIntake()
    monkeypatch.setattr(launch_jobs, "start_launch", intake)
    monkeypatch.setattr(probe, "_image_ready", lambda: True)
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates())
    return intake


def make_run(
    *,
    node: str = NODE,
    state: str = ProbeRunState.RUNNING,
    pool: str = "default",
    trigger: str = ProbeTrigger.ONBOARDING,
    scheduled_at: datetime = NOW - timedelta(hours=10),
    finished_at: datetime | None = None,
    torn_down_at: datetime | None = None,
    teardown_after: datetime | None = None,
    deadline_at: datetime | None = None,
    owner: str = USER,
    classified_tier: str = "",
    failure_reason: str = "",
    vm_id: str | None = None,
    launch_job_id: str = "",
) -> DiskProbeRun:
    target: dict[str, Any] = {"slot": "os", "kind": "pool", "pool_id": pool, "profile": "v1"}
    if classified_tier:
        target["classified_tier"] = classified_tier
    return DiskProbeRun.objects.create(
        nonce=secrets.token_bytes(32),
        vm_id=vm_id or f"hipc-{owner}-{secrets.token_hex(4)}",
        miner_node_id=node,
        chip_id=CHIP,
        owner=owner,
        trigger=trigger,
        state=state,
        flavor="medium",
        os_pool_id=pool,
        start_delay_s=6 * 3600,
        targets=[target],
        scheduled_at=scheduled_at,
        launched_at=scheduled_at if state != ProbeRunState.SCHEDULED else None,
        deadline_at=deadline_at,
        finished_at=finished_at,
        torn_down_at=torn_down_at,
        teardown_after=teardown_after,
        failure_reason=failure_reason,
        launch_job_id=launch_job_id,
    )


def result_for(
    run: DiskProbeRun,
    *,
    metrics: dict[str, int] | None = None,
    error: str = "",
    nonce_hex: str | None = None,
    run_id_hex: str | None = None,
    vm_id: str | None = None,
    slots: tuple[str, ...] = ("os",),
    profile: str = "v1",
) -> DiskProbeResult:
    return DiskProbeResult(
        run_id_hex=run_id_hex or run.run_id.hex,
        nonce_hex=nonce_hex or bytes(run.nonce).hex(),
        vm_id=vm_id or run.vm_id,
        vcpus=2,
        kernel="6.8.0",
        release_version=5,
        started_at=1_000,
        finished_at=1_300,
        targets=tuple(
            DiskProbeTarget(
                slot=slot,
                profile=profile,
                metrics=dict(V1_NVME if metrics is None else metrics) if not error else {},
                hist_qd1=(0,) * 32,
                error=error,
            )
            for slot in slots
        ),
    )


def other_uuid_hex() -> str:
    return uuid.uuid4().hex
