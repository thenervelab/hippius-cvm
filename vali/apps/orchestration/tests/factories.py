"""DB row builders for the orchestration test suite.

All builders touch the DB — callers need `@pytest.mark.django_db`.
"""

from __future__ import annotations

import secrets
import uuid

from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.models import (
    DecommissionJob,
    DecommissionState,
    LaunchJob,
    LaunchJobState,
    MigrationJob,
    MigrationState,
)


def make_service_client(name: str | None = None) -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name=name or f"actor-{uuid.uuid4().hex[:12]}"
    )


def make_vm(
    vm_id: str = "vm-1",
    *,
    state: str = VmState.ACTIVE,
    generation: int = 5,
    signing_generation: int | None = None,
    host: str = "node-src",
    lease_id: str | None = None,
    eol_nonce: bytes | None = b"\x11" * 32,
) -> Vm:
    """A `lifecycle.Vm` — `Active` on `node-src` at generation 5 by
    default.

    `eol_nonce` defaults to a fixed 32-byte value so the VM looks like a
    real LAUNCHED VM: `launch.launch_on_miner` bakes the EOL nonce into
    the measured cmdline AND persists it on the row at launch (GAP 3), so
    every VM that can reach a §24 decommission / §25 migration already
    carries one. Pass `eol_nonce=None` to model a pre-launch / unstamped
    row for the fail-closed tests.

    `signing_generation` (the immutable baked generation the guest signs EOL
    acks at) defaults to `generation` — the fresh-VM invariant (launch sets
    both to the launch gen). Pass a DISTINCT value to model a MIGRATED VM
    (`generation` bumped by the KBS fence, `signing_generation` still the
    launch gen the guest keeps signing at).
    """
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=lease_id or f"lease-{vm_id}",
        state=state,
        generation=generation,
        signing_generation=(
            generation if signing_generation is None else signing_generation
        ),
        host=host,
        lifecycle_vk=bytes(32),
        eol_nonce=eol_nonce,
    )


def make_launch_record(
    vm: Vm,
    *,
    disk_mode: str = "legacy_luks",
    cmdline: str = "ro console=ttyS0 hippius.kbs_url=vsock://2:19266",
    measured_cmdline: str | None = None,
    measurement_hex: str | None = None,
    flavor: str = "small",
    decided_by: ServiceClient | None = None,
    region: str | None = None,
) -> LaunchJob:
    """A SUCCEEDED `LaunchJob` for `vm` carrying `disk_mode` in `spec_json`.

    `region` is written into `spec_json` only when given, so the default
    record keeps the pre-region shape (what every VM launched before the
    field existed looks like) — `launch_region_for_vm` must read that as
    unconstrained.

    `service._is_golden` reads a VM's disk_mode from its most recent
    succeeded launch record; a golden decommission test builds one with
    `disk_mode="golden_verity_overlay"`. Pass `measured_cmdline` to populate
    `result_json["emit"]["measured_cmdline"]` (the persisted SNP-measured
    cmdline a §25 dest boots) — omit it to simulate a pre-fix golden record.
    `measurement_hex` populates `result_json["emit"]["measurement_hex"]` (the
    pinned SNP launch digest the §22 allowlist carry-forward reads back).
    """
    now = timezone.now()
    emit: dict[str, str] = {}
    if measured_cmdline is not None:
        emit["measured_cmdline"] = measured_cmdline
    if measurement_hex is not None:
        emit["measurement_hex"] = measurement_hex
    spec_json: dict[str, str] = {
        "disk_mode": disk_mode,
        "vm_id": vm.vm_id,
        "cmdline": cmdline,
        "flavor": flavor,
    }
    if region is not None:
        spec_json["region"] = region
    return LaunchJob.objects.create(
        job_id=secrets.token_hex(16),
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor=flavor,
        spec_json=spec_json,
        userdata_vault_path=f"secret/data/x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        result_json={"emit": emit} if emit else None,
        decided_by=decided_by or make_service_client(),
    )


def make_migration_job(
    vm: Vm,
    *,
    dest_node_id: str = "node-dst",
    state: str = MigrationState.DRAINING.value,
    decided_by: ServiceClient | None = None,
) -> MigrationJob:
    """Create a `MigrationJob` directly (for view-poll tests). The
    orchestrator state-machine tests instead drive a real job via
    `service.start_migration` + `service.tick_once`.
    """
    now = timezone.now()
    terminal = state in (MigrationState.DONE.value, MigrationState.FAILED.value)
    return MigrationJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        source_node_id=vm.host,
        dest_node_id=dest_node_id,
        source_gen=vm.generation,
        new_gen=vm.generation + 1,
        state=state,
        phase_started_at=now,
        finished_at=now if terminal else None,
        decided_by=decided_by or make_service_client(),
    )


def make_decommission_job(
    vm: Vm,
    *,
    state: str = DecommissionState.DRAINING.value,
    decided_by: ServiceClient | None = None,
) -> DecommissionJob:
    """Create a `DecommissionJob` directly (for view-poll tests)."""
    now = timezone.now()
    terminal = state in (
        DecommissionState.DONE.value,
        DecommissionState.FAILED.value,
    )
    return DecommissionJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        state=state,
        phase_started_at=now,
        finished_at=now if terminal else None,
        decided_by=decided_by or make_service_client(),
    )
