"""Cross-generation restore and failover (Genoa / Turin / Milan).

A restore or failover is a cold boot of the same measured guest on another
chip. Only the vCPU signature in the BSP VMSA differs between SNP
generations, so the launch digest differs. Nothing else is chip-family
bound: the disk keys are KBS KEKs, and the KBS binds a ticket to the exact
chip. A destination of another generation therefore needs a ticket that
carries the digest recomputed for ITS generation, pinned in the §22
allowlist first:

1. `prepare_dest_measurement`, before the KBS activate: recompute the digest
   for the destination, pin it (the class of the VM's current pin), and
   keep it on the job (`MigrationJob.dest_measurement_hex`).
2. The destination's ticket carries it (`effects.dispatch_migrate_activate`
   → `migration_ticket.remint_dest_ticket(measurement_hex=)`).
3. `record_dest_measurement`, at the commit: it becomes the VM's recorded
   measurement (`launch_record.record_relaunch`), so a later §25 hop, a KBS
   recovery re-mint and the allowlist carry-forward follow it.
4. The source's digest stays pinned until the source is reclaimed
   (`held_source_digests`) — or the VM relaunches on the destination.

Behind `VALI_FAILOVER_CROSS_GEN_ENABLED` (default off), its generations
(`VALI_FAILOVER_CROSS_GEN_GENERATIONS`: Genoa and Turin; Milan once proven),
an optional lab list of VMs (`VALI_FAILOVER_CROSS_GEN_VM_IDS`), and vali's
own launch-digest recompute (`launch_digest.is_enabled`). A VM with an
operator-pinned measurement never crosses: every relaunch replays the pin.
§25 migration and resize stay same-generation.
"""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.db.models import Q

from apps.lifecycle.models import Vm

from .models import MigrationJob, MigrationState, SourceReclaimState

log = logging.getLogger("apps.orchestration.cross_gen")

#: Oldest to newest. A move to an OLDER generation may lack instructions a
#: tenant binary built for the newer one uses (Zen5 / AVX-512 → SIGILL).
GENERATION_ORDER = {"EpycMilan": 0, "EpycGenoa": 1, "EpycTurin": 2}

OLDER_GENERATION_WARNING = (
    "A failover may restore this VM on an older CPU generation than the one it runs on. "
    "Software built for the newer CPU (e.g. -march=native, or Zen 5-only instructions; "
    "AVX-512 too when the older one is Milan) may crash there with an illegal-instruction "
    "error. Distribution packages are not affected."
)


def enabled() -> bool:
    """The flag, and vali able to recompute a digest itself."""
    from .services import launch_digest

    return bool(getattr(settings, "VALI_FAILOVER_CROSS_GEN_ENABLED", False)) and (
        launch_digest.is_enabled()
    )


def generations() -> frozenset[str]:
    """The generations a cross-generation move may join
    (`VALI_FAILOVER_CROSS_GEN_GENERATIONS`): Milan only once proven on
    hardware. `settings.py` refuses to start on a name that is no vCPU
    model (`EpycGenoa`, not `genoa`)."""
    return frozenset(getattr(settings, "VALI_FAILOVER_CROSS_GEN_GENERATIONS", ()) or ())


def allowed(vm: Vm, *between: str) -> bool:
    """Whether `vm` may be restored or failed over across `between` (the
    generations involved): `enabled()`, each of them in `generations()`, the
    VM in `VALI_FAILOVER_CROSS_GEN_VM_IDS` when that lab list is set, and no
    operator-pinned measurement on its launch."""
    from .resize import _pinned_measurement

    if not enabled() or not set(between) <= generations():
        return False
    lab = set(getattr(settings, "VALI_FAILOVER_CROSS_GEN_VM_IDS", ()) or ())
    if lab and vm.vm_id not in lab:
        return False
    return not _pinned_measurement(vm)


def pool(generation: str) -> str:
    """The failover-peer pool a miner of `generation` belongs to: one per
    region for the cross-generation ones while enabled for every VM, else
    its own — during a lab window (`VALI_FAILOVER_CROSS_GEN_VM_IDS`) only
    the listed VMs may cross, so nobody else counts the pool."""
    if getattr(settings, "VALI_FAILOVER_CROSS_GEN_VM_IDS", ()):
        return generation
    return "*" if enabled() and generation in generations() else generation


def generation(node_id: str) -> str:
    """The miner's SNP vCPU model; raises `service.StartError` when unknown."""
    from . import service

    return service._snp_generation(node_id)


def is_cross(job: MigrationJob) -> bool:
    """A restore / failover whose destination is of another generation than
    the host the VM's recorded measurement was booted on (the source). A
    generation that cannot be read is not a cross: the intake already
    checked both."""
    from . import service
    from .restore import RESTORE_KINDS

    if job.kind not in RESTORE_KINDS or job.dest_node_id == job.source_node_id:
        return False
    try:
        return generation(job.source_node_id) != generation(job.dest_node_id)
    except service.StartError:
        return False


def dest_digest(vm: Vm, dest_node_id: str) -> str:
    """vali's launch digest of the VM's recorded boot as the destination
    would measure it: the same cmdline, kernel, initrd and vCPU count the
    destination is sent (`effects._launch_paths`), the destination's chip."""
    from apps.miners.models import MinerIdentity

    from . import effects
    from .services import flavors, launch_digest, launch_record

    record = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    if record is None:
        raise effects.EffectError(f"vm {vm.vm_id!r} has no launch record")
    spec = record.spec_json or {}
    prefix, initrd_sha = launch_record.booted_artifacts(record)
    miner = MinerIdentity.objects.get(miner_id=dest_node_id)
    return launch_digest.recompute_expected_digest(
        s3_bucket=str(spec.get("s3_bucket") or ""),
        s3_key_prefix=prefix,
        kernel_sha256_hex=str(spec.get("kernel_sha256_hex") or ""),
        initrd_sha256_hex=initrd_sha,
        cmdline=effects._launch_paths(vm)["cmdline"],
        cpu_count=flavors.resolve_flavor(launch_record.booted_flavor(record)).cpu_count,
        platform_id=str(miner.platform_id or ""),
        snp_generation=miner.snp_generation,
    )


def prepare_dest_measurement(job: MigrationJob) -> None:
    """Before the KBS activate of a cross-generation restore / failover:
    the destination's digest, pinned, kept on the job. Idempotent; a no-op
    for a same-generation one. Raises before the KBS activate: a refusal of
    policy reverts the job at once (the fence is undone), a digest or pin
    failure is retried."""
    from . import service
    from .services import allowlist_pin

    if job.dest_measurement_hex:
        # Pinned already (the field is written only after the pin): this
        # state re-runs every tick while it polls the destination.
        return
    if not is_cross(job):
        return
    vm = job.vm
    source, dest = generation(job.source_node_id), generation(job.dest_node_id)
    if not allowed(vm, source, dest):
        # A refusal of policy, not a fault a retry can clear: the job fails
        # at once, before the KBS moves.
        raise service._StepFailed(
            f"cross-generation {job.kind} of {vm.vm_id!r} ({source} → {dest}) is not allowed "
            "(VALI_FAILOVER_CROSS_GEN_ENABLED / _GENERATIONS / _VM_IDS, vali's digest "
            "recompute, no pinned measurement)"
        )
    digest = dest_digest(vm, job.dest_node_id)
    source_digest = _recorded(vm)
    current = _current_ledger_row(vm)
    allowlist_pin.pin_measurement(
        measurement_hex=digest,
        measurement_class=(
            current.measurement_class
            if current is not None and current.measurement_class
            else allowlist_pin.ALLOWLIST_CLASS_TENANT
        ),
        ledger=allowlist_pin.PinLedger(
            vm_id=vm.vm_id,
            platform_id=_platform_id(job.dest_node_id),
            node_id=job.dest_node_id,
            flavor=current.flavor if current is not None else "",
            attests_resources=bool(current and current.attests_resources),
            accepts_memory_eagerly=bool(current and current.accepts_memory_eagerly),
            recomputed=True,
            launch_ref=job.job_id,
        ),
    )
    MigrationJob.objects.filter(pk=job.pk).update(
        dest_measurement_hex=digest, source_measurement_hex=source_digest
    )
    job.dest_measurement_hex, job.source_measurement_hex = digest, source_digest
    log.warning(
        "cross-generation %s %s: vm %s %s (%s) → %s (%s), destination digest %s… pinned",
        job.kind,
        job.job_id,
        vm.vm_id,
        job.source_node_id,
        source,
        job.dest_node_id,
        dest,
        digest[:16],
    )


def record_dest_measurement(job: MigrationJob) -> None:
    """At the commit, in its transaction: the destination's digest is the
    VM's recorded measurement from now on. A no-op for a same-generation
    move."""
    from .services import launch_record

    if job.dest_measurement_hex:
        launch_record.record_cross_generation(
            job.vm.vm_id,
            job.dest_measurement_hex,
            reason=f"cross-generation-{job.kind}:{job.job_id}",
        )


def held_source_digests(current: dict[str, tuple[str, Any]]) -> set[tuple[str, str]]:
    """`(vm_id, source digest)` the allowlist keeps for each VM a
    cross-generation restore / failover moved (it committed), while its
    source is not reclaimed and the destination's digest is still the VM's
    current launch (`current`, from `allowlist_pin._current_launch_pins`).
    Only that one digest: a later relaunch, or the reclaim, ends it. Belt
    and braces: an undo is same-host only and a pre-commit revert relaunches
    afresh, so nothing known needs it; it costs one digest for a bounded
    time while the source copy still exists."""
    if not current:
        return set()
    out: set[tuple[str, str]] = set()
    for vm_id, dest, source in (
        MigrationJob.objects.filter(
            vm__vm_id__in=set(current), source_reclaim_state=SourceReclaimState.PENDING
        )
        .filter(Q(state=MigrationState.DONE.value) | Q(committed_at__isnull=False))
        .exclude(dest_measurement_hex="")
        .exclude(source_measurement_hex="")
        .values_list("vm__vm_id", "dest_measurement_hex", "source_measurement_hex")
    ):
        if current[vm_id][0] == dest.lower():
            out.add((vm_id, source.lower()))
    return out


def warning(vm: Vm, peer_generations: set[str]) -> str | None:
    """The customer-facing warning when a failover could land on an older
    generation than the VM's host, else None."""
    from . import service

    try:
        own = GENERATION_ORDER.get(generation(vm.host))
    except service.StartError:
        return None
    if own is None:
        return None
    if any(GENERATION_ORDER.get(g, own) < own for g in peer_generations):
        return OLDER_GENERATION_WARNING
    return None


def _recorded(vm: Vm) -> str:
    from .services import launch_record

    return launch_record.recorded_measurement(vm.vm_id).lower()


def _current_ledger_row(vm: Vm) -> Any:
    from .models import MeasurementLedger
    from .services import launch_record

    measurement = launch_record.recorded_measurement(vm.vm_id)
    rows = MeasurementLedger.objects.filter(vm_id=vm.vm_id).order_by("-pinned_at")
    if measurement:
        row = rows.filter(launch_digest_hex__iexact=measurement).first()
        if row is not None:
            return row
    return rows.first()


def _platform_id(node_id: str) -> str:
    from apps.miners.models import MinerIdentity

    return str(
        MinerIdentity.objects.filter(miner_id=node_id).values_list("platform_id", flat=True).first()
        or ""
    )
