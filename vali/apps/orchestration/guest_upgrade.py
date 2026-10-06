"""Guest upgrade — move ONE VM onto a guest components build.

Design of record: `docs/design/guest-component-rollout.md`.

WHAT AN UPGRADE IS. A relaunch of the VM on the miner that holds its disks,
from another initrd: the VM's base initrd with a guest components release
appended (`GuestInitrdBuild`). Same kernel, same dm-verity base, same
overlay, same KEK, same anti-rollback counter. The measurement is new (the
initrd is measured), so it is the resize's relaunch with the initrd changed
instead of the flavor, and it reuses the same pieces: the power API's stop
and start (`_reboot_recovery_relaunch`, so the §22 auto-pin, the KBS
re-register at the VM's generation, `require_existing_disks` and the
launch-record update all carry over), and the launch record's CAS initrd
swap (`launch_record.swap_initrd`). Nothing here talks to a miner directly.

WHAT PROVES THE TARGET BOOTED. Not the launch record (mutable, and written
from what the relaunch path accepted) and not the miner's word: every
launch attempt is linked to the measurement vali itself PINNED for it — the
`MeasurementLedger` row the launch writes before it registers or dispatches
anything, tagged with the attempt's id (`launch_ref`) and marked
`recomputed` only when it is vali's own recompute of the boot it built
(target initrd, measured cmdline with its fresh nonces, vCPUs, pinned OVMF;
C2 ENFORCE, required at admission AND before every launch). The gate is a
KBS-verified live attestation of one of the job's recomputed pins for the
phase's set, verified after that attempt started — any of them: a retry the
miner answers `already-launched` runs an earlier attempt's boot. A guest
the miner kept from before — or any other boot — attests another
measurement and never moves the job.

THE STATES (`GuestUpgradeState`):

- `pending`: waits for `not_before` (the tenant's window). Holds nothing.
  Leaving it is decided under the VM row lock, against every other
  operation (`_busy`), on the locked row's host and power state; in the
  same transaction the VM's required epoch is raised to the target's (G3)
  and the CAS to `stopping` must win, or the whole decision rolls back.
  A STOPPED VM stays pending (its next power start is a plain start).
- `stopping`: the job's own power stop; done when the miner reports the
  domain DOWN.
- `launching`: the record is swapped to the target, then a relaunch with
  the KBS `supersede` perm until one attempt's register was accepted with
  it (`MeasurementLedger.superseded_at_register`).
- `verifying`: the gate above. A domain that goes DOWN here (a miner
  reboot) gets ONE `recover` relaunch on the same set (claimed before it is
  dispatched).
- `soaking`: the attempt's measurement keeps attesting for the soak. For a
  release with health checks (`GuestComponentRelease.health_mask`, gate
  condition 4): every sample from the gate sample to one past the soak's
  end passes them, from the gate sample's keepalive instance, with no new
  failing tick latched (`_soak_verdict`).
- `done`: the VM's `attested_epoch` is the target's.
- `rolling_back`: a NEW forward launch of the previous set — only when that
  set's epoch is at least the VM's required epoch. Same attempt discipline
  and gate.
- `parking`: the job failed with a boot of unknown health possibly up: it
  stops the domain and confirms it DOWN before releasing the VM to
  `park_to` (`upgrade_blocked` / `failed`). Past its deadline it keeps
  holding and alerting; only an operator releases it without the DOWN
  (`release_parked`, audited).
- terminal: `done`, `rolled_back`, `failed`, `upgrade_blocked`, `cancelled`.

WHY IT FAILED. A target that did not come up records a machine-readable
`outcome` (`OUTCOMES`) next to the prose `reason`: what the guest's own
samples said (`health-failed` with the missing checks, `health-latched`,
`guest-restarted`, `resources-mismatch`), what never came (`no-sample`:
nothing of the target attested — a guest that does not boot, or a miner
withholding its samples), what came instead (`measurement-mismatch`), or
what the miner refused (`dispatch-failed`, `stop-timeout`, ...).
`OUTCOME_SUSPECT` says whose side each one points at.

AFTER `upgrade_blocked`. The VM is stopped on the target (or still on the
previous set if nothing moved) and nothing below its required epoch is
started again. Two operator paths, both through the normal launch path (the
floor, C2 ENFORCE, the auto-pin and the KBS supersede all apply):

- `recover_start_on_target`: an audited start of the TARGET, ungated — the
  tenant gets the VM back, the operator judges its health;
- a retry (`start_guest_upgrade` on a VM whose latest job is blocked): the
  same build again, or a newer release. It may restart the VM that job
  left stopped, and a retry of the same build keeps that job's previous
  set, so a failure blocks again instead of "rolling back" onto the target.

RESTART-SAFETY. Every launch is preceded by a `GuestUpgradeAttempt` row;
before any new effect the newest open attempt is RECONCILED: its pin says
what it would measure, the pin's `launched_at`, the record, or the miner's
domain state say whether it was accepted. An attempt with nothing accepted
and the domain DOWN stays OPEN until its dispatch settled
(`VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S`) — an answer lost on the way back
may hide a launch still landing. A tick that dies anywhere resumes from the
stored state without dispatching twice.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

from . import effects
from .models import (
    TERMINAL_GUEST_UPGRADE_STATES,
    TERMINAL_LAUNCH_STATES,
    GuestInitrdBuild,
    GuestUpgradeAttempt,
    GuestUpgradeAttemptKind,
    GuestUpgradeJob,
    GuestUpgradeState,
    LaunchJob,
    MeasurementLedger,
)
from .service import StartError, _has_active_job
from .services import guest_components, launch_record

log = logging.getLogger("apps.orchestration.guest_upgrade")

S = GuestUpgradeState
K = GuestUpgradeAttemptKind

#: Relaunches the miner answered "rejected" before the job gives up on a set
#: (pin-busy refusals are retried until the state's deadline).
MAX_RELAUNCH_REJECTIONS = 3

_GOLDEN = "golden_verity_overlay"

#: Marks a parking job past its deadline in `reason` (the alert's key).
PARKING_OVERDUE = "parking-overdue: domain NOT confirmed down"

#: Attempt outcomes.
ACCEPTED = "accepted"
LOST = "lost"  # never dispatched, or the miner did not keep it

#: Job outcomes — why the target did not come up (`GuestUpgradeJob.outcome`).
#: A v4 sample of the target's own measurement failed a health check
#: (`reason` names the missing checks), or reported another release / epoch.
HEALTH_FAILED = "health-failed"
#: The guest counted failing ticks the samples never showed (a failing
#: sample withheld or lost on the way).
HEALTH_LATCHED = "health-latched"
#: The keepalive restarted under the soak (a guest reboot or crash).
GUEST_RESTARTED = "guest-restarted"
#: The guest attested other resources than its flavor's (gate condition 3).
RESOURCES_MISMATCH = "resources-mismatch"
#: Nothing of the target attested in time: a guest that does not boot, or
#: a miner holding its samples back.
NO_SAMPLE = "no-sample"
#: The VM attested, but not one of the job's own measurements: another boot
#: runs (the miner kept or started something else).
MEASUREMENT_MISMATCH = "measurement-mismatch"
#: The miner refused or rejected the relaunch (or the recover relaunch).
DISPATCH_FAILED = "dispatch-failed"
#: The miner never confirmed the stop.
STOP_TIMEOUT = "stop-timeout"
#: No relaunch was accepted before the deadline.
LAUNCH_TIMEOUT = "launch-timeout"
#: No relaunch without launch-digest ENFORCE.
C2_NOT_ENFORCED = "c2-not-enforced"
#: The VM left its miner (or its active state) under the job.
VM_MOVED = "vm-moved"

#: Whose side an outcome points at, for the alerts: `release` (our build),
#: `miner` (possibly an obstructing miner), `vali` (our configuration),
#: `fleet` (an operation elsewhere). A miner can always fake a "release"
#: outcome by breaking the guest's disk or network — the label is a first
#: lead, not a verdict.
OUTCOME_SUSPECT: dict[str, str] = {
    HEALTH_FAILED: "release",
    HEALTH_LATCHED: "release",
    GUEST_RESTARTED: "release",
    RESOURCES_MISMATCH: "miner",
    NO_SAMPLE: "miner",
    MEASUREMENT_MISMATCH: "miner",
    DISPATCH_FAILED: "miner",
    STOP_TIMEOUT: "miner",
    LAUNCH_TIMEOUT: "miner",
    C2_NOT_ENFORCED: "vali",
    VM_MOVED: "fleet",
}
OUTCOMES: frozenset[str] = frozenset(OUTCOME_SUSPECT)

#: The recovery actions (`recover`).
RECOVER_START_ON_TARGET = "start-on-target"
RECOVERY_ACTIONS: frozenset[str] = frozenset({RECOVER_START_ON_TARGET})
#: The terminal states an operator recovers a VM from.
RECOVERABLE_STATES: frozenset[str] = frozenset({S.UPGRADE_BLOCKED.value, S.FAILED.value})


def enabled() -> bool:
    return bool(getattr(settings, "VALI_GUEST_UPGRADE_ENABLED", False))


def _c2_enforced() -> bool:
    """The gate leans on the measurement vali pins being its OWN recompute
    of the boot it built — true only under launch-digest ENFORCE."""
    from .services import launch_digest as launch_digest_svc

    return bool(launch_digest_svc.enforce() and launch_digest_svc.is_enabled())


def _timeout_s(name: str, default: float) -> float:
    return float(getattr(settings, name, default))


def _state_timeout(job: GuestUpgradeJob) -> float:
    return {
        S.STOPPING.value: _timeout_s("VALI_GUEST_UPGRADE_STOP_TIMEOUT_S", 1500.0),
        S.LAUNCHING.value: _timeout_s("VALI_GUEST_UPGRADE_LAUNCH_TIMEOUT_S", 1800.0),
        S.VERIFYING.value: _timeout_s("VALI_GUEST_UPGRADE_GUEST_TIMEOUT_S", 1200.0),
        S.SOAKING.value: _timeout_s("VALI_GUEST_UPGRADE_SOAK_S", 900.0) + 1200.0,
        S.ROLLING_BACK.value: _timeout_s("VALI_GUEST_UPGRADE_ROLLBACK_TIMEOUT_S", 2400.0),
        S.PARKING.value: _timeout_s("VALI_GUEST_UPGRADE_PARK_TIMEOUT_S", 1500.0),
    }.get(job.state, 0.0)


def _soak_s() -> float:
    return _timeout_s("VALI_GUEST_UPGRADE_SOAK_S", 900.0)


def _fresh_s() -> float:
    """An attestation this recent says the guest is up now: two keepalive
    intervals (vali's coverage window)."""
    return _timeout_s("VALI_GUEST_UPGRADE_ATTESTATION_FRESH_S", 600.0)


def _pacing_s() -> float:
    return _timeout_s("VALI_GUEST_UPGRADE_DISPATCH_PACING_S", 60.0)


# ─── admission ──────────────────────────────────────────────────────


def _record(vm: Vm) -> Any:
    return launch_record.latest_record(vm.vm_id)


def _spec_pair(record: Any) -> tuple[str, str]:
    spec = (record.spec_json or {}) if record is not None else {}
    return str(spec.get("s3_key_prefix") or ""), str(spec.get("initrd_sha256_hex") or "").lower()


def _same_base(spec: dict[str, Any], build: GuestInitrdBuild) -> bool:
    return (
        str(spec.get("kernel_sha256_hex") or "").lower(),
        str(spec.get("rootfs_img_sha256_hex") or "").lower(),
        str(spec.get("rootfs_verity_sha256_hex") or "").lower(),
        str(spec.get("verity_root_hash_hex") or "").lower(),
    ) == (
        build.kernel_sha256,
        build.rootfs_img_sha256,
        build.rootfs_verity_sha256,
        build.verity_root_hash,
    )


def _on_this_base(initrd: str, build: GuestInitrdBuild) -> bool:
    """`initrd` is the build's base initrd, or another registered build of
    the same base (a VM on release N moving to N+1)."""
    if initrd == build.base_initrd_sha256:
        return True
    other = guest_components.build_for_initrd(initrd)
    return other is not None and (
        other.kernel_sha256,
        other.rootfs_img_sha256,
        other.rootfs_verity_sha256,
        other.verity_root_hash,
        other.base_initrd_sha256,
    ) == (
        build.kernel_sha256,
        build.rootfs_img_sha256,
        build.rootfs_verity_sha256,
        build.verity_root_hash,
        build.base_initrd_sha256,
    )


def anchor_job(vm: Vm) -> GuestUpgradeJob | None:
    """`vm`'s latest guest upgrade job that says where the VM stands: a
    cancelled job never moved anything (only a pending job is cancelled),
    and a pending retry has not taken the VM yet — the job it retries still
    does."""
    return (
        GuestUpgradeJob.objects.filter(vm=vm)
        .exclude(state=S.CANCELLED.value)
        .exclude(state=S.PENDING.value, retry_of__isnull=False)
        .order_by("-started_at")
        .first()
    )


def blocked_job(vm: Vm) -> GuestUpgradeJob | None:
    """`vm`'s anchor job when it ended `upgrade_blocked` — the job a new
    upgrade of the VM retries."""
    job = anchor_job(vm)
    return job if job is not None and job.state == S.UPGRADE_BLOCKED else None


def _same_build_retry(retry_of: GuestUpgradeJob | None, build: GuestInitrdBuild) -> bool:
    return retry_of is not None and retry_of.target_id == build.id


def _from_pair(job: GuestUpgradeJob, record: Any) -> tuple[str, str]:
    """The `(prefix, initrd)` the launch record may name when the job takes
    the VM — what its swap moves FROM: the previous set, or for a retry of
    the same build the target itself (the blocked job's swap is kept; a
    blocked job that never swapped left the previous set)."""
    target = (job.target.s3_key_prefix, job.target.initrd_sha256)
    if _same_build_retry(job.retry_of, job.target) and _spec_pair(record) == target:
        return target
    return job.previous_prefix, job.previous_initrd_sha256


def _blocked_swap(record: Any, retry_of: GuestUpgradeJob | None) -> bool:
    """The record's pending swap is the blocked job's own: the spec names
    that job's target, the running boot (none since) its previous set."""
    if retry_of is None:
        return False
    return _spec_pair(record) == (
        retry_of.target.s3_key_prefix,
        retry_of.target.initrd_sha256,
    ) and launch_record.booted_artifacts(record) == (
        retry_of.previous_prefix,
        retry_of.previous_initrd_sha256,
    )


def _refusal(
    vm: Vm,
    build: GuestInitrdBuild,
    *,
    rollback: bool,
    retry_of: GuestUpgradeJob | None = None,
) -> tuple[str, str] | None:
    """`(category, detail)` when `vm` cannot be upgraded onto `build`.
    `retry_of`: the `upgrade_blocked` job the upgrade retries — the VM may
    already name its target, with that job's swap still pending."""
    if not _c2_enforced():
        return "c2-not-enforced", "a guest upgrade needs launch-digest ENFORCE (its gate does)"
    if vm.state != VmState.ACTIVE:
        return "vm-not-active", f"vm is {vm.state!r}"
    if not vm.host:
        return "no-bound-miner", "vm has no bound miner"
    if build.withdrawn_at is not None or build.release.withdrawn_at is not None:
        return "build-withdrawn", f"build {build.s3_key_prefix} is withdrawn"
    record = _record(vm)
    if record is None:
        return "no-launch-record", "vm has no launch record"
    spec = record.spec_json or {}
    if spec.get("disk_mode") != _GOLDEN:
        return "not-golden", "only golden_verity_overlay VMs take guest releases"
    if str(spec.get("measurement_hex") or "").strip():
        return "measurement-pinned", "the launch record pins a measurement"
    if spec.get("auto_pin_allowlist") is not True:
        return "auto-pin-off", "the relaunch's new measurement must be auto-pinned"
    if str(spec.get("s3_bucket") or "") != build.s3_bucket:
        return "bucket-mismatch", "the vm's set and the build live in different buckets"
    if not _same_base(spec, build):
        return "other-base", "the build is for another base (kernel / rootfs / verity)"
    current = _spec_pair(record)[1]
    if current == build.initrd_sha256 and not _same_build_retry(retry_of, build):
        return "already-on-target", "the vm's launch record already names this build"
    if current != build.initrd_sha256 and not _on_this_base(current, build):
        return "unknown-initrd", "the vm boots an initrd that is neither the base nor a build of it"
    if launch_record.BOOTED_ARTIFACTS_KEY in (
        (record.result_json or {}).get("emit") or {}
    ) and not _blocked_swap(record, retry_of):
        return "swap-pending", "an earlier initrd swap is not relaunched yet"
    target_epoch = int(build.release.security_epoch)
    if target_epoch < guest_components.required_epoch(vm.vm_id):
        return "below-floor", "the build is below the vm's required epoch"
    current_build = guest_components.build_for_initrd(current)
    current_version = int(current_build.release_id) if current_build is not None else 0
    current_epoch = guest_components.epoch_of_initrd(current)
    if not rollback and (target_epoch < current_epoch or int(build.release_id) < current_version):
        return (
            "downgrade",
            "the build is older than the one the vm runs (an explicit rollback only)",
        )
    if _has_active_job(vm):
        return "job-in-flight", "another operation holds the vm"
    if LaunchJob.objects.filter(vm_id=vm.vm_id).exclude(state__in=TERMINAL_LAUNCH_STATES).exists():
        return "job-in-flight", "the vm is still launching"
    return None


def build_for_vm(vm: Vm, release: int) -> GuestInitrdBuild | None:
    """The registered build of `release` for `vm`'s base (kernel, rootfs,
    verity root of its launch record, and the base initrd of the initrd it
    names) — whichever initramfs family it is. Never another base's: an
    initrd-only rebuild of a bake (#1314) and the bake itself are two bases."""
    record = _record(vm)
    if record is None:
        return None
    spec = record.spec_json or {}
    base_initrd = guest_components.base_initrd_of(str(spec.get("initrd_sha256_hex") or ""))
    if not base_initrd:
        return None
    return (
        GuestInitrdBuild.objects.select_related("release")
        .filter(
            release_id=release,
            base_initrd_sha256=base_initrd,
            kernel_sha256=str(spec.get("kernel_sha256_hex") or "").lower(),
            rootfs_img_sha256=str(spec.get("rootfs_img_sha256_hex") or "").lower(),
            rootfs_verity_sha256=str(spec.get("rootfs_verity_sha256_hex") or "").lower(),
            verity_root_hash=str(spec.get("verity_root_hash_hex") or "").lower(),
        )
        .first()
    )


def components_of(vm: Vm) -> dict[str, Any]:
    """What `vm` runs and may move to: the release its launch record boots
    (`None` on a bare base), its epochs, the newest release with a build
    for its base, and the upgrade it waits for or runs."""
    from .models import GuestComponentRelease, VmGuestComponents

    record = _record(vm)
    # The release the VM BOOTED: a swapped record not relaunched yet keeps
    # the running boot under `booted_artifacts`.
    current = (
        guest_components.build_for_initrd(launch_record.booted_artifacts(record)[1].lower())
        if record
        else None
    )
    epochs = VmGuestComponents.objects.filter(vm=vm).first()
    newest = None
    for release in GuestComponentRelease.objects.filter(withdrawn_at__isnull=True).order_by(
        "-version"
    ):
        build = build_for_vm(vm, int(release.version))
        if build is not None and build.withdrawn_at is None:
            newest = build
            break
    job = (
        GuestUpgradeJob.objects.filter(vm=vm)
        .exclude(state__in=TERMINAL_GUEST_UPGRADE_STATES)
        .select_related("target")
        .first()
    )
    anchor = anchor_job(vm)
    stuck = anchor if anchor is not None and anchor.state in RECOVERABLE_STATES else None
    return {
        "vm_id": vm.vm_id,
        "release": int(current.release_id) if current is not None else None,
        "security_epoch": int(current.release.security_epoch) if current is not None else 0,
        "build_prefix": current.s3_key_prefix if current is not None else None,
        "required_epoch": int(epochs.required_epoch) if epochs else 0,
        "attested_epoch": int(epochs.attested_epoch) if epochs else 0,
        "newest_release": int(newest.release_id) if newest is not None else None,
        "newest_security_epoch": (
            int(newest.release.security_epoch) if newest is not None else None
        ),
        "upgrade": serialize_job(job) if job is not None else None,
        "needs_operator": serialize_job(stuck) if stuck is not None else None,
    }


def serialize_job(job: GuestUpgradeJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "release": int(job.target.release_id),
        "build_prefix": job.target.s3_key_prefix,
        "state": job.state,
        "not_before": job.not_before.isoformat(),
        "previous_prefix": job.previous_prefix,
        "previous_epoch": job.previous_epoch,
        "node_id": job.node_id,
        "reason": job.reason or None,
        "outcome": job.outcome or None,
        "suspect": OUTCOME_SUSPECT.get(job.outcome),
        "retry_of": job.retry_of.job_id if job.retry_of_id else None,
        "recoveries": list(job.recoveries or []),
        "decided_by": job.decided_by.name,
        "phase_started_at": job.phase_started_at.isoformat(),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "version": job.version,
    }


def _doomed(job: GuestUpgradeJob, vm: Vm) -> tuple[str, str] | None:
    """Why a PENDING job can never run (its target withdrawn, the VM no
    longer eligible), or `None`. Another operation holding the VM is not a
    reason: the job waits for it."""
    refusal = _refusal(vm, job.target, rollback=True, retry_of=job.retry_of)
    if refusal is None or refusal[0] == "job-in-flight":
        return None
    return refusal


def reschedule(job: GuestUpgradeJob, not_before: datetime) -> GuestUpgradeJob:
    """Move a PENDING job's window. Raises `StartError` once it left
    `pending` (it holds the VM from then on), or — cancelling it — when it
    can no longer run: a doomed job must not be pushed further out, nor
    block a replacement."""
    if job.state != S.PENDING:
        raise StartError(
            f"guest upgrade {job.job_id} is {job.state}, no longer pending", "not-pending"
        )
    doomed = _doomed(job, Vm.objects.get(pk=job.vm_id))
    if doomed is not None:
        _cas(job, S.CANCELLED.value, reason=f"{doomed[0]}: {doomed[1]}"[:256])
        raise StartError(f"the pending upgrade can no longer run: {doomed[1]}", doomed[0])
    if not _patch(job, not_before=not_before):
        raise StartError(f"guest upgrade {job.job_id} moved — retry", "not-pending")
    return job


def cancel_if_doomed(job: GuestUpgradeJob) -> bool:
    """Cancel a PENDING job that can no longer run; `True` if it did."""
    if job.state != S.PENDING:
        return False
    doomed = _doomed(job, Vm.objects.get(pk=job.vm_id))
    if doomed is None:
        return False
    return _cas(job, S.CANCELLED.value, reason=f"{doomed[0]}: {doomed[1]}"[:256])


def cancel_pending(job: GuestUpgradeJob, *, by: str) -> GuestUpgradeJob:
    """Cancel a PENDING job (nothing moved yet). Raises `StartError` once it
    left `pending`: from then on only the job itself releases the VM."""
    if job.state != S.PENDING or not _cas(
        job, S.CANCELLED.value, reason=f"cancelled by {by}"[:256]
    ):
        raise StartError(
            f"guest upgrade {job.job_id} is {job.state}, no longer pending", "not-pending"
        )
    job.refresh_from_db()
    return job


def start_guest_upgrade(
    *,
    vm: Vm,
    build: GuestInitrdBuild,
    decided_by: Any,
    not_before: datetime | None = None,
    rollback: bool = False,
    rollout: Any = None,
    wave: int | None = None,
) -> GuestUpgradeJob:
    """Admit an upgrade of `vm` onto `build` (job `pending`). Raises
    [`StartError`] — every refusal happens HERE, before anything moves.

    On a VM whose latest job ended `upgrade_blocked`, the job RETRIES it
    (`retry_of`): the same build is admitted although the record names it,
    and keeps the blocked job's previous set (what was last attested before
    it) — so a failing retry blocks again, the floor unchanged."""
    refusal = _refusal(vm, build, rollback=rollback, retry_of=blocked_job(vm))
    if refusal:
        raise StartError(refusal[1], refusal[0])
    now = timezone.now()
    try:
        with transaction.atomic():
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            retry_of = blocked_job(locked)
            refusal = _refusal(locked, build, rollback=rollback, retry_of=retry_of)
            if refusal:
                raise StartError(refusal[1], refusal[0])
            prefix, initrd = _spec_pair(_record(locked))
            previous_epoch = guest_components.epoch_of_initrd(initrd)
            if _same_build_retry(retry_of, build):
                prefix, initrd = retry_of.previous_prefix, retry_of.previous_initrd_sha256
                previous_epoch = retry_of.previous_epoch
            job = GuestUpgradeJob.objects.create(
                job_id=f"gu-{secrets.token_hex(12)}",
                vm=locked,
                target=build,
                previous_prefix=prefix,
                previous_initrd_sha256=initrd,
                previous_epoch=previous_epoch,
                retry_of=retry_of,
                node_id=locked.host,
                prior_power_state=locked.power_state,
                state=S.PENDING.value,
                not_before=not_before or now,
                phase_started_at=now,
                decided_by=decided_by,
                rollout=rollout,
                wave=wave,
            )
    except IntegrityError as exc:
        raise StartError("vm already has a guest upgrade in flight", "job-in-flight") from exc
    log.info(
        "guest upgrade %s admitted: vm=%s → v%s (%s), not before %s%s",
        job.job_id,
        vm.vm_id,
        build.release_id,
        build.s3_key_prefix,
        job.not_before.isoformat(),
        f", retrying {job.retry_of.job_id}" if job.retry_of is not None else "",
    )
    return job


# ─── the state machine ──────────────────────────────────────────────


class _Retry(Exception):
    """Not this tick; try again next tick (until the state's deadline)."""


class _CasLost(Exception):
    """The job moved under this tick: roll the decision back."""


def _cas(job: GuestUpgradeJob, next_state: str, **patch: Any) -> bool:
    now = timezone.now()
    fields: dict[str, Any] = {
        "state": next_state,
        "version": job.version + 1,
        "phase_started_at": now,
        **patch,
    }
    if next_state != job.state:
        fields.setdefault("attempts", 0)
        fields.setdefault("attempted_at", None)
    if next_state in TERMINAL_GUEST_UPGRADE_STATES:
        fields["finished_at"] = now
    updated = GuestUpgradeJob.objects.filter(
        id=job.id, version=job.version, state=job.state
    ).update(**fields)
    if updated:
        log.info("guest upgrade %s: %s → %s", job.job_id, job.state, next_state)
    return updated == 1


def _patch(job: GuestUpgradeJob, **patch: Any) -> bool:
    updated = GuestUpgradeJob.objects.filter(
        id=job.id, version=job.version, state=job.state
    ).update(version=F("version") + 1, **patch)
    if updated:
        job.version += 1
        for k, v in patch.items():
            setattr(job, k, v)
    return updated == 1


def _claim_dispatch(job: GuestUpgradeJob) -> bool:
    """Count one power dispatch BEFORE it is sent; refuse inside the
    pacing window."""
    now = timezone.now()
    if job.attempted_at is not None and (now - job.attempted_at).total_seconds() < _pacing_s():
        return False
    return _patch(job, attempts=job.attempts + 1, attempted_at=now)


def _terminal(job: GuestUpgradeJob, state: str, reason: str = "", **patch: Any) -> None:
    _cas(job, state, reason=reason[:256], **patch)
    level = logging.INFO if state == S.DONE else logging.WARNING
    outcome = patch.get("outcome", job.outcome)
    log.log(
        level,
        "guest upgrade %s %s (vm=%s, outcome=%s): %s",
        job.job_id,
        state,
        job.vm.vm_id,
        outcome or "-",
        reason,
    )


def _busy(vm: Vm) -> str:
    """Why the job cannot take the VM now (`""` = it can). Decided under the
    VM row lock — the lock every other intake decides under."""
    from apps.backup.models import ACTIVE_RUN_STATUSES, BackupRun

    from .services import power

    if _has_active_job(vm, ignore_guest_upgrade=True):
        return "job-in-flight"
    if LaunchJob.objects.filter(vm_id=vm.vm_id).exclude(state__in=TERMINAL_LAUNCH_STATES).exists():
        return "launch-in-flight"
    for marker in (VmPowerState.STOPPING, VmPowerState.STARTING):
        if power._live_marker(vm, marker):
            return f"power-op-in-flight:{marker}"
    if power._recovery_relaunch_in_flight(vm):
        return "recovery-relaunch-in-flight"
    if BackupRun.objects.filter(vm=vm, status__in=ACTIVE_RUN_STATUSES).exists():
        return "backup-in-flight"
    return ""


def _stale_marker(vm: Vm, marker: str) -> bool:
    from .services import power

    return (
        vm.power_state == marker
        and vm.power_state_at is not None
        and timezone.now() - vm.power_state_at >= power.STALE_POWER_MARKER
    )


def _domain_down(vm: Vm) -> bool:
    """`True` only on a definite DOWN from the miner; unknown retries."""
    running = effects.poll_domain_running(vm)
    if running is None:
        raise _Retry("domain state unknown")
    return running is False


def _settle_observed_down(vm: Vm) -> bool:
    """Record `stopped` for a VM the books say runs but whose miner reports
    the domain DOWN (a miner reboot under the job). A CAS on `running`."""
    now = timezone.now()
    if not Vm.objects.filter(pk=vm.pk, power_state=VmPowerState.RUNNING).update(
        power_state=VmPowerState.STOPPED, power_state_at=now
    ):
        return False
    vm.power_state, vm.power_state_at = VmPowerState.STOPPED, now
    log.warning("guest upgrade: vm=%s recorded stopped — the miner reports it down", vm.vm_id)
    return True


def _stop(job: GuestUpgradeJob, vm: Vm) -> None:
    """One job-owned power stop (claimed and paced)."""
    from .services import power

    if not _claim_dispatch(job):
        return
    try:
        power.stop_vm(vm, by_guest_upgrade=job.job_id)
    except power.PowerOpRefused as exc:
        raise _Retry(f"stop refused: {exc.reason}") from exc
    except Exception as exc:  # noqa: BLE001 — the order may have landed; re-read next tick
        raise _Retry(f"stop dispatch failed: {exc}") from exc


# ── attempts ────────────────────────────────────────────────────────


def _pin_of(attempt: GuestUpgradeAttempt) -> MeasurementLedger | None:
    """The measurement vali pinned for `attempt` — the ledger row its launch
    tagged with the attempt's id. None: no pin recorded (the launch did not
    get that far, or its best-effort ledger write failed)."""
    return (
        MeasurementLedger.objects.filter(launch_ref=str(attempt.id)).order_by("pinned_at").first()
    )


def _settle_s() -> float:
    """How long a dispatch may still land after vali last acted on it (the
    Edge forward / miner create deadlines): an attempt whose domain is DOWN
    stays open, not lost, until then."""
    return _timeout_s("VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S", 300.0)


def _settling_since(vm: Vm, attempt: GuestUpgradeAttempt, pin: Any) -> datetime:
    """When the attempt's dispatch was last in vali's hands — the window runs
    from the LATEST of: the power API's answer, the VM's last power marker
    change (the end of the start call, or the settle of a marker a dead tick
    left), the pin (written just before register + dispatch), the attempt.
    Never from the attempt alone: the launch choreography before the
    dispatch (preflight) may take longer than the window."""
    marks = [attempt.started_at, attempt.answered_at, vm.power_state_at]
    if pin is not None:
        marks.append(pin.pinned_at)
    return max(m for m in marks if m is not None)


def _reconcile(job: GuestUpgradeJob, vm: Vm, attempt: GuestUpgradeAttempt) -> str:
    """Settle an open attempt: `accepted`, `lost`, or `refused:<answer>`;
    raise `_Retry` while it cannot be told yet. Never dispatches.

    Accepted: its pin was stamped launched, the launch record names its
    measurement, or the domain is up (the dispatch reached the miner — the
    gate tells whether it is THIS boot that runs). Anything else stays OPEN
    until the dispatch settled (`_settle_s`) with the miner reporting the
    domain DOWN: a dispatch whose answer was lost may still land."""
    from .services import power

    if vm.power_state == VmPowerState.STARTING and not _stale_marker(vm, VmPowerState.STARTING):
        raise _Retry("open attempt: its start call may still be running")
    pin = _pin_of(attempt)
    accepted = pin is not None and (
        pin.launched_at is not None
        or launch_record.recorded_measurement(vm.vm_id).lower() == pin.launch_digest_hex.lower()
    )
    running = effects.poll_domain_running(vm)
    if running is None and not accepted:
        raise _Retry("open attempt: domain state unknown")
    if running and vm.power_state == VmPowerState.STOPPED:
        # The books follow the miner (a refusal that landed).
        power.settle_observed_running(vm)
    if running:
        accepted = True
    elif (
        not accepted
        and (timezone.now() - _settling_since(vm, attempt, pin)).total_seconds() < _settle_s()
    ):
        raise _Retry("open attempt: domain down, the dispatch may still land")
    if accepted:
        verdict = ACCEPTED
    else:
        verdict = f"refused:{attempt.answer}" if attempt.answer else LOST
    fields: dict[str, Any] = {"outcome": verdict}
    if pin is not None:
        fields["measurement"] = pin.launch_digest_hex.lower()
    if verdict == ACCEPTED:
        fields["accepted_at"] = attempt.accepted_at or timezone.now()
    GuestUpgradeAttempt.objects.filter(pk=attempt.pk, outcome="").update(**fields)
    for k, v in fields.items():
        setattr(attempt, k, v)
    return verdict


def _latest(job: GuestUpgradeJob, kinds: tuple[str, ...]) -> GuestUpgradeAttempt | None:
    return job.attempt_rows.filter(kind__in=kinds).order_by("-started_at").first()


def _launch_attempt(job: GuestUpgradeJob, vm: Vm, *, kind: str, prefix: str, initrd: str) -> str:
    """Reconcile the newest attempt of `kind`, or dispatch a new one.
    Returns `accepted`, `lost` (nothing live: the caller may retry), or
    `rejected` (the miner refused it); raises `_Retry` to wait."""
    from .services import power

    if vm.power_state == VmPowerState.STARTING and not _stale_marker(vm, VmPowerState.STARTING):
        raise _Retry("a start is in flight")
    latest = _latest(job, (kind,))
    if latest is not None and latest.outcome == "":
        verdict = _reconcile(job, vm, latest)
        if verdict == ACCEPTED:
            return ACCEPTED
        if verdict.startswith("refused:"):
            return "rejected"
    elif latest is not None and latest.outcome == ACCEPTED:
        return ACCEPTED
    # Per launch, not only at admission: the gate is only as good as the pin
    # being vali's own recompute. Without ENFORCE nothing is dispatched (the
    # state's deadline fails the job closed).
    if not _c2_enforced():
        raise _Retry("c2-not-enforced: no upgrade launch without launch-digest ENFORCE")
    if vm.power_state != VmPowerState.STOPPED:
        raise _Retry(f"vm is {vm.power_state}")
    if not _domain_down(vm):
        raise _Retry("the domain still runs")
    if not _claim_dispatch(job):
        raise _Retry("paced")
    first = job.attempt_rows.filter(kind=kind).order_by("started_at").first()
    supersede = kind != K.RECOVER and not (
        first is not None
        and MeasurementLedger.objects.filter(
            vm_id=vm.vm_id, superseded_at_register__gte=first.started_at
        ).exists()
    )
    attempt = GuestUpgradeAttempt.objects.create(
        job=job, kind=kind, prefix=prefix, initrd_sha256=initrd, supersede=supersede
    )
    try:
        power.start_vm(
            vm, by_guest_upgrade=job.job_id, supersede=supersede, launch_ref=str(attempt.id)
        )
    except power.PowerOpRefused as exc:
        if exc.reason == power.PIN_BUSY_REASON:
            # vali's own answer, before anything was signed or dispatched.
            GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(outcome=LOST)
            _patch(job, attempts=max(0, job.attempts - 1), attempted_at=None)
            raise _Retry("allowlist pin busy") from exc
        if exc.reason == power.DISKS_MISSING_REASON:
            GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(
                outcome=f"refused:{exc.reason}"
            )
            raise
        # A refusal answered by an Edge timeout may hide a launch that
        # landed: the attempt stays open until the dispatch settled.
        answered_at = timezone.now()
        GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(
            answer=exc.reason[:64], answered_at=answered_at
        )
        attempt.answer, attempt.answered_at = exc.reason[:64], answered_at
        vm.refresh_from_db()
        verdict = _reconcile(job, vm, attempt)
        return ACCEPTED if verdict == ACCEPTED else "rejected"
    except Exception as exc:  # noqa: BLE001 — ambiguous: reconciled next tick
        raise _Retry(f"relaunch dispatch failed: {exc}") from exc
    # Accepted — possibly `already-launched` (the miner started nothing and
    # an EARLIER dispatch of this job runs): the gate accepts any of the
    # job's pins of this phase, so that boot is judged on its own pin.
    pin = _pin_of(attempt)
    GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(
        outcome=ACCEPTED,
        accepted_at=timezone.now(),
        measurement=pin.launch_digest_hex.lower() if pin is not None else "",
    )
    return ACCEPTED


@dataclass(frozen=True)
class _Health:
    """What gate condition 4 wants of a launch of a release that declares
    health checks: that release and epoch, every declared check passing."""

    release_version: int
    security_epoch: int
    mask: int


def _health_expected(attempt: GuestUpgradeAttempt) -> _Health | None:
    """Condition 4 for `attempt`, from the build IT launched (the target
    for an upgrade / recover attempt, the previous set for a rollback):
    `None` for a bare base or a release without the health leg."""
    build = guest_components.build_for_initrd(attempt.initrd_sha256)
    if build is None or not build.release.health_mask:
        return None
    return _Health(
        release_version=int(build.release_id),
        security_epoch=int(build.release.security_epoch),
        mask=int(build.release.health_mask),
    )


def _healthy(row: Any, want: _Health | None) -> bool:
    return _unhealthy(row, want) == ""


def _unhealthy(row: Any, want: _Health | None) -> str:
    """What fails condition 4 in `row` (`""`: nothing) — the missing checks
    by bit, for the operator."""
    if want is None:
        return ""
    if row.components_health is None:
        return "a sample without the health leg"
    if (row.components_release_version, row.components_security_epoch) != (
        want.release_version,
        want.security_epoch,
    ):
        return (
            f"the guest reports release {row.components_release_version} epoch "
            f"{row.components_security_epoch}, not {want.release_version} epoch "
            f"{want.security_epoch}"
        )
    missing = want.mask & ~int(row.components_health)
    if not missing:
        return ""
    bits = [str(bit) for bit in range(missing.bit_length()) if missing >> bit & 1]
    return (
        f"health {int(row.components_health):#x} misses checks {missing:#x} "
        f"(bits {','.join(bits)}) of mask {want.mask:#x}"
    )


@dataclass(frozen=True)
class _Failure:
    """Why a target failed the gate or the soak: one of `OUTCOMES`, and the
    evidence for the operator."""

    outcome: str
    detail: str


def _row_failure(row: Any, attempt: GuestUpgradeAttempt, pin: MeasurementLedger) -> _Failure | None:
    """Conditions 3 and 4 on one sample of the job's own measurement."""
    unhealthy = _unhealthy(row, _health_expected(attempt))
    if unhealthy:
        return _Failure(HEALTH_FAILED, f"sample #{row.attestation_seq}: {unhealthy}")
    if not _resources_ok(row, pin):
        return _Failure(
            RESOURCES_MISMATCH,
            f"sample #{row.attestation_seq}: resources {row.resource_verdict or '?'}",
        )
    return None


def _diagnose(job: GuestUpgradeJob, vm: Vm, since_unix: int | None) -> _Failure:
    """Why no sample of the target passed (the gate, or the soak's
    freshness): from the live attestations of the VM since the job's first
    target attempt started (or `since_unix`). One of the job's measurements
    failing a check → that check; only other measurements → another boot
    runs; nothing at all → `no-sample`."""
    from apps.telemetry.models import VmLiveAttestation

    pins = _job_pins(job, vm, _TARGET_KINDS)
    first = _latest(job, _TARGET_KINDS)
    starts = [a.started_at for a, _ in pins] or ([first.started_at] if first else [])
    floor = since_unix if since_unix is not None else 0
    if starts:
        floor = max(floor, int(min(starts).timestamp()))
    by_digest = {pin.launch_digest_hex.lower(): (attempt, pin) for attempt, pin in pins}
    rows = list(
        VmLiveAttestation.objects.filter(vm_id=vm.vm_id, verified_at_unix__gte=floor).order_by(
            "-verified_at_unix", "-attestation_seq"
        )
    )
    others = 0
    for row in rows:  # newest first: the latest failing sample is the evidence
        hit = by_digest.get(row.measurement.lower())
        if hit is None:
            others += 1
            continue
        failure = _row_failure(row, *hit)
        if failure is not None:
            return failure
    if others:
        return _Failure(
            MEASUREMENT_MISMATCH,
            f"{others} live attestation(s) of another measurement "
            f"(latest {rows[0].measurement[:16]}…), none of this job's own boots",
        )
    return _Failure(NO_SAMPLE, "no live attestation of the target since its launch")


def _resources_ok(row: Any, pin: MeasurementLedger) -> bool:
    """Condition 3: the attested resources are the flavor's, when the
    launch attests them and resource enforcement is on."""
    from apps.telemetry import guest_resources

    if not (pin.attests_resources and guest_resources.enforce()):
        return True
    return row.resource_verdict == guest_resources.VERDICT_OK


def _job_pins(
    job: GuestUpgradeJob, vm: Vm, kinds: tuple[str, ...]
) -> list[tuple[GuestUpgradeAttempt, MeasurementLedger]]:
    """The recomputed pins linked to the job's attempts of `kinds` —
    whatever the attempt's outcome: a dispatch settled as refused may have
    landed after all, and its pin still names a boot vali built."""
    attempts = {str(a.id): a for a in job.attempt_rows.filter(kind__in=kinds)}
    if not attempts:
        return []
    pins = MeasurementLedger.objects.filter(
        vm_id=vm.vm_id, launch_ref__in=list(attempts), recomputed=True
    )
    return [(attempts[pin.launch_ref], pin) for pin in pins]


def _attesting(
    job: GuestUpgradeJob, vm: Vm, kinds: tuple[str, ...]
) -> tuple[GuestUpgradeAttempt, Any] | None:
    """The gate: the earliest KBS-verified live attestation of one of the
    job's pins (of `kinds`), verified after its attempt started, that meets
    conditions 3 and 4 for the build that attempt launched — with the
    attempt."""
    from apps.telemetry.models import VmLiveAttestation

    best: tuple[GuestUpgradeAttempt, Any] | None = None
    for attempt, pin in _job_pins(job, vm, kinds):
        want = _health_expected(attempt)
        rows = VmLiveAttestation.objects.filter(
            vm_id=vm.vm_id,
            measurement__iexact=pin.launch_digest_hex,
            verified_at_unix__gte=int(attempt.started_at.timestamp()),
        ).order_by("verified_at_unix")
        for row in rows:
            if _healthy(row, want) and _resources_ok(row, pin):
                if best is None or row.verified_at_unix < best[1].verified_at_unix:
                    best = (attempt, row)
                break
    return best


def _soak_verdict(
    job: GuestUpgradeJob, vm: Vm, soak_end_unix: int, deadline: datetime
) -> bool | _Failure | None:
    """The soak of a release with the health leg.

    Every sample of the job's target pins verified since the gate sample
    must pass conditions 3 and 4 with the gate sample's keepalive
    `instance` and failure count — the guest counts failing ticks before
    anything leaves it, so a withheld or delayed sample still shows in a
    later one. The soak ends with a sample OBSERVED at or after
    `soak_end_unix`: a v4 body's `observed_at_unix` is when the KBS issued
    its nonce, and the guest checks its components after receiving it, so
    a request the relay held back across the end cannot pass for a later
    check. That end sample must have reached vali by `deadline`.

    `True`: soaked. A `_Failure`: a sample failed (which check), or the
    deadline passed without an end sample (`no-sample`). `None`: wait."""
    from apps.telemetry.models import VmLiveAttestation

    pins = _job_pins(job, vm, _TARGET_KINDS)
    by_digest = {pin.launch_digest_hex.lower(): (attempt, pin) for attempt, pin in pins}
    rows = VmLiveAttestation.objects.filter(
        vm_id=vm.vm_id, verified_at_unix__gte=int(job.gate_verified_at_unix or 0)
    ).order_by("verified_at_unix", "attestation_seq")
    ended = False
    for row in rows:
        hit = by_digest.get(row.measurement.lower())
        if hit is None:
            continue  # another launch's guest: not this boot's soak
        attempt, pin = hit
        failure = _row_failure(row, attempt, pin)
        if failure is not None:
            return failure
        if row.components_instance != job.gate_instance:
            return _Failure(
                GUEST_RESTARTED,
                f"sample #{row.attestation_seq}: keepalive instance "
                f"{row.components_instance} ≠ {job.gate_instance} at the gate",
            )
        if row.components_unhealthy_ticks != job.gate_unhealthy_ticks:
            return _Failure(
                HEALTH_LATCHED,
                f"sample #{row.attestation_seq}: {row.components_unhealthy_ticks} failing "
                f"tick(s) counted, {job.gate_unhealthy_ticks} at the gate",
            )
        if row.observed_at_unix >= soak_end_unix and row.created_at <= deadline:
            ended = True
    if ended:
        return True
    if timezone.now() > deadline:
        return _Failure(NO_SAMPLE, "no sample observed after the soak's end by its deadline")
    return None


def _rejections(job: GuestUpgradeJob, kind: str) -> int:
    return job.attempt_rows.filter(kind=kind, outcome__startswith="refused:").count()


# ── handlers ────────────────────────────────────────────────────────


def _may_take(job: GuestUpgradeJob, vm: Vm) -> bool:
    """A running VM — or, for a retry, the VM the blocked job left stopped:
    no completed stop order since that job ended (a start that failed, or a
    domain observed down, are not someone's choice to keep it off). A VM
    someone stopped after it waits for its next start, like any other."""
    if vm.power_state == VmPowerState.RUNNING:
        return True
    blocked = job.retry_of
    return (
        blocked is not None
        and blocked.finished_at is not None
        and vm.power_state == VmPowerState.STOPPED
        and (vm.power_stop_ordered_at is None or vm.power_stop_ordered_at <= blocked.finished_at)
    )


def _h_pending(job: GuestUpgradeJob, vm: Vm) -> None:
    if vm.state != VmState.ACTIVE or vm.host != job.node_id:
        _terminal(job, S.CANCELLED.value, f"vm-changed: vm is {vm.state} on {vm.host!r}")
        return
    # A job that can never run is cancelled at once — before its window,
    # or while its VM is stopped — so a withdrawn target never blocks a
    # replacement upgrade.
    doomed = _doomed(job, vm)
    if doomed is not None:
        _terminal(job, S.CANCELLED.value, f"{doomed[0]}: {doomed[1]}")
        return
    if timezone.now() < job.not_before:
        return
    if not _may_take(job, vm):
        raise _Retry(f"vm is {vm.power_state} — upgraded once it runs")
    from .guest_rollout import global_lock, may_start, out_of_scope

    try:
        with transaction.atomic():
            # The guest-upgrade lock first, then the VM row (the order every
            # start decision takes): one upgrade per miner, the rollout's
            # leave and its pause are decided on a stable fleet.
            global_lock()
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            if locked.state != VmState.ACTIVE or locked.host != job.node_id:
                _terminal(
                    job,
                    S.CANCELLED.value,
                    f"vm-changed: vm is {locked.state} on {locked.host!r}",
                )
                return
            if not _may_take(job, locked):
                raise _Retry(f"vm is {locked.power_state}")
            refusal = _refusal(locked, job.target, rollback=True, retry_of=job.retry_of)
            if refusal and refusal[0] != "job-in-flight":
                _terminal(job, S.CANCELLED.value, f"{refusal[0]}: {refusal[1]}")
                return
            busy = _busy(locked)
            if busy:
                raise _Retry(busy)
            if out_of_scope(job, locked):
                _terminal(job, S.CANCELLED.value, "left-scope: the vm left its rollout's scope")
                return
            held_back = may_start(job)
            if held_back:
                raise _Retry(held_back)
            record = _record(locked)
            if _spec_pair(record) != _from_pair(job, record):
                _terminal(
                    job, S.CANCELLED.value, "the launch record moved since the job was admitted"
                )
                return
            # G3: the floor rises BEFORE anything is stopped or launched, in
            # the transaction that takes the VM.
            guest_components.raise_required_epoch(
                locked,
                int(job.target.release.security_epoch),
                by=job.job_id,
                reason=f"guest upgrade onto v{job.target.release_id}",
            )
            if not _cas(
                job,
                S.STOPPING.value,
                prior_power_state=locked.power_state,
                measurement_before=launch_record.recorded_measurement(locked.vm_id),
            ):
                raise _CasLost
    except _CasLost:
        return


def _h_stopping(job: GuestUpgradeJob, vm: Vm) -> None:
    if vm.power_state == VmPowerState.STOPPED:
        if not _domain_down(vm):
            raise _Retry("the domain still runs")
        _cas(job, S.LAUNCHING.value)
        return
    if vm.power_state != VmPowerState.RUNNING and not _stale_marker(vm, VmPowerState.STOPPING):
        return  # a stop settling
    _stop(job, vm)


def _swap_to(
    job: GuestUpgradeJob, vm: Vm, *, prefix: str, initrd: str, frm: tuple[str, str]
) -> None:
    """CAS the launch record from `frm` to `(prefix, initrd)` (no-op when it
    already names it)."""
    record = _record(vm)
    if _spec_pair(record) == (prefix, initrd):
        return
    marker = ((record.result_json or {}).get("emit") or {}).get(launch_record.BOOTED_ARTIFACTS_KEY)
    launch_record.swap_initrd(
        vm.vm_id,
        new_prefix=prefix,
        new_initrd_sha256_hex=initrd,
        expected_job_id=record.job_id,
        expected_prefix=frm[0],
        expected_initrd_sha256_hex=frm[1],
        expected_marker=marker,
        reason=f"guest-upgrade:{job.job_id}",
        operator=f"guest-upgrade:{job.decided_by_id}",
        evidence={"build": str(job.target_id), "release": job.target.release_id},
    )


def _h_launching(job: GuestUpgradeJob, vm: Vm) -> None:
    from .services import power

    target = (job.target.s3_key_prefix, job.target.initrd_sha256)
    if vm.power_state == VmPowerState.STOPPED:
        _swap_to(job, vm, prefix=target[0], initrd=target[1], frm=_from_pair(job, _record(vm)))
    try:
        verdict = _launch_attempt(job, vm, kind=K.UPGRADE, prefix=target[0], initrd=target[1])
    except power.PowerOpRefused as exc:
        _fail_target(job, vm, DISPATCH_FAILED, f"relaunch-refused: {exc.reason}")
        return
    if verdict == ACCEPTED:
        _cas(job, S.VERIFYING.value, relaunched_at=timezone.now())
        return
    if _rejections(job, K.UPGRADE) >= MAX_RELAUNCH_REJECTIONS:
        _fail_target(job, vm, DISPATCH_FAILED, f"relaunch-rejected ×{_rejections(job, K.UPGRADE)}")


_TARGET_KINDS = (K.UPGRADE.value, K.RECOVER.value)


def _current_attempt(job: GuestUpgradeJob) -> GuestUpgradeAttempt | None:
    return _latest(job, _TARGET_KINDS)


def _h_verifying(job: GuestUpgradeJob, vm: Vm) -> None:
    from .services import power

    gate = _attesting(job, vm, _TARGET_KINDS)
    if gate is not None:
        row = gate[1]
        _cas(
            job,
            S.SOAKING.value,
            gate_verified_at_unix=row.verified_at_unix,
            gate_instance=row.components_instance,
            gate_unhealthy_ticks=row.components_unhealthy_ticks,
        )
        return
    attempt = _current_attempt(job)
    if attempt is not None and attempt.outcome == "":
        if _reconcile(job, vm, attempt) != ACCEPTED:
            # The job's one recover did not take.
            _fail_target(job, vm, DISPATCH_FAILED, "recover relaunch did not take")
        return
    if job.recover_used:
        return
    if effects.poll_domain_running(vm) is not False:
        return
    # A miner reboot under the new boot: ONE relaunch of the same set,
    # claimed before it is dispatched.
    if vm.power_state == VmPowerState.RUNNING and not _settle_observed_down(vm):
        raise _Retry("the vm's power state changed under the job")
    if vm.power_state != VmPowerState.STOPPED:
        raise _Retry(f"vm is {vm.power_state}")
    if not _patch(job, recover_used=True):
        raise _Retry("job moved")
    try:
        verdict = _launch_attempt(
            job,
            vm,
            kind=K.RECOVER,
            prefix=job.target.s3_key_prefix,
            initrd=job.target.initrd_sha256,
        )
    except power.PowerOpRefused as exc:
        _fail_target(job, vm, DISPATCH_FAILED, f"recover refused: {exc.reason}")
        return
    if verdict != ACCEPTED:
        _fail_target(job, vm, DISPATCH_FAILED, "recover relaunch rejected")


def _h_soaking(job: GuestUpgradeJob, vm: Vm) -> None:
    soak_end = job.phase_started_at + timedelta(seconds=_soak_s())
    if job.target.release.health_mask:
        deadline = job.phase_started_at + timedelta(seconds=_state_timeout(job))
        # Rounded UP: a check made in the second the soak ends is before it.
        verdict = _soak_verdict(job, vm, math.ceil(soak_end.timestamp()), deadline)
        if isinstance(verdict, _Failure):
            _fail_target(job, vm, verdict.outcome, f"soak: {verdict.detail}")
            return
        if verdict is None:
            return  # the end sample has not arrived; the deadline bounds it
    else:
        if timezone.now() < soak_end:
            return
        since = int(time.time() - _fresh_s())
        if not _attested_fresh(job, vm, since):
            failure = _diagnose(job, vm, since)
            _fail_target(job, vm, failure.outcome, f"soak: {failure.detail}")
            return
    from .models import VmGuestComponents

    VmGuestComponents.objects.filter(vm=vm).update(
        attested_epoch=int(job.target.release.security_epoch)
    )
    _terminal(job, S.DONE.value)


def _attested_fresh(job: GuestUpgradeJob, vm: Vm, since_unix: int) -> bool:
    """The soak of a release without the health leg: one of the job's
    target pins attested since `since_unix` (conditions 3 apply)."""
    from apps.telemetry.models import VmLiveAttestation

    for attempt, pin in _job_pins(job, vm, _TARGET_KINDS):
        rows = VmLiveAttestation.objects.filter(
            vm_id=vm.vm_id,
            measurement__iexact=pin.launch_digest_hex,
            verified_at_unix__gte=max(since_unix, int(attempt.started_at.timestamp())),
        )
        if any(_resources_ok(row, pin) for row in rows):
            return True
    return False


def _target_dispatched(job: GuestUpgradeJob) -> bool:
    """Anything of the target may have been booted: an attempt still open,
    accepted, or that pinned (a refusal answered by an Edge timeout may have
    landed)."""
    return any(
        a.outcome in ("", ACCEPTED) or _pin_of(a) is not None
        for a in job.attempt_rows.filter(kind__in=_TARGET_KINDS)
    )


def _fail_target(job: GuestUpgradeJob, vm: Vm, outcome: str, detail: str) -> None:
    """The target did not come up (`outcome`, one of `OUTCOMES`): roll back
    when the floor allows it; otherwise park the VM (domain DOWN) for an
    operator — unless nothing of the target was ever dispatched, in which
    case the VM is as it was."""
    reason = f"{outcome}: {detail}"
    log.warning(
        "guest upgrade %s: target failed (vm=%s, outcome=%s, suspect=%s): %s",
        job.job_id,
        vm.vm_id,
        outcome,
        OUTCOME_SUSPECT.get(outcome, "?"),
        detail,
    )
    floor = guest_components.required_epoch(vm.vm_id)
    if job.previous_epoch >= floor:
        _cas(job, S.ROLLING_BACK.value, reason=reason[:256], outcome=outcome)
        return
    blocked = (
        f"{reason}; rollback forbidden (previous set epoch {job.previous_epoch} < required {floor})"
    )
    if not _target_dispatched(job) and _spec_pair(_record(vm)) == (
        job.previous_prefix,
        job.previous_initrd_sha256,
    ):
        _terminal(job, S.UPGRADE_BLOCKED.value, blocked, outcome=outcome)
        return
    _park(job, S.UPGRADE_BLOCKED.value, blocked, outcome=outcome)


def _park(job: GuestUpgradeJob, final: str, reason: str, **patch: Any) -> None:
    _cas(job, S.PARKING.value, park_to=final, reason=reason[:256], **patch)


def _h_parking(job: GuestUpgradeJob, vm: Vm) -> None:
    if vm.power_state == VmPowerState.STOPPED:
        if _domain_down(vm):
            _terminal(job, job.park_to or S.FAILED.value, job.reason)
            return
        raise _Retry("the domain still runs")
    if vm.power_state == VmPowerState.RUNNING or _stale_marker(vm, VmPowerState.STOPPING):
        _stop(job, vm)


def _h_rolling_back(job: GuestUpgradeJob, vm: Vm) -> None:
    from .services import power

    previous = (job.previous_prefix, job.previous_initrd_sha256)
    if guest_components.required_epoch(vm.vm_id) > job.previous_epoch:
        _park(job, S.UPGRADE_BLOCKED.value, f"{job.reason}; rollback forbidden by the floor")
        return
    if _attesting(job, vm, (K.ROLLBACK.value,)) is not None:
        _terminal(job, S.ROLLED_BACK.value, job.reason)
        return
    rb = _latest(job, (K.ROLLBACK,))
    if rb is not None and rb.outcome == "":
        _reconcile(job, vm, rb)
    if rb is not None and rb.outcome == ACCEPTED:
        return  # the gate above decides; the state's deadline bounds it
    if (
        not _target_dispatched(job)
        and vm.power_state == VmPowerState.RUNNING
        and _spec_pair(_record(vm)) == previous
    ):
        # Nothing of the target was ever dispatched (the stop never took):
        # the VM still runs the previous set — nothing to undo.
        _terminal(job, S.ROLLED_BACK.value, job.reason)
        return
    if vm.power_state == VmPowerState.RUNNING or _stale_marker(vm, VmPowerState.STOPPING):
        _stop(job, vm)
        return
    if vm.power_state != VmPowerState.STOPPED:
        return
    if not _domain_down(vm):
        raise _Retry("rollback: the domain still runs")
    _swap_to(job, vm, prefix=previous[0], initrd=previous[1], frm=_spec_pair(_record(vm)))
    try:
        verdict = _launch_attempt(job, vm, kind=K.ROLLBACK, prefix=previous[0], initrd=previous[1])
    except power.PowerOpRefused as exc:
        _park(job, S.FAILED.value, f"{job.reason}; rollback relaunch refused: {exc.reason}")
        return
    if verdict != ACCEPTED and _rejections(job, K.ROLLBACK) >= MAX_RELAUNCH_REJECTIONS:
        _park(job, S.FAILED.value, f"{job.reason}; rollback relaunch rejected")


def release_parked(job: GuestUpgradeJob, *, operator: str, reason: str) -> None:
    """The audited override for a PARKING job whose domain the miner never
    reported DOWN: release the VM to `park_to` on an operator's word (they
    looked at it). Raises `ValueError` when the job is not parking."""
    if not (operator and reason):
        raise ValueError("releasing a parked guest upgrade needs an operator and a reason")
    with transaction.atomic():
        Vm.objects.select_for_update().filter(pk=job.vm_id).first()
        job.refresh_from_db()
        if job.state != S.PARKING:
            raise ValueError(f"guest upgrade {job.job_id} is {job.state!r}, not parking")
        final = job.park_to or S.FAILED.value
        if not _cas(
            job,
            final,
            released_by=operator[:128],
            reason=f"{job.reason}; released by {operator}: {reason}"[-256:],
        ):
            raise ValueError(f"guest upgrade {job.job_id} moved — retry")
    log.warning(
        "guest upgrade %s RELEASED from parking → %s by %s without a confirmed DOWN: %s",
        job.job_id,
        final,
        operator,
        reason,
    )


# ─── operator recovery ───────────────────────────────────────────────


def _recovery_job_refusal(job: GuestUpgradeJob, vm: Vm) -> tuple[str, str] | None:
    """The job is not the one to recover: not ended in a recoverable state,
    no longer the VM's anchor, or the VM moved."""
    if job.state == S.PARKING:
        return (
            "parking",
            "the job still holds the vm, stopping its domain — wait for it, or release it "
            "(--release-parked) once the domain is known down",
        )
    if job.state not in RECOVERABLE_STATES:
        return "not-recoverable", f"guest upgrade {job.job_id} is {job.state}"
    anchor = anchor_job(vm)
    if anchor is None or anchor.pk != job.pk:
        return (
            "superseded",
            f"guest upgrade {anchor.job_id if anchor else '?'} is the vm's latest — "
            "recover that one",
        )
    if vm.state != VmState.ACTIVE or vm.host != job.node_id:
        return "vm-changed", f"vm is {vm.state} on {vm.host!r}, the job ran on {job.node_id!r}"
    return None


def _recovery_refusal(job: GuestUpgradeJob, vm: Vm) -> tuple[str, str] | None:
    """`(category, detail)` when `job`'s target cannot be started for an
    operator now. Read under the VM row lock."""
    refusal = _recovery_job_refusal(job, vm)
    if refusal:
        return refusal
    build = job.target
    if build.withdrawn_at is not None or build.release.withdrawn_at is not None:
        return (
            "build-withdrawn",
            f"build {build.s3_key_prefix} is withdrawn — retry onto a newer release instead",
        )
    floor = guest_components.required_epoch(vm.vm_id)
    if int(build.release.security_epoch) < floor:
        return "below-floor", f"the target's epoch is below the vm's required epoch {floor}"
    if not _c2_enforced():
        return "c2-not-enforced", "no recovery launch without launch-digest ENFORCE"
    record = _record(vm)
    if record is None:
        return "no-launch-record", "vm has no launch record"
    target = (build.s3_key_prefix, build.initrd_sha256)
    if _spec_pair(record) not in (target, (job.previous_prefix, job.previous_initrd_sha256)):
        return (
            "record-moved",
            "the launch record names neither the job's target nor its previous set",
        )
    if vm.power_state != VmPowerState.STOPPED and not _stale_marker(vm, VmPowerState.STARTING):
        return "vm-not-stopped", f"vm is {vm.power_state}"
    busy = _busy(vm)
    if busy:
        return busy.split(":", 1)[0], f"another operation holds the vm ({busy})"
    return None


def recovery_refusal(job: GuestUpgradeJob) -> tuple[str, str] | None:
    """The read-only preview of `recover_start_on_target` (a dry run): why
    it would be refused now, or `None`."""
    from . import effects

    vm = Vm.objects.get(pk=job.vm_id)
    if _open_recovery_starts(job):
        return "start-settling", "an earlier recovery start is not settled yet (--apply settles it)"
    refusal = _recovery_refusal(job, vm)
    if refusal:
        return refusal
    running = effects.poll_domain_running(vm)
    if running is None:
        return "domain-unknown", "the miner did not answer whether the domain runs"
    if running:
        return "domain-running", "the miner reports the domain RUNNING"
    return None


def _log_recovery(job: GuestUpgradeJob, entry: dict[str, Any]) -> None:
    """Append (or update, by `attempt`) one entry of `job.recoveries`."""
    for _ in range(5):
        job.refresh_from_db()
        log_ = [e for e in (job.recoveries or []) if e.get("attempt") != entry["attempt"]]
        if _patch(job, recoveries=[*log_, entry][-20:]):
            return
    raise RuntimeError(f"guest upgrade {job.job_id}: could not record the recovery")


def _open_recovery_starts(job: GuestUpgradeJob) -> list[GuestUpgradeAttempt]:
    return list(job.attempt_rows.filter(kind=K.OPERATOR_START, outcome=""))


def _settle_recovery_starts(job: GuestUpgradeJob, vm: Vm) -> None:
    """Settle the job's earlier recovery starts still open (an answer that
    may hide a launch still landing) the way the job settles its own
    attempts (`_reconcile`). Raises `StartError` (`start-settling`) while
    one cannot be told yet: no second start over a dispatch that may land."""
    for attempt in _open_recovery_starts(job):
        try:
            _reconcile(job, vm, attempt)
        except _Retry as exc:
            raise StartError(
                f"an earlier recovery start may still land ({exc}) — retry in a few minutes",
                "start-settling",
            ) from exc


def recover_start_on_target(job: GuestUpgradeJob, *, operator: str, reason: str) -> dict[str, Any]:
    """Start the VM a failed / blocked guest upgrade left stopped, on the
    job's TARGET — the operator's audited "give the tenant its VM back".

    Not gated: the boot's health is the operator's call from here (the job
    stays `upgrade_blocked` / `failed`; a retry is what verifies it). Never
    below the floor and never around the launch path: the target is at or
    above the VM's required epoch (and the launch refuses anything below
    it), the record is CAS-swapped onto it, and the start is the power API's
    — C2 ENFORCE, the §22 auto-pin, and a KBS `supersede` at register (every
    earlier launch, the job's failed attempts included, is refused from it
    on: the miner reports the domain DOWN before the start). The start is
    claimed (`starting`) in the transaction that decided it, so no other
    start takes the VM in between; a refusal that may hide a landed launch
    keeps the claim and leaves the attempt open until it settled. Recorded
    on the job (`recoveries`, and an `operator_start` attempt linked to its
    pin). Raises `StartError` on a refusal; returns the recovery entry."""
    from . import effects
    from .services import power

    if not (operator.strip() and reason.strip()):
        raise StartError("a recovery needs an operator and a reason", "wire")
    # Only the VM's anchor job settles its starts: once a later job took the
    # VM, a domain up is that job's, not an earlier recovery start's — decided
    # under the VM row lock every job takes the VM under (a miner poll inside
    # it, on an operator's action, when a start is open).
    with transaction.atomic():
        vm = Vm.objects.select_for_update().get(pk=job.vm_id)
        refusal = _recovery_job_refusal(job, vm)
        if refusal:
            raise StartError(refusal[1], refusal[0])
        _settle_recovery_starts(job, vm)
    vm.refresh_from_db()
    refusal = _recovery_refusal(job, vm)  # re-read under the lock below
    if refusal:
        raise StartError(refusal[1], refusal[0])
    # The miner's word on the domain (outside the row lock): a domain still
    # up may be a boot of unknown health — never start a second one. Nothing
    # vali dispatches can bring it up before the claim below: the job's own
    # attempts are settled, a recovery start is claimed, and any other start
    # is refused by that claim.
    running = effects.poll_domain_running(vm)
    if running is None:
        raise StartError("the miner did not answer whether the domain runs", "domain-unknown")
    if running:
        raise StartError(
            "the miner reports the domain RUNNING — stop it (or find out what runs) first",
            "domain-running",
        )
    with transaction.atomic():
        vm = Vm.objects.select_for_update().get(pk=job.vm_id)
        job = GuestUpgradeJob.objects.select_related("target", "target__release", "vm").get(
            pk=job.pk
        )
        refusal = _recovery_refusal(job, vm)
        if refusal is None and _open_recovery_starts(job):
            refusal = ("start-settling", "another recovery start is in flight")
        if refusal:
            raise StartError(refusal[1], refusal[0])
        try:
            vm = power.claim_start(vm)
        except power.PowerOpRefused as exc:
            raise StartError(exc.detail, exc.reason) from exc
        target = (job.target.s3_key_prefix, job.target.initrd_sha256)
        record = _record(vm)
        current = _spec_pair(record)
        if current != target:
            try:
                launch_record.swap_initrd(
                    vm.vm_id,
                    new_prefix=target[0],
                    new_initrd_sha256_hex=target[1],
                    expected_job_id=record.job_id,
                    expected_prefix=current[0],
                    expected_initrd_sha256_hex=current[1],
                    expected_marker=((record.result_json or {}).get("emit") or {}).get(
                        launch_record.BOOTED_ARTIFACTS_KEY
                    ),
                    reason=f"guest-upgrade-recover:{job.job_id}: {reason}"[:256],
                    operator=operator,
                    evidence={"build": str(job.target_id), "release": job.target.release_id},
                )
            except (ValueError, LookupError) as exc:
                raise StartError(str(exc), "record-moved") from exc
        attempt = GuestUpgradeAttempt.objects.create(
            job=job,
            kind=K.OPERATOR_START,
            prefix=target[0],
            initrd_sha256=target[1],
            supersede=True,
        )
        entry: dict[str, Any] = {
            "at": timezone.now().isoformat(),
            "by": operator[:128],
            "action": RECOVER_START_ON_TARGET,
            "reason": reason[:256],
            "attempt": str(attempt.id),
            "release": int(job.target.release_id),
            "result": "dispatching",
        }
        _log_recovery(job, entry)
    log.warning(
        "guest upgrade %s: RECOVERY %s by %s (vm=%s, v%s, job %s): %s",
        job.job_id,
        RECOVER_START_ON_TARGET,
        operator,
        vm.vm_id,
        job.target.release_id,
        job.state,
        reason,
    )
    try:
        power.start_vm(vm, supersede=True, launch_ref=str(attempt.id), claimed=True)
    except power.PowerOpRefused as exc:
        if exc.reason in (power.PIN_BUSY_REASON, power.DISKS_MISSING_REASON):
            # Definite: vali's own answer before anything was dispatched, or
            # the miner does not hold the disks.
            outcome = LOST if exc.reason == power.PIN_BUSY_REASON else f"refused:{exc.reason}"
            GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(outcome=outcome)
            result = f"refused:{exc.reason}"
        else:
            # Answered as refused, possibly after the order went out: the
            # attempt stays open and the VM `starting` until it settled.
            # (`start_vm(claimed=True)` left the claim in place.)
            GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(
                answer=exc.reason[:64], answered_at=timezone.now()
            )
            result = f"unsettled:{exc.reason}"
        _log_recovery(job, {**entry, "result": result})
        raise StartError(exc.detail, exc.reason) from exc
    except Exception as exc:
        # Ambiguous: the start may have landed — the attempt stays open and
        # the power marker `starting` until it settled.
        _log_recovery(job, {**entry, "result": f"error:{type(exc).__name__}"})
        raise
    pin = _pin_of(attempt)
    GuestUpgradeAttempt.objects.filter(pk=attempt.pk).update(
        outcome=ACCEPTED,
        accepted_at=timezone.now(),
        measurement=pin.launch_digest_hex.lower() if pin is not None else "",
    )
    entry = {**entry, "result": "started"}
    _log_recovery(job, entry)
    return entry


_HANDLERS = {
    S.PENDING.value: _h_pending,
    S.STOPPING.value: _h_stopping,
    S.LAUNCHING.value: _h_launching,
    S.VERIFYING.value: _h_verifying,
    S.SOAKING.value: _h_soaking,
    S.ROLLING_BACK.value: _h_rolling_back,
    S.PARKING.value: _h_parking,
}


def _on_timeout(job: GuestUpgradeJob, vm: Vm) -> None:
    elapsed = timedelta(seconds=_state_timeout(job))
    if job.state == S.STOPPING:
        _fail_target(job, vm, STOP_TIMEOUT, f"stopping-timeout ({elapsed})")
    elif job.state == S.LAUNCHING:
        outcome = LAUNCH_TIMEOUT if _c2_enforced() else C2_NOT_ENFORCED
        _fail_target(job, vm, outcome, f"launching-timeout ({elapsed})")
    elif job.state in (S.VERIFYING, S.SOAKING):
        failure = _diagnose(job, vm, None)
        _fail_target(job, vm, failure.outcome, f"{job.state}-timeout ({elapsed}): {failure.detail}")
    elif job.state == S.ROLLING_BACK:
        _park(job, S.FAILED.value, f"{job.reason}; rollback-timeout ({elapsed})")
    elif job.state == S.PARKING:
        # The domain could not be confirmed down: the VM may still run a
        # boot of unknown health, so the job keeps holding it and keeps
        # stopping it — never released on time alone. An operator looks
        # (`vali_guest_upgrade --release-parked`, audited).
        log.error(
            "guest upgrade %s: PARKING overdue (%s) — vm=%s NOT confirmed down; the job "
            "keeps holding it until the miner reports DOWN or an operator releases it",
            job.job_id,
            elapsed,
            job.vm.vm_id,
        )
        if PARKING_OVERDUE not in job.reason:
            _patch(job, reason=f"{job.reason}; {PARKING_OVERDUE}"[-256:])


def advance_guest_upgrade(job: GuestUpgradeJob) -> None:
    """Advance `job` by one bounded step. Never raises for a step failure."""
    if job.state in TERMINAL_GUEST_UPGRADE_STATES:
        return
    vm = Vm.objects.get(pk=job.vm_id)
    job.vm = vm
    if job.state != S.PENDING and (vm.state != VmState.ACTIVE or vm.host != job.node_id):
        _terminal(
            job,
            S.FAILED.value,
            f"vm-moved: vm is {vm.state} on {vm.host!r}, the upgrade ran on {job.node_id!r}",
            outcome=job.outcome or VM_MOVED,
        )
        return
    try:
        if job.state != S.PENDING:
            from .resize import _settle_power_marker

            # A starting/stopping marker a dead tick left inside a power op is
            # settled to what the miner runs (reboot-recovery, which would do
            # it, skips a VM a job holds).
            vm = _settle_power_marker(vm)
        _HANDLERS[job.state](job, vm)
    except _Retry as exc:
        log.info("guest upgrade %s: %s — retrying (%s)", job.job_id, job.state, exc)
    except Exception:  # noqa: BLE001 — a bug must not kill the tick; the deadline bounds it.
        log.exception("guest upgrade %s: unhandled error in %s", job.job_id, job.state)
    job.refresh_from_db()
    if job.state in TERMINAL_GUEST_UPGRADE_STATES or job.state == S.PENDING:
        return
    if (timezone.now() - job.phase_started_at).total_seconds() <= _state_timeout(job):
        return
    if job.attempt_rows.filter(outcome="").exists():
        # A dispatch that may still land is reconciled first, whatever the
        # deadline says: failing over now (a rollback's launch, a park)
        # could race it. `_reconcile` settles it once the dispatch settled;
        # until then the job keeps holding the VM, loudly.
        log.error(
            "guest upgrade %s: %s overdue with an open attempt — vm=%s held until the "
            "miner's answer settles",
            job.job_id,
            job.state,
            vm.vm_id,
        )
        return
    _on_timeout(job, vm)


def tick_guest_upgrades() -> int:
    """Advance every in-flight guest upgrade one step. Returns how many."""
    if not enabled():
        return 0
    jobs = list(
        GuestUpgradeJob.objects.exclude(state__in=TERMINAL_GUEST_UPGRADE_STATES).select_related(
            "vm", "target", "target__release", "decided_by"
        )
    )
    for job in jobs:
        try:
            advance_guest_upgrade(job)
        except Exception:  # noqa: BLE001 — one job must not kill the tick.
            log.exception("guest upgrade %s: unhandled error in tick", job.job_id)
    return len(jobs)
