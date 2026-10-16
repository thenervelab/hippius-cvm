"""Userdata restage: give an M0 VM a new cloud-init userdata at its NEXT boot.

Two callers share this module:
- the operator CLI `vali_restage_userdata`, which reads a file;
- the root-only API `POST /v1/vm/<id>/userdata/restage`. The upper layer
  rebuilds the complete userdata (it carries the guest's own secrets) and
  must not hand it over through a person.

## What a restage writes

A NEW version of the VM's template at `{prefix}/{vm_id}/userdata-intake`,
Transit-wrapped under `ud-<vm_id>` like the launch intake's, and STAMPED
verbatim inside the wrapped blob (`launch.stage_userdata_restage_copy`).
Then the launch record's `userdata_vault_path` / `userdata_vault_version`,
which a relaunch reads, are pointed at it (`launch_record.repoint_userdata`,
audited in `emit["userdata_restages"]`).

The bytes are stored and delivered BYTE FOR BYTE. No `{{NETBIRD_SETUP_KEY}}`
or other token is required, and none is substituted. The relaunch reads the
stamp (`launch.split_verbatim_userdata`) and `launch_on_miner` mints no
NetBird key for it: the guest is already enrolled, and the caller staged
its complete userdata.

The relaunch then re-stages the canonical copy under the KBS-only
`kek-<vm_id>` and mints a ticket whose §6 digest is over these bytes. That
is the ordinary launch path: the digest preimage and custody are unchanged.
Until the relaunch, nothing the VM boots changes: its ticket binds the
canonical version the last launch staged, an in-guest reboot re-pushes that
ticket, and §25 / KBS recovery re-mint from the canonical + working copies.

## M0 only

An M0 guest gets a fresh random cloud-init instance-id every boot
(`hippius-release-core.sh`), so the whole userdata re-applies at its next
boot. An M1/M2 guest hands cloud-init the released userdata only on its
volume's first boot, and an empty one after (`hippius-golden-overlay.sh`):
a restage would never reach it.

## Concurrency

Every decision is re-made under the Vm row lock, and that lock is held
across the Vault write: `start_decommission` creates its job under the same
lock, so a §24 can never erase the path ahead of a write it would then not
sweep. The record write is compare-and-set on the pointer that was decided
on.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState

from .effects import EffectError, EffectUnavailable
from .management.commands.vali_swap_vm_initrd import _in_flight_refusal, _shadowed_by
from .models import (
    TERMINAL_USERDATA_RESTAGE_PHASES,
    UserdataRestageJob,
    UserdataRestagePhase,
)
from .services import customer_keys, launch, launch_record, vault_kv

log = logging.getLogger("apps.orchestration.userdata_restage")

REASON_PREFIX = "userdata-restage"
ROLLBACK_PREFIX = "userdata-restage-rollback"
KIND_RESTAGE = "restage"
KIND_ROLLBACK = "rollback"
#: A rollback to the pointer the latest restage replaced (from the trail).
KIND_REVERT = "revert_last"
OUTCOME_COMMITTED = "committed"
OUTCOME_FAILED = "failed"

#: The intake leaf `start_launch` stages a template at; restages write there.
INTAKE_LEAF = "userdata-intake"

#: A `relaunching` job that has not settled in this long is failed, so that
#: the VM is not held forever; its `error` names the power state it is in.
RELAUNCH_STALE = timedelta(minutes=30)


class RestageRefused(Exception):
    """A restage that must not happen. `category` is the stable slug the API
    answers with, `http_status` its status."""

    def __init__(self, category: str, message: str, http_status: int = 409) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.http_status = http_status


@dataclass(frozen=True)
class Plan:
    """What a restage or rollback would do, decided on the VM as read."""

    vm_id: str
    job_id: str  # the launch record's
    kind: str
    from_path: str
    from_version: int
    to_path: str
    to_version: int  # 0 ⇒ the next version of `to_path` (a restage)
    size: int | None
    digest_hex: str
    evidence: dict[str, Any]

    @property
    def would_be_version(self) -> int:
        return self.to_version


def mount() -> str:
    return str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))


def intake_path(vm_id: str) -> str:
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise RestageRefused("internal", "VALI_VAULT_KV_PREFIX is not configured", 500)
    return f"{prefix}/{vm_id}/{INTAKE_LEAF}"


def userdata_cap() -> int:
    """The largest userdata the launch API admits: its request body (JSON
    envelope included) is bounded by `DATA_UPLOAD_MAX_MEMORY_SIZE`, so no
    launched VM carries more."""
    return int(getattr(settings, "DATA_UPLOAD_MAX_MEMORY_SIZE", 64 * 1024))


# ── the API's own gates ──────────────────────────────────────────────────


def allowlisted_vm_ids() -> frozenset[str]:
    raw = str(getattr(settings, "VALI_USERDATA_RESTAGE_VM_ALLOWLIST", "") or "")
    return frozenset(v.strip() for v in raw.split(",") if v.strip())


def check_api_gates(vm_id: str) -> None:
    """The feature flag and the per-VM allow-list — the API's and the CLI's."""
    if not bool(getattr(settings, "VALI_USERDATA_RESTAGE_ENABLED", False)):
        raise RestageRefused(
            "userdata-restage-disabled", "userdata restage is disabled on this validator", 403
        )
    if vm_id not in allowlisted_vm_ids():
        raise RestageRefused(
            "userdata-restage-not-allowed",
            "this vm is not on the userdata-restage allow-list",
            403,
        )


def decode_userdata_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise RestageRefused("bad-userdata", "userdata_b64 must be a non-empty string", 400)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RestageRefused("bad-userdata", "userdata_b64 is not valid base64", 400) from exc


def check_userdata(userdata: bytes) -> None:
    """The bytes themselves. Nothing about their content is required: they
    are delivered verbatim."""
    if not userdata:
        raise RestageRefused("bad-userdata", "userdata is empty", 400)
    if len(userdata) > userdata_cap():
        raise RestageRefused(
            "userdata-too-large",
            f"userdata is {len(userdata)} bytes, the launch limit is {userdata_cap()}",
            413,
        )
    if userdata.startswith(b"vault:"):
        # The discriminator every reader uses for Transit ciphertext.
        raise RestageRefused(
            "bad-userdata", "a `vault:`-prefixed value is reserved for Transit ciphertext", 400
        )
    try:
        userdata.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RestageRefused("bad-userdata", "userdata is not UTF-8", 400) from exc


# ── the VM ───────────────────────────────────────────────────────────────


def _key_mode_refusal(vm: Vm, job: Any) -> None:
    """Pass iff `vm` is provably M0: its pin, and the measured cmdline its
    record carries, which must agree."""
    measured = str(((job.result_json or {}).get("emit") or {}).get("measured_cmdline") or "")
    try:
        binding = customer_keys.resolve_for_remint(vm, measured or None)
    except customer_keys.CustomerKeysError as exc:
        raise RestageRefused(
            "userdata-restage-unsupported-key-mode", f"key mode not provably M0: {exc}"
        ) from exc
    if binding is not None:
        raise RestageRefused(
            "userdata-restage-unsupported-key-mode",
            f"vm is {binding.mode} (M1/M2): its guest hands cloud-init the released "
            "userdata only on its volume's first boot, so a restage would never reach it",
        )


def check_vm(vm: Vm) -> Any:
    """Refuse a VM that cannot be restaged now; return its launch record."""
    refusal = ""
    if (
        UserdataRestageJob.objects.filter(vm=vm)
        .exclude(phase__in=TERMINAL_USERDATA_RESTAGE_PHASES)
        .exists()
    ):
        refusal = "restage-in-flight"
    refusal = refusal or _in_flight_refusal(vm)
    if not refusal and vm.power_state != VmPowerState.RUNNING:
        refusal = f"power-not-running:{vm.power_state}"
    if refusal:
        raise RestageRefused("vm-not-restageable", f"vm cannot be restaged now: {refusal}")
    job = launch_record.latest_record(vm.vm_id)
    if job is None:
        raise RestageRefused("vm-not-restageable", "vm has no successful launch record")
    _key_mode_refusal(vm, job)
    spec = job.spec_json or {}
    # The relaunch is a new measurement (fresh nonces): a record that pins
    # one, or does not re-pin, boots a guest the KBS never releases to —
    # after the stop, with the VM down.
    if str(spec.get("measurement_hex") or "").strip():
        raise RestageRefused(
            "vm-not-restageable", "its launch record pins a measurement: a relaunch cannot match it"
        )
    if spec.get("auto_pin_allowlist") is not True:
        raise RestageRefused(
            "vm-not-restageable",
            "its launch record does not auto-pin the allowlist: the relaunch's new "
            "measurement would never be released to",
        )
    return job


def relaunch_input_refusal(path: str, version: int, *, intake: str) -> str:
    """`""` iff `path@version` is something a relaunch can read back as the
    template (`launch.open_userdata_intake_copy`). Reads the ciphertext's
    prefix only; nothing is decrypted.

    - it must exist (Vault prunes a path's oldest versions);
    - at the intake path it must be wrapped, as intake and restages write it;
    - the canonical `…/userdata` copy, once wrapped, is under the KBS-only
      `kek-<vm_id>`: vali cannot open it, so it is no template.

    A legacy `…/userdata-pending` pointer is taken as is: reverting puts
    back exactly what this VM's relaunches read before the restage."""
    try:
        stored = vault_kv.get_kv(mount(), path, version=version)
    except vault_kv.VaultNotFound:
        return f"no-such-version:{path}@{version}"
    except EffectError as exc:
        return f"vault-read-failed:{exc}"
    try:
        wrapped = stored.startswith(b"vault:")
    finally:
        stored = b"\x00" * len(stored)
    if path == intake and not wrapped:
        return f"not-a-wrapped-template:{path}@{version}"
    if path.rsplit("/", 1)[-1] == "userdata" and wrapped:
        return f"canonical-copy-not-a-template:{path}@{version}"
    return ""


def _next_version(path: str) -> int:
    try:
        return (
            vault_kv.latest_version(mount(), path) + 1 if vault_kv.kv_exists(mount(), path) else 1
        )
    except EffectError as exc:
        raise RestageRefused(
            "vault-unavailable", f"cannot read {path}'s metadata: {exc}", 503
        ) from exc


def kv_max_versions() -> int:
    """How many versions Vault KV keeps per path (the mount's
    `max_versions`; Vault's default is 10)."""
    return int(getattr(settings, "VALI_VAULT_KV_MAX_VERSIONS", 10))


def _refuse_pruning(target: str, from_path: str, from_version: int, next_version: int) -> None:
    """Writing `next_version` must not push the version the record points at
    out of Vault's history: the VM's next relaunch (and a rollback to it)
    would have nothing to read."""
    if from_path == target and next_version - from_version >= kv_max_versions():
        raise RestageRefused(
            "vm-not-restageable",
            f"{target} already holds {next_version - from_version - 1} versions past the "
            f"one the record points at ({from_version}); one more would prune it — point "
            "the record at the latest version first",
        )


def plan_restage(vm: Vm, userdata: bytes) -> Plan:
    check_userdata(userdata)
    job = check_vm(vm)
    target = intake_path(vm.vm_id)
    size, digest = len(userdata), hashlib.sha256(userdata).hexdigest()
    from_path, from_version = str(job.userdata_vault_path), int(job.userdata_vault_version)
    next_version = _next_version(target)
    _refuse_pruning(target, from_path, from_version, next_version)
    return Plan(
        vm_id=vm.vm_id,
        job_id=job.job_id,
        kind=KIND_RESTAGE,
        from_path=from_path,
        from_version=from_version,
        to_path=target,
        to_version=next_version,
        size=size,
        digest_hex=digest,
        evidence={"bytes": size, "sha256": digest},
    )


def plan_rollback(vm: Vm, *, to_version: int | None = None, revert_last: bool = False) -> Plan:
    """Re-point at `to_version` of the intake path, or (`revert_last`) back
    to the pointer the latest restage replaced, legacy paths included."""
    job = check_vm(vm)
    target = intake_path(vm.vm_id)
    current = (str(job.userdata_vault_path), int(job.userdata_vault_version))
    if revert_last:
        history = launch_record.userdata_restages(job)
        if not history:
            raise RestageRefused("rollback-unavailable", "no restage to revert")
        last = history[-1]
        if last.get("new") != {
            "userdata_vault_path": current[0],
            "userdata_vault_version": current[1],
        }:
            raise RestageRefused(
                "rollback-unavailable",
                f"the record names {current[0]}@{current[1]}, the last restage wrote "
                f"{last.get('new')}: the pointer moved since",
            )
        previous = last.get("previous") or {}
        to_path = str(previous.get("userdata_vault_path") or "")
        to_version = int(previous.get("userdata_vault_version") or 0)
        if not to_path.startswith(f"{target.rsplit('/', 1)[0]}/") or to_version <= 0:
            raise RestageRefused("rollback-unavailable", f"bad audit entry: {previous}")
        evidence: dict[str, Any] = {"reverts_restage_at": last.get("at")}
    else:
        if to_version is None or int(to_version) <= 0:
            raise RestageRefused(
                "bad-request", "rollback_to_version must be a positive version", 400
            )
        to_path, to_version = target, int(to_version)
        evidence = {"to_version": to_version}
    if (to_path, to_version) == current:
        raise RestageRefused("rollback-unavailable", f"already on {to_path}@{to_version}")
    refusal = relaunch_input_refusal(to_path, to_version, intake=target)
    if refusal:
        raise RestageRefused("rollback-unavailable", refusal)
    return Plan(
        vm_id=vm.vm_id,
        job_id=job.job_id,
        kind=KIND_ROLLBACK,
        from_path=current[0],
        from_version=current[1],
        to_path=to_path,
        to_version=to_version,
        size=None,
        digest_hex="",
        evidence=evidence,
    )


# ── the write ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Written:
    to_path: str
    to_version: int
    staged_version: int  # 0 for a rollback


def _write_locked(
    locked: Vm, plan: Plan, userdata: bytes, *, operator: str, reason: str, request_id: str
) -> Written:
    """Inside the caller's transaction, holding `locked`'s row: re-decide,
    stage (a restage) and point the record. Raises `RestageRefused`."""
    current = check_vm(locked)
    if current.job_id != plan.job_id:
        raise RestageRefused("vm-not-restageable", "the vm's launch record changed")
    to_path, to_version, staged = plan.to_path, plan.to_version, 0
    if plan.kind == KIND_RESTAGE:
        # Re-read under the lock, and written check-and-set against it: a
        # launch intake stages this path BEFORE it takes the lock, and a
        # version slipped in between would let this write prune the one the
        # record points at.
        expected = _next_version(to_path)
        _refuse_pruning(to_path, plan.from_path, plan.from_version, expected)
        try:
            out = launch.stage_userdata_restage_copy(
                mount(), to_path, plan.vm_id, userdata, cas=expected - 1
            )
        except vault_kv.VaultCasConflict as exc:
            raise RestageRefused(
                "vm-not-restageable", f"{to_path} was written meanwhile — retry: {exc}"
            ) from exc
        except (EffectError, EffectUnavailable) as exc:
            raise RestageRefused("vault-unavailable", f"vault stage failed: {exc}", 503) from exc
        to_version = staged = int(out.version)
    else:
        # Again under the lock: a write to the path since the plan may have
        # pruned the version.
        refusal = relaunch_input_refusal(to_path, to_version, intake=intake_path(plan.vm_id))
        if refusal:
            raise RestageRefused("rollback-unavailable", refusal)
    prefix = REASON_PREFIX if plan.kind == KIND_RESTAGE else ROLLBACK_PREFIX
    evidence = {**plan.evidence, **({"request_id": request_id} if request_id else {})}
    try:
        launch_record.repoint_userdata(
            plan.vm_id,
            new_path=to_path,
            new_version=to_version,
            expected_job_id=plan.job_id,
            expected_path=plan.from_path,
            expected_version=plan.from_version,
            reason=f"{prefix}:{reason}",
            operator=operator,
            evidence=evidence,
        )
    except (LookupError, ValueError) as exc:
        msg = f"record not written: {exc}"
        if staged:
            msg += (
                f" — {to_path}@{staged} was staged but nothing points at it "
                "(inert: the VM is live, and §24 erases the whole path)"
            )
        raise RestageRefused("vm-not-restageable", msg) from exc
    log.warning(
        "userdata-restage: vm=%s %s by=%s request_id=%s %s@%s → %s@%s sha256=%s",
        plan.vm_id,
        plan.kind,
        operator,
        request_id or "-",
        plan.from_path,
        plan.from_version,
        to_path,
        to_version,
        plan.digest_hex or "-",
    )
    return Written(to_path=to_path, to_version=to_version, staged_version=staged)


def apply_plan(plan: Plan, userdata: bytes, *, operator: str, reason: str) -> Written:
    """The CLI's write: no job, the caller relaunches (or not)."""
    with transaction.atomic():
        locked = Vm.objects.select_for_update().get(vm_id=plan.vm_id)
        written = _write_locked(
            locked, plan, userdata, operator=operator, reason=reason, request_id=""
        )
    shadow = _shadowed_by(plan.vm_id, plan.job_id)
    if shadow:
        raise RestageRefused(
            "vm-not-restageable",
            f"pointed at {written.to_path}@{written.to_version}, but another launch record "
            f"now describes the VM ({shadow}) — check it before relaunching",
        )
    return written


# ── the API job ──────────────────────────────────────────────────────────


def _same_request(
    job: UserdataRestageJob, plan_kind: str, digest_hex: str, to_version: int
) -> bool:
    if job.kind != plan_kind:
        return False
    if plan_kind == KIND_RESTAGE:
        return job.digest_hex == digest_hex
    if plan_kind == KIND_REVERT:
        return True
    return int(job.to_version) == int(to_version)


def existing_job(vm: Vm, request_id: str) -> UserdataRestageJob | None:
    return (
        UserdataRestageJob.objects.filter(vm=vm, request_id=request_id)
        .select_related("vm", "decided_by")
        .first()
    )


def replay(
    job: UserdataRestageJob, *, kind: str, userdata: bytes, rollback_to_version: int | None
) -> UserdataRestageJob:
    """The job a replayed `request_id` names — iff it asks for the same."""
    digest = hashlib.sha256(userdata).hexdigest() if kind == KIND_RESTAGE else ""
    if not _same_request(job, kind, digest, int(rollback_to_version or 0)):
        raise RestageRefused(
            "request-id-reused", "this request_id already names a different restage"
        )
    return job


def start_job(
    vm: Vm,
    *,
    kind: str,
    userdata: bytes = b"",
    rollback_to_version: int | None = None,
    request_id: str,
    decided_by: Any,
    operator: str = "",
    reason: str = "",
) -> UserdataRestageJob:
    """Admit a restage / rollback: stage, point the record and create the
    job (`staged`) in ONE transaction under the Vm row lock. The next tick
    relaunches. A replayed `request_id` returns its job. `operator` /
    `reason` default to the API principal and its request_id."""
    found = existing_job(vm, request_id)
    if found is not None:
        return replay(found, kind=kind, userdata=userdata, rollback_to_version=rollback_to_version)
    try:
        if kind == KIND_RESTAGE:
            plan = plan_restage(vm, userdata)
        elif kind == KIND_REVERT:
            plan = plan_rollback(vm, revert_last=True)
        else:
            plan = plan_rollback(vm, to_version=rollback_to_version)
    except RestageRefused:
        # An identical request may have committed since the lookup above:
        # its job is then why this one is refused (`restage-in-flight`).
        found = existing_job(vm, request_id)
        if found is not None:
            return replay(
                found, kind=kind, userdata=userdata, rollback_to_version=rollback_to_version
            )
        raise
    operator = operator or str(getattr(decided_by, "name", "") or "?")
    try:
        with transaction.atomic():
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            found = existing_job(locked, request_id)
            if found is not None:
                return replay(
                    found, kind=kind, userdata=userdata, rollback_to_version=rollback_to_version
                )
            written = _write_locked(
                locked,
                plan,
                userdata,
                operator=operator,
                reason=reason or f"api request_id={request_id}",
                request_id=request_id,
            )
            job = UserdataRestageJob.objects.create(
                job_id=secrets.token_hex(16),
                vm=locked,
                request_id=request_id,
                kind=kind,
                from_path=plan.from_path,
                from_version=plan.from_version,
                to_path=written.to_path,
                to_version=written.to_version,
                size=plan.size,
                digest_hex=plan.digest_hex,
                measurement_before=launch_record.recorded_measurement(plan.vm_id),
                phase=UserdataRestagePhase.STAGED.value,
                phase_started_at=timezone.now(),
                decided_by=decided_by,
            )
    except IntegrityError as exc:
        # A concurrent request won the per-VM or the request_id constraint.
        found = existing_job(vm, request_id)
        if found is not None:
            return replay(
                found, kind=kind, userdata=userdata, rollback_to_version=rollback_to_version
            )
        raise RestageRefused("vm-not-restageable", "another restage is in flight") from exc
    return job


def _finish(job: UserdataRestageJob, phase: str, *, outcome: str, error: str = "") -> bool:
    now = timezone.now()
    done = UserdataRestageJob.objects.filter(
        pk=job.pk, version=job.version, phase=job.phase
    ).update(
        phase=phase,
        outcome=outcome,
        error=error[:512],
        phase_started_at=now,
        finished_at=now,
        version=job.version + 1,
    )
    return bool(done)


def _fail(job: UserdataRestageJob, vm: Vm, error: str) -> None:
    _finish(
        job,
        UserdataRestagePhase.FAILED.value,
        outcome=OUTCOME_FAILED,
        error=f"{error} — vm left {vm.power_state}; the record points at "
        f"{job.to_path}@{job.to_version}, so its next relaunch takes it",
    )


def _patch(job: UserdataRestageJob, **fields: Any) -> bool:
    """CAS `fields` onto `job` (same version + phase), bumping its version."""
    done = UserdataRestageJob.objects.filter(
        pk=job.pk, version=job.version, phase=job.phase
    ).update(version=job.version + 1, **fields)
    if done:
        for name, value in fields.items():
            setattr(job, name, value)
        job.version += 1
    return bool(done)


#: Power dispatches a relaunching job makes before it gives up.
MAX_ATTEMPTS = 10
#: Refusals worth asking again next tick: nothing changed, the VM is as it was.
_RETRYABLE = frozenset(
    {"allowlist-pin-busy", "recovery-relaunch-in-flight", "already-starting", "start-in-flight"}
)


def _settle_running(job: UserdataRestageJob, vm: Vm) -> None:
    """Committed once the launch record holds the relaunch's own
    measurement (an accepted relaunch records it); until then, wait."""
    if launch_record.recorded_measurement(vm.vm_id) != job.measurement_before:
        _finish(job, UserdataRestagePhase.RUNNING.value, outcome=OUTCOME_COMMITTED)
        log.info("userdata-restage %s: vm=%s relaunched", job.job_id, vm.vm_id)


def _step(job: UserdataRestageJob, vm: Vm) -> None:
    """One bounded power step of a `relaunching` job: stop it (once), then
    start it, each retried across ticks while transient."""
    from .services import power

    if job.stopped_at is None:
        if vm.power_state == VmPowerState.STOPPING:
            return  # a stop is landing; wait for it (power settles a stale one)
        if vm.power_state == VmPowerState.STOPPED:
            if _patch(job, stopped_at=timezone.now()):
                _step(job, vm)
            return
        if not _patch(job, attempts=job.attempts + 1):
            return  # another tick advanced it
        try:
            power.stop_vm(vm, by_userdata_restage=job.job_id)
        except power.PowerOpRefused as exc:
            if exc.reason in _RETRYABLE and job.attempts < MAX_ATTEMPTS:
                return
            _fail(job, vm, f"stop-refused:{exc.reason}: {exc.detail}")
            return
        except Exception as exc:  # noqa: BLE001 — the order may have landed: re-read next tick
            log.warning("userdata-restage %s: stop dispatch failed: %s", job.job_id, exc)
            return
        if not _patch(job, stopped_at=timezone.now()):
            return
        vm.refresh_from_db()
    if vm.power_state == VmPowerState.RUNNING:
        _settle_running(job, vm)
        return
    if vm.power_state != VmPowerState.STOPPED:
        return  # `starting` (ours, landing) or `stopping` settling: wait
    if job.attempts >= MAX_ATTEMPTS:
        _fail(job, vm, f"start-gave-up after {job.attempts} power dispatches")
        return
    if not _patch(job, attempts=job.attempts + 1):
        return  # another tick advanced it
    try:
        power.start_vm(vm, by_userdata_restage=job.job_id)
    except power.PowerOpRefused as exc:
        if exc.reason == power.DISKS_MISSING_REASON:
            _fail(job, vm, f"start-refused:{exc.reason}: {exc.detail}")
        return  # anything else: the VM is stopped and must come back — retry
    except Exception as exc:  # noqa: BLE001 — retried next tick, bounded by the attempts
        log.warning("userdata-restage %s: start dispatch failed: %s", job.job_id, exc)
        return
    vm.refresh_from_db()
    if vm.power_state == VmPowerState.RUNNING:
        _settle_running(job, vm)


def advance(job: UserdataRestageJob) -> None:
    """Advance `job` one bounded step: claim a `staged` job, then stop and
    start the VM across ticks until it runs on the new userdata."""
    if job.phase in TERMINAL_USERDATA_RESTAGE_PHASES:
        return
    vm = Vm.objects.get(pk=job.vm_id)
    if job.phase == UserdataRestagePhase.STAGED:
        # Since the admission: a launch that became the VM's record would
        # make this relaunch boot something else. (The job holds the VM
        # against every other operation from its creation on.)
        record = launch_record.latest_record(vm.vm_id)
        pointer = (
            (str(record.userdata_vault_path), int(record.userdata_vault_version))
            if record
            else None
        )
        if pointer != (job.to_path, int(job.to_version)):
            _fail(job, vm, f"record-moved: the launch record now points at {pointer}")
            return
        if not _patch(
            job, phase=UserdataRestagePhase.RELAUNCHING.value, phase_started_at=timezone.now()
        ):
            return
    # A `stopping`/`starting` marker left by a tick that died inside a power
    # op is settled to what the miner runs — the reboot-recovery scan, which
    # also does it, skips a VM a job holds (and may be off).
    from .resize import _settle_power_marker

    vm = _settle_power_marker(vm)
    if job.stopped_at is not None and vm.power_state == VmPowerState.RUNNING:
        # A relaunch that landed (maybe while no tick ran) settles before
        # the deadline is looked at.
        _settle_running(job, vm)
        job.refresh_from_db()
        if job.phase in TERMINAL_USERDATA_RESTAGE_PHASES:
            return
    if timezone.now() - job.phase_started_at > RELAUNCH_STALE:
        _fail(job, vm, "relaunch-timed-out: the relaunch did not settle in time")
        return
    _step(job, vm)


def tick_userdata_restages() -> int:
    """Advance every in-flight restage job one step. Returns how many."""
    jobs = list(UserdataRestageJob.objects.exclude(phase__in=TERMINAL_USERDATA_RESTAGE_PHASES))
    for job in jobs:
        try:
            advance(job)
        except Exception:  # noqa: BLE001 — one job must not kill the tick.
            log.exception("userdata-restage %s: unhandled error in tick", job.job_id)
    return len(jobs)
