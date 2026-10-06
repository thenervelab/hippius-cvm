"""`vali_swap_vm_initrd` — move existing golden VMs onto a rebuilt initramfs.

## What it is for

An "initrd-only rebuild" (`scripts/tenant-initrd-rebuild.sh`) republishes a
golden bake with a new `tenant.initrd.img` and NOTHING else changed: same
kernel, same shared dm-verity base (`rootfs.img` + `rootfs.verity`), same
verity root hash. It writes the result under a NEW S3 prefix together with a
`measurement.json` recording the source it was rebuilt from.

This command points a VM's launch record at that rebuild, so the VM's NEXT
boot uses the new initramfs. It rewrites, on the VM's latest SUCCEEDED
`LaunchJob.spec_json`, exactly two keys — `s3_key_prefix` and
`initrd_sha256_hex` — which are what a relaunch (reboot-recovery, power
start) rebuilds its `LaunchSpec` from.

## It does NOT relaunch

The running guest is untouched. After `--apply`, the operator relaunches
each VM with the existing power stop/start (`POST .../power/stop`, then
`.../power/start`). The new boot is a new measurement, which the relaunch
records as usual. Until then the record keeps the artefacts the RUNNING boot
measured (`emit["booted_artifacts"]`), so a §25 migration in between stages
the initrd the guest actually booted and still unlocks.

## Invocation

Either let the command READ the rebuild's `golden.measurement.json` from S3
(vali's own client, a GET only — the prefix read is the rebuild's prefix):

    manage.py vali_swap_vm_initrd --vm-id <vm> [--vm-id ...] \
        --from-s3-prefix tenant/golden-ubuntu-x-initrd-abc123/ \
        --operator <who> --reason <why>            # dry-run; add --apply

(`--s3-bucket` defaults to VALI_PACKER_IMAGES_BUCKET), or pass a local copy:

    manage.py vali_swap_vm_initrd --vm-id <vm> \
        --measurement-json /tmp/golden.measurement.json \
        --s3-key-prefix tenant/golden-ubuntu-x-initrd-abc123 \
        --operator <who> --reason <why>

## Revert

`--revert` (no measurement.json) puts each VM back on the prefix + initrd its
latest swap replaced, read from the audit trail, with the same locks, CAS and
audit (`initrd-swap-revert:<reason>`). Two cases:

- the swap is still PENDING (no relaunch on the new initrd recorded: a
  refused power start, or none attempted) — the spec goes back;
- ONE relaunch on the new initrd was recorded but the guest never came up
  (never unlocked) — the spec AND the recorded boot go back, so the next
  start re-mints on the original initrd. Only if: nothing but that relaunch
  record follows the swap; the KBS never live-attested its measurement (no
  `VmLiveAttestation` of it — one that exists means the new initrd works:
  go back with a forward swap) and no in-guest signal since the relaunch;
  the VM was stopped by a completed power stop (the power API's stop — a
  `stopped` settled from a poll does not count) more than 2×
  VALI_UPTIME_LIVENESS_SKEW_S + 120 s ago (12 min by default), so no late
  attestation can still be written; and the miner affirmatively reports no
  live domain (an unreachable miner refuses).

Relaunch after reverting (power start), as after a swap.

## Refusals (no write)

A VM is only swapped when ALL of these hold; otherwise it is reported with
the reason and nothing is written for it:

- the VM is `active`, has no §25/restore job in flight, no power stop/start
  marker in flight and no reboot-recovery relaunch in flight;
- no launch job for it is queued or running (it would become the record);
- its launch record is `golden_verity_overlay`, carries no operator-pinned
  `measurement_hex` (a pin would deny the new boot) and has
  `auto_pin_allowlist` on (the new boot's measurement must be pinned);
- the rebuild's kernel sha, `rootfs.img` sha, `rootfs.verity` sha and
  verity root hash equal the record's;
- the rebuild records the record's CURRENT initrd sha as its source (and,
  when both name one, the record's bucket and source bake id);
- the rebuild's prefix is not the record's current prefix (the old prefix
  must stay intact: a §25 hop before the relaunch stages from it);
- no earlier swap of this VM is still waiting for its relaunch.

A record whose spec ALREADY names the rebuild is a no-op only when it also
records a consistent boot: the pending-swap marker naming the rebuild's
source initrd, or (marker gone) this swap followed by a recorded boot in the
audit trail. Otherwise (`on-rebuild-without-boot-record`,
`already-swapped-inconsistent-marker`) it is refused: nothing proves the
running guest measured the initrd the spec names. Relaunch the VM, or repair
the record with `vali_backfill_launch_measurement`.

## The measurement.json

The `golden.measurement.json` `scripts/tenant-initrd-rebuild.sh` writes: the
source golden bake's measurement with `initrd_sha256` replaced, plus an
`initrd_rebuild` provenance object. Read from it:

    kernel_sha256, initrd_sha256 (the rebuilt one), rootfs_img_sha256,
    rootfs_verity_sha256, verity_root_hash          top level
    initrd_rebuild.source_initrd_sha256             the initrd it replaced
    initrd_rebuild.source_bake_id                   optional; must equal the
                                                    record's bake_id when both set

It names no S3 location: pass the prefix the rebuild was uploaded to with
`--s3-key-prefix` (required). An optional top-level `s3_key_prefix` /
`s3_bucket` is honoured if present and must agree.

The miner verifies every fetched artefact against the sha in the spec, so a
prefix that does not hold the named bytes fails the relaunch's preflight —
it cannot boot something else.

## Audit

Each write is compare-and-set under the launch record's row lock and is
appended to the record's `emit["superseded"]` trail with the previous and
new prefix + initrd sha, `--operator`, `--reason` and the rebuild's
measurement.json.

Dry-run is the default; `--apply` writes. Exit status is non-zero when any
named VM was refused or a write failed.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch_record

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_GOLDEN = "golden_verity_overlay"
REASON_PREFIX = "initrd-swap"
REVERT_PREFIX = "initrd-swap-revert"

# Rebuild field → the launch-record spec key it must equal.
_UNCHANGED: tuple[tuple[str, str], ...] = (
    ("kernel_sha256", "kernel_sha256_hex"),
    ("rootfs_img_sha256", "rootfs_img_sha256_hex"),
    ("rootfs_verity_sha256", "rootfs_verity_sha256_hex"),
    ("verity_root_hash", "verity_root_hash_hex"),
)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


@dataclass(frozen=True)
class Rebuild:
    """The initrd-only rebuild, as its measurement.json describes it."""

    s3_key_prefix: str
    s3_bucket: str
    source_bake_id: str
    source_initrd_sha256: str
    initrd_sha256: str
    kernel_sha256: str
    rootfs_img_sha256: str
    rootfs_verity_sha256: str
    verity_root_hash: str
    document: dict[str, Any]


def _field(doc: dict[str, Any], name: str) -> str:
    for key in (name, f"{name}_hex"):
        if doc.get(key) not in (None, ""):
            return str(doc[key]).strip()
    return ""


# Provenance the rebuild script nests under `initrd_rebuild` (the rest of
# its measurement.json is the source golden bake's, `initrd_sha256` swapped).
_PROVENANCE = ("source_initrd_sha256", "source_bake_id")


def _provenance(doc: dict[str, Any], name: str) -> str:
    """`name` from the rebuild's `initrd_rebuild` object, where
    `scripts/tenant-initrd-rebuild.sh` writes it. A top-level copy is
    accepted too, but must agree with the nested one."""
    nested_doc = doc.get("initrd_rebuild")
    if nested_doc is not None and not isinstance(nested_doc, dict):
        raise CommandError("measurement.json: initrd_rebuild must be a JSON object")
    nested = _field(nested_doc or {}, name)
    top = _field(doc, name)
    if nested and top and _norm(nested) != _norm(top):
        raise CommandError(
            f"measurement.json: top-level {name} disagrees with initrd_rebuild.{name}"
        )
    return nested or top


#: The object name the rebuild script uploads its measurement under.
MEASUREMENT_OBJECT = "golden.measurement.json"
#: A measurement.json is a few KiB; anything near this is not one.
_MEASUREMENT_SIZE_CAP = 1 << 20


def load_rebuild(path: str, prefix_override: str) -> Rebuild:
    """Parse + validate the rebuild's measurement.json from a LOCAL file."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise CommandError(f"--measurement-json: {exc}") from exc
    return parse_rebuild(raw, prefix_override, source="--measurement-json")


def fetch_rebuild(bucket: str, prefix: str, prefix_override: str) -> Rebuild:
    """READ `<prefix>/golden.measurement.json` from `bucket` with vali's S3
    client (a GET — nothing is written) and parse it. The rebuild's prefix
    IS `prefix`; a `--s3-key-prefix` that names another one is refused."""
    from apps.storage import s3

    prefix = prefix.strip().strip("/")
    if not (bucket and prefix):
        raise CommandError("--from-s3-prefix needs a prefix and a bucket")
    if prefix_override and prefix_override.strip().rstrip("/") != prefix:
        raise CommandError("--s3-key-prefix disagrees with --from-s3-prefix")
    key = f"{prefix}/{MEASUREMENT_OBJECT}"
    read = {"bucket": bucket, "key": key, "max_bytes": _MEASUREMENT_SIZE_CAP}
    try:
        raw = s3.get_s3_client().get_object(**read)
    except Exception as exc:  # noqa: BLE001 — any S3 failure is a refusal.
        raise CommandError(f"--from-s3-prefix: cannot read s3://{bucket}/{key}: {exc}") from exc
    if raw is None:
        raise CommandError(f"--from-s3-prefix: s3://{bucket}/{key} does not exist")
    rebuild = parse_rebuild(raw, prefix, source=f"s3://{bucket}/{key}")
    if rebuild.s3_bucket and rebuild.s3_bucket != bucket:
        raise CommandError(f"s3://{bucket}/{key} names another bucket ({rebuild.s3_bucket})")
    # The bucket it was read from is where the rebuild lives: the VM's
    # record must name the same one (checked per VM, `bucket-mismatch`).
    return dataclasses.replace(rebuild, s3_bucket=bucket)


def parse_rebuild(raw: bytes, prefix_override: str, *, source: str) -> Rebuild:
    """Parse + validate a rebuild measurement.json. Raises `CommandError`
    on anything missing or malformed — no VM is looked at before this."""
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise CommandError(f"{source}: {exc}") from exc
    if not isinstance(doc, dict):
        raise CommandError(f"{source} must hold a JSON object")
    in_doc = _field(doc, "s3_key_prefix").rstrip("/")
    prefix = (prefix_override or in_doc).strip().rstrip("/")
    if not prefix:
        raise CommandError(
            "--s3-key-prefix is required: the measurement.json does not name the "
            "rebuild's S3 prefix (tenant-initrd-rebuild.sh never writes one)"
        )
    if prefix_override and in_doc and in_doc != prefix:
        raise CommandError("--s3-key-prefix disagrees with the measurement.json's s3_key_prefix")
    shas = {
        name: _norm(_provenance(doc, name) if name in _PROVENANCE else _field(doc, name))
        for name in (
            "source_initrd_sha256",
            "initrd_sha256",
            "kernel_sha256",
            "rootfs_img_sha256",
            "rootfs_verity_sha256",
            "verity_root_hash",
        )
    }
    bad = sorted(name for name, value in shas.items() if not _SHA_RE.match(value))
    if bad:
        raise CommandError(f"measurement.json: missing or non-64-hex {', '.join(bad)}")
    if shas["initrd_sha256"] == shas["source_initrd_sha256"]:
        raise CommandError(
            "measurement.json: the rebuilt initrd equals its source — nothing to swap"
        )
    return Rebuild(
        s3_key_prefix=prefix,
        s3_bucket=_field(doc, "s3_bucket"),
        source_bake_id=_provenance(doc, "source_bake_id"),
        document=doc,
        **shas,
    )


def _in_flight_refusal(vm: Vm) -> str:
    """Why `vm` cannot be swapped right now, `""` when it can. The same
    guards the power operations apply — a swap must not race a relaunch
    (it would launch whichever spec it read) or a migration/decommission."""
    from apps.orchestration.models import TERMINAL_MIGRATION_STATES, MigrationJob
    from apps.orchestration.services import power

    if vm.state != VmState.ACTIVE:
        return f"vm-not-active:{vm.state}"
    if MigrationJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_MIGRATION_STATES).exists():
        return "migration-in-flight"
    from apps.orchestration.service import _has_active_job

    if _has_active_job(vm):
        # A decommission, a resize, or a guest upgrade holding the VM.
        return "job-in-flight"
    for marker in (VmPowerState.STOPPING, VmPowerState.STARTING):
        if power._live_marker(vm, marker):
            return f"power-op-in-flight:{marker}"
    if power._recovery_relaunch_in_flight(vm):
        return "recovery-relaunch-in-flight"
    # A launch job finishing after the swap would become the latest
    # SUCCEEDED record — the one relaunches read — and silently undo it.
    if (
        LaunchJob.objects.filter(vm_id=vm.vm_id)
        .exclude(state__in=(LaunchJobState.SUCCEEDED.value, LaunchJobState.FAILED.value))
        .exists()
    ):
        return "launch-job-in-flight"
    return ""


def _shadowed_by(vm_id: str, job_id: str) -> str:
    """Re-check, AFTER the swap committed, that the swapped record is still
    the one a relaunch reads. Launch intake (`launch_jobs.start_launch`)
    refuses only a destroyed/decommissioning vm_id — it accepts an ACTIVE
    one — and a job it creates becomes the record relaunches read once it
    succeeds. Intake takes the same Vm row lock this command decides under,
    so a job is either visible to the decision (refused as in flight) or
    created after the swap committed (a later launch, which then legitimately
    describes the VM). This is the belt to that brace: it catches a job an
    intake without the lock (an older replica mid-deploy) slipped in. `""`
    when the swap stands."""
    ours = LaunchJob.objects.filter(job_id=job_id).values_list("finished_at", flat=True).first()
    # ONE statement, so a job moving queued → running → succeeded between
    # two reads cannot slip past both: any other job that is not FAILED and
    # is either still in flight or finished after ours.
    other = (
        LaunchJob.objects.filter(vm_id=vm_id)
        .exclude(job_id=job_id)
        .exclude(state=LaunchJobState.FAILED.value)
        .filter(
            ~Q(state=LaunchJobState.SUCCEEDED.value)
            | Q(finished_at__isnull=True)
            | Q(finished_at__gte=ours)
        )
        .values_list("state", flat=True)
        .first()
    )
    if other is None:
        return ""
    if other == LaunchJobState.SUCCEEDED.value:
        return "latest-launch-record-changed"
    return "launch-job-in-flight"


def verdict(vm: Vm, rebuild: Rebuild) -> tuple[str, dict[str, Any]]:
    """`(outcome, detail)` for one VM. Only `swap` leads to a write."""
    detail: dict[str, Any] = {}
    refusal = _in_flight_refusal(vm)
    if refusal:
        return refusal, detail
    job = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    if job is None:
        return "no-launch-record", detail
    spec = job.spec_json or {}
    current_prefix = str(spec.get("s3_key_prefix") or "")
    current_initrd = str(spec.get("initrd_sha256_hex") or "")
    detail["_marker"] = ((job.result_json or {}).get("emit") or {}).get(
        launch_record.BOOTED_ARTIFACTS_KEY
    )
    detail.update(
        {
            "job_id": job.job_id,
            "old_prefix": current_prefix,
            "old_initrd": current_initrd,
            "new_prefix": rebuild.s3_key_prefix,
            "new_initrd": rebuild.initrd_sha256,
        }
    )
    if str(spec.get("disk_mode") or "") != _GOLDEN:
        return "not-golden", detail
    if _norm(spec.get("measurement_hex")):
        return "measurement-pinned", detail
    if spec.get("auto_pin_allowlist") is not True:
        # The relaunch this swap exists for is a new measurement; without the
        # re-pin the KBS refuses it and the guest never unlocks.
        return "auto-pin-off", detail
    for field, key in _UNCHANGED:
        if _norm(spec.get(key)) != getattr(rebuild, field):
            return f"{field}-mismatch", detail
    if rebuild.s3_bucket and rebuild.s3_bucket != str(spec.get("s3_bucket") or ""):
        return "bucket-mismatch", detail
    bake_id = str(spec.get("bake_id") or "")
    if rebuild.source_bake_id and bake_id and rebuild.source_bake_id != bake_id:
        return "source-bake-mismatch", detail
    if (current_prefix.rstrip("/"), _norm(current_initrd)) == (
        rebuild.s3_key_prefix,
        rebuild.initrd_sha256,
    ):
        return _already_on_rebuild(job, rebuild), detail
    if launch_record.BOOTED_ARTIFACTS_KEY in ((job.result_json or {}).get("emit") or {}):
        # A previous swap is not relaunched yet. Swapping again would chain
        # rebuilds the running boot never measured; relaunch first.
        return "swap-pending-relaunch-first", detail
    if _norm(current_initrd) != rebuild.source_initrd_sha256:
        return "source-initrd-mismatch", detail
    if rebuild.s3_key_prefix == current_prefix.rstrip("/"):
        return "prefix-unchanged", detail
    return "swap", detail


def _spec_changes(history: list[dict[str, Any]]) -> list[int]:
    """Indices of the audit entries that changed the SPEC (a swap or a
    revert — they carry `new`). The rest record boots (relaunch, backfill)."""
    return [i for i, entry in enumerate(history) if isinstance(entry.get("new"), dict)]


def _is_forward_swap(entry: dict[str, Any]) -> bool:
    return str(entry.get("reason") or "").startswith(f"{REASON_PREFIX}:")


def _names(side: dict[str, Any], prefix: str, initrd: str) -> bool:
    """`side` (an audit entry's `new`/`previous`) names exactly `prefix` +
    `initrd`. Prefixes are S3 keys — case-sensitive, compared verbatim (bar
    a trailing `/`); shas case-insensitively."""
    return str(side.get("spec.s3_key_prefix") or "").rstrip("/") == prefix.rstrip("/") and _norm(
        side.get("spec.initrd_sha256_hex")
    ) == _norm(initrd)


def _already_on_rebuild(job: Any, rebuild: Rebuild) -> str:
    """The record's spec already names the rebuild. That is only a no-op
    when the record ALSO says which boot is running, consistently:

    - a pending-swap marker that is exactly what the swap replaced (the swap
      was applied, the VM not yet relaunched) — `already-swapped`;
    - no marker, and the audit trail shows this swap followed by a recorded
      boot (a relaunch, or a verified backfill) — `already-swapped-relaunched`.

    Only the LATEST spec change counts: an older swap onto this rebuild says
    nothing once a later swap or revert moved the record. Anything else
    means the spec names the rebuild while nothing proves the running boot
    measured it (a hand edit, a half-applied write): §25 would stage the new
    initrd against the old boot's measured cmdline and ticket, and the KBS
    would deny the destination. Refused, never papered over."""
    emit = (job.result_json or {}).get("emit") or {}
    marker = emit.get(launch_record.BOOTED_ARTIFACTS_KEY)
    history = list(emit.get("superseded") or [])
    changes = _spec_changes(history)
    last_swap = -1
    if changes:
        entry = history[changes[-1]]
        if _is_forward_swap(entry) and _names(
            entry["new"], rebuild.s3_key_prefix, rebuild.initrd_sha256
        ):
            last_swap = changes[-1]
    if marker is not None:
        if last_swap < 0:
            return "already-swapped-inconsistent-marker"
        previous = history[last_swap].get("previous") or {}
        booted_prefix, booted_initrd = launch_record.booted_artifacts(job)
        if (
            _names(previous, booted_prefix, booted_initrd)
            and _norm(booted_initrd) == rebuild.source_initrd_sha256
        ):
            return "already-swapped"
        return "already-swapped-inconsistent-marker"
    if last_swap >= 0 and any("new" not in later for later in history[last_swap + 1 :]):
        return "already-swapped-relaunched"
    return "on-rebuild-without-boot-record"


def revert_verdict(vm: Vm) -> tuple[str, dict[str, Any]]:
    """`(outcome, detail)` for putting `vm` back on its pre-swap initrd.
    Only `revert` leads to a write.

    Allowed only while the swap is still PENDING: the latest spec change is
    a swap, the record is exactly what it wrote, and the marker still names
    exactly what it replaced — i.e. no relaunch on the new initrd was ever
    recorded (it was refused, or never attempted). Once a relaunch recorded
    the new boot, the VM runs the new artefacts and going back is a new,
    audited swap with its own proofs, not a blind revert."""
    detail: dict[str, Any] = {}
    refusal = _in_flight_refusal(vm)
    if refusal:
        return refusal, detail
    job = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    if job is None:
        return "no-launch-record", detail
    spec = job.spec_json or {}
    current_prefix = str(spec.get("s3_key_prefix") or "")
    current_initrd = str(spec.get("initrd_sha256_hex") or "")
    detail["_marker"] = ((job.result_json or {}).get("emit") or {}).get(
        launch_record.BOOTED_ARTIFACTS_KEY
    )
    detail.update(
        {"job_id": job.job_id, "old_prefix": current_prefix, "old_initrd": current_initrd}
    )
    if str(spec.get("disk_mode") or "") != _GOLDEN:
        return "not-golden", detail
    emit = (job.result_json or {}).get("emit") or {}
    history = list(emit.get("superseded") or [])
    changes = _spec_changes(history)
    if not changes or not _is_forward_swap(history[changes[-1]]):
        return "no-swap-to-revert", detail
    entry = history[changes[-1]]
    previous = entry.get("previous") or {}
    detail.update(
        {
            "new_prefix": str(previous.get("spec.s3_key_prefix") or ""),
            "new_initrd": str(previous.get("spec.initrd_sha256_hex") or ""),
            "reverts_swap_at": entry.get("at"),
        }
    )
    if not _names(entry["new"], current_prefix, current_initrd):
        return "record-is-not-the-swapped-one", detail
    if launch_record.BOOTED_ARTIFACTS_KEY not in emit:
        return _relaunched_revert(vm, emit, history, changes[-1], detail)
    booted_prefix, booted_initrd = launch_record.booted_artifacts(job)
    if not (
        detail["new_prefix"]
        and _SHA_RE.match(_norm(detail["new_initrd"]))
        and _names(previous, booted_prefix, booted_initrd)
    ):
        return "inconsistent-marker", detail
    return "revert", detail


# The reason `_reboot_recovery_relaunch` (reboot-recovery AND power start)
# records a relaunch under.
RELAUNCH_REASON = "reboot-recovery-relaunch"


#: Upper bound on one attestation-ingest request, past its timestamp gate:
#: the gunicorn worker timeout (60 s, vali/Dockerfile) with margin.
_INGEST_REQUEST_BOUND_S = 120


def _attested(vm_id: str, measurement: str) -> bool:
    """The KBS live-attested `vm_id` at `measurement` — the boot came up."""
    from apps.telemetry.models import VmLiveAttestation

    return VmLiveAttestation.objects.filter(vm_id=vm_id, measurement__iexact=measurement).exists()


def _relaunched_revert(
    vm: Vm,
    emit: dict[str, Any],
    history: list[dict[str, Any]],
    swap_index: int,
    detail: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Revert of a swap whose relaunch on the new initrd WAS recorded but
    never came up: the most likely incident (the start was accepted, the
    guest never unlocked). Allowed only when ALL hold:

    - nothing but that ONE relaunch record follows the swap in the audit
      trail (no second relaunch, no backfill, no other change);
    - the KBS never live-attested the measurement that relaunch recorded —
      no `VmLiveAttestation` of it exists. One that does means the new
      initrd booted and unlocked: going back is a new, forward swap;
    - the VM is power-STOPPED by a completed stop ORDER
      (`Vm.stopped_by_order` — the miner then never restarts the domain on
      its own; a `stopped` settled from one "down" poll does not count) for
      more than twice the live-attestation skew window plus the bound on
      one ingest request, so no attestation of the new boot can still be
      written; no in-guest signal
      (`Vm.guest_signal_at`) since the relaunch; and its miner affirmatively
      reports NO live domain. `None` (miner unreachable) refuses.

    The write restores the pre-swap spec AND the boot the relaunch record
    replaced (measurement, measured cmdline, staged paths), so the record
    describes the pre-swap boot again: the next power start re-mints on the
    original initrd and a §25 hop stages the original."""
    from django.conf import settings
    from django.utils import timezone
    from django.utils.dateparse import parse_datetime

    from apps.orchestration import effects

    after = history[swap_index + 1 :]
    if (
        len(after) != 1
        or "new" in after[0]
        or after[0].get("reason") != RELAUNCH_REASON
        or not isinstance(after[0].get("previous"), dict)
    ):
        return "relaunched-on-new-initrd", detail
    restore = dict(after[0]["previous"])
    new_measurement = _norm(emit.get("measurement_hex"))
    if (
        not restore.get("measurement_hex")
        or not set(restore) <= set(launch_record.BOOT_KEYS)
        or not new_measurement
    ):
        return "relaunch-record-unusable", detail
    detail["new_measurement"] = new_measurement
    # The guest must be DURABLY stopped: an operator power stop completed
    # (the miner then no longer restarts the domain — an in-guest reboot's
    # watcher would, so a single "domain down" poll proves nothing), and
    # long enough ago that no attestation it produced can still arrive —
    # ingest refuses one verified more than the skew window ago
    # (`vm_liveness`), so after 2× that the attestation set is final.
    if vm.power_state != VmPowerState.STOPPED or vm.power_state_at is None:
        return f"not-stopped:{vm.power_state}", detail
    if not vm.stopped_by_order:
        # `stopped` from a settled abandoned marker (one "down" poll) or a
        # refused start — not a stop order the miner honours. Power start +
        # stop it, or just stop it again once it runs.
        return "stop-not-ordered", detail
    # Ingest accepts an attestation up to `skew` after its `verified_at`,
    # which a KBS clock up to `skew` ahead can put `skew` after the stop;
    # and an ingest request that passed that gate commits within the web
    # worker's timeout (gunicorn `--timeout 60`, vali/Dockerfile). Past this
    # quiet period no attestation of the stopped boot can still be written.
    skew_s = int(getattr(settings, "VALI_UPTIME_LIVENESS_SKEW_S", 300))
    quiet_s = 2 * skew_s + _INGEST_REQUEST_BOUND_S
    stopped_for = (timezone.now() - vm.power_state_at).total_seconds()
    if stopped_for <= quiet_s:
        detail["retry_in_s"] = int(quiet_s - stopped_for) + 1
        return "stopped-too-recently", detail
    # Any in-guest signal (served receipt or live attestation) after the
    # relaunch was recorded means the new boot came up.
    relaunched_at = parse_datetime(str(after[0].get("at") or ""))
    if relaunched_at is None:
        return "relaunch-record-unusable", detail
    if vm.guest_signal_at is not None and vm.guest_signal_at >= relaunched_at:
        return "guest-signalled-after-relaunch", detail
    if _attested(vm.vm_id, new_measurement):
        return "new-measurement-attested", detail
    running = effects.poll_domain_running(vm)
    if running is None:
        return "domain-state-unknown", detail
    if running:
        return "domain-running", detail
    detail["_restore_boot"] = restore
    detail["_expected_last_audit_at"] = after[0].get("at")
    return "revert", detail


_OK_OUTCOMES = frozenset(
    {"swap", "swapped", "already-swapped", "already-swapped-relaunched", "revert", "reverted"}
)


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--vm-id", action="append", required=True, help="VM to swap (repeatable)."
        )
        parser.add_argument(
            "--measurement-json",
            default="",
            help="LOCAL path to the rebuild's golden.measurement.json. Alternative to "
            "--from-s3-prefix; needs --s3-key-prefix.",
        )
        parser.add_argument(
            "--from-s3-prefix",
            default="",
            help="READ the rebuild's golden.measurement.json from this S3 prefix "
            "(e.g. tenant/golden-ubuntu-x-initrd-abc123/) with vali's S3 client — "
            "a GET only, nothing is written. The prefix is then the rebuild's "
            "prefix. Alternative to --measurement-json.",
        )
        parser.add_argument(
            "--s3-bucket",
            default="",
            help="Bucket for --from-s3-prefix (default: VALI_PACKER_IMAGES_BUCKET). "
            "Each VM's record must name the same bucket.",
        )
        parser.add_argument(
            "--s3-key-prefix",
            default="",
            help="The rebuild's S3 prefix (the upload's key prefix, no bucket). Required "
            "unless the measurement.json carries s3_key_prefix — the one "
            "tenant-initrd-rebuild.sh emits never does.",
        )
        parser.add_argument(
            "--revert",
            action="store_true",
            help="Put each VM back on the prefix + initrd its latest swap replaced "
            "(from the audit trail): while the swap is pending, or after ONE "
            "relaunch on it that never attested (VM stopped). See the docstring.",
        )
        parser.add_argument("--operator", required=True, help="Who is doing this (audited).")
        parser.add_argument("--reason", required=True, help="Why (audited).")
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Write. Without it nothing is written. Relaunch each VM "
            "afterwards with power stop + start (or power start, if it is "
            "stopped) — this command does not.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        from django.conf import settings

        revert = bool(opts["revert"])
        sources = [f for f in ("measurement_json", "from_s3_prefix") if opts[f]]
        if revert and (sources or opts["s3_key_prefix"] or opts["s3_bucket"]):
            raise CommandError(
                "--revert takes no --measurement-json / --from-s3-prefix / --s3-key-prefix"
            )
        if len(sources) > 1:
            raise CommandError("--measurement-json and --from-s3-prefix are mutually exclusive")
        if opts["s3_bucket"] and not opts["from_s3_prefix"]:
            raise CommandError("--s3-bucket only applies to --from-s3-prefix")
        if not revert and not sources:
            raise CommandError("--measurement-json or --from-s3-prefix is required (or --revert)")
        rebuild: Rebuild | None = None
        if opts["from_s3_prefix"]:
            bucket = opts["s3_bucket"] or str(
                getattr(settings, "VALI_PACKER_IMAGES_BUCKET", "") or ""
            )
            rebuild = fetch_rebuild(bucket, opts["from_s3_prefix"], opts["s3_key_prefix"])
        elif opts["measurement_json"]:
            rebuild = load_rebuild(opts["measurement_json"], opts["s3_key_prefix"])
        operator = str(opts["operator"]).strip()
        reason = str(opts["reason"]).strip()
        if not operator or not reason:
            raise CommandError("--operator and --reason must not be empty")
        apply = bool(opts["apply"])
        vm_ids = sorted(set(opts["vm_id"]))
        problems = 0
        written = 0
        for vm_id in vm_ids:
            outcome, detail = self._one(
                vm_id, rebuild, apply=apply, operator=operator, reason=reason
            )
            if outcome in ("swapped", "reverted"):
                written += 1
            elif outcome not in _OK_OUTCOMES:
                problems += 1
            shown = {
                k: (v[:16] if k.endswith(("_initrd", "_measurement")) and isinstance(v, str) else v)
                for k, v in detail.items()
                if not k.startswith("_")
            }
            self.stdout.write(f"vm={vm_id} outcome={outcome} {shown}")
        mode = "apply" if apply else "dry-run"
        verb = "reverted" if revert else "swapped"
        self.stdout.write(f"vali-swap-vm-initrd: mode={mode} {verb}={written} problems={problems}")
        if written:
            self.stdout.write(
                f"next: relaunch each {verb} VM with power stop + start (power start if "
                "it is stopped) — nothing boots the new record until then"
            )
        if problems:
            raise CommandError(f"{problems} VM(s) not {verb}: see the outcomes above")

    def _one(
        self, vm_id: str, rebuild: Rebuild | None, *, apply: bool, operator: str, reason: str
    ) -> tuple[str, dict[str, Any]]:
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return "no-such-vm", {}

        def decide(v: Vm) -> tuple[str, dict[str, Any]]:
            return revert_verdict(v) if rebuild is None else verdict(v, rebuild)

        if not apply:
            return decide(vm)
        go, done = ("revert", "reverted") if rebuild is None else ("swap", "swapped")
        with transaction.atomic():
            # The Vm row lock is the one power ops and reboot-recovery claim
            # their in-flight markers under: re-deciding while holding it
            # means no power op or relaunch starts between check and write.
            vm = Vm.objects.select_for_update().get(pk=vm.pk)
            outcome, detail = decide(vm)
            if outcome != go:
                return outcome, detail
            if rebuild is None:
                audit_reason = f"{REVERT_PREFIX}:{reason}"
                evidence: dict[str, Any] = {"reverts_swap_at": detail["reverts_swap_at"]}
            else:
                audit_reason = f"{REASON_PREFIX}:{reason}"
                evidence = {"rebuild_measurement": rebuild.document}
            try:
                launch_record.swap_initrd(
                    vm_id,
                    new_prefix=detail["new_prefix"],
                    new_initrd_sha256_hex=detail["new_initrd"],
                    expected_job_id=detail["job_id"],
                    expected_prefix=detail["old_prefix"],
                    expected_initrd_sha256_hex=detail["old_initrd"],
                    # What the decision saw of the recorded boot.
                    expected_marker=detail["_marker"],
                    reason=audit_reason,
                    operator=operator,
                    evidence=evidence,
                    restore_boot=detail.get("_restore_boot"),
                    expected_last_audit_at=detail.get("_expected_last_audit_at"),
                )
            except (LookupError, ValueError) as exc:
                return f"write-refused:{exc}", detail
            if detail.get("_restore_boot") is not None and _attested(
                vm_id, detail["new_measurement"]
            ):
                # Belt to the quiet period: an attestation of the new boot
                # committed after the decision read — undo the write.
                transaction.set_rollback(True)
                return "write-refused:new-measurement-attested-meanwhile", detail
        shadow = _shadowed_by(vm_id, detail["job_id"])
        if shadow:
            return f"{done}-but-shadowed:{shadow}", detail
        return done, detail
