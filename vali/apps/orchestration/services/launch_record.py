"""The launch record a VM's CURRENT boot is described by.

Every path that re-derives what a running VM booted — the §25 re-mint and
dest activation (`migration_ticket.resolve_ticket_inputs`,
`effects._launch_paths`), KBS-state recovery (`vali_kbs_recover`), the
allowlist carry-forward (`allowlist_pin`) — reads `result_json["emit"]` of
the VM's latest SUCCEEDED `LaunchJob`.

A reboot-recovery relaunch (and a power start, which uses it) is a new boot
with a NEW measurement: it mints a fresh `hippius.eol_nonce`, which is in the
SNP-measured cmdline. It never wrote a `LaunchJob`, so that emit kept
describing the FIRST boot. The KBS then held a VM at measurement B while
vali re-minted tickets at A — a latent brick at the next KBS-state recovery
or §25 hop ("measurement not in ticket's allowed set").

[`record_relaunch`] is the fix going forward: an accepted relaunch rewrites
the boot-describing emit keys of that same record. Deliberately NOT a new
`LaunchJob` row: other readers treat "a SUCCEEDED launch exists" as "the VM
has booted before" (NetBird persistent-key policy, abandoned-launch sweep),
and a relaunch must not change those answers. The values it replaces are
kept, newest last, under `emit["superseded"]`.

A launch dispatched but answered as failed may have booted all the same (an
Edge timeout, a ticket push that failed). A retry then meets that domain and
the miner answers `already-launched`: it started nothing, and its own
measurement never ran. vali cannot tell from its own history which earlier
dispatch is the one up, so the record keeps every candidate
(`emit["dispatched_boots"]`, [`add_dispatched_boot`]), is flagged
`emit["boot_unverified_since"]` ([`mark_boot_unverified`]) — no KBS
recovery registers it until it clears ([`assert_boot_verified`]): that would
bind the KBS to a launch that may not run, and refuse the running guest's
own ticket — and the guest's own KBS-attested measurement decides
([`resolve_unverified_boot`]). A §25 hop, a restore or a failover boots the
record afresh (cmdline and measurement together), so they need no wait.

An initrd swap ([`swap_initrd`], the `vali_swap_vm_initrd` command) moves
the record's `spec_json` onto a rebuilt initramfs for the NEXT boot. Until
that boot happens the running guest still measured the OLD initrd, so the
record also keeps `emit["booted_artifacts"]` — the artefact location the
CURRENT boot came from — and every reader that must reproduce the current
boot (the §25 dest staging, the launch-digest recompute) reads it through
[`booted_artifacts`]. An accepted relaunch records what IT booted there.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db import transaction
from django.utils import timezone

log = logging.getLogger(__name__)

# The emit keys that describe the BOOT (what the SNP launch measured and
# where its artefacts sit) — exactly what a relaunch changes. Everything
# else in the record (ticket_id, placement, attempts, the spec) describes
# the original LAUNCH and is left alone.
BOOT_KEYS: tuple[str, ...] = (
    "measurement_hex",
    "measurement_source",
    "measured_cmdline",
    "luks_disk_path",
    "kernel_path",
    "initrd_path",
    "rootfs_data_path",
    "rootfs_hash_path",
    "allowlist_epoch",
    "allowlist_sha256",
)

# Bound on `emit["superseded"]`: a VM restarted daily for years must not
# grow its launch record without limit. The newest entries are the useful
# ones (what the previous boots measured).
MAX_SUPERSEDED = 20


# `emit` key naming the artefacts the CURRENT boot measured, when they differ
# from the record's spec (an initrd swap not yet relaunched). Absent ⇒ the
# spec describes the current boot.
BOOTED_ARTIFACTS_KEY = "booted_artifacts"


# `emit` keys of an `already-launched` answer still to be settled (module
# docstring). Candidates are bounded: each is a dispatch since the boot on
# record, newest last.
DISPATCHED_BOOTS_KEY = "dispatched_boots"
BOOT_UNVERIFIED_KEY = "boot_unverified_since"
MAX_DISPATCHED_BOOTS = 8
# When an unverified record settled on the boot it ALREADY named (the guest
# attested it): no dispatch since then runs. Dropped by the next recorded
# boot.
ATTESTED_ON_RECORD_KEY = "attested_on_record_at"


def _latest_succeeded(vm_id: str, *, for_update: bool) -> Any:
    from apps.orchestration.models import LaunchJob, LaunchJobState

    qs = LaunchJob.objects.filter(vm_id=vm_id, state=LaunchJobState.SUCCEEDED.value)
    if for_update:
        qs = qs.select_for_update()
    return qs.order_by("-finished_at").first()


def latest_record(vm_id: str) -> Any:
    """`vm_id`'s launch record (its latest SUCCEEDED `LaunchJob`), or `None`."""
    return _latest_succeeded(vm_id, for_update=False)


def lock_latest_succeeded(vm_id: str) -> None:
    """Row-lock `vm_id`'s current launch record for the rest of the
    caller's transaction — the same row `record_relaunch` locks to write a
    relaunch's measurement, so a reader holding it sees no relaunch land."""
    _latest_succeeded(vm_id, for_update=True)


def recorded_measurement(vm_id: str) -> str:
    """The measurement vali currently records for `vm_id`'s boot — the same
    resolution `migration_ticket.resolve_ticket_inputs` uses (operator-pinned
    spec value first, else the emitted one). `""` when there is none."""
    job = _latest_succeeded(vm_id, for_update=False)
    if job is None:
        return ""
    spec = job.spec_json or {}
    emit = (job.result_json or {}).get("emit") or {}
    return str(spec.get("measurement_hex") or emit.get("measurement_hex") or "")


def booted_artifacts(job: Any) -> tuple[str, str]:
    """`(s3_key_prefix, initrd_sha256_hex)` the CURRENT boot of `job`'s VM
    was launched from. The spec's values, unless an initrd swap moved the
    spec ahead of the running boot (`emit["booted_artifacts"]`).

    A §25 destination must stage exactly these bytes: it replays the source
    boot's measured cmdline against a ticket minted for the source boot's
    measurement, and a different initrd changes the launch digest."""
    spec = job.spec_json or {}
    emit = (job.result_json or {}).get("emit") or {}
    booted = emit.get(BOOTED_ARTIFACTS_KEY)
    if isinstance(booted, dict):
        prefix = str(booted.get("s3_key_prefix") or "")
        initrd = str(booted.get("initrd_sha256_hex") or "")
        if prefix and initrd:
            return prefix, initrd
    return str(spec.get("s3_key_prefix") or ""), str(spec.get("initrd_sha256_hex") or "")


def _set_booted(job: Any, booted: tuple[str, str]) -> bool:
    """Record that the current boot came from `booted` — dropping the key
    when that is simply the spec. Returns `True` iff the emit changed (the
    caller saves)."""
    spec = job.spec_json or {}
    result = dict(job.result_json or {})
    emit = dict(result.get("emit") or {})
    before = emit.get(BOOTED_ARTIFACTS_KEY)
    spec_pair = (str(spec.get("s3_key_prefix") or ""), str(spec.get("initrd_sha256_hex") or ""))
    if booted == spec_pair:
        emit.pop(BOOTED_ARTIFACTS_KEY, None)
    else:
        emit[BOOTED_ARTIFACTS_KEY] = {"s3_key_prefix": booted[0], "initrd_sha256_hex": booted[1]}
    if emit.get(BOOTED_ARTIFACTS_KEY) == before:
        return False
    result["emit"] = emit
    job.result_json = result
    return True


def _supersede(job: Any, updates: dict[str, Any], *, reason: str, extra: dict[str, Any]) -> bool:
    """Apply `updates` to `job`'s emit, keeping the replaced values. Returns
    `False` (writes nothing) when nothing would change."""
    result = dict(job.result_json or {})
    emit = dict(result.get("emit") or {})
    changed = {k: v for k, v in updates.items() if emit.get(k) != v}
    if not changed:
        return False
    history = list(emit.get("superseded") or [])
    history.append(
        {
            "at": timezone.now().isoformat(),
            "reason": reason,
            "previous": {k: emit.get(k) for k in changed},
            **extra,
        }
    )
    emit.update(changed)
    emit["superseded"] = history[-MAX_SUPERSEDED:]
    result["emit"] = emit
    job.result_json = result
    job.save(update_fields=["result_json"])
    return True


def _set_flavor(job: Any, flavor: str, *, reason: str) -> bool:
    """Move the record's flavor (`spec_json["flavor"]` — what every relaunch,
    §25 hop and restore sizes the guest from — and the `flavor` column) to
    `flavor`, keeping the previous value in `emit["superseded"]`. Returns
    `True` iff it changed (the caller saves `spec_json`, `flavor` and
    `result_json`)."""
    spec = dict(job.spec_json or {})
    previous = str(spec.get("flavor") or "")
    if previous == flavor:
        return False
    # The disk stays the one the VM was launched with: pin it before the
    # flavor (which would otherwise imply its own) moves.
    spec.setdefault("data_disk_size_gb", data_disk_gb(job))
    spec["flavor"] = flavor
    job.spec_json = spec
    job.flavor = flavor
    result = dict(job.result_json or {})
    emit = dict(result.get("emit") or {})
    history = list(emit.get("superseded") or [])
    history.append(
        {"at": timezone.now().isoformat(), "reason": reason, "previous": {"flavor": previous}}
    )
    emit["superseded"] = history[-MAX_SUPERSEDED:]
    result["emit"] = emit
    job.result_json = result
    return True


# `emit` key naming the flavor the CURRENT boot was launched at, when the
# spec's moved ahead of it (a stopped VM resized on the books: its next start
# boots the spec's). Absent ⇒ the spec's flavor is the boot's.
BOOTED_FLAVOR_KEY = "booted_flavor"


def booted_flavor(job: Any) -> str:
    """The flavor `job`'s VM's CURRENT boot measured — what a §25 hop, a
    restore or a failover must reproduce (it replays that boot's
    measurement, and the vCPU count is measured). The spec's, unless a
    stopped-VM resize moved the spec ahead of the boot."""
    emit = (job.result_json or {}).get("emit") or {}
    booted = emit.get(BOOTED_FLAVOR_KEY)
    if booted:
        return str(booted)
    return str((job.spec_json or {}).get("flavor") or "")


def data_disk_gb(job: Any) -> int:
    """The DATA disk (GiB) `job`'s VM was launched with — pinned on the spec
    once a resize moved its flavor (the disk never follows the flavor), else
    the flavor's own. 0 when the record names no known flavor."""
    from .flavors import UnknownFlavor, resolve_flavor

    spec = job.spec_json or {}
    pinned = int(spec.get("data_disk_size_gb") or 0)
    if pinned:
        return pinned
    try:
        return resolve_flavor(str(spec.get("flavor") or "")).data_disk_size_gb
    except UnknownFlavor:
        return 0


def vm_data_disk_gb(vm_id: str) -> int:
    """[`data_disk_gb`] of `vm_id`'s current launch record (0 when none)."""
    job = _latest_succeeded(vm_id, for_update=False)
    return data_disk_gb(job) if job is not None else 0


def recorded_flavor(vm_id: str) -> str:
    """The flavor `vm_id`'s launch record sizes its next boot at — `""`
    when it has no record."""
    job = _latest_succeeded(vm_id, for_update=False)
    if job is None:
        return ""
    return str((job.spec_json or {}).get("flavor") or "")


def record_flavor(
    vm_id: str, flavor: str, *, reason: str, expected: str, booted: bool = False
) -> bool:
    """Move `vm_id`'s record to `flavor`. Compare-and-set against the
    flavor the caller decided on (`expected`): a record that moved since is
    refused. Returns `True` iff it changed.

    `booted=False` (a VM that is NOT running, resized on the books only):
    its next boot comes up at `flavor`, and the current boot stays recorded
    as `booted_flavor`. `booted=True`: a boot at `flavor` already happened
    (a relaunch whose own record write was lost) — no marker."""
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        current = str((job.spec_json or {}).get("flavor") or "")
        if current not in (expected, flavor):
            raise ValueError(
                f"vm {vm_id!r}: its recorded flavor is {current!r}, not the {expected!r} "
                "that was checked — refusing to overwrite"
            )
        before = booted_flavor(job)
        if not _set_flavor(job, flavor, reason=reason):
            return False
        # Nothing booted at `flavor`: the current boot (replayed by a §25
        # hop, a restore, a failover) is still the old size until a relaunch
        # records its own.
        result = dict(job.result_json or {})
        emit = dict(result.get("emit") or {})
        if booted or before == flavor:
            emit.pop(BOOTED_FLAVOR_KEY, None)
        else:
            emit[BOOTED_FLAVOR_KEY] = before
        result["emit"] = emit
        job.result_json = result
        job.save(update_fields=["spec_json", "flavor", "result_json"])
        return True


def record_relaunch(
    vm_id: str,
    relaunch_emit: dict[str, Any],
    *,
    reason: str,
    booted: tuple[str, str] | None = None,
    flavor: str | None = None,
) -> bool:
    """Make `vm_id`'s launch record describe the boot a relaunch just
    started. Only the [`BOOT_KEYS`] the relaunch actually emitted (non-empty)
    are written; the rest of the record is untouched. Returns `True` iff
    something changed.

    Raises when the relaunch emitted no measurement: an accepted relaunch
    always did, so a missing one is a bug to surface, never a reason to keep
    a record that is known to be stale.

    `booted` is the `(s3_key_prefix, initrd_sha256_hex)` the relaunch's
    spec named — what this new boot measured. It replaces any pending
    initrd-swap marker: a relaunch from the swapped spec clears it, one that
    raced a swap and launched the pre-swap spec keeps pointing at the old
    artefacts. `None` leaves the marker alone.

    `flavor` is the size this relaunch booted at (a resize): written in the
    SAME transaction as the measurement it produced, so the record never
    pairs a new-flavor measurement with the old flavor (a §25 hop would
    boot the wrong vCPU count against it) or the reverse. `None` leaves the
    record's flavor alone."""
    updates = {k: relaunch_emit[k] for k in BOOT_KEYS if relaunch_emit.get(k) not in (None, "")}
    if not updates.get("measurement_hex"):
        raise ValueError(f"relaunch of {vm_id!r} emitted no measurement_hex")
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        # This boot is the one on record now: nothing left to settle, and it
        # is the VM's current launch — stamped under this lock, so a
        # settlement racing it cannot leave an older one current.
        settled = _drop_unsettled(job)
        _stamp_current_launch(vm_id, str(updates["measurement_hex"]))
        booted_changed = (booted is not None and _set_booted(job, booted)) or settled
        flavor_changed = flavor is not None and _set_flavor(job, flavor, reason=reason)
        # This boot is at the spec's flavor: no pending booted-flavor marker.
        emit = dict((job.result_json or {}).get("emit") or {})
        if BOOTED_FLAVOR_KEY in emit:
            emit.pop(BOOTED_FLAVOR_KEY)
            job.result_json = {**(job.result_json or {}), "emit": emit}
            booted_changed = True
        superseded = _supersede(job, updates, reason=reason, extra={})
        if flavor_changed:
            # `_supersede` saves `result_json` only; the flavor also lives
            # in `spec_json` + the `flavor` column.
            job.save(update_fields=["spec_json", "flavor", "result_json"])
        elif booted_changed and not superseded:
            job.save(update_fields=["result_json"])
        return booted_changed or superseded or flavor_changed


def dispatched_boot_candidate(
    boot: dict[str, Any], *, booted: tuple[str, str] | None, flavor: str | None
) -> dict[str, Any]:
    """One candidate for `emit["dispatched_boots"]`: what a dispatch booted
    (its [`BOOT_KEYS`]), from which artefacts, at which size."""
    kept = {k: boot[k] for k in BOOT_KEYS if boot.get(k) not in (None, "")}
    if not kept.get("measurement_hex"):
        raise ValueError("a dispatched boot carries no measurement_hex")
    return {
        "boot": kept,
        "booted": list(booted) if booted is not None else None,
        "flavor": flavor,
        "at": timezone.now().isoformat(),
    }


def _drop_unsettled(job: Any) -> bool:
    """Drop the candidates and the unverified flag from `job` (unsaved).
    `True` iff there was anything to drop."""
    emit = dict((job.result_json or {}).get("emit") or {})
    keys = (DISPATCHED_BOOTS_KEY, BOOT_UNVERIFIED_KEY, ATTESTED_ON_RECORD_KEY)
    if not any(k in emit for k in keys):
        return False
    for k in keys:
        emit.pop(k, None)
    job.result_json = {**(job.result_json or {}), "emit": emit}
    return True


def add_dispatched_boot(vm_id: str, candidate: dict[str, Any]) -> None:
    """Keep a relaunch dispatched but answered as failed: it may be up all
    the same. The boot on record is untouched."""
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        emit = dict((job.result_json or {}).get("emit") or {})
        boots = [*(emit.get(DISPATCHED_BOOTS_KEY) or []), candidate]
        emit[DISPATCHED_BOOTS_KEY] = boots[-MAX_DISPATCHED_BOOTS:]
        job.result_json = {**(job.result_json or {}), "emit": emit}
        job.save(update_fields=["result_json"])


def mark_boot_unverified(vm_id: str) -> None:
    """An `already-launched` answer: the domain up is the boot on record or
    one of the candidates — not known until the guest attests. Kept from
    the FIRST such answer: only an attestation after it decides."""
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        emit = dict((job.result_json or {}).get("emit") or {})
        if emit.get(BOOT_UNVERIFIED_KEY):
            return
        emit[BOOT_UNVERIFIED_KEY] = timezone.now().isoformat()
        job.result_json = {**(job.result_json or {}), "emit": emit}
        job.save(update_fields=["result_json"])


def attested_on_record(job: Any) -> str:
    """When the guest attested the boot `job`'s record already named, after
    an `already-launched` answer (ISO time), `""` otherwise."""
    return str(((job.result_json or {}).get("emit") or {}).get(ATTESTED_ON_RECORD_KEY) or "")


def boot_unverified(job: Any) -> str:
    """When `job`'s record started waiting for an attestation of the boot
    that runs (ISO time), `""` when it is settled."""
    return str(((job.result_json or {}).get("emit") or {}).get(BOOT_UNVERIFIED_KEY) or "")


def assert_boot_verified(vm_id: str) -> None:
    """Raise `EffectError` while `vm_id`'s record waits for its guest to
    attest which boot runs ([`mark_boot_unverified`])."""
    from apps.orchestration.effects import EffectError

    job = _latest_succeeded(vm_id, for_update=False)
    since = boot_unverified(job) if job is not None else ""
    if since:
        raise EffectError(
            f"vm {vm_id!r} answered already-launched at {since}: which boot runs is not "
            "known until its guest attests (orchestration tick) — refusing to act on the "
            "record; vali_backfill_launch_measurement if it never attests"
        )


def resolve_unverified_boot(vm_id: str, attested_measurement_hex: str) -> str | None:
    """Settle an unverified record from the guest's KBS-attested
    measurement: the boot on record if it is that one, else the candidate
    that is (recorded as the boot, its size and artefacts with it). Returns
    the measurement now on record, `None` (nothing written) when the
    attested one is neither — a boot vali has no record of."""
    attested = attested_measurement_hex.strip().lower()
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None or not boot_unverified(job):
            return None
        spec = job.spec_json or {}
        emit = (job.result_json or {}).get("emit") or {}
        current = str(spec.get("measurement_hex") or emit.get("measurement_hex") or "")
        if current.strip().lower() == attested:
            _drop_unsettled(job)
            job.result_json["emit"][ATTESTED_ON_RECORD_KEY] = timezone.now().isoformat()
            job.save(update_fields=["result_json"])
            _stamp_current_launch(vm_id, current)
            return current
        match = next(
            (
                c
                for c in reversed(emit.get(DISPATCHED_BOOTS_KEY) or [])
                if str((c.get("boot") or {}).get("measurement_hex") or "").lower() == attested
            ),
            None,
        )
        if match is None:
            return None
        measurement = str(match["boot"]["measurement_hex"])
        record_relaunch(
            vm_id,
            dict(match["boot"]),
            reason="already-launched:attested",
            booted=tuple(match["booted"]) if match.get("booted") else None,
            flavor=match.get("flavor"),
        )
        return measurement


def _stamp_current_launch(vm_id: str, measurement_hex: str) -> None:
    """Make `measurement_hex` the VM's current launch NOW, in the caller's
    transaction: the allowlist then drops every launch before it AND the
    dispatches pinned since that never ran
    (`allowlist_pin._current_launch_pins`)."""
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.filter(vm_id=vm_id, launch_digest_hex__iexact=measurement_hex).update(
        launched_at=timezone.now()
    )


def correct_measurement(
    vm_id: str,
    measurement_hex: str,
    *,
    measured_cmdline: str,
    reason: str,
    evidence: dict[str, Any],
    expected_previous: str,
    booted: tuple[str, str] | None = None,
) -> bool:
    """Operator correction of the recorded boot (see the
    `vali_backfill_launch_measurement` command, which decides WHETHER).
    The measurement and the measured cmdline are written together: a §25
    destination boots the one against a ticket minted for the other.
    Refuses when an operator-pinned `spec_json["measurement_hex"]`
    disagrees: that value wins over the emit, and a pin is not ours to
    silently override. `evidence` is stored alongside the superseded values
    as the audit trail.

    `booted` is the `(s3_key_prefix, initrd_sha256_hex)` the correction's
    recompute PROVED the measurement over; it becomes the record's booted
    artefacts in the same write (clearing a pending-swap marker when it is
    the spec's). It must be what the record currently says is booted or
    what its spec names — anything else is a record that moved since it was
    read."""
    if not measured_cmdline:
        raise ValueError(f"vm {vm_id!r}: a correction needs the measured cmdline too")
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        spec = dict(job.spec_json or {})
        # Compare-and-set against the record the caller decided on: a
        # relaunch that recorded a NEWER boot since then must never be
        # overwritten with this older, now-superseded measurement.
        emit = (job.result_json or {}).get("emit") or {}
        current = str(spec.get("measurement_hex") or emit.get("measurement_hex") or "")
        if current.strip().lower() != expected_previous.strip().lower():
            raise ValueError(
                f"vm {vm_id!r}: its recorded measurement changed since it was read "
                f"({expected_previous[:16]}… → {current[:16]}…) — refusing to overwrite"
            )
        pinned = str(spec.get("measurement_hex") or "").strip().lower()
        if pinned and pinned != measurement_hex.strip().lower():
            raise ValueError(
                f"vm {vm_id!r} has an operator-pinned spec measurement {pinned[:16]}… — "
                "refusing to override a pin"
            )
        booted_changed = False
        if booted is not None:
            spec_pair = (
                str(spec.get("s3_key_prefix") or ""),
                str(spec.get("initrd_sha256_hex") or ""),
            )
            if booted not in (booted_artifacts(job), spec_pair):
                raise ValueError(
                    f"vm {vm_id!r}: the proved boot artefacts are neither the recorded "
                    "booted ones nor the spec's — the record moved, refusing to overwrite"
                )
            booted_changed = _set_booted(job, booted)
        # An operator-proven boot settles an `already-launched` record too,
        # and is the VM's current launch.
        booted_changed = _drop_unsettled(job) or booted_changed
        _stamp_current_launch(vm_id, measurement_hex)
        superseded = _supersede(
            job,
            {"measurement_hex": measurement_hex, "measured_cmdline": measured_cmdline},
            reason=reason,
            extra={"evidence": {k: v for k, v in evidence.items() if k != "measured_cmdline"}},
        )
        if booted_changed and not superseded:
            job.save(update_fields=["result_json"])
        return booted_changed or superseded


def swap_initrd(
    vm_id: str,
    *,
    new_prefix: str,
    new_initrd_sha256_hex: str,
    expected_job_id: str,
    expected_prefix: str,
    expected_initrd_sha256_hex: str,
    expected_marker: dict[str, Any] | None,
    reason: str,
    operator: str,
    evidence: dict[str, Any],
    restore_boot: dict[str, Any] | None = None,
    expected_last_audit_at: str | None = None,
) -> bool:
    """Move `vm_id`'s launch record onto a rebuilt initramfs for its NEXT
    boot (see the `vali_swap_vm_initrd` command, which decides WHETHER).

    Rewrites `spec_json["s3_key_prefix"]` + `spec_json["initrd_sha256_hex"]`
    — the only inputs a relaunch (`_reboot_recovery_relaunch`, power start)
    rebuilds the initrd from — under the record's row lock, compare-and-set
    against the record (`expected_job_id`), the values and the pending-swap
    marker (`expected_marker`, `None` = none) the caller decided on. The running boot is NOT
    changed, so the artefacts it measured are kept as
    `emit["booted_artifacts"]` until a relaunch records the new boot: a §25
    hop in between must stage the initrd the running guest measured.

    The previous and new values, the operator, the reason and `evidence` are
    appended to `emit["superseded"]`, the record's audit trail. A record
    already on the new values is a CAS failure like any other: whether that
    is a consistent no-op is the caller's decision, made before the call.
    Returns `True`.

    `restore_boot` (a REVERT of a swap whose relaunch was recorded but never
    attested) also puts the recorded boot back: each `BOOT_KEYS` value it
    names is restored (`None` = the key was absent), so the record again
    describes the pre-swap boot — which the restored spec matches, so no
    marker is kept. It requires `expected_last_audit_at` (the `at` of the
    audit entry the caller decided on — the relaunch record): anything
    recorded after it (another relaunch, a backfill) is a CAS failure."""
    if not (new_prefix and new_initrd_sha256_hex and operator and reason):
        raise ValueError(
            f"vm {vm_id!r}: a swap needs a prefix, an initrd sha, an operator, a reason"
        )
    with transaction.atomic():
        job = _latest_succeeded(vm_id, for_update=True)
        if job is None:
            raise LookupError(f"vm {vm_id!r} has no SUCCEEDED launch record")
        if job.job_id != expected_job_id:
            # Another launch record became the current one: it was never
            # checked (golden mode, unchanged kernel/base) — refuse.
            raise ValueError(
                f"vm {vm_id!r}: its current launch record is {job.job_id!r}, not the "
                f"{expected_job_id!r} that was checked — refusing to overwrite"
            )
        spec = dict(job.spec_json or {})
        current = (str(spec.get("s3_key_prefix") or ""), str(spec.get("initrd_sha256_hex") or ""))
        new = (new_prefix, new_initrd_sha256_hex)
        if current != (expected_prefix, expected_initrd_sha256_hex):
            raise ValueError(
                f"vm {vm_id!r}: its launch record's initrd changed since it was read "
                f"({expected_prefix} {expected_initrd_sha256_hex[:16]}… → "
                f"{current[0]} {current[1][:16]}…) — refusing to overwrite"
            )
        # The pending-swap marker is part of what the caller decided on: a
        # boot recorded meanwhile (a relaunch, a backfill) moves or clears
        # it, and changes what the running guest measured.
        marker = ((job.result_json or {}).get("emit") or {}).get(BOOTED_ARTIFACTS_KEY)
        if marker != expected_marker:
            raise ValueError(
                f"vm {vm_id!r}: its recorded boot changed since it was read — refusing to overwrite"
            )
        history_now = list(((job.result_json or {}).get("emit") or {}).get("superseded") or [])
        if restore_boot is not None:
            if not expected_last_audit_at or not history_now:
                raise ValueError(f"vm {vm_id!r}: a boot restore needs the audit entry it undoes")
            if history_now[-1].get("at") != expected_last_audit_at:
                raise ValueError(
                    f"vm {vm_id!r}: its launch record gained an audit entry since it was "
                    "read — refusing to overwrite"
                )
            if not set(restore_boot) <= set(BOOT_KEYS) or "measurement_hex" not in restore_boot:
                raise ValueError(f"vm {vm_id!r}: a boot restore must name boot keys only")
            # The restored boot came from the restored spec.
            booted = new
        else:
            booted = booted_artifacts(job)
        spec["s3_key_prefix"], spec["initrd_sha256_hex"] = new
        job.spec_json = spec
        _set_booted(job, booted)
        result = dict(job.result_json or {})
        emit = dict(result.get("emit") or {})
        entry: dict[str, Any] = {
            "at": timezone.now().isoformat(),
            "reason": reason,
            "operator": operator,
            "previous": {
                "spec.s3_key_prefix": current[0],
                "spec.initrd_sha256_hex": current[1],
            },
            "new": {"spec.s3_key_prefix": new[0], "spec.initrd_sha256_hex": new[1]},
            "evidence": evidence,
        }
        if restore_boot is not None:
            entry["previous_boot"] = {k: emit.get(k) for k in restore_boot}
            for key, value in restore_boot.items():
                if value is None:
                    emit.pop(key, None)
                else:
                    emit[key] = value
        history = list(emit.get("superseded") or [])
        history.append(entry)
        emit["superseded"] = history[-MAX_SUPERSEDED:]
        result["emit"] = emit
        job.result_json = result
        job.save(update_fields=["spec_json", "result_json"])
        return True
