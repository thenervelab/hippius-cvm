"""`vali_restage_userdata` — give an M0 VM a new cloud-init userdata at its NEXT boot.

## What it is for

Repairing a running tenant VM whose guest needs a one-off fix that cloud-init
can apply at boot (a `bootcmd` that rewrites a file before
`multi-user.target`), without touching its disks.

It stages a NEW version of the VM's userdata TEMPLATE exactly as launch
intake does (`launch_jobs.start_launch`): at `{prefix}/{vm_id}/userdata-intake`,
Transit-wrapped under `ud-<vm_id>`. It then points the VM's launch record
(`LaunchJob.userdata_vault_path` / `userdata_vault_version`) at that version.
That pointer is what a relaunch (reboot-recovery, power start) reads the
template back from. `launch.launch_on_miner` then does what it does on every
relaunch:
- substitutes the NetBird placeholder;
- re-stages the CANONICAL copy under the KBS-only `kek-<vm_id>`, plus the
  stamped working copy;
- mints a ticket whose §6 digest is taken over the new plaintext.

The KBS and the guest recompute that digest, as on any launch. Nothing about
the digest, its preimage or the custody of the canonical copy changes here.

Until the VM is relaunched, NOTHING it boots changes. Its current ticket binds
the canonical version the last launch staged. An in-guest `reboot` re-pushes
that ticket, and a §25 hop re-mints from the canonical + working copies (not
from the template), so both still see the old userdata. `--relaunch` does the
relaunch (power stop + start); otherwise do it with the power API.

## M0 ONLY

The golden initramfs hands cloud-init the KBS-released userdata on EVERY M0
boot, under a fresh random instance-id (`hippius-release-core.sh`
`hippius_write_seed_meta`). So the whole new userdata applies at the next
boot as a new instance: every per-instance module (users, ssh keys,
write_files, runcmd, ...) runs again, as it already does on every M0 boot.

An M1/M2 VM (`hippius.key_mode=split|customer`) hands cloud-init the
released userdata only on the boot that formats its volume, and an EMPTY one
on every later boot (`hippius-golden-overlay.sh` `hippius_golden_install_seed`).
A restage would never reach its cloud-init, so it is refused.

The userdata REPLACES the old one; nothing is merged. It must be the COMPLETE
template — the NetBird `{{NETBIRD_SETUP_KEY}}` placeholder when the VM
enrols NetBird, the tenant's keys, everything the original carried — plus the
fix. A `bootcmd` runs on EVERY boot the userdata stays staged: make it
idempotent, or wrap it in `cloud-init-per once <name> ...` (its semaphore is
on the persistent overlay and survives the per-boot instance-id). Restage
the original afterwards. See `docs/operator/userdata-restage-runbook.md`.

## Invocation

    manage.py vali_restage_userdata --vm-id <vm> --userdata-file <path> \\
        --by <who> --reason <why> [--dry-run] [--relaunch]

Rollback, without new bytes:

    manage.py vali_restage_userdata --vm-id <vm> --to-version <N> ...

points the record at version N of `{prefix}/{vm_id}/userdata-intake` (Vault
KV keeps the previous versions).

    manage.py vali_restage_userdata --vm-id <vm> --revert-last ...

puts back the pointer the latest restage replaced, read from the audit trail.
This works also when that pointer was a legacy path other than
`userdata-intake`.

## Refusals (nothing written)

- the VM is not `active`, not powered `running`, or has a §25/restore job,
  a decommission, resize or guest upgrade, a power stop/start, a
  reboot-recovery relaunch or a launch job in flight;
- it has no SUCCEEDED launch record;
- its key mode is not M0: the `Vm` pin, and the record's measured cmdline,
  which must agree with the pin (`customer_keys.resolve_for_remint`);
- the userdata is empty, not UTF-8, `vault:`-prefixed (reserved for
  ciphertext), larger than the launch API admits
  (`DATA_UPLOAD_MAX_MEMORY_SIZE`), or lacks the NetBird placeholder while
  the VM enrols NetBird;
- `--to-version` / `--revert-last` name a version a relaunch could not read
  back (pruned from Vault's history, an unwrapped value at the intake path,
  the KBS-only canonical copy), or the one the record already points at.

Everything is decided again under the Vm row lock, which is held across the
Vault write: a decommission cannot be created between the check and the
write and erase the path ahead of it. `--relaunch` re-checks once more
before the power stop: a launch or power op that took the VM after the
commit is left to finish, and the restage stands.

Not closed here: a launch intake for the SAME vm_id (`start_launch` admits
an active one) landing after that last check. Power ops do not refuse
launch jobs and intake does not refuse power markers, so this is the power
API's own gap. The same intake staging past Vault's `max_versions` could
prune a rollback target after the check under the lock. Both need a caller
re-POSTing the launch of a live VM. Don't run this command while one might.

## Custody

The command never prints, logs or stores the userdata: only its size and
sha256. It decrypts nothing. The new bytes are wrapped by Vault Transit
before they are written, and `--to-version` / `--revert-last` read only a
ciphertext prefix. vali still cannot decrypt the canonical copy.

## Audit

The write is compare-and-set under the Vm row lock and the launch record's
row lock. It is appended to the record's `emit["userdata_restages"]` with
the previous and new pointer, `--by`, `--reason`, and the size + sha256 of
the bytes staged.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.management.commands.vali_swap_vm_initrd import (
    _in_flight_refusal,
    _shadowed_by,
)
from apps.orchestration.services import customer_keys, launch, launch_record, vault_kv

REASON_PREFIX = "userdata-restage"
ROLLBACK_PREFIX = "userdata-restage-rollback"

#: The intake leaf `start_launch` stages a template at; restages write there.
INTAKE_LEAF = "userdata-intake"


def _intake_path(vm_id: str) -> str:
    prefix = str(getattr(settings, "VALI_VAULT_KV_PREFIX", ""))
    if not prefix:
        raise CommandError("VALI_VAULT_KV_PREFIX is not configured")
    return f"{prefix}/{vm_id}/{INTAKE_LEAF}"


def _mount() -> str:
    return str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))


def userdata_cap() -> int:
    """The largest userdata the launch API admits: its request body (JSON
    envelope included) is bounded by `DATA_UPLOAD_MAX_MEMORY_SIZE`, so no
    launched VM carries more."""
    return int(getattr(settings, "DATA_UPLOAD_MAX_MEMORY_SIZE", 64 * 1024))


def check_userdata(userdata: bytes, spec: dict[str, Any], vm_id: str) -> str:
    """Why `userdata` cannot be staged for this VM, `""` when it can. The
    launch intake's own rules, plus the cap the launch API's body bound
    implies."""
    if not userdata:
        return "userdata-empty"
    if len(userdata) > userdata_cap():
        return f"userdata-too-large:{len(userdata)}>{userdata_cap()}"
    if userdata.startswith(b"vault:"):
        # The discriminator every reader uses for Transit ciphertext.
        return "userdata-vault-prefixed"
    try:
        userdata.decode("utf-8")
    except UnicodeDecodeError:
        return "userdata-not-utf8"
    nb_err = launch.check_netbird_userdata(
        userdata,
        enable=bool(spec.get("enable_netbird", True)),
        hostname_template=str(spec.get("netbird_hostname_template") or "hippius-tenant-{vm_id}"),
        vm_id=vm_id,
    )
    if nb_err is not None:
        return f"userdata-netbird:{nb_err}"
    return ""


def _key_mode_refusal(vm: Vm, job: Any) -> str:
    """`""` iff `vm` is provably M0: its pin, and the measured cmdline its
    record carries, which must agree."""
    measured = str(((job.result_json or {}).get("emit") or {}).get("measured_cmdline") or "")
    try:
        binding = customer_keys.resolve_for_remint(vm, measured or None)
    except customer_keys.CustomerKeysError as exc:
        return f"key-mode-unprovable:{exc}"
    if binding is not None:
        return (
            f"not-m0:{binding.mode} — an M1/M2 guest hands cloud-init the released "
            "userdata only on its volume's first boot; a restage would never reach it"
        )
    return ""


def verdict(vm: Vm) -> tuple[str, dict[str, Any]]:
    """`(outcome, detail)` for `vm` itself (the target is checked by the
    caller). Only `restage` leads to a write."""
    detail: dict[str, Any] = {}
    refusal = _in_flight_refusal(vm)
    if refusal:
        return refusal, detail
    if vm.power_state != VmPowerState.RUNNING:
        return f"power-not-running:{vm.power_state}", detail
    job = launch_record.latest_record(vm.vm_id)
    if job is None:
        return "no-launch-record", detail
    detail.update(
        {
            "job_id": job.job_id,
            "old_path": str(job.userdata_vault_path),
            "old_version": int(job.userdata_vault_version),
            "_spec": dict(job.spec_json or {}),
            "_history": launch_record.userdata_restages(job),
        }
    )
    refusal = _key_mode_refusal(vm, job)
    if refusal:
        return refusal, detail
    return "restage", detail


def relaunch_input_refusal(path: str, version: int, *, intake: str) -> str:
    """`""` iff `path@version` is something a relaunch can read back as the
    template (`launch.open_userdata_intake_copy`). Reads the ciphertext's
    prefix only; nothing is decrypted.

    - it must exist (Vault prunes a path's oldest versions);
    - at the intake path it must be wrapped, as intake and restages write it;
    - the canonical `…/userdata` copy, once wrapped, is under the KBS-only
      `kek-<vm_id>`: vali cannot open it, so it is no template.

    A legacy `…/userdata-pending` pointer is taken as is: `--revert-last`
    puts back exactly what this VM's relaunches read before the restage."""
    try:
        stored = vault_kv.get_kv(_mount(), path, version=version)
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


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True, help="The VM to restage.")
        source = parser.add_mutually_exclusive_group(required=True)
        source.add_argument(
            "--userdata-file",
            default="",
            help="LOCAL path to the COMPLETE new cloud-init template (it replaces the "
            "old one; nothing is merged). Never printed.",
        )
        source.add_argument(
            "--to-version",
            type=int,
            default=None,
            help="Roll back: point the record at this existing version of "
            "{prefix}/{vm_id}/userdata-intake. No bytes are written.",
        )
        source.add_argument(
            "--revert-last",
            action="store_true",
            help="Roll back: put back the pointer the latest restage replaced "
            "(from the audit trail, legacy paths included).",
        )
        parser.add_argument("--by", required=True, help="Who is doing this (audited).")
        parser.add_argument("--reason", required=True, help="Why (audited).")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be staged and pointed at; write nothing.",
        )
        parser.add_argument(
            "--relaunch",
            action="store_true",
            help="After the write, relaunch the VM (power stop + start) so its next "
            "boot takes the new userdata. Without it, nothing boots the new "
            "userdata until a power stop/start or a reboot-recovery relaunch.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        by = str(opts["by"]).strip()
        reason = str(opts["reason"]).strip()
        if not by or not reason:
            raise CommandError("--by and --reason must not be empty")
        dry_run = bool(opts["dry_run"])
        if dry_run and opts["relaunch"]:
            raise CommandError("--dry-run and --relaunch are mutually exclusive")
        vm_id = str(opts["vm_id"]).strip()
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            raise CommandError(f"vm {vm_id!r}: no such VM")
        target = _intake_path(vm_id)

        userdata = b""
        if opts["userdata_file"]:
            try:
                userdata = Path(opts["userdata_file"]).read_bytes()
            except OSError as exc:
                raise CommandError(f"--userdata-file: {exc}") from exc
        try:
            self._run(vm, target, userdata, opts, by=by, reason=reason, dry_run=dry_run)
        finally:
            userdata = b"\x00" * len(userdata)

    def _run(
        self,
        vm: Vm,
        target: str,
        userdata: bytes,
        opts: dict[str, Any],
        *,
        by: str,
        reason: str,
        dry_run: bool,
    ) -> None:
        vm_id = vm.vm_id
        outcome, detail = verdict(vm)
        if outcome != "restage":
            raise CommandError(f"vm={vm_id} refused: {outcome}")
        evidence: dict[str, Any]
        new_path, new_version = target, 0
        if opts["userdata_file"]:
            refusal = check_userdata(userdata, detail["_spec"], vm_id)
            if refusal:
                raise CommandError(f"vm={vm_id} refused: {refusal}")
            evidence = {"bytes": len(userdata), "sha256": hashlib.sha256(userdata).hexdigest()}
            audit_reason = f"{REASON_PREFIX}:{reason}"
            try:
                next_version = (
                    vault_kv.latest_version(_mount(), target) + 1
                    if vault_kv.kv_exists(_mount(), target)
                    else 1
                )
            except EffectError as exc:
                raise CommandError(f"vm={vm_id}: cannot read {target}'s metadata: {exc}") from exc
            plan = (
                f"stage {evidence['bytes']} B (sha256 {evidence['sha256']}) at "
                f"{target}@{next_version} wrapped under "
                f"{vault_kv.userdata_transit_key_name(vm_id)}, then point the record at it"
            )
        else:
            if opts["revert_last"]:
                history = detail["_history"]
                if not history:
                    raise CommandError(f"vm={vm_id} refused: no-restage-to-revert")
                last = history[-1]
                current = {
                    "userdata_vault_path": detail["old_path"],
                    "userdata_vault_version": detail["old_version"],
                }
                if last.get("new") != current:
                    raise CommandError(
                        f"vm={vm_id} refused: pointer-moved-since-last-restage "
                        f"(the record names {detail['old_path']}@{detail['old_version']}, "
                        f"the last restage wrote {last.get('new')})"
                    )
                previous = last.get("previous") or {}
                new_path = str(previous.get("userdata_vault_path") or "")
                new_version = int(previous.get("userdata_vault_version") or 0)
                if not new_path.startswith(f"{target.rsplit('/', 1)[0]}/") or new_version <= 0:
                    raise CommandError(f"vm={vm_id} refused: bad-audit-entry:{previous}")
                evidence = {"reverts_restage_at": last.get("at")}
            else:
                new_version = int(opts["to_version"])
                if new_version <= 0:
                    raise CommandError("--to-version must be a positive version")
                evidence = {"to_version": new_version}
            if (new_path, new_version) == (detail["old_path"], detail["old_version"]):
                raise CommandError(
                    f"vm={vm_id} refused: already-on-version:{new_path}@{new_version}"
                )
            refusal = relaunch_input_refusal(new_path, new_version, intake=target)
            if refusal:
                raise CommandError(f"vm={vm_id} refused: {refusal}")
            audit_reason = f"{ROLLBACK_PREFIX}:{reason}"
            plan = f"point the record at {new_path}@{new_version} (nothing staged)"

        self.stdout.write(
            f"vm={vm_id} record={detail['job_id']} key_mode=M0 "
            f"current={detail['old_path']}@{detail['old_version']}"
        )
        self.stdout.write(f"plan: {plan}")
        if dry_run:
            self.stdout.write("vali-restage-userdata: mode=dry-run — nothing written")
            return

        staged_version = 0
        with transaction.atomic():
            # The Vm row lock power ops, reboot-recovery, launch intake and
            # §24 intake decide under, held across the Vault write too: a
            # decommission cannot be created between this check and the
            # write and then erase the path before it — which would leave
            # a template no later erase sweeps.
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            outcome, _now = verdict(locked)
            if outcome != "restage":
                raise CommandError(f"vm={vm_id} refused at write time: {outcome}")
            if opts["userdata_file"]:
                try:
                    staged = launch.stage_userdata_intake_copy(_mount(), target, vm_id, userdata)
                except (EffectError, EffectUnavailable) as exc:
                    raise CommandError(f"vm={vm_id}: vault stage failed: {exc}") from exc
                new_version = staged_version = int(staged.version)
            else:
                # Again under the lock: a write to the path since the first
                # check may have pruned the version.
                refusal = relaunch_input_refusal(new_path, new_version, intake=target)
                if refusal:
                    raise CommandError(f"vm={vm_id} refused at write time: {refusal}")
            try:
                launch_record.repoint_userdata(
                    vm_id,
                    new_path=new_path,
                    new_version=new_version,
                    expected_job_id=detail["job_id"],
                    expected_path=detail["old_path"],
                    expected_version=detail["old_version"],
                    reason=audit_reason,
                    operator=by,
                    evidence=evidence,
                )
            except (LookupError, ValueError) as exc:
                msg = f"vm={vm_id} refused at write time: write-refused:{exc}"
                if staged_version:
                    msg += (
                        f" — {target}@{staged_version} was staged but nothing points at "
                        "it (inert: the VM is live, and §24 erases the whole path)"
                    )
                raise CommandError(msg) from exc
        if staged_version:
            self.stdout.write(f"staged: {target}@{staged_version}")
        shadow = _shadowed_by(vm_id, detail["job_id"])
        if shadow:
            raise CommandError(
                f"vm={vm_id}: pointed at {new_path}@{new_version}, but another launch "
                f"record now describes the VM ({shadow}) — check it before relaunching"
            )
        self.stdout.write(
            f"vali-restage-userdata: mode=apply vm={vm_id} "
            f"{detail['old_path']}@{detail['old_version']} → {new_path}@{new_version}"
        )
        self.stdout.write(
            f"rollback: --to-version {detail['old_version']}"
            if detail["old_path"] == target
            else "rollback: --revert-last (the previous pointer is a legacy path)"
        )
        if not opts["relaunch"]:
            self.stdout.write(
                "next: relaunch the VM (power stop + start) — nothing boots the new "
                "userdata until then"
            )
            return
        self._relaunch(vm_id, detail["job_id"])

    def _relaunch(self, vm_id: str, job_id: str) -> None:
        from apps.orchestration.services import power

        vm = Vm.objects.get(vm_id=vm_id)
        # Since the commit: a launch intake, a power op or a relaunch that
        # took the VM would race the stop/start (power ops do not check
        # launch jobs). Leave the VM to it rather than relaunch over it.
        refusal = _in_flight_refusal(vm) or _shadowed_by(vm_id, job_id)
        if refusal:
            raise CommandError(
                f"vm={vm_id}: the restage stands, but the relaunch was NOT attempted "
                f"({refusal}) — relaunch it with the power API once that settles"
            )
        try:
            power.reboot_vm(vm)
        except power.PowerOpRefused as exc:
            raise CommandError(
                f"vm={vm_id}: the restage stands, but the relaunch was refused "
                f"({exc.reason}): {exc.detail} — relaunch it with the power API"
            ) from exc
        except Exception as exc:  # noqa: BLE001 — report, the restage stands
            raise CommandError(
                f"vm={vm_id}: the restage stands, but the relaunch failed "
                f"({type(exc).__name__}: {exc}) — the VM may be stopped: check its "
                "power state before retrying"
            ) from exc
        self.stdout.write(
            f"relaunched: vm={vm_id} — confirm a new VmLiveAttestation of its new "
            "measurement, then the fix in the guest"
        )
