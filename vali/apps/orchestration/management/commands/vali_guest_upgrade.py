"""`vali_guest_upgrade` — move one VM onto a guest components build
(docs/design/guest-component-rollout.md), or list its upgrades.

    manage.py vali_guest_upgrade --vm-id <vm> --release <N>
        [--not-before 2026-10-06T02:00:00Z] [--rollback] [--decided-by <client>]
        # dry-run (admission only); add --apply to create the job

    manage.py vali_guest_upgrade --vm-id <vm> --status

    manage.py vali_guest_upgrade --vm-id <vm> --release-parked <job_id> \
        --operator <who> --reason <why>
        # an operator who looked at a PARKING job's domain releases the VM
        # without the miner's DOWN (audited)

    manage.py vali_guest_upgrade --vm-id <vm> --recover start-on-target \
        [--job <job_id>] --operator <who> --reason <why>
        # dry-run; add --apply. Starts the VM a failed / upgrade_blocked job
        # left stopped, on the job's TARGET (never below the VM's required
        # epoch), through the power API (C2 ENFORCE, auto-pin, KBS
        # supersede). Not gated: the operator judges the boot. Audited on the
        # job. `--job` defaults to the VM's latest job.

`--release` picks the registered build of release N for the VM's base
(`vali_guest_build_register`). The job runs in the orchestration tick
(`VALI_GUEST_UPGRADE_ENABLED`): pending until `--not-before`, then stop,
swap, superseding relaunch, a live attestation of that launch, a soak.
`--rollback` admits a build OLDER than the one the VM runs (never one below
its required epoch).

On a VM whose latest job ended `upgrade_blocked`, `--release` RETRIES it:
the same release again (after a fix elsewhere), or a newer one. A retry may
restart the VM the blocked job left stopped. The required epoch never
moves. Runbook: docs/operator/guest-upgrade-recovery.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm
from apps.orchestration import guest_upgrade
from apps.orchestration.models import GuestInitrdBuild
from apps.orchestration.service import StartError
from apps.orchestration.services import launch, launch_record


def _build_for(vm: Vm, version: int) -> GuestInitrdBuild:
    if launch_record.latest_record(vm.vm_id) is None:
        raise CommandError(f"vm {vm.vm_id!r} has no launch record")
    build = guest_upgrade.build_for_vm(vm, version)
    if build is None:
        raise CommandError(
            f"no registered build of release v{version} for vm {vm.vm_id!r}'s base — build it "
            "(scripts/guest/guest-initrd-build.sh) and register it (vali_guest_build_register)"
        )
    return build


class Command(BaseCommand):
    help = "Upgrade one VM onto a guest components build (dry-run by default)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True)
        parser.add_argument("--release", type=int)
        parser.add_argument("--not-before", default="")
        parser.add_argument("--rollback", action="store_true")
        parser.add_argument("--decided-by", default="")
        parser.add_argument("--status", action="store_true")
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--release-parked", default="")
        parser.add_argument("--operator", default="")
        parser.add_argument("--reason", default="")
        parser.add_argument("--recover", choices=sorted(guest_upgrade.RECOVERY_ACTIONS))
        parser.add_argument("--job", default="")

    def handle(self, *args: Any, **opts: Any) -> None:
        vm = Vm.objects.filter(vm_id=opts["vm_id"]).first()
        if vm is None:
            raise CommandError(f"no vm {opts['vm_id']!r}")
        if opts["release_parked"]:
            job = vm.guest_upgrade_jobs.filter(job_id=opts["release_parked"]).first()
            if job is None:
                raise CommandError(f"no guest upgrade {opts['release_parked']!r} on {vm.vm_id!r}")
            try:
                guest_upgrade.release_parked(job, operator=opts["operator"], reason=opts["reason"])
            except ValueError as exc:
                raise CommandError(str(exc)) from exc
            job.refresh_from_db()
            self.stdout.write(f"released: job={job.job_id} → {job.state} by {job.released_by}")
            return
        if opts["recover"]:
            self._recover(vm, opts)
            return
        if opts["status"]:
            self._status(vm)
            return
        if opts["release"] is None:
            raise CommandError("--release is required (or --status)")
        build = _build_for(vm, opts["release"])
        not_before = None
        if opts["not_before"]:
            try:
                not_before = datetime.fromisoformat(opts["not_before"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise CommandError(f"--not-before: {exc}") from exc
        retry_of = guest_upgrade.blocked_job(vm)
        refusal = guest_upgrade._refusal(vm, build, rollback=opts["rollback"], retry_of=retry_of)
        if refusal:
            raise CommandError(f"refused: {refusal[0]}: {refusal[1]}")
        if not opts["apply"]:
            retry = f" (retrying {retry_of.job_id})" if retry_of is not None else ""
            self.stdout.write(
                f"dry-run: vm={vm.vm_id} would move to v{build.release_id} "
                f"(epoch {build.release.security_epoch}) {build.s3_key_prefix}{retry} — add --apply"
            )
            return
        decided_by = launch.resolve_forced_launch_principal(opts["decided_by"])
        try:
            job = guest_upgrade.start_guest_upgrade(
                vm=vm,
                build=build,
                decided_by=decided_by,
                not_before=not_before,
                rollback=opts["rollback"],
            )
        except StartError as exc:
            raise CommandError(f"refused: {exc.category}: {exc.message}") from exc
        self.stdout.write(
            f"admitted: job={job.job_id} vm={vm.vm_id} → v{build.release_id} "
            f"not_before={job.not_before.isoformat()} "
            f"(runs in the orchestration tick when VALI_GUEST_UPGRADE_ENABLED)"
        )

    def _status(self, vm: Vm) -> None:
        for job in vm.guest_upgrade_jobs.select_related("target", "retry_of").order_by(
            "started_at"
        ):
            outcome = (
                f" outcome={job.outcome} suspect={guest_upgrade.OUTCOME_SUSPECT.get(job.outcome)}"
                if job.outcome
                else ""
            )
            retry = f" retry_of={job.retry_of.job_id}" if job.retry_of_id else ""
            self.stdout.write(
                f"{job.job_id} v{job.target.release_id} {job.state}{outcome}{retry} "
                f"started={job.started_at.isoformat()} reason={job.reason or '-'}"
            )
            for a in job.attempt_rows.all():
                self.stdout.write(
                    f"    {a.kind} {a.outcome or 'open'} supersede={a.supersede} "
                    f"initrd={a.initrd_sha256[:16]}… measurement={a.measurement[:16] or '-'}"
                )
            for r in job.recoveries or []:
                self.stdout.write(
                    f"    recovery {r.get('action')} by={r.get('by')} at={r.get('at')} "
                    f"result={r.get('result')} reason={r.get('reason')}"
                )
        epochs = guest_upgrade.components_of(vm)
        self.stdout.write(
            f"required_epoch={epochs['required_epoch']} attested_epoch={epochs['attested_epoch']} "
            f"power={vm.power_state}"
        )

    def _recover(self, vm: Vm, opts: dict[str, Any]) -> None:
        jobs = vm.guest_upgrade_jobs.select_related("target", "target__release")
        job = (
            jobs.filter(job_id=opts["job"]).first()
            if opts["job"]
            else jobs.order_by("-started_at").first()
        )
        if job is None:
            raise CommandError(f"no guest upgrade {opts['job'] or ''} on {vm.vm_id!r}".strip())
        if not (opts["operator"].strip() and opts["reason"].strip()):
            raise CommandError("--recover needs --operator and --reason (audited)")
        if not opts["apply"]:
            refusal = guest_upgrade.recovery_refusal(job)
            if refusal:
                raise CommandError(f"refused: {refusal[0]}: {refusal[1]}")
            self.stdout.write(
                f"dry-run: would start vm={vm.vm_id} on v{job.target.release_id} "
                f"{job.target.s3_key_prefix} (job {job.job_id} is {job.state}, "
                f"outcome={job.outcome or '-'}) — add --apply"
            )
            return
        try:
            entry = guest_upgrade.recover_start_on_target(
                job, operator=opts["operator"], reason=opts["reason"]
            )
        except StartError as exc:
            raise CommandError(f"refused: {exc.category}: {exc.message}") from exc
        self.stdout.write(
            f"recovered: vm={vm.vm_id} started on v{entry['release']} (job {job.job_id}, "
            f"attempt {entry['attempt']}) by {entry['by']} — NOT health-verified: check "
            "--status and the guest; retry the upgrade to verify it"
        )
