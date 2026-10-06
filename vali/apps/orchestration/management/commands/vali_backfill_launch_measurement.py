"""`vali_backfill_launch_measurement` — record the measurement a running VM
actually booted, when vali's launch record still names an earlier boot's.

## Why

A reboot-recovery relaunch (and a power start) is a new boot with a new SNP
measurement — it mints a fresh `hippius.eol_nonce`, which is measured. Until
the fix that ships with this command (`launch_record.record_relaunch`), the
relaunch never updated the launch record every re-mint reads, so vali kept
the FIRST boot's measurement. A KBS-state recovery (`vali_kbs_recover`) or a
§25 hop then re-mints a ticket the running VM can never satisfy: it
registers cleanly and is denied at its next boot.

## What is recorded, and why it is safe

The new value must be proven by TWO independent sources that agree:

- the KBS's own evidence bundle for the VM (`GET /v1/admin/vm/:id/evidence`
  over the mTLS admin listener) — the measurement of the AMD-signed report
  the KBS verified at the VM's last release;
- the miner's persisted launch digest for the running domain
  (`/var/lib/hippius-miner/adopt/<vm>.json: launch_digest_hex`), read by the
  operator off the host and passed in with `--miner-digests`.

A VM is only corrected when both agree AND differ from what vali records.
Any disagreement between the two sources is reported and nothing is
written for that VM. An operator-pinned spec measurement is never
overridden.

The measured cmdline is corrected in the SAME write: a §25 destination
boots `emit["measured_cmdline"]` against a ticket minted for
`emit["measurement_hex"]`, so correcting one without the other would trade
a recovery brick for a migration brick. vali cannot rebuild the relaunch's
cmdline (it carries per-launch random tokens it never stored), so the
operator passes the running domain's `<os><cmdline>` (`virsh dumpxml`) with
`--miner-cmdlines`, and it is accepted only if vali's OWN launch-digest
recompute (pinned OVMF + the record's SHA-pinned kernel/initrd + that
cmdline) yields exactly the attested measurement.

After an initrd swap (`vali_swap_vm_initrd`) the record names two initrds:
the one the running boot measured (the pending-swap marker) and the swapped
one in the spec, which the next relaunch boots. A relaunch whose record
write failed leaves the marker on the OLD initrd while the guest runs the
NEW one; the recompute then tries the spec's initrd too, and a match (same
two agreeing sources, same cmdline proof) records the boot AND moves the
marker to what it proved was booted, in one write.

The replaced values and every source are kept in the record's
`emit["superseded"]` audit trail.

Run it BEFORE a KBS restart: the evidence archive does not survive one.

Dry-run is the default; `--commit` writes. Exit status is non-zero when any
VM's sources disagree or a write failed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import kbs_evidence, launch_record

_MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96}$")
REASON = "backfill:kbs-evidence+miner-adopt-digest+recomputed-cmdline"

# Outcomes that are fine to end on. Anything else is a problem for a VM the
# operator named with `--vm-id`; without `--vm-id`, "nothing to do here"
# outcomes (no miner input, no evidence) are expected for most of the fleet.
_OK = {"correct", "corrected", "already-correct", "settle", "settled"}
_BENIGN_UNSELECTED = {"no-miner-digest", "no-kbs-evidence", "no-launch-record"}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def recompute_digest(vm: Vm, cmdline: str, artifacts: tuple[str, str] | None = None) -> str:
    """vali's own C2 launch-digest recompute for `vm`'s launch record with
    `cmdline` — the same inputs `launch_on_miner` uses (the record's
    SHA-pinned kernel/initrd, the flavor's vCPU count, the host miner's
    chip generation). `artifacts` is the `(s3_key_prefix, initrd_sha)` to
    recompute over; by default the ones the record says are booted."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import flavors, launch_digest

    job = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    spec = job.spec_json or {}
    # The running boot's initrd — a swap not yet relaunched moved the spec on.
    prefix, initrd_sha = artifacts or launch_record.booted_artifacts(job)
    miner = MinerIdentity.objects.get(miner_id=vm.host)
    return launch_digest.recompute_expected_digest(
        s3_bucket=str(spec.get("s3_bucket") or ""),
        s3_key_prefix=prefix,
        kernel_sha256_hex=str(spec.get("kernel_sha256_hex") or ""),
        initrd_sha256_hex=initrd_sha,
        cmdline=cmdline,
        cpu_count=flavors.resolve_flavor(str(spec.get("flavor") or "")).cpu_count,
        platform_id=str(miner.platform_id or ""),
        snp_generation=miner.snp_generation,
    )


def verdict(
    vm: Vm, miner_digest: str | None, miner_cmdline: str | None
) -> tuple[str, dict[str, Any]]:
    """`(outcome, detail)` for one VM. Only `correct` leads to a write."""
    recorded = _norm(launch_record.recorded_measurement(vm.vm_id))
    detail: dict[str, Any] = {"recorded": recorded}
    if not recorded:
        return "no-launch-record", detail
    miner = _norm(miner_digest)
    if not miner:
        return "no-miner-digest", detail
    try:
        bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    except (EffectError, EffectUnavailable) as exc:
        detail["error"] = str(exc)
        return "kbs-evidence-error", detail
    if bundle is None:
        return "no-kbs-evidence", detail
    evidence = _norm(bundle.get("measurement_hex"))
    detail.update(
        {
            "kbs_evidence": evidence,
            "miner_adopt_digest": miner,
            "kbs_evidence_granted_at_unix": bundle.get("granted_at_unix"),
            "kbs_evidence_boot_counter": bundle.get("boot_counter"),
            "kbs_evidence_ticket_id": bundle.get("ticket_id"),
        }
    )
    if not (_MEASUREMENT_RE.match(evidence) and _MEASUREMENT_RE.match(miner)):
        return "malformed-source", detail
    if evidence != miner:
        return "sources-disagree", detail
    if evidence == recorded:
        # Both sources prove the boot on record runs: that settles a record
        # an `already-launched` answer left waiting (`launch_record`).
        job = launch_record._latest_succeeded(vm.vm_id, for_update=False)
        if job is not None and launch_record.boot_unverified(job):
            return "settle", detail
        return "already-correct", detail
    if not miner_cmdline:
        return "no-miner-cmdline", detail
    job = launch_record._latest_succeeded(vm.vm_id, for_update=False)
    booted = launch_record.booted_artifacts(job)
    spec = job.spec_json or {}
    spec_artifacts = (
        str(spec.get("s3_key_prefix") or ""),
        str(spec.get("initrd_sha256_hex") or ""),
    )
    # The artefacts the record says are booted first. When an initrd swap is
    # pending (`vali_swap_vm_initrd`) and they do not measure, the spec's —
    # the swapped initrd a relaunch boots: a relaunch whose record write
    # failed left the marker naming the OLD initrd. Either way the attested
    # measurement must equal vali's own recompute over the named bytes.
    candidates = [booted] + ([spec_artifacts] if spec_artifacts != booted else [])
    # A candidate whose recompute FAILS (its prefix unreadable, say) proves
    # nothing either way: the next one is still tried. Only when none
    # measures does a failure become the outcome.
    errors: list[str] = []
    for artifacts in candidates:
        try:
            recomputed = _norm(recompute_digest(vm, miner_cmdline, artifacts))
        except Exception as exc:  # noqa: BLE001 — any failure means "not proven".
            errors.append(f"{artifacts[0]}: {type(exc).__name__}: {exc}")
            continue
        detail["recomputed_from_cmdline"] = recomputed
        if recomputed == evidence:
            detail["measured_cmdline"] = miner_cmdline
            detail["booted_artifacts"] = list(artifacts)
            return "correct", detail
    if errors:
        # A candidate that could not be recomputed is not disproved.
        detail["error"] = "; ".join(errors)
        return "recompute-failed", detail
    return "cmdline-does-not-measure", detail


def _load(path: str, flag: str) -> dict[str, str]:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise CommandError(f"{flag}: {exc}") from exc
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise CommandError(f"{flag} must be a JSON object {{vm_id: string}}")
    return data


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--miner-digests",
            required=True,
            help="JSON file {vm_id: launch_digest_hex} read off each miner's "
            "/var/lib/hippius-miner/adopt/<vm>.json",
        )
        parser.add_argument(
            "--miner-cmdlines",
            required=True,
            help="JSON file {vm_id: cmdline} — the running domain's <os><cmdline> "
            "(virsh dumpxml), verbatim",
        )
        parser.add_argument("--vm-id", action="append", default=[], help="Limit to these VMs.")
        parser.add_argument("--commit", action="store_true", help="Write the corrections.")

    def handle(self, *args: Any, **opts: Any) -> None:
        digests = _load(opts["miner_digests"], "--miner-digests")
        cmdlines = _load(opts["miner_cmdlines"], "--miner-cmdlines")
        commit = bool(opts["commit"])
        selected = list(opts["vm_id"])
        qs = Vm.objects.filter(state=VmState.ACTIVE).order_by("vm_id")
        if selected:
            qs = qs.filter(vm_id__in=selected)
        vms = list(qs)
        problems = 0
        corrected = 0
        seen = {vm.vm_id for vm in vms}
        for vm_id in sorted(set(selected) - seen):
            self.stdout.write(f"vm={vm_id} outcome=not-an-active-vm")
            problems += 1
        for vm_id in sorted(set(digests) - seen):
            if not selected:
                self.stdout.write(f"vm={vm_id} outcome=digest-for-no-active-vm")
                problems += 1
        for vm in vms:
            outcome, detail = verdict(vm, digests.get(vm.vm_id), cmdlines.get(vm.vm_id))
            shown = {
                k: (str(v)[:16] if isinstance(v, str) else v)
                for k, v in detail.items()
                if k not in ("measured_cmdline", "booted_artifacts")
            }
            if outcome == "settle" and commit:
                if launch_record.resolve_unverified_boot(vm.vm_id, detail["kbs_evidence"]):
                    outcome = "settled"
                    corrected += 1
                else:
                    outcome = "write-refused:the record moved since it was read"
            if outcome == "correct" and commit:
                try:
                    launch_record.correct_measurement(
                        vm.vm_id,
                        detail["kbs_evidence"],
                        measured_cmdline=detail["measured_cmdline"],
                        reason=REASON,
                        evidence={k: v for k, v in detail.items() if k != "recorded"},
                        expected_previous=detail["recorded"],
                        booted=tuple(detail["booted_artifacts"]),
                    )
                    outcome = "corrected"
                    corrected += 1
                except (LookupError, ValueError) as exc:
                    outcome = f"write-refused:{exc}"
            if outcome not in _OK and (selected or outcome not in _BENIGN_UNSELECTED):
                problems += 1
            self.stdout.write(f"vm={vm.vm_id} outcome={outcome} {shown}")
        mode = "commit" if commit else "dry-run"
        self.stdout.write(
            "vali-backfill-launch-measurement: "
            f"mode={mode} corrected={corrected} problems={problems}"
        )
        if problems:
            raise CommandError(f"{problems} VM(s) need an operator: see the outcomes above")
