"""The attestation verdict `GET /v1/vm/<vm_id>/attestation` reports.

Two KBS-signed sources say a VM is attested, and they fail differently:

- the LIVE attestation (`apps.telemetry.models.VmLiveAttestation`): the
  KBS signs one on every guest keepalive (~300 s) after verifying a fresh
  `SNP_GET_REPORT` bound to a single-use nonce for this `vm_id`, and vali
  stores a row only after verifying that signature against the pinned KBS
  L0 key. It survives a KBS restart — the rows live in vali's database and
  the guest keeps attesting against the restarted KBS.
- the RELEASE evidence (`kbs_evidence.fetch_evidence`): the §280 bundle the
  KBS archives when it releases the disk key at boot. It carries the raw SNP
  report + VCEK chain a tenant re-verifies offline, but it lives in the KBS
  CVM's `emptyDir` and is gone after a KBS restart until the guest boots
  again.

Reading only the second one is what made every live VM read
"no-evidence-recorded" after the 2026-10-04 KBS restart while all of them
were still attesting every five minutes. So the live sample is the primary
source and the release bundle the boot detail.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from django.conf import settings
from django.db.models import Q

from apps.orchestration.services import launch_record
from apps.telemetry.models import VmLiveAttestation

from .models import Vm, VmPowerState, VmState


class AttestationState(StrEnum):
    """Why the VM is (or is not) proven attested, strongest proof first."""

    # A fresh KBS-verified live attestation, by the guest the KBS released
    # the disk key to, of the VM's CURRENT launch on its CURRENT host, while
    # the VM is meant to be running: the measured guest is running now.
    ATTESTED_LIVE = "attested-live"
    # No such live sample, but the KBS holds the signed release bundle of
    # the current launch: the guest booted attested (it may be stopped).
    ATTESTED_AT_BOOT = "attested-at-boot"
    # No fetch failure, no bundle, but the current launch's released guest
    # attested live before — just not recently (e.g. after a KBS restart,
    # on a VM that has since stopped).
    STALE = "stale"
    # No live proof and the KBS could not be asked for its bundle.
    UNAVAILABLE = "unavailable"
    # Nothing on record for the current launch. NOT a negative verdict:
    # a VM launched before live attestation existed reads the same.
    UNPROVEN = "unproven"


# The legacy `attestation_status` each state maps to. `hippius-backend`
# normalises that field (`compute.services.ATTESTATION_VERDICTS`) and maps
# anything it does not know to "unknown", so it keeps its three values;
# `attestation_state` carries the detail.
_LEGACY_STATUS: dict[AttestationState, str] = {
    AttestationState.ATTESTED_LIVE: "evidence-recorded",
    AttestationState.ATTESTED_AT_BOOT: "evidence-recorded",
    AttestationState.STALE: "no-evidence-recorded",
    AttestationState.UNAVAILABLE: "evidence-unavailable",
    AttestationState.UNPROVEN: "no-evidence-recorded",
}

# Power states in which no guest is meant to run, so no sample — however
# recent — says the VM is running now.
_NOT_RUNNING = frozenset({VmPowerState.STOPPED.value, VmPowerState.OFF.value})


@dataclass(frozen=True)
class AttestationVerdict:
    state: AttestationState
    # The newest live sample that vouches for the current launch, or None.
    live: dict[str, Any] | None

    @property
    def attested(self) -> bool | None:
        """Legacy `attested`: True on proof, else None — never False."""
        if self.state in (AttestationState.ATTESTED_LIVE, AttestationState.ATTESTED_AT_BOOT):
            return True
        return None

    @property
    def legacy_status(self) -> str:
        return _LEGACY_STATUS[self.state]


def max_live_age_seconds() -> int:
    """How old the newest live sample may be and still count as live.

    `VALI_ATTESTATION_LIVE_MAX_AGE_S`, default 600 s: two 300 s keepalives,
    so one dropped beat does not flip the verdict. A sample past its signed
    `expiry_unix` never counts, whatever this says.
    """
    return int(getattr(settings, "VALI_ATTESTATION_LIVE_MAX_AGE_S", 600))


def _live_sample(row: VmLiveAttestation, *, now_unix: int, max_age_s: int) -> dict[str, Any]:
    age_s = max(0, now_unix - row.verified_at_unix)
    return {
        "verified_at_unix": row.verified_at_unix,
        "expiry_unix": row.expiry_unix,
        "age_s": age_s,
        "fresh": age_s <= max_age_s and now_unix <= row.expiry_unix,
        "max_age_s": max_age_s,
        "measurement_hex": row.measurement,
        "attestation_seq": row.attestation_seq,
        "chain_epoch": row.chain_epoch,
        "binding_source": row.binding_source,
        "chip_id_hex": row.chip_id,
        "report_id_hex": row.report_id,
        "node_id_hex": row.node_id_hex,
        "snp_report_digest_hex": row.snp_report_digest,
        "body_digest_hex": row.body_digest,
    }


def newest_live_sample(
    vm_id: str,
    *,
    measurement_hex: str,
    platform_id: str | None,
    not_before_unix: int | None,
    now_unix: int,
) -> dict[str, Any] | None:
    """The newest verified live attestation that vouches for `vm_id`'s
    CURRENT boot on its CURRENT host, or None.

    A sample vouches only when all of these hold:

    - its measurement is `measurement_hex`, the current launch's: a
      relaunch mints a fresh measured nonce, so an older launch's samples
      say nothing about this one;
    - it names the guest the KBS RELEASED the disk key to: a `release`
      sample, or a `first-use` one (a KBS restart wiped the binding) whose
      `(chip_id, report_id)` a `release` sample of this launch already
      named. Any other `first-use` is whoever asked — e.g. a second guest
      of the same image a miner booted itself — and proves nothing;
    - its chip is the VM's current host (`platform_id`): after a §25 move
      (same measurement) the source's samples do not vouch for the
      destination;
    - it is not older than the current boot (`not_before_unix`, the VM's
      `boot_started_at`): after a §25 round trip back to a host, the
      previous residency's guest does not vouch for the new one.
    """
    from apps.scheduler.service import _is_real_chip_id

    if not measurement_hex or not platform_id or not _is_real_chip_id(platform_id):
        return None
    launch = VmLiveAttestation.objects.filter(
        vm_id=vm_id,
        measurement__iexact=measurement_hex,
        # `vm_liveness.chip_matches_platform`'s prefix rule, in SQL.
        chip_id__istartswith=platform_id.strip(),
    )
    if not_before_unix is not None:
        launch = launch.filter(verified_at_unix__gte=not_before_unix)
    released = set(
        launch.filter(binding_source="release")
        .exclude(report_id="")
        .values_list("chip_id", "report_id")
        .distinct()
    )
    if not released:
        return None
    same_guest = Q()
    for chip_id, report_id in released:
        same_guest |= Q(chip_id=chip_id, report_id=report_id)
    row = (
        launch.filter(binding_source__in=("release", "first-use"))
        .filter(same_guest)
        .order_by("-verified_at_unix")
        .first()
    )
    if row is None:
        return None
    return _live_sample(row, now_unix=now_unix, max_age_s=max_live_age_seconds())


def _evidence_is_current(evidence: dict[str, Any], *, measurement_hex: str) -> bool:
    """The release bundle is of the current launch. Without a recorded
    launch measurement there is nothing to compare, and the bundle stands
    on its own as before."""
    if not measurement_hex:
        return True
    bundled = str(evidence.get("measurement_hex") or "")
    return bundled.lower() == measurement_hex.lower()


def host_platform_id(vm: Vm) -> str | None:
    """The registered SNP chip of the VM's CURRENT host — the platform the
    KBS releases to (`migration_ticket._node_platform_id`). Not the
    `OrderTicketIntake`'s: the async launch path persists none, and after a
    §25 move it names the source."""
    from apps.miners.models import MinerIdentity

    if not vm.host:
        return None
    return (
        MinerIdentity.objects.filter(miner_id=vm.host)
        .values_list("platform_id", flat=True)
        .first()
    )


def evaluate(
    vm: Vm,
    *,
    evidence: dict[str, Any] | None,
    evidence_fetch_failed: bool,
    now_unix: int,
) -> AttestationVerdict:
    """The verdict for `vm`, strongest proof first."""
    measurement_hex = launch_record.recorded_measurement(vm.vm_id)
    live = newest_live_sample(
        vm.vm_id,
        measurement_hex=measurement_hex,
        platform_id=host_platform_id(vm),
        not_before_unix=int(vm.boot_started_at.timestamp()) if vm.boot_started_at else None,
        now_unix=now_unix,
    )
    running = vm.state == VmState.ACTIVE and vm.power_state not in _NOT_RUNNING
    if live is not None and live["fresh"] and running:
        state = AttestationState.ATTESTED_LIVE
    elif evidence is not None and _evidence_is_current(evidence, measurement_hex=measurement_hex):
        state = AttestationState.ATTESTED_AT_BOOT
    elif evidence_fetch_failed:
        state = AttestationState.UNAVAILABLE
    elif live is not None:
        state = AttestationState.STALE
    else:
        state = AttestationState.UNPROVEN
    return AttestationVerdict(state=state, live=live)
