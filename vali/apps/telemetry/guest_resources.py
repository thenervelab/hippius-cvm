"""Does the miner give a VM the resources of its flavor?

## What is enforced where

- **vCPU count** — cryptographically, at launch. The SNP launch digest
  folds one VMSA per vCPU; vali recomputes it from the flavor's
  `cpu_count` (`orchestration.services.launch_digest`), pins only that
  value in the §22 allowlist and the ticket, and the KBS releases the KEK
  only to a report carrying it. A miner that starts the guest with any
  other vCPU count gets no disk key.
- **RAM** — NOT measured: the VMM announces it through the firmware
  memory map. This module is the check. A keepalive image launched with
  the MEASURED `hippius.attest_resources=1` token reads, each tick, the
  vCPUs online, the firmware map's `System RAM`, `MemTotal` and the RAM
  it has not accepted yet, and folds them into the `REPORT_DATA` of its
  SNP report. The KBS verifies the report against AMD's root and that
  `REPORT_DATA`, and signs the values into the live attestation (schema
  v3). The miner relays those bytes but cannot change one number.

## Which launch a sample is judged against

Every sample carries the launch measurement the KBS saw. The
`MeasurementLedger` row vali wrote when it pinned that measurement says
which flavor the launch was measured for, whether its cmdline asked for
the resources, and whether it asked for `accept_memory=eager`. So a
sample is judged against the launch that produced it, never against
whatever the VM became since — no race with a resize.

- `superseded` — vali's newest ACCEPTED launch of the VM (the ledger row
  stamped `launched_at` when the miner created the domain) is a later one,
  and the sample was verified after that acceptance
  (+ `VALI_GUEST_SUPERSEDED_GRACE_S`, the vali/KBS clock skew bound). A
  guest of an EARLIER launch still attesting is a miner running a stale
  launch — e.g. the pre-resize size booted with the pre-resize ticket. A
  relaunch that failed after its pin never supersedes anything, and a §25
  migration keeps the measured cmdline (same measurement, no new pin).
- `unattested` — the launch asked for resources and the body carries
  none: an image too old to attest them. Not the miner's doing (the image
  is measured), so no evidence — but nothing to pay on under ENFORCE.
- `short` — fewer vCPUs online than the flavor, or less RAM:
  - with a firmware map: its `System RAM` more than
    `VALI_GUEST_MEM_FIRMWARE_SLACK_MIB` below the flavor (absolute: the
    firmware keeps a fixed few MiB; a ratio would hand the miner
    gigabytes on a large flavor);
  - without one: `MemTotal` below the flavor minus what the kernel
    reserves for itself — the struct page array (≤ 2 %), the SEV swiotlb
    (6 % capped at 1 GiB) and `VALI_GUEST_MEM_TOTAL_SLACK_MIB` for the
    rest (kernel image, firmware ranges);
  - a launch with `accept_memory=eager`: any unaccepted RAM beyond the
    slack. Eager acceptance makes the guest PVALIDATE all of it at boot,
    so the host had to back all of it; RAM still unaccepted means it did
    not. Without it the figure is only what the VMM ANNOUNCED — lazily
    accepted RAM a host could overcommit, found out only when the tenant
    touches it.
- `ok` — at least the flavor. Over-provisioning is not a finding.
- blank — the launch did not ask (pre-v3 body, flag off): unjudged.

## What a finding costs

- always: the row carries its verdict; `short` and `superseded` write or
  refresh `GuestResourceShortfall` (evidence against the node), flag the
  VM on `/v1/operator/fleet`, and fail the synthetic `guest_resources`
  check (alert);
- with `VALI_GUEST_RESOURCES_ENFORCE`: only an `ok` sample is uptime
  coverage, and any other one is a barrier no later sample vouches back
  across (`vm_liveness.covered_intervals`). A VM must therefore PROVE its
  size to be paid: a launch from before the attestation was switched on
  earns nothing until it is relaunched — arm ENFORCE only once the
  synthetic check reports no unproven VM.

## Trust

The miner cannot forge, strip or swap a figure. Root INSIDE the guest
can: it may ask `/dev/sev-guest` for a report over any `REPORT_DATA`, so
it can make its own VM look short — or, colluding with the miner (a
miner renting its own VM), make a short VM look full. That is the same
in-guest-root exclusion as the rest of uptime billing: a tenant who is
the miner is its own victim. So the evidence never removes a miner from
placement by itself; an operator reads it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

log = logging.getLogger("apps.telemetry.guest_resources")

VERDICT_OK = "ok"
VERDICT_SHORT = "short"
VERDICT_SUPERSEDED = "superseded"
VERDICT_UNATTESTED = "unattested"
#: The launch did not ask for resources — nothing judged.
VERDICT_NONE = ""

#: Evidence against the node (`GuestResourceShortfall`).
EVIDENCE_VERDICTS = frozenset({VERDICT_SHORT, VERDICT_SUPERSEDED})


@dataclass(frozen=True)
class Attested:
    vcpus_online: int
    mem_firmware_kib: int
    mem_total_kib: int
    mem_unaccepted_kib: int


@dataclass(frozen=True)
class LaunchFacts:
    """What vali recorded about the launch that produced a measurement."""

    flavor: str
    attests_resources: bool
    accepts_memory_eagerly: bool


@dataclass(frozen=True)
class Verdict:
    verdict: str
    # Closed vocabulary, `+`-joined: `vcpus`, `mem-firmware`, `mem-total`,
    # `mem-unaccepted`; `superseded-launch` for a superseded sample.
    reason: str = ""
    # The flavor judged against (blank when nothing was judged).
    flavor: str = ""


def enforce_requested() -> bool:
    return bool(getattr(settings, "VALI_GUEST_RESOURCES_ENFORCE", False))


def enforce() -> bool:
    """ENFORCE in effect. It acts through the uptime-coverage meter, which
    reads coverage only when `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION` is
    armed — without it nothing is withheld, so ENFORCE is not in effect
    (and `misconfigured()` says so)."""
    return enforce_requested() and bool(
        getattr(settings, "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION", False)
    )


def misconfigured() -> str | None:
    """Why the requested ENFORCE cannot act, or `None`."""
    if enforce_requested() and not enforce():
        return (
            "VALI_GUEST_RESOURCES_ENFORCE is set but VALI_UPTIME_REQUIRE_LIVENESS_"
            "ATTESTATION is not: uptime is credited without coverage, so nothing "
            "is withheld"
        )
    if enforce() and not attest_on_launch():
        return (
            "VALI_GUEST_RESOURCES_ENFORCE is in effect but VALI_GUEST_ATTEST_RESOURCES "
            "is off: no new launch can prove its size, so none will be paid"
        )
    return None


def attest_on_launch() -> bool:
    """Put `hippius.attest_resources=1` on the measured cmdline."""
    return bool(getattr(settings, "VALI_GUEST_ATTEST_RESOURCES", False))


def accept_memory_eagerly() -> bool:
    """Put `accept_memory=eager` on the measured cmdline."""
    return bool(getattr(settings, "VALI_GUEST_ACCEPT_MEMORY_EAGER", False))


def _firmware_slack_kib() -> int:
    return int(getattr(settings, "VALI_GUEST_MEM_FIRMWARE_SLACK_MIB", 64)) * 1024


def _mem_total_slack_kib() -> int:
    return int(getattr(settings, "VALI_GUEST_MEM_TOTAL_SLACK_MIB", 256)) * 1024


def _superseded_grace_s() -> int:
    return int(getattr(settings, "VALI_GUEST_SUPERSEDED_GRACE_S", 300))


def mem_total_floor_kib(want_kib: int) -> int:
    """The lowest `MemTotal` an honest SEV-SNP guest of `want_kib` shows:
    the kernel keeps the struct page array (64 B per 4 KiB page, 1.6 %;
    2 % here), the SEV swiotlb bounce buffer (6 % of RAM, capped at
    1 GiB) and a fixed slack for the rest."""
    swiotlb = min(want_kib * 6 // 100, 1024 * 1024)
    return want_kib - want_kib * 2 // 100 - swiotlb - _mem_total_slack_kib()


def flag_window_s() -> int:
    return int(getattr(settings, "VALI_GUEST_RESOURCES_FLAG_S", 3600))


def judge(*, cpu_count: int, memory_mb: int, attested: Attested, eager: bool = False) -> Verdict:
    """The verdict of one attested sample against a flavor's size."""
    short: list[str] = []
    if attested.vcpus_online < cpu_count:
        short.append("vcpus")
    want_kib = memory_mb * 1024
    if attested.mem_firmware_kib > 0:
        if want_kib - attested.mem_firmware_kib > _firmware_slack_kib():
            short.append("mem-firmware")
    elif attested.mem_total_kib < mem_total_floor_kib(want_kib):
        short.append("mem-total")
    if eager and attested.mem_unaccepted_kib > _firmware_slack_kib():
        short.append("mem-unaccepted")
    if short:
        return Verdict(VERDICT_SHORT, "+".join(short))
    return Verdict(VERDICT_OK)


def launch_facts(vm_id: str, measurement_hex: str) -> tuple[LaunchFacts | None, datetime | None]:
    """`(facts of the launch that pinned measurement_hex, when a LATER
    launch of the VM was accepted)` — the second is `None` while this
    measurement's launch is the newest accepted one (or no later launch
    was ever accepted). Facts are `None` when the measurement has no
    ledger row (the ingest refuses those before)."""
    from apps.orchestration.models import MeasurementLedger

    rows = MeasurementLedger.objects.filter(vm_id=vm_id)
    mine = rows.filter(launch_digest_hex__iexact=measurement_hex).order_by("-pinned_at").first()
    if mine is None:
        return None, None
    later = (
        rows.filter(launched_at__isnull=False, pinned_at__gt=mine.pinned_at)
        .exclude(launch_digest_hex__iexact=measurement_hex)
        .order_by("launched_at")
        .first()
    )
    facts = LaunchFacts(
        flavor=mine.flavor,
        attests_resources=mine.attests_resources,
        accepts_memory_eagerly=mine.accepts_memory_eagerly,
    )
    return facts, later.launched_at if later is not None else None


def judge_sample(
    *,
    vm_id: str,
    measurement_hex: str,
    verified_at_unix: int,
    binding_flavor: str,
    attested: Attested | None,
) -> Verdict:
    """The verdict for one ingested live attestation. Never raises on a
    vali-side data gap (an unknown flavor): logged, not judged — a liveness
    sample is never dropped because of this module."""
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor

    facts, superseded_at = launch_facts(vm_id, measurement_hex)
    if facts is None:
        return Verdict(VERDICT_NONE)
    if superseded_at is not None:
        cutoff = superseded_at + timedelta(seconds=_superseded_grace_s())
        if verified_at_unix > int(cutoff.timestamp()):
            return Verdict(VERDICT_SUPERSEDED, "superseded-launch")
    if attested is None:
        return Verdict(VERDICT_UNATTESTED if facts.attests_resources else VERDICT_NONE)
    # Rows pinned before the ledger recorded the flavor fall back to the
    # billing binding's.
    flavor = facts.flavor or binding_flavor
    try:
        size = resolve_flavor(flavor)
    except UnknownFlavor:
        log.error("guest resources not judged: flavor %r is not in the catalogue", flavor)
        return Verdict(VERDICT_NONE)
    v = judge(
        cpu_count=size.cpu_count,
        memory_mb=size.memory_mb,
        attested=attested,
        eager=facts.accepts_memory_eagerly,
    )
    return Verdict(v.verdict, v.reason, flavor)


def record_shortfall(
    *,
    vm_id: str,
    node_id_hex: str,
    flavor: str,
    attested: Attested | None,
    verdict: Verdict,
    body_digest: str,
    now: datetime | None = None,
) -> None:
    """Write or refresh the evidence row for a `short` / `superseded`
    sample. Runs inside the caller's transaction: the evidence and the
    sample it rests on are written together or not at all."""
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor

    from .models import GuestResourceShortfall

    now = now or timezone.now()
    try:
        size = resolve_flavor(flavor)
        want_vcpus, want_memory_mb = size.cpu_count, size.memory_mb
    except UnknownFlavor:
        want_vcpus = want_memory_mb = 0
    latest = {
        "vcpus_online": attested.vcpus_online if attested else None,
        "mem_firmware_kib": attested.mem_firmware_kib if attested else None,
        "mem_total_kib": attested.mem_total_kib if attested else None,
        "mem_unaccepted_kib": attested.mem_unaccepted_kib if attested else None,
        "reason": verdict.reason,
        "last_seen_at": now,
        "last_body_digest": body_digest,
    }
    key = {"vm_id": vm_id, "node_id_hex": node_id_hex.lower(), "flavor": flavor}
    updated = GuestResourceShortfall.objects.filter(**key).update(
        samples=F("samples") + 1, **latest
    )
    if not updated:
        try:
            with transaction.atomic():
                GuestResourceShortfall.objects.create(
                    **key,
                    want_vcpus=want_vcpus,
                    want_memory_mb=want_memory_mb,
                    first_seen_at=now,
                    **latest,
                )
        except IntegrityError:
            # A concurrent ingest of the same VM created it first.
            GuestResourceShortfall.objects.filter(**key).update(samples=F("samples") + 1, **latest)
    log.error(
        "guest resource FINDING: vm=%s node=%s flavor=%s (%d vCPU / %d MiB) verdict=%s "
        "reason=%s attested=%s%s",
        vm_id,
        node_id_hex[:16],
        flavor,
        want_vcpus,
        want_memory_mb,
        verdict.verdict,
        verdict.reason,
        attested,
        " — NOT credited (enforce)" if enforce() else " — observe mode, still credited",
    )


@dataclass(frozen=True)
class GuestResourceShortfallView:
    node_id_hex: str
    flavor: str
    reason: str
    want_vcpus: int
    want_memory_mb: int
    vcpus_online: int | None
    mem_firmware_kib: int | None
    mem_total_kib: int | None
    mem_unaccepted_kib: int | None
    samples: int
    first_seen_at: datetime
    last_seen_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id_hex,
            "flavor": self.flavor,
            "reason": self.reason,
            "want_vcpus": self.want_vcpus,
            "want_memory_mb": self.want_memory_mb,
            "vcpus_online": self.vcpus_online,
            "mem_firmware_kib": self.mem_firmware_kib,
            "mem_total_kib": self.mem_total_kib,
            "mem_unaccepted_kib": self.mem_unaccepted_kib,
            "samples": self.samples,
            "first_seen_at": self.first_seen_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
        }


def flagged(now: datetime | None = None) -> dict[str, GuestResourceShortfallView]:
    """`vm_id → its latest finding` for every VM with one within the flag
    window — the operator-facing "degraded" set."""
    from .models import GuestResourceShortfall

    now = now or timezone.now()
    since = now - timedelta(seconds=flag_window_s())
    out: dict[str, GuestResourceShortfallView] = {}
    for row in GuestResourceShortfall.objects.filter(last_seen_at__gte=since).order_by(
        "-last_seen_at"
    ):
        out.setdefault(
            row.vm_id,
            GuestResourceShortfallView(
                node_id_hex=row.node_id_hex,
                flavor=row.flavor,
                reason=row.reason,
                want_vcpus=row.want_vcpus,
                want_memory_mb=row.want_memory_mb,
                vcpus_online=row.vcpus_online,
                mem_firmware_kib=row.mem_firmware_kib,
                mem_total_kib=row.mem_total_kib,
                mem_unaccepted_kib=row.mem_unaccepted_kib,
                samples=row.samples,
                first_seen_at=row.first_seen_at,
                last_seen_at=row.last_seen_at,
            ),
        )
    return out
