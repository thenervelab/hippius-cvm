"""In-guest liveness — "is there positive evidence from INSIDE the VM?"

## The defect this closes

Before this module the control plane's only notion of a tenant VM being
healthy was `orchestration.effects.poll_domain_running` — which asks the
miner whether a **libvirt domain** is Live. That is a statement about a
QEMU process, not about the guest inside it.

Proved live in production (2026-08-12): a golden VM whose §22 measurement
had been evicted from the allowlist rebooted, its KEK release was refused
(403), it never unlocked its LUKS overlay and never left the initramfs.
The libvirt domain stayed `running` the whole time, so vali reported
`state=active boot_phase=running` — a silent GREEN for a VM that was
serving nothing. The allowlist eviction was only the TRIGGER (fixed in
#933); ANY initramfs hang — refused release, corrupt overlay, unreachable
KBS, boot-counter refusal — produces the same silent green.

`boot_phase` cannot close it either: it is MONOTONIC by construction
(`Vm.advance_boot_phase`), so once a VM has ever reached `running` it can
never go back, no matter how wedged the guest becomes.

## The signal — and why it is THIS one

A healthy guest emits things a wedged guest cannot. Two candidates
exist, and only one is universal across the live fleet:

  * `VmLiveAttestation` (the §322 SNP keepalive) is the strongest
    signal — a KBS-verified `SNP_GET_REPORT` can only come out of a
    running SEV-SNP guest. But it is carried ONLY by newly-baked images.
    Measured on the live fleet 2026-08-12:

        p1-liveness-1        live-attestations = 66,     age  ~30 s
        tenant-vm-1          live-attestations =  0,     NEVER

    `tenant-vm-1` is a REAL tenant on a pre-keepalive image.
    Gating health on keepalive freshness alone would flag it broken —
    a false positive far worse than the bug, because it would drive an
    automated relaunch of a perfectly healthy tenant.

  * The §23 `served_receipt` (`hippius-agent-tenant-telemetry`, signed
    in-guest, pushed over the guest→host vsock relay) predates the
    keepalive image. Measured on the same fleet, the same minute:

        p1-liveness-1        served-receipts =    460,   age 14 s
        tenant-vm-1          served-receipts = 30 690,   age 47 s

    Both live tenant VMs emit it, on a ~60 s cadence. It IS universal
    across the fleet as it stands today.

So the signal is **the freshest of the two**, recorded as a durable
per-VM watermark (`Vm.guest_signal_at` / `guest_signal_kind`). Taking
the max means a future keepalive-only image is covered without a code
change, and a pre-keepalive image is covered today.

Recording a WATERMARK rather than querying `TelemetryEnvelope` at read
time is deliberate:

  * `TelemetryEnvelope` rows are garbage-collected after
    `VALI_TELEMETRY_GC_AGE_DAYS`, so a query-at-read-time would turn a
    long-idle VM's history into "never emitted" — the watermark is
    durable;
  * the read path (`GET /v1/vm`, the admin list) stays a single indexed
    column read, no per-row aggregate over a 500k-row table.

## Three verdicts — and why `unknown` is not `dead`

    alive    a signal landed within `VALI_GUEST_LIVENESS_STALE_S`.
    wedged   this VM HAS emitted before, but nothing inside the bound.
    unknown  this VM has NEVER emitted an in-guest signal.

`unknown` is the load-bearing one. A VM whose image carries no telemetry
agent at all, a VM that has not finished its first boot, a VM whose
watermark predates this feature — all of them are `unknown`, and
`unknown` MUST NEVER drive an automated action. Absence of evidence is
not evidence of death. Every consumer here fails SAFE: no signal, or a
failed query, means DO NOTHING.

## Trust boundary — this is observability, NOT a security gate

A served receipt is signed by the guest telemetry key, which is
HKDF-derived from the §7 lifecycle key and therefore readable by root
inside the CVM (see `apps.telemetry.vm_liveness` for the full argument).
Root in the guest — or a miner that has launched a VM on its own node —
can both FORGE the signal and SUPPRESS it. That is fine here and it is
why this module gates nothing security-relevant:

  * forging it only hides a wedge from the operator, and a miner can
    already withhold `domain-state` to the same effect;
  * suppressing it is why the automated action built on it
    (`VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST`) is DEFAULT-OFF, capped,
    backed off, and refuses to act when a whole miner's fleet goes
    quiet at once (that pattern is a broken vsock relay, not N wedged
    guests).

Nothing in this module touches release, attestation, or any KBS gate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

log = logging.getLogger("apps.lifecycle.guest_liveness")

# The in-guest signal kinds, most→least preferred for the `kind` readout.
# Both are recorded into the SAME watermark; the freshest one wins.
SIGNAL_SERVED_RECEIPT = "served_receipt"
SIGNAL_LIVE_ATTESTATION = "live_attestation"

KNOWN_SIGNAL_KINDS: frozenset[str] = frozenset(
    {SIGNAL_SERVED_RECEIPT, SIGNAL_LIVE_ATTESTATION}
)

# Verdicts. Mirrored as `VmGuestLiveness` choices on the model so the
# wire/admin/API rendering shares one vocabulary.
ALIVE = "alive"
WEDGED = "wedged"
UNKNOWN = "unknown"


def staleness_bound_s() -> int:
    """How old the newest in-guest signal may be and still read `alive`.

    Default 600 s — TEN missed beats of the ~60 s served-receipt cadence
    measured on the live fleet. Sized generously on purpose: the cost of
    calling a healthy VM `wedged` (a spurious operator page, and — if the
    automated action is armed — a relaunch that disrupts a tenant) is far
    higher than the cost of noticing a genuine wedge ten minutes late.
    """
    return max(1, int(getattr(settings, "VALI_GUEST_LIVENESS_STALE_S", 600)))


@dataclass(frozen=True)
class Verdict:
    """The in-guest liveness readout for one VM.

    - `state`     `alive` | `wedged` | `unknown`.
    - `signal_at` the watermark itself (`None` when never emitted).
    - `age_s`     seconds since `signal_at` (`None` when never emitted),
                  floored at 0 so a slightly future-dated signal (clock
                  skew between vali and the ingest) never reads negative.
    - `kind`      which signal set the watermark (`""` when never).
    """

    state: str
    signal_at: datetime | None
    age_s: int | None
    kind: str

    @property
    def is_alive(self) -> bool:
        return self.state == ALIVE

    @property
    def is_wedged(self) -> bool:
        return self.state == WEDGED


def classify(
    signal_at: datetime | None,
    *,
    now: datetime | None = None,
    bound_s: int | None = None,
    kind: str = "",
) -> Verdict:
    """Classify a watermark. Pure — no DB access, no settings beyond the
    (injectable) staleness bound. The single place the three-way verdict
    is decided.

    A `None` watermark is `unknown`, NEVER `wedged`: a VM that has never
    emitted an in-guest signal is a VM we have no opinion about.
    """
    if signal_at is None:
        return Verdict(state=UNKNOWN, signal_at=None, age_s=None, kind="")
    now = now or timezone.now()
    bound = staleness_bound_s() if bound_s is None else max(1, int(bound_s))
    age = int((now - signal_at).total_seconds())
    if age < 0:
        age = 0
    return Verdict(
        state=ALIVE if age <= bound else WEDGED,
        signal_at=signal_at,
        age_s=age,
        kind=kind,
    )


def verdict_for(vm, *, now: datetime | None = None) -> Verdict:
    """`classify` the watermark carried on a `Vm` row."""
    return classify(
        vm.guest_signal_at, now=now, kind=vm.guest_signal_kind
    )


def record_signal(vm_id: str, kind: str, *, at: datetime | None = None) -> bool:
    """Advance a VM's in-guest signal watermark to `at`. Returns True iff
    a row was updated.

    MONOTONIC — the conditional `UPDATE … WHERE guest_signal_at IS NULL OR
    guest_signal_at < at` means a late/replayed/out-of-order signal can
    never pull the watermark BACKWARDS and manufacture a wedge.

    Writes ONLY `guest_signal_at` / `guest_signal_kind`: it never touches
    lifecycle `state`, and never bumps the optimistic-concurrency
    `version` (a liveness beat must not invalidate an in-flight §24/§25
    CAS held by the orchestrator).

    NEVER raises — this rides the synchronous telemetry-ingest path, and
    a display-only watermark must not be able to fail an ingest.
    """
    if kind not in KNOWN_SIGNAL_KINDS:
        log.warning("guest-liveness: refusing unknown signal kind %r", kind)
        return False
    at = at or timezone.now()
    try:
        from .models import Vm

        return bool(
            Vm.objects.filter(vm_id=vm_id)
            .filter(Q(guest_signal_at__isnull=True) | Q(guest_signal_at__lt=at))
            .update(guest_signal_at=at, guest_signal_kind=kind)
        )
    except Exception:  # noqa: BLE001 — display-only, never break ingest.
        log.warning(
            "guest-liveness: watermark update failed for vm_id=%s", vm_id,
            exc_info=True,
        )
        return False
