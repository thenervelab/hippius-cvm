"""Blackbox host-attestor RELEASE + coverage-reconcile service (PR-9).

Three operator/ops surfaces, all INERT with respect to reward +
dispatchability (nothing here gates emission — that arms in PR-11):

- `admit_release` — the cosign-verified admin release path. Verifies the
  CI-signed blackbox UKI, APPEND-ONLY pins its measurement into the §22
  allowlist under the `host_attestor` CLASS (never the tenant class, and
  NEVER auto-pinned from a miner report — blackbox host-attestor
  must-have #1), and records a `HostAttestorRelease` row marked active.
- `desired_releases` — the {current, previous} grace-window a miner polls
  to learn which blackbox UKI to boot (a miner mid-rolling-update on the
  previous measurement is still valid).
- `reconcile_coverage` — the warn-only coverage report: for each
  on-chain-Active miner, is there an `attested` (NEVER `pending` — the
  HARD CONSTRAINT) host-attestor seen within the liveness window on a
  desired measurement. Emits advisory logs/metrics; gates NOTHING.

Supply-chain (must-have #4): the admit path is a fleet-wide trust root. It
inherits the open GA-blockers (M-cosign-admission, M-allowlist-M-of-N,
online allowlist-root C1). Since M-of-N is NOT closed, a single-signer
release can PIN but the downstream emission stays INERT (PR-11 default-
off) — this module deliberately never flips a gate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.orchestration.services import allowlist_pin
from apps.orchestration.services.allowlist_pin import ALLOWLIST_CLASS_HOST_ATTESTOR

from . import cosign_verify
from .models import HostAttestor, HostAttestorRelease, HostAttestorStatus

log = logging.getLogger("apps.telemetry.release")

# The synthetic `vm_id` a host-attestor release records in the shared
# §22 `MeasurementLedger` audit trail — it is NOT a VM. Keeps
# `allowlist_pin._installed_epoch_floor` (which seeds from the ledger's max
# epoch) accurate across host-attestor + tenant pins so neither burns the
# HWM-drift retry budget.
_RELEASE_LEDGER_VM_ID = "host-attestor-release"

# How many releases stay `is_active` — the {current, previous} rolling-
# update grace window. A miner still booting the previous measurement mid-
# update is valid; anything older is deactivated.
_GRACE_ACTIVE_COUNT = 2


class ReleaseError(Exception):
    """A host-attestor release was refused. Carries the HTTP status +
    stable `category` the view returns."""

    def __init__(self, *, message: str, category: str, http_status: int) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.http_status = http_status


# ─── admit ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReleaseResult:
    release: HostAttestorRelease
    created: bool
    new_epoch: int


def admit_release(
    *,
    measurement_hex: str,
    version: str,
    artifact: bytes,
    signature_b64: str,
    certificate_pem: str,
    rekor_log_index: int | None = None,
) -> ReleaseResult:
    """Cosign-verify a blackbox UKI release, class-pin its measurement,
    and record it active. Raises `ReleaseError` on any refusal.

    Order (fail-closed throughout):
      1. cosign verify-blob with the pinned CI identity + issuer + Rekor.
      2. APPEND-ONLY §22 pin under `AllowlistClass::HostAttestor`.
      3. Upsert the `HostAttestorRelease` active + trim the grace window.
    """
    measurement_hex = (measurement_hex or "").strip().lower()
    if len(measurement_hex) != 96 or any(
        c not in "0123456789abcdef" for c in measurement_hex
    ):
        raise ReleaseError(
            message="measurement_hex must be 96 lower-case hex chars (48 bytes)",
            category="wire",
            http_status=400,
        )

    # 1. Supply-chain gate — keyless cosign verification, identity-pinned.
    try:
        pins = cosign_verify.verify_blob(
            artifact=artifact,
            signature_b64=signature_b64,
            certificate_pem=certificate_pem,
        )
    except cosign_verify.CosignVerifyFailed as exc:
        raise ReleaseError(
            message=f"cosign verification failed ({exc.category})",
            category=exc.category,
            http_status=400,
        ) from exc
    except cosign_verify.CosignUnavailable as exc:
        raise ReleaseError(
            message="cosign verifier is unavailable",
            category="internal",
            http_status=503,
        ) from exc

    # 2. APPEND-ONLY §22 pin — HOST-ATTESTOR CLASS. This is the ONLY path
    #    a host-attestor measurement is admitted: operator/CI-pinned via a
    #    cosign-verified release, NEVER auto-pinned from a miner SNP report.
    #    The class tag guarantees it can never alias a tenant measurement.
    from apps.orchestration.effects import EffectError, EffectUnavailable

    try:
        pin_result = allowlist_pin.pin_measurement(
            measurement_hex=measurement_hex,
            measurement_class=ALLOWLIST_CLASS_HOST_ATTESTOR,
        )
    except EffectUnavailable as exc:
        raise ReleaseError(
            message=f"allowlist pin unavailable: {exc}",
            category="internal",
            http_status=503,
        ) from exc
    except EffectError as exc:
        raise ReleaseError(
            message=f"allowlist pin failed: {exc}",
            category="allowlist-pin-failure",
            http_status=502,
        ) from exc

    # 2b. Mirror the pin into the §22 audit ledger (best-effort — the KBS
    #     pin above is authoritative). Keeps the epoch-floor accurate.
    _record_ledger(measurement_hex, pin_result)

    # 3. Record the release active + trim the grace window.
    with transaction.atomic():
        release, created = HostAttestorRelease.objects.select_for_update().get_or_create(
            measurement=measurement_hex,
            defaults={
                "version": version,
                "cosign_identity": pins.identity,
                "cosign_issuer": pins.issuer,
                "cosign_rekor_log_index": rekor_log_index,
                "is_active": True,
            },
        )
        if not created:
            # Re-admitting an existing measurement (e.g. re-activating a
            # rolled-back release): refresh provenance + re-activate.
            release.version = version or release.version
            release.cosign_identity = pins.identity
            release.cosign_issuer = pins.issuer
            if rekor_log_index is not None:
                release.cosign_rekor_log_index = rekor_log_index
            release.is_active = True
            release.save()
        _trim_grace_window()

    log.info(
        "host-attestor release admitted: measurement=%s… version=%s epoch=%d "
        "identity=%s (created=%s)",
        measurement_hex[:16],
        version,
        pin_result.new_epoch,
        pins.identity,
        created,
    )
    return ReleaseResult(
        release=release, created=created, new_epoch=pin_result.new_epoch
    )


def _record_ledger(measurement_hex: str, pin_result: allowlist_pin.PinResult) -> None:
    """Best-effort audit-ledger mirror of the host-attestor pin. A ledger
    write failure must never fail an otherwise-good release (the KBS pin is
    the authoritative record)."""
    try:
        from apps.orchestration.models import MeasurementLedger

        MeasurementLedger.objects.create(
            vm_id=_RELEASE_LEDGER_VM_ID,
            launch_digest_hex=measurement_hex,
            platform_id="",
            node_id="",
            allowlist_epoch=pin_result.new_epoch,
            allowlist_sha256=pin_result.new_cose_sha256_hex,
            # Records the HOST-ATTESTOR class so the §22 carry-forward can
            # veto any later attempt to re-pin this measurement as tenant.
            measurement_class=ALLOWLIST_CLASS_HOST_ATTESTOR,
        )
    except Exception as exc:  # noqa: BLE001 — audit is non-load-bearing.
        log.warning(
            "host-attestor release ledger write failed (non-fatal): %s", exc
        )


def _trim_grace_window() -> None:
    """Keep only the `_GRACE_ACTIVE_COUNT` most-recently-created releases
    `is_active` — the {current, previous} grace window. Older active rows
    are deactivated (a miner cannot pin a measurement more than one release
    behind)."""
    keep_ids = list(
        HostAttestorRelease.objects.filter(is_active=True)
        .order_by("-created_at")
        .values_list("id", flat=True)[:_GRACE_ACTIVE_COUNT]
    )
    HostAttestorRelease.objects.filter(is_active=True).exclude(
        id__in=keep_ids
    ).update(is_active=False)


# ─── desired ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DesiredReleases:
    """The grace-window a miner polls: `current` is the measurement to boot;
    `previous` (if any) is still accepted during a rolling update."""

    current: HostAttestorRelease | None
    previous: HostAttestorRelease | None


def desired_releases() -> DesiredReleases:
    """The {current, previous} active releases, newest first. `current` is
    the desired measurement; `previous` covers a miner mid-rolling-update.
    Both `None` before the operator has admitted any release."""
    active = list(
        HostAttestorRelease.objects.filter(is_active=True).order_by("-created_at")[
            :_GRACE_ACTIVE_COUNT
        ]
    )
    current = active[0] if active else None
    previous = active[1] if len(active) > 1 else None
    return DesiredReleases(current=current, previous=previous)


# ─── reconcile (WARN-ONLY) ───────────────────────────────────────────


def _liveness_window_seconds() -> int:
    """How recently an `attested` host-attestor must have been seen to
    count as covered. Default 600 s (10 min — generous vs the ~60 s
    beacon cadence)."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_LIVENESS_WINDOW_S", 600))


@dataclass(frozen=True)
class MinerCoverage:
    node_id: str
    covered: bool
    stale_measurement: bool
    reason: str


@dataclass(frozen=True)
class CoverageReport:
    total_active_miners: int
    covered: int
    missing: int
    stale: int
    desired_measurements: tuple[str, ...]
    per_miner: tuple[MinerCoverage, ...]


def reconcile_coverage() -> CoverageReport:
    """Compute host-attestor COVERAGE across the on-chain-Active fleet.

    WARN-ONLY: reads `attested` HostAttestor rows ONLY (a `pending` row is
    NOT coverage — the HARD CONSTRAINT), never gates / dispatches /
    rewards. A miner is COVERED when it has an `attested` host-attestor
    row, last seen within the liveness window, on a DESIRED measurement
    ({current, previous}). A live `attested` row on an OLD (non-desired)
    measurement is STALE. Anything else is MISSING.

    Raises `chain.ChainReadUnavailable` if the on-chain fleet cannot be
    read (the caller — a warn-only CronJob — logs + exits non-fatally).
    """
    from apps.scheduler import chain

    snapshot = chain.read_miner_status()
    active_miners = [m for m in snapshot.miners if m.status == "active"]

    desired = desired_releases()
    desired_measurements = tuple(
        r.measurement for r in (desired.current, desired.previous) if r is not None
    )
    desired_set = set(desired_measurements)

    now = timezone.now()
    window = timedelta(seconds=_liveness_window_seconds())
    live_cutoff = now - window

    # Only `attested` rows count — NEVER `pending` (untrusted by
    # definition; if the KBS L0 key is unwired EVERY row is pending, which
    # honestly reports zero coverage — see the log below).
    attested_rows = {
        row.node_id: row
        for row in HostAttestor.objects.filter(
            status=HostAttestorStatus.ATTESTED.value
        )
    }

    per_miner: list[MinerCoverage] = []
    covered = missing = stale = 0
    for miner in active_miners:
        row = attested_rows.get(miner.node_id)
        if row is None:
            missing += 1
            per_miner.append(
                MinerCoverage(
                    node_id=miner.node_id,
                    covered=False,
                    stale_measurement=False,
                    reason="no attested host-attestor",
                )
            )
            continue
        live = row.last_seen_at is not None and row.last_seen_at >= live_cutoff
        on_desired = row.measurement in desired_set
        if live and on_desired:
            covered += 1
            per_miner.append(
                MinerCoverage(
                    node_id=miner.node_id,
                    covered=True,
                    stale_measurement=False,
                    reason="attested + live on desired measurement",
                )
            )
        elif live and not on_desired:
            stale += 1
            per_miner.append(
                MinerCoverage(
                    node_id=miner.node_id,
                    covered=False,
                    stale_measurement=True,
                    reason="attested + live but on a stale (non-desired) measurement",
                )
            )
        else:
            missing += 1
            per_miner.append(
                MinerCoverage(
                    node_id=miner.node_id,
                    covered=False,
                    stale_measurement=False,
                    reason="attested but not seen within the liveness window",
                )
            )

    return CoverageReport(
        total_active_miners=len(active_miners),
        covered=covered,
        missing=missing,
        stale=stale,
        desired_measurements=desired_measurements,
        per_miner=tuple(per_miner),
    )


# ─── SLA / liveness meter (PR-11) ────────────────────────────────────
#
# The dispatchability gate + reward MULTIPLIER (PR-11) both consume the
# same per-host liveness signal computed here. Two hard properties, shared
# by every consumer:
#
#   - ATTESTED-ONLY (the PR-8 HARD CONSTRAINT): only `attested` HostAttestor
#     rows are ever read. A `pending` row is attacker-influenceable while
#     `VALI_KBS_L0_VERIFYING_KEY` is unwired and is NEVER coverage / reward.
#   - FAIL-CLOSED: a node with no attested row, a row on a non-desired
#     (stale) measurement, or a row whose last beacon is outside the window
#     contributes nothing — it is ABSENT from the covered set and gets a
#     0.0 ratio, never a default pass.
#
# SLA ≠ CAPACITY (security must-have #5): a positive liveness ratio proves
# ONLY that the measured attestor answered beacons recently on the pinned
# host-attestor measurement. It does NOT prove the host has spare capacity,
# nor that any tenant VM is healthy — a paused sliver-VM would still pass
# liveness. THAT is exactly why liveness is only ever a MULTIPLIER on real
# tenant-usage reward (`scoring.apply_attestor_liveness_multiplier`), never a
# standalone earner: bare uptime with no tenant usage yields ratio × 0 = 0.


def _beacon_cadence_seconds() -> int:
    """The nominal beacon cadence — a row seen within one cadence of `now`
    gets full liveness credit (ratio 1.0)."""
    return int(getattr(settings, "VALI_HOST_ATTESTOR_BEACON_CADENCE_S", 60))


def liveness_ratio(
    last_seen_at: datetime | None,
    *,
    now: datetime,
    cadence_s: int,
    window_s: int,
) -> float:
    """The per-host liveness ratio ∈ [0.0, 1.0] from a row's last beacon.

    The only beacon-history signal vali persists is `last_seen_at` (a beacon
    refreshes it; there is no per-beacon time-series). The ratio is the
    fraction of the liveness window during which the attestor was
    demonstrably alive, derived from that recency:

      - last seen within one beacon cadence     → 1.0 (beaconing normally);
      - last seen `window_s` past that cadence   → 0.0 (dead);
      - in between → linear decay over the window.

    `None` (never beaconed) → 0.0 (fail-closed).
    """
    if last_seen_at is None:
        return 0.0
    if window_s <= 0:
        return 0.0
    staleness = (now - last_seen_at).total_seconds()
    if staleness <= cadence_s:
        return 1.0
    alive = window_s - (staleness - cadence_s)
    if alive <= 0.0:
        return 0.0
    return min(1.0, alive / window_s)


def _desired_measurement_set() -> set[str]:
    """The {current, previous} desired release measurements. EMPTY before
    the operator has admitted any release — in which case NO host is on a
    desired measurement and every ratio is 0 (fail-closed: an armed reward
    gate requires a pinned release first)."""
    desired = desired_releases()
    return {
        r.measurement
        for r in (desired.current, desired.previous)
        if r is not None
    }


def attestor_liveness_ratios(*, now: datetime | None = None) -> dict[str, float]:
    """`{node_id (lower-case): liveness_ratio ∈ (0, 1]}` — the reward
    MULTIPLIER meter (PR-11).

    ATTESTED-only + on a DESIRED measurement + a positive (in-window) ratio.
    A node absent from the mapping has ratio 0 (fail-closed: no attested
    row / a pending row / a stale measurement / a dead beacon). Keyed
    lower-case so the caller's node_id lookup is case-insensitive.
    """
    now = now or timezone.now()
    desired_set = _desired_measurement_set()
    if not desired_set:
        return {}
    cadence = _beacon_cadence_seconds()
    window = _liveness_window_seconds()
    out: dict[str, float] = {}
    for row in HostAttestor.objects.filter(
        status=HostAttestorStatus.ATTESTED.value
    ):
        if row.measurement not in desired_set:
            continue
        ratio = liveness_ratio(
            row.last_seen_at, now=now, cadence_s=cadence, window_s=window
        )
        if ratio <= 0.0:
            continue
        key = row.node_id.lower()
        # A chip re-key could momentarily leave two attested rows for one
        # node — keep the most-live one.
        out[key] = max(out.get(key, 0.0), ratio)
    return out


def attestor_covered_node_ids(*, now: datetime | None = None) -> frozenset[str]:
    """The lower-case `node_id`s eligible under the DISPATCHABILITY gate
    (PR-11) — those with an `attested` host-attestor row, seen within the
    liveness window, on a desired measurement. Same attested-only +
    fail-closed contract as `reconcile_coverage`'s COVERED set, exposed as a
    membership set the scheduler ANDs into `dispatchable_node_ids`.
    """
    now = now or timezone.now()
    desired_set = _desired_measurement_set()
    if not desired_set:
        return frozenset()
    window = timedelta(seconds=_liveness_window_seconds())
    live_cutoff = now - window
    covered: set[str] = set()
    for row in HostAttestor.objects.filter(
        status=HostAttestorStatus.ATTESTED.value
    ):
        if row.measurement not in desired_set:
            continue
        if row.last_seen_at is not None and row.last_seen_at >= live_cutoff:
            covered.add(row.node_id.lower())
    return frozenset(covered)
