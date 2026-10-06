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
  previous measurement is still valid). Kept PER SEV-SNP GENERATION: the
  attestor launch measurement covers the VMSA, which carries the vCPU
  model's CPUID signature, so one UKI measures differently on Genoa /
  Turin / Milan and each generation rolls its own window.
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

from apps.miners.models import SnpGeneration
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

# How many releases stay `is_active` PER GENERATION — the {current,
# previous} rolling-update grace window. A miner still booting the previous
# measurement mid-update is valid; anything older is deactivated.
_GRACE_ACTIVE_COUNT = 2

# The generation group of an untagged (pre-generation) release row. Those
# rows form ONE group of their own, so a table with no tagged row behaves
# exactly as the old single fleet-wide window.
LEGACY_GENERATION = ""


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
    generation: str,
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
      3. Upsert the `HostAttestorRelease` active + trim the grace window
         of ITS generation only.

    `generation` (`SnpGeneration`: genoa | turin | milan) is REQUIRED: it
    names the CPU generation whose vCPU signature produced `measurement_hex`,
    and selects the grace window the release joins. A measurement belongs to
    exactly one generation — re-admitting it under a different one is
    refused (409); re-admitting an untagged legacy row tags it.
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
    generation = (generation or "").strip().lower()
    if generation not in SnpGeneration.values:
        raise ReleaseError(
            message=(
                f"generation must be one of {sorted(SnpGeneration.values)} "
                "(the SEV-SNP CPU generation the measurement is for)"
            ),
            category="wire",
            http_status=400,
        )
    _refuse_generation_conflict(measurement_hex, generation)

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
    #    Held under the pin lock through step 3: the carry-forward carries
    #    host-attestor measurements from the release ROW, so a concurrent
    #    tenant pin reading before it is committed would evict this one.
    #    (So this outer hold spans every 409 retry of this one pin — an
    #    operator release is rare; tenant pins hold the lock per attempt.)
    from apps.orchestration.effects import EffectError, EffectUnavailable

    with allowlist_pin.pin_lock():
        # Re-checked under the lock: the check above ran outside it, and a
        # refusal in step 3 — AFTER the KBS install — would leave the
        # measurement installed with no release row to carry it.
        _refuse_generation_conflict(measurement_hex, generation)
        try:
            pin_result = allowlist_pin.pin_measurement(
                measurement_hex=measurement_hex,
                measurement_class=ALLOWLIST_CLASS_HOST_ATTESTOR,
                # The audit-ledger mirror keeps the epoch floor accurate
                # and records the class the carry-forward vetoes on.
                ledger=allowlist_pin.PinLedger(vm_id=_RELEASE_LEDGER_VM_ID),
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

        # 3. Record the release active + trim the grace window. A failure
        #    here comes AFTER the KBS install: the lock's transaction must
        #    still commit the pin's ledger row (the epoch floor and the
        #    class veto the carry-forward reads), so it is re-raised only
        #    once the lock is released. Step 3's own writes roll back with
        #    its savepoint.
        step3_error: Exception | None = None
        try:
            with transaction.atomic():
                release, created = HostAttestorRelease.objects.select_for_update().get_or_create(
                    measurement=measurement_hex,
                    defaults={
                        "version": version,
                        "cosign_identity": pins.identity,
                        "cosign_issuer": pins.issuer,
                        "cosign_rekor_log_index": rekor_log_index,
                        "is_active": True,
                        "generation": generation,
                    },
                )
                if not created:
                    _refuse_generation_conflict(measurement_hex, generation, row=release)
                    # Re-admitting an existing measurement (e.g. re-activating a
                    # rolled-back release): refresh provenance + re-activate.
                    release.version = version or release.version
                    release.cosign_identity = pins.identity
                    release.cosign_issuer = pins.issuer
                    if rekor_log_index is not None:
                        release.cosign_rekor_log_index = rekor_log_index
                    release.is_active = True
                    release.generation = generation
                    release.save()
                _trim_grace_window(generation)
        except Exception as exc:  # noqa: BLE001 — re-raised below, after the commit
            step3_error = exc
    if step3_error is not None:
        log.error(
            "host-attestor release: measurement=%s… is pinned at epoch %d but "
            "its release row was not recorded (%s) — the next pin will not "
            "carry it; re-admit the release",
            measurement_hex[:16],
            pin_result.new_epoch,
            step3_error,
        )
        raise step3_error

    log.info(
        "host-attestor release admitted: measurement=%s… generation=%s "
        "version=%s epoch=%d identity=%s (created=%s)",
        measurement_hex[:16],
        generation,
        version,
        pin_result.new_epoch,
        pins.identity,
        created,
    )
    return ReleaseResult(
        release=release, created=created, new_epoch=pin_result.new_epoch
    )


def _refuse_generation_conflict(
    measurement_hex: str, generation: str, *, row: HostAttestorRelease | None = None
) -> None:
    """Refuse re-admitting a measurement under a generation other than the
    one it is recorded for. A measurement is produced by ONE vCPU signature;
    re-labelling it would move it into another generation's window. An
    untagged (legacy) row may be tagged."""
    if row is None:
        row = HostAttestorRelease.objects.filter(measurement=measurement_hex).first()
    if row is None or row.generation in (LEGACY_GENERATION, generation):
        return
    raise ReleaseError(
        message=(
            f"measurement is already released for generation "
            f"{row.generation!r}, not {generation!r}"
        ),
        category="generation-conflict",
        http_status=409,
    )


def _trim_grace_window(generation: str) -> None:
    """Keep only the `_GRACE_ACTIVE_COUNT` most-recently-created releases
    OF `generation` `is_active` — that generation's {current, previous}
    grace window. Its older active rows are deactivated (a miner cannot pin
    a measurement more than one release behind). Other generations — and
    the legacy untagged group — are never touched: admitting a Milan
    release must not evict a Genoa host's measurement."""
    in_group = HostAttestorRelease.objects.filter(is_active=True, generation=generation)
    keep_ids = list(
        in_group.order_by("-created_at").values_list("id", flat=True)[:_GRACE_ACTIVE_COUNT]
    )
    in_group.exclude(id__in=keep_ids).update(is_active=False)


# ─── desired ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DesiredReleases:
    """The grace-window a miner polls: `current` is the measurement to boot;
    `previous` (if any) is still accepted during a rolling update."""

    current: HostAttestorRelease | None
    previous: HostAttestorRelease | None

    def measurements(self) -> tuple[str, ...]:
        """The window's measurements, newest first."""
        return tuple(r.measurement for r in (self.current, self.previous) if r is not None)


def _window(rows: list[HostAttestorRelease]) -> DesiredReleases:
    """{current, previous} from active rows already sorted newest first."""
    return DesiredReleases(
        current=rows[0] if rows else None,
        previous=rows[1] if len(rows) > 1 else None,
    )


def desired_releases(generation: str) -> DesiredReleases:
    """The {current, previous} active releases OF `generation`, newest
    first. `current` is the desired measurement; `previous` covers a miner
    mid-rolling-update. Both `None` before the operator has admitted any
    release for that generation. `LEGACY_GENERATION` ("") selects the
    untagged group."""
    return _window(
        list(
            HostAttestorRelease.objects.filter(
                is_active=True, generation=generation
            ).order_by("-created_at")[:_GRACE_ACTIVE_COUNT]
        )
    )


def desired_by_generation() -> dict[str, DesiredReleases]:
    """Every generation group's {current, previous} window, from ONE query.
    Only groups with at least one active release appear. The legacy
    untagged group is keyed `LEGACY_GENERATION`."""
    grouped: dict[str, list[HostAttestorRelease]] = {}
    for row in HostAttestorRelease.objects.filter(is_active=True).order_by("-created_at"):
        grouped.setdefault(row.generation, []).append(row)
    return {gen: _window(rows[:_GRACE_ACTIVE_COUNT]) for gen, rows in grouped.items()}


def node_generation(node_id: str) -> str:
    """The SEV-SNP generation of the registered miner behind `node_id`
    (its on-chain `chain_node_id`, or its `miner_id`), or
    `LEGACY_GENERATION` when it cannot be resolved.

    Same resolution as the launch-digest recompute
    (`launch_digest._vcpu_type_for_platform`): the operator-registered
    `MinerIdentity.snp_generation` wins; unset ⇒ inferred from the CHIP_ID
    length (8 bytes ⇒ turin, 64 ⇒ genoa). The on-chain node id (stored
    lower-case) is matched first, then the exact `miner_id`."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services.launch_digest import (
        _CHIP_ID_BYTES_TO_VCPU,
        SNP_GENERATION_VCPU,
    )

    fields = ("snp_generation", "platform_id")
    identity = (
        MinerIdentity.objects.filter(chain_node_id=node_id.lower()).only(*fields).first()
        or MinerIdentity.objects.filter(miner_id=node_id).only(*fields).first()
    )
    if identity is None:
        return LEGACY_GENERATION
    if identity.snp_generation:
        return identity.snp_generation
    try:
        n_bytes = len(bytes.fromhex(identity.platform_id.strip()))
    except ValueError:
        return LEGACY_GENERATION
    vcpu = _CHIP_ID_BYTES_TO_VCPU.get(n_bytes)
    for generation, (model, _bytes) in SNP_GENERATION_VCPU.items():
        if model == vcpu:
            return generation
    return LEGACY_GENERATION


def desired_releases_for_node(node_id: str) -> tuple[str, DesiredReleases]:
    """`(generation, window)` a miner should boot onto: its own
    generation's window. Falls back to the legacy untagged group when the
    node's generation is unresolved or has no active release yet — exactly
    the fleet-wide answer an all-untagged table gave before generations."""
    generation = node_generation(node_id)
    if generation != LEGACY_GENERATION:
        own = desired_releases(generation)
        if own.current is not None:
            return generation, own
    return LEGACY_GENERATION, desired_releases(LEGACY_GENERATION)


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

    desired_measurements = _desired_measurements()
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


def _desired_measurements() -> tuple[str, ...]:
    """Every generation's {current, previous} measurements, in a stable
    order (generation, then newest first)."""
    by_gen = desired_by_generation()
    return tuple(m for gen in sorted(by_gen) for m in by_gen[gen].measurements())


def _desired_measurement_set() -> set[str]:
    """The UNION of every generation's {current, previous} desired
    measurements (the legacy untagged group is one more group). EMPTY
    before the operator has admitted any release — in which case NO host is
    on a desired measurement and every ratio is 0 (fail-closed: an armed
    reward gate requires a pinned release first).

    Why a union, not a per-node lookup, is the right gate: every member is
    a cosign-verified, host-attestor-class-pinned release of the approved
    blackbox UKI, and `row.measurement` comes from the KBS-verified SNP
    report. Checking a row against the union is EXACTLY checking it against
    the window of the generation its measurement was admitted for (a
    measurement belongs to one generation, see `admit_release`), so
    "stale" keeps its per-generation meaning: a Genoa host on a Genoa
    release that fell out of the Genoa window is not in the union. What the
    union does NOT check is that the host's physical generation matches the
    release's label. It cannot be relied on to (the vCPU model in the VMSA
    is chosen by the host's VMM, so a Genoa host could in principle launch
    the UKI with a Milan vCPU signature and reproduce the Milan
    measurement), and it need not be: such a guest still runs the approved
    attestor code in a genuine SNP VM on the chip the AMD-signed report
    names — the property the gate exists for. A per-node lookup would add
    a failure mode for no security gain: the generation would have to be
    resolved from the registry, and a 64-byte CHIP_ID is Genoa OR Milan, so
    an unset/mis-set `MinerIdentity.snp_generation` would turn a healthy
    host `measurement-stale`.

    The legacy untagged group contributes at most its two newest active
    measurements, like any group — but since every new admission is tagged,
    nothing trims it any more: an untagged active row stays accepted until
    it is deactivated or re-admitted with a generation (which tags it). The
    0008 backfill tags every measurement live on 2026-09-25, so on the live
    table this group is expected to be empty."""
    return set(_desired_measurements())


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


# ─── dispatchability gate: per-node coverage + reason ───────────────
#
# The reason vocabulary a NOT-covered node carries. Each value names the
# single predicate that failed, in the order the gate applies them, so an
# operator readout can say WHY instead of just "not dispatchable". Defined
# ONCE in `apps.scheduler.reasons` (shared with the registry gates and the
# operator serializer); re-exported here.

from apps.scheduler.reasons import (  # noqa: E402,F401  — re-exported, deliberately late
    REASON_ATTESTOR_MISSING,
    REASON_ATTESTOR_PENDING,
    REASON_ATTESTOR_STALE,
    REASON_CERT_EXPIRED,
    REASON_MEASUREMENT_STALE,
    REASON_RELEASE_UNPINNED,
)


def _row_coverage_reason(
    row: HostAttestor, *, desired_set: set[str], live_cutoff: datetime
) -> str | None:
    """The ONE predicate a single `HostAttestor` row fails, or `None` when
    the row covers its node. This is the per-row truth `reconcile_coverage`
    and the dispatchability gate both rest on: attested-only, on a desired
    measurement, beaconed within the liveness window."""
    if row.status == HostAttestorStatus.EXPIRED.value:
        return REASON_CERT_EXPIRED
    if row.status != HostAttestorStatus.ATTESTED.value:
        return REASON_ATTESTOR_PENDING
    if row.measurement not in desired_set:
        return REASON_MEASUREMENT_STALE
    if row.last_seen_at is None or row.last_seen_at < live_cutoff:
        return REASON_ATTESTOR_STALE
    return None


# Precedence when a node has several non-covering rows (a chip re-key can
# leave two): report the row that got FURTHEST through the gate.
_REASON_RANK: dict[str, int] = {
    REASON_ATTESTOR_STALE: 0,
    REASON_MEASUREMENT_STALE: 1,
    REASON_CERT_EXPIRED: 2,
    REASON_ATTESTOR_PENDING: 3,
}


@dataclass(frozen=True)
class AttestorCoverageMap:
    """The host-attestor gate evaluated once for the whole fleet.

    `by_node` maps a lower-case `node_id` to `None` (covered) or to the
    reason it is not. A node with no row at all is ABSENT from the map and
    resolves to `attestor-missing`; when no release is pinned EVERY node
    resolves to `release-unpinned` regardless of its rows (fail-closed,
    exactly as `covered_node_ids` is empty in that case).
    """

    release_pinned: bool
    by_node: dict[str, str | None]

    def reason_for(self, node_id: str) -> str | None:
        """`None` iff `node_id` is covered; otherwise the gate reason."""
        if not self.release_pinned:
            return REASON_RELEASE_UNPINNED
        return self.by_node.get(node_id.lower(), REASON_ATTESTOR_MISSING)

    def covered_node_ids(self) -> frozenset[str]:
        if not self.release_pinned:
            return frozenset()
        return frozenset(nid for nid, reason in self.by_node.items() if reason is None)


def attestor_coverage_by_node(*, now: datetime | None = None) -> AttestorCoverageMap:
    """Evaluate the dispatchability gate (PR-11) for every node that has a
    `HostAttestor` row: covered iff SOME row is `attested`, on a desired
    measurement, and beaconed within the liveness window. Otherwise the
    node carries the reason of its most-advanced row (see `_REASON_RANK`).

    Single source of truth for `attestor_covered_node_ids` (the membership
    set the scheduler ANDs in) and for the per-node operator readout — the
    two cannot drift because both are projections of this map.
    """
    now = now or timezone.now()
    desired_set = _desired_measurement_set()
    live_cutoff = now - timedelta(seconds=_liveness_window_seconds())
    by_node: dict[str, str | None] = {}
    for row in HostAttestor.objects.all():
        key = row.node_id.lower()
        reason = _row_coverage_reason(row, desired_set=desired_set, live_cutoff=live_cutoff)
        if key in by_node:
            current = by_node[key]
            if current is None:
                continue  # already covered by another row
            if reason is None or _REASON_RANK[reason] < _REASON_RANK[current]:
                by_node[key] = reason
        else:
            by_node[key] = reason
    return AttestorCoverageMap(release_pinned=bool(desired_set), by_node=by_node)


def attestor_covered_node_ids(*, now: datetime | None = None) -> frozenset[str]:
    """The lower-case `node_id`s eligible under the DISPATCHABILITY gate
    (PR-11) — those with an `attested` host-attestor row, seen within the
    liveness window, on a desired measurement. Same attested-only +
    fail-closed contract as `reconcile_coverage`'s COVERED set, exposed as a
    membership set the scheduler ANDs into `dispatchable_node_ids`.

    A projection of `attestor_coverage_by_node` — see it for the predicate.
    """
    return attestor_coverage_by_node(now=now).covered_node_ids()
