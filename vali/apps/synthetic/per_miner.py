"""Per-miner synthetic probe — test EVERY miner, not the scheduler's pick.

The full tier (`apps.synthetic.e2e`) launches with an empty `platform_id`,
so the scheduler chooses the host, and in practice it chose the same one
for 28 of 31 runs in a week: the other miners were never tested by us at
all. This tier runs the SAME launch → release → kek_alive → boot →
netbird → §24 → crypto-erase probe, pinned to one miner per run
(`platform_id` = its registered chip, as a disk-probe launch pins it),
round-robin over the fleet. `vali_synthetic_monitor --tier per-miner`,
from its own CronJob, behind `VALI_SYNTHETIC_PER_MINER` (off by default).

## Which miner

The universe is the scheduler's own: `dispatchable_node_ids()` (active,
reachable, heart-beating, a real chip, attested while the attestor gate
is armed), externals included, narrowed to the canary allow-list
`VALI_SYNTHETIC_PER_MINER_MINERS` when set. A miner in it is probeable
now unless (first match is the reason, `blocked`):

- `busy`        a probe of ours is in flight on it (1 per miner, always);
- `cordoned`    operator cordon, pending approval, no storage (gate h);
- `gated`       the rest of `hard_gated_node_ids` (not on-chain active,
                epoch-stale, CVM-incapable, zombie) — placement would
                refuse it;
- `net-policy`  edge-mode region without a fresh net-policy ack (gate i);
- `booting`     a guest is booting on it right now, or its boot cap is
                reached (gate g) — the probe never competes with a tenant
                boot;
- `capacity`    admission would take fewer than
                `VALI_SYNTHETIC_PER_MINER_MIN_FREE_SLOTS` probe-flavor VMs
                there (default 2: the probe never takes the last slot).

Due order: never attempted first; then a host whose attested host
CHANGED since its last attempt — the fingerprint of its `attested`
host-attestor rows (chip, `boot_id`, measurement) differs from the one
recorded at that attempt: a reboot, a new image or new hardware. The
routine daily re-enrolment keeps the fingerprint and does not jump the
queue. Then every host whose last attempt is older than
`VALI_SYNTHETIC_PER_MINER_INTERVAL_S`, oldest first. The first
due, probeable miner is claimed, under a lock, while fewer than
`VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT` probes are in flight fleet-wide.

## Evidence

A probe launch is a normal `POST /v1/vm/launch`, so the miner's answer
feeds exactly what a tenant's does: the §23 CVM-start ledger
(`cvm_last_ok_at` / fail streak), the operator's launch-error ledger, and
for an `earned` miner the capacity `start-failed` event (incident
`vm=<probe vm_id>`), probation included — no strike before the host's first
successful start. Nothing here writes a penalty of its own.

What the probe adds is the record per miner (`MinerProbe`): the last
CONCLUSIVE probe, its failed stage, and the run of failures. A failure is
the miner's only when it is: a node-side launch refusal (the operator
readout's own rule), or a later stage of a VM placed there (`release`,
`boot`, `resources`, `netbird`). A launch vali refused or never placed
there, and the stages that are not the miner's alone (`launch`,
`kek_alive`, `decommission`, `crypto_erase` — the API POST, Vault, the
§24 path that already pages on a forced teardown), leave the record and
the streak alone. A pass counts only for a VM placed on the claimed
miner. Served as `last_probe` on `/v1/operator/nodes` and
as per-miner metrics.

Probe VMs never earn, bill or prove capacity, on two independent keys:
the launch's authenticated `purpose: probe` (`orchestration.launch_purpose`
— dropped from the usage weight, the snapshot weight, the priced bill and
the fill proof, and never sent to the backend) and their owner
`VALI_SYNTHETIC_TENANT_ID` (`scheduler.scoring._excluded_owners`). They are
attributable: that purpose, that tenant, and a `synmon-pm-` vm id.

## The `resources` stage (anti-fake)

With `VALI_GUEST_ATTEST_RESOURCES` on, the probe guest attests its vCPUs
online and RAM in every live attestation (PSP-signed, KBS-verified; the
miner relays the bytes and cannot change them), and the ingest judges
them against the flavor (`telemetry.guest_resources`). The stage fails
the probe on a `short` / `superseded` verdict. The ingest has already
written the `GuestResourceShortfall` row, so the probe's finding enters
the capacity `GUEST_RESOURCE_SHORT` path like any tenant's.

That path charges a host only once its shortfalls span
`VALI_CAPACITY_SHORTFALL_MIN_OWNERS` (≥ 2) distinct tenants, because root
inside a guest can forge its own figures. The probe counts as ONE tenant
there (its own `tenant_id`), deliberately, and no more:

- it IS independent — the guest is ours (golden image, our userdata, no
  third-party root), so unlike a tenant it cannot be forging, and no
  tenant can speak for it;
- it is ONE identity — however many probes see a shortfall, they are one
  tenant set, so the probe can never corroborate itself;
- so the probe alone never cuts a host (a vali-side threshold error, say a
  slack mis-sized for a new CPU generation, would hit every host it
  probes), but the probe plus ONE real tenant is enough — and a lone
  tenant's forged shortfall still needs the probe to have seen one too.

Known limit: a miner can tell a probe from a tenant (the synthetic tenant
id rides the measured cmdline as `family_id`, and the vm id is
`synmon-pm-*`), so it could serve probes honestly and short-change
tenants. A probe failure is therefore proof of misbehaviour; a probe pass
is not proof of honesty. Tenant-shaped probe identities (as the disk-tier
probe uses) would close that, at the cost of the attributability asked
for here.

## Budget and no-leak

Max one probe per miner and `VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT`
fleet-wide, the probe flavor (`small` by default), the whole run capped at
`VALI_SYNTHETIC_PER_MINER_BUDGET_S`, and the e2e's `finally` teardown on
every exit path. A miner stays busy (and its probe counts against the
budget) while its claim is younger than `VALI_SYNTHETIC_REAP_AGE_S` OR
the claimed VM / launch job is still alive — so a run killed outright
(SIGKILL / OOM), or a teardown that handed the VM off, holds the budget
until the light-tier reaper has destroyed the VM. The chart refuses to
enable this tier without the light tier, whose reaper that is.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from . import e2e
from .models import MinerProbe

log = logging.getLogger("apps.synthetic.per_miner")

#: Why a miner in the universe cannot be probed now (`MinerView.blocked`).
BLOCKED_BUSY = "busy"
BLOCKED_GATED = "gated"
BLOCKED_CORDONED = "cordoned"
BLOCKED_NET_POLICY = "net-policy"
BLOCKED_BOOTING = "booting"
BLOCKED_CAPACITY = "capacity"

#: Outcome of one probe for the miner's record.
VERDICT_OK = "ok"
VERDICT_FAILED = "failed"
#: The probe never reached the miner (no placement on it): no record.
VERDICT_INCONCLUSIVE = "inconclusive"

VM_ID_PREFIX = "synmon-pm-"

# ASCII "synpmin1"; distinct from every other advisory lock key in vali.
_BUDGET_LOCK_KEY = 0x73796E706D696E31
_PROCESS_LOCK = threading.Lock()
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def enabled() -> bool:
    return bool(getattr(settings, "VALI_SYNTHETIC_PER_MINER", False))


def max_concurrent() -> int:
    return max(0, int(settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT))


def _claim_stale_after() -> timedelta:
    return timedelta(seconds=int(settings.VALI_SYNTHETIC_REAP_AGE_S))


def live_probe_vms(vm_ids: set[str]) -> frozenset[str]:
    """Of `vm_ids`, those with a VM not yet destroyed or a launch job not
    yet terminal — a probe VM that still holds (or may still take) room."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.models import TERMINAL_LAUNCH_STATES, LaunchJob

    if not vm_ids:
        return frozenset()
    vms = Vm.objects.filter(vm_id__in=vm_ids).exclude(state=VmState.DESTROYED)
    jobs = LaunchJob.objects.filter(vm_id__in=vm_ids).exclude(
        state__in=list(TERMINAL_LAUNCH_STATES)
    )
    return frozenset(vms.values_list("vm_id", flat=True)) | frozenset(
        jobs.values_list("vm_id", flat=True)
    )


def busy_nodes(probes: dict[str, MinerProbe], now: datetime) -> frozenset[str]:
    """Miners holding a probe of ours: a run younger than the reap age
    (`in_flight_since` set until the run records), or any claim whose VM is
    still alive (a killed run, or a teardown that handed off — busy until
    the VM is gone, which the reaper guarantees)."""
    claimed = {nid: p for nid, p in probes.items() if p.in_flight_vm_id}
    live = live_probe_vms({p.in_flight_vm_id for p in claimed.values()})
    stale = _claim_stale_after()
    return frozenset(
        nid
        for nid, p in claimed.items()
        if p.in_flight_vm_id in live
        or (p.in_flight_since is not None and now - p.in_flight_since < stale)
    )


def _canary() -> frozenset[str]:
    return frozenset(
        str(m).strip().lower() for m in settings.VALI_SYNTHETIC_PER_MINER_MINERS if str(m).strip()
    )


# ─── the fleet as the scheduler sees it ──────────────────────────────


@dataclass(frozen=True)
class MinerView:
    node_id: str
    miner_id: str
    platform_id: str
    #: `""` when probeable now, else the first `BLOCKED_*` that applies.
    blocked: str
    last_attempt_at: datetime | None
    last_probe_at: datetime | None
    #: Fingerprint of the node's `attested` host-attestor rows now
    #: (`attestor_fingerprint`), and the one recorded at its last attempt
    #: (`""` = none recorded yet).
    attestor_fingerprint: str = ""
    seen_fingerprint: str = ""


def fleet_views(*, flavor: str, now: datetime, probes: dict[str, MinerProbe]) -> list[MinerView]:
    """One view per miner in the universe (dispatchable ∩ canary), with
    the scheduler's own gate reads — see the module docstring."""
    from django.db.models.functions import Lower

    from apps.miners.models import MinerIdentity
    from apps.scheduler import service

    universe = {n.lower() for n in service.dispatchable_node_ids()}
    canary = _canary()
    identities = {
        m.nid: m  # type: ignore[attr-defined]  # annotated column
        for m in MinerIdentity.objects.annotate(nid=Lower("chain_node_id")).filter(nid__in=universe)
    }
    if canary:
        identities = {
            nid: m for nid, m in identities.items() if nid in canary or m.miner_id.lower() in canary
        }
    if not identities:
        return []
    gated = {n.lower() for n in service.hard_gated_node_ids()}
    cordoned = service.cordoned_node_ids()
    net_unready = service.net_policy_unready_node_ids()
    free = {n.lower(): v.free_by_flavor.get(flavor, 0) for n, v in service.capacity_views().items()}
    booting = {n.lower(): c for n, c in service.booting_by_node(now=now).items()}
    boot_caps = {n.lower(): c for n, c in service.max_booting_overrides().items()}
    fleet_cap = service.max_booting_per_miner()
    attested = attestor_fingerprints(list(identities))
    min_free = int(settings.VALI_SYNTHETIC_PER_MINER_MIN_FREE_SLOTS)
    busy = busy_nodes(probes, now)

    def blocked(nid: str) -> str:
        if nid in busy:
            return BLOCKED_BUSY
        if nid in cordoned:
            return BLOCKED_CORDONED
        if nid in gated:
            return BLOCKED_GATED
        if nid in net_unready:
            return BLOCKED_NET_POLICY
        n_booting = booting.get(nid, 0)
        cap = boot_caps.get(nid, fleet_cap)
        if n_booting > 0 or ((nid in boot_caps or cap > 0) and n_booting >= cap):
            return BLOCKED_BOOTING
        if free.get(nid, 0) < min_free:
            return BLOCKED_CAPACITY
        return ""

    views: list[MinerView] = []
    for nid in sorted(identities):
        row = probes.get(nid)
        views.append(
            MinerView(
                node_id=nid,
                miner_id=identities[nid].miner_id,
                platform_id=identities[nid].platform_id,
                blocked=blocked(nid),
                last_attempt_at=row.last_attempt_at if row else None,
                last_probe_at=row.last_probe_at if row else None,
                attestor_fingerprint=attested.get(nid, ""),
                seen_fingerprint=row.attestor_fingerprint if row else "",
            )
        )
    return views


def attestor_fingerprints(node_ids: list[str]) -> dict[str, str]:
    """`{node_id: fingerprint}` of each node's `attested` host-attestor
    rows: a digest of their (chip, `boot_id`, measurement), so it changes
    on a reboot (new `boot_id`), a new host image (measurement) or new
    hardware (chip) — and NOT on the routine re-enrolment, which only
    renews the certificate. A node without one is absent."""
    from django.db.models.functions import Lower

    from apps.telemetry.models import HostAttestor, HostAttestorStatus

    parts: dict[str, list[str]] = {}
    for nid, chip, boot, meas in (
        HostAttestor.objects.filter(status=HostAttestorStatus.ATTESTED)
        .annotate(nid=Lower("node_id"))
        .filter(nid__in=node_ids)
        .values_list("nid", "chip_id", "boot_id", "measurement")
    ):
        parts.setdefault(nid, []).append(f"{chip.lower()}|{boot}|{meas.lower()}")
    return {
        nid: hashlib.sha256("\n".join(sorted(rows)).encode()).hexdigest()[:32]
        for nid, rows in parts.items()
    }


def due_order(views: list[MinerView], *, now: datetime) -> list[MinerView]:
    """The due miners, most urgent first (blocked ones included — the
    caller skips them and counts why)."""
    interval = timedelta(seconds=int(settings.VALI_SYNTHETIC_PER_MINER_INTERVAL_S))

    def rank(v: MinerView) -> int | None:
        if v.last_attempt_at is None:
            return 0
        if (
            v.seen_fingerprint
            and v.attestor_fingerprint
            and v.attestor_fingerprint != v.seen_fingerprint
        ):
            # Both sides known and different: the attested host changed.
            # (No attestor now, or none recorded yet, is not a change.)
            return 1
        if now - v.last_attempt_at >= interval:
            return 2
        return None

    ranked = [(r, v) for v in views if (r := rank(v)) is not None]
    ranked.sort(key=lambda rv: (rv[0], rv[1].last_attempt_at or _EPOCH, rv[1].node_id))
    return [v for _, v in ranked]


# ─── claim / record ──────────────────────────────────────────────────


@contextmanager
def _budget_lock() -> Iterator[None]:
    """Serialise claims across concurrent runs (a transaction-scoped
    Postgres advisory lock; a process lock on SQLite, i.e. tests)."""
    if connection.vendor != "postgresql":
        with _PROCESS_LOCK, transaction.atomic():
            yield
        return
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_BUDGET_LOCK_KEY])
        yield


def new_vm_id(node_id: str, now: datetime) -> str:
    """`synmon-pm-<node 12>-<unix>`: attributable, unique (one probe per
    miner at a time), within `[a-z0-9-]{1,64}`."""
    return f"{VM_ID_PREFIX}{node_id[:12].lower()}-{int(now.timestamp())}"


@dataclass
class Claim:
    view: MinerView
    vm_id: str


@dataclass
class TickReport:
    enabled: bool = False
    error: str = ""
    universe: int = 0
    in_flight: int = 0
    due: int = 0
    skipped: Counter = field(default_factory=Counter)
    claim: Claim | None = None
    outcome: e2e.E2EOutcome | None = None
    verdict: str = ""


def claim_next(*, flavor: str, now: datetime, report: TickReport) -> Claim | None:
    """Claim the most urgent due, probeable miner within the budget, or
    `None`. The claim (in-flight vm id + attempt time) commits before the
    launch, so a concurrent run sees it."""
    with _budget_lock():
        probes = {p.miner_node_id: p for p in MinerProbe.objects.select_for_update()}
        report.in_flight = len(busy_nodes(probes, now))
        views = fleet_views(flavor=flavor, now=now, probes=probes)
        report.universe = len(views)
        due = due_order(views, now=now)
        report.due = len(due)
        if report.in_flight >= max_concurrent():
            report.skipped["concurrency"] += len(due)
            return None
        for v in due:
            if v.blocked:
                report.skipped[v.blocked] += 1
                continue
            vm_id = new_vm_id(v.node_id, now)
            MinerProbe.objects.update_or_create(
                miner_node_id=v.node_id,
                defaults={
                    "in_flight_vm_id": vm_id,
                    "in_flight_since": now,
                    "last_attempt_at": now,
                    # What "the host changed" is judged against next time.
                    "attestor_fingerprint": v.attestor_fingerprint,
                },
            )
            return Claim(view=v, vm_id=vm_id)
    return None


#: Stages whose failure is not (only) the miner's whatever host the VM is
#: on: the launch POST, the positive-control read of the KEK in Vault, the
#: §24 decommission (vali, the KBS and the miner — a failure there already
#: pages through the forced-teardown alert) and the crypto-erase verify
#: (Vault again). Never charged to the miner.
VALI_SIDE_STAGES = frozenset({"launch", "kek_alive", "decommission", "crypto_erase"})


def reached_miner(vm_id: str, node_id: str) -> bool:
    """A placement of the probe VM on that miner exists: the launch got as
    far as choosing it (pending, bound, or failed there)."""
    from apps.scheduler.models import Placement

    return Placement.objects.filter(vm__vm_id=vm_id, miner_node_id__iexact=node_id).exists()


def miner_refused_launch(vm_id: str, node_id: str) -> bool:
    """The launch ended on that miner with an outcome in which the NODE
    failed (refused, unreachable, lost the VM) — the operator readout's own
    rule (`failure_source = launch`, reason in `LAUNCH_REFUSAL_OUTCOMES`).
    A launch that died on vali's side (Vault, ticket mint, KBS admin) is
    not the miner's."""
    from apps.scheduler.models import Placement, PlacementFailureSource
    from apps.scheduler.reasons import LAUNCH_REFUSAL_OUTCOMES

    return Placement.objects.filter(
        vm__vm_id=vm_id,
        miner_node_id__iexact=node_id,
        failure_source=PlacementFailureSource.LAUNCH,
        reason__in=list(LAUNCH_REFUSAL_OUTCOMES),
    ).exists()


def _failed_stage(outcome: e2e.E2EOutcome) -> e2e.StageResult | None:
    return next((s for s in outcome.stages if not s.ok), None)


def verdict_of(claim: Claim, outcome: e2e.E2EOutcome | None) -> str:
    """`ok` on a pass of a VM placed on the claimed miner. `failed` only
    when the failure is the miner's: a node-side launch refusal at
    `launch_complete`, or a later stage of a VM placed there (`release`,
    `boot`, `resources`, `netbird`). Anything else is `inconclusive`."""
    if outcome is None:
        return VERDICT_INCONCLUSIVE
    nid = claim.view.node_id
    if outcome.success:
        if reached_miner(claim.vm_id, nid):
            return VERDICT_OK
        # The pin should make this impossible: never credit a miner for a
        # VM that ran somewhere else.
        log.error("per-miner probe %s passed but was not placed on %s", claim.vm_id, nid[:12])
        return VERDICT_INCONCLUSIVE
    failed = _failed_stage(outcome)
    if failed is None or failed.name in VALI_SIDE_STAGES:
        return VERDICT_INCONCLUSIVE
    if failed.name == "launch_complete":
        charged = miner_refused_launch(claim.vm_id, nid)
    else:
        charged = reached_miner(claim.vm_id, nid)
    return VERDICT_FAILED if charged else VERDICT_INCONCLUSIVE


def record(claim: Claim, outcome: e2e.E2EOutcome | None, *, now: datetime) -> str:
    """Release the claim (once its VM is gone) and, for a conclusive
    probe, write its result. Returns the verdict (`VERDICT_*`); a claim
    another run has since taken over writes nothing."""
    nid = claim.view.node_id
    verdict = verdict_of(claim, outcome)
    with transaction.atomic():
        row = MinerProbe.objects.select_for_update().get(miner_node_id=nid)
        if row.in_flight_vm_id != claim.vm_id:
            log.warning(
                "per-miner probe %s: claim on %s was taken over by %r — result not recorded",
                claim.vm_id,
                nid[:12],
                row.in_flight_vm_id,
            )
            return VERDICT_INCONCLUSIVE
        # The run is over either way (`in_flight_since` cleared). Its VM
        # id stays claimed only while the VM is alive — a teardown that
        # handed it off, or could not finish — so the miner stays busy
        # until it is destroyed, and not a moment longer (`busy_nodes`).
        row.in_flight_since = None
        if claim.vm_id in live_probe_vms({claim.vm_id}):
            log.warning("per-miner probe %s: VM still alive after the run", claim.vm_id)
        else:
            row.in_flight_vm_id = ""
        if verdict != VERDICT_INCONCLUSIVE:
            assert outcome is not None
            failed = _failed_stage(outcome)
            row.last_probe_at = now
            row.last_ok = verdict == VERDICT_OK
            row.last_stage = failed.name if failed else ""
            row.last_vm_id = claim.vm_id
            row.last_detail = (failed.detail if failed else "")[:512]
            if verdict == VERDICT_OK:
                row.last_ok_at = now
                row.fail_streak = 0
            else:
                row.fail_streak += 1
        row.save()
    return verdict


# ─── one run ─────────────────────────────────────────────────────────


def tick(
    *,
    api_factory: Callable[[], e2e.ApiClient],
    now: Callable[[], datetime] = timezone.now,
) -> TickReport:
    """One per-miner run: claim the next miner, probe it, record. A
    mis-configuration fails loud BEFORE any claim, so it never lands on a
    miner's record."""
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor
    from apps.telemetry import guest_resources

    report = TickReport(enabled=enabled())
    if not report.enabled:
        return report
    distro = str(settings.VALI_SYNTHETIC_PER_MINER_DISTRO)
    flavor = str(settings.VALI_SYNTHETIC_PER_MINER_FLAVOR)
    try:
        resolve_flavor(flavor)
        e2e._golden_bake_id(distro)
        api = api_factory()
    except (UnknownFlavor, e2e.ConfigError) as exc:
        report.error = str(exc)
        return report

    claim = claim_next(flavor=flavor, now=now(), report=report)
    if claim is None:
        return report
    report.claim = claim
    log.info(
        "per-miner probe: miner=%s node=%s vm=%s",
        claim.view.miner_id,
        claim.view.node_id[:12],
        claim.vm_id,
    )
    outcome: e2e.E2EOutcome | None = None
    try:
        outcome = e2e.run_e2e(
            api=api,
            distro=distro,
            budget_s=float(settings.VALI_SYNTHETIC_PER_MINER_BUDGET_S),
            target=e2e.Target(
                vm_id=claim.vm_id,
                platform_id=claim.view.platform_id,
                flavor=flavor,
                check_resources=guest_resources.attest_on_launch(),
            ),
        )
    finally:
        report.outcome = outcome
        report.verdict = record(claim, outcome, now=now())
    return report


# ─── fleet readout ───────────────────────────────────────────────────


@dataclass(frozen=True)
class FleetRow:
    view: MinerView
    fail_streak: int
    last_ok: bool | None


def fleet_readout(*, now: datetime) -> list[FleetRow]:
    """Every miner in the universe with its probe record — what the fleet
    metrics publish (and what the staleness alert judges)."""
    probes = {p.miner_node_id: p for p in MinerProbe.objects.all()}
    flavor = str(settings.VALI_SYNTHETIC_PER_MINER_FLAVOR)
    out: list[FleetRow] = []
    for v in fleet_views(flavor=flavor, now=now, probes=probes):
        row = probes.get(v.node_id)
        out.append(
            FleetRow(
                view=v,
                fail_streak=row.fail_streak if row else 0,
                last_ok=row.last_ok if row else None,
            )
        )
    return out


def operator_readout(node_ids: list[str]) -> dict[str, dict[str, object]]:
    """`{node_id: {at, ok, stage, vm_id}}` — the last conclusive probe of
    each node that has one (`/v1/operator/nodes`'s `last_probe`). `stage`
    is the stage that failed, `None` on a pass. The internal detail stays
    out."""
    rows = MinerProbe.objects.filter(
        miner_node_id__in=[n.lower() for n in node_ids], last_probe_at__isnull=False
    )
    return {
        r.miner_node_id: {
            "at": r.last_probe_at.isoformat() if r.last_probe_at else None,
            "ok": bool(r.last_ok),
            "stage": r.last_stage or None,
            "vm_id": r.last_vm_id,
        }
        for r in rows
    }
