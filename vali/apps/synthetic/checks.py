"""Light-tier read-only health checks.

Each check returns a [`CheckResult`]; the runner (in the management
command) aggregates them into `hippius_synthetic_light_success` and per-
check `hippius_synthetic_light_check_success{check=...}` gauges. NOTHING
here mutates state — the light tier is safe to run every 10-15 minutes.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from django.conf import settings
from django.utils import timezone

log = logging.getLogger("apps.synthetic.checks")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    # Extra gauges to emit alongside the pass/fail (e.g. the current
    # epoch, dispatchable count) — {metric_name: value}.
    gauges: dict[str, float] = field(default_factory=dict)


def _http_reachable(url: str, timeout_s: float, context: object = None) -> tuple[bool, str]:
    """A live HTTP server answering ANYTHING (even 4xx/5xx) proves
    liveness; a connection/DNS error is a real outage.

    `context` is an optional `ssl.SSLContext`. It matters for the KBS
    admin listener: once that hop is mTLS, probing it WITHOUT presenting
    a client cert produces a handshake rejection that is indistinguishable
    here from "the KBS is down" — the monitor would page for a healthy
    cluster. So the probe dials it the same way the control plane does.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout_s, context=context) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        # Server answered — it is up, just not with 2xx on this path.
        return True, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError) as exc:
        return False, f"unreachable: {exc}"


def check_vali_api() -> CheckResult:
    """The deployed vali web pod answers `/healthz` with 200."""
    base = settings.VALI_SYNTHETIC_API_BASE.rstrip("/")
    timeout = float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S)
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=timeout) as resp:
            ok = resp.status == 200
            return CheckResult("vali_api", ok, f"/healthz HTTP {resp.status}")
    except (urllib.error.URLError, OSError) as exc:
        return CheckResult("vali_api", False, f"/healthz unreachable: {exc}")


def check_kbs() -> CheckResult:
    """The KBS admin server is reachable — dialled with the control
    plane's own admin transport, so once the listener is mTLS this probe
    also proves vali's client identity is still accepted.

    A TLS misconfiguration is reported as a FAILED check, not raised: the
    light tier must keep running its other checks, and "vali cannot dial
    the KBS admin API" is exactly the condition this check exists to
    surface.
    """
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_ssl_context,
    )

    url = settings.VALI_SYNTHETIC_KBS_URL
    timeout = float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S)
    try:
        context = admin_ssl_context(url)
    except KbsAdminTlsMisconfigured as exc:
        return CheckResult("kbs", False, f"admin transport misconfigured: {exc}")
    ok, detail = _http_reachable(url, timeout, context)
    return CheckResult("kbs", ok, detail)


def check_dispatchable_matches_active() -> CheckResult:
    """`dispatchable_node_ids()` must be a non-empty subset of the
    on-chain ACTIVE miners — no ghost-dispatchable node, and the fleet is
    not dark."""
    from apps.scheduler import chain
    from apps.scheduler.service import dispatchable_node_ids

    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable as exc:
        return CheckResult("dispatchable", False, f"chain unreadable: {exc}")

    active = {m.node_id.lower() for m in snapshot.miners if m.status == "active"}
    dispatchable = {n.lower() for n in dispatchable_node_ids()}
    ghosts = dispatchable - active
    gauges = {
        "hippius_synthetic_dispatchable_count": float(len(dispatchable)),
        "hippius_synthetic_onchain_active_count": float(len(active)),
    }
    if ghosts:
        return CheckResult(
            "dispatchable",
            False,
            f"dispatchable nodes not on-chain-active: {sorted(ghosts)}",
            gauges,
        )
    if not dispatchable:
        return CheckResult(
            "dispatchable",
            False,
            f"no dispatchable miners (on-chain active={len(active)})",
            gauges,
        )
    return CheckResult(
        "dispatchable",
        True,
        f"dispatchable={len(dispatchable)} ⊆ active={len(active)}",
        gauges,
    )


def check_host_attestor_coverage() -> CheckResult:
    """Every on-chain-active miner has live host-attestor coverage. When
    no release measurement is pinned yet (coverage undesired) this is a
    SKIP (ok) — mirrors the warn-only reconcile, no false alarm."""
    from apps.scheduler import chain
    from apps.telemetry import release_service

    try:
        report = release_service.reconcile_coverage()
    except chain.ChainReadUnavailable as exc:
        return CheckResult("host_attestor", False, f"chain unreadable: {exc}")

    gauges = {
        "hippius_synthetic_attestor_covered": float(report.covered),
        "hippius_synthetic_attestor_active": float(report.total_active_miners),
    }
    if not report.desired_measurements:
        return CheckResult(
            "host_attestor",
            True,
            "no release measurement pinned yet (coverage undesired) — skip",
            gauges,
        )
    ok = report.covered == report.total_active_miners
    return CheckResult(
        "host_attestor",
        ok,
        f"covered={report.covered}/{report.total_active_miners} "
        f"missing={report.missing} stale={report.stale}",
        gauges,
    )


def check_dynamic_capacity() -> CheckResult:
    """The untrusted-miner-safe capacity function is sane AND a fabricated
    over-report cannot inflate the admission bound. Pure — reuses the real
    `effective_capacity` (e9d9a75 / 4f59f87), no DB mutation."""
    from apps.scheduler.capacity import CapacityInputs, effective_capacity

    # A representative trusted anchor: 64 GiB / 32 vCPU host, small
    # reserve, one placement committed. slot_ref = the `small` flavor.
    # The security invariant is that a self-reported free-RAM value can
    # only ever THROTTLE capacity DOWN toward the trusted ledger ceiling —
    # never above it. So compare the trusted ceiling (`reported=None`)
    # against a physically-impossible over-report: the over-report must
    # clamp to the SAME (ceiling) slot count AND trip the over_claim alarm.
    anchor = dict(
        operator_max=100,
        total_memory_mb=65536,
        total_cpus=32,
        committed_memory_mb=2048,
        committed_cpus=1,
        committed_slots=1,
        reserve_memory_mb=4096,
        reserve_cpus=2,
        slot_ref_memory_mb=2048,
        slot_ref_cpus=1,
    )
    ceiling = effective_capacity(CapacityInputs(reported_free_mib=None, **anchor))
    # Fabricate a physically-impossible free-RAM report (10× the box).
    lying = effective_capacity(CapacityInputs(reported_free_mib=655360, **anchor))
    if lying.slots > ceiling.slots:
        return CheckResult(
            "dynamic_capacity",
            False,
            f"over-report INFLATED slots past trusted ceiling "
            f"{ceiling.slots}→{lying.slots} (REGRESSION)",
        )
    if not lying.over_claim:
        return CheckResult(
            "dynamic_capacity",
            False,
            "physically-impossible over-report did not raise over_claim",
        )
    if ceiling.slots < 0:
        return CheckResult("dynamic_capacity", False, f"negative slots {ceiling.slots}")
    return CheckResult(
        "dynamic_capacity",
        True,
        f"trusted ceiling={ceiling.slots} slots; over-report clamped to "
        f"{lying.slots} + over_claim flagged",
        {"hippius_synthetic_capacity_slots": float(ceiling.slots)},
    )


def check_no_stuck_jobs() -> CheckResult:
    """No non-terminal LaunchJob / DecommissionJob older than the stuck
    threshold. Synthetic-monitor's own throwaway VMs are excluded (they
    are self-cleaning within the run budget)."""
    from apps.orchestration.models import (
        TERMINAL_DECOMMISSION_STATES,
        TERMINAL_LAUNCH_STATES,
        DecommissionJob,
        LaunchJob,
    )

    cutoff = timezone.now() - timezone.timedelta(
        seconds=int(settings.VALI_SYNTHETIC_STUCK_JOB_AGE_S)
    )
    synth_tenant = settings.VALI_SYNTHETIC_TENANT_ID
    stuck_launch = (
        LaunchJob.objects.exclude(state__in=list(TERMINAL_LAUNCH_STATES))
        .exclude(tenant_id=synth_tenant)
        .filter(phase_started_at__lt=cutoff)
        .count()
    )
    stuck_dec = (
        DecommissionJob.objects.exclude(state__in=list(TERMINAL_DECOMMISSION_STATES))
        .exclude(vm__tenant_id=synth_tenant)
        .filter(phase_started_at__lt=cutoff)
        .count()
    )
    gauges = {
        "hippius_synthetic_stuck_launch_jobs": float(stuck_launch),
        "hippius_synthetic_stuck_decommission_jobs": float(stuck_dec),
    }
    ok = stuck_launch == 0 and stuck_dec == 0
    return CheckResult(
        "stuck_jobs",
        ok,
        f"stuck launch={stuck_launch} decommission={stuck_dec}",
        gauges,
    )


def check_epoch_close_advancing() -> CheckResult:
    """The on-chain epoch is readable, non-zero, and backed by a pallet
    that is STILL IN THE RUNTIME.

    The `pallet_live` half is the point. This check used to assert only
    `epoch > 0` and defer "is it advancing?" to a Prometheus rule on the
    `hippius_synthetic_current_epoch` gauge — **a rule that was never
    written**. So when a runtime upgrade dropped `pallet-compute-scoring`
    on 2026-08-03 and left its storage prefix behind, the epoch froze
    and this check reported OK every 15 minutes for a week.

    A frozen epoch is not cosmetic: it silently disarms the §23
    stale-epoch gate (`placement.py` / `service.py` compare
    `current_epoch - data_epoch`, and both operands stop moving together),
    so no miner can ever be excluded as stale again.

    `pallet_live` is a DEFINITIVE signal, not a heuristic — the reader
    checks the runtime metadata for the pallet, so it distinguishes "the
    epoch happens to be quiet" from "these bytes are a fossil no extrinsic
    can ever update". Prefer it over a flat-gauge rule, which cannot tell
    the two apart and needs a time window to fire at all.
    """
    from apps.scheduler import chain

    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable as exc:
        return CheckResult("epoch_close", False, f"chain unreadable: {exc}")
    epoch = int(snapshot.current_epoch)
    pallet_live = bool(snapshot.pallet_live)
    gauges = {
        "hippius_synthetic_current_epoch": float(epoch),
        "hippius_synthetic_chain_pallet_live": 1.0 if pallet_live else 0.0,
    }
    if not pallet_live:
        return CheckResult(
            "epoch_close",
            False,
            f"FOSSIL: current_epoch={epoch} but the configured pallet is "
            "ABSENT from the runtime metadata — its orphaned storage prefix "
            "still answers, so every chain value is frozen and no epoch can "
            "ever close",
            gauges,
        )
    return CheckResult("epoch_close", epoch > 0, f"current_epoch={epoch}", gauges)


def check_uptime_liveness() -> CheckResult:
    """No VM that WAS earning attested uptime has silently stopped.

    ## The failure this exists to make visible

    On 2026-08-13 a VM ran continuously on one miner and stopped
    earning at 13:20. Everything reported success: the miner-agent logged
    `forward-VmLiveAttestation=ok`, vali logged
    `live-attestation replay ignored` at INFO, the VM stayed `active` and
    kept emitting served receipts (so `guest_liveness` read `alive`). Only
    the chain showed it — `vali weights: 0 miner(s), total 0` — and only
    because someone looked. The cause is fixed
    (`apps.telemetry.vm_liveness._resolve_chain`); this check is here so
    that the NEXT cause of the same symptom is not silent either.

    ## The predicate, and why it is scoped this way

    A VM counts as STALLED when it is bound to a miner and billable, it
    HAS produced live attestations before, and its newest one is older
    than `VALI_UPTIME_LIVENESS_STALL_S`. That is literally "this VM is
    running and earning nothing".

    "HAS produced before" is load-bearing, and it is the same trap
    `apps.lifecycle.guest_liveness` documents: a VM on a pre-keepalive
    image emits NOTHING, forever, legitimately. Flagging those would pin
    this check at failing for the whole rollout, and a permanently-red
    check is a check nobody reads — which is how a real stall stays
    invisible. Absence of evidence is not evidence of a stall; a
    REGRESSION from evidence to none is.

    Reported unconditionally, ARMED or not: an un-armed fleet with a
    stalled VM is a fleet that would stop paying the moment it is armed.
    """
    from django.db.models import Max

    from apps.lifecycle.models import Vm, VmState
    from apps.scheduler.models import VmBillingBinding
    from apps.telemetry.models import VmLiveAttestation

    stall_s = max(1, int(getattr(settings, "VALI_UPTIME_LIVENESS_STALL_S", 1800)))
    now = int(timezone.now().timestamp())
    armed = bool(getattr(settings, "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION", False))

    # Billable + live: a launch binding exists (so the meter would credit
    # it) and the lifecycle row has not been torn down.
    billable = set(
        VmBillingBinding.objects.filter(
            vm_id__in=Vm.objects.filter(state__in=[VmState.ACTIVE, VmState.MIGRATING]).values_list(
                "vm_id", flat=True
            )
        ).values_list("vm_id", flat=True)
    )
    # Newest attestation per VM — VMs with none at all are absent here,
    # which is the "never emitted ⇒ no opinion" case.
    newest = {
        row["vm_id"]: int(row["t"])
        for row in VmLiveAttestation.objects.filter(vm_id__in=billable)
        .values("vm_id")
        .annotate(t=Max("verified_at_unix"))
    }
    stalled = sorted((vm_id, now - t) for vm_id, t in newest.items() if now - t > stall_s)
    gauges = {
        "hippius_synthetic_uptime_attesting_vms": float(len(newest)),
        "hippius_synthetic_uptime_stalled_vms": float(len(stalled)),
        "hippius_synthetic_uptime_liveness_armed": 1.0 if armed else 0.0,
    }
    if stalled:
        named = ", ".join(f"{vm}(age={age}s)" for vm, age in stalled[:5])
        more = "" if len(stalled) <= 5 else f" (+{len(stalled) - 5} more)"
        return CheckResult(
            "uptime_liveness",
            False,
            f"{len(stalled)} VM(s) STOPPED producing live attestations while "
            f"still bound and billable — running and earning "
            f"{'NOTHING' if armed else 'nothing once the gate is armed'}: "
            f"{named}{more}",
            gauges,
        )
    return CheckResult(
        "uptime_liveness",
        True,
        f"{len(newest)}/{len(billable)} billable VM(s) attesting, none stalled "
        f">{stall_s}s (gate {'ARMED' if armed else 'disarmed'})",
        gauges,
    )


# ── KBS running-config drift (the ConfigMap is not the config) ───────
#
# Three verdicts, deliberately three and not two. See
# `compare_posture` for why UNKNOWN may not collapse into either
# neighbour.
POSTURE_AGREE = "AGREE"
POSTURE_DRIFT = "DRIFT"
POSTURE_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PostureComparison:
    """The outcome of diffing the declared posture against the running
    one. `verdict` is one of AGREE / DRIFT / UNKNOWN."""

    verdict: str
    #: `[(key, expected, observed)]` for keys that DISAGREE.
    drifted: list[tuple[str, object, object]]
    #: Keys that were compared and matched.
    agreed: list[str]
    #: Keys the running process did not report at all (endpoint absent,
    #: older binary, or a key we declared that it does not know).
    unknown: list[str]


def compare_posture(expected: dict, observed: dict) -> PostureComparison:
    """Diff a DECLARED posture against what the RUNNING KBS reports.

    ## The three verdicts

    - **DRIFT** — at least one key was reported and disagrees. This is
      the defect: the ConfigMap (and therefore the gitops `Synced`
      badge) says one thing and the process is doing another.
    - **AGREE** — at least one key was compared and every compared key
      matched.
    - **UNKNOWN** — nothing could be compared at all.

    UNKNOWN is a third state on purpose. Folding it into DRIFT would
    make the check fire for the whole window between merging
    `GET /v1/admin/config` and the next KBS restart (the endpoint 404s
    until then, and restarting the KBS wipes its state/audit/evidence
    emptyDirs, so that window is measured in weeks) — a check that cries
    wolf is a check that gets muted, and a muted check is the defect
    again. Folding it into AGREE would be worse: "we could not look" is
    exactly the "all good" this whole item exists to stop reporting.

    Note the asymmetry: ONE observable agreeing key is enough for AGREE
    even if others are unknown. That is what keeps the pre-restart state
    green — today the running-process oracle is
    `GET /v1/admin/volume-stamp`'s `configured_bound`, which is the key
    whose silent disarm matters most, and it works with no restart.
    Partial coverage is published as a gauge, not as a failure.
    """
    drifted: list[tuple[str, object, object]] = []
    agreed: list[str] = []
    unknown: list[str] = []
    for key in sorted(expected):
        if key not in observed:
            unknown.append(key)
        elif observed[key] == expected[key]:
            agreed.append(key)
        else:
            drifted.append((key, expected[key], observed[key]))
    if drifted:
        verdict = POSTURE_DRIFT
    elif agreed:
        verdict = POSTURE_AGREE
    else:
        verdict = POSTURE_UNKNOWN
    return PostureComparison(verdict, drifted, agreed, unknown)


def _admin_get_json(path: str, *, _urlopen=urllib.request.urlopen) -> tuple[str, dict | None]:
    """GET a KBS admin JSON endpoint through the control plane's own
    admin transport (mTLS when the cutover is done, plaintext before).

    Returns `("ok", body)`, `("absent", None)` for a 404, or
    `("unavailable: …", None)` for anything else — a connection error,
    a 403 (no client identity), a 5xx, or an undecodable body.

    404 is classified apart from every other failure because it is the
    ONE outcome that means "this KBS binary predates the endpoint",
    which is a coverage gap, not a fault.
    """
    from apps.orchestration.services.kbs_admin_tls import (
        KbsAdminTlsMisconfigured,
        admin_transport,
    )

    try:
        transport = admin_transport(settings.VALI_SYNTHETIC_KBS_URL)
    except KbsAdminTlsMisconfigured as exc:
        return f"unavailable: admin transport misconfigured: {exc}", None
    timeout = float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S)
    try:
        with _urlopen(transport.url(path), timeout=timeout, context=transport.context) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "absent", None
        return f"unavailable: HTTP {exc.code}", None
    except (urllib.error.URLError, OSError) as exc:
        return f"unavailable: {exc}", None
    except (ValueError, UnicodeDecodeError) as exc:
        return f"unavailable: undecodable body: {exc}", None
    if not isinstance(body, dict):
        return "unavailable: body is not a JSON object", None
    return "ok", body


def _observe_running_posture() -> tuple[dict, dict[str, str]]:
    """Ask the RUNNING KBS process what it is enforcing.

    Two oracles, both read-only, deliberately kept independent:

    1. `GET /v1/admin/volume-stamp` → `configured_bound`. Available
       TODAY, on the deployed binary, with no restart. It reports the
       resolved suppressed-confirm bound gate 5c is actually enforcing —
       the single key whose silent disarm matters most, and the one that
       caught the 2026-08-13 divergence.
    2. `GET /v1/admin/config` → the whole posture. 404s until the KBS is
       next restarted; that is a coverage gap, never a drift signal.

    Returns `(observed, sources)` where `observed` maps posture key →
    running value, and `sources` maps endpoint → status for the detail
    line.
    """
    observed: dict = {}
    sources: dict[str, str] = {}

    status, body = _admin_get_json("/v1/admin/config")
    sources["config"] = status
    if status == "ok" and body is not None:
        # Every key the endpoint reports is comparable. Unknown extra
        # keys are ignored by `compare_posture` (it iterates EXPECTED),
        # so a newer KBS never fails an older expectation.
        observed.update(body)

    status, body = _admin_get_json("/v1/admin/volume-stamp")
    sources["volume-stamp"] = status
    if status == "ok" and body is not None and "configured_bound" in body:
        # Same value, same resolution function, different endpoint — it
        # IS `max_unconfirmed_releases`. Setting it after the posture
        # endpoint is intentional: if both answer they cannot disagree
        # (one `Option<u64>` in the KBS), and if only this one answers it
        # is the whole of today's coverage.
        observed["max_unconfirmed_releases"] = body["configured_bound"]

    return observed, sources


def check_kbs_config_drift() -> CheckResult:
    """The KBS ConfigMap is NOT the KBS config.

    ## The failure this exists to make visible

    `Config::load` runs exactly once, at kbs-server start, and the KBS
    Deployment carries no `checksum/config` annotation. That omission is
    CORRECT — rolling the pod wipes its `state`/`audit`/`evidence`
    emptyDirs inside a Kata CVM, so auto-rolling on every config edit
    would be destructive. The consequence is that an edited ConfigMap
    can sit next to a process that has never read it, for the pod's
    whole life, while ArgoCD reports `Synced` and `Healthy`.

    On 2026-08-13 the suppressed-confirm anti-rollback gate was armed
    (`maxUnconfirmedReleases: 0 → 3`), merged and synced. The deployed
    ConfigMap read `max_unconfirmed_releases = 3`; the 152-minute-old
    process still reported `gate_armed=false`. Trusting the ConfigMap
    would have recorded a security gate as ARMED while it was not. Only
    querying the running process caught it — and nothing was querying
    the running process on a schedule. This is that schedule.

    ## What is compared

    `VALI_KBS_EXPECTED_POSTURE` (rendered from the vali chart, and
    pinned by CI against the KBS chart's OWN rendered `config.toml` —
    `binaries/kbs-server/tests/chart_deploy_safety.rs`) against what the
    running KBS reports over the admin listener. So the diff really is
    "what git says the KBS should be enforcing" vs "what the process
    reports it is enforcing"; the ConfigMap↔git half is the one thing
    the gitops badge does cover honestly.

    ## Verdicts

    AGREE ⇒ pass. DRIFT ⇒ fail, and the message names the key and BOTH
    values. UNKNOWN (nothing was observable) ⇒ fail too, but with
    `hippius_synthetic_kbs_config_keys_compared == 0`, which is what the
    Prometheus rules key off to tell "we verified nothing" apart from
    "we verified a divergence". A 404 on the posture endpoint alone is
    NEITHER — see `compare_posture`.
    """
    raw = str(getattr(settings, "VALI_KBS_EXPECTED_POSTURE", "") or "").strip()
    gauges = {
        "hippius_synthetic_kbs_config_drift": 0.0,
        "hippius_synthetic_kbs_config_keys_compared": 0.0,
        "hippius_synthetic_kbs_posture_endpoint": 0.0,
    }
    if not raw:
        return CheckResult(
            "kbs_config_drift",
            False,
            "VALI_KBS_EXPECTED_POSTURE is not set — nothing declares what the KBS should "
            "be enforcing, so a config change that never reached the running process "
            "cannot be detected",
            gauges,
        )
    try:
        expected = json.loads(raw)
    except ValueError as exc:
        return CheckResult(
            "kbs_config_drift", False, f"VALI_KBS_EXPECTED_POSTURE is not valid JSON: {exc}", gauges
        )
    if not isinstance(expected, dict) or not expected:
        return CheckResult(
            "kbs_config_drift",
            False,
            "VALI_KBS_EXPECTED_POSTURE must be a non-empty JSON object of posture key → value",
            gauges,
        )

    observed, sources = _observe_running_posture()
    cmp = compare_posture(expected, observed)
    gauges["hippius_synthetic_kbs_config_drift"] = float(len(cmp.drifted))
    gauges["hippius_synthetic_kbs_config_keys_compared"] = float(len(cmp.drifted) + len(cmp.agreed))
    gauges["hippius_synthetic_kbs_posture_endpoint"] = 1.0 if sources.get("config") == "ok" else 0.0
    where = ", ".join(f"{k}={v}" for k, v in sorted(sources.items()))

    if cmp.verdict == POSTURE_DRIFT:
        named = "; ".join(
            f"{key}: ConfigMap/git declares {exp!r} but the RUNNING process reports {obs!r}"
            for key, exp, obs in cmp.drifted
        )
        return CheckResult(
            "kbs_config_drift",
            False,
            f"DRIFT: {named}. The KBS has not re-read its config since that change — it is "
            f"INERT while gitops reports Synced. Restart the KBS deliberately (it wipes the "
            f"state/audit/evidence emptyDirs — see deploy/gitops/apps/kbs/README.md) or "
            f"revert the change. [{where}]",
            gauges,
        )
    if cmp.verdict == POSTURE_UNKNOWN:
        return CheckResult(
            "kbs_config_drift",
            False,
            f"UNKNOWN: verified NOTHING — none of {sorted(expected)} could be read back from "
            f"the running KBS. This is not 'no drift', it is no coverage. [{where}]",
            gauges,
        )
    partial = f", {len(cmp.unknown)} not yet observable {cmp.unknown}" if cmp.unknown else ""
    return CheckResult(
        "kbs_config_drift",
        True,
        f"AGREE: {len(cmp.agreed)} posture key(s) match the running process "
        f"({', '.join(cmp.agreed)}){partial}. [{where}]",
        gauges,
    )


# Ordered light-tier check registry.
def check_no_zombie_vms() -> CheckResult:
    """No VM past its §24 crypto-erase is still talking.

    A fresh guest frame for such a VM (`apps.lifecycle.zombie`) means a
    miner is still running a VM it was told to kill — the guest keeps its
    disk key in memory for as long as the domain lives. Fails while any
    fresh observation exists; clears on its own once the frames stop or
    the destroy is confirmed.
    """
    from apps.lifecycle import zombie

    fresh = zombie.fresh_observations()
    vms = sorted({row.vm_id for row in fresh})
    miners = sorted({row.miner_id or "?" for row in fresh})
    gauges = {
        "hippius_synthetic_zombie_vms": float(len(vms)),
        "hippius_synthetic_zombie_quarantined_miners": float(len(zombie.quarantined_node_ids())),
    }
    if not vms:
        return CheckResult("zombie_vms", True, "no crypto-erased VM is still running", gauges)
    return CheckResult(
        "zombie_vms",
        False,
        f"{len(vms)} crypto-erased VM(s) still running: {', '.join(vms[:5])} "
        f"on miner(s) {', '.join(miners[:5])}",
        gauges,
    )


def check_guest_resources() -> CheckResult:
    """No VM attested less than its flavor, or from a superseded launch,
    within the flag window — and, once ENFORCE is armed, no live VM goes
    unproven.

    The guest's vCPU / RAM figures arrive inside a KBS-signed live
    attestation (`apps.telemetry.guest_resources`) — the miner cannot
    change them — so a short VM is a miner under-delivering (or a tenant
    shrinking its own VM from inside, which the evidence row lets an
    operator tell apart), and a superseded one a miner running a stale
    launch. Fails while any VM is flagged; clears once nothing new is
    found for `VALI_GUEST_RESOURCES_FLAG_S`.

    `unproven` counts the live, billable VMs attesting right now whose
    latest sample is not `ok` (launched before the attestation was switched
    on, or on an image that cannot attest). It is the readiness gauge for
    arming ENFORCE — under ENFORCE those VMs earn nothing, so it then fails
    the check too. A VM attesting nothing at all is not counted: it earns
    nothing under the uptime gate either way, and `uptime_liveness` owns it.
    """
    from django.db.models import OuterRef, Subquery

    from apps.lifecycle.models import Vm, VmState
    from apps.scheduler.models import VmBillingBinding
    from apps.telemetry import guest_resources
    from apps.telemetry.models import VmLiveAttestation

    flagged = guest_resources.flagged()
    stall_s = int(getattr(settings, "VALI_UPTIME_LIVENESS_STALL_S", 1800))
    recent = int(timezone.now().timestamp()) - stall_s
    latest = (
        VmLiveAttestation.objects.filter(vm_id=OuterRef("vm_id"), verified_at_unix__gte=recent)
        .order_by("-verified_at_unix")
        .values("resource_verdict")[:1]
    )
    live = Vm.objects.filter(state__in=[VmState.ACTIVE, VmState.MIGRATING]).values_list(
        "vm_id", flat=True
    )
    unproven = sorted(
        VmBillingBinding.objects.filter(vm_id__in=live)
        .annotate(verdict=Subquery(latest))
        .exclude(verdict=None)
        .exclude(verdict=guest_resources.VERDICT_OK)
        .values_list("vm_id", flat=True)
    )
    enforce = guest_resources.enforce()
    gauges = {
        "hippius_synthetic_guest_resource_short_vms": float(len(flagged)),
        "hippius_synthetic_guest_resources_unproven_vms": float(len(unproven)),
        "hippius_synthetic_guest_resources_enforced": 1.0 if enforce else 0.0,
    }
    problems: list[str] = []
    misconfigured = guest_resources.misconfigured()
    if misconfigured:
        problems.append(misconfigured)
    if flagged:
        shown = ", ".join(
            f"{vm_id}@{v.node_id_hex[:12]}({v.flavor}:{v.reason})"
            for vm_id, v in sorted(flagged.items())[:5]
        )
        problems.append(
            f"{len(flagged)} VM(s) short of their flavor or on a stale launch: {shown}"
        )
    if enforce and unproven:
        problems.append(
            f"{len(unproven)} live VM(s) not proving their size, earning nothing under "
            f"ENFORCE: {', '.join(unproven[:5])}"
        )
    if problems:
        return CheckResult("guest_resources", False, "; ".join(problems), gauges)
    return CheckResult(
        "guest_resources",
        True,
        f"no VM attested less than its flavor ({len(unproven)} not yet proving it)",
        gauges,
    )


def check_no_unapplied_migrations() -> CheckResult:
    """Every migration in the deployed image is applied to the database.

    Migrations run from a `vali-django-migrations` Job, and **deploying a
    new image does NOT re-run it**. So an image can ship a model whose
    table does not exist, and nothing notices until the first query.

    That happened on 2026-08-10: `sha-7f93d33815bb` shipped the SNP
    liveness gate with `telemetry.0006_vmliveattestation` unapplied. It
    was harmless ONLY because the gate ships disabled, so the query was
    never reached — armed, every usage accrual would have raised
    `ProgrammingError: relation "telemetry_vmliveattestation" does not
    exist` and reward accrual would have stopped fleet-wide.

    A pending migration is not a warning: it means the running code and
    the schema disagree, and which queries happen to avoid the gap is an
    accident of configuration rather than a safety property.
    """
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    try:
        executor = MigrationExecutor(connection)
        targets = executor.loader.graph.leaf_nodes()
        plan = executor.migration_plan(targets)
    except Exception as exc:  # noqa: BLE001 — a broken loader is itself a failure
        return CheckResult("migrations", False, f"migration state unreadable: {exc}")

    gauges = {"hippius_synthetic_unapplied_migrations": float(len(plan))}
    if plan:
        names = ", ".join(f"{m.app_label}.{m.name}" for m, _backwards in plan[:5])
        more = "" if len(plan) <= 5 else f" (+{len(plan) - 5} more)"
        return CheckResult(
            "migrations",
            False,
            f"{len(plan)} UNAPPLIED migration(s) — the deployed image and the "
            f"database schema disagree: {names}{more}",
            gauges,
        )
    return CheckResult("migrations", True, "all migrations applied", gauges)


def check_live_vms_placed() -> CheckResult:
    """Every live VM holds an active placement on the host it runs on.

    Admission counts only active placements, so a running VM without one
    is RAM/CPU the scheduler will sell again. The orchestration tick
    repairs any it finds within one cycle (`sweep_live_vm_placements`),
    so this fails only when the repair itself is failing — or for a VM
    with no placement ledger at all, which it cannot repair.
    """
    from apps.scheduler.service import live_vm_placement_drift, stale_pending_verdicts

    drift = live_vm_placement_drift()
    # Stale `Pending` rows the tick can resolve (`sweep_stale_pending_placements`)
    # — one that survives here means that resolution is failing.
    stale = stale_pending_verdicts()
    gauges = {
        "hippius_synthetic_unplaced_live_vms": float(len(drift)),
        "hippius_synthetic_stale_pending_placements": float(len(stale)),
    }
    if not drift and not stale:
        return CheckResult("live_vms_placed", True, "every live VM is placed on its host", gauges)
    if not drift:
        return CheckResult(
            "live_vms_placed",
            False,
            f"{len(stale)} stale PENDING placement(s) unresolved: "
            + ", ".join(f"{s.placement.vm.vm_id}({s.verdict}:{s.why})" for s in stale[:5]),
            gauges,
        )
    shown = ", ".join(
        f"{d.vm.vm_id}@{d.host_node_id[:12]}"
        f"({'none' if not d.active_node_ids else ','.join(n[:12] for n in d.active_node_ids)})"
        for d in drift[:5]
    )
    return CheckResult(
        "live_vms_placed",
        False,
        f"{len(drift)} live VM(s) not placed on their host — admission under-counts them: {shown}",
        gauges,
    )


LIGHT_CHECKS = (
    check_vali_api,
    check_kbs,
    check_dispatchable_matches_active,
    check_host_attestor_coverage,
    check_dynamic_capacity,
    check_no_stuck_jobs,
    check_epoch_close_advancing,
    check_no_unapplied_migrations,
    check_uptime_liveness,
    check_kbs_config_drift,
    check_no_zombie_vms,
    check_live_vms_placed,
    check_guest_resources,
)


def run_light() -> list[CheckResult]:
    """Run every light-tier check; a check that raises unexpectedly is
    turned into a failed result (never crashes the run)."""
    results: list[CheckResult] = []
    for fn in LIGHT_CHECKS:
        try:
            results.append(fn())
        except Exception as exc:  # defensive — one bad check can't nuke the run
            log.exception("light check %s crashed", fn.__name__)
            results.append(CheckResult(fn.__name__.replace("check_", ""), False, f"crashed: {exc}"))
    return results
