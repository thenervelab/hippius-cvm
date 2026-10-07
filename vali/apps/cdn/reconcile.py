"""The CDN fleet reconciler (CDN plan V3), one pass per orchestration tick.

Per `CdnRegion` it keeps `desired_nodes` nodes serving (`active=False` means
zero), on the region's flavor and the blessed cdn-node image, and moves every
node along its lifecycle (contract §B.1):

    launching → booting → ready → draining → drained → decommissioning → destroyed
                     ↘ failed ↗ (a failed node that was ever ready drains too)

The DNS rule this module exists to keep: a node that was ever `ready` may
have a DNS record, so it is decommissioned only after the backend's
`dns-released` ack (`POST /v1/cdn/nodes/<id>/dns-released`) plus
`VALI_CDN_DRAIN_GRACE_S`. Without an ack it waits forever and alerts after
`VALI_CDN_DRAIN_ACK_TIMEOUT_S`; only the operator override
(`vali_cdn_node force-drained`) stands in for an ack. A DB constraint backs
the rule (`cdn_node_drained_only_after_dns_released`), and the decommission
re-checks it under the node's row lock.

Replacement before removal: a drain asked of a ready node (operator,
upgrade, rotation) first launches a replacement, and the node drains only
once that one has been ready for `VALI_CDN_READY_SETTLE_S` — or at once when
no replacement can come (a launch failed since the drain was asked: the
region's single host is busy, and the backend fails it over), or when the
region is scaling down.

A node is never relaunched: its root is ephemeral and its NetBird enrolment
does not survive a reboot. A node fails and is replaced when its guest
rebooted (a live attestation with another SNP `report_id` than the one it
went ready with), when its guest stops answering (liveness wedged past
`VALI_CDN_WEDGED_S` — unless more than half of the fleet's ready nodes went
quiet together, which is a telemetry outage, not a fleet of dead nodes:
vali then alerts and holds), when its VM was stopped or went away, or when
it never got ready in `VALI_CDN_BOOT_TIMEOUT_S`. Reboot recovery leaves CDN
VMs alone (`orchestration.service`). A launch that fails before its node is
ready backs the region off `VALI_CDN_LAUNCH_BACKOFF_S`.

Upgrades and fleet-key rotations are replacements too, one node per region
at a time: a node on another bake than the blessed image's, or launched
before a pending fleet key (whose keyring therefore lacks it). A pending key
turns active once every live node was launched after it.

Inert unless `VALI_CDN_ENABLED` and `VALI_CDN_RECONCILE_ENABLED`.
"""

from __future__ import annotations

import datetime as dt
import logging
import secrets
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.common.cdn import cdn_enabled, cdn_tenant_id
from apps.lifecycle import guest_liveness
from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState

from . import ca, fleet
from . import userdata as cdn_userdata
from .models import CdnNode, CdnNodeState, CdnRegion, CdnRevision, DrainReason

log = logging.getLogger("apps.cdn")

_ACTOR = "cdn-reconciler"

#: Nodes that serve, or will: they count toward `desired_nodes` unless a
#: drain was asked of them.
_SERVING = (CdnNodeState.LAUNCHING, CdnNodeState.BOOTING, CdnNodeState.READY)
_IN_FLIGHT = (CdnNodeState.LAUNCHING, CdnNodeState.BOOTING)


def enabled() -> bool:
    return cdn_enabled() and bool(getattr(settings, "VALI_CDN_RECONCILE_ENABLED", False))


def _s(name: str, default: int) -> dt.timedelta:
    return dt.timedelta(seconds=max(0, int(getattr(settings, name, default))))


@dataclass
class ReconcileReport:
    launched: int = 0
    readied: int = 0
    failed: int = 0
    drained: int = 0
    decommissioned: int = 0
    renewed: int = 0


def _actor() -> Any:
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        name=_ACTOR,
        defaults={
            "description": "Runs the CDN fleet: launches, drains and replaces nodes.",
            # Holds no token (never authenticated over HTTP), like the
            # placement reconciler.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )
    return actor


# ── state changes ────────────────────────────────────────────────────


def _move(
    node: CdnNode, state: str, *, now: dt.datetime, expect: tuple[str, ...], **fields: Any
) -> bool:
    """Move `node` to `state` if it is still in one of `expect` (a CAS: the
    views write drains and acks concurrently). Bumps the revision."""
    with transaction.atomic():
        locked = CdnNode.objects.select_for_update().filter(pk=node.pk, state__in=expect).first()
        if locked is None:
            return False
        locked.state = state
        locked.state_changed_at = now
        for key, value in fields.items():
            setattr(locked, key, value)
        locked.save()
        CdnRevision.bump()
    for key, value in {"state": state, "state_changed_at": now, **fields}.items():
        setattr(node, key, value)
    why = f" ({node.failure_reason})" if state == CdnNodeState.FAILED else ""
    log.info("cdn: node %s → %s%s", node.node_id, state, why)
    return True


def _fail(node: CdnNode, reason: str, *, now: dt.datetime) -> bool:
    moved = _move(
        node,
        CdnNodeState.FAILED,
        now=now,
        expect=_SERVING,
        failure_reason=reason[:256],
    )
    if moved and node.ready_at is None:
        _region_launch_failed(node.region, now=now)
    return moved


def _region_launch_failed(region: str, *, now: dt.datetime) -> None:
    from django.db.models import F

    CdnRegion.objects.filter(region=region).update(
        launch_failed_at=now, launch_failures=F("launch_failures") + 1
    )
    failures = CdnRegion.objects.filter(region=region).values_list("launch_failures", flat=True)
    count = next(iter(failures), 0)
    if count >= 3:
        log.error("cdn: region %s: %d node launches failed in a row", region, count)


def request_drain(node_id: str, reason: str, *, now: dt.datetime | None = None) -> CdnNode:
    """Ask for node `node_id`'s removal (`reason` ∈ `DrainReason`). Idempotent;
    the reconciler launches the replacement and drains it once that one is
    ready. Raises `ValueError` (`not-drainable`) outside launching, booting,
    ready."""
    now = now or timezone.now()
    DrainReason(reason)
    with transaction.atomic():
        node = CdnNode.objects.select_for_update().filter(node_id=node_id).first()
        if node is None:
            raise LookupError(node_id)
        if node.drain_requested_at is not None:
            return node
        if node.state not in _SERVING:
            raise ValueError("not-drainable")
        node.drain_requested_at = now
        node.drain_reason = reason
        node.save(update_fields=["drain_requested_at", "drain_reason", "updated_at"])
        CdnRevision.bump()
    return node


# ── per node ─────────────────────────────────────────────────────────


def _launch_job(node: CdnNode) -> Any:
    from apps.orchestration.models import LaunchJob

    if not node.launch_job_id:
        return None
    return LaunchJob.objects.filter(job_id=node.launch_job_id).first()


def _attached_ip(vm: Vm) -> Any:
    from apps.network.models import PublicIP, PublicIpState

    return (
        PublicIP.objects.filter(vm=vm, state=PublicIpState.ATTACHED).select_related("edge").first()
    )


def _advance_launching(node: CdnNode, *, now: dt.datetime, report: ReconcileReport) -> None:
    from apps.orchestration.models import LaunchJobState

    job = _launch_job(node)
    if job is None:
        _fail(node, "launch-missing", now=now)
        report.failed += 1
        return
    if job.state == LaunchJobState.FAILED:
        outcome = str((job.result_json or {}).get("outcome") or job.state)
        _fail(node, f"launch-failed: {outcome}", now=now)
        report.failed += 1
        return
    if job.state != LaunchJobState.SUCCEEDED:
        return
    if node.vm is None or node.vm.state != VmState.ACTIVE:
        _fail(node, "launch-unbound", now=now)
        report.failed += 1
        return
    _move(node, CdnNodeState.BOOTING, now=now, expect=(CdnNodeState.LAUNCHING,))


def _renew(node: CdnNode, *, now: dt.datetime, report: ReconcileReport) -> None:
    if not ca.cert_needs_renewal(node, now=now):
        return
    try:
        ca.issue_node_cert(node.node_id, now=now)
        report.renewed += 1
    except Exception as exc:  # noqa: BLE001 — retried next tick, never fatal.
        log.error("cdn: node %s certificate not issued: %s", node.node_id, exc)
    node.refresh_from_db()


def _vm_gone(node: CdnNode, *, now: dt.datetime, report: ReconcileReport) -> bool:
    """Fail a node whose VM is no longer meant to serve. True if it did."""
    vm = node.vm
    if vm is None or vm.state in (VmState.DECOMMISSIONING, VmState.DESTROYED):
        report.failed += _fail(node, "vm-gone", now=now)
        return True
    if vm.state == VmState.ACTIVE and vm.power_state != VmPowerState.RUNNING:
        report.failed += _fail(node, f"vm-{vm.power_state}", now=now)
        return True
    return False


def _advance_booting(node: CdnNode, *, now: dt.datetime, report: ReconcileReport) -> None:
    from apps.network import service as network

    if _vm_gone(node, now=now, report=report):
        return
    vm = node.vm
    if node.drain_requested_at is not None:
        # Never ready, so never in DNS: nothing to wait for.
        if _move(node, CdnNodeState.DECOMMISSIONING, now=now, expect=(CdnNodeState.BOOTING,)):
            _decommission(node, report=report)
        return
    # First, so nothing below can keep a node booting forever.
    since = node.state_changed_at or node.created_at
    if now - since > _s("VALI_CDN_BOOT_TIMEOUT_S", 1800):
        report.failed += _fail(node, "boot-timeout", now=now)
        return
    if vm.state != VmState.ACTIVE:
        return  # migrating: wait
    ip = _attached_ip(vm)
    if ip is None:
        try:
            ip, created = network.attach_cdn(vm)
            if created:
                CdnRevision.bump()
        except network.NetworkError as exc:
            log.warning("cdn: node %s has no address yet: %s", node.node_id, exc)
    _renew(node, now=now, report=report)
    verdict = guest_liveness.verdict_for(vm, now=now)
    ready = (
        vm.boot_phase == VmBootPhase.RUNNING
        and verdict.is_alive
        and bool(vm.netbird_ip)
        and ip is not None
        and ip.target_ip is not None
        and bool(node.cert_pem)
        and node.cert_generation == int(vm.generation)
    )
    if ready and _move(
        node, CdnNodeState.READY, now=now, expect=(CdnNodeState.BOOTING,), ready_at=now
    ):
        CdnRegion.objects.filter(region=node.region).update(launch_failures=0)
        report.readied += 1


def _wedged(vm: Vm, *, now: dt.datetime) -> int | None:
    """The age of `vm`'s last in-guest signal when it counts as wedged for
    a CDN node, else `None`."""
    verdict = guest_liveness.verdict_for(vm, now=now)
    age = verdict.age_s or 0
    if verdict.is_wedged and age >= _s("VALI_CDN_WEDGED_S", 600).total_seconds():
        return age
    return None


def _rebooted(node: CdnNode) -> bool:
    """The node's guest booted again since it went ready: a live attestation
    after `ready_at` carries another SNP `report_id` (the firmware's
    per-launch guest id) than the one it went ready with. Its NetBird
    enrolment and ephemeral state are gone with the reboot."""
    from apps.telemetry.models import VmLiveAttestation

    if node.ready_at is None:
        return False
    ready_unix = int(node.ready_at.timestamp())
    rows = VmLiveAttestation.objects.filter(vm_id=node.node_id).exclude(report_id="")
    base = (
        rows.filter(verified_at_unix__lte=ready_unix)
        .order_by("-verified_at_unix")
        .values_list("report_id", flat=True)
        .first()
    ) or (
        rows.filter(verified_at_unix__gt=ready_unix)
        .order_by("verified_at_unix")
        .values_list("report_id", flat=True)
        .first()
    )
    if base is None:
        return False
    return rows.filter(verified_at_unix__gt=ready_unix).exclude(report_id=base).exists()


#: The VMs (and miners) a breaker compares against: those heard from lately.
#: Consecutive passes without an outage before a hold's start is forgotten.
_HOLD_CLEAR_PASSES = 2


def _control_window() -> dt.timedelta:
    return _s("VALI_CDN_BREAKER_CONTROL_WINDOW_S", 86400)


def _liveness_breaker(*, now: dt.datetime) -> bool:
    """True when in-guest telemetry looks down as a whole, not just for some
    nodes: more than half of ALL the running VMs that ever signalled (at
    least three — tenants' included) read wedged at once. Failing CDN nodes
    then would pull every DNS record over a telemetry outage, so vali alerts
    and fails none on liveness while it holds — for at most
    `VALI_CDN_BREAKER_MAX_HOLD_S` (the hold start is kept on `CdnRevision`),
    after which liveness failures resume. While held, a wedged node still
    fails when its host proves the domain is not running, or the host is
    gone (`_host_gone`).

    The comparison counts VMs heard from in
    `VALI_CDN_BREAKER_CONTROL_WINDOW_S` (24 h): an outage longer than that
    empties it (alerted as critical), and the hold ends."""
    vms = Vm.objects.filter(
        state=VmState.ACTIVE,
        power_state=VmPowerState.RUNNING,
        boot_phase=VmBootPhase.RUNNING,
        # A VM whose agent died long ago is no evidence either way.
        guest_signal_at__gte=now - _control_window(),
    ).only("guest_signal_at", "guest_signal_kind")
    total = quiet = 0
    for vm in vms:
        total += 1
        quiet += _wedged(vm, now=now) is not None
    if total == 0 and CdnNode.objects.filter(state=CdnNodeState.READY).exists():
        log.critical(
            "cdn: no running VM has signalled in the breaker's control window — the "
            "liveness breaker cannot tell an outage from dead nodes"
        )
    outage = total >= 3 and quiet * 2 > total
    with transaction.atomic():
        row, _ = CdnRevision.objects.select_for_update().get_or_create(pk=1)
        if not outage:
            if row.liveness_hold_since is not None:
                passes = row.liveness_clear_passes + 1
                if passes >= _HOLD_CLEAR_PASSES:
                    CdnRevision.objects.filter(pk=1).update(
                        liveness_hold_since=None, liveness_clear_passes=0
                    )
                else:
                    CdnRevision.objects.filter(pk=1).update(liveness_clear_passes=passes)
            return False
        since = row.liveness_hold_since or now
        CdnRevision.objects.filter(pk=1).update(liveness_hold_since=since, liveness_clear_passes=0)
    held_s = int((now - since).total_seconds())
    if now - since > _s("VALI_CDN_BREAKER_MAX_HOLD_S", 1800):
        log.error(
            "cdn: %d of %d running VMs quiet for %ds — past VALI_CDN_BREAKER_MAX_HOLD_S, "
            "liveness replacement resumes",
            quiet,
            total,
            held_s,
        )
        return False
    log.error(
        "cdn: %d of %d running VMs report no in-guest signal at once — holding the "
        "CDN liveness replacement for %ds so far (telemetry outage?)",
        quiet,
        total,
        held_s,
    )
    return True


def _unseen_cutoff(now: dt.datetime) -> dt.datetime:
    from apps.scheduler.service import miner_liveness_timeout_s

    return now - dt.timedelta(seconds=miner_liveness_timeout_s()) - _s("VALI_CDN_WEDGED_S", 600)


def _unseen_breaker(*, now: dt.datetime) -> bool:
    """True when more than half of the active miners heard from lately (at
    least two) went unseen together. A miner's `last_seen_at` moves with the
    same telemetry ingest as the guest signals, so that is an ingest outage
    on vali's side, not a fleet of dead hosts; one dark datacentre still
    fails its own nodes."""
    from apps.miners.models import MinerIdentity, MinerStatus

    seen = list(
        MinerIdentity.objects.filter(
            status=MinerStatus.ACTIVE.value, last_seen_at__gte=now - _control_window()
        ).values_list("last_seen_at", flat=True)
    )
    cutoff = _unseen_cutoff(now)
    unseen = sum(1 for at in seen if at < cutoff)
    if len(seen) >= 2 and unseen * 2 > len(seen):
        log.error(
            "cdn: %d of %d active miners unseen at once — holding the CDN host-unseen "
            "replacement (telemetry ingest outage?)",
            unseen,
            len(seen),
        )
        return True
    return False


def _host_gone(vm: Vm, *, now: dt.datetime, hold_unseen: bool) -> str:
    """Why the miner `vm` runs on can no longer serve it ("" if it can): it
    left the active set (an explicit decision: always acted on), or has not
    been seen for the scheduler's liveness timeout plus `VALI_CDN_WEDGED_S`
    (unless `hold_unseen`, see `_unseen_breaker`). A CDN node is replaced,
    never migrated, so this is the node's to act on."""
    from apps.miners.models import MinerIdentity, MinerStatus
    from apps.orchestration import effects

    node_id = effects._bound_miner_id(vm)
    miner = MinerIdentity.objects.filter(miner_id=node_id).first() if node_id else None
    if miner is None:
        return ""
    if miner.status != MinerStatus.ACTIVE.value:
        return f"host-{miner.status}"
    if hold_unseen:
        return ""
    if miner.last_seen_at is None or miner.last_seen_at < _unseen_cutoff(now):
        return "host-unseen"
    return ""


def _advance_ready(
    node: CdnNode,
    *,
    now: dt.datetime,
    report: ReconcileReport,
    hold_liveness: bool,
    hold_unseen: bool,
) -> None:
    if _vm_gone(node, now=now, report=report):
        return
    vm = node.vm
    if vm.state != VmState.ACTIVE:
        return  # migrating: wait
    if _rebooted(node):
        report.failed += _fail(node, "rebooted", now=now)
        return
    gone = _host_gone(vm, now=now, hold_unseen=hold_unseen)
    if gone:
        report.failed += _fail(node, gone, now=now)
        return
    age = _wedged(vm, now=now)
    if age is not None and not hold_liveness:
        report.failed += _fail(node, f"wedged {age}s", now=now)
        return
    if age is not None:
        # Held: the host's own answer still counts, and a node nobody can
        # vouch for gets no new certificate.
        from apps.orchestration import effects

        if effects.poll_domain_running(vm) is False:
            report.failed += _fail(node, "domain-down", now=now)
        return
    _renew(node, now=now, report=report)


def _advance_draining(node: CdnNode, *, now: dt.datetime, report: ReconcileReport) -> None:
    """`draining`, or `failed` after having been ready: wait for the ack."""
    if (
        node.state == CdnNodeState.DRAINING
        and node.vm is not None
        and node.vm.state == VmState.ACTIVE
    ):
        # It may still have a DNS record (and must still register) while
        # the ack is late: keep its certificate valid.
        _renew(node, now=now, report=report)
    if node.dns_released_at is None:
        asked = node.drain_requested_at or node.state_changed_at or node.created_at
        late = now - asked > _s("VALI_CDN_DRAIN_ACK_TIMEOUT_S", 1800)
        if late and node.drain_ack_alerted_at is None:
            log.error(
                "cdn: node %s has waited %ds for the backend's dns-released; it is NOT "
                "decommissioned without it (operator override: vali_cdn_node force-drained)",
                node.node_id,
                int((now - asked).total_seconds()),
            )
            CdnNode.objects.filter(pk=node.pk).update(drain_ack_alerted_at=now)
        return
    if now < node.dns_released_at + _s("VALI_CDN_DRAIN_GRACE_S", 210):
        return
    if _move(
        node,
        CdnNodeState.DRAINED,
        now=now,
        expect=(CdnNodeState.DRAINING, CdnNodeState.FAILED),
    ):
        report.drained += 1


def _decommission(node: CdnNode, *, report: ReconcileReport) -> None:
    """Start the §24 decommission of a `drained` (or never-ready `failed` /
    `decommissioning`) node's VM; `destroyed` once the VM is."""
    from apps.orchestration.service import StartError, start_decommission

    now = timezone.now()
    with transaction.atomic():
        locked = CdnNode.objects.select_for_update().get(pk=node.pk)
        # The DNS gate, re-checked under the lock (and by a DB constraint).
        if locked.ready_at is not None and locked.dns_released_at is None:
            log.error("cdn: node %s refused a decommission without dns-released", node.node_id)
            return
        # The node's own VM — or, if its launch made the row but never bound
        # it, the CDN tenant's VM on the node's (reserved) id.
        vm = locked.vm or Vm.objects.filter(vm_id=locked.node_id, tenant_id=cdn_tenant_id()).first()
        if vm is None or vm.state == VmState.DESTROYED:
            locked.state = CdnNodeState.DESTROYED
            locked.state_changed_at = now
            locked.save(update_fields=["state", "state_changed_at", "updated_at"])
            CdnRevision.bump()
            node.state = CdnNodeState.DESTROYED
            return
        if locked.state != CdnNodeState.DECOMMISSIONING:
            locked.state = CdnNodeState.DECOMMISSIONING
            locked.state_changed_at = now
            locked.save(update_fields=["state", "state_changed_at", "updated_at"])
            CdnRevision.bump()
            node.state = CdnNodeState.DECOMMISSIONING
    if vm.state != VmState.ACTIVE:
        return  # decommissioning already, or migrating: next tick
    try:
        start_decommission(vm=vm, decided_by=_actor())
        report.decommissioned += 1
    except StartError as exc:
        if exc.category != "job-in-flight":
            log.error("cdn: node %s decommission not started: %s", node.node_id, exc)


def _advance(
    node: CdnNode,
    *,
    now: dt.datetime,
    report: ReconcileReport,
    hold_liveness: bool = False,
    hold_unseen: bool = False,
) -> None:
    state = node.state
    if state == CdnNodeState.LAUNCHING:
        _advance_launching(node, now=now, report=report)
    elif state == CdnNodeState.BOOTING:
        _advance_booting(node, now=now, report=report)
    elif state == CdnNodeState.READY:
        _advance_ready(
            node, now=now, report=report, hold_liveness=hold_liveness, hold_unseen=hold_unseen
        )
    elif state == CdnNodeState.DRAINING or (
        state == CdnNodeState.FAILED and node.ready_at is not None
    ):
        _advance_draining(node, now=now, report=report)
    elif state == CdnNodeState.FAILED:
        # Never ready: never in DNS, nothing to wait for.
        if _move(node, CdnNodeState.DECOMMISSIONING, now=now, expect=(CdnNodeState.FAILED,)):
            _decommission(node, report=report)
    elif state in (CdnNodeState.DRAINED, CdnNodeState.DECOMMISSIONING):
        _decommission(node, report=report)


# ── per region ───────────────────────────────────────────────────────


def _blessed_bake_id() -> str:
    from apps.images.models import GoldenImage

    image = str(getattr(settings, "VALI_CDN_IMAGE_NAME", "") or "")
    row = GoldenImage.objects.filter(image_name=image, restricted_tenant=cdn_tenant_id()).first()
    return row.bake_id if row is not None else ""


def _new_node_id(region: str) -> str:
    from apps.orchestration.models import LaunchJob

    for _ in range(8):
        # Unguessable: a node's vm id must not be launched by anyone before
        # the node exists (`identity.bind_vm` refuses an older row anyway).
        node_id = f"cdn-{region.lower()}-{secrets.token_hex(8)}"
        taken = (
            CdnNode.objects.filter(node_id=node_id).exists()
            or Vm.objects.filter(vm_id=node_id).exists()
            or LaunchJob.objects.filter(vm_id=node_id).exists()
        )
        if not taken:
            return node_id
    raise RuntimeError("no free CDN node id")


def _launch(region: CdnRegion, *, now: dt.datetime, report: ReconcileReport) -> None:
    from apps.orchestration import launch_jobs

    from .identity import fleet_versions

    if not fleet_versions():
        log.warning(
            "cdn: region %s: no fleet key published yet (vali_cdn_fleet mint)", region.region
        )
        return
    image = str(getattr(settings, "VALI_CDN_IMAGE_NAME", "") or "")
    bake_id = _blessed_bake_id()
    if not bake_id:
        log.error("cdn: region %s: no %r image blessed for the CDN tenant", region.region, image)
        return
    node_id = _new_node_id(region.region)
    node = CdnNode.objects.create(
        node_id=node_id,
        region=region.region,
        state=CdnNodeState.LAUNCHING,
        state_changed_at=now,
        flavor=region.flavor,
        image_name=image,
        bake_id=bake_id,
    )
    CdnRevision.bump()
    tenant = cdn_tenant_id()
    intent = {
        "tenant_id": tenant,
        "user_id": tenant,
        "vm_id": node_id,
        "lease_id": f"cdn-{node_id}",
        "flavor": region.flavor,
        "cmdline": str(getattr(settings, "VALI_CDN_CMDLINE", "")),
        "image": image,
        "region": region.region,
        "platform_id": "",
        "enable_netbird": True,
        "auto_pin_allowlist": True,
    }
    try:
        job = launch_jobs.start_launch(
            intent=intent,
            userdata=cdn_userdata.render(node_id, region.region),
            decided_by=_actor(),
            cdn_node=True,
        )
    except Exception as exc:  # noqa: BLE001 — retried after the backoff.
        # Refused before anything was staged: the node never existed.
        detail = getattr(exc, "message", str(exc))
        log.error("cdn: region %s launch refused: %s", region.region, detail)
        CdnNode.objects.filter(pk=node.pk).delete()
        CdnRevision.bump()
        _region_launch_failed(region.region, now=now)
        report.failed += 1
        return
    CdnNode.objects.filter(pk=node.pk).update(launch_job_id=job.job_id)
    report.launched += 1
    log.info("cdn: region %s launching node %s (job %s)", region.region, node_id, job.job_id)


def _launch_failed_since(region: CdnRegion, since: dt.datetime) -> bool:
    return region.launch_failed_at is not None and region.launch_failed_at >= since


def _plan_region(region: CdnRegion, *, now: dt.datetime, report: ReconcileReport) -> None:
    nodes = list(CdnNode.objects.filter(region=region.region).exclude(state=CdnNodeState.DESTROYED))
    desired = region.desired_nodes if region.active else 0
    serving = [n for n in nodes if n.state in _SERVING and n.drain_requested_at is None]
    in_flight = [n for n in nodes if n.state in _IN_FLIGHT]
    settle = _s("VALI_CDN_READY_SETTLE_S", 600)
    settled = [
        n
        for n in serving
        if n.state == CdnNodeState.READY and n.ready_at is not None and n.ready_at <= now - settle
    ]

    # Scale down: the newest first, never-ready ones before ready ones.
    excess = len(serving) - desired
    if excess > 0:
        victims = sorted(
            serving, key=lambda n: (n.state == CdnNodeState.READY, -n.created_at.timestamp())
        )[:excess]
        for node in victims:
            request_drain(node.node_id, DrainReason.SCALE_DOWN, now=now)
            node.drain_requested_at = now
            node.drain_reason = DrainReason.SCALE_DOWN
        serving = [n for n in serving if n not in victims]

    # A ready node asked to drain does so once its replacement is ready and
    # settled — or at once when none can come or the region shrinks.
    for node in nodes:
        if node.state != CdnNodeState.READY or node.drain_requested_at is None:
            continue
        shrinking = node.drain_reason == DrainReason.SCALE_DOWN or desired == 0
        replaced = len(settled) >= desired
        no_spare = _launch_failed_since(region, node.drain_requested_at)
        if shrinking or replaced or no_spare:
            if no_spare and not (shrinking or replaced):
                log.warning(
                    "cdn: region %s has no spare host for node %s's replacement: draining "
                    "it first (the region fails over meanwhile)",
                    region.region,
                    node.node_id,
                )
            _move(node, CdnNodeState.DRAINING, now=now, expect=(CdnNodeState.READY,))

    # Upgrade / fleet-key rotation: one node per region at a time, only
    # while the region is otherwise whole and quiet.
    pending_drain = any(
        n.drain_requested_at is not None and n.state in (*_SERVING, CdnNodeState.DRAINING)
        for n in nodes
    )
    if not pending_drain and not in_flight and len(settled) >= desired > 0:
        bake = _blessed_bake_id()
        key = fleet.pending()
        stale = [n for n in settled if (bake and n.bake_id != bake) or n.flavor != region.flavor]
        reason = DrainReason.UPGRADE
        if not stale and key is not None:
            stale = [n for n in settled if n.created_at < key.created_at]
            reason = DrainReason.ROTATE
        if stale:
            oldest = min(stale, key=lambda n: n.created_at)
            request_drain(oldest.node_id, reason, now=now)
            serving = [n for n in serving if n is not oldest]

    # Launch toward the target.
    if len(serving) >= desired:
        return
    if len(in_flight) >= max(1, int(getattr(settings, "VALI_CDN_MAX_PARALLEL_LAUNCH", 1))):
        return
    if _launch_failed_since(region, now - _s("VALI_CDN_LAUNCH_BACKOFF_S", 600)):
        return
    _launch(region, now=now, report=report)


def _activate_pending_fleet_key(*, now: dt.datetime) -> None:
    """A pending fleet key turns active once every live node was launched
    after it (so every node's keyring holds it)."""
    key = fleet.pending()
    if key is None:
        return
    from django.db.models import Q

    live = CdnNode.objects.filter(
        Q(state__in=(*_SERVING, CdnNodeState.DRAINING))
        | Q(state=CdnNodeState.FAILED, ready_at__isnull=False)
    )
    if not live.filter(state=CdnNodeState.READY).exists():
        return
    if live.filter(created_at__lt=key.created_at).exists():
        return
    fleet.set_state(key.version, "active")
    log.info("cdn: fleet key v%d active", key.version)


def sync_network_revision() -> None:
    """Bump the revision when what the CDN reads show but the network app
    owns changed (a node's address or edge, a region's edges and pool): those change
    without the CDN app, and a reader holding the old ETag must not get a
    304 for them. Runs whenever the CDN is enabled, reconciler or not."""
    import hashlib
    import json

    from apps.network.models import PublicIP, PublicIpPool

    nodes = list(
        CdnNode.objects.exclude(state=CdnNodeState.DESTROYED)
        .order_by("node_id")
        .values_list("node_id", "vm_id")
    )
    ips = list(
        PublicIP.objects.filter(pool=PublicIpPool.CDN)
        .order_by("address")
        .values_list("address", "edge__name", "edge__region", "state", "vm_id", "cap_mbps")
    )
    from apps.network.models import IngressEdge

    edges = list(IngressEdge.objects.order_by("name").values_list("name", "region"))
    blob = json.dumps([nodes, ips, edges], default=str, separators=(",", ":")).encode()
    digest = hashlib.sha256(blob).hexdigest()
    with transaction.atomic():
        row, _ = CdnRevision.objects.select_for_update().get_or_create(pk=1)
        if row.network_digest == digest:
            return
        CdnRevision.objects.filter(pk=1).update(network_digest=digest)
        CdnRevision.bump()


def reconcile(*, now: dt.datetime | None = None) -> ReconcileReport:
    """One pass. Each node and each region in its own `try`."""
    report = ReconcileReport()
    if not cdn_enabled():
        return report
    try:
        sync_network_revision()
    except Exception:  # noqa: BLE001
        log.exception("cdn: unhandled error syncing the network revision")
    if not enabled():
        return report
    now = now or timezone.now()
    try:
        hold = _liveness_breaker(now=now)
    except Exception:  # noqa: BLE001 — unknown: act on no liveness verdict.
        log.exception("cdn: unhandled error in the liveness breaker")
        hold = True
    try:
        hold_unseen = _unseen_breaker(now=now)
    except Exception:  # noqa: BLE001 — unknown: act on no unseen verdict.
        log.exception("cdn: unhandled error in the host-unseen breaker")
        hold_unseen = True
    for node in CdnNode.objects.exclude(state=CdnNodeState.DESTROYED).select_related("vm"):
        try:
            _advance(node, now=now, report=report, hold_liveness=hold, hold_unseen=hold_unseen)
        except Exception:  # noqa: BLE001 — one node must not stop the fleet.
            log.exception("cdn: unhandled error advancing node %s", node.node_id)
    for region in CdnRegion.objects.all():
        try:
            _plan_region(region, now=now, report=report)
        except Exception:  # noqa: BLE001 — one region must not stop the others.
            log.exception("cdn: unhandled error planning region %s", region.region)
    try:
        _activate_pending_fleet_key(now=now)
    except Exception:  # noqa: BLE001
        log.exception("cdn: unhandled error in the fleet-key rotation")
    return report
