"""Guest-poweroff policy — what a miner does when a tenant guest powers
ITSELF off: start it again (`restart`, the historic behaviour and the
default) or leave it stopped (`stop`, e.g. a single-use CI runner that
powers off when its job is done). A crash — QEMU killed, a guest reboot, a
panic — is restarted by the miner whatever the policy; telling the two
apart is the miner-agent's job (`binaries/miner-agent/src/lifecycle/
power_policy.rs`).

## The three values on a `Vm`

- `on_guest_poweroff` — what the tenant asked for (launch body, or
  `PATCH /v1/vm/<id>/power-policy`).
- `on_guest_poweroff_effective` + `_effective_host` — what a miner
  ACKNOWLEDGED: a launch that carried the field and was accepted, or an
  accepted `power-policy` order. It only describes the host that
  acknowledged it; a VM that moved since (§25) reads `restart` until the
  new host acknowledges, because its destination booted without the field.
- Derived on read ([`view`]): `effective` (also `restart` once the host no
  longer runs an agent that knows the policy), `pending`, and `reason`
  (`host-unsupported` | `awaiting-ack`).

## Which miners know it

An agent too old to know the policy refuses a launch that carries it, and
has no `power-policy` route (`deny_unknown_fields`), so vali sends either
ONLY to a miner whose latest host-health heartbeat (v6) reports a release
tag at or above `VALI_POWER_POLICY_MIN_AGENT_VERSION` ([`supports`]). Empty
⇒ no miner qualifies: `stop` launches fail
`no-miner-supports-power-policy` and `PATCH stop` answers 409
`power-policy-unsupported-on-host`. A launch never falls back to `restart`.

The tag is miner-declared, so a miner can claim support it lacks. It then
refuses the order (fail-closed, the VM stays pending) or ignores the
policy — which it could do anyway: a miner can always stop or restart a VM.

## A guest that powered off under `stop`

The agent leaves the domain down and its `domain-state` probe answers
`{"running": false, "stop_reason": "guest-poweroff"}`. The reboot-recovery
scan then records the VM `stopped` ([`settle_guest_poweroff`]) instead of
relaunching it — but only for a VM whose tenant asked for `stop`, so a
miner cannot keep a `restart` VM down by saying so.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

log = logging.getLogger("apps.orchestration.power_policy")

RESTART = "restart"
STOP = "stop"
POLICIES = (RESTART, STOP)

#: Async launch failure reason when no miner can honour a `stop` launch.
NO_MINER_REASON = "no-miner-supports-power-policy"
#: `PATCH` refusal (409) for `stop` on a host whose agent does not know it.
UNSUPPORTED_ON_HOST = "power-policy-unsupported-on-host"
#: The `domain-state` `stop_reason` (and the VM's) of a guest poweroff.
GUEST_POWEROFF = "guest-poweroff"

REASON_HOST_UNSUPPORTED = "host-unsupported"
REASON_AWAITING_ACK = "awaiting-ack"

#: Budget for one `power-policy` dispatch, re-asks included. The PATCH runs
#: it inside the request (gunicorn's 60 s worker timeout).
DISPATCH_DEADLINE_S = 30.0
#: The same inside the serial orchestration tick, which must stay short.
RECONCILE_DEADLINE_S = 10.0
#: How many times a PATCH re-sends when a newer PATCH changed the request
#: while its order was in flight (the two can land on the miner in either
#: order; the last word must be the newest request).
MAX_RESENDS = 3

#: How recent a `stop` VM's verified stopped-ack (`Vm.power_guest_ack_at`)
#: must be for its guest-poweroff stop to count as PROVEN (§24 then takes
#: it as the EOL ack). The guest signs it on its way down, seconds before
#: the miner reports the poweroff; the reboot-recovery scan that records
#: the stop runs within minutes.
GUEST_ACK_PROOF_WINDOW = timedelta(minutes=15)

_TAG_RE = re.compile(r"^v(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d{1,6}))?$")


class PowerPolicyRefused(Exception):
    """A policy change is not legal for this VM right now. `reason` is a
    stable slug (the API `category`)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def parse_policy(value: object) -> str:
    """`value` as a policy, or `ValueError` — never a silent default."""
    if not isinstance(value, str) or value not in POLICIES:
        raise ValueError(f"on_guest_poweroff must be one of: {', '.join(POLICIES)}")
    return value


def release_key(tag: str) -> tuple[int, int, int, int] | None:
    """A miner-agent release tag (`vYYYY.MM.DD` or `vYYYY.MM.DD.N`) as a
    sortable key; `None` for anything else (`dev`, a typo, garbage)."""
    m = _TAG_RE.match(tag or "")
    if m is None:
        return None
    year, month, day, n = m.groups()
    return int(year), int(month), int(day), int(n or 0)


def min_agent_version() -> tuple[int, int, int, int] | None:
    """`VALI_POWER_POLICY_MIN_AGENT_VERSION` as a key; `None` (no miner
    qualifies) when unset or malformed — logged, never guessed."""
    raw = str(getattr(settings, "VALI_POWER_POLICY_MIN_AGENT_VERSION", "") or "").strip()
    if not raw:
        return None
    key = release_key(raw)
    if key is None:
        log.error(
            "VALI_POWER_POLICY_MIN_AGENT_VERSION=%r is not a release tag (vYYYY.MM.DD[.N]) "
            "— no miner is treated as supporting the guest-poweroff policy",
            raw,
        )
    return key


def _capacity_supports(row: Any, minimum: tuple[int, int, int, int] | None) -> bool:
    """The miner's LATEST host-health report came with a release tag at or
    above `minimum` (a v6 ingest stamps both times at once; a later v5 —
    agent rolled back, flag off — advances only the host-health one)."""
    if minimum is None or row is None:
        return False
    key = release_key(row.agent_version)
    return (
        key is not None
        and key >= minimum
        and row.agent_version_reported_at is not None
        and row.host_health_reported_at is not None
        and row.agent_version_reported_at >= row.host_health_reported_at
    )


def capable_node_ids() -> frozenset[str]:
    """Lower-cased chain node ids of the miners that support the policy —
    the scheduler's gate (l)."""
    from apps.scheduler.models import MinerCapacity

    minimum = min_agent_version()
    if minimum is None:
        return frozenset()
    rows = MinerCapacity.objects.exclude(agent_version="").only(
        "miner_node_id", "agent_version", "agent_version_reported_at", "host_health_reported_at"
    )
    return frozenset(r.miner_node_id.lower() for r in rows if _capacity_supports(r, minimum))


def capable_hosts(hosts: set[str]) -> set[str]:
    """The subset of `hosts` (`MinerIdentity.miner_id`, what `Vm.host`
    holds) whose miner supports the policy. One query per call."""
    from apps.miners.models import MinerIdentity

    hosts = {h for h in hosts if h}
    if not hosts:
        return set()
    capable = capable_node_ids()
    if not capable:
        return set()
    return {
        miner_id
        for miner_id, node_id in MinerIdentity.objects.filter(miner_id__in=hosts).values_list(
            "miner_id", "chain_node_id"
        )
        if node_id and node_id.lower() in capable
    }


def supports(miner: Any) -> bool:
    """`miner` (a `MinerIdentity`) supports the policy."""
    node_id = (getattr(miner, "chain_node_id", "") or "").lower()
    return bool(node_id) and node_id in capable_node_ids()


def effective(vm: Vm, *, capable: bool) -> str:
    """What the VM's CURRENT host does on a guest poweroff, as far as vali
    knows: `stop` only if that host acknowledged `stop` and still runs an
    agent that knows it."""
    if (
        vm.on_guest_poweroff_effective == STOP
        and vm.host
        and vm.on_guest_poweroff_effective_host == vm.host
        and capable
    ):
        return STOP
    return RESTART


def view(vm: Vm, capable_hosts_set: set[str] | None = None) -> dict[str, Any]:
    """The four wire fields (`VmSerializer`)."""
    if capable_hosts_set is None:
        capable_hosts_set = capable_hosts({vm.host})
    capable = vm.host in capable_hosts_set
    eff = effective(vm, capable=capable)
    pending = vm.on_guest_poweroff != eff
    reason = None
    if pending:
        reason = (
            REASON_HOST_UNSUPPORTED
            if vm.on_guest_poweroff == STOP and not capable
            else REASON_AWAITING_ACK
        )
    return {
        "on_guest_poweroff": vm.on_guest_poweroff,
        "on_guest_poweroff_effective": eff,
        "on_guest_poweroff_pending": pending,
        "on_guest_poweroff_reason": reason,
    }


def stop_reason(vm: Vm) -> str | None:
    """The wire `stop_reason`: `guest-poweroff` for a VM its guest stopped
    under `stop`, else `null`."""
    return GUEST_POWEROFF if vm.stopped_by_guest else None


def record_effective(vm_id: str, policy: str, host: str) -> None:
    """A miner (`host`) acknowledged `policy` for `vm_id`."""
    Vm.objects.filter(vm_id=vm_id).update(
        on_guest_poweroff_effective=policy, on_guest_poweroff_effective_host=host
    )


def launch_field(policy: str, miner: Any, *, relaunch: bool) -> str | None:
    """What a launch onto `miner` carries for `policy`: `"stop"`, or `None`
    (the field is left out — `restart`, byte-identical to before).

    A FIRST launch of a `stop` VM onto a miner that cannot honour it is
    refused (`PowerPolicyRefused`): the scheduler's gate (l) keeps such
    miners out, this is the backstop. A RELAUNCH (power start,
    reboot-recovery) onto its own host whose agent lost the policy (rolled
    back) goes without it rather than leave the VM down — the VM then reads
    `pending` / `host-unsupported` until the host can take it again."""
    if policy != STOP:
        return None
    if supports(miner):
        return STOP
    if relaunch:
        log.warning(
            "power-policy: relaunching on miner=%s without on_guest_poweroff=stop — its "
            "agent no longer reports a version that knows it",
            getattr(miner, "miner_id", "?"),
        )
        return None
    raise PowerPolicyRefused(
        NO_MINER_REASON,
        f"miner {getattr(miner, 'miner_id', '?')!r} does not support on_guest_poweroff=stop",
    )


def _dispatch(vm: Vm, policy: str, deadline_s: float = DISPATCH_DEADLINE_S) -> bool:
    """Send a `power-policy` order to the VM's host. `True` iff the miner
    accepted it. Never raises."""
    from apps.orchestration import effects, order_dispatch

    try:
        miner_id, netbird_ip = effects._miner_identity(vm.host)
        result = order_dispatch.dispatch_order_settled(
            miner_id=miner_id,
            netbird_ip=netbird_ip,
            order_id=f"pwr-policy-{vm.vm_id}-{uuid.uuid4().hex[:12]}",
            kind="power-policy",
            payload_json=json.dumps({"vm_id": vm.vm_id, "on_guest_poweroff": policy}).encode(),
            deadline_s=deadline_s,
        )
    except Exception as exc:  # noqa: BLE001 — a failed dispatch leaves the VM pending
        log.warning("power-policy: vm=%s dispatch to %s failed: %s", vm.vm_id, vm.host, exc)
        return False
    if not result.ok:
        log.warning(
            "power-policy: vm=%s miner=%s refused (status=%s class=%r)",
            vm.vm_id,
            vm.host,
            result.status,
            result.classifier,
        )
        return False
    return True


def _push(
    vm: Vm,
    *,
    capable: bool,
    dispatch: bool = True,
    deadline_s: float = DISPATCH_DEADLINE_S,
) -> bool:
    """Bring the VM's current host in line with what the tenant asked for.
    `True` iff it is (or now is) acknowledged; `dispatch=False` only
    settles what needs no order."""
    for _ in range(MAX_RESENDS):
        wanted = vm.on_guest_poweroff
        eff = effective(vm, capable=capable)
        if eff == wanted:
            if wanted == RESTART and vm.on_guest_poweroff_effective_host != vm.host:
                # The VM moved: its new host booted it without the field, so
                # it restarts. Recorded as that host's, so it stops reading as
                # a candidate. (A `stop` still recorded for THIS host whose
                # agent rolled back is kept: once the agent knows the policy
                # again it reads that file again, and the `restart` must be
                # sent then.)
                record_effective(vm.vm_id, RESTART, vm.host)
            return True
        if not capable or vm.power_state != VmPowerState.RUNNING or not dispatch:
            # An agent that does not know the policy cannot take it; a VM
            # with no running instance gets it with its next start.
            return False
        if not _dispatch(vm, wanted, deadline_s):
            return False
        # CAS on the request we sent: only it may be recorded as acknowledged.
        if Vm.objects.filter(pk=vm.pk, on_guest_poweroff=wanted, host=vm.host).update(
            on_guest_poweroff_effective=wanted, on_guest_poweroff_effective_host=vm.host
        ):
            log.info("power-policy: vm=%s host=%s acknowledged %s", vm.vm_id, vm.host, wanted)
            return True
        # A newer request arrived meanwhile, and its order may have landed
        # BEFORE ours: the miner may now hold what WE sent. Record that (the
        # one order known to have landed last-or-not), then send the newest
        # request again so it has the last word; if that fails, the VM reads
        # pending and the reconcile tick re-sends it.
        record_effective(vm.vm_id, wanted, vm.host)
        vm = Vm.objects.get(pk=vm.pk)
    return False


def change(vm: Vm, policy: str) -> Vm:
    """`PATCH /v1/vm/<id>/power-policy`: record the tenant's choice and
    apply it to the running instance through its miner — no relaunch.

    `stop` on a host that cannot honour it is refused (nothing recorded).
    A dispatch that fails leaves the VM `pending` (`awaiting-ack`); the
    reconcile tick ([`reconcile_once`]) re-sends it. A stopped VM's next
    start carries the policy in its launch order."""
    policy = parse_policy(policy)
    vm = Vm.objects.get(pk=vm.pk)
    if vm.state != VmState.ACTIVE:
        raise PowerPolicyRefused(
            "vm-not-active",
            f"vm {vm.vm_id!r} is {vm.state} — the guest-poweroff policy applies to an active VM",
        )
    capable = bool(vm.host) and vm.host in capable_hosts({vm.host})
    if policy == STOP and not capable:
        raise PowerPolicyRefused(
            UNSUPPORTED_ON_HOST,
            f"the miner hosting {vm.vm_id!r} does not run an agent that supports "
            "on_guest_poweroff=stop",
        )
    Vm.objects.filter(pk=vm.pk).update(on_guest_poweroff=policy)
    vm.on_guest_poweroff = policy
    _push(vm, capable=capable)
    return Vm.objects.get(pk=vm.pk)


def reconcile_once(max_dispatches: int = 5) -> int:
    """Re-send the policy to every active, running VM whose host has not
    acknowledged what the tenant asked for (a failed PATCH dispatch, a §25
    move, an agent back on a version that knows it). Returns how many VMs
    became acknowledged.

    It runs inside the serial orchestration tick, so it stays bounded: at
    most `max_dispatches` orders of `RECONCILE_DEADLINE_S` each, only to
    miners with a fresh heartbeat, at most one failure per miner per tick,
    and in a random order so a VM that keeps failing cannot starve the
    rest."""
    import random

    from django.db.models import F, Q

    from apps.miners.models import MinerIdentity
    from apps.scheduler import service as scheduler_service

    rows = list(
        Vm.objects.filter(state=VmState.ACTIVE, power_state=VmPowerState.RUNNING)
        .exclude(host="")
        .filter(
            ~Q(on_guest_poweroff=F("on_guest_poweroff_effective"))
            | ~Q(on_guest_poweroff_effective_host=F("host"))
        )
        .exclude(on_guest_poweroff=RESTART, on_guest_poweroff_effective=RESTART)
    )
    random.shuffle(rows)
    hosts = {vm.host for vm in rows}
    capable = capable_hosts(hosts)
    cutoff = timezone.now() - timedelta(seconds=scheduler_service.miner_liveness_timeout_s())
    alive = set(
        MinerIdentity.objects.filter(miner_id__in=hosts, last_seen_at__gte=cutoff).values_list(
            "miner_id", flat=True
        )
    )
    failed_hosts: set[str] = set()
    settled = 0
    budget = max(0, max_dispatches)
    for vm in rows:
        try:
            host_ok = vm.host in capable
            needs_order = effective(vm, capable=host_ok) != vm.on_guest_poweroff
            may_send = budget > 0 and vm.host in alive and vm.host not in failed_hosts and host_ok
            if _push(vm, capable=host_ok, dispatch=may_send, deadline_s=RECONCILE_DEADLINE_S):
                settled += 1
            elif needs_order and may_send:
                failed_hosts.add(vm.host)
            if needs_order and may_send:
                budget -= 1
        except Exception:  # noqa: BLE001 — one VM must not stop the tick
            log.exception("power-policy: reconcile failed for vm=%s", vm.vm_id)
    return settled


def settle_guest_poweroff(vm: Vm) -> bool:
    """Record `stopped` (reason `guest-poweroff`) for a VM whose miner
    reports its guest powered itself off under `stop`. Only for a VM whose
    tenant asked for `stop` and that vali still has `running` (a CAS on
    that read, so a concurrent power op wins). Returns `True` iff recorded.

    The stop is PROVEN (`power_stop_proof`, what §24 takes as the EOL ack
    of a stopped VM) when the guest's own verified stopped-ack arrived
    within `GUEST_ACK_PROOF_WINDOW` (`Vm.power_guest_ack_at`); otherwise a
    later §24 falls back to the forced reclaim, as for any VM whose guest
    left no ack."""
    if vm.on_guest_poweroff != STOP:
        return False
    row = (
        Vm.objects.filter(pk=vm.pk)
        .values("power_state", "power_state_at", "power_guest_ack_at", "eol_nonce")
        .first()
    )
    if row is None or row["power_state"] != VmPowerState.RUNNING:
        return False
    now = timezone.now()
    acked = row["power_guest_ack_at"]
    proven = (
        acked is not None
        and row["eol_nonce"] is not None
        and now - GUEST_ACK_PROOF_WINDOW <= acked <= now
        # An ack from before the boot that is now down proves nothing.
        and (row["power_state_at"] is None or acked >= row["power_state_at"])
    )
    fields = {
        "power_state": VmPowerState.STOPPED,
        "power_state_at": now,
        "power_stopped_by_guest_at": now,
        "power_stop_ordered_at": None,
        "power_stop_proof": bytes(row["eol_nonce"]) if proven else None,
    }
    if not Vm.objects.filter(
        pk=vm.pk,
        state=VmState.ACTIVE,
        power_state=VmPowerState.RUNNING,
        power_state_at=row["power_state_at"],
        on_guest_poweroff=STOP,
    ).update(**fields):
        return False
    for name, value in fields.items():
        setattr(vm, name, value)
    log.warning(
        "power-policy: vm=%s recorded stopped — its guest powered itself off "
        "(on_guest_poweroff=stop, miner=%s, ack %s)",
        vm.vm_id,
        vm.host,
        "verified" if proven else "absent — a §24 would force the reclaim",
    )
    return True
