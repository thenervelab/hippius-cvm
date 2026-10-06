"""Tenant NetBird peer janitor — delete the peers of VMs that are gone.

A first launch enrols its tenant peer PERSISTENT
(`effects.mint_netbird_setup_key(persistent=True)`): NetBird never deletes
it on its own, so it lives until vali deletes it. §24 does
(`effects.revoke_netbird`, after the erase and again in `RevokingNetbird`),
but both are best-effort — a NetBird outage across the whole
decommission, or a VM tombstoned by a path that never revokes (the
operator transition API), would leak the peer forever. This sweep is the
backstop.

BOUND PEERS FIRST. A peer whose id is bound to a setup key vali minted for
a VM (`netbird_binding`, NetBird's own audit log — not a name) belongs to
that VM whatever it is called:

- bound to a Destroyed VM ⇒ deleted, under any name (`vm-destroyed(bound)`);
- bound to a live VM ⇒ never deleted, even under a Destroyed VM's name.

Open bindings are closed at the start of each pass (one audit-log read, only
while some key is open); a failure there is logged and the pass goes on with
the bindings already recorded. The rules below cover every other peer.

NAMES ARE CLAIMS. A peer's name is the hostname the guest sends, and the
guest's userdata is the tenant's own, so any tenant can enrol a peer under
any name — including another VM's. So the janitor only ever acts on a name
that cannot belong to a VM vali still runs:

- the name must start `hippius-tenant-` with a non-empty remainder; every
  other peer (ingress edges, miners, operators) is never looked at. The
  remainder names a vm_id literally, or after stripping a NetBird clash
  suffix (`-<d>-<d>`, see `effects.tenant_peer_vm_ids`).
- a peer is SKIPPED when the remainder is a live (non-Destroyed) VM's
  vm_id, or starts with one followed by `-` — `hippius-tenant-<live>`,
  `hippius-tenant-<live>-181-159` and `hippius-tenant-<live>-x` all could
  be that VM's. (`-` is required so `vm-1` does not shadow `vm-12`.)

A peer that passes is deleted when:

- a vm_id it names is Destroyed — the tombstone is terminal and the vm_id
  can never be relaunched. Deleted whether or not it is connected: a
  connected peer of a destroyed VM is a zombie guest §24 would cut anyway.
- no vm_id it names has a `Vm` row at all, AND this vali is the sole
  control plane on the NetBird account (`VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER`
  — another vali's VMs would have no row here), AND no live vm_id starts
  with the remainder either (a truncated name), AND it is disconnected,
  AND NetBird last saw it at least `VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S`
  ago, AND no launch of that vm_id is in flight. The row is created before
  a launch dispatches (`launch._ensure_vm_row`), so a row-less peer is a
  hard-deleted row, a pre-row launch, or a tenant's own stray enrolment. A
  missing / unparseable `last_seen` is NEVER deleted on this branch.

Deletions are capped per pass (`VALI_NETBIRD_PEER_JANITOR_MAX_DELETES`
SUCCESSFUL deletions; peers whose delete failed last pass go to the back of
the queue so they cannot starve the rest), logged at WARNING one by one,
and `VALI_NETBIRD_PEER_JANITOR_DRY_RUN` logs them without deleting.
`VALI_NETBIRD_PEER_JANITOR_ENABLED` turns it off.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from . import effects, netbird_binding

log = logging.getLogger("apps.orchestration.netbird_janitor")

#: Throttle key — one pass (one `GET /api/peers`) per interval, fleet-wide.
_THROTTLE_KEY = "vali:netbird-peer-janitor"
#: Peer ids whose delete failed on the last pass — tried last next time.
_FAILED_KEY = "vali:netbird-peer-janitor:failed"
_FAILED_TTL_S = 86400


@dataclass(frozen=True)
class Doomed:
    """One peer the janitor has decided to delete."""

    peer_id: str
    vm_id: str
    reason: str


def _parse_last_seen(value: Any) -> datetime | None:
    """NetBird's RFC 3339 `last_seen`, or `None` when absent / unparseable
    (which the no-row branch treats as "do not delete")."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    # NetBird reports `0001-01-01T00:00:00Z` for a peer it has never seen;
    # that is "unknown", not "very old".
    if parsed.year < 2000:
        return None
    return parsed


def select_doomed(peers: list[dict[str, Any]], *, now: datetime) -> list[Doomed]:
    """The peers of `peers` to delete, per the module rules. Pure over the
    listing + the DB; deletes nothing."""
    from apps.lifecycle.models import Vm, VmState

    from .models import TERMINAL_LAUNCH_STATES, LaunchJob

    bound_dead = netbird_binding.destroyed_bound_peers()
    bound_live = netbird_binding.live_bound_peer_ids()
    doomed: list[Doomed] = []
    named: list[tuple[dict[str, Any], tuple[str, ...]]] = []
    for p in peers:
        peer_id = str(p.get("id") or "")
        if peer_id in bound_live:
            continue  # a live VM's peer, whatever its name says
        if peer_id in bound_dead:
            reason = "vm-destroyed(bound)" + ("(connected)" if p.get("connected") else "")
            doomed.append(Doomed(peer_id=peer_id, vm_id=bound_dead[peer_id], reason=reason))
            continue
        candidates = effects.tenant_peer_vm_ids(str(p.get("name") or ""))
        if candidates:
            named.append((p, candidates))
    if not named:
        return doomed

    live = list(
        Vm.objects.exclude(state=VmState.DESTROYED).values_list("vm_id", flat=True)
    )
    wanted = {vm_id for _, candidates in named for vm_id in candidates}
    destroyed = set(
        Vm.objects.filter(vm_id__in=wanted, state=VmState.DESTROYED).values_list(
            "vm_id", flat=True
        )
    )
    launching = set(
        LaunchJob.objects.filter(vm_id__in=wanted)
        .exclude(state__in=TERMINAL_LAUNCH_STATES)
        .values_list("vm_id", flat=True)
    )
    grace = timedelta(seconds=int(settings.VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S))
    sole_owner = bool(settings.VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER)

    for p, candidates in named:
        rest = candidates[0]
        if any(rest == v or rest.startswith(f"{v}-") for v in live):
            continue  # could be a live VM's peer
        hit = next((c for c in candidates if c in destroyed), None)
        if hit is not None:
            reason = "vm-destroyed" + ("(connected)" if p.get("connected") else "")
            doomed.append(Doomed(peer_id=str(p.get("id") or ""), vm_id=hit, reason=reason))
            continue
        if not sole_owner:
            continue
        if any(v.startswith(rest) for v in live):
            continue  # a truncated name of a live VM
        if launching.intersection(candidates) or bool(p.get("connected")):
            continue
        last_seen = _parse_last_seen(p.get("last_seen"))
        if last_seen is None or now - last_seen < grace:
            continue
        doomed.append(
            Doomed(
                peer_id=str(p.get("id") or ""),
                vm_id=rest,
                reason=f"no-vm-row(offline-since={last_seen.isoformat()})",
            )
        )
    return doomed


def sweep_orphan_tenant_peers(*, now: datetime | None = None) -> int:
    """One throttled janitor pass. Returns the number of peers DELETED
    (0 in dry-run). Never raises for a NetBird failure — it is logged and
    the next pass retries."""
    if not settings.VALI_NETBIRD_PEER_JANITOR_ENABLED:
        return 0
    if not str(getattr(settings, "VALI_NETBIRD_API_TOKEN", "") or "").strip():
        return 0
    interval = int(settings.VALI_NETBIRD_PEER_JANITOR_INTERVAL_S)
    if not cache.add(_THROTTLE_KEY, 1, timeout=interval):
        return 0
    now = now or timezone.now()
    try:
        peers = effects.list_netbird_peers()
    except effects.EffectError as exc:  # EffectUnavailable included
        log.warning("netbird janitor: peer listing failed, skipping this pass: %s", exc)
        return 0
    try:
        netbird_binding.bind_netbird_keys(now=now)
    except effects.EffectError as exc:
        log.warning(
            "netbird janitor: binding setup keys to peers failed, going on with "
            "the bindings already recorded: %s",
            exc,
        )

    doomed = select_doomed(peers, now=now)
    cap = max(0, int(settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES))
    if len(doomed) > cap:
        log.warning(
            "netbird janitor: %d tenant peers to delete, at most %d this pass "
            "(the rest go on later passes)",
            len(doomed),
            cap,
        )
    if settings.VALI_NETBIRD_PEER_JANITOR_DRY_RUN:
        for d in doomed[:cap]:
            log.warning(
                "netbird janitor [dry-run]: WOULD delete peer %s of vm %s (%s)",
                d.peer_id,
                d.vm_id,
                d.reason,
            )
        return 0

    # Last pass's failures go last (stable sort), so a peer whose delete
    # keeps failing cannot hold the cap against the others.
    failed_before = set(cache.get(_FAILED_KEY) or ())
    doomed.sort(key=lambda d: d.peer_id in failed_before)
    failed_now: list[str] = []
    deleted = 0
    # Attempts are bounded too: every one is a NetBird call.
    for d in doomed[: 2 * cap]:
        if deleted >= cap:
            break
        try:
            effects.delete_netbird_peer(d.peer_id, label="netbird:janitor-delete-peer")
        except effects.EffectError as exc:
            failed_now.append(d.peer_id)
            log.warning(
                "netbird janitor: deleting peer %s of vm %s failed: %s", d.peer_id, d.vm_id, exc
            )
            continue
        deleted += 1
        log.warning(
            "netbird janitor: deleted peer %s of vm %s (%s)", d.peer_id, d.vm_id, d.reason
        )
    cache.set(_FAILED_KEY, failed_now, timeout=_FAILED_TTL_S)
    return deleted
