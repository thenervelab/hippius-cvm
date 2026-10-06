"""Bind the NetBird setup keys vali minted for a VM to the peers that used them.

A tenant peer's NAME is the hostname its guest sends — tenant userdata, so a
claim: a guest can enrol under any name, including another VM's. What the
tenant cannot choose is WHICH setup key it enrolled with, and NetBird's
audit log records exactly that (`peer.setupkey.add`: initiator = key id,
target = peer id — `effects.list_netbird_setup_key_enrolments`).

`launch.launch_on_miner` records every key it mints (`VmNetbirdKey`) before
the key leaves vali. This module reads the audit log for the keys whose
binding is still open and records the peer each one enrolled, then points
`Vm.netbird_peer_id` at the VM's PRIMARY peer ([`bindings_for`] ranks them).

Only a FIRST launch's key is persistent (`launch._netbird_key_is_persistent`);
a relaunch key is ephemeral and normally never used — the guest logs in with
the identity it already holds. A tenant CAN enrol some other machine with a
relaunch key, so a relaunch-key peer never outranks a first-launch key's
peer: it is revoked with the VM like every bound peer. For resolution
(overlay IP, public-IP target) a CONNECTED bound peer wins first — so a
guest that lost its NetBird state and re-enrolled with a relaunch key is
followed rather than pinned to its dead first peer (a persistent peer is
never GC'd, so it always "exists"); among connected or among disconnected
peers, the first-launch key's wins. An outside machine enrolled with a
relaunch key can therefore only win while the VM's own peer is offline —
and the address it takes is that tenant's own.

A key closes ("settles") when it is bound, or when it expired unused —
after `expires_at` NetBird refuses it (`SetupKey.IsValid`), so no peer can
appear for it later. Only open keys cost an audit-log read, so a VM's
bindings stop costing anything about an hour after its last launch.

Trust assumption: the audit log is written by the NetBird management server,
which vali already trusts for every peer record it acts on. Anyone holding a
key could have been the one to enrol with it; whoever did holds a credential
minted for this VM, so its peer is this VM's to revoke. The log keeps the
newest 10 000 events: a key still open when its event has aged out of that
window settles unbound, and the VM falls back to name matching.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.core.cache import cache
from django.utils import timezone

from . import effects

log = logging.getLogger("apps.orchestration.netbird_binding")

#: How long after a key's `expires_at` an unbound key is still looked for —
#: covers clock skew between vali and NetBird.
SETTLE_GRACE = timedelta(minutes=10)


def bind_netbird_keys(
    *, vm_ids: list[str] | None = None, now: datetime | None = None
) -> int:
    """Close the open `VmNetbirdKey` bindings (of `vm_ids`, or fleet-wide)
    against NetBird's audit log. Returns the number of keys BOUND.

    No open key ⇒ no NetBird call. Raises `EffectUnavailable` /
    `EffectError` when the audit log cannot be read; nothing is settled
    then.
    """
    from apps.lifecycle.models import VmNetbirdKey

    pending = VmNetbirdKey.objects.filter(settled_at__isnull=True)
    if vm_ids is not None:
        pending = pending.filter(vm__vm_id__in=vm_ids)
    keys = list(pending.select_related("vm"))
    if not keys:
        return 0
    enrolments = effects.list_netbird_setup_key_enrolments()
    now = now or timezone.now()
    touched: set[int] = set()
    bound = 0
    unbound: list[VmNetbirdKey] = []
    for key in keys:
        peer_id = enrolments.get(key.setup_key_id, "")
        if peer_id:
            VmNetbirdKey.objects.filter(pk=key.pk, settled_at__isnull=True).update(
                peer_id=peer_id, settled_at=now
            )
            touched.add(key.vm_id)
            bound += 1
        elif key.expires_at + SETTLE_GRACE <= now:
            if VmNetbirdKey.objects.filter(pk=key.pk, settled_at__isnull=True).update(
                settled_at=now
            ):
                unbound.append(key)
    for vm_pk in touched:
        _point_vm_at_primary_peer(vm_pk)
    _report_unbound(unbound)
    return bound


def _report_unbound(keys: list[Any]) -> None:
    """One line per pass for the keys that expired with no enrolment.

    A relaunch key going unused is the normal case (INFO). A FIRST-launch
    key going unused means that VM's guest never enrolled — or that the
    audit log vali reads the bindings from is off, unreadable to the token,
    or truncated — and the VM is left to name matching: WARNING, so a
    binding that silently stopped working gets noticed."""
    first = sorted(k.vm.vm_id for k in keys if k.persistent)
    relaunch = len(keys) - len(first)
    if first:
        log.warning(
            "netbird binding: %d first-launch setup key(s) expired with no enrolment "
            "in NetBird's audit log — the guest never enrolled, or the audit log "
            "is disabled / unreadable / truncated; these VMs fall back to name "
            "matching: %s",
            len(first),
            ", ".join(first),
        )
    if relaunch:
        log.info("netbird binding: %d relaunch setup key(s) expired unused", relaunch)


def _point_vm_at_primary_peer(vm_pk: int) -> None:
    """`Vm.netbird_peer_id` ← the VM's highest-ranked bound peer."""
    from apps.lifecycle.models import Vm, VmNetbirdKey

    rows = VmNetbirdKey.objects.filter(vm_id=vm_pk).exclude(peer_id="")
    ranked = _rank(rows.values_list("persistent", "created_at", "id", "peer_id"))
    if ranked:
        Vm.objects.filter(pk=vm_pk).exclude(netbird_peer_id=ranked[0]).update(
            netbird_peer_id=ranked[0]
        )


def _rank(rows: Iterable[tuple[bool, datetime, int, str]]) -> list[str]:
    """Peer ids of `(persistent, created_at, pk, peer_id)` rows: first-launch
    keys' peers first, newest first within each class."""
    out: list[str] = []
    for *_, peer_id in sorted(rows, reverse=True):
        if peer_id not in out:
            out.append(peer_id)
    return out


@dataclass(frozen=True)
class PeerBinding:
    """What vali has recorded about one VM's NetBird peers.

    - `ranked`  its bound peer ids in preference order: first-launch
                (persistent) keys' peers, then relaunch keys' peers, newest
                first within each; then `Vm.netbird_peer_id` if not already
                listed. The resolver takes the first CONNECTED one the
                listing holds, else the first it holds at all
                (`effects.tenant_peer_from_listing`).
    - `owners`  `{peer id: vm_id}` over every non-Destroyed VM's bound
                peers — SHARED by all the bindings one call returns (it is
                built once). A peer owned by another VM is never this
                VM's, whatever name it carries.
    """

    ranked: tuple[str, ...] = ()
    owners: Mapping[str, str] = field(default_factory=dict)


def bindings_for(vm_ids: Iterable[str]) -> dict[str, PeerBinding]:
    """[`PeerBinding`] for each of `vm_ids` — two queries in all, over the
    non-Destroyed VMs only (a Destroyed VM's peers are §24 / the janitor's
    to delete, not anyone's to resolve)."""
    from apps.lifecycle.models import Vm, VmNetbirdKey, VmState

    owners: dict[str, str] = {}
    per_vm: dict[str, list[tuple[bool, datetime, int, str]]] = defaultdict(list)
    # A Destroyed VM's peers still OWN their ids (so no other VM's name
    # fallback can pick one up while §24 / the janitor have yet to delete
    # it); they are just never ranked for anyone.
    keys = VmNetbirdKey.objects.exclude(peer_id="").values_list(
        "peer_id", "vm__vm_id", "vm__state", "persistent", "created_at", "id"
    )
    for peer_id, vm_id, state, persistent, created_at, pk in keys:
        owners[peer_id] = vm_id
        if state != VmState.DESTROYED:
            per_vm[vm_id].append((persistent, created_at, pk, peer_id))
    recorded: dict[str, str] = {}
    vms = (
        Vm.objects.exclude(netbird_peer_id="")
        .exclude(state=VmState.DESTROYED)
        .values_list("netbird_peer_id", "vm_id")
    )
    for peer_id, vm_id in vms:
        owners.setdefault(peer_id, vm_id)
        recorded[vm_id] = peer_id
    out: dict[str, PeerBinding] = {}
    for vm_id in vm_ids:
        ranked = _rank(per_vm.get(vm_id, []))
        if vm_id in recorded and recorded[vm_id] not in ranked:
            ranked.append(recorded[vm_id])
        out[vm_id] = PeerBinding(ranked=tuple(ranked), owners=owners)
    return out


#: `(pk, vm_id, netbird_ip, netbird_status)` of the live VMs, read BEFORE
#: the peer listing a refresh resolves against.
OverlaySnapshot = list[tuple[Any, str, str, str, str]]

#: How far apart two listings lacking a VM's peer must be before its
#: address is cleared — four 30 s reconcile passes.
ABSENCE_CONFIRM = timedelta(minutes=2)


def _absent_key(pk: Any) -> str:
    return f"netbird:peer-absent:{pk}"


def _absence_confirmed(pk: Any, address: str, now: datetime) -> bool:
    """Record that `pk`'s peer is absent from this listing while the row
    holds `address`; True once it was also absent, for that same address,
    from one `ABSENCE_CONFIRM` earlier. The record is dropped whenever the
    row cannot be cleared (seen, pending, migrating) and restarts when the
    address changed, so a stale one never shortcuts the confirmation. A
    lost cache only delays a clear."""
    key = _absent_key(pk)
    first = cache.get(key)
    if not isinstance(first, list) or len(first) != 2 or first[0] != address:
        ttl = int(ABSENCE_CONFIRM.total_seconds()) * 10
        cache.set(key, [address, now.isoformat()], timeout=ttl)
        return False
    return now - datetime.fromisoformat(first[1]) >= ABSENCE_CONFIRM


def overlay_snapshot() -> OverlaySnapshot:
    """`(pk, vm_id, state, netbird_ip, netbird_status)` of the rows
    [`refresh_overlay_ips`] may change, read before the peer listing: a
    value written after it (a served receipt resolving a newer peer) then
    fails the refresh's CAS instead of being overwritten from an older
    listing."""
    from apps.lifecycle.models import Vm, VmState

    live = Vm.objects.exclude(state=VmState.DESTROYED)
    return list(live.values_list("pk", "vm_id", "state", "netbird_ip", "netbird_status"))


def refresh_overlay_ips(peers: list[dict[str, Any]], snapshot: OverlaySnapshot) -> int:
    """Point every live VM's `Vm.netbird_ip` at the address its peer holds
    in the `peers` listing, resolved as the public-IP retarget resolves it
    (bound ids first, name only without a binding). Returns the number of
    rows changed.

    The served-receipt self-heal resolves the address ONCE, while the field
    is empty in a VM's first 30 minutes; a guest that re-enrols later (a
    lost NetBird state after a host incident) gets a new peer and a new
    address, and the row kept the dead one for good — the console showed
    it.

    - Open setup keys are bound first, so a re-enrolled guest's new peer is
      found by id (a bound VM is never matched by name).
    - A `pending` row is the §25 verifier's: left alone. A `lost` VM seen
      CONNECTED again is `ok` — the verifier settles only `pending` rows
      and would leave it reading unreachable forever.
    - A peer RECORD gone (a disconnected peer keeps its record; only the
      ephemeral GC or a revoke removes it): NetBird may hand its address to
      another peer — another tenant's VM — so an `active` VM's address is
      cleared and the VM reads `lost`, the same verdict §25 gives a peer
      lost in transit (off the overlay, cannot re-enrol by itself). The
      backend clears its mirror on exactly that pair (`lost`, `""`).
      Never a `migrating` VM, in the CAS too: the §25 dest-activation arms
      its overlay check only for a VM that still has an address, and
      clearing it mid-move would disarm the check that exists for a peer
      lost in transit. Absence must be CONFIRMED: seen on passes at least
      `ABSENCE_CONFIRM` apart (one listing that briefly lacks a peer —
      during a launch's final state read, say — must not fail it), never
      against an empty listing, and never on a pass whose setup-key
      binding failed (a re-enrolled guest's new peer is then invisible to
      the bound-id resolution, not gone).
    """
    from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState

    from . import effects

    vm_ids = [row[1] for row in snapshot]
    bound_ok = True
    try:
        bind_netbird_keys(vm_ids=vm_ids)
    except effects.EffectError as exc:
        bound_ok = False
        log.warning("netbird: binding setup keys failed, using the bindings recorded: %s", exc)
    now = timezone.now()
    bindings = bindings_for(vm_ids)
    index = effects.PeerIndex.of(peers)
    changed = 0
    for pk, vm_id, state, old, status in snapshot:
        if status == VmNetbirdStatus.PENDING:
            cache.delete(_absent_key(pk))
            continue
        binding = bindings[vm_id]
        peer = effects.tenant_peer_from_listing(
            index, vm_id, peer_ids=binding.ranked, bound_owners=binding.owners
        )
        fields: dict[str, Any] = {}
        if peer is None:
            clearable = old and peers and bound_ok and state == VmState.ACTIVE
            if not clearable:
                cache.delete(_absent_key(pk))
            elif _absence_confirmed(pk, old, now):
                fields = {"netbird_ip": "", "netbird_status": VmNetbirdStatus.LOST.value}
        else:
            cache.delete(_absent_key(pk))
            if peer.ip and peer.ip != old:
                fields["netbird_ip"] = peer.ip
            if peer.connected and status == VmNetbirdStatus.LOST:
                fields["netbird_status"] = VmNetbirdStatus.OK.value
        if not fields:
            continue
        # Conditional on the snapshot, the state included: a concurrent
        # writer, a §25 fence (active → migrating) or a §24 tombstone wins.
        if Vm.objects.filter(
            pk=pk, state=state, netbird_ip=old, netbird_status=status
        ).update(**fields):
            changed += 1
            if peer is None:
                cache.delete(_absent_key(pk))
                log.error(
                    "netbird: vm=%s has no NetBird peer any more — overlay address %s "
                    "cleared, vm reads lost (off the overlay; it cannot re-enrol itself)",
                    vm_id,
                    old,
                )
            else:
                log.warning(
                    "netbird: vm=%s overlay %s -> %s%s (peer %s)",
                    vm_id,
                    old or "(none)",
                    fields.get("netbird_ip", old),
                    " — back on the overlay" if "netbird_status" in fields else "",
                    peer.id,
                )
    return changed


def bound_peer_ids(vm_id: str) -> set[str]:
    """Every peer id recorded for `vm_id`: its keys' peers and
    `Vm.netbird_peer_id`."""
    from apps.lifecycle.models import Vm, VmNetbirdKey

    ids = set(
        VmNetbirdKey.objects.filter(vm__vm_id=vm_id)
        .exclude(peer_id="")
        .values_list("peer_id", flat=True)
    )
    ids.update(
        Vm.objects.filter(vm_id=vm_id)
        .exclude(netbird_peer_id="")
        .values_list("netbird_peer_id", flat=True)
    )
    return ids


def _bound_peers(*, destroyed: bool) -> dict[str, str]:
    """`{peer id: vm_id}` over the VMs that are (`destroyed=True`) or are
    not Destroyed."""
    from apps.lifecycle.models import Vm, VmNetbirdKey, VmState

    keys = VmNetbirdKey.objects.exclude(peer_id="")
    vms = Vm.objects.exclude(netbird_peer_id="")
    if destroyed:
        keys = keys.filter(vm__state=VmState.DESTROYED)
        vms = vms.filter(state=VmState.DESTROYED)
    else:
        keys = keys.exclude(vm__state=VmState.DESTROYED)
        vms = vms.exclude(state=VmState.DESTROYED)
    out = dict(keys.values_list("peer_id", "vm__vm_id"))
    out.update(dict(vms.values_list("netbird_peer_id", "vm_id")))
    return out


def live_bound_peer_ids(*, exclude_vm_id: str = "") -> set[str]:
    """Peer ids recorded for a non-Destroyed VM (other than `exclude_vm_id`)
    — peers no name-based sweep may delete for another VM."""
    return {p for p, v in _bound_peers(destroyed=False).items() if v != exclude_vm_id}


def destroyed_bound_peers() -> dict[str, str]:
    """`{peer id: vm_id}` of the peers recorded for Destroyed VMs."""
    return _bound_peers(destroyed=True)


def revoke_unneeded_relaunch_keys(
    peers: list[dict[str, Any]], *, now: datetime | None = None
) -> int:
    """Delete every live relaunch key whose guest is back on its own
    identity. Returns the number of keys deleted.

    A relaunch key is minted for the one case where the guest lost its
    NetBird state and must re-enrol (`launch._netbird_relaunch_needs_no_key`
    could not prove otherwise). Once one of the VM's bound peers is
    CONNECTED and seen after the key was minted, the guest logged in with
    the identity it already held, so the key will never be needed — but it
    sits readable in the guest's cloud-init state until it expires. This
    deletes it at NetBird instead.

    `peers` is the caller's listing, and the caller has just closed the
    open bindings (`refresh_overlay_ips`), so a key that WAS used is bound
    and never matches here. The row's `expires_at` moves to now: the next
    passes skip it, and `bind_netbird_keys` still binds it should a peer
    have enrolled with it in between — the binding is never lost.
    A NetBird failure on one key is logged; the next pass retries it.
    """
    from apps.lifecycle.models import VmNetbirdKey

    from . import effects
    from .netbird_janitor import _parse_last_seen

    now = now or timezone.now()
    keys = list(
        VmNetbirdKey.objects.filter(
            settled_at__isnull=True, persistent=False, peer_id="", expires_at__gt=now
        ).select_related("vm")
    )
    if not keys:
        return 0
    bindings = bindings_for({k.vm.vm_id for k in keys})
    index = effects.PeerIndex.of(peers)
    revoked = 0
    for key in keys:
        back = False
        for peer_id in bindings[key.vm.vm_id].ranked:
            p = index.by_id.get(peer_id)
            if p is None or not p.get("connected"):
                continue
            seen = _parse_last_seen(p.get("last_seen"))
            if seen is not None and seen > key.created_at:
                back = True
                break
        if not back:
            continue
        try:
            effects.delete_netbird_setup_key(
                key.setup_key_id, label="netbird:revoke-relaunch-key"
            )
        except effects.EffectError as exc:
            log.warning(
                "netbird: deleting the unneeded relaunch key %s of vm %s failed: %s",
                key.setup_key_id,
                key.vm.vm_id,
                exc,
            )
            continue
        VmNetbirdKey.objects.filter(pk=key.pk, settled_at__isnull=True).update(expires_at=now)
        revoked += 1
        log.info(
            "netbird: vm %s is back on its own peer — deleted its unneeded relaunch key %s",
            key.vm.vm_id,
            key.setup_key_id,
        )
    return revoked
