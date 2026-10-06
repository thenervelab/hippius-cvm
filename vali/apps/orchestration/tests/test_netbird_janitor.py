"""Tenant NetBird peer janitor (`netbird_janitor.sweep_orphan_tenant_peers`).

Tenant peers are persistent, so a missed §24 revoke would leak a peer
forever. The janitor deletes `hippius-tenant-<vm_id>` peers whose VM is
Destroyed, or has no `Vm` row and has been offline past a grace — and
nothing else.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from django.core.cache import cache
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, netbird_janitor, service
from apps.orchestration.models import LaunchJob, LaunchJobState

from .factories import make_launch_record, make_vm

pytestmark = pytest.mark.django_db

NOW = timezone.now()
LONG_AGO = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
RECENT = (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")


def _peer(peer_id: str, name: str, *, connected: bool = False, last_seen: Any = LONG_AGO) -> dict:
    return {"id": peer_id, "name": name, "connected": connected, "last_seen": last_seen}


class _NetBird:
    def __init__(self, peers: list[dict]) -> None:
        self.peers = peers
        self.lists = 0
        self.deleted: list[str] = []
        self.fail_delete: set[str] = set()
        self.fail_list: Exception | None = None

    def list_peers(self) -> list[dict]:
        self.lists += 1
        if self.fail_list is not None:
            raise self.fail_list
        return list(self.peers)

    def delete(self, peer_id: str, *, label: str) -> None:
        if peer_id in self.fail_delete:
            raise effects.EffectError("netbird: boom")
        self.deleted.append(peer_id)


@pytest.fixture
def nb(monkeypatch: pytest.MonkeyPatch, settings: Any) -> _NetBird:
    settings.VALI_NETBIRD_API_TOKEN = "nbp_test"
    settings.VALI_NETBIRD_PEER_JANITOR_ENABLED = True
    settings.VALI_NETBIRD_PEER_JANITOR_DRY_RUN = False
    settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = 50
    settings.VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S = 3600
    settings.VALI_NETBIRD_PEER_JANITOR_INTERVAL_S = 300
    settings.VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER = True
    fake = _NetBird([])
    monkeypatch.setattr(effects, "list_netbird_peers", fake.list_peers)
    monkeypatch.setattr(effects, "delete_netbird_peer", fake.delete)
    return fake


def _sweep(now: datetime = NOW) -> int:
    return netbird_janitor.sweep_orphan_tenant_peers(now=now)


# ─── what is deleted ─────────────────────────────────────────────────


def test_deletes_every_peer_of_a_destroyed_vm_connected_or_not(nb: _NetBird) -> None:
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [
        _peer("p1", "hippius-tenant-vm-dead"),
        _peer("p2", "hippius-tenant-vm-dead", connected=True, last_seen=RECENT),
    ]
    assert _sweep() == 2
    assert nb.deleted == ["p1", "p2"]


def test_deletes_a_rowless_peer_offline_past_the_grace(nb: _NetBird) -> None:
    nb.peers = [_peer("p1", "hippius-tenant-vm-ghost", last_seen=LONG_AGO)]
    assert _sweep() == 1
    assert nb.deleted == ["p1"]


# ─── what is never deleted ───────────────────────────────────────────


@pytest.mark.parametrize(
    "state", [VmState.ACTIVE, VmState.MIGRATING, VmState.DECOMMISSIONING]
)
def test_never_touches_a_live_vms_peers_duplicates_included(nb: _NetBird, state: str) -> None:
    # A peer's name is the hostname the guest sends, so a tenant can name
    # a peer after ANOTHER VM: de-duplicating a live VM would let it get
    # the victim's own peer deleted.
    vm = make_vm("vm-live", state=VmState.ACTIVE)
    extra: dict[str, Any] = {}
    if state == VmState.MIGRATING:
        extra = {"migration_dest": "node-dst", "new_generation": 6}
    Vm.objects.filter(id=vm.id).update(state=state, **extra)
    nb.peers = [
        _peer("p1", "hippius-tenant-vm-live"),
        _peer("p2", "hippius-tenant-vm-live", connected=True, last_seen=RECENT),
    ]
    assert _sweep() == 0
    assert nb.deleted == []


def test_never_touches_a_non_tenant_peer(nb: _NetBird) -> None:
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [
        _peer("e1", "hippius-pip-gw-edge-a"),
        _peer("e2", "edge-a"),
        _peer("m1", "miner-a"),
        # the bare prefix (an old truncated-hostname enrolment) has no vm_id
        _peer("t0", "hippius-tenant"),
        _peer("t1", "hippius-tenant-"),
        # the prefix must lead the name
        _peer("x1", "x-hippius-tenant-vm-dead"),
        _peer("x2", "Hippius-tenant-vm-dead"),
        {"id": "n1", "connected": False, "last_seen": LONG_AGO},
    ]
    assert _sweep() == 0
    assert nb.deleted == []


def test_a_rowless_peer_that_is_connected_is_kept(nb: _NetBird) -> None:
    nb.peers = [_peer("p1", "hippius-tenant-vm-ghost", connected=True, last_seen=LONG_AGO)]
    assert _sweep() == 0


def test_a_rowless_peer_inside_the_grace_is_kept(nb: _NetBird) -> None:
    nb.peers = [_peer("p1", "hippius-tenant-vm-ghost", last_seen=RECENT)]
    assert _sweep() == 0


@pytest.mark.parametrize(
    "last_seen", [None, "", "not-a-date", "0001-01-01T00:00:00Z", "2026-01-01T00:00:00", 42]
)
def test_a_rowless_peer_with_an_unknown_last_seen_is_kept(nb: _NetBird, last_seen: Any) -> None:
    nb.peers = [_peer("p1", "hippius-tenant-vm-ghost", last_seen=last_seen)]
    assert _sweep() == 0


def test_a_rowless_peer_whose_launch_is_in_flight_is_kept(nb: _NetBird) -> None:
    job = make_launch_record(SimpleNamespace(vm_id="vm-launching"))  # type: ignore[arg-type]
    LaunchJob.objects.filter(id=job.id).update(
        state=LaunchJobState.RUNNING.value, finished_at=None
    )
    nb.peers = [_peer("p1", "hippius-tenant-vm-launching", last_seen=LONG_AGO)]
    assert _sweep() == 0


def test_a_rowless_peer_whose_launch_finished_is_collected(nb: _NetBird) -> None:
    make_launch_record(SimpleNamespace(vm_id="vm-failed"))  # type: ignore[arg-type]
    nb.peers = [_peer("p1", "hippius-tenant-vm-failed", last_seen=LONG_AGO)]
    assert _sweep() == 1


# ─── safety rails ────────────────────────────────────────────────────


def test_deletions_are_capped_per_pass(nb: _NetBird, settings: Any) -> None:
    settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = 2
    for i in range(5):
        make_vm(f"vm-d{i}", state=VmState.DESTROYED)
    nb.peers = [_peer(f"p{i}", f"hippius-tenant-vm-d{i}") for i in range(5)]
    assert _sweep() == 2
    assert nb.deleted == ["p0", "p1"]


def test_dry_run_deletes_nothing_and_logs(
    nb: _NetBird, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings.VALI_NETBIRD_PEER_JANITOR_DRY_RUN = True
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [_peer("p1", "hippius-tenant-vm-dead")]
    lines: list[str] = []
    monkeypatch.setattr(
        netbird_janitor.log, "warning", lambda msg, *args: lines.append(msg % args)
    )
    assert _sweep() == 0
    assert nb.deleted == []
    assert any("WOULD delete peer p1 of vm vm-dead" in line for line in lines)


def test_the_kill_switch_stops_the_janitor_before_it_lists(nb: _NetBird, settings: Any) -> None:
    settings.VALI_NETBIRD_PEER_JANITOR_ENABLED = False
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [_peer("p1", "hippius-tenant-vm-dead")]
    assert _sweep() == 0
    assert nb.lists == 0


def test_no_netbird_token_means_no_pass(nb: _NetBird, settings: Any) -> None:
    settings.VALI_NETBIRD_API_TOKEN = ""
    assert _sweep() == 0
    assert nb.lists == 0


def test_one_pass_per_interval(nb: _NetBird) -> None:
    _sweep()
    _sweep()
    assert nb.lists == 1


def test_a_listing_failure_is_logged_not_raised(nb: _NetBird) -> None:
    nb.fail_list = effects.EffectUnavailable("netbird down")
    assert _sweep() == 0


def test_one_failed_delete_does_not_stop_the_others(nb: _NetBird) -> None:
    make_vm("vm-a", state=VmState.DESTROYED)
    make_vm("vm-b", state=VmState.DESTROYED)
    nb.peers = [_peer("pa", "hippius-tenant-vm-a"), _peer("pb", "hippius-tenant-vm-b")]
    nb.fail_delete.add("pa")
    assert _sweep() == 1
    assert nb.deleted == ["pb"]


def test_the_cap_counts_deletions_not_failed_attempts(nb: _NetBird, settings: Any) -> None:
    settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = 2
    for i in range(4):
        make_vm(f"vm-d{i}", state=VmState.DESTROYED)
    nb.peers = [_peer(f"p{i}", f"hippius-tenant-vm-d{i}") for i in range(4)]
    nb.fail_delete |= {"p0", "p1"}
    assert _sweep() == 2
    assert nb.deleted == ["p2", "p3"]


def test_peers_that_keep_failing_go_to_the_back_of_the_queue(
    nb: _NetBird, settings: Any
) -> None:
    # Cap 1 ⇒ 2 attempts per pass: two always-failing peers ahead of the
    # rest would otherwise starve them forever.
    settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = 1
    for i in range(4):
        make_vm(f"vm-d{i}", state=VmState.DESTROYED)
    nb.peers = [_peer(f"p{i}", f"hippius-tenant-vm-d{i}") for i in range(4)]
    nb.fail_delete |= {"p0", "p1"}
    assert _sweep() == 0
    cache.delete(netbird_janitor._THROTTLE_KEY)
    assert _sweep() == 1
    assert nb.deleted == ["p2"]


# ─── names are claims, not proof ─────────────────────────────────────


def test_a_live_vms_suffixed_name_is_never_read_as_an_orphan(nb: _NetBird) -> None:
    # A custom template (`hippius-tenant-{vm_id}-x`) or a NetBird clash
    # suffix: the remainder has no row, but it could be the live VM's peer.
    make_vm("vm-live", state=VmState.ACTIVE)
    nb.peers = [
        _peer("p1", "hippius-tenant-vm-live-x"),
        _peer("p2", "hippius-tenant-vm-live-181-159"),
    ]
    assert _sweep() == 0


def test_a_truncated_name_of_a_live_vm_is_kept(nb: _NetBird) -> None:
    make_vm("vm-longname", state=VmState.ACTIVE)
    nb.peers = [_peer("p1", "hippius-tenant-vm-long")]
    assert _sweep() == 0


def test_a_destroyed_vms_clash_renamed_peer_is_deleted(nb: _NetBird) -> None:
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [_peer("p1", "hippius-tenant-vm-dead-181-159", connected=True)]
    assert _sweep() == 1


def test_a_live_vm_id_prefix_needs_a_separator_to_shadow(nb: _NetBird) -> None:
    # `vm-1` alive must not protect the peer of a destroyed `vm-12`.
    make_vm("vm-1", state=VmState.ACTIVE)
    make_vm("vm-12", state=VmState.DESTROYED)
    nb.peers = [_peer("p1", "hippius-tenant-vm-12")]
    assert _sweep() == 1


def test_an_ambiguous_name_is_kept(nb: _NetBird) -> None:
    # Destroyed `a-1-2`, or live `a` renamed on a clash — cannot tell.
    make_vm("a", state=VmState.ACTIVE)
    make_vm("a-1-2", state=VmState.DESTROYED)
    nb.peers = [_peer("p1", "hippius-tenant-a-1-2")]
    assert _sweep() == 0


def test_without_sole_ownership_only_destroyed_vms_peers_go(
    nb: _NetBird, settings: Any
) -> None:
    # Another vali on the account: its VMs have no row HERE.
    settings.VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER = False
    make_vm("vm-dead", state=VmState.DESTROYED)
    nb.peers = [
        _peer("p1", "hippius-tenant-vm-ghost", last_seen=LONG_AGO),
        _peer("p2", "hippius-tenant-vm-dead"),
    ]
    assert _sweep() == 1
    assert nb.deleted == ["p2"]


# ─── wiring ──────────────────────────────────────────────────────────


def test_the_orchestration_tick_runs_the_janitor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(netbird_janitor, "sweep_orphan_tenant_peers", lambda: 3)
    assert service.tick_once().netbird_orphan_peers_deleted == 3


def test_a_janitor_crash_never_breaks_the_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> int:
        raise RuntimeError("bug")

    monkeypatch.setattr(netbird_janitor, "sweep_orphan_tenant_peers", boom)
    assert service.tick_once().netbird_orphan_peers_deleted == 0

