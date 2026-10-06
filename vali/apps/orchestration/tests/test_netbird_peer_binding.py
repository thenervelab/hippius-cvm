"""A tenant peer is bound to its VM by the setup key it enrolled with.

A peer's name is the hostname its guest sends — tenant userdata, a claim.
NetBird's audit log records which setup key each peer registered with
(`peer.setupkey.add`: initiator = key id, target = peer id), and vali
records every key it mints (`VmNetbirdKey`). So a VM's peer is found,
revoked and janitored by id, whatever it calls itself.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.lifecycle.models import Vm, VmNetbirdKey, VmState
from apps.orchestration import effects, netbird_binding, netbird_janitor

from .factories import make_vm

pytestmark = pytest.mark.django_db

# The suite's autouse `FakeEffects` patches these module attributes; the
# real ones are captured at import.
_real_revoke = effects.revoke_netbird
_real_resolve = effects.resolve_netbird_peer
_real_resolve_ip = effects.resolve_netbird_peer_ip

NOW = timezone.now()
LONG_AGO = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")


def _key(
    vm: Vm,
    key_id: str,
    *,
    peer_id: str = "",
    settled: bool = False,
    expires_in: timedelta = timedelta(hours=1),
    persistent: bool = True,
) -> VmNetbirdKey:
    return VmNetbirdKey.objects.create(
        vm=vm,
        setup_key_id=key_id,
        persistent=persistent,
        expires_at=NOW + expires_in,
        peer_id=peer_id,
        settled_at=NOW if settled or peer_id else None,
    )


def _enrolled(key_id: str, peer_id: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": str(len(key_id)),
        "activity_code": "peer.setupkey.add",
        "initiator_id": key_id,
        "target_id": peer_id,
        "meta": {"setup_key_name": "anything"},
        **extra,
    }


class _Resp:
    def __init__(self, body: Any) -> None:
        self.status = 200
        self._body = json.dumps(body).encode() if body is not None else b""

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _NetBirdApi:
    """`urllib.request.urlopen` double for the NetBird management API."""

    def __init__(self) -> None:
        self.peers: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.status: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, request: urllib.request.Request, timeout: float, **_kw: object) -> _Resp:
        method = request.get_method()
        path = request.full_url.removeprefix("https://nb.test")
        self.calls.append((method, path))
        status = self.status.get(path, 200)
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, "x", {}, io.BytesIO())
        if method == "GET" and path == "/api/peers":
            return _Resp(self.peers)
        if method == "GET" and path in ("/api/events/audit", "/api/events"):
            return _Resp(self.events)
        return _Resp(None)

    @property
    def deleted(self) -> list[str]:
        return [p.removeprefix("/api/peers/") for m, p in self.calls if m == "DELETE"]

    def reads(self, path: str) -> int:
        return sum(1 for m, p in self.calls if m == "GET" and p == path)


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> _NetBirdApi:
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_BASE", "https://nb.test")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "nbp_test")
    fake = _NetBirdApi()
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return fake


# ─── the audit-log reader ────────────────────────────────────────────


def test_enrolments_pair_each_setup_key_with_the_peer_that_used_it(api: _NetBirdApi) -> None:
    api.events = [
        _enrolled("sk-new", "cpeer2"),
        {"activity_code": "peer.user.add", "initiator_id": "sk-user", "target_id": "cx"},
        {"activity_code": "setupkey.add", "initiator_id": "u1", "target_id": "sk-new"},
        _enrolled("sk-old", "cpeer1"),
        _enrolled("sk-evil", "../../api/users"),  # never a URL path segment
        "not-an-object",
    ]

    assert effects.list_netbird_setup_key_enrolments() == {
        "sk-new": "cpeer2",
        "sk-old": "cpeer1",
    }
    assert api.calls == [("GET", "/api/events/audit")]


def test_enrolments_keep_the_newest_peer_of_a_reused_key(api: _NetBirdApi) -> None:
    # The server lists newest first.
    api.events = [_enrolled("sk-1", "cnewer"), _enrolled("sk-1", "colder")]
    assert effects.list_netbird_setup_key_enrolments() == {"sk-1": "cnewer"}


def test_enrolments_fall_back_to_the_pre_audit_path(api: _NetBirdApi) -> None:
    api.status["/api/events/audit"] = 404
    api.events = [_enrolled("sk-1", "cpeer")]

    assert effects.list_netbird_setup_key_enrolments() == {"sk-1": "cpeer"}
    assert api.calls == [("GET", "/api/events/audit"), ("GET", "/api/events")]


def test_enrolments_raise_when_the_log_cannot_be_read(api: _NetBirdApi) -> None:
    api.status["/api/events/audit"] = 403
    with pytest.raises(effects.EffectError, match="HTTP 403"):
        effects.list_netbird_setup_key_enrolments()


# ─── binding ─────────────────────────────────────────────────────────


def test_bind_records_the_peer_and_points_the_vm_at_its_newest_key(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    old = _key(vm, "sk-old")
    new = _key(vm, "sk-new")
    # Explicit: `created_at` is wall-clock, `NOW` is fixed at import.
    VmNetbirdKey.objects.filter(pk=old.pk).update(created_at=NOW)
    VmNetbirdKey.objects.filter(pk=new.pk).update(created_at=NOW + timedelta(minutes=1))
    api.events = [_enrolled("sk-new", "cnew"), _enrolled("sk-old", "cold")]

    assert netbird_binding.bind_netbird_keys(vm_ids=["vm-1"], now=NOW) == 2

    old.refresh_from_db()
    new.refresh_from_db()
    assert (old.peer_id, new.peer_id) == ("cold", "cnew")
    assert old.settled_at is not None and new.settled_at is not None
    vm.refresh_from_db()
    assert vm.netbird_peer_id == "cnew"


def test_bind_makes_no_call_without_an_open_key(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-done", peer_id="cpeer")
    _key(make_vm("vm-2"), "sk-other")  # open, but not asked for

    assert netbird_binding.bind_netbird_keys(vm_ids=["vm-1"], now=NOW) == 0
    assert api.calls == []


def test_an_unused_key_settles_only_once_it_is_past_expiry(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    live = _key(vm, "sk-live", expires_in=timedelta(minutes=30))
    just_expired = _key(vm, "sk-just", expires_in=-timedelta(minutes=1))
    long_expired = _key(vm, "sk-long", expires_in=-netbird_binding.SETTLE_GRACE)

    netbird_binding.bind_netbird_keys(now=NOW)

    for key in (live, just_expired, long_expired):
        key.refresh_from_db()
    assert live.settled_at is None
    assert just_expired.settled_at is None  # clock-skew grace
    assert long_expired.settled_at == NOW and long_expired.peer_id == ""
    vm.refresh_from_db()
    assert vm.netbird_peer_id == ""


@pytest.fixture
def bindlog(caplog: pytest.LogCaptureFixture):
    """`caplog` for `apps.orchestration.netbird_binding` (the project's
    `LOGGING` stops `apps.*` from propagating to the root logger)."""
    import logging

    logger = logging.getLogger("apps.orchestration.netbird_binding")
    logger.addHandler(caplog.handler)
    caplog.set_level(logging.INFO, logger="apps.orchestration.netbird_binding")
    yield caplog
    logger.removeHandler(caplog.handler)


def test_a_first_launch_key_expiring_unbound_is_a_warning(
    api: _NetBirdApi, bindlog: pytest.LogCaptureFixture
) -> None:
    # An audit log that is off / unreadable to the token / truncated shows
    # up as first-launch keys settling unbound — which must not be silent.
    _key(make_vm("vm-a"), "sk-a", expires_in=-timedelta(hours=1))
    _key(make_vm("vm-b"), "sk-b", expires_in=-timedelta(hours=1), persistent=False)

    netbird_binding.bind_netbird_keys(now=NOW)

    warnings = [r for r in bindlog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "vm-a" in warnings[0].getMessage() and "vm-b" not in warnings[0].getMessage()
    # Settled keys are not reported again.
    bindlog.clear()
    netbird_binding.bind_netbird_keys(now=NOW)
    assert bindlog.records == []


def test_a_key_another_pass_settled_meanwhile_is_not_reported_again(
    monkeypatch: pytest.MonkeyPatch, bindlog: pytest.LogCaptureFixture
) -> None:
    # Two binders race (janitor pass + a revoke): only the one whose update
    # actually settled the key reports it.
    key = _key(make_vm("vm-a"), "sk-a", expires_in=-timedelta(hours=1))

    def _log_read_while_another_pass_settles() -> dict[str, str]:
        VmNetbirdKey.objects.filter(pk=key.pk).update(settled_at=NOW)
        return {}

    monkeypatch.setattr(
        effects, "list_netbird_setup_key_enrolments", _log_read_while_another_pass_settles
    )

    netbird_binding.bind_netbird_keys(now=NOW)

    assert bindlog.records == []


def test_a_failed_log_read_settles_nothing(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    key = _key(vm, "sk-1", expires_in=-timedelta(hours=2))
    api.status["/api/events/audit"] = 500

    with pytest.raises(effects.EffectError):
        netbird_binding.bind_netbird_keys(now=NOW)
    key.refresh_from_db()
    assert key.settled_at is None


# ─── resolving ───────────────────────────────────────────────────────


def test_a_recorded_peer_is_found_by_id_not_by_name(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    Vm.objects.filter(pk=vm.pk).update(netbird_peer_id="cmine")
    api.peers = [
        # A newer, connected peer under the VM's name — stale / an impostor.
        {"id": "cname", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9", "connected": True},
        {"id": "cmine", "name": "laptop", "ip": "100.64.0.1", "connected": False},
    ]

    peer = _real_resolve("vm-1")

    assert peer is not None
    assert (peer.id, peer.ip, peer.connected) == ("cmine", "100.64.0.1", False)
    assert _real_resolve_ip("vm-1") == "100.64.0.1"


def test_a_recorded_peer_that_is_gone_is_not_replaced_by_a_name_match(
    api: _NetBirdApi,
) -> None:
    vm = make_vm("vm-1")
    Vm.objects.filter(pk=vm.pk).update(netbird_peer_id="cgone")
    api.peers = [{"id": "cname", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9"}]

    assert _real_resolve("vm-1") is None
    assert api.reads("/api/events/audit") == 0  # no open key ⇒ no log read


def test_a_gone_recorded_peer_follows_a_newer_bound_key(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-first", peer_id="cgone")
    first = VmNetbirdKey.objects.get(setup_key_id="sk-first")
    fresh = _key(vm, "sk-relaunch", persistent=False)
    VmNetbirdKey.objects.filter(pk=first.pk).update(created_at=NOW)
    VmNetbirdKey.objects.filter(pk=fresh.pk).update(created_at=NOW + timedelta(minutes=1))
    Vm.objects.filter(pk=vm.pk).update(netbird_peer_id="cgone")
    api.peers = [{"id": "cfresh", "name": "anything", "ip": "100.64.0.7", "connected": True}]
    api.events = [_enrolled("sk-relaunch", "cfresh")]

    peer = _real_resolve("vm-1")

    assert peer is not None and peer.id == "cfresh"
    # The first-launch key's peer stays the primary binding; the relaunch
    # key's peer is only what resolves while that one is gone.
    vm.refresh_from_db()
    assert vm.netbird_peer_id == "cgone"


def test_a_relaunch_key_peer_never_displaces_the_first_launch_peer(
    api: _NetBirdApi,
) -> None:
    # A tenant enrols an outside machine with an (unused) relaunch key. The
    # VM's real, persistent peer must stay its peer — binding and resolution
    # — and the outside peer is still revoked with the VM.
    vm = make_vm("vm-1")
    first = _key(vm, "sk-first")
    relaunch = _key(vm, "sk-relaunch", persistent=False)
    VmNetbirdKey.objects.filter(pk=first.pk).update(created_at=NOW)
    VmNetbirdKey.objects.filter(pk=relaunch.pk).update(created_at=NOW + timedelta(days=1))
    api.events = [_enrolled("sk-relaunch", "coutside"), _enrolled("sk-first", "creal")]
    api.peers = [
        {"id": "coutside", "name": "hippius-tenant-vm-1", "ip": "100.64.0.8", "connected": True},
        {"id": "creal", "name": "hippius-tenant-vm-1", "ip": "100.64.0.1", "connected": True},
    ]

    netbird_binding.bind_netbird_keys(vm_ids=["vm-1"], now=NOW)

    vm.refresh_from_db()
    assert vm.netbird_peer_id == "creal"
    peer = _real_resolve("vm-1")
    assert peer is not None and peer.id == "creal"
    assert netbird_binding.bindings_for(["vm-1"])["vm-1"].ranked == ("creal", "coutside")

    _real_revoke(vm)
    assert sorted(api.deleted) == ["coutside", "creal"]


def test_a_connected_relaunch_peer_wins_over_a_disconnected_first_launch_peer(
    api: _NetBirdApi,
) -> None:
    # The guest lost its NetBird state and re-enrolled with the relaunch key.
    # Its first peer is persistent, so it is never GC'd and still "exists" —
    # disconnected. Pinning it would aim the overlay IP (and the public IP)
    # at a dead address.
    vm = make_vm("vm-1")
    _key(vm, "sk-first", peer_id="cdead")
    _key(vm, "sk-relaunch", peer_id="clive", persistent=False)
    api.peers = [
        {"id": "cdead", "name": "hippius-tenant-vm-1", "ip": "100.64.0.1", "connected": False},
        {"id": "clive", "name": "hippius-tenant-vm-1", "ip": "100.64.0.2", "connected": True},
    ]

    peer = _real_resolve("vm-1")

    assert peer is not None and (peer.id, peer.ip) == ("clive", "100.64.0.2")


def test_both_bound_peers_offline_resolves_to_the_first_launch_peer(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    first = _key(vm, "sk-first", peer_id="cfirst")
    relaunch = _key(vm, "sk-relaunch", peer_id="crelaunch", persistent=False)
    VmNetbirdKey.objects.filter(pk=first.pk).update(created_at=NOW)
    VmNetbirdKey.objects.filter(pk=relaunch.pk).update(created_at=NOW + timedelta(days=1))
    api.peers = [
        {"id": "crelaunch", "name": "x", "ip": "100.64.0.2", "connected": False},
        {"id": "cfirst", "name": "y", "ip": "100.64.0.1", "connected": False},
    ]

    peer = _real_resolve("vm-1")

    assert peer is not None and peer.id == "cfirst"


def test_the_name_fallback_never_matches_a_peer_bound_to_another_vm(
    api: _NetBirdApi,
) -> None:
    # vm-1 has no binding (legacy / not bound yet). vm-2's guest enrolled
    # under vm-1's name: it must not become vm-1's peer.
    make_vm("vm-1")
    _key(make_vm("vm-2"), "sk-2", peer_id="cother")
    api.peers = [{"id": "cother", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9"}]

    assert _real_resolve("vm-1") is None

    api.peers.append({"id": "cmine", "name": "hippius-tenant-vm-1", "ip": "100.64.0.2"})
    peer = _real_resolve("vm-1")
    assert peer is not None and peer.id == "cmine"


def test_the_resolver_binds_an_open_key_when_nothing_matches(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1")
    api.events = [_enrolled("sk-1", "cnew")]
    api.peers = [{"id": "cnew", "name": "renamed", "ip": "100.64.0.3", "connected": True}]

    peer = _real_resolve("vm-1")

    assert peer is not None and peer.id == "cnew"


def test_a_resolver_bind_failure_with_nothing_found_is_raised_not_none(
    api: _NetBirdApi,
) -> None:
    # `None` means "the peer is gone" — the §25 verify settles that `lost`
    # for good. An unreadable binding that might name the guest's peer is an
    # outage, never absence.
    vm = make_vm("vm-1")
    _key(vm, "sk-1")
    api.status["/api/events/audit"] = 403

    with pytest.raises(effects.EffectError, match="HTTP 403"):
        _real_resolve("vm-1")


def test_a_resolver_bind_failure_still_returns_what_it_found(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-open")
    _key(vm, "sk-done", peer_id="cbound")
    api.status["/api/events/audit"] = 500
    api.peers = [{"id": "cbound", "name": "x", "ip": "100.64.0.4", "connected": True}]

    peer = _real_resolve("vm-1")

    assert peer is not None and peer.id == "cbound"


def test_a_resolver_bind_failure_with_only_a_disconnected_peer_is_raised(
    api: _NetBirdApi,
) -> None:
    # The guest may have re-enrolled as a peer only the unread binding
    # names; its old peer, disconnected, is no answer.
    vm = make_vm("vm-1")
    _key(vm, "sk-open")
    _key(vm, "sk-done", peer_id="cbound")
    api.status["/api/events/audit"] = 500
    api.peers = [{"id": "cbound", "name": "x", "ip": "100.64.0.4", "connected": False}]

    with pytest.raises(effects.EffectError):
        _real_resolve("vm-1")


def test_a_destroyed_vms_bound_peer_is_never_another_vms_by_name(api: _NetBirdApi) -> None:
    # vm-A was destroyed but its bound peer (named after vm-B) survived a
    # failed revoke; vm-B, unbound, must not name-match it.
    gone = make_vm("vm-a")
    _key(gone, "sk-a", peer_id="cgone")
    Vm.objects.filter(pk=gone.pk).update(state=VmState.DESTROYED)
    make_vm("vm-b")
    api.peers = [{"id": "cgone", "name": "hippius-tenant-vm-b", "ip": "100.64.0.9"}]

    assert _real_resolve("vm-b") is None


def test_the_resolver_binds_before_it_trusts_a_name(api: _NetBirdApi) -> None:
    # The guest enrolled under another name; a peer claims the VM's name.
    # The open key is bound first, so the claim never wins.
    vm = make_vm("vm-1")
    _key(vm, "sk-1")
    api.events = [_enrolled("sk-1", "cmine")]
    api.peers = [
        {"id": "cclaim", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9", "connected": True},
        {"id": "cmine", "name": "other", "ip": "100.64.0.1", "connected": True},
    ]

    peer = _real_resolve("vm-1")

    assert peer is not None and peer.id == "cmine"


def test_a_resolve_reads_the_audit_log_at_most_once(api: _NetBirdApi) -> None:
    # A not-yet-enrolled VM (open key, no peer) resolves on every receipt.
    vm = make_vm("vm-1")
    _key(vm, "sk-1")

    assert _real_resolve_ip("vm-1") is None
    assert api.reads("/api/events/audit") == 1


def test_a_destroyed_vms_peers_are_owned_but_never_ranked() -> None:
    dead = make_vm("vm-dead", state=VmState.DESTROYED)
    _key(dead, "sk-dead", peer_id="cdead")
    Vm.objects.filter(pk=dead.pk).update(netbird_peer_id="cdead")
    live = make_vm("vm-live")
    _key(live, "sk-live", peer_id="clive")

    bindings = netbird_binding.bindings_for(["vm-live", "vm-dead"])

    # Still OWNED (no other VM's name fallback may take it), never RANKED.
    assert dict(bindings["vm-live"].owners) == {"clive": "vm-live", "cdead": "vm-dead"}
    assert bindings["vm-dead"].ranked == ()
    # One owners map for the whole call, however many VMs it covers.
    assert bindings["vm-live"].owners is bindings["vm-dead"].owners


def test_a_vm_without_a_recorded_peer_is_still_found_by_name(api: _NetBirdApi) -> None:
    make_vm("vm-1")
    api.peers = [{"id": "cname", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9"}]

    peer = _real_resolve("vm-1")
    assert peer is not None and peer.id == "cname"


def test_listing_lookup_with_a_peer_id_never_falls_back_to_the_name() -> None:
    peers = [
        {"id": "cname", "name": "hippius-tenant-vm-1", "ip": "100.64.0.9"},
        {"id": "c2", "name": "x", "ip": "100.64.0.2"},
    ]
    assert effects.tenant_peer_from_listing(peers, "vm-1", peer_ids=("cother",)) is None
    peer = effects.tenant_peer_from_listing(peers, "vm-1", peer_ids=("cgone", "c2", "cname"))
    assert peer is not None and peer.id == "c2"  # the first that still exists
    peers[0]["connected"] = True
    peer = effects.tenant_peer_from_listing(peers, "vm-1", peer_ids=("cgone", "c2", "cname"))
    assert peer is not None and peer.id == "cname"  # a connected one first
    owned = {"cname": "vm-2"}
    assert effects.tenant_peer_from_listing(peers, "vm-1", bound_owners=owned) is None
    own = {"cname": "vm-1"}
    peer = effects.tenant_peer_from_listing(peers, "vm-1", bound_owners=own)
    assert peer is not None and peer.id == "cname"


# ─── §24 revoke ──────────────────────────────────────────────────────


def test_revoke_deletes_the_recorded_peer_whatever_its_name(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1", peer_id="cbound")
    Vm.objects.filter(pk=vm.pk).update(netbird_peer_id="cbound")
    api.peers = [
        {"id": "cbound", "name": "totally-not-a-tenant"},
        {"id": "cname", "name": "hippius-tenant-vm-1"},
    ]

    _real_revoke(vm)

    assert api.deleted == ["cbound", "cname"]
    # By id first, before the listing the name sweep needs.
    assert api.calls.index(("DELETE", "/api/peers/cbound")) < api.calls.index(
        ("GET", "/api/peers")
    )


def test_revoke_deletes_a_recorded_peer_under_the_vms_name_once(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1", peer_id="cmine")
    api.peers = [{"id": "cmine", "name": "hippius-tenant-vm-1"}]

    _real_revoke(vm)

    assert api.deleted == ["cmine"]


def test_revoke_binds_an_open_key_before_revoking(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1")
    api.events = [_enrolled("sk-1", "cunnamed")]
    api.peers = [{"id": "cunnamed", "name": "evil"}]

    _real_revoke(vm)

    assert api.deleted == ["cunnamed"]


def test_revoke_treats_an_already_deleted_recorded_peer_as_revoked(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1", peer_id="cgone")
    api.status["/api/peers/cgone"] = 404

    _real_revoke(vm)  # no raise

    assert api.deleted == ["cgone"]


def test_revoke_raises_when_the_recorded_peer_delete_fails(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-1", peer_id="cstuck")
    api.status["/api/peers/cstuck"] = 500

    with pytest.raises(effects.EffectError, match="HTTP 500"):
        _real_revoke(vm)


def test_revoke_goes_on_by_name_when_the_log_cannot_be_read(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    _key(vm, "sk-open")
    _key(vm, "sk-done", peer_id="cbound")
    api.status["/api/events/audit"] = 403
    api.peers = [{"id": "cname", "name": "hippius-tenant-vm-1"}]

    _real_revoke(vm)

    assert api.deleted == ["cbound", "cname"]


def test_revoke_by_name_spares_a_peer_bound_to_another_live_vm(api: _NetBirdApi) -> None:
    vm = make_vm("vm-1")
    other = make_vm("vm-2")
    _key(other, "sk-2", peer_id="cother")
    # vm-2's guest enrolled under vm-1's name.
    api.peers = [{"id": "cother", "name": "hippius-tenant-vm-1"}]

    _real_revoke(vm)

    assert api.deleted == []


# ─── the janitor ─────────────────────────────────────────────────────


@pytest.fixture
def janitor(settings: Any, api: _NetBirdApi) -> _NetBirdApi:
    settings.VALI_NETBIRD_PEER_JANITOR_ENABLED = True
    settings.VALI_NETBIRD_PEER_JANITOR_DRY_RUN = False
    settings.VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = 50
    settings.VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S = 3600
    settings.VALI_NETBIRD_PEER_JANITOR_INTERVAL_S = 300
    settings.VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER = True
    cache.clear()
    return api


def test_janitor_deletes_a_destroyed_vms_bound_peer_under_any_name(
    janitor: _NetBirdApi,
) -> None:
    vm = make_vm("vm-dead", state=VmState.DESTROYED)
    _key(vm, "sk-1", peer_id="cbound")
    janitor.peers = [
        {"id": "cbound", "name": "my-laptop", "connected": True, "last_seen": LONG_AGO},
        {"id": "cinfra", "name": "edge-a", "connected": False, "last_seen": LONG_AGO},
    ]

    assert netbird_janitor.sweep_orphan_tenant_peers(now=NOW) == 1
    assert janitor.deleted == ["cbound"]


def test_janitor_binds_open_keys_before_it_selects(janitor: _NetBirdApi) -> None:
    vm = make_vm("vm-dead", state=VmState.DESTROYED)
    _key(vm, "sk-1")
    janitor.events = [_enrolled("sk-1", "cunnamed")]
    janitor.peers = [{"id": "cunnamed", "name": "stray", "last_seen": LONG_AGO}]

    assert netbird_janitor.sweep_orphan_tenant_peers(now=NOW) == 1
    assert janitor.deleted == ["cunnamed"]


def test_janitor_spares_a_live_vms_bound_peer_named_for_a_destroyed_vm(
    janitor: _NetBirdApi,
) -> None:
    make_vm("vm-dead", state=VmState.DESTROYED)
    live = make_vm("vm-live")
    _key(live, "sk-live", peer_id="clive")
    janitor.peers = [{"id": "clive", "name": "hippius-tenant-vm-dead", "last_seen": LONG_AGO}]

    assert netbird_janitor.sweep_orphan_tenant_peers(now=NOW) == 0
    assert janitor.deleted == []


def test_janitor_goes_on_when_the_log_cannot_be_read(janitor: _NetBirdApi) -> None:
    vm = make_vm("vm-dead", state=VmState.DESTROYED)
    _key(vm, "sk-open")
    _key(vm, "sk-done", peer_id="cbound")
    janitor.status["/api/events/audit"] = 500
    janitor.peers = [{"id": "cbound", "name": "stray", "last_seen": LONG_AGO}]

    assert netbird_janitor.sweep_orphan_tenant_peers(now=NOW) == 1
    assert janitor.deleted == ["cbound"]


# ─── the displayed overlay address follows the peer ──────────────────


def _peer(peer_id: str, name: str, ip: str, *, connected: bool = True) -> dict[str, Any]:
    return {"id": peer_id, "name": name, "ip": ip, "connected": connected}


def test_a_re_enrolled_guest_moves_the_displayed_address() -> None:
    """09-21: a host incident cost two guests their NetBird state; they
    re-enrolled with new peers and addresses, and the rows kept the dead
    ones — the one-shot served-receipt resolve never runs again."""
    vm = make_vm("vm-moved")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.171.93")
    peers = [_peer("p-new", "hippius-tenant-vm-moved", "100.64.108.2")]

    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 1
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.108.2"
    again = netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    assert again == 0, "idempotent"


def test_a_bound_peer_wins_over_a_name_claim() -> None:
    vm = make_vm("vm-bound")
    _key(vm, "k1", peer_id="p-own")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.100.1")
    peers = [
        _peer("p-own", "whatever-the-guest-sent", "100.64.100.2"),
        _peer("p-squat", "hippius-tenant-vm-bound", "100.64.100.3"),
    ]
    netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.100.2"


@pytest.fixture
def _fresh_cache():
    cache.clear()
    yield
    cache.clear()


def _absent_since(vm: Vm, ago: timedelta) -> None:
    """As if an earlier pass had already missed `vm`'s peer `ago` ago."""
    vm.refresh_from_db()
    cache.set(
        netbird_binding._absent_key(vm.pk), [vm.netbird_ip, (timezone.now() - ago).isoformat()]
    )


def test_a_peer_record_gone_clears_an_active_vms_address_and_reads_lost(_fresh_cache) -> None:
    """NetBird may hand a deleted peer's address to another peer."""
    gone = make_vm("vm-gone")
    Vm.objects.filter(pk=gone.pk).update(netbird_ip="100.64.101.1")
    dead = make_vm("vm-dead")
    Vm.objects.filter(pk=dead.pk).update(
        state=VmState.DESTROYED, host="", netbird_ip="100.64.102.2"
    )
    peers = [_peer("p-x", "someone-else", "100.64.102.9")]

    # The first miss only records it: one listing may just be incomplete.
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0
    gone.refresh_from_db()
    assert gone.netbird_ip == "100.64.101.1"
    _absent_since(gone, netbird_binding.ABSENCE_CONFIRM)

    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 1
    gone.refresh_from_db()
    dead.refresh_from_db()
    assert (gone.netbird_ip, gone.netbird_status) == ("", "lost")
    assert dead.netbird_ip == "100.64.102.2"


def test_a_peer_seen_again_resets_the_absence(_fresh_cache) -> None:
    vm = make_vm("vm-blip")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.3")
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)
    netbird_binding.refresh_overlay_ips(
        [_peer("p-b", "hippius-tenant-vm-blip", "100.64.101.3")], netbird_binding.overlay_snapshot()
    )
    assert cache.get(netbird_binding._absent_key(vm.pk)) is None


def test_no_clear_when_the_binding_could_not_be_read(
    _fresh_cache, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A re-enrolled guest's new peer is invisible to bound-id resolution
    until its key is bound — not gone."""
    vm = make_vm("vm-unreadable")
    _key(vm, "k-first", peer_id="p-old")
    _key(vm, "k-relaunch", persistent=False)
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.4")
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)

    def _down():
        raise effects.EffectUnavailable("audit log down")

    monkeypatch.setattr(effects, "list_netbird_setup_key_enrolments", _down)
    peers = [_peer("p-new", "hippius-tenant-vm-unreadable", "100.64.101.5")]
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.101.4"


def test_it_comes_back_ok_when_the_guest_re_enrols() -> None:
    vm = make_vm("vm-back")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="", netbird_status="lost")
    peers = [_peer("p-new", "hippius-tenant-vm-back", "100.64.101.9")]
    netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    vm.refresh_from_db()
    assert (vm.netbird_ip, vm.netbird_status) == ("100.64.101.9", "ok")


def test_an_empty_listing_clears_nothing() -> None:
    vm = make_vm("vm-empty")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.2")
    assert netbird_binding.refresh_overlay_ips([], netbird_binding.overlay_snapshot()) == 0


def test_a_migrating_vm_keeps_its_address_so_the_25_check_stays_armed(_fresh_cache) -> None:
    """The §25 dest-activation arms its overlay check only for a VM that
    still has an address."""
    vm = make_vm("vm-moving")
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING, migration_dest="node-dst", new_generation=6,
        netbird_ip="100.64.106.6",
    )
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)
    peers = [_peer("p-x", "someone-else", "100.64.102.9")]
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.106.6"


def test_a_fence_landing_after_the_snapshot_wins(_fresh_cache) -> None:
    """active → migrating between the snapshot and the CAS: not cleared."""
    vm = make_vm("vm-fenced")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.106.7")
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)
    snapshot = netbird_binding.overlay_snapshot()
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING, migration_dest="node-dst", new_generation=6
    )
    peers = [_peer("p-x", "someone-else", "100.64.102.9")]
    assert netbird_binding.refresh_overlay_ips(peers, snapshot) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.106.7"


def test_a_value_written_after_the_snapshot_is_not_overwritten() -> None:
    """A served receipt that resolved a newer peer after the snapshot wins
    over the (older) listing the refresh resolves against."""
    vm = make_vm("vm-race")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.108.1")
    snapshot = netbird_binding.overlay_snapshot()
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.108.3")
    peers = [_peer("p-old", "hippius-tenant-vm-race", "100.64.108.2")]

    assert netbird_binding.refresh_overlay_ips(peers, snapshot) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.108.3"


def test_a_disconnected_peer_keeps_its_address() -> None:
    vm = make_vm("vm-off")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.103.3")
    peers = [_peer("p-off", "hippius-tenant-vm-off", "100.64.103.3", connected=False)]
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0


def test_a_re_enrolment_under_an_open_key_is_bound_then_followed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bound VM is never matched by name: its new peer is found only
    once the key it enrolled with is bound — in the same pass."""
    vm = make_vm("vm-rekey")
    _key(vm, "k-first", peer_id="p-old")
    _key(vm, "k-relaunch", persistent=False)
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.104.4", netbird_peer_id="p-old")
    monkeypatch.setattr(
        effects, "list_netbird_setup_key_enrolments", lambda: {"k-relaunch": "p-new"}
    )
    peers = [
        _peer("p-old", "hippius-tenant-vm-rekey", "100.64.104.4", connected=False),
        _peer("p-new", "hippius-tenant-vm-rekey", "100.64.104.5"),
    ]
    netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.104.5"


def test_a_lost_vm_seen_connected_again_is_ok() -> None:
    vm = make_vm("vm-lost")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.105.5", netbird_status="lost")
    peers = [_peer("p-back", "hippius-tenant-vm-lost", "100.64.105.6")]
    netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    vm.refresh_from_db()
    assert (vm.netbird_ip, vm.netbird_status) == ("100.64.105.6", "ok")


def test_a_pending_vm_is_the_verifiers() -> None:
    """The §25 verifier owns `pending` rows, even when the peer resolves."""
    vm = make_vm("vm-checking")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.107.7", netbird_status="pending")
    peers = [_peer("p-moved", "hippius-tenant-vm-checking", "100.64.107.8")]

    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.107.7"


def test_a_pass_indexes_the_listing_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Up to 160 VMs against hundreds of peers every 30 s: the listing is
    indexed once per pass, not scanned once per VM."""
    for n in range(20):
        make_vm(f"vm-{n}")
    peers = [_peer(f"p-{n}", f"hippius-tenant-vm-{n}", f"100.64.109.{n}") for n in range(20)]
    peers += [_peer(f"x-{n}", f"other-{n}", f"100.98.0.{n}") for n in range(200)]
    built: list[int] = []
    real_of = effects.PeerIndex.of

    def _of(listing: list[dict[str, Any]]) -> effects.PeerIndex:
        built.append(len(listing))
        return real_of(listing)

    monkeypatch.setattr(effects.PeerIndex, "of", staticmethod(_of))
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 20
    assert built == [220]
    assert Vm.objects.get(vm_id="vm-7").netbird_ip == "100.64.109.7"


@pytest.mark.parametrize(
    ("peer_ids", "owners"),
    [((), {}), (("p-b", "p-a"), {}), ((), {"p-a": "someone-else"}), (("p-gone",), {})],
)
def test_the_index_resolves_exactly_as_the_listing(peer_ids, owners) -> None:
    peers = [
        _peer("p-a", "hippius-tenant-vm-i", "100.64.110.1", connected=False),
        _peer("p-b", "hippius-tenant-vm-i", "100.64.110.2"),
        _peer("p-c", "unrelated", "100.64.110.3"),
    ]
    kw = {"peer_ids": peer_ids, "bound_owners": owners}
    assert effects.tenant_peer_from_listing(
        effects.PeerIndex.of(peers), "vm-i", **kw
    ) == effects.tenant_peer_from_listing(peers, "vm-i", **kw)



def test_a_stale_absence_for_another_address_never_shortcuts_the_confirmation(
    _fresh_cache,
) -> None:
    """A marker left from an earlier address (the VM moved since) restarts."""
    vm = make_vm("vm-stale-mark")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.6")
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.7")
    peers = [_peer("p-x", "someone-else", "100.64.102.9")]
    assert netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot()) == 0
    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.101.7"


def test_a_pending_pass_drops_the_absence(_fresh_cache) -> None:
    vm = make_vm("vm-pend-mark")
    Vm.objects.filter(pk=vm.pk).update(netbird_ip="100.64.101.8", netbird_status="pending")
    _absent_since(vm, netbird_binding.ABSENCE_CONFIRM)
    peers = [_peer("p-x", "x", "100.64.102.9")]
    netbird_binding.refresh_overlay_ips(peers, netbird_binding.overlay_snapshot())
    assert cache.get(netbird_binding._absent_key(vm.pk)) is None
