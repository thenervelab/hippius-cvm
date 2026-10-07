"""The egress feed (egress design §5.2, §8.3) and its operator surface:
leases, epochs, revisions, `/v1/network/egress-regions`, the port-25
unblock."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

import pytest
from django.conf import settings
from django.db import IntegrityError, transaction
from rest_framework.test import APIClient

from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState
from apps.miners.models import MinerIdentity
from apps.network import egress, net_policy, service
from apps.network.models import (
    EGRESS_CLASS_ID_MAX,
    EGRESS_CLASS_ID_MIN,
    EgressMode,
    EgressRegion,
    IngressEdge,
    PublicIP,
    PublicIpState,
    VmEgressLease,
)

from .conftest import make_edge, make_vm
from .test_net_policy import _flavor, _miner

pytestmark = pytest.mark.django_db

E = "198.51.100.7"


@pytest.fixture(autouse=True)
def _feed_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_EGRESS_VMS", ["*"])


def _vm(
    vm_id: str,
    miner: MinerIdentity,
    netbird_ip: str,
    *,
    flavor: str = "small",
    state: str = VmState.ACTIVE,
) -> Vm:
    make_vm(vm_id, host=miner.miner_id, region="")
    Vm.objects.filter(vm_id=vm_id).update(netbird_ip=netbird_ip)
    if state == VmState.MIGRATING:
        Vm.objects.filter(vm_id=vm_id).update(
            state=state, migration_dest="miner-elsewhere", new_generation=2
        )
    elif state != VmState.ACTIVE:
        Vm.objects.filter(vm_id=vm_id).update(state=state)
    _flavor(vm_id, flavor)
    return Vm.objects.get(vm_id=vm_id)


def _au_edge(
    name: str = "edge-au",
    *,
    address: str = "203.0.113.20",
    egress_ip: str | None = E,
    region: str = "AU",
) -> IngressEdge:
    edge = make_edge(name, region, (address,))
    IngressEdge.objects.filter(pk=edge.pk).update(egress_ip=egress_ip)
    edge.refresh_from_db()
    return edge


def _edge_region(region: str = "AU", *, routing: bool = True) -> EgressRegion:
    row, _ = EgressRegion.objects.update_or_create(
        region=region, defaults={"mode": EgressMode.EDGE, "routing_enabled": routing}
    )
    return row


def _attach(vm: Vm, edge: IngressEdge, target: str | None) -> PublicIP:
    ip = PublicIP.objects.filter(edge=edge, state=PublicIpState.FREE).first()
    assert ip is not None
    PublicIP.objects.filter(pk=ip.pk).update(
        vm=vm, state=PublicIpState.ATTACHED, target_ip=target, epoch=1, vm_region="AU"
    )
    ip.refresh_from_db()
    return ip


def _revision(edge: IngressEdge) -> int:
    edge.refresh_from_db()
    return edge.desired_revision


def _lease(vm_id: str) -> VmEgressLease:
    return VmEgressLease.objects.get(vm__vm_id=vm_id)


_ALPHA2 = re.compile(r"^[A-Z]{2}$")
_OVERLAY = ipaddress.ip_network("100.64.0.0/10")


def _uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _check_contract(feed: dict[str, Any]) -> None:
    """The backend's validation of a feed (FEED_CONTRACT §1): any failure
    there is a 502 to the edge, which keeps its old table."""
    attached_targets: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for entry in feed["addresses"]:
        ipaddress.IPv4Address(entry["address"])
        assert ipaddress.IPv4Address(entry["target_ip"]) in _OVERLAY
        if "vm_region" in entry:
            assert _ALPHA2.fullmatch(entry["vm_region"])
        for key in ("epoch", "cap_mbps"):
            if key in entry:
                assert _uint(entry[key]), (key, entry)
        assert entry.get("epoch", 0) <= 2**63 - 1 and entry.get("cap_mbps", 0) <= 100_000
        if "smtp_allowed" in entry:
            assert isinstance(entry["smtp_allowed"], bool)
        attached_targets.add(entry["target_ip"])
        pairs.append((entry["vm_id"], entry["target_ip"]))
    block = feed.get("egress")
    if block is not None:
        ipaddress.IPv4Address(block["address"])
        if "block_smtp" in block:
            assert isinstance(block["block_smtp"], bool)
        for vm in block["vms"]:
            assert _uint(vm["epoch"]) and _uint(vm["class_id"]) and _uint(vm["cap_mbps"])
            assert 0x1000 <= vm["class_id"] <= 0xFFFE
            assert vm["epoch"] <= 2**63 - 1 and vm["cap_mbps"] <= 100_000
            assert _ALPHA2.fullmatch(vm["vm_region"])
            assert ipaddress.IPv4Address(vm["target_ip"]) in _OVERLAY
            assert vm["target_ip"] not in attached_targets
            pairs.append((vm["vm_id"], vm["target_ip"]))
    vm_ids = [p[0] for p in pairs]
    targets = [p[1] for p in pairs]
    assert len(set(vm_ids)) == len(vm_ids), "a vm_id appears twice"
    assert len(set(targets)) == len(targets), "a target_ip appears twice"


# ── flag off / not an egress edge: byte-identical ─────────────────────


def _legacy(edge: IngressEdge) -> dict[str, Any]:
    """Today's feed, as the pre-egress code renders it."""
    edge.refresh_from_db()
    return {
        "edge": edge.name,
        "revision": edge.desired_revision,
        "per_ip_mbps": edge.per_ip_mbps,
        "addresses": [
            {"address": a, "vm_id": v, "target_ip": t}
            for a, v, t in PublicIP.objects.filter(
                edge=edge, state=PublicIpState.ATTACHED, target_ip__isnull=False
            )
            .order_by("address")
            .values_list("address", "vm__vm_id", "target_ip")
        ],
    }


def _world() -> tuple[IngressEdge, Vm, Vm]:
    """An AU edge-mode region with an egress edge, one VM holding a public
    IP and one VM that belongs in the egress list."""
    miner = _miner(1, "AU")
    edge = _au_edge()
    _edge_region()
    holder = _vm("vm-pip", miner, "100.70.0.5", flavor="medium")
    _attach(holder, edge, "100.70.0.5")
    plain = _vm("vm-egr", miner, "100.70.0.6")
    return edge, holder, plain


@pytest.mark.parametrize(
    "case", ["flag-off", "region-local", "no-egress-ip", "no-region-row", "unbound"]
)
def test_the_feed_is_byte_identical_unless_the_edge_serves_egress(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    edge, _, _ = _world()
    if case == "flag-off":
        monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", False)
    elif case == "region-local":
        EgressRegion.objects.filter(region="AU").update(mode=EgressMode.LOCAL)
    elif case == "no-egress-ip":
        IngressEdge.objects.filter(pk=edge.pk).update(egress_ip=None)
    elif case == "no-region-row":
        EgressRegion.objects.all().delete()
    elif case == "unbound":
        IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id="")
    rev = _revision(edge)

    egress.reconcile()
    egress.reconcile()

    assert _revision(edge) == rev
    want = _legacy(edge) if case != "unbound" else {**_legacy(edge), "addresses": []}
    assert json.dumps(service.desired_state(edge)) == json.dumps(want)
    if case == "flag-off":
        assert not VmEgressLease.objects.exists()


def test_a_local_region_edge_is_untouched_while_the_flag_is_on() -> None:
    _world()
    fr = make_edge("edge-fr", "FR", ("203.0.113.30",))
    IngressEdge.objects.filter(pk=fr.pk).update(egress_ip="198.51.100.8")
    vm = make_vm("vm-fr", region="FR")
    _attach(vm, fr, "100.70.0.9")
    rev = _revision(fr)

    egress.reconcile()

    assert _revision(fr) == rev
    assert service.desired_state(fr) == _legacy(fr)


# ── the egress feed ───────────────────────────────────────────────────


def test_the_egress_feed_matches_the_contract() -> None:
    edge, _, _ = _world()
    service.set_smtp_allowed("203.0.113.20", True)

    egress.reconcile()
    feed = service.desired_state(edge)

    _check_contract(feed)
    assert feed == {
        "edge": "edge-au",
        "revision": _revision(edge),
        "per_ip_mbps": 1000,
        "addresses": [
            {
                "address": "203.0.113.20",
                "vm_id": "vm-pip",
                "target_ip": "100.70.0.5",
                "vm_region": "AU",
                "epoch": 1,
                "cap_mbps": 250,  # medium, public IP: effective_cap(has_public_ip=True)
                "smtp_allowed": True,
            }
        ],
        "egress": {
            "address": E,
            "block_smtp": True,
            "vms": [
                {
                    "vm_id": "vm-egr",
                    "target_ip": "100.70.0.6",
                    "vm_region": "AU",
                    "epoch": 1,
                    "class_id": 0x1000,
                    "cap_mbps": 100,  # small, no public IP
                }
            ],
        },
    }


def test_smtp_allowed_is_absent_when_false() -> None:
    edge, _, _ = _world()
    egress.reconcile()
    (entry,) = service.desired_state(edge)["addresses"]
    assert "smtp_allowed" not in entry


def test_only_eligible_vms_are_in_the_egress_list(monkeypatch: pytest.MonkeyPatch) -> None:
    edge, _, _ = _world()
    au, fr = MinerIdentity.objects.get(miner_id="miner-01"), _miner(2, "FR")
    _vm("vm-fr", fr, "100.70.0.20")
    _vm("vm-no-overlay", au, "")
    lost = _vm("vm-lost", au, "100.70.0.21")
    Vm.objects.filter(pk=lost.pk).update(netbird_status=VmNetbirdStatus.LOST)
    _vm("vm-moving", au, "100.70.0.22", state=VmState.MIGRATING)
    _vm("vm-not-overlay", au, "10.0.0.5")
    _vm("vm-canary", au, "100.70.0.23")
    monkeypatch.setattr(settings, "VALI_EGRESS_VMS", ["vm-canary", "vm-pip", "vm-fr"])

    egress.reconcile()
    vms = service.desired_state(edge)["egress"]["vms"]

    # vm-egr is not allowlisted; vm-pip holds a public IP.
    assert [v["vm_id"] for v in vms] == ["vm-canary"]


def test_routing_off_serves_an_empty_egress_list() -> None:
    edge, _, _ = _world()
    _edge_region(routing=False)
    egress.reconcile()
    feed = service.desired_state(edge)
    assert feed["egress"] == {"address": E, "block_smtp": True, "vms": []}
    _check_contract(feed)


def test_a_public_ip_attach_takes_the_vm_off_the_egress_list_at_once() -> None:
    edge, _, plain = _world()
    Vm.objects.filter(pk=plain.pk).update(tenant_id="tenant-a")
    plain.refresh_from_db()
    PublicIP.objects.create(edge=make_edge("edge-au-b", "AU", ()), address="203.0.113.21")
    egress.reconcile()
    assert [v["vm_id"] for v in service.desired_state(edge)["egress"]["vms"]] == ["vm-egr"]
    rev = _revision(edge)

    # Before any reconcile: the attach (on another edge) takes it off this
    # edge's list, under a new revision of this edge.
    service.attach(plain, address="203.0.113.21")
    assert service.desired_state(edge)["egress"]["vms"] == []
    assert _revision(edge) == rev + 1


def test_addresses_with_a_shared_or_non_overlay_target_are_not_served() -> None:
    edge, _, _ = _world()
    au = MinerIdentity.objects.get(miner_id="miner-01")
    PublicIP.objects.create(edge=edge, address="203.0.113.22")
    PublicIP.objects.create(edge=edge, address="203.0.113.23")
    _attach(_vm("vm-dup", au, "100.70.0.50"), edge, "100.70.0.5")  # vm-pip's target
    _attach(_vm("vm-odd", au, "100.70.0.51"), edge, "10.1.1.1")

    egress.reconcile()
    feed = service.desired_state(edge)

    _check_contract(feed)
    assert feed["addresses"] == []


def test_colliding_overlay_addresses_are_never_served() -> None:
    edge, _, _ = _world()
    au = MinerIdentity.objects.get(miner_id="miner-01")
    _vm("vm-twin-a", au, "100.70.0.40")
    _vm("vm-twin-b", au, "100.70.0.40")
    _vm("vm-stale", au, "100.70.0.5")  # the public-IP holder's target

    egress.reconcile()
    feed = service.desired_state(edge)

    _check_contract(feed)
    assert [v["vm_id"] for v in feed["egress"]["vms"]] == ["vm-egr"]


# ── class ids ─────────────────────────────────────────────────────────


def test_class_ids_are_leased_per_edge_and_never_reused_while_the_vm_lives() -> None:
    edge, _, plain = _world()
    au = MinerIdentity.objects.get(miner_id="miner-01")
    second = _vm("vm-x2", au, "100.70.0.7")
    egress.reconcile()
    assert _lease("vm-egr").class_id == 0x1000
    assert _lease("vm-x2").class_id == 0x1001

    # vm-egr takes a public IP: out of the feed, its class id kept.
    make_edge("edge-au-b", "AU", ("203.0.113.21",))
    PublicIP.objects.filter(address="203.0.113.21").update(
        vm=plain, state=PublicIpState.ATTACHED
    )
    _vm("vm-x3", au, "100.70.0.8")
    egress.reconcile()
    assert _lease("vm-egr").active is False
    assert _lease("vm-egr").class_id == 0x1000
    assert _lease("vm-x3").class_id == 0x1002

    # It gives the address back: same class id, a new epoch.
    PublicIP.objects.filter(address="203.0.113.21").update(
        state=PublicIpState.QUARANTINED
    )
    egress.reconcile()
    lease = _lease("vm-egr")
    assert (lease.active, lease.class_id, lease.epoch) == (True, 0x1000, 2)

    # vm-x2 is destroyed: its lease goes, and its class id is free again.
    Vm.objects.filter(pk=second.pk).update(state=VmState.DESTROYED)
    _vm("vm-x4", au, "100.70.0.9")
    egress.reconcile()
    assert not VmEgressLease.objects.filter(vm=second).exists()
    assert _lease("vm-x4").class_id == 0x1001
    classes = [v["class_id"] for v in service.desired_state(edge)["egress"]["vms"]]
    assert len(set(classes)) == len(classes)


def test_class_ids_are_unique_per_edge_in_the_database() -> None:
    edge, holder, plain = _world()
    VmEgressLease.objects.create(
        vm=plain, edge=edge, region="AU", target_ip="100.70.0.6", class_id=0x1000
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        VmEgressLease.objects.create(
            vm=holder, edge=edge, region="AU", target_ip="100.70.0.5", class_id=0x1000
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        VmEgressLease.objects.filter(vm=plain).update(class_id=0x10)


def test_class_id_0xffff_is_never_leased(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backend validates `0x1000..=0xfffe`; a lease at 0xffff would
    fail the whole edge feed."""
    edge, _, plain = _world()
    assert EGRESS_CLASS_ID_MAX == 0xFFFE
    with pytest.raises(IntegrityError), transaction.atomic():
        VmEgressLease.objects.create(
            vm=plain, edge=edge, region="AU", target_ip="100.70.0.6", class_id=0xFFFF
        )

    # Every id up to 0xfffe in use: the allocator gives up rather than
    # hand out 0xffff, and 0xfffe is the last id it ever hands out.
    ids = egress._ClassIds([])
    ids._used[edge.pk] = set(range(EGRESS_CLASS_ID_MIN, EGRESS_CLASS_ID_MAX + 1))
    with pytest.raises(IntegrityError):
        ids.take(edge.pk)
    ids.release(edge.pk, 0xFFFE)
    assert ids.take(edge.pk) == 0xFFFE

    # A full edge in a real pass: the pass leases nothing (retried later).
    original = egress._ClassIds.take

    def _full(self: egress._ClassIds, edge_id: int) -> int:
        self._used.setdefault(edge_id, set()).update(
            range(EGRESS_CLASS_ID_MIN, EGRESS_CLASS_ID_MAX + 1)
        )
        return original(self, edge_id)

    monkeypatch.setattr(egress._ClassIds, "take", _full)
    egress.reconcile()
    assert not VmEgressLease.objects.exists()


def test_served_caps_and_epochs_stay_within_the_backend_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge, _, _ = _world()
    monkeypatch.setattr(settings, "VALI_NET_CAP_MBPS_BY_FLAVOR", {"small": 250_000})
    monkeypatch.setattr(settings, "VALI_NET_CAP_PUBLIC_IP_MBPS", 300_000)
    egress.reconcile()
    feed = service.desired_state(edge)
    _check_contract(feed)
    assert feed["addresses"][0]["cap_mbps"] == 100_000
    assert feed["egress"]["vms"][0]["cap_mbps"] == 100_000

    VmEgressLease.objects.update(epoch=2**63 - 1)
    assert service.desired_state(edge)["egress"]["vms"][0]["epoch"] == 2**63 - 1
    with pytest.raises(ValueError, match="epoch"):
        egress._feed_epoch(2**63)
    with pytest.raises(ValueError, match="epoch"):
        egress._feed_epoch(-1)


# ── epochs ────────────────────────────────────────────────────────────


def test_the_lease_epoch_moves_with_the_binding_only() -> None:
    edge, _, plain = _world()
    egress.reconcile()
    assert _lease("vm-egr").epoch == 1

    egress.reconcile()
    assert _lease("vm-egr").epoch == 1

    Vm.objects.filter(pk=plain.pk).update(netbird_ip="100.70.0.66")
    egress.reconcile()
    assert (_lease("vm-egr").epoch, _lease("vm-egr").target_ip) == (2, "100.70.0.66")


def test_a_move_to_another_edge_region_bumps_the_epoch_and_takes_a_class_there() -> None:
    _, _, plain = _world()
    nz_edge = _au_edge("edge-nz", address="203.0.113.40", egress_ip="198.51.100.9", region="NZ")
    _edge_region("NZ")
    egress.reconcile()
    assert _lease("vm-egr").epoch == 1

    nz = _miner(3, "NZ")
    Vm.objects.filter(pk=plain.pk).update(host=nz.miner_id)
    egress.reconcile()

    lease = _lease("vm-egr")
    assert (lease.edge_id, lease.region, lease.epoch, lease.class_id) == (
        nz_edge.pk,
        "NZ",
        2,
        0x1000,
    )
    vms = service.desired_state(nz_edge)["egress"]["vms"]
    assert [(v["vm_id"], v["vm_region"], v["epoch"]) for v in vms] == [("vm-egr", "NZ", 2)]


def test_the_address_epoch_moves_on_attach_and_on_a_region_change() -> None:
    miner = _miner(1, "AU")
    edge = _au_edge()
    _edge_region()
    vm = make_vm("vm-pip", host=miner.miner_id, region="AU")

    ip, _ = service.attach(vm)
    assert (ip.epoch, ip.vm_region, ip.smtp_allowed) == (1, "AU", False)

    egress.reconcile()
    ip.refresh_from_db()
    assert ip.epoch == 1  # nothing moved

    nz = _miner(2, "NZ")
    Vm.objects.filter(pk=vm.pk).update(host=nz.miner_id)
    egress.reconcile()
    ip.refresh_from_db()
    assert (ip.epoch, ip.vm_region) == (2, "NZ")

    # A host whose country is unknown for now keeps the last known region.
    Vm.objects.filter(pk=vm.pk).update(host="miner-unknown")
    egress.reconcile()
    ip.refresh_from_db()
    assert (ip.epoch, ip.vm_region) == (2, "NZ")

    # A re-attach is a new binding.
    service.detach(vm)
    PublicIP.objects.filter(pk=ip.pk).update(state=PublicIpState.FREE, vm=None)
    ip2, _ = service.attach(vm, address=ip.address)
    assert ip2.epoch == 3
    assert edge.pk == ip2.edge_id


@pytest.mark.parametrize("flags", ["off", "address-region", "egress"])
def test_a_blank_address_region_is_backfilled_under_the_same_epoch(
    flags: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An address attached before regions were recorded gets its holder's
    region whatever the flags; a later move bumps the epoch, a probe gap
    keeps the last region."""
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", flags == "egress")
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", flags == "address-region")
    fr = make_edge("edge-fr", "FR", ("203.0.113.30",))
    miner = _miner(1, "FR")
    vm = make_vm("vm-fr", host=miner.miner_id, region="FR")
    ip = _attach(vm, fr, "100.70.0.9")
    PublicIP.objects.filter(pk=ip.pk).update(vm_region="", epoch=4)

    assert egress.reconcile().regions == 1
    ip.refresh_from_db()
    assert (ip.epoch, ip.vm_region) == (4, "FR")
    assert egress.reconcile().regions == 0

    de = _miner(2, "DE")
    Vm.objects.filter(pk=vm.pk).update(host=de.miner_id)
    egress.reconcile()
    ip.refresh_from_db()
    assert (ip.epoch, ip.vm_region) == (5, "DE")

    Vm.objects.filter(pk=vm.pk).update(host="miner-unknown")
    egress.reconcile()
    ip.refresh_from_db()
    assert (ip.epoch, ip.vm_region) == (5, "DE")


def test_a_backfilled_region_reaches_the_local_feed_under_a_new_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)
    fr = make_edge("edge-fr", "FR", ("203.0.113.30",))
    miner = _miner(1, "FR")
    vm = make_vm("vm-fr", host=miner.miner_id, region="FR")
    ip = _attach(vm, fr, "100.70.0.9")
    PublicIP.objects.filter(pk=ip.pk).update(vm_region="", epoch=4)
    rev = _revision(fr)

    egress.reconcile()

    assert _revision(fr) == rev + 1
    [entry] = service.desired_state(fr)["addresses"]
    assert (entry["vm_region"], entry["epoch"]) == ("FR", 4)


# ── revisions ─────────────────────────────────────────────────────────


def test_any_change_to_the_egress_feed_bumps_the_revision_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge, _, plain = _world()
    rev = _revision(edge)

    egress.reconcile()  # the edge starts being served egress
    assert _revision(edge) == rev + 1
    egress.reconcile()
    assert _revision(edge) == rev + 1  # nothing changed

    Vm.objects.filter(pk=plain.pk).update(netbird_ip="100.70.0.66")
    egress.reconcile()
    assert _revision(edge) == rev + 2

    # A cap setting change reaches the edge too.
    monkeypatch.setattr(settings, "VALI_NET_CAP_MBPS_BY_FLAVOR", {"small": 150})
    egress.reconcile()
    assert _revision(edge) == rev + 3

    # Flag off: one more revision, and the plain table again.
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", False)
    egress.reconcile()
    assert _revision(edge) == rev + 4
    assert service.desired_state(edge) == _legacy(edge)
    egress.reconcile()
    assert _revision(edge) == rev + 4


# ── VALI_FEED_ADDRESS_REGION: vm_region/epoch on every edge ───────────


def _local_world() -> tuple[IngressEdge, IngressEdge]:
    """[`_world`]'s AU egress edge, plus a bound FR edge in local mode with
    one attached address (port 25 open, so a leak would show)."""
    edge, _, _ = _world()
    fr = make_edge("edge-fr", "FR", ("203.0.113.30",))
    vm = make_vm("vm-fr", region="FR")
    ip = _attach(vm, fr, "100.70.0.9")
    PublicIP.objects.filter(pk=ip.pk).update(vm_region="FR", epoch=7, smtp_allowed=True)
    egress.reconcile()
    return edge, fr


def test_address_region_off_is_byte_identical_on_local_and_egress_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge, fr = _local_world()
    before = {e.pk: json.dumps(service.desired_state(e)) for e in (edge, fr)}
    revs = {e.pk: _revision(e) for e in (edge, fr)}

    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", False)
    egress.reconcile()
    egress.reconcile()

    for e in (edge, fr):
        assert _revision(e) == revs[e.pk]
        assert json.dumps(service.desired_state(e)) == before[e.pk]
    assert json.dumps(service.desired_state(fr)) == json.dumps(_legacy(fr))

    # The egress edge's feed already carries both fields: the flag leaves it alone.
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)
    egress.reconcile()
    assert _revision(edge) == revs[edge.pk]
    assert json.dumps(service.desired_state(edge)) == before[edge.pk]


def test_address_region_on_a_local_edge_carries_vm_region_and_epoch_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, fr = _local_world()
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)
    egress.reconcile()

    feed = service.desired_state(fr)

    assert "egress" not in feed
    assert feed["addresses"] == [
        {
            "address": "203.0.113.30",
            "vm_id": "vm-fr",
            "target_ip": "100.70.0.9",
            "vm_region": "FR",
            "epoch": 7,
        }
    ]
    _check_contract(feed)


def test_address_region_omits_an_unknown_region(monkeypatch: pytest.MonkeyPatch) -> None:
    _, fr = _local_world()
    PublicIP.objects.filter(edge=fr).update(vm_region="")
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)

    [entry] = service.desired_state(fr)["addresses"]

    assert "vm_region" not in entry and entry["epoch"] == 7


def test_address_region_on_an_unbound_edge_serves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, fr = _local_world()
    IngressEdge.objects.filter(pk=fr.pk).update(netbird_peer_id="")
    rev = _revision(fr)
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)

    egress.reconcile()

    assert _revision(fr) == rev
    assert service.desired_state(fr)["addresses"] == []


@pytest.mark.parametrize("egress_feed", [True, False])
def test_address_region_flip_and_changes_bump_the_revision_once(
    egress_feed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, fr = _local_world()
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", egress_feed)
    egress.reconcile()
    rev = _revision(fr)

    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", True)
    egress.reconcile()
    assert _revision(fr) == rev + 1
    egress.reconcile()
    assert _revision(fr) == rev + 1  # nothing changed

    PublicIP.objects.filter(edge=fr).update(vm_region="DE")
    egress.reconcile()
    assert _revision(fr) == rev + 2
    PublicIP.objects.filter(edge=fr).update(epoch=8)
    egress.reconcile()
    assert _revision(fr) == rev + 3

    # Flag off: one more revision, and the plain table again — even with
    # the egress feed flag off too.
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", False)
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", False)
    egress.reconcile()
    assert _revision(fr) == rev + 4
    assert json.dumps(service.desired_state(fr)) == json.dumps(_legacy(fr))
    egress.reconcile()
    assert _revision(fr) == rev + 4


# ── VALI_FEED_BLOCK_SMTP: top-level block_smtp on every edge ──────────


def _smtp_world() -> tuple[IngressEdge, IngressEdge]:
    """[`_local_world`], plus a second FR address whose port 25 stays
    blocked."""
    edge, fr = _local_world()
    PublicIP.objects.create(edge=fr, address="203.0.113.31")
    _attach(make_vm("vm-fr-2", region="FR"), fr, "100.70.0.10")
    egress.reconcile()
    return edge, fr


def test_block_smtp_off_is_byte_identical_on_local_and_egress_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge, fr = _smtp_world()
    revs = {e.pk: _revision(e) for e in (edge, fr)}
    before = {e.pk: json.dumps(service.desired_state(e)) for e in (edge, fr)}

    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", False)
    egress.reconcile()

    for e in (edge, fr):
        assert _revision(e) == revs[e.pk]
        assert json.dumps(service.desired_state(e)) == before[e.pk]
        assert "block_smtp" not in service.desired_state(e)
    # The unblocked address is not exempted from a policy nobody asked for.
    assert json.dumps(service.desired_state(fr)) == json.dumps(_legacy(fr))


@pytest.mark.parametrize("address_region", [False, True])
def test_block_smtp_on_a_local_edge_exempts_only_the_unblocked_address(
    address_region: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, fr = _smtp_world()
    monkeypatch.setattr(settings, "VALI_FEED_ADDRESS_REGION", address_region)
    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", True)
    egress.reconcile()

    feed = service.desired_state(fr)

    assert "egress" not in feed
    assert feed["block_smtp"] is True
    allowed, blocked = feed["addresses"]
    assert allowed["address"] == "203.0.113.30" and allowed["smtp_allowed"] is True
    assert blocked["address"] == "203.0.113.31" and "smtp_allowed" not in blocked
    for entry in feed["addresses"]:
        assert "cap_mbps" not in entry
        assert ("epoch" in entry) is address_region
    _check_contract(feed)


def test_block_smtp_on_an_egress_edge_only_adds_the_top_level_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge, _ = _smtp_world()
    before = service.desired_state(edge)
    assert "egress" in before

    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", True)
    egress.reconcile()
    after = service.desired_state(edge)

    assert after.pop("block_smtp") is True
    assert after.pop("revision") == before.pop("revision") + 1
    assert after == before
    assert list(after) == list(before)


def test_block_smtp_on_an_unbound_edge_serves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _, fr = _smtp_world()
    IngressEdge.objects.filter(pk=fr.pk).update(netbird_peer_id="")
    rev = _revision(fr)
    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", True)

    egress.reconcile()

    assert _revision(fr) == rev
    feed = service.desired_state(fr)
    assert feed["addresses"] == [] and "block_smtp" not in feed


@pytest.mark.parametrize("egress_feed", [True, False])
def test_block_smtp_flip_and_changes_bump_the_revision_once(
    egress_feed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    edge, fr = _smtp_world()
    monkeypatch.setattr(settings, "VALI_EGRESS_FEED_ENABLED", egress_feed)
    egress.reconcile()
    revs = {e.pk: _revision(e) for e in (edge, fr)}

    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", True)
    egress.reconcile()
    egress.reconcile()  # nothing changed
    for e in (edge, fr):
        assert _revision(e) == revs[e.pk] + 1
        assert service.desired_state(e)["block_smtp"] is True

    # An address unblocked (or blocked again) behind the API's back: the
    # digest still sees it.
    PublicIP.objects.filter(address="203.0.113.31").update(smtp_allowed=True)
    egress.reconcile()
    assert _revision(fr) == revs[fr.pk] + 2
    PublicIP.objects.filter(address="203.0.113.30").update(smtp_allowed=False)
    egress.reconcile()
    assert _revision(fr) == revs[fr.pk] + 3

    # Flag off: one more revision, and the feed it had before.
    monkeypatch.setattr(settings, "VALI_FEED_BLOCK_SMTP", False)
    egress.reconcile()
    egress.reconcile()
    assert _revision(fr) == revs[fr.pk] + 4
    assert _revision(edge) == revs[edge.pk] + 2
    assert "block_smtp" not in service.desired_state(fr)
    if not egress_feed:
        assert json.dumps(service.desired_state(fr)) == json.dumps(_legacy(fr))


# ── /v1/network/egress-regions ────────────────────────────────────────


def test_the_regions_view_has_the_contract_shape(root_client: APIClient) -> None:
    _au_edge()
    _edge_region()
    EgressRegion.objects.create(region="FR")

    body = root_client.get("/v1/network/egress-regions").json()

    caps = {k: int(v) for k, v in settings.VALI_NET_CAP_MBPS_BY_FLAVOR.items()}
    assert body == {
        "regions": [
            {
                "region": "AU",
                "mode": "edge",
                "routing_enabled": True,
                "enforce": False,
                "default_cap_mbps": settings.VALI_NET_CAP_DEFAULT_MBPS,
                "cap_mbps_by_flavor": caps,
            },
            {
                "region": "FR",
                "mode": "local",
                "routing_enabled": False,
                "enforce": False,
                "default_cap_mbps": settings.VALI_NET_CAP_DEFAULT_MBPS,
                "cap_mbps_by_flavor": caps,
            },
        ]
    }


def test_patch_upserts_a_normalised_region(root_client: APIClient) -> None:
    resp = root_client.patch("/v1/network/egress-regions/au", {}, format="json")
    assert resp.status_code == 200
    assert resp.json()["region"] == "AU"
    assert resp.json()["mode"] == "local"

    # Edge mode needs an egress edge in the region.
    resp = root_client.patch("/v1/network/egress-regions/AU", {"mode": "edge"}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (409, "no-egress-edge")
    assert EgressRegion.objects.get(region="AU").mode == "local"

    _au_edge()
    resp = root_client.patch(
        "/v1/network/egress-regions/AU",
        {"mode": "edge", "routing_enabled": True},
        format="json",
    )
    assert resp.status_code == 200
    row = EgressRegion.objects.get(region="AU")
    assert (row.mode, row.routing_enabled, row.enforce) == ("edge", True, False)
    assert root_client.get("/v1/network/egress-regions/au").json()["mode"] == "edge"


@pytest.mark.parametrize(
    ("region", "body"),
    [
        ("A1", {}),
        ("AUS", {}),
        ("AU", {"mode": "remote"}),
        ("AU", {"enforce": "yes"}),
        ("AU", {"revision": 3}),
    ],
)
def test_patch_refuses_a_bad_region_or_field(
    root_client: APIClient, region: str, body: dict[str, Any]
) -> None:
    resp = root_client.patch(f"/v1/network/egress-regions/{region}", body, format="json")
    assert resp.status_code == 400
    assert not EgressRegion.objects.exists()


def test_the_database_refuses_a_non_alpha2_region() -> None:
    for bad in ("au", "A1"):
        with pytest.raises(IntegrityError), transaction.atomic():
            EgressRegion.objects.create(region=bad)


def test_an_unknown_region_is_404(root_client: APIClient) -> None:
    assert root_client.get("/v1/network/egress-regions/JP").status_code == 404


# ── edge egress_ip ────────────────────────────────────────────────────


def test_patch_sets_and_clears_the_egress_ip(root_client: APIClient) -> None:
    edge = make_edge("edge-au", "AU", ("203.0.113.20",))
    rev = _revision(edge)
    url = "/v1/network/edges/edge-au"

    resp = root_client.patch(url, {"egress_ip": E}, format="json")
    assert resp.status_code == 200
    assert resp.json()["egress_ip"] == E
    assert _revision(edge) == rev + 1

    # An address of a pool, or a non-public one, is refused.
    resp = root_client.patch(url, {"egress_ip": "203.0.113.20"}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (409, "address-taken")
    resp = root_client.patch(url, {"egress_ip": "10.0.0.1"}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (400, "bad-address")
    # And no pool takes the egress address.
    resp = root_client.post(url + "/addresses", {"addresses": [E]}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (409, "address-taken")

    # The last egress edge of an edge-mode region keeps its address.
    _edge_region()
    resp = root_client.patch(url, {"egress_ip": None}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (409, "egress-in-use")
    EgressRegion.objects.filter(region="AU").update(mode=EgressMode.LOCAL)
    resp = root_client.patch(url, {"egress_ip": None}, format="json")
    assert resp.status_code == 200
    assert resp.json()["egress_ip"] is None


def test_two_edges_cannot_share_an_egress_ip(root_client: APIClient) -> None:
    _au_edge()
    make_edge("edge-au-b", "AU", ("203.0.113.21",))
    resp = root_client.patch("/v1/network/edges/edge-au-b", {"egress_ip": E}, format="json")
    assert (resp.status_code, resp.json()["error"]) == (409, "address-taken")


# ── port 25 ───────────────────────────────────────────────────────────


def test_the_smtp_endpoint_opens_port_25_on_the_miner_policy(root_client: APIClient) -> None:
    edge, holder, _ = _world()
    miner = MinerIdentity.objects.select_related("location").get(miner_id="miner-01")
    assert net_policy.build_content(miner, "AU")["smtp_allowed_vms"] == []
    rev = _revision(edge)

    resp = root_client.post(
        "/v1/network/public-ips/203.0.113.20/smtp", {"allowed": True}, format="json"
    )
    assert resp.status_code == 200
    assert resp.json() == {"address": "203.0.113.20", "vm_id": "vm-pip", "smtp_allowed": True}
    assert _revision(edge) == rev + 1
    assert net_policy.build_content(miner, "AU")["smtp_allowed_vms"] == ["vm-pip"]

    resp = root_client.post(
        "/v1/network/public-ips/203.0.113.20/smtp", {"allowed": False}, format="json"
    )
    assert resp.json()["smtp_allowed"] is False
    assert net_policy.build_content(miner, "AU")["smtp_allowed_vms"] == []


def test_the_smtp_endpoint_checks_the_expected_holder(root_client: APIClient) -> None:
    edge, _, _ = _world()
    url = "/v1/network/public-ips/203.0.113.20/smtp"
    rev = _revision(edge)

    resp = root_client.post(url, {"allowed": True, "expected_vm_id": "vm-other"}, format="json")
    assert resp.status_code == 409
    assert resp.json() == {
        "error": "vm-mismatch",
        "detail": "203.0.113.20 is attached to vm-pip",
    }
    assert PublicIP.objects.get(address="203.0.113.20").smtp_allowed is False
    assert _revision(edge) == rev

    resp = root_client.post(url, {"allowed": True, "expected_vm_id": "vm-pip"}, format="json")
    assert resp.status_code == 200
    assert resp.json() == {"address": "203.0.113.20", "vm_id": "vm-pip", "smtp_allowed": True}
    assert _revision(edge) == rev + 1

    # Absent (or null) is the unchecked path.
    resp = root_client.post(url, {"allowed": False, "expected_vm_id": None}, format="json")
    assert (resp.status_code, resp.json()["smtp_allowed"]) == (200, False)


def test_the_smtp_endpoint_reads_the_flag(root_client: APIClient) -> None:
    _world()
    url = "/v1/network/public-ips/203.0.113.20/smtp"
    resp = root_client.get(url)
    assert resp.status_code == 200
    assert resp.json() == {"address": "203.0.113.20", "vm_id": "vm-pip", "smtp_allowed": False}

    root_client.post(url, {"allowed": True}, format="json")
    assert root_client.get(url).json()["smtp_allowed"] is True


@pytest.mark.parametrize(
    ("address", "status", "error"),
    [
        ("not-an-ip", 400, "bad-address"),
        ("10.0.0.1", 400, "bad-address"),
        ("203.0.113.99", 404, "address-not-found"),
        ("203.0.113.21", 409, "address-not-attached"),
    ],
)
def test_the_smtp_read_refusals(
    root_client: APIClient, address: str, status: int, error: str
) -> None:
    _world()
    make_edge("edge-au-b", "AU", ("203.0.113.21",))
    resp = root_client.get(f"/v1/network/public-ips/{address}/smtp")
    assert (resp.status_code, resp.json()["error"]) == (status, error)
    if status == 409:
        assert resp.json() == {
            "error": "address-not-attached",
            "detail": "203.0.113.21 is free",
        }


def test_a_re_attach_closes_port_25_again() -> None:
    miner = _miner(1, "AU")
    _au_edge()
    vm = make_vm("vm-pip", host=miner.miner_id, region="AU", tenant_id="tenant-a")
    ip, _ = service.attach(vm)
    service.set_smtp_allowed(ip.address, True)
    service.detach(vm)
    ip2, _ = service.attach(vm)
    assert ip2.address == ip.address  # back from quarantine to the same tenant
    assert ip2.smtp_allowed is False


@pytest.mark.parametrize(
    ("address", "body", "status", "error"),
    [
        ("203.0.113.20", {"allowed": "yes"}, 400, "bad-request"),
        ("203.0.113.20", {}, 400, "bad-request"),
        ("203.0.113.20", {"allowed": True, "expected_vm_id": 7}, 400, "bad-request"),
        ("203.0.113.20", {"allowed": True, "expected_vm_id": ["vm-pip"]}, 400, "bad-request"),
        ("not-an-ip", {"allowed": True}, 400, "bad-address"),
        ("203.0.113.99", {"allowed": True}, 404, "address-not-found"),
        ("203.0.113.21", {"allowed": True}, 409, "address-not-attached"),
    ],
)
def test_the_smtp_endpoint_refusals(
    root_client: APIClient, address: str, body: dict[str, Any], status: int, error: str
) -> None:
    _world()
    make_edge("edge-au-b", "AU", ("203.0.113.21",))
    resp = root_client.post(f"/v1/network/public-ips/{address}/smtp", body, format="json")
    assert (resp.status_code, resp.json()["error"]) == (status, error)
