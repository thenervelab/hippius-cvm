"""Same-tenant reuse of a quarantined address, and the quarantine window.

A released address is held away from OTHER tenants for
`VALI_PUBLIC_IP_QUARANTINE_S`; the tenant that released it gets it back
first, even inside the window.
"""

from __future__ import annotations

import importlib
import threading
from datetime import timedelta

import pytest
from django.apps import apps as django_apps
from django.conf import settings
from django.db import OperationalError, connection, connections
from django.utils import timezone

from apps.network import service
from apps.network.models import IngressEdge, PublicIP, PublicIpState
from apps.network.service import NetworkError

from .conftest import make_edge, make_vm
from .test_service import _located_host

pytestmark = pytest.mark.django_db


def _release(vm_id: str, tenant: str, **edge_kw: object) -> PublicIP:
    """A VM of `tenant` that held an address and released it."""
    vm = make_vm(vm_id, tenant_id=tenant)
    service.attach(vm, **edge_kw)
    ip = service.detach(vm)
    assert ip is not None
    ip.refresh_from_db()
    return ip


def _release_two(tenant: str) -> tuple[PublicIP, PublicIP]:
    """Two addresses held at once by two VMs of `tenant`, released five
    minutes apart; `(older, newer)`."""
    vms = [make_vm(f"vm-{tenant}-{i}", tenant_id=tenant) for i in (1, 2)]
    ips = [service.attach(vm)[0] for vm in vms]
    for vm in vms:
        service.detach(vm)
    PublicIP.objects.filter(pk=ips[0].pk).update(released_at=timezone.now() - timedelta(minutes=5))
    assert ips[0].pk != ips[1].pk
    return ips[0], ips[1]


# ── the window ────────────────────────────────────────────────────────


def test_the_default_quarantine_is_one_hour(monkeypatch: pytest.MonkeyPatch) -> None:
    import vali.settings as vali_settings

    monkeypatch.delenv("VALI_PUBLIC_IP_QUARANTINE_S", raising=False)
    monkeypatch.setenv("DJANGO_SECRET_KEY", "test-secret-key-not-for-prod")
    monkeypatch.setenv("DJANGO_DEBUG", "1")
    assert importlib.reload(vali_settings).VALI_PUBLIC_IP_QUARANTINE_S == 3600.0
    monkeypatch.delattr(settings, "VALI_PUBLIC_IP_QUARANTINE_S")
    assert service._quarantine_s() == 3600.0


def test_the_quarantine_window_is_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    make_edge(addresses=("203.0.113.10",))
    ip = _release("vm-1", "tenant-a")
    monkeypatch.setattr(settings, "VALI_PUBLIC_IP_QUARANTINE_S", 7200.0)

    service.reconcile(now=timezone.now() + timedelta(hours=1, minutes=1))
    ip.refresh_from_db()
    assert ip.state == PublicIpState.QUARANTINED

    service.reconcile(now=timezone.now() + timedelta(hours=2, seconds=1))
    ip.refresh_from_db()
    assert ip.state == PublicIpState.FREE


# ── release records the tenant ────────────────────────────────────────


def test_detach_records_the_releasing_tenant() -> None:
    make_edge()
    ip = _release("vm-1", "tenant-a")

    assert ip.state == PublicIpState.QUARANTINED
    assert ip.last_tenant_id == "tenant-a"


def test_destroy_records_the_releasing_tenant() -> None:
    make_edge()
    vm = make_vm(tenant_id="tenant-a")
    ip, _ = service.attach(vm)
    vm.state = "destroyed"
    vm.save(update_fields=["state"])

    service.release_for_destroyed_vm(vm)

    ip.refresh_from_db()
    assert (ip.state, ip.last_tenant_id) == (PublicIpState.QUARANTINED, "tenant-a")


def test_reconcile_backstop_records_the_releasing_tenant() -> None:
    make_edge()
    vm = make_vm(tenant_id="tenant-a")
    ip, _ = service.attach(vm)
    type(vm).objects.filter(pk=vm.pk).update(state="destroyed")

    service.reconcile()

    ip.refresh_from_db()
    assert (ip.state, ip.last_tenant_id) == (PublicIpState.QUARANTINED, "tenant-a")


# ── same-tenant reuse ─────────────────────────────────────────────────


def test_the_same_tenant_gets_its_quarantined_address_back() -> None:
    edge = make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    old = _release("vm-1", "tenant-a")
    edge.refresh_from_db()
    rev = edge.desired_revision

    ip, created = service.attach(make_vm("vm-2", tenant_id="tenant-a"))

    assert created
    assert ip.pk == old.pk  # over the free 203.0.113.11
    assert ip.state == PublicIpState.ATTACHED
    assert ip.vm.vm_id == "vm-2"
    assert ip.released_at is None
    assert ip.target_ip is None  # the edge learns the NEW VM's peer, never the old one's
    assert ip.last_tenant_id == ""
    edge.refresh_from_db()
    assert edge.desired_revision == rev + 1


def test_the_most_recently_released_address_comes_back_first() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11", "203.0.113.12"))
    first, second = _release_two("tenant-a")

    ip, _ = service.attach(make_vm("vm-3", tenant_id="tenant-a"))

    assert ip.pk == second.pk


def test_a_quarantined_address_never_goes_to_another_tenant() -> None:
    make_edge(addresses=("203.0.113.10",))
    _release("vm-1", "tenant-a")

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-2", tenant_id="tenant-b"))

    assert exc.value.code == "no-free-public-ip"
    assert not PublicIP.objects.filter(state=PublicIpState.ATTACHED).exists()


def test_another_tenant_gets_a_free_address_not_the_quarantined_one() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    old = _release("vm-1", "tenant-a")

    ip, _ = service.attach(make_vm("vm-2", tenant_id="tenant-b"))

    assert ip.pk != old.pk
    old.refresh_from_db()
    assert (old.state, old.last_tenant_id) == (PublicIpState.QUARANTINED, "tenant-a")


def test_a_blank_tenant_reuses_nothing() -> None:
    make_edge(addresses=("203.0.113.10",))
    _release("vm-1", "")

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-2", tenant_id=""))

    assert exc.value.code == "no-free-public-ip"


def test_reuse_skips_an_edge_that_takes_no_attachment() -> None:
    edge = make_edge(addresses=("203.0.113.10",))
    _release("vm-1", "tenant-a")
    IngressEdge.objects.filter(pk=edge.pk).update(status="draining")

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-2", tenant_id="tenant-a"))

    assert exc.value.code == "no-free-public-ip"


def test_reuse_skips_an_unbound_edge() -> None:
    edge = make_edge(addresses=("203.0.113.10",))
    _release("vm-1", "tenant-a")
    IngressEdge.objects.filter(pk=edge.pk).update(netbird_peer_id="", netbird_ip=None)

    with pytest.raises(NetworkError):
        service.attach(make_vm("vm-2", tenant_id="tenant-a"))


def test_a_stale_last_tenant_id_never_hands_over_another_tenants_address() -> None:
    """A process predating `last_tenant_id` (a rolling deploy) can attach
    and release a row without rewriting it; the previous holder decides."""
    make_edge(addresses=("203.0.113.10",))
    b_ip = _release("vm-b", "tenant-b")
    PublicIP.objects.filter(pk=b_ip.pk).update(last_tenant_id="tenant-a")

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-a", tenant_id="tenant-a"))
    assert exc.value.code == "no-free-public-ip"
    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-a2", tenant_id="tenant-a"), address=b_ip.address)
    assert exc.value.code == "address-unavailable"


def test_an_expired_address_is_free_for_anyone() -> None:
    make_edge(addresses=("203.0.113.10",))
    old = _release("vm-1", "tenant-a")
    service.reconcile(now=timezone.now() + timedelta(hours=1, seconds=1))

    ip, _ = service.attach(make_vm("vm-2", tenant_id="tenant-b"))

    assert ip.pk == old.pk


# ── reuse vs region preference ────────────────────────────────────────


def test_an_own_address_in_the_vm_region_beats_a_free_one_there() -> None:
    make_edge("edge-fr", "FR", ("203.0.113.10", "203.0.113.11"))
    make_edge("edge-de", "DE", ("198.51.100.1",))
    old = _release("vm-1", "tenant-a", region_hint="FR")
    assert old.edge.name == "edge-fr"
    _located_host("miner-fr", "FR")

    ip, _ = service.attach(make_vm("vm-2", host="miner-fr", tenant_id="tenant-a"))

    assert ip.pk == old.pk


def test_region_beats_reuse() -> None:
    """A free address where the VM runs wins over the tenant's own address
    in another region: the address serves the VM's traffic, latency first."""
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-fr", "FR", ("203.0.113.10",))
    old = _release("vm-1", "tenant-a", region_hint="DE")
    assert old.edge.name == "edge-de"
    _located_host("miner-fr", "FR")

    ip, _ = service.attach(make_vm("vm-2", host="miner-fr", tenant_id="tenant-a"))

    assert ip.edge.name == "edge-fr"
    old.refresh_from_db()
    assert old.state == PublicIpState.QUARANTINED


def test_reuse_in_another_region_beats_a_free_address_in_a_third() -> None:
    """No candidate region has anything: in the same-zone fallback the
    tenant's own address comes before a free one."""
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-nl", "NL", ("192.0.2.1", "192.0.2.2", "192.0.2.3"))
    old = _release("vm-1", "tenant-a", region_hint="DE")
    assert old.edge.name == "edge-de"

    ip, _ = service.attach(make_vm("vm-2", tenant_id="tenant-a"), region_hint="BE")

    assert ip.pk == old.pk


def test_an_own_address_in_the_hinted_region_beats_the_fallback() -> None:
    make_edge("edge-de", "DE", ("198.51.100.1",))
    make_edge("edge-nl", "NL", ("192.0.2.1", "192.0.2.2", "192.0.2.3"))
    old = _release("vm-1", "tenant-a", region_hint="DE")

    ip, _ = service.attach(make_vm("vm-2", tenant_id="tenant-a"), region_hint="DE")

    assert ip.pk == old.pk


# ── asking for one address ────────────────────────────────────────────


def test_a_tenant_may_ask_for_its_own_quarantined_address() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11", "203.0.113.12"))
    first, _second = _release_two("tenant-a")  # `_second` is the default choice

    ip, created = service.attach(make_vm("vm-3", tenant_id="tenant-a"), address=first.address)

    assert created
    assert ip.pk == first.pk


def test_a_tenant_may_ask_for_a_free_address() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11"))

    ip, _ = service.attach(make_vm(tenant_id="tenant-a"), address="203.0.113.11")

    assert ip.address == "203.0.113.11"


@pytest.mark.parametrize("case", ["other-tenant", "attached", "draining", "unknown", "blank"])
def test_asking_for_an_unavailable_address_is_refused(case: str) -> None:
    edge = make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    tenant = "tenant-a"
    address = "203.0.113.10"
    if case == "other-tenant":
        _release("vm-0", "tenant-b")
    elif case == "attached":
        service.attach(make_vm("vm-0", tenant_id=tenant))
    elif case == "draining":
        _release("vm-0", tenant)
        IngressEdge.objects.filter(pk=edge.pk).update(status="draining")
    elif case == "unknown":
        address = "198.51.100.77"
    else:
        _release("vm-0", "")
        tenant = ""

    with pytest.raises(NetworkError) as exc:
        service.attach(make_vm("vm-9", tenant_id=tenant), address=address)

    assert exc.value.code == "address-unavailable"
    assert not PublicIP.objects.filter(vm__vm_id="vm-9").exists()


def test_asking_for_an_address_keeps_attach_idempotent() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    vm = make_vm(tenant_id="tenant-a")
    held, _ = service.attach(vm)

    again, created = service.attach(vm, address="203.0.113.11")

    assert not created
    assert again.pk == held.pk


# ── deadlock retry ────────────────────────────────────────────────────


def _deadlock() -> OperationalError:
    class _Deadlock(Exception):
        sqlstate = "40P01"

    exc = OperationalError("deadlock detected")
    exc.__cause__ = _Deadlock()
    return exc


def test_a_deadlocked_attach_runs_again(monkeypatch: pytest.MonkeyPatch) -> None:
    make_edge()
    real = service._pick_ip
    calls: list[int] = []

    def flaky(vm: object, hint: str) -> PublicIP | None:
        calls.append(1)
        if len(calls) == 1:
            raise _deadlock()
        return real(vm, hint)  # type: ignore[arg-type]

    monkeypatch.setattr(service, "_pick_ip", flaky)

    ip, created = service.attach(make_vm())

    assert created and ip.state == PublicIpState.ATTACHED
    assert len(calls) == 2


def test_attach_gives_up_after_repeated_deadlocks(monkeypatch: pytest.MonkeyPatch) -> None:
    make_edge()
    calls: list[int] = []

    def always(vm: object, hint: str) -> None:
        calls.append(1)
        raise _deadlock()

    monkeypatch.setattr(service, "_pick_ip", always)

    with pytest.raises(OperationalError):
        service.attach(make_vm())
    assert len(calls) == service._ATTACH_ATTEMPTS


def test_other_database_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    make_edge()
    calls: list[int] = []

    def broken(vm: object, hint: str) -> None:
        calls.append(1)
        raise OperationalError("connection lost")

    monkeypatch.setattr(service, "_pick_ip", broken)

    with pytest.raises(OperationalError):
        service.attach(make_vm())
    assert len(calls) == 1


# ── the migration's backfill ──────────────────────────────────────────


def test_the_migration_backfills_addresses_already_in_quarantine() -> None:
    migration = importlib.import_module("apps.network.migrations.0003_publicip_last_tenant_id")
    make_edge(addresses=("203.0.113.10", "203.0.113.11", "203.0.113.12"))
    a = _release("vm-1", "tenant-a")
    blank = _release("vm-2", "")
    b, _ = service.attach(make_vm("vm-3", tenant_id="tenant-b"))
    PublicIP.objects.update(last_tenant_id="")  # as before the migration

    migration.backfill_quarantined(django_apps, None)

    got = dict(PublicIP.objects.values_list("pk", "last_tenant_id"))
    assert got == {a.pk: "tenant-a", blank.pk: "", b.pk: ""}


# ── concurrency (Postgres only: SQLite has no row locks) ──────────────


@pytest.mark.django_db(transaction=True)
@pytest.mark.skipif(
    connection.vendor != "postgresql", reason="row locking needs a real database"
)
def test_two_vms_of_one_tenant_never_share_a_reused_address() -> None:
    make_edge(addresses=("203.0.113.10", "203.0.113.11"))
    old = _release("vm-0", "tenant-a")
    vms = [make_vm(f"vm-{i}", tenant_id="tenant-a") for i in (1, 2)]
    barrier = threading.Barrier(len(vms))
    got: dict[str, PublicIP | Exception] = {}

    def run(vm: object) -> None:
        barrier.wait()
        try:
            got[vm.vm_id], _ = service.attach(vm)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 — asserted below
            got[vm.vm_id] = exc  # type: ignore[attr-defined]
        finally:
            connections.close_all()

    threads = [threading.Thread(target=run, args=(vm,)) for vm in vms]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ips = list(got.values())
    assert all(isinstance(ip, PublicIP) for ip in ips), got
    assert {ip.pk for ip in ips} == set(PublicIP.objects.values_list("pk", flat=True))  # type: ignore[union-attr]
    assert old.pk in {ip.pk for ip in ips}  # type: ignore[union-attr]
    assert PublicIP.objects.filter(state=PublicIpState.ATTACHED).count() == 2
