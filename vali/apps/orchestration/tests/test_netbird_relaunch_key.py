"""NetBird setup keys a tenant's root can read back must not be live.

The setup key rides the userdata, and the guest's root reads it back from
cloud-init's state. A first launch's key is consumed by the enrolment
(`usage_limit=1`); a relaunch's was not, and stayed a live credential for
its whole TTL. Pins, per launch path:

- first launch: a persistent key at the caller's TTL, as before;
- reboot-recovery / power start of a golden VM whose guest provably holds
  its identity (a bound peer NetBird still holds, and that is persistent —
  `ephemeral: false` at NetBird, or minted persistent by vali): NOTHING
  minted, the userdata carries an inert UUID;
- any relaunch that cannot prove it: an ephemeral key capped at
  `RELAUNCH_NETBIRD_KEY_TTL_S`, deleted by `revoke_unneeded_relaunch_keys`
  as soon as the guest is back on its own peer;
- §25: re-binds the userdata already staged, mints nothing.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmNetbirdKey, VmPowerState
from apps.orchestration import effects, netbird_binding
from apps.orchestration.services import launch, migration_ticket

from .test_customer_keys_launch import (  # noqa: F401 — `harness` / `remint` are fixtures
    _measured,
    _miner,
    _pinned_vm,
    _spec,
    _spec_json,
    _succeeded_job,
    harness,
    remint,
)

pytestmark = pytest.mark.django_db

VM = "vm-nb-relaunch"
USERDATA = (
    b"#cloud-config\nruncmd:\n"
    b"  - [ netbird, up, --setup-key={{NETBIRD_SETUP_KEY}}, --hostname={{NETBIRD_HOSTNAME}} ]\n"
)
LIVE_KEY = b"live-secret-key"
INERT = launch.NO_NETBIRD_SETUP_KEY.encode()


@pytest.fixture
def minted(monkeypatch) -> list[dict]:
    calls: list[dict] = []

    def mint(**kw: object) -> effects.MintedSetupKey:
        calls.append(kw)
        return effects.MintedSetupKey(id=f"sk-{len(calls)}", key=LIVE_KEY.decode())

    monkeypatch.setattr(effects, "mint_netbird_setup_key", mint)
    return calls


@pytest.fixture
def staged(monkeypatch) -> list[bytes]:
    """The canonical userdata bytes each launch hands the KBS."""
    seen: list[bytes] = []
    real = launch._stage_userdata

    def spy(mount: str, path: str, vm_id: str, userdata: bytes):
        seen.append(bytes(userdata))
        return real(mount, path, vm_id, userdata)

    monkeypatch.setattr(launch, "_stage_userdata", spy)
    return seen


@pytest.fixture
def peers(monkeypatch) -> list[dict]:
    """What NetBird's peer listing returns; a test appends records."""
    listing: list[dict] = []
    monkeypatch.setattr(effects, "list_netbird_peers", lambda: list(listing))
    return listing


def _nb_spec(vm_id: str = VM, **overrides) -> launch.LaunchSpec:
    return _spec(vm_id=vm_id, mode="hippius", enable_netbird=True, userdata=USERDATA, **overrides)


def _vm(vm_id: str = VM) -> Vm:
    return _pinned_vm(vm_id, "hippius")


def _key(vm: Vm, *, persistent: bool = True, peer_id: str = "peer-1") -> VmNetbirdKey:
    """The VM's first-launch key, (un)bound."""
    return VmNetbirdKey.objects.create(
        vm=vm,
        setup_key_id="sk-first",
        persistent=persistent,
        expires_at=timezone.now() - timedelta(hours=1),
        peer_id=peer_id,
        settled_at=timezone.now() if peer_id else None,
    )


def _relaunchable(vm: Vm, monkeypatch) -> None:
    """What reboot-recovery / power start rebuild the spec from."""
    _miner()
    spec_json = {**_spec_json(vm.vm_id, "hippius"), "enable_netbird": True}
    _succeeded_job(vm.vm_id, spec_json, measured_cmdline=_measured("hippius"))
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a: bytearray(USERDATA))


# ── first launch ──────────────────────────────────────────────────────


@pytest.mark.usefixtures("harness")
def test_a_first_launch_mints_a_persistent_key_at_the_callers_ttl(minted, staged) -> None:
    out = launch.launch_on_miner(_nb_spec(), _miner())

    assert out.disposition == launch.ACCEPTED, out.emit
    (kw,) = minted
    assert (kw["persistent"], kw["expires_in_seconds"]) == (True, 3600)
    (ud,) = staged
    assert LIVE_KEY in ud


# ── reboot-recovery / power start ─────────────────────────────────────


@pytest.mark.usefixtures("harness")
def test_reboot_recovery_of_an_enrolled_guest_mints_no_key(
    monkeypatch, minted, staged, peers
) -> None:
    from apps.orchestration import service

    vm = _vm()
    _key(vm)
    peers.append({"id": "peer-1", "connected": False})
    _relaunchable(vm, monkeypatch)

    assert service._reboot_recovery_relaunch(vm, "miner-ck") is True

    assert minted == []
    assert list(VmNetbirdKey.objects.values_list("setup_key_id", flat=True)) == ["sk-first"]
    (ud,) = staged
    assert INERT in ud and LIVE_KEY not in ud
    assert b"{{NETBIRD_SETUP_KEY}}" not in ud
    # The hostname is still substituted: the guest logs in under its name.
    assert f"--hostname=hippius-tenant-{VM}".encode() in ud


@pytest.mark.usefixtures("harness")
def test_power_start_of_an_enrolled_guest_mints_no_key(monkeypatch, minted, staged, peers) -> None:
    from apps.orchestration.services import power

    vm = _vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    vm.refresh_from_db()
    _key(vm)
    peers.append({"id": "peer-1", "ephemeral": False, "connected": False})
    _relaunchable(vm, monkeypatch)

    assert power.start_vm(vm).power_state == VmPowerState.RUNNING

    assert minted == []
    (ud,) = staged
    assert INERT in ud and LIVE_KEY not in ud


@pytest.mark.usefixtures("harness")
def test_a_peer_flipped_persistent_at_netbird_counts_as_proof(
    monkeypatch, minted, staged, peers
) -> None:
    """A first-launch key minted ephemeral (before tenant peers became
    persistent) whose peer was flipped `ephemeral: false` since."""
    from apps.orchestration import service

    vm = _vm()
    _key(vm, persistent=False)
    peers.append({"id": "peer-1", "ephemeral": False, "connected": False})
    _relaunchable(vm, monkeypatch)

    assert service._reboot_recovery_relaunch(vm, "miner-ck") is True

    assert minted == []
    (ud,) = staged
    assert INERT in ud


@pytest.mark.usefixtures("harness")
@pytest.mark.parametrize(
    ("persistent", "peer_id", "listing"),
    [
        # the guest never enrolled (or its binding aged out unbound)
        (True, "", []),
        # vali minted it persistent, but NetBird no longer holds the peer
        # (deleted by an admin, a cleanup, a revoke): the guest must re-enrol
        (True, "peer-1", []),
        # vali minted it persistent, but NetBird's record says ephemeral
        (True, "peer-1", [{"id": "peer-1", "ephemeral": True}]),
        # its only peer is ephemeral: NetBird may GC it, the guest re-enrols
        (False, "peer-1", [{"id": "peer-1", "ephemeral": True}]),
        # its peer is gone from NetBird
        (False, "peer-1", []),
        # NetBird does not say
        (False, "peer-1", [{"id": "peer-1"}]),
        # a peer NAMED like the VM proves nothing: only bound ids count
        (False, "", [{"id": "peer-x", "name": f"hippius-tenant-{VM}", "ephemeral": False}]),
    ],
)
def test_a_relaunch_that_cannot_prove_the_identity_gets_a_short_key(
    monkeypatch, minted, staged, peers, persistent, peer_id, listing
) -> None:
    from apps.orchestration import service

    vm = _vm()
    _key(vm, persistent=persistent, peer_id=peer_id)
    peers.extend(listing)
    _relaunchable(vm, monkeypatch)

    assert service._reboot_recovery_relaunch(vm, "miner-ck") is True

    (kw,) = minted
    assert kw["persistent"] is False
    assert kw["expires_in_seconds"] == launch.RELAUNCH_NETBIRD_KEY_TTL_S == 600
    row = VmNetbirdKey.objects.get(setup_key_id="sk-1")
    assert row.expires_at <= timezone.now() + timedelta(seconds=600)
    (ud,) = staged
    assert LIVE_KEY in ud


@pytest.mark.usefixtures("harness")
@pytest.mark.parametrize("persistent", [True, False])
def test_a_netbird_outage_proves_nothing(monkeypatch, minted, staged, persistent) -> None:
    from apps.orchestration import service

    def down() -> list[dict]:
        raise effects.EffectUnavailable("netbird: down")

    monkeypatch.setattr(effects, "list_netbird_peers", down)
    vm = _vm()
    _key(vm, persistent=persistent)
    _relaunchable(vm, monkeypatch)

    assert service._reboot_recovery_relaunch(vm, "miner-ck") is True
    (kw,) = minted
    assert kw["expires_in_seconds"] == launch.RELAUNCH_NETBIRD_KEY_TTL_S


@pytest.mark.usefixtures("harness")
def test_a_re_place_or_retried_first_launch_is_not_a_relaunch(minted, staged) -> None:
    """Without `require_existing_disks` the miner may boot a blank overlay."""
    _key(_vm())

    out = launch.launch_on_miner(_nb_spec(), _miner())

    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(minted) == 1


def test_a_legacy_relaunch_still_gets_a_key() -> None:
    """A legacy VM's identity lives on the order-staged image, not on a disk
    the miner's relaunch check guarantees."""
    _key(_vm())
    spec = launch.LaunchSpec(
        tenant_id="t",
        user_id="u",
        vm_id=VM,
        lease_id="lease-1",
        s3_bucket="b",
        s3_key_prefix="tenant/x/",
        luks_disk_sha256_hex="a" * 64,
        kernel_sha256_hex="a" * 64,
        initrd_sha256_hex="a" * 64,
        luks_header_sha256_hex="a" * 64,
        flavor="small",
        cmdline="ro",
        kek_bytes=None,
        userdata=USERDATA,
    )
    assert spec.disk_mode == "legacy_luks"
    assert launch._netbird_relaunch_needs_no_key(spec, require_existing_disks=True) is False


def test_another_vms_bound_key_proves_nothing() -> None:
    _key(_vm())
    other = _nb_spec(vm_id="vm-someone-else")
    assert launch._netbird_relaunch_needs_no_key(other, require_existing_disks=True) is False


def test_the_placeholder_is_a_uuid_netbird_never_issues() -> None:
    assert uuid.UUID(launch.NO_NETBIRD_SETUP_KEY).int == 0


# ── §25 ───────────────────────────────────────────────────────────────


def test_a_migration_remint_mints_no_setup_key(
    monkeypatch,
    remint: dict,  # noqa: F811 — the imported fixture
) -> None:
    def refuse(**_kw: object) -> effects.MintedSetupKey:
        raise AssertionError("§25 must not mint a NetBird setup key")

    monkeypatch.setattr(effects, "mint_netbird_setup_key", refuse)
    _miner()
    vm = _vm("vm-nb-moved")
    spec_json = {**_spec_json(vm.vm_id, "hippius"), "enable_netbird": True}
    _succeeded_job(vm.vm_id, spec_json, measured_cmdline=_measured("hippius"))

    assert migration_ticket.remint_dest_ticket(vm, dest_node_id="miner-ck", new_gen=2) == b"cose"
    assert len(remint["mints"]) == 1
    assert not VmNetbirdKey.objects.exists()


# ── revoking a relaunch key the guest did not need ────────────────────


def _open_relaunch_key(vm: Vm, *, minted_ago: timedelta = timedelta(minutes=2)) -> VmNetbirdKey:
    row = VmNetbirdKey.objects.create(
        vm=vm,
        setup_key_id="sk-relaunch",
        persistent=False,
        expires_at=timezone.now() + timedelta(minutes=8),
    )
    VmNetbirdKey.objects.filter(pk=row.pk).update(created_at=timezone.now() - minted_ago)
    row.refresh_from_db()
    return row


@pytest.fixture
def deleted(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        effects, "delete_netbird_setup_key", lambda key_id, *, label: calls.append(key_id)
    )
    return calls


def _seen(delta: timedelta) -> str:
    return (timezone.now() + delta).isoformat().replace("+00:00", "Z")


def test_a_relaunch_key_is_deleted_once_the_guest_is_back_on_its_peer(deleted) -> None:
    vm = _vm()
    _key(vm)
    row = _open_relaunch_key(vm)
    listing = [{"id": "peer-1", "connected": True, "last_seen": _seen(timedelta(0))}]

    assert netbird_binding.revoke_unneeded_relaunch_keys(listing) == 1

    assert deleted == ["sk-relaunch"]
    row.refresh_from_db()
    # Still open: a peer that enrolled with it meanwhile is still bound.
    assert row.settled_at is None and row.expires_at <= timezone.now()
    # …and the next pass does not delete it again.
    assert netbird_binding.revoke_unneeded_relaunch_keys(listing) == 0
    assert deleted == ["sk-relaunch"]


@pytest.mark.parametrize(
    "peer",
    [
        {"id": "peer-1", "connected": False, "last_seen": "now"},
        # connected, but not seen since the key was minted: the old session
        {"id": "peer-1", "connected": True, "last_seen": "an hour ago"},
        {"id": "peer-1", "connected": True, "last_seen": "0001-01-01T00:00:00Z"},
        # a connected peer that is not one of this VM's bound peers
        {"id": "peer-other", "connected": True, "last_seen": "now"},
    ],
)
def test_a_relaunch_key_is_kept_while_the_guest_may_still_need_it(deleted, peer) -> None:
    when = {"now": _seen(timedelta(0)), "an hour ago": _seen(-timedelta(hours=1))}
    peer = {**peer, "last_seen": when.get(peer["last_seen"], peer["last_seen"])}
    vm = _vm()
    _key(vm)
    _open_relaunch_key(vm)

    assert netbird_binding.revoke_unneeded_relaunch_keys([peer]) == 0
    assert deleted == []


def test_a_used_or_first_launch_key_is_never_revoked(deleted) -> None:
    vm = _vm()
    _key(vm)
    used = _open_relaunch_key(vm)
    VmNetbirdKey.objects.filter(pk=used.pk).update(peer_id="peer-2", settled_at=timezone.now())
    VmNetbirdKey.objects.create(
        vm=vm,
        setup_key_id="sk-first-open",
        persistent=True,
        expires_at=timezone.now() + timedelta(minutes=30),
    )
    listing = [{"id": "peer-1", "connected": True, "last_seen": _seen(timedelta(0))}]

    assert netbird_binding.revoke_unneeded_relaunch_keys(listing) == 0
    assert deleted == []


def test_a_failed_delete_is_retried_next_pass(monkeypatch) -> None:
    def fail(key_id: str, *, label: str) -> None:
        raise effects.EffectError("netbird: 500")

    monkeypatch.setattr(effects, "delete_netbird_setup_key", fail)
    vm = _vm()
    _key(vm)
    row = _open_relaunch_key(vm)
    listing = [{"id": "peer-1", "connected": True, "last_seen": _seen(timedelta(0))}]

    assert netbird_binding.revoke_unneeded_relaunch_keys(listing) == 0
    row.refresh_from_db()
    assert row.expires_at > timezone.now()
