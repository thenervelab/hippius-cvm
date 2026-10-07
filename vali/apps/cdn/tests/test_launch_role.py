"""The CDN launch role (CDN plan V2): the ticket perm on every mint, the
measured role tokens, the `cdn_node` pin class and its carry-forward, the
role check at intake, and the node's user-data."""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml
from django.conf import settings

from apps.cdn import identity, userdata
from apps.cdn.models import CdnNode
from apps.images.tests.conftest import make_golden_bake  # noqa: F401 — fixture
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.effects import EffectError
from apps.orchestration.services import allowlist_pin, launch, migration_ticket, ticket_mint
from apps.orchestration.tests.factories import make_vm
from apps.orchestration.tests.test_allowlist_pin_carry_forward import (  # noqa: F401 — fixture
    _Harness,
    _ledger,
    harness,
)
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)
from apps.orchestration.tests.test_migration_ticket import (  # noqa: F401 — fixture
    _launch_record,
    _vault_and_mint,
)

from .conftest import CDN_TENANT

pytestmark = pytest.mark.django_db

NODE = "cdn-fr-7k2m"
_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


@pytest.fixture(autouse=True)
def _role_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", True)
    _fleet_key(1, "active")


def _fleet_key(version: int, state: str) -> None:
    from apps.cdn.models import CdnFleetKey

    CdnFleetKey.objects.create(
        version=version,
        x25519_public=bytes([version]) * 32,
        kbs_kid_hex="ab",
        kbs_signature=b"\x02" * 64,
        state=state,
    )


def _node(node_id: str = NODE) -> CdnNode:
    return CdnNode.objects.create(node_id=node_id, region="FR")


# ── identity ──────────────────────────────────────────────────────────


def _bound(node_id: str = NODE, *, tenant: str = CDN_TENANT) -> Vm:
    """A CDN node bound to its VM row, as its launch leaves it."""
    vm = make_vm(node_id, state=VmState.ACTIVE)
    Vm.objects.filter(pk=vm.pk).update(tenant_id=tenant)
    CdnNode.objects.create(node_id=node_id, region="FR", vm=vm)
    return Vm.objects.get(pk=vm.pk)


def test_no_node_no_role() -> None:
    assert identity.check_launch("cdn-fr-none", CDN_TENANT) is False
    assert identity.ticket_perms(("launch",), "cdn-fr-none") == ("launch",)


def test_a_node_of_the_cdn_tenant_is_a_cdn_launch() -> None:
    _node()
    assert identity.check_launch(NODE, CDN_TENANT) is True


def test_the_perm_follows_the_binding_only() -> None:
    """An unbound node (its launch has not created the row yet) gives no
    VM the perm; once bound, every mint carries it."""
    _node()
    assert identity.ticket_perms(("launch",), NODE) == ("launch",)
    vm = make_vm(NODE, state=VmState.ACTIVE)
    identity.bind_vm(NODE, vm)
    assert identity.ticket_perms(("launch",), NODE) == ("launch", "cdn-node", "cdn-fleet-v1")
    assert identity.ticket_perms(("launch", "supersede"), NODE) == (
        "launch",
        "supersede",
        "cdn-node",
        "cdn-fleet-v1",
    )


def test_a_node_binds_to_one_vm_row_only() -> None:
    _node()
    first = make_vm(NODE, state=VmState.ACTIVE)
    identity.bind_vm(NODE, first)
    identity.bind_vm(NODE, first)
    other = make_vm("vm-other", state=VmState.ACTIVE)
    with pytest.raises(identity.CdnRoleError):
        identity.bind_vm(NODE, other)
    Vm.objects.filter(pk=first.pk).update(vm_id="cdn-fr-renamed")
    with pytest.raises(identity.CdnRoleError):
        identity.bind_vm(NODE, make_vm(NODE, state=VmState.ACTIVE))


@pytest.mark.parametrize("who", ["launch", "row"])
def test_a_nodes_vm_id_is_reserved_to_the_cdn_tenant(who: str) -> None:
    _node()
    if who == "row":
        vm = make_vm(NODE, state=VmState.ACTIVE)
        Vm.objects.filter(pk=vm.pk).update(tenant_id="tenant-a")
    with pytest.raises(identity.CdnRoleError) as exc:
        identity.check_launch(NODE, "tenant-a" if who == "launch" else CDN_TENANT)
    assert exc.value.code == "cdn-node-id-reserved"


@pytest.mark.parametrize("flag", ["VALI_CDN_LAUNCH_ROLE", "VALI_CDN_ENABLED"])
def test_a_cdn_launch_refuses_while_the_role_is_off(
    monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    _bound()
    monkeypatch.setattr(settings, flag, False)
    with pytest.raises(identity.CdnRoleError) as exc:
        identity.check_launch(NODE, CDN_TENANT)
    assert exc.value.code == "cdn-role-disabled"
    # The perm is a fact of the bound VM, not of the flag: a re-mint of a
    # live CDN VM's ticket still carries it.
    assert identity.ticket_perms(("launch",), NODE) == ("launch", "cdn-node", "cdn-fleet-v1")


def test_the_role_does_not_follow_the_tenant_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    _bound()
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "renamed")
    assert identity.is_cdn_vm(NODE)
    assert identity.ticket_perms(("launch",), NODE) == ("launch", "cdn-node", "cdn-fleet-v1")


# ── measured cmdline ──────────────────────────────────────────────────


def _cmdline(spec: launch.LaunchSpec, **kw: Any) -> str:
    return launch._derive_measured_cmdline(
        spec,
        None,
        disk_gb=40,
        node_id_hex="a" * 64,
        validator_nonce_hex="b" * 64,
        telemetry_epoch=7,
        eol_nonce_hex="c" * 64,
        **kw,
    )


def test_a_cdn_node_cmdline_carries_the_role_tokens() -> None:
    tokens = _cmdline(_spec(), cdn_node=True).split()
    assert "hippius.cdn_node=1" in tokens
    assert "hippius.cdn_fleet_dir=/run/hippius/cdn-fleet" in tokens
    assert "systemd.import_credentials=no" in tokens


def test_a_tenant_cmdline_is_byte_identical() -> None:
    spec = _spec()
    assert _cmdline(spec) == _cmdline(spec, cdn_node=False)
    assert "cdn" not in _cmdline(spec)


def test_a_tenant_cmdline_never_carries_the_role_whatever_its_base() -> None:
    spec = _spec(cmdline="ro hippius.cdn_node=1 hippius.cdn_fleet_dir=/tmp/x")
    assert "cdn" not in _cmdline(spec)
    forced = _cmdline(spec, cdn_node=True).split()
    assert forced.count("hippius.cdn_node=1") == 1
    assert "hippius.cdn_fleet_dir=/run/hippius/cdn-fleet" in forced
    assert "hippius.cdn_fleet_dir=/tmp/x" not in forced


# ── launch_on_miner: ticket perm, pin class, refusal ──────────────────


@pytest.fixture
def _backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_BACKEND_URL", "https://api.example.test")


@pytest.fixture
def _bakes(make_golden_bake: Any) -> None:  # noqa: F811
    from django.utils import timezone

    from apps.images.models import GoldenImage

    for bake_id, profile in (("gb-cdn", "cdn-node"), ("gb-std", "standard")):
        make_golden_bake(bake_id=bake_id, profile=profile)
        GoldenImage.objects.create(
            image_name=f"img-{bake_id}",
            distro="debian",
            bake_id=bake_id,
            blessed_at=timezone.now(),
            restricted_tenant=CDN_TENANT if profile == "cdn-node" else "",
        )


def _cdn_spec(**overrides: Any) -> dict[str, Any]:
    """The launch spec of node NODE on the gb-cdn bake (images/tests
    `make_golden_bake` artifacts), with its own user-data."""
    base: dict[str, Any] = dict(
        vm_id=NODE,
        tenant_id=CDN_TENANT,
        bake_id="gb-cdn",
        disk_mode="golden_verity_overlay",
        kernel_sha256_hex="2" * 64,
        initrd_sha256_hex="3" * 64,
        rootfs_img_sha256_hex="a1" * 32,
        rootfs_verity_sha256_hex="b2" * 32,
        verity_root_hash_hex="c3" * 32,
        enable_netbird=True,
        userdata=userdata.render(NODE, "FR"),
        cmdline=settings.VALI_CDN_CMDLINE,
    )
    base.update(overrides)
    return base


def _launch(
    monkeypatch: pytest.MonkeyPatch, *, miner: int = 1, recompute: bool = True, **spec: Any
) -> tuple[launch.LaunchOutcome, list[tuple[str, ...]], list[dict[str, Any]]]:
    from apps.orchestration.services import launch_digest as launch_digest_svc
    from apps.orchestration.services import preflight as preflight_svc

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    if recompute:
        # Production: vali's own recompute, enforced (it equals the
        # miner's report here).
        monkeypatch.setattr(launch_digest_svc, "enforce", lambda: True)
        monkeypatch.setattr(launch_digest_svc, "is_enabled", lambda: True)
        monkeypatch.setattr(launch_digest_svc, "recompute_expected_digest", lambda **kw: "ab" * 48)
    monkeypatch.setattr(
        preflight_svc,
        "dispatch_preflight",
        lambda *a, **k: preflight_svc.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
            rootfs_data_path=f"/var/lib/hippius-miner/staging/{NODE}/rootfs.img",
            rootfs_hash_path=f"/var/lib/hippius-miner/staging/{NODE}/rootfs.verity",
        ),
    )
    minted: list[tuple[str, ...]] = []
    pins: list[dict[str, Any]] = []

    def _mint(args: ticket_mint.MintArgs) -> bytes:
        minted.append(tuple(args.lifecycle_perm))
        return b"cose"

    def _pin(**kw: Any) -> allowlist_pin.PinResult:
        pins.append(kw)
        return allowlist_pin.PinResult(new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x")

    monkeypatch.setattr(ticket_mint, "mint", _mint)
    monkeypatch.setattr(launch.allowlist_pin, "pin_measurement", _pin)
    monkeypatch.setattr(launch.allowlist_pin, "evict_superseded_measurements", lambda: 0)
    fields = {"userdata": _USERDATA, "auto_pin_allowlist": True, **spec}
    from apps.miners.models import MinerIdentity

    miner_id = f"miner-{chr(ord('a') + miner - 1)}"
    host = MinerIdentity.objects.filter(miner_id=miner_id).first() or _register_miner(miner)
    out = launch.launch_on_miner(_spec(**fields), host)
    return out, minted, pins


def test_a_cdn_launch_binds_mints_the_perm_and_pins_cdn_node(
    monkeypatch: pytest.MonkeyPatch, _bakes: None, _backend: None
) -> None:
    """Every relaunch path (power start, reboot recovery, resize, guest
    upgrade) runs this function: one rule for all (the `supersede` base is
    `ticket_perms`', above)."""
    _node()
    out, minted, pins = _launch(monkeypatch, **_cdn_spec())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert minted == [("launch", "cdn-node", "cdn-fleet-v1")]
    assert pins[0]["measurement_class"] == allowlist_pin.ALLOWLIST_CLASS_CDN_NODE
    assert CdnNode.objects.get(node_id=NODE).vm == Vm.objects.get(vm_id=NODE)
    # A relaunch of the bound node: the same.
    out, minted, pins = _launch(monkeypatch, **_cdn_spec())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert minted == [("launch", "cdn-node", "cdn-fleet-v1")]


def test_a_cdn_launch_on_a_guest_release_build_of_the_bake(
    monkeypatch: pytest.MonkeyPatch, _bakes: None, _backend: None
) -> None:
    from apps.orchestration.models import GuestComponentRelease, GuestInitrdBuild

    release = GuestComponentRelease.objects.create(
        version=3, commit="c" * 40, security_epoch=1, squashfs_sha256="d" * 64
    )
    GuestInitrdBuild.objects.create(
        release=release,
        source_bake_id="gb-cdn",
        family="debian",
        release_cpio_sha256="e" * 64,
        measurement={},
        base_initrd_sha256="3" * 64,
        kernel_sha256="2" * 64,
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
        initrd_sha256="4" * 64,
        s3_bucket="b",
        s3_key_prefix="guest/3/",
    )
    _node()
    out, minted, _ = _launch(monkeypatch, **_cdn_spec(initrd_sha256_hex="4" * 64))
    assert out.disposition == launch.ACCEPTED, out.emit
    assert minted == [("launch", "cdn-node", "cdn-fleet-v1")]


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"kernel_sha256_hex": "9" * 64}, "cdn-node-needs-cdn-image"),
        ({"initrd_sha256_hex": "9" * 64}, "cdn-node-needs-cdn-image"),
        ({"verity_root_hash_hex": "9" * 64}, "cdn-node-needs-cdn-image"),
        ({"rootfs_img_sha256_hex": "9" * 64}, "cdn-node-needs-cdn-image"),
        ({"disk_mode": "legacy_luks"}, "cdn-node-needs-cdn-image"),
        ({"bake_id": "gb-std"}, "cdn-node-needs-cdn-image"),
        ({"bake_id": ""}, "cdn-node-needs-cdn-image"),
        ({"userdata": b"#cloud-config\nruncmd: [ [ sh, -c, id ] ]\n"}, "cdn-node-userdata"),
        ({"enable_netbird": False}, "cdn-node-userdata"),
        ({"cmdline": "ro systemd.debug-shell=1"}, "cdn-node-needs-cdn-image"),
        ({"measurement_hex": "ab" * 48}, "cdn-node-needs-cdn-image"),
    ],
)
def test_a_cdn_launch_boots_only_the_cdn_image_with_its_own_userdata(
    monkeypatch: pytest.MonkeyPatch,
    _bakes: None,
    _backend: None,
    override: dict[str, Any],
    code: str,
) -> None:
    """Checked on the FINAL spec: a caller field that swaps an artifact or
    the user-data in never gets the role (and so never the fleet keyring)."""
    _node()
    out, minted, pins = _launch(monkeypatch, **_cdn_spec(**override))
    assert out.emit["outcome"] == "cdn-role-refused", out.emit
    assert code in out.emit["error"]
    assert minted == [] and pins == []
    assert not Vm.objects.filter(vm_id=NODE).exists()


def test_a_tenant_launch_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    out, minted, pins = _launch(monkeypatch)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert minted == [("launch",)]
    assert "measurement_class" not in pins[0]


def test_another_tenant_cannot_launch_a_nodes_vm_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _node()
    out, minted, pins = _launch(monkeypatch, vm_id=NODE, tenant_id="tenant-a")
    assert out.emit["outcome"] == "cdn-role-refused"
    assert "cdn-node-id-reserved" in out.emit["error"]
    assert minted == [] and pins == []
    assert not Vm.objects.filter(vm_id=NODE).exists()


def test_a_cdn_launch_refuses_while_the_role_is_off_and_stages_nothing(
    monkeypatch: pytest.MonkeyPatch, _bakes: None, _backend: None
) -> None:
    _node()
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", False)
    out, minted, pins = _launch(monkeypatch, **_cdn_spec())
    assert out.emit["outcome"] == "cdn-role-refused"
    assert "cdn-role-disabled" in out.emit["error"]
    assert minted == [] and pins == []
    assert not Vm.objects.filter(vm_id=NODE).exists()


# ── §25 / KBS-recovery re-mint ────────────────────────────────────────


@pytest.mark.parametrize(
    ("bound", "perms"), [(True, ("launch", "cdn-node", "cdn-fleet-v1")), (False, ("launch",))]
)
def test_the_remint_carries_the_perm_for_a_cdn_node(
    monkeypatch: pytest.MonkeyPatch,
    _vault_and_mint: dict[str, Any],  # noqa: F811
    bound: bool,
    perms: tuple[str, ...],
) -> None:
    from apps.miners.models import MinerIdentity

    vm = make_vm(NODE, generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    CdnNode.objects.create(node_id=NODE, region="FR", vm=vm if bound else None)
    MinerIdentity.objects.create(miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64)
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)
    # Even with the launch role off: the KBS needs the perm for the
    # VM's `cdn_node` measurement on every re-mint.
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", False)

    migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    assert tuple(_vault_and_mint["args"].lifecycle_perm) == perms


# ── allowlist: the class and the carry-forward (plan A.8) ─────────────

CDN_M = "8" * 96
TENANT_M = "2" * 96
NEXT_M = "9" * 96


def _cdn_vm(vm_id: str = NODE) -> Vm:
    return _bound(vm_id)


def test_a_new_cdn_node_pin_is_refused_while_the_role_is_off(
    harness: _Harness,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An older KBS rejects the whole artifact on an unknown class, so the
    first `cdn_node` entry waits for the flag (on once K1 is live)."""
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", False)
    with pytest.raises(EffectError, match="VALI_CDN_LAUNCH_ROLE"):
        allowlist_pin.pin_measurement(
            measurement_hex=CDN_M, measurement_class=allowlist_pin.ALLOWLIST_CLASS_CDN_NODE
        )
    assert harness.signed == []


def test_the_first_cdn_pin_does_not_break_the_next_pin(harness: _Harness) -> None:  # noqa: F811
    """THE A.8 regression: the carry-forward used to class every live VM
    `tenant` and veto any ledger row that disagreed, so the pin AFTER the
    first `cdn_node` one failed — for every VM in the fleet."""
    vm = _cdn_vm()
    allowlist_pin.pin_measurement(
        measurement_hex=CDN_M,
        measurement_class=allowlist_pin.ALLOWLIST_CLASS_CDN_NODE,
        ledger=allowlist_pin.PinLedger(vm_id=vm.vm_id),
    )
    assert harness.class_of(CDN_M) == "cdn_node"

    tenant_vm = make_vm("tenant-vm-1", state=VmState.ACTIVE)
    allowlist_pin.pin_measurement(
        measurement_hex=NEXT_M, ledger=allowlist_pin.PinLedger(vm_id=tenant_vm.vm_id)
    )
    assert harness.class_of(CDN_M) == "cdn_node"
    assert harness.class_of(NEXT_M) == "tenant"
    assert 'class = "cdn_node"' in harness.signed[-1]


def test_carry_forward_with_mixed_classes(harness: _Harness, monkeypatch) -> None:  # noqa: F811
    _cdn_vm()
    _ledger(NODE, CDN_M, cls="cdn_node")
    make_vm("tenant-vm-1", state=VmState.ACTIVE)
    _ledger("tenant-vm-1", TENANT_M, cls="tenant")
    # The flag going off later does not reclass a live CDN VM, nor stop the
    # carry: only NEW cdn_node pins wait for it.
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", False)

    assert allowlist_pin._query_carry_forward_classes() == {
        CDN_M: "cdn_node",
        TENANT_M: "tenant",
    }
    allowlist_pin.pin_measurement(measurement_hex=NEXT_M)
    assert harness.class_of(CDN_M) == "cdn_node"
    assert harness.class_of(TENANT_M) == "tenant"


def test_an_unbound_node_never_reclasses_a_vm(harness: _Harness) -> None:  # noqa: F811
    """A node naming a vm id is not a role: only the binding its own launch
    made is. Another tenant's VM on that id stays `tenant`."""
    vm = make_vm(NODE, state=VmState.ACTIVE)
    Vm.objects.filter(pk=vm.pk).update(tenant_id="tenant-a")
    _node()
    _ledger(NODE, TENANT_M, cls="tenant")

    assert allowlist_pin._query_carry_forward_classes() == {TENANT_M: "tenant"}
    allowlist_pin.pin_measurement(measurement_hex=NEXT_M)
    assert harness.class_of(TENANT_M) == "tenant"


def test_a_measurement_keeps_its_recorded_class(harness: _Harness) -> None:  # noqa: F811
    """A bound VM's measurement pinned `tenant` (before the binding) stays
    `tenant`: reclassing it would trip the veto for every pin."""
    _cdn_vm()
    _ledger(NODE, TENANT_M, cls="tenant")
    _ledger(NODE, CDN_M, cls="cdn_node")
    assert allowlist_pin._query_carry_forward_classes() == {
        TENANT_M: "tenant",
        CDN_M: "cdn_node",
    }
    allowlist_pin.pin_measurement(measurement_hex=NEXT_M)


def test_an_unrecorded_measurement_follows_the_binding(harness: _Harness) -> None:  # noqa: F811
    from apps.orchestration.tests.factories import make_launch_record

    vm = _cdn_vm()
    make_launch_record(vm, measurement_hex=CDN_M)
    assert allowlist_pin._query_carry_forward_classes() == {CDN_M: "cdn_node"}


def test_the_tenant_setting_does_not_reclass(
    harness: _Harness,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _cdn_vm()
    _ledger(NODE, CDN_M, cls="cdn_node")
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "")
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    allowlist_pin.pin_measurement(measurement_hex=NEXT_M)
    assert harness.class_of(CDN_M) == "cdn_node"


def test_the_ledger_veto_still_fires_across_vms(harness: _Harness) -> None:  # noqa: F811
    """Another row recording the CDN VM's measurement under another class
    (here a host-attestor release's audit row) still vetoes the pin."""
    _cdn_vm()
    _ledger(NODE, CDN_M, cls="cdn_node")
    _ledger("host-attestor-release", CDN_M, cls="host_attestor")
    with pytest.raises(EffectError, match="was pinned as 'host_attestor' but resolves to"):
        allowlist_pin.pin_measurement(measurement_hex=NEXT_M)


def test_a_measurement_claimed_by_a_cdn_vm_and_another_vm_is_refused(
    harness: _Harness,  # noqa: F811
) -> None:
    _cdn_vm()
    _ledger(NODE, CDN_M)
    make_vm("tenant-vm-1", state=VmState.ACTIVE)
    _ledger("tenant-vm-1", CDN_M)
    with pytest.raises(EffectError, match="BOTH a CDN node and another VM"):
        allowlist_pin.pin_measurement(measurement_hex=NEXT_M)


def test_a_cdn_node_entry_in_the_base_manifest_parses() -> None:
    text = (
        "schema = 1\nepoch = 1\n\n[[entries]]\n"
        f'measurement_hex = "{CDN_M}"\n'
        'accepted_l1_kids_hex = ["6c31"]\naccepted_kbs_response_kids_hex = ["6b6273"]\n'
        'class = "cdn_node"\n'
    )
    assert allowlist_pin._manifest_entry_classes(text) == {CDN_M: "cdn_node"}


# ── intake: role check and image ──────────────────────────────────────


def _intake(intent: dict[str, Any], *, cdn_node: bool) -> None:
    from apps.orchestration import launch_jobs

    launch_jobs._check_cdn_role(intent, cdn_node=cdn_node)


@pytest.mark.parametrize(
    ("tenant", "bake", "cdn_node", "code"),
    [
        # The HTTP API never launches a node's vm id, whoever calls it.
        (CDN_TENANT, "gb-cdn", False, "cdn-node-id-reserved"),
        ("tenant-a", "gb-cdn", True, "cdn-node-id-reserved"),
        (CDN_TENANT, "gb-std", True, "cdn-node-needs-cdn-image"),
        (CDN_TENANT, "", True, "cdn-node-needs-cdn-image"),
    ],
)
def test_intake_role_refusals(
    _bakes: None, tenant: str, bake: str, cdn_node: bool, code: str
) -> None:
    from apps.orchestration import launch_jobs

    _node()
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _intake({"vm_id": NODE, "tenant_id": tenant, "bake_id": bake}, cdn_node=cdn_node)
    assert exc.value.category == code


def test_intake_refuses_a_fleet_launch_no_node_names() -> None:
    from apps.orchestration import launch_jobs

    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _intake({"vm_id": NODE, "tenant_id": CDN_TENANT}, cdn_node=True)
    assert exc.value.category == "cdn-node-id-reserved"


def test_intake_accepts_a_cdn_node_on_its_image(
    _bakes: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import launch_jobs

    _node()
    _intake({"vm_id": NODE, "tenant_id": CDN_TENANT, "bake_id": "gb-cdn"}, cdn_node=True)
    _intake({"vm_id": "vm-other", "tenant_id": "tenant-a", "bake_id": ""}, cdn_node=False)
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", False)
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _intake({"vm_id": NODE, "tenant_id": CDN_TENANT, "bake_id": "gb-cdn"}, cdn_node=True)
    assert exc.value.category == "cdn-role-disabled"


def test_start_launch_runs_the_role_check() -> None:
    import inspect

    from apps.orchestration import launch_jobs

    source = inspect.getsource(launch_jobs.start_launch)
    assert source.index("_resolve_bake(intent)") < source.index("_check_cdn_role(intent")


# ── user-data ─────────────────────────────────────────────────────────


def test_userdata_names_the_node_and_enrols_netbird(_backend: None) -> None:
    raw = userdata.render(NODE, "FR")
    # As the launch substitutes it (`launch.launch_on_miner`).
    doc = yaml.safe_load(
        raw.replace(b"{{NETBIRD_SETUP_KEY}}", b"setup-key").replace(
            b"{{NETBIRD_HOSTNAME}}", f"hippius-tenant-{NODE}".encode()
        )
    )
    files = {f["path"]: f for f in doc["write_files"]}
    identity_doc = json.loads(files["/run/hippius/cdn-node.json"]["content"])
    # The cdn-agent's identity file is a closed field set.
    assert identity_doc == {
        "node_id": NODE,
        "region": "FR",
        "backend_url": "https://api.example.test",
    }
    assert files["/var/lib/cloud/seed/nocloud/netbird-setup-key"]["content"] == "setup-key\n"
    assert doc["runcmd"][0][:2] == ["netbird", "up"]
    assert f"--hostname=hippius-tenant-{NODE}" in doc["runcmd"][0]
    assert "rm -f" in doc["runcmd"][-1][-1]
    assert doc["users"] == [] and doc["ssh_pwauth"] is False
    # No software, and none of the tenant template's public-IP inbound unit.
    assert b"public-ip-inbound" not in raw and b"apt" not in raw and b"curl" not in raw
    assert (
        launch.check_netbird_userdata(
            raw, enable=True, hostname_template="hippius-tenant-{vm_id}", vm_id=NODE
        )
        is None
    )
    assert userdata.render(NODE, "FR") == raw


@pytest.mark.parametrize(
    "url", ["", "http://api.example.test", "https://a'b.test", "https://x.test/?q=1"]
)
def test_userdata_refuses_a_bad_backend_url(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_BACKEND_URL", url)
    with pytest.raises(userdata.CdnUserdataError):
        userdata.render(NODE, "FR")


@pytest.mark.parametrize(("node_id", "region"), [("CDN-FR", "FR"), (NODE, "fr"), ("a/b", "FR")])
def test_userdata_refuses_a_bad_identity(_backend: None, node_id: str, region: str) -> None:
    with pytest.raises(userdata.CdnUserdataError):
        userdata.render(node_id, region)


def test_a_cdn_launch_needs_valis_own_digest(
    monkeypatch: pytest.MonkeyPatch, _bakes: None, _backend: None
) -> None:
    """In the C2 WARN mode the miner's digest would be pinned: never for a
    measurement that gets the fleet keyring."""
    _node()
    out, minted, pins = _launch(monkeypatch, recompute=False, **_cdn_spec())
    assert out.emit["outcome"] == "cdn-role-refused"
    assert "cdn-node-unverified-digest" in out.emit["error"]
    assert pins == [] and minted == []


def test_a_cdn_launch_must_pin(
    monkeypatch: pytest.MonkeyPatch, _bakes: None, _backend: None
) -> None:
    _node()
    out, _, pins = _launch(monkeypatch, **_cdn_spec(auto_pin_allowlist=False))
    assert out.emit["outcome"] == "cdn-role-refused" and pins == []


def test_a_node_never_adopts_a_vm_row_older_than_itself() -> None:
    """A launch of the id before the node existed made that row, and its
    guest got the id's first-write-wins lifecycle seed."""
    import datetime as dt

    vm = make_vm(NODE, state=VmState.ACTIVE)
    Vm.objects.filter(pk=vm.pk).update(created_at=vm.created_at - dt.timedelta(minutes=5))
    vm.refresh_from_db()
    _node()
    with pytest.raises(identity.CdnRoleError) as exc:
        identity.bind_vm(NODE, vm)
    assert exc.value.code == "cdn-node-id-reserved"
    assert CdnNode.objects.get(node_id=NODE).vm is None


def test_the_ticket_names_every_published_fleet_version() -> None:
    _fleet_key(2, "pending")
    _fleet_key(3, "retired")
    _bound()
    assert identity.ticket_perms(("launch",), NODE) == (
        "launch",
        "cdn-node",
        "cdn-fleet-v1",
        "cdn-fleet-v2",
    )


def test_a_cdn_launch_needs_one_to_four_fleet_versions() -> None:
    from apps.cdn.models import CdnFleetKey

    _node()
    CdnFleetKey.objects.all().delete()
    with pytest.raises(identity.CdnRoleError) as exc:
        identity.check_launch(NODE, CDN_TENANT)
    assert exc.value.code == "cdn-fleet-no-version"
    for v in range(1, 6):
        _fleet_key(v, "retiring")
    with pytest.raises(identity.CdnRoleError) as exc:
        identity.check_launch(NODE, CDN_TENANT)
    assert exc.value.code == "cdn-fleet-too-many-versions"
