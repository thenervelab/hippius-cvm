"""P9/#18 — an operator-forced launch must not be invisible to the
control plane.

`vali_create_vm` called `launch.launch_on_miner` DIRECTLY, so it produced
a real, attested, RUNNING CVM while writing neither a `lifecycle.Vm` row
nor a `scheduler.Placement`. Everything that acts on a VM keys off one of
those two tables, so an unbound VM was:

- **un-crypto-erasable** — `DecommissionJob.vm` is a non-null FK and
  `DecommissionStartView` 404s on a missing row, so §24 could never run
  and its Vault-Transit KEK stayed live forever;
- **uncounted** — `scheduler.service.decision_inputs` sums load /
  committed RAM / committed CPUs over ACTIVE `Placement` rows only, so
  the miner was oversubscribed by exactly the forced VMs;
- **outside every sweep** — `sweep_guest_liveness`,
  `reboot_recovery_once`, `verify_netbird_enrolments` and
  `reclaim_migrated_sources` all iterate `Vm`.

These tests pin the three halves of the fix:

1. `launch_on_miner` — the SHARED choreography — creates the row, so
   "launched by vali but unknown to vali" is unrepresentable for EVERY
   caller, not just the ones that remember.
2. `launch_on_named_miner` records + settles the forced `Placement`.
3. `sweep_unbound_launches` SURFACES any that already exist and ADOPTS
   NOTHING (adoption is what makes a VM crypto-erasable).
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration.effects import EffectUnavailable
from apps.orchestration.services import launch, vault_kv
from apps.scheduler.models import Placement, PlacementStatus

from apps.scheduler.tests.factories import node_id  # isort: skip

pytestmark = pytest.mark.django_db


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-unbound",
        user_id="u-1",
        vm_id="vm-unbound-1",
        lease_id="lease-1",
        s3_bucket="b",
        s3_key_prefix="tenant/x/",
        luks_disk_sha256_hex="a" * 64,
        kernel_sha256_hex="a" * 64,
        initrd_sha256_hex="a" * 64,
        luks_header_sha256_hex="a" * 64,
        flavor="small",
        cmdline="ro",
        kek_bytes=b"\x00" * 32,
        userdata=b"#cloud-config\n",
        enable_netbird=False,
    )
    base.update(overrides)
    return launch.LaunchSpec(**base)


def _miner(seed: int = 1, *, netbird_ip: str | None = None) -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=f"miner-{chr(ord('a') + seed - 1)}",
        pubkey_hex=format(seed, "064x"),
        platform_id=f"{seed:02x}" + "cd" * 15,
        netbird_ip="100.64.0." + str(seed) if netbird_ip is None else netbird_ip,
        chain_node_id=node_id(seed),
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


def _fail_at_first_vault_call(monkeypatch) -> None:
    """Make the launch die at its FIRST external effect (Vault), so a test
    can assert on what the choreography persisted BEFORE it."""

    def _boom(*a, **kw):
        raise EffectUnavailable("vault down (test)")

    monkeypatch.setattr(vault_kv, "ensure_transit_key", _boom)


def _outcome(disposition: str) -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=disposition,
        emit={"ok": disposition == launch.ACCEPTED, "outcome": "x"},
        exit_code=0 if disposition == launch.ACCEPTED else 2,
        ticket_id="tk-x" if disposition == launch.ACCEPTED else None,
    )


# ── 1. the shared choreography always creates the row ────────────────


def test_launch_on_miner_creates_the_vm_row_for_a_caller_that_did_not(
    monkeypatch,
) -> None:
    """THE root-cause claim. `launch_on_miner` is what `vali_create_vm`
    called directly; on its own it created no `Vm` row, so the CLI's VM
    was unreachable by §24 crypto-erase forever."""
    _fail_at_first_vault_call(monkeypatch)
    miner = _miner()

    out = launch.launch_on_miner(_spec(vm_id="vm-row-1"), miner)

    assert out.disposition == launch.TERMINAL  # died at Vault, as staged
    vm = Vm.objects.get(vm_id="vm-row-1")
    assert vm.state == VmState.ACTIVE
    assert vm.tenant_id == "t-unbound"
    assert vm.lease_id == "lease-1"


def test_the_row_exists_before_any_secret_is_staged(monkeypatch) -> None:
    """Ordering claim: there must be NO window in which a vm_id has Vault
    secrets / a ticket / a domain but no row. Assert the row is already
    there at the moment of the first Vault call."""
    seen: dict[str, bool] = {}
    miner = _miner()

    def _boom(*a, **kw):
        seen["row_at_first_vault_call"] = Vm.objects.filter(
            vm_id="vm-order-1"
        ).exists()
        raise EffectUnavailable("vault down (test)")

    monkeypatch.setattr(vault_kv, "ensure_transit_key", _boom)

    launch.launch_on_miner(_spec(vm_id="vm-order-1"), miner)

    assert seen["row_at_first_vault_call"] is True


@pytest.mark.parametrize(
    ("kwargs", "miner_kwargs"),
    [
        ({"vm_id": "Bad/../Id"}, {}),
        ({"vm_id": "vm-no-nb"}, {"netbird_ip": ""}),
    ],
)
def test_no_row_when_the_caller_config_is_refused(kwargs, miner_kwargs) -> None:
    """A `LaunchConfigError` is caller-fixable and nothing happened — it
    must not leave a row behind. (The vm_id charset gate in particular:
    the row must never be created from an unvalidated vm_id.)"""
    miner = _miner(**miner_kwargs)
    with pytest.raises(launch.LaunchConfigError):
        launch.launch_on_miner(_spec(**kwargs), miner)
    assert Vm.objects.count() == 0


def test_existing_row_is_never_clobbered(monkeypatch) -> None:
    """`_ensure_vm_row` is get-or-create: reboot-recovery and a §25-migrated
    VM (generation >= 2, host already set) must survive the new call
    untouched, or a relaunch would silently roll a VM's generation back to
    1 and strand its host binding."""
    _fail_at_first_vault_call(monkeypatch)
    Vm.objects.create(
        vm_id="vm-keep-1",
        lease_id="lease-old",
        state=VmState.ACTIVE,
        generation=7,
        signing_generation=1,
        host="miner-preexisting",
        lifecycle_vk=bytes(32),
    )

    launch.launch_on_miner(_spec(vm_id="vm-keep-1", lease_id="lease-new"), _miner())

    vm = Vm.objects.get(vm_id="vm-keep-1")
    assert vm.generation == 7
    assert vm.host == "miner-preexisting"
    assert vm.lease_id == "lease-old"
    assert Vm.objects.filter(vm_id="vm-keep-1").count() == 1


# ── 2. the forced placement ──────────────────────────────────────────


def test_forced_launch_records_an_active_placement(monkeypatch) -> None:
    """Capacity claim: the #668 fit gate counts ACTIVE `Placement` rows.
    A forced launch that records none makes the miner look emptier than
    it is."""
    from apps.scheduler import service as scheduler_service

    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED)
    )
    miner = _miner()
    actor = launch.resolve_forced_launch_principal()

    out = launch.launch_on_named_miner(
        _spec(vm_id="vm-cap-1"), miner, decided_by=actor
    )

    assert out.disposition == launch.ACCEPTED
    p = Placement.objects.get(vm__vm_id="vm-cap-1")
    assert p.status == PlacementStatus.BOUND.value
    assert p.miner_node_id == node_id(1)
    assert p.resource_class == "small"
    assert p.vm_family == "t-unbound"
    assert p.owner == "u-1"
    # The fit gate now SEES it: load + committed resources are non-zero.
    _cap, load, family = scheduler_service.decision_inputs("t-unbound")
    assert load[node_id(1)] == 1
    assert node_id(1) in family


def test_forced_launch_stamps_the_vm_host(monkeypatch) -> None:
    """`vm.host` is what §24 destroy / the EOL relay / §25 source-routing
    resolve from. A forced launch must set it like a scheduled one."""
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED)
    )
    launch.launch_on_named_miner(
        _spec(vm_id="vm-host-f1"),
        _miner(),
        decided_by=launch.resolve_forced_launch_principal(),
    )
    assert Vm.objects.get(vm_id="vm-host-f1").host == "miner-a"


def test_a_rejected_forced_launch_fails_the_placement(monkeypatch) -> None:
    """Otherwise a failed forced launch would hold a capacity slot (and the
    one-active-placement index) forever."""
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.TERMINAL)
    )
    out = launch.launch_on_named_miner(
        _spec(vm_id="vm-fail-1"),
        _miner(),
        decided_by=launch.resolve_forced_launch_principal(),
    )
    assert out.disposition == launch.TERMINAL
    p = Placement.objects.get(vm__vm_id="vm-fail-1")
    assert p.status == PlacementStatus.FAILED.value
    assert p.failed_at is not None
    # Slot freed — the fit gate no longer counts it.
    from apps.scheduler import service as scheduler_service

    _cap, load, _fam = scheduler_service.decision_inputs("t-unbound")
    assert load.get(node_id(1), 0) == 0


def test_second_forced_launch_of_a_live_vm_is_refused(monkeypatch) -> None:
    """A vm_id the control plane believes is LIVE must not be force-launched
    again — that is a duplicate CVM on possibly a different miner, and only
    one of them would ever be reachable by §24."""
    calls: list[str] = []

    def _fake(spec, miner):
        calls.append(spec.vm_id)
        return _outcome(launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", _fake)
    actor = launch.resolve_forced_launch_principal()
    launch.launch_on_named_miner(_spec(vm_id="vm-dup-1"), _miner(1), decided_by=actor)

    with pytest.raises(launch.ActivePlacementConflict):
        launch.launch_on_named_miner(
            _spec(vm_id="vm-dup-1"), _miner(2), decided_by=actor
        )

    # …and it REFUSED BEFORE dispatching — no second launch happened.
    assert calls == ["vm-dup-1"]
    assert Placement.objects.filter(vm__vm_id="vm-dup-1").count() == 1


# ── 3. the audit principal ───────────────────────────────────────────


def test_default_forced_launch_principal_cannot_authenticate() -> None:
    """`Placement.decided_by` is a non-null PROTECT FK, so the forced path
    needs a principal. Auto-creating one must not be a credential-minting
    side-effect of running a CLI: `is_active=False` makes BOTH
    `identity.authentication` lookups (mTLS CN, token) reject it."""
    from django.test import RequestFactory

    from apps.identity import authentication

    client = launch.resolve_forced_launch_principal()

    assert client.name == launch.OPERATOR_CLI_PRINCIPAL
    assert client.is_active is False
    assert client.scope == PrincipalScope.UNCLASSIFIED
    assert client.is_operator_principal is False
    # The REAL resolver refuses it on the mTLS-CN path — the strongest
    # credential vali accepts — even with a verified client certificate
    # whose subject CN is exactly this principal's name.
    request = RequestFactory().get("/")
    request.mtls_present = True
    request.mtls_verify = "SUCCESS"
    request.mtls_subject_cn = launch.OPERATOR_CLI_PRINCIPAL
    assert authentication.resolve_principal(request) is None
    # Idempotent — a second CLI run reuses the same row.
    assert launch.resolve_forced_launch_principal().pk == client.pk


def test_named_but_unknown_principal_is_refused_not_created() -> None:
    """A typo in `--decided-by` must fail loud, never silently manufacture
    a principal that then owns audit rows."""
    with pytest.raises(launch.LaunchConfigError, match="not a registered"):
        launch.resolve_forced_launch_principal("does-not-exist")
    assert ServiceClient.objects.filter(name="does-not-exist").count() == 0


def test_named_principal_is_credited_when_it_exists(monkeypatch) -> None:
    real = ServiceClient.objects.create(
        name="ops-oncall", scope=PrincipalScope.OPERATOR.value
    )
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED)
    )
    launch.launch_on_named_miner(
        _spec(vm_id="vm-actor-1"),
        _miner(),
        decided_by=launch.resolve_forced_launch_principal("ops-oncall"),
    )
    assert Placement.objects.get(vm__vm_id="vm-actor-1").decided_by_id == real.pk


# ── 4. the detection sweep ───────────────────────────────────────────


def _launched_but_unbound(vm_id: str) -> None:
    """The exact ledger `launch_on_miner` writes for a vm_id, WITHOUT a
    `Vm` row — i.e. what a pre-fix CLI launch left behind."""
    from apps.scheduler.models import VmBillingBinding
    from apps.telemetry.models import SourceType, TelemetrySource

    VmBillingBinding.objects.create(
        vm_id=vm_id, node_id_hex="ab" * 32, resource_class="small", lease_id="l"
    )
    TelemetrySource.objects.create(
        source=SourceType.TENANT_VM.value,
        source_id=vm_id,
        verifying_key=bytes(32),
    )


def _warnings(caplog) -> list[str]:
    import logging

    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and "unbound-launch" in r.getMessage()
    ]


def test_sweep_surfaces_a_launched_vm_with_no_row(caplog, monkeypatch) -> None:
    """`nbproof-3` is not a made-up id: it is a REAL production vm_id that
    carries a launch billing binding, a telemetry source, a LIVE
    Vault-Transit KEK — and no `Vm` row."""
    import logging

    from apps.orchestration import service

    # `LOGGING` pins `apps` with `propagate: False`; caplog handles ROOT.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    service._unbound_warn_memo = (frozenset(), 0.0)
    _launched_but_unbound("nbproof-3")

    with caplog.at_level(logging.WARNING, logger="apps.orchestration.service"):
        n = service.sweep_unbound_launches()

    assert n == 1
    warned = _warnings(caplog)
    assert warned, "an unbound running VM must be LOUD"
    assert "nbproof-3" in warned[0]


def test_sweep_reports_zero_when_every_launch_has_a_row() -> None:
    from apps.orchestration import service

    service._unbound_warn_memo = (frozenset(), 0.0)
    _launched_but_unbound("vm-bound-1")
    Vm.objects.create(
        vm_id="vm-bound-1",
        lease_id="l",
        state=VmState.ACTIVE,
        generation=1,
        host="miner-a",
        lifecycle_vk=bytes(32),
    )
    assert service.sweep_unbound_launches() == 0


def test_sweep_adopts_nothing() -> None:
    """THE safety claim. A `Vm` row is what makes a VM eligible for §24
    crypto-erase; a detection sweep must never create one on its own."""
    from apps.orchestration import service

    service._unbound_warn_memo = (frozenset(), 0.0)
    _launched_but_unbound("vm-orphan-1")
    before = Vm.objects.count()

    service.sweep_unbound_launches()

    assert Vm.objects.count() == before == 0
    assert not Vm.objects.filter(vm_id="vm-orphan-1").exists()


def test_sweep_warning_is_throttled_for_an_unchanged_set(
    caplog, monkeypatch
) -> None:
    """The condition is permanent until an operator acts and the tick runs
    every ~10 s. An unthrottled warning would emit ~8.6k identical lines a
    day and bury the one that changed."""
    import logging

    from apps.orchestration import service

    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    service._unbound_warn_memo = (frozenset(), 0.0)
    _launched_but_unbound("vm-throttle-1")

    with caplog.at_level(logging.WARNING, logger="apps.orchestration.service"):
        assert service.sweep_unbound_launches() == 1
        assert service.sweep_unbound_launches() == 1
        assert service.sweep_unbound_launches() == 1
        assert len(_warnings(caplog)) == 1

        # A CHANGE to the set re-warns immediately, throttle or not.
        _launched_but_unbound("vm-throttle-2")
        assert service.sweep_unbound_launches() == 2
        assert len(_warnings(caplog)) == 2


def test_tick_reports_the_unbound_count(monkeypatch) -> None:
    """The count must reach `TickReport` so it lands in the tick log line —
    a sweep nobody can see is not surfacing anything."""
    from apps.orchestration import service

    service._unbound_warn_memo = (frozenset(), 0.0)
    _launched_but_unbound("vm-tick-1")

    report = service.tick_once()

    assert report.unbound_launches == 1
