"""Tests for `apps.orchestration.services.launch`.

The choreography (`launch_on_miner`) talks to Vault / preflight / KBS /
Edge — exercised live, not here. These tests pin the SCHEDULER loop
(`launch_vm`): placement, the bridge from a chain node_id to a
`MinerIdentity`, and the re-place-on-reject behaviour. `launch_on_miner`
is faked so the loop logic is tested in isolation.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration.services import launch
from apps.scheduler import chain
from apps.scheduler.models import Placement, PlacementFailureSource, PlacementStatus

from apps.scheduler.tests.factories import (  # isort: skip
    make_miner,
    make_snapshot,
    node_id,
)

pytestmark = pytest.mark.django_db


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-launch",
        user_id="u-1",
        vm_id="vm-launch-1",
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
    )
    base.update(overrides)
    return launch.LaunchSpec(**base)


def _register_miner(seed: int) -> MinerIdentity:
    """A registered miner whose `chain_node_id` matches the snapshot's
    node_id(seed) — the bridge `launch_vm` joins on. Must satisfy the
    §23 `dispatchable_node_ids` gate: a REAL CHIP_ID (hex, even, ≥16)
    and a FRESH heartbeat, else the miner is excluded as un-attestable /
    dark even though it is on-chain Active.
    """
    return MinerIdentity.objects.create(
        miner_id=f"miner-{chr(ord('a') + seed - 1)}",
        pubkey_hex=format(seed, "064x"),
        platform_id=f"{seed:02x}" + "cd" * 15,
        netbird_ip="100.64.0." + str(seed),
        chain_node_id=node_id(seed),
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


def _outcome(disposition: str, miner_id: str) -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=disposition,
        emit={"ok": disposition == launch.ACCEPTED, "miner_id": miner_id},
        exit_code=0 if disposition == launch.ACCEPTED else 2,
        cose_ticket=b"cose" if disposition == launch.ACCEPTED else None,
        ticket_id="tk-x" if disposition == launch.ACCEPTED else None,
    )


def test_launch_vm_accepts_on_first_miner(monkeypatch) -> None:
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id)
    )

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is True
    assert result.miner_id == "miner-a"
    assert result.miner_node_id == node_id(1)
    # Exactly one Bound placement, no Failed.
    assert Placement.objects.filter(status=PlacementStatus.BOUND.value).count() == 1
    assert Placement.objects.filter(status=PlacementStatus.FAILED.value).count() == 0


def test_launch_vm_stamps_vm_host_on_success(monkeypatch) -> None:
    """Root-cause fix for the §24 zombie: a successful launch must stamp
    the placed miner's node_id onto `Vm.host`. The async worker records
    the miner only on `LaunchJob.miner_id`; without this, `vm.host` stayed
    "" and `dispatch_destroy` / the EOL relay resolved an EMPTY miner. The
    stamped value is `MinerIdentity.miner_id` — the same shape the §24
    destroy + §25 migration routing key on."""
    from apps.lifecycle.models import Vm

    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)])
    )
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id),
    )

    result = launch.launch_vm(_spec(vm_id="vm-host-1"), actor)

    assert result.ok is True
    assert Vm.objects.get(vm_id="vm-host-1").host == "miner-a"


def test_launch_vm_does_not_clobber_existing_vm_host(monkeypatch) -> None:
    """The stamp only FILLS an empty placeholder (`host=""`): a host a §25
    migrate-activation already advanced must never be overwritten by a
    late/duplicate launch tick. Model a pre-set host + assert it survives."""
    from apps.lifecycle.models import Vm, VmState

    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    Vm.objects.create(
        vm_id="vm-host-2",
        lease_id="lease-x",
        state=VmState.ACTIVE,
        generation=1,
        host="miner-preexisting",
        lifecycle_vk=bytes(32),
    )
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)])
    )
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id),
    )

    launch.launch_vm(_spec(vm_id="vm-host-2"), actor)

    assert Vm.objects.get(vm_id="vm-host-2").host == "miner-preexisting"


def test_launch_vm_replaces_on_retriable_then_accepts(monkeypatch) -> None:
    """The core re-place loop: miner-a rejects (retriable) → miner-b
    accepts. One Failed + one Bound placement, miner-a excluded."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    _register_miner(2)
    # Both miners eligible; decide_placement tie-breaks on lowest node_id,
    # so miner-a (node 0…01) is tried first, then miner-b after exclusion.
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )

    def fake(spec, miner):
        if miner.miner_id == "miner-a":
            return _outcome(launch.RETRIABLE, miner.miner_id)
        return _outcome(launch.ACCEPTED, miner.miner_id)

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is True
    assert result.miner_id == "miner-b"
    # The audit trail records both attempts in order.
    assert [a["disposition"] for a in result.attempts] == [
        launch.RETRIABLE,
        launch.ACCEPTED,
    ]
    # miner-a's placement Failed; miner-b's Bound.
    failed = Placement.objects.get(miner_node_id=node_id(1), status=PlacementStatus.FAILED.value)
    # provenance: `_fail_placement` stamps `launch`; the operator readout
    # then maps the stored outcome (here the default, an emit with no
    # `outcome` key → `launch-failed`)
    assert failed.failure_source == PlacementFailureSource.LAUNCH
    assert failed.reason == "launch-failed"
    assert Placement.objects.filter(
        miner_node_id=node_id(2), status=PlacementStatus.BOUND.value
    ).count() == 1
    # `vm.host` names the miner that ACTUALLY took the VM — the invariant
    # every downstream router depends on (`_bound_miner_id` PREFERS
    # `vm.host`, so a wrong value sends §25's quiesce, the §24 EOL push and
    # the §24 destroy to a host that does not run the VM).
    #
    # ⚠️ This assertion pins `launch_vm`'s OWN bind only: `launch_on_miner`
    # is monkeypatched above, so the stamp inside it is NOT exercised here.
    # Reaching that line needs the full Vault/KBS/dispatch choreography.
    # The guard that it fires only on an ACCEPTED dispatch is therefore
    # UNCOVERED by tests — stated rather than implied.
    from apps.lifecycle.models import Vm

    assert Vm.objects.get(vm_id=_spec().vm_id).host == "miner-b"


def test_launch_vm_retries_same_miner_on_post_register_dispatch_failure(
    monkeypatch,
) -> None:
    """A dispatch failure AFTER the KBS register (registered=True) must
    retry the SAME miner — re-placing would kbs-admin-conflict. Two
    transient failures then accept, all on miner-a; miner-b never tried."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    _register_miner(2)
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )
    monkeypatch.setattr(launch.time, "sleep", lambda _s: None)
    monkeypatch.setattr(launch, "max_dispatch_retries", lambda: 3)

    calls = []

    def fake(spec, miner):
        calls.append(miner.miner_id)
        # miner-a dispatch-fails twice post-register, then accepts.
        n = calls.count("miner-a")
        if miner.miner_id == "miner-a" and n < 3:
            return launch.LaunchOutcome(
                disposition=launch.RETRIABLE,
                emit={"ok": False, "outcome": "miner-rejected"},
                exit_code=2,
                registered=True,
            )
        return _outcome(launch.ACCEPTED, miner.miner_id)

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is True
    assert result.miner_id == "miner-a"
    # Retried the SAME miner — never re-placed to miner-b.
    assert calls == ["miner-a", "miner-a", "miner-a"]
    assert Placement.objects.filter(
        miner_node_id=node_id(2)
    ).count() == 0


def test_launch_vm_terminal_when_post_register_dispatch_keeps_failing(
    monkeypatch,
) -> None:
    """A post-register dispatch failure that survives the same-miner
    retries is TERMINAL (dispatch-failed-after-register) — launch_vm does
    NOT re-place into a guaranteed kbs-admin-conflict."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    _register_miner(2)
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )
    monkeypatch.setattr(launch.time, "sleep", lambda _s: None)
    monkeypatch.setattr(launch, "max_dispatch_retries", lambda: 2)

    calls = []

    def fake(spec, miner):
        calls.append(miner.miner_id)
        return launch.LaunchOutcome(
            disposition=launch.RETRIABLE,
            emit={"ok": False, "outcome": "miner-rejected"},
            exit_code=2,
            registered=True,
        )

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is False
    assert result.outcome == "dispatch-failed-after-register"
    # First attempt + 2 retries, ALL on miner-a; never re-placed.
    assert calls == ["miner-a", "miner-a", "miner-a"]
    assert Placement.objects.filter(miner_node_id=node_id(2)).count() == 0


def test_launch_vm_stops_on_terminal(monkeypatch) -> None:
    """A TERMINAL outcome (vault/mint/kbs error) is not the miner's
    fault — re-placing would hit the same wall, so launch_vm stops."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    _register_miner(2)
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )
    calls = []

    def fake(spec, miner):
        calls.append(miner.miner_id)
        return launch.LaunchOutcome(
            disposition=launch.TERMINAL,
            emit={"ok": False, "outcome": "vault-failure", "error": "boom"},
            exit_code=launch.EXIT_VAULT_FAILURE,
        )

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is False
    assert result.outcome == "vault-failure"
    # Stopped after the first miner — did NOT re-place.
    assert calls == ["miner-a"]
    failed = Placement.objects.get(status=PlacementStatus.FAILED.value)
    # provenance is `launch` even for a control-plane fault — the operator
    # readout excludes it by OUTCOME (`vault-failure` is vali's fault)
    assert failed.failure_source == PlacementFailureSource.LAUNCH
    assert failed.reason == "vault-failure"
    assert Placement.objects.filter(status=PlacementStatus.BOUND.value).count() == 0


def test_launch_vm_no_eligible_miner(monkeypatch) -> None:
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    # Empty snapshot → decide_placement raises PlacementError.
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, []))
    monkeypatch.setattr(
        launch, "launch_on_miner",
        lambda spec, miner: pytest.fail("should not dispatch with no miner"),
    )

    result = launch.launch_vm(_spec(), actor)
    assert result.ok is False
    assert result.outcome == "no-eligible-miner"


def test_launch_vm_skips_node_without_registered_identity(monkeypatch) -> None:
    """A chain node with no complete + live MinerIdentity is excluded by
    the §23 `dispatchable_node_ids` gate at PLACEMENT — it is never a
    candidate, so vali never dispatches to it. Here the only miner has no
    identity, so placement itself returns no-eligible-miner with no
    dispatch attempt recorded."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    # Snapshot has node 1, but NO MinerIdentity registered for it.
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(
        launch, "launch_on_miner",
        lambda spec, miner: pytest.fail("should not dispatch to an unmapped node"),
    )

    result = launch.launch_vm(_spec(), actor)
    assert result.ok is False
    # Excluded at placement (dispatchable gate) → no eligible miner, and
    # no dispatch was ever attempted.
    assert result.outcome == "no-eligible-miner"
    assert result.attempts == []


def test_launch_vm_exhausts_attempts(monkeypatch) -> None:
    """All miners keep rejecting (retriable) → bounded by max_attempts."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    for seed in (1, 2, 3):
        _register_miner(seed)
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2), make_miner(3)]),
    )
    monkeypatch.setattr(
        launch, "launch_on_miner",
        lambda spec, miner: _outcome(launch.RETRIABLE, miner.miner_id),
    )

    result = launch.launch_vm(_spec(), actor, max_attempts=2)
    assert result.ok is False
    assert result.outcome == "no-capacity-after-replace"
    # Exactly max_attempts miners were tried.
    assert len(result.attempts) == 2


def test_launch_on_miner_refuses_when_enforce_without_recompute_config(monkeypatch) -> None:
    """C2 fail-closed: ENFORCE on but the recompute is NOT configured must
    REFUSE before any work — never silently pin the untrusted miner digest.
    """
    miner = _register_miner(1)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: False)

    outcome = launch.launch_on_miner(_spec(), miner)

    assert outcome.disposition == launch.TERMINAL
    assert outcome.emit["outcome"] == "launch-digest-not-configured"
    assert outcome.exit_code == launch.EXIT_MEASUREMENT_MISMATCH


def test_launch_on_miner_enforce_with_config_passes_the_guard(monkeypatch) -> None:
    """The guard is inert when the recompute IS configured (enforce+enabled)
    — the launch proceeds past it (fails later on the faked-out choreography,
    NOT on the not-configured refusal)."""
    miner = _register_miner(1)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)

    outcome = launch.launch_on_miner(_spec(), miner)

    # Whatever happens downstream, it is NOT the not-configured refusal.
    assert outcome.emit.get("outcome") != "launch-digest-not-configured"


@pytest.mark.django_db
def test_bind_vm_host_fills_an_empty_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """⚠️ This is a `_bind_vm_host` UNIT test. It does NOT exercise the
    `launch_on_miner` stamp — proven by mutation: deleting that call leaves
    the whole suite green. Reaching it needs the full Vault/KBS/dispatch
    choreography, so the root-cause fix itself is UNCOVERED (tracked).

    What it does pin is the mechanism the fix relies on: `_bind_vm_host`
    fills an empty `host`. Context: `vali_create_vm` calls
    `launch_on_miner` DIRECTLY and creates no LaunchJob, so a fully-running
    CLI-launched VM used to have `vm.host == ""` and no launch record
    naming a miner — §24's destroy had nowhere to route, and §25's source
    routing likewise."""
    from apps.lifecycle.models import Vm
    from apps.orchestration.services import launch as launch_mod

    Vm.objects.filter(vm_id="cli-vm-1").delete()
    Vm.objects.create(
        vm_id="cli-vm-1", tenant_id="t1", state="active", host="", generation=1
    )
    launch_mod._bind_vm_host("cli-vm-1", "node-cli")

    assert Vm.objects.get(vm_id="cli-vm-1").host == "node-cli"


@pytest.mark.django_db
def test_bind_vm_host_never_clobbers_an_existing_host() -> None:
    """The stamp must stay non-destructive: a §25 migrate-activation (or a
    re-adopt) that already advanced `host` must survive a late or duplicate
    launch tick.

    This first-stamp-wins property is ALSO why the stamp fires only on an
    ACCEPTED dispatch: a rejected-dispatch stamp would let a failed miner
    claim `host` permanently, and a later successful launch of the same
    `vm_id` elsewhere would silently no-op — a WRONG binding, which is
    worse than an empty one because nothing fails loud."""
    from apps.lifecycle.models import Vm
    from apps.orchestration.services import launch as launch_mod

    Vm.objects.filter(vm_id="cli-vm-2").delete()
    Vm.objects.create(
        vm_id="cli-vm-2", tenant_id="t1", state="active", host="node-dst", generation=2
    )
    launch_mod._bind_vm_host("cli-vm-2", "node-src")

    assert Vm.objects.get(vm_id="cli-vm-2").host == "node-dst"


def _fake_the_launch_choreography(monkeypatch, *, dispatch_ok: bool) -> None:
    """Stub every collaborator between `launch_on_miner`'s entry and its
    final return, so a test can reach the `vm.host` stamp at the end.

    Nothing here is the subject of the test — the point is only to get the
    real function to run to completion with a chosen dispatch outcome."""
    from apps.orchestration import effects as eff
    from apps.orchestration import order_dispatch
    from apps.orchestration.services import (
        launch_digest as launch_digest_svc,
    )
    from apps.orchestration.services import (
        preflight as preflight_svc,
    )
    from apps.orchestration.services import (
        ticket_mint,
        vault_kv,
    )

    monkeypatch.setattr(launch_digest_svc, "enforce", lambda: False)
    monkeypatch.setattr(launch_digest_svc, "is_enabled", lambda: False)
    monkeypatch.setattr(
        preflight_svc,
        "dispatch_preflight",
        lambda *a, **k: preflight_svc.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
        ),
    )
    monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda *a, **k: None)
    monkeypatch.setattr(vault_kv, "transit_encrypt", lambda *a, **k: "vault:v1:x")
    class _V:
        version = 1

    monkeypatch.setattr(vault_kv, "put_kv", lambda *a, **k: _V())
    # §7 lifecycle keygen shells out to the RELEASE ticket-validator
    # binary, which CI's vali job never builds (it is the `rust` job's
    # artifact). Stub the staging itself rather than skipping the test:
    # skipping would make this coverage invisible in CI, which is the one
    # place it has to run.
    monkeypatch.setattr(
        launch, "_stage_lifecycle_key", lambda *a, **k: (b"\x01" * 32, b"\x02" * 32)
    )
    monkeypatch.setattr(
        launch.telemetry_keygen, "derive_telemetry_vk", lambda *a, **k: b"\x03" * 32
    )
    # `mint` is `-> bytes` (ticket_mint.py). Returning a tuple here was
    # harmless only because every consumer is stubbed — exactly the kind of
    # fixture lie that misleads the next person.
    monkeypatch.setattr(ticket_mint, "mint", lambda *a, **k: b"cose")
    monkeypatch.setattr(
        "apps.orchestration.services.migration_ticket.persist_intake",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        eff,
        "mint_netbird_setup_key",
        lambda *a, **k: eff.MintedSetupKey(id=uuid.uuid4().hex, key="key"),
    )
    class _Admin:
        def __init__(self, vm_id: str) -> None:
            self.vm_id = vm_id
            self.vm_generation = 1
            self.cached = False

    monkeypatch.setattr(
        launch.kbs_admin,
        "register_vm_active_with_vm_id",
        lambda *a, **k: _Admin(k.get("vm_id", "")),
    )
    monkeypatch.setattr(
        order_dispatch, "build_launch_payload", lambda *a, **k: {}
    )
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=dispatch_ok,
            status=200 if dispatch_ok else 500,
            classifier="launched" if dispatch_ok else "miner-rejected",
        ),
    )


@pytest.mark.django_db
def test_launch_on_miner_stamps_vm_host_on_an_accepted_dispatch(monkeypatch) -> None:
    """An ACCEPTED dispatch stamps the placed miner onto a Vm row that
    EXISTS — the `launch_vm` / reboot-recovery shape.

    Deliberately not claiming more: `_bind_vm_host` only UPDATEs, so this
    stamp does nothing for the operator CLI, which creates no `Vm` row at
    all (`_ensure_vm_row`'s sole caller is `launch_vm`). The test
    pre-creates the row for that reason, and the CLI path remains
    unbound-but-running — tracked separately, not fixed by this stamp.

    Where the stamp does new work is reboot-recovery, which calls
    `launch_on_miner` directly for a VM whose row exists and whose `host`
    may be empty.

    Drives the REAL `launch_on_miner`: a `_bind_vm_host` unit test cannot
    catch the stamp being removed (proven by mutation — deleting the call
    left the whole suite green)."""
    from apps.lifecycle.models import Vm

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active", host="", generation=1
    )

    # userdata must carry the NetBird placeholder — the intake check
    # documented in #875; without it the launch stops at
    # `netbird-bad-userdata` long before the stamp.
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    assert Vm.objects.get(vm_id="vm-launch-1").host == "miner-a"


@pytest.mark.django_db
def test_launch_on_miner_pins_with_the_vms_ledger_row(monkeypatch) -> None:
    """The pin records the VM's ledger row itself, under its lock (#1340):
    the next pin's carry-forward reads it, so it must name this VM, the
    chip and the miner the VM was dispatched to."""
    from apps.orchestration.services import allowlist_pin

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    pins: list[dict] = []

    def fake_pin(**kwargs):
        pins.append(kwargs)
        return allowlist_pin.PinResult(
            new_epoch=7, new_cose_sha256_hex="00" * 32, s3_url="s3://b/k"
        )

    monkeypatch.setattr(allowlist_pin, "pin_measurement", fake_pin)

    out = launch.launch_on_miner(
        _spec(
            auto_pin_allowlist=True,
            userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        ),
        miner,
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    assert [p["ledger"] for p in pins] == [
        allowlist_pin.PinLedger(
            vm_id="vm-launch-1",
            platform_id=miner.platform_id,
            node_id="miner-a",
            flavor="small",
        )
    ]
    # ...and ONLY through the pin: the launch writes no row of its own after
    # it (this fake pin writes none), which is the pre-#1340 window where
    # a concurrent pin read a carry-forward without this VM.
    from apps.orchestration.models import MeasurementLedger

    assert not MeasurementLedger.objects.filter(vm_id="vm-launch-1").exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("enforce", "explicit", "recomputed"),
    [(True, False, True), (False, False, False), (True, True, False)],
)
def test_the_pin_says_whether_it_is_valis_own_recompute(
    monkeypatch, enforce: bool, explicit: bool, recomputed: bool
) -> None:
    """`recomputed` only when the pinned digest IS vali's recompute (C2
    ENFORCE, no operator override) — WARN mode pins the miner's digest. The
    caller's `launch_ref` rides the same row (a guest upgrade's attempt)."""
    from apps.orchestration.services import allowlist_pin

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: enforce)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)
    monkeypatch.setattr(
        launch.launch_digest_svc, "recompute_expected_digest", lambda **kw: "ab" * 48
    )
    pins: list[dict] = []

    def fake_pin(**kwargs):
        pins.append(kwargs)
        return allowlist_pin.PinResult(
            new_epoch=7, new_cose_sha256_hex="00" * 32, s3_url="s3://b/k"
        )

    monkeypatch.setattr(allowlist_pin, "pin_measurement", fake_pin)

    out = launch.launch_on_miner(
        _spec(
            auto_pin_allowlist=True,
            userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
            **({"measurement_hex": "ab" * 48} if explicit else {}),
        ),
        miner,
        launch_ref="attempt-1",
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    (pin,) = pins
    assert (pin["ledger"].recomputed, pin["ledger"].launch_ref) == (recomputed, "attempt-1")


@pytest.mark.django_db
def test_a_pin_stuck_behind_other_pins_is_retriable_not_terminal(monkeypatch) -> None:
    """The tail of a burst of starts waits out the pin lock. Nothing was
    signed and the KBS is not registered yet, so the launch is RETRIABLE —
    terminal would fail those VMs for vali's own queue."""
    from apps.orchestration.services import allowlist_pin

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def busy(**_kwargs):
        raise allowlist_pin.AllowlistPinBusy("another pin held the lock for over 30s")

    monkeypatch.setattr(allowlist_pin, "pin_measurement", busy)

    out = launch.launch_on_miner(
        _spec(
            auto_pin_allowlist=True,
            userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        ),
        miner,
    )

    assert out.disposition == launch.RETRIABLE
    assert out.emit["outcome"] == launch.ALLOWLIST_PIN_BUSY
    assert out.registered is False


def test_launch_vm_keeps_a_miner_eligible_after_a_busy_pin(monkeypatch) -> None:
    """A busy pin is vali's queue, not the miner: the re-place may pick the
    same (here: the only) miner again instead of running out of miners."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    calls: list[str] = []

    def fake(spec, miner):
        calls.append(miner.miner_id)
        if len(calls) == 1:
            return launch.LaunchOutcome(
                disposition=launch.RETRIABLE,
                emit={"ok": False, "outcome": launch.ALLOWLIST_PIN_BUSY, "error": "busy"},
                exit_code=launch.EXIT_ALLOWLIST_FAILURE,
            )
        return _outcome(launch.ACCEPTED, miner.miner_id)

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is True, result.emit
    assert calls == ["miner-a", "miner-a"]
    failed = Placement.objects.get(status=PlacementStatus.FAILED.value)
    assert failed.reason == launch.ALLOWLIST_PIN_BUSY


@pytest.mark.django_db
def test_launch_on_miner_does_NOT_stamp_a_rejected_dispatch(monkeypatch) -> None:
    """The guard, and the reason it exists. `_bind_vm_host` filters on
    `host=""`, so the FIRST stamp wins forever — a rejected dispatch
    claiming `vm.host` would make a LATER successful launch of the same
    `vm_id` on another miner silently no-op, leaving every consumer
    (`_bound_miner_id` prefers `vm.host`) pointing at a machine that does
    not run the VM: §24 destroys into the void, §25 uses the wrong source,
    reboot-recovery polls the wrong host. A wrong binding is worse than an
    empty one because nothing fails loud."""
    from apps.lifecycle.models import Vm

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active", host="", generation=1
    )

    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )

    assert out.disposition == launch.RETRIABLE
    assert Vm.objects.get(vm_id="vm-launch-1").host == "", (
        "a rejected dispatch must not claim the host — the first stamp wins "
        "forever, so it would permanently mis-bind the VM"
    )


@pytest.mark.django_db
@pytest.mark.parametrize("generation", ["", "genoa", "milan"])
def test_launch_on_miner_recomputes_the_digest_for_the_miners_generation(
    monkeypatch, generation: str
) -> None:
    """The C2 recompute is handed the placed miner's registered
    `snp_generation` — the only thing that tells a Milan host (64-byte
    CHIP_ID, like Genoa) apart. Unset stays unset (legacy inference)."""
    miner = _register_miner(1)
    miner.platform_id = "ef" * 64
    miner.snp_generation = generation
    miner.save(update_fields=["platform_id", "snp_generation"])
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)
    seen: list[dict] = []

    def _recompute(**kw):
        seen.append(kw)
        return "ab" * 48  # == the faked preflight digest

    monkeypatch.setattr(
        launch.launch_digest_svc, "recompute_expected_digest", _recompute
    )

    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    assert len(seen) == 1
    assert seen[0]["platform_id"] == "ef" * 64
    assert seen[0]["snp_generation"] == generation


@pytest.mark.django_db
def test_launch_on_miner_refuses_a_stale_explicit_measurement(monkeypatch) -> None:
    """A caller-supplied measurement_hex that does not match vali's C2
    recompute of the measured cmdline is pinned + ticketed AS-IS while the
    guest boots the recomputed cmdline → guaranteed KBS denial. Refuse it.

    This guards an operator/dev override gone stale after a measured-cmdline
    change (e.g. systemd.import_credentials=no). Production never supplies
    measurement_hex, so the path costs nothing there."""
    miner = _register_miner(1)
    miner.platform_id = "ef" * 64
    miner.save(update_fields=["platform_id"])
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)
    monkeypatch.setattr(
        launch.launch_digest_svc, "recompute_expected_digest", lambda **kw: "ab" * 48
    )

    out = launch.launch_on_miner(
        _spec(
            measurement_hex="cd" * 48,
            userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        ),
        miner,
    )

    assert out.disposition == launch.TERMINAL, out.emit
    assert out.emit["outcome"] == "explicit-measurement-stale"
    assert out.exit_code == launch.EXIT_MEASUREMENT_MISMATCH


@pytest.mark.django_db
def test_launch_on_miner_accepts_a_matching_explicit_measurement(monkeypatch) -> None:
    """An explicit measurement that DOES match the recompute is not stale —
    the refusal must fire only on a mismatch."""
    miner = _register_miner(1)
    miner.platform_id = "ef" * 64
    miner.save(update_fields=["platform_id"])
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)
    monkeypatch.setattr(
        launch.launch_digest_svc, "recompute_expected_digest", lambda **kw: "ab" * 48
    )

    out = launch.launch_on_miner(
        _spec(
            measurement_hex="ab" * 48,
            userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        ),
        miner,
    )

    assert out.disposition == launch.ACCEPTED, out.emit


# ── the userdata copies staged per launch attempt ────────────────────


@pytest.mark.django_db
def test_both_userdata_copies_hold_the_substituted_bytes(monkeypatch) -> None:
    """Two copies, and they must agree.

    `{vm}/userdata` is what the ticket binds and the KBS releases, wrapped
    under `kek-<vm_id>`. `{vm}/userdata-pending` is vali's working copy,
    wrapped under `ud-<vm_id>` — the only one vali can reopen, and what
    the §25 / KBS-recovery re-mint re-derives the §6 digest from. So it
    has to hold the SUBSTITUTED bytes, not the template intake staged: a
    digest over the template binds bytes the guest never receives, and the
    release denies.

    And the digest itself stays over the PLAINTEXT — the guest re-derives
    it that way (`hippius_guest::release`) and refuses otherwise.
    """
    from apps.orchestration.services import userdata_digest

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    from apps.orchestration import effects as eff
    from apps.orchestration.services import ticket_mint, vault_kv

    puts: list[tuple[str, bytes]] = []
    encrypts: list[tuple[str, bytes]] = []
    mint_args: dict = {}

    class _V:
        version = 4

    monkeypatch.setattr(
        vault_kv, "put_kv", lambda mount, path, value, **kw: (
            puts.append((path, value)) or _V()
        )
    )
    monkeypatch.setattr(
        vault_kv,
        "transit_encrypt",
        lambda name, pt: (
            encrypts.append((name, pt))
            or b"vault:v1:" + pt.hex().encode("ascii")
        ),
    )
    monkeypatch.setattr(
        ticket_mint, "mint", lambda args: mint_args.update(args=args) or b"cose"
    )
    monkeypatch.setattr(
        "apps.orchestration.services.migration_ticket.persist_intake",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        eff,
        "mint_netbird_setup_key",
        lambda **kw: eff.MintedSetupKey(id=uuid.uuid4().hex, key="fake-key"),
    )

    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )
    assert out.disposition == launch.ACCEPTED, out.emit

    canonical = next(v for p, v in puts if p.endswith("/userdata"))
    working = next(v for p, v in puts if p.endswith("/userdata-pending"))
    assert canonical.startswith(b"vault:") and working.startswith(b"vault:")
    # Same bytes underneath, both with the NetBird key substituted — and
    # the working copy STAMPED with the canonical version it belongs to,
    # which is what lets the §25 re-mint prove the correspondence (the two
    # writes are not atomic).
    substituted = bytes.fromhex(canonical.removeprefix(b"vault:v1:").decode())
    working_body = bytes.fromhex(working.removeprefix(b"vault:v1:").decode())
    assert working_body == launch._WORKING_STAMP + b"4\n" + substituted
    assert b"fake-key" in substituted
    assert b"{{NETBIRD_SETUP_KEY}}" not in substituted
    # …under the two DIFFERENT per-VM keys.
    assert {name for name, _pt in encrypts} == {"kek-vm-launch-1", "ud-vm-launch-1"}

    args = mint_args["args"]
    assert args.allowed_userdata_digest_hex == userdata_digest.userdata_digest_hex(
        tenant_id="t-launch",
        vm_id="vm-launch-1",
        ticket_id=args.ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=args.userdata_vault_path,
        version=args.userdata_vault_version,
        plaintext=substituted,
    )


@pytest.mark.django_db
def test_a_decommissioned_vm_id_cannot_be_relaunched(monkeypatch) -> None:
    """§24 crypto-erased that vm_id: both per-VM Transit keys destroyed,
    every KV blob deleted. A launch under the same id stages fresh
    secrets that nothing can ever reach again — a second decommission is
    refused for an already-Destroyed VM.

    Enforced in `_ensure_vm_row`, which EVERY launch path runs, because
    the operator CLI never goes through API intake and the async worker
    acts on a state that may have changed since the POST.
    """
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.services import vault_kv

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    puts: list[str] = []
    monkeypatch.setattr(
        vault_kv, "put_kv", lambda mount, path, value, **kw: puts.append(path)
    )
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1",
        tenant_id="t-launch",
        lease_id="lease-1",
        state=VmState.DESTROYED,
        generation=1,
    )

    with pytest.raises(launch.LaunchConfigError, match="decommissioned"):
        launch.launch_on_miner(
            _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
        )
    assert puts == [], "secrets were staged under a crypto-erased vm_id"


# ── relaunch of a VM §25 moved: minted at its generation, not re-registered


def _record_mint_and_register(monkeypatch) -> dict:
    from apps.orchestration import order_dispatch
    from apps.orchestration.services import ticket_mint

    seen: dict = {"mint_gens": [], "registered": 0, "cmdlines": []}

    def mint(args, *a, **k):
        seen["mint_gens"].append(args.vm_generation)
        return b"cose"

    def register(*a, **k):
        seen["registered"] += 1
        return SimpleNamespace(vm_id=k.get("vm_id", ""), vm_generation=1, cached=False)

    def payload(*a, **k):
        seen["cmdlines"].append(k["cmdline"])
        return {}

    monkeypatch.setattr(ticket_mint, "mint", mint)
    monkeypatch.setattr(launch.kbs_admin, "register_vm_active_with_vm_id", register)
    monkeypatch.setattr(order_dispatch, "build_launch_payload", payload)
    return seen


@pytest.mark.django_db
@pytest.mark.parametrize(("generation", "registers"), [(1, 1), (3, 0)])
def test_a_relaunch_mints_at_the_vms_generation(monkeypatch, generation, registers) -> None:
    """Gen 1 registers `Active{1}` as ever. A moved VM (gen >= 2) is minted
    at its generation and NOT registered: the KBS row its last §25 activate
    wrote (`Migrating{new_gen, dest}`) already admits exactly that, and
    `register-vm` would 409 against it. Its measured cmdline still says
    generation 1 — what it signs acks at, and what its dest booted."""
    from apps.lifecycle.models import Vm

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen = _record_mint_and_register(monkeypatch)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active",
        host="miner-a", generation=generation,
    )
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"),
        miner,
        generation=generation,
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen["mint_gens"] == [generation]
    assert seen["registered"] == registers
    (cmdline,) = seen["cmdlines"]
    assert "hippius.vm_generation=1" in cmdline.split()


@pytest.mark.django_db
def test_a_relaunch_at_a_generation_the_vm_does_not_hold_is_refused(monkeypatch) -> None:
    from apps.lifecycle.models import Vm

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen = _record_mint_and_register(monkeypatch)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active", host="miner-a", generation=3
    )
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner, generation=2
    )
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "kbs-admin-vm-state-refused"
    assert seen["mint_gens"] == [] and seen["registered"] == 0


# ── vali records every ticket it launches with (stranded-VM restore) ─────


@pytest.mark.django_db
def test_the_launch_ticket_is_recorded_before_it_is_registered(monkeypatch) -> None:
    """A §25 stranded-VM restore vetoes any KBS grant whose ticket vali has
    no intake for; the launch ticket IS the grant of every never-moved VM."""
    from apps.lifecycle.models import Vm

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen = _record_mint_and_register(monkeypatch)
    events: list[tuple] = []

    def persist(cose, **kw):
        events.append(("intake", cose, kw))

    def register(*a, **k):
        events.append(("register",))
        return SimpleNamespace(vm_id=k.get("vm_id", ""), vm_generation=1, cached=False)

    monkeypatch.setattr("apps.orchestration.services.migration_ticket.persist_intake", persist)
    monkeypatch.setattr(launch.kbs_admin, "register_vm_active_with_vm_id", register)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active", host="", generation=1
    )
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen["mint_gens"] == [1]
    (intake, reg) = events
    assert reg == ("register",)
    assert intake[1] == b"cose"
    assert intake[2] == {
        "vm_id": "vm-launch-1",
        "generation": 1,
        "ticket_id": out.ticket_id,
        "received_from": "system:launch",
        # The launch reads the mode back out of its own ticket (M0 here).
        "expected_key_mode": "hippius",
    }


@pytest.mark.django_db
def test_a_ticket_vali_cannot_record_is_never_registered(monkeypatch) -> None:
    from apps.lifecycle.models import Vm
    from apps.orchestration.effects import EffectUnavailable

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen = _record_mint_and_register(monkeypatch)

    def persist(cose, **kw):
        raise EffectUnavailable("validator unavailable")

    monkeypatch.setattr("apps.orchestration.services.migration_ticket.persist_intake", persist)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    Vm.objects.create(
        vm_id="vm-launch-1", tenant_id="t-launch", state="active", host="", generation=1
    )
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "mint-failure"
    assert seen["registered"] == 0


# ── NetBird: only a FIRST launch mints a persistent-peer key ──────────


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("prior_job_state", "persistent"),
    [(None, True), ("failed", True), ("running", True), ("succeeded", False)],
)
def test_only_a_first_launch_mints_a_persistent_netbird_key(
    monkeypatch, prior_job_state: str | None, persistent: bool
) -> None:
    """A relaunch (power start, reboot-recovery — both rebuild from the VM's
    SUCCEEDED launch) boots the same overlay, so the guest logs in with the
    identity it holds and never uses the key. Minted persistent, that spare
    key would let the guest's root enrol a peer that outlives the VM."""
    from apps.orchestration import effects as eff
    from apps.orchestration.models import LaunchJob

    from .factories import make_launch_record

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    if prior_job_state is not None:
        job = make_launch_record(SimpleNamespace(vm_id="vm-launch-1"))  # type: ignore[arg-type]
        LaunchJob.objects.filter(id=job.id).update(state=prior_job_state)
    minted: list[dict] = []
    monkeypatch.setattr(
        eff,
        "mint_netbird_setup_key",
        lambda **kw: minted.append(kw) or eff.MintedSetupKey(id=uuid.uuid4().hex, key="key"),
    )

    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    assert [kw["persistent"] for kw in minted] == [persistent]


# ── NetBird: every minted key is recorded against its VM ──────────────


@pytest.mark.django_db
@pytest.mark.parametrize("prior_job_state", [None, "succeeded"])
def test_a_minted_netbird_key_is_recorded_before_it_leaves_vali(
    monkeypatch, prior_job_state: str | None
) -> None:
    """The key's id is recorded against the VM BEFORE the key is staged into
    the userdata the guest receives: whatever peer enrols with it, under
    whatever name, is traceable to this VM. Recorded even when the launch
    dies right after (here: the Vault stage), since the key may already
    have reached nobody — or somebody."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.lifecycle.models import VmNetbirdKey
    from apps.orchestration import effects as eff
    from apps.orchestration.effects import EffectUnavailable
    from apps.orchestration.models import LaunchJob
    from apps.orchestration.services import vault_kv

    from .factories import make_launch_record

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    if prior_job_state is not None:
        job = make_launch_record(SimpleNamespace(vm_id="vm-launch-1"))  # type: ignore[arg-type]
        LaunchJob.objects.filter(id=job.id).update(state=prior_job_state)
    monkeypatch.setattr(
        eff,
        "mint_netbird_setup_key",
        lambda **kw: eff.MintedSetupKey(id="sk-first", key="the-secret"),
    )

    def _vault_down(*_a: object, **_k: object) -> None:
        raise EffectUnavailable("vault: down")

    monkeypatch.setattr(vault_kv, "put_kv", _vault_down)

    before = timezone.now()
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), miner
    )

    assert out.emit["outcome"] == "vault-failure", out.emit
    key = VmNetbirdKey.objects.get()
    assert (key.vm.vm_id, key.setup_key_id) == ("vm-launch-1", "sk-first")
    assert key.persistent is (prior_job_state is None)
    assert (key.peer_id, key.settled_at) == ("", None)
    # A relaunch key lives at most `RELAUNCH_NETBIRD_KEY_TTL_S`.
    ttl = 3600 if prior_job_state is None else launch.RELAUNCH_NETBIRD_KEY_TTL_S
    assert before + timedelta(seconds=ttl - 60) < key.expires_at
    assert key.expires_at <= timezone.now() + timedelta(seconds=ttl)


@pytest.mark.parametrize(
    ("template", "ok"),
    [
        ("hippius-tenant-{vm_id}", True),
        ("hippius-tenant-{vm_id}-x", False),
        ("my-{vm_id}", False),
        ("hippius-tenant-fixed", False),
        ("bad-{tenant_id}", False),
    ],
)
def test_intake_only_accepts_the_revocable_hostname(template: str, ok: bool) -> None:
    err = launch.check_netbird_hostname(enable=True, hostname_template=template, vm_id="vm-1")
    assert (err is None) is ok, err


def test_the_hostname_rule_is_off_without_netbird() -> None:
    assert launch.check_netbird_hostname(enable=False, hostname_template="x", vm_id="vm-1") is None
