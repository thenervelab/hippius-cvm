"""Tests for `apps.orchestration.services.launch`.

The choreography (`launch_on_miner`) talks to Vault / preflight / KBS /
Edge — exercised live, not here. These tests pin the SCHEDULER loop
(`launch_vm`): placement, the bridge from a chain node_id to a
`MinerIdentity`, and the re-place-on-reject behaviour. `launch_on_miner`
is faked so the loop logic is tested in isolation.
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration.services import launch
from apps.scheduler import chain
from apps.scheduler.models import Placement, PlacementStatus

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
        miner_id=f"miner-{seed}",
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
    assert result.miner_id == "miner-1"
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
    assert Vm.objects.get(vm_id="vm-host-1").host == "miner-1"


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
    """The core re-place loop: miner-1 rejects (retriable) → miner-2
    accepts. One Failed + one Bound placement, miner-1 excluded."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    _register_miner(2)
    # Both miners eligible; decide_placement tie-breaks on lowest node_id,
    # so miner-1 (node 0…01) is tried first, then miner-2 after exclusion.
    monkeypatch.setattr(
        chain, "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )

    def fake(spec, miner):
        if miner.miner_id == "miner-1":
            return _outcome(launch.RETRIABLE, miner.miner_id)
        return _outcome(launch.ACCEPTED, miner.miner_id)

    monkeypatch.setattr(launch, "launch_on_miner", fake)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is True
    assert result.miner_id == "miner-2"
    # The audit trail records both attempts in order.
    assert [a["disposition"] for a in result.attempts] == [
        launch.RETRIABLE,
        launch.ACCEPTED,
    ]
    # miner-1's placement Failed; miner-2's Bound.
    assert Placement.objects.filter(
        miner_node_id=node_id(1), status=PlacementStatus.FAILED.value
    ).count() == 1
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

    assert Vm.objects.get(vm_id=_spec().vm_id).host == "miner-2"


def test_launch_vm_retries_same_miner_on_post_register_dispatch_failure(
    monkeypatch,
) -> None:
    """A dispatch failure AFTER the KBS register (registered=True) must
    retry the SAME miner — re-placing would kbs-admin-conflict. Two
    transient failures then accept, all on miner-1; miner-2 never tried."""
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
        # miner-1 dispatch-fails twice post-register, then accepts.
        n = calls.count("miner-1")
        if miner.miner_id == "miner-1" and n < 3:
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
    assert result.miner_id == "miner-1"
    # Retried the SAME miner — never re-placed to miner-2.
    assert calls == ["miner-1", "miner-1", "miner-1"]
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
    # First attempt + 2 retries, ALL on miner-1; never re-placed.
    assert calls == ["miner-1", "miner-1", "miner-1"]
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
    assert calls == ["miner-1"]
    assert Placement.objects.filter(status=PlacementStatus.FAILED.value).count() == 1
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
    monkeypatch.setattr(eff, "mint_netbird_setup_key", lambda *a, **k: "key")
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
    assert Vm.objects.get(vm_id="vm-launch-1").host == "miner-1"


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
