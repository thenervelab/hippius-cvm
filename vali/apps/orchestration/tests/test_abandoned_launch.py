"""The PHANTOM leak — a `Vm` row a failed launch left `active` with an
empty host and a LIVE per-VM Vault-Transit KEK.

## The defect, proved live 2026-08-13

`launch_on_miner` registers the vm_id with the KBS and provisions its
per-VM KEK BEFORE it dispatches (step 8 before step 9). That ordering is
deliberate and must not be reversed — the guest's KBS release is
single-shot, so a VM registered against one node and then re-placed hits
the anti-migration CAS fence (#668 `kbs-admin-conflict`). When the
dispatch then failed, three consecutive launches left:

    p1final-1: state=active  host=''  kek_destroyed=False
    p1final-2: state=active  host=''  kek_destroyed=False
    p1final-3: state=active  host=''  kek_destroyed=False

A live KEK with no VM — the same data-death invariant leak as the 37-VM
sweep, by a route no sweep watched. Every sweep that filters
`exclude(state='destroyed')` counted them as live tenants, and the KEKs
had to be erased by hand.

The fix lives in the FAILURE path: mark the row, then reap it from a
sweep ON EVIDENCE. These tests pin both halves, and above all the ones
that must NOT happen — the reap is a crypto-erase, so every test below
that asserts a VETO is protecting a tenant's disk.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects, service
from apps.orchestration.models import (
    DecommissionJob,
    DecommissionState,
    LaunchJob,
    LaunchJobState,
)
from apps.orchestration.services import launch
from apps.scheduler import chain
from apps.scheduler.models import Placement, PlacementStatus

from apps.scheduler.tests.factories import (  # isort: skip
    make_miner,
    make_snapshot,
    node_id,
)

pytestmark = pytest.mark.django_db

VM_ID = "p1final-1"


# ── builders ─────────────────────────────────────────────────────────


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-phantom",
        user_id="u-1",
        vm_id=VM_ID,
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


def _register_miner(seed: int = 1) -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=f"miner-{seed}",
        pubkey_hex=format(seed, "064x"),
        platform_id=f"{seed:02x}" + "cd" * 15,
        netbird_ip=f"100.64.0.{seed}",
        chain_node_id=node_id(seed),
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


def _actor(name: str = "launcher") -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name=name
    )


def _outcome(disposition: str, *, registered: bool, outcome: str) -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=disposition,
        emit={"ok": False, "outcome": outcome},
        exit_code=2,
        registered=registered,
    )


def _phantom(
    vm_id: str = VM_ID,
    *,
    registered: bool = True,
    age_s: float = 10_000.0,
    outcome: str = "dispatch-failed-after-register",
    **fields,
) -> Vm:
    """The row today's bug leaves behind: `active`, no host, a live KEK,
    and (post-fix) the abandoned-launch marker."""
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="t-phantom",
        state=VmState.ACTIVE.value,
        generation=1,
        signing_generation=1,
        host="",
        lifecycle_vk=bytes(32),
        eol_nonce=fields.pop("eol_nonce", b"\x11" * 32),
        launch_abandoned_at=timezone.now() - timedelta(seconds=age_s),
        launch_abandoned_outcome=outcome,
        launch_abandoned_registered=registered,
        **fields,
    )


def _failed_launch_job(vm_id: str = VM_ID, *, miner_id: str = "miner-1") -> LaunchJob:
    """The `LaunchJob` the async worker finishes FAILED — it records the
    miner the order was sent to, which is the phantom's probe/destroy
    target."""
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id="t-phantom",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.FAILED.value,
        reason="dispatch-failed-after-register",
        miner_id=miner_id,
        phase_started_at=now,
        finished_at=now,
        decided_by=_actor(f"worker-{vm_id}"),
    )


@pytest.fixture
def domain_down(monkeypatch) -> list:
    """The miner AFFIRMATIVELY reports no live domain — the only answer
    that may unblock a reap. Returns the recorded probe targets."""
    seen: list[str] = []

    def _probe(vm, node_id_arg):
        seen.append(node_id_arg)
        return False

    monkeypatch.setattr(effects, "poll_domain_running_on", _probe)
    return seen


# ══ 1. the marker — the launch side ══════════════════════════════════


def test_post_register_dispatch_failure_marks_the_phantom(monkeypatch) -> None:
    """TODAY'S BUG. `dispatch-failed-after-register` left the row
    `active host=''` with a live KEK and NOTHING recording that its
    launch had given up — indistinguishable from a launch still in its
    (up to 30 min) preflight, so no sweep could safely act on it."""
    _register_miner(1)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)])
    )
    monkeypatch.setattr(launch.time, "sleep", lambda _s: None)
    monkeypatch.setattr(launch, "max_dispatch_retries", lambda: 0)
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, miner: _outcome(
            launch.RETRIABLE, registered=True, outcome="miner-rejected"
        ),
    )

    result = launch.launch_vm(_spec(), _actor())

    assert result.ok is False
    assert result.outcome == "dispatch-failed-after-register"
    assert result.registered is True
    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.host == ""  # unchanged — the phantom shape
    assert vm.launch_abandoned_at is not None
    assert vm.launch_abandoned_outcome == "dispatch-failed-after-register"
    assert vm.launch_abandoned_registered is True


def test_pre_register_failure_is_marked_but_not_reapable(monkeypatch) -> None:
    """A launch that never reached the KBS register is ALSO an orphan —
    its KEK is staged too — but its vm_id may still be launchable, so it
    is marked `registered=False` and only ever SURFACED."""
    _register_miner(1)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)])
    )
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, miner: _outcome(
            launch.TERMINAL, registered=False, outcome="vault-failure"
        ),
    )

    result = launch.launch_vm(_spec(), _actor())

    assert result.ok is False
    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.launch_abandoned_at is not None
    assert vm.launch_abandoned_outcome == "vault-failure"
    assert vm.launch_abandoned_registered is False


def test_launch_vm_marks_even_when_no_miner_was_ever_tried(monkeypatch) -> None:
    """The row (and, on the golden async path, the KEK) exists from the
    very first line of `launch_vm` — so a launch that dies before any
    dispatch is an orphan too, and must not be silently invisible."""
    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: (_ for _ in ()).throw(chain.ChainReadUnavailable("rpc down")),
    )

    result = launch.launch_vm(_spec(), _actor())

    assert result.outcome == "chain-unavailable"
    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.launch_abandoned_at is not None
    assert vm.launch_abandoned_registered is False


def test_a_successful_launch_clears_the_marker() -> None:
    """THE re-placement guard. Miner A abandons the launch; an operator
    clears the KBS registration and re-launches onto miner B. B's bind
    must wipe A's marker in the SAME update as `host`, or the sweep would
    later erase the KEK B's guest is running on."""
    vm = _phantom()

    launch._bind_vm_host(VM_ID, "miner-2")

    vm.refresh_from_db()
    assert vm.host == "miner-2"
    assert vm.launch_abandoned_at is None
    assert vm.launch_abandoned_outcome == ""
    assert vm.launch_abandoned_registered is False
    # …and the sweep no longer sees it at all.
    assert service.sweep_abandoned_launches() == 0


def test_marker_never_touches_a_BOUND_vm() -> None:
    """Reboot-recovery relaunches an ALREADY-BOUND VM through the same
    choreography. A post-register failure there must never mark a live
    tenant's row as abandoned."""
    vm = Vm.objects.create(
        vm_id="live-tenant-1",
        lease_id="lease-live",
        state=VmState.ACTIVE.value,
        generation=1,
        signing_generation=1,
        host="miner-1",  # BOUND — a real running tenant
        lifecycle_vk=bytes(32),
        eol_nonce=b"\x11" * 32,
    )

    launch._mark_launch_abandoned(
        "live-tenant-1", outcome="edge-unreachable", registered=True
    )

    vm.refresh_from_db()
    assert vm.launch_abandoned_at is None


def test_marker_never_resurrects_a_destroyed_row() -> None:
    """`_destroy_vm` clears `host` on the §24 tombstone, so a Destroyed
    row has the phantom's exact shape. A late/duplicate launch attempt
    must not re-mark it as a fresh live orphan."""
    vm = Vm.objects.create(
        vm_id="dead-1",
        lease_id="lease-dead",
        state=VmState.DESTROYED.value,
        generation=1,
        signing_generation=1,
        host="",
        lifecycle_vk=bytes(32),
    )

    launch._mark_launch_abandoned("dead-1", outcome="edge-error", registered=True)

    vm.refresh_from_db()
    assert vm.launch_abandoned_at is None


def test_forced_cli_launch_marks_its_own_phantom(monkeypatch) -> None:
    """`launch_on_named_miner` (the operator CLI) creates the row + stages
    the KEK exactly like a scheduled launch, so it leaves the identical
    orphan and must mark it too."""
    miner = _register_miner(1)
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m: _outcome(
            launch.RETRIABLE, registered=True, outcome="miner-rejected"
        ),
    )

    launch.launch_on_named_miner(_spec(), miner, decided_by=_actor("cli"))

    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.launch_abandoned_registered is True
    assert Placement.objects.get(vm=vm).status == PlacementStatus.FAILED.value


def _fake_choreography(monkeypatch, *, dispatch) -> None:
    """Stub every collaborator between `launch_on_miner`'s entry and the
    dispatch, so the REAL function runs to step 9 and `dispatch` decides
    what happens there. Nothing stubbed here is the subject of the test —
    what IS the subject is that the KBS register (step 8) has really
    happened by the time `dispatch` is called."""
    from apps.orchestration import effects as eff
    from apps.orchestration import order_dispatch
    from apps.orchestration.services import launch_digest as launch_digest_svc
    from apps.orchestration.services import preflight as preflight_svc
    from apps.orchestration.services import ticket_mint, vault_kv

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
    monkeypatch.setattr(
        launch, "_stage_lifecycle_key", lambda *a, **k: (b"\x01" * 32, b"\x02" * 32)
    )
    monkeypatch.setattr(
        launch.telemetry_keygen, "derive_telemetry_vk", lambda *a, **k: b"\x03" * 32
    )
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
    monkeypatch.setattr(order_dispatch, "build_launch_payload", lambda *a, **k: {})
    monkeypatch.setattr(order_dispatch, "dispatch_order", dispatch)


def test_a_post_register_TERMINAL_reports_registered_and_marks(monkeypatch) -> None:
    """The `edge-unreachable` shape, through the REAL choreography.

    Before this fix only the DISPATCH-RESULT return carried
    `registered=True`; the four terminal returns between the KBS register
    and it reported `registered=False` — i.e. they claimed the KBS had not
    been touched when it had. That is not cosmetic: `registered` is the
    reap gate, so a vm_id permanently burned at the KBS by a timed-out
    dispatch would have been classified `pre-register` and its KEK left
    live forever, which is the very leak being closed."""
    from apps.orchestration import order_dispatch

    miner = _register_miner(1)

    def _unreachable(*a, **k):
        raise order_dispatch.OrderDispatchUnavailable("edge-order: peer unreachable")

    _fake_choreography(monkeypatch, dispatch=_unreachable)

    out = launch.launch_on_named_miner(
        _spec(enable_netbird=False), miner, decided_by=_actor("cli")
    )

    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "edge-unreachable"
    assert out.registered is True, (
        "the KBS register already ran — a terminal that says otherwise "
        "misclassifies the phantom as pre-register and never reaps its KEK"
    )
    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.host == ""
    assert vm.launch_abandoned_registered is True


# ══ 2. the reap — only on POSITIVE evidence of absence ════════════════


def test_sweep_reaps_a_proven_phantom(domain_down) -> None:
    """The whole point: a post-register abandonment, past its grace, whose
    miner reports NO live domain, is torn down through §24 — which is what
    destroys the per-VM Vault-Transit KEK."""
    vm = _phantom()
    _failed_launch_job()

    assert service.sweep_abandoned_launches() == 1

    job = DecommissionJob.objects.get(vm=vm)
    assert job.state == DecommissionState.DRAINING.value
    assert job.decided_by.name == service._ABANDONED_REAP_ACTOR
    # It probed the miner the FAILED LaunchJob names — the same host §24's
    # destroy will be aimed at.
    assert domain_down == ["miner-1"]


def test_reap_erases_the_kek_and_tombstones_the_hostless_row(fx, domain_down) -> None:
    """MUTATION: "a hostless phantom stays invisible to §24". Drive the
    reaped job to completion and prove the two things the leak was about
    — the KEK is destroyed, and the row leaves `active` so every
    `exclude(state='destroyed')` sweep stops counting it as a tenant.

    The clock is NEVER advanced here, and that is now load-bearing: this
    phantom's guest was never created, so §24 proves it and skips the
    EOL-ack wait (`_skip_ack_for_a_guest_that_never_existed`) instead of
    burning the 600 s window on an ack that cannot come. When this test
    did expire the phase by hand it was hiding that wait — the teardown
    completed only because the test moved the clock."""
    vm = _phantom()
    _failed_launch_job()
    fx.eol_ack = None  # no guest ⇒ no ack, ever

    service.sweep_abandoned_launches()
    for _ in range(6):
        service.tick_once()
        job = DecommissionJob.objects.get(vm=vm)
        if job.state in (DecommissionState.DONE.value, DecommissionState.FAILED.value):
            break

    assert job.state == DecommissionState.DONE.value
    assert job.forced is False, (
        "nothing failed to ack — there was nothing to ack. `forced` is the "
        "signal §13 quarantines a host on; a guest that was never created "
        "must not put its host under suspicion"
    )
    assert fx.did("crypto_erase_kek_transit")
    # The destroy ROUTED despite `vm.host == ""` — resolved from the failed
    # LaunchJob, so a domain the failed dispatch left behind is force-stopped
    # rather than orphaned.
    assert fx.did("dispatch_destroy")
    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    assert service.sweep_abandoned_launches() == 0


def test_a_post_register_dispatch_failure_leaves_no_ACTIVE_vm_with_a_live_KEK(
    fx, monkeypatch, domain_down
) -> None:
    """THE end-to-end invariant, across BOTH halves at once.

    The two mechanisms are pinned separately above — the launch marks the
    row, the sweep reaps it — and a seam between them would leave the leak
    open with every individual test still green. So this one starts at a
    real `launch_vm` whose dispatch fails after the KBS register (the
    `stamp-fed-1` shape, live 2026-08-13) and ends at the only property
    that actually matters: no `Vm` row is left `active` holding a live
    per-VM Vault-Transit KEK.

    Ordering is asserted, not assumed: the KEK is destroyed BEFORE the row
    is tombstoned. The reverse is the 37-orphan state that had to be swept
    by hand — a row marked `destroyed` while its KEK is still live leaves
    every sweep that filters `exclude(state='destroyed')` blind to a
    decryptable disk."""
    from apps.orchestration import order_dispatch

    _register_miner(1)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)])
    )
    monkeypatch.setattr(launch.time, "sleep", lambda _s: None)
    monkeypatch.setattr(launch, "max_dispatch_retries", lambda: 0)
    # The REAL `launch_on_miner` choreography, failing exactly where the live
    # one did: the miner answered 500 `libvirt-driver/create` — the domain was
    # never created — AFTER the KBS register. Running the real function is
    # what makes the row's `eol_nonce` real too (baked at step 4b, before the
    # register), which is what §24 verifies an ack against.
    _fake_choreography(
        monkeypatch,
        dispatch=lambda **_kw: order_dispatch.DispatchResult(
            ok=False, status=500, classifier="libvirt-driver/create"
        ),
    )
    fx.eol_ack = None  # the domain was never created — no guest, no ack

    state_when_the_kek_died: list[str] = []

    def _erase(vm_arg):
        state_when_the_kek_died.append(Vm.objects.get(vm_id=vm_arg.vm_id).state)
        fx.calls.append(("crypto_erase_kek_transit", vm_arg.vm_id))

    monkeypatch.setattr(effects, "crypto_erase_kek_transit", _erase)

    result = launch.launch_vm(_spec(), _actor())
    assert result.outcome == "dispatch-failed-after-register"
    _failed_launch_job()
    # Only the grace window is collapsed, and via the SETTING — never by
    # writing `launch_abandoned_at` here. Back-dating the marker would
    # re-create the very field this test needs the launch to have written,
    # so a reverted marker would still pass. (It did, until the mutant
    # showed it.) The grace exists so a guest that started despite the
    # failed dispatch can announce itself; nothing below depends on any
    # other clock.
    monkeypatch.setattr(settings, "VALI_ABANDONED_LAUNCH_GRACE_S", 0.0)

    service.sweep_abandoned_launches()
    for _ in range(6):
        service.tick_once()

    assert fx.did("crypto_erase_kek_transit")
    assert not Vm.objects.filter(state=VmState.ACTIVE.value).exists(), (
        "a launch that failed after the KBS register left a `Vm` the "
        "control plane believes is running, with a live disk key and no host"
    )
    vm = Vm.objects.get(vm_id=VM_ID)
    assert vm.state == VmState.DESTROYED
    assert state_when_the_kek_died == [VmState.DECOMMISSIONING], (
        "the tombstone must FOLLOW the erase: a row marked `destroyed` "
        "while its KEK is still live is invisible to every sweep and its "
        "disk is still decryptable — the 37-orphan state"
    )


def test_sweep_does_not_reap_while_the_domain_may_be_RUNNING(monkeypatch) -> None:
    """The miner says a domain IS live. Erasing here would brick a running
    guest — the launch failed, the VM did not."""
    _phantom()
    _failed_launch_job()
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm, n: True)

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_when_the_probe_is_UNAVAILABLE(monkeypatch) -> None:
    """THE timed-out-but-actually-started window.

    `dispatch-failed-after-register` includes an Edge 502, which the Edge
    returns when its 30 s forward does not complete — and the miner AWAITS
    domain creation, so a slow host fails the dispatch while the guest goes
    on to boot and release its KEK. A miner we cannot reach therefore
    tells us NOTHING, and `None` must never be read as "no domain"."""
    _phantom(outcome="edge-unreachable")
    _failed_launch_job()
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm, n: None)

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_a_vm_that_reported_boot_progress(domain_down) -> None:
    """A signed `booting` / `kek-released` / `running` milestone means a
    guest STARTED — even though the launch reported failure. For an
    unbound VM the vm-progress ingress authorizes the reporter against the
    VM's latest Placement, so this signal really does land for a phantom
    whose guest came up."""
    _phantom(boot_phase=VmBootPhase.BOOTING.value)
    _failed_launch_job()

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_a_vm_that_spoke_from_inside(domain_down) -> None:
    """A §23 served receipt / §322 live attestation can only come from
    inside a running guest."""
    _phantom(guest_signal_at=timezone.now(), guest_signal_kind="served_receipt")
    _failed_launch_job()

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_under_an_IN_FLIGHT_launch(domain_down) -> None:
    """THE cross-call re-placement guard. An operator cleared the KBS
    registration and re-launched; that launch is still in its preflight
    (up to 30 min) so the row still looks abandoned — but its guest will
    use this very KEK. A queued/running LaunchJob is an absolute veto."""
    vm = _phantom()
    _failed_launch_job()
    LaunchJob.objects.create(
        job_id="job-retry",
        vm_id=VM_ID,
        tenant_id="t-phantom",
        flavor="small",
        spec_json={"vm_id": VM_ID},
        userdata_vault_path=f"x/{VM_ID}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{VM_ID}/luks-kek",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=_actor("worker-retry"),
    )

    assert service._abandoned_reap_veto(vm) == "launch-in-flight"
    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_when_some_launch_SUCCEEDED(domain_down) -> None:
    """A vm_id that ever bound a host is not a phantom, whatever a later
    attempt did."""
    vm = _phantom()
    job = _failed_launch_job()
    LaunchJob.objects.filter(id=job.id).update(state=LaunchJobState.SUCCEEDED.value)

    assert service._abandoned_reap_veto(vm) == "launch-succeeded"
    assert DecommissionJob.objects.count() == 0


def test_sweep_does_not_reap_under_an_active_placement(domain_down) -> None:
    """The forced/CLI path records a Pending `Placement` and no
    `LaunchJob` — a live forced launch must veto too."""
    vm = _phantom()
    Placement.objects.create(
        vm=vm,
        vm_family="t-phantom",
        owner="u-1",
        resource_class="small",
        miner_node_id=node_id(1),
        status=PlacementStatus.PENDING.value,
        chain_epoch=1,
        decided_by=_actor("cli"),
    )

    assert service._abandoned_reap_veto(vm) == "placement-active"


def test_sweep_does_not_reap_inside_the_grace_window(domain_down) -> None:
    """The grace gives a guest that started DESPITE the failed dispatch
    time to announce itself before anything looks at it."""
    _phantom(age_s=5.0)
    _failed_launch_job()

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_never_reaps_a_pre_register_abandonment(domain_down) -> None:
    """A vm_id that never reached the KBS register may still be
    launchable — a crypto-erase is not something to do to a VM an
    operator can still save. Surfaced, never reaped."""
    _phantom(registered=False, outcome="vault-failure")
    _failed_launch_job()

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_a_no_nonce_vm_that_MIGHT_have_run_is_still_never_reaped(domain_down) -> None:
    """A missing `eol_nonce` used to be a flat `no-eol-nonce` VETO. It is
    now read as "no measured cmdline was ever baked" — but ONLY when
    `never_ran_veto` clears too. A row with no nonce and a boot milestone
    (something only a guest emits) is still refused.

    The never-baked case that IS reaped lives in
    `test_never_placed_phantom.py`; this is the overshoot guard for it."""
    vm = _phantom(eol_nonce=None, boot_phase=VmBootPhase.BOOTING.value)
    _failed_launch_job()

    assert service._abandoned_reap_veto(vm) == "boot-phase:booting"
    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


def test_sweep_never_touches_an_unmarked_row(domain_down) -> None:
    """A launch still in flight has the SAME `active host=''` shape for
    its whole preflight. Only the marker separates the two."""
    Vm.objects.create(
        vm_id="mid-launch-1",
        lease_id="lease-mid",
        state=VmState.ACTIVE.value,
        generation=1,
        signing_generation=1,
        host="",
        lifecycle_vk=bytes(32),
        eol_nonce=b"\x11" * 32,
    )

    assert service.sweep_abandoned_launches() == 0
    assert DecommissionJob.objects.count() == 0


def test_repeated_sweeps_open_one_teardown(domain_down) -> None:
    """The tick runs every ~10 s; a reap must not pile up jobs."""
    vm = _phantom()
    _failed_launch_job()

    service.sweep_abandoned_launches()
    service.sweep_abandoned_launches()
    service.sweep_abandoned_launches()

    assert DecommissionJob.objects.filter(vm=vm).count() == 1


def test_the_reap_ITSELF_is_idempotent(domain_down) -> None:
    """The sweep above is defended by the `orchestration-job-in-flight`
    veto, which MASKS whether the reap is idempotent on its own — a
    naive `DecommissionJob.objects.create` would pass it and blow up the
    first time two tick processes raced. So call the reap DIRECTLY,
    twice, past the veto: `start_decommission` + the partial unique index
    on `DecommissionJob.vm` are the real boundary, and losing that race
    must be an ordinary `False`, never an exception."""
    vm = _phantom()
    _failed_launch_job()

    assert service._reap_abandoned_launch(vm) is True
    assert service._reap_abandoned_launch(vm) is False

    assert DecommissionJob.objects.filter(vm=vm).count() == 1


def test_reap_kill_switch(monkeypatch, domain_down) -> None:
    """Detection is unconditional; the ACTION has an operator kill
    switch."""
    _phantom()
    _failed_launch_job()
    monkeypatch.setattr(settings, "VALI_ABANDONED_LAUNCH_REAP_ENABLED", False)

    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


# ══ 3. the probe target ══════════════════════════════════════════════


def test_probe_target_prefers_the_launch_record(domain_down) -> None:
    """Same resolver §24's destroy uses — so the host we ask about
    liveness is the host we would send the destroy to."""
    vm = _phantom()
    _failed_launch_job(miner_id="miner-1")

    assert service._abandoned_probe_target(vm) == "miner-1"


def test_probe_target_falls_back_to_the_placement(domain_down) -> None:
    """A forced/CLI phantom has a `Placement` and no `LaunchJob`; without
    this bridge it would have no probe target at all and could never be
    proven absent."""
    vm = _phantom()
    Placement.objects.create(
        vm=vm,
        vm_family="t-phantom",
        owner="u-1",
        resource_class="small",
        miner_node_id=node_id(1),
        status=PlacementStatus.FAILED.value,
        failed_at=timezone.now(),
        reason="dispatch-failed-after-register",
        chain_epoch=1,
        decided_by=_actor("cli"),
    )
    _register_miner(1)

    assert service._abandoned_probe_target(vm) == "miner-1"


def test_an_unresolvable_probe_target_is_a_veto_not_a_licence(monkeypatch) -> None:
    """A miner WAS chosen but cannot be resolved right now — a
    `Placement` naming a chain node with no `MinerIdentity` mirror. The
    probe target is `""`, but for a reason that is an unanswered
    QUESTION, not an answer, so it must still veto.

    This is the boundary of the `no_miner_was_ever_chosen` relaxation:
    the same empty string means "wait" here and "there is no host" when
    no record ever named a miner at all."""
    vm = _phantom()
    Placement.objects.create(
        vm=vm,
        vm_family="t-phantom",
        owner="u-1",
        resource_class="small",
        miner_node_id=node_id(9),  # deliberately NOT registered
        status=PlacementStatus.FAILED.value,
        failed_at=timezone.now(),
        reason="dispatch-failed-after-register",
        chain_epoch=1,
        decided_by=_actor("cli"),
    )

    assert service._abandoned_probe_target(vm) == ""
    assert service.no_miner_was_ever_chosen(vm) is False
    assert effects.poll_domain_running_on(vm, "") is None
    assert service._abandoned_reap_veto(vm) == "domain-unproven"
