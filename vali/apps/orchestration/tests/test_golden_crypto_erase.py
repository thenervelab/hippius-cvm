"""§24 GOLDEN crypto-erase + explicit destroy-order — the REAL effect bodies.

A golden dm-verity-overlay VM's tenant KEK is a Vault-Transit key
(`kek-<vm_id>`) with NO KBS record, so the legacy KBS admin `crypto-erase`
404s. `crypto_erase_kek_transit` instead DESTROYS the Transit key (making
the wrapped per-VM KEK forever un-unwrappable ⇒ the in-guest LUKS master key
unrecoverable) + deletes the wrapped-KEK KV blob. `dispatch_destroy` sends an
explicit signed `destroy` order so a golden guest that ignores the EOL
self-poweroff is still force-stopped.

These bypass the autouse `fx` fixture (which replaces the whole `effects`
module) by capturing the REAL effect bodies at import time and patching only
their inner seams (`vault_kv.*` / `order_dispatch.dispatch_order`), so the real
key-name + path derivation runs.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects, order_dispatch
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import vault_kv


def _launch_job(vm_id: str, *, miner_id: str, state: LaunchJobState) -> LaunchJob:
    """A terminal `LaunchJob` for `vm_id` bound to `miner_id`. Sets
    `finished_at` (the DB CHECK requires it for terminal states)."""
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=f"j-{vm_id}-{miner_id}",
        vm_id=vm_id,
        tenant_id="t-1",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path=f"secret/data/x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=state.value,
        miner_id=miner_id,
        phase_started_at=now,
        finished_at=now,
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value,
            name=f"svc-{vm_id}-{miner_id}",
        ),
    )

# The autouse `fx` fixture replaces `effects.crypto_erase_kek_transit` /
# `effects.dispatch_destroy` with in-memory fakes — capture the REAL bodies
# before any fixture runs so these tests exercise the actual logic.
_REAL_GOLDEN_ERASE = effects.crypto_erase_kek_transit
_REAL_DISPATCH_DESTROY = effects.dispatch_destroy


@pytest.fixture(autouse=True)
def _kv_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_VAULT_KV_MOUNT", "secret", raising=False)
    monkeypatch.setattr(
        settings,
        "VALI_VAULT_KV_PREFIX",
        "hippius-compute/kbs/tenants",
        raising=False,
    )
    # Restore the REAL effect bodies the autouse `fx` fixture shadowed.
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", _REAL_GOLDEN_ERASE)
    monkeypatch.setattr(effects, "dispatch_destroy", _REAL_DISPATCH_DESTROY)


def _vm(vm_id: str = "vm-golden", host: str = "miner-1", generation: int = 5) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.DECOMMISSIONING,
        generation=generation,
        host=host,
        lifecycle_vk=bytes(32),
        eol_nonce=bytes(range(32)),
    )


# ── crypto_erase_kek_transit ──────────────────────────────────────


@pytest.mark.django_db
def test_golden_erase_destroys_the_right_transit_key_and_kv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple] = []
    monkeypatch.setattr(
        vault_kv, "transit_key_delete", lambda name: calls.append(("transit", name))
    )
    monkeypatch.setattr(
        vault_kv,
        "delete_kv_all_versions",
        lambda mount, path: calls.append(("kv", mount, path)),
    )
    vm = _vm(vm_id="vm-golden")
    effects.crypto_erase_kek_transit(vm)
    # The Transit key destroyed is EXACTLY `kek-<vm_id>` — the same key the
    # KBS + the launch provisioning bind — so a sibling/other-tenant key can
    # never be hit. Once it's gone the wrapped KEK is un-unwrappable.
    assert ("transit", "kek-vm-golden") in calls
    # The wrapped-KEK KV blob at the canonical per-VM path is deleted.
    assert (
        "kv",
        "secret",
        "hippius-compute/kbs/tenants/vm-golden/luks-kek",
    ) in calls


@pytest.mark.django_db
def test_golden_erase_rejects_a_malformed_vm_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A vm_id that fails the charset lock must NEVER be interpolated into a
    # Vault delete path — fail closed, touch nothing.
    hit: list[Any] = []
    monkeypatch.setattr(vault_kv, "transit_key_delete", lambda n: hit.append(n))
    monkeypatch.setattr(
        vault_kv, "delete_kv_all_versions", lambda m, p: hit.append(p)
    )
    vm = _vm(vm_id="ok-id")
    vm.vm_id = "../evil"  # tamper post-construction
    with pytest.raises(effects.EffectError):
        effects.crypto_erase_kek_transit(vm)
    assert hit == []


@pytest.mark.django_db
def test_golden_erase_propagates_a_real_failure_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A genuine Transit-key destroy failure must propagate so the caller
    # keeps the decommission retryable — never a silent "erased".
    def _boom(name: str) -> None:
        raise effects.EffectError("permission denied")

    monkeypatch.setattr(vault_kv, "transit_key_delete", _boom)
    monkeypatch.setattr(vault_kv, "delete_kv_all_versions", lambda m, p: None)
    with pytest.raises(effects.EffectError):
        effects.crypto_erase_kek_transit(_vm())


# ── dispatch_destroy ─────────────────────────────────────────────────


@pytest.mark.django_db
def test_dispatch_destroy_targets_the_bound_miner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex="ab" * 32,
        platform_id="plat-1",
        netbird_ip="100.64.0.9",
    )
    captured: dict[str, Any] = {}

    def _fake_dispatch(**kwargs: Any) -> order_dispatch.DispatchResult:
        captured.update(kwargs)
        return order_dispatch.DispatchResult(ok=True, status=200, classifier="")

    monkeypatch.setattr(order_dispatch, "dispatch_order", _fake_dispatch)
    effects.dispatch_destroy(_vm(vm_id="vm-golden", host="miner-1"))
    # Routed to the VM's bound miner via its chain-provisioned NetBird IP —
    # no misroute (address never came from request data).
    assert captured["miner_id"] == "miner-1"
    assert captured["netbird_ip"] == "100.64.0.9"
    assert captured["kind"] == "destroy"
    assert b"vm-golden" in captured["payload_json"]


@pytest.mark.django_db
def test_dispatch_destroy_falls_back_to_launch_job_when_host_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every VM launched via the async `POST /v1/vm/launch` path has
    `vm.host == ""` (the worker records the miner only on
    `LaunchJob.miner_id`). The destroy MUST fall back to that trusted
    placement record so the order routes instead of raising `miner ''`."""
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex="ab" * 32,
        platform_id="plat-1",
        netbird_ip="100.64.0.9",
    )
    _launch_job("vm-async", miner_id="miner-1", state=LaunchJobState.SUCCEEDED)
    captured: dict[str, Any] = {}

    def _fake_dispatch(**kwargs: Any) -> order_dispatch.DispatchResult:
        captured.update(kwargs)
        return order_dispatch.DispatchResult(ok=True, status=200, classifier="")

    monkeypatch.setattr(order_dispatch, "dispatch_order", _fake_dispatch)
    # host="" → resolve the bound miner from the SUCCEEDED LaunchJob.
    effects.dispatch_destroy(_vm(vm_id="vm-async", host=""))
    assert captured["miner_id"] == "miner-1"
    assert captured["netbird_ip"] == "100.64.0.9"
    assert captured["kind"] == "destroy"


@pytest.mark.django_db
def test_dispatch_destroy_prefers_vm_host_over_launch_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`vm.host` is authoritative when set: a stale/other SUCCEEDED launch
    record must never override the VM's current bound host."""
    for mid, pk, ip in (
        ("miner-1", "ab" * 32, "100.64.0.9"),
        ("miner-2", "cd" * 32, "100.64.0.8"),
    ):
        MinerIdentity.objects.create(
            miner_id=mid, pubkey_hex=pk, platform_id=mid, netbird_ip=ip
        )
    _launch_job("vm-async2", miner_id="miner-2", state=LaunchJobState.SUCCEEDED)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: (captured.update(kw) or order_dispatch.DispatchResult(
            ok=True, status=200, classifier=""
        )),
    )
    effects.dispatch_destroy(_vm(vm_id="vm-async2", host="miner-1"))
    assert captured["miner_id"] == "miner-1"


@pytest.mark.django_db
def test_dispatch_destroy_fails_loud_when_no_host_and_no_launch_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail-closed: a VM with neither `vm.host` NOR a SUCCEEDED launch
    record cannot route a destroy — it must raise LOUD, never silently
    tombstone a still-running domain as Destroyed."""
    dispatched: list[Any] = []
    monkeypatch.setattr(
        order_dispatch, "dispatch_order", lambda **kw: dispatched.append(kw)
    )
    with pytest.raises(effects.EffectError):
        effects.dispatch_destroy(_vm(vm_id="vm-orphan", host=""))
    assert dispatched == []


@pytest.mark.django_db
def test_dispatch_destroy_uses_a_failed_launch_jobs_miner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DELIBERATE REVERSAL of the previous rule ("a FAILED launch may carry
    a miner it never actually bound to, so ignore it").

    That reasoning is right for BINDING and wrong for the DESTROY, because
    the two questions differ: `_bound_miner_id` asks "where is this VM
    bound" — still strict, and still what the §25 relay and the EOL push
    use — while the destroy asks "who might have a domain to stop".

    A launch can FAIL in vali after its order already reached the miner and
    the domain came up (an `edge-unreachable` timeout, or a rejection after
    `lifecycle.launch` completed), and the LaunchJob records exactly which
    miner it was sent to. The asymmetry is total: a misrouted destroy is
    HARMLESS — it carries the `vm_id` and the miner's `handle_destroy`
    no-ops for one it does not know — whereas a destroy never sent leaves a
    live CVM tombstoned as Destroyed, holding an ASID and RAM, with no
    further §24 possible (`start_decommission` requires Active).

    Live case: `migproof-1`, whose launch failed on a miner 500 (SEV ASID
    exhaustion) while its LaunchJob named `miner-2`."""
    MinerIdentity.objects.create(
        miner_id="miner-1", pubkey_hex="ab" * 32, platform_id="p", netbird_ip="100.64.0.9"
    )
    _launch_job("vm-failed", miner_id="miner-1", state=LaunchJobState.FAILED)
    dispatched: list[Any] = []
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: dispatched.append(kw)
        or order_dispatch.DispatchResult(ok=True, status=200, classifier="destroyed"),
    )
    effects.dispatch_destroy(_vm(vm_id="vm-failed", host=""))
    assert len(dispatched) == 1
    assert dispatched[0]["miner_id"] == "miner-1"


@pytest.mark.django_db
def test_dispatch_destroy_still_fails_loud_when_no_miner_was_ever_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The widening is bounded. With NO vali record naming any miner —
    `vm.host` empty and no LaunchJob at all — there is nowhere to send the
    order, and the destroy must still fail LOUD rather than let §24
    tombstone a VM whose domain was never proven gone."""
    dispatched: list[Any] = []
    monkeypatch.setattr(
        order_dispatch, "dispatch_order", lambda **kw: dispatched.append(kw)
    )
    with pytest.raises(effects.EffectError):
        effects.dispatch_destroy(_vm(vm_id="vm-nowhere", host=""))
    assert dispatched == []


@pytest.mark.django_db
def test_dispatch_destroy_raises_on_miner_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex="ab" * 32,
        platform_id="plat-1",
        netbird_ip="100.64.0.9",
    )
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: order_dispatch.DispatchResult(
            ok=False, status=409, classifier="order-id-collision"
        ),
    )
    with pytest.raises(effects.EffectError):
        effects.dispatch_destroy(_vm(host="miner-1"))


@pytest.mark.django_db
def test_dispatch_destroy_maps_unavailable_to_effect_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex="ab" * 32,
        platform_id="plat-1",
        netbird_ip="100.64.0.9",
    )

    def _unavail(**kw: Any) -> Any:
        raise order_dispatch.OrderDispatchUnavailable("edge down")

    monkeypatch.setattr(order_dispatch, "dispatch_order", _unavail)
    with pytest.raises(effects.EffectUnavailable):
        effects.dispatch_destroy(_vm(host="miner-1"))
