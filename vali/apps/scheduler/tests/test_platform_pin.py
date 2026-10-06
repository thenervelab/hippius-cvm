"""A launch that names a `platform_id` lands on THAT chip or nowhere.

Live 2026-09-24: a launch naming a Genoa host's CHIP_ID was placed on a
Turin host — placement ignored the field, while the C2 recompute used
it — and failed terminally at `launch-digest-mismatch` after vali had
already staged it. These pin the three layers: the pure gate, the input
that builds it, and the launch loop that must stop instead of wandering.
"""

from __future__ import annotations

import pytest

from apps.identity.models import PrincipalScope, ServiceClient
from apps.orchestration.services import launch
from apps.scheduler import chain, service
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import make_dispatchable_identity, make_miner, make_snapshot, node_id


def _decide(miners, **kw) -> str:
    return decide_placement(
        snapshot=make_snapshot(10, miners),
        capacity_by_node={m.node_id: 4 for m in miners},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        **kw,
    )


# ─── the pure gate ───────────────────────────────────────────────────


def test_pin_places_on_the_pinned_miner_even_when_another_ranks_first() -> None:
    # Without a pin the tie-break picks the lowest node_id (miner 1).
    assert _decide([make_miner(1), make_miner(2)]) == node_id(1)
    assert _decide([make_miner(1), make_miner(2)], pinned=frozenset({node_id(2)})) == node_id(2)


def test_pin_never_falls_back_to_another_miner() -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(
            [make_miner(1), make_miner(2, status="inactive")],
            pinned=frozenset({node_id(2)}),
        )
    assert exc.value.category == "no-eligible-miner"
    assert "pinned by platform_id" in exc.value.message


def test_an_empty_pin_places_nothing() -> None:
    """An unknown platform_id resolves to an EMPTY set — no placement,
    never "place anywhere"."""
    with pytest.raises(PlacementError):
        _decide([make_miner(1)], pinned=frozenset())


def test_no_pin_is_inert() -> None:
    assert _decide([make_miner(1)], pinned=None) == node_id(1)


# ─── the input ───────────────────────────────────────────────────────


@pytest.mark.django_db
def test_pin_arguments_resolves_the_chip_case_insensitively() -> None:
    m2 = make_dispatchable_identity(2)
    make_dispatchable_identity(3)
    assert service.pin_arguments("") == {"pinned": None}
    assert service.pin_arguments(m2.platform_id.upper()) == {"pinned": frozenset({node_id(2)})}
    assert service.pin_arguments("ff" * 32) == {"pinned": frozenset()}


@pytest.mark.django_db
def test_placement_arguments_carries_the_pin() -> None:
    m1 = make_dispatchable_identity(1)
    snap = make_snapshot(10, [])
    args = service.placement_arguments(snapshot=snap, tenant_id="t", user_id="u", flavor="small")
    assert args["pinned"] is None
    args = service.placement_arguments(
        snapshot=snap, tenant_id="t", user_id="u", flavor="small", platform_id=m1.platform_id
    )
    assert args["pinned"] == frozenset({node_id(1)})


# ─── the launch loop ─────────────────────────────────────────────────


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-pin",
        user_id="u-pin",
        vm_id="vm-pin-1",
        lease_id="lease-pin",
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


@pytest.mark.django_db
def test_launch_vm_lands_on_the_pinned_miner(monkeypatch) -> None:
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="pin")
    make_dispatchable_identity(1)
    m2 = make_dispatchable_identity(2)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1), make_miner(2)])
    )
    chosen: list[str] = []

    def fake(spec, miner):  # noqa: ANN001, ANN202
        chosen.append(miner.miner_id)
        return launch.LaunchOutcome(
            disposition=launch.ACCEPTED,
            emit={"ok": True},
            exit_code=0,
            cose_ticket=b"cose",
            ticket_id="tk",
        )

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    result = launch.launch_vm(_spec(platform_id=m2.platform_id), actor)
    assert result.ok is True
    assert chosen == ["miner-02"]


@pytest.mark.django_db
def test_launch_vm_with_a_pin_stops_after_the_pinned_miner_rejects(monkeypatch) -> None:
    """RETRIABLE excludes the miner and re-places; with a pin that must END
    with `no-eligible-miner`, not wander onto another host."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="pin")
    make_dispatchable_identity(1)
    m2 = make_dispatchable_identity(2)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1), make_miner(2)])
    )
    chosen: list[str] = []

    def fake(spec, miner):  # noqa: ANN001, ANN202
        chosen.append(miner.miner_id)
        return launch.LaunchOutcome(
            disposition=launch.RETRIABLE, emit={"ok": False}, exit_code=2
        )

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    result = launch.launch_vm(_spec(platform_id=m2.platform_id), actor)
    assert result.ok is False
    assert result.outcome == "no-eligible-miner"
    assert chosen == ["miner-02"]


@pytest.mark.django_db
def test_launch_on_miner_refuses_a_platform_id_of_another_miner() -> None:
    """The explicit-miner paths (CLI) bypass placement: refuse a mismatch
    before anything is minted, instead of failing at C2 or at release."""
    m1 = make_dispatchable_identity(1)
    m2 = make_dispatchable_identity(2)
    outcome = launch.launch_on_miner(_spec(platform_id=m2.platform_id), m1)
    assert outcome.disposition == launch.TERMINAL
    assert outcome.emit["outcome"] == "platform-id-mismatch"
    assert outcome.exit_code == launch.EXIT_CONFIG_ERROR
