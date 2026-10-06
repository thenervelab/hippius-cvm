"""Runner flavors (`runner-*`): unlisted CI sizes with a small data disk.

They resolve like any flavor (`resolve_flavor`), stay out of every
catalogue enumeration, and are minted into the OrderTicket as their
compute class — so the Rust `Flavor` enum (KBS / guest / miner-agent)
does not change — while the small disk rides the measured
`hippius.disk_gb` token and the LaunchOrder.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings

from apps.orchestration import launch_jobs
from apps.orchestration.services import flavors, ticket_mint

RUNNERS = {
    # name: (cpu_count, memory_mb, disk_gb, ticket flavor)
    "runner-small": (1, 4096, 20, "small"),
    "runner-medium": (2, 8192, 20, "medium"),
    "runner-large": (4, 16384, 30, "large"),
}


@pytest.mark.parametrize("name", sorted(RUNNERS))
def test_runner_flavor_resolves_to_its_size(name: str) -> None:
    cpu, mem, disk, _ = RUNNERS[name]
    size = flavors.resolve_flavor(name)
    assert (size.cpu_count, size.memory_mb, size.data_disk_size_gb) == (cpu, mem, disk)
    assert size.luks_disk_size_gb == flavors.ROOTFS_DISK_GB


@pytest.mark.parametrize("name", sorted(RUNNERS))
def test_ticket_flavor_is_a_rust_variant_with_the_same_compute(name: str) -> None:
    """The miner checks the ticket flavor's vCPUs against `cpu_count` and
    preflight takes RAM from it: the compute class must match exactly.
    (`FLAVOR_NAMES` == the Rust enum is pinned by
    `test_flavor_python_catalogue_matches_rust_enum`.)"""
    ticket = flavors.ticket_flavor(name)
    assert ticket == RUNNERS[name][3]
    assert ticket in flavors.FLAVOR_NAMES
    runner, base = flavors.resolve_flavor(name), flavors.resolve_flavor(ticket)
    assert (runner.cpu_count, runner.memory_mb) == (base.cpu_count, base.memory_mb)


def test_catalogue_flavor_is_its_own_ticket_flavor() -> None:
    for name in flavors.FLAVOR_NAMES:
        assert flavors.ticket_flavor(name) == name
    with pytest.raises(flavors.UnknownFlavor):
        flavors.ticket_flavor("nope")


def test_runner_flavors_are_unlisted_but_launchable() -> None:
    assert set(flavors.RUNNER_FLAVOR_NAMES) == set(RUNNERS)
    assert not set(flavors.FLAVOR_NAMES) & set(RUNNERS)
    assert flavors.LAUNCHABLE_FLAVOR_NAMES == flavors.FLAVOR_NAMES + flavors.RUNNER_FLAVOR_NAMES
    # `LaunchJob.flavor` / `ResizeJob` / ledger columns are max_length=32.
    assert all(len(name) <= 32 for name in RUNNERS)
    for name in RUNNERS:
        launch_jobs._check_flavor(name)


def test_runner_flavor_follows_its_compute_class_under_a_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_SCHEDULER_MAX_FLAVOR", "small")
    assert flavors.is_offered("runner-small")
    assert not flavors.is_offered("runner-medium")
    assert not flavors.is_offered("runner-large")
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._check_flavor("runner-medium")
    assert exc.value.category == "flavor-not-offered"

    monkeypatch.setattr(settings, "VALI_SCHEDULER_MAX_FLAVOR", "")
    assert all(flavors.is_offered(name) for name in RUNNERS)


def test_runner_disk_is_what_placement_commits() -> None:
    from apps.scheduler import service as scheduler_service

    assert scheduler_service._committed_disk_gb("runner-small") == 20 + flavors.ROOTFS_DISK_GB
    assert scheduler_service._committed_resources("runner-large") == (16384, 4)


def _mint_argv(monkeypatch: pytest.MonkeyPatch, flavor: str, tmp_path: Any) -> list[str]:
    captured: list[list[str]] = []

    class _Done:
        returncode = 0
        stderr = b""

    def fake_run(argv: list[str], **_kw: Any) -> _Done:
        captured.append(argv)
        out = argv[argv.index("--out") + 1]
        with open(out, "wb") as fh:
            fh.write(b"\xd2cose")
        return _Done()

    monkeypatch.setattr(ticket_mint, "_bin_path", lambda: "/bin/order-ticket-mint")
    monkeypatch.setattr(ticket_mint, "reserve_issue_time", lambda _vm: 1_700_000_000)
    monkeypatch.setattr(ticket_mint, "_resolve_l1_seed", lambda: None)
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", str(tmp_path / "seed"))
    monkeypatch.setattr(ticket_mint.subprocess, "run", fake_run)
    ticket_mint.mint(
        ticket_mint.MintArgs(
            kid="k" * 16,
            ticket_id="t1",
            tenant_id="tenant",
            user_id="user",
            vm_id="vm-1",
            lease_id="lease",
            node_id="ab" * 32,
            platform_id="cd" * 32,
            allowed_measurement_hex="ef" * 48,
            userdata_vault_path="ud",
            userdata_vault_version=1,
            luks_vault_path="luks",
            luks_vault_version=1,
            allowed_userdata_digest_hex="01" * 32,
            flavor=flavor,
        )
    )
    (argv,) = captured
    return argv


@pytest.mark.parametrize(
    ("flavor", "signed"),
    [("runner-small", "small"), ("runner-large", "large"), ("medium", "medium")],
)
def test_mint_signs_the_compute_class(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, flavor: str, signed: str
) -> None:
    argv = _mint_argv(monkeypatch, flavor, tmp_path)
    assert argv[argv.index("--flavor") + 1] == signed


@pytest.mark.django_db
def test_a_runner_launch_measures_its_disk_and_tickets_its_compute_class(monkeypatch) -> None:
    """The whole launch: vali measures `hippius.disk_gb=20` and the
    flavor's vCPUs, orders a 20 GiB disk from the miner, and the minted
    ticket says `small` — what the miner's `cpu_count` gate and the KBS
    accept."""
    from apps.orchestration import order_dispatch
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_flavor_resources_launch import (
        _USERDATA,
        _digest_for,
        _miner,
        _miner_reports,
    )
    from apps.orchestration.tests.test_launch_service import (
        _fake_the_launch_choreography,
        _spec,
    )

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen: dict[str, list[Any]] = {"recompute": [], "payload": [], "argv": []}
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)

    def _recompute(**kw: Any) -> str:
        seen["recompute"].append(kw)
        return _digest_for(kw["cpu_count"])

    monkeypatch.setattr(launch.launch_digest_svc, "recompute_expected_digest", _recompute)
    monkeypatch.setattr(
        launch.allowlist_pin,
        "pin_measurement",
        lambda **_: launch.allowlist_pin.PinResult(
            new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x"
        ),
    )

    def _mint(args: ticket_mint.MintArgs) -> bytes:
        seen["argv"].append(ticket_mint._ticket_flavor(args.flavor))
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", _mint)

    def _payload(**kw: Any) -> dict[str, Any]:
        seen["payload"].append(kw)
        return {}

    monkeypatch.setattr(order_dispatch, "build_launch_payload", _payload)
    _miner_reports(monkeypatch, _digest_for(1))

    spec = _spec(flavor="runner-small", auto_pin_allowlist=True, userdata=_USERDATA)
    out = launch.launch_on_miner(spec, _miner())

    assert out.disposition == launch.ACCEPTED, out.emit
    (recompute,) = seen["recompute"]
    assert recompute["cpu_count"] == 1
    assert "hippius.disk_gb=20" in recompute["cmdline"].split()
    (payload,) = seen["payload"]
    assert (payload["cpu_count"], payload["memory_mb"], payload["data_disk_size_gb"]) == (
        1,
        4096,
        20,
    )
    assert payload["cmdline"] == recompute["cmdline"]
    assert seen["argv"] == ["small"]
