"""Tests for the placement-derived reward weight (`scoring.py`)."""

from __future__ import annotations

import pytest

from apps.scheduler import scoring
from apps.scheduler.models import PlacementStatus

from .factories import make_placement, make_vm

pytestmark = pytest.mark.django_db


def test_resource_units_blends_cpu_ram_disk() -> None:
    # small = 1 vCPU / 2048 MiB / (8 data + 10 rootfs) GB.
    # (1*1 + 2*0.25 + 18*0.005) * 1000 = 1590.
    assert scoring.resource_units("small") == 1590
    # xlarge = 8 / 16384 / (64 + 10).
    # (8 + 16*0.25 + 74*0.005) * 1000 = 12370.
    assert scoring.resource_units("xlarge") == 12370
    # Strict ordering: a bigger flavor is worth strictly more.
    assert scoring.resource_units("4xlarge") > scoring.resource_units("xlarge")


def test_resource_units_unknown_flavor_is_zero() -> None:
    # A placement whose resource_class is not a catalogue flavor accrues
    # nothing (e.g. a legacy "std" /place call).
    assert scoring.resource_units("std") == 0
    assert scoring.resource_units("") == 0


def test_compute_epoch_weights_sums_only_bound_placements_per_miner() -> None:
    node_a = "a" * 64
    node_b = "b" * 64

    # Miner A hosts two bound `small` VMs.
    make_placement(
        make_vm("vm-a1"),
        node_a,
        status=PlacementStatus.BOUND.value,
        resource_class="small",
    )
    make_placement(
        make_vm("vm-a2"),
        node_a,
        status=PlacementStatus.BOUND.value,
        resource_class="small",
    )
    # Miner B hosts one bound `xlarge`.
    make_placement(
        make_vm("vm-b1"),
        node_b,
        status=PlacementStatus.BOUND.value,
        resource_class="xlarge",
    )
    # A PENDING placement on A must NOT count (not yet confirmed hosting).
    make_placement(
        make_vm("vm-a3"),
        node_a,
        status=PlacementStatus.PENDING.value,
        resource_class="xlarge",
    )
    # A FAILED placement must NOT count either.
    make_placement(
        make_vm("vm-b2"),
        node_b,
        status=PlacementStatus.FAILED.value,
        resource_class="2xlarge",
    )

    weights = scoring.compute_epoch_weights()

    assert weights == {
        node_a: 2 * 1590,  # two bound smalls
        node_b: 12370,  # one bound xlarge
    }


def test_compute_epoch_weights_empty_when_nothing_bound() -> None:
    make_placement(
        make_vm("vm-1"),
        "c" * 64,
        status=PlacementStatus.PENDING.value,
        resource_class="small",
    )
    assert scoring.compute_epoch_weights() == {}


# ── chain.submit_epoch_close (the producer's on-chain write seam) ─────

from types import SimpleNamespace  # noqa: E402

from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402

from apps.scheduler import chain  # noqa: E402


def test_submit_epoch_close_empty_is_noop(monkeypatch) -> None:
    called = []
    monkeypatch.setattr(chain.subprocess, "run", lambda *a, **k: called.append(1))
    chain.submit_epoch_close({})
    assert called == []


def test_submit_epoch_close_missing_rpc_raises(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "", raising=False)
    with pytest.raises(chain.ChainWriteUnavailable):
        chain.submit_epoch_close({"a" * 64: 5})


def test_submit_epoch_close_shells_out_with_decimal_u128(monkeypatch, tmp_path) -> None:
    fake_bin = tmp_path / "hippius-ticket-validator"
    fake_bin.write_text("#\n")
    fake_bin.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "ws://chain:9944", raising=False)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake_bin), raising=False)
    monkeypatch.setattr(settings, "VALI_THEBRAIN_SIGNING_KEY_PATH", "/seed", raising=False)

    captured = {}

    def fake_run(argv, input=None, **kw):  # noqa: A002
        captured["argv"] = argv
        captured["stdin"] = input
        captured["rpc"] = kw["env"]["THEBRAIN_RPC_URL"]
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(chain.subprocess, "run", fake_run)
    # A weight beyond u64 proves the decimal-string carriage.
    big = 9_000_000_000_000_000_000_000
    chain.submit_epoch_close({"b" * 64: big, "a" * 64: 5})

    assert captured["argv"][1] == "submit-epoch-close"
    assert captured["rpc"] == "ws://chain:9944"
    import json

    payload = json.loads(captured["stdin"])
    # Sorted by node_id; weight is a decimal STRING (u128-safe).
    assert payload[0]["node_id"] == "a" * 64
    assert payload[1]["weight"] == str(big)


def test_submit_epoch_close_nonzero_exit_raises(monkeypatch, tmp_path) -> None:
    fake_bin = tmp_path / "hippius-ticket-validator"
    fake_bin.write_text("#\n")
    fake_bin.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "ws://c:9944", raising=False)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake_bin), raising=False)
    monkeypatch.setattr(settings, "VALI_THEBRAIN_SIGNING_KEY_PATH", "/seed", raising=False)
    monkeypatch.setattr(
        chain.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"", stderr=b"boom"),
    )
    with pytest.raises(chain.ChainWriteUnavailable):
        chain.submit_epoch_close({"a" * 64: 5})


# ── vali_epoch_close command ─────────────────────────────────────────


def test_epoch_close_command_dry_run_does_not_submit(monkeypatch) -> None:
    make_placement(
        make_vm("vm-d1"),
        "a" * 64,
        status=PlacementStatus.BOUND.value,
        resource_class="small",
    )
    submitted = []
    monkeypatch.setattr(chain, "submit_epoch_close", lambda w: submitted.append(w))
    call_command("vali_epoch_close", once=True, dry_run=True)
    assert submitted == []


def test_epoch_close_command_submits_computed_weights(monkeypatch) -> None:
    make_placement(
        make_vm("vm-s1"),
        "a" * 64,
        status=PlacementStatus.BOUND.value,
        resource_class="small",
    )
    submitted = []
    monkeypatch.setattr(chain, "submit_epoch_close", lambda w: submitted.append(w))
    call_command("vali_epoch_close", once=True)
    assert submitted == [{"a" * 64: 1590}]
