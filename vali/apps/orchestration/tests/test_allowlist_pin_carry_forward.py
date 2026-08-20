"""§22 auto-pin CARRY-FORWARD — the artifact must never evict a live VM.

`kbs_core::allowlist::InstalledAllowlist::install` REPLACES the active
allowlist body; it does not merge. The static base manifest is a
read-only ConfigMap that no pin writes back to, so the pre-fix
`base + 1 entry` rebuild evicted every previously auto-pinned
measurement — and the same allowlist gates `pre_release_validate`, so an
evicted VM cannot unlock its LUKS overlay at its next boot.

These tests drive the REAL `pin_measurement` with the subprocess/S3/KBS
edges faked, and assert on the TOML that was actually handed to the
signer — i.e. on the bytes the KBS would install.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings

from apps.lifecycle.models import VmState
from apps.orchestration.effects import EffectError
from apps.orchestration.models import MeasurementLedger
from apps.orchestration.services import allowlist_pin
from apps.orchestration.tests.factories import make_launch_record, make_vm
from apps.telemetry.models import HostAttestorRelease

# Distinct, well-formed 96-hex measurements.
BASE_M = "1" * 96
LIVE_LEDGER_M = "2" * 96
LIVE_EMIT_M = "3" * 96
DEAD_M = "4" * 96
HOST_M = "5" * 96
NEW_M = "6" * 96
SHARED_GOLDEN_M = "7" * 96

_BASE_MANIFEST = (
    "schema = 1\n"
    "epoch = 5\n"
    "\n"
    "[[entries]]\n"
    f'measurement_hex = "{BASE_M}"\n'
    'accepted_l1_kids_hex = ["6c31"]\n'
    'accepted_kbs_response_kids_hex = ["6b6273"]\n'
)


class _Harness:
    """Captures the manifest text each sign attempt was handed."""

    def __init__(self) -> None:
        self.signed: list[str] = []

    @property
    def last(self) -> dict[str, Any]:
        return tomllib.loads(self.signed[-1])

    def entries(self) -> list[dict[str, Any]]:
        return list(self.last.get("entries") or [])

    def measurements(self) -> list[str]:
        return [e["measurement_hex"] for e in self.entries()]

    def class_of(self, measurement: str) -> str:
        for e in self.entries():
            if e["measurement_hex"] == measurement:
                return str(e.get("class") or "tenant")
        raise AssertionError(f"{measurement[:8]}… absent from the signed manifest")


@pytest.fixture()
def harness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> _Harness:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(_BASE_MANIFEST, encoding="utf-8")
    seed = tmp_path / "seed.hex"
    seed.write_text("ab" * 32, encoding="utf-8")
    tool = tmp_path / "kbs-allowlist-tool"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)

    monkeypatch.setattr(settings, "VALI_ALLOWLIST_MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_S3_URL", "s3://bucket/key")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_TOOL_BIN", str(tool))
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", "")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", str(seed))

    h = _Harness()

    def fake_run(argv, *, label, timeout_s, env=None):  # noqa: ANN001, ANN202
        args = list(argv)
        with open(args[args.index("--manifest") + 1], encoding="utf-8") as fh:
            h.signed.append(fh.read())
        with open(args[args.index("--out") + 1], "wb") as fh:
            fh.write(b"\x00cose-bytes")
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(allowlist_pin, "_run", fake_run)
    monkeypatch.setattr(allowlist_pin, "_s3_upload", lambda *a, **k: None)
    monkeypatch.setattr(allowlist_pin, "_reload_kbs_allowlist", lambda *a, **k: None)
    return h


def _ledger(vm_id: str, digest: str, *, cls: str = "", epoch: int = 10) -> None:
    MeasurementLedger.objects.create(
        vm_id=vm_id,
        launch_digest_hex=digest,
        allowlist_epoch=epoch,
        measurement_class=cls,
    )


# ─── the bug: a re-pin must not evict what is already trusted ────────


@pytest.mark.django_db()
def test_pin_carries_forward_live_measurements(harness: _Harness) -> None:
    """THE regression. A live VM whose measurement was auto-pinned into a
    previous artifact must still be in the NEXT artifact — otherwise its
    next boot cannot pass `offline.contains(&report.measurement)`.

    Mutant killed: rebuilding from `base + 1` (the shipped bug).
    """
    vm = make_vm("live-1", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert BASE_M in got, "the base manifest's own entries must survive"
    assert LIVE_LEDGER_M in got, "a live VM's pinned measurement was EVICTED"
    assert NEW_M in got


@pytest.mark.django_db()
def test_first_ever_pin_on_an_empty_fleet(harness: _Harness) -> None:
    """With nothing to carry the artifact is exactly `base + {new}` — the
    pre-fix behaviour, which was only ever WRONG because of what it
    dropped."""
    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert harness.measurements() == [BASE_M, NEW_M]


@pytest.mark.django_db()
def test_pin_carries_forward_from_launch_job_when_ledger_has_a_hole(
    harness: _Harness,
) -> None:
    """The `MeasurementLedger` write is best-effort, so it has holes. The
    latest `LaunchJob.result_json['emit']['measurement_hex']` is the
    second source — the one the live measurements were recovered from.

    Mutant killed: sourcing the carry set from the ledger alone.
    """
    vm = make_vm("live-2", state=VmState.ACTIVE)
    make_launch_record(vm, measurement_hex=LIVE_EMIT_M)  # no ledger row

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert LIVE_EMIT_M in harness.measurements()


@pytest.mark.django_db()
def test_pin_does_not_carry_a_destroyed_vm(harness: _Harness) -> None:
    """Growth bound: a destroyed VM's image must NOT stay admissible.

    Mutant killed: carrying every measurement ever pinned.
    """
    dead = make_vm("dead-1", state=VmState.DESTROYED)
    _ledger(dead.vm_id, DEAD_M)
    live = make_vm("live-3", state=VmState.ACTIVE)
    _ledger(live.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert DEAD_M not in got, "a DESTROYED VM's measurement was carried forward"
    assert LIVE_LEDGER_M in got


@pytest.mark.django_db()
def test_dead_state_filter_is_case_insensitive(harness: _Harness) -> None:
    """`VmState` values are lower-case in the DB; a mixed-case row must
    still be recognised as dead (and, symmetrically, a mixed-case live
    state must not be mistaken for dead)."""
    dead = make_vm("dead-2", state=VmState.DESTROYED)
    dead.state = "DESTROYED"
    dead.save(update_fields=["state"])
    _ledger(dead.vm_id, DEAD_M)
    live = make_vm("live-4", state=VmState.ACTIVE)
    live.state = "Active"
    live.save(update_fields=["state"])
    _ledger(live.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert DEAD_M not in got
    assert LIVE_LEDGER_M in got


@pytest.mark.django_db()
def test_migrating_and_decommissioning_vms_are_carried(harness: _Harness) -> None:
    """Only terminal states may be dropped — a migrating VM still has to
    unlock on its destination, and a decommissioning one has not been
    crypto-erased yet."""
    migrating = make_vm("mig-1", state=VmState.ACTIVE)
    migrating.state = VmState.MIGRATING
    migrating.new_generation = migrating.generation + 1
    migrating.migration_dest = "node-dst"
    migrating.save(update_fields=["state", "new_generation", "migration_dest"])
    _ledger(migrating.vm_id, LIVE_LEDGER_M)
    decom = make_vm("dec-1", state=VmState.DECOMMISSIONING)
    _ledger(decom.vm_id, LIVE_EMIT_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert LIVE_LEDGER_M in got
    assert LIVE_EMIT_M in got


# ─── fail-closed, not best-effort ────────────────────────────────────


@pytest.mark.django_db()
def test_carry_forward_query_failure_raises(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DB failure must ABORT the pin. Silently degrading to `base + 1`
    is exactly the eviction bug — the opposite of `_installed_epoch_floor`,
    which is only an optimisation and may swallow.

    Mutant killed: `except Exception: return {}` in the carry-forward.
    """
    make_vm("live-5", state=VmState.ACTIVE)

    def boom() -> dict[str, str]:
        raise RuntimeError("db down")

    monkeypatch.setattr(allowlist_pin, "_query_carry_forward_classes", boom)

    with pytest.raises(EffectError, match="carry-forward"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert harness.signed == [], "nothing may be signed when the set is unknown"


@pytest.mark.django_db()
def test_carry_forward_wraps_db_error_as_effect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public helper maps ANY underlying failure to a fail-closed
    `EffectError` (never `None`, never an empty dict)."""

    def boom() -> dict[str, str]:
        raise ValueError("column missing")

    monkeypatch.setattr(allowlist_pin, "_query_carry_forward_classes", boom)
    with pytest.raises(EffectError, match="refusing to sign"):
        allowlist_pin._carry_forward_classes()


@pytest.mark.django_db()
def test_unparseable_base_manifest_raises(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The base manifest is parsed to dedup against it; a manifest we
    cannot parse fails the pin rather than risking a duplicate entry
    (which the signing tool refuses anyway)."""
    bad = tmp_path / "bad.toml"
    bad.write_text("epoch = 5\nthis is not toml\n", encoding="utf-8")
    monkeypatch.setattr(settings, "VALI_ALLOWLIST_MANIFEST_PATH", str(bad))

    with pytest.raises(EffectError, match="not valid TOML"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)


# ─── §22 trust class: a host-attestor measurement is NEVER tenant ────


@pytest.mark.django_db()
def test_host_attestor_release_is_carried_with_its_class(
    harness: _Harness,
) -> None:
    """An active host-attestor release must be carried forward WITH
    `class = "host_attestor"`. Re-emitting it as `tenant` would let a
    host-attestor measurement satisfy a TENANT release — strictly worse
    than the availability bug being fixed.

    Mutant killed: defaulting every carried entry to `tenant`.
    """
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=True)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert HOST_M in harness.measurements()
    assert harness.class_of(HOST_M) == "host_attestor"
    assert harness.class_of(NEW_M) == "tenant"


@pytest.mark.django_db()
def test_inactive_host_attestor_release_is_not_carried(
    harness: _Harness,
) -> None:
    """Only the {current, previous} grace window stays trusted — a
    release trimmed out of it is not re-admitted."""
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=False)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert HOST_M not in harness.measurements()


@pytest.mark.django_db()
def test_class_ambiguity_between_sources_raises(harness: _Harness) -> None:
    """The same measurement claimed by BOTH a live VM and an active
    host-attestor release is unresolvable — fail closed rather than pick
    `tenant`."""
    vm = make_vm("live-6", state=VmState.ACTIVE)
    _ledger(vm.vm_id, HOST_M)
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=True)

    with pytest.raises(EffectError, match="§22 class"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)
    assert harness.signed == []


@pytest.mark.django_db()
def test_trimmed_host_attestor_measurement_can_never_become_tenant(
    harness: _Harness,
) -> None:
    """A release trimmed out of the grace window is no longer carried —
    but if a live VM then claims that measurement (the "auto-pinned from
    a miner report" bleed the class namespace exists to stop) it must NOT
    be re-admitted as `tenant`.

    Mutant killed: sourcing the host-attestor blocklist from `is_active`
    rows only.
    """
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=False)
    vm = make_vm("live-15", state=VmState.ACTIVE)
    make_launch_record(vm, measurement_hex=HOST_M)

    with pytest.raises(EffectError, match="§22 class"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)
    assert harness.signed == []


@pytest.mark.django_db()
def test_host_attestor_ledger_sentinel_vetoes_a_tenant_re_emit(
    harness: _Harness,
) -> None:
    """The audit ledger's `host-attestor-release` sentinel row records
    the class a host-attestor pin used. It vetoes a tenant re-emit of
    that measurement even with no `HostAttestorRelease` row in sight.

    Mutant killed: scoping the class veto to LIVE VMs' ledger rows.
    """
    _ledger(
        "host-attestor-release",
        HOST_M,
        cls=allowlist_pin.ALLOWLIST_CLASS_HOST_ATTESTOR,
    )
    vm = make_vm("live-16", state=VmState.ACTIVE)
    make_launch_record(vm, measurement_hex=HOST_M)

    with pytest.raises(EffectError, match="different §22 class"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)
    assert harness.signed == []


@pytest.mark.django_db()
def test_ledger_recorded_class_vetoes_a_tenant_re_emit(
    harness: _Harness,
) -> None:
    """The ledger records the class each pin used. A row that says
    `host_attestor` for a measurement the derivation resolved as
    `tenant` fails the pin — the derivation may never silently
    downgrade a recorded class.

    Mutant killed: ignoring `MeasurementLedger.measurement_class`.
    """
    vm = make_vm("live-7", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M, cls=allowlist_pin.ALLOWLIST_CLASS_HOST_ATTESTOR)

    with pytest.raises(EffectError, match="different §22 class"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)
    assert harness.signed == []


@pytest.mark.django_db()
def test_pinning_a_carried_measurement_under_a_new_class_raises(
    harness: _Harness,
) -> None:
    """Re-pinning a measurement that is already carried as `tenant` under
    the `host_attestor` class (or vice-versa) is refused."""
    vm = make_vm("live-8", state=VmState.ACTIVE)
    _ledger(vm.vm_id, NEW_M)

    with pytest.raises(EffectError, match="refusing to re-pin"):
        allowlist_pin.pin_measurement(
            measurement_hex=NEW_M,
            measurement_class=allowlist_pin.ALLOWLIST_CLASS_HOST_ATTESTOR,
        )
    assert harness.signed == []


@pytest.mark.django_db()
def test_base_manifest_class_mismatch_raises(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """A measurement present in the base manifest under one class but
    resolving to another is class-ambiguous — refuse."""
    manifest = tmp_path / "m.toml"
    manifest.write_text(
        _BASE_MANIFEST
        + "\n[[entries]]\n"
        + f'measurement_hex = "{HOST_M}"\n'
        + 'accepted_l1_kids_hex = ["6c31"]\n'
        + 'accepted_kbs_response_kids_hex = ["6b6273"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VALI_ALLOWLIST_MANIFEST_PATH", str(manifest))
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=True)

    with pytest.raises(EffectError, match="class-ambiguous"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)


# ─── dedup: a duplicate ABORTS the signing tool ──────────────────────


@pytest.mark.django_db()
def test_shared_golden_measurement_emits_one_entry(harness: _Harness) -> None:
    """Several VMs share a golden image measurement. The signing tool
    refuses a manifest with a duplicate measurement (and the KBS demands
    strictly-ascending unique entries), so a duplicate would ABORT the
    pin, not merely bloat it.

    Mutant killed: appending one entry per source row.
    """
    for i in range(3):
        vm = make_vm(f"golden-{i}", state=VmState.ACTIVE)
        _ledger(vm.vm_id, SHARED_GOLDEN_M)
        make_launch_record(vm, measurement_hex=SHARED_GOLDEN_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert got.count(SHARED_GOLDEN_M) == 1
    assert len(got) == len(set(got)), "duplicate [[entries]] would abort signing"


@pytest.mark.django_db()
def test_new_measurement_already_carried_is_not_duplicated(
    harness: _Harness,
) -> None:
    """Re-pinning the measurement of a VM that is already carried (a
    relaunch / reboot-recovery) must emit exactly one entry."""
    vm = make_vm("live-9", state=VmState.ACTIVE)
    _ledger(vm.vm_id, NEW_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert got.count(NEW_M) == 1


@pytest.mark.django_db()
def test_measurement_already_in_base_is_not_re_appended(
    harness: _Harness,
) -> None:
    """Base entries survive the rewrite verbatim — re-appending one would
    duplicate it and abort the signing tool."""
    vm = make_vm("live-10", state=VmState.ACTIVE)
    _ledger(vm.vm_id, BASE_M)

    allowlist_pin.pin_measurement(measurement_hex=BASE_M)

    got = harness.measurements()
    assert got.count(BASE_M) == 1


@pytest.mark.django_db()
def test_malformed_ledger_digest_is_skipped_not_fatal(
    harness: _Harness,
) -> None:
    """A junk digest could never have been pinned (`pin_measurement`
    validates 96-hex before signing), so dropping it evicts nothing — and
    it must not brick every launch."""
    vm = make_vm("live-11", state=VmState.ACTIVE)
    _ledger(vm.vm_id, "not-a-digest")
    _ledger(vm.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    got = harness.measurements()
    assert LIVE_LEDGER_M in got
    assert all(len(m) == 96 for m in got)


# ─── growth bound ────────────────────────────────────────────────────


@pytest.mark.django_db()
def test_carry_forward_cap_fails_closed(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The live-VM scope is the growth bound; blowing the cap means the
    filter stopped filtering. Refuse rather than sign a runaway set."""
    monkeypatch.setattr(allowlist_pin, "_MAX_CARRY_FORWARD_ENTRIES", 2)
    for i in range(3):
        vm = make_vm(f"many-{i}", state=VmState.ACTIVE)
        _ledger(vm.vm_id, f"{i}{'a' * 95}")

    with pytest.raises(EffectError, match="cap"):
        allowlist_pin.pin_measurement(measurement_hex=NEW_M)


# ─── the epoch machinery keeps working ───────────────────────────────


@pytest.mark.django_db()
def test_epoch_retry_preserves_the_full_entry_set(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 409 retry must re-emit the SAME cumulative entry set at a higher
    epoch — the retry may not quietly rebuild a narrower artifact."""
    vm = make_vm("live-12", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M, epoch=5)

    calls = {"n": 0}

    def flaky(_cose: bytes) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise allowlist_pin.AllowlistEpochConflict("409")

    monkeypatch.setattr(allowlist_pin, "_reload_kbs_allowlist", flaky)

    result = allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert len(harness.signed) == 2
    first = tomllib.loads(harness.signed[0])
    second = tomllib.loads(harness.signed[1])
    assert [e["measurement_hex"] for e in first["entries"]] == [
        e["measurement_hex"] for e in second["entries"]
    ]
    assert second["epoch"] > first["epoch"]
    assert result.new_epoch == second["epoch"]


@pytest.mark.django_db()
def test_epoch_floor_still_seeds_from_the_ledger(harness: _Harness) -> None:
    """`_installed_epoch_floor` (the HWM-drift fix) must keep working
    alongside the carry-forward."""
    vm = make_vm("live-13", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M, epoch=2600000116)

    result = allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    assert result.new_epoch == 2600000117
    assert harness.last["epoch"] == 2600000117


@pytest.mark.django_db()
def test_carried_entries_carry_the_default_kids(harness: _Harness) -> None:
    """Every pin this control plane has emitted used the module default
    kids, so a carried entry re-states them (an entry with no kids is
    rejected by both the tool and the KBS)."""
    vm = make_vm("live-14", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    carried = next(
        e for e in harness.entries() if e["measurement_hex"] == LIVE_LEDGER_M
    )
    assert carried["accepted_l1_kids_hex"] == [allowlist_pin.DEFAULT_L1_KID_HEX]
    assert carried["accepted_kbs_response_kids_hex"] == [
        allowlist_pin.DEFAULT_KBS_RESPONSE_KID_HEX
    ]


@pytest.mark.django_db()
def test_explicit_kids_apply_only_to_the_new_measurement(
    harness: _Harness,
) -> None:
    """Kids passed to `pin_measurement` describe the measurement being
    pinned NOW. A carried entry keeps the module defaults — the kids it
    was originally installed with — instead of being silently re-bound to
    the caller's."""
    vm = make_vm("live-17", state=VmState.ACTIVE)
    _ledger(vm.vm_id, LIVE_LEDGER_M)

    allowlist_pin.pin_measurement(
        measurement_hex=NEW_M,
        l1_kids_hex=("deadbeef",),
        kbs_response_kids_hex=("feedface",),
    )

    entries = {e["measurement_hex"]: e for e in harness.entries()}
    assert entries[NEW_M]["accepted_l1_kids_hex"] == ["deadbeef"]
    assert entries[NEW_M]["accepted_kbs_response_kids_hex"] == ["feedface"]
    carried = entries[LIVE_LEDGER_M]
    assert carried["accepted_l1_kids_hex"] == [allowlist_pin.DEFAULT_L1_KID_HEX]
    assert carried["accepted_kbs_response_kids_hex"] == [
        allowlist_pin.DEFAULT_KBS_RESPONSE_KID_HEX
    ]


# ─── real signing tool: the rebuilt manifest must actually MINT ──────


_REPO_ROOT = Path(__file__).resolve().parents[4]
# Captured at import, BEFORE the `harness` fixture fakes it out.
_REAL_RUN = allowlist_pin._run


def _real_tool() -> str | None:
    for profile in ("release", "debug"):
        candidate = _REPO_ROOT / "target" / profile / "hippius-kbs-allowlist-tool"
        if os.access(candidate, os.X_OK):
            return str(candidate)
    return None


@pytest.mark.django_db()
def test_rebuilt_manifest_signs_with_the_real_tool(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """End-to-end against the REAL `hippius-kbs-allowlist-tool`: a
    multi-entry rebuilt manifest must mint. The tool re-parses what it is
    about to write through `kbs_core::allowlist::parse_and_verify` before
    emitting, so a successful mint proves the KBS would accept these
    bytes — including the "entries sorted ascending and unique" rule that
    `into_indexed` enforces (a duplicate carried entry aborts the mint).

    Skips when the binary is not built (the CI `vali` job is pure Python;
    the `rust` job covers the binary).
    """
    tool = _real_tool()
    if tool is None:
        pytest.skip("hippius-kbs-allowlist-tool not built — run `cargo build`")
    monkeypatch.setattr(settings, "VALI_KBS_ALLOWLIST_TOOL_BIN", tool)
    # Un-fake the subprocess runner: this test wants the REAL mint.
    monkeypatch.setattr(allowlist_pin, "_run", _REAL_RUN)
    # The tool's manifest schema is `deny_unknown_fields` (epoch+entries
    # only), so use a production-shaped base rather than the fixture's.
    manifest = tmp_path / "real-manifest.toml"
    manifest.write_text(
        "epoch = 5\n"
        "\n[[entries]]\n"
        f'measurement_hex = "{BASE_M}"\n'
        f'accepted_l1_kids_hex = ["{allowlist_pin.DEFAULT_L1_KID_HEX}"]\n'
        "accepted_kbs_response_kids_hex = "
        f'["{allowlist_pin.DEFAULT_KBS_RESPONSE_KID_HEX}"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "VALI_ALLOWLIST_MANIFEST_PATH", str(manifest))

    posted: list[bytes] = []
    monkeypatch.setattr(
        allowlist_pin, "_reload_kbs_allowlist", lambda b: posted.append(b)
    )

    for i in range(4):
        vm = make_vm(f"real-{i}", state=VmState.ACTIVE)
        _ledger(vm.vm_id, f"{i}{'b' * 95}", epoch=10)
    HostAttestorRelease.objects.create(measurement=HOST_M, is_active=True)

    result = allowlist_pin.pin_measurement(measurement_hex=NEW_M)

    # 1 base + 4 live tenants + 1 host-attestor + the new one = 7 entries,
    # all minted into one COSE the KBS would accept.
    assert posted, "the signed artifact was never handed to the reload"
    assert (
        hashlib.sha256(posted[0]).hexdigest() == result.new_cose_sha256_hex
    )
    # `_installed_epoch_floor` seeds from the ledger's max epoch (10).
    assert result.new_epoch == 11
