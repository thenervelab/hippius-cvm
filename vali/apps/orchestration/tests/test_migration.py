"""§25 migration orchestrator tests.

Each test drives a real `MigrationJob` through `service.tick_once()`
with `effects` mocked by the autouse `fx` controller.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState
from apps.orchestration import effects, service
from apps.orchestration.effects import EffectError
from apps.orchestration.fence import release_allowed
from apps.orchestration.models import MigrationJob, MigrationState

from .conftest import FakeEffects
from .factories import (
    make_launch_record,
    make_migration_job,
    make_service_client,
    make_vm,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """§25's same-CPU-gen gate resolves the source/dest generation from each
    miner's registered CHIP_ID length. Register `node-src` + `node-dst` (the
    hosts every test migrates between) as the SAME generation (Genoa,
    64-byte chip_id) so the gate passes; cross-gen is covered by a dedicated
    test. `get_or_create` so a test that registers them itself is a no-op."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def _drive_until(job: MigrationJob, target: str, *, limit: int = 25) -> None:
    """Tick until `job` reaches `target` (refreshing it each cycle)."""
    for _ in range(limit):
        service.tick_once()
        job.refresh_from_db()
        if job.state == target:
            return
    raise AssertionError(f"job stuck at {job.state!r}, never reached {target!r}")


def _backdate_phase(job: MigrationJob) -> None:
    """Age the job's current phase past any timeout."""
    MigrationJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )


# ─── happy path ──────────────────────────────────────────────────────


def test_migration_happy_path_end_to_end(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value

    _drive_until(job, MigrationState.DONE.value)

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.DONE.value
    assert job.source_ack_verified is True
    assert job.finished_at is not None
    # The VM is now Active on the destination, one generation up.
    assert vm.state == VmState.ACTIVE
    assert vm.generation == 6
    assert vm.host == "node-dst"
    assert vm.migration_dest == ""
    assert vm.new_generation is None
    # Each guest-ward / KBS effect was performed.
    assert fx.did("relay_quiesce")
    assert fx.did("trigger_snapshot")
    assert fx.did("kbs_activate_dest")
    # §25 M4 — the dest miner was actually told to restore + boot.
    assert fx.did("dispatch_migrate_activate")


def test_migration_preserves_eol_nonce_on_the_dest(fx: FakeEffects) -> None:
    # The migrated guest is LIVE again at new_gen booting the SAME measured
    # cmdline, so its baked eol_nonce is unchanged — vali must PRESERVE
    # Vm.eol_nonce through Migrating→Active. Clearing it would strand the
    # migrated VM: it could neither be RE-migrated (start_migration requires
    # eol_nonce) nor cleanly §24-decommissioned (_verify_ack reads it).
    launch_nonce = b"\x5a" * 32
    vm = make_vm(generation=5, host="node-src", eol_nonce=launch_nonce)
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert vm.generation == 6
    # The nonce survived — same launch-baked bytes the guest still signs with.
    assert vm.eol_nonce is not None
    assert bytes(vm.eol_nonce) == launch_nonce
    # …and signing_generation is preserved (guest still signs at its launch
    # gen) while the live generation advanced — so a SECOND migration
    # COMPLETES end-to-end (the nonce-gate passes AND the source-ack verifies
    # at the baked signing_generation). Pre-fix this stranded the tenant
    # powered-off; now it re-migrates cleanly back to Done.
    assert vm.signing_generation == 5
    job2 = service.start_migration(
        vm=vm, dest_node_id="node-src", decided_by=make_service_client()
    )
    _drive_until(job2, MigrationState.DONE.value)
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert vm.generation == 7  # bumped again
    assert vm.signing_generation == 5  # still the launch gen
    assert bytes(vm.eol_nonce) == launch_nonce  # still preserved


def test_migration_is_non_destructive_never_crypto_erases(fx: FakeEffects) -> None:
    # COLD-migration shutdown-sign is NON-DESTRUCTIVE: the source guest's EOL
    # teardown is luksClose + poweroff (mapping only), and §25 must NEVER
    # crypto-erase — the encrypted disk survives for the snapshot + the dest
    # restore, and the SAME KEK is re-released at the new generation. Only §24
    # decommission crypto-erases.
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    assert not fx.did("crypto_erase_kek_transit"), (
        "§25 migration must be non-destructive — never crypto-erase the KEK"
    )


def _capture_verify_generation(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    from apps.lifecycle import validator as lifecycle_validator

    seen: dict[str, int] = {}

    def _capture(**kwargs: object) -> object:
        seen["vm_generation"] = int(kwargs["vm_generation"])  # type: ignore[arg-type]
        return lifecycle_validator.VerifiedStoppedAck(now_unix=1_700_000_000)

    monkeypatch.setattr(lifecycle_validator, "verify_stopped_ack", _capture)
    return seen


def test_source_ack_is_verified_at_signing_generation(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # For a never-migrated VM signing_generation == generation (5), so the
    # source ack verifies at 5 (not new_gen=6).
    seen = _capture_verify_generation(monkeypatch)
    vm = make_vm(generation=5, host="node-src")  # signing_generation defaults to 5
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)
    assert seen.get("vm_generation") == 5


def test_remigration_source_ack_verifies_at_baked_signing_generation(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A MIGRATED VM: live generation bumped to 6 by a prior fence, but the
    # guest still signs at its BAKED launch generation (1). The source ack
    # of a RE-migration must be verified at signing_generation (1), NOT the
    # live/source generation (6) — else the guest's launch-gen signature
    # would be checked against the wrong generation and never verify.
    seen = _capture_verify_generation(monkeypatch)
    vm = make_vm(generation=6, signing_generation=1, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)
    assert seen.get("vm_generation") == 1, "re-migration verifies at the baked gen"
    vm.refresh_from_db()
    # The migration bumped the live generation (fence) but LEFT the baked
    # signing_generation — the guest's cmdline is never re-baked.
    assert vm.generation == 7
    assert vm.signing_generation == 1


def test_eol_nonce_is_the_launch_baked_value_preserved_at_start(
    fx: FakeEffects,
) -> None:
    # §24/§25 GAP 3: the EOL nonce is the LAUNCH-baked value (set in the
    # measured cmdline + persisted on Vm.eol_nonce at launch). It is the
    # value the guest signs its stopped-ack with. `start_migration` does
    # NOT re-mint it — re-minting would hand the verifier a nonce the
    # running guest never saw → fail closed forever → spurious quarantine.
    launch_nonce = b"\xab" * 32
    vm = make_vm(generation=5, host="node-src", eol_nonce=launch_nonce)
    service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    vm.refresh_from_db()
    assert vm.eol_nonce is not None
    # UNCHANGED — the launch-baked nonce is preserved, not re-minted.
    assert bytes(vm.eol_nonce) == launch_nonce


def test_start_migration_fails_closed_when_launch_baked_no_nonce(
    fx: FakeEffects,
) -> None:
    # A VM with no eol_nonce was never launched through the GAP-3 path —
    # its stopped-ack could never verify, so the migration must not start.
    vm = make_vm(generation=5, host="node-src", eol_nonce=None)
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
        )
    assert exc.value.category == "no-eol-nonce"


def test_cross_generation_migration_is_refused(fx: FakeEffects) -> None:
    # The dest re-mints the source's measurement, so a dest of a DIFFERENT
    # SNP generation would fail the KBS release. Refuse it at intake.
    from apps.miners.models import MinerIdentity

    # node-src is Genoa (64-byte, from the autouse fixture); register a Turin
    # (8-byte chip_id) dest.
    MinerIdentity.objects.create(
        miner_id="node-turin", pubkey_hex="cc" * 32, platform_id="33" * 8
    )
    vm = make_vm(generation=5, host="node-src")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-turin", decided_by=make_service_client()
        )
    assert exc.value.category == "cross-gen"


def test_migration_to_an_unregistered_dest_is_refused(fx: FakeEffects) -> None:
    # A dest with no MinerIdentity has no resolvable generation (and could
    # not be reached/attested anyway) — fail closed.
    vm = make_vm(generation=5, host="node-src")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="ghost-miner", decided_by=make_service_client()
        )
    assert exc.value.category == "miner-unknown"


def test_migration_with_a_malformed_platform_id_is_refused(fx: FakeEffects) -> None:
    # A miner whose registered platform_id is not a valid CHIP_ID (not hex, or
    # neither 8 nor 64 bytes) has no resolvable SNP generation, so the same-gen
    # gate cannot be evaluated — fail closed at intake with a DISTINCT category
    # rather than letting the migration proceed on an unknown generation.
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="node-badchip",
        pubkey_hex="dd" * 32,
        platform_id="ff" * 12,  # 12 bytes — neither Turin (8) nor Genoa (64)
    )
    vm = make_vm(generation=5, host="node-src")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-badchip", decided_by=make_service_client()
        )
    assert exc.value.category == "platform-id-invalid"


def test_migration_refuses_when_the_SOURCE_miner_is_unknown(fx: FakeEffects) -> None:
    # `miner-unknown` covers the SOURCE too: the VM's current host is resolved
    # BEFORE the destination, so a VM sitting on an unregistered miner is
    # refused naming that host — the SDK documents this, so pin it.
    vm = make_vm(generation=5, host="ghost-host")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
        )
    assert exc.value.category == "miner-unknown"
    assert "ghost-host" in str(exc.value)


_GOLDEN_MEASURED = (
    "ro console=ttyS0 hippius.kbs_url=vsock://2:19266 "
    "dm-verity.root=" + "ab" * 32 + " boot=hippius-golden"
)


def test_golden_migration_is_enabled(fx: FakeEffects) -> None:
    # Golden §25 migration is ENABLED (the #859 intake guard was lifted once
    # the golden guest ack was proven to deliver). A golden VM whose launch
    # record carries the persisted measured cmdline starts a MigrationJob
    # exactly like a legacy VM.
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(
        vm, disk_mode="golden_verity_overlay", measured_cmdline=_GOLDEN_MEASURED
    )
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value


def test_start_migration_refuses_a_golden_vm_without_measured_cmdline(
    fx: FakeEffects,
) -> None:
    # A golden VM launched BEFORE measured_cmdline was persisted must be
    # refused at INTAKE — before the quiesce fences + stops the source and
    # kbs_activate_dest denies the old gen (which would strand it). The source
    # Vm must be left untouched (still Active on its host).
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")  # no measured_cmdline
    with pytest.raises(service.StartError) as ei:
        service.start_migration(
            vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
        )
    assert ei.value.category == "not-migratable"
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE  # source NEVER fenced
    assert vm.host == "node-src"
    # No job row was created.
    assert not MigrationJob.objects.filter(vm=vm).exists()


def test_golden_source_ack_timeout_does_not_quarantine_the_source(
    fx: FakeEffects,
) -> None:
    # Defence-in-depth for the newly-enabled golden path: if a GOLDEN
    # migration ever times out at AwaitingSourceAck, it must fail closed
    # WITHOUT quarantining the source — a conservative safety net so a
    # spurious timeout on a not-yet-battle-tested path can't take a healthy
    # real-tenant miner offline.
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")
    # Build a migration job parked at AwaitingSourceAck, phase aged past the
    # ack timeout.
    job = make_migration_job(vm, state=MigrationState.AWAITING_SOURCE_ACK)
    _backdate_phase(job)
    service._on_migration_poll_timeout(job)
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert job.quarantine_node_id == ""  # source NOT quarantined
    assert "golden-no-quarantine" in job.reason


def test_cross_gen_chain_ids_excludes_only_the_other_generation() -> None:
    # The auto-migration same-gen filter (operates on chain node_ids): given a
    # Genoa (64-byte) source, only the Turin (8-byte) candidates are excluded;
    # a same-gen Genoa candidate is kept.
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="src",
        pubkey_hex="a1" * 32,
        platform_id="ab" * 64,
        chain_node_id="aa" * 32,  # Genoa source
    )
    MinerIdentity.objects.create(
        miner_id="genoa",
        pubkey_hex="b2" * 32,
        platform_id="cd" * 64,
        chain_node_id="bb" * 32,  # Genoa candidate — kept
    )
    MinerIdentity.objects.create(
        miner_id="turin",
        pubkey_hex="c3" * 32,
        platform_id="ef" * 8,
        chain_node_id="cc" * 32,  # Turin candidate — excluded
    )
    candidates = frozenset({"bb" * 32, "cc" * 32})
    excluded = service._cross_gen_chain_ids("aa" * 32, candidates)
    assert excluded == frozenset({"cc" * 32})  # only the cross-gen Turin


def test_quiesce_relays_the_nonce_and_source_gen_to_the_source(
    fx: FakeEffects,
) -> None:
    # §25 M3 producer: the quiesce relay carries the source_gen the guest
    # must sign at (its CURRENT generation, NOT new_gen).
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.SNAPSHOTTING.value)
    # relay_quiesce was called with source_gen == 5 (== the VM's gen).
    quiesce_calls = [c for c in fx.calls if c[0] == "relay_quiesce"]
    assert quiesce_calls, "the quiesce was relayed"
    assert quiesce_calls[0][2] == 5, "the source signs at source_gen (5), not new_gen"


def test_fence_preserves_the_launch_baked_nonce(fx: FakeEffects) -> None:
    # §24/§25 GAP 3: the FENCING step must NOT re-mint the nonce — the
    # guest has already signed its ack with the LAUNCH-baked nonce. A
    # re-mint would invalidate that ack (vali would verify against a nonce
    # the guest never saw → fail closed forever → spurious quarantine).
    launch_nonce = b"\xcd" * 32
    vm = make_vm(generation=5, host="node-src", eol_nonce=launch_nonce)
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    vm.refresh_from_db()
    nonce_at_start = bytes(vm.eol_nonce)
    assert nonce_at_start == launch_nonce

    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)
    vm.refresh_from_db()
    # The VM is fenced (Migrating) but the nonce is UNCHANGED across the
    # fence — the same bytes the source signed at quiesce time.
    assert vm.state == VmState.MIGRATING
    assert bytes(vm.eol_nonce) == nonce_at_start


def test_fence_precedes_the_quiesce_so_the_ack_can_ingest(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # REGRESSION: the source guest signs + POSTs its stopped-ack DURING the
    # quiesce shutdown, and `StoppedAckIngestView` only accepts an ack for a
    # VM already in Migrating/Decommissioning. So the fence (Active→Migrating)
    # MUST happen BEFORE relay_quiesce dispatches — otherwise the ack races in
    # while the VM is still Active → 404 → the migration hangs at
    # AwaitingSourceAck forever (the golden §25 hang this fixes).
    #
    # Assert ordering at the effect level: at the moment relay_quiesce is
    # relayed, the VM is already Migrating.
    vm = make_vm(generation=5, host="node-src")
    vm_state_at_quiesce: list[str] = []
    original_relay = effects.relay_quiesce

    def _record_state(v: Any, *, source_gen: int) -> None:
        v.refresh_from_db()
        vm_state_at_quiesce.append(v.state)
        original_relay(v, source_gen=source_gen)

    monkeypatch.setattr(effects, "relay_quiesce", _record_state)

    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.SNAPSHOTTING.value)

    assert vm_state_at_quiesce == [VmState.MIGRATING.value], (
        "the VM must be fenced (Migrating) BEFORE the quiesce dispatches, so "
        "the guest's stopped-ack ingests"
    )


def test_migration_fences_the_vm_before_awaiting_the_ack(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    vm.refresh_from_db()
    # §25 generation fence applied: the VM is Migrating, new gen + dest
    # recorded, and the launch-baked EOL nonce is preserved for the source
    # to sign (GAP 3 — NOT minted at the fence).
    assert vm.state == VmState.MIGRATING
    assert vm.new_generation == 6
    assert vm.migration_dest == "node-dst"
    assert vm.eol_nonce is not None


# ─── split-brain: source-ack timeout ─────────────────────────────────


def test_source_ack_timeout_quarantines_source_and_never_activates_dest(
    fx: FakeEffects,
) -> None:
    # The source guest never produces a stopped ack.
    fx.source_ack = None
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    # Age the ack-wait past its timeout, then run one more tick.
    _backdate_phase(job)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    # Fails closed — §13-quarantines the source.
    assert job.state == MigrationState.FAILED.value
    assert "source-ack-timeout" in job.reason
    assert job.quarantine_node_id == "node-src"
    # SPLIT-BRAIN INVARIANT: the destination is NEVER activated on an
    # ack timeout — `kbs_activate_dest` was not called, and the VM
    # stays Migrating (fenced), still bound to the source host.
    assert not fx.did("kbs_activate_dest")
    # …and the dest miner is NEVER told to restore + boot.
    assert not fx.did("dispatch_migrate_activate")
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"


def test_invalid_source_ack_never_advances_past_awaiting(fx: FakeEffects) -> None:
    # A delivered ack that fails verification must not advance the job.
    fx.ack_valid = False
    vm = make_vm()
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)
    for _ in range(5):
        service.tick_once()

    job.refresh_from_db()
    # Fail-closed: a bad ack keeps the job waiting; never DestActivating.
    assert job.state == MigrationState.AWAITING_SOURCE_ACK.value
    assert job.source_ack_verified is False
    assert not fx.did("kbs_activate_dest")


# ─── dest-activation (async restore poll) ────────────────────────────


def test_dest_activation_waits_while_the_dest_restore_runs(fx: FakeEffects) -> None:
    # The dest ACKs migrate-activate immediately and restores on a background
    # task; vali polls the dest status. While it reports `running` the job
    # STAYS in DestActivating (the Vm is NOT activated yet).
    fx.dest_activation_status = "running"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    for _ in range(5):
        service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value
    # The dest was dispatched, but the Vm is not activated until the restore
    # reports `done` — it is still fenced-Migrating on the source host.
    assert fx.did("dispatch_migrate_activate")
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"


def test_dest_activation_completes_when_the_restore_reports_done(
    fx: FakeEffects,
) -> None:
    # `running` first, then `done` → the Vm activates on the dest at new_gen.
    fx.dest_activation_status = "running"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value  # still restoring

    fx.dest_activation_status = "done"
    for _ in range(3):
        service.tick_once()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.DONE.value
    assert vm.state == VmState.ACTIVE
    assert vm.host == "node-dst"
    assert vm.generation == 6


def test_dest_activation_failure_fails_closed_without_activating(
    fx: FakeEffects,
) -> None:
    # The dest restore/boot fails → the migration fails closed and the Vm is
    # NEVER activated on the dest (split-brain gate holds; it stays fenced).
    # Like the snapshot-failure path (`_h_mig_uploading`), a `failed` poll
    # raises a retryable error that terminates at the phase deadline.
    fx.dest_activation_status = "failed"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    # It retries `failed` until the deadline, then fails closed.
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value
    _backdate_phase(job)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert vm.state == VmState.MIGRATING  # never activated on the dest
    assert vm.host == "node-src"


def test_dest_activation_timeout_fails_without_activating(fx: FakeEffects) -> None:
    # The dest restore never completes (stuck `running`) → after the (longer)
    # activation timeout the job fails closed; the dest is never activated.
    fx.dest_activation_status = "running"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    # Age past the (longer) activation timeout — `_backdate_phase` ages 1h,
    # well past the 20-min default `_activate_timeout`.
    _backdate_phase(job)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"


# ─── generation fence ────────────────────────────────────────────────


def test_generation_fence_refuses_source_release_after_commit(
    fx: FakeEffects,
) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)
    vm.refresh_from_db()

    # After the migration commits, the §24/§25 fence denies every
    # release that targets the old source or the old generation —
    # exactly the rule the KBS enforces before a key release.
    assert release_allowed(vm, node_id="node-src", generation=5) is False
    assert release_allowed(vm, node_id="node-src", generation=6) is False
    assert release_allowed(vm, node_id="node-dst", generation=5) is False
    # Only the committed destination at the advanced generation passes.
    assert release_allowed(vm, node_id="node-dst", generation=6) is True


# ─── concurrency ─────────────────────────────────────────────────────


def test_concurrent_migration_for_same_vm_is_rejected() -> None:
    vm = make_vm()
    actor = make_service_client()
    service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=actor)
    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-other", decided_by=actor)
    assert exc.value.category == "job-in-flight"
    assert MigrationJob.objects.filter(vm=vm).count() == 1


def test_migration_rejected_when_vm_not_active() -> None:
    vm = make_vm(state=VmState.DECOMMISSIONING)
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
        )
    assert exc.value.category == "vm-not-active"


def test_migration_rejected_when_dest_is_the_current_host() -> None:
    vm = make_vm(host="node-src")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-src", decided_by=make_service_client()
        )
    assert exc.value.category == "same-node"


# ─── step failure + compensation ─────────────────────────────────────


def test_step_failure_retries_then_fails_with_vm_fenced_on_source(
    fx: FakeEffects,
) -> None:
    # A persistent failure of a post-fence step (Snapshotting runs after
    # the Quiescing fence, so the VM is already Migrating here).
    fx.fail.add("trigger_snapshot")
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.SNAPSHOTTING.value)
    # It stays in Snapshotting (retrying) — not advancing, not failing.
    for _ in range(3):
        service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.SNAPSHOTTING.value

    # Once the phase deadline passes, the job fails.
    _backdate_phase(job)
    service.tick_once()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert "snapshotting" in job.reason
    # The fence moved to Quiescing (so the guest's stopped-ack, pushed during
    # that shutdown, lands in an ack-accepting state). So a Snapshotting
    # failure is POST-fence: the VM is Migrating on the source, deliberately
    # NOT rolled back across the fence — recovery is forward-only (re-drive
    # or an operator relaunch of the intact source disk at source_gen). The
    # KBS generation fence is NOT applied until DestActivating, so the source
    # disk is never crypto-erased and stays restorable. The dest is never
    # activated (no split-brain), and the host is unchanged.
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"
    assert vm.generation == 5


def test_snapshot_reported_failure_fails_the_migration(fx: FakeEffects) -> None:
    fx.snapshot_status = "failed"
    vm = make_vm()
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.UPLOADING.value)
    _backdate_phase(job)
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value


# ─── idempotency guard ───────────────────────────────────────────────


def test_guarded_runs_a_side_effect_at_most_once() -> None:
    calls: list[int] = []
    service._guarded("migration:test-job:demo", lambda: calls.append(1))
    # A second call with the same key — the §14 store says "done".
    service._guarded("migration:test-job:demo", lambda: calls.append(1))
    assert calls == [1]


def test_each_migration_side_effect_runs_exactly_once(fx: FakeEffects) -> None:
    vm = make_vm()
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    # Tick well past completion — extra ticks must not re-fire effects.
    for _ in range(30):
        service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.DONE.value
    for effect in (
        "relay_quiesce",
        "trigger_snapshot",
        "kbs_activate_dest",
        "dispatch_migrate_activate",
    ):
        assert sum(1 for c in fx.calls if c[0] == effect) == 1


# ─── invariant guards (defense-in-depth) ─────────────────────────────


def test_dest_activating_without_verified_ack_fails_closed(
    fx: FakeEffects,
) -> None:
    # A job that reaches DestActivating with `source_ack_verified`
    # unset (corruption / hand-edit) must NEVER activate the dest —
    # the split-brain gate is enforced at the activation point too.
    vm = make_vm()
    job = make_migration_job(vm)
    MigrationJob.objects.filter(id=job.id).update(
        state=MigrationState.DEST_ACTIVATING.value, source_ack_verified=False
    )
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert "dest-activating-without-verified-source-ack" in job.reason
    assert not fx.did("kbs_activate_dest")
    # The split-brain gate blocks the dest dispatch too — the dest miner
    # is never told to restore + boot without a verified source ack.
    assert not fx.did("dispatch_migrate_activate")


def test_pre_fence_migration_fails_fast_if_vm_leaves_active(
    fx: FakeEffects,
) -> None:
    # A racing decommission (or any cause) flips the VM out of Active
    # while the migration is still pre-fence — the migration fails
    # fast instead of wasting ticks.
    vm = make_vm()
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    Vm.objects.filter(id=vm.id).update(state=VmState.DECOMMISSIONING)
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert "vm-no-longer-active" in job.reason


def test_activate_dest_refuses_a_mismatched_fence() -> None:
    # `_activate_dest_vm` must refuse to activate over a Migrating VM
    # that is fenced for a DIFFERENT migration (different dest / gen).
    vm = make_vm(generation=5)
    job = make_migration_job(vm, dest_node_id="node-dst")  # wants node-dst / gen 6
    MigrationJob.objects.filter(id=job.id).update(
        state=MigrationState.DEST_ACTIVATING.value, source_ack_verified=True
    )
    job.refresh_from_db()
    # Fence the VM for some OTHER migration.
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING, migration_dest="other-node", new_generation=99
    )
    with pytest.raises(EffectError, match="different migration"):
        service._activate_dest_vm(job)


# ─── §25 M4 — dest-activation order dispatch ─────────────────────────


def test_dest_dispatch_fires_only_after_the_kbs_release(fx: FakeEffects) -> None:
    # The dest miner is told to restore + boot ONLY after (a) the verified
    # source-ack fence and (b) the KBS release to (new_gen, dest). Assert the
    # ordering: `kbs_activate_dest` precedes `dispatch_migrate_activate`.
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    order = [c[0] for c in fx.calls]
    assert "kbs_activate_dest" in order
    assert "dispatch_migrate_activate" in order
    assert order.index("kbs_activate_dest") < order.index(
        "dispatch_migrate_activate"
    )
    # The dispatch named the destination + the forward-only generation.
    activate = next(c for c in fx.calls if c[0] == "dispatch_migrate_activate")
    assert activate[2] == "node-dst"  # dest_node_id
    assert activate[3] == 6  # new_gen


def test_dest_dispatch_failure_keeps_polling_and_never_activates_vm(
    fx: FakeEffects,
) -> None:
    # A dest-dispatch failure (e.g. the miner 4xx until the new_gen ticket
    # re-mint lands) must NOT activate the VM — the job stays in
    # DestActivating (retrying) until its deadline, fenced + safe.
    fx.fail.add("dispatch_migrate_activate")
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    # The KBS release ran, but the failed dispatch blocks the local CAS:
    # the VM is still Migrating (fenced), never activated on the dest.
    assert fx.did("kbs_activate_dest")
    assert job.state == MigrationState.DEST_ACTIVATING.value
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"


def test_dest_dispatch_carries_resolved_boot_artifacts(fx: FakeEffects) -> None:
    # The handler resolves the boot-artifact staging bundle and passes it to
    # the dispatch — `resolve_boot_artifacts` is called before the dispatch.
    fx.boot_artifacts = {
        "kernel": {"url": "https://s3/k", "sha256_hex": "ab" * 32},
        "initrd": {"url": "https://s3/i", "sha256_hex": "cd" * 32},
    }
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    order = [c[0] for c in fx.calls]
    assert "resolve_boot_artifacts" in order
    assert order.index("resolve_boot_artifacts") < order.index(
        "dispatch_migrate_activate"
    )


# ─── anti-rollback state disk (the boot counter) ─────────────────────


def test_snapshot_carries_the_boot_counter_state_disk(fx: FakeEffects) -> None:
    """The guest's anti-rollback boot counter lives on a per-VM state disk,
    NOT inside the encrypted volume (it must be readable before the unlock).
    The miner formats a BLANK one whenever the file is absent, so a dest that
    did not receive the source's disk submits counter `1` while the KBS still
    holds `stored = N` for the same vm_id — refused before any Vault read,
    and the migrated guest never unlocks. So §25 must carry it."""
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.UPLOADING.value)

    job.refresh_from_db()
    assert job.snapshot_state_key, "the state disk needs its own S3 object"
    assert job.snapshot_state_key != job.snapshot_key

    call = next(c for c in fx.calls if c[0] == "trigger_snapshot")
    _, _vm_id, put_url, state_put_url = call
    assert state_put_url, "the source must be told where to upload the counter"
    assert state_put_url != put_url


def test_dest_activation_carries_the_state_disk_get_url(fx: FakeEffects) -> None:
    """The dest must be handed the counter BEFORE it boots — the launch
    path's `ensure_state_disk` only preserves a file that is already there."""
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    call = next(c for c in fx.calls if c[0] == "dispatch_migrate_activate")
    state_get_url = call[4]
    assert state_get_url, "dest activation must carry the state-disk GET"


def test_migration_started_before_the_state_disk_field_still_activates(
    fx: FakeEffects,
) -> None:
    """Forward-compat: a job already in flight when this shipped has no
    `snapshot_state_key`, so no such object was ever uploaded. Handing the
    dest a presigned URL for a non-existent object would fail the restore;
    it must instead get "" and fall back to the pre-fix blank counter."""
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.UPLOADING.value)
    # Simulate the pre-fix job record.
    MigrationJob.objects.filter(id=job.id).update(snapshot_state_key="")

    _drive_until(job, MigrationState.DONE.value)

    call = next(c for c in fx.calls if c[0] == "dispatch_migrate_activate")
    assert call[4] == "", "no object was uploaded ⇒ no URL may be handed out"


def test_boot_phase_is_reset_AT_THE_FENCE_not_at_dest_activation(
    fx: FakeEffects,
) -> None:
    """Placement is the whole point, not just the reset.

    The destination's `booting` fires from `run_domain` INSIDE the same
    `handle_launch` whose return triggers `mark_activate_done`, so it
    reaches vali milliseconds BEFORE the dest reports done. Resetting at
    activation refused that milestone against the inherited `running` and
    then wiped it — `booting` was lost on every migration.

    Fencing early also stops `GET /state` reporting `running` for a guest
    that is powered off mid-migration."""
    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(id=vm.id).update(
        boot_phase="running", boot_phase_at=timezone.now()
    )
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )

    # Stop BEFORE the destination is activated.
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value, "still mid-migration"
    assert vm.boot_phase == "", (
        "the reset must already have happened at the fence — otherwise the "
        "dest's `booting` is refused against the inherited `running`"
    )
    assert vm.boot_phase_at is None


def test_a_source_receipt_flushed_AFTER_the_fence_is_mopped_up(
    fx: FakeEffects,
) -> None:
    """THE REGRESSION the fence-only reset introduced.

    `_fence_vm` runs BEFORE `relay_quiesce` dispatches, so the source guest
    is still RUNNING when the fence clears the phase. The tenant telemetry
    agent does a FINAL DRAIN of its buffered receipts on shutdown — which
    is exactly what the quiesce triggers. That flushed `served_receipt`
    lands after the fence and `_advance_tenant_vm_boot_progress` puts the
    row straight back to `running`; it does not check lifecycle state.

    With only the fence reset nothing cleaned that up, and the
    destination's milestones were refused for the rest of the VM's life —
    the original bug, restored. The activation-site reset is the backstop.

    This is why the placement test alone is not enough: it stops at
    `awaiting_source_ack`, before any receipt can arrive, so it pins that
    the reset HAPPENED, not that it SURVIVED."""
    from apps.telemetry import service as telemetry_service

    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(id=vm.id).update(
        boot_phase="running", boot_phase_at=timezone.now()
    )
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    vm.refresh_from_db()
    assert vm.boot_phase == "", "fence cleared it"

    # The source guest's shutdown drain lands here — post-fence.
    telemetry_service._advance_tenant_vm_boot_progress(
        "tenant_vm", vm.vm_id, "served_receipt", timezone.now()
    )
    vm.refresh_from_db()
    assert vm.boot_phase == "running", (
        "precondition: the late receipt really does restore `running` — if "
        "this ever fails the regression is unreachable and this test is inert"
    )

    _drive_until(job, MigrationState.DONE.value)

    vm.refresh_from_db()
    assert vm.boot_phase == "", (
        "the activation-site backstop must mop up what the source drained "
        "after the fence"
    )
    assert vm.advance_boot_phase("booting") is True


def test_a_receipt_landing_DURING_activation_is_still_mopped(
    fx: FakeEffects,
) -> None:
    """TOCTOU. Deciding the mop-up from a row read BEFORE the UPDATE would
    lose to a receipt landing in between.

    The served-receipt writer saves `boot_phase` with `update_fields` that
    do NOT include `version`, so the CAS's version pin cannot detect it.
    A read-then-decide mop-up is therefore skipped on a stale decision and
    the destination's milestones are suppressed for the rest of the VM's
    life — silently, and permanently until the next migration.

    Simulated by firing the receipt from inside the effect that runs
    immediately before `_activate_dest_vm`, i.e. between the row read and
    the UPDATE."""
    from apps.telemetry import service as telemetry_service

    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    # Land the receipt AFTER `_activate_dest_vm` has read the row and
    # BEFORE its UPDATE runs — the only window where the two forms differ.
    # Hooking `poll_dest_activation` (which runs BEFORE the read) does not
    # reproduce it: the read then already sees `running` and even a
    # read-then-decide mop-up fires correctly. Verified by mutation — that
    # placement failed to catch the read-then-decide form at all.
    real_mop_up = service._mop_up_boot_phase

    def receipt_between_read_and_update(*args, **kwargs):
        telemetry_service._advance_tenant_vm_boot_progress(
            "tenant_vm", vm.vm_id, "served_receipt", timezone.now()
        )
        return real_mop_up(*args, **kwargs)

    monkeypatch_target = service
    monkeypatch_target._mop_up_boot_phase = receipt_between_read_and_update

    try:
        _drive_until(job, MigrationState.DONE.value)
    finally:
        monkeypatch_target._mop_up_boot_phase = real_mop_up

    vm.refresh_from_db()
    assert vm.boot_phase == "", (
        "a receipt landing during activation must still be mopped — the "
        "decision has to be made INSIDE the UPDATE, not from an earlier read"
    )
    assert vm.advance_boot_phase("booting") is True


def test_the_dests_real_progress_SURVIVES_the_activation_mop_up(
    fx: FakeEffects,
) -> None:
    """The mop-up must not undo the destination's own milestones.

    In the clean case the dest has already reported `booting` and
    `kek_released` by the time activation runs. Clearing unconditionally
    made `boot_phase` visibly REGRESS (`kek_released → "" → running`) in a
    field the model documents as monotonic, briefly reporting `""` for a
    guest that had already released its KEK.

    Only `running` is mopped. The asymmetry is SELF-HEALING, not
    provenance: `running` is re-asserted by every served receipt, so
    mopping one that belonged to the dest costs a receipt interval, while
    `booting`/`kek_released` are one-shot and never return once refused."""
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.AWAITING_SOURCE_ACK.value)

    # The destination boots and reports its real milestones.
    vm.refresh_from_db()
    assert vm.advance_boot_phase("kek-released") is True
    vm.boot_phase_at = timezone.now()
    vm.save(update_fields=["boot_phase", "boot_phase_at", "updated_at"])

    _drive_until(job, MigrationState.DONE.value)

    vm.refresh_from_db()
    assert vm.boot_phase == "kek_released", (
        "the dest's own progress must survive activation — it is one-shot "
        "and never comes back once refused"
    )
    assert vm.boot_phase_at is not None


def test_migration_resets_boot_phase_so_the_dest_can_report_progress(
    fx: FakeEffects,
) -> None:
    """`advance_boot_phase` is MONOTONIC, so an inherited terminal
    `running` from the source does not merely go stale — it permanently
    SUPPRESSES the destination's milestones (`booting` ranks below
    `running` and is refused, and so is `kek_released`).

    Before the reset the API reported a migrated VM as fully booted the
    instant the row flipped Active, while the dest guest was still in
    initramfs — and the SDK's `wait_for_boot` returned immediately on that
    inherited value, so it could not wait for a destination boot at all."""
    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(id=vm.id).update(
        boot_phase="running", boot_phase_at=timezone.now()
    )
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )

    _drive_until(job, MigrationState.DONE.value)

    vm.refresh_from_db()
    assert vm.boot_phase == "", "the source's terminal phase must not be inherited"
    assert vm.boot_phase_at is None
    # And the destination can now actually report progress.
    assert vm.advance_boot_phase("booting") is True


def test_migration_preserves_the_netbird_ip(fx: FakeEffects) -> None:
    """The overlay IP must SURVIVE the activation CAS.

    §25 still re-mints no setup key, so the guest can only come back as
    the SAME peer, from the identity on its migrated disk — when NetBird
    has not GC'd that peer (P9/#17). Clearing the field would be strictly
    worse than carrying a possibly-stale one: the served-receipt self-heal
    re-resolves only while the field is EMPTY and the VM is under 30
    minutes old, and every migration candidate is older than that, so a
    cleared IP would be permanently blank. Whether the peer survived is
    reported separately by `netbird_status` — pinned here as `pending`
    because the NetBird API is unavailable in this test, so the sweep
    cannot settle and the carried-over value is all a reader has."""
    fx.fail.add("resolve_netbird_peer")
    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(id=vm.id).update(netbird_ip="100.64.0.40")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )

    _drive_until(job, MigrationState.DONE.value)

    vm.refresh_from_db()
    assert vm.netbird_ip == "100.64.0.40"
    assert vm.netbird_status == VmNetbirdStatus.PENDING.value
