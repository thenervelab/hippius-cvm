"""Edge-relayed guest-boot progress ingest gates.

`POST /v1/telemetry/vm-progress` with `content-type: application/cbor` is
the Edge-relayed guest-boot progress ingress: after a launch is accepted
the tenant guest boots asynchronously on the miner, and the miner-agent
POSTs a signed `SignedVmProgress` milestone to the Edge, which relays the
raw CBOR here, stamping the miner's mTLS identity on the
`X-Hippius-Peer-Id` header (mirrors the graceful-exit ingress exactly).

These tests drive every fail-closed gate — peer-id resolution, miner
lookup, signature verify, peer-vs-body `miner_id` match, ±skew, the
oversize cap, the empty body — plus the happy-path monotonic
`boot_phase` advance (and its stamped `boot_phase_at`) and the fail-open
"vm not tracked yet" path. The data-bearing `verify-vm-progress`
shell-out is replaced by `FakeVmProgressVerifier`, so the gate logic
runs without the built Rust binary (`test_verifier.py` covers the real
shell-out).
"""

from __future__ import annotations

import time
from typing import Any
from unittest import mock

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.telemetry import verifier
from apps.telemetry.models import SourceType, TelemetrySource

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_vm_progress")

MINER_ID = "miner-a"
PEER_ID = f"hippius-miner:{MINER_ID}"
VM_ID = "vm-boot-1"
DOMAIN = "HIPPIUS_VM_PROGRESS_V1"


# ─── verify-vm-progress fake ─────────────────────────────────────────


class FakeVmProgressVerifier:
    """In-memory stand-in for `telemetry.verifier.verify_vm_progress`.

    - `outcome` ∈ {"ok", "failed", "unavailable"} steers the verdict.
    - on "ok" the returned body is built from the steerable `miner_id`
      / `vm_id` / `milestone` / `timestamp_unix` attrs
      (`timestamp_unix=None` ⇒ vali's current clock — inside the skew
      window).
    - `calls` records every `(envelope, verifying_key)` verified.
    """

    def __init__(self) -> None:
        self.outcome = "ok"
        self.miner_id = MINER_ID
        self.vm_id = VM_ID
        self.milestone = "booting"
        self.reason: str | None = None
        self.timestamp_unix: int | None = None
        self.schema_version = 1
        self.fail_category = "signature_invalid"
        self.calls: list[tuple[bytes, bytes]] = []

    def verify_vm_progress(
        self, *, envelope: bytes, verifying_key: bytes
    ) -> verifier.VmProgressBody:
        self.calls.append((bytes(envelope), bytes(verifying_key)))
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(
                message="injected verification failure",
                category=self.fail_category,
            )
        ts = self.timestamp_unix
        if ts is None:
            ts = int(time.time())
        return verifier.VmProgressBody(
            schema_version=self.schema_version,
            domain=DOMAIN,
            miner_id=self.miner_id,
            vm_id=self.vm_id,
            milestone=self.milestone,
            timestamp_unix=ts,
            reason=self.reason,
        )


@pytest.fixture(autouse=True)
def fake_verifier(monkeypatch: pytest.MonkeyPatch) -> FakeVmProgressVerifier:
    fake = FakeVmProgressVerifier()
    monkeypatch.setattr(verifier, "verify_vm_progress", fake.verify_vm_progress)
    return fake


# ─── helpers ─────────────────────────────────────────────────────────


def _make_miner(
    *,
    miner_id: str = MINER_ID,
    source_active: bool = True,
    chain_node_id: str = "",
) -> MinerIdentity:
    miner = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=("ab" * 32),
        platform_id=f"amd-chipid-{miner_id}",
        status=MinerStatus.ACTIVE.value,
        chain_node_id=chain_node_id,
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=miner_id,
        verifying_key=bytes(32),
        is_active=source_active,
    )
    return miner


def _make_vm(
    *,
    vm_id: str = VM_ID,
    host: str = MINER_ID,
    state: str = VmState.ACTIVE,
    migration_dest: str = "",
) -> Vm:
    """A tracked VM. `host` defaults to the REPORTING miner — that is the
    binding vali stamps on an accepted dispatch, and the ownership gate
    now requires it (`host=""` exercises the pre-dispatch / placement-
    only window).
    """
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id="lease-1",
        state=state,
        generation=1,
        host=host,
        migration_dest=migration_dest,
        # DB CHECK: a Migrating row MUST carry the new generation.
        new_generation=2 if state == VmState.MIGRATING else None,
        lifecycle_vk=bytes(32),
    )


def _make_placement(vm: Vm, *, miner_node_id: str) -> None:
    """Record a §23 placement binding this VM to `miner_node_id` — the
    row the cross-miner ownership gate consults."""
    from django.utils import timezone

    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.scheduler.models import Placement, PlacementStatus

    Placement.objects.create(
        vm=vm,
        vm_family="fam-1",
        resource_class="small",
        miner_node_id=miner_node_id,
        status=PlacementStatus.BOUND.value,
        chain_epoch=1,
        bound_at=timezone.now(),
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value,
            name="scheduler",
        ),
    )


def _make_succeeded_launch_job(vm: Vm, *, miner_id: str) -> None:
    """A SUCCEEDED `LaunchJob` naming `miner_id` — the binding
    `effects.bound_miner_id` falls back to when `vm.host` is empty."""
    import secrets

    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.orchestration.models import LaunchJob, LaunchJobState

    now = timezone.now()
    LaunchJob.objects.create(
        job_id=secrets.token_hex(16),
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={"vm_id": vm.vm_id},
        userdata_vault_path=f"secret/data/x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        miner_id=miner_id,
        phase_started_at=now,
        finished_at=now,
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value,
            name=f"launcher-{secrets.token_hex(4)}",
        ),
    )


def _post(
    body: bytes = b"signed-vm-progress-cbor",
    *,
    peer_id: str | None = PEER_ID,
):
    """POST a raw-CBOR vm-progress milestone. The CBOR ingress carries no
    bearer token, so an unauthenticated client is the default.
    """
    extra: dict[str, Any] = {}
    if peer_id is not None:
        extra["HTTP_X_HIPPIUS_PEER_ID"] = peer_id
    return APIClient().post(INGEST_URL, data=body, content_type="application/cbor", **extra)


# ─── happy path ──────────────────────────────────────────────────────


def test_advances_boot_phase_on_valid_milestone(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    fake_verifier.milestone = "booting"

    resp = _post()

    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body == {
        "ok": True,
        "vm_id": VM_ID,
        "boot_phase": VmBootPhase.BOOTING.value,
        "tracked": True,
        "advanced": True,
    }
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.BOOTING.value
    assert vm.boot_phase_at is not None
    # The verifier saw the raw envelope + the miner's registered key
    # (`MinerIdentity.pubkey_hex`), not the source's `verifying_key`.
    assert fake_verifier.calls == [(b"signed-vm-progress-cbor", bytes.fromhex("ab" * 32))]


def test_hyphen_wire_milestone_maps_to_underscore_choice(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    # The wire value uses a HYPHEN; the recorded phase uses an underscore.
    fake_verifier.milestone = "kek-released"

    resp = _post()

    assert resp.status_code == 200, resp.content
    assert resp.json()["boot_phase"] == VmBootPhase.KEK_RELEASED.value
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED.value


def test_ingress_needs_no_bearer_token(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    _make_vm()
    resp = APIClient().post(
        INGEST_URL,
        data=b"vp",
        content_type="application/cbor",
        HTTP_X_HIPPIUS_PEER_ID=PEER_ID,
    )
    assert resp.status_code == 200, resp.content


def test_get_vm_returns_boot_phase(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    from apps.identity.models import (
        PrincipalScope,
        ServiceClient,
        ServiceToken,
        TokenLifetime,
    )

    _make_miner()
    _make_vm()
    fake_verifier.milestone = "running"
    assert _post().status_code == 200

    # The lifecycle GET is IsAuthenticated (service principal).
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="upstream")
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    resp = api.get(reverse("vm_state", args=[VM_ID]))
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["boot_phase"] == VmBootPhase.RUNNING.value
    assert body["boot_phase_at"] is not None


# ─── monotonic advance ───────────────────────────────────────────────


def test_monotonic_never_regresses(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()

    # Advance to running.
    fake_verifier.milestone = "running"
    assert _post().status_code == 200
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    at_running = vm.boot_phase_at

    # A late/replayed `booting` must NOT regress the recorded phase.
    fake_verifier.milestone = "booting"
    resp = _post()
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["advanced"] is False
    assert body["boot_phase"] == VmBootPhase.RUNNING.value
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    # A no-op milestone does not re-stamp `boot_phase_at`.
    assert vm.boot_phase_at == at_running


def test_idempotent_same_milestone_is_noop(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    fake_verifier.milestone = "kek-released"
    assert _post().json()["advanced"] is True
    # Re-delivery of the SAME milestone is a no-op (equal rank).
    resp = _post()
    assert resp.status_code == 200
    assert resp.json()["advanced"] is False
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED.value


# ─── fail-open display ───────────────────────────────────────────────


def test_untracked_vm_is_benign_200(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # A verified milestone for a VM whose row does not exist yet returns a
    # benign 200 (fail-open display), never a hard 404.
    _make_miner()
    fake_verifier.vm_id = "vm-not-tracked-yet"
    resp = _post()
    assert resp.status_code == 200, resp.content
    assert resp.json() == {
        "ok": True,
        "vm_id": "vm-not-tracked-yet",
        "boot_phase": "",
        "tracked": False,
        "advanced": False,
    }


# ─── fail-closed gates ───────────────────────────────────────────────


def test_rejects_missing_peer_id_header() -> None:
    _make_miner()
    _make_vm()
    resp = _post(peer_id=None)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_rejects_unknown_miner() -> None:
    _make_vm()
    resp = _post(peer_id="hippius-miner:nope")
    assert resp.status_code == 404


def test_rejects_empty_body() -> None:
    _make_miner()
    resp = _post(body=b"")
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_rejects_oversize_body() -> None:
    _make_miner()
    resp = _post(body=b"x" * 4097)
    assert resp.status_code == 413
    assert resp.json()["category"] == "too-large"


def test_rejects_body_miner_id_mismatch(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    _make_vm()
    fake_verifier.miner_id = "some-other-miner"
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "identity"


def test_rejects_timestamp_outside_skew(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    _make_vm()
    fake_verifier.timestamp_unix = int(time.time()) - 10_000
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "timestamp-skew"


def test_verify_failed_is_403(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    fake_verifier.outcome = "failed"
    fake_verifier.fail_category = "milestone_invalid"
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "milestone_invalid"
    # A failed verify must NOT touch the boot phase.
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_verifier_unavailable_is_503(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    _make_vm()
    fake_verifier.outcome = "unavailable"
    resp = _post()
    assert resp.status_code == 503


# ─── cross-miner ownership bind ──────────────────────────────────────


def test_owning_miner_advances_when_placement_matches(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # Pre-dispatch window (no host binding stamped yet): the reporting
    # miner's `chain_node_id` equals the VM's placement `miner_node_id`
    # — it HOSTS the VM, so the milestone advances.
    _make_miner(chain_node_id="node-owner")
    vm = _make_vm(host="")
    _make_placement(vm, miner_node_id="node-owner")
    fake_verifier.milestone = "running"

    resp = _post()

    assert resp.status_code == 200, resp.content
    assert resp.json()["advanced"] is True
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.RUNNING.value


def test_rejects_non_owning_miner(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # A registered miner B (verified over its OWN mTLS leg, signing a
    # valid body for its own miner_id) must NOT advance a VM placed on
    # miner A — the placement `miner_node_id` binds ownership.
    _make_miner(chain_node_id="node-B")
    vm = _make_vm(host="")
    _make_placement(vm, miner_node_id="node-A")
    fake_verifier.milestone = "running"

    resp = _post()

    assert resp.status_code == 403, resp.content
    assert resp.json()["category"] == "identity"
    # The spoof must NOT touch the boot phase.
    vm.refresh_from_db()
    assert vm.boot_phase == ""


# ─── P9/#19 — the bind FAILS CLOSED ──────────────────────────────────
#
# Every case below used to be an ACCEPT: the old gate only rejected when
# BOTH a placement node_id AND a reporter chain_node_id resolved and they
# differed, so any VM/miner pair where either side was unresolvable was
# waved through — `boot_phase` was writable by any registered miner for
# any vm_id it could name.


def test_rejects_miner_b_for_vm_hosted_on_miner_a(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # THE headline claim: miner B cannot report progress for a VM whose
    # vali-recorded host is miner A — with NO placement row and NO
    # chain_node_id on either side (the old gate's blind spot).
    _make_miner()  # the reporter, B (chain_node_id unset)
    vm = _make_vm(host="miner-A")
    fake_verifier.milestone = "running"

    resp = _post()

    assert resp.status_code == 403, resp.content
    assert resp.json()["category"] == "identity"
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_rejects_when_reporter_has_no_chain_node_id(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # A miner registered WITHOUT a `chain_node_id` (the model's documented
    # "NULL until the operator backfills it" state) cannot be the host of
    # a placed VM — the launch path resolves its miner BY chain_node_id.
    # The unverifiable side must REFUSE, not wave through.
    _make_miner(chain_node_id="")
    vm = _make_vm(host="")
    _make_placement(vm, miner_node_id="node-owner")
    fake_verifier.milestone = "running"

    resp = _post()

    assert resp.status_code == 403, resp.content
    assert resp.json()["category"] == "identity"
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_rejects_when_no_binding_is_resolvable_at_all(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # No `vm.host`, no SUCCEEDED LaunchJob, no Placement: vali cannot say
    # who hosts this VM, so NOBODY may write its boot_phase.
    _make_miner(chain_node_id="node-B")
    vm = _make_vm(host="")
    fake_verifier.milestone = "running"

    resp = _post()

    assert resp.status_code == 403, resp.content
    assert resp.json()["category"] == "identity"
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_refusal_message_does_not_distinguish_spoof_from_unresolvable(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # A probing miner must not learn WHICH binding vali holds.
    _make_miner(chain_node_id="node-B")
    spoofed = _make_vm(vm_id="vm-hosted-elsewhere", host="miner-A")
    unbound = _make_vm(vm_id="vm-unbound", host="")

    fake_verifier.vm_id = spoofed.vm_id
    a = _post()
    fake_verifier.vm_id = unbound.vm_id
    b = _post()

    assert a.status_code == b.status_code == 403
    assert a.json() == b.json()


def test_launch_job_fallback_binds_when_vm_host_is_empty(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # `vm.host` is empty for VMs launched before the worker stamped it;
    # the SUCCEEDED LaunchJob is then the binding — the SAME resolver §24
    # destroy / §25 relay / reboot-recovery route on.
    _make_miner()
    vm = _make_vm(host="")
    _make_succeeded_launch_job(vm, miner_id=MINER_ID)
    fake_verifier.milestone = "kek-released"

    resp = _post()

    assert resp.status_code == 200, resp.content
    assert resp.json()["advanced"] is True
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED.value


def test_launch_job_fallback_rejects_a_different_miner(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm(host="")
    _make_succeeded_launch_job(vm, miner_id="miner-A")

    resp = _post()

    assert resp.status_code == 403, resp.content
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_host_binding_wins_over_a_stale_placement(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # §25 does NOT re-write the Placement, so after a migration the latest
    # placement still names the SOURCE. The host binding must take
    # precedence: the source (which no longer holds the domain) is refused
    # even though the stale placement still names it.
    source = _make_miner(miner_id="miner-a", chain_node_id="node-source")
    assert source.chain_node_id == "node-source"
    vm = _make_vm(host="miner-dest")
    _make_placement(vm, miner_node_id="node-source")

    resp = _post()

    assert resp.status_code == 403, resp.content
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_migration_destination_may_report_before_activation(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # §25: the dest emits `booting` from inside `handle_launch`, which
    # lands BEFORE `mark_activate_done` stamps `vm.host = dest`. While the
    # VM is Migrating, `vm.migration_dest` (vali's own record of where IT
    # sent the VM) is an accepted reporter — else every migration loses
    # the destination's first milestones.
    _make_miner()  # the reporter IS the destination
    vm = _make_vm(
        host="miner-source",
        state=VmState.MIGRATING,
        migration_dest=MINER_ID,
    )
    fake_verifier.milestone = "booting"

    resp = _post()

    assert resp.status_code == 200, resp.content
    assert resp.json()["advanced"] is True
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.BOOTING.value


def test_migration_source_may_still_report_while_migrating(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # The source still holds `vm.host` until activation — it remains an
    # accepted reporter while Migrating (it is still the recorded host).
    _make_miner()
    vm = _make_vm(
        host=MINER_ID,
        state=VmState.MIGRATING,
        migration_dest="miner-dest",
    )

    resp = _post()

    assert resp.status_code == 200, resp.content
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.BOOTING.value


def test_third_miner_refused_during_migration(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # Migrating widens the accepted set to {host, migration_dest} — and no
    # further: an unrelated miner C is still refused.
    _make_miner()
    vm = _make_vm(
        host="miner-source",
        state=VmState.MIGRATING,
        migration_dest="miner-dest",
    )

    resp = _post()

    assert resp.status_code == 403, resp.content
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_stale_migration_dest_does_not_authorize_outside_migrating(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # `migration_dest` only widens the accepted set WHILE the VM is
    # Migrating. The lifecycle transitions clear it on the way back to
    # Active — but the DB constraint does not require that, so pin it: a
    # VM that is Active with a leftover `migration_dest` must NOT let that
    # miner report.
    _make_miner()
    vm = _make_vm(
        host="miner-source",
        state=VmState.ACTIVE,
        migration_dest=MINER_ID,
    )

    resp = _post()

    assert resp.status_code == 403, resp.content
    vm.refresh_from_db()
    assert vm.boot_phase == ""


def test_refused_report_is_logged_for_the_operator(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # The miner-agent sink swallows the 403 and never retries, so vali's
    # own log is the ONLY place a refusal is visible.
    #
    # Asserts on the logger call rather than via caplog: the project sets
    # `propagate: False` on the `apps` logger, so caplog's root handler
    # never sees the record.
    from apps.telemetry import views as telemetry_views

    _make_miner()
    _make_vm(host="miner-A")

    with mock.patch.object(telemetry_views.log, "warning") as logged:
        assert _post().status_code == 403

    assert logged.call_count == 1
    fmt, *args = logged.call_args.args
    rendered = fmt % tuple(args)
    assert "vm-progress REFUSED" in rendered
    # Enough to diagnose: which VM, which reporter, and the binding vali
    # actually holds.
    assert VM_ID in rendered
    assert MINER_ID in rendered
    assert "miner-A" in rendered


def test_untracked_vm_stays_benign_for_a_non_hosting_miner(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    # The surviving fail-open (no `Vm` row) writes NOTHING, so it stays a
    # benign 200 even for a miner that hosts nothing.
    _make_miner()
    fake_verifier.vm_id = "vm-no-row"

    resp = _post()

    assert resp.status_code == 200, resp.content
    assert resp.json()["tracked"] is False
    assert Vm.objects.filter(vm_id="vm-no-row").count() == 0


# ─── zombie gate ─────────────────────────────────────────────────────


def _erased_decommission(vm: Vm) -> None:
    import secrets

    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.orchestration.models import DecommissionJob, DecommissionState

    DecommissionJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        state=DecommissionState.CRYPTO_ERASING.value,
        phase_started_at=timezone.now(),
        kek_erased_at=timezone.now(),
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value, name="op-zombie"
        ),
    )


def test_progress_for_an_erased_vm_is_refused_and_pins_the_reporting_miner(
    settings,
) -> None:
    from apps.lifecycle.models import ZombieObservation

    settings.VALI_ZOMBIE_ERASE_GRACE_S = 0
    _make_miner(chain_node_id="cc" * 32)
    vm = _make_vm(state=VmState.DECOMMISSIONING)
    _erased_decommission(vm)

    resp = _post()

    assert resp.status_code == 410
    assert resp.json()["category"] == "vm-not-live"
    vm.refresh_from_db()
    assert vm.boot_phase == ""  # the milestone was not recorded
    row = ZombieObservation.objects.get(vm_id=VM_ID)
    # Signed by the reporting miner's own key over its own mTLS leg.
    assert (row.miner_id, row.miner_node_id, row.attribution) == (
        MINER_ID,
        "cc" * 32,
        "peer",
    )


def test_progress_for_a_decommissioning_vm_before_its_erase_is_unaffected() -> None:
    from apps.lifecycle.models import ZombieObservation

    _make_miner()
    _make_vm(state=VmState.DECOMMISSIONING)  # no erase recorded
    resp = _post()
    assert resp.status_code != 410
    assert not ZombieObservation.objects.exists()


# ─── customer-held keys: awaiting-guardian (display-only) ────────────


def _await(fake: FakeVmProgressVerifier, reason: str) -> None:
    fake.milestone = "awaiting-guardian"
    fake.reason = reason


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_awaiting_guardian_is_recorded_for_an_m1_m2_vm(
    fake_verifier: FakeVmProgressVerifier, mode: str
) -> None:
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode=mode)
    _await(fake_verifier, "unreachable")

    resp = _post()

    assert resp.status_code == 200, resp.content
    # Not a boot_phase step: nothing advanced, the phase is untouched.
    assert resp.json() == {
        "ok": True,
        "vm_id": VM_ID,
        "boot_phase": "",
        "tracked": True,
        "advanced": False,
    }
    vm.refresh_from_db()
    assert vm.boot_phase == ""
    assert vm.guardian_wait_reason == "unreachable"
    assert vm.guardian_wait_since is not None
    assert vm.guardian_wait_at == vm.guardian_wait_since


def test_awaiting_guardian_for_an_m0_vm_is_ignored(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    """M0 has no guardian: a miner reporting one records nothing (so it
    can never hold back a timer for an M0 VM)."""
    _make_miner()
    vm = _make_vm()
    _await(fake_verifier, "timeout")

    resp = _post()

    assert resp.status_code == 200, resp.content
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == ""
    assert vm.guardian_wait_at is None


def test_a_wait_keeps_its_since_and_takes_the_latest_reason(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="split")
    _await(fake_verifier, "unreachable")
    _post()
    vm.refresh_from_db()
    since = vm.guardian_wait_since
    _await(fake_verifier, "refused:awaiting-approval")
    _post()
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == "refused:awaiting-approval"
    assert vm.guardian_wait_since == since
    assert vm.guardian_wait_at >= since


def test_a_stale_wait_starts_a_new_since(fake_verifier: FakeVmProgressVerifier) -> None:
    from datetime import timedelta

    _make_miner()
    vm = _make_vm()
    old = timezone.now() - timedelta(hours=2)
    Vm.objects.filter(pk=vm.pk).update(
        key_mode="split",
        guardian_wait_reason="timeout",
        guardian_wait_since=old,
        guardian_wait_at=old,
    )
    _await(fake_verifier, "timeout")
    _post()
    vm.refresh_from_db()
    assert vm.guardian_wait_since > old


@pytest.mark.parametrize(
    ("milestone", "clears"),
    [("kek-released", True), ("running", True), ("booting", False)],
)
def test_a_later_milestone_clears_the_wait_but_keeps_its_last_report(
    fake_verifier: FakeVmProgressVerifier, milestone: str, clears: bool
) -> None:
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="customer")
    _await(fake_verifier, "unreachable")
    _post()
    vm.refresh_from_db()
    at = vm.guardian_wait_at
    fake_verifier.milestone, fake_verifier.reason = milestone, None
    _post()
    vm.refresh_from_db()
    assert (vm.guardian_wait_reason == "") is clears
    assert (vm.guardian_wait_since is None) is clears
    # The last report stays: a timer credits the time spent waiting.
    assert vm.guardian_wait_at == at


def test_the_vm_status_shows_awaiting_guardian(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    from apps.lifecycle.views import _serialize_vm

    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="split")
    vm.refresh_from_db()
    assert _serialize_vm(vm)["guardian_wait"] is None
    _await(fake_verifier, "refused:release-not-pinned")
    _post()
    vm.refresh_from_db()
    wait = _serialize_vm(vm)["guardian_wait"]
    assert wait["boot"] == "awaiting-guardian"
    assert wait["reason"] == "refused:release-not-pinned"
    assert wait["since"] == vm.guardian_wait_since.isoformat()
    assert wait["terminal"] is False
    assert _serialize_vm(vm)["key_mode"] == "split"


def test_the_verifier_body_pairs_reason_and_milestone() -> None:
    base = {
        "schema_version": 1,
        "domain": DOMAIN,
        "miner_id": "m",
        "vm_id": "vm-1",
        "timestamp_unix": 1,
    }
    ok = verifier._vm_progress_body({**base, "milestone": "booting"})
    assert ok.reason is None
    ok = verifier._vm_progress_body({**base, "milestone": "awaiting-guardian", "reason": "timeout"})
    assert ok.reason == "timeout"
    for bad in (
        {**base, "milestone": "awaiting-guardian"},
        {**base, "milestone": "booting", "reason": "timeout"},
        {**base, "milestone": "awaiting-guardian", "reason": 3},
    ):
        with pytest.raises(verifier.VerifierUnavailable):
            verifier._vm_progress_body(bad)


def _at(fake: FakeVmProgressVerifier, milestone: str, ts: int, reason: str | None = None):
    fake.milestone, fake.reason, fake.timestamp_unix = milestone, reason, ts
    assert _post().status_code == 200


def test_a_late_wait_report_never_re_arms_a_cleared_wait(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    """Delivery can reorder: a wait report signed BEFORE the kek-released
    that cleared it, delivered after, is dropped (it would otherwise pause
    timers for a guest that is already up)."""
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="split")
    t0 = int(time.time()) - 100
    _at(fake_verifier, "awaiting-guardian", t0, "unreachable")
    _at(fake_verifier, "kek-released", t0 + 10)
    _at(fake_verifier, "awaiting-guardian", t0 + 5, "timeout")  # late
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == ""
    # A NEW wait, signed after the clear (the next boot), is recorded.
    _at(fake_verifier, "awaiting-guardian", t0 + 20, "unreachable")
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == "unreachable"


def test_a_late_clearing_milestone_does_not_hide_a_newer_wait(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="customer")
    t0 = int(time.time()) - 100
    _at(fake_verifier, "awaiting-guardian", t0 + 20, "unreachable")
    _at(fake_verifier, "running", t0 + 10)  # an earlier boot's, delivered late
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == "unreachable"
    # …but it still moves the clearing watermark: an even older report drops.
    _at(fake_verifier, "awaiting-guardian", t0 + 5, "timeout")
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == "unreachable"


def test_an_older_wait_report_does_not_overwrite_a_newer_one(
    fake_verifier: FakeVmProgressVerifier,
) -> None:
    _make_miner()
    vm = _make_vm()
    Vm.objects.filter(pk=vm.pk).update(key_mode="split")
    t0 = int(time.time()) - 100
    _at(fake_verifier, "awaiting-guardian", t0 + 10, "refused:awaiting-approval")
    _at(fake_verifier, "awaiting-guardian", t0, "unreachable")
    vm.refresh_from_db()
    assert vm.guardian_wait_reason == "refused:awaiting-approval"


@pytest.mark.parametrize(
    ("mode", "phrase"), [("customer", "§24 decommission"), ("split", "§24 crypto-erase")]
)
def test_the_zombie_refusal_never_calls_an_m2_decommission_a_crypto_erase(
    settings, mode: str, phrase: str
) -> None:
    settings.VALI_ZOMBIE_ERASE_GRACE_S = 0
    _make_miner(chain_node_id="cc" * 32)
    vm = _make_vm(state=VmState.DECOMMISSIONING)
    Vm.objects.filter(pk=vm.pk).update(key_mode=mode)
    _erased_decommission(vm)
    resp = _post()
    assert resp.status_code == 410
    assert resp.json()["error"] == f"vm is past its {phrase}"
