"""Integration tests for the guest-pushed stopped-ack ingress.

`POST /v1/lifecycle/stopped?vm_id=…&generation=…` (§24/§25) — the
measured guest's clean-shutdown ack landing pad. The view is an OPAQUE
store: it records raw `SignedStoppedAck` bytes keyed by
`(vm_id, generation)` and never decodes the CBOR (the Rust verifier owns
that, on poll). These tests pin:

  - an unauthenticated guest can POST (AllowAny — public front door);
  - the bytes round-trip into the `StoppedAckIngest` store;
  - `effects.poll_source_ack` / `poll_eol_ack` read them back keyed by
    the VM's generation;
  - bad / missing query params + oversize bodies are rejected;
  - a re-push for the same (vm_id, generation) overwrites (latest wins).
"""

from __future__ import annotations

import pytest
from django.conf import settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.lifecycle.models import StoppedAckIngest, Vm, VmState
from apps.orchestration import effects

pytestmark = pytest.mark.django_db

_URL = "/v1/lifecycle/stopped"


def _post(client: APIClient, *, vm_id: str, generation: int, body: bytes):
    return client.post(
        f"{_URL}?vm_id={vm_id}&generation={generation}",
        data=body,
        content_type="application/cbor",
    )


def _awaiting_vm(
    vm_id: str,
    generation: int,
    state: str = VmState.DECOMMISSIONING,
    signing_generation: int | None = None,
) -> Vm:
    """A VM in an ack-awaiting state — the identity-bind (audit
    M-StoppedAck) requires one for the ingress to store an ack. The gate
    keys on `signing_generation` (the guest's baked generation), which
    defaults to `generation` (the fresh-VM invariant); pass a distinct
    value to model a MIGRATED VM whose live `generation` was bumped."""
    kw: dict = {
        "vm_id": vm_id,
        "lease_id": f"lease-{vm_id}",
        "state": state,
        "generation": generation,
        "signing_generation": (
            generation if signing_generation is None else signing_generation
        ),
        "host": "host-a",
        "lifecycle_vk": bytes(32),
    }
    if state == VmState.MIGRATING:
        kw.update(new_generation=generation + 1, migration_dest="host-b")
    return Vm.objects.create(**kw)


def test_unauthenticated_guest_can_ingest_and_bytes_round_trip() -> None:
    # The guest has no ServiceToken — it reaches vali over the public
    # ingress. AllowAny lets the POST through; the verify step (elsewhere)
    # is the trust gate, not this store. The identity-bind requires a VM
    # genuinely awaiting an ack (audit M-StoppedAck).
    _awaiting_vm("vm-1", 7)
    client = APIClient()
    body = b"\xde\xad\xbe\xef-opaque-cbor"
    resp = _post(client, vm_id="vm-1", generation=7, body=body)
    assert resp.status_code == status.HTTP_202_ACCEPTED
    assert resp.json() == {"ok": True, "vm_id": "vm-1", "generation": 7}

    row = StoppedAckIngest.objects.get(vm_id="vm-1", generation=7)
    assert bytes(row.signed_ack) == body


def test_migrated_vm_ack_is_gated_on_signing_generation_not_live_gen() -> None:
    # A MIGRATED VM: live generation bumped to 2 by the fence, but the guest
    # still signs + POSTs its ack at its BAKED launch generation (1). The
    # ingest gate must ACCEPT the post at signing_generation (1) and REFUSE
    # one at the live generation (2) — else a migrated VM's §24/re-migration
    # ack is 404'd and never stored (→ forced-reclaim / hang).
    _awaiting_vm(
        "vm-migd",
        generation=2,
        state=VmState.DECOMMISSIONING,
        signing_generation=1,
    )
    client = APIClient()
    # Guest posts at its baked (signing) generation → accepted.
    ok = _post(client, vm_id="vm-migd", generation=1, body=b"baked-gen-ack")
    assert ok.status_code == status.HTTP_202_ACCEPTED
    assert StoppedAckIngest.objects.filter(vm_id="vm-migd", generation=1).exists()
    # A post at the LIVE (bumped) generation is refused — the guest never
    # signs there.
    bad = _post(client, vm_id="vm-migd", generation=2, body=b"live-gen-ack")
    assert bad.status_code == status.HTTP_404_NOT_FOUND
    assert not StoppedAckIngest.objects.filter(vm_id="vm-migd", generation=2).exists()


def test_ack_for_nonexistent_vm_is_refused_before_any_write() -> None:
    # Audit M-StoppedAck: an AllowAny caller can't create rows for
    # arbitrary vm_ids — no VM, no stored ack.
    client = APIClient()
    resp = _post(client, vm_id="does-not-exist", generation=1, body=b"x")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert StoppedAckIngest.objects.count() == 0


def test_ack_for_active_vm_is_refused() -> None:
    # A VM that exists but is NOT in an ack-awaiting state (Active) must
    # not accept a stopped-ack — nothing is polling for one.
    _awaiting_vm("vm-active", 2, state=VmState.ACTIVE)
    client = APIClient()
    resp = _post(client, vm_id="vm-active", generation=2, body=b"x")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert StoppedAckIngest.objects.count() == 0


def test_ack_for_wrong_generation_is_refused() -> None:
    # The generation must match the one the orchestrator polls
    # (vm.generation) — a mismatched-gen ack is inert, so it is refused
    # before the DB write.
    _awaiting_vm("vm-gen", 5, state=VmState.MIGRATING)
    client = APIClient()
    resp = _post(client, vm_id="vm-gen", generation=6, body=b"x")
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert StoppedAckIngest.objects.count() == 0


def test_poll_source_ack_reads_the_stored_bytes_at_signing_generation() -> None:
    body = b"signed-source-ack-bytes"
    StoppedAckIngest.objects.create(vm_id="vm-mig", generation=4, signed_ack=body)
    # poll_source_ack reads at signing_generation (the guest's baked gen);
    # for a fresh VM it equals generation.
    vm = Vm.objects.create(
        vm_id="vm-mig",
        lease_id="lease-mig",
        state=VmState.MIGRATING,
        generation=4,
        signing_generation=4,
        new_generation=5,
        migration_dest="host-b",
        host="host-a",
        lifecycle_vk=bytes(32),
    )
    assert effects.poll_source_ack(vm) == body


def test_poll_eol_ack_reads_the_stored_bytes_at_signing_generation() -> None:
    body = b"signed-eol-ack-bytes"
    StoppedAckIngest.objects.create(vm_id="vm-dec", generation=9, signed_ack=body)
    vm = Vm.objects.create(
        vm_id="vm-dec",
        lease_id="lease-dec",
        state=VmState.DECOMMISSIONING,
        generation=9,
        signing_generation=9,
        host="host-a",
        lifecycle_vk=bytes(32),
    )
    assert effects.poll_eol_ack(vm) == body


def test_poll_eol_ack_reads_at_signing_gen_for_a_migrated_vm() -> None:
    # A MIGRATED VM: live generation bumped by the fence (2), but the guest
    # still signs its §24 ack at its BAKED launch generation (1). poll_eol_ack
    # must read at signing_generation (1), NOT the live generation (2) — else
    # the ack is never found and §24 drops to forced-reclaim.
    body = b"migrated-eol-ack"
    StoppedAckIngest.objects.create(vm_id="vm-migd", generation=1, signed_ack=body)
    vm = Vm.objects.create(
        vm_id="vm-migd",
        lease_id="lease-migd",
        state=VmState.DECOMMISSIONING,
        generation=2,  # bumped by a prior §25 migration
        signing_generation=1,  # the launch gen the guest still signs at
        host="host-b",
        lifecycle_vk=bytes(32),
    )
    assert effects.poll_eol_ack(vm) == body


def test_poll_returns_none_when_no_ack_for_that_generation() -> None:
    # A stale ack at an EARLIER generation must NOT satisfy a poll at the
    # current generation (fail-closed: no verified ack ⇒ no advance).
    StoppedAckIngest.objects.create(vm_id="vm-x", generation=3, signed_ack=b"old")
    vm = Vm.objects.create(
        vm_id="vm-x",
        lease_id="lease-x",
        state=VmState.MIGRATING,
        generation=4,  # newer than the stored ack's generation
        new_generation=5,
        migration_dest="host-b",
        host="host-a",
        lifecycle_vk=bytes(32),
    )
    assert effects.poll_source_ack(vm) is None


def test_re_push_overwrites_latest_wins() -> None:
    _awaiting_vm("vm-1", 7)
    client = APIClient()
    _post(client, vm_id="vm-1", generation=7, body=b"first")
    _post(client, vm_id="vm-1", generation=7, body=b"second")
    # The uniqueness constraint holds: exactly one row, latest bytes.
    rows = StoppedAckIngest.objects.filter(vm_id="vm-1", generation=7)
    assert rows.count() == 1
    assert bytes(rows.first().signed_ack) == b"second"


def test_missing_vm_id_is_rejected() -> None:
    client = APIClient()
    resp = client.post(
        f"{_URL}?generation=7", data=b"x", content_type="application/cbor"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_non_integer_generation_is_rejected() -> None:
    client = APIClient()
    resp = client.post(
        f"{_URL}?vm_id=vm-1&generation=abc",
        data=b"x",
        content_type="application/cbor",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_empty_body_is_rejected() -> None:
    client = APIClient()
    resp = _post(client, vm_id="vm-1", generation=7, body=b"")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "stopped-decode"


def test_oversize_body_is_rejected_413() -> None:
    client = APIClient()
    max_bytes = int(settings.VALI_STOPPED_ACK_MAX_HEX_LEN) // 2
    resp = _post(
        client, vm_id="vm-1", generation=7, body=b"a" * (max_bytes + 1)
    )
    assert resp.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


def test_relay_forwarded_delivery_lands_at_source_gen_for_poll() -> None:
    """End-to-end (vali half) of the §25 source-ack delivery: the miner
    vsock relay forwards the guest's POST verbatim — the EXACT
    `?vm_id=&generation=` query the guest built + the OPAQUE ack body — to
    this ingress, and `poll_source_ack` reads those exact bytes back at the
    source VM's generation.

    The guest→vsock→miner-relay hop is Rust (proven by the miner-agent
    `kbs_proxy` forwarding tests + the guest `eol` url tests). The relay is
    opaque: it neither decodes nor mutates the body, so an `APIClient` POST
    of the verbatim wire is a faithful stand-in for what the relay
    delivers. The signature/generation verification (`_verify_ack`) runs on
    poll against the guest's lifecycle key — that requires a booted SNP
    guest + the validator binary and is an e2e-only step (fail-closed: no
    verified ack ⇒ the migration never advances).
    """
    opaque_ack = bytes(range(64)) + b"\x00\xff-signed-stopped-ack"
    # The source VM is Migrating at generation 3 (the fence preserves
    # generation == source_gen) — the identity-bind requires it to exist
    # before the guest's ack is accepted.
    vm = Vm.objects.create(
        vm_id="mig-e2e-1",
        lease_id="lease-mig",
        state=VmState.MIGRATING,
        generation=3,
        signing_generation=3,
        new_generation=4,
        migration_dest="node-dst",
        host="node-src",
        lifecycle_vk=bytes(32),
    )
    client = APIClient()
    # The relay forwards exactly the URL the guest built (vm_id + source
    # generation) and the opaque CBOR body — byte for byte.
    resp = _post(client, vm_id="mig-e2e-1", generation=3, body=opaque_ack)
    assert resp.status_code == status.HTTP_202_ACCEPTED

    # poll_source_ack reads the exact bytes.
    assert effects.poll_source_ack(vm) == opaque_ack


def test_gc_reaps_stale_rows_but_keeps_fresh_ones() -> None:
    # Audit M-StoppedAck: the GC command reaps rows older than the TTL so
    # the table stays bounded, while a still-in-flight (fresh) ack is kept.
    from datetime import timedelta

    from django.utils import timezone

    from apps.lifecycle.management.commands.vali_stopped_ack_gc import (
        gc_stopped_acks,
    )

    fresh = StoppedAckIngest.objects.create(
        vm_id="vm-fresh", generation=1, signed_ack=b"fresh"
    )
    stale = StoppedAckIngest.objects.create(
        vm_id="vm-stale", generation=1, signed_ack=b"stale"
    )
    # `received_at` is auto_now; force the stale row's stamp into the past
    # (past the 24h TTL) via a direct UPDATE that bypasses auto_now.
    StoppedAckIngest.objects.filter(pk=stale.pk).update(
        received_at=timezone.now() - timedelta(hours=48)
    )

    deleted = gc_stopped_acks(age_hours=24.0)
    assert deleted == 1
    assert StoppedAckIngest.objects.filter(pk=fresh.pk).exists()
    assert not StoppedAckIngest.objects.filter(pk=stale.pk).exists()
