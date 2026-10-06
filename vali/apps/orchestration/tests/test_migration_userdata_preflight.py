"""§25 intake refuses a VM whose userdata digest could never be re-derived.

The destination ticket's §6 digest is taken over the cloud-init PLAINTEXT
and binds a fresh ticket_id, so it is recomputed at mint time — from the
canonical copy when that is a legacy plaintext value, or from vali's
working copy (`ud-<vm_id>`-wrapped, same KV version) when it is not.

A VM with neither can never have a destination ticket minted. That mint
happens at `DestActivating`, i.e. AFTER the source has been quiesced,
stopped and KBS-fenced, and recovery from there is forward-only: the
tenant's VM is simply down until an operator intervenes. So the check has
to run at intake, while the source is still running, and it has to be the
SAME check the mint applies — open the working copy under `ud-<vm_id>`,
require the stamp, require it to name this canonical version — because a
looser one (a `vault:` prefix at the working path) admitted copies the
mint then refused, after the fence. The canonical copy's plaintext is
never touched: that key is `kek-<vm_id>`, KBS-only.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings

from apps.lifecycle.models import VmState
from apps.orchestration import service
from apps.orchestration.models import MigrationJob
from apps.orchestration.services import migration_ticket, vault_kv

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _vault_configured(settings):
    """The probe skips entirely when no Vault ADDRESS is configured (a
    deployment with no Vault — the dev shape). These tests are about what
    it does when there IS one."""
    settings.VALI_VAULT_ADDR = "https://vault.invalid:8200"


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """Source + destination registered as the SAME SNP generation, so the
    cross-gen gate is not what these tests measure."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def _launch_record(vm: Any) -> None:
    """The SUCCEEDED `LaunchJob` a dest re-mint reads its binding metadata
    from. Every VM launched through the API has one."""
    from django.utils import timezone

    from apps.orchestration.models import LaunchJob, LaunchJobState

    LaunchJob.objects.create(
        job_id=f"lj-{vm.vm_id}",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={"tenant_id": "tenant-1", "user_id": "u", "flavor": "small"},
        userdata_vault_path=f"x/{vm.vm_id}/userdata-intake",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )


def _vm() -> Any:
    vm = make_vm(generation=5, host="node-src")
    vm.state = VmState.ACTIVE
    vm.eol_nonce = bytes(range(32))
    vm.save(update_fields=["state", "eol_nonce"])
    return vm


_CANONICAL_VERSION = 3


def _stub_vault(monkeypatch, *, canonical: bytes, working: bytes | None) -> list[str]:
    """Canonical at version 3; `transit/decrypt` modelled as the reverse
    of the `_wrapped` transform below. Returns the list of Transit keys
    the probe decrypts with, so a test can pin WHICH copy it opens."""
    monkeypatch.setattr(vault_kv, "latest_version", lambda *a, **k: _CANONICAL_VERSION)

    def get_kv(mount, path, **kw):
        if path.endswith("-pending"):
            if working is None:
                raise vault_kv.VaultNotFound("no working copy")
            return working
        return canonical

    monkeypatch.setattr(vault_kv, "get_kv", get_kv)

    decrypted_with: list[str] = []

    def transit_decrypt(key: str, blob: bytes) -> bytes:
        decrypted_with.append(key)
        return bytes.fromhex(blob[len(b"vault:v1:") :].decode("ascii"))

    monkeypatch.setattr(vault_kv, "transit_decrypt", transit_decrypt)
    return decrypted_with


def _wrapped(plaintext: bytes) -> bytes:
    return b"vault:v1:" + plaintext.hex().encode("ascii")


def _stamped(version: int, plaintext: bytes = b"#cloud-config\n") -> bytes:
    """A working copy as `launch.stage_userdata_working_copy` writes it:
    the canonical-version stamp INSIDE the wrapped blob."""
    from apps.orchestration.services import launch

    return _wrapped(launch._WORKING_STAMP + str(version).encode("ascii") + b"\n" + plaintext)


_WRAPPED = _wrapped(b"#cloud-config\n")
_WORKING_PAIRED = _stamped(_CANONICAL_VERSION)


def test_intake_refuses_a_wrapped_canonical_with_no_working_copy(monkeypatch) -> None:
    """The shape that strands a migration: vali cannot open the canonical
    copy and has no copy of its own. Refused BEFORE anything is fenced."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(monkeypatch, canonical=_WRAPPED, working=None)

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert "no working copy" in str(exc.value)
    # Nothing started: the source is untouched and still Active.
    assert MigrationJob.objects.count() == 0
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE


def test_intake_refuses_a_plaintext_template_at_the_working_path(monkeypatch) -> None:
    """A VM launched between the canonical wrapping and the working copy
    has the pre-substitution TEMPLATE at that path. It is not a copy of
    the canonical bytes, so it cannot re-derive the digest either."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(
        monkeypatch,
        canonical=_WRAPPED,
        working=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert MigrationJob.objects.count() == 0


def test_intake_admits_a_wrapped_canonical_with_a_paired_working_copy(
    monkeypatch,
) -> None:
    """The production shape since the working copy landed: wrapped under
    `ud-<vm_id>` and stamped for the canonical version the mint binds."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(monkeypatch, canonical=_WRAPPED, working=_WORKING_PAIRED)

    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert job.dest_node_id == "node-dst"


def test_intake_refuses_an_unstamped_working_copy(monkeypatch) -> None:
    """Wrapped under the right key but carrying no stamp — what an older
    stager wrote. The mint's pairing check refuses it, so the intake must
    too, or the refusal lands after the fence with the source stopped."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(monkeypatch, canonical=_WRAPPED, working=_WRAPPED)

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert "no canonical-version stamp" in str(exc.value)
    assert MigrationJob.objects.count() == 0
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE


def test_intake_refuses_a_working_copy_stamped_for_another_version(monkeypatch) -> None:
    """The two staging writes are not atomic: a canonical write that
    succeeded while the working-copy write did not leaves a copy stamped
    for the PREVIOUS version. Its bytes are not the ones the ticket would
    bind — refused at intake, not at `DestActivating`."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(monkeypatch, canonical=_WRAPPED, working=_stamped(_CANONICAL_VERSION - 1))

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert f"stamped for canonical version {_CANONICAL_VERSION - 1}" in str(exc.value)
    assert MigrationJob.objects.count() == 0


def test_intake_admits_a_legacy_plaintext_canonical(monkeypatch) -> None:
    """A VM staged before the wrapping keeps migrating: the canonical
    value IS the plaintext, so the digest re-derives from it directly."""
    vm = _vm()
    _launch_record(vm)
    _stub_vault(monkeypatch, canonical=b"#cloud-config\nlegacy", working=None)

    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert job.dest_node_id == "node-dst"


def test_a_vault_outage_refuses_the_intake_as_RETRYABLE(monkeypatch) -> None:
    """The probe failing is not a verdict about the VM — but it is not a
    licence to proceed either: the KBS activation fences the source BEFORE
    the destination ticket is minted, so starting blind risks quiescing a
    VM whose ticket then cannot be built. Refuse, under a category that
    says "retry" (503) rather than "this VM cannot migrate" (409)."""
    vm = _vm()
    _launch_record(vm)

    def boom(*a, **k):
        raise vault_kv.EffectError("vault-kv-metadata: vault returned HTTP 503")

    monkeypatch.setattr(vault_kv, "latest_version", boom)

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "vault-unavailable"
    assert MigrationJob.objects.count() == 0
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE


def test_intake_refuses_a_vm_with_no_successful_launch_record(monkeypatch) -> None:
    """`vali_create_vm` writes `Vm` and `Placement` rows but no
    `LaunchJob`, and the dest re-mint reads its binding metadata off that
    row — so such a VM was quiesced, stopped and fenced, and only then
    found unmintable. Refuse at intake instead."""
    vm = _vm()  # no launch record
    _stub_vault(monkeypatch, canonical=_WRAPPED, working=_WORKING_PAIRED)

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert "no successful launch record" in str(exc.value)
    assert MigrationJob.objects.count() == 0


def test_intake_refuses_when_no_canonical_userdata_is_staged(monkeypatch) -> None:
    """Nothing at the canonical path at all: the mint would read it and
    fail — after the fence."""
    vm = _vm()
    _launch_record(vm)
    monkeypatch.setattr(vault_kv, "latest_version", lambda *a, **k: 3)
    monkeypatch.setattr(
        vault_kv,
        "get_kv",
        lambda *a, **k: (_ for _ in ()).throw(vault_kv.VaultNotFound("absent")),
    )

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "not-migratable"
    assert MigrationJob.objects.count() == 0


def test_the_probe_opens_only_the_working_copy(monkeypatch) -> None:
    """It decrypts exactly once, under vali's own `ud-<vm_id>`, and never
    attempts the canonical copy's `kek-<vm_id>` (KBS-only — a call there
    would 403 and say nothing about the VM)."""
    vm = _vm()
    _launch_record(vm)
    decrypted_with = _stub_vault(monkeypatch, canonical=_WRAPPED, working=_WORKING_PAIRED)
    migration_ticket.assert_userdata_rebindable(vm)
    assert decrypted_with == [vault_kv.userdata_transit_key_name(vm.vm_id)]
    assert not any(k.startswith("kek-") for k in decrypted_with)
    assert settings.VALI_VAULT_KV_PREFIX  # sanity: the paths were derivable


def test_a_legacy_plaintext_canonical_opens_nothing(monkeypatch) -> None:
    """When the canonical copy IS the plaintext there is no working copy
    to pair, and the probe must not go looking for one."""
    vm = _vm()
    _launch_record(vm)
    decrypted_with = _stub_vault(monkeypatch, canonical=b"#cloud-config\nlegacy", working=None)
    migration_ticket.assert_userdata_rebindable(vm)
    assert decrypted_with == []
