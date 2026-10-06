"""The last check before vali binds a VM at the KBS (`register-vm`).

`register-vm` makes the KBS release a VM's disk key to the host a ticket
names. Two paths used to call it on the strength of the ticket alone:
reboot-recovery's `launch_on_miner`, which only refused a VM already
decommissioning/destroyed at the START of a launch that can take many
minutes, and the operator `vali_dispatch_launch`, which never looked at the
Vm row at all. Either could re-bind a VM that had meanwhile started a §24
decommission or a §25 migration, or bind a ticket for a placement the VM
has left.

`register_under_vm_lock` re-reads the Vm row under `select_for_update` and
runs the KBS call inside the same transaction, so every vali transition of
the VM (the row-version CASes in the §24/§25 handlers) waits for the call
instead of slipping in between the check and the write. The lock is taken
`no_key=True` (Postgres `FOR NO KEY UPDATE`): it serialises every UPDATE of
the row, but does not block inserts of rows that reference it (Placement,
BackupRun, PublicIP, MigrationJob …) for the seconds the KBS call takes.

`vali_kbs_recover` on main does NOT follow this discipline yet: it
registers without re-reading the row under lock. The ceremony PR #1132
rewrites it to seed/register under the same row lock and to refuse every
non-active VM.

What is allowed: the VM is `active`, at the generation the ticket was minted
for, and either bound to the very miner the ticket targets, or not bound to
any miner at all (a fresh launch). "Bound" is resolved like every other
vali router does (`effects._bound_miner_id`): `vm.host`, else the miner of
the VM's latest SUCCEEDED LaunchJob — legacy rows launched before
`vm.host` was stamped carry their placement only there.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from django.db import transaction

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.effects import EffectError, _bound_miner_id

T = TypeVar("T")


class RegisterRefused(EffectError):
    """The Vm row does not allow this `register-vm`. Nothing was sent."""


def register_refusal(
    vm: Vm, *, generation: int, miner_id: str, initrd_sha256_hex: str | None = None
) -> str | None:
    """Why `vm` (a row already read under lock) must NOT be registered for a
    ticket at `generation` targeting `miner_id` — or `None` when it may.

    `initrd_sha256_hex` — the initrd the ticket's launch boots: refused when
    its guest components epoch is below the VM's required epoch
    (docs/design/guest-component-rollout.md, G3). Checked here, under the
    row lock and right before the KBS call, so a floor raised while the
    launch was minting is seen. `None` (a caller that names no initrd)
    passes only when the VM has no floor."""
    if vm.state == VmState.MIGRATING:
        return (
            f"vm {vm.vm_id!r} is migrating — a §25 move owns its KBS state; "
            "finish or recover the migration first"
        )
    if vm.state != VmState.ACTIVE:
        return f"vm {vm.vm_id!r} is {vm.state} — it can never be registered again"
    if int(vm.generation) != int(generation):
        return (
            f"vm {vm.vm_id!r} is at generation {vm.generation}, the ticket was "
            f"minted for generation {generation}"
        )
    bound = _bound_miner_id(vm)
    if bound not in ("", miner_id):
        return f"vm {vm.vm_id!r} is bound to host {bound!r}, the ticket targets {miner_id!r}"
    from . import guest_components

    if initrd_sha256_hex is None:
        if guest_components.required_epoch(vm.vm_id) > 0:
            return (
                f"vm {vm.vm_id!r} has a guest components floor and the register names "
                "no initrd to check against it"
            )
        return None
    return guest_components.launch_epoch_refusal(vm.vm_id, initrd_sha256_hex) or None


def register_under_vm_lock(
    vm_id: str,
    *,
    generation: int,
    miner_id: str,
    register: Callable[[], T],
    initrd_sha256_hex: str | None = None,
) -> T:
    """Run `register` (the KBS `register-vm` call) only if the Vm row allows
    it, holding the row lock across the call. Raises [`RegisterRefused`] —
    without calling `register` — when the row is absent or refuses."""
    with transaction.atomic():
        vm = Vm.objects.select_for_update(no_key=True).filter(vm_id=vm_id).first()
        if vm is None:
            raise RegisterRefused(f"no Vm row for {vm_id!r} — refusing to register it")
        refusal = register_refusal(
            vm, generation=generation, miner_id=miner_id, initrd_sha256_hex=initrd_sha256_hex
        )
        if refusal is not None:
            raise RegisterRefused(refusal)
        return register()
