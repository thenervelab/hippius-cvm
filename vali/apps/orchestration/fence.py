"""§24/§25 generation fence — the KBS release-denial rule, mirrored.

The authoritative fence is enforced by the KBS: it serializably
checks the unified per-`vm_id` lifecycle state before every key
release and denies any release whose `vm_id` is not `Active`, whose
`vm_generation` ≠ the state's current `gen`, or whose intended
`node_id` ≠ the state's bound host (§24/§25).

vali's `lifecycle.Vm` row is the authoritative *intent* the
orchestrator advances; `release_allowed` is the same denial rule
expressed against that row. It exists so PR-G5 can (a) unit-test the
fence ("after a committed migration, a release on the old
source/generation is refused") and (b) give any vali-side caller a
single honest predicate instead of re-deriving the rule.
"""

from __future__ import annotations

from apps.lifecycle.models import Vm, VmState


def release_allowed(vm: Vm, *, node_id: str, generation: int) -> bool:
    """Return `True` iff a KBS key release for `(node_id, generation)`
    should be permitted for `vm`.

    Fails closed on every §24/§25 fence condition:

    - the VM is not `Active` (it is mid-migration, decommissioning,
      or a permanent `Destroyed` tombstone);
    - `generation` is not the VM's current generation (a stale
      generation — e.g. the source's generation after a committed
      migration advanced it);
    - `node_id` is not the VM's bound host (a release aimed at the
      old source after the VM moved to the destination).
    """
    if vm.state != VmState.ACTIVE:
        return False
    if vm.generation != generation:
        return False
    return vm.host == node_id
