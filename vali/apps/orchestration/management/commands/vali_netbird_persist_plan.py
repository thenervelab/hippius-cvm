"""`vali_netbird_persist_plan` — READ-ONLY plan to make existing tenant
NetBird peers persistent.

Tenant VMs launched before persistent setup keys enrolled EPHEMERAL peers,
which NetBird deletes after ~10 min offline (a §25 migration, a stopped
VM). The NetBird management API cannot change a peer's `ephemeral` flag —
it is set once, from the setup key, at registration — so the only path is
an UPDATE in the management server's store (`peers.ephemeral`).

This command changes nothing. It lists the tenant peers and prints the SQL
for an operator with access to that store, for the peers that qualify:

- named `hippius-tenant-<vm_id>` for a VM that is `active` in vali;
- currently `ephemeral`;
- CONNECTED right now. NetBird queues a peer for deletion when it
  disconnects and does not re-read the store before deleting it, so a
  disconnected peer is refused: flipping its flag would not save it.

Run it again right before applying: connectivity changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from django.core.management.base import BaseCommand

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects

_PREFIX = "hippius-tenant-"
#: NetBird peer ids are xid strings; anything else never reaches the SQL.
_PEER_ID = re.compile(r"^[a-z0-9]{20}$")


@dataclass(frozen=True)
class PeerVerdict:
    peer_id: str
    name: str
    action: str  # "convert" | "skip"
    reason: str


def plan(peers: list[dict[str, Any]], vm_states: dict[str, str]) -> list[PeerVerdict]:
    """Classify every tenant peer. Pure — no I/O."""
    out: list[PeerVerdict] = []
    for p in peers:
        name = str(p.get("name") or "")
        if not name.startswith(_PREFIX):
            continue
        peer_id = str(p.get("id") or "")
        vm_id = name[len(_PREFIX) :]

        def verdict(action: str, reason: str) -> None:
            out.append(PeerVerdict(peer_id, name, action, reason))  # noqa: B023

        if not _PEER_ID.match(peer_id):
            verdict("skip", "malformed-peer-id")
        elif not p.get("ephemeral"):
            verdict("skip", "already-persistent")
        elif vm_states.get(vm_id) != VmState.ACTIVE.value:
            verdict("skip", f"vm-not-active:{vm_states.get(vm_id, 'no-row')}")
        elif not p.get("connected"):
            verdict("skip", "disconnected-may-be-queued-for-deletion")
        else:
            verdict("convert", "active-connected-ephemeral")
    return out


def sql(peer_ids: list[str], *, ephemeral: bool) -> str:
    ids = ", ".join(f"'{i}'" for i in peer_ids)
    return (
        f"UPDATE peers SET ephemeral = {'true' if ephemeral else 'false'} "
        f"WHERE id IN ({ids}) AND ephemeral = {'false' if ephemeral else 'true'};"
    )


class Command(BaseCommand):
    help = __doc__

    def handle(self, *args: Any, **opts: Any) -> None:
        peers = effects.list_netbird_peers()
        vm_states = dict(Vm.objects.values_list("vm_id", "state"))
        verdicts = plan(peers, vm_states)
        for v in verdicts:
            self.stdout.write(f"  {v.action:8} {v.peer_id} {v.name} ({v.reason})")
        convert = [v.peer_id for v in verdicts if v.action == "convert"]
        self.stdout.write(f"READ-ONLY: {len(convert)} peer(s) qualify; nothing was changed.")
        if convert:
            self.stdout.write("-- apply, in ONE transaction, on the NetBird management store:")
            self.stdout.write("BEGIN;")
            self.stdout.write(sql(convert, ephemeral=False))
            self.stdout.write(f"-- expect exactly {len(convert)} row(s) updated, else ROLLBACK;")
            self.stdout.write("COMMIT;")
            self.stdout.write("-- rollback:")
            self.stdout.write(sql(convert, ephemeral=True))
