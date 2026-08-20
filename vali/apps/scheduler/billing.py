"""§23/§25 — the time-ranged answer to "which miner do we PAY for this
VM's uptime, over which seconds".

Two questions that look like one and are not:

  * WHAT may be billed — the `resource_class` / `lease_id` / `node_id` a
    guest-signed served receipt is allowed to declare. That is
    [`VmBillingBinding`], written at launch, and it is IMMUTABLE for the
    VM's life: the guest reads those values off its SNP-measured cmdline,
    which a §25 migration carries to the destination verbatim.
  * WHO is paid — the miner actually running the workload. That CHANGES
    on a §25 migration, and it changes at a specific INSTANT, so it is a
    history ([`VmBillingAssignment`]), not a field.

This module owns the history: [`record_assignment`] appends a change of
custody, [`credited_node_id`] resolves the miner in force at a given
instant. The meter (`usage.py`) resolves by the receipt's SERVICE WINDOW,
never by wall-clock — a receipt for a pre-migration window that is
metered after the cutover must still pay the source.
"""

from __future__ import annotations

import logging

from .models import VmBillingAssignment

log = logging.getLogger("apps.scheduler.billing")


def record_assignment(
    *, vm_id: str, node_id_hex: str, at_unix: int, reason: str
) -> VmBillingAssignment | None:
    """Append "from `at_unix` on, `node_id_hex` serves `vm_id`".

    APPEND-IF-CHANGED: when the miner already in force is the one being
    recorded, this is a NO-OP and returns `None`. That is what keeps a
    re-launch on the SAME host (reboot-recovery re-runs the whole launch
    path, and a §25 re-drive re-enters the activation) from littering the
    history with spurious custody changes — the history must record moves
    that HAPPENED, or it stops being auditable evidence of who was paid.

    Never rewrites or deletes a prior row: already-credited seconds are
    settled and moving them would be a new payments bug.
    """
    node_id_hex = (node_id_hex or "").lower()
    latest = _latest(vm_id)
    if latest is not None and latest.node_id_hex == node_id_hex:
        return None
    row = VmBillingAssignment.objects.create(
        vm_id=vm_id,
        node_id_hex=node_id_hex,
        effective_from_unix=int(at_unix),
        reason=reason,
    )
    log.info(
        "billing: vm=%s credited to node=%s from %d (%s)",
        vm_id,
        node_id_hex[:12] or "<unattributable>",
        int(at_unix),
        reason,
    )
    return row


def credited_node_id(
    *, vm_id: str, at_unix: int, fallback_node_id_hex: str
) -> str:
    """The miner credited for `vm_id`'s service at `at_unix`.

    The newest assignment whose `effective_from_unix <= at_unix` wins
    (rows are half-open, newest ⇒ `+∞`). Returns `""` when the row in
    force is UNATTRIBUTABLE — the caller must then credit nobody.

    `fallback_node_id_hex` (the launch binding's node) is used only when
    NO row covers the instant: a VM launched before this history existed,
    or a receipt window that predates the first recorded assignment. That
    fallback reproduces exactly the pre-history behaviour — credit the
    launch miner — so introducing the history re-attributes nothing.
    """
    row = (
        VmBillingAssignment.objects.filter(
            vm_id=vm_id, effective_from_unix__lte=int(at_unix)
        )
        .order_by("-effective_from_unix", "-created_at")
        .first()
    )
    if row is None:
        return fallback_node_id_hex
    return row.node_id_hex


def _latest(vm_id: str) -> VmBillingAssignment | None:
    return (
        VmBillingAssignment.objects.filter(vm_id=vm_id)
        .order_by("-effective_from_unix", "-created_at")
        .first()
    )
