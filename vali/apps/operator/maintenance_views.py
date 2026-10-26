"""The node owner's maintenance cordon (providers dashboard, proxied 1:1
by the backend).

  POST /v1/operator/miners/{node_id}/maintenance
      body {"cordon": true|false, "reason": "<optional, ≤ 200 printable chars>"}

Auth: exactly the operator storage API's (`apps.disktier.storage_views`):
an operator-scoped principal named in `VALI_OPERATOR_CONFIG_PRINCIPALS`
(`IsOperatorConfigWriter`), plus `X-Hippius-Acting-Family: <ss58>` and
`X-Hippius-Acting-User: <id>`, the family re-checked FRESH on chain to run
the node.

`cordon: true` sets the owner's maintenance cordon (source `owner`,
`apps.scheduler.cordon`); `cordon: false` lifts it. Only an owner cordon
is the owner's: while a staff or automatic cordon is in force, both
directions answer `409 cordon-not-owner` and change nothing. Idempotent:
a repeated call answers `200` with `changed: false`. Every change lands
`MinerCapacityAudit` rows (actor `owner:<family ss58>`, the backend user
and principal in the reason).

A cordon only stops NEW placements. The VMs already on the node run on —
nothing is stopped, drained or migrated. The owner waits for
`hosted_vm_count == 0`: runner VMs finish on their own; customer VMs
(`hosted_customer_vm_count`) stay until their owners migrate or stop them.
Like any cordon it also takes the node out of the NEW-work target sets
(backup restore / failover destinations, auto-approval candidates).

The cordon belongs to the node, not to the family that set it: if the
node changes family on chain, the new family sees it as `owner` and may
lift it.

  → 200 {node_id, changed, cordoned, cordon_source, cordon_reason,
         cordoned_at, hosted_vm_count, hosted_runner_vm_count,
         hosted_customer_vm_count}
  → 400 wire (`code`: body-invalid | reason-invalid | acting-family-invalid
        | acting-user-invalid) / 401 / 403 (not an operator-config principal,
        or `code: not-family-node`) / 404 `code: no-capacity-record`
        / 409 `code: cordon-not-owner` (+ `cordon_source`)
        / 503 `code: chain-unavailable`.
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response

from apps.common.schemas import ErrorSerializer
from apps.disktier.storage_views import _AUTH_RESPONSES, _COMMON_PARAMS, _error, _NodeStorageView
from apps.scheduler import cordon
from apps.scheduler import service as scheduler_service
from apps.scheduler.models import MinerCapacity

from .schemas import OperatorMaintenanceRequestSerializer, OperatorMaintenanceSerializer
from .service import cordon_fields, hosted_runner_counts

_BODY_KEYS = frozenset({"cordon", "reason"})
_AUDIT_REASON_MAX = 512
_ACTOR_MAX = 128


def _parse(data: Any) -> tuple[bool, str] | Response:
    if not isinstance(data, dict) or not set(data) <= _BODY_KEYS or "cordon" not in data:
        return _error(
            400,
            'body must be {"cordon": true|false, "reason": "<optional>"}',
            "wire",
            code="body-invalid",
        )
    want = data["cordon"]
    reason = data.get("reason", "")
    if not isinstance(want, bool):
        return _error(400, "cordon must be true or false", "wire", code="body-invalid")
    if reason is None:
        reason = ""
    if not isinstance(reason, str):
        return _error(400, "reason must be a string", "wire", code="reason-invalid")
    try:
        return want, cordon.validate_owner_reason(reason)
    except ValueError as exc:
        return _error(400, str(exc), "wire", code="reason-invalid")


def _readout(node_id: str, row: MinerCapacity, *, changed: bool) -> dict[str, Any]:
    # The same load figure `/v1/operator/nodes` shows (placements + incoming
    # moves), summed over every spelling of the node id so a case drift can
    # never report 0 VMs on a node still running some.
    _capacity, load_by_node, _family = scheduler_service.decision_inputs("")
    load = sum(n for nid, n in load_by_node.items() if nid.lower() == node_id)
    runners = hosted_runner_counts([node_id]).get(node_id, 0)
    return {
        "node_id": node_id,
        "changed": changed,
        **cordon_fields(row),
        "cordoned_at": row.cordoned_at.isoformat() if row.cordoned_at is not None else None,
        "hosted_vm_count": load,
        "hosted_runner_vm_count": runners,
        "hosted_customer_vm_count": max(0, load - runners),
    }


class OperatorMaintenanceView(_NodeStorageView):
    """`POST /v1/operator/miners/{node_id}/maintenance`."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Set or lift the node owner's maintenance cordon",
        description=(
            "`cordon: true` closes the node to NEW placements under an `owner` cordon; "
            "`cordon: false` lifts it. A staff or automatic cordon is never lifted nor "
            "restated here (409 `cordon-not-owner`). Idempotent (`changed: false`). "
            "Audited. The VMs already on the node are NOT stopped or moved: wait for "
            "`hosted_vm_count == 0` — runner VMs finish on their own, customer VMs stay "
            "until their owners migrate or stop them."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        request=OperatorMaintenanceRequestSerializer,
        responses={
            200: OperatorMaintenanceSerializer,
            404: OpenApiResponse(ErrorSerializer, "`code: no-capacity-record`."),
            409: OpenApiResponse(
                ErrorSerializer, "`code: cordon-not-owner` — a staff / automatic cordon."
            ),
            **_AUTH_RESPONSES,
        },
    )
    def post(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        parsed = _parse(request.data)
        if isinstance(parsed, Response):
            return parsed
        want, reason = parsed
        actor = call.actor
        try:
            result = cordon.set_owner_cordon(
                call.node_id,
                cordon=want,
                reason=reason,
                actor=f"owner:{actor.family}"[:_ACTOR_MAX],
                audit_reason=(
                    f"owner maintenance {'cordon' if want else 'uncordon'} "
                    f"(user={actor.user} principal={actor.principal}): {reason}"
                )[:_AUDIT_REASON_MAX],
            )
        except cordon.NotOwnerCordon as exc:
            return _error(
                409,
                "the node is cordoned by Hippius, not by its owner; only Hippius can lift it",
                "conflict",
                code="cordon-not-owner",
                cordon_source=exc.source,
            )
        if result is None:
            return _error(
                404,
                "vali has no capacity record for this node yet",
                "not-found",
                code="no-capacity-record",
            )
        return Response(
            _readout(call.node_id, result.row, changed=result.changed), status=status.HTTP_200_OK
        )
