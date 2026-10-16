"""Operator storage API: `/v1/operator/miners/{node_id}/…` (disk-tier
design §9; the providers dashboard, proxied 1:1 by the backend).

    GET    …/storage                       desired + applied + sync status
    PUT    …/storage                       replace the desired document
    POST   …/storage/pools                 add a pool
    PATCH  …/storage/pools/{pool_id}       change a pool
    DELETE …/storage/pools/{pool_id}       drain a pool (removed once empty)
    POST   …/storage/validate              dry run on the host (≤ 60 s)
    POST   …/storage/adopt                 desired := what the miner reports
    GET    …/storage/history               revisions, who, verdicts
    GET    …/disk-tiers                    verified tier / health per pool
    GET    …/dedicated-disks               dedicated-disk inventory
    POST   …/dedicated-disks/{disk_id}/drain

Auth, every call:

- a service principal with the operator scope (`OPERATOR_ONLY`); a write
  needs one named in `VALI_OPERATOR_CONFIG_PRINCIPALS` too
  (`IsOperatorConfigWriter`);
- `X-Hippius-Acting-Family: <ss58>` and `X-Hippius-Acting-User: <id>`:
  the family and backend user the call is made for. vali re-checks on
  chain (`apps.disktier.node_family`) that the family runs the node —
  `403 not-family-node` if not, `503 chain-unavailable` when the chain
  cannot say (fail closed). Every write is audited with principal,
  family and user (`MinerStorageConfigAudit`).

Writes change the DESIRED document only; the push loop
(`apps.disktier.storage_config.reconcile`) delivers it, dark unless
`VALI_STORAGE_CONFIG_PUSH`. `PUT` and the pool/disk edits take an
optional `If-Match: <revision>` (412 on mismatch; `0` = no document yet)
and answer `202 {revision, changed}`. A refusal mirrors the agent's:
`400 {error, category: "validation", code, pool|disk}`.

No probe or tenant identity is served: probe dates are days, an assigned
dedicated disk says `assigned`, not to which VM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from django.db.models import Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.operator.permissions import IsOperatorConfigWriter
from apps.orchestration.order_dispatch import OrderDispatchError

from . import node_family, storage_config, storage_doc
from . import storage_schemas as doc_schemas
from .models import (
    DedicatedDisk,
    DedicatedDiskState,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
)

_NODE_ID_RE = re.compile(r"[0-9a-f]{64}")
_USER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}")
_IF_MATCH_RE = re.compile(r'(?:W/)?"?([0-9]{1,19})"?')
FAMILY_HEADER = "X-Hippius-Acting-Family"
USER_HEADER = "X-Hippius-Acting-User"
HISTORY_DEFAULT = 50
HISTORY_MAX = 200


def _error(http_status: int, message: str, category: str, **extra: Any) -> Response:
    return Response({"error": message, "category": category, **extra}, status=http_status)


def _day(at: datetime | None) -> date | None:
    return at.astimezone(UTC).date() if at is not None else None


@dataclass(frozen=True)
class _Call:
    node_id: str
    actor: storage_config.Actor


_COMMON_PARAMS = [
    OpenApiParameter(
        "node_id", str, OpenApiParameter.PATH, description="On-chain node_id (64 hex)."
    ),
    OpenApiParameter(
        FAMILY_HEADER,
        str,
        OpenApiParameter.HEADER,
        required=True,
        description="SS58 address of the family the call is made for; re-checked on chain.",
    ),
    OpenApiParameter(
        USER_HEADER,
        str,
        OpenApiParameter.HEADER,
        required=True,
        description="The backend user the call is made for (audited).",
    ),
]
_IF_MATCH = OpenApiParameter(
    "If-Match",
    str,
    OpenApiParameter.HEADER,
    required=False,
    description="The revision the edit is based on; 412 if it is no longer current.",
)
_AUTH_RESPONSES = {
    400: OpenApiResponse(ErrorSerializer, "Bad node_id / headers / document (with `code`)."),
    401: OpenApiResponse(ErrorSerializer, "No / invalid service credential."),
    403: OpenApiResponse(
        ErrorSerializer, "Not an operator(-config) principal, or `code: not-family-node`."
    ),
    503: OpenApiResponse(ErrorSerializer, "`code: chain-unavailable` — fail closed."),
}


class _NodeStorageView(APIView):
    """The shared posture: operator-only, reads for any operator principal,
    writes for an operator-config principal, family re-checked on chain."""

    object_scope = scoping.OPERATOR_ONLY
    #: Methods that change something (need `IsOperatorConfigWriter`).
    write_methods: frozenset[str] = frozenset({"PUT", "POST", "PATCH", "DELETE"})

    def get_permissions(self) -> list[Any]:
        if self.request.method in self.write_methods:
            return [IsAuthenticated(), IsOperatorConfigWriter()]
        return [IsAuthenticated()]

    def _call(self, request: Request, node_id: str) -> _Call | Response:
        node_id = node_id.lower()
        if not _NODE_ID_RE.fullmatch(node_id):
            return _error(400, "node_id must be exactly 64 hex chars", "wire")
        family = (request.headers.get(FAMILY_HEADER) or "").strip()
        user = (request.headers.get(USER_HEADER) or "").strip()
        try:
            account = node_family.ss58_decode(family).hex()
        except ValueError:
            return _error(
                400,
                f"{FAMILY_HEADER} must be an SS58 address",
                "wire",
                code="acting-family-invalid",
            )
        if not _USER_RE.fullmatch(user):
            return _error(
                400,
                f"{USER_HEADER} must be 1..128 chars of [A-Za-z0-9._:@-]",
                "wire",
                code="acting-user-invalid",
            )
        try:
            runs = node_family.family_runs_node(
                node_id, family, fresh=request.method in self.write_methods
            )
        except node_family.FamilyCheckUnavailable:
            return _error(
                503,
                "the chain could not confirm the node's family",
                "unavailable",
                code="chain-unavailable",
            )
        if not runs:
            return _error(
                403, "the acting family does not run this node", "forbidden", code="not-family-node"
            )
        principal = getattr(request.user, "name", "") or ""
        return _Call(
            node_id,
            storage_config.Actor(principal=principal, family=family, user=user, account=account),
        )


def _owned(call: _Call) -> MinerStorageConfig | None:
    """The node's desired document if the acting family wrote it: a
    document of the node's former family is invisible to the new one."""
    row = MinerStorageConfig.objects.filter(miner_node_id=call.node_id).first()
    return storage_config.owned_by(row, call.actor.account)


def _if_match(request: Request) -> int | None | Response:
    raw = request.headers.get("If-Match")
    if raw is None:
        return None
    match = _IF_MATCH_RE.fullmatch(raw.strip())
    if match is None:
        return _error(400, "If-Match is a revision number", "wire", code="if-match-invalid")
    return int(match.group(1))


def _stage_response(row: MinerStorageConfig, changed: bool) -> Response:
    response = Response(
        {"revision": row.revision, "changed": changed}, status=status.HTTP_202_ACCEPTED
    )
    response["ETag"] = f'"{row.revision}"'
    return response


def _write(fn: Any) -> Response:
    """Run a staging call and map its exceptions."""
    try:
        row, changed = fn()
    except storage_doc.DocError as exc:
        return Response(exc.body(), status=status.HTTP_400_BAD_REQUEST)
    except storage_config.StageConflict as exc:
        return _error(
            412,
            "the document changed: re-read it and retry",
            "conflict",
            code="revision-mismatch",
            revision=exc.current,
        )
    except LookupError:
        return _error(
            404,
            "the node has no desired storage document (PUT or adopt one first)",
            "not-found",
            code="storage-config-missing",
        )
    return _stage_response(row, changed)


# ─── readouts ────────────────────────────────────────────────────────


def _applied_pool(pool: MinerStoragePool) -> dict[str, Any]:
    return {
        "pool_id": pool.pool_id,
        "class": pool.declared_class,
        "os_disks": pool.os_disks,
        "state": pool.reported_state,
        "error": pool.reported_error,
        "total_gb": pool.total_gb,
        "available_gb": pool.available_gb,
        "budget_gb": pool.budget_gb,
        "committed_gb": pool.committed_gb,
        "reported_at": pool.reported_at,
        "retired": pool.retired_at is not None,
    }


def _tier_row(pool: MinerStoragePool) -> dict[str, Any]:
    last_run = pool.last_run
    return {
        "pool_id": pool.pool_id,
        "tier": pool.tier,
        "tier_since_on": _day(pool.tier_since),
        "operator_override": pool.operator_override,
        "override_reason": pool.override_reason,
        "effective_tier": pool.effective_tier,
        "health": pool.health,
        "health_since_on": _day(pool.health_since),
        "next_probe_due_on": _day(pool.next_probe_due_at),
        "last_probe_on": _day(
            (last_run.result_at or last_run.scheduled_at) if last_run is not None else None
        ),
        "retired": pool.retired_at is not None,
    }


def _desired(row: MinerStorageConfig | None) -> dict[str, Any] | None:
    if row is None or row.revision == 0:
        return None
    return {
        "revision": row.revision,
        "pools": row.body.get("pools", []),
        "dedicated_disks": row.body.get("dedicated_disks", []),
        "updated_by": {
            "principal": row.updated_by_principal,
            "family": row.updated_by_family,
            "user": row.updated_by_user,
        },
        "updated_at": row.updated_at,
    }


def _sync(row: MinerStorageConfig | None) -> dict[str, Any]:
    out: dict[str, Any] = {"status": storage_config.sync_status(row)}
    if row is None or row.revision == 0:
        return out
    out.update(
        {
            "acked_revision": row.acked_revision,
            "acked_at": row.acked_at,
            "sent_at": row.sent_at,
            "last_error": row.last_error,
            "refusal": (
                {"code": row.refusal_code, "pool": row.refusal_pool, "disk": row.refusal_disk}
                if row.refusal_code
                else None
            ),
        }
    )
    return out


def _disk_row(disk: DedicatedDisk, desired: dict[str, str]) -> dict[str, Any]:
    return {
        "disk_id": disk.disk_id,
        "size_bytes": disk.size_bytes,
        "desired_state": desired.get(disk.disk_id),
        "reported_state": disk.reported_state,
        "reported_error": disk.reported_error,
        "reported_at": disk.reported_at,
        "state": disk.state,
        "verified_tier": disk.verified_tier,
        "last_probed_on": _day(disk.probed_at),
        "behind_controller": disk.behind_controller,
        "assigned": disk.state == DedicatedDiskState.ASSIGNED,
    }


def _desired_disk_states(row: MinerStorageConfig | None) -> dict[str, str]:
    if row is None:
        return {}
    return {d["id"]: d["state"] for d in row.body.get("dedicated_disks", [])}


def storage_readout(node_id: str, account: str) -> dict[str, Any]:
    """The `GET …/storage` body for the family `account` (the desired
    document and its sync state only when it is that family's)."""
    raw = MinerStorageConfig.objects.filter(miner_node_id=node_id).first()
    row = storage_config.owned_by(raw, account)
    pools = list(
        MinerStoragePool.objects.filter(miner_node_id=node_id)
        .select_related("last_run")
        .order_by("pool_id")
    )
    disks = DedicatedDisk.objects.filter(miner_node_id=node_id).order_by("disk_id")
    desired_disks = _desired_disk_states(row)
    return {
        "node_id": node_id,
        "desired": _desired(row),
        "applied": {
            "storage_config_revision": raw.reported_revision if raw is not None else None,
            "reported_at": raw.reported_at if raw is not None else None,
            "pools": [_applied_pool(p) for p in pools],
            "dedicated_disks": [_disk_row(d, desired_disks) for d in disks],
        },
        "sync": _sync(row),
        "tiers": [_tier_row(p) for p in pools],
    }


# ─── views ───────────────────────────────────────────────────────────


class OperatorStorageView(_NodeStorageView):
    http_method_names = ["get", "put", "options"]

    @extend_schema(
        summary="A node's desired and applied storage configuration",
        description=(
            "The desired storage-config document (pools + dedicated disks, revision, who "
            "changed it), what the miner reports (heartbeat v7, untrusted), the push sync "
            "status (`in_sync`, `pending`, `refused:<code>:<id>`, `agent-unsupported`, "
            "`drift`, `unmanaged`) and the verified tier per pool. ETag = revision."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        responses={200: doc_schemas.StorageReadoutSerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        data = storage_readout(call.node_id, call.actor.account)
        response = Response(data, status=status.HTTP_200_OK)
        if data["desired"] is not None:
            response["ETag"] = f'"{data["desired"]["revision"]}"'
        return response

    @extend_schema(
        summary="Replace a node's desired storage document",
        description=(
            "Validated like the agent validates it without the host (ids, count, `default` "
            "kept at the host budget, class, budget > 0, plain absolute paths, dedicated "
            "disk ids, no duplicates); a refusal carries the agent's `code` and the `pool` "
            "or `disk`. Unchanged content keeps the revision. Delivered by the push loop."
        ),
        tags=["Operator"],
        parameters=[*_COMMON_PARAMS, _IF_MATCH],
        request=doc_schemas.StorageDocSerializer,
        responses={
            202: doc_schemas.StagedSerializer,
            412: OpenApiResponse(ErrorSerializer, "`If-Match` is not the current revision."),
            **_AUTH_RESPONSES,
        },
    )
    def put(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        if_match = _if_match(request)
        if isinstance(if_match, Response):
            return if_match

        def _put() -> tuple[MinerStorageConfig, bool]:
            doc = storage_doc.normalize(
                request.data, **storage_config.local_limits(call.node_id, call.actor.account)
            )
            return storage_config.stage(
                call.node_id, doc, actor=call.actor, action="put", if_match=if_match
            )

        return _write(_put)


def _pool_edit(call: _Call, request: Request, change: Any, action: str) -> Response:
    if_match = _if_match(request)
    if isinstance(if_match, Response):
        return if_match
    return _write(
        lambda: storage_config.edit(
            call.node_id, change, actor=call.actor, action=action, if_match=if_match
        )
    )


class OperatorStoragePoolsView(_NodeStorageView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Add a storage pool to a node's desired document",
        tags=["Operator"],
        parameters=[*_COMMON_PARAMS, _IF_MATCH],
        request=doc_schemas.StoragePoolSerializer,
        responses={
            202: doc_schemas.StagedSerializer,
            404: OpenApiResponse(ErrorSerializer, "`code: storage-config-missing`."),
            409: OpenApiResponse(ErrorSerializer, "`code: pool-exists`."),
            412: OpenApiResponse(ErrorSerializer, "`If-Match` is not the current revision."),
            **_AUTH_RESPONSES,
        },
    )
    def post(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        pool = request.data
        pool_id = pool.get("id") if isinstance(pool, dict) else None
        current = _owned(call)
        if current is not None and any(p["id"] == pool_id for p in current.body.get("pools", [])):
            return _error(
                409,
                "the node already has this pool",
                "conflict",
                code="pool-exists",
                pool=str(pool_id)[:32],
            )

        def _add(doc: dict[str, Any]) -> dict[str, Any]:
            doc["pools"].append(pool)
            return doc

        return _pool_edit(call, request, _add, "pool-add")


_POOL_PATCH_KEYS = frozenset({"path", "class", "budget_gb", "os_disks", "state"})


class OperatorStoragePoolView(_NodeStorageView):
    http_method_names = ["patch", "delete", "options"]

    @extend_schema(
        summary="Change one pool of a node's desired document",
        description="Any of path, class, budget_gb, os_disks, state; the id is fixed.",
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("pool_id", str, OpenApiParameter.PATH),
            _IF_MATCH,
        ],
        request=doc_schemas.StoragePoolPatchSerializer,
        responses={
            202: doc_schemas.StagedSerializer,
            404: OpenApiResponse(ErrorSerializer, "No such pool / no document."),
            412: OpenApiResponse(ErrorSerializer, "`If-Match` is not the current revision."),
            **_AUTH_RESPONSES,
        },
    )
    def patch(self, request: Request, node_id: str, pool_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        fields = request.data
        if not isinstance(fields, dict) or not fields or not set(fields) <= _POOL_PATCH_KEYS:
            return _error(
                400,
                f"a pool patch sets some of {sorted(_POOL_PATCH_KEYS)}",
                "validation",
                code="storage-config-malformed",
                pool=pool_id[:32],
            )
        missing = self._missing_pool(call, pool_id)
        if missing is not None:
            return missing

        def _patch(doc: dict[str, Any]) -> dict[str, Any]:
            for pool in doc["pools"]:
                if pool["id"] == pool_id:
                    pool.update(fields)
            return doc

        return _pool_edit(call, request, _patch, "pool-update")

    @extend_schema(
        summary="Drain one pool of a node",
        description=(
            "Sets the pool `draining`: it takes no new disk. vali removes it from the "
            "document once the agent applied that and reports the pool empty "
            "(`committed_gb == 0`). Pool `default` cannot be drained."
        ),
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("pool_id", str, OpenApiParameter.PATH),
            _IF_MATCH,
        ],
        request=None,
        responses={
            202: doc_schemas.StagedSerializer,
            404: OpenApiResponse(ErrorSerializer, "No such pool / no document."),
            412: OpenApiResponse(ErrorSerializer, "`If-Match` is not the current revision."),
            **_AUTH_RESPONSES,
        },
    )
    def delete(self, request: Request, node_id: str, pool_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        missing = self._missing_pool(call, pool_id)
        if missing is not None:
            return missing

        def _drain(doc: dict[str, Any]) -> dict[str, Any]:
            for pool in doc["pools"]:
                if pool["id"] == pool_id:
                    pool["state"] = "draining"
            return doc

        return _pool_edit(call, request, _drain, "pool-drain")

    @staticmethod
    def _missing_pool(call: _Call, pool_id: str) -> Response | None:
        row = _owned(call)
        if row is None:
            return _error(
                404,
                "the node has no desired storage document (PUT or adopt one first)",
                "not-found",
                code="storage-config-missing",
            )
        if not any(p["id"] == pool_id for p in row.body.get("pools", [])):
            return _error(
                404, "no such pool", "not-found", code="pool-not-found", pool=pool_id[:32]
            )
        return None


class OperatorStorageValidateView(_NodeStorageView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Dry-run a storage document on the host",
        description=(
            "Pushes a `dry_run` storage-config order and returns the agent's verdict: "
            "`ok` with `dry-run-ok:<rev>:<sha>`, or the refusal `code` and `pool`/`disk`. "
            "Nothing is applied or stored. The body is a document to judge; empty = the "
            "current desired document. Synchronous, at most 60 s. 409 with the reason "
            "when the node cannot be sent orders (push off, not selected, agent too old)."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        request=doc_schemas.StorageDocSerializer,
        responses={
            200: doc_schemas.DryRunSerializer,
            404: OpenApiResponse(ErrorSerializer, "No body and no desired document."),
            409: OpenApiResponse(ErrorSerializer, "The node cannot be sent orders (`code`)."),
            502: OpenApiResponse(ErrorSerializer, "The agent did not answer."),
            **_AUTH_RESPONSES,
        },
    )
    def post(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        row = _owned(call)
        if request.data:
            try:
                doc = storage_doc.normalize(
                    request.data, **storage_config.local_limits(call.node_id, call.actor.account)
                )
            except storage_doc.DocError as exc:
                return Response(exc.body(), status=status.HTTP_400_BAD_REQUEST)
        elif row is not None:
            doc = row.body
        else:
            return _error(
                404,
                "no document given and the node has none",
                "not-found",
                code="storage-config-missing",
            )
        revision = row.revision if row is not None else 1
        try:
            verdict = storage_config.dry_run(call.node_id, doc, revision=revision)
        except storage_config.DryRunUnavailable as exc:
            return _error(409, "the node cannot be sent orders now", "conflict", code=str(exc))
        except OrderDispatchError as exc:
            return _error(
                503, f"the order could not be built: {exc}", "unavailable", code="order-unavailable"
            )
        storage_config.audit(
            call.node_id, revision, "validate", call.actor, doc=doc, outcome=verdict.outcome
        )
        if verdict.error:
            return _error(502, verdict.error, "unavailable", code="agent-unreachable")
        return Response({"revision": revision, **verdict.body()}, status=status.HTTP_200_OK)


class OperatorStorageAdoptView(_NodeStorageView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Manage a node's storage from the dashboard: desired := applied",
        description=(
            "Builds the desired document from what the miner reports (heartbeat v7): its "
            "pools with their class, budget, OS-disk flag and state, and its dedicated "
            "disks. The heartbeat carries no paths, so `pools` gives each reported pool's "
            "`path` (and a `class` for a pool reported without one). The first adoption "
            "is revision 1 (its push re-applies what is in force). 409 if a document "
            "exists, unless `force`."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        request=doc_schemas.AdoptRequestSerializer,
        responses={
            202: doc_schemas.StagedSerializer,
            409: OpenApiResponse(
                ErrorSerializer, "`storage-config-exists` / `storage-report-missing`."
            ),
            **_AUTH_RESPONSES,
        },
    )
    def post(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        body = request.data if isinstance(request.data, dict) else None
        if body is None or not set(body) <= {"pools", "force"}:
            return _error(
                400,
                "the body is {pools: {pool_id: {path, class?}}, force?}",
                "validation",
                code="storage-config-malformed",
            )
        force = body.get("force", False)
        if not isinstance(force, bool):
            return _error(400, "force is a boolean", "validation", code="storage-config-malformed")
        try:
            row, changed = storage_config.adopt(
                call.node_id, body.get("pools", {}), actor=call.actor, force=force
            )
        except storage_doc.DocError as exc:
            http = 409 if exc.code == "storage-report-missing" else 400
            return Response(exc.body(), status=http)
        except storage_config.StageConflict as exc:
            return _error(
                409,
                "the node already has a desired document (force to replace it)",
                "conflict",
                code="storage-config-exists",
                revision=exc.current,
            )
        return _stage_response(row, changed)


class OperatorStorageHistoryView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's storage-config history",
        description=(
            "Newest first: every write (who: principal, family, user; the document it "
            "produced) and every change of the agent's verdict on a revision."
        ),
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("limit", int, OpenApiParameter.QUERY, description=f"1..{HISTORY_MAX}"),
        ],
        responses={200: doc_schemas.HistorySerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        raw = request.query_params.get("limit", str(HISTORY_DEFAULT))
        if not raw.isdigit() or not 1 <= int(raw) <= HISTORY_MAX:
            return _error(400, f"limit is 1..{HISTORY_MAX}", "wire")
        # Only the acting family's own history: from the moment its
        # document replaced the node's former family's.
        row = _owned(call)
        if row is None:
            rows: Any = []
        else:
            # Its own entries and vali's, never another family's (a
            # validate it ran between two terms of this family's).
            rows = MinerStorageConfigAudit.objects.filter(
                Q(family_account=call.actor.account) | Q(family_account=""),
                miner_node_id=call.node_id,
                at__gte=row.owner_since,
            )[: int(raw)]
        entries = [
            {
                "revision": r.revision,
                "action": r.action,
                "principal": r.principal,
                "family": r.family,
                "user": r.user,
                "at": r.at,
                "outcome": r.outcome,
                "doc": r.doc or None,
            }
            for r in rows
        ]
        return Response({"node_id": call.node_id, "entries": entries}, status=status.HTTP_200_OK)


class OperatorDiskTiersView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Verified disk tier and health per pool of a node",
        description="Probe timing at day granularity only. Empty until probes run.",
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        responses={200: doc_schemas.DiskTiersSerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        pools = (
            MinerStoragePool.objects.filter(miner_node_id=call.node_id)
            .select_related("last_run")
            .order_by("pool_id")
        )
        return Response(
            {"node_id": call.node_id, "pools": [_tier_row(p) for p in pools]},
            status=status.HTTP_200_OK,
        )


class OperatorDedicatedDisksView(_NodeStorageView):
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A node's dedicated-disk inventory",
        description=(
            "Per disk: what the miner reports (state, refusal code), vali's state and "
            "verified tier, and the desired state in the storage document (null when the "
            "document does not declare it). Never the VM a disk is assigned to."
        ),
        tags=["Operator"],
        parameters=_COMMON_PARAMS,
        responses={200: doc_schemas.DedicatedDisksSerializer, **_AUTH_RESPONSES},
    )
    def get(self, request: Request, node_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        desired = _desired_disk_states(_owned(call))
        disks = DedicatedDisk.objects.filter(miner_node_id=call.node_id).order_by("disk_id")
        return Response(
            {"node_id": call.node_id, "disks": [_disk_row(d, desired) for d in disks]},
            status=status.HTTP_200_OK,
        )


class OperatorDedicatedDiskDrainView(_NodeStorageView):
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Drain a dedicated disk",
        description=(
            "Sets the disk `draining` in the storage document: no new assignment; it "
            "leaves placement once released."
        ),
        tags=["Operator"],
        parameters=[
            *_COMMON_PARAMS,
            OpenApiParameter("disk_id", str, OpenApiParameter.PATH),
            _IF_MATCH,
        ],
        request=None,
        responses={
            202: doc_schemas.StagedSerializer,
            404: OpenApiResponse(ErrorSerializer, "The document does not declare the disk."),
            412: OpenApiResponse(ErrorSerializer, "`If-Match` is not the current revision."),
            **_AUTH_RESPONSES,
        },
    )
    def post(self, request: Request, node_id: str, disk_id: str) -> Response:
        call = self._call(request, node_id)
        if isinstance(call, Response):
            return call
        row = _owned(call)
        if row is None or not any(d["id"] == disk_id for d in row.body.get("dedicated_disks", [])):
            return _error(
                404,
                "the storage document does not declare this disk",
                "not-found",
                code="disk-not-in-config",
                disk=disk_id[:96],
            )

        def _drain(doc: dict[str, Any]) -> dict[str, Any]:
            for disk in doc["dedicated_disks"]:
                if disk["id"] == disk_id:
                    disk["state"] = "draining"
            return doc

        return _pool_edit(call, request, _drain, "disk-drain")
