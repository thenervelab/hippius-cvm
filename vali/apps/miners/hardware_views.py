"""Miner-admin support reads of a miner's host inventory — read-only.

    GET /v1/admin/miner/<miner_id>/hardware
    GET /v1/admin/miner/<miner_id>/hardware/history
    GET /v1/admin/miner/<miner_id>/disk-inventory
    GET /v1/admin/miner/<miner_id>/host-disk-advisories

Auth: ServiceToken, the miner-admin principal (the same as
`/v1/admin/miner/<miner_id>/approval`). Staff support sees a miner's
hardware without being — or naming — its family: the miner id is resolved
to its chain node and the §18.10 operator readouts
(`apps.disktier.hardware_views`, `apps.disktier.host_advisories`) are served
as they are, same shapes, same `verified: false`.

With one difference: serials and by-id names are the node OWNER's, so they
are WITHHELD here (`apps.disktier.withhold`): every serial key removed, every
by-id name replaced by an opaque per-node handle. The owner keeps reading them
on the family-checked operator routes.

→ 200 / 400 bad query / 403 not the miner-admin / 404 unknown miner or not
bridged to a chain node. Anything but GET is 405.
"""

from __future__ import annotations

from typing import Any

from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.disktier.hardware_views import (
    HISTORY_MAX,
    AdvisoriesSerializer,
    DiskInventorySerializer,
    HardwareHistorySerializer,
    HardwareSerializer,
    advisories_params,
    disk_inventory_readout,
    hardware_history_readout,
    hardware_readout,
    history_limit,
)
from apps.disktier.host_advisories import HISTORY_DAYS_MAX, advisories_readout
from apps.disktier.withhold import withhold
from apps.identity import scoping
from apps.identity.authentication import ServiceTokenAuthentication

from .models import MinerIdentity
from .permissions import IsMinerAdmin

_MINER_ID_PARAM = OpenApiParameter(
    "miner_id", str, OpenApiParameter.PATH, description="Target miner id."
)
_RESPONSES: dict[int, Any] = {
    403: OpenApiResponse(ErrorSerializer, "Not the miner-admin principal."),
    404: OpenApiResponse(ErrorSerializer, "Unknown miner, or not bridged to a chain node."),
}
_WITHHELD = (
    " Serials and by-id names are WITHHELD: serial fields removed, by-id names "
    "replaced by an opaque per-node handle (`withheld:<hex>`)."
)


def _with_miner_id(base: type[serializers.Serializer]) -> type[serializers.Serializer]:
    """`base` plus the top-level `miner_id` these routes add."""
    return type(
        f"Admin{base.__name__}",
        (base,),
        {
            "miner_id": serializers.CharField(),
            "__doc__": f"{base.__name__}, as served to the miner-admin, serials withheld.",
        },
    )


AdminHardwareSerializer = _with_miner_id(HardwareSerializer)
AdminHardwareHistorySerializer = _with_miner_id(HardwareHistorySerializer)
AdminDiskInventorySerializer = _with_miner_id(DiskInventorySerializer)
AdminAdvisoriesSerializer = _with_miner_id(AdvisoriesSerializer)


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


def _node_id(miner_id: str) -> str | None:
    node_id = (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("chain_node_id", flat=True)
        .first()
    )
    return node_id.lower() if node_id else None


class _AdminHardwareView(APIView):
    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: fleet operator read.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsMinerAdmin]
    http_method_names = ["get", "options"]

    def readout(self, request: Request, node_id: str) -> dict[str, Any] | Response:
        raise NotImplementedError

    def get(self, request: Request, miner_id: str) -> Response:
        node_id = _node_id(miner_id)
        if node_id is None:
            return _error(status.HTTP_404_NOT_FOUND, "miner not found", "not-found")
        out = self.readout(request, node_id)
        if isinstance(out, Response):
            return out
        return Response({"miner_id": miner_id, **withhold(out, node_id=node_id)})


class MinerHardwareView(_AdminHardwareView):
    @extend_schema(
        summary="A miner's host-reported hardware, serials withheld (not verified)",
        description=(
            "Miner-admin only. The §18.10 hardware readout of the miner's chain node: "
            "every section of its latest host inventory and vali's attested block." + _WITHHELD
        ),
        tags=["Miners"],
        parameters=[_MINER_ID_PARAM],
        responses={200: AdminHardwareSerializer, **_RESPONSES},
    )
    def get(self, request: Request, miner_id: str) -> Response:
        return super().get(request, miner_id)

    def readout(self, request: Request, node_id: str) -> dict[str, Any] | Response:
        return hardware_readout(node_id, now=timezone.now())


class MinerHardwareHistoryView(_AdminHardwareView):
    @extend_schema(
        summary="A miner's hardware changes (not verified)",
        description=(
            "Miner-admin only. Newest first: which section changed, when, and which "
            "of its fields. Values are not kept." + _WITHHELD
        ),
        tags=["Miners"],
        parameters=[
            _MINER_ID_PARAM,
            OpenApiParameter("limit", int, OpenApiParameter.QUERY, description=f"1..{HISTORY_MAX}"),
        ],
        responses={
            200: AdminHardwareHistorySerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad `limit`."),
            **_RESPONSES,
        },
    )
    def get(self, request: Request, miner_id: str) -> Response:
        return super().get(request, miner_id)

    def readout(self, request: Request, node_id: str) -> dict[str, Any] | Response:
        limit = history_limit(request)
        if limit is None:
            return _error(status.HTTP_400_BAD_REQUEST, f"limit is 1..{HISTORY_MAX}", "wire")
        return hardware_history_readout(node_id, limit=limit)


class MinerDiskInventoryView(_AdminHardwareView):
    @extend_schema(
        summary="A miner's host-reported disks, serials withheld (not verified)",
        description=(
            "Miner-admin only. The storage section of the miner's latest host inventory "
            "and `cross_check` against vali's pools and dedicated disks." + _WITHHELD
        ),
        tags=["Miners"],
        parameters=[_MINER_ID_PARAM],
        responses={200: AdminDiskInventorySerializer, **_RESPONSES},
    )
    def get(self, request: Request, miner_id: str) -> Response:
        return super().get(request, miner_id)

    def readout(self, request: Request, node_id: str) -> dict[str, Any] | Response:
        return disk_inventory_readout(node_id, now=timezone.now())


class MinerHostDiskAdvisoriesView(_AdminHardwareView):
    @extend_schema(
        summary="A miner's host-reported disk health, serials withheld (not verified)",
        description=(
            "Miner-admin only. Open disk advisories by subject with a suggested action; "
            "`include_resolved` adds the resolved ones, `history_days` "
            f"(≤ {HISTORY_DAYS_MAX}) the transitions." + _WITHHELD
        ),
        tags=["Miners"],
        parameters=[
            _MINER_ID_PARAM,
            OpenApiParameter("include_resolved", bool, OpenApiParameter.QUERY),
            OpenApiParameter(
                "history_days", int, OpenApiParameter.QUERY, description=f"0..{HISTORY_DAYS_MAX}"
            ),
        ],
        responses={
            200: AdminAdvisoriesSerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad `include_resolved` / `history_days`."),
            **_RESPONSES,
        },
    )
    def get(self, request: Request, miner_id: str) -> Response:
        return super().get(request, miner_id)

    def readout(self, request: Request, node_id: str) -> dict[str, Any] | Response:
        params = advisories_params(request)
        if isinstance(params, str):
            return _error(status.HTTP_400_BAD_REQUEST, params, "wire")
        include_resolved, history_days = params
        return advisories_readout(
            node_id,
            include_resolved=include_resolved,
            history_days=history_days,
            now=timezone.now(),
        )
