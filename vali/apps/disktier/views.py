"""`GET /v1/operator/disk-profiles[?node_id=<hex>…]`

Auth: any classified service principal; operator-only scope — the same
posture as the other `/v1/operator/*` reads (see `apps.operator.views`):
the upstream resolves which nodes a signed-in operator may see, vali
answers for the nodes it is asked about. `node_id` is REQUIRED and
repeatable (1..100 values, 64 hex each), exactly as `/v1/operator/nodes`:
there is no "every node" form, so an upstream that forwards an empty
authorised-node list gets a 400, never the whole fleet.
→ 200 {nodes, count} / 400 wire / 401 / 403.
"""

from __future__ import annotations

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.operator.service import MAX_NODE_IDS
from apps.operator.views import _parse_node_ids

from .schemas import DiskProfilesSerializer
from .service import disk_profile_rows


class OperatorDiskProfilesView(APIView):
    """`GET /v1/operator/disk-profiles` — storage pools, dedicated disks and
    their verified tiers, per node."""

    # Fleet hardware state: operator-only, no tenant object.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Storage pools, dedicated disks and verified disk tiers per node",
        description=(
            "One row per node with at least one storage pool or dedicated disk: per pool "
            "the miner's report (untrusted), the probe-verified tier, any operator "
            "override and the effective tier, and health; per dedicated disk its state "
            "and verified tier. Probe timing is given as a date only, and no probe or "
            "tenant VM is named. Unknown node_ids are absent."
        ),
        tags=["Operator"],
        parameters=[
            OpenApiParameter(
                "node_id",
                str,
                OpenApiParameter.QUERY,
                many=True,
                required=True,
                description=f"On-chain node_id (64 hex). Repeatable, max {MAX_NODE_IDS}.",
            ),
        ],
        responses={
            200: DiskProfilesSerializer,
            400: OpenApiResponse(ErrorSerializer, "Missing / malformed / too many node_id."),
            401: OpenApiResponse(ErrorSerializer, "No / invalid service credential."),
            403: OpenApiResponse(ErrorSerializer, "Not an operator principal."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            node_ids = _parse_node_ids(request.query_params.getlist("node_id"))
        except ValueError as exc:
            return Response(
                {"error": str(exc), "category": "wire"}, status=status.HTTP_400_BAD_REQUEST
            )
        rows = disk_profile_rows(node_ids)
        return Response({"nodes": rows, "count": len(rows)}, status=status.HTTP_200_OK)
