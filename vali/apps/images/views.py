"""Golden-image catalog surface — `GET /v1/images`.

Read-only discovery of the launchable golden images so a tenant / SDK can
learn which image NAMES `POST /v1/vm/launch` accepts (launch-by-image). The
catalog itself is OPERATOR-controlled — there is NO write endpoint here; rows
are set only by the `vali_bless_golden_image` management command.

Auth is the same tier as listing VMs / fetching a bake: any authenticated
`ServiceClient` (`IsAuthenticated`).
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.identity import scoping
from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode, TenantBakeState

from .models import GoldenImage
from .schemas import GoldenImageListSerializer


class ImageListView(APIView):
    """`GET /v1/images` — list the operator-blessed golden-image catalog."""

    # P2 object-level authorization: the operator-blessed launchable-image
    # catalog carries no tenant object.
    object_scope = scoping.NO_TENANT_DATA
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="List launchable golden images",
        description=(
            "Any authenticated ServiceClient. Returns the operator-blessed "
            "golden-image catalog — the image NAMES `POST /v1/vm/launch` "
            "accepts (launch-by-image), each mapping to the CURRENT blessed "
            "golden `bake_id`. Read-only; the catalog is set only by the "
            "operator (`vali_bless_golden_image`), never by a tenant."
        ),
        tags=["Images"],
        responses={200: OpenApiResponse(GoldenImageListSerializer, "The catalog.")},
    )
    def get(self, request: Request) -> Response:
        images = list(GoldenImage.objects.all())
        # Resolve `is_golden` from the referenced bakes in one query. The
        # operator only blesses Succeeded golden bakes, so this is normally
        # always True; it flips false only if a blessed bake was removed /
        # altered out-of-band (surfaced for diagnostics, never for authz).
        bakes = {
            b.bake_id: b
            for b in TenantBake.objects.filter(
                bake_id__in=[img.bake_id for img in images]
            )
        }
        rows = [_serialize_image(img, bakes.get(img.bake_id)) for img in images]
        return Response(
            {"images": rows, "total": len(rows)}, status=status.HTTP_200_OK
        )


def _serialize_image(img: GoldenImage, bake: TenantBake | None) -> dict[str, Any]:
    is_golden = bool(
        bake
        and bake.state == TenantBakeState.SUCCEEDED.value
        and bake.disk_mode == TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value
    )
    return {
        "image_name": img.image_name,
        "distro": img.distro,
        "bake_id": img.bake_id,
        "is_golden": is_golden,
        "blessed_at": img.blessed_at.isoformat(),
        "blessed_by": img.blessed_by or "",
        "guest_release": img.guest_release,
    }
