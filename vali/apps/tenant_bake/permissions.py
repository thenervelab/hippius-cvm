"""Permission classes for the tenant_bake app.

`/finalize` is callable ONLY by the baker k8s Job principal — the
`ServiceClient` with `name == settings.VALI_TENANT_BAKE_WORKER_PRINCIPAL`.
Every other authenticated client gets 403. Same shape as
`apps.packer.IsPackerWorker`.

The other endpoints (`POST /v1/tenant-bakes`,
`GET /v1/tenant-bakes/<id>`) are gated on plain `IsAuthenticated` —
any registered `ServiceClient` (typically `vali_create_vm`) can
trigger a bake / query its state.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


class IsTenantBakeWorker(BasePermission):
    """Allow only the configured baker k8s Job principal.

    `request.user` after authentication is a `ServiceClient`; we
    compare its `name` against the locked principal. The principal
    name comes from `settings.VALI_TENANT_BAKE_WORKER_PRINCIPAL` —
    kept in settings so the deploy can set a different value
    (e.g. `tenant-baker-prod`) without code churn.
    """

    message = "only the tenant_bake worker principal may call this endpoint"

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if not isinstance(user, ServiceClient):
            return False
        # P2: a root/worker grant is a CROSS-TENANT power, so the
        # principal must ALSO carry the explicit operator scope. Without
        # this a tenant-scoped client that happens to be named the
        # configured root principal would inherit fleet-wide authority
        # from a name match alone.
        if not user.is_operator_principal:
            return False
        principal = getattr(settings, "VALI_TENANT_BAKE_WORKER_PRINCIPAL", None)
        if not principal:
            return False
        return user.name == principal
