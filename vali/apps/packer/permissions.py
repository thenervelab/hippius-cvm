"""Permission classes for the packer app.

`/finalize` is callable ONLY by the Packer Job worker — the
`ServiceClient` with `name == settings.VALI_PACKER_WORKER_PRINCIPAL`.
Every other authenticated client gets 403.

The rest of the endpoints are gated on plain `IsAuthenticated` —
any registered `ServiceClient` can trigger a build / query its
state / presign a download URL.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


class IsPackerWorker(BasePermission):
    """Allow only the configured Packer Job principal.

    `request.user` after authentication is a `ServiceClient`; we
    compare its `name` against the locked principal. The principal
    name comes from `settings.VALI_PACKER_WORKER_PRINCIPAL` — kept
    in settings so the deploy can set a different value (e.g.
    `packer-job-prod`) without code churn.
    """

    message = "only the packer worker principal may call this endpoint"

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
        if not user.is_active:
            return False
        expected = getattr(settings, "VALI_PACKER_WORKER_PRINCIPAL", "")
        if not expected:
            # If the deploy hasn't pinned a worker principal, deny —
            # the endpoint is too sensitive to fall open. A clear
            # 403 surfaces the misconfiguration faster than silent
            # acceptance would.
            return False
        return user.name == expected
