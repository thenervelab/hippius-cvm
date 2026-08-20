"""Permission class for the orchestration app.

`POST /v1/vm/<id>/migrate` and `POST /v1/vm/<id>/decommission` are
**root-only** — they are operator actions that move a tenant VM
across miners or cryptographically destroy it (§24/§25). They are
gated to the single principal named by
`settings.VALI_ORCHESTRATION_ROOT_PRINCIPAL`.

The `GET .../<job_id>` poll endpoints are plain `IsAuthenticated` —
any registered `ServiceClient` may observe a job's progress.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


class IsOrchestrationRoot(BasePermission):
    """Allow only the configured orchestration-root principal.

    Fails closed: if the deploy has not pinned a root principal the
    endpoint denies (a §24/§25 orchestration trigger is far too
    sensitive to fall open), and a clear 403 surfaces the
    misconfiguration.
    """

    message = "only the orchestration root principal may call this endpoint"

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
        expected = getattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", "")
        if not expected:
            return False
        return user.name == expected
