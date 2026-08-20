"""Permission classes for the scheduler app.

`POST /v1/scheduler/place` is callable by any authenticated
`ServiceClient` (the L1 minter / orchestrator triggers placement).

`POST /v1/scheduler/<vm_id>/bind` and `.../fail` are **root-only** —
they are operator actions that finalize or tear down a placement
(§23: "Slashing/quarantine is performed by the authoritative
validator (us) … an operator action"). They are gated to the single
principal named by `settings.VALI_SCHEDULER_ROOT_PRINCIPAL`.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


class IsRootClient(BasePermission):
    """Allow only the configured scheduler-root principal.

    `request.user` after authentication is a `ServiceClient`; its
    `name` must equal `settings.VALI_SCHEDULER_ROOT_PRINCIPAL`. If
    the deploy has not pinned a root principal the endpoint **fails
    closed** (denies) — bind/fail are too sensitive to fall open,
    and a clear 403 surfaces the misconfiguration fast.
    """

    message = "only the scheduler root principal may call this endpoint"

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
        expected = getattr(settings, "VALI_SCHEDULER_ROOT_PRINCIPAL", "")
        if not expected:
            return False
        return user.name == expected
