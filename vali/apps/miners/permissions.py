"""Permission class for the miner-registry endpoints.

`POST /v1/admin/miner/register` and `POST /v1/admin/miner/<id>/quarantine`
mutate the trusted miner registry — they are operator actions, gated to
the single principal named by `settings.VALI_MINER_ADMIN_PRINCIPAL`.
`GET /v1/admin/miner/list` is read-only and open to any authenticated
`ServiceClient` (sentinel / ops), so it carries only `IsAuthenticated`.

vali has no scope system; this mirrors the established root-principal
pattern (`scheduler.IsRootClient`, `telemetry.IsTelemetryRoot`).
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


class IsMinerAdmin(BasePermission):
    """Allow only the configured miner-admin principal.

    Fails closed: if the deploy has not pinned a principal the endpoint
    denies — registering a miner identity establishes a trust anchor —
    and a clear 403 surfaces the misconfiguration fast.
    """

    message = "only the miner-admin principal may call this endpoint"

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
        # `.strip()` mirrors `vali_identity_seed_miner_admin`'s
        # normalisation: a Kubernetes ConfigMap or Secret mount can
        # introduce a trailing newline / whitespace; without symmetric
        # stripping the seed creates a `"miner-admin"` `ServiceClient`
        # while the permission check looks for `"miner-admin\n"` and
        # silently 403s every request — a painful misconfiguration to
        # debug. Both sides MUST strip the same way.
        expected = (getattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "") or "").strip()
        if not expected:
            return False
        return user.name == expected
