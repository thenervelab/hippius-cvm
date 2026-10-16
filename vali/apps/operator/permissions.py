"""`IsOperatorConfigWriter` — who may change a miner's configuration
through `/v1/operator/*` (the providers dashboard's writes, design
disk-tier-verification §9).

The reads under `/v1/operator/*` take any operator-scoped principal. A
write needs a principal named in `VALI_OPERATOR_CONFIG_PRINCIPALS`: the
backend calls with a DEDICATED token (`VALI_OPERATOR_CONFIG_TOKEN` on its
side), not the read token, so leaking the read token changes nothing.
Minted like any vali credential:

    manage.py vali_identity_issue_token --client backend-operator-config \\
        --token-name prod-2026q4 --operator --lifetime service

then `VALI_OPERATOR_CONFIG_PRINCIPALS=backend-operator-config`.

Fails closed: an empty allowlist denies every write. The per-family check
(`X-Hippius-Acting-Family` re-checked on chain) comes on top, in the view.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient


def config_writer_principals() -> frozenset[str]:
    # `.strip()` like `IsMinerAdmin`: a mounted value may carry a newline.
    raw = getattr(settings, "VALI_OPERATOR_CONFIG_PRINCIPALS", []) or []
    return frozenset(p.strip() for p in raw if p.strip())


class IsOperatorConfigWriter(BasePermission):
    """Allow only an active, operator-scoped principal named in
    `VALI_OPERATOR_CONFIG_PRINCIPALS`."""

    message = "only an operator-config principal may change a miner's configuration"

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if not isinstance(user, ServiceClient):
            return False
        if not user.is_operator_principal or not user.is_active:
            return False
        return user.name in config_writer_principals()
