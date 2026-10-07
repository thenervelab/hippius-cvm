"""Who the CDN fleet is (docs/design/cdn.md): the internal tenant every CDN
node runs as, and whether the CDN role is on.

Every CDN rule that is not plain identity — one node per host, the
miner-side bandwidth exemption, launching the restricted cdn-node image —
applies only while `VALI_CDN_ENABLED` is on ([`cdn_role`]), so with the
flag off vali behaves as if the fleet did not exist.
"""

from __future__ import annotations

import re

from django.conf import settings

#: A bare https origin: scheme, lower-case host, optional port — no path,
#: no trailing slash (the cdn-agent appends `/api/cdn/node/...` itself, so
#: anything more would bake a double slash or a wrong prefix into the
#: measured image), no userinfo, query or fragment.
_BACKEND_ORIGIN_RE = re.compile(
    r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
    r"(?::[0-9]{1,5})?"
)


def cdn_backend_url() -> str:
    """`VALI_CDN_BACKEND_URL` when it is a bare https origin, else `""`. It is
    measured into every cdn-node image and named by every node's user-data,
    so anything else is refused rather than baked."""
    url = str(getattr(settings, "VALI_CDN_BACKEND_URL", "") or "")
    return url if _BACKEND_ORIGIN_RE.fullmatch(url) else ""


def cdn_enabled() -> bool:
    return bool(getattr(settings, "VALI_CDN_ENABLED", False))


def cdn_tenant_id() -> str:
    return str(getattr(settings, "VALI_CDN_TENANT_ID", "") or "").strip()


def is_cdn_tenant(tenant_id: str) -> bool:
    """`tenant_id` is the CDN fleet's (`VALI_CDN_TENANT_ID`), whatever the
    flag. A blank setting matches no tenant."""
    tenant = cdn_tenant_id()
    return bool(tenant) and tenant_id == tenant


def cdn_role(tenant_id: str) -> bool:
    """The CDN rules apply to `tenant_id`: it is the CDN tenant and
    `VALI_CDN_ENABLED` is on."""
    return cdn_enabled() and is_cdn_tenant(tenant_id)
