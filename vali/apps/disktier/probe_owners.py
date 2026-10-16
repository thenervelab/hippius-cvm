"""The disk-probe identities (`VALI_DISK_PROBE_OWNERS`, design §2).

A probe VM must look like a tenant's, so it runs under operator-created,
backend-shaped accounts: a numeric backend user id (what `Placement.owner`
holds) and an SS58 tenant id. Each entry is `user_id:tenant_id`.

Three readers, one parse:

- the orchestrator picks an owner per run (`apps.disktier.probe`);
- `scheduler.scoring._excluded_owners` keeps every probe user id out of
  rewards and billing, as it does the synthetic monitor's tenant;
- the launch intake refuses either id from any caller but the
  orchestrator (`disk-probe-id-reserved`).

Settings only: no database, safe to import anywhere."""

from __future__ import annotations

import re
from dataclasses import dataclass

from django.conf import settings

# The user id lands in a vm id (`hipc-<user_id>-<8 hex>`, `[a-z0-9-]{1,64}`).
_USER_RE = re.compile(r"[0-9]{1,20}")
# An SS58 account (base58, no `0OIl`).
_TENANT_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,64}")


@dataclass(frozen=True)
class ProbeOwner:
    user_id: str
    tenant_id: str


class ProbeOwnerConfigError(ValueError):
    pass


def probe_owners() -> tuple[ProbeOwner, ...]:
    """The configured probe identities. Raises `ProbeOwnerConfigError` on a
    malformed entry: a typo must not silently drop an id out of the reward
    exclusion."""
    raw = getattr(settings, "VALI_DISK_PROBE_OWNERS", ()) or ()
    if isinstance(raw, str):
        raw = [raw]
    out: list[ProbeOwner] = []
    for entry in raw:
        user, sep, tenant = str(entry).strip().partition(":")
        if not sep or not _USER_RE.fullmatch(user) or not _TENANT_RE.fullmatch(tenant):
            raise ProbeOwnerConfigError(
                f"VALI_DISK_PROBE_OWNERS entry {entry!r} is not `<numeric user id>:<SS58 tenant>`"
            )
        out.append(ProbeOwner(user_id=user, tenant_id=tenant))
    return tuple(out)


def probe_user_ids() -> frozenset[str]:
    return frozenset(o.user_id for o in probe_owners())


def probe_tenant_ids() -> frozenset[str]:
    return frozenset(o.tenant_id for o in probe_owners())
