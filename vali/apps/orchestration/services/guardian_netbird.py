"""Customer-held keys — the NetBird side of a tenant's key guardian.

Design §1.1 finding 1 / §5.5: at unlock the guest reaches its customer's
guardian through a miner-agent vsock relay, and the relay dials the
guardian's NetBird address. So the guardian joins Hippius' NetBird as a
peer, and a narrow policy lets the miners reach ONLY the guardian port:

- group  `hippius-guardian-<tenant>` — the tenant's guardian peer(s), and
  nothing else (a guardian enrols with a setup key minted here, whose
  `auto_groups` is exactly that group);
- policy `hippius-guardian-<tenant>` — ONE rule: miners group →
  guardian group, TCP, the guardian port only, one-way (the guardian gets
  no route back into the miners);
- setup keys `hippius-guardian-<tenant>` — one-off, persistent peer.

OPERATOR surface only (HARD RULE: no tenant API in hippius-compute): the
backend calls it with its operator token and hands the key to its tenant.
Hippius never calls the guardian; the channel through the relay is
authenticated end to end at the application layer, so NetBird (and the
miner) can only drop traffic.

Every write goes through the existing NetBird client in `effects`
(`_netbird_call` / `_netbird_list` / `_ensure_group`) and its id checks.
`ensure_policy` and `revoke` are idempotent; each `mint_setup_key` is a
fresh one-off key (an unused one expires on its own).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings

from apps.orchestration import effects
from apps.orchestration.effects import EffectError

#: Prefix of every NetBird object this module owns.
GUARDIAN_PREFIX = "hippius-guardian-"
#: What a tenant id may be to name NetBird objects after it.
_TENANT_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
#: NetBird's built-in group every peer belongs to.
_NETBIRD_ALL_GROUP = "All"
#: Setup-key lifetime bounds (seconds).
MIN_KEY_TTL_S = 60
MAX_KEY_TTL_S = 7 * 86400
DEFAULT_KEY_TTL_S = 86400


class GuardianNetbirdError(Exception):
    """A refusal with a stable `code` the view maps to a status."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class GuardianAccess:
    """The tenant's guardian group and the policy that opens it to miners."""

    tenant_id: str
    group: str
    group_id: str
    policy: str
    policy_id: str
    port: int


@dataclass(frozen=True)
class GuardianSetupKey:
    access: GuardianAccess
    key_id: str
    expires_in_s: int
    #: §20 secret: returned to the operator caller once, never stored.
    key: str = field(repr=False)


def object_name(tenant_id: str) -> str:
    """The group / policy / setup-key name for `tenant_id`."""
    return f"{GUARDIAN_PREFIX}{tenant_id}"


def check_tenant_id(tenant_id: Any) -> str:
    if not isinstance(tenant_id, str) or not _TENANT_ID_RE.fullmatch(tenant_id):
        raise GuardianNetbirdError("bad-request", "tenant_id must match [A-Za-z0-9._-]{1,64}")
    return tenant_id


def check_port(port: Any) -> int:
    if port is None:
        port = int(getattr(settings, "VALI_GUARDIAN_DEFAULT_PORT", 7443))
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise GuardianNetbirdError("bad-request", "port must be an integer in 1..65535")
    return port


def check_ttl(ttl_s: Any) -> int:
    if ttl_s is None:
        return DEFAULT_KEY_TTL_S
    if isinstance(ttl_s, bool) or not isinstance(ttl_s, int):
        raise GuardianNetbirdError("bad-request", "ttl_s must be an integer")
    if not MIN_KEY_TTL_S <= ttl_s <= MAX_KEY_TTL_S:
        raise GuardianNetbirdError(
            "bad-request", f"ttl_s must be in {MIN_KEY_TTL_S}..{MAX_KEY_TTL_S}"
        )
    return ttl_s


def _miners_group_id(groups: list[dict[str, Any]]) -> str:
    """The id of the group every miner's NetBird peer is in
    (`VALI_NETBIRD_MINERS_GROUP`, a name or an id). Unconfigured or absent
    is a deployment fault, never a guess."""
    configured = str(getattr(settings, "VALI_NETBIRD_MINERS_GROUP", "") or "").strip()
    if not configured:
        raise GuardianNetbirdError(
            "guardian-netbird-misconfigured", "VALI_NETBIRD_MINERS_GROUP is not configured"
        )
    for g in groups:
        if configured in (g.get("name"), g.get("id")):
            return effects._require_netbird_id(str(g.get("id") or ""), label="netbird:miners")
    raise GuardianNetbirdError(
        "guardian-netbird-misconfigured",
        f"the miners group {configured!r} does not exist in NetBird",
    )


def _policy_body(name: str, tenant_id: str, miners_id: str, group_id: str, port: int):
    return {
        "name": name,
        "description": f"miners -> key guardian of tenant {tenant_id}, tcp/{port} only",
        "enabled": True,
        "rules": [
            {
                "name": name,
                "description": "",
                "enabled": True,
                "action": "accept",
                # One-way: a miner opens the connection; the guardian gets
                # no route back into the miners group.
                "bidirectional": False,
                "protocol": "tcp",
                "ports": [str(port)],
                "sources": [miners_id],
                "destinations": [group_id],
            }
        ],
    }


def _policy_matches(policy: dict[str, Any], miners_id: str, group_id: str, port: int) -> bool:
    rules = policy.get("rules") or []
    if not policy.get("enabled") or len(rules) != 1 or not isinstance(rules[0], dict):
        return False
    rule = rules[0]
    return (
        bool(rule.get("enabled"))
        and rule.get("action") == "accept"
        and not rule.get("bidirectional")
        and rule.get("protocol") == "tcp"
        and [str(p) for p in rule.get("ports") or []] == [str(port)]
        and not rule.get("port_ranges")
        and effects._ids(rule.get("sources")) == [miners_id]
        and effects._ids(rule.get("destinations")) == [group_id]
        and not rule.get("sourceResource")
        and not rule.get("destinationResource")
    )


def _opening_policies(policies: list[dict[str, Any]], own: str, reachable: set[str]) -> list[str]:
    """Names of the ENABLED policies, other than `own`, with an enabled rule
    that lets something reach a group in `reachable` (NetBird's `All`, which
    every guardian peer is in, and the guardian group itself): as a
    destination, or as either side of a bidirectional rule."""
    out: list[str] = []
    for p in policies:
        if p.get("name") == own or not p.get("enabled"):
            continue
        for rule in p.get("rules") or []:
            if not isinstance(rule, dict) or not rule.get("enabled"):
                continue
            ends = set(effects._ids(rule.get("destinations")))
            if rule.get("bidirectional"):
                ends |= set(effects._ids(rule.get("sources")))
            if ends & reachable:
                out.append(str(p.get("name") or p.get("id") or "?"))
                break
    return out


def ensure_policy(tenant_id: str, port: int) -> GuardianAccess:
    """Make the tenant's guardian group and its `miners → guardian:port`
    policy exist and match (created, or rewritten when it drifted).
    Idempotent. Raises `GuardianNetbirdError`, `EffectUnavailable`,
    `EffectError`.

    "Miners reach the guardian port and nothing else does" also needs the
    REST of the NetBird account to cooperate: NetBird's `Default` policy
    (All ↔ All) must be disabled, and `VALI_NETBIRD_MINERS_GROUP` must hold
    only miners. The first is checked here: any other enabled policy whose
    rule reaches `All` or the guardian group refuses
    (`guardian-netbird-open-policy`) before anything is written. The second
    is the operator's (runbook: docs/operator/launching-a-vm.md)."""
    name = object_name(check_tenant_id(tenant_id))
    port = check_port(port)
    groups = effects._netbird_list("/api/groups", label="netbird:list-groups")
    miners_id = _miners_group_id(groups)
    policies = effects._netbird_list("/api/policies", label="netbird:list-policies")
    reachable = {
        str(g.get("id"))
        for g in groups
        if g.get("name") in (_NETBIRD_ALL_GROUP, name) and g.get("id")
    }
    opening = _opening_policies(policies, name, reachable)
    if opening:
        raise GuardianNetbirdError(
            "guardian-netbird-open-policy",
            f"enabled NetBird policies {sorted(opening)} let peers reach the `All` group "
            f"(which every guardian is in) or {name!r}: disable them (NetBird's `Default` "
            "All<->All policy first) so miners -> guardian:port is the only way in",
        )
    group = effects._ensure_group(groups, name, peers=None)
    group_id = effects._require_netbird_id(str(group.get("id") or ""), label="netbird:guardian")
    body = _policy_body(name, tenant_id, miners_id, group_id, port)
    policy = next((p for p in policies if p.get("name") == name), None)
    if policy is None:
        created = effects._netbird_call(
            "POST", "/api/policies", label="netbird:create-policy", body=body
        )
        policy_id = effects._created_id(created, label="netbird:create-policy")
    else:
        policy_id = effects._require_netbird_id(
            str(policy.get("id") or ""), label="netbird:update-policy"
        )
        if not _policy_matches(policy, miners_id, group_id, port):
            effects._netbird_call(
                "PUT", f"/api/policies/{policy_id}", label="netbird:update-policy", body=body
            )
    return GuardianAccess(
        tenant_id=tenant_id,
        group=name,
        group_id=group_id,
        policy=name,
        policy_id=policy_id,
        port=port,
    )


def mint_setup_key(tenant_id: str, port: int, ttl_s: int) -> GuardianSetupKey:
    """Ensure the access (`ensure_policy`), then mint a one-off setup key
    whose peer joins ONLY the tenant's guardian group. The peer is
    persistent (a guardian must survive its host's downtime); `revoke`
    deletes it."""
    access = ensure_policy(tenant_id, port)
    ttl_s = check_ttl(ttl_s)
    body = {
        "name": access.group,
        "type": "one-off",
        "expires_in": ttl_s,
        "usage_limit": 1,
        "auto_groups": [access.group_id],
        "revoked": False,
        "ephemeral": False,
        "description": f"hippius key guardian of tenant_id={tenant_id}",
    }
    parsed = effects._netbird_call(
        "POST", "/api/setup-keys", label="netbird:mint-guardian-key", body=body
    )
    if not isinstance(parsed, dict):
        raise EffectError("netbird:mint-guardian-key: response is not a JSON object")
    key = parsed.get("key")
    if not isinstance(key, str) or not key:
        raise EffectError("netbird:mint-guardian-key: response missing 'key'")
    key_id = effects._created_id(parsed, label="netbird:mint-guardian-key")
    return GuardianSetupKey(access=access, key_id=key_id, expires_in_s=ttl_s, key=key)


def revoke(tenant_id: str) -> list[str]:
    """Take the tenant's guardian off the mesh: the policy (miners lose the
    route), its setup keys, its peers, then the group. Idempotent: what is
    already gone is skipped. Returns what was deleted, as `kind/name-or-id`.

    Refuses (`guardian-peer-shared`, nothing deleted) when a peer in the
    guardian group also belongs to any other group but NetBird's `All`: only
    keys minted here join that group, so such a peer was put there by hand
    and is not ours to delete."""
    name = object_name(check_tenant_id(tenant_id))
    groups = effects._netbird_list("/api/groups", label="netbird:list-groups")
    group = next((g for g in groups if g.get("name") == name), None)
    peer_ids: list[str] = []
    if group is not None:
        for peer_id in effects._ids(group.get("peers")):
            effects._require_netbird_id(peer_id, label="netbird:guardian-peer")
            peer = effects._netbird_call("GET", f"/api/peers/{peer_id}", label="netbird:peer")
            others = {
                str(g.get("name") if isinstance(g, dict) else g)
                for g in ((peer or {}).get("groups") or [])
            } - {name, _NETBIRD_ALL_GROUP}
            if others:
                raise GuardianNetbirdError(
                    "guardian-peer-shared",
                    f"peer {peer_id} is also in {sorted(others)}; remove it from "
                    f"{name!r} by hand first",
                )
            peer_ids.append(peer_id)

    deleted: list[str] = []
    for policy in effects._netbird_list("/api/policies", label="netbird:list-policies"):
        if policy.get("name") == name:
            pid = effects._require_netbird_id(str(policy.get("id") or ""), label="netbird:gc")
            effects._netbird_call("DELETE", f"/api/policies/{pid}", label="netbird:delete-policy")
            deleted.append(f"policy/{name}")
    for key in effects._netbird_list("/api/setup-keys", label="netbird:list-setup-keys"):
        if key.get("name") == name:
            kid = effects._require_netbird_id(str(key.get("id") or ""), label="netbird:gc")
            effects._netbird_call(
                "DELETE", f"/api/setup-keys/{kid}", label="netbird:delete-setup-key"
            )
            deleted.append(f"setup-key/{kid}")
    for peer_id in peer_ids:
        effects._netbird_call("DELETE", f"/api/peers/{peer_id}", label="netbird:delete-peer")
        deleted.append(f"peer/{peer_id}")
    if group is not None:
        gid = effects._require_netbird_id(str(group.get("id") or ""), label="netbird:gc")
        effects._netbird_call("DELETE", f"/api/groups/{gid}", label="netbird:delete-group")
        deleted.append(f"group/{name}")
    return deleted
