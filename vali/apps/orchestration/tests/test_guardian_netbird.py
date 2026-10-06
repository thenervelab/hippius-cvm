"""Customer-held keys — a tenant's key guardian on the NetBird mesh
(`services.guardian_netbird` + `guardian_views`), against an in-memory
NetBird management API behind `effects._netbird_call`."""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from django.conf import settings

from apps.orchestration import effects
from apps.orchestration.services import guardian_netbird as gn

pytestmark = pytest.mark.django_db

MINERS = "hippius-miners"


class FakeNetbird:
    """Groups, policies, setup keys and peers, keyed by id."""

    def __init__(self) -> None:
        self._ids = (f"id{n:04d}" for n in itertools.count(1))
        self.groups: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, dict[str, Any]] = {}
        self.peers: dict[str, dict[str, Any]] = {}
        self.writes: list[tuple[str, str]] = []
        self.unavailable = False
        self.add_group(MINERS, [])
        self.add_group("All", [])

    def add_group(self, name: str, peers: list[str]) -> str:
        gid = next(self._ids)
        self.groups[gid] = {"id": gid, "name": name, "peers": [{"id": p} for p in peers]}
        return gid

    def add_peer(self, groups: list[str]) -> str:
        pid = next(self._ids)
        self.peers[pid] = {"id": pid, "groups": [{"name": g} for g in groups]}
        for g in self.groups.values():
            if g["name"] in groups:
                g["peers"].append({"id": pid})
        return pid

    def call(self, method: str, path: str, *, label: str, body: Any = None) -> Any:
        if self.unavailable:
            raise effects.EffectUnavailable(f"{label}: unreachable (test)")
        if method != "GET":
            self.writes.append((method, path))
        parts = path.strip("/").split("/")  # api, kind, [id]
        kind = parts[1]
        store = {
            "groups": self.groups,
            "policies": self.policies,
            "setup-keys": self.keys,
            "peers": self.peers,
        }[kind]
        if method == "GET" and len(parts) == 2:
            return list(store.values())
        if method == "GET":
            return store[parts[2]]
        if method == "POST":
            oid = next(self._ids)
            obj = {"id": oid, **body}
            if kind == "groups":
                obj["peers"] = [{"id": p} for p in body.get("peers", [])]
            if kind == "setup-keys":
                obj["key"] = f"SECRET-{oid}"
            store[oid] = obj
            return obj
        if method == "PUT":
            store[parts[2]] = {"id": parts[2], **body}
            return store[parts[2]]
        if method == "DELETE":
            store.pop(parts[2])
            if kind == "peers":
                for g in self.groups.values():
                    g["peers"] = [p for p in g["peers"] if p["id"] != parts[2]]
            return None
        raise AssertionError(method)

    def named(self, store: dict[str, dict[str, Any]], name: str) -> list[dict[str, Any]]:
        return [o for o in store.values() if o.get("name") == name]


@pytest.fixture
def nb(monkeypatch: pytest.MonkeyPatch) -> FakeNetbird:
    fake = FakeNetbird()
    monkeypatch.setattr(effects, "_netbird_call", fake.call)
    monkeypatch.setattr(settings, "VALI_NETBIRD_MINERS_GROUP", MINERS)
    monkeypatch.setattr(settings, "VALI_CUSTOMER_KEYS_ENABLED", True)
    return fake


def _policy(nb: FakeNetbird, tenant: str = "t-1") -> dict[str, Any]:
    (p,) = nb.named(nb.policies, f"hippius-guardian-{tenant}")
    return p


def test_ensure_creates_a_one_rule_miners_to_guardian_port_policy(nb: FakeNetbird) -> None:
    access = gn.ensure_policy("t-1", 7443)
    (group,) = nb.named(nb.groups, "hippius-guardian-t-1")
    (miners,) = nb.named(nb.groups, MINERS)
    assert access.group_id == group["id"] and access.port == 7443
    (rule,) = _policy(nb)["rules"]
    assert rule["action"] == "accept" and rule["protocol"] == "tcp"
    assert rule["ports"] == ["7443"]
    assert rule["bidirectional"] is False
    assert rule["sources"] == [miners["id"]]
    assert rule["destinations"] == [group["id"]]
    assert _policy(nb)["enabled"] is True


def test_ensure_is_idempotent_and_repairs_drift(nb: FakeNetbird) -> None:
    gn.ensure_policy("t-1", 7443)
    writes = len(nb.writes)
    gn.ensure_policy("t-1", 7443)
    assert len(nb.writes) == writes  # nothing to do
    # a new port rewrites the rule, same objects
    gn.ensure_policy("t-1", 9000)
    assert _policy(nb)["rules"][0]["ports"] == ["9000"]
    assert len(nb.named(nb.groups, "hippius-guardian-t-1")) == 1
    assert len(nb.named(nb.policies, "hippius-guardian-t-1")) == 1


@pytest.mark.parametrize(
    "drift",
    [
        {"bidirectional": True},
        {"protocol": "all"},
        {"ports": ["7443", "22"]},
        {"port_ranges": [{"start": 1, "end": 65535}]},
        {"sources": ["someone-else"]},
        {"destinations": ["someone-else"]},
        {"action": "drop"},
        {"enabled": False},
    ],
)
def test_each_field_of_the_rule_is_repaired_on_drift(nb: FakeNetbird, drift) -> None:
    gn.ensure_policy("t-1", 7443)
    want = dict(_policy(nb)["rules"][0])
    _policy(nb)["rules"][0].update(drift)
    gn.ensure_policy("t-1", 7443)
    assert _policy(nb)["rules"][0] == want


def _other_policy(nb: FakeNetbird, *, src: str, dst: str, **kw: Any) -> None:
    gid = {g["name"]: g["id"] for g in nb.groups.values()}
    rule = {
        "enabled": kw.pop("rule_enabled", True),
        "bidirectional": kw.pop("bidirectional", True),
        "sources": [gid.get(src, src)],
        "destinations": [gid.get(dst, dst)],
    }
    pid = f"pol-{len(nb.policies)}"
    nb.policies[pid] = {
        "id": pid,
        "name": kw.pop("name", "Default"),
        "enabled": kw.pop("enabled", True),
        "rules": [rule],
    }


@pytest.mark.parametrize(
    "policy",
    [
        {"src": "All", "dst": "All"},  # NetBird's Default
        {"src": "vms", "dst": "All", "bidirectional": False},
        {"src": "All", "dst": "vms"},  # bidirectional: vms reach All
        {"src": "vms", "dst": "hippius-guardian-t-1", "bidirectional": False},
    ],
)
def test_an_enabled_policy_that_reaches_the_guardian_refuses_the_ensure(
    nb: FakeNetbird, policy: dict[str, Any]
) -> None:
    nb.add_group("vms", [])
    if "guardian" in policy["dst"]:
        nb.add_group("hippius-guardian-t-1", [])
    _other_policy(nb, **policy)
    writes = len(nb.writes)
    with pytest.raises(gn.GuardianNetbirdError) as exc:
        gn.mint_setup_key("t-1", 7443, 3600)
    assert exc.value.code == "guardian-netbird-open-policy"
    assert "Default" in exc.value.message
    assert len(nb.writes) == writes  # nothing created, no key minted


@pytest.mark.parametrize(
    "policy",
    [
        {"src": "All", "dst": "All", "enabled": False},  # Default disabled
        {"src": "All", "dst": "All", "rule_enabled": False},
        {"src": "All", "dst": "vms", "bidirectional": False},  # one-way, away from All
        {"src": "vms", "dst": MINERS},
    ],
)
def test_policies_that_do_not_reach_the_guardian_are_fine(
    nb: FakeNetbird, policy: dict[str, Any]
) -> None:
    nb.add_group("vms", [])
    _other_policy(nb, **policy)
    gn.ensure_policy("t-1", 7443)
    assert _policy(nb)["rules"][0]["ports"] == ["7443"]


def test_the_open_policy_refusal_is_a_409(nb: FakeNetbird, monkeypatch) -> None:
    api = _api(monkeypatch)
    _other_policy(nb, src="All", dst="All")
    resp = api.put("/v1/guardian/t-9/netbird/policy", {}, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "guardian-netbird-open-policy"


def test_the_setup_key_joins_only_the_guardian_group(nb: FakeNetbird) -> None:
    minted = gn.mint_setup_key("t-1", 7443, 3600)
    (key,) = nb.named(nb.keys, "hippius-guardian-t-1")
    assert minted.key == key["key"] and minted.key_id == key["id"]
    assert key["auto_groups"] == [minted.access.group_id]
    assert key["type"] == "one-off" and key["usage_limit"] == 1
    assert key["ephemeral"] is False and key["expires_in"] == 3600
    assert "SECRET" not in repr(minted)


def test_revoke_removes_policy_keys_peers_and_group_and_is_idempotent(nb: FakeNetbird) -> None:
    minted = gn.mint_setup_key("t-1", 7443, 3600)
    gname = "hippius-guardian-t-1"
    peer = nb.add_peer([gname, "All"])
    other_tenant = gn.mint_setup_key("t-2", 7443, 3600)
    deleted = gn.revoke("t-1")
    assert deleted == [
        f"policy/{gname}",
        f"setup-key/{minted.key_id}",
        f"peer/{peer}",
        f"group/{gname}",
    ]
    assert not nb.named(nb.groups, gname) and peer not in nb.peers
    # the other tenant's guardian is untouched, the miners group too
    assert nb.named(nb.groups, "hippius-guardian-t-2")
    assert other_tenant.key_id in nb.keys
    assert nb.named(nb.groups, MINERS)
    assert gn.revoke("t-1") == []


def test_revoke_refuses_a_peer_that_is_also_elsewhere(nb: FakeNetbird) -> None:
    gn.ensure_policy("t-1", 7443)
    peer = nb.add_peer(["hippius-guardian-t-1", "vms"])
    writes = len(nb.writes)
    with pytest.raises(gn.GuardianNetbirdError) as exc:
        gn.revoke("t-1")
    assert exc.value.code == "guardian-peer-shared"
    assert len(nb.writes) == writes and peer in nb.peers


@pytest.mark.parametrize("configured", ["", "no-such-group"])
def test_an_unknown_miners_group_is_a_misconfiguration(
    nb: FakeNetbird, monkeypatch, configured: str
) -> None:
    monkeypatch.setattr(settings, "VALI_NETBIRD_MINERS_GROUP", configured)
    with pytest.raises(gn.GuardianNetbirdError) as exc:
        gn.ensure_policy("t-1", 7443)
    assert exc.value.code == "guardian-netbird-misconfigured"
    assert nb.writes == []


@pytest.mark.parametrize("tenant", ["", "a/b", "a b", "x" * 65, "t\n", None])
def test_a_bad_tenant_id_is_refused(nb: FakeNetbird, tenant: Any) -> None:
    with pytest.raises(gn.GuardianNetbirdError):
        gn.ensure_policy(tenant, 7443)
    with pytest.raises(gn.GuardianNetbirdError):
        gn.revoke(tenant)
    assert nb.writes == []


@pytest.mark.parametrize("port", [0, 65536, -1, True, "7443"])
def test_a_bad_port_is_refused(port: Any) -> None:
    with pytest.raises(gn.GuardianNetbirdError):
        gn.check_port(port)


@pytest.mark.parametrize("ttl", [59, 7 * 86400 + 1, True, "60"])
def test_a_bad_ttl_is_refused(ttl: Any) -> None:
    with pytest.raises(gn.GuardianNetbirdError):
        gn.check_ttl(ttl)


# ── the API ──────────────────────────────────────────────────────────


def _api(monkeypatch):
    from apps.backup.tests.conftest import ROOT, _bearer
    from apps.identity.models import PrincipalScope

    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT)
    return _bearer(ROOT, PrincipalScope.OPERATOR.value)


def test_the_operator_routes(nb: FakeNetbird, monkeypatch) -> None:
    api = _api(monkeypatch)
    resp = api.post("/v1/guardian/t-9/netbird/setup-key", {"ttl_s": 600}, format="json")
    assert resp.status_code == 201, resp.json()
    body = resp.json()
    assert body["setup_key"].startswith("SECRET-") and body["port"] == 7443
    assert body["group"] == "hippius-guardian-t-9" and body["expires_in_s"] == 600
    resp = api.put("/v1/guardian/t-9/netbird/policy", {"port": 8443}, format="json")
    assert resp.status_code == 200 and resp.json()["port"] == 8443
    resp = api.post("/v1/guardian/t-9/netbird/setup-key", {"nope": 1}, format="json")
    assert resp.status_code == 400 and resp.json()["error"] == "bad-request"
    resp = api.delete("/v1/guardian/t-9/netbird")
    assert resp.status_code == 200 and "group/hippius-guardian-t-9" in resp.json()["deleted"]


def test_minting_needs_the_flag_but_revoking_does_not(nb: FakeNetbird, monkeypatch) -> None:
    api = _api(monkeypatch)
    monkeypatch.setattr(settings, "VALI_CUSTOMER_KEYS_ENABLED", False)
    resp = api.post("/v1/guardian/t-9/netbird/setup-key", {}, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "customer-keys-disabled"
    resp = api.put("/v1/guardian/t-9/netbird/policy", {}, format="json")
    assert resp.status_code == 409
    assert nb.writes == []
    assert api.delete("/v1/guardian/t-9/netbird").status_code == 200


def test_netbird_down_is_a_503(nb: FakeNetbird, monkeypatch) -> None:
    api = _api(monkeypatch)
    nb.unavailable = True
    resp = api.put("/v1/guardian/t-9/netbird/policy", {}, format="json")
    assert resp.status_code == 503 and resp.json()["error"] == "netbird-unavailable"


def test_a_non_root_principal_is_refused(nb: FakeNetbird, monkeypatch) -> None:
    from apps.backup.tests.conftest import _bearer
    from apps.identity.models import PrincipalScope

    _api(monkeypatch)
    other = _bearer("someone-else", PrincipalScope.OPERATOR.value)
    assert other.delete("/v1/guardian/t-9/netbird").status_code == 403
    tenant = _bearer("tenant-x", PrincipalScope.TENANT.value, tenant_id="t-9")
    assert tenant.post("/v1/guardian/t-9/netbird/setup-key", {}, format="json").status_code == 403
    assert nb.writes == []
