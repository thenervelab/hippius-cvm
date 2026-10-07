"""The `net-policy` order: body, caps, revision rules, ack, flags, the
placement gate (`apps.network.net_policy`)."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings
from django.core.management import call_command
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.network import net_policy
from apps.network.models import EgressRegion, MinerNetPolicy, PublicIP, PublicIpState
from apps.orchestration import order_dispatch
from apps.orchestration.order_dispatch import DispatchResult
from apps.orchestration.tests.factories import make_service_client
from apps.scheduler.tests.factories import make_dispatchable_identity

from .conftest import make_edge, make_vm

pytestmark = pytest.mark.django_db


def _fake_digest(payload_json: bytes) -> str:
    # Same shape as the real one: everything but the expiry.
    body = json.loads(payload_json)
    body.pop("not_after_unix")
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


@dataclass
class FakeMiner:
    """The miner-agent's net-policy store (C1): refuses a lower revision
    and the same revision with other content, acks
    `applied:<revision>:<sha>`."""

    revision: int = 0
    sha: str = ""
    sent: list[dict[str, Any]] = field(default_factory=list)
    order_ids: list[str] = field(default_factory=list)
    #: Next answers to give instead of the real one, `(status, classifier)`.
    script: list[tuple[int, str]] = field(default_factory=list)
    unreachable: bool = False

    def __call__(self, **kw: Any) -> DispatchResult:
        assert kw["kind"] == "net-policy"
        if self.unreachable:
            raise order_dispatch.OrderDispatchUnavailable("edge-order: peer unreachable")
        body = json.loads(kw["payload_json"])
        self.sent.append(body)
        self.order_ids.append(kw["order_id"])
        if self.script:
            status, cls = self.script.pop(0)
            return DispatchResult(ok=200 <= status < 300, status=status, classifier=cls)
        sha = _fake_digest(kw["payload_json"])
        rev = body["revision"]
        if rev < self.revision:
            return DispatchResult(ok=False, status=409, classifier="net-policy-stale-revision")
        if rev == self.revision and sha != self.sha:
            return DispatchResult(ok=False, status=409, classifier="net-policy-revision-conflict")
        self.revision, self.sha = rev, sha
        return DispatchResult(ok=True, status=200, classifier=f"applied:{rev}:{sha}")


@pytest.fixture
def miner_agent(monkeypatch: pytest.MonkeyPatch) -> FakeMiner:
    fake = FakeMiner()
    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", fake)
    monkeypatch.setattr(order_dispatch, "net_policy_digest", _fake_digest)
    return fake


@pytest.fixture(autouse=True)
def _defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_NET_POLICY_PUSH", True)
    monkeypatch.setattr(settings, "VALI_NET_POLICY_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_NET_POLICY_LOCAL_ACTION", "count")
    monkeypatch.setattr(settings, "VALI_NET_POLICY_INFRA", [])
    monkeypatch.setattr(settings, "VALI_NET_POLICY_NB_CONTROL", [])


def _miner(seed: int, country: str = "FR", ip: str = "") -> MinerIdentity:
    miner = make_dispatchable_identity(seed)
    MinerLocation.objects.create(
        miner=miner,
        connection_ip=ip or f"192.0.2.{100 + seed}",
        country_code=country,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now(),
    )
    return MinerIdentity.objects.select_related("location").get(pk=miner.pk)


def _flavor(vm_id: str, flavor: str) -> None:
    from apps.orchestration.models import LaunchJob

    LaunchJob.objects.create(
        job_id=f"j-{vm_id}-{flavor}",
        vm_id=vm_id,
        tenant_id="t",
        flavor=flavor,
        spec_json={"vm_id": vm_id, "flavor": flavor},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state="succeeded",
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )


def _vm(vm_id: str, host: str, flavor: str = "small", **kw: Any) -> None:
    make_vm(vm_id, host=host, region="", **kw)
    _flavor(vm_id, flavor)


def _attach_ip(vm_id: str, *, smtp_allowed: bool = False) -> None:
    n = PublicIP.objects.count() + 1
    edge = make_edge(f"edge-np-{n}", addresses=(f"198.100.1.{n}",))
    from apps.lifecycle.models import Vm

    PublicIP.objects.filter(edge=edge).update(
        vm=Vm.objects.get(vm_id=vm_id), state=PublicIpState.ATTACHED, smtp_allowed=smtp_allowed
    )


def _row(miner: MinerIdentity) -> MinerNetPolicy:
    return MinerNetPolicy.objects.get(miner=miner)


# ─── caps ────────────────────────────────────────────────────────────


def test_the_cap_table_by_flavor() -> None:
    assert net_policy.flavor_cap_mbps("small") == 100
    assert net_policy.flavor_cap_mbps("medium") == 250
    assert net_policy.flavor_cap_mbps("large") == 500
    for big in ("xlarge", "2xlarge", "4xlarge"):
        assert net_policy.flavor_cap_mbps(big) == 500
    # Runners follow their base flavor; anything unknown gets the default.
    assert net_policy.flavor_cap_mbps("runner-medium") == 250
    assert net_policy.flavor_cap_mbps("runner-large") == 500
    assert net_policy.flavor_cap_mbps("") == 100
    assert net_policy.flavor_cap_mbps("nonsense") == 100


def test_the_cap_table_is_a_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_NET_CAP_MBPS_BY_FLAVOR", {"small": 50, "xlarge": 1000})
    monkeypatch.setattr(settings, "VALI_NET_CAP_DEFAULT_MBPS", 75)
    assert net_policy.flavor_cap_mbps("small") == 50
    assert net_policy.flavor_cap_mbps("runner-small") == 50
    assert net_policy.flavor_cap_mbps("xlarge") == 1000
    assert net_policy.flavor_cap_mbps("medium") == 75


def test_a_public_ip_raises_the_cap_to_its_floor_only() -> None:
    assert net_policy.effective_cap_mbps("small", has_public_ip=True) == 250
    assert net_policy.effective_cap_mbps("small", has_public_ip=False) == 100
    assert net_policy.effective_cap_mbps("large", has_public_ip=True) == 500


def test_edge_mode_leaves_room_for_the_tunnel() -> None:
    assert net_policy.miner_cap_mbps(100, "local") == 100
    assert net_policy.miner_cap_mbps(100, "edge") == 110
    assert net_policy.miner_cap_mbps(255, "edge") == 281  # rounded up


# ─── body ────────────────────────────────────────────────────────────


def test_the_local_body_carries_caps_and_port_25_exemptions() -> None:
    miner = _miner(1)
    _vm("vm-small", miner.miner_id, "small")
    _vm("vm-medium", miner.miner_id, "medium")
    _vm("vm-ip", miner.miner_id, "small")
    _attach_ip("vm-ip")
    _vm("vm-smtp", miner.miner_id, "small")
    _attach_ip("vm-smtp", smtp_allowed=True)
    _vm("vm-in", "other-miner", "large")
    from apps.lifecycle.models import Vm

    Vm.objects.filter(vm_id="vm-in").update(
        state=VmState.MIGRATING, migration_dest=miner.miner_id, new_generation=2
    )
    _vm("vm-gone", miner.miner_id, "large", state=VmState.DESTROYED)
    _vm("vm-elsewhere", "other-miner", "large")

    body = net_policy.build_content(miner, "FR")
    assert body == {
        "region": "FR",
        "mode": "local",
        "enforce": False,
        "local_action": "count",
        "infra": [],
        "region_miners": [],
        "nb_control": [],
        "dns_limit_pps": 20,
        # A public IP alone does not open port 25; an unblock does.
        "smtp_allowed_vms": ["vm-smtp"],
        "vm_caps": {
            "vm-in": 500,
            "vm-ip": 250,
            "vm-medium": 250,
            "vm-small": 100,
            "vm-smtp": 250,
        },
    }
    assert net_policy.content_key(body) == net_policy.content_key(
        net_policy.build_content(miner, "FR")
    )


def test_the_edge_body_lists_the_allowed_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    miner = _miner(1, "AU", ip="51.1.1.1")
    _miner(2, "AU", ip="51.1.1.2")
    _miner(3, "FR", ip="51.1.1.3")
    _vm("vm-a", miner.miner_id, "small")
    EgressRegion.objects.create(region="AU", mode="edge", enforce=True)
    nb = [{"ip": "9.9.9.9", "proto": "tcp", "port": 443}]
    monkeypatch.setattr(settings, "VALI_NET_POLICY_NB_CONTROL", nb)
    monkeypatch.setattr(
        settings, "VALI_NET_POLICY_INFRA", [{"ip": "1.1.1.1", "proto": "udp", "port": 51820}]
    )
    body = net_policy.build_content(miner, "AU")
    assert body["mode"] == "edge" and body["enforce"] is True
    assert body["region_miners"] == ["51.1.1.1", "51.1.1.2"]
    assert body["nb_control"] == nb
    assert body["vm_caps"] == {"vm-a": 110}


def test_enforce_without_netbird_control_is_refused() -> None:
    miner = _miner(1, "AU")
    EgressRegion.objects.create(region="AU", mode="edge", enforce=True)
    with pytest.raises(net_policy.PolicyError, match="NB_CONTROL"):
        net_policy.build_content(miner, "AU")


def test_a_bad_endpoint_setting_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    miner = _miner(1, "AU")
    EgressRegion.objects.create(region="AU", mode="edge")
    for bad in (
        [{"ip": "10.0.0.1", "proto": "tcp", "port": 443}],
        [{"ip": "9.9.9.9", "proto": "icmp", "port": 443}],
        [{"ip": "9.9.9.9", "proto": "tcp", "port": 0}],
        [{"ip": "9.9.9.9", "proto": "tcp"}],
    ):
        monkeypatch.setattr(settings, "VALI_NET_POLICY_NB_CONTROL", bad)
        with pytest.raises(net_policy.PolicyError):
            net_policy.build_content(miner, "AU")


def test_the_public_ipv4_rule_matches_the_miner() -> None:
    assert net_policy.is_public_ipv4("1.1.1.1")
    for ip in ("010.0.0.1", "100.64.0.1", "192.88.99.2", "198.18.0.1", "224.0.0.1", "::1"):
        assert not net_policy.is_public_ipv4(ip), ip


# ─── reconcile ───────────────────────────────────────────────────────


def test_flag_off_sends_nothing(monkeypatch: pytest.MonkeyPatch, miner_agent: FakeMiner) -> None:
    monkeypatch.setattr(settings, "VALI_NET_POLICY_PUSH", False)
    _miner(1)
    report = net_policy.reconcile()
    assert not report.enabled
    assert miner_agent.sent == []
    assert not MinerNetPolicy.objects.exists()


def test_only_the_listed_miners_get_a_policy(
    monkeypatch: pytest.MonkeyPatch, miner_agent: FakeMiner
) -> None:
    canary, other = _miner(1), _miner(2)
    monkeypatch.setattr(settings, "VALI_NET_POLICY_MINERS", [])
    net_policy.reconcile()
    assert miner_agent.sent == []

    monkeypatch.setattr(settings, "VALI_NET_POLICY_MINERS", [canary.miner_id])
    net_policy.reconcile()
    assert len(miner_agent.sent) == 1
    assert _row(canary).acked_current
    assert not MinerNetPolicy.objects.filter(miner=other).exists()


def test_the_revision_moves_with_the_content_only(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    _vm("vm-a", miner.miner_id)
    t0 = timezone.now()

    net_policy.reconcile(now=t0)
    row = _row(miner)
    assert (row.revision, row.acked_revision, row.last_error) == (1, 1, "")
    first = miner_agent.sent[-1]
    assert first["revision"] == 1
    assert first["not_after_unix"] == int(t0.timestamp()) + 86400

    # Not due yet: nothing sent.
    net_policy.reconcile(now=t0 + timedelta(seconds=30))
    assert len(miner_agent.sent) == 1

    # The periodic re-send keeps the revision; only the expiry moves.
    t1 = t0 + timedelta(seconds=settings.VALI_NET_POLICY_SYNC_S)
    net_policy.reconcile(now=t1)
    assert len(miner_agent.sent) == 2
    resent = miner_agent.sent[-1]
    assert resent["revision"] == 1
    assert resent["not_after_unix"] == int(t1.timestamp()) + 86400
    assert {k: v for k, v in resent.items() if k != "not_after_unix"} == {
        k: v for k, v in first.items() if k != "not_after_unix"
    }
    # A fresh order_id per push.
    assert len(set(miner_agent.order_ids)) == 2

    # New content: a new revision, sent at once.
    _vm("vm-b", miner.miner_id, "medium")
    net_policy.reconcile(now=t1 + timedelta(seconds=1))
    assert miner_agent.sent[-1]["revision"] == 2
    assert miner_agent.sent[-1]["vm_caps"] == {"vm-a": 100, "vm-b": 250}
    row = _row(miner)
    assert (row.revision, row.acked_revision) == (2, 2)
    assert row.body["revision"] == 2


def test_a_wrong_ack_is_not_an_ack(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    miner_agent.script = [(200, "applied:1:" + "0" * 64)]
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    row = _row(miner)
    assert row.acked_revision == 0 and row.acked_at is None
    assert row.last_error.startswith("ack-mismatch")

    # Retried after the retry period, then acked.
    net_policy.reconcile(now=t0 + timedelta(seconds=settings.VALI_NET_POLICY_RETRY_S))
    row = _row(miner)
    assert row.acked_current and row.last_error == ""


def test_an_unknown_outcome_or_an_unreachable_miner_is_retried(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    miner_agent.script = [(502, "upstream")]
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    assert _row(miner).last_error.startswith("refused: status=502")

    miner_agent.unreachable = True
    net_policy.reconcile(now=t0 + timedelta(seconds=60))
    assert _row(miner).last_error.startswith("unreachable")

    miner_agent.unreachable = False
    net_policy.reconcile(now=t0 + timedelta(seconds=120))
    row = _row(miner)
    assert row.acked_current and row.revision == 1


def test_vali_moves_past_a_miner_revision_it_lost(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    miner_agent.revision, miner_agent.sha = 5, "f" * 64
    t = timezone.now()
    for _ in range(8):
        net_policy.reconcile(now=t)
        t += timedelta(seconds=settings.VALI_NET_POLICY_RETRY_S)
        if _row(miner).acked_current:
            break
    row = _row(miner)
    assert row.acked_current
    assert row.revision > 5
    assert miner_agent.revision == row.revision


def test_a_revision_conflict_takes_the_next_revision(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    miner_agent.revision, miner_agent.sha = 1, "e" * 64
    t = timezone.now()
    net_policy.reconcile(now=t)
    assert "revision-conflict" in _row(miner).last_error
    net_policy.reconcile(now=t + timedelta(seconds=settings.VALI_NET_POLICY_RETRY_S))
    row = _row(miner)
    assert row.acked_current and row.revision == 2


def test_an_agent_without_edge_mode_is_not_sent_edge_mode_again(
    miner_agent: FakeMiner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """422 `net-policy-unsupported` (C2): no edge-mode revision, new or not,
    until the hold ends or an operator lifts it after the upgrade."""
    monkeypatch.setattr(settings, "VALI_NET_POLICY_UNSUPPORTED_RETRY_S", 3600)
    miner = _miner(1, "AU")
    EgressRegion.objects.create(region="AU", mode="edge")
    miner_agent.script = [(422, "net-policy-unsupported")]
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    row = _row(miner)
    assert row.edge_unsupported_at == t0
    assert row.last_error.startswith("unsupported: edge mode refused")
    assert len(miner_agent.sent) == 1

    # Not re-sent at the retry period, nor when the content changes.
    net_policy.reconcile(now=t0 + timedelta(seconds=settings.VALI_NET_POLICY_RETRY_S))
    _vm("vm-new", miner.miner_id, "small")
    net_policy.reconcile(now=t0 + timedelta(seconds=600))
    assert len(miner_agent.sent) == 1
    assert _row(miner).revision == 2  # staged, held

    # The hold ends: the current revision goes out, and its ack clears it.
    net_policy.reconcile(now=t0 + timedelta(seconds=3600))
    row = _row(miner)
    assert len(miner_agent.sent) == 2 and miner_agent.sent[-1]["revision"] == 2
    assert row.acked_current and row.edge_unsupported_at is None and row.last_error == ""


def test_an_operator_lifts_the_unsupported_hold(miner_agent: FakeMiner) -> None:
    miner = _miner(1, "AU")
    EgressRegion.objects.create(region="AU", mode="edge")
    miner_agent.script = [(422, "net-policy-unsupported")]
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    net_policy.reconcile(now=t0 + timedelta(seconds=120))
    assert len(miner_agent.sent) == 1

    call_command("vali_net_policy", "--retry", miner.miner_id, stdout=io.StringIO())
    net_policy.reconcile(now=t0 + timedelta(seconds=121))
    assert len(miner_agent.sent) == 2
    assert _row(miner).acked_current


def test_a_local_policy_refused_as_unsupported_is_not_held(miner_agent: FakeMiner) -> None:
    miner = _miner(1, "FR")
    miner_agent.script = [(422, "net-policy-unsupported")]
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    assert _row(miner).edge_unsupported_at is None
    net_policy.reconcile(now=t0 + timedelta(seconds=settings.VALI_NET_POLICY_RETRY_S))
    assert _row(miner).acked_current


def test_a_failed_apply_retries_the_same_revision_with_backoff(
    miner_agent: FakeMiner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """500 `net-policy-apply` (C2): the rules are not installed; the SAME
    revision again, every RETRY_S doubled per failure, capped."""
    monkeypatch.setattr(settings, "VALI_NET_POLICY_RETRY_S", 60)
    monkeypatch.setattr(settings, "VALI_NET_POLICY_APPLY_BACKOFF_MAX_S", 200)
    miner = _miner(1)
    miner_agent.script = [(500, "net-policy-apply")] * 4
    t = timezone.now()
    net_policy.reconcile(now=t)
    assert _row(miner).apply_failures == 1
    # Waits: 60 s, 120 s, then capped at 200 s.
    for wait, failures in ((60, 2), (120, 3), (200, 4)):
        net_policy.reconcile(now=t + timedelta(seconds=wait - 1))
        assert _row(miner).apply_failures == failures - 1, wait
        t += timedelta(seconds=wait)
        net_policy.reconcile(now=t)
        assert _row(miner).apply_failures == failures
    assert {body["revision"] for body in miner_agent.sent} == {1}
    assert _row(miner).last_error.startswith("refused: status=500")

    t += timedelta(seconds=200)
    net_policy.reconcile(now=t)
    row = _row(miner)
    assert row.acked_current and row.apply_failures == 0 and row.revision == 1


def test_a_new_revision_restarts_the_apply_backoff(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    miner_agent.script = [(500, "net-policy-apply")] * 3
    t = timezone.now()
    net_policy.reconcile(now=t)
    net_policy.reconcile(now=t + timedelta(seconds=60))
    assert _row(miner).apply_failures == 2
    _vm("vm-new", miner.miner_id, "small")
    net_policy.reconcile(now=t + timedelta(seconds=61))
    row = _row(miner)
    assert row.revision == 2 and row.apply_failures == 1


def test_a_miner_with_no_country_is_reported(miner_agent: FakeMiner) -> None:
    miner = make_dispatchable_identity(7)
    net_policy.reconcile()
    assert miner_agent.sent == []
    assert _row(miner).last_error.startswith("no-region")


# ─── placement gate ──────────────────────────────────────────────────


def test_the_gate_is_empty_while_every_region_is_local(miner_agent: FakeMiner) -> None:
    _miner(1, "AU")
    EgressRegion.objects.create(region="AU", mode="local")
    assert net_policy.unready_node_ids() == {}


def test_an_edge_region_miner_needs_a_fresh_edge_ack(
    monkeypatch: pytest.MonkeyPatch, miner_agent: FakeMiner
) -> None:
    au, fr = _miner(1, "AU"), _miner(2, "FR")
    # Acked while the region was still local: not enough.
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    EgressRegion.objects.create(region="AU", mode="edge")
    monkeypatch.setattr(
        settings, "VALI_NET_POLICY_NB_CONTROL", [{"ip": "9.9.9.9", "proto": "tcp", "port": 443}]
    )
    nid = au.chain_node_id.lower()
    assert net_policy.unready_node_ids(now=t0) == {nid: "net-policy-not-acked"}

    # The edge-mode policy is a new revision, pushed and acked.
    net_policy.reconcile(now=t0 + timedelta(seconds=1))
    assert _row(au).mode == "edge" and _row(au).acked_current
    assert net_policy.unready_node_ids(now=t0 + timedelta(seconds=2)) == {}
    # FR stays local and is never gated.
    assert _row(fr).mode == "local"

    stale = t0 + timedelta(seconds=settings.VALI_NET_POLICY_ACK_STALE_S + 5)
    assert net_policy.unready_node_ids(now=stale) == {nid: "net-policy-ack-stale"}

    MinerNetPolicy.objects.filter(miner=au).delete()
    assert net_policy.unready_node_ids(now=t0) == {nid: "net-policy-missing"}


def test_decide_placement_skips_an_unready_miner() -> None:
    from apps.scheduler.placement import PlacementError, decide_placement
    from apps.scheduler.tests.factories import make_miner, make_snapshot, node_id

    snap = make_snapshot(miners=[make_miner(1), make_miner(2)])
    base = dict(
        snapshot=snap,
        capacity_by_node={node_id(1): 4, node_id(2): 4},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
    )
    chosen = decide_placement(**base, net_policy_unready={node_id(1): "net-policy-missing"})
    assert chosen == node_id(2)
    with pytest.raises(PlacementError, match="net-policy ack"):
        decide_placement(
            **base,
            net_policy_unready={node_id(1): "net-policy-missing", node_id(2): "x"},
        )


# ─── readout ─────────────────────────────────────────────────────────


def test_the_operator_readout(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    _vm("vm-a", miner.miner_id)
    net_policy.reconcile()
    out = io.StringIO()
    call_command("vali_net_policy", "--show", stdout=out)
    text = out.getvalue()
    assert miner.miner_id in text and "push=on" in text

    out = io.StringIO()
    call_command("vali_net_policy", "--body", miner.miner_id, stdout=out)
    assert json.loads(out.getvalue())["vm_caps"] == {"vm-a": 100}


# ─── the real encoder ────────────────────────────────────────────────

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)
_VECTOR = Path(__file__).resolve().parents[4] / "test_vectors" / "orders" / "net_policy_v1.json"
real_binary = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)


@real_binary
def test_the_digest_matches_the_shared_vector() -> None:
    for case in json.loads(_VECTOR.read_text())["cases"]:
        payload = json.dumps(case["payload"]).encode()
        assert order_dispatch.net_policy_digest(payload) == case["content_sha256"], case["name"]


@real_binary
def test_the_body_vali_builds_encodes_and_its_digest_ignores_only_the_expiry() -> None:
    miner = _miner(1)
    _vm("vm-a", miner.miner_id, "medium")
    _vm("vm-b", miner.miner_id)
    _attach_ip("vm-b")
    content = net_policy.build_content(miner, "FR")
    payload = net_policy.order_payload(content, revision=3, not_after_unix=1_790_000_000)
    body = order_dispatch._encode_order_body(
        order_id="np-wire-test",
        kind="net-policy",
        target_miner_id=miner.miner_id,
        issued_at_unix=1_789_990_000,
        payload_json=payload,
    )
    assert body
    digest = order_dispatch.net_policy_digest(payload)
    later = net_policy.order_payload(content, revision=3, not_after_unix=1_790_090_000)
    assert order_dispatch.net_policy_digest(later) == digest
    bumped = net_policy.order_payload(content, revision=4, not_after_unix=1_790_000_000)
    assert order_dispatch.net_policy_digest(bumped) != digest


def test_a_late_ack_of_an_older_revision_keeps_the_newer_one(miner_agent: FakeMiner) -> None:
    miner = _miner(1)
    t0 = timezone.now()
    net_policy.reconcile(now=t0)
    old = _row(miner)
    _vm("vm-a", miner.miner_id)
    net_policy.reconcile(now=t0 + timedelta(seconds=1))
    assert _row(miner).acked_revision == 2
    # The revision-1 push answering last (a concurrent tick).
    miner_agent.script = [(200, f"applied:1:{old.body_sha}")]
    content = {k: v for k, v in old.body.items() if k != "revision"}
    net_policy._push(miner, old, content, now=t0 + timedelta(seconds=2))
    row = _row(miner)
    assert (row.acked_revision, row.revision) == (2, 2) and row.acked_current


# ─── launch spec ─────────────────────────────────────────────────────


def _acked(miner: MinerIdentity, *, mode: str = "local", acked_revision: int = 1) -> None:
    MinerNetPolicy.objects.create(
        miner=miner,
        revision=max(acked_revision, 1),
        body_sha="s",
        mode=mode,
        acked_revision=acked_revision,
        acked_sha="s",
        acked_at=timezone.now(),
    )


@pytest.fixture
def launch_spec_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC", True)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", ["*"])


def test_no_launch_spec_while_the_flag_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    miner = _miner(1)
    _acked(miner)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", ["*"])
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC", False)
    assert net_policy.launch_net_spec(miner_id=miner.miner_id, vm_id="vm-1", flavor="small") is None


def test_the_launch_spec_goes_only_to_listed_miners(monkeypatch: pytest.MonkeyPatch) -> None:
    listed, other = _miner(1), _miner(2)
    _acked(listed)
    _acked(other)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC", True)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", [])
    assert net_policy.launch_net_spec(miner_id=listed.miner_id, vm_id="v", flavor="small") is None
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", [listed.miner_id])
    assert net_policy.launch_net_spec(miner_id=listed.miner_id, vm_id="v", flavor="small")
    assert net_policy.launch_net_spec(miner_id=other.miner_id, vm_id="v", flavor="small") is None


@pytest.mark.usefixtures("launch_spec_on")
def test_no_launch_spec_for_a_miner_that_never_acked() -> None:
    fresh, pending = _miner(1), _miner(2)
    _acked(pending, acked_revision=0)
    for miner in (fresh, pending):
        assert (
            net_policy.launch_net_spec(miner_id=miner.miner_id, vm_id="vm-1", flavor="small")
            is None
        )


@pytest.mark.usefixtures("launch_spec_on")
def test_the_launch_spec_carries_the_policy_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    local, edge = _miner(1), _miner(2, country="AU")
    _acked(local)
    _acked(edge, mode="edge")
    spec = net_policy.launch_net_spec
    assert spec(miner_id=local.miner_id, vm_id="vm-a", flavor="medium") == {
        "cap_mbps": 250,
        "isolate": True,
    }
    # Edge mode: room for the tunnel.
    assert spec(miner_id=edge.miner_id, vm_id="vm-a", flavor="small")["cap_mbps"] == 110
    # No flavor given: the launch record's; a public IP raises it.
    _vm("vm-rec", host=local.miner_id, flavor="large")
    assert spec(miner_id=local.miner_id, vm_id="vm-rec")["cap_mbps"] == 500
    _vm("vm-ip", host=local.miner_id, flavor="small")
    _attach_ip("vm-ip")
    assert spec(miner_id=local.miner_id, vm_id="vm-ip")["cap_mbps"] == 250
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_ISOLATE", False)
    assert spec(miner_id=local.miner_id, vm_id="vm-a", flavor="small") == {
        "cap_mbps": 100,
        "isolate": False,
    }


@pytest.mark.usefixtures("launch_spec_on")
def test_the_launch_spec_matches_the_policy_vm_caps(miner_agent: FakeMiner) -> None:
    """The first-packet cap and the cap the policy re-applies agree, so a
    launch is never re-tuned on the next drift check."""
    miner = _miner(1)
    _vm("vm-a", host=miner.miner_id, flavor="medium")
    _vm("vm-b", host=miner.miner_id, flavor="small")
    _attach_ip("vm-b")
    assert net_policy.sync_miner(miner) == "acked"
    vm_caps = miner_agent.sent[-1]["vm_caps"]
    for vm_id in ("vm-a", "vm-b"):
        spec = net_policy.launch_net_spec(miner_id=miner.miner_id, vm_id=vm_id)
        assert spec is not None
        assert spec["cap_mbps"] == vm_caps[vm_id]


def test_order_payloads_omit_net_unless_given() -> None:
    common = dict(
        vm_id="vm-1",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="ro",
        luks_disk_path="/d",
        luks_disk_size_gb=10,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=1,
        memory_mb=1024,
        cose_ticket=b"c",
    )
    net = {"cap_mbps": 100, "isolate": True}
    assert "net" not in order_dispatch.build_launch_payload(**common)
    assert order_dispatch.build_launch_payload(**common, net=net)["net"] == net
    assert "net" not in order_dispatch.build_migrate_activate_payload(
        **common, get_url="https://s3/x", new_gen=2
    )
    assert (
        order_dispatch.build_migrate_activate_payload(
            **common, get_url="https://s3/x", new_gen=2, net=net
        )["net"]
        == net
    )


def test_migrate_activate_carries_net_to_the_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.lifecycle.models import Vm
    from apps.orchestration import effects
    from apps.orchestration.services import customer_keys, migration_ticket

    dest = _miner(2)
    _acked(dest)
    _vm("vm-mig", host="elsewhere", flavor="medium")
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(effects, "_miner_identity", lambda n: (dest.miner_id, "100.64.0.9"))
    monkeypatch.setattr(migration_ticket, "remint_dest_ticket", lambda *a, **k: b"cose")
    monkeypatch.setattr(customer_keys, "resolve_for_remint", lambda *a, **k: None)
    monkeypatch.setattr(
        effects,
        "_launch_paths",
        lambda v: {
            "ovmf_path": "/o",
            "kernel_path": "/k",
            "initrd_path": "/i",
            "cmdline": "ro",
            "luks_disk_path": "/d",
            "luks_disk_size_gb": 10,
            "rootfs_data_path": "/r",
            "rootfs_hash_path": "/h",
            "cpu_count": 2,
            "memory_mb": 2048,
        },
    )

    def dispatch(**kw: Any) -> DispatchResult:
        sent.append(json.loads(kw["payload_json"]))
        return DispatchResult(ok=True, status=200, classifier="accepted")

    monkeypatch.setattr(order_dispatch, "dispatch_order", dispatch)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", ["*"])
    vm = Vm.objects.get(vm_id="vm-mig")
    for flag in (False, True):
        monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC", flag)
        effects.dispatch_migrate_activate(
            vm, dest_node_id="node", new_gen=2, get_url="https://s3/x", boot_artifacts=None
        )
    off, on = sent
    assert "net" not in off
    assert on["net"] == {"cap_mbps": 250, "isolate": True}
