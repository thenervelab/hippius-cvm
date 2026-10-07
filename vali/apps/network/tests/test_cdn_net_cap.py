"""CDN nodes are exempt from the miner-side flavor caps (CDN plan N2):
their `vm_caps` entry and their launch `net.cap_mbps` are
`VALI_CDN_NET_CAP_MBPS`, no cap (the order maximum) by default — only
while `VALI_CDN_ENABLED` is on."""

from __future__ import annotations

import json

import pytest
from django.conf import settings

from apps.network import net_policy
from apps.network.net_policy import MAX_VM_CAP_MBPS

from .test_net_policy import _acked, _attach_ip, _miner, _vm

pytestmark = pytest.mark.django_db

CDN = "hippius-cdn"


@pytest.fixture(autouse=True)
def _cdn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN)
    monkeypatch.setattr(settings, "VALI_CDN_NET_CAP_MBPS", 0)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC", True)
    monkeypatch.setattr(settings, "VALI_NET_LAUNCH_SPEC_MINERS", ["*"])


def _world() -> str:
    miner = _miner(1)
    _vm("vm-tenant", miner.miner_id, "xlarge", tenant_id="tenant-a")
    _vm("cdn-1", miner.miner_id, "xlarge", tenant_id=CDN)
    _attach_ip("cdn-1")
    return miner.miner_id


def test_a_cdn_node_is_not_capped_by_its_flavor() -> None:
    miner_id = _world()
    miner = net_policy.MinerIdentity.objects.get(miner_id=miner_id)

    caps = net_policy.build_content(miner, "FR")["vm_caps"]

    assert caps["cdn-1"] == MAX_VM_CAP_MBPS
    assert caps["vm-tenant"] == net_policy.flavor_cap_mbps("xlarge")


def test_the_cdn_cap_is_a_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    miner_id = _world()
    miner = net_policy.MinerIdentity.objects.get(miner_id=miner_id)
    monkeypatch.setattr(settings, "VALI_CDN_NET_CAP_MBPS", 4000)

    assert net_policy.build_content(miner, "FR")["vm_caps"]["cdn-1"] == 4000
    monkeypatch.setattr(settings, "VALI_CDN_NET_CAP_MBPS", -1)
    with pytest.raises(net_policy.PolicyError):
        net_policy.build_content(miner, "FR")


def test_the_policy_is_byte_identical_while_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    miner_id = _world()
    miner = net_policy.MinerIdentity.objects.get(miner_id=miner_id)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    off = net_policy.build_content(miner, "FR")

    # Today's rule: the flavor, raised to the public-IP floor.
    assert off["vm_caps"]["cdn-1"] == net_policy.effective_cap_mbps("xlarge", has_public_ip=True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "someone-else")
    assert json.dumps(net_policy.build_content(miner, "FR")) == json.dumps(off)


def test_the_launch_spec_follows_the_policy() -> None:
    miner_id = _world()
    _acked(net_policy.MinerIdentity.objects.get(miner_id=miner_id))

    spec = net_policy.launch_net_spec(miner_id=miner_id, vm_id="cdn-1")
    tenant = net_policy.launch_net_spec(miner_id=miner_id, vm_id="vm-tenant")

    assert spec == {"cap_mbps": MAX_VM_CAP_MBPS, "isolate": True}
    assert tenant is not None and tenant["cap_mbps"] == net_policy.flavor_cap_mbps("xlarge")


def test_the_launch_spec_is_unchanged_while_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    miner_id = _world()
    _acked(net_policy.MinerIdentity.objects.get(miner_id=miner_id))
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)

    spec = net_policy.launch_net_spec(miner_id=miner_id, vm_id="cdn-1")

    assert spec == {
        "cap_mbps": net_policy.effective_cap_mbps("xlarge", has_public_ip=True),
        "isolate": True,
    }


def test_a_set_cdn_cap_gets_the_edge_mode_room(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_NET_CAP_MBPS", 1000)

    assert net_policy.cdn_cap_mbps("local") == 1000
    assert net_policy.cdn_cap_mbps("edge") == net_policy.miner_cap_mbps(1000, "edge") > 1000
    monkeypatch.setattr(settings, "VALI_CDN_NET_CAP_MBPS", 0)
    assert net_policy.cdn_cap_mbps("edge") == MAX_VM_CAP_MBPS
