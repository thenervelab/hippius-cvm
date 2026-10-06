"""`effects.dispatch_backup` / `effects.poll_backup_status` and the
`backup_chain` plumbing into the `migrate-activate` payload."""

from __future__ import annotations

import json

import pytest
from django.conf import settings

from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects, order_dispatch

pytestmark = pytest.mark.django_db


@pytest.fixture
def miner() -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id="miner-a",
        pubkey_hex="07" * 32,
        platform_id="07" * 64,
        chain_node_id=f"{7:064x}",
        status=MinerStatus.ACTIVE,
        netbird_ip="100.64.0.7",
    )


def _dispatch_returning(monkeypatch: pytest.MonkeyPatch, result: order_dispatch.DispatchResult):
    calls: list[dict] = []

    def fake(**kw: object) -> order_dispatch.DispatchResult:
        calls.append(kw)
        return result

    monkeypatch.setattr(order_dispatch, "dispatch_order", fake)
    return calls


def test_dispatch_backup_goes_through_the_signed_order_path(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _dispatch_returning(monkeypatch, order_dispatch.DispatchResult(True, 200, "ok"))
    effects.dispatch_backup(miner_id="miner-a", order_id="backup-r1", payload={"vm_id": "v"})
    [call] = calls
    assert call["kind"] == "backup"
    assert call["netbird_ip"] == "100.64.0.7"
    assert call["order_id"] == "backup-r1"
    assert json.loads(call["payload_json"]) == {"vm_id": "v"}


def test_dispatch_backup_treats_order_in_flight_as_accepted(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dispatch_returning(monkeypatch, order_dispatch.DispatchResult(False, 409, "order-in-flight"))
    effects.dispatch_backup(miner_id="miner-a", order_id="o", payload={})


def test_dispatch_backup_surfaces_the_miner_classifier(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dispatch_returning(monkeypatch, order_dispatch.DispatchResult(False, 409, "bitmap-missing"))
    with pytest.raises(effects.BackupRejected) as exc:
        effects.dispatch_backup(miner_id="miner-a", order_id="o", payload={})
    assert exc.value.classifier == "bitmap-missing" and exc.value.status == 409


def test_dispatch_backup_5xx_is_transient(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dispatch_returning(monkeypatch, order_dispatch.DispatchResult(False, 502, ""))
    with pytest.raises(effects.EffectUnavailable):
        effects.dispatch_backup(miner_id="miner-a", order_id="o", payload={})


def test_poll_backup_status_routes_to_the_miner_and_maps_404(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_EDGE_GATEWAY_URL", "http://edge.test")
    seen: list[tuple[str, str, dict]] = []
    answer = {
        "status": 200,
        "body": b'{"vm_id":"v","live":{"boot_counter":2,"point_run_ids":[]},"run":null}',
    }

    def fake_http(method: str, url: str, *, label: str, headers: dict, **_kw: object):
        seen.append((method, url, headers))
        return answer["status"], answer["body"]

    monkeypatch.setattr(effects, "_http", fake_http)
    got = effects.poll_backup_status(vm_id="v", miner_id="miner-a")
    assert got == {"vm_id": "v", "live": {"boot_counter": 2, "point_run_ids": []}, "run": None}
    assert seen[0][:2] == ("GET", "http://edge.test/v1/relay/v/backup")
    assert seen[0][2] == {"x-hippius-target-addr": "100.64.0.7:9700"}

    answer.update(status=404, body=b"no-domain")
    assert effects.poll_backup_status(vm_id="v", miner_id="miner-a") is None
    answer.update(status=502, body=b"")
    with pytest.raises(effects.EffectUnavailable):
        effects.poll_backup_status(vm_id="v", miner_id="miner-a")
    answer.update(status=400, body=b"bad-vm-id")
    with pytest.raises(effects.EffectError):
        effects.poll_backup_status(vm_id="v", miner_id="miner-a")


def _activate(**kw: object) -> dict:
    return order_dispatch.build_migrate_activate_payload(
        vm_id="v",
        get_url="https://s3/full",
        new_gen=2,
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="ro",
        luks_disk_path="/l",
        luks_disk_size_gb=10,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=1,
        memory_mb=1024,
        cose_ticket=b"t",
        **kw,
    )


def test_migrate_activate_payload_carries_a_backup_chain_only_when_given() -> None:
    assert "backup_chain" not in _activate()
    chain = {"restore_id": "job-1", "full": {}, "incrementals": [], "state": {}}
    assert _activate(backup_chain=chain)["backup_chain"] == chain


def test_poll_backup_status_outwaits_the_edge_relay(
    miner: MinerIdentity, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The poll's client timeout sits above the Edge relay's 30 s cap (and
    above the generic 15 s effect timeout), so a status query queued behind
    a run's own QMP setup is answered instead of timed out by vali."""
    monkeypatch.setattr(settings, "VALI_EDGE_GATEWAY_URL", "http://edge.test")
    seen: list[object] = []

    def fake_http(method: str, url: str, **kw: object):
        seen.append(kw.get("timeout"))
        return 404, b""

    monkeypatch.setattr(effects, "_http", fake_http)
    effects.poll_backup_status(vm_id="v", miner_id="miner-a")
    assert seen == [32.0]
