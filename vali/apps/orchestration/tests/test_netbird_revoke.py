"""`revoke_netbird` deletes the VM's peer BY ITS NETBIRD ID.

NetBird keys peers on its own opaque id; the vm_id only appears in the
peer's name (`hippius-tenant-<vm_id>`). The earlier `DELETE
/api/peers/<vm_id>` always 404'd — which the code read as "already
revoked" — so no peer was ever revoked.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectError, revoke_netbird

from .factories import make_vm

pytestmark = pytest.mark.django_db


class _Resp:
    def __init__(self, body: Any) -> None:
        self.status = 200
        self._body = json.dumps(body).encode() if body is not None else b""

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _netbird(monkeypatch: pytest.MonkeyPatch, peers: list[dict], delete_status: int = 200):
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_BASE", "https://nb.test")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "nbp_test")
    calls: list[tuple[str, str]] = []

    def _urlopen(request: urllib.request.Request, timeout: float, **_kw: object) -> _Resp:
        calls.append((request.get_method(), request.full_url))
        if request.get_method() == "GET":
            return _Resp(peers)
        if delete_status >= 400:
            raise urllib.error.HTTPError(request.full_url, delete_status, "x", {}, io.BytesIO())
        return _Resp(None)

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return calls


def test_revoke_deletes_every_peer_named_for_the_vm(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = make_vm("vm-7")
    calls = _netbird(
        monkeypatch,
        [
            {"id": "cabc1", "name": "hippius-tenant-vm-7", "ip": "100.70.0.1"},
            {"id": "cabc2", "name": "hippius-tenant-vm-7", "ip": "100.70.0.2"},
            {"id": "cother", "name": "hippius-tenant-vm-70", "ip": "100.70.0.3"},
        ],
    )

    revoke_netbird(vm)

    assert calls == [
        ("GET", "https://nb.test/api/peers"),
        ("DELETE", "https://nb.test/api/peers/cabc1"),
        ("DELETE", "https://nb.test/api/peers/cabc2"),
    ]


def test_revoke_deletes_a_peer_netbird_renamed_on_a_clash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # NetBird appends the last two overlay octets to a clashing name (seen
    # live: `hippius-tenant-<vm_id>-181-159`). A persistent peer missed here
    # would outlive the VM.
    vm = make_vm("vm-7")
    calls = _netbird(
        monkeypatch,
        [
            {"id": "cabc1", "name": "hippius-tenant-vm-7-181-159"},
            {"id": "cabc2", "name": "hippius-tenant-vm-7-x"},
        ],
    )
    revoke_netbird(vm)
    assert ("DELETE", "https://nb.test/api/peers/cabc1") in calls
    assert ("DELETE", "https://nb.test/api/peers/cabc2") not in calls


def test_revoke_spares_a_clash_name_that_is_another_live_vms_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `hippius-tenant-a-1-2` is live VM `a-1-2`'s own name, whatever `a`'s
    # clash rename could also produce.
    make_vm("a-1-2")
    vm = make_vm("a")
    calls = _netbird(monkeypatch, [{"id": "cabc1", "name": "hippius-tenant-a-1-2"}])
    revoke_netbird(vm)
    assert [m for m, _ in calls] == ["GET"]


def test_revoke_with_no_peer_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _netbird(monkeypatch, [])
    revoke_netbird(make_vm("vm-7"))
    assert calls == [("GET", "https://nb.test/api/peers")]


def test_revoke_tolerates_a_concurrent_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    _netbird(monkeypatch, [{"id": "cabc1", "name": "hippius-tenant-vm-7"}], delete_status=404)
    revoke_netbird(make_vm("vm-7"))


def test_revoke_raises_on_a_refused_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    _netbird(monkeypatch, [{"id": "cabc1", "name": "hippius-tenant-vm-7"}], delete_status=500)
    with pytest.raises(EffectError):
        revoke_netbird(make_vm("vm-7"))


def test_revoke_refuses_a_malformed_peer_id(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _netbird(monkeypatch, [{"id": "../groups/x", "name": "hippius-tenant-vm-7"}])
    with pytest.raises(EffectError):
        revoke_netbird(make_vm("vm-7"))
    assert [m for m, _ in calls] == ["GET"]
