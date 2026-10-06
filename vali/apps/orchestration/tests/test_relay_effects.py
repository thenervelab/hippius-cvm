"""§25 migration M1 — Edge relay effect glue.

Covers the source-side `relay_quiesce` / `trigger_snapshot` effects:
they must resolve the source miner's NetBird socket address from
`MinerIdentity` (keyed on `vm.host == miner_id`) and post it alongside
the `node_id` so the Edge can route the signed order to the source
miner the SAME way the launch/stop dispatch does.

These tests bypass the autouse `fx` fixture (which replaces the whole
`effects` module) by patching only `effects._http` — so the real effect
body, including `_source_miner_addr`, runs.
"""

from __future__ import annotations

from typing import Any

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects

# The autouse `fx` fixture (conftest) replaces `effects.relay_quiesce` /
# `effects.trigger_snapshot` with an in-memory fake — which would shadow
# the REAL effect body these tests target. Capture the originals at
# import time (before any fixture runs) so `captured_http` can restore
# them and exercise the actual `_source_miner_addr` resolution.
_REAL_RELAY_QUIESCE = effects.relay_quiesce
_REAL_TRIGGER_SNAPSHOT = effects.trigger_snapshot
_REAL_POLL_SOURCE_ACK = effects.poll_source_ack


@pytest.fixture
def captured_http(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch `effects._http` to capture every call's `(method, url,
    json_body)` and return a 200 with an empty body. Also restores the
    REAL relay effect bodies (the autouse `fx` fixture replaced them).
    """
    calls: list[dict[str, Any]] = []

    def fake_http(
        method: str,
        url: str,
        *,
        label: str,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        calls.append(
            {
                "method": method,
                "url": url,
                "label": label,
                "json": json_body,
                "headers": headers,
            }
        )
        return 200, b""

    monkeypatch.setattr(effects, "_http", fake_http)
    # Restore the real effect bodies the autouse `fx` fixture stubbed.
    monkeypatch.setattr(effects, "relay_quiesce", _REAL_RELAY_QUIESCE)
    monkeypatch.setattr(effects, "trigger_snapshot", _REAL_TRIGGER_SNAPSHOT)
    monkeypatch.setattr(
        effects.settings, "VALI_EDGE_GATEWAY_URL", "http://edge.test", raising=False
    )
    return calls


def _vm(host: str = "miner-src") -> Vm:
    return Vm.objects.create(
        vm_id="tenant-x",
        lease_id="lease-x",
        state=VmState.ACTIVE,
        generation=5,
        signing_generation=5,
        host=host,
        lifecycle_vk=bytes(32),
        # §25 M3 — `relay_quiesce` carries the single-use EOL nonce to the
        # source guest; `start_migration` mints it before the first
        # quiesce, so a VM under quiesce always has one.
        eol_nonce=bytes(range(32)),
    )


def _miner(miner_id: str = "miner-src", netbird_ip: str = "100.64.0.7") -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex="ab" * 32,
        platform_id="plat-src",
        netbird_ip=netbird_ip,
    )


@pytest.mark.django_db
def test_relay_quiesce_posts_node_id_and_resolved_miner_addr(
    captured_http: list[dict[str, Any]],
) -> None:
    vm = _vm()
    _miner()
    effects.relay_quiesce(vm, source_gen=5)
    assert len(captured_http) == 1
    call = captured_http[0]
    assert call["method"] == "POST"
    assert call["url"] == "http://edge.test/v1/relay/tenant-x/quiesce"
    # The body carries the source miner_id (node_id), the resolved NetBird
    # socket address the Edge routes to, AND (§25 M3) the producer fields:
    # the single-use eol_nonce + the source_gen the guest signs at + the
    # lease_id.
    assert call["json"] == {
        "node_id": "miner-src",
        "miner_addr": "100.64.0.7:9700",
        "lease_id": "lease-x",
        "source_gen": 5,
        "eol_nonce_hex": bytes(range(32)).hex(),
    }


@pytest.mark.django_db
def test_trigger_snapshot_posts_put_url_with_resolved_addr(
    captured_http: list[dict[str, Any]],
) -> None:
    vm = _vm()
    _miner()
    effects.trigger_snapshot(
        vm,
        put_url="https://s3.example/put?sig=x",
        state_put_url="https://s3.example/state?sig=y",
    )
    assert len(captured_http) == 1
    call = captured_http[0]
    assert call["url"] == "http://edge.test/v1/relay/tenant-x/snapshot"
    assert call["json"] == {
        "node_id": "miner-src",
        "miner_addr": "100.64.0.7:9700",
        "put_url": "https://s3.example/put?sig=x",
        # The anti-rollback state disk travels with the volume — without
        # it the destination boots a blank boot counter and the KBS
        # refuses the release before any Vault read.
        "state_put_url": "https://s3.example/state?sig=y",
    }


@pytest.mark.django_db
def test_relay_quiesce_fails_loudly_when_source_miner_has_no_identity(
    captured_http: list[dict[str, Any]],
) -> None:
    vm = _vm(host="ghost-miner")
    # No MinerIdentity row for `ghost-miner` — the effect must raise an
    # EffectError (NOT silently post a bad/empty address).
    with pytest.raises(effects.EffectError):
        effects.relay_quiesce(vm, source_gen=5)
    assert captured_http == []


@pytest.mark.django_db
def test_relay_quiesce_fails_loudly_when_source_miner_has_no_netbird_ip(
    captured_http: list[dict[str, Any]],
) -> None:
    vm = _vm()
    MinerIdentity.objects.create(
        miner_id="miner-src",
        pubkey_hex="ab" * 32,
        platform_id="plat-src",
        netbird_ip=None,
    )
    with pytest.raises(effects.EffectError):
        effects.relay_quiesce(vm, source_gen=5)
    assert captured_http == []


@pytest.mark.django_db
def test_relay_quiesce_fails_loudly_when_vm_has_no_eol_nonce(
    captured_http: list[dict[str, Any]],
) -> None:
    # §25 M3: the quiesce carries the single-use eol_nonce the guest signs;
    # a VM without one cannot produce a verifiable ack — fail closed loudly
    # rather than relay a quiesce the guest could never sign.
    vm = _vm()
    vm.eol_nonce = None
    vm.save(update_fields=["eol_nonce"])
    _miner()
    with pytest.raises(effects.EffectError, match="no eol_nonce"):
        effects.relay_quiesce(vm, source_gen=5)
    assert captured_http == []


# ─── §25 source-ack poll (reads the guest-pushed StoppedAckIngest) ────
#
# The guest pushes its signed `stopped{}` ack to vali's
# `/v1/lifecycle/stopped` ingress (the StoppedAckIngest store), keyed by
# `(vm_id, generation)`. `poll_source_ack` reads the raw bytes from THAT
# store at the VM's generation — NOT an Edge GET relay (the pre-#536
# design). The miner-agent vsock signer path remains a fail-closed stub.


@pytest.mark.django_db
def test_poll_source_ack_reads_stored_bytes_at_vm_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`poll_source_ack` returns the raw `SignedStoppedAck` bytes the
    guest pushed for `(vm_id, generation)` — the bytes vali's
    `_verify_ack` then cryptographically verifies.
    """
    from apps.lifecycle.models import StoppedAckIngest

    monkeypatch.setattr(effects, "poll_source_ack", _REAL_POLL_SOURCE_ACK)
    vm = _vm()  # vm_id="tenant-x", generation=5
    StoppedAckIngest.objects.create(
        vm_id="tenant-x", generation=5, signed_ack=bytes.fromhex("deadbeef")
    )
    assert effects.poll_source_ack(vm) == bytes.fromhex("deadbeef")


@pytest.mark.django_db
def test_poll_source_ack_no_stored_ack_means_not_produced_yet_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No stored ack for `(vm_id, generation)` ⇒ `None` — vali keeps
    waiting, NEVER advances to dest activation. The fail-closed half of
    the split-brain fence on the poll side. (A stale ack at an EARLIER
    generation must NOT satisfy the poll either.)
    """
    from apps.lifecycle.models import StoppedAckIngest

    monkeypatch.setattr(effects, "poll_source_ack", _REAL_POLL_SOURCE_ACK)
    vm = _vm()  # generation=5
    # A stale ack at gen 4 must not satisfy a gen-5 poll.
    StoppedAckIngest.objects.create(
        vm_id="tenant-x", generation=4, signed_ack=b"stale"
    )
    assert effects.poll_source_ack(vm) is None


# ── §25 multipart snapshot ───────────────────────────────────────────

_REAL_TRIGGER_MULTIPART = effects.trigger_multipart_snapshot
_REAL_POLL_SNAPSHOT_STATUS = effects.poll_snapshot_status


@pytest.mark.django_db
def test_a_multipart_snapshot_is_a_signed_migrate_snapshot_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dispatched through the Edge's generic order path (the relay route
    rebuilds only the single-PUT shape), per job, to the SOURCE miner."""
    import json

    from apps.orchestration import order_dispatch

    monkeypatch.setattr(effects, "trigger_multipart_snapshot", _REAL_TRIGGER_MULTIPART)
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: sent.append(kw)
        or order_dispatch.DispatchResult(ok=True, status=200, classifier="snapshot-accepted"),
    )
    vm = _vm()
    _miner()
    effects.trigger_multipart_snapshot(
        vm,
        job_id="job1",
        part_size=1 << 30,
        part_urls=["https://s3/p1", "https://s3/p2"],
        state_put_url="https://s3/state",
    )
    (kw,) = sent
    assert kw["kind"] == "migrate-snapshot"
    assert (kw["miner_id"], kw["netbird_ip"]) == ("miner-src", "100.64.0.7")
    assert kw["order_id"] == "mig-snapshot-tenant-x-job1"
    assert json.loads(kw["payload_json"]) == {
        "vm_id": "tenant-x",
        "node_id": "miner-src",
        "part_size": 1 << 30,
        "disk_part_urls": ["https://s3/p1", "https://s3/p2"],
        "state_put_url": "https://s3/state",
    }


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("status", "classifier", "raises"),
    [(409, "order-in-flight", False), (409, "not-quiesced", True), (503, "", True)],
)
def test_a_multipart_snapshot_refused_by_the_miner_is_an_error(
    monkeypatch: pytest.MonkeyPatch, status: int, classifier: str, raises: bool
) -> None:
    from apps.orchestration import order_dispatch

    monkeypatch.setattr(effects, "trigger_multipart_snapshot", _REAL_TRIGGER_MULTIPART)
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: order_dispatch.DispatchResult(ok=False, status=status, classifier=classifier),
    )
    vm = _vm()
    _miner()
    call = lambda: effects.trigger_multipart_snapshot(  # noqa: E731
        vm, job_id="j", part_size=1 << 30, part_urls=["u"], state_put_url="s"
    )
    if raises:
        with pytest.raises(effects.EffectError):
            call()
    else:
        call()


@pytest.mark.django_db
def test_the_snapshot_status_carries_the_part_receipts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(effects, "poll_snapshot_status", _REAL_POLL_SNAPSHOT_STATUS)
    disk = {"parts": [{"part_number": 1, "etag": '"e"', "size": 5}], "size": 5}
    replies = iter(
        [
            (200, b'{"status":"done","disk":' + __import__("json").dumps(disk).encode() + b"}"),
            (200, b'{"status":"running"}'),
        ]
    )
    monkeypatch.setattr(effects, "_edge_get", lambda vm, path: next(replies))
    vm = _vm()
    assert effects.poll_snapshot_status(vm) == ("done", disk)
    assert effects.poll_snapshot_status(vm) == ("running", None)


@pytest.mark.django_db
def test_a_miner_with_no_record_of_the_migration_reports_it_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """404 after the quiesce: the agent restarted and lost its in-memory
    upload task — nothing on that host will finish it."""
    monkeypatch.setattr(effects, "poll_snapshot_status", _REAL_POLL_SNAPSHOT_STATUS)
    monkeypatch.setattr(effects, "_edge_get", lambda vm, path: (404, b"no-migration"))
    vm = _vm()
    assert effects.poll_snapshot_status(vm) == ("failed", None)
    monkeypatch.setattr(effects, "_edge_get", lambda vm, path: (502, b""))
    with pytest.raises(effects.EffectError):
        effects.poll_snapshot_status(vm)


_REAL_POLL_DEST_ACTIVATION_STATUS = effects.poll_dest_activation_status


@pytest.mark.django_db
def test_the_dest_activation_status_carries_the_failure_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dest's class for a `failed` reaches the handler; a body without
    one (an older agent) or a non-failed status carries none."""
    monkeypatch.setattr(
        effects, "poll_dest_activation_status", _REAL_POLL_DEST_ACTIVATION_STATUS
    )
    monkeypatch.setattr(effects, "_miner_identity", lambda n: (n, "100.64.0.9"))
    replies = iter(
        [
            (200, b'{"status":"failed","class":"migration/dest-settle-by-passed"}'),
            (200, b'{"status":"failed"}'),
            (200, b'{"status":"running","class":"migration/x"}'),
            (200, b'{"status":"failed","class":7}'),
        ]
    )
    monkeypatch.setattr(effects, "_edge_get_addr", lambda vm, path, addr: next(replies))
    vm = _vm()
    poll = lambda: effects.poll_dest_activation_status(vm, dest_node_id="n")  # noqa: E731
    assert poll() == ("failed", "migration/dest-settle-by-passed")
    assert poll() == ("failed", "")
    assert poll() == ("running", "")
    assert poll() == ("failed", "")
