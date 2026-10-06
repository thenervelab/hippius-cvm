"""Shared fixtures for the orchestration test suite.

`fx` (autouse) replaces every `effects.*` peer call + the lifecycle
ack verifier with an in-memory `FakeEffects` controller — tests tweak
it (inject a failure, drop an ack, …). `_mock_idempotency` (autouse)
swaps the §14 shell-out for an in-memory dict so the tick loop runs
without the built Rust binary; `test_idempotency.py` opts out via the
`real_idempotency` marker to exercise the real wrapper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle import validator as lifecycle_validator
from apps.orchestration import effects, idempotency

ROOT_PRINCIPAL = "orchestration-root"


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers",
        "real_idempotency: exercise the real idempotency shell-out (skip the in-memory mock)",
    )


@pytest.fixture(autouse=True)
def _orchestration_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pin orchestration settings deterministically for every test."""
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL)
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_STEP_TIMEOUT_S", 60.0)
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_ACK_TIMEOUT_S", 60.0)
    monkeypatch.setattr(settings, "VALI_IDEMPOTENCY_DIR", str(tmp_path / "idem"))
    monkeypatch.setattr(settings, "VALI_EDGE_GATEWAY_URL", "http://edge.test")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_URL", "http://kbs.test")
    # The admin hop's mTLS material — pinned EMPTY so the suite exercises
    # the pre-cutover plaintext transport deterministically, whatever the
    # developer's environment happens to export. `test_kbs_admin_tls.py`
    # sets them explicitly where it means to.
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_CERT", "")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CLIENT_KEY", "")
    monkeypatch.setattr(settings, "VALI_KBS_ADMIN_CACERT", "")
    monkeypatch.setattr(settings, "VALI_NETBIRD_API_TOKEN", "test-token")
    # The token above would let every `tick_once` in this suite send the
    # peer janitor's `GET /api/peers` to the real NetBird API. Off here;
    # `test_netbird_janitor.py` turns it on against a fake.
    monkeypatch.setattr(settings, "VALI_NETBIRD_PEER_JANITOR_ENABLED", False)
    # Same token, same problem for the public-IP sweep `tick_once` runs:
    # its NetBird half (peer listing + edge-routing GC) would call the real
    # API on every tick. Its database half (releasing a departed VM's
    # address) still runs; `apps/network/tests` drive the NetBird half
    # against a fake.
    from apps.network import service as network_service

    monkeypatch.setattr(network_service, "_netbird_sync_due", lambda: False)


class FakeEffects:
    """In-memory stand-in for `apps.orchestration.effects`.

    Defaults drive a fully-happy migration / decommission; tests
    mutate the attributes to steer:

    - `snapshot_status`  — what `poll_snapshot` returns.
    - `source_ack` / `eol_ack` — ack bytes, or `None` to never ack.
    - `ack_valid`        — whether the (mocked) verifier accepts acks.
    - `fail`             — effect names that raise `EffectError`.
    - `calls`            — ordered record of side-effects performed.
    """

    def __init__(self) -> None:
        self.snapshot_status = "done"
        #: What `poll_snapshot_status` reports as the multipart receipts.
        self.snapshot_disk: dict[str, Any] | None = None
        #: The last multipart snapshot dispatched: `(part_size, part_urls)`.
        self.multipart: tuple[int, list[str]] | None = None
        #: `(snapshot_size, snapshot_sha256_hex)` the last activation carried.
        self.activate_snapshot: tuple[int, str] | None = None
        # `settle_by_unix` of each `dispatch_migrate_activate`, in order.
        self.activate_settle_by: list[int] = []
        # §25 M4 — what `poll_dest_activation` returns (the dest's async
        # restore/boot outcome). Defaults to a happy `done`.
        self.dest_activation_status = "done"
        #: The class a `failed` dest activation reports ("" = none).
        self.dest_activation_class = ""
        self.source_ack: bytes | None = b"fake-source-ack"
        self.eol_ack: bytes | None = b"fake-eol-ack"
        #: The miner's class for the graceful stop (`stopped` / `not-running`).
        self.graceful_stop_outcome: str = "stopped"
        self.ack_valid = True
        # §25 M4 — the resolved dest-staging bundle (None ⇒ dest relies on
        # its pre-staged-artifact existence check). Tests can set a dict.
        self.boot_artifacts: Any = None
        # P9/#17 — what `resolve_netbird_peer` returns for the post-§25
        # overlay check. Defaults to a CONNECTED peer (the happy "the peer
        # survived the move" case); tests set `None` to model NetBird's
        # ephemeral GC having deleted the record.
        self.netbird_peer: Any = effects.NetbirdPeer(ip="100.9.9.9", connected=True)
        #: What `kbs_evidence.fetch_evidence` answers: a bundle dict, `None`
        #: (no bundle recorded), or an exception to raise. Defaults to the
        #: KBS admin being unreachable — the fail-safe answer, and what the
        #: suite used to get by resolving `kbs.test` for real.
        self.kbs_evidence: Any = effects.EffectUnavailable(
            "kbs-evidence: KBS admin unreachable (test default)"
        )
        self._minted = 0
        self.fail: set[str] = set()
        # §24 KBS fence — `kbs_tombstone` raises `KbsTombstoneConflict` when
        # set (the KBS holds a tombstone at another generation).
        self.tombstone_conflict = False
        self.calls: list[tuple] = []
        #: `restore` orders sent, in order: `(miner_id, order_id, payload)`.
        self.restore_orders: list[tuple[str, str, dict[str, Any]]] = []
        #: What `poll_restore_status` answers per miner: a status dict, or
        #: `None` (404). Tests set it.
        self.restore_status: dict[str, Any] = {}
        #: `(classifier, status)` the next `dispatch_restore` is refused with.
        self.restore_reject: tuple[str, int] | None = None
        #: What `poll_domain_running_on` answers once a test installs it
        #: (`test_restore.py` does; the rest of the suite keeps the real one).
        self.domain_running: bool | None = False
        #: The last `migrate-activate`'s restore fields.
        self.activate_restore: dict[str, Any] = {}
        # `name -> the REAL effects callable`, captured by the `fx` fixture
        # before it swaps them out.
        self.real: dict[str, Any] = {}

    def _maybe_fail(self, name: str) -> None:
        if name in self.fail:
            raise effects.EffectError(f"injected failure: {name}")

    def relay_quiesce(self, vm: Any, *, source_gen: int) -> None:
        self.calls.append(("relay_quiesce", vm.vm_id, source_gen))
        self._maybe_fail("relay_quiesce")

    def trigger_snapshot(self, vm: Any, *, put_url: str, state_put_url: str = "") -> None:
        self.calls.append(("trigger_snapshot", vm.vm_id, put_url, state_put_url))
        self._maybe_fail("trigger_snapshot")

    def poll_snapshot(self, vm: Any) -> str:
        self._maybe_fail("poll_snapshot")
        return self.snapshot_status

    def trigger_multipart_snapshot(
        self,
        vm: Any,
        *,
        job_id: str,
        part_size: int,
        part_urls: list[str],
        state_put_url: str,
    ) -> None:
        self.calls.append(
            ("trigger_multipart_snapshot", vm.vm_id, part_size, len(part_urls), state_put_url)
        )
        self._maybe_fail("trigger_multipart_snapshot")
        self.multipart = (part_size, part_urls)

    def poll_snapshot_status(self, vm: Any) -> tuple[str, dict[str, Any] | None]:
        self._maybe_fail("poll_snapshot")
        if self.snapshot_status == "done" and self.snapshot_disk is None and self.multipart:
            self.snapshot_disk = self._upload_every_part_but_the_spare()
        return self.snapshot_status, self.snapshot_disk

    def _upload_every_part_but_the_spare(self) -> dict[str, Any]:
        """A healthy miner: PUT full parts through all but the last presigned
        URL (the plan's headroom), then report their receipts."""
        from urllib.parse import parse_qs, urlsplit

        from apps.storage import s3

        assert self.multipart is not None
        part_size, urls = self.multipart
        used = urls[: max(1, len(urls) - 1)]
        client = s3.get_s3_client()
        parts = []
        for url in used:
            q = parse_qs(urlsplit(url).query)
            number = int(q["part_number"][0])
            client.record_part(upload_id=q["upload_id"][0], part_number=number, size=part_size)
            parts.append(
                {
                    "part_number": number,
                    "etag": f'"e{number}"',
                    "sha256_hex": "0" * 64,
                    "size": part_size,
                }
            )
        return {"parts": parts, "size": part_size * len(parts), "sha256_hex": "1" * 64}

    def poll_source_ack(self, vm: Any) -> bytes | None:
        self._maybe_fail("poll_source_ack")
        return self.source_ack

    def kbs_activate_dest(self, vm: Any, *, dest_node_id: str, new_gen: int, get_url: str) -> None:
        self.calls.append(("kbs_activate_dest", vm.vm_id, dest_node_id, new_gen))
        self._maybe_fail("kbs_activate_dest")

    def resolve_boot_artifacts(self, vm: Any) -> Any:
        self.calls.append(("resolve_boot_artifacts", vm.vm_id))
        self._maybe_fail("resolve_boot_artifacts")
        return self.boot_artifacts

    def dispatch_migrate_activate(
        self,
        vm: Any,
        *,
        dest_node_id: str,
        new_gen: int,
        get_url: str,
        state_get_url: str = "",
        boot_artifacts: Any,
        job_id: str = "",
        attempt: int = 0,
        snapshot_size: int = 0,
        snapshot_sha256_hex: str = "",
        settle_by_unix: int = 0,
        staged_restore_id: str = "",
        backup_chain: Any = None,
    ) -> None:
        self.activate_restore = {
            "staged_restore_id": staged_restore_id,
            "get_url": get_url,
            "backup_chain": backup_chain,
        }
        self.activate_snapshot = (snapshot_size, snapshot_sha256_hex)
        self.activate_settle_by.append(settle_by_unix)
        self.calls.append(
            (
                "dispatch_migrate_activate",
                vm.vm_id,
                dest_node_id,
                new_gen,
                state_get_url,
                job_id,
                attempt,
            )
        )
        self._maybe_fail("dispatch_migrate_activate")

    def poll_dest_activation(self, vm: Any, *, dest_node_id: str) -> str:
        self._maybe_fail("poll_dest_activation")
        return self.dest_activation_status

    def poll_dest_activation_status(self, vm: Any, *, dest_node_id: str) -> tuple[str, str]:
        self._maybe_fail("poll_dest_activation")
        failure_class = self.dest_activation_class
        return self.dest_activation_status, (
            failure_class if self.dest_activation_status == "failed" else ""
        )

    def dispatch_graceful_stop(self, vm: Any, **_kw: Any) -> str:
        self.calls.append(("dispatch_graceful_stop", vm.vm_id))
        self._maybe_fail("dispatch_graceful_stop")
        return self.graceful_stop_outcome

    def poll_eol_ack(self, vm: Any) -> bytes | None:
        self._maybe_fail("poll_eol_ack")
        return self.eol_ack

    def crypto_erase_kek_transit(self, vm: Any) -> None:
        self.calls.append(("crypto_erase_kek_transit", vm.vm_id))
        self._maybe_fail("crypto_erase_kek_transit")

    def dispatch_destroy(self, vm: Any) -> None:
        self.calls.append(("dispatch_destroy", vm.vm_id, vm.host))
        self._maybe_fail("dispatch_destroy")

    def revoke_netbird(self, vm: Any) -> None:
        self.calls.append(("revoke_netbird", vm.vm_id))
        self._maybe_fail("revoke_netbird")

    def mint_netbird_setup_key(
        self,
        *,
        vm_id: str,
        tenant_id: str,
        auto_group_name: str,
        persistent: bool,
        expires_in_seconds: int = 3600,
    ) -> effects.MintedSetupKey:
        self.calls.append(
            (
                "mint_netbird_setup_key",
                vm_id,
                tenant_id,
                auto_group_name,
                expires_in_seconds,
                persistent,
            )
        )
        self._maybe_fail("mint_netbird_setup_key")
        # Deterministic fake key so tests can assert the substitution
        # happened end-to-end without depending on network entropy.
        self._minted += 1
        return effects.MintedSetupKey(
            id=f"fake-sk-{vm_id}-{self._minted}", key=f"fake-setup-key-{vm_id}"
        )

    def resolve_netbird_peer(self, vm_id: str) -> Any:
        self.calls.append(("resolve_netbird_peer", vm_id))
        self._maybe_fail("resolve_netbird_peer")
        return self.netbird_peer

    def kbs_fence_decommission(self, vm_id: str) -> Any:
        self.calls.append(("kbs_fence_decommission", vm_id))
        self._maybe_fail("kbs_fence_decommission")
        return effects.KbsFenceOk(previous="active", state="decommissioning", cached=False)

    def kbs_tombstone(self, vm_id: str, *, generation: int) -> Any:
        self.calls.append(("kbs_tombstone", vm_id, generation))
        self._maybe_fail("kbs_tombstone")
        if self.tombstone_conflict:
            raise effects.KbsTombstoneConflict("injected 409 tombstone-generation-conflict")
        return effects.KbsFenceOk(previous="decommissioning", state="destroyed", cached=False)
    def resolve_netbird_peer_ip(self, vm_id: str) -> str | None:
        # The real effect's projection, over the same fake peer.
        self.calls.append(("resolve_netbird_peer_ip", vm_id))
        self._maybe_fail("resolve_netbird_peer_ip")
        peer = self.netbird_peer
        return peer.ip if peer is not None and peer.ip else None

    def fetch_evidence(self, vm_id: str) -> Any:
        self.calls.append(("fetch_evidence", vm_id))
        if isinstance(self.kbs_evidence, Exception):
            raise self.kbs_evidence
        return self.kbs_evidence

    def dispatch_restore(
        self,
        *,
        miner_id: str,
        order_id: str,
        payload: dict[str, Any],
        in_flight_ok: bool = True,
    ) -> None:
        self.calls.append(("dispatch_restore", miner_id, payload["op"], order_id))
        self._maybe_fail("dispatch_restore")
        if self.restore_reject is not None:
            raise effects.RestoreRejected(*self.restore_reject)
        self.restore_orders.append((miner_id, order_id, payload))
        status = self.restore_status.get(miner_id)
        final = {"abort": "aborted", "reclaim": "reclaimed"}.get(payload["op"])
        if final and status and status.get("restore_id") == payload["restore_id"]:
            status.update(state=final, op=payload["op"], domain_live=False)

    def poll_restore_status(self, *, vm_id: str, miner_id: str) -> Any:
        self._maybe_fail("poll_restore_status")
        return self.restore_status.get(miner_id)

    def poll_domain_running_on(self, vm: Any, node_id: str) -> bool | None:
        self.calls.append(("poll_domain_running_on", vm.vm_id, node_id))
        return self.domain_running

    def did(self, name: str) -> bool:
        """True iff a side-effect named `name` was performed."""
        return any(call[0] == name for call in self.calls)


@pytest.fixture(autouse=True)
def fx(monkeypatch: pytest.MonkeyPatch) -> FakeEffects:
    """Replace every peer effect + the ack verifier with `FakeEffects`."""
    fake = FakeEffects()
    # Keep a handle on the REAL callables before they are swapped out, so a
    # test that means to exercise one (rather than the fake) can reach it —
    # `fx.real["dispatch_migrate_activate"]`. Without this the autouse patch
    # makes the genuine function unreachable from inside the suite.
    fake.real = {}
    for name in (
        "relay_quiesce",
        "trigger_snapshot",
        "poll_snapshot",
        "poll_snapshot_status",
        "trigger_multipart_snapshot",
        "poll_source_ack",
        "kbs_activate_dest",
        "resolve_boot_artifacts",
        "dispatch_migrate_activate",
        "poll_dest_activation",
        "poll_dest_activation_status",
        "dispatch_graceful_stop",
        "poll_eol_ack",
        "crypto_erase_kek_transit",
        "dispatch_destroy",
        "revoke_netbird",
        "mint_netbird_setup_key",
        "resolve_netbird_peer",
        "kbs_fence_decommission",
        "kbs_tombstone",
        "resolve_netbird_peer_ip",
        "dispatch_restore",
        "poll_restore_status",
    ):
        fake.real[name] = getattr(effects, name)
        monkeypatch.setattr(effects, name, getattr(fake, name))
    # The KBS admin evidence read (§25 source reclaim, stranded-migration
    # veto) lives outside `effects` but is just as much a peer call.
    from apps.orchestration.services import kbs_evidence

    fake.real["fetch_evidence"] = kbs_evidence.fetch_evidence
    monkeypatch.setattr(kbs_evidence, "fetch_evidence", fake.fetch_evidence)

    def _fake_verify(**_kwargs: Any) -> Any:
        if fake.ack_valid:
            return lifecycle_validator.VerifiedStoppedAck(now_unix=1_700_000_000)
        raise lifecycle_validator.ValidatorFailed(
            message="injected bad ack", category="stopped-signature"
        )

    monkeypatch.setattr(lifecycle_validator, "verify_stopped_ack", _fake_verify)
    return fake


@pytest.fixture(autouse=True)
def _mock_idempotency(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """In-memory §14 idempotency store so the tick loop needs no
    built Rust binary. `test_idempotency.py` opts out via the
    `real_idempotency` marker.
    """
    if request.node.get_closest_marker("real_idempotency"):
        return
    store: dict[str, str] = {}

    def fake_recall(key: str) -> str | None:
        return store.get(key)

    def fake_record(key: str, response_hash_hex: str) -> bool:
        if key in store:
            return False
        store[key] = response_hash_hex
        return True

    monkeypatch.setattr(idempotency, "recall", fake_recall)
    monkeypatch.setattr(idempotency, "record", fake_record)


def _bearer_client(name: str) -> APIClient:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=name)
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@pytest.fixture
def authed_client() -> APIClient:
    """A non-root authenticated `ServiceClient`."""
    return _bearer_client("orchestrator")


@pytest.fixture
def root_client() -> APIClient:
    """The orchestration-root principal — accepted by `IsOrchestrationRoot`."""
    return _bearer_client(ROOT_PRINCIPAL)
