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
        "real_idempotency: exercise the real idempotency shell-out "
        "(skip the in-memory mock)",
    )


@pytest.fixture(autouse=True)
def _orchestration_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Pin orchestration settings deterministically for every test."""
    monkeypatch.setattr(
        settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL
    )
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
        # §25 M4 — what `poll_dest_activation` returns (the dest's async
        # restore/boot outcome). Defaults to a happy `done`.
        self.dest_activation_status = "done"
        self.source_ack: bytes | None = b"fake-source-ack"
        self.eol_ack: bytes | None = b"fake-eol-ack"
        self.ack_valid = True
        # §25 M4 — the resolved dest-staging bundle (None ⇒ dest relies on
        # its pre-staged-artifact existence check). Tests can set a dict.
        self.boot_artifacts: Any = None
        # P9/#17 — what `resolve_netbird_peer` returns for the post-§25
        # overlay check. Defaults to a CONNECTED peer (the happy "the peer
        # survived the move" case); tests set `None` to model NetBird's
        # ephemeral GC having deleted the record.
        self.netbird_peer: Any = effects.NetbirdPeer(ip="100.9.9.9", connected=True)
        self.fail: set[str] = set()
        self.calls: list[tuple] = []
        # `name -> the REAL effects callable`, captured by the `fx` fixture
        # before it swaps them out.
        self.real: dict[str, Any] = {}

    def _maybe_fail(self, name: str) -> None:
        if name in self.fail:
            raise effects.EffectError(f"injected failure: {name}")

    def relay_quiesce(self, vm: Any, *, source_gen: int) -> None:
        self.calls.append(("relay_quiesce", vm.vm_id, source_gen))
        self._maybe_fail("relay_quiesce")

    def trigger_snapshot(
        self, vm: Any, *, put_url: str, state_put_url: str = ""
    ) -> None:
        self.calls.append(("trigger_snapshot", vm.vm_id, put_url, state_put_url))
        self._maybe_fail("trigger_snapshot")

    def poll_snapshot(self, vm: Any) -> str:
        self._maybe_fail("poll_snapshot")
        return self.snapshot_status

    def poll_source_ack(self, vm: Any) -> bytes | None:
        self._maybe_fail("poll_source_ack")
        return self.source_ack

    def kbs_activate_dest(
        self, vm: Any, *, dest_node_id: str, new_gen: int, get_url: str
    ) -> None:
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
    ) -> None:
        self.calls.append(
            (
                "dispatch_migrate_activate",
                vm.vm_id,
                dest_node_id,
                new_gen,
                state_get_url,
                job_id,
            )
        )
        self._maybe_fail("dispatch_migrate_activate")

    def poll_dest_activation(self, vm: Any, *, dest_node_id: str) -> str:
        self._maybe_fail("poll_dest_activation")
        return self.dest_activation_status

    def dispatch_graceful_stop(self, vm: Any) -> None:
        self.calls.append(("dispatch_graceful_stop", vm.vm_id))
        self._maybe_fail("dispatch_graceful_stop")

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
        expires_in_seconds: int = 3600,
    ) -> str:
        self.calls.append(
            (
                "mint_netbird_setup_key",
                vm_id,
                tenant_id,
                auto_group_name,
                expires_in_seconds,
            )
        )
        self._maybe_fail("mint_netbird_setup_key")
        # Deterministic fake key so tests can assert the substitution
        # happened end-to-end without depending on network entropy.
        return f"fake-setup-key-{vm_id}"

    def resolve_netbird_peer(self, vm_id: str) -> Any:
        self.calls.append(("resolve_netbird_peer", vm_id))
        self._maybe_fail("resolve_netbird_peer")
        return self.netbird_peer

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
        "poll_source_ack",
        "kbs_activate_dest",
        "resolve_boot_artifacts",
        "dispatch_migrate_activate",
        "poll_dest_activation",
        "dispatch_graceful_stop",
        "poll_eol_ack",
        "crypto_erase_kek_transit",
        "dispatch_destroy",
        "revoke_netbird",
        "mint_netbird_setup_key",
        "resolve_netbird_peer",
    ):
        fake.real[name] = getattr(effects, name)
        monkeypatch.setattr(effects, name, getattr(fake, name))

    def _fake_verify(**_kwargs: Any) -> Any:
        if fake.ack_valid:
            return lifecycle_validator.VerifiedStoppedAck(now_unix=1_700_000_000)
        raise lifecycle_validator.ValidatorFailed(
            message="injected bad ack", category="stopped-signature"
        )

    monkeypatch.setattr(lifecycle_validator, "verify_stopped_ack", _fake_verify)
    return fake


@pytest.fixture(autouse=True)
def _mock_idempotency(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
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
