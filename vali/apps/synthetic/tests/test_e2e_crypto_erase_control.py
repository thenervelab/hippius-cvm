"""The crypto-erase DIFFERENTIAL — the monitor's positive control.

`crypto_erase` is the only continuous watcher of the property the whole
confidential-compute design rests on: at §24 the per-VM Vault-Transit KEK
`kek-<vm_id>` is DESTROYED, so the ciphertext on the (untrusted) miner's
disk is permanently unreadable.

It used to prove that with ONE observation — "the key is absent now" —
and absence has two causes it could not tell apart:

  * §24 destroyed it                    ⇒ erase VERIFIED, or
  * it was never at that name at all    ⇒ nothing was erased, nothing
                                           could be, and the real key
                                           material is untouched.

Every branch downstream reads the second as a pass: Vault answers a
missing Transit key with "encryption key not found" (⇒ gone),
`transit_key_delete` is idempotent on 404 (⇒ §24 SUCCESS), and the KV read
403s by KEK-HSM design (⇒ accepted as gone). So a regression that stopped
the launch path provisioning `kek-<vm_id>`, or drifted the name between
the provisioning and erase paths, would have reported `crypto_erase ok`
indefinitely.

These tests pin the differential (ALIVE before → GONE after) and, most
importantly, that the run FAILS in each of the two ways it can be wrong:
the KEK survived the decommission, and the KEK was never there.

They drive the REAL `vault_kv` code through its `_round_trip` HTTP seam
against an in-memory Vault whose transit keys are an actual set — NOT a
monkeypatched `transit_key_gone` — so the Vault status-code semantics
(a missing Transit key is a 400, not a 404) are part of what is proven.
"""

from __future__ import annotations

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import vault_kv
from apps.orchestration.services.vault_kv import EffectError, VaultNotFound
from apps.orchestration.tests.factories import make_vm
from apps.synthetic import e2e

_WRAPPED_ROUTE = "/v1/transit/datakey/wrapped/"


class FakeVault:
    """An in-memory Vault Transit, spoken to over the real `_round_trip`
    seam. `keys` is the set of Transit keys that EXIST."""

    def __init__(self, *, keys: set[str] | None = None) -> None:
        self.keys: set[str] = set(keys or ())
        self.probes: list[str] = []

    def round_trip(self, method, path, *, label="", json_body=None):
        if path.startswith(_WRAPPED_ROUTE):
            name = path[len(_WRAPPED_ROUTE) :]
            self.probes.append(name)
            if name in self.keys:
                # A live key derives a fresh datakey and returns ONLY the
                # wrapped ciphertext (vali can never unwrap it).
                return 200, b'{"data":{"ciphertext":"vault:v1:derived"}}'
            # Vault does NOT 404 a missing Transit key — it 400s.
            return 400, b'{"errors":["encryption key not found"]}'
        raise AssertionError(f"unexpected Vault route: {method} {path}")


def _kv_403(mount, path):
    """The deployed vali identity is read-denied on `luks-kek` (KEK-HSM),
    so that half of the KV check 403s on success AND on failure — which is
    exactly why the transit half is the one that needs a control.

    The USERDATA paths are different: vali may read them, so the verifier
    requires an observed 404 there and this stand-in answers accordingly.
    """
    if path.endswith("/luks-kek"):
        raise EffectError("vault-kv-get:secret: vault returned HTTP 403")
    raise VaultNotFound("gone")


# ── the control itself ────────────────────────────────────────────────


def test_kek_alive_passes_while_the_key_exists(monkeypatch) -> None:
    fake = FakeVault(keys={"kek-synmon-live"})
    monkeypatch.setattr(vault_kv, "_round_trip", fake.round_trip)
    assert e2e._verify_kek_alive("synmon-live") is True
    # Probed the SAME per-VM name §24 erases — a drift between the two
    # would make the control test a different key than the erase.
    assert fake.probes == [vault_kv.transit_key_name("synmon-live")]


def test_kek_alive_FAILS_when_the_key_was_never_provisioned(monkeypatch) -> None:
    """THE regression this stage exists for: the VM is running but there
    is no `kek-<vm_id>`, so a later 'it is gone' proves nothing."""
    fake = FakeVault(keys=set())
    monkeypatch.setattr(vault_kv, "_round_trip", fake.round_trip)
    with pytest.raises(e2e.ApiError, match="ALREADY absent"):
        e2e._verify_kek_alive("synmon-missing")


@pytest.mark.parametrize(
    "status,raw",
    [
        (403, b"denied"),  # the probe is denied
        (400, b'{"errors":["bad request"]}'),  # ambiguous 400
        (404, b'{"errors":["route entry not found."]}'),  # wrong route
    ],
)
def test_kek_alive_fails_closed_on_an_unreadable_probe(monkeypatch, status, raw) -> None:
    """A broken probe must NEVER manufacture the control it provides:
    'alive' is asserted only on a clean 2xx."""
    monkeypatch.setattr(vault_kv, "_round_trip", lambda *a, **k: (status, raw))
    with pytest.raises(EffectError):
        e2e._verify_kek_alive("synmon-denied")


# ── the verify refuses to certify without a before-state ──────────────


@pytest.mark.django_db
@pytest.mark.parametrize("control", [False, None, 0, ""])
def test_verify_refuses_without_a_positive_control(monkeypatch, control) -> None:
    """A post-state-only assertion is unfalsifiable — refuse it rather
    than report a pass. This is the ONLY safe direction: no value of
    `kek_was_alive` skips an assertion, it can only add one."""
    make_vm("synmon-nocontrol", state=VmState.DESTROYED)
    fake = FakeVault(keys=set())  # key absent — would otherwise "pass"
    monkeypatch.setattr(vault_kv, "_round_trip", fake.round_trip)
    monkeypatch.setattr(vault_kv, "get_kv", _kv_403)
    with pytest.raises(e2e.ApiError, match="NO positive control"):
        e2e._verify_crypto_erase("synmon-nocontrol", kek_was_alive=control)


@pytest.mark.django_db
def test_verify_cannot_be_called_without_the_control_at_all() -> None:
    """Keyword-only and NO default: a refactor that drops the `kek_alive`
    stage fails to call this, instead of silently going green."""
    make_vm("synmon-argless", state=VmState.DESTROYED)
    with pytest.raises(TypeError):
        e2e._verify_crypto_erase("synmon-argless")  # type: ignore[call-arg]


# ── the whole state machine, end to end ───────────────────────────────


class _FakeApi:
    """A control plane whose §24 either erases the Transit key or does
    not — the single variable these end-to-end tests turn."""

    def __init__(self, *, vault: FakeVault, vm_id: str, erase_on_decommission: bool) -> None:
        self._vault = vault
        self._vm_id = vm_id
        self._erase = erase_on_decommission

    def launch(self, body):
        return {"job_id": "j1", "state": "queued"}

    def poll_launch(self, job_id):
        return {"job_id": job_id, "state": "succeeded"}

    def decommission(self, vm_id):
        if self._erase:
            # What a working §24 does: destroy `kek-<vm_id>`.
            self._vault.keys.discard(vault_kv.transit_key_name(vm_id))
        Vm.objects.filter(vm_id=vm_id).update(state=VmState.DESTROYED)
        return {"job_id": "d1", "state": "draining"}

    def poll_decommission(self, vm_id, job_id):
        return {"job_id": job_id, "state": "done"}


def _drive(monkeypatch, *, vm_id: str, keys: set[str], erase: bool) -> e2e.E2EOutcome:
    monkeypatch.setattr(e2e, "_synthetic_vm_id", lambda distro: vm_id)
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)
    from django.utils import timezone

    from apps.images.models import GoldenImage

    # The blessed catalog row the monitor resolves `ubuntu` through.
    GoldenImage.objects.get_or_create(
        image_name="ubuntu",
        defaults={
            "distro": "ubuntu",
            "bake_id": "bake-ubuntu-9",
            "blessed_at": timezone.now(),
            "blessed_by": "test",
        },
    )
    vm = make_vm(vm_id, state=VmState.ACTIVE)
    vm.boot_phase = "running"
    vm.netbird_ip = "100.64.0.41"
    vm.save(update_fields=["boot_phase", "netbird_ip"])
    fake = FakeVault(keys=keys)
    monkeypatch.setattr(vault_kv, "_round_trip", fake.round_trip)
    monkeypatch.setattr(vault_kv, "get_kv", _kv_403)
    api = _FakeApi(vault=fake, vm_id=vm_id, erase_on_decommission=erase)
    return e2e.run_e2e(api=api, distro="ubuntu", budget_s=60)


def _stages(outcome: e2e.E2EOutcome) -> dict[str, bool]:
    return {s.name: s.ok for s in outcome.stages}


@pytest.mark.django_db
def test_e2e_green_on_a_real_alive_then_dead_differential(monkeypatch) -> None:
    """The happy path is a DIFFERENTIAL, not an absence: the key is
    observed alive before §24 and gone after."""
    vm_id = "synmon-diff-ok"
    outcome = _drive(monkeypatch, vm_id=vm_id, keys={f"kek-{vm_id}"}, erase=True)
    stages = _stages(outcome)
    assert stages["kek_alive"] is True
    assert stages["crypto_erase"] is True
    assert outcome.success is True


@pytest.mark.django_db
def test_e2e_FAILS_when_the_kek_survives_the_decommission(monkeypatch) -> None:
    """THE regression the stage exists to catch: §24 ran, reported done,
    and the KEK is still live in Vault — the tenant's ciphertext is still
    decryptable. The run must FAIL, not silently pass and not skip."""
    vm_id = "synmon-diff-live"
    outcome = _drive(monkeypatch, vm_id=vm_id, keys={f"kek-{vm_id}"}, erase=False)
    stages = _stages(outcome)
    assert stages["kek_alive"] is True  # the control held...
    assert stages["decommission"] is True  # ...§24 claimed success...
    assert stages["crypto_erase"] is False  # ...and the erase is caught.
    assert outcome.success is False
    detail = next(s.detail for s in outcome.stages if s.name == "crypto_erase")
    assert "still present after decommission" in detail


@pytest.mark.django_db
def test_e2e_FAILS_when_the_kek_was_never_provisioned(monkeypatch) -> None:
    """The vacuity that made the check unsound: with no `kek-<vm_id>` the
    post-state is 'gone' whether or not anything was erased. Before the
    control this run went GREEN; now it fails at `kek_alive` and the
    crypto_erase stage is never reached, so nothing is certified."""
    vm_id = "synmon-diff-none"
    outcome = _drive(monkeypatch, vm_id=vm_id, keys=set(), erase=False)
    stages = _stages(outcome)
    assert stages["kek_alive"] is False
    assert "crypto_erase" not in stages  # never claimed either way
    assert outcome.success is False


@pytest.mark.django_db
def test_e2e_still_tears_down_when_the_control_fails(monkeypatch) -> None:
    """A new stage must not open a leak: a `kek_alive` failure still runs
    the mandatory §24 teardown of the throwaway VM."""
    vm_id = "synmon-diff-teardown"
    outcome = _drive(monkeypatch, vm_id=vm_id, keys=set(), erase=False)
    assert outcome.teardown_forced is False
    assert Vm.objects.get(vm_id=vm_id).state == VmState.DESTROYED


@pytest.mark.django_db
def test_kek_alive_probe_does_not_mutate_the_key(monkeypatch) -> None:
    """The control runs against a LIVE tenant KEK, so it must be a pure
    derive: the key set is unchanged and the KV blob is untouched."""
    vm_id = "synmon-diff-nomutate"
    fake = FakeVault(keys={f"kek-{vm_id}"})
    monkeypatch.setattr(vault_kv, "_round_trip", fake.round_trip)
    before = set(fake.keys)
    e2e._verify_kek_alive(vm_id)
    assert fake.keys == before


def test_kek_alive_is_a_stage_of_the_reported_run() -> None:
    """The gauge set must carry `kek_alive`, or a 0 on the control would
    never reach Prometheus and the alert could not fire."""
    from apps.synthetic.management.commands import vali_synthetic_monitor as cmd

    stages = cmd._E2E_STAGES
    assert "kek_alive" in stages
    # And it must come BEFORE the erase it controls for.
    assert stages.index("kek_alive") < stages.index("crypto_erase")
