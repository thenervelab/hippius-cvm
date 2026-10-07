"""Tests for the admin→API launch surface (PR-A2): `POST /v1/vm/launch`,
`GET /v1/vm/launch/<job_id>`, and the `vali_launch_tick` worker.

Vault (`put_kv`/`get_kv`) and the `launch_vm` choreography are mocked —
these pin the job intake, the §20 no-secret-in-DB discipline, and the
worker's claim + terminal-state machine.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.orchestration import launch_jobs, order_dispatch
from apps.orchestration.models import LaunchJob, LaunchJobState, LaunchPhase
from apps.orchestration.services import launch, vault_kv

pytestmark = pytest.mark.django_db

LAUNCH_URL = reverse("vm_launch")

# NetBird is ON by default, so the baseline userdata carries the
# `{{NETBIRD_SETUP_KEY}}` placeholder the launch validates + substitutes.
_USERDATA = "#cloud-config\nssh_pwauth: true\n# {{NETBIRD_SETUP_KEY}}\n"


def _kek_path(vm_id: str = "vm-api-1") -> str:
    """A kek_vault_path under THIS vm's namespace (passes the §HIGH-3
    confinement check). Derived from the real configured prefix."""
    from django.conf import settings

    return f"{settings.VALI_VAULT_KV_PREFIX}/{vm_id}/luks-kek"


def _intent(**overrides) -> dict:
    vm_id = overrides.get("vm_id", "vm-api-1")
    body = {
        "tenant_id": "t-api",
        "user_id": "u-1",
        "vm_id": vm_id,
        "lease_id": "lease-1",
        "flavor": "small",
        "cmdline": "ro ds=nocloud;s=/run/cloud-init/seed/",
        "s3_bucket": "hippius-compute-images",
        "s3_key_prefix": "tenant/x/",
        "luks_disk_sha256_hex": "a" * 64,
        "kernel_sha256_hex": "a" * 64,
        "initrd_sha256_hex": "a" * 64,
        "luks_header_sha256_hex": "a" * 64,
        "kek_vault_path": _kek_path(vm_id),
        "userdata": _USERDATA,
    }
    body.update(overrides)
    return body


# A reversible stand-in for Vault Transit, so a test can assert BOTH that
# what was staged is ciphertext AND which plaintext it wraps.
def _fake_ct(plaintext: bytes) -> bytes:
    return b"vault:v1:" + plaintext.hex().encode("ascii")


def _fake_pt(ciphertext: bytes) -> bytes:
    return bytes.fromhex(ciphertext.removeprefix(b"vault:v1:").decode())


@pytest.fixture
def stub_vault_put(monkeypatch):
    """Capture `put_kv` calls + return a fake version.

    Also stubs Transit: intake now WRAPS the userdata working copy before
    staging it (`launch.stage_userdata_working_copy`), so a `put_kv`-only
    stub would fail on the first Transit round-trip.
    """
    calls = []

    def fake_put(mount, path, value, *, cas=None):
        # `cas` is optional: the golden overlay KEK is written `cas=0`
        # (first-write-wins), the userdata staging is written without it.
        calls.append((mount, path, value))
        return vault_kv.VaultWriteResult(version=7)

    monkeypatch.setattr(launch_jobs.vault_kv, "put_kv", fake_put)
    monkeypatch.setattr(launch_jobs.vault_kv, "ensure_transit_key", lambda name: None)
    monkeypatch.setattr(
        launch_jobs.vault_kv, "transit_encrypt", lambda name, pt: _fake_ct(pt)
    )
    monkeypatch.setattr(
        launch_jobs.vault_kv, "transit_decrypt", lambda name, ct: _fake_pt(ct)
    )
    return calls


# ── POST /v1/vm/launch ───────────────────────────────────────────────


def test_launch_post_requires_auth(stub_vault_put) -> None:
    resp = APIClient().post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code in (401, 403)
    assert LaunchJob.objects.count() == 0


def test_launch_post_requires_root(authed_client, stub_vault_put) -> None:
    """§HIGH-1 — launch is root-only (mints L1 tickets, stages secrets,
    dispatches). A non-root authenticated client is 403."""
    resp = authed_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 403
    assert LaunchJob.objects.count() == 0


def test_launch_post_rejects_vm_id_path_traversal(root_client, stub_vault_put) -> None:
    """§HIGH-2 — vm_id is interpolated into Vault paths; a `../` escape is
    refused before any staging."""
    resp = root_client.post(
        LAUNCH_URL, _intent(vm_id="../other-tenant/x"), format="json"
    )
    assert resp.status_code == 400
    assert "vm_id" in resp.json()["error"]
    assert len(stub_vault_put) == 0
    assert LaunchJob.objects.count() == 0


def test_launch_post_rejects_kek_path_outside_vm_namespace(
    root_client, stub_vault_put
) -> None:
    """§HIGH-3 — a kek_vault_path pointing outside `{prefix}/{vm_id}/`
    (e.g. another tenant's KEK) is refused."""
    resp = root_client.post(
        LAUNCH_URL,
        _intent(kek_vault_path="hippius-compute/kbs/tenants/victim-vm/luks-kek"),
        format="json",
    )
    assert resp.status_code == 400
    assert "kek_vault_path" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_launch_post_accepts_auto_pin_on_prod(
    root_client, stub_vault_put, monkeypatch
) -> None:
    """#587 Phase 1A — `auto_pin_allowlist` is a PRODUCTION control-plane
    operation (the worker signs the §22 artifact with the prod root seed
    from Vault, not a committed dev seed), so it is accepted at intake even
    with VALI_ALLOW_PROD asserted — no longer gated."""
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_ALLOW_PROD", True)
    resp = root_client.post(
        LAUNCH_URL, _intent(auto_pin_allowlist=True), format="json"
    )
    assert resp.status_code == 202, resp.content
    assert resp.json()["state"] == "queued"


def test_launch_post_enqueues_job(root_client, stub_vault_put) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content
    body = resp.json()
    assert body["state"] == "queued"
    # `phase` is exposed on the response + stamped `queued` at intake.
    assert body["phase"] == "queued"
    assert body["vm_id"] == "vm-api-1"
    job = LaunchJob.objects.get(job_id=body["job_id"])
    assert job.state == LaunchJobState.QUEUED.value
    assert job.phase == LaunchPhase.QUEUED.value
    assert job.userdata_vault_version == 7
    # The userdata was staged to Vault (one put) — Transit-WRAPPED. The
    # plaintext cloud-init (SSH keys, tokens, the NetBird key the launch
    # substitutes into it) never reaches Vault storage in the clear, and
    # §24 destroys the key that opens it.
    assert len(stub_vault_put) == 1
    _mount, path, staged = stub_vault_put[0]
    # Its OWN path: the intake template, not the working copy
    # `launch_on_miner` keeps in version lockstep with the canonical copy.
    assert path.endswith("/userdata-intake")
    assert staged.startswith(b"vault:"), staged[:32]
    assert b"ssh_pwauth" not in staged
    assert _fake_pt(staged) == _USERDATA.encode("utf-8")


def test_launch_post_wraps_the_working_copy_under_the_key_vali_may_open(
    root_client, stub_vault_put, monkeypatch
) -> None:
    """TWO per-VM Transit keys, deliberately. The canonical userdata the
    ticket binds is wrapped under `kek-<vm_id>`, which vali may encrypt
    with and NEVER decrypt — only the attested KBS opens it. This working
    copy is wrapped under `ud-<vm_id>`, which vali may open, because the
    NetBird substitution and the §6 digest re-derivation still need the
    plaintext after intake. Wrapping it under the KEK key instead would
    strand both."""
    keys: list[str] = []
    monkeypatch.setattr(
        launch_jobs.vault_kv, "transit_encrypt", lambda name, pt: keys.append(name) or _fake_ct(pt)
    )
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content
    assert keys == ["ud-vm-api-1"], keys


def test_launch_post_normalizes_kv_data_prefix_on_kek_path(
    root_client, stub_vault_put
) -> None:
    """A caller (or a bake) that supplies the KV-v2 DATA path
    `secret/data/<prefix>/<vm>/luks-kek` (the `vali_tenant_bake_create
    --kek-vault-path` CLI convention) must be accepted: the launch strips
    the leading `<mount>/data/` so it passes the namespace check and the
    worker's `get_kv` reads the right path (no double `/data/`)."""
    from django.conf import settings

    mount = getattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
    rel = _kek_path("vm-api-1")  # hippius-compute/kbs/tenants/vm-api-1/luks-kek
    data_form = f"{mount}/data/{rel}"
    resp = root_client.post(
        LAUNCH_URL, _intent(kek_vault_path=data_form), format="json"
    )
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    # Stored KV-relative (no `secret/data/` prefix) — what get_kv expects.
    assert job.kek_vault_path == rel


def test_launch_post_userdata_never_touches_the_db(root_client, stub_vault_put) -> None:
    """§20 — the cloud-init plaintext must not be persisted on the row."""
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    blob = repr(job.spec_json) + job.userdata_vault_path + job.kek_vault_path
    assert "ssh_pwauth" not in blob
    assert "userdata" not in job.spec_json


def test_launch_post_rejects_a_vault_prefixed_userdata(root_client, stub_vault_put) -> None:
    """`vault:` is the discriminator for "already Transit ciphertext"
    wherever a staged userdata is read back — a caller must not be able to
    set it. The userdata here also carries the NetBird placeholder, so the
    `vault:` guard is the only thing that can reject it."""
    resp = root_client.post(
        LAUNCH_URL,
        _intent(userdata="vault:v1:deadbeef\n# {{NETBIRD_SETUP_KEY}}\n"),
        format="json",
    )
    assert resp.status_code == 400, resp.content
    assert LaunchJob.objects.count() == 0


@pytest.mark.parametrize("bad", [59, 86401, 30 * 86400])
def test_launch_post_bounds_the_ticket_lifetime(root_client, stub_vault_put, bad) -> None:
    """The minted ticket authorizes releasing this VM's KEK + userdata to
    whoever attests, so its lifetime is a security parameter — an
    unbounded `expiry_seconds` let a caller mint one redeemable for a
    year."""
    resp = root_client.post(LAUNCH_URL, _intent(expiry_seconds=bad), format="json")
    assert resp.status_code == 400, resp.content
    assert "expiry_seconds" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


@pytest.mark.parametrize("ok", [60, 3600, 86400])
def test_launch_post_accepts_the_lifetime_boundaries(root_client, stub_vault_put, ok) -> None:
    """Both ends inclusive — a bound that rejects its own endpoints is a
    different bound from the documented one."""
    resp = root_client.post(
        LAUNCH_URL, _intent(vm_id=f"vm-exp-{ok}", expiry_seconds=ok), format="json"
    )
    assert resp.status_code == 202, resp.content


def test_launch_post_refuses_a_decommissioned_vm_id(root_client, stub_vault_put) -> None:
    """§24 crypto-erased that vm_id: its Transit keys are destroyed and its
    KV blobs deleted. Staging fresh secrets under it recreates exactly the
    material the erase removed — and a second decommission is refused for
    an already-Destroyed VM, so nothing can reach it again."""
    from apps.lifecycle.models import Vm, VmState

    Vm.objects.create(
        vm_id="vm-api-1",
        tenant_id="t-api",
        lease_id="lease-1",
        state=VmState.DESTROYED,
        generation=1,
    )
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 409, resp.content
    assert LaunchJob.objects.count() == 0
    # …and nothing was staged before the refusal.
    assert stub_vault_put == []


def test_launch_post_missing_required_field_is_400(root_client, stub_vault_put) -> None:
    body = _intent()
    del body["luks_header_sha256_hex"]
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 400
    assert LaunchJob.objects.count() == 0


def test_launch_post_missing_kek_path_is_400(root_client, stub_vault_put) -> None:
    body = _intent()
    del body["kek_vault_path"]
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 400


def test_launch_post_empty_userdata_is_400(root_client, stub_vault_put) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(userdata=""), format="json")
    assert resp.status_code == 400


def test_launch_post_bad_netbird_template_is_400(root_client, stub_vault_put) -> None:
    # netbird on (the default) but the userdata lacks the placeholder.
    resp = root_client.post(
        LAUNCH_URL,
        _intent(userdata="#cloud-config\nssh_pwauth: true\n"),
        format="json",
    )
    assert resp.status_code == 400
    assert "NETBIRD_SETUP_KEY" in resp.json()["error"]


def test_launch_post_custom_netbird_hostname_is_400(root_client, stub_vault_put) -> None:
    # The peer is persistent and revoked BY NAME: a name vali did not choose
    # would be a peer nothing ever deletes.
    resp = root_client.post(
        LAUNCH_URL,
        _intent(netbird_hostname_template="hippius-tenant-{vm_id}-x"),
        format="json",
    )
    assert resp.status_code == 400
    assert "netbird_hostname_template" in resp.json()["error"]


def test_launch_post_netbird_opt_out_skips_placeholder_check(
    root_client, stub_vault_put
) -> None:
    # Explicit opt-out: a plain userdata (no placeholder) is accepted.
    resp = root_client.post(
        LAUNCH_URL,
        _intent(enable_netbird=False, userdata="#cloud-config\nssh_pwauth: true\n"),
        format="json",
    )
    assert resp.status_code == 202, resp.content


def test_launch_post_one_active_launch_per_vm_is_409(root_client, stub_vault_put) -> None:
    first = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert first.status_code == 202
    second = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert second.status_code == 409
    assert second.json()["category"] == "conflict"


# ── GET /v1/vm/launch/<job_id> ───────────────────────────────────────


def test_launch_get_returns_state(root_client, stub_vault_put) -> None:
    job_id = root_client.post(LAUNCH_URL, _intent(), format="json").json()["job_id"]
    resp = root_client.get(reverse("vm_launch_job", args=[job_id]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["job_id"] == job_id
    # `_serialize_launch` includes the fine-grained `phase`.
    assert body["phase"] == "queued"


def test_launch_get_unknown_is_404(authed_client) -> None:
    # GET poll stays IsAuthenticated (not root-only) — a non-root client polls.
    resp = authed_client.get(reverse("vm_launch_job", args=["nope"]))
    assert resp.status_code == 404


# ── worker (vali_launch_tick / run_job / claim) ──────────────────────


def _queue_job(stub_vault_put, root_client) -> LaunchJob:
    job_id = root_client.post(LAUNCH_URL, _intent(), format="json").json()["job_id"]
    return LaunchJob.objects.get(job_id=job_id)


def _stub_secrets(monkeypatch) -> None:
    monkeypatch.setattr(
        launch_jobs.vault_kv, "get_kv", lambda mount, path, **kw: b"\x00" * 32
    )


def _ok_launch_vm(spec, decided_by, *, on_phase=None, queued_for_s=0.0):
    """A stub `launch_vm` that mimics the in-process placing→dispatching
    progress callbacks the real one fires, then accepts."""
    if on_phase is not None:
        on_phase("placing")
        on_phase("dispatching")
    return launch.LaunchResult(
        ok=True,
        outcome="miner-accepted",
        vm_id=spec.vm_id,
        miner_id="miner-a",
        miner_node_id="0" * 64,
        ticket_id="tk-1",
        placement_id="pl-1",
        emit={"ok": True},
    )


def test_worker_runs_and_records_success(root_client, stub_vault_put, monkeypatch) -> None:
    _queue_job(stub_vault_put, root_client)
    _stub_secrets(monkeypatch)
    monkeypatch.setattr(launch_jobs.launch, "launch_vm", _ok_launch_vm)

    assert launch_jobs.tick_once() is True
    job = LaunchJob.objects.get(vm_id="vm-api-1")
    assert job.state == LaunchJobState.SUCCEEDED.value
    assert job.phase == LaunchPhase.LAUNCHED.value
    assert job.miner_id == "miner-a"
    assert job.result_json["ticket_id"] == "tk-1"
    assert job.finished_at is not None


def test_worker_advances_phase_through_expected_sequence(
    root_client, stub_vault_put, monkeypatch
) -> None:
    """The worker advances `phase` queued → staging → placing → dispatching
    → launched on a happy path (additive instrumentation over `state`)."""
    _queue_job(stub_vault_put, root_client)
    _stub_secrets(monkeypatch)

    seen: list[str] = []
    orig_set_phase = launch_jobs._set_phase

    def spy(job, phase):
        seen.append(phase.value)
        orig_set_phase(job, phase)

    monkeypatch.setattr(launch_jobs, "_set_phase", spy)
    monkeypatch.setattr(launch_jobs.launch, "launch_vm", _ok_launch_vm)

    assert launch_jobs.tick_once() is True
    # `queued` was stamped at intake; the worker drives staging → placing →
    # dispatching via `_set_phase`, then the terminal CAS writes `launched`.
    assert seen == ["staging", "placing", "dispatching"]
    job = LaunchJob.objects.get(vm_id="vm-api-1")
    assert job.phase == LaunchPhase.LAUNCHED.value


def test_worker_records_failure(root_client, stub_vault_put, monkeypatch) -> None:
    _queue_job(stub_vault_put, root_client)
    _stub_secrets(monkeypatch)
    monkeypatch.setattr(
        launch_jobs.launch,
        "launch_vm",
        lambda spec, decided_by, on_phase=None, queued_for_s=0.0: launch.LaunchResult(
            ok=False, outcome="no-eligible-miner", vm_id=spec.vm_id
        ),
    )

    assert launch_jobs.tick_once() is True
    job = LaunchJob.objects.get(vm_id="vm-api-1")
    assert job.state == LaunchJobState.FAILED.value
    assert job.phase == LaunchPhase.FAILED.value
    assert job.reason == "no-eligible-miner"


def test_worker_dispatch_raise_fails_the_job_not_stuck_running(
    root_client, stub_vault_put, monkeypatch
) -> None:
    """`launch_vm` RAISING (e.g. OrderDispatchUnavailable when the miner /
    Edge is unreachable) must finish the job FAILED — not leave it wedged
    `running` forever (claim_one only re-picks `queued`). Regression for the
    #587 launch-tick stall."""
    _queue_job(stub_vault_put, root_client)
    _stub_secrets(monkeypatch)

    def raise_unavailable(spec, decided_by, on_phase=None, queued_for_s=0.0):
        raise order_dispatch.OrderDispatchUnavailable("edge-order: peer unreachable")

    monkeypatch.setattr(launch_jobs.launch, "launch_vm", raise_unavailable)

    assert launch_jobs.tick_once() is True
    job = LaunchJob.objects.get(vm_id="vm-api-1")
    assert job.state == LaunchJobState.FAILED.value
    assert job.phase == LaunchPhase.FAILED.value
    assert "launch-error" in job.reason
    assert "OrderDispatchUnavailable" in job.reason
    assert job.finished_at is not None
    # FAILED is terminal → the vm_id is freed for a re-POST (in-flight
    # unique index excludes succeeded/failed).
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-api-1"), format="json")
    assert resp.status_code == 202, resp.content


def test_worker_secret_fetch_failure_fails_the_job(
    root_client, stub_vault_put, monkeypatch
) -> None:
    _queue_job(stub_vault_put, root_client)

    def boom(mount, path, **kw):
        raise launch_jobs.EffectError("vault down")

    monkeypatch.setattr(launch_jobs.vault_kv, "get_kv", boom)
    monkeypatch.setattr(
        launch_jobs.launch, "launch_vm",
        lambda *a, **k: pytest.fail("must not launch without secrets"),
    )

    assert launch_jobs.tick_once() is True
    job = LaunchJob.objects.get(vm_id="vm-api-1")
    assert job.state == LaunchJobState.FAILED.value
    assert job.phase == LaunchPhase.FAILED.value
    assert "secret-fetch-failed" in job.reason


# ── KEK-HSM Phase 1 — vali never reads a plaintext tenant disk KEK ────


def test_launch_post_rejects_non_canonical_kek_leaf(root_client, stub_vault_put) -> None:
    """KEK-HSM Phase 1: `kek_vault_path` must be EXACTLY the canonical
    `{prefix}/{vm_id}/luks-kek` the KBS releases from. A different leaf
    under the vm namespace (here `luks-kek-staging`) would force the worker
    to copy — and thus read — the KEK, so it is rejected at POST."""
    from django.conf import settings

    bad = f"{settings.VALI_VAULT_KV_PREFIX}/vm-api-1/luks-kek-staging"
    resp = root_client.post(
        LAUNCH_URL, _intent(kek_vault_path=bad), format="json"
    )
    assert resp.status_code == 400, resp.content
    assert "kek_vault_path" in resp.json()["error"]


def test_worker_never_reads_the_plaintext_kek(
    root_client, stub_vault_put, monkeypatch
) -> None:
    """KEK-HSM Phase 1 / C1: the async launch worker must pass NO plaintext
    KEK into `launch_vm` and must NEVER read a `luks-kek` path back — it
    reads only the userdata transport blob. The KEK stays where the caller
    staged it (canonical path); `launch_vm` reads only its KV version."""
    _queue_job(stub_vault_put, root_client)

    read_paths: list[str] = []

    read_versions: list = []

    def spy_get_kv(mount, path, **kw):
        read_paths.append(path)
        read_versions.append(kw.get("version"))
        return _fake_ct(_USERDATA.encode())

    monkeypatch.setattr(launch_jobs.vault_kv, "get_kv", spy_get_kv)

    captured: dict = {}

    def fake_launch_vm(spec, decided_by, on_phase=None, queued_for_s=0.0):
        captured["kek_bytes"] = spec.kek_bytes
        captured["userdata"] = spec.userdata
        return launch.LaunchResult(
            ok=True,
            outcome="miner-accepted",
            vm_id=spec.vm_id,
            miner_id="miner-a",
            miner_node_id="0" * 64,
            ticket_id="tk-1",
            placement_id="pl-1",
            emit={"ok": True},
        )

    monkeypatch.setattr(launch_jobs.launch, "launch_vm", fake_launch_vm)

    assert launch_jobs.tick_once() is True
    # No plaintext KEK is handed to the launch on the async path.
    assert captured["kek_bytes"] is None
    # The worker never read a luks-kek path back out of Vault.
    assert not any(p.endswith("/luks-kek") for p in read_paths), read_paths
    # It DID read the userdata working copy (the one legitimate read) —
    # and unwrapped it, since the NetBird substitution downstream needs
    # the plaintext.
    assert any("userdata-intake" in p for p in read_paths), read_paths
    # …at the version the row PINNED, never "latest": a second POST for
    # the same vm_id would otherwise change the bytes this queued job
    # consumes between intake and launch.
    assert read_versions == [7], read_versions
    assert captured["userdata"] == _USERDATA.encode("utf-8")


def test_claim_one_is_atomic(root_client, stub_vault_put) -> None:
    _queue_job(stub_vault_put, root_client)
    first = launch_jobs.claim_one()
    assert first is not None
    assert first.state == LaunchJobState.RUNNING.value
    # The job is no longer queued — a second claim finds nothing.
    assert launch_jobs.claim_one() is None


def test_tick_once_returns_false_on_empty_queue() -> None:
    assert launch_jobs.tick_once() is False


# ─── Tenant price ceiling (max_price_per_unit) ───────────────────────


def test_launch_post_threads_price_ceiling_into_spec(root_client, stub_vault_put) -> None:
    resp = root_client.post(
        LAUNCH_URL, _intent(max_price_per_unit=5_000_000), format="json"
    )
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["max_price_per_unit"] == 5_000_000


def test_launch_post_price_ceiling_defaults_to_none(root_client, stub_vault_put) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["max_price_per_unit"] is None


def test_launch_post_rejects_non_positive_price_ceiling(
    root_client, stub_vault_put
) -> None:
    for bad in (0, -1, "100", 1.5):
        resp = root_client.post(
            LAUNCH_URL, _intent(vm_id="vm-mpu", max_price_per_unit=bad), format="json"
        )
        assert resp.status_code == 400, (bad, resp.content)


# ── #587 Phase 1C — bake→launch chaining (_resolve_bake) ─────────────


def _make_succeeded_bake(**overrides):
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.tenant_bake.models import TenantBake, TenantBakeState

    sc, _ = ServiceClient.objects.get_or_create(
        scope=PrincipalScope.OPERATOR.value,
        name="bake-owner",
    )
    fields = dict(
        bake_id="bake-1",
        vm_id="vm-bake-1",
        base_image_url="https://s3.example/base.qcow2",
        base_image_sha256="a" * 64,
        size_gb=10,
        kek_vault_path="hippius-compute/kbs/tenants/vm-bake-1/luks-kek",
        s3_output_bucket="hippius-compute-images",
        s3_output_prefix="tenant/vm-bake-1/",
        state=TenantBakeState.SUCCEEDED.value,
        qcow2_sha256="1" * 64,
        kernel_sha256="2" * 64,
        initrd_sha256="3" * 64,
        luks_header_sha256="4" * 64,
        requested_by=sc,
    )
    fields.update(overrides)
    return TenantBake.objects.create(**fields)


def test_resolve_bake_fills_artifact_fields() -> None:
    _make_succeeded_bake()
    intent = {"bake_id": "bake-1"}
    launch_jobs._resolve_bake(intent)
    assert intent["kek_vault_path"] == "hippius-compute/kbs/tenants/vm-bake-1/luks-kek"
    assert intent["s3_bucket"] == "hippius-compute-images"
    assert intent["s3_key_prefix"] == "tenant/vm-bake-1/"
    assert intent["luks_disk_sha256_hex"] == "1" * 64
    assert intent["kernel_sha256_hex"] == "2" * 64
    assert intent["initrd_sha256_hex"] == "3" * 64
    assert intent["luks_header_sha256_hex"] == "4" * 64


def test_resolve_bake_caller_value_wins() -> None:
    _make_succeeded_bake()
    intent = {"bake_id": "bake-1", "s3_bucket": "operator-override"}
    launch_jobs._resolve_bake(intent)
    assert intent["s3_bucket"] == "operator-override"  # not overwritten


def test_resolve_bake_noop_without_bake_id() -> None:
    intent = {"s3_bucket": "x"}
    launch_jobs._resolve_bake(intent)  # no DB hit, no change
    assert intent == {"s3_bucket": "x"}


def test_resolve_bake_unknown_is_bad_field() -> None:
    intent = {"bake_id": "does-not-exist"}
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake(intent)
    assert exc.value.category == "bad-field"


def test_resolve_bake_not_succeeded_is_conflict() -> None:
    from apps.tenant_bake.models import TenantBakeState

    _make_succeeded_bake(state=TenantBakeState.RUNNING.value)
    intent = {"bake_id": "bake-1"}
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake(intent)
    assert exc.value.category == "conflict"


# ── golden-bake (option b) — disk_mode plumbing to the LaunchSpec ─────


def test_spec_json_defaults_disk_mode_to_legacy() -> None:
    # Absent from the intent → the legacy per-VM LUKS path (byte-identical).
    spec = launch_jobs._build_spec_json(_intent())
    assert spec["disk_mode"] == "legacy_luks"
    assert spec["verity_root_hash_hex"] == ""


def _golden_intent(**overrides) -> dict:
    """A golden POST body: the verity trio replaces the LUKS-header MAC."""
    body = _intent(
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex="b3" * 32,
        rootfs_img_sha256_hex="a1" * 32,
        rootfs_verity_sha256_hex="b2" * 32,
    )
    # A golden bake has no per-VM LUKS header — the intake must not need it.
    body.pop("luks_header_sha256_hex", None)
    body.update(overrides)
    return body


def test_spec_json_carries_golden_fields() -> None:
    spec = launch_jobs._build_spec_json(_golden_intent())
    assert spec["disk_mode"] == "golden_verity_overlay"
    assert spec["verity_root_hash_hex"] == "b3" * 32
    # The spec_json feeds `LaunchSpec(**spec_json, …)` — it must construct.
    launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"#cloud-config\n")


def test_spec_json_golden_needs_no_luks_header() -> None:
    """A golden POST carries NO `luks_header_sha256_hex` (the base is an
    unkeyed dm-verity volume). The intake must accept its absence and leave
    the field empty — no inert placeholder required."""
    spec = launch_jobs._build_spec_json(_golden_intent())
    assert spec["luks_header_sha256_hex"] == ""


def test_spec_json_golden_requires_verity_trio() -> None:
    """Golden mode requires the verity trio instead of the LUKS header — a
    missing member is a 400-class bad-field, not a silent unbootable launch."""
    for missing in (
        "verity_root_hash_hex",
        "rootfs_img_sha256_hex",
        "rootfs_verity_sha256_hex",
    ):
        body = _golden_intent()
        body.pop(missing)
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            launch_jobs._build_spec_json(body)
        assert missing in str(exc.value)
        assert exc.value.category == "bad-field"


def test_spec_json_legacy_still_requires_luks_header() -> None:
    """Legacy mode keeps the pre-golden contract: the LUKS-header MAC is
    mandatory (the guest asserts it before unlocking with the KEK)."""
    body = _intent()
    del body["luks_header_sha256_hex"]
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._build_spec_json(body)
    assert "luks_header_sha256_hex" in str(exc.value)


@pytest.fixture
def stub_golden_transit(monkeypatch):
    """Stub the Vault Transit primitives vali uses to provision the golden
    overlay-upper KEK (datakey/wrapped), so the golden intake path runs
    without a live Vault."""
    calls = {"ensure": [], "datakey": []}

    def fake_ensure(name):
        calls["ensure"].append(name)

    def fake_datakey(name):
        calls["datakey"].append(name)
        return b"vault:v1:GOLDENWRAPPEDKEK"

    monkeypatch.setattr(launch_jobs.vault_kv, "ensure_transit_key", fake_ensure)
    monkeypatch.setattr(
        launch_jobs.vault_kv, "transit_datakey_wrapped", fake_datakey
    )
    # Intake also wraps the userdata working copy under `ud-<vm_id>`.
    monkeypatch.setattr(
        launch_jobs.vault_kv, "transit_encrypt", lambda name, pt: _fake_ct(pt)
    )
    return calls


def test_launch_post_golden_provisions_wrapped_kek(
    root_client, stub_vault_put, stub_golden_transit
) -> None:
    """Defect #1 — the async golden path must stage a Transit-WRAPPED KEK
    (`vault:v1:…`) the KBS `require_wrapped_kek` gate accepts on release. A
    golden POST carries NO `kek_vault_path` (the golden bake stages no KEK);
    vali generates the per-VM overlay KEK inside Vault (never holding
    plaintext) and stages the ciphertext at the canonical luks-kek path."""
    from django.conf import settings

    body = _golden_intent(vm_id="golden-api-x")
    body.pop("kek_vault_path", None)  # golden bake stages no KEK
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 202, resp.content

    prefix = settings.VALI_VAULT_KV_PREFIX
    canonical = f"{prefix}/golden-api-x/luks-kek"
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.kek_vault_path == canonical
    # Vault GENERATED the KEK (datakey/wrapped on the per-VM transit key) —
    # vali never held the plaintext (C1 / KEK-HSM Phase 4).
    assert stub_golden_transit["datakey"] == ["kek-golden-api-x"]
    # The bytes staged at the canonical path are the vault:-wrapped ciphertext.
    kek_puts = [v for _, p, v in stub_vault_put if p == canonical]
    assert kek_puts == [b"vault:v1:GOLDENWRAPPEDKEK"]
    assert kek_puts[0].startswith(b"vault:")


def test_launch_post_golden_respects_supplied_kek_path(
    root_client, stub_vault_put, stub_golden_transit
) -> None:
    """A golden caller that pre-staged its OWN (wrapped) KEK and supplied
    `kek_vault_path` is respected — vali does not overwrite it."""
    body = _golden_intent(vm_id="golden-api-y")
    body["kek_vault_path"] = _kek_path("golden-api-y")
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 202, resp.content
    # No server-side generation when the caller supplied the path.
    assert stub_golden_transit["datakey"] == []


def test_launch_post_golden_kek_first_write_wins(
    root_client, stub_golden_transit, monkeypatch
) -> None:
    """DATA-LOSS GUARD — a RELAUNCH of an existing golden VM (e.g. reboot-
    recovery) re-enters `_provision_golden_overlay_kek` because `_resolve_bake`
    drops the bake's `kek_vault_path`. The KEK write is `cas=0` (create-only);
    when a KEK is ALREADY staged, Vault refuses (`VaultCasConflict`) and vali
    REUSES the existing datakey rather than overwriting it — overwriting would
    strand the existing overlay (formatted with the ORIGINAL datakey) and
    destroy tenant data."""
    from django.conf import settings

    prefix = settings.VALI_VAULT_KV_PREFIX
    canonical = f"{prefix}/golden-relaunch/luks-kek"
    puts: list[tuple[str, int | None]] = []

    def fake_put(mount, path, value, *, cas=None):
        puts.append((path, cas))
        # The luks-kek path already exists → `cas=0` create-only is refused.
        if path == canonical and cas == 0:
            raise vault_kv.VaultCasConflict("check-and-set conflict (cas=0)")
        return vault_kv.VaultWriteResult(version=7)

    monkeypatch.setattr(launch_jobs.vault_kv, "put_kv", fake_put)

    body = _golden_intent(vm_id="golden-relaunch")
    body.pop("kek_vault_path", None)  # golden bake stages no KEK → re-provision
    resp = root_client.post(LAUNCH_URL, body, format="json")

    # The relaunch must SUCCEED — a pre-existing KEK is not an error.
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.kek_vault_path == canonical
    # The KEK write was attempted `cas=0` (create-only) at the canonical path…
    assert (canonical, 0) in puts
    # …and it was the ONLY write to that path — the conflict was NOT retried
    # without cas (which would have OVERWRITTEN the existing datakey).
    assert [c for p, c in puts if p == canonical] == [0]


# ── golden-bake PR6 — _resolve_bake resolves the golden fields ───────


def test_resolve_bake_golden_fills_verity_fields_not_kek() -> None:
    from apps.tenant_bake.models import TenantBakeDiskMode

    _make_succeeded_bake(
        disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
        # A golden bake stores NO qcow2 / luks-header (the base is unkeyed
        # dm-verity); it stores the verity artifacts instead.
        qcow2_sha256="",
        luks_header_sha256="",
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
    )
    intent = {"bake_id": "bake-1"}
    launch_jobs._resolve_bake(intent)
    assert intent["disk_mode"] == "golden_verity_overlay"
    assert intent["rootfs_img_sha256_hex"] == "a1" * 32
    assert intent["rootfs_verity_sha256_hex"] == "b2" * 32
    assert intent["verity_root_hash_hex"] == "c3" * 32
    assert intent["kernel_sha256_hex"] == "2" * 64
    assert intent["initrd_sha256_hex"] == "3" * 64
    assert intent["s3_bucket"] == "hippius-compute-images"
    assert intent["s3_key_prefix"] == "tenant/vm-bake-1/"
    # The golden fetch slot carries rootfs.img; `luks_disk_sha256_hex` is
    # unused on the golden path but filled (with the rootfs.img sha) only
    # to satisfy the required-non-empty intent check.
    assert intent["luks_disk_sha256_hex"] == "a1" * 32
    # A golden bake stages NO KEK — the resolver must NOT copy the bake's
    # kek_vault_path (the launch's per-VM luks-kek is caller-supplied).
    assert "kek_vault_path" not in intent
    # No per-VM LUKS header on a dm-verity base ⇒ golden cmdline branch.
    assert not intent.get("luks_header_sha256_hex")


# ── golden-everywhere — launch-by-image (_resolve_image) ─────────────


def _bless_golden_image(image_name: str, bake_id: str, distro: str = "") -> None:
    """Create a GoldenImage catalog row (the operator-controlled mapping)."""
    from django.utils import timezone

    from apps.images.models import GoldenImage

    GoldenImage.objects.create(
        image_name=image_name,
        distro=distro or image_name,
        bake_id=bake_id,
        blessed_at=timezone.now(),
        blessed_by="ops",
    )


def _make_golden_bake(bake_id: str = "gb-img-1"):
    """A Succeeded golden bake the catalog can point an image at."""
    from apps.tenant_bake.models import TenantBakeDiskMode

    return _make_succeeded_bake(
        bake_id=bake_id,
        vm_id=f"vm-{bake_id}"[:64],
        disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
        qcow2_sha256="",
        luks_header_sha256="",
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
    )


def test_resolve_image_maps_to_blessed_golden_bake() -> None:
    """`image=ubuntu` resolves to the blessed golden bake → the golden launch
    spec (transparent). The tenant supplied only the NAME."""
    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    intent = {"image": "ubuntu"}
    launch_jobs._resolve_bake(intent)
    # Resolved to the blessed bake and through the golden resolution path.
    assert intent["bake_id"] == "gb-ubuntu"
    assert intent["disk_mode"] == "golden_verity_overlay"
    assert intent["rootfs_img_sha256_hex"] == "a1" * 32
    assert intent["verity_root_hash_hex"] == "c3" * 32
    # A golden bake stages no KEK — the resolver must not copy one.
    assert "kek_vault_path" not in intent


def test_resolve_image_can_only_reach_the_blessed_bake() -> None:
    """Adversarial: a tenant-supplied `image` resolves ONLY to the operator-
    blessed bake — there is no path to an arbitrary/other bake_id. Even with
    a second (un-blessed) golden bake present, `image` yields the blessed one."""
    _make_golden_bake(bake_id="gb-blessed")
    _make_golden_bake(bake_id="gb-arbitrary-unblessed")
    _bless_golden_image("ubuntu", "gb-blessed")
    intent = {"image": "ubuntu"}
    launch_jobs._resolve_bake(intent)
    assert intent["bake_id"] == "gb-blessed"  # never the un-blessed one


def test_resolve_image_unknown_fails_closed() -> None:
    """An unknown image is rejected (bad-field) — it never falls through to a
    launch off some default/arbitrary bake."""
    intent = {"image": "not-a-real-image"}
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake(intent)
    assert exc.value.category == "bad-field"
    assert "not a known launchable image" in str(exc.value)
    assert "bake_id" not in intent


def test_resolve_image_and_bake_id_conflict_rejected() -> None:
    """`image` + `bake_id` together are rejected — a tenant cannot pin a
    blessed image name to a bake_id of their own choosing."""
    _make_golden_bake(bake_id="gb-blessed")
    _bless_golden_image("ubuntu", "gb-blessed")
    intent = {"image": "ubuntu", "bake_id": "some-other-bake"}
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake(intent)
    assert exc.value.category == "bad-field"
    assert "mutually exclusive" in str(exc.value)


def test_resolve_image_bad_charset_rejected() -> None:
    intent = {"image": "../etc/passwd"}
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake(intent)
    assert exc.value.category == "bad-field"


def _guest_build(release: int, *, bake_initrd: str = "3" * 64, initrd: str = "4d" * 32):
    from apps.orchestration.models import GuestComponentRelease, GuestInitrdBuild

    rel, _ = GuestComponentRelease.objects.get_or_create(
        version=release,
        defaults={"commit": "c" * 40, "security_epoch": 1, "squashfs_sha256": "d" * 64},
    )
    return GuestInitrdBuild.objects.create(
        release=rel,
        source_bake_id="gb-ubuntu",
        family="initramfs-tools",
        kernel_sha256="2" * 64,
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
        base_initrd_sha256=bake_initrd,
        release_cpio_sha256="e" * 64,
        initrd_sha256=initrd,
        s3_bucket="hippius-compute-images",
        s3_key_prefix=f"tenant/golden-ubuntu-gr{release}/",
        measurement={},
    )


def test_resolve_image_boots_the_images_blessed_guest_release() -> None:
    """Phase 7: an image with a blessed guest release launches the bake's
    kernel + dm-verity base with the release's build of its initrd."""
    from apps.images.models import GoldenImage

    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    build = _guest_build(2)
    GoldenImage.objects.filter(image_name="ubuntu").update(guest_release=2)
    intent = {"image": "ubuntu"}
    launch_jobs._resolve_bake(intent)
    assert (intent["s3_key_prefix"], intent["initrd_sha256_hex"]) == (
        build.s3_key_prefix,
        build.initrd_sha256,
    )
    assert intent["kernel_sha256_hex"] == "2" * 64, "the bake's kernel"
    assert intent["verity_root_hash_hex"] == "c3" * 32, "the bake's dm-verity base"
    assert "_image_guest_release" not in intent


def test_a_withdrawn_guest_build_fails_the_image_launch_closed() -> None:
    from django.utils import timezone

    from apps.images.models import GoldenImage
    from apps.orchestration.models import GuestInitrdBuild

    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    build = _guest_build(2)
    GoldenImage.objects.filter(image_name="ubuntu").update(guest_release=2)
    GuestInitrdBuild.objects.filter(pk=build.pk).update(withdrawn_at=timezone.now())
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake({"image": "ubuntu"})
    assert exc.value.category == "conflict"


def test_a_caller_cannot_pick_the_artifacts_or_the_guest_release() -> None:
    from apps.images.models import GoldenImage

    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    _guest_build(2)
    GoldenImage.objects.filter(image_name="ubuntu").update(guest_release=2)
    with pytest.raises(launch_jobs.LaunchIntentError):
        launch_jobs._resolve_bake({"image": "ubuntu", "initrd_sha256_hex": "f" * 64})
    # A spoofed private key is dropped: the bare image resolves to its bake.
    GoldenImage.objects.filter(image_name="ubuntu").update(guest_release=None)
    intent = {"image": "ubuntu", "_image_guest_release": 2}
    launch_jobs._resolve_bake(intent)
    assert intent["initrd_sha256_hex"] == "3" * 64
    assert "_image_guest_release" not in intent


@pytest.mark.parametrize(
    "field", ["rootfs_img_sha256_hex", "verity_root_hash_hex", "kernel_sha256_hex", "disk_mode"]
)
def test_a_launch_by_image_takes_no_caller_artifact(field: str) -> None:
    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake({"image": "ubuntu", field: "f" * 64})
    assert exc.value.category == "bad-field"


def test_resolve_image_noop_without_image() -> None:
    intent = {"s3_bucket": "x"}
    launch_jobs._resolve_bake(intent)
    assert intent == {"s3_bucket": "x"}


def test_launch_post_by_image_enqueues_golden_job(
    root_client, stub_vault_put, stub_golden_transit
) -> None:
    """Full POST path: `image=ubuntu` (NO bake_id) resolves the blessed golden
    bake → a queued launch job with the golden spec + a server-provisioned
    wrapped overlay KEK. Proves launch-by-image end-to-end at intake."""
    from django.conf import settings

    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    # A launch-by-image body: only the image NAME + the non-bake intent
    # fields. The bake resolves the artifacts; the golden overlay KEK is
    # provisioned server-side (no kek_vault_path supplied).
    body = _intent(vm_id="img-launch-1")
    body["image"] = "ubuntu"
    for k in (
        "s3_bucket",
        "s3_key_prefix",
        "luks_disk_sha256_hex",
        "kernel_sha256_hex",
        "initrd_sha256_hex",
        "luks_header_sha256_hex",
        "kek_vault_path",
    ):
        body.pop(k, None)
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["disk_mode"] == "golden_verity_overlay"
    assert job.spec_json["rootfs_img_sha256_hex"] == "a1" * 32
    canonical = f"{settings.VALI_VAULT_KV_PREFIX}/img-launch-1/luks-kek"
    assert job.kek_vault_path == canonical
    # `image` is sugar — it never leaks into the launch spec.
    assert "image" not in job.spec_json


def test_launch_post_unknown_image_is_400(root_client, stub_vault_put) -> None:
    """A tenant naming an un-blessed image is rejected (fail closed) — no job."""
    body = _intent(vm_id="img-unknown-1")
    body["image"] = "not-blessed"
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 400, resp.content
    assert "not a known launchable image" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_launch_post_image_and_bake_id_conflict_is_400(
    root_client, stub_vault_put
) -> None:
    body = _intent(vm_id="img-conflict-1")
    body["image"] = "ubuntu"
    body["bake_id"] = "some-bake"
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 400, resp.content
    assert "mutually exclusive" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


# ─── Region constraint (region) ──────────────────────────────────────


def test_launch_post_region_defaults_to_unconstrained(root_client, stub_vault_put) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["region"] == ""


def test_launch_post_uppercases_the_region(root_client, stub_vault_put) -> None:
    """`fr` and `FR` are one region; `MinerLocation.region` is uppercase and
    the gate compares with `==`."""
    resp = root_client.post(LAUNCH_URL, _intent(region="fr"), format="json")
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["region"] == "FR"


@pytest.mark.parametrize("bad", ["FRA", "F1", "France", "F", 12, " "])
def test_launch_post_rejects_a_malformed_region(root_client, stub_vault_put, bad) -> None:
    """Shape-checked at intake: an unparseable region would otherwise match
    no miner and surface minutes later as a fleet-wide `no-miner-in-region`
    — a capacity problem that is really a typo."""
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-region", region=bad), format="json")
    if bad == " ":
        # Whitespace-only is "nothing asked", same as omitted.
        assert resp.status_code == 202, resp.content
        assert LaunchJob.objects.get(job_id=resp.json()["job_id"]).spec_json["region"] == ""
        return
    assert resp.status_code == 400, (bad, resp.content)
    assert resp.json()["category"] == "bad-field"
    assert "region" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_region_survives_into_the_launch_spec() -> None:
    """The worker builds `LaunchSpec(**spec_json, …)`; the field must exist
    there, and a spec WITHOUT it (every pre-region job) must still build."""
    spec = launch_jobs._build_spec_json(_intent(region="de"))
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"x").region == "DE"
    old = {k: v for k, v in spec.items() if k != "region"}
    assert launch.LaunchSpec(**old, kek_bytes=None, userdata=b"x").region == ""


def test_launch_threads_the_region_into_placement(monkeypatch) -> None:
    """End to end through the real scheduler: a region nobody is detected
    in fails the launch `no-miner-in-region` — it never places elsewhere."""
    from apps.scheduler import chain
    from apps.scheduler.tests.factories import make_dispatchable_identity, make_miner, make_snapshot

    make_dispatchable_identity(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    spec = launch.LaunchSpec(
        **launch_jobs._build_spec_json(_intent(vm_id="vm-region-e2e", region="FR")),
        kek_bytes=None,
        userdata=b"#cloud-config\n",
    )
    from apps.identity.models import PrincipalScope, ServiceClient

    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    result = launch.launch_vm(spec, actor)
    assert result.ok is False
    assert result.outcome == "no-miner-in-region"


def test_launch_post_refuses_a_flavor_above_the_offered_maximum(
    root_client, stub_vault_put, settings
) -> None:
    """In the catalogue is not for sale: 4xlarge is refused at intake with
    its own category, and no job is created (so nothing is minted or
    placed) — even on a fleet whose hardware could hold it."""
    settings.VALI_SCHEDULER_MAX_FLAVOR = "2xlarge"
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-big", flavor="4xlarge"), format="json")
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "flavor-not-offered"
    assert "2xlarge" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_launch_post_accepts_the_largest_offered_flavor(root_client, stub_vault_put) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-2xl", flavor="2xlarge"), format="json")
    assert resp.status_code == 202, resp.content


def test_4xlarge_is_offered_by_default(root_client, stub_vault_put) -> None:
    """No cap unless one is configured: the whole grid is for sale."""
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-4xl", flavor="4xlarge"), format="json")
    assert resp.status_code == 202, resp.content


def test_a_refused_golden_launch_writes_nothing_to_vault(
    root_client, monkeypatch, settings
) -> None:
    """A golden launch (image-based, no `kek_vault_path`) provisions its
    overlay KEK in Vault early. An above-cap flavor must be refused BEFORE
    that — otherwise the Transit key and the KV entry are stranded under a
    vm_id with no `Vm` row, where §24 never looks."""
    settings.VALI_SCHEDULER_MAX_FLAVOR = "2xlarge"
    touched: list[str] = []

    def fail(*_a: object, **_k: object) -> None:
        touched.append("vault")
        raise AssertionError("Vault touched for a refused launch")

    monkeypatch.setattr(launch_jobs, "_provision_golden_overlay_kek", fail)
    monkeypatch.setattr(vault_kv, "put_kv", fail)
    body = _intent(vm_id="vm-gold-big", flavor="4xlarge")
    body.pop("kek_vault_path")
    body["image"] = "ubuntu"
    resp = root_client.post(LAUNCH_URL, body, format="json")
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "flavor-not-offered"
    assert touched == []
    assert LaunchJob.objects.count() == 0


def test_the_cap_is_validated_when_the_app_loads(settings) -> None:
    from django.apps import apps
    from django.core.exceptions import ImproperlyConfigured

    settings.VALI_SCHEDULER_MAX_FLAVOR = "huge"
    with pytest.raises(ImproperlyConfigured, match="not a flavor"):
        apps.get_app_config("orchestration").ready()


def test_intake_serializes_with_the_vm_row_lock(root_client, stub_vault_put, monkeypatch) -> None:
    """Intake accepts an ACTIVE vm_id; the job it creates becomes that VM's
    launch record once it succeeds. It takes the Vm row lock BEFORE creating
    the job, so a writer deciding under that lock (`vali_swap_vm_initrd`)
    either sees the job or precedes it."""
    from apps.lifecycle.models import Vm

    from .factories import make_vm

    make_vm("vm-api-1")
    events: list[str] = []
    real_lock = Vm.objects.select_for_update
    real_create = LaunchJob.objects.create

    def lock(*a, **k):
        events.append("lock-vm")
        return real_lock(*a, **k)

    def create(*a, **k):
        events.append("create-job")
        return real_create(*a, **k)

    monkeypatch.setattr(Vm.objects, "select_for_update", lock)
    monkeypatch.setattr(LaunchJob.objects, "create", create)
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content
    assert events == ["lock-vm", "create-job"]


def test_resolve_bake_refuses_a_cdn_node_bake() -> None:
    """CDN plan I3 — no launch uses a cdn-node image until the CDN launch
    role exists (V2/V3)."""
    bake = _make_succeeded_bake()
    bake.profile = "cdn-node"
    bake.save(update_fields=["profile"])
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._resolve_bake({"bake_id": "bake-1"})
    assert exc.value.category == "image-restricted"
