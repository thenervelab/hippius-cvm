"""Tests for the Hippius validator client — HTTP layer fully mocked.

Sync paths use ``responses``; async paths use ``respx``. No live calls.
"""

from __future__ import annotations

import httpx
import pytest
import responses
import respx

from hippius_validator_client import (
    AsyncHippiusValidatorClient,
    Bake,
    BakeRequest,
    DecommissionJob,
    Feasibility,
    HippiusApiError,
    HippiusTimeoutError,
    HippiusValidatorClient,
    Image,
    LaunchJob,
    LaunchRequest,
    MigrationFailedError,
    ProvisionPhase,
    ProvisionStep,
)

BASE = "https://vali.example"
TOKEN = "svc-token-abc"


def _client() -> HippiusValidatorClient:
    return HippiusValidatorClient(
        BASE, TOKEN, host_header="vali.vali.svc.cluster.local"
    )


def _bake_body(state: str, **over: object) -> dict[str, object]:
    body = {
        "bake_id": "bake123",
        "vm_id": "vm-1",
        "state": state,
        "version": 1,
        "qcow2_sha256": "a" * 64 if state == "succeeded" else None,
        "kernel_sha256": "b" * 64 if state == "succeeded" else None,
        "initrd_sha256": "c" * 64 if state == "succeeded" else None,
        "failure_reason": None,
    }
    body.update(over)
    return body


def _launch_body(state: str, **over: object) -> dict[str, object]:
    body = {
        "job_id": "job-9",
        "vm_id": "vm-1",
        "tenant_id": "tenant-1",
        "flavor": "small",
        "state": state,
        "miner_id": "miner-b" if state != "queued" else None,
        "placement_id": None,
        "reason": None,
        "result": {"ok": True} if state == "succeeded" else None,
        "decided_by": "orchestration-root",
        "started_at": "2026-07-09T00:00:00Z",
        "finished_at": None,
        "version": 1,
    }
    body.update(over)
    return body


# Sentinel: omit the `boot_phase` key entirely (an older validator that does
# not report guest-boot progress) vs. include it (a newer one, maybe `""`).
_ABSENT = object()


def _vm_body(
    boot_phase: object = _ABSENT,
    netbird_ip: object = _ABSENT,
    **over: object,
) -> dict[str, object]:
    """A `Vm` row as `GET /v1/vm/<vm_id>/state` renders it.

    ``boot_phase`` left as ``_ABSENT`` omits the key (older validator, no boot
    reporting). Passing a string (incl. ``""``) includes ``boot_phase`` +
    ``boot_phase_at`` (newer validator). ``netbird_ip`` works the same way:
    ``_ABSENT`` omits the key (older validator), a string (incl. ``""`` before
    the overlay peer resolves) includes it.
    """
    body: dict[str, object] = {
        "vm_id": "vm-1",
        "tenant_id": "tenant-1",
        "lease_id": "lease-1",
        "state": "active",
        "generation": 1,
        "new_generation": None,
        "host": "node-a",
        "migration_dest": "",
        "version": 1,
        "created_at": "2026-07-09T00:00:00Z",
        "updated_at": "2026-07-09T00:00:00Z",
    }
    if boot_phase is not _ABSENT:
        body["boot_phase"] = boot_phase
        body["boot_phase_at"] = (
            "2026-07-09T00:00:01Z" if boot_phase else None
        )
    if netbird_ip is not _ABSENT:
        body["netbird_ip"] = netbird_ip
    body.update(over)
    return body


# ─── sync: launch happy path (202 → poll → succeeded) ───────────────────


@responses.activate
def test_launch_happy_path_polls_to_succeeded() -> None:
    responses.post(
        f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202
    )
    # First poll running, then succeeded (responses replays in order).
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("succeeded"), status=200
    )

    with _client() as c:
        job = c.launch_vm(
            LaunchRequest(
                tenant_id="tenant-1",
                user_id="user-1",
                vm_id="vm-1",
                lease_id="lease-1",
                flavor="small",
                cmdline="console=ttyS0",
                bake_id="bake123",
            ),
            userdata="#cloud-config\n",
        )
        assert job.state == "queued"
        final = c.wait_for_launch(job.job_id, interval=0, timeout=5)

    assert final.is_succeeded
    assert final.miner_id == "miner-b"
    assert final.result == {"ok": True}

    # Auth + Host headers are sent on the launch POST.
    launch_req = responses.calls[0].request
    assert launch_req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert launch_req.headers["Host"] == "vali.vali.svc.cluster.local"


# ─── sync: launch-by-image + the golden-image catalog ───────────────────


def _images_body() -> dict[str, object]:
    return {
        "images": [
            {
                "image_name": "ubuntu",
                "distro": "ubuntu",
                "bake_id": "920b04f0bd4965dca293a9e3678973b1",
                "is_golden": True,
                "blessed_at": "2026-07-22T00:00:00Z",
                "blessed_by": "ops",
            }
        ],
        "total": 1,
    }


@responses.activate
def test_list_images() -> None:
    responses.get(f"{BASE}/v1/images", json=_images_body(), status=200)
    with _client() as c:
        images = c.list_images()
    assert len(images) == 1
    img = images[0]
    assert isinstance(img, Image)
    assert img.image_name == "ubuntu"
    assert img.bake_id == "920b04f0bd4965dca293a9e3678973b1"
    assert img.is_golden is True


def test_launch_request_image_is_in_body() -> None:
    """`image` is the launch-by-image fast path — it must reach the wire."""
    body = LaunchRequest(vm_id="vm-1", image="ubuntu").to_body(userdata="#c\n")
    assert body["image"] == "ubuntu"
    # A `None` bake_id is dropped so the two are not both sent by default.
    assert "bake_id" not in body


# ─── sync: error envelope → HippiusApiError ─────────────────────────────


@responses.activate
def test_error_envelope_raises() -> None:
    responses.post(
        f"{BASE}/v1/vm/launch",
        json={"error": "userdata must be a non-empty string", "category": "wire"},
        status=400,
    )
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.launch_vm(LaunchRequest(vm_id="vm-1"), userdata="x")

    err = exc.value
    assert err.status == 400
    assert err.category == "wire"
    assert "userdata" in err.error
    assert err.body["category"] == "wire"


@responses.activate
def test_launch_failed_state_raises() -> None:
    responses.get(
        f"{BASE}/v1/vm/launch/job-9",
        json=_launch_body("failed", reason="no capacity"),
        status=200,
    )
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.wait_for_launch("job-9", interval=0, timeout=5)
    assert exc.value.category == "launch-failed"
    assert "no capacity" in exc.value.error


# ─── sync: provision_vm chaining ────────────────────────────────────────


@responses.activate
def test_provision_vm_chains_bake_then_launch() -> None:
    responses.post(
        f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(
        f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("succeeded"), status=200
    )
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)

    bake = BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/ubuntu.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/hippius-compute/vms/vm-1/luks-kek",
        s3_output_bucket="bakes",
        s3_output_prefix="tenant/vm-1/",
    )
    launch = LaunchRequest(
        tenant_id="tenant-1",
        user_id="user-1",
        vm_id="vm-1",
        lease_id="lease-1",
        flavor="small",
        cmdline="console=ttyS0",
        userdata="#cloud-config\n",
    )

    with _client() as c:
        job = c.provision_vm(
            bake=bake,
            launch=launch,
            bake_interval=0,
            launch_interval=0,
        )

    assert job.is_succeeded
    # bake_id was auto-filled onto the launch intent.
    assert launch.bake_id == "bake123"
    # The bake create body carried the request fields verbatim.
    create_req = responses.calls[0].request
    assert b'"vm_id": "vm-1"' in create_req.body
    # The launch body carried the resolved bake_id + userdata (no None fields).
    launch_req = responses.calls[3].request
    assert b'"bake_id": "bake123"' in launch_req.body
    assert b'"userdata"' in launch_req.body


@responses.activate
def test_provision_vm_raises_on_bake_failure() -> None:
    responses.post(
        f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123",
        json=_bake_body("failed", failure_reason="fetch 404"),
        status=200,
    )
    bake = BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/x.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/x",
        s3_output_bucket="b",
        s3_output_prefix="p/",
    )
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.provision_vm(
            bake=bake,
            launch=LaunchRequest(userdata="x"),
            bake_interval=0,
        )
    assert exc.value.category == "bake-failed"
    assert "fetch 404" in exc.value.error


# ─── sync: lifecycle helpers ────────────────────────────────────────────


@responses.activate
def test_get_vm_state_and_transition() -> None:
    responses.get(
        f"{BASE}/v1/vm/vm-1/state",
        json={
            "vm_id": "vm-1",
            "tenant_id": "t",
            "lease_id": "l",
            "state": "active",
            "generation": 1,
            "new_generation": None,
            "host": "node-a",
            "migration_dest": "",
            "version": 3,
            "created_at": "2026-07-09T00:00:00Z",
            "updated_at": "2026-07-09T00:00:00Z",
        },
        status=200,
    )
    with _client() as c:
        vm = c.get_vm_state("vm-1")
    assert vm.state == "active"
    assert vm.generation == 1
    assert vm.version == 3


@responses.activate
def test_migrate_vm() -> None:
    responses.post(
        f"{BASE}/v1/vm/vm-1/migrate",
        json={
            "job_id": "mig-1",
            "vm_id": "vm-1",
            "source_node_id": "node-a",
            "dest_node_id": "node-b",
            "source_gen": 1,
            "new_gen": 2,
            "state": "draining",
            "source_ack_verified": False,
            "version": 1,
        },
        status=202,
    )
    with _client() as c:
        job = c.migrate_vm("vm-1", "node-b")
    assert job.dest_node_id == "node-b"
    assert job.state == "draining"


def _migration_body(state: str, **over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "job_id": "mig-1",
        "vm_id": "vm-1",
        "state": state,
        "source_node_id": "node-a",
        "dest_node_id": "node-b",
        "source_gen": 1,
        "new_gen": 2,
        "source_ack_verified": state in ("dest_activating", "done"),
        "quarantine_node_id": None,
        "reason": None,
        "decided_by": "orchestration-root",
        "phase_started_at": "2026-07-27T00:00:00Z",
        "finished_at": "2026-07-27T00:08:00Z" if state in ("done", "failed") else None,
        "version": 1,
    }
    body.update(over)
    return body


@responses.activate
def test_wait_for_migration_polls_to_done() -> None:
    # The dest-activation step downloads a multi-GB snapshot, so the waiter
    # must keep polling through the long non-terminal states.
    for state in ("quiescing", "uploading", "dest_activating", "done"):
        responses.get(
            f"{BASE}/v1/vm/vm-1/migrate/mig-1",
            json=_migration_body(state),
            status=200,
        )
    with _client() as c:
        job = c.wait_for_migration("vm-1", "mig-1", interval=0, timeout=5)
    assert job.is_done
    assert job.is_terminal
    assert job.source_ack_verified is True


@responses.activate
def test_wait_for_migration_raises_on_failed() -> None:
    responses.get(
        f"{BASE}/v1/vm/vm-1/migrate/mig-1",
        json=_migration_body(
            "failed",
            reason="source-ack-timeout:quarantine-source",
            quarantine_node_id="node-a",
        ),
        status=200,
    )
    with _client() as c, pytest.raises(MigrationFailedError) as ei:
        c.wait_for_migration("vm-1", "mig-1", interval=0, timeout=5)
    # §25 fails closed — the destination was never activated.
    assert "source-ack-timeout" in str(ei.value)
    assert ei.value.body["quarantine_node_id"] == "node-a"


@responses.activate
def test_wait_for_migration_times_out() -> None:
    responses.get(
        f"{BASE}/v1/vm/vm-1/migrate/mig-1",
        json=_migration_body("dest_activating"),
        status=200,
    )
    with _client() as c, pytest.raises(HippiusTimeoutError):
        c.wait_for_migration("vm-1", "mig-1", interval=0, timeout=-1)


@responses.activate
def test_cancel_migration_past_fence_is_a_conflict() -> None:
    # Since the fence moved to `quiescing`, only a `draining` job is
    # cancellable — anything later is a 409 `past-fence`.
    responses.post(
        f"{BASE}/v1/vm/vm-1/migrate/mig-1/cancel",
        json={"error": "migration has passed the KBS fence", "category": "past-fence"},
        status=409,
    )
    with _client() as c, pytest.raises(HippiusApiError) as ei:
        c.cancel_migration("vm-1", "mig-1")
    assert ei.value.category == "past-fence"
    assert ei.value.status == 409


@responses.activate
def test_migrate_vm_cross_gen_is_refused_at_intake() -> None:
    # A cross-generation destination would boot a different measurement and
    # the KBS would refuse the key — the API refuses it up front.
    responses.post(
        f"{BASE}/v1/vm/vm-1/migrate",
        json={"error": "cross-generation migration refused", "category": "cross-gen"},
        status=409,
    )
    with _client() as c, pytest.raises(HippiusApiError) as ei:
        c.migrate_vm("vm-1", "node-genoa")
    assert ei.value.category == "cross-gen"


@pytest.mark.asyncio
@respx.mock
async def test_async_wait_for_migration_polls_to_done() -> None:
    route = respx.get(f"{BASE}/v1/vm/vm-1/migrate/mig-1")
    route.side_effect = [
        httpx.Response(200, json=_migration_body("uploading")),
        httpx.Response(200, json=_migration_body("done")),
    ]
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.wait_for_migration("vm-1", "mig-1", interval=0, timeout=5)
    assert job.is_done


# ─── async: mirror of the happy path + error ────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_async_launch_happy_path() -> None:
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(202, json=_launch_body("queued"))
    )
    route = respx.get(f"{BASE}/v1/vm/launch/job-9")
    route.side_effect = [
        httpx.Response(200, json=_launch_body("running")),
        httpx.Response(200, json=_launch_body("succeeded")),
    ]
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.launch_vm(LaunchRequest(vm_id="vm-1"), userdata="x")
        final = await c.wait_for_launch(job.job_id, interval=0, timeout=5)
    assert final.is_succeeded


@pytest.mark.asyncio
@respx.mock
async def test_async_list_images() -> None:
    respx.get(f"{BASE}/v1/images").mock(
        return_value=httpx.Response(200, json=_images_body())
    )
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        images = await c.list_images()
    assert [i.image_name for i in images] == ["ubuntu"]
    assert images[0].is_golden is True


@pytest.mark.asyncio
@respx.mock
async def test_async_error_envelope_raises() -> None:
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(
            403, json={"error": "not root", "category": "forbidden"}
        )
    )
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        with pytest.raises(HippiusApiError) as exc:
            await c.launch_vm(LaunchRequest(vm_id="vm-1"), userdata="x")
    assert exc.value.status == 403
    assert exc.value.category == "forbidden"


@pytest.mark.asyncio
@respx.mock
async def test_async_provision_vm_chains() -> None:
    respx.post(f"{BASE}/v1/tenant-bakes").mock(
        return_value=httpx.Response(202, json=_bake_body("queued"))
    )
    respx.get(f"{BASE}/v1/tenant-bakes/bake123").mock(
        return_value=httpx.Response(200, json=_bake_body("succeeded"))
    )
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(202, json=_launch_body("queued"))
    )
    respx.get(f"{BASE}/v1/vm/launch/job-9").mock(
        return_value=httpx.Response(200, json=_launch_body("succeeded"))
    )
    respx.get(f"{BASE}/v1/vm/vm-1/state").mock(
        return_value=httpx.Response(200, json=_vm_body())
    )
    bake = BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/x.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/x",
        s3_output_bucket="b",
        s3_output_prefix="p/",
    )
    launch = LaunchRequest(vm_id="vm-1", userdata="#cloud-config\n")
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.provision_vm(
            bake=bake, launch=launch, bake_interval=0, launch_interval=0
        )
    assert job.is_succeeded
    assert launch.bake_id == "bake123"


# ─── progress streaming ─────────────────────────────────────────────────


def _bake_req() -> BakeRequest:
    return BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/x.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/x",
        s3_output_bucket="b",
        s3_output_prefix="p/",
    )


def _register_happy_provision() -> None:
    """POST bake → GET running/succeeded → POST launch → GET queued/running/succeeded."""
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("queued"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("succeeded"), status=200
    )
    # Older validator: `GET /v1/vm/<vm_id>` carries no `boot_phase` key, so the
    # boot-wait returns immediately and the flow ends at launch-succeeded.
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)


_HAPPY_PHASES = [
    ProvisionPhase.BAKING,
    ProvisionPhase.BAKE_SUCCEEDED,
    ProvisionPhase.LAUNCH_QUEUED,
    ProvisionPhase.PLACED,
    ProvisionPhase.SUCCEEDED,
]


@responses.activate
def test_provision_vm_on_progress_emits_phases_in_order() -> None:
    _register_happy_provision()
    steps: list[ProvisionStep] = []
    with _client() as c:
        job = c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="#cloud-config\n"),
            bake_interval=0,
            launch_interval=0,
            on_progress=steps.append,
        )
    assert job.is_succeeded
    assert [s.phase for s in steps] == _HAPPY_PHASES
    # PLACED carries the miner it landed on; SUCCEEDED is terminal.
    placed = next(s for s in steps if s.phase is ProvisionPhase.PLACED)
    assert placed.miner_id == "miner-b"
    assert steps[-1].terminal
    # pct is a monotonic non-decreasing estimate up to 100.
    pcts = [s.pct for s in steps]
    assert pcts == sorted(pcts)
    assert pcts[-1] == 100


@responses.activate
def test_provision_vm_on_progress_failure_emits_failed_with_reason() -> None:
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/vm/launch/job-9",
        json=_launch_body("failed", reason="no-eligible-miner"),
        status=200,
    )
    steps: list[ProvisionStep] = []
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            on_progress=steps.append,
        )
    assert exc.value.category == "launch-failed"
    last = steps[-1]
    assert last.phase is ProvisionPhase.FAILED
    assert last.reason == "no-eligible-miner"
    assert last.terminal


@responses.activate
def test_on_progress_exception_does_not_crash_poll_loop() -> None:
    _register_happy_provision()

    def _boom(_step: ProvisionStep) -> None:
        raise RuntimeError("bad UI callback")

    with _client() as c:
        job = c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            on_progress=_boom,
        )
    assert job.is_succeeded


@responses.activate
def test_iter_provision_yields_same_sequence() -> None:
    _register_happy_provision()
    with _client() as c:
        steps = list(
            c.iter_provision(
                bake=_bake_req(),
                launch=LaunchRequest(vm_id="vm-1", userdata="x"),
                bake_interval=0,
                launch_interval=0,
            )
        )
    assert [s.phase for s in steps] == _HAPPY_PHASES
    assert steps[-1].phase is ProvisionPhase.SUCCEEDED


@responses.activate
def test_iter_provision_stops_on_bake_failure_without_launching() -> None:
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123",
        json=_bake_body("failed", failure_reason="fetch 404"),
        status=200,
    )
    with _client() as c:
        steps = list(
            c.iter_provision(
                bake=_bake_req(),
                launch=LaunchRequest(vm_id="vm-1", userdata="x"),
                bake_interval=0,
            )
        )
    assert [s.phase for s in steps] == [ProvisionPhase.BAKE_FAILED]
    assert steps[-1].reason == "fetch 404"
    assert steps[-1].terminal
    # No launch POST was made (bake failed short-circuits).
    assert all("/v1/vm/launch" not in call.request.url for call in responses.calls)


# ─── launch phase mapping (server `phase` → ProvisionPhase) ─────────────


def test_from_launch_prefers_server_phase_when_present() -> None:
    """The finer server `phase` maps 1:1 (staging/placing/dispatching) and
    wins over the coarse state+miner_id derivation."""
    cases = {
        ("queued", "queued"): ProvisionPhase.LAUNCH_QUEUED,
        ("running", "staging"): ProvisionPhase.STAGING,
        ("running", "placing"): ProvisionPhase.PLACING,
        ("running", "dispatching"): ProvisionPhase.DISPATCHING,
        ("succeeded", "launched"): ProvisionPhase.SUCCEEDED,
        ("failed", "failed"): ProvisionPhase.FAILED,
    }
    for (state, phase), expected in cases.items():
        job = LaunchJob.from_dict(
            {
                "job_id": "j",
                "vm_id": "v",
                "state": state,
                "version": 1,
                "phase": phase,
                "reason": "boom" if state == "failed" else None,
            }
        )
        step = ProvisionStep.from_launch(job)
        assert step.phase is expected, (state, phase)
    # A dispatching step even before miner_id is known is still fine-grained
    # (the coarse path would have called it RUNNING).
    disp = ProvisionStep.from_launch(
        LaunchJob.from_dict(
            {"job_id": "j", "vm_id": "v", "state": "running", "version": 1,
             "phase": "dispatching"}
        )
    )
    assert disp.phase is ProvisionPhase.DISPATCHING
    assert disp.pct == 80


def test_from_launch_backward_compat_without_phase() -> None:
    """An older server that omits `phase` falls back to the coarse
    state+miner_id derivation (queued → LAUNCH_QUEUED; running+miner →
    PLACED; running → RUNNING)."""
    queued = ProvisionStep.from_launch(
        LaunchJob.from_dict({"job_id": "j", "vm_id": "v", "state": "queued", "version": 1})
    )
    assert queued.phase is ProvisionPhase.LAUNCH_QUEUED
    placed = ProvisionStep.from_launch(
        LaunchJob.from_dict(
            {"job_id": "j", "vm_id": "v", "state": "running", "version": 1,
             "miner_id": "m-1"}
        )
    )
    assert placed.phase is ProvisionPhase.PLACED
    running = ProvisionStep.from_launch(
        LaunchJob.from_dict({"job_id": "j", "vm_id": "v", "state": "running", "version": 1})
    )
    assert running.phase is ProvisionPhase.RUNNING


_FINE_PHASES = [
    ProvisionPhase.BAKING,
    ProvisionPhase.BAKE_SUCCEEDED,
    ProvisionPhase.LAUNCH_QUEUED,
    ProvisionPhase.STAGING,
    ProvisionPhase.PLACING,
    ProvisionPhase.DISPATCHING,
    ProvisionPhase.SUCCEEDED,
]


@responses.activate
def test_provision_vm_emits_fine_phases_when_server_sends_phase() -> None:
    """A server that populates `phase` drives the finer staging→placing→
    dispatching sequence through the poll loop, pct still monotonic."""
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(
        f"{BASE}/v1/vm/launch", json=_launch_body("queued", phase="queued"), status=202
    )
    for st, ph in [
        ("queued", "queued"),
        ("running", "staging"),
        ("running", "placing"),
        ("running", "dispatching"),
        ("succeeded", "launched"),
    ]:
        responses.get(
            f"{BASE}/v1/vm/launch/job-9",
            json=_launch_body(st, phase=ph),
            status=200,
        )
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)
    steps: list[ProvisionStep] = []
    with _client() as c:
        job = c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="#cloud-config\n"),
            bake_interval=0,
            launch_interval=0,
            on_progress=steps.append,
        )
    assert job.is_succeeded
    assert [s.phase for s in steps] == _FINE_PHASES
    pcts = [s.pct for s in steps]
    assert pcts == sorted(pcts)
    assert pcts[-1] == 100


# ─── async: progress streaming ──────────────────────────────────────────


def _respx_happy_provision() -> None:
    respx.post(f"{BASE}/v1/tenant-bakes").mock(
        return_value=httpx.Response(202, json=_bake_body("queued"))
    )
    respx.get(f"{BASE}/v1/tenant-bakes/bake123").side_effect = [
        httpx.Response(200, json=_bake_body("running")),
        httpx.Response(200, json=_bake_body("succeeded")),
    ]
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(202, json=_launch_body("queued"))
    )
    respx.get(f"{BASE}/v1/vm/launch/job-9").side_effect = [
        httpx.Response(200, json=_launch_body("queued")),
        httpx.Response(200, json=_launch_body("running")),
        httpx.Response(200, json=_launch_body("succeeded")),
    ]
    # Older validator: no `boot_phase` key ⇒ boot-wait returns immediately.
    respx.get(f"{BASE}/v1/vm/vm-1/state").mock(
        return_value=httpx.Response(200, json=_vm_body())
    )


@pytest.mark.asyncio
@respx.mock
async def test_async_provision_vm_on_progress() -> None:
    _respx_happy_provision()
    steps: list[ProvisionStep] = []
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            on_progress=steps.append,
        )
    assert job.is_succeeded
    assert [s.phase for s in steps] == _HAPPY_PHASES


@pytest.mark.asyncio
@respx.mock
async def test_async_iter_provision_yields_same_sequence() -> None:
    _respx_happy_provision()
    steps: list[ProvisionStep] = []
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        async for step in c.async_iter_provision(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
        ):
            steps.append(step)
    assert [s.phase for s in steps] == _HAPPY_PHASES
    assert steps[-1].phase is ProvisionPhase.SUCCEEDED


# ─── guest-boot progress (server `boot_phase` on the Vm row) ─────────────

_BOOT_PHASES = [
    ProvisionPhase.BOOTING,
    ProvisionPhase.KEK_RELEASED,
    ProvisionPhase.RUNNING,
]
# The full lifecycle now runs past launch-succeeded into the guest boot.
_HAPPY_PHASES_WITH_BOOT = _HAPPY_PHASES + _BOOT_PHASES


def _register_boot_vm_gets() -> None:
    """`GET /v1/vm/vm-1/state` returns booting → kek_released → running in order."""
    for ph in ("booting", "kek_released", "running"):
        responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(boot_phase=ph), status=200)


def test_boot_phase_of_maps_wire_strings() -> None:
    """`boot_phase` wire strings map 1:1; empty / absent / unknown ⇒ None."""
    from hippius_validator_client.models import Vm, boot_phase_of, reports_boot_phase

    cases = {
        "booting": ProvisionPhase.BOOTING,
        "kek_released": ProvisionPhase.KEK_RELEASED,
        "running": ProvisionPhase.RUNNING,
    }
    for wire, expected in cases.items():
        vm = Vm.from_dict(_vm_body(boot_phase=wire))
        assert boot_phase_of(vm) is expected, wire
        assert reports_boot_phase(vm) is True
    # Present but empty ⇒ newer server, not booting yet (None phase, reports=True).
    empty = Vm.from_dict(_vm_body(boot_phase=""))
    assert boot_phase_of(empty) is None
    assert reports_boot_phase(empty) is True
    # Absent key ⇒ older server (None phase, reports=False).
    absent = Vm.from_dict(_vm_body())
    assert boot_phase_of(absent) is None
    assert reports_boot_phase(absent) is False


@responses.activate
def test_wait_for_boot_yields_booting_kek_running() -> None:
    _register_boot_vm_gets()
    with _client() as c:
        steps = list(c.wait_for_boot("vm-1", interval=0, timeout=5))
    assert [s.phase for s in steps] == _BOOT_PHASES
    assert steps[-1].phase is ProvisionPhase.RUNNING
    assert steps[-1].terminal
    assert steps[-1].pct == 100
    # RUNNING carries the placement host in its detail.
    assert "node-a" in steps[-1].detail


@responses.activate
def test_wait_for_boot_backward_compat_no_boot_phase_returns_empty() -> None:
    """An older validator (no `boot_phase` key) yields nothing and does NOT
    hang — a single GET is enough for the boot-wait to give up."""
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)
    with _client() as c:
        steps = list(c.wait_for_boot("vm-1", interval=0, timeout=5))
    assert steps == []
    # Exactly one GET was made (it returned immediately, no polling loop).
    assert sum("/v1/vm/vm-1/state" in call.request.url for call in responses.calls) == 1


@responses.activate
def test_provision_vm_continues_past_launch_to_running() -> None:
    """The provision stream now runs past launch-succeeded into the guest
    boot phases and ends terminal at RUNNING."""
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("queued"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("succeeded"), status=200
    )
    _register_boot_vm_gets()
    steps: list[ProvisionStep] = []
    with _client() as c:
        job = c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            boot_interval=0,
            on_progress=steps.append,
        )
    # provision_vm still returns the LaunchJob (signature unchanged).
    assert job.is_succeeded
    assert [s.phase for s in steps] == _HAPPY_PHASES_WITH_BOOT
    assert steps[-1].phase is ProvisionPhase.RUNNING
    assert steps[-1].terminal
    # pct stays monotonic non-decreasing and tops out at 100.
    pcts = [s.pct for s in steps]
    assert pcts == sorted(pcts)
    assert pcts[-1] == 100


@responses.activate
def test_provision_vm_backward_compat_ends_at_succeeded() -> None:
    """No `boot_phase` reported ⇒ the flow ends at launch-succeeded exactly
    as before, without hanging on the boot-wait."""
    _register_happy_provision()
    steps: list[ProvisionStep] = []
    with _client() as c:
        job = c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            boot_interval=0,
            on_progress=steps.append,
        )
    assert job.is_succeeded
    assert [s.phase for s in steps] == _HAPPY_PHASES
    assert steps[-1].phase is ProvisionPhase.SUCCEEDED


@responses.activate
def test_iter_provision_streams_boot_phases() -> None:
    responses.post(f"{BASE}/v1/tenant-bakes", json=_bake_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/tenant-bakes/bake123", json=_bake_body("succeeded"), status=200
    )
    responses.post(f"{BASE}/v1/vm/launch", json=_launch_body("queued"), status=202)
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("queued"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("running"), status=200
    )
    responses.get(
        f"{BASE}/v1/vm/launch/job-9", json=_launch_body("succeeded"), status=200
    )
    _register_boot_vm_gets()
    with _client() as c:
        steps = list(
            c.iter_provision(
                bake=_bake_req(),
                launch=LaunchRequest(vm_id="vm-1", userdata="x"),
                bake_interval=0,
                launch_interval=0,
                boot_interval=0,
            )
        )
    assert [s.phase for s in steps] == _HAPPY_PHASES_WITH_BOOT
    assert steps[-1].phase is ProvisionPhase.RUNNING


def _respx_boot_vm_gets() -> None:
    respx.get(f"{BASE}/v1/vm/vm-1/state").side_effect = [
        httpx.Response(200, json=_vm_body(boot_phase="booting")),
        httpx.Response(200, json=_vm_body(boot_phase="kek_released")),
        httpx.Response(200, json=_vm_body(boot_phase="running")),
    ]


@pytest.mark.asyncio
@respx.mock
async def test_async_provision_vm_streams_boot_phases() -> None:
    respx.post(f"{BASE}/v1/tenant-bakes").mock(
        return_value=httpx.Response(202, json=_bake_body("queued"))
    )
    respx.get(f"{BASE}/v1/tenant-bakes/bake123").side_effect = [
        httpx.Response(200, json=_bake_body("running")),
        httpx.Response(200, json=_bake_body("succeeded")),
    ]
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(202, json=_launch_body("queued"))
    )
    respx.get(f"{BASE}/v1/vm/launch/job-9").side_effect = [
        httpx.Response(200, json=_launch_body("queued")),
        httpx.Response(200, json=_launch_body("running")),
        httpx.Response(200, json=_launch_body("succeeded")),
    ]
    _respx_boot_vm_gets()
    steps: list[ProvisionStep] = []
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.provision_vm(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            boot_interval=0,
            on_progress=steps.append,
        )
    assert job.is_succeeded
    assert [s.phase for s in steps] == _HAPPY_PHASES_WITH_BOOT
    assert steps[-1].phase is ProvisionPhase.RUNNING


@pytest.mark.asyncio
@respx.mock
async def test_async_iter_provision_streams_boot_phases() -> None:
    respx.post(f"{BASE}/v1/tenant-bakes").mock(
        return_value=httpx.Response(202, json=_bake_body("queued"))
    )
    respx.get(f"{BASE}/v1/tenant-bakes/bake123").side_effect = [
        httpx.Response(200, json=_bake_body("running")),
        httpx.Response(200, json=_bake_body("succeeded")),
    ]
    respx.post(f"{BASE}/v1/vm/launch").mock(
        return_value=httpx.Response(202, json=_launch_body("queued"))
    )
    respx.get(f"{BASE}/v1/vm/launch/job-9").side_effect = [
        httpx.Response(200, json=_launch_body("queued")),
        httpx.Response(200, json=_launch_body("running")),
        httpx.Response(200, json=_launch_body("succeeded")),
    ]
    _respx_boot_vm_gets()
    steps: list[ProvisionStep] = []
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        async for step in c.async_iter_provision(
            bake=_bake_req(),
            launch=LaunchRequest(vm_id="vm-1", userdata="x"),
            bake_interval=0,
            launch_interval=0,
            boot_interval=0,
        ):
            steps.append(step)
    assert [s.phase for s in steps] == _HAPPY_PHASES_WITH_BOOT
    assert steps[-1].phase is ProvisionPhase.RUNNING


# ─── NetBird overlay IP (server `netbird_ip` on the Vm row) ──────────────


@responses.activate
def test_get_vm_state_parses_netbird_ip() -> None:
    """A newer validator surfaces `netbird_ip` on the VM state row."""
    responses.get(
        f"{BASE}/v1/vm/vm-1/state",
        json=_vm_body(netbird_ip="100.72.1.5"),
        status=200,
    )
    with _client() as c:
        vm = c.get_vm_state("vm-1")
    assert vm.netbird_ip == "100.72.1.5"


@responses.activate
def test_get_vm_state_parses_the_post_migration_overlay_verdict() -> None:
    """A §25-migrated VM that lost its peer reads `active` with a STALE
    `netbird_ip` — `netbird_status` is the only field that says so."""
    responses.get(
        f"{BASE}/v1/vm/vm-1/state",
        json=_vm_body(netbird_ip="100.72.1.5", netbird_status="lost"),
        status=200,
    )
    with _client() as c:
        vm = c.get_vm_state("vm-1")
    assert vm.state == "active"
    assert vm.netbird_ip == "100.72.1.5"
    assert vm.netbird_status == "lost"
    assert vm.netbird_lost is True


@responses.activate
def test_netbird_lost_is_false_on_a_healthy_or_older_validator() -> None:
    """Absence of the signal is NOT evidence of loss, and a VM that came
    back on the overlay must not be flagged."""
    responses.get(
        f"{BASE}/v1/vm/vm-1/state",
        json=_vm_body(netbird_ip="100.72.1.5", netbird_status="ok"),
        status=200,
    )
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)
    with _client() as c:
        assert c.get_vm_state("vm-1").netbird_lost is False  # settled ok
        older = c.get_vm_state("vm-1")
    assert older.netbird_status is None  # key absent entirely
    assert older.netbird_lost is False


def test_from_boot_running_carries_netbird_ip() -> None:
    """The RUNNING boot step carries the resolved NetBird IP (field + detail)."""
    from hippius_validator_client.models import ProvisionStep, Vm

    vm = Vm.from_dict(_vm_body(boot_phase="running", netbird_ip="100.72.1.5"))
    step = ProvisionStep.from_boot(vm)
    assert step.phase is ProvisionPhase.RUNNING
    assert step.netbird_ip == "100.72.1.5"
    assert "100.72.1.5" in step.detail
    # Not yet resolved (`""`) ⇒ no IP on the step, no IP in the detail.
    vm_unresolved = Vm.from_dict(_vm_body(boot_phase="running", netbird_ip=""))
    step_unresolved = ProvisionStep.from_boot(vm_unresolved)
    assert step_unresolved.netbird_ip is None
    assert "netbird" not in step_unresolved.detail


@responses.activate
def test_wait_for_netbird_ip_resolves() -> None:
    """`wait_for_netbird_ip` polls past the empty IP and returns it once set."""
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(netbird_ip=""), status=200)
    responses.get(
        f"{BASE}/v1/vm/vm-1/state", json=_vm_body(netbird_ip="100.72.1.5"), status=200
    )
    with _client() as c:
        ip = c.wait_for_netbird_ip("vm-1", interval=0, timeout=5)
    assert ip == "100.72.1.5"


@responses.activate
def test_wait_for_netbird_ip_backward_compat_absent_returns_none() -> None:
    """An older validator (no `netbird_ip` key) returns None after one GET —
    it does NOT poll to the timeout."""
    responses.get(f"{BASE}/v1/vm/vm-1/state", json=_vm_body(), status=200)
    with _client() as c:
        ip = c.wait_for_netbird_ip("vm-1", interval=0, timeout=5)
    assert ip is None
    assert sum("/v1/vm/vm-1/state" in call.request.url for call in responses.calls) == 1


@responses.activate
def test_reports_netbird_ip_distinguishes_server_generations() -> None:
    from hippius_validator_client.models import Vm, reports_netbird_ip

    assert reports_netbird_ip(Vm.from_dict(_vm_body(netbird_ip="100.72.1.5"))) is True
    assert reports_netbird_ip(Vm.from_dict(_vm_body(netbird_ip=""))) is True
    assert reports_netbird_ip(Vm.from_dict(_vm_body())) is False


@pytest.mark.asyncio
@respx.mock
async def test_async_wait_for_netbird_ip_resolves() -> None:
    respx.get(f"{BASE}/v1/vm/vm-1/state").side_effect = [
        httpx.Response(200, json=_vm_body(netbird_ip="")),
        httpx.Response(200, json=_vm_body(netbird_ip="100.72.1.5")),
    ]
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        ip = await c.wait_for_netbird_ip("vm-1", interval=0, timeout=5)
    assert ip == "100.72.1.5"


# ─── golden bakes (disk_mode + rootfs/verity shas) ──────────────────────


def test_bake_request_omits_disk_mode_by_default() -> None:
    """Legacy path: no `disk_mode` on the wire ⇒ server applies its default."""
    body = BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/x.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/x",
        s3_output_bucket="b",
        s3_output_prefix="p/",
    ).to_body()
    assert "disk_mode" not in body


def test_bake_request_golden_disk_mode_round_trips() -> None:
    """A golden bake request carries `disk_mode` verbatim on the wire."""
    body = BakeRequest(
        vm_id="vm-1",
        base_image_url="https://img.example/x.qcow2",
        base_image_sha256="d" * 64,
        size_gb=20,
        kek_vault_path="secret/data/x",
        s3_output_bucket="b",
        s3_output_prefix="p/",
        disk_mode="golden_verity_overlay",
    ).to_body()
    assert body["disk_mode"] == "golden_verity_overlay"


@responses.activate
def test_create_golden_bake_sends_disk_mode() -> None:
    responses.post(
        f"{BASE}/v1/tenant-bakes",
        json=_bake_body("queued", disk_mode="golden_verity_overlay"),
        status=202,
    )
    with _client() as c:
        bake = c.create_bake(
            BakeRequest(
                vm_id="vm-1",
                base_image_url="https://img.example/x.qcow2",
                base_image_sha256="d" * 64,
                size_gb=20,
                kek_vault_path="secret/data/x",
                s3_output_bucket="b",
                s3_output_prefix="p/",
                disk_mode="golden_verity_overlay",
            )
        )
    assert bake.disk_mode == "golden_verity_overlay"
    assert b'"disk_mode": "golden_verity_overlay"' in responses.calls[0].request.body


def test_bake_response_parses_golden_fields() -> None:
    """A golden bake row surfaces the rootfs/verity digests; qcow2 is null."""
    bake = Bake.from_dict(
        {
            "bake_id": "bake123",
            "vm_id": "vm-1",
            "state": "succeeded",
            "version": 2,
            "disk_mode": "golden_verity_overlay",
            "qcow2_sha256": None,
            "rootfs_img_sha256": "a" * 64,
            "rootfs_verity_sha256": "b" * 64,
            "verity_root_hash": "c" * 64,
            "kernel_sha256": "d" * 64,
            "initrd_sha256": "e" * 64,
        }
    )
    assert bake.is_golden
    assert bake.qcow2_sha256 is None
    assert bake.rootfs_img_sha256 == "a" * 64
    assert bake.rootfs_verity_sha256 == "b" * 64
    assert bake.verity_root_hash == "c" * 64


def test_bake_response_legacy_is_not_golden() -> None:
    bake = Bake.from_dict(_bake_body("succeeded", disk_mode="legacy_luks"))
    assert not bake.is_golden
    assert bake.qcow2_sha256 == "a" * 64
    assert bake.rootfs_img_sha256 is None


# ─── decommission (§24 crypto-erase lifecycle) ───────────────────────────


def _decommission_body(state: str, **over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "job_id": "dec-1",
        "vm_id": "vm-1",
        "state": state,
        "eol_ack_verified": state == "done",
        "forced": False,
        "quarantine_node_id": None,
        "reason": None,
        "decided_by": "orchestration-root",
        "phase_started_at": "2026-07-09T00:00:00Z",
        "started_at": "2026-07-09T00:00:00Z",
        "finished_at": "2026-07-09T00:01:00Z" if state in ("done", "failed") else None,
        "version": 1,
    }
    body.update(over)
    return body


@responses.activate
def test_decommission_vm_starts_job() -> None:
    responses.post(
        f"{BASE}/v1/vm/vm-1/decommission",
        json=_decommission_body("draining"),
        status=202,
    )
    with _client() as c:
        job = c.decommission_vm("vm-1")
    assert isinstance(job, DecommissionJob)
    assert job.state == "draining"
    assert not job.is_terminal


@responses.activate
def test_wait_for_decommission_polls_to_done() -> None:
    responses.get(
        f"{BASE}/v1/vm/vm-1/decommission/dec-1",
        json=_decommission_body("crypto_erasing"),
        status=200,
    )
    responses.get(
        f"{BASE}/v1/vm/vm-1/decommission/dec-1",
        json=_decommission_body("done"),
        status=200,
    )
    with _client() as c:
        job = c.wait_for_decommission("vm-1", "dec-1", interval=0, timeout=5)
    assert job.is_done
    assert job.is_terminal


@responses.activate
def test_wait_for_decommission_raises_on_failed() -> None:
    responses.get(
        f"{BASE}/v1/vm/vm-1/decommission/dec-1",
        json=_decommission_body("failed", reason="eol ack missing"),
        status=200,
    )
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.wait_for_decommission("vm-1", "dec-1", interval=0, timeout=5)
    assert exc.value.category == "decommission-failed"
    assert "eol ack missing" in exc.value.error


@pytest.mark.asyncio
@respx.mock
async def test_async_wait_for_decommission_polls_to_done() -> None:
    respx.get(f"{BASE}/v1/vm/vm-1/decommission/dec-1").side_effect = [
        httpx.Response(200, json=_decommission_body("crypto_erasing")),
        httpx.Response(200, json=_decommission_body("done")),
    ]
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        job = await c.wait_for_decommission("vm-1", "dec-1", interval=0, timeout=5)
    assert job.is_done


# ─── Pre-sale feasibility ───────────────────────────────────────────────


def _feasibility_body() -> dict:
    """The shape the validator returns for the real fleet: the small end
    is sellable, `4xlarge` is not and never will be."""
    return {
        "flavors": [
            {
                "flavor": "small",
                "verdict": "yes",
                "placeable_now": True,
                "fits_any_host": True,
                "headroom": 66,
                "cpu_count": 1,
                "memory_mb": 4096,
                "data_disk_size_gb": 40,
                "reason": "",
                "scheduler_error": "",
                "disk_checked": False,
                "hosts": [
                    {
                        "node_id": "n1",
                        "big_enough": True,
                        "fits": True,
                        "free_memory_mb": 120904,
                        "free_cpus": 22,
                        "budget_memory_mb": 120904,
                        "budget_cpus": 22,
                        "shortfall": "",
                    }
                ],
            },
            {
                "flavor": "4xlarge",
                "verdict": "never",
                "placeable_now": False,
                "fits_any_host": False,
                "headroom": 0,
                "cpu_count": 32,
                "memory_mb": 131072,
                "data_disk_size_gb": 1280,
                "reason": "flavor-exceeds-every-host",
                "scheduler_error": "",
                "disk_checked": False,
                "hosts": [
                    {
                        "node_id": "n1",
                        "big_enough": False,
                        "fits": False,
                        "free_memory_mb": 120904,
                        "free_cpus": 22,
                        "budget_memory_mb": 120904,
                        "budget_cpus": 22,
                        "shortfall": (
                            "host memory budget 120904 < 131072 MiB; "
                            "host cpu budget 22 < 32"
                        ),
                    }
                ],
            },
        ]
    }


@responses.activate
def test_feasibility_board() -> None:
    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200
    )
    with _client() as c:
        board = c.feasibility()
    assert [f.flavor for f in board] == ["small", "4xlarge"]
    assert isinstance(board[0], Feasibility)
    assert board[0].sellable is True
    assert board[1].sellable is False


@responses.activate
def test_can_place_never_is_distinct_from_full() -> None:
    """The commercial point of the endpoint: `never` must be readable as
    "do not take the money", separately from a retryable shortage."""
    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200
    )
    with _client() as c:
        answer = c.can_place("4xlarge")
    assert answer.verdict == "never"
    assert answer.reason == "flavor-exceeds-every-host"
    assert answer.sellable is False
    # And the caller can tell the operator WHICH dimension is short.
    assert "memory budget" in answer.hosts[0].shortfall


@responses.activate
def test_can_place_forwards_the_scoping_params() -> None:
    """`tenant_id` / `user_id` make the answer about THAT customer (they
    feed anti-affinity and the per-owner budget), so they must reach the
    wire rather than being silently dropped."""
    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200
    )
    with _client() as c:
        c.can_place("small", tenant_id="acme", user_id="u-1")
    qs = responses.calls[0].request.url
    assert "flavor=small" in qs
    assert "tenant_id=acme" in qs
    assert "user_id=u-1" in qs


@responses.activate
def test_feasibility_never_writes() -> None:
    """It is a GET. A pre-sale check that could create a VM would be a
    trap, so pin the method."""
    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200
    )
    with _client() as c:
        c.feasibility()
    assert responses.calls[0].request.method == "GET"


@responses.activate
def test_can_place_refuses_a_body_missing_the_flavor_it_asked_for() -> None:
    """A proxy that drops the query parameter must not make us price on
    another flavor's verdict. Better to fail than to answer confidently
    about the wrong thing."""
    from hippius_validator_client import HippiusApiError

    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json={"flavors": []}, status=200
    )
    with _client() as c, pytest.raises(HippiusApiError):
        c.can_place("small")


# ─── Regions ────────────────────────────────────────────────────────────


def _regions_body() -> dict:
    return {
        "regions": [
            {
                "region": "FR",
                "country_code": "FR",
                "miners_total": 3,
                "miners_verified": 3,
                "miners_dispatchable": 2,
                "hosted_vm_count": 1,
                "capacity": {"total_units": 16, "committed_units": 1, "free_units": 15},
                "node_ids": ["n1", "n2", "n3"],
            },
            {
                "region": "DE",
                "country_code": "DE",
                "miners_total": 1,
                "miners_verified": 0,
                "miners_dispatchable": 0,
                "hosted_vm_count": 0,
                "capacity": None,
                "node_ids": [],
            },
        ],
        "unlocated_miners": 1,
        "require_verified": True,
        "vantage": {"name": "cp-1-eu", "latitude": 52.37, "longitude": 4.9},
        "generated_at": "2026-09-21T00:00:00Z",
    }


def _feasibility_body_for(region: str) -> dict:
    body = _feasibility_body()
    for row in body["flavors"]:
        row["region"] = region
    return body


@responses.activate
def test_can_place_forwards_region() -> None:
    """`region` makes the answer about ONE country; dropped on the way to
    the wire it would return the fleet-wide verdict and oversell."""
    responses.get(
        f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body_for("FR"), status=200
    )
    with _client() as c:
        answer = c.can_place("small", region="fr")
    assert "region=fr" in responses.calls[0].request.url
    assert answer.region == "FR"


@responses.activate
def test_can_place_refuses_an_answer_not_given_for_the_region_asked() -> None:
    """A validator that pre-dates `?region=` ignores the parameter and
    answers fleet-wide with no echo. Pricing an FR sale on that would
    launch anywhere; the client must refuse rather than guess."""
    responses.get(f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200)
    with _client() as c, pytest.raises(HippiusApiError) as exc:
        c.can_place("small", region="FR")
    assert exc.value.category == "wire"
    # Without a region asked, the same body is perfectly fine.
    responses.get(f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200)
    with _client() as c:
        assert c.can_place("small").flavor == "small"


@responses.activate
def test_feasibility_omits_region_when_not_asked() -> None:
    responses.get(f"{BASE}/v1/scheduler/feasibility", json=_feasibility_body(), status=200)
    with _client() as c:
        c.feasibility("small")
    assert "region" not in responses.calls[0].request.url


@responses.activate
def test_feasibility_parses_the_region_echo_and_tolerates_its_absence() -> None:
    body = _feasibility_body()
    body["flavors"][0]["region"] = "FR"
    body["flavors"][0]["reason"] = "region-unverified"
    responses.get(f"{BASE}/v1/scheduler/feasibility", json=body, status=200)
    with _client() as c:
        board = c.feasibility()
    assert board[0].region == "FR"
    # An older validator sends no `region` key at all.
    assert board[1].region == ""


def test_launch_request_region_is_in_the_body_only_when_set() -> None:
    from hippius_validator_client import LaunchRequest

    assert "region" not in LaunchRequest(image="ubuntu").to_body("#cloud-config")
    body = LaunchRequest(image="ubuntu", region="fr").to_body("#cloud-config")
    assert body["region"] == "fr"


@responses.activate
def test_regions_report() -> None:
    from hippius_validator_client import Region, RegionsReport

    responses.get(f"{BASE}/v1/operator/regions", json=_regions_body(), status=200)
    with _client() as c:
        report = c.regions()
    assert isinstance(report, RegionsReport)
    assert [r.region for r in report.regions] == ["FR", "DE"]
    fr = report.get("fr")
    assert isinstance(fr, Region)
    assert fr.capacity is not None and fr.capacity.free_units == 15
    assert fr.node_ids == ["n1", "n2", "n3"]
    assert fr.placeable is True
    de = report.get("DE")
    assert de is not None and de.capacity is None and de.placeable is False
    assert report.get("JP") is None
    # Dispatchable miners but UNKNOWN capacity is not a sales hint.
    assert Region.from_dict({"region": "IT", "miners_dispatchable": 2}).placeable is False
    assert report.unlocated_miners == 1
    assert report.require_verified is True
    assert report.vantage["name"] == "cp-1-eu"
    # The default asks the validator's own rule: no parameter on the wire.
    assert responses.calls[0].request.method == "GET"
    assert "verified_only" not in responses.calls[0].request.url


@responses.activate
def test_regions_sends_verified_only_false_only_when_asked() -> None:
    responses.get(f"{BASE}/v1/operator/regions", json=_regions_body(), status=200)
    with _client() as c:
        c.regions(verified_only=False)
    assert "verified_only=false" in responses.calls[0].request.url


@respx.mock
async def test_async_regions_and_region_feasibility() -> None:
    route = respx.get(f"{BASE}/v1/operator/regions").mock(
        return_value=httpx.Response(200, json=_regions_body())
    )
    feas = respx.get(f"{BASE}/v1/scheduler/feasibility").mock(
        return_value=httpx.Response(200, json=_feasibility_body_for("FR"))
    )
    async with AsyncHippiusValidatorClient(BASE, TOKEN) as c:
        report = await c.regions(verified_only=False)
        answer = await c.can_place("small", region="FR")
    assert route.called and "verified_only=false" in str(route.calls[0].request.url)
    assert [r.region for r in report.regions] == ["FR", "DE"]
    assert feas.called and "region=FR" in str(feas.calls[0].request.url)
    assert answer.flavor == "small"
