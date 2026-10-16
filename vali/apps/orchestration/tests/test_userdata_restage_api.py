"""`POST /v1/vm/<id>/userdata/restage` + `GET …/restage/<job_id>`, and the
tick that relaunches what the API admitted.

Pins, per claim:
- `/v1/vm` is a PREFIX on the public Ingress: both routes are root-only and
  operator-scoped, and refuse tenant / non-root / anonymous callers;
- the flag (403 `userdata-restage-disabled`) and the per-VM allow-list
  (403 `userdata-restage-not-allowed`, empty = none) gate every POST;
- the wire refusals: malformed base64 (400), over the launch limit (413),
  M1/M2 (409 `userdata-restage-unsupported-key-mode`), a VM not active /
  running or with a migration in flight (409 `vm-not-restageable`);
- `dry_run` (the default) writes nothing;
- an apply stages BYTE FOR BYTE and points the record in the request,
  answers 202 with a `staged` job, and a replayed `request_id` names the
  same job (a different body under it: 409);
- the tick relaunches it (`running` / `committed`), fails it on a refused
  relaunch, a moved record or a dead relaunching tick;
- rollback re-points and relaunches the same way;
- no response or log line carries the userdata.
"""

from __future__ import annotations

import base64
import logging
from datetime import timedelta

import pytest
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity import scoping
from apps.identity.models import PrincipalScope, ServiceClient, ServiceToken, TokenLifetime
from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration import userdata_restage
from apps.orchestration.models import LaunchJob, UserdataRestageJob
from apps.orchestration.permissions import IsOrchestrationRoot
from apps.orchestration.services import launch, launch_record, power

from .factories import make_migration_job
from .test_customer_keys_launch import _measured, _pinned_vm, _spec_json, _succeeded_job
from .test_restage_userdata import VM, _intake, _m0_vm, _Vault

pytestmark = pytest.mark.django_db

URL = f"/v1/vm/{VM}/userdata/restage"
#: Never in any response or log line.
MARK = b"sekrit-agent-token-0f1e2d"
USERDATA = b"#cloud-config\nwrite_files:\n  - path: /etc/agent\n    content: " + MARK + b"\n"


@pytest.fixture
def vault(monkeypatch) -> _Vault:
    v = _Vault()
    v.install(monkeypatch)
    return v


@pytest.fixture(autouse=True)
def _enabled(settings) -> None:
    settings.VALI_USERDATA_RESTAGE_ENABLED = True
    settings.VALI_USERDATA_RESTAGE_VM_ALLOWLIST = f"other-vm, {VM}"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _post(client: APIClient, **body):
    body.setdefault("request_id", "req-1")
    return client.post(URL, body, format="json")


# ── the gate ─────────────────────────────────────────────────────────────


def _restage_routes() -> list[tuple[str, type]]:
    out: list[tuple[str, type]] = []

    def walk(patterns, prefix: str = "") -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                cls = getattr(p.callback, "cls", None)
                if (
                    cls is not None
                    and cls.__module__ == "apps.orchestration.userdata_restage_views"
                ):
                    out.append((prefix + str(p.pattern), cls))

    walk(get_resolver().url_patterns)
    return out


def test_every_restage_route_is_root_only_and_operator_scoped() -> None:
    """Published by the `/v1/vm` prefix the moment it exists."""
    routes = _restage_routes()
    assert sorted(r for r, _ in routes) == [
        "v1/vm/<str:vm_id>/userdata/restage",
        "v1/vm/<str:vm_id>/userdata/restage/<str:job_id>",
    ]
    for route, cls in routes:
        assert IsOrchestrationRoot in cls.permission_classes, route
        assert scoping.declared_scope(cls) == scoping.OPERATOR_ONLY, route


def _bearer(name: str, scope: str, tenant_id: str = "") -> APIClient:
    sc = ServiceClient.objects.create(scope=scope, name=name, tenant_id=tenant_id)
    _row, token = ServiceToken.issue(client=sc, name="ops", lifetime=TokenLifetime.OPS.value)
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return api


@pytest.mark.parametrize(("method", "url"), [("post", URL), ("get", f"{URL}/job-1")])
def test_tenant_non_root_and_anonymous_callers_are_refused(vault, method, url) -> None:
    _m0_vm(vault)
    tenant = _bearer("portal-a", PrincipalScope.TENANT.value, tenant_id="t-ck")
    operator = _bearer("upstream-api", PrincipalScope.OPERATOR.value)
    body = {"userdata_b64": _b64(USERDATA), "request_id": "r", "dry_run": False}
    assert getattr(tenant, method)(url, body, format="json").status_code == 403
    assert getattr(operator, method)(url, body, format="json").status_code == 403
    assert getattr(APIClient(), method)(url, body, format="json").status_code == 401
    assert UserdataRestageJob.objects.count() == 0


def test_disabled_answers_403(vault, root_client, settings) -> None:
    _m0_vm(vault)
    settings.VALI_USERDATA_RESTAGE_ENABLED = False

    r = _post(root_client, userdata_b64=_b64(USERDATA))

    assert (r.status_code, r.json()["category"]) == (403, "userdata-restage-disabled")


@pytest.mark.parametrize("allowlist", ["", "other-vm", f"{VM}x"])
def test_a_vm_off_the_allowlist_answers_403(vault, root_client, settings, allowlist) -> None:
    _m0_vm(vault)
    settings.VALI_USERDATA_RESTAGE_VM_ALLOWLIST = allowlist

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (r.status_code, r.json()["category"]) == (403, "userdata-restage-not-allowed")
    assert len(vault.kv[_intake()]) == 1


# ── wire refusals ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"userdata_b64": "%%%not-base64%%%"},
        {"userdata_b64": ""},
        {},
        {"userdata_b64": _b64(USERDATA), "rollback_to_version": 1},
        {"rollback_to_version": 0},
        {"userdata_b64": _b64(USERDATA), "dry_run": "yes"},
        {"userdata_b64": _b64(USERDATA), "request_id": "has space"},
        {"userdata_b64": _b64(USERDATA), "request_id": "trailing-newline\n"},
        {"userdata_b64": _b64(USERDATA), "request_id": "x" * 129},
    ],
)
def test_a_bad_body_answers_400(vault, root_client, body) -> None:
    _m0_vm(vault)

    r = _post(root_client, **body)

    assert r.status_code == 400, r.content


def test_over_the_launch_limit_answers_413(vault, root_client, settings) -> None:
    """The launch convention: base64 makes the body larger than the
    userdata, so the request-body bound (the same setting) answers first."""
    _m0_vm(vault)
    settings.DATA_UPLOAD_MAX_MEMORY_SIZE = len(USERDATA) + 64
    big = USERDATA + b"#" * 64

    r = _post(root_client, userdata_b64=_b64(big), dry_run=False)

    assert r.status_code == 413
    assert len(vault.kv[_intake()]) == 1


def test_the_userdata_bound_itself_answers_413(vault) -> None:
    with pytest.raises(userdata_restage.RestageRefused) as exc:
        userdata_restage.check_userdata(b"#" * (userdata_restage.userdata_cap() + 1))
    assert (exc.value.http_status, exc.value.category) == (413, "userdata-too-large")


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_m1_m2_answers_409(vault, root_client, mode) -> None:
    _pinned_vm(VM, mode)
    _succeeded_job(VM, _spec_json(VM, mode), measured_cmdline=_measured(mode))

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (r.status_code, r.json()["category"]) == (409, "userdata-restage-unsupported-key-mode")


def test_a_vm_not_running_or_migrating_answers_409(vault, root_client) -> None:
    vm, _job = _m0_vm(vault)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)
    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")

    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    make_migration_job(vm)
    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False, request_id="req-2")
    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")
    assert UserdataRestageJob.objects.count() == 0


def test_an_unknown_vm_answers_404(vault, root_client, settings) -> None:
    settings.VALI_USERDATA_RESTAGE_VM_ALLOWLIST = VM
    assert _post(root_client, userdata_b64=_b64(USERDATA)).status_code == 404


# ── dry run ──────────────────────────────────────────────────────────────


def test_dry_run_is_the_default_and_writes_nothing(vault, root_client) -> None:
    _m0_vm(vault)

    r = _post(root_client, userdata_b64=_b64(USERDATA))

    assert r.status_code == 200, r.content
    body = r.json()
    assert body["dry_run"] is True
    assert body["size"] == len(USERDATA)
    assert body["current_version"] == 1 and body["would_be_version"] == 2
    assert body["checks"]["key_mode"] == "M0"
    assert len(vault.kv[_intake()]) == 1
    assert UserdataRestageJob.objects.count() == 0
    assert MARK not in r.content


# ── apply, idempotence, the tick ─────────────────────────────────────────


def test_apply_stages_byte_for_byte_and_replays_by_request_id(vault, root_client, caplog) -> None:
    _m0_vm(vault, enable_netbird=True)
    caplog.set_level(logging.DEBUG)

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert r.status_code == 202, r.content
    body = r.json()
    assert (body["phase"], body["outcome"]) == ("staged", None)
    assert (body["from_version"], body["to_version"]) == (1, 2)
    # Byte for byte, behind the verbatim stamp, inside the ud-<vm> wrapping.
    assert vault.plaintext(_intake(), 2) == launch.VERBATIM_STAMP + USERDATA
    job = launch_record.latest_record(VM)
    assert job.userdata_vault_version == 2
    entry = launch_record.userdata_restages(job)[-1]
    assert entry["evidence"]["request_id"] == "req-1"
    assert entry["operator"] == "orchestration-root"
    # Replay: the same job, nothing new staged.
    again = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)
    assert (again.status_code, again.json()["job_id"]) == (202, body["job_id"])
    assert len(vault.kv[_intake()]) == 2
    # The same request_id for something else: refused.
    other = _post(root_client, userdata_b64=_b64(USERDATA + b"#"), dry_run=False)
    assert (other.status_code, other.json()["category"]) == (409, "request-id-reused")
    assert MARK not in r.content + again.content + other.content
    assert MARK.decode() not in caplog.text


class _Power:
    """`power.stop_vm` / `start_vm` as the miner would answer them: the VM's
    power state moves, an accepted start records a new measurement."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.start_refusals: list[str] = []
        monkeypatch.setattr(power, "stop_vm", self.stop)
        monkeypatch.setattr(power, "start_vm", self.start)

    def stop(self, vm: Vm, *, by_userdata_restage: str = "", **_kw) -> Vm:
        self.calls.append(("stop", by_userdata_restage, self._pointer()))
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
        return vm

    def start(self, vm: Vm, *, by_userdata_restage: str = "", **_kw) -> Vm:
        self.calls.append(("start", by_userdata_restage, self._pointer()))
        if self.start_refusals:
            raise power.PowerOpRefused(self.start_refusals.pop(0), "refused")
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
        job = launch_record.latest_record(VM)
        # Each accepted relaunch is a new boot: a measurement of its own.
        emit = {
            **(job.result_json or {}).get("emit", {}),
            "measurement_hex": f"{len(self.calls):096x}",
        }
        LaunchJob.objects.filter(pk=job.pk).update(result_json={"emit": emit})
        return vm

    @staticmethod
    def _pointer() -> int:
        return launch_record.latest_record(VM).userdata_vault_version


def _job(root_client, job_id: str) -> dict:
    return root_client.get(f"{URL}/{job_id}").json()


def test_an_identical_request_racing_the_first_gets_its_job(
    vault, root_client, monkeypatch
) -> None:
    """The twin committed between this request's first lookup and its plan:
    the plan is refused (`restage-in-flight`) — and the replay answers."""
    _m0_vm(vault)
    first = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    real = userdata_restage.existing_job
    misses = iter([None])
    monkeypatch.setattr(
        userdata_restage, "existing_job", lambda vm, rid: next(misses, None) or real(vm, rid)
    )

    again = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (again.status_code, again.json()["job_id"]) == (202, first)


def test_the_tick_stops_then_starts_and_commits(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)
    p = _Power(monkeypatch)
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]

    userdata_restage.tick_userdata_restages()

    # One tick: its own stop and start (the holder exemption), both on the new pointer.
    assert p.calls == [("stop", job_id, 2), ("start", job_id, 2)]
    body = _job(root_client, job_id)
    assert (body["phase"], body["outcome"]) == ("running", "committed")
    assert body["finished_at"] is not None and "error" not in body
    assert userdata_restage.tick_userdata_restages() == 0


def test_a_transient_start_refusal_is_retried_not_left_stopped(
    vault, root_client, monkeypatch
) -> None:
    """`allowlist-pin-busy` comes AFTER the stop landed: the VM is down, and
    must be started again on a later tick, not abandoned."""
    _m0_vm(vault)
    p = _Power(monkeypatch)
    p.start_refusals = ["allowlist-pin-busy", "relaunch-rejected"]
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]

    for _ in range(5):
        userdata_restage.tick_userdata_restages()

    assert [c[0] for c in p.calls] == ["stop", "start", "start", "start"]
    assert _job(root_client, job_id)["outcome"] == "committed"
    assert Vm.objects.get(vm_id=VM).power_state == VmPowerState.RUNNING


def test_a_start_that_keeps_failing_gives_up_and_says_the_vm_is_stopped(
    vault, root_client, monkeypatch
) -> None:
    _m0_vm(vault)
    p = _Power(monkeypatch)
    p.start_refusals = ["relaunch-rejected"] * 50
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]

    for _ in range(userdata_restage.MAX_ATTEMPTS + 3):
        userdata_restage.tick_userdata_restages()

    body = _job(root_client, job_id)
    assert (body["phase"], body["outcome"]) == ("failed", "failed")
    assert body["error"].startswith("start-gave-up") and "vm left stopped" in body["error"]
    assert launch_record.latest_record(VM).userdata_vault_version == 2


def test_a_refused_stop_fails_with_the_vm_untouched(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)

    def refuse(vm: Vm, **_kw) -> Vm:
        raise power.PowerOpRefused("vm-not-active", "no")

    monkeypatch.setattr(power, "stop_vm", refuse)
    monkeypatch.setattr(power, "start_vm", lambda vm, **kw: pytest.fail("started"))
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]

    userdata_restage.tick_userdata_restages()

    body = _job(root_client, job_id)
    assert body["phase"] == "failed" and body["error"].startswith("stop-refused:vm-not-active")
    assert "vm left running" in body["error"]


def test_a_moved_record_is_not_relaunched(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)
    monkeypatch.setattr(power, "stop_vm", lambda vm, **kw: pytest.fail("stopped"))
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    LaunchJob.objects.filter(vm_id=VM).update(userdata_vault_version=1)

    userdata_restage.tick_userdata_restages()

    body = _job(root_client, job_id)
    assert body["phase"] == "failed" and body["error"].startswith("record-moved")


def test_the_job_holds_the_vm_against_every_other_operation(vault, root_client) -> None:
    """From admission on: other power ops, §25/§24/resize/backup admission
    (`_has_active_job`) and launch intake for the vm_id are all refused —
    only the job's own stop/start pass."""
    from apps.orchestration import service

    vm, _job_row = _m0_vm(vault)
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    vm.refresh_from_db()

    assert service._has_active_job(vm) is True
    with pytest.raises(power.PowerOpRefused) as exc:
        power._claim(vm, VmPowerState.STOPPING)
    assert exc.value.reason == "userdata-restage-in-flight"
    with pytest.raises(power.PowerOpRefused) as exc:
        power._claim(vm, VmPowerState.STOPPING, by_userdata_restage="someone-else")
    assert exc.value.reason == "userdata-restage-in-flight"
    # Its own passes.
    assert power._claim(vm, VmPowerState.STOPPING, by_userdata_restage=job_id)


def test_a_relaunch_that_never_settles_times_out(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)
    p = _Power(monkeypatch)
    p.start_refusals = ["allowlist-pin-busy"]
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    userdata_restage.tick_userdata_restages()  # claimed + stopped, start refused
    UserdataRestageJob.objects.filter(job_id=job_id).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )

    userdata_restage.tick_userdata_restages()

    body = _job(root_client, job_id)
    assert body["phase"] == "failed" and body["error"].startswith("relaunch-timed-out")


def test_a_second_restage_waits_for_the_first(vault, root_client) -> None:
    _m0_vm(vault)
    assert _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).status_code == 202

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False, request_id="req-2")

    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")
    assert "restage-in-flight" in r.json()["error"]


# ── rollback ─────────────────────────────────────────────────────────────


def test_rollback_re_points_and_relaunches(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)
    _Power(monkeypatch)
    _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)
    for _ in range(2):
        userdata_restage.tick_userdata_restages()

    dry = _post(root_client, rollback_to_version=1, request_id="rb-1")
    assert (dry.status_code, dry.json()["would_be_version"]) == (200, 1)
    r = _post(root_client, rollback_to_version=1, request_id="rb-1", dry_run=False)

    assert r.status_code == 202, r.content
    body = r.json()
    assert (body["kind"], body["from_version"], body["to_version"]) == ("rollback", 2, 1)
    assert body["size"] is None and body["digest_hex"] is None
    assert launch_record.latest_record(VM).userdata_vault_version == 1
    assert len(vault.kv[_intake()]) == 2
    assert vault.decrypts == []
    for _ in range(2):
        userdata_restage.tick_userdata_restages()
    assert root_client.get(f"{URL}/{body['job_id']}").json()["outcome"] == "committed"


def test_rollback_to_a_missing_version_answers_409(vault, root_client) -> None:
    _m0_vm(vault)

    r = _post(root_client, rollback_to_version=9, dry_run=False)

    assert (r.status_code, r.json()["category"]) == (409, "rollback-unavailable")


def test_get_an_unknown_job_answers_404(vault, root_client) -> None:
    _m0_vm(vault)
    assert root_client.get(f"{URL}/nope").status_code == 404


def test_the_settings_default_to_off() -> None:
    from vali import settings as base

    assert base.VALI_USERDATA_RESTAGE_ENABLED is False
    assert base.VALI_USERDATA_RESTAGE_VM_ALLOWLIST == ""


def test_a_restage_that_would_prune_the_pointed_version_is_refused(
    vault, root_client, settings
) -> None:
    """Vault keeps `max_versions` per path: one more write must never push
    out the version the record points at (a rolled-back admission, or a
    later rollback, would have nothing to read)."""
    _m0_vm(vault)
    settings.VALI_VAULT_KV_MAX_VERSIONS = 2
    vault.put_kv("secret", _intake(), b"vault:v1:orphan")  # an inert v2

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")
    assert "would prune it" in r.json()["error"]
    assert len(vault.kv[_intake()]) == 2


def test_a_launch_intake_staging_meanwhile_loses_the_cas_not_the_pointed_version(
    vault, root_client, monkeypatch
) -> None:
    """Launch intake stages the intake path BEFORE it takes the Vm lock: a
    version that lands between this request's read and its write makes the
    write fail check-and-set, never prune past it."""
    _m0_vm(vault)
    real = userdata_restage._next_version
    calls = {"n": 0}

    def next_version_then_intake(path: str) -> int:
        calls["n"] += 1
        out = real(path)
        if calls["n"] == 2:  # the under-lock read, then a racing intake write
            vault.kv[path].append(b"vault:v1:racing-intake")
        return out

    monkeypatch.setattr(userdata_restage, "_next_version", next_version_then_intake)

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")
    assert "written meanwhile" in r.json()["error"]
    assert launch_record.latest_record(VM).userdata_vault_version == 1


def test_running_on_an_unchanged_measurement_is_not_committed(
    vault, root_client, monkeypatch
) -> None:
    """Running is not enough: the record must hold the relaunch's own
    measurement — then it commits, once."""
    _m0_vm(vault)

    def start_without_record(vm: Vm, **_kw) -> Vm:
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
        return vm

    monkeypatch.setattr(
        power,
        "stop_vm",
        lambda vm, **kw: Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED),
    )
    monkeypatch.setattr(power, "start_vm", start_without_record)
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]

    userdata_restage.tick_userdata_restages()
    userdata_restage.tick_userdata_restages()
    assert _job(root_client, job_id)["phase"] == "relaunching"

    job = launch_record.latest_record(VM)
    LaunchJob.objects.filter(pk=job.pk).update(result_json={"emit": {"measurement_hex": "ef" * 48}})
    userdata_restage.tick_userdata_restages()

    body = _job(root_client, job_id)
    assert (body["phase"], body["outcome"]) == ("running", "committed")
    assert userdata_restage.tick_userdata_restages() == 0


def test_a_tick_that_loses_the_claim_dispatches_nothing(vault, root_client, monkeypatch) -> None:
    """Two ticks on one job: the one whose attempt CAS loses must not stop
    the VM (the winner would read its `already-stopping` as terminal)."""
    _m0_vm(vault)
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    job = UserdataRestageJob.objects.get(job_id=job_id)
    userdata_restage._patch(job, phase="relaunching", phase_started_at=timezone.now())
    stale = UserdataRestageJob.objects.get(job_id=job_id)
    UserdataRestageJob.objects.filter(pk=stale.pk).update(version=stale.version + 1)
    monkeypatch.setattr(power, "stop_vm", lambda vm, **kw: pytest.fail("dispatched"))

    userdata_restage._step(stale, Vm.objects.get(vm_id=VM))

    assert UserdataRestageJob.objects.get(job_id=job_id).attempts == 0


@pytest.mark.parametrize(
    ("patch", "why"),
    [
        ({"measurement_hex": "ab" * 48}, "pins a measurement"),
        ({"auto_pin_allowlist": False}, "does not auto-pin"),
    ],
)
def test_a_record_a_relaunch_could_never_unlock_is_refused(vault, root_client, patch, why) -> None:
    """Refused at admission — not after the stop, with the VM down."""
    _vm, job = _m0_vm(vault)
    LaunchJob.objects.filter(pk=job.pk).update(spec_json={**job.spec_json, **patch})

    r = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)

    assert (r.status_code, r.json()["category"]) == (409, "vm-not-restageable")
    assert why in r.json()["error"]


def test_a_relaunch_that_landed_before_the_deadline_tick_commits(
    vault, root_client, monkeypatch
) -> None:
    """The tick comes back after the deadline to a VM its start DID bring
    up on a new measurement: committed, not failed."""
    _m0_vm(vault)
    p = _Power(monkeypatch)
    p.start_refusals = ["allowlist-pin-busy"]
    job_id = _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False).json()["job_id"]
    userdata_restage.tick_userdata_restages()  # stopped, start refused
    p.start(Vm.objects.get(vm_id=VM))  # the start lands out of band
    UserdataRestageJob.objects.filter(job_id=job_id).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )

    userdata_restage.tick_userdata_restages()

    assert _job(root_client, job_id)["outcome"] == "committed"


def test_revert_last_puts_back_the_replaced_pointer(vault, root_client, monkeypatch) -> None:
    _m0_vm(vault)
    _Power(monkeypatch)
    _post(root_client, userdata_b64=_b64(USERDATA), dry_run=False)
    userdata_restage.tick_userdata_restages()

    dry = _post(root_client, revert_last=True, request_id="rv-1")
    assert (dry.status_code, dry.json()["would_be_version"]) == (200, 1)
    r = _post(root_client, revert_last=True, request_id="rv-1", dry_run=False)

    assert r.status_code == 202, r.content
    assert (r.json()["kind"], r.json()["to_version"]) == ("revert_last", 1)
    again = _post(root_client, revert_last=True, request_id="rv-1", dry_run=False)
    assert again.json()["job_id"] == r.json()["job_id"]
    assert launch_record.latest_record(VM).userdata_vault_version == 1


@pytest.mark.parametrize(
    "body", [{"revert_last": "yes"}, {"revert_last": True, "rollback_to_version": 1}]
)
def test_revert_last_wire_refusals(vault, root_client, body) -> None:
    _m0_vm(vault)
    assert _post(root_client, **body).status_code == 400


# ── power ops and launch intake refuse each other ────────────────────────


def test_a_power_op_is_refused_while_a_launch_job_is_in_flight(vault) -> None:
    from apps.orchestration.models import LaunchJobState

    vm, job = _m0_vm(vault)
    for state in (LaunchJobState.QUEUED.value, LaunchJobState.RUNNING.value):
        queued = LaunchJob.objects.create(
            job_id=f"lj-{state}",
            vm_id=VM,
            tenant_id="t-ck",
            flavor="small",
            spec_json=job.spec_json,
            userdata_vault_path=_intake(),
            userdata_vault_version=1,
            kek_vault_path=job.kek_vault_path,
            state=state,
            phase_started_at=job.phase_started_at,
            decided_by=job.decided_by,
        )
        for marker in (VmPowerState.STOPPING, VmPowerState.STARTING):
            with pytest.raises(power.PowerOpRefused) as exc:
                power._claim(vm, marker)
            assert exc.value.reason == "launch-in-flight"
        queued.delete()
    # A job driving its own power ops (§25 / resize / restore) is not held.
    assert power._claim(vm, VmPowerState.STOPPING, by_migration=True)


@pytest.mark.parametrize("marker", [VmPowerState.STOPPING, VmPowerState.STARTING])
def test_launch_intake_is_refused_while_a_power_op_is_in_flight(vault, marker) -> None:
    from apps.orchestration import launch_jobs

    vm, _job = _m0_vm(vault)
    Vm.objects.filter(pk=vm.pk).update(power_state=marker, power_state_at=timezone.now())

    with pytest.raises(launch_jobs.LaunchIntentError, match=f"power {marker} in flight"):
        launch_jobs._refuse_held(Vm.objects.get(pk=vm.pk))

    # A marker abandoned past STALE_POWER_MARKER no longer blocks.
    Vm.objects.filter(pk=vm.pk).update(
        power_state_at=timezone.now() - power.STALE_POWER_MARKER - timedelta(minutes=1)
    )
    launch_jobs._refuse_held(Vm.objects.get(pk=vm.pk))
